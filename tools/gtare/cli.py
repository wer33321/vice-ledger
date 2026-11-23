"""Command line interface: init / pull / export / validate / submit / review / fmt."""
import argparse
import datetime
import json
import os
import shutil
import subprocess
import sys

from . import SCHEMA_VERSION, __version__, canon, config, exporter, ghidra, gitops, importer, model, safety, store
from .config import ConfigError


def out(msg=""):
    print(msg)


def fail(msg):
    print("error: %s" % msg, file=sys.stderr)
    return 1


def ask(value, prompt, default=None):
    if value:
        return value
    if not sys.stdin.isatty():
        return default
    suffix = " [%s]" % default if default else ""
    try:
        got = input("%s%s: " % (prompt, suffix)).strip().strip('"')
    except EOFError:
        return default
    return got or default


def print_issues(issues, label, limit=60):
    for i, (path, msg) in enumerate(issues):
        if i == limit:
            out("  ... and %d more %s" % (len(issues) - limit, label))
            break
        out("  %s: %s: %s" % (label, os.path.relpath(path) if os.path.isabs(path) else path, msg))


# ---------------------------------------------------------------- init
def cmd_init(a):
    repo = config.find_repo()
    existing = {}
    if os.path.isfile(config.config_path(repo)):
        existing = config.load(repo)
    cfg = dict(existing)
    exe = ask(a.exe, "Path to YOUR local GTA VI executable", existing.get("executable"))
    if not exe or not os.path.isfile(exe):
        return fail("executable not found: %r" % exe)
    exe = os.path.abspath(exe)
    if config.is_inside(exe, repo):
        return fail("the executable is inside the repository folder. Keep it outside the clone so it can "
                    "never be committed.")
    cfg["executable"] = exe
    cfg["ghidra_install"] = ask(a.ghidra, "Ghidra install folder (contains ghidraRun)", existing.get("ghidra_install"))
    cfg["ghidra_project_dir"] = ask(a.project_dir, "Ghidra project folder", existing.get("ghidra_project_dir"))
    cfg["ghidra_project_name"] = ask(a.project_name, "Ghidra project name (without .gpr)", existing.get("ghidra_project_name"))
    cfg["ghidra_program"] = ask(a.program, "Program name inside the Ghidra project",
                                existing.get("ghidra_program") or os.path.basename(exe))
    cfg["contributor"] = ask(a.contributor, "Your GitHub handle", existing.get("contributor"))
    cfg["remote"] = a.remote or existing.get("remote") or "origin"
    if not cfg["contributor"] or not model.HANDLE_RE.match(cfg["contributor"]):
        return fail("a valid GitHub handle is required (used for attribution in exported records).")
    if cfg["ghidra_install"]:
        try:
            ghidra.find_headless(cfg["ghidra_install"])
        except ConfigError as exc:
            out("warning: %s" % exc)
    out("Hashing the executable locally (nothing is uploaded)...")
    sha = config.sha256_file(exe)
    bid = "b-" + sha[:16]
    cfg["build_id"] = bid
    build = store.load_build(repo, bid)
    if build:
        out("Recognised build %s (%s)." % (bid, build.get("label", "no label")))
    elif a.register_build:
        base = a.image_base and int(a.image_base, 16) or config.pe_image_base(exe)
        if base is None:
            return fail("could not read the PE image base; pass --image-base 0x140000000")
        build = {"schema": SCHEMA_VERSION, "build_id": bid, "sha256": sha, "image_base": "0x%x" % base,
                 "file_size": os.path.getsize(exe)}
        if a.label:
            build["label"] = a.label
        store.write_json(os.path.join(store.build_dir(repo, bid), "build.json"), build)
        out("Registered NEW build %s. Commit db/builds/%s/build.json in your PR." % (bid, bid))
    else:
        out("This executable (sha256 %s...) is not a registered build yet.\n"
            "Re-run with --register-build --label \"<store/version>\" to add it, or check that you have the "
            "same version as the community." % sha[:16])
    config.save(repo, cfg)
    out("Saved %s (git-ignored). Next: 'python gtare.py pull'." % config.CONFIG_NAME)
    return 0


def _ctx(a, required=("build_id",)):
    repo = config.find_repo()
    cfg = config.load(repo, required)
    bid = getattr(a, "build", None) or cfg["build_id"]
    build = store.load_build(repo, bid)
    if build is None:
        raise ConfigError("Build %s is not in db/builds/. Pull the latest changes or run "
                          "'python gtare.py init --register-build'." % bid)
    return repo, cfg, build


def _check_db_or_abort(repo, bid):
    errors, _ = store.check_database(repo, [bid])
    if errors:
        print_issues(errors, "ERROR")
        raise ConfigError("The database has validation errors (listed above); refusing to continue.")


# ---------------------------------------------------------------- pull
def cmd_pull(a):
    repo, cfg, build = _ctx(a, ("build_id", "ghidra_install", "ghidra_project_dir", "ghidra_project_name", "ghidra_program")
                            if not (a.bundle_only or a.apply_report) else ("build_id",))
    bid = build["build_id"]
    if not a.no_git and not a.apply_report:
        if not gitops.is_repo(repo):
            return fail("not a git repository; use --no-git to skip fetching.")
        out("Fetching latest community findings...")
        try:
            gitops.run(repo, "pull", "--ff-only", cfg.get("remote", "origin"), gitops.current_branch(repo))
        except gitops.GitError as exc:
            return fail("%s\nCommit or stash your changes, or use --no-git." % exc)
    _check_db_or_abort(repo, bid)
    wd = config.state_dir(repo)
    bundle_path, report_path = os.path.join(wd, "bundle.json"), os.path.join(wd, "last-pull-report.json")
    if a.apply_report:
        with open(bundle_path, "r", encoding="utf-8") as fh:
            bundle = json.load(fh)
        report_path = a.apply_report
    else:
        bundle = importer.build_bundle(repo, build, full=a.full, create_functions=not a.no_create,
                                       force=a.force, allow_hash_mismatch=a.allow_hash_mismatch)
        with open(bundle_path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(bundle, fh, sort_keys=True)
        total = sum(len(bundle[k]) for k in ("types", "functions", "globals"))
        out("%d record(s) to apply, %d already up to date." % (total, bundle["skipped_unchanged"]))
        if a.bundle_only:
            out("Bundle written to %s.\nIn Ghidra: Script Manager > GtareImport.py, choose that bundle, then run "
                "'python gtare.py pull --apply-report <report file it wrote>'." % bundle_path)
            return 0
        if total == 0:
            return 0
        if os.path.exists(report_path):
            os.remove(report_path)
        rc = ghidra.run_script(cfg, "GtareImport.py", [bundle_path, report_path], read_only=False)
        if rc != 0 or not os.path.isfile(report_path):
            return fail("Ghidra exited with code %s and no report was produced. Check the Ghidra output above." % rc)
    with open(report_path, "r", encoding="utf-8") as fh:
        report = json.load(fh)
    if a.apply_report:
        shutil.copyfile(report_path, os.path.join(wd, "last-pull-report.json"))
    counts = importer.apply_report(repo, bid, bundle, report)
    out("Applied %(applied)d, already matching %(matched)d, CONFLICTS %(conflicts)d, UNRESOLVED %(unresolved)d." % counts)
    for c in report.get("conflicts", [])[:50]:
        out("  conflict %s [%s]: local=%r community=%r -> kept your local value" % (
            c["id"], c.get("field"), c.get("local"), c.get("community")))
    for u in report.get("unresolved", [])[:50]:
        out("  unresolved %s: %s" % (u["id"], u.get("reason")))
    if counts["conflicts"] or counts["unresolved"]:
        out("Full report: %s (use 'pull --force' to let the community value win for conflicts)." % report_path)
    return 0


# ---------------------------------------------------------------- export
def cmd_export(a):
    repo, cfg, build = _ctx(a, ("build_id", "contributor"))
    bid = build["build_id"]
    wd = config.state_dir(repo)
    snap_path = a.snapshot or os.path.join(wd, "snapshot.json")
    if not a.snapshot:
        for k in ("ghidra_install", "ghidra_project_dir", "ghidra_project_name", "ghidra_program"):
            if not cfg.get(k):
                return fail("%s is not configured; run 'python gtare.py init'." % k)
        if os.path.exists(snap_path):
            os.remove(snap_path)
        rc = ghidra.run_script(cfg, "GtareExport.py", [snap_path], read_only=True)
        if rc != 0 or not os.path.isfile(snap_path):
            return fail("Ghidra exited with code %s and no snapshot was produced." % rc)
    with open(snap_path, "r", encoding="utf-8") as fh:
        snap = json.load(fh)
    prog = snap.get("program", {})
    if prog.get("sha256") and prog["sha256"].lower() != build["sha256"]:
        return fail("The Ghidra program's SHA-256 (%s...) does not match build %s (%s...). You are analysing a "
                    "different executable version than the one configured." % (prog["sha256"][:12], bid, build["sha256"][:12]))
    if prog.get("image_base") and int(prog["image_base"], 16) != int(build["image_base"], 16):
        out("warning: Ghidra image base %s differs from the registered %s; RVAs use the Ghidra value "
            "relative to the program's own base, so this is only informational." % (prog["image_base"], build["image_base"]))
    records, skipped = exporter.snapshot_to_records(snap, cfg["contributor"], a.confidence, a.include_auto, not a.no_comments)
    plan = exporter.plan_changes(repo, bid, records, cfg["contributor"], force=a.force)
    out("Considered %d finding(s): %d new, %d modified, %d unchanged." % (
        len(records), len(plan.new), len(plan.modified), len(plan.unchanged)))
    for rec, old in plan.stale:
        out("  SKIPPED %s: the community version changed since you last pulled. Run 'pull' and re-export (or --force)." % rec["id"])
    for rec, old in plan.protected:
        out("  SKIPPED %s: reviewed record differs from your local work; open an issue/PR discussion (or --force)." % rec["id"])
    for rid, errs in plan.invalid:
        out("  INVALID %s: %s" % (rid, "; ".join(errs)))
    for what, why in skipped:
        out("  skipped %s: %s" % (what, why))
    if a.dry_run:
        out("Dry run: nothing written.")
        return 0
    paths = exporter.write_plan(repo, bid, plan)
    out("Wrote %d file(s) under db/builds/%s/. Next: 'python gtare.py validate' then 'python gtare.py submit'." % (len(paths), bid))
    return 0


# ---------------------------------------------------------------- validate
def cmd_validate(a):
    repo = config.find_repo()
    problems = 0
    files = None
    changed = None
    if a.base:
        changed = gitops.changed_files(repo, a.base)
        if a.data_only:
            bad = [f for f in changed if not f.startswith("db/")]
            for f in bad:
                out("  ERROR: %s: data-only contribution may only change files under db/ (tooling changes need a "
                    "maintainer PR)" % f)
            problems += len(bad)
        if not a.allow_review:
            for f in changed:
                if f.startswith("db/") and f.endswith(".json") and os.path.isfile(os.path.join(repo, f)):
                    try:
                        new = json.load(open(os.path.join(repo, f), encoding="utf-8"))
                    except ValueError:
                        continue
                    old_txt = gitops.show(repo, a.base, f)
                    old = json.loads(old_txt) if old_txt else {}
                    if new.get("status") == "reviewed" and (old.get("status") != "reviewed" or
                                                           canon.content(old) != canon.content(new)):
                        out("  ERROR: %s: only maintainers may set or keep status 'reviewed' on a changed record" % f)
                        problems += 1
        files = [f for f in safety.list_repo_files(repo)]
    sissues = safety.scan_repo(repo, files)
    print_issues(sissues, "ERROR")
    problems += len(sissues)
    errors, warnings = store.check_database(repo, [a.build] if a.build else None)
    print_issues(errors, "ERROR")
    print_issues(warnings, "warning")
    problems += len(errors) + (len(warnings) if a.strict else 0)
    out("Validation %s: %d error(s), %d warning(s)." % ("FAILED" if problems else "passed", len(errors) + len(sissues), len(warnings)))
    return 1 if problems else 0


# ---------------------------------------------------------------- fmt / review
def cmd_fmt(a):
    repo = config.find_repo()
    n = 0
    for bid in store.list_builds(repo):
        for path in store.iter_record_files(repo, bid):
            with open(path, "r", encoding="utf-8") as fh:
                rec = json.load(fh)
            txt = canon.dumps(rec)
            if open(path, "r", encoding="utf-8", newline="").read() != txt:
                store.write_json(path, rec)
                n += 1
    out("Rewrote %d file(s) in canonical form." % n)
    return 0


def cmd_stats(a):
    repo = config.find_repo()
    for bid in store.list_builds(repo):
        recs, _ = store.load_records(repo, bid)
        build = store.load_build(repo, bid) or {}
        out("%s  %s" % (bid, build.get("label", "")))
        for kind in model.KINDS:
            rs = [r for r in recs.values() if r["kind"] == kind]
            if rs:
                by = {s: sum(1 for r in rs if r["status"] == s) for s in model.STATUSES}
                out("  %-9s %6d   auto %d / manual %d / reviewed %d" % (kind, len(rs), by["auto"], by["manual"], by["reviewed"]))
    if not store.list_builds(repo):
        out("No builds registered yet.")
    return 0


def cmd_review(a):
    repo, cfg, build = _ctx(a, ("build_id", "contributor"))
    recs, _ = store.load_records(repo, build["build_id"])
    me = a.as_handle or cfg["contributor"]
    rc = 0
    for rid in a.ids:
        rec = recs.get(rid)
        if not rec:
            out("  unknown id %s" % rid)
            rc = 1
            continue
        if rec["contributor"].lower() == me.lower() and not a.allow_self:
            out("  %s: you authored this record; an independent reviewer must mark it reviewed" % rid)
            rc = 1
            continue
        path = rec.pop("_path")
        rec["status"], rec["reviewed_by"] = "reviewed", me
        store.write_json(path, rec)
        out("  %s marked reviewed by %s" % (rid, me))
    return rc


# ---------------------------------------------------------------- submit
def cmd_submit(a):
    repo, cfg, build = _ctx(a, ("build_id", "contributor"))
    if not gitops.is_repo(repo):
        return fail("not a git repository")
    if cmd_validate(argparse.Namespace(base=None, data_only=False, allow_review=True, strict=False, build=None)):
        return fail("validation failed; fix the errors above first.")
    status = gitops.run(repo, "status", "--porcelain", "--untracked-files=all")
    changed = [l[3:].strip().strip('"') for l in status.splitlines()]
    db_changes = [c for c in changed if c.startswith("db/")]
    others = [c for c in changed if not c.startswith("db/")]
    if not db_changes:
        return fail("no changes under db/ to submit. Run 'python gtare.py export' first.")
    if others:
        out("note: ignoring changes outside db/ (not included in the contribution): %s" % ", ".join(others[:5]))
    branch = gitops.current_branch(repo)
    if branch in ("main", "master"):
        branch = a.branch or "contrib/%s/%s" % (cfg["contributor"], datetime.datetime.now().strftime("%Y%m%d-%H%M%S"))
        gitops.run(repo, "checkout", "-b", branch)
    gitops.run(repo, "add", "--", "db")
    staged = [l for l in gitops.run(repo, "diff", "--cached", "--name-only").splitlines() if l]
    if any(not f.startswith("db/") for f in staged):
        gitops.run(repo, "reset", "-q")
        return fail("staged files outside db/ detected; aborted. Unstage them and retry.")
    nf = sum("/functions/" in f for f in staged)
    nt = sum("/types/" in f for f in staged)
    ng = sum("/globals/" in f for f in staged)
    msg = a.message or "Add findings: %d function(s), %d type(s), %d global(s) [%s]" % (nf, nt, ng, build["build_id"])
    gitops.run(repo, "commit", "-m", msg)
    out("Committed %d file(s) on branch %s." % (len(staged), branch))
    if a.push:
        gitops.run(repo, "push", "-u", cfg.get("remote", "origin"), branch)
        out("Pushed.")
        if a.pr:
            if not shutil.which("gh"):
                out("Install the GitHub CLI ('gh') or open the PR in your browser from the pushed branch.")
            else:
                subprocess.call(["gh", "pr", "create", "--fill", "--title", msg])
    else:
        out("Next: git push -u %s %s  (or rerun with --push --pr) and open a pull request." % (cfg.get("remote", "origin"), branch))
    return 0


# ---------------------------------------------------------------- main
def build_parser():
    p = argparse.ArgumentParser(prog="gtare", description="GTA VI community reverse-engineering database tool")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="configure local executable + Ghidra project")
    s.add_argument("--exe"), s.add_argument("--ghidra"), s.add_argument("--project-dir")
    s.add_argument("--project-name"), s.add_argument("--program"), s.add_argument("--contributor")
    s.add_argument("--remote"), s.add_argument("--label"), s.add_argument("--image-base")
    s.add_argument("--register-build", action="store_true", help="add this executable's fingerprint to the database")
    s.set_defaults(fn=cmd_init)

    s = sub.add_parser("pull", help="fetch the latest findings and import them into Ghidra")
    s.add_argument("--build"), s.add_argument("--no-git", action="store_true")
    s.add_argument("--full", action="store_true", help="re-apply every record, not just new/changed ones")
    s.add_argument("--no-create", action="store_true", help="do not create functions that do not exist yet")
    s.add_argument("--force", action="store_true", help="overwrite conflicting local work")
    s.add_argument("--allow-hash-mismatch", action="store_true")
    s.add_argument("--bundle-only", action="store_true", help="only write the import bundle (for GUI use)")
    s.add_argument("--apply-report", metavar="FILE", help="record the report of a GUI-run GtareImport.py")
    s.set_defaults(fn=cmd_pull)

    s = sub.add_parser("export", help="export new local findings into db/")
    s.add_argument("--build"), s.add_argument("--snapshot", help="use an existing snapshot instead of running Ghidra")
    s.add_argument("--include-auto", action="store_true", help="also export analysis-derived (auto) findings")
    s.add_argument("--confidence", choices=model.CONFIDENCES, default="low")
    s.add_argument("--no-comments", action="store_true")
    s.add_argument("--force", action="store_true")
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(fn=cmd_export)

    s = sub.add_parser("validate", help="validate schema, safety rules and cross-record consistency")
    s.add_argument("--build"), s.add_argument("--base", help="git ref to diff against (CI)")
    s.add_argument("--data-only", action="store_true", help="fail if files outside db/ changed (needs --base)")
    s.add_argument("--allow-review", action="store_true", help="permit changes that set status 'reviewed'")
    s.add_argument("--strict", action="store_true", help="treat warnings as errors")
    s.set_defaults(fn=cmd_validate)

    s = sub.add_parser("submit", help="validate, create a branch and commit only db/ changes")
    s.add_argument("--build"), s.add_argument("-m", "--message"), s.add_argument("--branch")
    s.add_argument("--push", action="store_true"), s.add_argument("--pr", action="store_true")
    s.set_defaults(fn=cmd_submit)

    s = sub.add_parser("review", help="mark records as independently reviewed (maintainers/reviewers)")
    s.add_argument("ids", nargs="+"), s.add_argument("--build"), s.add_argument("--as", dest="as_handle")
    s.add_argument("--allow-self", action="store_true")
    s.set_defaults(fn=cmd_review)

    s = sub.add_parser("fmt", help="rewrite db/ files in canonical form")
    s.set_defaults(fn=cmd_fmt)

    s = sub.add_parser("stats", help="show how many findings exist per build and status")
    s.set_defaults(fn=cmd_stats)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except (ConfigError, gitops.GitError) as exc:
        return fail(str(exc))
    except KeyboardInterrupt:
        return 130
