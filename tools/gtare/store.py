"""On-disk layout of the database and cross-record validation.

db/builds/<build_id>/build.json
db/builds/<build_id>/functions/<rva[0:4]>/<rva>.json     one file per function
db/builds/<build_id>/globals/<rva[0:4]>/<rva>.json
db/builds/<build_id>/types/<Namespace>/<Name>.json       one file per type

One file per finding, in a directory sharded by address, means two contributors
only ever conflict when they edit the *same* finding.
"""
import json
import os
import re

from . import canon, model

KIND_DIR = {"function": "functions", "global": "globals", "struct": "types", "enum": "types", "typedef": "types"}


def build_dir(repo, build_id):
    return os.path.join(repo, "db", "builds", build_id)


def list_builds(repo):
    root = os.path.join(repo, "db", "builds")
    return sorted(d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d))) if os.path.isdir(root) else []


def load_build(repo, build_id):
    path = os.path.join(build_dir(repo, build_id), "build.json")
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(canon.dumps(obj))


def expected_relpath(rec):
    k = rec["kind"]
    if k in ("function", "global"):
        r = rec["rva"]
        return "%s/%s/%s.json" % (KIND_DIR[k], r[2:6], r[2:])
    ns = rec.get("namespace", "")
    parts = ns.split("::") if ns else []
    return "/".join(["types"] + parts + [rec["name"] + ".json"])


def record_path(repo, build_id, rec):
    return os.path.join(build_dir(repo, build_id), *expected_relpath(rec).split("/"))


def iter_record_files(repo, build_id):
    base = build_dir(repo, build_id)
    for sub in ("functions", "globals", "types"):
        for root, _dirs, files in os.walk(os.path.join(base, sub)):
            for f in sorted(files):
                yield os.path.join(root, f)


def load_records(repo, build_id):
    """Return (records_by_id, errors). Errors are (path, message)."""
    recs, errs = {}, []
    for path in iter_record_files(repo, build_id):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                rec = json.load(fh)
        except (ValueError, UnicodeDecodeError) as exc:
            errs.append((path, "not valid JSON: %s" % exc))
            continue
        if isinstance(rec, dict) and "id" in rec:
            if rec["id"] in recs:
                errs.append((path, "duplicate id %s" % rec["id"]))
            recs[rec["id"]] = rec
            rec["_path"] = path
    return recs, errs


def check_database(repo, only_builds=None):
    """Validate every build. Returns (errors, warnings) as lists of (path, message)."""
    errors, warnings = [], []
    for bid in (only_builds or list_builds(repo)):
        bpath = os.path.join(build_dir(repo, bid), "build.json")
        try:
            build = load_build(repo, bid)
        except ValueError as exc:
            errors.append((bpath, "not valid JSON: %s" % exc))
            continue
        if build is None:
            errors.append((build_dir(repo, bid), "missing build.json"))
            continue
        for e in model.validate_build(build):
            errors.append((bpath, e))
        if build.get("build_id") != bid:
            errors.append((bpath, "directory name %r does not match build_id %r" % (bid, build.get("build_id"))))
        _check_build_records(repo, bid, errors, warnings)
    return errors, warnings


def _check_build_records(repo, bid, errors, warnings):
    base = build_dir(repo, bid)
    seen_lower = {}
    valid = []
    for path in iter_record_files(repo, bid):
        rel = os.path.relpath(path, base).replace(os.sep, "/")
        try:
            with open(path, "r", encoding="utf-8") as fh:
                rec = json.load(fh)
        except (ValueError, UnicodeDecodeError) as exc:
            errors.append((path, "not valid JSON: %s" % exc))
            continue
        errs = model.validate_record(rec)
        for e in errs:
            errors.append((path, e))
        if errs:
            continue
        want = expected_relpath(rec)
        if rel != want:
            errors.append((path, "record belongs at %s (path must be derived from its address/name)" % want))
        if want.lower() in seen_lower:
            errors.append((path, "case-insensitive path clash with %s" % seen_lower[want.lower()]))
        seen_lower[want.lower()] = rel
        raw = open(path, "r", encoding="utf-8", newline="").read()
        if raw != canon.dumps(rec):
            errors.append((path, "not in canonical form; run 'python gtare.py fmt' to rewrite it"))
        valid.append((path, rec))

    type_names = {(r.get("namespace", ""), r["name"]) for _, r in valid if r["kind"] in ("struct", "enum", "typedef")}
    simple_types = {n for _, n in type_names}
    qual_seen = {}
    funcs = []
    for path, rec in valid:
        if rec["kind"] == "function":
            proto = rec.get("prototype", {})
            key = (rec.get("namespace", ""), rec["name"], tuple(p["type"] for p in proto.get("params", [])))
            if key in qual_seen and not rec["name"].startswith("FUN_"):
                errors.append((path, "duplicate definition of %s%s: also at %s (same name and parameter types)" % (
                    (key[0] + "::") if key[0] else "", key[1], qual_seen[key])))
            qual_seen[key] = os.path.relpath(path, base).replace(os.sep, "/")
            if "size" in rec:
                funcs.append((int(rec["rva"], 16), rec["size"], path))
        for ref in _type_refs(rec):
            if ref not in simple_types and not model.BUILTIN_TYPE.match(ref):
                warnings.append((path, "type '%s' is not defined in this build's database (fine if it is a Ghidra built-in)" % ref))
    funcs.sort()
    for (a, asz, _), (b, _bsz, bpath) in zip(funcs, funcs[1:]):
        if a + asz > b:
            warnings.append((bpath, "function at 0x%08x overlaps the previous function (0x%08x + %d)" % (b, a, asz)))


def _base_type(ref):
    ref = re.sub(r"\b(const|volatile|struct|enum|union)\b", "", ref)
    ref = re.sub(r"(\*|\[\d+\]|&)", "", ref).strip()
    return ref.split("::")[-1].strip()


def _type_refs(rec):
    refs = []
    if rec["kind"] == "function":
        p = rec.get("prototype", {})
        refs += [p.get("return_type")] + [x["type"] for x in p.get("params", [])]
    elif rec["kind"] == "global":
        refs.append(rec.get("type"))
    elif rec["kind"] == "struct":
        refs += [m["type"] for m in rec.get("members", [])] + list(rec.get("bases", []))
    elif rec["kind"] == "typedef":
        refs.append(rec.get("target"))
    out = []
    for r in refs:
        if r:
            b = _base_type(r)
            if b and "(" not in b and "<" not in b:
                out.append(b)
    return out
