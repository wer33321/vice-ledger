"""Build import bundles for Ghidra and track what was applied (incremental imports).

Local state (.gtare/state/<build>.json, never committed) remembers, per record,
the content hash that was last applied plus the name/signature/comment as they
looked in Ghidra right afterwards. That lets the next import tell the difference
between "Ghidra still has what we put there" (safe to update) and "the user
changed it" (conflict, never silently overwritten).
"""
import json
import os

from . import canon, config, store

BUNDLE_SCHEMA = 1


def state_path(repo, build_id):
    d = os.path.join(config.state_dir(repo), "state")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, build_id + ".json")


def load_state(repo, build_id):
    path = state_path(repo, build_id)
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    return {"records": {}}


def save_state(repo, build_id, state):
    with open(state_path(repo, build_id), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(canon.dumps(state))


def build_bundle(repo, build, full=False, create_functions=True, force=False, allow_hash_mismatch=False):
    recs, _ = store.load_records(repo, build["build_id"])
    state = load_state(repo, build["build_id"])["records"]
    todo = {"types": [], "functions": [], "globals": []}
    skipped_unchanged = 0
    for rid in sorted(recs):
        rec = {k: v for k, v in recs[rid].items() if k != "_path"}
        h = canon.content_hash(rec)
        if not full and state.get(rid, {}).get("hash") == h:
            skipped_unchanged += 1
            continue
        group = {"function": "functions", "global": "globals"}.get(rec["kind"], "types")
        todo[group].append(rec)
    return {
        "bundle_schema": BUNDLE_SCHEMA,
        "build": build,
        "options": {"create_functions": create_functions, "force": force,
                    "allow_hash_mismatch": allow_hash_mismatch},
        "state": {rid: v for rid, v in state.items()},
        "skipped_unchanged": skipped_unchanged,
        **todo,
    }


def apply_report(repo, build_id, bundle, report):
    """Update local state from the script's report. Returns a printable summary dict."""
    st = load_state(repo, build_id)
    by_id = {r["id"]: r for g in ("types", "functions", "globals") for r in bundle[g]}
    for item in report.get("applied", []) + report.get("matched", []):
        rec = by_id.get(item["id"])
        if rec:
            st["records"][item["id"]] = {"hash": canon.content_hash(rec), "name": item.get("name", ""),
                                         "sig": item.get("sig", ""), "comment": item.get("comment", "")}
    save_state(repo, build_id, st)
    return {k: len(report.get(k, [])) for k in ("applied", "matched", "conflicts", "unresolved")}
