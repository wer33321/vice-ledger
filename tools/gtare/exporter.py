"""Turn a Ghidra snapshot into minimal, deterministic database changes."""
import json
import os
from collections import namedtuple

from . import SCHEMA_VERSION, canon, model, safety, store
from .importer import load_state

Plan = namedtuple("Plan", "new modified unchanged stale protected invalid")


def _status_for(source, include_auto):
    if source == "USER_DEFINED":
        return "manual"
    if include_auto and source in ("ANALYSIS", "IMPORTED"):
        return "auto"
    return None


def snapshot_to_records(snap, contributor, confidence, include_auto=False, comments=True):
    """Returns (records, skipped) where skipped is a list of (what, reason)."""
    records, skipped = [], []

    def finish(kind, rec, status, label):
        rec.update({"schema": SCHEMA_VERSION, "kind": kind, "status": status,
                    "confidence": confidence if status == "manual" else "low", "contributor": contributor})
        if rec.get("comment"):
            if not comments:
                del rec["comment"]
            else:
                bad = safety.check_text("comment", rec["comment"])
                if bad:
                    skipped.append((label + " (comment only)", "comment dropped: it " + "; ".join(bad)))
                    del rec["comment"]
        rec = canon.prune(rec)
        rec["id"] = canon.record_id(kind, rec) if "name" in rec else None
        records.append(rec)

    for f in snap.get("functions", []):
        label = "function 0x%08x %s" % (f["rva"], f.get("name", ""))
        name_status = _status_for(f.get("name_source"), include_auto)
        sig_status = _status_for(f.get("sig_source"), include_auto)
        status = "manual" if "manual" in (name_status, sig_status) else (name_status or sig_status)
        if status is None:
            continue
        rec = {"rva": canon.fmt_rva(f["rva"]), "name": f["name"], "namespace": f.get("namespace", ""),
               "comment": f.get("comment"), "size": f.get("size")}
        if sig_status:
            rec["prototype"] = f.get("prototype")
        finish("function", rec, status, label)
    for g in snap.get("globals", []):
        status = _status_for(g.get("name_source"), include_auto)
        if status:
            finish("global", {"rva": canon.fmt_rva(g["rva"]), "name": g["name"], "namespace": g.get("namespace", ""),
                              "type": g.get("type"), "size": g.get("size"), "comment": g.get("comment")},
                   status, "global 0x%08x %s" % (g["rva"], g["name"]))
    for t in snap.get("types", []):
        label = "type %s" % t.get("name")
        if not model.NAME_RE.match(t.get("name", "")) or not model.NS_RE.match(t.get("namespace", "")):
            skipped.append((label, "name/category is not a plain identifier path (templates/spaces are not supported yet)"))
            continue
        rec = {"name": t["name"], "namespace": t.get("namespace", ""), "comment": t.get("comment")}
        kind = t["kind"]
        if kind == "struct":
            rec["size"] = t["size"]
            rec["members"] = sorted(t.get("members", []), key=lambda m: m["offset"])
            if "size" not in rec:
                rec["size"] = 0
        elif kind == "enum":
            rec["size"] = t["size"]
            rec["values"] = sorted(t.get("values", []), key=lambda v: (v["value"], v["name"]))
        else:
            rec["target"] = t["target"]
        finish(kind, rec, "manual", label)
    return records, skipped


def plan_changes(repo, build_id, records, contributor, force=False):
    existing, _ = store.load_records(repo, build_id)
    state = load_state(repo, build_id)["records"]
    new, modified, unchanged, stale, protected, invalid = [], [], [], [], [], []
    for rec in records:
        errs = [] if rec["id"] else ["missing name"]
        errs += model.validate_record(rec) if not errs else []
        if errs:
            invalid.append((rec.get("id") or rec.get("name"), errs))
            continue
        old = existing.get(rec["id"])
        if old is None:
            new.append(rec)
        elif canon.content_hash(old) == canon.content_hash(rec):
            unchanged.append(rec)
        elif old["status"] == "reviewed" and not force:
            protected.append((rec, old))
        elif state.get(rec["id"], {}).get("hash") != canon.content_hash(old) and not force:
            stale.append((rec, old))
        else:
            merged = dict(rec)
            merged["contributor"] = old["contributor"]
            if contributor != old["contributor"]:
                merged["updated_by"] = contributor
            if old["status"] != "auto":
                merged["confidence"] = old["confidence"]
            if old.get("tags"):
                merged["tags"] = old["tags"]
            modified.append(merged)
    return Plan(new, modified, unchanged, stale, protected, invalid)


def write_plan(repo, build_id, plan):
    paths = []
    for rec in plan.new + plan.modified:
        path = store.record_path(repo, build_id, rec)
        store.write_json(path, rec)
        paths.append(path)
    return paths
