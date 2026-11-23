"""Canonical serialisation: identical findings always produce identical bytes."""
import hashlib
import json
import re

RVA_RE = re.compile(r"^0x[0-9a-f]{8}$")

# Fields that describe provenance rather than the finding itself. Changing them
# alone never counts as a modification of a finding.
META_KEYS = {"schema", "id", "kind", "status", "confidence", "contributor",
             "updated_by", "reviewed_by", "tags", "_path"}


def dumps(obj):
    return json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=True) + "\n"


def fmt_rva(value):
    return "0x%08x" % value


def parse_rva(text):
    if not isinstance(text, str) or not RVA_RE.match(text):
        raise ValueError("RVA must look like 0x0012ab40 (8 lowercase hex digits), got %r" % (text,))
    return int(text, 16)


def content(rec):
    return {k: v for k, v in rec.items() if k not in META_KEYS and not k.startswith("x-")}


def content_hash(rec):
    return hashlib.sha256(dumps(content(rec)).encode("ascii")).hexdigest()[:16]


def prune(obj):
    """Remove None / empty values recursively so optional fields stay absent."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            v = prune(v)
            if v is None or v == "" or v == [] or v == {}:
                continue
            out[k] = v
        return out
    if isinstance(obj, list):
        return [prune(v) for v in obj]
    return obj


def record_id(kind, rec):
    if kind == "function":
        return "fn:" + rec["rva"]
    if kind == "global":
        return "gv:" + rec["rva"]
    ns = rec.get("namespace", "")
    return "type:" + (ns + "::" if ns else "") + rec["name"]
