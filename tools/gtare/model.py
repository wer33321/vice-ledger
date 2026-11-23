"""Explicit schema validation for build and finding records (schema version 1)."""
import re

from . import SCHEMA_VERSION, canon, safety

SEG = r"[A-Za-z_][A-Za-z0-9_]*"
NAME_RE = re.compile(r"^%s$" % SEG)                    # type names (also used as file names)
NS_RE = re.compile(r"^(%s(::%s)*)?$" % (SEG, SEG))
SYMBOL_RE = re.compile(r"^[A-Za-z_~?@$][A-Za-z0-9_~?@$.<>,]{0,254}$")  # function/global names (may be mangled)
TYPE_REF_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_:<>, *\[\]()&]{0,199}$")
CONV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,31}$")
HANDLE_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
TAG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
BUILD_RE = re.compile(r"^b-[0-9a-f]{16}$")
HEX_RE = re.compile(r"^[0-9a-f]{64}$")

STATUSES = ("auto", "manual", "reviewed")
CONFIDENCES = ("low", "medium", "high")
KINDS = ("function", "global", "struct", "enum", "typedef")
COMMON = {"schema", "id", "kind", "status", "confidence", "contributor", "updated_by",
          "reviewed_by", "tags", "comment"}
ALLOWED = {
    "function": COMMON | {"rva", "name", "namespace", "prototype", "size"},
    "global": COMMON | {"rva", "name", "namespace", "type", "size"},
    "struct": COMMON | {"name", "namespace", "size", "members", "bases", "vtable"},
    "enum": COMMON | {"name", "namespace", "size", "values"},
    "typedef": COMMON | {"name", "namespace", "target"},
}
BUILTIN_TYPE = re.compile(r"^(?:void|bool|char|wchar_t|short|int|long|float|double|byte|word|dword|qword|"
                          r"u?int\d*(?:_t)?|undefined\d*|unsigned.*|signed.*|[A-Z][A-Z0-9_]*|string|"
                          r"pointer\d*|longlong|ulonglong|uchar|ushort|uint|ulong|size_t)$")


def _keys(obj, allowed, where, errs):
    for k in obj:
        if k not in allowed and not str(k).startswith("x-"):
            errs.append("%sunknown field '%s' (custom fields must start with 'x-')" % (where, k))


def _match(obj, key, rx, where, errs, required=True, what=None):
    val = obj.get(key)
    if val is None:
        if required:
            errs.append("%smissing required field '%s'" % (where, key))
        return None
    if not isinstance(val, str) or not rx.match(val):
        errs.append("%sfield '%s' has invalid value %r%s" % (where, key, val, (" (" + what + ")") if what else ""))
        return None
    return val


def _int(obj, key, where, errs, required=False, lo=0, hi=0x7FFFFFFF):
    val = obj.get(key)
    if val is None:
        if required:
            errs.append("%smissing required field '%s'" % (where, key))
        return None
    if isinstance(val, bool) or not isinstance(val, int) or not (lo <= val <= hi):
        errs.append("%sfield '%s' must be an integer between %d and %d" % (where, key, lo, hi))
        return None
    return val


def validate_build(b):
    errs = []
    if not isinstance(b, dict):
        return ["build.json must contain a JSON object"]
    _keys(b, {"schema", "build_id", "sha256", "image_base", "file_size", "label", "platform"}, "", errs)
    if b.get("schema") != SCHEMA_VERSION:
        errs.append("unsupported 'schema' %r (this tool understands %d)" % (b.get("schema"), SCHEMA_VERSION))
    bid = _match(b, "build_id", BUILD_RE, "", errs, what="expected b-<first 16 hex digits of sha256>")
    sha = _match(b, "sha256", HEX_RE, "", errs, what="64 lowercase hex digits")
    if bid and sha and bid != "b-" + sha[:16]:
        errs.append("build_id does not match sha256 (expected b-%s)" % sha[:16])
    _match(b, "image_base", re.compile(r"^0x[0-9a-f]{1,16}$"), "", errs)
    _int(b, "file_size", "", errs, required=True, lo=1, hi=1 << 40)
    for k in ("label", "platform"):
        if k in b and (not isinstance(b[k], str) or len(b[k]) > 100):
            errs.append("field '%s' must be a string up to 100 characters" % k)
    return errs


def validate_record(rec):
    """Validate one finding record. Returns a list of error strings."""
    errs = []
    if not isinstance(rec, dict):
        return ["record must be a JSON object"]
    kind = rec.get("kind")
    if kind not in KINDS:
        return ["field 'kind' must be one of %s" % ", ".join(KINDS)]
    _keys(rec, ALLOWED[kind], "", errs)
    sv = rec.get("schema")
    if sv != SCHEMA_VERSION:
        if isinstance(sv, int) and sv > SCHEMA_VERSION:
            errs.append("record uses schema %d, newer than this tool (%d); update the tooling" % (sv, SCHEMA_VERSION))
        else:
            errs.append("field 'schema' must be %d" % SCHEMA_VERSION)
    if rec.get("status") not in STATUSES:
        errs.append("field 'status' must be one of %s" % ", ".join(STATUSES))
    if rec.get("confidence") not in CONFIDENCES:
        errs.append("field 'confidence' must be one of %s" % ", ".join(CONFIDENCES))
    _match(rec, "contributor", HANDLE_RE, "", errs, what="GitHub handle")
    if "updated_by" in rec:
        _match(rec, "updated_by", HANDLE_RE, "", errs, what="GitHub handle")
    if rec.get("status") == "reviewed":
        _match(rec, "reviewed_by", HANDLE_RE, "", errs, what="status 'reviewed' needs a reviewer handle")
    elif "reviewed_by" in rec:
        errs.append("'reviewed_by' is only allowed when status is 'reviewed'")
    tags = rec.get("tags", [])
    if not isinstance(tags, list) or len(tags) > 10 or any(not isinstance(t, str) or not TAG_RE.match(t) for t in tags) \
            or tags != sorted(set(tags)):
        errs.append("field 'tags' must be a sorted, unique list of up to 10 lowercase-kebab strings")
    if "comment" in rec and not isinstance(rec["comment"], str):
        errs.append("field 'comment' must be a string")

    if kind in ("function", "global"):
        rva = rec.get("rva")
        try:
            canon.parse_rva(rva)
        except ValueError as exc:
            errs.append("field 'rva': %s" % exc)
        _match(rec, "name", SYMBOL_RE, "", errs)
        _match(rec, "namespace", NS_RE, "", errs, required=False, what="use A::B::C")
        _int(rec, "size", "", errs, lo=1, hi=0x10000000)
    else:
        _match(rec, "name", NAME_RE, "", errs, what="letters, digits and underscores only")
        _match(rec, "namespace", NS_RE, "", errs, required=False, what="use A::B::C")
    if not any(e.startswith(("field 'rva'", "field 'name'", "field 'namespace'", "missing")) for e in errs):
        expected = canon.record_id(kind, rec)
        if rec.get("id") != expected:
            errs.append("field 'id' is %r but must be %r" % (rec.get("id"), expected))

    if kind == "function" and "prototype" in rec:
        _prototype(rec["prototype"], errs)
    elif kind == "global" and "type" in rec:
        _match(rec, "type", TYPE_REF_RE, "", errs)
    elif kind == "struct":
        _struct(rec, errs)
    elif kind == "enum":
        _enum(rec, errs)
    elif kind == "typedef":
        _match(rec, "target", TYPE_REF_RE, "", errs)

    errs.extend("%s" % e for e in safety.check_record_text(rec))
    return errs


def _prototype(p, errs):
    w = "prototype: "
    if not isinstance(p, dict):
        errs.append(w + "must be an object")
        return
    _keys(p, {"return_type", "calling_convention", "params", "varargs", "noreturn"}, w, errs)
    _match(p, "return_type", TYPE_REF_RE, w, errs, required=False)
    _match(p, "calling_convention", CONV_RE, w, errs, required=False)
    for flag in ("varargs", "noreturn"):
        if flag in p and not isinstance(p[flag], bool):
            errs.append(w + "'%s' must be true or false" % flag)
    params = p.get("params", [])
    if not isinstance(params, list) or len(params) > 64:
        errs.append(w + "'params' must be a list of at most 64 entries")
        return
    for i, prm in enumerate(params):
        ww = "prototype.params[%d]: " % i
        if not isinstance(prm, dict):
            errs.append(ww + "must be an object")
            continue
        _keys(prm, {"name", "type"}, ww, errs)
        _match(prm, "name", NAME_RE, ww, errs, required=False)
        _match(prm, "type", TYPE_REF_RE, ww, errs)


def _struct(rec, errs):
    size = _int(rec, "size", "", errs, required=True, hi=0x1000000)
    members = rec.get("members", [])
    if not isinstance(members, list):
        errs.append("field 'members' must be a list")
        return
    last_end, last_off = 0, -1
    for i, m in enumerate(members):
        w = "members[%d]: " % i
        if not isinstance(m, dict):
            errs.append(w + "must be an object")
            continue
        _keys(m, {"offset", "name", "type", "size", "comment"}, w, errs)
        off = _int(m, "offset", w, errs, required=True, hi=0x1000000)
        _match(m, "name", NAME_RE, w, errs, required=False)
        _match(m, "type", TYPE_REF_RE, w, errs)
        msz = _int(m, "size", w, errs, lo=1, hi=0x1000000)
        if "comment" in m and not isinstance(m["comment"], str):
            errs.append(w + "'comment' must be a string")
        if off is None:
            continue
        if off < last_off or (off == last_off and i):
            errs.append(w + "members must be sorted by strictly increasing offset (offset 0x%x)" % off)
        if off < last_end:
            errs.append(w + "offset 0x%x overlaps the previous member" % off)
        end = off + (msz or 0)
        if size is not None and end > size:
            errs.append(w + "member ends at 0x%x, beyond struct size 0x%x" % (end, size))
        last_off, last_end = off, max(last_end, end)
    names = [m.get("name") for m in members if isinstance(m, dict) and m.get("name")]
    if len(names) != len(set(names)):
        errs.append("duplicate member names in struct")
    for b in rec.get("bases", []) if isinstance(rec.get("bases", []), list) else []:
        if not isinstance(b, str) or not TYPE_REF_RE.match(b):
            errs.append("field 'bases' contains an invalid type name %r" % (b,))
    if "vtable" in rec:
        try:
            canon.parse_rva(rec["vtable"])
        except ValueError as exc:
            errs.append("field 'vtable': %s" % exc)


def _enum(rec, errs):
    _int(rec, "size", "", errs, required=True, lo=1, hi=8)
    vals = rec.get("values", [])
    if not isinstance(vals, list):
        errs.append("field 'values' must be a list")
        return
    keys = []
    for i, v in enumerate(vals):
        w = "values[%d]: " % i
        if not isinstance(v, dict):
            errs.append(w + "must be an object")
            continue
        _keys(v, {"name", "value"}, w, errs)
        _match(v, "name", NAME_RE, w, errs)
        val = _int(v, "value", w, errs, required=True, lo=-(1 << 63), hi=(1 << 64) - 1)
        keys.append((val if val is not None else 0, v.get("name") or ""))
    if keys != sorted(keys):
        errs.append("enum values must be sorted by (value, name)")
    if len({k[1] for k in keys}) != len(keys):
        errs.append("duplicate enum value names")
