# Apply community findings (from an import bundle written by 'gtare pull') to the current program.
# Never overwrites user-defined local work silently: differences are reported as conflicts.
# Written to run under both Jython 2.7 and PyGhidra/Python 3.
# @category GTAVI-RE
import json
import re

from java.util import ArrayList
from ghidra.program.model.data import (CategoryPath, StructureDataType, EnumDataType, TypedefDataType,
                                       DataTypeConflictHandler, DataTypeParser, Structure, Enum, TypeDef)
from ghidra.program.model.listing import ParameterImpl, ReturnParameterImpl, Function
from ghidra.program.model.symbol import SourceType

try:
    text_type = unicode  # noqa: F821 (Jython)
except NameError:
    text_type = str

DEFAULT_NAME = re.compile(r"^(FUN|DAT|LAB|SUB|PTR|UNK)_[0-9a-fA-F]+$")
USER = SourceType.USER_DEFINED

report = {"applied": [], "matched": [], "conflicts": [], "unresolved": []}


def s(x):
    return None if x is None else text_type(x)


def conflict(rid, field, local, community):
    report["conflicts"].append({"id": rid, "field": field, "local": local, "community": community})


def unresolved(rid, reason):
    report["unresolved"].append({"id": rid, "reason": reason})


class Importer(object):
    def __init__(self, prog, bundle):
        self.prog = prog
        self.bundle = bundle
        self.opts = bundle["options"]
        self.force = bool(self.opts.get("force"))
        self.state = bundle.get("state", {})
        self.dtm = prog.getDataTypeManager()
        self.parser = DataTypeParser(self.dtm, self.dtm, None, DataTypeParser.AllowedDataTypes.ALL)
        self.cache = {}
        self.base = prog.getImageBase()
        self.symtab = prog.getSymbolTable()

    # ---- helpers
    def resolve(self, text):
        if text not in self.cache:
            try:
                self.cache[text] = self.parser.parse(text)
            except Exception:
                self.cache[text] = None
        return self.cache[text]

    def prev(self, rid):
        return self.state.get(rid, {})

    def namespace(self, ns):
        cur = self.prog.getGlobalNamespace()
        if ns:
            for seg in ns.split("::"):
                cur = self.symtab.getOrCreateNameSpace(cur, seg, USER)
        return cur

    def addr(self, rva):
        return self.base.add(int(rva, 16))

    # ---- types
    @staticmethod
    def cat(ns):
        return CategoryPath("/gtare" + "".join("/" + p for p in (ns.split("::") if ns else [])))

    def find_type(self, rec):
        dt = self.dtm.getDataType(self.cat(rec.get("namespace", "")), rec["name"])
        return dt

    def render(self, dt):
        if isinstance(dt, Structure):
            parts = ["%x:%s:%s" % (c.getOffset(), c.getFieldName() or "", c.getDataType().getDisplayName())
                     for c in dt.getDefinedComponents()]
            return "struct %d {%s}" % (dt.getLength(), ";".join(parts))
        if isinstance(dt, Enum):
            return "enum %d {%s}" % (dt.getLength(), ";".join(
                "%s=%d" % (n, dt.getValue(n)) for n in sorted([text_type(x) for x in dt.getNames()])))
        if isinstance(dt, TypeDef):
            return "typedef %s" % dt.getDataType().getDisplayName()
        return ""

    def import_types(self):
        recs = self.bundle["types"]
        structs = [r for r in recs if r["kind"] == "struct"]
        shells = {}
        for r in structs:  # pass 1: shells so members can reference each other
            dt = self.find_type(r)
            fresh = dt is None
            if fresh:
                dt = self.dtm.addDataType(StructureDataType(self.cat(r.get("namespace", "")), r["name"], 0),
                                          DataTypeConflictHandler.KEEP_HANDLER)
            shells[r["id"]] = (dt, fresh)
        for r in recs:  # enums
            if r["kind"] == "enum":
                self.import_enum(r)
        pending = [r for r in recs if r["kind"] == "typedef"]
        for _ in range(6):
            pending = [r for r in pending if not self.import_typedef(r, last=False)]
            if not pending:
                break
        for r in pending:
            self.import_typedef(r, last=True)
        for r in structs:
            dt, fresh = shells[r["id"]]
            if not isinstance(dt, Structure):
                conflict(r["id"], "kind", self.render(dt), "struct")
                continue
            self.fill_struct(r, dt, fresh)

    def finish_type(self, r, dt):
        report["applied"].append({"id": r["id"], "name": s(dt.getName()), "sig": self.render(dt), "comment": ""})

    def guard(self, r, dt, desired_sig):
        """True if it is OK to overwrite dt."""
        cur = self.render(dt)
        if cur == desired_sig:
            report["matched"].append({"id": r["id"], "name": s(dt.getName()), "sig": cur, "comment": ""})
            return False
        if self.force or cur in ("", "struct 0 {}") or cur == self.prev(r["id"]).get("sig"):
            return True
        conflict(r["id"], "definition", cur, desired_sig)
        return False

    def import_enum(self, r):
        new = EnumDataType(self.cat(r.get("namespace", "")), r["name"], r["size"])
        for v in r.get("values", []):
            new.add(v["name"], v["value"])
        old = self.find_type(r)
        if old is None:
            self.finish_type(r, self.dtm.addDataType(new, DataTypeConflictHandler.KEEP_HANDLER))
        elif isinstance(old, Enum) and self.guard(r, old, self.render(new)):
            self.finish_type(r, self.dtm.replaceDataType(old, new, True))
        elif not isinstance(old, Enum):
            conflict(r["id"], "kind", self.render(old), "enum")

    def import_typedef(self, r, last):
        target = self.resolve(r["target"])
        if target is None:
            if last:
                unresolved(r["id"], "unknown target type '%s'" % r["target"])
            return False
        new = TypedefDataType(self.cat(r.get("namespace", "")), r["name"], target)
        old = self.find_type(r)
        if old is None:
            self.finish_type(r, self.dtm.addDataType(new, DataTypeConflictHandler.KEEP_HANDLER))
        elif isinstance(old, TypeDef) and self.guard(r, old, self.render(new)):
            self.finish_type(r, self.dtm.replaceDataType(old, new, True))
        elif not isinstance(old, TypeDef):
            conflict(r["id"], "kind", self.render(old), "typedef")
        return True

    def fill_struct(self, r, st, fresh):
        members, ok = [], True
        for m in r.get("members", []):
            dt = self.resolve(m["type"])
            if dt is None or dt.getLength() <= 0:
                unresolved(r["id"], "member at 0x%x: unknown or unsized type '%s'" % (m["offset"], m["type"]))
                ok = False
                continue
            members.append((m["offset"], m.get("name"), dt, m.get("comment")))
        desired = "struct %d {%s}" % (r["size"], ";".join(
            "%x:%s:%s" % (o, n or "", dt.getDisplayName()) for o, n, dt, _ in members))
        if not fresh and not self.guard(r, st, desired):
            return
        st.setPackingEnabled(False)
        st.deleteAll()
        if r["size"] > 0:
            st.growStructure(r["size"] - st.getLength())
        for off, name, dt, comment in members:
            try:
                st.replaceAtOffset(off, dt, dt.getLength(), name, comment)
            except Exception as exc:
                unresolved(r["id"], "member at 0x%x could not be placed: %s" % (off, exc))
                ok = False
        if r.get("comment"):
            st.setDescription(r["comment"])
        if ok:
            self.finish_type(r, st)

    # ---- functions
    def fn_sig(self, ret, conv, params, varargs, noreturn):
        return "%s %s(%s)%s%s" % (ret, conv, ",".join("%s %s" % (t, n or "") for t, n in params),
                                  " varargs" if varargs else "", " noreturn" if noreturn else "")

    def local_sig(self, f):
        params = [(s(p.getDataType().getDisplayName()), s(p.getName()) if p.getSource() != SourceType.DEFAULT else "")
                  for p in f.getParameters() if not p.isAutoParameter()]
        return self.fn_sig(s(f.getReturnType().getDisplayName()), s(f.getCallingConventionName()), params,
                           f.hasVarArgs(), f.hasNoReturn())

    def import_function(self, r):
        rid, prev = r["id"], self.prev(r["id"])
        addr = self.addr(r["rva"])
        if not self.prog.getMemory().contains(addr):
            return unresolved(rid, "address %s (RVA %s) is outside the program's memory" % (addr, r["rva"]))
        f = self.prog.getFunctionManager().getFunctionAt(addr)
        if f is None:
            inside = self.prog.getFunctionManager().getFunctionContaining(addr)
            if inside is not None:
                return unresolved(rid, "RVA %s lies inside function %s, not at its entry" % (r["rva"], inside.getName()))
            if not self.opts.get("create_functions", True):
                return unresolved(rid, "no function at this address (creation disabled)")
            disassemble(addr)  # noqa: F821
            f = createFunction(addr, None)  # noqa: F821
            if f is None:
                return unresolved(rid, "no function here and none could be created (not valid code?)")
        changed, conflicted = False, False

        name, ns = r["name"], r.get("namespace", "")
        want_q = (ns + "::" if ns else "") + name
        cur_q = s(f.getName(True))
        if not DEFAULT_NAME.match(name) and cur_q != want_q:
            local_user = f.getSymbol().getSource() == USER
            if local_user and not self.force and cur_q != prev.get("name"):
                conflict(rid, "name", cur_q, want_q)
                conflicted = True
            else:
                try:
                    f.setParentNamespace(self.namespace(ns))
                    f.setName(name, USER)
                    changed = True
                except Exception as exc:
                    unresolved(rid, "could not rename to '%s': %s" % (want_q, exc))
                    conflicted = True

        proto = r.get("prototype")
        if proto:
            res = self.apply_prototype(rid, f, proto, prev)
            changed, conflicted = changed or res[0], conflicted or res[1]

        comment = r.get("comment")
        if comment:
            cur = s(f.getComment())
            if cur != comment:
                if cur and not self.force and cur != prev.get("comment"):
                    conflict(rid, "comment", cur, comment)
                    conflicted = True
                else:
                    f.setComment(comment)
                    changed = True
        if not conflicted:
            entry = {"id": rid, "name": s(f.getName(True)), "sig": self.local_sig(f) if proto else "",
                     "comment": s(f.getComment()) or ""}
            report["applied" if changed else "matched"].append(entry)

    def apply_prototype(self, rid, f, proto, prev):
        ret_dt = f.getReturnType()
        if proto.get("return_type"):
            ret_dt = self.resolve(proto["return_type"])
            if ret_dt is None:
                unresolved(rid, "unknown return type '%s'" % proto["return_type"])
                return (False, True)
        params = []
        for p in proto.get("params", []):
            dt = self.resolve(p["type"])
            if dt is None:
                unresolved(rid, "unknown parameter type '%s'" % p["type"])
                return (False, True)
            params.append((dt, p.get("name")))
        conv = proto.get("calling_convention") or s(f.getCallingConventionName())
        if proto.get("calling_convention") and self.prog.getCompilerSpec().getCallingConvention(conv) is None:
            unresolved(rid, "calling convention '%s' is not defined by this program's compiler spec" % conv)
            conv = s(f.getCallingConventionName())
        varargs = bool(proto.get("varargs", f.hasVarArgs()))
        noreturn = bool(proto.get("noreturn", f.hasNoReturn()))
        want = self.fn_sig(s(ret_dt.getDisplayName()), conv, [(s(d.getDisplayName()), n) for d, n in params],
                           varargs, noreturn)
        cur = self.local_sig(f)
        if cur == want:
            return (False, False)
        if f.getSignatureSource() == USER and not self.force and cur != prev.get("sig"):
            conflict(rid, "signature", cur, want)
            return (False, True)
        plist = ArrayList()
        for dt, n in params:
            plist.add(ParameterImpl(n, dt, self.prog))
        try:
            f.updateFunction(conv, ReturnParameterImpl(ret_dt, self.prog), plist,
                             Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, True, USER)
            f.setVarArgs(varargs)
            f.setNoReturn(noreturn)
        except Exception as exc:
            unresolved(rid, "could not apply signature: %s" % exc)
            return (False, True)
        return (True, False)

    # ---- globals
    def import_global(self, r):
        rid, prev = r["id"], self.prev(r["id"])
        addr = self.addr(r["rva"])
        if not self.prog.getMemory().contains(addr):
            return unresolved(rid, "address %s (RVA %s) is outside the program's memory" % (addr, r["rva"]))
        changed, conflicted = False, False
        name, ns = r["name"], r.get("namespace", "")
        want_q = (ns + "::" if ns else "") + name
        sym = self.symtab.getPrimarySymbol(addr)
        cur_q = s(sym.getName(True)) if sym is not None else None
        if cur_q != want_q:
            if sym is not None and sym.getSource() == USER and not self.force and cur_q != prev.get("name"):
                conflict(rid, "name", cur_q, want_q)
                conflicted = True
            else:
                try:
                    if sym is not None:
                        sym.setNameAndNamespace(name, self.namespace(ns), USER)
                    else:
                        self.symtab.createLabel(addr, name, self.namespace(ns), USER).setPrimary()
                    changed = True
                except Exception as exc:
                    unresolved(rid, "could not name data '%s': %s" % (want_q, exc))
                    conflicted = True
        if r.get("type"):
            dt = self.resolve(r["type"])
            listing = self.prog.getListing()
            data = listing.getDefinedDataAt(addr)
            if dt is None or dt.getLength() <= 0:
                unresolved(rid, "unknown or unsized type '%s'" % r["type"])
                conflicted = True
            elif data is None or s(data.getDataType().getDisplayName()) != s(dt.getDisplayName()):
                cur_t = s(data.getDataType().getDisplayName()) if data is not None else None
                if data is not None and not s(cur_t).startswith("undefined") and not self.force and cur_t != prev.get("sig"):
                    conflict(rid, "type", cur_t, s(dt.getDisplayName()))
                    conflicted = True
                else:
                    try:
                        listing.clearCodeUnits(addr, addr.add(dt.getLength() - 1), False)
                        listing.createData(addr, dt)
                        changed = True
                    except Exception as exc:
                        unresolved(rid, "could not apply type '%s': %s" % (r["type"], exc))
                        conflicted = True
        if not conflicted:
            report["applied" if changed else "matched"].append(
                {"id": rid, "name": want_q, "sig": r.get("type", ""), "comment": ""})


def main():
    prog = currentProgram  # noqa: F821
    args = getScriptArgs()  # noqa: F821
    if len(args) >= 2:
        bundle_path, report_path = str(args[0]), str(args[1])
    else:
        bundle_path = str(askFile("Import bundle (from 'gtare pull --bundle-only')", "Open").getAbsolutePath())  # noqa: F821
        report_path = str(askFile("Where to write the report", "Save").getAbsolutePath())  # noqa: F821
    with open(bundle_path, "rb") as fh:
        bundle = json.loads(fh.read().decode("utf-8"))
    want = bundle["build"]["sha256"]
    have = s(prog.getExecutableSHA256())
    if have and have.lower() != want and not bundle["options"].get("allow_hash_mismatch"):
        raise Exception("GTARE: this program's SHA-256 (%s...) does not match build %s (%s...). Refusing to import "
                        "findings for a different executable version." % (have[:12], bundle["build"]["build_id"], want[:12]))
    imp = Importer(prog, bundle)
    imp.import_types()
    for r in bundle["functions"]:
        try:
            imp.import_function(r)
        except Exception as exc:
            unresolved(r["id"], "unexpected error: %s" % exc)
    for r in bundle["globals"]:
        try:
            imp.import_global(r)
        except Exception as exc:
            unresolved(r["id"], "unexpected error: %s" % exc)
    with open(report_path, "wb") as fh:
        fh.write(json.dumps(report, sort_keys=True, indent=1).encode("ascii"))
    print("GTARE: applied %d, matched %d, conflicts %d, unresolved %d" % (
        len(report["applied"]), len(report["matched"]), len(report["conflicts"]), len(report["unresolved"])))
    print("GTARE: remember to save the program if you ran this from the GUI.")


main()
