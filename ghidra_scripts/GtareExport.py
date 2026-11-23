# Export user-authored findings from the current program to a snapshot JSON file.
# Run via 'python gtare.py export' (headless) or Script Manager (GUI).
# Written to run under both Jython 2.7 and PyGhidra/Python 3.
# The snapshot holds names, types and layouts only - no bytes, no listings, no decompiler output.
# @category GTAVI-RE
import json

from ghidra.framework import Application
from ghidra.program.model.data import Structure, Enum, TypeDef, ArchiveType
from ghidra.program.model.symbol import SourceType, SymbolType

try:
    text_type = unicode  # noqa: F821 (Jython)
except NameError:
    text_type = str


def s(x):
    return None if x is None else text_type(x)


def ns_of(sym_or_func_parent):
    """'A::B' for a namespace, '' for global."""
    if sym_or_func_parent is None or sym_or_func_parent.isGlobal():
        return ""
    return s(sym_or_func_parent.getName(True))


def src(source):
    return s(source.toString()) if source is not None else "DEFAULT"


def export_functions(prog, base):
    out = []
    for f in prog.getFunctionManager().getFunctions(True):
        if f.isExternal():
            continue
        name_src, sig_src = src(f.getSymbol().getSource()), src(f.getSignatureSource())
        comment = s(f.getComment())
        if name_src == "DEFAULT" and sig_src == "DEFAULT":
            continue
        params = []
        for p in f.getParameters():
            if p.isAutoParameter():
                continue
            entry = {"type": s(p.getDataType().getDisplayName())}
            if src(p.getSource()) != "DEFAULT":
                entry["name"] = s(p.getName())
            params.append(entry)
        proto = {"return_type": s(f.getReturnType().getDisplayName()), "params": params}
        conv = s(f.getCallingConventionName())
        if conv and conv not in ("unknown", "default"):
            proto["calling_convention"] = conv
        if f.hasVarArgs():
            proto["varargs"] = True
        if f.hasNoReturn():
            proto["noreturn"] = True
        out.append({
            "rva": f.getEntryPoint().getOffset() - base,
            "name": s(f.getName()),
            "namespace": ns_of(f.getParentNamespace()),
            "name_source": name_src, "sig_source": sig_src,
            "comment": comment, "size": int(f.getBody().getNumAddresses()),
            "prototype": proto,
        })
    return out


def export_globals(prog, base):
    out = []
    for d in prog.getListing().getDefinedData(True):
        sym = d.getPrimarySymbol()
        if sym is None or sym.getSymbolType() != SymbolType.LABEL or sym.getSource() == SourceType.DEFAULT:
            continue
        if sym.isExternal():
            continue
        out.append({
            "rva": d.getMinAddress().getOffset() - base,
            "name": s(sym.getName()), "namespace": ns_of(sym.getParentNamespace()),
            "name_source": src(sym.getSource()),
            "type": s(d.getDataType().getDisplayName()), "size": int(d.getLength()),
            "comment": s(d.getComment(0)),
        })
    return out


def category_namespace(dt):
    path = s(dt.getCategoryPath().getPath())  # e.g. /gtare/Engine/Core
    parts = [p for p in path.split("/") if p]
    if parts and parts[0] == "gtare":
        parts = parts[1:]
    return "::".join(parts)


AUTO_CATEGORIES = ("Demangler", "ClassDataTypes", "PE", "DWARF", "ELF", "DOS", "PDB", "COFF", "Mach-O")  # created by loaders/analyzers


def export_types(prog):
    out = []
    dtm = prog.getDataTypeManager()
    for dt in dtm.getAllDataTypes():
        sa = dt.getSourceArchive()
        if sa is not None and sa.getArchiveType() != ArchiveType.PROGRAM:
            continue  # came from a Ghidra/Windows data type archive
        top = [p for p in s(dt.getCategoryPath().getPath()).split("/") if p][:1]
        if top and top[0] in AUTO_CATEGORIES:
            continue
        base = {"name": s(dt.getName()), "namespace": category_namespace(dt)}
        if isinstance(dt, Structure):
            if dt.isNotYetDefined():
                continue
            members = []
            for c in dt.getDefinedComponents():
                m = {"offset": int(c.getOffset()), "type": s(c.getDataType().getDisplayName()),
                     "size": int(c.getLength())}
                if c.getFieldName() is not None:
                    m["name"] = s(c.getFieldName())
                if c.getComment():
                    m["comment"] = s(c.getComment())
                members.append(m)
            base.update({"kind": "struct", "size": int(dt.getLength()), "members": members,
                         "comment": s(dt.getDescription())})
        elif isinstance(dt, Enum):
            base.update({"kind": "enum", "size": int(dt.getLength()),
                         "values": [{"name": s(n), "value": int(dt.getValue(n))} for n in dt.getNames()],
                         "comment": s(dt.getDescription())})
        elif isinstance(dt, TypeDef):
            base.update({"kind": "typedef", "target": s(dt.getDataType().getDisplayName())})
        else:
            continue
        out.append(base)
    return out


def main():
    prog = currentProgram  # noqa: F821
    args = getScriptArgs()  # noqa: F821
    if len(args) >= 1:
        path = str(args[0])
    else:
        path = str(askFile("Snapshot output file", "Save").getAbsolutePath())  # noqa: F821
    base = prog.getImageBase().getOffset()
    snap = {
        "snapshot_schema": 1,
        "ghidra_version": s(Application.getApplicationVersion()),
        "program": {"name": s(prog.getName()), "sha256": s(prog.getExecutableSHA256()),
                    "image_base": "0x%x" % base},
        "functions": export_functions(prog, base),
        "globals": export_globals(prog, base),
        "types": export_types(prog),
    }
    with open(path, "wb") as fh:
        fh.write(json.dumps(snap, sort_keys=True, indent=1).encode("ascii"))
    print("GTARE: wrote %d functions, %d globals, %d types to %s" % (
        len(snap["functions"]), len(snap["globals"]), len(snap["types"]), path))


main()
