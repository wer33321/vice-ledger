"""Safeguards that keep game data out of the repository.

These checks are defence in depth on top of .gitignore. They run locally in
`gtare validate` / `export` / `submit` and again in CI.
"""
import os
import re
import subprocess

ALLOWED_EXT = {".json", ".md", ".py", ".yml", ".yaml", ".txt", ".toml", ".java"}
ALLOWED_NOEXT = {"LICENSE", "CODEOWNERS", ".gitignore", ".gitattributes"}
ALLOWED_TOP = {"db", "docs", "tools", "ghidra_scripts", "tests", ".github"}
FORBIDDEN_EXT = {
    ".exe", ".dll", ".sys", ".bin", ".dmp", ".mdmp", ".pdb", ".obj", ".lib", ".so", ".dylib",
    ".elf", ".o", ".rpf", ".rar", ".zip", ".7z", ".gz", ".tar", ".iso", ".gdt", ".gzf",
    ".gpr", ".rep", ".lock", ".lock~", ".asm", ".s", ".dis", ".c", ".cpp", ".h", ".hpp",
    ".png", ".jpg", ".dds", ".wav", ".ogg", ".mp4", ".ytd", ".ydr", ".ytyp", ".ymap",
}
MAGIC = [(b"MZ", "Windows executable (MZ)"), (b"\x7fELF", "ELF binary"), (b"PK\x03\x04", "ZIP archive"),
         (b"7z\xbc\xaf", "7-Zip archive"), (b"Rar!", "RAR archive"), (b"\x1f\x8b", "gzip data"),
         (b"MDMP", "Windows minidump"), (b"\xca\xfe\xba\xbe", "Mach-O/Java class"),
         (b"RPF", "RAGE package"), (b"\x89PNG", "PNG image")]
MAX_FILE = 512 * 1024
MAX_DB_FILE = 64 * 1024
MAX_COMMENT = 2000
MAX_COMMENT_LINES = 20

ASM_LINE = re.compile(r"^\s*(?:[0-9a-fA-F]{6,16}\s+)?(?:mov[a-z]*|lea|call|jmp|j[a-z]{1,3}|push|pop|add|sub|xor|and|or|cmp|test|ret[n]?|nop|int3|imul|shl|shr)\s+[%\w\[\]\+\*,\s\-:$]+$", re.I)
HEX_DUMP = re.compile(r"(?:\b[0-9A-Fa-f]{2}\b[ \t]+){8,}")
LONG_HEX = re.compile(r"\b[0-9A-Fa-f]{40,}\b")
BASE64 = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")
DECOMP = re.compile(r"\b(?:[iu]?Var\d+|[a-z]?Stack_[0-9a-f]+|local_[0-9a-f]+|in_[A-Z]{2,}|unaff_\w+|undefined[1-8]\s+\w+\s*[=;])")

# Keys whose values are legitimately free text (checked strictly) vs identifiers.
FREE_TEXT_KEYS = {"comment"}
EXEMPT_KEYS = {"sha256"}


def check_text(key, value):
    """Return a list of problems for a string value of the given key."""
    out = []
    if key in EXEMPT_KEYS:
        return out
    if LONG_HEX.search(value):
        out.append("contains a long hex string (looks like a hash or raw bytes dump)")
    if HEX_DUMP.search(value):
        out.append("contains a hex byte dump")
    if BASE64.search(value):
        out.append("contains a long base64-like blob")
    if key in FREE_TEXT_KEYS or key.startswith("x-"):
        lines = value.splitlines()
        if len(value) > MAX_COMMENT:
            out.append("is longer than %d characters; write a summary instead" % MAX_COMMENT)
        if len(lines) > MAX_COMMENT_LINES:
            out.append("has more than %d lines" % MAX_COMMENT_LINES)
        if sum(1 for ln in lines if ASM_LINE.match(ln)) >= 2:
            out.append("looks like an assembly listing (not allowed)")
        if DECOMP.search(value):
            out.append("looks like decompiler output (not allowed)")
        if sum(1 for ln in lines if ln.rstrip().endswith(";")) >= 3:
            out.append("looks like source code (not allowed)")
    return out


def walk_strings(obj, key=""):
    if isinstance(obj, str):
        yield key, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk_strings(v, k)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk_strings(v, key)


def check_record_text(rec):
    errs = []
    for key, val in walk_strings(rec):
        for problem in check_text(key, val):
            errs.append("field '%s' %s" % (key, problem))
    return errs


def list_repo_files(repo):
    """Tracked + untracked-but-not-ignored files (relative, '/'-separated)."""
    try:
        out = subprocess.run(["git", "ls-files", "-z", "-co", "--exclude-standard"], cwd=repo,
                             capture_output=True, check=True).stdout.decode("utf-8", "replace")
        files = [p for p in out.split("\0") if p]
    except (OSError, subprocess.CalledProcessError):
        files = []
        for base, dirs, names in os.walk(repo):
            dirs[:] = [d for d in dirs if d not in (".git", ".gtare", "__pycache__")]
            for n in names:
                files.append(os.path.relpath(os.path.join(base, n), repo).replace(os.sep, "/"))
    return [f for f in files if os.path.exists(os.path.join(repo, f))]


def scan_file(repo, rel):
    """Return a list of error strings for one repo-relative file."""
    errs = []
    name = os.path.basename(rel)
    ext = os.path.splitext(name)[1].lower()
    top = rel.split("/")[0]
    full = os.path.join(repo, rel)
    if name == "gtare.local.json" or rel.startswith(".gtare/"):
        return ["local configuration/state must never be committed"]
    if ext in FORBIDDEN_EXT or name.lower().endswith(".lock"):
        return ["prohibited file type '%s' (game binaries, dumps, archives, assets, Ghidra projects and "
                "disassembly/source exports are never accepted)" % (ext or name)]
    if "/" in rel and top not in ALLOWED_TOP:
        errs.append("directory '%s/' is not an allowed top-level location" % top)
    if ext not in ALLOWED_EXT and name not in ALLOWED_NOEXT:
        errs.append("unexpected file type '%s'; only structured metadata and docs are accepted" % (ext or name))
    if top == "db" and ext != ".json" and rel != "db/README.md":
        errs.append("only .json records are allowed under db/")
    size = os.path.getsize(full)
    if size > MAX_FILE:
        errs.append("file is %d KiB; limit is %d KiB" % (size // 1024, MAX_FILE // 1024))
    if top == "db" and size > MAX_DB_FILE:
        errs.append("database record is %d KiB; limit is %d KiB" % (size // 1024, MAX_DB_FILE // 1024))
    with open(full, "rb") as fh:
        head = fh.read(8192)
    for magic, label in MAGIC:
        if head.startswith(magic):
            errs.append("content is a %s" % label)
    if b"\0" in head:
        errs.append("contains NUL bytes (binary content)")
    else:
        try:
            head.decode("utf-8")
        except UnicodeDecodeError as exc:
            if exc.start < len(head) - 4:
                errs.append("is not valid UTF-8 text")
    return errs


def scan_repo(repo, files=None):
    """Return list of (relpath, message)."""
    issues = []
    for rel in (files if files is not None else list_repo_files(repo)):
        for msg in scan_file(repo, rel):
            issues.append((rel, msg))
    return issues
