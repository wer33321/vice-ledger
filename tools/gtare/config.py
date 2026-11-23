"""Local (never committed) configuration and executable fingerprinting.

The executable is only ever *read locally* to compute a SHA-256 and to read the
PE header's ImageBase field. Nothing from it is stored except those two values.
"""
import hashlib
import json
import os
import struct

CONFIG_NAME = "gtare.local.json"
KEYS = ("executable", "ghidra_install", "ghidra_project_dir", "ghidra_project_name", "ghidra_program",
        "build_id", "contributor", "remote")


class ConfigError(Exception):
    pass


def find_repo(start=None):
    d = os.path.abspath(start or os.getcwd())
    while True:
        if os.path.isfile(os.path.join(d, "gtare.py")) and os.path.isdir(os.path.join(d, "tools", "gtare")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            raise ConfigError("Run this from inside a clone of the gta6-re-db repository.")
        d = parent


def config_path(repo):
    return os.path.join(repo, CONFIG_NAME)


def load(repo, required=()):
    path = config_path(repo)
    if not os.path.isfile(path):
        raise ConfigError("No %s found. Run 'python gtare.py init' first." % CONFIG_NAME)
    with open(path, "r", encoding="utf-8") as fh:
        cfg = json.load(fh)
    missing = [k for k in required if not cfg.get(k)]
    if missing:
        raise ConfigError("%s is missing: %s. Re-run 'python gtare.py init'." % (CONFIG_NAME, ", ".join(missing)))
    return cfg


def save(repo, cfg):
    with open(config_path(repo), "w", encoding="utf-8", newline="\n") as fh:
        json.dump({k: cfg[k] for k in KEYS if cfg.get(k)}, fh, indent=2, sort_keys=True)
        fh.write("\n")


def state_dir(repo):
    d = os.path.join(repo, ".gtare")
    os.makedirs(d, exist_ok=True)
    return d


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def pe_image_base(path):
    """Read ImageBase from a PE header (header bytes only). Returns int or None."""
    with open(path, "rb") as fh:
        dos = fh.read(64)
        if len(dos) < 64 or dos[:2] != b"MZ":
            return None
        (lfanew,) = struct.unpack_from("<I", dos, 0x3C)
        fh.seek(lfanew)
        hdr = fh.read(24 + 32)
        if len(hdr) < 56 or hdr[:4] != b"PE\0\0":
            return None
        magic = struct.unpack_from("<H", hdr, 24)[0]
        if magic == 0x20B:
            return struct.unpack_from("<Q", hdr, 24 + 24)[0]
        if magic == 0x10B:
            return struct.unpack_from("<I", hdr, 24 + 28)[0]
    return None


def is_inside(path, repo):
    p, r = os.path.normcase(os.path.realpath(path)), os.path.normcase(os.path.realpath(repo))
    return os.path.commonpath([p, r]) == r
