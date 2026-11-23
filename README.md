# vice-ledger

[![validate](https://github.com/wer33321/vice-ledger/actions/workflows/validate.yml/badge.svg)](https://github.com/wer33321/vice-ledger/actions/workflows/validate.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)
![Ghidra 11+](https://img.shields.io/badge/Ghidra-11%2B-red)

**A community ledger of GTA VI reverse-engineering findings: function names, signatures, structs and notes that sync in and out of your own local Ghidra project.**

> [!IMPORTANT]
> **You need your own copy of the game.** This repository contains no executable, no bytes, no disassembly, no decompiled code and no assets, and CI rejects any pull request that tries to add them. Findings are stored as small JSON records keyed by RVA and tied to a build by SHA-256.

## How it works

```
 your GTA VI exe + Ghidra project (local only)
            |  export                     ^  pull
            v                             |
   db/builds/<build>/*.json  <-- pull requests, reviewed + CI-validated -->  everyone else
```

1. Analyse your own copy in Ghidra as usual.
2. `export` writes **only your new or changed** findings into `db/`.
3. `submit` makes a branch and PR; CI validates schema, duplicates and prohibited content.
4. After merge, everyone's `pull` applies the finding to their local Ghidra program, without overwriting their own conflicting work.

| Feature | |
|---|---|
| Functions: name, namespace, return type, params, calling convention, varargs/noreturn | yes |
| Structs/classes, enums, typedefs, globals | yes |
| Comments (own words only) | yes |
| Provenance: `auto` / `manual` / `reviewed`, confidence, contributor | yes |
| Multiple executable builds, versioned schema, `x-` extensions | yes |
| Incremental + conflict-aware import, stale-export protection | yes |
| Zero game data: allow-listed files, magic-byte and content scanning, CI from base branch | yes |

Current contents: run `python gtare.py stats`.

## Quick start

Requirements: Python 3.9+ (no packages), git, Ghidra 11+, optionally the GitHub CLI `gh`.

```
git clone https://github.com/wer33321/vice-ledger
cd vice-ledger
python gtare.py init --exe "D:\Games\GTA6\GTA6.exe" --ghidra C:\ghidra_11.3_PUBLIC ^
       --project-dir C:\re\ghidra --project-name gta6 --contributor your-github-handle
python gtare.py pull        # import community findings into Ghidra
# ... investigate in Ghidra, then close the project ...
python gtare.py export      # your findings -> db/
python gtare.py validate
python gtare.py submit --push --pr
```

If your executable's build is not registered yet, add `--register-build --label "<version/store>"` to `init`.

| Command | What it does |
|---|---|
| `init` | Saves paths in git-ignored `gtare.local.json`, hashes your exe locally, matches/registers the build. Refuses an exe inside the clone. |
| `pull` | `git pull --ff-only`, validates, applies new/changed records via `GtareImport.py`, reports applied / conflicts / unresolved. |
| `export` | Runs `GtareExport.py`, keeps user-authored findings (`--include-auto` for analysis-derived), writes only the diff. |
| `validate` | Schema, canonical form, duplicates, paths, overlaps, prohibited-content scanner (same as CI). |
| `submit` | Validates, branches `contrib/<you>/<time>`, commits only `db/`, optionally pushes and opens the PR. |
| `review` | Marks records independently reviewed (never by their author). |
| `stats` / `fmt` | Counts per build and status / rewrite files canonically. |

No headless Ghidra? Use the Script Manager flow: `pull --bundle-only` then `pull --apply-report`, and `export --snapshot`.

## Documentation

- [CONTRIBUTING.md](CONTRIBUTING.md) - rules and workflow
- [docs/FORMAT.md](docs/FORMAT.md) - record schema and layout
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - design decisions and limitations
- [SECURITY.md](SECURITY.md) - reporting leaked game data

## Status

Early. The Python tooling is unit-tested with synthetic data. `export` has been verified against a real PE program in Ghidra 12.2 (via PyGhidra); `pull`/import is still awaiting a real-world test, so please report problems via issues. Ghidra 12+ has no Jython: install PyGhidra (`pip install pyghidra`), the tool picks the right runner automatically.

## Legal

Unofficial fan project, not affiliated with or endorsed by Rockstar Games or Take-Two Interactive. "Grand Theft Auto" is a trademark of its owners. The code is MIT licensed; by contributing findings you agree they are released under the same license. Do not submit anything copied from the game.

## Credits

Inspired by community decompilation projects such as [IGI-RE](https://github.com/neonixmoddingteam/IGI-RE) and the wider Project Leonida community.
