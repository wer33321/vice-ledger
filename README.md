# vice-ledger

A community ledger of GTA VI reverse-engineering findings, built around Ghidra.
It stores **names, signatures, types and notes only** - never the executable, bytes, disassembly or decompiled code.

```
python gtare.py init --exe "D:\Games\GTA6\GTA6.exe" --ghidra C:\ghidra_11.3_PUBLIC ^
       --project-dir C:\re\ghidra --project-name gta6 --contributor your-github-handle
python gtare.py pull        # fetch community findings and apply them to your local Ghidra program
# ... investigate in Ghidra, close the project ...
python gtare.py export      # write ONLY your new/changed findings into db/
python gtare.py validate
python gtare.py submit --push --pr
```

Requirements: Python 3.9+ (no packages), git, Ghidra 11+, optional `gh`. Details: [CONTRIBUTING.md](CONTRIBUTING.md), [docs/FORMAT.md](docs/FORMAT.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

| Command | What it does |
|---|---|
| `init` | Stores paths in git-ignored `gtare.local.json`, hashes your exe locally, matches it to a registered build (`--register-build` adds a new one). Refuses an exe located inside the clone. |
| `pull` | `git pull --ff-only`, validates the DB, builds an import bundle of new/changed records, runs `GtareImport.py` in Ghidra headless, prints applied / conflicts / unresolved. |
| `export` | Runs `GtareExport.py`, keeps only user-authored findings (add `--include-auto` for analysis-derived ones), diffs against `db/` and writes only what is new or modified. |
| `validate` | Schema, canonical form, duplicates, path rules, overlaps, plus the prohibited-content scanner. CI runs the same command. |
| `submit` | Validates, creates `contrib/<you>/<timestamp>`, commits only `db/`, optionally pushes and opens a PR. |
| `review` | Marks records independently reviewed (not by their author). |
| `fmt` | Rewrites records into canonical form. |

Scripts can also be run from Ghidra's Script Manager (`pull --bundle-only` / `pull --apply-report`, `export --snapshot`) if you prefer the GUI or cannot use headless mode.
