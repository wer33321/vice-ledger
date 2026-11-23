# Contributing

1. Clone the repo. Keep your game executable and Ghidra project **outside** the clone.
2. `python gtare.py init ...` (see README). If your executable's build is not in `db/builds/`, add `--register-build --label "<version>"` and include the new `build.json` in your PR.
3. `python gtare.py pull` to import everything the community knows.
4. Reverse engineer in Ghidra. Rename functions, set signatures/calling conventions, create structs/enums. Ghidra marks these as user-defined; that is what gets exported.
5. Close the project in the Ghidra GUI (headless needs the project lock), then `python gtare.py export`. Review `git diff`.
6. `python gtare.py validate`, then `python gtare.py submit --push --pr`.

## Rules (enforced locally and by CI)

- PRs may only change files under `db/` (tooling changes need the maintainer `tooling` label).
- Never include: executables/DLLs, dumps, archives, assets, Ghidra projects (`*.gpr`, `*.rep`), assembly listings, decompiler output, hex/base64 blobs. The validator rejects them by extension, magic bytes, NUL bytes and content heuristics.
- Comments must be your own words: summarise what a function does, do not paste code.
- New findings are `manual`; set `--confidence low|medium|high` honestly. `reviewed` is only for independent reviewers (`gtare review <id>`; you cannot review your own record).
- Changing a `reviewed` record needs the `review-approved` label from a maintainer.
- If `export` says a record is SKIPPED because the community version changed, `pull` first and redo your edit on top of it. Conflicts are resolved by humans in the PR, never silently.
- Removing a finding is done by deleting its file in a PR.
