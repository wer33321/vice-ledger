# Architecture and decisions

## Split
- `ghidra_scripts/` - the only code that touches Ghidra APIs (`GtareExport.py`, `GtareImport.py`). They are Jython 2.7 / PyGhidra compatible, use only public APIs (FunctionManager, SymbolTable, DataTypeManager, `Function.updateFunction`, `DataTypeParser`) and exchange plain JSON files with the tool. No GUI automation.
- `tools/gtare/` - stdlib-only Python CLI: config, hashing, schema validation, safety scanner, diffing, git workflow. It never imports Ghidra, so it is testable with synthetic data and reusable by other analysis tools.
- `db/` - the data. Tool-independent JSON.

## Key decisions
1. **RVA addressing.** `address = program image base + RVA`; survives rebasing, resolved against the local program on import.
2. **Per-finding files, address-sharded.** Minimises merge conflicts and makes PR diffs equal the findings changed. Cost: many small files; sharding keeps directories manageable.
3. **Provenance.** `auto`/`manual`/`reviewed` + confidence. Export defaults to user-defined Ghidra items only (`SourceType.USER_DEFINED`), never default `FUN_` names. Authors cannot review themselves.
4. **Safe imports.** Local state (`.gtare/state/<build>.json`, git-ignored) records what was last applied. On import a local value is overwritten only if it is non-user-defined or still equals what we applied; otherwise it is reported as a *conflict* and kept. `--force` overrides explicitly.
5. **Safe exports.** Records that changed upstream since the contributor last pulled are skipped as *stale*; reviewed records are protected. Unchanged findings produce no file changes.
6. **Executable stays local.** Only SHA-256, size and PE ImageBase are derived from it. Both scripts compare the Ghidra program's SHA-256 with the build and refuse to proceed on mismatch. `init` refuses an exe inside the clone.
7. **Defence in depth against leaks.** `.gitignore`; allow-list of directories/extensions; magic-byte, NUL and UTF-8 checks; size limits; regex heuristics for hex dumps, base64 blobs, assembly listings, decompiler variables and source code in free text; CI runs the validator from the *base* branch (a PR cannot weaken it), enforces data-only PRs and blocks self-granted `reviewed`.
8. **Versioning.** `schema` per record, `x-` extension fields, explicit unknown-field errors.

## Known limitations
- The Ghidra scripts could not be executed in the development environment (no Ghidra install, no game binary); the Python core is covered by unit tests with synthetic snapshots, and the scripts are untested against a real Ghidra - expect small API fixes. Headless Python scripts need Jython (Ghidra 11.x) or PyGhidra; otherwise use the GUI flow.
- Type names must be plain identifiers (no templates/spaces yet); such types are reported as skipped. Types are matched by simple name, namespace comes from the Ghidra category path.
- Not yet covered: unions, bitfields, packed structs, vtable/RTTI discovery, local variables, per-instruction comments (comments on instructions would risk leaking listings), cross-build function matching (would need non-byte fingerprints), deletions propagation.
- Import is not transactional per record beyond Ghidra's script transaction; save/inspect the program afterwards.
