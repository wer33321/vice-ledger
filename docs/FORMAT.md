# Database format (schema version 1)

All files are UTF-8 JSON, written canonically (sorted keys, 2-space indent, ASCII escapes, trailing newline). `gtare validate` rejects non-canonical files, so identical findings always yield identical bytes.

## Layout

```
db/builds/<build_id>/build.json
db/builds/<build_id>/functions/<rva[0:4]>/<rva>.json     e.g. functions/0014/00141a20.json
db/builds/<build_id>/globals/<rva[0:4]>/<rva>.json
db/builds/<build_id>/types/<Namespace>/.../<Name>.json   e.g. types/Game/Player.json
```

`build_id` = `b-` + first 16 hex digits of the executable's SHA-256. One file per finding, placed by address/name, means two PRs conflict only if they touch the **same** finding. There are no index or counter files.

## build.json
`schema`, `build_id`, `sha256`, `image_base`, `file_size`, optional `label`, `platform`. Identification metadata only.

## Common fields (every record)
| Field | Meaning |
|---|---|
| `schema` | integer, currently 1 |
| `id` | stable identifier: `fn:<rva>`, `gv:<rva>`, `type:<Namespace::Name>` (must match the path) |
| `kind` | `function`, `global`, `struct`, `enum`, `typedef` |
| `status` | `auto` (analysis-derived), `manual` (a human identified it), `reviewed` (independently confirmed; needs `reviewed_by`) |
| `confidence` | `low`, `medium`, `high` |
| `contributor` | GitHub handle of the original author; `updated_by` for later editors |
| `comment`, `tags` | optional, own words only; tags are sorted kebab-case |
| `x-*` | free extension fields; ignored by the tools, so third parties can add data without schema changes |

RVAs are strings: `0x` + 8 lowercase hex digits, relative to the program's image base (so rebasing a program does not matter).

## Kinds
- **function**: `rva`, `name`, `namespace` (`A::B`), `size`, `prototype{return_type, calling_convention, params[{name,type}], varargs, noreturn}`. `this` parameters of `__thiscall` are implicit and not listed.
- **global**: `rva`, `name`, `namespace`, `type`, `size`.
- **struct** (also classes): `size`, `members[{offset,name,type,size,comment}]` sorted by offset, optional `bases`, `vtable` (RVA).
- **enum**: `size` (1-8), `values[{name,value}]` sorted by (value, name).
- **typedef**: `target`.

Type references are Ghidra-style display strings (`char *`, `Player *`, `int[4]`). Unknown names only produce warnings because they may be Ghidra built-ins.

## Evolution
Unknown fields are errors unless prefixed `x-`. A record with a higher `schema` than the tool understands is rejected with an "update the tooling" message; migrations will be added as `schema` increases. Types are per build today; a future `db/shared/` tree can hold cross-build types without changing existing records.
