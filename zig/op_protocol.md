# DAFSA Differential Harness Protocol (U1)

## Overview
Line-based op scripts are fed to the driver on stdin. Each op prints exactly one result line (plus payload lines) to stdout. Keys are **lowercase hex strings** (embedded-NUL-safe, no 0x prefix). All file paths are resolved under `argv[1]` workdir.

## Grammar

### Ops
- `add <hex>` → `= add <1|0|-1>`
- `lookup <hex>` → `= lookup <1|0>`
- `del <hex>` → `= del <1|0|-1>`
- `stats` → `= stats <n_total> <n_reach> <n_final> <n_trans> <probes>`
- `prefix <hex>` → `= pfx <count>` + `count` lines `<hex payload>` (DFS sym-ascending, callback returns 0)
- `rank <hex>` → `= rank <u64>`
- `select <k>` → `= select <len> <hex>` | `= select -1`
- `rancount <hex> <hex>` → `= rc <u64>`
- `build` (multi-line):
  - `buildbegin`
  - `bkey <hex>` (repeated)
  - `buildend`
  → `= build 1|0`
- `save <name>` → `= save 0|-1`
- `load <name>` → `= load 1|0` (replaces handle, mutable)
- `loadro <name>` → `= loadro 1|0`
- `vopen <name>` → `= vopen 1|0`
- `vlookup <hex>` → `= vlookup <1|0>`
- `vprefix <hex>` → `= vpfx <count>` + `count` lines `<hex payload>`
- `vrank <hex>` → `= vrank <u64>`
- `vselect <k>` → `= vselect <len> <hex>` | `= vselect -1`
- `vrancount <hex> <hex>` → `= vrc <u64>`
- `vclose` → `= vclose`
- `wopen <name>` → `= wopen 1|0` (rw)
- `wopenro` → `= wopenro 1|0`
- `wadd <hex>` → `= wadd 0|-1`
- `wdel <hex>` → `= wdel 0|-1`
- `wsize` → `= wsize <n>`
- `wreplay` → `= wreplay <n>` + `n` lines `<op> <hex>`
- `wclose` → `= wclose`
- `lopen <fst> <wal>` → `= lopen 1|0` (layered)
- `dot` → `= dot` + graph lines (printf-format identical to dafsa.c:165-198)
- `abi` → `= abi <n>`
- `create` → `= create <1|0>`
- `free` → `= free <1|0>`

Unknown op → `= error`

## Key encoding
- Keys are **lowercase hex strings** (e.g., `616263` for "abc").
- Embedded NUL bytes are allowed (e.g., `610062`).
- The driver parses the hex into a length-delimited byte buffer (embedded-NUL-safe).

## File path resolution
All file paths (e.g., save/load names) are resolved under the workdir passed as `argv[1]`.

## Output grammar details
- Result lines always start with `=`.
- Payload lines (e.g., prefix results) follow the result line.
- Integer values are decimal unless otherwise noted.
- `= error` is printed for unknown ops or unimplemented ops.

## Example script (S1)
```
create
abi
add 616263
lookup 616263
stats
add 616263
lookup 616263
del 616263
lookup 616263
free
```
