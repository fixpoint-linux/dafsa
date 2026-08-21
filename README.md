# Carrasco–Forcada Incremental DAFSA engine

A self-contained C implementation of **incremental construction and
maintenance of a minimal acyclic finite-state automaton (DAFSA)**, following
the clone-on-write + register + confluence algorithm described in:

> Carrasco, R. C. & Forcada, M. L. (2002)
> *Incremental Construction and Maintenance of Minimal Acyclic
> Finite-State Automata*. Computational Linguistics, 28(2), pp. 207–216.

This is the **canonical DAFSA engine** for the fixpoint-linux stack. It is
consumed as a git submodule by:

- [`datalog-dafsa`](https://github.com/fixpoint-linux/datalog-dafsa) — at
  `vendor/dafsa` (bulk minimal build + rank + view).
- `jing-meta` — at `indexer/dafsa/vendor/dafsa` (full-text indexer CLI).

It is a **split multi-file engine** (not a single monolithic `.c`). The engine
is extended with a bulk `dafsa_build_sorted()` (Daciuk et al. minimal
construction from a sorted, deduplicated key list) plus `dafsa_rank` /
`dafsa_view_rank`, all needed by datalog-dafsa. `jing-meta`'s indexer CLI keeps
its own `dafsa_build.c` (`build_main`) locally and compiles the core engine
objects from this submodule.

## What it does

A DAFSA (also called a DAWG — directed acyclic word graph) is a minimized,
deterministic, acyclic finite-state automaton that represents a set of
strings/keys. Unlike a trie, shared suffixes are merged, so common
prefixes **and** suffixes collapse into shared states, yielding a compact
representation.

Unlike a batch-built automaton, this implementation supports **incremental
add and delete** of individual keys while keeping the automaton minimal after
each operation. It uses:

- **Clone-on-write** — split a shared state before diverging from it.
- **A register** (open-addressing hash table) keyed by state signature to
  detect isomorphic states and merge them.
- **Confluence** — rerouting incoming transitions so the machine stays minimal.

Keys are **length-delimited** (`_n` API), so they may contain embedded `NUL`
bytes — a deliberate design requirement for the target use case.

## Features

- Opaque `dafsa` handle; all state heap-allocated and growable (no fixed
  static arrays, no per-edge malloc/free).
- Incremental `add` / `lookup` / `delete`.
- Length-delimited key API (`dafsa_add_n`, `dafsa_lookup_n`, `dafsa_delete_n`)
  plus NUL-terminated convenience wrappers.
- Persistence (`dafsa_save` / `dafsa_load`, PDWG v4 format, atomic rename +
  fsync), prefix enumeration (`dafsa_prefix_enum`, `W\0` semantics), zero-copy
  mmap view (`dafsa_view_open`), WAL, CRC32.
- Bulk minimal construction (`dafsa_build_sorted`) and rank / view_rank.
- Statistics (`dafsa_stats`) and Graphviz DOT export (`dafsa_dot`).
- Portably C99; builds with a system `cc` (`-D_POSIX_C_SOURCE=200809L`).

## Building

```sh
make        # builds libdafsa.so (shared)
make clean
```

Both consumers (`datalog-dafsa`, `jing-meta`) compile the engine objects from
this submodule and run their own test suites against them.

## Layout

| File               | Purpose                                                    |
|--------------------|------------------------------------------------------------|
| `dafsa.h`          | Public API — opaque `dafsa`, lifecycle, key ops, rank, view|
| `dafsa_internal.h` | Shared internals (not public)                              |
| `dafsa.c`          | Public API + length-delimited add/lookup/delete            |
| `dafsa_state.c`    | State heap / transition storage                            |
| `dafsa_core.c`     | Minimality maintenance (register, replace, clone)          |
| `dafsa_persist.c`  | PDWG v4 save/load (fsync + atomic rename)                  |
| `dafsa_view.c`     | Zero-copy mmap read-only view + prefix enum                |
| `dafsa_wal.c`      | Write-ahead log + overlay                                  |
| `dafsa_crc32.c`    | CRC32 checksums                                            |
| `dafsa_build.c`    | `dafsa_build_sorted` bulk minimal construction             |
| `dafsa_rank.c`     | rank / rank_from queries                                   |
| `dafsa_view_rank.c`| rank over a read-only view                                 |
| `Makefile`         | `build` / `clean`                                          |

## Usage example

```c
#include "dafsa.h"

dafsa *d = dafsa_create();                       /* NULL on OOM */
dafsa_add(d, (const unsigned char *)"cat");
dafsa_add(d, (const unsigned char *)"car");
dafsa_add(d, (const unsigned char *)"cart");

dafsa_lookup(d, (const unsigned char *)"car");   /* 1 */
dafsa_delete(d, (const unsigned char *)"car");   /* 1 */
dafsa_lookup(d, (const unsigned char *)"car");   /* 0 */

dafsa_stats_out st;
dafsa_stats(d, &st);                             /* inspect state counts */

dafsa_free(d);
```

## History

This engine began as the research PoC for replacing the Rust `fst` crate in
Palimpsest's `fst-indexer` (see `ROADMAP.stale.md`, the historical D1–D11 decision log). It was
then adopted as the canonical DAFSA engine for the fixpoint-linux stack, split
into multiple files, and consumed as a submodule by `datalog-dafsa` and
`jing-meta`.
