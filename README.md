# Carrasco–Forcada Incremental DAFSA (PoC)

A self-contained C implementation of **incremental construction and
maintenance of a minimal acyclic finite-state automaton (DAFSA)**, following
the clone-on-write + register + confluence algorithm described in:

> Carrasco, R. C. & Forcada, M. L. (2002)
> *Incremental Construction and Maintenance of Minimal Acyclic
> Finite-State Automata*. Computational Linguistics, 28(2), pp. 207–216.

This repository is the **research & development testbed** for replacing the Rust
`fst` crate backend in [`palimpsest`](https://github.com/palimpsest-labs) with a
vendored C DAFSA. It is **not** yet integrated anywhere; it is a standalone
library + test harness used to validate the core algorithm before integration
(see [ROADMAP.md](ROADMAP.md)).

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
bytes — a deliberate design requirement for the target use case
(see ROADMAP decision **D3**).

## Features

- Opaque `dafsa` handle; all state heap-allocated and growable (no fixed
  static arrays, no per-edge malloc/free).
- Incremental `add` / `lookup` / `delete`.
- Length-delimited key API (`dafsa_add_n`, `dafsa_lookup_n`, `dafsa_delete_n`)
  plus NUL-terminated convenience wrappers.
- Statistics (`dafsa_stats`) and Graphviz DOT export (`dafsa_dot`).
- Portably C99; builds with a system `cc` *or* `cosmocc`.

## Current status

**Milestone M0 is complete** (2026-08-06): heap + opaque handle + `_n` APIs.
All 10 tests pass under `-Werror` with a native ELF build.

The following are **stubs returning failure / empty**, implemented in M1:

- `dafsa_save` / `dafsa_load` (persistence)
- `dafsa_prefix_enum` (prefix enumeration)

Milestone progression (M0–M4) and the full integration plan live in
[ROADMAP.md](ROADMAP.md).

## Project context & history

This PoC grew out of a planning session (2026-08-06) to replace the Rust `fst`
crate in Palimpsest's `fst-indexer`. The key locked decisions, recorded in
[ROADMAP.md](ROADMAP.md), shape everything in this repo:

- **D1 — Hybrid, not a standalone C binary.** The `fst-indexer` Rust binary
  keeps its name, CLI, JSON, and `manifest.json` shape. Only the `fst` crate is
  replaced; the C core is compiled in via the `cc` crate + FFI. Tokenization,
  globbing, extractors, and manifest-writing **stay in Rust**, unchanged.
- **D2 — True incremental.** A persistent read-write DAFSA (load → mutate →
  save) with append-only file slots + tombstones for a stable `file_idx`, a
  per-file key sidecar, and a new `update` subcommand. The hourly reindex timer
  is dropped; a cheap nightly `build` remains for compaction/GC.
  `dafsa_delete_n` is therefore load-bearing → randomized differential tests are
  mandatory.
- **D3 — Length-delimited key API (NUL-in-keys).** The composite key
  `{word}\0{file_idx}{entry_idx}` embeds a NUL separator, so every key API is
  length-delimited (`_n`); `strlen` wrappers are thin shims.
- **D4 — On-disk format is ours to replace**, but the filename stays
  `index.fst` (a consumer hardcodes it) and `manifest.json` keeps its shape.
- **D5 — Stable `file_idx`** via append-only slots + tombstones; only `build`
  (compaction) renumbers.
- **D6 — Prefix semantics = `W\0`, not `W`.** A query must require a `\0` edge
  next, so `"ca"` must NOT return `"cat"` hits.
- **D7 — `MAX_STATES` is too small.** Fixed arrays were converted to growable
  heap arrays; the state-count cap on real corpora is measured at the M2 gate.
- **D8 — Deployment.** The shipped `fst-indexer` stays a native Rust binary
  (not cosmocc/APE); `build.rs` uses the system `cc`. Cosmocc is used **only**
  for this standalone PoC test binary.
- **D10 — Naming.** The core is **`dafsa`** (DAFSA — Deterministic Acyclic
  Finite State Automaton); the deployed binary stays `fst-indexer` for drop-in
  compatibility.
- **D11 — Standardized on the `dafsa` prefix.** The M0 refactor produced
  `dafsa.h`/`dafsa.c`/`dafsa_test.c` with an opaque `dafsa` type; the legacy
  `dawg.c` was removed from the tree (still recoverable in git history at
  commit `ccba17b`).

The repo also serves as the **source of truth** for the C core. The
`Makefile` `sync` target copies `dafsa.{c,h}` into
`palimpsest/fst-indexer/c/`, which `build.rs` compiles into the Rust binary at
M2.

## Layout

| File               | Purpose                                                       |
|--------------------|---------------------------------------------------------------|
| `dafsa.h`          | Public API — opaque `dafsa`, lifecycle, key ops, stats, DOT   |
| `dafsa.c`          | Core implementation (algorithm, register, growable arrays)    |
| `dafsa_test.c`     | Test harness (10 tests: add/lookup/delete, embedded-NUL)      |
| `Makefile`         | `build` / `test` / `clean` / `sync`                           |
| `ROADMAP.md`       | Session decision log, file-by-file plan, M0–M4 phasing, risks |

## Building & testing

```sh
make test       # builds ./dafsa (test harness) and runs it
```

The default toolchain is `cosmocc`. To build with a plain `cc` instead:

```sh
cc -Wall -Wextra -Werror -O2 -o dafsa dafsa_test.c dafsa.c
./dafsa
```

The test harness prints the resulting stats (total/reachable/final states,
transitions, register probes) after each scenario. On success all `assert`s
pass and the binary exits `0`.

### Toolchain note (cosmocc / APE)

The default build uses `cosmocc`, which produces **cosmopolitan APE** binaries.
These need `fork` at runtime, so under a restricted sandbox they may not run
directly — use `make test` (which runs via `make`) or the native ELF build
(`cc` above). This matters only for local PoC testing; the shipped Rust binary
is built with the system `cc` (decision **D8**), so this is a non-issue in
production.

### Visualizing the automaton

`dafsa_dot` emits a Graphviz DOT description. Render it with:

```sh
./dafsa > dafsa.dot   # or your own driver calling dafsa_dot(d, stdout)
dot -Tpng dafsa.dot -o dafsa.png
```

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

dafsa_dot(d, stdout);                            /* Graphviz export */
dafsa_free(d);
```

## Why this matters to Palimpsest

`fst-indexer` currently ships a Rust binary that embeds the `fst` crate to
index web-archive/session data. The roadmap replaces that backend with this C
DAFSA to get **true incremental updates** (per-key add/delete) instead of
periodic full rebuilds, with a stable on-disk format and append-only slots +
tombstones. This PoC validates the tricky core — incremental minimization with
deletes — before the Rust FFI (`build.rs` + `cc` crate) and Python wiring in
milestones M2–M3. The design decisions behind this (D1–D11) are summarized in
[Project context & history](#project-context--history).

See [ROADMAP.md](ROADMAP.md) for the full design, phasing, and open risks
(e.g. the `MAX_STATES` RAM measurement at the M2 gate, and the `cc` vs
`cosmocc` build question).
