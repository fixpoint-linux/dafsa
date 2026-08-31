#!/usr/bin/env bash
# dafsa_diff.sh — Golden harness for the dafsa Zig engine
#
# The C engine was the migration oracle and is now removed; the Zig engine
# (zig/src/*.zig, driven by zig/dafsa_zig_driver.zig) is authoritative.  This
# harness no longer compiles or invokes any C.  Instead it runs ONLY the Zig
# driver on each op script and byte-compares its stdout against a recorded
# golden baseline under golden/ (captured from the differentially-verified Zig
# engine, so each baseline is byte-identical to what the trusted engine emits).
#
# Remaining engine-internal invariants (no golden, no C reference):
#   - S9 build==incremental language-stats: a build_sorted corpus and the same
#     keys added incrementally must report identical n_reach/n_final/n_trans
#     (the minimal-DFA language detector).
#   - U4 build_sorted-save == incremental-save: reaching the same language two
#     ways must produce byte-identical .pdwg files.
# The randomized-seed scripts are pre-recorded under golden/ (dafsa_gen is
# deterministic via rand_r), so no generator build is needed here.
#
# Gate: `bash zig/dafsa_diff.sh` from zig/ must exit 0 with every case PASS.
# Regenerate baselines with: RECORD_GOLDEN=1 bash zig/dafsa_diff.sh
set -euo pipefail

# ─── Zig cache dirs (sandbox) ────────────────────────────────────────────────
if [ -z "${ZIG_GLOBAL_CACHE_DIR:-}" ]; then export ZIG_GLOBAL_CACHE_DIR=/tmp/.zcache; fi
if [ -z "${ZIG_LOCAL_CACHE_DIR:-}" ]; then  export ZIG_LOCAL_CACHE_DIR=/tmp/.zlcache;  fi
mkdir -p "$ZIG_GLOBAL_CACHE_DIR" "$ZIG_LOCAL_CACHE_DIR"

ZIG=zig
ZIG_DRIVER=dafsa_zig_driver
GOLDEN_DIR=golden

# ─── Build ──────────────────────────────────────────────────────────────────
printf "[build] Zig driver...\n"
$ZIG build-exe dafsa_zig_driver.zig -O ReleaseSafe -lc

# ─── Temp files / cleanup ───────────────────────────────────────────────────
ZIG_OUT=$(mktemp)
SCRIPT=$(mktemp)
WORK=$(mktemp -d)
trap 'rm -f "$ZIG_OUT" "$SCRIPT"; rm -rf "$WORK"' EXIT

PASS_COUNT=0
FAIL_COUNT=0

# run_golden <name> <script-file> <golden-file>
# Runs the Zig driver on the script in a fresh workdir, then byte-compares its
# stdout to golden/<golden-file>.  In RECORD_GOLDEN mode the current output is
# written to golden/<golden-file> instead of compared (used to capture/refresh).
run_golden() {
  local name="$1"; local script="$2"; local golden="$3"
  rm -rf "$WORK"; mkdir -p "$WORK"
  ./$ZIG_DRIVER "$WORK" < "$script" > "$ZIG_OUT"
  if [ "${RECORD_GOLDEN:-0}" = "1" ]; then
    mkdir -p "$GOLDEN_DIR"
    cp "$ZIG_OUT" "$GOLDEN_DIR/$golden"
    printf "RECORDED: %s -> %s/%s\n" "$name" "$GOLDEN_DIR" "$golden"
    return 0
  fi
  if cmp -s "$ZIG_OUT" "$GOLDEN_DIR/$golden"; then
    printf "PASS: %s\n" "$name"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    printf "FAIL: %s — Zig stdout differs from %s/%s\n" "$name" "$GOLDEN_DIR" "$golden"
    diff "$GOLDEN_DIR/$golden" "$ZIG_OUT" || true
    FAIL_COUNT=$((FAIL_COUNT + 1))
    exit 1
  fi
}

# ─── S1-S5, S8: hand-written corpora (files under scripts/) ──────────────────
run_golden "S1 lifecycle basics"         scripts/S1  S1.out
run_golden "S2 shared-prefix families"   scripts/S2  S2.out
run_golden "S3 embedded-NUL keys"        scripts/S3  S3.out
run_golden "S4 delete/re-add ghost"      scripts/S4  S4.out
run_golden "S5 empty key"                scripts/S5  S5.out
run_golden "S8 interleaved add/del/lookup" scripts/S8 S8.out

# ─── S9: Daciuk build_sorted corpus + build==incremental language-equality ──
# The script builds from a sorted/dedup key list (buildbegin/bkey/buildend) and
# then adds the same keys incrementally.  Golden-compare the Zig stdout, and
# additionally assert the LANGUAGE-LEVEL stats (n_reach, n_final, n_trans)
# match between the two paths — proving both produce the same minimal DFA for
# the same language.  n_states_total and probes are internal bookkeeping and
# may differ between strategies.
run_golden "S9 build_sorted + build==incremental" scripts/S9 S9.out
{
  rm -rf "$WORK"; mkdir -p "$WORK"
  ./$ZIG_DRIVER "$WORK" < scripts/S9 > "$ZIG_OUT"
  # stats line: '= stats <n_total> <n_reach> <n_final> <n_trans> <probes>'
  # language-level fields = 4,5,6 (n_reach, n_final, n_trans)
  B4=$(grep '^= stats' "$ZIG_OUT" | sed -n '1p' | awk '{print $4}')
  B5=$(grep '^= stats' "$ZIG_OUT" | sed -n '1p' | awk '{print $5}')
  B6=$(grep '^= stats' "$ZIG_OUT" | sed -n '1p' | awk '{print $6}')
  I4=$(grep '^= stats' "$ZIG_OUT" | sed -n '2p' | awk '{print $4}')
  I5=$(grep '^= stats' "$ZIG_OUT" | sed -n '2p' | awk '{print $5}')
  I6=$(grep '^= stats' "$ZIG_OUT" | sed -n '2p' | awk '{print $6}')
  if [ "$B4" = "$I4" ] && [ "$B5" = "$I5" ] && [ "$B6" = "$I6" ]; then
    echo "PASS: S9 build==incremental language stats (reach=$B4 final=$B5 trans=$B6)"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo "FAIL: S9 build==incremental stats differ: build=[$B4/$B5/$B6] incr=[$I4/$I5/$I6]"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    exit 1
  fi
}

# ─── S10: save/load/loadro persistence (golden stdout) ──────────────────────
run_golden "S10 save/load/loadro persistence" scripts/S10 S10.out

# ─── S12: corruption parity (golden stdout, Zig-staged corrupt files) ───────
# Every corrupt variant (truncated / bad magic / bad CRC / empty) must make the
# Zig engine's load AND loadro fail identically ('= load 0').  The corrupt files
# are derived deterministically from a single Zig save, so the stdout is stable.
{
  rm -rf "$WORK"; mkdir -p "$WORK"
  # one good save via the Zig engine
  printf 'create\nadd 616263\nadd 616264\nadd 626364\nadd 61\nsave good.pdwg\nfree\n' \
    | ./$ZIG_DRIVER "$WORK" > /dev/null
  # truncate: cut off the tail (drops CRC + part of CSR)
  head -c 20 "$WORK/good.pdwg" > "$WORK/trunc.pdwg"
  # bad magic: flip first byte
  cp "$WORK/good.pdwg" "$WORK/badmagic.pdwg"
  printf 'X' | dd of="$WORK/badmagic.pdwg" bs=1 seek=0 conv=notrunc 2>/dev/null
  # bad CRC: flip a byte in the middle (data region, before the trailing CRC)
  cp "$WORK/good.pdwg" "$WORK/badcrc.pdwg"
  printf 'Z' | dd of="$WORK/badcrc.pdwg" bs=1 seek=30 conv=notrunc 2>/dev/null
  # empty file
  : > "$WORK/empty.pdwg"
  ./$ZIG_DRIVER "$WORK" < scripts/S12 > "$ZIG_OUT"
  if [ "${RECORD_GOLDEN:-0}" = "1" ]; then
    mkdir -p "$GOLDEN_DIR"
    cp "$ZIG_OUT" "$GOLDEN_DIR/S12.out"
    echo "RECORDED: S12 corruption parity -> $GOLDEN_DIR/S12.out"
  elif cmp -s "$ZIG_OUT" "$GOLDEN_DIR/S12.out"; then
    echo "PASS: S12 corruption parity (load + loadro fail identically)"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo "FAIL: S12 corruption parity diverged from golden"
    diff "$GOLDEN_DIR/S12.out" "$ZIG_OUT" || true
    FAIL_COUNT=$((FAIL_COUNT + 1)); exit 1
  fi
}

# ─── U4-deferred: build_sorted-save == incremental-save byte-equality ───────
# Same language reached two ways (Daciuk build vs incremental add) must produce
# byte-identical .pdwg files from the Zig engine.  This is engine-internal and
# needs no C reference.
{
  rm -rf "$WORK"; mkdir -p "$WORK"
  # incremental path -> save
  printf 'create\nadd 61\nadd 6162\nadd 616263\nadd 616264\nadd 6163\nadd 6164\nadd 62\nadd 6263\nadd 626364\nadd 6265\nadd 63\nsave inc.pdwg\nfree\n' \
    | ./$ZIG_DRIVER "$WORK" > /dev/null
  # build path -> save
  printf 'create\nbuildbegin\nbkey 61\nbkey 6162\nbkey 616263\nbkey 616264\nbkey 6163\nbkey 6164\nbkey 62\nbkey 6263\nbkey 626364\nbkey 6265\nbkey 63\nbuildend\nsave build.pdwg\nfree\n' \
    | ./$ZIG_DRIVER "$WORK" > /dev/null
  if cmp -s "$WORK/inc.pdwg" "$WORK/build.pdwg"; then
    echo "PASS: build_sorted-save == incremental-save (byte-identical)"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo "FAIL: Zig build-save != Zig incremental-save"
    echo "  inc:   $(wc -c < "$WORK/inc.pdwg" 2>/dev/null || echo missing) bytes"
    echo "  build: $(wc -c < "$WORK/build.pdwg" 2>/dev/null || echo missing) bytes"
    FAIL_COUNT=$((FAIL_COUNT + 1)); exit 1
  fi
}

# ─── S6: byte-alphabet 256-value stress (heap promotion + binary search) ────
# 256 single-byte keys → root gets 256 transitions (n>8 → binary search,
# >4 → heap promotion).  Plus a 5-key 2-byte-prefix family → a non-root state
# with 5 transitions (heap promotion off-root).  Then full delete sweep.
{
  echo create
  for i in $(seq 0 255); do printf "add %02x\n" "$i"; done
  echo stats
  for i in $(seq 0 255); do printf "lookup %02x\n" "$i"; done
  echo stats
  echo add 0041; echo add 0042; echo add 0043; echo add 0044; echo add 0045
  echo stats
  for i in $(seq 0 255); do printf "del %02x\n" "$i"; done
  echo stats
  echo free
} > "$SCRIPT"
run_golden "S6 byte-alphabet 256-value stress" "$SCRIPT" S6.out

# ─── S7: long keys near 4096 + 4097 rejection ────────────────────────────────
# The Zig driver faithfully replicates the 4095-char fgets window, so lines >
# 4095 chars (keys ≥ 2046 bytes) are chunked and re-dispatched identically to
# the original behavior.  A 2045-byte key fits (4094 chars) and exercises real
# deep-path traversal + scratch-array growth.
{
  K2045=$(printf "%0.s61" $(seq 1 2045))
  K2046=$(printf "%0.s61" $(seq 1 2046))
  K4096=$(printf "%0.s61" $(seq 1 4096))
  K4097=$(printf "%0.s61" $(seq 1 4097))
  echo create
  echo "add $K2045"
  echo "lookup $K2045"
  echo "add $K2046"
  echo "lookup $K2046"
  echo "add $K4096"
  echo "add $K4097"
  echo "del $K2045"
  echo stats
  echo free
} > "$SCRIPT"
run_golden "S7 long keys near 4096 + 4097 rejection" "$SCRIPT" S7.out

# ─── Randomized seeds: ~5k-op S8-style scripts, 3 pre-recorded seeds ─────────
# The scripts were generated by dafsa_gen (deterministic rand_r, 3-symbol
# alphabet → heavy confluence) and are recorded under golden/ so the harness
# needs no C generator.  Golden-compare the Zig driver's stdout per seed.
for seed in 1 2 3; do
  run_golden "randomized seed=$seed (5000 ops)" "$GOLDEN_DIR/seed$seed.ops" "seed$seed.out"
done

# ─── S10 view: vopen/vlookup/vprefix over a Zig-saved .pdwg (golden) ────────
# Build a W\0-payload language, save, re-open via view, exercise vlookup +
# vprefix (payload DFS sym-ascending).  Golden-compare stdout.
{
  echo create
  for i in $(seq 1 40); do printf "add 61%02x%02x\n" "$((i/2))" "$i"; done
  for i in $(seq 1 30); do printf "add 62%02x%02x\n" "$((i/2))" "$i"; done
  echo "add 6300ff"; echo "add 6300fe"
  echo "save view1.pdwg"
  echo "vopen view1.pdwg"
  for i in $(seq 0 20); do printf "vlookup 61%02x%02x\n" "$((i/2))" "$i"; done
  echo "vlookup 6200aa"; echo "vlookup 9900ff"
  echo "vprefix 61"; echo "vprefix 62"; echo "vprefix 63"; echo "vprefix 64"; echo "vprefix 00"
  echo "vclose"
  echo "free"
} > "$SCRIPT"
run_golden "S10 view vopen/vlookup/vprefix" "$SCRIPT" S10view.out

# scale-pass view: larger corpus (400 keys, W\0 payload) saved and re-opened
# via view, vlookup + vprefix sampled (golden stdout).
{
  echo create
  for i in $(seq 0 399); do printf "add 61%02x%04x\n" "$((i / 64))" "$i"; done
  echo "add 6200cafe"
  echo "save viewscale.pdwg"
  echo "vopen viewscale.pdwg"
  echo "vlookup 610001"; echo "vlookup 61ff0000"; echo "vlookup 6200cafe"; echo "vlookup 6300cafe"
  echo "vprefix 61"; echo "vprefix 62"
  echo "vclose"
  echo free
} > "$SCRIPT"
run_golden "S10 view scale-pass (400-key corpus via view)" "$SCRIPT" S10viewscale.out

# ─── S11 WAL: layered lopen + torn-tail ftruncate (golden) ──────────────────
run_golden "S11 WAL + layered lopen" scripts/S11 S11.out
# torn-tail ftruncate: a valid WAL with a partial tail record appended must
# have its torn tail ftruncated on wopen(rw); the resulting stdout AND .wal
# file are both recorded golden (deterministic).
{
  rm -rf "$WORK"; mkdir -p "$WORK"
  # create a valid 2-record WAL via the Zig engine
  printf 'wopen tt.wal\nwadd 610000000000000000aa\nwadd 620000000000000000bb\nwclose\n' \
    | ./$ZIG_DRIVER "$WORK" > /dev/null
  # simulate a torn tail: append a partial record (op=ADD, key_len=1, one key
  # byte, no CRC) — incomplete per wal_validate_record (needs >=10 bytes).
  printf '\001\000\000\000\001a' >> "$WORK/tt.wal"
  printf 'wopen tt.wal\nwsize\nwreplay\nwclose\n' | ./$ZIG_DRIVER "$WORK" > "$ZIG_OUT"
  if [ "${RECORD_GOLDEN:-0}" = "1" ]; then
    mkdir -p "$GOLDEN_DIR"
    cp "$ZIG_OUT" "$GOLDEN_DIR/S11torn.out"
    cp "$WORK/tt.wal" "$GOLDEN_DIR/S11torn.wal"
    echo "RECORDED: S11 torn-tail ftruncate -> $GOLDEN_DIR/S11torn.out + S11torn.wal"
  elif cmp -s "$ZIG_OUT" "$GOLDEN_DIR/S11torn.out" && cmp -s "$WORK/tt.wal" "$GOLDEN_DIR/S11torn.wal"; then
    echo "PASS: S11 torn-tail ftruncate (golden stdout + file)"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo "FAIL: S11 torn-tail ftruncate diverged from golden"
    diff "$GOLDEN_DIR/S11torn.out" "$ZIG_OUT" || true
    echo "  golden wal: $(wc -c < "$GOLDEN_DIR/S11torn.wal" 2>/dev/null || echo missing) bytes"
    echo "  zig    wal: $(wc -c < "$WORK/tt.wal" 2>/dev/null || echo missing) bytes"
    FAIL_COUNT=$((FAIL_COUNT + 1)); exit 1
  fi
}

# ─── S13 rank/select/rancount (U8) + _from + view rank (golden) ─────────────
run_golden "S13 rank/select/rancount + _from + view rank" scripts/S13 S13.out

# ─── S13-scale: rank/select/rancount pass on a larger corpus (golden) ───────
# 400 generated keys + a few outliers; sampled rank (present + absent),
# select (in-range + k>=total), rancount, and a fromstate _from sample.
{
  echo create > "$SCRIPT"
  for i in $(seq 0 399); do
    printf "add 61%02x%04x\n" "$((i / 64))" "$i" >> "$SCRIPT"
  done
  echo "add 6200cafe" >> "$SCRIPT"
  echo "add 63000000" >> "$SCRIPT"
  echo stats >> "$SCRIPT"
  for i in 0 63 64 127 128 191 192 255 256 319 320 383 384 399 400; do
    echo "select $i" >> "$SCRIPT"
  done
  echo "select 401" >> "$SCRIPT"
  echo "select 99999" >> "$SCRIPT"
  echo "rank 610000" >> "$SCRIPT"    # absent (below first)
  echo "rank 6101ffff" >> "$SCRIPT"  # absent (mid-range)
  echo "rank 6200cafe" >> "$SCRIPT"  # present
  echo "rank 6200cb00" >> "$SCRIPT"  # absent (after cafe, before second outlier)
  echo "rank ff" >> "$SCRIPT"        # absent (above all)
  echo "rancount 610000 620000" >> "$SCRIPT"
  echo "rancount 0000 ff" >> "$SCRIPT"
  echo "fromstate 61" >> "$SCRIPT"
  echo "select 0" >> "$SCRIPT"
  echo "select 399" >> "$SCRIPT"
  echo "select 400" >> "$SCRIPT"
  echo "rank 00" >> "$SCRIPT"
  echo free >> "$SCRIPT"
  run_golden "S13-scale rank/select/rancount (400-key corpus)" "$SCRIPT" S13scale.out
}

# ─── Summary ────────────────────────────────────────────────────────────────
printf "\n[gate] %d passed, %d failed\n" "$PASS_COUNT" "$FAIL_COUNT"
if [ "$FAIL_COUNT" -ne 0 ]; then exit 1; fi
if [ "${RECORD_GOLDEN:-0}" = "1" ]; then
  printf "[gate] RECORD_GOLDEN: baselines written to %s/ (re-run without the env var to verify)\n" "$GOLDEN_DIR"
  exit 0
fi
printf "[gate] S1-S13 + 3 randomized seeds ALL PASS (golden mode, Zig-only)\n"
printf "ALL PASS\n"
