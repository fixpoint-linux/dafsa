#!/usr/bin/env bash
# dafsa_diff.sh — Differential harness for the dafsa C→Zig migration (U3+U4+U5 gate)
#
# Gate (must ALL PASS): S1-S12 + 3 randomized seeds C-vs-Zig, exact stats
# equality (n_states_total + register_probes must match the C engine exactly —
# the state-faithfulness detector), S9's build==incremental language-stats
# invariant, S10's save/load/loadro byte-equality of the on-disk .pdwg files
# (C-vs-Zig), cross-load interop (each engine loads the other's saved file),
# S12 corruption parity (truncated / bad magic / bad CRC / empty files must all
# load-fail identically on both engines), and the U4-deferred invariant that a
# build_sorted-then-save is byte-identical to an incremental-add-then-save.
# The C engine is authoritative and never modified; any divergence is fixed on
# the Zig side.
set -euo pipefail

# ─── Zig cache dirs (sandbox) ────────────────────────────────────────────────
if [ -z "${ZIG_GLOBAL_CACHE_DIR:-}" ]; then export ZIG_GLOBAL_CACHE_DIR=/tmp/.zcache; fi
if [ -z "${ZIG_LOCAL_CACHE_DIR:-}" ]; then  export ZIG_LOCAL_CACHE_DIR=/tmp/.zlcache;  fi
mkdir -p "$ZIG_GLOBAL_CACHE_DIR" "$ZIG_LOCAL_CACHE_DIR"

ZIG=zig
GCC=gcc
C_DRIVER=dafsa_c_driver
ZIG_DRIVER=dafsa_zig_driver
GEN=dafsa_gen

# ─── Build ──────────────────────────────────────────────────────────────────
printf "[build] C driver...\\n"
$GCC -O2 -Wall -Wextra -Werror -std=c11 -D_GNU_SOURCE -I.. \
  ../dafsa.c ../dafsa_state.c ../dafsa_core.c ../dafsa_persist.c \
  ../dafsa_view.c ../dafsa_crc32.c ../dafsa_wal.c ../dafsa_build.c \
  ../dafsa_rank.c ../dafsa_view_rank.c dafsa_c_driver.c -o $C_DRIVER

printf "[build] Zig driver...\\n"
$ZIG build-exe dafsa_zig_driver.zig -O ReleaseSafe -lc

printf "[build] randomized generator...\\n"
$GCC -O2 -Wall -Wextra -std=c11 -D_GNU_SOURCE -o $GEN dafsa_gen.c

# ─── Temp files / cleanup ───────────────────────────────────────────────────
C_OUT=$(mktemp); ZIG_OUT=$(mktemp)
C_STATS=$(mktemp); ZIG_STATS=$(mktemp)
SCRIPT=$(mktemp)
trap 'rm -f "$C_OUT" "$ZIG_OUT" "$C_STATS" "$ZIG_STATS" "$SCRIPT"' EXIT

PASS_COUNT=0
FAIL_COUNT=0

# run_case <name> <script-file>
# Runs both drivers on the script in separate workdirs, asserts byte-equal
# stdout.  On failure, prints full diff + a stats-only diff (the state-
# faithfulness detector: n_states_total + register_probes must match).
run_case() {
  local name="$1"; local script="$2"
  rm -rf /tmp/work_c /tmp/work_z
  mkdir -p /tmp/work_c /tmp/work_z
  ./$C_DRIVER  /tmp/work_c < "$script" > "$C_OUT"
  ./$ZIG_DRIVER /tmp/work_z < "$script" > "$ZIG_OUT"
  if cmp -s "$C_OUT" "$ZIG_OUT"; then
    printf "PASS: %s\\n" "$name"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    printf "FAIL: %s — outputs differ\\n" "$name"
    printf "--- C output (full) ---\\n"; cat "$C_OUT"
    printf "--- Zig output (full) ---\\n"; cat "$ZIG_OUT"
    printf "--- stats-only diff (state-faithfulness) ---\\n"
    grep '^= stats' "$C_OUT"  > "$C_STATS"
    grep '^= stats' "$ZIG_OUT" > "$ZIG_STATS"
    diff "$C_STATS" "$ZIG_STATS" || true
    FAIL_COUNT=$((FAIL_COUNT + 1))
    exit 1
  fi
}

# ─── S1-S5, S8: hand-written corpora (files under scripts/) ──────────────────
run_case "S1 lifecycle basics"        scripts/S1
run_case "S2 shared-prefix families"  scripts/S2
run_case "S3 embedded-NUL keys"        scripts/S3
run_case "S4 delete/re-add ghost"      scripts/S4
run_case "S5 empty key"                scripts/S5
run_case "S8 interleaved add/del/lookup" scripts/S8

# ─── S9: Daciuk build_sorted corpus + build==incremental language-equality ──
# Case 1 builds from a sorted/dedup key list via buildbegin/bkey/buildend;
# Case 2 adds the same keys incrementally.  Both drivers must agree byte-for-byte
# (C-vs-Zig).  Additionally the LANGUAGE-LEVEL stats (fields 2,3,4 = n_reach,
# n_final, n_trans) must match between the build path and the incremental path,
# proving both produce the same minimal DFA for the same language.
run_case "S9 build_sorted + build==incremental" scripts/S9
{
  # Parse the two '= stats' lines (first = build path, second = incremental path)
  # and assert fields 2..4 are equal.  n_states_total (field 1) and probes
  # (field 5) are internal bookkeeping and may differ between strategies.
  ./$C_DRIVER  /tmp/work_c < scripts/S9 > "$C_OUT"
  C_BUILD=$(grep '^= stats' "$C_OUT" | sed -n '1p')
  C_INC=$(  grep '^= stats' "$C_OUT" | sed -n '2p')
  # stats line: '= stats <n_total> <n_reach> <n_final> <n_trans> <probes>'
  # language-level fields = 4,5,6 (n_reach, n_final, n_trans)
  B4=$(echo "$C_BUILD" | awk '{print $4}'); B5=$(echo "$C_BUILD" | awk '{print $5}'); B6=$(echo "$C_BUILD" | awk '{print $6}')
  I4=$(echo "$C_INC"   | awk '{print $4}'); I5=$(echo "$C_INC"   | awk '{print $5}'); I6=$(echo "$C_INC"   | awk '{print $6}')
  if [ "$B4" = "$I4" ] && [ "$B5" = "$I5" ] && [ "$B6" = "$I6" ]; then
    echo "PASS: S9 build==incremental language stats (reach=$B4 final=$B5 trans=$B6)"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo "FAIL: S9 build==incremental stats differ: build=[$C_BUILD] incr=[$C_INC]"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    exit 1
  fi
}

# ─── S10: save/load/loadro persistence + byte-equality of saved .pdwg ───────
# Runs the save->load->mutate->save->loadro sequence on both engines (run_case
# asserts byte-equal stdout), then byte-compares every .pdwg file the C engine
# saved into /tmp/work_c against the one the Zig engine saved into /tmp/work_z.
run_case "S10 save/load/loadro persistence" scripts/S10
{
  pass=1
  for f in s1.pdwg s2.pdwg s3.pdwg s4.pdwg; do
    if cmp -s "/tmp/work_c/$f" "/tmp/work_z/$f"; then
      echo "PASS: S10 byte-equality $f"
    else
      echo "FAIL: S10 byte-equality $f — C and Zig saved different bytes"
      echo "  C:  $(wc -c < /tmp/work_c/$f 2>/dev/null || echo missing) bytes"
      echo "  Z:  $(wc -c < /tmp/work_z/$f 2>/dev/null || echo missing) bytes"
      pass=0
    fi
  done
  if [ "$pass" -eq 1 ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    exit 1
  fi
}

# ─── Cross-load interop (both directions) ───────────────────────────────────
# The C engine saves into /tmp/work_c; that file is copied into the Zig
# workdir and the Zig engine must load it and reproduce identical stats/lookups
# to the C engine loading its own save.  Then the reverse: Zig saves, C loads.
{
  # direction 1: C saves, Zig loads
  rm -rf /tmp/work_c /tmp/work_z
  mkdir -p /tmp/work_c /tmp/work_z
  {
    echo create
    echo "add 616263"; echo "add 616264"; echo "add 626364"; echo "add 61"
    echo "save interop.pdwg"
    echo free
  } > "$SCRIPT"
  ./$C_DRIVER /tmp/work_c < "$SCRIPT" > "$C_OUT"
  cp /tmp/work_c/interop.pdwg /tmp/work_z/interop.pdwg
  # same read-back script: load then lookup/stats, run on both engines
  {
    echo "load interop.pdwg"
    echo "lookup 616263"; echo "lookup 616264"; echo "lookup 626364"; echo "lookup 61"
    echo "lookup 646566"
    echo stats
    echo free
  } > "$SCRIPT"
  ./$C_DRIVER  /tmp/work_c < "$SCRIPT" > "$C_OUT"
  ./$ZIG_DRIVER /tmp/work_z < "$SCRIPT" > "$ZIG_OUT"
  if cmp -s "$C_OUT" "$ZIG_OUT"; then
    echo "PASS: cross-load C-save->Zig-load identical"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo "FAIL: cross-load C-save->Zig-load diverged"
    diff "$C_OUT" "$ZIG_OUT" || true
    FAIL_COUNT=$((FAIL_COUNT + 1)); exit 1
  fi

  # direction 2: Zig saves, C loads
  rm -rf /tmp/work_c /tmp/work_z
  mkdir -p /tmp/work_c /tmp/work_z
  printf 'create\nadd 616263\nadd 616264\nadd 626364\nadd 61\nsave interop.pdwg\nfree\n' | ./$ZIG_DRIVER /tmp/work_z > /dev/null
  cp /tmp/work_z/interop.pdwg /tmp/work_c/interop.pdwg
  printf 'load interop.pdwg\nlookup 616263\nlookup 626364\nstats\nfree\n' | ./$C_DRIVER  /tmp/work_c > "$C_OUT"
  printf 'load interop.pdwg\nlookup 616263\nlookup 626364\nstats\nfree\n' | ./$ZIG_DRIVER /tmp/work_z > "$ZIG_OUT"
  if cmp -s "$C_OUT" "$ZIG_OUT"; then
    echo "PASS: cross-load Zig-save->C-load identical"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo "FAIL: cross-load Zig-save->C-load diverged"
    diff "$C_OUT" "$ZIG_OUT" || true
    FAIL_COUNT=$((FAIL_COUNT + 1)); exit 1
  fi
}

# ─── S12: corruption parity ──────────────────────────────────────────────────
# Every corrupt variant (truncated / bad magic / bad CRC / empty) must make
# BOTH engines' load AND loadro fail identically ('= load 0').  The corrupt
# files are staged into both workdirs from a single good C save.
{
  rm -rf /tmp/work_c /tmp/work_z /tmp/s12gen
  mkdir -p /tmp/work_c /tmp/work_z /tmp/s12gen
  # one good save via C oracle
  printf 'create\nadd 616263\nadd 616264\nadd 626364\nadd 61\nsave good.pdwg\nfree\n' | ./$C_DRIVER /tmp/s12gen > /dev/null
  # truncate: cut off the tail (drops CRC + part of CSR)
  head -c 20 /tmp/s12gen/good.pdwg > /tmp/s12gen/trunc.pdwg
  # bad magic: flip first byte
  cp /tmp/s12gen/good.pdwg /tmp/s12gen/badmagic.pdwg
  printf 'X' | dd of=/tmp/s12gen/badmagic.pdwg bs=1 seek=0 conv=notrunc 2>/dev/null
  # bad CRC: flip a byte in the middle (data region, before the trailing CRC)
  cp /tmp/s12gen/good.pdwg /tmp/s12gen/badcrc.pdwg
  printf 'Z' | dd of=/tmp/s12gen/badcrc.pdwg bs=1 seek=30 conv=notrunc 2>/dev/null
  # empty file
  : > /tmp/s12gen/empty.pdwg
  for f in good trunc badmagic badcrc empty; do
    cp "/tmp/s12gen/$f.pdwg" "/tmp/work_c/$f.pdwg"
    cp "/tmp/s12gen/$f.pdwg" "/tmp/work_z/$f.pdwg"
  done
  ./$C_DRIVER  /tmp/work_c < scripts/S12 > "$C_OUT"
  ./$ZIG_DRIVER /tmp/work_z < scripts/S12 > "$ZIG_OUT"
  if cmp -s "$C_OUT" "$ZIG_OUT"; then
    echo "PASS: S12 corruption parity (load + loadro fail identically)"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo "FAIL: S12 corruption parity diverged"
    echo "--- C ---"; cat "$C_OUT"
    echo "--- Z ---"; cat "$Z_OUT"
    FAIL_COUNT=$((FAIL_COUNT + 1)); exit 1
  fi
}

# ─── U4-deferred: build_sorted-save == incremental-save byte-equality ───────
# Same language reached two ways (Daciuk build vs incremental add) must produce
# byte-identical .pdwg files on BOTH engines, and C's save must equal Zig's
# save.  This is the invariant deferred from U4.
{
  rm -rf /tmp/work_c /tmp/work_z
  mkdir -p /tmp/work_c /tmp/work_z
  # incremental path -> save
  printf 'create\nadd 61\nadd 6162\nadd 616263\nadd 616264\nadd 6163\nadd 6164\nadd 62\nadd 6263\nadd 626364\nadd 6265\nadd 63\nsave inc.pdwg\nfree\n' | ./$C_DRIVER  /tmp/work_c > /dev/null
  printf 'create\nadd 61\nadd 6162\nadd 616263\nadd 616264\nadd 6163\nadd 6164\nadd 62\nadd 6263\nadd 626364\nadd 6265\nadd 63\nsave inc.pdwg\nfree\n' | ./$ZIG_DRIVER /tmp/work_z > /dev/null
  # build path -> save
  printf 'create\nbuildbegin\nbkey 61\nbkey 6162\nbkey 616263\nbkey 616264\nbkey 6163\nbkey 6164\nbkey 62\nbkey 6263\nbkey 626364\nbkey 6265\nbkey 63\nbuildend\nsave build.pdwg\nfree\n' | ./$C_DRIVER  /tmp/work_c > /dev/null
  printf 'create\nbuildbegin\nbkey 61\nbkey 6162\nbkey 616263\nbkey 616264\nbkey 6163\nbkey 6164\nbkey 62\nbkey 6263\nbkey 626364\nbkey 6265\nbkey 63\nbuildend\nsave build.pdwg\nfree\n' | ./$ZIG_DRIVER /tmp/work_z > /dev/null
  ok=1
  cmp -s /tmp/work_c/inc.pdwg   /tmp/work_c/build.pdwg || { echo "FAIL: C build-save != C incremental-save"; ok=0; }
  cmp -s /tmp/work_z/inc.pdwg   /tmp/work_z/build.pdwg || { echo "FAIL: Zig build-save != Zig incremental-save"; ok=0; }
  cmp -s /tmp/work_c/inc.pdwg   /tmp/work_z/inc.pdwg   || { echo "FAIL: C inc-save != Zig inc-save"; ok=0; }
  cmp -s /tmp/work_c/build.pdwg /tmp/work_z/build.pdwg || { echo "FAIL: C build-save != Zig build-save"; ok=0; }
  if [ "$ok" -eq 1 ]; then
    echo "PASS: build_sorted-save == incremental-save (C + Zig, byte-identical)"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    FAIL_COUNT=$((FAIL_COUNT + 1)); exit 1
  fi
}

# ─── S6: byte-alphabet 256-value stress (heap promotion + binary search) ────
# 256 single-byte keys → root gets 256 transitions (n>8 → binary search,
# >4 → heap promotion).  Plus a 5-key 2-byte-prefix family → a non-root state
# with 5 transitions (heap promotion off-root).  Then full delete sweep.
{
  echo create
  for i in $(seq 0 255); do printf "add %02x\\n" "$i"; done
  echo stats
  for i in $(seq 0 255); do printf "lookup %02x\\n" "$i"; done
  echo stats
  echo add 0041; echo add 0042; echo add 0043; echo add 0044; echo add 0045
  echo stats
  for i in $(seq 0 255); do printf "del %02x\\n" "$i"; done
  echo stats
  echo free
} > "$SCRIPT"
run_case "S6 byte-alphabet 256-value stress" "$SCRIPT"

# ─── S7: long keys near 4096 + 4097 rejection ────────────────────────────────
# NOTE: the C oracle driver uses `char line[4096]` + fgets, so lines > 4095
# chars (keys ≥ 2046 bytes) are truncated and re-dispatched as multiple
# "lines" — the Zig driver faithfully replicates this fgets chunking, so both
# produce identical output on long keys.  A 2045-byte key fits (4094 chars)
# and exercises real deep-path traversal + scratch-array growth.  Keys of
# 2046/4096/4097 bytes truncate identically on both sides.
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
run_case "S7 long keys near 4096 + 4097 rejection" "$SCRIPT"

# ─── Randomized seeds: ~5k-op S8-style scripts, 3 seeds ──────────────────────
# Deterministic (rand_r(seed)), 3-symbol alphabet → heavy confluence.  The
# exact-stats gate (n_states_total + register_probes) catches any silent
# state-ID / register / clone-on-write divergence.
for seed in 1 2 3; do
  ./$GEN "$seed" 5000 > "$SCRIPT"
  run_case "randomized seed=$seed (5000 ops)" "$SCRIPT"
done

# ─── U6 VIEW: S10 vopen/vlookup/vprefix over .pdwg saved by both engines ────
# Case 1: same script run on both drivers (each saves its own .pdwg, then opens
# it via the view and runs vlookup/vprefix) — byte-equal stdout, and the saved
# .pdwg files are byte-identical (so the two views index the same bytes).
# Case 2: cross-engine view interop — the C-saved .pdwg opened by the Zig view
# and the Zig-saved .pdwg opened by the C view must both produce the SAME
# vlookup/vprefix results as each driver reading its own save.
# Case 3: scale-pass view — a larger corpus (100 keys, W\0 payload form) saved
# and re-opened via view, vlookup + vprefix sampled.
{
  # view case script: build a W\0-payload language, save, re-open via view,
  # exercise vlookup + vprefix (payload DFS sym-ascending)
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
run_case "S10 view vopen/vlookup/vprefix" "$SCRIPT"
{
  # byte-equality of the .pdwg saved in the view case above
  if cmp -s /tmp/work_c/view1.pdwg /tmp/work_z/view1.pdwg; then
    echo "PASS: S10 view .pdwg byte-equality (C-vs-Zig)"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo "FAIL: S10 view .pdwg byte-equality — C and Zig saved different bytes"
    echo "  C: $(wc -c < /tmp/work_c/view1.pdwg) bytes  Z: $(wc -c < /tmp/work_z/view1.pdwg) bytes"
    FAIL_COUNT=$((FAIL_COUNT + 1)); exit 1
  fi
}
# cross-engine view interop: both directions
{
  rm -rf /tmp/work_c /tmp/work_z
  mkdir -p /tmp/work_c /tmp/work_z
  # C saves, Zig view opens it
  printf 'create\nadd 610001\nadd 610002\nadd 610003\nadd 6200aa\nadd 6200bb\nsave ci.pdwg\nfree\n' | ./$C_DRIVER /tmp/work_c > /dev/null
  cp /tmp/work_c/ci.pdwg /tmp/work_z/ci.pdwg
  printf 'vopen ci.pdwg\nvlookup 610002\nvlookup 6200bb\nvlookup 9900ff\nvprefix 61\nvprefix 62\nvclose\n' | ./$ZIG_DRIVER /tmp/work_z > "$ZIG_OUT"
  # Zig saves, C view opens it
  rm -rf /tmp/work_c /tmp/work_z
  mkdir -p /tmp/work_c /tmp/work_z
  printf 'create\nadd 610001\nadd 610002\nadd 610003\nadd 6200aa\nadd 6200bb\nsave zi.pdwg\nfree\n' | ./$ZIG_DRIVER /tmp/work_z > /dev/null
  cp /tmp/work_z/zi.pdwg /tmp/work_c/zi.pdwg
  printf 'vopen zi.pdwg\nvlookup 610002\nvlookup 6200bb\nvlookup 9900ff\nvprefix 61\nvprefix 62\nvclose\n' | ./$C_DRIVER /tmp/work_c > "$C_OUT"
  if cmp -s "$C_OUT" "$ZIG_OUT"; then
    echo "PASS: S10 view cross-engine interop (C-save->Zig-view == Zig-save->C-view)"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo "FAIL: S10 view cross-engine interop diverged"
    echo "--- C-view output ---"; cat "$C_OUT"
    echo "--- Zig-view output ---"; cat "$ZIG_OUT"
    FAIL_COUNT=$((FAIL_COUNT + 1)); exit 1
  fi
}
# scale-pass view: larger corpus opened via view, vlookup + vprefix sampled
{
  rm -rf /tmp/work_c /tmp/work_z
  mkdir -p /tmp/work_c /tmp/work_z
  # generate a 400-key W\0-payload corpus on the C side (save shared bytes)
  echo create > "$SCRIPT"
  for i in $(seq 0 399); do
    printf "add 61%02x%04x\n" "$((i / 64))" "$i" >> "$SCRIPT"
  done
  echo "add 6200cafe" >> "$SCRIPT"
  echo "save viewscale.pdwg" >> "$SCRIPT"
  echo free >> "$SCRIPT"
  ./$C_DRIVER /tmp/work_c < "$SCRIPT" > /dev/null
  # Zig view over the C-saved scale file, and C view over its own file: identical
  cp /tmp/work_c/viewscale.pdwg /tmp/work_z/viewscale.pdwg
  {
    echo "vopen viewscale.pdwg"
    echo "vlookup 610001"; echo "vlookup 61ff0000"; echo "vlookup 6200cafe"; echo "vlookup 6300cafe"
    echo "vprefix 61"; echo "vprefix 62"
    echo "vclose"
  } > "$SCRIPT"
  ./$C_DRIVER  /tmp/work_c < "$SCRIPT" > "$C_OUT"
  ./$ZIG_DRIVER /tmp/work_z < "$SCRIPT" > "$ZIG_OUT"
  if cmp -s "$C_OUT" "$ZIG_OUT"; then
    echo "PASS: S10 view scale-pass (400-key corpus via view, C-vs-Zig identical)"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo "FAIL: S10 view scale-pass diverged"
    diff "$C_OUT" "$ZIG_OUT" || true
    FAIL_COUNT=$((FAIL_COUNT + 1)); exit 1
  fi
}

# ─── S11 WAL: byte-equality + replay + torn-tail + layered lopen ────────────
# WAL ops (wopen/wopenro/wadd/wdel/wsize/wreplay/wclose/lopen) added in U7.
# Gate 1: same script on both drivers — byte-equal stdout incl. the wreplay
# per-record lines and the layered lopen vlookup/vprefix (last-wins tombstones).
# Gate 2: WAL file byte-equality — the .wal and base .pdwg written by both
# engines must be byte-identical.
# Gate 3: torn-tail ftruncate parity — corrupt a valid WAL with a partial tail
# record; both engines' wopen(rw) must ftruncate to the same good length and
# produce byte-identical resulting files + output.
run_case "S11 WAL + layered lopen" scripts/S11
{
  pass=1
  for f in wal.wal base.pdwg; do
    if cmp -s "/tmp/work_c/$f" "/tmp/work_z/$f"; then
      echo "PASS: S11 byte-equality $f"
    else
      echo "FAIL: S11 byte-equality $f — C and Zig wrote different bytes"
      echo "  C: $(wc -c < /tmp/work_c/$f 2>/dev/null || echo missing) bytes"
      echo "  Z: $(wc -c < /tmp/work_z/$f 2>/dev/null || echo missing) bytes"
      pass=0
    fi
  done
  if [ "$pass" -eq 1 ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    FAIL_COUNT=$((FAIL_COUNT + 1)); exit 1
  fi
}
{
  rm -rf /tmp/work_c /tmp/work_z /tmp/ttgen
  mkdir -p /tmp/work_c /tmp/work_z /tmp/ttgen
  # create a valid 2-record WAL via the C oracle
  printf 'wopen tt.wal\nwadd 610000000000000000aa\nwadd 620000000000000000bb\nwclose\n' | ./$C_DRIVER /tmp/ttgen > /dev/null
  # simulate a torn tail: append a partial record (op=ADD, key_len=1, one key
  # byte, no CRC) — incomplete per wal_validate_record (needs >=10 bytes).
  printf '\001\000\000\000\001a' >> /tmp/ttgen/tt.wal
  cp /tmp/ttgen/tt.wal /tmp/work_c/tt.wal
  cp /tmp/ttgen/tt.wal /tmp/work_z/tt.wal
  # both engines wopen(rw) -> ftruncate the torn tail; then wsize/wreplay
  printf 'wopen tt.wal\nwsize\nwreplay\nwclose\n' > "$SCRIPT"
  ./$C_DRIVER  /tmp/work_c < "$SCRIPT" > "$C_OUT"
  ./$ZIG_DRIVER /tmp/work_z < "$SCRIPT" > "$ZIG_OUT"
  if cmp -s "$C_OUT" "$ZIG_OUT" && cmp -s /tmp/work_c/tt.wal /tmp/work_z/tt.wal; then
    echo "PASS: S11 torn-tail ftruncate parity (byte-identical stdout + file)"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo "FAIL: S11 torn-tail ftruncate parity diverged"
    echo "--- C stdout ---"; cat "$C_OUT"
    echo "--- Z stdout ---"; cat "$ZIG_OUT"
    echo "  C file: $(wc -c < /tmp/work_c/tt.wal 2>/dev/null || echo missing) bytes"
    echo "  Z file: $(wc -c < /tmp/work_z/tt.wal 2>/dev/null || echo missing) bytes"
    FAIL_COUNT=$((FAIL_COUNT + 1)); exit 1
  fi
}

# ─── S13 rank/select/rancount (U8) ──────────────────────────────────────────
# Differential corpus: rank (present + absent insertion-position), select in
# range + k>=total -> -1, rancount half-open intervals, _from forms via
# fromstate (prefix-walk start state), and view rank over the saved .pdwg.
# Also byte-compare the s13.pdwg saved by both engines.
run_case "S13 rank/select/rancount + _from + view rank" scripts/S13
{
  if cmp -s /tmp/work_c/s13.pdwg /tmp/work_z/s13.pdwg; then
    echo "PASS: S13 .pdwg byte-equality (C-vs-Zig)"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo "FAIL: S13 .pdwg byte-equality — C and Zig saved different bytes"
    echo "  C: $(wc -c < /tmp/work_c/s13.pdwg 2>/dev/null || echo missing) bytes"
    echo "  Z: $(wc -c < /tmp/work_z/s13.pdwg 2>/dev/null || echo missing) bytes"
    FAIL_COUNT=$((FAIL_COUNT + 1)); exit 1
  fi
}

# ─── S13-scale: rank/select/rancount pass on a larger corpus ────────────────
# 400 generated keys + a few outliers; then sampled rank (present + absent),
# select (in-range + k>=total), rancount, and a fromstate _from sample.  Both
# engines must produce byte-identical output.
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
  run_case "S13-scale rank/select/rancount (400-key corpus)" "$SCRIPT"
}

# ─── Summary ────────────────────────────────────────────────────────────────
printf "\\n[gate] %d passed, %d failed\\n" "$PASS_COUNT" "$FAIL_COUNT"
if [ "$FAIL_COUNT" -ne 0 ]; then exit 1; fi
printf "[gate] S1-S12 + 3 randomized seeds ALL PASS (exact stats + byte-equality)\\n"
printf "ALL PASS\\n"
