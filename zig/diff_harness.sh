#!/usr/bin/env bash
# diff_harness.sh — Differential-test harness for C↔Zig CRC32 migration
set -euo pipefail

# Ensure cache dirs for Zig in sandbox
if [ -z "${ZIG_GLOBAL_CACHE_DIR:-}" ]; then
  export ZIG_GLOBAL_CACHE_DIR=/tmp/.zcache
fi
if [ -z "${ZIG_LOCAL_CACHE_DIR:-}" ]; then
  export ZIG_LOCAL_CACHE_DIR=/tmp/.zlcache
fi
mkdir -p "$ZIG_GLOBAL_CACHE_DIR" "$ZIG_LOCAL_CACHE_DIR"

# Build C driver
printf "[1/5] Building C driver...\n"
gcc -O2 -Wall -Wextra -Werror -std=c11 -I.. -o crc32_c_driver ../dafsa_crc32.c crc32_c_driver.c

# Build Zig driver
printf "[2/5] Building Zig driver...\n"
zig build-exe crc32_zig_driver.zig -O ReleaseSafe

# Prepare temp files for outputs
C_OUT=$(mktemp)
ZIG_OUT=$(mktemp)

trap 'rm -f "$C_OUT" "$ZIG_OUT"' EXIT

# Function to run a test case from a string variable
# NOTE: bash variables cannot contain NUL bytes, so this is only
# safe for NUL-free inputs. Use run_case_raw for binary inputs.
run_case() {
  local name="$1"; shift
  local input="$1"; shift
  printf "[3/5] Running case: %s...\n" "$name"

  # Run C driver
  printf "%s" "$input" | ./crc32_c_driver > "$C_OUT"

  # Run Zig driver
  printf "%s" "$input" | ./crc32_zig_driver > "$ZIG_OUT"

  # Compare outputs
  if ! cmp -s "$C_OUT" "$ZIG_OUT"; then
    echo "FAIL: $name — outputs differ"
    echo "C output:"
    cat "$C_OUT"
    echo "Zig output:"
    cat "$ZIG_OUT"
    exit 1
  fi
  echo "PASS: $name"
}

# Function to run a test case from raw printf (supports NUL bytes)
run_case_raw() {
  local name="$1"; shift
  local printf_args=("$@")
  printf "[3/5] Running case: %s...\n" "$name"

  printf "${printf_args[@]}" | ./crc32_c_driver > "$C_OUT"
  printf "${printf_args[@]}" | ./crc32_zig_driver > "$ZIG_OUT"

  if ! cmp -s "$C_OUT" "$ZIG_OUT"; then
    echo "FAIL: $name — outputs differ"
    echo "C output:"
    cat "$C_OUT"
    echo "Zig output:"
    cat "$ZIG_OUT"
    exit 1
  fi
  echo "PASS: $name"
}

# Empty input
run_case "empty" ""

# Canonical check value string
run_case "123456789" "123456789"

# Plain ASCII strings
run_case "hello" "hello"
run_case "hello world" "hello world"
run_case "The quick brown fox jumps over the lazy dog" "The quick brown fox jumps over the lazy dog"

# Embedded NUL bytes (use run_case_raw — bash vars can't hold NUL)
run_case_raw "embedded_nul" 'a\0b\0c\0d\0e'

# ~1KB buffer (patterned)
printf -v kb1k '%*s' 1024 "A" 
run_case "1k_buffer" "$kb1k"

# ~1MB buffer (patterned)
printf -v mb1 'A%.0s' {1..1048576} 
run_case "1m_buffer" "$mb1"

# Assert C driver canonical check value.
# NOTE: $C_OUT currently holds the LAST differential case's output (1m_buffer),
# not 123456789, so re-run the C driver on the canonical input here.
printf "123456789" | ./crc32_c_driver > "$C_OUT"
C_VAL=$(cat "$C_OUT")
if [ "$C_VAL" != "cbf43926" ]; then
  echo "FAIL: C driver canonical check value mismatch: expected cbf43926, got $C_VAL"
  exit 1
fi

printf "[4/5] All differential tests PASSED.\n"
printf "[5/5] Canonical check value verified: cbf43926\n"
echo "ALL PASS"
