#!/usr/bin/env bash
# Build the sancov-instrumented bench binary and run it across seeds.
#
# Usage: ./run_matrix.sh [label] [seeds...]
#   env knobs are forwarded to the binary: STRUCTURED, COST, HAVOC, SEMANTIC,
#   DISCOVERY_CASES, MINIMIZATION_CASES, VERBOSE.
#   PROFILE=debug builds without --release (default: release).
#   ASLR=1 keeps address-space randomization on (default: off via `setarch -R`).
#   SKIP_BUILD=1 reuses the existing binary.
set -euo pipefail

cd "$(dirname "$0")"

label="${1:-run}"
shift || true
seeds=("$@")
if [ "${#seeds[@]}" -eq 0 ]; then
  seeds=(0 1 2 3 4 5 6 7 8 9)
fi

profile="${PROFILE:-release}"
if [ "$profile" = "release" ]; then
  profile_flag="--release"
else
  profile_flag=""
fi

sancov_flags=(
  -Cpasses=sancov-module
  -Cllvm-args=-sanitizer-coverage-level=3
  -Cllvm-args=-sanitizer-coverage-inline-8bit-counters
  -Cllvm-args=-sanitizer-coverage-pc-table
  -Cllvm-args=-sanitizer-coverage-trace-compares
)

if [ "${SKIP_BUILD:-0}" != "1" ]; then
  # shellcheck disable=SC2086
  cargo rustc --quiet --bin shrink-bench $profile_flag -- "${sancov_flags[@]}"
fi

bin="target/$profile/shrink-bench"
runner=()
if [ "${ASLR:-0}" != "1" ] && command -v setarch >/dev/null 2>&1; then
  runner=(setarch x86_64 -R)
fi

ops_row=""
success=0
for seed in "${seeds[@]}"; do
  line="$(SEED="$seed" "${runner[@]}" "$bin" || true)"
  echo "$label $line"
  ops="$(sed -n 's/.* ops=\([0-9]*\) .*/\1/p' <<<"$line")"
  if [ -z "$ops" ]; then
    ops="X"
  elif [ "$ops" -le 8 ]; then
    success=$((success + 1))
  fi
  ops_row="$ops_row $ops"
done
echo "$label SUMMARY ops:$ops_row  success(<=8 ops): $success/${#seeds[@]}"
