#!/usr/bin/env bash
# Cases-to-bug and shrink result over N seeds: in-process sancov+cmp vs bridge forkserver.
# Run from spikes/coverage-bridge after building (see README "Build").
set -euo pipefail
cd "$(dirname "$0")/.."
SEEDS="${SEEDS:-1 2 3 4 5 6 7 8 9 10}"
MIN="${MIN:-2048}"
printf '%-5s %-22s %-22s %-14s %-14s\n' seed "in-process cases->bug" "bridge cases->bug" "in-proc shrink" "bridge shrink"
for seed in $SEEDS; do
  inproc=$(./target/release/buggy_stack_child --seed "$seed" --minimize "$MIN")
  bridge=$(./target/release/buggy_stack_bridge --quiet --seed "$seed" --minimize "$MIN")
  in_cases=$(sed -n 's/.*found bug after \([0-9]*\) cases.*/\1/p' <<<"$inproc")
  in_shrink=$(sed -n 's/.*minimized to \([0-9]*\) ops \/ \([0-9]*\) bytes.*/\1 ops \2 B/p' <<<"$inproc")
  br_cases=$(sed -n 's/.*: case \([0-9]*\) failed with.*/\1/p' <<<"$bridge")
  br_shrink=$(sed -n 's/^replay in-process: REPRODUCED with \([0-9]*\) ops (\([0-9]*\) bytes).*/\1 ops \2 B/p' <<<"$bridge")
  printf '%-5s %-22s %-22s %-14s %-14s\n' "$seed" "${in_cases:-none}" "${br_cases:-none}" "${in_shrink:-?}" "${br_shrink:-?}"
done
