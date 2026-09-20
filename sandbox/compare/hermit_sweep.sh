#!/usr/bin/env bash
# Seed sweep of the sandbox targets under Hermit (facebookexperimental/hermit).
#
#   HERMIT=/path/to/hermit ./hermit_sweep.sh [seeds]
#
# Building hermit on this host needed: upstream commit 20622f9 (v1; HEAD's autocargo Cargo.toml
# drops the detcore-dbi/reverie-kvm path deps), reverie pinned to 3ca6f7f with two patches
# (Emerald Rapids model 0xCF in timer.rs, and REVERIE_NO_PRECISE_IP=1 to skip PEBS, which the
# KVM guest rejects), nightly-2025-03-03, textwrap 0.16.1, time 0.3.36, RUSTFLAGS=-Clink-arg=-llzma.
# The maintained fork (rrnewton/hermit) needs Linux >= 6.9 (PIDFD_THREAD) and does not start on 6.8.
set -euo pipefail
cd "$(dirname "$0")"
HERMIT=${HERMIT:-hermit}
N=${1:-100}
T=../targets/target/release
export REVERIE_NO_PRECISE_IP=1

sweep() {
  local label=$1 t=$2; shift 2
  local fails=0 first="" rc
  local start end
  start=$(date +%s.%N)
  for i in $(seq 1 "$N"); do
    if ! timeout 120 "$HERMIT" run "$@" --seed="$i" -- "$T/$t" >/dev/null 2>&1; then
      fails=$((fails + 1)); [ -z "$first" ] && first=$i
    fi
  done
  end=$(date +%s.%N)
  printf 'hermit %-11s %-34s %s/%s failed (first=%s) %.1f ms/run\n' "$t" "[$label]" "$fails" "$N" "${first:-none}" \
    "$(echo "($end-$start)*1000/$N" | bc -l)"
}

echo "hermit: $("$HERMIT" --version 2>&1 | head -1)"
for t in lost_update deadlock sleep_race; do
  sweep "default" "$t"
  sweep "Random" "$t" --sched-heuristic=Random
  sweep "StickyRandom p=0.5" "$t" --sched-heuristic=StickyRandom --sched-sticky-random-param=0.5
  sweep "chaos pt=100000" "$t" --chaos --preemption-timeout=100000
  sweep "chaos pt=10000" "$t" --chaos --preemption-timeout=10000
done
echo "hermit verify (2 runs + log compare):"
( time "$HERMIT" run --verify --chaos --preemption-timeout=100000 --seed=7 -- "$T/lost_update" ) 2>&1 | grep -E "Success|differ|real"
