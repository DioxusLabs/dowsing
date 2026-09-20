#!/usr/bin/env bash
# Median / max runs-to-failure over seeds for each small target with the current build.
# usage: sandbox/sweep.sh [seeds=10] [max_runs=3000] [extra explore flags...]
set -euo pipefail
cd "$(dirname "$0")/.."
seeds=${1:-10}
max=${2:-3000}
shift 2 || true
for t in lost_update deadlock sleep_race; do
    vals=()
    for s in $(seq 1 "$seeds"); do
        out=$(./target/release/examples/explore "sandbox/targets/target/release/$t" --runs "$max" --seed "$s" "$@" 2>&1 | grep -E '^runs' | head -1)
        r=$(echo "$out" | sed -E 's/^runs ([0-9]+) .*/\1/')
        if ! echo "$out" | grep -q 'failures [1-9]'; then r="${max}+"; fi
        vals+=("$r")
    done
    sorted=$(printf '%s\n' "${vals[@]}" | sed 's/+//' | sort -n)
    med=$(echo "$sorted" | awk '{a[NR]=$1} END{print (NR%2)?a[(NR+1)/2]:(a[NR/2]+a[NR/2+1])/2}')
    sum=$(echo "$sorted" | awk '{s+=$1} END{print s}')
    printf '%-12s median %6s  total %7s  [%s]\n' "$t" "$med" "$sum" "${vals[*]}"
done
