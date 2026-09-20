#!/usr/bin/env bash
# Time-to-bug over N seeds for the sancov-instrumented demo. Run from spikes/fs-env-intercept
# after building `sandboxed_config` with the SanitizerCoverage flags from README.md.
#
#   scripts/time_to_bug.sh [seeds=10] [extra args for sandboxed_config...]
#
# Prints one line per seed (cases to bug, seconds) and a summary (min/median/max cases).
set -euo pipefail
seeds=${1:-10}
shift || true
bin=target/release/examples/sandboxed_config
results=()
for seed in $(seq 1 "$seeds"); do
    out=$("$bin" --seed "$seed" --cases 200000 "$@" 2>/dev/null | grep -E "^(found|no) bug" || true)
    if [[ "$out" =~ found\ bug\ after\ ([0-9]+)\ cases.*in\ ([0-9.]+)(ms|s) ]]; then
        cases=${BASH_REMATCH[1]}
        secs=${BASH_REMATCH[2]}
        [[ ${BASH_REMATCH[3]} == ms ]] && secs=$(awk "BEGIN{print $secs/1000}")
        printf 'seed %2d: %7d cases  %6.2fs\n' "$seed" "$cases" "$secs"
        results+=("$cases")
    else
        printf 'seed %2d: NOT FOUND in 200000 cases\n' "$seed"
        results+=(200000)
    fi
done
sorted=$(printf '%s\n' "${results[@]}" | sort -n)
min=$(echo "$sorted" | head -1)
max=$(echo "$sorted" | tail -1)
median=$(echo "$sorted" | awk '{a[NR]=$1} END{print (NR%2)? a[(NR+1)/2] : (a[NR/2]+a[NR/2+1])/2}')
echo "summary ($seeds seeds$*): min $min, median $median, max $max cases to bug"
