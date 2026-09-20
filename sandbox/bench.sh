#!/usr/bin/env bash
# Runs-to-first-failure per target × seed. Usage: bench.sh [max_runs] [seeds...]
set -uo pipefail
cd "$(dirname "$0")/.."
MAX="${1:-3000}"
shift || true
SEEDS="${*:-1 2 3}"
cargo build --release -q -p dowsing-sandbox --example explore
for t in lost_update deadlock sleep_race; do
    for s in $SEEDS; do
        out=$(timeout 300 ./target/release/examples/explore "sandbox/targets/target/release/$t" \
            --runs "$MAX" --seed "$s" --replays 0 2>&1 | grep -vE '^\[sandbox\]')
        first=$(echo "$out" | grep -oE '^failure on run [0-9]+: .*' | head -1)
        shrink=$(echo "$out" | grep -oE '^shrink: .*' | head -1)
        printf '%-12s seed %s: %s | %s\n' "$t" "$s" "${first:-no failure in $MAX runs}" "${shrink:--}"
    done
done
