#!/usr/bin/env bash
# Reproduces every number in README.md. Run from spikes/coverage-bridge after the build steps
# in README "Build" (instrumented buggy_stack_child in target/release, edge-only variant in
# target/edges, uninstrumented variant in target/plain).
set -euo pipefail
cd "$(dirname "$0")/.."
R=./target/release
run() { echo; echo "\$ $*"; "$@"; }

echo "== demo: forkserver, curious() -> cautious() -> Case::replay()"
run $R/buggy_stack_bridge --mode fork --seed 1
echo; echo "== demo: exec-per-case baseline"
run $R/buggy_stack_bridge --mode exec --seed 1 --minimize 1000
echo; echo "== demo: crash path (harness aborts on the bug)"
BUGGY_STACK_ABORT=1 run $R/buggy_stack_bridge --mode fork --seed 1 --minimize 2048

echo; echo "== throughput: curious() loop, 4096 cases, every case fed back"
run $R/buggy_stack_bridge --bench 4096
run $R/buggy_stack_bridge --bench 4096 --no-cmp
run $R/buggy_stack_bridge --bench 4096 --mode exec
run $R/buggy_stack_bridge --bench 4096 --mode exec --no-cmp
run $R/buggy_stack_bridge --bench 4096 --no-cmp --child ./target/edges/release/buggy_stack_child
run $R/buggy_stack_child --bench 4096
run $R/buggy_stack_child --bench 4096 --no-cmp
run ./target/edges/release/buggy_stack_child --bench 4096 --no-cmp
run $R/buggy_stack_child --bench 4096 --no-coverage

echo; echo "== where the child spends its time (one case, instrumented with trace-compares)"
COVERAGE_BRIDGE_PROFILE=1 run $R/buggy_stack_bridge --bench 3 2>&1 | grep -E "profile|exec/s" | tail -2
echo; echo "== same, edge counters only"
COVERAGE_BRIDGE_PROFILE=1 run $R/buggy_stack_bridge --bench 3 --no-cmp --child ./target/edges/release/buggy_stack_child 2>&1 | grep -E "profile|exec/s" | tail -2

echo; echo "== protocol floor and fork cost vs RSS (uninstrumented echo target, discard every case)"
run $R/bench --child $R/echo_child --cases 3000 --rss 10,100 -- --always-pass
echo; echo "== bridge round trip for the real target, uninstrumented / edges / edges+cmp"
run $R/bench --child ./target/plain/release/buggy_stack_child --cases 3000
run $R/bench --child ./target/edges/release/buggy_stack_child --cases 3000
run $R/bench --child $R/buggy_stack_child --cases 3000

echo; echo "== cases-to-bug and shrink result over 10 seeds, in-process vs bridge"
run ./scripts/seeds.sh
