#!/usr/bin/env bash
# Build the demo targets with SanitizerCoverage trace-pc-guard instrumentation.
#
# `cargo rustc` applies the extra flags only to the final crate, so the `sched-target-rt` runtime
# (which defines the __sanitizer_cov_* callbacks) and std are NOT instrumented — otherwise the
# callback would call itself. Binaries land in targets/target/release/. An uninstrumented copy of
# the edge microbenchmark is built into targets/target/plain/release/ for the overhead comparison.
set -euo pipefail
cd "$(dirname "$0")/targets"
BINS="sched_lost_update sched_deadlock sched_missed_notify sched_edge_bench sched_stop_bench"
for bin in $BINS; do
    cargo rustc --release --bin "$bin" -- \
        -Cpasses=sancov-module \
        -Cllvm-args=-sanitizer-coverage-level=3 \
        -Cllvm-args=-sanitizer-coverage-trace-pc-guard \
        -Cllvm-args=-sanitizer-coverage-pc-table
done
cargo build --release --bin sched_edge_bench --target-dir target/plain
if command -v objdump >/dev/null; then
    for bin in $BINS; do
        n=$(objdump -d --no-show-raw-insn "target/release/$bin" | grep -c 'call.*__sanitizer_cov_trace_pc_guard>' || true)
        echo "$bin: $n instrumented edges"
    done
fi
