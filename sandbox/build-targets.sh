#!/usr/bin/env bash
# Build the demo targets with SanitizerCoverage trace-pc-guard edge instrumentation.
#
# `cargo rustc` applies the flags only to the final crate: the target runtime (which defines the
# __sanitizer_cov_* callbacks) and std stay uninstrumented. Binaries: targets/target/release/.
set -euo pipefail
cd "$(dirname "$0")/targets"
BINS="${*:-lost_update deadlock sleep_race uncontrolled slow_setup axum_counter}"
for bin in $BINS; do
    cargo rustc --release --bin "$bin" -- \
        -Cpasses=sancov-module \
        -Cllvm-args=-sanitizer-coverage-level=3 \
        -Cllvm-args=-sanitizer-coverage-trace-pc-guard
done
if command -v objdump >/dev/null; then
    for bin in $BINS; do
        n=$(objdump -d --no-show-raw-insn "target/release/$bin" | grep -c 'call.*__sanitizer_cov_trace_pc_guard>' || true)
        echo "$bin: $n instrumented edges"
    done
fi
