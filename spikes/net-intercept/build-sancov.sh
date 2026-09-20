#!/usr/bin/env bash
# Build one example with LLVM SanitizerCoverage so ChildCoverage has counters to read.
# Usage: ./build-sancov.sh std_client  (binary lands in target/release/examples/<name>)
set -euo pipefail
cd "$(dirname "$0")"
name="${1:-std_client}"
cargo rustc --release --example "$name" -- \
  -Cpasses=sancov-module \
  -Cllvm-args=-sanitizer-coverage-level=3 \
  -Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
  -Cllvm-args=-sanitizer-coverage-pc-table \
  -Cllvm-args=-sanitizer-coverage-trace-compares
