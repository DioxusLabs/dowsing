#!/usr/bin/env bash
# Measures every tool on the same three bugs + the snapshot/restore task and writes one line
# per measurement to compare/results.txt. Usage: run.sh [section...]
# Sections: native rr sandbox loom shuttle snapshot tsan axum   (default: all)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
TGT="$ROOT/sandbox/targets/target/release"
OUT="${OUT:-$HERE/results.txt}"
SECTIONS="${*:-native rr sandbox loom shuttle snapshot tsan axum}"
SEEDS="${SEEDS:-1 2 3}"

say() { echo "$*" | tee -a "$OUT"; }
ms() { echo "($2-$1)*1000" | bc; }
has() { case " $SECTIONS " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

# Runs `cmd` N times, counting non-zero exits (timeout 124 = hang). Prints runs, failures, per-run ms.
stress() {
    local label=$1 n=$2 tmo=$3; shift 3
    local f=0 hang=0 s e
    s=$(date +%s.%N)
    for _ in $(seq "$n"); do
        timeout "$tmo" "$@" > /dev/null 2>&1
        case $? in 0) ;; 124) hang=$((hang + 1)) ;; *) f=$((f + 1)) ;; esac
    done
    e=$(date +%s.%N)
    say "$label runs=$n failures=$f hangs=$hang total_ms=$(ms "$s" "$e") per_run_ms=$(echo "scale=2; $(ms "$s" "$e")/$n" | bc)"
}

[ -x "$TGT/lost_update" ] || "$ROOT/sandbox/build-targets.sh"
(cd "$ROOT" && cargo build --release -q -p dowsing-sandbox --example explore)
(cd "$HERE" && cargo build --release -q)
: > "$OUT"
say "# $(date -u +%FT%TZ) $(uname -r) $(nproc)cpu $(lscpu | awk -F: '/Model name/{gsub(/^ +/,"",$2);print $2}')"

if has native; then
    say "## native: run the unmodified binary in a loop (stress testing)"
    stress "tool=native target=lost_update" 20000 5 "$TGT/lost_update"
    stress "tool=native target=deadlock" 2000 2 "$TGT/deadlock"
    stress "tool=native target=sleep_race" 2000 5 "$TGT/sleep_race"
fi

# rr and hermit need hardware perf counters; with perf_event_paranoid > 1 every run exits
# non-zero and `stress` would count that as 300/300 failures.
perf_ok() {
    local p; p=$(cat /proc/sys/kernel/perf_event_paranoid)
    [ "$p" -le 1 ] && return 0
    say "$1 skipped: kernel.perf_event_paranoid=$p (needs <= 1; sudo sysctl kernel.perf_event_paranoid=1)"
    return 1
}

if has rr && perf_ok "tool=rr-chaos"; then
    say "## rr chaos mode (rr record -h): randomized scheduling of the unmodified binary"
    export _RR_TRACE_DIR=/tmp/rr-compare
    rm -rf "$_RR_TRACE_DIR"; mkdir -p "$_RR_TRACE_DIR"
    stress "tool=rr-chaos target=lost_update" 300 10 rr record -h "$TGT/lost_update"
    rm -rf "$_RR_TRACE_DIR"/*
    stress "tool=rr-chaos target=deadlock" 300 3 rr record -h "$TGT/deadlock"
    rm -rf "$_RR_TRACE_DIR"/*
    stress "tool=rr-chaos target=sleep_race" 300 10 rr record -h "$TGT/sleep_race"
    rm -rf "$_RR_TRACE_DIR"/*
    rr record -o "$_RR_TRACE_DIR/one" "$TGT/lost_update" > /dev/null 2>&1
    s=$(date +%s.%N)
    for _ in $(seq 20); do rr replay -a "$_RR_TRACE_DIR/one" > /dev/null 2>&1; done
    e=$(date +%s.%N)
    say "tool=rr-replay target=lost_update replays=20 per_replay_ms=$(echo "scale=1; $(ms "$s" "$e")/20" | bc) (deterministic by construction)"
    rm -rf "$_RR_TRACE_DIR"
fi

if has sandbox; then
    say "## dowsing-sandbox (this PR): explore <bin> --runs 3000 --seed S --replays 100"
    for t in lost_update deadlock sleep_race; do
        for s in $SEEDS; do
            out=$(cd "$ROOT" && timeout 600 ./target/release/examples/explore "$TGT/$t" --runs 3000 --seed "$s" --replays 100 2>&1 | grep -vE '^\[sandbox\]')
            first=$(echo "$out" | grep -E '^runs [0-9]+ in' | head -1)
            fail=$(echo "$out" | grep -oE '^failure on run [0-9]+: .*' | head -1)
            replay=$(echo "$out" | grep -oE '^replay x100: .*' | head -1)
            shrink=$(echo "$out" | grep -oE '^shrink: .*' | head -1)
            snap=$(echo "$out" | grep -oE '^snapshots: .*' | head -1)
            rest=$(echo "$out" | grep -oE '^restores: .*' | head -1)
            say "tool=sandbox target=$t seed=$s | ${fail:-no failure} | ${first} | ${replay:-} | ${shrink:-} | $snap | $rest"
        done
    done
fi

# One sandbox search over the axum server driven through virtual sockets; prints the same
# summary line as the sandbox section. axum <label> <corpus-dir> <seed> [extra explore flags]
axum() {
    local label=$1 corpus=$2 s=$3; shift 3
    local out first fail replay shrink
    out=$(cd "$ROOT" && timeout 700 ./target/release/examples/explore "$TGT/axum_counter" --clients 3 --corpus "$corpus" --snapshot-every 32 --replays 10 --seed "$s" "$@" 2>&1 | grep -vE '^\[sandbox\]')
    first=$(echo "$out" | grep -E '^runs [0-9]+ in' | head -1)
    fail=$(echo "$out" | grep -oE '^failure on run [0-9]+: .*' | head -1)
    stderr=$(echo "$out" | grep -oE 'lost update: .*' | head -1)
    replay=$(echo "$out" | grep -oE '^replay x10: .*' | head -1)
    shrink=$(echo "$out" | grep -oE '^shrink: .*' | head -1)
    say "tool=sandbox target=axum_counter case=$label seed=$s | ${fail:-no failure} ${stderr:+($stderr)} | ${first} | ${replay:-} | ${shrink:-}"
}

if has axum; then
    say "## axum 0.8 + tokio (2 workers), unmodified binary, driven through the virtual socket API"
    say "## native: python client, 2 concurrent POSTs then GET /check per round, 60 s budget"
    for p in /inc /inc_nowait; do
        python3 "$HERE/axum_native_stress.py" "$TGT/axum_counter" 60 "$p" 2>&1 | grep -E '^native' | tee -a "$OUT"
    done
    say "## sandbox: explore axum_counter --clients 3 --corpus <dir> --runs 3000 (stop on first failure)"
    for s in $SEEDS; do axum inc_await "$ROOT/sandbox/corpus/axum_await" "$s" --runs 3000; done
    say "## sandbox: /sum framing bug (HTTP 500 when the JSON body is split across reads), corpus/axum"
    for s in $SEEDS; do axum sum_split "$ROOT/sandbox/corpus/axum" "$s" --runs 3000; done
    say "## sandbox: /inc_nowait (no await between the two lock() calls), --runs 50000 --wall 600"
    for s in $SEEDS; do axum inc_nowait "$ROOT/sandbox/corpus/axum_hard" "$s" --runs 50000 --wall 600; done
fi

if has loom; then
    say "## loom 0.7 (exhaustive model checker; program ported to loom::sync / loom::thread)"
    for t in lost_update deadlock sleep_race; do
        (cd "$HERE" && timeout 300 ./target/release/loom_bench "$t" 2> /dev/null) | tee -a "$OUT"
    done
fi

if has shuttle; then
    say "## shuttle 0.8 (random / PCT depth 2 / DFS schedulers; program ported to shuttle::sync)"
    for t in lost_update deadlock sleep_race; do
        for m in random pct dfs; do
            (cd "$HERE" && timeout 300 ./target/release/shuttle_bench "$t" "$m" 100000 2> /dev/null) | tee -a "$OUT"
        done
    done
fi

if has snapshot; then
    say "## snapshot/restore: resume the two-thread race after a 64 MB setup"
    s=$(date +%s.%N); for _ in $(seq 10); do "$TGT/slow_setup" > /dev/null 2>&1; done; e=$(date +%s.%N)
    say "tool=fresh-exec target=slow_setup(instrumented) runs=10 per_run_ms=$(echo "scale=1; $(ms "$s" "$e")/10" | bc)"
    (cd "$HERE" && ./target/release/snapshot_baselines fresh 10 && ./target/release/snapshot_baselines fork 50) | tee -a "$OUT"
    if [ -n "${CRIU:-}" ] && sudo -n true 2> /dev/null; then
        (cd "$HERE" && CRIU="$CRIU" ./criu_cost.sh 5 2>&1 | grep '^tool=') | tee -a "$OUT"
    else
        say "tool=criu skipped (set CRIU=/path/to/criu>=3.17 and allow sudo)"
    fi
    out=$(cd "$ROOT" && timeout 600 ./target/release/examples/explore "$TGT/slow_setup" --runs 3000 --seed 1 --replays 20 2>&1 | grep -vE '^\[sandbox\]')
    say "tool=sandbox target=slow_setup | $(echo "$out" | grep -oE '^root: .*' | head -1) | $(echo "$out" | grep -E '^runs [0-9]+ in' | head -1) | $(echo "$out" | grep -oE '^replay x20: .*') | $(echo "$out" | grep -oE '^snapshots: .*' | head -1) | $(echo "$out" | grep -oE '^restores: .*' | head -1)"
fi

if has tsan; then
    say "## ThreadSanitizer (nightly -Zsanitizer=thread) on lost_update: the bug is not a data race"
    if [ -x "$HERE/tsan/target/x86_64-unknown-linux-gnu/release/lost_update_tsan" ]; then
        stress "tool=tsan target=lost_update" 200 5 "$HERE/tsan/target/x86_64-unknown-linux-gnu/release/lost_update_tsan"
    else
        say "tool=tsan skipped (build compare/tsan first, see its README line in Cargo.toml)"
    fi
fi
say "# done"
