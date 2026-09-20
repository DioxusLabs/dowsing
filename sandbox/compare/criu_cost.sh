#!/usr/bin/env bash
# CRIU checkpoint/restore cost of the 64 MB `pause` process (needs sudo; CRIU >= 3.17 for kernel 6.x, set CRIU=/path/to/criu).
set -uo pipefail
BIN="$(dirname "$0")/target/release/snapshot_baselines"
IMG="${IMG:-/tmp/criu-img}"
N="${1:-5}"
ms() { echo "($2-$1)*1000" | bc; }

rm -rf "$IMG" && mkdir -p "$IMG"
GLIBC_TUNABLES=glibc.pthread.rseq=0 setsid "$BIN" pause > "$IMG/pause.out" 2>&1 < /dev/null &
sleep 0.5
PID=$(sed -n 's/^pid=\([0-9]*\).*/\1/p' "$IMG/pause.out")
RSS=$(awk '/VmRSS/{print $2}' "/proc/$PID/status")
s=$(date +%s.%N)
sudo -n "${CRIU:-criu}" dump -t "$PID" -D "$IMG" -o dump.log || { echo "criu dump failed"; tail -5 "$IMG/dump.log"; exit 1; }
e=$(date +%s.%N)
IMG_KB=$(sudo -n du -sk "$IMG" | cut -f1)
echo "tool=criu op=dump rss_kb=$RSS image_kb=$IMG_KB time_ms=$(ms "$s" "$e")"

total=0
for _ in $(seq "$N"); do
    s=$(date +%s.%N)
    sudo -n "${CRIU:-criu}" restore -d -D "$IMG" -o restore.log || { echo "criu restore failed"; tail -5 "$IMG/restore.log"; exit 1; }
    e=$(date +%s.%N)
    t=$(ms "$s" "$e")
    total=$(echo "$total+$t" | bc)
    sudo -n kill -9 "$PID"
    sleep 0.1
done
echo "tool=criu op=restore runs=$N per_run_ms=$(echo "scale=1; $total/$N" | bc)"
