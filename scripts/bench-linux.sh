#!/usr/bin/env bash
# Compare the CPU cost of two vigil builds on Linux under a server-like load:
# many idle processes plus one process with thousands of threads (a JVM, a
# database). Used by .github/workflows/bench.yml; runs on any Linux box too.
#
#   scripts/bench-linux.sh BASE_BINARY NEW_BINARY [THREADS] [SECONDS]
set -uo pipefail
base=$1; new=$2; threads=${3:-4000}; secs=${4:-30}
hz=$(getconf CLK_TCK)

load=()
for _ in $(seq 150); do sleep 3600 & load+=($!); done
python3 -c "
import threading, time
for _ in range($threads):
    threading.Thread(target=time.sleep, args=(3600,), daemon=True).start()
time.sleep(3600)" &
load+=($!)
trap 'kill "${load[@]}" 2>/dev/null; pkill -f "vigil --no-save" 2>/dev/null; true' EXIT
sleep 3
echo "load: $(ls -d /proc/[0-9]* | wc -l) processes, $(ls -d /proc/[0-9]*/task/[0-9]* | wc -l) threads, $(nproc) cores, kernel $(uname -r)"
echo

measure() { # BINARY LABEL INTERVAL_MS
  local bin=$1 label=$2 interval=$3
  # A pseudo-terminal of a known size; the pipe keeps its input open.
  script -qfec "stty rows 50 cols 160; exec $bin --no-save -i $interval -t procs" /dev/null < <(sleep $((secs + 60))) >/dev/null 2>&1 &
  sleep 4
  local pid
  pid=$(pgrep -f "^$bin --no-save" | head -1)
  if [ -z "$pid" ]; then
    echo "$label: vigil did not start"
    return
  fi
  ticks() { awk '{print $14 + $15}' "/proc/$pid/stat"; }
  local t0 t1 calls="-"
  t0=$(ticks)
  if command -v strace >/dev/null; then
    # System calls in ten seconds, all threads.
    sudo timeout 10 strace -f -c -q -p "$pid" -o "/tmp/strace.$label.$interval" >/dev/null 2>&1
    calls=$(awk '$NF == "total" {print $4}' "/tmp/strace.$label.$interval" 2>/dev/null)
    sleep $((secs - 10))
  else
    sleep "$secs"
  fi
  t1=$(ticks)
  local fds rss
  fds=$(ls "/proc/$pid/fd" 2>/dev/null | wc -l)
  rss=$(awk '/VmRSS/ {print $2}' "/proc/$pid/status")
  kill "$pid" 2>/dev/null
  sleep 1
  awk -v a="$t0" -v b="$t1" -v hz="$hz" -v s="$secs" -v l="$label" -v i="$interval" -v f="$fds" -v r="$rss" -v c="${calls:--}" \
    'BEGIN { printf "%-5s every %4d ms: %6.2f %% of a core · %s syscalls in 10 s · %d open files · %.1f MB\n", l, i, (b - a) / hz / s * 100, c, f, r / 1024 }'
}

for interval in 250 1000; do
  measure "$base" base "$interval"
  measure "$new" new "$interval"
done
