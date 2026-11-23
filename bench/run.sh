#!/usr/bin/env bash
# Run the deadhop-relay benchmark set into bench/results/<date>/.
# Build first: (cd bench && cargo build --release) && cargo build --release
#
# The floods open thousands of sockets and send over a million messages a
# second: run them in a resource-limited Linux container or on a server, not
# on a desktop, where they can exhaust the kernel's network buffers:
#   docker run --rm --cpus 2 --memory 1g --ulimit nofile=65536:65536 -v "$PWD/..:/src" -w /src/relay \
#     -e RELAY=... -e BENCH=... rust:1.99 bench/run.sh
set -euo pipefail
cd "$(dirname "$0")/.."
ulimit -n 10240
out="bench/results/${1:-$(date +%F)}"
mkdir -p "$out"
bench="${BENCH:-bench/target/release/deadhop-relay-bench}"
relay="${RELAY:-target/release/deadhop-relay}"
#        name      clients rate/s secs attackers
while read -r name clients rate secs attackers; do
  echo "== $name: $clients clients x $rate/s for ${secs}s, $attackers attackers"
  "$bench" "$relay" "$out/$name.json" "$clients" "$rate" "$secs" "$attackers" > /dev/null
done <<'RUNS'
load-2k   400 5 30 0
load-5k  1000 5 30 0
flood     200 5 30 32
flood-big 400 5 30 64
RUNS
if command -v node >/dev/null; then node bench/summary.mjs "$out"; fi
