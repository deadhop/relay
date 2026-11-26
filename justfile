# deadhop relay: lints, tests with enforced 100% coverage, and the release build
check:
    cargo fmt --check
    cargo clippy --all-targets -- -D warnings
    cargo llvm-cov --all-targets --fail-under-lines 100 --fail-under-functions 100
    cargo build --release --locked

# Load and flood benchmark (about 4 minutes) in a Linux container limited to
# 2 CPUs and 1 GiB, never on the host: the floods can exhaust a desktop's network buffers.
# Results in bench/results/<date>/.
bench:
    docker volume create dhr-bench-target >/dev/null
    docker run --rm -v "$PWD:/src" -v dhr-bench-target:/target -w /src rust:1.99 sh -c 'CARGO_TARGET_DIR=/target/relay cargo build --release --locked && cd bench && CARGO_TARGET_DIR=/target/bench cargo build --release'
    docker run --rm --cpus 2 --memory 1g --ulimit nofile=65536:65536 -v "$PWD:/src" -v dhr-bench-target:/target -w /src -e RELAY=/target/relay/release/deadhop-relay -e BENCH=/target/bench/release/deadhop-relay-bench rust:1.99 bench/run.sh
    node bench/summary.mjs bench/results/$(date +%F)
