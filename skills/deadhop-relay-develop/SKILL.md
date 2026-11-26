---
name: deadhop-relay-develop
description: "Contribute to deadhop relay (deadhop-relay, Rust): run the gate (just check, with 100% line and function coverage and the release build), run the load and flood benchmark only inside the container just bench starts, and keep assets/brand in step with deadhop/brand. Use it whenever you change code, tests or dependencies in the deadhop/relay repository, a relay CI run fails, coverage drops below 100%, someone wants to benchmark the relay, or asks how to build, test or contribute to it."
license: MIT
metadata:
  repository: https://github.com/deadhop/relay
---

# Develop deadhop relay

One Rust crate with one binary, `deadhop-relay`; `src/bin/deadhop-relay.rs` is one call into
the library. Requirements: Rust 1.99 (CI's toolchain), [`just`](https://github.com/casey/just)
and [`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov). For `just bench`: Docker
and Node.js.

## The gate

```sh
just check
```

It runs `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
`cargo llvm-cov --all-targets --fail-under-lines 100 --fail-under-functions 100` and
`cargo build --release --locked`. CI runs the same on every pull request; run it before you
push.

- **Coverage is 100% of lines and functions.** Every new line needs a test that reaches it; do
  not lower the thresholds or exclude code to pass. End-to-end tests over real sockets are in
  `src/tests.rs`; the binary's exit codes and signals in `tests/binary.rs`.
- **`--locked`** on the release build means `Cargo.lock` must match `Cargo.toml`: commit it with
  any dependency change.
- **Settings** are read in `src/config.rs`, all named `DEADHOP_RELAY_*`, each with a default and
  a range. A value out of range must stop the relay with a message naming the variable, and a
  missing whitelist must never open the relay (exit status 2 unless `DEADHOP_RELAY_PUBLIC=on`).
  Keep those properties when you add a setting, and add it to `deploy/compose.yaml` and
  `deploy/deadhop-relay.env.example` if operators are likely to set it.
- **Cheap checks before the signature.** The write policy (`src/state.rs`) refuses by kind,
  time, whitelist, per-address budget and duplicates before any Schnorr check. Keep new checks
  in that order so floods stay cheap to refuse.

## The benchmark: never on a desktop

```sh
just bench
```

It builds the relay and the benchmark (`bench/`, its own crate) in a `rust:1.99` container,
runs `bench/run.sh` in a container limited to 2 CPUs and 1 GiB, takes about 4 minutes, and
writes results to `bench/results/<date>/` (summarised by `node bench/summary.mjs`).

Run it only through `just bench`. Do not run `bench/run.sh` or the benchmark binary on the
host: the floods reach hundreds of thousands of messages a second and can exhaust a desktop's
network buffers, taking the browser and other apps down with them. Ask the user before
starting it, since it occupies the machine for several minutes. Compare a change against the
previous results in `bench/results/`; the published numbers are on
https://deadhop.run/docs/relay/performance.md.

## Brand copies

`assets/brand/` holds copies of the deadhop brand's fonts, mark and favicon for the status
pages (`assets/relay.css` is the relay's own). The originals are in
https://github.com/deadhop/brand: change them there first, then copy the files here unchanged.
Do not edit the copies in place.

## Cross-repository notes

- The relay must keep accepting what deadhop sends: ContextVM messages and gift wraps (kinds
  25910, 1059 and 21059), NIP-42 AUTH from the service, and the dashboard's relay health check.
  The deadhop service lives in https://github.com/deadhop/server. To test against it end to
  end, get the components side by side from a https://github.com/deadhop/stack checkout
  (`just clone`, `just up` for the regtest stack, `just server`), run your build of
  `deadhop-relay` with the service's two keys whitelisted, and make it the service's and the
  dashboard's relay. The regtest stack's own relay is a different, open relay.
- The repository must build from its own clone: no paths that reach outside it.

## Docs and pull requests

- The user docs are in https://github.com/deadhop/site under `docs/relay/`. A change to a
  setting, limit or page needs a matching pull request there; setting names must match
  `src/config.rs` exactly.
- Open issues and pull requests in https://github.com/deadhop/relay.
- Never commit keys (`nsec`) or real whitelists; tests make their own keys.
