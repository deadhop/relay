<div align="center">

# deadhop relay

A Nostr relay that carries one deadhop service's ContextVM traffic, and nothing else.

[![License](https://img.shields.io/github/license/sandwichfarm/deadhop?style=for-the-badge)](https://github.com/sandwichfarm/deadhop/blob/main/LICENSE)
[![Coverage](https://img.shields.io/badge/coverage-100%25%20lines%20%26%20functions-5fc6b9?style=for-the-badge)](#verify)
[![Docs](https://img.shields.io/badge/docs-%2Fdocs%2Frelay-e8c547?style=for-the-badge)](https://deadhop.run/docs/relay/)

</div>

## What is this?

deadhop talks only over [ContextVM](https://contextvm.org) (MCP over Nostr), so its service and its dashboard need relays. `deadhop-relay` is a relay for your service alone. You list your service's keys (the invoice key, the admin key, or both), and the relay accepts:

- **requests** to those keys, from anyone: ContextVM messages and gift wraps (kinds 25910, 1059 and 21059);
- **answers** from those keys only, either signed by them or sent on a connection that proved the key with NIP-42 AUTH;
- those keys' **announcements**.

It can also be served on Tor, I2P and FIPS, alone or all at once, each through an adapter your daemon forwards to ([networks](https://deadhop.run/docs/relay/networks.html)). It refuses everything else, before checking any signature. Without a whitelist it does not start, unless you set `DEADHOP_RELAY_PUBLIC=on`: it then carries ContextVM traffic for any key, under public limits, and whitelisted keys keep their privileges ([public mode](https://deadhop.run/docs/relay/security.html#public-mode)).

```text
customer / dashboard ──wss──▶ deadhop-relay ◀──wss── deadhop service (AUTH as a whitelisted key)
     requests: from anyone                  answers: from whitelisted keys only
```

Use it on your home network to keep admin traffic off public relays, or on a small VPS as the service's main relay or a fallback.

| Measure | Result |
| --- | --- |
| Dropped | **0** of 300,000 round trips, none refused, including under floods of up to 970,000 messages a second |
| Throughput | 4,823 round trips a second with 1,000 clients on 2 CPUs and 1 GiB, p99 27.5 ms ([benchmark](https://deadhop.run/docs/relay/performance.html)) |
| Size | one static binary of about 2 MB; about 2.7 MiB of memory idle; no disk |
| Privacy | a request reaches only the connection authenticated as its recipient |

## Quick start

```sh
cargo build --release
export DEADHOP_RELAY_WHITELIST="invoices=npub1…,admin=npub1…"   # from deadhop's server.pubkey and admin.pubkey
./target/release/deadhop-relay check                             # print what it understood; start nothing
./target/release/deadhop-relay                                   # relay on :7447, operator page on 127.0.0.1:7448
```

With Docker, from the repository root:

```sh
docker build -t deadhop-relay .                                  # about 2 MB, scratch base
docker run -d -p 7447:7447 -p 127.0.0.1:7448:7448 \
  -e DEADHOP_RELAY_WHITELIST="admin=npub1…" deadhop-relay
```

Put TLS in front (Caddy, nginx or Traefik). Then set `DEADHOP_RELAY_TRUSTED_PROXIES` to the proxy's address and `DEADHOP_RELAY_PUBLIC_URLS` to `wss://…`. Add that URL in deadhop under **Network › Relays**, and to `relays` in the dashboard's `config.json`. The service authenticates on its own when the relay challenges it.

## How it stays up under load

- **Cheap checks first.** Kind, time, whitelist, per-address budget and duplicates are all checked before the Schnorr signature.
- **Indexed fan-out.** An event visits only the subscriptions of its author and recipients. Every subscription must name `#p` or `authors`.
- **Nobody waits on a socket.** Each connection has a writer task and a queue measured in bytes. A reader that falls behind is cut off alone.
- **Reserved room for the service.** A connection over the total or per-address limit goes on probation: it stays only if it authenticates as a whitelisted key within 5 seconds.
- **Held, not lost.** Requests that arrive while the service is reconnecting are held for 30 seconds (up to 1,000 of them) and delivered when it subscribes again.
- **Push back, not drop.** When the service falls behind, new requests to it are refused (`rate-limited:`) instead of accepted and lost.

## Documentation

The docs are published at [deadhop.run/docs/relay](https://deadhop.run/docs/relay/), with the rest of the deadhop docs. Their source is in [deadhop/site](https://github.com/deadhop/site) under `docs/relay/`: send doc fixes there.

| Page | What it covers |
| --- | --- |
| [Overview](https://deadhop.run/docs/relay/) | what the relay carries and where to run it |
| [Quick start](https://deadhop.run/docs/relay/quickstart.html) | keys, run, TLS, pointing deadhop at it |
| [How it works](https://deadhop.run/docs/relay/architecture.html) | write and read rules, fan-out, memory, why nothing accepted is dropped |
| [Flood resistance](https://deadhop.run/docs/relay/hardening.html) | every limit, probation, trusted proxies, what it cannot stop |
| [Performance](https://deadhop.run/docs/relay/performance.html) | the benchmark and its results |
| [Security](https://deadhop.run/docs/relay/security.html) | what the relay sees and trusts; the health-check exception |
| [Configuration](https://deadhop.run/docs/relay/configuration.html) | every `DEADHOP_RELAY_*` variable, default and range |
| [Deployment](https://deadhop.run/docs/relay/deployment.html) | systemd, Docker, Caddy, nginx, Traefik, the home network |
| [Tor, I2P and FIPS](https://deadhop.run/docs/relay/networks.html) | serving the relay on overlay networks, at once, with each network's numbers |
| [Status pages](https://deadhop.run/docs/relay/status-pages.html) | the public page, the operator page, NIP-11, `/stats.json` |
| [Testing](https://deadhop.run/docs/relay/testing.html) | what the tests cover, and the deadhop e2e runs |

## Project structure

```text
.
├── assets/relay.css          status page styles (deadhop brand)
├── assets/brand/             copies of the brand's fonts, mark and favicon (from deadhop/brand)
├── bench/                    load and flood benchmark (its own crate) and results
├── deploy/                   compose file, systemd unit, Caddyfile, example env
├── src/
│   ├── bin/deadhop-relay.rs  the binary: one call into the library
│   ├── config.rs             DEADHOP_RELAY_* settings and the whitelist
│   ├── event.rs              NIP-01 events: parse, id, Schnorr signature
│   ├── filter.rs             subscription filters
│   ├── http.rs               request heads, WebSocket upgrade
│   ├── hub.rs                subscriptions, fan-out, per-connection queues
│   ├── lib.rs                command line and serve loop
│   ├── limits.rs             token buckets, per-address accounting
│   ├── networks/             Tor, I2P and FIPS adapters, per-network counters
│   ├── server.rs             listeners and admission
│   ├── session.rs            one connection: EVENT, REQ, CLOSE, AUTH
│   ├── state.rs              the write policy and shared state
│   ├── stats.rs              counters and the last hour
│   ├── store.rs              in-memory store and duplicate ids
│   ├── tests.rs              end-to-end tests over real sockets
│   └── web.rs                NIP-11, status and operator pages
├── tests/binary.rs           the binary: exit codes, signals
├── Cargo.toml
└── Dockerfile
```

## Verify

```sh
just check          # fmt, clippy -D warnings, tests with 100% line and function coverage, release build
just bench          # about 4 minutes in a 2-CPU, 1 GiB container (never on a desktop); results in bench/results/<date>/
```

## License

MIT, as the rest of deadhop.
