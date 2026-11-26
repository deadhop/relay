---
name: deadhop-relay-setup
description: "Run deadhop-relay, a whitelist-only Nostr relay that carries one deadhop service's ContextVM traffic and nothing else: pick the keys to whitelist, check the configuration, put TLS in front with the right trusted proxy and public URL, add the relay to deadhop and to the dashboard's config.json, and keep the operator page on loopback. Use it whenever someone wants their own relay for deadhop, to keep admin traffic off public relays, a fallback relay on a VPS, asks about DEADHOP_RELAY_WHITELIST, public mode, deadhop-relay check, the relay's status or operator page, or serving the relay on Tor, I2P or FIPS."
license: MIT
metadata:
  repository: https://github.com/deadhop/relay
---

# Run deadhop relay for a deadhop service

`deadhop-relay` (https://github.com/deadhop/relay) is one static binary. Given the service's
public keys, it accepts only requests to those keys, answers from them, and their
announcements; everything else is refused before any signature check. It needs no disk and
keeps nothing across restarts.

Fetch the Markdown docs for details instead of guessing:

| Topic | Page |
| --- | --- |
| Walk-through | https://deadhop.run/docs/relay/quickstart.md |
| Every `DEADHOP_RELAY_*` setting, default and range | https://deadhop.run/docs/relay/configuration.md |
| systemd, Docker, Caddy, nginx, Traefik, home network | https://deadhop.run/docs/relay/deployment.md |
| Tor, I2P and FIPS | https://deadhop.run/docs/relay/networks.md |
| Status page, operator page, NIP-11, `/stats.json` | https://deadhop.run/docs/relay/status-pages.md |
| Public mode, what the relay sees and trusts | https://deadhop.run/docs/relay/security.md |
| Limits and probation | https://deadhop.run/docs/relay/hardening.md |

## Safety rules

- **Whitelist public keys only.** The whitelist takes `npub1…` (or 64 hex) public keys. Never
  ask for or accept an `nsec`; the relay never needs one.
- **Keep the operator page on loopback.** It has no sign-in. It listens on `127.0.0.1:7448`; in
  the Docker image it listens on `0.0.0.0:7448` inside the container, so publish it only as
  `127.0.0.1:7448:7448`. Reach it from elsewhere over SSH (`ssh -L 7448:127.0.0.1:7448 host`).
- **No accidental open relay.** Without a whitelisted key and without `DEADHOP_RELAY_PUBLIC=on`
  the relay exits with status 2. Do not turn on public mode to "make it start"; fix the
  whitelist.
- **Trust only your own proxy.** `DEADHOP_RELAY_TRUSTED_PROXIES` must list only the reverse
  proxy's address. Anything else lets clients fake their address and dodge per-address limits.

## Decide with the user first

1. **Which keys.** deadhop has two: **invoices** (customers reach it) and **admin** (operators
   only). Their npubs are in deadhop's data directory (`server.pubkey`, `admin.pubkey`) and at
   the bottom of the dashboard's **Overview**. For an admin-only relay on the home network,
   the admin key alone is enough.
2. **Where it runs.** On the home network next to deadhop (keeps admin traffic off public
   relays), or on a small VPS as the main relay or a fallback next to public relays.
3. **How it is reached.** Browsers and deadhop on mainnet need `wss://`, so a TLS proxy with a
   domain. On mainnet deadhop accepts plain `ws://` only on loopback and on `.onion`, `.i2p`
   and `.fips` hosts.
4. **Docker or systemd.** `deploy/` has `compose.yaml`, `deadhop-relay.service`, a `Caddyfile`
   and `deadhop-relay.env.example`.

## Steps

### 1. Build and check

```sh
git clone https://github.com/deadhop/relay && cd relay
cargo build --release                       # or: docker build -t deadhop-relay .   (about 2 MB)
export DEADHOP_RELAY_WHITELIST="invoices=npub1…,admin=npub1…"
./target/release/deadhop-relay check        # prints what it understood, starts nothing
```

Each whitelist entry is `label=key` or just `key`; labels show on the operator page. A file
works too: `DEADHOP_RELAY_WHITELIST_FILE`, one entry per line, `#` for comments.

### 2. Run it

Docker:

```sh
docker run -d --name deadhop-relay --restart unless-stopped \
  -p 7447:7447 -p 127.0.0.1:7448:7448 \
  -e DEADHOP_RELAY_WHITELIST="invoices=npub1…,admin=npub1…" \
  deadhop-relay
```

Or Compose: `DEADHOP_RELAY_WHITELIST=… docker compose -f deploy/compose.yaml up -d --build`
(it reads the variables from a `.env` next to it or the shell).

systemd: install the binary to `/usr/local/bin/`, `deploy/deadhop-relay.env.example` to
`/etc/deadhop-relay.env` (mode 0600, then edit), `deploy/deadhop-relay.service` to
`/etc/systemd/system/`, and `systemctl enable --now deadhop-relay`. The unit runs as a throwaway
user with 65,536 open files and 256 MiB of memory.

The relay listens on `0.0.0.0:7447` (`DEADHOP_RELAY_LISTEN`).

### 3. TLS in front

Caddy (`deploy/Caddyfile`):

```text
relay.example.com {
	reverse_proxy 127.0.0.1:7447
}
```

Then tell the relay about it:

```sh
DEADHOP_RELAY_TRUSTED_PROXIES=127.0.0.1             # the proxy's address as the relay sees it
DEADHOP_RELAY_PUBLIC_URLS=wss://relay.example.com    # AUTH must name one of these
```

The relay believes only the last `X-Forwarded-For` entry, so nginx must overwrite it
(`proxy_set_header X-Forwarded-For $remote_addr;`) and pass the WebSocket upgrade. With Traefik
in Docker, the trusted proxy is Traefik's container address. Configs: deployment.md.

### 4. Point deadhop at it

- **Service:** add `wss://relay.example.com` in the dashboard under **Network › Relays** (or to
  `DEADHOP_RELAYS`). The service authenticates (NIP-42) on its own when the relay asks. For an
  admin-only relay, set it as the admin key's relay there, and keep one other relay for the
  admin key until this one has proved itself.
- **Dashboard and checkout:** add the same URL to `relays` in the dashboard's `config.json`, or
  to the relays a checkout passes to `@deadhop/client`. With deadhop/stack's Compose file,
  `config.json` is written at every start: set `DEADHOP_DASHBOARD_RELAYS` (and
  `DEADHOP_DASHBOARD_ADMIN_RELAYS` for the admin key) in its `.env` instead.

## Verify

```sh
deadhop-relay check                                              # configuration only
curl https://relay.example.com/health                            # ok
curl -H 'Accept: application/nostr+json' https://relay.example.com/   # NIP-11 document
curl http://127.0.0.1:7448/stats.json                            # on the relay's host: every counter
```

On the operator page (`http://127.0.0.1:7448/`), each whitelisted key shows a green dot while
the service is connected and authenticated; in `/stats.json` that key has `"sessions": 1`. If it
stays at 0, the service has not added the relay yet, cannot reach it, or AUTH fails because the
URL it dialled is not in `DEADHOP_RELAY_PUBLIC_URLS`. The dashboard's relay health check also
works through this relay (`DEADHOP_RELAY_ALLOW_PROBE`, on by default).

## Public mode

`DEADHOP_RELAY_PUBLIC=on` makes it a public ContextVM relay: it carries ContextVM traffic for
any key under public limits, and whitelisted keys keep their privileges. Only do this when the
user wants to run a relay for others; read security.md#public-mode with them first.

## Tor, I2P and FIPS

The relay can also (or only) listen on Tor, I2P and FIPS, each through its own adapter that
your Tor daemon, I2P router or FIPS node forwards to: `DEADHOP_RELAY_TOR_LISTEN` with
`DEADHOP_RELAY_TOR_URLS`, and the same for `I2P_` and `FIPS_`. `DEADHOP_RELAY_LISTEN=off` turns
clearnet off. The relay does not run those daemons. Fetch
https://deadhop.run/docs/relay/networks.md for the settings and each daemon's setup.

## Sizing

The defaults fit a 512 MiB machine. On 256 MiB, lower `DEADHOP_RELAY_MAX_CONNECTIONS` to 256 and
`DEADHOP_RELAY_STORE_MAX_EVENTS` to 5,000, and raise the open-file limit. A value out of range
stops the relay at start with a message naming the variable.
