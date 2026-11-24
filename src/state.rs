//! The relay's shared state and its write policy.
//!
//! An event is judged in order of cost: kind, timestamps and the whitelist
//! first, then the per-address budget and proof of work, and only then the
//! signature. Junk is refused before it costs a Schnorr verification.
//!
//! In public mode, keys that are not whitelisted may also talk to each other
//! and announce themselves, under the same per-address limits as requests.
//! Whitelisted keys keep everything they had: their own store budget, their
//! large queue, and requests to them readable only by them.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use crate::config::Config;
use crate::event::{leading_zero_bits, Event, Key, ANNOUNCE_KINDS, AUTH, CTXVM, MESSAGE_KINDS};
use crate::filter::Filter;
use crate::hub::{Conn, Hub};
use crate::limits::{unix_now, Bucket, Origin, Origins};
use crate::stats::{Reason, Stats};
use crate::store::{Seen, Store, Writer};

/// The content of deadhop's relay health check (`server/src/relayhealth.rs`).
pub const PROBE_CONTENT: &str = "deadhop relay check";
/// How far into the future an event's time may be.
pub const MAX_FUTURE_SECS: u64 = 900;
/// How far an AUTH event's time may be from ours.
pub const AUTH_WINDOW_SECS: u64 = 600;
/// Event ids remembered to spot duplicates.
pub const SEEN_IDS: usize = 200_000;

pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The host in a relay URL, lowercased, without scheme, port or path.
pub fn host_of(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or_default(),
        None => authority.split(':').next().unwrap_or_default(),
    };
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// Whether `e` is deadhop's relay health check: a plain ContextVM event with
/// the check's text, addressed to one (random) key.
pub fn is_probe(e: &Event) -> bool {
    e.kind == CTXVM && e.content == PROBE_CONTENT && e.tags.len() == 1 && e.recipients().len() == 1
}

pub enum Verdict {
    Accept(Writer),
    Refuse(Reason, String),
}

pub struct Shared {
    pub cfg: Config,
    pub stats: Stats,
    pub hub: Hub,
    pub store: Mutex<Store>,
    seen: Mutex<Seen>,
    pub origins: Mutex<Origins>,
    probes: Mutex<Bucket>,
    next_id: AtomicU64,
    /// Open WebSocket connections, probation included.
    pub open: AtomicUsize,
    /// Connections over a limit that must authenticate as a whitelisted key.
    pub probation: AtomicUsize,
    /// TCP connections that have not finished their HTTP request yet.
    pub handshakes: AtomicUsize,
    pub started: Instant,
    pub started_unix: u64,
}

impl Shared {
    pub fn new(cfg: Config) -> Arc<Shared> {
        let now = Instant::now();
        Arc::new(Shared {
            stats: Stats::new(&cfg.whitelist),
            hub: Hub::default(),
            store: Mutex::new(Store::new(
                cfg.limits.store_max_events,
                cfg.limits.public_store_max_events,
                cfg.limits.open_store_max_events,
            )),
            seen: Mutex::new(Seen::new(SEEN_IDS)),
            origins: Mutex::new(Origins::new(cfg.limits.public_events_per_min)),
            probes: Mutex::new(Bucket::per_minute(cfg.limits.probes_per_min, now)),
            next_id: AtomicU64::new(1),
            open: AtomicUsize::new(0),
            probation: AtomicUsize::new(0),
            handshakes: AtomicUsize::new(0),
            started: now,
            started_unix: unix_now(),
            cfg,
        })
    }

    pub fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Relaxed)
    }

    /// Decide on an event before its signature is checked.
    /// `authed` are the whitelisted keys the connection proved; `other` says
    /// whether it proved a key that is not whitelisted.
    pub fn judge(
        &self,
        e: &Event,
        authed: &[Key],
        other: bool,
        origin: Origin,
        now_unix: u64,
        now: Instant,
    ) -> Verdict {
        let wl = &self.cfg.whitelist;
        let lim = &self.cfg.limits;
        let refuse = |r: Reason, m: &str| Verdict::Refuse(r, m.to_string());
        if e.created_at > now_unix + MAX_FUTURE_SECS {
            return refuse(Reason::Invalid, "invalid: created_at is more than 15 minutes ahead");
        }
        let by_whitelisted = wl.contains(&e.pubkey);
        if ANNOUNCE_KINDS.contains(&e.kind) {
            return if by_whitelisted {
                Verdict::Accept(Writer::Trusted)
            } else if self.cfg.public {
                self.open(e, origin, now)
            } else {
                refuse(
                    Reason::Restricted,
                    "restricted: only a whitelisted key may publish this kind here",
                )
            };
        }
        if !MESSAGE_KINDS.contains(&e.kind) {
            return refuse(
                Reason::Blocked,
                "blocked: this relay carries deadhop ContextVM messages only",
            );
        }
        if by_whitelisted || !authed.is_empty() {
            return Verdict::Accept(Writer::Trusted);
        }
        if now_unix.saturating_sub(e.created_at) > lim.max_event_age_secs {
            return refuse(Reason::Invalid, "invalid: created_at is too old");
        }
        let to: Vec<Key> = e.recipients().into_iter().filter(|p| wl.contains(p)).collect();
        if !to.is_empty() {
            if e.raw.len() > lim.public_max_event_bytes {
                let m = format!(
                    "invalid: events from keys that are not whitelisted are limited to {} bytes",
                    lim.public_max_event_bytes
                );
                return Verdict::Refuse(Reason::Invalid, m);
            }
            if self.hub.busy(&to) {
                return refuse(
                    Reason::RateLimited,
                    "rate-limited: the service is busy; try again shortly",
                );
            }
            return self.budget(e, origin, now, Writer::Public);
        }
        if self.cfg.allow_probe && is_probe(e) {
            // The sender's own budget first, so one address cannot spend
            // everyone's health checks.
            if !lock(&self.origins).take_event(origin, now) {
                return refuse(
                    Reason::RateLimited,
                    "rate-limited: too many events from your address; slow down",
                );
            }
            return if lock(&self.probes).take(now) {
                Verdict::Accept(Writer::Probe)
            } else {
                refuse(
                    Reason::RateLimited,
                    "rate-limited: too many relay checks; try again in a minute",
                )
            };
        }
        if self.cfg.public {
            return self.open(e, origin, now);
        }
        if other {
            return refuse(
                Reason::Restricted,
                "restricted: the key you authenticated as is not whitelisted here",
            );
        }
        refuse(
            Reason::AuthRequired,
            "auth-required: only a whitelisted key may write to keys that are not whitelisted; authenticate first",
        )
    }

    /// Public mode: an event by a key that is not whitelisted, to keys that
    /// are not whitelisted either (or its own announcement).
    fn open(&self, e: &Event, origin: Origin, now: Instant) -> Verdict {
        let max = self.cfg.limits.open_max_event_bytes;
        if e.raw.len() > max {
            let m = format!("invalid: events between keys that are not whitelisted are limited to {max} bytes");
            return Verdict::Refuse(Reason::Invalid, m);
        }
        self.budget(e, origin, now, Writer::Open)
    }

    /// The sender address's event budget, then proof of work.
    fn budget(&self, e: &Event, origin: Origin, now: Instant, writer: Writer) -> Verdict {
        if !lock(&self.origins).take_event(origin, now) {
            return Verdict::Refuse(
                Reason::RateLimited,
                "rate-limited: too many events from your address; slow down".into(),
            );
        }
        let pow = self.cfg.limits.min_pow;
        if leading_zero_bits(&e.id) < u32::from(pow) {
            return Verdict::Refuse(Reason::Pow, format!("pow: this relay needs {pow} bits of work"));
        }
        Verdict::Accept(writer)
    }

    fn refuse(&self, r: Reason, m: String) -> (bool, String) {
        self.stats.refuse(r, unix_now() / 60);
        (false, m)
    }

    /// Take an `EVENT` from `conn`. The answer is the `OK` status and message.
    pub fn publish(&self, e: Event, conn: &Conn, origin: Origin) -> (bool, String) {
        let now_unix = unix_now();
        let writer = match self.judge(&e, &conn.authed(), conn.is_other(), origin, now_unix, Instant::now()) {
            Verdict::Accept(w) => w,
            Verdict::Refuse(r, m) => return self.refuse(r, m),
        };
        if lock(&self.seen).contains(&e.id) {
            self.stats.refuse(Reason::Duplicate, now_unix / 60);
            return (true, "duplicate: already have this event".into());
        }
        if let Err(m) = e.verify() {
            return self.refuse(Reason::Invalid, m.into());
        }
        lock(&self.seen).insert(e.id);
        // The content is only needed to check the id; subscribers get `raw`.
        let e = Arc::new(Event {
            content: String::new(),
            ..e
        });
        let lim = &self.cfg.limits;
        // Stored before the fan-out: a subscription that starts in between
        // finds it in the store, so nothing slips between the two.
        let ttl = if e.is_ephemeral() {
            lim.hold_secs
        } else {
            lim.store_ttl_secs
        };
        let kept = writer != Writer::Probe && (ttl > 0 || e.is_replaceable());
        if kept {
            lock(&self.store).insert(e.clone(), writer, now_unix + ttl);
        }
        let f = self.hub.fanout(&e, writer);
        // Ephemeral messages are held only for a subscriber that was not
        // there yet: once delivered, a later subscription (a client that
        // reconnected, say) must not get them again as if they were new.
        if kept && e.is_ephemeral() && f.delivered > 0 {
            lock(&self.store).remove(&e.id, writer);
        }
        let counter = match writer {
            Writer::Trusted => &self.stats.events_trusted,
            Writer::Public => &self.stats.events_public,
            Writer::Probe => &self.stats.events_probe,
            Writer::Open => &self.stats.events_open,
        };
        counter.fetch_add(1, Relaxed);
        self.stats.dropped.fetch_add(f.failed, Relaxed);
        if f.delivered == 0 {
            self.stats.held.fetch_add(1, Relaxed);
        }
        self.stats.accepted(now_unix / 60, f.delivered);
        // A reply signed by a one-time key counts for the key its connection proved.
        let by = if self.cfg.whitelist.contains(&e.pubkey) {
            Some(e.pubkey)
        } else {
            conn.authed().first().copied()
        };
        if let Some(c) = by.and_then(|k| self.stats.key(&k)) {
            c.outbound.fetch_add(1, Relaxed);
        }
        for p in e.recipients() {
            if let Some(c) = self.stats.key(&p) {
                c.inbound.fetch_add(1, Relaxed);
            }
        }
        (true, String::new())
    }

    /// Stored events for a new subscription.
    /// A connection authenticated as a whitelisted key gets everything kept
    /// for it (requests held while it was away), not just the newest few.
    pub fn query(&self, filters: &[Filter], authed: &[Key]) -> Vec<Arc<Event>> {
        let max = if authed.is_empty() {
            self.cfg.limits.max_limit
        } else {
            usize::MAX
        };
        let limit = filters
            .iter()
            .map(|f| f.limit.unwrap_or(max).min(max))
            .max()
            .unwrap_or(max);
        lock(&self.store).query(filters, authed, unix_now(), limit)
    }

    /// Check a NIP-42 AUTH event. `hosts` are the names this connection may
    /// call the relay by. Gives the key it proves; only a whitelisted one
    /// earns anything (any key may authenticate, as NIP-42 expects).
    pub fn check_auth(&self, e: &Event, challenge: &str, hosts: &[String], now_unix: u64) -> Result<Key, String> {
        if e.kind != AUTH {
            return Err("invalid: AUTH needs a kind 22242 event".into());
        }
        if e.created_at.abs_diff(now_unix) > AUTH_WINDOW_SECS {
            return Err("invalid: AUTH event is more than 10 minutes from now".into());
        }
        if e.first_tag("challenge") != Some(challenge) {
            return Err("invalid: AUTH challenge does not match".into());
        }
        if !e.first_tag("relay").is_some_and(|r| hosts.contains(&host_of(r))) {
            return Err("invalid: AUTH relay tag names another relay".into());
        }
        e.verify().map(|()| e.pubkey).map_err(str::to_string)
    }

    /// The names a client reaching us through `host_header` may use in AUTH.
    /// The configured public URLs when there are any: the Host header is the
    /// client's to choose, so another relay could forward our challenge and
    /// replay the answer under any name. Without them, the Host dialled.
    pub fn hosts(&self, host_header: Option<&str>) -> Vec<String> {
        if self.cfg.public_urls.is_empty() {
            host_header.map(host_of).into_iter().collect()
        } else {
            self.cfg.public_urls.iter().map(|u| host_of(u)).collect()
        }
    }

    /// Expire stored events and idle address records.
    pub fn purge(&self) {
        lock(&self.store).purge(unix_now());
        lock(&self.origins).purge(Instant::now());
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::config::tests::config;
    use crate::config::ENV_WHITELIST;
    use crate::event::tests::{from_sdk, signed};
    use crate::event::{EPHEMERAL_GIFT_WRAP, GIFT_WRAP};
    use nostr_sdk::prelude::{EventBuilder, Keys, Kind, RelayUrl, Tag, Timestamp};

    pub fn shared(service: &Keys, extra: &[(&str, &str)]) -> Arc<Shared> {
        let wl = format!("invoices={}", service.public_key().to_hex());
        let mut pairs = vec![(ENV_WHITELIST, wl.as_str())];
        pairs.extend_from_slice(extra);
        Shared::new(config(&pairs).unwrap())
    }

    fn at(keys: &Keys, kind: u16, content: &str, tags: Vec<Tag>, ts: u64) -> Event {
        from_sdk(
            &EventBuilder::new(Kind::Custom(kind), content)
                .tags(tags)
                .custom_created_at(Timestamp::from(ts))
                .sign_with_keys(keys)
                .unwrap(),
        )
    }

    fn verdict(s: &Shared, e: &Event, authed: &[Key]) -> Result<Writer, String> {
        match s.judge(e, authed, false, Origin::V4(1), unix_now(), Instant::now()) {
            Verdict::Accept(w) => Ok(w),
            Verdict::Refuse(r, m) => {
                assert!(m.starts_with(r.prefix()), "{m}");
                Err(m)
            }
        }
    }

    #[test]
    fn hosts_are_compared_without_scheme_port_or_path() {
        assert_eq!(host_of("wss://Relay.Example.:443/path?x"), "relay.example");
        assert_eq!(host_of("ws://[::1]:7447"), "::1");
        assert_eq!(host_of("ws://user@10.0.0.2:7447"), "10.0.0.2");
        assert_eq!(host_of("relay.example:80"), "relay.example");
    }

    #[test]
    fn the_write_policy() {
        let service = Keys::generate();
        let client = Keys::generate();
        let s = shared(&service, &[]);
        let to_service = vec![Tag::public_key(service.public_key())];
        let to_client = vec![Tag::public_key(client.public_key())];
        let now = unix_now();

        // Requests to a whitelisted key are public writes; replies need the service.
        assert_eq!(
            verdict(&s, &signed(&client, GIFT_WRAP, "r", to_service.clone()), &[]),
            Ok(Writer::Public)
        );
        assert_eq!(
            verdict(&s, &signed(&service, CTXVM, "r", to_client.clone()), &[]),
            Ok(Writer::Trusted)
        );
        let wrap = signed(&Keys::generate(), EPHEMERAL_GIFT_WRAP, "r", to_client.clone());
        assert!(verdict(&s, &wrap, &[]).unwrap_err().starts_with("auth-required:"));
        let other = s.judge(&wrap, &[], true, Origin::V4(1), now, Instant::now());
        assert!(matches!(other, Verdict::Refuse(Reason::Restricted, _)));
        assert_eq!(
            verdict(&s, &wrap, &[service.public_key().to_bytes()]),
            Ok(Writer::Trusted)
        );

        // Announcements only from whitelisted keys; other kinds never.
        assert_eq!(
            verdict(&s, &signed(&service, 11316, "{}", vec![]), &[]),
            Ok(Writer::Trusted)
        );
        assert!(verdict(&s, &signed(&client, 11316, "{}", vec![]), &[])
            .unwrap_err()
            .starts_with("restricted:"));
        assert!(verdict(&s, &signed(&service, 1, "hi", vec![]), &[])
            .unwrap_err()
            .starts_with("blocked:"));

        // Times.
        let future = at(&client, GIFT_WRAP, "r", to_service.clone(), now + 3600);
        assert!(verdict(&s, &future, &[]).unwrap_err().contains("ahead"));
        let old = at(&client, GIFT_WRAP, "r", to_service.clone(), now - 3600);
        assert!(verdict(&s, &old, &[]).unwrap_err().contains("too old"));
        assert_eq!(
            verdict(&s, &at(&service, GIFT_WRAP, "r", to_client, now - 3600), &[]),
            Ok(Writer::Trusted)
        );

        // The health check, within its budget.
        let probe = signed(
            &Keys::generate(),
            CTXVM,
            PROBE_CONTENT,
            vec![Tag::public_key(Keys::generate().public_key())],
        );
        assert!(is_probe(&probe));
        assert_eq!(verdict(&s, &probe, &[]), Ok(Writer::Probe));
        let off = shared(&service, &[("DEADHOP_RELAY_ALLOW_PROBE", "false")]);
        assert!(verdict(&off, &probe, &[]).unwrap_err().starts_with("auth-required:"));
        let stingy = shared(&service, &[("DEADHOP_RELAY_PUBLIC_EVENTS_PER_MIN", "1")]);
        assert_eq!(verdict(&stingy, &probe, &[]), Ok(Writer::Probe));
        assert!(
            verdict(&stingy, &probe, &[]).unwrap_err().contains("from your address"),
            "charged per address first"
        );
        let one = shared(&service, &[("DEADHOP_RELAY_PROBES_PER_MIN", "1")]);
        assert_eq!(verdict(&one, &probe, &[]), Ok(Writer::Probe));
        assert!(verdict(&one, &probe, &[]).unwrap_err().starts_with("rate-limited:"));
    }

    #[test]
    fn public_mode_opens_the_relay_to_every_key() {
        let service = Keys::generate();
        let server = Keys::generate();
        let client = Keys::generate();
        let to_server = vec![Tag::public_key(server.public_key())];
        let to_client = vec![Tag::public_key(client.public_key())];
        let s = shared(&service, &[("DEADHOP_RELAY_PUBLIC", "on")]);

        // Any key may talk to any other, and announce itself.
        assert_eq!(
            verdict(&s, &signed(&client, GIFT_WRAP, "r", to_server), &[]),
            Ok(Writer::Open)
        );
        let reply = signed(&server, EPHEMERAL_GIFT_WRAP, "r", to_client.clone());
        assert_eq!(verdict(&s, &reply, &[]), Ok(Writer::Open));
        let other = s.judge(&reply, &[], true, Origin::V4(1), unix_now(), Instant::now());
        assert!(
            matches!(other, Verdict::Accept(Writer::Open)),
            "AUTH as any key changes nothing"
        );
        assert_eq!(
            verdict(&s, &signed(&server, 11316, "{}", vec![]), &[]),
            Ok(Writer::Open)
        );
        assert!(verdict(&s, &signed(&server, 1, "hi", vec![]), &[])
            .unwrap_err()
            .starts_with("blocked:"));
        let old = at(&server, GIFT_WRAP, "r", to_client.clone(), unix_now() - 3600);
        assert!(verdict(&s, &old, &[]).unwrap_err().contains("too old"));

        // Whitelisted keys keep what they had.
        let to_service = vec![Tag::public_key(service.public_key())];
        assert_eq!(
            verdict(&s, &signed(&client, GIFT_WRAP, "r", to_service), &[]),
            Ok(Writer::Public)
        );
        assert_eq!(
            verdict(&s, &signed(&service, CTXVM, "r", to_client.clone()), &[]),
            Ok(Writer::Trusted)
        );
        let probe = signed(
            &client,
            CTXVM,
            PROBE_CONTENT,
            vec![Tag::public_key(Keys::generate().public_key())],
        );
        assert_eq!(
            verdict(&s, &probe, &[]),
            Ok(Writer::Probe),
            "health checks are still not kept"
        );

        // Open writes have their own size limit and share the address budget.
        let s = shared(
            &service,
            &[
                ("DEADHOP_RELAY_PUBLIC", "on"),
                ("DEADHOP_RELAY_OPEN_MAX_EVENT_BYTES", "1024"),
                ("DEADHOP_RELAY_PUBLIC_EVENTS_PER_MIN", "1"),
            ],
        );
        let big = signed(&server, GIFT_WRAP, &"x".repeat(2000), to_client.clone());
        assert!(verdict(&s, &big, &[]).unwrap_err().contains("limited to 1024 bytes"));
        let e = signed(&server, GIFT_WRAP, "r", to_client);
        assert_eq!(verdict(&s, &e, &[]), Ok(Writer::Open));
        assert!(verdict(&s, &e, &[]).unwrap_err().starts_with("rate-limited:"));
    }

    #[test]
    fn big_public_writes_and_a_busy_service_are_refused() {
        let service = Keys::generate();
        let client = Keys::generate();
        let to_service = vec![Tag::public_key(service.public_key())];
        let s = shared(&service, &[("DEADHOP_RELAY_PUBLIC_MAX_EVENT_BYTES", "1024")]);
        let big = signed(&client, GIFT_WRAP, &"x".repeat(2000), to_service.clone());
        assert!(verdict(&s, &big, &[]).unwrap_err().contains("limited to 1024 bytes"));
        // The service may still send big events itself.
        let reply = signed(
            &service,
            GIFT_WRAP,
            &"x".repeat(2000),
            vec![Tag::public_key(client.public_key())],
        );
        assert_eq!(verdict(&s, &reply, &[]), Ok(Writer::Trusted));
        // A service whose queue is more than half full makes writers wait.
        let (svc, _rx) = Conn::new(1, 1 << 20, 1000);
        svc.add_authed(service.public_key().to_bytes());
        let to = |k: &Keys| vec![Filter::parse(&serde_json::json!({"#p": [k.public_key().to_hex()]})).unwrap()];
        s.hub
            .subscribe(crate::hub::Sub::new(svc.clone(), "s".into(), to(&service)));
        let req = signed(&client, GIFT_WRAP, "r", to_service);
        assert_eq!(verdict(&s, &req, &[]), Ok(Writer::Public));
        assert!(svc.push("y".repeat(600)));
        assert!(verdict(&s, &req, &[])
            .unwrap_err()
            .starts_with("rate-limited: the service is busy"));
        // Full, it refuses messages but stays connected.
        assert!(!svc.push("y".repeat(600)));
        assert!(!svc.is_dead());
    }

    #[test]
    fn public_writes_have_a_budget_and_optional_work() {
        let service = Keys::generate();
        let client = Keys::generate();
        let to_service = vec![Tag::public_key(service.public_key())];
        let s = shared(&service, &[("DEADHOP_RELAY_PUBLIC_EVENTS_PER_MIN", "2")]);
        let e = signed(&client, GIFT_WRAP, "r", to_service.clone());
        assert!(verdict(&s, &e, &[]).is_ok() && verdict(&s, &e, &[]).is_ok());
        assert!(verdict(&s, &e, &[]).unwrap_err().starts_with("rate-limited:"));
        let pow = shared(&service, &[("DEADHOP_RELAY_MIN_POW", "8")]);
        let mut e = e;
        e.id[0] = 0xff; // judged before the id is checked; no chance of accidental work
        assert_eq!(
            verdict(&pow, &e, &[]).unwrap_err(),
            "pow: this relay needs 8 bits of work"
        );
        let mined = from_sdk(
            &EventBuilder::new(Kind::Custom(GIFT_WRAP), "r")
                .tags(to_service)
                .pow(8)
                .sign_with_keys(&client)
                .unwrap(),
        );
        assert_eq!(verdict(&pow, &mined, &[]), Ok(Writer::Public));
    }

    #[test]
    fn publish_counts_stores_and_refuses_duplicates() {
        let service = Keys::generate();
        let client = Keys::generate();
        let s = shared(&service, &[]);
        let (conn, _rx) = Conn::new(1, 1 << 20, 1 << 30);
        let req = signed(&client, GIFT_WRAP, "r", vec![Tag::public_key(service.public_key())]);
        assert_eq!(s.publish(req.clone(), &conn, Origin::V4(1)), (true, String::new()));
        assert_eq!(
            s.publish(req.clone(), &conn, Origin::V4(1)),
            (true, "duplicate: already have this event".into())
        );
        let mut bad = signed(&client, GIFT_WRAP, "r2", vec![Tag::public_key(service.public_key())]);
        bad.sig[5] ^= 1;
        assert_eq!(
            s.publish(bad, &conn, Origin::V4(1)),
            (false, "invalid: bad signature".into())
        );
        let (ok, m) = s.publish(signed(&client, 1, "x", vec![]), &conn, Origin::V4(1));
        assert!(!ok && m.starts_with("blocked:"));
        let k = service.public_key().to_bytes();
        let reply = signed(
            &service,
            EPHEMERAL_GIFT_WRAP,
            "x",
            vec![Tag::public_key(client.public_key())],
        );
        assert!(s.publish(reply, &conn, Origin::V4(1)).0);
        let probe = signed(
            &Keys::generate(),
            CTXVM,
            PROBE_CONTENT,
            vec![Tag::public_key(Keys::generate().public_key())],
        );
        assert!(s.publish(probe, &conn, Origin::V4(1)).0);
        assert_eq!(s.stats.events_total(), 3);
        assert_eq!(s.stats.key(&k).unwrap().inbound.load(Relaxed), 1);
        assert_eq!(s.stats.key(&k).unwrap().outbound.load(Relaxed), 1);
        // A gift wrap from a connection authenticated as the service counts for the service.
        let (svc, _rx2) = Conn::new(2, 1 << 20, 1 << 30);
        svc.add_authed(k);
        let wrap = signed(
            &Keys::generate(),
            EPHEMERAL_GIFT_WRAP,
            "w",
            vec![Tag::public_key(client.public_key())],
        );
        assert!(s.publish(wrap, &svc, Origin::V4(1)).0);
        assert_eq!(s.stats.key(&k).unwrap().outbound.load(Relaxed), 2);
        assert_eq!(s.stats.refused(Reason::Duplicate), 1);
        // The request is readable only by the service; the reply by anyone with the filter.
        let to = |k: &Keys| vec![Filter::parse(&serde_json::json!({"#p": [k.public_key().to_hex()]})).unwrap()];
        assert!(s.query(&to(&service), &[]).is_empty());
        assert_eq!(s.query(&to(&service), &[k]).len(), 1);
        assert_eq!(s.query(&to(&client), &[]).len(), 2);
        // A connection authenticated as the recipient gets everything held for it.
        let few = shared(&service, &[("DEADHOP_RELAY_MAX_LIMIT", "1")]);
        for i in 0..3 {
            let r = signed(
                &client,
                GIFT_WRAP,
                &format!("held {i}"),
                vec![Tag::public_key(service.public_key())],
            );
            assert!(few.publish(r, &conn, Origin::V4(1)).0);
        }
        assert_eq!(few.query(&to(&service), &[k]).len(), 3);
        let reply = signed(&service, GIFT_WRAP, "a", vec![Tag::public_key(client.public_key())]);
        assert!(few.publish(reply, &conn, Origin::V4(1)).0);
        let reply = signed(&service, GIFT_WRAP, "b", vec![Tag::public_key(client.public_key())]);
        assert!(few.publish(reply, &conn, Origin::V4(1)).0);
        assert_eq!(few.query(&to(&client), &[]).len(), 1, "others get MAX_LIMIT");
        // With the store off, ephemeral messages are not held.
        let off = shared(&service, &[("DEADHOP_RELAY_HOLD_SECS", "0")]);
        let reply = signed(
            &service,
            EPHEMERAL_GIFT_WRAP,
            "y",
            vec![Tag::public_key(client.public_key())],
        );
        assert!(off.publish(reply, &conn, Origin::V4(1)).0);
        assert!(off.query(&to(&client), &[]).is_empty());
        s.purge();
    }

    #[test]
    fn auth_events() {
        let service = Keys::generate();
        let s = shared(&service, &[("DEADHOP_RELAY_PUBLIC_URLS", "wss://relay.example")]);
        // With public URLs set, the Host header (the client's choice) is ignored.
        let hosts = s.hosts(Some("10.0.0.2:7447"));
        assert_eq!(hosts, vec!["relay.example"]);
        assert_eq!(shared(&service, &[]).hosts(Some("10.0.0.2:7447")), vec!["10.0.0.2"]);
        assert!(shared(&service, &[]).hosts(None).is_empty());
        let now = unix_now();
        let auth = |keys: &Keys, relay: &str, challenge: &str| {
            from_sdk(
                &EventBuilder::auth(challenge, RelayUrl::parse(relay).unwrap())
                    .sign_with_keys(keys)
                    .unwrap(),
            )
        };
        let k = service.public_key().to_bytes();
        assert_eq!(
            s.check_auth(&auth(&service, "wss://relay.example", "c1"), "c1", &hosts, now),
            Ok(k)
        );
        let forged = s.check_auth(&auth(&service, "ws://10.0.0.2:7447/", "c1"), "c1", &hosts, now);
        assert!(
            forged.unwrap_err().contains("another relay"),
            "a name not in the public URLs"
        );
        let err = |e: Event| s.check_auth(&e, "c1", &hosts, now).unwrap_err();
        assert!(err(auth(&service, "wss://elsewhere.example", "c1")).contains("another relay"));
        assert!(err(auth(&service, "wss://relay.example", "c2")).contains("challenge"));
        let stranger = Keys::generate();
        let got = s.check_auth(&auth(&stranger, "wss://relay.example", "c1"), "c1", &hosts, now);
        assert_eq!(got, Ok(stranger.public_key().to_bytes()), "any key may authenticate");
        assert!(err(signed(&service, 1, "", vec![])).contains("22242"));
        let stale = at(&service, AUTH, "", vec![], now - 3600);
        assert!(err(stale).contains("10 minutes"));
        let mut forged = auth(&service, "wss://relay.example", "c1");
        forged.sig[0] ^= 1;
        assert_eq!(err(forged), "invalid: bad signature");
        assert_eq!(s.next_id() + 1, s.next_id());
    }
}
