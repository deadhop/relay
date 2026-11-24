//! The in-memory store: gift wraps for a while, announcements until replaced,
//! and ephemeral messages nobody was subscribed to, for a few seconds.
//!
//! Events written by unauthenticated clients have their own budget, so a
//! flood of them can never push out what a whitelisted key wrote. In public
//! mode, traffic between keys that are not whitelisted has a third budget,
//! announcements included, so it can never push out either of the others.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use crate::event::{Event, Key};
use crate::filter::Filter;

/// Who wrote an event, which decides who may read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Writer {
    /// A whitelisted key, or a connection authenticated as one.
    Trusted,
    /// Anyone, addressed to a whitelisted key: only that key may read it.
    Public,
    /// deadhop's relay health check.
    Probe,
    /// Public mode: a key that is not whitelisted, to another such key (or
    /// its own announcement). Anyone may read it, as on any open relay.
    Open,
}

impl Writer {
    /// Whether a connection authenticated as `authed` may receive an event
    /// addressed to `recipients`.
    pub fn may_read(self, recipients: &[Key], authed: &[Key]) -> bool {
        self != Writer::Public || recipients.iter().any(|p| authed.contains(p))
    }
}

#[derive(Debug, Clone)]
pub struct Stored {
    pub event: Arc<Event>,
    pub writer: Writer,
    pub expires: u64,
}

/// Remembers recent event ids, to answer duplicates without re-sending them.
pub struct Seen {
    set: HashSet<Key>,
    order: VecDeque<Key>,
    cap: usize,
}

impl Seen {
    pub fn new(cap: usize) -> Seen {
        Seen {
            set: HashSet::with_capacity(cap.min(4096)),
            order: VecDeque::new(),
            cap,
        }
    }

    pub fn contains(&self, id: &Key) -> bool {
        self.set.contains(id)
    }

    pub fn insert(&mut self, id: Key) {
        if self.set.insert(id) {
            self.order.push_back(id);
            if self.order.len() > self.cap {
                let old = self.order.pop_front().expect("longer than cap");
                self.set.remove(&old);
            }
        }
    }
}

pub struct Store {
    trusted: VecDeque<Stored>,
    public: VecDeque<Stored>,
    open: VecDeque<Stored>,
    replaceable: HashMap<(Key, u16), Stored>,
    trusted_cap: usize,
    public_cap: usize,
    open_cap: usize,
}

impl Store {
    pub fn new(trusted_cap: usize, public_cap: usize, open_cap: usize) -> Store {
        Store {
            trusted: VecDeque::new(),
            public: VecDeque::new(),
            open: VecDeque::new(),
            replaceable: HashMap::new(),
            trusted_cap,
            public_cap,
            open_cap,
        }
    }

    /// Keep `event` until `expires` (Unix seconds). Replaceable events replace
    /// an older one by the same author and are kept until replaced; those by
    /// keys that are not whitelisted live in the capped open budget, so minted
    /// keys cannot grow the store without bound.
    pub fn insert(&mut self, event: Arc<Event>, writer: Writer, expires: u64) {
        if writer == Writer::Open && event.is_replaceable() {
            let same = |s: &Stored| s.event.pubkey == event.pubkey && s.event.kind == event.kind;
            if self
                .open
                .iter()
                .any(|s| same(s) && s.event.created_at > event.created_at)
            {
                return;
            }
            self.open.retain(|s| !same(s));
            return self.push(event, writer, u64::MAX);
        }
        if event.is_replaceable() {
            let k = (event.pubkey, event.kind);
            if self
                .replaceable
                .get(&k)
                .is_none_or(|old| old.event.created_at <= event.created_at)
            {
                self.replaceable.insert(
                    k,
                    Stored {
                        event,
                        writer,
                        expires: u64::MAX,
                    },
                );
            }
            return;
        }
        self.push(event, writer, expires);
    }

    fn push(&mut self, event: Arc<Event>, writer: Writer, expires: u64) {
        let (ring, cap) = match writer {
            Writer::Public => (&mut self.public, self.public_cap),
            Writer::Open => (&mut self.open, self.open_cap),
            _ => (&mut self.trusted, self.trusted_cap),
        };
        ring.push_back(Stored { event, writer, expires });
        while ring.len() > cap {
            ring.pop_front();
        }
    }

    /// Forget a kept event: an ephemeral one that a live subscriber received,
    /// so a client that reconnects is not sent another session's replies.
    pub fn remove(&mut self, id: &Key, writer: Writer) {
        let ring = match writer {
            Writer::Public => &mut self.public,
            Writer::Open => &mut self.open,
            _ => &mut self.trusted,
        };
        // Just added, so it is near the end.
        if let Some(i) = ring.iter().rposition(|s| s.event.id == *id) {
            ring.remove(i);
        }
    }

    /// Drop what has expired.
    pub fn purge(&mut self, now: u64) {
        self.trusted.retain(|s| s.expires > now);
        self.public.retain(|s| s.expires > now);
        self.open.retain(|s| s.expires > now);
    }

    pub fn len(&self) -> usize {
        self.trusted.len() + self.public.len() + self.open.len() + self.replaceable.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Events matching any of `filters` that a connection authenticated as
    /// `authed` may read, newest first, at most `limit`.
    pub fn query(&self, filters: &[Filter], authed: &[Key], now: u64, limit: usize) -> Vec<Arc<Event>> {
        let mut out: Vec<Arc<Event>> = self
            .trusted
            .iter()
            .chain(self.public.iter())
            .chain(self.open.iter())
            .chain(self.replaceable.values())
            .filter(|s| s.expires > now && filters.iter().any(|f| f.matches(&s.event)))
            .filter(|s| s.writer.may_read(&s.event.recipients(), authed))
            .map(|s| s.event.clone())
            .collect();
        out.sort_by_key(|e| std::cmp::Reverse(e.created_at));
        out.truncate(limit);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::tests::signed;
    use crate::event::{EPHEMERAL_GIFT_WRAP, GIFT_WRAP};
    use nostr_sdk::prelude::{Keys, Tag};
    use serde_json::json;

    fn wrap(to: &Keys, kind: u16) -> Arc<Event> {
        Arc::new(signed(
            &Keys::generate(),
            kind,
            "x",
            vec![Tag::public_key(to.public_key())],
        ))
    }

    fn to(k: &Keys) -> Vec<Filter> {
        vec![Filter::parse(&json!({"#p": [k.public_key().to_hex()]})).unwrap()]
    }

    #[test]
    fn seen_forgets_the_oldest() {
        let mut s = Seen::new(2);
        s.insert([1; 32]);
        s.insert([1; 32]);
        s.insert([2; 32]);
        s.insert([3; 32]);
        assert!(!s.contains(&[1; 32]) && s.contains(&[2; 32]) && s.contains(&[3; 32]));
    }

    #[test]
    fn public_writes_are_read_only_by_their_recipient() {
        let service = Keys::generate();
        let mut st = Store::new(10, 10, 10);
        let e = wrap(&service, GIFT_WRAP);
        st.insert(e.clone(), Writer::Public, 100);
        assert!(st.query(&to(&service), &[], 0, 10).is_empty(), "not authenticated");
        assert!(st.query(&to(&service), &[[7; 32]], 0, 10).is_empty(), "someone else");
        assert_eq!(
            st.query(&to(&service), &[service.public_key().to_bytes()], 0, 10),
            vec![e.clone()]
        );
        assert!(
            st.query(&to(&service), &[service.public_key().to_bytes()], 100, 10)
                .is_empty(),
            "expired"
        );
        st.purge(100);
        assert!(st.is_empty());
    }

    #[test]
    fn floods_of_public_writes_cannot_evict_trusted_ones() {
        let service = Keys::generate();
        let client = Keys::generate();
        let mut st = Store::new(2, 2, 2);
        let reply = wrap(&client, EPHEMERAL_GIFT_WRAP);
        st.insert(reply.clone(), Writer::Trusted, 100);
        for _ in 0..10 {
            st.insert(wrap(&service, GIFT_WRAP), Writer::Public, 100);
        }
        assert_eq!(st.len(), 3);
        assert_eq!(st.query(&to(&client), &[], 0, 10), vec![reply]);
        st.insert(wrap(&client, GIFT_WRAP), Writer::Probe, 100);
        st.insert(wrap(&client, GIFT_WRAP), Writer::Trusted, 100);
        assert_eq!(st.query(&to(&client), &[], 0, 10).len(), 2, "capped at 2");
        assert_eq!(st.query(&to(&client), &[], 0, 1).len(), 1, "limit");
    }

    #[test]
    fn open_writes_are_read_by_anyone_and_evict_only_each_other() {
        let service = Keys::generate();
        let client = Keys::generate();
        let mut st = Store::new(1, 1, 2);
        let reply = wrap(&client, GIFT_WRAP);
        st.insert(reply.clone(), Writer::Trusted, 100);
        let request = wrap(&service, GIFT_WRAP);
        st.insert(request.clone(), Writer::Public, 100);
        let open = wrap(&client, GIFT_WRAP);
        st.insert(open.clone(), Writer::Open, 100);
        assert!(st.query(&to(&client), &[], 0, 10).contains(&open), "no AUTH needed");
        for _ in 0..10 {
            st.insert(wrap(&Keys::generate(), GIFT_WRAP), Writer::Open, 100);
        }
        assert_eq!(st.len(), 4, "1 trusted + 1 public + 2 open");
        assert_eq!(st.query(&to(&client), &[], 0, 10), vec![reply]);
        assert_eq!(
            st.query(&to(&service), &[service.public_key().to_bytes()], 0, 10),
            vec![request]
        );
        st.purge(100);
        assert!(st.is_empty());
    }

    #[test]
    fn open_announcements_keep_the_newest_within_their_budget() {
        let server = Keys::generate();
        let mk = |k: &Keys, ts: u64| {
            let e = nostr_sdk::prelude::EventBuilder::new(nostr_sdk::prelude::Kind::Custom(11316), "{}")
                .custom_created_at(nostr_sdk::prelude::Timestamp::from(ts))
                .sign_with_keys(k)
                .unwrap();
            Arc::new(crate::event::tests::from_sdk(&e))
        };
        let mut st = Store::new(10, 10, 3);
        st.insert(mk(&server, 10), Writer::Open, 0);
        st.insert(mk(&server, 20), Writer::Open, 0);
        st.insert(mk(&server, 15), Writer::Open, 0);
        let by = vec![Filter::parse(&json!({"authors": [server.public_key().to_hex()]})).unwrap()];
        let got = st.query(&by, &[], 1_000_000, 10);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].created_at, 20);
        st.purge(u64::MAX - 1);
        assert_eq!(st.len(), 1, "kept until replaced or pushed out");
        // A flood of minted keys stays within the open budget.
        for _ in 0..20 {
            st.insert(mk(&Keys::generate(), 30), Writer::Open, 0);
        }
        assert_eq!(st.len(), 3);
        assert!(st.query(&by, &[], 1_000_000, 10).is_empty(), "pushed out");
    }

    #[test]
    fn replaceable_events_keep_the_newest() {
        let service = Keys::generate();
        let mut st = Store::new(0, 0, 0);
        let mk = |ts: u64| {
            let e = nostr_sdk::prelude::EventBuilder::new(nostr_sdk::prelude::Kind::Custom(11316), "{}")
                .custom_created_at(nostr_sdk::prelude::Timestamp::from(ts))
                .sign_with_keys(&service)
                .unwrap();
            Arc::new(crate::event::tests::from_sdk(&e))
        };
        st.insert(mk(10), Writer::Trusted, 0);
        st.insert(mk(20), Writer::Trusted, 0);
        st.insert(mk(15), Writer::Trusted, 0);
        let by = vec![Filter::parse(&json!({"authors": [service.public_key().to_hex()]})).unwrap()];
        let got = st.query(&by, &[], 1_000_000, 10);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].created_at, 20);
        st.purge(u64::MAX - 1);
        assert_eq!(st.len(), 1, "kept until replaced");
    }
}
