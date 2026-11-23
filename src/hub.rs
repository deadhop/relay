//! Live subscriptions and fan-out.
//!
//! Every subscription names keys (`#p` or `authors`), so it is indexed under
//! them and an event only visits the subscriptions of its author and its
//! recipients, however many connections are open.
//!
//! Each connection has an outgoing queue measured in bytes. A connection that
//! lets its queue grow past its budget is cut off rather than slowing anyone
//! else down; connections authenticated as a whitelisted key get a far larger
//! budget, so the service is never the one cut off.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, PoisonError, RwLock};

use tokio::sync::{mpsc, Notify};

use crate::event::{Event, Key};
use crate::filter::Filter;
use crate::store::Writer;

/// What a connection's writer sends next.
#[derive(Debug, PartialEq, Eq)]
pub enum Out {
    Text(String),
    Ping,
    Close(String),
}

pub struct Conn {
    pub id: u64,
    tx: mpsc::UnboundedSender<Out>,
    queued: AtomicUsize,
    budget: usize,
    trusted_budget: usize,
    authed: RwLock<Vec<Key>>,
    dead: AtomicBool,
    gone: AtomicBool,
    other: AtomicBool,
    /// Woken when the connection must close (its queue overflowed).
    pub kill: Notify,
}

impl Conn {
    pub fn new(id: u64, budget: usize, trusted_budget: usize) -> (Arc<Conn>, mpsc::UnboundedReceiver<Out>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let c = Conn {
            id,
            tx,
            queued: AtomicUsize::new(0),
            budget,
            trusted_budget,
            authed: RwLock::new(vec![]),
            dead: AtomicBool::new(false),
            gone: AtomicBool::new(false),
            other: AtomicBool::new(false),
            kill: Notify::new(),
        };
        (Arc::new(c), rx)
    }

    /// The whitelisted keys this connection authenticated as.
    pub fn authed(&self) -> Vec<Key> {
        self.authed.read().unwrap_or_else(PoisonError::into_inner).clone()
    }

    pub fn is_trusted(&self) -> bool {
        !self.authed.read().unwrap_or_else(PoisonError::into_inner).is_empty()
    }

    /// Record a whitelisted key; false if it was already there.
    pub fn add_authed(&self, k: Key) -> bool {
        let mut a = self.authed.write().unwrap_or_else(PoisonError::into_inner);
        if a.contains(&k) {
            false
        } else {
            a.push(k);
            true
        }
    }

    /// Close the connection: its writer is gone.
    pub fn end(&self) {
        self.gone.store(true, Relaxed);
        self.dead.store(true, Relaxed);
        self.kill.notify_one();
    }

    /// Whether the writer is gone (as opposed to the reader being too slow).
    pub fn is_gone(&self) -> bool {
        self.gone.load(Relaxed)
    }

    /// Note that the connection proved a key that is not whitelisted.
    pub fn set_other(&self) {
        self.other.store(true, Relaxed);
    }

    pub fn is_other(&self) -> bool {
        self.other.load(Relaxed)
    }

    pub fn is_dead(&self) -> bool {
        self.dead.load(Relaxed)
    }

    pub fn queued(&self) -> usize {
        self.queued.load(Relaxed)
    }

    /// Queue a message. False when the connection is closing or its queue is
    /// full; a full queue also marks the connection for closing.
    pub fn push(&self, msg: String) -> bool {
        if self.is_dead() {
            return false;
        }
        let trusted = self.is_trusted();
        let budget = if trusted { self.trusted_budget } else { self.budget };
        let n = msg.len();
        if self.queued.fetch_add(n, Relaxed) + n > budget {
            self.queued.fetch_sub(n, Relaxed);
            // The service is never cut off: the message is refused instead
            // (and writers to it are slowed down well before this; see `busy`).
            if !trusted {
                self.dead.store(true, Relaxed);
                self.kill.notify_one();
            }
            return false;
        }
        self.tx.send(Out::Text(msg)).is_ok()
    }

    /// Queue a control message outside the budget.
    pub fn control(&self, out: Out) {
        let _ = self.tx.send(out);
    }

    /// Whether the queue is more than half full, for a trusted connection.
    pub fn is_busy(&self) -> bool {
        self.queued() * 2 > self.trusted_budget
    }

    /// The writer sent `n` bytes of a queued message.
    pub fn sent(&self, n: usize) {
        self.queued.fetch_sub(n, Relaxed);
    }
}

pub struct Sub {
    pub conn: Arc<Conn>,
    pub id: String,
    pub filters: Vec<Filter>,
    /// `["EVENT","<id>",` with the id escaped, ready to prepend.
    prefix: String,
}

impl Sub {
    pub fn new(conn: Arc<Conn>, id: String, filters: Vec<Filter>) -> Sub {
        let prefix = format!("[\"EVENT\",{},", serde_json::Value::String(id.clone()));
        Sub {
            conn,
            id,
            filters,
            prefix,
        }
    }

    /// The `EVENT` message carrying `e` for this subscription.
    pub fn frame(&self, e: &Event) -> String {
        let mut s = String::with_capacity(self.prefix.len() + e.raw.len() + 1);
        s.push_str(&self.prefix);
        s.push_str(&e.raw);
        s.push(']');
        s
    }

    fn keys(&self) -> Vec<Key> {
        let mut k: Vec<Key> = self
            .filters
            .iter()
            .flat_map(|f| f.authors.iter().flatten().copied().chain(f.p_keys()))
            .collect();
        k.sort_unstable();
        k.dedup();
        k
    }
}

type SubKey = (u64, String);

#[derive(Default)]
struct Inner {
    subs: HashMap<SubKey, Arc<Sub>>,
    index: HashMap<Key, Vec<SubKey>>,
}

impl Inner {
    fn remove(&mut self, key: &SubKey) -> bool {
        let Some(old) = self.subs.remove(key) else { return false };
        for k in old.keys() {
            let list = self.index.get_mut(&k).expect("indexed when added");
            list.retain(|x| x != key);
            if list.is_empty() {
                self.index.remove(&k);
            }
        }
        true
    }
}

/// The result of one fan-out.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Fanout {
    pub delivered: u64,
    /// Matching subscriptions whose connection could not take the event.
    pub failed: u64,
}

#[derive(Default)]
pub struct Hub {
    inner: RwLock<Inner>,
}

impl Hub {
    /// Add a subscription, replacing one with the same id on the same connection.
    pub fn subscribe(&self, sub: Sub) {
        let key = (sub.conn.id, sub.id.clone());
        let mut inner = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        inner.remove(&key);
        for k in sub.keys() {
            inner.index.entry(k).or_default().push(key.clone());
        }
        inner.subs.insert(key, Arc::new(sub));
    }

    pub fn unsubscribe(&self, conn: u64, id: &str) -> bool {
        self.inner
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&(conn, id.to_string()))
    }

    pub fn len(&self) -> usize {
        self.inner.read().unwrap_or_else(PoisonError::into_inner).subs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether every connection authenticated as one of `keys` and reading
    /// it is backed up. Writes to such a key are then refused (`rate-limited`)
    /// rather than accepted and dropped.
    pub fn busy(&self, keys: &[Key]) -> bool {
        let inner = self.inner.read().unwrap_or_else(PoisonError::into_inner);
        let readers: Vec<&Arc<Conn>> = keys
            .iter()
            .filter_map(|k| inner.index.get(k))
            .flatten()
            .map(|s| &inner.subs[s].conn)
            .filter(|c| c.authed().iter().any(|a| keys.contains(a)))
            .collect();
        !readers.is_empty() && readers.iter().all(|c| c.is_busy())
    }

    /// Queue `e` to every live subscription that matches it and may read it.
    pub fn fanout(&self, e: &Event, writer: Writer) -> Fanout {
        let recipients = e.recipients();
        let inner = self.inner.read().unwrap_or_else(PoisonError::into_inner);
        let mut cands: Vec<&SubKey> = std::iter::once(&e.pubkey)
            .chain(recipients.iter())
            .filter_map(|k| inner.index.get(k))
            .flatten()
            .collect();
        cands.sort_unstable();
        cands.dedup();
        let mut out = Fanout::default();
        for key in cands {
            let sub = &inner.subs[key];
            if !writer.may_read(&recipients, &sub.conn.authed()) || !sub.filters.iter().any(|f| f.matches(e)) {
                continue;
            }
            if sub.conn.push(sub.frame(e)) {
                out.delivered += 1;
            } else {
                out.failed += 1;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::tests::signed;
    use crate::event::{CTXVM, GIFT_WRAP};
    use nostr_sdk::prelude::{Keys, Tag};
    use serde_json::json;

    fn p(k: &Keys) -> Vec<Filter> {
        vec![Filter::parse(&json!({"#p": [k.public_key().to_hex()]})).unwrap()]
    }

    #[test]
    fn delivers_by_key_and_respects_who_may_read() {
        let hub = Hub::default();
        let service = Keys::generate();
        let client = Keys::generate();
        let (svc, mut svc_rx) = Conn::new(1, 1 << 20, 1 << 30);
        let (cli, mut cli_rx) = Conn::new(2, 1 << 20, 1 << 30);
        let (spy, mut spy_rx) = Conn::new(3, 1 << 20, 1 << 30);
        hub.subscribe(Sub::new(svc.clone(), "s".into(), p(&service)));
        hub.subscribe(Sub::new(cli.clone(), "c\"1".into(), p(&client)));
        hub.subscribe(Sub::new(spy.clone(), "x".into(), p(&service)));
        assert_eq!(hub.len(), 3);

        // A request from an unauthenticated client reaches only the service,
        // and only once the service has authenticated.
        let req = signed(&client, GIFT_WRAP, "req", vec![Tag::public_key(service.public_key())]);
        assert_eq!(hub.fanout(&req, Writer::Public), Fanout::default());
        assert!(svc.add_authed(service.public_key().to_bytes()));
        assert!(!svc.add_authed(service.public_key().to_bytes()));
        assert!(svc.is_trusted() && !spy.is_trusted());
        assert_eq!(
            hub.fanout(&req, Writer::Public),
            Fanout {
                delivered: 1,
                failed: 0
            }
        );
        assert_eq!(
            svc_rx.try_recv().unwrap(),
            Out::Text(format!("[\"EVENT\",\"s\",{}]", req.raw))
        );
        assert!(spy_rx.try_recv().is_err());

        // A reply from the service reaches the client.
        let reply = signed(&service, CTXVM, "reply", vec![Tag::public_key(client.public_key())]);
        assert_eq!(hub.fanout(&reply, Writer::Trusted).delivered, 1);
        assert_eq!(
            cli_rx.try_recv().unwrap(),
            Out::Text(format!("[\"EVENT\",\"c\\\"1\",{}]", reply.raw))
        );

        // Filters still apply after the index.
        hub.subscribe(Sub::new(
            cli.clone(),
            "c\"1".into(),
            vec![Filter::parse(&json!({"#p": [client.public_key().to_hex()], "kinds": [1059]})).unwrap()],
        ));
        assert_eq!(hub.len(), 3, "replaced, not added");
        assert_eq!(hub.fanout(&reply, Writer::Trusted).delivered, 0);

        assert!(hub.unsubscribe(3, "x"));
        assert!(!hub.unsubscribe(3, "x"));
        assert!(hub.unsubscribe(1, "s"));
        assert!(hub.unsubscribe(2, "c\"1"));
        assert!(hub.is_empty());
    }

    #[test]
    fn a_full_queue_cuts_off_only_that_connection() {
        let hub = Hub::default();
        let client = Keys::generate();
        let (slow, _rx) = Conn::new(1, 600, 1 << 30);
        let (fast, mut fast_rx) = Conn::new(2, 1 << 20, 1 << 30);
        let by_author = vec![Filter::parse(&json!({"authors": [client.public_key().to_hex()]})).unwrap()];
        hub.subscribe(Sub::new(slow.clone(), "a".into(), by_author.clone()));
        hub.subscribe(Sub::new(fast.clone(), "b".into(), by_author));
        let e = signed(&client, CTXVM, "x", vec![]);
        assert_eq!(
            hub.fanout(&e, Writer::Trusted),
            Fanout {
                delivered: 2,
                failed: 0
            }
        );
        assert!(slow.queued() > 0);
        assert_eq!(
            hub.fanout(&e, Writer::Trusted),
            Fanout {
                delivered: 1,
                failed: 1
            }
        );
        assert!(slow.is_dead() && !fast.is_dead());
        assert!(!slow.push("x".into()), "a dead connection takes nothing");
        slow.kill.notified().await_never();
        let frame = Sub::new(fast.clone(), "b".into(), vec![]).frame(&e);
        let n = frame.len();
        assert_eq!(fast_rx.try_recv().unwrap(), Out::Text(frame));
        fast.sent(n);
        fast.control(Out::Ping);
        assert_eq!(fast.queued(), n);
    }

    /// `notified()` on a Notify that was already signalled completes at once.
    trait Never {
        fn await_never(self);
    }
    impl<F: std::future::Future<Output = ()>> Never for F {
        fn await_never(self) {
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            rt.block_on(self);
        }
    }

    #[test]
    fn a_closed_writer_refuses_messages() {
        let (c, rx) = Conn::new(1, 100, 100);
        drop(rx);
        assert!(!c.push("x".into()));
        assert!(c.authed().is_empty());
    }
}
