//! One WebSocket connection: NIP-01 messages in, queued messages out.
//!
//! The reader runs here; a separate writer task drains the connection's
//! queue, so a slow socket never holds up the fan-out to anyone else.

use std::ops::ControlFlow;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Duration;

use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::value::RawValue;
use tokio::sync::{mpsc, watch};
use tokio::time::{sleep_until, Instant};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use crate::event::Event;
use crate::filter::Filter;
use crate::http::Prefixed;
use crate::hub::{Conn, Out, Sub};
use crate::limits::{unix_now, Bucket, Origin};
use crate::networks::{NetStats, Network};
use crate::state::{lock, Shared};
use crate::stats::Reason;

/// Connections only arrive on networks the relay is served on, each counted.
const COUNTED: &str = "every network a connection arrives on has counters";

/// Rate-limited messages a connection may send before it is closed.
pub const MAX_STRIKES: u32 = 50;
/// How long a closing connection may take to flush what it was sent.
pub const FLUSH_SECS: u64 = 5;

pub type Ws = WebSocketStream<Prefixed>;

/// Counts a connection in and, when dropped, out.
pub struct Admission {
    pub sh: Arc<Shared>,
    pub origin: Origin,
    pub probation: bool,
}

impl Admission {
    pub fn new(sh: Arc<Shared>, origin: Origin, probation: bool) -> Admission {
        let n = sh.net(origin.network()).expect(COUNTED);
        n.open.fetch_add(1, Relaxed);
        n.total.fetch_add(1, Relaxed);
        sh.open.fetch_add(1, Relaxed);
        sh.stats.connections_open.fetch_add(1, Relaxed);
        sh.stats.connections_total.fetch_add(1, Relaxed);
        if probation {
            sh.probation.fetch_add(1, Relaxed);
        }
        Admission { sh, origin, probation }
    }

    fn end_probation(&mut self) {
        if self.probation {
            self.probation = false;
            self.sh.probation.fetch_sub(1, Relaxed);
            lock(&self.sh.origins).end_probation(self.origin);
        }
    }
}

impl Drop for Admission {
    fn drop(&mut self) {
        self.end_probation();
        self.sh
            .net(self.origin.network())
            .expect(COUNTED)
            .open
            .fetch_sub(1, Relaxed);
        self.sh.open.fetch_sub(1, Relaxed);
        self.sh.stats.connections_open.fetch_sub(1, Relaxed);
        lock(&self.sh.origins).disconnect(self.origin);
    }
}

#[derive(Deserialize)]
struct IdOnly {
    id: String,
}

fn id_of(raw: &RawValue) -> Option<String> {
    serde_json::from_str::<IdOnly>(raw.get()).ok().map(|i| i.id)
}

fn text<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v).expect("plain values serialise")
}

struct Pending {
    id: String,
    filters: Vec<Filter>,
    deadline: Instant,
}

struct Session {
    sh: Arc<Shared>,
    conn: Arc<Conn>,
    adm: Admission,
    challenge: String,
    hosts: Vec<String>,
    subs: Vec<String>,
    pending: Vec<Pending>,
    bucket: Bucket,
    strikes: u32,
    probation_until: Option<Instant>,
}

impl Session {
    fn send(&self, msg: String) {
        self.conn.push(msg);
    }

    fn notice(&self, m: &str) {
        self.send(text(&("NOTICE", m)));
    }

    fn closed(&self, id: &str, m: &str) {
        self.send(text(&("CLOSED", id, m)));
    }

    fn ok(&self, id: &str, accepted: bool, m: &str) {
        self.send(text(&("OK", id, accepted, m)));
    }

    fn handle(&mut self, msg: &str) -> ControlFlow<()> {
        let parts: Vec<&RawValue> = match serde_json::from_str(msg) {
            Ok(p) => p,
            Err(_) => {
                self.notice("invalid: a message must be a JSON array");
                return ControlFlow::Continue(());
            }
        };
        let verb = parts
            .first()
            .and_then(|v| serde_json::from_str::<String>(v.get()).ok())
            .unwrap_or_default();
        let limited = !self.conn.is_trusted() && !self.bucket.take(std::time::Instant::now());
        let second = parts.get(1).copied();
        match (verb.as_str(), second) {
            ("EVENT", Some(raw)) => self.event(raw, limited),
            ("REQ", Some(raw)) => self.req(raw, &parts[2..], limited),
            ("CLOSE", Some(raw)) => self.close(raw),
            ("AUTH", Some(raw)) => self.auth(raw),
            _ => self.notice("invalid: unknown or incomplete message"),
        }
        if limited {
            self.strikes += 1;
            if self.strikes > MAX_STRIKES {
                self.notice("rate-limited: too many messages; closing");
                return ControlFlow::Break(());
            }
        }
        ControlFlow::Continue(())
    }

    fn refuse(&self, r: Reason) {
        self.sh.stats.refuse(r, unix_now() / 60);
        self.net().refuse(r, unix_now() / 60);
    }

    /// This connection's network's counters.
    fn net(&self) -> &NetStats {
        self.sh.net(self.adm.origin.network()).expect(COUNTED)
    }

    fn event(&mut self, raw: &RawValue, limited: bool) {
        let e = match Event::parse(raw) {
            Ok(e) => e,
            Err(m) => {
                self.refuse(Reason::Invalid);
                match id_of(raw) {
                    Some(id) => self.ok(&id, false, &m),
                    None => self.notice(&m),
                }
                return;
            }
        };
        let id = hex::encode(e.id);
        if limited {
            self.refuse(Reason::RateLimited);
            return self.ok(&id, false, "rate-limited: too many messages; slow down");
        }
        if self.adm.probation {
            self.refuse(Reason::AuthRequired);
            return self.ok(
                &id,
                false,
                "auth-required: this relay is full; only whitelisted keys may write now",
            );
        }
        let (accepted, m) = self.sh.publish(e, &self.conn, self.adm.origin);
        // A duplicate is answered OK but counted as refused, as above.
        if accepted && m.is_empty() {
            self.net().accept(unix_now() / 60);
        } else {
            self.net().refuse(Reason::of(&m), unix_now() / 60);
        }
        self.ok(&id, accepted, &m);
    }

    /// Whether a subscription must wait for AUTH: on probation every one
    /// does; otherwise those that read a whitelisted key's requests.
    fn needs_auth(&self, filters: &[Filter]) -> bool {
        let authed = self.conn.authed();
        self.adm.probation
            || filters
                .iter()
                .flat_map(Filter::p_keys)
                .any(|k| self.sh.cfg.whitelist.contains(&k) && !authed.contains(&k))
    }

    fn req(&mut self, raw: &RawValue, rest: &[&RawValue], limited: bool) {
        let Ok(id) = serde_json::from_str::<String>(raw.get()) else {
            return self.notice("invalid: a subscription id must be a string");
        };
        let lim = &self.sh.cfg.limits;
        let fail = |r: Reason, m: &str| {
            self.refuse(r);
            self.closed(&id, m);
        };
        if limited {
            return fail(Reason::RateLimited, "rate-limited: too many messages; slow down");
        }
        if id.is_empty() || id.chars().count() > 64 {
            return fail(Reason::Invalid, "invalid: a subscription id must be 1 to 64 characters");
        }
        if rest.is_empty() || rest.len() > lim.max_filters {
            return fail(
                Reason::Invalid,
                &format!("invalid: send 1 to {} filters", lim.max_filters),
            );
        }
        let parsed: Result<Vec<Filter>, String> = rest
            .iter()
            // Each part is already valid JSON: it came out of the message's array.
            .map(|r| Filter::parse(&serde_json::from_str(r.get()).unwrap_or_default()))
            .collect();
        let filters = match parsed {
            Ok(f) => f,
            Err(m) => return fail(Reason::Invalid, &m),
        };
        if !filters.iter().all(Filter::is_scoped) {
            return fail(Reason::Restricted, "restricted: every filter must name #p or authors");
        }
        let known = self.subs.contains(&id) || self.pending.iter().any(|p| p.id == id);
        if !known && self.subs.len() + self.pending.len() >= lim.max_subscriptions {
            let m = format!(
                "rate-limited: at most {} subscriptions per connection",
                lim.max_subscriptions
            );
            return fail(Reason::RateLimited, &m);
        }
        self.pending.retain(|p| p.id != id);
        if self.needs_auth(&filters) {
            // Held until AUTH arrives: deadhop authenticates as soon as it is
            // challenged, often just after it subscribes (and, on probation,
            // just after it is let in).
            let deadline = Instant::now() + Duration::from_secs(lim.auth_grace_secs);
            self.pending.push(Pending { id, filters, deadline });
            return;
        }
        self.activate(id, filters);
    }

    /// Register a subscription, then send what is stored. Registering first
    /// means an event arriving in between is sent twice, never missed.
    fn activate(&mut self, id: String, filters: Vec<Filter>) {
        let sub = Sub::new(self.conn.clone(), id.clone(), filters.clone());
        let frames = Sub::new(self.conn.clone(), id.clone(), vec![]);
        self.sh.hub.subscribe(sub);
        let stored = self.sh.query(&filters, &self.conn.authed());
        let frames: Vec<String> = stored.iter().map(|e| frames.frame(e)).collect();
        self.sh.stats.subscriptions.fetch_add(1, Relaxed);
        for f in frames {
            self.send(f);
        }
        self.send(text(&("EOSE", &id)));
        if !self.subs.contains(&id) {
            self.subs.push(id);
        }
    }

    fn close(&mut self, raw: &RawValue) {
        let id = serde_json::from_str::<String>(raw.get()).unwrap_or_default();
        self.sh.hub.unsubscribe(self.conn.id, &id);
        self.subs.retain(|s| *s != id);
        self.pending.retain(|p| p.id != id);
    }

    fn auth(&mut self, raw: &RawValue) {
        let e = match Event::parse(raw) {
            Ok(e) => e,
            Err(m) => return self.notice(&m),
        };
        let id = hex::encode(e.id);
        match self.sh.check_auth(&e, &self.challenge, &self.hosts, unix_now()) {
            Ok(k) if !self.sh.cfg.whitelist.contains(&k) => {
                // Accepted, as NIP-42 expects, but it earns nothing here.
                self.conn.set_other();
                self.sh.stats.auth_other.fetch_add(1, Relaxed);
                self.ok(&id, true, "");
            }
            Ok(k) => {
                if self.conn.add_authed(k) {
                    self.sh.stats.auth_ok.fetch_add(1, Relaxed);
                    let counters = self.sh.stats.key(&k).expect("whitelisted keys have counters");
                    counters.sessions.fetch_add(1, Relaxed);
                    self.net().session(&k, true);
                }
                self.adm.end_probation();
                self.probation_until = None;
                self.ok(&id, true, "");
                let (ready, waiting): (Vec<Pending>, Vec<Pending>) = std::mem::take(&mut self.pending)
                    .into_iter()
                    .partition(|p| !self.needs_auth(&p.filters));
                self.pending = waiting;
                for p in ready {
                    self.activate(p.id, p.filters);
                }
            }
            Err(m) => {
                self.sh.stats.auth_failed.fetch_add(1, Relaxed);
                self.ok(&id, false, &m);
            }
        }
    }

    /// The next time something expires: a held subscription or probation.
    fn next_deadline(&self) -> Option<Instant> {
        self.pending
            .iter()
            .map(|p| p.deadline)
            .chain(self.probation_until)
            .min()
    }

    /// Close held subscriptions that were never authenticated; end probation.
    fn expire(&mut self, now: Instant) -> ControlFlow<()> {
        let (late, waiting): (Vec<Pending>, Vec<Pending>) = std::mem::take(&mut self.pending)
            .into_iter()
            .partition(|p| p.deadline <= now);
        self.pending = waiting;
        for p in late {
            self.refuse(Reason::AuthRequired);
            self.closed(
                &p.id,
                "auth-required: reading a whitelisted key's messages needs AUTH as that key",
            );
        }
        if self.probation_until.is_some_and(|t| t <= now) {
            self.sh.stats.probation_closed.fetch_add(1, Relaxed);
            self.notice("restricted: this relay is full; only whitelisted keys may stay connected");
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    }
}

type WsError = tokio_tungstenite::tungstenite::Error;

/// Write errors worth waiting out: the kernel is short of buffers (ENOBUFS,
/// seen under floods), or the socket would block.
pub fn transient(e: &WsError) -> bool {
    match e {
        WsError::Io(io) => {
            matches!(
                io.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) || matches!(io.raw_os_error(), Some(55 | 105))
        }
        _ => false,
    }
}

/// How often, and how far apart, a transient write error is retried.
pub const RETRIES: u32 = 100;
pub const RETRY_MS: u64 = 20;

/// Retry what is buffered while the error is transient.
/// (The error is tungstenite's own, as the sink returns it.)
#[allow(clippy::result_large_err)]
pub async fn settle<S>(sink: &mut S, mut r: Result<(), WsError>) -> Result<(), WsError>
where
    S: futures_util::Sink<Message, Error = WsError> + Unpin,
{
    let mut tries = 0;
    loop {
        match r {
            Err(e) if transient(&e) && tries < RETRIES => {
                tries += 1;
                tokio::time::sleep(Duration::from_millis(RETRY_MS)).await;
                r = sink.flush().await;
            }
            other => return other,
        }
    }
}

/// Drain the queue. When the socket fails for good, the whole connection is
/// closed, so the client reconnects (and finds what was held for it) instead
/// of staying connected to a writer that is gone.
async fn write_loop(
    sink: SplitSink<Ws, Message>,
    rx: mpsc::UnboundedReceiver<Out>,
    conn: Arc<Conn>,
    sh: Arc<Shared>,
    net: Network,
) {
    let _ = pump(sink, rx, conn.clone(), sh, net).await;
    conn.end();
}

/// Send queued messages, flushing whenever the queue runs dry.
async fn pump(
    mut sink: SplitSink<Ws, Message>,
    mut rx: mpsc::UnboundedReceiver<Out>,
    conn: Arc<Conn>,
    sh: Arc<Shared>,
    net: Network,
) -> Result<(), Box<WsError>> {
    loop {
        // The queue outlives this task, so it only ends with a Close.
        match rx.recv().await.unwrap_or(Out::Close(String::new())) {
            Out::Text(s) => {
                let n = s.len();
                let r = sink.feed(Message::text(s)).await;
                conn.sent(n);
                sh.stats.bytes_out.fetch_add(n as u64, Relaxed);
                sh.net(net).expect(COUNTED).bytes_out.fetch_add(n as u64, Relaxed);
                settle(&mut sink, r).await?;
            }
            Out::Ping => {
                let r = sink.feed(Message::Ping(Default::default())).await;
                settle(&mut sink, r).await?;
            }
            Out::Close(reason) => {
                let frame = CloseFrame {
                    code: CloseCode::Normal,
                    reason: reason.into(),
                };
                return Ok(sink.send(Message::Close(Some(frame))).await?);
            }
        }
        if rx.is_empty() {
            let r = sink.flush().await;
            settle(&mut sink, r).await?;
        }
    }
}

/// Why a connection was told to close: its writer failed, or it read too slowly.
pub fn kill_reason(conn: &Conn, sh: &Shared) -> &'static str {
    if conn.is_gone() {
        "connection lost"
    } else {
        sh.stats.slow_closed.fetch_add(1, Relaxed);
        "too slow"
    }
}

/// A random NIP-42 challenge.
pub fn challenge() -> String {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("the system has randomness");
    hex::encode(b)
}

/// Serve one upgraded connection until it closes.
pub async fn run(adm: Admission, ws: Ws, host: Option<&str>, mut shutdown: watch::Receiver<bool>) {
    let sh = adm.sh.clone();
    let lim = sh.cfg.limits.clone();
    let (conn, rx) = Conn::new(sh.next_id(), lim.queue_bytes, lim.trusted_queue_bytes);
    let (sink, mut stream) = ws.split();
    let network = adm.origin.network();
    let writer = tokio::spawn(write_loop(sink, rx, conn.clone(), sh.clone(), network));
    let rate = f64::from(lim.messages_per_sec);
    let mut s = Session {
        hosts: sh.hosts_on(network, host),
        conn: conn.clone(),
        challenge: challenge(),
        subs: vec![],
        pending: vec![],
        bucket: Bucket::new(rate, rate * 3.0, std::time::Instant::now()),
        strikes: 0,
        probation_until: adm
            .probation
            .then(|| Instant::now() + Duration::from_secs(lim.auth_grace_secs)),
        sh: sh.clone(),
        adm,
    };
    s.send(text(&("AUTH", &s.challenge)));
    let idle = Duration::from_secs(lim.idle_secs);
    let mut last_seen = Instant::now();
    let mut ping = tokio::time::interval_at(Instant::now() + idle / 3, idle / 3);
    let far = Instant::now() + Duration::from_secs(365 * 86_400);
    let reason = loop {
        let deadline = s.next_deadline().unwrap_or(far);
        tokio::select! {
            msg = stream.next() => match msg {
                Some(Ok(Message::Text(t))) => {
                    last_seen = Instant::now();
                    sh.stats.bytes_in.fetch_add(t.len() as u64, Relaxed);
                    sh.net(network).expect(COUNTED).bytes_in.fetch_add(t.len() as u64, Relaxed);
                    if s.handle(t.as_str()).is_break() {
                        break "rate-limited";
                    }
                }
                Some(Ok(Message::Binary(_))) => {
                    last_seen = Instant::now();
                    s.notice("invalid: binary messages are not supported");
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break "bye",
                Some(Ok(_)) => last_seen = Instant::now(),
            },
            _ = sleep_until(deadline) => {
                if s.expire(Instant::now()).is_break() {
                    break "full";
                }
            }
            _ = sleep_until(last_seen + idle) => break "idle",
            _ = ping.tick() => conn.control(Out::Ping),
            () = conn.kill.notified() => break kill_reason(&conn, &sh),
            _ = shutdown.changed() => break "shutting down",
        }
    };
    for id in &s.subs {
        sh.hub.unsubscribe(conn.id, id);
    }
    for k in conn.authed() {
        sh.stats
            .key(&k)
            .expect("whitelisted keys have counters")
            .sessions
            .fetch_sub(1, Relaxed);
        sh.net(network).expect(COUNTED).session(&k, false);
    }
    conn.control(Out::Close(reason.into()));
    // A peer that stops reading cannot hold the task open.
    let _ = tokio::time::timeout(Duration::from_secs(FLUSH_SECS), writer).await;
    drop(s);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// A sink whose flush fails `left` times with `error`, then succeeds.
    struct Flaky {
        left: u32,
        error: fn() -> WsError,
    }

    impl futures_util::Sink<Message> for Flaky {
        type Error = WsError;
        fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), WsError>> {
            Poll::Ready(Ok(()))
        }
        fn start_send(self: Pin<&mut Self>, _: Message) -> Result<(), WsError> {
            Ok(())
        }
        fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), WsError>> {
            if self.left == 0 {
                return Poll::Ready(Ok(()));
            }
            self.left -= 1;
            Poll::Ready(Err((self.error)()))
        }
        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), WsError>> {
            Poll::Ready(Ok(()))
        }
    }

    fn enobufs() -> WsError {
        WsError::Io(std::io::Error::from_raw_os_error(55))
    }

    fn broken() -> WsError {
        WsError::Io(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
    }

    #[test]
    fn kill_reasons() {
        let sh = crate::state::tests::shared(&nostr_sdk::prelude::Keys::generate(), &[]);
        let (c, _rx) = Conn::new(1, 100, 100);
        assert_eq!(kill_reason(&c, &sh), "too slow");
        c.end();
        assert!(c.is_dead());
        assert_eq!(kill_reason(&c, &sh), "connection lost");
        assert_eq!(sh.stats.slow_closed.load(Relaxed), 1);
    }

    #[test]
    fn which_errors_are_transient() {
        assert!(transient(&enobufs()));
        assert!(transient(&WsError::Io(std::io::Error::from_raw_os_error(105))));
        assert!(transient(&WsError::Io(std::io::ErrorKind::WouldBlock.into())));
        assert!(transient(&WsError::Io(std::io::ErrorKind::Interrupted.into())));
        assert!(!transient(&broken()));
        assert!(!transient(&WsError::ConnectionClosed));
    }

    #[tokio::test]
    async fn transient_errors_are_waited_out_and_others_are_not() {
        let mut s = Flaky {
            left: 3,
            error: enobufs,
        };
        assert!(settle(&mut s, Err(enobufs())).await.is_ok());
        assert_eq!(s.left, 0);
        let mut s = Flaky {
            left: 0,
            error: enobufs,
        };
        assert!(settle(&mut s, Ok(())).await.is_ok());
        assert!(settle(&mut s, Err(broken())).await.is_err());
        let mut forever = Flaky {
            left: u32::MAX,
            error: enobufs,
        };
        assert!(
            settle(&mut forever, Err(enobufs())).await.is_err(),
            "gives up after RETRIES"
        );
        // Unused parts of the sink, exercised for completeness.
        use futures_util::SinkExt;
        forever.send(Message::text("x")).await.unwrap_err();
        let mut ok = Flaky { left: 0, error: broken };
        ok.close().await.unwrap();
    }
}
