//! Listeners: the relay (WebSocket and public pages) and the operator page.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};
use tokio_tungstenite::WebSocketStream;

use crate::config::{Config, Limits};
use crate::http::{read_head, respond, switching, Prefixed, Request, Response};
use crate::limits::{Admit, Origin};
use crate::session::{self, Admission};
use crate::state::{lock, Shared};
use crate::web;

/// How often expired events and idle address records are dropped.
pub const PURGE_SECS: u64 = 10;

pub struct Running {
    pub addr: SocketAddr,
    pub stats_addr: Option<SocketAddr>,
    pub shared: Arc<Shared>,
    stop: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl Running {
    /// Stop accepting, close every connection, and wait for the listeners.
    pub async fn stop(self) {
        let _ = self.stop.send(true);
        for t in self.tasks {
            let _ = t.await;
        }
    }
}

/// Small buffers: most connections are idle clients, and the defaults
/// (128 KiB each way) would cost a quarter of a megabyte per connection.
pub const WS_BUFFER: usize = 8 * 1024;

pub fn ws_config(l: &Limits) -> WebSocketConfig {
    WebSocketConfig::default()
        .read_buffer_size(WS_BUFFER)
        .write_buffer_size(WS_BUFFER)
        .max_message_size(Some(l.max_message_bytes))
        .max_frame_size(Some(l.max_message_bytes))
}

/// Bind the listeners and start serving.
pub async fn start(cfg: Config) -> io::Result<Running> {
    let main = TcpListener::bind(cfg.listen).await?;
    let stats = match cfg.stats_listen {
        Some(a) => Some(TcpListener::bind(a).await?),
        None => None,
    };
    let (stop, rx) = watch::channel(false);
    let sh = Shared::new(cfg);
    let addr = main.local_addr()?;
    let mut tasks = vec![tokio::spawn(accept_loop(sh.clone(), main, false, rx.clone()))];
    let stats_addr = match stats {
        Some(l) => {
            let a = l.local_addr()?;
            tasks.push(tokio::spawn(accept_loop(sh.clone(), l, true, rx.clone())));
            Some(a)
        }
        None => None,
    };
    tasks.push(tokio::spawn(housekeeping(sh.clone(), rx)));
    Ok(Running {
        addr,
        stats_addr,
        shared: sh,
        stop,
        tasks,
    })
}

async fn housekeeping(sh: Arc<Shared>, mut stop: watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(Duration::from_secs(PURGE_SECS));
    loop {
        tokio::select! {
            _ = tick.tick() => sh.purge(),
            _ = stop.changed() => return,
        }
    }
}

/// After a failed accept (out of file descriptors, usually), wait a moment
/// instead of spinning.
pub async fn backoff(e: io::Error) {
    eprintln!("deadhop-relay: accept failed: {e}");
    tokio::time::sleep(Duration::from_millis(50)).await;
}

async fn accept_loop(sh: Arc<Shared>, l: TcpListener, operator: bool, mut stop: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            r = l.accept() => accepted(&sh, r, operator, &stop).await,
            _ = stop.changed() => return,
        }
    }
}

/// Serve an accepted connection in its own task, or back off after a failed accept.
pub async fn accepted(
    sh: &Arc<Shared>,
    r: io::Result<(TcpStream, SocketAddr)>,
    operator: bool,
    stop: &watch::Receiver<bool>,
) {
    match r {
        Ok((s, peer)) => drop(tokio::spawn(handle(sh.clone(), s, peer, operator, stop.clone()))),
        Err(e) => backoff(e).await,
    }
}

async fn handle(sh: Arc<Shared>, mut s: TcpStream, peer: SocketAddr, operator: bool, stop: watch::Receiver<bool>) {
    let lim = &sh.cfg.limits;
    let _ = s.set_nodelay(true);
    if sh.handshakes.fetch_add(1, Relaxed) >= lim.max_connections + lim.reserved_connections {
        sh.handshakes.fetch_sub(1, Relaxed);
        sh.stats.connections_refused.fetch_add(1, Relaxed);
        return;
    }
    let head = tokio::time::timeout(Duration::from_secs(lim.handshake_secs), read_head(&mut s)).await;
    sh.handshakes.fetch_sub(1, Relaxed);
    let Ok(Ok((req, rest))) = head else {
        sh.stats.connections_refused.fetch_add(1, Relaxed);
        let _ = respond(&mut s, Response::text(400, "bad request"), false).await;
        return;
    };
    match req.websocket_key().filter(|_| !operator) {
        Some(key) => upgrade(sh.clone(), s, peer, &req, key, rest, stop).await,
        None => {
            let _ = respond(&mut s, web::route(&sh, &req, operator), req.method == "HEAD").await;
        }
    }
}

async fn upgrade(
    sh: Arc<Shared>,
    mut s: TcpStream,
    peer: SocketAddr,
    req: &Request,
    key: &str,
    rest: Vec<u8>,
    stop: watch::Receiver<bool>,
) {
    let lim = &sh.cfg.limits;
    let origin = Origin::of(req.client_ip(peer.ip(), &sh.cfg.trusted_proxies));
    let admit = lock(&sh.origins).connect(origin, lim.connections_per_ip, Instant::now());
    let probation = admit == Admit::Probation || sh.open.load(Relaxed) >= lim.max_connections;
    let full = probation
        && (sh.probation.load(Relaxed) >= lim.reserved_connections || !lock(&sh.origins).take_probation(origin));
    if full {
        lock(&sh.origins).disconnect(origin);
        sh.stats.connections_refused.fetch_add(1, Relaxed);
        let _ = respond(&mut s, Response::text(503, "this relay is full"), false).await;
        return;
    }
    let adm = Admission::new(sh.clone(), origin, probation);
    // A failed write shows up as a closed socket on the first read.
    let _ = s.write_all(switching(key).as_bytes()).await;
    let ws = WebSocketStream::from_raw_socket(Prefixed::new(rest, s), Role::Server, Some(ws_config(lim))).await;
    session::run(adm, ws, req.header("host"), stop).await;
}
