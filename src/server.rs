//! Listeners: the relay (WebSocket and public pages) and the operator page.

use std::io;
use std::net::{IpAddr, SocketAddr};
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
use crate::http::{read_head_after, respond, switching, Prefixed, Request, Response};
use crate::limits::{Admit, Origin};
use crate::networks::{fips, i2p, tor, Network};
use crate::session::{self, Admission};
use crate::state::{lock, Shared};
use crate::web;

/// How often expired events and idle address records are dropped.
pub const PURGE_SECS: u64 = 10;

pub struct Running {
    /// Clearnet's address, or the first adapter's when clearnet is off.
    pub addr: SocketAddr,
    pub stats_addr: Option<SocketAddr>,
    /// Every network's listener, clearnet first.
    pub listeners: Vec<(Network, SocketAddr)>,
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

/// Which listener a connection arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Door {
    /// The operator page.
    Operator,
    /// The relay, over a network.
    Net(Network),
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
    let mut binds = vec![];
    if let Some(a) = cfg.listen {
        binds.push((Network::Clearnet, TcpListener::bind(a).await?));
    }
    for a in &cfg.adapters {
        binds.push((a.network, TcpListener::bind(a.listen).await?));
    }
    let stats = match cfg.stats_listen {
        Some(a) => Some(TcpListener::bind(a).await?),
        None => None,
    };
    let (stop, rx) = watch::channel(false);
    let sh = Shared::new(cfg);
    let mut listeners = vec![];
    let mut tasks = vec![];
    for (n, l) in binds {
        listeners.push((n, l.local_addr()?));
        tasks.push(tokio::spawn(accept_loop(sh.clone(), l, Door::Net(n), rx.clone())));
    }
    let stats_addr = match stats {
        Some(l) => {
            let a = l.local_addr()?;
            tasks.push(tokio::spawn(accept_loop(sh.clone(), l, Door::Operator, rx.clone())));
            Some(a)
        }
        None => None,
    };
    tasks.push(tokio::spawn(housekeeping(sh.clone(), rx)));
    Ok(Running {
        addr: listeners[0].1,
        stats_addr,
        listeners,
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

async fn accept_loop(sh: Arc<Shared>, l: TcpListener, door: Door, mut stop: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            r = l.accept() => accepted(&sh, r, door, &stop).await,
            _ = stop.changed() => return,
        }
    }
}

/// Serve an accepted connection in its own task, or back off after a failed accept.
pub async fn accepted(
    sh: &Arc<Shared>,
    r: io::Result<(TcpStream, SocketAddr)>,
    door: Door,
    stop: &watch::Receiver<bool>,
) {
    match r {
        Ok((s, peer)) => drop(tokio::spawn(handle(sh.clone(), s, peer, door, stop.clone()))),
        Err(e) => backoff(e).await,
    }
}

/// Count a connection turned away, under its network too.
fn turn_away(sh: &Shared, door: Door) {
    sh.stats.connections_refused.fetch_add(1, Relaxed);
    if let Door::Net(n) = door {
        let s = sh.net(n).expect("every network listened on has counters");
        s.turned_away.fetch_add(1, Relaxed);
    }
}

/// Whether `peer` may use network `n`'s listener at all: on Tor and I2P only
/// the daemon, which vouches for who is behind it; on FIPS only FIPS
/// addresses. Checked before a byte is read.
pub fn admits(sh: &Shared, n: Network, peer: IpAddr) -> bool {
    let peer = peer.to_canonical();
    match n {
        Network::Clearnet => true,
        Network::Fips => fips::node(peer).is_some(),
        _ => sh
            .cfg
            .adapter(n)
            .is_some_and(|a| a.daemons.iter().any(|d| d.to_canonical() == peer)),
    }
}

/// Read what precedes the request on `door` (Tor's PROXY line), then the
/// request head.
async fn arrive(s: &mut TcpStream, door: Door) -> io::Result<(Option<u32>, Request, Vec<u8>)> {
    let (circuit, buf) = match door {
        Door::Net(Network::Tor) => {
            let (gid, rest) = tor::preamble(s).await?;
            (Some(gid), rest)
        }
        _ => (None, Vec::with_capacity(1024)),
    };
    let (req, rest) = read_head_after(s, buf).await?;
    Ok((circuit, req, rest))
}

/// Who is connecting, by the rules of the network it came over. `None` when
/// the network cannot tell (an I2P tunnel that is not `type = http`).
pub fn origin_of(sh: &Shared, n: Network, peer: IpAddr, circuit: Option<u32>, req: &Request) -> Option<Origin> {
    match n {
        Network::Clearnet => Some(Origin::of(req.client_ip(peer, &sh.cfg.trusted_proxies))),
        Network::Tor => circuit.map(Origin::Tor),
        Network::I2p => i2p::destination(req).map(Origin::I2p),
        Network::Fips => fips::node(peer.to_canonical()).map(Origin::Fips),
    }
}

async fn handle(sh: Arc<Shared>, mut s: TcpStream, peer: SocketAddr, door: Door, stop: watch::Receiver<bool>) {
    let lim = &sh.cfg.limits;
    let _ = s.set_nodelay(true);
    if let Door::Net(n) = door {
        if !admits(&sh, n, peer.ip()) {
            return turn_away(&sh, door);
        }
    }
    if sh.handshakes.fetch_add(1, Relaxed) >= lim.max_connections + lim.reserved_connections {
        sh.handshakes.fetch_sub(1, Relaxed);
        return turn_away(&sh, door);
    }
    let head = tokio::time::timeout(Duration::from_secs(lim.handshake_secs), arrive(&mut s, door)).await;
    sh.handshakes.fetch_sub(1, Relaxed);
    let Ok(Ok((circuit, req, rest))) = head else {
        turn_away(&sh, door);
        let _ = respond(&mut s, Response::text(400, "bad request"), false).await;
        return;
    };
    let Door::Net(n) = door else {
        let _ = respond(&mut s, web::route(&sh, &req, true), req.method == "HEAD").await;
        return;
    };
    let Some(key) = req.websocket_key() else {
        let _ = respond(&mut s, web::route(&sh, &req, false), req.method == "HEAD").await;
        return;
    };
    match origin_of(&sh, n, peer.ip(), circuit, &req) {
        Some(origin) => upgrade(sh.clone(), s, origin, &req, key, rest, stop).await,
        None => {
            turn_away(&sh, door);
            let m = "this I2P tunnel does not say who is connecting: make it type = http";
            let _ = respond(&mut s, Response::text(400, m), false).await;
        }
    }
}

async fn upgrade(
    sh: Arc<Shared>,
    mut s: TcpStream,
    origin: Origin,
    req: &Request,
    key: &str,
    rest: Vec<u8>,
    stop: watch::Receiver<bool>,
) {
    let lim = &sh.cfg.limits;
    let n = origin.network();
    let admit = lock(&sh.origins).connect(origin, lim.connections_per_ip, Instant::now());
    // An overlay's own cap: its clients are free to mint, so this bounds them.
    let net_full = sh
        .cfg
        .adapter(n)
        .zip(sh.net(n))
        .is_some_and(|(a, s)| s.open.load(Relaxed) >= a.max_connections);
    let probation = admit == Admit::Probation || net_full || sh.open.load(Relaxed) >= lim.max_connections;
    let full = probation
        && (sh.probation.load(Relaxed) >= lim.reserved_connections || !lock(&sh.origins).take_probation(origin));
    if full {
        lock(&sh.origins).disconnect(origin);
        turn_away(&sh, Door::Net(n));
        let _ = respond(&mut s, Response::text(503, "this relay is full"), false).await;
        return;
    }
    let adm = Admission::new(sh.clone(), origin, probation);
    // A failed write shows up as a closed socket on the first read.
    let _ = s.write_all(switching(key).as_bytes()).await;
    let ws = WebSocketStream::from_raw_socket(Prefixed::new(rest, s), Role::Server, Some(ws_config(lim))).await;
    session::run(adm, ws, req.header("host"), stop).await;
}
