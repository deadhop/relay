//! The adapters over real sockets: a raw client stands in for the daemon
//! (writing Tor's PROXY line, or the headers i2pd adds).

use std::sync::atomic::Ordering::Relaxed;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use nostr_sdk::prelude::*;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{client_async, WebSocketStream};

use crate::config::tests::config;
use crate::config::ENV_WHITELIST;
use crate::networks::Network;
use crate::server::{self, Running};

type Ws = WebSocketStream<TcpStream>;

const ONION: &str = "ws://k7m3x2p4vq5zl6n8a7rjw3e9tthd4ysq2bgm5c6uv7xn2pqe5ar4lyid.onion";
const I2P: &str = "ws://xq4z7d2mvt3qkg5r6ly8p2c4n7u5h3s9a2wqe6tkb7fjzvx4ma2a.b32.i2p";
const DEST: &str = "z~5mQ0xH9Rk-J2uW8n1VbT3lYc6pFsA4eDgHiKjLmNo=";

async fn start(service: &Keys, extra: &[(&str, &str)]) -> Running {
    let wl = format!("invoices={}", service.public_key().to_hex());
    let mut pairs = vec![
        (ENV_WHITELIST, wl.as_str()),
        ("DEADHOP_RELAY_LISTEN", "127.0.0.1:0"),
        ("DEADHOP_RELAY_STATS_LISTEN", "127.0.0.1:0"),
        ("DEADHOP_RELAY_PUBLIC_URLS", "wss://relay.example.com"),
        ("DEADHOP_RELAY_TOR_LISTEN", "127.0.0.1:0"),
        ("DEADHOP_RELAY_TOR_URLS", ONION),
        ("DEADHOP_RELAY_I2P_LISTEN", "127.0.0.1:0"),
        ("DEADHOP_RELAY_I2P_URLS", I2P),
        // Reachable from here only on loopback, which is not a FIPS address.
        ("DEADHOP_RELAY_FIPS_LISTEN", "127.0.0.1:0"),
        ("DEADHOP_RELAY_FIPS_URLS", "ws://npub1x3wd.fips:7447"),
    ];
    pairs.extend_from_slice(extra);
    server::start(config(&pairs).unwrap()).await.unwrap()
}

fn on(r: &Running, n: Network) -> std::net::SocketAddr {
    r.listeners.iter().find(|(x, _)| *x == n).expect("listening").1
}

/// A WebSocket to network `n`'s listener, after `preamble` (Tor's line), with
/// `headers` (i2pd's) on the request. Gives the socket and its AUTH challenge.
async fn via(r: &Running, n: Network, preamble: &str, headers: &[(&'static str, &str)]) -> (Ws, String) {
    let addr = on(r, n);
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(preamble.as_bytes()).await.unwrap();
    let mut req = format!("ws://{addr}").into_client_request().unwrap();
    for (k, v) in headers {
        req.headers_mut().insert(*k, v.parse().unwrap());
    }
    let (mut ws, _) = client_async(req, tcp).await.unwrap();
    let a = next(&mut ws).await;
    assert_eq!(a[0], "AUTH");
    let challenge = a[1].as_str().unwrap().to_string();
    (ws, challenge)
}

async fn next(ws: &mut Ws) -> Value {
    loop {
        let m = tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await
            .expect("in time");
        if let Message::Text(t) = m.expect("open").expect("no error") {
            return serde_json::from_str(&t).unwrap();
        }
    }
}

async fn send(ws: &mut Ws, v: Value) {
    ws.send(Message::text(v.to_string())).await.unwrap();
}

/// What a plain HTTP request to network `n`'s listener gets back.
async fn http(r: &Running, n: Network, preamble: &str, request: &str) -> String {
    let mut s = TcpStream::connect(on(r, n)).await.unwrap();
    s.write_all(format!("{preamble}{request}").as_bytes()).await.unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out).await;
    out
}

fn tor_line(gid: u32) -> String {
    format!(
        "PROXY TCP6 fc00:dead:beef:4dad::{:x}:{:x} ::1 {} 80\r\n", // as Tor writes it: note the "::"
        gid >> 16,
        gid & 0xffff,
        gid & 0xffff
    )
}

fn auth_event(keys: &Keys, challenge: &str, url: &str) -> Value {
    let e = EventBuilder::auth(challenge, RelayUrl::parse(url).unwrap())
        .sign_with_keys(keys)
        .unwrap();
    json!(["AUTH", serde_json::to_value(&e).unwrap()])
}

#[tokio::test]
async fn tor_clients_by_circuit_and_auth_by_onion_address() {
    let service = Keys::generate();
    let r = start(&service, &[]).await;
    // The service over Tor: AUTH names the onion address, not the Host dialled
    // and not the clearnet PUBLIC_URLS.
    let (mut svc, ch) = via(&r, Network::Tor, &tor_line(0x10029), &[]).await;
    send(&mut svc, auth_event(&service, &ch, "wss://relay.example.com")).await;
    assert_eq!(
        next(&mut svc).await[2],
        json!(false),
        "the clearnet name is not this listener's"
    );
    send(&mut svc, auth_event(&service, &ch, ONION)).await;
    assert_eq!(next(&mut svc).await[2], json!(true));
    send(&mut svc, json!(["REQ", "in", {"#p": [service.public_key().to_hex()]}])).await;
    assert_eq!(next(&mut svc).await[0], "EOSE");

    // A customer on another circuit; a duplicate counts as refused, as on clearnet.
    let (mut c, _) = via(&r, Network::Tor, &tor_line(7), &[]).await;
    let req = EventBuilder::new(Kind::Custom(25910), "hi")
        .tag(Tag::public_key(service.public_key()))
        .sign_with_keys(&Keys::generate())
        .unwrap();
    send(&mut c, json!(["EVENT", req])).await;
    assert_eq!(next(&mut c).await[2], json!(true));
    assert_eq!(next(&mut svc).await[2]["content"], "hi");
    send(&mut c, json!(["EVENT", req])).await;
    assert!(next(&mut c).await[3].as_str().unwrap().starts_with("duplicate:"));
    send(&mut c, json!(["REQ", "x", {"kinds": [1]}])).await;
    assert_eq!(next(&mut c).await[0], "CLOSED");

    let sh = &r.shared;
    let tor = sh.net(Network::Tor).unwrap();
    assert_eq!(tor.open.load(Relaxed), 2);
    assert_eq!(tor.accepted.load(Relaxed), 1);
    assert_eq!(tor.refused_total(), 2);
    assert!(tor.bytes_in.load(Relaxed) > 0 && tor.bytes_out.load(Relaxed) > 0);
    assert_eq!(tor.sessions()[0].1, 1, "the service is connected over Tor");
    assert_eq!(
        crate::state::lock(&sh.origins).connected(Network::Tor),
        2,
        "two circuits"
    );
    assert_eq!(sh.net(Network::Clearnet).unwrap().open.load(Relaxed), 0);

    // The operator sees it.
    let page = http_op(&r, "/networks/tor").await;
    assert!(
        page.contains("by circuit") && page.contains(ONION) && page.contains("Whitelisted keys over Tor"),
        "{page}"
    );
    let overview = http_op(&r, "/").await;
    assert!(overview.contains("href=\"/networks/i2p\"") && overview.contains("class=\"dot ok\""));
    drop(svc);
    drop(c);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(sh.net(Network::Tor).unwrap().sessions()[0].1, 0);
    r.stop().await;
}

async fn http_op(r: &Running, path: &str) -> String {
    let mut s = TcpStream::connect(r.stats_addr.unwrap()).await.unwrap();
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    out
}

#[tokio::test]
async fn tor_without_its_line_is_turned_away() {
    let r = start(&Keys::generate(), &[]).await;
    let out = http(&r, Network::Tor, "", "GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert!(out.starts_with("HTTP/1.1 400"), "{out}");
    // With it, the status page is served over the onion address too.
    let out = http(&r, Network::Tor, &tor_line(1), "GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert!(out.starts_with("HTTP/1.1 200") && out.contains(ONION), "{out}");
    assert_eq!(r.shared.net(Network::Tor).unwrap().turned_away.load(Relaxed), 1);
    r.stop().await;
}

#[tokio::test]
async fn only_the_daemon_may_connect() {
    let r = start(&Keys::generate(), &[("DEADHOP_RELAY_TOR_DAEMONS", "10.9.8.7")]).await;
    let out = http(&r, Network::Tor, &tor_line(1), "GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert!(out.is_empty(), "closed without a word: {out}");
    // FIPS takes only FIPS addresses; loopback is not one.
    let out = http(&r, Network::Fips, "", "GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert!(out.is_empty(), "{out}");
    assert_eq!(r.shared.net(Network::Tor).unwrap().turned_away.load(Relaxed), 1);
    assert_eq!(r.shared.net(Network::Fips).unwrap().turned_away.load(Relaxed), 1);
    assert_eq!(r.shared.stats.connections_refused.load(Relaxed), 2);
    r.stop().await;
}

#[tokio::test]
async fn i2p_clients_by_destination() {
    let r = start(&Keys::generate(), &[]).await;
    let (_ws, _) = via(&r, Network::I2p, "", &[("x-i2p-desthash", DEST)]).await;
    assert_eq!(r.shared.net(Network::I2p).unwrap().open.load(Relaxed), 1);
    // A plain server tunnel says nothing about who is connecting: refused.
    let ws_head = "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                   Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    let out = http(&r, Network::I2p, "", ws_head).await;
    assert!(out.starts_with("HTTP/1.1 400") && out.contains("type = http"), "{out}");
    // Pages need no identity.
    let out = http(&r, Network::I2p, "", "GET /health HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    assert_eq!(r.shared.net(Network::I2p).unwrap().turned_away.load(Relaxed), 1);
    r.stop().await;
}

#[tokio::test]
async fn a_full_overlay_leaves_clearnet_open() {
    let r = start(
        &Keys::generate(),
        &[
            ("DEADHOP_RELAY_TOR_MAX_CONNECTIONS", "1"),
            ("DEADHOP_RELAY_RESERVED_CONNECTIONS", "0"),
        ],
    )
    .await;
    let (_a, _) = via(&r, Network::Tor, &tor_line(1), &[]).await;
    let ws_head = "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                   Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    let out = http(&r, Network::Tor, &tor_line(2), ws_head).await;
    assert!(
        out.starts_with("HTTP/1.1 503"),
        "a new circuit does not get past the cap: {out}"
    );
    let (_b, _) = via(&r, Network::Clearnet, "", &[]).await;
    assert_eq!(r.shared.net(Network::Clearnet).unwrap().open.load(Relaxed), 1);
    assert_eq!(r.shared.net(Network::Tor).unwrap().turned_away.load(Relaxed), 1);
    r.stop().await;
}

#[tokio::test]
async fn clearnet_can_be_off() {
    let cfg = config(&[
        ("DEADHOP_RELAY_PUBLIC", "on"),
        ("DEADHOP_RELAY_LISTEN", "off"),
        ("DEADHOP_RELAY_STATS_LISTEN", "off"),
        ("DEADHOP_RELAY_TOR_LISTEN", "127.0.0.1:0"),
        ("DEADHOP_RELAY_TOR_URLS", ONION),
    ])
    .unwrap();
    let r = server::start(cfg).await.unwrap();
    assert_eq!(r.listeners.len(), 1);
    assert_eq!(r.addr, on(&r, Network::Tor));
    assert!(r.shared.net(Network::Clearnet).is_none());
    let (_ws, _) = via(&r, Network::Tor, &tor_line(3), &[]).await;
    r.stop().await;
}

#[tokio::test]
async fn the_operator_listener_turns_away_bad_requests_too() {
    let r = start(&Keys::generate(), &[]).await;
    let mut s = TcpStream::connect(r.stats_addr.unwrap()).await.unwrap();
    s.write_all(b"\x00\x01 not http\r\n\r\n").await.unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out).await;
    assert!(out.starts_with("HTTP/1.1 400"), "{out}");
    assert_eq!(r.shared.stats.connections_refused.load(Relaxed), 1);
    assert!(r.shared.nets.iter().all(|n| n.turned_away.load(Relaxed) == 0));
    r.stop().await;
}

#[test]
fn fips_peers_are_their_own_clients() {
    use crate::http::Request;
    let sh = crate::state::Shared::new(
        config(&[
            ("DEADHOP_RELAY_PUBLIC", "on"),
            ("DEADHOP_RELAY_FIPS_LISTEN", "[::]:7447"),
            ("DEADHOP_RELAY_FIPS_URLS", "ws://npub1x.fips:7447"),
        ])
        .unwrap(),
    );
    let peer: std::net::IpAddr = "fd3c:1a2b:3c4d:5e6f:7081:92a3:b4c5:d6e7".parse().unwrap();
    let req = Request {
        method: "GET".into(),
        path: "/".into(),
        headers: vec![],
    };
    assert!(server::admits(&sh, Network::Fips, peer) && !server::admits(&sh, Network::Fips, "::1".parse().unwrap()));
    let o = server::origin_of(&sh, Network::Fips, peer, None, &req).unwrap();
    assert_eq!(o.network(), Network::Fips);
    assert!(server::admits(&sh, Network::Clearnet, "10.0.0.1".parse().unwrap()));
    assert!(
        !server::admits(&sh, Network::Tor, "127.0.0.1".parse().unwrap()),
        "not served on Tor"
    );
    assert_eq!(server::origin_of(&sh, Network::Tor, peer, None, &req), None);
}

#[tokio::test]
async fn an_overlay_holds_only_its_share_of_the_reserved_slots() {
    // Cap 1, 8 reserved: Tor may hold 2 probation slots (a quarter).
    let r = start(
        &Keys::generate(),
        &[
            ("DEADHOP_RELAY_TOR_MAX_CONNECTIONS", "1"),
            ("DEADHOP_RELAY_RESERVED_CONNECTIONS", "8"),
        ],
    )
    .await;
    let (_a, _) = via(&r, Network::Tor, &tor_line(1), &[]).await;
    let (_b, _) = via(&r, Network::Tor, &tor_line(2), &[]).await;
    let (_c, _) = via(&r, Network::Tor, &tor_line(3), &[]).await;
    let ws_head = "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                   Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    let out = http(&r, Network::Tor, &tor_line(4), ws_head).await;
    assert!(out.starts_with("HTTP/1.1 503"), "{out}");
    let tor = r.shared.net(Network::Tor).unwrap();
    assert_eq!((tor.probation.load(Relaxed), r.shared.probation.load(Relaxed)), (2, 2));
    assert_eq!(crate::networks::probation_share(0), 1);
    r.stop().await;
}
