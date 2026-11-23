//! Load and flood benchmark for deadhop-relay.
//!
//! Starts the relay binary with a fresh whitelisted service key, then:
//! - one service connection authenticates, subscribes to its requests and
//!   answers each one (as deadhop does);
//! - `clients` connections each send ContextVM requests at a fixed rate and
//!   wait for the answers;
//! - optionally, `attackers` connections flood the relay at full speed with
//!   valid spam to the service, junk, refused kinds, subscriptions and
//!   reconnects.
//!
//! Every connection claims its own address through `X-Forwarded-For`
//! (the relay trusts 127.0.0.1 as a proxy here), so per-address limits act
//! as they would in front of real users.
//!
//! "Dropped" means accepted by the relay (OK true) and never delivered:
//! requests that never reached the service, and answers that never reached
//! their client. The target is zero.
//!
//! usage: deadhop-relay-bench <relay-binary> <out.json> [clients] [rate/s per client] [secs] [attackers]

use std::collections::HashMap;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use nostr::prelude::*;
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{client_async, WebSocketStream};

type Ws = WebSocketStream<TcpStream>;

#[derive(Default)]
struct Counters {
    sent: AtomicU64,
    ok: AtomicU64,
    refused: AtomicU64,
    at_service: AtomicU64,
    spam_at_service: AtomicU64,
    replies_sent: AtomicU64,
    replies_ok: AtomicU64,
    answered: AtomicU64,
    attack_sent: AtomicU64,
    attack_ok: AtomicU64,
    attack_refused: AtomicU64,
    attack_closed: AtomicU64,
    latencies_us: Mutex<Vec<u64>>,
    refusals: Mutex<HashMap<String, u64>>,
}

async fn connect(port: u16, ip: &str) -> Option<Ws> {
    // Retried: a burst of connects can overflow the listen backlog.
    for attempt in 0..20 {
        let mut req = format!("ws://127.0.0.1:{port}/").into_client_request().ok()?;
        req.headers_mut().insert("X-Forwarded-For", ip.parse().ok()?);
        let r = match TcpStream::connect(("127.0.0.1", port)).await {
            Ok(tcp) => client_async(req, tcp)
                .await
                .map(|(ws, _)| ws)
                .map_err(|e| e.to_string()),
            Err(e) => Err(e.to_string()),
        };
        match r {
            Ok(ws) => return Some(ws),
            Err(e) if attempt == 19 => eprintln!("connect {ip}: {e}"),
            Err(_) => tokio::time::sleep(Duration::from_millis(50 * (attempt + 1))).await,
        }
    }
    None
}

fn text(v: Value) -> Message {
    Message::text(v.to_string())
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn start_relay(bin: &str, service: &Keys, port: u16, stats: u16) -> Child {
    let child = Command::new(bin)
        .env(
            "DEADHOP_RELAY_WHITELIST",
            format!("invoices={}", service.public_key().to_hex()),
        )
        .env("DEADHOP_RELAY_LISTEN", format!("127.0.0.1:{port}"))
        .env("DEADHOP_RELAY_STATS_LISTEN", format!("127.0.0.1:{stats}"))
        .env("DEADHOP_RELAY_TRUSTED_PROXIES", "127.0.0.1")
        .env("DEADHOP_RELAY_PUBLIC_URLS", format!("ws://127.0.0.1:{port}"))
        .env("DEADHOP_RELAY_MAX_CONNECTIONS", "4096")
        .stderr(Stdio::null())
        .spawn()
        .expect("start the relay");
    std::thread::sleep(Duration::from_millis(400));
    child
}

/// The service: AUTH, subscribe to its requests, answer each one.
async fn service(port: u16, keys: Keys, c: Arc<Counters>, ready: Arc<AtomicBool>, stop: Arc<AtomicBool>) {
    let mut ws = connect(port, "10.255.0.1").await.expect("service connects");
    let challenge = loop {
        if let Some(Ok(Message::Text(t))) = ws.next().await {
            let v: Value = serde_json::from_str(&t).unwrap();
            if v[0] == "AUTH" {
                break v[1].as_str().unwrap().to_string();
            }
        }
    };
    let url = RelayUrl::parse(&format!("ws://127.0.0.1:{port}")).unwrap();
    let auth = EventBuilder::auth(challenge, url).sign_with_keys(&keys).unwrap();
    ws.send(text(json!(["AUTH", auth]))).await.unwrap();
    ws.send(text(
        json!(["REQ", "svc", {"#p": [keys.public_key().to_hex()], "kinds": [25910, 1059, 21059]}]),
    ))
    .await
    .unwrap();
    let (mut tx, mut rx) = ws.split();
    // After the run, keep reading until the relay has been quiet for 5 s.
    let mut quiet = 0;
    loop {
        let m = match tokio::time::timeout(Duration::from_secs(1), rx.next()).await {
            Ok(Some(Ok(m))) => m,
            Ok(_) => break,
            Err(_) if stop.load(Relaxed) && quiet >= 4 => break,
            Err(_) => {
                quiet += i32::from(stop.load(Relaxed));
                continue;
            }
        };
        quiet = 0;
        let Message::Text(t) = m else { continue };
        let v: Value = serde_json::from_str(&t).unwrap();
        match v[0].as_str() {
            Some("EOSE") => ready.store(true, Relaxed),
            Some("OK") if v[1] != auth.id.to_hex() => {
                if v[2] == true {
                    c.replies_ok.fetch_add(1, Relaxed);
                }
            }
            Some("EVENT") if v[2]["content"].as_str().is_some_and(|t| t.starts_with("spam")) => {
                c.spam_at_service.fetch_add(1, Relaxed);
            }
            Some("EVENT") => {
                c.at_service.fetch_add(1, Relaxed);
                let req = &v[2];
                let from = PublicKey::from_hex(req["pubkey"].as_str().unwrap()).unwrap();
                let reply = EventBuilder::new(Kind::Custom(25910), req["id"].as_str().unwrap())
                    .tag(Tag::public_key(from))
                    .sign_with_keys(&keys)
                    .unwrap();
                c.replies_sent.fetch_add(1, Relaxed);
                if tx.send(text(json!(["EVENT", reply]))).await.is_err() {
                    break;
                }
            }
            _ => {}
        }
    }
}

/// One client: subscribe to its answers, send `n` requests `every` apart.
async fn client(port: u16, i: usize, service: PublicKey, n: usize, every: Duration, c: Arc<Counters>) {
    let keys = Keys::generate();
    // Signed before the clock starts: signing is the client's cost, not the relay's.
    let reqs: Vec<Event> = (0..n)
        .map(|k| {
            EventBuilder::new(Kind::Custom(25910), format!("{{\"method\":\"tools/call\",\"n\":{k}}}"))
                .tag(Tag::public_key(service))
                .sign_with_keys(&keys)
                .unwrap()
        })
        .collect();
    let ip = format!("10.0.{}.{}", i / 250, i % 250 + 1);
    let Some(ws) = connect(port, &ip).await else { return };
    let (mut tx, mut rx) = ws.split();
    tx.send(text(json!(["REQ", "me", {"#p": [keys.public_key().to_hex()]}])))
        .await
        .unwrap();
    let sent_at: Arc<Mutex<HashMap<String, Instant>>> = Arc::default();
    let reader = {
        let c = c.clone();
        let sent_at = sent_at.clone();
        tokio::spawn(async move {
            let mut answered = 0;
            while let Ok(Some(Ok(m))) = tokio::time::timeout(Duration::from_secs(120), rx.next()).await {
                let Message::Text(t) = m else { continue };
                let v: Value = serde_json::from_str(&t).unwrap();
                match v[0].as_str() {
                    Some("OK") if v[2] == true => drop(c.ok.fetch_add(1, Relaxed)),
                    Some("OK") => {
                        c.refused.fetch_add(1, Relaxed);
                        let why = v[3].as_str().unwrap_or("").split(':').next().unwrap_or("").to_string();
                        *c.refusals.lock().unwrap().entry(why).or_default() += 1;
                    }
                    Some("EVENT") => {
                        let id = v[2]["content"].as_str().unwrap_or("").to_string();
                        if let Some(t0) = sent_at.lock().unwrap().remove(&id) {
                            c.latencies_us.lock().unwrap().push(t0.elapsed().as_micros() as u64);
                            c.answered.fetch_add(1, Relaxed);
                            answered += 1;
                            if answered == n {
                                return;
                            }
                        }
                    }
                    _ => {}
                }
            }
        })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut tick = tokio::time::interval(every);
    for e in reqs {
        tick.tick().await;
        sent_at.lock().unwrap().insert(e.id.to_hex(), Instant::now());
        c.sent.fetch_add(1, Relaxed);
        if tx.send(text(json!(["EVENT", e]))).await.is_err() {
            break;
        }
    }
    let _ = reader.await;
}

/// One attacker: open a connection from its own address and flood it.
async fn attacker(port: u16, i: usize, service: PublicKey, c: Arc<Counters>, stop: Arc<AtomicBool>) {
    let spam_keys = Keys::generate();
    // Valid requests to the service (the costliest thing an outsider can send),
    // duplicates, refused kinds, garbage, unscoped and huge subscriptions.
    // Every tenth valid one is as big as a request may be (30 KB); every
    // fiftieth is over the limit for strangers (40 KB).
    let valid: Vec<String> = (0..400)
        .map(|k| {
            let pad = match k % 50 {
                0 => "z".repeat(40_000),
                n if n % 10 == 0 => "z".repeat(30_000),
                _ => String::new(),
            };
            let e = EventBuilder::new(Kind::Custom(21059), format!("spam {k}{pad}"))
                .tag(Tag::public_key(service))
                .sign_with_keys(&spam_keys)
                .unwrap();
            json!(["EVENT", e]).to_string()
        })
        .collect();
    let note = json!([
        "EVENT",
        EventBuilder::text_note("buy now").sign_with_keys(&spam_keys).unwrap()
    ])
    .to_string();
    let junk = [
        note,
        "[\"EVENT\",{\"id\":\"00\"}]".to_string(),
        "not json at all".to_string(),
        json!(["REQ", "all", {}]).to_string(),
        json!(["REQ", "snoop", {"#p": [service.to_hex()]}]).to_string(),
        // A valid, scoped subscription: makes the relay search its store.
        json!(["REQ", "mine", {"authors": [spam_keys.public_key().to_hex()], "limit": 500}]).to_string(),
        json!(["EVENT", {"x": "y".repeat(60_000)}]).to_string(),
    ];
    let mut k = 0usize;
    while !stop.load(Relaxed) {
        let ip = format!("10.{}.{}.{}", 100 + i % 100, (i / 100) % 250, k % 250 + 1);
        let Some(ws) = connect(port, &ip).await else {
            c.attack_closed.fetch_add(1, Relaxed);
            tokio::time::sleep(Duration::from_millis(20)).await;
            continue;
        };
        let (mut tx, mut rx) = ws.split();
        let c2 = c.clone();
        let reader = tokio::spawn(async move {
            while let Some(Ok(m)) = rx.next().await {
                if let Message::Text(t) = m {
                    if t.starts_with("[\"OK\"") {
                        if t.contains(",true,") {
                            c2.attack_ok.fetch_add(1, Relaxed);
                        } else {
                            c2.attack_refused.fetch_add(1, Relaxed);
                        }
                    }
                }
            }
        });
        // Send until the relay closes the connection, then come back from a new address.
        loop {
            let msg = if k.is_multiple_of(3) {
                junk[k % junk.len()].clone()
            } else {
                valid[k % valid.len()].clone()
            };
            k += 1;
            c.attack_sent.fetch_add(1, Relaxed);
            if stop.load(Relaxed) || tx.send(Message::text(msg)).await.is_err() {
                break;
            }
            if k.is_multiple_of(64) {
                tokio::task::yield_now().await;
            }
        }
        c.attack_closed.fetch_add(1, Relaxed);
        reader.abort();
    }
}

fn rss_kib(pid: u32) -> u64 {
    let out = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().parse().unwrap_or(0)
}

fn pct(v: &[u64], p: f64) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v[((v.len() - 1) as f64 * p).round() as usize] as f64 / 1000.0
}

#[tokio::main]
async fn main() {
    let a: Vec<String> = std::env::args().collect();
    let bin = a.get(1).expect("relay binary").clone();
    let out = a.get(2).expect("output file").clone();
    let clients: usize = a.get(3).map_or(50, |s| s.parse().unwrap());
    let rate: f64 = a.get(4).map_or(5.0, |s| s.parse().unwrap());
    let secs: f64 = a.get(5).map_or(30.0, |s| s.parse().unwrap());
    let attackers: usize = a.get(6).map_or(0, |s| s.parse().unwrap());

    let service = Keys::generate();
    let (port, stats_port) = (free_port(), free_port());
    let mut relay = start_relay(&bin, &service, port, stats_port);
    eprintln!("relay on ws://127.0.0.1:{port}, operator page on http://127.0.0.1:{stats_port}/");
    let pid = relay.id();
    let rss_idle = rss_kib(pid);
    let c = Arc::new(Counters::default());
    let ready = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let svc = tokio::spawn(service_task(
        port,
        service.clone(),
        c.clone(),
        ready.clone(),
        stop.clone(),
    ));
    while !ready.load(Relaxed) {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let attack_stop = Arc::new(AtomicBool::new(false));
    let mut attack = vec![];
    for i in 0..attackers {
        attack.push(tokio::spawn(attacker(
            port,
            i,
            service.public_key(),
            c.clone(),
            attack_stop.clone(),
        )));
    }
    if attackers > 0 {
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    let n = (rate * secs).round() as usize;
    let every = Duration::from_secs_f64(1.0 / rate);
    let started = Instant::now();
    let mut peak_rss = 0;
    let sampler = {
        let stop = stop.clone();
        tokio::spawn(async move {
            let mut peak = 0;
            while !stop.load(Relaxed) {
                peak = peak.max(rss_kib(pid));
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            peak
        })
    };
    let mut legit = vec![];
    for i in 0..clients {
        legit.push(tokio::spawn(client(port, i, service.public_key(), n, every, c.clone())));
    }
    for t in legit {
        let _ = t.await;
    }
    let elapsed = started.elapsed().as_secs_f64();
    attack_stop.store(true, Relaxed);
    for t in attack {
        let _ = t.await;
    }
    stop.store(true, Relaxed);
    peak_rss = peak_rss.max(sampler.await.unwrap());
    let _ = svc.await;
    let stats: Value = reqwest_stats(stats_port).await;
    let _ = relay.kill();
    let _ = relay.wait();

    let mut lat = c.latencies_us.lock().unwrap().clone();
    lat.sort_unstable();
    let ok = c.ok.load(Relaxed);
    let at_service = c.at_service.load(Relaxed);
    let replies_ok = c.replies_ok.load(Relaxed);
    let answered = c.answered.load(Relaxed);
    let result = json!({
        "clients": clients,
        "rate_per_client": rate,
        "seconds": secs,
        "attackers": attackers,
        "elapsed_secs": elapsed,
        "requests_sent": c.sent.load(Relaxed),
        "requests_accepted": ok,
        "requests_refused": c.refused.load(Relaxed),
        "refusals": *c.refusals.lock().unwrap(),
        "requests_at_service": at_service,
        "replies_accepted": replies_ok,
        "replies_at_client": answered,
        "dropped_requests": ok.saturating_sub(at_service.min(ok)),
        "dropped_replies": replies_ok.saturating_sub(answered),
        "throughput_round_trips_per_sec": answered as f64 / elapsed,
        "latency_ms": {"p50": pct(&lat, 0.5), "p90": pct(&lat, 0.9), "p99": pct(&lat, 0.99), "max": pct(&lat, 1.0)},
        "attack": {
            "messages_sent": c.attack_sent.load(Relaxed),
            "events_accepted": c.attack_ok.load(Relaxed),
            "spam_delivered_to_service": c.spam_at_service.load(Relaxed),
            "events_refused": c.attack_refused.load(Relaxed),
            "connections_closed": c.attack_closed.load(Relaxed),
        },
        "relay": {"rss_idle_kib": rss_idle, "rss_peak_kib": peak_rss, "stats": stats},
    });
    std::fs::write(&out, serde_json::to_string_pretty(&result).unwrap()).unwrap();
    println!("{}", serde_json::to_string_pretty(&result).unwrap());
}

async fn service_task(port: u16, keys: Keys, c: Arc<Counters>, ready: Arc<AtomicBool>, stop: Arc<AtomicBool>) {
    service(port, keys, c, ready, stop).await;
}

/// The relay's operator numbers, read over plain HTTP.
async fn reqwest_stats(port: u16) -> Value {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)).await else { return Value::Null };
    let _ = s.write_all(b"GET /stats.json HTTP/1.1\r\nHost: x\r\n\r\n").await;
    let mut buf = String::new();
    let _ = s.read_to_string(&mut buf).await;
    let body = buf.split("\r\n\r\n").nth(1).unwrap_or("null");
    let mut v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    if let Some(o) = v.as_object_mut() {
        o.remove("history");
    }
    v
}
