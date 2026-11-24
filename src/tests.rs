//! End-to-end tests over real sockets: raw WebSocket clients for the edges,
//! nostr-sdk clients for the way deadhop actually talks (it authenticates on
//! its own when challenged).

use std::sync::atomic::Ordering::Relaxed;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use nostr_sdk::prelude::*;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{client_async, WebSocketStream};

use crate::config::tests::config;
use crate::config::ENV_WHITELIST;
use crate::server::{self, Running};
use crate::state::PROBE_CONTENT;

type Raw = WebSocketStream<TcpStream>;

async fn start(service: &Keys, extra: &[(&str, &str)]) -> Running {
    let wl = format!("invoices={}", service.public_key().to_hex());
    let mut pairs = vec![
        (ENV_WHITELIST, wl.as_str()),
        ("DEADHOP_RELAY_LISTEN", "127.0.0.1:0"),
        ("DEADHOP_RELAY_STATS_LISTEN", "127.0.0.1:0"),
    ];
    pairs.extend_from_slice(extra);
    server::start(config(&pairs).unwrap()).await.unwrap()
}

fn url(r: &Running) -> String {
    format!("ws://{}", r.addr)
}

async fn raw(r: &Running) -> Raw {
    raw_with(r, &[]).await
}

async fn raw_with(r: &Running, headers: &[(&'static str, &str)]) -> Raw {
    let mut req = tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(url(r)).unwrap();
    for (k, v) in headers {
        req.headers_mut().insert(*k, v.parse().unwrap());
    }
    let tcp = TcpStream::connect(r.addr).await.unwrap();
    let (mut ws, _) = client_async(req, tcp).await.unwrap();
    let auth = next(&mut ws).await;
    assert_eq!(auth[0], "AUTH");
    ws
}

async fn send(ws: &mut Raw, v: Value) {
    ws.send(Message::text(v.to_string())).await.unwrap();
}

/// The next JSON message, skipping pings.
async fn next(ws: &mut Raw) -> Value {
    loop {
        let m = tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await
            .expect("a message in time");
        match m.expect("open").expect("no error") {
            Message::Text(t) => return serde_json::from_str(&t).unwrap(),
            Message::Ping(_) | Message::Pong(_) => {}
            other => panic!("unexpected {other:?}"),
        }
    }
}

/// Whether the server closes the socket (a close frame or the end) in time.
async fn closes(ws: &mut Raw) -> Option<String> {
    loop {
        match tokio::time::timeout(Duration::from_secs(15), ws.next())
            .await
            .expect("closed in time")
        {
            Some(Ok(Message::Close(f))) => return f.map(|f| f.reason.to_string()),
            Some(Ok(_)) => {}
            None | Some(Err(_)) => return None,
        }
    }
}

fn ev(e: &nostr_sdk::Event) -> Value {
    serde_json::to_value(e).unwrap()
}

fn wrap_to(to: &PublicKey, kind: u16, content: &str) -> nostr_sdk::Event {
    EventBuilder::new(Kind::Custom(kind), content)
        .tag(Tag::public_key(*to))
        .sign_with_keys(&Keys::generate())
        .unwrap()
}

async fn http(addr: std::net::SocketAddr, request: &str) -> String {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(request.as_bytes()).await.unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    out
}

async fn auth(ws: &mut Raw, r: &Running, keys: &Keys, challenge: &str) -> Value {
    let e = EventBuilder::auth(challenge, RelayUrl::parse(&url(r)).unwrap())
        .sign_with_keys(keys)
        .unwrap();
    send(ws, json!(["AUTH", ev(&e)])).await;
    next(ws).await
}

async fn raw_challenge(r: &Running) -> (Raw, String) {
    let tcp = TcpStream::connect(r.addr).await.unwrap();
    let (mut ws, _) = client_async(url(r), tcp).await.unwrap();
    let a = next(&mut ws).await;
    (ws, a[1].as_str().unwrap().to_string())
}

#[tokio::test]
async fn a_contextvm_round_trip_through_nostr_sdk() {
    let service_keys = Keys::generate();
    let client_keys = Keys::generate();
    let r = start(&service_keys, &[]).await;

    // The service: whitelisted, subscribes to its own messages and is
    // challenged on connect, as deadhop is.
    let service = Client::new(service_keys.clone());
    service.add_relay(url(&r)).await.unwrap();
    service.connect().await;
    let filter = Filter::new()
        .kinds([Kind::Custom(25910), Kind::Custom(21059)])
        .pubkey(service_keys.public_key());
    service.subscribe(filter, None).await.unwrap();
    let mut service_notes = service.notifications();

    let client = Client::new(client_keys.clone());
    client.add_relay(url(&r)).await.unwrap();
    client.connect().await;
    client
        .subscribe(Filter::new().pubkey(client_keys.public_key()), None)
        .await
        .unwrap();
    let mut client_notes = client.notifications();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // A request: an ephemeral gift wrap to the service, from a random key.
    let request = wrap_to(&service_keys.public_key(), 21059, "request");
    client.send_event(&request).await.unwrap();
    let got = wait_for(&mut service_notes, request.id).await;
    assert_eq!(got.content, "request");

    // A reply: a gift wrap to the client from a random key. Only allowed
    // because the service's connection authenticated as a whitelisted key.
    let reply = wrap_to(&client_keys.public_key(), 21059, "reply");
    let out = service.send_event(&reply).await.unwrap();
    assert!(!out.success.is_empty(), "{:?}", out.failed);
    assert_eq!(wait_for(&mut client_notes, reply.id).await.content, "reply");

    // The client cannot answer anyone itself.
    let forged = wrap_to(&Keys::generate().public_key(), 21059, "spoof");
    let out = client.send_event(&forged).await.unwrap();
    assert!(out.success.is_empty());

    let s = &r.shared.stats;
    assert_eq!(s.dropped.load(Relaxed), 0);
    assert!(s.auth_ok.load(Relaxed) >= 1);
    assert_eq!(
        s.key(&service_keys.public_key().to_bytes())
            .unwrap()
            .sessions
            .load(Relaxed),
        1
    );
    service.disconnect().await;
    client.disconnect().await;
    r.stop().await;
}

#[tokio::test]
async fn a_public_relay_carries_any_key_without_a_whitelist() {
    let server_keys = Keys::generate();
    let client_keys = Keys::generate();
    let cfg = config(&[
        ("DEADHOP_RELAY_PUBLIC", "on"),
        ("DEADHOP_RELAY_LISTEN", "127.0.0.1:0"),
        ("DEADHOP_RELAY_STATS_LISTEN", "off"),
    ])
    .unwrap();
    let r = server::start(cfg).await.unwrap();

    // Neither side is whitelisted; both still authenticate when challenged.
    let server = Client::new(server_keys.clone());
    server.add_relay(url(&r)).await.unwrap();
    server.connect().await;
    server
        .subscribe(Filter::new().pubkey(server_keys.public_key()), None)
        .await
        .unwrap();
    let mut server_notes = server.notifications();
    let client = Client::new(client_keys.clone());
    client.add_relay(url(&r)).await.unwrap();
    client.connect().await;
    client
        .subscribe(Filter::new().pubkey(client_keys.public_key()), None)
        .await
        .unwrap();
    let mut client_notes = client.notifications();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let request = wrap_to(&server_keys.public_key(), 1059, "request");
    assert!(!client.send_event(&request).await.unwrap().success.is_empty());
    assert_eq!(wait_for(&mut server_notes, request.id).await.content, "request");
    let reply = wrap_to(&client_keys.public_key(), 21059, "reply");
    assert!(!server.send_event(&reply).await.unwrap().success.is_empty());
    assert_eq!(wait_for(&mut client_notes, reply.id).await.content, "reply");

    // The server's announcement, found by its author with no AUTH at all.
    let announce = EventBuilder::new(Kind::Custom(11316), "{}")
        .sign_with_keys(&server_keys)
        .unwrap();
    assert!(!server.send_event(&announce).await.unwrap().success.is_empty());
    let mut ws = raw(&r).await;
    send(
        &mut ws,
        json!(["REQ", "a", {"authors": [server_keys.public_key().to_hex()]}]),
    )
    .await;
    let got = next(&mut ws).await;
    assert_eq!(
        (got[0].as_str(), got[2]["id"].as_str()),
        (Some("EVENT"), Some(announce.id.to_hex().as_str()))
    );
    // So is the request stored for the server: open traffic is readable by anyone.
    send(
        &mut ws,
        json!(["REQ", "b", {"#p": [server_keys.public_key().to_hex()]}]),
    )
    .await;
    let got = loop {
        let m = next(&mut ws).await;
        if m[0] == "EVENT" && m[1] == "b" {
            break m;
        }
    };
    assert_eq!(got[2]["id"], json!(request.id.to_hex()));

    let s = &r.shared.stats;
    assert_eq!(s.events_open.load(Relaxed), 3);
    assert_eq!(s.dropped.load(Relaxed), 0);
    server.disconnect().await;
    client.disconnect().await;
    r.stop().await;
}

#[tokio::test]
async fn a_delivered_ephemeral_reply_is_not_sent_again_after_a_reconnect() {
    let service = Keys::generate();
    let client = Keys::generate();
    let r = start(&service, &[]).await;
    let sub = json!(["REQ", "mine", {"#p": [client.public_key().to_hex()], "since": 0}]);
    let mut first = raw(&r).await;
    send(&mut first, sub.clone()).await;
    assert_eq!(next(&mut first).await[0], "EOSE");
    let delivered = EventBuilder::new(Kind::Custom(21059), "delivered")
        .tag(Tag::public_key(client.public_key()))
        .sign_with_keys(&service)
        .unwrap();
    let mut svc = raw(&r).await;
    send(&mut svc, json!(["EVENT", ev(&delivered)])).await;
    assert_eq!(next(&mut first).await[2]["content"], "delivered");
    assert_eq!(next(&mut svc).await[2], json!(true));
    drop(first);
    // Sent while nobody listens: held for the client's next subscription.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let missed = EventBuilder::new(Kind::Custom(21059), "missed")
        .tag(Tag::public_key(client.public_key()))
        .sign_with_keys(&service)
        .unwrap();
    send(&mut svc, json!(["EVENT", ev(&missed)])).await;
    assert_eq!(next(&mut svc).await[2], json!(true));
    let mut again = raw(&r).await;
    send(&mut again, sub).await;
    assert_eq!(next(&mut again).await[2]["content"], "missed");
    assert_eq!(
        next(&mut again).await[0],
        "EOSE",
        "the delivered reply is not sent again"
    );
    r.stop().await;
}

async fn wait_for(
    notes: &mut tokio::sync::broadcast::Receiver<RelayPoolNotification>,
    id: EventId,
) -> nostr_sdk::Event {
    let fut = async {
        loop {
            if let Ok(RelayPoolNotification::Event { event, .. }) = notes.recv().await {
                if event.id == id {
                    return *event;
                }
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(10), fut)
        .await
        .expect("the event arrives")
}

#[tokio::test]
async fn requests_wait_for_the_service_and_are_held_while_it_is_away() {
    let service = Keys::generate();
    let r = start(&service, &[("DEADHOP_RELAY_PUBLIC_URLS", "wss://relay.example")]).await;

    // A request arrives while the service is not connected: it is held.
    let mut client = raw(&r).await;
    let request = wrap_to(&service.public_key(), 25910, "early");
    send(&mut client, json!(["EVENT", ev(&request)])).await;
    assert_eq!(next(&mut client).await, json!(["OK", request.id.to_hex(), true, ""]));
    assert_eq!(r.shared.stats.held.load(Relaxed), 1);

    // The service subscribes before it authenticates: the subscription waits.
    let (mut svc, challenge) = raw_challenge(&r).await;
    let p = service.public_key().to_hex();
    send(&mut svc, json!(["REQ", "s", {"#p": [p], "since": 0}])).await;
    // AUTH naming the relay by its public URL (or by the Host it dialled).
    let a = EventBuilder::auth(&challenge, RelayUrl::parse("wss://relay.example").unwrap())
        .sign_with_keys(&service)
        .unwrap();
    send(&mut svc, json!(["AUTH", ev(&a)])).await;
    assert_eq!(next(&mut svc).await, json!(["OK", a.id.to_hex(), true, ""]));
    let held = next(&mut svc).await;
    assert_eq!(held[0], "EVENT");
    assert_eq!(held[2]["content"], "early");
    assert_eq!(next(&mut svc).await, json!(["EOSE", "s"]));

    // Live requests now go straight through; a second AUTH changes nothing.
    let live = wrap_to(&service.public_key(), 1059, "live");
    send(&mut client, json!(["EVENT", ev(&live)])).await;
    next(&mut client).await;
    assert_eq!(next(&mut svc).await[2]["content"], "live");
    let again = EventBuilder::auth(&challenge, RelayUrl::parse("wss://relay.example").unwrap())
        .custom_created_at(Timestamp::from(Timestamp::now().as_secs() - 1))
        .sign_with_keys(&service)
        .unwrap();
    send(&mut svc, json!(["AUTH", ev(&again)])).await;
    assert_eq!(next(&mut svc).await[2], true);

    // Duplicates are acknowledged and not sent again.
    send(&mut client, json!(["EVENT", ev(&live)])).await;
    assert_eq!(next(&mut client).await[3], "duplicate: already have this event");

    // A subscription by author finds the service's stored announcement.
    let ann = EventBuilder::new(Kind::Custom(11316), "{}")
        .sign_with_keys(&service)
        .unwrap();
    send(&mut svc, json!(["EVENT", ev(&ann)])).await;
    assert_eq!(next(&mut svc).await[2], true);
    send(&mut client, json!(["REQ", "a", {"authors": [p], "kinds": [11316]}])).await;
    assert_eq!(next(&mut client).await[2]["kind"], 11316);
    assert_eq!(next(&mut client).await, json!(["EOSE", "a"]));
    send(&mut client, json!(["CLOSE", "a"])).await;
    send(&mut client, json!(["PING"])).await;
    assert_eq!(next(&mut client).await[0], "NOTICE", "the CLOSE was handled first");
    assert_eq!(r.shared.hub.len(), 1, "only the service's subscription is left");
    r.stop().await;
    assert_eq!(closes(&mut svc).await.as_deref(), Some("shutting down"));
}

#[tokio::test]
async fn subscriptions_to_a_whitelisted_key_need_its_auth() {
    let service = Keys::generate();
    let r = start(
        &service,
        &[
            ("DEADHOP_RELAY_AUTH_GRACE_SECS", "1"),
            ("DEADHOP_RELAY_MAX_SUBSCRIPTIONS", "2"),
        ],
    )
    .await;
    let (mut spy, challenge) = raw_challenge(&r).await;
    let p = service.public_key().to_hex();
    send(&mut spy, json!(["REQ", "x", {"#p": [p]}])).await;
    // Another key's AUTH is accepted but does not help.
    assert_eq!(auth(&mut spy, &r, &Keys::generate(), &challenge).await[2], true);
    let reply = wrap_to(&Keys::generate().public_key(), 21059, "x");
    send(&mut spy, json!(["EVENT", ev(&reply)])).await;
    assert!(next(&mut spy).await[3].as_str().unwrap().starts_with("restricted:"));
    assert_eq!(
        auth(&mut spy, &r, &service, "wrong").await[3],
        "invalid: AUTH challenge does not match"
    );
    let closed = next(&mut spy).await;
    assert_eq!(closed[0], "CLOSED");
    assert!(closed[2].as_str().unwrap().starts_with("auth-required:"));
    // Two held at once fill the subscription budget; replacing one does not.
    send(&mut spy, json!(["REQ", "y", {"#p": [p]}])).await;
    send(&mut spy, json!(["REQ", "z", {"#p": [p]}])).await;
    send(&mut spy, json!(["REQ", "z", {"#p": [p]}])).await;
    send(&mut spy, json!(["REQ", "w", {"#p": [p]}])).await;
    let full = next(&mut spy).await;
    assert_eq!(full[1], "w");
    assert!(full[2].as_str().unwrap().starts_with("rate-limited:"));
    send(&mut spy, json!(["CLOSE", "y"])).await;
    let late = next(&mut spy).await;
    assert_eq!(late[1], "z");
    r.stop().await;
}

#[tokio::test]
async fn malformed_and_unwanted_messages_get_answers() {
    let service = Keys::generate();
    let r = start(&service, &[("DEADHOP_RELAY_MAX_FILTERS", "1")]).await;
    let mut ws = raw(&r).await;
    let p = service.public_key().to_hex();
    let cases: Vec<(Value, &str)> = vec![
        (json!({"not": "an array"}), "NOTICE"),
        (json!(["PING"]), "NOTICE"),
        (json!(["REQ", 5, {}]), "NOTICE"),
        (json!(["REQ", "", {"#p": [p]}]), "CLOSED"),
        (json!(["REQ", "q"]), "CLOSED"),
        (json!(["REQ", "q", {"#p": [p]}, {"#p": [p]}]), "CLOSED"),
        (json!(["REQ", "q", {"kinds": [1]}]), "CLOSED"),
        (json!(["REQ", "q", {"bogus": 1}]), "CLOSED"),
        (json!(["REQ", "q", "not a filter"]), "CLOSED"),
        (json!(["EVENT", {"id": "ab"}]), "OK"),
        (json!(["EVENT", {"x": 1}]), "NOTICE"),
        (json!(["AUTH", {"x": 1}]), "NOTICE"),
    ];
    for (msg, want) in cases {
        send(&mut ws, msg.clone()).await;
        let got = next(&mut ws).await;
        assert_eq!(got[0], want, "{msg} -> {got}");
    }
    ws.send(Message::Text("not json".into())).await.unwrap();
    assert_eq!(next(&mut ws).await[0], "NOTICE");
    ws.send(Message::binary(vec![1, 2, 3])).await.unwrap();
    assert_eq!(next(&mut ws).await[1], "invalid: binary messages are not supported");
    ws.send(Message::Ping(Default::default())).await.unwrap();
    // A note kind is refused; so is a reply from an unauthenticated stranger.
    let note = EventBuilder::text_note("hi").sign_with_keys(&Keys::generate()).unwrap();
    send(&mut ws, json!(["EVENT", ev(&note)])).await;
    assert!(next(&mut ws).await[3].as_str().unwrap().starts_with("blocked:"));
    // The health check is let through and read by its listener.
    let target = Keys::generate().public_key();
    send(&mut ws, json!(["REQ", "probe", {"#p": [target.to_hex()]}])).await;
    assert_eq!(next(&mut ws).await[0], "EOSE");
    let probe = EventBuilder::new(Kind::Custom(25910), PROBE_CONTENT)
        .tag(Tag::public_key(target))
        .sign_with_keys(&Keys::generate())
        .unwrap();
    send(&mut ws, json!(["EVENT", ev(&probe)])).await;
    let a = next(&mut ws).await;
    let b = next(&mut ws).await;
    let (ok, delivered) = if a[0] == "OK" { (a, b) } else { (b, a) };
    assert_eq!(ok[2], true);
    assert_eq!(delivered[1], "probe");
    // A huge message closes the connection.
    ws.send(Message::text("x".repeat(200 * 1024))).await.unwrap();
    closes(&mut ws).await;
    r.stop().await;
}

#[tokio::test]
async fn floods_are_cut_off() {
    let service = Keys::generate();
    let r = start(&service, &[("DEADHOP_RELAY_MESSAGES_PER_SEC", "1")]).await;
    let mut ws = raw(&r).await;
    let p = service.public_key().to_hex();
    let e = wrap_to(&service.public_key(), 1059, "flood");
    let mut limited = 0;
    for i in 0..60 {
        if i % 2 == 0 {
            send(&mut ws, json!(["EVENT", ev(&e)])).await;
        } else {
            send(&mut ws, json!(["REQ", format!("s{i}"), {"#p": [p]}])).await;
        }
    }
    loop {
        match tokio::time::timeout(Duration::from_secs(10), ws.next()).await.unwrap() {
            Some(Ok(Message::Text(t))) => {
                if t.contains("rate-limited") {
                    limited += 1;
                }
            }
            Some(Ok(_)) => {}
            _ => break,
        }
    }
    assert!(limited > MAX_LIMITED, "{limited}");
    r.stop().await;
}
const MAX_LIMITED: usize = crate::session::MAX_STRIKES as usize - 10;

#[tokio::test]
async fn public_writers_have_a_budget_per_address() {
    let service = Keys::generate();
    let r = start(&service, &[("DEADHOP_RELAY_PUBLIC_EVENTS_PER_MIN", "1")]).await;
    let mut ws = raw(&r).await;
    for (i, want) in [(0, true), (1, false)] {
        let e = wrap_to(&service.public_key(), 1059, &format!("r{i}"));
        send(&mut ws, json!(["EVENT", ev(&e)])).await;
        assert_eq!(next(&mut ws).await[2], want);
    }
    r.stop().await;
}

#[tokio::test]
async fn over_the_limits_only_whitelisted_keys_stay() {
    let service = Keys::generate();
    let r = start(
        &service,
        &[
            ("DEADHOP_RELAY_CONNECTIONS_PER_IP", "1"),
            ("DEADHOP_RELAY_RESERVED_CONNECTIONS", "2"),
            ("DEADHOP_RELAY_AUTH_GRACE_SECS", "1"),
        ],
    )
    .await;
    let _first = raw(&r).await;
    // The second connection from this address is on probation.
    let (mut second, challenge) = raw_challenge(&r).await;
    let e = wrap_to(&service.public_key(), 1059, "x");
    send(&mut second, json!(["EVENT", ev(&e)])).await;
    assert!(next(&mut second).await[3]
        .as_str()
        .unwrap()
        .starts_with("auth-required:"));
    send(
        &mut second,
        json!(["REQ", "s", {"#p": [Keys::generate().public_key().to_hex()]}]),
    )
    .await;
    // The subscription is held; authenticating as the service ends probation and starts it.
    assert_eq!(auth(&mut second, &r, &service, &challenge).await[2], true);
    assert_eq!(next(&mut second).await, json!(["EOSE", "s"]));
    assert_eq!(r.shared.probation.load(Relaxed), 0);
    // A third that never authenticates is closed after the grace period.
    let mut third = raw(&r).await;
    assert!(next(&mut third).await[1].as_str().unwrap().starts_with("restricted:"));
    assert_eq!(closes(&mut third).await.as_deref(), Some("full"));
    assert_eq!(r.shared.stats.probation_closed.load(Relaxed), 1);
    r.stop().await;

    // With no reserved room, the door stays shut.
    let r = start(
        &service,
        &[
            ("DEADHOP_RELAY_MAX_CONNECTIONS", "1"),
            ("DEADHOP_RELAY_RESERVED_CONNECTIONS", "0"),
        ],
    )
    .await;
    let _first = raw(&r).await;
    let tcp = TcpStream::connect(r.addr).await.unwrap();
    let err = client_async(url(&r), tcp).await.unwrap_err().to_string();
    assert!(err.contains("503"), "{err}");
    // A request head that never comes counts against the handshake budget.
    let r2 = start(
        &service,
        &[
            ("DEADHOP_RELAY_MAX_CONNECTIONS", "1"),
            ("DEADHOP_RELAY_RESERVED_CONNECTIONS", "0"),
            ("DEADHOP_RELAY_HANDSHAKE_SECS", "1"),
        ],
    )
    .await;
    let mut silent = TcpStream::connect(r2.addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut turned_away = TcpStream::connect(r2.addr).await.unwrap();
    let mut buf = vec![];
    assert_eq!(turned_away.read_to_end(&mut buf).await.unwrap_or(0), 0);
    let mut answer = String::new();
    silent.read_to_string(&mut answer).await.unwrap();
    assert!(answer.starts_with("HTTP/1.1 400"), "{answer}");
    assert_eq!(r2.shared.stats.connections_refused.load(Relaxed), 2);
    r.stop().await;
    r2.stop().await;
}

#[tokio::test]
async fn a_reader_that_stops_reading_is_cut_off_alone() {
    let service = Keys::generate();
    let r = start(&service, &[("DEADHOP_RELAY_QUEUE_BYTES", "65536")]).await;
    let mut svc = raw(&r).await;
    let mut slow = raw(&r).await;
    let p = service.public_key().to_hex();
    send(&mut slow, json!(["REQ", "s", {"authors": [p]}])).await;
    assert_eq!(next(&mut slow).await[0], "EOSE");
    let big = "y".repeat(100 * 1024);
    let client = Keys::generate().public_key();
    for i in 0..120 {
        let e = EventBuilder::new(Kind::Custom(25910), format!("{i}{big}"))
            .tag(Tag::public_key(client))
            .sign_with_keys(&service)
            .unwrap();
        send(&mut svc, json!(["EVENT", ev(&e)])).await;
        next(&mut svc).await;
        if r.shared.stats.slow_closed.load(Relaxed) > 0 {
            break;
        }
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(r.shared.stats.slow_closed.load(Relaxed), 1);
    assert!(r.shared.stats.dropped.load(Relaxed) >= 1);
    r.stop().await;
}

#[tokio::test]
async fn silent_peers_are_pinged_then_closed() {
    let service = Keys::generate();
    let r = start(&service, &[("DEADHOP_RELAY_IDLE_SECS", "2")]).await;
    // Upgrade by hand and then never answer anything, pings included.
    let mut s = TcpStream::connect(r.addr).await.unwrap();
    let up = "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
    s.write_all(up.as_bytes()).await.unwrap();
    let mut got = vec![];
    tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut got))
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&got);
    assert!(text.starts_with("HTTP/1.1 101"));
    assert!(got.contains(&0x89), "a ping was sent");
    assert!(text.ends_with("idle"), "{text}");
    r.stop().await;
}

#[tokio::test]
async fn pages_on_both_listeners() {
    let service = Keys::generate();
    let r = start(&service, &[("DEADHOP_RELAY_TRUSTED_PROXIES", "127.0.0.1")]).await;
    let page = http(r.addr, "GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert!(page.starts_with("HTTP/1.1 200") && page.contains("<h1>deadhop relay</h1>"));
    let info = http(r.addr, "GET / HTTP/1.1\r\nAccept: application/nostr+json\r\n\r\n").await;
    assert!(info.contains("\"supported_nips\""));
    let head = http(r.addr, "HEAD / HTTP/1.1\r\n\r\n").await;
    assert!(head.starts_with("HTTP/1.1 200") && !head.contains("<h1>"));
    let op = http(r.stats_addr.unwrap(), "GET / HTTP/1.1\r\n\r\n").await;
    assert!(op.contains("Operator view"));
    // The operator listener does not upgrade.
    let up = "GET / HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
    assert!(http(r.stats_addr.unwrap(), up).await.starts_with("HTTP/1.1 200"));
    assert!(http(r.addr, "\x01\x02 nonsense\r\n\r\n")
        .await
        .starts_with("HTTP/1.1 400"));
    // Behind a trusted proxy, limits apply to the forwarded address.
    let _ws = raw_with(&r, &[("X-Forwarded-For", "203.0.113.9")]).await;
    assert_eq!(r.shared.origins.lock().unwrap().len(), 1);
    let stop = tokio::sync::watch::channel(false).1;
    server::accepted(&r.shared, Err(std::io::Error::other("test")), false, &stop).await;
    r.stop().await;
}

#[tokio::test]
async fn binding_a_busy_port_fails() {
    let service = Keys::generate();
    let r = start(&service, &[]).await;
    let busy = r.addr.to_string();
    let wl = service.public_key().to_hex();
    let cfg = config(&[
        (ENV_WHITELIST, &wl),
        ("DEADHOP_RELAY_LISTEN", &busy),
        ("DEADHOP_RELAY_STATS_LISTEN", "off"),
    ])
    .unwrap();
    assert!(server::start(cfg).await.is_err());
    let cfg = config(&[
        (ENV_WHITELIST, &wl),
        ("DEADHOP_RELAY_LISTEN", "127.0.0.1:0"),
        ("DEADHOP_RELAY_STATS_LISTEN", &busy),
    ])
    .unwrap();
    assert!(server::start(cfg.clone()).await.is_err());
    let off = config(&[
        (ENV_WHITELIST, &wl),
        ("DEADHOP_RELAY_LISTEN", "127.0.0.1:0"),
        ("DEADHOP_RELAY_STATS_LISTEN", "off"),
    ]);
    let quiet = server::start(off.unwrap()).await.unwrap();
    assert!(quiet.stats_addr.is_none());
    quiet.stop().await;
    assert_eq!(
        crate::serve(config(&[(ENV_WHITELIST, &wl), ("DEADHOP_RELAY_LISTEN", &busy)]).unwrap()).await,
        1
    );
    r.stop().await;
}

#[test]
fn the_command_line() {
    let args = |a: &[&str]| -> Vec<String> { a.iter().map(|s| s.to_string()).collect() };
    let none = |_: &str| None;
    assert_eq!(crate::cli(&args(&["r", "version"]), &none), 0);
    assert_eq!(crate::cli(&args(&["r", "--help"]), &none), 0);
    assert_eq!(crate::cli(&args(&["r", "frobnicate"]), &none), 2);
    assert_eq!(crate::cli(&args(&["r"]), &none), 2, "no whitelist");
    let wl = |k: &str| (k == ENV_WHITELIST).then(|| Keys::generate().public_key().to_hex());
    assert_eq!(crate::cli(&args(&["r", "check"]), &wl), 0);
    let c = config(&[
        (ENV_WHITELIST, &Keys::generate().public_key().to_hex()),
        ("DEADHOP_RELAY_STATS_LISTEN", "off"),
    ])
    .unwrap();
    assert!(crate::summary(&c).contains("operator page off"));
}

#[tokio::test]
async fn the_service_gets_in_through_probation_with_nostr_sdk() {
    let service_keys = Keys::generate();
    let client_keys = Keys::generate();
    let r = start(
        &service_keys,
        &[
            ("DEADHOP_RELAY_MAX_CONNECTIONS", "2"),
            ("DEADHOP_RELAY_RESERVED_CONNECTIONS", "4"),
        ],
    )
    .await;
    // The relay is full of strangers.
    let mut filler = raw(&r).await;
    let mut filler2 = raw(&r).await;

    // deadhop arrives over the limit: on probation, it subscribes, is challenged,
    // authenticates, and its held subscription starts.
    let service = Client::new(service_keys.clone());
    service.add_relay(url(&r)).await.unwrap();
    service.connect().await;
    service
        .subscribe(Filter::new().pubkey(service_keys.public_key()), None)
        .await
        .unwrap();
    let mut notes = service.notifications();
    for _ in 0..50 {
        if r.shared.stats.auth_ok.load(Relaxed) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(r.shared.probation.load(Relaxed), 0, "probation ended by AUTH");

    // The strangers leave; a customer gets a free slot and reaches the service.
    filler.close(None).await.unwrap();
    filler2.close(None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let client = Client::new(client_keys);
    client.add_relay(url(&r)).await.unwrap();
    client.connect().await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let request = wrap_to(&service_keys.public_key(), 21059, "through probation");
    assert!(!client.send_event(&request).await.unwrap().success.is_empty());
    assert_eq!(wait_for(&mut notes, request.id).await.content, "through probation");
    service.disconnect().await;
    client.disconnect().await;
    r.stop().await;
}

#[tokio::test]
async fn auth_must_name_a_public_url_when_there_are_some() {
    let service = Keys::generate();
    let r = start(&service, &[("DEADHOP_RELAY_PUBLIC_URLS", "wss://relay.example")]).await;
    let (mut ws, challenge) = raw_challenge(&r).await;
    // Naming the host it dialled (or any Host a forwarding relay chose) is refused.
    let got = auth(&mut ws, &r, &service, &challenge).await;
    assert_eq!(got[2], false);
    assert!(got[3].as_str().unwrap().contains("another relay"));
    r.stop().await;
}

#[tokio::test]
async fn one_address_cannot_take_every_probation_slot() {
    let service = Keys::generate();
    let r = start(
        &service,
        &[
            ("DEADHOP_RELAY_MAX_CONNECTIONS", "1"),
            ("DEADHOP_RELAY_RESERVED_CONNECTIONS", "8"),
            ("DEADHOP_RELAY_TRUSTED_PROXIES", "127.0.0.1"),
        ],
    )
    .await;
    let _filler = raw_with(&r, &[("X-Forwarded-For", "10.9.9.9")]).await;
    // One address gets two probation slots, then 503.
    let _a = raw_with(&r, &[("X-Forwarded-For", "10.1.1.1")]).await;
    let _b = raw_with(&r, &[("X-Forwarded-For", "10.1.1.1")]).await;
    let mut req = tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(url(&r)).unwrap();
    req.headers_mut().insert("X-Forwarded-For", "10.1.1.1".parse().unwrap());
    let err = client_async(req, TcpStream::connect(r.addr).await.unwrap())
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("503"), "{err}");
    // The service, from another address, still gets in and authenticates.
    let mut svc = raw_with(&r, &[("X-Forwarded-For", "10.2.2.2")]).await;
    send(&mut svc, json!(["REQ", "s", {"#p": [service.public_key().to_hex()]}])).await;
    assert_eq!(r.shared.probation.load(Relaxed), 3);
    drop(svc);
    r.stop().await;
}

#[tokio::test]
async fn a_reconnecting_service_gets_what_arrived_while_it_was_away() {
    let service_keys = Keys::generate();
    let r = start(&service_keys, &[]).await;
    let service = Client::new(service_keys.clone());
    service.add_relay(url(&r)).await.unwrap();
    service.connect().await;
    let filter = Filter::new()
        .kinds([Kind::Custom(25910), Kind::Custom(21059)])
        .pubkey(service_keys.public_key())
        .since(Timestamp::now());
    service.subscribe(filter, None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    service.disconnect().await;
    // nostr-sdk resubscribes only when the new connection is in a later
    // second than the subscription (whole-second timestamps).
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(
        r.shared
            .stats
            .key(&service_keys.public_key().to_bytes())
            .unwrap()
            .sessions
            .load(Relaxed),
        0
    );

    // While it is away, a customer sends a request (ephemeral: only held).
    let mut client = raw(&r).await;
    let request = wrap_to(&service_keys.public_key(), 21059, "while away");
    send(&mut client, json!(["EVENT", ev(&request)])).await;
    assert_eq!(next(&mut client).await[2], true);

    // nostr-sdk reconnects, authenticates and resubscribes on its own.
    let mut notes = service.notifications();
    service.connect().await;
    assert_eq!(wait_for(&mut notes, request.id).await.content, "while away");
    service.disconnect().await;
    r.stop().await;
}
