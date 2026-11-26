//! The web interface: NIP-11 relay information, a public status page, and an
//! operator page on its own (loopback) listener. Pages are rendered here and
//! use no JavaScript, under a strict Content-Security-Policy; they refresh
//! themselves every 15 seconds.

use std::fmt::Write as _;
use std::sync::atomic::Ordering::Relaxed;

use serde_json::{json, Value};

use crate::config::npub;
use crate::http::{Request, Response};
use crate::limits::unix_now;
use crate::networks::{NetStats, Network};
use crate::state::{lock, Shared};
use crate::stats::{Minute, REASONS};

const CSS: &str = include_str!("../assets/relay.css");
const MARK: &str = include_str!("../assets/brand/logo/mark-currentcolor.svg");
const FAVICON: &str = include_str!("../assets/brand/icons/favicon.svg");
const FONTS: [(&str, &[u8]); 3] = [
    ("geist.woff2", include_bytes!("../assets/brand/fonts/geist.woff2")),
    (
        "martian-mono.woff2",
        include_bytes!("../assets/brand/fonts/martian-mono.woff2"),
    ),
    (
        "schibsted-grotesk.woff2",
        include_bytes!("../assets/brand/fonts/schibsted-grotesk.woff2"),
    ),
];
const CSP: &str = "default-src 'none'; style-src 'self'; font-src 'self'; img-src 'self'; base-uri 'none'; \
                   form-action 'none'; frame-ancestors 'none'";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// The NIPs this relay implements.
pub const NIPS: [u16; 5] = [1, 11, 13, 42, 59];

/// Escape text for HTML.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// `12345` as `12,345`.
pub fn num(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// A count for a tile: exact below a million, then `10.5M`.
pub fn short(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1e6)
    } else {
        num(n)
    }
}

/// A duration as `3d 4h`, `4h 5m` or `5m 6s`.
pub fn uptime(secs: u64) -> String {
    let (d, h, m, s) = (secs / 86_400, secs / 3600 % 24, secs / 60 % 60, secs % 60);
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{m}m {s}s")
    }
}

/// NIP-11 relay information.
pub fn info(sh: &Shared) -> Value {
    let lim = &sh.cfg.limits;
    json!({
        "name": sh.cfg.name,
        "description": sh.cfg.description,
        "software": "https://github.com/deadhop/relay",
        "version": VERSION,
        "supported_nips": NIPS,
        "limitation": {
            "max_message_length": lim.max_message_bytes,
            "max_subscriptions": lim.max_subscriptions,
            "max_filters": lim.max_filters,
            "max_limit": lim.max_limit,
            "max_subid_length": 64,
            "min_pow_difficulty": lim.min_pow,
            "auth_required": false,
            "payment_required": false,
            "restricted_writes": true,
        },
        "retention": [
            {"kinds": [1059], "time": lim.store_ttl_secs},
            {"kinds": [25910, 21059], "time": lim.hold_secs},
        ],
    })
}

/// The numbers both status pages show, as JSON. `operator` adds the
/// whitelist, refusal reasons and the limits.
pub fn stats(sh: &Shared, operator: bool) -> Value {
    let s = &sh.stats;
    let now = unix_now();
    let mut v = json!({
        "name": sh.cfg.name,
        "version": VERSION,
        "uptime_secs": now.saturating_sub(sh.started_unix),
        "whitelisted_keys": sh.cfg.whitelist.len(),
        "public": sh.cfg.public,
        "connections": s.connections_open.load(Relaxed),
        "subscriptions": sh.hub.len(),
        "events": s.events_total(),
        "deliveries": s.deliveries.load(Relaxed),
        "dropped": s.dropped.load(Relaxed),
        "refused": s.refused_total(),
        "history": s.history(now / 60),
    });
    if operator {
        let keys: Vec<Value> = sh
            .cfg
            .whitelist
            .entries()
            .iter()
            .map(|(k, label)| {
                let c = s.key(k).expect("whitelisted keys have counters");
                json!({
                    "label": label,
                    "npub": npub(k),
                    "sessions": c.sessions.load(Relaxed),
                    "inbound": c.inbound.load(Relaxed),
                    "outbound": c.outbound.load(Relaxed),
                })
            })
            .collect();
        let refusals: serde_json::Map<String, Value> = REASONS
            .iter()
            .map(|r| (r.prefix().to_string(), json!(s.refused(*r))))
            .collect();
        let extra = json!({
            "keys": keys,
            "refusals": refusals,
            "events_by_writer": {
                "whitelisted": s.events_trusted.load(Relaxed),
                "public": s.events_public.load(Relaxed),
                "health_checks": s.events_probe.load(Relaxed),
                "open": s.events_open.load(Relaxed),
            },
            "held": s.held.load(Relaxed),
            "stored": lock(&sh.store).len(),
            "addresses_tracked": lock(&sh.origins).len(),
            "probation": sh.probation.load(Relaxed),
            "connections_total": s.connections_total.load(Relaxed),
            "connections_refused": s.connections_refused.load(Relaxed),
            "probation_closed": s.probation_closed.load(Relaxed),
            "slow_closed": s.slow_closed.load(Relaxed),
            "auth_ok": s.auth_ok.load(Relaxed),
            "auth_failed": s.auth_failed.load(Relaxed),
            "auth_other": s.auth_other.load(Relaxed),
            "bytes_in": s.bytes_in.load(Relaxed),
            "bytes_out": s.bytes_out.load(Relaxed),
            "limits": limits(sh),
        });
        v.as_object_mut()
            .expect("an object")
            .extend(extra.as_object().expect("an object").clone());
        if sh.has_overlays() {
            let nets: Vec<Value> = sh.nets.iter().map(|n| network(sh, n, now)).collect();
            v["networks"] = json!(nets);
        }
    }
    v
}

/// One network's numbers, for the operator: the overview's card and the
/// network's own page.
pub fn network(sh: &Shared, n: &NetStats, now: u64) -> Value {
    let net = n.network;
    let (listen, urls, cap) = match sh.cfg.adapter(net) {
        Some(a) => (Some(a.listen), a.urls.clone(), Some(a.max_connections)),
        None => (sh.cfg.listen, sh.cfg.public_urls.clone(), None),
    };
    let history = n.history(now / 60);
    let sessions: Vec<Value> = n
        .sessions()
        .into_iter()
        .map(|(k, c)| json!({"label": sh.cfg.whitelist.label(&k), "npub": npub(&k), "sessions": c}))
        .collect();
    let refusals: serde_json::Map<String, Value> = REASONS
        .iter()
        .map(|r| (r.prefix().to_string(), json!(n.refused(*r))))
        .collect();
    json!({
        "id": net.id(),
        "label": net.label(),
        "listen": listen.map(|a| a.to_string()),
        "urls": urls,
        "identity": net.identity(),
        "daemons": sh
            .cfg
            .adapter(net)
            .filter(|a| !a.daemons.is_empty())
            .map(|a| a.daemons.iter().map(ToString::to_string).collect::<Vec<_>>()),
        "connections": n.open.load(Relaxed),
        "max_connections": cap,
        "clients": lock(&sh.origins).connected(net),
        "services": n.sessions().iter().filter(|(_, c)| *c > 0).count(),
        "connections_total": n.total.load(Relaxed),
        "turned_away": n.turned_away.load(Relaxed),
        "events": n.accepted.load(Relaxed),
        "refused": n.refused_total(),
        "events_last_hour": history.iter().map(|m| m.accepted).sum::<u64>(),
        "refused_last_hour": history.iter().map(|m| m.refused).sum::<u64>(),
        "bytes_in": n.bytes_in.load(Relaxed),
        "bytes_out": n.bytes_out.load(Relaxed),
        "refusals": refusals,
        "sessions": sessions,
        "history": history,
    })
}

fn limits(sh: &Shared) -> Value {
    let l = &sh.cfg.limits;
    json!({
        "max_connections": l.max_connections,
        "reserved_connections": l.reserved_connections,
        "connections_per_ip": l.connections_per_ip,
        "max_subscriptions": l.max_subscriptions,
        "max_filters": l.max_filters,
        "max_message_bytes": l.max_message_bytes,
        "public_max_event_bytes": l.public_max_event_bytes,
        "max_limit": l.max_limit,
        "max_event_age_secs": l.max_event_age_secs,
        "handshake_secs": l.handshake_secs,
        "store_max_events": l.store_max_events,
        "public_store_max_events": l.public_store_max_events,
        "open_max_event_bytes": l.open_max_event_bytes,
        "open_store_max_events": l.open_store_max_events,
        "messages_per_sec": l.messages_per_sec,
        "public_events_per_min": l.public_events_per_min,
        "probes_per_min": l.probes_per_min,
        "min_pow": l.min_pow,
        "store_ttl_secs": l.store_ttl_secs,
        "hold_secs": l.hold_secs,
        "idle_secs": l.idle_secs,
        "auth_grace_secs": l.auth_grace_secs,
        "queue_bytes": l.queue_bytes,
        "trusted_queue_bytes": l.trusted_queue_bytes,
        "allow_health_check": sh.cfg.allow_probe,
        "trusted_proxies": sh.cfg.trusted_proxies.len(),
    })
}

/// The last hour as bars: accepted events up, refusals down.
pub fn chart(history: &[Minute]) -> String {
    let max = history
        .iter()
        .map(|m| m.accepted.max(m.refused))
        .max()
        .unwrap_or(0)
        .max(1) as f64;
    let w = 600.0 / history.len().max(1) as f64;
    let mut svg = String::from(
        "<svg class=\"chart\" viewBox=\"0 0 600 120\" preserveAspectRatio=\"none\" role=\"img\" \
         aria-label=\"Events accepted and refused per minute, last hour\"><line class=\"axis\" x1=\"0\" y1=\"80\" x2=\"600\" y2=\"80\"/>",
    );
    for (i, m) in history.iter().enumerate() {
        let x = i as f64 * w + 1.0;
        let up = (m.accepted as f64 / max * 76.0).round();
        let down = (m.refused as f64 / max * 36.0).round();
        if up > 0.0 {
            let _ = write!(
                svg,
                "<rect class=\"a\" x=\"{x:.1}\" y=\"{:.0}\" width=\"{:.1}\" height=\"{up:.0}\"/>",
                80.0 - up,
                w - 2.0
            );
        }
        if down > 0.0 {
            let _ = write!(
                svg,
                "<rect class=\"r\" x=\"{x:.1}\" y=\"81\" width=\"{:.1}\" height=\"{down:.0}\"/>",
                w - 2.0
            );
        }
    }
    svg.push_str("</svg>");
    svg
}

/// The last hour's accepted events as a strip of bars, for a network's card.
pub fn spark(history: &[Minute]) -> String {
    let max = history.iter().map(|m| m.accepted).max().unwrap_or(0).max(1) as f64;
    let mut svg = String::from(
        "<svg class=\"spark\" viewBox=\"0 0 120 22\" preserveAspectRatio=\"none\" role=\"img\" \
         aria-label=\"Events accepted per minute, last hour\">",
    );
    for (i, m) in history.iter().enumerate() {
        let h = m.accepted as f64 / max * 20.0;
        if m.accepted > 0 {
            let _ = write!(
                svg,
                "<rect x=\"{}\" y=\"{:.1}\" width=\"1.4\" height=\"{h:.1}\"/>",
                i * 2,
                22.0 - h
            );
        }
    }
    svg.push_str("</svg>");
    svg
}

/// Bytes as `812 B`, `4.2 KiB`, `38.1 MiB` or `2.0 GiB`.
pub fn size(n: u64) -> String {
    let units = ["KiB", "MiB", "GiB", "TiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64 / 1024.0;
    let mut u = 0;
    while v >= 1024.0 && u < units.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    format!("{v:.1} {}", units[u])
}

fn layout(sh: &Shared, title: &str, tag: &str, body: &str) -> String {
    layout_nav(sh, title, tag, "", body)
}

/// The operator pages' links between networks, when there is more than one.
fn nav(sh: &Shared, on: Option<Network>) -> String {
    if !sh.has_overlays() {
        return String::new();
    }
    let link = |href: String, label: &str, here: bool| {
        format!(
            "<a href=\"{href}\"{}>{label}</a>",
            if here { " class=\"on\"" } else { "" }
        )
    };
    let mut out = String::from("<nav>");
    out += &link("/".into(), "Overview", on.is_none());
    for n in &sh.nets {
        out += &link(
            format!("/networks/{}", n.network.id()),
            n.network.label(),
            on == Some(n.network),
        );
    }
    out + "</nav>"
}

fn layout_nav(sh: &Shared, title: &str, tag: &str, nav: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<meta http-equiv=\"refresh\" content=\"15\"><meta name=\"referrer\" content=\"no-referrer\"><title>{t} · deadhop relay</title>\
<link rel=\"icon\" href=\"/assets/favicon.svg\" type=\"image/svg+xml\"><link rel=\"stylesheet\" href=\"/assets/relay.css\"></head>\
<body><header class=\"top\"><span class=\"mark\">{MARK}</span><span class=\"word\">deadhop</span><span class=\"tag\">{tag}</span>{nav}</header>\
<main>{body}<footer>deadhop relay {VERSION} · {name} · this page refreshes every 15 seconds</footer></main></body></html>",
        t = esc(title),
        name = esc(&sh.cfg.name),
    )
}

fn tile(label: &str, value: &str, class: &str) -> String {
    format!(
        "<div class=\"tile\"><div class=\"lbl\">{label}</div><div class=\"v {class}\">{}</div></div>",
        esc(value)
    )
}

fn tiles(v: &Value) -> String {
    let n = |k: &str| v[k].as_u64().expect("a counter");
    let dropped = n("dropped");
    format!(
        "<div class=\"tiles\">{}{}{}{}{}{}</div>",
        tile("Uptime", &uptime(n("uptime_secs")), ""),
        tile("Connections", &short(n("connections")), ""),
        tile("Events relayed", &short(n("events")), ""),
        tile("Deliveries", &short(n("deliveries")), ""),
        tile("Dropped", &short(dropped), if dropped == 0 { "ok" } else { "bad" }),
        tile("Refused", &short(n("refused")), ""),
    )
}

fn history(sh: &Shared) -> String {
    format!(
        "<h2>Last hour</h2><div class=\"card\">{}<div class=\"legend lbl\"><span><span class=\"sw a\"></span>accepted per minute</span>\
<span><span class=\"sw r\"></span>refused per minute</span></div></div>",
        chart(&sh.stats.history(unix_now() / 60))
    )
}

/// The public status page.
pub fn status_page(sh: &Shared) -> String {
    let v = stats(sh, false);
    let urls: String = sh
        .cfg
        .public_urls
        .iter()
        .map(|u| format!("<code>{}</code>", esc(u)))
        .collect();
    let urls = if sh.has_overlays() {
        addresses(sh)
    } else if urls.is_empty() {
        String::new()
    } else {
        format!("<div class=\"urls\">{urls}</div>")
    };
    let body = format!(
        "<h1>{name}</h1><p class=\"lead\">{desc}</p>{urls}{tiles}{history}\
<h2>What this relay carries</h2><div class=\"card\"><p>{carries}</p>\
<p class=\"muted\">Nothing is written to disk. Gift wraps are kept in memory for {ttl}; other messages nobody was \
listening for are held for {hold} seconds. Relay information (NIP-11): request this page with \
<code>Accept: application/nostr+json</code>.</p></div>",
        name = esc(&sh.cfg.name),
        desc = esc(&sh.cfg.description),
        tiles = tiles(&v),
        history = history(sh),
        carries = carries(sh),
        ttl = uptime(sh.cfg.limits.store_ttl_secs),
        hold = sh.cfg.limits.hold_secs,
    );
    layout(sh, &sh.cfg.name, "relay", &body)
}

/// Every network's addresses, one row each, for a relay on more than clearnet.
fn addresses(sh: &Shared) -> String {
    let mut rows = String::new();
    for n in sh.cfg.networks() {
        let urls = match sh.cfg.adapter(n) {
            Some(a) => &a.urls,
            None => &sh.cfg.public_urls,
        };
        if urls.is_empty() {
            continue;
        }
        let codes: String = urls.iter().map(|u| format!("<code>{}</code>", esc(u))).collect();
        let _ = write!(
            rows,
            "<tr><td class=\"key lbl\">{}</td><td>{codes}</td></tr>",
            n.label()
        );
    }
    format!("<table class=\"addrs\"><tbody>{rows}</tbody></table>")
}

/// The overview's cards: one per network, each a link to the network's page.
fn network_cards(v: &Value) -> String {
    let Some(nets) = v["networks"].as_array() else {
        return String::new();
    };
    let mut cards = String::new();
    for n in nets {
        let cap = n["max_connections"]
            .as_u64()
            .map_or(String::new(), |c| format!("<span class=\"of\"> / {}</span>", num(c)));
        let history: Vec<Minute> = serde_json::from_value(n["history"].clone()).expect("minutes");
        let _ = write!(
            cards,
            "<a class=\"netcard\" href=\"/networks/{id}\"><div class=\"lbl\"><span class=\"dot {dot}\"></span>{label}</div>\
<div class=\"v\">{conns}{cap}</div>{spark}<div class=\"lbl\">{events} events · {refused} refused</div></a>",
            id = n["id"].as_str().expect("an id"),
            dot = if n["connections"].as_u64() > Some(0) { "ok" } else { "wait" },
            label = esc(n["label"].as_str().expect("a label")),
            conns = num(n["connections"].as_u64().expect("a counter")),
            spark = spark(&history),
            events = num(n["events_last_hour"].as_u64().expect("a counter")),
            refused = num(n["refused_last_hour"].as_u64().expect("a counter")),
        );
    }
    format!(
        "<h2>Networks</h2><p class=\"muted sub\">Open connections, and events in the last hour. Open a network for its own numbers.</p>\
<div class=\"netcards\">{cards}</div>"
    )
}

/// A network's own page: only what arrived over it.
pub fn network_page(sh: &Shared, net: Network) -> Option<String> {
    let n = sh.net(net).filter(|_| sh.has_overlays())?;
    let v = network(sh, n, unix_now());
    let u = |k: &str| v[k].as_u64().expect("a counter");
    let conns = match v["max_connections"].as_u64() {
        Some(c) => format!("{}<span class=\"of\"> / {}</span>", num(u("connections")), num(c)),
        None => num(u("connections")),
    };
    let tiles = format!(
        "<div class=\"tiles\"><div class=\"tile\"><div class=\"lbl\">Connections</div><div class=\"v\">{conns}</div></div>{}{}{}{}{}</div>",
        tile("Clients now", &num(u("clients")), ""),
        tile("Services", &num(u("services")), ""),
        tile("Events · hour", &short(u("events_last_hour")), ""),
        tile("Refused · hour", &short(u("refused_last_hour")), ""),
        tile("Turned away", &short(u("turned_away")), ""),
    );
    let urls: String = v["urls"]
        .as_array()
        .expect("a list")
        .iter()
        .map(|x| format!("<code>{}</code>", esc(x.as_str().expect("a url"))))
        .collect();
    let row = |k: &str, val: String| format!("<tr><td>{k}</td><td>{val}</td></tr>");
    let mono = |s: String| format!("<span class=\"mono\">{}</span>", esc(&s));
    let mut how = row(
        "Listening on",
        mono(v["listen"].as_str().expect("an address").to_string()),
    );
    how += &row("Clients told apart", esc(net.identity()));
    if let Some(d) = v["daemons"].as_array() {
        let d: Vec<&str> = d.iter().map(|x| x.as_str().expect("an address")).collect();
        how += &row("Accepted only from", mono(d.join(", ")));
    } else if net == Network::Fips {
        how += &row("Accepted only from", "FIPS addresses (fd00::/8)".into());
    }
    how += &row(
        "Connection cap",
        mono(v["max_connections"].as_u64().map_or_else(
            || format!("the relay's ({})", num(sh.cfg.limits.max_connections as u64)),
            num,
        )),
    );
    how += &row(
        "Since start",
        mono(format!(
            "{} connections, {} events",
            num(u("connections_total")),
            num(u("events"))
        )),
    );
    how += &row(
        "Bytes in / out",
        mono(format!("{} / {}", size(u("bytes_in")), size(u("bytes_out")))),
    );
    let refusals: String = v["refusals"]
        .as_object()
        .expect("an object")
        .iter()
        .map(|(k, c)| {
            format!(
                "<tr><td>{k}</td><td class=\"n\">{}</td></tr>",
                num(c.as_u64().expect("a counter"))
            )
        })
        .collect();
    let mut keys = String::new();
    for k in v["sessions"].as_array().expect("a list") {
        let c = k["sessions"].as_u64().expect("a counter");
        let _ = write!(
            keys,
            "<tr><td class=\"key\"><span class=\"dot {}\"></span>{}</td><td class=\"mono\">{}</td><td class=\"n\">{c}</td></tr>",
            if c > 0 { "ok" } else { "wait" },
            esc(k["label"].as_str().expect("a label")),
            k["npub"].as_str().expect("an npub"),
        );
    }
    let services = if keys.is_empty() {
        String::new()
    } else {
        format!(
            "<h2>Whitelisted keys over {label}</h2><div class=\"card\"><table class=\"netkeys\"><thead><tr><th>Key</th><th>npub</th>\
<th class=\"n\">Sessions</th></tr></thead><tbody>{keys}</tbody></table></div>",
            label = net.label()
        )
    };
    let history: Vec<Minute> = serde_json::from_value(v["history"].clone()).expect("minutes");
    let body = format!(
        "<p class=\"crumb lbl\"><a href=\"/\">Overview</a> / {label}</p><h1>{label}</h1>\
<p class=\"lead\">{service}. Numbers on this page count only what arrived over {label}.</p><div class=\"urls net\">{urls}</div>{tiles}\
<h2>Last hour</h2><div class=\"card\">{chart}<div class=\"legend lbl\"><span><span class=\"sw a\"></span>accepted per minute</span>\
<span><span class=\"sw r\"></span>refused per minute</span></div></div>\
<div class=\"cols\"><div><h2>How it is reached</h2><div class=\"card\"><table><tbody>{how}</tbody></table></div></div>\
<div><h2>Refusals</h2><div class=\"card\"><table><tbody>{refusals}</tbody></table></div></div></div>{services}",
        label = net.label(),
        service = net.service(),
        chart = chart(&history),
    );
    Some(layout_nav(
        sh,
        net.label(),
        "relay · operator",
        &nav(sh, Some(net)),
        &body,
    ))
}

/// What the status page says the relay carries, by mode.
fn carries(sh: &Shared) -> String {
    let cvm = "<a href=\"https://contextvm.org\">ContextVM</a> messages (kinds 25910, 1059 and 21059)";
    let n = sh.cfg.whitelist.len();
    let keys = format!("the {n} key{} its operator whitelisted", if n == 1 { "" } else { "s" });
    match (sh.cfg.public, n) {
        (false, _) => format!(
            "Only {cvm} to and from {keys}, and those keys' announcements. Anyone may send a request to a \
             whitelisted key; only a whitelisted key may answer. Everything else is refused."
        ),
        (true, 0) => format!("Only {cvm} and ContextVM announcements, for any key. Everything else is refused."),
        (true, _) => format!(
            "Only {cvm} and ContextVM announcements, for any key. Requests to {keys} are kept for those keys \
             alone to read; everything else here is readable by anyone. Everything else is refused."
        ),
    }
}

/// The operator page: the public numbers plus the whitelist and refusals.
pub fn operator_page(sh: &Shared) -> String {
    let v = stats(sh, true);
    let mut keys = String::new();
    for k in v["keys"].as_array().expect("a list") {
        let live = k["sessions"].as_u64().expect("a counter") > 0;
        let _ = write!(
            keys,
            "<tr><td class=\"key\"><span class=\"dot {}\"></span>{}</td><td class=\"mono\">{}</td><td class=\"n\">{}</td><td class=\"n\">{}</td><td class=\"n\">{}</td></tr>",
            if live { "ok" } else { "wait" },
            esc(k["label"].as_str().expect("text")),
            esc(k["npub"].as_str().expect("text")),
            k["sessions"],
            num(k["inbound"].as_u64().expect("a counter")),
            num(k["outbound"].as_u64().expect("a counter")),
        );
    }
    let row = |k: &str, val: String| format!("<tr><td>{}</td><td class=\"n\">{}</td></tr>", esc(k), esc(&val));
    let refusals: String = v["refusals"]
        .as_object()
        .expect("an object")
        .iter()
        .map(|(k, n)| row(k, num(n.as_u64().expect("a counter"))))
        .collect();
    let traffic: String = [
        ("from whitelisted keys", v["events_by_writer"]["whitelisted"].clone()),
        ("requests from anyone", v["events_by_writer"]["public"].clone()),
        ("relay health checks", v["events_by_writer"]["health_checks"].clone()),
        ("between other keys", v["events_by_writer"]["open"].clone()),
        ("held for a later subscriber", v["held"].clone()),
        ("in memory now", v["stored"].clone()),
        ("connections since start", v["connections_total"].clone()),
        ("turned away at the door", v["connections_refused"].clone()),
        ("on probation now", v["probation"].clone()),
        ("closed after probation", v["probation_closed"].clone()),
        ("closed for reading too slowly", v["slow_closed"].clone()),
        (
            "AUTH whitelisted / other keys / refused",
            json!(format!("{} / {} / {}", v["auth_ok"], v["auth_other"], v["auth_failed"])),
        ),
        ("addresses tracked", v["addresses_tracked"].clone()),
        (
            "bytes in / out",
            json!(format!(
                "{} / {}",
                num(v["bytes_in"].as_u64().expect("n")),
                num(v["bytes_out"].as_u64().expect("n"))
            )),
        ),
    ]
    .into_iter()
    .map(|(k, n)| {
        row(
            k,
            n.as_u64()
                .map_or_else(|| n.as_str().unwrap_or_default().to_string(), num),
        )
    })
    .collect();
    let limits: String = v["limits"]
        .as_object()
        .expect("an object")
        .iter()
        .map(|(k, n)| row(k, n.as_u64().map_or_else(|| n.to_string(), num)))
        .collect();
    let body = format!(
        "<h1>{name}</h1><p class=\"lead\">Operator view. Served on its own listener without sign-in: keep it on loopback.</p>\
{tiles}{networks}{history}<h2>Whitelist</h2><div class=\"card\"><table><thead><tr><th>Key</th><th>npub</th><th class=\"n\">Sessions</th>\
<th class=\"n\">Requests in</th><th class=\"n\">Published</th></tr></thead><tbody>{keys}</tbody></table></div>\
<div class=\"cols\"><div><h2>Traffic</h2><div class=\"card\"><table><tbody>{traffic}</tbody></table></div>\
<h2>Refusals</h2><div class=\"card\"><table><tbody>{refusals}</tbody></table></div></div>\
<div><h2>Limits</h2><div class=\"card\"><table><tbody>{limits}</tbody></table></div></div></div>",
        name = esc(&sh.cfg.name),
        tiles = tiles(&v),
        networks = network_cards(&v),
        history = history(sh),
    );
    layout_nav(sh, "Operator", "relay · operator", &nav(sh, None), &body)
}

fn asset(path: &str) -> Option<Response> {
    let cached = |r: Response| Some(r.header("Cache-Control", "public, max-age=86400"));
    match path {
        "/assets/relay.css" => cached(Response::new(200, "text/css; charset=utf-8", CSS)),
        "/assets/favicon.svg" | "/favicon.ico" => cached(Response::new(200, "image/svg+xml", FAVICON)),
        _ => {
            let name = path.strip_prefix("/assets/")?;
            let (_, bytes) = FONTS.iter().find(|(n, _)| *n == name)?;
            cached(Response::new(200, "font/woff2", bytes.to_vec()))
        }
    }
}

fn html(body: String) -> Response {
    Response::new(200, "text/html; charset=utf-8", body)
        .header("Content-Security-Policy", CSP)
        .header("X-Content-Type-Options", "nosniff")
        .header("Cache-Control", "no-store")
}

fn json_response(v: &Value) -> Response {
    Response::new(200, "application/json", v.to_string())
        .header("Access-Control-Allow-Origin", "*")
        .header("Cache-Control", "no-store")
}

/// Answer a plain HTTP request. `operator` is the stats listener.
pub fn route(sh: &Shared, req: &Request, operator: bool) -> Response {
    if req.method != "GET" && req.method != "HEAD" {
        return Response::text(405, "only GET and HEAD").header("Allow", "GET, HEAD");
    }
    let path = req.path.split('?').next().unwrap_or_default();
    let wants_info = req
        .header("accept")
        .is_some_and(|a| a.contains("application/nostr+json"));
    match path {
        "/" if wants_info && !operator => Response::new(200, "application/nostr+json", info(sh).to_string())
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Headers", "Accept")
            .header("Access-Control-Allow-Methods", "GET"),
        "/" if operator => html(operator_page(sh)),
        "/" => html(status_page(sh)),
        "/stats.json" => json_response(&stats(sh, operator)),
        "/health" => Response::text(200, "ok"),
        p if operator && p.starts_with("/networks/") => {
            let id = &p["/networks/".len()..];
            let net = sh.nets.iter().map(|n| n.network).find(|n| n.id() == id);
            match net.and_then(|n| network_page(sh, n)) {
                Some(page) => html(page),
                None => Response::text(404, "not found"),
            }
        }
        p => asset(p).unwrap_or_else(|| Response::text(404, "not found")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::tests::shared;
    use nostr_sdk::prelude::Keys;

    fn get(path: &str, accept: Option<&str>) -> Request {
        let mut headers = vec![];
        if let Some(a) = accept {
            headers.push(("Accept".to_string(), a.to_string()));
        }
        Request {
            method: "GET".into(),
            path: path.into(),
            headers,
        }
    }

    fn body(r: &Response) -> String {
        String::from_utf8(r.body.clone()).unwrap()
    }

    #[test]
    fn formatting() {
        assert_eq!(num(0), "0");
        assert_eq!(num(1234567), "1,234,567");
        assert_eq!(num(123), "123");
        assert_eq!(short(999_999), "999,999");
        assert_eq!(short(10_536_366), "10.5M");
        assert_eq!(uptime(59), "0m 59s");
        assert_eq!(uptime(3_700), "1h 1m");
        assert_eq!(uptime(90_000), "1d 1h");
        assert_eq!(
            esc("<a href='x'>&\"</a>"),
            "&lt;a href=&#39;x&#39;&gt;&amp;&quot;&lt;/a&gt;"
        );
    }

    #[test]
    fn the_chart_draws_both_directions() {
        let h = vec![
            Minute {
                minute: 1,
                accepted: 4,
                refused: 2,
                delivered: 4,
            },
            Minute::default(),
        ];
        let svg = chart(&h);
        assert_eq!(svg.matches("class=\"a\"").count(), 1);
        assert_eq!(svg.matches("class=\"r\"").count(), 1);
        assert!(chart(&[]).ends_with("</svg>"));
    }

    #[test]
    fn pages_and_information() {
        let service = Keys::generate();
        let sh = shared(
            &service,
            &[
                ("DEADHOP_RELAY_PUBLIC_URLS", "wss://relay.example"),
                ("DEADHOP_RELAY_NAME", "<home>"),
            ],
        );
        let info = route(&sh, &get("/", Some("application/nostr+json")), false);
        let v: Value = serde_json::from_str(&body(&info)).unwrap();
        assert_eq!(v["supported_nips"], json!(NIPS));
        assert_eq!(v["limitation"]["restricted_writes"], json!(true));
        assert_eq!(info.headers[0].1, "application/nostr+json");

        let page = route(&sh, &get("/?x=1", Some("text/html")), false);
        let html = body(&page);
        assert!(
            html.contains("&lt;home&gt;")
                && html.contains("wss://relay.example")
                && html.contains("1 key its operator")
        );
        assert!(
            !html.contains(&npub(&service.public_key().to_bytes())),
            "the public page lists no keys"
        );
        assert!(page
            .headers
            .iter()
            .any(|(n, v)| *n == "Content-Security-Policy" && v.contains("default-src 'none'")));

        let op = body(&route(&sh, &get("/", Some("application/nostr+json")), true));
        assert!(op.contains(&npub(&service.public_key().to_bytes())) && op.contains("Operator view"));
        assert!(op.contains("auth-required") && op.contains("max_connections"));

        let public: Value = serde_json::from_str(&body(&route(&sh, &get("/stats.json", None), false))).unwrap();
        assert!(public.get("keys").is_none());
        assert_eq!(public["dropped"], json!(0));
        let full: Value = serde_json::from_str(&body(&route(&sh, &get("/stats.json", None), true))).unwrap();
        assert_eq!(full["keys"][0]["label"], json!("invoices"));
        assert_eq!(full["history"].as_array().unwrap().len(), 60);

        assert_eq!(route(&sh, &get("/health", None), false).status, 200);
        for p in [
            "/assets/relay.css",
            "/assets/favicon.svg",
            "/favicon.ico",
            "/assets/geist.woff2",
        ] {
            assert_eq!(route(&sh, &get(p, None), false).status, 200, "{p}");
        }
        assert_eq!(route(&sh, &get("/assets/nope.woff2", None), false).status, 404);
        assert_eq!(route(&sh, &get("/nope", None), false).status, 404);
        let post = Request {
            method: "POST".into(),
            path: "/".into(),
            headers: vec![],
        };
        assert_eq!(route(&sh, &post, false).status, 405);
        let two = shared(&service, &[]);
        assert!(body(&route(&two, &get("/", None), false)).contains("1 key its"));
    }

    #[test]
    fn clearnet_only_shows_nothing_about_networks() {
        let sh = shared(
            &Keys::generate(),
            &[("DEADHOP_RELAY_PUBLIC_URLS", "wss://relay.example")],
        );
        assert!(!sh.has_overlays());
        let status = body(&route(&sh, &get("/", None), false));
        assert!(status.contains("<div class=\"urls\"><code>wss://relay.example</code></div>"));
        assert!(!status.contains("addrs") && !status.contains("<nav>"));
        let op = body(&route(&sh, &get("/", None), true));
        assert!(!op.contains("<nav>") && !op.contains("Networks") && !op.contains("netcard"));
        let v: Value = serde_json::from_str(&body(&route(&sh, &get("/stats.json", None), true))).unwrap();
        assert!(v.get("networks").is_none());
        assert_eq!(route(&sh, &get("/networks/clearnet", None), true).status, 404);
        assert!(network_page(&sh, Network::Clearnet).is_none());
    }

    #[test]
    fn networks_on_the_operator_pages() {
        let sh = shared(
            &Keys::generate(),
            &[
                ("DEADHOP_RELAY_TOR_LISTEN", "127.0.0.1:7451"),
                ("DEADHOP_RELAY_TOR_URLS", "ws://abc.onion"),
                ("DEADHOP_RELAY_FIPS_LISTEN", "[::]:7447"),
                ("DEADHOP_RELAY_FIPS_URLS", "ws://npub1x.fips:7447"),
            ],
        );
        sh.net(Network::Tor).unwrap().accept(unix_now() / 60);
        let op = body(&route(&sh, &get("/", None), true));
        assert!(op.contains("<a href=\"/\" class=\"on\">Overview</a>") && op.contains("href=\"/networks/fips\""));
        assert!(op.contains("<span class=\"dot wait\"></span>Tor") && op.contains("1 events · 0 refused"));
        // Clearnet has no cap of its own and no URLs here; the status page skips it.
        let clear = body(&route(&sh, &get("/networks/clearnet", None), true));
        assert!(clear.contains("the relay&#39;s (512)") && !clear.contains("Accepted only from"));
        let fips = body(&route(&sh, &get("/networks/fips", None), true));
        assert!(fips.contains("by node") && fips.contains("class=\"on\">FIPS"));
        assert!(fips.contains("<td>Accepted only from</td><td>FIPS addresses (fd00::/8)</td>"));
        assert_eq!(
            route(&sh, &get("/networks/i2p", None), true).status,
            404,
            "not served on I2P"
        );
        assert_eq!(
            route(&sh, &get("/networks/tor", None), false).status,
            404,
            "operator only"
        );
        let status = body(&route(&sh, &get("/", None), false));
        assert!(status.contains("<td class=\"key lbl\">Tor</td>") && !status.contains(">Clearnet<"));
        assert!(!status.contains("netcard"), "no per-network numbers in public");
    }

    #[test]
    fn a_network_page_without_a_whitelist() {
        let cfg = crate::config::tests::config(&[
            ("DEADHOP_RELAY_PUBLIC", "on"),
            ("DEADHOP_RELAY_TOR_LISTEN", "127.0.0.1:7451"),
            ("DEADHOP_RELAY_TOR_URLS", "ws://abc.onion"),
        ])
        .unwrap();
        let sh = crate::state::Shared::new(cfg);
        let page = body(&route(&sh, &get("/networks/tor", None), true));
        assert!(page.contains("127.0.0.1, ::1") && !page.contains("Whitelisted keys over"));
    }

    #[test]
    fn sizes_and_sparks() {
        assert_eq!(size(812), "812 B");
        assert_eq!(size(4300), "4.2 KiB");
        assert_eq!(size(40_000_000), "38.1 MiB");
        assert_eq!(size(u64::MAX), "16777216.0 TiB");
        let mut h = vec![Minute::default(); 60];
        h[59].accepted = 4;
        h[58].accepted = 2;
        let svg = spark(&h);
        assert_eq!(svg.matches("<rect").count(), 2);
        assert!(svg.contains("x=\"118\" y=\"2.0\""));
    }

    #[test]
    fn public_mode_says_so() {
        let service = Keys::generate();
        let mixed = shared(&service, &[("DEADHOP_RELAY_PUBLIC", "on")]);
        let html = body(&route(&mixed, &get("/", None), false));
        assert!(html.contains("for any key") && html.contains("1 key its operator whitelisted are kept"));
        let open = crate::state::Shared::new(crate::config::tests::config(&[("DEADHOP_RELAY_PUBLIC", "on")]).unwrap());
        let html = body(&route(&open, &get("/", None), false));
        assert!(html.contains("for any key") && !html.contains("whitelisted"), "{html}");
        let v: Value = serde_json::from_str(&body(&route(&open, &get("/stats.json", None), true))).unwrap();
        assert_eq!(
            (v["public"].clone(), v["whitelisted_keys"].clone()),
            (json!(true), json!(0))
        );
        assert_eq!(v["events_by_writer"]["open"], json!(0));
        assert_eq!(v["limits"]["open_store_max_events"], json!(5_000));
        assert!(body(&route(&open, &get("/", None), true)).contains("between other keys"));
    }

    #[test]
    fn plural_keys_and_a_bad_drop_count() {
        let a = Keys::generate();
        let b = Keys::generate();
        let wl = format!("{},{}", a.public_key().to_hex(), b.public_key().to_hex());
        let sh =
            crate::state::Shared::new(crate::config::tests::config(&[(crate::config::ENV_WHITELIST, &wl)]).unwrap());
        sh.stats.dropped.fetch_add(1, Relaxed);
        sh.stats
            .key(&a.public_key().to_bytes())
            .unwrap()
            .sessions
            .fetch_add(1, Relaxed);
        let html = status_page(&sh);
        assert!(html.contains("2 keys its") && html.contains("v bad"));
        assert!(operator_page(&sh).contains("dot ok"));
    }
}
