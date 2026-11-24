//! Configuration, read once at startup from `DEADHOP_RELAY_*` environment
//! variables. The relay does not start without a whitelist unless its
//! operator opens it to every key (`DEADHOP_RELAY_PUBLIC=on`).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use crate::event::{hex_bytes, Key};
use crate::networks::{Adapter, Network, OVERLAYS};

/// The keys this relay carries traffic for, with the operator's label for each.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Whitelist {
    entries: Vec<(Key, String)>,
    index: HashMap<Key, usize>,
}

impl Whitelist {
    pub fn contains(&self, k: &Key) -> bool {
        self.index.contains_key(k)
    }

    pub fn label(&self, k: &Key) -> Option<&str> {
        self.index.get(k).map(|i| self.entries[*i].1.as_str())
    }

    pub fn entries(&self) -> &[(Key, String)] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn add(&mut self, key: Key, label: String) {
        if !self.index.contains_key(&key) {
            self.index.insert(key, self.entries.len());
            self.entries.push((key, label));
        }
    }
}

/// Every limit, with the value it takes when unset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub max_connections: usize,
    pub reserved_connections: usize,
    pub connections_per_ip: usize,
    pub max_subscriptions: usize,
    pub max_filters: usize,
    pub max_limit: usize,
    pub max_message_bytes: usize,
    pub public_max_event_bytes: usize,
    pub messages_per_sec: u32,
    pub public_events_per_min: u32,
    pub probes_per_min: u32,
    pub min_pow: u8,
    pub store_ttl_secs: u64,
    pub hold_secs: u64,
    pub store_max_events: usize,
    pub public_store_max_events: usize,
    /// Public mode: the largest event a key that is not whitelisted may send
    /// to another such key (a whole service reply, so larger than requests).
    pub open_max_event_bytes: usize,
    /// Public mode: events kept for keys that are not whitelisted, their
    /// announcements included. Separate, so they never evict the rest.
    pub open_store_max_events: usize,
    pub idle_secs: u64,
    pub handshake_secs: u64,
    pub auth_grace_secs: u64,
    pub max_event_age_secs: u64,
    pub queue_bytes: usize,
    pub trusted_queue_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_connections: 512,
            reserved_connections: 32,
            connections_per_ip: 8,
            max_subscriptions: 8,
            max_filters: 4,
            max_limit: 500,
            max_message_bytes: 128 * 1024,
            public_max_event_bytes: 32 * 1024,
            messages_per_sec: 50,
            public_events_per_min: 600,
            probes_per_min: 30,
            min_pow: 0,
            store_ttl_secs: 3600,
            hold_secs: 30,
            store_max_events: 20_000,
            public_store_max_events: 1_000,
            open_max_event_bytes: 128 * 1024,
            open_store_max_events: 5_000,
            idle_secs: 300,
            handshake_secs: 10,
            auth_grace_secs: 5,
            max_event_age_secs: 600,
            queue_bytes: 1024 * 1024,
            trusted_queue_bytes: 64 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Clearnet. `None` (`off`) only when an adapter serves the relay instead.
    pub listen: Option<SocketAddr>,
    /// The operator page, served without sign-in: keep it on loopback.
    pub stats_listen: Option<SocketAddr>,
    pub whitelist: Whitelist,
    /// Carry ContextVM traffic for every key, not only whitelisted ones.
    pub public: bool,
    pub name: String,
    pub description: String,
    /// The addresses clients reach this relay at (for NIP-42 and the status page).
    pub public_urls: Vec<String>,
    /// Reverse proxies whose `X-Forwarded-For` (its last entry) is believed.
    pub trusted_proxies: Vec<IpAddr>,
    /// Accept deadhop's relay health check (see the docs).
    pub allow_probe: bool,
    pub limits: Limits,
    /// The overlay networks the relay is also served on (Tor, I2P, FIPS).
    pub adapters: Vec<Adapter>,
}

impl Config {
    pub fn adapter(&self, n: Network) -> Option<&Adapter> {
        self.adapters.iter().find(|a| a.network == n)
    }

    /// The networks the relay is served on, clearnet first.
    pub fn networks(&self) -> Vec<Network> {
        let clearnet = self.listen.map(|_| Network::Clearnet);
        clearnet
            .into_iter()
            .chain(self.adapters.iter().map(|a| a.network))
            .collect()
    }
}

pub const ENV_WHITELIST: &str = "DEADHOP_RELAY_WHITELIST";
pub const ENV_WHITELIST_FILE: &str = "DEADHOP_RELAY_WHITELIST_FILE";
pub const ENV_PUBLIC: &str = "DEADHOP_RELAY_PUBLIC";

/// Decode an `npub1…` or 64-character hex public key.
pub fn parse_key(s: &str) -> Option<Key> {
    if s.starts_with("npub1") {
        // The prefix fixes the human-readable part; only the data can be wrong.
        bech32::decode(s).ok()?.1.try_into().ok()
    } else {
        hex_bytes::<32>(s)
    }
}

/// Encode a key as `npub1…`.
pub fn npub(k: &Key) -> String {
    bech32::encode::<bech32::Bech32>(bech32::Hrp::parse_unchecked("npub"), k).expect("32 bytes always encode")
}

/// One whitelist entry: `label=npub1…`, `npub1…` or hex.
fn entry(raw: &str, n: usize) -> Result<(Key, String), String> {
    let (label, key) = match raw.split_once('=') {
        Some((l, k)) => (l.trim().to_string(), k.trim()),
        None => (format!("key {n}"), raw),
    };
    let ok_label = !label.is_empty() && label.len() <= 32 && label.chars().all(|c| c.is_ascii_graphic() || c == ' ');
    if !ok_label {
        return Err(format!(
            "whitelist label '{label}' must be 1 to 32 printable ASCII characters"
        ));
    }
    let key = parse_key(key).ok_or(format!(
        "whitelist entry '{raw}' is not an npub or 64-character hex key"
    ))?;
    Ok((key, label))
}

/// Read the whitelist from the environment value and the file's lines.
/// It may be empty; [`Config::from_env`] decides whether that is allowed.
pub fn whitelist(inline: Option<&str>, file: Option<&str>) -> Result<Whitelist, String> {
    let mut wl = Whitelist::default();
    let lines = inline
        .into_iter()
        .flat_map(|s| s.split([',', '\n']))
        .chain(file.into_iter().flat_map(str::lines));
    for line in lines {
        let line = line.split('#').next().unwrap_or_default().trim();
        if !line.is_empty() {
            let (k, l) = entry(line, wl.len() + 1)?;
            wl.add(k, l);
        }
    }
    Ok(wl)
}

type Get<'a> = &'a dyn Fn(&str) -> Option<String>;

/// A bounded whole number from `DEADHOP_RELAY_<suffix>`.
fn num<T: TryFrom<u64>>(get: Get, suffix: &str, default: T, min: u64, max: u64) -> Result<T, String> {
    let name = format!("DEADHOP_RELAY_{suffix}");
    let Some(v) = get(&name) else { return Ok(default) };
    let n = v.trim().parse::<u64>().ok().filter(|n| (min..=max).contains(n));
    n.and_then(|n| T::try_from(n).ok())
        .ok_or(format!("{name} must be a whole number from {min} to {max}, not '{v}'"))
}

fn flag(get: Get, name: &str, default: bool) -> Result<bool, String> {
    match get(name).as_deref().map(str::trim) {
        None => Ok(default),
        Some("1" | "true" | "yes" | "on") => Ok(true),
        Some("0" | "false" | "no" | "off") => Ok(false),
        Some(o) => Err(format!("{name} must be true or false, not '{o}'")),
    }
}

fn addr(get: Get, name: &str, default: &str) -> Result<Option<SocketAddr>, String> {
    let v = get(name).unwrap_or_else(|| default.into());
    match v.trim() {
        "" | "off" => Ok(None),
        t => t
            .parse()
            .map(Some)
            .map_err(|_| format!("{name} must be an ip:port address, not '{v}'")),
    }
}

fn csv(get: Get, name: &str) -> Vec<String> {
    get(name)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// The IP addresses in `DEADHOP_RELAY_<suffix>`, comma-separated.
fn ips(get: Get, name: &str) -> Result<Vec<IpAddr>, String> {
    csv(get, name)
        .iter()
        .map(|p| p.parse().map_err(|_| format!("{name}: '{p}' is not an IP address")))
        .collect()
}

/// The `ws://` or `wss://` addresses in `name`, each on network `n` when it
/// is an overlay (`.onion`, `.i2p`, `.fips`).
fn urls(get: Get, name: &str, n: Network) -> Result<Vec<String>, String> {
    let urls = csv(get, name);
    for u in &urls {
        if !(u.starts_with("ws://") || u.starts_with("wss://")) {
            return Err(format!("{name}: '{u}' must start with ws:// or wss://"));
        }
        if n != Network::Clearnet && !crate::state::host_of(u).ends_with(n.suffix()) {
            return Err(format!(
                "{name}: '{u}' is not a {} address (…{})",
                n.label(),
                n.suffix()
            ));
        }
    }
    Ok(urls)
}

/// The adapter for overlay `n`, if `DEADHOP_RELAY_<N>_LISTEN` is set.
fn adapter(get: Get, n: Network) -> Result<Option<Adapter>, String> {
    let var = |s: &str| format!("DEADHOP_RELAY_{}_{s}", n.env());
    let Some(listen) = addr(get, &var("LISTEN"), "off")? else {
        return Ok(None);
    };
    let urls = urls(get, &var("URLS"), n)?;
    if urls.is_empty() {
        return Err(format!(
            "{} is required with {}: the {} address clients use, for example ws://….{}",
            var("URLS"),
            var("LISTEN"),
            n.label(),
            n.suffix().trim_start_matches('.')
        ));
    }
    let daemons = match n {
        Network::Fips => vec![],
        _ if get(&var("DAEMONS")).is_none() => {
            vec![IpAddr::from([127, 0, 0, 1]), IpAddr::from([0u16, 0, 0, 0, 0, 0, 0, 1])]
        }
        _ => ips(get, &var("DAEMONS"))?,
    };
    Ok(Some(Adapter {
        network: n,
        listen,
        urls,
        daemons,
        max_connections: num(get, &format!("{}_MAX_CONNECTIONS", n.env()), 128, 1, 1_000_000)?,
    }))
}

impl Config {
    /// Read the configuration. `read_file` loads the whitelist file.
    /// An empty value counts as unset, so a compose file can pass every
    /// variable through as `${NAME:-}`.
    pub fn from_env(raw: Get, read_file: &dyn Fn(&str) -> std::io::Result<String>) -> Result<Config, String> {
        let get: Get = &|k| raw(k).filter(|v| !v.trim().is_empty());
        let file = match get(ENV_WHITELIST_FILE) {
            Some(path) => Some(read_file(&path).map_err(|e| format!("{ENV_WHITELIST_FILE} {path}: {e}"))?),
            None => None,
        };
        let whitelist = whitelist(get(ENV_WHITELIST).as_deref(), file.as_deref())?;
        let public = flag(get, ENV_PUBLIC, false)?;
        if whitelist.is_empty() && !public {
            return Err(format!(
                "{ENV_WHITELIST} (or {ENV_WHITELIST_FILE}) is required: list the deadhop invoice and/or admin keys this \
                 relay serves, for example {ENV_WHITELIST}=invoices=npub1…,admin=npub1…. To carry ContextVM traffic \
                 for every key instead, set {ENV_PUBLIC}=on. The relay does not start without one or the other."
            ));
        }
        let d = Limits::default();
        let mb = 1024 * 1024;
        let limits = Limits {
            max_connections: num(get, "MAX_CONNECTIONS", d.max_connections, 1, 1_000_000)?,
            reserved_connections: num(get, "RESERVED_CONNECTIONS", d.reserved_connections, 0, 10_000)?,
            connections_per_ip: num(get, "CONNECTIONS_PER_IP", d.connections_per_ip, 1, 100_000)?,
            max_subscriptions: num(get, "MAX_SUBSCRIPTIONS", d.max_subscriptions, 1, 256)?,
            max_filters: num(get, "MAX_FILTERS", d.max_filters, 1, 64)?,
            max_limit: num(get, "MAX_LIMIT", d.max_limit, 1, 100_000)?,
            max_message_bytes: num(get, "MAX_MESSAGE_BYTES", d.max_message_bytes, 1024, 16 * mb)?,
            public_max_event_bytes: num(get, "PUBLIC_MAX_EVENT_BYTES", d.public_max_event_bytes, 512, 16 * mb)?,
            messages_per_sec: num(get, "MESSAGES_PER_SEC", d.messages_per_sec, 1, 100_000)?,
            public_events_per_min: num(get, "PUBLIC_EVENTS_PER_MIN", d.public_events_per_min, 1, 1_000_000)?,
            probes_per_min: num(get, "PROBES_PER_MIN", d.probes_per_min, 1, 100_000)?,
            min_pow: num(get, "MIN_POW", d.min_pow, 0, 32)?,
            store_ttl_secs: num(get, "STORE_TTL_SECS", d.store_ttl_secs, 0, 7 * 86_400)?,
            hold_secs: num(get, "HOLD_SECS", d.hold_secs, 0, 3_600)?,
            store_max_events: num(get, "STORE_MAX_EVENTS", d.store_max_events, 0, 10_000_000)?,
            public_store_max_events: num(get, "PUBLIC_STORE_MAX_EVENTS", d.public_store_max_events, 0, 10_000_000)?,
            open_max_event_bytes: num(get, "OPEN_MAX_EVENT_BYTES", d.open_max_event_bytes, 512, 16 * mb)?,
            open_store_max_events: num(get, "OPEN_STORE_MAX_EVENTS", d.open_store_max_events, 0, 10_000_000)?,
            idle_secs: num(get, "IDLE_SECS", d.idle_secs, 2, 86_400)?,
            handshake_secs: num(get, "HANDSHAKE_SECS", d.handshake_secs, 1, 120)?,
            auth_grace_secs: num(get, "AUTH_GRACE_SECS", d.auth_grace_secs, 1, 120)?,
            max_event_age_secs: num(get, "MAX_EVENT_AGE_SECS", d.max_event_age_secs, 10, 7 * 86_400)?,
            queue_bytes: num(get, "QUEUE_BYTES", d.queue_bytes, 64 * 1024, 1024 * mb)?,
            trusted_queue_bytes: num(get, "TRUSTED_QUEUE_BYTES", d.trusted_queue_bytes, mb, 16 * 1024 * mb)?,
        };
        let trusted_proxies = ips(get, "DEADHOP_RELAY_TRUSTED_PROXIES")?;
        let public_urls = urls(get, "DEADHOP_RELAY_PUBLIC_URLS", Network::Clearnet)?;
        let mut adapters = vec![];
        for n in OVERLAYS {
            adapters.extend(adapter(get, n)?);
        }
        let listen = addr(get, "DEADHOP_RELAY_LISTEN", "0.0.0.0:7447")?;
        if listen.is_none() && adapters.is_empty() {
            return Err(
                "DEADHOP_RELAY_LISTEN cannot be off unless the relay is served on Tor, I2P or FIPS (DEADHOP_RELAY_TOR_LISTEN, …)"
                    .into(),
            );
        }
        let name = get("DEADHOP_RELAY_NAME").unwrap_or_else(|| "deadhop relay".into());
        if name.chars().count() > 64 {
            return Err("DEADHOP_RELAY_NAME must be at most 64 characters".into());
        }
        Ok(Config {
            listen,
            stats_listen: addr(get, "DEADHOP_RELAY_STATS_LISTEN", "127.0.0.1:7448")?,
            whitelist,
            public,
            name,
            description: get("DEADHOP_RELAY_DESCRIPTION").unwrap_or_else(|| {
                if public {
                    "Carries ContextVM requests, replies and announcements for any key.".into()
                } else {
                    "Carries deadhop ContextVM requests and replies for its whitelisted keys only.".into()
                }
            }),
            public_urls,
            trusted_proxies,
            allow_probe: flag(get, "DEADHOP_RELAY_ALLOW_PROBE", true)?,
            limits,
            adapters,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub const HEX: &str = "5c1e8f4ab2d3e60c7a9b1f2e3d4c5b6a79881726354a5b6c7d8e9fa0b1c2d3e4";
    pub const NPUB: &str = "npub1ts0g7j4j60nqc75mruhr6nzmdfucs9exx499kmra3606pvwz60jq8zdcpg";

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k| map.get(k).cloned()
    }

    fn no_file(_: &str) -> std::io::Result<String> {
        Err(std::io::Error::other("no such file"))
    }

    pub fn config(pairs: &[(&str, &str)]) -> Result<Config, String> {
        Config::from_env(&env(pairs), &no_file)
    }

    #[test]
    fn keys_decode_both_ways() {
        let k = parse_key(HEX).unwrap();
        assert_eq!(parse_key(NPUB), Some(k));
        assert_eq!(npub(&k), NPUB);
        assert_eq!(parse_key("npub1"), None);
        assert_eq!(parse_key(&NPUB.replacen("npub", "nsec", 1)), None);
        // An npub with the wrong length.
        assert_eq!(parse_key(&npub_of(&[1, 2, 3])), None);
        // Wrong prefix inside a string that starts like an npub.
        assert_eq!(parse_key("npub1qqqqqqqq"), None);
    }

    fn npub_of(data: &[u8]) -> String {
        bech32::encode::<bech32::Bech32>(bech32::Hrp::parse_unchecked("npub"), data).unwrap()
    }

    #[test]
    fn refuses_to_start_without_a_whitelist() {
        let e = config(&[]).unwrap_err();
        assert!(
            e.contains("DEADHOP_RELAY_WHITELIST") && e.contains("does not start"),
            "{e}"
        );
        assert!(config(&[(ENV_WHITELIST, " , # nothing")]).is_err());
        assert!(config(&[(ENV_PUBLIC, "off")]).is_err(), "public mode is opt-in");
        assert!(config(&[(ENV_PUBLIC, "maybe")])
            .unwrap_err()
            .contains("DEADHOP_RELAY_PUBLIC"));
    }

    #[test]
    fn overlay_adapters() {
        let onion = "ws://k7m3x2p4vq5zl6n8a7rjw3e9tthd4ysq2bgm5c6uv7xn2pqe5ar4lyid.onion";
        let c = config(&[
            (ENV_WHITELIST, HEX),
            ("DEADHOP_RELAY_TOR_LISTEN", "127.0.0.1:7451"),
            ("DEADHOP_RELAY_TOR_URLS", onion),
            ("DEADHOP_RELAY_I2P_LISTEN", "127.0.0.1:7452"),
            ("DEADHOP_RELAY_I2P_URLS", "ws://abc.b32.i2p"),
            ("DEADHOP_RELAY_I2P_DAEMONS", "10.0.0.2"),
            ("DEADHOP_RELAY_I2P_MAX_CONNECTIONS", "9"),
            ("DEADHOP_RELAY_FIPS_LISTEN", "[::]:7447"),
            ("DEADHOP_RELAY_FIPS_URLS", "wss://npub1x.fips:7447/"),
        ])
        .unwrap();
        assert_eq!(
            c.networks(),
            [Network::Clearnet, Network::Tor, Network::I2p, Network::Fips]
        );
        let tor = c.adapter(Network::Tor).unwrap();
        assert_eq!(
            (tor.listen.port(), tor.urls[0].as_str(), tor.max_connections),
            (7451, onion, 128)
        );
        assert_eq!(
            tor.daemons,
            ["127.0.0.1".parse::<IpAddr>().unwrap(), "::1".parse().unwrap()]
        );
        let i2p = c.adapter(Network::I2p).unwrap();
        assert_eq!(
            (i2p.daemons.clone(), i2p.max_connections),
            (vec!["10.0.0.2".parse::<IpAddr>().unwrap()], 9)
        );
        assert!(c.adapter(Network::Fips).unwrap().daemons.is_empty());
        assert!(c.adapter(Network::Clearnet).is_none());
        // None configured: nothing changes.
        let plain = config(&[(ENV_WHITELIST, HEX)]).unwrap();
        assert!(plain.adapters.is_empty() && plain.networks() == [Network::Clearnet]);

        let tor = |extra: &[(&'static str, &'static str)]| {
            let mut p = vec![(ENV_WHITELIST, HEX), ("DEADHOP_RELAY_TOR_LISTEN", "127.0.0.1:7451")];
            p.extend_from_slice(extra);
            config(&p)
        };
        assert!(tor(&[]).unwrap_err().contains("DEADHOP_RELAY_TOR_URLS is required"));
        assert!(tor(&[("DEADHOP_RELAY_TOR_URLS", "ws://example.com")])
            .unwrap_err()
            .contains("not a Tor address"));
        assert!(tor(&[("DEADHOP_RELAY_TOR_URLS", "http://x.onion")])
            .unwrap_err()
            .contains("ws://"));
        assert!(
            tor(&[("DEADHOP_RELAY_TOR_URLS", onion), ("DEADHOP_RELAY_TOR_DAEMONS", "tor")])
                .unwrap_err()
                .contains("not an IP address")
        );
        assert!(tor(&[
            ("DEADHOP_RELAY_TOR_URLS", onion),
            ("DEADHOP_RELAY_TOR_MAX_CONNECTIONS", "0")
        ])
        .is_err());
        assert!(config(&[(ENV_WHITELIST, HEX), ("DEADHOP_RELAY_TOR_LISTEN", "tor")]).is_err());
        assert!(config(&[(ENV_WHITELIST, HEX), ("DEADHOP_RELAY_TOR_LISTEN", "off")])
            .unwrap()
            .adapters
            .is_empty());

        // Clearnet off: only with an overlay.
        let off = tor(&[("DEADHOP_RELAY_TOR_URLS", onion), ("DEADHOP_RELAY_LISTEN", "off")]).unwrap();
        assert_eq!((off.listen, off.networks()), (None, vec![Network::Tor]));
        assert!(config(&[(ENV_WHITELIST, HEX), ("DEADHOP_RELAY_LISTEN", "off")])
            .unwrap_err()
            .contains("unless the relay is served on Tor, I2P or FIPS"));
    }

    #[test]
    fn public_mode_needs_no_whitelist() {
        let c = config(&[(ENV_PUBLIC, "on")]).unwrap();
        assert!(c.public && c.whitelist.is_empty());
        assert!(c.description.contains("any key"), "{}", c.description);
        let c = config(&[(ENV_PUBLIC, "on"), (ENV_WHITELIST, HEX)]).unwrap();
        assert!(c.public && c.whitelist.len() == 1, "both at once");
        let c = config(&[(ENV_WHITELIST, HEX)]).unwrap();
        assert!(!c.public && c.description.contains("whitelisted keys only"));
        assert_eq!(c.limits.open_max_event_bytes, 128 * 1024);
        assert_eq!(c.limits.open_store_max_events, 5_000);
        let c = config(&[
            (ENV_PUBLIC, "on"),
            ("DEADHOP_RELAY_OPEN_MAX_EVENT_BYTES", "4096"),
            ("DEADHOP_RELAY_OPEN_STORE_MAX_EVENTS", "7"),
        ])
        .unwrap();
        assert_eq!(
            (c.limits.open_max_event_bytes, c.limits.open_store_max_events),
            (4096, 7)
        );
    }

    #[test]
    fn reads_labelled_keys_from_env_and_file() {
        let read = |p: &str| -> std::io::Result<String> {
            assert_eq!(p, "/wl");
            Ok(format!("# operators\nadmin = {HEX}  # the admin key\n\n{NPUB}\n"))
        };
        let other = "00".repeat(31) + "01";
        let c = Config::from_env(
            &env(&[
                (ENV_WHITELIST, &format!("invoices={other}")),
                (ENV_WHITELIST_FILE, "/wl"),
            ]),
            &read,
        )
        .unwrap();
        // The duplicate line keeps the first label.
        assert_eq!(c.whitelist.len(), 2);
        let k = parse_key(HEX).unwrap();
        assert!(c.whitelist.contains(&k));
        assert_eq!(c.whitelist.label(&k), Some("admin"));
        assert_eq!(c.whitelist.label(&[9; 32]), None);
        assert_eq!(c.whitelist.entries()[0].1, "invoices");
        assert_eq!(
            config(&[(ENV_WHITELIST, HEX)]).unwrap().whitelist.entries()[0].1,
            "key 1"
        );
        let e = config(&[(ENV_WHITELIST_FILE, "/missing")]).unwrap_err();
        assert!(e.starts_with("DEADHOP_RELAY_WHITELIST_FILE /missing:"), "{e}");
    }

    #[test]
    fn refuses_bad_entries() {
        assert!(config(&[(ENV_WHITELIST, "abc")]).unwrap_err().contains("not an npub"));
        assert!(config(&[(ENV_WHITELIST, &format!("={HEX}"))])
            .unwrap_err()
            .contains("label"));
        assert!(config(&[(ENV_WHITELIST, &format!("{}={HEX}", "x".repeat(33)))])
            .unwrap_err()
            .contains("label"));
        assert!(config(&[(ENV_WHITELIST, &format!("tab\there={HEX}"))])
            .unwrap_err()
            .contains("label"));
    }

    #[test]
    fn empty_values_are_unset() {
        let c = config(&[
            (ENV_WHITELIST, HEX),
            ("DEADHOP_RELAY_MAX_CONNECTIONS", ""),
            ("DEADHOP_RELAY_STATS_LISTEN", " "),
        ])
        .unwrap();
        assert_eq!(c.limits.max_connections, Limits::default().max_connections);
        assert_eq!(c.stats_listen, Some("127.0.0.1:7448".parse().unwrap()));
        assert!(config(&[(ENV_WHITELIST, "")]).is_err());
    }

    #[test]
    fn defaults_and_overrides() {
        let c = config(&[(ENV_WHITELIST, HEX)]).unwrap();
        assert_eq!(c.listen, Some("0.0.0.0:7447".parse().unwrap()));
        assert_eq!(c.stats_listen, Some("127.0.0.1:7448".parse().unwrap()));
        assert_eq!(c.limits, Limits::default());
        assert!(c.allow_probe);
        assert_eq!(c.name, "deadhop relay");
        let c = config(&[
            (ENV_WHITELIST, HEX),
            ("DEADHOP_RELAY_LISTEN", "127.0.0.1:9000"),
            ("DEADHOP_RELAY_STATS_LISTEN", "off"),
            ("DEADHOP_RELAY_MAX_CONNECTIONS", "64"),
            ("DEADHOP_RELAY_MIN_POW", "8"),
            ("DEADHOP_RELAY_ALLOW_PROBE", "no"),
            ("DEADHOP_RELAY_TRUSTED_PROXIES", "127.0.0.1, ::1"),
            ("DEADHOP_RELAY_PUBLIC_URLS", "wss://relay.example, ws://10.0.0.2:7447"),
            ("DEADHOP_RELAY_NAME", "home"),
            ("DEADHOP_RELAY_DESCRIPTION", "mine"),
        ])
        .unwrap();
        assert_eq!(c.listen, Some("127.0.0.1:9000".parse().unwrap()));
        assert_eq!(c.stats_listen, None);
        assert_eq!(c.limits.max_connections, 64);
        assert_eq!(c.limits.min_pow, 8);
        assert!(!c.allow_probe);
        assert_eq!(c.trusted_proxies.len(), 2);
        assert_eq!(c.public_urls, vec!["wss://relay.example", "ws://10.0.0.2:7447"]);
        assert_eq!((c.name.as_str(), c.description.as_str()), ("home", "mine"));
        assert_eq!(
            config(&[(ENV_WHITELIST, HEX), ("DEADHOP_RELAY_STATS_LISTEN", "off")])
                .unwrap()
                .stats_listen,
            None
        );
        assert!(
            config(&[(ENV_WHITELIST, HEX), ("DEADHOP_RELAY_ALLOW_PROBE", "on")])
                .unwrap()
                .allow_probe
        );
    }

    #[test]
    fn refuses_bad_values() {
        for (k, v, want) in [
            ("DEADHOP_RELAY_MAX_CONNECTIONS", "0", "from 1 to 1000000"),
            ("DEADHOP_RELAY_MIN_POW", "x", "not 'x'"),
            ("DEADHOP_RELAY_ALLOW_PROBE", "maybe", "true or false"),
            ("DEADHOP_RELAY_LISTEN", "nowhere", "ip:port"),
            ("DEADHOP_RELAY_LISTEN", "off", "cannot be off"),
            ("DEADHOP_RELAY_TRUSTED_PROXIES", "proxy.local", "not an IP"),
            ("DEADHOP_RELAY_PUBLIC_URLS", "https://x", "ws:// or wss://"),
            ("DEADHOP_RELAY_NAME", &"n".repeat(65), "at most 64"),
        ] {
            let e = config(&[(ENV_WHITELIST, HEX), (k, v)]).unwrap_err();
            assert!(e.contains(want), "{k}: {e}");
        }
    }
}
