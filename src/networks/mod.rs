//! The networks the relay is served on, and an adapter for each overlay.
//!
//! Clearnet is the relay's own listener (`DEADHOP_RELAY_LISTEN`). Each overlay
//! network is an adapter with a listener of its own, which the operator's Tor,
//! I2P or FIPS daemon forwards to. The relay never runs those daemons; it
//! only knows how each one tells its clients apart, which is what per-client
//! limits need:
//!
//! - [`tor`]: by circuit, from the PROXY header Tor adds
//!   (`HiddenServiceExportCircuitID haproxy`);
//! - [`i2p`]: by destination, from the `X-I2P-DestHash` header an i2pd
//!   `http` server tunnel adds;
//! - [`fips`]: by node, from the peer's own FIPS address.
//!
//! Every connection is counted under the network it arrived on, so the
//! operator page can show each one on its own.

pub mod fips;
pub mod i2p;
pub mod tor;

#[cfg(test)]
mod socket_tests;

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};

use crate::config::Whitelist;
use crate::event::Key;
use crate::stats::{History, Minute, Reason, REASONS};

/// A network the relay can be reached on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    Clearnet,
    Tor,
    I2p,
    Fips,
}

/// The overlay networks, in the order they are shown.
pub const OVERLAYS: [Network; 3] = [Network::Tor, Network::I2p, Network::Fips];

impl Network {
    /// Lowercase, for URLs and JSON.
    pub fn id(self) -> &'static str {
        match self {
            Network::Clearnet => "clearnet",
            Network::Tor => "tor",
            Network::I2p => "i2p",
            Network::Fips => "fips",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Network::Clearnet => "Clearnet",
            Network::Tor => "Tor",
            Network::I2p => "I2P",
            Network::Fips => "FIPS",
        }
    }

    /// The part of `DEADHOP_RELAY_<PREFIX>_LISTEN` that names the adapter.
    pub fn env(self) -> &'static str {
        match self {
            Network::Clearnet => "",
            Network::Tor => "TOR",
            Network::I2p => "I2P",
            Network::Fips => "FIPS",
        }
    }

    /// The host suffix every address on the network ends with.
    pub fn suffix(self) -> &'static str {
        match self {
            Network::Clearnet => "",
            Network::Tor => ".onion",
            Network::I2p => ".i2p",
            Network::Fips => ".fips",
        }
    }

    /// What the network's service is, for the network's page.
    pub fn service(self) -> &'static str {
        match self {
            Network::Clearnet => "Direct connections, or through your reverse proxy",
            Network::Tor => "An onion service run by your Tor daemon",
            Network::I2p => "An I2P server tunnel run by your I2P router",
            Network::Fips => "A listener on this node's FIPS address",
        }
    }

    /// How clients are told apart, for per-client limits.
    pub fn identity(self) -> &'static str {
        match self {
            Network::Clearnet => "by address: the peer's, or the last X-Forwarded-For entry from a trusted proxy",
            Network::Tor => "by circuit: Tor's PROXY header (HiddenServiceExportCircuitID haproxy)",
            Network::I2p => "by destination: the X-I2P-DestHash header of an i2pd http server tunnel",
            Network::Fips => "by node: the peer's FIPS address (fd00::/8)",
        }
    }
}

/// An overlay network's listener and how it is reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adapter {
    pub network: Network,
    /// Where the daemon forwards connections to.
    pub listen: SocketAddr,
    /// The addresses clients use (`ws://….onion`), for NIP-42 and the pages.
    pub urls: Vec<String>,
    /// Tor and I2P: the daemon's addresses. Only they may connect, since only
    /// they can vouch for the circuit or destination they report.
    pub daemons: Vec<IpAddr>,
    /// Open connections over this network, at most; past it, a connection is
    /// on probation, as it is past the relay's own limit. Circuits and
    /// destinations are free to mint, so this is what bounds a flood.
    pub max_connections: usize,
}

/// Counters for one network: what the network's page shows.
pub struct NetStats {
    pub network: Network,
    pub open: AtomicUsize,
    pub total: AtomicU64,
    /// Connections turned away: over the limits, a peer that is not the
    /// daemon, or no identity where one was required.
    pub turned_away: AtomicU64,
    pub accepted: AtomicU64,
    pub refused: [AtomicU64; 7],
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    /// Connections over this network authenticated as each whitelisted key.
    keys: Vec<(Key, AtomicU64)>,
    history: History,
}

impl NetStats {
    pub fn new(network: Network, wl: &Whitelist) -> NetStats {
        NetStats {
            network,
            open: AtomicUsize::new(0),
            total: AtomicU64::new(0),
            turned_away: AtomicU64::new(0),
            accepted: AtomicU64::new(0),
            refused: Default::default(),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            keys: wl.entries().iter().map(|(k, _)| (*k, AtomicU64::new(0))).collect(),
            history: History::default(),
        }
    }

    pub fn accept(&self, minute: u64) {
        self.accepted.fetch_add(1, Relaxed);
        self.history.record(minute, |m| m.accepted += 1);
    }

    pub fn refuse(&self, r: Reason, minute: u64) {
        self.refused[REASONS.iter().position(|x| *x == r).expect("every reason is listed")].fetch_add(1, Relaxed);
        self.history.record(minute, |m| m.refused += 1);
    }

    pub fn refused(&self, r: Reason) -> u64 {
        self.refused[REASONS.iter().position(|x| *x == r).expect("every reason is listed")].load(Relaxed)
    }

    pub fn refused_total(&self) -> u64 {
        self.refused.iter().map(|a| a.load(Relaxed)).sum()
    }

    pub fn history(&self, now_minute: u64) -> Vec<Minute> {
        self.history.last_hour(now_minute)
    }

    /// A connection over this network authenticated as `k` (+1) or closed (-1).
    pub fn session(&self, k: &Key, open: bool) {
        if let Some((_, n)) = self.keys.iter().find(|(x, _)| x == k) {
            if open {
                n.fetch_add(1, Relaxed);
            } else {
                n.fetch_sub(1, Relaxed);
            }
        }
    }

    /// Sessions over this network per whitelisted key, in whitelist order.
    pub fn sessions(&self) -> Vec<(Key, u64)> {
        self.keys.iter().map(|(k, n)| (*k, n.load(Relaxed))).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::{config, HEX};
    use crate::config::{parse_key, ENV_WHITELIST};

    #[test]
    fn names_and_words() {
        let all = [Network::Clearnet, Network::Tor, Network::I2p, Network::Fips];
        let ids: Vec<&str> = all.iter().map(|n| n.id()).collect();
        assert_eq!(ids, ["clearnet", "tor", "i2p", "fips"]);
        let labels: Vec<&str> = all.iter().map(|n| n.label()).collect();
        assert_eq!(labels, ["Clearnet", "Tor", "I2P", "FIPS"]);
        let envs: Vec<&str> = all.iter().map(|n| n.env()).collect();
        assert_eq!(envs, ["", "TOR", "I2P", "FIPS"]);
        let suffixes: Vec<&str> = all.iter().map(|n| n.suffix()).collect();
        assert_eq!(suffixes, ["", ".onion", ".i2p", ".fips"]);
        for n in all {
            assert!(!n.service().is_empty() && n.identity().starts_with("by "));
        }
    }

    #[test]
    fn counters() {
        let wl = config(&[(ENV_WHITELIST, HEX)]).unwrap().whitelist;
        let s = NetStats::new(Network::Tor, &wl);
        s.accept(1000);
        s.refuse(Reason::Pow, 1000);
        s.refuse(Reason::Pow, 1001);
        assert_eq!(
            (s.accepted.load(Relaxed), s.refused(Reason::Pow), s.refused_total()),
            (1, 2, 2)
        );
        let h = s.history(1001);
        assert_eq!((h[58].accepted, h[58].refused, h[59].refused), (1, 1, 1));
        let k = parse_key(HEX).unwrap();
        s.session(&k, true);
        s.session(&[9; 32], true);
        assert_eq!(s.sessions(), vec![(k, 1)]);
        s.session(&k, false);
        assert_eq!(s.sessions(), vec![(k, 0)]);
    }
}
