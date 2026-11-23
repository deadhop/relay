//! Counters for the status pages. All lock-free except the per-minute history.

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Mutex;

use serde::Serialize;

use crate::config::Whitelist;
use crate::event::Key;

/// Why an event or subscription was refused: the NIP-01 machine-readable prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Invalid,
    Restricted,
    AuthRequired,
    RateLimited,
    Pow,
    Duplicate,
    Blocked,
}

pub const REASONS: [Reason; 7] = [
    Reason::Invalid,
    Reason::Restricted,
    Reason::AuthRequired,
    Reason::RateLimited,
    Reason::Pow,
    Reason::Duplicate,
    Reason::Blocked,
];

impl Reason {
    pub fn prefix(self) -> &'static str {
        match self {
            Reason::Invalid => "invalid",
            Reason::Restricted => "restricted",
            Reason::AuthRequired => "auth-required",
            Reason::RateLimited => "rate-limited",
            Reason::Pow => "pow",
            Reason::Duplicate => "duplicate",
            Reason::Blocked => "blocked",
        }
    }

    /// The reason a message starting with a known prefix stands for.
    pub fn of(message: &str) -> Reason {
        let p = message.split(':').next().unwrap_or_default();
        REASONS.into_iter().find(|r| r.prefix() == p).unwrap_or(Reason::Invalid)
    }
}

/// Traffic to and from one whitelisted key.
#[derive(Default)]
pub struct KeyCounters {
    /// Events addressed to the key (requests).
    pub inbound: AtomicU64,
    /// Events the key published (replies, announcements).
    pub outbound: AtomicU64,
    /// Connections authenticated as the key right now.
    pub sessions: AtomicU64,
}

/// One minute of history: events accepted, deliveries, refusals.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct Minute {
    pub minute: u64,
    pub accepted: u64,
    pub delivered: u64,
    pub refused: u64,
}

pub const HISTORY: usize = 60;

#[derive(Default)]
pub struct Stats {
    pub connections_open: AtomicU64,
    pub connections_total: AtomicU64,
    /// Connections turned away at the door (over every limit, or bad HTTP).
    pub connections_refused: AtomicU64,
    /// Connections closed for failing to authenticate while on probation.
    pub probation_closed: AtomicU64,
    /// Connections closed because they read too slowly.
    pub slow_closed: AtomicU64,
    pub events_trusted: AtomicU64,
    pub events_public: AtomicU64,
    pub events_probe: AtomicU64,
    pub refused: [AtomicU64; 7],
    pub deliveries: AtomicU64,
    /// Accepted events not queued to a live matching subscription. Should stay 0.
    pub dropped: AtomicU64,
    /// Events kept because nobody was subscribed when they arrived.
    pub held: AtomicU64,
    pub subscriptions: AtomicU64,
    pub auth_ok: AtomicU64,
    pub auth_failed: AtomicU64,
    /// Valid AUTH by keys that are not whitelisted (accepted, worth nothing).
    pub auth_other: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    keys: Vec<(Key, KeyCounters)>,
    history: Mutex<Vec<Minute>>,
}

impl Stats {
    pub fn new(wl: &Whitelist) -> Stats {
        Stats {
            keys: wl.entries().iter().map(|(k, _)| (*k, KeyCounters::default())).collect(),
            ..Stats::default()
        }
    }

    pub fn key(&self, k: &Key) -> Option<&KeyCounters> {
        self.keys.iter().find(|(x, _)| x == k).map(|(_, c)| c)
    }

    pub fn refuse(&self, r: Reason, minute: u64) {
        self.refused[REASONS.iter().position(|x| *x == r).expect("every reason is listed")].fetch_add(1, Relaxed);
        self.record(minute, |m| m.refused += 1);
    }

    pub fn refused(&self, r: Reason) -> u64 {
        self.refused[REASONS.iter().position(|x| *x == r).expect("every reason is listed")].load(Relaxed)
    }

    pub fn accepted(&self, minute: u64, delivered: u64) {
        self.deliveries.fetch_add(delivered, Relaxed);
        self.record(minute, |m| {
            m.accepted += 1;
            m.delivered += delivered;
        });
    }

    fn record(&self, minute: u64, f: impl FnOnce(&mut Minute)) {
        let mut h = self.history.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if h.last().is_none_or(|m| m.minute != minute) {
            h.push(Minute {
                minute,
                ..Minute::default()
            });
            if h.len() > HISTORY {
                h.remove(0);
            }
        }
        f(h.last_mut().expect("just pushed"));
    }

    /// The last hour, one entry per minute, oldest first, gaps filled with zeros.
    pub fn history(&self, now_minute: u64) -> Vec<Minute> {
        let h = self.history.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        (now_minute + 1 - HISTORY as u64..=now_minute)
            .map(|m| {
                h.iter().find(|x| x.minute == m).copied().unwrap_or(Minute {
                    minute: m,
                    ..Minute::default()
                })
            })
            .collect()
    }

    pub fn refused_total(&self) -> u64 {
        self.refused.iter().map(|a| a.load(Relaxed)).sum()
    }

    pub fn events_total(&self) -> u64 {
        self.events_trusted.load(Relaxed) + self.events_public.load(Relaxed) + self.events_probe.load(Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::{config, HEX};
    use crate::config::{parse_key, ENV_WHITELIST};

    #[test]
    fn reasons_round_trip() {
        for r in REASONS {
            assert_eq!(Reason::of(&format!("{}: why", r.prefix())), r);
        }
        assert_eq!(Reason::of("whatever"), Reason::Invalid);
    }

    #[test]
    fn counts_and_keeps_an_hour() {
        let wl = config(&[(ENV_WHITELIST, HEX)]).unwrap().whitelist;
        let s = Stats::new(&wl);
        assert!(s.key(&parse_key(HEX).unwrap()).is_some());
        assert!(s.key(&[0; 32]).is_none());
        s.refuse(Reason::Pow, 10);
        s.accepted(10, 3);
        s.accepted(11, 0);
        assert_eq!(s.refused(Reason::Pow), 1);
        assert_eq!(s.refused_total(), 1);
        assert_eq!(s.deliveries.load(Relaxed), 3);
        let h = s.history(70);
        assert_eq!(h.len(), HISTORY);
        assert_eq!(h[0].minute, 11);
        assert_eq!(h[0].accepted, 1);
        assert_eq!(
            h[59],
            Minute {
                minute: 70,
                ..Minute::default()
            }
        );
        for m in 12..80 {
            s.accepted(m, 1);
        }
        assert_eq!(s.history(79).iter().map(|m| m.accepted).sum::<u64>(), 60);
        s.events_probe.fetch_add(2, Relaxed);
        assert_eq!(s.events_total(), 2);
    }
}
