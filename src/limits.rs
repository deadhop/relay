//! Rate limits and per-address connection accounting.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// A token bucket: `rate` tokens a second, holding at most `burst`.
#[derive(Debug, Clone)]
pub struct Bucket {
    tokens: f64,
    rate: f64,
    burst: f64,
    last: Instant,
}

impl Bucket {
    pub fn new(rate_per_sec: f64, burst: f64, now: Instant) -> Bucket {
        Bucket {
            tokens: burst,
            rate: rate_per_sec,
            burst,
            last: now,
        }
    }

    /// A bucket for `n` a minute that may burst to `n`.
    pub fn per_minute(n: u32, now: Instant) -> Bucket {
        Bucket::new(f64::from(n) / 60.0, f64::from(n), now)
    }

    fn refill(&mut self, now: Instant) {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + dt * self.rate).min(self.burst);
        self.last = now;
    }

    /// Take one token if there is one.
    pub fn take(&mut self, now: Instant) -> bool {
        self.refill(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Whether the bucket has refilled completely by `now`.
    pub fn is_full(&mut self, now: Instant) -> bool {
        self.refill(now);
        self.tokens >= self.burst
    }
}

/// Where connections come from, for limits: an IPv4 address, or the /64 an
/// IPv6 address sits in (one host usually holds a whole /64).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Origin {
    V4(u32),
    V6(u64),
}

impl Origin {
    pub fn of(ip: IpAddr) -> Origin {
        match ip {
            IpAddr::V4(v4) => Origin::V4(u32::from(v4)),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => Origin::V4(u32::from(v4)),
                None => Origin::V6((u128::from(v6) >> 64) as u64),
            },
        }
    }
}

/// Probation slots one address may hold at once, so no single address can
/// fill the slots kept for whitelisted keys.
pub const PROBATION_PER_ADDRESS: usize = 2;

struct PerOrigin {
    conns: usize,
    probation: usize,
    events: Bucket,
}

/// Open connections and the public write budget of each origin.
pub struct Origins {
    map: HashMap<Origin, PerOrigin>,
    events_per_min: u32,
}

/// What [`Origins::connect`] decided.
#[derive(Debug, PartialEq, Eq)]
pub enum Admit {
    /// Within the limits.
    Open,
    /// Over a limit: kept only if it authenticates as a whitelisted key.
    Probation,
}

impl Origins {
    pub fn new(events_per_min: u32) -> Origins {
        Origins {
            map: HashMap::new(),
            events_per_min,
        }
    }

    /// Count a new connection from `o`; `per_origin` is the limit.
    pub fn connect(&mut self, o: Origin, per_origin: usize, now: Instant) -> Admit {
        let rate = self.events_per_min;
        let e = self.map.entry(o).or_insert_with(|| PerOrigin {
            conns: 0,
            probation: 0,
            events: Bucket::per_minute(rate, now),
        });
        e.conns += 1;
        if e.conns > per_origin {
            Admit::Probation
        } else {
            Admit::Open
        }
    }

    /// Take one of `o`'s probation slots, if it has one left.
    pub fn take_probation(&mut self, o: Origin) -> bool {
        match self.map.get_mut(&o) {
            Some(e) if e.probation < PROBATION_PER_ADDRESS => {
                e.probation += 1;
                true
            }
            _ => false,
        }
    }

    pub fn end_probation(&mut self, o: Origin) {
        if let Some(e) = self.map.get_mut(&o) {
            e.probation = e.probation.saturating_sub(1);
        }
    }

    pub fn disconnect(&mut self, o: Origin) {
        if let Some(e) = self.map.get_mut(&o) {
            e.conns = e.conns.saturating_sub(1);
        }
    }

    /// Take one public write from `o`'s budget.
    pub fn take_event(&mut self, o: Origin, now: Instant) -> bool {
        let rate = self.events_per_min;
        self.map
            .entry(o)
            .or_insert_with(|| PerOrigin {
                conns: 0,
                probation: 0,
                events: Bucket::per_minute(rate, now),
            })
            .events
            .take(now)
    }

    /// Forget origins with no connection whose budget has refilled.
    pub fn purge(&mut self, now: Instant) {
        self.map.retain(|_, e| e.conns > 0 || !e.events.is_full(now));
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Seconds since the Unix epoch.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_refill_over_time() {
        let t = Instant::now();
        let mut b = Bucket::new(2.0, 2.0, t);
        assert!(b.take(t) && b.take(t) && !b.take(t));
        assert!(!b.is_full(t));
        assert!(b.take(t + Duration::from_millis(500)));
        assert!(b.is_full(t + Duration::from_secs(10)));
        let mut m = Bucket::per_minute(60, t);
        for _ in 0..60 {
            assert!(m.take(t));
        }
        assert!(!m.take(t));
        assert!(m.take(t + Duration::from_secs(1)));
    }

    #[test]
    fn ipv6_counts_by_64_and_mapped_v4_as_v4() {
        let a: IpAddr = "2001:db8::1".parse().unwrap();
        let b: IpAddr = "2001:db8::ffff:2".parse().unwrap();
        let c: IpAddr = "2001:db8:0:1::1".parse().unwrap();
        assert_eq!(Origin::of(a), Origin::of(b));
        assert_ne!(Origin::of(a), Origin::of(c));
        assert_eq!(
            Origin::of("::ffff:10.0.0.1".parse().unwrap()),
            Origin::of("10.0.0.1".parse().unwrap())
        );
    }

    #[test]
    fn origins_put_extra_connections_on_probation() {
        let t = Instant::now();
        let mut o = Origins::new(2);
        let x = Origin::of("10.0.0.1".parse().unwrap());
        assert_eq!(o.connect(x, 2, t), Admit::Open);
        assert_eq!(o.connect(x, 2, t), Admit::Open);
        assert_eq!(o.connect(x, 2, t), Admit::Probation);
        assert!(o.take_event(x, t) && o.take_event(x, t) && !o.take_event(x, t));
        // Two probation slots per address, then none until one is given back.
        assert!(o.take_probation(x) && o.take_probation(x) && !o.take_probation(x));
        o.end_probation(x);
        assert!(o.take_probation(x));
        assert!(!o.take_probation(Origin::V4(12345)), "unknown address");
        o.end_probation(Origin::V4(12345));
        for _ in 0..3 {
            o.disconnect(x);
        }
        o.disconnect(Origin::V4(7));
        o.purge(t);
        assert_eq!(o.len(), 1, "kept while its budget refills");
        o.purge(t + Duration::from_secs(120));
        assert!(o.is_empty());
        // A write from an address with no connection still counts.
        assert!(o.take_event(Origin::V4(9), t));
        assert!(unix_now() > 1_700_000_000);
    }
}
