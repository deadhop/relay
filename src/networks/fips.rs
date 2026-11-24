//! FIPS: the relay listens on this node's FIPS address, and clients reach it
//! at `ws://npub1….fips:<port>`.
//!
//! FIPS gives every node an address in fd00::/8 derived from its Nostr key,
//! and peers arrive from their own address, so the peer address is the
//! client's identity, whole (not by /64, as on clearnet). A peer from
//! outside fd00::/8 did not come over FIPS and is turned away. fd00::/8 is
//! all of private IPv6, though, so the docs say to bind to the node's own
//! address rather than `[::]`.

use std::net::IpAddr;

/// The peer's FIPS address, if it has one.
pub fn node(peer: IpAddr) -> Option<u128> {
    match peer {
        IpAddr::V6(v6) if v6.octets()[0] == 0xfd => Some(u128::from(v6)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_fips_addresses() {
        let a: IpAddr = "fd3c:1a2b:3c4d:5e6f:7081:92a3:b4c5:d6e7".parse().unwrap();
        let b: IpAddr = "fd3c:1a2b:3c4d:5e6f:7081:92a3:b4c5:d6e8".parse().unwrap();
        assert!(node(a).is_some() && node(a) != node(b), "whole addresses, not /64s");
        for other in ["127.0.0.1", "::1", "2001:db8::1", "fc00::1", "fe80::1"] {
            assert_eq!(node(other.parse().unwrap()), None, "{other}");
        }
    }
}
