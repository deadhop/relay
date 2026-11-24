//! I2P: an i2pd server tunnel of `type = http` whose `host`/`port` point at
//! this adapter's listener.
//!
//! i2pd's HTTP server tunnel removes every `X-I2P*` header the client sent,
//! then adds `X-I2P-DestHash` (the client destination's hash, in I2P's
//! Base64), `X-I2P-DestB64` and `X-I2P-DestB32`. It keeps `Connection:
//! Upgrade`, so WebSockets pass, and forwards the rest of the stream as is.
//! The destination hash is the client's identity here. A plain `server`
//! tunnel adds nothing, and is refused: every client would look the same.

use sha2::{Digest, Sha256};

use crate::http::Request;

pub const HEADER: &str = "x-i2p-desthash";

/// The client's destination, from the header i2pd added: 32 bytes in I2P's
/// Base64 (`-` and `~` for `+` and `/`), so 44 characters.
pub fn destination(req: &Request) -> Option<u128> {
    let v = req.header(HEADER)?.trim();
    let ok = v.len() == 44
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'~' || b == b'=');
    // Hashed down: limits only need to tell destinations apart.
    ok.then(|| u128::from_be_bytes(Sha256::digest(v.as_bytes())[..16].try_into().expect("16 bytes")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(headers: &[(&str, &str)]) -> Request {
        Request {
            method: "GET".into(),
            path: "/".into(),
            headers: headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        }
    }

    #[test]
    fn destinations_from_the_tunnel_header() {
        let a = "z~5mQ0xH9Rk-J2uW8n1VbT3lYc6pFsA4eDgHiKjLmNo=";
        let b = "Az~5mQ0xH9Rk-J2uW8n1VbT3lYc6pFsA4eDgHiKjLmN=";
        let da = destination(&req(&[("X-I2P-DestHash", a)])).unwrap();
        assert_eq!(destination(&req(&[("x-i2p-desthash", &format!(" {a} "))])), Some(da));
        assert_ne!(destination(&req(&[("X-I2P-DestHash", b)])), Some(da));
        assert_eq!(destination(&req(&[])), None, "a plain server tunnel");
        assert_eq!(destination(&req(&[("X-I2P-DestHash", "short")])), None);
        assert_eq!(destination(&req(&[("X-I2P-DestHash", &"/".repeat(44))])), None);
    }
}
