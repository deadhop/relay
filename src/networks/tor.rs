//! Tor: an onion service whose `HiddenServicePort` points at this adapter's
//! listener, with `HiddenServiceExportCircuitID haproxy`.
//!
//! Every connection then starts with a PROXY protocol (v1) line, written by
//! Tor before anything the client sends. The circuit's global identifier is
//! the low 32 bits of the source address, inside `fc00:dead:beef:4dad::/64`:
//!
//! ```text
//! PROXY TCP6 fc00:dead:beef:4dad::0:29a ::1 666 42\r\n      (circuit 666, onion port 42)
//! ```
//!
//! (Tor's `export_hs_client_circuit_id`, and the lines its unit tests expect.)
//! The circuit is the only thing that tells two clients of an onion service
//! apart.

use std::io;
use std::net::Ipv6Addr;

use tokio::io::{AsyncRead, AsyncReadExt};

/// A PROXY v1 line is at most 107 bytes, the CRLF included.
pub const MAX_LINE: usize = 107;

/// The /64 Tor puts circuits in.
const CIRCUITS: u64 = 0xfc00_dead_beef_4dad;

/// The circuit identifier in Tor's PROXY line (without its CRLF).
pub fn circuit(line: &str) -> Option<u32> {
    let parts: Vec<&str> = line.split(' ').collect();
    let [proxy, family, src, _dst, sport, dport] = parts[..] else {
        return None;
    };
    let src = src.parse::<Ipv6Addr>().ok().map(u128::from)?;
    let ok = proxy == "PROXY"
        && family == "TCP6"
        && (src >> 64) as u64 == CIRCUITS
        && (src >> 32) as u32 == 0
        && sport.parse::<u16>().is_ok()
        && dport.parse::<u16>().is_ok();
    ok.then_some(src as u32)
}

/// Read Tor's PROXY line. Gives the circuit and whatever followed the line
/// in the same reads (the start of the HTTP request).
pub async fn preamble(s: &mut (dyn AsyncRead + Unpin + Send)) -> io::Result<(u32, Vec<u8>)> {
    let mut buf = Vec::with_capacity(256);
    let mut chunk = [0u8; 256];
    loop {
        if let Some(end) = buf.windows(2).position(|w| w == b"\r\n") {
            let line = std::str::from_utf8(&buf[..end]).map_err(|_| io::ErrorKind::InvalidData)?;
            let gid = circuit(line).ok_or(io::ErrorKind::InvalidData)?;
            return Ok((gid, buf.split_off(end + 2)));
        }
        if buf.len() >= MAX_LINE {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circuits_from_tor_lines() {
        // The lines Tor's own unit test (test_hs_service.c) expects, for
        // circuits 666, UINT32_MAX, UINT16_MAX and UINT16_MAX + 7.
        assert_eq!(circuit("PROXY TCP6 fc00:dead:beef:4dad::0:29a ::1 666 42"), Some(666));
        assert_eq!(
            circuit("PROXY TCP6 fc00:dead:beef:4dad::ffff:ffff ::1 65535 42"),
            Some(u32::MAX)
        );
        assert_eq!(
            circuit("PROXY TCP6 fc00:dead:beef:4dad::0:ffff ::1 65535 42"),
            Some(65_535)
        );
        assert_eq!(circuit("PROXY TCP6 fc00:dead:beef:4dad::1:6 ::1 6 42"), Some(65_542));
        for bad in [
            "PROXY TCP4 1.2.3.4 5.6.7.8 1 2",
            "PROXY TCP6 fc00:dead:beef:4dad:1:29 ::1 41 80",
            "PROXY TCP6 fc00:dead:beef:4dae::1:6 ::1 6 42",
            "PROXY TCP6 fc00:dead:beef:4dad:0:1:0:6 ::1 6 42",
            "PROXY TCP6 2001:db8::1 ::1 6 42",
            "PROXY TCP6 fc00:dead:beef:4dad::1:6 ::1 x 42",
            "PROXY TCP6 fc00:dead:beef:4dad::1:6 ::1 6 x",
            "PROXY TCP6 fc00:dead:beef:4dad::1:6 ::1 6",
            "proxy TCP6 fc00:dead:beef:4dad::1:6 ::1 6 42",
            "PROXY UNKNOWN fc00:dead:beef:4dad::1:6 ::1 6 42",
            "GET / HTTP/1.1",
        ] {
            assert_eq!(circuit(bad), None, "{bad}");
        }
    }

    #[tokio::test]
    async fn the_line_in_pieces_and_joined_to_the_request() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let w = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            b.write_all(b"PROXY TCP6 fc00:dead:").await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            b.write_all(b"beef:4dad::0:7 ::1 7 80\r\nGET / HTTP/1.1\r\n")
                .await
                .unwrap();
            b
        });
        let (gid, rest) = preamble(&mut a).await.unwrap();
        assert_eq!((gid, rest.as_slice()), (7, &b"GET / HTTP/1.1\r\n"[..]));
        drop(w.await);
    }

    #[tokio::test]
    async fn no_line_no_connection() {
        let mut long = &[b'P'; 300][..];
        assert_eq!(
            preamble(&mut long).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let mut http = &b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"[..];
        assert_eq!(
            preamble(&mut http).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let mut binary = &b"PROXY \xff\r\n"[..];
        assert_eq!(
            preamble(&mut binary).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let mut short = &b"PROXY TCP6"[..];
        assert_eq!(
            preamble(&mut short).await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}
