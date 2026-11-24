//! Tor: an onion service whose `HiddenServicePort` points at this adapter's
//! listener, with `HiddenServiceExportCircuitID haproxy`.
//!
//! Every connection then starts with a PROXY protocol (v1) line, written by
//! Tor before anything the client sends:
//!
//! ```text
//! PROXY TCP6 fc00:dead:beef:4dad:<gid high 16 bits>:<gid low 16 bits> ::1 <src port> <onion port>\r\n
//! ```
//!
//! The circuit's global identifier is the only thing that tells two clients
//! of an onion service apart. The address is not valid IPv6 (six groups and
//! no `::`), so it is read here rather than parsed as an address.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt};

/// A PROXY v1 line is at most 107 bytes, the CRLF included.
pub const MAX_LINE: usize = 107;

const PREFIX: &str = "PROXY TCP6 fc00:dead:beef:4dad:";

/// The circuit identifier in Tor's PROXY line (without its CRLF).
pub fn circuit(line: &str) -> Option<u32> {
    let rest = line.strip_prefix(PREFIX)?;
    let mut parts = rest.split(' ');
    let src = parts.next()?;
    let (hi, lo) = src.split_once(':')?;
    let hi = u16::from_str_radix(hi, 16).ok()?;
    let lo = u16::from_str_radix(lo, 16).ok()?;
    let rest: Vec<&str> = parts.collect();
    // Destination address, source port, destination port.
    let ports_ok = rest.len() == 3 && rest[1].parse::<u16>().is_ok() && rest[2].parse::<u16>().is_ok();
    ports_ok.then_some((u32::from(hi) << 16) | u32::from(lo))
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
        // What Tor writes for global identifier 0x00010029 (65,577) on port 80.
        assert_eq!(
            circuit("PROXY TCP6 fc00:dead:beef:4dad:1:29 ::1 41 80"),
            Some(0x0001_0029)
        );
        assert_eq!(circuit("PROXY TCP6 fc00:dead:beef:4dad:0:0 ::1 1 80"), Some(0));
        assert_eq!(
            circuit("PROXY TCP6 fc00:dead:beef:4dad:ffff:ffff ::1 65535 7447"),
            Some(u32::MAX)
        );
        for bad in [
            "PROXY TCP4 1.2.3.4 5.6.7.8 1 2",
            "PROXY TCP6 fc00:dead:beef:4dad:1 ::1 1 80",
            "PROXY TCP6 fc00:dead:beef:4dad:1:2:3 ::1 1 80",
            "PROXY TCP6 fc00:dead:beef:4dad:g:1 ::1 1 80",
            "PROXY TCP6 fc00:dead:beef:4dad:1:g ::1 1 80",
            "PROXY TCP6 fc00:dead:beef:4dad:1:2 ::1 1",
            "PROXY TCP6 fc00:dead:beef:4dad:1:2 ::1 x 80",
            "PROXY TCP6 fc00:dead:beef:4dad:1:2 ::1 1 x",
            "PROXY TCP6 fc00:dead:beef:4dad:1:2",
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
            b.write_all(b"beef:4dad:0:7 ::1 7 80\r\nGET / HTTP/1.1\r\n")
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
