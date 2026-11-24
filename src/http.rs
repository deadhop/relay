//! Just enough HTTP/1.1: one request head per connection, either a WebSocket
//! upgrade or a page. Heads are capped in size and time.

use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

/// Largest request head accepted.
pub const MAX_HEAD: usize = 8 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
}

impl Request {
    /// A header's value; names are compared without case.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn has_token(&self, name: &str, token: &str) -> bool {
        self.header(name)
            .is_some_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
    }

    /// The `Sec-WebSocket-Key` of a valid WebSocket upgrade request.
    pub fn websocket_key(&self) -> Option<&str> {
        let ok = self.method == "GET"
            && self.has_token("upgrade", "websocket")
            && self.has_token("connection", "upgrade")
            && self.header("sec-websocket-version") == Some("13");
        self.header("sec-websocket-key").filter(|_| ok)
    }

    /// The client's address: the peer, or what a trusted proxy says it is
    /// (the last `X-Forwarded-For` entry, which that proxy appended).
    pub fn client_ip(&self, peer: IpAddr, trusted: &[IpAddr]) -> IpAddr {
        if !trusted.contains(&peer) {
            return peer;
        }
        // Only the last entry: the one our proxy appended. X-Real-IP is not
        // read, because some proxies pass a client's own value through.
        let said = self.header("x-forwarded-for").and_then(|v| v.rsplit(',').next());
        said.and_then(|v| v.trim().parse().ok()).unwrap_or(peer)
    }
}

/// Parse a complete head. `Ok(None)` means more bytes are needed.
pub fn parse(buf: &[u8]) -> Result<Option<(Request, usize)>, httparse::Error> {
    let mut headers = [httparse::EMPTY_HEADER; 48];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(buf) {
        Ok(httparse::Status::Complete(n)) => {
            let headers = req
                .headers
                .iter()
                .map(|h| (h.name.to_string(), String::from_utf8_lossy(h.value).into_owned()))
                .collect();
            let r = Request {
                method: req.method.unwrap_or_default().to_string(),
                path: req.path.unwrap_or_default().to_string(),
                headers,
            };
            Ok(Some((r, n)))
        }
        Ok(httparse::Status::Partial) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Read one request head. Bytes after it are kept for the WebSocket.
pub async fn read_head(stream: &mut TcpStream) -> io::Result<(Request, Vec<u8>)> {
    read_head_after(stream, Vec::with_capacity(1024)).await
}

/// Read one request head whose first bytes, `buf`, were already read (after
/// Tor's PROXY line, say).
pub async fn read_head_after(stream: &mut TcpStream, mut buf: Vec<u8>) -> io::Result<(Request, Vec<u8>)> {
    let mut chunk = [0u8; 2048];
    loop {
        match parse(&buf) {
            Ok(Some((req, used))) => return Ok((req, buf.split_off(used))),
            Ok(None) if buf.len() < MAX_HEAD => {}
            _ => return Err(io::ErrorKind::InvalidData.into()),
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// A response with a body; the connection closes after it.
pub struct Response {
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16, content_type: &str, body: impl Into<Vec<u8>>) -> Response {
        Response {
            status,
            headers: vec![("Content-Type", content_type.into())],
            body: body.into(),
        }
    }

    pub fn header(mut self, name: &'static str, value: &str) -> Response {
        self.headers.push((name, value.into()));
        self
    }

    pub fn text(status: u16, body: &str) -> Response {
        Response::new(status, "text/plain; charset=utf-8", body)
    }

    pub fn bytes(&self, head_only: bool) -> Vec<u8> {
        let reason = match self.status {
            200 => "OK",
            404 => "Not Found",
            405 => "Method Not Allowed",
            503 => "Service Unavailable",
            _ => "Bad Request",
        };
        let mut out = format!("HTTP/1.1 {} {reason}\r\n", self.status);
        for (n, v) in &self.headers {
            out.push_str(&format!("{n}: {v}\r\n"));
        }
        out.push_str(&format!(
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            self.body.len()
        ));
        let mut bytes = out.into_bytes();
        if !head_only {
            bytes.extend_from_slice(&self.body);
        }
        bytes
    }
}

pub async fn respond(stream: &mut TcpStream, r: Response, head_only: bool) -> io::Result<()> {
    stream.write_all(&r.bytes(head_only)).await?;
    stream.shutdown().await
}

/// The handshake answer for a WebSocket upgrade.
pub fn switching(key: &str) -> String {
    let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
    format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    )
}

/// A TCP stream that first replays bytes read past the request head.
pub struct Prefixed {
    prefix: Vec<u8>,
    pos: usize,
    inner: TcpStream,
}

impl Prefixed {
    pub fn new(prefix: Vec<u8>, inner: TcpStream) -> Prefixed {
        Prefixed { prefix, pos: 0, inner }
    }
}

impl AsyncRead for Prefixed {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.pos < self.prefix.len() {
            let n = (self.prefix.len() - self.pos).min(buf.remaining());
            let start = self.pos;
            buf.put_slice(&self.prefix[start..start + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Prefixed {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    const UPGRADE: &str = "GET / HTTP/1.1\r\nHost: relay.example\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";

    #[test]
    fn recognises_websocket_upgrades() {
        let (r, n) = parse(UPGRADE.as_bytes()).unwrap().unwrap();
        assert_eq!(n, UPGRADE.len());
        assert_eq!(r.websocket_key(), Some("dGhlIHNhbXBsZSBub25jZQ=="));
        assert_eq!(r.header("HOST"), Some("relay.example"));
        assert!(switching("dGhlIHNhbXBsZSBub25jZQ==").contains("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
        let plain = parse(b"GET /x HTTP/1.1\r\nAccept: text/html\r\n\r\n")
            .unwrap()
            .unwrap()
            .0;
        assert_eq!(plain.websocket_key(), None);
        assert_eq!(plain.path, "/x");
        assert_eq!(parse(b"GET / HTTP/1.1\r\nHost"), Ok(None));
        assert!(parse(b"\x00\x01 nonsense\r\n\r\n").is_err());
    }

    #[test]
    fn believes_only_trusted_proxies() {
        let r = Request {
            method: "GET".into(),
            path: "/".into(),
            headers: vec![("X-Forwarded-For".into(), "1.1.1.1, 2.2.2.2".into())],
        };
        let proxy: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(r.client_ip(proxy, &[]), proxy);
        assert_eq!(r.client_ip(proxy, &[proxy]), "2.2.2.2".parse::<IpAddr>().unwrap());
        // X-Real-IP can be the client's own, passed through by the proxy: ignored.
        let mut real = r.clone();
        real.headers.push(("X-Real-IP".into(), "3.3.3.3".into()));
        assert_eq!(real.client_ip(proxy, &[proxy]), "2.2.2.2".parse::<IpAddr>().unwrap());
        let mut junk = r.clone();
        junk.headers = vec![("X-Forwarded-For".into(), "nope".into())];
        assert_eq!(junk.client_ip(proxy, &[proxy]), proxy);
    }

    #[test]
    fn responses() {
        let r = Response::text(404, "no").header("X-A", "b");
        let s = String::from_utf8(r.bytes(false)).unwrap();
        assert!(s.starts_with("HTTP/1.1 404 Not Found\r\n") && s.contains("X-A: b\r\n") && s.ends_with("\r\n\r\nno"));
        assert!(!String::from_utf8(r.bytes(true)).unwrap().ends_with("no"));
        for (code, word) in [(200, "OK"), (405, "Method"), (503, "Unavailable"), (400, "Bad Request")] {
            assert!(String::from_utf8(Response::text(code, "").bytes(true))
                .unwrap()
                .contains(word));
        }
    }

    #[tokio::test]
    async fn reads_heads_and_keeps_the_rest() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut c = TcpStream::connect(addr).await.unwrap();
            c.write_all(format!("{UPGRADE}extra").as_bytes()).await.unwrap();
            let mut back = vec![0u8; 4];
            c.read_exact(&mut back).await.unwrap();
            back
        });
        let (mut s, _) = l.accept().await.unwrap();
        let (req, rest) = read_head(&mut s).await.unwrap();
        assert!(req.websocket_key().is_some());
        assert_eq!(rest, b"extra", "one small write arrives in one read on loopback");
        let mut p = Prefixed::new(rest, s);
        let mut got = [0u8; 3];
        p.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ext");
        let mut got = [0u8; 2];
        p.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ra");
        p.write_all(b"back").await.unwrap();
        p.flush().await.unwrap();
        assert_eq!(client.await.unwrap(), b"back");
        p.shutdown().await.unwrap();
        let mut more = [0u8; 1];
        assert_eq!(p.read(&mut more).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn refuses_endless_or_cut_heads() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let mut c = TcpStream::connect(addr).await.unwrap();
            let _ = c
                .write_all(format!("GET / HTTP/1.1\r\nX: {}\r\n", "a".repeat(MAX_HEAD)).as_bytes())
                .await;
            let mut c = TcpStream::connect(addr).await.unwrap();
            c.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        });
        let (mut s, _) = l.accept().await.unwrap();
        assert_eq!(read_head(&mut s).await.unwrap_err().kind(), io::ErrorKind::InvalidData);
        let (mut s, _) = l.accept().await.unwrap();
        assert_eq!(
            read_head(&mut s).await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}
