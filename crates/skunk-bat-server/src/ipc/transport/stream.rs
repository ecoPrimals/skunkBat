// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Transport-agnostic connected stream (G66).
//!
//! Business logic reads/writes to [`TransportStream`] without knowing whether
//! the underlying connection is UDS or TCP. All `#[cfg(unix)]` for stream
//! variants lives here — not scattered across IPC modules.

use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A transport-agnostic connected stream.
///
/// Wraps platform-specific stream types behind a unified `AsyncRead + AsyncWrite`
/// interface. The `Unix` variant only exists on Unix platforms.
#[derive(Debug)]
pub enum TransportStream {
    /// Connected Unix domain socket (local only).
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
    /// Connected TCP stream (local or remote).
    Tcp(tokio::net::TcpStream),
}

#[allow(
    dead_code,
    reason = "G66 public API — used in tests, available for callers"
)]
impl TransportStream {
    /// Transport kind for logging/diagnostics.
    #[must_use]
    pub const fn transport_name(&self) -> &'static str {
        match self {
            #[cfg(unix)]
            Self::Unix(_) => "uds",
            Self::Tcp(_) => "tcp",
        }
    }

    /// Whether this connection is local (UDS is always local, TCP checks loopback).
    #[must_use]
    pub fn is_local(&self) -> bool {
        match self {
            #[cfg(unix)]
            Self::Unix(_) => true,
            Self::Tcp(s) => s.peer_addr().map(|a| a.ip().is_loopback()).unwrap_or(false),
        }
    }

    /// Human-readable label for the peer (for logging).
    #[must_use]
    pub fn peer_label(&self) -> String {
        match self {
            #[cfg(unix)]
            Self::Unix(_) => "UDS".to_owned(),
            Self::Tcp(s) => s
                .peer_addr()
                .map_or_else(|_| "TCP unknown".to_owned(), |a| format!("TCP {a}")),
        }
    }

    /// Set `TCP_NODELAY` (no-op for UDS).
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the TCP socket option cannot be set.
    pub fn set_nodelay(&self, nodelay: bool) -> std::io::Result<()> {
        match self {
            #[cfg(unix)]
            Self::Unix(_) => Ok(()),
            Self::Tcp(s) => s.set_nodelay(nodelay),
        }
    }
}

impl AsyncRead for TransportStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            #[cfg(unix)]
            Self::Unix(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tcp(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TransportStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            #[cfg(unix)]
            Self::Unix(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tcp(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            #[cfg(unix)]
            Self::Unix(s) => Pin::new(s).poll_flush(cx),
            Self::Tcp(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            #[cfg(unix)]
            Self::Unix(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tcp(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn tcp_roundtrip() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ts = TransportStream::Tcp(stream);
            assert_eq!(ts.transport_name(), "tcp");
            assert!(ts.is_local());
            let mut buf = [0u8; 4];
            ts.read_exact(&mut buf).await.unwrap();
            ts.write_all(&buf).await.unwrap();
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut ts = TransportStream::Tcp(stream);
        ts.set_nodelay(true).unwrap();
        ts.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        ts.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        assert!(ts.peer_label().starts_with("TCP"));

        server.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn uds_roundtrip() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let sock = tmp.path().to_owned();
        drop(tmp);

        let listener = tokio::net::UnixListener::bind(&sock).unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ts = TransportStream::Unix(stream);
            assert_eq!(ts.transport_name(), "uds");
            assert!(ts.is_local());
            let mut buf = [0u8; 3];
            ts.read_exact(&mut buf).await.unwrap();
            ts.write_all(&buf).await.unwrap();
        });

        let stream = tokio::net::UnixStream::connect(&sock).await.unwrap();
        let mut ts = TransportStream::Unix(stream);
        ts.set_nodelay(true).unwrap();
        ts.write_all(b"hey").await.unwrap();
        let mut buf = [0u8; 3];
        ts.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hey");
        assert_eq!(ts.peer_label(), "UDS");

        server.await.unwrap();
        let _ = std::fs::remove_file(&sock);
    }
}
