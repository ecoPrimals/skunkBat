// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! First-byte peek wrapper for async streams.
//!
//! `tokio::net::UnixStream` lacks `peek()`. This wrapper reads one byte
//! destructively via the caller, then replays it on the first `poll_read`.
//! Both `AsyncRead` and `AsyncWrite` are delegated so the wrapper is a
//! transparent drop-in for any stream type.

use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct PeekedStream<S> {
    pub peeked: Option<u8>,
    pub inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for PeekedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if let Some(byte) = this.peeked.take() {
            buf.put_slice(&[byte]);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PeekedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn replays_byte() {
        let inner = std::io::Cursor::new(b"ello world");
        let mut ps = PeekedStream {
            peeked: Some(b'h'),
            inner,
        };

        let mut buf = vec![0u8; 11];
        let n = ps.read(&mut buf).await.unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf[0], b'h');

        let n2 = ps.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n2], b"ello world");
    }

    #[tokio::test]
    async fn json_detection() {
        let inner = std::io::Cursor::new(b"\"jsonrpc\":\"2.0\"}");
        let mut ps = PeekedStream {
            peeked: Some(b'{'),
            inner,
        };

        let mut buf = [0u8; 32];
        let mut total = 0;
        loop {
            let n = ps.read(&mut buf[total..]).await.unwrap();
            if n == 0 {
                break;
            }
            total += n;
        }
        assert_eq!(&buf[..total], b"{\"jsonrpc\":\"2.0\"}");
    }

    #[tokio::test]
    async fn write_passthrough() {
        let inner = Vec::<u8>::new();
        let mut ps = PeekedStream {
            peeked: Some(b'x'),
            inner,
        };

        ps.write_all(b"hello").await.unwrap();
        ps.flush().await.unwrap();
        assert_eq!(&ps.inner, b"hello");
    }
}
