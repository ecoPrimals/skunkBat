// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Transport-agnostic listener (G66 server-side transport abstraction).
//!
//! Mirrors [`super::stream::TransportStream`] for the accept side.
//! Business logic calls `listener.accept()` and gets back a
//! [`TransportStream`] without knowing the underlying mechanism.

use super::stream::TransportStream;
use skunk_bat_integrations::TransportEndpoint;
use std::io;

/// A transport-agnostic listener that accepts incoming connections.
///
/// On Unix: can bind to UDS or TCP.
/// On non-Unix: only TCP is available (UDS binding returns an error).
#[derive(Debug)]
pub enum TransportListener {
    /// Unix domain socket listener.
    #[cfg(unix)]
    Unix(tokio::net::UnixListener),
    /// TCP listener.
    Tcp(tokio::net::TcpListener),
}

impl TransportListener {
    /// Accept the next incoming connection.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if accept fails.
    pub async fn accept(&self) -> io::Result<TransportStream> {
        match self {
            #[cfg(unix)]
            Self::Unix(l) => {
                let (stream, _) = l.accept().await?;
                Ok(TransportStream::Unix(stream))
            }
            Self::Tcp(l) => {
                let (stream, _) = l.accept().await?;
                Ok(TransportStream::Tcp(stream))
            }
        }
    }

    /// Transport kind for logging/diagnostics.
    #[must_use]
    pub const fn transport_name(&self) -> &'static str {
        match self {
            #[cfg(unix)]
            Self::Unix(_) => "uds",
            Self::Tcp(_) => "tcp",
        }
    }

    /// Whether this listener accepts only local connections.
    #[must_use]
    #[allow(dead_code, reason = "G66 API — available for auth/trust decisions")]
    pub fn is_local(&self) -> bool {
        match self {
            #[cfg(unix)]
            Self::Unix(_) => true,
            Self::Tcp(l) => l
                .local_addr()
                .map(|a| a.ip().is_loopback())
                .unwrap_or(false),
        }
    }
}

/// Bind a listener from a [`TransportEndpoint`].
///
/// For UDS: creates parent directory, removes stale socket, and binds.
/// For TCP: binds on `host:port`.
/// For `MeshRelay`: returns an error (not directly bindable).
///
/// # Errors
///
/// Returns `io::Error` on bind failure or unsupported endpoint type.
pub async fn bind_transport(endpoint: &TransportEndpoint) -> io::Result<TransportListener> {
    match endpoint {
        #[cfg(unix)]
        TransportEndpoint::Uds { path } => {
            let socket_path = std::path::PathBuf::from(path);
            if let Some(parent) = socket_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let _ = std::fs::remove_file(&socket_path);
            let listener = tokio::net::UnixListener::bind(&socket_path)?;
            Ok(TransportListener::Unix(listener))
        }
        #[cfg(not(unix))]
        TransportEndpoint::Uds { path } => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("UDS not available on this platform for {path}"),
        )),
        TransportEndpoint::Tcp { host, port } => {
            let addr = format!("{host}:{port}");
            let listener = tokio::net::TcpListener::bind(&addr).await?;
            Ok(TransportListener::Tcp(listener))
        }
        TransportEndpoint::MeshRelay {
            peer_id,
            capability,
        } => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "mesh relay ({peer_id}/{capability}) cannot be bound — \
                 register with songBird and let it route traffic"
            ),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn bind_tcp_and_accept() {
        let ep = TransportEndpoint::Tcp {
            host: "127.0.0.1".to_owned(),
            port: 0,
        };
        let listener = bind_transport(&ep).await.unwrap();
        assert_eq!(listener.transport_name(), "tcp");
        assert!(listener.is_local());

        let addr = match &listener {
            TransportListener::Tcp(l) => l.local_addr().unwrap(),
            #[cfg(unix)]
            _ => unreachable!(),
        };

        let server = tokio::spawn(async move {
            let mut stream = listener.accept().await.unwrap();
            assert_eq!(stream.transport_name(), "tcp");
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            stream.write_all(&buf).await.unwrap();
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        client.write_all(b"echo").await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"echo");

        server.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bind_uds_and_accept() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let sock = tmp.path().to_owned();
        drop(tmp);

        let ep = TransportEndpoint::Uds {
            path: sock.to_string_lossy().into_owned(),
        };
        let listener = bind_transport(&ep).await.unwrap();
        assert_eq!(listener.transport_name(), "uds");
        assert!(listener.is_local());

        let server = tokio::spawn(async move {
            let mut stream = listener.accept().await.unwrap();
            assert_eq!(stream.transport_name(), "uds");
            let mut buf = [0u8; 3];
            stream.read_exact(&mut buf).await.unwrap();
            stream.write_all(&buf).await.unwrap();
        });

        let mut client = tokio::net::UnixStream::connect(&sock).await.unwrap();
        client.write_all(b"hey").await.unwrap();
        let mut buf = [0u8; 3];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hey");

        server.await.unwrap();
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn bind_mesh_relay_unsupported() {
        let ep = TransportEndpoint::MeshRelay {
            peer_id: "peer".to_owned(),
            capability: "cap".to_owned(),
        };
        let result = bind_transport(&ep).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Unsupported);
    }
}
