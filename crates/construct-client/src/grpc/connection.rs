//! TCP + TLS + HTTP/2 with system-root certificates.
//!
//! `ams.konstruct.cc:443` is Caddy HTTP/2 (the iOS production path). QUIC/H3
//! lives on `quic.konstruct.cc` behind a pinned gateway cert and is not used
//! here — a handshake to the public hostname over UDP times out.

use std::sync::Arc;
use std::time::Duration;

use rustls::RootCertStore;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};

use super::error::GrpcError;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

pub struct H2Session {
    pub send_request: h2::client::SendRequest<bytes::Bytes>,
    pub driver: tokio::task::JoinHandle<()>,
}

impl Drop for H2Session {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

pub async fn connect_h2(host: &str, port: u16) -> Result<H2Session, GrpcError> {
    let tls = build_tls_config()?;
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| GrpcError::tls(format!("server name '{host}': {e}")))?;

    let addr = resolve_addr(host, port).await?;
    info!(host, %addr, "h2 connecting");

    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| GrpcError::transport(format!("TCP connect to {addr} timed out")))?
        .map_err(|e| GrpcError::transport(format!("TCP connect {addr}: {e}")))?;
    let _ = tcp.set_nodelay(true);

    let connector = TlsConnector::from(Arc::new(tls));
    let tls_stream = tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(server_name, tcp))
        .await
        .map_err(|_| GrpcError::tls("TLS handshake timed out"))?
        .map_err(|e| GrpcError::tls(format!("TLS handshake: {e}")))?;

    let (send_request, conn) = h2::client::Builder::new()
        .initial_window_size(1024 * 1024)
        .initial_connection_window_size(1024 * 1024)
        .handshake(tls_stream)
        .await
        .map_err(|e| GrpcError::transport(format!("h2 handshake: {e}")))?;

    let driver = tokio::spawn(async move {
        if let Err(e) = conn.await {
            warn!("h2 connection closed: {e}");
        }
    });

    debug!(host, "h2 session ready");
    Ok(H2Session {
        send_request,
        driver,
    })
}

fn build_tls_config() -> Result<rustls::ClientConfig, GrpcError> {
    let mut root_store = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs()
        .map_err(|e| GrpcError::tls(format!("native certs: {e}")))?;
    for cert in native {
        let _ = root_store.add(cert);
    }
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    Ok(tls)
}

async fn resolve_addr(host: &str, port: u16) -> Result<std::net::SocketAddr, GrpcError> {
    let host_port = format!("{host}:{port}");
    tokio::net::lookup_host(&host_port)
        .await
        .map_err(|e| GrpcError::transport(format!("DNS resolve '{host_port}': {e}")))?
        .next()
        .ok_or_else(|| GrpcError::transport(format!("no addresses for '{host_port}'")))
}
