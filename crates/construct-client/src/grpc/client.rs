//! Persistent HTTP/2 connection + unary gRPC.
//!
//! One `GrpcClient` per process: clone the handle (cheap Arc) and share it
//! across auth, the orchestrator, and the message stream.

use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use http::{HeaderMap, Request};
use tokio::sync::RwLock;
use tracing::debug;

use super::connection::{H2Session, connect_h2};
use super::error::GrpcError;
use super::framing::{decode_frame, encode_frame};

pub(crate) type H2SendReq = h2::client::SendRequest<Bytes>;

struct Inner {
    host: String,
    port: u16,
    session: RwLock<Option<H2Session>>,
    token: std::sync::RwLock<Option<String>>,
    device_id: std::sync::RwLock<Option<String>>,
}

/// Shared gRPC-over-H2 client. Clone is cheap (`Arc`).
#[derive(Clone)]
pub struct GrpcClient {
    inner: Arc<Inner>,
}

impl GrpcClient {
    /// Parse `server_url` and install the rustls provider. Does not open TCP.
    pub fn new(server_url: &str) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (host, port) = parse_server_url(server_url);
        Self {
            inner: Arc::new(Inner {
                host,
                port,
                session: RwLock::new(None),
                token: std::sync::RwLock::new(None),
                device_id: std::sync::RwLock::new(None),
            }),
        }
    }

    pub fn set_token(&self, token: Option<String>) {
        *self.inner.token.write().expect("token lock") = token;
    }

    pub fn set_device_id(&self, device_id: Option<String>) {
        *self.inner.device_id.write().expect("device_id lock") = device_id;
    }

    pub fn authority(&self) -> String {
        format!("{}:{}", self.inner.host, self.inner.port)
    }

    /// Drop the live H2 session so the next RPC opens a new TCP/TLS connection.
    pub async fn invalidate(&self) {
        *self.inner.session.write().await = None;
    }

    /// Kept as a name the stream worker already calls.
    pub async fn invalidate_h3(&self) {
        self.invalidate().await;
    }

    async fn ensure(&self) -> Result<(), GrpcError> {
        if self.inner.session.read().await.is_none() {
            let session = connect_h2(&self.inner.host, self.inner.port).await?;
            *self.inner.session.write().await = Some(session);
        }
        Ok(())
    }

    async fn send_request(&self) -> Result<H2SendReq, GrpcError> {
        self.inner
            .session
            .read()
            .await
            .as_ref()
            .map(|s| s.send_request.clone())
            .ok_or_else(|| GrpcError::transport("H2 not connected"))
    }

    /// Unary gRPC call. `path` is `/package.Service/Method`.
    /// One retry after a transport error (new session); auth errors are not retried.
    pub async fn unary(&self, path: &str, request_bytes: &[u8]) -> Result<Vec<u8>, GrpcError> {
        match self.unary_once(path, request_bytes).await {
            Err(e) if e.is_retryable_transport() => {
                debug!("unary '{path}' transport error, retrying once: {e}");
                self.invalidate().await;
                self.unary_once(path, request_bytes).await
            }
            other => other,
        }
    }

    async fn unary_once(&self, path: &str, request_bytes: &[u8]) -> Result<Vec<u8>, GrpcError> {
        self.ensure().await?;
        let mut send_req = self.send_request().await?;
        let token = self.inner.token.read().expect("token lock").clone();
        let device_id = self.inner.device_id.read().expect("device_id lock").clone();
        let authority = self.authority();

        let result = do_unary(
            &mut send_req,
            path,
            &authority,
            request_bytes,
            token.as_deref(),
            device_id.as_deref(),
        )
        .await;

        if matches!(&result, Err(e) if e.is_retryable_transport()) {
            *self.inner.session.write().await = None;
            debug!("H2 dropped after transport error");
        }
        result
    }

    pub(crate) async fn send_request_handle(&self) -> Result<H2SendReq, GrpcError> {
        self.ensure().await?;
        self.send_request().await
    }

    pub(crate) fn auth_headers(&self) -> (Option<String>, Option<String>) {
        (
            self.inner.token.read().expect("token lock").clone(),
            self.inner.device_id.read().expect("device_id lock").clone(),
        )
    }
}

pub fn parse_server_url(url: &str) -> (String, u16) {
    let rest = url
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let hostport = rest.split('/').next().unwrap_or(rest);
    if let Some((host, port)) = hostport.split_once(':') {
        (host.to_string(), port.parse().unwrap_or(443))
    } else {
        (hostport.to_string(), 443)
    }
}

pub(crate) fn apply_auth_headers(
    mut builder: http::request::Builder,
    token: Option<&str>,
    device_id: Option<&str>,
) -> http::request::Builder {
    builder = builder
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("grpc-encoding", "identity")
        .header(
            "user-agent",
            format!("konstruct-tui/{}", env!("CARGO_PKG_VERSION")),
        );
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    if let Some(id) = device_id {
        builder = builder.header("x-device-id", id);
    }
    builder
}

pub(crate) fn check_grpc_status(headers: &HeaderMap) -> Result<(), GrpcError> {
    let Some(code) = headers
        .get("grpc-status")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u32>().ok())
    else {
        return Ok(());
    };
    if code == 0 {
        return Ok(());
    }
    let msg = headers
        .get("grpc-message")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if code == 16 {
        return Err(GrpcError::unauthenticated(msg));
    }
    if code == 7 {
        return Err(GrpcError::permission_denied(msg));
    }
    Err(GrpcError::status(code, msg))
}

pub(crate) async fn send_h2_data(
    send: &mut h2::SendStream<Bytes>,
    data: Bytes,
) -> Result<(), GrpcError> {
    let needed = data.len();
    if send.capacity() < needed {
        send.reserve_capacity(needed);
        loop {
            match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
                Some(Ok(n)) if n >= needed || send.capacity() >= needed => break,
                Some(Ok(_)) => continue,
                Some(Err(e)) => {
                    return Err(GrpcError::transport(format!("h2 capacity: {e}")));
                }
                None => {
                    return Err(GrpcError::transport("h2 send stream closed"));
                }
            }
        }
    }
    send.send_data(data, false)
        .map_err(|e| GrpcError::transport(format!("h2 send_data: {e}")))
}

async fn do_unary(
    send_req: &mut H2SendReq,
    path: &str,
    authority: &str,
    request_bytes: &[u8],
    token: Option<&str>,
    device_id: Option<&str>,
) -> Result<Vec<u8>, GrpcError> {
    let builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("host", authority);
    let req = apply_auth_headers(builder, token, device_id)
        .body(())
        .map_err(|e| GrpcError::transport(format!("build request: {e}")))?;

    let (resp_fut, mut send_stream) = send_req
        .send_request(req, false)
        .map_err(|e| GrpcError::transport(format!("send_request '{path}': {e}")))?;

    send_h2_data(&mut send_stream, encode_frame(request_bytes)).await?;
    send_stream
        .send_data(Bytes::new(), true)
        .map_err(|e| GrpcError::transport(format!("end stream: {e}")))?;

    let response = resp_fut
        .await
        .map_err(|e| GrpcError::transport(format!("recv_response '{path}': {e}")))?;
    if response.status() != http::StatusCode::OK {
        return Err(GrpcError::transport(format!(
            "HTTP {} from '{path}'",
            response.status()
        )));
    }
    check_grpc_status(response.headers())?;

    let mut recv = response.into_body();
    let mut body = BytesMut::new();
    while let Some(chunk) = recv.data().await {
        let chunk = chunk.map_err(|e| GrpcError::transport(format!("recv_data: {e}")))?;
        let n = chunk.len();
        body.extend_from_slice(&chunk);
        let _ = recv.flow_control().release_capacity(n);
    }

    if let Ok(Some(trailers)) = recv.trailers().await {
        check_grpc_status(&trailers)?;
    }

    if body.is_empty() {
        return Ok(Vec::new());
    }
    let (msg, _) = decode_frame(body.freeze())?;
    Ok(msg.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn clones_share_token() {
        let a = GrpcClient::new("https://ams.konstruct.cc:443");
        let b = a.clone();
        a.set_token(Some("tok-1".into()));
        a.set_device_id(Some("dev-1".into()));
        let (token, device) = b.auth_headers();
        assert_eq!(token.as_deref(), Some("tok-1"));
        assert_eq!(device.as_deref(), Some("dev-1"));
    }

    #[test]
    fn parse_url_host_port() {
        assert_eq!(
            parse_server_url("https://ams.konstruct.cc:443"),
            ("ams.konstruct.cc".into(), 443)
        );
        assert_eq!(
            parse_server_url("https://example.com"),
            ("example.com".into(), 443)
        );
    }
}
