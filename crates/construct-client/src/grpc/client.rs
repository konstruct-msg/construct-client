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

/// The longest a unary call may take, connecting included.
const UNARY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

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

    /// Connect once: callers racing here share one connection. Checked again under the write
    /// lock, because a second connection replacing the first drops it and every call on it.
    async fn ensure(&self) -> Result<(), GrpcError> {
        if self.inner.session.read().await.is_some() {
            return Ok(());
        }
        let mut session = self.inner.session.write().await;
        if session.is_none() {
            *session = Some(connect_h2(&self.inner.host, self.inner.port).await?);
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
        match self.unary_timed(path, request_bytes).await {
            Err(e) if e.is_retryable_transport() => {
                debug!("unary '{path}' transport error, retrying once: {e}");
                self.invalidate().await;
                self.unary_timed(path, request_bytes).await
            }
            other => other,
        }
    }

    /// No call waits forever: the orchestrator task awaits some of them, and everything else
    /// waits behind it.
    async fn unary_timed(&self, path: &str, request_bytes: &[u8]) -> Result<Vec<u8>, GrpcError> {
        match tokio::time::timeout(UNARY_TIMEOUT, self.unary_once(path, request_bytes)).await {
            Ok(result) => result,
            Err(_) => {
                *self.inner.session.write().await = None;
                Err(GrpcError::transport(format!("'{path}' timed out")))
            }
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
    let msg = percent_decode(
        headers
            .get("grpc-message")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
    );
    if code == 16 {
        return Err(GrpcError::unauthenticated(msg));
    }
    if code == 7 {
        return Err(GrpcError::permission_denied(msg));
    }
    Err(GrpcError::status(code, msg))
}

/// `grpc-message` is percent-encoded on the wire (gRPC over HTTP/2): "already%20taken".
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: Option<&u8>| b.and_then(|b| (*b as char).to_digit(16));
        match (bytes[i], hex(bytes.get(i + 1)), hex(bytes.get(i + 2))) {
            (b'%', Some(h), Some(l)) => {
                out.push((h * 16 + l) as u8);
                i += 3;
            }
            (b, ..) => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Send `data` as the peer's flow-control window allows: a chunk per grant of capacity.
///
/// It waited for capacity for the whole message and then sent it in one go. A message larger
/// than the window (a prekey upload with 99 Kyber keys, ~500 KB) then never got that capacity,
/// and the call hung with the orchestrator task behind it.
pub(crate) async fn send_h2_data(
    send: &mut h2::SendStream<Bytes>,
    mut data: Bytes,
) -> Result<(), GrpcError> {
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let granted = match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
            Some(Ok(n)) => n,
            Some(Err(e)) => return Err(GrpcError::transport(format!("h2 capacity: {e}"))),
            None => return Err(GrpcError::transport("h2 send stream closed")),
        };
        if granted == 0 {
            continue;
        }
        let chunk = data.split_to(granted.min(data.len()));
        send.send_data(chunk, false)
            .map_err(|e| GrpcError::transport(format!("h2 send_data: {e}")))?;
    }
    Ok(())
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
    fn a_status_message_is_read_as_the_server_wrote_it() {
        let mut headers = HeaderMap::new();
        headers.insert("grpc-status", "6".parse().unwrap());
        headers.insert(
            "grpc-message",
            "username%20is%20already%20taken".parse().unwrap(),
        );
        let err = check_grpc_status(&headers).unwrap_err();
        assert_eq!(err.to_string(), "grpc 6: username is already taken");
        assert_eq!(percent_decode("50%"), "50%");
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

    /// A peer whose flow-control window is 16 KB still receives a 200 KB message whole. Before
    /// the message went in chunks, this hung waiting for capacity the window never grants.
    #[tokio::test]
    async fn a_message_larger_than_the_window_is_sent_whole() {
        const LEN: usize = 200_000;
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut conn = h2::server::Builder::new()
                .initial_window_size(16_384)
                .initial_connection_window_size(16_384)
                .handshake::<_, Bytes>(server_io)
                .await
                .expect("server handshake");
            let (request, _respond) = conn.accept().await.expect("a request").expect("ok");
            tokio::spawn(async move { while conn.accept().await.is_some() {} });
            let mut body = request.into_body();
            let mut received = 0;
            while let Some(chunk) = body.data().await {
                let chunk = chunk.expect("data");
                received += chunk.len();
                let _ = body.flow_control().release_capacity(chunk.len());
            }
            received
        });

        let (mut client, connection) = h2::client::handshake(client_io).await.expect("handshake");
        tokio::spawn(connection);
        let (_response, mut send) = client
            .send_request(http::Request::post("/x").body(()).unwrap(), false)
            .expect("request");
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            send_h2_data(&mut send, Bytes::from(vec![7u8; LEN])),
        )
        .await
        .expect("the send finishes")
        .expect("the send succeeds");
        send.send_data(Bytes::new(), true).expect("end of stream");

        assert_eq!(server.await.unwrap(), LEN);
    }
}
