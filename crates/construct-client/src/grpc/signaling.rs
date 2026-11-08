//! `SignalingService` — the auxiliary call-signaling channel.
//!
//! SDP offer/answer and the DTLS fingerprint never travel this stream: they go E2EE through the
//! core's Double Ratchet ([[../../../../construct-docs/decisions/call-signaling-e2ee-primary]]).
//! The stream carries wakeup (`IncomingCallNotification`), ringing/connected/hangup presence,
//! busy/offline, and a keepalive ping. `InitiateCall` registers a call attempt with the server so
//! it can wake the callee; `GetTurnCredentials` returns the relay credentials for relay-only ICE.

use std::time::Duration;

use bytes::Bytes;
use http::Request;
use prost::Message;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::proto::signaling::v1::{
    CallType, GetTurnCredentialsRequest, GetTurnCredentialsResponse, InitiateCallRequest,
    InitiateCallResponse, RoutedWebRtcSignal, SignalPing, SignalRequest, SignalResponse,
    SignalRoute, TurnCredentials, UserTarget, WebRtcSignal, signal_request, signal_route,
};

use super::client::{GrpcClient, apply_auth_headers, check_grpc_status, send_h2_data};
use super::error::GrpcError;
use super::framing::encode_frame;
use super::paths::{SIGNALING_GET_TURN_CREDENTIALS, SIGNALING_INITIATE_CALL, SIGNALING_SIGNAL};

/// The Signal stream's keepalive cadence, as iOS sends it.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(25);
const OUTGOING_CHANNEL_DEPTH: usize = 64;

/// Register a call attempt with the server: its busy/rate-limit gate, and the hook that wakes the
/// callee (Signal stream if online, VoIP push if not). The SDP offer itself goes E2EE after.
pub async fn initiate_call(
    client: &GrpcClient,
    call_id: &str,
    callee_user_id: &str,
    call_type: CallType,
    caller_name: &str,
) -> Result<InitiateCallResponse, GrpcError> {
    let request = InitiateCallRequest {
        call_id: call_id.to_owned(),
        callee_user_id: callee_user_id.to_owned(),
        call_type: call_type as i32,
        caller_name: caller_name.to_owned(),
        caller_avatar: Vec::new(),
    };
    let response = client
        .unary(SIGNALING_INITIATE_CALL, &request.encode_to_vec())
        .await?;
    InitiateCallResponse::decode(response.as_slice())
        .map_err(|e| GrpcError::transport(format!("InitiateCall decode: {e}")))
}

/// Relay credentials for relay-only ICE, minted for `call_id`.
pub async fn get_turn_credentials(
    client: &GrpcClient,
    call_id: &str,
) -> Result<TurnCredentials, GrpcError> {
    let request = GetTurnCredentialsRequest {
        call_id: call_id.to_owned(),
    };
    let response = client
        .unary(SIGNALING_GET_TURN_CREDENTIALS, &request.encode_to_vec())
        .await?;
    let response = GetTurnCredentialsResponse::decode(response.as_slice())
        .map_err(|e| GrpcError::transport(format!("GetTurnCredentials decode: {e}")))?;
    response
        .credentials
        .ok_or_else(|| GrpcError::transport("GetTurnCredentials: no credentials"))
}

/// The Signal stream, kept open for the duration of a call. Dropping it closes the stream.
pub struct SignalStream {
    request_tx: mpsc::Sender<SignalRequest>,
    task: tokio::task::JoinHandle<()>,
}

impl SignalStream {
    /// Send one request into the stream.
    pub async fn send(&self, request: SignalRequest) -> Result<(), GrpcError> {
        self.request_tx
            .send(request)
            .await
            .map_err(|_| GrpcError::transport("Signal stream send channel closed"))
    }

    /// A presence signal to every device of `to_user` — ringing, busy, hangup. Never SDP.
    pub async fn send_routed(
        &self,
        signal: WebRtcSignal,
        to_user: String,
    ) -> Result<(), GrpcError> {
        self.send(SignalRequest {
            request: Some(signal_request::Request::RoutedSignal(RoutedWebRtcSignal {
                signal: Some(signal),
                route: Some(SignalRoute {
                    target: Some(signal_route::Target::User(UserTarget {
                        user_id: to_user,
                        all_devices: true,
                    })),
                }),
                caller_name: String::new(),
                caller_avatar: Vec::new(),
            })),
        })
        .await
    }
}

impl Drop for SignalStream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Open the bidi `SignalingService/Signal` stream. Every incoming `SignalResponse` goes to
/// `on_message`; the pump keeps the stream alive with a ping every 25 s.
pub async fn open_signal_stream<F>(
    client: &GrpcClient,
    on_message: F,
) -> Result<SignalStream, GrpcError>
where
    F: Fn(SignalResponse) + Send + 'static,
{
    let mut send_req = client.send_request_handle().await?;
    let (token, device_id) = client.auth_headers();
    let authority = client.authority();

    let builder = Request::builder()
        .method("POST")
        .uri(SIGNALING_SIGNAL)
        .header("host", authority);
    let req = apply_auth_headers(builder, token.as_deref(), device_id.as_deref())
        .body(())
        .map_err(|e| GrpcError::transport(format!("build Signal stream request: {e}")))?;

    let (resp_fut, mut send_stream) = send_req
        .send_request(req, false)
        .map_err(|e| GrpcError::transport(format!("open Signal stream: {e}")))?;

    let response = resp_fut
        .await
        .map_err(|e| GrpcError::transport(format!("Signal stream response: {e}")))?;
    if response.status() != http::StatusCode::OK {
        return Err(GrpcError::transport(format!(
            "Signal stream HTTP {}",
            response.status()
        )));
    }
    check_grpc_status(response.headers())?;

    let recv = response.into_body();
    let (request_tx, request_rx) = mpsc::channel::<SignalRequest>(OUTGOING_CHANNEL_DEPTH);
    let task = tokio::spawn(pump_task(send_stream, recv, request_rx, on_message));
    Ok(SignalStream { request_tx, task })
}

async fn pump_task<F>(
    mut send: h2::SendStream<Bytes>,
    mut recv: h2::RecvStream,
    mut outgoing_rx: mpsc::Receiver<SignalRequest>,
    on_message: F,
) where
    F: Fn(SignalResponse),
{
    debug!("Signal stream pump started");
    let mut recv_buf = bytes::BytesMut::new();
    let mut keepalive = tokio::time::interval(KEEPALIVE_INTERVAL);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            outgoing = outgoing_rx.recv() => {
                match outgoing {
                    Some(request) => {
                        if let Err(e) = send_h2_data(&mut send, encode_frame(&request.encode_to_vec())).await {
                            warn!("Signal stream send failed: {e}");
                            let _ = send.send_reset(h2::Reason::CANCEL);
                            return;
                        }
                    }
                    None => {
                        let _ = send.send_data(Bytes::new(), true);
                        return;
                    }
                }
            }
            _ = keepalive.tick() => {
                let ping = SignalRequest {
                    request: Some(signal_request::Request::Ping(SignalPing {
                        timestamp: now_ms(),
                    })),
                };
                if let Err(e) = send_h2_data(&mut send, encode_frame(&ping.encode_to_vec())).await {
                    warn!("Signal stream keepalive failed: {e}");
                    let _ = send.send_reset(h2::Reason::CANCEL);
                    return;
                }
            }
            incoming = recv.data() => {
                match incoming {
                    Ok(Some(Ok(chunk))) => {
                        let n = chunk.len();
                        recv_buf.extend_from_slice(&chunk);
                        let _ = recv.flow_control().release_capacity(n);
                        loop {
                            if recv_buf.len() < 5 {
                                break;
                            }
                            if recv_buf[0] != 0 {
                                warn!("compressed Signal stream message");
                                return;
                            }
                            let msg_len = u32::from_be_bytes([
                                recv_buf[1],
                                recv_buf[2],
                                recv_buf[3],
                                recv_buf[4],
                            ]) as usize;
                            if recv_buf.len() < 5 + msg_len {
                                break;
                            }
                            let frame = recv_buf.split_to(5 + msg_len).freeze();
                            match SignalResponse::decode(frame.slice(5..)) {
                                Ok(response) => on_message(response),
                                Err(e) => warn!("Signal stream response does not parse: {e}"),
                            }
                        }
                    }
                    Ok(Some(Err(e))) => {
                        warn!("Signal stream recv error: {e}");
                        return;
                    }
                    Ok(None) => {
                        debug!("Signal stream: server closed send side");
                        return;
                    }
                    Err(e) => {
                        warn!("Signal stream recv failed: {e}");
                        return;
                    }
                }
            }
        }
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default()
}
