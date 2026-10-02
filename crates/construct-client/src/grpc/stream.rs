//! Bidirectional `MessagingService/MessageStream` over HTTP/2.

use std::time::Duration;

use bytes::Bytes;
use http::Request;
use prost::Message;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::proto::core::v1::Envelope;
use crate::proto::services::v1::{MessageStreamRequest, SubscribeRequest, message_stream_request};

use super::client::{GrpcClient, apply_auth_headers, check_grpc_status, send_h2_data};
use super::error::GrpcError;
use super::framing::encode_frame;
use super::paths::MESSAGING_STREAM;

const RECV_POLL_INTERVAL: Duration = Duration::from_millis(50);
const OUTGOING_CHANNEL_DEPTH: usize = 256;

pub struct MessageStream {
    frame_tx: mpsc::Sender<Bytes>,
    task: tokio::task::JoinHandle<()>,
}

impl MessageStream {
    pub async fn send_frame(&self, frame: Bytes) -> Result<(), GrpcError> {
        self.frame_tx
            .send(frame)
            .await
            .map_err(|_| GrpcError::transport("MessageStream send channel closed"))
    }

    pub async fn send_envelope(&self, envelope: Envelope) -> Result<(), GrpcError> {
        let req = MessageStreamRequest {
            request: Some(message_stream_request::Request::Send(envelope)),
            request_id: uuid_v4(),
            attempt_id: None,
        };
        self.send_frame(encode_frame(&req.encode_to_vec())).await
    }
}

impl Drop for MessageStream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn open_message_stream<F>(
    client: &GrpcClient,
    conversation_ids: Vec<String>,
    since_cursor: Option<String>,
    on_frame: F,
) -> Result<MessageStream, GrpcError>
where
    F: Fn(Bytes) + Send + 'static,
{
    let mut send_req = client.send_request_handle().await?;
    let (token, device_id) = client.auth_headers();
    let authority = client.authority();

    let builder = Request::builder()
        .method("POST")
        .uri(MESSAGING_STREAM)
        .header("host", authority);
    let req = apply_auth_headers(builder, token.as_deref(), device_id.as_deref())
        .body(())
        .map_err(|e| GrpcError::transport(format!("build stream request: {e}")))?;

    let (resp_fut, mut send_stream) = send_req
        .send_request(req, false)
        .map_err(|e| GrpcError::transport(format!("open MessageStream: {e}")))?;

    let subscribe = MessageStreamRequest {
        request: Some(message_stream_request::Request::Subscribe(
            SubscribeRequest {
                conversation_ids: conversation_ids.clone(),
                since_cursor,
                include_presence: false,
            },
        )),
        request_id: uuid_v4(),
        attempt_id: None,
    };
    send_h2_data(&mut send_stream, encode_frame(&subscribe.encode_to_vec())).await?;

    let response = resp_fut
        .await
        .map_err(|e| GrpcError::transport(format!("MessageStream recv_response: {e}")))?;
    if response.status() != http::StatusCode::OK {
        return Err(GrpcError::transport(format!(
            "MessageStream HTTP {}",
            response.status()
        )));
    }
    check_grpc_status(response.headers())?;
    info!(
        "MessageStream open — {} conversation(s)",
        conversation_ids.len()
    );

    let recv = response.into_body();
    let (frame_tx, frame_rx) = mpsc::channel::<Bytes>(OUTGOING_CHANNEL_DEPTH);
    let task = tokio::spawn(pump_task(send_stream, recv, frame_rx, on_frame));
    Ok(MessageStream { frame_tx, task })
}

async fn pump_task<F>(
    mut send: h2::SendStream<Bytes>,
    mut recv: h2::RecvStream,
    mut outgoing_rx: mpsc::Receiver<Bytes>,
    on_frame: F,
) where
    F: Fn(Bytes),
{
    debug!("MessageStream pump started");
    let mut recv_buf = bytes::BytesMut::new();
    loop {
        tokio::select! {
            outgoing = outgoing_rx.recv() => {
                match outgoing {
                    Some(frame) => {
                        if let Err(e) = send_h2_data(&mut send, frame).await {
                            warn!("MessageStream send_data failed: {e}");
                            send.send_reset(h2::Reason::CANCEL);
                            return;
                        }
                    }
                    None => {
                        info!("MessageStream outgoing channel closed");
                        let _ = send.send_data(Bytes::new(), true);
                        return;
                    }
                }
            }
            incoming = tokio::time::timeout(RECV_POLL_INTERVAL, recv.data()) => {
                match incoming {
                    Ok(Some(Ok(chunk))) => {
                        let n = chunk.len();
                        recv_buf.extend_from_slice(&chunk);
                        let _ = recv.flow_control().release_capacity(n);
                        loop {
                            if recv_buf.len() < 5 {
                                break;
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
                            on_frame(frame);
                        }
                    }
                    Ok(Some(Err(e))) => {
                        error!("MessageStream recv_data error: {e}");
                        return;
                    }
                    Ok(None) => {
                        info!("MessageStream: server closed send side");
                        return;
                    }
                    Err(_timeout) => {}
                }
            }
        }
    }
}

fn uuid_v4() -> String {
    uuid::Uuid::new_v4().to_string()
}
