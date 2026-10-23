//! From the message stream to the orchestrator: hand each delivery over with its cursor (the
//! orchestrator task opens it — opening a session envelope needs the core); pass acks, stream
//! status and errors on.

use tokio::sync::mpsc;

use super::{ClientEvent, Inbox};
use crate::{
    bridge::BridgeEvent,
    orchestrator_task::OrchestratorHandle,
    streaming::{CursorTracker, StreamEvent},
};
use construct_core::orchestration::actions::IncomingEvent;

pub(super) fn spawn_relay(
    mut stream_rx: mpsc::Receiver<StreamEvent>,
    orch: OrchestratorHandle,
    cursor: CursorTracker,
    events: mpsc::UnboundedSender<ClientEvent>,
    inbox: mpsc::UnboundedSender<Inbox>,
) {
    let orch_tx = orch.tx.clone();
    tokio::spawn(async move {
        while let Some(event) = stream_rx.recv().await {
            match event {
                StreamEvent::Message {
                    envelope,
                    stream_cursor,
                } => orch.stream_envelope(envelope, stream_cursor),
                StreamEvent::Ack {
                    message_id,
                    stream_cursor,
                } => {
                    cursor.note(&message_id, stream_cursor);
                    let _ = orch_tx.send(IncomingEvent::AckReceived { message_id });
                }
                StreamEvent::Heartbeat {
                    timestamp,
                    server_timestamp,
                    stream_cursor,
                } => {
                    tracing::debug!(
                        timestamp,
                        server_timestamp,
                        stream_cursor = ?stream_cursor,
                        "stream heartbeat observed"
                    );
                }
                StreamEvent::StreamError {
                    message_id,
                    error_code,
                    error_message,
                    retryable,
                    retry_after_ms,
                    stream_cursor,
                } => {
                    tracing::warn!(
                        message_id = %message_id,
                        error_code,
                        retryable,
                        retry_after_ms = ?retry_after_ms,
                        stream_cursor = ?stream_cursor,
                        "stream server error routed to UI: {}",
                        error_message
                    );
                    let label = if message_id.is_empty() {
                        format!("Stream error {error_code}: {error_message}")
                    } else {
                        format!("Stream error for {message_id}: {error_message}")
                    };
                    let _ = events.send(ClientEvent::Bridge(BridgeEvent::Error(label)));
                }
                StreamEvent::Connected => {
                    let _ = events.send(ClientEvent::Bridge(BridgeEvent::StreamStatus {
                        connected: true,
                    }));
                    let _ = orch_tx.send(IncomingEvent::NetworkReconnected);
                }
                StreamEvent::Disconnected => {
                    let _ = events.send(ClientEvent::Bridge(BridgeEvent::StreamStatus {
                        connected: false,
                    }));
                }
                StreamEvent::Reconnecting { attempt, delay } => {
                    let _ = events.send(ClientEvent::Bridge(BridgeEvent::StreamReconnecting {
                        attempt,
                        delay_ms: delay.as_millis() as u64,
                    }));
                }
                StreamEvent::AuthRequired => {
                    let _ = inbox.send(Inbox::StreamAuthRequired);
                }
            }
        }
    });
}
