//! TUI implementation of `construct_core::orchestration::PlatformBridge`.
//!
//! `TuiBridge` wires the Rust crypto core to:
//! - SQLite (`Storage`) for message + key persistence
//! - gRPC stream (`StreamCmd` sender) for outbound envelopes
#![allow(dead_code)]
//! - A UI event channel for notifying the app of new messages
//!
//! The bridge is the **only** place that should call `Storage` or push to the
//! gRPC stream. All crypto decisions flow through `construct_core`'s
//! `Orchestrator` → `PlatformBridge` callback chain.

use anyhow::Result;
use construct_core::orchestration::PlatformBridge;
use std::sync::Mutex;
use tokio::sync::mpsc;

use crate::storage::{Storage, StoredMessage};
use crate::streaming::StreamCmd;

// ── Public event type ─────────────────────────────────────────────────────────

/// Events from the bridge to the UI layer.
#[derive(Debug, Clone)]
pub enum BridgeEvent {
    /// A new message was decrypted and stored. UI should refresh.
    NewMessage {
        peer_id: String,
        message_id: String,
        text: String,
        timestamp_ms: i64,
    },
    /// A message we sent was acknowledged by the server.
    MessageDelivered { message_id: String },
    /// Stream connection status changed (connected / disconnected).
    StreamStatus { connected: bool },
    /// Stream is retrying after a drop.
    StreamReconnecting { attempt: u32, delay_ms: u64 },
    /// A platform-level error worth surfacing.
    Error(String),
    /// Double Ratchet session with this contact is ready for encrypt/decrypt.
    SessionReady { contact_id: String },
}

// ── TuiBridge ─────────────────────────────────────────────────────────────────

/// `PlatformBridge` implementation backed by SQLite and gRPC.
///
/// Construct like:
/// ```ignore
/// let bridge = TuiBridge::new(storage, stream_cmd_tx, ui_event_tx);
/// let orchestrator = Orchestrator::new(Arc::new(bridge));
/// ```
pub struct TuiBridge {
    storage: Mutex<Storage>,
    stream_tx: mpsc::Sender<StreamCmd>,
    ui_tx: mpsc::Sender<BridgeEvent>,
}

impl TuiBridge {
    pub fn new(
        storage: Storage,
        stream_tx: mpsc::Sender<StreamCmd>,
        ui_tx: mpsc::Sender<BridgeEvent>,
    ) -> Self {
        Self {
            storage: Mutex::new(storage),
            stream_tx,
            ui_tx,
        }
    }

    /// Store a decrypted incoming message (called from the `MessageDecrypted` action handler).
    pub fn on_message_decrypted(
        &self,
        peer_id: &str,
        message_id: &str,
        text: &str,
        timestamp_ms: i64,
    ) -> Result<()> {
        let msg = StoredMessage {
            id: message_id.to_owned(),
            peer_id: peer_id.to_owned(),
            text: text.to_owned(),
            direction: "received".into(),
            timestamp_ms,
            delivery_status: "delivered".into(),
        };
        self.storage.lock().unwrap().store_message(&msg)?;
        let _ = self.ui_tx.try_send(BridgeEvent::NewMessage {
            peer_id: peer_id.to_owned(),
            message_id: message_id.to_owned(),
            text: text.to_owned(),
            timestamp_ms,
        });
        Ok(())
    }

    /// Store an outgoing message locally (optimistic, before server ACK).
    pub fn on_message_sent(
        &self,
        peer_id: &str,
        message_id: &str,
        text: &str,
        timestamp_ms: i64,
    ) -> Result<()> {
        let msg = StoredMessage {
            id: message_id.to_owned(),
            peer_id: peer_id.to_owned(),
            text: text.to_owned(),
            direction: "sent".into(),
            timestamp_ms,
            delivery_status: "".into(),
        };
        self.storage.lock().unwrap().store_message(&msg)
    }

    /// Mark a message as delivered (called on server ACK).
    pub fn on_ack(&self, message_id: &str) -> Result<()> {
        self.storage.lock().unwrap().mark_delivered(message_id)?;
        let _ = self.ui_tx.try_send(BridgeEvent::MessageDelivered {
            message_id: message_id.to_owned(),
        });
        Ok(())
    }

    /// Load conversation history for a peer.
    pub fn load_messages(&self, peer_id: &str, limit: usize) -> Result<Vec<StoredMessage>> {
        self.storage.lock().unwrap().get_messages(peer_id, limit)
    }

    /// Subscribe the stream worker to a peer's updates.
    pub fn subscribe(&self, user_id: String) {
        let _ = self
            .stream_tx
            .try_send(StreamCmd::Subscribe(vec![user_id], None));
    }
}

// ── PlatformBridge impl ───────────────────────────────────────────────────────

impl PlatformBridge for TuiBridge {
    fn save_to_secure_store(&self, key: String, data: Vec<u8>) {
        if let Err(e) = self
            .storage
            .lock()
            .unwrap()
            .secure_save_or_delete(&key, &data)
        {
            eprintln!("[bridge] secure_save_or_delete({key}): {e}");
        }
    }

    fn load_from_secure_store(&self, key: String) -> Option<Vec<u8>> {
        self.storage
            .lock()
            .unwrap()
            .secure_load(&key)
            .ok()
            .flatten()
    }

    fn persist_record(&self, table: String, json: String) {
        if let Err(e) = self.storage.lock().unwrap().persist_record(&table, &json) {
            eprintln!("[bridge] persist_record({table}): {e}");
        }
    }

    fn query_record(&self, table: String, _query_json: String) -> Option<String> {
        self.storage
            .lock()
            .unwrap()
            .query_last_record(&table)
            .ok()
            .flatten()
    }

    fn log_event(&self, level: String, tag: String, message: String) {
        eprintln!("[{level}] {tag}: {message}");
    }
}

// ── Token refresh task ────────────────────────────────────────────────────────

/// Messages from the token refresh background task to the app.
#[derive(Debug)]
pub enum TokenRefreshMsg {
    /// New tokens — app must re-save the session and update in-memory state.
    Refreshed {
        access_token: String,
        refresh_token: String,
        expires_at: i64,
    },
    /// Network transport failure — keep tokens, let the stream reconnect.
    FailedTransport(String),
    /// Refresh token rejected (gRPC 16/7) — device re-auth, do not wipe yet.
    FailedAuth(String),
}

/// Spawn a background task that refreshes the access token 5 minutes before expiry.
///
/// Sends at most one `TokenRefreshMsg` per lifetime; the app is responsible for
/// restarting the task after a successful refresh with the new `expires_at`.
pub fn spawn_token_refresh(
    client: crate::grpc::GrpcClient,
    device_id: String,
    refresh_token: String,
    expires_at: i64,
) -> mpsc::Receiver<TokenRefreshMsg> {
    let (tx, rx) = mpsc::channel(1);
    tokio::spawn(token_refresh_loop(
        client,
        device_id,
        refresh_token,
        expires_at,
        tx,
    ));
    rx
}

/// Refresh immediately on the shared client (stream got gRPC 16).
pub fn spawn_token_refresh_now(
    client: crate::grpc::GrpcClient,
    device_id: String,
    refresh_token: String,
) -> mpsc::Receiver<TokenRefreshMsg> {
    let (tx, rx) = mpsc::channel(1);
    tokio::spawn(async move {
        let msg = do_refresh(&client, &device_id, &refresh_token).await;
        let _ = tx.send(msg).await;
    });
    rx
}

async fn token_refresh_loop(
    client: crate::grpc::GrpcClient,
    device_id: String,
    refresh_token: String,
    expires_at: i64,
    tx: mpsc::Sender<TokenRefreshMsg>,
) {
    const REFRESH_AHEAD_SECS: i64 = 5 * 60;

    let now = now_unix_secs();
    let wake_at = expires_at.saturating_sub(REFRESH_AHEAD_SECS);
    let delay = (wake_at - now).max(0) as u64;

    tokio::time::sleep(tokio::time::Duration::from_secs(delay)).await;

    let msg = do_refresh(&client, &device_id, &refresh_token).await;
    let _ = tx.send(msg).await;
}

async fn do_refresh(
    client: &crate::grpc::GrpcClient,
    device_id: &str,
    refresh_token: &str,
) -> TokenRefreshMsg {
    client.set_device_id(Some(device_id.to_string()));
    match crate::grpc::refresh_token(client, refresh_token, device_id).await {
        Ok((access_token, new_refresh, expires_at)) => TokenRefreshMsg::Refreshed {
            access_token,
            refresh_token: if new_refresh.is_empty() {
                refresh_token.to_string()
            } else {
                new_refresh
            },
            expires_at,
        },
        Err(e) if e.is_unauthenticated() || e.is_permission_denied() => {
            TokenRefreshMsg::FailedAuth(e.to_string())
        }
        Err(e) => TokenRefreshMsg::FailedTransport(e.to_string()),
    }
}

fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
