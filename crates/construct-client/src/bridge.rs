//! Events from the client layer to the front end, and the access-token refresh task.

use tokio::sync::mpsc;

use crate::local_store::StoredMessage;

// ── Public event type ─────────────────────────────────────────────────────────

/// Events from the bridge to the UI layer.
#[derive(Debug, Clone)]
pub enum BridgeEvent {
    /// A new message was decrypted and stored. UI should refresh.
    NewMessage { message: StoredMessage },
    /// A message we sent from another device of this account, copied here.
    OwnMessage { message: StoredMessage },
    /// A message held changed: edited by its author, or its reactions.
    MessageChanged { message: StoredMessage },
    /// A message was deleted on this device.
    MessageDeleted { peer_id: String, message_id: String },
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
    /// Devices of this contact's account that no device we trust vouched for: perhaps the
    /// contact linked a device without a certificate, perhaps the server added one. Only an
    /// alarm — they still receive messages (decisions/devices-of-an-account-sign-each-other.md).
    UnvouchedDevices {
        peer_id: String,
        device_ids: Vec<String>,
    },
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
