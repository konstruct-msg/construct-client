//! Actor-style task that owns the `Orchestrator` and dispatches `Action`s.
//!
//! # Pattern
//!
//! ```text
//! App / StreamWorker
//!   ──── IncomingEvent ──→ OrchestratorTask
//!                              │  orchestrator.handle_event(event)
//!                              │  → Vec<Action>
//!                              │  dispatch each Action:
//!                              │    storage   ──→ SQLite
//!                              │    gRPC      ──→ KeyUserClient (async sub-task)
//!                              │    stream    ──→ StreamCmd channel
//!                              │    timer     ──→ tokio::time (sub-task → self_tx)
//!                              │    ui        ──→ internal_tx (BridgeEvent)
//!                              └────────────────────────────────────────────────
//! ```

use std::collections::{HashMap, HashSet};

use anyhow::Result;
use construct_core::orchestration::{
    actions::{Action, IncomingEvent},
    orchestrator::Orchestrator,
};
use tokio::sync::mpsc;
use tokio::task::AbortHandle;

use crate::bridge::BridgeEvent;
use crate::grpc::GrpcClient;
use crate::proto::core::v1::{ContentType, Envelope, UserId, envelope::MessageIdType};
use crate::storage::Storage;
use crate::streaming::{CursorTracker, StreamCmd};

// ── Public handle ─────────────────────────────────────────────────────────────

/// Cheaply cloneable handle for sending events to the Orchestrator task.
#[derive(Clone)]
pub struct OrchestratorHandle {
    pub tx: mpsc::UnboundedSender<IncomingEvent>,
    cmd_tx: mpsc::UnboundedSender<OrchestratorCommand>,
}

impl OrchestratorHandle {
    /// Send an event to the orchestrator (fire-and-forget).
    pub fn send(&self, event: IncomingEvent) {
        let _ = self.tx.send(event);
    }

    /// Drop volatile session state for a contact that the user removed locally.
    pub fn forget_contact(&self, contact_id: String) {
        let _ = self
            .cmd_tx
            .send(OrchestratorCommand::ForgetContact { contact_id });
    }

    /// Mark a contact as locally known before opening/proactively initializing it.
    pub fn remember_contact(&self, contact_id: String) {
        let _ = self
            .cmd_tx
            .send(OrchestratorCommand::RememberContact { contact_id });
    }

    /// Route an inbound stream message with its server cursor context.
    pub(crate) fn stream_message(&self, event: IncomingEvent, context: StreamMessageContext) {
        let _ = self.cmd_tx.send(OrchestratorCommand::StreamMessage {
            event: Box::new(event),
            context,
        });
    }
}

#[derive(Debug, Clone)]
pub(crate) struct StreamMessageContext {
    pub contact_id: String,
    pub message_id: String,
    pub stream_cursor: Option<String>,
    pub content_type: u8,
    pub msg_num: u32,
}

impl StreamMessageContext {
    fn is_replay_sensitive(&self) -> bool {
        self.msg_num == 0
            || self.content_type == ContentType::SessionReset as u8
            || self.content_type == ContentType::SessionResetInit as u8
    }
}

#[derive(Debug, Clone)]
enum OrchestratorCommand {
    ForgetContact {
        contact_id: String,
    },
    RememberContact {
        contact_id: String,
    },
    StreamMessage {
        // Boxed: an `IncomingEvent` dwarfs the other variants (clippy large_enum_variant).
        event: Box<IncomingEvent>,
        context: StreamMessageContext,
    },
}

// ── Startup ───────────────────────────────────────────────────────────────────

/// Spawn the orchestrator task and return a handle to it.
///
/// * `orchestrator` — fully constructed (keys loaded, sessions pre-populated)
/// * `storage` — open SQLite storage
/// * `stream_tx` — command channel to the gRPC stream worker
/// * `internal_tx` — channel back to the UI app event loop (BridgeEvent)
/// * `grpc` — shared gRPC client (bundle fetch)
/// * `cursor` — stream watermark, advanced after inbound persist
/// * `known_contacts` — local contact ids allowed to enter the core receive path
/// * `my_user_id` / `my_device_id` — local identity for Envelope construction
#[allow(clippy::too_many_arguments)]
pub fn spawn_orchestrator_task(
    orchestrator: Orchestrator,
    storage: Storage,
    stream_tx: mpsc::Sender<StreamCmd>,
    internal_tx: mpsc::UnboundedSender<crate::client::ClientEvent>,
    grpc: GrpcClient,
    cursor: CursorTracker,
    known_contacts: Vec<String>,
    my_user_id: String,
    my_device_id: String,
) -> OrchestratorHandle {
    let (tx, rx) = mpsc::unbounded_channel::<IncomingEvent>();
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<OrchestratorCommand>();
    let handle = OrchestratorHandle {
        tx: tx.clone(),
        cmd_tx,
    };

    tokio::spawn(run(
        orchestrator,
        storage,
        stream_tx,
        internal_tx,
        grpc,
        cursor,
        known_contacts,
        my_user_id,
        my_device_id,
        tx,
        rx,
        cmd_rx,
    ));

    handle
}

// ── Main loop ─────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn run(
    mut orchestrator: Orchestrator,
    mut storage: Storage,
    stream_tx: mpsc::Sender<StreamCmd>,
    internal_tx: mpsc::UnboundedSender<crate::client::ClientEvent>,
    grpc: GrpcClient,
    cursor: CursorTracker,
    known_contacts: Vec<String>,
    my_user_id: String,
    my_device_id: String,
    self_tx: mpsc::UnboundedSender<IncomingEvent>,
    mut rx: mpsc::UnboundedReceiver<IncomingEvent>,
    mut cmd_rx: mpsc::UnboundedReceiver<OrchestratorCommand>,
) {
    let mut timers: HashMap<String, AbortHandle> = HashMap::new();
    let mut session_established_at_ms: HashMap<String, u64> = HashMap::new();
    let mut known_contacts: HashSet<String> = known_contacts.into_iter().collect();

    loop {
        let event = tokio::select! {
            maybe_cmd = cmd_rx.recv() => {
                let Some(cmd) = maybe_cmd else {
                    break;
                };
                handle_command(
                    cmd,
                    &mut orchestrator,
                    &mut storage,
                    &stream_tx,
                    &internal_tx,
                    &grpc,
                    &cursor,
                    &my_user_id,
                    &my_device_id,
                    &self_tx,
                    &mut timers,
                    &mut session_established_at_ms,
                    &mut known_contacts,
                )
                .await;
                continue;
            }
            maybe_event = rx.recv() => {
                let Some(event) = maybe_event else {
                    break;
                };
                event
            }
        };

        let event = match prepare_outgoing(
            event,
            &mut orchestrator,
            &mut storage,
            &stream_tx,
            &internal_tx,
            &grpc,
            &cursor,
            &my_user_id,
            &my_device_id,
            &self_tx,
            &mut timers,
            &mut session_established_at_ms,
        )
        .await
        {
            Some(event) => event,
            None => continue,
        };

        let actions = orchestrator.handle_event(event);

        // Collect any inline follow-up events (from synchronous Action handlers).
        let mut follow_ups: Vec<IncomingEvent> = Vec::new();
        // Track contacts that completed session init in this dispatch cycle so
        // we can skip a spurious SessionHealNeeded for the same contact.
        let mut session_inited: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        for action in actions {
            dispatch(
                action,
                &mut orchestrator,
                &mut storage,
                &stream_tx,
                &internal_tx,
                &grpc,
                &cursor,
                &my_user_id,
                &my_device_id,
                &self_tx,
                &mut timers,
                &mut follow_ups,
                &mut session_inited,
                &mut session_established_at_ms,
            )
            .await;
        }

        // Process inline follow-ups (e.g. SessionInitCompleted after InitSession).
        // One level of depth is enough — they should only produce simple actions.
        // Share session_inited so that a SessionHealNeeded produced by drain_pending
        // inside handle_session_init_completed is still suppressed by the dedup guard
        // that was set when InitSession succeeded moments earlier.
        for follow_up in follow_ups {
            let more = orchestrator.handle_event(follow_up);
            for action in more {
                dispatch(
                    action,
                    &mut orchestrator,
                    &mut storage,
                    &stream_tx,
                    &internal_tx,
                    &grpc,
                    &cursor,
                    &my_user_id,
                    &my_device_id,
                    &self_tx,
                    &mut timers,
                    &mut Vec::new(),     // no further follow-up nesting
                    &mut session_inited, // share dedup context with follow-ups
                    &mut session_established_at_ms,
                )
                .await;
            }
        }
    }
}

// ── Action dispatch ───────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn handle_command(
    command: OrchestratorCommand,
    orchestrator: &mut Orchestrator,
    storage: &mut Storage,
    stream_tx: &mpsc::Sender<StreamCmd>,
    internal_tx: &mpsc::UnboundedSender<crate::client::ClientEvent>,
    grpc: &GrpcClient,
    cursor: &CursorTracker,
    my_user_id: &str,
    my_device_id: &str,
    self_tx: &mpsc::UnboundedSender<IncomingEvent>,
    timers: &mut HashMap<String, AbortHandle>,
    session_established_at_ms: &mut HashMap<String, u64>,
    known_contacts: &mut HashSet<String>,
) {
    match command {
        OrchestratorCommand::ForgetContact { contact_id } => {
            let had_active_session = orchestrator.has_active_session(&contact_id);
            orchestrator.forget_contact_state(&contact_id);
            session_established_at_ms.remove(&contact_id);
            known_contacts.remove(&contact_id);
            match orchestrator.export_orchestrator_state_cfe() {
                Ok(state) => {
                    if let Err(e) =
                        storage.secure_save_or_delete("construct.orchestrator_state", &state)
                    {
                        tracing::warn!(
                            target: "orchestrator_task",
                            contact_id = %contact_id,
                            error = %e,
                            "forget_contact: failed to persist orchestrator state"
                        );
                    }
                }
                Err(e) => tracing::warn!(
                    target: "orchestrator_task",
                    contact_id = %contact_id,
                    error = %e,
                    "forget_contact: failed to export orchestrator state"
                ),
            }

            let session_key = format!("session_{contact_id}");
            if let Err(e) = storage.secure_delete(&session_key) {
                tracing::warn!(
                    target: "orchestrator_task",
                    contact_id = %contact_id,
                    key = %session_key,
                    error = %e,
                    "forget_contact: failed to delete hot session key"
                );
            }
            let archive_key = format!("archive_{contact_id}");
            if let Err(e) = storage.secure_delete(&archive_key) {
                tracing::warn!(
                    target: "orchestrator_task",
                    contact_id = %contact_id,
                    key = %archive_key,
                    error = %e,
                    "forget_contact: failed to delete archive session key"
                );
            }

            tracing::info!(
                target: "orchestrator_task",
                contact_id = %contact_id,
                had_active_session,
                "forgot contact session material"
            );
        }
        OrchestratorCommand::RememberContact { contact_id } => {
            known_contacts.insert(contact_id.clone());
            tracing::debug!(
                target: "orchestrator_task",
                contact_id = %contact_id,
                "remembered contact for stream routing"
            );
        }
        OrchestratorCommand::StreamMessage { event, context } => {
            if !known_contacts.contains(&context.contact_id) {
                cursor.commit_direct(storage, context.stream_cursor.clone());
                tracing::warn!(
                    target: "orchestrator_task",
                    contact_id = %context.contact_id,
                    message_id = %context.message_id,
                    content_type = context.content_type,
                    msg_num = context.msg_num,
                    stream_cursor = ?context.stream_cursor,
                    "dropped stream message from unknown contact"
                );
                return;
            }

            if should_drop_stale_session_replay(&context, session_established_at_ms) {
                cursor.commit_direct(storage, context.stream_cursor.clone());
                tracing::warn!(
                    target: "orchestrator_task",
                    contact_id = %context.contact_id,
                    message_id = %context.message_id,
                    content_type = context.content_type,
                    msg_num = context.msg_num,
                    stream_cursor = ?context.stream_cursor,
                    "dropped stale replay-sensitive stream message"
                );
                return;
            }

            cursor.note(&context.message_id, context.stream_cursor);
            let actions = orchestrator.handle_event(*event);
            let mut follow_ups: Vec<IncomingEvent> = Vec::new();
            let mut session_inited = std::collections::HashSet::new();
            for action in actions {
                dispatch(
                    action,
                    orchestrator,
                    storage,
                    stream_tx,
                    internal_tx,
                    grpc,
                    cursor,
                    my_user_id,
                    my_device_id,
                    self_tx,
                    timers,
                    &mut follow_ups,
                    &mut session_inited,
                    session_established_at_ms,
                )
                .await;
            }
            for follow_up in follow_ups {
                let more = orchestrator.handle_event(follow_up);
                for action in more {
                    dispatch(
                        action,
                        orchestrator,
                        storage,
                        stream_tx,
                        internal_tx,
                        grpc,
                        cursor,
                        my_user_id,
                        my_device_id,
                        self_tx,
                        timers,
                        &mut Vec::new(),
                        &mut session_inited,
                        session_established_at_ms,
                    )
                    .await;
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn dispatch(
    action: Action,
    orchestrator: &mut Orchestrator,
    storage: &mut Storage,
    stream_tx: &mpsc::Sender<StreamCmd>,
    internal_tx: &mpsc::UnboundedSender<crate::client::ClientEvent>,
    grpc: &GrpcClient,
    cursor: &CursorTracker,
    my_user_id: &str,
    my_device_id: &str,
    self_tx: &mpsc::UnboundedSender<IncomingEvent>,
    timers: &mut HashMap<String, AbortHandle>,
    follow_ups: &mut Vec<IncomingEvent>,
    session_inited: &mut std::collections::HashSet<String>,
    session_established_at_ms: &mut HashMap<String, u64>,
) {
    match action {
        // ── Crypto (platform must handle synchronously) ────────────────────
        Action::OpenReceiving { contact_id } => {
            let opened = orchestrator.open_receiving(&contact_id);
            if opened.awaiting_server_key {
                tracing::warn!(%contact_id, "trusted server key is required to open receiving session");
            }
            if let Some(error) = opened.last_error {
                let _ = internal_tx.send(crate::client::ClientEvent::Bridge(BridgeEvent::Error(
                    format!("[SESSION_OPEN] {error}"),
                )));
            }
            for action in opened.actions {
                Box::pin(dispatch(
                    action,
                    orchestrator,
                    storage,
                    stream_tx,
                    internal_tx,
                    grpc,
                    cursor,
                    my_user_id,
                    my_device_id,
                    self_tx,
                    timers,
                    follow_ups,
                    session_inited,
                    session_established_at_ms,
                ))
                .await;
            }
        }
        Action::OpenSession { contact_id } => {
            let tx = self_tx.clone();
            let grpc = grpc.clone();
            tokio::spawn(async move {
                let bundle = fetch_bundle(&grpc, &contact_id)
                    .await
                    .map(|f| f.bundle)
                    .map_err(|e| e.to_string());
                let _ = tx.send(IncomingEvent::SessionBundleFetched {
                    contact_id,
                    bundle: Box::new(bundle),
                });
            });
        }

        // These are handled internally by the Orchestrator itself.
        Action::DecryptMessage { .. }
        | Action::EncryptMessage { .. }
        | Action::ArchiveSession { .. } => {}

        // ── Decrypted message ready ─────────────────────────────────────────
        Action::MessageDecrypted {
            contact_id,
            message_id,
            plaintext,
        } => {
            let text = crate::knst::decode_text(&plaintext);
            tracing::info!(
                target: "orchestrator_task",
                contact_id = %contact_id,
                message_id = %message_id,
                plaintext_len = plaintext.len(),
                text_len = text.len(),
                text_preview = %text.chars().take(40).collect::<String>(),
                "MessageDecrypted: storing and notifying UI"
            );
            // Persist to storage.
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;
            persist_inbound(
                storage,
                cursor,
                &message_id,
                crate::storage::StoredMessage {
                    id: message_id.clone(),
                    peer_id: contact_id.clone(),
                    text: text.clone(),
                    direction: "received".into(),
                    timestamp_ms: now_ms,
                    delivery_status: String::new(),
                },
            );

            // Notify UI.
            let _ = internal_tx.send(crate::client::ClientEvent::Bridge(
                BridgeEvent::NewMessage {
                    peer_id: contact_id,
                    message_id,
                    text,
                    timestamp_ms: now_ms,
                },
            ));
        }

        Action::CallSignalDecrypted { .. } => {
            // Calls not yet implemented in TUI.
        }

        Action::ControlFrameDecrypted { content_type, .. } => {
            // A silent control frame the core named (receipt, heartbeat, card, profile, retired
            // ping/ready). The TUI handles none of them yet; it must only never show one, which
            // it did until core 0.30 named them: each arrived as MessageDecrypted.
            tracing::debug!(content_type, "control frame — not handled by the TUI");
        }

        Action::MessageQueuedPendingInit { .. } => {}

        // ── Persistence ─────────────────────────────────────────────────────
        Action::SaveToSecureStore { slot, data } => {
            let key = secure_store_key(&slot);
            if let Err(error) = apply_secure_store_save(storage, &key, data.as_ref()) {
                tracing::error!(%key, %error, "secure store save failed");
            }
        }
        Action::DuplicateDropped { message_id } => cursor.commit(storage, &message_id),
        // A payload the core cannot parse (or a retired suite): nothing will ever read it, so it
        // is recorded and passed like a duplicate. The core sends the NotifyError beside it.
        Action::MalformedDropped { message_id } => cursor.commit(storage, &message_id),

        Action::PersistAck {
            message_id,
            timestamp,
        } => {
            let _ = storage.store_ack(&message_id, timestamp as i64);
        }

        Action::PruneAckStore { cutoff_ts } => {
            let _ = storage.prune_acks(cutoff_ts as i64);
        }

        Action::MarkMessageDelivered { message_id } => {
            let _ = storage.mark_delivered(&message_id);
        }

        Action::CheckAckInDb { message_id } => {
            let is_processed = storage.has_ack(&message_id).unwrap_or(false);
            follow_ups.push(IncomingEvent::AckDbResult {
                message_id,
                is_processed,
            });
        }

        // ── Network ─────────────────────────────────────────────────────────
        Action::SendEncryptedMessage {
            to,
            payload,
            message_id,
            content_type,
        } => {
            // Core addresses a device; the envelope still requires its account UUID.
            // Until that mapping is retained, sending `to` as recipient.user_id
            // would create an envelope addressed to the wrong identity space.
            if uuid::Uuid::parse_str(&to).is_err() {
                let _ = internal_tx.send(crate::client::ClientEvent::Bridge(BridgeEvent::Error(
                    "Device-to-account routing is not ready".into(),
                )));
                tracing::warn!(device_id = %to, %message_id, "encrypted send held: no account routing");
                return;
            }
            tracing::info!(
                target: "orchestrator_task",
                to = %to,
                payload_len = payload.len(),
                message_id = %message_id,
                content_type = content_type,
                "SendEncryptedMessage: dispatching envelope"
            );
            let content_type_proto = content_type_from_u8(content_type);
            let envelope = build_envelope(
                my_user_id,
                my_device_id,
                &to,
                payload,
                message_id,
                content_type_proto,
            );
            tracing::info!(
                target: "orchestrator_task",
                encrypted_payload_len = envelope.encrypted_payload.len(),
                "SendEncryptedMessage: envelope built, sending"
            );
            let _ = stream_tx.try_send(StreamCmd::Send(Box::new(envelope)));
        }

        Action::SendReceipt { message_id, status } => {
            // TODO: construct DeliveryReceipt proto and send via stream.
            tracing::debug!(
                target: "orchestrator_task",
                message_id = %message_id,
                status = ?status,
                "SendReceipt (not yet wired)"
            );
        }

        Action::SendDecryptionError {
            contact_id,
            message_id,
            payload,
            enveloped,
        } => {
            // An enveloped answer goes back as a session envelope inside a sealed inner. This
            // client neither opens nor sends session envelopes (it hands the core no
            // `envelope_session`), so the core does not ask for one; if it ever does, sending the
            // envelope as a plain box would be unreadable, so it is held instead.
            if enveloped {
                tracing::warn!(%contact_id, %message_id, "decryption error held: enveloped answer needs sealed sending");
                return;
            }
            if uuid::Uuid::parse_str(&contact_id).is_err() {
                tracing::warn!(device_id = %contact_id, %message_id, "decryption error held: no account routing");
                return;
            }
            let envelope = build_control_envelope(
                my_user_id,
                my_device_id,
                &contact_id,
                ContentType::DecryptionError,
                payload,
                message_id,
            );
            let _ = stream_tx.try_send(StreamCmd::Send(Box::new(envelope)));
        }
        Action::SessionRetired { contact_id, .. } => {
            session_established_at_ms.remove(&contact_id);
        }
        Action::ResendMessage {
            contact_id,
            message_id,
        } => {
            tracing::warn!(%contact_id, %message_id, "resend requires outgoing message lookup");
        }

        // ── UI notifications ─────────────────────────────────────────────────
        Action::NotifyNewMessage { chat_id, preview } => {
            let _ = internal_tx.send(crate::client::ClientEvent::Bridge(
                BridgeEvent::NewMessage {
                    peer_id: chat_id,
                    message_id: String::new(),
                    text: preview,
                    timestamp_ms: now_ms(),
                },
            ));
        }

        Action::NotifySessionCreated { contact_id } => {
            tracing::info!(
                target: "orchestrator_task",
                contact_id = %contact_id,
                "Session created"
            );
            let _ = internal_tx.send(crate::client::ClientEvent::Bridge(
                BridgeEvent::SessionReady { contact_id },
            ));
        }

        Action::NotifyError { code, message } => {
            tracing::warn!(
                target: "orchestrator_task",
                code = %code,
                message = %message,
                "NotifyError from orchestrator"
            );
            let _ = internal_tx.send(crate::client::ClientEvent::Bridge(BridgeEvent::Error(
                format!("[{code}] {message}"),
            )));
        }

        // ── Timers ──────────────────────────────────────────────────────────
        Action::ScheduleTimer { timer_id, delay_ms } => {
            let tx = self_tx.clone();
            let tid = timer_id.clone();
            let handle = tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                let _ = tx.send(IncomingEvent::TimerFired { timer_id: tid });
            });
            timers.insert(timer_id, handle.abort_handle());
        }

        Action::CancelTimer { timer_id } => {
            if let Some(handle) = timers.remove(&timer_id) {
                handle.abort();
            }
        }
    }
}

fn apply_secure_store_save(storage: &Storage, key: &str, data: &[u8]) -> Result<()> {
    storage.secure_save_or_delete(key, data)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn secure_store_key(slot: &construct_core::orchestration::actions::SecureStoreSlot) -> String {
    use construct_core::orchestration::actions::SecureStoreSlot;
    match slot {
        SecureStoreSlot::Session { contact_id } => format!("session_{contact_id}"),
        SecureStoreSlot::OrchestratorState => "construct.orchestrator_state".into(),
    }
}

async fn fetch_bundle(
    client: &GrpcClient,
    user_id: &str,
) -> Result<crate::grpc::FetchedPreKeyBundle> {
    Ok(crate::grpc::get_pre_key_bundle(client, user_id).await?)
}

/// Before the Orchestrator sees an event:
/// - opening a chat / adding a contact establishes an INITIATOR session
/// - a send with no session does the same (message becomes the X3DH carrier)
/// - UTF-8 chat text is wrapped in a KNST + `MessageContent` frame
#[allow(clippy::too_many_arguments)]
async fn prepare_outgoing(
    event: IncomingEvent,
    orchestrator: &mut Orchestrator,
    storage: &mut Storage,
    stream_tx: &mpsc::Sender<StreamCmd>,
    internal_tx: &mpsc::UnboundedSender<crate::client::ClientEvent>,
    grpc: &GrpcClient,
    cursor: &CursorTracker,
    my_user_id: &str,
    my_device_id: &str,
    self_tx: &mpsc::UnboundedSender<IncomingEvent>,
    timers: &mut HashMap<String, AbortHandle>,
    session_established_at_ms: &mut HashMap<String, u64>,
) -> Option<IncomingEvent> {
    match event {
        IncomingEvent::OutgoingMessage {
            contact_id,
            message_id,
            plaintext,
            content_type,
        } => {
            if !orchestrator.has_active_session(&contact_id)
                && let Err(e) = establish_session(
                    orchestrator,
                    storage,
                    stream_tx,
                    internal_tx,
                    grpc,
                    cursor,
                    my_user_id,
                    my_device_id,
                    self_tx,
                    timers,
                    session_established_at_ms,
                    &contact_id,
                )
                .await
            {
                tracing::error!(
                    target: "orchestrator_task",
                    contact_id = %contact_id,
                    error = %e,
                    "session init before send failed"
                );
                let _ = internal_tx.send(crate::client::ClientEvent::Bridge(BridgeEvent::Error(
                    format!("[SESSION_INIT_FAILED] {e}"),
                )));
                return None;
            }
            if !orchestrator.has_active_session(&contact_id) {
                let _ = internal_tx.send(crate::client::ClientEvent::Bridge(BridgeEvent::Error(
                    "Device routing is required before sending".into(),
                )));
                return None;
            }
            let plaintext = if crate::knst::is_frame(&plaintext) || plaintext.first() == Some(&0) {
                plaintext
            } else {
                crate::knst::encode_text(&String::from_utf8_lossy(&plaintext), &message_id)
            };
            Some(IncomingEvent::OutgoingMessage {
                contact_id,
                message_id,
                plaintext,
                content_type,
            })
        }
        other => Some(other),
    }
}

/// Fetch the peer's pre-key bundle and run the existing InitSession dispatch
/// (INITIATOR vs RESPONDER chosen there). Returns whether a session was created.
#[allow(clippy::too_many_arguments)]
async fn establish_session(
    orchestrator: &mut Orchestrator,
    storage: &mut Storage,
    stream_tx: &mpsc::Sender<StreamCmd>,
    internal_tx: &mpsc::UnboundedSender<crate::client::ClientEvent>,
    grpc: &GrpcClient,
    cursor: &CursorTracker,
    my_user_id: &str,
    my_device_id: &str,
    self_tx: &mpsc::UnboundedSender<IncomingEvent>,
    timers: &mut HashMap<String, AbortHandle>,
    session_established_at_ms: &mut HashMap<String, u64>,
    contact_id: &str,
) -> Result<bool, String> {
    if orchestrator.has_active_session(contact_id) {
        return Ok(false);
    }
    let fetched = fetch_bundle(grpc, contact_id)
        .await
        .map_err(|e| format!("GetPreKeyBundle: {e:#}"))?;
    let device_id = fetched.device_id;
    if device_id.is_empty() {
        return Err("prekey bundle did not identify a device".into());
    }
    orchestrator.init_session_with_bundle(
        &device_id,
        fetched.bundle.x3dh,
        fetched.bundle.kyber,
        false,
    )?;
    session_established_at_ms.insert(device_id.clone(), now_ms_u64());
    let actions = orchestrator.handle_event(IncomingEvent::SessionInitCompleted {
        contact_id: device_id.clone(),
        session_data: vec![],
    });
    let mut follow_ups = Vec::new();
    let mut session_inited = std::collections::HashSet::new();
    for action in actions {
        dispatch(
            action,
            orchestrator,
            storage,
            stream_tx,
            internal_tx,
            grpc,
            cursor,
            my_user_id,
            my_device_id,
            self_tx,
            timers,
            &mut follow_ups,
            &mut session_inited,
            session_established_at_ms,
        )
        .await;
    }
    for follow_up in follow_ups {
        let more = orchestrator.handle_event(follow_up);
        for action in more {
            dispatch(
                action,
                orchestrator,
                storage,
                stream_tx,
                internal_tx,
                grpc,
                cursor,
                my_user_id,
                my_device_id,
                self_tx,
                timers,
                &mut Vec::new(),
                &mut session_inited,
                session_established_at_ms,
            )
            .await;
        }
    }
    if orchestrator.has_active_session(&device_id) {
        Ok(true)
    } else {
        Err("no session after init".into())
    }
}

fn persist_inbound(
    storage: &Storage,
    cursor: &CursorTracker,
    message_id: &str,
    msg: crate::storage::StoredMessage,
) {
    if storage.store_inbound_message(&msg).is_ok() {
        cursor.commit(storage, message_id);
    }
}

fn build_envelope(
    from_user: &str,
    from_device: &str,
    to_user: &str,
    payload: Vec<u8>,
    message_id: String,
    content_type: ContentType,
) -> Envelope {
    use crate::proto::core::v1::DeviceId;

    Envelope {
        sender: Some(UserId {
            user_id: from_user.to_string(),
            domain: None,
            display_name: None,
        }),
        sender_device: Some(DeviceId {
            user: None,
            device_id: from_device.to_string(),
            ..Default::default()
        }),
        recipient: Some(UserId {
            user_id: to_user.to_string(),
            domain: None,
            display_name: None,
        }),
        recipient_device: None,
        content_type: content_type as i32,
        message_id_type: Some(MessageIdType::MessageId(message_id)),
        encrypted_payload: payload.into(),
        conversation_id: {
            // Must match iOS ConversationId.direct() — sort user IDs lexicographically
            // so both sides produce the same key regardless of message direction.
            let (a, b) = if from_user < to_user {
                (from_user, to_user)
            } else {
                (to_user, from_user)
            };
            format!("direct:{}:{}", a, b)
        },
        ..Default::default()
    }
}

fn build_control_envelope(
    from_user: &str,
    from_device: &str,
    to_user: &str,
    content_type: ContentType,
    payload: Vec<u8>,
    message_id: String,
) -> Envelope {
    build_envelope(
        from_user,
        from_device,
        to_user,
        payload,
        message_id,
        content_type,
    )
}

fn content_type_from_u8(v: u8) -> ContentType {
    match v {
        1 => ContentType::E2eeSignal,
        12 => ContentType::CallSignal,
        20 => ContentType::KeyExchange,
        21 => ContentType::SessionReset,
        24 => ContentType::SessionResetInit,
        _ => ContentType::E2eeSignal,
    }
}

fn should_drop_stale_session_replay(
    context: &StreamMessageContext,
    session_established_at_ms: &HashMap<String, u64>,
) -> bool {
    if !context.is_replay_sensitive() {
        return false;
    }
    let Some(established_at_ms) = session_established_at_ms.get(&context.contact_id) else {
        return false;
    };
    let Some(cursor_ms) = stream_cursor_millis(context.stream_cursor.as_deref()) else {
        return false;
    };
    cursor_ms < *established_at_ms
}

fn stream_cursor_millis(cursor: Option<&str>) -> Option<u64> {
    let cursor = cursor?;
    let (millis, _) = cursor.split_once('-')?;
    millis.parse().ok()
}

fn now_ms() -> i64 {
    i64::try_from(now_ms_u64()).unwrap_or(i64::MAX)
}

fn now_ms_u64() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use construct_core::crypto::{
        client_api::ClassicClient, suites::classic::ClassicSuiteProvider,
    };

    #[test]
    fn secure_store_save_action_deletes_empty_payload() {
        let storage = Storage::open_in_memory().expect("in-memory storage opens");
        apply_secure_store_save(&storage, "session_peer", b"old-session")
            .expect("initial session save succeeds");
        apply_secure_store_save(&storage, "session_peer", b"").expect("delete sentinel succeeds");

        assert_eq!(storage.secure_load("session_peer").unwrap(), None);
    }

    #[test]
    fn stream_cursor_millis_parses_redis_stream_id() {
        assert_eq!(
            stream_cursor_millis(Some("1787431771124-0")),
            Some(1787431771124)
        );
        assert_eq!(stream_cursor_millis(Some("1787431771124")), None);
        assert_eq!(stream_cursor_millis(Some("not-a-cursor")), None);
        assert_eq!(stream_cursor_millis(None), None);
    }

    #[test]
    fn stale_replay_guard_drops_old_msg_zero() {
        let mut established = HashMap::new();
        established.insert("bob".to_string(), 2000);

        let context = stream_context("bob", 0, 0, Some("1000-0"));

        assert!(should_drop_stale_session_replay(&context, &established));
    }

    #[test]
    fn stale_replay_guard_drops_old_reset_control() {
        let mut established = HashMap::new();
        established.insert("bob".to_string(), 2000);

        let context = stream_context("bob", ContentType::SessionReset as u8, 42, Some("1000-0"));

        assert!(should_drop_stale_session_replay(&context, &established));
    }

    #[test]
    fn stale_replay_guard_keeps_old_regular_message() {
        let mut established = HashMap::new();
        established.insert("bob".to_string(), 2000);

        let context = stream_context("bob", 0, 42, Some("1000-0"));

        assert!(!should_drop_stale_session_replay(&context, &established));
    }

    #[test]
    fn stale_replay_guard_keeps_without_local_established_at() {
        let established = HashMap::new();
        let context = stream_context("bob", 0, 0, Some("1000-0"));

        assert!(!should_drop_stale_session_replay(&context, &established));
    }

    #[test]
    fn stale_replay_guard_keeps_newer_replay_sensitive_message() {
        let mut established = HashMap::new();
        established.insert("bob".to_string(), 2000);

        let context = stream_context("bob", 0, 0, Some("3000-0"));

        assert!(!should_drop_stale_session_replay(&context, &established));
    }

    #[tokio::test]
    async fn stream_message_command_terminally_drops_stale_msg_zero() {
        let mut harness = ReplayHarness::new();
        harness.remember_contact("bob");
        harness.mark_session_established("bob", 2_000);

        harness
            .handle_stream_message(stale_message_command("bob", "stale-msg0", 0, 0, false))
            .await;

        assert_eq!(
            harness.storage.load_stream_cursor().unwrap().as_deref(),
            Some("1000-0")
        );
        assert_eq!(
            harness.orchestrator.pending_message_count("bob"),
            0,
            "stale msgNum=0 must not enter core pending init queue"
        );
        assert!(harness.stream_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn stream_message_command_terminally_drops_stale_reset_with_invalid_wire_payload() {
        let mut harness = ReplayHarness::new();
        harness.remember_contact("bob");
        harness.mark_session_established("bob", 2_000);

        harness
            .handle_stream_message(stale_message_command(
                "bob",
                "stale-reset",
                ContentType::SessionReset as u8,
                0,
                true,
            ))
            .await;

        assert_eq!(
            harness.storage.load_stream_cursor().unwrap().as_deref(),
            Some("1000-0")
        );
        assert_eq!(
            harness.orchestrator.pending_message_count("bob"),
            0,
            "stale reset control must not archive/heal the active actor session"
        );
        assert!(harness.stream_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn stream_message_command_drops_unknown_contact_before_core_pending_queue() {
        let mut harness = ReplayHarness::new();

        harness
            .handle_stream_message(stale_message_command("bob", "unknown-msg0", 0, 0, false))
            .await;

        assert_eq!(
            harness.storage.load_stream_cursor().unwrap().as_deref(),
            Some("1000-0")
        );
        assert_eq!(
            harness.orchestrator.pending_message_count("bob"),
            0,
            "unknown contact backlog must not force a later re-add down RESPONDER path"
        );
        assert!(harness.stream_rx.try_recv().is_err());
    }

    fn stream_context(
        contact_id: &str,
        content_type: u8,
        msg_num: u32,
        stream_cursor: Option<&str>,
    ) -> StreamMessageContext {
        StreamMessageContext {
            contact_id: contact_id.to_string(),
            message_id: "message-1".to_string(),
            stream_cursor: stream_cursor.map(str::to_string),
            content_type,
            msg_num,
        }
    }

    fn stale_message_command(
        contact_id: &str,
        message_id: &str,
        content_type: u8,
        msg_num: u32,
        _is_control: bool,
    ) -> OrchestratorCommand {
        OrchestratorCommand::StreamMessage {
            event: Box::new(IncomingEvent::MessageReceived {
                message_id: message_id.to_string(),
                from: contact_id.to_string(),
                data: b"not-a-wire-payload".to_vec(),
                sender_certificate: None,
                content_type,
                envelope_session: None,
            }),
            context: StreamMessageContext {
                contact_id: contact_id.to_string(),
                message_id: message_id.to_string(),
                stream_cursor: Some("1000-0".to_string()),
                content_type,
                msg_num,
            },
        }
    }

    struct ReplayHarness {
        orchestrator: Orchestrator,
        storage: Storage,
        stream_tx: tokio::sync::mpsc::Sender<StreamCmd>,
        stream_rx: tokio::sync::mpsc::Receiver<StreamCmd>,
        internal_tx: tokio::sync::mpsc::UnboundedSender<crate::client::ClientEvent>,
        grpc: GrpcClient,
        cursor: CursorTracker,
        self_tx: tokio::sync::mpsc::UnboundedSender<IncomingEvent>,
        timers: HashMap<String, AbortHandle>,
        session_established_at_ms: HashMap<String, u64>,
        known_contacts: HashSet<String>,
    }

    impl ReplayHarness {
        fn new() -> Self {
            let client = ClassicClient::<ClassicSuiteProvider>::new()
                .expect("test ClassicClient should initialize");
            let orchestrator = Orchestrator::new(client, "alice".to_string());
            let storage = Storage::open_in_memory().expect("in-memory storage opens");
            let cursor = CursorTracker::load(&storage);
            let (stream_tx, stream_rx) = tokio::sync::mpsc::channel(4);
            let (internal_tx, _internal_rx) = tokio::sync::mpsc::unbounded_channel();
            let (self_tx, _self_rx) = tokio::sync::mpsc::unbounded_channel();

            Self {
                orchestrator,
                storage,
                stream_tx,
                stream_rx,
                internal_tx,
                grpc: GrpcClient::new("https://127.0.0.1:1"),
                cursor,
                self_tx,
                timers: HashMap::new(),
                session_established_at_ms: HashMap::new(),
                known_contacts: HashSet::new(),
            }
        }

        fn remember_contact(&mut self, contact_id: &str) {
            self.known_contacts.insert(contact_id.to_string());
        }

        fn mark_session_established(&mut self, contact_id: &str, established_at_ms: u64) {
            self.session_established_at_ms
                .insert(contact_id.to_string(), established_at_ms);
        }

        async fn handle_stream_message(&mut self, command: OrchestratorCommand) {
            handle_command(
                command,
                &mut self.orchestrator,
                &mut self.storage,
                &self.stream_tx,
                &self.internal_tx,
                &self.grpc,
                &self.cursor,
                "alice",
                "device-a",
                &self.self_tx,
                &mut self.timers,
                &mut self.session_established_at_ms,
                &mut self.known_contacts,
            )
            .await;
        }
    }
}
