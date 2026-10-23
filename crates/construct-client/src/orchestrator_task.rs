//! Actor-style task that owns the `Orchestrator` and dispatches `Action`s.
//!
//! # Pattern
//!
//! ```text
//! App / StreamWorker
//!   ──── IncomingEvent / command ──→ Task
//!                                      │  account → devices (peers), sealed inner opened here
//!                                      │  orchestrator.handle_event(event) → Vec<Action>
//!                                      │  dispatch each Action:
//!                                      │    storage ──→ SQLite
//!                                      │    gRPC    ──→ bundles, certificate (async)
//!                                      │    send    ──→ sealed sender worker (in order)
//!                                      │    timer   ──→ tokio::time (sub-task → self_tx)
//!                                      │    ui      ──→ internal_tx (BridgeEvent)
//!                                      └──────────────────────────────────────────
//! ```
//!
//! Two id spaces meet here. Screens and the server speak accounts; the core speaks devices. An
//! `OutgoingMessage` from the screens names an account and fans out to its devices; everything
//! the core says names a device and is mapped back through [`PeerDevices`] before it reaches the
//! screens.

use std::collections::{HashMap, HashSet, VecDeque};

use construct_core::orchestration::{
    actions::{Action, IncomingEvent},
    orchestrator::Orchestrator,
};
use prost::Message;
use tokio::sync::mpsc;
use tokio::task::AbortHandle;

use crate::bridge::BridgeEvent;
use crate::grpc::{GrpcClient, SenderCertificate};
use crate::peers::PeerDevices;
use crate::proto::core::v1::{ContentType, Envelope, SealedInner, envelope::MessageIdType};
use crate::sealing::{self, Opened, SealedBody};
use crate::storage::Storage;
use crate::streaming::CursorTracker;

/// A certificate this close to its expiry is fetched again before it is used.
const CERTIFICATE_REFRESH_AHEAD_SECS: i64 = 5 * 60;

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

    /// Drop session state for an account that the user removed locally.
    pub fn forget_contact(&self, contact_id: String) {
        let _ = self
            .cmd_tx
            .send(OrchestratorCommand::ForgetContact { contact_id });
    }

    /// Mark an account as locally known, so its deliveries enter the core.
    pub fn remember_contact(&self, contact_id: String) {
        let _ = self
            .cmd_tx
            .send(OrchestratorCommand::RememberContact { contact_id });
    }

    /// A delivery from the message stream, with its cursor.
    pub(crate) fn stream_envelope(&self, envelope: Box<Envelope>, stream_cursor: Option<String>) {
        let _ = self.cmd_tx.send(OrchestratorCommand::StreamEnvelope {
            envelope,
            stream_cursor,
        });
    }

    /// Delegations of the server's hybrid keys, as `GetServerTrust` served them.
    pub(crate) fn server_delegations(&self, delegations: Vec<Vec<u8>>) {
        let _ = self
            .cmd_tx
            .send(OrchestratorCommand::ServerDelegations { delegations });
    }
}

#[derive(Debug, Clone)]
pub(crate) struct StreamMessageContext {
    /// The account the delivery came from: what `known_contacts` is checked against.
    pub contact_id: String,
    /// The device that wrote it: what the replay guard keys on, like the core.
    pub device: String,
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
    StreamEnvelope {
        envelope: Box<Envelope>,
        stream_cursor: Option<String>,
    },
    ServerDelegations {
        delegations: Vec<Vec<u8>>,
    },
    /// The sealed sender worker sent `local_id`; the server calls it `server_id`.
    Sent {
        server_id: String,
        local_id: String,
    },
}

/// One sealed send, queued for the worker that sends them in order.
struct OutboundSealed {
    inner: SealedInner,
    local_id: String,
}

// ── Startup ───────────────────────────────────────────────────────────────────

/// What the task needs about this device.
pub struct LocalIdentity {
    /// This device: the core's id for us (`derive_device_id(identity_key)`).
    pub device_id: String,
    /// X25519 identity secret, to open a certificate box (`sealing::open_sealed_inner`).
    pub identity_secret: Vec<u8>,
    /// Ed25519 signing secret, to bind the hybrid identity when prekeys are published.
    pub signing_secret: Vec<u8>,
    /// A saved prekey blob was missing: the server's one-time prekeys are replaced.
    pub replace_prekeys: bool,
}

/// Spawn the orchestrator task and return a handle to it.
///
/// * `orchestrator` — fully constructed (keys loaded, sessions restored), local id = our device
/// * `storage` — open SQLite storage
/// * `internal_tx` — channel back to the client (BridgeEvent)
/// * `grpc` — the authenticated client (bundles, certificate)
/// * `anonymous` — a client that never holds a token, for sealed sends
/// * `cursor` — stream watermark, advanced after inbound persist
/// * `known_contacts` — accounts whose deliveries may enter the core
#[allow(clippy::too_many_arguments)]
pub fn spawn_orchestrator_task(
    orchestrator: Orchestrator,
    storage: Storage,
    internal_tx: mpsc::UnboundedSender<crate::client::ClientEvent>,
    grpc: GrpcClient,
    anonymous: GrpcClient,
    cursor: CursorTracker,
    known_contacts: Vec<String>,
    identity: LocalIdentity,
) -> OrchestratorHandle {
    let (tx, rx) = mpsc::unbounded_channel::<IncomingEvent>();
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<OrchestratorCommand>();
    let handle = OrchestratorHandle {
        tx: tx.clone(),
        cmd_tx: cmd_tx.clone(),
    };

    let sealed_tx = spawn_sealed_sender(anonymous, cmd_tx, internal_tx.clone());
    let mut task = Task::new(
        orchestrator,
        storage,
        internal_tx,
        grpc,
        sealed_tx,
        cursor,
        known_contacts,
        identity,
        tx,
    );
    tokio::spawn(async move { task.run(rx, cmd_rx).await });

    handle
}

/// Sends sealed inners one at a time, in the order queued: two copies to one device must reach
/// the server in the order their ratchet wrote them.
fn spawn_sealed_sender(
    anonymous: GrpcClient,
    cmd_tx: mpsc::UnboundedSender<OrchestratorCommand>,
    internal_tx: mpsc::UnboundedSender<crate::client::ClientEvent>,
) -> mpsc::UnboundedSender<OutboundSealed> {
    let (tx, mut rx) = mpsc::unbounded_channel::<OutboundSealed>();
    tokio::spawn(async move {
        while let Some(outbound) = rx.recv().await {
            match crate::grpc::send_sealed_message(&anonymous, &outbound.inner).await {
                Ok(server_id) => {
                    tracing::info!(
                        local_id = %outbound.local_id,
                        %server_id,
                        "sealed message sent"
                    );
                    let _ = cmd_tx.send(OrchestratorCommand::Sent {
                        server_id,
                        local_id: outbound.local_id,
                    });
                }
                Err(e) => {
                    tracing::warn!(local_id = %outbound.local_id, error = %e, "sealed send failed");
                    let _ = internal_tx.send(crate::client::ClientEvent::Bridge(
                        BridgeEvent::Error(format!("[SEND_FAILED] {e}")),
                    ));
                }
            }
        }
    });
    tx
}

// ── The task ──────────────────────────────────────────────────────────────────

struct Task {
    orchestrator: Orchestrator,
    storage: Storage,
    internal_tx: mpsc::UnboundedSender<crate::client::ClientEvent>,
    grpc: GrpcClient,
    sealed_tx: mpsc::UnboundedSender<OutboundSealed>,
    cursor: CursorTracker,
    identity: LocalIdentity,
    self_tx: mpsc::UnboundedSender<IncomingEvent>,
    timers: HashMap<String, AbortHandle>,
    session_established_at_ms: HashMap<String, u64>,
    known_contacts: HashSet<String>,
    peers: PeerDevices,
    certificate: Option<SenderCertificate>,
    /// Certificates of first messages waiting on a receiving session, by device: filed in
    /// `peers` once the session opens from them, and the address a DECRYPTION_ERROR goes back
    /// to if it does not.
    pending_certificates: HashMap<String, (String, Vec<u8>)>,
}

impl Task {
    #[allow(clippy::too_many_arguments)]
    fn new(
        mut orchestrator: Orchestrator,
        storage: Storage,
        internal_tx: mpsc::UnboundedSender<crate::client::ClientEvent>,
        grpc: GrpcClient,
        sealed_tx: mpsc::UnboundedSender<OutboundSealed>,
        cursor: CursorTracker,
        known_contacts: Vec<String>,
        identity: LocalIdentity,
        self_tx: mpsc::UnboundedSender<IncomingEvent>,
    ) -> Self {
        orchestrator.set_trusted_server_keys(crate::trust::pinned_certificate_keys());
        let peers = PeerDevices::load(&storage);
        Self {
            orchestrator,
            storage,
            internal_tx,
            grpc,
            sealed_tx,
            cursor,
            identity,
            self_tx,
            timers: HashMap::new(),
            session_established_at_ms: HashMap::new(),
            known_contacts: known_contacts.into_iter().collect(),
            peers,
            certificate: None,
            pending_certificates: HashMap::new(),
        }
    }

    async fn run(
        &mut self,
        mut rx: mpsc::UnboundedReceiver<IncomingEvent>,
        mut cmd_rx: mpsc::UnboundedReceiver<OrchestratorCommand>,
    ) {
        // Before anything is sent: a peer can open a session only to prekeys the server holds.
        if let Err(e) = self.publish_prekeys().await {
            tracing::error!(error = %e, "prekey publish failed");
            self.ui_error(format!("[PREKEYS] {e}"));
        }
        loop {
            tokio::select! {
                maybe_cmd = cmd_rx.recv() => {
                    let Some(cmd) = maybe_cmd else { break };
                    self.handle_command(cmd).await;
                }
                maybe_event = rx.recv() => {
                    let Some(event) = maybe_event else { break };
                    for event in self.prepare_outgoing(event).await {
                        self.process(event).await;
                    }
                }
            }
        }
    }

    async fn publish_prekeys(&mut self) -> Result<(), String> {
        let Some(publish) = crate::prekeys::prepare_publish(
            &mut self.orchestrator,
            &self.storage,
            &self.identity.device_id,
            &self.identity.signing_secret,
            self.identity.replace_prekeys,
        )?
        else {
            return Ok(());
        };
        let (upload, kyber_spk_id, rotating) = publish.into_parts();
        let result =
            crate::grpc::upload_prekeys_full(&self.grpc, &self.identity.device_id, upload).await;
        crate::prekeys::finish_publish(
            &mut self.orchestrator,
            &self.storage,
            &self.identity.device_id,
            kyber_spk_id,
            rotating,
            result,
        )
    }

    /// Hand `event` to the core and carry out everything it answers, including the events those
    /// answers produce in turn (a receipt for a message just decrypted, a session just opened).
    async fn process(&mut self, event: IncomingEvent) {
        let mut queue = VecDeque::from([event]);
        while let Some(event) = queue.pop_front() {
            let actions = self.orchestrator.handle_event(event);
            let mut follow_ups = Vec::new();
            for action in actions {
                self.dispatch(action, &mut follow_ups).await;
            }
            queue.extend(follow_ups);
        }
    }

    // ── Commands ──────────────────────────────────────────────────────────────

    async fn handle_command(&mut self, command: OrchestratorCommand) {
        match command {
            OrchestratorCommand::ForgetContact { contact_id } => self.forget_contact(&contact_id),
            OrchestratorCommand::RememberContact { contact_id } => {
                tracing::debug!(%contact_id, "remembered contact for stream routing");
                self.known_contacts.insert(contact_id);
            }
            OrchestratorCommand::StreamEnvelope {
                envelope,
                stream_cursor,
            } => self.handle_envelope(&envelope, stream_cursor).await,
            OrchestratorCommand::ServerDelegations { delegations } => {
                let offered = delegations.len();
                let admitted = self.orchestrator.admit_server_delegations(delegations);
                tracing::info!(
                    offered,
                    admitted,
                    "server key delegations handed to the core"
                );
            }
            OrchestratorCommand::Sent {
                server_id,
                local_id,
            } => {
                if let Err(e) = self.storage.record_server_message_id(&server_id, &local_id) {
                    tracing::warn!(%server_id, error = %e, "failed to record server message id");
                }
            }
        }
    }

    fn forget_contact(&mut self, contact_id: &str) {
        for device in self.peers.devices_of(contact_id) {
            self.orchestrator.forget_contact_state(&device);
            self.session_established_at_ms.remove(&device);
            for key in [format!("session_{device}"), format!("archive_{device}")] {
                if let Err(e) = self.storage.secure_delete(&key) {
                    tracing::warn!(%key, error = %e, "forget_contact: failed to delete session key");
                }
            }
            self.peers.forget(&self.storage, &device);
        }
        self.known_contacts.remove(contact_id);
        self.save_orchestrator_state();
        tracing::info!(%contact_id, "forgot contact session material");
    }

    fn save_orchestrator_state(&self) {
        match self.orchestrator.export_orchestrator_state_cfe() {
            Ok(state) => {
                if let Err(e) = self
                    .storage
                    .secure_save_or_delete("construct.orchestrator_state", &state)
                {
                    tracing::warn!(error = %e, "failed to persist orchestrator state");
                }
            }
            Err(e) => tracing::warn!(error = %e, "failed to export orchestrator state"),
        }
    }

    // ── Receiving ─────────────────────────────────────────────────────────────

    /// Open a delivery and route it: who wrote it is read from the sealed inner — the pair its
    /// envelope matched, or the certificate it carries — never from the outer envelope.
    async fn handle_envelope(&mut self, envelope: &Envelope, stream_cursor: Option<String>) {
        let message_id = direct_envelope_message_id(envelope).to_owned();
        let Some(sealed) = envelope.sealed_sender.as_ref() else {
            // Only an account's own devices send unsealed (SENDER_SYNC); this client is not a
            // linked device yet (TODO 218, stage 4).
            tracing::warn!(%message_id, "unsealed delivery dropped: own-device traffic is not handled");
            self.cursor.commit_direct(&self.storage, stream_cursor);
            return;
        };
        let opened = sealing::open_sealed_inner(
            &self.orchestrator,
            &self.identity.device_id,
            &self.identity.identity_secret,
            &sealed.sealed_inner,
        );
        let routed = match opened {
            Ok(Opened::OtherDevice) => {
                tracing::debug!(%message_id, "delivery for another device of this account");
                None
            }
            Err(e) => {
                tracing::warn!(%message_id, "sealed delivery dropped: {e}");
                None
            }
            Ok(Opened::Envelope {
                device,
                session_id,
                body,
                decryption_error,
            }) => {
                let account = self.account_of(&device);
                Some(if decryption_error {
                    (
                        IncomingEvent::DecryptionErrorReceived {
                            contact_id: device.clone(),
                            payload: body,
                            opened: true,
                        },
                        account,
                        device,
                        ContentType::DecryptionError as u8,
                        None,
                    )
                } else {
                    let msg_num = message_number(&body);
                    (
                        IncomingEvent::MessageReceived {
                            message_id: message_id.clone(),
                            from: device.clone(),
                            data: body,
                            sender_certificate: None,
                            content_type: 0,
                            envelope_session: Some(session_id),
                        },
                        account,
                        device,
                        0,
                        msg_num,
                    )
                })
            }
            Ok(Opened::Certified {
                certificate,
                wire_payload,
                content_type,
            }) => {
                let device = certificate.device_id.clone();
                let account = certificate.user_id.clone();
                self.pending_certificates.insert(
                    device.clone(),
                    (account.clone(), certificate.identity_key.clone()),
                );
                Some(if content_type == ContentType::DecryptionError as u8 {
                    (
                        IncomingEvent::DecryptionErrorReceived {
                            contact_id: device.clone(),
                            payload: wire_payload,
                            opened: false,
                        },
                        account,
                        device,
                        content_type,
                        None,
                    )
                } else {
                    let msg_num = message_number(&wire_payload);
                    (
                        IncomingEvent::MessageReceived {
                            message_id: message_id.clone(),
                            from: device.clone(),
                            data: wire_payload,
                            sender_certificate: Some(certificate),
                            content_type: 0,
                            envelope_session: None,
                        },
                        account,
                        device,
                        0,
                        msg_num,
                    )
                })
            }
        };
        let Some((event, account, device, content_type, msg_num)) = routed else {
            self.cursor.commit_direct(&self.storage, stream_cursor);
            return;
        };
        let msg_num = match msg_num {
            Some(Ok(n)) => n,
            Some(Err(e)) => {
                tracing::warn!(%message_id, %device, "delivery dropped: wire payload unpack failed: {e}");
                self.cursor.commit_direct(&self.storage, stream_cursor);
                return;
            }
            // A DECRYPTION_ERROR carries no ratchet message: never replay-sensitive.
            None => 1,
        };
        tracing::info!(%message_id, %device, %account, content_type, msg_num, "sealed delivery opened");
        self.handle_stream_message(
            event,
            StreamMessageContext {
                contact_id: account,
                device,
                message_id,
                stream_cursor,
                content_type,
                msg_num,
            },
        )
        .await;
    }

    async fn handle_stream_message(&mut self, event: IncomingEvent, context: StreamMessageContext) {
        if !self.known_contacts.contains(&context.contact_id) {
            self.cursor
                .commit_direct(&self.storage, context.stream_cursor.clone());
            tracing::warn!(
                contact_id = %context.contact_id,
                message_id = %context.message_id,
                content_type = context.content_type,
                msg_num = context.msg_num,
                stream_cursor = ?context.stream_cursor,
                "dropped stream message from unknown contact"
            );
            return;
        }

        if should_drop_stale_session_replay(&context, &self.session_established_at_ms) {
            self.cursor
                .commit_direct(&self.storage, context.stream_cursor.clone());
            tracing::warn!(
                contact_id = %context.contact_id,
                message_id = %context.message_id,
                content_type = context.content_type,
                msg_num = context.msg_num,
                stream_cursor = ?context.stream_cursor,
                "dropped stale replay-sensitive stream message"
            );
            return;
        }

        self.cursor.note(&context.message_id, context.stream_cursor);
        self.process(event).await;
    }

    // ── Sending ───────────────────────────────────────────────────────────────

    /// An `OutgoingMessage` from the screens names an account: fan it out, one event per device
    /// of the account, each with a session ready. Every other event passes as it is.
    async fn prepare_outgoing(&mut self, event: IncomingEvent) -> Vec<IncomingEvent> {
        let IncomingEvent::OutgoingMessage {
            contact_id,
            message_id,
            plaintext,
            content_type,
        } = event
        else {
            return vec![event];
        };
        let devices = match self.recipient_devices(&contact_id).await {
            Ok(devices) if !devices.is_empty() => devices,
            Ok(_) => {
                self.ui_error(format!(
                    "[NO_DEVICES] {contact_id} has no device to send to"
                ));
                return Vec::new();
            }
            Err(e) => {
                tracing::error!(%contact_id, error = %e, "session init before send failed");
                self.ui_error(format!("[SESSION_INIT_FAILED] {e}"));
                return Vec::new();
            }
        };
        let plaintext = if crate::knst::is_frame(&plaintext) || plaintext.first() == Some(&0) {
            plaintext
        } else {
            crate::knst::encode_text(&String::from_utf8_lossy(&plaintext), &message_id)
        };
        devices
            .into_iter()
            .map(|device| IncomingEvent::OutgoingMessage {
                contact_id: device,
                message_id: message_id.clone(),
                plaintext: plaintext.clone(),
                content_type,
            })
            .collect()
    }

    /// The devices of `account` a message goes to, each with a session. Devices without one get
    /// a bundle from the server (all of the account's when none is known yet) and a session
    /// opened from it. A device whose session cannot be opened is left out with a warning.
    async fn recipient_devices(&mut self, account: &str) -> Result<Vec<String>, String> {
        let known = self.peers.devices_of(account);
        let missing: Vec<String> = known
            .iter()
            .filter(|d| !self.orchestrator.has_session_for_sending(d))
            .cloned()
            .collect();
        if known.is_empty() || !missing.is_empty() {
            let fetched = crate::grpc::get_pre_key_bundles(&self.grpc, account, missing, true)
                .await
                .map_err(|e| format!("GetPreKeyBundles: {e}"))?;
            let fetched_ids: Vec<String> = fetched
                .bundles
                .iter()
                .map(|b| b.device_id.clone())
                .collect();
            for bundle in &fetched.bundles {
                self.peers.record(
                    &self.storage,
                    account,
                    &bundle.device_id,
                    &bundle.bundle.x3dh.identity_public,
                );
            }
            let dropped = self.peers.reconcile(
                &self.storage,
                account,
                &fetched.active_devices,
                &fetched_ids,
            );
            if !dropped.is_empty() {
                tracing::info!(%account, ?dropped, "devices no longer active");
            }
            for bundle in fetched.bundles {
                if self.orchestrator.has_session_for_sending(&bundle.device_id) {
                    continue;
                }
                let device = bundle.device_id.clone();
                if let Err(e) = self.open_session(bundle).await {
                    tracing::warn!(%account, %device, error = %e, "device left out of the send");
                }
            }
        }
        Ok(self
            .peers
            .devices_of(account)
            .into_iter()
            .filter(|d| self.orchestrator.has_active_session(d))
            .collect())
    }

    /// Open an INITIATOR session with a fetched bundle's device.
    async fn open_session(
        &mut self,
        fetched: crate::grpc::FetchedPreKeyBundle,
    ) -> Result<(), String> {
        let device = fetched.device_id;
        self.orchestrator.init_session_with_bundle(
            &device,
            fetched.bundle.x3dh,
            fetched.bundle.kyber,
            false,
        )?;
        self.session_established_at_ms
            .insert(device.clone(), now_ms_u64());
        self.process(IncomingEvent::SessionInitCompleted {
            contact_id: device.clone(),
            session_data: vec![],
        })
        .await;
        if self.orchestrator.has_active_session(&device) {
            Ok(())
        } else {
            Err("no session after init".into())
        }
    }

    /// The account and X25519 identity key of `device`: filed, or named by a certificate that
    /// is waiting on a receiving session.
    fn address_of(&self, device: &str) -> Option<(String, Vec<u8>)> {
        if let (Some(account), Some(key)) = (
            self.peers.account_of(device),
            self.peers.identity_of(device),
        ) {
            return Some((account.to_string(), key.to_vec()));
        }
        self.pending_certificates.get(device).cloned()
    }

    /// The account `device` belongs to, or the device itself when it is not filed (logged: the
    /// screens will not find it).
    fn account_of(&self, device: &str) -> String {
        match self.address_of(device) {
            Some((account, _)) => account,
            None => {
                tracing::warn!(%device, "device belongs to no known account");
                device.to_string()
            }
        }
    }

    /// The sender certificate, fetched again when missing or close to expiry.
    async fn certificate(&mut self) -> Result<Vec<u8>, String> {
        let now = now_ms_u64() as i64 / 1000;
        if let Some(cert) = &self.certificate
            && cert.expires_at - CERTIFICATE_REFRESH_AHEAD_SECS > now
        {
            return Ok(cert.bytes.clone());
        }
        let cert = crate::grpc::get_sender_certificate(&self.grpc)
            .await
            .map_err(|e| format!("GetSenderCertificate: {e}"))?;
        let bytes = cert.bytes.clone();
        self.certificate = Some(cert);
        Ok(bytes)
    }

    /// Seal a wire payload the core wrote for `device` and queue it for the server.
    async fn send_sealed(
        &mut self,
        device: &str,
        payload: Vec<u8>,
        local_id: String,
        decryption_error: Option<bool>,
    ) -> Result<(), String> {
        let (account, identity_key) = self
            .address_of(device)
            .ok_or("the device belongs to no known account")?;
        let (body, content_type) = match decryption_error {
            // The core sealed it along the pair already.
            Some(true) => (
                SealedBody::SessionEnvelope(payload),
                ContentType::Unspecified,
            ),
            Some(false) => {
                let certificate = self.certificate().await?;
                (
                    sealing::certificate_box(&identity_key, &payload, &certificate)?,
                    ContentType::DecryptionError,
                )
            }
            None => {
                let body = match self.orchestrator.seal_envelope(device, &payload) {
                    Some(envelope) => SealedBody::SessionEnvelope(envelope),
                    None => {
                        let certificate = self.certificate().await?;
                        sealing::seal_with_certificate(
                            &self.orchestrator,
                            device,
                            &identity_key,
                            &payload,
                            &certificate,
                        )?
                    }
                };
                (body, ContentType::Unspecified)
            }
        };
        let inner = sealing::sealed_inner(&account, device, body, content_type);
        self.sealed_tx
            .send(OutboundSealed { inner, local_id })
            .map_err(|_| "sealed sender worker stopped".to_string())
    }

    /// A delivery receipt (ct 14) for `message_id` back to the device that wrote it. Queued as
    /// a follow-up so it is written on the session the message just arrived on.
    fn delivery_receipt(&self, device: &str, message_id: &str) -> Option<IncomingEvent> {
        use crate::proto::signaling::v1::{
            DeliveryReceipt, DirectReceipt, ReceiptStatus, delivery_receipt::ReceiptType,
        };
        let account = self.address_of(device)?.0;
        let receipt = DeliveryReceipt {
            receipt_type: Some(ReceiptType::Direct(DirectReceipt {
                message_ids: vec![message_id.to_string()],
                status: ReceiptStatus::Delivered as i32,
                timestamp: now_ms(),
                sender_device_id: self.identity.device_id.clone(),
                recipient_user_id: account,
            })),
        };
        let receipt_id = uuid::Uuid::new_v4().to_string();
        Some(IncomingEvent::OutgoingMessage {
            contact_id: device.to_string(),
            plaintext: crate::knst::frame_whole(
                &receipt.encode_to_vec(),
                crate::knst::CONTENT_DELIVERY_RECEIPT,
                &receipt_id,
            ),
            message_id: receipt_id,
            content_type: 0,
        })
    }

    /// A delivery receipt arrived: the ids it names are the server's for messages we sent.
    fn receipt_received(&self, body: &[u8]) {
        use crate::proto::signaling::v1::{DeliveryReceipt, delivery_receipt::ReceiptType};
        let receipt = match DeliveryReceipt::decode(body) {
            Ok(receipt) => receipt,
            Err(e) => {
                tracing::warn!(error = %e, "delivery receipt does not parse");
                return;
            }
        };
        let Some(ReceiptType::Direct(direct)) = receipt.receipt_type else {
            return;
        };
        for server_id in direct.message_ids {
            let local_id = match self.storage.local_message_id(&server_id) {
                Ok(Some(local_id)) => local_id,
                _ => {
                    tracing::debug!(%server_id, "receipt for a message this device did not send");
                    continue;
                }
            };
            let _ = self.storage.mark_delivered(&local_id);
            let _ = self.internal_tx.send(crate::client::ClientEvent::Bridge(
                BridgeEvent::MessageDelivered {
                    message_id: local_id,
                },
            ));
        }
    }

    fn ui_error(&self, message: String) {
        let _ = self
            .internal_tx
            .send(crate::client::ClientEvent::Bridge(BridgeEvent::Error(
                message,
            )));
    }

    // ── Action dispatch ───────────────────────────────────────────────────────

    async fn dispatch(&mut self, action: Action, follow_ups: &mut Vec<IncomingEvent>) {
        match action {
            // ── Crypto (platform must handle synchronously) ────────────────────
            Action::OpenReceiving { contact_id } => {
                let opened = self.orchestrator.open_receiving(&contact_id);
                if opened.awaiting_server_key {
                    tracing::warn!(%contact_id, "trusted server key is required to open receiving session");
                }
                if let Some(device) = &opened.opened_device {
                    crate::prekeys::save_after_responder_init(
                        &mut self.orchestrator,
                        &self.storage,
                    );
                    match self.pending_certificates.remove(device) {
                        Some((account, key)) => {
                            self.peers.record(&self.storage, &account, device, &key);
                        }
                        None => tracing::warn!(%device, "session opened with no certificate held"),
                    }
                } else if let Some(error) = &opened.last_error {
                    self.ui_error(format!("[SESSION_OPEN] {error}"));
                }
                for action in opened.actions {
                    Box::pin(self.dispatch(action, follow_ups)).await;
                }
            }
            Action::OpenSession { contact_id } => {
                let tx = self.self_tx.clone();
                let grpc = self.grpc.clone();
                let account = self.address_of(&contact_id).map(|(account, _)| account);
                tokio::spawn(async move {
                    let bundle = match account {
                        Some(account) => crate::grpc::get_pre_key_bundles(
                            &grpc,
                            &account,
                            vec![contact_id.clone()],
                            true,
                        )
                        .await
                        .ok()
                        .and_then(|f| f.bundles.into_iter().find(|b| b.device_id == contact_id)),
                        None => None,
                    };
                    let _ = tx.send(match bundle {
                        Some(fetched) => IncomingEvent::SessionBundleFetched {
                            contact_id,
                            bundle: Box::new(Ok(fetched.bundle)),
                        },
                        None => IncomingEvent::SessionBundleUnavailable { contact_id },
                    });
                });
            }

            // ── Decrypted message ready ─────────────────────────────────────────
            Action::MessageDecrypted {
                contact_id,
                message_id,
                plaintext,
            } => {
                let account = self.account_of(&contact_id);
                let text = crate::knst::decode_text(&plaintext);
                tracing::info!(
                    device = %contact_id,
                    %account,
                    message_id = %message_id,
                    plaintext_len = plaintext.len(),
                    "MessageDecrypted: storing and notifying UI"
                );
                let now_ms = now_ms();
                persist_inbound(
                    &self.storage,
                    &self.cursor,
                    &message_id,
                    crate::storage::StoredMessage {
                        id: message_id.clone(),
                        peer_id: account.clone(),
                        text: text.clone(),
                        direction: "received".into(),
                        timestamp_ms: now_ms,
                        delivery_status: String::new(),
                    },
                );
                if let Some(receipt) = self.delivery_receipt(&contact_id, &message_id) {
                    follow_ups.push(receipt);
                }
                let _ = self.internal_tx.send(crate::client::ClientEvent::Bridge(
                    BridgeEvent::NewMessage {
                        peer_id: account,
                        message_id,
                        text,
                        timestamp_ms: now_ms,
                    },
                ));
            }

            Action::CallSignalDecrypted { .. } => {
                // Calls not yet implemented in TUI.
            }

            Action::ControlFrameDecrypted {
                content_type, body, ..
            } => {
                if content_type == crate::knst::CONTENT_DELIVERY_RECEIPT {
                    self.receipt_received(&body);
                } else {
                    // Heartbeat, card, profile, read markers, retired ping/ready: never shown.
                    tracing::debug!(content_type, "control frame — not handled by the TUI");
                }
            }

            Action::MessageQueuedPendingInit { .. } => {}

            // ── Persistence ─────────────────────────────────────────────────────
            Action::SaveToSecureStore { slot, data } => {
                let key = secure_store_key(&slot);
                if let Err(error) = self.storage.secure_save_or_delete(&key, data.as_ref()) {
                    tracing::error!(%key, %error, "secure store save failed");
                }
                // A session's envelope keys live in the orchestrator state (the envelope book),
                // not in the session record; a session restored without them is refused
                // (SESSION_PREDATES_ENVELOPE). The core does not ask for this save itself.
                if matches!(
                    slot,
                    construct_core::orchestration::actions::SecureStoreSlot::Session { .. }
                ) {
                    self.save_orchestrator_state();
                }
            }
            Action::DuplicateDropped { message_id } => {
                self.cursor.commit(&self.storage, &message_id)
            }
            // A payload the core cannot parse (or a retired suite): nothing will ever read it, so
            // it is recorded and passed like a duplicate. The core sends the NotifyError beside it.
            Action::MalformedDropped { message_id } => {
                self.cursor.commit(&self.storage, &message_id)
            }

            Action::PersistAck {
                message_id,
                timestamp,
            } => {
                let _ = self.storage.store_ack(&message_id, timestamp as i64);
            }

            Action::PruneAckStore { cutoff_ts } => {
                let _ = self.storage.prune_acks(cutoff_ts as i64);
            }

            Action::MarkMessageDelivered { message_id } => {
                let _ = self.storage.mark_delivered(&message_id);
            }

            Action::CheckAckInDb { message_id } => {
                let is_processed = self.storage.has_ack(&message_id).unwrap_or(false);
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
                ..
            } => {
                if let Err(e) = self
                    .send_sealed(&to, payload, message_id.clone(), None)
                    .await
                {
                    tracing::warn!(device = %to, %message_id, error = %e, "send held");
                    self.ui_error(format!("[SEND_HELD] {e}"));
                }
            }

            Action::SendDecryptionError {
                contact_id,
                message_id,
                payload,
                enveloped,
            } => {
                let local_id = uuid::Uuid::new_v4().to_string();
                if let Err(e) = self
                    .send_sealed(&contact_id, payload, local_id, Some(enveloped))
                    .await
                {
                    tracing::warn!(device = %contact_id, %message_id, error = %e, "decryption error held");
                }
            }
            Action::SessionRetired { contact_id, .. } => {
                self.session_established_at_ms.remove(&contact_id);
            }
            Action::ResendMessage {
                contact_id,
                message_id,
            } => {
                tracing::warn!(%contact_id, %message_id, "resend requires outgoing message lookup");
            }

            // ── UI notifications ─────────────────────────────────────────────────
            // A notification hint beside a `MessageDecrypted` the screens already got; its preview
            // is the raw plaintext (KNST frame), so shown as a message it made a second bubble.
            Action::NotifyNewMessage { chat_id, .. } => {
                tracing::debug!(device = %chat_id, "new message notification hint");
            }

            Action::NotifySessionCreated { contact_id } => {
                tracing::info!(device = %contact_id, "Session created");
                let contact_id = self.account_of(&contact_id);
                let _ = self.internal_tx.send(crate::client::ClientEvent::Bridge(
                    BridgeEvent::SessionReady { contact_id },
                ));
            }

            Action::NotifyError { code, message } => {
                tracing::warn!(%code, %message, "NotifyError from orchestrator");
                self.ui_error(format!("[{code}] {message}"));
            }

            // ── Timers ──────────────────────────────────────────────────────────
            Action::ScheduleTimer { timer_id, delay_ms } => {
                let tx = self.self_tx.clone();
                let tid = timer_id.clone();
                let handle = tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                    let _ = tx.send(IncomingEvent::TimerFired { timer_id: tid });
                });
                if let Some(previous) = self.timers.insert(timer_id, handle.abort_handle()) {
                    previous.abort();
                }
            }
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn secure_store_key(slot: &construct_core::orchestration::actions::SecureStoreSlot) -> String {
    use construct_core::orchestration::actions::SecureStoreSlot;
    match slot {
        SecureStoreSlot::Session { contact_id } => format!("session_{contact_id}"),
        SecureStoreSlot::OrchestratorState => "construct.orchestrator_state".into(),
    }
}

fn message_number(wire_payload: &[u8]) -> Option<Result<u32, String>> {
    Some(
        construct_core::wire_payload::unpack(wire_payload)
            .map(|decoded| decoded.message_number)
            .map_err(|e| e.to_string()),
    )
}

fn direct_envelope_message_id(envelope: &Envelope) -> &str {
    match &envelope.message_id_type {
        Some(MessageIdType::MessageId(id)) => id,
        Some(MessageIdType::GroupMessageId(_)) | None => "",
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

fn should_drop_stale_session_replay(
    context: &StreamMessageContext,
    session_established_at_ms: &HashMap<String, u64>,
) -> bool {
    if !context.is_replay_sensitive() {
        return false;
    }
    let Some(established_at_ms) = session_established_at_ms.get(&context.device) else {
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
        established.insert("bob-device".to_string(), 2000);

        let context = stream_context("bob", 0, 0, Some("1000-0"));

        assert!(should_drop_stale_session_replay(&context, &established));
    }

    #[test]
    fn stale_replay_guard_drops_old_reset_control() {
        let mut established = HashMap::new();
        established.insert("bob-device".to_string(), 2000);

        let context = stream_context("bob", ContentType::SessionReset as u8, 42, Some("1000-0"));

        assert!(should_drop_stale_session_replay(&context, &established));
    }

    #[test]
    fn stale_replay_guard_keeps_old_regular_message() {
        let mut established = HashMap::new();
        established.insert("bob-device".to_string(), 2000);

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
        established.insert("bob-device".to_string(), 2000);

        let context = stream_context("bob", 0, 0, Some("3000-0"));

        assert!(!should_drop_stale_session_replay(&context, &established));
    }

    #[test]
    fn stale_replay_guard_keys_on_the_device_not_the_account() {
        let mut established = HashMap::new();
        established.insert("bob".to_string(), 2000);

        let context = stream_context("bob", 0, 0, Some("1000-0"));

        assert!(!should_drop_stale_session_replay(&context, &established));
    }

    #[tokio::test]
    async fn stream_message_command_terminally_drops_stale_msg_zero() {
        let mut task = test_task();
        task.known_contacts.insert("bob".into());
        task.session_established_at_ms
            .insert("bob-device".into(), 2_000);

        let (event, context) = stale_message("bob", "stale-msg0", 0, 0);
        task.handle_stream_message(event, context).await;

        assert_eq!(
            task.storage.load_stream_cursor().unwrap().as_deref(),
            Some("1000-0")
        );
        assert_eq!(
            task.orchestrator.pending_message_count("bob-device"),
            0,
            "stale msgNum=0 must not enter core pending init queue"
        );
    }

    #[tokio::test]
    async fn stream_message_command_terminally_drops_stale_reset_with_invalid_wire_payload() {
        let mut task = test_task();
        task.known_contacts.insert("bob".into());
        task.session_established_at_ms
            .insert("bob-device".into(), 2_000);

        let (event, context) =
            stale_message("bob", "stale-reset", ContentType::SessionReset as u8, 0);
        task.handle_stream_message(event, context).await;

        assert_eq!(
            task.storage.load_stream_cursor().unwrap().as_deref(),
            Some("1000-0")
        );
        assert_eq!(
            task.orchestrator.pending_message_count("bob-device"),
            0,
            "stale reset control must not archive/heal the active actor session"
        );
    }

    #[tokio::test]
    async fn stream_message_command_drops_unknown_contact_before_core_pending_queue() {
        let mut task = test_task();

        let (event, context) = stale_message("bob", "unknown-msg0", 0, 0);
        task.handle_stream_message(event, context).await;

        assert_eq!(
            task.storage.load_stream_cursor().unwrap().as_deref(),
            Some("1000-0")
        );
        assert_eq!(
            task.orchestrator.pending_message_count("bob-device"),
            0,
            "unknown contact backlog must not force a later re-add down RESPONDER path"
        );
    }

    #[tokio::test]
    async fn an_unsealed_delivery_is_dropped_and_passed() {
        let mut task = test_task();
        task.known_contacts.insert("bob".into());
        let envelope = Envelope {
            encrypted_payload: b"plain".to_vec().into(),
            message_id_type: Some(MessageIdType::MessageId("m1".into())),
            ..Default::default()
        };

        task.handle_envelope(&envelope, Some("5000-0".into())).await;

        assert_eq!(
            task.storage.load_stream_cursor().unwrap().as_deref(),
            Some("5000-0")
        );
    }

    #[test]
    fn a_receipt_names_the_server_id_and_marks_our_message_delivered() {
        let task = test_task();
        task.storage
            .store_message(&crate::storage::StoredMessage {
                id: "local-1".into(),
                peer_id: "bob".into(),
                text: "hi".into(),
                direction: "sent".into(),
                timestamp_ms: 1,
                delivery_status: String::new(),
            })
            .unwrap();
        task.storage
            .record_server_message_id("server-1", "local-1")
            .unwrap();
        let receipt = {
            use crate::proto::signaling::v1::{
                DeliveryReceipt, DirectReceipt, delivery_receipt::ReceiptType,
            };
            DeliveryReceipt {
                receipt_type: Some(ReceiptType::Direct(DirectReceipt {
                    message_ids: vec!["server-1".into(), "unknown".into()],
                    ..Default::default()
                })),
            }
        };

        task.receipt_received(&receipt.encode_to_vec());

        let messages = task.storage.get_messages("bob", 10).unwrap();
        assert_eq!(messages[0].delivery_status, "delivered");
    }

    #[test]
    fn a_receipt_goes_to_the_writing_device_framed_as_ct_14() {
        let mut task = test_task();
        let key = vec![4u8; 32];
        let device = construct_core::device_id::derive_device_id(&key);
        task.peers.record(&task.storage, "bob", &device, &key);

        let Some(IncomingEvent::OutgoingMessage {
            contact_id,
            plaintext,
            ..
        }) = task.delivery_receipt(&device, "server-9")
        else {
            panic!("a filed device gets a receipt");
        };

        assert_eq!(contact_id, device);
        let frame = construct_core::knst::Frame::parse(&plaintext).expect("a KNST frame");
        assert_eq!(frame.content_type, crate::knst::CONTENT_DELIVERY_RECEIPT);
        let receipt =
            crate::proto::signaling::v1::DeliveryReceipt::decode(frame.payload).expect("parses");
        let Some(crate::proto::signaling::v1::delivery_receipt::ReceiptType::Direct(direct)) =
            receipt.receipt_type
        else {
            panic!("a direct receipt");
        };
        assert_eq!(direct.message_ids, vec!["server-9".to_string()]);
        assert_eq!(direct.recipient_user_id, "bob");
        assert_eq!(direct.sender_device_id, "device-a");
    }

    #[tokio::test]
    async fn a_session_save_saves_the_envelope_book_with_it() {
        use construct_core::orchestration::actions::SecureStoreSlot;
        let mut task = test_task();
        let mut follow_ups = Vec::new();

        task.dispatch(
            Action::SaveToSecureStore {
                slot: SecureStoreSlot::Session {
                    contact_id: "bob-device".into(),
                },
                data: vec![1, 2, 3].into(),
            },
            &mut follow_ups,
        )
        .await;

        assert!(
            task.storage
                .secure_load("construct.orchestrator_state")
                .unwrap()
                .is_some(),
            "without the orchestrator state the session restores with no envelope keys"
        );
    }

    #[tokio::test]
    async fn a_notification_hint_is_not_a_second_message() {
        let (internal_tx, mut internal_rx) = mpsc::unbounded_channel();
        let mut task = test_task();
        task.internal_tx = internal_tx;
        let mut follow_ups = Vec::new();

        task.dispatch(
            Action::NotifyNewMessage {
                chat_id: "bob-device".into(),
                preview: "KNST raw frame".into(),
            },
            &mut follow_ups,
        )
        .await;

        assert!(internal_rx.try_recv().is_err());
    }

    fn stream_context(
        contact_id: &str,
        content_type: u8,
        msg_num: u32,
        stream_cursor: Option<&str>,
    ) -> StreamMessageContext {
        StreamMessageContext {
            contact_id: contact_id.to_string(),
            device: format!("{contact_id}-device"),
            message_id: "message-1".to_string(),
            stream_cursor: stream_cursor.map(str::to_string),
            content_type,
            msg_num,
        }
    }

    fn stale_message(
        contact_id: &str,
        message_id: &str,
        content_type: u8,
        msg_num: u32,
    ) -> (IncomingEvent, StreamMessageContext) {
        let device = format!("{contact_id}-device");
        (
            IncomingEvent::MessageReceived {
                message_id: message_id.to_string(),
                from: device.clone(),
                data: b"not-a-wire-payload".to_vec(),
                sender_certificate: None,
                content_type,
                envelope_session: None,
            },
            StreamMessageContext {
                contact_id: contact_id.to_string(),
                device,
                message_id: message_id.to_string(),
                stream_cursor: Some("1000-0".to_string()),
                content_type,
                msg_num,
            },
        )
    }

    fn test_task() -> Task {
        let client = ClassicClient::<ClassicSuiteProvider>::new()
            .expect("test ClassicClient should initialize");
        let orchestrator = Orchestrator::new(client, "device-a".to_string());
        let storage = Storage::open_in_memory().expect("in-memory storage opens");
        let cursor = CursorTracker::load(&storage);
        let (internal_tx, _internal_rx) = mpsc::unbounded_channel();
        let (self_tx, _self_rx) = mpsc::unbounded_channel();
        let (sealed_tx, _sealed_rx) = mpsc::unbounded_channel();
        Task::new(
            orchestrator,
            storage,
            internal_tx,
            GrpcClient::new("https://127.0.0.1:1"),
            sealed_tx,
            cursor,
            Vec::new(),
            LocalIdentity {
                device_id: "device-a".into(),
                identity_secret: vec![1u8; 32],
                signing_secret: vec![2u8; 32],
                replace_prekeys: false,
            },
            self_tx,
        )
    }
}
