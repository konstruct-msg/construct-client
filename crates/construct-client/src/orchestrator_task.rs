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
use crate::local_store::LocalStore;
use crate::peers::PeerDevices;
use crate::proto::core::v1::{ContentType, Envelope, SealedInner, envelope::MessageIdType};
use crate::sealing::{self, Opened, SealedBody};
use crate::streaming::CursorTracker;

/// How long an account's device set is trusted before it is asked again.
const DEVICES_RECHECK: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// How long a device being linked has to publish its keys before it is vouched for, and how
/// often the directory is asked (iOS `DeviceCertificateIssuer`).
const VOUCH_DEADLINE: std::time::Duration = std::time::Duration::from_secs(15 * 60);
const VOUCH_POLL: std::time::Duration = std::time::Duration::from_secs(5);

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

    /// Vouch for `device_id`, a device just linked to this account, once the directory serves
    /// the keys `evidence` names.
    pub(crate) fn vouch(&self, device_id: String, evidence: crate::device_certs::Evidence) {
        let _ = self.cmd_tx.send(OrchestratorCommand::Vouch {
            device_id,
            evidence,
        });
    }

    /// Send `content` to `peer` (see [`OrchestratorCommand::Send`]).
    pub(crate) fn send_content(
        &self,
        peer: String,
        message_id: String,
        content: crate::content::Content,
    ) {
        let payload = crate::content::encode(&content);
        let _ = self.cmd_tx.send(OrchestratorCommand::Send {
            peer,
            message_id,
            content,
            payload,
        });
    }

    /// Send a `MessageContent` made elsewhere — a file's — to `peer`. Not sent when it reads as
    /// no message.
    pub(crate) fn send_payload(&self, peer: String, message_id: String, payload: Vec<u8>) {
        let Some(content) = crate::content::parse(&payload) else {
            return tracing::warn!(%message_id, "not a message — not sent");
        };
        let _ = self.cmd_tx.send(OrchestratorCommand::Send {
            peer,
            message_id,
            content,
            payload,
        });
    }

    /// Our profile to every device of `peer`.
    pub(crate) fn send_profile(&self, peer: String, payload: Vec<u8>) {
        let _ = self.cmd_tx.send(OrchestratorCommand::SendControl {
            peer,
            content_type: crate::knst::CONTENT_PROFILE,
            payload,
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
    /// Send `content` to `peer` under `message_id`: kept here as ours, copied to our other
    /// devices, then sent to each of the peer's.
    Send {
        peer: String,
        message_id: String,
        content: crate::content::Content,
        /// `content` as it goes on the wire.
        payload: Vec<u8>,
    },
    /// A control frame to every device of `peer` (a profile, content type 29).
    SendControl {
        peer: String,
        content_type: u8,
        payload: Vec<u8>,
    },
    /// Vouch for a device being linked to this account once the directory serves its keys.
    Vouch {
        device_id: String,
        evidence: crate::device_certs::Evidence,
    },
    /// The directory serves the keys of a device being vouched for.
    VouchKeys {
        device_id: String,
        evidence: crate::device_certs::Evidence,
        keys: crate::device_certs::SubjectKeys,
    },
    /// The sealed sender worker sent `local_id`; the server calls it `server_id`.
    Sent {
        server_id: String,
        local_id: String,
    },
}

/// One send, queued for the worker that sends them in order.
enum Outbound {
    /// To another account: sealed, on the connection without a token.
    Sealed {
        inner: Box<SealedInner>,
        local_id: String,
    },
    /// A copy to one of our own devices: identified, on the authenticated connection.
    OwnCopy { envelope: Box<Envelope> },
}

// ── Startup ───────────────────────────────────────────────────────────────────

/// What the task needs about this device.
pub struct LocalIdentity {
    /// Our account: copies between our devices name it as both sender and recipient.
    pub user_id: String,
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
    storage: LocalStore,
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

    let avatars = anonymous.clone();
    let sealed_tx = spawn_sender(anonymous, grpc.clone(), cmd_tx.clone(), internal_tx.clone());
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
        cmd_tx,
    );
    task.anonymous = Some(avatars);
    tokio::spawn(async move { task.run(rx, cmd_rx).await });

    handle
}

/// Sends one at a time, in the order queued: two copies to one device must reach the server in
/// the order their ratchet wrote them.
fn spawn_sender(
    anonymous: GrpcClient,
    authenticated: GrpcClient,
    cmd_tx: mpsc::UnboundedSender<OrchestratorCommand>,
    internal_tx: mpsc::UnboundedSender<crate::client::ClientEvent>,
) -> mpsc::UnboundedSender<Outbound> {
    let (tx, mut rx) = mpsc::unbounded_channel::<Outbound>();
    tokio::spawn(async move {
        while let Some(outbound) = rx.recv().await {
            match outbound {
                Outbound::Sealed { inner, local_id } => {
                    match crate::grpc::send_sealed_message(&anonymous, &inner).await {
                        Ok(server_id) => {
                            tracing::info!(%local_id, %server_id, "sealed message sent");
                            let _ = cmd_tx.send(OrchestratorCommand::Sent {
                                server_id,
                                local_id,
                            });
                        }
                        Err(e) => {
                            tracing::warn!(%local_id, error = %e, "sealed send failed");
                            let _ = internal_tx.send(crate::client::ClientEvent::Bridge(
                                BridgeEvent::Error(format!("[SEND_FAILED] {e}")),
                            ));
                        }
                    }
                }
                // Best effort, as on iOS: a copy that does not arrive costs a bubble on the other
                // device, not the message.
                Outbound::OwnCopy { envelope } => {
                    let id = direct_envelope_message_id(&envelope).to_owned();
                    match crate::grpc::send_own_device_copy(&authenticated, *envelope).await {
                        Ok(()) => tracing::info!(%id, "own-device copy sent"),
                        Err(e) => tracing::warn!(%id, error = %e, "own-device copy not sent"),
                    }
                }
            }
        }
    });
    tx
}

// ── The task ──────────────────────────────────────────────────────────────────

struct Task {
    orchestrator: Orchestrator,
    storage: LocalStore,
    internal_tx: mpsc::UnboundedSender<crate::client::ClientEvent>,
    grpc: GrpcClient,
    sealed_tx: mpsc::UnboundedSender<Outbound>,
    cursor: CursorTracker,
    identity: LocalIdentity,
    self_tx: mpsc::UnboundedSender<IncomingEvent>,
    /// Commands back to this task, from its own sub-tasks.
    self_cmd: mpsc::UnboundedSender<OrchestratorCommand>,
    timers: HashMap<String, AbortHandle>,
    session_established_at_ms: HashMap<String, u64>,
    known_contacts: HashSet<String>,
    peers: PeerDevices,
    certificate: Option<SenderCertificate>,
    /// Certificates of first messages waiting on a receiving session, by device: filed in
    /// `peers` once the session opens from them, and the address a DECRYPTION_ERROR goes back
    /// to if it does not.
    pending_certificates: HashMap<String, (String, Vec<u8>)>,
    /// When each account's device set was last asked of the server.
    devices_checked: HashMap<String, tokio::time::Instant>,
    /// The client that never holds a token: avatars a profile names are fetched on it.
    anonymous: Option<GrpcClient>,
}

impl Task {
    #[allow(clippy::too_many_arguments)]
    fn new(
        mut orchestrator: Orchestrator,
        storage: LocalStore,
        internal_tx: mpsc::UnboundedSender<crate::client::ClientEvent>,
        grpc: GrpcClient,
        sealed_tx: mpsc::UnboundedSender<Outbound>,
        cursor: CursorTracker,
        known_contacts: Vec<String>,
        identity: LocalIdentity,
        self_tx: mpsc::UnboundedSender<IncomingEvent>,
        self_cmd: mpsc::UnboundedSender<OrchestratorCommand>,
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
            self_cmd,
            timers: HashMap::new(),
            session_established_at_ms: HashMap::new(),
            known_contacts: known_contacts.into_iter().collect(),
            peers,
            certificate: None,
            pending_certificates: HashMap::new(),
            devices_checked: HashMap::new(),
            anonymous: None,
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
        // The first tick is now: rotation and top-up are checked at launch too.
        let mut maintenance = tokio::time::interval(crate::prekeys::MAINTENANCE_INTERVAL);
        maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = maintenance.tick() => {
                    if let Err(e) = crate::prekeys::maintain(
                        &mut self.orchestrator,
                        &self.storage,
                        &self.grpc,
                        &self.identity.device_id,
                    )
                    .await
                    {
                        tracing::warn!(error = %e, "prekey maintenance failed");
                    }
                }
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
            OrchestratorCommand::Send {
                peer,
                message_id,
                content,
                payload,
            } => self.send_content(peer, message_id, content, payload).await,
            OrchestratorCommand::SendControl {
                peer,
                content_type,
                payload,
            } => self.send_control(peer, content_type, payload).await,
            OrchestratorCommand::Vouch {
                device_id,
                evidence,
            } => self.await_subject_keys(device_id, evidence),
            OrchestratorCommand::VouchKeys {
                device_id,
                evidence,
                keys,
            } => self.vouch(device_id, &evidence, &keys),
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

    /// Wait, off the task, for the directory to serve the keys of `device_id`: a device being
    /// linked publishes its hybrid key and binding only with its first prekey upload, after the
    /// link. Pending work lives in memory; a client closed meanwhile leaves the device
    /// unvouched, and its peers see the alarm — the safe side.
    fn await_subject_keys(&self, device_id: String, evidence: crate::device_certs::Evidence) {
        let grpc = self.grpc.clone();
        let account = self.identity.user_id.clone();
        let commands = self.self_cmd.clone();
        tokio::spawn(async move {
            let deadline = tokio::time::Instant::now() + VOUCH_DEADLINE;
            while tokio::time::Instant::now() < deadline {
                tokio::time::sleep(VOUCH_POLL).await;
                let listed = match crate::grpc::get_pre_key_bundles(
                    &grpc,
                    &account,
                    vec![device_id.clone()],
                    false,
                )
                .await
                {
                    Ok(listed) => listed,
                    Err(e) => {
                        tracing::debug!(device = %device_id, error = %e, "device keys unavailable");
                        continue;
                    }
                };
                let keys = listed
                    .bundles
                    .iter()
                    .find(|b| b.device_id == device_id)
                    .and_then(crate::device_certs::SubjectKeys::of);
                if let Some(keys) = keys {
                    let _ = commands.send(OrchestratorCommand::VouchKeys {
                        device_id,
                        evidence,
                        keys,
                    });
                    return;
                }
            }
            tracing::info!(device = %device_id, "keys not published in time: not vouched");
        });
    }

    /// Ask the core for a certificate over the keys the directory serves, and publish it. The
    /// core signs only the keys the link code named; other keys are the substitution the
    /// certificate exists to catch, reported and never retried.
    fn vouch(
        &self,
        device_id: String,
        evidence: &crate::device_certs::Evidence,
        keys: &crate::device_certs::SubjectKeys,
    ) {
        use construct_core::crypto::device_certificate::CertError;
        let certificate = match self
            .orchestrator
            .issue_device_certificate(&keys.view(), &evidence.view())
        {
            Ok(certificate) => certificate,
            Err(CertError::EvidenceMismatch) => {
                tracing::error!(device = %device_id, "directory keys differ from the link code: refused");
                return self.ui_error(format!(
                    "[DEVICE_CERT] The server's keys for device {} differ from its code: not vouched",
                    &device_id[..8.min(device_id.len())]
                ));
            }
            Err(e) => {
                return tracing::error!(device = %device_id, error = ?e, "certificate not issued");
            }
        };
        let grpc = self.grpc.clone();
        tokio::spawn(async move {
            for _ in 0..5 {
                match crate::grpc::publish_device_certificate(
                    &grpc,
                    &device_id,
                    certificate.clone(),
                )
                .await
                {
                    Ok(()) => return tracing::info!(device = %device_id, "device vouched for"),
                    Err(e) => {
                        tracing::warn!(device = %device_id, error = %e, "certificate not published")
                    }
                }
                tokio::time::sleep(VOUCH_POLL).await;
            }
        });
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
            self.peers.forget(&device);
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
            // Only an account's own devices send unsealed: a copy of a message sent elsewhere.
            if envelope.content_type == ContentType::SenderSync as i32 {
                self.handle_own_copy(envelope).await;
            } else {
                tracing::warn!(%message_id, content_type = envelope.content_type, "unsealed delivery dropped");
            }
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
        // A delivery from an account with no contact row is taken in: a device linked to an
        // account starts with no contacts at all. Its writer becomes a contact once a message
        // from it decrypts (`adopt_writer`).
        if !self.known_contacts.contains(&context.contact_id) {
            tracing::info!(
                contact_id = %context.contact_id,
                message_id = %context.message_id,
                "delivery from an account that is not a contact"
            );
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
            // Text from the screens: kept in the transcript, copied to our other devices.
            let text = String::from_utf8_lossy(&plaintext).into_owned();
            self.keep_sent(&contact_id, &message_id, &text);
            let content = crate::content::encode(&crate::content::Content::Message {
                text: text.clone(),
                quote: None,
                attachment: None,
            });
            self.send_own_copies(&contact_id, &message_id, &content)
                .await;
            crate::knst::encode_text(&text, &message_id)
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

    /// The devices of `account` a message goes to, each with a session (see `refresh_devices`).
    async fn recipient_devices(&mut self, account: &str) -> Result<Vec<String>, String> {
        self.refresh_devices(account).await?;
        Ok(self
            .peers
            .devices_of(account)
            .into_iter()
            .filter(|d| *d != self.identity.device_id && self.orchestrator.has_active_session(d))
            .collect())
    }

    /// Bring `account`'s device set up to date and give each device a session.
    ///
    /// The set is asked of the server when nothing is known, when a known device has no session,
    /// or every `DEVICES_RECHECK` — a device the account gained since (a desktop linked to the
    /// phone) is otherwise never written to. That ask spends no one-time prekeys; only devices
    /// that need a session are asked again for a bundle that does.
    async fn refresh_devices(&mut self, account: &str) -> Result<(), String> {
        let known = self.peers.devices_of(account);
        let missing = known.iter().any(|d| {
            *d != self.identity.device_id && !self.orchestrator.has_session_for_sending(d)
        });
        let stale = self
            .devices_checked
            .get(account)
            .is_none_or(|at| at.elapsed() >= DEVICES_RECHECK);
        if !known.is_empty() && !missing && !stale {
            return Ok(());
        }
        self.devices_checked
            .insert(account.to_string(), tokio::time::Instant::now());
        let listed = crate::grpc::get_pre_key_bundles(&self.grpc, account, Vec::new(), false)
            .await
            .map_err(|e| format!("GetPreKeyBundles: {e}"))?;
        let listed_ids: Vec<String> = listed.bundles.iter().map(|b| b.device_id.clone()).collect();
        // Judged against the devices trusted before this answer is recorded below. Not our own
        // account, and not one seen for the first time (nothing to vouch from).
        if account != self.identity.user_id && !known.is_empty() {
            let alarm =
                crate::device_certs::vet(&self.orchestrator, account, &known, &listed.bundles);
            if !alarm.is_empty() {
                tracing::error!(%account, devices = ?alarm, "UNVOUCHED devices");
                let _ = self.internal_tx.send(crate::client::ClientEvent::Bridge(
                    BridgeEvent::UnvouchedDevices {
                        peer_id: account.to_string(),
                        device_ids: alarm,
                    },
                ));
            }
        }
        for bundle in &listed.bundles {
            if bundle.device_id != self.identity.device_id {
                self.peers.record(
                    &self.storage,
                    account,
                    &bundle.device_id,
                    &bundle.bundle.x3dh.identity_public,
                );
            }
        }
        let dropped =
            self.peers
                .reconcile(&self.storage, account, &listed.active_devices, &listed_ids);
        if !dropped.is_empty() {
            tracing::info!(%account, ?dropped, "devices no longer active");
        }
        let need: Vec<String> = self
            .peers
            .devices_of(account)
            .into_iter()
            .filter(|d| {
                *d != self.identity.device_id && !self.orchestrator.has_session_for_sending(d)
            })
            .collect();
        if need.is_empty() {
            return Ok(());
        }
        let fetched = crate::grpc::get_pre_key_bundles(&self.grpc, account, need, true)
            .await
            .map_err(|e| format!("GetPreKeyBundles: {e}"))?;
        for bundle in fetched.bundles {
            let device = bundle.device_id.clone();
            if let Err(e) = self.open_session(bundle).await {
                tracing::warn!(%account, %device, error = %e, "device left out of the send");
            }
        }
        Ok(())
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
            .send(Outbound::Sealed {
                inner: Box::new(inner),
                local_id,
            })
            .map_err(|_| "sealed sender worker stopped".to_string())
    }

    /// A delivery receipt (ct 14) for `message_id` back to the device that wrote it. Queued as
    /// a follow-up so it is written on the session the message just arrived on.
    /// None when the person turned receipts off: then no sender learns that this device got
    /// their message (iOS `DeliveryReceiptPreference`).
    fn delivery_receipt(&self, device: &str, message_id: &str) -> Option<IncomingEvent> {
        use crate::proto::signaling::v1::{
            DeliveryReceipt, DirectReceipt, ReceiptStatus, delivery_receipt::ReceiptType,
        };
        if !self.storage.sends_delivery_receipts() {
            return None;
        }
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

    /// A profile `account` shared: applied if newer and they are held, then shown; an avatar it
    /// names is fetched aside.
    fn profile_received(&mut self, account: &str, body: &[u8]) {
        let Some(profile) = crate::profile::ProfileShare::decode(body) else {
            return tracing::warn!("profile does not parse");
        };
        match self.storage.apply_profile(account, &profile, now_ms()) {
            Ok(Some(action)) => {
                self.contact_updated(account);
                if matches!(action, crate::profile::AvatarAction::Download(_)) {
                    self.fetch_avatar(account.to_string());
                }
            }
            Ok(None) => tracing::info!("profile not newer, or from no one held — ignored"),
            Err(e) => tracing::warn!(error = %e, "profile not kept"),
        }
    }

    fn contact_updated(&self, account: &str) {
        contact_updated(&self.storage, &self.internal_tx, account);
    }

    fn fetch_avatar(&self, account: String) {
        let Some(anonymous) = self.anonymous.clone() else {
            return;
        };
        let storage = self.storage.clone();
        let events = self.internal_tx.clone();
        tokio::spawn(async move {
            if crate::profile::fetch_pending_avatar(&storage, &anonymous, &account).await {
                contact_updated(&storage, &events, &account);
            }
        });
    }

    /// A control frame (`content_type`) to every device of `peer`: not kept, not copied to our
    /// other devices.
    async fn send_control(&mut self, peer: String, content_type: u8, payload: Vec<u8>) {
        let message_id = uuid::Uuid::new_v4().to_string();
        let event = IncomingEvent::OutgoingMessage {
            contact_id: peer,
            plaintext: crate::knst::frame_whole(&payload, content_type, &message_id),
            message_id,
            content_type: 0,
        };
        for event in self.prepare_outgoing(event).await {
            self.process(event).await;
        }
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

    /// Save `device`'s session and the envelope book beside it, after the core changed it
    /// outside the event loop (a sibling's copy, opened or written directly).
    fn persist_session(&self, device: &str) {
        match self.orchestrator.export_session_cfe(device) {
            Ok(bytes) => {
                if let Err(e) = self
                    .storage
                    .secure_save(&format!("session_{device}"), &bytes)
                {
                    tracing::error!(%device, error = %e, "session save failed");
                }
            }
            Err(e) => tracing::error!(%device, error = %e, "session export failed"),
        }
        self.save_orchestrator_state();
    }

    /// The writer of a message that decrypted becomes a contact, so its chat shows.
    fn adopt_writer(&mut self, account: &str) {
        if self.known_contacts.contains(account)
            || account == self.identity.user_id
            || uuid::Uuid::parse_str(account).is_err()
        {
            return;
        }
        let username = format!("{}…", &account[..8]);
        if let Err(e) = self
            .storage
            .upsert_contact(&crate::local_store::StoredContact {
                user_id: account.to_string(),
                display_name: username.clone(),
                identity_key_b64: String::new(),
                ..Default::default()
            })
        {
            tracing::warn!(%account, error = %e, "new contact not saved");
        }
        self.known_contacts.insert(account.to_string());
        let _ = self
            .internal_tx
            .send(crate::client::ClientEvent::ContactAdded {
                user_id: account.to_string(),
                username,
            });
    }

    /// A message we send, in the transcript from the moment it is handed over.
    fn keep_sent(&self, peer: &str, message_id: &str, text: &str) {
        if let Err(e) = self
            .storage
            .store_message(&crate::local_store::StoredMessage {
                id: message_id.to_string(),
                peer_id: peer.to_string(),
                text: text.to_string(),
                direction: "sent".into(),
                timestamp_ms: now_ms(),
                delivery_status: String::new(),
                ..Default::default()
            })
        {
            tracing::warn!(%message_id, error = %e, "sent message not kept");
        }
    }

    /// Our other devices, each with a session (see `refresh_devices`).
    async fn own_siblings(&mut self) -> Vec<String> {
        let me = self.identity.user_id.clone();
        if let Err(e) = self.refresh_devices(&me).await {
            tracing::warn!(error = %e, "own device set unavailable");
        }
        self.peers
            .devices_of(&me)
            .into_iter()
            .filter(|d| *d != self.identity.device_id && self.orchestrator.has_active_session(d))
            .collect()
    }

    /// A copy of a text we sent to `partner`, for each of our other devices (SENDER_SYNC).
    /// Send what the screens wrote. It is placed here first, as a copy from another of our
    /// devices would be — an edit only of our own message, a reaction by its clock — and not
    /// sent when that changes nothing (an edit of a message that is not ours).
    async fn send_content(
        &mut self,
        peer: String,
        message_id: String,
        content: crate::content::Content,
        payload: Vec<u8>,
    ) {
        // Text the screens learned of from `MessageQueued`; a file they learn of here, once kept.
        let is_message = matches!(
            content,
            crate::content::Content::Message {
                attachment: None,
                ..
            }
        );
        let placed = place_inbound(
            &self.storage,
            Sender::OwnDevice { partner: &peer },
            &message_id,
            content,
            &payload,
            now_ms(),
        );
        match placed {
            // The screens learned of a message from `MessageQueued`.
            Ok(Some(event)) if !is_message => {
                let _ = self
                    .internal_tx
                    .send(crate::client::ClientEvent::Bridge(event));
            }
            Ok(None) if !is_message => {
                return tracing::info!(%message_id, "changes nothing here — not sent");
            }
            Ok(_) => {}
            Err(()) => return self.ui_error(format!("[NOT_KEPT] {message_id}")),
        }
        self.send_own_copies(&peer, &message_id, &payload).await;
        let framed =
            crate::knst::frame_whole(&payload, crate::knst::CONTENT_E2EE_SIGNAL, &message_id);
        let event = IncomingEvent::OutgoingMessage {
            contact_id: peer,
            message_id,
            plaintext: framed,
            content_type: 0,
        };
        for event in self.prepare_outgoing(event).await {
            self.process(event).await;
        }
    }

    /// Copies of what we sent to `partner` (`content`, its `MessageContent`) for our other devices.
    async fn send_own_copies(&mut self, partner: &str, message_id: &str, content: &[u8]) {
        let siblings = self.own_siblings().await;
        if siblings.is_empty() {
            return;
        }
        let Some(plaintext) = crate::own_copy::copy(partner, message_id, content) else {
            return;
        };
        let certificate = match self.certificate().await {
            Ok(cert) => cert,
            Err(e) => return tracing::warn!(error = %e, "own-device copies not sent"),
        };
        let Ok(certificate) =
            crate::proto::core::v1::SenderCertificate::decode(certificate.as_slice())
        else {
            return tracing::warn!("own sender certificate does not parse");
        };
        for device in siblings {
            let Some(identity_key) = self.peers.identity_of(&device).map(<[u8]>::to_vec) else {
                continue;
            };
            let wire = match self.orchestrator.encrypt_bytes_for(&device, &plaintext) {
                Ok(wire) => wire,
                Err(e) => {
                    tracing::warn!(%device, error = %e, "own-device copy not written");
                    continue;
                }
            };
            self.persist_session(&device);
            let tag = match construct_core::crypto::device_copy_tag::device_copy_tag(
                message_id,
                &device,
                &self.identity.identity_secret,
                &identity_key,
            ) {
                Ok(tag) => tag,
                Err(e) => {
                    tracing::warn!(%device, error = %e, "own-device copy tag failed");
                    continue;
                }
            };
            let copy = crate::proto::core::v1::OwnDeviceCopy {
                sender_certificate: Some(certificate.clone()),
                wire_payload: wire.into(),
            };
            let envelope = own_copy_envelope(
                &self.identity.user_id,
                &device,
                crate::own_copy::copy_id(message_id, &tag),
                copy.encode_to_vec(),
            );
            let _ = self.sealed_tx.send(Outbound::OwnCopy {
                envelope: Box::new(envelope),
            });
        }
    }

    /// A copy of a message we sent from another device: open it, place it in its conversation.
    async fn handle_own_copy(&mut self, envelope: &Envelope) {
        let message_id = direct_envelope_message_id(envelope).to_owned();
        let me = self.identity.user_id.clone();
        if envelope.sender.as_ref().map(|u| u.user_id.as_str()) != Some(me.as_str()) {
            return tracing::warn!(%message_id, "copy from another account dropped");
        }
        let copy = match crate::proto::core::v1::OwnDeviceCopy::decode(
            envelope.encrypted_payload.as_ref(),
        ) {
            Ok(copy) => copy,
            Err(e) => return tracing::warn!(%message_id, error = %e, "copy does not parse"),
        };
        let Some(cert) = copy.sender_certificate else {
            return tracing::warn!(%message_id, "copy carries no sender certificate");
        };
        let certificate = match crate::sealing::certificate_from_proto(&cert.encode_to_vec()) {
            Ok(certificate) => certificate,
            Err(e) => return tracing::warn!(%message_id, error = %e, "copy certificate unreadable"),
        };
        if certificate.user_id != me || certificate.device_id == self.identity.device_id {
            return tracing::warn!(%message_id, "copy certificate names another account");
        }
        let sibling = certificate.device_id.clone();
        // Addressed to another of our devices: its tag says so.
        let (base_id, tag) = crate::own_copy::split_copy_id(&message_id);
        if let Some(tag) = tag
            && !construct_core::crypto::device_copy_tag::device_copy_tag_matches(
                tag,
                base_id,
                &self.identity.device_id,
                &self.identity.identity_secret,
                &certificate.identity_key,
            )
        {
            return tracing::debug!(%message_id, "copy for another device of this account");
        }
        let plaintext = match self
            .orchestrator
            .decrypt_bytes_for(&sibling, &copy.wire_payload)
        {
            Ok(plaintext) => plaintext,
            Err(_) => match self
                .orchestrator
                .receiving_from_certificate(&certificate, &copy.wire_payload)
            {
                Ok((device, plaintext)) => {
                    self.peers
                        .record(&self.storage, &me, &device, &certificate.identity_key);
                    crate::prekeys::save_after_responder_init(
                        &mut self.orchestrator,
                        &self.storage,
                    );
                    plaintext
                }
                Err(e) => return tracing::warn!(%message_id, %sibling, "copy does not open: {e}"),
            },
        };
        self.persist_session(&sibling);
        match crate::own_copy::read(&plaintext) {
            crate::own_copy::Copy::Content {
                partner,
                content,
                payload,
            } => {
                let from = Sender::OwnDevice { partner: &partner };
                match place_inbound(&self.storage, from, base_id, content, &payload, now_ms()) {
                    Ok(event) => {
                        tracing::info!(%message_id, %partner, "copy from another device placed");
                        if let Some(event) = event {
                            let _ = self
                                .internal_tx
                                .send(crate::client::ClientEvent::Bridge(event));
                        }
                    }
                    Err(()) => tracing::warn!(%message_id, "copied message not kept"),
                }
                self.adopt_writer(&partner);
            }
            crate::own_copy::Copy::ReadMarkers => {
                tracing::debug!(%message_id, "read markers from another device — not applied yet");
            }
            crate::own_copy::Copy::Unsupported(why) => {
                tracing::warn!(%message_id, "copy not shown: {why}");
            }
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
                self.adopt_writer(&account);
                tracing::info!(
                    device = %contact_id,
                    %account,
                    message_id = %message_id,
                    plaintext_len = plaintext.len(),
                    "MessageDecrypted"
                );
                let inbound = match crate::knst::decode(&plaintext) {
                    crate::knst::Inbound::Chunk(chunk) => {
                        match self.storage.hold_chunk(&account, &chunk, &message_id) {
                            Ok(Some(whole)) => crate::knst::decode_assembled(chunk.id, &whole),
                            Ok(None) => {
                                self.cursor.commit(&self.storage, &message_id);
                                crate::knst::Inbound::Silent
                            }
                            Err(e) => {
                                tracing::warn!(%message_id, error = %e, "chunk not held");
                                crate::knst::Inbound::Silent
                            }
                        }
                    }
                    other => other,
                };
                if let Some(receipt) = self.delivery_receipt(&contact_id, &message_id) {
                    follow_ups.push(receipt);
                }
                if let crate::knst::Inbound::Content {
                    id,
                    content,
                    payload,
                } = inbound
                {
                    let id = id.unwrap_or_else(|| message_id.clone());
                    // Not kept: the cursor stays, so the server delivers it again.
                    let from = Sender::Peer(&account);
                    if let Ok(event) =
                        place_inbound(&self.storage, from, &id, content, &payload, now_ms())
                    {
                        self.cursor.commit(&self.storage, &message_id);
                        if let Some(event) = event {
                            let _ = self
                                .internal_tx
                                .send(crate::client::ClientEvent::Bridge(event));
                        }
                    }
                }
            }

            Action::CallSignalDecrypted { .. } => {
                // Calls not yet implemented in TUI.
            }

            Action::ControlFrameDecrypted {
                contact_id,
                content_type,
                body,
                ..
            } => {
                if content_type == crate::knst::CONTENT_DELIVERY_RECEIPT {
                    self.receipt_received(&body);
                } else if content_type == crate::knst::CONTENT_PROFILE {
                    let account = self.account_of(&contact_id);
                    self.profile_received(&account, &body);
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

/// The envelope of a copy to one of our devices. Identified on purpose — sender and recipient are
/// both us, which the relay knows from the authenticated channel — and it names no conversation.
fn own_copy_envelope(
    account: &str,
    device: &str,
    message_id: String,
    payload: Vec<u8>,
) -> Envelope {
    use crate::proto::core::v1::{DeviceId, UserId};
    let me = UserId {
        user_id: account.to_string(),
        domain: None,
        display_name: None,
    };
    Envelope {
        sender: Some(me.clone()),
        recipient: Some(me),
        recipient_device: Some(DeviceId {
            user: None,
            device_id: device.to_string(),
            ..Default::default()
        }),
        content_type: ContentType::SenderSync as i32,
        message_id_type: Some(MessageIdType::MessageId(message_id)),
        encrypted_payload: payload.into(),
        ..Default::default()
    }
}

fn direct_envelope_message_id(envelope: &Envelope) -> &str {
    match &envelope.message_id_type {
        Some(MessageIdType::MessageId(id)) => id,
        Some(MessageIdType::GroupMessageId(_)) | None => "",
    }
}

/// Apply what `account` sent under message id `id`: a message goes into the transcript, an edit
/// or a reaction changes the message it names. Returns what the screens are told, if anything;
/// `Err` when it could not be kept.
///
/// An edit counts only from the author of its target (iOS `MessageRouter`); a reaction is the
/// reactor's newest by its own clock, and may come before the message it is on. A delete is
/// read and not applied — no client sends one (decision in TODO 218, 2026-10-24).
fn place_inbound(
    storage: &LocalStore,
    from: Sender<'_>,
    id: &str,
    content: crate::content::Content,
    payload: &[u8],
    now_ms: i64,
) -> Result<Option<BridgeEvent>, ()> {
    use crate::content::Content;
    let (chat, author) = match from {
        Sender::Peer(account) => (account, account),
        Sender::OwnDevice { partner } => (partner, storage.own_account()),
    };
    let author = author.to_string();
    match content {
        Content::Message {
            text,
            quote,
            attachment,
        } => {
            let own = matches!(from, Sender::OwnDevice { .. });
            let message = crate::local_store::StoredMessage {
                id: id.to_string(),
                peer_id: chat.to_string(),
                text,
                direction: if own { "sent" } else { "received" }.into(),
                timestamp_ms: now_ms,
                quote,
                attachment,
                media: crate::content::media_files(payload)
                    .into_iter()
                    .map(|f| f.info)
                    .collect(),
                ..Default::default()
            };
            let stored = if attachment.is_some() && !payload.is_empty() {
                storage.store_content(&message, payload)
            } else {
                storage.store_message(&message)
            };
            if let Err(e) = stored {
                tracing::warn!(%id, error = %e, "message not kept");
                return Err(());
            }
            Ok(Some(if own {
                BridgeEvent::OwnMessage { message }
            } else {
                BridgeEvent::NewMessage { message }
            }))
        }
        Content::Edit { target, text } => match storage.edit(&target, &author, &text, now_ms) {
            Ok(true) => Ok(changed(storage, &target)),
            Ok(false) => {
                tracing::info!(%target, "edit of a message not held or not theirs — dropped");
                Ok(None)
            }
            Err(e) => {
                tracing::warn!(%target, error = %e, "edit not applied");
                Err(())
            }
        },
        Content::Reaction {
            target,
            emoji,
            timestamp_ms,
        } => {
            let clock = if timestamp_ms > 0 {
                timestamp_ms
            } else {
                now_ms
            };
            match storage.react(&target, &author, emoji.as_deref(), clock) {
                Ok(true) => Ok(changed(storage, &target)),
                Ok(false) => Ok(None),
                Err(e) => {
                    tracing::warn!(%target, error = %e, "reaction not applied");
                    Err(())
                }
            }
        }
        Content::Delete => {
            tracing::info!(%id, "delete from the peer — not applied");
            Ok(None)
        }
    }
}

/// Who sent what is being placed.
#[derive(Clone, Copy)]
enum Sender<'a> {
    /// The account on the other side of the chat.
    Peer(&'a str),
    /// Another device of ours, in the chat with `partner`.
    OwnDevice { partner: &'a str },
}

/// The message `id` as it now is, for the screens; nothing when it is not held (a reaction that
/// came first).
fn changed(storage: &LocalStore, id: &str) -> Option<BridgeEvent> {
    let message = storage.message(id).ok()??;
    Some(BridgeEvent::MessageChanged { message })
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

/// Tell the screens that `account` changed, as the store now holds them.
fn contact_updated(
    storage: &LocalStore,
    events: &mpsc::UnboundedSender<crate::client::ClientEvent>,
    account: &str,
) {
    if let Ok(Some(contact)) = storage.get_contact_by_id(account) {
        let _ = events.send(crate::client::ClientEvent::Bridge(
            BridgeEvent::ContactUpdated { contact },
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── What a payload does once decrypted ─────────────────────────────────────

    fn text_from(storage: &LocalStore, peer: &str, id: &str, text: &str) {
        let content = crate::content::Content::Message {
            text: text.into(),
            quote: None,
            attachment: None,
        };
        place_inbound(storage, Sender::Peer(peer), id, content, &[], 1).unwrap();
    }

    #[test]
    fn a_message_from_ios_is_kept_under_the_id_its_header_carries() {
        let storage = LocalStore::open_in_memory().unwrap();
        let id = "6ae5e1ff-cd35-484d-a9ca-f2dc3fdb78ac";
        let framed = crate::knst::encode_text("hi", id);
        let crate::knst::Inbound::Content {
            id: Some(header_id),
            content,
            payload,
        } = crate::knst::decode(&framed)
        else {
            panic!("a text frame is content");
        };
        place_inbound(
            &storage,
            Sender::Peer("bob"),
            &header_id,
            content,
            &payload,
            1,
        )
        .unwrap();
        assert!(storage.message(id).unwrap().is_some());
    }

    #[test]
    fn a_photo_arrives_with_its_file_and_keeps_the_key_to_fetch_it() {
        let storage = LocalStore::open_in_memory().unwrap();
        let file = crate::outgoing::Outgoing {
            kind: crate::content::Attachment::Photo,
            mime: "image/png".into(),
            filename: Some("p.png".into()),
            bytes: b"pixels".to_vec(),
            width: 3,
            height: 2,
        };
        let sealed = construct_core::media::seal_media(&file.bytes).unwrap();
        let uploaded = crate::grpc::Uploaded {
            media_id: "m-9".into(),
            download_url: String::new(),
        };
        let payload = crate::outgoing::content(&file, &uploaded, &sealed, "", None);
        let content = crate::content::parse(&payload).unwrap();
        let Some(BridgeEvent::NewMessage { message }) =
            place_inbound(&storage, Sender::Peer("bob"), "p1", content, &payload, 1).unwrap()
        else {
            panic!("a photo is a new message");
        };
        assert_eq!(message.media.len(), 1, "the screens are told of its file");
        assert_eq!((message.media[0].width, message.media[0].height), (3, 2));
        let held = storage.media_files("p1").unwrap();
        assert_eq!(held[0].media_id, "m-9");
        assert_eq!(held[0].key.as_slice(), sealed.key.as_slice());
    }

    #[test]
    fn only_the_author_edits_a_message() {
        let storage = LocalStore::open_in_memory().unwrap();
        text_from(&storage, "bob", "m1", "helo");
        let edit = |text: &str| crate::content::Content::Edit {
            target: "m1".into(),
            text: text.into(),
        };

        // Someone else's edit, and ours of bob's message, change nothing.
        assert!(
            place_inbound(&storage, Sender::Peer("carol"), "e1", edit("x"), &[], 2)
                .unwrap()
                .is_none()
        );
        let own = Sender::OwnDevice { partner: "bob" };
        assert!(
            place_inbound(&storage, own, "e2", edit("y"), &[], 2)
                .unwrap()
                .is_none()
        );
        assert_eq!(storage.message("m1").unwrap().unwrap().text, "helo");

        let Some(BridgeEvent::MessageChanged { message }) =
            place_inbound(&storage, Sender::Peer("bob"), "e3", edit("hello"), &[], 3).unwrap()
        else {
            panic!("the author's edit changes the message");
        };
        assert_eq!((message.text.as_str(), message.edited), ("hello", true));
    }

    #[test]
    fn a_reaction_is_the_newest_by_the_reactors_clock() {
        let storage = LocalStore::open_in_memory().unwrap();
        text_from(&storage, "bob", "m1", "hi");
        let react = |emoji: Option<&str>, timestamp_ms| crate::content::Content::Reaction {
            target: "m1".into(),
            emoji: emoji.map(Into::into),
            timestamp_ms,
        };
        let emojis = || -> Vec<String> {
            let m = storage.message("m1").unwrap().unwrap();
            m.reactions.into_iter().map(|r| r.emoji).collect()
        };

        place_inbound(
            &storage,
            Sender::Peer("bob"),
            "r1",
            react(Some("👍"), 10),
            &[],
            0,
        )
        .unwrap();
        // Older, and a tie, are ignored; a redelivery changes nothing.
        place_inbound(
            &storage,
            Sender::Peer("bob"),
            "r2",
            react(Some("😂"), 5),
            &[],
            0,
        )
        .unwrap();
        place_inbound(&storage, Sender::Peer("bob"), "r3", react(None, 10), &[], 0).unwrap();
        assert_eq!(emojis(), ["👍"]);

        // Our own, copied from another device, is ours — beside bob's.
        let own = Sender::OwnDevice { partner: "bob" };
        place_inbound(&storage, own, "r4", react(Some("❤️"), 11), &[], 0).unwrap();
        assert_eq!(emojis(), ["👍", "❤️"]);

        place_inbound(&storage, Sender::Peer("bob"), "r5", react(None, 12), &[], 0).unwrap();
        assert_eq!(emojis(), ["❤️"]);
    }

    #[test]
    fn a_split_message_is_placed_once_every_frame_is_in() {
        let storage = LocalStore::open_in_memory().unwrap();
        let id = "6ae5e1ff-cd35-484d-a9ca-f2dc3fdb78ac";
        let long = "x".repeat(9000);
        let payload = {
            use prost::Message;
            crate::proto::messaging::v1::MessageContent {
                content: Some(crate::proto::messaging::v1::message_content::Content::Text(
                    crate::proto::messaging::v1::TextMessage {
                        text: long.clone(),
                        ..Default::default()
                    },
                )),
                ..Default::default()
            }
            .encode_to_vec()
        };
        let frames = construct_core::knst::encode_chunks(
            &payload,
            crate::knst::CONTENT_E2EE_SIGNAL,
            &construct_core::knst::message_id_bytes(id).unwrap(),
        )
        .unwrap();
        assert!(
            frames.len() > 2,
            "the test needs a message in several frames"
        );

        // Out of order and with a redelivered frame, as the stream may hand them over.
        let mut order: Vec<usize> = (0..frames.len()).rev().collect();
        order.insert(1, frames.len() - 1);
        let mut whole = None;
        for (n, i) in order.iter().enumerate() {
            let crate::knst::Inbound::Chunk(chunk) = crate::knst::decode(&frames[*i]) else {
                panic!("frame {i} is a chunk");
            };
            let held = storage
                .hold_chunk("bob", &chunk, &format!("env-{n}"))
                .unwrap();
            assert_eq!(held.is_some(), n == order.len() - 1, "after frame {n}");
            whole = held;
        }
        let crate::knst::Inbound::Content { content, .. } =
            crate::knst::decode_assembled(id.into(), &whole.unwrap())
        else {
            panic!("the joined frames are content");
        };
        assert!(matches!(content, crate::content::Content::Message { text, .. } if text == long));
    }
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

    #[test]
    fn the_writer_of_a_message_becomes_a_contact_once() {
        let (internal_tx, mut internal_rx) = mpsc::unbounded_channel();
        let mut task = test_task();
        task.internal_tx = internal_tx;
        let writer = "ed3c4cb1-5ee7-4a6f-9862-62a5a8b8560f";

        task.adopt_writer(writer);
        task.adopt_writer(writer);
        task.adopt_writer(OWN_ACCOUNT); // ourselves
        task.adopt_writer("bob-device"); // not an account id

        assert!(matches!(
            internal_rx.try_recv(),
            Ok(crate::client::ClientEvent::ContactAdded { ref user_id, .. }) if user_id == writer
        ));
        assert!(
            internal_rx.try_recv().is_err(),
            "one ContactAdded, for the writer only"
        );
        assert_eq!(task.storage.get_contacts().unwrap().len(), 1);
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
            .store_message(&crate::local_store::StoredMessage {
                id: "local-1".into(),
                peer_id: "bob".into(),
                text: "hi".into(),
                direction: "sent".into(),
                timestamp_ms: 1,
                delivery_status: String::new(),
                ..Default::default()
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
    fn a_profile_names_the_person_who_shared_it() {
        let mut task = test_task();
        let bob = "550e8400-e29b-41d4-a716-446655440000";
        task.storage
            .upsert_contact(&crate::local_store::StoredContact {
                user_id: bob.into(),
                display_name: "bob_k".into(),
                ..Default::default()
            })
            .unwrap();
        let profile = crate::profile::ProfileShare {
            display_name: "Боб".into(),
            edited_at_ms: 7,
            avatar: crate::profile::Avatar::Removed,
        };
        task.profile_received(bob, &profile.encode());
        let held = task.storage.get_contact_by_id(bob).unwrap().unwrap();
        assert_eq!(held.display_name, "Боб");
        task.profile_received(bob, b"\xff not a profile");
        assert_eq!(
            task.storage
                .get_contact_by_id(bob)
                .unwrap()
                .unwrap()
                .display_name,
            "Боб"
        );
    }

    #[test]
    fn no_receipt_is_sent_once_they_are_turned_off() {
        let mut task = test_task();
        let key = vec![4u8; 32];
        let device = construct_core::device_id::derive_device_id(&key);
        task.peers.record(&task.storage, "bob", &device, &key);
        assert!(
            task.storage.sends_delivery_receipts(),
            "on until turned off"
        );
        task.storage.set_sends_delivery_receipts(false).unwrap();
        assert!(task.delivery_receipt(&device, "server-9").is_none());
        task.storage.set_sends_delivery_receipts(true).unwrap();
        assert!(task.delivery_receipt(&device, "server-9").is_some());
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

    const OWN_ACCOUNT: &str = "753f79af-ede4-432c-9fcd-41deb5a35f0e";

    fn test_task() -> Task {
        let client = ClassicClient::<ClassicSuiteProvider>::new()
            .expect("test ClassicClient should initialize");
        let orchestrator = Orchestrator::new(client, "device-a".to_string());
        let storage = LocalStore::open_in_memory().expect("in-memory storage opens");
        let cursor = CursorTracker::load(&storage);
        let (internal_tx, _internal_rx) = mpsc::unbounded_channel();
        let (self_tx, _self_rx) = mpsc::unbounded_channel();
        let (sealed_tx, _sealed_rx) = mpsc::unbounded_channel();
        let (self_cmd, _self_cmd_rx) = mpsc::unbounded_channel();
        Task::new(
            orchestrator,
            storage,
            internal_tx,
            GrpcClient::new("https://127.0.0.1:1"),
            sealed_tx,
            cursor,
            Vec::new(),
            LocalIdentity {
                user_id: OWN_ACCOUNT.into(),
                device_id: "device-a".into(),
                identity_secret: vec![1u8; 32],
                signing_secret: vec![2u8; 32],
                replace_prekeys: false,
            },
            self_tx,
            self_cmd,
        )
    }
}
