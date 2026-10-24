//! The client layer: account, session keys, the orchestrator, the message stream, storage and
//! contacts — everything this program is, apart from how it is shown.
//!
//! The client runs as its own task. A front end holds a [`ClientHandle`], sends it
//! [`ClientCommand`]s and reads [`ClientEvent`]s — it never calls into the client or waits on it,
//! so key derivation and opening the database do not freeze the screen, and a second front end
//! (`decisions/desktop-is-the-tui-client-with-a-second-shell.md`) talks to it the same way.

mod auth;
mod contacts;
mod identity;
mod inbound;
mod messages;
mod orchestrator;
mod tokens;

pub(crate) use auth::AuthMsg;
pub use contacts::{FindStarted, SearchResult};

use tokio::sync::mpsc;
use zeroize::Zeroizing;

use crate::{
    auth::RegistrationStep,
    bridge::{BridgeEvent, TokenRefreshMsg},
    config::{Session, SessionState, TransportConfig},
    grpc::GrpcClient,
    local_store::{StoredContact, StoredMessage},
};

/// What a front end asks the client to do.
pub enum ClientCommand {
    /// Restore the plaintext session on disk (legacy / `--no-encrypt`).
    RestoreFromDisk,
    /// Open the encrypted session with this passphrase and sign in.
    Unlock(Zeroizing<Vec<u8>>),
    /// Register a new account and device.
    Register {
        username: String,
    },
    /// Link this device to an account with the code another device of it shows
    /// (`konstruct://link?…`, or its bare token).
    LinkDevice {
        token: String,
    },
    /// Become a new device of an existing account: show a code for the phone to scan
    /// ([`ClientEvent::LinkCode`]) and wait for its approval.
    LinkByQr,
    /// Stop waiting for the phone.
    CancelLink,
    /// Let a device that asked to join this account (its `link-to-me` code names it) become one
    /// of its devices — what the phone does when it scans the code.
    ApproveJoin {
        device_id: String,
        /// The `fp` of its code: the keys this device vouches for once the directory serves
        /// them. Without it the device is approved and left unvouched.
        fingerprint: Option<Vec<u8>>,
    },
    /// Protect the new session with this passphrase and start.
    SetPassphrase(Zeroizing<Vec<u8>>),
    SendText {
        contact_id: String,
        text: String,
    },
    LoadHistory {
        peer_id: String,
        limit: usize,
    },
    /// A username, or an invite link to redeem.
    FindContact {
        query: String,
    },
    AddContact {
        user_id: String,
        username: String,
    },
    DeleteContact {
        peer_id: String,
    },
    SafetyNumber {
        contact_id: String,
    },
    ExportIdentityKey,
    /// Mint an invite for our QR code.
    MintInvite,
    /// Show the recovery phrase that waits for its copy ([`ClientEvent::RecoveryPhrase`]).
    RevealRecoveryPhrase,
    /// The copy is made: words of the phrase by position (from 0), as the person gives them
    /// back. Right — the phrase is erased from this device.
    ConfirmRecoveryCopy {
        answers: Vec<(usize, String)>,
    },
    /// The recovery phrase, typed on a device that did not make it, so it learns the address.
    EnterRecoveryPhrase(Zeroizing<String>),
    Logout,
}

/// What the client tells a front end.
pub enum ClientEvent {
    /// Who we are, as far as a front end shows it. Sent whenever it changes.
    Account(AccountInfo),
    /// Signed in and running; these are the stored contacts.
    Started(Vec<StoredContact>),
    /// A new account is signed in and waits for [`ClientCommand::SetPassphrase`].
    NeedsPassphrase,
    /// Signing in failed. `no_session`: there was nothing on disk to restore.
    AuthFailed {
        reason: String,
        no_session: bool,
    },
    /// Signed in, but the session could not be saved.
    SaveFailed(String),
    UnlockFailed(String),
    PassphraseFailed(String),
    RegistrationStep(RegistrationStep),
    /// Stream status, new messages, session readiness, errors from the engine.
    Bridge(BridgeEvent),
    SearchStarted(FindStarted),
    ContactSearchResult(Vec<SearchResult>),
    /// A search or an invite redemption failed.
    ContactSearchError(String),
    ContactAdded {
        user_id: String,
        username: String,
    },
    ContactRemoved {
        peer_id: String,
    },
    /// A message was handed to the engine to send.
    MessageQueued {
        contact_id: String,
        message_id: String,
        text: String,
    },
    History {
        peer_id: String,
        messages: Vec<StoredMessage>,
    },
    /// The safety number with a contact, computed by the core.
    SafetyNumber {
        contact_id: String,
        number: String,
    },
    InviteMinted(Result<String, String>),
    /// What the phone scans to approve this device (`konstruct://link-to-me?…`).
    LinkCode(String),
    /// Linking stopped: refused, expired, or the server could not be reached.
    LinkFailed(String),
    LoggedOut,
    /// Where the account's recovery key stands, for this device. Sent after each start and
    /// whenever it changes.
    Recovery(crate::recovery::RecoveryState),
    /// The phrase waiting for its copy, or why it cannot be shown.
    RecoveryPhrase(Result<Zeroizing<String>, String>),
    /// A recovery command failed: the copy check, or a typed phrase.
    RecoveryFailed(String),
    /// A one-line message for the user.
    Notice(String),
}

/// The account as a front end shows it. No key material.
#[derive(Debug, Clone, Default)]
pub struct AccountInfo {
    pub server_url: String,
    pub transport_label: &'static str,
    pub pq_active: bool,
    pub user_id: String,
    pub device_id: String,
    /// A passphrase has unlocked or created the session key.
    pub has_session_key: bool,
}

/// The client's inbox: commands from the front end, and results from its own background work.
enum Inbox {
    Command(ClientCommand),
    Auth(AuthMsg),
    TokenRefresh(TokenRefreshMsg),
    /// MessageStream got gRPC 16 — refresh the bearer, do not wipe keys.
    StreamAuthRequired,
    /// An invite was redeemed; the person is added like any other.
    InviteAccepted {
        user_id: String,
        username: String,
    },
    /// The recovery key's state after background work.
    Recovery(crate::recovery::RecoveryState),
}

/// The front end's end of the client: send commands, nothing else.
#[derive(Clone)]
pub struct ClientHandle {
    inbox: mpsc::UnboundedSender<Inbox>,
}

impl ClientHandle {
    pub fn send(&self, command: ClientCommand) {
        let _ = self.inbox.send(Inbox::Command(command));
    }
}

/// Start the client task. Its events arrive on `events`.
pub fn spawn(cfg: ClientConfig, events: mpsc::UnboundedSender<ClientEvent>) -> ClientHandle {
    let (inbox_tx, inbox_rx) = mpsc::unbounded_channel();
    let client = Client::new(cfg, events, inbox_tx.clone());
    tokio::spawn(client.run(inbox_rx));
    ClientHandle { inbox: inbox_tx }
}

/// What is on disk: an encrypted session, a plaintext one, or none. Read before the client is
/// asked for anything, to choose the first screen.
pub fn stored_session_state() -> SessionState {
    use crate::local_data::{KeyKeeping, default_dir, existing_in};
    match default_dir().and_then(|dir| existing_in(&dir)) {
        Some(KeyKeeping::Passphrase) => SessionState::Encrypted,
        Some(KeyKeeping::KeyStore | KeyKeeping::KeyFile) => SessionState::Plaintext,
        // Nothing in the store yet: a session file from before it, if any.
        None => crate::config::detect_session(),
    }
}

/// Configuration derived from the config file and CLI overrides.
pub struct ClientConfig {
    pub server_url: String,
    pub transport: TransportConfig,
    pub no_encrypt: bool,
    pub pq_active: bool,
}

pub(crate) struct Client {
    server_url: String,
    transport: TransportConfig,
    /// Skip at-rest encryption (headless / `--no-encrypt`).
    no_encrypt: bool,
    pq_active: bool,
    grpc: GrpcClient,
    events: mpsc::UnboundedSender<ClientEvent>,
    /// Where background work started here reports back.
    inbox: mpsc::UnboundedSender<Inbox>,
    /// The data directory, locked while this client runs.
    data: Option<crate::local_data::DataDir>,
    /// The account's store: its session, keys, sessions with peers, messages. Shared with the
    /// orchestrator task.
    store: Option<crate::local_store::LocalStore>,
    /// The store was opened (or made) with a passphrase.
    unlocked_by_passphrase: bool,
    /// The decrypted session in memory — re-saved on token refresh without a disk read.
    current_session: Option<Session>,
    /// A new session waiting for its passphrase before it is saved.
    pending_session: Option<Session>,
    user_id: String,
    device_id: String,
    access_token: String,
    /// Our identity public key, captured at orchestrator start; for safety numbers and export.
    our_identity_key: Option<Vec<u8>>,
    orch_handle: Option<crate::orchestrator_task::OrchestratorHandle>,
    stream_tx: Option<mpsc::Sender<crate::streaming::StreamCmd>>,
    /// The people the stream is subscribed for, in the order they were added.
    contact_ids: Vec<String>,
    /// A link waiting for the phone's approval.
    link_task: Option<tokio::task::AbortHandle>,
    /// An approved link's key record and starting cursor, until there is a store to write them to.
    pending_link: Option<(Vec<u8>, Option<String>)>,
}

impl Client {
    fn new(
        cfg: ClientConfig,
        events: mpsc::UnboundedSender<ClientEvent>,
        inbox: mpsc::UnboundedSender<Inbox>,
    ) -> Self {
        Self {
            grpc: GrpcClient::new(&cfg.server_url),
            server_url: cfg.server_url,
            transport: cfg.transport,
            no_encrypt: cfg.no_encrypt,
            pq_active: cfg.pq_active,
            events,
            inbox,
            data: None,
            store: None,
            unlocked_by_passphrase: false,
            current_session: None,
            pending_session: None,
            user_id: String::new(),
            device_id: String::new(),
            access_token: String::new(),
            our_identity_key: None,
            orch_handle: None,
            stream_tx: None,
            contact_ids: Vec::new(),
            link_task: None,
            pending_link: None,
        }
    }

    async fn run(mut self, mut inbox: mpsc::UnboundedReceiver<Inbox>) {
        self.emit(ClientEvent::Account(self.account_info()));
        while let Some(message) = inbox.recv().await {
            match message {
                Inbox::Command(command) => self.handle(command),
                Inbox::Auth(msg) => self.apply_auth(msg),
                Inbox::TokenRefresh(msg) => self.apply_token_refresh(msg),
                Inbox::StreamAuthRequired => self.refresh_token_now(),
                Inbox::InviteAccepted { user_id, username } => self.add_contact(user_id, username),
                Inbox::Recovery(state) => self.emit(ClientEvent::Recovery(state)),
            }
        }
    }

    fn handle(&mut self, command: ClientCommand) {
        match command {
            ClientCommand::RestoreFromDisk => self.restore_from_disk(),
            ClientCommand::Unlock(passphrase) => self.unlock(&passphrase),
            ClientCommand::Register { username } => self.register(username),
            ClientCommand::LinkDevice { token } => self.link_device(token),
            ClientCommand::LinkByQr => self.link_by_qr(),
            ClientCommand::CancelLink => self.cancel_link(),
            ClientCommand::ApproveJoin {
                device_id,
                fingerprint,
            } => self.approve_join(device_id, fingerprint),
            ClientCommand::SetPassphrase(passphrase) => self.set_passphrase(&passphrase),
            ClientCommand::SendText { contact_id, text } => self.send_text(contact_id, text),
            ClientCommand::LoadHistory { peer_id, limit } => self.load_history(peer_id, limit),
            ClientCommand::FindContact { query } => self.find_contact(&query),
            ClientCommand::AddContact { user_id, username } => self.add_contact(user_id, username),
            ClientCommand::DeleteContact { peer_id } => self.delete_contact(peer_id),
            ClientCommand::SafetyNumber { contact_id } => self.safety_number(contact_id),
            ClientCommand::ExportIdentityKey => self.export_identity_key(),
            ClientCommand::MintInvite => self.mint_invite(),
            ClientCommand::RevealRecoveryPhrase => self.reveal_recovery_phrase(),
            ClientCommand::ConfirmRecoveryCopy { answers } => self.confirm_recovery_copy(&answers),
            ClientCommand::EnterRecoveryPhrase(phrase) => self.enter_recovery_phrase(phrase),
            ClientCommand::Logout => self.logout(),
        }
    }

    fn emit(&self, event: ClientEvent) {
        let _ = self.events.send(event);
    }

    fn account_info(&self) -> AccountInfo {
        AccountInfo {
            server_url: self.server_url.clone(),
            transport_label: transport_label(&self.transport),
            pq_active: self.pq_active,
            user_id: self.user_id.clone(),
            device_id: self.device_id.clone(),
            has_session_key: self.unlocked_by_passphrase,
        }
    }
}

pub fn transport_label(t: &TransportConfig) -> &'static str {
    match t {
        TransportConfig::Direct => "direct",
        TransportConfig::Obfs4 { .. } => "obfs4",
        TransportConfig::Obfs4Tls { .. } => "obfs4+tls",
        TransportConfig::CdnFront { .. } => "cdn-front",
    }
}
