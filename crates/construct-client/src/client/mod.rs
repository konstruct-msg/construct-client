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
    config::{Session, SessionKey, SessionState, TransportConfig},
    grpc::GrpcClient,
    storage::{StoredContact, StoredMessage},
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
    /// Link this device to an account with a token from another device.
    LinkDevice {
        token: String,
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
    LoggedOut,
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
    crate::config::detect_session()
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
    /// Derived key material for the active session (zeroized on drop / logout). `None` in
    /// `--no-encrypt` mode or before a passphrase is entered.
    session_key: Option<SessionKey>,
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
    /// Read connection for queries (messages, contacts); the orchestrator holds the writer.
    read_storage: Option<crate::storage::Storage>,
    /// The people the stream is subscribed for, in the order they were added.
    contact_ids: Vec<String>,
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
            session_key: None,
            current_session: None,
            pending_session: None,
            user_id: String::new(),
            device_id: String::new(),
            access_token: String::new(),
            our_identity_key: None,
            orch_handle: None,
            stream_tx: None,
            read_storage: None,
            contact_ids: Vec::new(),
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
            }
        }
    }

    fn handle(&mut self, command: ClientCommand) {
        match command {
            ClientCommand::RestoreFromDisk => self.restore_from_disk(),
            ClientCommand::Unlock(passphrase) => self.unlock(&passphrase),
            ClientCommand::Register { username } => self.register(username),
            ClientCommand::LinkDevice { token } => self.link_device(token),
            ClientCommand::SetPassphrase(passphrase) => self.set_passphrase(&passphrase),
            ClientCommand::SendText { contact_id, text } => self.send_text(contact_id, text),
            ClientCommand::LoadHistory { peer_id, limit } => self.load_history(peer_id, limit),
            ClientCommand::FindContact { query } => self.find_contact(&query),
            ClientCommand::AddContact { user_id, username } => self.add_contact(user_id, username),
            ClientCommand::DeleteContact { peer_id } => self.delete_contact(peer_id),
            ClientCommand::SafetyNumber { contact_id } => self.safety_number(contact_id),
            ClientCommand::ExportIdentityKey => self.export_identity_key(),
            ClientCommand::MintInvite => self.mint_invite(),
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
            has_session_key: self.session_key.is_some(),
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
