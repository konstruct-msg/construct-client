//! Getting in and out: restore, unlock, register, link, the passphrase for a new account, the
//! outcome of an authentication, and logout.

use tokio::sync::mpsc;

use super::{Client, ClientEvent, Inbox};
use crate::{
    auth::RegistrationStep,
    bridge::BridgeEvent,
    config::{self, Session},
};

/// The outcome of an authentication attempt, sent from the task that ran it.
#[derive(Debug)]
pub(crate) enum AuthMsg {
    Success(Box<AuthSuccess>),
    Failure(String),
}

/// `try_restore_session` found nothing on disk.
const NO_SESSION: &str = "no_session";

#[derive(Debug)]
pub(crate) struct AuthSuccess {
    pub(super) user_id: String,
    pub(super) device_id: String,
    pub(super) access_token: String,
    /// Full session including private keys — used to construct the Orchestrator.
    pub(super) full_session: Session,
    /// When `Some`, this session must be persisted to disk (new/updated).
    pub(super) pending_save: Option<Session>,
}

impl Client {
    /// Restore a plaintext session from disk (legacy / `--no-encrypt` path).
    pub(super) fn restore_from_disk(&self) {
        let inbox = self.inbox.clone();
        let grpc = self.grpc.clone();
        tokio::spawn(async move {
            let msg = match crate::auth::try_restore_session(&grpc).await {
                Ok(Some(result)) => {
                    let full = result
                        .session
                        .clone()
                        .expect("try_restore_session always returns session");
                    AuthMsg::Success(Box::new(AuthSuccess {
                        user_id: result.user_id,
                        device_id: result.device_id,
                        access_token: result.access_token,
                        full_session: full,
                        pending_save: None, // already saved inside try_restore_session
                    }))
                }
                Ok(None) => AuthMsg::Failure(NO_SESSION.into()),
                Err(e) => AuthMsg::Failure(format!("{e:#}")),
            };
            let _ = inbox.send(Inbox::Auth(msg));
        });
    }

    /// Open the encrypted session with a passphrase and authenticate it.
    pub(super) fn unlock(&mut self, passphrase: &[u8]) {
        let session = match config::open_session_key(passphrase) {
            Ok(Some(sk)) => match config::load_session_encrypted(&sk) {
                Ok(Some(session)) => {
                    self.session_key = Some(sk);
                    session
                }
                Ok(None) => return self.emit(ClientEvent::UnlockFailed("No session found".into())),
                Err(e) => {
                    return self.emit(ClientEvent::UnlockFailed(format!("Session corrupted: {e}")));
                }
            },
            Ok(None) => return self.emit(ClientEvent::UnlockFailed("No session found".into())),
            Err(_) => {
                return self.emit(ClientEvent::UnlockFailed(
                    "Wrong passphrase or corrupted session".into(),
                ));
            }
        };
        self.emit(ClientEvent::Account(self.account_info()));
        self.authenticate_saved(session);
    }

    /// Authenticate a session already decrypted in memory.
    fn authenticate_saved(&self, session: Session) {
        let inbox = self.inbox.clone();
        let grpc = self.grpc.clone();
        tokio::spawn(async move {
            let msg = match crate::auth::authenticate_saved_session(session, &grpc).await {
                Ok(result) => {
                    let full = result
                        .session
                        .clone()
                        .expect("authenticate_saved_session always returns session");
                    AuthMsg::Success(Box::new(AuthSuccess {
                        user_id: result.user_id,
                        device_id: result.device_id,
                        access_token: result.access_token,
                        full_session: full,
                        pending_save: result.session,
                    }))
                }
                Err(e) => AuthMsg::Failure(format!("{e:#}")),
            };
            let _ = inbox.send(Inbox::Auth(msg));
        });
    }

    /// Register a new account and device; steps arrive as [`ClientEvent::RegistrationStep`].
    pub(super) fn register(&self, username: String) {
        let inbox = self.inbox.clone();
        let events = self.events.clone();
        let grpc = self.grpc.clone();
        let name = (!username.is_empty()).then_some(username);

        let (step_tx, mut step_rx) = mpsc::unbounded_channel::<RegistrationStep>();
        tokio::spawn(async move {
            while let Some(s) = step_rx.recv().await {
                let _ = events.send(ClientEvent::RegistrationStep(s));
            }
        });

        tokio::spawn(async move {
            let msg = match crate::auth::register_new_device(&grpc, name.as_deref(), &step_tx).await
            {
                Ok(result) => {
                    let full = result
                        .session
                        .clone()
                        .expect("register_new_device always returns session");
                    AuthMsg::Success(Box::new(AuthSuccess {
                        user_id: result.user_id,
                        device_id: result.device_id,
                        access_token: result.access_token,
                        full_session: full,
                        pending_save: result.session,
                    }))
                }
                Err(e) => AuthMsg::Failure(format!("{e:#}")),
            };
            let _ = inbox.send(Inbox::Auth(msg));
        });
    }

    /// Link this device to an existing account with a token from another device.
    pub(super) fn link_device(&self, token: String) {
        let inbox = self.inbox.clone();
        let grpc = self.grpc.clone();
        tokio::spawn(async move {
            let msg = match crate::auth::link_existing_device(&grpc, &token).await {
                Ok(result) => {
                    let full = result
                        .session
                        .clone()
                        .expect("link_existing_device always returns session");
                    AuthMsg::Success(Box::new(AuthSuccess {
                        user_id: result.user_id,
                        device_id: result.device_id,
                        access_token: result.access_token,
                        full_session: full,
                        pending_save: result.session,
                    }))
                }
                Err(e) => AuthMsg::Failure(format!("{e:#}")),
            };
            let _ = inbox.send(Inbox::Auth(msg));
        });
    }

    pub(super) fn apply_auth(&mut self, msg: AuthMsg) {
        match msg {
            AuthMsg::Success(success) => self.apply_auth_success(*success),
            AuthMsg::Failure(reason) => {
                let no_session = reason == NO_SESSION;
                self.emit(ClientEvent::AuthFailed { reason, no_session });
            }
        }
    }

    /// Take in a successful authentication: tokens, persistence, and — once the session can be
    /// saved — the orchestrator and the stream.
    fn apply_auth_success(&mut self, success: AuthSuccess) {
        let AuthSuccess {
            user_id,
            device_id,
            access_token,
            full_session,
            pending_save,
        } = success;
        self.user_id = user_id;
        self.device_id = device_id.clone();
        self.access_token = access_token.clone();
        self.grpc.set_token(Some(access_token));
        self.grpc.set_device_id(Some(device_id));
        self.current_session = Some(full_session.clone());
        self.emit(ClientEvent::Account(self.account_info()));

        let Some(session) = pending_save else {
            // Already saved (restore-from-disk path) — start right away.
            return self.start(full_session);
        };
        self.start_token_refresh(&session);

        if let Some(ref sk) = self.session_key {
            // Keys already derived (unlock path, or link/register with existing keys).
            match config::save_session_encrypted(&session, sk) {
                Ok(()) => self.start(full_session),
                Err(e) => self.emit(ClientEvent::SaveFailed(format!("Save failed: {e}"))),
            }
        } else if self.no_encrypt {
            match config::save_session(&session) {
                Ok(()) => self.start(full_session),
                Err(e) => self.emit(ClientEvent::SaveFailed(format!("Save failed: {e}"))),
            }
        } else {
            // New registration — wait for a passphrase before opening the encrypted database.
            self.pending_session = Some(session);
            self.emit(ClientEvent::NeedsPassphrase);
        }
    }

    /// Start the engine and report it started. If only the local engine failed, the account is
    /// still in: report the error and carry on with no contacts.
    fn start(&mut self, session: Session) {
        let contacts = self.start_orchestrator(session).unwrap_or_else(|e| {
            self.emit(ClientEvent::Bridge(BridgeEvent::Error(e)));
            Vec::new()
        });
        self.emit(ClientEvent::Started(contacts));
    }

    /// Protect a newly created session with a passphrase, save it, and start. Without a new
    /// session waiting for one, nothing happens.
    pub(super) fn set_passphrase(&mut self, passphrase: &[u8]) {
        let Some(session) = self.pending_session.take() else {
            return;
        };
        let sk = match config::create_session_key(passphrase) {
            Ok(sk) => sk,
            Err(e) => {
                self.pending_session = Some(session);
                return self.emit(ClientEvent::PassphraseFailed(format!(
                    "Key derivation failed: {e}"
                )));
            }
        };
        if let Err(e) = config::save_session_encrypted(&session, &sk) {
            self.pending_session = Some(session);
            return self.emit(ClientEvent::PassphraseFailed(format!("Save failed: {e}")));
        }
        self.session_key = Some(sk);
        self.emit(ClientEvent::Account(self.account_info()));
        // The orchestrator waited for this: the database key comes from the passphrase.
        match self.current_session.clone() {
            Some(full) => self.start(full),
            None => self.emit(ClientEvent::Started(Vec::new())),
        }
    }

    /// Clear the session from disk and stop everything running for it.
    pub(super) fn logout(&mut self) {
        if let Err(e) = config::clear_session() {
            return self.emit(ClientEvent::Notice(format!("Logout error: {e}")));
        }
        // Dropping the handle stops the orchestrator task; the stream worker is told.
        self.orch_handle = None;
        if let Some(ref tx) = self.stream_tx.take() {
            let _ = tx.try_send(crate::streaming::StreamCmd::Shutdown);
        }
        if let Some(ref storage) = self.read_storage {
            let _ = storage.clear_stream_cursor();
        }
        self.grpc.set_token(None);
        self.grpc.set_device_id(None);
        let grpc = self.grpc.clone();
        tokio::spawn(async move {
            grpc.invalidate_h3().await;
        });
        self.read_storage = None;
        self.session_key = None;
        self.current_session = None;
        self.pending_session = None;
        self.our_identity_key = None;
        self.user_id.clear();
        self.device_id.clear();
        self.access_token.clear();
        self.contact_ids.clear();
        self.emit(ClientEvent::Account(self.account_info()));
        self.emit(ClientEvent::LoggedOut);
    }
}
