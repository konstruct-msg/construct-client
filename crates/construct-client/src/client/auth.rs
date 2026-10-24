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
    /// A linked device's key record, made before the phone approved it (its hybrid key is the
    /// one the QR committed to): written into the new store before the engine starts.
    pub(super) key_record: Option<Vec<u8>>,
    /// Where a linked device starts reading the stream.
    pub(super) link_cursor: Option<String>,
}

/// Where the session (keys and tokens) lives in the store.
const SESSION_KEY: &str = "account.session";

impl Client {
    /// Lock the data directory, once per process. Another shell holding it is a failure.
    fn data_dir(&mut self) -> Result<&crate::local_data::DataDir, String> {
        if self.data.is_none() {
            self.data =
                Some(crate::local_data::DataDir::open_default().map_err(|e| format!("{e:#}"))?);
        }
        Ok(self.data.as_ref().expect("set above"))
    }

    fn fail(&self, reason: String) {
        self.emit(ClientEvent::AuthFailed {
            reason,
            no_session: false,
        });
    }

    /// Take `store` as this account's and read its session.
    fn adopt_store(&mut self, store: construct_store::Store) -> Result<Session, String> {
        let store = crate::local_store::LocalStore::new(store, "");
        let session = store
            .secure_load(SESSION_KEY)
            .map_err(|e| format!("{e:#}"))?
            .ok_or("the store holds no session")?;
        let session: Session =
            serde_json::from_slice(&session).map_err(|e| format!("session unreadable: {e}"))?;
        self.store = Some(store.for_account(&session.user_id));
        Ok(session)
    }

    /// Start with what is on disk without asking for anything: a store whose key the OS key
    /// store or a key file keeps, or a plaintext session from before the store.
    pub(super) fn restore_from_disk(&mut self) {
        use crate::local_data::KeyKeeping;
        let data = match self.data_dir() {
            Ok(data) => data,
            Err(e) => return self.fail(e),
        };
        match data.existing() {
            Some(KeyKeeping::KeyStore | KeyKeeping::KeyFile) => {
                let session = data
                    .open_store()
                    .map_err(|e| format!("{e:#}"))
                    .and_then(|store| self.adopt_store(store));
                match session {
                    Ok(session) => self.authenticate_saved(session),
                    Err(e) => self.fail(e),
                }
            }
            Some(KeyKeeping::Passphrase) => self.fail("this store needs its passphrase".into()),
            None => match config::load_session() {
                Ok(Some(session)) => {
                    let key_file = self.no_encrypt;
                    match self.migrate_legacy(session, key_file, None) {
                        Ok(session) => self.authenticate_saved(session),
                        Err(e) => self.fail(e),
                    }
                }
                Ok(None) => self.emit(ClientEvent::AuthFailed {
                    reason: NO_SESSION.into(),
                    no_session: true,
                }),
                Err(e) => self.fail(format!("{e:#}")),
            },
        }
    }

    /// Open the store with its passphrase — or, from before the store, the encrypted session
    /// file — and authenticate.
    pub(super) fn unlock(&mut self, passphrase: &[u8]) {
        use crate::local_data::KeyKeeping;
        let data = match self.data_dir() {
            Ok(data) => data,
            Err(e) => return self.emit(ClientEvent::UnlockFailed(e)),
        };
        let session = match data.existing() {
            Some(KeyKeeping::Passphrase) => data
                .open_store_with_passphrase(passphrase)
                .map_err(|e| format!("{e:#}"))
                .and_then(|store| self.adopt_store(store)),
            None => match config::open_session_key(passphrase)
                .and_then(|sk| sk.map(|sk| config::load_session_encrypted(&sk)).transpose())
            {
                Ok(Some(Some(session))) => self.migrate_legacy(session, false, Some(passphrase)),
                Ok(_) => Err("No session found".into()),
                Err(_) => Err("Wrong passphrase or corrupted session".into()),
            },
            Some(_) => Err("this store opens without a passphrase".into()),
        };
        match session {
            Ok(session) => {
                self.unlocked_by_passphrase = true;
                self.emit(ClientEvent::Account(self.account_info()));
                self.authenticate_saved(session);
            }
            Err(e) => self.emit(ClientEvent::UnlockFailed(e)),
        }
    }

    /// A session from before the store: make the store (the OS key store keeps its key, else the
    /// passphrase the session was under, else a key file), move the session in, delete the old
    /// files. The old database is not carried over: its sessions reopen from the peers' next
    /// messages, its history is gone (pre-release; TODO 218 stage 2).
    fn migrate_legacy(
        &mut self,
        session: Session,
        key_file: bool,
        passphrase: Option<&[u8]>,
    ) -> Result<Session, String> {
        let data = self.data_dir()?;
        let store = match data.create_store(key_file).map_err(|e| format!("{e:#}"))? {
            Some(store) => store,
            None => match passphrase {
                Some(p) => data
                    .create_store_with_passphrase(p)
                    .map_err(|e| format!("{e:#}"))?,
                None => data
                    .create_store(true)
                    .map_err(|e| format!("{e:#}"))?
                    .ok_or("no way to keep the store key")?,
            },
        };
        data.remove_legacy_database();
        self.store = Some(crate::local_store::LocalStore::new(store, &session.user_id));
        self.save_session(&session)?;
        if let Err(e) = config::clear_session() {
            tracing::warn!(error = %e, "old session file not removed");
        }
        tracing::info!("session moved into the local store");
        Ok(session)
    }

    /// Write the session into the store.
    pub(super) fn save_session(&self, session: &Session) -> Result<(), String> {
        let store = self.store.as_ref().ok_or("no store open")?;
        let bytes = serde_json::to_vec(session).map_err(|e| e.to_string())?;
        store
            .secure_save(SESSION_KEY, &bytes)
            .map_err(|e| format!("{e:#}"))
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
                        key_record: None,
                        link_cursor: None,
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
                        key_record: None,
                        link_cursor: None,
                    }))
                }
                Err(e) => AuthMsg::Failure(format!("{e:#}")),
            };
            let _ = inbox.send(Inbox::Auth(msg));
        });
    }

    /// Link this device to an existing account with a code another device of it showed: the
    /// `konstruct://link?…` code, or its bare token.
    pub(super) fn link_device(&self, code: String) {
        let inbox = self.inbox.clone();
        let grpc = self.grpc.clone();
        tokio::spawn(async move {
            let Some(code) = crate::device_certs::parse_link_code(&code) else {
                let reason = "That is not a link code".to_string();
                return drop(inbox.send(Inbox::Auth(AuthMsg::Failure(reason))));
            };
            if code.secret.is_none() {
                tracing::info!("link code carries no secret: this device will be unvouched");
            }
            let msg = match crate::auth::link_existing_device(&grpc, &code).await {
                Ok(linked) => {
                    let result = linked.result;
                    let full = result
                        .session
                        .clone()
                        .expect("link_existing_device always returns session");
                    let link_cursor = crate::auth::link_cursor(&result.access_token);
                    AuthMsg::Success(Box::new(AuthSuccess {
                        user_id: result.user_id,
                        device_id: result.device_id,
                        access_token: result.access_token,
                        full_session: full,
                        pending_save: result.session,
                        key_record: Some(linked.key_record),
                        link_cursor,
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
            key_record,
            link_cursor,
        } = success;
        self.pending_link = key_record.map(|record| (record, link_cursor));
        self.user_id = user_id;
        self.device_id = device_id.clone();
        self.access_token = access_token.clone();
        self.grpc.set_token(Some(access_token));
        self.grpc.set_device_id(Some(device_id));
        self.current_session = Some(full_session.clone());
        self.emit(ClientEvent::Account(self.account_info()));

        let Some(session) = pending_save else {
            return self.start(full_session);
        };
        self.start_token_refresh(&session);

        if self.store.is_none() {
            // A new account: make its store. Without an OS key store, wait for a passphrase.
            let key_file = self.no_encrypt;
            let created = self
                .data_dir()
                .and_then(|data| data.create_store(key_file).map_err(|e| format!("{e:#}")));
            match created {
                Ok(Some(store)) => {
                    self.store = Some(crate::local_store::LocalStore::new(store, &session.user_id))
                }
                Ok(None) => {
                    self.pending_session = Some(session);
                    return self.emit(ClientEvent::NeedsPassphrase);
                }
                Err(e) => return self.emit(ClientEvent::SaveFailed(format!("Save failed: {e}"))),
            }
        }
        match self
            .save_session(&session)
            .and_then(|()| self.write_pending_link())
        {
            Ok(()) => self.start(full_session),
            Err(e) => self.emit(ClientEvent::SaveFailed(format!("Save failed: {e}"))),
        }
    }

    /// A linked device's key record and starting cursor, into the store it just got.
    fn write_pending_link(&mut self) -> Result<(), String> {
        let Some((record, cursor)) = self.pending_link.take() else {
            return Ok(());
        };
        let store = self.store.as_ref().ok_or("no store open")?;
        store
            .secure_save(crate::prekeys::KEY_RECORD, &record)
            .map_err(|e| format!("{e:#}"))?;
        if let Some(cursor) = cursor {
            store
                .save_stream_cursor(&cursor)
                .map_err(|e| format!("{e:#}"))?;
        }
        Ok(())
    }

    /// Become a new device of an existing account (Flow B): make the keys, hand them to the
    /// server, show the phone a code, and wait for its approval. Success arrives as an ordinary
    /// [`AuthMsg::Success`], carrying the key record made here.
    pub(super) fn link_by_qr(&mut self) {
        self.cancel_link();
        let inbox = self.inbox.clone();
        let events = self.events.clone();
        let grpc = self.grpc.clone();
        let task = tokio::spawn(async move {
            let prep = match tokio::task::spawn_blocking(crate::auth::prepare_join).await {
                Ok(Ok(prep)) => prep,
                Ok(Err(e)) => return drop(events.send(ClientEvent::LinkFailed(format!("{e:#}")))),
                Err(e) => return drop(events.send(ClientEvent::LinkFailed(e.to_string()))),
            };
            if let Err(e) = crate::grpc::submit_join_request(&grpc, &prep.request).await {
                return drop(events.send(ClientEvent::LinkFailed(format!(
                    "The server did not take the request: {e}"
                ))));
            }
            let _ = events.send(ClientEvent::LinkCode(prep.qr.clone()));
            let device_id = prep.request.device_id.clone();
            let tokens = match crate::auth::wait_for_approval(&grpc, &device_id).await {
                Ok(tokens) => tokens,
                Err(e) => return drop(events.send(ClientEvent::LinkFailed(format!("{e:#}")))),
            };
            let mut session = prep.session_secrets;
            session.user_id = tokens.user_id.clone();
            session.access_token = tokens.access_token.clone();
            session.refresh_token = tokens.refresh_token;
            session.expires_at = tokens.expires_at;
            let link_cursor = crate::auth::link_cursor(&tokens.access_token);
            let _ = inbox.send(Inbox::Auth(AuthMsg::Success(Box::new(AuthSuccess {
                user_id: tokens.user_id,
                device_id,
                access_token: tokens.access_token,
                full_session: session.clone(),
                pending_save: Some(session),
                key_record: Some(prep.key_record),
                link_cursor,
            }))));
        });
        self.link_task = Some(task.abort_handle());
    }

    /// Let a device that asked to join become one of this account's devices, then vouch for it
    /// when its code carried the fingerprint of its keys.
    pub(super) fn approve_join(&self, device_id: String, fingerprint: Option<Vec<u8>>) {
        let events = self.events.clone();
        let grpc = self.grpc.clone();
        let orchestrator = self.orch_handle.clone();
        tokio::spawn(async move {
            let short = &device_id[..8.min(device_id.len())];
            let notice = match crate::grpc::approve_join_request(&grpc, &device_id).await {
                Ok(()) => {
                    match (fingerprint, orchestrator) {
                        (Some(fp), Some(orchestrator)) => orchestrator.vouch(
                            device_id.clone(),
                            crate::device_certs::Evidence::QrFingerprint(fp),
                        ),
                        _ => {
                            tracing::info!(device = %short, "linked without a fingerprint: not vouched")
                        }
                    }
                    format!("Device {short} linked to this account")
                }
                Err(e) => format!("Linking device {short} failed: {e}"),
            };
            let _ = events.send(ClientEvent::Notice(notice));
        });
    }

    pub(super) fn cancel_link(&mut self) {
        if let Some(task) = self.link_task.take() {
            task.abort();
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
        let created = self.data_dir().and_then(|data| {
            data.create_store_with_passphrase(passphrase)
                .map_err(|e| format!("{e:#}"))
        });
        match created {
            Ok(store) => {
                self.store = Some(crate::local_store::LocalStore::new(store, &session.user_id))
            }
            Err(e) => {
                self.pending_session = Some(session);
                return self.emit(ClientEvent::PassphraseFailed(format!(
                    "Store not made: {e}"
                )));
            }
        }
        if let Err(e) = self
            .save_session(&session)
            .and_then(|()| self.write_pending_link())
        {
            return self.emit(ClientEvent::PassphraseFailed(format!("Save failed: {e}")));
        }
        self.unlocked_by_passphrase = true;
        self.emit(ClientEvent::Account(self.account_info()));
        match self.current_session.clone() {
            Some(full) => self.start(full),
            None => self.emit(ClientEvent::Started(Vec::new())),
        }
    }

    /// Clear the session from disk and stop everything running for it.
    pub(super) fn logout(&mut self) {
        // Dropping the handle stops the orchestrator task; the stream worker is told.
        self.orch_handle = None;
        if let Some(ref tx) = self.stream_tx.take() {
            let _ = tx.try_send(crate::streaming::StreamCmd::Shutdown);
        }
        // Signing out wipes the device (decisions/sign-out-wipes-the-device.md): the store's
        // files and its key. The task's handle may still be closing; the files go regardless.
        let store = self.store.take();
        let wiped = self
            .data_dir()
            .and_then(|data| data.wipe(store).map_err(|e| format!("{e:#}")));
        if let Err(e) = wiped {
            self.emit(ClientEvent::Notice(format!("Logout error: {e}")));
        }
        if let Err(e) = config::clear_session() {
            tracing::warn!(error = %e, "old session file not removed");
        }
        self.grpc.set_token(None);
        self.grpc.set_device_id(None);
        let grpc = self.grpc.clone();
        tokio::spawn(async move {
            grpc.invalidate_h3().await;
        });
        self.unlocked_by_passphrase = false;
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
