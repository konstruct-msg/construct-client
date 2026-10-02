//! Starting the engine for a signed-in account: keys into the core's Orchestrator, storage,
//! restored sessions, the message stream, the orchestrator task and the inbound relay.

use super::{Client, inbound};
use crate::{config::Session, storage::StoredContact};

impl Client {
    /// Construct the Orchestrator, open storage, spawn the stream worker and the orchestrator
    /// task, and wire them together. Returns the stored contacts.
    pub(super) fn start_orchestrator(
        &mut self,
        session: Session,
    ) -> Result<Vec<StoredContact>, String> {
        use crate::orchestrator_task::spawn_orchestrator_task;
        use crate::storage::Storage;
        use crate::streaming::{CursorTracker, spawn_stream_worker};
        use construct_core::{
            crypto::{client_api::ClassicClient, suites::classic::ClassicSuiteProvider},
            orchestration::orchestrator::Orchestrator,
        };

        let decode = |hex_str: &str| {
            hex::decode(hex_str).map_err(|e| format!("Orchestrator key decode error: {e}"))
        };
        let identity_secret = decode(&session.identity_key_hex)?;
        let signing_secret = decode(&session.signing_key_hex)?;
        let spk_secret = decode(&session.spk_key_hex)?;
        let spk_sig = decode(&session.spk_sig_hex)?;

        // The stream relay must unseal SealedInner.sender_cert_ciphertext before it can recover
        // the sender. Keep a private-key copy at that boundary; Double Ratchet decryption still
        // happens inside the orchestrator.
        let identity_secret_for_sealed = identity_secret.clone();

        let core_client = ClassicClient::<ClassicSuiteProvider>::from_keys(
            identity_secret,
            signing_secret,
            spk_secret,
            spk_sig,
        )
        .map_err(|e| format!("Orchestrator init error: {e}"))?;
        let mut orchestrator = Orchestrator::new(core_client, self.user_id.clone());

        // Two connections: the orchestrator writes, queries read.
        let (storage, read_storage) = if let Some(ref sk) = self.session_key {
            let db_key = sk.keys.database.as_ref();
            (Storage::open(db_key), Storage::open(db_key))
        } else {
            (Storage::open_unencrypted(), Storage::open_unencrypted())
        };
        let (storage, read_storage) = match (storage, read_storage) {
            (Ok(s1), Ok(s2)) => (s1, s2),
            (Err(e), _) | (_, Err(e)) => return Err(format!("Storage open error: {e}")),
        };

        let contacts = read_storage.get_contacts().unwrap_or_else(|e| {
            tracing::warn!("Failed to load contacts: {e}");
            Vec::new()
        });
        let contact_ids: Vec<String> = contacts.iter().map(|c| c.user_id.clone()).collect();

        // Restore core coordination state and per-contact DR material before the stream worker
        // can redeliver old envelopes. Without this the core starts with an empty session map
        // while secure_store still holds `session_<id>` / `archive_<id>` bytes.
        match read_storage.secure_load("construct.orchestrator_state") {
            Ok(Some(state)) if !state.is_empty() => {
                if let Err(e) = orchestrator.import_orchestrator_state_cfe(&state) {
                    tracing::warn!(error = %e, "failed to restore orchestrator coordination state");
                }
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "failed to load orchestrator coordination state"),
        }
        for contact_id in &contact_ids {
            match read_storage.secure_load(&format!("session_{contact_id}")) {
                Ok(Some(data)) => {
                    if let Err(error) = orchestrator.import_session_cfe(contact_id, &data) {
                        tracing::warn!(%contact_id, %error, "failed to restore session");
                    }
                }
                Ok(None) => {}
                Err(error) => tracing::warn!(%contact_id, %error, "failed to load session"),
            }
        }

        // OTPKs and our identity key before the orchestrator moves into its task.
        let otpks = orchestrator.generate_otpks(100).unwrap_or_default();
        self.our_identity_key = orchestrator.identity_public_key_bytes().ok();

        let cursor = CursorTracker::load(&read_storage);
        self.read_storage = Some(read_storage);
        self.contact_ids = contact_ids.clone();

        let (stream_tx, stream_rx) =
            spawn_stream_worker(self.grpc.clone(), contact_ids.clone(), cursor.clone());
        self.stream_tx = Some(stream_tx.clone());

        let orch_handle = spawn_orchestrator_task(
            orchestrator,
            storage,
            stream_tx,
            self.events.clone(),
            self.grpc.clone(),
            cursor.clone(),
            contact_ids,
            self.user_id.clone(),
            self.device_id.clone(),
        );
        // AppLaunched triggers the session GC / prewarm sweep.
        orch_handle.send(construct_core::orchestration::actions::IncomingEvent::AppLaunched);
        self.orch_handle = Some(orch_handle.clone());

        if !otpks.is_empty() {
            tracing::info!("OTPKs generated: {} keys", otpks.len());
            let did = self.device_id.clone();
            let grpc = self.grpc.clone();
            tokio::spawn(async move {
                grpc.set_device_id(Some(did.clone()));
                if let Err(e) = crate::grpc::upload_pre_keys(&grpc, &did, otpks, false).await {
                    tracing::warn!("OTPK upload failed: {e}");
                }
            });
        }

        inbound::spawn_relay(
            stream_rx,
            orch_handle,
            cursor,
            self.events.clone(),
            self.inbox.clone(),
            identity_secret_for_sealed,
        );
        Ok(contacts)
    }
}
