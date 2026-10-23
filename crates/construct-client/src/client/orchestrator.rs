//! Starting the engine for a signed-in account: keys into the core's Orchestrator, storage,
//! restored sessions, the message stream, the orchestrator task and the inbound relay.

use super::{Client, inbound};
use crate::{config::Session, local_store::StoredContact};

impl Client {
    /// Construct the Orchestrator, open storage, spawn the stream worker and the orchestrator
    /// task, and wire them together. Returns the stored contacts.
    pub(super) fn start_orchestrator(
        &mut self,
        session: Session,
    ) -> Result<Vec<StoredContact>, String> {
        use crate::orchestrator_task::spawn_orchestrator_task;
        use crate::streaming::{CursorTracker, spawn_stream_worker};
        use construct_core::orchestration::orchestrator::Orchestrator;

        let decode = |hex_str: &str| {
            hex::decode(hex_str).map_err(|e| format!("Orchestrator key decode error: {e}"))
        };
        let identity_secret = decode(&session.identity_key_hex)?;
        let signing_secret = decode(&session.signing_key_hex)?;
        let spk_secret = decode(&session.spk_key_hex)?;
        let spk_sig = decode(&session.spk_sig_hex)?;

        // The task opens a certificate box (`SealedInner.sender_cert_ciphertext`) with it; Double
        // Ratchet decryption still happens inside the orchestrator.
        let identity_secret_for_sealed = identity_secret.clone();

        let signing_secret_for_prekeys = signing_secret.clone();

        // One store, shared with the orchestrator task; it serialises its own writes.
        let storage = self
            .store
            .clone()
            .ok_or("the store is not open")?
            .for_account(&self.user_id);
        let read_storage = storage.clone();

        let core_client = crate::prekeys::restore_client(
            &storage,
            identity_secret,
            signing_secret,
            spk_secret,
            spk_sig,
        )
        .map_err(|e| format!("Orchestrator init error: {e}"))?;
        // The core's id for us is this device's, as every peer's core knows us: it enters the
        // ratchet's associated data and the envelope keys (iOS passes the same,
        // `SessionAddressing.localIdentity`).
        let mut orchestrator = Orchestrator::new(core_client, self.device_id.clone());
        let prekeys_whole = crate::prekeys::restore_prekeys(&mut orchestrator, &storage)
            .map_err(|e| format!("Prekey restore error: {e}"))?;

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
        // Sessions are the core's, keyed by device.
        let devices: Vec<String> = read_storage
            .peer_devices()
            .unwrap_or_default()
            .into_iter()
            .map(|(_, device_id, _)| device_id)
            .collect();
        for contact_id in &devices {
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

        // Our identity key before the orchestrator moves into its task.
        self.our_identity_key = orchestrator
            .get_registration_bundle_fields()
            .ok()
            .map(|fields| fields.identity_public);

        let cursor = CursorTracker::load(&read_storage);
        self.store = Some(read_storage);
        self.contact_ids = contact_ids.clone();

        let (stream_tx, stream_rx) =
            spawn_stream_worker(self.grpc.clone(), contact_ids.clone(), cursor.clone());
        self.stream_tx = Some(stream_tx);

        // Sealed sends and the server's trust material go on a connection that never carries
        // the token.
        let anonymous = crate::grpc::GrpcClient::new(&self.server_url);
        let orch_handle = spawn_orchestrator_task(
            orchestrator,
            storage,
            self.events.clone(),
            self.grpc.clone(),
            anonymous.clone(),
            cursor.clone(),
            contact_ids,
            crate::orchestrator_task::LocalIdentity {
                user_id: self.user_id.clone(),
                device_id: self.device_id.clone(),
                identity_secret: identity_secret_for_sealed,
                signing_secret: signing_secret_for_prekeys,
                replace_prekeys: !prekeys_whole,
            },
        );
        {
            let orch = orch_handle.clone();
            tokio::spawn(async move {
                match crate::grpc::get_server_trust_delegations(&anonymous).await {
                    Ok(delegations) if !delegations.is_empty() => {
                        orch.server_delegations(delegations)
                    }
                    Ok(_) => {}
                    Err(e) => tracing::warn!(error = %e, "GetServerTrust failed"),
                }
            });
        }
        // AppLaunched triggers the session GC / prewarm sweep.
        orch_handle.send(construct_core::orchestration::actions::IncomingEvent::AppLaunched);
        self.orch_handle = Some(orch_handle.clone());

        inbound::spawn_relay(
            stream_rx,
            orch_handle,
            cursor,
            self.events.clone(),
            self.inbox.clone(),
        );
        Ok(contacts)
    }
}
