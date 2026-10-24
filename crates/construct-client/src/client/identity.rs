//! Our identity: the safety-number pair for a contact, export of the identity key, and the
//! invite our QR code shows.

use base64::Engine as _;

use super::{Client, ClientEvent, Inbox};
use zeroize::Zeroizing;

impl Client {
    /// The safety number with a contact — the core's computation over both device ids, the
    /// one iOS shows (`construct-protos/conformance/knst_safety_number.json`).
    ///
    /// Until 2026-10-02 this client computed its own (SHA-512 over the two identity keys), so
    /// the numbers on a TUI screen and an iOS screen never matched; and with the peer's key not
    /// yet fetched it computed one against zeros and showed it as if it meant something. No
    /// key, no number.
    pub(super) fn safety_number(&self, contact_id: String) {
        let Some(ours) = self.our_identity_key.as_deref() else {
            return self.emit(ClientEvent::Notice("Identity key not available".into()));
        };
        let theirs = self
            .store
            .as_ref()
            .and_then(|s| s.get_contact_by_id(&contact_id).ok().flatten())
            .filter(|c| !c.identity_key_b64.is_empty())
            .and_then(|c| {
                base64::engine::general_purpose::STANDARD
                    .decode(&c.identity_key_b64)
                    .ok()
            });
        let Some(theirs) = theirs else {
            return self.emit(ClientEvent::Notice(
                "No safety number yet: their key has not been received".into(),
            ));
        };
        let number = construct_core::crypto::recovery::compute_safety_number(
            &construct_core::device_id::derive_device_id(ours),
            &construct_core::device_id::derive_device_id(&theirs),
        );
        match number {
            Some(number) => self.emit(ClientEvent::SafetyNumber { contact_id, number }),
            None => self.emit(ClientEvent::Notice(
                "No safety number: a key could not be read".into(),
            )),
        }
    }

    /// Write our identity public key to `~/construct_identity_<user>.txt`.
    pub(super) fn export_identity_key(&self) {
        let Some(key) = self.our_identity_key.as_ref() else {
            return self.emit(ClientEvent::Notice("Identity key not available".into()));
        };
        let hex = hex::encode(key);
        let path = format!(
            "{}/construct_identity_{}.txt",
            std::env::var("HOME").unwrap_or_else(|_| ".".into()),
            &self.user_id,
        );
        let notice = match std::fs::write(
            &path,
            format!("identity_public_key_hex={hex}\nuser_id={}\n", self.user_id),
        ) {
            Ok(()) => format!("Key exported → {path}"),
            Err(e) => format!("Export failed: {e}"),
        };
        self.emit(ClientEvent::Notice(notice));
    }

    /// Mint an invite for our QR code. The signing key stays here: the front end gets the
    /// payload, never the key (until 2026-10-02 the settings screen held it to mint invites).
    pub(super) fn mint_invite(&self) {
        let Some(signing_key_hex) = self.current_session.as_ref().map(|s| &s.signing_key_hex)
        else {
            return self.emit(ClientEvent::InviteMinted(Err("Not signed in".into())));
        };
        let Some(address) = self.store.as_ref().and_then(crate::recovery::own_address) else {
            return self.emit(ClientEvent::InviteMinted(Err(
                "This device does not know the account's address yet: it is made in the \
                 background, or, if the account was made on another device, comes from the \
                 recovery phrase entered in Settings"
                    .into(),
            )));
        };
        let ttl = crate::invite::QR_TTL_SECONDS;
        let result = crate::invite::mint(
            &self.user_id,
            &self.device_id,
            &self.server_url,
            signing_key_hex,
            None,
            ttl,
            &address,
        )
        .and_then(|invite| {
            // Kept, so it can be revoked while unused; one invite is the QR and the link both.
            let journal = self
                .store
                .as_ref()
                .map(|store| store.record_issued_invite(&invite.jti, "qr", invite.ts * 1000, ttl));
            if let Some(Err(e)) = journal {
                tracing::warn!("invite not kept for revoking: {e}");
            }
            invite.https_link()
        })
        .map_err(|e| format!("{e:#}"));
        self.emit(ClientEvent::InviteMinted(result));
    }

    // ── Recovery key (crate::recovery) ─────────────────────────────────────────

    /// Make the account's recovery key in the background if it has none, and learn where it
    /// stands. Nothing waits on it: until it is done only the QR and the link are missing.
    pub(super) fn ensure_recovery_key(&self) {
        let Some(store) = self.store.clone() else {
            return;
        };
        let grpc = self.grpc.clone();
        let user_id = self.user_id.clone();
        let inbox = self.inbox.clone();
        tokio::spawn(async move {
            let state = crate::recovery::ensure_key(&store, &grpc, &user_id).await;
            let _ = inbox.send(Inbox::Recovery(state));
        });
    }

    pub(super) fn reveal_recovery_phrase(&self) {
        let phrase = self
            .store
            .as_ref()
            .and_then(crate::recovery::pending_phrase)
            .ok_or_else(|| "No recovery phrase is kept on this device".to_string());
        self.emit(ClientEvent::RecoveryPhrase(phrase));
    }

    pub(super) fn confirm_recovery_copy(&self, answers: &[(usize, String)]) {
        let Some(store) = self.store.as_ref() else {
            return;
        };
        match crate::recovery::confirm_copy(store, answers) {
            Ok(()) => self.emit(ClientEvent::Recovery(crate::recovery::RecoveryState::Ready)),
            Err(e) => self.emit(ClientEvent::RecoveryFailed(e)),
        }
    }

    pub(super) fn enter_recovery_phrase(&self, phrase: Zeroizing<String>) {
        let Some(store) = self.store.clone() else {
            return;
        };
        let grpc = self.grpc.clone();
        let events = self.events.clone();
        let inbox = self.inbox.clone();
        tokio::spawn(async move {
            match crate::recovery::enter_phrase(&store, &grpc, &phrase).await {
                Ok(state) => drop(inbox.send(Inbox::Recovery(state))),
                Err(e) => drop(events.send(ClientEvent::RecoveryFailed(e))),
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Client, ClientCommand, ClientConfig, ClientEvent};
    use crate::config::TransportConfig;
    use tokio::sync::mpsc;

    /// Without the person's key there is no number to compare. The old screen showed one
    /// computed against zeros — a verification that confirms nothing while looking like one.
    #[test]
    fn no_safety_number_without_their_key() {
        let (events_tx, mut events) = mpsc::unbounded_channel();
        let (inbox_tx, _inbox) = mpsc::unbounded_channel();
        let mut client = Client::new(
            ClientConfig {
                server_url: "https://localhost".into(),
                transport: TransportConfig::Direct,
                no_encrypt: true,
                pq_active: true,
            },
            events_tx,
            inbox_tx,
        );
        client.our_identity_key = Some(vec![7u8; 32]);
        client.handle(ClientCommand::SafetyNumber {
            contact_id: "alice".into(),
        });
        match events.try_recv() {
            Ok(ClientEvent::Notice(_)) => {}
            Ok(ClientEvent::SafetyNumber { number, .. }) => {
                panic!("a number without their key: {number}")
            }
            _ => panic!("expected a notice"),
        }
    }
}
