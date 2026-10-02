//! Sending a text message and reading a conversation's history.

use uuid::Uuid;

use super::{Client, ClientEvent};

impl Client {
    /// Hand a text message to the orchestrator.
    pub(super) fn send_text(&self, contact_id: String, text: String) {
        let message_id = Uuid::new_v4().to_string();
        if let Some(ref orch) = self.orch_handle {
            orch.send(
                construct_core::orchestration::actions::IncomingEvent::OutgoingMessage {
                    contact_id: contact_id.clone(),
                    message_id: message_id.clone(),
                    plaintext: text.as_bytes().to_vec(),
                    content_type: 0,
                },
            );
        }
        self.emit(ClientEvent::MessageQueued {
            contact_id,
            message_id,
            text,
        });
    }

    /// The last `limit` stored messages with one person, oldest first.
    pub(super) fn load_history(&self, peer_id: String, limit: usize) {
        let messages = self
            .read_storage
            .as_ref()
            .and_then(|s| s.get_messages(&peer_id, limit).ok())
            .unwrap_or_default();
        self.emit(ClientEvent::History { peer_id, messages });
    }
}
