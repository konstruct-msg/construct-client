//! Sending messages, answers, edits and reactions, and reading a conversation's history.

use uuid::Uuid;

use super::{Client, ClientEvent};
use crate::content::{Content, QUOTE_PREVIEW_CHARS, Quote};
use crate::local_store::StoredMessage;

impl Client {
    /// Hand a message to the orchestrator.
    pub(super) fn send_text(&self, contact_id: String, text: String, quote: Option<Quote>) {
        let message_id = Uuid::new_v4().to_string();
        if let Some(ref orch) = self.orch_handle {
            orch.send_content(
                contact_id.clone(),
                message_id.clone(),
                Content::Message {
                    text: text.clone(),
                    quote: quote.clone(),
                    attachment: None,
                },
            );
        }
        self.emit(ClientEvent::MessageQueued {
            contact_id,
            message_id,
            text,
            quote,
        });
    }

    /// Answer message `to`; the quote shows what it said, as its sender wrote it.
    pub(super) fn reply(&self, contact_id: String, text: String, to: String) {
        let Some(quoted) = self.held(&to) else {
            return self.emit(ClientEvent::Notice("The message is no longer here".into()));
        };
        let quote = Quote {
            message_id: quoted.id.clone(),
            preview: quote_preview(&quoted),
        };
        self.send_text(contact_id, text, Some(quote));
    }

    /// Replace the text of our message; the orchestrator refuses one that is not ours.
    pub(super) fn edit_message(&self, message_id: String, text: String) {
        let Some(message) = self.held(&message_id) else {
            return;
        };
        if message.direction != "sent" || text.trim().is_empty() || text == message.text {
            return;
        }
        self.send_action(
            message.peer_id,
            Content::Edit {
                target: message_id,
                text,
            },
        );
    }

    /// Our reaction on a message, or none when `emoji` is the one we have there already.
    pub(super) fn react(&self, message_id: String, emoji: String) {
        let Some(message) = self.held(&message_id) else {
            return;
        };
        let ours = message
            .reactions
            .iter()
            .any(|r| r.reactor_id == self.user_id && r.emoji == emoji);
        self.send_action(
            message.peer_id,
            Content::Reaction {
                target: message_id,
                emoji: (!ours).then_some(emoji),
                timestamp_ms: now_ms(),
            },
        );
    }

    /// Delete a message here, and tell the screens.
    pub(super) fn delete_message(&self, message_id: String) {
        let Some(message) = self.held(&message_id) else {
            return;
        };
        let Some(store) = self.store.as_ref() else {
            return;
        };
        match store.delete_message(&message_id) {
            Ok(()) => self.emit(ClientEvent::Bridge(
                crate::bridge::BridgeEvent::MessageDeleted {
                    peer_id: message.peer_id,
                    message_id,
                },
            )),
            Err(e) => self.emit(ClientEvent::Notice(format!("Not deleted: {e}"))),
        }
    }

    /// An edit or a reaction, under an id of its own (iOS: a fresh action id each).
    fn send_action(&self, peer: String, content: Content) {
        if let Some(ref orch) = self.orch_handle {
            orch.send_content(peer, Uuid::new_v4().to_string(), content);
        }
    }

    fn held(&self, message_id: &str) -> Option<StoredMessage> {
        self.store.as_ref()?.message(message_id).ok()?
    }

    /// The last `limit` stored messages with one person, oldest first.
    pub(super) fn load_history(&self, peer_id: String, limit: usize) {
        let messages = self
            .store
            .as_ref()
            .and_then(|s| s.get_messages(&peer_id, limit).ok())
            .unwrap_or_default();
        self.emit(ClientEvent::History { peer_id, messages });
    }
}

/// What a quote of `message` shows: its text, cut to what the wire carries.
fn quote_preview(message: &StoredMessage) -> String {
    message.text.chars().take(QUOTE_PREVIEW_CHARS).collect()
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
