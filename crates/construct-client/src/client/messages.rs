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

    /// Send a file the person chose: prepared (a photo loses its metadata), sealed by the core,
    /// uploaded, then sent like any message. Runs aside; the screens see it once it is kept
    /// ([`crate::bridge::BridgeEvent::OwnMessage`]), and a failure as a notice.
    pub(super) fn send_file(
        &self,
        contact_id: String,
        name: String,
        bytes: Vec<u8>,
        caption: String,
    ) {
        let Some(orch) = self.orch_handle.clone() else {
            return;
        };
        let grpc = self.grpc.clone();
        let events = self.events.clone();
        tokio::spawn(async move {
            let fail = |reason: String| {
                tracing::warn!("file not sent: {reason}");
                let _ = events.send(ClientEvent::Notice(format!("File not sent: {reason}")));
            };
            let file = crate::outgoing::prepare(&name, bytes);
            let sealed = match construct_core::media::seal_media(&file.bytes) {
                Ok(sealed) => sealed,
                Err(e) => return fail(e.to_string()),
            };
            let uploaded =
                match crate::grpc::upload_media(&grpc, &sealed.blob, &sealed.sha256).await {
                    Ok(uploaded) => uploaded,
                    Err(e) => return fail(e.to_string()),
                };
            tracing::info!(media_id = %uploaded.media_id, kind = ?file.kind, "file uploaded");
            let payload = crate::outgoing::content(&file, &uploaded, &sealed, &caption, None);
            orch.send_payload(contact_id, Uuid::new_v4().to_string(), payload);
        });
    }

    /// Fetch and open file `index` of message `message_id`; the result comes as
    /// [`ClientEvent::Media`]. Runs aside, so a large download holds up nothing else.
    pub(super) fn load_media(&self, message_id: String, index: usize) {
        let (Some(store), Some(data)) = (self.store.as_ref(), self.data.as_ref()) else {
            return;
        };
        let file = match store.media_files(&message_id) {
            Ok(mut files) if index < files.len() => files.swap_remove(index),
            Ok(_) => {
                return self.emit(ClientEvent::Media {
                    message_id,
                    index,
                    result: Err("the message carries no such file".into()),
                });
            }
            Err(e) => {
                return self.emit(ClientEvent::Media {
                    message_id,
                    index,
                    result: Err(e.to_string()),
                });
            }
        };
        let cache = crate::media::MediaCache::new(data.media_dir());
        let local_key = store.media_local_key(&file.media_id);
        let anonymous = self.anonymous.clone();
        let events = self.events.clone();
        tokio::spawn(async move {
            let result = crate::media::open(
                &cache,
                &anonymous,
                &file,
                local_key.as_deref().map(|k| &k[..]),
            )
            .await;
            if let Err(e) = &result {
                tracing::warn!("media {} not opened: {e}", file.media_id);
            }
            let _ = events.send(ClientEvent::Media {
                message_id,
                index,
                result,
            });
        });
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
