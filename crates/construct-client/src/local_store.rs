//! The client's view of the local store.
//!
//! The schema, the queries and the encryption are `construct-store`'s, one for every client
//! (decisions/local-store-in-the-core.md); this file only says how this client's calls map onto
//! it and turns rows into what the screens read. One [`LocalStore`] is shared by the orchestrator
//! task and the client: the store serialises its own writes.

use std::sync::Arc;

use anyhow::Result;
use construct_store::{Chat, Contact, Message, PeerDevice, Store, delivery, payload};
use serde::{Deserialize, Serialize};

// ── What the screens read ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMessage {
    pub id: String,
    /// The account on the other side (the conversation).
    pub peer_id: String,
    pub text: String,
    /// `"sent"` | `"received"`
    pub direction: String,
    /// Unix milliseconds.
    pub timestamp_ms: i64,
    /// `"delivered"` once the peer's receipt came, else `""`.
    pub delivery_status: String,
}

#[derive(Debug, Clone)]
pub struct StoredContact {
    pub user_id: String,
    pub display_name: String,
    /// Base-64 encoded identity public key (for safety number display).
    pub identity_key_b64: String,
}

// ── The store ─────────────────────────────────────────────────────────────────

const STREAM_CURSOR_KEY: &str = "stream_cursor";

#[derive(Clone)]
pub struct LocalStore {
    store: Arc<Store>,
    /// Our account: the `from` of what we send, the `to` of what we receive.
    own_account: String,
}

impl LocalStore {
    pub fn new(store: Store, own_account: &str) -> Self {
        Self {
            store: Arc::new(store),
            own_account: own_account.to_string(),
        }
    }

    /// The same store, writing `own_account` as our side of each message.
    pub fn for_account(self, own_account: &str) -> Self {
        Self {
            store: self.store,
            own_account: own_account.to_string(),
        }
    }

    /// A throwaway store for tests, under the same encryption code path.
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self> {
        Ok(Self::new(Store::open_in_memory(&[7u8; 32])?, "me"))
    }

    /// Close the store and delete its files, if this is the last handle. The caller deletes the
    /// key.
    pub fn wipe(self) -> Result<()> {
        match Arc::try_unwrap(self.store) {
            Ok(store) => Ok(store.wipe()?),
            Err(shared) => {
                if let Some(path) = shared.path() {
                    let path = path.to_path_buf();
                    drop(shared);
                    Store::remove_files(&path)?;
                }
                Ok(())
            }
        }
    }

    // ── Secrets the core and the client keep (sessions, key records, cursors) ──

    pub fn secure_save(&self, key: &str, value: &[u8]) -> Result<()> {
        Ok(self.store.put(key, value)?)
    }

    /// Store non-empty data, or delete the key when the core sends its empty payload delete
    /// sentinel.
    pub fn secure_save_or_delete(&self, key: &str, value: &[u8]) -> Result<()> {
        if value.is_empty() {
            self.secure_delete(key)
        } else {
            self.secure_save(key, value)
        }
    }

    pub fn secure_load(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.store.get(key)?)
    }

    pub fn secure_delete(&self, key: &str) -> Result<()> {
        Ok(self.store.remove(key)?)
    }

    // ── Stream cursor (Redis stream id, advanced only after durable persist) ──

    pub fn load_stream_cursor(&self) -> Result<Option<String>> {
        Ok(self
            .secure_load(STREAM_CURSOR_KEY)?
            .and_then(|b| String::from_utf8(b).ok())
            .filter(|s| !s.is_empty()))
    }

    /// Persist `cursor` only if it is strictly after the stored value. Returns whether the stored
    /// watermark moved.
    pub fn save_stream_cursor(&self, cursor: &str) -> Result<bool> {
        if cursor.is_empty() {
            return Ok(false);
        }
        if let Some(old) = self.load_stream_cursor()?
            && !cursor_after(cursor, &old)
        {
            return Ok(false);
        }
        self.secure_save(STREAM_CURSOR_KEY, cursor.as_bytes())?;
        Ok(true)
    }

    pub fn clear_stream_cursor(&self) -> Result<()> {
        self.secure_delete(STREAM_CURSOR_KEY)
    }

    // ── Messages ──────────────────────────────────────────────────────────────

    /// The chat with `peer`, made on first use. One chat per peer; its id is the peer's account.
    fn chat_with(&self, peer: &str) -> Result<String> {
        if let Some(chat) = self.store.chat_for_peer(peer)? {
            return Ok(chat.id);
        }
        // A chat names a contact row; a peer not in the contacts gets one that says so.
        self.store.insert_contact(&Contact {
            id: peer.to_string(),
            ..Default::default()
        })?;
        self.store.insert_chat(&Chat {
            id: peer.to_string(),
            peer_id: peer.to_string(),
            ..Default::default()
        })?;
        Ok(peer.to_string())
    }

    /// A message we sent, or one received. A message id already held is kept as it is, so a
    /// redelivery cannot clobber what was stored.
    fn insert(&self, msg: &StoredMessage, sent_by_me: bool) -> Result<()> {
        let chat_id = self.chat_with(&msg.peer_id)?;
        let (from, to) = if sent_by_me {
            (self.own_account.clone(), msg.peer_id.clone())
        } else {
            (msg.peer_id.clone(), self.own_account.clone())
        };
        self.store.insert_message(
            &Message {
                id: msg.id.clone(),
                chat_id: chat_id.clone(),
                from_user_id: from,
                to_user_id: to,
                is_sent_by_me: sent_by_me,
                timestamp: msg.timestamp_ms,
                order_key: payload::local_order_key(msg.timestamp_ms, &msg.id),
                body: payload::encode(payload::kind::TEXT, msg.text.as_bytes()),
                content_type: 1,
                delivery_status: if sent_by_me {
                    delivery::SENDING
                } else {
                    delivery::DELIVERED
                },
                ..Default::default()
            },
            Some(&msg.text),
        )?;
        self.store
            .set_chat_preview(&chat_id, Some(&msg.text), Some(msg.timestamp_ms))?;
        Ok(())
    }

    pub fn store_message(&self, msg: &StoredMessage) -> Result<()> {
        self.insert(msg, msg.direction == "sent")
    }

    /// Inbound path: a replay of an id already held changes nothing.
    pub fn store_inbound_message(&self, msg: &StoredMessage) -> Result<()> {
        self.insert(msg, false)
    }

    /// Up to `limit` most recent messages with `peer`, oldest first.
    pub fn get_messages(&self, peer: &str, limit: usize) -> Result<Vec<StoredMessage>> {
        let Some(chat) = self.store.chat_for_peer(peer)? else {
            return Ok(Vec::new());
        };
        let rows =
            self.store
                .messages_before(&chat.id, None, limit.try_into().unwrap_or(u32::MAX))?;
        let mut messages: Vec<StoredMessage> = rows
            .into_iter()
            .map(|m| StoredMessage {
                text: match payload::Payload::decode(&m.body) {
                    payload::Payload::Text(text) => text.to_string(),
                    other => String::from_utf8_lossy(match other {
                        payload::Payload::Legacy(b) => b,
                        _ => &[],
                    })
                    .into_owned(),
                },
                direction: if m.is_sent_by_me { "sent" } else { "received" }.into(),
                delivery_status: if m.is_sent_by_me && m.delivery_status == delivery::DELIVERED {
                    "delivered".into()
                } else {
                    String::new()
                },
                id: m.id,
                peer_id: peer.to_string(),
                timestamp_ms: m.timestamp,
            })
            .collect();
        messages.sort_by_key(|m| m.timestamp_ms);
        Ok(messages)
    }

    pub fn mark_delivered(&self, message_id: &str) -> Result<()> {
        self.store
            .set_delivery_status(message_id, delivery::DELIVERED)?;
        Ok(())
    }

    // ── Contacts ──────────────────────────────────────────────────────────────

    pub fn upsert_contact(&self, contact: &StoredContact) -> Result<()> {
        let existing = self.store.contact(&contact.user_id)?;
        self.store.upsert_contact(&Contact {
            id: contact.user_id.clone(),
            username: contact.display_name.clone(),
            display_name: contact.display_name.clone(),
            is_contact: true,
            added_at: Some(now_ms()),
            ..existing.unwrap_or_default()
        })?;
        Ok(())
    }

    pub fn get_contacts(&self) -> Result<Vec<StoredContact>> {
        Ok(self
            .store
            .contacts()?
            .into_iter()
            .filter(|c| c.is_contact)
            .map(view_contact)
            .collect())
    }

    pub fn get_contact_by_id(&self, user_id: &str) -> Result<Option<StoredContact>> {
        Ok(self.store.contact(user_id)?.map(view_contact))
    }

    /// Delete a contact with its chat, messages and devices.
    pub fn delete_contact(&self, user_id: &str) -> Result<bool> {
        Ok(self.store.delete_contact(user_id)?)
    }

    // ── Processed deliveries (the core's ACK store) ───────────────────────────

    pub fn store_ack(&self, message_id: &str, timestamp_ms: i64) -> Result<()> {
        self.store.mark_processed(message_id, "", timestamp_ms)?;
        Ok(())
    }

    pub fn has_ack(&self, message_id: &str) -> Result<bool> {
        Ok(self.store.is_processed(message_id)?)
    }

    pub fn prune_acks(&self, cutoff_ms: i64) -> Result<()> {
        self.store.forget_processed_before(cutoff_ms)?;
        Ok(())
    }

    // ── Peer devices ──────────────────────────────────────────────────────────

    /// File `device_id` under `user_id`. The id must derive from `identity_key`; the caller
    /// checked it. A device already filed keeps its row: its id is its key's.
    pub fn upsert_peer_device(
        &self,
        user_id: &str,
        device_id: &str,
        identity_key: &[u8],
    ) -> Result<()> {
        self.store.record_peer_device(&PeerDevice {
            device_id: device_id.to_string(),
            account_id: user_id.to_string(),
            identity_key: identity_key.to_vec(),
            first_seen_at: now_ms(),
        })?;
        Ok(())
    }

    /// Every filed device: `(user_id, device_id, identity_key)`.
    pub fn peer_devices(&self) -> Result<Vec<(String, String, Vec<u8>)>> {
        Ok(self
            .store
            .all_peer_devices()?
            .into_iter()
            .map(|d| (d.account_id, d.device_id, d.identity_key))
            .collect())
    }

    /// Keep only `active` of `user_id`'s devices; returns the ids removed. An empty list removes
    /// nothing.
    pub fn retain_peer_devices(&self, user_id: &str, active: &[String]) -> Result<Vec<String>> {
        Ok(self.store.retain_peer_devices(user_id, active)?)
    }

    // ── Server message ids ────────────────────────────────────────────────────

    pub fn record_server_message_id(&self, server_id: &str, local_id: &str) -> Result<()> {
        self.store
            .record_server_message_id(server_id, local_id, now_ms())?;
        Ok(())
    }

    pub fn local_message_id(&self, server_id: &str) -> Result<Option<String>> {
        Ok(self.store.local_message_id(server_id)?)
    }
}

fn view_contact(c: Contact) -> StoredContact {
    use base64::Engine;
    StoredContact {
        identity_key_b64: c
            .known_identity_key
            .as_deref()
            .map(|k| base64::engine::general_purpose::STANDARD.encode(k))
            .unwrap_or_default(),
        display_name: if c.display_name.is_empty() {
            c.username
        } else {
            c.display_name
        },
        user_id: c.id,
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Redis stream ids compare as `(ms, seq)`; anything else falls back to string order.
pub fn cursor_after(new: &str, old: &str) -> bool {
    match (parse_stream_cursor(new), parse_stream_cursor(old)) {
        (Some(new), Some(old)) => new > old,
        _ => new > old,
    }
}

fn parse_stream_cursor(s: &str) -> Option<(u64, u64)> {
    let (ms, seq) = s.split_once('-')?;
    Some((ms.parse().ok()?, seq.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(id: &str, text: &str, direction: &str, ts: i64) -> StoredMessage {
        StoredMessage {
            id: id.into(),
            peer_id: "alice".into(),
            text: text.into(),
            direction: direction.into(),
            timestamp_ms: ts,
            delivery_status: String::new(),
        }
    }

    #[test]
    fn a_conversation_reads_back_in_order_with_its_direction() {
        let s = LocalStore::open_in_memory().unwrap();
        s.store_message(&message("m2", "second", "sent", 2))
            .unwrap();
        s.store_inbound_message(&message("m1", "first", "received", 1))
            .unwrap();

        let msgs = s.get_messages("alice", 10).unwrap();
        assert_eq!(
            msgs.iter().map(|m| m.text.as_str()).collect::<Vec<_>>(),
            ["first", "second"]
        );
        assert_eq!(msgs[0].direction, "received");
        assert_eq!(msgs[1].direction, "sent");
        assert_eq!(msgs[1].delivery_status, "");

        s.mark_delivered("m2").unwrap();
        assert_eq!(
            s.get_messages("alice", 10).unwrap()[1].delivery_status,
            "delivered"
        );
    }

    #[test]
    fn a_replayed_inbound_message_does_not_clobber_the_stored_one() {
        let s = LocalStore::open_in_memory().unwrap();
        s.store_inbound_message(&message("m1", "original", "received", 1))
            .unwrap();
        s.store_inbound_message(&message("m1", "replay", "received", 1))
            .unwrap();
        assert_eq!(s.get_messages("alice", 10).unwrap()[0].text, "original");
    }

    #[test]
    fn the_stream_cursor_only_moves_forward() {
        let s = LocalStore::open_in_memory().unwrap();
        assert!(s.save_stream_cursor("1000-1").unwrap());
        assert!(!s.save_stream_cursor("999-9").unwrap());
        assert!(s.save_stream_cursor("1000-2").unwrap());
        assert_eq!(s.load_stream_cursor().unwrap().as_deref(), Some("1000-2"));
    }

    #[test]
    fn an_empty_secure_save_deletes_the_key() {
        let s = LocalStore::open_in_memory().unwrap();
        s.secure_save("session_alice", b"state").unwrap();
        s.secure_save_or_delete("session_alice", b"").unwrap();
        assert_eq!(s.secure_load("session_alice").unwrap(), None);
    }

    #[test]
    fn deleting_a_contact_takes_its_messages_and_devices() {
        let s = LocalStore::open_in_memory().unwrap();
        s.upsert_contact(&StoredContact {
            user_id: "alice".into(),
            display_name: "Alice".into(),
            identity_key_b64: String::new(),
        })
        .unwrap();
        s.store_inbound_message(&message("m1", "hi", "received", 1))
            .unwrap();
        s.upsert_peer_device("alice", "dev", &[1u8; 32]).unwrap();

        assert!(s.delete_contact("alice").unwrap());

        assert!(s.get_contacts().unwrap().is_empty());
        assert!(s.get_messages("alice", 10).unwrap().is_empty());
        assert!(s.peer_devices().unwrap().is_empty());
    }
}
