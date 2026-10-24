//! The client's view of the local store.
//!
//! The schema, the queries and the encryption are `construct-store`'s, one for every client
//! (decisions/local-store-in-the-core.md); this file only says how this client's calls map onto
//! it and turns rows into what the screens read. One [`LocalStore`] is shared by the orchestrator
//! task and the client: the store serialises its own writes.

use std::sync::Arc;

use anyhow::Result;
use construct_store::{
    Chat, Contact, Message, OwnProfile, PeerDevice, PendingChunk, Reaction, Store, delivery,
    payload,
};

pub use crate::content::{Attachment, MediaInfo, Quote};
use serde::{Deserialize, Serialize};

// ── What the screens read ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
    /// Its author changed the text after sending.
    #[serde(default)]
    pub edited: bool,
    /// The message this one answers.
    #[serde(default)]
    pub quote: Option<Quote>,
    /// What it carries besides `text` (which is then its caption, or a sticker's emoji).
    #[serde(default)]
    pub attachment: Option<Attachment>,
    /// One per person, oldest first.
    #[serde(default)]
    pub reactions: Vec<StoredReaction>,
    /// The files it carries, in display order; fetched by index ([`LocalStore::media_files`]).
    #[serde(default)]
    pub media: Vec<MediaInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredReaction {
    pub reactor_id: String,
    pub emoji: String,
}

const PREF_DELIVERY_RECEIPTS: &str = "pref.delivery_receipts";
const PREF_DISCOVERABLE: &str = "pref.discoverable";
const PREF_MEDIA: &str = "pref.media";

/// How long a split message waits for its missing frames (iOS `PendingReassemblyStore`).
const CHUNK_RETENTION_MS: i64 = 24 * 60 * 60 * 1000;

/// How attachments are fetched and kept, as iOS offers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaPrefs {
    pub auto_download: crate::media::AutoDownload,
    /// Bytes the cache may take; `None` for no limit.
    pub quota: Option<u64>,
    /// Days a fetched file is kept; `None` for always.
    pub keep_days: Option<u32>,
}

impl Default for MediaPrefs {
    /// iOS's: small files on arrival, 1 GB, kept always.
    fn default() -> Self {
        Self {
            auto_download: crate::media::AutoDownload::Small,
            quota: Some(1 << 30),
            keep_days: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct StoredContact {
    pub user_id: String,
    pub display_name: String,
    /// Base-64 encoded identity public key (for safety number display).
    pub identity_key_b64: String,
    /// The picture they shared, as it came (a JPEG with zeros after it).
    pub avatar: Option<Vec<u8>>,
    /// We share our profile with them.
    pub sharing: bool,
    /// The name we gave them ourselves; it never leaves this device.
    pub alias: Option<String>,
}

/// Our profile as we share it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OwnProfileView {
    pub display_name: String,
    pub username: String,
    pub avatar: Option<Vec<u8>>,
    /// The version contacts hold it at; 0 before the first edit.
    pub edited_at_ms: i64,
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

    // ── Choices the person made in settings, kept with the rest of the account ──

    /// Whether this device tells senders a message arrived (iOS `sendDeliveryReceipts`, on by
    /// default).
    pub fn sends_delivery_receipts(&self) -> bool {
        self.flag(PREF_DELIVERY_RECEIPTS).unwrap_or(true)
    }

    pub fn set_sends_delivery_receipts(&self, on: bool) -> Result<()> {
        self.secure_save(PREF_DELIVERY_RECEIPTS, &[u8::from(on)])
    }

    /// Whether the account can be found by its username, as last set here; the server does not
    /// say (iOS keeps it the same way).
    pub fn discoverable(&self) -> Option<bool> {
        self.flag(PREF_DISCOVERABLE)
    }

    pub fn set_discoverable(&self, on: bool) -> Result<()> {
        self.secure_save(PREF_DISCOVERABLE, &[u8::from(on)])
    }

    /// How attachments are fetched and kept (Settings → Data and storage).
    pub fn media_prefs(&self) -> MediaPrefs {
        match self.secure_load(PREF_MEDIA) {
            Ok(Some(v)) if v.len() == 13 => MediaPrefs {
                auto_download: crate::media::AutoDownload::from_byte(v[0]),
                quota: Some(u64::from_le_bytes(v[1..9].try_into().unwrap())).filter(|q| *q > 0),
                keep_days: Some(u32::from_le_bytes(v[9..13].try_into().unwrap()))
                    .filter(|d| *d > 0),
            },
            _ => MediaPrefs::default(),
        }
    }

    pub fn set_media_prefs(&self, prefs: &MediaPrefs) -> Result<()> {
        let mut v = vec![prefs.auto_download.to_byte()];
        v.extend_from_slice(&prefs.quota.unwrap_or(0).to_le_bytes());
        v.extend_from_slice(&prefs.keep_days.unwrap_or(0).to_le_bytes());
        self.secure_save(PREF_MEDIA, &v)
    }

    /// Our username, as last set from this device: the server does not tell it back
    /// (`GetUserProfile` leaves it out for our own account), so it is kept here, as on iOS.
    pub fn own_username(&self) -> Option<String> {
        Some(self.own_profile().ok()?.username).filter(|u| !u.is_empty())
    }

    /// The username does not version the profile: contacts learn it from the server.
    pub fn set_own_username(&self, username: &str) -> Result<()> {
        let mut p = self.own_profile()?;
        p.username = username.to_owned();
        self.save_own_profile(&p)
    }

    // ── Profiles: ours, and the ones shared with us ──

    pub fn own_profile(&self) -> Result<OwnProfileView> {
        Ok(self
            .store
            .own_profile()?
            .map(|p| OwnProfileView {
                display_name: p.display_name,
                username: p.username,
                avatar: p.avatar,
                edited_at_ms: p.profile_edited_at_ms,
            })
            .unwrap_or_default())
    }

    fn save_own_profile(&self, p: &OwnProfileView) -> Result<()> {
        Ok(self.store.set_own_profile(&OwnProfile {
            account_id: self.own_account.clone(),
            username: p.username.clone(),
            display_name: p.display_name.clone(),
            avatar: p.avatar.clone(),
            profile_edited_at_ms: p.edited_at_ms,
        })?)
    }

    /// A new version of our name and avatar, stamped `now_ms` (never older than the last).
    pub fn edit_own_profile(
        &self,
        display_name: String,
        avatar: Option<Vec<u8>>,
        now_ms: i64,
    ) -> Result<OwnProfileView> {
        let mut p = self.own_profile()?;
        p.display_name = display_name;
        p.avatar = avatar;
        p.edited_at_ms = now_ms.max(p.edited_at_ms + 1);
        self.save_own_profile(&p)?;
        Ok(p)
    }

    /// A profile that has never been stamped gets one now, once: what makes it a version is
    /// that sending it again does not change it (iOS `prepareProfile`).
    pub fn stamped_own_profile(&self, now_ms: i64) -> Result<OwnProfileView> {
        let mut p = self.own_profile()?;
        if p.edited_at_ms == 0 {
            p.edited_at_ms = now_ms;
            self.save_own_profile(&p)?;
        }
        Ok(p)
    }

    /// The people we share our profile with.
    pub fn sharing_with(&self) -> Result<Vec<String>> {
        Ok(self.store.sharing_with(Some(&self.own_account))?)
    }

    /// Our own name for `id`, kept here only; `None` or blank removes it.
    pub fn set_alias(&self, id: &str, alias: Option<&str>) -> Result<bool> {
        let alias = alias.map(str::trim).filter(|a| !a.is_empty());
        Ok(self.store.set_contact_alias(id, alias)?)
    }

    pub fn set_sharing_with(&self, id: &str, sharing: bool) -> Result<bool> {
        Ok(self.store.set_sharing_with(id, sharing)?)
    }

    /// `profile` from `sender`, applied if it is newer than the one held and `sender` is a
    /// person we hold. Returns what then happens to their avatar; `None`: ignored.
    pub fn apply_profile(
        &self,
        sender: &str,
        profile: &crate::profile::ProfileShare,
        now_ms: i64,
    ) -> Result<Option<crate::profile::AvatarAction>> {
        use crate::profile::AvatarAction;
        let Some(held) = self.store.contact(sender)? else {
            return Ok(None);
        };
        let Some(action) = profile.decision(held.profile_edited_at_ms) else {
            return Ok(None);
        };
        // The sender's whole state: no chosen name means none, and the username shows again.
        self.store.apply_shared_profile(
            sender,
            &profile.chosen_name(sender).unwrap_or_default(),
            now_ms,
            i64::try_from(profile.edited_at_ms).unwrap_or(i64::MAX),
        )?;
        match &action {
            AvatarAction::Download(r) => {
                self.store.set_pending_avatar(sender, &r.stored(), now_ms)?;
            }
            AvatarAction::Clear => {
                self.store.set_contact_avatar(sender, None, None, None)?;
            }
            AvatarAction::Keep => {}
        }
        Ok(Some(action))
    }

    /// The avatar `id` announced and since when, if one waits to be downloaded.
    pub fn pending_avatar(&self, id: &str) -> Result<Option<(Vec<u8>, i64)>> {
        Ok(self.store.contact(id)?.and_then(|c| {
            c.pending_avatar_ref
                .map(|r| (r, c.pending_avatar_since.unwrap_or(0)))
        }))
    }

    pub fn contacts_with_pending_avatar(&self) -> Result<Vec<String>> {
        Ok(self
            .store
            .contacts_with_pending_avatar()?
            .into_iter()
            .map(|c| c.id)
            .collect())
    }

    /// The download of `expected` finished; false when a newer one was announced meanwhile.
    pub fn complete_pending_avatar(
        &self,
        id: &str,
        expected: &[u8],
        avatar: &[u8],
    ) -> Result<bool> {
        Ok(self.store.complete_pending_avatar(id, expected, avatar)?)
    }

    /// The wait for `expected` ends without it; the avatar shown stays.
    pub fn drop_pending_avatar(&self, id: &str, expected: &[u8]) -> Result<bool> {
        Ok(self.store.drop_pending_avatar(id, expected)?)
    }

    fn flag(&self, key: &str) -> Option<bool> {
        match self.secure_load(key) {
            Ok(Some(v)) => v.first().map(|b| *b != 0),
            _ => None,
        }
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
    /// redelivery cannot clobber what was stored. `content` is the wire `MessageContent` of a
    /// message that is more than text, kept whole so what this client cannot show yet is not
    /// lost; plain text is stored as text.
    fn insert(&self, msg: &StoredMessage, sent_by_me: bool, content: Option<&[u8]>) -> Result<()> {
        let chat_id = self.chat_with(&msg.peer_id)?;
        let (from, to) = if sent_by_me {
            (self.own_account.clone(), msg.peer_id.clone())
        } else {
            (msg.peer_id.clone(), self.own_account.clone())
        };
        let body = match content {
            Some(content) => payload::encode(payload::kind::MESSAGE_CONTENT, content),
            None => payload::encode(payload::kind::TEXT, msg.text.as_bytes()),
        };
        let preview = preview(msg);
        self.store.insert_message(
            &Message {
                id: msg.id.clone(),
                chat_id: chat_id.clone(),
                from_user_id: from,
                to_user_id: to,
                is_sent_by_me: sent_by_me,
                timestamp: msg.timestamp_ms,
                order_key: payload::local_order_key(msg.timestamp_ms, &msg.id),
                body,
                content_type: 1,
                delivery_status: if sent_by_me {
                    delivery::SENDING
                } else {
                    delivery::DELIVERED
                },
                reply_to_message_id: msg.quote.as_ref().map(|q| q.message_id.clone()),
                reply_to_content: msg.quote.as_ref().map(|q| q.preview.clone()),
                ..Default::default()
            },
            Some(&msg.text),
        )?;
        self.store
            .set_chat_preview(&chat_id, Some(&preview), Some(msg.timestamp_ms))?;
        Ok(())
    }

    pub fn store_message(&self, msg: &StoredMessage) -> Result<()> {
        self.insert(msg, msg.direction == "sent", None)
    }

    /// Inbound path: a replay of an id already held changes nothing.
    pub fn store_inbound_message(&self, msg: &StoredMessage) -> Result<()> {
        self.insert(msg, false, None)
    }

    /// A message that is more than text, sent or received: `content` is its `MessageContent`.
    pub fn store_content(&self, msg: &StoredMessage, content: &[u8]) -> Result<()> {
        self.insert(msg, msg.direction == "sent", Some(content))
    }

    /// Our account, the author of what this device and its siblings send.
    pub fn own_account(&self) -> &str {
        &self.own_account
    }

    /// One message, as the screens read it.
    pub fn message(&self, id: &str) -> Result<Option<StoredMessage>> {
        let Some(row) = self.store.message(id)? else {
            return Ok(None);
        };
        let Some(chat) = self.store.chat(&row.chat_id)? else {
            return Ok(None);
        };
        let reactions = self.store.reactions(id)?;
        Ok(Some(view_message(row, &chat.peer_id, &reactions)))
    }

    /// The files message `id` carries, with what fetching and opening them takes.
    pub fn media_files(&self, id: &str) -> Result<Vec<crate::content::MediaFile>> {
        Ok(match self.store.message(id)? {
            Some(row) => match payload::Payload::decode(&row.body) {
                payload::Payload::MessageContent(bytes) => crate::content::media_files(bytes),
                _ => Vec::new(),
            },
            None => Vec::new(),
        })
    }

    /// The author of message `id`, when it is held.
    pub fn author_of(&self, id: &str) -> Result<Option<String>> {
        Ok(self.store.message(id)?.map(|m| m.from_user_id))
    }

    /// `author` replaced the text of `id`. False — nothing changed — when there is no such
    /// message, it is not theirs, or it is not text (a caption edit waits on attachments).
    pub fn edit(&self, id: &str, author: &str, text: &str, edited_at: i64) -> Result<bool> {
        let Some(row) = self.store.message(id)? else {
            return Ok(false);
        };
        if row.from_user_id != author
            || !matches!(
                payload::Payload::decode(&row.body),
                payload::Payload::Text(_)
            )
        {
            return Ok(false);
        }
        Ok(self.store.edit_message(
            id,
            &payload::encode(payload::kind::TEXT, text.as_bytes()),
            Some(text),
            edited_at,
        )?)
    }

    /// `reactor`'s reaction on `target`, set or taken back, if `clock` is newer than the one
    /// held (iOS `ReactionReducer`). Returns whether anything changed.
    pub fn react(
        &self,
        target: &str,
        reactor: &str,
        emoji: Option<&str>,
        clock: i64,
    ) -> Result<bool> {
        let held = self
            .store
            .reactions(target)?
            .into_iter()
            .find(|r| r.reactor_user_id == reactor);
        if !crate::content::reaction_wins(clock, held.as_ref().map(|r| r.timestamp_ms)) {
            return Ok(false);
        }
        match emoji {
            Some(emoji) => self.store.upsert_reaction(&Reaction {
                target_message_id: target.to_string(),
                reactor_user_id: reactor.to_string(),
                emoji: emoji.to_string(),
                timestamp_ms: clock,
                received_at: Some(now_ms()),
            })?,
            None if held.is_some() => self.store.delete_reaction(target, reactor)?,
            None => return Ok(false),
        }
        Ok(true)
    }

    /// Delete message `id` here, with its reactions. Other devices and the peer keep theirs.
    pub fn delete_message(&self, id: &str) -> Result<()> {
        Ok(self.store.delete_message(id)?)
    }

    /// Hold one frame of `sender`'s split message. Returns the whole payload once every frame is
    /// in — and forgets the frames — else `None`. A frame decrypts once (its ratchet key is gone
    /// after), so the frames are kept on disk, not in memory.
    pub fn hold_chunk(
        &self,
        sender: &str,
        chunk: &crate::knst::Chunk,
        envelope_id: &str,
    ) -> Result<Option<Vec<u8>>> {
        let now = now_ms();
        self.store
            .forget_pending_chunks_before(now - CHUNK_RETENTION_MS)?;
        self.store.add_pending_chunk(&PendingChunk {
            sender_id: sender.to_string(),
            message_id: chunk.id.clone(),
            chunk_index: chunk.index.into(),
            total_chunks: chunk.total.into(),
            plaintext_length: chunk.plaintext_length.into(),
            content_type: chunk.content_type,
            payload: chunk.payload.clone(),
            envelope_id: Some(envelope_id.to_string()),
            received_at: now,
        })?;
        if self.store.pending_chunk_count(sender, &chunk.id)? < u32::from(chunk.total) {
            return Ok(None);
        }
        let held = self.store.pending_chunks(sender, &chunk.id)?;
        self.store.delete_pending_chunks(sender, &chunk.id)?;
        Ok(assemble(&held, chunk.total))
    }

    /// Up to `limit` most recent messages with `peer`, oldest first.
    pub fn get_messages(&self, peer: &str, limit: usize) -> Result<Vec<StoredMessage>> {
        let Some(chat) = self.store.chat_for_peer(peer)? else {
            return Ok(Vec::new());
        };
        let rows =
            self.store
                .messages_before(&chat.id, None, limit.try_into().unwrap_or(u32::MAX))?;
        let reactions = self.store.reactions_in_chat(&chat.id)?;
        let mut messages: Vec<StoredMessage> = rows
            .into_iter()
            .map(|m| {
                let on_it: Vec<Reaction> = reactions
                    .iter()
                    .filter(|r| r.target_message_id == m.id)
                    .cloned()
                    .collect();
                view_message(m, peer, &on_it)
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
        // A name they shared stays: the username is a fallback, not a newer name (iOS
        // `applyServerUsername`).
        let display_name = match &existing {
            Some(c) if c.is_sharing_with_me => c.display_name.clone(),
            _ => contact.display_name.clone(),
        };
        self.store.upsert_contact(&Contact {
            id: contact.user_id.clone(),
            username: contact.display_name.clone(),
            display_name,
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
        // As iOS names a person: the name they shared, their username, or the one generated
        // from their id — never a blank or a raw id.
        display_name: crate::names::resolved(
            c.local_alias.as_deref(),
            &c.display_name,
            &c.username,
            &c.id,
        ),
        alias: c.local_alias,
        avatar: c.avatar,
        sharing: c.am_i_sharing_with,
        user_id: c.id,
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// A stored row as the screens read it.
fn view_message(m: Message, peer: &str, reactions: &[Reaction]) -> StoredMessage {
    let mut media = Vec::new();
    let (text, quote, attachment) = match payload::Payload::decode(&m.body) {
        payload::Payload::Text(text) => (text.to_string(), None, None),
        payload::Payload::MessageContent(bytes) => match crate::content::parse(bytes) {
            Some(crate::content::Content::Message {
                text,
                quote,
                attachment,
            }) => {
                media = crate::content::media_files(bytes)
                    .into_iter()
                    .map(|f| f.info)
                    .collect();
                (text, quote, attachment)
            }
            _ => (String::new(), None, Some(Attachment::Other)),
        },
        payload::Payload::Legacy(bytes) => {
            (String::from_utf8_lossy(bytes).into_owned(), None, None)
        }
        payload::Payload::MediaAlbum(_) => (String::new(), None, Some(Attachment::Photo)),
        payload::Payload::Profile(_) => (String::new(), None, Some(Attachment::Contact)),
    };
    let quote = quote.or_else(|| {
        m.reply_to_message_id.clone().map(|message_id| Quote {
            message_id,
            preview: m.reply_to_content.clone().unwrap_or_default(),
        })
    });
    let mut reactions = reactions.to_vec();
    reactions.sort_by_key(|r| r.timestamp_ms);
    StoredMessage {
        text,
        direction: if m.is_sent_by_me { "sent" } else { "received" }.into(),
        delivery_status: if m.is_sent_by_me && m.delivery_status == delivery::DELIVERED {
            "delivered".into()
        } else {
            String::new()
        },
        edited: m.is_edited,
        quote,
        attachment,
        reactions: reactions
            .into_iter()
            .map(|r| StoredReaction {
                reactor_id: r.reactor_user_id,
                emoji: r.emoji,
            })
            .collect(),
        media,
        id: m.id,
        peer_id: peer.to_string(),
        timestamp_ms: m.timestamp,
    }
}

/// The chat list's line for a message: its text, or what it carries.
fn preview(msg: &StoredMessage) -> String {
    match (msg.attachment, msg.text.is_empty()) {
        (Some(_), true) => "📎".to_string(),
        (Some(_), false) => format!("📎 {}", msg.text),
        (None, _) => msg.text.clone(),
    }
}

/// The frames of a split message joined in order and cut to the length they declare. `None`
/// when one is missing or they disagree about the message.
fn assemble(held: &[PendingChunk], total: u16) -> Option<Vec<u8>> {
    let first = held.first()?;
    let whole = held.len() == usize::from(total)
        && held.iter().enumerate().all(|(i, c)| {
            c.chunk_index as usize == i
                && c.total_chunks == u32::from(total)
                && c.plaintext_length == first.plaintext_length
                && c.content_type == first.content_type
        });
    if !whole {
        return None;
    }
    let mut payload: Vec<u8> = held
        .iter()
        .flat_map(|c| c.payload.iter().copied())
        .collect();
    let length = usize::try_from(first.plaintext_length).ok()?;
    if length > payload.len() {
        return None;
    }
    payload.truncate(length);
    Some(payload)
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
            ..Default::default()
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
    fn split_frames_join_in_order_and_lose_their_padding() {
        let chunk = |index: u32, payload: &[u8]| PendingChunk {
            sender_id: "bob".into(),
            message_id: "m".into(),
            chunk_index: index,
            total_chunks: 2,
            plaintext_length: 5,
            content_type: 1,
            payload: payload.to_vec(),
            envelope_id: None,
            received_at: 0,
        };
        assert_eq!(
            assemble(&[chunk(0, b"abc"), chunk(1, b"de\0\0")], 2).as_deref(),
            Some(&b"abcde"[..])
        );
        // A frame missing, or one that says it is another message's, joins nothing.
        assert_eq!(assemble(&[chunk(0, b"abc")], 2), None);
        let mut stray = chunk(1, b"de");
        stray.plaintext_length = 9;
        assert_eq!(assemble(&[chunk(0, b"abc"), stray], 2), None);
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
            ..Default::default()
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

    fn profile(
        name: &str,
        at: u64,
        avatar: crate::profile::Avatar,
    ) -> crate::profile::ProfileShare {
        crate::profile::ProfileShare {
            display_name: name.into(),
            edited_at_ms: at,
            avatar,
        }
    }

    fn avatar_ref(id: &str) -> crate::profile::AvatarRef {
        crate::profile::AvatarRef {
            media_id: id.into(),
            media_url: String::new(),
            media_key: vec![7; 32],
            mime_type: "image/jpeg".into(),
        }
    }

    fn held(s: &LocalStore, id: &str) {
        s.upsert_contact(&StoredContact {
            user_id: id.into(),
            display_name: "bob_k".into(),
            ..Default::default()
        })
        .unwrap();
    }

    #[test]
    fn a_shared_profile_names_a_held_person_and_only_when_newer() {
        use crate::profile::{Avatar, AvatarAction};
        let s = LocalStore::open_in_memory().unwrap();
        let bob = "550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(
            s.apply_profile(bob, &profile("Bob", 5, Avatar::Unchanged), 1)
                .unwrap(),
            None,
            "sending to us makes no contact"
        );
        held(&s, bob);
        let name = |s: &LocalStore| s.get_contact_by_id(bob).unwrap().unwrap().display_name;
        assert_eq!(
            s.apply_profile(bob, &profile("Bob", 5, Avatar::Set(avatar_ref("a1"))), 1)
                .unwrap(),
            Some(AvatarAction::Download(avatar_ref("a1")))
        );
        assert_eq!(name(&s), "Bob");
        assert_eq!(
            s.pending_avatar(bob).unwrap().unwrap().0,
            avatar_ref("a1").stored()
        );
        assert_eq!(
            s.apply_profile(bob, &profile("Old", 5, Avatar::Removed), 2)
                .unwrap(),
            None
        );
        assert_eq!(name(&s), "Bob", "the same version applies once");

        // Re-adding them keeps the name they shared.
        held(&s, bob);
        assert_eq!(name(&s), "Bob");

        // Their generated name is no name: the username shows again.
        s.apply_profile(bob, &profile("cool cobra", 6, Avatar::Unchanged), 3)
            .unwrap();
        assert_eq!(name(&s), "bob_k");
    }

    #[test]
    fn a_downloaded_avatar_counts_only_if_it_is_still_the_one_named() {
        use crate::profile::Avatar;
        let s = LocalStore::open_in_memory().unwrap();
        held(&s, "bob");
        s.apply_profile("bob", &profile("Bob", 1, Avatar::Set(avatar_ref("a1"))), 1)
            .unwrap();
        s.apply_profile("bob", &profile("Bob", 2, Avatar::Set(avatar_ref("a2"))), 1)
            .unwrap();
        assert!(
            !s.complete_pending_avatar("bob", &avatar_ref("a1").stored(), b"old")
                .unwrap()
        );
        assert!(
            s.complete_pending_avatar("bob", &avatar_ref("a2").stored(), b"new")
                .unwrap()
        );
        let bob = s.get_contact_by_id("bob").unwrap().unwrap();
        assert_eq!(bob.avatar.as_deref(), Some(&b"new"[..]));
        s.apply_profile("bob", &profile("Bob", 3, Avatar::Removed), 1)
            .unwrap();
        assert_eq!(s.get_contact_by_id("bob").unwrap().unwrap().avatar, None);
    }

    #[test]
    fn our_profile_versions_only_move_forward() {
        let s = LocalStore::open_in_memory().unwrap();
        assert_eq!(s.stamped_own_profile(100).unwrap().edited_at_ms, 100);
        assert_eq!(
            s.stamped_own_profile(200).unwrap().edited_at_ms,
            100,
            "stamped once"
        );
        let p = s.edit_own_profile("Me".into(), None, 50).unwrap();
        assert_eq!(
            p.edited_at_ms, 101,
            "never older than the last, even with a clock behind"
        );
        s.set_own_username("me_k").unwrap();
        let p = s.own_profile().unwrap();
        assert_eq!(
            (p.display_name.as_str(), p.username.as_str(), p.edited_at_ms),
            ("Me", "me_k", 101)
        );
    }
}
