//! SQLite message/session storage for construct-tui.
//!
//! Uses WAL journal mode and a 2 MB page cache (safe on Raspberry Pi with 1 GB RAM).
//! All tables use INTEGER rowid primary keys for efficient range queries.

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ── Public row types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMessage {
    pub id: String,
    /// User ID of the remote party (the "conversation bucket").
    pub peer_id: String,
    /// Decrypted plaintext (empty while ciphertext is pending).
    pub text: String,
    /// `"sent"` | `"received"` | `"pending"`
    pub direction: String,
    /// Unix milliseconds.
    pub timestamp_ms: i64,
    /// `"delivered"` | `"read"` | `"failed"` | `""`
    pub delivery_status: String,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct StoredContact {
    pub user_id: String,
    pub display_name: String,
    /// Base-64 encoded identity public key (for safety number display).
    pub identity_key_b64: String,
}

// ── Storage struct ────────────────────────────────────────────────────────────

/// Wraps a `rusqlite::Connection` with domain-specific helpers.
/// **Not** `Send`/`Sync` — create one per async task / thread if needed.
pub struct Storage {
    conn: Connection,
}

impl Storage {
    /// Open (or create) the storage database encrypted with SQLCipher.
    ///
    /// `db_key` is the 32-byte AES-256 database key derived from the user's passphrase
    /// via Argon2id + HKDF (`config::SessionKey::keys.database`).
    pub fn open(db_key: &[u8]) -> Result<Self> {
        anyhow::ensure!(db_key.len() == 32, "db_key must be 32 bytes");
        let path = db_path()?;
        let conn =
            Connection::open(&path).with_context(|| format!("open db at {}", path.display()))?;
        // SQLCipher key must be set before any schema access.
        let key_hex = hex::encode(db_key);
        conn.execute_batch(&format!(
            "PRAGMA key = \"x'{key_hex}'\";\nPRAGMA cipher_page_size = 4096;\n"
        ))
        .context("SQLCipher key/cipher_page_size pragma")?;
        let storage = Self { conn };
        storage.init()?;
        Ok(storage)
    }

    /// Open an unencrypted database (`--no-encrypt` mode only).
    /// All plaintext data is protected solely by filesystem permissions (`0o600`).
    pub fn open_unencrypted() -> Result<Self> {
        let path = db_path()?;
        let conn =
            Connection::open(&path).with_context(|| format!("open db at {}", path.display()))?;
        let storage = Self { conn };
        storage.init()?;
        Ok(storage)
    }

    /// Open an in-memory database (unit tests).
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let storage = Self { conn };
        storage.init()?;
        Ok(storage)
    }

    // ── Schema ────────────────────────────────────────────────────────────────

    fn init(&self) -> Result<()> {
        // Performance pragmas (RPi-friendly).
        self.conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous   = NORMAL;
            PRAGMA cache_size    = -2048;
            PRAGMA foreign_keys  = ON;
        ",
        )?;

        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS messages (
                id               TEXT PRIMARY KEY NOT NULL,
                peer_id          TEXT NOT NULL,
                text             TEXT NOT NULL DEFAULT '',
                direction        TEXT NOT NULL CHECK(direction IN ('sent','received','pending')),
                timestamp_ms     INTEGER NOT NULL,
                delivery_status  TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_messages_peer
                ON messages(peer_id, timestamp_ms DESC);

            CREATE TABLE IF NOT EXISTS contacts (
                user_id          TEXT PRIMARY KEY NOT NULL,
                display_name     TEXT NOT NULL DEFAULT '',
                identity_key_b64 TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS pending_acks (
                message_id       TEXT PRIMARY KEY NOT NULL,
                timestamp_ms     INTEGER NOT NULL
            );

            -- Generic secure key-value store (replaces Keychain on Linux).
            CREATE TABLE IF NOT EXISTS secure_store (
                key   TEXT PRIMARY KEY NOT NULL,
                value BLOB NOT NULL
            );

            -- Generic JSON record store (implements PlatformBridge::persist_record).
            CREATE TABLE IF NOT EXISTS records (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                table_name TEXT NOT NULL,
                json      TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (unixepoch())
            );
            CREATE INDEX IF NOT EXISTS idx_records_table ON records(table_name);
        ",
        )?;

        Ok(())
    }

    // ── Messages ──────────────────────────────────────────────────────────────

    pub fn store_message(&self, msg: &StoredMessage) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO messages
             (id, peer_id, text, direction, timestamp_ms, delivery_status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                msg.id,
                msg.peer_id,
                msg.text,
                msg.direction,
                msg.timestamp_ms,
                msg.delivery_status
            ],
        )?;
        Ok(())
    }

    /// Inbound path: ignore replays so a server rewind cannot clobber plaintext.
    pub fn store_inbound_message(&self, msg: &StoredMessage) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO messages
             (id, peer_id, text, direction, timestamp_ms, delivery_status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                msg.id,
                msg.peer_id,
                msg.text,
                msg.direction,
                msg.timestamp_ms,
                msg.delivery_status
            ],
        )?;
        Ok(())
    }

    /// Load up to `limit` most recent messages for a conversation.
    pub fn get_messages(&self, peer_id: &str, limit: usize) -> Result<Vec<StoredMessage>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, peer_id, text, direction, timestamp_ms, delivery_status
             FROM messages
             WHERE peer_id = ?1
             ORDER BY timestamp_ms DESC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![peer_id, limit as i64], |row| {
            Ok(StoredMessage {
                id: row.get(0)?,
                peer_id: row.get(1)?,
                text: row.get(2)?,
                direction: row.get(3)?,
                timestamp_ms: row.get(4)?,
                delivery_status: row.get(5)?,
            })
        })?;
        let mut msgs: Vec<StoredMessage> = rows.collect::<rusqlite::Result<_>>()?;
        msgs.reverse(); // return chronological order
        Ok(msgs)
    }

    pub fn mark_delivered(&self, message_id: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE messages SET delivery_status = 'delivered' WHERE id = ?1",
            params![message_id],
        )?;
        Ok(())
    }

    // ── Contacts ──────────────────────────────────────────────────────────────

    #[allow(dead_code)]
    pub fn upsert_contact(&self, contact: &StoredContact) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO contacts (user_id, display_name, identity_key_b64)
             VALUES (?1, ?2, ?3)",
            params![
                contact.user_id,
                contact.display_name,
                contact.identity_key_b64
            ],
        )?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn get_contacts(&self) -> Result<Vec<StoredContact>> {
        let mut stmt = self.conn.prepare(
            "SELECT user_id, display_name, identity_key_b64 FROM contacts ORDER BY display_name",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(StoredContact {
                user_id: row.get(0)?,
                display_name: row.get(1)?,
                identity_key_b64: row.get(2)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn get_contact_by_id(&self, user_id: &str) -> Result<Option<StoredContact>> {
        let mut stmt = self.conn.prepare(
            "SELECT user_id, display_name, identity_key_b64 FROM contacts WHERE user_id = ?1",
        )?;
        let mut rows = stmt.query_map([user_id], |row| {
            Ok(StoredContact {
                user_id: row.get(0)?,
                display_name: row.get(1)?,
                identity_key_b64: row.get(2)?,
            })
        })?;
        Ok(rows.next().transpose()?)
    }

    // ── ACK store ─────────────────────────────────────────────────────────────

    pub fn store_ack(&self, message_id: &str, timestamp_ms: i64) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO pending_acks (message_id, timestamp_ms) VALUES (?1, ?2)",
            params![message_id, timestamp_ms],
        )?;
        Ok(())
    }

    /// Drain all pending ACKs, clearing the table.
    #[allow(dead_code)]
    pub fn pop_all_acks(&self) -> Result<Vec<(String, i64)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT message_id, timestamp_ms FROM pending_acks")?;
        let rows: Vec<(String, i64)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        if !rows.is_empty() {
            self.conn.execute("DELETE FROM pending_acks", [])?;
        }
        Ok(rows)
    }

    pub fn prune_acks(&self, cutoff_ms: i64) -> Result<()> {
        self.conn.execute(
            "DELETE FROM pending_acks WHERE timestamp_ms < ?1",
            params![cutoff_ms],
        )?;
        Ok(())
    }

    /// Returns `true` if the given message_id has a pending ACK entry.
    /// Used by the Orchestrator's `CheckAckInDb` action for deduplication.
    pub fn has_ack(&self, message_id: &str) -> Result<bool> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM pending_acks WHERE message_id = ?1",
            params![message_id],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    // ── Contact / message deletion ───────────────────────────────────────────

    /// Delete a contact and all associated messages and DR session keys.
    /// Returns the number of message rows deleted.
    pub fn delete_contact(&self, user_id: &str) -> Result<usize> {
        self.conn
            .execute("DELETE FROM contacts WHERE user_id = ?1", params![user_id])?;
        let msg_count = self
            .conn
            .execute("DELETE FROM messages WHERE peer_id = ?1", params![user_id])?;
        // DR session keys stored by construct-core use keys that contain the peer UUID.
        // Wipe all matching entries so the next init starts from a clean state.
        self.conn.execute(
            "DELETE FROM secure_store WHERE key LIKE '%' || ?1 || '%'",
            params![user_id],
        )?;
        Ok(msg_count)
    }

    // ── Secure key-value store ────────────────────────────────────────────────

    pub fn secure_save(&self, key: &str, value: &[u8]) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO secure_store (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    /// Store non-empty data, or delete the key when the core sends its empty
    /// payload delete sentinel.
    pub fn secure_save_or_delete(&self, key: &str, value: &[u8]) -> Result<()> {
        if value.is_empty() {
            self.secure_delete(key)
        } else {
            self.secure_save(key, value)
        }
    }

    pub fn secure_load(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let mut stmt = self
            .conn
            .prepare("SELECT value FROM secure_store WHERE key = ?1")?;
        let mut rows = stmt.query(params![key])?;
        Ok(rows.next()?.map(|r| r.get(0)).transpose()?)
    }

    pub fn secure_delete(&self, key: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM secure_store WHERE key = ?1", params![key])?;
        Ok(())
    }

    // ── Stream cursor (Redis stream id, advanced only after durable persist) ──

    const STREAM_CURSOR_KEY: &'static str = "stream_cursor";

    pub fn load_stream_cursor(&self) -> Result<Option<String>> {
        Ok(self
            .secure_load(Self::STREAM_CURSOR_KEY)?
            .and_then(|b| String::from_utf8(b).ok())
            .filter(|s| !s.is_empty()))
    }

    /// Persist `cursor` only if it is strictly after the stored value.
    /// Returns whether the stored watermark moved.
    pub fn save_stream_cursor(&self, cursor: &str) -> Result<bool> {
        if cursor.is_empty() {
            return Ok(false);
        }
        if let Some(old) = self.load_stream_cursor()?
            && !cursor_after(cursor, &old)
        {
            return Ok(false);
        }
        self.secure_save(Self::STREAM_CURSOR_KEY, cursor.as_bytes())?;
        Ok(true)
    }

    pub fn clear_stream_cursor(&self) -> Result<()> {
        self.secure_delete(Self::STREAM_CURSOR_KEY)
    }

    // ── Generic record store ──────────────────────────────────────────────────

    pub fn persist_record(&self, table_name: &str, json: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO records (table_name, json) VALUES (?1, ?2)",
            params![table_name, json],
        )?;
        Ok(())
    }

    /// Return the most recent JSON record for a table (last insert).
    pub fn query_last_record(&self, table_name: &str) -> Result<Option<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT json FROM records WHERE table_name = ?1 ORDER BY id DESC LIMIT 1")?;
        let mut rows = stmt.query(params![table_name])?;
        Ok(rows.next()?.map(|r| r.get(0)).transpose()?)
    }
}

// ── Path helpers ──────────────────────────────────────────────────────────────

/// Redis stream ids are `<millis>-<seq>`. True when `new` is strictly after `old`.
pub fn cursor_after(new: &str, old: &str) -> bool {
    match (parse_stream_cursor(new), parse_stream_cursor(old)) {
        (Some(a), Some(b)) => a > b,
        _ => new > old,
    }
}

fn parse_stream_cursor(s: &str) -> Option<(u64, u64)> {
    let (ms, seq) = s.split_once('-')?;
    Some((ms.parse().ok()?, seq.parse().ok()?))
}

fn db_path() -> Result<PathBuf> {
    let base = dirs::data_local_dir().context("cannot locate data dir")?;
    let dir = base.join("construct-tui");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("messages.db");
    // Restrict permissions to owner read/write only on Unix.
    #[cfg(unix)]
    if !path.exists() {
        // Create the file first so we can set permissions before SQLite writes to it.
        let _ = std::fs::File::create(&path);
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(path)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_message() {
        let s = Storage::open_in_memory().unwrap();
        let msg = StoredMessage {
            id: "msg-1".into(),
            peer_id: "alice".into(),
            text: "hello".into(),
            direction: "sent".into(),
            timestamp_ms: 1_000_000,
            delivery_status: "".into(),
        };
        s.store_message(&msg).unwrap();
        let msgs = s.get_messages("alice", 10).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].text, "hello");
    }

    #[test]
    fn ack_store_drain() {
        let s = Storage::open_in_memory().unwrap();
        s.store_ack("m1", 100).unwrap();
        s.store_ack("m2", 200).unwrap();
        let acks = s.pop_all_acks().unwrap();
        assert_eq!(acks.len(), 2);
        assert!(s.pop_all_acks().unwrap().is_empty());
    }

    #[test]
    fn secure_store_roundtrip() {
        let s = Storage::open_in_memory().unwrap();
        s.secure_save("session_key", b"secret").unwrap();
        let val = s.secure_load("session_key").unwrap();
        assert_eq!(val.as_deref(), Some(b"secret".as_ref()));
    }

    #[test]
    fn secure_save_or_delete_treats_empty_value_as_delete_sentinel() {
        let s = Storage::open_in_memory().unwrap();
        s.secure_save("session_alice", b"secret").unwrap();
        s.secure_save_or_delete("session_alice", b"").unwrap();
        assert_eq!(s.secure_load("session_alice").unwrap(), None);
    }

    #[test]
    fn inbound_replay_does_not_clobber() {
        let s = Storage::open_in_memory().unwrap();
        let first = StoredMessage {
            id: "msg-1".into(),
            peer_id: "alice".into(),
            text: "hello".into(),
            direction: "received".into(),
            timestamp_ms: 1,
            delivery_status: "".into(),
        };
        s.store_inbound_message(&first).unwrap();
        let replay = StoredMessage {
            text: "clobber".into(),
            ..first.clone()
        };
        s.store_inbound_message(&replay).unwrap();
        let msgs = s.get_messages("alice", 10).unwrap();
        assert_eq!(msgs[0].text, "hello");
    }

    #[test]
    fn stream_cursor_refuses_to_go_backwards() {
        let s = Storage::open_in_memory().unwrap();
        assert!(s.save_stream_cursor("100-0").unwrap());
        assert!(!s.save_stream_cursor("99-0").unwrap());
        assert!(!s.save_stream_cursor("100-0").unwrap());
        assert!(s.save_stream_cursor("100-1").unwrap());
        assert_eq!(s.load_stream_cursor().unwrap().as_deref(), Some("100-1"));
        s.clear_stream_cursor().unwrap();
        assert!(s.load_stream_cursor().unwrap().is_none());
    }

    #[test]
    fn cursor_after_parses_redis_ids() {
        assert!(cursor_after("1785830217320-0", "1785829024441-0"));
        assert!(!cursor_after("10-0", "10-0"));
        assert!(cursor_after("10-1", "10-0"));
    }
}
