use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use anyhow::{Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::PathBuf;
use zeroize::{Zeroize, Zeroizing};

/// Persisted device identity (keys + tokens).
/// Stored in `~/.config/construct-tui/session.enc`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Ed25519 device signing key (hex, 64 bytes — private).
    pub signing_key_hex: String,
    /// X25519 identity key (hex, 32 bytes — private).
    pub identity_key_hex: String,
    /// Server-assigned device ID (hex, typically 8 bytes).
    pub device_id: String,
    /// Server-assigned user ID (UUID).
    pub user_id: String,
    /// JWT access token.
    pub access_token: String,
    /// JWT refresh token.
    pub refresh_token: String,
    /// Token expiry (Unix seconds).
    pub expires_at: i64,
    /// X25519 signed pre-key (hex, 32 bytes — private). Required by ClassicClient::from_keys().
    #[serde(default)]
    pub spk_key_hex: String,
    /// Ed25519 signature over the SPK public key (hex, 64 bytes). Required by ClassicClient::from_keys().
    #[serde(default)]
    pub spk_sig_hex: String,
}

/// Per-session derived key material. Both fields are zeroized on drop.
/// Held in memory for the full authenticated session lifetime — never serialized to disk.
pub struct DerivedKeys {
    /// AES-256-GCM key for encrypting `session.enc`.
    pub session: Zeroizing<[u8; 32]>,
    /// AES-256 key fed to SQLCipher for `messages.db` page encryption.
    pub database: Zeroizing<[u8; 32]>,
}

/// Bundles derived keys with the Argon2id master salt.
/// The salt is constant for the lifetime of an identity — it must never change while
/// the database is open, because the DB key is derived from it.
pub struct SessionKey {
    pub keys: DerivedKeys,
    /// 16-byte Argon2id salt, stored in `session.enc` and reused on every re-save.
    pub master_salt: [u8; 16],
}

/// App-level config.
/// Stored in `~/.config/construct-tui/config.json`.
/// Transport layer selection — controls how gRPC traffic reaches the server.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(tag = "mode")]
pub enum TransportConfig {
    /// Direct TLS — default for uncensored networks.
    #[default]
    Direct,
    /// Future VEIL/bridge placeholder. Parsed in config, not wired to transport.
    Obfs4 {
        /// Bridge configuration string for a future transport connector.
        bridge_line: String,
    },
    /// Future bridge + outer TLS wrapper placeholder.
    Obfs4Tls {
        bridge_line: String,
        /// SNI hostname for a future outer TLS connector.
        tls_server_name: String,
    },
    /// Future domain-fronting placeholder.
    CdnFront {
        cdn_endpoint: String,
        sni_host: String,
        real_host: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_server")]
    pub server: String,
    #[serde(default)]
    pub transport: TransportConfig,
}

/// Encrypted session blob stored on disk.
/// The presence of the `v` field distinguishes it from the legacy plaintext `Session`.
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedSession {
    /// Format version (always 1).
    pub v: u32,
    /// Argon2id salt (base64, 16 bytes).
    pub salt: String,
    /// AES-256-GCM nonce (base64, 12 bytes).
    pub nonce: String,
    /// Encrypted `Session` JSON (base64 + AES-256-GCM tag).
    pub ciphertext: String,
}

/// What kind of session file is present on disk.
pub enum SessionState {
    /// File exists and is AES-256-GCM encrypted.
    Encrypted,
    /// File exists as legacy plaintext JSON.
    Plaintext,
    /// No session file found.
    None,
}

/// Detect what kind of session file exists without loading keys.
pub fn detect_session() -> SessionState {
    let Ok(path) = session_path() else {
        return SessionState::None;
    };
    if !path.exists() {
        return SessionState::None;
    }
    let Ok(data) = std::fs::read_to_string(&path) else {
        return SessionState::None;
    };
    if serde_json::from_str::<EncryptedSession>(&data).is_ok() {
        SessionState::Encrypted
    } else {
        SessionState::Plaintext
    }
}

// ── Key derivation ─────────────────────────────────────────────────────────────

/// Argon2id: passphrase + salt → 32-byte master key.
/// Parameters tuned for Raspberry Pi 4 (32 MB memory, 3 iterations, 1 thread).
fn derive_master_key(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let params =
        Params::new(32_768, 3, 1, Some(32)).map_err(|e| anyhow::anyhow!("Argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|e| anyhow::anyhow!("Argon2: {e}"))?;
    Ok(key)
}

/// HKDF-SHA-256: master key → two domain-separated 32-byte keys.
/// Using distinct info strings gives independent keys even from the same master.
fn derive_keys_from_master(master: &[u8; 32]) -> Result<DerivedKeys> {
    let hkdf = Hkdf::<Sha256>::new(None, master.as_ref());
    let mut session_key = Zeroizing::new([0u8; 32]);
    let mut db_key = Zeroizing::new([0u8; 32]);
    hkdf.expand(b"construct-session-v1", session_key.as_mut())
        .map_err(|_| anyhow::anyhow!("HKDF expand (session) failed"))?;
    hkdf.expand(b"construct-database-v1", db_key.as_mut())
        .map_err(|_| anyhow::anyhow!("HKDF expand (database) failed"))?;
    Ok(DerivedKeys {
        session: session_key,
        database: db_key,
    })
}

/// Derive a `SessionKey` for an **existing** session on disk.
///
/// Reads the master salt from `session.enc` (no decryption), runs Argon2id,
/// then splits with HKDF into session-encryption and database-encryption keys.
/// Returns `None` if no session file exists.
pub fn open_session_key(passphrase: &[u8]) -> Result<Option<SessionKey>> {
    let Some(master_salt) = read_master_salt()? else {
        return Ok(None);
    };
    let master = derive_master_key(passphrase, &master_salt)?;
    let keys = derive_keys_from_master(&master)?;
    Ok(Some(SessionKey { keys, master_salt }))
}

/// Create a **fresh** `SessionKey` for a brand-new account.
/// Generates a random 16-byte master salt and derives all keys from it.
pub fn create_session_key(passphrase: &[u8]) -> Result<SessionKey> {
    let mut master_salt = [0u8; 16];
    OsRng.fill_bytes(&mut master_salt);
    let master = derive_master_key(passphrase, &master_salt)?;
    let keys = derive_keys_from_master(&master)?;
    Ok(SessionKey { keys, master_salt })
}

/// Read the Argon2id master salt from `session.enc` without decrypting the session.
/// Used to derive keys before decryption.
pub fn read_master_salt() -> Result<Option<[u8; 16]>> {
    let path = session_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let data = std::fs::read_to_string(&path)?;
    let enc: EncryptedSession =
        serde_json::from_str(&data).context("session file is not in encrypted format")?;
    let salt = B64.decode(&enc.salt).context("bad salt encoding")?;
    if salt.len() != 16 {
        return Err(anyhow::anyhow!(
            "unexpected salt length: {} (expected 16)",
            salt.len()
        ));
    }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&salt);
    Ok(Some(arr))
}

// ── Encryption helpers ─────────────────────────────────────────────────────────

/// Save session encrypted with the provided `SessionKey`.
/// Uses the `master_salt` from `sk` (constant per identity) and a fresh AES-GCM nonce.
pub fn save_session_encrypted(session: &Session, sk: &SessionKey) -> Result<()> {
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(sk.keys.session.as_ref())
        .map_err(|_| anyhow::anyhow!("AES-GCM init failed"))?;

    let mut plaintext = serde_json::to_vec(session)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|_| anyhow::anyhow!("AES-GCM encrypt failed"))?;
    plaintext.zeroize();

    let enc = EncryptedSession {
        v: 1,
        salt: B64.encode(sk.master_salt),
        nonce: B64.encode(nonce_bytes),
        ciphertext: B64.encode(ciphertext),
    };

    let path = session_path()?;
    std::fs::write(&path, serde_json::to_string(&enc)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Decrypt and load the session using the provided `SessionKey`.
/// Returns `None` if the session file doesn't exist.
/// Returns `Err` if the file is present but decryption fails (wrong key or corruption).
pub fn load_session_encrypted(sk: &SessionKey) -> Result<Option<Session>> {
    let path = session_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let data = std::fs::read_to_string(&path)?;
    let enc: EncryptedSession =
        serde_json::from_str(&data).context("session file is not in encrypted format")?;

    let nonce_bytes = B64.decode(&enc.nonce).context("bad nonce encoding")?;
    let ciphertext = B64
        .decode(&enc.ciphertext)
        .context("bad ciphertext encoding")?;

    let cipher = Aes256Gcm::new_from_slice(sk.keys.session.as_ref())
        .map_err(|_| anyhow::anyhow!("AES-GCM init failed"))?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| anyhow::anyhow!("Decryption failed — wrong passphrase?"))?;

    let session: Session = serde_json::from_slice(&plaintext)?;
    plaintext.zeroize();
    Ok(Some(session))
}

fn default_server() -> String {
    "https://ams.konstruct.cc:443".into()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: default_server(),
            transport: TransportConfig::Direct,
        }
    }
}

// ── Paths ──────────────────────────────────────────────────────────────────────

/// The directory everything of this client lives in; a front end keeps its own preferences
/// here too.
pub fn config_dir() -> Result<PathBuf> {
    let base = dirs::config_dir().context("cannot locate config dir")?;
    let dir = base.join("construct-tui");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

pub fn config_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("config.json"))
}

pub fn session_path() -> Result<PathBuf> {
    let dir = config_dir()?;
    let enc_path = dir.join("session.enc");
    let old_path = dir.join("session.json");
    // Transparent migration: rename on first access so both plaintext and encrypted
    // sessions land in session.enc going forward.
    if old_path.exists() && !enc_path.exists() {
        std::fs::rename(&old_path, &enc_path)?;
    }
    Ok(enc_path)
}

// ── Persistence ────────────────────────────────────────────────────────────────

pub fn load_config() -> Result<Config> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(Config::default());
    }
    let data = std::fs::read_to_string(&path)?;
    Ok(serde_json::from_str(&data)?)
}

#[allow(dead_code)]
pub fn save_config(cfg: &Config) -> Result<()> {
    let path = config_path()?;
    std::fs::write(path, serde_json::to_string_pretty(cfg)?)?;
    Ok(())
}

pub fn load_session() -> Result<Option<Session>> {
    let path = session_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let data = std::fs::read_to_string(&path)?;
    Ok(Some(serde_json::from_str(&data)?))
}

pub fn save_session(session: &Session) -> Result<()> {
    let path = session_path()?;
    // Permissions: owner read/write only
    let json = serde_json::to_string_pretty(session)?;
    std::fs::write(&path, json)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn clear_session() -> Result<()> {
    let path = session_path()?;
    if path.exists() {
        // Overwrite with random bytes before deleting.
        // Mitigates forensic recovery on flash/SD storage (wear-levelling caveat applies).
        let len = std::fs::metadata(&path)?.len() as usize;
        let mut garbage = vec![0u8; len];
        OsRng.fill_bytes(&mut garbage);
        std::fs::write(&path, &garbage)?;
        std::fs::remove_file(path)?;
    }
    Ok(())
}
