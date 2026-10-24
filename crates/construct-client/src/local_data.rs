//! Where this device's data lives, how the store key is kept, and who holds the data open.
//!
//! Everything the device keeps — its keys, its session with the server, its sessions with peers,
//! its messages — is in one `construct-store` database, SQLCipher-encrypted whole. The platform
//! keeps only the 32-byte store key (decisions/local-store-in-the-core.md, p. 3):
//!
//! - **the OS key store** (`keyring`: Keychain, Secret Service, Credential Manager) — a random
//!   key, nothing to type;
//! - **a passphrase** when there is no key store: the key is Argon2id(passphrase, salt), the salt
//!   in a file beside the database;
//! - **a key file** beside the database for `--no-encrypt` (development and the headless probe):
//!   the database is still encrypted, the key is not protected.
//!
//! One process holds the directory at a time (`konstruct.lock`): the terminal and the desktop
//! shell share it, and two of them writing one account's ratchets would break it.

use std::fs::File;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use construct_store::{KEY_LEN, Store};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const STORE_FILE: &str = "store.db";
const SALT_FILE: &str = "store.salt";
const KEY_FILE: &str = "store.key";
const LOCK_FILE: &str = "konstruct.lock";
const KEYRING_SERVICE: &str = "Konstruct";

/// How the store key of a directory is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKeeping {
    KeyStore,
    Passphrase,
    KeyFile,
}

/// The data directory, held for as long as this value lives.
#[derive(Debug)]
pub struct DataDir {
    dir: PathBuf,
    _lock: File,
}

impl DataDir {
    /// The default directory (`<data dir>/construct-tui`), locked.
    pub fn open_default() -> Result<Self> {
        let base = dirs::data_local_dir().context("cannot locate the data directory")?;
        Self::open(&base.join("construct-tui"))
    }

    /// Lock `dir`, creating it. Fails when another process holds it.
    pub fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        restrict(dir, 0o700);
        let lock = File::create(dir.join(LOCK_FILE))?;
        if lock.try_lock().is_err() {
            bail!("Konstruct is already open in another window or terminal");
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            _lock: lock,
        })
    }

    fn store_path(&self) -> PathBuf {
        self.dir.join(STORE_FILE)
    }

    /// Where fetched attachments are kept, still encrypted (`media::MediaCache`).
    pub fn media_dir(&self) -> PathBuf {
        self.dir.join("media")
    }

    /// Whether a store exists here, and how its key is kept. `None` when there is no store.
    pub fn existing(&self) -> Option<KeyKeeping> {
        existing_in(&self.dir)
    }

    /// Open the store with the key the OS key store or the key file holds.
    pub fn open_store(&self) -> Result<Store> {
        let key = match self.existing() {
            Some(KeyKeeping::KeyStore) => keystore_get(&self.store_path())?
                .context("the store key is not in the OS key store")?,
            Some(KeyKeeping::KeyFile) => read_key_file(&self.dir.join(KEY_FILE))?,
            Some(KeyKeeping::Passphrase) => bail!("this store is opened with its passphrase"),
            None => bail!("there is no store here"),
        };
        Ok(Store::open(self.store_path(), key.as_slice())?)
    }

    /// Open a passphrase-kept store.
    pub fn open_store_with_passphrase(&self, passphrase: &[u8]) -> Result<Store> {
        let salt = std::fs::read(self.dir.join(SALT_FILE)).context("no passphrase salt")?;
        let key = crate::config::derive_master_key(passphrase, &salt)?;
        Store::open(self.store_path(), key.as_slice()).map_err(|e| match e {
            construct_store::StoreError::WrongKey => anyhow::anyhow!("Wrong passphrase"),
            e => e.into(),
        })
    }

    /// Make a new store whose key the OS key store keeps, or — `key_file` — a key file. `None`
    /// when the OS key store cannot be used: the caller asks for a passphrase.
    pub fn create_store(&self, key_file: bool) -> Result<Option<Store>> {
        // A new account on this device replaces whatever store was here: without its key it was
        // ciphertext nobody could open.
        Store::remove_files(&self.store_path())?;
        crate::media::MediaCache::wipe(&self.media_dir())?;
        self.remove_leftovers()?;
        let key = random_key();
        if key_file {
            let path = self.dir.join(KEY_FILE);
            std::fs::write(&path, key.as_slice())?;
            restrict(&path, 0o600);
        } else if let Err(e) = keystore_set(&self.store_path(), key.as_slice()) {
            tracing::warn!(error = %e, "OS key store unavailable; a passphrase will keep the key");
            return Ok(None);
        }
        Ok(Some(Store::open(self.store_path(), key.as_slice())?))
    }

    /// Make a new store whose key is derived from `passphrase`.
    pub fn create_store_with_passphrase(&self, passphrase: &[u8]) -> Result<Store> {
        Store::remove_files(&self.store_path())?;
        self.remove_leftovers()?;
        let mut salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let path = self.dir.join(SALT_FILE);
        std::fs::write(&path, salt)?;
        restrict(&path, 0o600);
        let key = crate::config::derive_master_key(passphrase, &salt)?;
        Ok(Store::open(self.store_path(), key.as_slice())?)
    }

    /// Delete the store's files and its key, wherever it is kept.
    pub fn wipe(&self, store: Option<crate::local_store::LocalStore>) -> Result<()> {
        if let Some(store) = store {
            store.wipe()?;
        }
        Store::remove_files(&self.store_path())?;
        self.remove_leftovers()
    }

    /// The database of the client before the store (`messages.db`, its own schema). Nothing
    /// reads it any more.
    pub fn remove_legacy_database(&self) {
        let _ = Store::remove_files(&self.dir.join("messages.db"));
    }

    /// Key material of a store that is gone: a salt, a key file, a key store entry.
    fn remove_leftovers(&self) -> Result<()> {
        for file in [SALT_FILE, KEY_FILE] {
            match std::fs::remove_file(self.dir.join(file)) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
                _ => {}
            }
        }
        keystore_delete(&self.store_path());
        Ok(())
    }
}

/// How a store in `dir` is kept, read without locking (the first screen is chosen from this).
pub fn existing_in(dir: &Path) -> Option<KeyKeeping> {
    if !dir.join(STORE_FILE).exists() {
        return None;
    }
    Some(if dir.join(SALT_FILE).exists() {
        KeyKeeping::Passphrase
    } else if dir.join(KEY_FILE).exists() {
        KeyKeeping::KeyFile
    } else {
        KeyKeeping::KeyStore
    })
}

pub fn default_dir() -> Option<PathBuf> {
    dirs::data_local_dir().map(|base| base.join("construct-tui"))
}

fn random_key() -> Zeroizing<[u8; KEY_LEN]> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    rand::rngs::OsRng.fill_bytes(key.as_mut());
    key
}

fn read_key_file(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let key = Zeroizing::new(std::fs::read(path)?);
    if key.len() != KEY_LEN {
        bail!("the key file is not a store key");
    }
    Ok(key)
}

/// One key store entry per store file: two data directories on one machine (two HOMEs, two
/// probes) do not share a key.
fn keystore_entry(store_path: &Path) -> Result<keyring::Entry> {
    let digest = Sha256::digest(store_path.to_string_lossy().as_bytes());
    let user = format!("store-key-{}", hex::encode(&digest[..8]));
    Ok(keyring::Entry::new(KEYRING_SERVICE, &user)?)
}

fn keystore_get(store_path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>> {
    match keystore_entry(store_path)?.get_secret() {
        Ok(key) => Ok(Some(Zeroizing::new(key))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn keystore_set(store_path: &Path, key: &[u8]) -> Result<()> {
    keystore_entry(store_path)?.set_secret(key)?;
    // Read it back: a key store that accepts a write and loses it would orphan the store.
    match keystore_get(store_path)? {
        Some(read) if read.as_slice() == key => Ok(()),
        _ => bail!("the OS key store did not keep the key"),
    }
}

fn keystore_delete(store_path: &Path) {
    if let Ok(entry) = keystore_entry(store_path) {
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => {}
            Err(e) => tracing::warn!(error = %e, "store key not deleted from the OS key store"),
        }
    }
}

fn restrict(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("construct-client-{name}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_second_holder_of_the_directory_is_refused() {
        let dir = temp_dir("lock");
        let first = DataDir::open(&dir).unwrap();
        assert!(DataDir::open(&dir).is_err());
        drop(first);
        assert!(DataDir::open(&dir).is_ok());
    }

    #[test]
    fn a_passphrase_store_reopens_with_it_and_not_without() {
        let dir = temp_dir("passphrase");
        let data = DataDir::open(&dir).unwrap();
        let store = data.create_store_with_passphrase(b"correct horse").unwrap();
        store.put("k", b"v").unwrap();
        drop(store);

        assert_eq!(data.existing(), Some(KeyKeeping::Passphrase));
        assert!(data.open_store_with_passphrase(b"wrong").is_err());
        let store = data.open_store_with_passphrase(b"correct horse").unwrap();
        assert_eq!(store.get("k").unwrap().as_deref(), Some(&b"v"[..]));
    }

    #[test]
    fn the_database_file_holds_no_plaintext() {
        let dir = temp_dir("plaintext");
        let data = DataDir::open(&dir).unwrap();
        let store = data.create_store(true).unwrap().unwrap();
        let local = crate::local_store::LocalStore::new(store, "me");
        local
            .store_inbound_message(&crate::local_store::StoredMessage {
                id: "m1".into(),
                peer_id: "alice".into(),
                text: "a very findable sentence".into(),
                direction: "received".into(),
                timestamp_ms: 1,
                delivery_status: String::new(),
                ..Default::default()
            })
            .unwrap();
        local
            .secure_save("session_x", b"ratchet-state-marker")
            .unwrap();
        drop(local);

        let bytes = std::fs::read(dir.join(STORE_FILE)).unwrap();
        for needle in [
            &b"findable sentence"[..],
            b"ratchet-state-marker",
            b"SQLite format",
        ] {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle),
                "{} is in the database file in the open",
                String::from_utf8_lossy(needle)
            );
        }
    }

    #[test]
    fn wiping_removes_the_store_and_its_key() {
        let dir = temp_dir("wipe");
        let data = DataDir::open(&dir).unwrap();
        let store = data.create_store(true).unwrap().unwrap();
        let local = crate::local_store::LocalStore::new(store, "me");

        data.wipe(Some(local)).unwrap();

        assert_eq!(data.existing(), None);
        assert!(!dir.join(KEY_FILE).exists());
        assert!(!dir.join(STORE_FILE).exists());
    }

    /// Writes to the real OS key store, so not run by default:
    /// `cargo test -p construct-client --lib -- --ignored the_os_key_store`.
    #[test]
    #[ignore]
    fn the_os_key_store_keeps_and_forgets_a_store_key() {
        let dir = temp_dir("keystore");
        let data = DataDir::open(&dir).unwrap();
        let store = data
            .create_store(false)
            .unwrap()
            .expect("an OS key store is available here");
        store.put("k", b"v").unwrap();
        drop(store);
        assert_eq!(data.existing(), Some(KeyKeeping::KeyStore));

        let store = data.open_store().unwrap();
        assert_eq!(store.get("k").unwrap().as_deref(), Some(&b"v"[..]));

        data.wipe(Some(crate::local_store::LocalStore::new(store, "me")))
            .unwrap();
        assert!(keystore_get(&dir.join(STORE_FILE)).unwrap().is_none());
    }
}
