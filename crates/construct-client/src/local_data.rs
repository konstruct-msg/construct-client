//! Where this device's data lives, how the store key is kept, and who holds the data open.
//!
//! Everything the device keeps — its keys, its session with the server, its sessions with peers,
//! its messages — is in one `construct-store` database, SQLCipher-encrypted whole. The platform
//! keeps only the 32-byte store key (decisions/local-store-in-the-core.md, p. 3):
//!
//! - **the OS key store** (`keyring`: Keychain, Secret Service, Credential Manager) — a random
//!   key, nothing to type — or, with a launch passphrase, that key sealed under it
//!   (`sealed_key`), and then opening takes both;
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

use crate::sealed_key;

const STORE_FILE: &str = "store.db";
const SALT_FILE: &str = "store.salt";
const KEY_FILE: &str = "store.key";
const LOCK_FILE: &str = "konstruct.lock";
const KEYRING_SERVICE: &str = "Konstruct";

/// 2027-05-31 (Unix seconds).
#[cfg_attr(not(test), allow(dead_code))]
const VEIL_SCORES_UNTIL: u64 = 1_811_721_600;

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
    keys: KeyStore,
    _lock: File,
}

/// construct-veil before 4.0.0 kept a record of networks and methods here, and nothing reads it
/// since (construct-docs `decisions/veil-keeps-no-network-history.md`). Removed until
/// [`VEIL_SCORES_UNTIL`]; `removing_the_veil_scores_has_an_end` fails after it (rule 11).
fn remove_veil_scores(dir: &Path) {
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let file = dir.join(format!("veil-scores.sqlite{suffix}"));
        match std::fs::remove_file(&file) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                tracing::warn!("{} not removed: {e}", file.display())
            }
            _ => {}
        }
    }
}

impl DataDir {
    /// The default directory (`<data dir>/construct-tui`), locked.
    pub fn open_default() -> Result<Self> {
        let base = dirs::data_local_dir().context("cannot locate the data directory")?;
        Self::open(&base.join("construct-tui"))
    }

    /// Lock `dir`, creating it. Fails when another process holds it.
    pub fn open(dir: &Path) -> Result<Self> {
        Self::open_with(dir, KeyStore::Os)
    }

    pub(crate) fn open_with(dir: &Path, keys: KeyStore) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        restrict(dir, 0o700);
        let lock = File::create(dir.join(LOCK_FILE))?;
        if lock.try_lock().is_err() {
            bail!("Konstruct is already open in another window or terminal");
        }
        remove_veil_scores(dir);
        Ok(Self {
            dir: dir.to_path_buf(),
            keys,
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

    /// Where sticker packs are kept (`stickers::Library`): public files, checked by hash.
    pub fn stickers_dir(&self) -> PathBuf {
        self.dir.join("stickers")
    }

    /// Whether a store exists here, and how its key is kept. `None` when there is no store.
    pub fn existing(&self) -> Option<KeyKeeping> {
        existing_in(&self.dir)
    }

    /// Open the store with the key the OS key store or the key file holds. `None` when the key
    /// in the OS key store is sealed under a launch passphrase: the caller asks for it.
    pub fn open_store(&self) -> Result<Option<Store>> {
        let key = match self.existing() {
            Some(KeyKeeping::KeyStore) => match self.entry()? {
                sealed_key::Entry::Bare(key) => key,
                sealed_key::Entry::Sealed(_) => return Ok(None),
            },
            Some(KeyKeeping::KeyFile) => read_key_file(&self.dir.join(KEY_FILE))?,
            Some(KeyKeeping::Passphrase) => bail!("this store is opened with its passphrase"),
            None => bail!("there is no store here"),
        };
        Ok(Some(Store::open(self.store_path(), key.as_slice())?))
    }

    /// Open a store that takes a passphrase: its key is derived from it, or sealed under it in
    /// the OS key store.
    pub fn open_store_with_passphrase(&self, passphrase: &[u8]) -> Result<Store> {
        let kept = self.existing();
        let key = match kept {
            Some(KeyKeeping::Passphrase) => {
                let salt = std::fs::read(self.dir.join(SALT_FILE)).context("no passphrase salt")?;
                let key = crate::config::derive_master_key(passphrase, &salt)?;
                Zeroizing::new(key.to_vec())
            }
            Some(KeyKeeping::KeyStore) => match self.entry()? {
                sealed_key::Entry::Sealed(sealed) => {
                    sealed_key::open(&sealed, passphrase)?.context("Wrong passphrase")?
                }
                sealed_key::Entry::Bare(_) => bail!("this store opens without a passphrase"),
            },
            Some(KeyKeeping::KeyFile) => bail!("this store opens without a passphrase"),
            None => bail!("there is no store here"),
        };
        Store::open(self.store_path(), key.as_slice()).map_err(|e| match e {
            construct_store::StoreError::WrongKey if kept == Some(KeyKeeping::Passphrase) => {
                anyhow::anyhow!("Wrong passphrase")
            }
            e => e.into(),
        })
    }

    /// Set, change (`new`) or remove (`new: None`) the launch passphrase of a store whose key the
    /// OS key store keeps. With one set, `current` must be it. One write of the entry: the store
    /// key itself stays as it is, so whoever took it before still has it.
    pub fn set_launch_passphrase(&self, current: Option<&[u8]>, new: Option<&[u8]>) -> Result<()> {
        if self.existing() != Some(KeyKeeping::KeyStore) {
            bail!("the OS key store does not keep the key of this store");
        }
        let length = |p: &[u8]| std::str::from_utf8(p).map_or(p.len(), |s| s.chars().count());
        if new.is_some_and(|p| length(p) < sealed_key::MIN_PASSPHRASE_LEN) {
            bail!(
                "A passphrase has at least {} characters",
                sealed_key::MIN_PASSPHRASE_LEN
            );
        }
        let (key, before) = match self.entry()? {
            sealed_key::Entry::Bare(key) => (key.clone(), key),
            sealed_key::Entry::Sealed(sealed) => {
                let current = current.context("The current passphrase is needed")?;
                let key = sealed_key::open(&sealed, current)?
                    .context("The current passphrase is wrong")?;
                (key, Zeroizing::new(sealed))
            }
        };
        let after = match new {
            Some(passphrase) => Zeroizing::new(sealed_key::seal(&key, passphrase)?),
            None => key,
        };
        self.keys.set(&self.store_path(), &after).inspect_err(|_| {
            // Written but not read back the same: what was there opened the store.
            if let Err(e) = self.keys.set(&self.store_path(), &before) {
                tracing::error!(error = %e, "the store key's entry could not be put back");
            }
        })
    }

    /// Make the store of a session from before it, under the passphrase that session had, if any:
    /// its key sealed in the OS key store, or made from it where there is none. `None`: there is
    /// neither. That passphrase was chosen before there was a shortest length; it stays as it is.
    pub fn create_store_for_session(
        &self,
        key_file: bool,
        passphrase: Option<&[u8]>,
    ) -> Result<Option<Store>> {
        match (self.create_store(key_file)?, passphrase) {
            (Some(store), Some(p)) if !key_file => {
                if let Err(e) = self.seal_new_store(p) {
                    drop(store);
                    // Left, the next start would find a store with no session in it.
                    self.wipe(None)?;
                    return Err(e);
                }
                Ok(Some(store))
            }
            (Some(store), _) => Ok(Some(store)),
            (None, Some(p)) => Ok(Some(self.create_store_with_passphrase(p)?)),
            (None, None) => Ok(None),
        }
    }

    fn seal_new_store(&self, passphrase: &[u8]) -> Result<()> {
        let sealed_key::Entry::Bare(key) = self.entry()? else {
            bail!("the key of this store is already sealed");
        };
        let sealed = sealed_key::seal(&key, passphrase)?;
        self.keys.set(&self.store_path(), &sealed)
    }

    fn entry(&self) -> Result<sealed_key::Entry> {
        let entry = self
            .keys
            .get(&self.store_path())?
            .context("the store key is not in the OS key store")?;
        sealed_key::read(entry)
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
        } else if let Err(e) = self.keys.set(&self.store_path(), key.as_slice()) {
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
        self.keys.delete(&self.store_path());
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

/// Where the store key is kept. Tests put their own in place of the system's.
#[derive(Debug, Clone)]
pub(crate) enum KeyStore {
    Os,
    /// Entries in memory, by store path.
    #[cfg(test)]
    Memory(std::sync::Arc<std::sync::Mutex<std::collections::HashMap<PathBuf, Vec<u8>>>>),
    /// A system without one.
    #[cfg(test)]
    Absent,
}

impl KeyStore {
    fn get(&self, store_path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>> {
        match self {
            Self::Os => {
                let entry = keystore_entry(store_path)?;
                match entry.get_secret() {
                    Ok(key) => {
                        let key = Zeroizing::new(key);
                        keep_on_this_machine(&entry, &key);
                        Ok(Some(key))
                    }
                    Err(keyring::Error::NoEntry) => Ok(None),
                    Err(e) => Err(e.into()),
                }
            }
            #[cfg(test)]
            Self::Memory(entries) => Ok(entries
                .lock()
                .unwrap()
                .get(store_path)
                .cloned()
                .map(Zeroizing::new)),
            #[cfg(test)]
            Self::Absent => bail!("no key store here"),
        }
    }

    fn set(&self, store_path: &Path, secret: &[u8]) -> Result<()> {
        match self {
            Self::Os => write_entry(&keystore_entry(store_path)?, secret)?,
            #[cfg(test)]
            Self::Memory(entries) => {
                entries
                    .lock()
                    .unwrap()
                    .insert(store_path.to_path_buf(), secret.to_vec());
            }
            #[cfg(test)]
            Self::Absent => bail!("no key store here"),
        }
        // Read it back: a key store that accepts a write and loses it would orphan the store.
        match self.get(store_path)? {
            Some(read) if read.as_slice() == secret => Ok(()),
            _ => bail!("the OS key store did not keep the key"),
        }
    }

    fn delete(&self, store_path: &Path) {
        match self {
            Self::Os => {
                if let Ok(entry) = keystore_entry(store_path) {
                    match entry.delete_credential() {
                        Ok(()) | Err(keyring::Error::NoEntry) => {}
                        Err(e) => {
                            tracing::warn!(error = %e, "store key not deleted from the OS key store")
                        }
                    }
                }
            }
            #[cfg(test)]
            Self::Memory(entries) => drop(entries.lock().unwrap().remove(store_path)),
            #[cfg(test)]
            Self::Absent => {}
        }
    }
}

#[cfg(not(windows))]
fn write_entry(entry: &keyring::Entry, secret: &[u8]) -> Result<()> {
    Ok(entry.set_secret(secret)?)
}

#[cfg(windows)]
fn write_entry(entry: &keyring::Entry, secret: &[u8]) -> Result<()> {
    crate::windows_credential::write(entry, secret)
}

#[cfg(not(windows))]
fn keep_on_this_machine(_: &keyring::Entry, _: &[u8]) {}

/// An entry an earlier build wrote roams with the profile: write it again as local. Failing to
/// changes nothing for opening the store, so it is only logged.
#[cfg(windows)]
fn keep_on_this_machine(entry: &keyring::Entry, secret: &[u8]) {
    use crate::windows_credential::{is_local, write};
    match is_local(entry) {
        Ok(true) => {}
        Ok(false) => match write(entry, secret) {
            Ok(()) => tracing::info!("the store key's entry no longer roams"),
            Err(e) => tracing::warn!(error = %e, "the store key's entry still roams"),
        },
        Err(e) => tracing::warn!(error = %e, "whether the store key's entry roams is unknown"),
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

    /// Opening the directory takes the old record of networks with it, its journals too, and
    /// nothing else.
    #[test]
    fn the_veil_scores_of_an_earlier_build_are_removed() {
        let dir = temp_dir("scores");
        let gone = ["", "-wal", "-shm", "-journal"].map(|s| format!("veil-scores.sqlite{s}"));
        for name in gone
            .iter()
            .map(String::as_str)
            .chain(["veil-scores.sqlite-x"])
        {
            std::fs::write(dir.join(name), b"x").unwrap();
        }
        DataDir::open(&dir).unwrap();
        for name in &gone {
            assert!(!dir.join(name).exists(), "{name}");
        }
        assert!(dir.join("veil-scores.sqlite-x").exists());
    }

    /// Rule 11: the removal is temporary, and this fails on the day it should be gone.
    #[test]
    fn removing_the_veil_scores_has_an_end() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(
            now < VEIL_SCORES_UNTIL,
            "2027-05-31 has passed: remove remove_veil_scores and this test"
        );
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

    fn memory() -> KeyStore {
        KeyStore::Memory(Default::default())
    }

    /// A store the key store keeps the key of, with `k` = `v` in it.
    fn kept(name: &str, keys: &KeyStore) -> (PathBuf, DataDir) {
        let dir = temp_dir(name);
        let data = DataDir::open_with(&dir, keys.clone()).unwrap();
        let store = data.create_store(false).unwrap().unwrap();
        store.put("k", b"v").unwrap();
        (dir, data)
    }

    fn holds_v(store: Store) -> bool {
        store.get("k").unwrap().as_deref() == Some(&b"v"[..])
    }

    #[test]
    fn with_a_launch_passphrase_the_key_store_alone_does_not_open_the_store() {
        let keys = memory();
        let (dir, data) = kept("launch", &keys);
        assert!(holds_v(data.open_store().unwrap().unwrap()));

        data.set_launch_passphrase(None, Some(b"correct horse"))
            .unwrap();

        // What a process that reads the directory and the entry has: no key in either.
        let entry = keys.get(&dir.join(STORE_FILE)).unwrap().unwrap();
        for key in entry.windows(KEY_LEN) {
            assert!(Store::open(dir.join(STORE_FILE), key).is_err());
        }
        assert!(!dir.join(KEY_FILE).exists() && !dir.join(SALT_FILE).exists());
        assert!(data.open_store().unwrap().is_none());
        assert!(data.open_store_with_passphrase(b"wrong horse").is_err());
        assert!(holds_v(
            data.open_store_with_passphrase(b"correct horse").unwrap()
        ));
    }

    #[test]
    fn the_passphrase_alone_does_not_open_a_copied_directory() {
        let (_dir, data) = kept("copied", &memory());
        data.set_launch_passphrase(None, Some(b"correct horse"))
            .unwrap();
        let copy = temp_dir("copy");
        std::fs::copy(data.store_path(), copy.join(STORE_FILE)).unwrap();
        // The other machine's key store knows nothing of it.
        let there = DataDir::open_with(&copy, memory()).unwrap();
        assert!(there.open_store_with_passphrase(b"correct horse").is_err());
        assert!(there.open_store().is_err());
    }

    #[test]
    fn a_launch_passphrase_changes_and_goes_only_with_the_current_one() {
        let (_dir, data) = kept("change", &memory());
        let (first, second) = (&b"correct horse"[..], &b"battery staple"[..]);
        data.set_launch_passphrase(None, Some(first)).unwrap();

        assert!(data.set_launch_passphrase(None, Some(second)).is_err());
        assert!(data.set_launch_passphrase(Some(second), None).is_err());
        assert!(holds_v(data.open_store_with_passphrase(first).unwrap()));

        data.set_launch_passphrase(Some(first), Some(second))
            .unwrap();
        assert!(data.open_store_with_passphrase(first).is_err());
        assert!(holds_v(data.open_store_with_passphrase(second).unwrap()));

        data.set_launch_passphrase(Some(second), None).unwrap();
        assert!(holds_v(data.open_store().unwrap().unwrap()));
    }

    #[test]
    fn a_short_launch_passphrase_is_refused_and_nothing_changes() {
        let (_dir, data) = kept("short", &memory());
        for short in ["1234567", "пароль7"] {
            let set = data.set_launch_passphrase(None, Some(short.as_bytes()));
            assert!(set.is_err(), "{short}");
        }
        assert!(holds_v(data.open_store().unwrap().unwrap()));
    }

    #[test]
    fn a_store_the_key_store_does_not_keep_takes_no_launch_passphrase() {
        let dir = temp_dir("file-kept");
        let data = DataDir::open_with(&dir, memory()).unwrap();
        drop(data.create_store(true).unwrap().unwrap());
        let refused = data.set_launch_passphrase(None, Some(b"correct horse"));
        assert!(refused.unwrap_err().to_string().contains("does not keep"));
        assert!(data.open_store().unwrap().is_some());
    }

    /// Moving a session that had a passphrase used to drop it where there is a key store.
    #[test]
    fn a_session_moved_into_a_store_keeps_its_passphrase() {
        for keys in [memory(), KeyStore::Absent] {
            let data = DataDir::open_with(&temp_dir("moved"), keys).unwrap();
            let store = data.create_store_for_session(false, Some(b"old")).unwrap();
            store.unwrap().put("k", b"v").unwrap();
            assert!(!matches!(data.open_store(), Ok(Some(_))));
            assert!(data.open_store_with_passphrase(b"new").is_err());
            assert!(holds_v(data.open_store_with_passphrase(b"old").unwrap()));
        }
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

        let store = data.open_store().unwrap().expect("no passphrase yet");
        assert_eq!(store.get("k").unwrap().as_deref(), Some(&b"v"[..]));
        drop(store);

        // Sealed, the entry is longer than a key and still kept as it is.
        data.set_launch_passphrase(None, Some(b"correct horse"))
            .unwrap();
        assert!(data.open_store().unwrap().is_none());
        let store = data.open_store_with_passphrase(b"correct horse").unwrap();

        data.wipe(Some(crate::local_store::LocalStore::new(store, "me")))
            .unwrap();
        assert!(KeyStore::Os.get(&dir.join(STORE_FILE)).unwrap().is_none());
    }

    /// An entry `keyring` wrote (the builds before this one) roams; reading it makes it local.
    /// Named so the desktop's CI filter runs it.
    #[cfg(windows)]
    #[test]
    #[ignore]
    fn the_os_key_store_entry_stays_on_this_machine() {
        use crate::windows_credential::is_local;
        let path = temp_dir("roaming").join(STORE_FILE);
        let entry = keystore_entry(&path).unwrap();
        entry.set_secret(&[7u8; KEY_LEN]).unwrap();
        assert!(!is_local(&entry).unwrap(), "keyring wrote it to roam");
        let read = KeyStore::Os.get(&path).unwrap().unwrap();
        assert_eq!(read.as_slice(), [7u8; KEY_LEN]);
        assert!(is_local(&entry).unwrap());

        KeyStore::Os.set(&path, &[8u8; KEY_LEN]).unwrap();
        assert!(is_local(&entry).unwrap());
        KeyStore::Os.delete(&path);
        assert!(KeyStore::Os.get(&path).unwrap().is_none());
    }
}
