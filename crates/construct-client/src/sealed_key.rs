//! The store key under a launch passphrase: what the OS key store holds instead of the bare key.
//!
//! The store key stays the random one the database was made with; only its entry in the OS key
//! store changes, in one write, so turning the passphrase on, changing it or removing it rewrites
//! no database and has no half-way state. Opening then takes both: the entry (a copied directory
//! alone is noise, whatever the passphrase) and the passphrase (the entry alone is noise too).
//! Telegram Desktop wraps its local key the same way (decisions/launch-passphrase.md).
//!
//! Not CFE: it is read before there is a store, and the entry next to it is bare bytes as well.
//!
//! `KNS1` ‖ salt (16) ‖ nonce (12) ‖ AES-256-GCM(Argon2id(passphrase, salt), store key) (32 + 16),
//! with `KNS1` as associated data. The magic names the KDF cost too: a new cost is a new magic.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Result, anyhow, bail};
use construct_store::KEY_LEN;
use rand::RngCore;
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"KNS1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const SEALED_LEN: usize = MAGIC.len() + SALT_LEN + NONCE_LEN + KEY_LEN + TAG_LEN;

/// Shortest launch passphrase taken. Whoever copies the entry guesses offline.
pub const MIN_PASSPHRASE_LEN: usize = 8;

/// What an entry of the OS key store is.
pub(crate) enum Entry {
    Bare(Zeroizing<Vec<u8>>),
    Sealed(Vec<u8>),
}

/// Tell the two apart by their whole shape; anything else is refused, never guessed at.
pub(crate) fn read(entry: Zeroizing<Vec<u8>>) -> Result<Entry> {
    if entry.len() == KEY_LEN {
        Ok(Entry::Bare(entry))
    } else if entry.len() == SEALED_LEN && entry.starts_with(MAGIC) {
        Ok(Entry::Sealed(entry.to_vec()))
    } else {
        bail!("the key in the OS key store is not one this version can read")
    }
}

pub(crate) fn seal(key: &[u8], passphrase: &[u8]) -> Result<Vec<u8>> {
    let mut sealed = MAGIC.to_vec();
    let mut random = [0u8; SALT_LEN + NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut random);
    sealed.extend_from_slice(&random);
    let (salt, nonce) = random.split_at(SALT_LEN);
    let sealing = crate::config::derive_master_key(passphrase, salt)?;
    let boxed = Aes256Gcm::new(sealing.as_ref().into())
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: key,
                aad: MAGIC,
            },
        )
        .map_err(|_| anyhow!("the store key could not be sealed"))?;
    sealed.extend_from_slice(&boxed);
    Ok(sealed)
}

/// `None`: the passphrase is not the one (or the entry was tampered with — the tag cannot say
/// which).
pub(crate) fn open(sealed: &[u8], passphrase: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
    if sealed.len() != SEALED_LEN || !sealed.starts_with(MAGIC) {
        bail!("not a sealed store key");
    }
    let (salt, rest) = sealed[MAGIC.len()..].split_at(SALT_LEN);
    let (nonce, boxed) = rest.split_at(NONCE_LEN);
    let sealing = crate::config::derive_master_key(passphrase, salt)?;
    Ok(Aes256Gcm::new(sealing.as_ref().into())
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: boxed,
                aad: MAGIC,
            },
        )
        .ok()
        .map(Zeroizing::new))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; KEY_LEN] = [7; KEY_LEN];

    #[test]
    fn a_sealed_key_opens_with_its_passphrase_only() {
        let sealed = seal(&KEY, b"correct horse").unwrap();
        assert!(!sealed.windows(KEY_LEN).any(|w| w == KEY));
        let opened = open(&sealed, b"correct horse").unwrap().unwrap();
        assert_eq!(opened.as_slice(), KEY);
        assert!(open(&sealed, b"wrong horse").unwrap().is_none());
    }

    #[test]
    fn a_changed_byte_does_not_open() {
        let sealed = seal(&KEY, b"correct horse").unwrap();
        for at in [MAGIC.len(), MAGIC.len() + SALT_LEN, SEALED_LEN - 1] {
            let mut changed = sealed.clone();
            changed[at] ^= 1;
            assert!(open(&changed, b"correct horse").unwrap().is_none(), "{at}");
        }
    }

    #[test]
    fn two_sealings_of_one_key_share_nothing() {
        let a = seal(&KEY, b"correct horse").unwrap();
        let b = seal(&KEY, b"correct horse").unwrap();
        assert_ne!(a[MAGIC.len()..], b[MAGIC.len()..]);
        let salt = MAGIC.len()..MAGIC.len() + SALT_LEN;
        assert_ne!(a[salt.clone()], b[salt]);
    }

    /// A sealed entry must never be handed to SQLCipher as a key, nor a bare one be unsealed.
    #[test]
    fn an_entry_is_read_by_its_whole_shape() {
        let sealed = seal(&KEY, b"correct horse").unwrap();
        assert!(matches!(
            read(Zeroizing::new(sealed.clone())).unwrap(),
            Entry::Sealed(_)
        ));
        assert!(matches!(
            read(Zeroizing::new(KEY.to_vec())).unwrap(),
            Entry::Bare(_)
        ));
        let mut other = sealed.clone();
        other[3] = b'9';
        assert!(read(Zeroizing::new(other)).is_err(), "a newer format");
        assert!(read(Zeroizing::new(sealed[..40].to_vec())).is_err());
    }
}
