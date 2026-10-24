//! The account's recovery key, made without a screen
//! (`decisions/recovery-key-backup-is-deferred-not-skipped.md`).
//!
//! The recovery public key is the account's address: invites carry it, and without it this
//! device can show no QR and no link (`decisions/invite-carries-the-account-address.md`). It used
//! to exist only after twelve words and a quiz; now it is made at the first launch of an account
//! that has none, and the phrase waits in the store for its copy. As iOS
//! `RecoveryKeyProvisioner`:
//!
//! - the phrase is in the store before the server hears of its key, so there is never a key on
//!   the server whose phrase exists nowhere; a retry uses the stored phrase, and the server
//!   accepts the same key twice;
//! - this device's address comes only from a phrase on this device, never from the server: a key
//!   the server handed out could name another account, and every invite would point there;
//! - after the copy is confirmed the phrase is erased.

use construct_core::crypto::recovery;
use zeroize::Zeroizing;

use crate::local_store::LocalStore;

/// The phrase made here, until its copy is confirmed.
const PENDING_PHRASE: &str = "recovery.pending_phrase";
/// This account's address: the recovery public key, derived from a phrase on this device.
const OWN_ADDRESS: &str = "recovery.address";
const ADDRESS_LEN: usize = 32;
const WORDS: u8 = 12;
/// How many words a copy is checked by.
pub const QUIZ_WORDS: usize = 3;

/// Where the account's recovery key stands, for this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryState {
    /// Not known yet: the server could not be asked. Tried again at the next launch.
    Unknown,
    /// The key is set and this device knows the address; the phrase waits here for its copy.
    CopyPending,
    /// The key is set and this device knows the address; no phrase is kept here.
    Ready,
    /// The account has a key this device has not seen (made on another device): the phrase
    /// entered here gives the address.
    NeedsPhrase,
}

/// What the server says about the account's key: the part of the network this needs.
pub(crate) trait RecoveryServer {
    /// Whether a key is set, and the server's fingerprint of it.
    async fn status(&self) -> Result<(bool, Option<String>), String>;
    /// Set `public_key`; `Err(true)` when another key is already set.
    async fn set_key(
        &self,
        public_key: &[u8],
        signature: &[u8],
        timestamp: i64,
    ) -> Result<(), bool>;
}

impl RecoveryServer for crate::grpc::GrpcClient {
    async fn status(&self) -> Result<(bool, Option<String>), String> {
        crate::grpc::get_recovery_status(self)
            .await
            .map(|s| (s.is_setup, s.fingerprint))
            .map_err(|e| e.to_string())
    }

    async fn set_key(
        &self,
        public_key: &[u8],
        signature: &[u8],
        timestamp: i64,
    ) -> Result<(), bool> {
        match crate::grpc::set_recovery_key(self, public_key, signature, timestamp).await {
            Ok(()) => Ok(()),
            Err(crate::grpc::GrpcError::Status { code: 6, .. }) => Err(true),
            Err(e) => {
                tracing::info!(error = %e, "recovery key upload deferred");
                Err(false)
            }
        }
    }
}

/// Make sure the account has a recovery key and this device knows its address; make one if the
/// account has none. Idempotent: run at every start.
pub(crate) async fn ensure_key(
    store: &LocalStore,
    server: &impl RecoveryServer,
    user_id: &str,
) -> RecoveryState {
    let pending = pending_phrase(store);
    let status = server.status().await;
    if let Some(stored) = own_address(store) {
        let fingerprint = match &status {
            Ok((_, fingerprint)) => fingerprint.as_deref(),
            Err(e) => {
                tracing::info!(error = %e, "recovery status unavailable");
                return RecoveryState::Unknown;
            }
        };
        match verdict(&stored, fingerprint) {
            Verdict::Confirmed => return state_with(pending.is_some()),
            Verdict::Foreign => {
                // A store outlives nothing here, but the rule is the same as on iOS: an address
                // the server does not hold for this account is never handed to anyone.
                tracing::error!("stored own address is not this account's: deleted");
                let _ = store.secure_delete(OWN_ADDRESS);
            }
            Verdict::Unconfirmed => {}
        }
    }

    // A phrase from an earlier launch whose upload got no answer goes first: the server may
    // already hold its key.
    let phrase = match pending {
        Some(phrase) => phrase,
        None => {
            match status {
                Ok((true, _)) => return RecoveryState::NeedsPhrase,
                Ok((false, _)) => {}
                Err(e) => {
                    tracing::info!(error = %e, "recovery status unavailable");
                    return RecoveryState::Unknown;
                }
            }
            let made = match recovery::generate_mnemonic(WORDS) {
                Ok(phrase) => Zeroizing::new(phrase),
                Err(e) => {
                    tracing::error!(error = %e, "recovery phrase not generated");
                    return RecoveryState::Unknown;
                }
            };
            if let Err(e) = store.secure_save(PENDING_PHRASE, made.as_bytes()) {
                tracing::error!(error = %e, "recovery phrase not stored: no key made");
                return RecoveryState::Unknown;
            }
            made
        }
    };

    let Ok(keypair) = keypair(&phrase) else {
        tracing::error!("stored recovery phrase does not derive a key: dropped");
        let _ = store.secure_delete(PENDING_PHRASE);
        return RecoveryState::Unknown;
    };
    let timestamp = now_secs();
    let message = format!("CONSTRUCT_RECOVERY_SETUP:{user_id}:{timestamp}");
    let Ok(signature) = recovery::sign_recovery_challenge(&keypair.private_key, &message) else {
        return RecoveryState::Unknown;
    };
    match server
        .set_key(&keypair.public_key, &signature, timestamp)
        .await
    {
        Ok(()) => {}
        Err(true) => {
            // Not ours, and never will be: the phrase names nothing.
            tracing::info!("another recovery key is set for the account: pending phrase dropped");
            let _ = store.secure_delete(PENDING_PHRASE);
            return RecoveryState::NeedsPhrase;
        }
        Err(false) => return RecoveryState::Unknown,
    }
    if let Err(e) = store.secure_save(OWN_ADDRESS, &keypair.public_key) {
        tracing::error!(error = %e, "own address not stored");
        return RecoveryState::Unknown;
    }
    tracing::info!("recovery key created and set; copy pending");
    RecoveryState::CopyPending
}

/// The phrase waiting for its copy, to show the person.
pub(crate) fn pending_phrase(store: &LocalStore) -> Option<Zeroizing<String>> {
    let bytes = Zeroizing::new(store.secure_load(PENDING_PHRASE).ok()??);
    String::from_utf8(bytes.to_vec()).ok().map(Zeroizing::new)
}

/// The copy is made: `answers` are words of the phrase by position (from 0), as the person
/// gives them back. All right — the phrase is erased; any wrong — nothing changes.
pub(crate) fn confirm_copy(store: &LocalStore, answers: &[(usize, String)]) -> Result<(), String> {
    let phrase = pending_phrase(store).ok_or("No recovery phrase is waiting for a copy")?;
    let words: Vec<&str> = phrase.split_whitespace().collect();
    let right = answers.len() >= QUIZ_WORDS
        && answers.iter().all(|(i, word)| {
            words
                .get(*i)
                .is_some_and(|w| w.eq_ignore_ascii_case(word.trim()))
        });
    if !right {
        return Err("Those words are not the phrase".into());
    }
    store
        .secure_delete(PENDING_PHRASE)
        .map_err(|e| format!("{e:#}"))
}

/// The phrase, entered on a device that did not make it: the address it gives is kept only if
/// the server holds the same key for this account.
pub(crate) async fn enter_phrase(
    store: &LocalStore,
    server: &impl RecoveryServer,
    phrase: &str,
) -> Result<RecoveryState, String> {
    let phrase = Zeroizing::new(normalize(phrase));
    if !recovery::validate_mnemonic(&phrase) {
        return Err("That is not a recovery phrase: check the words".into());
    }
    let keypair = keypair(&phrase)?;
    let (_, fingerprint) = server.status().await?;
    if verdict(&keypair.public_key, fingerprint.as_deref()) != Verdict::Confirmed {
        return Err("That phrase belongs to another account".into());
    }
    store
        .secure_save(OWN_ADDRESS, &keypair.public_key)
        .map_err(|e| format!("{e:#}"))?;
    Ok(state_with(pending_phrase(store).is_some()))
}

/// This account's address, as this device knows it.
pub(crate) fn own_address(store: &LocalStore) -> Option<Vec<u8>> {
    store
        .secure_load(OWN_ADDRESS)
        .ok()?
        .filter(|a| a.len() == ADDRESS_LEN)
}

fn state_with(pending: bool) -> RecoveryState {
    if pending {
        RecoveryState::CopyPending
    } else {
        RecoveryState::Ready
    }
}

fn keypair(phrase: &str) -> Result<recovery::RecoveryKeypair, String> {
    let seed = Zeroizing::new(recovery::mnemonic_to_seed(phrase).map_err(|e| e.to_string())?);
    recovery::derive_recovery_keypair(seed.as_slice()).map_err(|e| e.to_string())
}

fn normalize(phrase: &str) -> String {
    phrase
        .split_whitespace()
        .map(str::to_lowercase)
        .collect::<Vec<_>>()
        .join(" ")
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// The server's key for the account starts with this one.
    Confirmed,
    /// The server names another key.
    Foreign,
    /// The server reports no key to compare with.
    Unconfirmed,
}

/// The server formats its fingerprint as the key's leading hex in spaced groups. The comparison
/// ignores the formatting and demands at least 16 bytes, so a truncated fingerprint confirms
/// nothing. The server can make this answer "no", never "yes" for a key the phrase did not give.
fn verdict(key: &[u8], fingerprint: Option<&str>) -> Verdict {
    let Some(fingerprint) = fingerprint else {
        return Verdict::Unconfirmed;
    };
    let digits: String = fingerprint
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_lowercase();
    if digits.len() >= 32 && hex::encode(key).starts_with(&digits) {
        Verdict::Confirmed
    } else {
        Verdict::Foreign
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// A server that remembers the one key it accepted.
    #[derive(Default)]
    struct Server {
        key: RefCell<Option<Vec<u8>>>,
        down: bool,
        uploads: RefCell<usize>,
    }

    impl Server {
        fn fingerprint(&self) -> Option<String> {
            self.key.borrow().as_ref().map(|k| {
                hex::encode(&k[..16])
                    .as_bytes()
                    .chunks(4)
                    .map(|c| std::str::from_utf8(c).unwrap())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
        }
    }

    impl RecoveryServer for Server {
        async fn status(&self) -> Result<(bool, Option<String>), String> {
            if self.down {
                return Err("down".into());
            }
            Ok((self.key.borrow().is_some(), self.fingerprint()))
        }

        async fn set_key(&self, public_key: &[u8], _: &[u8], _: i64) -> Result<(), bool> {
            if self.down {
                return Err(false);
            }
            *self.uploads.borrow_mut() += 1;
            let mut key = self.key.borrow_mut();
            match key.as_ref() {
                Some(k) if k != public_key => Err(true),
                _ => {
                    *key = Some(public_key.to_vec());
                    Ok(())
                }
            }
        }
    }

    fn store() -> LocalStore {
        LocalStore::open_in_memory().unwrap()
    }

    fn run<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn a_new_account_gets_a_key_its_phrase_waits_and_the_address_is_kept() {
        let (store, server) = (store(), Server::default());
        assert_eq!(
            run(ensure_key(&store, &server, "u")),
            RecoveryState::CopyPending
        );
        let phrase = pending_phrase(&store).expect("phrase kept for the copy");
        assert_eq!(phrase.split_whitespace().count(), 12);
        let derived = keypair(&phrase).unwrap().public_key.to_vec();
        assert_eq!(server.key.borrow().as_deref(), Some(derived.as_slice()));
        assert_eq!(own_address(&store), Some(derived));
        // The next start changes nothing and uploads nothing.
        assert_eq!(
            run(ensure_key(&store, &server, "u")),
            RecoveryState::CopyPending
        );
        assert_eq!(*server.uploads.borrow(), 1);
    }

    /// The phrase is stored before the server hears of it: an upload lost on the way is retried
    /// with the same phrase, never a new one.
    #[test]
    fn an_upload_that_got_no_answer_is_retried_with_the_same_phrase() {
        let store = store();
        let down = Server {
            down: true,
            ..Default::default()
        };
        // Status works, the upload does not: emulate by a server that is down for both, after
        // the phrase is made by hand as an earlier launch would have left it.
        store
            .secure_save(
                PENDING_PHRASE,
                recovery::generate_mnemonic(12).unwrap().as_bytes(),
            )
            .unwrap();
        let before = pending_phrase(&store).unwrap().to_string();
        assert_eq!(run(ensure_key(&store, &down, "u")), RecoveryState::Unknown);
        assert_eq!(pending_phrase(&store).unwrap().as_str(), before);

        let up = Server::default();
        assert_eq!(
            run(ensure_key(&store, &up, "u")),
            RecoveryState::CopyPending
        );
        assert_eq!(
            up.key.borrow().as_deref(),
            Some(keypair(&before).unwrap().public_key.as_slice())
        );
    }

    #[test]
    fn an_account_with_a_key_made_elsewhere_asks_for_the_phrase() {
        let (store, server) = (store(), Server::default());
        let phrase = recovery::generate_mnemonic(12).unwrap();
        *server.key.borrow_mut() = Some(keypair(&phrase).unwrap().public_key.to_vec());

        assert_eq!(
            run(ensure_key(&store, &server, "u")),
            RecoveryState::NeedsPhrase
        );
        assert!(
            pending_phrase(&store).is_none(),
            "no phrase made for a key set elsewhere"
        );
        assert_eq!(
            *server.uploads.borrow(),
            0,
            "nothing offered for a key set elsewhere"
        );
        assert!(own_address(&store).is_none());

        let other = recovery::generate_mnemonic(12).unwrap();
        assert!(run(enter_phrase(&store, &server, &other)).is_err());
        assert!(own_address(&store).is_none());
        let shouted = phrase.to_uppercase().replace(' ', "  ");
        assert_eq!(
            run(enter_phrase(&store, &server, &shouted)),
            Ok(RecoveryState::Ready)
        );
        assert!(own_address(&store).is_some());
    }

    /// A pending phrase whose key lost to another one names nothing: dropped.
    #[test]
    fn a_pending_phrase_refused_for_another_key_is_dropped() {
        let (store, server) = (store(), Server::default());
        *server.key.borrow_mut() = Some(vec![9u8; 32]);
        store
            .secure_save(
                PENDING_PHRASE,
                recovery::generate_mnemonic(12).unwrap().as_bytes(),
            )
            .unwrap();
        assert_eq!(
            run(ensure_key(&store, &server, "u")),
            RecoveryState::NeedsPhrase
        );
        assert!(pending_phrase(&store).is_none());
        assert!(own_address(&store).is_none());
    }

    #[test]
    fn an_address_the_server_does_not_hold_is_deleted() {
        let (store, server) = (store(), Server::default());
        store.secure_save(OWN_ADDRESS, &[1u8; 32]).unwrap();
        *server.key.borrow_mut() = Some(vec![2u8; 32]);
        assert_eq!(
            run(ensure_key(&store, &server, "u")),
            RecoveryState::NeedsPhrase
        );
        assert!(own_address(&store).is_none());
    }

    #[test]
    fn the_copy_is_confirmed_by_three_right_words_then_the_phrase_is_erased() {
        let (store, server) = (store(), Server::default());
        run(ensure_key(&store, &server, "u"));
        let words: Vec<String> = pending_phrase(&store)
            .unwrap()
            .split_whitespace()
            .map(String::from)
            .collect();
        let wrong = vec![
            (0, words[0].clone()),
            (5, words[5].clone()),
            (11, "nope".into()),
        ];
        assert!(confirm_copy(&store, &wrong).is_err());
        assert!(
            confirm_copy(&store, &wrong[..2]).is_err(),
            "two words are not enough"
        );
        assert!(pending_phrase(&store).is_some());

        let right = vec![
            (0, words[0].to_uppercase()),
            (5, format!(" {} ", words[5])),
            (11, words[11].clone()),
        ];
        assert!(confirm_copy(&store, &right).is_ok());
        assert!(pending_phrase(&store).is_none());
        assert_eq!(run(ensure_key(&store, &server, "u")), RecoveryState::Ready);
    }

    #[test]
    fn a_short_or_other_fingerprint_confirms_nothing() {
        let key = [0xabu8; 32];
        assert_eq!(
            verdict(&key, Some("abab abab abab abab abab abab abab abab")),
            Verdict::Confirmed
        );
        assert_eq!(verdict(&key, Some("abab abab")), Verdict::Foreign);
        assert_eq!(
            verdict(&key, Some("cdcd cdcd cdcd cdcd cdcd cdcd cdcd cdcd")),
            Verdict::Foreign
        );
        assert_eq!(verdict(&key, None), Verdict::Unconfirmed);
    }
}
