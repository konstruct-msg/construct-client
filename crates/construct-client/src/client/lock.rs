//! The app lock (iOS Security → PIN code, lock delay): a code asked for before the window shows
//! anything once it has been away for the chosen time.
//!
//! It is a lock on the screen, not on the data: the store stays open behind it, as on iOS. The
//! code is kept as an Argon2id hash with its own salt; a front end hands codes in and learns only
//! whether one matched.

use std::time::{Duration, Instant};

use rand::RngCore;
use zeroize::Zeroizing;

use super::{Client, ClientEvent};

const PREF_APP_LOCK: &str = "pref.app_lock";
/// Shortest code taken.
pub const MIN_CODE_LEN: usize = 4;
/// Wrong codes in a row before the next is refused for a while.
const FREE_TRIES: u32 = 5;
const LOCKOUT: Duration = Duration::from_secs(30);

/// Whether a code is set, and how long the window may be away before it is asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppLock {
    pub enabled: bool,
    /// 0: as soon as the window loses the focus.
    pub delay_secs: u32,
}

/// What is kept: the delay, a salt and the code's hash.
struct Stored {
    delay_secs: u32,
    salt: [u8; 16],
    hash: [u8; 32],
}

impl Stored {
    fn encode(&self) -> Vec<u8> {
        let mut v = self.delay_secs.to_le_bytes().to_vec();
        v.extend_from_slice(&self.salt);
        v.extend_from_slice(&self.hash);
        v
    }

    fn decode(v: &[u8]) -> Option<Self> {
        (v.len() == 52).then(|| Self {
            delay_secs: u32::from_le_bytes(v[..4].try_into().unwrap()),
            salt: v[4..20].try_into().unwrap(),
            hash: v[20..52].try_into().unwrap(),
        })
    }
}

fn hash(code: &str, salt: &[u8]) -> Option<[u8; 32]> {
    crate::config::derive_master_key(code.as_bytes(), salt)
        .ok()
        .map(|k| *k)
}

/// Equal without telling, by its timing, how much of it was.
fn same(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Wrong codes so far and when the last came: past [`FREE_TRIES`], one try per [`LOCKOUT`].
#[derive(Debug, Default)]
pub(super) struct Tries {
    wrong: u32,
    last: Option<Instant>,
}

impl Tries {
    fn wait(&self, now: Instant) -> Option<Duration> {
        let last = self.last?;
        (self.wrong >= FREE_TRIES)
            .then(|| LOCKOUT.saturating_sub(now.duration_since(last)))
            .filter(|d| !d.is_zero())
    }
}

impl Client {
    fn stored_lock(&self) -> Option<Stored> {
        let v = self.store.as_ref()?.secure_load(PREF_APP_LOCK).ok()??;
        Stored::decode(&v)
    }

    pub(super) fn app_lock(&self) -> AppLock {
        self.stored_lock().map_or(
            AppLock {
                enabled: false,
                delay_secs: 0,
            },
            |s| AppLock {
                enabled: true,
                delay_secs: s.delay_secs,
            },
        )
    }

    pub(super) fn emit_app_lock(&self) {
        self.emit(ClientEvent::AppLock(self.app_lock()));
    }

    /// Set, change or remove the code, or only the delay (`code: None` with a code set). Changing
    /// or removing a code takes the current one.
    pub(super) fn set_app_lock(
        &mut self,
        current: Option<Zeroizing<String>>,
        code: Option<Zeroizing<String>>,
        remove: bool,
        delay_secs: u32,
    ) {
        let Some(store) = self.store.clone() else {
            return;
        };
        let stored = self.stored_lock();
        let refuse = |this: &Self, why: &str| this.emit(ClientEvent::AppLockRefused(why.into()));
        if let Some(stored) = &stored
            && (remove || code.is_some())
        {
            if let Some(wait) = self.lock_tries.wait(Instant::now()) {
                return refuse(
                    self,
                    &format!("Too many wrong codes: wait {} s", wait.as_secs() + 1),
                );
            }
            let matches = current
                .as_deref()
                .and_then(|c| hash(c, &stored.salt))
                .is_some_and(|h| same(&h, &stored.hash));
            if !matches {
                self.note_wrong();
                return refuse(self, "The current code is wrong");
            }
            self.lock_tries = Tries::default();
        }
        let saved = if remove {
            store.secure_delete(PREF_APP_LOCK)
        } else {
            let (salt, hash) = match (&code, &stored) {
                (Some(code), _) => {
                    if code.chars().count() < MIN_CODE_LEN {
                        return refuse(self, "A code has at least 4 characters");
                    }
                    let mut salt = [0u8; 16];
                    rand::rngs::OsRng.fill_bytes(&mut salt);
                    match hash(code, &salt) {
                        Some(h) => (salt, h),
                        None => return refuse(self, "The code could not be kept"),
                    }
                }
                (None, Some(stored)) => (stored.salt, stored.hash),
                (None, None) => return refuse(self, "Choose a code first"),
            };
            store.secure_save(
                PREF_APP_LOCK,
                &Stored {
                    delay_secs,
                    salt,
                    hash,
                }
                .encode(),
            )
        };
        if let Err(e) = saved {
            return refuse(self, &format!("Not changed: {e}"));
        }
        self.emit_app_lock();
    }

    /// A code handed in at the lock screen.
    pub(super) fn unlock_app(&mut self, code: Zeroizing<String>) {
        let Some(stored) = self.stored_lock() else {
            return self.emit(ClientEvent::AppUnlocked(Ok(())));
        };
        if let Some(wait) = self.lock_tries.wait(Instant::now()) {
            return self.emit(ClientEvent::AppUnlocked(Err(format!(
                "Too many wrong codes: wait {} s",
                wait.as_secs() + 1
            ))));
        }
        let ok = hash(&code, &stored.salt).is_some_and(|h| same(&h, &stored.hash));
        if ok {
            self.lock_tries = Tries::default();
            self.emit(ClientEvent::AppUnlocked(Ok(())));
        } else {
            self.note_wrong();
            self.emit(ClientEvent::AppUnlocked(Err("Wrong code".into())));
        }
    }

    fn note_wrong(&mut self) {
        self.lock_tries.wrong += 1;
        self.lock_tries.last = Some(Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_kept_code_reads_back_and_matches_only_itself() {
        let salt = [3u8; 16];
        let stored = Stored {
            delay_secs: 60,
            salt,
            hash: hash("2468", &salt).unwrap(),
        };
        let back = Stored::decode(&stored.encode()).unwrap();
        assert_eq!(back.delay_secs, 60);
        assert!(same(&hash("2468", &back.salt).unwrap(), &back.hash));
        assert!(!same(&hash("2469", &back.salt).unwrap(), &back.hash));
        assert!(Stored::decode(&[0u8; 51]).is_none());
    }

    #[test]
    fn past_five_wrong_codes_the_next_waits() {
        let now = Instant::now();
        let mut tries = Tries::default();
        for _ in 0..FREE_TRIES - 1 {
            tries.wrong += 1;
            tries.last = Some(now);
        }
        assert_eq!(tries.wait(now), None, "four wrong codes cost nothing");
        tries.wrong += 1;
        assert!(tries.wait(now + Duration::from_secs(1)).is_some());
        assert_eq!(tries.wait(now + LOCKOUT), None, "and the wait ends");
    }
}
