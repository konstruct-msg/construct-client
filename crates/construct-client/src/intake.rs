//! The account's intake key on this device (construct-docs
//! decisions/intake-key-is-the-accounts-not-the-devices.md; iOS `IntakeCredentialService`).
//!
//! A contact that holds the key presents a tag of it with each sealed message to us, and owes no
//! token for it. The key is the account's, one generation at a time: this device publishes the
//! tags of the generation it holds, a window of seven days from today, once a day — at every
//! stream connection and on an hourly recheck, so a process that runs for weeks keeps its window
//! full. It makes a key only when the account has none alive, and otherwise waits for one from its
//! own devices, which hand it over as a contact card inside SENDER_SYNC.
//!
//! Each contact's key comes the same way, as their card, and is kept by their account: our
//! envelopes to them carry its tag for the day, sealed to the server, instead of a token. Our card
//! goes to each of their devices once (when we first hear from or write to it), and again after
//! our key changes.
//!
//! The rules every client must compute alike are the core's: which of two keys to keep and a new
//! generation (`construct_core::intake`), and since 2026-11-12 the decisions — when to publish,
//! whether the server holds our key, what to do with our own, a rotation's schedule, the verdict,
//! the key record (construct-rules `intake`, todo 300). What is here is when to ask and what to keep.

use construct_core::intake::{IntakeKeyState, intake_epoch, intake_tag};

use construct_core::rule_state::intake as rule;
pub use construct_core::rule_state::intake::Published;

/// How often a running process asks whether to publish; the RPC goes once an epoch, key and
/// account (the core's `RECHECK_MS`).
pub const RECHECK: std::time::Duration = std::time::Duration::from_millis(rule::RECHECK_MS);

const OWN_KEY: &str = "intake_own_key";
/// What the last publish covered: account, epoch and key, the core's CFE (`IntakePublished`).
const PUBLISHED: &str = "intake_published.v2";
/// Until 2026-11-12 the epoch alone. Not read — it cannot say which key — and dropped: one publish.
const LEGACY_PUBLISHED_EPOCH: &str = "intake_published_epoch";
const SENT_TO: &str = "intake_sent_to";
const PEER_KEY: &str = "intake_peer_";

/// A key as kept: the generation (big-endian) then the 32-byte key, as iOS keeps it
/// (`IntakeKeyRecord`); a bare 32-byte key is generation 0, a per-device key from before.
pub fn encode(state: &IntakeKeyState) -> Vec<u8> {
    rule::encode_key_record(state.generation, &state.key)
}

pub fn decode(bytes: &[u8]) -> Option<IntakeKeyState> {
    rule::decode_key_record(bytes).map(|(generation, key)| IntakeKeyState { generation, key })
}

/// What reading our key from the store said.
#[derive(Debug, PartialEq, Eq)]
pub enum Held {
    Key(IntakeKeyState),
    /// Definitely not there, or there and damaged.
    Absent,
    /// Could not be read. It may well be there: nothing is made in its place.
    Unreadable,
}

/// What to do about our key, given what this device holds and what the server says of the
/// account (`GetIntakeState`). Named by state, never by time (iOS `IntakeOwnKey.next`).
#[derive(Debug, PartialEq, Eq)]
pub enum Next {
    Use(IntakeKeyState),
    /// Our per-device key from before generations becomes the account's generation 1: the
    /// contacts that hold it stay valid. Only while the account has no generation.
    Promote(IntakeKeyState),
    /// No live key anywhere on the account: a new one above what the server saw.
    Mint {
        above: u32,
    },
    /// The account has a live key this device lacks: it is due from one of our devices.
    Wait,
}

pub fn next(held: Option<&IntakeKeyState>, server_generation: u32, server_live: bool) -> Next {
    // The core's decision (construct-rules `intake::own_key`); this attaches the held key.
    match rule::own_key(held.map(|k| k.generation), server_generation, server_live) {
        rule::OwnKey::Use => held.map_or(
            Next::Mint {
                above: server_generation,
            },
            |k| Next::Use(k.clone()),
        ),
        rule::OwnKey::Promote => held.map_or(
            Next::Mint {
                above: server_generation,
            },
            |k| {
                Next::Promote(IntakeKeyState {
                    generation: 1,
                    key: k.key.clone(),
                })
            },
        ),
        rule::OwnKey::Mint { above } => Next::Mint { above },
        rule::OwnKey::Wait => Next::Wait,
    }
}

/// What a publish of `key` for `account` in `epoch` covers.
pub fn marker(key: &IntakeKeyState, account: &str, epoch: u64) -> Published {
    Published {
        account_id: account.to_string(),
        epoch,
        key_id: rule::key_id(&key.key),
    }
}

/// Whether to publish: once per epoch per account and key (the core's rule; until 2026-11-12 the
/// epoch only, the marker cleared when the key changed).
pub fn should_publish(last: Option<&Published>, due: &Published) -> bool {
    rule::should_publish(last, due)
}

/// Whether the server holds the tags of `key` for `account` in `current`: a card names only such
/// a key (iOS `IntakePublishing.serverHolds`).
pub fn server_holds(
    last: Option<&Published>,
    key: &IntakeKeyState,
    account: &str,
    current: u64,
) -> bool {
    rule::server_holds(last, account, &rule::key_id(&key.key), current)
}

/// The generation a rotation mints above: past both ours and the server's (None: not asked).
pub fn rotation_floor(held: Option<&IntakeKeyState>, server: Option<u32>) -> u32 {
    rule::mint_above(held.map(|k| k.generation), server)
}

/// The tags of `key` for `account`, from `epoch` on, as `PublishIntakeTags` takes them.
pub fn window(key: &IntakeKeyState, account: &str, epoch: u64) -> Vec<(u64, Vec<u8>)> {
    rule::window(epoch)
        .into_iter()
        .filter_map(|e| intake_tag(&key.key, account, e).ok().map(|tag| (e, tag)))
        .collect()
}

pub fn epoch_now() -> u64 {
    intake_epoch(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
}

/// The account's key as this device keeps it, and who has been handed it.
pub struct Store<'a>(pub &'a crate::local_store::LocalStore);

impl Store<'_> {
    pub fn own(&self) -> Held {
        match self.0.secure_load(OWN_KEY) {
            Ok(Some(bytes)) => decode(&bytes).map_or(Held::Absent, Held::Key),
            Ok(None) => Held::Absent,
            Err(e) => {
                tracing::warn!(error = %e, "intake key unreadable");
                Held::Unreadable
            }
        }
    }

    /// Make `state` our key. Every copy our devices and contacts hold of the one before is stale:
    /// who was handed it and when it was published are forgotten, so the new one goes out now.
    pub fn adopt(&self, state: &IntakeKeyState) -> bool {
        if let Err(e) = self.0.secure_save(OWN_KEY, &encode(state)) {
            tracing::error!(error = %e, "intake key not kept — not used");
            return false;
        }
        let _ = self.0.secure_delete(SENT_TO);
        let _ = self.0.secure_delete(PUBLISHED);
        true
    }

    /// What the last publish covered; the epoch-only marker from before is dropped on the way.
    pub fn published(&self) -> Option<Published> {
        let _ = self.0.secure_delete(LEGACY_PUBLISHED_EPOCH);
        construct_core::rule_state::decode_intake_published(&self.0.secure_load(PUBLISHED).ok()??)
    }

    /// Mark `published` as published for `account` in `epoch` — only while it is still our key: a
    /// publish that lands after a newer key was adopted says nothing of the newer one. Whether it
    /// was marked.
    pub fn mark_published(&self, published: &IntakeKeyState, account: &str, epoch: u64) -> bool {
        if self.own() != Held::Key(published.clone()) {
            return false;
        }
        match construct_core::rule_state::encode_intake_published(&marker(
            published, account, epoch,
        )) {
            Ok(bytes) => self.0.secure_save(PUBLISHED, &bytes).is_ok(),
            Err(e) => {
                tracing::warn!(error = ?e, "intake publish marker not encoded");
                false
            }
        }
    }

    /// Our key as a card may name it for `account` in `epoch`: one of a generation, whose tags the
    /// server holds.
    pub fn card_key(&self, account: &str, epoch: u64) -> Option<IntakeKeyState> {
        match self.own() {
            Held::Key(key)
                if key.generation > 0
                    && server_holds(self.published().as_ref(), &key, account, epoch) =>
            {
                Some(key)
            }
            _ => None,
        }
    }

    /// The key `account` accepts, as their card gave it.
    pub fn peer(&self, account: &str) -> Option<IntakeKeyState> {
        decode(&self.0.secure_load(&peer_slot(account)).ok()??)
    }

    /// `account` handed us their key: kept when its generation is above the one held
    /// (`intake_offer`) — a late card, or an old build's per-device key, does not replace the
    /// account's current one. Whether it was kept.
    pub fn offer_peer(&self, account: &str, offered: &IntakeKeyState) -> bool {
        use construct_core::intake::{IntakeOffer, intake_offer};
        match intake_offer(self.peer(account).as_ref(), offered) {
            Ok(IntakeOffer::Adopt) => {
                match self.0.secure_save(&peer_slot(account), &encode(offered)) {
                    Ok(()) => true,
                    Err(e) => {
                        tracing::warn!(error = %e, "contact's intake key not kept");
                        false
                    }
                }
            }
            Ok(IntakeOffer::Keep) => false,
            Err(e) => {
                tracing::warn!(error = ?e, "contact sent a malformed intake key");
                false
            }
        }
    }

    /// Devices — ours and our contacts' — handed our key since it last changed.
    pub fn sent_to(&self) -> Vec<String> {
        self.0
            .secure_load(SENT_TO)
            .ok()
            .flatten()
            .map(|b| {
                String::from_utf8_lossy(&b)
                    .lines()
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn mark_sent(&self, devices: &[String]) {
        let mut all = self.sent_to();
        for d in devices {
            if !all.contains(d) {
                all.push(d.clone());
            }
        }
        let _ = self.0.secure_save(SENT_TO, all.join("\n").as_bytes());
    }
}

fn peer_slot(account: &str) -> String {
    format!("{PEER_KEY}{}", account.trim().to_lowercase())
}

/// Which contacts' keys the server did not accept today (`IntakeVerdict::NotAccepted`, or a Privacy
/// Pass refusal of an envelope that presented one): not presented again until the epoch rolls,
/// and their envelopes pay meanwhile. Not dropped — the usual cause is a device of theirs whose
/// window lapsed while it was off, and it works again once that device publishes; a dropped key
/// would never come back, since they have no reason to send their card again. A card of a newer
/// generation from them lifts it at once (the refusal was the old key after their rotation); a
/// card of the same or an older one does not. In memory, as the cost of forgetting is one more
/// refusal.
#[derive(Default)]
pub struct Suspended(std::collections::HashMap<String, u64>);

impl Suspended {
    pub fn suspend(&mut self, account: &str, epoch: u64) {
        self.0.retain(|_, e| *e >= epoch);
        self.0.insert(account.to_lowercase(), epoch);
    }

    pub fn is_suspended(&self, account: &str, epoch: u64) -> bool {
        self.0.get(&account.to_lowercase()) == Some(&epoch)
    }

    /// iOS's `liftSuspension(for:)`: that account only.
    pub fn lift(&mut self, account: &str) {
        self.0.remove(&account.to_lowercase());
    }
}

/// What the server's verdict on a tag we presented asks of us: only "not accepted" suspends.
/// "Unchecked" is the server failing to look (its tag store down) — acting on it would make every
/// sender drop working keys during an outage.
pub fn suspends(verdict: i32) -> bool {
    rule::verdict_suspends_key(verdict)
}

/// The tag to present on an envelope to `account` in `epoch`, sealed to the server's `server_key`
/// with the box tokens use: `SealedInner` is plaintext to the relay, and a tag in the clear is one
/// any relay could spend on them until the epoch rolls. None — the envelope pays — when we hold
/// no key for them, or cannot derive or seal.
pub fn sealed_tag(
    key: &IntakeKeyState,
    account: &str,
    epoch: u64,
    server_key: Vec<u8>,
) -> Option<Vec<u8>> {
    let tag = intake_tag(&key.key, account, epoch).ok()?;
    construct_core::crypto::privacy_pass::pp_seal_token_bytes(tag, server_key).ok()
}

/// Our key as a contact card (content type 27): the key and its generation (iOS
/// `ContactCardPayload`). No account address — this client does not hold one yet; iOS sends the
/// key alone in that case too.
pub fn own_card(state: &IntakeKeyState) -> Vec<u8> {
    use prost::Message;
    crate::proto::core::v1::ContactCard {
        intake_key: state.key.clone().into(),
        intake_generation: state.generation,
        ..Default::default()
    }
    .encode_to_vec()
}

/// The key a contact card carries.
pub fn card_key(payload: &[u8]) -> Option<IntakeKeyState> {
    use prost::Message;
    let card = crate::proto::core::v1::ContactCard::decode(payload).ok()?;
    (!card.intake_key.is_empty()).then(|| IntakeKeyState {
        generation: card.intake_generation,
        key: card.intake_key.to_vec(),
    })
}

#[cfg(test)]
mod tests;
