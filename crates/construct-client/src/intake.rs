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
//! The rule two clients must compute alike — which of two keys to keep, a new generation — is the
//! core's (`construct_core::intake`); what is here is when to ask and what to keep.

use construct_core::intake::{IntakeKeyState, intake_epoch, intake_tag};

/// Epochs published from today: a device silent for a week still receives tag-paid traffic.
pub const WINDOW: u64 = 7;
/// How often a running process asks whether to publish; the RPC goes once an epoch.
pub const RECHECK: std::time::Duration = std::time::Duration::from_secs(3600);

const OWN_KEY: &str = "intake_own_key";
const PUBLISHED_EPOCH: &str = "intake_published_epoch";
const SENT_TO: &str = "intake_sent_to";

/// A key as kept: the generation (big-endian) then the 32-byte key, as iOS keeps it
/// (`IntakeKeyRecord`); a bare 32-byte key is generation 0, a per-device key from before.
pub fn encode(state: &IntakeKeyState) -> Vec<u8> {
    let mut out = state.generation.to_be_bytes().to_vec();
    out.extend_from_slice(&state.key);
    out
}

pub fn decode(bytes: &[u8]) -> Option<IntakeKeyState> {
    match bytes.len() {
        32 => Some(IntakeKeyState {
            generation: 0,
            key: bytes.to_vec(),
        }),
        36 => Some(IntakeKeyState {
            generation: u32::from_be_bytes(bytes[..4].try_into().ok()?),
            key: bytes[4..].to_vec(),
        }),
        _ => None,
    }
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
    if let Some(held) = held
        && held.generation > 0
    {
        return Next::Use(held.clone());
    }
    let live = server_generation > 0 && server_live;
    match held {
        Some(held) if server_generation == 0 => Next::Promote(IntakeKeyState {
            generation: 1,
            key: held.key.clone(),
        }),
        _ if live => Next::Wait,
        _ => Next::Mint {
            above: server_generation,
        },
    }
}

/// Whether to publish in `current`, having last published in `last`. A clock that went back is
/// no reason to skip.
pub fn should_publish(last: Option<u64>, current: u64) -> bool {
    last != Some(current)
}

/// The tags of `key` for `account`, from `epoch` on, as `PublishIntakeTags` takes them.
pub fn window(key: &IntakeKeyState, account: &str, epoch: u64) -> Vec<(u64, Vec<u8>)> {
    (epoch..epoch + WINDOW)
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
        let _ = self.0.secure_delete(PUBLISHED_EPOCH);
        true
    }

    pub fn published_epoch(&self) -> Option<u64> {
        let bytes = self.0.secure_load(PUBLISHED_EPOCH).ok()??;
        Some(u64::from_be_bytes(bytes.try_into().ok()?))
    }

    pub fn set_published_epoch(&self, epoch: u64) {
        let _ = self.0.secure_save(PUBLISHED_EPOCH, &epoch.to_be_bytes());
    }

    /// Devices handed our key since it last changed.
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

/// Our key as a contact card (content type 27), for our own devices: the key and its
/// generation (iOS `ContactCardPayload`; no address — they are us).
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
