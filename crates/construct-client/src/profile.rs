//! A profile a person shares with a contact: the name they chose and their avatar, sent inside
//! the ciphertext as content type 29 (`ProfileShare`), never to the server.
//!
//! The rules are iOS's (`ProfileShare.swift`, `ProfileSharingManager`, `ProfileShareViewModel`)
//! and the conformance vectors' (`construct-protos/conformance/knst_profile_share.json`,
//! decisions/profile-share-is-a-typed-versioned-state.md):
//! - a profile is the sender's whole state at a version, `edited_at_ms`; one not strictly newer
//!   than the one held is ignored, so a resend or a reordered queue never puts an older one back;
//! - it is applied only onto a person already held: sending to us does not make a contact;
//! - the avatar is set (download it), removed (clear it) or unchanged (absent, or a key that is
//!   not 32 bytes: keep what is held);
//! - a generated name is no name: it is never sent, and never taken as one.
//!
//! An avatar goes out as a JPEG padded with zeros to one size, uploaded once per contact, so the
//! copies sent to different people cannot be matched by their length or their media id
//! (`AvatarPadding`).

use prost::Message;

use crate::proto::core::v1::{AvatarRef as AvatarRefProto, ProfileShare as ProfileShareProto};

/// Every avatar on the wire is this long, or the next multiple (iOS `maxAvatarFileSize`).
pub const AVATAR_PADDED_LEN: usize = 200 * 1024;
/// The longest name iOS lets a person choose (`maxDisplayNameCharacters`).
pub const MAX_DISPLAY_NAME_CHARS: usize = 50;
/// The media store deletes everything after seven days; an avatar announced longer ago is not
/// worth asking for (iOS `pendingAvatarLifetime`).
pub const PENDING_AVATAR_LIFETIME_MS: i64 = 7 * 24 * 3600 * 1000;
const MEDIA_KEY_LEN: usize = 32;

/// Where an avatar is on the media server and the key that opens it.
#[derive(Clone, PartialEq, Eq)]
pub struct AvatarRef {
    pub media_id: String,
    pub media_url: String,
    pub media_key: Vec<u8>,
    pub mime_type: String,
}

impl std::fmt::Debug for AvatarRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AvatarRef")
            .field("media_id", &self.media_id)
            .finish_non_exhaustive()
    }
}

impl AvatarRef {
    fn from_proto(p: AvatarRefProto) -> Option<Self> {
        (p.media_key.len() == MEDIA_KEY_LEN).then(|| Self {
            media_id: p.media_id,
            media_url: p.media_url,
            media_key: p.media_key.to_vec(),
            mime_type: p.mime_type,
        })
    }

    fn to_proto(&self) -> AvatarRefProto {
        AvatarRefProto {
            media_id: self.media_id.clone(),
            media_url: self.media_url.clone(),
            media_key: self.media_key.clone().into(),
            mime_type: self.mime_type.clone(),
        }
    }

    /// As the store keeps a pending avatar: the `AvatarRef` bytes, as iOS keeps it.
    pub fn stored(&self) -> Vec<u8> {
        self.to_proto().encode_to_vec()
    }

    pub fn from_stored(bytes: &[u8]) -> Option<Self> {
        Self::from_proto(AvatarRefProto::decode(bytes).ok()?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Avatar {
    Set(AvatarRef),
    Removed,
    Unchanged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileShare {
    pub display_name: String,
    pub edited_at_ms: u64,
    pub avatar: Avatar,
}

/// What a receiver does with the avatar it holds once a profile is applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AvatarAction {
    Download(AvatarRef),
    Clear,
    Keep,
}

impl ProfileShare {
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        use crate::proto::core::v1::profile_share::Avatar as A;
        let p = ProfileShareProto::decode(bytes).ok()?;
        let avatar = match p.avatar {
            Some(A::AvatarSet(r)) => {
                AvatarRef::from_proto(r).map_or(Avatar::Unchanged, Avatar::Set)
            }
            Some(A::AvatarRemoved(true)) => Avatar::Removed,
            _ => Avatar::Unchanged,
        };
        Some(Self {
            display_name: p.display_name,
            edited_at_ms: p.edited_at_ms,
            avatar,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        use crate::proto::core::v1::profile_share::Avatar as A;
        ProfileShareProto {
            display_name: self.display_name.clone(),
            edited_at_ms: self.edited_at_ms,
            avatar: match &self.avatar {
                Avatar::Set(r) => Some(A::AvatarSet(r.to_proto())),
                Avatar::Removed => Some(A::AvatarRemoved(true)),
                Avatar::Unchanged => None,
            },
        }
        .encode_to_vec()
    }

    /// The name the sender chose, or none: blank, or only the name generated from their id.
    pub fn chosen_name(&self, sender: &str) -> Option<String> {
        let name = self.display_name.trim();
        (!name.is_empty() && !crate::names::is_generated(name, sender)).then(|| name.to_owned())
    }

    /// Whether to apply this over the profile held (`held_edited_at_ms`, 0 when none), and what
    /// then happens to the avatar. `None`: ignore it whole.
    pub fn decision(&self, held_edited_at_ms: i64) -> Option<AvatarAction> {
        let newer = held_edited_at_ms <= 0 || self.edited_at_ms > held_edited_at_ms as u64;
        newer.then(|| match &self.avatar {
            Avatar::Set(r) => AvatarAction::Download(r.clone()),
            Avatar::Removed => AvatarAction::Clear,
            Avatar::Unchanged => AvatarAction::Keep,
        })
    }
}

/// Fetch the avatar `id`'s profile named, if one still waits, and make it theirs. True when it
/// did. Gone from the media store, or announced longer ago than the store keeps anything: the
/// wait ends and the avatar shown stays. Any other failure leaves it waiting for the next start.
pub async fn fetch_pending_avatar(
    store: &crate::local_store::LocalStore,
    anonymous: &crate::grpc::GrpcClient,
    id: &str,
) -> bool {
    let Ok(Some((stored, since))) = store.pending_avatar(id) else {
        return false;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64);
    let drop = || {
        let _ = store.drop_pending_avatar(id, &stored);
        false
    };
    if now - since > PENDING_AVATAR_LIFETIME_MS {
        return drop();
    }
    let Some(r) = AvatarRef::from_stored(&stored) else {
        return drop();
    };
    let blob = match crate::grpc::download_media(anonymous, &r.media_id, MAX_AVATAR_BLOB).await {
        Ok(blob) => blob,
        Err(crate::grpc::GrpcError::Status { code: 5, .. }) => return drop(),
        Err(e) => {
            tracing::info!("avatar not fetched, tried again at the next start: {e}");
            return false;
        }
    };
    match construct_core::media::open_media(&r.media_key, &blob) {
        // A newer profile may have named another avatar meanwhile; the store checks.
        Ok(avatar) => store
            .complete_pending_avatar(id, &stored, &avatar)
            .unwrap_or(false),
        Err(e) => {
            tracing::warn!("avatar did not open: {e}");
            drop()
        }
    }
}

/// An avatar blob larger than this is not one (a padded JPEG is 200 KiB, a few times that at
/// most).
const MAX_AVATAR_BLOB: usize = 4 * 1024 * 1024;

/// The name that goes out: the one chosen, else the username — never the generated one, which a
/// contact computes for itself and would take for a choice.
pub fn outgoing_name(display_name: &str, username: &str, own_account: &str) -> String {
    let name = display_name.trim();
    if name.is_empty() || crate::names::is_generated(name, own_account) {
        username.to_owned()
    } else {
        name.to_owned()
    }
}

/// `jpeg` followed by zeros up to the one avatar size, or the next multiple of it. A decoder stops
/// at the end of the image; the server sees only the length, the same for everyone.
pub fn padded(jpeg: &[u8]) -> Vec<u8> {
    let target = jpeg.len().div_ceil(AVATAR_PADDED_LEN).max(1) * AVATAR_PADDED_LEN;
    let mut out = jpeg.to_vec();
    out.resize(target, 0);
    out
}

/// A name a person typed for themselves, made one: trimmed, without control characters, cut to
/// the length iOS allows.
pub fn clean_display_name(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .chars()
        .take(MAX_DISPLAY_NAME_CHARS)
        .collect::<String>()
        .trim_end()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS: &str = include_str!(concat!(
        env!("CONSTRUCT_PROTOS_DIR"),
        "/conformance/knst_profile_share.json"
    ));

    fn vectors() -> serde_json::Value {
        serde_json::from_str(VECTORS).expect("vectors are valid JSON")
    }

    #[test]
    fn profiles_read_as_the_vectors_say() {
        for v in vectors()["decode"].as_array().unwrap() {
            let name = v["name"].as_str().unwrap();
            let bytes = hex::decode(v["payload"].as_str().unwrap()).unwrap();
            let p = ProfileShare::decode(&bytes).unwrap();
            assert_eq!(
                p.display_name,
                v["display_name"].as_str().unwrap(),
                "{name}"
            );
            assert_eq!(
                p.edited_at_ms,
                v["edited_at_ms"].as_u64().unwrap(),
                "{name}"
            );
            match (&p.avatar, &v["avatar"]) {
                (Avatar::Set(r), serde_json::Value::Object(o)) => {
                    let set = &o["set"];
                    assert_eq!(r.media_id, set["media_id"].as_str().unwrap(), "{name}");
                    assert_eq!(r.media_url, set["media_url"].as_str().unwrap(), "{name}");
                    assert_eq!(
                        hex::encode(&r.media_key),
                        set["media_key"].as_str().unwrap()
                    );
                    assert_eq!(r.mime_type, set["mime_type"].as_str().unwrap(), "{name}");
                }
                (Avatar::Removed, serde_json::Value::String(s)) => assert_eq!(s, "removed"),
                (Avatar::Unchanged, serde_json::Value::String(s)) => assert_eq!(s, "unchanged"),
                (got, want) => panic!("{name}: read {got:?}, vectors say {want}"),
            }
            // What this client writes reads back the same: the wire bytes of a well-formed one
            // are the vector's.
            if name != "short_key_is_unchanged" {
                assert_eq!(
                    hex::encode(p.encode()),
                    v["payload"].as_str().unwrap(),
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn profiles_apply_as_the_vectors_say() {
        let r = AvatarRef {
            media_id: "m".into(),
            media_url: String::new(),
            media_key: vec![1; 32],
            mime_type: "image/jpeg".into(),
        };
        for v in vectors()["apply"].as_array().unwrap() {
            let name = v["name"].as_str().unwrap();
            let avatar = match v["avatar"].as_str().unwrap() {
                "set" => Avatar::Set(r.clone()),
                "removed" => Avatar::Removed,
                _ => Avatar::Unchanged,
            };
            let p = ProfileShare {
                display_name: "Alice".into(),
                edited_at_ms: v["edited_at_ms"].as_u64().unwrap(),
                avatar,
            };
            let held = v["held_edited_at_ms"].as_i64().unwrap_or(0);
            let action = p.decision(held).map(|a| match a {
                AvatarAction::Download(_) => "download",
                AvatarAction::Clear => "clear",
                AvatarAction::Keep => "keep",
            });
            let want = match v["result"].as_str().unwrap() {
                "apply" => v["avatar_action"].as_str(),
                _ => None,
            };
            assert_eq!(action, want, "{name}");
        }
    }

    #[test]
    fn a_generated_name_is_neither_sent_nor_taken() {
        let id = "550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(outgoing_name("Cool Cobra", "anna_k", id), "anna_k");
        assert_eq!(outgoing_name("", "anna_k", id), "anna_k");
        assert_eq!(outgoing_name(" Анна ", "anna_k", id), "Анна");
        let p = |name: &str| ProfileShare {
            display_name: name.into(),
            edited_at_ms: 1,
            avatar: Avatar::Unchanged,
        };
        assert_eq!(p("cool cobra").chosen_name(id), None);
        assert_eq!(p("  ").chosen_name(id), None);
        assert_eq!(p("Анна").chosen_name(id).as_deref(), Some("Анна"));
    }

    #[test]
    fn every_avatar_goes_out_at_one_length() {
        assert_eq!(padded(&[0xFF; 10]).len(), AVATAR_PADDED_LEN);
        assert_eq!(padded(&vec![1; AVATAR_PADDED_LEN]).len(), AVATAR_PADDED_LEN);
        assert_eq!(
            padded(&vec![1; AVATAR_PADDED_LEN + 1]).len(),
            2 * AVATAR_PADDED_LEN
        );
        assert_eq!(&padded(b"jpeg")[..4], b"jpeg");
    }

    #[test]
    fn a_typed_name_is_cut_and_cleaned() {
        assert_eq!(clean_display_name("  Анна\u{7}  "), "Анна");
        assert_eq!(clean_display_name(&"я".repeat(60)).chars().count(), 50);
    }
}
