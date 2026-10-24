//! A device's name and platform, readable by the devices of its own account and by nobody else
//! (iOS `DeviceMetadataService`): sealed once to each device's X25519 identity key by the core
//! (`seal_to_x25519_public`), the copies stored together on the server
//! (`DeviceInfo.sealed_metadata`), which keeps them and cannot read them. A reader finds its own
//! copy by trying each; the copies carry no label saying whose they are, on purpose.
//!
//! A device is sealed to only while it is in the set: one removed stops being able to read at
//! the next publish, which runs whenever the set changes.

use prost::Message;

use crate::proto::core::v1::DevicePlatform;
use crate::proto::services::v1::{DeviceMetadata, SealedDeviceMetadata};

/// The largest blob the server takes (`SetDeviceMetadataRequest`); larger is refused, so it is
/// never sent.
pub const MAX_BLOB_BYTES: usize = 4096;
/// The longest name a person gives a device.
pub const MAX_NAME_CHARS: usize = 40;

/// What this build calls its device until the person names it: the platform, not a model or a
/// host name, which would tell the account's other devices more than the person chose to.
pub fn default_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "Windows"
    } else if cfg!(target_os = "macos") {
        "macOS"
    } else {
        "Linux"
    }
}

/// How a device describes itself, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Description {
    pub name: String,
    /// `ios`, `android`, `desktop`, `web`, `bot`, or empty.
    pub platform: &'static str,
}

/// Our description sealed to each of `identity_keys` (ours included, so this device reads its
/// own row the same way). `None` when there is nothing to seal to, or the blob would be refused.
pub fn seal(name: &str, identity_keys: &[Vec<u8>]) -> Option<Vec<u8>> {
    let plaintext = DeviceMetadata {
        device_name: clean_name(name),
        platform: DevicePlatform::Desktop as i32,
    }
    .encode_to_vec();
    let copies: Vec<bytes::Bytes> = identity_keys
        .iter()
        .filter_map(|key| {
            construct_core::crypto::sealed_sender::seal_to_x25519_public(&plaintext, key)
                .map_err(|e| tracing::warn!("a device key not sealed to: {e}"))
                .ok()
                .map(Into::into)
        })
        .collect();
    if copies.is_empty() {
        return None;
    }
    let blob = SealedDeviceMetadata { copies }.encode_to_vec();
    (blob.len() <= MAX_BLOB_BYTES).then_some(blob)
}

/// The copy of `blob` sealed to us, opened with our identity secret; `None` when none is — a
/// device linked after the last publish, or one that never published.
pub fn open(blob: &[u8], identity_secret: &[u8]) -> Option<Description> {
    let sealed = SealedDeviceMetadata::decode(blob).ok()?;
    sealed.copies.iter().find_map(|copy| {
        let plaintext =
            construct_core::crypto::sealed_sender::open_with_x25519_secret(copy, identity_secret)
                .ok()?;
        let meta = DeviceMetadata::decode(plaintext.as_slice()).ok()?;
        Some(Description {
            name: clean_name(&meta.device_name),
            platform: match DevicePlatform::try_from(meta.platform) {
                Ok(DevicePlatform::Ios) => "ios",
                Ok(DevicePlatform::Android) => "android",
                Ok(DevicePlatform::Desktop) => "desktop",
                Ok(DevicePlatform::Web) => "web",
                Ok(DevicePlatform::Bot) => "bot",
                _ => "",
            },
        })
    })
}

/// Whether the device set moved since the blob was last published for `last`: a device added
/// has no copy, a device removed can still read. An empty `current` is an unknown set, never a
/// reason to publish one with no copies.
pub fn needs_publish(current: &[String], last: &[String]) -> bool {
    use std::collections::BTreeSet;
    !current.is_empty()
        && current.iter().collect::<BTreeSet<_>>() != last.iter().collect::<BTreeSet<_>>()
}

pub fn clean_name(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .chars()
        .take(MAX_NAME_CHARS)
        .collect::<String>()
        .trim_end()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(seed: u8) -> (Vec<u8>, Vec<u8>) {
        let secret = x25519_dalek::StaticSecret::from([seed; 32]);
        let public = x25519_dalek::PublicKey::from(&secret);
        (secret.to_bytes().to_vec(), public.as_bytes().to_vec())
    }

    #[test]
    fn each_device_of_the_set_reads_the_name_and_no_other() {
        let (a_secret, a_public) = pair(1);
        let (b_secret, b_public) = pair(2);
        let (outsider, _) = pair(3);
        let blob = seal("Рабочий ноутбук", &[a_public, b_public]).unwrap();
        for secret in [&a_secret, &b_secret] {
            let d = open(&blob, secret).unwrap();
            assert_eq!(
                (d.name.as_str(), d.platform),
                ("Рабочий ноутбук", "desktop")
            );
        }
        assert_eq!(
            open(&blob, &outsider),
            None,
            "a device sealed to no longer reads it"
        );
        assert!(
            !blob.windows(6).any(|w| w == "Рабо".as_bytes()),
            "the server sees no name"
        );
    }

    #[test]
    fn nothing_is_published_with_no_copies_or_over_the_limit() {
        assert_eq!(seal("x", &[]), None);
        let keys: Vec<Vec<u8>> = (1..=40).map(|n| pair(n).1).collect();
        let long = "я".repeat(MAX_NAME_CHARS);
        assert!(
            seal(&long, &keys).is_none(),
            "forty long copies are over 4 KiB"
        );
        assert!(seal(&long, &keys[..10]).is_some());
    }

    #[test]
    fn a_publish_follows_the_device_set() {
        let ids = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(needs_publish(&ids(&["a", "b"]), &ids(&["a"])), "one added");
        assert!(
            needs_publish(&ids(&["a"]), &ids(&["a", "b"])),
            "one removed"
        );
        assert!(!needs_publish(&ids(&["b", "a"]), &ids(&["a", "b"])));
        assert!(!needs_publish(&[], &ids(&["a"])), "an unknown set");
    }
}
