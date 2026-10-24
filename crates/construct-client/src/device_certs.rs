//! Devices of an account vouch for each other
//! (`decisions/devices-of-an-account-sign-each-other.md`).
//!
//! The decisions are the core's (`crypto::device_certificate`): whether to sign, and whether a
//! peer's device is trusted. This module only translates — a link code into the evidence it
//! carries, a bundle into the keys a certificate covers — and picks out what to alarm about from
//! the core's verdicts, as iOS `PeerDeviceVetting` does.

use construct_core::crypto::device_certificate::{
    DeviceKeys, DeviceVerdict, LinkEvidence, OfferedDevice,
};
use construct_core::orchestration::orchestrator::Orchestrator;

use crate::grpc::FetchedPreKeyBundle;

/// A code shown by a device of the account (Flow A), as this device received it: the link token,
/// and the secret this device proves its keys under so the old device can vouch for them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkCode {
    pub token: String,
    pub secret: Option<Vec<u8>>,
}

/// `konstruct://link?token=…&fp=…&s=…`, or a bare token. A code whose secret is malformed is
/// still a link code, without the secret — the device links, unvouched, as iOS does.
pub fn parse_link_code(code: &str) -> Option<LinkCode> {
    let code = code.trim();
    let Some(query) = code.strip_prefix("konstruct://link?") else {
        let bare = !code.is_empty() && !code.contains("://") && !code.contains(char::is_whitespace);
        return bare.then(|| LinkCode {
            token: code.to_string(),
            secret: None,
        });
    };
    let token = query_value(query, "token").filter(|t| !t.is_empty())?;
    Some(LinkCode {
        token: token.to_string(),
        secret: query_value(query, "s").and_then(hex32),
    })
}

/// A code shown by a device that asks to join this account (Flow B), as this device scanned it:
/// the device, and the fingerprint of its keys this device vouches for once the directory
/// serves them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinCode {
    pub device_id: String,
    pub fingerprint: Option<Vec<u8>>,
}

/// `konstruct://link-to-me?id=…&fp=…`, or a bare device id (approved, never vouched for).
pub fn parse_join_code(code: &str) -> Option<JoinCode> {
    let code = code.trim();
    let Some(query) = code.strip_prefix("konstruct://link-to-me?") else {
        let bare = !code.is_empty() && code.chars().all(|c| c.is_ascii_hexdigit());
        return bare.then(|| JoinCode {
            device_id: code.to_string(),
            fingerprint: None,
        });
    };
    let device_id = query_value(query, "id").filter(|id| !id.is_empty())?;
    Some(JoinCode {
        device_id: device_id.to_string(),
        fingerprint: query_value(query, "fp").and_then(hex32),
    })
}

fn query_value<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value)
}

fn hex32(value: &str) -> Option<Vec<u8>> {
    hex::decode(value).ok().filter(|bytes| bytes.len() == 32)
}

/// What the link code showed about the device being vouched for.
#[derive(Debug, Clone)]
pub(crate) enum Evidence {
    /// Flow B: the new device's code carried the fingerprint of its keys.
    QrFingerprint(Vec<u8>),
    /// Flow A: our code carried `secret`; the new device answered with `proof`.
    QrSecret { secret: Vec<u8>, proof: Vec<u8> },
}

impl Evidence {
    pub(crate) fn view(&self) -> LinkEvidence<'_> {
        match self {
            Evidence::QrFingerprint(fp) => LinkEvidence::QrFingerprint(fp),
            Evidence::QrSecret { secret, proof } => LinkEvidence::QrSecret { secret, proof },
        }
    }
}

/// The keys a certificate covers, as the directory serves them.
#[derive(Debug, Clone)]
pub(crate) struct SubjectKeys {
    identity_public: Vec<u8>,
    verifying_key: Vec<u8>,
    hybrid_public: Vec<u8>,
    hybrid_binding: Vec<u8>,
}

impl SubjectKeys {
    /// `None` until the device has published its hybrid key and the binding to its Ed25519 key.
    /// Such a device cannot open a session with anyone (the core requires PQ), so it is neither
    /// vouched for nor worth an alarm.
    pub(crate) fn of(fetched: &FetchedPreKeyBundle) -> Option<Self> {
        let x3dh = &fetched.bundle.x3dh;
        let kyber = &fetched.bundle.kyber;
        let hybrid_public = kyber
            .hybrid_identity_key
            .clone()
            .filter(|k| !k.is_empty())?;
        let hybrid_binding = kyber
            .hybrid_identity_signature
            .clone()
            .filter(|s| !s.is_empty())?;
        Some(Self {
            identity_public: x3dh.identity_public.clone(),
            verifying_key: x3dh.verifying_key.clone(),
            hybrid_public,
            hybrid_binding,
        })
    }

    pub(crate) fn view(&self) -> DeviceKeys<'_> {
        DeviceKeys {
            identity_public: &self.identity_public,
            verifying_key: &self.verifying_key,
            hybrid_public: &self.hybrid_public,
            hybrid_binding: &self.hybrid_binding,
        }
    }
}

/// The devices to alarm about: unvouched, and not already trusted here. A device the user was
/// warned about once is pinned by the next fetch, which reads it as `Pinned`.
pub(crate) fn unvouched(
    trusted: &[String],
    offered: &[&str],
    verdicts: &[DeviceVerdict],
) -> Vec<String> {
    offered
        .iter()
        .zip(verdicts)
        .filter(|(device, verdict)| {
            **verdict == DeviceVerdict::Unvouched && !trusted.iter().any(|t| t == **device)
        })
        .map(|(device, _)| device.to_string())
        .collect()
}

/// Judge a full answer for `account` — every device the server lists — against the devices of
/// it trusted **before** this answer was recorded (after, every device it names is trusted and
/// nothing could be new), and return the devices to alarm about.
///
/// Only a full answer: one narrowed to some devices may leave out the one that signed the
/// others. The caller skips its own account and an account seen for the first time.
pub(crate) fn vet(
    orchestrator: &Orchestrator,
    account: &str,
    trusted_before: &[String],
    bundles: &[FetchedPreKeyBundle],
) -> Vec<String> {
    let subjects: Vec<(&FetchedPreKeyBundle, SubjectKeys)> = bundles
        .iter()
        .filter_map(|b| SubjectKeys::of(b).map(|keys| (b, keys)))
        .collect();
    if subjects.is_empty() {
        return Vec::new();
    }
    let offered: Vec<OfferedDevice<'_>> = subjects
        .iter()
        .map(|(b, keys)| OfferedDevice {
            device_id: &b.device_id,
            keys: keys.view(),
            certificate: b.certificate.as_deref(),
        })
        .collect();
    let verdicts = orchestrator.judge_peer_devices(trusted_before, &offered);
    for (device, verdict) in offered.iter().zip(&verdicts) {
        tracing::debug!(device = %device.device_id, %account, ?verdict, "device judged");
        match verdict {
            DeviceVerdict::KeyChanged => {
                tracing::error!(device = %device.device_id, %account, "device presents another hybrid key")
            }
            DeviceVerdict::Invalid => {
                tracing::error!(device = %device.device_id, %account, "device bundle does not hold together")
            }
            _ => {}
        }
    }
    let ids: Vec<&str> = offered.iter().map(|d| d.device_id).collect();
    unvouched(trusted_before, &ids, &verdicts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::services::v1::{DevicePreKeyBundle, GetPreKeyBundlesResponse, PreKeyBundle};

    const S: &str = "0101010101010101010101010101010101010101010101010101010101010101";

    #[test]
    fn a_link_code_gives_its_token_and_secret() {
        let code = parse_link_code(&format!("konstruct://link?token=abc-_9&fp={S}&s={S}"))
            .expect("a link code");
        assert_eq!(code.token, "abc-_9");
        assert_eq!(code.secret, Some(vec![1u8; 32]));
    }

    #[test]
    fn a_link_code_with_a_bad_secret_links_without_one() {
        let code = parse_link_code("konstruct://link?token=abc&s=0102").expect("a link code");
        assert_eq!(code.secret, None);
        assert_eq!(
            parse_link_code("  abc  "),
            Some(LinkCode {
                token: "abc".into(),
                secret: None
            })
        );
        assert_eq!(parse_link_code("konstruct://link?s=00"), None);
        assert_eq!(parse_link_code("konstruct://link-to-me?id=ab"), None);
    }

    #[test]
    fn a_join_code_gives_the_device_and_its_fingerprint() {
        let code = parse_join_code(&format!(
            "konstruct://link-to-me?id=00ff&pubkey=x%2B&fp={S}&name=a&platform=linux"
        ))
        .expect("a join code");
        assert_eq!(code.device_id, "00ff");
        assert_eq!(code.fingerprint, Some(vec![1u8; 32]));
        assert_eq!(
            parse_join_code("00ff"),
            Some(JoinCode {
                device_id: "00ff".into(),
                fingerprint: None
            })
        );
        assert_eq!(parse_join_code("konstruct://link?token=abc"), None);
    }

    /// A device's entry in a `GetPreKeyBundles` answer, with the core that holds its keys.
    fn device() -> (Orchestrator, DevicePreKeyBundle) {
        use construct_core::crypto::client_api::ClassicClient;
        use construct_core::crypto::keys::{Ed25519KeyPair, X25519KeyPair};
        use ed25519_dalek::Signer;

        let signing = Ed25519KeyPair::generate();
        let identity = X25519KeyPair::generate();
        let spk = X25519KeyPair::generate();
        let device_id = construct_core::device_id::derive_device_id(&identity.public_key);
        let client = ClassicClient::from_keys(
            identity.private_key.to_vec(),
            signing.private_key.to_vec(),
            spk.private_key.to_vec(),
            vec![0u8; 64],
        )
        .expect("keys");
        let mut orchestrator = Orchestrator::new(client, device_id.clone());
        let hybrid = orchestrator
            .ensure_hybrid_signature_key()
            .expect("hybrid key");
        let binding = signing
            .get_signing_key()
            .sign(&Orchestrator::build_hybrid_identity_bind_message(&hybrid))
            .to_bytes()
            .to_vec();
        let entry = DevicePreKeyBundle {
            device_id,
            bundle: Some(PreKeyBundle {
                identity_key: identity.public_key.to_vec().into(),
                signed_pre_key: spk.public_key.to_vec().into(),
                hybrid_identity_key: Some(hybrid.into()),
                hybrid_identity_signature: Some(binding.into()),
                ..Default::default()
            }),
            verifying_key: signing.public_key.to_vec().into(),
            ..Default::default()
        };
        (orchestrator, entry)
    }

    /// The answer as the client reads it off the wire.
    fn answer(entries: Vec<DevicePreKeyBundle>) -> Vec<FetchedPreKeyBundle> {
        crate::grpc::device_bundles(GetPreKeyBundlesResponse {
            bundles: entries,
            ..Default::default()
        })
        .bundles
    }

    fn fingerprint(b: &FetchedPreKeyBundle) -> Evidence {
        Evidence::QrFingerprint(
            construct_core::history::discovery::qr_fingerprint(
                &b.bundle.x3dh.identity_public,
                b.bundle.kyber.hybrid_identity_key.as_deref().unwrap(),
            )
            .to_vec(),
        )
    }

    /// The bundle's keys reach the core as the keys a certificate covers: a device the trusted
    /// one vouched for passes, the one nobody vouched for is the alarm.
    #[test]
    fn a_device_vouched_for_by_a_trusted_one_passes_and_an_unsigned_one_alarms() {
        let (phone, phone_entry) = device();
        let (_, mut laptop_entry) = device();
        let (_, stranger_entry) = device();
        let laptop = answer(vec![laptop_entry.clone()]).remove(0);
        let keys = SubjectKeys::of(&laptop).expect("hybrid key published");
        let certificate = phone
            .issue_device_certificate(&keys.view(), &fingerprint(&laptop).view())
            .expect("issued for the keys the code named");
        laptop_entry.device_certificate = Some(certificate.into());

        let trusted = vec![phone_entry.device_id.clone()];
        let stranger = stranger_entry.device_id.clone();
        let offered = answer(vec![phone_entry, laptop_entry, stranger_entry]);
        let (judge, _) = device();
        assert_eq!(vet(&judge, "account", &trusted, &offered), vec![stranger]);
        assert!(
            vet(&judge, "account", &[], &offered).is_empty(),
            "first sight of an account"
        );
    }

    /// Keys other than the ones the code named are not signed: the directory's substitution.
    #[test]
    fn keys_other_than_the_code_named_are_not_vouched_for() {
        let (phone, _) = device();
        let (_, laptop) = device();
        let (_, substitute) = device();
        let offered = answer(vec![laptop, substitute]);
        let keys = SubjectKeys::of(&offered[1]).expect("hybrid key published");
        let refused =
            phone.issue_device_certificate(&keys.view(), &fingerprint(&offered[0]).view());
        assert_eq!(
            refused,
            Err(construct_core::crypto::device_certificate::CertError::EvidenceMismatch)
        );
    }

    #[test]
    fn a_device_without_its_hybrid_key_is_not_judged() {
        let (_, mut laptop) = device();
        laptop.bundle.as_mut().unwrap().hybrid_identity_signature = None;
        assert!(SubjectKeys::of(&answer(vec![laptop])[0]).is_none());
    }

    #[test]
    fn only_an_unvouched_device_not_trusted_before_is_alarmed() {
        let trusted = vec!["kept".to_string()];
        let offered = ["kept", "new", "signed", "first"];
        let verdicts = [
            DeviceVerdict::Unvouched,
            DeviceVerdict::Unvouched,
            DeviceVerdict::Vouched { by: "kept".into() },
            DeviceVerdict::FirstOfAccount,
        ];
        assert_eq!(unvouched(&trusted, &offered, &verdicts), vec!["new"]);
    }
}
