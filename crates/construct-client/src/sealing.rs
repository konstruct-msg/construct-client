//! `SealedInner`, both ways: what a send puts in it and what a delivery takes out of it.
//!
//! Every send to another account is sealed: the outer envelope names neither party, the inner
//! names only the recipient (decisions/sealing-is-a-declared-value.md). The inner carries one of
//! three bodies, chosen by the core:
//!
//! - `session_envelope` — an established session's envelope; the tag names the pair, no
//!   certificate rides (decisions/sealed-envelope-keyed-by-the-session.md);
//! - `first_flight` — the session's first flight sealed whole with the certificate inside
//!   (decisions/first-flight-sealed-whole.md);
//! - `sender_cert_ciphertext` + `encrypted_payload` — the certificate boxed to the recipient's
//!   identity key, for a body that is neither (a DECRYPTION_ERROR about an unread first message).
//!
//! The real content type travels in KNST byte 5 inside the ciphertext; the inner's
//! `content_type` stays unspecified, except a boxed DECRYPTION_ERROR (28), the one body the core
//! does not frame.

use construct_core::crypto::sealed_sender::{
    SenderCertificate, envelope::EnvelopeKind, open_with_x25519_secret, seal_to_x25519_public,
};
use construct_core::orchestration::orchestrator::Orchestrator;
use prost::Message;
use rand::RngCore;

use crate::proto::core::v1::{self as pb, ContentType, SealedInner};

/// The body of a sealed send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealedBody {
    SessionEnvelope(Vec<u8>),
    FirstFlight(Vec<u8>),
    CertificateBox {
        sender_cert_ciphertext: Vec<u8>,
        encrypted_payload: Vec<u8>,
    },
}

/// Seal a wire payload the core wrote for `device` that its session envelope does not cover
/// (`Orchestrator::seal_envelope` said `None`): the first flight sealed whole, else the
/// certificate box. `identity_key` is the X25519 key the session was opened to.
///
/// A first flight the core refuses to seal is an error, never sent another way: its handshake
/// header names the sender.
pub fn seal_with_certificate(
    orchestrator: &Orchestrator,
    device: &str,
    identity_key: &[u8],
    wire_payload: &[u8],
    certificate: &[u8],
) -> Result<SealedBody, String> {
    if let Some(sealed) =
        orchestrator.seal_first_flight(device, identity_key, wire_payload, certificate)?
    {
        return Ok(SealedBody::FirstFlight(sealed));
    }
    certificate_box(identity_key, wire_payload, certificate)
}

/// The certificate boxed to `identity_key` beside `payload`.
pub fn certificate_box(
    identity_key: &[u8],
    payload: &[u8],
    certificate: &[u8],
) -> Result<SealedBody, String> {
    let sender_cert_ciphertext =
        seal_to_x25519_public(certificate, identity_key).map_err(|e| e.to_string())?;
    Ok(SealedBody::CertificateBox {
        sender_cert_ciphertext,
        encrypted_payload: payload.to_vec(),
    })
}

/// The inner for one recipient device. `recipient_device` is derived from the key the body was
/// sealed to, so routing and ciphertext cannot disagree.
pub fn sealed_inner(
    recipient_user_id: &str,
    recipient_device: &str,
    body: SealedBody,
    content_type: ContentType,
) -> SealedInner {
    let mut delivery_tag = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut delivery_tag);
    let mut inner = SealedInner {
        recipient_user_id: recipient_user_id.to_string(),
        recipient_device: recipient_device.to_string(),
        delivery_tag: delivery_tag.into(),
        content_type: content_type as i32,
        ..Default::default()
    };
    match body {
        SealedBody::SessionEnvelope(bytes) => inner.session_envelope = bytes.into(),
        SealedBody::FirstFlight(bytes) => inner.first_flight = bytes.into(),
        SealedBody::CertificateBox {
            sender_cert_ciphertext,
            encrypted_payload,
        } => {
            inner.sender_cert_ciphertext = sender_cert_ciphertext.into();
            inner.encrypted_payload = encrypted_payload.into();
        }
    }
    inner
}

/// What a sealed delivery turned out to be.
#[derive(Debug)]
pub enum Opened {
    /// A session envelope: the pair its tag matched names the writer's device.
    Envelope {
        device: String,
        session_id: String,
        body: Vec<u8>,
        decryption_error: bool,
    },
    /// A first flight or a certificate box: the certificate names the writer, unchecked yet —
    /// the core judges it when it opens a session from it.
    Certified {
        certificate: Box<SenderCertificate>,
        wire_payload: Vec<u8>,
        /// The inner's own content type: 28 for a boxed DECRYPTION_ERROR, else unspecified.
        content_type: u8,
    },
    /// Addressed to another device of this account.
    OtherDevice,
}

/// Open a delivery's `SealedInner` for this device.
pub fn open_sealed_inner(
    orchestrator: &Orchestrator,
    my_device_id: &str,
    identity_secret: &[u8],
    sealed_inner: &[u8],
) -> Result<Opened, String> {
    let inner =
        SealedInner::decode(sealed_inner).map_err(|e| format!("sealed inner decode: {e}"))?;
    if !inner.recipient_device.is_empty() && inner.recipient_device != my_device_id {
        return Ok(Opened::OtherDevice);
    }
    if !inner.session_envelope.is_empty() {
        let opened = orchestrator
            .open_envelope(&inner.session_envelope)
            .ok_or("session envelope: no pair held here matches its tag")?;
        return Ok(Opened::Envelope {
            device: opened.device,
            session_id: opened.session_id,
            body: opened.body,
            decryption_error: opened.kind == EnvelopeKind::DecryptionError,
        });
    }
    let content_type = u8::try_from(inner.content_type).unwrap_or_default();
    if !inner.first_flight.is_empty() {
        let opened = orchestrator.open_first_flight(&inner.first_flight)?;
        return Ok(Opened::Certified {
            certificate: Box::new(certificate_from_proto(&opened.certificate)?),
            wire_payload: opened.wire_payload,
            content_type,
        });
    }
    if inner.sender_cert_ciphertext.is_empty() {
        return Err("sealed inner carries no body".into());
    }
    let cert_bytes = open_with_x25519_secret(&inner.sender_cert_ciphertext, identity_secret)
        .map_err(|e| format!("sender certificate unseal: {e}"))?;
    if inner.encrypted_payload.is_empty() {
        return Err("sealed inner encrypted_payload is empty".into());
    }
    Ok(Opened::Certified {
        certificate: Box::new(certificate_from_proto(&cert_bytes)?),
        wire_payload: inner.encrypted_payload.to_vec(),
        content_type,
    })
}

/// A serialized `SenderCertificate` proto as the core's struct, every field carried over.
pub fn certificate_from_proto(bytes: &[u8]) -> Result<SenderCertificate, String> {
    let cert = pb::SenderCertificate::decode(bytes)
        .map_err(|e| format!("sender certificate decode: {e}"))?;
    if cert.sender_user_id.is_empty() || cert.sender_device_id.is_empty() {
        return Err("sender certificate names no account or device".into());
    }
    Ok(SenderCertificate {
        user_id: cert.sender_user_id,
        domain: cert.sender_domain,
        identity_key: cert.sender_identity_key.to_vec(),
        device_id: cert.sender_device_id,
        issued_at: cert.issued_at,
        expires_at: cert.expires_at,
        signature: cert.server_signature.to_vec(),
        server_kid: cert.server_kid.to_vec(),
        server_signature_hybrid: cert.server_signature_hybrid.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use construct_core::crypto::provider::CryptoProvider;
    use construct_core::crypto::suites::classic::ClassicSuiteProvider;

    fn proto_cert() -> pb::SenderCertificate {
        pb::SenderCertificate {
            sender_user_id: "sender-user".into(),
            sender_domain: "example.test".into(),
            sender_identity_key: vec![9u8; 32].into(),
            sender_device_id: "sender-device".into(),
            issued_at: 1,
            expires_at: 2,
            server_signature: vec![3u8; 64].into(),
            server_kid: vec![5u8; 16].into(),
            server_signature_hybrid: vec![6u8; 3373].into(),
        }
    }

    fn orchestrator() -> Orchestrator {
        let client =
            construct_core::crypto::client_api::ClassicClient::<ClassicSuiteProvider>::new()
                .expect("client");
        Orchestrator::new(client, "me".into())
    }

    #[test]
    fn the_inner_names_only_the_recipient() {
        let inner = sealed_inner(
            "bob",
            "bob-device",
            SealedBody::SessionEnvelope(vec![1, 2, 3]),
            ContentType::Unspecified,
        );
        assert_eq!(inner.recipient_user_id, "bob");
        assert_eq!(inner.recipient_device, "bob-device");
        assert_eq!(inner.session_envelope.as_ref(), &[1, 2, 3]);
        assert!(inner.first_flight.is_empty());
        assert!(inner.sender_cert_ciphertext.is_empty());
        assert!(inner.encrypted_payload.is_empty());
        assert_eq!(inner.content_type, ContentType::Unspecified as i32);
        assert_eq!(inner.delivery_tag.len(), 32);
    }

    #[test]
    fn a_delivery_for_another_device_is_not_opened() {
        let inner = sealed_inner(
            "me",
            "my-other-device",
            SealedBody::SessionEnvelope(vec![1]),
            ContentType::Unspecified,
        );
        let opened = open_sealed_inner(
            &orchestrator(),
            "this-device",
            &[0u8; 32],
            &inner.encode_to_vec(),
        )
        .expect("opens");
        assert!(matches!(opened, Opened::OtherDevice));
    }

    #[test]
    fn a_certificate_box_round_trips_with_every_certificate_field() {
        let secret = vec![7u8; 32];
        let public = ClassicSuiteProvider::from_private_key_to_public_key(
            &ClassicSuiteProvider::kem_private_key_from_bytes(secret.clone()),
        )
        .expect("public key");
        let body = certificate_box(public.as_ref(), b"payload", &proto_cert().encode_to_vec())
            .expect("box");
        let inner = sealed_inner("me", "", body, ContentType::DecryptionError);

        let opened = open_sealed_inner(
            &orchestrator(),
            "this-device",
            &secret,
            &inner.encode_to_vec(),
        )
        .expect("opens");
        let Opened::Certified {
            certificate,
            wire_payload,
            content_type,
        } = opened
        else {
            panic!("expected a certified delivery, got {opened:?}");
        };
        assert_eq!(wire_payload, b"payload");
        assert_eq!(content_type, ContentType::DecryptionError as u8);
        assert_eq!(certificate.device_id, "sender-device");
        assert_eq!(certificate.user_id, "sender-user");
        assert_eq!(certificate.server_kid, vec![5u8; 16]);
        assert_eq!(certificate.server_signature_hybrid, vec![6u8; 3373]);
    }

    #[test]
    fn an_envelope_no_pair_matches_is_an_error_not_a_guess() {
        let inner = sealed_inner(
            "me",
            "this-device",
            SealedBody::SessionEnvelope(vec![0u8; 64]),
            ContentType::Unspecified,
        );
        assert!(
            open_sealed_inner(
                &orchestrator(),
                "this-device",
                &[0u8; 32],
                &inner.encode_to_vec()
            )
            .is_err()
        );
    }
}
