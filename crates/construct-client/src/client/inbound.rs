//! From the message stream to the orchestrator: resolve each envelope (unsealing the sender
//! certificate when it is sealed) and hand it over with its cursor context; pass acks, stream
//! status and errors on.

use prost::Message;
use tokio::sync::mpsc;

use super::{ClientEvent, Inbox};
use crate::{
    bridge::BridgeEvent,
    orchestrator_task::{OrchestratorHandle, StreamMessageContext},
    streaming::{CursorTracker, StreamEvent},
};
use construct_core::orchestration::actions::IncomingEvent;

pub(super) fn spawn_relay(
    mut stream_rx: mpsc::Receiver<StreamEvent>,
    orch: OrchestratorHandle,
    cursor: CursorTracker,
    events: mpsc::UnboundedSender<ClientEvent>,
    inbox: mpsc::UnboundedSender<Inbox>,
    identity_secret: Vec<u8>,
) {
    let orch_tx = orch.tx.clone();
    tokio::spawn(async move {
        while let Some(event) = stream_rx.recv().await {
            match event {
                StreamEvent::Message {
                    envelope,
                    stream_cursor,
                } => route_message(&orch, &envelope, stream_cursor, &identity_secret),
                StreamEvent::Ack {
                    message_id,
                    stream_cursor,
                } => {
                    cursor.note(&message_id, stream_cursor);
                    let _ = orch_tx.send(IncomingEvent::AckReceived { message_id });
                }
                StreamEvent::Heartbeat {
                    timestamp,
                    server_timestamp,
                    stream_cursor,
                } => {
                    tracing::debug!(
                        timestamp,
                        server_timestamp,
                        stream_cursor = ?stream_cursor,
                        "stream heartbeat observed"
                    );
                }
                StreamEvent::StreamError {
                    message_id,
                    error_code,
                    error_message,
                    retryable,
                    retry_after_ms,
                    stream_cursor,
                } => {
                    tracing::warn!(
                        message_id = %message_id,
                        error_code,
                        retryable,
                        retry_after_ms = ?retry_after_ms,
                        stream_cursor = ?stream_cursor,
                        "stream server error routed to UI: {}",
                        error_message
                    );
                    let label = if message_id.is_empty() {
                        format!("Stream error {error_code}: {error_message}")
                    } else {
                        format!("Stream error for {message_id}: {error_message}")
                    };
                    let _ = events.send(ClientEvent::Bridge(BridgeEvent::Error(label)));
                }
                StreamEvent::Connected => {
                    let _ = events.send(ClientEvent::Bridge(BridgeEvent::StreamStatus {
                        connected: true,
                    }));
                    let _ = orch_tx.send(IncomingEvent::NetworkReconnected);
                }
                StreamEvent::Disconnected => {
                    let _ = events.send(ClientEvent::Bridge(BridgeEvent::StreamStatus {
                        connected: false,
                    }));
                }
                StreamEvent::Reconnecting { attempt, delay } => {
                    let _ = events.send(ClientEvent::Bridge(BridgeEvent::StreamReconnecting {
                        attempt,
                        delay_ms: delay.as_millis() as u64,
                    }));
                }
                StreamEvent::AuthRequired => {
                    let _ = inbox.send(Inbox::StreamAuthRequired);
                }
            }
        }
    });
}

fn route_message(
    orch: &OrchestratorHandle,
    envelope: &crate::proto::core::v1::Envelope,
    stream_cursor: Option<String>,
    identity_secret: &[u8],
) {
    let inbound = match resolve_inbound_envelope(envelope, identity_secret) {
        Ok(inbound) => inbound,
        Err(e) => {
            tracing::warn!(
                message_id = %direct_envelope_message_id(envelope),
                has_sealed_sender = envelope.sealed_sender.is_some(),
                payload_len = envelope.encrypted_payload.len(),
                stream_cursor = ?stream_cursor,
                "incoming envelope dropped: {e}"
            );
            return;
        }
    };
    if inbound.is_sealed {
        tracing::info!(
            message_id = %inbound.message_id,
            sender = %inbound.from,
            content_type = inbound.content_type,
            payload_len = inbound.wire_payload.len(),
            "incoming sealed sender envelope resolved"
        );
    }

    let sender_user_id = inbound
        .sender_certificate
        .as_ref()
        .map(|cert| cert.user_id.clone())
        .unwrap_or_else(|| inbound.from.clone());
    let content_type = inbound.content_type;

    let msg_num = match construct_core::wire_payload::unpack(&inbound.wire_payload) {
        Ok(decoded) => decoded.message_number,
        Err(e) if is_session_reset_control_type(content_type) => {
            tracing::warn!(
                message_id = %inbound.message_id,
                sender = %inbound.from,
                content_type,
                payload_len = inbound.wire_payload.len(),
                has_sealed_sender = inbound.is_sealed,
                stream_cursor = ?stream_cursor,
                "incoming reset control routed without wire payload decode: {e}"
            );
            0
        }
        Err(e) => {
            tracing::warn!(
                message_id = %inbound.message_id,
                sender = %inbound.from,
                content_type,
                payload_len = inbound.wire_payload.len(),
                has_sealed_sender = inbound.is_sealed,
                stream_cursor = ?stream_cursor,
                "incoming envelope dropped: wire payload unpack failed: {e}"
            );
            return;
        }
    };

    orch.stream_message(
        IncomingEvent::MessageReceived {
            message_id: inbound.message_id.clone(),
            from: inbound.from,
            data: inbound.wire_payload,
            sender_certificate: inbound.sender_certificate,
            content_type,
            // This client does not open session envelopes yet.
            envelope_session: None,
        },
        StreamMessageContext {
            contact_id: sender_user_id,
            message_id: inbound.message_id,
            stream_cursor,
            content_type,
            msg_num,
        },
    );
}

struct InboundEnvelope {
    message_id: String,
    from: String,
    wire_payload: Vec<u8>,
    content_type: u8,
    is_sealed: bool,
    sender_certificate: Option<construct_core::crypto::sealed_sender::SenderCertificate>,
}

fn resolve_inbound_envelope(
    envelope: &crate::proto::core::v1::Envelope,
    identity_secret: &[u8],
) -> Result<InboundEnvelope, String> {
    let message_id = direct_envelope_message_id(envelope).to_owned();
    let Some(sealed) = envelope.sealed_sender.as_ref() else {
        return Ok(InboundEnvelope {
            message_id,
            from: envelope
                .sender
                .as_ref()
                .map(|sender| sender.user_id.clone())
                .unwrap_or_default(),
            wire_payload: envelope.encrypted_payload.to_vec(),
            content_type: content_type_to_u8(envelope.content_type),
            is_sealed: false,
            sender_certificate: None,
        });
    };

    let inner = crate::proto::core::v1::SealedInner::decode(sealed.sealed_inner.as_ref())
        .map_err(|e| format!("sealed inner decode failed: {e}"))?;
    let cert_bytes = construct_core::crypto::sealed_sender::open_with_x25519_secret(
        &inner.sender_cert_ciphertext,
        identity_secret,
    )
    .map_err(|e| format!("sealed sender cert unseal failed: {e}"))?;
    let cert = crate::proto::core::v1::SenderCertificate::decode(cert_bytes.as_slice())
        .map_err(|e| format!("sender certificate decode failed: {e}"))?;
    if cert.sender_user_id.is_empty() {
        return Err("sender certificate has empty sender_user_id".to_string());
    }

    // Sealed delivery deliberately masks the outer sender and content type. Everything
    // authoritative after this boundary comes from SealedInner / SenderCertificate; the inner
    // bytes then go down the normal ratchet path, which remains the authentication root.
    let wire_payload = if envelope.encrypted_payload.is_empty() {
        inner.encrypted_payload.to_vec()
    } else {
        envelope.encrypted_payload.to_vec()
    };
    if wire_payload.is_empty() {
        return Err("sealed inner encrypted_payload is empty".to_string());
    }

    Ok(InboundEnvelope {
        message_id,
        from: cert.sender_device_id.clone(),
        wire_payload,
        content_type: content_type_to_u8(inner.content_type),
        is_sealed: true,
        sender_certificate: Some(construct_core::crypto::sealed_sender::SenderCertificate {
            user_id: cert.sender_user_id,
            domain: cert.sender_domain,
            identity_key: cert.sender_identity_key.to_vec(),
            device_id: cert.sender_device_id,
            issued_at: cert.issued_at,
            expires_at: cert.expires_at,
            signature: cert.server_signature.to_vec(),
        }),
    })
}

fn content_type_to_u8(content_type: i32) -> u8 {
    u8::try_from(content_type).unwrap_or_default()
}

fn is_session_reset_control_type(content_type: u8) -> bool {
    content_type == crate::proto::core::v1::ContentType::SessionReset as u8
        || content_type == crate::proto::core::v1::ContentType::SessionResetInit as u8
}

fn direct_envelope_message_id(envelope: &crate::proto::core::v1::Envelope) -> &str {
    match &envelope.message_id_type {
        Some(crate::proto::core::v1::envelope::MessageIdType::MessageId(id)) => id,
        Some(crate::proto::core::v1::envelope::MessageIdType::GroupMessageId(_)) | None => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use construct_core::crypto::provider::CryptoProvider;
    use construct_core::crypto::suites::classic::ClassicSuiteProvider;

    #[test]
    fn invalid_wire_payload_with_reset_type_is_routed_as_control() {
        let invalid_wire_payload = b"not-a-wire-payload";

        assert!(construct_core::wire_payload::unpack(invalid_wire_payload).is_err());
        assert!(is_session_reset_control_type(
            crate::proto::core::v1::ContentType::SessionReset as u8
        ));
        assert!(is_session_reset_control_type(
            crate::proto::core::v1::ContentType::SessionResetInit as u8
        ));
        assert!(!is_session_reset_control_type(
            crate::proto::core::v1::ContentType::E2eeSignal as u8
        ));
    }

    #[test]
    fn resolves_sealed_envelope_from_inner_payload_and_sender_cert() {
        let identity_secret = vec![7u8; 32];
        let identity_private =
            ClassicSuiteProvider::kem_private_key_from_bytes(identity_secret.clone());
        let identity_public =
            ClassicSuiteProvider::from_private_key_to_public_key(&identity_private)
                .expect("test identity public key should derive");

        let cert = crate::proto::core::v1::SenderCertificate {
            sender_user_id: "sender-user".to_string(),
            sender_domain: "konstruct.cc".to_string(),
            sender_identity_key: vec![9u8; 32].into(),
            sender_device_id: "sender-device".to_string(),
            issued_at: 1,
            expires_at: 2,
            server_signature: vec![3u8; 64].into(),
        };
        let sealed_cert = construct_core::crypto::sealed_sender::seal_to_x25519_public(
            &cert.encode_to_vec(),
            identity_public.as_ref(),
        )
        .expect("test sender cert should seal");
        let wire_payload = vec![1, 2, 3, 4];
        let inner = crate::proto::core::v1::SealedInner {
            recipient_user_id: "recipient-user".to_string(),
            delivery_tag: vec![4u8; 32].into(),
            sender_cert_ciphertext: sealed_cert.into(),
            encrypted_payload: wire_payload.clone().into(),
            content_type: 13,
            ..Default::default()
        };
        let envelope = crate::proto::core::v1::Envelope {
            recipient: Some(crate::proto::core::v1::UserId {
                user_id: "recipient-user".to_string(),
                domain: None,
                display_name: None,
            }),
            encrypted_payload: Vec::new().into(),
            sealed_sender: Some(crate::proto::core::v1::SealedSenderEnvelope {
                sealed_inner: inner.encode_to_vec().into(),
                ..Default::default()
            }),
            message_id_type: Some(crate::proto::core::v1::envelope::MessageIdType::MessageId(
                "msg-1".to_string(),
            )),
            content_type: 1,
            ..Default::default()
        };

        let resolved = resolve_inbound_envelope(&envelope, &identity_secret)
            .expect("sealed envelope should resolve");

        assert_eq!(resolved.message_id, "msg-1");
        // The core keys sessions by device since bfe444a, so `from` is the certificate's device.
        assert_eq!(resolved.from, "sender-device");
        assert_eq!(resolved.wire_payload, wire_payload);
        assert_eq!(resolved.content_type, 13);
        assert!(resolved.is_sealed);
    }
}
