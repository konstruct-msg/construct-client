//! The sealed send path: the sender certificate, `SendSealedMessage`, and the server's trust
//! material.
//!
//! `SendSealedMessage` and `GetServerTrust` go on a client that never holds a token, a connection
//! of its own: a sealed send that carried the bearer token, or rode the authenticated connection,
//! would name its sender to the server (decisions/sealing-is-a-declared-value.md).

use prost::Message;

use crate::proto::core::v1::{SealedInner, SealedSenderEnvelope};
use crate::proto::services::v1::{
    GetSenderCertificateRequest, GetSenderCertificateResponse, GetServerTrustRequest,
    GetServerTrustResponse, SendMessageResponse, SendSealedMessageRequest,
};

use super::client::GrpcClient;
use super::error::GrpcError;
use super::paths;

/// A sender certificate as the server signed it: the serialized `SenderCertificate` proto.
#[derive(Debug, Clone)]
pub struct SenderCertificate {
    pub bytes: Vec<u8>,
    pub expires_at: i64,
}

/// `AuthService.GetSenderCertificate` — authenticated: the certificate names this device.
pub async fn get_sender_certificate(client: &GrpcClient) -> Result<SenderCertificate, GrpcError> {
    let bytes = client
        .unary(
            paths::AUTH_SENDER_CERT,
            &GetSenderCertificateRequest {}.encode_to_vec(),
        )
        .await?;
    let resp = GetSenderCertificateResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("GetSenderCertificate decode: {e}")))?;
    if resp.certificate.is_empty() {
        return Err(GrpcError::transport(
            "GetSenderCertificate: empty certificate",
        ));
    }
    Ok(SenderCertificate {
        bytes: resp.certificate.to_vec(),
        expires_at: resp.expires_at,
    })
}

/// `MessagingService.SendSealedMessage` on `anonymous`. Returns the id the server gave the
/// message, which is what the recipient acknowledges in its delivery receipt.
pub async fn send_sealed_message(
    anonymous: &GrpcClient,
    inner: &SealedInner,
) -> Result<String, GrpcError> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let req = SendSealedMessageRequest {
        sealed_sender: Some(SealedSenderEnvelope {
            sealed_inner: inner.encode_to_vec().into(),
            timestamp,
            ..Default::default()
        }),
        attempt_id: Some(uuid::Uuid::new_v4().to_string()),
    };
    let bytes = anonymous
        .unary(paths::MESSAGING_SEND_SEALED, &req.encode_to_vec())
        .await?;
    let resp = SendMessageResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("SendSealedMessage decode: {e}")))?;
    if let Some(error) = resp.error {
        return Err(GrpcError::status(
            error.error_code as u32,
            format!("SendSealedMessage refused: {}", error.error_message),
        ));
    }
    if !resp.success {
        return Err(GrpcError::transport("SendSealedMessage: not accepted"));
    }
    Ok(resp.message_id)
}

/// `ServerTrustService.GetServerTrust` — the delegations of the server's hybrid keys. Nothing
/// here is trusted for arriving: the core keeps only those a root pinned in the build signed.
pub async fn get_server_trust_delegations(
    anonymous: &GrpcClient,
) -> Result<Vec<Vec<u8>>, GrpcError> {
    let bytes = anonymous
        .unary(
            paths::SERVER_TRUST,
            &GetServerTrustRequest {}.encode_to_vec(),
        )
        .await?;
    let resp = GetServerTrustResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("GetServerTrust decode: {e}")))?;
    Ok(resp.delegations.into_iter().map(|d| d.to_vec()).collect())
}

/// `MessagingService.SendMessage` with an identified envelope, on the authenticated client — only
/// for a copy to one of our own devices, the one send that goes unsealed
/// (decisions/sealing-is-a-declared-value.md, `.ownDevices`).
pub async fn send_own_device_copy(
    client: &GrpcClient,
    envelope: crate::proto::core::v1::Envelope,
) -> Result<(), GrpcError> {
    use crate::proto::services::v1::SendMessageRequest;
    let req = SendMessageRequest {
        message: Some(envelope),
        attempt_id: Some(uuid::Uuid::new_v4().to_string()),
        ..Default::default()
    };
    let bytes = client
        .unary(paths::MESSAGING_SEND, &req.encode_to_vec())
        .await?;
    let resp = SendMessageResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("SendMessage decode: {e}")))?;
    if let Some(error) = resp.error {
        return Err(GrpcError::status(
            error.error_code as u32,
            format!("SendMessage refused: {}", error.error_message),
        ));
    }
    Ok(())
}
