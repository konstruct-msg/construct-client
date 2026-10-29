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
    /// The server's X25519 key that tokens (and intake tags) are sealed to; empty when the
    /// server sent none.
    pub token_key: Vec<u8>,
}

/// A sealed message the server took: its id, and what it made of the intake tag
/// (`IntakeVerdict`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedSent {
    pub message_id: String,
    pub intake_verdict: i32,
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
        token_key: resp.token_encryption_key.to_vec(),
    })
}

/// `MessagingService.SendSealedMessage` on `anonymous`. Returns the id the server gave the
/// message, which is what the recipient acknowledges in its delivery receipt, and the verdict
/// on its intake tag.
pub async fn send_sealed_message(
    anonymous: &GrpcClient,
    inner: &SealedInner,
) -> Result<SealedSent, GrpcError> {
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
    Ok(SealedSent {
        message_id: resp.message_id,
        intake_verdict: resp.intake_verdict,
    })
}

/// `AuthService.IssueTokens` — authenticated; the points are blinded, so the tokens they become
/// do not name this account.
pub async fn issue_tokens(
    client: &GrpcClient,
    blinded: &[Vec<u8>],
) -> Result<crate::tokens::Evaluated, GrpcError> {
    use crate::proto::services::v1::{IssueTokensRequest, IssueTokensResponse};
    let req = IssueTokensRequest {
        blinded_points: blinded.iter().map(|p| p.clone().into()).collect(),
    };
    let bytes = client
        .unary(paths::AUTH_ISSUE_TOKENS, &req.encode_to_vec())
        .await?;
    let resp = IssueTokensResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("IssueTokens decode: {e}")))?;
    Ok(crate::tokens::Evaluated {
        points: resp
            .evaluated_points
            .into_iter()
            .map(|p| p.to_vec())
            .collect(),
        server_pubkey: resp.server_pubkey.to_vec(),
        dleq_proof: resp.dleq_proof.to_vec(),
        key_version: resp.issuer_key_version,
    })
}

/// `MessagingService.GetIntakeState` — our account's intake generation, and whether it has tags
/// for today. A server from before generations (UNIMPLEMENTED) is generation 0 without tags.
pub async fn get_intake_state(client: &GrpcClient) -> Result<(u32, bool), GrpcError> {
    use crate::proto::services::v1::{GetIntakeStateRequest, GetIntakeStateResponse};
    let bytes = match client
        .unary(
            paths::MESSAGING_GET_INTAKE_STATE,
            &GetIntakeStateRequest {}.encode_to_vec(),
        )
        .await
    {
        Ok(bytes) => bytes,
        Err(GrpcError::Status { code: 12, .. }) => return Ok((0, false)),
        Err(e) => return Err(e),
    };
    let resp = GetIntakeStateResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("GetIntakeState decode: {e}")))?;
    Ok((resp.generation, resp.has_tags_for_current_epoch))
}

/// `MessagingService.PublishIntakeTags` — authenticated: the tags of our account's key of
/// `generation`. Returns how many the server took and the account's generation there; one above
/// ours means the publish was refused as stale.
pub async fn publish_intake_tags(
    client: &GrpcClient,
    tags: &[(u64, Vec<u8>)],
    generation: u32,
) -> Result<(u32, u32), GrpcError> {
    use crate::proto::services::v1::{
        IntakeTagEntry, PublishIntakeTagsRequest, PublishIntakeTagsResponse,
    };
    let req = PublishIntakeTagsRequest {
        tags: tags
            .iter()
            .map(|(epoch, tag)| IntakeTagEntry {
                epoch: *epoch,
                tag: tag.clone().into(),
            })
            .collect(),
        generation,
    };
    let bytes = client
        .unary(paths::MESSAGING_PUBLISH_INTAKE_TAGS, &req.encode_to_vec())
        .await?;
    let resp = PublishIntakeTagsResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("PublishIntakeTags decode: {e}")))?;
    Ok((resp.accepted, resp.current_generation))
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
