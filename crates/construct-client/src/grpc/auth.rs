//! AuthService + DeviceLinkService unary RPCs.

use prost::Message;

use crate::proto::services::v1::{
    AuthenticateDeviceRequest, AuthenticateDeviceResponse, ConfirmDeviceLinkRequest,
    ConfirmDeviceLinkResponse, DevicePublicKeys, GetPowChallengeRequest, GetPowChallengeResponse,
    PowSolution, RefreshTokenRequest, RefreshTokenResponse, RegisterDeviceRequest,
    RegisterDeviceResponse,
};

use super::client::GrpcClient;
use super::error::GrpcError;
use super::paths;

#[derive(Debug, Clone)]
pub struct AuthTokens {
    pub user_id: String,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: i64,
}

pub async fn get_pow_challenge(client: &GrpcClient) -> Result<(String, u32), GrpcError> {
    let bytes = client
        .unary(
            paths::AUTH_POW_CHALLENGE,
            &GetPowChallengeRequest {}.encode_to_vec(),
        )
        .await?;
    let resp = GetPowChallengeResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("GetPowChallenge decode: {e}")))?;
    if resp.challenge.is_empty() {
        return Err(GrpcError::transport(
            "GetPowChallenge returned an empty challenge (HTTP/2 body missing?)",
        ));
    }
    tracing::info!(
        difficulty = resp.difficulty,
        challenge_len = resp.challenge.len(),
        "PoW challenge received"
    );
    Ok((resp.challenge, resp.difficulty))
}

pub async fn register_device(
    client: &GrpcClient,
    username: Option<String>,
    device_id: &str,
    public_keys: DevicePublicKeys,
    pow: construct_core::pow::PowSolution,
    challenge: String,
) -> Result<AuthTokens, GrpcError> {
    let req = RegisterDeviceRequest {
        username,
        device_id: device_id.to_string(),
        public_keys: Some(public_keys),
        pow_solution: Some(PowSolution {
            challenge,
            nonce: pow.nonce,
            hash: pow.hash,
        }),
    };
    let bytes = client
        .unary(paths::AUTH_REGISTER, &req.encode_to_vec())
        .await?;
    let resp = RegisterDeviceResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("RegisterDevice decode: {e}")))?;
    tokens_from(resp.tokens)
}

pub async fn authenticate_device(
    client: &GrpcClient,
    device_id: &str,
    timestamp: i64,
    signature: &[u8],
) -> Result<AuthTokens, GrpcError> {
    let req = AuthenticateDeviceRequest {
        device_id: device_id.to_string(),
        timestamp,
        signature: signature.to_vec().into(),
    };
    let bytes = client
        .unary(paths::AUTH_AUTHENTICATE, &req.encode_to_vec())
        .await?;
    let resp = AuthenticateDeviceResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("AuthenticateDevice decode: {e}")))?;
    tokens_from(resp.tokens)
}

pub async fn refresh_token(
    client: &GrpcClient,
    refresh_token: &str,
    device_id: &str,
) -> Result<(String, String, i64), GrpcError> {
    let req = RefreshTokenRequest {
        refresh_token: refresh_token.to_string(),
        device_id: device_id.to_string(),
    };
    let bytes = client
        .unary(paths::AUTH_REFRESH, &req.encode_to_vec())
        .await?;
    let resp = RefreshTokenResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("RefreshToken decode: {e}")))?;
    Ok((
        resp.access_token,
        resp.refresh_token.unwrap_or_default(),
        resp.expires_at,
    ))
}

pub async fn confirm_device_link(
    client: &GrpcClient,
    link_token: &str,
    device_id: &str,
    public_keys: DevicePublicKeys,
    link_key_proof: Vec<u8>,
) -> Result<AuthTokens, GrpcError> {
    let req = ConfirmDeviceLinkRequest {
        link_token: link_token.to_string(),
        device_id: device_id.to_string(),
        public_keys: Some(public_keys),
        // HMAC under the secret in the old device's QR (core `device_link_key_proof`), so that
        // device can vouch for these keys. Empty when the code carried no secret: the old device
        // then leaves this one unvouched.
        link_key_proof: link_key_proof.into(),
    };
    let bytes = client
        .unary(paths::DEVICE_CONFIRM_LINK, &req.encode_to_vec())
        .await?;
    let resp = ConfirmDeviceLinkResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("ConfirmDeviceLink decode: {e}")))?;
    tokens_from(resp.tokens)
}

/// `AuthService.ApproveJoinRequest` — authenticated: a device of this account lets the device
/// that asked to join become one of its devices.
pub async fn approve_join_request(client: &GrpcClient, device_id: &str) -> Result<(), GrpcError> {
    use crate::proto::services::v1::{ApproveJoinRequestRequest, ApproveJoinRequestResponse};
    let req = ApproveJoinRequestRequest {
        pending_device_id: device_id.to_string(),
        crypto_suite: "Curve25519+Ed25519".into(),
    };
    let bytes = client
        .unary(paths::AUTH_APPROVE_JOIN, &req.encode_to_vec())
        .await?;
    ApproveJoinRequestResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("ApproveJoinRequest decode: {e}")))?;
    Ok(())
}

/// `DeviceService.PublishDeviceCertificate` — authenticated: this device vouches for `subject`,
/// another device of its account. The server stores it beside the subject's bundle unverified;
/// peers verify it (construct-core `judge_peer_devices`).
pub async fn publish_device_certificate(
    client: &GrpcClient,
    subject: &str,
    certificate: Vec<u8>,
) -> Result<(), GrpcError> {
    use crate::proto::services::v1::{
        PublishDeviceCertificateRequest, PublishDeviceCertificateResponse,
    };
    let req = PublishDeviceCertificateRequest {
        subject_device_id: subject.to_string(),
        certificate: certificate.into(),
    };
    let bytes = client
        .unary(paths::DEVICE_PUBLISH_CERTIFICATE, &req.encode_to_vec())
        .await?;
    let resp = PublishDeviceCertificateResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("PublishDeviceCertificate decode: {e}")))?;
    if resp.success {
        Ok(())
    } else {
        Err(GrpcError::transport("certificate not stored"))
    }
}

/// `GetRecoveryStatus`: whether the account has a recovery key, and the server's fingerprint of
/// it — the key's leading hex, for comparing with a key derived on this device.
pub struct RecoveryStatus {
    pub is_setup: bool,
    pub fingerprint: Option<String>,
}

/// `AuthService.GetRecoveryStatus` — authenticated, for this account.
pub async fn get_recovery_status(client: &GrpcClient) -> Result<RecoveryStatus, GrpcError> {
    use crate::proto::services::v1::{GetRecoveryStatusRequest, GetRecoveryStatusResponse};
    let bytes = client
        .unary(
            paths::AUTH_RECOVERY_STATUS,
            &GetRecoveryStatusRequest {}.encode_to_vec(),
        )
        .await?;
    let resp = GetRecoveryStatusResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("GetRecoveryStatus decode: {e}")))?;
    Ok(RecoveryStatus {
        is_setup: resp.is_setup,
        fingerprint: resp.fingerprint.filter(|f| !f.is_empty()),
    })
}

/// `AuthService.SetRecoveryKey` — authenticated: the account's recovery public key, with a
/// signature by it over `CONSTRUCT_RECOVERY_SETUP:{user_id}:{timestamp}`. The same key twice is
/// accepted; another key than the one set is refused with gRPC 6 (ALREADY_EXISTS).
pub async fn set_recovery_key(
    client: &GrpcClient,
    public_key: &[u8],
    signature: &[u8],
    timestamp: i64,
) -> Result<(), GrpcError> {
    use crate::proto::services::v1::{SetRecoveryKeyRequest, SetRecoveryKeyResponse};
    let req = SetRecoveryKeyRequest {
        recovery_public_key: public_key.to_vec().into(),
        setup_signature: signature.to_vec().into(),
        timestamp,
        ..Default::default()
    };
    let bytes = client
        .unary(paths::AUTH_SET_RECOVERY_KEY, &req.encode_to_vec())
        .await?;
    let resp = SetRecoveryKeyResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("SetRecoveryKey decode: {e}")))?;
    if resp.success {
        Ok(())
    } else {
        Err(GrpcError::status(
            2,
            resp.error.unwrap_or_else(|| "recovery key not set".into()),
        ))
    }
}

/// This device's keys for the phone to approve (Flow B): what `SubmitJoinRequest` carries.
pub struct JoinRequest {
    pub device_id: String,
    pub identity_public: Vec<u8>,
    pub verifying_key: Vec<u8>,
    pub signed_prekey_public: Vec<u8>,
    pub signed_prekey_signature: Vec<u8>,
    pub device_name: String,
    pub platform: String,
}

/// `DeviceLinkService.SubmitJoinRequest` — no token: the server holds the request until a device
/// of the account approves it, or ten minutes pass.
pub async fn submit_join_request(client: &GrpcClient, join: &JoinRequest) -> Result<(), GrpcError> {
    use crate::proto::services::v1::{JoinRequestAck, JoinRequestPayload};
    let req = JoinRequestPayload {
        pending_device_id: join.device_id.clone(),
        device_name: join.device_name.clone(),
        platform: join.platform.clone(),
        identity_public: join.identity_public.clone().into(),
        verifying_key: join.verifying_key.clone().into(),
        signed_prekey_public: join.signed_prekey_public.clone().into(),
        signed_prekey_signature: join.signed_prekey_signature.clone().into(),
        ..Default::default()
    };
    let bytes = client
        .unary(paths::DEVICE_SUBMIT_JOIN, &req.encode_to_vec())
        .await?;
    JoinRequestAck::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("SubmitJoinRequest decode: {e}")))?;
    Ok(())
}

/// Where a join request stands.
pub enum JoinStatus {
    Pending,
    Approved(AuthTokens),
    Rejected,
    Expired,
}

/// `DeviceLinkService.CheckJoinRequestStatus`.
pub async fn check_join_request(
    client: &GrpcClient,
    device_id: &str,
) -> Result<JoinStatus, GrpcError> {
    use crate::proto::services::v1::{
        CheckJoinRequestStatusRequest, CheckJoinRequestStatusResponse,
        check_join_request_status_response::Status,
    };
    let req = CheckJoinRequestStatusRequest {
        pending_device_id: device_id.to_string(),
    };
    let bytes = client
        .unary(paths::DEVICE_CHECK_JOIN, &req.encode_to_vec())
        .await?;
    let resp = CheckJoinRequestStatusResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("CheckJoinRequestStatus decode: {e}")))?;
    Ok(
        match Status::try_from(resp.status).unwrap_or(Status::Pending) {
            Status::Pending => JoinStatus::Pending,
            Status::Approved => JoinStatus::Approved(tokens_from(resp.tokens)?),
            Status::Rejected => JoinStatus::Rejected,
            Status::Expired => JoinStatus::Expired,
        },
    )
}

fn tokens_from(
    tokens: Option<crate::proto::services::v1::AuthTokensResponse>,
) -> Result<AuthTokens, GrpcError> {
    let t = tokens.ok_or_else(|| GrpcError::transport("server returned empty tokens"))?;
    Ok(AuthTokens {
        user_id: t.user_id,
        access_token: t.access_token,
        refresh_token: t.refresh_token,
        expires_at: t.expires_at,
    })
}

pub fn device_public_keys(
    verifying_key: &[u8],
    identity_public: &[u8],
    signed_prekey_public: &[u8],
    signed_prekey_signature: &[u8],
) -> DevicePublicKeys {
    DevicePublicKeys {
        verifying_key: verifying_key.to_vec().into(),
        identity_public: identity_public.to_vec().into(),
        signed_prekey_public: signed_prekey_public.to_vec().into(),
        signed_prekey_signature: signed_prekey_signature.to_vec().into(),
        crypto_suite: "Curve25519+Ed25519".into(),
        ..Default::default()
    }
}
