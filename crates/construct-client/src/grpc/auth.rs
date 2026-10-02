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
) -> Result<AuthTokens, GrpcError> {
    let req = ConfirmDeviceLinkRequest {
        link_token: link_token.to_string(),
        device_id: device_id.to_string(),
        public_keys: Some(public_keys),
    };
    let bytes = client
        .unary(paths::DEVICE_CONFIRM_LINK, &req.encode_to_vec())
        .await?;
    let resp = ConfirmDeviceLinkResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("ConfirmDeviceLink decode: {e}")))?;
    tokens_from(resp.tokens)
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
