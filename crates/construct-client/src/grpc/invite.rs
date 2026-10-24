//! InviteService unary RPCs.

use prost::Message;

use crate::invite::Invite;
use crate::proto::services::v1::{
    AcceptInviteRequest, AcceptInviteResponse, InviteToken, RevokeInviteRequest,
    RevokeInviteResponse,
};

use super::client::GrpcClient;
use super::error::GrpcError;
use super::paths;

pub struct AcceptedInvite {
    pub user_id: String,
}

pub async fn accept_invite(
    client: &GrpcClient,
    invite: &Invite,
) -> Result<AcceptedInvite, GrpcError> {
    let token = InviteToken {
        v: i32::from(invite.v),
        jti: invite.jti.clone(),
        uuid: invite.uuid.clone(),
        device_id: Some(invite.device_id.clone()),
        server: invite.server.clone(),
        ts: invite.ts,
        // v5 has no ephemeral key; the field stays for the wire's older versions.
        eph_pub: String::new(),
        sig: invite.sig.clone(),
        un: invite.un.clone(),
        ttl: invite.ttl,
        addr: invite.addr.clone().into(),
    };
    let req = AcceptInviteRequest {
        invite: Some(token),
    };
    let bytes = client
        .unary(paths::INVITE_ACCEPT, &req.encode_to_vec())
        .await?;
    let resp = AcceptInviteResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("AcceptInvite decode: {e}")))?;
    if resp.user_id.is_empty() {
        return Err(GrpcError::transport("AcceptInvite empty user_id"));
    }
    tracing::info!(
        user_id = %resp.user_id,
        device_id = ?resp.device_id,
        "AcceptInvite ok"
    );
    Ok(AcceptedInvite {
        user_id: resp.user_id,
    })
}

/// `InviteService.RevokeInvite`: burn an unused invite. `Ok(false)`: it was already used or
/// revoked — an answer, not an error (iOS `InviteRevocation`).
pub async fn revoke_invite(client: &GrpcClient, jti: &str) -> Result<bool, GrpcError> {
    let req = RevokeInviteRequest {
        jti: jti.to_owned(),
    };
    let bytes = client
        .unary(paths::INVITE_REVOKE, &req.encode_to_vec())
        .await?;
    let resp = RevokeInviteResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("RevokeInvite decode: {e}")))?;
    Ok(resp.success)
}
