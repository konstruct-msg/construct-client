//! The account as settings change it: its devices, its username, whether it can be found. All
//! signed in, as on iOS (`AuthServiceClient`, `UserServiceClient`).

use prost::Message;

use crate::proto::services::v1::{
    BlockUserRequest, BlockUserResponse, CheckUsernameAvailabilityRequest,
    CheckUsernameAvailabilityResponse, DeleteAccountRequest, DeleteAccountResponse,
    GetBlockedUsersRequest, GetBlockedUsersResponse, GetUserProfileRequest, GetUserProfileResponse,
    ListDevicesRequest, ListDevicesResponse, LogoutRequest, LogoutResponse, RevokeDeviceRequest,
    RevokeDeviceResponse, SetDeviceMetadataRequest, SetDiscoverableRequest,
    SetDiscoverableResponse, UnblockUserRequest, UnblockUserResponse, UpdateUserProfileRequest,
    UpdateUserProfileResponse,
};

use super::client::GrpcClient;
use super::error::GrpcError;
use super::paths;

/// One device of our account as the server lists it. Its name and platform are sealed to the
/// account's devices (`sealed_metadata`), and not read here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub device_id: String,
    /// Unix seconds; 0 when the server does not say.
    pub created_at: i64,
    pub is_current: bool,
    pub is_primary: bool,
    /// Its name and platform sealed to the account's devices (`device_meta`); empty when none.
    pub sealed_metadata: Vec<u8>,
}

/// Most devices an account lists; the stream is cut there.
const MAX_DEVICES: usize = 64;

/// `DeviceService.ListDevices`, a server stream of one device per message.
pub async fn list_devices(client: &GrpcClient) -> Result<Vec<Device>, GrpcError> {
    let mut devices = Vec::new();
    super::media::server_streaming(
        client,
        paths::DEVICE_LIST,
        &ListDevicesRequest::default().encode_to_vec(),
        true,
        |message| {
            let info = ListDevicesResponse::decode(message)
                .map_err(|e| GrpcError::transport(format!("ListDevices decode: {e}")))?
                .device
                .unwrap_or_default();
            let device_id = info.device.map(|d| d.device_id).unwrap_or_default();
            if !device_id.is_empty() && devices.len() < MAX_DEVICES {
                devices.push(Device {
                    device_id,
                    created_at: info.created_at,
                    is_current: info.is_current,
                    is_primary: info.is_primary,
                    sealed_metadata: info.sealed_metadata.to_vec(),
                });
            }
            Ok(())
        },
    )
    .await?;
    Ok(devices)
}

/// `DeviceService.RevokeDevice`. The server refuses the account's primary device.
pub async fn revoke_device(client: &GrpcClient, device_id: &str) -> Result<(), GrpcError> {
    let req = RevokeDeviceRequest {
        device_id: device_id.to_owned(),
    };
    let bytes = client
        .unary(paths::DEVICE_REVOKE, &req.encode_to_vec())
        .await?;
    let resp = RevokeDeviceResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("RevokeDevice decode: {e}")))?;
    if !resp.success {
        return Err(GrpcError::transport("the server did not revoke the device"));
    }
    Ok(())
}

/// `DeviceService.SetDeviceMetadata`: this device's sealed description; the server keeps it and
/// cannot read it.
pub async fn set_device_metadata(client: &GrpcClient, blob: &[u8]) -> Result<(), GrpcError> {
    let req = SetDeviceMetadataRequest {
        sealed_metadata: blob.to_vec().into(),
    };
    client
        .unary(paths::DEVICE_SET_METADATA, &req.encode_to_vec())
        .await?;
    Ok(())
}

/// Our username, as the server holds it; `None` when there is none.
pub async fn own_username(client: &GrpcClient, user_id: &str) -> Result<Option<String>, GrpcError> {
    let req = GetUserProfileRequest {
        user_id: user_id.to_owned(),
    };
    let bytes = client
        .unary(paths::USER_PROFILE, &req.encode_to_vec())
        .await?;
    let resp = GetUserProfileResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("GetUserProfile decode: {e}")))?;
    Ok(resp
        .profile
        .and_then(|p| p.username)
        .filter(|u| !u.is_empty()))
}

/// Why a username cannot be taken, as the server words it ("taken", "reserved", …).
pub async fn username_refusal(
    client: &GrpcClient,
    username: &str,
) -> Result<Option<String>, GrpcError> {
    let req = CheckUsernameAvailabilityRequest {
        username: username.to_owned(),
    };
    let bytes = client
        .unary(paths::USER_CHECK_USERNAME, &req.encode_to_vec())
        .await?;
    let resp = CheckUsernameAvailabilityResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("CheckUsernameAvailability decode: {e}")))?;
    Ok((!resp.available).then(|| resp.reason.unwrap_or_else(|| "taken".into())))
}

/// `UserService.UpdateUserProfile` with a new username; returns the one the server now holds.
pub async fn set_username(
    client: &GrpcClient,
    user_id: &str,
    username: &str,
) -> Result<String, GrpcError> {
    let req = UpdateUserProfileRequest {
        user_id: user_id.to_owned(),
        username: Some(username.to_owned()),
    };
    let bytes = client
        .unary(paths::USER_UPDATE_PROFILE, &req.encode_to_vec())
        .await?;
    let resp = UpdateUserProfileResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("UpdateUserProfile decode: {e}")))?;
    Ok(resp
        .profile
        .and_then(|p| p.username)
        .unwrap_or_else(|| username.to_owned()))
}

/// `UserService.BlockUser`: the server's row for this block. It refuses a call; what arrives as a
/// message is dropped here (`crate::block_sync`). The blocker is the caller, as iOS sends it.
pub async fn block_user(
    client: &GrpcClient,
    user_id: &str,
    reason: Option<&str>,
) -> Result<(), GrpcError> {
    let req = BlockUserRequest {
        user_id: user_id.to_owned(),
        reason: reason.map(str::to_owned),
        ..Default::default()
    };
    let bytes = client
        .unary(paths::USER_BLOCK, &req.encode_to_vec())
        .await?;
    BlockUserResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("BlockUser decode: {e}")))?;
    Ok(())
}

/// `UserService.UnblockUser`.
pub async fn unblock_user(client: &GrpcClient, user_id: &str) -> Result<(), GrpcError> {
    let req = UnblockUserRequest {
        user_id: user_id.to_owned(),
        ..Default::default()
    };
    let bytes = client
        .unary(paths::USER_UNBLOCK, &req.encode_to_vec())
        .await?;
    UnblockUserResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("UnblockUser decode: {e}")))?;
    Ok(())
}

/// `UserService.GetBlockedUsers`: everyone this account blocks on the server, from any of its
/// devices. The user id is left empty — the caller's own list, as iOS asks it.
pub async fn blocked_users(client: &GrpcClient) -> Result<Vec<String>, GrpcError> {
    let bytes = client
        .unary(
            paths::USER_BLOCKED,
            &GetBlockedUsersRequest::default().encode_to_vec(),
        )
        .await?;
    let resp = GetBlockedUsersResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("GetBlockedUsers decode: {e}")))?;
    if resp.has_more {
        tracing::warn!("the server's block list has more than one page: the rest is not read");
    }
    Ok(resp.blocked_users.into_iter().map(|b| b.user_id).collect())
}

/// `UserService.SetDiscoverable`: whether `FindUser` finds us by username.
pub async fn set_discoverable(client: &GrpcClient, discoverable: bool) -> Result<bool, GrpcError> {
    let bytes = client
        .unary(
            paths::USER_SET_DISCOVERABLE,
            &SetDiscoverableRequest { discoverable }.encode_to_vec(),
        )
        .await?;
    let resp = SetDiscoverableResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("SetDiscoverable decode: {e}")))?;
    Ok(resp.discoverable)
}

/// `AuthService.Logout`: the server stops taking this session's tokens, and with `all_devices`
/// every device's. It marks the devices inactive, so a revoked one wipes itself when it next
/// signs in (decisions/sign-out-wipes-the-device.md).
pub async fn logout(
    client: &GrpcClient,
    access_token: &str,
    all_devices: bool,
) -> Result<(), GrpcError> {
    let req = LogoutRequest {
        access_token: access_token.to_owned(),
        all_devices,
    };
    let bytes = client
        .unary(paths::AUTH_LOGOUT, &req.encode_to_vec())
        .await?;
    let resp = LogoutResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("Logout decode: {e}")))?;
    if !resp.success {
        return Err(GrpcError::transport("the server did not sign out"));
    }
    Ok(())
}

/// `UserService.DeleteAccount`, confirmed the way iOS confirms it.
pub async fn delete_account(client: &GrpcClient) -> Result<(), GrpcError> {
    let req = DeleteAccountRequest {
        confirmation: "DELETE".into(),
        reason: Some("user_requested".into()),
    };
    let bytes = client
        .unary(paths::USER_DELETE_ACCOUNT, &req.encode_to_vec())
        .await?;
    let resp = DeleteAccountResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("DeleteAccount decode: {e}")))?;
    if !resp.success {
        let why = if resp.message.is_empty() {
            "the server did not delete the account".to_string()
        } else {
            resp.message
        };
        return Err(GrpcError::transport(why));
    }
    Ok(())
}
