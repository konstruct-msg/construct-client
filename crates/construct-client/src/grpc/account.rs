//! The account as settings change it: its devices, its username, whether it can be found. All
//! signed in, as on iOS (`AuthServiceClient`, `UserServiceClient`).

use prost::Message;

use crate::proto::services::v1::{
    CheckUsernameAvailabilityRequest, CheckUsernameAvailabilityResponse, GetUserProfileRequest,
    GetUserProfileResponse, ListDevicesRequest, ListDevicesResponse, RevokeDeviceRequest,
    RevokeDeviceResponse, SetDeviceMetadataRequest, SetDiscoverableRequest,
    SetDiscoverableResponse, UpdateUserProfileRequest, UpdateUserProfileResponse,
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
