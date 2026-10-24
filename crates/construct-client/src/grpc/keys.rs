//! KeyService unary RPCs.

use construct_core::crypto::SuiteID;
use construct_core::crypto::handshake::x3dh::X3DHPublicKeyBundle;
use construct_core::orchestration::orchestrator::{KyberBundleKeys, SessionBundle};
use prost::Message;

use crate::proto::core::v1::CryptoSuite;
use crate::proto::services::v1::{
    GetPreKeyBundlesRequest, GetPreKeyBundlesResponse, KyberOneTimePreKey, KyberSignedPreKeyUpload,
    OneTimePreKey, PreKeyBundle, UploadPreKeysRequest, UploadPreKeysResponse,
};

use crate::proto::services::v1::{
    GetPreKeyCountRequest, GetPreKeyCountResponse, GetSignedPreKeyAgeRequest,
    GetSignedPreKeyAgeResponse, RotateSignedPreKeyRequest, RotateSignedPreKeyResponse,
    SignedPreKeyRotationReason, SignedPreKeyUpload,
};

use super::client::GrpcClient;
use super::error::GrpcError;
use super::paths;

pub struct FetchedPreKeyBundle {
    pub bundle: SessionBundle,
    pub device_id: String,
    /// The certificate by which another device of the account vouches for this one, as the
    /// server keeps it (`DevicePreKeyBundle.device_certificate`); the core judges it.
    pub certificate: Option<Vec<u8>>,
}

/// The bundles of an account's devices — of `device_ids` only, or of every device when empty —
/// and the devices the server counts as active (`GetPreKeyBundlesResponse.active_devices`).
pub struct DeviceBundles {
    pub bundles: Vec<FetchedPreKeyBundle>,
    pub active_devices: Vec<String>,
}

/// `GetPreKeyBundles`. Each bundle's device id must derive from its identity key; one that does
/// not is left out with a warning, so a server cannot file a key under another device.
pub async fn get_pre_key_bundles(
    client: &GrpcClient,
    user_id: &str,
    device_ids: Vec<String>,
    consume_one_time_prekey: bool,
) -> Result<DeviceBundles, GrpcError> {
    let req = GetPreKeyBundlesRequest {
        user_id: user_id.to_string(),
        device_ids,
        consume_one_time_prekey: Some(consume_one_time_prekey),
        ..Default::default()
    };
    let bytes = client
        .unary(paths::KEY_GET_BUNDLES, &req.encode_to_vec())
        .await?;
    let resp = GetPreKeyBundlesResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("GetPreKeyBundles decode: {e}")))?;
    Ok(device_bundles(resp))
}

/// The bundles of a `GetPreKeyBundles` answer that hold together, each with its certificate.
pub(crate) fn device_bundles(resp: GetPreKeyBundlesResponse) -> DeviceBundles {
    let mut bundles = Vec::new();
    for device in resp.bundles {
        let Some(bundle) = device.bundle else {
            continue;
        };
        match fetched_bundle(device.device_id, bundle, device.verifying_key.to_vec()) {
            Ok(mut fetched) => {
                fetched.certificate = device.device_certificate.map(|c| c.to_vec());
                bundles.push(fetched);
            }
            Err(e) => tracing::warn!(error = %e, "bundle left out"),
        }
    }
    DeviceBundles {
        bundles,
        active_devices: resp.active_devices,
    }
}

fn fetched_bundle(
    device_id: String,
    b: PreKeyBundle,
    verifying_key: Vec<u8>,
) -> Result<FetchedPreKeyBundle, GrpcError> {
    let kyber = KyberBundleKeys {
        pre_key_id: b.kyber_pre_key_id,
        pre_key_public: b.kyber_pre_key.as_ref().map(|v| v.to_vec()),
        pre_key_created_at: b.kyber_pre_key_created_at,
        pre_key_signature: b.kyber_pre_key_signature.as_ref().map(|v| v.to_vec()),
        pre_key_hybrid_signature: b
            .kyber_pre_key_hybrid_signature
            .as_ref()
            .map(|v| v.to_vec()),
        one_time_prekey_id: b.kyber_one_time_pre_key_id,
        one_time_prekey_public: b.kyber_one_time_pre_key.as_ref().map(|v| v.to_vec()),
        one_time_prekey_created_at: b.kyber_one_time_pre_key_created_at,
        one_time_prekey_signature: b
            .kyber_one_time_pre_key_signature
            .as_ref()
            .map(|v| v.to_vec()),
        one_time_prekey_hybrid_signature: b
            .kyber_one_time_pre_key_hybrid_signature
            .as_ref()
            .map(|v| v.to_vec()),
        hybrid_identity_key: b.hybrid_identity_key.as_ref().map(|v| v.to_vec()),
        hybrid_identity_signature: b.hybrid_identity_signature.as_ref().map(|v| v.to_vec()),
    };
    let x3dh = bundle_to_x3dh(b, verifying_key);
    let derived_device_id = construct_core::device_id::derive_device_id(&x3dh.identity_public);
    if device_id != derived_device_id {
        return Err(GrpcError::transport(
            "prekey bundle device ID does not match identity key",
        ));
    }
    Ok(FetchedPreKeyBundle {
        bundle: SessionBundle { x3dh, kyber },
        device_id,
        certificate: None,
    })
}

/// Everything a device publishes beside its registration: one-time prekeys of both kinds, the
/// Kyber signed prekey, and the hybrid identity with the signatures binding it.
pub struct PrekeyUpload {
    pub one_time: Vec<(u32, Vec<u8>)>,
    pub kyber_one_time: Vec<construct_core::crypto::kyber_prekeys::KyberPrekeyUpload>,
    pub kyber_spk: construct_core::crypto::kyber_prekeys::KyberPrekeyUpload,
    pub hybrid_identity: Vec<u8>,
    /// Ed25519 by the device signing key over `build_hybrid_identity_bind_message`.
    pub hybrid_identity_signature: Vec<u8>,
    /// The hybrid key over the classic signed prekey (`sign_hybrid_prekey`).
    pub signed_pre_key_hybrid_signature: Vec<u8>,
}

/// `UploadPreKeys` replacing the server's one-time prekeys with these, as iOS publishes after
/// registration (`KyberPrekeyService.publish`). The Kyber SPK's hybrid signature goes in field
/// 17, not inside field 13.
pub async fn upload_prekeys_full(
    client: &GrpcClient,
    device_id: &str,
    upload: PrekeyUpload,
) -> Result<(), GrpcError> {
    let req = UploadPreKeysRequest {
        device_id: device_id.to_string(),
        pre_keys: upload
            .one_time
            .into_iter()
            .map(|(key_id, public_key)| OneTimePreKey {
                key_id,
                public_key: public_key.into(),
            })
            .collect(),
        replace_existing: true,
        kyber_pre_keys: kyber_one_time(upload.kyber_one_time),
        kyber_signed_pre_key: Some(KyberSignedPreKeyUpload {
            key_id: upload.kyber_spk.key_id,
            public_key: upload.kyber_spk.public_key.into(),
            signature: upload.kyber_spk.signature.into(),
            created_at: upload.kyber_spk.created_at,
        }),
        hybrid_identity_key: Some(upload.hybrid_identity.into()),
        hybrid_identity_signature: Some(upload.hybrid_identity_signature.into()),
        signed_pre_key_hybrid_signature: Some(upload.signed_pre_key_hybrid_signature.into()),
        kyber_signed_pre_key_hybrid_signature: Some(upload.kyber_spk.hybrid_signature.into()),
        ..Default::default()
    };
    let bytes = client
        .unary(paths::KEY_UPLOAD, &req.encode_to_vec())
        .await?;
    let resp = UploadPreKeysResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("UploadPreKeys decode: {e}")))?;
    if !resp.success {
        return Err(GrpcError::transport("UploadPreKeys: not accepted"));
    }
    Ok(())
}

fn kyber_one_time(
    keys: Vec<construct_core::crypto::kyber_prekeys::KyberPrekeyUpload>,
) -> Vec<KyberOneTimePreKey> {
    keys.into_iter()
        .map(|k| KyberOneTimePreKey {
            key_id: k.key_id,
            public_key: k.public_key.into(),
            signature: k.signature.into(),
            created_at: k.created_at,
            hybrid_signature: k.hybrid_signature.into(),
        })
        .collect()
}

/// `UploadPreKeys` adding one-time prekeys of both kinds to what the server holds.
pub async fn append_one_time_prekeys(
    client: &GrpcClient,
    device_id: &str,
    one_time: Vec<(u32, Vec<u8>)>,
    kyber: Vec<construct_core::crypto::kyber_prekeys::KyberPrekeyUpload>,
) -> Result<(), GrpcError> {
    let req = UploadPreKeysRequest {
        device_id: device_id.to_string(),
        pre_keys: one_time
            .into_iter()
            .map(|(key_id, public_key)| OneTimePreKey {
                key_id,
                public_key: public_key.into(),
            })
            .collect(),
        replace_existing: false,
        kyber_pre_keys: kyber_one_time(kyber),
        ..Default::default()
    };
    let bytes = client
        .unary(paths::KEY_UPLOAD, &req.encode_to_vec())
        .await?;
    let resp = UploadPreKeysResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("UploadPreKeys decode: {e}")))?;
    if !resp.success {
        return Err(GrpcError::transport("UploadPreKeys: not accepted"));
    }
    Ok(())
}

/// How many classic one-time prekeys the server holds for us, and how many it wants.
pub async fn get_prekey_count(
    client: &GrpcClient,
    device_id: &str,
) -> Result<(u32, u32), GrpcError> {
    let req = GetPreKeyCountRequest {
        device_id: device_id.to_string(),
    };
    let bytes = client.unary(paths::KEY_COUNT, &req.encode_to_vec()).await?;
    let resp = GetPreKeyCountResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("GetPreKeyCount decode: {e}")))?;
    Ok((resp.count, resp.recommended_minimum))
}

/// The server's view of our signed prekey: its age, and whether it says to rotate.
pub async fn get_signed_prekey_age(
    client: &GrpcClient,
    device_id: &str,
) -> Result<(i64, bool), GrpcError> {
    let req = GetSignedPreKeyAgeRequest {
        device_id: device_id.to_string(),
    };
    let bytes = client
        .unary(paths::KEY_SPK_AGE, &req.encode_to_vec())
        .await?;
    let resp = GetSignedPreKeyAgeResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("GetSignedPreKeyAge decode: {e}")))?;
    Ok((resp.age_seconds, resp.should_rotate))
}

/// A new classic and Kyber signed prekey, replacing the current ones in one call.
pub struct SignedPrekeyRotation {
    pub spk_id: u32,
    pub spk_public: Vec<u8>,
    pub spk_signature: Vec<u8>,
    /// The hybrid key over the new classic signed prekey (`sign_hybrid_prekey`).
    pub spk_hybrid_signature: Vec<u8>,
    pub kyber_spk: construct_core::crypto::kyber_prekeys::KyberPrekeyUpload,
}

/// `RotateSignedPreKey`, both signed prekeys at once, as iOS's `PreKeyRotationService` sends.
pub async fn rotate_signed_prekey(
    client: &GrpcClient,
    device_id: &str,
    rotation: SignedPrekeyRotation,
) -> Result<(), GrpcError> {
    let req = RotateSignedPreKeyRequest {
        device_id: device_id.to_string(),
        new_signed_pre_key: Some(SignedPreKeyUpload {
            key_id: rotation.spk_id,
            public_key: rotation.spk_public.into(),
            signature: rotation.spk_signature.into(),
        }),
        reason: SignedPreKeyRotationReason::Scheduled as i32,
        new_kyber_signed_pre_key: Some(KyberSignedPreKeyUpload {
            key_id: rotation.kyber_spk.key_id,
            public_key: rotation.kyber_spk.public_key.into(),
            signature: rotation.kyber_spk.signature.into(),
            created_at: rotation.kyber_spk.created_at,
        }),
        signed_pre_key_hybrid_signature: Some(rotation.spk_hybrid_signature.into()),
        kyber_signed_pre_key_hybrid_signature: Some(rotation.kyber_spk.hybrid_signature.into()),
    };
    let bytes = client
        .unary(paths::KEY_ROTATE_SPK, &req.encode_to_vec())
        .await?;
    let resp = RotateSignedPreKeyResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("RotateSignedPreKey decode: {e}")))?;
    if !resp.success {
        return Err(GrpcError::transport("RotateSignedPreKey: not accepted"));
    }
    Ok(())
}

fn bundle_to_x3dh(bundle: PreKeyBundle, verifying_key: Vec<u8>) -> X3DHPublicKeyBundle {
    let cs = bundle.crypto_suite;
    let suite_id = if cs == CryptoSuite::HybridKyber1024X25519 as i32
        || cs == CryptoSuite::HybridKyber768X25519 as i32
    {
        SuiteID::PQ_HYBRID
    } else {
        SuiteID::CLASSIC
    };
    X3DHPublicKeyBundle {
        identity_public: bundle.identity_key.to_vec(),
        signed_prekey_public: bundle.signed_pre_key.to_vec(),
        signature: bundle.signed_pre_key_signature.to_vec(),
        verifying_key,
        suite_id,
        one_time_prekey_public: bundle.one_time_pre_key.map(|b| b.to_vec()),
        one_time_prekey_id: bundle.one_time_pre_key_id,
        spk_uploaded_at: bundle.spk_uploaded_at as u64,
        spk_rotation_epoch: bundle.spk_rotation_epoch,
        kyber_spk_uploaded_at: bundle.kyber_spk_uploaded_at.unwrap_or(0) as u64,
        kyber_spk_rotation_epoch: bundle.kyber_spk_rotation_epoch.unwrap_or(0),
    }
}
