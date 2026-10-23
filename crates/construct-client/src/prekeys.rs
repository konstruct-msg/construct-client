//! This device's key material beyond the four classic secrets: the core's whole key record, its
//! one-time prekeys and its Kyber prekeys — kept across launches, and published once.
//!
//! PQXDH v2 is mandatory. An initiator puts its KEM identity in the first flight, and the core
//! derives that from the hybrid signature key, so the key must exist and stay the same across
//! launches. A responder needs a Kyber prekey on the server, signed by the hybrid key, before any
//! peer can open a session to it. So the core's state is restored whole, in the order iOS uses
//! (`CryptoManager.setLocalUserId`): key record, one-time prekeys, Kyber prekeys; and what it
//! has not published yet goes up in one `UploadPreKeys`, the way iOS's
//! `KyberPrekeyService.publish` does after registration.
//!
//! The blobs live in `secure_store`, inside the SQLCipher database.

use construct_core::cfe::{CfeMessageType, CfePrivateKeysV1, decode_as};
use construct_core::crypto::client_api::ClassicClient;
use construct_core::crypto::suites::classic::ClassicSuiteProvider;
use construct_core::orchestration::orchestrator::Orchestrator;
use ed25519_dalek::Signer;

use crate::local_store::LocalStore;

pub(crate) const KEY_RECORD: &str = "crypto_private_keys";
const ONE_TIME_PREKEYS: &str = "crypto_otpks";
const KYBER_PREKEYS: &str = "crypto_kyber_prekeys";
/// `device_id:kyber_spk_id` of the last successful publish.
const PUBLISHED: &str = "crypto_prekeys_published";

const CLASSIC_ONE_TIME_BATCH: u32 = 100;
/// Below this many classic one-time prekeys on the server, more go up (iOS's low-water mark).
const ONE_TIME_LOW_WATER: u32 = 20;
/// A signed prekey this old is rotated. Peers refuse a bundle whose signed prekey is older than
/// the core's `SPK_MAX_AGE_SECS` (30 days); iOS rotates weekly.
const ROTATE_AFTER_SECS: i64 = 7 * 24 * 3600;
/// How often a running client looks again.
pub const MAINTENANCE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(6 * 3600);
const KYBER_ONE_TIME_BATCH: u32 = 50;
/// Suite byte of the classic signed prekey in its hybrid signature (`sign_hybrid_prekey`).
const CLASSIC_SPK_SUITE: u8 = 0x01;

/// The core's client: from the saved key record, or — the first launch after this code — from
/// the four classic secrets the session file holds.
pub fn restore_client(
    storage: &LocalStore,
    identity: Vec<u8>,
    signing: Vec<u8>,
    spk: Vec<u8>,
    spk_sig: Vec<u8>,
) -> Result<ClassicClient<ClassicSuiteProvider>, String> {
    if let Ok(Some(record)) = storage.secure_load(KEY_RECORD) {
        let keys = decode_as::<CfePrivateKeysV1>(&record, CfeMessageType::PrivateKeys)
            .map_err(|e| format!("key record decode: {e}"))?;
        return ClassicClient::from_private_keys_cfe(keys);
    }
    ClassicClient::from_keys(identity, signing, spk, spk_sig).map_err(|e| e.to_string())
}

/// Restore the prekeys into a fresh orchestrator, then make sure the hybrid key exists and the
/// key record that carries it is saved. Returns whether the blobs were all there (a missing or
/// unreadable one means the server's one-time prekeys must be replaced, not appended to).
pub fn restore_prekeys(
    orchestrator: &mut Orchestrator,
    storage: &LocalStore,
) -> Result<bool, String> {
    let mut whole = true;
    match storage.secure_load(ONE_TIME_PREKEYS) {
        Ok(Some(blob)) => {
            if let Err(e) = orchestrator.import_otpks_cfe(&blob) {
                tracing::warn!(error = %e, "one-time prekeys did not restore");
                whole = false;
            }
        }
        _ => whole = false,
    }
    match storage.secure_load(KYBER_PREKEYS) {
        Ok(Some(blob)) => {
            if let Err(e) = orchestrator.import_kyber_prekeys_cfe(&blob) {
                tracing::warn!(error = %e, "Kyber prekeys did not restore");
                whole = false;
            }
        }
        _ => whole = false,
    }
    orchestrator.ensure_hybrid_signature_key()?;
    save_key_record(orchestrator, storage)?;
    Ok(whole)
}

pub fn save_key_record(orchestrator: &Orchestrator, storage: &LocalStore) -> Result<(), String> {
    let record = orchestrator.export_private_keys_cfe()?;
    storage
        .secure_save(KEY_RECORD, &record)
        .map_err(|e| format!("key record save: {e}"))
}

pub fn save_one_time_prekeys(
    orchestrator: &Orchestrator,
    storage: &LocalStore,
) -> Result<(), String> {
    let blob = orchestrator.export_otpks_cfe()?;
    storage
        .secure_save(ONE_TIME_PREKEYS, &blob)
        .map_err(|e| format!("one-time prekeys save: {e}"))
}

pub fn save_kyber_prekeys(orchestrator: &Orchestrator, storage: &LocalStore) -> Result<(), String> {
    let blob = orchestrator.export_kyber_prekeys_cfe()?;
    storage
        .secure_save(KYBER_PREKEYS, &blob)
        .map_err(|e| format!("Kyber prekeys save: {e}"))
}

/// After a responder session opened: a consumed Kyber one-time prekey and a consumed classic one
/// are gone from the core, and must be gone from the saved blobs before anything else happens.
pub fn save_after_responder_init(orchestrator: &mut Orchestrator, storage: &LocalStore) {
    if let Some(blob) = orchestrator.take_kyber_prekeys_to_persist()
        && let Err(e) = storage.secure_save(KYBER_PREKEYS, &blob)
    {
        tracing::error!(error = %e, "Kyber prekeys save after responder init failed");
    }
    if let Err(e) = save_one_time_prekeys(orchestrator, storage) {
        tracing::error!(error = %e, "one-time prekeys save after responder init failed");
    }
}

/// What `prepare_publish` made ready: the upload, and what to do once it is answered.
pub struct Publish {
    pub upload: crate::grpc::PrekeyUpload,
    kyber_spk_id: u32,
    rotating: bool,
}

/// Get ready to publish the Kyber signed prekey, a batch of each kind of one-time prekey and the
/// hybrid identity — `None` when this device already published its current Kyber prekey and no
/// replacement is asked for. Every secret is saved before its public half can leave.
pub fn prepare_publish(
    orchestrator: &mut Orchestrator,
    storage: &LocalStore,
    device_id: &str,
    signing_secret: &[u8],
    force_replace: bool,
) -> Result<Option<Publish>, String> {
    let current = orchestrator.current_kyber_spk_upload()?;
    if let Some(spk) = &current
        && !force_replace
        && storage.secure_load(PUBLISHED).ok().flatten()
            == Some(published_mark(device_id, spk.key_id))
    {
        return Ok(None);
    }
    let rotating = current.is_none();
    let kyber_spk = match current {
        Some(spk) => spk,
        None => orchestrator.begin_kyber_spk_rotation()?,
    };
    save_kyber_prekeys(orchestrator, storage)?;
    let kyber_one_time = orchestrator.generate_kyber_one_time_prekeys(KYBER_ONE_TIME_BATCH)?;
    save_kyber_prekeys(orchestrator, storage)?;
    let one_time = orchestrator.generate_otpks(CLASSIC_ONE_TIME_BATCH)?;
    save_one_time_prekeys(orchestrator, storage)?;

    let hybrid_identity = orchestrator.ensure_hybrid_signature_key()?;
    save_key_record(orchestrator, storage)?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(
        signing_secret
            .try_into()
            .map_err(|_| "signing key must be 32 bytes")?,
    );
    let hybrid_identity_signature = signing_key
        .sign(&Orchestrator::build_hybrid_identity_bind_message(
            &hybrid_identity,
        ))
        .to_bytes()
        .to_vec();
    let classic_spk = orchestrator
        .get_registration_bundle_fields()?
        .signed_prekey_public;
    let signed_pre_key_hybrid_signature =
        orchestrator.sign_hybrid_prekey(CLASSIC_SPK_SUITE, &classic_spk)?;

    Ok(Some(Publish {
        kyber_spk_id: kyber_spk.key_id,
        rotating,
        upload: crate::grpc::PrekeyUpload {
            one_time,
            kyber_one_time,
            kyber_spk,
            hybrid_identity,
            hybrid_identity_signature,
            signed_pre_key_hybrid_signature,
        },
    }))
}

/// After the upload: commit a new Kyber signed prekey and remember the publish, or roll the
/// rotation back when the server refused it (not on a transport error: it may have arrived).
pub fn finish_publish(
    orchestrator: &mut Orchestrator,
    storage: &LocalStore,
    device_id: &str,
    kyber_spk_id: u32,
    rotating: bool,
    result: Result<(), crate::grpc::GrpcError>,
) -> Result<(), String> {
    match result {
        Ok(()) => {
            if rotating {
                orchestrator.commit_kyber_spk_rotation();
                save_kyber_prekeys(orchestrator, storage)?;
            }
            storage
                .secure_save(PUBLISHED, &published_mark(device_id, kyber_spk_id))
                .map_err(|e| format!("publish mark save: {e}"))?;
            tracing::info!(kyber_spk_id, "prekeys published");
            Ok(())
        }
        Err(e) => {
            if rotating && !e.is_retryable_transport() {
                orchestrator.rollback_kyber_spk_rotation();
                save_kyber_prekeys(orchestrator, storage)?;
            }
            Err(format!("UploadPreKeys: {e}"))
        }
    }
}

impl Publish {
    pub fn into_parts(self) -> (crate::grpc::PrekeyUpload, u32, bool) {
        (self.upload, self.kyber_spk_id, self.rotating)
    }
}

fn published_mark(device_id: &str, kyber_spk_id: u32) -> Vec<u8> {
    format!("{device_id}:{kyber_spk_id}").into_bytes()
}

/// Whether to rotate a signed prekey of this age, given what the server says.
fn needs_rotation(age_secs: i64, server_says: bool) -> bool {
    server_says || age_secs >= ROTATE_AFTER_SECS
}

/// How many one-time prekeys of each kind to add, given how many the server holds and the
/// minimum it recommends; `None` when it holds enough.
fn replenish_count(server_count: u32, recommended: u32) -> Option<u32> {
    if server_count >= recommended.max(ONE_TIME_LOW_WATER) {
        return None;
    }
    Some(
        CLASSIC_ONE_TIME_BATCH
            .saturating_sub(server_count)
            .max(ONE_TIME_LOW_WATER),
    )
}

/// Rotate the signed prekeys when due and top up the one-time prekeys when low. Each step is
/// tried even when the other failed; the first error is returned.
///
/// `CONSTRUCT_ROTATE_PREKEYS_NOW` forces the rotation, for interop checks against the server.
pub async fn maintain(
    orchestrator: &mut Orchestrator,
    storage: &LocalStore,
    grpc: &crate::grpc::GrpcClient,
    device_id: &str,
) -> Result<(), String> {
    let forced = std::env::var_os("CONSTRUCT_ROTATE_PREKEYS_NOW").is_some();
    let rotation = match crate::grpc::get_signed_prekey_age(grpc, device_id).await {
        Ok((age, server_says)) if forced || needs_rotation(age, server_says) => {
            tracing::info!(
                age_secs = age,
                server_says,
                forced,
                "rotating signed prekeys"
            );
            rotate_signed_prekeys(orchestrator, storage, grpc, device_id).await
        }
        Ok(_) => Ok(()),
        Err(e) => Err(format!("GetSignedPreKeyAge: {e}")),
    };
    let topping = match crate::grpc::get_prekey_count(grpc, device_id).await {
        Ok((count, recommended)) => match replenish_count(count, recommended) {
            Some(n) => {
                tracing::info!(
                    server_count = count,
                    adding = n,
                    "replenishing one-time prekeys"
                );
                replenish(orchestrator, storage, grpc, device_id, n).await
            }
            None => Ok(()),
        },
        Err(e) => Err(format!("GetPreKeyCount: {e}")),
    };
    rotation.and(topping)
}

/// A new classic and Kyber signed prekey, saved, then sent in one `RotateSignedPreKey`. The
/// classic rotation keeps the previous signed prekey in the key record for
/// `SPK_RETENTION_AFTER_ROTATION`, so sessions started from the old bundle still open; a refused
/// Kyber rotation is rolled back.
async fn rotate_signed_prekeys(
    orchestrator: &mut Orchestrator,
    storage: &LocalStore,
    grpc: &crate::grpc::GrpcClient,
    device_id: &str,
) -> Result<(), String> {
    let (spk_id, spk_public, spk_signature) = orchestrator.rotate_spk()?;
    save_key_record(orchestrator, storage)?;
    let spk_hybrid_signature = orchestrator.sign_hybrid_prekey(CLASSIC_SPK_SUITE, &spk_public)?;
    let kyber_spk = orchestrator.begin_kyber_spk_rotation()?;
    save_kyber_prekeys(orchestrator, storage)?;
    let kyber_spk_id = kyber_spk.key_id;
    let result = crate::grpc::rotate_signed_prekey(
        grpc,
        device_id,
        crate::grpc::SignedPrekeyRotation {
            spk_id,
            spk_public,
            spk_signature,
            spk_hybrid_signature,
            kyber_spk,
        },
    )
    .await;
    match result {
        Ok(()) => {
            orchestrator.commit_kyber_spk_rotation();
            save_kyber_prekeys(orchestrator, storage)?;
            storage
                .secure_save(PUBLISHED, &published_mark(device_id, kyber_spk_id))
                .map_err(|e| format!("publish mark save: {e}"))?;
            tracing::info!(spk_id, kyber_spk_id, "signed prekeys rotated");
            Ok(())
        }
        Err(e) => {
            if !e.is_retryable_transport() {
                orchestrator.rollback_kyber_spk_rotation();
                save_kyber_prekeys(orchestrator, storage)?;
            }
            Err(format!("RotateSignedPreKey: {e}"))
        }
    }
}

/// `count` more one-time prekeys of each kind, saved before they go up.
async fn replenish(
    orchestrator: &mut Orchestrator,
    storage: &LocalStore,
    grpc: &crate::grpc::GrpcClient,
    device_id: &str,
    count: u32,
) -> Result<(), String> {
    let one_time = orchestrator.generate_otpks(count)?;
    save_one_time_prekeys(orchestrator, storage)?;
    let kyber = orchestrator.generate_kyber_one_time_prekeys(count)?;
    save_kyber_prekeys(orchestrator, storage)?;
    crate::grpc::append_one_time_prekeys(grpc, device_id, one_time, kyber)
        .await
        .map_err(|e| format!("UploadPreKeys: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn orchestrator() -> Orchestrator {
        Orchestrator::new(ClassicClient::new().expect("client"), "device".into())
    }

    #[test]
    fn the_kem_identity_survives_a_relaunch() {
        let storage = LocalStore::open_in_memory().unwrap();
        let mut first = orchestrator();
        restore_prekeys(&mut first, &storage).unwrap();
        let hybrid = first
            .hybrid_signature_public_key()
            .expect("hybrid key made");

        let client = restore_client(&storage, vec![], vec![], vec![], vec![]).expect("restores");
        let mut second = Orchestrator::new(client, "device".into());
        restore_prekeys(&mut second, &storage).unwrap();

        assert_eq!(second.hybrid_signature_public_key(), Some(hybrid));
    }

    #[test]
    fn kyber_prekeys_survive_a_relaunch() {
        let storage = LocalStore::open_in_memory().unwrap();
        let mut first = orchestrator();
        restore_prekeys(&mut first, &storage).unwrap();
        let spk = first.begin_kyber_spk_rotation().unwrap();
        first.commit_kyber_spk_rotation();
        save_kyber_prekeys(&first, &storage).unwrap();
        save_one_time_prekeys(&first, &storage).unwrap();

        let client = restore_client(&storage, vec![], vec![], vec![], vec![]).unwrap();
        let mut second = Orchestrator::new(client, "device".into());
        assert!(restore_prekeys(&mut second, &storage).unwrap());

        let restored = second
            .current_kyber_spk_upload()
            .unwrap()
            .expect("a Kyber SPK");
        assert_eq!(restored.key_id, spk.key_id);
        assert_eq!(restored.public_key, spk.public_key);
    }

    #[test]
    fn a_first_launch_without_blobs_asks_for_replacement() {
        let storage = LocalStore::open_in_memory().unwrap();
        let mut orchestrator = orchestrator();
        assert!(!restore_prekeys(&mut orchestrator, &storage).unwrap());
    }

    #[test]
    fn missing_one_time_prekeys_alone_ask_for_replacement() {
        let storage = LocalStore::open_in_memory().unwrap();
        let mut first = orchestrator();
        restore_prekeys(&mut first, &storage).unwrap();
        first.begin_kyber_spk_rotation().unwrap();
        first.commit_kyber_spk_rotation();
        save_kyber_prekeys(&first, &storage).unwrap();

        let client = restore_client(&storage, vec![], vec![], vec![], vec![]).unwrap();
        let mut second = Orchestrator::new(client, "device".into());
        assert!(!restore_prekeys(&mut second, &storage).unwrap());
    }

    #[test]
    fn a_week_old_signed_prekey_is_rotated_and_a_fresh_one_only_on_request() {
        assert!(!needs_rotation(ROTATE_AFTER_SECS - 1, false));
        assert!(needs_rotation(ROTATE_AFTER_SECS, false));
        assert!(needs_rotation(0, true));
    }

    #[test]
    fn one_time_prekeys_are_topped_up_below_the_low_water_mark() {
        assert_eq!(replenish_count(ONE_TIME_LOW_WATER, 0), None);
        assert_eq!(replenish_count(50, 60), Some(50));
        assert_eq!(replenish_count(5, 0), Some(95));
        assert_eq!(replenish_count(0, 0), Some(CLASSIC_ONE_TIME_BATCH));
        // Never fewer than the low-water mark at a time.
        assert_eq!(replenish_count(90, 200), Some(ONE_TIME_LOW_WATER));
    }

    #[test]
    fn a_rotated_signed_prekey_survives_a_relaunch_beside_the_old_one() {
        let storage = LocalStore::open_in_memory().unwrap();
        let mut first = orchestrator();
        restore_prekeys(&mut first, &storage).unwrap();
        let old = first
            .get_registration_bundle_fields()
            .unwrap()
            .signed_prekey_public;
        let (_, new, _) = first.rotate_spk().unwrap();
        save_key_record(&first, &storage).unwrap();

        let client = restore_client(&storage, vec![], vec![], vec![], vec![]).unwrap();
        let second = Orchestrator::new(client, "device".into());
        assert_eq!(
            second
                .get_registration_bundle_fields()
                .unwrap()
                .signed_prekey_public,
            new
        );
        assert_ne!(old, new);
    }
}
