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

const KEY_RECORD: &str = "crypto_private_keys";
const ONE_TIME_PREKEYS: &str = "crypto_otpks";
const KYBER_PREKEYS: &str = "crypto_kyber_prekeys";
/// `device_id:kyber_spk_id` of the last successful publish.
const PUBLISHED: &str = "crypto_prekeys_published";

const CLASSIC_ONE_TIME_BATCH: u32 = 100;
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
}
