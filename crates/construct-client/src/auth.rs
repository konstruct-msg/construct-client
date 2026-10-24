//! High-level authentication flow for construct-tui.
//!
//! Key generation is local. Server RPCs go through [`crate::grpc`].

use anyhow::{Context, Result};

use construct_core::{
    crypto::{
        SuiteID,
        keys::{Ed25519KeyPair, X25519KeyPair, build_prologue},
    },
    device_id::derive_device_id,
};
use ed25519_dalek::Signer;
use tokio::sync::mpsc;
use tokio::time::{Duration, sleep};

use crate::config::Session;
use crate::grpc::GrpcClient;

/// Each step of registration, sent to the UI as it progresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationStep {
    GeneratingSigningKey,
    GeneratingIdentityKey,
    GeneratingPreKey,
    SigningPreKey,
    Connecting,
    SolvingPoW,
    Registering,
}

impl RegistrationStep {
    /// Index corresponding to `screens::registration::STEPS` order.
    pub fn index(self) -> usize {
        match self {
            Self::GeneratingSigningKey => 0,
            Self::GeneratingIdentityKey => 1,
            Self::GeneratingPreKey => 2,
            Self::SigningPreKey => 3,
            Self::Connecting => 4,
            Self::SolvingPoW => 5,
            Self::Registering => 6,
        }
    }
}

/// Minimum time each step stays visible so the user can read it (ms).
const MIN_STEP_MS: u64 = 500;

/// Result of a successful auth (returned to the UI layer).
#[derive(Debug, Clone)]
pub struct AuthResult {
    pub user_id: String,
    pub device_id: String,
    pub access_token: String,
    /// The full session for new registrations/links, or an updated session after
    /// encrypted-session restore (contains refreshed tokens). `None` for plaintext restores
    /// (those handle their own persistence in `try_restore_session`).
    pub session: Option<crate::config::Session>,
}

/// Register a brand-new device and save the resulting session.
/// `username` is optional (display name hint sent to the server).
/// `progress_tx` receives step updates for the UI checklist; send errors are silently ignored.
pub async fn register_new_device(
    client: &GrpcClient,
    username: Option<&str>,
    progress_tx: &mpsc::UnboundedSender<RegistrationStep>,
) -> Result<AuthResult> {
    let step = |s: RegistrationStep| {
        let _ = progress_tx.send(s);
    };

    // 1. Generate device keys — each step has a minimum display time
    step(RegistrationStep::GeneratingSigningKey);
    let signing_pair = Ed25519KeyPair::generate();
    sleep(Duration::from_millis(MIN_STEP_MS)).await;

    step(RegistrationStep::GeneratingIdentityKey);
    let identity_pair = X25519KeyPair::generate();
    sleep(Duration::from_millis(MIN_STEP_MS)).await;

    step(RegistrationStep::GeneratingPreKey);
    let spk_pair = X25519KeyPair::generate();
    sleep(Duration::from_millis(MIN_STEP_MS)).await;

    step(RegistrationStep::SigningPreKey);
    // 2. Derive device_id from identity public key
    let device_id = derive_device_id(&identity_pair.public_key);
    // 3. Sign the SPK: prologue || spk_public_key (standard X3DH SPK signing)
    let prologue = build_prologue(SuiteID::CLASSIC);
    let mut spk_msg = prologue;
    spk_msg.extend_from_slice(&spk_pair.public_key);
    let sk = signing_pair.get_signing_key();
    let spk_sig = sk.sign(&spk_msg);
    sleep(Duration::from_millis(MIN_STEP_MS)).await;

    // 4. Build CFE-encoded private keys blob
    use construct_core::{
        cfe::{CfePrivateKeysV1, encode},
        crypto::SecretBytes,
    };
    use serde_bytes::ByteBuf;
    let private_keys = CfePrivateKeysV1 {
        suite_id: 1, // CLASSIC
        ik_priv: SecretBytes::from_slice(&identity_pair.private_key[..]),
        sk_priv: SecretBytes::from_slice(&signing_pair.private_key[..]),
        spk_priv: SecretBytes::from_slice(&spk_pair.private_key[..]),
        spk_sig: ByteBuf::from(spk_sig.to_bytes().to_vec()),
        spk_id: 0,
        ik_pub: ByteBuf::from(identity_pair.public_key.to_vec()),
        vk_pub: ByteBuf::from(signing_pair.public_key.to_vec()),
        spk_pub: ByteBuf::from(spk_pair.public_key.to_vec()),
        old_spks: vec![],
        hybrid_sig_priv: None,
    };
    let keys_cfe_data = encode(
        construct_core::cfe::CfeMessageType::PrivateKeys,
        &private_keys,
    )?;

    // 5. Brief "Connecting" confirmation
    step(RegistrationStep::Connecting);
    sleep(Duration::from_millis(MIN_STEP_MS)).await;

    step(RegistrationStep::SolvingPoW);

    client.set_device_id(Some(device_id.clone()));
    let (challenge, difficulty) = crate::grpc::get_pow_challenge(client)
        .await
        .context("pow challenge")?;

    tracing::info!(
        difficulty,
        "solving PoW (Argon2id, may take minutes at difficulty 8)"
    );
    let challenge_for_pow = challenge.clone();
    let solution = tokio::task::spawn_blocking(move || {
        construct_core::pow::compute_pow(&challenge_for_pow, difficulty)
    })
    .await
    .context("PoW computation panicked")?
    .context("PoW")?;
    tracing::info!(nonce = solution.nonce, "PoW solved");

    step(RegistrationStep::Registering);
    sleep(Duration::from_millis(MIN_STEP_MS)).await;

    let pubs = crate::grpc::device_public_keys(
        &signing_pair.public_key,
        &identity_pair.public_key,
        &spk_pair.public_key,
        &spk_sig.to_bytes(),
    );
    let tokens = crate::grpc::register_device(
        client,
        username.map(str::to_string),
        &device_id,
        pubs,
        solution,
        challenge,
    )
    .await
    .context("register device")?;
    let user_id = tokens.user_id;
    let access_token = tokens.access_token;
    let refresh_token = tokens.refresh_token;
    let expires_at = tokens.expires_at;
    let _ = keys_cfe_data;

    // 7. Build session (caller is responsible for saving — encrypted or plaintext)
    let session = Session {
        signing_key_hex: hex::encode(*signing_pair.private_key),
        identity_key_hex: hex::encode(*identity_pair.private_key),
        device_id: device_id.clone(),
        user_id: user_id.clone(),
        access_token: access_token.clone(),
        refresh_token: refresh_token.clone(),
        expires_at,
        spk_key_hex: hex::encode(*spk_pair.private_key),
        spk_sig_hex: hex::encode(spk_sig.to_bytes()),
    };

    Ok(AuthResult {
        user_id,
        device_id,
        access_token,
        session: Some(session),
    })
}

/// This device, linked to an existing account by a code another device of it showed (Flow A).
pub struct LinkedDevice {
    pub result: AuthResult,
    /// The core's key record, hybrid key included: the proof sent to the server is over that
    /// key, so it is the one this device must publish.
    pub key_record: Vec<u8>,
}

/// Link this device to an existing account with a code from another device of it (iOS or
/// Desktop Settings → Add Device): make the keys, then `ConfirmDeviceLink` with the token and,
/// when the code carried a secret, the proof of these keys under it — the old device vouches
/// for exactly the keys the proof names.
pub async fn link_existing_device(
    client: &GrpcClient,
    code: &crate::device_certs::LinkCode,
) -> Result<LinkedDevice> {
    let secret = code.secret.clone();
    let keys = tokio::task::spawn_blocking(move || new_device_keys(secret.as_deref()))
        .await
        .context("key generation")??;
    let device_id = keys.session_secrets.device_id.clone();
    client.set_device_id(Some(device_id.clone()));
    let pubs = crate::grpc::device_public_keys(
        &keys.verifying_key,
        &keys.identity_public,
        &keys.signed_prekey_public,
        &keys.signed_prekey_signature,
    );
    let proof = keys.link_key_proof.map(|p| p.to_vec()).unwrap_or_default();
    let tokens = crate::grpc::confirm_device_link(client, &code.token, &device_id, pubs, proof)
        .await
        .context("confirm device link")?;

    let mut session = keys.session_secrets;
    session.user_id = tokens.user_id.clone();
    session.access_token = tokens.access_token.clone();
    session.refresh_token = tokens.refresh_token;
    session.expires_at = tokens.expires_at;
    Ok(LinkedDevice {
        result: AuthResult {
            user_id: tokens.user_id,
            device_id,
            access_token: tokens.access_token,
            session: Some(session),
        },
        key_record: keys.key_record,
    })
}

/// Authenticate using a session that was already loaded from disk (e.g. after decryption).
/// Unlike `try_restore_session`, this does NOT touch the session file — the caller is
/// responsible for re-saving the session with updated tokens.
pub async fn authenticate_saved_session(
    session: Session,
    client: &GrpcClient,
) -> Result<AuthResult> {
    // Parse signing key
    let sk_bytes = hex::decode(&session.signing_key_hex).context("invalid signing key hex")?;
    let sk_array: [u8; 32] = sk_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("signing key must be 32 bytes"))?;

    // Generate challenge response (sign timestamp)
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    let message = format!("{}{}", session.device_id, timestamp);

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&sk_array);
    let signature = signing_key.sign(message.as_bytes());

    client.set_device_id(Some(session.device_id.clone()));
    let tokens = crate::grpc::authenticate_device(
        client,
        &session.device_id,
        timestamp,
        &signature.to_bytes(),
    )
    .await
    .context("authenticate")?;

    let mut session = session;
    session.access_token = tokens.access_token.clone();
    session.refresh_token = tokens.refresh_token;
    session.expires_at = tokens.expires_at;

    Ok(AuthResult {
        user_id: tokens.user_id,
        device_id: session.device_id.clone(),
        access_token: tokens.access_token,
        session: Some(session),
    })
}

// ── Linking as a new device of an existing account (Flow B) ─────────────────────

/// A device made ready to be approved by the phone: its keys, its key record with the hybrid key
/// already in it, and what the QR code says.
pub struct JoinPrep {
    pub session_secrets: Session,
    /// The core's key record (`export_private_keys_cfe`), hybrid key included: the QR's
    /// fingerprint commits to that key, so it must be the one the device later publishes.
    pub key_record: Vec<u8>,
    pub request: crate::grpc::JoinRequest,
    /// `konstruct://link-to-me?…`, what the phone scans.
    pub qr: String,
}

/// How long the server holds a join request.
const JOIN_TTL: Duration = Duration::from_secs(10 * 60);
const JOIN_POLL: Duration = Duration::from_secs(3);

/// Make the keys of a device that will join an account, as iOS's `prepareLinkIdentity` does: the
/// classic keys, then the hybrid signature key, all kept in one key record. The QR carries
/// `SHA256(identity ‖ hybrid)`; the phone vouches for this device only if the keys it later finds
/// in the directory match.
pub fn prepare_join() -> Result<JoinPrep> {
    use base64::Engine;

    let keys = new_device_keys(None)?;
    let device_id = keys.session_secrets.device_id.clone();
    let fingerprint = construct_core::history::discovery::qr_fingerprint(
        &keys.identity_public,
        &keys.hybrid_public,
    );
    let device_name = format!("Konstruct on {}", os_label());
    let platform = std::env::consts::OS.to_string();
    let pubkey = base64::engine::general_purpose::STANDARD.encode(&keys.identity_public);
    let qr = format!(
        "konstruct://link-to-me?id={device_id}&pubkey={}&fp={}&name={}&platform={}",
        percent_encode(&pubkey),
        hex::encode(fingerprint),
        percent_encode(&device_name),
        percent_encode(&platform),
    );

    Ok(JoinPrep {
        session_secrets: keys.session_secrets,
        key_record: keys.key_record,
        request: crate::grpc::JoinRequest {
            device_id,
            identity_public: keys.identity_public,
            verifying_key: keys.verifying_key,
            signed_prekey_public: keys.signed_prekey_public,
            signed_prekey_signature: keys.signed_prekey_signature,
            device_name,
            platform,
        },
        qr,
    })
}

/// The keys of a device about to join an account, in either flow.
struct NewDeviceKeys {
    /// The secrets, under the device id; the account and tokens come with the link.
    session_secrets: Session,
    /// The core's key record (`export_private_keys_cfe`), hybrid key included.
    key_record: Vec<u8>,
    identity_public: Vec<u8>,
    verifying_key: Vec<u8>,
    signed_prekey_public: Vec<u8>,
    signed_prekey_signature: Vec<u8>,
    hybrid_public: Vec<u8>,
    /// Flow A: the answer to the secret in the old device's code (core `device_link_key_proof`).
    link_key_proof: Option<[u8; 32]>,
}

/// Make a joining device's keys as iOS's `prepareLinkIdentity` does: the classic keys, then the
/// hybrid signature key, all in one key record — whatever the old device vouches for names the
/// hybrid key, so it exists before any code or proof does, and is kept.
fn new_device_keys(link_secret: Option<&[u8]>) -> Result<NewDeviceKeys> {
    use construct_core::crypto::client_api::ClassicClient;
    use construct_core::orchestration::orchestrator::Orchestrator;

    let signing_pair = Ed25519KeyPair::generate();
    let identity_pair = X25519KeyPair::generate();
    let spk_pair = X25519KeyPair::generate();
    let device_id = derive_device_id(&identity_pair.public_key);
    let mut spk_msg = build_prologue(SuiteID::CLASSIC);
    spk_msg.extend_from_slice(&spk_pair.public_key);
    let spk_sig = signing_pair.get_signing_key().sign(&spk_msg);

    let client = ClassicClient::from_keys(
        identity_pair.private_key.to_vec(),
        signing_pair.private_key.to_vec(),
        spk_pair.private_key.to_vec(),
        spk_sig.to_bytes().to_vec(),
    )
    .map_err(|e| anyhow::anyhow!("keys: {e}"))?;
    let mut orchestrator = Orchestrator::new(client, device_id.clone());
    let hybrid_public = orchestrator
        .ensure_hybrid_signature_key()
        .map_err(|e| anyhow::anyhow!("hybrid key: {e}"))?;
    let key_record = orchestrator
        .export_private_keys_cfe()
        .map_err(|e| anyhow::anyhow!("key record: {e}"))?;
    let link_key_proof = link_secret
        .map(|secret| orchestrator.device_link_key_proof(secret))
        .transpose()
        .map_err(|e| anyhow::anyhow!("link key proof: {e:?}"))?;

    Ok(NewDeviceKeys {
        session_secrets: Session {
            signing_key_hex: hex::encode(*signing_pair.private_key),
            identity_key_hex: hex::encode(*identity_pair.private_key),
            device_id,
            user_id: String::new(),
            access_token: String::new(),
            refresh_token: String::new(),
            expires_at: 0,
            spk_key_hex: hex::encode(*spk_pair.private_key),
            spk_sig_hex: hex::encode(spk_sig.to_bytes()),
        },
        key_record,
        identity_public: identity_pair.public_key.to_vec(),
        verifying_key: signing_pair.public_key.to_vec(),
        signed_prekey_public: spk_pair.public_key.to_vec(),
        signed_prekey_signature: spk_sig.to_bytes().to_vec(),
        hybrid_public,
        link_key_proof,
    })
}

/// Wait for the phone: poll the join request until it is approved, refused or expired.
pub async fn wait_for_approval(
    client: &GrpcClient,
    device_id: &str,
) -> Result<crate::grpc::AuthTokens> {
    use crate::grpc::JoinStatus;
    let deadline = tokio::time::Instant::now() + JOIN_TTL;
    while tokio::time::Instant::now() < deadline {
        match crate::grpc::check_join_request(client, device_id).await {
            Ok(JoinStatus::Approved(tokens)) => return Ok(tokens),
            Ok(JoinStatus::Rejected) => anyhow::bail!("The phone declined this device"),
            Ok(JoinStatus::Expired) => anyhow::bail!("The link code expired; show a new one"),
            Ok(JoinStatus::Pending) => {}
            Err(e) => tracing::warn!(error = %e, "join request status unavailable"),
        }
        sleep(JOIN_POLL).await;
    }
    anyhow::bail!("The link code expired; show a new one")
}

/// The stream position a linked device starts from: its token's issue time. What the mailbox
/// held before that was sealed to keys this device never had (iOS `DeviceLinkOutcome`).
pub fn link_cursor(access_token: &str) -> Option<String> {
    use base64::Engine;
    let payload = access_token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()?;
    let iat = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()?
        .get("iat")?
        .as_i64()?;
    Some(format!("{}-0", iat.checked_mul(1000)?))
}

fn os_label() -> &'static str {
    match std::env::consts::OS {
        "linux" => "Linux",
        "windows" => "Windows",
        "macos" => "macOS",
        other => other,
    }
}

/// Percent-encode everything but RFC 3986 unreserved characters.
fn percent_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_link_code_commits_to_the_keys_the_record_holds() {
        use construct_core::crypto::client_api::ClassicClient;
        use construct_core::orchestration::orchestrator::Orchestrator;
        let prep = prepare_join().unwrap();

        let keys = construct_core::cfe::decode_as::<construct_core::cfe::CfePrivateKeysV1>(
            &prep.key_record,
            construct_core::cfe::CfeMessageType::PrivateKeys,
        )
        .unwrap();
        let restored = Orchestrator::new(
            ClassicClient::from_private_keys_cfe(keys).unwrap(),
            prep.request.device_id.clone(),
        );
        let hybrid = restored
            .hybrid_signature_public_key()
            .expect("hybrid key in the record");
        let fp = construct_core::history::discovery::qr_fingerprint(
            &prep.request.identity_public,
            &hybrid,
        );

        assert!(prep.qr.starts_with("konstruct://link-to-me?"));
        assert!(prep.qr.contains(&format!("id={}", prep.request.device_id)));
        assert!(prep.qr.contains(&format!("fp={}", hex::encode(fp))));
        assert_eq!(
            derive_device_id(&prep.request.identity_public),
            prep.request.device_id
        );
        // Nothing in the query needs a decoder the phone does not run.
        let query = prep.qr.split('?').nth(1).unwrap();
        assert!(!query.contains('+') && !query.contains('/') && !query.contains(' '));
    }

    /// Flow A: the proof sent with `ConfirmDeviceLink` answers the code's secret over the keys
    /// the record holds — the ones this device will publish and the old device vouches for.
    #[test]
    fn the_link_proof_is_over_the_keys_the_record_holds() {
        use construct_core::crypto::client_api::ClassicClient;
        use construct_core::orchestration::orchestrator::Orchestrator;
        let secret = [7u8; 32];
        let keys = new_device_keys(Some(&secret)).unwrap();

        let record = construct_core::cfe::decode_as::<construct_core::cfe::CfePrivateKeysV1>(
            &keys.key_record,
            construct_core::cfe::CfeMessageType::PrivateKeys,
        )
        .unwrap();
        let restored = Orchestrator::new(
            ClassicClient::from_private_keys_cfe(record).unwrap(),
            keys.session_secrets.device_id.clone(),
        );
        let hybrid = restored
            .hybrid_signature_public_key()
            .expect("hybrid key in the record");
        let expected = construct_core::crypto::device_certificate::link_key_proof(
            &secret,
            &keys.identity_public,
            &hybrid,
        )
        .unwrap();
        assert_eq!(keys.link_key_proof, Some(expected));
        assert_eq!(new_device_keys(None).unwrap().link_key_proof, None);
    }

    #[test]
    fn a_linked_device_starts_reading_at_its_token_issue_time() {
        use base64::Engine;
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"sub":"u","iat":1792780000}"#);
        let token = format!("h.{payload}.s");
        assert_eq!(link_cursor(&token).as_deref(), Some("1792780000000-0"));
        assert_eq!(link_cursor("not-a-jwt"), None);
    }
}
