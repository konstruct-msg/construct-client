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

use crate::config::{Session, load_session, save_session};
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

/// Try to authenticate using a saved session.
/// Returns `None` if no session file exists.
pub async fn try_restore_session(client: &GrpcClient) -> Result<Option<AuthResult>> {
    let Some(session) = load_session()? else {
        return Ok(None);
    };

    let result = authenticate_saved_session(session.clone(), client).await?;

    // Refresh stored tokens
    let mut updated = session.clone();
    updated.access_token = result.access_token.clone();
    if let Some(ref sess) = result.session {
        updated.refresh_token = sess.refresh_token.clone();
        updated.expires_at = sess.expires_at;
    }
    save_session(&updated)?;

    Ok(Some(AuthResult {
        user_id: result.user_id,
        device_id: result.device_id,
        access_token: result.access_token,
        session: Some(updated),
    }))
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
    .context("PoW computation panicked")?;
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

/// Link this TUI client to an existing account using a link token
/// generated on another device (iOS/Desktop Settings → Add Device).
///
/// Generates fresh device keys, then calls `ConfirmDeviceLink` with the token.
pub async fn link_existing_device(client: &GrpcClient, link_token: &str) -> Result<AuthResult> {
    // 1. Generate fresh device keys (same as register_new_device)
    let signing_pair = Ed25519KeyPair::generate();
    let identity_pair = X25519KeyPair::generate();
    let spk_pair = X25519KeyPair::generate();

    let device_id = derive_device_id(&identity_pair.public_key);

    let prologue = build_prologue(SuiteID::CLASSIC);
    let mut spk_msg = prologue;
    spk_msg.extend_from_slice(&spk_pair.public_key);
    let sk = signing_pair.get_signing_key();
    let spk_sig = sk.sign(&spk_msg);

    // Build CFE-encoded private keys
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

    client.set_device_id(Some(device_id.clone()));
    let pubs = crate::grpc::device_public_keys(
        &signing_pair.public_key,
        &identity_pair.public_key,
        &spk_pair.public_key,
        &spk_sig.to_bytes(),
    );
    let tokens = crate::grpc::confirm_device_link(client, link_token, &device_id, pubs)
        .await
        .context("confirm device link")?;
    let user_id = tokens.user_id;
    let access_token = tokens.access_token;
    let refresh_token = tokens.refresh_token;
    let expires_at = tokens.expires_at;
    let _ = keys_cfe_data;

    // 3. Build session (caller is responsible for saving — encrypted or plaintext)
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
