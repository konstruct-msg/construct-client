//! Privacy Pass tokens: one goes with every sealed message (construct-docs
//! decisions/intake-key-is-the-accounts-not-the-devices.md, point 5; iOS `BlindTokenService`,
//! `TokenWalletService`). A token proves the sender was issued one without saying who: the
//! nonce is blinded before the issuer sees it (VOPRF, Ristretto255, in the core).
//!
//! The wallet is filled in batches of 20 (the server's limit a call) toward one hour of the
//! server's budget, 120, and spent one token a logical message to one account: further envelopes
//! of the same message to that account name the same spend id and ride on it. Successful
//! batches are spaced by 90 s, our own pacing; the issuer's refusals are waited out (the hourly
//! cap to the next UTC hour). An empty wallet sends without a token, as iOS does: the
//! certificate seal still hides the sender.
//!
//! A batch is checked against the issuer key pinned here (DLEQ): one key for everyone, so the
//! issuer cannot give a user tokens of a key of their own to recognise them by.

use std::collections::VecDeque;
use std::time::{Duration, SystemTime};

use construct_core::crypto::privacy_pass as pp;

/// Blinded points a call; the server's bound.
pub const BATCH: usize = 20;
/// Filled toward this: one hour of the server's issuance budget.
pub const BANK: usize = 120;
/// Below this the wallet is cold: filled at once, batch after batch, without our pacing.
pub const COLD: usize = 10;
/// Never held more than this.
pub const MAX: usize = 500;
/// Between successful batches.
pub const PACING: Duration = Duration::from_secs(90);
/// After a transport failure or a refused access token.
pub const TRANSIENT_RETRY: Duration = Duration::from_secs(120);
/// After the issuer said it is not configured, or the batch did not verify.
pub const REFUSED_RETRY: Duration = Duration::from_secs(3600);

/// The wallet in the account's store.
pub const WALLET_KEY: &str = "stealth_token_wallet";

/// Issuer public keys `K = k·G` by `issuer_key_version`, as iOS pins them
/// (`BlindTokenService.issuerKeyPins`; v1 is `zFQy29lYJWV8AkJPtya3/P+xlS/t9bDJqHWuGG5qKTM=`).
const ISSUER_PINS: &[(u32, [u8; 32])] = &[(
    1,
    [
        0xcc, 0x54, 0x32, 0xdb, 0xd9, 0x58, 0x25, 0x65, 0x7c, 0x02, 0x42, 0x4f, 0xb7, 0x26, 0xb7,
        0xfc, 0xff, 0xb1, 0x95, 0x2f, 0xed, 0xf5, 0xb0, 0xc9, 0xa8, 0x75, 0xae, 0x18, 0x6e, 0x6a,
        0x29, 0x33,
    ],
)];

fn pinned(version: u32) -> Option<&'static [u8; 32]> {
    ISSUER_PINS
        .iter()
        .find(|(v, _)| *v == version)
        .map(|(_, k)| k)
}

/// A finalized token and the nonce it was made from; both go to the server when spent.
#[derive(Clone, PartialEq, Eq)]
pub struct Token {
    pub nonce: [u8; 32],
    pub token: [u8; 32],
}

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Token(..)")
    }
}

/// The tokens held, oldest first.
#[derive(Debug, Default)]
pub struct Wallet {
    tokens: VecDeque<Token>,
}

impl Wallet {
    /// As kept: 64 bytes a token, nonce then token. Anything else reads as empty.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let tokens = if bytes.len().is_multiple_of(64) {
            bytes
                .chunks(64)
                .take(MAX)
                .map(|c| Token {
                    nonce: c[..32].try_into().expect("32"),
                    token: c[32..].try_into().expect("32"),
                })
                .collect()
        } else {
            VecDeque::new()
        };
        Self { tokens }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.tokens
            .iter()
            .flat_map(|t| t.nonce.iter().chain(t.token.iter()).copied())
            .collect()
    }

    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    /// Add `tokens`, up to [`MAX`] held.
    pub fn deposit(&mut self, tokens: Vec<Token>) {
        let room = MAX.saturating_sub(self.tokens.len());
        self.tokens.extend(tokens.into_iter().take(room));
    }

    pub fn take(&mut self) -> Option<Token> {
        self.tokens.pop_front()
    }
}

/// How an issuance ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Issued(usize),
    /// The hourly cap (RESOURCE_EXHAUSTED).
    RateLimited,
    /// Issuance not configured on the server.
    Disabled,
    Unauthenticated,
    /// The batch did not verify against the pinned issuer key.
    Rejected,
    Transport(String),
    Malformed,
}

/// When to ask the issuer again after `outcome`, if it was not a success.
pub fn retry_at(outcome: &Outcome, now: SystemTime) -> SystemTime {
    match outcome {
        Outcome::Issued(_) => now,
        Outcome::Transport(_) | Outcome::Unauthenticated => now + TRANSIENT_RETRY,
        // The server counts by the UTC hour (`timestamp / 3600`): its next hour.
        Outcome::RateLimited => {
            let secs = now
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            SystemTime::UNIX_EPOCH + Duration::from_secs((secs / 3600 + 1) * 3600)
        }
        Outcome::Disabled | Outcome::Rejected | Outcome::Malformed => now + REFUSED_RETRY,
    }
}

/// The issuer as this device last heard from it.
#[derive(Debug, Default)]
pub struct Issuance {
    pub in_flight: bool,
    /// Our own spacing of successful batches.
    pub pacing_until: Option<SystemTime>,
    /// The issuer refused: not asked again before this.
    pub backoff_until: Option<SystemTime>,
}

impl Issuance {
    /// Whether to ask for a batch now, holding `balance` tokens. An empty wallet outweighs our
    /// own pacing — that pacing is politeness, and a message without a token is what it costs.
    pub fn should_issue(&self, balance: usize, now: SystemTime) -> bool {
        if self.in_flight || balance >= BANK {
            return false;
        }
        if self.backoff_until.is_some_and(|t| t > now) {
            return false;
        }
        balance < COLD || self.pacing_until.is_none_or(|t| t <= now)
    }

    /// A batch ended: what it means for the next one.
    pub fn ended(&mut self, outcome: &Outcome, now: SystemTime) {
        self.in_flight = false;
        match outcome {
            Outcome::Issued(_) => {
                self.pacing_until = Some(now + PACING);
                self.backoff_until = None;
            }
            other => self.backoff_until = Some(retry_at(other, now)),
        }
    }
}

/// A batch blinded and ready to send: the points for the issuer, what finalizes them here.
pub struct Blinded {
    pub points: Vec<Vec<u8>>,
    nonces: Vec<[u8; 32]>,
    factors: Vec<Vec<u8>>,
}

/// `n` fresh nonces, blinded.
pub fn blind(n: usize) -> Result<Blinded, Outcome> {
    let mut batch = Blinded {
        points: Vec::with_capacity(n),
        nonces: Vec::with_capacity(n),
        factors: Vec::with_capacity(n),
    };
    for _ in 0..n {
        let nonce: [u8; 32] = rand::random();
        let packed = pp::pp_blind_token(nonce.to_vec()).map_err(|_| Outcome::Malformed)?;
        if packed.len() != 64 {
            return Err(Outcome::Malformed);
        }
        batch.points.push(packed[..32].to_vec());
        batch.factors.push(packed[32..].to_vec());
        batch.nonces.push(nonce);
    }
    Ok(batch)
}

/// What the issuer answered, as `IssueTokensResponse` carries it.
pub struct Evaluated {
    pub points: Vec<Vec<u8>>,
    pub server_pubkey: Vec<u8>,
    pub dleq_proof: Vec<u8>,
    pub key_version: u32,
}

/// The tokens of `batch` from the issuer's answer. Fewer points than asked is the rest of the
/// hourly cap; more is an answer that cannot be finalized. With the key version pinned the
/// batch must carry a DLEQ proof against the pin — never against the key the answer echoes: a
/// key of its own for one user would let the issuer recognise their tokens. A point the core
/// cannot finalize (off the curve) is left out.
pub fn finalize(batch: &Blinded, answer: &Evaluated) -> Result<Vec<Token>, Outcome> {
    let issued = answer.points.len();
    if issued == 0 || issued > batch.points.len() {
        return Err(Outcome::Malformed);
    }
    if let Some(pin) = pinned(answer.key_version) {
        if answer.dleq_proof.is_empty()
            || !pp::pp_verify_dleq(
                batch.points[..issued].to_vec(),
                answer.points.clone(),
                answer.dleq_proof.clone(),
                pin.to_vec(),
            )
        {
            return Err(Outcome::Rejected);
        }
    } else {
        tracing::warn!(
            version = answer.key_version,
            "token issuer key not pinned: the batch is not checked against it"
        );
    }
    let mut tokens = Vec::with_capacity(issued);
    for (i, point) in answer.points.iter().enumerate() {
        let Ok(token) = pp::pp_finalize_token(
            point.clone(),
            batch.factors[i].clone(),
            batch.nonces[i].to_vec(),
        ) else {
            continue;
        };
        if let Ok(token) = <[u8; 32]>::try_from(token) {
            tokens.push(Token {
                nonce: batch.nonces[i],
                token,
            });
        }
    }
    if tokens.is_empty() {
        return Err(Outcome::Rejected);
    }
    Ok(tokens)
}

/// One batch from the issuer: `AuthService.IssueTokens` on the authenticated client (the
/// blinding is what keeps the tokens from naming us).
pub async fn issue(grpc: &crate::grpc::GrpcClient, n: usize) -> Result<Vec<Token>, Outcome> {
    let batch = blind(n.clamp(1, BATCH))?;
    let answer = crate::grpc::issue_tokens(grpc, &batch.points)
        .await
        .map_err(|e| classify(&e))?;
    finalize(&batch, &answer)
}

fn classify(e: &crate::grpc::GrpcError) -> Outcome {
    use crate::grpc::GrpcError;
    // gRPC codes: 8 RESOURCE_EXHAUSTED, 14 UNAVAILABLE.
    match e {
        GrpcError::Status { code: 8, .. } => Outcome::RateLimited,
        GrpcError::Status { code: 14, message } if message.contains("not configured") => {
            Outcome::Disabled
        }
        GrpcError::Unauthenticated(_) => Outcome::Unauthenticated,
        other => Outcome::Transport(other.to_string()),
    }
}

/// One logical message to one account pays once: the first envelope that carries a token, and
/// every other envelope of it to that account names the same spend id.
#[derive(Debug, Default)]
pub struct SpendUnits {
    units: std::collections::HashMap<(String, String), (Vec<u8>, bool)>,
    order: VecDeque<(String, String)>,
}

/// Units remembered; a message's envelopes are queued together, long before this many others.
const UNITS_KEPT: usize = 1024;

impl SpendUnits {
    /// The spend id of `message_id` to `account`, and whether an envelope of it already paid.
    pub fn unit(&mut self, account: &str, message_id: &str) -> (Vec<u8>, bool) {
        let key = (account.to_owned(), message_id.to_owned());
        if let Some((id, paid)) = self.units.get(&key) {
            return (id.clone(), *paid);
        }
        if self.order.len() >= UNITS_KEPT
            && let Some(old) = self.order.pop_front()
        {
            self.units.remove(&old);
        }
        let id = rand::random::<[u8; 32]>().to_vec();
        self.units.insert(key.clone(), (id.clone(), false));
        self.order.push_back(key);
        (id, false)
    }

    pub fn paid(&mut self, account: &str, message_id: &str) {
        if let Some(unit) = self
            .units
            .get_mut(&(account.to_owned(), message_id.to_owned()))
        {
            unit.1 = true;
        }
    }
}

#[cfg(test)]
mod tests;
