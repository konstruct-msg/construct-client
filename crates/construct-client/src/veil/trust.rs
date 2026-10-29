//! Which fronts this device takes, and with what: iOS `VeilRelayTrust`, `VeilEntryPointSignature`
//! and `VeilConfigImporter`, held to the same bytes.
//!
//! No front is built in ([[no-bundled-veil-fronts]]). A front comes signed by the key every
//! client pins, `relayConfigSigningKey`: as an entry point the server issues with a capability,
//! or in a `konstruct://veil-config` link someone hands over. Its capability carries the same
//! issuer's signature and a validity window, checked here as the relay checks it. A front this
//! device already knows keeps its key: an entry naming the same address with another SPKI is
//! refused, whatever signs it.

use std::collections::BTreeMap;

use base64::Engine;
use construct_veil_protocol::{Capability, CapabilityV2};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// `VEILConfig.relayConfigSigningKey` (iOS `Constants.swift`), as it is written there: signs
/// the relay coordinates, the config links, the vouchers and every capability. Kept as the same
/// hex string so the two can be compared by eye and by test, not retyped byte by byte.
pub const RELAY_CONFIG_SIGNING_KEY_HEX: &str =
    "8a0ee71cd95f86a9f6877211accefaff6bb97f3051b3b2141f1c71690b9a2dcf";

pub fn relay_config_signing_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    hex::decode_to_slice(RELAY_CONFIG_SIGNING_KEY_HEX, &mut key)
        .expect("the relay key is 64 hex digits");
    key
}

/// A front this device may use, and the capability it presents there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Front {
    /// `host:port`.
    pub relay: String,
    pub sni: String,
    /// Hex SHA-256 of the front's SubjectPublicKeyInfo: the TLS pin.
    pub spki: String,
    /// Unix seconds; the capability's end.
    pub not_after: i64,
    /// The signed capability blob, base64 (standard).
    pub capability: String,
    /// 1: a bearer capability (AUTH v2); 2: bound to this device's `veil_pk` (AUTH v3).
    pub version: u32,
}

impl Front {
    pub fn usable_at(&self, now: i64) -> bool {
        self.not_after > now
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    BadSignature,
    BadCapability,
    Expired,
    /// A key-bound capability for another device's key.
    NotOurKey,
    /// The address is known here with another key.
    SpkiChanged,
    Malformed(&'static str),
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadSignature => f.write_str("not signed by the Konstruct relay key"),
            Self::BadCapability => f.write_str("its capability is not the issuer's"),
            Self::Expired => f.write_str("it has expired"),
            Self::NotOurKey => f.write_str("its capability is for another device"),
            Self::SpkiChanged => f.write_str("the front is known here with another key"),
            Self::Malformed(what) => write!(f, "malformed: {what}"),
        }
    }
}

/// `ed25519:<base64url>` by `key` over `message`.
fn signed(signature: &str, message: &[u8], key: &[u8; 32]) -> bool {
    let Some(sig) = signature
        .strip_prefix("ed25519:")
        .and_then(base64url)
        .and_then(|b| Signature::from_slice(&b).ok())
    else {
        return false;
    };
    VerifyingKey::from_bytes(key).is_ok_and(|k| k.verify(message, &sig).is_ok())
}

fn base64url(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .ok()
}

/// The bytes an entry point's coordinates are signed as: compact JSON, keys sorted, slashes
/// unescaped (`VeilEntryPointSignature.canonicalTuple`).
pub fn canonical_tuple(relay: &str, sni: &str, spki: &str, exp: i64) -> Vec<u8> {
    let mut m = BTreeMap::new();
    m.insert("exp", serde_json::Value::from(exp));
    m.insert("relay", relay.into());
    m.insert("sni", sni.into());
    m.insert("spki", spki.into());
    serde_json::to_vec(&m).expect("a map of strings and a number encodes")
}

/// A capability blob, checked: the issuer's signature, its window at `now`, and for a key-bound
/// one, that it is bound to `our_pk`. Returns its end (Unix seconds).
pub fn check_capability(
    blob: &[u8],
    version: u32,
    our_pk: Option<&[u8; 32]>,
    now: i64,
    key: &[u8; 32],
) -> Result<i64, Refused> {
    let now_u = u64::try_from(now).unwrap_or(0);
    let not_after = match version {
        1 => {
            let cap = Capability::decode_slice(blob).ok_or(Refused::BadCapability)?;
            if !cap.verify_signature(key) {
                return Err(Refused::BadCapability);
            }
            if !cap.is_valid_at(now_u) {
                return Err(Refused::Expired);
            }
            cap.ticket.not_after
        }
        2 => {
            let cap = CapabilityV2::decode_slice(blob).ok_or(Refused::BadCapability)?;
            if !cap.verify_signature(key) {
                return Err(Refused::BadCapability);
            }
            if !cap.is_valid_at(now_u) {
                return Err(Refused::Expired);
            }
            if our_pk.is_some_and(|pk| *pk != cap.veil_pk) {
                return Err(Refused::NotOurKey);
            }
            cap.not_after
        }
        _ => return Err(Refused::Malformed("capability version")),
    };
    i64::try_from(not_after).map_err(|_| Refused::Malformed("capability window"))
}

/// What the server issued for one front, before it is trusted.
pub struct Entry<'a> {
    pub relay: &'a str,
    pub sni: &'a str,
    pub spki: &'a str,
    pub not_after: i64,
    pub capability: &'a [u8],
    pub version: u32,
    pub signature: &'a str,
}

/// An issued entry point, through iOS's gates: its coordinates are signed, its capability is the
/// issuer's and live (and ours, if key-bound), and an address already known here keeps its key.
pub fn accept_entry(
    e: &Entry<'_>,
    known: &[Front],
    our_pk: &[u8; 32],
    now: i64,
) -> Result<Front, Refused> {
    accept_entry_with(e, known, our_pk, now, &relay_config_signing_key())
}

fn accept_entry_with(
    e: &Entry<'_>,
    known: &[Front],
    our_pk: &[u8; 32],
    now: i64,
    key: &[u8; 32],
) -> Result<Front, Refused> {
    if e.relay.is_empty() || e.sni.is_empty() || !valid_spki(e.spki) {
        return Err(Refused::Malformed("coordinates"));
    }
    if !signed(
        e.signature,
        &canonical_tuple(e.relay, e.sni, e.spki, e.not_after),
        key,
    ) {
        return Err(Refused::BadSignature);
    }
    let not_after = check_capability(e.capability, e.version, Some(our_pk), now, key)?;
    pinned_alike(known, e.relay, e.spki)?;
    Ok(Front {
        relay: e.relay.to_owned(),
        sni: e.sni.to_owned(),
        spki: e.spki.to_ascii_lowercase(),
        not_after,
        capability: base64::engine::general_purpose::STANDARD.encode(e.capability),
        version: e.version,
    })
}

fn valid_spki(spki: &str) -> bool {
    spki.len() == 64 && spki.bytes().all(|b| b.is_ascii_hexdigit())
}

fn pinned_alike(known: &[Front], relay: &str, spki: &str) -> Result<(), Refused> {
    match known.iter().find(|f| f.relay.eq_ignore_ascii_case(relay)) {
        Some(f) if !f.spki.eq_ignore_ascii_case(spki) => Err(Refused::SpkiChanged),
        _ => Ok(()),
    }
}

/// A `konstruct://veil-config?d=<base64url JSON>` link, a bare blob, or one pasted with spaces:
/// the front it names, checked (`VeilConfigImporter.parseAndVerify`). The whole object minus
/// `signature` is signed, as canonical JSON.
pub fn import_link(input: &str, known: &[Front], now: i64) -> Result<Front, Refused> {
    import_link_with(input, known, now, &relay_config_signing_key())
}

fn import_link_with(
    input: &str,
    known: &[Front],
    now: i64,
    key: &[u8; 32],
) -> Result<Front, Refused> {
    let compact: String = input.split_whitespace().collect();
    let blob = compact
        .split_once("?d=")
        .map_or(compact.as_str(), |(_, d)| d.split('&').next().unwrap_or(d));
    let json = base64url(blob).ok_or(Refused::Malformed("not a config link"))?;
    let mut object: BTreeMap<String, serde_json::Value> =
        serde_json::from_slice(&json).map_err(|_| Refused::Malformed("not a config link"))?;
    let signature = match object.remove("signature") {
        Some(serde_json::Value::String(s)) => s,
        _ => return Err(Refused::BadSignature),
    };
    let canonical = serde_json::to_vec(&object).map_err(|_| Refused::Malformed("config"))?;
    if !signed(&signature, &canonical, key) {
        return Err(Refused::BadSignature);
    }
    let text = |k: &str| object.get(k).and_then(|v| v.as_str()).unwrap_or("");
    let relay = text("relay");
    let spki = text("spki");
    let host = relay.rsplit_once(':').map_or(relay, |(h, _)| h);
    let sni = Some(text("sni")).filter(|s| !s.is_empty()).unwrap_or(host);
    let exp = object.get("exp").and_then(|v| v.as_i64()).unwrap_or(0);
    if relay.is_empty() || !valid_spki(spki) {
        return Err(Refused::Malformed("coordinates"));
    }
    if exp <= now {
        return Err(Refused::Expired);
    }
    let capability = Some(text("capability"))
        .filter(|c| !c.is_empty())
        .unwrap_or(text("ticket"));
    let blob = base64::engine::general_purpose::STANDARD
        .decode(capability)
        .map_err(|_| Refused::Malformed("capability"))?;
    // A link carries a bearer capability, or a key-bound one for whoever made it for us.
    let version = if CapabilityV2::decode_slice(&blob).is_some() {
        2
    } else {
        1
    };
    let not_after = check_capability(&blob, version, None, now, key)?;
    pinned_alike(known, relay, spki)?;
    Ok(Front {
        relay: relay.to_owned(),
        sni: sni.to_owned(),
        spki: spki.to_ascii_lowercase(),
        not_after: not_after.min(exp),
        capability: capability.to_owned(),
        version,
    })
}

#[cfg(test)]
mod tests;
