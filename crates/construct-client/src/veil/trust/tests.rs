use super::*;
use construct_veil_protocol::{AuthKey, Ticket};
use ed25519_dalek::{Signer, SigningKey};

const NOW: i64 = 1_800_000_000;
const SEED: [u8; 32] = [7; 32];
const SPKI: &str = "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12";

fn issuer_key() -> [u8; 32] {
    SigningKey::from_bytes(&SEED).verifying_key().to_bytes()
}

fn sign(message: &[u8]) -> String {
    let sig = SigningKey::from_bytes(&SEED).sign(message).to_bytes();
    format!(
        "ed25519:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig)
    )
}

fn bearer(not_after: u64) -> Vec<u8> {
    let ticket = Ticket {
        ticket_id: [1; 16],
        auth_key: AuthKey::new([2; 32]),
        not_before: 0,
        not_after,
        suite_id: 1,
    };
    Capability::sign(ticket, String::new(), &SEED)
        .unwrap()
        .encode()
        .to_vec()
}

fn bound(pk: [u8; 32], not_after: u64) -> Vec<u8> {
    CapabilityV2::sign([3; 16], pk, 0, 0, not_after, 1, String::new(), &SEED)
        .unwrap()
        .encode()
        .to_vec()
}

fn entry<'a>(
    relay: &'a str,
    spki: &'a str,
    cap: &'a [u8],
    version: u32,
    sig: &'a str,
) -> Entry<'a> {
    Entry {
        relay,
        sni: "cdn.example",
        spki,
        not_after: NOW + 3600,
        capability: cap,
        version,
        signature: sig,
    }
}

/// The coordinates are signed as iOS signs and checks them — keys sorted, compact, slashes as
/// they are.
#[test]
fn the_tuple_is_canonical_json() {
    assert_eq!(
        String::from_utf8(canonical_tuple("front.example:443", "a/b", SPKI, 5)).unwrap(),
        format!(r#"{{"exp":5,"relay":"front.example:443","sni":"a/b","spki":"{SPKI}"}}"#)
    );
}

/// An issued front is taken when its coordinates are signed and its capability is the issuer's,
/// live and bound to this device; each of those failing refuses it.
#[test]
fn an_issued_front_passes_every_gate_or_is_refused() {
    let our_pk = [9; 32];
    let cap = bound(our_pk, (NOW + 3600) as u64);
    let sig = sign(&canonical_tuple(
        "front.example:443",
        "cdn.example",
        SPKI,
        NOW + 3600,
    ));
    let key = issuer_key();

    let front = accept_entry_with(
        &entry("front.example:443", SPKI, &cap, 2, &sig),
        &[],
        &our_pk,
        NOW,
        &key,
    )
    .expect("a well-issued front");
    assert_eq!(
        (front.relay.as_str(), front.version),
        ("front.example:443", 2)
    );
    assert_eq!(front.not_after, NOW + 3600);

    // Another address under the same signature.
    assert_eq!(
        accept_entry_with(
            &entry("evil.example:443", SPKI, &cap, 2, &sig),
            &[],
            &our_pk,
            NOW,
            &key
        ),
        Err(Refused::BadSignature)
    );
    // Signed by a key that is not the relay key.
    assert_eq!(
        accept_entry_with(
            &entry("front.example:443", SPKI, &cap, 2, &sig),
            &[],
            &our_pk,
            NOW,
            &[1; 32]
        ),
        Err(Refused::BadSignature)
    );
    // Someone else's key-bound capability.
    assert_eq!(
        accept_entry_with(
            &entry("front.example:443", SPKI, &cap, 2, &sig),
            &[],
            &[8; 32],
            NOW,
            &key
        ),
        Err(Refused::NotOurKey)
    );
    // Expired.
    let old = bound(our_pk, (NOW - 1) as u64);
    assert_eq!(
        accept_entry_with(
            &entry("front.example:443", SPKI, &old, 2, &sig),
            &[],
            &our_pk,
            NOW,
            &key
        ),
        Err(Refused::Expired)
    );
    // A capability whose own signature does not hold.
    let mut forged = cap.clone();
    *forged.last_mut().unwrap() ^= 1;
    assert_eq!(
        accept_entry_with(
            &entry("front.example:443", SPKI, &forged, 2, &sig),
            &[],
            &our_pk,
            NOW,
            &key
        ),
        Err(Refused::BadCapability)
    );
    // The front is known here with another key: a signature does not re-pin it.
    let known = Front {
        spki: "cd".repeat(32),
        ..front.clone()
    };
    assert_eq!(
        accept_entry_with(
            &entry("front.example:443", SPKI, &cap, 2, &sig),
            &[known],
            &our_pk,
            NOW,
            &key
        ),
        Err(Refused::SpkiChanged)
    );
}

fn link(fields: serde_json::Value) -> String {
    let mut object: BTreeMap<String, serde_json::Value> = serde_json::from_value(fields).unwrap();
    let signature = sign(&serde_json::to_vec(&object).unwrap());
    object.insert("signature".into(), signature.into());
    format!(
        "konstruct://veil-config?d={}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&object).unwrap())
    )
}

/// A config link, as make_config_link writes one: the whole object signed, the bearer capability
/// inside checked too. Changing any field breaks it; the SNI defaults to the host.
#[test]
fn a_config_link_is_taken_only_as_signed() {
    let cap = base64::engine::general_purpose::STANDARD.encode(bearer((NOW + 7200) as u64));
    let fields = serde_json::json!({
        "relay": "front.example:443",
        "spki": SPKI,
        "capability": cap,
        "exp": NOW + 3600,
    });
    let key = issuer_key();
    let good = link(fields.clone());
    let front = import_link_with(&good, &[], NOW, &key).expect("a signed link");
    assert_eq!(front.sni, "front.example");
    assert_eq!(front.version, 1);
    assert_eq!(
        front.not_after,
        NOW + 3600,
        "the earlier of the link's and the capability's end"
    );
    // Pasted with line breaks.
    let wrapped: String = good
        .chars()
        .collect::<Vec<_>>()
        .chunks(20)
        .map(|c| c.iter().collect::<String>() + "\n")
        .collect();
    assert!(import_link_with(&wrapped, &[], NOW, &key).is_ok());

    // A field changed after signing.
    let mut object: BTreeMap<String, serde_json::Value> =
        serde_json::from_slice(&base64url(good.split_once("?d=").unwrap().1).unwrap()).unwrap();
    object.insert("relay".into(), "evil.example:443".into());
    let tampered = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&object).unwrap());
    assert_eq!(
        import_link_with(&tampered, &[], NOW, &key),
        Err(Refused::BadSignature)
    );

    // Expired link.
    let mut stale = fields;
    stale["exp"] = (NOW - 1).into();
    assert_eq!(
        import_link_with(&link(stale), &[], NOW, &key),
        Err(Refused::Expired)
    );
}

/// The relay key is iOS's (`VEILConfig.relayConfigSigningKey`, copied from `Constants.swift`
/// as text) and a valid Ed25519 key. It used to be a byte array typed by hand with two bytes
/// swapped — not a point on the curve — so every real link and voucher was refused while the
/// tests, signing with their own key, passed.
#[test]
fn the_relay_key_is_the_one_ios_pins() {
    assert_eq!(
        RELAY_CONFIG_SIGNING_KEY_HEX,
        "8a0ee71cd95f86a9f6877211accefaff6bb97f3051b3b2141f1c71690b9a2dcf"
    );
    assert!(VerifyingKey::from_bytes(&relay_config_signing_key()).is_ok());
}
