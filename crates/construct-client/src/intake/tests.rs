use super::*;

fn key(generation: u32, byte: u8) -> IntakeKeyState {
    IntakeKeyState {
        generation,
        key: vec![byte; 32],
    }
}

/// iOS's `IntakeOwnKey.next`, case by case: what this device holds against what the server
/// says of the account.
#[test]
fn our_key_is_settled_by_state_as_on_ios() {
    // A key of a generation is used as it is, whatever the server says.
    assert_eq!(next(Some(&key(3, 1)), 5, true), Next::Use(key(3, 1)));
    // A per-device key from before, on an account without a generation: it becomes 1.
    assert_eq!(next(Some(&key(0, 1)), 0, false), Next::Promote(key(1, 1)));
    assert_eq!(next(Some(&key(0, 1)), 0, true), Next::Promote(key(1, 1)));
    // The account moved on and is alive: the key is due from our devices.
    assert_eq!(next(Some(&key(0, 1)), 2, true), Next::Wait);
    assert_eq!(next(None, 2, true), Next::Wait);
    // Nothing alive anywhere: a new generation above the server's.
    assert_eq!(next(Some(&key(0, 1)), 2, false), Next::Mint { above: 2 });
    assert_eq!(next(None, 2, false), Next::Mint { above: 2 });
    // The account's first device.
    assert_eq!(next(None, 0, false), Next::Mint { above: 0 });
    // Tags but no generation (a server from before): not alive by generation.
    assert_eq!(next(None, 0, true), Next::Mint { above: 0 });
}

/// iOS's record: the generation big-endian, then the key; a bare key is generation 0.
#[test]
fn a_key_is_kept_as_ios_keeps_it() {
    let state = key(0x0102_0304, 7);
    let bytes = encode(&state);
    assert_eq!(&bytes[..4], &[1, 2, 3, 4]);
    assert_eq!(bytes.len(), 36);
    assert_eq!(decode(&bytes), Some(state));
    assert_eq!(decode(&[9; 32]), Some(key(0, 9)));
    assert_eq!(decode(&[9; 33]), None);
}

#[test]
fn a_window_is_seven_days_of_the_cores_tags() {
    let state = key(1, 5);
    let tags = window(&state, "Account-ID", 100);
    let epochs: Vec<u64> = tags.iter().map(|(e, _)| *e).collect();
    assert_eq!(epochs, (100..107).collect::<Vec<_>>());
    for (epoch, tag) in &tags {
        assert_eq!(
            tag,
            &intake_tag(&state.key, "account-id", *epoch).unwrap(),
            "the tag a contact derives for us"
        );
    }
    assert!(should_publish(None, 100));
    assert!(!should_publish(Some(100), 100));
    assert!(should_publish(Some(99), 100));
    assert!(should_publish(Some(101), 100), "a clock that went back");
}

/// A changed key goes out again: to our devices, and to the server.
#[test]
fn adopting_a_key_forgets_who_had_the_old_one() {
    let local = crate::local_store::LocalStore::open_in_memory().unwrap();
    let store = Store(&local);
    assert_eq!(store.own(), Held::Absent);
    assert!(store.adopt(&key(1, 1)));
    store.mark_sent(&["d1".into(), "d2".into()]);
    store.mark_sent(&["d2".into()]);
    store.set_published_epoch(100);
    assert_eq!(store.sent_to(), ["d1", "d2"]);
    assert_eq!(store.published_epoch(), Some(100));
    assert!(store.adopt(&key(2, 2)));
    assert_eq!(store.own(), Held::Key(key(2, 2)));
    assert!(store.sent_to().is_empty());
    assert_eq!(store.published_epoch(), None);
}

/// Our card carries the key and its generation; a card with no key is no key.
#[test]
fn a_card_carries_the_key_and_its_generation() {
    assert_eq!(card_key(&own_card(&key(4, 3))), Some(key(4, 3)));
    use prost::Message;
    let empty = crate::proto::core::v1::ContactCard::default().encode_to_vec();
    assert_eq!(card_key(&empty), None);
}

/// From one of our devices, inside SENDER_SYNC: the card is our own account's key.
#[test]
fn a_card_from_our_device_is_our_key() {
    let frame = crate::knst::frame_whole(
        &own_card(&key(2, 8)),
        crate::knst::CONTENT_CONTACT_CARD,
        "card-1",
    );
    assert_eq!(
        crate::own_copy::read(&frame),
        crate::own_copy::Copy::IntakeKey(key(2, 8))
    );
}

/// A contact's key is theirs by account, and a lower or equal generation does not replace it.
#[test]
fn a_contacts_key_is_kept_by_account_and_only_moves_forward() {
    let local = crate::local_store::LocalStore::open_in_memory().unwrap();
    let store = Store(&local);
    assert_eq!(store.peer("bob"), None);
    assert!(store.offer_peer("Bob", &key(2, 2)));
    assert_eq!(
        store.peer("bob"),
        Some(key(2, 2)),
        "filed by the account, any case"
    );
    assert!(!store.offer_peer("bob", &key(1, 1)), "a late card");
    assert!(!store.offer_peer("bob", &key(2, 3)), "the same generation");
    assert_eq!(store.peer("bob"), Some(key(2, 2)));
    assert!(store.offer_peer("bob", &key(3, 3)));
    assert_eq!(store.peer("bob"), Some(key(3, 3)));
    let short = IntakeKeyState {
        generation: 9,
        key: vec![1; 31],
    };
    assert!(!store.offer_peer("bob", &short), "a malformed key");
    assert_eq!(store.peer("bob"), Some(key(3, 3)));
    assert_eq!(store.peer("carol"), None);
}

/// A refused key rests for the epoch it was refused in, for that contact only.
#[test]
fn a_refused_key_rests_until_the_epoch_rolls() {
    let mut suspended = Suspended::default();
    suspended.suspend("Bob", 100);
    assert!(suspended.is_suspended("bob", 100));
    assert!(!suspended.is_suspended("bob", 101));
    assert!(!suspended.is_suspended("carol", 100));
    suspended.suspend("carol", 101);
    assert!(
        !suspended.is_suspended("bob", 100),
        "past epochs are dropped"
    );
    assert!(suspended.is_suspended("carol", 101));
}

#[test]
fn only_not_accepted_suspends() {
    use crate::proto::services::v1::IntakeVerdict;
    assert!(suspends(IntakeVerdict::NotAccepted as i32));
    for v in [
        IntakeVerdict::Unspecified,
        IntakeVerdict::None,
        IntakeVerdict::Accepted,
        IntakeVerdict::Unchecked,
    ] {
        assert!(!suspends(v as i32), "{v:?}");
    }
}

/// What the server opens with its token key is the tag the recipient published for today.
#[test]
fn the_server_opens_the_tag_the_contact_published() {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use x25519_dalek::{PublicKey, StaticSecret};
    let server = StaticSecret::from([7u8; 32]);
    let server_pub = PublicKey::from(&server).as_bytes().to_vec();
    let theirs = key(4, 9);
    let sealed = sealed_tag(&theirs, "bob", 100, server_pub).unwrap();

    let eph = PublicKey::from(<[u8; 32]>::try_from(&sealed[..32]).unwrap());
    let shared = server.diffie_hellman(&eph);
    let mut k = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(None, shared.as_bytes())
        .expand(b"construct-token-seal-v1", &mut k)
        .unwrap();
    let opened = chacha20poly1305::ChaCha20Poly1305::new((&k).into())
        .decrypt(sealed[32..44].into(), &sealed[44..])
        .unwrap();
    assert_eq!(
        opened,
        window(&theirs, "bob", 100)[0].1,
        "the tag of their window for this epoch"
    );
    assert_eq!(sealed_tag(&theirs, "bob", 100, vec![1; 31]), None);
}

/// A card names a key the server holds: published, and still inside the window.
#[test]
fn the_server_holds_a_key_for_a_week_from_its_publish() {
    assert!(!server_holds(None, 100));
    assert!(server_holds(Some(100), 100));
    assert!(server_holds(Some(100), 106));
    assert!(!server_holds(Some(100), 107), "the window ran out");
    assert!(!server_holds(Some(101), 100), "a marker from the future");
}

#[test]
fn a_rotation_goes_past_both_generations() {
    assert_eq!(rotation_floor(Some(&key(3, 1)), Some(5)), 5);
    assert_eq!(rotation_floor(Some(&key(4, 1)), Some(1)), 4);
    assert_eq!(
        rotation_floor(Some(&key(3, 1)), None),
        3,
        "server not asked"
    );
    assert_eq!(rotation_floor(None, Some(2)), 2);
    assert_eq!(rotation_floor(None, None), 0);
}

/// A publish that lands after a newer key was adopted marks nothing.
#[test]
fn a_publish_marks_only_the_key_still_ours() {
    let local = crate::local_store::LocalStore::open_in_memory().unwrap();
    let store = Store(&local);
    store.adopt(&key(1, 1));
    assert!(store.mark_published(&key(1, 1), 100));
    assert_eq!(store.published_epoch(), Some(100));
    store.adopt(&key(2, 2));
    assert!(!store.mark_published(&key(1, 1), 100));
    assert_eq!(store.published_epoch(), None);
}

/// The lazy card waits for the publish of the current key.
#[test]
fn a_card_waits_for_the_publish() {
    let local = crate::local_store::LocalStore::open_in_memory().unwrap();
    let store = Store(&local);
    assert_eq!(store.card_key(100), None, "no key");
    store.adopt(&key(0, 1));
    store.set_published_epoch(100);
    assert_eq!(store.card_key(100), None, "a key of no generation");
    store.adopt(&key(2, 2));
    assert_eq!(store.card_key(100), None, "not published since it changed");
    store.set_published_epoch(100);
    assert_eq!(store.card_key(100), Some(key(2, 2)));
    assert_eq!(store.card_key(107), None, "its window ran out");
}
