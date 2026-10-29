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
