use super::*;

/// An issuer in this process: the core's own evaluation under key `k`.
fn issuer_answer(batch: &Blinded, k: &[u8; 32], n: usize, key_version: u32) -> Evaluated {
    Evaluated {
        points: batch.points[..n]
            .iter()
            .map(|p| {
                pp::evaluate(k, p.as_slice().try_into().unwrap())
                    .unwrap()
                    .to_vec()
            })
            .collect(),
        server_pubkey: pp::issuer_pubkey(k).unwrap().to_vec(),
        dleq_proof: Vec::new(),
        key_version,
    }
}

const K: [u8; 32] = {
    let mut k = [0u8; 32];
    k[0] = 7;
    k
};
/// A version no pin names: the batch is taken without a DLEQ proof.
const UNPINNED: u32 = 99;

/// The tokens a batch becomes are ones the issuer redeems.
#[test]
fn issued_tokens_redeem_at_the_issuer() {
    let batch = blind(5).unwrap();
    let tokens = finalize(&batch, &issuer_answer(&batch, &K, 5, UNPINNED)).unwrap();
    assert_eq!(tokens.len(), 5);
    for t in &tokens {
        assert!(pp::server_verify(&t.token, &t.nonce, &K).unwrap());
    }
    // Another key does not redeem them.
    let mut other = K;
    other[0] = 9;
    assert!(!pp::server_verify(&tokens[0].token, &tokens[0].nonce, &other).unwrap());
}

/// Fewer points than asked is the rest of the hourly cap; none, or more, is no answer.
#[test]
fn an_answer_is_as_long_as_the_batch_or_shorter() {
    let batch = blind(4).unwrap();
    assert_eq!(
        finalize(&batch, &issuer_answer(&batch, &K, 2, UNPINNED))
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        finalize(&batch, &issuer_answer(&batch, &K, 0, UNPINNED)),
        Err(Outcome::Malformed)
    );
    let mut long = issuer_answer(&batch, &K, 4, UNPINNED);
    long.points.push(long.points[0].clone());
    assert_eq!(finalize(&batch, &long), Err(Outcome::Malformed));
}

/// Under a pinned version the issuer cannot use a key of its own, and must prove its batch.
#[test]
fn a_pinned_issuer_is_held_to_its_pin() {
    let batch = blind(3).unwrap();
    // Under our own key, echoed: no proof against the pin, nothing taken.
    let mut quiet = issuer_answer(&batch, &K, 3, 1);
    assert_eq!(finalize(&batch, &quiet), Err(Outcome::Rejected));
    // A proof that is not one.
    quiet.dleq_proof = vec![1; 64];
    assert_eq!(finalize(&batch, &quiet), Err(Outcome::Rejected));
}

/// What is not on the curve does not become a token.
#[test]
fn a_point_off_the_curve_is_left_out() {
    let batch = blind(2).unwrap();
    let mut answer = issuer_answer(&batch, &K, 2, UNPINNED);
    answer.points[0] = vec![0xff; 32];
    let tokens = finalize(&batch, &answer).unwrap();
    assert_eq!(tokens.len(), 1);
    assert!(pp::server_verify(&tokens[0].token, &tokens[0].nonce, &K).unwrap());
}

#[test]
fn the_wallet_keeps_its_tokens_in_order_and_within_bounds() {
    let token = |b: u8| Token {
        nonce: [b; 32],
        token: [b.wrapping_add(1); 32],
    };
    let mut wallet = Wallet::default();
    wallet.deposit((0..3).map(token).collect());
    let mut back = Wallet::from_bytes(&wallet.to_bytes());
    assert_eq!(back.len(), 3);
    assert_eq!(back.take(), Some(token(0)), "oldest first");
    assert_eq!(back.len(), 2);
    assert!(
        Wallet::from_bytes(&[0; 65]).is_empty(),
        "a torn record reads as nothing"
    );
    let mut full = Wallet::default();
    full.deposit((0..=255u8).cycle().take(MAX + 50).map(token).collect());
    assert_eq!(full.len(), MAX);
}

/// An empty wallet outweighs our pacing; the issuer's refusal, a batch in flight and a full bank
/// do not ask.
#[test]
fn the_issuer_is_asked_when_it_is_worth_it() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let paced = Issuance {
        pacing_until: Some(now + PACING),
        ..Default::default()
    };
    assert!(paced.should_issue(0, now), "empty: pacing yields");
    assert!(paced.should_issue(COLD - 1, now), "cold: pacing yields");
    assert!(!paced.should_issue(COLD + 5, now), "warm: paced");
    assert!(Issuance::default().should_issue(COLD + 5, now));
    assert!(!Issuance::default().should_issue(BANK, now), "banked");
    let refused = Issuance {
        backoff_until: Some(now + Duration::from_secs(10)),
        ..Default::default()
    };
    assert!(!refused.should_issue(0, now), "the issuer said no");
    let busy = Issuance {
        in_flight: true,
        ..Default::default()
    };
    assert!(!busy.should_issue(0, now));
}

/// The hourly cap is the issuer's UTC hour; a blip is two minutes; a success paces.
#[test]
fn refusals_are_waited_out_as_the_issuer_counts() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(3600 * 100 + 55 * 60);
    assert_eq!(
        retry_at(&Outcome::RateLimited, now),
        SystemTime::UNIX_EPOCH + Duration::from_secs(3600 * 101)
    );
    assert_eq!(
        retry_at(&Outcome::Transport("x".into()), now),
        now + TRANSIENT_RETRY
    );
    let mut issuance = Issuance {
        in_flight: true,
        ..Default::default()
    };
    issuance.ended(&Outcome::Issued(20), now);
    assert!(!issuance.in_flight);
    assert_eq!(issuance.pacing_until, Some(now + PACING));
    issuance.ended(&Outcome::Disabled, now);
    assert_eq!(issuance.backoff_until, Some(now + REFUSED_RETRY));
}

/// One message to one account pays once, whichever of its envelopes carries the token.
#[test]
fn a_message_to_an_account_is_one_spend() {
    let mut units = SpendUnits::default();
    let (id, paid) = units.unit("alice", "m1");
    assert!(!paid);
    let (again, paid) = units.unit("alice", "m1");
    assert_eq!(
        (again.clone(), paid),
        (id.clone(), false),
        "unpaid until a token goes"
    );
    units.paid("alice", "m1");
    assert_eq!(units.unit("alice", "m1"), (id.clone(), true));
    assert_ne!(
        units.unit("bob", "m1").0,
        id,
        "another account pays its own"
    );
    assert_ne!(
        units.unit("alice", "m2").0,
        id,
        "another message pays its own"
    );
    assert_eq!(id.len(), 32);
}
