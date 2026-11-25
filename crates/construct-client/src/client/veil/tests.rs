use super::*;

const PIN: &str = "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12";
const NOW: i64 = 1_800_000_000;

fn front(relay: &str) -> Front {
    Front {
        relay: relay.into(),
        sni: "cdn.example".into(),
        spki: PIN.into(),
        not_after: NOW + 2 * RENEW_BEFORE,
        capability: String::new(),
        version: 2,
    }
}

fn disputing(fronts: &[&Front]) -> Disputes {
    let disputes = Disputes::default();
    for f in fronts {
        disputes.dialed(&f.relay, &f.spki, DialOutcome::PinMismatch);
    }
    disputes
}

#[test]
fn a_disputed_front_is_dialled_last_and_a_demoted_one_after_its_equals() {
    let (a, b, c, d) = (
        front("a:443"),
        front("b:443"),
        front("c:443"),
        front("d:443"),
    );
    let disputes = disputing(&[&a]);
    let demoted = [("b:443".to_owned(), 2), ("c:443".to_owned(), 1)].into();
    let mut fronts = [a, b, c, d];
    dial_order(&mut fronts, &demoted, &disputes);
    let order: Vec<&str> = fronts.iter().map(|f| f.relay.as_str()).collect();
    assert_eq!(order, ["d:443", "c:443", "b:443", "a:443"]);
}

/// Each dial reaches the router by its front; one that met another key disputes the pin and is
/// also a dial that did not come up; one of a session before says nothing.
#[test]
fn a_dial_reaches_the_router_and_a_foreign_key_disputes_the_pin() {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let f = front("a:443");
    let disputes = Disputes::default();
    let hear = dial_observer(f.clone(), disputes.clone(), tx);
    let mut next = || match rx.try_recv() {
        Ok(Input::Dialed { relay, up }) => Some((relay, up)),
        Ok(_) => panic!("not a dial"),
        Err(_) => None,
    };

    hear("a:443", DialOutcome::Failed);
    assert_eq!(next(), Some(("a:443".into(), false)));
    assert!(!disputes.disputed(&f));

    hear("a:443", DialOutcome::PinMismatch);
    assert_eq!(next(), Some(("a:443".into(), false)));
    assert!(disputes.disputed(&f));

    hear("b:443", DialOutcome::Up);
    hear("b:443", DialOutcome::PinMismatch);
    assert_eq!(next(), None);
    assert!(disputes.disputed(&f) && !disputes.disputed(&front("b:443")));

    hear("a:443", DialOutcome::Up);
    assert_eq!(next(), Some(("a:443".into(), true)));
    assert!(!disputes.disputed(&f));
}

/// Coordinates are asked for when no front is held with time to live and a key nothing disputes.
#[test]
fn a_disputed_front_is_not_one_held() {
    let (a, b) = (front("a:443"), front("b:443"));
    let none = Disputes::default();
    assert!(holds_fresh(std::slice::from_ref(&a), &none, NOW));
    assert!(!holds_fresh(
        std::slice::from_ref(&a),
        &disputing(&[&a]),
        NOW
    ));
    assert!(holds_fresh(&[a.clone(), b.clone()], &disputing(&[&a]), NOW));
    assert!(!holds_fresh(&[], &none, NOW));
    let bearer = Front {
        version: 1,
        ..a.clone()
    };
    assert!(!holds_fresh(&[bearer], &none, NOW), "not this device's own");
    let ending = Front {
        not_after: NOW + RENEW_BEFORE,
        ..a
    };
    assert!(!holds_fresh(&[ending], &none, NOW));
}

#[test]
fn the_front_asked_by_is_an_undisputed_one_while_there_is_one() {
    let (a, b) = (front("a:443"), front("b:443"));
    let held = [a.clone(), b.clone()];
    assert_eq!(asked_for(&held, &Disputes::default()), Some("a:443".into()));
    assert_eq!(asked_for(&held, &disputing(&[&a])), Some("b:443".into()));
    assert_eq!(
        asked_for(&held, &disputing(&[&a, &b])),
        Some("a:443".into())
    );
    assert_eq!(asked_for(&[], &Disputes::default()), None);
}

/// The coordinator's own account of a session to a front that is not there, through the tunnel
/// and the observer to the router.
#[tokio::test]
async fn a_tunnel_tells_of_a_front_that_is_not_there() {
    let gone = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let relay = gone.local_addr().unwrap().to_string();
    drop(gone);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let f = front(&relay);
    let hear = dial_observer(f.clone(), Disputes::default(), tx);
    assert!(Tunnel::new().start(&f, &[7; 32], hear).await.is_err());
    let heard = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("the dial is told");
    assert!(matches!(heard, Some(Input::Dialed { relay: r, up: false }) if r == relay));
}

fn router(mode: Mode, state: State, source: Fronts) -> Router {
    let (tx, _) = tokio::sync::mpsc::unbounded_channel();
    let (events, _) = tokio::sync::mpsc::unbounded_channel();
    let grpc = || crate::grpc::GrpcClient::new("https://127.0.0.1:1");
    Router {
        mode,
        state,
        source: Arc::new(Mutex::new(source)),
        sk: zeroize::Zeroizing::new([7; 32]),
        holder: Default::default(),
        status: Status::new(events),
        clients: (grpc(), grpc()),
        demoted: Default::default(),
        disputes: Disputes::default(),
        starting: false,
        tx,
    }
}

fn active(relay: &str) -> State {
    State::VeilActive {
        relay: relay.into(),
        port: 1,
        since_ms: 0,
        soft_fails: Default::default(),
        front_fails: 0,
    }
}

/// What the router hears reaches the rule as what it was: three dials in a row that did not come
/// up leave the front, with one that did between them they do not; calls count on the path they
/// went on.
#[test]
fn the_router_tells_the_rule_what_it_heard() {
    use construct_core::rule_state::transport_route::{Lane, RpcFailure};
    let heard = |inputs: &[Input]| {
        let mut r = router(Mode::On, active("a:443"), Fronts::Armed(front("a:443")));
        for input in inputs {
            let input = match input {
                Input::Dialed { relay, up } => Input::Dialed {
                    relay: relay.clone(),
                    up: *up,
                },
                Input::Report(r) => Input::Report(*r),
                _ => unreachable!(),
            };
            let event = r.event(input).expect("an event");
            r.state = reduce(&r.state, &event, r.mode, Config::default(), 0).state;
        }
        matches!(r.state, State::VeilActive { .. })
    };
    let dial = |up| Input::Dialed {
        relay: "a:443".into(),
        up,
    };
    assert!(heard(&[dial(false), dial(false)]));
    assert!(!heard(&[dial(false), dial(false), dial(false)]));
    assert!(heard(&[
        dial(false),
        dial(false),
        dial(true),
        dial(false),
        dial(false)
    ]));
    let call = |veil| {
        Input::Report((
            route::Report::RpcFailed {
                lane: Lane::Auth,
                failure: RpcFailure::StreamTimeout,
            },
            veil,
        ))
    };
    assert!(!heard(&[call(true), call(true), call(true)]));
    assert!(heard(&[call(false), call(false), call(false)]));
}
