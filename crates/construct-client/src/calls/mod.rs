//! Call signaling: the 1:1 call state machine and the `WebRtcSignal` protos it moves.
//!
//! Stage A proves the transport — offer/answer/ICE/hangup travel E2EE through the core's Double
//! Ratchet (`call-signaling-e2ee-primary`) — while the auxiliary Signal stream carries wakeup and
//! presence. There is no media yet, so the SDP fields are stubs; stage B fills them from the
//! PeerConnection. The core decides nothing here: this is the client's own dialing state, the
//! "first answer wins" rule among a contact's devices included.

use crate::proto::signaling::v1::{
    CallAnswer, CallBusy, CallHangup, CallOffer, CallRinging, HangupReason, IceCandidate,
    WebRtcSignal, web_rtc_signal,
};

/// The call kind, re-exported so front ends can read it without naming the proto module.
pub use crate::proto::signaling::v1::CallType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Outgoing,
    Incoming,
}

/// What a call screen shows, decided from the call's state alone (macOS `CallPhase.swift`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    /// Ringing on us.
    Incoming,
    /// Outgoing, before the other side's device rang.
    Calling,
    /// Outgoing, ringing on the other side.
    Ringing,
    /// Answered; media is being set up (stage B).
    Connecting,
    /// Active.
    Live,
    Over(Outcome),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Ended,
    Declined,
    Busy,
    NoAnswer,
    Failed,
    /// Another of our devices took the call: not a missed call, no history entry.
    AnsweredElsewhere,
}

/// The call as the UI sees it: no device ids, no key material.
#[derive(Debug, Clone, PartialEq)]
pub struct CallState {
    pub call_id: String,
    pub peer_id: String,
    pub direction: Direction,
    pub phase: Phase,
    pub call_type: CallType,
    /// When the call went live (Unix ms); the timer ticks from here.
    pub connected_at_ms: Option<i64>,
}

/// A call the orchestrator holds. `peer` is an account id; `peer_device` is the device that
/// answered (set by the first answer — later devices are released `ACCEPTED_ELSEWHERE`).
#[derive(Debug, Clone)]
pub struct Call {
    pub call_id: String,
    pub peer: String,
    pub direction: Direction,
    pub phase: Phase,
    pub call_type: CallType,
    pub peer_device: Option<String>,
    pub offered_devices: Vec<String>,
    pub started_at_ms: i64,
    /// When the call went live (an answer arrived, or we answered); the timer and the history
    /// duration count from here.
    pub connected_at_ms: Option<i64>,
    /// The history row was already written.
    pub recorded: bool,
}

/// A signal the manager decided to send, and where it goes: one device (the one that answered,
/// or a device being released), or every device of `peer` with a session (`None`).
#[derive(Debug)]
pub struct SignalToSend {
    pub peer: String,
    pub signal: WebRtcSignal,
    pub to_device: Option<String>,
}

/// What the store needs when a call ends, except `peer_name` (the orchestrator fills it from its
/// contacts) and the end time (now). `status` is `CallStore.Status`, `direction` its `Direction`.
#[derive(Debug)]
pub struct HistoryRecord {
    pub id: String,
    pub peer_user_id: String,
    pub direction: i16,
    pub status: i16,
    pub started_at_ms: i64,
    pub duration_seconds: i32,
}

/// One row of the call log, as a front end reads it. The store's numeric codes are already named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryRow {
    pub id: String,
    pub peer_user_id: String,
    pub peer_name: String,
    /// `"outgoing"` or `"incoming"`.
    pub direction: &'static str,
    /// `"completed"`, `"missed"`, `"declined"` or `"failed"`.
    pub status: &'static str,
    pub started_at: Option<i64>,
    pub duration_seconds: i32,
}

/// One 1:1 call at a time; a second call while one is held answers busy (stage A keeps it
/// single and answers the E2EE busy signal).
#[derive(Debug, Default)]
pub struct Manager {
    active: Option<Call>,
}

impl Manager {
    pub fn new() -> Self {
        Self { active: None }
    }

    pub fn active(&self) -> Option<&Call> {
        self.active.as_ref()
    }

    pub fn state(&self) -> Option<CallState> {
        self.active.as_ref().map(|call| CallState {
            call_id: call.call_id.clone(),
            peer_id: call.peer.clone(),
            direction: call.direction,
            phase: call.phase.clone(),
            call_type: call.call_type,
            connected_at_ms: call.connected_at_ms,
        })
    }

    pub fn is_busy(&self) -> bool {
        // A call whose outcome the person has not dismissed yet does not block a new one.
        self.active
            .as_ref()
            .is_some_and(|c| !matches!(c.phase, Phase::Over(_)))
    }

    /// Begin an outgoing call to `peer`. Returns the offer to send.
    pub fn begin_outgoing(
        &mut self,
        call_id: String,
        peer: String,
        call_type: CallType,
        my_device: &str,
        my_user: &str,
    ) -> SignalToSend {
        let call = Call {
            call_id,
            peer,
            direction: Direction::Outgoing,
            phase: Phase::Calling,
            call_type,
            peer_device: None,
            offered_devices: Vec::new(),
            started_at_ms: now_ms(),
            connected_at_ms: None,
            recorded: false,
        };
        let signal = offer(
            &call.call_id,
            my_device,
            my_user,
            call.call_type,
            String::new(),
        );
        let to_send = SignalToSend {
            peer: call.peer.clone(),
            signal,
            to_device: None,
        };
        self.active = Some(call);
        to_send
    }

    /// An offer arrived from `sender_device` of `peer`. Returns nothing to send yet — the person
    /// decides. A call already held makes this one busy (handled by the caller of this method).
    pub fn begin_incoming(
        &mut self,
        call_id: String,
        peer: String,
        sender_device: String,
        call_type: CallType,
    ) {
        self.active = Some(Call {
            call_id,
            peer,
            direction: Direction::Incoming,
            phase: Phase::Incoming,
            call_type,
            peer_device: Some(sender_device),
            offered_devices: Vec::new(),
            started_at_ms: now_ms(),
            connected_at_ms: None,
            recorded: false,
        });
    }

    /// Record which devices the outgoing offer went to.
    pub fn note_offered(&mut self, devices: &[String]) {
        if let Some(call) = &mut self.active {
            call.offered_devices = devices.to_vec();
        }
    }

    /// A signal arrived from `sender_device` (a device id) for the held call. Returns signals to
    /// send back — a release to a device that answered after another one did, mostly.
    pub fn on_signal(&mut self, signal: &WebRtcSignal, sender_device: &str) -> Vec<SignalToSend> {
        let Some(call) = &mut self.active else {
            return Vec::new();
        };
        // A late signal of an ended call, or of a different call.
        if signal.call_id != call.call_id {
            return Vec::new();
        }
        let Some(inner) = &signal.signal else {
            return Vec::new();
        };
        use web_rtc_signal::Signal as S;
        match inner {
            S::Ringing(_) => {
                if call.direction == Direction::Outgoing && call.phase == Phase::Calling {
                    call.phase = Phase::Ringing;
                }
                Vec::new()
            }
            S::Answer(_) => {
                if call.direction != Direction::Outgoing {
                    return Vec::new();
                }
                if call.peer_device.is_some() {
                    // First answer won; tell this later device the call was taken elsewhere.
                    return vec![SignalToSend {
                        peer: call.peer.clone(),
                        signal: hangup(
                            &call.call_id,
                            &signal.sender_device_id,
                            HangupReason::AcceptedElsewhere,
                        ),
                        to_device: Some(sender_device.to_string()),
                    }];
                }
                call.peer_device = Some(sender_device.to_string());
                call.connected_at_ms = Some(now_ms());
                call.phase = Phase::Live;
                Vec::new()
            }
            S::Hangup(hangup) => {
                call.phase = Phase::Over(outcome_of(hangup.reason));
                Vec::new()
            }
            S::Busy(_) => {
                call.phase = Phase::Over(Outcome::Busy);
                Vec::new()
            }
            // ICE, connected and media updates have no media to apply yet (stage B). A second
            // offer while we hold a call is glare; stage A ignores it.
            S::IceCandidate(_) | S::IceCandidates(_) | S::Connected(_) | S::MediaUpdate(_) => {
                Vec::new()
            }
            S::Offer(_) => Vec::new(),
        }
    }

    /// The person answered the incoming call. Returns the answer to send back.
    pub fn accept(&mut self, my_device: &str, my_user: &str) -> Vec<SignalToSend> {
        let Some(call) = &mut self.active else {
            return Vec::new();
        };
        if call.direction != Direction::Incoming {
            return Vec::new();
        }
        call.connected_at_ms = Some(now_ms());
        call.phase = Phase::Live;
        let signal = answer(&call.call_id, my_device, my_user, String::new());
        vec![SignalToSend {
            peer: call.peer.clone(),
            signal,
            to_device: call.peer_device.clone(),
        }]
    }

    /// The person declined. Returns the hangup; the call stays in `Over(Declined)` until
    /// `dismiss`, so the person sees the outcome.
    pub fn decline(&mut self, my_device: &str) -> Vec<SignalToSend> {
        let Some(call) = &mut self.active else {
            return Vec::new();
        };
        if call.direction != Direction::Incoming {
            return Vec::new();
        }
        call.phase = Phase::Over(Outcome::Declined);
        vec![SignalToSend {
            peer: call.peer.clone(),
            signal: hangup(&call.call_id, my_device, HangupReason::Declined),
            to_device: call.peer_device.clone(),
        }]
    }

    /// The person (or the app) ended the call. Returns the hangup; the call stays in
    /// `Over(Ended)` until `dismiss`.
    pub fn end(&mut self, my_device: &str) -> Vec<SignalToSend> {
        let Some(call) = &mut self.active else {
            return Vec::new();
        };
        call.phase = Phase::Over(Outcome::Ended);
        vec![SignalToSend {
            peer: call.peer.clone(),
            signal: hangup(&call.call_id, my_device, HangupReason::Normal),
            to_device: call.peer_device.clone(),
        }]
    }

    /// The person closed the ended call's outcome.
    pub fn dismiss(&mut self) {
        self.active = None;
    }

    /// The history row for a call that just ended and was not yet recorded. `None` when there is
    /// no call, it has not ended, it was already recorded, or it must not be recorded (taken on
    /// another of our devices).
    pub fn take_history_record(&mut self, now_ms: i64) -> Option<HistoryRecord> {
        let call = self.active.as_mut()?;
        if call.recorded || !matches!(call.phase, Phase::Over(_)) {
            return None;
        }
        call.recorded = true;
        let status = history_status(call)?;
        Some(HistoryRecord {
            id: call.call_id.clone(),
            peer_user_id: call.peer.clone(),
            direction: history_direction(call),
            status,
            started_at_ms: call.started_at_ms,
            duration_seconds: call
                .connected_at_ms
                .map(|since| ((now_ms - since) / 1000).max(0) as i32)
                .unwrap_or(0),
        })
    }
}

fn outcome_of(reason: i32) -> Outcome {
    match HangupReason::try_from(reason).unwrap_or(HangupReason::Normal) {
        HangupReason::Declined => Outcome::Declined,
        HangupReason::Busy => Outcome::Busy,
        HangupReason::Timeout => Outcome::NoAnswer,
        HangupReason::ConnectionFailed => Outcome::Failed,
        HangupReason::AcceptedElsewhere => Outcome::AnsweredElsewhere,
        _ => Outcome::Ended,
    }
}

/// The store's `CallStore.Status` code (completed 0, missed 1, declined 2, failed 3), as iOS
/// maps a call end (`CallManager.endActiveCall`). `None`: do not record.
fn history_status(call: &Call) -> Option<i16> {
    let answered = call.connected_at_ms.is_some();
    let incoming = call.direction == Direction::Incoming;
    let code = match &call.phase {
        Phase::Over(Outcome::Ended) => {
            if answered {
                0
            } else {
                1
            }
        }
        Phase::Over(Outcome::Declined) => {
            if incoming {
                2
            } else {
                1
            }
        }
        Phase::Over(Outcome::Busy | Outcome::NoAnswer) => 1,
        Phase::Over(Outcome::Failed) => {
            if answered {
                0
            } else {
                3
            }
        }
        Phase::Over(Outcome::AnsweredElsewhere) => return None,
        _ => return None,
    };
    Some(code)
}

/// The store's `CallRecord.Direction` code (outgoing 0, incoming 1).
fn history_direction(call: &Call) -> i16 {
    match call.direction {
        Direction::Outgoing => 0,
        Direction::Incoming => 1,
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default()
}

// ── `WebRtcSignal` builders ───────────────────────────────────────────────────
//
// The SDP fields are empty until stage B: a PeerConnection fills them. The structure (call id,
// device ids, timestamps) is already the wire format.

pub fn offer(
    call_id: &str,
    device_id: &str,
    user_id: &str,
    call_type: CallType,
    sdp: String,
) -> WebRtcSignal {
    WebRtcSignal {
        call_id: call_id.to_owned(),
        sender_device_id: device_id.to_owned(),
        timestamp: now_ms(),
        signal: Some(web_rtc_signal::Signal::Offer(CallOffer {
            sdp,
            call_type: call_type as i32,
            caller_device_id: device_id.to_owned(),
            caller_user_id: user_id.to_owned(),
            offered_at: now_ms(),
            ..Default::default()
        })),
    }
}

pub fn answer(call_id: &str, device_id: &str, user_id: &str, sdp: String) -> WebRtcSignal {
    WebRtcSignal {
        call_id: call_id.to_owned(),
        sender_device_id: device_id.to_owned(),
        timestamp: now_ms(),
        signal: Some(web_rtc_signal::Signal::Answer(CallAnswer {
            sdp,
            answerer_device_id: device_id.to_owned(),
            answerer_user_id: user_id.to_owned(),
            answered_at: now_ms(),
            ..Default::default()
        })),
    }
}

pub fn hangup(call_id: &str, device_id: &str, reason: HangupReason) -> WebRtcSignal {
    WebRtcSignal {
        call_id: call_id.to_owned(),
        sender_device_id: device_id.to_owned(),
        timestamp: now_ms(),
        signal: Some(web_rtc_signal::Signal::Hangup(CallHangup {
            reason: reason as i32,
            device_id: device_id.to_owned(),
            hangup_at: now_ms(),
            ..Default::default()
        })),
    }
}

pub fn ringing(call_id: &str, device_id: &str) -> WebRtcSignal {
    WebRtcSignal {
        call_id: call_id.to_owned(),
        sender_device_id: device_id.to_owned(),
        timestamp: now_ms(),
        signal: Some(web_rtc_signal::Signal::Ringing(CallRinging {
            device_id: device_id.to_owned(),
            ringing_at: now_ms(),
        })),
    }
}

pub fn busy(call_id: &str, device_id: &str) -> WebRtcSignal {
    WebRtcSignal {
        call_id: call_id.to_owned(),
        sender_device_id: device_id.to_owned(),
        timestamp: now_ms(),
        signal: Some(web_rtc_signal::Signal::Busy(CallBusy {
            device_id: device_id.to_owned(),
            busy_at: now_ms(),
        })),
    }
}

/// An ICE candidate, its `candidate` bytes sealed by the core's ratchet on the way out (the
/// producer of a live candidate in stage B passes `Bytes` here).
pub fn ice_candidate(
    call_id: &str,
    device_id: &str,
    sdp_m_line_index: u32,
    sdp_mid: String,
    candidate: bytes::Bytes,
) -> WebRtcSignal {
    WebRtcSignal {
        call_id: call_id.to_owned(),
        sender_device_id: device_id.to_owned(),
        timestamp: now_ms(),
        signal: Some(web_rtc_signal::Signal::IceCandidate(IceCandidate {
            sdp_m_line_index,
            sdp_mid,
            candidate,
            ..Default::default()
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::signaling::v1::web_rtc_signal::Signal as S;

    fn begin_outgoing(manager: &mut Manager) {
        manager.begin_outgoing(
            "c1".into(),
            "peer".into(),
            CallType::Audio,
            "me",
            "me@konstruct.cc",
        );
    }

    #[test]
    fn an_outgoing_call_rings_then_goes_live_on_the_first_answer() {
        let mut m = Manager::new();
        begin_outgoing(&mut m);
        assert_eq!(m.active().unwrap().phase, Phase::Calling);

        let ringing_sig = ringing("c1", "peer-device");
        assert!(m.on_signal(&ringing_sig, "peer-device").is_empty());
        assert_eq!(m.active().unwrap().phase, Phase::Ringing);

        let answer_sig = answer("c1", "peer-device", "peer@konstruct.cc", String::new());
        assert!(m.on_signal(&answer_sig, "peer-device").is_empty());
        assert_eq!(m.active().unwrap().phase, Phase::Live);
        assert_eq!(
            m.active().unwrap().peer_device.as_deref(),
            Some("peer-device")
        );
    }

    #[test]
    fn a_later_answer_is_released_accepted_elsewhere() {
        let mut m = Manager::new();
        begin_outgoing(&mut m);
        let first = answer("c1", "device-1", "peer", String::new());
        m.on_signal(&first, "device-1");

        let second = answer("c1", "device-2", "peer", String::new());
        let out = m.on_signal(&second, "device-2");
        assert_eq!(out.len(), 1);
        let Some(S::Hangup(h)) = &out[0].signal.signal else {
            panic!("expected a hangup, got {:?}", out[0].signal.signal);
        };
        assert_eq!(h.reason, HangupReason::AcceptedElsewhere as i32);
        assert_eq!(out[0].to_device.as_deref(), Some("device-2"));
        assert_eq!(m.active().unwrap().peer_device.as_deref(), Some("device-1"));
    }

    #[test]
    fn accepting_an_incoming_call_answers_and_goes_live() {
        let mut m = Manager::new();
        m.begin_incoming(
            "c1".into(),
            "peer".into(),
            "peer-device".into(),
            CallType::Audio,
        );
        assert_eq!(m.active().unwrap().phase, Phase::Incoming);

        let out = m.accept("me", "me@konstruct.cc");
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0].signal.signal, Some(S::Answer(_))));
        assert_eq!(m.active().unwrap().phase, Phase::Live);
    }

    #[test]
    fn a_hangup_ends_the_call_with_its_outcome() {
        let mut m = Manager::new();
        begin_outgoing(&mut m);
        let hangup_sig = hangup("c1", "peer-device", HangupReason::Declined);
        assert!(m.on_signal(&hangup_sig, "peer-device").is_empty());
        assert_eq!(m.active().unwrap().phase, Phase::Over(Outcome::Declined));
    }

    #[test]
    fn a_busy_signal_ends_an_outgoing_call() {
        let mut m = Manager::new();
        begin_outgoing(&mut m);
        let busy_sig = busy("c1", "peer-device");
        m.on_signal(&busy_sig, "peer-device");
        assert_eq!(m.active().unwrap().phase, Phase::Over(Outcome::Busy));
    }

    #[test]
    fn declining_keeps_the_outcome_until_dismiss_and_does_not_block_a_new_call() {
        let mut m = Manager::new();
        m.begin_incoming(
            "c1".into(),
            "peer".into(),
            "peer-device".into(),
            CallType::Audio,
        );
        let out = m.decline("me");
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0].signal.signal, Some(S::Hangup(_))));
        assert_eq!(m.active().unwrap().phase, Phase::Over(Outcome::Declined));
        assert!(!m.is_busy(), "an ended call does not block a new one");

        m.dismiss();
        assert!(m.active().is_none());
    }

    #[test]
    fn a_call_taken_elsewhere_writes_no_history() {
        let mut m = Manager::new();
        begin_outgoing(&mut m);
        let h = hangup("c1", "peer-device", HangupReason::AcceptedElsewhere);
        m.on_signal(&h, "peer-device");
        assert_eq!(
            m.active().unwrap().phase,
            Phase::Over(Outcome::AnsweredElsewhere)
        );
        assert!(m.take_history_record(now_ms()).is_none());
    }

    #[test]
    fn history_status_maps_the_outcomes_as_ios_does() {
        // Incoming, declined by us → declined (2), direction incoming (1).
        let mut m = Manager::new();
        m.begin_incoming(
            "c1".into(),
            "peer".into(),
            "peer-device".into(),
            CallType::Audio,
        );
        m.decline("me");
        assert_eq!(history_status(m.active().unwrap()), Some(2));
        assert_eq!(history_direction(m.active().unwrap()), 1);

        // Outgoing, the peer declined → missed (1), direction outgoing (0).
        let mut m = Manager::new();
        begin_outgoing(&mut m);
        let h = hangup("c1", "peer-device", HangupReason::Declined);
        m.on_signal(&h, "peer-device");
        assert_eq!(history_status(m.active().unwrap()), Some(1));
        assert_eq!(history_direction(m.active().unwrap()), 0);

        // Connected and ended normally → completed (0); never connected → missed (1).
        let mut m = Manager::new();
        begin_outgoing(&mut m);
        let a = answer("c1", "peer-device", "peer", String::new());
        m.on_signal(&a, "peer-device");
        let h = hangup("c1", "peer-device", HangupReason::Normal);
        m.on_signal(&h, "peer-device");
        assert_eq!(history_status(m.active().unwrap()), Some(0));

        let mut m = Manager::new();
        begin_outgoing(&mut m);
        let h = hangup("c1", "peer-device", HangupReason::Normal);
        m.on_signal(&h, "peer-device");
        assert_eq!(history_status(m.active().unwrap()), Some(1));
    }
}
