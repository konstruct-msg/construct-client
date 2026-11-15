//! Call signaling: the 1:1 call state machine and the `WebRtcSignal` protos it moves.
//!
//! Stage A proves the transport — offer/answer/ICE/hangup travel E2EE through the core's Double
//! Ratchet (`call-signaling-e2ee-primary`) — while the auxiliary Signal stream carries wakeup and
//! presence. There is no media yet, so the SDP fields are stubs; stage B fills them from the
//! PeerConnection. Which device a signal goes to and comes from, how a call ended, its history
//! row and glare are the core's rule (`construct_rules::calls`, todo 295), the same iOS and
//! Android call; this module keeps the dialing state and turns the rule's answers into signals.

use crate::proto::signaling::v1::{
    CallAnswer, CallBusy, CallHangup, CallOffer, CallRinging, HangupReason, IceCandidate,
    WebRtcSignal, web_rtc_signal,
};
use construct_core::rule_state::calls as rule;

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
    /// Why it ended, once it has: what the outcome and the history row are read from.
    pub end_reason: Option<rule::EndReason>,
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

/// What to do with an offer that arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfferDisposition {
    /// Ring: the call is now held, incoming.
    Ring,
    /// A call is already held: answer busy to the offering device.
    Busy,
    /// Glare, and ours wins (`rule::glare`): ignore their offer; they will answer ours.
    KeepOurs,
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
            end_reason: None,
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

    /// An offer for `call_id` arrived from `sender_device` of `peer`. Both sides dialling each
    /// other at once is glare: the rule keeps the larger account id's call, and the smaller one
    /// gives its own up and rings for theirs. Any other held call makes this one busy.
    pub fn on_offer(
        &mut self,
        call_id: String,
        peer: String,
        sender_device: String,
        call_type: CallType,
        my_user: &str,
    ) -> OfferDisposition {
        if let Some(call) = &self.active
            && !matches!(call.phase, Phase::Over(_))
        {
            let glare = call.direction == Direction::Outgoing && call.peer == peer;
            if !glare {
                return OfferDisposition::Busy;
            }
            if rule::glare(my_user, &peer) == rule::Glare::KeepOurs {
                return OfferDisposition::KeepOurs;
            }
            // Ours yields: their offer replaces it, as on iOS and Android. The peer ignores our
            // offer (it keeps its own call), so nothing is sent for the call we drop.
        }
        self.begin_incoming(call_id, peer, sender_device, call_type);
        OfferDisposition::Ring
    }

    /// An offer arrived from `sender_device` of `peer`. Returns nothing to send yet — the person
    /// decides. Use [`Manager::on_offer`], which decides busy and glare first.
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
            end_reason: None,
        });
    }

    /// Record which devices the outgoing offer went to.
    pub fn note_offered(&mut self, devices: &[String]) {
        if let Some(call) = &mut self.active {
            call.offered_devices = devices.to_vec();
        }
    }

    /// A signal arrived from `sender_device` (the device whose session opened it) for the held
    /// call. Returns signals to send back: releases to devices the call no longer needs.
    pub fn on_signal(
        &mut self,
        signal: &WebRtcSignal,
        sender_device: &str,
        my_device: &str,
    ) -> Vec<SignalToSend> {
        let Some(call) = &mut self.active else {
            return Vec::new();
        };
        // A late signal of an ended call, or of a different call.
        if signal.call_id != call.call_id || matches!(call.phase, Phase::Over(_)) {
            return Vec::new();
        }
        let Some(inner) = &signal.signal else {
            return Vec::new();
        };
        use web_rtc_signal::Signal as S;
        match inner {
            S::Answer(_) => {
                if call.direction != Direction::Outgoing {
                    return Vec::new();
                }
                match rule::on_answer(
                    sender_device,
                    call.peer_device.as_deref(),
                    &call.offered_devices,
                ) {
                    rule::AnswerDisposition::ReleaseLate { device } => {
                        release(call, &[device], my_device)
                    }
                    rule::AnswerDisposition::Accept {
                        device,
                        release: others,
                    } => {
                        let first = call.peer_device.is_none();
                        call.peer_device = Some(device);
                        call.offered_devices.clear();
                        if first {
                            call.connected_at_ms = Some(now_ms());
                            call.phase = Phase::Live;
                        }
                        release(call, &others, my_device)
                    }
                }
            }
            S::Hangup(h) => remote_hangup(
                call,
                sender_device,
                rule::HangupReason::from_wire(h.reason),
                my_device,
            ),
            S::Busy(_) => remote_hangup(call, sender_device, rule::HangupReason::Busy, my_device),
            _ if !rule::admits(sender_device, call.peer_device.as_deref()) => Vec::new(),
            S::Ringing(_) => {
                if call.direction == Direction::Outgoing && call.phase == Phase::Calling {
                    call.phase = Phase::Ringing;
                }
                Vec::new()
            }
            // ICE, connected and media updates have no media to apply yet (stage B). An offer
            // for the held call id is a renegotiation, which stage A has none of.
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
        match &self.active {
            Some(call) if call.direction == Direction::Incoming => self.end(my_device),
            _ => Vec::new(),
        }
    }

    /// The person (or the app) ended the call: declined if it is incoming and still ringing,
    /// a normal hangup otherwise (`rule::local_hangup_reason`). Returns the hangup to every
    /// device the call reaches; the call stays in `Over(_)` until `dismiss`.
    pub fn end(&mut self, my_device: &str) -> Vec<SignalToSend> {
        let Some(call) = &mut self.active else {
            return Vec::new();
        };
        if matches!(call.phase, Phase::Over(_)) {
            return Vec::new();
        }
        let reason = rule::local_hangup_reason(
            rule_direction(call.direction),
            call.phase == Phase::Incoming,
        );
        let targets = rule::targets(call.peer_device.as_deref(), &call.offered_devices, None);
        finish(call, rule::EndReason::Hangup(reason));
        let wire = hangup(&call.call_id, my_device, proto_reason(reason));
        if targets.is_empty() {
            // No device known yet (the offer is still going out): every device with a session.
            return vec![SignalToSend {
                peer: call.peer.clone(),
                signal: wire,
                to_device: None,
            }];
        }
        targets
            .into_iter()
            .map(|device| SignalToSend {
                peer: call.peer.clone(),
                signal: wire.clone(),
                to_device: Some(device),
            })
            .collect()
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
            duration_seconds: i32::try_from(rule::duration_seconds(call.connected_at_ms, now_ms))
                .unwrap_or(i32::MAX),
        })
    }
}

/// Release `devices`: tell each the call was taken elsewhere (E2EE, to that device alone).
fn release(call: &Call, devices: &[String], my_device: &str) -> Vec<SignalToSend> {
    devices
        .iter()
        .map(|device| SignalToSend {
            peer: call.peer.clone(),
            signal: hangup(&call.call_id, my_device, HangupReason::AcceptedElsewhere),
            to_device: Some(device.clone()),
        })
        .collect()
}

/// A hangup (or a busy) from one of the peer's devices, as the rule routes it.
fn remote_hangup(
    call: &mut Call,
    from: &str,
    reason: rule::HangupReason,
    my_device: &str,
) -> Vec<SignalToSend> {
    match rule::on_hangup(
        from,
        reason,
        call.peer_device.as_deref(),
        &call.offered_devices,
    ) {
        rule::HangupDisposition::Ignore => Vec::new(),
        rule::HangupDisposition::DropDevice { remaining } => {
            call.offered_devices = remaining;
            Vec::new()
        }
        rule::HangupDisposition::EndTakenElsewhere => {
            finish(
                call,
                rule::EndReason::Hangup(rule::HangupReason::AcceptedElsewhere),
            );
            Vec::new()
        }
        rule::HangupDisposition::End { release: others } => {
            finish(call, rule::EndReason::Hangup(reason));
            release(call, &others, my_device)
        }
    }
}

/// End the call for `reason`: the phase shows the rule's outcome.
fn finish(call: &mut Call, reason: rule::EndReason) {
    let connected = call
        .connected_at_ms
        .map(|_| rule::duration_seconds(call.connected_at_ms, now_ms()));
    call.phase = Phase::Over(outcome_of(reason, connected));
    call.end_reason = Some(reason);
}

/// The screen's outcome: the rule's, plus the one case the rule leaves to the screen — a call
/// another of our devices took, which is neither missed nor ended here.
fn outcome_of(reason: rule::EndReason, connected_seconds: Option<u32>) -> Outcome {
    if reason == rule::EndReason::Hangup(rule::HangupReason::AcceptedElsewhere) {
        return Outcome::AnsweredElsewhere;
    }
    match rule::outcome(reason, connected_seconds) {
        rule::Outcome::Ended { .. } => Outcome::Ended,
        rule::Outcome::Declined => Outcome::Declined,
        rule::Outcome::Busy => Outcome::Busy,
        rule::Outcome::NoAnswer => Outcome::NoAnswer,
        rule::Outcome::Failed => Outcome::Failed,
    }
}

/// The store's `CallStore.Status` code (completed 0, missed 1, declined 2, failed 3), by the
/// rule. `None`: do not record (not ended, or taken on another of our devices).
fn history_status(call: &Call) -> Option<i16> {
    let reason = call.end_reason?;
    let status = rule::history_status(
        rule_direction(call.direction),
        reason,
        call.connected_at_ms.is_some(),
    )?;
    Some(i16::from(status.code()))
}

fn rule_direction(direction: Direction) -> rule::Direction {
    match direction {
        Direction::Outgoing => rule::Direction::Outgoing,
        Direction::Incoming => rule::Direction::Incoming,
    }
}

fn proto_reason(reason: rule::HangupReason) -> HangupReason {
    HangupReason::try_from(reason.wire()).unwrap_or(HangupReason::Unspecified)
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
        assert!(m.on_signal(&ringing_sig, "peer-device", "me").is_empty());
        assert_eq!(m.active().unwrap().phase, Phase::Ringing);

        let answer_sig = answer("c1", "peer-device", "peer@konstruct.cc", String::new());
        assert!(m.on_signal(&answer_sig, "peer-device", "me").is_empty());
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
        m.on_signal(&first, "device-1", "me");

        let second = answer("c1", "device-2", "peer", String::new());
        let out = m.on_signal(&second, "device-2", "me");
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
        assert!(m.on_signal(&hangup_sig, "peer-device", "me").is_empty());
        assert_eq!(m.active().unwrap().phase, Phase::Over(Outcome::Declined));
    }

    #[test]
    fn a_busy_signal_ends_an_outgoing_call() {
        let mut m = Manager::new();
        begin_outgoing(&mut m);
        let busy_sig = busy("c1", "peer-device");
        m.on_signal(&busy_sig, "peer-device", "me");
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
        m.begin_incoming(
            "c1".into(),
            "peer".into(),
            "peer-device".into(),
            CallType::Audio,
        );
        let h = hangup("c1", "peer-device", HangupReason::AcceptedElsewhere);
        m.on_signal(&h, "peer-device", "me");
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
        m.on_signal(&h, "peer-device", "me");
        assert_eq!(history_status(m.active().unwrap()), Some(1));
        assert_eq!(history_direction(m.active().unwrap()), 0);

        // Connected and ended normally → completed (0); never connected → missed (1).
        let mut m = Manager::new();
        begin_outgoing(&mut m);
        let a = answer("c1", "peer-device", "peer", String::new());
        m.on_signal(&a, "peer-device", "me");
        let h = hangup("c1", "peer-device", HangupReason::Normal);
        m.on_signal(&h, "peer-device", "me");
        assert_eq!(history_status(m.active().unwrap()), Some(0));

        let mut m = Manager::new();
        begin_outgoing(&mut m);
        let h = hangup("c1", "peer-device", HangupReason::Normal);
        m.on_signal(&h, "peer-device", "me");
        assert_eq!(history_status(m.active().unwrap()), Some(1));
    }

    // ── The five places this client differed from iOS and Android (todo 295) ──────────────

    fn hangup_reason(to_send: &SignalToSend) -> i32 {
        match &to_send.signal.signal {
            Some(S::Hangup(h)) => h.reason,
            other => panic!("expected a hangup, got {other:?}"),
        }
    }

    /// Mutation: keep the other devices ringing after the first answer.
    #[test]
    fn the_first_answer_releases_every_other_ringing_device() {
        let mut m = Manager::new();
        begin_outgoing(&mut m);
        m.note_offered(&["d1".into(), "d2".into(), "d3".into()]);
        let out = m.on_signal(&answer("c1", "d2", "peer", String::new()), "d2", "me");
        let released: Vec<_> = out.iter().map(|o| o.to_device.clone().unwrap()).collect();
        assert_eq!(released, ["d1", "d3"]);
        for o in &out {
            assert_eq!(hangup_reason(o), HangupReason::AcceptedElsewhere as i32);
            assert_eq!(
                o.signal.sender_device_id, "me",
                "the release is ours, not the answerer's"
            );
        }
        assert_eq!(m.active().unwrap().phase, Phase::Live);
    }

    /// Mutation: end the whole call on one device's busy.
    #[test]
    fn busy_on_one_device_keeps_the_others_ringing_until_all_are_busy() {
        let mut m = Manager::new();
        begin_outgoing(&mut m);
        m.note_offered(&["d1".into(), "d2".into()]);
        m.on_signal(&busy("c1", "d1"), "d1", "me");
        assert_eq!(m.active().unwrap().phase, Phase::Calling);
        assert_eq!(m.active().unwrap().offered_devices, ["d2"]);
        m.on_signal(&busy("c1", "d2"), "d2", "me");
        assert_eq!(m.active().unwrap().phase, Phase::Over(Outcome::Busy));
    }

    /// Mutation: listen to hangups from any device after the answer.
    #[test]
    fn after_the_answer_a_hangup_from_another_device_is_ignored() {
        let mut m = Manager::new();
        begin_outgoing(&mut m);
        m.note_offered(&["d1".into(), "d2".into()]);
        m.on_signal(&answer("c1", "d1", "peer", String::new()), "d1", "me");
        m.on_signal(&hangup("c1", "d2", HangupReason::Normal), "d2", "me");
        assert_eq!(m.active().unwrap().phase, Phase::Live);
        m.on_signal(&hangup("c1", "d1", HangupReason::Normal), "d1", "me");
        assert_eq!(m.active().unwrap().phase, Phase::Over(Outcome::Ended));
    }

    /// Mutations: keep our call always; yield always.
    #[test]
    fn glare_keeps_the_larger_account_ids_call() {
        let mut m = Manager::new();
        begin_outgoing(&mut m); // to "peer"
        let d = m.on_offer(
            "c2".into(),
            "peer".into(),
            "pd".into(),
            CallType::Audio,
            "zzz",
        );
        assert_eq!(d, OfferDisposition::KeepOurs);
        assert_eq!(m.active().unwrap().call_id, "c1");

        let d = m.on_offer(
            "c2".into(),
            "peer".into(),
            "pd".into(),
            CallType::Audio,
            "aaa",
        );
        assert_eq!(d, OfferDisposition::Ring);
        let call = m.active().unwrap();
        assert_eq!(
            (call.call_id.as_str(), call.direction),
            ("c2", Direction::Incoming)
        );
    }

    #[test]
    fn an_offer_from_someone_else_while_in_a_call_is_busy() {
        let mut m = Manager::new();
        begin_outgoing(&mut m);
        let d = m.on_offer(
            "c2".into(),
            "other".into(),
            "od".into(),
            CallType::Audio,
            "aaa",
        );
        assert_eq!(d, OfferDisposition::Busy);
        assert_eq!(m.active().unwrap().call_id, "c1");
    }

    /// Mutation: write "failed" (3) for a connection failure nobody answered — iOS writes missed.
    #[test]
    fn an_unanswered_connection_failure_is_missed() {
        let mut m = Manager::new();
        begin_outgoing(&mut m);
        m.on_signal(
            &hangup("c1", "pd", HangupReason::ConnectionFailed),
            "pd",
            "me",
        );
        assert_eq!(m.active().unwrap().phase, Phase::Over(Outcome::Failed));
        assert_eq!(history_status(m.active().unwrap()), Some(1));
    }

    /// Mutation: always a normal hangup — a ringing call we end is declined.
    #[test]
    fn ending_an_incoming_call_that_still_rings_declines_it() {
        let mut m = Manager::new();
        m.begin_incoming("c1".into(), "peer".into(), "pd".into(), CallType::Audio);
        let out = m.end("me");
        assert_eq!(hangup_reason(&out[0]), HangupReason::Declined as i32);
        assert_eq!(out[0].to_device.as_deref(), Some("pd"));
        assert_eq!(m.active().unwrap().phase, Phase::Over(Outcome::Declined));
    }

    /// Mutation: send the caller's hangup only to the pinned/none — every ringing device must hear.
    #[test]
    fn hanging_up_before_an_answer_reaches_every_offered_device() {
        let mut m = Manager::new();
        begin_outgoing(&mut m);
        m.note_offered(&["d1".into(), "d2".into()]);
        let out = m.end("me");
        let to: Vec<_> = out.iter().map(|o| o.to_device.clone().unwrap()).collect();
        assert_eq!(to, ["d1", "d2"]);
        assert_eq!(hangup_reason(&out[0]), HangupReason::Normal as i32);
    }

    /// Mutation: let a sibling of the call's device stop it as taken elsewhere.
    #[test]
    fn taken_elsewhere_counts_only_from_the_calls_own_device() {
        let mut m = Manager::new();
        m.begin_incoming("c1".into(), "peer".into(), "pd".into(), CallType::Audio);
        m.on_signal(
            &hangup("c1", "other", HangupReason::AcceptedElsewhere),
            "other",
            "me",
        );
        assert_eq!(m.active().unwrap().phase, Phase::Incoming);
    }

    /// Mutation: act on a signal of a call that is over (or of another call while it is live).
    #[test]
    fn a_signal_after_the_end_or_for_another_call_changes_nothing() {
        let mut m = Manager::new();
        begin_outgoing(&mut m);
        m.on_signal(&answer("c1", "pd", "peer", String::new()), "pd", "me");
        m.on_signal(&hangup("c9", "pd", HangupReason::Normal), "pd", "me");
        assert_eq!(
            m.active().unwrap().phase,
            Phase::Live,
            "another call's hangup"
        );
        m.on_signal(&hangup("c1", "pd", HangupReason::Normal), "pd", "me");
        m.on_signal(&hangup("c1", "pd", HangupReason::Declined), "pd", "me");
        assert_eq!(
            m.active().unwrap().phase,
            Phase::Over(Outcome::Ended),
            "a late second hangup"
        );
    }

    /// Mutation: let a ringing signal move an incoming call.
    #[test]
    fn ringing_moves_only_an_outgoing_call_that_is_calling() {
        let mut m = Manager::new();
        m.begin_incoming("c1".into(), "peer".into(), "pd".into(), CallType::Audio);
        m.on_signal(&ringing("c1", "pd"), "pd", "me");
        assert_eq!(m.active().unwrap().phase, Phase::Incoming);
    }

    /// Mutation: decline an outgoing call as if it rang on us.
    #[test]
    fn declining_is_for_an_incoming_call_only() {
        let mut m = Manager::new();
        begin_outgoing(&mut m);
        assert!(m.decline("me").is_empty());
        assert_eq!(m.active().unwrap().phase, Phase::Calling);
    }

    /// Mutations: never write the row; write it twice; write it before the call ended.
    #[test]
    fn an_ended_call_writes_its_row_once_with_its_length() {
        let mut m = Manager::new();
        begin_outgoing(&mut m);
        m.on_signal(&answer("c1", "pd", "peer", String::new()), "pd", "me");
        assert!(m.take_history_record(now_ms()).is_none(), "not over yet");
        let answered = m.active().unwrap().connected_at_ms.unwrap();
        m.on_signal(&hangup("c1", "pd", HangupReason::Normal), "pd", "me");
        let row = m.take_history_record(answered + 61_500).expect("a row");
        assert_eq!((row.id.as_str(), row.peer_user_id.as_str()), ("c1", "peer"));
        assert_eq!(
            (row.direction, row.status, row.duration_seconds),
            (0, 0, 61)
        );
        assert!(m.take_history_record(now_ms()).is_none(), "written once");
    }
}
