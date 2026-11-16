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
use construct_core::rule_state::call_machine as machine;
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

/// The call as this client shows it: the one the machine holds, or the one that just ended,
/// until the person closes its outcome (the machine forgets a call when it ends). `peer` is an
/// account id. Devices, the answer, budgets and deadlines are the machine's
/// ([`Manager::chosen_device`], [`Manager::offered_devices`]).
#[derive(Debug, Clone)]
pub struct Call {
    pub call_id: String,
    pub peer: String,
    pub direction: Direction,
    pub phase: Phase,
    pub call_type: CallType,
    /// When the call went live (an answer arrived, or we answered); the timer counts from here.
    pub connected_at_ms: Option<i64>,
}

/// A signal the manager decided to send, and where it goes: one device (the one that answered,
/// or a device being released), or every device of `peer` with a session (`None`); and on which
/// paths (`route`). A hangup's paths are the rule's (`rule::hangup_route`); every other signal
/// travels end to end only.
#[derive(Debug)]
pub struct SignalToSend {
    pub peer: String,
    pub signal: WebRtcSignal,
    pub to_device: Option<String>,
    pub route: rule::HangupRoute,
}

/// End to end only: offer, answer, ringing.
const E2EE_ONLY: rule::HangupRoute = rule::HangupRoute {
    e2ee: true,
    stream: false,
};

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

/// What to do with an offer that arrived, from the core's rule (`rule::on_offer`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfferDisposition {
    /// Ring: the call is now held, incoming. Also glare where theirs wins: our outgoing call gave
    /// way to it.
    Ring,
    /// A call is already held: answer busy to the offering device.
    Busy,
    /// Glare, and ours wins: ignore their offer; they will answer ours.
    KeepOurs,
    /// The offer is for the call already held — held until the answer, or a renegotiation.
    /// Nothing to ring and nothing to send: stage A carries no SDP to apply.
    HeldCall,
}

/// One 1:1 call at a time. The call's state is the core's call machine (construct-rules
/// `call_machine`, todo 295 step 5), the same iOS and Android hold; this keeps what the screen
/// shows and turns the machine's answers into signals.
#[derive(Debug, Default)]
pub struct Manager {
    machine: machine::Calls,
    active: Option<Call>,
    /// The history row of the call that just ended, not taken yet.
    record: Option<HistoryRecord>,
}

impl Manager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn active(&self) -> Option<&Call> {
        self.active.as_ref()
    }

    /// The device the call talks to, once chosen.
    pub fn chosen_device(&self) -> Option<&str> {
        self.machine.active()?.chosen.as_deref()
    }

    /// The devices our offer went to, until one answers.
    pub fn offered_devices(&self) -> &[String] {
        self.machine.active().map_or(&[], |c| c.offered.as_slice())
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

    /// A call is up. One whose outcome the person has not dismissed yet does not block a new one.
    pub fn is_busy(&self) -> bool {
        self.machine.active().is_some()
    }

    /// Bring the screen's call in line with the machine's after a change.
    fn sync(&mut self) {
        let (Some(held), Some(call)) = (self.machine.active(), self.active.as_mut()) else {
            return;
        };
        if held.call_id != call.call_id {
            return;
        }
        call.phase = match held.phase {
            machine::Phase::Incoming => Phase::Incoming,
            machine::Phase::Dialing => Phase::Calling,
            machine::Phase::Ringing => Phase::Ringing,
            machine::Phase::Connecting => Phase::Connecting,
            machine::Phase::Active => Phase::Live,
        };
        call.connected_at_ms = held.answered_at_ms;
    }

    /// The machine ended the call: the screen shows its outcome, and its history row waits.
    fn ended(&mut self, ended: machine::Ended) {
        if let Some(call) = self.active.as_mut().filter(|c| c.call_id == ended.call_id) {
            call.phase = Phase::Over(outcome_of(&ended));
        }
        self.record = ended.history.map(|status| HistoryRecord {
            id: ended.call_id.clone(),
            peer_user_id: ended.peer_user_id.clone(),
            direction: match ended.direction {
                rule::Direction::Outgoing => 0,
                rule::Direction::Incoming => 1,
            },
            status: i16::from(status.code()),
            started_at_ms: ended.started_at_ms,
            duration_seconds: i32::try_from(ended.duration_seconds).unwrap_or(i32::MAX),
        });
    }

    /// Begin an outgoing call to `peer`. Returns the offer to send, or nothing when a call is
    /// already up (the machine's `dial`; the orchestrator asks [`Manager::is_busy`] first).
    pub fn begin_outgoing(
        &mut self,
        call_id: String,
        peer: String,
        call_type: CallType,
        my_device: &str,
        my_user: &str,
    ) -> Option<SignalToSend> {
        if self.machine.dial(&call_id, &peer, now_ms()) != machine::DialAction::Start {
            return None;
        }
        let signal = offer(&call_id, my_device, my_user, call_type, String::new());
        self.active = Some(Call {
            call_id,
            peer: peer.clone(),
            direction: Direction::Outgoing,
            phase: Phase::Calling,
            call_type,
            connected_at_ms: None,
        });
        self.sync();
        Some(SignalToSend {
            peer,
            signal,
            to_device: None,
            route: E2EE_ONLY,
        })
    }

    /// An offer for `call_id` arrived from `sender_device` of `peer`. What it means is the
    /// machine's (`offer`), as on iOS and Android: an ended call's offer rings nothing; glare keeps
    /// the larger account id's call, the smaller one gives its own up and rings for theirs; any
    /// other held call makes this one busy. Stage A carries no SDP, so every offer is usable.
    pub fn on_offer(
        &mut self,
        call_id: String,
        peer: String,
        sender_device: String,
        call_type: CallType,
        my_user: &str,
    ) -> OfferDisposition {
        let step = self
            .machine
            .offer(&call_id, &peer, &sender_device, true, my_user, now_ms());
        match step {
            machine::OfferStep::Busy => OfferDisposition::Busy,
            machine::OfferStep::KeepOurs => OfferDisposition::KeepOurs,
            machine::OfferStep::Ignore
            | machine::OfferStep::Hold
            | machine::OfferStep::ResumeAnswer
            | machine::OfferStep::Renegotiate => OfferDisposition::HeldCall,
            machine::OfferStep::Fail(ended) => {
                self.ended(ended);
                OfferDisposition::HeldCall
            }
            // Ours gives way: their offer replaces it. The peer ignores our offer (it keeps its
            // own call), so nothing is sent for the call we drop.
            machine::OfferStep::Ring | machine::OfferStep::ReplaceOutgoing { .. } => {
                self.active = Some(Call {
                    call_id,
                    peer,
                    direction: Direction::Incoming,
                    phase: Phase::Incoming,
                    call_type,
                    connected_at_ms: None,
                });
                self.record = None;
                self.sync();
                OfferDisposition::Ring
            }
        }
    }

    /// Record which devices the outgoing offer went to.
    pub fn note_offered(&mut self, devices: &[String]) {
        self.machine.offer_sent(devices.to_vec());
    }

    /// A signal arrived from `sender_device` (the device whose session opened it) for the held
    /// call. Returns signals to send back: releases to devices the call no longer needs, and the
    /// received hangup repeated where the machine routes it.
    pub fn on_signal(
        &mut self,
        signal: &WebRtcSignal,
        sender_device: &str,
        my_device: &str,
    ) -> Vec<SignalToSend> {
        let Some(peer) = self
            .machine
            .active()
            .filter(|c| c.call_id == signal.call_id)
            .map(|c| c.peer_user_id.clone())
        else {
            // A late signal of an ended call, or of a different call.
            return Vec::new();
        };
        let Some(inner) = &signal.signal else {
            return Vec::new();
        };
        use web_rtc_signal::Signal as S;
        let out = match inner {
            S::Answer(_) => match self.machine.answer_from(&signal.call_id, sender_device) {
                Some(rule::AnswerDisposition::ReleaseLate { device }) => {
                    release(&peer, &signal.call_id, &[device], my_device)
                }
                Some(rule::AnswerDisposition::Accept {
                    release: others, ..
                }) => {
                    // Stage A has no SDP to apply: the answer is the call answered.
                    self.machine.answered(now_ms());
                    release(&peer, &signal.call_id, &others, my_device)
                }
                None => Vec::new(),
            },
            S::Hangup(h) => self.remote_hangup(
                &peer,
                &signal.call_id,
                sender_device,
                rule::HangupReason::from_wire(h.reason),
                my_device,
            ),
            S::Busy(_) => self.remote_hangup(
                &peer,
                &signal.call_id,
                sender_device,
                rule::HangupReason::Busy,
                my_device,
            ),
            _ if !rule::admits(sender_device, self.chosen_device()) => Vec::new(),
            S::Ringing(_) => {
                self.machine.ringing();
                Vec::new()
            }
            // ICE, connected and media updates have no media to apply yet (stage B). An offer
            // for the held call id is the machine's (`on_offer`).
            S::IceCandidate(_)
            | S::IceCandidates(_)
            | S::Connected(_)
            | S::MediaUpdate(_)
            | S::Offer(_) => Vec::new(),
        };
        self.sync();
        out
    }

    /// A hangup (or a busy) from one of the peer's devices, as the machine routes it.
    fn remote_hangup(
        &mut self,
        peer: &str,
        call_id: &str,
        from: &str,
        reason: rule::HangupReason,
        my_device: &str,
    ) -> Vec<SignalToSend> {
        match self.machine.hangup_from(call_id, from, reason, now_ms()) {
            machine::RemoteHangupStep::Ignore | machine::RemoteHangupStep::DropDevice { .. } => {
                Vec::new()
            }
            machine::RemoteHangupStep::End {
                release: others,
                reason,
                route,
                ended,
            } => {
                self.ended(ended);
                let mut out = release(peer, call_id, &others, my_device);
                // The peer told us; the server has not heard, and without it keeps us "in a call"
                // and refuses the peer's call-back as busy (iOS AC92380B). Nowhere for "taken
                // elsewhere". The machine says which paths.
                if route.e2ee || route.stream {
                    out.push(SignalToSend {
                        peer: peer.to_owned(),
                        signal: hangup(call_id, my_device, proto_reason(reason)),
                        to_device: None,
                        route,
                    });
                }
                out
            }
        }
    }

    /// The person answered the incoming call. Returns the answer to send back.
    pub fn accept(&mut self, my_device: &str, my_user: &str) -> Vec<SignalToSend> {
        if self.machine.accept(now_ms()) == machine::AcceptStep::Ignore {
            return Vec::new();
        }
        let Some(held) = self.machine.active() else {
            return Vec::new();
        };
        let (peer, call_id, device) = (
            held.peer_user_id.clone(),
            held.call_id.clone(),
            held.chosen.clone(),
        );
        // Stage A has no offer to apply: the answer going out is the call answered.
        self.machine.answered(now_ms());
        self.sync();
        vec![SignalToSend {
            peer,
            signal: answer(&call_id, my_device, my_user, String::new()),
            to_device: device,
            route: E2EE_ONLY,
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
    /// a normal hangup otherwise — the machine's `hang_up`. Returns the hangup to every device the
    /// call reaches; the call stays in `Over(_)` until `dismiss`.
    pub fn end(&mut self, my_device: &str) -> Vec<SignalToSend> {
        let Some(hangup) = self.machine.hang_up(now_ms()) else {
            return Vec::new();
        };
        self.local_hangup(hangup, my_device)
    }

    fn local_hangup(&mut self, h: machine::Hangup, my_device: &str) -> Vec<SignalToSend> {
        let (peer, call_id) = (h.ended.peer_user_id.clone(), h.ended.call_id.clone());
        self.ended(h.ended);
        let wire = hangup(&call_id, my_device, proto_reason(h.reason));
        if h.targets.is_empty() {
            // No device known yet (the offer is still going out): every device with a session.
            return vec![SignalToSend {
                peer,
                signal: wire,
                to_device: None,
                route: h.route,
            }];
        }
        h.targets
            .into_iter()
            .map(|device| SignalToSend {
                peer: peer.clone(),
                signal: wire.clone(),
                to_device: Some(device),
                route: h.route,
            })
            .collect()
    }

    /// The earliest moment (Unix ms) [`Manager::tick`] has something to do.
    pub fn next_deadline(&self) -> Option<i64> {
        self.machine.next_deadline()
    }

    /// What the deadlines that passed by `now_ms` decided: an incoming call nobody answered ends
    /// with our TIMEOUT (until now nothing ended it here, and it made every later caller busy).
    /// An ICE restart waits for media (stage B).
    pub fn tick(&mut self, now_ms: i64, my_device: &str) -> Vec<SignalToSend> {
        match self.machine.tick(now_ms) {
            Some(machine::Due::Unanswered(h)) => self.local_hangup(h, my_device),
            Some(machine::Due::NoOffer(ended)) => {
                self.ended(ended);
                Vec::new()
            }
            Some(machine::Due::RestartIce) => {
                self.machine.ice_restart_sent();
                Vec::new()
            }
            None => Vec::new(),
        }
    }

    /// The person closed the ended call's outcome.
    pub fn dismiss(&mut self) {
        if !self.is_busy() {
            self.active = None;
        }
    }

    /// The history row for a call that just ended and was not yet recorded. `None` when there is
    /// none, or it must not be recorded (taken on another of our devices). Its length is the
    /// machine's, at the end.
    pub fn take_history_record(&mut self, _now_ms: i64) -> Option<HistoryRecord> {
        self.record.take()
    }
}

/// Release `devices`: tell each the call was taken elsewhere (E2EE, to that device alone).
fn release(peer: &str, call_id: &str, devices: &[String], my_device: &str) -> Vec<SignalToSend> {
    devices
        .iter()
        .map(|device| SignalToSend {
            peer: peer.to_owned(),
            signal: hangup(call_id, my_device, HangupReason::AcceptedElsewhere),
            to_device: Some(device.clone()),
            route: rule::hangup_route(
                rule::HangupSide::Local,
                rule::HangupReason::AcceptedElsewhere,
            ),
        })
        .collect()
}

/// The screen's outcome: the machine's, plus the one case it leaves to the screen — a call
/// another of our devices took, which is neither missed nor ended here.
fn outcome_of(ended: &machine::Ended) -> Outcome {
    if ended.reason == rule::EndReason::Hangup(rule::HangupReason::AcceptedElsewhere) {
        return Outcome::AnsweredElsewhere;
    }
    match ended.outcome {
        rule::Outcome::Ended { .. } => Outcome::Ended,
        rule::Outcome::Declined => Outcome::Declined,
        rule::Outcome::Busy => Outcome::Busy,
        rule::Outcome::NoAnswer => Outcome::NoAnswer,
        rule::Outcome::Failed => Outcome::Failed,
    }
}

fn proto_reason(reason: rule::HangupReason) -> HangupReason {
    HangupReason::try_from(reason.wire()).unwrap_or(HangupReason::Unspecified)
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

/// Ringing back to the device that offered: end to end only.
pub fn ring_back(peer: String, device: String, call_id: &str, my_device: &str) -> SignalToSend {
    SignalToSend {
        peer,
        signal: ringing(call_id, my_device),
        to_device: Some(device),
        route: E2EE_ONLY,
    }
}

/// Busy back to the device that offered a second call: ours, so it goes as a local hangup of
/// reason busy does (`rule::hangup_route`) — the peer hears it and the server frees the call.
pub fn refuse_busy(peer: String, device: String, call_id: &str, my_device: &str) -> SignalToSend {
    SignalToSend {
        peer,
        signal: busy(call_id, my_device),
        to_device: Some(device),
        route: rule::hangup_route(rule::HangupSide::Local, rule::HangupReason::Busy),
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
        manager
            .begin_outgoing(
                "c1".into(),
                "peer".into(),
                CallType::Audio,
                "me",
                "me@konstruct.cc",
            )
            .expect("nothing else is up");
    }

    /// Their call `call_id`, rung by its offer from `device`.
    fn ring(manager: &mut Manager, call_id: &str, device: &str) {
        assert_eq!(
            manager.on_offer(
                call_id.into(),
                "peer".into(),
                device.into(),
                CallType::Audio,
                "me"
            ),
            OfferDisposition::Ring
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
        assert_eq!(m.chosen_device(), Some("peer-device"));
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
        // Never on the stream: the server would end the call for the device that took it.
        assert_eq!(out[0].route, E2EE_ONLY);
        assert_eq!(m.chosen_device(), Some("device-1"));
    }

    #[test]
    fn accepting_an_incoming_call_answers_and_goes_live() {
        let mut m = Manager::new();
        ring(&mut m, "c1", "peer-device");
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
        m.on_signal(&hangup_sig, "peer-device", "me");
        assert_eq!(m.active().unwrap().phase, Phase::Over(Outcome::Declined));
    }

    /// iOS AC92380B: the peer's hangup reached us end to end and not the server, which kept us
    /// "in a call" and refused the peer's call-back as busy. It goes to the stream, and not back
    /// to the peer, who already knows.
    ///
    /// Mutations: drop the stream hangup after a received one; send it end to end too.
    #[test]
    fn a_received_hangup_tells_the_server_and_not_the_peer() {
        let mut m = Manager::new();
        begin_outgoing(&mut m);
        let hangup_sig = hangup("c1", "peer-device", HangupReason::Declined);
        let out = m.on_signal(&hangup_sig, "peer-device", "me");
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].route,
            rule::HangupRoute {
                e2ee: false,
                stream: true
            }
        );
        let Some(S::Hangup(h)) = &out[0].signal.signal else {
            panic!("expected a hangup, got {:?}", out[0].signal.signal);
        };
        assert_eq!(h.reason, HangupReason::Declined as i32);
    }

    /// Ours goes both ways: the peer hears it, the server frees us.
    ///
    /// Mutation: `end` routes its hangup as a received one.
    #[test]
    fn our_hangup_goes_to_the_peer_and_the_server() {
        let mut m = Manager::new();
        begin_outgoing(&mut m);
        let out = m.end("me");
        assert!(!out.is_empty());
        for to_send in &out {
            assert_eq!(
                to_send.route,
                rule::HangupRoute {
                    e2ee: true,
                    stream: true
                }
            );
        }
    }

    /// Busy back to a second caller goes as our hangup does; ringing back only end to end.
    ///
    /// Mutations: `refuse_busy` end to end only; `ring_back` on the stream.
    #[test]
    fn busy_back_frees_the_server_and_ringing_back_does_not_touch_it() {
        let busy = refuse_busy("peer".into(), "d".into(), "c1", "me");
        assert_eq!(
            busy.route,
            rule::HangupRoute {
                e2ee: true,
                stream: true
            }
        );
        let ring = ring_back("peer".into(), "d".into(), "c1", "me");
        assert_eq!(ring.route, E2EE_ONLY);
        assert!(matches!(ring.signal.signal, Some(S::Ringing(_))));
    }

    /// An offer for the call already ringing is that call's, not a second caller: answering it
    /// busy would end the call the person is about to take.
    ///
    /// Mutation: `held` never names the same call.
    #[test]
    fn an_offer_for_the_held_call_is_not_a_second_caller() {
        let mut m = Manager::new();
        ring(&mut m, "c1", "peer-device");
        assert_eq!(
            m.on_offer(
                "c1".into(),
                "peer".into(),
                "peer-device".into(),
                CallType::Audio,
                "me"
            ),
            OfferDisposition::HeldCall
        );
        assert_eq!(m.active().unwrap().phase, Phase::Incoming);
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
        ring(&mut m, "c1", "peer-device");
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
        ring(&mut m, "c1", "peer-device");
        let h = hangup("c1", "peer-device", HangupReason::AcceptedElsewhere);
        m.on_signal(&h, "peer-device", "me");
        assert_eq!(
            m.active().unwrap().phase,
            Phase::Over(Outcome::AnsweredElsewhere)
        );
        assert!(m.take_history_record(now_ms()).is_none());
    }

    /// The row's status and direction, as the store keeps them.
    fn row(m: &mut Manager) -> (i16, i16) {
        let r = m.take_history_record(0).expect("a row");
        (r.status, r.direction)
    }

    #[test]
    fn history_status_maps_the_outcomes_as_ios_does() {
        // Incoming, declined by us → declined (2), direction incoming (1).
        let mut m = Manager::new();
        ring(&mut m, "c1", "peer-device");
        m.decline("me");
        assert_eq!(row(&mut m), (2, 1));

        // Outgoing, the peer declined → missed (1), direction outgoing (0).
        let mut m = Manager::new();
        begin_outgoing(&mut m);
        let h = hangup("c1", "peer-device", HangupReason::Declined);
        m.on_signal(&h, "peer-device", "me");
        assert_eq!(row(&mut m), (1, 0));

        // Connected and ended normally → completed (0); never connected → missed (1).
        let mut m = Manager::new();
        begin_outgoing(&mut m);
        let a = answer("c1", "peer-device", "peer", String::new());
        m.on_signal(&a, "peer-device", "me");
        let h = hangup("c1", "peer-device", HangupReason::Normal);
        m.on_signal(&h, "peer-device", "me");
        assert_eq!(row(&mut m).0, 0);

        let mut m = Manager::new();
        begin_outgoing(&mut m);
        let h = hangup("c1", "peer-device", HangupReason::Normal);
        m.on_signal(&h, "peer-device", "me");
        assert_eq!(row(&mut m).0, 1);
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
        assert_eq!(m.offered_devices(), ["d2"]);
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
        assert_eq!(row(&mut m).0, 1);
    }

    /// Mutation: always a normal hangup — a ringing call we end is declined.
    #[test]
    fn ending_an_incoming_call_that_still_rings_declines_it() {
        let mut m = Manager::new();
        ring(&mut m, "c1", "pd");
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
        ring(&mut m, "c1", "pd");
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
        ring(&mut m, "c1", "pd");
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
    fn an_ended_call_writes_its_row_once() {
        let mut m = Manager::new();
        begin_outgoing(&mut m);
        m.on_signal(&answer("c1", "pd", "peer", String::new()), "pd", "me");
        assert!(m.take_history_record(now_ms()).is_none(), "not over yet");
        m.on_signal(&hangup("c1", "pd", HangupReason::Normal), "pd", "me");
        let row = m.take_history_record(now_ms()).expect("a row");
        assert_eq!((row.id.as_str(), row.peer_user_id.as_str()), ("c1", "peer"));
        // The length is the machine's, counted at the end: under a second here.
        assert_eq!((row.direction, row.status, row.duration_seconds), (0, 0, 0));
        assert!(m.take_history_record(now_ms()).is_none(), "written once");
    }

    /// Nothing ended an unanswered incoming call here: it rang until the caller gave up and made
    /// every later caller busy. The machine's deadline ends it with our TIMEOUT to its device.
    ///
    /// Mutations: `tick` ignores the unanswered deadline; no deadline armed.
    #[test]
    fn an_unanswered_call_ends_at_the_machines_deadline() {
        let mut m = Manager::new();
        ring(&mut m, "c1", "pd");
        let due = m.next_deadline().expect("a ring deadline");
        assert!(m.tick(due - 1, "me").is_empty());
        let out = m.tick(due, "me");
        assert_eq!(out.len(), 1);
        assert_eq!(hangup_reason(&out[0]), HangupReason::Timeout as i32);
        assert_eq!(out[0].to_device.as_deref(), Some("pd"));
        assert_eq!(m.active().unwrap().phase, Phase::Over(Outcome::NoAnswer));
        assert_eq!(row(&mut m), (1, 1));
        assert!(!m.is_busy());
    }

    /// What the screen reads is the machine's call: its phase and when it went live.
    ///
    /// Mutation: `state` returns nothing.
    #[test]
    fn the_screen_reads_the_machines_call() {
        let mut m = Manager::new();
        assert_eq!(m.state(), None);
        begin_outgoing(&mut m);
        let state = m.state().expect("a call");
        assert_eq!(
            (
                state.call_id.as_str(),
                state.peer_id.as_str(),
                state.direction,
                state.phase,
                state.connected_at_ms
            ),
            ("c1", "peer", Direction::Outgoing, Phase::Calling, None)
        );
        m.on_signal(&answer("c1", "pd", "peer", String::new()), "pd", "me");
        let state = m.state().expect("a call");
        assert_eq!(state.phase, Phase::Live);
        assert!(state.connected_at_ms.is_some());
    }
}
