//! VEIL for the screens: the mode, the fronts this device holds, and the tunnel kept up while
//! the mode is on (decisions/desktop-veil.md).
//!
//! - **Off**: every connection goes straight to the server.
//! - **Auto** (the default, as on iOS): direct, until direct fails the way a block fails; then
//!   through a front, and back to direct when a direct call answers.
//! - **On**: every connection goes through a front, and none goes anywhere else
//!   (decisions/veil-on-never-goes-direct.md): with no front up, requests fail instead of
//!   leaving the tunnel.
//!
//! When to go through a front and when to come back is `veil::transport_route` — the reducer
//! iOS and Android run on the same vectors — driven by what calls and the message stream report
//! (`grpc::route::report`); the router here carries out what it decides.
//!
//! Fronts come signed (`veil::trust`): issued to this device with its capability while it is
//! signed in — in any mode, so they are there before the mode is turned on — or from a
//! `konstruct://veil-config` link. The device's own access key (`veil_sk`) is made here once and
//! never leaves it; only its public half goes to the server, which binds capabilities to it.
//!
//! **Before there is an account** (a new install on a blocked network), a link "arms" VEIL, as
//! on iOS (decisions/user-vouched-veil-bootstrap.md): its front is held in memory, the route is
//! closed to anything but the tunnel, and registering or linking goes through it. When the new
//! account's store is made, the front and the mode move into it.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::{Client, ClientEvent};
use crate::grpc::route::{self, Route};
use crate::local_store::LocalStore;
use crate::veil::transport_route::{
    Config, Effect, Event, Mode, State, StreamMethod, Target, initial, reduce,
};
use crate::veil::trust::{self, Front};
use crate::veil::tunnel::Tunnel;

const KEY_MODE: &str = "veil.mode";
const KEY_SK: &str = "veil.sk";
const KEY_FRONTS: &str = "veil.fronts";

/// A capability is renewed when it has less than this left (iOS: 14 days).
const RENEW_BEFORE: i64 = 14 * 24 * 3600;
const ISSUE_RETRY: Duration = Duration::from_secs(60);
const ISSUE_RECHECK: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum VeilMode {
    Off,
    Auto,
    On,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum VeilState {
    /// Not through a front: VEIL off, or Auto on the direct path.
    Off,
    Connecting,
    /// Connected through this front (its host only).
    Up {
        front: String,
    },
    /// On, and no front answers: nothing is sent.
    NoFront,
}

/// What the VEIL settings show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VeilStatus {
    pub mode: VeilMode,
    pub state: VeilState,
    /// Fronts this device holds a live capability for.
    pub fronts: usize,
}

/// Where the tunnel takes its fronts from: the account's store, or, before there is one, the
/// front of a link (in memory only — a voucher lasts minutes).
enum Fronts {
    Store(LocalStore),
    Armed(Front),
}

impl Fronts {
    fn usable(&self) -> Vec<Front> {
        let now = now();
        match self {
            Self::Store(store) => fronts(store),
            Self::Armed(front) => vec![front.clone()],
        }
        .into_iter()
        .filter(|f| f.usable_at(now))
        .collect()
    }
}

/// Shared with the tunnel loop, which reads it on every round: the armed front becomes the
/// account's without the tunnel being restarted.
type FrontSource = Arc<Mutex<Fronts>>;

/// The tasks VEIL runs while an account is open, or while it is armed before one.
#[derive(Default)]
pub(super) struct VeilRuntime {
    tunnel_loop: Option<tokio::task::AbortHandle>,
    provisioner: Option<tokio::task::AbortHandle>,
    source: Option<FrontSource>,
}

impl Drop for VeilRuntime {
    fn drop(&mut self) {
        for task in [&self.tunnel_loop, &self.provisioner].into_iter().flatten() {
            task.abort();
        }
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// The mode as kept: 0 off, 1 on, 2 auto; nothing kept is Auto, iOS's default.
fn mode(store: &LocalStore) -> VeilMode {
    match store.secure_load(KEY_MODE) {
        Ok(Some(v)) if v == [0] => VeilMode::Off,
        Ok(Some(v)) if v == [1] => VeilMode::On,
        _ => VeilMode::Auto,
    }
}

fn mode_byte(mode: VeilMode) -> u8 {
    match mode {
        VeilMode::Off => 0,
        VeilMode::On => 1,
        VeilMode::Auto => 2,
    }
}

/// This device's access key, made once.
fn veil_sk(store: &LocalStore) -> Result<zeroize::Zeroizing<[u8; 32]>, String> {
    if let Ok(Some(v)) = store.secure_load(KEY_SK)
        && let Ok(sk) = <[u8; 32]>::try_from(v.as_slice())
    {
        return Ok(zeroize::Zeroizing::new(sk));
    }
    let sk = zeroize::Zeroizing::new(rand::random::<[u8; 32]>());
    store
        .secure_save(KEY_SK, sk.as_slice())
        .map_err(|e| format!("VEIL key not kept: {e}"))?;
    Ok(sk)
}

fn veil_pk(sk: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(sk)
        .verifying_key()
        .to_bytes()
}

pub(super) fn fronts(store: &LocalStore) -> Vec<Front> {
    let fronts: Vec<Front> = store
        .secure_load(KEY_FRONTS)
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_slice(&v).ok())
        .unwrap_or_default();
    register(&fronts);
    fronts
}

/// Keep `new` among the fronts, each address once (the newer replaces the older), the expired
/// ones dropped, newest first — the order they are tried in.
fn merge(store: &LocalStore, new: Vec<Front>) -> Vec<Front> {
    let now = now();
    register(&new);
    let mut all = new;
    for f in fronts(store) {
        if !all.iter().any(|n| n.relay.eq_ignore_ascii_case(&f.relay)) {
            all.push(f);
        }
    }
    all.retain(|f| f.usable_at(now));
    match serde_json::to_vec(&all) {
        Ok(v) => {
            if let Err(e) = store.secure_save(KEY_FRONTS, &v) {
                tracing::warn!("VEIL fronts not kept: {e}");
            }
        }
        Err(e) => tracing::warn!("VEIL fronts not encoded: {e}"),
    }
    all
}

/// How a status or a log names a front: its keyed label in a release build
/// (decisions/veil-front-in-logs-is-a-keyed-label).
fn host(relay: &str) -> String {
    crate::veil::redact::front_label(relay.rsplit_once(':').map_or(relay, |(h, _)| h))
}

/// Let the log writer replace these fronts' names.
fn register(fronts: &[Front]) {
    crate::veil::redact::register(fronts.iter().flat_map(|f| {
        let host = f
            .relay
            .rsplit_once(':')
            .map_or(f.relay.as_str(), |(h, _)| h);
        // `host:port` becomes `label:port`: one label per front.
        [host.to_owned(), f.sni.clone()]
    }));
}

/// Shared between the tasks and the client: the last status, sent on every change.
#[derive(Clone)]
pub(super) struct Status {
    current: Arc<Mutex<VeilStatus>>,
    events: tokio::sync::mpsc::UnboundedSender<ClientEvent>,
}

impl Status {
    fn new(events: tokio::sync::mpsc::UnboundedSender<ClientEvent>) -> Self {
        Self {
            current: Arc::new(Mutex::new(VeilStatus {
                mode: VeilMode::Off,
                state: VeilState::Off,
                fronts: 0,
            })),
            events,
        }
    }

    fn update(&self, change: impl FnOnce(&mut VeilStatus)) {
        let snapshot = {
            let mut s = self.current.lock().unwrap_or_else(|e| e.into_inner());
            let before = s.clone();
            change(&mut s);
            (*s != before).then(|| s.clone())
        };
        if let Some(s) = snapshot {
            let _ = self.events.send(ClientEvent::Veil(s));
        }
    }

    fn get(&self) -> VeilStatus {
        self.current
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

impl Client {
    fn veil_status(&mut self) -> Status {
        self.veil_status
            .get_or_insert_with(|| Status::new(self.events.clone()))
            .clone()
    }

    /// The account's store is open: route connections by its mode, and keep the tunnel while it
    /// is on. Before this nothing is routed through VEIL — a store that is not open has no fronts.
    /// Capabilities are asked for once the session is signed in ([`Self::provision_veil`]).
    pub(super) fn start_veil(&mut self) {
        let Some(store) = self.store.clone() else {
            return;
        };
        self.veil = None;
        let mode = mode(&store);
        let status = self.veil_status();
        let held = fronts(&store).iter().filter(|f| f.usable_at(now())).count();
        status.update(|s| {
            s.mode = mode;
            s.fronts = held;
            s.state = if mode == VeilMode::On {
                VeilState::Connecting
            } else {
                VeilState::Off
            };
        });
        let tunnel_loop = match mode {
            VeilMode::Off => {
                route::set_sink(None);
                route::set_route(Route::Direct);
                let tunnel = self.veil_tunnel.clone();
                tokio::spawn(async move {
                    if let Some(t) = tunnel.lock().await.as_ref() {
                        t.stop().await;
                    }
                });
                None
            }
            VeilMode::Auto | VeilMode::On => match veil_sk(&store) {
                Ok(sk) => Some(self.spawn_router(
                    mode,
                    Arc::new(Mutex::new(Fronts::Store(store.clone()))),
                    sk,
                    status.clone(),
                )),
                Err(e) => {
                    tracing::warn!("{e}");
                    route::set_route(if mode == VeilMode::On {
                        Route::Closed
                    } else {
                        Route::Direct
                    });
                    None
                }
            },
        };
        self.drop_connections();
        let signed_in = self.orch_handle.is_some();
        self.veil = Some(VeilRuntime {
            tunnel_loop,
            provisioner: None,
            source: None,
        });
        if signed_in {
            self.provision_veil();
        }
    }

    /// Signed in: keep a capability for this device and its fronts, in any mode.
    pub(super) fn provision_veil(&mut self) {
        let Some(store) = self.store.clone() else {
            return;
        };
        let status = self.veil_status();
        let task = tokio::spawn(provision(self.grpc.clone(), store, status)).abort_handle();
        self.veil.get_or_insert_with(Default::default).provisioner = Some(task);
    }

    /// Connections open now were made on the route before; a live one (the message stream) would
    /// stay on it until something replaced it. Closed now, as iOS closes its channels when the
    /// mode changes: what was on them reconnects along the new route.
    fn drop_connections(&self) {
        let (signed, anonymous) = (self.grpc.clone(), self.anonymous.clone());
        tokio::spawn(async move {
            signed.invalidate().await;
            anonymous.invalidate().await;
        });
    }

    /// The account is closed: back to direct, the tunnel down.
    pub(super) fn stop_veil(&mut self) {
        self.veil = None;
        route::set_sink(None);
        route::set_route(Route::Direct);
        self.drop_connections();
        let tunnel = self.veil_tunnel.clone();
        tokio::spawn(async move {
            if let Some(t) = tunnel.lock().await.as_ref() {
                t.stop().await;
            }
        });
        self.veil_status().update(|s| {
            s.mode = VeilMode::Off;
            s.state = VeilState::Off;
            s.fronts = 0;
        });
    }

    pub(super) fn load_veil(&mut self) {
        let status = self.veil_status().get();
        self.emit(ClientEvent::Veil(status));
    }

    /// A voucher for another device: a `konstruct://veil-config` link to one front, short-lived
    /// (iOS: 45 minutes, three a day), for someone who cannot reach the server yet.
    pub(super) fn issue_veil_voucher(&self) {
        let grpc = self.grpc.clone();
        let events = self.events.clone();
        tokio::spawn(async move {
            let result = crate::grpc::issue_bootstrap_voucher(&grpc)
                .await
                .map(|r| (r.config_uri, r.exp))
                .map_err(|e| e.to_string());
            let _ = events.send(ClientEvent::VeilVoucher(result));
        });
    }

    pub(super) fn set_veil_mode(&mut self, mode: VeilMode) {
        let Some(store) = self.store.as_ref() else {
            // No account yet: turning it off disarms a link.
            if mode == VeilMode::Off && self.armed.take().is_some() {
                tracing::info!("VEIL disarmed");
                self.stop_veil();
            }
            return;
        };
        if let Err(e) = store.secure_save(KEY_MODE, &[mode_byte(mode)]) {
            return self.emit(ClientEvent::Notice(format!("Not changed: {e}")));
        }
        tracing::info!(?mode, "VEIL mode set");
        self.start_veil();
    }

    /// A `konstruct://veil-config` link: its front, checked and kept; with the mode on, the
    /// tunnel starts over to use it.
    pub(super) fn import_veil_link(&mut self, link: String) {
        let Some(store) = self.store.clone() else {
            return self.arm_veil(&link);
        };
        match trust::import_link(&link, &fronts(&store), now()) {
            Ok(front) => {
                register(std::slice::from_ref(&front));
                tracing::info!(front = %host(&front.relay), "VEIL front added from a link");
                let held = merge(&store, vec![front]).len();
                self.veil_status().update(|s| s.fronts = held);
                if mode(&store) != VeilMode::Off {
                    self.start_veil();
                }
            }
            Err(e) => self.emit(ClientEvent::Notice(format!(
                "This VEIL link is refused: {e}"
            ))),
        }
    }
}

impl Client {
    /// No account yet: a link's front carries what comes before one — registering, linking.
    /// Nothing goes anywhere else while it is armed.
    fn arm_veil(&mut self, link: &str) {
        let front = match trust::import_link(link, &[], now()) {
            Ok(front) => front,
            Err(e) => {
                return self.emit(ClientEvent::Notice(format!(
                    "This VEIL link is refused: {e}"
                )));
            }
        };
        register(std::slice::from_ref(&front));
        tracing::info!(front = %host(&front.relay), "VEIL armed before sign-in");
        self.armed = Some(front.clone());
        self.veil = None;
        route::set_route(Route::Closed);
        self.drop_connections();
        let status = self.veil_status();
        status.update(|s| {
            s.mode = VeilMode::On;
            s.state = VeilState::Connecting;
            s.fronts = 1;
        });
        // A bearer capability needs no key of ours; the device key is made with the account.
        let sk = zeroize::Zeroizing::new(rand::random::<[u8; 32]>());
        let source = Arc::new(Mutex::new(Fronts::Armed(front)));
        let task = self.spawn_router(VeilMode::On, source.clone(), sk, status);
        self.veil = Some(VeilRuntime {
            tunnel_loop: Some(task),
            provisioner: None,
            source: Some(source),
        });
    }

    /// The new account's store is made: an armed front and the mode go into it, and VEIL goes on
    /// from the store (the device key is made, a capability of its own follows sign-in).
    pub(super) fn adopt_armed_veil(&mut self) {
        let (Some(front), Some(store)) = (self.armed.take(), self.store.clone()) else {
            return;
        };
        let held = merge(&store, vec![front]).len();
        if let Err(e) = store.secure_save(KEY_MODE, &[mode_byte(VeilMode::On)]) {
            tracing::warn!("VEIL mode not kept: {e}");
        }
        if let Err(e) = veil_sk(&store) {
            tracing::warn!("{e}");
        }
        tracing::info!("VEIL front kept with the new account");
        self.veil_status().update(|s| s.fronts = held);
        // The tunnel stays as it is — the same front, and connections on it — and its loop reads
        // the account's fronts from now on. A restart here, a minute after the voucher's first
        // session, left the front's probe hanging (2026-10-29).
        match self.veil.as_ref().and_then(|v| v.source.clone()) {
            Some(source) => {
                *source.lock().unwrap_or_else(|e| e.into_inner()) = Fronts::Store(store);
            }
            None => self.start_veil(),
        }
    }
}

impl Client {
    /// The router for `mode` (Auto or On), its fronts from `source`; its task's handle.
    fn spawn_router(
        &self,
        mode: VeilMode,
        source: FrontSource,
        sk: zeroize::Zeroizing<[u8; 32]>,
        status: Status,
    ) -> tokio::task::AbortHandle {
        let (sink, reports) = tokio::sync::mpsc::unbounded_channel();
        route::set_sink(Some(sink));
        let (tx, inputs) = tokio::sync::mpsc::unbounded_channel();
        let router = Router {
            mode: match mode {
                VeilMode::On => Mode::On,
                _ => Mode::Auto,
            },
            state: State::Direct { fails: 0 },
            source,
            sk,
            holder: self.veil_tunnel.clone(),
            scores: self.data.as_ref().map(|d| d.veil_scores_path()),
            status,
            clients: (self.grpc.clone(), self.anonymous.clone()),
            demoted: Default::default(),
            starting: false,
            tx,
        };
        tokio::spawn(router.run(inputs, reports)).abort_handle()
    }
}

/// What the router hears: a call or the stream (and whether it went through the tunnel), or the
/// answer to something it set going.
enum Input {
    Report((route::Report, bool)),
    Started { relay: String, port: u16 },
    StartFailed(String),
    CooldownElapsed,
}

/// Carries out what `veil::transport_route` decides: starts and stops the tunnel, points the
/// route, drops connections, keeps score of fronts that failed.
struct Router {
    mode: Mode,
    state: State,
    source: FrontSource,
    sk: zeroize::Zeroizing<[u8; 32]>,
    holder: Arc<tokio::sync::Mutex<Option<Arc<Tunnel>>>>,
    scores: Option<std::path::PathBuf>,
    status: Status,
    clients: (crate::grpc::GrpcClient, crate::grpc::GrpcClient),
    /// Rotations each front caused: fewer first when a start picks one.
    demoted: std::collections::HashMap<String, u32>,
    starting: bool,
    tx: tokio::sync::mpsc::UnboundedSender<Input>,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

impl Router {
    async fn run(
        mut self,
        mut inputs: tokio::sync::mpsc::UnboundedReceiver<Input>,
        mut reports: tokio::sync::mpsc::UnboundedReceiver<(route::Report, bool)>,
    ) {
        self.state = initial(self.mode, false, true);
        // Starting direct (Auto): a session a router before this one left up goes now.
        if self.state != State::VeilProbing
            && let Some(t) = self.holder.lock().await.as_ref()
        {
            t.stop().await;
        }
        route::set_route(if self.mode == Mode::On {
            Route::Closed
        } else {
            Route::Direct
        });
        self.show();
        if self.state == State::VeilProbing {
            self.apply(vec![Effect::RequestProxyStart]).await;
        }
        loop {
            let input = tokio::select! {
                Some(input) = inputs.recv() => input,
                Some(report) = reports.recv() => Input::Report(report),
                else => break,
            };
            let Some(event) = self.event(input) else {
                continue;
            };
            let out = reduce(&self.state, &event, self.mode, Config::default(), now_ms());
            if out.state != self.state {
                tracing::info!(state = ?Brief(&out.state), "VEIL route");
            }
            self.state = out.state;
            self.apply(out.effects).await;
            self.show();
        }
    }

    fn event(&mut self, input: Input) -> Option<Event> {
        let via = |veil: bool, state: &State| match (veil, state) {
            (true, State::VeilActive { relay, port, .. }) => Target::Veil {
                port: *port,
                relay: relay.clone(),
            },
            (true, _) => Target::Veil {
                port: 0,
                relay: String::new(),
            },
            (false, _) => Target::Direct,
        };
        Some(match input {
            Input::Report((r, veil)) => {
                let via = via(veil, &self.state);
                match r {
                    route::Report::RpcSucceeded { lane, latency_ms } => Event::RpcSucceeded {
                        via,
                        latency_ms,
                        lane,
                    },
                    route::Report::RpcFailed { lane, failure } => Event::RpcFailed {
                        failure,
                        via,
                        // A desktop has no background: every call is one the person waits on.
                        foreground: true,
                        lane,
                    },
                    route::Report::StreamOpened => Event::StreamOpened {
                        method: if veil {
                            StreamMethod::Veil
                        } else {
                            StreamMethod::H2
                        },
                        via,
                    },
                    route::Report::StreamFailed { failure } => Event::StreamFailed {
                        method: if veil {
                            StreamMethod::Veil
                        } else {
                            StreamMethod::H2
                        },
                        failure,
                        via,
                    },
                }
            }
            Input::Started { relay, port } => {
                self.starting = false;
                Event::ProxyStarted {
                    relay,
                    port,
                    restarted: false,
                }
            }
            Input::StartFailed(reason) => {
                self.starting = false;
                Event::ProxyStartFailed {
                    relay: None,
                    reason,
                }
            }
            Input::CooldownElapsed => Event::CooldownElapsed,
        })
    }

    async fn apply(&mut self, effects: Vec<Effect>) {
        for effect in effects {
            match effect {
                Effect::InvalidateGrpcClient => {
                    let (a, b) = self.clients.clone();
                    tokio::spawn(async move {
                        a.invalidate().await;
                        b.invalidate().await;
                    });
                }
                Effect::SetVeilPort(Some(port)) => route::set_route(Route::Veil { port }),
                // Away from the tunnel: direct under Auto, nowhere under On.
                Effect::SetVeilPort(None) => route::set_route(if self.mode == Mode::On {
                    Route::Closed
                } else {
                    Route::Direct
                }),
                // Inline, so a start that follows (a rotation) is not overtaken by it.
                Effect::RequestProxyStop => {
                    if let Some(t) = self.holder.lock().await.as_ref() {
                        t.stop().await;
                    }
                }
                Effect::RequestProxyStart => self.start(),
                Effect::DemoteRelay(relay) => {
                    tracing::info!(front = %host(&relay), "VEIL front demoted");
                    *self.demoted.entry(relay).or_default() += 1;
                }
                Effect::ScheduleCooldownEnd(at_ms) => {
                    let tx = self.tx.clone();
                    let wait = Duration::from_millis((at_ms - now_ms()).max(0) as u64);
                    tokio::spawn(async move {
                        tokio::time::sleep(wait).await;
                        let _ = tx.send(Input::CooldownElapsed);
                    });
                }
            }
        }
    }

    /// Try the live fronts, the least demoted first, newest first among equals; the first that
    /// answers is the tunnel.
    fn start(&mut self) {
        if self.starting {
            return;
        }
        self.starting = true;
        let mut fronts = self
            .source
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .usable();
        fronts.sort_by_key(|f| self.demoted.get(&f.relay).copied().unwrap_or(0));
        let (holder, scores, sk, tx) = (
            self.holder.clone(),
            self.scores.clone(),
            self.sk.clone(),
            self.tx.clone(),
        );
        tokio::spawn(async move {
            let tunnel = {
                let mut held = holder.lock().await;
                if held.is_none() {
                    match Tunnel::new(scores.as_deref()).await {
                        Ok(t) => *held = Some(Arc::new(t)),
                        Err(e) => {
                            let _ = tx.send(Input::StartFailed(e));
                            return;
                        }
                    }
                }
                held.clone().expect("set above")
            };
            if fronts.is_empty() {
                let _ = tx.send(Input::StartFailed("no front".into()));
                return;
            }
            for front in &fronts {
                match tunnel.start(front, &sk).await {
                    Ok(port) => {
                        tracing::info!(front = %host(&front.relay), port, "VEIL tunnel up");
                        let _ = tx.send(Input::Started {
                            relay: front.relay.clone(),
                            port,
                        });
                        return;
                    }
                    Err(e) => {
                        tracing::warn!(front = %host(&front.relay), "VEIL front did not answer: {e}")
                    }
                }
            }
            let _ = tx.send(Input::StartFailed("no front answered".into()));
        });
    }

    /// The state, as the settings show it.
    fn show(&self) {
        let held = self
            .source
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .usable()
            .len();
        let state = match &self.state {
            State::Offline | State::Direct { .. } => VeilState::Off,
            State::VeilProbing => VeilState::Connecting,
            State::VeilActive { relay, .. } => VeilState::Up { front: host(relay) },
            State::VeilCooldown { .. } => VeilState::NoFront,
        };
        self.status.update(|s| {
            s.state = state;
            s.fronts = held;
        });
    }
}

/// A state for the log: the front by its label, not its name.
struct Brief<'a>(&'a State);

impl std::fmt::Debug for Brief<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            State::VeilActive { relay, port, .. } => {
                write!(f, "VeilActive({}, {port})", host(relay))
            }
            other => write!(f, "{other:?}"),
        }
    }
}

/// While signed in, in any mode: a key-bound capability for this device and the fronts that come
/// with it, renewed before it ends. Whatever route is up carries the request — direct, or the
/// tunnel; with the mode on and no tunnel, it waits.
async fn provision(grpc: crate::grpc::GrpcClient, store: LocalStore, status: Status) {
    let sk = match veil_sk(&store) {
        Ok(sk) => sk,
        Err(e) => return tracing::warn!("{e}"),
    };
    let pk = veil_pk(&sk);
    loop {
        let fresh = fronts(&store)
            .iter()
            .any(|f| f.version == 2 && f.not_after - now() > RENEW_BEFORE);
        if fresh {
            tokio::time::sleep(ISSUE_RECHECK).await;
            continue;
        }
        // The server picks the front by the address asked for, one this device holds. No front
        // is built in: the first comes in a link or a voucher, and this renews and widens it.
        let Some(relay_address) = fronts(&store).first().map(|f| f.relay.clone()) else {
            tokio::time::sleep(ISSUE_RETRY).await;
            continue;
        };
        let request = crate::proto::services::v1::IssueVeilCapabilityRequest {
            relay_address,
            veil_pk: pk.to_vec().into(),
            role: 0,
            ..Default::default()
        };
        match crate::grpc::issue_veil_capability(&grpc, &request).await {
            Ok(r) => {
                let known = fronts(&store);
                let now = now();
                let primary = trust::Entry {
                    relay: &r.relay_address,
                    sni: &r.sni,
                    spki: &r.spki,
                    not_after: r.not_after,
                    capability: &r.capability,
                    version: r.capability_version,
                    signature: &r.signature,
                };
                let mut accepted = Vec::new();
                for (i, e) in std::iter::once(primary)
                    .chain(r.alternates.iter().map(|a| trust::Entry {
                        relay: &a.relay_address,
                        sni: &a.sni,
                        spki: &a.spki,
                        not_after: a.not_after,
                        capability: &a.capability,
                        version: a.capability_version,
                        signature: &a.signature,
                    }))
                    .enumerate()
                {
                    match trust::accept_entry(&e, &known, &pk, now) {
                        Ok(f) => accepted.push(f),
                        Err(why) => tracing::warn!(entry = i, "VEIL front refused: {why}"),
                    }
                }
                if accepted.is_empty() {
                    tokio::time::sleep(ISSUE_RETRY).await;
                    continue;
                }
                let held = merge(&store, accepted).len();
                tracing::info!(fronts = held, "VEIL capability issued");
                status.update(|s| s.fronts = held);
            }
            Err(e) => {
                tracing::debug!("VEIL capability not issued yet: {e}");
                tokio::time::sleep(ISSUE_RETRY).await;
            }
        }
    }
}
