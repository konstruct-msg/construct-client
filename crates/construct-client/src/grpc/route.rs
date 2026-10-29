//! Where every connection to the server goes: straight to it, or into the local end of the VEIL
//! tunnel — or nowhere, while VEIL is on and no front is up (decisions/veil-on-never-goes-direct).
//!
//! One route per process, read by every [`super::GrpcClient`] when it connects: the signed
//! client, the one without a token, any made later. A change of route ends their connections, so
//! nothing stays on the old path.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::veil::transport_route::{Lane, RpcFailure, StreamFailure};
use std::sync::{LazyLock, RwLock};
use std::time::Duration;

/// How long a call waits for the tunnel while the route is closed, before it fails (iOS
/// `VeilTunnelWait.untilRouted`: a send waits for the tunnel instead of failing at once).
#[cfg(not(test))]
pub const TUNNEL_WAIT: Duration = Duration::from_secs(30);
#[cfg(test)]
pub const TUNNEL_WAIT: Duration = Duration::from_millis(300);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// TLS to the server itself.
    Direct,
    /// Plain HTTP/2 to `127.0.0.1:port`, where construct-veil carries it to a front.
    Veil { port: u16 },
    /// VEIL is on and there is no tunnel: no connection at all, never a direct one.
    Closed,
}

static ROUTE: RwLock<Route> = RwLock::new(Route::Direct);
static GENERATION: AtomicU64 = AtomicU64::new(0);
/// Connections this process ended itself: route changes and invalidations. A call or a stream
/// that dies across one died of us, not of the network.
static DISRUPTIONS: AtomicU64 = AtomicU64::new(0);
/// Woken on every change of route.
static CHANGED: LazyLock<tokio::sync::watch::Sender<u64>> =
    LazyLock::new(|| tokio::sync::watch::channel(0).0);

/// Send every connection from now on along `route`; connections on another route are ended.
pub fn set_route(route: Route) {
    let mut current = ROUTE.write().unwrap_or_else(|e| e.into_inner());
    if *current != route {
        *current = route;
        let generation = GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
        DISRUPTIONS.fetch_add(1, Ordering::SeqCst);
        CHANGED.send_replace(generation);
        tracing::info!(?route, "transport route changed");
    }
}

/// The route and its generation: a connection made under an older generation is stale.
pub(crate) fn current() -> (Route, u64) {
    let route = ROUTE.read().unwrap_or_else(|e| e.into_inner());
    (*route, GENERATION.load(Ordering::SeqCst))
}

/// What happened to a call or to the message stream, for the VEIL router
/// (`veil::transport_route`): its inputs, as iOS's router gets them from its channels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Report {
    RpcSucceeded { lane: Lane, latency_ms: u32 },
    RpcFailed { lane: Lane, failure: RpcFailure },
    StreamOpened,
    StreamFailed { failure: StreamFailure },
}

/// A report, and whether it went through the tunnel.
pub(crate) type Sink = tokio::sync::mpsc::UnboundedSender<(Report, bool)>;

static REPORTS: RwLock<Option<Sink>> = RwLock::new(None);

/// Where reports go from now on (`None`: nowhere — VEIL off).
pub(crate) fn set_sink(sink: Option<Sink>) {
    *REPORTS.write().unwrap_or_else(|e| e.into_inner()) = sink;
}

/// The count of connections this process ended itself, to compare before and after a call.
pub(crate) fn disruptions() -> u64 {
    DISRUPTIONS.load(Ordering::SeqCst)
}

/// This process is ending its connections (an invalidation).
pub(crate) fn note_disruption() {
    DISRUPTIONS.fetch_add(1, Ordering::SeqCst);
}

/// Tell the router what happened, on the route it happened on — unless this process ended
/// connections meanwhile (`since`, from [`disruptions`] when it began): then a failure is ours,
/// and counting it would read our own reconnect as a block.
pub(crate) fn report(report: Report, since: u64) {
    let failed = matches!(
        report,
        Report::RpcFailed { .. } | Report::StreamFailed { .. }
    );
    if failed && disruptions() != since {
        return;
    }
    if let Some(sink) = REPORTS.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
        let _ = sink.send((report, matches!(current().0, Route::Veil { .. })));
    }
}

/// A failed call, as the router weighs it. A refused local port is our proxy gone, not the
/// front; a call that never came back is a timeout; the server answering with a status is the
/// application, not the path.
pub(crate) fn classify(e: &super::GrpcError) -> Option<RpcFailure> {
    use super::GrpcError as E;
    Some(match e {
        E::Unauthenticated(_) => RpcFailure::AuthRejected,
        E::PermissionDenied(_) | E::Status { .. } => RpcFailure::ApplicationError,
        E::Tls(_) => RpcFailure::TransportUnknown,
        E::Transport(m) if m.contains("VEIL is on") => return None,
        E::Transport(m) if m.contains("route changed") => RpcFailure::TransientCancellation,
        E::Transport(m) if m.starts_with("VEIL tunnel") && !m.contains("no answer") => {
            RpcFailure::StaleLocalProxy
        }
        E::Transport(m) if m.contains("timed out") => RpcFailure::StreamTimeout,
        E::Transport(_) => RpcFailure::TransportUnknown,
    })
}

/// The route, once it is not closed — or still closed after `wait`.
pub(crate) async fn open_within(wait: Duration) -> (Route, u64) {
    let mut changed = CHANGED.subscribe();
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let now = current();
        if now.0 != Route::Closed {
            return now;
        }
        if tokio::time::timeout_at(deadline, changed.changed())
            .await
            .is_err()
        {
            return current();
        }
    }
}

/// The route is one per process; tests that move it take turns.
#[cfg(test)]
pub(crate) static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::GrpcError;

    /// Failures are weighed as the router needs them: our proxy gone, a timeout, the server's own
    /// answer, the path; and VEIL waiting for a front is no failure of the path at all.
    #[test]
    fn failures_are_classified_for_the_router() {
        let t = |m: &str| classify(&GrpcError::transport(m));
        assert_eq!(
            t("VEIL tunnel 127.0.0.1:5: connection refused"),
            Some(RpcFailure::StaleLocalProxy)
        );
        assert_eq!(
            t("VEIL tunnel 127.0.0.1:5: no answer through the front"),
            Some(RpcFailure::TransportUnknown)
        );
        assert_eq!(t("'/x' timed out"), Some(RpcFailure::StreamTimeout));
        assert_eq!(t("VEIL is on and no front is available"), None);
        assert_eq!(
            t("the route changed while connecting"),
            Some(RpcFailure::TransientCancellation)
        );
        assert_eq!(
            classify(&GrpcError::Unauthenticated("x".into())),
            Some(RpcFailure::AuthRejected)
        );
        assert_eq!(
            classify(&GrpcError::Status {
                code: 5,
                message: "x".into()
            }),
            Some(RpcFailure::ApplicationError)
        );
        assert_eq!(
            classify(&GrpcError::tls("eof")),
            Some(RpcFailure::TransportUnknown)
        );
    }

    /// A failure across a disruption of our own is not reported — it is our reconnect, not a
    /// block; a success is, and so is a failure with nothing in between.
    #[test]
    fn our_own_disruptions_are_not_reported_as_failures() {
        let _turn = TEST_LOCK.blocking_lock();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        set_sink(Some(tx));
        let failed = Report::RpcFailed {
            lane: Lane::Auth,
            failure: RpcFailure::TransportUnknown,
        };
        let since = disruptions();
        note_disruption();
        report(failed, since);
        report(Report::StreamOpened, since);
        let since = disruptions();
        report(failed, since);
        set_sink(None);
        let got: Vec<Report> = std::iter::from_fn(|| rx.try_recv().ok().map(|(r, _)| r)).collect();
        assert_eq!(got, vec![Report::StreamOpened, failed]);
    }
}
