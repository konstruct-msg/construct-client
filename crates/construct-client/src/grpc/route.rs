//! Where every connection to the server goes: straight to it, or into the local end of the VEIL
//! tunnel — or nowhere, while VEIL is on and no front is up (decisions/veil-on-never-goes-direct).
//!
//! One route per process, read by every [`super::GrpcClient`] when it connects: the signed
//! client, the one without a token, any made later. A change of route ends their connections, so
//! nothing stays on the old path.

use std::sync::atomic::{AtomicU64, Ordering};
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
/// Connections into the tunnel that failed since the route last changed.
static TUNNEL_FAILURES: AtomicU64 = AtomicU64::new(0);
/// Woken on every change of route.
static CHANGED: LazyLock<tokio::sync::watch::Sender<u64>> =
    LazyLock::new(|| tokio::sync::watch::channel(0).0);

/// Send every connection from now on along `route`; connections on another route are ended.
pub fn set_route(route: Route) {
    let mut current = ROUTE.write().unwrap_or_else(|e| e.into_inner());
    if *current != route {
        *current = route;
        let generation = GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
        TUNNEL_FAILURES.store(0, Ordering::SeqCst);
        CHANGED.send_replace(generation);
        tracing::info!(?route, "transport route changed");
    }
}

/// The route and its generation: a connection made under an older generation is stale.
pub(crate) fn current() -> (Route, u64) {
    let route = ROUTE.read().unwrap_or_else(|e| e.into_inner());
    (*route, GENERATION.load(Ordering::SeqCst))
}

/// A connection into the tunnel failed: the front may be gone though the local end is up.
pub(crate) fn note_tunnel_failure() {
    TUNNEL_FAILURES.fetch_add(1, Ordering::SeqCst);
}

/// How many connections into the tunnel failed since the route last changed.
pub fn tunnel_failures() -> u64 {
    TUNNEL_FAILURES.load(Ordering::SeqCst)
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
