//! Blocking a contact: where a block lives, and how the places are kept alike.
//!
//! A block lives in two places (iOS `BlockSync`, Android `BlockSync`; canon: iOS): the flag in the
//! account's store, which drops what arrives from the person (`orchestrator_task`), and the
//! server's `user_blocks` row, which refuses a call and carries a block to the account's other
//! devices and across a reinstall. Sealed messages bypass the server's row — it cannot see who
//! sent them — so the local flag is the one that does the blocking
//! (construct-docs `decisions/sealed-sender-authenticated-transitional.md`, point 5).
//!
//! The server's row used to be sent once, best-effort, and a lost unblock left it behind for good
//! (TODO 170). Here the wanted state is kept per person in the store and resent until the server
//! answers, and the server's list is read back once the queue is empty, so a block made on the
//! person's phone shows here.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, mpsc};

use crate::client::ClientEvent;
use crate::grpc::{GrpcClient, GrpcError};
use crate::local_store::LocalStore;

/// What the person wants the server to hold for one contact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Intent {
    pub blocked: bool,
    pub reason: Option<String>,
}

/// The wishes waiting for the server, by account. The latest for a person replaces an earlier
/// one still waiting.
pub type Wishes = HashMap<String, Intent>;

/// Waits between passes that found the path down; a new request, a reconnected stream and a
/// start begin a pass anyway.
const BACKOFF: [Duration; 4] = [
    Duration::from_secs(2),
    Duration::from_secs(10),
    Duration::from_secs(30),
    Duration::from_secs(120),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    Retry,
    Drop,
}

/// The path failing, or the session being renewed, is tried again; a refusal by the server (an
/// account that is gone, an id it rejects) would be refused every time.
pub fn disposition(error: &GrpcError) -> Disposition {
    if error.is_unauthenticated() || error.is_retryable_transport() {
        return Disposition::Retry;
    }
    match error {
        // Cancelled, unknown, deadline, aborted, resource exhausted, unavailable: the path's.
        GrpcError::Status {
            code: 1 | 2 | 4 | 8 | 10 | 14,
            ..
        } => Disposition::Retry,
        _ => Disposition::Drop,
    }
}

/// Server rows this device does not show, to be made visible: so the person sees what the server
/// enforces and can lift it. Never unblocked blindly — the row is also what carries a block across
/// a reinstall. A person with a wish still queued is left to the queue.
pub fn to_adopt(
    server_blocked: &[String],
    wishes: &Wishes,
    is_blocked_here: impl Fn(&str) -> bool,
) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    server_blocked
        .iter()
        .filter(|id| {
            !id.is_empty()
                && !wishes.contains_key(*id)
                && !is_blocked_here(id)
                && seen.insert(id.as_str())
        })
        .cloned()
        .collect()
}

/// Reads and writes of the wishes are one at a time: the worker confirms while a command records.
static WISHES: Mutex<()> = Mutex::new(());

/// Record what the person wants for `account`, replacing an earlier wish for them.
pub fn record(
    store: &LocalStore,
    account: &str,
    blocked: bool,
    reason: Option<&str>,
) -> anyhow::Result<()> {
    let _guard = WISHES.lock().unwrap_or_else(|e| e.into_inner());
    let mut all = store.block_wishes();
    all.insert(
        account.to_owned(),
        Intent {
            blocked,
            reason: reason.map(str::to_owned),
        },
    );
    store.set_block_wishes(&all)
}

/// The server answered for `sent`: drop the wish, unless a newer one came in while it was in
/// flight — that one stays for the next pass.
fn confirm(store: &LocalStore, account: &str, sent: &Intent) {
    let _guard = WISHES.lock().unwrap_or_else(|e| e.into_inner());
    let mut all = store.block_wishes();
    if all.get(account) != Some(sent) {
        return;
    }
    all.remove(account);
    if let Err(e) = store.set_block_wishes(&all) {
        tracing::warn!("block wish not cleared: {e:#}");
    }
}

/// A running worker: one pass at a time. A wake during a pass is kept, so a wish recorded
/// mid-pass is never overtaken by the read-back that follows.
#[derive(Clone)]
pub struct Worker {
    wake: Arc<Notify>,
}

impl Worker {
    pub fn wake(&self) {
        self.wake.notify_one();
    }
}

/// Start the worker for the account `store` holds. Contacts it shows as blocked after a
/// read-back are reported on `events`. The first pass runs at once.
pub fn spawn(
    grpc: GrpcClient,
    store: LocalStore,
    events: mpsc::UnboundedSender<ClientEvent>,
) -> (Worker, tokio::task::AbortHandle) {
    let wake = Arc::new(Notify::new());
    wake.notify_one();
    let worker = Worker { wake: wake.clone() };
    let task = tokio::spawn(async move {
        loop {
            wake.notified().await;
            pass(&grpc, &store, &events).await;
        }
    });
    (worker, task.abort_handle())
}

async fn pass(grpc: &GrpcClient, store: &LocalStore, events: &mpsc::UnboundedSender<ClientEvent>) {
    for attempt in 0..=BACKOFF.len() {
        let Some(failure) = flush(grpc, store).await else {
            return read_back(grpc, store, events).await;
        };
        let Some(wait) = BACKOFF.get(attempt) else {
            break;
        };
        tracing::info!(error = %failure, "block sync: the path is not ready — again in {wait:?}");
        tokio::time::sleep(*wait).await;
    }
    tracing::info!(
        queued = store.block_wishes().len(),
        "block sync: still queued — next start, request or reconnect"
    );
}

/// Send the wishes. `None` when none is left; otherwise the failure that stopped it.
async fn flush(grpc: &GrpcClient, store: &LocalStore) -> Option<GrpcError> {
    for (account, intent) in store.block_wishes() {
        let sent = if intent.blocked {
            crate::grpc::block_user(grpc, &account, intent.reason.as_deref()).await
        } else {
            crate::grpc::unblock_user(grpc, &account).await
        };
        match sent {
            Ok(()) => confirm(store, &account, &intent),
            Err(e) => match disposition(&e) {
                Disposition::Retry => return Some(e),
                Disposition::Drop => {
                    tracing::error!(
                        error = %e,
                        blocked = intent.blocked,
                        "block sync refused for {}…",
                        account.chars().take(8).collect::<String>()
                    );
                    confirm(store, &account, &intent);
                }
            },
        }
    }
    None
}

async fn read_back(
    grpc: &GrpcClient,
    store: &LocalStore,
    events: &mpsc::UnboundedSender<ClientEvent>,
) {
    let server_blocked = match crate::grpc::blocked_users(grpc).await {
        Ok(list) => list,
        Err(e) => return tracing::info!(error = %e, "block sync: the server's list is not read"),
    };
    tracing::info!(
        held = server_blocked.len(),
        "block sync: the server's list read"
    );
    let adopt = to_adopt(&server_blocked, &store.block_wishes(), |id| {
        store.is_blocked(id)
    });
    for account in adopt {
        // A person with no row here has nobody to show it on.
        if !matches!(store.set_blocked(&account, true), Ok(true)) {
            continue;
        }
        tracing::info!("block sync: a server block was not shown here — now shown");
        if let Ok(Some(contact)) = store.get_contact_by_id(&account) {
            let _ = events.send(ClientEvent::Bridge(
                crate::bridge::BridgeEvent::ContactUpdated { contact },
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wishes(ids: &[&str]) -> Wishes {
        ids.iter()
            .map(|id| {
                (
                    (*id).to_owned(),
                    Intent {
                        blocked: false,
                        reason: None,
                    },
                )
            })
            .collect()
    }

    #[test]
    fn a_path_failure_is_tried_again_and_a_refusal_is_not() {
        for retry in [
            GrpcError::transport("reset"),
            GrpcError::tls("handshake"),
            GrpcError::unauthenticated("token expired"),
            GrpcError::status(14, "unavailable"),
            GrpcError::status(4, "deadline"),
            GrpcError::status(8, "exhausted"),
        ] {
            assert_eq!(disposition(&retry), Disposition::Retry, "{retry}");
        }
        for refused in [
            GrpcError::status(5, "not found"),
            GrpcError::status(3, "invalid argument"),
            GrpcError::status(7, "denied"),
            GrpcError::permission_denied("no"),
        ] {
            assert_eq!(disposition(&refused), Disposition::Drop, "{refused}");
        }
    }

    /// A block the server holds that this device does not show is shown; never the other way.
    #[test]
    fn the_servers_blocks_are_adopted_unless_shown_or_still_wished() {
        let server = ["a", "b", "c", "a", ""].map(String::from);
        let blocked_here = |id: &str| id == "b";
        assert_eq!(
            to_adopt(&server, &wishes(&[]), blocked_here),
            ["a", "c"],
            "b is shown already, a once, the empty id never"
        );
        assert_eq!(
            to_adopt(&server, &wishes(&["c"]), blocked_here),
            ["a"],
            "c has a wish queued: the queue decides, the server's old row does not"
        );
    }

    #[test]
    fn a_wish_is_replaced_by_a_later_one_and_cleared_only_when_it_was_the_one_sent() {
        let store = LocalStore::open_in_memory().unwrap();
        assert!(store.block_wishes().is_empty());
        record(&store, "bob", true, Some("spam")).unwrap();
        let first = store.block_wishes()["bob"].clone();
        assert_eq!(
            first,
            Intent {
                blocked: true,
                reason: Some("spam".into())
            }
        );
        // The person changed their mind while the block was in flight.
        record(&store, "bob", false, None).unwrap();
        confirm(&store, "bob", &first);
        assert_eq!(
            store.block_wishes().len(),
            1,
            "the unblock is not the wish that was sent: it stays"
        );
        let second = store.block_wishes()["bob"].clone();
        confirm(&store, "bob", &second);
        assert!(store.block_wishes().is_empty());
    }
}
