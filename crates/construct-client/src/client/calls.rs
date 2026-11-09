//! The call intents a front end sends: start, answer, decline, end.

use super::Client;

impl Client {
    /// Begin a 1:1 audio call to `contact_id`. The call state arrives on
    /// [`crate::bridge::BridgeEvent::CallState`].
    pub(super) fn start_call(&self, contact_id: String) {
        if let Some(ref orch) = self.orch_handle {
            orch.start_call(contact_id);
        }
    }

    pub(super) fn accept_call(&self) {
        if let Some(ref orch) = self.orch_handle {
            orch.accept_call();
        }
    }

    pub(super) fn decline_call(&self) {
        if let Some(ref orch) = self.orch_handle {
            orch.decline_call();
        }
    }

    pub(super) fn end_call(&self) {
        if let Some(ref orch) = self.orch_handle {
            orch.end_call();
        }
    }

    pub(super) fn dismiss_call(&self) {
        if let Some(ref orch) = self.orch_handle {
            orch.dismiss_call();
        }
    }

    /// Read the call log and hand it to the front end. Newest first, as the store returns it.
    pub(super) fn load_call_history(&self) {
        let calls = self
            .store
            .as_ref()
            .and_then(|store| store.calls(200).ok())
            .unwrap_or_default()
            .into_iter()
            .map(|record| crate::calls::HistoryRow {
                id: record.id,
                peer_user_id: record.peer_user_id,
                peer_name: record.peer_name,
                direction: match record.direction {
                    0 => "outgoing",
                    _ => "incoming",
                },
                status: match record.status {
                    0 => "completed",
                    1 => "missed",
                    2 => "declined",
                    _ => "failed",
                },
                started_at: record.started_at,
                duration_seconds: record.duration_seconds,
            })
            .collect();
        self.emit(crate::client::ClientEvent::CallHistory(calls));
    }

    pub(super) fn delete_call(&self, id: String) {
        if let Some(ref store) = self.store {
            if let Err(e) = store.delete_call(&id) {
                tracing::warn!(error = %e, "call row not deleted");
            }
        }
        self.load_call_history();
    }

    pub(super) fn clear_calls(&self) {
        if let Some(ref store) = self.store {
            if let Err(e) = store.delete_all_calls() {
                tracing::warn!(error = %e, "call log not cleared");
            }
        }
        self.load_call_history();
    }
}
