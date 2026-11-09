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
}
