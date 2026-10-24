//! What the settings screen changes on the account: its devices, its username, whether it can be
//! found, whether it sends delivery receipts. Server calls run aside; each result comes back as
//! [`ClientEvent::Settings`] or a notice.

use super::{Client, ClientEvent};
use crate::grpc::GrpcError;

/// The account as the settings screen shows it.
#[derive(Debug, Clone, Default)]
pub struct AccountSettings {
    /// `None` when the account has none, or the server was not reached.
    pub username: Option<String>,
    pub devices: Vec<crate::grpc::Device>,
    pub delivery_receipts: bool,
    /// As last set on this device; `None` when never set here.
    pub discoverable: Option<bool>,
    /// The name we chose to share; empty when none.
    pub display_name: String,
    /// The picture we share, a JPEG.
    pub avatar: Option<Vec<u8>>,
}

/// A username as iOS takes it: trimmed, lower case, 3 to 20 letters, digits or `_`.
pub fn normalize_username(raw: &str) -> Result<String, &'static str> {
    let name = crate::grpc::users::normalize_username(raw);
    if !(3..=20).contains(&name.len()) {
        return Err("a username is 3 to 20 characters");
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err("a username has only letters, digits and _");
    }
    Ok(name)
}

impl Client {
    /// Fetch what the settings screen shows.
    pub(super) fn load_settings(&self) {
        let Some(store) = self.store.clone() else {
            return;
        };
        let grpc = self.grpc.clone();
        let user_id = self.user_id.clone();
        let events = self.events.clone();
        tokio::spawn(async move {
            let own = store.own_profile().unwrap_or_default();
            let (username, devices) = tokio::join!(
                crate::grpc::own_username(&grpc, &user_id),
                crate::grpc::list_devices(&grpc)
            );
            let devices = devices.unwrap_or_else(|e| {
                notice(&events, format!("Devices not loaded: {e}"));
                Vec::new()
            });
            let _ = events.send(ClientEvent::Settings(AccountSettings {
                username: username.ok().flatten().or_else(|| store.own_username()),
                devices,
                delivery_receipts: store.sends_delivery_receipts(),
                discoverable: store.discoverable(),
                display_name: own.display_name,
                avatar: own.avatar,
            }));
        });
    }

    pub(super) fn change_username(&self, raw: String) {
        let username = match normalize_username(&raw) {
            Ok(username) => username,
            Err(reason) => return self.emit(ClientEvent::Notice(capitalize(reason))),
        };
        let Some(store) = self.store.clone() else {
            return;
        };
        let grpc = self.grpc.clone();
        let user_id = self.user_id.clone();
        let events = self.events.clone();
        let reload = self.inbox.clone();
        tokio::spawn(async move {
            // "taken" is also the answer for the name we already hold, so it is left to the
            // update, which refuses someone else's.
            match crate::grpc::username_refusal(&grpc, &username).await {
                Ok(Some(reason)) if reason != "taken" => {
                    return notice(&events, format!("@{username} cannot be taken: {reason}"));
                }
                Err(e) => return notice(&events, format!("Username not changed: {e}")),
                Ok(_) => {}
            }
            match crate::grpc::set_username(&grpc, &user_id, &username).await {
                Ok(now) => {
                    if let Err(e) = store.set_own_username(&now) {
                        tracing::warn!("username not kept: {e}");
                    }
                    notice(&events, format!("Your username is @{now}"));
                }
                Err(e) => notice(&events, format!("Username not changed: {e}")),
            }
            let _ = reload.send(super::Inbox::Command(super::ClientCommand::LoadSettings));
        });
    }

    /// Being found by username needs one: the server finds nobody without.
    pub(super) fn set_discoverable(&self, on: bool) {
        let Some(store) = self.store.clone() else {
            return;
        };
        let grpc = self.grpc.clone();
        let events = self.events.clone();
        let reload = self.inbox.clone();
        tokio::spawn(async move {
            match crate::grpc::set_discoverable(&grpc, on).await {
                Ok(now) => {
                    if let Err(e) = store.set_discoverable(now) {
                        tracing::warn!("discoverable not kept: {e}");
                    }
                }
                Err(e) => notice(&events, format!("Not changed: {e}")),
            }
            let _ = reload.send(super::Inbox::Command(super::ClientCommand::LoadSettings));
        });
    }

    pub(super) fn set_delivery_receipts(&self, on: bool) {
        let Some(store) = self.store.as_ref() else {
            return;
        };
        if let Err(e) = store.set_sends_delivery_receipts(on) {
            return self.emit(ClientEvent::Notice(format!("Not changed: {e}")));
        }
        self.load_settings();
    }

    /// Sign out other devices of this account: `device_id`, or every one but this.
    pub(super) fn revoke_devices(&self, device_id: Option<String>) {
        let grpc = self.grpc.clone();
        let own = self.device_id.clone();
        let events = self.events.clone();
        let reload = self.inbox.clone();
        tokio::spawn(async move {
            let targets = match device_id {
                Some(id) => vec![id],
                None => match crate::grpc::list_devices(&grpc).await {
                    Ok(devices) => devices
                        .into_iter()
                        .filter(|d| !d.is_current && d.device_id != own)
                        .map(|d| d.device_id)
                        .collect(),
                    Err(e) => return notice(&events, format!("Devices not loaded: {e}")),
                },
            };
            for id in targets.into_iter().filter(|id| *id != own) {
                if let Err(e) = crate::grpc::revoke_device(&grpc, &id).await {
                    notice(&events, revoke_failure(&id, &e));
                }
            }
            let _ = reload.send(super::Inbox::Command(super::ClientCommand::LoadSettings));
        });
    }
}

fn revoke_failure(id: &str, e: &GrpcError) -> String {
    let short = &id[..8.min(id.len())];
    match e {
        // The server keeps the account's first device.
        GrpcError::Status { code: 9, .. } => {
            format!("Device {short}… is the account's main device and stays signed in")
        }
        e => format!("Device {short}… not signed out: {e}"),
    }
}

fn notice(events: &tokio::sync::mpsc::UnboundedSender<ClientEvent>, text: String) {
    let _ = events.send(ClientEvent::Notice(text));
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    chars
        .next()
        .map(|c| c.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_username_is_taken_as_ios_takes_it() {
        assert_eq!(normalize_username("  @Alice_1 ").unwrap(), "alice_1");
        assert!(normalize_username("al").is_err());
        assert!(normalize_username(&"a".repeat(21)).is_err());
        assert!(normalize_username("alice-1").is_err());
        assert!(normalize_username("алиса").is_err());
    }
}
