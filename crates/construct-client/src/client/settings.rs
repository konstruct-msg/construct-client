//! What the settings screen changes on the account: its devices, its username, whether it can be
//! found, whether it sends delivery receipts. Server calls run aside; each result comes back as
//! [`ClientEvent::Settings`] or a notice.

use super::{Client, ClientEvent};
use crate::grpc::GrpcError;

/// The account as the settings screen shows it.
/// A device of the account and what it says about itself, if a copy was sealed to us.
#[derive(Debug, Clone)]
pub struct DeviceEntry {
    pub device: crate::grpc::Device,
    pub description: Option<crate::device_meta::Description>,
}

#[derive(Debug, Clone, Default)]
pub struct AccountSettings {
    /// `None` when the account has none, or the server was not reached.
    pub username: Option<String>,
    pub devices: Vec<DeviceEntry>,
    /// What this device calls itself to the others.
    pub device_name: String,
    pub delivery_receipts: bool,
    /// As last set on this device; `None` when never set here.
    pub discoverable: Option<bool>,
    /// The name we chose to share; empty when none.
    pub display_name: String,
    /// The picture we share, a JPEG.
    pub avatar: Option<Vec<u8>>,
    pub user_id: String,
    pub device_id: String,
    /// Our identity key, short, to compare out of band (iOS `IdentityFingerprint`).
    pub fingerprint: Option<String>,
    /// Bytes the fetched attachments take, and how many there are.
    pub media_bytes: u64,
    pub media_files: usize,
    pub media: crate::local_store::MediaPrefs,
    /// Invites this device handed out that may still be redeemed, newest first.
    pub invites: Vec<InviteEntry>,
}

/// An invite handed out and not yet expired: revoking it burns it on the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteEntry {
    pub jti: String,
    /// `qr` or `link`, as iOS records it.
    pub kind: String,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
}

/// A key's short fingerprint, as iOS shows it: the first 8 bytes of its SHA-256, in groups of four
/// upper-case hex digits. A label for "which key is this", not a safety number.
pub fn fingerprint(identity_public: &[u8]) -> Option<String> {
    use sha2::Digest;
    if identity_public.is_empty() {
        return None;
    }
    let hex = hex::encode_upper(&sha2::Sha256::digest(identity_public)[..8]);
    Some(
        hex.as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join(" "),
    )
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
        let secret = self.identity_secret.clone();
        let device_id = self.device_id.clone();
        let fingerprint = self.our_identity_key.as_deref().and_then(fingerprint);
        let media = self.media_cache();
        tokio::spawn(async move {
            let own = store.own_profile().unwrap_or_default();
            let (media_bytes, media_files) = media.map(|m| m.usage()).unwrap_or_default();
            let (username, devices) = tokio::join!(
                crate::grpc::own_username(&grpc, &user_id),
                crate::grpc::list_devices(&grpc)
            );
            let devices = devices.unwrap_or_else(|e| {
                notice(&events, format!("Devices not loaded: {e}"));
                Vec::new()
            });
            let devices = devices
                .into_iter()
                .map(|device| DeviceEntry {
                    description: secret
                        .as_ref()
                        .and_then(|s| crate::device_meta::open(&device.sealed_metadata, s)),
                    device,
                })
                .collect();
            let _ = events.send(ClientEvent::Settings(AccountSettings {
                username: username.ok().flatten().or_else(|| store.own_username()),
                devices,
                device_name: device_name(&store),
                delivery_receipts: store.sends_delivery_receipts(),
                discoverable: store.discoverable(),
                display_name: own.display_name,
                avatar: own.avatar,
                user_id,
                device_id,
                fingerprint,
                media_bytes,
                media_files,
                media: store.media_prefs(),
                invites: live_invites(&store),
            }));
        });
    }

    fn media_cache(&self) -> Option<crate::media::MediaCache> {
        Some(crate::media::MediaCache::new(
            self.data.as_ref()?.media_dir(),
        ))
    }

    pub(super) fn clear_media_cache(&self) {
        let Some(cache) = self.media_cache() else {
            return;
        };
        if let Err(e) = cache.clear() {
            self.emit(ClientEvent::Notice(format!("Not cleared: {e}")));
        }
        self.load_settings();
    }

    /// Kept, and the cache brought within them now.
    pub(super) fn set_media_prefs(&self, prefs: crate::local_store::MediaPrefs) {
        let (Some(store), Some(cache)) = (self.store.as_ref(), self.media_cache()) else {
            return;
        };
        if let Err(e) = store.set_media_prefs(&prefs) {
            return self.emit(ClientEvent::Notice(format!("Not changed: {e}")));
        }
        cache.evict(prefs.quota, prefs.keep_days);
        self.load_settings();
    }

    /// Burn invites on the server so nobody can redeem them. One already used or revoked is
    /// forgotten too; one the server did not answer for stays, to try again.
    pub(super) fn revoke_invites(&self, jtis: Vec<String>) {
        let Some(store) = self.store.clone() else {
            return;
        };
        let grpc = self.grpc.clone();
        let events = self.events.clone();
        let reload = self.inbox.clone();
        tokio::spawn(async move {
            let mut done = Vec::new();
            let mut used = 0;
            let mut failed = 0;
            for jti in jtis {
                match crate::grpc::revoke_invite(&grpc, &jti).await {
                    Ok(revoked) => {
                        used += usize::from(!revoked);
                        done.push(jti);
                    }
                    Err(e) => {
                        tracing::warn!(jti = %&jti[..8.min(jti.len())], "invite not revoked: {e}");
                        failed += 1;
                    }
                }
            }
            if let Err(e) = store.forget_invites(&done) {
                tracing::warn!("revoked invites not forgotten: {e}");
            }
            if failed > 0 {
                notice(
                    &events,
                    format!("{failed} invite(s) not revoked: the server did not answer"),
                );
            } else if used > 0 {
                notice(&events, format!("{used} invite(s) had already been used"));
            } else if !done.is_empty() {
                notice(&events, "Revoked: nobody can use it now".into());
            }
            let _ = reload.send(super::Inbox::Command(super::ClientCommand::LoadSettings));
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

    /// Our own name for a contact: shown instead of any other, never sent.
    pub(super) fn set_alias(&self, contact_id: String, alias: Option<String>) {
        let Some(store) = self.store.as_ref() else {
            return;
        };
        let alias = alias.map(|a| crate::profile::clean_display_name(&a));
        if let Err(e) = store.set_alias(&contact_id, alias.as_deref()) {
            return self.emit(ClientEvent::Notice(format!("Not changed: {e}")));
        }
        if let Ok(Some(contact)) = store.get_contact_by_id(&contact_id) {
            self.emit(ClientEvent::Bridge(
                crate::bridge::BridgeEvent::ContactUpdated { contact },
            ));
        }
    }

    pub(super) fn rename_device(&self, name: String) {
        let Some(store) = self.store.as_ref() else {
            return;
        };
        let name = crate::device_meta::clean_name(&name);
        if let Err(e) = store.secure_save(PREF_DEVICE_NAME, name.as_bytes()) {
            return self.emit(ClientEvent::Notice(format!("Not changed: {e}")));
        }
        self.publish_device_description(true);
    }

    /// Seal this device's description to every device of the account and give it to the server,
    /// when the set moved since the last time (or `force`, after a rename). An unknown set, or a
    /// refusal, leaves the blob published before standing; the next start tries again.
    pub(super) fn publish_device_description(&self, force: bool) {
        let Some(store) = self.store.clone() else {
            return;
        };
        let grpc = self.grpc.clone();
        let user_id = self.user_id.clone();
        let reload = self.inbox.clone();
        tokio::spawn(async move {
            let bundles =
                match crate::grpc::get_pre_key_bundles(&grpc, &user_id, Vec::new(), false).await {
                    Ok(b) => b.bundles,
                    Err(e) => return tracing::info!("own devices not listed, not published: {e}"),
                };
            let mut ids: Vec<String> = bundles.iter().map(|b| b.device_id.clone()).collect();
            ids.sort();
            let last: Vec<String> = store
                .secure_load(PREF_DEVICE_PUBLISHED_FOR)
                .ok()
                .flatten()
                .map(|v| {
                    String::from_utf8_lossy(&v)
                        .split('\n')
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            if !force && !crate::device_meta::needs_publish(&ids, &last) {
                return;
            }
            let keys: Vec<Vec<u8>> = bundles
                .iter()
                .map(|b| b.bundle.x3dh.identity_public.clone())
                .collect();
            let Some(blob) = crate::device_meta::seal(&device_name(&store), &keys) else {
                return tracing::warn!("device description not sealed, not published");
            };
            match crate::grpc::set_device_metadata(&grpc, &blob).await {
                Ok(()) => {
                    // Kept only once the server took it, so a failure is retried.
                    let _ = store.secure_save(PREF_DEVICE_PUBLISHED_FOR, ids.join("\n").as_bytes());
                    tracing::info!(devices = ids.len(), "device description published");
                    if force {
                        let _ =
                            reload.send(super::Inbox::Command(super::ClientCommand::LoadSettings));
                    }
                }
                Err(e) => tracing::warn!("device description not published: {e}"),
            }
        });
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

fn live_invites(store: &crate::local_store::LocalStore) -> Vec<InviteEntry> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64);
    store
        .live_invites(now)
        .unwrap_or_else(|e| {
            tracing::warn!("invites not read: {e}");
            Vec::new()
        })
        .into_iter()
        .map(|i| InviteEntry {
            expires_at_ms: i.issued_at + i64::from(i.ttl_seconds) * 1000,
            jti: i.jti,
            kind: i.kind,
            issued_at_ms: i.issued_at,
        })
        .collect()
}

const PREF_DEVICE_NAME: &str = "pref.device_name";
const PREF_DEVICE_PUBLISHED_FOR: &str = "device_meta.published_for";

/// The name this device goes by: the person's, or the platform's.
fn device_name(store: &crate::local_store::LocalStore) -> String {
    store
        .secure_load(PREF_DEVICE_NAME)
        .ok()
        .flatten()
        .and_then(|v| String::from_utf8(v).ok())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| crate::device_meta::default_name().to_owned())
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
    fn a_fingerprint_reads_as_on_ios() {
        // SHA-256 of 32 zero bytes begins 66687aadf862bd77.
        assert_eq!(
            fingerprint(&[0u8; 32]).as_deref(),
            Some("6668 7AAD F862 BD77")
        );
        assert_eq!(fingerprint(&[]), None);
    }

    #[test]
    fn a_username_is_taken_as_ios_takes_it() {
        assert_eq!(normalize_username("  @Alice_1 ").unwrap(), "alice_1");
        assert!(normalize_username("al").is_err());
        assert!(normalize_username(&"a".repeat(21)).is_err());
        assert!(normalize_username("alice-1").is_err());
        assert!(normalize_username("алиса").is_err());
    }
}
