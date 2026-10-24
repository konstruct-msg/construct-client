//! Our profile: the name and the picture we share, and with whom. Shared one contact at a time,
//! as iOS does (a switch on the contact), and sent again to everyone it is shared with when it
//! changes — one by one, a few seconds apart, each with its own upload of the avatar, so the
//! server sees neither a burst to N recipients nor one object fetched by all of them.

use rand::Rng;
use rand::seq::SliceRandom;

use super::{Client, ClientEvent};
use crate::grpc::GrpcClient;
use crate::local_store::LocalStore;
use crate::orchestrator_task::OrchestratorHandle;
use crate::profile::{Avatar, AvatarRef, ProfileShare};

/// What a change does to the picture.
#[derive(Debug, Clone)]
pub enum AvatarChange {
    Keep,
    Remove,
    /// A JPEG the front end made: square, at most 512 px, at most 200 KiB.
    Set(Vec<u8>),
}

/// A rebroadcast waits this long between two contacts, in seconds (iOS `rebroadcastSpacing`).
const SPACING_SECS: std::ops::RangeInclusive<f64> = 2.0..=12.0;
/// Set when a profile went out without its avatar because the upload failed: contacts keep the
/// old one, and the profile is sent again at the next start.
const REBROADCAST_OWED: &str = "profile.rebroadcast_owed";

impl Client {
    /// A new name, picture, or both: kept as a new version, then sent to everyone it is shared
    /// with.
    pub(super) fn set_profile(&self, display_name: Option<String>, avatar: AvatarChange) {
        let Some(store) = self.store.clone() else {
            return;
        };
        let current = match store.own_profile() {
            Ok(p) => p,
            Err(e) => return self.emit(ClientEvent::Notice(format!("Profile not changed: {e}"))),
        };
        let avatar = match avatar {
            AvatarChange::Keep => current.avatar,
            AvatarChange::Remove => None,
            AvatarChange::Set(bytes) => match avatar_jpeg(bytes) {
                Ok(jpeg) => Some(jpeg),
                Err(reason) => return self.emit(ClientEvent::Notice(reason.into())),
            },
        };
        let name = display_name.map_or(current.display_name, |n| {
            crate::profile::clean_display_name(&n)
        });
        if let Err(e) = store.edit_own_profile(name, avatar, now_ms()) {
            return self.emit(ClientEvent::Notice(format!("Profile not changed: {e}")));
        }
        self.load_settings();
        self.rebroadcast();
    }

    /// Share our profile with `contact_id`, or stop. Shared: it is sent to them now.
    pub(super) fn share_profile(&self, contact_id: String, on: bool) {
        let (Some(store), Some(orch)) = (self.store.clone(), self.orch_handle.clone()) else {
            return;
        };
        if let Err(e) = store.set_sharing_with(&contact_id, on) {
            return self.emit(ClientEvent::Notice(format!("Not changed: {e}")));
        }
        if let Ok(Some(contact)) = store.get_contact_by_id(&contact_id) {
            self.emit(ClientEvent::Bridge(
                crate::bridge::BridgeEvent::ContactUpdated { contact },
            ));
        }
        if on {
            let grpc = self.grpc.clone();
            let own = self.user_id.clone();
            tokio::spawn(async move { deliver(&store, &grpc, &orch, &own, &contact_id).await });
        }
    }

    /// Our profile to everyone it is shared with, in a random order, spaced out.
    pub(super) fn rebroadcast(&self) {
        let (Some(store), Some(orch)) = (self.store.clone(), self.orch_handle.clone()) else {
            return;
        };
        let grpc = self.grpc.clone();
        let own = self.user_id.clone();
        tokio::spawn(async move {
            let _ = store.secure_delete(REBROADCAST_OWED);
            let mut ids = store.sharing_with().unwrap_or_default();
            ids.shuffle(&mut rand::thread_rng());
            for (n, id) in ids.iter().enumerate() {
                if n > 0 {
                    let secs = rand::thread_rng().gen_range(SPACING_SECS);
                    tokio::time::sleep(std::time::Duration::from_secs_f64(secs)).await;
                }
                deliver(&store, &grpc, &orch, &own, id).await;
            }
        });
    }

    /// At each start: a rebroadcast an avatar upload left owed, and avatars still to download.
    pub(super) fn profile_chores(&self, anonymous: GrpcClient) {
        let Some(store) = self.store.clone() else {
            return;
        };
        if matches!(store.secure_load(REBROADCAST_OWED), Ok(Some(_))) {
            tracing::info!("profile rebroadcast owed from a failed avatar upload — sending again");
            self.rebroadcast();
        }
        let events = self.events.clone();
        tokio::spawn(async move {
            for id in store.contacts_with_pending_avatar().unwrap_or_default() {
                if crate::profile::fetch_pending_avatar(&store, &anonymous, &id).await
                    && let Ok(Some(contact)) = store.get_contact_by_id(&id)
                {
                    let _ = events.send(ClientEvent::Bridge(
                        crate::bridge::BridgeEvent::ContactUpdated { contact },
                    ));
                }
            }
        });
    }
}

/// Our profile, as it is now, to every device of `contact`. The avatar is uploaded for them
/// alone; if that fails it goes as unchanged, so they keep the old one, and a rebroadcast is
/// owed (iOS `prepareProfile`).
async fn deliver(
    store: &LocalStore,
    grpc: &GrpcClient,
    orch: &OrchestratorHandle,
    own_account: &str,
    contact: &str,
) {
    let me = match store.stamped_own_profile(now_ms()) {
        Ok(me) => me,
        Err(e) => return tracing::warn!("profile not read: {e}"),
    };
    let avatar = match &me.avatar {
        None => Avatar::Removed,
        Some(jpeg) => match upload_avatar(grpc, jpeg).await {
            Ok(r) => Avatar::Set(r),
            Err(e) => {
                tracing::warn!("avatar not uploaded, the profile goes without it: {e}");
                let _ = store.secure_save(REBROADCAST_OWED, &[1]);
                Avatar::Unchanged
            }
        },
    };
    let profile = ProfileShare {
        display_name: crate::profile::outgoing_name(&me.display_name, &me.username, own_account),
        edited_at_ms: u64::try_from(me.edited_at_ms).unwrap_or(0),
        avatar,
    };
    orch.send_profile(contact.to_owned(), profile.encode());
}

/// One new object on the media server: the avatar padded to the one size, sealed by the core.
async fn upload_avatar(grpc: &GrpcClient, jpeg: &[u8]) -> Result<AvatarRef, String> {
    let sealed = construct_core::media::seal_media(&crate::profile::padded(jpeg))
        .map_err(|e| e.to_string())?;
    let uploaded = crate::grpc::upload_media(grpc, &sealed.blob, &sealed.sha256)
        .await
        .map_err(|e| e.to_string())?;
    Ok(AvatarRef {
        media_id: uploaded.media_id,
        media_url: uploaded.download_url,
        media_key: sealed.key.clone(),
        mime_type: "image/jpeg".into(),
    })
}

/// The picture a front end handed over, as it may go out: a JPEG that reads as one, its metadata
/// dropped (a canvas writes none, but a front end is not trusted to have used one), no larger
/// than the one avatar size.
fn avatar_jpeg(bytes: Vec<u8>) -> Result<Vec<u8>, &'static str> {
    let file = crate::outgoing::prepare("avatar.jpg", bytes);
    if file.kind != crate::content::Attachment::Photo || file.mime != "image/jpeg" {
        return Err("The picture is not a JPEG");
    }
    if file.bytes.len() > crate::profile::AVATAR_PADDED_LEN {
        return Err("The picture is larger than 200 KB");
    }
    Ok(file.bytes)
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_small_jpeg_is_taken_as_the_picture() {
        assert!(avatar_jpeg(b"\x89PNG\r\n\x1a\n".to_vec()).is_err());
        assert!(avatar_jpeg(b"not a picture".to_vec()).is_err());
        let mut jpeg = vec![
            0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x0B, 8, 0, 4, 0, 4, 1, 1, 0x11, 0,
        ];
        jpeg.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 1, 1, 0, 0, 0x3F, 0, 0x12, 0x34]);
        jpeg.extend_from_slice(&[0xFF, 0xD9]);
        assert!(avatar_jpeg(jpeg.clone()).is_ok());
        let mut big = jpeg[..jpeg.len() - 2].to_vec();
        big.resize(crate::profile::AVATAR_PADDED_LEN + 10, 0x55);
        big.extend_from_slice(&[0xFF, 0xD9]);
        assert!(avatar_jpeg(big).is_err());
    }
}
