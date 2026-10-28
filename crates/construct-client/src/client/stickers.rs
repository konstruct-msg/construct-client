//! Stickers for the screens: the picker's packs, a sticker's picture, sending one, and adding
//! packs from the server's catalog (`crate::stickers`). File work and fetching run aside.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use uuid::Uuid;

use super::{Client, ClientEvent};
use crate::stickers::{HASH_LEN, Library, StickerRef, pack_id};

/// The first wait after a pack could not be fetched; it doubles up to [`MAX_BACKOFF`] (iOS).
const FIRST_BACKOFF: Duration = Duration::from_secs(30);
const MAX_BACKOFF: Duration = Duration::from_secs(15 * 60);

/// A pack in the picker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StickerPackView {
    pub pack_id: String,
    pub title: String,
    pub publisher: String,
    pub stickers: Vec<StickerRef>,
}

/// Packs being fetched, with the stickers waiting for them, and packs that recently could not
/// be: one fetch per pack at a time, and not again until its wait is over.
#[derive(Default, Clone)]
pub(super) struct Fetches(Arc<Mutex<FetchState>>);

#[derive(Default)]
struct FetchState {
    waiting: HashMap<[u8; HASH_LEN], Vec<StickerRef>>,
    failed: HashMap<[u8; HASH_LEN], (Instant, Duration)>,
}

impl Fetches {
    /// Wait for `pack` with `sticker`; true when this is the call that should fetch it.
    fn join(&self, pack: [u8; HASH_LEN], sticker: StickerRef) -> bool {
        let mut s = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((at, wait)) = s.failed.get(&pack)
            && at.elapsed() < *wait
        {
            return false;
        }
        match s.waiting.get_mut(&pack) {
            Some(waiting) => {
                if !waiting.contains(&sticker) {
                    waiting.push(sticker);
                }
                false
            }
            None => {
                s.waiting.insert(pack, vec![sticker]);
                true
            }
        }
    }

    /// The fetch of `pack` ended; the stickers that were waiting for it.
    fn done(&self, pack: [u8; HASH_LEN], ok: bool) -> Vec<StickerRef> {
        let mut s = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if ok {
            s.failed.remove(&pack);
        } else {
            let wait = s
                .failed
                .get(&pack)
                .map_or(FIRST_BACKOFF, |(_, w)| (*w * 2).min(MAX_BACKOFF));
            s.failed.insert(pack, (Instant::now(), wait));
        }
        s.waiting.remove(&pack).unwrap_or_default()
    }
}

impl Client {
    fn sticker_library(&self) -> Option<Library> {
        Some(Library::new(self.data.as_ref()?.stickers_dir()))
    }

    /// Put the app's own packs in place, once each.
    pub(super) fn seed_stickers(&self) {
        let Some(library) = self.sticker_library() else {
            return;
        };
        tokio::task::spawn_blocking(move || {
            let added = library.seed_bundled(&crate::trust::pinned_certificate_keys());
            if added > 0 {
                tracing::info!(added, "stickers: bundled packs placed");
            }
        });
    }

    /// The picker: the packs offered and the stickers sent lately.
    pub(super) fn load_stickers(&self) {
        let Some(library) = self.sticker_library() else {
            return;
        };
        let events = self.events.clone();
        tokio::task::spawn_blocking(move || {
            let packs = library
                .listed()
                .into_iter()
                .map(|p| StickerPackView {
                    pack_id: p.hex_id(),
                    stickers: (0..p.stickers.len() as u32)
                        .filter_map(|i| p.reference(i))
                        .collect(),
                    title: p.title,
                    publisher: p.publisher,
                })
                .collect();
            let _ = events.send(ClientEvent::Stickers {
                packs,
                recent: library.recent(),
            });
        });
    }

    /// A sticker's picture. When its pack is not here it is fetched, whole, and the picture
    /// follows; meanwhile, and if it cannot be had, the screens show the emoji.
    pub(super) fn load_sticker(&self, sticker: StickerRef) {
        let (Some(library), Some(id)) = (self.sticker_library(), pack_id(&sticker.pack_id)) else {
            return;
        };
        let events = self.events.clone();
        let anonymous = self.anonymous.clone();
        let fetches = self.sticker_fetches.clone();
        tokio::spawn(async move {
            let lookup = library.clone();
            let probe = sticker.clone();
            let found = tokio::task::spawn_blocking(move || {
                (
                    lookup.image(&probe),
                    lookup.pack(&id).map(|p| p.stickers.len()),
                )
            })
            .await;
            let (image, held) = found.unwrap_or((None, None));
            // A pack that is here but has no such sticker stays the emoji; one whose picture is
            // missing (a cleared cache) is fetched again, for what it lacks.
            if image.is_some() || held.is_some_and(|len| sticker.index as usize >= len) {
                let _ = events.send(ClientEvent::StickerImage { sticker, image });
                return;
            }
            if !fetches.join(id, sticker) {
                return;
            }
            let keys = crate::trust::pinned_certificate_keys();
            let result = crate::stickers::fetch(&anonymous, &library, id, &keys).await;
            if let Err(e) = &result {
                tracing::warn!(pack = %hex::encode(id), "stickers: pack not fetched: {e}");
            }
            let waiting = fetches.done(id, result.is_ok());
            let _ = tokio::task::spawn_blocking(move || {
                for sticker in waiting {
                    let image = library.image(&sticker);
                    let _ = events.send(ClientEvent::StickerImage { sticker, image });
                }
            })
            .await;
        });
    }

    /// Send sticker `index` of an offered pack: only its reference travels.
    pub(super) fn send_sticker(&self, contact_id: String, pack: String, index: u32) {
        let (Some(library), Some(orch)) = (self.sticker_library(), self.orch_handle.clone()) else {
            return;
        };
        // The emoji comes from the pack this device holds, not from the screens.
        let Some(sticker) = pack_id(&pack)
            .and_then(|id| library.pack(&id))
            .and_then(|p| p.reference(index))
        else {
            return self.emit(ClientEvent::Notice("That sticker is not here".into()));
        };
        let Some(payload) = crate::content::encode_sticker(&sticker) else {
            return;
        };
        orch.send_payload(contact_id, Uuid::new_v4().to_string(), payload);
        library.record_used(&sticker);
    }

    /// The packs the server offers, without those already in the picker.
    pub(super) fn load_sticker_catalog(&self) {
        let Some(library) = self.sticker_library() else {
            return;
        };
        let anonymous = self.anonymous.clone();
        let events = self.events.clone();
        tokio::spawn(async move {
            let result = crate::stickers::catalog(&anonymous).await.map(|packs| {
                let listed: Vec<String> = library.listed().iter().map(|p| p.hex_id()).collect();
                packs
                    .into_iter()
                    .filter(|p| !listed.contains(&p.pack_id))
                    .collect()
            });
            if let Err(e) = &result {
                tracing::warn!("stickers: catalog not read: {e}");
            }
            let _ = events.send(ClientEvent::StickerCatalog(result));
        });
    }

    /// Fetch a pack from the catalog and offer it in the picker; the picker is sent again.
    pub(super) fn add_sticker_pack(&self, pack: String) {
        let (Some(library), Some(id)) = (self.sticker_library(), pack_id(&pack)) else {
            return;
        };
        let anonymous = self.anonymous.clone();
        let events = self.events.clone();
        let inbox = self.inbox.clone();
        tokio::spawn(async move {
            let keys = crate::trust::pinned_certificate_keys();
            let present = match library.pack(&id) {
                Some(_) => Ok(()),
                None => crate::stickers::fetch(&anonymous, &library, id, &keys)
                    .await
                    .map(drop),
            };
            match present {
                Ok(()) => {
                    library.set_listed(&pack, true);
                    let _ = inbox.send(super::Inbox::Command(super::ClientCommand::LoadStickers));
                }
                Err(e) => {
                    let _ = events.send(ClientEvent::Notice(format!("Pack not added: {e}")));
                }
            }
        });
    }

    /// Stop offering a pack. Its files stay, so the stickers already in chats still show.
    pub(super) fn remove_sticker_pack(&self, pack: String) {
        let Some(library) = self.sticker_library() else {
            return;
        };
        if pack_id(&pack).is_none() {
            return;
        }
        library.set_listed(&pack, false);
        self.load_stickers();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sticker(index: u32) -> StickerRef {
        StickerRef {
            pack_id: "ab".repeat(32),
            index,
            emoji: "🐱".into(),
        }
    }

    /// One fetch per pack: later stickers wait for it and are answered with it; after a
    /// failure the pack is not asked for again until its wait is over.
    #[test]
    fn a_pack_is_fetched_once_and_not_retried_at_once() {
        let fetches = Fetches::default();
        let pack = [0xab; HASH_LEN];
        assert!(fetches.join(pack, sticker(0)), "the first starts the fetch");
        assert!(!fetches.join(pack, sticker(1)), "the next one waits");
        assert!(!fetches.join(pack, sticker(1)));
        assert_eq!(fetches.done(pack, false), vec![sticker(0), sticker(1)]);
        assert!(!fetches.join(pack, sticker(0)), "too soon after a failure");
        assert!(fetches.done(pack, true).is_empty());
        assert!(fetches.join(pack, sticker(0)), "a success clears the wait");
    }
}
