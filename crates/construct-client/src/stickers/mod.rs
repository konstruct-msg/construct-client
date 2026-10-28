//! Stickers, as iOS has them (`Services/Stickers`, client/specs/STICKER_CLIENT_SPEC.md): a
//! message carries only a reference — the pack's hash, a position in it, an emoji — and the
//! pictures come from a pack this device holds.
//!
//! A pack is content-addressed and signed: its id is the SHA-256 of its manifest's canonical
//! bytes, each sticker is named by the SHA-256 of its file, and the manifest is signed with the
//! key the server's sender certificates are signed with (pinned in `trust`). So the server that
//! hands out packs is trusted with nothing: what it sends either hashes to what was asked for and
//! carries the signature, or is refused. Packs are fetched whole, never one sticker at a time, so
//! the server does not learn which sticker a device is showing — and on the client without a
//! token, so it does not learn which account asked.
//!
//! On disk, beside the account's data (public files, so not in the encrypted store):
//!
//! ```text
//! stickers/manifests/<pack id hex>.pb   verified manifests; written last, so present = complete
//! stickers/blobs/<sha256 hex>.webp      the pictures, checked before they are written
//! stickers/state.json                   packs offered in the picker, recent stickers, seeded packs
//! ```

mod bundled;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::grpc::GrpcClient;
use crate::proto::messaging::v1 as wire;

/// A pack id and a sticker's name are SHA-256s.
pub const HASH_LEN: usize = 32;
/// `knst_sticker_ref.json` `rules`: an emoji is 1…32 bytes of UTF-8 — bytes, so every client
/// counts the same thing.
const EMOJI_MAX_BYTES: usize = 32;
/// Every sticker is a static WebP on this square (STICKER_PLATFORM_SPEC).
const CANVAS: u32 = 512;
/// Largest sticker file; refused above this from the manifest, before anything is fetched.
pub const MAX_STICKER_BYTES: usize = 100 * 1024;
/// Recent stickers kept, as iOS keeps them.
const RECENT: usize = 24;
/// Most packs read from the catalog.
const MAX_CATALOG: usize = 500;

/// A sticker as a message names it, checked (`knst_sticker_ref.json`). The pack id is lower-case
/// hex here, the one form it takes in this client's files and on the screens.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StickerRef {
    pub pack_id: String,
    pub index: u32,
    pub emoji: String,
}

impl StickerRef {
    /// The wire reference, or `None` when it is not a valid one: then the message is corrupt
    /// and is not shown as a sticker at all.
    pub fn from_wire(r: &wire::StickerRef) -> Option<Self> {
        (r.pack_id.len() == HASH_LEN && valid_emoji(&r.emoji)).then(|| Self {
            pack_id: hex::encode(&r.pack_id),
            index: r.index,
            emoji: r.emoji.clone(),
        })
    }

    pub fn to_wire(&self) -> Option<wire::StickerRef> {
        Some(wire::StickerRef {
            pack_id: pack_id(&self.pack_id)?.to_vec().into(),
            index: self.index,
            emoji: self.emoji.clone(),
        })
    }
}

fn valid_emoji(emoji: &str) -> bool {
    (1..=EMOJI_MAX_BYTES).contains(&emoji.len())
}

/// A pack id from its hex form: exactly 64 lower-case hex digits, so it is safe as a file name.
pub fn pack_id(hex_id: &str) -> Option<[u8; HASH_LEN]> {
    if hex_id.len() != HASH_LEN * 2 || hex_id.bytes().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    hex::decode(hex_id).ok()?.try_into().ok()
}

/// One sticker of a verified pack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub sha256: [u8; HASH_LEN],
    pub emoji: String,
}

/// A pack whose manifest hashed to its id, with well-formed entries and — when it came from
/// outside this device — a good signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pack {
    pub id: [u8; HASH_LEN],
    pub title: String,
    pub publisher: String,
    pub stickers: Vec<Entry>,
}

impl Pack {
    pub fn hex_id(&self) -> String {
        hex::encode(self.id)
    }

    /// The reference a send names sticker `index` by.
    pub fn reference(&self, index: u32) -> Option<StickerRef> {
        let entry = self.stickers.get(index as usize)?;
        Some(StickerRef {
            pack_id: self.hex_id(),
            index,
            emoji: entry.emoji.clone(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    Undecodable,
    PackIdMismatch,
    BadEntry(usize),
    Unsigned,
    BadSignature,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Undecodable => f.write_str("the pack's manifest does not decode"),
            Self::PackIdMismatch => f.write_str("the pack is not the one its id names"),
            Self::BadEntry(i) => write!(f, "sticker {i} of the pack is malformed"),
            Self::Unsigned => f.write_str("the pack is not signed"),
            Self::BadSignature => f.write_str("the pack's signature is not the server's"),
        }
    }
}

/// Whether the signature is checked: always for a manifest from the server or the app's own
/// bundle; not for one this client verified before and wrote to its own disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signature<'k> {
    Check(&'k [Vec<u8>]),
    CheckedBefore,
}

/// The bytes a pack's identity is the hash of: the manifest with `pack_id` and `signature`
/// cleared, encoded (`knst_sticker_pack.json`). Fields go out in ascending order and empty ones
/// not at all, the same encoding every client and the publisher produce.
fn canonical(manifest: &wire::StickerPackManifest) -> Vec<u8> {
    let mut m = manifest.clone();
    m.pack_id = Default::default();
    m.signature = Default::default();
    m.encode_to_vec()
}

/// Verify a manifest, in iOS's order (`StickerPack.verify`): decode, hash, entries, signature
/// — so a manifest is refused for being unsigned only once everything else about it is right.
pub fn verify(manifest_bytes: &[u8], signature: Signature<'_>) -> Result<Pack, VerifyError> {
    let manifest =
        wire::StickerPackManifest::decode(manifest_bytes).map_err(|_| VerifyError::Undecodable)?;
    let canonical = canonical(&manifest);
    let id: [u8; HASH_LEN] = Sha256::digest(&canonical).into();
    if manifest.pack_id.as_ref() != id {
        return Err(VerifyError::PackIdMismatch);
    }
    let mut stickers = Vec::with_capacity(manifest.stickers.len());
    for (i, e) in manifest.stickers.iter().enumerate() {
        let sha256: [u8; HASH_LEN] = e
            .sha256
            .as_ref()
            .try_into()
            .map_err(|_| VerifyError::BadEntry(i))?;
        if !valid_emoji(&e.emoji)
            || e.width != CANVAS
            || e.height != CANVAS
            || e.byte_len == 0
            || e.byte_len as usize > MAX_STICKER_BYTES
        {
            return Err(VerifyError::BadEntry(i));
        }
        stickers.push(Entry {
            sha256,
            emoji: e.emoji.clone(),
        });
    }
    if let Signature::Check(keys) = signature {
        if manifest.signature.is_empty() {
            return Err(VerifyError::Unsigned);
        }
        if !signed_by_any(&manifest.signature, &canonical, keys) {
            return Err(VerifyError::BadSignature);
        }
    }
    Ok(Pack {
        id,
        title: manifest.title,
        publisher: manifest.publisher,
        stickers,
    })
}

/// A raw Ed25519 signature over `message` by any of `keys` (iOS `BundleSigningTrust.verify`).
fn signed_by_any(signature: &[u8], message: &[u8], keys: &[Vec<u8>]) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };
    keys.iter().any(|k| {
        <[u8; 32]>::try_from(k.as_slice())
            .ok()
            .and_then(|k| VerifyingKey::from_bytes(&k).ok())
            .is_some_and(|k| k.verify(message, &signature).is_ok())
    })
}

/// A sticker file is what its manifest says: that hash, so that size, and a static WebP on the
/// sticker canvas — read from its header before anything decodes it (iOS `WebPHeader`).
fn check_blob(entry: &Entry, bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > MAX_STICKER_BYTES {
        return Err("a sticker is larger than a sticker may be".into());
    }
    if Sha256::digest(bytes).as_slice() != entry.sha256 {
        return Err("a sticker is not the one its pack names".into());
    }
    if !is_sticker_webp(bytes) {
        return Err("a sticker is not a 512×512 still WebP".into());
    }
    Ok(())
}

/// A WebP's header says it is a still picture on the sticker canvas.
fn is_sticker_webp(b: &[u8]) -> bool {
    if b.len() < 30 || &b[0..4] != b"RIFF" || &b[8..12] != b"WEBP" {
        return false;
    }
    let p = 20; // the first byte of the first chunk's payload
    let (w, h) = match &b[12..16] {
        // A 3-byte frame tag, the start code, then 14-bit width and height.
        b"VP8 " => {
            if b[p + 3..p + 6] != [0x9D, 0x01, 0x2A] {
                return false;
            }
            (
                u32::from(b[p + 6]) | (u32::from(b[p + 7] & 0x3F) << 8),
                u32::from(b[p + 8]) | (u32::from(b[p + 9] & 0x3F) << 8),
            )
        }
        // A signature byte, then 14 bits of width − 1 and 14 of height − 1.
        b"VP8L" => {
            if b[p] != 0x2F {
                return false;
            }
            let (b1, b2, b3, b4) = (
                u32::from(b[p + 1]),
                u32::from(b[p + 2]),
                u32::from(b[p + 3]),
                u32::from(b[p + 4]),
            );
            (
                1 + (b1 | ((b2 & 0x3F) << 8)),
                1 + ((b2 >> 6) | (b3 << 2) | ((b4 & 0x0F) << 10)),
            )
        }
        // Flags (animation is refused), three reserved bytes, then 24-bit width − 1, height − 1.
        b"VP8X" => {
            if b[p] & 0x02 != 0 {
                return false;
            }
            let le24 = |i: usize| {
                u32::from(b[i]) | (u32::from(b[i + 1]) << 8) | (u32::from(b[i + 2]) << 16)
            };
            (1 + le24(p + 4), 1 + le24(p + 7))
        }
        _ => return false,
    };
    w == CANVAS && h == CANVAS
}

/// What the picker offers and remembers.
#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    /// Packs offered in the picker, in the order they were added.
    #[serde(default)]
    listed: Vec<String>,
    /// Newest first.
    #[serde(default)]
    recent: Vec<StickerRef>,
    /// Bundled packs already put in place, so one the person removed stays removed.
    #[serde(default)]
    seeded: Vec<String>,
}

/// The packs on this device.
#[derive(Clone)]
pub struct Library {
    dir: PathBuf,
    /// `state.json` is read, changed and written under this.
    state: Arc<Mutex<()>>,
}

impl Library {
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            state: Arc::new(Mutex::new(())),
        }
    }

    fn manifest_path(&self, id: &[u8; HASH_LEN]) -> PathBuf {
        self.dir
            .join("manifests")
            .join(format!("{}.pb", hex::encode(id)))
    }

    fn blob_path(&self, sha256: &[u8; HASH_LEN]) -> PathBuf {
        self.dir
            .join("blobs")
            .join(format!("{}.webp", hex::encode(sha256)))
    }

    /// A pack this device holds whole.
    pub fn pack(&self, id: &[u8; HASH_LEN]) -> Option<Pack> {
        let bytes = std::fs::read(self.manifest_path(id)).ok()?;
        verify(&bytes, Signature::CheckedBefore)
            .ok()
            .filter(|p| &p.id == id)
    }

    /// The picture of a sticker, when its pack is here.
    pub fn image(&self, r: &StickerRef) -> Option<Vec<u8>> {
        let pack = self.pack(&pack_id(&r.pack_id)?)?;
        let entry = pack.stickers.get(r.index as usize)?;
        let bytes = std::fs::read(self.blob_path(&entry.sha256)).ok()?;
        // The disk is this device's, but a file there is read back as what it claims to be.
        check_blob(entry, &bytes).ok()?;
        Some(bytes)
    }

    fn has_blob(&self, entry: &Entry) -> bool {
        self.blob_path(&entry.sha256).is_file()
    }

    /// Keep one sticker of `pack`, checked.
    fn put_blob(&self, entry: &Entry, bytes: &[u8]) -> Result<(), String> {
        check_blob(entry, bytes)?;
        write_atomically(&self.blob_path(&entry.sha256), bytes)
    }

    /// Make a pack present: every sticker must be here already, and the manifest goes last.
    fn install(&self, manifest_bytes: &[u8], pack: &Pack) -> Result<(), String> {
        if let Some(missing) = pack.stickers.iter().position(|e| !self.has_blob(e)) {
            return Err(format!("sticker {missing} of the pack did not arrive"));
        }
        write_atomically(&self.manifest_path(&pack.id), manifest_bytes)
    }

    fn with_state<T>(&self, change: impl FnOnce(&mut State) -> T) -> T {
        let _held = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let path = self.dir.join("state.json");
        let mut state: State = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let out = change(&mut state);
        match serde_json::to_vec(&state) {
            Ok(bytes) => {
                if let Err(e) = write_atomically(&path, &bytes) {
                    tracing::warn!("stickers: state not written: {e}");
                }
            }
            Err(e) => tracing::warn!("stickers: state not encoded: {e}"),
        }
        out
    }

    /// The packs the picker offers, those present only.
    pub fn listed(&self) -> Vec<Pack> {
        self.with_state(|s| s.listed.clone())
            .iter()
            .filter_map(|id| self.pack(&pack_id(id)?))
            .collect()
    }

    pub fn set_listed(&self, id: &str, listed: bool) {
        self.with_state(|s| {
            s.listed.retain(|p| p != id);
            if listed {
                s.listed.push(id.to_owned());
            }
        });
    }

    /// Stickers sent lately that can still be sent: their pack is offered.
    pub fn recent(&self) -> Vec<StickerRef> {
        let (listed, recent) = self.with_state(|s| (s.listed.clone(), s.recent.clone()));
        recent
            .into_iter()
            .filter(|r| listed.contains(&r.pack_id))
            .collect()
    }

    pub fn record_used(&self, r: &StickerRef) {
        self.with_state(|s| {
            s.recent
                .retain(|x| (x.pack_id.as_str(), x.index) != (r.pack_id.as_str(), r.index));
            s.recent.insert(0, r.clone());
            s.recent.truncate(RECENT);
        });
    }

    /// Put the app's own packs in place, once each, checked like a fetched pack. Returns how
    /// many were added.
    pub fn seed_bundled(&self, keys: &[Vec<u8>]) -> usize {
        let seeded: HashSet<String> = self.with_state(|s| s.seeded.iter().cloned().collect());
        let mut added = 0;
        for (manifest, listed) in bundled::PACKS {
            let pack = match verify(manifest, Signature::Check(keys)) {
                Ok(pack) => pack,
                Err(e) => {
                    tracing::warn!("stickers: a bundled pack is refused: {e}");
                    continue;
                }
            };
            let id = pack.hex_id();
            if seeded.contains(&id) {
                continue;
            }
            let placed = pack.stickers.iter().try_for_each(|entry| {
                let hex = hex::encode(entry.sha256);
                let bytes = bundled::BLOBS
                    .iter()
                    .find(|(h, _)| *h == hex)
                    .map(|(_, b)| *b)
                    .ok_or_else(|| format!("bundled sticker {hex} is missing"))?;
                self.put_blob(entry, bytes)
            });
            if let Err(e) = placed.and_then(|()| self.install(manifest, &pack)) {
                tracing::warn!(pack = %id, "stickers: a bundled pack is not placed: {e}");
                continue;
            }
            self.with_state(|s| {
                if *listed && !s.listed.contains(&id) {
                    s.listed.push(id.clone());
                }
                s.seeded.push(id.clone());
            });
            added += 1;
        }
        added
    }
}

fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let dir = path.parent().ok_or("no folder")?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let part = path.with_extension("part");
    std::fs::write(&part, bytes).map_err(|e| e.to_string())?;
    std::fs::rename(&part, path).map_err(|e| e.to_string())
}

/// Fetch pack `id` whole from the server and make it present: the manifest, verified against
/// `keys` and the id asked for, then every sticker not here yet, each checked as it comes.
pub async fn fetch(
    anonymous: &GrpcClient,
    library: &Library,
    id: [u8; HASH_LEN],
    keys: &[Vec<u8>],
) -> Result<Pack, String> {
    use crate::proto::services::v1::{GetStickerPackBlobsRequest, GetStickerPackManifestRequest};
    let manifest = crate::grpc::sticker_manifest(
        anonymous,
        &GetStickerPackManifestRequest {
            pack_id: id.to_vec().into(),
        },
    )
    .await
    .map_err(|e| e.to_string())?
    .ok_or("the server has no such pack")?;
    let manifest_bytes = manifest.encode_to_vec();
    let pack = verify(&manifest_bytes, Signature::Check(keys)).map_err(|e| e.to_string())?;
    if pack.id != id {
        return Err("the server sent another pack".into());
    }
    let have: Vec<_> = pack
        .stickers
        .iter()
        .filter(|e| library.has_blob(e))
        .map(|e| e.sha256.to_vec().into())
        .collect();
    if have.len() < pack.stickers.len() {
        let request = GetStickerPackBlobsRequest {
            pack_id: id.to_vec().into(),
            have_sha256: have,
        };
        crate::grpc::sticker_pack_blobs(anonymous, &request, |sha256, data| {
            let entry = pack
                .stickers
                .iter()
                .find(|e| e.sha256.as_slice() == sha256)
                .ok_or_else(|| "the server sent a sticker the pack does not have".to_string())?;
            library.put_blob(entry, data)
        })
        .await
        .map_err(|e| e.to_string())?;
    }
    library.install(&manifest_bytes, &pack)?;
    tracing::info!(pack = %pack.hex_id(), stickers = pack.stickers.len(), "stickers: pack fetched");
    Ok(pack)
}

/// A pack the server offers, as its catalog lists it (unsigned: what is installed is checked
/// when it is fetched).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CatalogPack {
    pub pack_id: String,
    pub title: String,
    pub publisher: String,
    pub sticker_count: u32,
    pub total_bytes: u64,
}

/// Every pack the server offers, page by page.
pub async fn catalog(anonymous: &GrpcClient) -> Result<Vec<CatalogPack>, String> {
    use crate::proto::services::v1::ListStickerPacksRequest;
    let mut packs = Vec::new();
    let mut page_token = bytes::Bytes::new();
    loop {
        let page = crate::grpc::sticker_packs(
            anonymous,
            &ListStickerPacksRequest {
                page_token: page_token.clone(),
                page_size: 100,
            },
        )
        .await
        .map_err(|e| e.to_string())?;
        let more = !page.next_page_token.is_empty() && page.next_page_token != page_token;
        packs.extend(
            page.packs
                .into_iter()
                .filter(|p| p.pack_id.len() == HASH_LEN)
                .map(|p| CatalogPack {
                    pack_id: hex::encode(&p.pack_id),
                    title: p.title,
                    publisher: p.publisher,
                    sticker_count: p.sticker_count,
                    total_bytes: p.total_bytes,
                }),
        );
        if !more || packs.len() >= MAX_CATALOG {
            break;
        }
        page_token = page.next_page_token;
    }
    packs.truncate(MAX_CATALOG);
    Ok(packs)
}

#[cfg(test)]
mod tests;
