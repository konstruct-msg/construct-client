//! History moved between two devices of this account as a file (CTHF), the way iOS saves one
//! when the devices cannot see each other (`client/specs/DEVICE_LINK_HISTORY_TRANSFER.md`).
//!
//! The core does the protocol: the header, the key agreed with the recipient's keys, the sealed
//! chunks, the record order (`construct_core::history::session`), and how records and store rows
//! map to each other (`history::project`), so a transfer lands here as it does on iOS. This module
//! moves bytes between the core, the store, the media cache and a file.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::path::Path;

use construct_core::history::cth1::Event;
use construct_core::history::frames::{KnownKeys, Pin};
use construct_core::history::project::{self, MessageExport, MessageImport};
use construct_core::history::session::{PeerKeys, Receiver, Source, Status};
use construct_core::history::{self, HistoryFailure, record_type as rt};

use crate::content::MediaFile;
use crate::grpc::GrpcClient;
use crate::local_store::LocalStore;
use crate::media::MediaCache;
use crate::orchestrator_task::OrchestratorHandle;

/// What a transfer carried.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HistorySummary {
    pub contacts: usize,
    pub chats: usize,
    pub messages: usize,
    pub reactions: usize,
    pub media: usize,
    /// Files referred to but not carried: not on this device's disk, or too large.
    pub media_skipped: usize,
}

/// Written to the file in pieces of about this much.
const FLUSH_AT: usize = 1 << 20;

fn fail(f: HistoryFailure) -> String {
    format!("history transfer refused: {}", f.as_str())
}

fn io(e: std::io::Error) -> String {
    format!("history file: {e}")
}

fn store_err(e: impl std::fmt::Display) -> String {
    format!("history: the store refused: {e}")
}

/// The account as the transfer names it: its 16 raw bytes.
fn account_raw(user_id: &str) -> Result<[u8; 16], String> {
    history::records::raw(user_id)
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| "this account's id is not a UUID".to_string())
}

/// `HistoryManifest`, encoded by its field numbers (construct-protos `client/history_snapshot.proto`).
fn manifest(
    snapshot_id: [u8; 16],
    user_id: [u8; 16],
    source_device_id: &str,
    summary: &HistorySummary,
    media_count: usize,
    media_bytes: u64,
) -> Vec<u8> {
    use prost::encoding::{bytes, int64, string, uint32, uint64};
    let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let mut m = Vec::new();
    uint32::encode(1, &1, &mut m);
    bytes::encode(2, &snapshot_id.to_vec(), &mut m);
    bytes::encode(3, &user_id.to_vec(), &mut m);
    string::encode(4, &source_device_id.to_lowercase(), &mut m);
    int64::encode(5, &now, &mut m);
    string::encode(
        6,
        &format!("construct-client {}", env!("CARGO_PKG_VERSION")),
        &mut m,
    );
    uint32::encode(7, &count(summary.contacts), &mut m);
    uint32::encode(8, &count(summary.chats), &mut m);
    uint32::encode(9, &count(summary.messages), &mut m);
    uint32::encode(10, &count(summary.reactions), &mut m);
    uint32::encode(11, &count(media_count), &mut m);
    uint64::encode(12, &media_bytes, &mut m);
    // A file carries both phases (K18).
    uint32::encode(13, &3, &mut m);
    m
}

/// The bundle of `device_id`, a device of our own account, as the directory serves it.
async fn own_bundle(
    grpc: &GrpcClient,
    user_id: &str,
    device_id: &str,
) -> Result<construct_core::orchestration::orchestrator::SessionBundle, String> {
    crate::grpc::get_pre_key_bundles(grpc, user_id, vec![device_id.to_string()], false)
        .await
        .map_err(|e| format!("the directory was not reached: {e}"))?
        .bundles
        .into_iter()
        .find(|b| b.device_id.eq_ignore_ascii_case(device_id))
        .map(|b| b.bundle)
        .ok_or_else(|| format!("device {} is not one of this account's", short(device_id)))
}

fn short(id: &str) -> &str {
    &id[..8.min(id.len())]
}

fn hybrid_of(
    bundle: &construct_core::orchestration::orchestrator::SessionBundle,
) -> Result<Vec<u8>, String> {
    bundle
        .kyber
        .hybrid_identity_key
        .clone()
        .filter(|k| !k.is_empty())
        .ok_or_else(|| "that device has no hybrid key: it cannot take part in a transfer".into())
}

/// What the file is sealed to: the recipient's identity, hybrid and Kyber signed prekey.
async fn peer_keys(grpc: &GrpcClient, user_id: &str, device_id: &str) -> Result<PeerKeys, String> {
    let bundle = own_bundle(grpc, user_id, device_id).await?;
    let identity_public: [u8; 32] = bundle
        .x3dh
        .identity_public
        .as_slice()
        .try_into()
        .map_err(|_| "that device's identity key is malformed".to_string())?;
    let hybrid_public = hybrid_of(&bundle)?;
    let (Some(kyber_prekey_public), Some(kyber_prekey_id)) =
        (bundle.kyber.pre_key_public.clone(), bundle.kyber.pre_key_id)
    else {
        return Err("that device has no Kyber prekey: it cannot take a file".into());
    };
    Ok(PeerKeys {
        identity_public,
        hybrid_public,
        kyber_prekey_public,
        kyber_prekey_id,
    })
}

/// What the importer checks the file's sender against: the directory's keys for it. A file has
/// no QR to pin it, so the directory is the only pin (spec: `bundle_only`, and it is logged).
async fn known_keys(
    grpc: &GrpcClient,
    user_id: &str,
    device_id: &str,
) -> Result<KnownKeys, String> {
    let bundle = own_bundle(grpc, user_id, device_id).await?;
    Ok(KnownKeys {
        identity_public: bundle.x3dh.identity_public.clone(),
        hybrid_public: hybrid_of(&bundle)?,
    })
}

/// Records as the stream carries them: the type byte and the protobuf.
type Records = Vec<(u8, Vec<u8>)>;

/// The records of a transcript in the order the protocol requires, and the files its messages
/// refer to.
pub(crate) fn collect(
    store: &LocalStore,
) -> Result<(Records, Vec<MediaFile>, HistorySummary), String> {
    let rows = store.history_rows().map_err(store_err)?;
    let own = store.own_account().to_string();
    let mut summary = HistorySummary::default();
    let mut records = Vec::new();
    for c in &rows.contacts {
        records.push((rt::CONTACT, project::export_contact(c)));
        summary.contacts += 1;
    }
    for c in &rows.chats {
        records.push((rt::CHAT, project::export_chat(&c.peer_id, c.is_pinned)));
        summary.chats += 1;
    }
    for d in &rows.peer_devices {
        records.push((rt::PEER_DEVICE, project::export_peer_device(d)));
    }
    for c in &rows.calls {
        records.push((rt::CALL, project::export_call(c)));
    }
    let mut media = Vec::new();
    let mut seen = HashSet::new();
    for (m, peer) in &rows.messages {
        if let MessageExport::Record {
            record,
            media: refs,
        } = project::export_message(m, &own, peer.as_deref())
        {
            records.push((rt::MESSAGE, record));
            summary.messages += 1;
            if !refs.is_empty() {
                for f in store.media_files(&m.id).unwrap_or_default() {
                    if seen.insert(f.media_id.clone()) {
                        media.push(f);
                    }
                }
            }
        }
    }
    for r in &rows.reactions {
        records.push((rt::REACTION, project::export_reaction(r)));
        summary.reactions += 1;
    }
    Ok((records, media, summary))
}

/// Write this device's history to `path`, sealed to `device_id`, another device of the account.
/// Written aside and renamed, so a cut write never leaves something that looks like a file.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn export_to_file(
    orch: &OrchestratorHandle,
    grpc: &GrpcClient,
    store: &LocalStore,
    cache: &MediaCache,
    user_id: &str,
    own_device: &str,
    device_id: &str,
    path: &Path,
) -> Result<HistorySummary, String> {
    if device_id.eq_ignore_ascii_case(own_device) {
        return Err("choose another device of the account".into());
    }
    let user = account_raw(user_id)?;
    let peer = peer_keys(grpc, user_id, device_id).await?;
    let mut sender = orch.history_file_sender(user, peer).await?;
    let (records, media, mut summary) = collect(store)?;

    let partial = path.with_extension("part");
    let mut file = std::fs::File::create(&partial).map_err(io)?;
    let written = (|| -> Result<(), String> {
        let mut out = Vec::with_capacity(FLUSH_AT * 2);
        out.extend_from_slice(sender.first_frame());
        let media_bytes = media.iter().map(|f| f.info.size).sum();
        let head = manifest(
            sender.snapshot_id(),
            user,
            own_device,
            &summary,
            media.len(),
            media_bytes,
        );
        sender
            .push_record(rt::MANIFEST, &head, &mut out)
            .map_err(fail)?;
        for (kind, record) in &records {
            sender.push_record(*kind, record, &mut out).map_err(fail)?;
            flush(&mut file, &mut out, false)?;
        }
        for f in &media {
            let key = store.media_local_key(&f.media_id);
            match cache.plaintext(f, key.as_deref().map(|k| &k[..])) {
                Some(bytes) if (bytes.len() as u64) < history::MAX_RECORD_BYTES => {
                    sender
                        .begin_media(&f.media_id, &f.info.mime, bytes.len() as u64, &mut out)
                        .map_err(fail)?;
                    sender.push_media(&bytes, &mut out).map_err(fail)?;
                    summary.media += 1;
                }
                _ => summary.media_skipped += 1,
            }
            flush(&mut file, &mut out, false)?;
        }
        sender.finish(&mut out).map_err(fail)?;
        flush(&mut file, &mut out, true)?;
        file.sync_all().map_err(io)
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&partial);
        return Err(e);
    }
    std::fs::rename(&partial, path).map_err(io)?;
    Ok(summary)
}

fn flush(file: &mut std::fs::File, out: &mut Vec<u8>, all: bool) -> Result<(), String> {
    if all || out.len() >= FLUSH_AT {
        file.write_all(out).map_err(io)?;
        out.clear();
    }
    Ok(())
}

/// Read a history file into the store: what it brings is added, what this device holds is kept
/// (the core's merge rules). Returns what landed and the accounts it named, for the session to
/// take deliveries from.
pub(crate) async fn import_file(
    orch: &OrchestratorHandle,
    grpc: &GrpcClient,
    store: &LocalStore,
    cache: &MediaCache,
    user_id: &str,
    path: &Path,
) -> Result<(HistorySummary, Vec<String>), String> {
    let user = account_raw(user_id)?;
    let mut file = std::fs::File::open(path).map_err(io)?;
    let mut receiver = Receiver::new(Source::File, user);
    let mut importer = Importer::new(store, cache);
    let mut buf = Vec::new();
    loop {
        let need = receiver.need();
        buf.resize(need, 0);
        let n = read_up_to(&mut file, &mut buf)?;
        if n == 0 {
            receiver.end_of_input().map_err(fail)?;
            break;
        }
        let (events, status) = receiver.feed(&buf[..n]).map_err(fail)?;
        for event in events {
            importer.event(event)?;
        }
        match status {
            Status::NeedMore => {}
            Status::AwaitKeys { sender_device_id } => {
                let sender = hex::encode(sender_device_id);
                let known = known_keys(grpc, user_id, &sender).await?;
                tracing::info!(device = %short(&sender), "history file: sender pinned by the directory only");
                let (back, accepted) = orch
                    .history_accept(Box::new(receiver), known, Pin::BundleOnly)
                    .await?;
                receiver = *back;
                accepted.map_err(fail)?;
            }
            Status::Done => break,
            Status::Skipped => return Err("the file holds no history".into()),
        }
    }
    Ok((importer.summary, importer.contacts))
}

/// Read until `buf` is full or the file ends; how much was read.
fn read_up_to(file: &mut std::fs::File, buf: &mut [u8]) -> Result<usize, String> {
    let mut at = 0;
    while at < buf.len() {
        match file.read(&mut buf[at..]).map_err(io)? {
            0 => break,
            n => at += n,
        }
    }
    Ok(at)
}

/// Where the records of a transfer go, one at a time, as the core hands them over.
struct Importer<'a> {
    store: &'a LocalStore,
    cache: &'a MediaCache,
    now_ms: i64,
    summary: HistorySummary,
    contacts: Vec<String>,
    /// The file being received: its id and the bytes so far.
    media: Option<(String, Vec<u8>)>,
}

impl<'a> Importer<'a> {
    fn new(store: &'a LocalStore, cache: &'a MediaCache) -> Self {
        Self {
            store,
            cache,
            now_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as i64),
            summary: HistorySummary::default(),
            contacts: Vec::new(),
            media: None,
        }
    }

    fn event(&mut self, event: Event) -> Result<(), String> {
        match event {
            Event::Record { record_type, proto } => self.record(record_type, &proto),
            Event::Skipped { record_type } => {
                tracing::info!(
                    record_type,
                    "history record this version does not read: skipped"
                );
                Ok(())
            }
            Event::MediaStart {
                media_id, byte_len, ..
            } => {
                // The core caps a blob at `MAX_RECORD_BYTES`; it is collected to be sealed whole.
                let capacity = usize::try_from(byte_len.min(64 << 20)).unwrap_or(0);
                self.media = Some((media_id, Vec::with_capacity(capacity)));
                Ok(())
            }
            Event::MediaBytes(bytes) => {
                if let Some((_, held)) = self.media.as_mut() {
                    held.extend_from_slice(&bytes);
                }
                Ok(())
            }
            Event::MediaEnd => {
                let Some((media_id, bytes)) = self.media.take() else {
                    return Ok(());
                };
                match self.cache.keep_imported(&media_id, &bytes) {
                    Ok(Some(key)) => {
                        self.store
                            .set_media_local_key(&media_id, &key)
                            .map_err(store_err)?;
                        self.summary.media += 1;
                    }
                    Ok(None) => {}
                    Err(e) => tracing::warn!(%media_id, "imported file not kept: {e}"),
                }
                Ok(())
            }
            Event::End => Ok(()),
        }
    }

    fn record(&mut self, record_type: u8, proto: &[u8]) -> Result<(), String> {
        let raw = self.store.raw();
        let own = self.store.own_account().to_string();
        match record_type {
            rt::CONTACT => {
                let decoded = history::records::ContactRecord::decode(proto).map_err(fail)?;
                let Some(id) = history::records::dashed(&decoded.user_id) else {
                    return Err(fail(HistoryFailure::Malformed));
                };
                if id == own {
                    return Ok(());
                }
                let existing = raw.contact(&id).map_err(store_err)?;
                let contact =
                    project::import_contact(proto, existing, self.now_ms).map_err(fail)?;
                raw.upsert_contact(&contact).map_err(store_err)?;
                if contact.is_contact {
                    self.contacts.push(id);
                }
                self.summary.contacts += 1;
            }
            rt::CHAT => {
                let chat = project::import_chat(proto).map_err(fail)?;
                let id = self.store.chat_for(&chat.peer_id).map_err(store_err)?;
                if chat.pin {
                    raw.set_chat_pinned(&id, true).map_err(store_err)?;
                }
                self.summary.chats += 1;
            }
            rt::MESSAGE => {
                if let MessageImport::Row { peer_id, message } =
                    project::import_message(proto, &own).map_err(fail)?
                    && self
                        .store
                        .import_history_message(*message, &peer_id)
                        .map_err(store_err)?
                {
                    self.summary.messages += 1;
                }
            }
            rt::REACTION => {
                let reaction = project::import_reaction(proto, self.now_ms).map_err(fail)?;
                raw.upsert_reaction(&reaction).map_err(store_err)?;
                self.summary.reactions += 1;
            }
            rt::PEER_DEVICE => {
                if let Some(device) =
                    project::import_peer_device(proto, self.now_ms).map_err(fail)?
                {
                    raw.record_peer_device(&device).map_err(store_err)?;
                }
            }
            // The manifest is the core's to check; a call this client has nowhere to show.
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_manifest_reads_back_as_the_core_reads_it() {
        let summary = HistorySummary {
            contacts: 2,
            chats: 3,
            messages: 40,
            reactions: 5,
            ..Default::default()
        };
        let m = manifest(
            [9; 16],
            [7; 16],
            "ABCDEF0123456789abcdef0123456789",
            &summary,
            1,
            100,
        );
        // The core's reader takes a manifest as the first record of a stream; one it refuses
        // fails here with the reason.
        let mut writer = construct_core::history::cth1::Writer::new();
        let mut stream = Vec::new();
        writer.record(rt::MANIFEST, &m, &mut stream).unwrap();
        writer.end(&mut stream).unwrap();
        let mut reader = construct_core::history::cth1::Reader::new(Some(
            construct_core::history::cth1::Envelope {
                snapshot_id: [9; 16],
                user_id: [7; 16],
            },
        ));
        let mut events = Vec::new();
        reader
            .push(&stream, &mut events)
            .expect("the core takes the manifest");
        assert!(matches!(
            events.first(),
            Some(Event::Record {
                record_type: rt::MANIFEST,
                ..
            })
        ));
        let mut wrong = construct_core::history::cth1::Reader::new(Some(
            construct_core::history::cth1::Envelope {
                snapshot_id: [8; 16],
                user_id: [7; 16],
            },
        ));
        assert!(
            wrong.push(&stream, &mut Vec::new()).is_err(),
            "and refuses it for another snapshot"
        );
    }
}
