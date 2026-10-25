//! History moved between two devices of this account, the way iOS moves it
//! (`client/specs/DEVICE_LINK_HISTORY_TRANSFER.md`): over the local network (CTT1 v2, two
//! connections — the transcript, then the files), or as a file (CTHF) when the devices cannot see
//! each other.
//!
//! The core does the protocol: the header, the key agreed with the recipient's keys, the sealed
//! chunks, the record order (`construct_core::history::session`), and how records and store rows
//! map to each other (`history::project`), so a transfer lands here as it does on iOS. This module
//! moves bytes between the core, the store, the media cache and a file or a socket
//! (`crate::nearby`).

use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

use construct_core::history::cth1::Event;
use construct_core::history::discovery::{discovery_instance_name, discovery_tag};
use construct_core::history::frames::{KnownKeys, Pin};
use construct_core::history::project::{self, MessageExport, MessageImport};
use construct_core::history::session::{PeerKeys, Receiver, Sender, Source, Status};
use construct_core::history::{self, HistoryFailure, record_type as rt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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

/// Where a transfer over the local network stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NearbyStep {
    /// Sending: waiting for the other device to connect.
    Waiting,
    /// Sending: connected; history is moving.
    Moving,
    /// Another device of the account connected and is sending its history here. Nobody asked
    /// for it on this device: it was asked for on the sending one.
    Receiving,
    /// Everything was sent.
    Sent(HistorySummary),
    /// The other device declined to send.
    Skipped,
    /// It stopped, and why. What was received before is kept and reported as imported.
    Failed(String),
}

/// Written out in pieces of about this much.
const FLUSH_AT: usize = 1 << 20;

/// Which records a stream carries (K18): the transcript, the files, or both.
const PHASE_TRANSCRIPT: u32 = 1;
const PHASE_MEDIA: u32 = 2;
const PHASE_BOTH: u32 = 3;

/// After the transcript, how long the sending device may take to offer the files.
const MEDIA_PHASE_WAIT: Duration = Duration::from_secs(2 * 60);

/// How long a device that connected may take to answer the opening.
const REPLY_WAIT: Duration = Duration::from_secs(60);

/// Spec §6: right after a link the directory may not serve the new device's keys yet; asked again
/// this often, this many times (iOS: 2 s × 15).
const PEER_KEYS_RETRY: Duration = Duration::from_secs(2);
const PEER_KEYS_ATTEMPTS: u32 = 15;

fn fail(f: HistoryFailure) -> String {
    format!("history transfer refused: {}", f.as_str())
}

fn io(e: std::io::Error) -> String {
    format!("history transfer: {e}")
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
    phase: u32,
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
    uint32::encode(13, &phase, &mut m);
    m
}

/// The phase a manifest names (field 13); `None` for one that does not parse.
fn manifest_phase(mut proto: &[u8]) -> Option<u32> {
    use prost::encoding::{DecodeContext, WireType, decode_key, decode_varint, skip_field};
    let mut phase = None;
    while !proto.is_empty() {
        let (tag, wire_type) = decode_key(&mut proto).ok()?;
        if tag == 13 && wire_type == WireType::Varint {
            phase = u32::try_from(decode_varint(&mut proto).ok()?).ok();
        } else {
            skip_field(wire_type, tag, &mut proto, DecodeContext::default()).ok()?;
        }
    }
    phase
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

/// What a transfer is sealed to: the recipient's identity, hybrid and Kyber signed prekey.
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

/// What the importer checks the sender against: the directory's keys for it. A file has no QR to
/// pin it, and neither has a device this one was linked to by showing its own code (Flow B), so
/// the directory is the only pin (spec: `bundle_only`, and it is logged).
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

/// What this device sends: its transcript and the files its messages refer to.
struct Outgoing {
    records: Records,
    media: Vec<MediaFile>,
    summary: HistorySummary,
}

/// The records of a transcript in the order the protocol requires, and the files its messages
/// refer to.
fn collect(store: &LocalStore) -> Result<Outgoing, String> {
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
    Ok(Outgoing {
        records,
        media,
        summary,
    })
}

/// One phase of `out` through `sender` into `w`: the manifest, then the transcript, the files, or
/// both. Returns what it carried.
#[allow(clippy::too_many_arguments)]
async fn write_phase<W: AsyncWrite + Unpin>(
    w: &mut W,
    sender: &mut Sender,
    phase: u32,
    out: &Outgoing,
    store: &LocalStore,
    cache: &MediaCache,
    user: [u8; 16],
    own_device: &str,
) -> Result<HistorySummary, String> {
    let mut buf = Vec::with_capacity(FLUSH_AT * 2);
    let media_bytes = out.media.iter().map(|f| f.info.size).sum();
    let head = manifest(
        phase,
        sender.snapshot_id(),
        user,
        own_device,
        &out.summary,
        out.media.len(),
        media_bytes,
    );
    sender
        .push_record(rt::MANIFEST, &head, &mut buf)
        .map_err(fail)?;
    let mut carried = HistorySummary::default();
    if phase != PHASE_MEDIA {
        for (kind, record) in &out.records {
            sender.push_record(*kind, record, &mut buf).map_err(fail)?;
            flush(w, &mut buf, false).await?;
        }
        carried = HistorySummary {
            media: 0,
            media_skipped: 0,
            ..out.summary.clone()
        };
    }
    if phase != PHASE_TRANSCRIPT {
        for f in &out.media {
            let key = store.media_local_key(&f.media_id);
            match cache.plaintext(f, key.as_deref().map(|k| &k[..])) {
                Some(bytes) if (bytes.len() as u64) < history::MAX_RECORD_BYTES => {
                    sender
                        .begin_media(&f.media_id, &f.info.mime, bytes.len() as u64, &mut buf)
                        .map_err(fail)?;
                    sender.push_media(&bytes, &mut buf).map_err(fail)?;
                    carried.media += 1;
                }
                _ => carried.media_skipped += 1,
            }
            flush(w, &mut buf, false).await?;
        }
    }
    sender.finish(&mut buf).map_err(fail)?;
    flush(w, &mut buf, true).await?;
    w.flush().await.map_err(io)?;
    Ok(carried)
}

async fn flush<W: AsyncWrite + Unpin>(
    w: &mut W,
    buf: &mut Vec<u8>,
    all: bool,
) -> Result<(), String> {
    if all || buf.len() >= FLUSH_AT {
        w.write_all(buf).await.map_err(io)?;
        buf.clear();
    }
    Ok(())
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
    let out = collect(store)?;

    let partial = path.with_extension("part");
    let mut file = tokio::fs::File::create(&partial).await.map_err(io)?;
    let written = async {
        file.write_all(sender.first_frame()).await.map_err(io)?;
        let carried = write_phase(
            &mut file,
            &mut sender,
            PHASE_BOTH,
            &out,
            store,
            cache,
            user,
            own_device,
        )
        .await?;
        file.sync_all().await.map_err(io)?;
        Ok::<_, String>(carried)
    }
    .await;
    drop(file);
    match written {
        Ok(carried) => {
            tokio::fs::rename(&partial, path).await.map_err(io)?;
            Ok(carried)
        }
        Err(e) => {
            let _ = tokio::fs::remove_file(&partial).await;
            Err(e)
        }
    }
}

/// The name a transfer to `device_id` is advertised under on the local network.
fn instance_for(user_id: &str, device_id: &str) -> String {
    discovery_instance_name(&discovery_tag(
        &user_id.to_lowercase(),
        &device_id.to_lowercase(),
    ))
}

/// [`peer_keys`], asked again while the directory does not serve them yet.
async fn peer_keys_waiting(
    grpc: &GrpcClient,
    user_id: &str,
    device_id: &str,
) -> Result<PeerKeys, String> {
    let mut attempt = 1;
    loop {
        match peer_keys(grpc, user_id, device_id).await {
            Ok(keys) => return Ok(keys),
            Err(e) if attempt >= PEER_KEYS_ATTEMPTS => return Err(e),
            Err(e) => {
                tracing::info!(
                    attempt,
                    "history: the other device's keys are not served yet: {e}"
                );
                attempt += 1;
                tokio::time::sleep(PEER_KEYS_RETRY).await;
            }
        }
    }
}

/// Send this device's history to `device_id` over the local network, the way iOS does: advertise,
/// and on each of two connections send the opening, check the reply, and stream a phase — the
/// transcript, then the files.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn offer_nearby(
    orch: &OrchestratorHandle,
    grpc: &GrpcClient,
    store: &LocalStore,
    cache: &MediaCache,
    user_id: &str,
    own_device: &str,
    device_id: &str,
    step: impl Fn(NearbyStep),
) -> Result<HistorySummary, String> {
    if device_id.eq_ignore_ascii_case(own_device) {
        return Err("choose another device of the account".into());
    }
    let user = account_raw(user_id)?;
    let peer = peer_keys_waiting(grpc, user_id, device_id).await?;
    let out = collect(store)?;
    // One listener for both connections: the receiver looks the name up again for the second,
    // and finds the same port.
    let advertised = crate::nearby::advertise(&instance_for(user_id, device_id)).await?;
    let mut summary = HistorySummary::default();
    for phase in [PHASE_TRANSCRIPT, PHASE_MEDIA] {
        step(NearbyStep::Waiting);
        let mut stream = advertised.accept().await?;
        step(NearbyStep::Moving);
        let mut sender = orch.history_nearby_sender(user, peer.clone()).await?;
        stream.write_all(sender.first_frame()).await.map_err(io)?;
        let mut reply = vec![0u8; history::frames::REPLY_LEN];
        match tokio::time::timeout(REPLY_WAIT, stream.read_exact(&mut reply)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(io(e)),
            Err(_) => return Err("the other device did not answer".into()),
        }
        sender.accept_reply(&reply).map_err(fail)?;
        let carried = write_phase(
            &mut stream,
            &mut sender,
            phase,
            &out,
            store,
            cache,
            user,
            own_device,
        )
        .await?;
        let _ = stream.shutdown().await;
        tracing::info!(phase, ?carried, "history phase sent");
        if phase == PHASE_TRANSCRIPT {
            summary = carried;
        } else {
            summary.media = carried.media;
            summary.media_skipped = carried.media_skipped;
        }
    }
    Ok(summary)
}

/// What a transfer brought in: its summary, the accounts it named, and why it stopped short, if
/// it did — a cut second phase keeps the first.
pub(crate) type Landed = (HistorySummary, Vec<String>, Option<String>);

/// Wait for another device of the account to offer history to this one over the local network —
/// it is advertised under the name both compute for this device — and import a phase per
/// connection until the files are in (or it sends everything at once, or declines). The person
/// chose to send on that device; here it is taken without asking again, since the core admits
/// only a device of this account that signs for itself, and an import only adds.
///
/// `Err` when nothing was received: the network was not usable, or the offer went away before it
/// could be taken. Nothing to tell the person.
pub(crate) async fn receive_nearby(
    orch: &OrchestratorHandle,
    grpc: &GrpcClient,
    store: &LocalStore,
    cache: &MediaCache,
    user_id: &str,
    own_device: &str,
    step: impl Fn(NearbyStep),
) -> Result<Landed, String> {
    let instance = instance_for(user_id, own_device);
    let user = account_raw(user_id)?;
    let first = crate::nearby::connect(&instance, None).await?;
    step(NearbyStep::Receiving);
    let mut importer = Importer::new(store, cache);
    let mut stream = Some(first);
    loop {
        let received = async {
            let stream = match stream.take() {
                Some(stream) => stream,
                None => crate::nearby::connect(&instance, Some(MEDIA_PHASE_WAIT))
                    .await
                    .map_err(|e| format!("the files did not follow: {e}"))?,
            };
            receive_stream(
                stream,
                Source::Nearby,
                orch,
                grpc,
                user_id,
                user,
                &mut importer,
            )
            .await
        }
        .await;
        let landed = |e| Ok((importer.summary.clone(), importer.contacts.clone(), e));
        match received {
            Ok(Received::Phase(PHASE_TRANSCRIPT)) => continue,
            Ok(Received::Phase(_)) => return landed(None),
            Ok(Received::Skipped) => {
                step(NearbyStep::Skipped);
                return landed(None);
            }
            Err(e) => return landed(Some(e)),
        }
    }
}

/// How a stream ended.
enum Received {
    /// It carried this phase, all of it.
    Phase(u32),
    /// The sending device declined.
    Skipped,
}

/// Read one stream — a file, or a connection — into the store through `importer`. On a
/// connection the reply to the opening is written back on it.
async fn receive_stream<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    source: Source,
    orch: &OrchestratorHandle,
    grpc: &GrpcClient,
    user_id: &str,
    user: [u8; 16],
    importer: &mut Importer<'_>,
) -> Result<Received, String> {
    let mut receiver = Receiver::new(source, user);
    let mut buf = Vec::new();
    importer.phase = None;
    loop {
        let need = receiver.need();
        buf.resize(need, 0);
        let n = read_up_to(&mut stream, &mut buf).await?;
        if n == 0 && need > 0 {
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
                tracing::info!(device = %short(&sender), "history: sender pinned by the directory only");
                let (back, accepted) = orch
                    .history_accept(Box::new(receiver), known, Pin::BundleOnly)
                    .await?;
                receiver = *back;
                if let Some(reply) = accepted.map_err(fail)? {
                    stream.write_all(&reply).await.map_err(io)?;
                    stream.flush().await.map_err(io)?;
                }
            }
            Status::Done => break,
            Status::Skipped => return Ok(Received::Skipped),
        }
    }
    Ok(Received::Phase(importer.phase.unwrap_or(PHASE_BOTH)))
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
    let file = tokio::fs::File::open(path).await.map_err(io)?;
    let mut importer = Importer::new(store, cache);
    // A file has nothing to answer: writes to it are never made.
    let stream = tokio::io::join(file, tokio::io::sink());
    match receive_stream(
        stream,
        Source::File,
        orch,
        grpc,
        user_id,
        user,
        &mut importer,
    )
    .await?
    {
        Received::Skipped => Err("the file holds no history".into()),
        Received::Phase(_) => Ok((importer.summary, importer.contacts)),
    }
}

/// Read until `buf` is full or the input ends; how much was read.
async fn read_up_to<R: AsyncRead + Unpin>(r: &mut R, buf: &mut [u8]) -> Result<usize, String> {
    let mut at = 0;
    while at < buf.len() {
        match r.read(&mut buf[at..]).await.map_err(io)? {
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
    /// The phase the current stream's manifest names.
    phase: Option<u32>,
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
            phase: None,
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
            // The manifest is the core's to check; what it says is next is ours.
            rt::MANIFEST => self.phase = manifest_phase(proto),
            // A call this client has nowhere to show.
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
            PHASE_TRANSCRIPT,
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
        assert_eq!(manifest_phase(&m), Some(PHASE_TRANSCRIPT));
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
