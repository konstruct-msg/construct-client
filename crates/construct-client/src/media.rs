//! Attachments: a file a message carries, fetched from the server and opened.
//!
//! The blob is fetched on the client that never holds a token (`grpc::download_media`) and kept
//! on disk as it came, encrypted, under its media id: without the key in the message — which
//! stays in the store — the cache reads as noise. The core opens it (`open_media`), so what was
//! substituted on the server or on disk fails to open instead of being shown.

use std::path::{Path, PathBuf};

use crate::content::MediaFile;
use crate::grpc::GrpcClient;

/// A file, opened: what a front end shows or saves.
#[derive(Debug, Clone)]
pub struct OpenedMedia {
    pub mime: String,
    pub filename: Option<String>,
    pub bytes: Vec<u8>,
}

/// The encrypted blobs fetched so far, one file per media id.
#[derive(Debug, Clone)]
pub struct MediaCache {
    dir: PathBuf,
}

impl MediaCache {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn path(&self, media_id: &str) -> Option<PathBuf> {
        crate::content::valid_media_id(media_id).then(|| self.dir.join(media_id))
    }

    fn load(&self, media_id: &str) -> Option<Vec<u8>> {
        std::fs::read(self.path(media_id)?).ok()
    }

    /// Written aside and renamed into place, so a crash never leaves half a blob under the id.
    fn save(&self, media_id: &str, blob: &[u8]) -> std::io::Result<()> {
        let Some(path) = self.path(media_id) else {
            return Ok(());
        };
        std::fs::create_dir_all(&self.dir)?;
        let partial = self.dir.join(format!(".{media_id}.part"));
        std::fs::write(&partial, blob)?;
        std::fs::rename(&partial, path)
    }

    fn forget(&self, media_id: &str) {
        if let Some(path) = self.path(media_id) {
            let _ = std::fs::remove_file(path);
        }
    }

    /// Every blob kept: its id, size and age since it was fetched (its file's mtime: a blob is
    /// written once, when it comes from the server, and never touched again).
    fn entries(&self) -> Vec<(PathBuf, u64, std::time::Duration)> {
        let Ok(dir) = std::fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        let now = std::time::SystemTime::now();
        dir.flatten()
            .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
            .filter_map(|e| {
                let meta = e.metadata().ok().filter(|m| m.is_file())?;
                let age = meta
                    .modified()
                    .ok()
                    .and_then(|t| now.duration_since(t).ok())
                    .unwrap_or_default();
                Some((e.path(), meta.len(), age))
            })
            .collect()
    }

    /// Bytes on disk and how many files.
    pub fn usage(&self) -> (u64, usize) {
        let entries = self.entries();
        (entries.iter().map(|e| e.1).sum(), entries.len())
    }

    /// Delete every blob, the only copies among them too: the person asked.
    pub fn clear(&self) -> std::io::Result<()> {
        Self::wipe(&self.dir)
    }

    /// Bring the cache within the person's settings: blobs older than `keep_days` go (their
    /// choice, so the only copies too), then, over `quota`, only blobs the server may still hold.
    pub fn evict(&self, quota: Option<u64>, keep_days: Option<u32>) {
        let mut entries = self.entries();
        if let Some(days) = keep_days.filter(|d| *d > 0) {
            let cutoff = std::time::Duration::from_secs(u64::from(days) * 86_400);
            entries.retain(|(path, _, age)| {
                let keep = *age < cutoff;
                if !keep {
                    let _ = std::fs::remove_file(path);
                }
                keep
            });
        }
        if let Some(quota) = quota.filter(|q| *q > 0) {
            for i in files_to_evict(&entries, quota) {
                let _ = std::fs::remove_file(&entries[i].0);
            }
        }
    }

    /// Every blob, for a sign-out.
    pub fn wipe(dir: &Path) -> std::io::Result<()> {
        match std::fs::remove_dir_all(dir) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }
}

/// How long the server keeps an upload, from upload; a download does not extend it (media-service
/// `MEDIA_FILE_TTL_SECONDS`). Too large here deletes photos that exist nowhere else.
pub const SERVER_RETENTION: std::time::Duration = std::time::Duration::from_secs(7 * 86_400);

/// Which blobs to delete, in order, to bring the cache under `quota` (iOS `MediaEvictionPolicy`).
///
/// Only one fetched less than [`SERVER_RETENTION`] ago may go: it was on the server when fetched,
/// so it may still be. One fetched earlier is certainly gone there, and this is the only copy.
/// Oldest of the evictable first; when they are not enough the cache stays over its quota — a full
/// disk shows, a missing photo does not.
fn files_to_evict(entries: &[(PathBuf, u64, std::time::Duration)], quota: u64) -> Vec<usize> {
    let mut total: u64 = entries.iter().map(|e| e.1).sum();
    let mut evictable: Vec<usize> = (0..entries.len())
        .filter(|&i| entries[i].2 < SERVER_RETENTION)
        .collect();
    evictable.sort_by_key(|&i| std::cmp::Reverse(entries[i].2));
    let mut doomed = Vec::new();
    for i in evictable {
        if total <= quota {
            break;
        }
        total = total.saturating_sub(entries[i].1);
        doomed.push(i);
    }
    doomed
}

/// Whether a file is fetched as its message arrives (iOS `media.autoDownload`). The server's copy
/// lasts a week from upload, so a file left for later may be gone when its chat is opened
/// (decisions/media-fetch-on-arrival.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AutoDownload {
    Never,
    /// Up to [`AUTO_DOWNLOAD_CEILING`]: iOS's Wi-Fi rule, for a desktop that cannot tell a
    /// metered network.
    #[default]
    Small,
    Always,
}

/// Larger files are fetched when shown (iOS: 16 MB).
pub const AUTO_DOWNLOAD_CEILING: u64 = 16 * 1024 * 1024;

impl AutoDownload {
    pub fn allows(self, info: &crate::content::MediaInfo) -> bool {
        match self {
            Self::Never => false,
            Self::Small => info.size <= AUTO_DOWNLOAD_CEILING,
            Self::Always => true,
        }
    }

    pub fn to_byte(self) -> u8 {
        match self {
            Self::Never => 0,
            Self::Small => 1,
            Self::Always => 2,
        }
    }

    pub fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::Never,
            2 => Self::Always,
            _ => Self::Small,
        }
    }
}

/// Fetch into the cache the files a message just brought, as `policy` allows; each is opened
/// first, so what does not open is not kept.
pub async fn prefetch(
    cache: &MediaCache,
    anonymous: &GrpcClient,
    files: Vec<MediaFile>,
    policy: AutoDownload,
) {
    for file in files.into_iter().filter(|f| policy.allows(&f.info)) {
        if cache.load(&file.media_id).is_some() {
            continue;
        }
        match open(cache, anonymous, &file).await {
            Ok(_) => tracing::info!("media {} fetched on arrival", file.media_id),
            Err(e) => tracing::warn!("media {} not fetched on arrival: {e}", file.media_id),
        }
    }
}

/// `file`, opened: from the cache, or fetched and then cached. A blob that does not open is not
/// kept, so the next try fetches it again.
pub async fn open(
    cache: &MediaCache,
    anonymous: &GrpcClient,
    file: &MediaFile,
) -> Result<OpenedMedia, String> {
    let opened = |blob: &[u8]| {
        construct_core::media::open_media(&file.key, blob).map(|bytes| OpenedMedia {
            mime: file.info.mime.clone(),
            filename: file.info.filename.clone(),
            bytes,
        })
    };
    if let Some(blob) = cache.load(&file.media_id) {
        match opened(&blob) {
            Ok(media) => return Ok(media),
            Err(e) => {
                tracing::warn!("cached media did not open, fetching again: {e}");
                cache.forget(&file.media_id);
            }
        }
    }
    let max_len = construct_core::media::MEDIA_MAX_BLOB_LEN as usize;
    let blob = crate::grpc::download_media(anonymous, &file.media_id, max_len)
        .await
        .map_err(|e| {
            if matches!(&e, crate::grpc::GrpcError::Status { code: 5, .. }) {
                "the file is no longer on the server".to_string()
            } else {
                e.to_string()
            }
        })?;
    let media = opened(&blob).map_err(|e| format!("the file did not open: {e}"))?;
    if let Err(e) = cache.save(&file.media_id, &blob) {
        tracing::warn!("media not cached: {e}");
    }
    Ok(media)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_cache() -> (PathBuf, MediaCache) {
        let dir = std::env::temp_dir().join(format!("construct-media-{}", uuid::Uuid::new_v4()));
        (dir.clone(), MediaCache::new(dir))
    }

    fn file_for(media_id: &str, key: &[u8]) -> MediaFile {
        MediaFile {
            media_id: media_id.into(),
            key: zeroize::Zeroizing::new(key.to_vec()),
            info: crate::content::MediaInfo {
                mime: "image/png".into(),
                ..Default::default()
            },
        }
    }

    /// Nothing listens there: a fetch fails at once.
    fn offline() -> GrpcClient {
        GrpcClient::new("http://localhost:9")
    }

    #[tokio::test]
    async fn a_cached_blob_opens_with_the_key_from_the_message() {
        let (dir, cache) = temp_cache();
        let sealed = construct_core::media::seal_media(b"the picture").unwrap();
        cache.save("m1", &sealed.blob).unwrap();
        let media = open(&cache, &offline(), &file_for("m1", &sealed.key))
            .await
            .unwrap();
        assert_eq!(media.bytes, b"the picture");
        assert_eq!(media.mime, "image/png");
        MediaCache::wipe(&dir).unwrap();
    }

    #[tokio::test]
    async fn a_cached_blob_that_does_not_open_is_dropped() {
        let (dir, cache) = temp_cache();
        let sealed = construct_core::media::seal_media(b"the picture").unwrap();
        let mut blob = sealed.blob.clone();
        let last = blob.len() - 1;
        blob[last] ^= 1;
        cache.save("m1", &blob).unwrap();
        let result = open(&cache, &offline(), &file_for("m1", &sealed.key)).await;
        assert!(result.is_err(), "a changed blob is never shown");
        assert_eq!(cache.load("m1"), None, "and not kept for the next try");
        MediaCache::wipe(&dir).unwrap();
    }

    fn entry(age_days: u64, bytes: u64) -> (PathBuf, u64, std::time::Duration) {
        let age = std::time::Duration::from_secs(age_days * 86_400 + 60);
        (PathBuf::from(format!("{age_days}")), bytes, age)
    }

    #[test]
    fn over_the_quota_only_what_the_server_may_still_hold_goes() {
        // 10 days and 8 days old: past the server's week, the only copies.
        let entries = [entry(10, 100), entry(8, 100), entry(5, 100), entry(1, 100)];
        assert_eq!(
            files_to_evict(&entries, 250),
            vec![2, 3],
            "oldest evictable first"
        );
        assert_eq!(files_to_evict(&entries, 350), vec![2]);
        assert_eq!(
            files_to_evict(&entries, 50),
            vec![2, 3],
            "the only copies stay, over the quota"
        );
        assert!(files_to_evict(&entries, 400).is_empty());
    }

    #[test]
    fn small_files_are_fetched_on_arrival_by_default() {
        let info = |size| crate::content::MediaInfo {
            size,
            ..Default::default()
        };
        let policy = AutoDownload::default();
        assert!(policy.allows(&info(AUTO_DOWNLOAD_CEILING)));
        assert!(!policy.allows(&info(AUTO_DOWNLOAD_CEILING + 1)));
        assert!(AutoDownload::Always.allows(&info(u64::MAX)));
        assert!(!AutoDownload::Never.allows(&info(1)));
        for p in [
            AutoDownload::Never,
            AutoDownload::Small,
            AutoDownload::Always,
        ] {
            assert_eq!(AutoDownload::from_byte(p.to_byte()), p);
        }
    }

    #[test]
    fn a_cache_reports_its_size_and_clears() {
        let (dir, cache) = temp_cache();
        cache.save("a", b"12345").unwrap();
        cache.save("b", b"123").unwrap();
        assert_eq!(cache.usage(), (8, 2));
        cache.evict(Some(1), None);
        assert_eq!(
            cache.usage(),
            (0, 0),
            "fresh blobs may go to meet the quota"
        );
        cache.save("c", b"1").unwrap();
        cache.clear().unwrap();
        assert_eq!(cache.usage(), (0, 0));
        MediaCache::wipe(&dir).unwrap();
    }

    #[test]
    fn a_cached_blob_is_found_by_its_id_only() {
        let (dir, cache) = temp_cache();
        cache.save("abc-1", b"blob").unwrap();
        assert_eq!(cache.load("abc-1").as_deref(), Some(&b"blob"[..]));
        assert_eq!(cache.load("abc-2"), None);
        assert_eq!(cache.path("../store"), None, "an id is never a path");
        cache.forget("abc-1");
        assert_eq!(cache.load("abc-1"), None);
        MediaCache::wipe(&dir).unwrap();
        assert!(!dir.exists());
    }
}
