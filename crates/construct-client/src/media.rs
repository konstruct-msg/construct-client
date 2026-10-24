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

    /// Every blob, for a sign-out.
    pub fn wipe(dir: &Path) -> std::io::Result<()> {
        match std::fs::remove_dir_all(dir) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
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
