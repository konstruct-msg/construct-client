//! `StickerService`: packs by their hash, whole, as iOS fetches them (`StickerPackFetcher`).
//! Called on the client that holds no token; nothing about a pack is secret, and the server
//! should not learn which account wanted which pack.

use prost::Message;

use crate::proto::messaging::v1::StickerPackManifest;
use crate::proto::services::v1::{
    GetStickerPackBlobsRequest, GetStickerPackBlobsResponse, GetStickerPackManifestRequest,
    GetStickerPackManifestResponse, ListStickerPacksRequest, ListStickerPacksResponse,
};

use super::client::GrpcClient;
use super::error::GrpcError;
use super::paths;

/// `GetStickerPackManifest`; `None` when the server sends no manifest.
pub async fn sticker_manifest(
    client: &GrpcClient,
    request: &GetStickerPackManifestRequest,
) -> Result<Option<StickerPackManifest>, GrpcError> {
    let bytes = client
        .unary(paths::STICKER_MANIFEST, &request.encode_to_vec())
        .await?;
    let resp = GetStickerPackManifestResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("GetStickerPackManifest decode: {e}")))?;
    Ok(resp.manifest)
}

/// `GetStickerPackBlobs`: each sticker the request does not say it has, to `on_blob` as
/// `(sha256, bytes)`; an error from it ends the call.
pub async fn sticker_pack_blobs(
    client: &GrpcClient,
    request: &GetStickerPackBlobsRequest,
    mut on_blob: impl FnMut(&[u8], &[u8]) -> Result<(), String>,
) -> Result<(), GrpcError> {
    super::media::server_streaming(
        client,
        paths::STICKER_PACK_BLOBS,
        &request.encode_to_vec(),
        false,
        |message| {
            let blob = GetStickerPackBlobsResponse::decode(message)
                .map_err(|e| GrpcError::transport(format!("GetStickerPackBlobs decode: {e}")))?;
            on_blob(&blob.sha256, &blob.data).map_err(GrpcError::transport)
        },
    )
    .await
}

/// `ListStickerPacks`, one page.
pub async fn sticker_packs(
    client: &GrpcClient,
    request: &ListStickerPacksRequest,
) -> Result<ListStickerPacksResponse, GrpcError> {
    let bytes = client
        .unary(paths::STICKER_LIST_PACKS, &request.encode_to_vec())
        .await?;
    ListStickerPacksResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("ListStickerPacks decode: {e}")))
}
