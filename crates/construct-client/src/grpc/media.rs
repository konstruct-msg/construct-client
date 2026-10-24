//! `MediaService`: an attachment's encrypted blob, uploaded and fetched by its id.
//!
//! Downloads go on the client that never holds a token, as iOS does (`MediaServiceClient`): the
//! server serves a blob to anyone holding its id, and over the signed-in connection every download
//! would tell it which account fetched whose attachment. Uploads go signed in, as iOS's do: the
//! server hands out upload tokens to accounts only. It learns that this account uploaded a blob of
//! a padded size, and not what it is or for whom.

use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http::Request;
use prost::Message;

use crate::proto::services::v1::{
    DownloadMediaRequest, DownloadMediaResponse, GenerateUploadTokenRequest,
    GenerateUploadTokenResponse, UploadMediaRequest, UploadMediaResponse,
};

use super::client::{GrpcClient, apply_auth_headers, check_grpc_status, send_h2_data};
use super::error::GrpcError;
use super::framing::encode_frame;
use super::paths::{MEDIA_DOWNLOAD, MEDIA_UPLOAD, MEDIA_UPLOAD_TOKEN};

/// Each upload message carries this much of the blob, as on iOS.
const UPLOAD_CHUNK: usize = 64 * 1024;

/// A blob on the server: its id, and the address iOS puts in `file_url`.
#[derive(Debug, Clone)]
pub struct Uploaded {
    pub media_id: String,
    pub download_url: String,
}

/// Upload a sealed blob; `sha256` is its hash, which the server checks the upload against.
pub async fn upload_media(
    client: &GrpcClient,
    blob: &[u8],
    sha256: &[u8],
) -> Result<Uploaded, GrpcError> {
    // No content type: a MIME type beside a padded size would name what the padding hides.
    let token = client
        .unary(
            MEDIA_UPLOAD_TOKEN,
            &GenerateUploadTokenRequest {
                expected_size: Some(blob.len() as i64),
                content_type: None,
            }
            .encode_to_vec(),
        )
        .await?;
    let token = GenerateUploadTokenResponse::decode(token.as_slice())
        .map_err(|e| GrpcError::transport(format!("GenerateUploadToken decode: {e}")))?
        .upload_token;

    let mut send_req = client.send_request_handle().await?;
    let (bearer, device_id) = client.auth_headers();
    let builder = Request::builder()
        .method("POST")
        .uri(MEDIA_UPLOAD)
        .header("host", client.authority());
    let req = apply_auth_headers(builder, bearer.as_deref(), device_id.as_deref())
        .body(())
        .map_err(|e| GrpcError::transport(format!("build request: {e}")))?;
    let (resp_fut, mut send) = send_req
        .send_request(req, false)
        .map_err(|e| GrpcError::transport(format!("UploadMedia: {e}")))?;
    let file_hash = hex::encode(sha256);
    let chunks: Vec<&[u8]> = blob.chunks(UPLOAD_CHUNK).collect();
    for (n, chunk) in chunks.iter().enumerate() {
        let message = UploadMediaRequest {
            upload_token: Some(token.clone()),
            chunk: Bytes::copy_from_slice(chunk),
            chunk_number: n as i32,
            is_last: n + 1 == chunks.len(),
            total_size: Some(blob.len() as i64),
            file_hash: Some(file_hash.clone()),
        };
        tokio::time::timeout(
            IDLE_TIMEOUT,
            send_h2_data(&mut send, encode_frame(&message.encode_to_vec())),
        )
        .await
        .map_err(|_| GrpcError::transport("UploadMedia stalled"))??;
    }
    send.send_data(Bytes::new(), true)
        .map_err(|e| GrpcError::transport(format!("end stream: {e}")))?;

    let response = tokio::time::timeout(IDLE_TIMEOUT, resp_fut)
        .await
        .map_err(|_| GrpcError::transport("UploadMedia timed out"))?
        .map_err(|e| GrpcError::transport(format!("UploadMedia response: {e}")))?;
    if response.status() != http::StatusCode::OK {
        return Err(GrpcError::transport(format!(
            "UploadMedia HTTP {}",
            response.status()
        )));
    }
    check_grpc_status(response.headers())?;
    let mut recv = response.into_body();
    let mut frames = BytesMut::new();
    while let Some(chunk) = tokio::time::timeout(IDLE_TIMEOUT, recv.data())
        .await
        .map_err(|_| GrpcError::transport("UploadMedia stalled"))?
    {
        let chunk = chunk.map_err(|e| GrpcError::transport(format!("recv: {e}")))?;
        let _ = recv.flow_control().release_capacity(chunk.len());
        frames.extend_from_slice(&chunk);
    }
    if let Ok(Some(trailers)) = recv.trailers().await {
        check_grpc_status(&trailers)?;
    }
    let message = take_messages(&mut frames)?
        .into_iter()
        .next()
        .ok_or_else(|| GrpcError::transport("UploadMedia: no response"))?;
    let response = UploadMediaResponse::decode(message)
        .map_err(|e| GrpcError::transport(format!("UploadMedia decode: {e}")))?;
    if !crate::content::valid_media_id(&response.media_id) {
        return Err(GrpcError::transport("UploadMedia: no usable media id"));
    }
    Ok(Uploaded {
        media_id: response.media_id,
        download_url: response.download_url,
    })
}

/// No byte for this long and the download is given up. Not a limit on the whole download: a
/// large file on a slow link takes as long as it takes.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// The blob of `media_id`, whole. Fails once it grows past `max_len`, the largest blob the core
/// opens, so a server cannot fill the memory.
pub async fn download_media(
    anonymous: &GrpcClient,
    media_id: &str,
    max_len: usize,
) -> Result<Vec<u8>, GrpcError> {
    let request = DownloadMediaRequest {
        media_id: media_id.to_owned(),
        ..Default::default()
    };
    let mut blob = Vec::new();
    server_streaming(
        anonymous,
        MEDIA_DOWNLOAD,
        &request.encode_to_vec(),
        false,
        |message| {
            let part = DownloadMediaResponse::decode(message)
                .map_err(|e| GrpcError::transport(format!("DownloadMedia decode: {e}")))?;
            if blob.len() + part.chunk.len() > max_len {
                return Err(GrpcError::transport("DownloadMedia: larger than any media"));
            }
            blob.extend_from_slice(&part.chunk);
            Ok(())
        },
    )
    .await?;
    Ok(blob)
}

/// A server-streaming call: one request, then each response message to `on_message` as it
/// arrives. `signed_in`: with the client's token, else with none at all.
pub(crate) async fn server_streaming(
    client: &GrpcClient,
    path: &str,
    request: &[u8],
    signed_in: bool,
    mut on_message: impl FnMut(Bytes) -> Result<(), GrpcError>,
) -> Result<(), GrpcError> {
    let mut send_req = client.send_request_handle().await?;
    let (token, device_id) = if signed_in {
        client.auth_headers()
    } else {
        (None, None)
    };
    let builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("host", client.authority());
    let req = apply_auth_headers(builder, token.as_deref(), device_id.as_deref())
        .body(())
        .map_err(|e| GrpcError::transport(format!("build request: {e}")))?;
    let (resp_fut, mut send) = send_req
        .send_request(req, false)
        .map_err(|e| GrpcError::transport(format!("'{path}': {e}")))?;
    send_h2_data(&mut send, encode_frame(request)).await?;
    send.send_data(Bytes::new(), true)
        .map_err(|e| GrpcError::transport(format!("end stream: {e}")))?;

    let response = tokio::time::timeout(IDLE_TIMEOUT, resp_fut)
        .await
        .map_err(|_| GrpcError::transport(format!("'{path}' timed out")))?
        .map_err(|e| GrpcError::transport(format!("'{path}' response: {e}")))?;
    if response.status() != http::StatusCode::OK {
        return Err(GrpcError::transport(format!(
            "'{path}' HTTP {}",
            response.status()
        )));
    }
    check_grpc_status(response.headers())?;

    let mut recv = response.into_body();
    let mut frames = BytesMut::new();
    loop {
        let chunk = match tokio::time::timeout(IDLE_TIMEOUT, recv.data()).await {
            Err(_) => return Err(GrpcError::transport(format!("'{path}' stalled"))),
            Ok(None) => break,
            Ok(Some(chunk)) => chunk.map_err(|e| GrpcError::transport(format!("recv: {e}")))?,
        };
        let _ = recv.flow_control().release_capacity(chunk.len());
        frames.extend_from_slice(&chunk);
        for message in take_messages(&mut frames)? {
            on_message(message)?;
        }
    }
    if let Ok(Some(trailers)) = recv.trailers().await {
        check_grpc_status(&trailers)?;
    }
    if !frames.is_empty() {
        return Err(GrpcError::transport(format!(
            "'{path}': cut off mid-message"
        )));
    }
    Ok(())
}

/// The whole gRPC messages at the front of `buf`, taken out of it; a partial one stays.
fn take_messages(buf: &mut BytesMut) -> Result<Vec<Bytes>, GrpcError> {
    let mut messages = Vec::new();
    while buf.len() >= 5 {
        if buf[0] != 0 {
            return Err(GrpcError::transport("compressed gRPC message"));
        }
        let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
        if buf.len() < 5 + len {
            break;
        }
        let frame = buf.split_to(5 + len).freeze();
        messages.push(frame.slice(5..));
    }
    Ok(messages)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_split_across_reads_are_taken_whole() {
        let a = encode_frame(b"first");
        let b = encode_frame(b"second");
        let mut wire = BytesMut::new();
        wire.extend_from_slice(&a);
        // Its header whole, its body not yet.
        wire.extend_from_slice(&b[..8]);
        let taken = take_messages(&mut wire).unwrap();
        assert_eq!(taken, vec![Bytes::from_static(b"first")]);
        assert_eq!(wire.len(), 8, "the partial message waits");

        wire.extend_from_slice(&b[8..]);
        let taken = take_messages(&mut wire).unwrap();
        assert_eq!(taken, vec![Bytes::from_static(b"second")]);
        assert!(wire.is_empty());
    }
}
