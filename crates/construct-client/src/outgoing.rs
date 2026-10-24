//! A file the person sends, made ready: a photo without what it says about where and with what
//! it was taken, anything else as it is.
//!
//! A photo's metadata — EXIF with the GPS position, the camera and the time, XMP, comments, the
//! thumbnail inside EXIF, a phone's extra pictures after the image — is dropped before the file
//! is sealed, as iOS does (`ImageMetadataStripper`), keeping only the orientation, so the photo
//! is not shown on its side. A JPEG or PNG that does not read as one is sent as a file, unchanged:
//! the person chose to send that file, and a file is what iOS sends unchanged too
//! (`MediaManager.uploadFile`).

use crate::content::Attachment;

/// What goes on the wire for one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    pub kind: Attachment,
    pub mime: String,
    pub filename: Option<String>,
    pub bytes: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

/// `bytes`, named `name` by the person's system, made ready to send.
pub fn prepare(name: &str, bytes: Vec<u8>) -> Outgoing {
    let filename = crate::content::safe_filename(name);
    let photo = if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        strip_jpeg(&bytes).map(|p| ("image/jpeg", p))
    } else if bytes.starts_with(PNG_SIGNATURE) {
        strip_png(&bytes).map(|p| ("image/png", p))
    } else {
        None
    };
    match photo {
        Some((mime, photo)) => Outgoing {
            kind: Attachment::Photo,
            mime: mime.into(),
            filename,
            bytes: photo.bytes,
            width: photo.width,
            height: photo.height,
        },
        None => Outgoing {
            kind: Attachment::File,
            mime: mime_by_extension(name).into(),
            filename,
            bytes,
            width: 0,
            height: 0,
        },
    }
}

/// The `MessageContent` of `file`, sealed and uploaded: an album of one, as iOS sends photos and
/// files (`MediaWireCodec.albumContent`). No thumbnail: the receiver fetches the file.
pub(crate) fn content(
    file: &Outgoing,
    uploaded: &crate::grpc::Uploaded,
    sealed: &construct_core::media::SealedMedia,
    caption: &str,
    quote: Option<&crate::content::Quote>,
) -> Vec<u8> {
    use crate::proto::messaging::v1::{
        MediaAlbumMessage, MediaDimensions, MediaMessage, MediaType, MessageContent, QuotedMessage,
        message_content,
    };
    use prost::Message;
    let item = MediaMessage {
        // As iOS types an item by its MIME type (`protoMediaType`), except a picture that kept its
        // metadata: that goes as a file, never shown as a photo.
        media_type: match file.kind {
            Attachment::Photo => MediaType::Image,
            _ if file.mime.starts_with("audio/") => MediaType::Audio,
            _ if file.mime.starts_with("video/") => MediaType::Video,
            _ => MediaType::File,
        } as i32,
        file_url: uploaded.download_url.clone(),
        encryption_key: sealed.key.clone().into(),
        file_hash: sealed.sha256.clone().into(),
        file_size: file.bytes.len() as u64,
        mime_type: file.mime.clone(),
        filename: file.filename.clone(),
        dimensions: (file.width > 0 && file.height > 0).then_some(MediaDimensions {
            width: file.width,
            height: file.height,
        }),
        media_id: uploaded.media_id.clone(),
        ..Default::default()
    };
    MessageContent {
        content: Some(message_content::Content::MediaAlbum(MediaAlbumMessage {
            items: vec![item],
            caption: (!caption.is_empty()).then(|| caption.to_owned()),
            quoted: quote.map(|q| QuotedMessage {
                message_id: q.message_id.clone(),
                text_preview: Some(
                    q.preview
                        .chars()
                        .take(crate::content::QUOTE_PREVIEW_CHARS)
                        .collect(),
                ),
                ..Default::default()
            }),
        })),
        ..Default::default()
    }
    .encode_to_vec()
}

/// A picture with its metadata gone, and its size as shown.
#[derive(Debug, PartialEq, Eq)]
struct Photo {
    bytes: Vec<u8>,
    width: u32,
    height: u32,
}

const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";

/// PNG chunks that draw the picture. Everything else — text, EXIF, time — is dropped.
const PNG_KEPT: &[&[u8; 4]] = &[
    b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"gAMA", b"cHRM", b"sRGB", b"iCCP", b"sBIT",
    b"pHYs", b"bKGD", b"acTL", b"fcTL", b"fdAT",
];

fn strip_png(bytes: &[u8]) -> Option<Photo> {
    let mut out = PNG_SIGNATURE.to_vec();
    let mut at = PNG_SIGNATURE.len();
    let (mut width, mut height) = (0, 0);
    loop {
        let len = u32::from_be_bytes(bytes.get(at..at + 4)?.try_into().ok()?) as usize;
        let kind: &[u8; 4] = bytes.get(at + 4..at + 8)?.try_into().ok()?;
        let chunk = bytes.get(at..at.checked_add(12 + len)?)?;
        if kind == b"IHDR" {
            width = u32::from_be_bytes(chunk.get(8..12)?.try_into().ok()?);
            height = u32::from_be_bytes(chunk.get(12..16)?.try_into().ok()?);
        }
        if PNG_KEPT.contains(&kind) {
            out.extend_from_slice(chunk);
        }
        at += chunk.len();
        // Whatever follows the end is not the picture.
        if kind == b"IEND" {
            return (width > 0 && height > 0).then_some(Photo {
                bytes: out,
                width,
                height,
            });
        }
    }
}

fn strip_jpeg(bytes: &[u8]) -> Option<Photo> {
    let mut out = vec![0xFF, 0xD8];
    let mut at = 2;
    let mut orientation = 1u16;
    let (mut width, mut height) = (0u32, 0u32);
    // Segments up to the first scan; after it, the image data.
    loop {
        if *bytes.get(at)? != 0xFF {
            return None;
        }
        let marker = *bytes.get(at + 1)?;
        match marker {
            0xFF => {
                at += 1;
                continue;
            }
            0x01 | 0xD0..=0xD7 => {
                out.extend_from_slice(&bytes[at..at + 2]);
                at += 2;
                continue;
            }
            0xDA => break,
            0xD9 => return None,
            _ => {}
        }
        let len = usize::from(u16::from_be_bytes(
            bytes.get(at + 2..at + 4)?.try_into().ok()?,
        ));
        let segment = bytes.get(at..at.checked_add(2 + len)?)?;
        let body = segment.get(4..)?;
        let keep = match marker {
            0xE1 => {
                if let Some(rest) = body.strip_prefix(b"Exif\0\0") {
                    orientation = exif_orientation(rest).unwrap_or(orientation);
                }
                false
            }
            // An ICC profile draws the colours; any other APP2 (a phone's extra pictures) goes.
            0xE2 => body.starts_with(b"ICC_PROFILE\0"),
            0xE3..=0xEF | 0xFE => false,
            0xC0..=0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF => {
                height = u32::from(u16::from_be_bytes(body.get(1..3)?.try_into().ok()?));
                width = u32::from(u16::from_be_bytes(body.get(3..5)?.try_into().ok()?));
                true
            }
            _ => true,
        };
        if keep {
            out.extend_from_slice(segment);
        }
        at += segment.len();
    }
    // The scans, up to the end of the image. In the image data a 0xFF is followed by 0x00
    // (stuffing) or a restart marker; anything else is a marker: the end of the image, or a
    // segment between the scans of a progressive JPEG, copied whole. What follows the end — a
    // second picture, a vendor trailer — is dropped.
    loop {
        let marker_at = at
            + bytes
                .get(at..)?
                .windows(2)
                .position(|w| w[0] == 0xFF && !matches!(w[1], 0x00 | 0xD0..=0xD7 | 0xFF))?;
        out.extend_from_slice(&bytes[at..marker_at]);
        at = marker_at;
        match bytes[at + 1] {
            0xD9 => {
                out.extend_from_slice(&[0xFF, 0xD9]);
                break;
            }
            marker => {
                let len = usize::from(u16::from_be_bytes(
                    bytes.get(at + 2..at + 4)?.try_into().ok()?,
                ));
                let segment = bytes.get(at..at.checked_add(2 + len)?)?;
                if !matches!(marker, 0xE1..=0xEF | 0xFE) {
                    out.extend_from_slice(segment);
                }
                at += segment.len();
            }
        }
    }
    if width == 0 || height == 0 {
        return None;
    }
    if (2..=8).contains(&orientation) {
        // After SOI and a JFIF APP0, if there is one.
        let insert = if out.get(2..4) == Some(&[0xFF, 0xE0]) {
            4 + usize::from(u16::from_be_bytes([out[4], out[5]]))
        } else {
            2
        };
        out.splice(insert..insert, orientation_exif(orientation));
    }
    // Turned a quarter, the picture is shown the other way round.
    if (5..=8).contains(&orientation) {
        std::mem::swap(&mut width, &mut height);
    }
    Some(Photo {
        bytes: out,
        width,
        height,
    })
}

/// The orientation tag of a TIFF block, from its first directory.
fn exif_orientation(tiff: &[u8]) -> Option<u16> {
    let big = match tiff.get(0..2)? {
        b"MM" => true,
        b"II" => false,
        _ => return None,
    };
    let u16_at = |i: usize| -> Option<u16> {
        let b: [u8; 2] = tiff.get(i..i + 2)?.try_into().ok()?;
        Some(if big {
            u16::from_be_bytes(b)
        } else {
            u16::from_le_bytes(b)
        })
    };
    let u32_at = |i: usize| -> Option<u32> {
        let b: [u8; 4] = tiff.get(i..i + 4)?.try_into().ok()?;
        Some(if big {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        })
    };
    let ifd = u32_at(4)? as usize;
    let count = usize::from(u16_at(ifd)?);
    (0..count.min(256))
        .map(|n| ifd + 2 + n * 12)
        .find(|&entry| u16_at(entry) == Some(0x0112))
        .and_then(|entry| u16_at(entry + 8))
}

/// An APP1 segment that holds nothing but the orientation.
fn orientation_exif(orientation: u16) -> Vec<u8> {
    let mut segment = vec![0xFF, 0xE1, 0x00, 0x22];
    segment.extend_from_slice(b"Exif\0\0MM\0\x2a\0\0\0\x08");
    segment.extend_from_slice(&[0x00, 0x01, 0x01, 0x12, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01]);
    segment.extend_from_slice(&orientation.to_be_bytes());
    segment.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    segment
}

/// The type a file's extension names, for the receiver to choose an icon and an app by.
fn mime_by_extension(name: &str) -> &'static str {
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase());
    match ext.as_deref() {
        Some("pdf") => "application/pdf",
        Some("txt" | "log" | "md") => "text/plain",
        Some("csv") => "text/csv",
        Some("zip") => "application/zip",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("heic") => "image/heic",
        Some("mp4") => "video/mp4",
        Some("mov") => "video/quicktime",
        Some("mp3") => "audio/mpeg",
        Some("m4a") => "audio/mp4",
        Some("ogg" | "opus") => "audio/ogg",
        Some("wav") => "audio/wav",
        Some("doc") => "application/msword",
        Some("docx") => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        Some("xlsx") => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segment(marker: u8, body: &[u8]) -> Vec<u8> {
        let mut s = vec![0xFF, marker];
        s.extend_from_slice(&((body.len() + 2) as u16).to_be_bytes());
        s.extend_from_slice(body);
        s
    }

    /// EXIF with a position-like payload and an orientation, little-endian as phones write it.
    fn exif(orientation: u16) -> Vec<u8> {
        let mut b = b"Exif\0\0II\x2a\0\x08\0\0\0".to_vec();
        b.extend_from_slice(&[0x02, 0x00]);
        b.extend_from_slice(&[0x12, 0x01, 0x03, 0x00, 0x01, 0, 0, 0]);
        b.extend_from_slice(&orientation.to_le_bytes());
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(&[0x25, 0x88, 0x04, 0x00, 0x01, 0, 0, 0, 0x26, 0, 0, 0]);
        b.extend_from_slice(&[0, 0, 0, 0]);
        b.extend_from_slice(b"GPS 55.75N 37.61E");
        b
    }

    fn jpeg(orientation: u16) -> Vec<u8> {
        let mut j = vec![0xFF, 0xD8];
        j.extend(segment(0xE0, b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0"));
        j.extend(segment(0xE1, &exif(orientation)));
        j.extend(segment(
            0xE1,
            b"http://ns.adobe.com/xap/1.0/\0<x:xmpmeta>Moscow</x:xmpmeta>",
        ));
        j.extend(segment(0xE2, b"ICC_PROFILE\0\x01\x01colours"));
        j.extend(segment(0xE2, b"MPF\0second picture"));
        j.extend(segment(0xFE, b"taken at home"));
        j.extend(segment(0xC0, &[8, 0x01, 0xE0, 0x02, 0x80, 1, 1, 0x11, 0]));
        j.extend(segment(0xDA, &[1, 1, 0, 0, 0x3F, 0]));
        j.extend_from_slice(&[0x12, 0xFF, 0x00, 0x34, 0xFF, 0xD0, 0x56]);
        j.extend_from_slice(&[0xFF, 0xD9]);
        j.extend_from_slice(b"\xFF\xD8 trailer picture GPS");
        j
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn a_jpeg_loses_its_metadata_and_keeps_its_picture() {
        let out = prepare("IMG_0001.JPG", jpeg(1));
        assert_eq!(out.kind, Attachment::Photo);
        assert_eq!(out.mime, "image/jpeg");
        assert_eq!((out.width, out.height), (640, 480));
        for gone in [
            &b"GPS"[..],
            b"Moscow",
            b"MPF",
            b"taken at home",
            b"trailer",
            b"Exif",
        ] {
            assert!(
                !contains(&out.bytes, gone),
                "{}",
                String::from_utf8_lossy(gone)
            );
        }
        for kept in [
            &b"JFIF"[..],
            b"ICC_PROFILE",
            &[0x12, 0xFF, 0x00, 0x34, 0xFF, 0xD0, 0x56],
        ] {
            assert!(contains(&out.bytes, kept));
        }
        assert!(out.bytes.ends_with(&[0xFF, 0xD9]));
    }

    #[test]
    fn a_turned_jpeg_keeps_only_its_orientation() {
        let out = prepare("p.jpg", jpeg(6));
        assert!(!contains(&out.bytes, b"GPS"));
        let at = out
            .bytes
            .windows(6)
            .position(|w| w == b"Exif\0\0")
            .expect("an orientation block");
        assert_eq!(exif_orientation(&out.bytes[at + 6..]), Some(6));
        assert_eq!((out.width, out.height), (480, 640), "shown upright");
    }

    #[test]
    fn a_png_loses_its_text_chunks() {
        let chunk = |kind: &[u8; 4], data: &[u8]| {
            let mut c = (data.len() as u32).to_be_bytes().to_vec();
            c.extend_from_slice(kind);
            c.extend_from_slice(data);
            c.extend_from_slice(&[0, 0, 0, 0]);
            c
        };
        let mut png = PNG_SIGNATURE.to_vec();
        png.extend(chunk(b"IHDR", &[0, 0, 0, 3, 0, 0, 0, 2, 8, 6, 0, 0, 0]));
        png.extend(chunk(b"tEXt", b"Author\0me"));
        png.extend(chunk(b"eXIf", b"MM GPS"));
        png.extend(chunk(b"IDAT", b"pixels"));
        png.extend(chunk(b"IEND", b""));
        png.extend_from_slice(b"after the end");
        let out = prepare("shot.png", png);
        assert_eq!(out.kind, Attachment::Photo);
        assert_eq!((out.width, out.height), (3, 2));
        assert!(contains(&out.bytes, b"pixels"));
        for gone in [&b"Author"[..], b"GPS", b"after the end"] {
            assert!(!contains(&out.bytes, gone));
        }
    }

    #[test]
    fn a_sent_file_reads_back_as_what_was_sent() {
        let file = prepare("p.jpg", jpeg(1));
        let sealed = construct_core::media::seal_media(&file.bytes).unwrap();
        let uploaded = crate::grpc::Uploaded {
            media_id: "m-1".into(),
            download_url: "https://media.example/m-1".into(),
        };
        let quote = crate::content::Quote {
            message_id: "q1".into(),
            preview: "look".into(),
        };
        let payload = content(&file, &uploaded, &sealed, "the view", Some(&quote));
        assert_eq!(
            crate::content::parse(&payload),
            Some(crate::content::Content::Message {
                text: "the view".into(),
                quote: Some(quote),
                attachment: Some(Attachment::Photo),
            })
        );
        let files = crate::content::media_files(&payload);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].media_id, "m-1");
        assert_eq!(files[0].key.as_slice(), sealed.key.as_slice());
        assert_eq!((files[0].info.width, files[0].info.height), (640, 480));
        assert_eq!(
            construct_core::media::open_media(&files[0].key, &sealed.blob).unwrap(),
            file.bytes
        );
    }

    #[test]
    fn a_sound_or_a_video_is_typed_as_one() {
        let sealed = construct_core::media::seal_media(b"x").unwrap();
        let uploaded = crate::grpc::Uploaded {
            media_id: "m".into(),
            download_url: String::new(),
        };
        let kind = |name: &str| {
            let payload = content(
                &prepare(name, b"data".to_vec()),
                &uploaded,
                &sealed,
                "",
                None,
            );
            crate::content::media_files(&payload)[0].info.kind
        };
        assert_eq!(kind("note.m4a"), Some(Attachment::Audio));
        assert_eq!(kind("clip.mp4"), Some(Attachment::Video));
        assert_eq!(kind("notes.txt"), Some(Attachment::File));
    }

    #[test]
    fn anything_else_goes_as_a_file_unchanged() {
        let out = prepare("/home/me/Report.PDF", b"%PDF-1.7 ...".to_vec());
        assert_eq!(out.kind, Attachment::File);
        assert_eq!(out.mime, "application/pdf");
        assert_eq!(out.filename.as_deref(), Some("Report.PDF"));
        assert_eq!(out.bytes, b"%PDF-1.7 ...");
        let broken = prepare("cut.jpg", vec![0xFF, 0xD8, 0xFF, 0xE1, 0x00]);
        assert_eq!(
            broken.kind,
            Attachment::File,
            "a JPEG that does not read is a file"
        );
    }
}
