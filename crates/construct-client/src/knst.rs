//! KNST plaintext frame — same 30-byte header iOS writes.
//!
//! Layout (`architecture/WIRE_FORMAT.md`):
//! ```text
//! [0..4]   magic b"KNST"
//! [4]      version 0x01
//! [5]      content_type (inside the ciphertext; server cannot read this)
//! [6..22]  message UUID (16 raw bytes)
//! [22..24] chunk_index (BE u16)
//! [24..26] total_chunks (BE u16)
//! [26..30] plaintext_length (BE u32)
//! [30..]   payload
//! ```
//!
//! Regular chat: byte 5 = `E2EE_SIGNAL` (1), payload = `MessageContent` protobuf.
//! Session ping: byte 5 = `SESSION_PING` (25), payload = `SessionControl` protobuf.

use prost::Message;
use uuid::Uuid;

use crate::proto::core::v1::ContentType;
use crate::proto::messaging::v1::{MessageContent, TextMessage, message_content};

pub const MAGIC: &[u8; 4] = b"KNST";
pub const VERSION: u8 = 0x01;
pub const HEADER_SIZE: usize = 30;

/// Byte-5 values, derived from the generated enum rather than typed out again.
///
/// They were `= 1`, `= 12`, … with a comment saying "must match
/// `shared.proto.core.v1.ContentType`". A comment is not a mechanism: the numbers are generated
/// from the same proto three directories away and were being copied by hand anyway.
pub const CONTENT_E2EE_SIGNAL: u8 = ContentType::E2eeSignal as u8;
pub const CONTENT_CALL_SIGNAL: u8 = ContentType::CallSignal as u8;
pub const CONTENT_HEARTBEAT: u8 = ContentType::Heartbeat as u8;
pub const CONTENT_DELIVERY_RECEIPT: u8 = ContentType::DeliveryReceipt as u8;
pub const CONTENT_SESSION_RESET: u8 = ContentType::SessionReset as u8;
pub const CONTENT_SENDER_SYNC: u8 = ContentType::SenderSync as u8;
pub const CONTENT_SESSION_RESET_INIT: u8 = ContentType::SessionResetInit as u8;
pub const CONTENT_SESSION_PING: u8 = ContentType::SessionPing as u8;
/// A profile card riding beside a message; never a bubble (`framed_side_channel: contact_card`).
pub const CONTENT_CONTACT_CARD: u8 = ContentType::ContactCard as u8;
/// "I could not read your message", answered by the core; never a bubble.
pub const CONTENT_DECRYPTION_ERROR: u8 = ContentType::DecryptionError as u8;
pub const CONTENT_SESSION_READY: u8 = ContentType::SessionReady as u8;

/// Wrap UTF-8 chat text as a single-chunk KNST frame carrying `MessageContent`.
pub fn encode_text(text: &str, message_id: &str) -> Vec<u8> {
    let content = MessageContent {
        content: Some(message_content::Content::Text(TextMessage {
            text: text.to_owned(),
            ..Default::default()
        })),
        ..Default::default()
    };
    frame_whole(&content.encode_to_vec(), CONTENT_E2EE_SIGNAL, message_id)
}

/// Single-frame KNST (never split). Matches iOS `ChunkedMessageCodec.frameWhole`.
pub fn frame_whole(payload: &[u8], content_type: u8, message_id: &str) -> Vec<u8> {
    let uuid = Uuid::parse_str(message_id).unwrap_or_else(|_| Uuid::nil());
    let mut out = Vec::with_capacity(HEADER_SIZE + payload.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(content_type);
    out.extend_from_slice(uuid.as_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // chunk_index
    out.extend_from_slice(&1u16.to_be_bytes()); // total_chunks
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// True when `data` already has a KNST v1 header (do not double-wrap).
pub fn is_frame(data: &[u8]) -> bool {
    data.len() >= HEADER_SIZE && data.starts_with(MAGIC) && data[4] == VERSION
}

/// Displayable chat text from a decrypted plaintext buffer.
///
/// Control types (ping / ready / call / heartbeat / receipt) return empty so
/// they never become a bubble. Unknown KNST payloads try `MessageContent`, then
/// UTF-8. Bare UTF-8 is the TUI↔TUI / leftover path.
pub fn decode_text(plaintext: &[u8]) -> String {
    if !is_frame(plaintext) {
        return String::from_utf8_lossy(plaintext).into_owned();
    }
    let content_type = plaintext[5];
    if is_silent_type(content_type) {
        return String::new();
    }
    let payload_len =
        u32::from_be_bytes(plaintext[26..30].try_into().unwrap_or([0, 0, 0, 0])) as usize;
    let raw = &plaintext[HEADER_SIZE..];
    let payload = raw.get(..payload_len.min(raw.len())).unwrap_or(raw);

    if let Ok(content) = MessageContent::decode(payload)
        && let Some(message_content::Content::Text(text_msg)) = content.content
    {
        return text_msg.text;
    }
    String::from_utf8_lossy(payload).into_owned()
}

/// What a client must do with the payload behind a KNST byte-5 value.
///
/// The authority is `construct-protos/conformance/knst_content_types.json`, and
/// `content_type_vectors_match_this_table` reads it. Before that file existed this list was a
/// local `matches!` and iOS had its own, answering a slightly different question; the two had
/// already drifted apart on 13 and 23 without anything noticing, because a divergence here is
/// not an error — it is a message that is a bubble on one client and nothing on the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// User content from the peer. Belongs in the transcript.
    TranscriptIncoming,
    /// Our own message, echoed from another device of this account. Belongs in the transcript
    /// as a *sent* bubble. The TUI has no multi-device path yet, so it currently renders this
    /// as ordinary incoming text — wrong, but visible rather than silent, and tracked as such.
    TranscriptOwnDevice,
    /// Never reaches the transcript. A bubble here is a user-visible defect.
    SilentControl,
    /// No current producer frames this. A peer that sends one is ahead of us: do not guess.
    NotCarried,
}

pub fn disposition(content_type: u8) -> Disposition {
    match content_type {
        CONTENT_E2EE_SIGNAL => Disposition::TranscriptIncoming,
        CONTENT_SENDER_SYNC => Disposition::TranscriptOwnDevice,
        CONTENT_CALL_SIGNAL
        | CONTENT_HEARTBEAT
        | CONTENT_DELIVERY_RECEIPT
        | CONTENT_SESSION_RESET
        | CONTENT_SESSION_RESET_INIT
        | CONTENT_SESSION_PING
        | CONTENT_SESSION_READY
        | CONTENT_CONTACT_CARD
        | CONTENT_DECRYPTION_ERROR => Disposition::SilentControl,
        _ => Disposition::NotCarried,
    }
}

fn is_silent_type(content_type: u8) -> bool {
    disposition(content_type) == Disposition::SilentControl
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_frame_round_trips() {
        let id = "ffeeddc6-14f2-4d02-a66a-caf0d8dfeda8";
        let framed = encode_text("hello from tui", id);
        assert!(is_frame(&framed));
        assert_eq!(framed[5], CONTENT_E2EE_SIGNAL);
        assert_eq!(&framed[6..22], Uuid::parse_str(id).unwrap().as_bytes());
        assert_eq!(&framed[22..24], &[0, 0]);
        assert_eq!(&framed[24..26], &[0, 1]);
        assert_eq!(decode_text(&framed), "hello from tui");
    }

    #[test]
    fn bare_utf8_still_decodes() {
        assert_eq!(decode_text(b"plain leftover"), "plain leftover");
    }

    /// The table above must say what `construct-protos/conformance/knst_content_types.json`
    /// says, for every value in it — including the ones this client has no code for yet.
    ///
    /// That last part is the point. A content type added to the protocol gains a row there; if
    /// the TUI has not learned it, this test goes red on the next build instead of the client
    /// silently rendering a control payload as a chat bubble. Before the vectors existed, iOS
    /// and this file had already drifted on 13 and 23 and nothing said so.
    #[test]
    fn content_type_vectors_match_this_table() {
        const VECTORS: &str = include_str!(concat!(
            env!("CONSTRUCT_PROTOS_DIR"),
            "/conformance/knst_content_types.json"
        ));
        let doc: serde_json::Value = serde_json::from_str(VECTORS).expect("vectors are valid JSON");
        let rows = doc["types"].as_array().expect("`types` is an array");
        assert!(
            !rows.is_empty(),
            "empty vectors would pass every assertion below"
        );

        for row in rows {
            let value = row["value"].as_u64().expect("value") as u8;
            let name = row["name"].as_str().expect("name");
            let expected = match row["disposition"].as_str().expect("disposition") {
                "transcript_incoming" => Disposition::TranscriptIncoming,
                "transcript_own_device" => Disposition::TranscriptOwnDevice,
                "silent_control" => Disposition::SilentControl,
                "not_carried" => Disposition::NotCarried,
                other => panic!("{name}: unknown disposition {other:?} — teach this test first"),
            };
            assert_eq!(
                disposition(value),
                expected,
                "{name} = {value}: the vectors and this client disagree about what it means"
            );
        }
    }

    /// `is_silent_type` is the gate `decode_text` actually uses. Asserted through the public
    /// function so the delegation cannot be quietly removed while `disposition` stays correct.
    #[test]
    fn every_silent_control_type_decodes_to_nothing() {
        for ct in [
            CONTENT_CALL_SIGNAL,
            CONTENT_HEARTBEAT,
            CONTENT_DELIVERY_RECEIPT,
            CONTENT_SESSION_PING,
            CONTENT_SESSION_READY,
        ] {
            let framed = frame_whole(b"payload", ct, &Uuid::nil().to_string());
            assert!(
                decode_text(&framed).is_empty(),
                "content type {ct} reached the transcript"
            );
        }
        let chat = frame_whole(b"", CONTENT_E2EE_SIGNAL, &Uuid::nil().to_string());
        assert!(
            is_frame(&chat),
            "the negative case must exercise the same path"
        );
    }

    #[test]
    fn header_plaintext_length_matches_payload() {
        let framed = encode_text("ab", &Uuid::nil().to_string());
        let declared = u32::from_be_bytes(framed[26..30].try_into().unwrap()) as usize;
        assert_eq!(declared, framed.len() - HEADER_SIZE);
    }
}
