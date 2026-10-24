//! Copies of our own messages between the devices of this account (SENDER_SYNC, content type 23).
//!
//! When one device of an account sends, each of its other devices gets a copy, so all of them show
//! the message as sent. The copy goes unsealed — the pair is (us, us), which the relay knows from
//! the authenticated channel anyway (decisions/sealing-is-a-declared-value.md, `.ownDevices`) — as
//! an `OwnDeviceCopy { sender_certificate, wire_payload }` addressed to one device.
//!
//! Inside the ciphertext the KNST frame (byte 5 = 23) carries a 20-byte routing header before the
//! message content: `"SSR1"` and the partner's account UUID as raw bytes. The server blanks every
//! field of the envelope that could say whose conversation it is, so the receiver learns it only
//! from here (iOS `SenderSyncRouting`). READ_SYNC (30) travels the same way.

#[cfg(test)]
use prost::Message;

#[cfg(test)]
use crate::proto::messaging::v1::{MessageContent, TextMessage, message_content};

const MAGIC: &[u8; 4] = b"SSR1";
const HEADER_LEN: usize = 4 + 16;
/// Between a message id and the per-device tag of its copy (iOS `DeviceDeliveryPlan.Marker`).
const COPY_MARKER: &str = "-ss-";

/// The plaintext of a copy of a text message we sent to `partner`: a whole KNST frame, byte 5 = 23,
/// `"SSR1" ‖ partner ‖ MessageContent`. `None` when `partner` is not a UUID.
#[cfg(test)]
pub fn text_copy(partner: &str, message_id: &str, text: &str) -> Option<Vec<u8>> {
    let content = MessageContent {
        content: Some(message_content::Content::Text(TextMessage {
            text: text.to_owned(),
            ..Default::default()
        })),
        ..Default::default()
    };
    copy(partner, message_id, &content.encode_to_vec())
}

/// The plaintext of a copy of what we sent to `partner` — `content` is its `MessageContent`: a
/// whole KNST frame, byte 5 = 23, `"SSR1" ‖ partner ‖ content`. `None` when `partner` is not a
/// UUID.
pub fn copy(partner: &str, message_id: &str, content: &[u8]) -> Option<Vec<u8>> {
    let partner = uuid::Uuid::parse_str(partner).ok()?;
    let mut body = Vec::with_capacity(HEADER_LEN + content.len());
    body.extend_from_slice(MAGIC);
    body.extend_from_slice(partner.as_bytes());
    body.extend_from_slice(content);
    Some(crate::knst::frame_whole(
        &body,
        crate::knst::CONTENT_SENDER_SYNC,
        message_id,
    ))
}

/// What a decrypted copy turned out to be.
#[derive(Debug, PartialEq, Eq)]
pub enum Copy {
    /// Something we sent to `partner` from another device: a message, or a reaction or edit of
    /// one. `payload` is its `MessageContent`.
    Content {
        partner: String,
        content: crate::content::Content,
        payload: Vec<u8>,
    },
    /// Read markers from another device (READ_SYNC); this client does not apply them yet.
    ReadMarkers,
    /// Split into chunks, or a kind of content this client does not show.
    Unsupported(&'static str),
}

/// Read a decrypted copy.
pub fn read(plaintext: &[u8]) -> Copy {
    let Some(frame) = construct_core::knst::Frame::parse(plaintext) else {
        return Copy::Unsupported("not a KNST frame");
    };
    if frame.content_type == crate::knst::CONTENT_READ_SYNC {
        return Copy::ReadMarkers;
    }
    if frame.content_type != crate::knst::CONTENT_SENDER_SYNC {
        return Copy::Unsupported("not a copy of a sent message");
    }
    if frame.total_chunks > 1 {
        return Copy::Unsupported("split into chunks");
    }
    let length = (frame.plaintext_length as usize).min(frame.payload.len());
    let body = &frame.payload[..length];
    if body.len() < HEADER_LEN || &body[..4] != MAGIC {
        return Copy::Unsupported("no routing header");
    }
    let partner = uuid::Uuid::from_slice(&body[4..HEADER_LEN])
        .expect("16 bytes")
        .to_string();
    let payload = &body[HEADER_LEN..];
    match crate::content::parse(payload) {
        Some(content) => Copy::Content {
            partner,
            content,
            payload: payload.to_vec(),
        },
        None => Copy::Unsupported("not a message this client reads"),
    }
}

/// The id a copy for one device travels under: `<message id>-ss-<tag>`.
pub fn copy_id(message_id: &str, tag: &str) -> String {
    format!("{message_id}{COPY_MARKER}{tag}")
}

/// A copy's id split into the message id and its tag; the tag is `None` for an id without one.
pub fn split_copy_id(id: &str) -> (&str, Option<&str>) {
    match id.rsplit_once(COPY_MARKER) {
        Some((base, tag)) => (base, Some(tag.split("-c").next().unwrap_or(tag))),
        None => (id, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PARTNER: &str = "ed3c4cb1-5ee7-4a6f-9862-62a5a8b8560f";
    const ID: &str = "6ae5e1ff-cd35-484d-a9ca-f2dc3fdb78ac";

    #[test]
    fn a_text_copy_reads_back_with_its_partner() {
        let plaintext = text_copy(PARTNER, ID, "sent from the phone").unwrap();
        let frame = construct_core::knst::Frame::parse(&plaintext).unwrap();
        assert_eq!(frame.content_type, 23);
        assert_eq!(&frame.payload[..4], b"SSR1");
        assert!(matches!(
            read(&plaintext),
            Copy::Content {
                partner,
                content: crate::content::Content::Message { text, .. },
                ..
            } if partner == PARTNER && text == "sent from the phone"
        ));
    }

    #[test]
    fn a_copy_without_the_routing_header_is_not_placed() {
        let plaintext =
            // Longer than the header, so only the magic can tell it is not one.
            crate::knst::frame_whole(
                b"a sender from before the routing header",
                crate::knst::CONTENT_SENDER_SYNC,
                ID,
            );
        assert_eq!(read(&plaintext), Copy::Unsupported("no routing header"));
    }

    #[test]
    fn read_markers_are_recognised_and_not_shown() {
        let plaintext = crate::knst::frame_whole(b"markers", crate::knst::CONTENT_READ_SYNC, ID);
        assert_eq!(read(&plaintext), Copy::ReadMarkers);
    }

    #[test]
    fn a_copy_id_splits_into_the_message_id_and_its_tag() {
        let id = copy_id(ID, "0123456789abcdef");
        assert_eq!(split_copy_id(&id), (ID, Some("0123456789abcdef")));
        assert_eq!(
            split_copy_id(&format!("{id}-c2")),
            (ID, Some("0123456789abcdef"))
        );
        assert_eq!(split_copy_id(ID), (ID, None));
    }

    #[test]
    fn a_partner_that_is_not_an_account_id_gets_no_copy() {
        assert_eq!(text_copy("not-a-uuid", ID, "x"), None);
    }
}
