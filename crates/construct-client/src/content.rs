//! What a chat payload says: the `MessageContent` inside a KNST frame, read into what this
//! client acts on.
//!
//! Until this module the receive path read only `MessageContent.text` and showed anything else
//! as its bytes taken for UTF-8 — an iOS edit or reaction became a new bubble of garbage. The
//! rules here are iOS's (`MessageRouter`, `ReactionReducer`), since the core decides none of
//! them: an edit is applied only by the author of the message, a reaction is the reactor's
//! latest by its own clock, a delete is never sent by any client and is not applied.

use prost::Message;

use crate::proto::messaging::v1::{
    MediaType, MessageContent, QuotedMessage, ReactionAction, message_content,
};

/// The quoted message a reply carries: its id and the preview the sender put in.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Quote {
    pub message_id: String,
    pub preview: String,
}

/// What a message this client cannot show yet holds, so the screens can say so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Attachment {
    Photo,
    Video,
    Audio,
    File,
    Voice,
    Sticker,
    Location,
    Contact,
    Poll,
    Other,
}

/// A chat payload, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Content {
    /// A message for the transcript: text, or an attachment with its caption as `text`.
    Message {
        text: String,
        quote: Option<Quote>,
        attachment: Option<Attachment>,
    },
    /// The author replaces the text of `target`.
    Edit { target: String, text: String },
    /// `reactor`'s reaction on `target`: set to `emoji`, or taken back when `emoji` is `None`.
    Reaction {
        target: String,
        emoji: Option<String>,
        /// The reactor's clock at the tap; 0 from a peer that predates it.
        timestamp_ms: i64,
    },
    /// A delete. No client sends one; it is read so it never becomes a bubble.
    Delete,
}

/// Longest reaction iOS accepts, in UTF-8 bytes (`ReactionReducer`).
const MAX_EMOJI_BYTES: usize = 32;
/// Longest message id iOS accepts as a reaction target.
const MAX_TARGET_LEN: usize = 64;
/// The sender's preview of a quote, as the proto bounds it.
pub const QUOTE_PREVIEW_CHARS: usize = 200;

/// `MessageContent` bytes, read. `None` when they are not one, or carry nothing this client knows.
pub fn parse(payload: &[u8]) -> Option<Content> {
    use message_content::Content as C;
    let content = MessageContent::decode(payload).ok()?.content?;
    Some(match content {
        C::Text(text) => Content::Message {
            text: text.text,
            quote: text.quoted.and_then(quote),
            attachment: None,
        },
        C::Media(media) => Content::Message {
            text: media.caption.unwrap_or_default(),
            quote: None,
            attachment: Some(media_attachment(media.media_type)),
        },
        C::MediaAlbum(album) => Content::Message {
            text: album.caption.unwrap_or_default(),
            quote: album.quoted.and_then(quote),
            attachment: Some(
                album
                    .items
                    .first()
                    .map_or(Attachment::Photo, |m| media_attachment(m.media_type)),
            ),
        },
        C::Voice(voice) => Content::Message {
            text: String::new(),
            quote: voice.quoted.and_then(quote),
            attachment: Some(Attachment::Voice),
        },
        C::Sticker(sticker) => Content::Message {
            text: sticker.emoji,
            quote: None,
            attachment: Some(Attachment::Sticker),
        },
        C::Location(_) => attachment_only(Attachment::Location),
        C::Contact(_) => attachment_only(Attachment::Contact),
        C::Poll(_) => attachment_only(Attachment::Poll),
        C::Edit(edit) => {
            use crate::proto::messaging::v1::edit_message::NewContent;
            let text = match edit.new_content? {
                NewContent::NewText(text) => text.text,
                // A new caption: iOS sends captions as `new_text` too.
                NewContent::NewMedia(media) => media.caption.unwrap_or_default(),
            };
            Content::Edit {
                target: target(&edit.target_message_id)?,
                text,
            }
        }
        C::Reaction(reaction) => {
            let target = target(&reaction.target_message_id)?;
            let emoji = match ReactionAction::try_from(reaction.action) {
                Ok(ReactionAction::Remove) => None,
                Ok(ReactionAction::Add) if valid_emoji(&reaction.emoji) => Some(reaction.emoji),
                _ => return None,
            };
            Content::Reaction {
                target,
                emoji,
                timestamp_ms: reaction.timestamp_ms.max(0),
            }
        }
        C::Delete(_) => Content::Delete,
    })
}

fn attachment_only(attachment: Attachment) -> Content {
    Content::Message {
        text: String::new(),
        quote: None,
        attachment: Some(attachment),
    }
}

fn media_attachment(media_type: i32) -> Attachment {
    match MediaType::try_from(media_type) {
        Ok(MediaType::Image | MediaType::Animated) => Attachment::Photo,
        Ok(MediaType::Video) => Attachment::Video,
        Ok(MediaType::Audio) => Attachment::Audio,
        Ok(MediaType::File) => Attachment::File,
        Ok(MediaType::Sticker) => Attachment::Sticker,
        _ => Attachment::Other,
    }
}

fn quote(quoted: QuotedMessage) -> Option<Quote> {
    Some(Quote {
        message_id: target(&quoted.message_id)?,
        preview: quoted
            .text_preview
            .unwrap_or_default()
            .chars()
            .take(QUOTE_PREVIEW_CHARS)
            .collect(),
    })
}

/// A message id another message points at, as ids are kept here: lower case. iOS writes upper.
fn target(id: &str) -> Option<String> {
    let id = id.trim();
    (!id.is_empty() && id.len() <= MAX_TARGET_LEN).then(|| id.to_lowercase())
}

/// A reaction is one short emoji, not text.
fn valid_emoji(emoji: &str) -> bool {
    !emoji.is_empty()
        && emoji.len() <= MAX_EMOJI_BYTES
        && !emoji
            .chars()
            .any(|c| c.is_ascii() || c.is_control() || c.is_whitespace())
}

/// The `MessageContent` bytes of what this client sends: a message, an edit or a reaction, as
/// iOS writes them (`ChatSendCoordinator`). An edit sets only the target and the new text, a
/// reaction taken back has no emoji, and a quote carries no sender — iOS sets none of those.
pub fn encode(content: &Content) -> Vec<u8> {
    use crate::proto::messaging::v1::{EditMessage, ReactionMessage, TextMessage, edit_message};
    use message_content::Content as C;
    let text_message = |text: &str, quoted: Option<QuotedMessage>| TextMessage {
        text: text.to_owned(),
        quoted,
        ..Default::default()
    };
    let content = match content {
        Content::Message { text, quote, .. } => C::Text(text_message(
            text,
            quote.as_ref().map(|q| QuotedMessage {
                message_id: q.message_id.clone(),
                text_preview: Some(q.preview.chars().take(QUOTE_PREVIEW_CHARS).collect()),
                ..Default::default()
            }),
        )),
        Content::Edit { target, text } => C::Edit(EditMessage {
            target_message_id: target.clone(),
            new_content: Some(edit_message::NewContent::NewText(text_message(text, None))),
            ..Default::default()
        }),
        Content::Reaction {
            target,
            emoji,
            timestamp_ms,
        } => C::Reaction(ReactionMessage {
            target_message_id: target.clone(),
            emoji: emoji.clone().unwrap_or_default(),
            action: if emoji.is_some() {
                ReactionAction::Add
            } else {
                ReactionAction::Remove
            } as i32,
            timestamp_ms: *timestamp_ms,
        }),
        Content::Delete => C::Delete(Default::default()),
    };
    MessageContent {
        content: Some(content),
        ..Default::default()
    }
    .encode_to_vec()
}

/// Whether a reaction with clock `incoming` replaces one held with clock `held`: strictly newer
/// only, so a tie keeps what is there and a redelivery changes nothing (iOS `ReactionReducer`).
pub fn reaction_wins(incoming: i64, held: Option<i64>) -> bool {
    held.is_none_or(|held| incoming > held)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::messaging::v1::{
        EditMessage, MediaMessage, ReactionMessage, StickerRef, TextMessage, edit_message,
    };

    fn bytes(content: message_content::Content) -> Vec<u8> {
        MessageContent {
            content: Some(content),
            ..Default::default()
        }
        .encode_to_vec()
    }

    #[test]
    fn a_reply_keeps_its_quote() {
        let payload = bytes(message_content::Content::Text(TextMessage {
            text: "yes".into(),
            quoted: Some(QuotedMessage {
                message_id: "AB-CD".into(),
                text_preview: Some("are you there?".into()),
                ..Default::default()
            }),
            ..Default::default()
        }));
        assert_eq!(
            parse(&payload),
            Some(Content::Message {
                text: "yes".into(),
                quote: Some(Quote {
                    message_id: "ab-cd".into(),
                    preview: "are you there?".into()
                }),
                attachment: None,
            })
        );
    }

    #[test]
    fn an_edit_names_its_target_and_the_new_text() {
        let payload = bytes(message_content::Content::Edit(EditMessage {
            target_message_id: "6AE5E1FF".into(),
            new_content: Some(edit_message::NewContent::NewText(TextMessage {
                text: "fixed".into(),
                ..Default::default()
            })),
            ..Default::default()
        }));
        assert_eq!(
            parse(&payload),
            Some(Content::Edit {
                target: "6ae5e1ff".into(),
                text: "fixed".into()
            })
        );
    }

    #[test]
    fn a_reaction_is_added_or_taken_back() {
        let reaction = |emoji: &str, action: ReactionAction| {
            bytes(message_content::Content::Reaction(ReactionMessage {
                target_message_id: "m1".into(),
                emoji: emoji.into(),
                action: action as i32,
                timestamp_ms: 42,
            }))
        };
        assert_eq!(
            parse(&reaction("👍", ReactionAction::Add)),
            Some(Content::Reaction {
                target: "m1".into(),
                emoji: Some("👍".into()),
                timestamp_ms: 42
            })
        );
        assert_eq!(
            parse(&reaction("", ReactionAction::Remove)),
            Some(Content::Reaction {
                target: "m1".into(),
                emoji: None,
                timestamp_ms: 42
            })
        );
        // Text is not a reaction, nor is a reaction without an action.
        assert_eq!(parse(&reaction("lol", ReactionAction::Add)), None);
        assert_eq!(parse(&reaction("👍", ReactionAction::Unspecified)), None);
    }

    #[test]
    fn media_is_an_attachment_with_its_caption() {
        let payload = bytes(message_content::Content::Media(MediaMessage {
            media_type: MediaType::Image as i32,
            caption: Some("the view".into()),
            ..Default::default()
        }));
        assert_eq!(
            parse(&payload),
            Some(Content::Message {
                text: "the view".into(),
                quote: None,
                attachment: Some(Attachment::Photo),
            })
        );
        let sticker = bytes(message_content::Content::Sticker(StickerRef {
            emoji: "🐱".into(),
            ..Default::default()
        }));
        assert!(matches!(
            parse(&sticker),
            Some(Content::Message { attachment: Some(Attachment::Sticker), text, .. }) if text == "🐱"
        ));
    }

    #[test]
    fn what_this_client_sends_reads_back_as_it_was_meant() {
        for content in [
            Content::Message {
                text: "yes".into(),
                quote: Some(Quote {
                    message_id: "m1".into(),
                    preview: "are you there?".into(),
                }),
                attachment: None,
            },
            Content::Edit {
                target: "m1".into(),
                text: "fixed".into(),
            },
            Content::Reaction {
                target: "m1".into(),
                emoji: Some("👍".into()),
                timestamp_ms: 7,
            },
            Content::Reaction {
                target: "m1".into(),
                emoji: None,
                timestamp_ms: 8,
            },
        ] {
            assert_eq!(parse(&encode(&content)), Some(content));
        }
    }

    #[test]
    fn a_tie_keeps_the_reaction_held() {
        assert!(reaction_wins(5, None));
        assert!(reaction_wins(6, Some(5)));
        assert!(!reaction_wins(5, Some(5)));
        assert!(!reaction_wins(4, Some(5)));
    }
}
