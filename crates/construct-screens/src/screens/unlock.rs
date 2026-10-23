//! Passphrase screen — used in two modes:
//!   `Unlock`    — enter passphrase to decrypt an existing session on startup.
//!   `SetNew`    — choose a passphrase to protect a newly created session.

use crate::theme::ThemeMode;
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::Modifier,
    widgets::{Paragraph, Widget},
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone, PartialEq)]
pub enum UnlockMode {
    /// Decrypt an existing session on startup.
    Unlock,
    /// Protect a newly registered/linked session with a passphrase.
    SetNew,
}

pub struct UnlockScreen {
    pub theme: ThemeMode,
    /// Raw passphrase bytes — zeroized on drop.
    passphrase: Zeroizing<String>,
    pub error: Option<String>,
    pub mode: UnlockMode,
}

impl UnlockScreen {
    pub fn new(mode: UnlockMode) -> Self {
        Self {
            theme: ThemeMode::default(),
            passphrase: Zeroizing::new(String::new()),
            error: None,
            mode,
        }
    }

    /// Reset state and switch to a different mode (e.g. after failed unlock).
    pub fn reset_for_mode(&mut self, mode: UnlockMode) {
        self.passphrase.zeroize();
        self.passphrase.clear();
        self.error = None;
        self.mode = mode;
    }

    pub fn push_char(&mut self, c: char) {
        // Reasonable passphrase limit
        if self.passphrase.len() < 128 {
            self.passphrase.push(c);
        }
    }

    pub fn pop_char(&mut self) {
        self.passphrase.pop();
    }

    pub fn is_empty(&self) -> bool {
        self.passphrase.is_empty()
    }

    /// Extract passphrase as zeroizing byte vector and clear the in-screen buffer.
    pub fn take_passphrase(&mut self) -> Zeroizing<Vec<u8>> {
        let bytes = Zeroizing::new(self.passphrase.as_bytes().to_vec());
        self.passphrase.zeroize();
        self.passphrase.clear();
        bytes
    }

    pub fn set_error(&mut self, msg: impl Into<String>) {
        self.error = Some(msg.into());
    }

    pub fn clear_error(&mut self) {
        self.error = None;
    }
}

impl Widget for &UnlockScreen {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let palette = self.theme.palette();
        let (title, hint, field_title) = match self.mode {
            UnlockMode::Unlock => (
                " Unlock session ",
                "Enter=unlock   Ctrl+C=quit",
                " Passphrase ",
            ),
            UnlockMode::SetNew => (
                " Protect your session ",
                "Enter=confirm   Ctrl+C=quit",
                " Choose a passphrase ",
            ),
        };

        let subtitle = match self.mode {
            UnlockMode::Unlock => "Enter your passphrase to decrypt your session keys.",
            UnlockMode::SetNew => "Your keys will be encrypted at rest with this passphrase.",
        };

        // total_h: title + gap + subtitle + gap + field + gap + status/hint
        let total_h = 1u16 + 1 + 1 + 2 + 3 + 1 + 1;
        let v_offset = area.height.saturating_sub(total_h) / 2;
        let mut y = area.y + v_offset;

        // ── Title ─────────────────────────────────────────────────────────────
        let tw = title.len() as u16;
        let tx = area.x + area.width.saturating_sub(tw) / 2;
        Paragraph::new(title).style(palette.emphasis()).render(
            Rect {
                x: tx,
                y,
                width: tw.min(area.width),
                height: 1,
            },
            buf,
        );
        y += 2;

        // ── Subtitle ──────────────────────────────────────────────────────────
        let sw = subtitle.len() as u16;
        let sx = area.x + area.width.saturating_sub(sw) / 2;
        Paragraph::new(subtitle).style(palette.muted()).render(
            Rect {
                x: sx,
                y,
                width: sw.min(area.width),
                height: 1,
            },
            buf,
        );
        y += 2;

        // ── Passphrase field (masked) ─────────────────────────────────────────
        let field_w = 42u16.min(area.width.saturating_sub(4));
        let field_x = area.x + area.width.saturating_sub(field_w) / 2;
        // Mask typed chars with bullets; show underscore cursor only at end
        let masked = format!("{}_", "•".repeat(self.passphrase.len()));

        Paragraph::new(masked)
            .block(palette.panel(field_title, true))
            .style(palette.surface())
            .render(
                Rect {
                    x: field_x,
                    y,
                    width: field_w,
                    height: 3,
                },
                buf,
            );
        y += 4;

        // ── Error or hint ─────────────────────────────────────────────────────
        if let Some(ref err) = self.error {
            let ex = area.x + area.width.saturating_sub(err.len() as u16) / 2;
            Paragraph::new(err.as_str())
                .style(palette.state(true).add_modifier(Modifier::BOLD))
                .render(
                    Rect {
                        x: ex,
                        y,
                        width: (err.len() as u16).min(area.width),
                        height: 1,
                    },
                    buf,
                );
            y += 2;
        }

        let hx = area.x + area.width.saturating_sub(hint.len() as u16) / 2;
        Paragraph::new(hint).style(palette.muted()).render(
            Rect {
                x: hx,
                y,
                width: (hint.len() as u16).min(area.width),
                height: 1,
            },
            buf,
        );
    }
}
