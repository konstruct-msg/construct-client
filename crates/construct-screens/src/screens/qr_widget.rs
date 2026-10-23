//! Terminal QR code widget using Unicode half-block characters.
//!
//! Each pair of QR rows collapses into one terminal row:
//!   '█' both pixels dark   ' ' both light
//!   '▀' top dark only      '▄' bottom dark only
//!
//! Rendering includes a mandatory 2-cell quiet zone (white border) so scanners
//! work reliably. Total size for a typical ~25-module QR ≈ 15 rows × 29 chars.

use crate::theme::ThemeMode;
use qrcode::{EcLevel, QrCode};
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Paragraph, Widget},
};

const QUIET: usize = 2; // quiet-zone cells on each side

pub struct QrWidget<'a> {
    pub theme: ThemeMode,
    /// The data to encode (URL, token, username handle, …)
    pub data: &'a str,
    /// Optional caption rendered below the QR
    pub caption: Option<&'a str>,
    /// Foreground (dark modules). Always high contrast by default.
    pub fg: Color,
    /// Background (light modules). Includes the QR quiet zone.
    pub bg: Color,
}

impl<'a> QrWidget<'a> {
    pub fn new(data: &'a str) -> Self {
        Self {
            theme: ThemeMode::default(),
            data,
            caption: None,
            fg: Color::Black,
            bg: Color::White,
        }
    }

    pub fn theme(mut self, theme: ThemeMode) -> Self {
        self.theme = theme;
        self
    }

    pub fn caption(mut self, caption: &'a str) -> Self {
        self.caption = Some(caption);
        self
    }

    /// Returns (width_chars, height_rows) the widget will occupy, or None if
    /// data cannot be encoded (too long for QR).
    pub fn size_hint(data: &str) -> Option<(u16, u16)> {
        let code = QrCode::with_error_correction_level(data, EcLevel::M).ok()?;
        let modules = code.width();
        let w = (modules + QUIET * 2) as u16;
        let h = ((modules + QUIET * 2) as u16).div_ceil(2);
        Some((w, h))
    }
}

impl Widget for &QrWidget<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let palette = self.theme.palette();
        let code = match QrCode::with_error_correction_level(self.data, EcLevel::M) {
            Ok(c) => c,
            Err(_) => {
                // Data too long or encoding error — show fallback text
                let msg = "[ QR unavailable ]";
                let x = area.x + area.width.saturating_sub(msg.len() as u16) / 2;
                if area.height > 0 {
                    Paragraph::new(msg).style(palette.muted()).render(
                        Rect {
                            x,
                            y: area.y,
                            width: msg.len() as u16,
                            height: 1,
                        },
                        buf,
                    );
                }
                return;
            }
        };

        let modules = code.width();
        let padded = modules + QUIET * 2;

        // Build a flat bool matrix: true = dark module
        let grid: Vec<bool> = {
            let raw = code.to_colors();
            let mut padded_grid = vec![false; padded * padded];
            for row in 0..modules {
                for col in 0..modules {
                    padded_grid[(row + QUIET) * padded + (col + QUIET)] =
                        raw[row * modules + col] == qrcode::Color::Dark;
                }
            }
            padded_grid
        };

        // Render: two QR rows → one terminal row via half-blocks
        let row_count = padded.div_ceil(2);
        let mut lines: Vec<Line> = Vec::with_capacity(row_count + 1);

        for half_row in 0..row_count {
            let top_row = half_row * 2;
            let bot_row = half_row * 2 + 1;

            let mut spans: Vec<Span> = Vec::with_capacity(padded);
            for col in 0..padded {
                let top = top_row < padded && grid[top_row * padded + col];
                let bot = bot_row < padded && grid[bot_row * padded + col];

                let (ch, fg, bg) = match (top, bot) {
                    (true, true) => ('█', self.fg, self.bg),
                    (true, false) => ('▀', self.fg, self.bg),
                    (false, true) => ('▄', self.fg, self.bg),
                    (false, false) => (' ', self.fg, self.bg),
                };
                spans.push(Span::styled(ch.to_string(), Style::default().fg(fg).bg(bg)));
            }
            lines.push(Line::from(spans));
        }

        // Optional caption
        if let Some(cap) = self.caption {
            lines.push(Line::from(Span::styled(cap, palette.muted())));
        }

        // Centre within the allocated area
        let qr_w = padded as u16;
        let qr_h = lines.len() as u16;
        let x = area.x + area.width.saturating_sub(qr_w) / 2;
        let y = area.y + area.height.saturating_sub(qr_h) / 2;

        Paragraph::new(lines).render(
            Rect {
                x,
                y,
                width: qr_w.min(area.width),
                height: qr_h.min(area.height),
            },
            buf,
        );
    }
}
