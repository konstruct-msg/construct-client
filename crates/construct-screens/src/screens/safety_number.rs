//! Safety number verification screen.
//!
//! Shows the safety number the client hands over (the core computes it, the same number iOS
//! shows): 12 groups of 5 decimal digits, displayed in a 4×3 grid.
//! Example:
//!   12345 67890 11234  56789 01234 56789
//!   01234 56789 01234  56789 01234 56789

use crate::theme::ThemeMode;
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Paragraph, Widget},
};

/// Safety number verification overlay.
pub struct SafetyNumberScreen {
    pub theme: ThemeMode,
    pub contact_name: String,
    pub number: String,
}

impl SafetyNumberScreen {
    /// `number` is the client's — the core computes it; this screen only lays it out.
    pub fn new(contact_name: impl Into<String>, number: String) -> Self {
        Self {
            theme: ThemeMode::default(),
            contact_name: contact_name.into(),
            number,
        }
    }

    /// Format the safety number as a 4×3 grid of groups.
    fn formatted_grid(&self) -> Vec<String> {
        let groups: Vec<&str> = self.number.split_whitespace().collect();
        groups.chunks(3).map(|row| row.join("  ")).collect()
    }
}

impl Widget for &SafetyNumberScreen {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let palette = self.theme.palette();
        let outer = palette.panel(format!(" Safety number — {} ", self.contact_name), true);

        let inner = outer.inner(area);
        outer.render(area, buf);

        let mut lines = vec![
            Line::from(Span::styled(
                "  Compare this number with the other person.",
                palette.muted(),
            )),
            Line::from(Span::raw("")),
        ];

        for row in self.formatted_grid() {
            lines.push(Line::from(Span::styled(
                format!("    {}", row),
                Style::default()
                    .fg(palette.warning)
                    .add_modifier(Modifier::BOLD),
            )));
        }

        lines.push(Line::from(Span::raw("")));
        lines.push(Line::from(Span::styled("  [Esc] Back", palette.muted())));

        Paragraph::new(lines)
            .style(palette.surface())
            .render(inner, buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn twelve_groups_lay_out_as_four_rows_of_three() {
        let number = (0..12)
            .map(|i| format!("{i:05}"))
            .collect::<Vec<_>>()
            .join(" ");
        let screen = SafetyNumberScreen::new("alice", number);
        let rows = screen.formatted_grid();
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[0], "00000  00001  00002");
    }
}
