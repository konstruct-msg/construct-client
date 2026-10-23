use crate::theme::ThemeMode;
use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Paragraph, Widget, Wrap},
};

#[derive(Debug, Clone, PartialEq)]
pub enum MessageKind {
    Sent,
    Received,
}

#[derive(Debug, Clone)]
pub struct ChatMessage {
    pub id: String,
    pub kind: MessageKind,
    pub text: String,
    pub time: String,
}

pub struct ChatViewPane {
    pub contact_name: String,
    pub messages: Vec<ChatMessage>,
    pub compose: String,
    pub focused: bool,
    pub compose_focused: bool,
    pub theme: ThemeMode,
    /// How many messages to skip from the bottom (0 = show latest).
    scroll_offset: usize,
}

impl ChatViewPane {
    pub fn new(contact_name: impl Into<String>) -> Self {
        Self {
            contact_name: contact_name.into(),
            messages: Vec::new(),
            compose: String::new(),
            focused: false,
            compose_focused: false,
            theme: ThemeMode::default(),
            scroll_offset: 0,
        }
    }

    pub fn push_char(&mut self, c: char) {
        self.compose.push(c);
    }

    pub fn pop_char(&mut self) {
        self.compose.pop();
    }

    pub fn take_compose(&mut self) -> String {
        std::mem::take(&mut self.compose)
    }

    /// Scroll up by `n` messages (older messages).
    pub fn scroll_up(&mut self, n: usize) {
        let max_offset = self.messages.len().saturating_sub(1);
        self.scroll_offset = (self.scroll_offset + n).min(max_offset);
    }

    /// Scroll down by `n` messages (newer messages).
    pub fn scroll_down(&mut self, n: usize) {
        self.scroll_offset = self.scroll_offset.saturating_sub(n);
    }

    /// Jump to the oldest message.
    pub fn scroll_to_top(&mut self) {
        self.scroll_offset = self.messages.len().saturating_sub(1);
    }

    /// Jump to the latest message (default view).
    pub fn scroll_to_bottom(&mut self) {
        self.scroll_offset = 0;
    }

    /// Reset scroll when a new message arrives (auto-scroll to bottom, unless the user scrolled up).
    pub fn on_new_message(&mut self) {
        if self.scroll_offset == 0 {
            // Already at bottom — keep it that way.
        } else {
            // User is reading history — don't auto-scroll, just bump offset so they stay in place.
            self.scroll_offset += 1;
        }
    }
}

impl Widget for &mut ChatViewPane {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let palette = self.theme.palette();
        let outer = palette.panel(
            format!(" {} ", self.contact_name),
            self.focused || self.compose_focused,
        );

        let inner = outer.inner(area);
        outer.render(area, buf);

        // Split inner: messages area + compose bar
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1), Constraint::Length(3)])
            .split(inner);

        let msg_area_height = chunks[0].height as usize;
        let total = self.messages.len();

        // Determine the visible window.
        // scroll_offset=0 → show the last N messages.
        let end = total.saturating_sub(self.scroll_offset);
        let start = end.saturating_sub(msg_area_height);

        let visible = &self.messages[start..end];

        // Scroll indicator (shown when not at the latest).
        let scroll_hint = if self.scroll_offset > 0 {
            Some(format!(
                "  ↑ {} older  PgUp/PgDn  End=latest",
                self.scroll_offset
            ))
        } else {
            None
        };

        let mut msg_lines: Vec<Line> = visible
            .iter()
            .map(|m| {
                if m.kind == MessageKind::Sent {
                    let time =
                        Span::styled(format!("[{}] ", m.time), Style::default().fg(palette.muted));
                    let text = Span::styled(
                        &m.text,
                        Style::default()
                            .fg(palette.foreground)
                            .add_modifier(Modifier::BOLD),
                    );
                    Line::from(vec![Span::raw("  "), text, Span::raw("  "), time])
                } else {
                    let time =
                        Span::styled(format!("[{}] ", m.time), Style::default().fg(palette.muted));
                    let text = Span::styled(&m.text, Style::default().fg(palette.accent));
                    Line::from(vec![time, text])
                }
            })
            .collect();

        // Append scroll hint at the bottom if scrolled up.
        if let Some(hint) = scroll_hint {
            msg_lines.push(Line::from(Span::styled(
                hint,
                Style::default().fg(palette.warning),
            )));
        }

        Paragraph::new(msg_lines)
            .wrap(Wrap { trim: false })
            .style(palette.surface())
            .render(chunks[0], buf);

        // Compose box
        let compose_text = if self.compose.is_empty() && !self.compose_focused {
            "Write a message…".to_owned()
        } else {
            format!("{}_", self.compose)
        };
        Paragraph::new(compose_text)
            .block(palette.panel(" Message ", self.compose_focused))
            .style(palette.surface())
            .render(chunks[1], buf);
    }
}
