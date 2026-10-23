//! Connection state tracking and status bar widget.

use std::time::{Duration, Instant};

use crate::theme::ThemeMode;
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Paragraph, Widget},
};

/// Live connection state — updated by the streaming worker via InternalEvent.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub enum ConnectionState {
    /// Not yet connected (startup).
    #[default]
    Disconnected,
    /// Currently establishing the connection.
    Connecting { transport: String },
    /// Fully connected.
    Connected {
        transport: String,
        latency_ms: Option<u32>,
    },
    /// Lost connection, trying to restore.
    Reconnecting {
        attempt: u32,
        next_retry: Instant,
        interval: Duration,
    },
}

impl ConnectionState {
    /// Short human-readable label for the status bar.
    pub fn label(&self) -> String {
        match self {
            Self::Disconnected => "✗ disconnected".into(),
            Self::Connecting { transport } => format!("⠋ connecting ({transport})…"),
            Self::Connected {
                transport,
                latency_ms: Some(ms),
            } => {
                format!("● {transport}  {ms}ms")
            }
            Self::Connected {
                transport,
                latency_ms: None,
            } => {
                format!("● {transport}")
            }
            Self::Reconnecting {
                attempt,
                next_retry,
                interval,
            } => {
                let secs_left = next_retry
                    .saturating_duration_since(Instant::now())
                    .as_secs();
                let _ = interval; // used for display elsewhere
                format!("↺ reconnecting (attempt {attempt}, retry in {secs_left}s)")
            }
        }
    }
}

/// Single-line status bar rendered at the bottom of the main view.
pub struct StatusBar<'a> {
    pub connection: &'a ConnectionState,
    pub status_text: &'a str,
    pub unread_count: usize,
    pub pq_active: bool,
    pub theme: ThemeMode,
}

impl Widget for StatusBar<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let conn_label = self.connection.label();
        let palette = self.theme.palette();
        let conn_color = match self.connection {
            ConnectionState::Connected { .. } => palette.success,
            ConnectionState::Connecting { .. } => palette.accent,
            ConnectionState::Reconnecting { .. } => palette.warning,
            ConnectionState::Disconnected => palette.danger,
        };

        let pq_badge = if self.pq_active {
            Span::styled(" [PQ] ", Style::default().fg(palette.accent))
        } else {
            Span::raw("")
        };

        let unread = if self.unread_count > 0 {
            Span::styled(
                format!(" {} unread ", self.unread_count),
                Style::default().fg(palette.warning),
            )
        } else {
            Span::raw("")
        };

        let sep = Span::styled(" │ ", Style::default().fg(palette.border));

        let line = Line::from(vec![
            Span::styled(" ", Style::default()),
            Span::styled(&conn_label, Style::default().fg(conn_color)),
            pq_badge,
            sep.clone(),
            unread,
            sep,
            Span::styled(self.status_text, Style::default().fg(palette.muted)),
        ]);

        Paragraph::new(line)
            .style(Style::default().bg(palette.background))
            .render(area, buf);
    }
}
