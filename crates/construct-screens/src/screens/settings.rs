//! Settings screen — server/transport info, device identity, logout, safety number.

use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{List, ListItem, ListState, Paragraph, StatefulWidget, Widget},
};

use crate::theme::ThemeMode;

/// An action the user triggered from the settings screen.
#[derive(Debug, Clone, PartialEq)]
pub enum SettingsAction {
    CycleTheme,
    /// User pressed [L] — log out, clear session.
    Logout,
    /// User pressed [S] — open safety number view.
    ShowSafetyNumber,
    /// User pressed [E] — export identity keys.
    ExportKeys,
    /// User pressed [Q] — show own identity QR (narrow terminals only).
    ShowMyQr,
    /// User pressed Esc or [B] — go back.
    Back,
}

#[derive(Debug, Clone)]
pub struct SettingsItem {
    label: String,
    value: String,
    action: Option<SettingsAction>,
}

pub struct SettingsScreen {
    pub theme: ThemeMode,
    pub server: String,
    pub transport_label: String,
    pub device_id: String,
    pub user_id: String,
    pub pq_active: bool,
    state: ListState,
    items: Vec<SettingsItem>,
}

impl SettingsScreen {
    pub fn new(
        server: impl Into<String>,
        transport_label: impl Into<String>,
        device_id: impl Into<String>,
        user_id: impl Into<String>,
        pq_active: bool,
    ) -> Self {
        let server = server.into();
        let transport_label = transport_label.into();
        let device_id = device_id.into();
        let user_id = user_id.into();

        let pq_str = if pq_active {
            "yes (Kyber-768)"
        } else {
            "no (classic)"
        };

        let items = vec![
            SettingsItem {
                label: "[T] Theme".into(),
                value: String::new(),
                action: Some(SettingsAction::CycleTheme),
            },
            SettingsItem {
                label: "Server".into(),
                value: server.clone(),
                action: None,
            },
            SettingsItem {
                label: "Transport".into(),
                value: transport_label.clone(),
                action: None,
            },
            SettingsItem {
                label: "Device ID".into(),
                value: device_id.clone(),
                action: None,
            },
            SettingsItem {
                label: "User ID".into(),
                value: user_id.clone(),
                action: None,
            },
            SettingsItem {
                label: "Post-quantum".into(),
                value: pq_str.into(),
                action: None,
            },
            // Separator (empty value)
            SettingsItem {
                label: String::new(),
                value: String::new(),
                action: None,
            },
            // Actions
            SettingsItem {
                label: "[Q] My QR code".into(),
                value: String::new(),
                action: Some(SettingsAction::ShowMyQr),
            },
            SettingsItem {
                label: "[S] Safety number".into(),
                value: String::new(),
                action: Some(SettingsAction::ShowSafetyNumber),
            },
            SettingsItem {
                label: "[E] Export keys".into(),
                value: String::new(),
                action: Some(SettingsAction::ExportKeys),
            },
            SettingsItem {
                label: "[L] Logout".into(),
                value: String::new(),
                action: Some(SettingsAction::Logout),
            },
            SettingsItem {
                label: "[Esc] Back".into(),
                value: String::new(),
                action: Some(SettingsAction::Back),
            },
        ];

        let mut state = ListState::default();
        state.select(Some(0));

        Self {
            theme: ThemeMode::default(),
            server,
            transport_label,
            device_id,
            user_id,
            pq_active,
            state,
            items,
        }
    }

    pub fn next(&mut self) {
        let max = self.items.len().saturating_sub(1);
        let i = self.state.selected().map(|i| (i + 1).min(max)).unwrap_or(0);
        self.state.select(Some(i));
    }

    pub fn prev(&mut self) {
        let i = self
            .state
            .selected()
            .map(|i| i.saturating_sub(1))
            .unwrap_or(0);
        self.state.select(Some(i));
    }

    /// Returns the action for the currently selected item, if any.
    pub fn confirm(&self) -> Option<SettingsAction> {
        self.state
            .selected()
            .and_then(|i| self.items.get(i))
            .and_then(|item| item.action.clone())
    }

    /// Update dynamic values (called after auth or config changes).
    pub fn update(
        &mut self,
        server: impl Into<String>,
        transport_label: impl Into<String>,
        device_id: impl Into<String>,
        user_id: impl Into<String>,
        pq_active: bool,
    ) {
        *self = Self::new(server, transport_label, device_id, user_id, pq_active);
    }
}

impl Widget for &mut SettingsScreen {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let palette = self.theme.palette();
        let outer = palette.panel(" Settings ", true);

        let inner = outer.inner(area);
        outer.render(area, buf);

        // On wide terminals (≥ 100 cols) split: settings list | identity QR
        if area.width >= 100 {
            let cols =
                Layout::horizontal([Constraint::Min(50), Constraint::Length(36)]).split(inner);
            self.render_list(cols[0], buf);
            self.render_identity_qr(cols[1], buf);
        } else {
            self.render_list(inner, buf);
        }
    }
}

impl SettingsScreen {
    fn render_list(&mut self, area: Rect, buf: &mut Buffer) {
        let palette = self.theme.palette();
        // Header hint
        let chunks = Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).split(area);
        let hint = Paragraph::new(Line::from(Span::styled(
            "  ↑↓ navigate  Enter=select  Esc=back",
            Style::default().fg(palette.muted),
        )));
        hint.render(chunks[0], buf);

        let items: Vec<ListItem> = self
            .items
            .iter()
            .map(|item| {
                if item.label.is_empty() {
                    // Separator row
                    ListItem::new(Line::from(Span::styled(
                        "  ─────────────────────────────────────────",
                        Style::default().fg(palette.muted),
                    )))
                } else if item.action.is_some() {
                    // Action row
                    let color = if item.label.contains("Logout") {
                        palette.danger
                    } else {
                        palette.accent
                    };
                    let value = if item.action == Some(SettingsAction::CycleTheme) {
                        format!("  {}", self.theme.label())
                    } else {
                        String::new()
                    };
                    ListItem::new(Line::from(Span::styled(
                        format!("  {}{}", item.label, value),
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    )))
                } else {
                    // Info row: label  value
                    let label = Span::styled(
                        format!("  {:<16}", item.label),
                        Style::default().fg(palette.muted),
                    );
                    let value = Span::styled(&item.value, Style::default().fg(palette.foreground));
                    ListItem::new(Line::from(vec![label, value]))
                }
            })
            .collect();

        let list = List::new(items)
            .style(palette.surface())
            .highlight_style(palette.selected().add_modifier(Modifier::BOLD))
            .highlight_symbol("▸ ");

        let mut state = self.state;
        StatefulWidget::render(list, chunks[1], buf, &mut state);
        self.state = state;
    }

    fn render_identity_qr(&mut self, area: Rect, buf: &mut Buffer) {
        let palette = self.theme.palette();
        let block = palette.panel(" My device ", false);
        let inner = block.inner(area);
        block.render(area, buf);

        let hint = vec![
            Line::from(Span::styled(
                &self.user_id,
                Style::default().fg(palette.foreground),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "Press [Q] to show",
                Style::default().fg(palette.muted),
            )),
            Line::from(Span::styled(
                "scannable QR code",
                Style::default().fg(palette.muted),
            )),
        ];
        Paragraph::new(hint)
            .style(palette.surface())
            .render(inner, buf);
    }
}
