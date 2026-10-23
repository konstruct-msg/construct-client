use crate::theme::ThemeMode;
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{List, ListItem, ListState, StatefulWidget, Widget},
};

#[derive(Debug, Clone)]
pub struct Contact {
    pub id: String,
    pub display_name: String,
    pub unread: usize,
    pub last_message: Option<String>,
}

pub struct ChatListPane {
    pub contacts: Vec<Contact>,
    pub state: ListState,
    pub focused: bool,
    pub theme: ThemeMode,
}

impl ChatListPane {
    pub fn new() -> Self {
        let mut state = ListState::default();
        state.select(None);
        Self {
            contacts: Vec::new(),
            state,
            focused: true,
            theme: ThemeMode::default(),
        }
    }

    /// Replace the full contacts list (called after loading from DB on login).
    pub fn set_contacts(&mut self, contacts: Vec<Contact>) {
        self.contacts = contacts;
        if !self.contacts.is_empty() {
            self.state.select(Some(0));
        } else {
            self.state.select(None);
        }
    }

    /// Append a single newly-added contact.
    pub fn add_contact(&mut self, contact: Contact) {
        self.contacts.push(contact);
        if self.state.selected().is_none() {
            self.state.select(Some(0));
        }
    }

    pub fn next(&mut self) {
        let i = self
            .state
            .selected()
            .map(|i| (i + 1).min(self.contacts.len().saturating_sub(1)));
        self.state.select(i);
    }

    pub fn prev(&mut self) {
        let i = self.state.selected().map(|i| i.saturating_sub(1));
        self.state.select(i);
    }

    pub fn selected_contact(&self) -> Option<&Contact> {
        self.state.selected().and_then(|i| self.contacts.get(i))
    }

    /// Remove the contact at `index`. Adjusts selection so it stays in-bounds.
    pub fn remove_at(&mut self, index: usize) {
        if index >= self.contacts.len() {
            return;
        }
        self.contacts.remove(index);
        let new_sel = if self.contacts.is_empty() {
            None
        } else {
            Some(index.min(self.contacts.len() - 1))
        };
        self.state.select(new_sel);
    }
}

impl StatefulWidget for &mut ChatListPane {
    type State = ListState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut ListState) {
        let palette = self.theme.palette();
        let preview_width = area.width.saturating_sub(6) as usize;

        let items: Vec<ListItem> = self
            .contacts
            .iter()
            .map(|c| {
                let badge = if c.unread > 0 {
                    Span::styled(
                        format!(" [{}]", c.unread),
                        Style::default()
                            .fg(palette.warning)
                            .add_modifier(Modifier::BOLD),
                    )
                } else {
                    Span::raw("")
                };
                let name = Span::styled(
                    &c.display_name,
                    Style::default().add_modifier(Modifier::BOLD),
                );
                let preview = if let Some(last) = &c.last_message {
                    let truncated = if last.chars().count() > preview_width {
                        format!(
                            "{}…",
                            last.chars()
                                .take(preview_width.saturating_sub(1))
                                .collect::<String>()
                        )
                    } else {
                        last.clone()
                    };
                    Span::styled(
                        format!("  {}", truncated),
                        Style::default().fg(palette.muted),
                    )
                } else {
                    Span::raw("")
                };
                ListItem::new(vec![
                    Line::from(vec![name, badge]),
                    Line::from(vec![preview]),
                ])
                .style(palette.surface())
            })
            .collect();

        let list = List::new(items)
            .block(palette.panel(" Chats ", self.focused))
            .highlight_style(palette.selected().add_modifier(Modifier::BOLD))
            .highlight_symbol("▸ ");

        StatefulWidget::render(list, area, buf, state);
    }
}

impl Widget for &mut ChatListPane {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let mut state = self.state;
        StatefulWidget::render(self, area, buf, &mut state);
    }
}
