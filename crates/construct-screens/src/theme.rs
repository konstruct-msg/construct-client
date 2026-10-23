//! Visual tokens shared by every terminal screen.

use ratatui::{
    style::{Color, Modifier, Style},
    widgets::{Block, Borders},
};
use serde::{Deserialize, Serialize};

/// Konstruct blue. Text accents use theme-specific shades for legibility.
pub const BRAND_BLUE: Color = Color::Rgb(0, 140, 255); // #008CFF

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThemeMode {
    #[default]
    Phosphor,
    Paper,
}

impl ThemeMode {
    pub fn next(self) -> Self {
        match self {
            Self::Phosphor => Self::Paper,
            Self::Paper => Self::Phosphor,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Phosphor => "Phosphor",
            Self::Paper => "Paper",
        }
    }

    pub fn palette(self) -> Palette {
        match self {
            Self::Phosphor => Palette {
                background: Color::Rgb(6, 32, 56),
                panel: Color::Rgb(11, 48, 75),
                foreground: Color::Rgb(234, 242, 244),
                muted: Color::Rgb(122, 157, 176),
                border: Color::Rgb(82, 125, 144),
                accent: Color::Rgb(84, 180, 255),
                selection: BRAND_BLUE,
                selection_text: Color::Rgb(3, 30, 30),
                success: Color::Rgb(55, 193, 113),
                warning: Color::Rgb(236, 193, 72),
                danger: Color::Rgb(255, 107, 107),
            },
            Self::Paper => Palette {
                background: Color::Rgb(224, 225, 226),
                panel: Color::Rgb(241, 241, 240),
                foreground: Color::Rgb(26, 29, 31),
                muted: Color::Rgb(103, 108, 111),
                border: Color::Rgb(62, 67, 69),
                accent: Color::Rgb(0, 98, 179),
                selection: BRAND_BLUE,
                selection_text: Color::Rgb(3, 30, 30),
                success: Color::Rgb(0, 111, 62),
                warning: Color::Rgb(139, 91, 0),
                danger: Color::Rgb(174, 37, 52),
            },
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Palette {
    pub background: Color,
    pub panel: Color,
    pub foreground: Color,
    pub muted: Color,
    pub border: Color,
    pub accent: Color,
    pub selection: Color,
    pub selection_text: Color,
    pub success: Color,
    pub warning: Color,
    pub danger: Color,
}

impl Palette {
    pub fn canvas(self) -> Style {
        Style::default().fg(self.foreground).bg(self.background)
    }

    pub fn surface(self) -> Style {
        Style::default().fg(self.foreground).bg(self.panel)
    }

    pub fn text(self) -> Style {
        Style::default().fg(self.foreground)
    }

    pub fn muted(self) -> Style {
        Style::default().fg(self.muted)
    }

    pub fn emphasis(self) -> Style {
        Style::default()
            .fg(self.accent)
            .add_modifier(Modifier::BOLD)
    }

    pub fn state(self, error: bool) -> Style {
        Style::default()
            .fg(if error { self.danger } else { self.success })
            .add_modifier(Modifier::BOLD)
    }

    pub fn border(self, focused: bool) -> Style {
        Style::default()
            .fg(if focused { BRAND_BLUE } else { self.border })
            .bg(self.panel)
    }

    pub fn selected(self) -> Style {
        Style::default().fg(self.selection_text).bg(self.selection)
    }

    pub fn panel(self, title: impl Into<String>, focused: bool) -> Block<'static> {
        Block::default()
            .title(title.into())
            .borders(Borders::ALL)
            .border_style(self.border(focused))
            .style(self.surface())
    }
}

// ── Persistence ───────────────────────────────────────────────────────────────

/// Front-end preferences, beside the client's own config in the same directory. Until
/// 2026-10-02 the theme was a field of the client's `config.json`; the client crate knows no
/// theme, so it lives in its own file now (an old `config.json` theme is not carried over).
#[derive(Debug, Default, Serialize, Deserialize)]
struct UiPrefs {
    #[serde(default)]
    theme: ThemeMode,
}

fn prefs_path() -> anyhow::Result<std::path::PathBuf> {
    Ok(construct_client::config::config_dir()?.join("ui.json"))
}

/// The saved theme, or the default when there is none or it cannot be read.
pub fn load_theme() -> ThemeMode {
    prefs_path()
        .ok()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str::<UiPrefs>(&s).ok())
        .map(|p| p.theme)
        .unwrap_or_default()
}

pub fn save_theme(theme: ThemeMode) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(&UiPrefs { theme })?;
    std::fs::write(prefs_path()?, json)?;
    Ok(())
}
