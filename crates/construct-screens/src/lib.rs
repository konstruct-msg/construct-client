//! The Konstruct screens: what is shown and what a key does, for every shell.
//!
//! [`App`] owns the screens and a running `construct-client`. A shell gives it keys and pastes,
//! waits on [`App::wake`] for the client's events, and draws [`App::render`] into whatever
//! surface it has — the terminal (`construct-tui`) or the character grid in the desktop window
//! (`construct-desktop`). Neither shell decides anything shown here.

mod app;
mod screens;
mod theme;

pub use app::{App, AppConfig, Wake};
pub use theme::{ThemeMode, load_theme};
