//! The Konstruct client layer: everything a Konstruct client is apart from how it is shown —
//! the account and its keys, the core's Orchestrator, the message stream, storage, contacts and
//! invites.
//!
//! A front end starts it with [`spawn`], sends [`ClientCommand`]s through the returned
//! [`ClientHandle`] and reads [`ClientEvent`]s. The terminal UI (`konstruct`) is the first front
//! end; a desktop window is meant to be the second
//! (`decisions/desktop-is-the-tui-client-with-a-second-shell.md`). Nothing in this crate knows
//! either: it has no front-end dependency, and a test fails if one is added.

pub mod auth;
pub mod bridge;
pub mod config;
mod grpc;
mod invite;
mod knst;
mod orchestrator_task;
mod proto;
pub mod storage;
mod streaming;

mod client;
pub use client::*;

#[cfg(test)]
mod tests {
    /// The boundary is the dependency list: a front-end crate here would let client code draw.
    #[test]
    fn the_client_crate_depends_on_no_front_end() {
        let manifest = include_str!("../Cargo.toml");
        let dependencies = manifest
            .split("[dependencies]")
            .nth(1)
            .expect("a [dependencies] table");
        for front_end in [
            "ratatui",
            "crossterm",
            "tauri",
            "egui",
            "iced",
            "slint",
            "winit",
        ] {
            assert!(
                !dependencies
                    .lines()
                    .any(|l| l.trim_start().starts_with(front_end)),
                "construct-client depends on `{front_end}`"
            );
        }
    }
}
