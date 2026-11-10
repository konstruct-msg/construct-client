//! The name a person is shown by, and the one generated for a person who chose none.
//!
//! The rules live in the core now, once for every client (construct-rules `names`, through
//! `construct_core::rule_state`; construct-docs `decisions/client-rules-shared-in-rust.md`). They
//! were written here, on iOS and on Android, and had drifted in whitespace and an empty alias.
//! `resolved` keeps its name for the callers here; the core calls it `shown`.

pub use construct_core::rule_state::names::{generated, is_generated, shown as resolved};
