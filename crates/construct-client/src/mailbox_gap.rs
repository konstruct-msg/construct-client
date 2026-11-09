//! Messages the server's queue trimmed before this device collected them: the notice above the
//! chat list (construct-docs `decisions/mailbox-gap-is-reported.md`).
//!
//! The rule lives in the core now, once for every client (`construct-rules`, through
//! `construct_core::rule_state`; `decisions/client-rules-shared-in-rust.md`). It was written here
//! first and moved there as it was; iOS and Android, which had kept only the dates and showed a
//! closed notice again on every connection, call the same code (todo 290).

pub use construct_core::rule_state::mailbox_gap::*;
