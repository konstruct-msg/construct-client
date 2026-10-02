//! gRPC-over-HTTP/2 client for Konstruct.
//!
//! Production talks to `ams.konstruct.cc` the same way iOS does (TCP/TLS/H2,
//! system-root certs). QUIC/H3 is a different host (`quic.konstruct.cc`) with a
//! pinned gateway cert and is not this module.
//!
//! Screens and `app.rs` must not import `h2`/`rustls`. A later Linux/Windows
//! GUI can lift this directory into its own crate.
//!
//! Layout:
//! - [`client`] — connection, unary, token
//! - [`stream`] — MessageStream bidi
//! - [`auth`] / [`keys`] / [`users`] — typed RPCs

mod auth;
mod client;
mod connection;
mod error;
pub(crate) mod framing;
mod invite;
mod keys;
mod paths;
mod stream;
pub(crate) mod users;

pub use auth::{
    authenticate_device, confirm_device_link, device_public_keys, get_pow_challenge, refresh_token,
    register_device,
};
pub use client::GrpcClient;
pub use invite::accept_invite;
pub use keys::{FetchedPreKeyBundle, get_pre_key_bundle, upload_pre_keys};
pub use stream::open_message_stream;
pub use users::find_user;
