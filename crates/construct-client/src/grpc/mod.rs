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
mod sealed;
mod stream;
pub(crate) mod users;

pub use auth::{
    AuthTokens, JoinRequest, JoinStatus, approve_join_request, authenticate_device,
    check_join_request, confirm_device_link, device_public_keys, get_pow_challenge,
    publish_device_certificate, refresh_token, register_device, submit_join_request,
};
pub use client::GrpcClient;
pub use error::GrpcError;
pub use invite::accept_invite;
#[cfg(test)]
pub(crate) use keys::device_bundles;
pub use keys::{
    FetchedPreKeyBundle, PrekeyUpload, SignedPrekeyRotation, append_one_time_prekeys,
    get_pre_key_bundles, get_prekey_count, get_signed_prekey_age, rotate_signed_prekey,
    upload_prekeys_full,
};
pub use sealed::{
    SenderCertificate, get_sender_certificate, get_server_trust_delegations, send_own_device_copy,
    send_sealed_message,
};
pub use stream::open_message_stream;
pub use users::find_user;
