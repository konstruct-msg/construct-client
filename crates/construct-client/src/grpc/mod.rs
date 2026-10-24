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
//! - [`media`] — attachment downloads
//! - [`auth`] / [`keys`] / [`users`] — typed RPCs

mod account;
mod auth;
mod client;
mod connection;
mod error;
pub(crate) mod framing;
mod invite;
mod keys;
mod media;
mod paths;
mod sealed;
mod stream;
pub(crate) mod users;

pub use account::{
    Device, delete_account, list_devices, logout, own_username, revoke_device, set_device_metadata,
    set_discoverable, set_username, username_refusal,
};
pub use auth::{
    AuthTokens, JoinRequest, JoinStatus, approve_join_request, authenticate_device,
    check_join_request, confirm_device_link, device_public_keys, get_pow_challenge,
    get_recovery_status, publish_device_certificate, refresh_token, register_device,
    set_recovery_key, submit_join_request,
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
pub use media::{Uploaded, download_media, upload_media};
pub use sealed::{
    SenderCertificate, get_sender_certificate, get_server_trust_delegations, send_own_device_copy,
    send_sealed_message,
};
pub use stream::open_message_stream;
pub use users::find_user;
