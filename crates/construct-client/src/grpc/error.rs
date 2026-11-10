//! Errors for the gRPC-over-H2 client.
//!
//! Kept as a dedicated type so this module can move to its own crate without
//! dragging `anyhow` into the public surface.

use construct_core::rule_state::device_refusal;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GrpcError {
    #[error("transport: {0}")]
    Transport(String),
    #[error("tls: {0}")]
    Tls(String),
    #[error("grpc {code}: {message}")]
    Status { code: u32, message: String },
    /// `refusal`: the first value of `construct-device-refusal` the status carried, if any — the
    /// server's number for why it refused this device (construct-protos `DeviceRefusal`).
    #[error("unauthenticated: {message}")]
    Unauthenticated {
        message: String,
        refusal: Option<String>,
    },
    #[error("permission denied: {0}")]
    PermissionDenied(String),
}

impl GrpcError {
    pub fn transport(msg: impl ToString) -> Self {
        Self::Transport(msg.to_string())
    }

    pub fn tls(msg: impl ToString) -> Self {
        Self::Tls(msg.to_string())
    }

    pub fn status(code: u32, message: impl ToString) -> Self {
        Self::Status {
            code,
            message: message.to_string(),
        }
    }

    pub fn unauthenticated(msg: impl ToString) -> Self {
        Self::Unauthenticated {
            message: msg.to_string(),
            refusal: None,
        }
    }

    /// UNAUTHENTICATED with the server's refusal number, as `check_grpc_status` reads it.
    pub fn refused(msg: impl ToString, refusal: Option<String>) -> Self {
        Self::Unauthenticated {
            message: msg.to_string(),
            refusal,
        }
    }

    pub fn permission_denied(msg: impl ToString) -> Self {
        Self::PermissionDenied(msg.to_string())
    }

    pub fn is_unauthenticated(&self) -> bool {
        matches!(
            self,
            Self::Unauthenticated { .. } | Self::Status { code: 16, .. }
        )
    }

    /// Why the server refused this device, as the core reads it: the number on UNAUTHENTICATED,
    /// never the text (construct-rules `device_refusal`, todo 292). Whether it erases the device
    /// also depends on the path — `erases_device`.
    pub fn device_refusal(&self) -> device_refusal::Refusal {
        match self {
            Self::Unauthenticated { refusal, .. } => {
                device_refusal::refusal(device_refusal::UNAUTHENTICATED, refusal.as_deref())
            }
            Self::Status { code, .. } => device_refusal::refusal(*code, None),
            _ => device_refusal::Refusal::Unspecified,
        }
    }

    /// The server deactivated this device (`RevokeDevice` from another device of the account, or
    /// its `Logout`) and said so over direct TLS: the one signal that wipes it
    /// (decisions/sign-out-wipes-the-device.md). Until todo 292 this read the text "Device is
    /// inactive" and ignored the path, so a VEIL relay (h2c) could wipe the device.
    pub fn erases_device(&self, over_direct_tls: bool) -> bool {
        device_refusal::erases_device(self.device_refusal(), over_direct_tls)
    }

    pub fn is_permission_denied(&self) -> bool {
        matches!(
            self,
            Self::PermissionDenied(_) | Self::Status { code: 7, .. }
        )
    }

    /// Transport failure — retry on a fresh connection. Not an auth signal.
    pub fn is_retryable_transport(&self) -> bool {
        matches!(self, Self::Transport(_) | Self::Tls(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The number decides, over direct TLS only; the text is no reason (todo 292).
    /// Mutations that redden it: read the text again; drop the path.
    #[test]
    fn only_the_removed_number_over_direct_tls_erases() {
        let removed = GrpcError::refused("Device is inactive", Some("1".into()));
        assert!(removed.erases_device(true));
        assert!(
            !removed.erases_device(false),
            "through VEIL a relay could forge it"
        );
        assert!(
            !GrpcError::refused("Device is inactive", None).erases_device(true),
            "the text alone"
        );
        assert!(!GrpcError::refused("Device not found", Some("2".into())).erases_device(true));
        assert!(!GrpcError::status(16, "Device is inactive").erases_device(true));
        assert!(!GrpcError::status(7, "Device is inactive").erases_device(true));
        assert!(!GrpcError::transport("Device is inactive").erases_device(true));
    }

    #[test]
    fn transport_is_not_unauthenticated() {
        let e = GrpcError::transport("connection reset");
        assert!(!e.is_unauthenticated());
        assert!(!e.is_permission_denied());
        assert!(e.is_retryable_transport());
    }

    #[test]
    fn status_16_is_unauthenticated() {
        let e = GrpcError::status(16, "expired");
        assert!(e.is_unauthenticated());
        assert!(!e.is_retryable_transport());
    }
}
