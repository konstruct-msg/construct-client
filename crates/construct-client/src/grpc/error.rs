//! Errors for the gRPC-over-H2 client.
//!
//! Kept as a dedicated type so this module can move to its own crate without
//! dragging `anyhow` into the public surface.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum GrpcError {
    #[error("transport: {0}")]
    Transport(String),
    #[error("tls: {0}")]
    Tls(String),
    #[error("grpc {code}: {message}")]
    Status { code: u32, message: String },
    #[error("unauthenticated: {0}")]
    Unauthenticated(String),
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
        Self::Unauthenticated(msg.to_string())
    }

    pub fn permission_denied(msg: impl ToString) -> Self {
        Self::PermissionDenied(msg.to_string())
    }

    pub fn is_unauthenticated(&self) -> bool {
        matches!(
            self,
            Self::Unauthenticated(_) | Self::Status { code: 16, .. }
        )
    }

    /// The server deactivated this device (`RevokeDevice` from another device of the account, or
    /// its `Logout`): the one signal that wipes it (decisions/sign-out-wipes-the-device.md). Any
    /// other refusal — "Device not found" too, which a server that lost rows also says — is not.
    pub fn is_device_removed(&self) -> bool {
        match self {
            Self::Unauthenticated(m)
            | Self::Status {
                code: 16,
                message: m,
            } => m.trim() == "Device is inactive",
            _ => false,
        }
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

    #[test]
    fn only_an_inactive_device_reads_as_removed() {
        assert!(GrpcError::status(16, "Device is inactive").is_device_removed());
        assert!(GrpcError::unauthenticated("Device is inactive").is_device_removed());
        // A server that lost its rows says this too; a wipe on it would be a false alarm.
        assert!(!GrpcError::status(16, "Device not found").is_device_removed());
        assert!(!GrpcError::status(7, "Device is inactive").is_device_removed());
        assert!(!GrpcError::transport("Device is inactive").is_device_removed());
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
