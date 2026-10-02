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
