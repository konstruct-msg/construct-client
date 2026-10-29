//! The tunnel: construct-veil's coordinator in this process, one session at a time, its local
//! port where [`crate::grpc::route`] sends the connections.

use std::path::Path;
use std::sync::Arc;

use construct_veil::veil::{
    MethodSet, NetworkFingerprint, PersistentScores, VeilConfig, VeilCoordinator, VeilFrontAuthV3,
    VeilFrontObfuscator,
};
use zeroize::Zeroizing;

use super::trust::Front;

/// The coordinator scores methods per network; a desktop has one method and no network label
/// worth keeping apart, so all its networks are one.
const NETWORK: &[u8] = b"desktop";

pub struct Tunnel {
    coordinator: Arc<VeilCoordinator>,
}

impl Tunnel {
    /// A coordinator with veil-front, scoring kept in `scores` (a file of its own beside the
    /// data; `None`: in memory).
    pub async fn new(scores: Option<&Path>) -> Result<Self, String> {
        super::install_chrome_hello();
        let path = scores.map_or(":memory:".to_owned(), |p| p.display().to_string());
        let scores = PersistentScores::open_default(&path)
            .await
            .map_err(|e| format!("VEIL scores: {e}"))?;
        let mut coordinator = VeilCoordinator::new(VeilConfig::default(), scores);
        coordinator.register(Box::new(VeilFrontObfuscator::new()));
        Ok(Self {
            coordinator: Arc::new(coordinator),
        })
    }

    /// Open a session to `front`, ending the one before; the local port gRPC goes to.
    /// `veil_sk` signs the TLS exporter for a key-bound capability (AUTH v3).
    pub async fn start(&self, front: &Front, veil_sk: &[u8; 32]) -> Result<u16, String> {
        self.coordinator.stop().await;
        let (ticket, auth_v3) = match front.version {
            2 => (
                String::new(),
                VeilFrontAuthV3 {
                    capability_v2_b64: front.capability.clone(),
                    veil_sk_hex: Zeroizing::new(hex::encode(veil_sk)).to_string(),
                },
            ),
            _ => (front.capability.clone(), VeilFrontAuthV3::default()),
        };
        let started = self
            .coordinator
            .start_session_with_params(
                front.relay.clone(),
                NetworkFingerprint::new(NETWORK.to_vec()),
                MethodSet::all(),
                front.sni.clone(),
                front.spki.clone(),
                ticket,
                auth_v3,
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(started.port)
    }

    pub async fn stop(&self) {
        self.coordinator.stop().await;
    }

    pub async fn is_alive(&self) -> bool {
        self.coordinator.is_alive().await
    }
}
