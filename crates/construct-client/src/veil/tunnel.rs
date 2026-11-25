//! The tunnel: construct-veil's coordinator in this process, one session at a time, its local
//! port where [`crate::grpc::route`] sends the connections.

use std::sync::{Arc, Mutex};

use construct_veil::veil::{
    DialObserver, MethodSet, VeilConfig, VeilCoordinator, VeilFrontAuthV3, VeilFrontObfuscator,
};
use zeroize::Zeroizing;

use super::trust::Front;

pub struct Tunnel {
    coordinator: Arc<VeilCoordinator>,
    /// Who hears what the dials of the session come to: whoever started it last.
    heard: Arc<Mutex<Option<DialObserver>>>,
}

impl Default for Tunnel {
    fn default() -> Self {
        Self::new()
    }
}

impl Tunnel {
    /// A coordinator with veil-front.
    pub fn new() -> Self {
        super::install_chrome_hello();
        let mut coordinator = VeilCoordinator::new(VeilConfig::default());
        coordinator.register(Box::new(VeilFrontObfuscator::new()));
        let heard: Arc<Mutex<Option<DialObserver>>> = Default::default();
        let to = heard.clone();
        coordinator.observe_dials(Arc::new(move |relay, outcome| {
            let observer = to.lock().unwrap_or_else(|e| e.into_inner()).clone();
            if let Some(observer) = observer {
                observer(relay, outcome);
            }
        }));
        Self {
            coordinator: Arc::new(coordinator),
            heard,
        }
    }

    /// Open a session to `front`, ending the one before; the local port gRPC goes to.
    /// `veil_sk` signs the TLS exporter for a key-bound capability (AUTH v3). `on_dial` hears what
    /// each dial of this session comes to, the first one included.
    pub async fn start(
        &self,
        front: &Front,
        veil_sk: &[u8; 32],
        on_dial: DialObserver,
    ) -> Result<u16, String> {
        self.coordinator.stop().await;
        *self.heard.lock().unwrap_or_else(|e| e.into_inner()) = Some(on_dial);
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
}
