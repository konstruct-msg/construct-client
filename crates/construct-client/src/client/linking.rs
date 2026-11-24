//! A new device linked from this one (Flow A, iOS "Link new device"): the server hands out a
//! token, this device shows it in a code with a secret of its own, the new device presents the
//! token with its keys and a proof under the secret, and this device vouches for those keys
//! (`decisions/devices-of-an-account-sign-each-other.md`).

use std::time::Duration;

use rand::RngCore;
use zeroize::Zeroizing;

use super::{Client, ClientCommand, ClientEvent, Inbox};
use crate::device_certs::Evidence;
use crate::grpc::{GrpcClient, LinkResult};

/// How often the server is asked whether a device used the token (iOS: 3 s).
const POLL: Duration = Duration::from_secs(3);

impl Client {
    pub(super) fn offer_link(&mut self) {
        self.cancel_link_offer();
        let (Some(identity), Some(orchestrator)) =
            (self.our_identity_key.clone(), self.orch_handle.clone())
        else {
            return self.emit(ClientEvent::LinkOfferEnded(Err("not signed in".into())));
        };
        let hybrid = self.our_hybrid_key.clone();
        let grpc = self.grpc.clone();
        let (events, inbox) = (self.events.clone(), self.inbox.clone());
        let directory_change = orchestrator.changing_own_devices();
        let task = tokio::spawn(async move {
            let _directory_change = directory_change;
            let ended = offer(
                &grpc,
                &events,
                &identity,
                hybrid.as_deref(),
                |device_id, evidence| orchestrator.vouch(device_id, evidence),
            )
            .await;
            match &ended {
                Ok(device_id) => {
                    tracing::info!(device = %short(device_id), "device linked from here")
                }
                Err(e) => tracing::warn!("link offer ended: {e}"),
            }
            let linked = ended.is_ok();
            let _ = events.send(ClientEvent::LinkOfferEnded(ended));
            if linked {
                let _ = inbox.send(Inbox::Command(ClientCommand::LoadSettings));
            }
        });
        self.offer_task = Some(task.abort_handle());
    }

    pub(super) fn cancel_link_offer(&mut self) {
        if let Some(task) = self.offer_task.take() {
            task.abort();
        }
    }
}

async fn offer(
    grpc: &GrpcClient,
    events: &tokio::sync::mpsc::UnboundedSender<ClientEvent>,
    identity: &[u8],
    hybrid: Option<&[u8]>,
    vouch: impl FnOnce(String, Evidence),
) -> Result<String, String> {
    let (token, expires_at) = crate::grpc::initiate_device_link(grpc)
        .await
        .map_err(|e| format!("no link code: {e}"))?;
    let mut secret =
        Zeroizing::new([0u8; construct_core::crypto::device_certificate::LINK_SECRET_LEN]);
    rand::rngs::OsRng.fill_bytes(&mut secret[..]);
    let fingerprint =
        hybrid.map(|h| construct_core::history::discovery::qr_fingerprint(identity, h));
    let _ = events.send(ClientEvent::LinkOffer {
        code: Zeroizing::new(construct_core::device_link_qr::offer(
            &token,
            fingerprint.as_ref(),
            &secret,
        )),
        expires_at,
    });
    loop {
        tokio::time::sleep(POLL).await;
        if now_secs() > expires_at {
            return Err("the code expired".into());
        }
        match crate::grpc::device_link_result(grpc, &token).await {
            Ok(LinkResult::Pending) => {}
            Ok(LinkResult::Confirmed { device_id, proof }) => {
                vouch(
                    device_id.clone(),
                    Evidence::QrSecret {
                        secret: secret.to_vec(),
                        proof,
                    },
                );
                return Ok(device_id);
            }
            Ok(LinkResult::Expired) => return Err("the code expired".into()),
            Err(e) => tracing::info!("link result not read, asking again: {e}"),
        }
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn short(id: &str) -> &str {
    &id[..8.min(id.len())]
}
