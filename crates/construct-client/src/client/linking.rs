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
        let task = tokio::spawn(async move {
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
        Zeroizing::new(vec![0u8; construct_core::crypto::device_certificate::LINK_SECRET_LEN]);
    rand::rngs::OsRng.fill_bytes(&mut secret);
    let fingerprint =
        hybrid.map(|h| construct_core::history::discovery::qr_fingerprint(identity, h));
    let _ = events.send(ClientEvent::LinkOffer {
        code: link_code(&token, fingerprint.as_ref().map(|f| &f[..]), &secret),
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

/// `konstruct://link?token=…&fp=…&s=…`, as iOS shows it. `fp` pins this device's keys for the
/// new one; `s` is the secret the new device proves its keys under. Neither reaches the server.
pub fn link_code(token: &str, fingerprint: Option<&[u8]>, secret: &[u8]) -> Zeroizing<String> {
    let fp = fingerprint
        .map(|f| format!("&fp={}", hex::encode(f)))
        .unwrap_or_default();
    Zeroizing::new(format!(
        "konstruct://link?token={token}{fp}&s={}",
        hex::encode(secret)
    ))
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn short(id: &str) -> &str {
    &id[..8.min(id.len())]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_shown_here_reads_back_as_the_new_device_reads_it() {
        let secret = [7u8; 32];
        let code = link_code("tok_en-1", Some(&[1u8; 32]), &secret);
        let parsed = crate::device_certs::parse_link_code(&code).expect("a link code");
        assert_eq!(parsed.token, "tok_en-1");
        assert_eq!(parsed.secret.as_deref(), Some(&secret[..]));
        assert!(code.contains(&format!("fp={}", hex::encode([1u8; 32]))));
        let without = link_code("t", None, &secret);
        assert!(!without.contains("fp="));
        assert_eq!(
            crate::device_certs::parse_link_code(&without)
                .unwrap()
                .secret
                .as_deref(),
            Some(&secret[..])
        );
    }
}
