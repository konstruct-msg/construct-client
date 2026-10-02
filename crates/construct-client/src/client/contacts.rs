//! People: username search, invite redemption, adding and removing, and the contact set the
//! message stream is subscribed for.

use super::{Client, ClientEvent, Inbox};
use crate::storage::StoredContact;

/// One FindUser hit.
#[derive(Debug, Clone)]
pub struct SearchResult {
    pub user_id: String,
    pub username: String,
    pub display_name: String,
}

/// What a [`ClientCommand::FindContact`](super::ClientCommand::FindContact) started.
pub enum FindStarted {
    UsernameSearch,
    InviteRedemption,
}

impl Client {
    /// Look a person up: an invite link is redeemed, anything else is a username search.
    /// What started arrives as [`ClientEvent::SearchStarted`], results as `ContactSearchResult`
    /// / `ContactAdded` / `ContactSearchError`.
    pub(super) fn find_contact(&self, raw: &str) {
        let raw = raw.trim();
        if crate::invite::looks_like_invite(raw) {
            return match self.redeem_invite(raw) {
                Ok(()) => self.emit(ClientEvent::SearchStarted(FindStarted::InviteRedemption)),
                Err(e) => self.emit(ClientEvent::ContactSearchError(e)),
            };
        }
        let query = crate::grpc::users::normalize_username(raw);
        if !crate::grpc::users::username_is_searchable(&query) {
            return self.emit(ClientEvent::ContactSearchError(
                "Username: 3–30 chars, letters/digits/_  (no @)".into(),
            ));
        }
        let tx = self.events.clone();
        let grpc = self.grpc.clone();
        tokio::spawn(async move {
            let event = match crate::grpc::find_user(&grpc, &query).await {
                Ok(Some(user_id)) => ClientEvent::ContactSearchResult(vec![SearchResult {
                    user_id,
                    username: query.clone(),
                    display_name: query,
                }]),
                Ok(None) => ClientEvent::ContactSearchResult(vec![]),
                Err(e) => ClientEvent::ContactSearchError(e.to_string()),
            };
            let _ = tx.send(event);
        });
        self.emit(ClientEvent::SearchStarted(FindStarted::UsernameSearch));
    }

    fn redeem_invite(&self, raw: &str) -> Result<(), String> {
        let invite = crate::invite::parse_invite(raw).map_err(|e| format!("Bad invite: {e:#}"))?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        if invite.is_expired(now) {
            return Err("Invite expired".into());
        }
        let inbox = self.inbox.clone();
        let events = self.events.clone();
        let grpc = self.grpc.clone();
        let username = invite
            .un
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| invite.uuid[..8.min(invite.uuid.len())].to_string());
        tokio::spawn(async move {
            match crate::grpc::accept_invite(&grpc, &invite).await {
                Ok(accepted) => {
                    let _ = inbox.send(Inbox::InviteAccepted {
                        user_id: accepted.user_id,
                        username,
                    });
                }
                Err(e) => {
                    let _ = events.send(ClientEvent::ContactSearchError(format!("Invite: {e}")));
                }
            }
        });
        Ok(())
    }

    /// Store a person, subscribe the stream to them, and tell the orchestrator.
    pub(super) fn add_contact(&mut self, user_id: String, username: String) {
        if let Some(ref storage) = self.read_storage {
            let _ = storage.upsert_contact(&StoredContact {
                user_id: user_id.clone(),
                display_name: username.clone(),
                identity_key_b64: String::new(),
            });
        }
        if !self.contact_ids.contains(&user_id) {
            self.contact_ids.push(user_id.clone());
        }
        self.resubscribe_stream();
        if let Some(ref orch) = self.orch_handle {
            orch.remember_contact(user_id.clone());
        }
        self.emit(ClientEvent::ContactAdded { user_id, username });
    }

    /// Remove a person and their messages.
    pub(super) fn delete_contact(&mut self, peer_id: String) {
        if let Some(Err(e)) = self
            .read_storage
            .as_ref()
            .map(|s| s.delete_contact(&peer_id))
        {
            return self.emit(ClientEvent::Notice(format!("Delete failed: {e}")));
        }
        if let Some(ref orch) = self.orch_handle {
            orch.forget_contact(peer_id.clone());
        }
        self.contact_ids.retain(|id| *id != peer_id);
        self.resubscribe_stream();
        self.emit(ClientEvent::ContactRemoved { peer_id });
    }

    /// Re-subscribe the stream for the full contact set — never a subset.
    fn resubscribe_stream(&self) {
        let Some(ref stream_tx) = self.stream_tx else {
            return;
        };
        let stream_cursor = self
            .read_storage
            .as_ref()
            .and_then(|storage| storage.load_stream_cursor().ok().flatten());
        let _ = stream_tx.try_send(crate::streaming::StreamCmd::Subscribe(
            self.contact_ids.clone(),
            stream_cursor,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{ClientCommand, ClientConfig};
    use crate::config::TransportConfig;
    use tokio::sync::mpsc;

    fn client() -> (Client, mpsc::UnboundedReceiver<ClientEvent>) {
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let (inbox_tx, _inbox_rx) = mpsc::unbounded_channel();
        let client = Client::new(
            ClientConfig {
                server_url: "https://localhost".into(),
                transport: TransportConfig::Direct,
                no_encrypt: true,
                pq_active: true,
            },
            events_tx,
            inbox_tx,
        );
        (client, events_rx)
    }

    fn last_subscription(rx: &mut mpsc::Receiver<crate::streaming::StreamCmd>) -> Vec<String> {
        let mut last = None;
        while let Ok(cmd) = rx.try_recv() {
            if let crate::streaming::StreamCmd::Subscribe(ids, _) = cmd {
                last = Some(ids);
            }
        }
        last.expect("a subscription was sent")
    }

    /// Adding or removing one person re-subscribes for everyone, not just for them — a
    /// subscription for a subset silently stops delivery from the rest.
    #[test]
    fn the_stream_is_resubscribed_for_the_full_contact_set() {
        let (mut client, _events) = client();
        let (stream_tx, mut stream_rx) = mpsc::channel(8);
        client.stream_tx = Some(stream_tx);

        client.handle(ClientCommand::AddContact {
            user_id: "alice".into(),
            username: "Alice".into(),
        });
        client.handle(ClientCommand::AddContact {
            user_id: "bob".into(),
            username: "Bob".into(),
        });
        assert_eq!(last_subscription(&mut stream_rx), vec!["alice", "bob"]);

        client.handle(ClientCommand::AddContact {
            user_id: "alice".into(),
            username: "Alice".into(),
        });
        assert_eq!(
            last_subscription(&mut stream_rx),
            vec!["alice", "bob"],
            "adding someone already there does not duplicate them"
        );

        client.handle(ClientCommand::DeleteContact {
            peer_id: "alice".into(),
        });
        assert_eq!(last_subscription(&mut stream_rx), vec!["bob"]);
    }

    /// A front end learns of a change only from events — the command alone changes nothing
    /// it can see. An add that emitted nothing would leave the list on screen stale.
    #[test]
    fn adding_and_removing_report_back() {
        let (mut client, mut events) = client();
        client.handle(ClientCommand::AddContact {
            user_id: "alice".into(),
            username: "Alice".into(),
        });
        client.handle(ClientCommand::DeleteContact {
            peer_id: "alice".into(),
        });
        assert!(matches!(
            events.try_recv(),
            Ok(ClientEvent::ContactAdded { ref user_id, .. }) if user_id == "alice"
        ));
        assert!(matches!(
            events.try_recv(),
            Ok(ClientEvent::ContactRemoved { ref peer_id }) if peer_id == "alice"
        ));
    }
}
