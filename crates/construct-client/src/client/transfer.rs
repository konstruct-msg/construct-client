//! History moved to and from another device of the account as a file (`crate::history`).

use std::path::PathBuf;

use super::{Client, ClientEvent, Inbox};

impl Client {
    pub(super) fn export_history(&mut self, device_id: String, path: PathBuf) {
        let (Some(store), Some(orch)) = (self.store.clone(), self.orch_handle.clone()) else {
            return self.emit(ClientEvent::HistoryExported(Err("not signed in".into())));
        };
        let cache = match self.data_dir() {
            Ok(data) => crate::media::MediaCache::new(data.media_dir()),
            Err(e) => return self.emit(ClientEvent::HistoryExported(Err(e))),
        };
        let grpc = self.grpc.clone();
        let (user_id, own_device) = (self.user_id.clone(), self.device_id.clone());
        let events = self.events.clone();
        tokio::spawn(async move {
            let result = crate::history::export_to_file(
                &orch,
                &grpc,
                &store,
                &cache,
                &user_id,
                &own_device,
                &device_id,
                &path,
            )
            .await;
            match &result {
                Ok(s) => tracing::info!(?s, "history file written"),
                Err(e) => tracing::warn!("history file not written: {e}"),
            }
            let _ = events.send(ClientEvent::HistoryExported(result.map(|s| (s, path))));
        });
    }

    pub(super) fn import_history(&mut self, path: PathBuf) {
        let (Some(store), Some(orch)) = (self.store.clone(), self.orch_handle.clone()) else {
            return self.emit(ClientEvent::HistoryImported(Err("not signed in".into())));
        };
        let cache = match self.data_dir() {
            Ok(data) => crate::media::MediaCache::new(data.media_dir()),
            Err(e) => return self.emit(ClientEvent::HistoryImported(Err(e))),
        };
        let grpc = self.grpc.clone();
        let user_id = self.user_id.clone();
        let (events, inbox) = (self.events.clone(), self.inbox.clone());
        tokio::spawn(async move {
            match crate::history::import_file(&orch, &grpc, &store, &cache, &user_id, &path).await {
                Ok((summary, contacts)) => {
                    tracing::info!(?summary, "history file imported");
                    let _ = inbox.send(Inbox::HistoryImported { summary, contacts });
                }
                Err(e) => {
                    tracing::warn!("history file not imported: {e}");
                    let _ = events.send(ClientEvent::HistoryImported(Err(e)));
                }
            }
        });
    }

    /// An import landed: take deliveries from the accounts it named, and redraw the chats.
    pub(super) fn history_imported(
        &mut self,
        summary: crate::history::HistorySummary,
        contacts: Vec<String>,
    ) {
        for id in contacts {
            if !self.contact_ids.contains(&id) {
                self.contact_ids.push(id.clone());
                if let Some(ref orch) = self.orch_handle {
                    orch.remember_contact(id);
                }
            }
        }
        self.emit(ClientEvent::HistoryImported(Ok(summary)));
        if let Some(store) = &self.store {
            match store.get_contacts() {
                Ok(contacts) => self.emit(ClientEvent::Started(contacts)),
                Err(e) => tracing::warn!("contacts not reread after the import: {e}"),
            }
        }
    }
}
