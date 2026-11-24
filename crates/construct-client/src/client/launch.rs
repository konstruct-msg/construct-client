//! The launch passphrase: asked for at each start, before the store is open. Unlike the app lock
//! (`lock`), it is on the data: without it what the disk and the OS key store hold opens nothing.

use zeroize::Zeroizing;

use super::{Client, ClientEvent};
use crate::local_data::KeyKeeping;

/// How this device's store stands with a passphrase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchPassphrase {
    /// The OS key store opens it; a passphrase can be set.
    Off,
    /// Set; it can be changed and removed.
    On,
    /// There is no OS key store here: the key is made from the passphrase, and stays so.
    Always,
    /// The key is in a file (`--no-encrypt`), or there is no store.
    Unavailable,
}

impl Client {
    fn launch_passphrase(&self) -> LaunchPassphrase {
        match self.data.as_ref().and_then(|data| data.existing()) {
            Some(KeyKeeping::KeyStore) if self.unlocked_by_passphrase => LaunchPassphrase::On,
            Some(KeyKeeping::KeyStore) => LaunchPassphrase::Off,
            Some(KeyKeeping::Passphrase) => LaunchPassphrase::Always,
            Some(KeyKeeping::KeyFile) | None => LaunchPassphrase::Unavailable,
        }
    }

    pub(super) fn emit_launch_passphrase(&self) {
        self.emit(ClientEvent::LaunchPassphrase(self.launch_passphrase()));
    }

    /// Set, change (`new`) or remove (`new: None`) the passphrase. `current` is the one set.
    pub(super) fn set_launch_passphrase(
        &mut self,
        current: Option<Zeroizing<Vec<u8>>>,
        new: Option<Zeroizing<Vec<u8>>>,
    ) {
        if self.store.is_none() {
            return;
        }
        let set = self.data_dir().and_then(|data| {
            data.set_launch_passphrase(
                current.as_deref().map(Vec::as_slice),
                new.as_deref().map(Vec::as_slice),
            )
            .map_err(|e| format!("{e:#}"))
        });
        match set {
            Ok(()) => {
                self.unlocked_by_passphrase = new.is_some();
                self.emit_launch_passphrase();
            }
            Err(why) => self.emit(ClientEvent::LaunchPassphraseRefused(why)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{ClientCommand, ClientConfig, Inbox};
    use crate::config::{Session, TransportConfig};
    use crate::local_data::{DataDir, KeyStore};
    use crate::local_store::LocalStore;
    use std::path::PathBuf;
    use tokio::sync::mpsc;

    struct Bench {
        client: Client,
        events: mpsc::UnboundedReceiver<ClientEvent>,
        _inbox: mpsc::UnboundedReceiver<Inbox>,
        dir: PathBuf,
    }

    /// A client over an empty directory of its own and `keys`.
    fn bench(keys: &KeyStore) -> Bench {
        let dir =
            std::env::temp_dir().join(format!("construct-client-launch-{}", uuid::Uuid::new_v4()));
        let (events_tx, events) = mpsc::unbounded_channel();
        let (inbox_tx, _inbox) = mpsc::unbounded_channel();
        let mut client = Client::new(
            ClientConfig {
                server_url: "https://localhost".into(),
                transport: TransportConfig::Direct,
                no_encrypt: false,
                pq_active: true,
            },
            events_tx,
            inbox_tx,
        );
        client.data = Some(DataDir::open_with(&dir, keys.clone()).unwrap());
        Bench {
            client,
            events,
            _inbox,
            dir,
        }
    }

    fn bytes(s: &str) -> Option<Zeroizing<Vec<u8>>> {
        Some(Zeroizing::new(s.as_bytes().to_vec()))
    }

    fn session() -> Session {
        Session {
            signing_key_hex: "11".repeat(32),
            identity_key_hex: "22".repeat(32),
            device_id: "device".into(),
            user_id: "account".into(),
            access_token: String::new(),
            refresh_token: String::new(),
            expires_at: 0,
            spk_key_hex: String::new(),
            spk_sig_hex: String::new(),
        }
    }

    #[test]
    fn the_setting_follows_the_passphrase_and_the_next_start_asks_for_it() {
        let mut b = bench(&KeyStore::Memory(Default::default()));
        let store = b.client.data.as_ref().unwrap().create_store(false);
        b.client.store = Some(LocalStore::new(store.unwrap().unwrap(), "me"));
        assert_eq!(b.client.launch_passphrase(), LaunchPassphrase::Off);

        b.client.handle(ClientCommand::SetLaunchPassphrase {
            current: None,
            new: bytes("correct horse"),
        });
        assert!(matches!(
            b.events.try_recv(),
            Ok(ClientEvent::LaunchPassphrase(LaunchPassphrase::On))
        ));

        // Off needs the passphrase, and says so without turning it off.
        b.client.handle(ClientCommand::SetLaunchPassphrase {
            current: bytes("wrong horse"),
            new: None,
        });
        assert!(matches!(
            b.events.try_recv(),
            Ok(ClientEvent::LaunchPassphraseRefused(_))
        ));
        assert_eq!(b.client.launch_passphrase(), LaunchPassphrase::On);

        b.client.store = None;
        b.client.handle(ClientCommand::RestoreFromDisk);
        assert!(matches!(b.events.try_recv(), Ok(ClientEvent::NeedsUnlock)));
        assert!(b.client.store.is_none());

        b.client
            .handle(ClientCommand::Unlock(bytes("wrong horse").unwrap()));
        assert!(matches!(
            b.events.try_recv(),
            Ok(ClientEvent::UnlockFailed(_))
        ));
        assert!(b.client.store.is_none());
    }

    /// The fallback was a key file beside the database: a copied directory opened by itself.
    #[test]
    fn an_old_session_without_a_key_store_waits_for_a_passphrase() {
        let mut b = bench(&KeyStore::Absent);
        let moved = b.client.migrate_legacy(session(), false, None).unwrap();
        assert!(moved.is_none());
        assert!(b.client.pending_session.is_some());
        assert!(b.client.store.is_none());
        let left: Vec<_> = std::fs::read_dir(&b.dir)
            .unwrap()
            .map(|f| f.unwrap().file_name())
            .collect();
        assert_eq!(left, ["konstruct.lock"], "no store and no key");
    }
}
