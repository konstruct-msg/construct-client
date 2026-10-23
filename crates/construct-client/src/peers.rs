//! The seam between the server's accounts and the core's devices.
//!
//! The core knows only device ids (`derive_device_id(identity_key)`); the server and the screens
//! know accounts. Everything handed to the core is a device id, everything shown or addressed on
//! the server is an account id, and this map is the one place that goes from one to the other
//! (decisions/a-peer-is-a-set-of-devices.md).
//!
//! A device enters from a bundle the server gave for the account, or from the certificate a
//! receiving session opened from. It leaves only when the server's `active_devices` for its
//! account omits it.

use std::collections::HashMap;

use crate::storage::Storage;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerDevice {
    pub user_id: String,
    pub identity_key: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct PeerDevices {
    by_device: HashMap<String, PeerDevice>,
}

impl PeerDevices {
    pub fn load(storage: &Storage) -> Self {
        let rows = storage.peer_devices().unwrap_or_else(|e| {
            tracing::warn!(error = %e, "failed to load peer devices");
            Vec::new()
        });
        let by_device = rows
            .into_iter()
            .map(|(user_id, device_id, identity_key)| {
                (
                    device_id,
                    PeerDevice {
                        user_id,
                        identity_key,
                    },
                )
            })
            .collect();
        Self { by_device }
    }

    /// The account `device_id` belongs to.
    pub fn account_of(&self, device_id: &str) -> Option<&str> {
        self.by_device.get(device_id).map(|d| d.user_id.as_str())
    }

    pub fn identity_of(&self, device_id: &str) -> Option<&[u8]> {
        self.by_device
            .get(device_id)
            .map(|d| d.identity_key.as_slice())
    }

    /// The devices filed under `user_id`, sorted so a fan-out goes in the same order every time.
    pub fn devices_of(&self, user_id: &str) -> Vec<String> {
        let mut devices: Vec<String> = self
            .by_device
            .iter()
            .filter(|(_, d)| d.user_id == user_id)
            .map(|(id, _)| id.clone())
            .collect();
        devices.sort();
        devices
    }

    /// File a device. Refused when `device_id` does not derive from `identity_key`: whoever
    /// supplied the pair could otherwise file their key under someone else's device.
    pub fn record(
        &mut self,
        storage: &Storage,
        user_id: &str,
        device_id: &str,
        identity_key: &[u8],
    ) -> bool {
        if construct_core::device_id::derive_device_id(identity_key) != device_id {
            tracing::warn!(%device_id, "peer device refused: id does not derive from its key");
            return false;
        }
        let device = PeerDevice {
            user_id: user_id.to_string(),
            identity_key: identity_key.to_vec(),
        };
        if self.by_device.get(device_id) == Some(&device) {
            return true;
        }
        if let Err(e) = storage.upsert_peer_device(user_id, device_id, identity_key) {
            tracing::warn!(%device_id, error = %e, "failed to persist peer device");
        }
        self.by_device.insert(device_id.to_string(), device);
        true
    }

    /// Drop the devices of `user_id` the server no longer counts as active. An empty
    /// `active_devices` prunes nothing (an older server, or a failed lookup); a device in `keep`
    /// (it just gave a bundle) stays even when the list omits it. Returns the dropped ids.
    pub fn reconcile(
        &mut self,
        storage: &Storage,
        user_id: &str,
        active_devices: &[String],
        keep: &[String],
    ) -> Vec<String> {
        if active_devices.is_empty() {
            return Vec::new();
        }
        let dropped: Vec<String> = self
            .devices_of(user_id)
            .into_iter()
            .filter(|d| !active_devices.contains(d) && !keep.contains(d))
            .collect();
        for device_id in &dropped {
            self.forget(storage, device_id);
        }
        dropped
    }

    pub fn forget(&mut self, storage: &Storage, device_id: &str) {
        self.by_device.remove(device_id);
        if let Err(e) = storage.delete_peer_device(device_id) {
            tracing::warn!(%device_id, error = %e, "failed to delete peer device");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use construct_core::device_id::derive_device_id;

    fn key(n: u8) -> (Vec<u8>, String) {
        let key = vec![n; 32];
        let id = derive_device_id(&key);
        (key, id)
    }

    #[test]
    fn a_device_id_that_does_not_derive_from_its_key_is_refused() {
        let storage = Storage::open_in_memory().unwrap();
        let mut peers = PeerDevices::default();
        let (key_a, _) = key(1);
        let (_, id_b) = key(2);

        assert!(!peers.record(&storage, "alice", &id_b, &key_a));
        assert_eq!(peers.account_of(&id_b), None);
        assert!(storage.peer_devices().unwrap().is_empty());
    }

    #[test]
    fn recorded_devices_survive_a_reload() {
        let storage = Storage::open_in_memory().unwrap();
        let mut peers = PeerDevices::default();
        let (key_a, id_a) = key(1);
        assert!(peers.record(&storage, "alice", &id_a, &key_a));

        let reloaded = PeerDevices::load(&storage);
        assert_eq!(reloaded.account_of(&id_a), Some("alice"));
        assert_eq!(reloaded.identity_of(&id_a), Some(key_a.as_slice()));
        assert_eq!(reloaded.devices_of("alice"), vec![id_a]);
    }

    #[test]
    fn reconcile_drops_inactive_devices_but_keeps_one_that_just_gave_a_bundle() {
        let storage = Storage::open_in_memory().unwrap();
        let mut peers = PeerDevices::default();
        let (key_a, id_a) = key(1);
        let (key_b, id_b) = key(2);
        let (key_c, id_c) = key(3);
        peers.record(&storage, "alice", &id_a, &key_a);
        peers.record(&storage, "alice", &id_b, &key_b);
        peers.record(&storage, "alice", &id_c, &key_c);

        let dropped = peers.reconcile(
            &storage,
            "alice",
            std::slice::from_ref(&id_a),
            std::slice::from_ref(&id_c),
        );

        assert_eq!(dropped, vec![id_b.clone()]);
        assert_eq!(peers.account_of(&id_b), None);
        let mut left = vec![id_a, id_c];
        left.sort();
        assert_eq!(peers.devices_of("alice"), left);
        assert_eq!(PeerDevices::load(&storage).devices_of("alice"), left);
    }

    #[test]
    fn an_empty_active_list_prunes_nothing() {
        let storage = Storage::open_in_memory().unwrap();
        let mut peers = PeerDevices::default();
        let (key_a, id_a) = key(1);
        peers.record(&storage, "alice", &id_a, &key_a);

        assert!(peers.reconcile(&storage, "alice", &[], &[]).is_empty());
        assert_eq!(peers.devices_of("alice"), vec![id_a]);
    }
}
