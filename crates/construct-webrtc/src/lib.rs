//! `construct-webrtc` — the media plane for Desktop (Linux/Windows), starting as a spike.
//!
//! First and only piece so far: a guard test that the pinned libwebrtc prebuilt carries
//! post-quantum DTLS. Calls on this stack are only acceptable with X25519MLKEM768 negotiated
//! behind the `WebRTC-EnableDtlsPqc` field trial (construct-docs
//! `decisions/calls-post-quantum-dtls.md`); if a future prebuilt update drops either, this
//! test turns red instead of silently falling back to X25519.
//!
//! `build.rs` downloads and verifies the prebuilt (pinned by sha256) and exposes its path as
//! `WEBRTC_LIB_PATH`.

pub mod ffi;

/// The field-trial key that turns hybrid DTLS on (X25519MLKEM768 first group).
pub const PQ_TRIAL: &[u8] = b"WebRTC-EnableDtlsPqc";
/// The hybrid group the phones negotiate; its presence here is what the guard checks.
pub const PQ_GROUP: &[u8] = b"X25519MLKEM768";

/// Whether `bytes` contains the field-trial key and the hybrid group name.
/// The check is the same `strings`-style byte scan the decision's iOS test uses.
pub fn pq_dtls_markers_present(bytes: &[u8]) -> (bool, bool) {
    let has = |marker: &[u8]| bytes.windows(marker.len()).any(|w| w == marker);
    (has(PQ_TRIAL), has(PQ_GROUP))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_linked_webrtc_carries_pq_dtls() {
        let path = env!("WEBRTC_LIB_PATH");
        let bytes = std::fs::read(path).expect("build.rs must fetch the pinned prebuilt");
        let (trial, group) = pq_dtls_markers_present(&bytes);
        assert!(
            trial,
            "field trial `{}` is gone from {path}: PQ-DTLS would fall back to X25519",
            String::from_utf8_lossy(PQ_TRIAL)
        );
        assert!(
            group,
            "group `{}` is gone from {path}: no hybrid DTLS to negotiate",
            String::from_utf8_lossy(PQ_GROUP)
        );
    }

    #[test]
    fn removing_the_group_from_a_copy_is_visible_to_the_guard() {
        let path = env!("WEBRTC_LIB_PATH");
        let mut bytes = std::fs::read(path).expect("build.rs must fetch the pinned prebuilt");
        // Zero out every occurrence of the group marker: the guard must then report it absent.
        let mut start = 0;
        while let Some(pos) = bytes[start..]
            .windows(PQ_GROUP.len())
            .position(|w| w == PQ_GROUP)
        {
            let at = start + pos;
            bytes[at..at + PQ_GROUP.len()].fill(0);
            start = at + PQ_GROUP.len();
        }
        let (trial, group) = pq_dtls_markers_present(&bytes);
        assert!(trial, "the trial marker must survive this mutation");
        assert!(!group, "the guard must see the group marker was removed");
    }

    #[test]
    fn the_guard_sees_each_marker_alone_and_both_missing() {
        let both = b"WebRTC-EnableDtlsPqc ... X25519MLKEM768";
        assert_eq!(pq_dtls_markers_present(both), (true, true));
        // One byte wrong in each marker is enough to fail that marker.
        assert_eq!(
            pq_dtls_markers_present(b"WebRTC-EnableDtlsPqx ... X25519MLKEM768"),
            (false, true)
        );
        assert_eq!(
            pq_dtls_markers_present(b"WebRTC-EnableDtlsPqc ... X25519MLKEM769"),
            (true, false)
        );
        assert_eq!(pq_dtls_markers_present(b"no markers here"), (false, false));
    }
}
