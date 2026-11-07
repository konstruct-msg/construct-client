//! Raw FFI to `src/ffi/shim.cpp`, the C boundary over libwebrtc's C++ API.
//!
//! The declarations type-check everywhere, but the wrappers and the test are only built on
//! Linux, where `build.rs` compiles the shim and links `libwebrtc.so`. On macOS the crate's
//! guard test only scans the binary's bytes; it does not call into it.

#[cfg(target_os = "linux")]
use std::os::raw::c_char;

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn ct_webrtc_init(field_trials_csv: *const c_char) -> std::os::raw::c_int;
    fn ct_webrtc_field_trial_enabled(key: *const c_char) -> std::os::raw::c_int;
    fn ct_webrtc_terminate();
    fn ct_loopback_handshake(
        timeout_ms: std::os::raw::c_int,
        out_dtls_state: *mut std::os::raw::c_int,
    ) -> std::os::raw::c_int;
}

/// Apply the comma-separated field trials (`"Key/Value/"` entries) and initialize WebRTC.
#[cfg(target_os = "linux")]
pub fn init(trials: &str) {
    let c = std::ffi::CString::new(trials).expect("no NUL byte in field trials");
    let rc = unsafe { ct_webrtc_init(c.as_ptr()) };
    assert_eq!(rc, 0, "ct_webrtc_init failed");
}

/// Whether the running WebRTC has `key` enabled (its group starts with "Enabled").
#[cfg(target_os = "linux")]
pub fn field_trial_enabled(key: &str) -> bool {
    let c = std::ffi::CString::new(key).expect("no NUL byte in key");
    unsafe { ct_webrtc_field_trial_enabled(c.as_ptr()) != 0 }
}

#[cfg(target_os = "linux")]
pub fn terminate() {
    unsafe { ct_webrtc_terminate() };
}

/// Runs the loopback handshake and returns `(cipher_suite, dtls_state)`.
/// `dtls_state` is `2` for `kConnected`.
#[cfg(target_os = "linux")]
pub fn loopback_handshake(timeout_ms: i32) -> (i32, i32) {
    let mut dtls_state = -1i32;
    let cipher = unsafe { ct_loopback_handshake(timeout_ms, &mut dtls_state) };
    (cipher, dtls_state)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #[test]
    fn the_runtime_negotiates_pq_dtls() {
        // One app lifetime = one init/terminate pair: the field trial must apply,
        // and two peer connections must complete a DTLS 1.3 handshake.
        super::init("WebRTC-EnableDtlsPqc/Enabled/");
        assert!(
            super::field_trial_enabled("WebRTC-EnableDtlsPqc"),
            "InitializeWithFieldTrials did not apply WebRTC-EnableDtlsPqc"
        );
        let (cipher, dtls_state) = super::loopback_handshake(10_000);
        assert_eq!(dtls_state, 2, "DTLS transport should reach kConnected");
        assert!(
            (0x1301..=0x1305).contains(&cipher),
            "expected a TLS 1.3 cipher suite, got {cipher:#x}"
        );
        super::terminate();
    }
}
