// The C boundary Rust links against. The implementation (shim.cpp) is C++ and
// converts between plain C types and libwebrtc's ABI-safe `libwebrtc::string` /
// `libwebrtc::vector` types, which is what the prebuilt exposes across its
// shared-library boundary.
#ifndef CONSTRUCT_WEBRTC_SHIM_H
#define CONSTRUCT_WEBRTC_SHIM_H

#ifdef __cplusplus
extern "C" {
#endif

// Applies the comma-separated field trials ("Key/Value/" entries) and
// initializes WebRTC. Returns 0 on success.
int ct_webrtc_init(const char* field_trials_csv);

// Whether the running WebRTC has the given field trial enabled (group starts
// with "Enabled"). Must be called after ct_webrtc_init.
int ct_webrtc_field_trial_enabled(const char* key);

void ct_webrtc_terminate(void);

// Runs a loopback: two peer connections in one process, offer/answer, ICE over
// host candidates, then the DTLS handshake. Returns the negotiated TLS cipher
// suite (0 on failure) and writes the DTLS transport state into out_dtls_state
// (2 == kConnected).
int ct_loopback_handshake(int timeout_ms, int* out_dtls_state);

#ifdef __cplusplus
}
#endif

#endif  // CONSTRUCT_WEBRTC_SHIM_H
