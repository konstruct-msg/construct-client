# construct-webrtc (spike)

The media plane for Desktop (Linux/Windows) calls, started as a spike. Decision:
`construct-docs/decisions/desktop-calls-webrtc-stack.md` (libwebrtc, not webrtc-rs). Task:
`construct-docs/todo/272-desktop-zvonki-linux-windows.md`.

## What exists

- `build.rs` fetches the pinned `webrtc-sdk/libwebrtc` prebuilt (m150 line, MIT C++ wrapper),
  verifies it by sha256, links it on Linux, and exposes `WEBRTC_LIB_PATH`.
- `src/lib.rs` has the PQ-DTLS guard: the prebuilt must contain the `WebRTC-EnableDtlsPqc`
  field-trial key and the `X25519MLKEM768` group. `cargo test` fails if a future prebuilt
  update drops either.

## Pins (tag `libwebrtc.m150.7871.07`)

| archive | sha256 |
|---|---|
| libwebrtc-linux-x64-release.zip | `ef380526cf9616848bc0b97b24990cbf2ad851c209d5dce93cc3ebb9d3789fbc` |
| libwebrtc-linux-arm64-release.zip | `887de0a1da6c9b8807da9fe2fc237e03ac5fcc3df4142a5f8889d66baa24bf08` |
| libwebrtc-win-x64-release.zip | `0cf141cd803af8f860080d94861d2d591ab9081a28f5cdead1b7c775ad5d3bf8` |
| libwebrtc-win-arm64-release.zip | `2546c8cc20a4326d6b40e06a250a642733e80e03a1ba36a0b115a491d65d3f85` |

## Next steps

1. Run the Linux-gated test (`cargo test -p construct-webrtc --target x86_64-unknown-linux-gnu`
   on Linux, or in CI): proves the FFI chain and that `WebRTC-EnableDtlsPqc` applies at runtime.
   `build.rs` compiles `src/ffi/shim.cpp` and links `libwebrtc.so` there; the shim itself was
   compile-checked on macOS against the real headers (`clang++ -I <include> -c src/ffi/shim.cpp`).
2. Loopback offer/answer over the same shim (two peer connections, one process), asserting DTLS
   state `kConnected` and a TLS 1.3 cipher; the negotiated *group* needs a `tcpdump` capture as
   on iOS, since the wrapper exposes `ssl_cipher_suite` but not `ssl_group_id`.
3. Windows linking: `libwebrtc.dll.lib` import library (already in the win archive).
4. AEC with cpal, Opus, relay-only ICE; then interop against an iOS/macOS peer.
