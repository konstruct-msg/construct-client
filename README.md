# construct-client

The Konstruct client layer and its screens, shared by two shells:

- [`construct-tui`](https://github.com/konstruct-msg/construct-tui) — the terminal;
- [`construct-desktop`](https://github.com/konstruct-msg/construct-desktop) — Linux and Windows, a Tauri window whose content is a character grid.

| Crate | What it is |
|---|---|
| `crates/construct-client` | Account, keys, sessions, the message stream and storage, around `construct-core`'s `Orchestrator`. No front end. |
| `crates/construct-screens` | The screens, drawn with Ratatui. A shell feeds keys and draws frames; nothing here opens a terminal or a window. |

Directory RPC bookkeeping distinguishes a successful **self-only** active-device response from
an unknown/failed read. It reuses the existing device-directory freshness bound without treating
self as a peer; unknown remote sets or active siblings whose keys are unpublished still retry.
Own-account link attempts invalidate before and after the whole operation, including cancellation
or an uncertain response, and bypass reuse while in flight. Session/key admission stays in core.
The production actor/RPC decoder are exercised by HTTP/2 tests in `orchestrator_task/directory_tests.rs`.

The crates take `construct-core` and `construct-protos` by path, so check them out next to this repository.

```bash
cargo test --workspace
HOME=/tmp/probe-a cargo run -p construct-client --example probe -- --username tui_test_x --wait 60   # headless client for interop checks
```

Licensed under MPL-2.0.
