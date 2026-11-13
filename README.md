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

For bounded interop traffic between **separate test accounts**, the headless probe also accepts
`--add <test-account-id> --send <text> --send-count 30 --send-interval-ms 1000 --wait 90`.
Counts are limited to 1–1,000 and spacing to 100–60,000 ms, with no catch-up burst. Multi-send
texts receive `probe_seq=NNNN`; `LOAD_ENQUEUE sequence=N` is emitted before each client command.
Verify the receiver's decrypted `RECEIVED` text **and message IDs**, not just sender `QUEUED`.
This is client/E2E traffic (including crypto, receipts and directory lookups), not server-only
latency or a capacity claim. Admission failures stop a load run; never disable production gates
or switch to identified sends to make a benchmark pass. Keep each account's HOME and logs private.

Licensed under MPL-2.0.
