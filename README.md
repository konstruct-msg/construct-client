# construct-client

The Konstruct client layer and its screens, shared by two shells:

- [`construct-tui`](https://github.com/konstruct-msg/construct-tui) — the terminal;
- [`construct-desktop`](https://github.com/konstruct-msg/construct-desktop) — Linux and Windows, a Tauri window whose content is a character grid.

| Crate | What it is |
|---|---|
| `crates/construct-client` | Account, keys, sessions, the message stream and storage, around `construct-core`'s `Orchestrator`. No front end. |
| `crates/construct-screens` | The screens, drawn with Ratatui. A shell feeds keys and draws frames; nothing here opens a terminal or a window. |

The crates take `construct-core` and `construct-protos` by path, so check them out next to this repository.

```bash
cargo test --workspace
HOME=/tmp/probe-a cargo run -p construct-client --example probe -- --username tui_test_x --wait 60   # headless client for interop checks
```

Licensed under MPL-2.0.
