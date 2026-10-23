# AGENTS.md — construct-client

The Konstruct client layer (`crates/construct-client`) and the screens (`crates/construct-screens`).
Two shells use them: `construct-tui` (terminal) and `construct-desktop` (Linux and Windows window).
Decision: `~/Code/construct-docs/decisions/desktop-is-the-tui-client-with-a-second-shell.md`.
The plan and its progress: vault `todo/218-desktop-linux-windows-plan.md`.

The crate moved here from `construct-tui` on 2026-10-23 with its history (owner decision 1 in TODO 218).

## Checkouts

The crates take their dependencies by path. `~/Code/construct-core` and `~/Code/construct-protos`
must sit next to this repository (`CONSTRUCT_PROTOS_DIR` overrides the protos path). Other agent
sessions work in those two working copies. Never switch their branches; change them in a
worktree, on a branch, through a PR. The owner merges `construct-core` PRs.

Turn the hooks on once per clone with `git config core.hooksPath .githooks`. The commit-msg hook
strips `Co-authored-by` lines; that is intended. The pre-push hook runs fmt and clippy
(`-D warnings`).

## Invariants

- **`construct-client` has no front end.** No ratatui, crossterm or windowing toolkit.
  `tests::the_client_crate_depends_on_no_front_end` reads its `Cargo.toml`.
- **`construct-screens` has no terminal or window.** A shell supplies keys and a `Frame`. Key types
  come from `ratatui::crossterm`, so both shells name the same ones.
- **No protocol here.** What the core decides is asked of it. Before writing one in Rust, look in
  `construct-core/src/construct_core.udl` and the crate API for it.
- **Everything handed to the core is a device id; everything shown or addressed on the server is
  an account id.** `peers.rs` is the one map between them.
- **Every send to another account is sealed.** There is no unsealed send path.
- **The local store is `construct-store`'s; this repository has no schema.** `local_store.rs` maps
  the client's calls onto it, `local_data.rs` owns the directory: one process at a time
  (`konstruct.lock`), the store key in the OS key store, else from a passphrase (Argon2id, salt
  beside the database), else a key file (`--no-encrypt`). Logout wipes the store and its key.

## Working rules

- **This repository is public.** Never write server host names, IP addresses or other people's
  personal data here, in commit messages or in PR descriptions.
- On the delivery or crypto path, every commit answers the three questions:
  1. What does the server learn?
  2. What can a party withhold or substitute?
  3. Which trust boundary moves?
- A new test counts only after it has failed under a deliberate mutation.
- Interop checks against the server use recognisable test accounts (`examples/probe.rs`, one
  `HOME` per account). Before release the test and production server are the same machine
  (owner, 2026-10-23).

## Git workflow (branch + PR only)

Never commit on `main`. Every change goes on a topic branch cut from an up-to-date `main`
(`feat|fix|docs|chore|test/<topic>`) and lands through a GitHub pull request.

## Documentation

Docs live in `~/Code/construct-docs`; its `AGENTS.md` is authoritative. After a session with
design decisions or root-cause analysis, write `sessions/YYYY-MM-DD-<topic>.md` (with `## Why`),
update the affected `decisions/` note and spec, and append one line to `log.md`.
