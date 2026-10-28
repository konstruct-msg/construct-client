# AGENTS.md — construct-client

The Konstruct client layer (`crates/construct-client`: account, keys, the core, stream, storage) and the screens (`crates/construct-screens`: `App`, screens, theme). Two shells use them: `construct-tui` (terminal) and `construct-desktop` (Linux and Windows window). The crate moved here from `construct-tui` on 2026-10-23 with its history.

If a rule here and your plan disagree, the rule wins until a `decisions/` note says otherwise.

## Read first

| Area | Read |
|---|---|
| Why these rules exist; checklist before any protocol feature | `~/Code/construct-docs/decisions/rules-from-the-first-year.md` |
| Why two shells share one client | `~/Code/construct-docs/decisions/desktop-is-the-tui-client-with-a-second-shell.md` |
| Plan and progress | `~/Code/construct-docs/todo/218-desktop-linux-windows-plan.md` |
| Session / identity / AD | `~/Code/construct-docs/decisions/identity-spaces.md` |
| Three questions, session lifecycle | `construct-messenger/AGENTS.md` |
| Everything else | `~/Code/construct-docs` (vault; its own `AGENTS.md` is authoritative) |

## The Zen of Konstruct

```
Someone has solved it before. Read them first.
The core decides; the app executes.
A message names the state it means. Time is not an address.
Reproduce, then fix.
One meaning, one carrier.
Bytes stay bytes.
Measure, then build.
The effect is the proof, not the exit code.
A test that cannot fail is worse than no test.
Boring before new.
Temporary is permanent, unless something checks it.
What nothing reads is not sent.
Silence is the worst failure: a message that never appears raises no error.
```

Canonical source: `~/Code/construct-docs/decisions/rules-from-the-first-year.md` — change it there first.

## Rules

1. **Prior art first.** Before any protocol mechanism, write down how Signal / MLS / Matrix solve it and why we deviate. The reference client is iOS.
2. **The core decides, this client executes.** If two clients must compute it identically, or it touches ratchet/session state or a session's lifecycle, it is a `construct-core` call. A decision rebuilt here does not fail loudly — the message just never appears. Look in `construct-core/src/construct_core.udl` first.
3. **A control message names the state it refers to.** A timer, cooldown, window, tie-break or retry budget in a fix means the message has no address.
4. **Reproduce before fixing**; a fix counts when the case that was red turns green (interop probe, `examples/probe.rs`).
5. **One meaning, one carrier.** Device id and account id are different types; read `decisions/one-meaning-two-carriers.md` before adding a field, counter or timeout.
6. **Binary stays binary** from source to destination; text encodings only at text boundaries.
7. **Measure, then build.**
8. **Verify the effect, not the exit code.**
9. **A test must be able to fail**: a new test counts only after it has failed under a deliberate mutation. Put the decision in a pure function.
10. **Depth before breadth.** 1:1 delivery against iOS before new surfaces.
11. **A temporary exception has an end date and a check.**
12. **Branch and PR, always** (see Git).

A change on the delivery or crypto path answers three questions in its commit message: what does the server learn that it did not before; what can a party withhold or substitute that it could not before; which trust boundary moves, and which way.

## Invariants of this repo

- **`construct-client` has no front end.** No ratatui, crossterm or windowing toolkit; `tests::the_client_crate_depends_on_no_front_end` reads its `Cargo.toml`.
- **`construct-screens` has no terminal or window.** A shell supplies keys and a `Frame`; key types come from `ratatui::crossterm` so both shells name the same ones.
- **No protocol here.** What the core decides is asked of it; look in `construct-core/src/construct_core.udl` and the crate API before writing one.
- **Everything handed to the core is a device id; everything shown or addressed on the server is an account id.** `peers.rs` is the one map between them.
- **Every send to another account is sealed.** There is no unsealed send path.
- **The local store is `construct-store`'s; this repo has no schema.** `local_store.rs` maps calls onto it; `local_data.rs` owns the directory: one process at a time (`konstruct.lock`), the store key in the OS key store, else from a passphrase (Argon2id, salt beside the database), else a key file (`--no-encrypt`). Logout wipes the store and its key.
- **This repository is public.** No server host names, IPs or other people's personal data in files, commits or PRs.
- **Interop checks** use recognisable test accounts (`examples/probe.rs`, one `HOME` per account). Before release test and production server are one machine (owner, 2026-10-23).

### Checkouts

Dependencies are by path: `~/Code/construct-core` and `~/Code/construct-protos` must sit next to this repo (`CONSTRUCT_PROTOS_DIR` overrides the protos path). Other sessions work in those working copies: never switch their branches; change them in a worktree, on a branch, through a PR (the owner merges core PRs). Once per clone: `git config core.hooksPath .githooks` (the commit-msg hook strips `Co-authored-by` lines, intended; pre-push runs fmt and clippy `-D warnings`).

## Git and process

- **Never commit on `main`.** Topic branch (`feat|fix|docs|chore|test/<topic>`) from an up-to-date `main`, PR into `main`. Conventional Commits.
- Check branch and `git status` before every commit; never `checkout -- .`, `reset --hard` or `stash` in a shared tree; never rewrite pushed history.
- Docs live in `~/Code/construct-docs` (its `AGENTS.md` is authoritative). After a session with design decisions or root cause: `sessions/` note (with `## Why`), the `decisions/` note and spec, one line in `log.md`.
