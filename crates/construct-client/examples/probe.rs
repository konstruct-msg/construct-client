//! A headless client for interop checks (TODO 218, stage 1): signs in or registers, optionally
//! adds a contact and sends one text, then prints what arrives for a while.
//!
//! Its state lives under `$HOME` like the terminal client's, unencrypted, so run each account
//! with its own `HOME`:
//!
//! ```text
//! HOME=/tmp/probe-a cargo run -p construct-client --example probe -- --username tui-test-a --wait 60
//! HOME=/tmp/probe-b cargo run -p construct-client --example probe -- \
//!     --add <user_id> --send "hello" --wait 60
//! ```
//!
//! `--approve <link code>` lets a device that asked to join (its `konstruct://link-to-me` code,
//! or just its `id`) become a device of this account — what the phone does when it scans the
//! code — and vouches for it when the code carries `fp`.
//!
//! `--answer <text>`: to the first message that arrives, reply with `text`, react 👍, then edit
//! the reply — the message actions, end to end.
//!
//! `--invite`: once the account's recovery key is in place, mint an invite link and print it.
//!
//! `--link` instead of `--username`: become a new device of an existing account — print the
//! `konstruct://link-to-me` code for the phone to scan, then wait for its approval.
//!
//! `--find <username or invite link>` instead of `--add`: a username is looked up (only accounts
//! that made themselves discoverable are found), an invite link is redeemed; either is added and
//! sent to.
//!
//! `CONSTRUCT_ROTATE_PREKEYS_NOW=1` makes the client rotate its signed prekeys at launch, to check
//! a rotation against the server.
//!
//! Register only test accounts with it, named so they read as such.

use construct_client::{ClientCommand, ClientConfig, ClientEvent, bridge::BridgeEvent};
use tokio::sync::mpsc;

struct Args {
    server: String,
    username: Option<String>,
    add: Option<String>,
    find: Option<String>,
    send: Option<String>,
    link: bool,
    approve: Option<String>,
    invite: bool,
    answer: Option<String>,
    wait_secs: u64,
}

fn parse_args() -> Args {
    let mut args = Args {
        server: "https://ams.konstruct.cc:443".into(),
        username: None,
        add: None,
        find: None,
        send: None,
        link: false,
        approve: None,
        invite: false,
        answer: None,
        wait_secs: 30,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().unwrap_or_else(|| panic!("{flag} needs a value"));
        match flag.as_str() {
            "--server" => args.server = value(),
            "--username" => args.username = Some(value()),
            "--add" => args.add = Some(value()),
            "--find" => args.find = Some(value()),
            "--send" => args.send = Some(value()),
            "--link" => args.link = true,
            "--approve" => args.approve = Some(value()),
            "--invite" => args.invite = true,
            "--answer" => args.answer = Some(value()),
            "--wait" => args.wait_secs = value().parse().expect("--wait takes seconds"),
            other => panic!("unknown flag {other}"),
        }
    }
    args
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,h2=warn,rustls=warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let mut args = parse_args();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let client = construct_client::spawn(
        ClientConfig {
            server_url: args.server.clone(),
            transport: Default::default(),
            no_encrypt: true,
            pq_active: true,
        },
        tx,
    );
    client.send(ClientCommand::RestoreFromDisk);

    let deadline = tokio::time::sleep(std::time::Duration::from_secs(args.wait_secs));
    tokio::pin!(deadline);
    let mut started = false;
    let mut sent: Option<String> = None;
    let mut answering = false;
    let mut to_edit: Option<(String, String)> = None;
    loop {
        let event = tokio::select! {
            _ = &mut deadline, if started => break,
            event = rx.recv() => match event { Some(e) => e, None => break },
        };
        match event {
            ClientEvent::AuthFailed { reason, no_session } => {
                if no_session && args.link {
                    println!("LINKING");
                    client.send(ClientCommand::LinkByQr);
                } else if no_session && let Some(username) = &args.username {
                    println!("REGISTERING {username}");
                    client.send(ClientCommand::Register {
                        username: username.clone(),
                    });
                } else {
                    println!("AUTH_FAILED {reason}");
                    return;
                }
            }
            ClientEvent::Account(info) if !info.user_id.is_empty() => {
                println!(
                    "ACCOUNT user_id={} device_id={}",
                    info.user_id, info.device_id
                );
            }
            ClientEvent::Started(contacts) => {
                started = true;
                println!("STARTED contacts={}", contacts.len());
                if let Some(code) = &args.approve {
                    match construct_client::device_certs::parse_join_code(code) {
                        Some(join) => client.send(ClientCommand::ApproveJoin {
                            device_id: join.device_id,
                            fingerprint: join.fingerprint,
                        }),
                        None => println!("NOT A JOIN CODE {code}"),
                    }
                }
                if let Some(username) = &args.find {
                    client.send(ClientCommand::FindContact {
                        query: username.clone(),
                    });
                }
                if let Some(user_id) = &args.add {
                    client.send(ClientCommand::AddContact {
                        user_id: user_id.clone(),
                        username: format!("peer-{}", &user_id[..8.min(user_id.len())]),
                    });
                }
            }
            ClientEvent::ContactSearchResult(results) => match results.first() {
                Some(hit) => {
                    println!("FOUND {} user_id={}", hit.username, hit.user_id);
                    client.send(ClientCommand::AddContact {
                        user_id: hit.user_id.clone(),
                        username: hit.username.clone(),
                    });
                }
                None => println!("NOT_FOUND"),
            },
            ClientEvent::ContactSearchError(e) => println!("SEARCH_ERROR {e}"),
            // Added by --add, by a --find hit, or by redeeming an invite link: send once.
            ClientEvent::ContactAdded { user_id, username } => {
                println!("ADDED {username} user_id={user_id}");
                if let Some(text) = sent.is_none().then(|| args.send.clone()).flatten() {
                    client.send(ClientCommand::SendText {
                        contact_id: user_id.clone(),
                        text,
                    });
                    sent = Some(user_id);
                }
            }
            ClientEvent::Bridge(BridgeEvent::NewMessage { message: m }) => {
                println!(
                    "RECEIVED from={} id={} text={:?} quote={:?} attachment={:?}",
                    m.peer_id, m.id, m.text, m.quote, m.attachment
                );
                if let Some(text) = args.answer.take() {
                    client.send(ClientCommand::Reply {
                        contact_id: m.peer_id.clone(),
                        text,
                        to: m.id.clone(),
                    });
                    client.send(ClientCommand::React {
                        message_id: m.id,
                        emoji: "👍".into(),
                    });
                    answering = true;
                }
            }
            ClientEvent::Bridge(BridgeEvent::OwnMessage { message: m }) => {
                println!("OWN_COPY to={} id={} text={:?}", m.peer_id, m.id, m.text);
            }
            ClientEvent::Bridge(BridgeEvent::MessageChanged { message: m }) => {
                println!(
                    "CHANGED id={} text={:?} edited={} reactions={:?}",
                    m.id, m.text, m.edited, m.reactions
                );
            }
            ClientEvent::Bridge(BridgeEvent::MessageDelivered { message_id }) => {
                println!("DELIVERED {message_id}");
                if to_edit.as_ref().is_some_and(|(id, _)| *id == message_id) {
                    let (message_id, text) = to_edit.take().expect("checked");
                    client.send(ClientCommand::EditMessage { message_id, text });
                }
            }
            ClientEvent::Bridge(BridgeEvent::Error(e)) => println!("ERROR {e}"),
            ClientEvent::Bridge(BridgeEvent::UnvouchedDevices {
                peer_id,
                device_ids,
            }) => println!("UNVOUCHED {peer_id} {device_ids:?}"),
            ClientEvent::MessageQueued {
                message_id, text, ..
            } => {
                println!("QUEUED {message_id}");
                if std::mem::take(&mut answering) {
                    to_edit = Some((message_id, format!("{text} (edited)")));
                }
            }
            ClientEvent::RegistrationStep(step) => println!("STEP {step:?}"),
            ClientEvent::Notice(n) => println!("NOTICE {n}"),
            ClientEvent::Recovery(state) => {
                println!("RECOVERY {state:?}");
                use construct_client::recovery::RecoveryState;
                if args.invite && matches!(state, RecoveryState::CopyPending | RecoveryState::Ready)
                {
                    client.send(ClientCommand::MintInvite);
                }
            }
            ClientEvent::InviteMinted(result) => match result {
                Ok(link) => println!("INVITE {link}"),
                Err(e) => println!("INVITE_FAILED {e}"),
            },
            ClientEvent::LinkCode(code) => {
                started = true;
                println!("LINK_CODE {code}");
            }
            ClientEvent::LinkFailed(e) => println!("LINK_FAILED {e}"),
            _ => {}
        }
    }
}
