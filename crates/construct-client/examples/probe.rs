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
//! `--find <username or invite link>` instead of `--add`: a username is looked up (only accounts
//! that made themselves discoverable are found), an invite link is redeemed; either is added and
//! sent to.
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
    wait_secs: u64,
}

fn parse_args() -> Args {
    let mut args = Args {
        server: "https://ams.konstruct.cc:443".into(),
        username: None,
        add: None,
        find: None,
        send: None,
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
    let args = parse_args();
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
    loop {
        let event = tokio::select! {
            _ = &mut deadline, if started => break,
            event = rx.recv() => match event { Some(e) => e, None => break },
        };
        match event {
            ClientEvent::AuthFailed { reason, no_session } => {
                if no_session && let Some(username) = &args.username {
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
            ClientEvent::Bridge(BridgeEvent::NewMessage { peer_id, text, .. }) => {
                println!("RECEIVED from={peer_id} text={text:?}");
            }
            ClientEvent::Bridge(BridgeEvent::MessageDelivered { message_id }) => {
                println!("DELIVERED {message_id}");
            }
            ClientEvent::Bridge(BridgeEvent::Error(e)) => println!("ERROR {e}"),
            ClientEvent::MessageQueued { message_id, .. } => println!("QUEUED {message_id}"),
            ClientEvent::RegistrationStep(step) => println!("STEP {step:?}"),
            ClientEvent::Notice(n) => println!("NOTICE {n}"),
            _ => {}
        }
    }
}
