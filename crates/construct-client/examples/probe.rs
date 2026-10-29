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
//! `--file <path>`: with `--add`, send that file too (a photo goes without its metadata). A file
//! that arrives is fetched, opened and written to `$HOME/received-<name>`; `MEDIA` names it.
//!
//! `--settings`: once started, print the account's settings (username, devices, receipts).
//! `--set-username <name>`: change the username first; `--discoverable on|off` likewise;
//! `--revoke <device id|others>` signs out a device of the account, or all but this one;
//! `--rename-device <name>` names this device for the account's others.
//!
//! `--goodbye logout|everywhere|delete|local`: once started, sign out here, sign out every device,
//! delete the account, or wipe only this device; prints `LOGGED_OUT` (or `DELETE_FAILED`) and stops.
//!
//! `--profile <name>` [`--avatar <jpeg>`]: set our shared name and picture; `--share-with <id>`:
//! share our profile with that contact. A profile shared with us prints `CONTACT`.
//!
//! `--invite`: once the account's recovery key is in place, mint an invite link and print it;
//! with `--revoke-invites`, then revoke every live invite (`INVITES` lists them).
//!
//! `--link` instead of `--username`: become a new device of an existing account — print the
//! `konstruct://link-to-me` code for the phone to scan, then wait for its approval.
//!
//! `--offer-link`: once started, show a Flow A code (`LINK_OFFER <code>`) and wait for a device
//! to link with it; `--link-code <code>` instead of `--username`: become a device of the account
//! that showed it.
//!
//! `--history-to <device id> --history-file <path>`: once started, write this device's history
//! to that file for that device of the account (`HISTORY_EXPORTED`); `--import-history <path>`:
//! read one (`HISTORY_IMPORTED`). `--history-nearby-to <device id>`: send it over the local
//! network to that device, which takes it by itself while it runs (`HISTORY_NEARBY` steps).
//!
//! `--veil on|off`: once started, set the VEIL mode (`VEIL` lines follow); `--veil-link <link>`:
//! take the front of a `konstruct://veil-config` link first; `--veil-voucher`: print a voucher
//! link for another device (`VEIL_VOUCHER`).
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
    file: Option<String>,
    settings: bool,
    set_username: Option<String>,
    discoverable: Option<bool>,
    revoke: Option<String>,
    rename_device: Option<String>,
    profile: Option<String>,
    avatar: Option<String>,
    share_with: Option<String>,
    goodbye: Option<String>,
    offer_link: bool,
    link_code: Option<String>,
    revoke_invites: bool,
    history_to: Option<String>,
    history_file: Option<String>,
    import_history: Option<String>,
    history_nearby_to: Option<String>,
    veil: Option<String>,
    veil_link: Option<String>,
    veil_voucher: bool,
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
        file: None,
        settings: false,
        set_username: None,
        discoverable: None,
        revoke: None,
        rename_device: None,
        profile: None,
        avatar: None,
        share_with: None,
        goodbye: None,
        offer_link: false,
        link_code: None,
        revoke_invites: false,
        history_to: None,
        history_file: None,
        import_history: None,
        history_nearby_to: None,
        veil: None,
        veil_link: None,
        veil_voucher: false,
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
            "--file" => args.file = Some(value()),
            "--settings" => args.settings = true,
            "--set-username" => args.set_username = Some(value()),
            "--discoverable" => args.discoverable = Some(value() == "on"),
            "--revoke" => args.revoke = Some(value()),
            "--rename-device" => args.rename_device = Some(value()),
            "--profile" => args.profile = Some(value()),
            "--avatar" => args.avatar = Some(value()),
            "--share-with" => args.share_with = Some(value()),
            "--goodbye" => args.goodbye = Some(value()),
            "--offer-link" => args.offer_link = true,
            "--revoke-invites" => args.revoke_invites = true,
            "--history-to" => args.history_to = Some(value()),
            "--history-file" => args.history_file = Some(value()),
            "--import-history" => args.import_history = Some(value()),
            "--history-nearby-to" => args.history_nearby_to = Some(value()),
            "--link-code" => args.link_code = Some(value()),
            "--veil" => args.veil = Some(value()),
            "--veil-link" => args.veil_link = Some(value()),
            "--veil-voucher" => args.veil_voucher = true,
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
    // Before signing in: with VEIL on and no front yet, the front has to come first.
    if let Some(link) = args.veil_link.take() {
        client.send(ClientCommand::ImportVeilLink(link));
    }

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
                if no_session && let Some(token) = args.link_code.take() {
                    println!("LINKING WITH CODE");
                    client.send(ClientCommand::LinkDevice { token });
                } else if no_session && args.link {
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
                if let Some(name) = args.set_username.take() {
                    client.send(ClientCommand::ChangeUsername(name));
                }
                if let Some(name) = args.profile.take() {
                    let avatar = match args.avatar.take() {
                        Some(path) => construct_client::AvatarChange::Set(
                            std::fs::read(path).expect("--avatar is readable"),
                        ),
                        None => construct_client::AvatarChange::Keep,
                    };
                    client.send(ClientCommand::SetProfile {
                        display_name: Some(name),
                        avatar,
                    });
                }
                if let Some(contact_id) = args.share_with.take() {
                    client.send(ClientCommand::ShareProfile {
                        contact_id,
                        on: true,
                    });
                }
                if let Some(name) = args.rename_device.take() {
                    client.send(ClientCommand::RenameDevice(name));
                }
                if let Some(target) = args.revoke.take() {
                    client.send(ClientCommand::RevokeDevices(
                        (target != "others").then_some(target),
                    ));
                }
                if let Some(on) = args.discoverable.take() {
                    client.send(ClientCommand::SetDiscoverable(on));
                }
                if args.settings {
                    client.send(ClientCommand::LoadSettings);
                }
                if args.offer_link {
                    client.send(ClientCommand::OfferLink);
                }
                if let (Some(device_id), Some(path)) = (args.history_to.take(), &args.history_file)
                {
                    client.send(ClientCommand::ExportHistory {
                        device_id,
                        path: path.into(),
                    });
                }
                if let Some(path) = args.import_history.take() {
                    client.send(ClientCommand::ImportHistory(path.into()));
                }
                if let Some(device_id) = args.history_nearby_to.take() {
                    client.send(ClientCommand::OfferHistoryNearby { device_id });
                }
                if args.veil_voucher {
                    client.send(ClientCommand::IssueVeilVoucher);
                }
                match args.veil.take().as_deref() {
                    Some("on") => {
                        client.send(ClientCommand::SetVeilMode(construct_client::VeilMode::On))
                    }
                    Some("off") => {
                        client.send(ClientCommand::SetVeilMode(construct_client::VeilMode::Off))
                    }
                    Some(other) => panic!("--veil takes on or off, not {other}"),
                    None => client.send(ClientCommand::LoadVeil),
                }
                match args.goodbye.as_deref() {
                    Some("logout") => client.send(ClientCommand::Logout),
                    Some("everywhere") => client.send(ClientCommand::LogoutEverywhere),
                    Some("delete") => {
                        client.send(ClientCommand::DeleteAccount { local_only: false })
                    }
                    Some("local") => client.send(ClientCommand::DeleteAccount { local_only: true }),
                    Some(other) => panic!("--goodbye {other}?"),
                    None => {}
                }
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
                        username: String::new(),
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
                    sent = Some(user_id.clone());
                }
                if let Some(path) = args.file.take() {
                    let bytes = std::fs::read(&path).expect("--file is readable");
                    client.send(ClientCommand::SendFile {
                        contact_id: user_id,
                        name: path,
                        bytes,
                        caption: "a file from the probe".into(),
                    });
                }
            }
            ClientEvent::Bridge(BridgeEvent::NewMessage { message: m }) => {
                println!(
                    "RECEIVED from={} id={} text={:?} quote={:?} attachment={:?}",
                    m.peer_id, m.id, m.text, m.quote, m.attachment
                );
                for (index, info) in m.media.iter().enumerate() {
                    println!("  FILE {index} {info:?}");
                    client.send(ClientCommand::LoadMedia {
                        message_id: m.id.clone(),
                        index,
                    });
                }
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
                println!(
                    "OWN_COPY to={} id={} text={:?} media={:?}",
                    m.peer_id, m.id, m.text, m.media
                );
            }
            ClientEvent::Media {
                message_id,
                index,
                result,
            } => match result {
                Ok(media) => {
                    let name = media
                        .filename
                        .unwrap_or_else(|| format!("{message_id}-{index}"));
                    let path = std::path::Path::new(&std::env::var("HOME").unwrap_or_default())
                        .join(format!("received-{name}"));
                    std::fs::write(&path, &media.bytes).expect("written");
                    println!(
                        "MEDIA {message_id} {index} {} bytes {} -> {}",
                        media.bytes.len(),
                        media.mime,
                        path.display()
                    );
                }
                Err(e) => println!("MEDIA_FAILED {message_id} {index} {e}"),
            },
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
            ClientEvent::Bridge(BridgeEvent::ContactUpdated { contact: c }) => println!(
                "CONTACT {} name={:?} sharing={} avatar={:?}",
                c.user_id,
                c.display_name,
                c.sharing,
                c.avatar.as_ref().map(Vec::len)
            ),
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
            ClientEvent::Settings(s) => {
                println!(
                    "SETTINGS username={:?} receipts={} discoverable={:?} this_device={:?}",
                    s.username, s.delivery_receipts, s.discoverable, s.device_name
                );
                println!(
                    "  KEY {:?} media={} bytes in {} files {:?}",
                    s.fingerprint, s.media_bytes, s.media_files, s.media
                );
                println!("  INVITES {}", s.invites.len());
                if args.revoke_invites && !s.invites.is_empty() {
                    args.revoke_invites = false;
                    client.send(ClientCommand::RevokeInvites(
                        s.invites.iter().map(|i| i.jti.clone()).collect(),
                    ));
                }
                for d in &s.devices {
                    println!(
                        "  DEVICE {} current={} described={:?}",
                        &d.device.device_id[..8],
                        d.device.is_current,
                        d.description.as_ref().map(|x| (&x.name, x.platform))
                    );
                }
            }
            ClientEvent::Recovery(state) => {
                println!("RECOVERY {state:?}");
                use construct_client::recovery::RecoveryState;
                if args.invite && matches!(state, RecoveryState::CopyPending | RecoveryState::Ready)
                {
                    client.send(ClientCommand::MintInvite);
                }
            }
            ClientEvent::InviteMinted(result) => match result {
                Ok(link) => {
                    println!("INVITE {link}");
                    if args.revoke_invites {
                        client.send(ClientCommand::LoadSettings);
                    }
                }
                Err(e) => println!("INVITE_FAILED {e}"),
            },
            ClientEvent::LinkCode(code) => {
                started = true;
                println!("LINK_CODE {code}");
            }
            ClientEvent::LinkFailed(e) => println!("LINK_FAILED {e}"),
            ClientEvent::LinkOffer { code, expires_at } => {
                println!("LINK_OFFER {} expires_at={expires_at}", code.as_str())
            }
            ClientEvent::LinkOfferEnded(ended) => println!("LINK_OFFER_ENDED {ended:?}"),
            ClientEvent::HistoryExported(result) => println!("HISTORY_EXPORTED {result:?}"),
            ClientEvent::HistoryImported(result) => println!("HISTORY_IMPORTED {result:?}"),
            ClientEvent::HistoryNearby(step) => println!("HISTORY_NEARBY {step:?}"),
            ClientEvent::Veil(status) => println!("VEIL {status:?}"),
            ClientEvent::VeilVoucher(Ok((link, exp))) => println!("VEIL_VOUCHER exp={exp} {link}"),
            ClientEvent::VeilVoucher(Err(e)) => println!("VEIL_VOUCHER_FAILED {e}"),
            ClientEvent::LoggedOut if args.goodbye.is_some() => {
                println!("LOGGED_OUT");
                return;
            }
            ClientEvent::DeleteAccountFailed(e) => {
                println!("DELETE_FAILED {e}");
                return;
            }
            _ => {}
        }
    }
}
