//! The screens, focus, keys and drawing. What the program *does* is the client layer
//! (`construct-client`), running as its own task; this file sends it commands for keys and turns
//! its events into what is on screen. Where the keys come from and where the frame goes is the
//! shell's.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph},
};
use tokio::sync::mpsc;

use construct_client::{
    self as client, AccountInfo, ClientCommand, ClientConfig, ClientEvent, ClientHandle,
    FindStarted,
    bridge::BridgeEvent,
    config::{SessionState, TransportConfig},
    local_store::StoredContact,
};

use crate::{
    screens::onboarding::OnboardingField,
    screens::{
        ChatListPane, ChatViewPane, ConnectionState, ContactSearchScreen, DeviceLinkScreen,
        OnboardingScreen, RegistrationScreen, SafetyNumberScreen, SettingsAction, SettingsScreen,
        StatusBar, UnlockMode, UnlockScreen,
        chat_list::Contact,
        chat_view::{ChatMessage, MessageKind},
        qr_widget::QrWidget,
    },
    theme::ThemeMode,
};

/// What woke the app: a client event, or the registration spinner's tick.
pub enum Wake {
    Client(Box<ClientEvent>),
    Tick,
}

/// How many messages opening a conversation shows.
const HISTORY_LIMIT: usize = 50;

#[derive(Debug, Clone, PartialEq)]
enum Screen {
    /// Checking for saved session on startup.
    Startup,
    /// Existing encrypted session found — enter passphrase to unlock.
    Unlock,
    /// New session created — choose a passphrase to protect it.
    SetPassphrase,
    /// Onboarding form (first run or after logout).
    Onboarding,
    /// Device link form — enter link token from another device.
    DeviceLink,
    /// Registration in progress — animated checklist.
    Registering,
    /// Auth request in flight — show spinner message.
    Connecting(String),
    /// Auth failed — show error, return to onboarding.
    AuthError(String),
    /// Authenticated — show main chat UI.
    Main,
    /// Settings (server, transport, device ID, logout, safety number…).
    Settings,
    /// Full-screen identity QR code (any key to dismiss).
    IdentityQr,
    /// Add-contact search overlay.
    ContactSearch,
    /// Safety number verification for the currently selected contact.
    SafetyNumber,
}

#[derive(Debug, Clone, PartialEq)]
enum Focus {
    ContactList,
    ChatView,
    Compose,
}

/// Configuration derived from config file + CLI overrides.
/// Passed to `App::new()` at startup.
pub struct AppConfig {
    pub server_url: String,
    pub transport: TransportConfig,
    pub no_encrypt: bool,
    pub pq_active: bool,
    pub theme: ThemeMode,
}

pub struct App {
    client: ClientHandle,
    /// Everything the client reports back.
    client_rx: mpsc::UnboundedReceiver<ClientEvent>,
    /// The client's last word on who we are.
    account: AccountInfo,
    /// The invite our QR code shows, as last minted.
    invite: Option<Result<String, String>>,
    /// Spinner ticks for the registration screen — a front-end concern, not the client's.
    tick_tx: mpsc::UnboundedSender<()>,
    tick_rx: mpsc::UnboundedReceiver<()>,
    screen: Screen,
    onboarding: OnboardingScreen,
    device_link: DeviceLinkScreen,
    unlock_screen: UnlockScreen,
    registration: RegistrationScreen,
    /// Handle to the spinner ticker task — present only while Screen::Registering is active.
    ticker_handle: Option<tokio::task::AbortHandle>,
    focus: Focus,
    chat_list: ChatListPane,
    chat_view: ChatViewPane,
    /// The contact whose conversation the chat view shows.
    open_peer: Option<String>,
    status: String,
    running: bool,
    theme: ThemeMode,
    /// Live connection state shown in the status bar.
    connection: ConnectionState,
    settings_screen: SettingsScreen,
    contact_search: ContactSearchScreen,
    /// Safety number widget for the currently selected contact.
    safety_number: Option<SafetyNumberScreen>,
    /// When `Some`, a delete-confirmation dialog is shown for the given contact id.
    delete_confirm: Option<String>,
}

impl App {
    pub fn new(cfg: AppConfig) -> Self {
        let chat_list = ChatListPane::new();
        let initial_name = chat_list
            .selected_contact()
            .map(|c| c.display_name.clone())
            .unwrap_or_default();

        let (client_tx, client_rx) = mpsc::unbounded_channel();
        let (tick_tx, tick_rx) = mpsc::unbounded_channel();
        let account = AccountInfo {
            server_url: cfg.server_url.clone(),
            transport_label: client::transport_label(&cfg.transport),
            pq_active: cfg.pq_active,
            ..AccountInfo::default()
        };
        let client = client::spawn(
            ClientConfig {
                server_url: cfg.server_url,
                transport: cfg.transport,
                no_encrypt: cfg.no_encrypt,
                pq_active: cfg.pq_active,
            },
            client_tx,
        );
        let settings_screen = fresh_settings_screen(&account);

        Self {
            client,
            client_rx,
            account,
            invite: None,
            tick_tx,
            tick_rx,
            screen: Screen::Startup,
            onboarding: OnboardingScreen::new(),
            device_link: DeviceLinkScreen::new(),
            unlock_screen: UnlockScreen::new(UnlockMode::Unlock),
            registration: RegistrationScreen::new(),
            ticker_handle: None,
            focus: Focus::ContactList,
            chat_list,
            chat_view: ChatViewPane::new(initial_name),
            open_peer: None,
            status: "Ready".into(),
            running: true,
            theme: cfg.theme,
            connection: ConnectionState::default(),
            settings_screen,
            contact_search: ContactSearchScreen::new(),
            safety_number: None,
            delete_confirm: None,
        }
    }

    /// Choose the first screen from what is on disk. Call once, before the first draw.
    pub fn start(&mut self) {
        self.startup_check();
    }

    /// False once the person asked to quit; the shell stops then.
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Wait for the client's next event or the spinner's tick. Cancel-safe: a shell selects on
    /// it beside its own input and hands the result to [`App::on_wake`].
    pub async fn wake(&mut self) -> Wake {
        tokio::select! {
            Some(event) = self.client_rx.recv() => Wake::Client(Box::new(event)),
            Some(()) = self.tick_rx.recv() => Wake::Tick,
        }
    }

    pub fn on_wake(&mut self, wake: Wake) {
        match wake {
            Wake::Client(event) => self.handle_client_event(*event),
            Wake::Tick => {
                if matches!(self.screen, Screen::Registering) {
                    self.registration.tick();
                }
            }
        }
    }

    /// Pasted text, typed into whatever has focus one character at a time — an invite link
    /// pasted into the search, a link token into the device-link form.
    pub fn handle_paste(&mut self, text: &str) {
        for c in text.chars().filter(|c| !c.is_control()) {
            self.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
    }

    // ── Startup ─────────────────────────────────────────────────────────────────

    /// Detect session state on disk and set the initial screen accordingly.
    fn startup_check(&mut self) {
        match client::stored_session_state() {
            SessionState::Encrypted => self.screen = Screen::Unlock,
            SessionState::Plaintext => {
                self.client.send(ClientCommand::RestoreFromDisk);
                self.screen = Screen::Connecting("Restoring session…".into());
            }
            SessionState::None => self.screen = Screen::Onboarding,
        }
    }

    fn start_registration(&mut self, username: String) {
        self.client.send(ClientCommand::Register { username });
        self.registration = RegistrationScreen::new();
        self.start_ticker();
        self.screen = Screen::Registering;
    }

    /// Spawn a background task that ticks every 80ms for the registration spinner.
    fn start_ticker(&mut self) {
        self.stop_ticker();
        let tx = self.tick_tx.clone();
        let handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_millis(80)).await;
                if tx.send(()).is_err() {
                    break;
                }
            }
        });
        self.ticker_handle = Some(handle.abort_handle());
    }

    fn stop_ticker(&mut self) {
        if let Some(h) = self.ticker_handle.take() {
            h.abort();
        }
    }

    // ── Client events ───────────────────────────────────────────────────────────

    fn handle_client_event(&mut self, event: ClientEvent) {
        match event {
            ClientEvent::Account(account) => self.apply_account(account),
            ClientEvent::Started(contacts) => {
                self.finish_registration_screen();
                self.enter_main(contacts);
            }
            ClientEvent::NeedsPassphrase => {
                self.finish_registration_screen();
                self.unlock_screen.reset_for_mode(UnlockMode::SetNew);
                self.screen = Screen::SetPassphrase;
            }
            ClientEvent::SaveFailed(e) => {
                self.finish_registration_screen();
                self.screen = Screen::AuthError(e);
            }
            ClientEvent::AuthFailed { reason, no_session } => {
                self.finish_registration_screen();
                self.stop_ticker();
                // Auto-restore on startup (plaintext path): no passphrase has been entered, so
                // show Onboarding — the user likely logged out or the session file is stale.
                // Unlock path: the passphrase opened the session, so this is a server/network
                // error; show it rather than silently landing on onboarding.
                let is_auto_restore = matches!(self.screen, Screen::Connecting(_))
                    && !self.account.has_session_key
                    && self.onboarding.username.is_empty();
                if no_session || is_auto_restore {
                    self.screen = Screen::Onboarding;
                } else {
                    tracing::error!(error = %reason, "Authentication failed");
                    self.screen = Screen::AuthError(reason);
                }
            }
            ClientEvent::UnlockFailed(e) => {
                self.unlock_screen.set_error(e);
                self.screen = Screen::Unlock;
            }
            ClientEvent::PassphraseFailed(e) => self.unlock_screen.set_error(e),
            ClientEvent::RegistrationStep(step) => self.registration.advance(step.index()),
            ClientEvent::Bridge(evt) => self.handle_bridge_event(evt),
            ClientEvent::SearchStarted(started) => {
                self.contact_search.searching = true;
                if let FindStarted::InviteRedemption = started {
                    self.contact_search.status = Some("Redeeming invite…".into());
                }
            }
            ClientEvent::ContactSearchResult(results) => self.contact_search.set_results(results),
            ClientEvent::ContactSearchError(msg) => {
                let shown = if msg.contains("rate limit") || msg.contains("8:") {
                    "Search limit (5/hour). Wait, then Enter once.".to_string()
                } else {
                    msg
                };
                self.contact_search.set_error(shown);
            }
            ClientEvent::ContactAdded { user_id, username } => {
                if !self.chat_list.contacts.iter().any(|c| c.id == user_id) {
                    self.chat_list.add_contact(Contact {
                        id: user_id,
                        display_name: username.clone(),
                        unread: 0,
                        last_message: None,
                    });
                }
                self.status = format!("Added @{username}");
                self.contact_search.reset();
                self.screen = Screen::Main;
            }
            ClientEvent::ContactRemoved { peer_id } => self.remove_contact_from_view(&peer_id),
            ClientEvent::MessageQueued {
                contact_id,
                message_id,
                text,
            } => {
                if self.open_peer.as_deref() == Some(contact_id.as_str()) {
                    self.chat_view.messages.push(ChatMessage {
                        id: message_id,
                        kind: MessageKind::Sent,
                        text,
                        time: current_time_hhmm(),
                    });
                }
                self.status = "Message sent".into();
            }
            ClientEvent::History { peer_id, messages } => {
                if self.open_peer.as_deref() != Some(peer_id.as_str()) {
                    return; // the user has moved on
                }
                self.chat_view.messages.clear();
                for msg in messages {
                    let kind = if msg.direction == "sent" {
                        MessageKind::Sent
                    } else {
                        MessageKind::Received
                    };
                    let secs = msg.timestamp_ms / 1000;
                    self.chat_view.messages.push(ChatMessage {
                        id: msg.id,
                        kind,
                        text: msg.text,
                        time: format!("{:02}:{:02}", (secs / 3600) % 24, (secs / 60) % 60),
                    });
                }
            }
            ClientEvent::SafetyNumber { contact_id, number } => {
                let name = self
                    .chat_list
                    .contacts
                    .iter()
                    .find(|c| c.id == contact_id)
                    .map(|c| c.display_name.clone())
                    .unwrap_or(contact_id);
                self.safety_number = Some(SafetyNumberScreen::new(name, number));
                self.screen = Screen::SafetyNumber;
            }
            ClientEvent::InviteMinted(result) => {
                if let Err(ref e) = result {
                    tracing::warn!("invite generation failed: {e}");
                }
                self.invite = Some(result);
            }
            ClientEvent::LinkCode(code) => {
                self.device_link.own_token = Some(code);
                self.device_link.set_status(
                    "On your phone: Konstruct → Settings → Devices → scan this code",
                    false,
                );
            }
            ClientEvent::LinkFailed(reason) => {
                self.device_link.own_token = None;
                self.device_link
                    .set_status(format!("{reason}   Enter=show a new code"), true);
            }
            ClientEvent::LoggedOut => self.reset_after_logout(),
            ClientEvent::Notice(text) => self.status = text,
        }
    }

    /// Registration finished one way or another: show every step done and stop the spinner.
    fn finish_registration_screen(&mut self) {
        if matches!(self.screen, Screen::Registering) {
            self.stop_ticker();
            self.registration.active_step = crate::screens::registration::STEPS.len();
        }
    }

    fn apply_account(&mut self, account: AccountInfo) {
        let signed_in = !account.user_id.is_empty();
        if signed_in {
            self.status = format!("Connected as {}", account.user_id);
            self.connection = ConnectionState::Connected {
                transport: account.transport_label.into(),
                latency_ms: None,
            };
            self.settings_screen.update(
                &account.server_url,
                account.transport_label,
                &account.device_id,
                &account.user_id,
                account.pq_active,
            );
        }
        self.account = account;
    }

    /// The client is running: show its contacts and the chat screen.
    fn enter_main(&mut self, contacts: Vec<StoredContact>) {
        self.chat_list.set_contacts(
            contacts
                .into_iter()
                .map(|c| Contact {
                    id: c.user_id,
                    display_name: c.display_name,
                    unread: 0,
                    last_message: None,
                })
                .collect(),
        );
        self.screen = Screen::Main;
    }

    fn handle_bridge_event(&mut self, evt: BridgeEvent) {
        match evt {
            // Into the open conversation only if it is the writer's; it went into every
            // conversation that happened to be open until a linked device had several.
            BridgeEvent::NewMessage {
                peer_id,
                message_id,
                text,
                ..
            } => {
                if self.open_peer.as_deref() == Some(peer_id.as_str()) {
                    self.chat_view.messages.push(ChatMessage {
                        id: message_id,
                        kind: MessageKind::Received,
                        text,
                        time: current_time_hhmm(),
                    });
                    self.chat_view.on_new_message();
                } else {
                    let name = self.contact_name(&peer_id);
                    self.status = format!("New message from @{name}");
                }
            }
            BridgeEvent::OwnMessage {
                peer_id,
                message_id,
                text,
                ..
            } => {
                if self.open_peer.as_deref() == Some(peer_id.as_str()) {
                    self.chat_view.messages.push(ChatMessage {
                        id: message_id,
                        kind: MessageKind::Sent,
                        text,
                        time: current_time_hhmm(),
                    });
                    self.chat_view.on_new_message();
                }
            }
            BridgeEvent::MessageDelivered { message_id: _ } => {
                // TODO: update delivery indicator
            }
            BridgeEvent::StreamStatus { connected } => {
                if connected {
                    self.connection = ConnectionState::Connected {
                        transport: self.account.transport_label.into(),
                        latency_ms: None,
                    };
                    self.status = "● connected".into();
                } else {
                    self.connection = ConnectionState::Disconnected;
                    self.status = "○ disconnected".into();
                }
            }
            BridgeEvent::StreamReconnecting { attempt, delay_ms } => {
                let interval = std::time::Duration::from_millis(delay_ms);
                self.connection = ConnectionState::Reconnecting {
                    attempt,
                    next_retry: std::time::Instant::now() + interval,
                    interval,
                };
                self.status = format!("↺ reconnecting (attempt {attempt})");
            }
            BridgeEvent::Error(e) => {
                self.status = format!("Bridge error: {e}");
            }
            BridgeEvent::SessionReady { contact_id } => {
                let name = self
                    .chat_list
                    .contacts
                    .iter()
                    .find(|c| c.id == contact_id)
                    .map(|c| c.display_name.as_str())
                    .unwrap_or("contact");
                self.status = format!("Session ready with @{name}");
            }
            // Only told: the devices still receive messages (owner's decision).
            BridgeEvent::UnvouchedDevices {
                peer_id,
                device_ids,
            } => {
                let name = self.contact_name(&peer_id);
                let count = device_ids.len();
                self.status = format!(
                    "⚠ @{name}: {count} new device(s) not vouched for by their other devices — compare safety numbers"
                );
            }
        }
    }

    // ── Event handling ──────────────────────────────────────────────────────────

    pub fn handle_key(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }

        // Ctrl+C always exits regardless of screen.
        if key.code == KeyCode::Char('c') && key.modifiers == KeyModifiers::CONTROL {
            self.running = false;
            return;
        }

        // Use discriminant checks to avoid cloning Screen variants that hold String data.
        if matches!(self.screen, Screen::Startup | Screen::Connecting(_)) {
            return;
        }
        if matches!(self.screen, Screen::AuthError(_)) {
            // A session key means the user came from Unlock — go back there to retry.
            // Otherwise it was an auto-restore or registration error: Onboarding.
            if self.account.has_session_key {
                self.unlock_screen.reset_for_mode(UnlockMode::Unlock);
                self.screen = Screen::Unlock;
            } else {
                self.screen = Screen::Onboarding;
            }
            return;
        }
        if matches!(self.screen, Screen::Unlock) {
            return self.handle_unlock(key);
        }
        if matches!(self.screen, Screen::SetPassphrase) {
            return self.handle_set_passphrase(key);
        }
        if matches!(self.screen, Screen::Onboarding) {
            return self.handle_onboarding(key);
        }
        if matches!(self.screen, Screen::DeviceLink) {
            return self.handle_device_link(key);
        }
        if matches!(self.screen, Screen::Main) {
            return self.handle_main(key);
        }
        if matches!(self.screen, Screen::Settings) {
            return self.handle_settings(key);
        }
        if matches!(self.screen, Screen::ContactSearch) {
            return self.handle_contact_search(key);
        }
        if matches!(self.screen, Screen::SafetyNumber | Screen::IdentityQr) {
            // Any key goes back to settings.
            self.screen = Screen::Settings;
        }
    }

    fn handle_onboarding(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q')
                if key.modifiers == KeyModifiers::NONE
                    && self.onboarding.focused_field == OnboardingField::Username
                    && self.onboarding.username.is_empty() =>
            {
                self.running = false;
            }
            KeyCode::Char('c') if key.modifiers == KeyModifiers::CONTROL => {
                self.running = false;
            }
            // Tab: link this device to an account on a phone — show a code for it to scan.
            KeyCode::Tab | KeyCode::BackTab => {
                self.device_link = DeviceLinkScreen::new();
                self.client.send(ClientCommand::LinkByQr);
                self.screen = Screen::DeviceLink;
            }
            KeyCode::Enter => {
                let username = self.onboarding.username.trim().to_string();
                self.onboarding.status = None;
                self.start_registration(username);
            }
            KeyCode::Backspace => {
                self.onboarding.pop_char();
                self.onboarding.status = None;
            }
            KeyCode::Char(c) => {
                self.onboarding.push_char(c);
                self.onboarding.status = None;
            }
            _ => {}
        }
    }

    fn handle_unlock(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Backspace => {
                self.unlock_screen.pop_char();
                self.unlock_screen.clear_error();
            }
            KeyCode::Char(c) => {
                self.unlock_screen.push_char(c);
                self.unlock_screen.clear_error();
            }
            KeyCode::Enter => {
                let passphrase = self.unlock_screen.take_passphrase();
                if passphrase.is_empty() {
                    self.unlock_screen.set_error("Enter your passphrase");
                    return;
                }
                // Key derivation runs in the client task; a wrong passphrase comes back as
                // UnlockFailed and returns here.
                self.client.send(ClientCommand::Unlock(passphrase));
                self.screen = Screen::Connecting("Authenticating…".into());
            }
            _ => {}
        }
    }

    fn handle_set_passphrase(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Backspace => self.unlock_screen.pop_char(),
            KeyCode::Char(c) => self.unlock_screen.push_char(c),
            KeyCode::Enter => {
                let passphrase = self.unlock_screen.take_passphrase();
                if passphrase.is_empty() {
                    self.unlock_screen
                        .set_error("Choose a passphrase to protect your session");
                    return;
                }
                self.client.send(ClientCommand::SetPassphrase(passphrase));
            }
            _ => {}
        }
    }

    fn handle_device_link(&mut self, key: KeyEvent) {
        use crate::screens::device_link::DeviceLinkTab;
        match key.code {
            KeyCode::Esc => {
                self.client.send(ClientCommand::CancelLink);
                self.screen = Screen::Onboarding;
            }
            KeyCode::Char('q')
                if key.modifiers == KeyModifiers::NONE
                    && self.device_link.tab == DeviceLinkTab::Show =>
            {
                self.client.send(ClientCommand::CancelLink);
                self.screen = Screen::Onboarding;
            }
            KeyCode::Char('c') if key.modifiers == KeyModifiers::CONTROL => {
                self.running = false;
            }
            KeyCode::Tab | KeyCode::BackTab => self.device_link.toggle_tab(),
            // A code that failed or expired: show a new one.
            KeyCode::Enter
                if self.device_link.tab == DeviceLinkTab::Show
                    && self.device_link.own_token.is_none() =>
            {
                self.device_link.set_status("Making a new code…", false);
                self.client.send(ClientCommand::LinkByQr);
            }
            KeyCode::Enter if self.device_link.tab == DeviceLinkTab::Scan => {
                let token = self.device_link.token.trim().to_string();
                if token.is_empty() {
                    self.device_link
                        .set_status("Paste the link token first", true);
                } else {
                    self.client.send(ClientCommand::CancelLink);
                    self.device_link.clear_status();
                    self.client.send(ClientCommand::LinkDevice { token });
                    self.screen = Screen::Connecting("Confirming device link…".into());
                }
            }
            KeyCode::Backspace => {
                self.device_link.pop_char();
            }
            KeyCode::Char(c) => {
                self.device_link.push_char(c);
            }
            _ => {}
        }
    }

    fn handle_main(&mut self, key: KeyEvent) {
        // If a delete-confirm dialog is active, intercept all keys.
        if self.delete_confirm.is_some() {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    if let Some(peer_id) = self.delete_confirm.take() {
                        self.client.send(ClientCommand::DeleteContact { peer_id });
                    }
                }
                _ => {
                    self.delete_confirm = None;
                }
            }
            return;
        }
        if is_quit(&key) && self.focus != Focus::Compose {
            self.running = false;
            return;
        }
        match self.focus {
            Focus::ContactList => match key.code {
                KeyCode::Down | KeyCode::Char('j') => self.chat_list.next(),
                KeyCode::Up | KeyCode::Char('k') => self.chat_list.prev(),
                // Delete selected contact (x key)
                KeyCode::Char('x') if key.modifiers == KeyModifiers::NONE => {
                    if let Some(c) = self.chat_list.selected_contact() {
                        self.delete_confirm = Some(c.id.clone());
                    }
                }
                KeyCode::Enter | KeyCode::Tab => {
                    self.open_selected_chat();
                    self.set_focus(Focus::ChatView);
                }
                // Open settings
                KeyCode::Char('s') if key.modifiers == KeyModifiers::NONE => {
                    self.screen = Screen::Settings;
                }
                // Add contact / search (`a` as documented, `n` as the old binding)
                KeyCode::Char('a' | 'n') if key.modifiers == KeyModifiers::NONE => {
                    self.contact_search.reset();
                    self.screen = Screen::ContactSearch;
                }
                _ => {}
            },
            Focus::ChatView => match key.code {
                KeyCode::Tab | KeyCode::Char('i') => self.set_focus(Focus::Compose),
                KeyCode::BackTab => self.set_focus(Focus::ContactList),
                KeyCode::Esc => self.set_focus(Focus::ContactList),
                KeyCode::PageUp | KeyCode::Char('u') => self.chat_view.scroll_up(10),
                KeyCode::PageDown | KeyCode::Char('d') => self.chat_view.scroll_down(10),
                KeyCode::Up | KeyCode::Char('k') => self.chat_view.scroll_up(1),
                KeyCode::Down | KeyCode::Char('j') => self.chat_view.scroll_down(1),
                KeyCode::Home => self.chat_view.scroll_to_top(),
                KeyCode::End => self.chat_view.scroll_to_bottom(),
                _ => {}
            },
            Focus::Compose => match key.code {
                KeyCode::Esc => self.set_focus(Focus::ChatView),
                KeyCode::Enter => {
                    let text = self.chat_view.take_compose();
                    if !text.trim().is_empty()
                        && let Some(contact) = self.chat_list.selected_contact()
                    {
                        self.client.send(ClientCommand::SendText {
                            contact_id: contact.id.clone(),
                            text,
                        });
                    }
                }
                KeyCode::Backspace => self.chat_view.pop_char(),
                KeyCode::Char(c) => self.chat_view.push_char(c),
                _ => {}
            },
        }
    }

    /// Show the selected person's conversation; the history arrives as an event.
    fn open_selected_chat(&mut self) {
        let Some(c) = self.chat_list.selected_contact() else {
            return;
        };
        self.chat_view.contact_name = c.display_name.clone();
        self.chat_view.messages.clear();
        self.open_peer = Some(c.id.clone());
        self.client.send(ClientCommand::LoadHistory {
            peer_id: c.id.clone(),
            limit: HISTORY_LIMIT,
        });
    }

    fn set_focus(&mut self, f: Focus) {
        self.chat_list.focused = f == Focus::ContactList;
        self.chat_view.focused = f == Focus::ChatView;
        self.chat_view.compose_focused = f == Focus::Compose;
        self.focus = f;
    }

    fn handle_settings(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => self.screen = Screen::Main,
            KeyCode::Up | KeyCode::Char('k') => self.settings_screen.prev(),
            KeyCode::Down | KeyCode::Char('j') => self.settings_screen.next(),
            KeyCode::Enter => {
                if let Some(action) = self.settings_screen.confirm() {
                    match action {
                        SettingsAction::CycleTheme => self.cycle_theme(),
                        SettingsAction::Back => self.screen = Screen::Main,
                        SettingsAction::Logout => self.client.send(ClientCommand::Logout),
                        SettingsAction::ShowSafetyNumber => self.open_safety_number_screen(),
                        SettingsAction::ExportKeys => {
                            self.client.send(ClientCommand::ExportIdentityKey);
                        }
                        SettingsAction::ShowMyQr => self.show_my_qr(),
                    }
                }
            }
            // Shortcut keys
            KeyCode::Char('l') | KeyCode::Char('L') => self.client.send(ClientCommand::Logout),
            KeyCode::Char('q') | KeyCode::Char('Q') => self.show_my_qr(),
            KeyCode::Char('s') | KeyCode::Char('S') => self.open_safety_number_screen(),
            KeyCode::Char('t') | KeyCode::Char('T') => self.cycle_theme(),
            _ => {}
        }
    }

    /// A fresh invite every time: its TTL is five minutes.
    fn show_my_qr(&mut self) {
        self.invite = None;
        self.client.send(ClientCommand::MintInvite);
        self.screen = Screen::IdentityQr;
    }

    /// The theme is a front-end preference, stored beside the client's config.
    fn cycle_theme(&mut self) {
        let next = self.theme.next();
        match crate::theme::save_theme(next) {
            Ok(()) => {
                self.theme = next;
                self.settings_screen.theme = next;
                self.status = format!("Theme: {}", next.label());
            }
            Err(e) => self.status = format!("Could not save theme: {e}"),
        }
    }

    fn open_safety_number_screen(&mut self) {
        let Some(contact) = self.chat_list.selected_contact() else {
            self.status = "Select a contact first".into();
            return;
        };
        self.client.send(ClientCommand::SafetyNumber {
            contact_id: contact.id.clone(),
        });
    }

    fn handle_contact_search(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.contact_search.reset();
                self.screen = Screen::Main;
            }
            KeyCode::Down => self.contact_search.next(),
            KeyCode::Up => self.contact_search.prev(),
            KeyCode::Enter => {
                if self.contact_search.selected().is_some() {
                    self.add_selected_search_result();
                } else {
                    self.client.send(ClientCommand::FindContact {
                        query: self.contact_search.query.clone(),
                    });
                }
            }
            KeyCode::Tab => self.contact_search.next(),
            KeyCode::BackTab => self.contact_search.prev(),
            KeyCode::Char('a') if key.modifiers == KeyModifiers::CONTROL => {
                self.add_selected_search_result();
            }
            KeyCode::Backspace => self.contact_search.pop_char(),
            KeyCode::Char(c) => self.contact_search.push_char(c),
            _ => {}
        }
    }

    fn add_selected_search_result(&mut self) {
        let Some(result) = self.contact_search.selected().cloned() else {
            return;
        };
        self.client.send(ClientCommand::AddContact {
            user_id: result.user_id,
            username: result.username,
        });
    }

    /// The client removed a person: drop them from the list and, if open, the chat view.
    fn remove_contact_from_view(&mut self, peer_id: &str) {
        if let Some(i) = self.chat_list.contacts.iter().position(|c| c.id == peer_id) {
            self.chat_list.remove_at(i);
        }
        if self.open_peer.as_deref() == Some(peer_id)
            || self.chat_list.contacts.iter().all(|c| c.id != peer_id)
        {
            self.chat_view.messages.clear();
            self.chat_view.contact_name = self
                .chat_list
                .selected_contact()
                .map(|c| c.display_name.clone())
                .unwrap_or_default();
            if self.open_peer.as_deref() == Some(peer_id) {
                self.open_peer = None;
            }
        }
        self.status = "Person removed.".into();
    }

    /// The client signed out: back to onboarding with nothing of the old account on screen.
    fn reset_after_logout(&mut self) {
        self.connection = ConnectionState::Disconnected;
        self.contact_search.reset();
        self.chat_list = ChatListPane::new();
        self.chat_view = ChatViewPane::new(String::new());
        self.open_peer = None;
        self.invite = None;
        self.settings_screen = fresh_settings_screen(&self.account);
        self.onboarding = OnboardingScreen::new();
        self.screen = Screen::Onboarding;
    }

    // ── Rendering ───────────────────────────────────────────────────────────────

    pub fn render(&mut self, frame: &mut Frame) {
        let area = frame.area();
        let palette = self.theme.palette();
        frame.render_widget(Block::default().style(palette.canvas()), area);

        self.onboarding.theme = self.theme;
        self.device_link.theme = self.theme;
        self.unlock_screen.theme = self.theme;
        self.registration.theme = self.theme;
        self.settings_screen.theme = self.theme;
        self.contact_search.theme = self.theme;
        if let Some(ref mut safety_number) = self.safety_number {
            safety_number.theme = self.theme;
        }

        if matches!(self.screen, Screen::Main) {
            self.render_main(frame);
            // Overlay delete confirmation dialog on top of the main view.
            if let Some(ref peer_id) = self.delete_confirm.clone() {
                self.render_delete_confirm(frame, peer_id);
            }
            return;
        }
        if matches!(self.screen, Screen::Settings) {
            return frame.render_widget(&mut self.settings_screen, area);
        }
        if matches!(self.screen, Screen::ContactSearch) {
            return frame.render_widget(&mut self.contact_search, area);
        }
        if matches!(self.screen, Screen::SafetyNumber) {
            if let Some(ref sn) = self.safety_number {
                return frame.render_widget(sn, area);
            }
            self.screen = Screen::Settings;
            return frame.render_widget(&mut self.settings_screen, area);
        }
        if matches!(self.screen, Screen::IdentityQr) {
            let invite = self.invite.clone();
            let user_id = self.account.user_id.clone();
            return self.render_identity_qr_fullscreen(frame, area, invite.as_ref(), &user_id);
        }
        if matches!(self.screen, Screen::DeviceLink) {
            return frame.render_widget(&self.device_link, area);
        }
        if matches!(self.screen, Screen::Registering) {
            return frame.render_widget(&self.registration, area);
        }
        if matches!(self.screen, Screen::Unlock | Screen::SetPassphrase) {
            return frame.render_widget(&self.unlock_screen, area);
        }
        if matches!(self.screen, Screen::Startup) {
            frame.render_widget(&self.onboarding, area);
            return self.render_spinner(frame, "Restoring session…");
        }
        if let Screen::Connecting(ref msg) = self.screen {
            let msg = msg.clone();
            frame.render_widget(&self.onboarding, area);
            return self.render_spinner(frame, &msg);
        }
        if let Screen::AuthError(ref msg) = self.screen {
            let msg = msg.clone();
            frame.render_widget(&self.onboarding, area);
            return self.render_error_overlay(frame, &msg);
        }
        // Screen::Onboarding (and any future unauthenticated screens)
        frame.render_widget(&self.onboarding, area);
    }

    fn render_identity_qr_fullscreen(
        &self,
        frame: &mut Frame,
        area: Rect,
        invite: Option<&Result<String, String>>,
        user_id: &str,
    ) {
        let palette = self.theme.palette();
        frame.render_widget(Clear, area);
        frame.render_widget(Block::default().style(palette.canvas()), area);

        let payload = match invite {
            Some(Ok(payload)) => payload.as_str(),
            Some(Err(e)) => {
                let msg = Paragraph::new(format!("No invite: {e}"))
                    .style(palette.muted())
                    .alignment(Alignment::Center);
                frame.render_widget(msg, area);
                return;
            }
            None => {
                let msg = Paragraph::new("Generating invite…")
                    .style(palette.muted())
                    .alignment(Alignment::Center);
                frame.render_widget(msg, area);
                return;
            }
        };

        // Hint at bottom
        let hint = Paragraph::new(Line::from(vec![
            Span::styled("  Scan with Konstruct iOS  (v5, 5 min)  ", palette.muted()),
            Span::styled(
                "[ any key to return ]",
                palette.muted().add_modifier(Modifier::DIM),
            ),
        ]))
        .alignment(Alignment::Center);

        let chunks = Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).split(area);
        frame.render_widget(hint, chunks[1]);

        // Centre the QR within the available area
        let qr_area = chunks[0];
        let Some((qr_w, qr_h)) = QrWidget::size_hint(payload) else {
            let msg = Paragraph::new("[ QR unavailable — payload too large ]")
                .style(palette.muted())
                .alignment(Alignment::Center);
            frame.render_widget(msg, qr_area);
            return;
        };

        let x = qr_area.x + qr_area.width.saturating_sub(qr_w) / 2;
        let y = qr_area.y + qr_area.height.saturating_sub(qr_h) / 2;
        let render_area = Rect {
            x,
            y,
            width: qr_w.min(qr_area.width),
            height: qr_h.min(qr_area.height),
        };

        let widget = QrWidget {
            theme: self.theme,
            data: payload,
            caption: Some(user_id),
            fg: Color::Black,
            bg: Color::White,
        };
        frame.render_widget(&widget, render_area);
    }

    fn render_spinner(&self, frame: &mut Frame, msg: &str) {
        let area = frame.area();
        let palette = self.theme.palette();
        let y = area.height.saturating_sub(2);
        let line = Line::from(vec![
            Span::styled("  ⠋ ", palette.emphasis()),
            Span::styled(msg, palette.text()),
        ]);
        frame.render_widget(
            Paragraph::new(line),
            ratatui::layout::Rect {
                x: 0,
                y,
                width: area.width,
                height: 1,
            },
        );
    }

    fn render_error_overlay(&self, frame: &mut Frame, msg: &str) {
        let area = frame.area();
        let palette = self.theme.palette();
        let y = area.height.saturating_sub(2);
        let display = format!("  ✗ {}  (any key to retry)", msg);
        let line = Line::from(Span::styled(display, palette.state(true)));
        frame.render_widget(
            Paragraph::new(line),
            ratatui::layout::Rect {
                x: 0,
                y,
                width: area.width,
                height: 1,
            },
        );
    }

    /// Render the delete confirmation over the active screen.
    fn render_delete_confirm(&self, frame: &mut Frame, peer_id: &str) {
        let area = frame.area();
        let palette = self.theme.palette();
        let name = self
            .chat_list
            .contacts
            .iter()
            .find(|c| c.id == peer_id)
            .map(|c| c.display_name.as_str())
            .unwrap_or(peer_id);
        let width = area.width.min(54);
        let height = area.height.min(5);
        let dialog = Rect::new(
            area.x + area.width.saturating_sub(width) / 2,
            area.y + area.height.saturating_sub(height) / 2,
            width,
            height,
        );
        frame.render_widget(Clear, dialog);
        let block = palette
            .panel(" Remove person ", false)
            .border_style(Style::default().fg(palette.warning).bg(palette.panel))
            .style(palette.surface());
        let inner = block.inner(dialog);
        frame.render_widget(block, dialog);
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(name),
                Line::from("Remove this person and all messages?"),
                Line::from(vec![
                    Span::styled("Y", Style::default().fg(palette.warning)),
                    Span::raw(" remove    Any other key cancel"),
                ]),
            ])
            .style(palette.surface()),
            inner,
        );
    }

    fn render_main(&mut self, frame: &mut Frame) {
        let area = frame.area();
        let palette = self.theme.palette();
        let root = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(area);

        let title = Paragraph::new(Line::from(vec![
            Span::styled(
                " KONSTRUCT ",
                palette.selected().add_modifier(Modifier::BOLD),
            ),
            Span::styled("  CHATS", Style::default().fg(palette.foreground)),
            Span::styled(
                format!("  ·  {}", self.theme.label()),
                Style::default().fg(palette.muted),
            ),
        ]))
        .style(Style::default().bg(palette.background));
        frame.render_widget(title, root[0]);

        self.chat_list.theme = self.theme;
        self.chat_view.theme = self.theme;
        if area.width >= 96 {
            let body = Layout::horizontal([Constraint::Percentage(34), Constraint::Percentage(66)])
                .split(root[1]);
            frame.render_widget(&mut self.chat_list, body[0]);
            frame.render_widget(&mut self.chat_view, body[1]);
        } else if self.focus == Focus::ContactList {
            frame.render_widget(&mut self.chat_list, root[1]);
        } else {
            frame.render_widget(&mut self.chat_view, root[1]);
        }

        let hints = match self.focus {
            Focus::ContactList => "↑↓ choose  Enter open  a add  x remove  s settings  q quit",
            Focus::ChatView => "Tab write  Esc chats  ↑↓ scroll  s settings",
            Focus::Compose => "Enter send  Esc back",
        };
        let footer_text = format!("{}  │  {}", self.status, hints);
        let status_bar = StatusBar {
            connection: &self.connection,
            status_text: &footer_text,
            unread_count: self.chat_list.contacts.iter().map(|c| c.unread).sum(),
            pq_active: self.account.pq_active,
            theme: self.theme,
        };
        frame.render_widget(status_bar, root[2]);
    }
}

fn fresh_settings_screen(account: &AccountInfo) -> SettingsScreen {
    SettingsScreen::new(
        &account.server_url,
        account.transport_label,
        "—",
        "—",
        account.pq_active,
    )
}

fn current_time_hhmm() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{:02}:{:02}", (secs % 86400) / 3600, (secs % 3600) / 60)
}

/// Ctrl+C, or `q` with nothing held.
fn is_quit(key: &KeyEvent) -> bool {
    matches!(
        (key.code, key.modifiers),
        (KeyCode::Char('c'), KeyModifiers::CONTROL) | (KeyCode::Char('q'), KeyModifiers::NONE)
    )
}

impl App {
    /// The name a contact shows under, or its id when it has none.
    fn contact_name(&self, id: &str) -> String {
        self.chat_list
            .contacts
            .iter()
            .find(|c| c.id == id)
            .map(|c| c.display_name.clone())
            .unwrap_or_else(|| id.to_string())
    }
}
