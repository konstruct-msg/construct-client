//! Access tokens: scheduled and on-demand refresh, device re-authentication when the refresh
//! token is refused, and re-saving the session with the new tokens.

use super::{AuthMsg, Client, ClientEvent, Inbox, auth::AuthSuccess};
use crate::{
    bridge::TokenRefreshMsg,
    config::{self, Session},
};

impl Client {
    pub(super) fn refresh_token_now(&self) {
        let Some(session) = self.current_session.clone() else {
            return;
        };
        let inbox = self.inbox.clone();
        let mut rx = crate::bridge::spawn_token_refresh_now(
            self.grpc.clone(),
            session.device_id,
            session.refresh_token,
        );
        tokio::spawn(async move {
            if let Some(msg) = rx.recv().await {
                let _ = inbox.send(Inbox::TokenRefresh(msg));
            }
        });
    }

    pub(super) fn start_token_refresh(&self, session: &Session) {
        let inbox = self.inbox.clone();
        let mut rx = crate::bridge::spawn_token_refresh(
            self.grpc.clone(),
            session.device_id.clone(),
            session.refresh_token.clone(),
            session.expires_at,
        );
        tokio::spawn(async move {
            if let Some(msg) = rx.recv().await {
                let _ = inbox.send(Inbox::TokenRefresh(msg));
            }
        });
    }

    /// Take in a token-refresh result.
    pub(super) fn apply_token_refresh(&mut self, msg: TokenRefreshMsg) {
        match msg {
            TokenRefreshMsg::Refreshed {
                access_token,
                refresh_token,
                expires_at,
            } => {
                self.access_token = access_token.clone();
                self.grpc.set_token(Some(access_token.clone()));
                if let Some(mut session) = self.current_session.clone() {
                    session.access_token = access_token;
                    session.refresh_token = refresh_token;
                    session.expires_at = expires_at;
                    self.persist_session(session);
                }
            }
            TokenRefreshMsg::FailedTransport(e) => {
                tracing::warn!("Token refresh transport failure ({e}) — keeping tokens");
            }
            TokenRefreshMsg::FailedAuth(e) => {
                tracing::warn!("Token refresh rejected ({e}) — attempting device re-auth");
                self.start_device_reauth();
            }
        }
    }

    /// Fall back to device signing-key authentication when the refresh token is expired or
    /// rejected (e.g. key rotation on redeploy). Success arrives as a normal
    /// [`AuthMsg::Success`], which updates tokens and persists the session.
    fn start_device_reauth(&self) {
        let Some(session) = self.current_session.clone() else {
            return self.emit(ClientEvent::Notice(
                "Device re-auth failed: no session in memory".into(),
            ));
        };
        let inbox = self.inbox.clone();
        let grpc = self.grpc.clone();
        tokio::spawn(async move {
            let msg = match crate::auth::authenticate_saved_session(session, &grpc).await {
                Ok(result) => {
                    let full = result
                        .session
                        .clone()
                        .expect("authenticate_saved_session always returns session");
                    AuthMsg::Success(Box::new(AuthSuccess {
                        user_id: result.user_id,
                        device_id: result.device_id,
                        access_token: result.access_token,
                        full_session: full.clone(),
                        pending_save: Some(full),
                    }))
                }
                Err(e) => AuthMsg::Failure(format!("Device re-auth failed: {e}")),
            };
            let _ = inbox.send(Inbox::Auth(msg));
        });
    }

    fn persist_session(&mut self, session: Session) {
        // Keep the in-memory copy fresh so token refreshes need no disk read.
        self.current_session = Some(session.clone());
        self.start_token_refresh(&session);
        if let Some(ref sk) = self.session_key {
            let _ = config::save_session_encrypted(&session, sk);
        } else if self.no_encrypt {
            let _ = config::save_session(&session);
        }
    }
}
