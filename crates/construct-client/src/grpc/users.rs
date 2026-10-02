//! UserService unary RPCs.

use prost::Message;

use crate::proto::services::v1::{FindUserRequest, FindUserResponse};

use super::client::GrpcClient;
use super::error::GrpcError;
use super::paths;

/// Same rules as identity-service `FindUser` and iOS `findUser`:
/// trim, strip a leading `@`, lowercase. Invalid charset is NOT_FOUND on the
/// server (`@alice` never matches).
pub fn normalize_username(raw: &str) -> String {
    raw.trim()
        .trim_start_matches('@')
        .trim()
        .to_ascii_lowercase()
}

pub fn username_is_searchable(normalized: &str) -> bool {
    (3..=30).contains(&normalized.len())
        && normalized
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
}

pub async fn find_user(client: &GrpcClient, username: &str) -> Result<Option<String>, GrpcError> {
    let username = normalize_username(username);
    if !username_is_searchable(&username) {
        tracing::info!(username = %username, "FindUser skipped: invalid username");
        return Ok(None);
    }
    let req = FindUserRequest {
        username: username.clone(),
    };
    tracing::info!(username = %username, "FindUser");
    match client.unary(paths::USER_FIND, &req.encode_to_vec()).await {
        Ok(bytes) => {
            let resp = FindUserResponse::decode(bytes.as_slice())
                .map_err(|e| GrpcError::transport(format!("FindUser decode: {e}")))?;
            if resp.user_id.is_empty() {
                tracing::info!(username = %username, "FindUser empty user_id");
                Ok(None)
            } else {
                tracing::info!(username = %username, user_id = %resp.user_id, "FindUser hit");
                Ok(Some(resp.user_id))
            }
        }
        Err(GrpcError::Status { code: 5, .. }) => {
            tracing::info!(username = %username, "FindUser NOT_FOUND");
            Ok(None)
        }
        Err(e) => {
            tracing::warn!(username = %username, error = %e, "FindUser failed");
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_at_and_lowercases() {
        assert_eq!(normalize_username(" @Alice "), "alice");
        assert_eq!(normalize_username("bob_1"), "bob_1");
        assert!(username_is_searchable("alice"));
        assert!(!username_is_searchable("@alice"));
        assert!(!username_is_searchable("ab"));
    }
}
