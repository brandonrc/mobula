//! Local-auth domain types (ADR-0011): users and opaque API tokens stored
//! by the control plane. Mobula stores credentials, never signs them.
//!
//! Hash discipline: `password_hash` / `token_hash` live ONLY on the stored
//! records (`LocalUserRecord`, `ApiTokenRecord`), which are deliberately
//! not `Serialize`. The wire-facing projections (`LocalUserView`,
//! `ApiTokenView`) carry no secret material at all, so a handler can never
//! accidentally serialize a hash.

/// A local user's role (ADR-0011: roles are a column on the user, resolved
/// per request — no claim staleness). Stored as TEXT in `local_users.role`;
/// the vocabulary mirrors `mobula_auth::Role` (kept as a separate enum so
/// core never depends on the auth crate).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, utoipa::ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum LocalRole {
    Viewer,
    Developer,
    Operator,
    Admin,
}

impl LocalRole {
    pub fn as_str(self) -> &'static str {
        match self {
            LocalRole::Viewer => "viewer",
            LocalRole::Developer => "developer",
            LocalRole::Operator => "operator",
            LocalRole::Admin => "admin",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "viewer" => Some(LocalRole::Viewer),
            "developer" => Some(LocalRole::Developer),
            "operator" => Some(LocalRole::Operator),
            "admin" => Some(LocalRole::Admin),
            _ => None,
        }
    }
}

/// A stored local user — the full row, INCLUDING the bcrypt password hash.
/// Never serialized; handlers project to [`LocalUserView`].
#[derive(Debug, Clone)]
pub struct LocalUserRecord {
    pub username: String,
    pub email: Option<String>,
    /// bcrypt hash of the password. Store-facing only.
    pub password_hash: String,
    pub role: LocalRole,
    pub disabled: bool,
    /// Unix seconds.
    pub created_at: u64,
    /// Consecutive failed logins since the last success (reset on lock).
    pub failed_logins: u32,
    /// Unix seconds until which logins are refused; `None` when not locked.
    pub locked_until: Option<u64>,
}

/// The public projection of a local user — everything EXCEPT the password
/// hash and the lockout internals that are nobody else's business.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct LocalUserView {
    pub username: String,
    pub email: Option<String>,
    pub role: LocalRole,
    pub disabled: bool,
    /// Unix seconds.
    pub created_at: u64,
}

impl LocalUserRecord {
    pub fn view(&self) -> LocalUserView {
        LocalUserView {
            username: self.username.clone(),
            email: self.email.clone(),
            role: self.role,
            disabled: self.disabled,
            created_at: self.created_at,
        }
    }
}

/// A stored opaque API token (ADR-0011) — the full row, INCLUDING the
/// bcrypt token hash. Never serialized; handlers project to
/// [`ApiTokenView`]. The plaintext token is shown exactly once at
/// issuance and never stored.
#[derive(Debug, Clone)]
pub struct ApiTokenRecord {
    /// First 8 url-safe characters of the token — the lookup key. Not
    /// secret on its own (the remaining 32 hex chars carry the entropy).
    pub prefix: String,
    /// bcrypt hash of the full token. Store-facing only.
    pub token_hash: String,
    pub username: String,
    pub label: String,
    /// Unix seconds.
    pub created_at: u64,
    /// Unix seconds after which the token no longer authenticates.
    pub expires_at: u64,
    pub revoked: bool,
    pub last_used_at: Option<u64>,
}

/// The public projection of an API token — no hash, no plaintext.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ApiTokenView {
    pub prefix: String,
    pub username: String,
    pub label: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub revoked: bool,
    pub last_used_at: Option<u64>,
}

impl ApiTokenRecord {
    pub fn view(&self) -> ApiTokenView {
        ApiTokenView {
            prefix: self.prefix.clone(),
            username: self.username.clone(),
            label: self.label.clone(),
            created_at: self.created_at,
            expires_at: self.expires_at,
            revoked: self.revoked,
            last_used_at: self.last_used_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_role_round_trips() {
        for r in [
            LocalRole::Viewer,
            LocalRole::Developer,
            LocalRole::Operator,
            LocalRole::Admin,
        ] {
            assert_eq!(LocalRole::parse(r.as_str()), Some(r));
        }
        assert_eq!(LocalRole::parse("bogus"), None);
    }

    #[test]
    fn views_carry_no_hashes() {
        let rec = LocalUserRecord {
            username: "alice".into(),
            email: None,
            password_hash: "$2b$12$secret".into(),
            role: LocalRole::Admin,
            disabled: false,
            created_at: 1,
            failed_logins: 0,
            locked_until: None,
        };
        let json = serde_json::to_string(&rec.view()).unwrap();
        assert!(!json.contains("secret") && !json.contains("hash"), "{json}");

        let tok = ApiTokenRecord {
            prefix: "abcd1234".into(),
            token_hash: "$2b$12$secret".into(),
            username: "alice".into(),
            label: "ci".into(),
            created_at: 1,
            expires_at: 2,
            revoked: false,
            last_used_at: None,
        };
        let json = serde_json::to_string(&tok.view()).unwrap();
        assert!(!json.contains("secret") && !json.contains("hash"), "{json}");
    }
}
