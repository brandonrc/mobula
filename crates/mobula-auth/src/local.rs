//! Local (IdP-free) authentication (ADR-0011): username/password login and
//! personal access tokens backed by the Mobula store.
//!
//! **Opaque tokens only — no JWT minting.** Mobula stores credentials, it
//! never signs them. Tokens are `mob_<8-char prefix>_<32 hex>` random
//! strings, bcrypt-hashed at rest, looked up by prefix. Roles are a column
//! on the user row and resolved per request, so role changes apply live.
//!
//! Brute-force posture (mirroring artifact-keeper's local half):
//! - unknown usernames run a constant-time dummy bcrypt verify so login
//!   timing does not enumerate accounts;
//! - 5 consecutive failures lock the account for 5 minutes
//!   ([`mobula_controller::LOGIN_LOCKOUT_THRESHOLD`] /
//!   [`mobula_controller::LOCKOUT_SECS`]);
//! - every failure mode returns the same `invalid_credentials` error to the
//!   caller — lockout/disablement is visible only in the audit trail.
//!
//! This crate must stay free of Kubernetes/cloud deps (same rule as core).

use std::sync::Arc;

use mobula_controller::{now_unix, Store, StoreError};
use mobula_core::{ApiTokenRecord, LocalRole, LocalUserRecord};

use crate::{Identity, Role};

/// bcrypt work factor: the crate default (12).
const COST: u32 = bcrypt::DEFAULT_COST;

/// Pre-computed bcrypt hash of a dummy password. Unknown usernames verify
/// against this so a login attempt always costs one bcrypt — the
/// user-exists oracle via response timing stays closed.
const DUMMY_HASH: &str = "$2b$12$dcjUjjUwxXC4Z9wsZzBD3.8Ec1/3r8C.XkqTVfQsgyrNz9sJGUt.K";

/// Hash a password (bcrypt, default cost) off the async executor.
pub async fn hash_password(password: &str) -> Result<String, LocalAuthError> {
    let pwd = password.to_string();
    tokio::task::spawn_blocking(move || bcrypt::hash(pwd, COST))
        .await
        .map_err(|e| LocalAuthError::Backend(format!("hash task: {e}")))?
        .map_err(|e| LocalAuthError::Backend(format!("bcrypt: {e}")))
}

/// Verify a password against a bcrypt hash, off the async executor.
/// Malformed stored hashes return `Ok(false)`, not an error — a corrupt row
/// must fail closed, not 500.
pub async fn verify_password(password: &str, hash: &str) -> Result<bool, LocalAuthError> {
    let pwd = password.to_string();
    let h = hash.to_string();
    Ok(tokio::task::spawn_blocking(move || bcrypt::verify(pwd, &h))
        .await
        .map_err(|e| LocalAuthError::Backend(format!("verify task: {e}")))?
        .unwrap_or(false))
}

/// A freshly minted opaque token. `token` is the plaintext, shown to the
/// caller exactly once; only its bcrypt hash is ever stored.
#[derive(Debug, Clone)]
pub struct MintedToken {
    /// The 8-character lookup prefix (the `<prefix>` in `mob_<prefix>_…`).
    pub prefix: String,
    /// The full plaintext token.
    pub token: String,
    /// bcrypt hash of `token`, for `ApiTokenRecord::token_hash`.
    pub token_hash: String,
}

/// The token scheme: `mob_` + 8 url-safe chars + `_` + 32 hex chars
/// (16 random bytes). The prefix is the store lookup key — not secret; the
/// 128-bit suffix carries the entropy.
pub const TOKEN_PREFIX_LEN: usize = 8;

/// Mint the random parts of a token (no hashing — see [`hash_token`]).
/// Split so tests can exercise the format without paying a bcrypt.
pub fn mint_token_parts() -> (String, String) {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let prefix: String = (0..TOKEN_PREFIX_LEN)
        .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
        .collect();
    let bytes: [u8; 16] = rng.r#gen();
    let mut hex = String::with_capacity(32);
    for b in bytes {
        hex.push_str(&format!("{b:02x}"));
    }
    let token = format!("mob_{prefix}_{hex}");
    (prefix, token)
}

/// A random url-safe password of `len` alphanumeric characters — used by
/// the CLI to bootstrap the first local admin (ADR-0011).
pub fn random_password(len: usize) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
        .collect()
}

/// Extract the lookup prefix from a presented token, checking the scheme.
/// `None` for anything not shaped like a Mobula token.
pub fn token_prefix(presented: &str) -> Option<&str> {
    let rest = presented.strip_prefix("mob_")?;
    if rest.len() != TOKEN_PREFIX_LEN + 1 + 32 {
        return None;
    }
    let (prefix, suffix) = rest.split_at(TOKEN_PREFIX_LEN);
    if !prefix.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    let hex = suffix.strip_prefix('_')?;
    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(prefix)
}

/// Hash a token for storage (same bcrypt posture as passwords).
pub async fn hash_token(token: &str) -> Result<String, LocalAuthError> {
    hash_password(token).await
}

/// Verify a presented token against its stored bcrypt hash.
pub async fn verify_token(stored_hash: &str, presented: &str) -> Result<bool, LocalAuthError> {
    verify_password(presented, stored_hash).await
}

/// What a successful login returns.
#[derive(Debug, Clone)]
pub struct LoginOutcome {
    /// The plaintext token (shown once).
    pub token: MintedToken,
    /// Unix seconds after which the token no longer authenticates.
    pub expires_at: u64,
    pub identity: Identity,
}

/// Every login failure is the SAME 401 on the wire (`invalid_credentials`)
/// — the distinct variants exist only so the audit trail can tell them
/// apart (ADR-0011: no user enumeration, lockout visible only in audit).
#[derive(Debug, thiserror::Error)]
pub enum LocalAuthError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("account is locked")]
    Locked,
    #[error("account is disabled")]
    Disabled,
    #[error("no such user")]
    UnknownUser,
    #[error("token ttl exceeds the configured maximum")]
    TtlTooLong,
    #[error("backend error: {0}")]
    Backend(String),
}

impl From<StoreError> for LocalAuthError {
    fn from(e: StoreError) -> Self {
        LocalAuthError::Backend(e.to_string())
    }
}

fn to_role(role: LocalRole) -> Role {
    match role {
        LocalRole::Viewer => Role::Viewer,
        LocalRole::Developer => Role::Developer,
        LocalRole::Operator => Role::Operator,
        LocalRole::Admin => Role::Admin,
    }
}

fn identity_of(user: &LocalUserRecord) -> Identity {
    Identity {
        subject: user.username.clone(),
        email: user.email.clone(),
        groups: vec![],
        roles: vec![to_role(user.role)],
    }
}

/// Local username/password + PAT authentication against the store
/// (ADR-0011).
pub struct LocalAuthenticator {
    store: Arc<dyn Store>,
    /// Lifetime of a token issued by `login`.
    login_ttl_secs: u64,
    /// Maximum lifetime of a user-minted PAT, in days.
    token_max_days: u64,
}

impl LocalAuthenticator {
    pub fn new(store: Arc<dyn Store>, login_ttl_secs: u64, token_max_days: u64) -> Self {
        Self {
            store,
            login_ttl_secs,
            token_max_days,
        }
    }

    pub fn store(&self) -> &Arc<dyn Store> {
        &self.store
    }

    /// Username/password login. Enforces disabled → locked → password, in
    /// that order; unknown users run the dummy-hash verify so every failure
    /// path costs one bcrypt. On success the lockout counters clear and a
    /// login token (TTL `login_ttl_secs`) is stored.
    pub async fn login(
        &self,
        username: &str,
        password: &str,
    ) -> Result<LoginOutcome, LocalAuthError> {
        let user = self.store.get_local_user(username).await?;
        let Some(user) = user else {
            // Constant-time dummy verify: unknown users cost the same
            // bcrypt as known ones (no user-exists timing oracle).
            let _ = verify_password(password, DUMMY_HASH).await?;
            return Err(LocalAuthError::InvalidCredentials);
        };
        if user.disabled {
            // Still pay the bcrypt — disabled users are indistinguishable
            // from wrong passwords on the wire and in timing.
            let _ = verify_password(password, &user.password_hash).await?;
            return Err(LocalAuthError::Disabled);
        }
        let now = now_unix();
        if user.locked_until.is_some_and(|until| until > now) {
            // Refuse without verifying: the lock short-circuits, and no
            // failure is recorded while locked (the store's counter reset
            // when the lock tripped).
            return Err(LocalAuthError::Locked);
        }
        if !verify_password(password, &user.password_hash).await? {
            self.store.record_login_failure(username).await?;
            return Err(LocalAuthError::InvalidCredentials);
        }
        self.store.record_login_success(username).await?;

        let expires_at = now + self.login_ttl_secs;
        let token = self.store_token(username, "login", expires_at).await?;
        Ok(LoginOutcome {
            token,
            expires_at,
            identity: identity_of(&user),
        })
    }

    /// Authenticate a presented bearer as an opaque token. `None` for
    /// anything that doesn't fully check out (bad scheme, unknown prefix,
    /// hash mismatch, revoked, expired, disabled/deleted user). Role is
    /// read from the user row per request — role changes apply live.
    pub async fn authenticate_token(&self, presented: &str) -> Option<Identity> {
        let prefix = token_prefix(presented)?;
        let record = self.store.get_api_token_by_prefix(prefix).await.ok()??;
        let now = now_unix();
        if record.revoked || record.expires_at <= now {
            return None;
        }
        if !verify_token(&record.token_hash, presented).await.ok()? {
            return None;
        }
        let user = self.store.get_local_user(&record.username).await.ok()??;
        if user.disabled {
            return None;
        }
        // Best-effort last-used stamp; never fails the authentication.
        let _ = self.store.touch_api_token(prefix, now).await;
        Some(identity_of(&user))
    }

    /// Issue a personal access token for `username`, capped at
    /// `token_max_days`. Returns the minted token (plaintext shown once).
    pub async fn issue_token(
        &self,
        username: &str,
        label: &str,
        ttl_days: u64,
    ) -> Result<(MintedToken, ApiTokenRecord), LocalAuthError> {
        if ttl_days == 0 || ttl_days > self.token_max_days {
            return Err(LocalAuthError::TtlTooLong);
        }
        // Issuing a token for a nonexistent or disabled user is a store-level
        // error, not a credential failure — the caller is already authed.
        let user = self
            .store
            .get_local_user(username)
            .await?
            .ok_or(LocalAuthError::UnknownUser)?;
        if user.disabled {
            return Err(LocalAuthError::Disabled);
        }
        let expires_at = now_unix() + ttl_days * 86_400;
        let minted = self.store_token(username, label, expires_at).await?;
        let record = self
            .store
            .get_api_token_by_prefix(&minted.prefix)
            .await?
            .ok_or_else(|| LocalAuthError::Backend("token vanished after create".into()))?;
        Ok((minted, record))
    }

    async fn store_token(
        &self,
        username: &str,
        label: &str,
        expires_at: u64,
    ) -> Result<MintedToken, LocalAuthError> {
        let (prefix, plaintext) = mint_token_parts();
        let token_hash = hash_token(&plaintext).await?;
        let record = ApiTokenRecord {
            prefix: prefix.clone(),
            token_hash: token_hash.clone(),
            username: username.to_string(),
            label: label.to_string(),
            created_at: now_unix(),
            expires_at,
            revoked: false,
            last_used_at: None,
        };
        self.store.create_api_token(record).await?;
        Ok(MintedToken {
            prefix,
            token: plaintext,
            token_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mobula_controller::{InMemoryStore, LOGIN_LOCKOUT_THRESHOLD};

    fn authenticator(store: Arc<dyn Store>) -> LocalAuthenticator {
        LocalAuthenticator::new(store, 3600, 90)
    }

    async fn store_with_user(username: &str, password: &str, role: LocalRole) -> Arc<dyn Store> {
        let store = Arc::new(InMemoryStore::new());
        let hash = hash_password(password).await.unwrap();
        store
            .create_local_user(username, None, &hash, role)
            .await
            .unwrap();
        store
    }

    #[tokio::test]
    async fn password_hash_round_trip_and_malformed_hash_fails_closed() {
        let hash = hash_password("correct horse").await.unwrap();
        assert!(hash.starts_with("$2"));
        assert!(verify_password("correct horse", &hash).await.unwrap());
        assert!(!verify_password("wrong", &hash).await.unwrap());
        // A corrupt stored hash verifies false rather than erroring.
        assert!(!verify_password("correct horse", "not-a-hash")
            .await
            .unwrap());
    }

    #[test]
    fn minted_token_format_and_prefix_parsing() {
        let (prefix, token) = mint_token_parts();
        assert_eq!(prefix.len(), 8);
        assert!(prefix.chars().all(|c| c.is_ascii_alphanumeric()));
        // mob_<8>_<32 hex>
        assert!(token.starts_with(&format!("mob_{prefix}_")));
        assert_eq!(token.len(), 4 + 8 + 1 + 32);
        assert_eq!(token_prefix(&token), Some(prefix.as_str()));

        // Rejects non-scheme shapes.
        assert_eq!(token_prefix("mob_short_hex"), None);
        assert_eq!(
            token_prefix("nope_abcd1234_0123456789abcdef0123456789abcdef"),
            None
        );
        assert_eq!(
            token_prefix("mob_abcd1234_0123456789abcdef0123456789abcdeg"),
            None,
            "non-hex suffix rejected"
        );
        assert_eq!(
            token_prefix("mob_abcd!234_0123456789abcdef0123456789abcdef"),
            None
        );
        // Two random mints never collide.
        let (_, other) = mint_token_parts();
        assert_ne!(token, other);
    }

    #[tokio::test]
    async fn unknown_user_takes_the_verify_path() {
        let store = store_with_user("alice", "pw", LocalRole::Admin).await;
        let auth = authenticator(store);
        // Not a timing test: the contract is that unknown users get the
        // same error (and the same bcrypt cost, via the dummy hash) as a
        // wrong password on a real account.
        let unknown = auth.login("ghost", "pw").await.unwrap_err();
        assert!(matches!(unknown, LocalAuthError::InvalidCredentials));
        let wrong_pw = auth.login("alice", "nope").await.unwrap_err();
        assert!(matches!(wrong_pw, LocalAuthError::InvalidCredentials));
        assert_eq!(unknown.to_string(), wrong_pw.to_string());
    }

    #[tokio::test]
    async fn lockout_state_machine() {
        let store = store_with_user("alice", "pw", LocalRole::Admin).await;
        let auth = authenticator(store.clone());
        for _ in 0..LOGIN_LOCKOUT_THRESHOLD {
            let e = auth.login("alice", "wrong").await.unwrap_err();
            assert!(matches!(e, LocalAuthError::InvalidCredentials));
        }
        // The 6th attempt is refused as locked — even with the CORRECT
        // password — and no failure is recorded while locked.
        let e = auth.login("alice", "pw").await.unwrap_err();
        assert!(matches!(e, LocalAuthError::Locked));
        let user = store.get_local_user("alice").await.unwrap().unwrap();
        assert!(user.locked_until.unwrap() > now_unix());
        assert_eq!(user.failed_logins, 0, "counter reset when the lock tripped");

        // Clearing the counters (admin unlock) restores access.
        store.record_login_success("alice").await.unwrap();
        assert!(auth.login("alice", "pw").await.is_ok());
    }

    #[tokio::test]
    async fn successful_login_clears_failures_and_issues_a_working_token() {
        let store = store_with_user("alice", "pw", LocalRole::Operator).await;
        let auth = authenticator(store.clone());
        auth.login("alice", "wrong").await.unwrap_err();
        let outcome = auth.login("alice", "pw").await.unwrap();
        assert_eq!(
            store
                .get_local_user("alice")
                .await
                .unwrap()
                .unwrap()
                .failed_logins,
            0
        );
        assert_eq!(outcome.identity.subject, "alice");
        assert_eq!(outcome.identity.roles, vec![Role::Operator]);
        // The issued token authenticates.
        let id = auth.authenticate_token(&outcome.token.token).await.unwrap();
        assert_eq!(id.subject, "alice");
        // Garbage and truncated tokens do not.
        assert!(auth.authenticate_token("mob_garbage").await.is_none());
        assert!(auth
            .authenticate_token(&outcome.token.token[..20])
            .await
            .is_none());
    }

    #[tokio::test]
    async fn disabled_user_cannot_login_and_existing_tokens_die() {
        let store = store_with_user("alice", "pw", LocalRole::Viewer).await;
        let auth = authenticator(store.clone());
        let outcome = auth.login("alice", "pw").await.unwrap();
        store.set_local_user_disabled("alice", true).await.unwrap();
        let e = auth.login("alice", "pw").await.unwrap_err();
        assert!(matches!(e, LocalAuthError::Disabled));
        assert!(auth
            .authenticate_token(&outcome.token.token)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn issue_token_caps_ttl_and_requires_a_live_user() {
        let store = store_with_user("alice", "pw", LocalRole::Viewer).await;
        let auth = authenticator(store);
        assert!(matches!(
            auth.issue_token("alice", "ci", 91).await.unwrap_err(),
            LocalAuthError::TtlTooLong
        ));
        assert!(matches!(
            auth.issue_token("alice", "ci", 0).await.unwrap_err(),
            LocalAuthError::TtlTooLong
        ));
        assert!(matches!(
            auth.issue_token("ghost", "ci", 30).await.unwrap_err(),
            LocalAuthError::UnknownUser
        ));
        let (minted, record) = auth.issue_token("alice", "ci", 30).await.unwrap();
        assert_eq!(minted.prefix, record.prefix);
        assert!(record.expires_at > now_unix() + 29 * 86_400);
        assert!(auth.authenticate_token(&minted.token).await.is_some());
    }

    #[tokio::test]
    async fn expired_and_revoked_tokens_are_rejected() {
        let store = store_with_user("alice", "pw", LocalRole::Viewer).await;
        let auth = authenticator(store.clone());

        // Expired: insert a record whose expiry is in the past.
        let (prefix, plaintext) = mint_token_parts();
        let hash = hash_token(&plaintext).await.unwrap();
        store
            .create_api_token(ApiTokenRecord {
                prefix,
                token_hash: hash,
                username: "alice".into(),
                label: "old".into(),
                created_at: 1,
                expires_at: 2, // long past
                revoked: false,
                last_used_at: None,
            })
            .await
            .unwrap();
        assert!(auth.authenticate_token(&plaintext).await.is_none());

        // Revoked.
        let (minted, _) = auth.issue_token("alice", "ci", 30).await.unwrap();
        store
            .revoke_api_token(&minted.prefix, "alice")
            .await
            .unwrap();
        assert!(auth.authenticate_token(&minted.token).await.is_none());
    }

    #[tokio::test]
    async fn role_changes_apply_live() {
        // ADR-0011: roles are a column, resolved per request — a token
        // minted as viewer picks up an admin promotion without re-login.
        let store = store_with_user("alice", "pw", LocalRole::Viewer).await;
        let auth = authenticator(store.clone());
        let outcome = auth.login("alice", "pw").await.unwrap();
        let id = auth.authenticate_token(&outcome.token.token).await.unwrap();
        assert_eq!(id.roles, vec![Role::Viewer]);
        store
            .set_local_user_role("alice", LocalRole::Admin)
            .await
            .unwrap();
        let id = auth.authenticate_token(&outcome.token.token).await.unwrap();
        assert_eq!(id.roles, vec![Role::Admin]);
    }
}
