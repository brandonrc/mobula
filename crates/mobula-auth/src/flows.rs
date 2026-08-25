//! OAuth 2.0 token-acquisition flows (Phase 2, ADR-0003).
//!
//! Humans: Device Authorization Grant (RFC 8628) — `mobula login` prints
//! a code, the user approves in a browser, the CLI polls for the token.
//! Machines: Client Credentials Grant (RFC 6749 §4.4) — service accounts
//! exchange id/secret for a token; Mobula never mints tokens itself.
//! On-behalf-of: Token Exchange (RFC 8693) — a trusted service swaps its
//! own credentials plus a user's token for a short-lived token that carries
//! the USER as subject, so jobs submitted through the gateway attribute to
//! the human, not the service account (#102, checkmaite-frontend#25).

use serde::Deserialize;

use crate::AuthError;

#[derive(Clone, Deserialize)]
pub struct DeviceAuthorization {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    #[serde(default)]
    pub verification_uri_complete: Option<String>,
    /// Seconds until the codes expire.
    pub expires_in: u64,
    /// Suggested polling interval in seconds (default 5 per RFC 8628).
    #[serde(default = "default_interval")]
    pub interval: u64,
}

fn default_interval() -> u64 {
    5
}

// Redacting Debug: device_code is a bearer-equivalent secret while the
// grant is pending (#33).
impl std::fmt::Debug for DeviceAuthorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceAuthorization")
            .field("device_code", &"[REDACTED]")
            .field("user_code", &self.user_code)
            .field("verification_uri", &self.verification_uri)
            .field("expires_in", &self.expires_in)
            .field("interval", &self.interval)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub token_type: Option<String>,
}

// Redacting Debug: access_token and refresh_token are secrets (#33).
impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("expires_in", &self.expires_in)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("token_type", &self.token_type)
            .finish()
    }
}

#[derive(Debug, Deserialize)]
struct TokenError {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

/// Start a device authorization (RFC 8628 §3.1).
pub async fn device_authorize(
    client: &reqwest::Client,
    device_authorization_endpoint: &str,
    client_id: &str,
    scope: &str,
) -> Result<DeviceAuthorization, AuthError> {
    let res = client
        .post(device_authorization_endpoint)
        .form(&[("client_id", client_id), ("scope", scope)])
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| AuthError::Flow(e.without_url().to_string()))?;
    res.json()
        .await
        .map_err(|e| AuthError::Flow(e.without_url().to_string()))
}

/// One poll of the token endpoint for a pending device grant
/// (RFC 8628 §3.4/§3.5). The caller owns the sleep/deadline loop so this
/// stays testable and runtime-agnostic.
pub enum DevicePoll {
    /// Keep polling (authorization_pending / slow_down — on slow_down the
    /// caller must add 5s to its interval).
    Pending {
        slow_down: bool,
    },
    Ready(Box<TokenResponse>),
}

pub async fn poll_device_token(
    client: &reqwest::Client,
    token_endpoint: &str,
    client_id: &str,
    device_code: &str,
) -> Result<DevicePoll, AuthError> {
    // A transport hiccup (IdP/ingress blip, DNS, reset) is transient — keep
    // polling until the caller's deadline rather than aborting the whole
    // device flow (#22).
    let res = match client
        .post(token_endpoint)
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", device_code),
            ("client_id", client_id),
        ])
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return Ok(DevicePoll::Pending { slow_down: false }),
    };

    let status = res.status();
    if status.is_success() {
        let token = res
            .json::<TokenResponse>()
            .await
            .map_err(|e| AuthError::Flow(e.without_url().to_string()))?;
        return Ok(DevicePoll::Ready(Box::new(token)));
    }
    // Non-2xx: if the body is a well-formed RFC 8628 error, act on it;
    // otherwise (a 502 HTML page from an ingress, a truncated body) treat
    // it as transient and keep polling (#22).
    let err = match res.json::<TokenError>().await {
        Ok(e) => e,
        Err(_) => return Ok(DevicePoll::Pending { slow_down: false }),
    };
    match err.error.as_str() {
        "authorization_pending" => Ok(DevicePoll::Pending { slow_down: false }),
        "slow_down" => Ok(DevicePoll::Pending { slow_down: true }),
        // Terminal grant errors (access_denied, expired_token, ...).
        other => Err(AuthError::Flow(format!(
            "{other}: {}",
            err.error_description.unwrap_or_default()
        ))),
    }
}

/// Client-credentials grant for service accounts (RFC 6749 §4.4).
pub async fn client_credentials(
    client: &reqwest::Client,
    token_endpoint: &str,
    client_id: &str,
    client_secret: &str,
    scope: Option<&str>,
) -> Result<TokenResponse, AuthError> {
    let mut form = vec![
        ("grant_type", "client_credentials"),
        ("client_id", client_id),
        ("client_secret", client_secret),
    ];
    if let Some(s) = scope {
        form.push(("scope", s));
    }
    let res = client
        .post(token_endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|e| AuthError::Flow(e.without_url().to_string()))?;
    if !res.status().is_success() {
        let err = res
            .json::<TokenError>()
            .await
            .map_err(|e| AuthError::Flow(e.without_url().to_string()))?;
        return Err(AuthError::Flow(format!(
            "{}: {}",
            err.error,
            err.error_description.unwrap_or_default()
        )));
    }
    res.json()
        .await
        .map_err(|e| AuthError::Flow(e.without_url().to_string()))
}

/// RFC 8693 grant type for OAuth 2.0 Token Exchange.
pub const GRANT_TYPE_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
/// RFC 8693 token-type URN for an OAuth 2.0 access token.
pub const TOKEN_TYPE_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
/// RFC 8693 token-type URN for an OIDC ID token.
pub const TOKEN_TYPE_ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";

/// Parameters for an RFC 8693 token exchange (see [`exchange_token`]).
///
/// Construct with [`TokenExchange::new`] (defaults `subject_token_type` to an
/// access token) then set [`audience`](Self::audience)/[`scope`](Self::scope).
#[derive(Clone)]
pub struct TokenExchange<'a> {
    /// The requesting (trusted) service's confidential client id — the
    /// service that holds the user's gateway-verified token and is submitting
    /// on their behalf (e.g. `checkmaite-svc`).
    pub client_id: &'a str,
    /// The requesting service's client secret.
    pub client_secret: &'a str,
    /// The subject token to exchange: the user's gateway-verified access
    /// token (or id token), typically lifted from the gateway session
    /// cookie. The exchanged token inherits THIS token's identity — its
    /// `sub` becomes the exchanged token's subject, which is the whole point
    /// (#102): the resulting token is the user's, not the service's.
    pub subject_token: &'a str,
    /// RFC 8693 type URN of `subject_token`: [`TOKEN_TYPE_ACCESS_TOKEN`]
    /// (the [`TokenExchange::new`] default) or [`TOKEN_TYPE_ID_TOKEN`].
    pub subject_token_type: &'a str,
    /// Requested audience for the exchanged token (Keycloak's `audience`
    /// form field). Set this to Mobula's audience/client id so the result
    /// validates against the gateway with `aud=mobula`.
    pub audience: Option<&'a str>,
    /// Optional requested scope for the exchanged token.
    pub scope: Option<&'a str>,
}

impl<'a> TokenExchange<'a> {
    /// A token-exchange request for `subject_token` (typed as an access
    /// token), authenticated by the given confidential client. Set
    /// [`audience`](Self::audience) to the Mobula audience before exchanging.
    pub fn new(client_id: &'a str, client_secret: &'a str, subject_token: &'a str) -> Self {
        Self {
            client_id,
            client_secret,
            subject_token,
            subject_token_type: TOKEN_TYPE_ACCESS_TOKEN,
            audience: None,
            scope: None,
        }
    }
}

// Redacting Debug: client_secret and subject_token are bearer-equivalent
// secrets (#33) — the subject_token is the user's live credential.
impl std::fmt::Debug for TokenExchange<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenExchange")
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("subject_token", &"[REDACTED]")
            .field("subject_token_type", &self.subject_token_type)
            .field("audience", &self.audience)
            .field("scope", &self.scope)
            .finish()
    }
}

/// RFC 8693 OAuth 2.0 Token Exchange. A trusted service swaps its own client
/// credentials plus a user's `subject_token` for a NEW token whose subject is
/// the USER, scoped to the requested `audience`.
///
/// Mobula uses this so a service submitting jobs on a human's behalf (e.g.
/// checkmaite's api, #102 / checkmaite-frontend#25) obtains a short-lived,
/// mobula-audience token that carries the human as `sub`. The service then
/// submits that token through the gateway and Mobula attributes the job to
/// the real user rather than the shared service account — closing the
/// `created_by` spoof at its root. Mobula itself mints nothing: Keycloak
/// performs the exchange and Mobula validates the result like any other
/// bearer (aud/iss/exp + JWKS signature).
///
/// The `requested_token_type` is always an access token — that is what the
/// `ray job submit` bearer path and the gateway consume.
pub async fn exchange_token(
    client: &reqwest::Client,
    token_endpoint: &str,
    params: &TokenExchange<'_>,
) -> Result<TokenResponse, AuthError> {
    let mut form = vec![
        ("grant_type", GRANT_TYPE_TOKEN_EXCHANGE),
        ("client_id", params.client_id),
        ("client_secret", params.client_secret),
        ("subject_token", params.subject_token),
        ("subject_token_type", params.subject_token_type),
        ("requested_token_type", TOKEN_TYPE_ACCESS_TOKEN),
    ];
    if let Some(audience) = params.audience {
        form.push(("audience", audience));
    }
    if let Some(scope) = params.scope {
        form.push(("scope", scope));
    }
    let res = client
        .post(token_endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|e| AuthError::Flow(e.without_url().to_string()))?;
    if !res.status().is_success() {
        let err = res
            .json::<TokenError>()
            .await
            .map_err(|e| AuthError::Flow(e.without_url().to_string()))?;
        return Err(AuthError::Flow(format!(
            "{}: {}",
            err.error,
            err.error_description.unwrap_or_default()
        )));
    }
    res.json()
        .await
        .map_err(|e| AuthError::Flow(e.without_url().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_exchange_debug_redacts_secrets() {
        let mut x = TokenExchange::new("checkmaite-svc", "svc-secret", "user-subject-token");
        x.audience = Some("mobula");
        let s = format!("{x:?}");
        assert!(!s.contains("svc-secret"), "{s}");
        assert!(!s.contains("user-subject-token"), "{s}");
        assert!(s.contains("[REDACTED]"));
        // Non-secret fields stay visible for debugging.
        assert!(s.contains("checkmaite-svc"), "{s}");
        assert!(s.contains("mobula"), "{s}");
        // Sensible defaults from the constructor.
        assert_eq!(x.subject_token_type, TOKEN_TYPE_ACCESS_TOKEN);
    }

    #[test]
    fn debug_redacts_secrets() {
        let t = TokenResponse {
            access_token: "super-secret-token".into(),
            expires_in: Some(300),
            refresh_token: Some("refresh-secret".into()),
            token_type: Some("Bearer".into()),
        };
        let s = format!("{t:?}");
        assert!(!s.contains("super-secret-token"), "{s}");
        assert!(!s.contains("refresh-secret"), "{s}");
        assert!(s.contains("[REDACTED]"));

        let d = DeviceAuthorization {
            device_code: "device-secret".into(),
            user_code: "WDJB-MJHT".into(),
            verification_uri: "https://idp/device".into(),
            verification_uri_complete: None,
            expires_in: 600,
            interval: 5,
        };
        let s = format!("{d:?}");
        assert!(!s.contains("device-secret"), "{s}");
        assert!(s.contains("WDJB-MJHT"), "user_code is not secret");
    }
}
