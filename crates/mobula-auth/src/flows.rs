//! OAuth 2.0 token-acquisition flows (Phase 2, ADR-0003).
//!
//! Humans: Device Authorization Grant (RFC 8628) — `mobula login` prints
//! a code, the user approves in a browser, the CLI polls for the token.
//! Machines: Client Credentials Grant (RFC 6749 §4.4) — service accounts
//! exchange id/secret for a token; Mobula never mints tokens itself.

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

#[cfg(test)]
mod tests {
    use super::*;

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
