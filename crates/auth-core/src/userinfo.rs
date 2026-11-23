use serde::Deserialize;

use crate::{http, AuthError, ClientConfig, HttpClient, HttpMethod, HttpRequest, SignInResult};

/// Fresh, scope-filtered data. Never persisted in the session journal or ID token.
#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct UserInfo {
    #[serde(rename = "sub")]
    pub subject: String,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
    pub picture: Option<String>,
    pub phone_number: Option<String>,
    pub phone_number_verified: Option<bool>,
}

impl std::fmt::Debug for UserInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UserInfo(redacted)")
    }
}

pub(crate) async fn fetch(
    config: &ClientConfig,
    transport: &dyn HttpClient,
    session: &SignInResult,
) -> Result<UserInfo, AuthError> {
    // This fixed Link API route stays on the configured regional ingress.
    // No discovery round trip and no caller-supplied destination for the bearer.
    let endpoint = format!(
        "{}/oauth/v1/userinfo",
        config.api_base_url.as_str().trim_end_matches('/')
    );
    let mut request = HttpRequest::new(HttpMethod::Get, endpoint, vec![]);
    request.headers.push((
        "Authorization".into(),
        format!("Bearer {}", session.access_token.expose_secret()),
    ));
    request
        .headers
        .push(("Cache-Control".into(), "no-store".into()));
    let mut info: UserInfo = http::json(transport, request).await?;
    if info.subject != session.user.subject {
        return Err(AuthError::InvalidResponse);
    }
    if !session.user.granted_scopes.iter().any(|s| s == "profile") {
        info.name = None;
        info.preferred_username = None;
        info.picture = None;
    }
    if !session.user.granted_scopes.iter().any(|s| s == "phone") {
        info.phone_number = None;
        info.phone_number_verified = None;
    }
    if let Some(phone) = &info.phone_number {
        if !(8..=16).contains(&phone.len())
            || !phone.starts_with('+')
            || !phone[1..].bytes().all(|c| c.is_ascii_digit())
        {
            return Err(AuthError::InvalidResponse);
        }
    } else {
        info.phone_number_verified = None;
    }
    Ok(info)
}
