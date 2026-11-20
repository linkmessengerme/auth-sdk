use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use url::Url;

use crate::{
    config::RESPONSE_PARAMETERS, http, token, AuthError, ClientConfig, HttpClient, HttpMethod,
    HttpRequest, OAuthError, SecretString, SignInResult,
};

const LOGIN_TTL_SECONDS: u64 = 600;

/// Backend challenges must contain at least 192 random bits encoded as base64url.
pub(crate) fn validate_nonce(nonce: &str) -> Result<(), AuthError> {
    if !(32..=256).contains(&nonce.len())
        || !nonce
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return Err(AuthError::InvalidNonce);
    }
    Ok(())
}

pub trait Clock: Send + Sync {
    fn unix_time_seconds(&self) -> Result<u64, AuthError>;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn unix_time_seconds(&self) -> Result<u64, AuthError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|time| time.as_secs())
            .map_err(|_| AuthError::InvalidClock)
    }
}

pub struct AuthorizationRequest {
    pub transaction_id: String,
    /// Open this URL using the platform's verified app-link mechanism.
    pub authorization_url: String,
    pub expires_at: u64,
}

impl fmt::Debug for AuthorizationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizationRequest")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// One instance owns at most one sign-in. No Tokio runtime, HTTP stack, UI or
/// persistent token store is embedded. This first slice returns a verified result;
/// it does not yet implement durable sessions, refresh, or process-death recovery.
pub struct AuthClient {
    config: ClientConfig,
    transport: Arc<dyn HttpClient>,
    clock: Arc<dyn Clock>,
    state: Arc<Mutex<State>>,
}

enum State {
    Idle,
    Loading(String),
    Pending(Box<Pending>),
    Exchanging(String),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Pending {
    id: String,
    #[serde(with = "crate::secret::serialized")]
    state: SecretString,
    #[serde(with = "crate::secret::serialized")]
    nonce: SecretString,
    #[serde(with = "crate::secret::serialized")]
    verifier: SecretString,
    scopes: Vec<String>,
    discovery: Discovery,
    pub(crate) expires_at: u64,
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    pub(crate) token_endpoint: String,
    pub(crate) jwks_uri: String,
    #[serde(default)]
    pub(crate) revocation_endpoint: Option<String>,
    response_types_supported: Vec<String>,
    grant_types_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
    code_challenge_methods_supported: Vec<String>,
    scopes_supported: Vec<String>,
    authorization_response_iss_parameter_supported: bool,
}

impl AuthClient {
    pub(crate) fn export_pending(&self) -> Result<Pending, AuthError> {
        let state = self.state.lock().map_err(|_| AuthError::Internal)?;
        let State::Pending(pending) = &*state else {
            return Err(AuthError::NoPendingLogin);
        };
        Ok(Pending {
            id: pending.id.clone(),
            state: pending.state.duplicate(),
            nonce: pending.nonce.duplicate(),
            verifier: pending.verifier.duplicate(),
            scopes: pending.scopes.clone(),
            discovery: pending.discovery.clone(),
            expires_at: pending.expires_at,
        })
    }

    pub(crate) fn import_pending(&self, pending: Pending) -> Result<(), AuthError> {
        let now = self.clock.unix_time_seconds()?;
        if pending.expires_at <= now {
            return Err(AuthError::Expired);
        }
        if pending.expires_at > now.saturating_add(LOGIN_TTL_SECONDS)
            || [
                &pending.id,
                pending.state.expose_secret(),
                pending.verifier.expose_secret(),
            ]
            .iter()
            .any(|s| {
                s.len() != 43
                    || !s
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
            })
        {
            return Err(AuthError::InvalidStoredState);
        }
        validate_nonce(pending.nonce.expose_secret()).map_err(|_| AuthError::InvalidStoredState)?;
        self.config.requested_scopes(pending.scopes.clone())?;
        pending.discovery.validate(&self.config, &pending.scopes)?;
        *self.state.lock().map_err(|_| AuthError::Internal)? = State::Pending(Box::new(pending));
        Ok(())
    }

    pub(crate) fn check_callback(&self, callback: &str) -> Result<(), AuthError> {
        let state = self.state.lock().map_err(|_| AuthError::Internal)?;
        let State::Pending(pending) = &*state else {
            return Err(AuthError::NoPendingLogin);
        };
        validate_callback(&self.config, pending, callback).map(|_| ())
    }

    pub fn new(config: ClientConfig, transport: Arc<dyn HttpClient>) -> Self {
        Self::with_clock(config, transport, Arc::new(SystemClock))
    }

    /// Alternate clocks are intended for deterministic integration tests.
    pub fn with_clock(
        config: ClientConfig,
        transport: Arc<dyn HttpClient>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            config,
            transport,
            clock,
            state: Arc::new(Mutex::new(State::Idle)),
        }
    }

    pub async fn begin_sign_in(
        &self,
        scopes: Vec<String>,
    ) -> Result<AuthorizationRequest, AuthError> {
        self.begin_sign_in_inner(scopes, None).await
    }

    /// Use the one-use nonce issued and saved by your backend before login.
    /// State and PKCE are still generated independently by this SDK.
    pub async fn begin_sign_in_with_nonce(
        &self,
        scopes: Vec<String>,
        nonce: String,
    ) -> Result<AuthorizationRequest, AuthError> {
        validate_nonce(&nonce)?;
        self.begin_sign_in_inner(scopes, Some(nonce)).await
    }

    async fn begin_sign_in_inner(
        &self,
        scopes: Vec<String>,
        nonce: Option<String>,
    ) -> Result<AuthorizationRequest, AuthError> {
        let scopes = self.config.requested_scopes(scopes)?;
        let id = random_secret()?.expose_secret().to_owned();
        let state = random_secret()?;
        let nonce = match nonce {
            Some(value) => SecretString::new(value),
            None => random_secret()?,
        };
        let verifier = random_secret()?;
        let now = self.clock.unix_time_seconds()?;
        let expires_at = now
            .checked_add(LOGIN_TTL_SECONDS)
            .ok_or(AuthError::InvalidClock)?;
        {
            let mut current = self.state.lock().map_err(|_| AuthError::Internal)?;
            if matches!(&*current, State::Pending(p) if now >= p.expires_at) {
                *current = State::Idle;
            }
            if !matches!(*current, State::Idle) {
                return Err(AuthError::AlreadyInProgress);
            }
            *current = State::Loading(id.clone());
        }
        let guard = OperationGuard::new(self.state.clone(), id.clone());
        let discovery = http::json::<Discovery>(
            self.transport.as_ref(),
            HttpRequest::new(HttpMethod::Get, self.config.discovery_url(), vec![]),
            false,
        )
        .await;
        guard.check()?;
        let discovery = discovery?;
        discovery.validate(&self.config, &scopes)?;
        if self.clock.unix_time_seconds()? >= expires_at {
            return Err(AuthError::Expired);
        }
        let mut authorize = self
            .config
            .authorization_endpoint(&discovery.authorization_endpoint)?;
        authorize
            .query_pairs_mut()
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", &self.config.redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", &scopes.join(" "))
            .append_pair("state", state.expose_secret())
            .append_pair("nonce", nonce.expose_secret())
            .append_pair("code_challenge", &pkce_challenge(verifier.expose_secret()))
            .append_pair("code_challenge_method", "S256");
        let result = AuthorizationRequest {
            transaction_id: id.clone(),
            authorization_url: authorize.into(),
            expires_at,
        };
        {
            let mut current = self.state.lock().map_err(|_| AuthError::Internal)?;
            if !matches!(&*current, State::Loading(active) if *active == id) {
                return Err(AuthError::Cancelled);
            }
            *current = State::Pending(Box::new(Pending {
                id,
                state,
                nonce,
                verifier,
                scopes,
                discovery,
                expires_at,
            }));
        }
        Ok(result)
    }

    /// Consume a valid callback once. Invalid/mismatched callbacks leave the
    /// legitimate pending attempt intact. Network failures after consumption
    /// require a new login; this method never retries an authorization code.
    pub async fn complete_sign_in(&self, callback_url: &str) -> Result<SignInResult, AuthError> {
        let (pending, code) = {
            let mut current = self.state.lock().map_err(|_| AuthError::Internal)?;
            let pending = match &*current {
                State::Pending(pending) => pending,
                State::Exchanging(_) | State::Loading(_) => {
                    return Err(AuthError::AlreadyInProgress)
                }
                State::Idle => return Err(AuthError::NoPendingLogin),
            };
            if self.clock.unix_time_seconds()? >= pending.expires_at {
                *current = State::Idle;
                return Err(AuthError::Expired);
            }
            let callback = validate_callback(&self.config, pending, callback_url)?;
            if let Callback::Error(error) = callback {
                *current = State::Idle;
                return Err(error);
            }
            let Callback::Code(code) = callback else {
                return Err(AuthError::Internal);
            };
            let active_id = pending.id.clone();
            let State::Pending(pending) =
                std::mem::replace(&mut *current, State::Exchanging(active_id))
            else {
                return Err(AuthError::Internal);
            };
            (pending, code)
        };
        let guard = OperationGuard::new(self.state.clone(), pending.id.clone());
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", &self.config.redirect_uri)
            .append_pair("code", code.expose_secret())
            .append_pair("code_verifier", pending.verifier.expose_secret())
            .finish()
            .into_bytes();
        let tokens = http::json::<token::TokenResponse>(
            self.transport.as_ref(),
            HttpRequest::new(
                HttpMethod::Post,
                pending.discovery.token_endpoint.clone(),
                body,
            ),
            true,
        )
        .await;
        guard.check()?;
        let tokens = tokens?;
        tokens.validate(&self.config, &pending.scopes)?;
        let jwks = http::json::<serde_json::Value>(
            self.transport.as_ref(),
            HttpRequest::new(HttpMethod::Get, pending.discovery.jwks_uri.clone(), vec![]),
            false,
        )
        .await;
        guard.check()?;
        let now = self.clock.unix_time_seconds()?;
        if now >= pending.expires_at {
            return Err(AuthError::Expired);
        }
        let result = token::verify(
            tokens,
            jwks?,
            &self.config,
            pending.nonce.expose_secret(),
            now,
        )?;
        // Linearization point: cancellation before this point invalidates the result.
        guard.finish()?;
        Ok(result)
    }

    /// Invalidate the current operation, including an in-flight HTTP exchange.
    /// Native wrappers must also cancel their transport task to release resources.
    /// Cancellation cannot undo a request that has already reached the server.
    pub fn cancel_sign_in(&self) -> Result<(), AuthError> {
        *self.state.lock().map_err(|_| AuthError::Internal)? = State::Idle;
        Ok(())
    }
}

impl Discovery {
    pub(crate) async fn fetch(
        config: &ClientConfig,
        transport: &dyn HttpClient,
    ) -> Result<Self, AuthError> {
        let doc: Self = http::json(
            transport,
            HttpRequest::new(HttpMethod::Get, config.discovery_url(), vec![]),
            false,
        )
        .await?;
        doc.validate(config, &["openid".into()])?;
        Ok(doc)
    }

    fn validate(&self, config: &ClientConfig, requested: &[String]) -> Result<(), AuthError> {
        if self.issuer != config.issuer
            || self.token_endpoint != config.token_url
            || !self.authorization_response_iss_parameter_supported
            || !self.response_types_supported.iter().any(|s| s == "code")
            || !self
                .grant_types_supported
                .iter()
                .any(|s| s == "authorization_code")
            || !self
                .id_token_signing_alg_values_supported
                .iter()
                .any(|s| s == "EdDSA")
            || !self
                .token_endpoint_auth_methods_supported
                .iter()
                .any(|s| s == "none")
            || !self
                .code_challenge_methods_supported
                .iter()
                .any(|s| s == "S256")
            || !requested
                .iter()
                .all(|scope| self.scopes_supported.contains(scope))
        {
            return Err(AuthError::InvalidDiscovery);
        }
        config.authorization_endpoint(&self.authorization_endpoint)?;
        config.endpoint(&self.token_endpoint)?;
        config.endpoint(&self.jwks_uri)?;
        if let Some(endpoint) = &self.revocation_endpoint {
            config.endpoint(endpoint)?;
        }
        Ok(())
    }
}

enum Callback {
    Code(SecretString),
    Error(AuthError),
}

fn validate_callback(
    config: &ClientConfig,
    pending: &Pending,
    value: &str,
) -> Result<Callback, AuthError> {
    let mut params = callback_parameters(config, value)?;
    let state = params.get("state").ok_or(AuthError::StateMismatch)?;
    if !bool::from(
        state
            .as_bytes()
            .ct_eq(pending.state.expose_secret().as_bytes()),
    ) {
        return Err(AuthError::StateMismatch);
    }
    if params.get("iss") != Some(&config.issuer) {
        return Err(AuthError::IssuerMismatch);
    }
    match (params.remove("code"), params.remove("error")) {
        (Some(code), None)
            if !code.is_empty()
                && code.len() <= 2048
                && !code.bytes().any(|b| b.is_ascii_control()) =>
        {
            if params.contains_key("error_description") || params.contains_key("error_uri") {
                return Err(AuthError::InvalidCallback);
            }
            Ok(Callback::Code(SecretString::new(code)))
        }
        (None, Some(error)) if !error.is_empty() => Ok(Callback::Error(OAuthError::parse(&error))),
        _ => Err(AuthError::InvalidCallback),
    }
}

/// Routing filter shared with native facades. This does not authenticate a
/// callback: complete_sign_in still checks state, issuer, code and the ID token.
pub(crate) fn callback_parameters(
    config: &ClientConfig,
    value: &str,
) -> Result<HashMap<String, String>, AuthError> {
    if value.len() > 8192 || value.bytes().any(|b| b.is_ascii_control() || b == b' ') {
        return Err(AuthError::InvalidCallback);
    }
    let mut url = Url::parse(value).map_err(|_| AuthError::InvalidCallback)?;
    if url.fragment().is_some() {
        return Err(AuthError::InvalidCallback);
    }
    let mut params = HashMap::new();
    for (name, value) in url.query_pairs() {
        if params
            .insert(name.into_owned(), value.into_owned())
            .is_some()
        {
            return Err(AuthError::InvalidCallback);
        }
    }
    for (name, value) in config.redirect_url.query_pairs() {
        if params.remove(name.as_ref()).as_deref() != Some(value.as_ref()) {
            return Err(AuthError::InvalidCallback);
        }
    }
    if params
        .keys()
        .any(|name| !RESPONSE_PARAMETERS.contains(&name.as_str()))
    {
        return Err(AuthError::InvalidCallback);
    }
    url.set_query(config.redirect_url.query());
    if url != config.redirect_url {
        return Err(AuthError::InvalidCallback);
    }
    Ok(params)
}

pub(crate) fn random_secret() -> Result<SecretString, AuthError> {
    let mut bytes = zeroize::Zeroizing::new([0_u8; 32]);
    getrandom::fill(&mut *bytes).map_err(|_| AuthError::RandomUnavailable)?;
    Ok(SecretString::new(URL_SAFE_NO_PAD.encode(*bytes)))
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Drop also cleans up when the caller drops an async future; it never clears a
/// newer transaction or a successfully prepared pending request.
struct OperationGuard {
    state: Arc<Mutex<State>>,
    id: String,
}

impl OperationGuard {
    fn new(state: Arc<Mutex<State>>, id: String) -> Self {
        Self { state, id }
    }
    fn check(&self) -> Result<(), AuthError> {
        let state = self.state.lock().map_err(|_| AuthError::Internal)?;
        if matches!(&*state, State::Loading(id) | State::Exchanging(id) if id == &self.id) {
            Ok(())
        } else {
            Err(AuthError::Cancelled)
        }
    }
    fn finish(&self) -> Result<(), AuthError> {
        let mut state = self.state.lock().map_err(|_| AuthError::Internal)?;
        if !matches!(&*state, State::Exchanging(id) if id == &self.id) {
            return Err(AuthError::Cancelled);
        }
        *state = State::Idle;
        Ok(())
    }
}

impl Drop for OperationGuard {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            if matches!(&*state, State::Loading(id) | State::Exchanging(id) if id == &self.id) {
                *state = State::Idle;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn rfc7636_pkce_vector() {
        assert_eq!(
            super::pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }
}
