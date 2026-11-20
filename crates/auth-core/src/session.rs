use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use futures::lock::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    client::{random_secret, Discovery, Pending},
    http, token, AuthClient, AuthError, AuthorizationRequest, ClientConfig, Clock, HttpClient,
    HttpMethod, HttpRequest, SecretString, SecureStore, SignInResult, StoredEntry, SystemClock,
    UserIdentity,
};

const MAX_JOURNAL_BYTES: usize = 64 * 1024;
const REFRESH_MARGIN_SECONDS: u64 = 30;

#[derive(Debug, PartialEq, Eq)]
pub enum SessionStatus {
    SignedOut,
    PendingLogin {
        expires_at: u64,
    },
    SignedIn {
        user: UserIdentity,
        expires_at: u64,
        can_refresh: bool,
    },
    /// Also returned when a previous process died after marking a token consumed.
    ReauthenticationRequired,
    RevocationPending,
}

#[derive(Debug, PartialEq, Eq)]
pub enum LogoutStatus {
    /// No known token was available to revoke (e.g. a cancelled pending login).
    LocalOnly,
    Revoked,
    /// The local session is disabled durably. Calling logout again retries revoke.
    RevocationPending,
}

/// Stateful API. A durable CAS journal prevents reuse of codes/refresh tokens
/// across crashes and competing clients. A per-instance async gate coalesces
/// concurrent refresh callers; no executor or network runtime is embedded.
pub struct SessionClient {
    config: ClientConfig,
    transport: Arc<dyn HttpClient>,
    store: Arc<dyn SecureStore>,
    clock: Arc<dyn Clock>,
    auth: AuthClient,
    key: String,
    gate: Mutex<()>,
}

#[derive(Serialize, Deserialize)]
struct StoredSecret(#[serde(with = "crate::secret::serialized")] SecretString);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedSession {
    user: UserIdentity,
    access_token: StoredSecret,
    id_token: StoredSecret,
    refresh_token: Option<StoredSecret>,
    expires_at: u64,
}

impl SavedSession {
    fn save(value: &SignInResult) -> Self {
        Self {
            user: value.user.clone(),
            access_token: StoredSecret(value.access_token.duplicate()),
            id_token: StoredSecret(value.id_token.duplicate()),
            refresh_token: value
                .refresh_token
                .as_ref()
                .map(|s| StoredSecret(s.duplicate())),
            expires_at: value.expires_at,
        }
    }

    fn into_result(self) -> SignInResult {
        SignInResult {
            user: self.user,
            access_token: self.access_token.0,
            id_token: self.id_token.0,
            refresh_token: self.refresh_token.map(|s| s.0),
            expires_at: self.expires_at,
        }
    }

    fn validate(&self, config: &ClientConfig) -> Result<(), AuthError> {
        let profile = self.user.granted_scopes.iter().any(|s| s == "profile");
        if self.user.issuer != config.issuer()
            || self.user.subject.is_empty()
            || self.user.subject.len() > 255
            // Issued grants are a snapshot. Updating the public config must not
            // make an old session unreadable (in particular, impossible to revoke).
            || !crate::config::valid_scopes(&self.user.granted_scopes)
            || [&self.access_token.0, &self.id_token.0]
                .iter()
                .any(|s| s.expose_secret().is_empty() || s.expose_secret().len() > 8192)
            || self
                .refresh_token
                .as_ref()
                .is_some_and(|s| s.0.expose_secret().is_empty() || s.0.expose_secret().len() > 8192)
            || self
                .user
                .granted_scopes
                .iter()
                .any(|s| s == "offline_access")
                != self.refresh_token.is_some()
            || (!profile
                && (self.user.name.is_some()
                    || self.user.preferred_username.is_some()
                    || self.user.picture.is_some()))
            || self.expires_at == 0
        {
            return Err(AuthError::InvalidStoredState);
        }
        Ok(())
    }

    fn revocation_token(&self) -> SecretString {
        self.refresh_token
            .as_ref()
            .map_or(&self.access_token.0, |s| &s.0)
            .duplicate()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "phase", content = "data", rename_all = "snake_case")]
enum Phase {
    Pending(Pending),
    Exchanging,
    Session(SavedSession),
    // Retained only for revocation, NEVER for another refresh or API request.
    Refreshing(SavedSession),
    Revoking(StoredSecret),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema: u32,
    binding: String,
    state: Phase,
}

struct Entry {
    revision: String,
    state: Phase,
}

impl SessionClient {
    /// Filters unrelated OS links without reading storage or consuming an attempt.
    pub fn is_callback_url(&self, value: &str) -> bool {
        crate::client::callback_parameters(&self.config, value).is_ok()
    }

    pub fn new(
        config: ClientConfig,
        transport: Arc<dyn HttpClient>,
        store: Arc<dyn SecureStore>,
    ) -> Self {
        Self::with_clock(config, transport, store, Arc::new(SystemClock))
    }

    pub fn with_clock(
        config: ClientConfig,
        transport: Arc<dyn HttpClient>,
        store: Arc<dyn SecureStore>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let mut digest = Sha256::new();
        for field in [config.issuer(), config.client_id(), config.redirect_uri()] {
            digest.update((field.len() as u64).to_be_bytes());
            digest.update(field.as_bytes());
        }
        let key = format!("link.auth.v1.{}", URL_SAFE_NO_PAD.encode(digest.finalize()));
        let auth = AuthClient::with_clock(config.clone(), transport.clone(), clock.clone());
        Self {
            config,
            transport,
            store,
            clock,
            auth,
            key,
            gate: Mutex::new(()),
        }
    }

    /// Startup snapshot from trusted platform storage. An expired session may be
    /// shown as cached identity; only valid_session returns usable credentials.
    /// Call on startup, not as an in-flight progress polling API.
    pub fn restore(&self) -> Result<SessionStatus, AuthError> {
        let Some(entry) = self.load()? else {
            return Ok(SessionStatus::SignedOut);
        };
        match entry.state {
            Phase::Session(session) => Ok(SessionStatus::SignedIn {
                user: session.user,
                expires_at: session.expires_at,
                can_refresh: session.refresh_token.is_some(),
            }),
            Phase::Pending(pending) => {
                if self.clock.unix_time_seconds()? >= pending.expires_at {
                    self.cas(Some(&entry.revision), None)?;
                    Ok(SessionStatus::SignedOut)
                } else {
                    let expires_at = pending.expires_at;
                    self.auth.import_pending(pending)?;
                    Ok(SessionStatus::PendingLogin { expires_at })
                }
            }
            Phase::Revoking(_) => Ok(SessionStatus::RevocationPending),
            Phase::Refreshing(_) | Phase::Exchanging => Ok(SessionStatus::ReauthenticationRequired),
        }
    }

    pub async fn begin_sign_in(
        &self,
        scopes: Vec<String>,
    ) -> Result<AuthorizationRequest, AuthError> {
        self.begin_sign_in_inner(scopes, None).await
    }

    /// Bind this login to a one-use challenge created by your backend.
    pub async fn begin_sign_in_with_nonce(
        &self,
        scopes: Vec<String>,
        nonce: String,
    ) -> Result<AuthorizationRequest, AuthError> {
        crate::client::validate_nonce(&nonce)?;
        self.begin_sign_in_inner(scopes, Some(nonce)).await
    }

    async fn begin_sign_in_inner(
        &self,
        scopes: Vec<String>,
        nonce: Option<String>,
    ) -> Result<AuthorizationRequest, AuthError> {
        // An interrupted refresh still has a family handle. Revoke it before
        // creating another session. No consumed refresh is ever sent to /token.
        if self
            .load()?
            .is_some_and(|e| matches!(e.state, Phase::Refreshing(_) | Phase::Revoking(_)))
            && self.logout().await? == LogoutStatus::RevocationPending
        {
            return Err(AuthError::RevocationPending);
        }
        let _gate = self.gate.lock().await;
        let old = self.load()?;
        if let Some(entry) = &old {
            match &entry.state {
                Phase::Session(_) => return Err(AuthError::SessionExists),
                Phase::Pending(pending)
                    if pending.expires_at > self.clock.unix_time_seconds()? =>
                {
                    return Err(AuthError::AlreadyInProgress)
                }
                Phase::Refreshing(_) | Phase::Revoking(_) => {
                    return Err(AuthError::RevocationPending)
                }
                _ => (),
            }
        }
        self.auth.cancel_sign_in()?;
        // Reserve storage before discovery. A simultaneous logout invalidates
        // this revision and prevents a later pending flow from reappearing.
        let reservation = self.cas(
            old.as_ref().map(|e| e.revision.as_str()),
            Some(Phase::Exchanging),
        )?;
        let result = match nonce {
            Some(value) => self.auth.begin_sign_in_with_nonce(scopes, value).await,
            None => self.auth.begin_sign_in(scopes).await,
        };
        match result {
            Ok(request) => {
                let pending = self.auth.export_pending()?;
                if let Err(error) = self.cas(Some(&reservation), Some(Phase::Pending(pending))) {
                    self.auth.cancel_sign_in()?;
                    return Err(error);
                }
                Ok(request)
            }
            Err(error) => {
                self.remove_if_current(&reservation);
                Err(error)
            }
        }
    }

    pub async fn complete_sign_in(&self, callback: &str) -> Result<SignInResult, AuthError> {
        let _gate = self.gate.lock().await;
        let entry = self.load()?.ok_or(AuthError::NoPendingLogin)?;
        let Phase::Pending(pending) = entry.state else {
            return Err(AuthError::NoPendingLogin);
        };
        self.auth.import_pending(pending)?;
        self.auth.check_callback(callback)?;
        // This must be durable BEFORE the one-use authorization code is sent.
        let marker = self.cas(Some(&entry.revision), Some(Phase::Exchanging))?;
        match self.auth.complete_sign_in(callback).await {
            Ok(result) => {
                self.cas(
                    Some(&marker),
                    Some(Phase::Session(SavedSession::save(&result))),
                )?;
                Ok(result)
            }
            Err(error) => {
                self.remove_if_current(&marker);
                Err(error)
            }
        }
    }

    pub fn cancel_sign_in(&self) -> Result<(), AuthError> {
        self.auth.cancel_sign_in()?;
        if let Some(entry) = self.load()? {
            if matches!(entry.state, Phase::Pending(_) | Phase::Exchanging) {
                self.cas(Some(&entry.revision), None)?;
            }
        }
        Ok(())
    }

    /// Coalesces concurrent callers and refreshes when <= 30 seconds remain.
    pub async fn valid_session(&self) -> Result<SignInResult, AuthError> {
        self.valid_session_with_revision()
            .await
            .map(|(session, _)| session)
    }

    async fn valid_session_with_revision(&self) -> Result<(SignInResult, String), AuthError> {
        let _gate = self.gate.lock().await;
        let entry = self.load()?.ok_or(AuthError::ReauthenticationRequired)?;
        if let Phase::Session(session) = &entry.state {
            if session.expires_at
                > self
                    .clock
                    .unix_time_seconds()?
                    .saturating_add(REFRESH_MARGIN_SECONDS)
            {
                let Phase::Session(session) = entry.state else {
                    unreachable!()
                };
                return Ok((session.into_result(), entry.revision));
            }
        }
        self.refresh_entry(entry).await
    }

    /// Fetches current data using the session's access token, refreshing first
    /// when needed. Scopes are selected at sign-in, never by this data request.
    /// A late response cannot escape after logout or session replacement.
    pub async fn get_user_info(&self) -> Result<crate::UserInfo, AuthError> {
        let (session, revision) = self.valid_session_with_revision().await?;
        let info = crate::userinfo::fetch(&self.config, self.transport.as_ref(), &session).await?;
        if self.load()?.is_none_or(|entry| entry.revision != revision) {
            return Err(AuthError::Cancelled);
        }
        if self.clock.unix_time_seconds()? >= session.expires_at {
            return Err(AuthError::Expired);
        }
        Ok(info)
    }

    /// Explicit refresh. Callers overlapping the same revision share one exchange.
    pub async fn refresh(&self) -> Result<SignInResult, AuthError> {
        let observed = self
            .load()?
            .ok_or(AuthError::ReauthenticationRequired)?
            .revision;
        let _gate = self.gate.lock().await;
        let entry = self.load()?.ok_or(AuthError::ReauthenticationRequired)?;
        if observed != entry.revision {
            if let Phase::Session(session) = entry.state {
                return Ok(session.into_result());
            }
        }
        self.refresh_entry(entry).await.map(|(session, _)| session)
    }

    async fn refresh_entry(&self, entry: Entry) -> Result<(SignInResult, String), AuthError> {
        let Phase::Session(previous) = entry.state else {
            return Err(AuthError::ReauthenticationRequired);
        };
        let refresh = previous
            .refresh_token
            .as_ref()
            .ok_or(AuthError::ReauthenticationRequired)?
            .0
            .duplicate();
        let scopes = previous.user.granted_scopes.clone();
        let subject = previous.user.subject.clone();
        // Safe to retry discovery: the refresh has not been consumed yet.
        let discovery = Discovery::fetch(&self.config, self.transport.as_ref()).await?;
        let marker = self.cas(Some(&entry.revision), Some(Phase::Refreshing(previous)))?;
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "refresh_token")
            .append_pair("client_id", self.config.client_id())
            .append_pair("refresh_token", refresh.expose_secret())
            .finish()
            .into_bytes();
        let tokens: token::TokenResponse = http::json(
            self.transport.as_ref(),
            HttpRequest::new(HttpMethod::Post, discovery.token_endpoint, body),
            true,
        )
        .await?;
        tokens.validate(&self.config, &scopes)?;
        let jwks = http::json(
            self.transport.as_ref(),
            HttpRequest::new(HttpMethod::Get, discovery.jwks_uri, vec![]),
            false,
        )
        .await?;
        let result = token::verify_refresh(
            tokens,
            jwks,
            &self.config,
            &subject,
            self.clock.unix_time_seconds()?,
        )?;
        if result
            .refresh_token
            .as_ref()
            .is_some_and(|s| s.expose_secret() == refresh.expose_secret())
        {
            return Err(AuthError::InvalidTokenResponse);
        }
        // Failure/cancellation/process death leaves the consumed marker intact.
        // Only a successful durable CAS makes new credentials available.
        let revision = self.cas(
            Some(&marker),
            Some(Phase::Session(SavedSession::save(&result))),
        )?;
        Ok((result, revision))
    }

    /// Local invalidation is durable before network I/O and does not wait for an
    /// in-flight refresh. A tombstone keeps a revocation handle for offline retry.
    pub async fn logout(&self) -> Result<LogoutStatus, AuthError> {
        self.auth.cancel_sign_in()?;
        for _ in 0..8 {
            let Some(entry) = self.load()? else {
                return Ok(LogoutStatus::LocalOnly);
            };
            let token = match entry.state {
                Phase::Session(session) | Phase::Refreshing(session) => session.revocation_token(),
                Phase::Revoking(token) => token.0,
                Phase::Pending(_) | Phase::Exchanging => {
                    match self.cas(Some(&entry.revision), None) {
                        Ok(_) => return Ok(LogoutStatus::LocalOnly),
                        Err(AuthError::Cancelled) => continue,
                        Err(error) => return Err(error),
                    }
                }
            };
            let marker = match self.cas(
                Some(&entry.revision),
                Some(Phase::Revoking(StoredSecret(token.duplicate()))),
            ) {
                Ok(marker) => marker,
                Err(AuthError::Cancelled) => continue,
                Err(error) => return Err(error),
            };
            let revoked = async {
                let discovery = Discovery::fetch(&self.config, self.transport.as_ref()).await?;
                let endpoint = discovery
                    .revocation_endpoint
                    .ok_or(AuthError::InvalidDiscovery)?;
                let body = url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("client_id", self.config.client_id())
                    .append_pair("token", token.expose_secret())
                    .finish()
                    .into_bytes();
                http::revoke(
                    self.transport.as_ref(),
                    HttpRequest::new(HttpMethod::Post, endpoint, body),
                )
                .await
            }
            .await;
            if revoked.is_err() {
                return Ok(LogoutStatus::RevocationPending);
            }
            match self.cas(Some(&marker), None) {
                Ok(_) | Err(AuthError::Cancelled) => return Ok(LogoutStatus::Revoked),
                Err(error) => return Err(error),
            }
        }
        Err(AuthError::AlreadyInProgress)
    }

    fn load(&self) -> Result<Option<Entry>, AuthError> {
        let Some(entry) = self.store.load(&self.key).map_err(|_| AuthError::Storage)? else {
            return Ok(None);
        };
        if entry.payload.expose_secret().len() > MAX_JOURNAL_BYTES || entry.revision.len() != 43 {
            return Err(AuthError::InvalidStoredState);
        }
        let journal: Journal = serde_json::from_str(entry.payload.expose_secret())
            .map_err(|_| AuthError::InvalidStoredState)?;
        if journal.schema != 1 || journal.binding != self.key {
            return Err(AuthError::InvalidStoredState);
        }
        if let Phase::Session(session) | Phase::Refreshing(session) = &journal.state {
            session.validate(&self.config)?;
        }
        if let Phase::Revoking(token) = &journal.state {
            if token.0.expose_secret().is_empty() || token.0.expose_secret().len() > 8192 {
                return Err(AuthError::InvalidStoredState);
            }
        }
        Ok(Some(Entry {
            revision: entry.revision,
            state: journal.state,
        }))
    }

    fn cas(&self, expected: Option<&str>, replacement: Option<Phase>) -> Result<String, AuthError> {
        let revision = random_secret()?.expose_secret().to_owned();
        let value = replacement
            .map(|state| {
                let payload = serde_json::to_string(&Journal {
                    schema: 1,
                    binding: self.key.clone(),
                    state,
                })
                .map_err(|_| AuthError::Internal)?;
                if payload.len() > MAX_JOURNAL_BYTES {
                    return Err(AuthError::InvalidStoredState);
                }
                Ok(StoredEntry::new(revision.clone(), payload))
            })
            .transpose()?;
        if self
            .store
            .compare_exchange(&self.key, expected, value)
            .map_err(|_| AuthError::Storage)?
        {
            Ok(revision)
        } else {
            Err(AuthError::Cancelled)
        }
    }

    fn remove_if_current(&self, revision: &str) {
        // Best-effort cleanup only. The durable consumed marker is already safe.
        let _ = self.cas(Some(revision), None);
    }
}
