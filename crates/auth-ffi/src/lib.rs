//! Native-language boundary. The protocol core has no dependency on UniFFI.
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use link_auth_core as core;

uniffi::setup_scaffolding!();

#[derive(Debug, uniffi::Enum)]
pub enum ErrorCode {
    Storage,
    InvalidStoredState,
    ReauthenticationRequired,
    SessionExists,
    RevocationPending,
    InvalidConfig,
    InvalidScopes,
    InvalidDiscovery,
    Transport,
    InvalidResponse,
    AlreadyInProgress,
    NoPendingLogin,
    Cancelled,
    Expired,
    InvalidCallback,
    StateMismatch,
    IssuerMismatch,
    AuthorizationDenied,
    InvalidTokenResponse,
    InvalidIdToken,
    InvalidSigningKey,
    RandomUnavailable,
    InvalidClock,
    Internal,
    Http {
        status: u16,
    },
    OAuth {
        code: String,
    },
    InvalidNonce,
    /// The application requires device attestation and this device did not pass.
    AttestationRequired,
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum AuthError {
    #[error("Link authentication failed: {code:?}")]
    Failure { code: ErrorCode },
}

impl From<core::AuthError> for AuthError {
    fn from(error: core::AuthError) -> Self {
        let code = match error {
            core::AuthError::Storage => ErrorCode::Storage,
            core::AuthError::InvalidStoredState => ErrorCode::InvalidStoredState,
            core::AuthError::ReauthenticationRequired => ErrorCode::ReauthenticationRequired,
            core::AuthError::SessionExists => ErrorCode::SessionExists,
            core::AuthError::RevocationPending => ErrorCode::RevocationPending,
            core::AuthError::InvalidConfig => ErrorCode::InvalidConfig,
            core::AuthError::InvalidScopes => ErrorCode::InvalidScopes,
            core::AuthError::InvalidDiscovery => ErrorCode::InvalidDiscovery,
            core::AuthError::Transport => ErrorCode::Transport,
            core::AuthError::Http { status } => ErrorCode::Http { status },
            core::AuthError::InvalidResponse => ErrorCode::InvalidResponse,
            core::AuthError::AlreadyInProgress => ErrorCode::AlreadyInProgress,
            core::AuthError::NoPendingLogin => ErrorCode::NoPendingLogin,
            core::AuthError::Cancelled => ErrorCode::Cancelled,
            core::AuthError::Expired => ErrorCode::Expired,
            core::AuthError::InvalidCallback => ErrorCode::InvalidCallback,
            core::AuthError::StateMismatch => ErrorCode::StateMismatch,
            core::AuthError::IssuerMismatch => ErrorCode::IssuerMismatch,
            core::AuthError::AuthorizationDenied => ErrorCode::AuthorizationDenied,
            core::AuthError::OAuth { code } => ErrorCode::OAuth {
                code: code.to_string(),
            },
            core::AuthError::InvalidTokenResponse => ErrorCode::InvalidTokenResponse,
            core::AuthError::InvalidIdToken => ErrorCode::InvalidIdToken,
            core::AuthError::InvalidSigningKey => ErrorCode::InvalidSigningKey,
            core::AuthError::RandomUnavailable => ErrorCode::RandomUnavailable,
            core::AuthError::InvalidClock => ErrorCode::InvalidClock,
            core::AuthError::Internal => ErrorCode::Internal,
            core::AuthError::InvalidNonce => ErrorCode::InvalidNonce,
            core::AuthError::AttestationRequired => ErrorCode::AttestationRequired,
        };
        Self::Failure { code }
    }
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum StorageFailure {
    #[error("secure storage operation failed")]
    Unavailable,
}

impl From<uniffi::UnexpectedUniFFICallbackError> for StorageFailure {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Unavailable
    }
}

#[derive(uniffi::Object)]
pub struct StorageEntry {
    inner: core::StoredEntry,
}

#[uniffi::export]
impl StorageEntry {
    #[uniffi::constructor]
    pub fn new(revision: String, payload: String) -> Arc<Self> {
        Arc::new(Self {
            inner: core::StoredEntry::new(revision, payload),
        })
    }
    pub fn revision(&self) -> String {
        self.inner.revision.clone()
    }
    pub fn payload(&self) -> String {
        self.inner.payload.expose_secret().to_owned()
    }
}

/// Native implementations must durably compare-and-swap the entire secret entry.
/// Use the supplied platform adapters. In-memory implementations are for tests.
#[uniffi::export(with_foreign)]
pub trait SecureStorage: Send + Sync {
    fn load(&self, key: String) -> Result<Option<Arc<StorageEntry>>, StorageFailure>;
    fn compare_exchange(
        &self,
        key: String,
        expected_revision: Option<String>,
        replacement: Option<Arc<StorageEntry>>,
    ) -> Result<bool, StorageFailure>;
}

struct StorageAdapter(Arc<dyn SecureStorage>);
impl core::SecureStore for StorageAdapter {
    fn load(&self, key: &str) -> Result<Option<core::StoredEntry>, core::StorageError> {
        self.0
            .load(key.into())
            .map(|entry| entry.map(|e| core::StoredEntry::new(e.revision(), e.payload())))
            .map_err(|_| core::StorageError)
    }
    fn compare_exchange(
        &self,
        key: &str,
        expected_revision: Option<&str>,
        replacement: Option<core::StoredEntry>,
    ) -> Result<bool, core::StorageError> {
        self.0
            .compare_exchange(
                key.into(),
                expected_revision.map(str::to_owned),
                replacement.map(|inner| Arc::new(StorageEntry { inner })),
            )
            .map_err(|_| core::StorageError)
    }
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum AttestationFailure {
    /// No key this time: unsupported device, a hardware or platform-service failure.
    #[error("device attestation is unavailable")]
    Unavailable,
    /// The key no longer exists on the device.
    #[error("the attested key no longer exists")]
    KeyLost,
}

impl From<uniffi::UnexpectedUniFFICallbackError> for AttestationFailure {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Unavailable
    }
}

#[derive(uniffi::Enum)]
pub enum KeyAttestation {
    /// DER certificates of the key, the key's own certificate first.
    Android { certificate_chain: Vec<Vec<u8>> },
    /// `keyId` as `generateKey` returned it and the object from `attestKey`.
    Apple {
        key_id: String,
        attestation: Vec<u8>,
    },
}

/// `key_ref` is how the platform finds the key again: a Keystore alias or an
/// App Attest `keyId`.
#[derive(uniffi::Record)]
pub struct AttestedKey {
    pub key_ref: String,
    pub attestation: KeyAttestation,
}

/// Hardware-backed signing key of this installation. Use the supplied platform
/// adapters. Private key material never crosses this interface.
#[uniffi::export(with_foreign)]
#[async_trait]
pub trait DeviceAttestor: Send + Sync {
    /// Cheap and local: false where the platform cannot attest at all.
    fn is_available(&self) -> Result<bool, AttestationFailure>;
    /// Create a sign-only P-256 key bound to the 32-byte challenge. `name` is a
    /// namespace for platform aliases. Give up after `timeout_millis`.
    async fn create_key(
        &self,
        name: String,
        challenge: Vec<u8>,
        timeout_millis: u32,
    ) -> Result<AttestedKey, AttestationFailure>;
    /// Android: SHA256withECDSA over `message`, DER. Apple: the assertion for
    /// `clientDataHash = SHA-256(message)`.
    async fn sign(&self, key_ref: String, message: Vec<u8>) -> Result<Vec<u8>, AttestationFailure>;
    async fn delete_key(&self, key_ref: String) -> Result<(), AttestationFailure>;
}

struct AttestorAdapter(Arc<dyn DeviceAttestor>);

impl From<AttestationFailure> for core::AttestorError {
    fn from(failure: AttestationFailure) -> Self {
        match failure {
            AttestationFailure::Unavailable => Self::Unavailable,
            AttestationFailure::KeyLost => Self::KeyLost,
        }
    }
}

#[async_trait]
impl core::DeviceAttestor for AttestorAdapter {
    fn is_available(&self) -> bool {
        self.0.is_available().unwrap_or(false)
    }
    async fn create_key(
        &self,
        name: &str,
        challenge: &[u8],
        timeout_millis: u32,
    ) -> Result<core::AttestedKey, core::AttestorError> {
        let created = self
            .0
            .create_key(name.into(), challenge.to_vec(), timeout_millis)
            .await?;
        Ok(core::AttestedKey {
            key_ref: created.key_ref,
            attestation: match created.attestation {
                KeyAttestation::Android { certificate_chain } => {
                    core::KeyAttestation::Android { certificate_chain }
                }
                KeyAttestation::Apple {
                    key_id,
                    attestation,
                } => core::KeyAttestation::Apple {
                    key_id,
                    attestation,
                },
            },
        })
    }
    async fn sign(&self, key_ref: &str, message: &[u8]) -> Result<Vec<u8>, core::AttestorError> {
        Ok(self.0.sign(key_ref.into(), message.to_vec()).await?)
    }
    async fn delete_key(&self, key_ref: &str) {
        let _ = self.0.delete_key(key_ref.into()).await;
    }
}

#[derive(uniffi::Enum)]
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
    ReauthenticationRequired,
    RevocationPending,
}

#[derive(uniffi::Enum)]
pub enum LogoutStatus {
    LocalOnly,
    Revoked,
    RevocationPending,
}

#[derive(uniffi::Object)]
pub struct LinkSessionClient {
    inner: core::SessionClient,
}

#[uniffi::export]
impl LinkSessionClient {
    pub fn is_callback_url(&self, value: String) -> bool {
        self.inner.is_callback_url(&value)
    }

    #[uniffi::constructor]
    pub fn new(
        config_json: String,
        redirect_uri: String,
        transport: Arc<dyn HttpTransport>,
        storage: Arc<dyn SecureStorage>,
    ) -> Result<Arc<Self>, AuthError> {
        let config = core::ClientConfig::from_console_json(&config_json, &redirect_uri)?;
        Ok(Arc::new(Self {
            inner: core::SessionClient::new(
                config,
                Arc::new(TransportAdapter(transport)),
                Arc::new(StorageAdapter(storage)),
            ),
        }))
    }

    /// The same client with device attestation: token requests are signed by a
    /// hardware key of this installation when the server asks for it.
    #[uniffi::constructor]
    pub fn with_attestation(
        config_json: String,
        redirect_uri: String,
        transport: Arc<dyn HttpTransport>,
        storage: Arc<dyn SecureStorage>,
        attestor: Arc<dyn DeviceAttestor>,
    ) -> Result<Arc<Self>, AuthError> {
        let config = core::ClientConfig::from_console_json(&config_json, &redirect_uri)?;
        Ok(Arc::new(Self {
            inner: core::SessionClient::new(
                config,
                Arc::new(TransportAdapter(transport)),
                Arc::new(StorageAdapter(storage)),
            )
            .with_device_attestor(Arc::new(AttestorAdapter(attestor))),
        }))
    }

    pub fn restore(&self) -> Result<SessionStatus, AuthError> {
        Ok(match self.inner.restore()? {
            core::SessionStatus::SignedOut => SessionStatus::SignedOut,
            core::SessionStatus::PendingLogin { expires_at } => {
                SessionStatus::PendingLogin { expires_at }
            }
            core::SessionStatus::SignedIn {
                user,
                expires_at,
                can_refresh,
            } => SessionStatus::SignedIn {
                user: user.into(),
                expires_at,
                can_refresh,
            },
            core::SessionStatus::ReauthenticationRequired => {
                SessionStatus::ReauthenticationRequired
            }
            core::SessionStatus::RevocationPending => SessionStatus::RevocationPending,
        })
    }
    pub async fn begin_sign_in(
        &self,
        scopes: Vec<String>,
    ) -> Result<Arc<AuthorizationRequest>, AuthError> {
        Ok(Arc::new(AuthorizationRequest {
            inner: self.inner.begin_sign_in(scopes).await?,
        }))
    }
    pub async fn begin_sign_in_with_nonce(
        &self,
        scopes: Vec<String>,
        nonce: String,
    ) -> Result<Arc<AuthorizationRequest>, AuthError> {
        Ok(Arc::new(AuthorizationRequest {
            inner: self.inner.begin_sign_in_with_nonce(scopes, nonce).await?,
        }))
    }

    pub async fn complete_sign_in(
        &self,
        callback_url: String,
    ) -> Result<Arc<SignInResult>, AuthError> {
        Ok(Arc::new(SignInResult {
            inner: self.inner.complete_sign_in(&callback_url).await?,
        }))
    }
    pub fn cancel_sign_in(&self) -> Result<(), AuthError> {
        self.inner.cancel_sign_in().map_err(Into::into)
    }
    pub async fn valid_session(&self) -> Result<Arc<SignInResult>, AuthError> {
        Ok(Arc::new(SignInResult {
            inner: self.inner.valid_session().await?,
        }))
    }
    pub async fn refresh(&self) -> Result<Arc<SignInResult>, AuthError> {
        Ok(Arc::new(SignInResult {
            inner: self.inner.refresh().await?,
        }))
    }
    pub async fn get_user_info(&self) -> Result<UserInfo, AuthError> {
        Ok(self.inner.get_user_info().await?.into())
    }
    pub async fn logout(&self) -> Result<LogoutStatus, AuthError> {
        Ok(match self.inner.logout().await? {
            core::LogoutStatus::LocalOnly => LogoutStatus::LocalOnly,
            core::LogoutStatus::Revoked => LogoutStatus::Revoked,
            core::LogoutStatus::RevocationPending => LogoutStatus::RevocationPending,
        })
    }
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum TransportFailure {
    #[error("native HTTP transport failed")]
    RequestFailed,
}

impl From<uniffi::UnexpectedUniFFICallbackError> for TransportFailure {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::RequestFailed
    }
}

#[derive(Clone, uniffi::Record)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

/// Object rather than a generated data class: Debug/toString must not dump a
/// token exchange body containing the PKCE verifier or authorization code.
#[derive(uniffi::Object)]
pub struct HttpRequest {
    inner: core::HttpRequest,
}

#[uniffi::export]
impl HttpRequest {
    pub fn method(&self) -> String {
        match self.inner.method {
            core::HttpMethod::Get => "GET",
            core::HttpMethod::Post => "POST",
        }
        .into()
    }
    pub fn url(&self) -> String {
        self.inner.url.clone()
    }
    pub fn headers(&self) -> Vec<HttpHeader> {
        self.inner
            .headers
            .iter()
            .map(|(name, value)| HttpHeader {
                name: name.clone(),
                value: value.clone(),
            })
            .collect()
    }
    pub fn body(&self) -> Vec<u8> {
        self.inner.body.clone()
    }
    pub fn timeout_millis(&self) -> u32 {
        self.inner.timeout_millis
    }
    pub fn max_response_bytes(&self) -> u32 {
        self.inner.max_response_bytes
    }
}

#[derive(uniffi::Object)]
pub struct HttpResponse {
    inner: Mutex<Option<core::HttpResponse>>,
}

#[uniffi::export]
impl HttpResponse {
    #[uniffi::constructor]
    pub fn new(status: u16, url: String, content_type: String, body: Vec<u8>) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Some(core::HttpResponse {
                status,
                url,
                content_type,
                body,
            })),
        })
    }
}

/// Implement with a native HTTP client. TLS verification is mandatory. Disable
/// redirects, automatic retries, cookies and credential injection. Enforce the
/// request's timeout and response-body limit while reading, and redact logging.
#[uniffi::export(with_foreign)]
#[async_trait]
pub trait HttpTransport: Send + Sync {
    async fn execute(
        &self,
        request: Arc<HttpRequest>,
    ) -> Result<Arc<HttpResponse>, TransportFailure>;
}

struct TransportAdapter(Arc<dyn HttpTransport>);

#[async_trait]
impl core::HttpClient for TransportAdapter {
    async fn execute(
        &self,
        request: core::HttpRequest,
    ) -> Result<core::HttpResponse, core::TransportError> {
        let response = self
            .0
            .execute(Arc::new(HttpRequest { inner: request }))
            .await
            .map_err(|_| core::TransportError)?;
        let result = response
            .inner
            .lock()
            .map_err(|_| core::TransportError)?
            .take()
            .ok_or(core::TransportError);
        result
    }
}

#[derive(uniffi::Object)]
pub struct AuthorizationRequest {
    inner: core::AuthorizationRequest,
}

#[uniffi::export]
impl AuthorizationRequest {
    pub fn transaction_id(&self) -> String {
        self.inner.transaction_id.clone()
    }
    pub fn authorization_url(&self) -> String {
        self.inner.authorization_url.clone()
    }
    pub fn expires_at(&self) -> u64 {
        self.inner.expires_at
    }
}

#[derive(Clone, uniffi::Record)]
pub struct UserIdentity {
    pub issuer: String,
    pub subject: String,
    pub granted_scopes: Vec<String>,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
    pub picture: Option<String>,
    /// `verified`, `unlocked`, `mismatch` or `none`: the server's view of this
    /// device. Absent while the application's device attestation is off.
    #[uniffi(default = None)]
    pub device_trust: Option<String>,
}

impl From<core::UserIdentity> for UserIdentity {
    fn from(user: core::UserIdentity) -> Self {
        Self {
            issuer: user.issuer,
            subject: user.subject,
            granted_scopes: user.granted_scopes,
            name: user.name,
            preferred_username: user.preferred_username,
            picture: user.picture,
            device_trust: user.device_trust,
        }
    }
}

/// Optional fields reflect current authorization, not only the original grant.
#[derive(uniffi::Record)]
pub struct UserInfo {
    pub subject: String,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
    pub picture: Option<String>,
    pub phone_number: Option<String>,
    pub phone_number_verified: Option<bool>,
}

impl From<core::UserInfo> for UserInfo {
    fn from(info: core::UserInfo) -> Self {
        Self {
            subject: info.subject,
            name: info.name,
            preferred_username: info.preferred_username,
            picture: info.picture,
            phone_number: info.phone_number,
            phone_number_verified: info.phone_number_verified,
        }
    }
}

#[derive(uniffi::Object)]
pub struct SignInResult {
    inner: core::SignInResult,
}

#[uniffi::export]
impl SignInResult {
    pub fn user(&self) -> UserIdentity {
        self.inner.user.clone().into()
    }
    /// Copies a secret into native memory. Do not log it; use protected storage.
    pub fn access_token(&self) -> String {
        self.inner.access_token.expose_secret().to_owned()
    }
    pub fn id_token(&self) -> String {
        self.inner.id_token.expose_secret().to_owned()
    }
    pub fn refresh_token(&self) -> Option<String> {
        self.inner
            .refresh_token
            .as_ref()
            .map(|s| s.expose_secret().to_owned())
    }
    pub fn expires_at(&self) -> u64 {
        self.inner.expires_at
    }
}

#[derive(uniffi::Object)]
pub struct LinkAuthClient {
    inner: core::AuthClient,
}

#[uniffi::export]
impl LinkAuthClient {
    #[uniffi::constructor]
    pub fn new(
        config_json: String,
        redirect_uri: String,
        transport: Arc<dyn HttpTransport>,
    ) -> Result<Arc<Self>, AuthError> {
        let config = core::ClientConfig::from_console_json(&config_json, &redirect_uri)?;
        Ok(Arc::new(Self {
            inner: core::AuthClient::new(config, Arc::new(TransportAdapter(transport))),
        }))
    }

    pub async fn begin_sign_in(
        &self,
        scopes: Vec<String>,
    ) -> Result<Arc<AuthorizationRequest>, AuthError> {
        Ok(Arc::new(AuthorizationRequest {
            inner: self.inner.begin_sign_in(scopes).await?,
        }))
    }

    pub async fn begin_sign_in_with_nonce(
        &self,
        scopes: Vec<String>,
        nonce: String,
    ) -> Result<Arc<AuthorizationRequest>, AuthError> {
        Ok(Arc::new(AuthorizationRequest {
            inner: self.inner.begin_sign_in_with_nonce(scopes, nonce).await?,
        }))
    }

    pub async fn complete_sign_in(
        &self,
        callback_url: String,
    ) -> Result<Arc<SignInResult>, AuthError> {
        Ok(Arc::new(SignInResult {
            inner: self.inner.complete_sign_in(&callback_url).await?,
        }))
    }

    pub fn cancel_sign_in(&self) -> Result<(), AuthError> {
        self.inner.cancel_sign_in().map_err(Into::into)
    }
}
