use thiserror::Error;

/// Errors deliberately exclude URLs, response bodies, tokens and server descriptions.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("secure storage operation failed")]
    Storage,
    #[error("stored authentication state is invalid or belongs to another client")]
    InvalidStoredState,
    #[error("sign in again; the previous refresh token must not be reused")]
    ReauthenticationRequired,
    #[error("a session already exists; log out before changing accounts")]
    SessionExists,
    #[error("local logout is saved but remote revocation is pending")]
    RevocationPending,
    #[error("invalid public client configuration")]
    InvalidConfig,
    #[error("requested scopes must include openid and belong to the configured Login scopes")]
    InvalidScopes,
    #[error("provider discovery does not match the configured Link issuer")]
    InvalidDiscovery,
    #[error("network request failed; start a new login after a token exchange failure")]
    Transport,
    #[error("HTTP request failed with status {status}")]
    Http { status: u16 },
    #[error("invalid HTTP response")]
    InvalidResponse,
    #[error("a login operation is already in progress")]
    AlreadyInProgress,
    #[error("there is no pending login")]
    NoPendingLogin,
    #[error("login was cancelled")]
    Cancelled,
    #[error("login expired")]
    Expired,
    #[error("callback does not match the registered redirect URI")]
    InvalidCallback,
    #[error("callback state does not match the pending login")]
    StateMismatch,
    #[error("callback issuer does not match the configured issuer")]
    IssuerMismatch,
    #[error("authorization was denied")]
    AuthorizationDenied,
    #[error("OAuth request failed: {code}")]
    OAuth { code: OAuthError },
    #[error("invalid token response")]
    InvalidTokenResponse,
    #[error("ID token validation failed")]
    InvalidIdToken,
    #[error("the ID token signing key is missing or ambiguous")]
    InvalidSigningKey,
    #[error("secure random source unavailable")]
    RandomUnavailable,
    #[error("system clock is invalid")]
    InvalidClock,
    #[error("internal synchronization failure")]
    Internal,
    #[error("nonce must be 32 to 256 base64url characters")]
    InvalidNonce,
    #[error("the application requires device attestation and this device did not pass")]
    AttestationRequired,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum OAuthError {
    #[error("invalid_request")]
    InvalidRequest,
    #[error("invalid_client")]
    InvalidClient,
    #[error("invalid_grant")]
    InvalidGrant,
    #[error("unauthorized_client")]
    UnauthorizedClient,
    #[error("invalid_scope")]
    InvalidScope,
    #[error("unsupported_grant_type")]
    UnsupportedGrantType,
    #[error("temporarily_unavailable")]
    TemporarilyUnavailable,
    #[error("server_error")]
    ServerError,
    #[error("unrecognized OAuth error")]
    Other,
}

impl OAuthError {
    pub(crate) fn parse(value: &str) -> AuthError {
        if value == "access_denied" {
            return AuthError::AuthorizationDenied;
        }
        AuthError::OAuth {
            code: match value {
                "invalid_request" => Self::InvalidRequest,
                "invalid_client" => Self::InvalidClient,
                "invalid_grant" => Self::InvalidGrant,
                "unauthorized_client" => Self::UnauthorizedClient,
                "invalid_scope" => Self::InvalidScope,
                "unsupported_grant_type" => Self::UnsupportedGrantType,
                "temporarily_unavailable" => Self::TemporarilyUnavailable,
                "server_error" => Self::ServerError,
                _ => Self::Other,
            },
        }
    }
}
