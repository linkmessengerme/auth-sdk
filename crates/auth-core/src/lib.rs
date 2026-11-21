//! The Link Login protocol core. Platform integration is supplied by adapters.

mod attest;
mod client;
mod config;
mod error;
mod http;
mod secret;
mod session;
mod storage;
mod token;
mod userinfo;

pub use attest::{AttestedKey, AttestorError, DeviceAttestor, KeyAttestation};
pub use client::{AuthClient, AuthorizationRequest, Clock, SystemClock};
pub use config::ClientConfig;
pub use error::{AuthError, OAuthError};
pub use http::{HttpClient, HttpMethod, HttpRequest, HttpResponse, TransportError};
pub use secret::SecretString;
pub use session::{LogoutStatus, SessionClient, SessionStatus};
pub use storage::{SecureStore, StorageError, StoredEntry};
pub use token::{SignInResult, UserIdentity};
pub use userinfo::UserInfo;
