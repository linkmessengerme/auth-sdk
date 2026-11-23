use std::fmt;

use async_trait::async_trait;
use serde::de::DeserializeOwned;
use zeroize::Zeroize;

use crate::{attest::AttestReason, AuthError, OAuthError};

pub const MAX_RESPONSE_BYTES: u32 = 256 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
}

pub struct HttpRequest {
    pub method: HttpMethod,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub timeout_millis: u32,
    pub max_response_bytes: u32,
}

impl HttpRequest {
    pub(crate) fn new(method: HttpMethod, url: String, body: Vec<u8>) -> Self {
        let mut headers = vec![("Accept".into(), "application/json".into())];
        if method == HttpMethod::Post {
            headers.push((
                "Content-Type".into(),
                "application/x-www-form-urlencoded".into(),
            ));
        }
        Self {
            method,
            url,
            headers,
            body,
            timeout_millis: 15_000,
            max_response_bytes: MAX_RESPONSE_BYTES,
        }
    }
}

impl Drop for HttpRequest {
    fn drop(&mut self) {
        self.body.zeroize();
        for (_, value) in &mut self.headers {
            value.zeroize();
        }
    }
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .finish_non_exhaustive()
    }
}

pub struct HttpResponse {
    pub status: u16,
    /// The actual response URL. Redirects must already have been disabled by the adapter.
    pub url: String,
    pub content_type: String,
    pub body: Vec<u8>,
}

impl Drop for HttpResponse {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("HTTP transport failed")]
pub struct TransportError;

/// Adapter contract: TLS verification enabled, no redirects, no automatic retries,
/// no cookies/credentials injected, and timeout/body limits applied during reading.
/// In particular a POST may have consumed a code even when its response was lost.
#[async_trait]
pub trait HttpClient: Send + Sync {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, TransportError>;
}

/// A JSON response from the address that was asked, within the size limit.
async fn fetch(
    transport: &dyn HttpClient,
    request: HttpRequest,
) -> Result<HttpResponse, AuthError> {
    let expected_url = request.url.clone();
    let response = transport
        .execute(request)
        .await
        .map_err(|_| AuthError::Transport)?;
    if response.url != expected_url
        || response.body.len() > MAX_RESPONSE_BYTES as usize
        || !response
            .content_type
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .eq_ignore_ascii_case("application/json")
    {
        return Err(AuthError::InvalidResponse);
    }
    Ok(response)
}

pub(crate) async fn json<T: DeserializeOwned>(
    transport: &dyn HttpClient,
    request: HttpRequest,
) -> Result<T, AuthError> {
    let response = fetch(transport, request).await?;
    if response.status != 200 {
        return Err(AuthError::Http {
            status: response.status,
        });
    }
    serde_json::from_slice(&response.body).map_err(|_| AuthError::InvalidResponse)
}

/// Why a token request did not produce tokens.
pub(crate) struct TokenFailure {
    pub error: AuthError,
    /// The server's `attestation_error`, when it sent one.
    pub reason: Option<AttestReason>,
    /// No definite answer (network failure, an unusable response, 429, 5xx):
    /// the request may or may not have been processed.
    pub unanswered: bool,
}

/// POST to the token endpoint. An OAuth error body is reduced to its code and
/// the attestation reason; descriptions never leave this function.
pub(crate) async fn token<T: DeserializeOwned>(
    transport: &dyn HttpClient,
    request: HttpRequest,
) -> Result<T, TokenFailure> {
    let response = match fetch(transport, request).await {
        Ok(response) => response,
        Err(error) => {
            return Err(TokenFailure {
                error,
                reason: None,
                unanswered: true,
            })
        }
    };
    if response.status == 200 {
        return serde_json::from_slice(&response.body).map_err(|_| TokenFailure {
            error: AuthError::InvalidTokenResponse,
            reason: None,
            unanswered: false,
        });
    }
    #[derive(serde::Deserialize)]
    struct ErrorBody {
        error: String,
        #[serde(default)]
        attestation_error: Option<serde_json::Value>,
    }
    let unanswered = response.status == 429 || response.status >= 500;
    if (400..500).contains(&response.status) {
        if let Ok(body) = serde_json::from_slice::<ErrorBody>(&response.body) {
            return Err(TokenFailure {
                error: OAuthError::parse(&body.error),
                reason: body
                    .attestation_error
                    .as_ref()
                    .and_then(serde_json::Value::as_str)
                    .map(AttestReason::parse),
                unanswered,
            });
        }
    }
    Err(TokenFailure {
        error: AuthError::Http {
            status: response.status,
        },
        reason: None,
        unanswered,
    })
}

/// Status and JSON body of a request whose non-200 answers carry meaning.
pub(crate) struct Reply {
    pub status: u16,
    pub body: serde_json::Value,
}

pub(crate) async fn reply(
    transport: &dyn HttpClient,
    request: HttpRequest,
) -> Result<Reply, AuthError> {
    let response = fetch(transport, request).await?;
    Ok(Reply {
        status: response.status,
        body: serde_json::from_slice(&response.body).unwrap_or(serde_json::Value::Null),
    })
}

/// RFC 7009 success has an empty body and need not have a Content-Type header.
pub(crate) async fn revoke(
    transport: &dyn HttpClient,
    request: HttpRequest,
) -> Result<(), AuthError> {
    let expected_url = request.url.clone();
    let response = transport
        .execute(request)
        .await
        .map_err(|_| AuthError::Transport)?;
    if response.url != expected_url || response.body.len() > MAX_RESPONSE_BYTES as usize {
        return Err(AuthError::InvalidResponse);
    }
    if response.status != 200 {
        return Err(AuthError::Http {
            status: response.status,
        });
    }
    Ok(())
}
