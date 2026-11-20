use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use openidconnect::{
    core::{CoreIdToken, CoreIdTokenVerifier, CoreJsonWebKeySet, CoreJwsSigningAlgorithm},
    AccessToken, AccessTokenHash, ClientId, IssuerUrl, Nonce,
};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::{config::valid_scopes, AuthError, ClientConfig, SecretString};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserIdentity {
    pub issuer: String,
    pub subject: String,
    /// Actual grants from the token response, not the requested/configured set.
    pub granted_scopes: Vec<String>,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
    pub picture: Option<String>,
}

#[derive(Debug)]
pub struct SignInResult {
    pub user: UserIdentity,
    pub access_token: SecretString,
    pub id_token: SecretString,
    pub refresh_token: Option<SecretString>,
    pub expires_at: u64,
}

#[derive(Deserialize)]
pub(crate) struct TokenResponse {
    access_token: String,
    id_token: String,
    refresh_token: Option<String>,
    token_type: String,
    expires_in: u64,
    scope: String,
}

impl Drop for TokenResponse {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.id_token.zeroize();
        self.refresh_token.zeroize();
    }
}

impl TokenResponse {
    pub(crate) fn validate(
        &self,
        config: &ClientConfig,
        requested: &[String],
    ) -> Result<(), AuthError> {
        let granted: Vec<String> = self
            .scope
            .split_ascii_whitespace()
            .map(str::to_owned)
            .collect();
        if !self.token_type.eq_ignore_ascii_case("Bearer")
            || self.expires_in == 0
            || self.access_token.is_empty()
            || self.access_token.len() > 8192
            || self.id_token.is_empty()
            || self.id_token.len() > 8192
            || self
                .refresh_token
                .as_ref()
                .is_some_and(|token| token.is_empty() || token.len() > 8192)
            || !valid_scopes(&granted)
            || !granted.iter().all(|s| requested.contains(s))
            || config
                .required_scopes
                .iter()
                .any(|s| requested.contains(s) && !granted.contains(s))
            || granted.iter().any(|s| s == "offline_access") != self.refresh_token.is_some()
        {
            return Err(AuthError::InvalidTokenResponse);
        }
        Ok(())
    }
}

pub(crate) fn verify(
    tokens: TokenResponse,
    jwks: serde_json::Value,
    config: &ClientConfig,
    nonce: &str,
    now: u64,
) -> Result<SignInResult, AuthError> {
    verify_context(tokens, jwks, config, Some(nonce), None, now)
}

pub(crate) fn verify_refresh(
    tokens: TokenResponse,
    jwks: serde_json::Value,
    config: &ClientConfig,
    subject: &str,
    now: u64,
) -> Result<SignInResult, AuthError> {
    verify_context(tokens, jwks, config, None, Some(subject), now)
}

fn verify_context(
    mut tokens: TokenResponse,
    jwks: serde_json::Value,
    config: &ClientConfig,
    nonce: Option<&str>,
    subject: Option<&str>,
    now: u64,
) -> Result<SignInResult, AuthError> {
    let timestamp = i64::try_from(now).map_err(|_| AuthError::InvalidClock)?;
    let current_time =
        DateTime::<Utc>::from_timestamp(timestamp, 0).ok_or(AuthError::InvalidClock)?;
    let keys = signing_keys(&tokens.id_token, jwks)?;
    let verifier = CoreIdTokenVerifier::new_public_client(
        ClientId::new(config.client_id.clone()),
        IssuerUrl::new(config.issuer.clone()).map_err(|_| AuthError::InvalidConfig)?,
        keys,
    )
    .set_allowed_algs([CoreJwsSigningAlgorithm::EdDsa])
    .set_time_fn(move || current_time)
    .set_issue_time_verifier_fn(move |issued| {
        if issued.timestamp() < 0 || issued.timestamp() > timestamp.saturating_add(30) {
            Err("invalid issue time".into())
        } else {
            Ok(())
        }
    });
    let id: CoreIdToken = tokens
        .id_token
        .parse()
        .map_err(|_| AuthError::InvalidIdToken)?;
    let claims = id
        .claims(&verifier, |actual: Option<&Nonce>| {
            match (nonce, actual) {
                (Some(expected), Some(actual))
                    if bool::from(expected.as_bytes().ct_eq(actual.secret().as_bytes())) =>
                {
                    Ok(())
                }
                // Link deliberately omits nonce on refresh; signature, issuer,
                // audience and the previous subject still have to match.
                (None, None) => Ok(()),
                _ => Err("invalid nonce".to_owned()),
            }
        })
        .map_err(|_| AuthError::InvalidIdToken)?;
    if claims.subject().as_str().is_empty()
        || claims.subject().as_str().len() > 255
        || claims.expiration() <= claims.issue_time()
        || claims.audiences().len() != 1
        || subject.is_some_and(|sub| sub != claims.subject().as_str())
        || claims
            .authorized_party()
            .is_some_and(|azp| azp.as_str() != config.client_id)
    {
        return Err(AuthError::InvalidIdToken);
    }
    if let Some(expected_hash) = claims.access_token_hash() {
        let actual_hash = AccessTokenHash::from_token(
            &AccessToken::new(tokens.access_token.clone()),
            id.signing_alg().map_err(|_| AuthError::InvalidIdToken)?,
            id.signing_key(&verifier)
                .map_err(|_| AuthError::InvalidIdToken)?,
        )
        .map_err(|_| AuthError::InvalidIdToken)?;
        if actual_hash != *expected_hash {
            return Err(AuthError::InvalidIdToken);
        }
    }
    let granted_scopes: Vec<String> = tokens
        .scope
        .split_ascii_whitespace()
        .map(str::to_owned)
        .collect();
    let profile = granted_scopes.iter().any(|s| s == "profile");
    let user = UserIdentity {
        issuer: config.issuer.clone(),
        subject: claims.subject().as_str().to_owned(),
        granted_scopes,
        name: profile
            .then(|| {
                claims
                    .name()
                    .and_then(|s| s.get(None))
                    .map(|value| value.as_str().to_owned())
            })
            .flatten(),
        preferred_username: profile
            .then(|| {
                claims
                    .preferred_username()
                    .map(|value| value.as_str().to_owned())
            })
            .flatten(),
        picture: profile
            .then(|| {
                claims
                    .picture()
                    .and_then(|s| s.get(None))
                    .map(|value| value.as_str().to_owned())
            })
            .flatten(),
    };
    let id_expires_at =
        u64::try_from(claims.expiration().timestamp()).map_err(|_| AuthError::InvalidIdToken)?;
    // Current Link ID/access tokens share an expiry; never outlive the verified ID token.
    let expires_at = now
        .checked_add(tokens.expires_in)
        .ok_or(AuthError::InvalidTokenResponse)?
        .min(id_expires_at);
    Ok(SignInResult {
        user,
        access_token: SecretString::new(std::mem::take(&mut tokens.access_token)),
        id_token: SecretString::new(std::mem::take(&mut tokens.id_token)),
        refresh_token: tokens.refresh_token.take().map(SecretString::new),
        expires_at,
    })
}

/// Restrict selection to exactly one named Ed25519 verification key from this
/// issuer's fetched JWKS. Never follow a token-supplied jku/x5u or accept private keys.
fn signing_keys(token: &str, jwks: serde_json::Value) -> Result<CoreJsonWebKeySet, AuthError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Header {
        alg: String,
        kid: String,
        typ: Option<String>,
    }
    let mut parts = token.split('.');
    let encoded = parts.next().ok_or(AuthError::InvalidIdToken)?;
    if parts.next().is_none()
        || parts.next().is_none()
        || parts.next().is_some()
        || encoded.len() > 2048
    {
        return Err(AuthError::InvalidIdToken);
    }
    let header: Header = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| AuthError::InvalidIdToken)?,
    )
    .map_err(|_| AuthError::InvalidIdToken)?;
    if header.alg != "EdDSA"
        || header.kid.is_empty()
        || header.kid.len() > 128
        || header.typ.as_deref().is_some_and(|typ| typ != "JWT")
    {
        return Err(AuthError::InvalidIdToken);
    }
    let keys = jwks
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .ok_or(AuthError::InvalidSigningKey)?;
    if keys.is_empty() || keys.len() > 16 {
        return Err(AuthError::InvalidSigningKey);
    }
    let matched: Vec<_> = keys
        .iter()
        .filter(|key| key.get("kid").and_then(serde_json::Value::as_str) == Some(&header.kid))
        .collect();
    if matched.len() != 1 {
        return Err(AuthError::InvalidSigningKey);
    }
    let key = matched[0];
    if key.get("kty").and_then(serde_json::Value::as_str) != Some("OKP")
        || key.get("crv").and_then(serde_json::Value::as_str) != Some("Ed25519")
        || key.get("d").is_some()
        || key.get("alg").is_some_and(|v| v.as_str() != Some("EdDSA"))
        || key.get("use").is_some_and(|v| v.as_str() != Some("sig"))
        || key.get("key_ops").is_some_and(|v| {
            v.as_array().is_none_or(|ops| {
                ops.is_empty() || ops.iter().any(|op| op.as_str() != Some("verify"))
            })
        })
    {
        return Err(AuthError::InvalidSigningKey);
    }
    let x = key
        .get("x")
        .and_then(serde_json::Value::as_str)
        .ok_or(AuthError::InvalidSigningKey)?;
    if URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|_| AuthError::InvalidSigningKey)?
        .len()
        != 32
    {
        return Err(AuthError::InvalidSigningKey);
    }
    serde_json::from_value(serde_json::json!({"keys": [key]}))
        .map_err(|_| AuthError::InvalidSigningKey)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn verifies_go_ed25519_fixture_using_backend_claim_and_jwk_shapes() {
        #[derive(Deserialize)]
        struct Fixture {
            now: u64,
            nonce: String,
            jwks: serde_json::Value,
            response: TokenResponse,
        }
        let fixture: Fixture =
            serde_json::from_str(include_str!("../tests/fixtures/go-token.json")).unwrap();
        let config = ClientConfig::from_console_json(
            include_str!("../../../bindings/fixtures/console-config.json"),
            "com.example.app://oauth/callback",
        )
        .unwrap();
        fixture
            .response
            .validate(&config, &["openid".into(), "profile".into()])
            .unwrap();
        let result = verify(
            fixture.response,
            fixture.jwks,
            &config,
            &fixture.nonce,
            fixture.now,
        )
        .unwrap();
        assert_eq!(result.user.subject, "go-signed-pairwise-sub");
        assert_eq!(result.user.name.as_deref(), Some("Go Fixture"));
        assert_eq!(result.expires_at, fixture.now + 3600);
    }
}
