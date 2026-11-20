use std::collections::HashSet;

use serde::Deserialize;
use url::Url;

use crate::AuthError;

const MAX_CONFIG_BYTES: usize = 64 * 1024;
const SHARED_AUTHORIZATION_ENDPOINT: &str = "https://linkm.me/oauth/authorize";
pub(crate) const RESPONSE_PARAMETERS: &[&str] = &[
    "code",
    "state",
    "iss",
    "error",
    "error_description",
    "error_uri",
];

#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub(crate) client_id: String,
    pub(crate) issuer: String,
    pub(crate) api_base_url: Url,
    pub(crate) token_url: String,
    pub(crate) redirect_uri: String,
    pub(crate) redirect_url: Url,
    pub(crate) scopes: Vec<String>,
    pub(crate) required_scopes: Vec<String>,
}

#[derive(Deserialize)]
struct ConsoleConfig {
    #[serde(rename = "type")]
    kind: String,
    app_id: String,
    platform: String,
    client_id: String,
    issuer: String,
    #[serde(default)]
    api_base_url: Option<String>,
    token_url: String,
    redirect_uris: Vec<String>,
    scopes: Vec<String>,
    required_scopes: Vec<String>,
    grant_types: Vec<String>,
    pkce_method: String,
    scope_mode: String,
    // Explicitly reject accidental use of confidential credentials, even if empty.
    #[serde(default)]
    private_key: Option<serde_json::Value>,
    #[serde(default)]
    client_secret: Option<serde_json::Value>,
}

impl ClientConfig {
    /// Load the public JSON downloaded from Console. The caller explicitly selects
    /// one registered redirect URI; client secrets/key-files are not supported.
    pub fn from_console_json(json: &str, redirect_uri: &str) -> Result<Self, AuthError> {
        if json.len() > MAX_CONFIG_BYTES || redirect_uri.len() > 2048 {
            return Err(AuthError::InvalidConfig);
        }
        let raw: ConsoleConfig =
            serde_json::from_str(json).map_err(|_| AuthError::InvalidConfig)?;
        let raw_value: serde_json::Value =
            serde_json::from_str(json).map_err(|_| AuthError::InvalidConfig)?;
        if raw.kind != "link_oauth_client_config"
            || raw.app_id.is_empty()
            || raw.app_id.len() > 128
            || !matches!(raw.platform.as_str(), "ios" | "android" | "web")
            || raw.client_id.is_empty()
            || raw.client_id.len() > 40
            || !raw
                .client_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
            || !matches!(raw.scope_mode.as_str(), "inherit" | "explicit")
            || raw.pkce_method != "S256"
            || raw.private_key.is_some()
            || raw.client_secret.is_some()
            || raw_value.get("private_key").is_some()
            || raw_value.get("client_secret").is_some()
            || !raw.grant_types.iter().any(|g| g == "authorization_code")
            || raw
                .grant_types
                .iter()
                .any(|g| !matches!(g.as_str(), "authorization_code" | "refresh_token"))
            || !raw.redirect_uris.iter().any(|uri| uri == redirect_uri)
        {
            return Err(AuthError::InvalidConfig);
        }
        if !valid_scopes(&raw.scopes)
            || !valid_scopes(&raw.required_scopes)
            || !raw.required_scopes.iter().all(|s| raw.scopes.contains(s))
        {
            return Err(AuthError::InvalidConfig);
        }
        let issuer_url = parse_server_url(&raw.issuer)?;
        if issuer_url.query().is_some() {
            return Err(AuthError::InvalidConfig);
        }
        // The AS identity is independent of the regional reverse proxy. Only
        // the address pinned by the application's Console config is trusted;
        // discovery cannot add origins or silently switch back to the issuer.
        let api_base_url = match raw.api_base_url.as_deref() {
            Some(value) => {
                let url = parse_server_url(value)?;
                if url.path() != "/" {
                    return Err(AuthError::InvalidConfig);
                }
                url
            }
            None => issuer_url,
        };
        if api_base_url.query().is_some() {
            return Err(AuthError::InvalidConfig);
        }
        let token_url = parse_server_url(&raw.token_url)?;
        if token_url.origin() != api_base_url.origin() || token_url.query().is_some() {
            return Err(AuthError::InvalidConfig);
        }
        let redirect_url = Url::parse(redirect_uri).map_err(|_| AuthError::InvalidConfig)?;
        if !redirect_url.username().is_empty()
            || redirect_url.password().is_some()
            || redirect_url.fragment().is_some()
        {
            return Err(AuthError::InvalidConfig);
        }
        match redirect_url.scheme() {
            "https" | "http" => {
                parse_server_url(redirect_uri)?;
            }
            scheme => {
                // Reverse-domain private-use schemes only, as required by Console.
                if !scheme.contains('.') || redirect_url.cannot_be_a_base() {
                    return Err(AuthError::InvalidConfig);
                }
            }
        }
        let mut fixed_params = HashSet::new();
        for (name, _) in redirect_url.query_pairs() {
            if RESPONSE_PARAMETERS.contains(&name.as_ref())
                || !fixed_params.insert(name.into_owned())
            {
                return Err(AuthError::InvalidConfig);
            }
        }
        Ok(Self {
            client_id: raw.client_id,
            issuer: raw.issuer,
            api_base_url,
            token_url: raw.token_url,
            redirect_uri: redirect_uri.to_owned(),
            redirect_url,
            scopes: raw.scopes,
            required_scopes: raw.required_scopes,
        })
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    pub(crate) fn requested_scopes(
        &self,
        mut scopes: Vec<String>,
    ) -> Result<Vec<String>, AuthError> {
        if !valid_scopes(&scopes) || !scopes.iter().all(|scope| self.scopes.contains(scope)) {
            return Err(AuthError::InvalidScopes);
        }
        scopes.sort();
        Ok(scopes)
    }

    pub(crate) fn endpoint(&self, value: &str) -> Result<Url, AuthError> {
        let url = parse_server_url(value).map_err(|_| AuthError::InvalidDiscovery)?;
        if url.origin() != self.api_base_url.origin() || url.query().is_some() {
            return Err(AuthError::InvalidDiscovery);
        }
        Ok(url)
    }

    pub(crate) fn authorization_endpoint(&self, value: &str) -> Result<Url, AuthError> {
        // Only this exact cross-origin URL may open Link.
        // Credentials and JWKS remain bound to the configured regional API.
        if value == SHARED_AUTHORIZATION_ENDPOINT {
            return Url::parse(value).map_err(|_| AuthError::InvalidDiscovery);
        }
        // API-local test deployments use the same unversioned route.
        let url = self.endpoint(value)?;
        if url.path() != "/oauth/authorize" {
            return Err(AuthError::InvalidDiscovery);
        }
        Ok(url)
    }

    pub(crate) fn discovery_url(&self) -> String {
        format!(
            "{}/.well-known/openid-configuration",
            self.api_base_url.as_str().trim_end_matches('/')
        )
    }
}

pub(crate) fn valid_scopes(scopes: &[String]) -> bool {
    scopes.iter().any(|s| s == "openid")
        && scopes.len() <= 4
        && scopes.iter().all(|s| {
            matches!(
                s.as_str(),
                "openid" | "profile" | "offline_access" | "phone"
            )
        })
        && scopes.iter().collect::<HashSet<_>>().len() == scopes.len()
}

fn parse_server_url(value: &str) -> Result<Url, AuthError> {
    if value.len() > 2048 || value.bytes().any(|b| b.is_ascii_control() || b == b' ') {
        return Err(AuthError::InvalidConfig);
    }
    let url = Url::parse(value).map_err(|_| AuthError::InvalidConfig)?;
    let loopback = match url.host() {
        Some(url::Host::Domain(host)) => host == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    if url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
    {
        return Err(AuthError::InvalidConfig);
    }
    Ok(url)
}
