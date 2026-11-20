#![allow(clippy::unwrap_used)]

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use futures::{channel::oneshot, executor::block_on};
use link_auth_core::{
    AuthClient, AuthError, ClientConfig, Clock, HttpClient, HttpRequest, HttpResponse,
    SignInResult, TransportError,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha512};
use url::Url;

const ISSUER: &str = "https://login.example.test";
const REGIONAL_API: &str = "https://fr.example.test";
const AUTHORIZE: &str = "https://linkm.me/oauth/authorize";
const CLIENT_ID: &str = "lk_client_sdk_test";
const REDIRECT: &str = "com.example.app://oauth/callback?tenant=qa";
const NOW: u64 = 1_790_000_000;

#[path = "support/sessions.rs"]
mod sessions;

fn config_json() -> Value {
    json!({"type":"link_oauth_client_config", "app_id":"f2d6be62-99c0-4a22-9114-000000000001",
        "platform":"ios", "client_id":CLIENT_ID, "issuer":ISSUER, "token_url":format!("{ISSUER}/oauth/v1/token"),
        "redirect_uris":[REDIRECT], "scopes":["openid","profile","offline_access"],
        "required_scopes":["openid"], "scope_mode":"inherit",
        "grant_types":["authorization_code","refresh_token"], "pkce_method":"S256", "bundle_id":"com.example.app"})
}

fn regional_config_json() -> Value {
    let mut config = config_json();
    config["api_base_url"] = json!(REGIONAL_API);
    config["token_url"] = json!(format!("{REGIONAL_API}/oauth/v1/token"));
    config
}

fn regional_discovery(server: &Server) {
    let mut state = server.state.lock().unwrap();
    for (field, path) in [
        ("token_endpoint", "token"),
        ("jwks_uri", "jwks.json"),
        ("revocation_endpoint", "revoke"),
    ] {
        state.discovery.insert(
            field.into(),
            json!(format!("{REGIONAL_API}/oauth/v1/{path}")),
        );
    }
}

struct TestClock(AtomicU64);
impl Clock for TestClock {
    fn unix_time_seconds(&self) -> Result<u64, AuthError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

#[derive(Default)]
struct ServerState {
    now: u64,
    refresh_count: u64,
    fail_discovery: bool,
    fail_revoke: bool,
    nonce: String,
    requests: Vec<HttpRequest>,
    discovery: HashMap<String, Value>,
    claims: HashMap<String, Value>,
    header: HashMap<String, Value>,
    token: HashMap<String, Value>,
    duplicate_key: bool,
    wrong_key: bool,
    private_key: bool,
    fail_token: bool,
    token_status: Option<u16>,
    userinfo: Option<Value>,
    userinfo_status: Option<u16>,
    userinfo_gate: Option<oneshot::Receiver<()>>,
    redirect_response: bool,
    oversized_response: bool,
    gate: Option<oneshot::Receiver<()>>,
}

struct Server {
    state: Mutex<ServerState>,
}

fn override_fields(value: &mut Value, fields: &HashMap<String, Value>) {
    for (key, field) in fields {
        if field.is_null() {
            value.as_object_mut().unwrap().remove(key);
        } else {
            value[key] = field.clone();
        }
    }
}

fn discovery() -> Value {
    json!({"issuer":ISSUER, "authorization_endpoint":AUTHORIZE,
        "token_endpoint":format!("{ISSUER}/oauth/v1/token"), "jwks_uri":format!("{ISSUER}/oauth/v1/jwks.json"),
        "revocation_endpoint":format!("{ISSUER}/oauth/v1/revoke"),
        "response_types_supported":["code"], "grant_types_supported":["authorization_code","refresh_token"],
        "id_token_signing_alg_values_supported":["EdDSA"], "token_endpoint_auth_methods_supported":["none"],
        "code_challenge_methods_supported":["S256"], "scopes_supported":["openid","profile","offline_access"],
        "authorization_response_iss_parameter_supported":true})
}

fn jwk(seed: u8) -> Value {
    json!({"kty":"OKP", "crv":"Ed25519", "alg":"EdDSA", "use":"sig", "kid":"sdk-test-key",
        "x":URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[seed; 32]).verifying_key().as_bytes())})
}

fn signed_token(state: &ServerState, refreshing: bool) -> String {
    let mut header = json!({"alg":"EdDSA", "typ":"JWT", "kid":"sdk-test-key"});
    override_fields(&mut header, &state.header);
    let now = if state.now == 0 { NOW } else { state.now };
    let mut claims = json!({"iss":ISSUER, "aud":[CLIENT_ID], "azp":CLIENT_ID, "sub":"opaque-project-test-sub",
        "iat":now, "exp":now + 3600, "nonce":state.nonce,
        "name":"Test User", "preferred_username":"test_user", "picture":"https://images.example.test/avatar.jpg"});
    if refreshing {
        claims.as_object_mut().unwrap().remove("nonce");
    }
    override_fields(&mut claims, &state.claims);
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    let signature = SigningKey::from_bytes(&[7; 32]).sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

#[async_trait]
impl HttpClient for Server {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        let url = request.url.clone();
        let is_token = request.url.ends_with("/token");
        let refreshing = is_token
            && url::form_urlencoded::parse(&request.body)
                .any(|(k, v)| k == "grant_type" && v == "refresh_token");
        let gate = {
            let mut state = self.state.lock().unwrap();
            state.requests.push(request);
            if is_token {
                state.gate.take()
            } else if url.ends_with("/userinfo") {
                state.userinfo_gate.take()
            } else {
                None
            }
        };
        if let Some(gate) = gate {
            gate.await.map_err(|_| TransportError)?;
        }
        let mut state = self.state.lock().unwrap();
        let mut status = 200;
        let body = if url.ends_with("openid-configuration") {
            if state.fail_discovery {
                return Err(TransportError);
            }
            let mut doc = discovery();
            override_fields(&mut doc, &state.discovery);
            doc
        } else if is_token {
            if state.fail_token {
                return Err(TransportError);
            }
            if refreshing {
                state.refresh_count += 1;
            }
            let refresh_token = if refreshing {
                format!("rotated-refresh-{}", state.refresh_count)
            } else {
                "refresh-secret".into()
            };
            let mut token = json!({"access_token":"access-secret", "id_token":signed_token(&state, refreshing),
                "refresh_token":refresh_token, "token_type":"Bearer", "expires_in":3600,
                "scope":"openid profile offline_access"});
            if let Some(code) = state.token_status {
                status = code;
                token = json!({"error":"invalid_grant", "error_description":"DO-NOT-LEAK-CODE-OR-TOKEN"});
            }
            override_fields(&mut token, &state.token);
            token
        } else if url.ends_with("/userinfo") {
            status = state.userinfo_status.unwrap_or(200);
            state.userinfo.clone().unwrap_or_else(|| json!({
                "sub": "opaque-project-test-sub", "name": "Current Name",
                "preferred_username": "current_user", "picture": "https://images.example.test/current.jpg",
                "phone_number": "+12025550123"
            }))
        } else if url.ends_with("/revoke") {
            if state.fail_revoke {
                return Err(TransportError);
            }
            Value::Null
        } else if url.ends_with("jwks.json") {
            let mut key = jwk(if state.wrong_key { 8 } else { 7 });
            if state.private_key {
                key["d"] = json!("private-material");
            }
            if state.duplicate_key {
                json!({"keys":[key.clone(),key]})
            } else {
                json!({"keys":[key]})
            }
        } else {
            panic!("unexpected HTTP endpoint")
        };
        Ok(HttpResponse {
            status,
            url: if state.redirect_response {
                "https://other.example.test".into()
            } else {
                url.clone()
            },
            content_type: if url.ends_with("/revoke") {
                "".into()
            } else {
                "application/json; charset=utf-8".into()
            },
            body: if url.ends_with("/revoke") {
                vec![]
            } else if state.oversized_response {
                vec![b'x'; 256 * 1024 + 1]
            } else {
                serde_json::to_vec(&body).unwrap()
            },
        })
    }
}

fn fixture_with_config(config: Value) -> (AuthClient, Arc<Server>, Arc<TestClock>) {
    let server = Arc::new(Server {
        state: Mutex::new(ServerState::default()),
    });
    let clock = Arc::new(TestClock(AtomicU64::new(NOW)));
    let config = ClientConfig::from_console_json(&config.to_string(), REDIRECT).unwrap();
    (
        AuthClient::with_clock(config, server.clone(), clock.clone()),
        server,
        clock,
    )
}

fn fixture() -> (AuthClient, Arc<Server>, Arc<TestClock>) {
    fixture_with_config(config_json())
}

async fn begin(client: &AuthClient, server: &Server) -> (HashMap<String, String>, String) {
    let authorization = client
        .begin_sign_in(vec![
            "openid".into(),
            "profile".into(),
            "offline_access".into(),
        ])
        .await
        .unwrap();
    let url = Url::parse(&authorization.authorization_url).unwrap();
    assert_eq!(&url[..url::Position::AfterPath], AUTHORIZE);
    let query: HashMap<String, String> = url.query_pairs().into_owned().collect();
    server.state.lock().unwrap().nonce = query["nonce"].clone();
    let mut callback = Url::parse(REDIRECT).unwrap();
    callback
        .query_pairs_mut()
        .append_pair("code", "single-use-code")
        .append_pair("state", &query["state"])
        .append_pair("iss", ISSUER);
    (query, callback.into())
}

async fn complete(client: &AuthClient, server: &Server) -> Result<SignInResult, AuthError> {
    let (_, callback) = begin(client, server).await;
    client.complete_sign_in(&callback).await
}

#[test]
fn successful_login_uses_real_signature_and_actual_grants() {
    block_on(async {
        let (client, server, _) = fixture();
        let (params, callback) = begin(&client, &server).await;
        assert_eq!(params["client_id"], CLIENT_ID);
        assert_eq!(params["redirect_uri"], REDIRECT);
        assert_eq!(params["response_type"], "code");
        assert_eq!(params["code_challenge_method"], "S256");
        assert_eq!(params["nonce"].len(), 43);
        assert_eq!(params["state"].len(), 43);
        let result = client.complete_sign_in(&callback).await.unwrap();
        assert_eq!(result.user.subject, "opaque-project-test-sub");
        assert_eq!(result.user.name.as_deref(), Some("Test User"));
        assert_eq!(
            result.refresh_token.as_ref().unwrap().expose_secret(),
            "refresh-secret"
        );
        assert_eq!(result.expires_at, NOW + 3600);
        let state = server.state.lock().unwrap();
        assert_eq!(state.requests.len(), 3);
        assert!(state
            .requests
            .iter()
            .all(|r| r.url.starts_with(&format!("{ISSUER}/"))));
        let request = &state.requests[1];
        let form: HashMap<String, String> = url::form_urlencoded::parse(&request.body)
            .into_owned()
            .collect();
        assert_eq!(form["grant_type"], "authorization_code");
        assert_eq!(form["redirect_uri"], REDIRECT);
        assert!(!form.contains_key("client_secret"));
        assert_eq!(
            URL_SAFE_NO_PAD.encode(Sha256::digest(form["code_verifier"].as_bytes())),
            params["code_challenge"]
        );
        assert!(!format!("{result:?}").contains("refresh-secret"));
        assert!(!format!("{result:?}").contains("access-secret"));
        assert!(!format!("{request:?}").contains(&form["code_verifier"]));
    });
}

#[test]
fn optional_scope_refusal_succeeds_and_filters_profile() {
    block_on(async {
        let (client, server, _) = fixture();
        {
            let mut state = server.state.lock().unwrap();
            state.token.insert("scope".into(), json!("openid"));
            state.token.insert("refresh_token".into(), Value::Null);
        }
        let result = complete(&client, &server).await.unwrap();
        assert_eq!(result.user.granted_scopes, ["openid"]);
        assert!(result.refresh_token.is_none());
        assert!(result.user.name.is_none());
        assert!(result.user.preferred_username.is_none());
        assert!(result.user.picture.is_none());
    });
}

#[test]
fn validates_optional_access_token_hash_for_ed25519() {
    block_on(async {
        let (client, server, _) = fixture();
        let hash = Sha512::digest(b"access-secret");
        server
            .state
            .lock()
            .unwrap()
            .claims
            .insert("at_hash".into(), json!(URL_SAFE_NO_PAD.encode(&hash[..32])));
        complete(&client, &server).await.unwrap();
    });
}

#[test]
fn malicious_callbacks_do_not_consume_the_real_attempt() {
    block_on(async {
        let (client, server, _) = fixture();
        let (_, callback) = begin(&client, &server).await;
        for (bad, expected) in [
            (
                callback.replace("oauth/callback", "oauth/other"),
                AuthError::InvalidCallback,
            ),
            (
                callback.replace("tenant=qa", "tenant=other"),
                AuthError::InvalidCallback,
            ),
            (
                format!("{callback}&state=extra"),
                AuthError::InvalidCallback,
            ),
            (
                format!("{callback}&error=access_denied"),
                AuthError::InvalidCallback,
            ),
            (format!("{callback}#fragment"), AuthError::InvalidCallback),
            (
                callback.replace("state=", "state=wrong"),
                AuthError::StateMismatch,
            ),
            (
                callback.replace("iss=", "iss=wrong"),
                AuthError::IssuerMismatch,
            ),
        ] {
            assert_eq!(client.complete_sign_in(&bad).await.unwrap_err(), expected);
        }
        assert_eq!(server.state.lock().unwrap().requests.len(), 1);
        client.complete_sign_in(&callback).await.unwrap();
        assert_eq!(
            client.complete_sign_in(&callback).await.unwrap_err(),
            AuthError::NoPendingLogin
        );
    });
}

#[test]
fn denial_is_validated_and_consumed_without_token_request() {
    block_on(async {
        let (client, server, _) = fixture();
        let (_, callback) = begin(&client, &server).await;
        let denied = callback.replace("code=single-use-code", "error=access_denied");
        assert_eq!(
            client.complete_sign_in(&denied).await.unwrap_err(),
            AuthError::AuthorizationDenied
        );
        assert_eq!(
            client.complete_sign_in(&callback).await.unwrap_err(),
            AuthError::NoPendingLogin
        );
        assert_eq!(server.state.lock().unwrap().requests.len(), 1);
    });
}

#[test]
fn expires_and_generates_new_random_state() {
    block_on(async {
        let (client, server, clock) = fixture();
        let (old, callback) = begin(&client, &server).await;
        clock.0.store(NOW + 600, Ordering::SeqCst);
        assert_eq!(
            client.complete_sign_in(&callback).await.unwrap_err(),
            AuthError::Expired
        );
        let (new, _) = begin(&client, &server).await;
        for key in ["state", "nonce", "code_challenge"] {
            assert_ne!(old[key], new[key]);
        }
    });
}

#[test]
fn validates_signed_identity_claims_and_header() {
    block_on(async {
        for (field, value) in [
            ("iss", json!("https://another.example.test")),
            ("aud", json!(["other-client"])),
            ("aud", json!([CLIENT_ID, "another-client"])),
            ("azp", json!("other-client")),
            ("nonce", json!("wrong-nonce")),
            ("nonce", Value::Null),
            ("sub", json!("")),
            ("iat", json!(NOW + 31)),
            ("iat", Value::Null),
            ("exp", json!(NOW)),
            ("exp", Value::Null),
            ("exp", json!(NOW - 1)),
            ("at_hash", json!("invalid-hash")),
        ] {
            let (client, server, _) = fixture();
            server
                .state
                .lock()
                .unwrap()
                .claims
                .insert(field.into(), value);
            assert_eq!(
                complete(&client, &server).await.unwrap_err(),
                AuthError::InvalidIdToken,
                "claim {field}"
            );
        }
        for (field, value) in [
            ("alg", json!("none")),
            ("alg", json!("HS256")),
            ("jku", json!("https://attacker.example.test/jwks")),
            ("crit", json!(["b64"])),
            ("kid", Value::Null),
        ] {
            let (client, server, _) = fixture();
            server
                .state
                .lock()
                .unwrap()
                .header
                .insert(field.into(), value);
            assert_eq!(
                complete(&client, &server).await.unwrap_err(),
                AuthError::InvalidIdToken,
                "header {field}"
            );
        }
    });
}

#[test]
fn rejects_wrong_signature_and_ambiguous_or_private_keys() {
    block_on(async {
        for mode in 0..4 {
            let (client, server, _) = fixture();
            {
                let mut state = server.state.lock().unwrap();
                match mode {
                    0 => state.wrong_key = true,
                    1 => state.duplicate_key = true,
                    2 => state.private_key = true,
                    _ => {
                        state.header.insert("kid".into(), json!("unknown"));
                    }
                }
            }
            assert_eq!(
                complete(&client, &server).await.unwrap_err(),
                if mode == 0 {
                    AuthError::InvalidIdToken
                } else {
                    AuthError::InvalidSigningKey
                }
            );
        }
    });
}

#[test]
fn scopes_refresh_and_required_fields_cannot_be_invented() {
    block_on(async {
        for (field, value) in [
            ("scope", json!("openid phone")),
            ("scope", json!("profile")),
            ("scope", json!("openid openid")),
            ("refresh_token", Value::Null),
            ("id_token", Value::Null),
            ("access_token", json!("")),
            ("expires_in", json!(0)),
            ("token_type", json!("MAC")),
        ] {
            let (client, server, _) = fixture();
            server
                .state
                .lock()
                .unwrap()
                .token
                .insert(field.into(), value);
            assert_eq!(
                complete(&client, &server).await.unwrap_err(),
                AuthError::InvalidTokenResponse,
                "field {field}"
            );
        }
        let mut config = config_json();
        config["required_scopes"] = json!(["openid", "profile"]);
        let (client, server, _) = fixture_with_config(config);
        server
            .state
            .lock()
            .unwrap()
            .token
            .insert("scope".into(), json!("openid offline_access"));
        assert_eq!(
            complete(&client, &server).await.unwrap_err(),
            AuthError::InvalidTokenResponse
        );
    });
}

#[test]
fn discovery_does_not_send_secrets_to_another_origin() {
    block_on(async {
        for (field, value) in [
            ("issuer", json!("https://evil.example.test")),
            ("token_endpoint", json!("https://evil.example.test/token")),
            ("jwks_uri", json!("https://evil.example.test/jwks")),
            (
                "revocation_endpoint",
                json!("https://evil.example.test/revoke"),
            ),
            ("token_endpoint", json!("https://linkm.me/oauth/v1/token")),
            ("jwks_uri", json!("https://linkm.me/oauth/v1/jwks.json")),
            (
                "revocation_endpoint",
                json!("https://linkm.me/oauth/v1/revoke"),
            ),
            (
                "authorization_endpoint",
                json!("https://evil.example.test/authorize"),
            ),
            (
                "authorization_response_iss_parameter_supported",
                json!(false),
            ),
            ("code_challenge_methods_supported", json!(["plain"])),
        ] {
            let (client, server, _) = fixture();
            server
                .state
                .lock()
                .unwrap()
                .discovery
                .insert(field.into(), value);
            assert_eq!(
                client
                    .begin_sign_in(vec!["openid".into()])
                    .await
                    .unwrap_err(),
                AuthError::InvalidDiscovery
            );
            assert_eq!(server.state.lock().unwrap().requests.len(), 1);
        }
    });
}

#[test]
fn regional_login_uses_only_configured_api_and_verifies_shared_issuer() {
    block_on(async {
        let (client, server, _) = fixture_with_config(regional_config_json());
        regional_discovery(&server);
        let (_, callback) = begin(&client, &server).await;
        let encoded_issuer = |value: &str| {
            url::form_urlencoded::Serializer::new(String::new())
                .append_pair("iss", value)
                .finish()
        };
        let wrong_issuer = callback.replace(&encoded_issuer(ISSUER), &encoded_issuer(REGIONAL_API));
        assert_eq!(
            client.complete_sign_in(&wrong_issuer).await.unwrap_err(),
            AuthError::IssuerMismatch
        );
        assert_eq!(server.state.lock().unwrap().requests.len(), 1);
        let result = client.complete_sign_in(&callback).await.unwrap();
        assert_eq!(result.user.issuer, ISSUER);
        {
            let state = server.state.lock().unwrap();
            let urls: Vec<_> = state.requests.iter().map(|r| r.url.clone()).collect();
            assert_eq!(
                urls,
                vec![
                    format!("{REGIONAL_API}/.well-known/openid-configuration"),
                    format!("{REGIONAL_API}/oauth/v1/token"),
                    format!("{REGIONAL_API}/oauth/v1/jwks.json"),
                ]
            );
        }

        let (client, server, _) = fixture_with_config(regional_config_json());
        regional_discovery(&server);
        server
            .state
            .lock()
            .unwrap()
            .claims
            .insert("iss".into(), json!(REGIONAL_API));
        assert_eq!(
            complete(&client, &server).await.unwrap_err(),
            AuthError::InvalidIdToken
        );
    });
}

#[test]
fn regional_discovery_cannot_switch_http_origin_even_to_issuer() {
    block_on(async {
        for (field, value) in [
            ("issuer", json!(REGIONAL_API)),
            ("token_endpoint", json!(format!("{ISSUER}/oauth/v1/token"))),
            ("jwks_uri", json!(format!("{ISSUER}/oauth/v1/jwks.json"))),
            (
                "revocation_endpoint",
                json!(format!("{ISSUER}/oauth/v1/revoke")),
            ),
            (
                "token_endpoint",
                json!(format!("{REGIONAL_API}/other/token")),
            ),
            ("token_endpoint", json!("https://evil.example.test/token")),
            (
                "jwks_uri",
                json!("https://fr.example.test.evil.example/jwks"),
            ),
            ("jwks_uri", json!("https://fr.example.test:8443/jwks")),
            ("jwks_uri", json!("https://user@fr.example.test/jwks")),
            ("jwks_uri", json!("https://fr.example.test/jwks#ignored")),
            (
                "revocation_endpoint",
                json!("https://linkm.me/oauth/v1/revoke"),
            ),
        ] {
            let (client, server, _) = fixture_with_config(regional_config_json());
            regional_discovery(&server);
            server
                .state
                .lock()
                .unwrap()
                .discovery
                .insert(field.into(), value);
            assert_eq!(
                client
                    .begin_sign_in(vec!["openid".into()])
                    .await
                    .unwrap_err(),
                AuthError::InvalidDiscovery,
                "{field}"
            );
            assert_eq!(server.state.lock().unwrap().requests.len(), 1);
        }
    });
}

#[test]
fn regional_api_must_be_explicit_and_secure_in_console_config() {
    let mut config = regional_config_json();
    config.as_object_mut().unwrap().remove("api_base_url");
    assert!(matches!(
        ClientConfig::from_console_json(&config.to_string(), REDIRECT),
        Err(AuthError::InvalidConfig)
    ));
    for api in [
        "http://fr.example.test",
        "https://user:pass@fr.example.test",
        "https://fr.example.test/tenant",
        "https://fr.example.test?",
        "https://fr.example.test#fragment",
        "https://another.example.test",
        "https://fr.example.test:8443",
    ] {
        let mut config = regional_config_json();
        config["api_base_url"] = json!(api);
        assert!(
            matches!(
                ClientConfig::from_console_json(&config.to_string(), REDIRECT),
                Err(AuthError::InvalidConfig)
            ),
            "{api}"
        );
    }
    let mut config = regional_config_json();
    config["token_url"] = json!(format!("{ISSUER}/oauth/v1/token"));
    assert!(matches!(
        ClientConfig::from_console_json(&config.to_string(), REDIRECT),
        Err(AuthError::InvalidConfig)
    ));
    // Explicit loopback ingress remains available for local test fixtures only.
    config["api_base_url"] = json!("http://127.0.0.1:8765");
    config["token_url"] = json!("http://127.0.0.1:8765/oauth/v1/token");
    assert!(ClientConfig::from_console_json(&config.to_string(), REDIRECT).is_ok());
    config["token_url"] = json!("http://api.example.test/oauth/v1/token");
    assert!(ClientConfig::from_console_json(&config.to_string(), REDIRECT).is_err());
}

#[test]
fn shared_authorization_allows_only_the_exact_trusted_url() {
    block_on(async {
        let path = "/oauth/authorize";
        for endpoint in [
            format!("http://linkm.me{path}"),
            format!("https://linkm.me:443{path}"),
            format!("https://linkm.me:8443{path}"),
            format!("https://user@linkm.me{path}"),
            format!("https://linkm.me@evil.example.test{path}"),
            format!("https://linkm.me.evil.example.test{path}"),
            format!("https://auth.linkm.me{path}"),
            format!("https://linkm.me{path}/"),
            format!("https://linkm.me{path}?"),
            format!("https://linkm.me{path}?redirect_uri=https://evil.example.test"),
            format!("https://linkm.me{path}#fragment"),
            format!("https://linkm.me{path}/../authorize"),
            format!("https://linkm.me{path}/%2e%2e/authorize"),
            "https://linkm.me/oauth/v1/token".into(),
            "https://linkm.me/oauth/v2/authorize".into(),
        ] {
            let (client, server, _) = fixture();
            server
                .state
                .lock()
                .unwrap()
                .discovery
                .insert("authorization_endpoint".into(), json!(endpoint));
            assert_eq!(
                client
                    .begin_sign_in(vec!["openid".into()])
                    .await
                    .unwrap_err(),
                AuthError::InvalidDiscovery,
                "{endpoint}",
            );
            assert_eq!(server.state.lock().unwrap().requests.len(), 1);
        }
    });
}

#[test]
fn versioned_authorization_endpoints_are_rejected() {
    block_on(async {
        for endpoint in [
            "https://linkm.me/oauth/v1/authorize".to_owned(),
            format!("{ISSUER}/oauth/v1/authorize"),
        ] {
            let (client, server, _) = fixture();
            server
                .state
                .lock()
                .unwrap()
                .discovery
                .insert("authorization_endpoint".into(), json!(endpoint));
            assert_eq!(
                client
                    .begin_sign_in(vec!["openid".into()])
                    .await
                    .unwrap_err(),
                AuthError::InvalidDiscovery,
                "{endpoint}",
            );
            assert_eq!(server.state.lock().unwrap().requests.len(), 1);
        }
    });
}

#[test]
fn public_config_rejects_credentials_bad_urls_and_capabilities() {
    for (field, value) in [
        ("private_key", json!("secret")),
        ("private_key", Value::Null),
        ("client_secret", json!("secret")),
        ("type", json!("link_oauth_client")),
        ("issuer", json!("http://remote.example.test")),
        ("issuer", json!("https://user:pass@login.example.test")),
        ("pkce_method", json!("plain")),
        ("scopes", json!(["openid", "otp"])),
        ("required_scopes", json!(["profile"])),
        (
            "grant_types",
            json!(["authorization_code", "client_credentials"]),
        ),
    ] {
        let mut config = config_json();
        config[field] = value;
        assert!(
            matches!(
                ClientConfig::from_console_json(&config.to_string(), REDIRECT),
                Err(AuthError::InvalidConfig)
            ),
            "{field}"
        );
    }
    assert!(ClientConfig::from_console_json(
        &config_json().to_string(),
        "com.other.app://callback"
    )
    .is_err());
    let mut config = config_json();
    config["issuer"] = json!("http://127.0.0.1:8765");
    config["token_url"] = json!("http://127.0.0.1:8765/oauth/v1/token");
    assert!(ClientConfig::from_console_json(&config.to_string(), REDIRECT).is_ok());
    config["token_url"] = json!("http://api.example.test/oauth/v1/token");
    assert!(ClientConfig::from_console_json(&config.to_string(), REDIRECT).is_err());
}

#[test]
fn token_network_failure_is_never_retried_and_requires_new_login() {
    block_on(async {
        let (client, server, _) = fixture();
        let (_, callback) = begin(&client, &server).await;
        server.state.lock().unwrap().fail_token = true;
        assert_eq!(
            client.complete_sign_in(&callback).await.unwrap_err(),
            AuthError::Transport
        );
        assert_eq!(
            client.complete_sign_in(&callback).await.unwrap_err(),
            AuthError::NoPendingLogin
        );
        assert_eq!(server.state.lock().unwrap().requests.len(), 2);
    });
}

#[test]
fn http_errors_are_sanitized_and_redirects_and_large_bodies_rejected() {
    block_on(async {
        let (client, server, _) = fixture();
        server.state.lock().unwrap().token_status = Some(400);
        let error = complete(&client, &server).await.unwrap_err();
        assert!(!format!("{error:?} {error}").contains("DO-NOT-LEAK"));
        assert!(matches!(error, AuthError::OAuth { .. }));
        for oversized in [false, true] {
            let (client, server, _) = fixture();
            {
                let mut state = server.state.lock().unwrap();
                state.redirect_response = !oversized;
                state.oversized_response = oversized;
            }
            assert_eq!(
                client
                    .begin_sign_in(vec!["openid".into()])
                    .await
                    .unwrap_err(),
                AuthError::InvalidResponse
            );
        }
    });
}

#[test]
fn cancellation_and_duplicate_completion_cannot_produce_a_late_success() {
    block_on(async {
        let (client, server, _) = fixture();
        let (_, callback) = begin(&client, &server).await;
        let (release, wait) = oneshot::channel();
        server.state.lock().unwrap().gate = Some(wait);
        let mut first = Box::pin(client.complete_sign_in(&callback));
        assert!(futures::poll!(&mut first).is_pending());
        assert_eq!(
            client.complete_sign_in(&callback).await.unwrap_err(),
            AuthError::AlreadyInProgress
        );
        client.cancel_sign_in().unwrap();
        let (_, next_callback) = begin(&client, &server).await;
        release.send(()).unwrap();
        assert_eq!(first.await.unwrap_err(), AuthError::Cancelled);
        client.complete_sign_in(&next_callback).await.unwrap();
    });
}

#[test]
fn dropping_an_exchange_future_releases_the_operation() {
    block_on(async {
        let (client, server, _) = fixture();
        let (_, callback) = begin(&client, &server).await;
        let (_release, wait) = oneshot::channel();
        server.state.lock().unwrap().gate = Some(wait);
        let mut first = Box::pin(client.complete_sign_in(&callback));
        assert!(futures::poll!(&mut first).is_pending());
        drop(first);
        assert_eq!(
            client.complete_sign_in(&callback).await.unwrap_err(),
            AuthError::NoPendingLogin
        );
        let _ = begin(&client, &server).await;
    });
}

#[test]
fn phone_is_an_optional_supported_scope_but_not_a_capability() {
    let mut config = config_json();
    config["scopes"] = json!(["openid", "profile", "offline_access", "phone"]);
    assert!(ClientConfig::from_console_json(&config.to_string(), REDIRECT).is_ok());
    config["required_scopes"] = json!(["openid", "phone"]);
    assert!(ClientConfig::from_console_json(&config.to_string(), REDIRECT).is_ok());
    config["scopes"] = json!(["openid", "contacts.read"]);
    assert!(ClientConfig::from_console_json(&config.to_string(), REDIRECT).is_err());
}
