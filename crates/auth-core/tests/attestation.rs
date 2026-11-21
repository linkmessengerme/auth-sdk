//! Device attestation against an in-memory server that follows the server side
//! of the contract: modes, key registration, proofs checked before anything is
//! spent, sessions bound to keys and the retry of a refresh whose answer was lost.
#![allow(clippy::unwrap_used)]

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::Signer as _;
use futures::{channel::oneshot, executor::block_on};
use link_auth_core::{
    AttestedKey, AttestorError, AuthClient, AuthError, ClientConfig, Clock, DeviceAttestor,
    HttpClient, HttpRequest, HttpResponse, KeyAttestation, LogoutStatus, OAuthError, SecureStore,
    SessionClient, SessionStatus, SignInResult, StorageError, StoredEntry, TransportError,
};
use p256::ecdsa::{signature::Verifier as _, Signature, SigningKey, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use url::Url;

const ISSUER: &str = "https://login.example.test";
const CLIENT_ID: &str = "lk_client_sdk_test";
const REDIRECT: &str = "com.example.app://oauth/callback";
const NOW: u64 = 1_790_000_000;

fn config() -> ClientConfig {
    let json = json!({"type":"link_oauth_client_config", "app_id":"f2d6be62-99c0-4a22-9114-000000000001",
        "platform":"android", "client_id":CLIENT_ID, "issuer":ISSUER, "token_url":format!("{ISSUER}/oauth/v1/token"),
        "redirect_uris":[REDIRECT], "scopes":["openid","profile","offline_access"],
        "required_scopes":["openid"], "scope_mode":"inherit",
        "grant_types":["authorization_code","refresh_token"], "pkce_method":"S256"});
    ClientConfig::from_console_json(&json.to_string(), REDIRECT).unwrap()
}

struct TestClock(AtomicU64);
impl Clock for TestClock {
    fn unix_time_seconds(&self) -> Result<u64, AuthError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

// ---- platform key --------------------------------------------------------

/// A software stand-in for the platform adapters: P-256, SHA256withECDSA, DER —
/// what the Android adapter produces. The "certificate chain" is the public
/// key followed by the challenge, which is all the test server needs.
#[derive(Default)]
struct SoftAttestor {
    keys: Mutex<HashMap<String, SigningKey>>,
    created: AtomicU64,
    deleted: Mutex<Vec<String>>,
    unsupported: AtomicBool,
    fail_create: AtomicBool,
    fail_sign: Mutex<Option<AttestorError>>,
    wrong_signature: AtomicBool,
    signed: AtomicU64,
}

#[async_trait]
impl DeviceAttestor for SoftAttestor {
    fn is_available(&self) -> bool {
        !self.unsupported.load(Ordering::SeqCst)
    }
    async fn create_key(
        &self,
        name: &str,
        challenge: &[u8],
        timeout_millis: u32,
    ) -> Result<AttestedKey, AttestorError> {
        assert!(name.starts_with("link.attest.v1.") && challenge.len() == 32);
        assert!((250..=10_000).contains(&timeout_millis));
        if self.fail_create.load(Ordering::SeqCst) {
            return Err(AttestorError::Unavailable);
        }
        let number = self.created.fetch_add(1, Ordering::SeqCst) + 1;
        let key = SigningKey::from_slice(&[u8::try_from(number).unwrap(); 32]).unwrap();
        let public = key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let key_ref = format!("{name}.k{number}");
        self.keys.lock().unwrap().insert(key_ref.clone(), key);
        Ok(AttestedKey {
            key_ref,
            attestation: KeyAttestation::Android {
                certificate_chain: vec![public, challenge.to_vec()],
            },
        })
    }
    async fn sign(&self, key_ref: &str, message: &[u8]) -> Result<Vec<u8>, AttestorError> {
        if let Some(error) = *self.fail_sign.lock().unwrap() {
            return Err(error);
        }
        self.signed.fetch_add(1, Ordering::SeqCst);
        let keys = self.keys.lock().unwrap();
        let key = keys.get(key_ref).ok_or(AttestorError::KeyLost)?;
        let signature: Signature = if self.wrong_signature.load(Ordering::SeqCst) {
            key.sign(b"something else")
        } else {
            key.sign(message)
        };
        Ok(signature.to_der().as_bytes().to_vec())
    }
    async fn delete_key(&self, key_ref: &str) {
        self.keys.lock().unwrap().remove(key_ref);
        self.deleted.lock().unwrap().push(key_ref.to_owned());
    }
}

// ---- storage -------------------------------------------------------------

#[derive(Default)]
struct Store {
    entries: Mutex<HashMap<String, (String, String)>>,
}

impl Store {
    fn names(&self) -> Vec<String> {
        let mut names: Vec<_> = self.entries.lock().unwrap().keys().cloned().collect();
        names.sort();
        names
    }
    fn payload(&self, prefix: &str) -> Option<Value> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .find(|(name, _)| name.starts_with(prefix))
            .map(|(_, entry)| serde_json::from_str(&entry.1).unwrap())
    }
}

impl SecureStore for Store {
    fn load(&self, key: &str) -> Result<Option<StoredEntry>, StorageError> {
        Ok(self
            .entries
            .lock()
            .unwrap()
            .get(key)
            .map(|(r, p)| StoredEntry::new(r.clone(), p.clone())))
    }
    fn compare_exchange(
        &self,
        key: &str,
        expected: Option<&str>,
        value: Option<StoredEntry>,
    ) -> Result<bool, StorageError> {
        let mut entries = self.entries.lock().unwrap();
        if entries.get(key).map(|e| e.0.as_str()) != expected {
            return Ok(false);
        }
        match value {
            Some(value) => {
                assert_eq!(value.revision.len(), 43);
                entries.insert(
                    key.into(),
                    (value.revision, value.payload.expose_secret().into()),
                );
            }
            None => {
                entries.remove(key);
            }
        }
        Ok(true)
    }
}

// ---- server --------------------------------------------------------------

enum Step {
    /// The request never arrives.
    Unreachable,
    /// The request is processed and its answer is lost.
    Lose,
    /// A canned answer; the request is not processed.
    Reply(u16, Value),
    /// A gateway page instead of JSON.
    Html(u16),
    /// Hold the request until the test lets it through.
    Wait(oneshot::Receiver<()>),
}

struct KeyRow {
    public: Vec<u8>,
    revoked: bool,
}

struct TokenRow {
    session: usize,
    used: bool,
    revoked: bool,
    attempt: Option<u8>,
    parent: Option<String>,
}

struct SessionRow {
    key_id: Option<String>,
    revoked: bool,
}

struct World {
    mode: &'static str,
    /// `link_attestation` in discovery; `Value::Null` removes it.
    advertised: Value,
    /// What a key's attestation says about the application.
    level: &'static str,
    /// "Required" lets devices without a verified key in.
    allow_unverified: bool,
    now: u64,
    nonce: String,
    log: Vec<(&'static str, HashMap<String, String>)>,
    script: HashMap<&'static str, VecDeque<Step>>,
    challenges: HashSet<String>,
    keys: HashMap<String, KeyRow>,
    codes: HashSet<String>,
    tokens: HashMap<String, TokenRow>,
    sessions: Vec<SessionRow>,
    sequence: u32,
    claims: HashMap<String, Value>,
}

struct Server {
    world: Mutex<World>,
}

fn refusal(reason: &str) -> (u16, Value) {
    match reason {
        "retry_refused" => (
            400,
            json!({"error":"invalid_grant","attestation_error":reason}),
        ),
        "challenge_invalid" | "attestation_invalid" => (
            400,
            json!({"error":"invalid_request","attestation_error":reason}),
        ),
        _ => (
            401,
            json!({"error":"invalid_client","error_description":"DO-NOT-LEAK","attestation_error":reason}),
        ),
    }
}

fn invalid_grant() -> (u16, Value) {
    (400, json!({"error":"invalid_grant"}))
}

/// The proof message, built here independently of the SDK.
fn expected_message(purpose: &str, key_id: &str, secret: &str, attempt: u8) -> Vec<u8> {
    let hash = URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()));
    [
        "link-login-attest-v1",
        purpose,
        CLIENT_ID,
        key_id,
        &hash,
        &attempt.to_string(),
    ]
    .join("\n")
    .into_bytes()
}

impl World {
    fn new(mode: &'static str) -> Self {
        Self {
            mode,
            advertised: json!({"versions":["1"],
                "challenge_endpoint":format!("{ISSUER}/oauth/v1/attest/challenge"),
                "keys_endpoint":format!("{ISSUER}/oauth/v1/attest/keys")}),
            level: "verified",
            allow_unverified: false,
            now: NOW,
            nonce: String::new(),
            log: vec![],
            script: HashMap::new(),
            challenges: HashSet::new(),
            keys: HashMap::new(),
            codes: HashSet::new(),
            tokens: HashMap::new(),
            sessions: vec![],
            sequence: 0,
            claims: HashMap::new(),
        }
    }

    fn next(&mut self) -> u32 {
        self.sequence += 1;
        self.sequence
    }

    /// `Ok(None)`: the request carries no proof. Nothing is spent here.
    fn proof(
        &self,
        form: &HashMap<String, String>,
        purpose: &str,
        secret: &str,
    ) -> Result<Option<(String, u8)>, &'static str> {
        let field = |name: &str| form.get(name).map(String::as_str).unwrap_or_default();
        let (key_id, attempt, proof) = (
            field("attest_key_id"),
            field("attest_attempt"),
            field("attest_proof"),
        );
        if key_id.is_empty() && attempt.is_empty() && proof.is_empty() {
            return Ok(None);
        }
        let number = attempt
            .parse::<u8>()
            .ok()
            .filter(|n| *n <= 8 && n.to_string() == attempt);
        let Some(number) = number.filter(|n| purpose != "code" || *n == 0) else {
            return Err("proof_invalid");
        };
        if key_id.is_empty() || proof.is_empty() {
            return Err("proof_invalid");
        }
        let key = self.keys.get(key_id).ok_or("key_unknown")?;
        if key.revoked {
            return Err("key_revoked");
        }
        let verified = URL_SAFE_NO_PAD
            .decode(proof)
            .ok()
            .and_then(|der| Signature::from_der(&der).ok())
            .zip(VerifyingKey::from_sec1_bytes(&key.public).ok())
            .is_some_and(|(signature, public)| {
                public
                    .verify(
                        &expected_message(purpose, key_id, secret, number),
                        &signature,
                    )
                    .is_ok()
            });
        if !verified {
            return Err("proof_invalid");
        }
        Ok(Some((key_id.to_owned(), number)))
    }

    fn tokens(&mut self, session: usize, parent: Option<String>, with_nonce: bool) -> (u16, Value) {
        let number = self.next();
        let refresh = format!("refresh-{number}");
        self.tokens.insert(
            refresh.clone(),
            TokenRow {
                session,
                used: false,
                revoked: false,
                attempt: None,
                parent,
            },
        );
        let mut claims = json!({"iss":ISSUER, "aud":[CLIENT_ID], "azp":CLIENT_ID, "sub":"attest-sub",
            "iat":self.now, "exp":self.now + 3600, "name":"Attested User"});
        if with_nonce {
            claims["nonce"] = json!(self.nonce);
        }
        if self.mode != "off" {
            claims["device_trust"] = json!(if self.sessions[session].key_id.is_some() {
                self.level
            } else {
                "none"
            });
        }
        for (name, value) in &self.claims {
            if value.is_null() {
                claims.as_object_mut().unwrap().remove(name);
            } else {
                claims[name] = value.clone();
            }
        }
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"JWT","kid":"attest-test"}"#),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
        );
        let signature = ed25519_dalek::SigningKey::from_bytes(&[9; 32]).sign(input.as_bytes());
        (
            200,
            json!({"access_token":format!("access-{number}"),
                "id_token":format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes())),
                "refresh_token":refresh, "token_type":"Bearer", "expires_in":3600,
                "scope":"openid profile offline_access"}),
        )
    }

    fn code(&mut self, form: &HashMap<String, String>) -> (u16, Value) {
        let code = form["code"].clone();
        let mut key_id = None;
        if self.mode != "off" {
            let proof = self.proof(form, "code", &code);
            if self.mode == "report" {
                key_id = proof.ok().flatten().map(|(key_id, _)| key_id);
            } else {
                match proof {
                    Err(reason) => return refusal(reason),
                    Ok(Some((id, _))) if self.level == "verified" => key_id = Some(id),
                    Ok(Some(_)) if self.level == "mismatch" => return refusal("required"),
                    Ok(proof) => {
                        if !self.allow_unverified {
                            return refusal("required");
                        }
                        key_id = proof.map(|(id, _)| id);
                    }
                }
            }
        }
        if !self.codes.insert(code) {
            return invalid_grant();
        }
        self.sessions.push(SessionRow {
            key_id,
            revoked: false,
        });
        self.tokens(self.sessions.len() - 1, None, true)
    }

    fn refresh(&mut self, form: &HashMap<String, String>) -> (u16, Value) {
        let token = form["refresh_token"].clone();
        let Some(row) = self.tokens.get(&token) else {
            return invalid_grant();
        };
        let session = row.session;
        if row.revoked || self.sessions[session].revoked {
            return invalid_grant();
        }
        let bound = self.sessions[session].key_id.clone();
        // (attempt, key to bind the session to)
        let mut proven: Option<(u8, Option<String>)> = None;
        if bound.is_some() || self.mode != "off" {
            let proof = self.proof(form, "refresh", &token);
            match (&bound, proof) {
                (Some(_), Err(reason)) => return refusal(reason),
                (Some(key), Ok(Some((id, attempt)))) if *key == id => {
                    proven = Some((attempt, None));
                }
                (Some(_), Ok(_)) => return refusal("proof_invalid"),
                (None, Ok(Some((id, attempt)))) if self.level != "mismatch" => {
                    proven = Some((attempt, Some(id)));
                }
                (None, _) => (),
            }
        }
        let row = self.tokens.get(&token).unwrap();
        if row.used {
            let Some((attempt, None)) = proven else {
                self.sessions[session].revoked = true;
                return invalid_grant();
            };
            if row.attempt.is_some_and(|accepted| attempt <= accepted) {
                return refusal("retry_refused");
            }
            let successor_used = self
                .tokens
                .values()
                .any(|next| next.parent.as_deref() == Some(token.as_str()) && next.used);
            if successor_used {
                self.sessions[session].revoked = true;
                return invalid_grant();
            }
            for next in self.tokens.values_mut() {
                if next.parent.as_deref() == Some(token.as_str()) {
                    next.revoked = true;
                }
            }
        }
        let row = self.tokens.get_mut(&token).unwrap();
        row.used = true;
        if let Some((attempt, bind)) = proven {
            row.attempt = Some(attempt);
            if bind.is_some() {
                self.sessions[session].key_id = bind;
            }
        }
        self.tokens(session, Some(token), false)
    }

    fn process(&mut self, name: &str, form: &HashMap<String, String>) -> (u16, Value) {
        match name {
            "discovery" => {
                let mut doc = json!({"issuer":ISSUER, "authorization_endpoint":"https://linkm.me/oauth/authorize",
                    "token_endpoint":format!("{ISSUER}/oauth/v1/token"), "jwks_uri":format!("{ISSUER}/oauth/v1/jwks.json"),
                    "revocation_endpoint":format!("{ISSUER}/oauth/v1/revoke"),
                    "response_types_supported":["code"], "grant_types_supported":["authorization_code","refresh_token"],
                    "id_token_signing_alg_values_supported":["EdDSA"], "token_endpoint_auth_methods_supported":["none"],
                    "code_challenge_methods_supported":["S256"], "scopes_supported":["openid","profile","offline_access"],
                    "authorization_response_iss_parameter_supported":true, "a_future_field":{"x":1}});
                if !self.advertised.is_null() {
                    doc["link_attestation"] = self.advertised.clone();
                }
                (200, doc)
            }
            "jwks" => {
                let public = ed25519_dalek::SigningKey::from_bytes(&[9; 32]).verifying_key();
                (
                    200,
                    json!({"keys":[{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig","kid":"attest-test",
                    "x":URL_SAFE_NO_PAD.encode(public.as_bytes())}]}),
                )
            }
            "challenge" => {
                assert_eq!(form["client_id"], CLIENT_ID);
                if self.mode == "off" {
                    return (200, json!({"mode":"off"}));
                }
                let number = self.next();
                let challenge = URL_SAFE_NO_PAD.encode([u8::try_from(number).unwrap(); 32]);
                self.challenges.insert(challenge.clone());
                (
                    200,
                    json!({"mode":self.mode,"challenge":challenge,"expires_in":300}),
                )
            }
            "keys" => {
                assert_eq!(form["client_id"], CLIENT_ID);
                assert_eq!(form["platform"], "android");
                if !self.challenges.remove(&form["challenge"]) {
                    return refusal("challenge_invalid");
                }
                let chain: Vec<Vec<u8>> = form["certificate_chain"]
                    .split('.')
                    .map(|part| URL_SAFE_NO_PAD.decode(part).unwrap())
                    .collect();
                let challenge = URL_SAFE_NO_PAD.decode(&form["challenge"]).unwrap();
                if chain.len() != 2
                    || chain[1] != challenge
                    || VerifyingKey::from_sec1_bytes(&chain[0]).is_err()
                {
                    return refusal("attestation_invalid");
                }
                let key_id = format!("ak_{:022}", self.next());
                self.keys.insert(
                    key_id.clone(),
                    KeyRow {
                        public: chain[0].clone(),
                        revoked: false,
                    },
                );
                (200, json!({"key_id":key_id,"level":self.level}))
            }
            "token" => match form["grant_type"].as_str() {
                "authorization_code" => self.code(form),
                "refresh_token" => self.refresh(form),
                _ => (400, json!({"error":"unsupported_grant_type"})),
            },
            "revoke" => (200, Value::Null),
            _ => panic!("unexpected endpoint {name}"),
        }
    }
}

#[async_trait]
impl HttpClient for Server {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        let url = request.url.clone();
        let name = match Url::parse(&url).unwrap().path() {
            "/.well-known/openid-configuration" => "discovery",
            "/oauth/v1/jwks.json" => "jwks",
            "/oauth/v1/attest/challenge" => "challenge",
            "/oauth/v1/attest/keys" => "keys",
            "/oauth/v1/token" => "token",
            "/oauth/v1/revoke" => "revoke",
            other => panic!("unexpected path {other}"),
        };
        let form: HashMap<String, String> = url::form_urlencoded::parse(&request.body)
            .into_owned()
            .collect();
        let step = {
            let mut world = self.world.lock().unwrap();
            world.log.push((name, form.clone()));
            world.script.get_mut(name).and_then(VecDeque::pop_front)
        };
        let step = match step {
            Some(Step::Wait(gate)) => {
                gate.await.map_err(|_| TransportError)?;
                None
            }
            other => other,
        };
        let mut world = self.world.lock().unwrap();
        let (status, body, html) = match step {
            Some(Step::Unreachable) => return Err(TransportError),
            Some(Step::Lose) => {
                world.process(name, &form);
                return Err(TransportError);
            }
            Some(Step::Reply(status, body)) => (status, body, false),
            Some(Step::Html(status)) => (status, Value::Null, true),
            Some(Step::Wait(_)) | None => {
                let (status, body) = world.process(name, &form);
                (status, body, false)
            }
        };
        Ok(HttpResponse {
            status,
            url,
            content_type: if html {
                "text/html".into()
            } else if name == "revoke" {
                String::new()
            } else {
                "application/json".into()
            },
            body: if html {
                b"<html>Bad Gateway</html>".to_vec()
            } else if name == "revoke" {
                vec![]
            } else {
                serde_json::to_vec(&body).unwrap()
            },
        })
    }
}

// ---- fixture -------------------------------------------------------------

struct Fx {
    server: Arc<Server>,
    store: Arc<Store>,
    clock: Arc<TestClock>,
    attestor: Arc<SoftAttestor>,
    client: SessionClient,
    logins: AtomicU64,
}

fn scopes() -> Vec<String> {
    vec!["openid".into(), "profile".into(), "offline_access".into()]
}

impl Fx {
    fn new(mode: &'static str) -> Self {
        let server = Arc::new(Server {
            world: Mutex::new(World::new(mode)),
        });
        let store = Arc::new(Store::default());
        let clock = Arc::new(TestClock(AtomicU64::new(NOW)));
        let attestor = Arc::new(SoftAttestor::default());
        let client =
            SessionClient::with_clock(config(), server.clone(), store.clone(), clock.clone())
                .with_device_attestor(attestor.clone());
        Self {
            server,
            store,
            clock,
            attestor,
            client,
            logins: AtomicU64::new(0),
        }
    }

    /// A new SDK instance over the same storage: a process restart.
    fn restart(&self) -> SessionClient {
        SessionClient::with_clock(
            config(),
            self.server.clone(),
            self.store.clone(),
            self.clock.clone(),
        )
        .with_device_attestor(self.attestor.clone())
    }

    fn world(&self) -> std::sync::MutexGuard<'_, World> {
        self.server.world.lock().unwrap()
    }

    fn queue(&self, name: &'static str, step: Step) {
        self.world().script.entry(name).or_default().push_back(step);
    }

    fn names(&self) -> Vec<&'static str> {
        self.world().log.iter().map(|(name, _)| *name).collect()
    }

    fn count(&self, name: &str) -> usize {
        self.world().log.iter().filter(|(n, _)| *n == name).count()
    }

    fn forms(&self, name: &str) -> Vec<HashMap<String, String>> {
        self.world()
            .log
            .iter()
            .filter(|(n, _)| *n == name)
            .map(|(_, form)| form.clone())
            .collect()
    }

    fn clear_log(&self) {
        self.world().log.clear();
    }

    async fn begin_with(&self, client: &SessionClient) -> Result<String, AuthError> {
        let request = client.begin_sign_in(scopes()).await?;
        let params: HashMap<_, _> = Url::parse(&request.authorization_url)
            .unwrap()
            .query_pairs()
            .into_owned()
            .collect();
        self.world().nonce = params["nonce"].clone();
        let mut callback = Url::parse(REDIRECT).unwrap();
        callback
            .query_pairs_mut()
            .append_pair(
                "code",
                &format!("code-{}", self.logins.fetch_add(1, Ordering::SeqCst)),
            )
            .append_pair("state", &params["state"])
            .append_pair("iss", ISSUER);
        Ok(callback.into())
    }

    async fn begin(&self) -> String {
        self.begin_with(&self.client).await.unwrap()
    }

    async fn login(&self) -> SignInResult {
        let callback = self.begin().await;
        self.client.complete_sign_in(&callback).await.unwrap()
    }

    fn near_expiry(&self) {
        self.clock.0.store(NOW + 3580, Ordering::SeqCst);
        self.world().now = NOW + 3580;
    }

    fn key_record(&self) -> Option<Value> {
        self.store.payload("link.attest.v1.")
    }

    fn journal(&self) -> Option<Value> {
        self.store.payload("link.auth.v1.")
    }
}

fn has_proof(form: &HashMap<String, String>) -> bool {
    form.contains_key("attest_key_id")
        || form.contains_key("attest_attempt")
        || form.contains_key("attest_proof")
}

fn invalid_client() -> AuthError {
    AuthError::OAuth {
        code: OAuthError::InvalidClient,
    }
}

// ---- no attestation: nothing changes -------------------------------------

#[test]
fn without_the_discovery_block_the_sdk_works_as_before() {
    block_on(async {
        let f = Fx::new("report");
        f.world().advertised = Value::Null;
        let result = f.login().await;
        assert_eq!(result.user.device_trust.as_deref(), Some("none"));
        f.client.refresh().await.unwrap();
        assert_eq!(
            f.names(),
            ["discovery", "jwks", "token", "discovery", "jwks", "token"]
        );
        assert!(f.forms("token").iter().all(|form| !has_proof(form)));
        assert_eq!(f.attestor.created.load(Ordering::SeqCst), 0);
        assert_eq!(f.store.names().len(), 1);
        // A lost answer still costs the session of a client without a key.
        f.queue("token", Step::Lose);
        assert_eq!(f.client.refresh().await.unwrap_err(), AuthError::Transport);
        assert_eq!(
            f.restart().restore().unwrap(),
            SessionStatus::ReauthenticationRequired
        );
    });
}

#[test]
fn a_client_without_an_attestor_never_talks_attestation() {
    block_on(async {
        let f = Fx::new("report");
        let plain =
            SessionClient::with_clock(config(), f.server.clone(), f.store.clone(), f.clock.clone());
        let callback = f.begin_with(&plain).await.unwrap();
        let result = plain.complete_sign_in(&callback).await.unwrap();
        assert_eq!(result.user.device_trust.as_deref(), Some("none"));
        plain.refresh().await.unwrap();
        assert_eq!(f.count("challenge") + f.count("keys"), 0);
        assert!(f.forms("token").iter().all(|form| !has_proof(form)));
        // The journal of a session without a key keeps its 0.1.0 shape.
        let journal = f.journal().unwrap().to_string();
        assert!(!journal.contains("key_id") && !journal.contains("refresh_attempt"));
    });
}

#[test]
fn unusable_discovery_blocks_mean_no_attestation_not_a_failed_sign_in() {
    block_on(async {
        for block in [
            json!({"versions":["2"], "challenge_endpoint":format!("{ISSUER}/oauth/v1/attest/challenge"),
                "keys_endpoint":format!("{ISSUER}/oauth/v1/attest/keys")}),
            json!({"versions":["1"], "challenge_endpoint":"https://evil.example.test/oauth/v1/attest/challenge",
                "keys_endpoint":format!("{ISSUER}/oauth/v1/attest/keys")}),
            json!({"versions":["1"], "challenge_endpoint":format!("{ISSUER}/oauth/v1/attest/challenge"),
                "keys_endpoint":"https://login.example.test.evil.example/keys"}),
            json!({"versions":["1"], "challenge_endpoint":"http://login.example.test/oauth/v1/attest/challenge",
                "keys_endpoint":format!("{ISSUER}/oauth/v1/attest/keys")}),
            json!({"versions":"1"}),
            json!("yes"),
            json!({}),
        ] {
            let f = Fx::new("report");
            f.world().advertised = block.clone();
            f.login().await;
            f.client.refresh().await.unwrap();
            assert_eq!(f.count("challenge") + f.count("keys"), 0, "{block}");
            assert!(f.forms("token").iter().all(|form| !has_proof(form)));
            assert_eq!(f.attestor.created.load(Ordering::SeqCst), 0);
        }
    });
}

#[test]
fn the_stateless_client_fetches_signing_keys_first_and_sends_no_proof() {
    block_on(async {
        let f = Fx::new("report");
        let client = AuthClient::with_clock(config(), f.server.clone(), f.clock.clone());
        let request = client.begin_sign_in(scopes()).await.unwrap();
        let params: HashMap<_, _> = Url::parse(&request.authorization_url)
            .unwrap()
            .query_pairs()
            .into_owned()
            .collect();
        f.world().nonce = params["nonce"].clone();
        let callback = format!(
            "{REDIRECT}?code=code-x&state={}&iss={}",
            params["state"],
            url::form_urlencoded::byte_serialize(ISSUER.as_bytes()).collect::<String>()
        );
        client.complete_sign_in(&callback).await.unwrap();
        assert_eq!(f.names(), ["discovery", "jwks", "token"]);
        assert!(!has_proof(&f.forms("token")[0]));
    });
}

// ---- registration --------------------------------------------------------

#[test]
fn first_sign_in_registers_a_key_and_signs_the_code_exchange() {
    block_on(async {
        let f = Fx::new("report");
        let callback = f.begin().await;
        // Both registration requests happen before Link is opened.
        assert_eq!(f.names(), ["discovery", "challenge", "keys"]);
        let keys = &f.forms("keys")[0];
        assert_eq!(keys["platform"], "android");
        assert_eq!(keys["certificate_chain"].split('.').count(), 2);
        let result = f.client.complete_sign_in(&callback).await.unwrap();
        assert_eq!(
            f.names(),
            ["discovery", "challenge", "keys", "jwks", "token"]
        );
        let form = &f.forms("token")[0];
        assert_eq!(form["attest_attempt"], "0");
        assert_eq!(form["attest_key_id"].len(), 25);
        // The server verified the signature and bound the session to the key.
        assert!(f.world().sessions[0].key_id.is_some());
        assert_eq!(result.user.device_trust.as_deref(), Some("verified"));

        // The key record sits next to the journal, under the same digest.
        let names = f.store.names();
        assert_eq!(names.len(), 2);
        assert_eq!(
            names[0].strip_prefix("link.attest.v1."),
            names[1].strip_prefix("link.auth.v1.")
        );
        let record = f.key_record().unwrap();
        assert_eq!(record["key_id"], form["attest_key_id"]);
        assert_eq!(record["level"], "verified");
        assert_eq!(record["binding"], names[0]);
        assert_eq!(
            f.journal().unwrap()["state"]["data"]["key_id"],
            record["key_id"]
        );
        match f.restart().restore().unwrap() {
            SessionStatus::SignedIn { user, .. } => {
                assert_eq!(user.device_trust.as_deref(), Some("verified"));
            }
            other => panic!("{other:?}"),
        }
    });
}

#[test]
fn the_key_belongs_to_the_installation_and_survives_sign_out() {
    block_on(async {
        let f = Fx::new("report");
        f.login().await;
        let record = f.key_record().unwrap();
        assert_eq!(f.client.logout().await.unwrap(), LogoutStatus::Revoked);
        assert_eq!(f.store.names().len(), 1);
        assert_eq!(f.key_record().unwrap(), record);
        // The revocation request is not signed.
        assert!(!has_proof(&f.forms("revoke")[0]));
        f.clear_log();
        let restarted = f.restart();
        let callback = f.begin_with(&restarted).await.unwrap();
        restarted.complete_sign_in(&callback).await.unwrap();
        assert_eq!(f.names(), ["discovery", "jwks", "token"]);
        assert_eq!(f.forms("token")[0]["attest_key_id"], record["key_id"]);
        assert_eq!(f.attestor.created.load(Ordering::SeqCst), 1);
        assert!(f.attestor.deleted.lock().unwrap().is_empty());
    });
}

#[test]
fn mode_off_creates_no_key() {
    block_on(async {
        let f = Fx::new("off");
        let result = f.login().await;
        assert_eq!(result.user.device_trust, None);
        assert_eq!(f.names(), ["discovery", "challenge", "jwks", "token"]);
        assert_eq!(f.attestor.created.load(Ordering::SeqCst), 0);
        assert!(!has_proof(&f.forms("token")[0]));
        assert!(f.key_record().is_none());
    });
}

#[test]
fn registration_failures_never_fail_the_sign_in() {
    block_on(async {
        // (what goes wrong, keys created, keys deleted, challenge requests)
        type Break = fn(&Fx);
        let cases: [(&str, Break, u64, usize, usize); 12] = [
            (
                "challenge unreachable",
                |f| f.queue("challenge", Step::Unreachable),
                0,
                0,
                1,
            ),
            (
                "challenge 429",
                |f| {
                    f.queue(
                        "challenge",
                        Step::Reply(429, json!({"error":"temporarily_unavailable"})),
                    );
                },
                0,
                0,
                1,
            ),
            (
                "challenge 503",
                |f| {
                    f.queue(
                        "challenge",
                        Step::Reply(503, json!({"error":"temporarily_unavailable"})),
                    );
                },
                0,
                0,
                1,
            ),
            (
                "challenge gateway page",
                |f| f.queue("challenge", Step::Html(502)),
                0,
                0,
                1,
            ),
            (
                "short challenge",
                |f| {
                    f.queue(
                        "challenge",
                        Step::Reply(200, json!({"mode":"report","challenge":"c2hvcnQ"})),
                    );
                },
                0,
                0,
                1,
            ),
            (
                "unknown mode",
                |f| {
                    f.queue(
                        "challenge",
                        Step::Reply(200, json!({"mode":"strict","challenge":"x"})),
                    );
                },
                0,
                0,
                1,
            ),
            (
                "device cannot attest",
                |f| f.attestor.unsupported.store(true, Ordering::SeqCst),
                0,
                0,
                0,
            ),
            (
                "keystore failure",
                |f| f.attestor.fail_create.store(true, Ordering::SeqCst),
                0,
                0,
                1,
            ),
            (
                "attestation rejected",
                |f| f.queue("keys", Step::Reply(400, refusal("attestation_invalid").1)),
                1,
                1,
                1,
            ),
            (
                "challenge rejected",
                |f| f.queue("keys", Step::Reply(400, refusal("challenge_invalid").1)),
                1,
                1,
                1,
            ),
            (
                "keys 429",
                |f| {
                    f.queue(
                        "keys",
                        Step::Reply(429, json!({"error":"temporarily_unavailable"})),
                    );
                },
                1,
                1,
                1,
            ),
            (
                "malformed key id",
                |f| {
                    f.queue(
                        "keys",
                        Step::Reply(200, json!({"key_id":"ak_\nbad","level":"verified"})),
                    );
                },
                1,
                1,
                1,
            ),
        ];
        for (name, break_it, created, deleted, challenges) in cases {
            let f = Fx::new("report");
            break_it(&f);
            let result = f.login().await;
            assert_eq!(result.user.device_trust.as_deref(), Some("none"), "{name}");
            assert_eq!(f.attestor.created.load(Ordering::SeqCst), created, "{name}");
            assert_eq!(f.attestor.deleted.lock().unwrap().len(), deleted, "{name}");
            assert_eq!(f.count("challenge"), challenges, "{name}");
            assert!(!has_proof(&f.forms("token")[0]), "{name}");
            assert!(f.key_record().is_none(), "{name}");
            // A session made without a key is refreshed without one.
            f.client.refresh().await.unwrap();
            assert!(!has_proof(&f.forms("token")[1]), "{name}");
        }
    });
}

#[test]
fn a_lost_registration_answer_gets_one_new_key_with_a_new_challenge() {
    block_on(async {
        let lost: [fn() -> Step; 4] = [
            || Step::Lose,
            || Step::Unreachable,
            || Step::Reply(503, json!({"error":"temporarily_unavailable"})),
            || Step::Html(502),
        ];
        for step in lost {
            let f = Fx::new("report");
            f.queue("keys", step());
            let result = f.login().await;
            assert_eq!(result.user.device_trust.as_deref(), Some("verified"));
            assert_eq!(
                f.names(),
                [
                    "discovery",
                    "challenge",
                    "keys",
                    "challenge",
                    "keys",
                    "jwks",
                    "token"
                ]
            );
            let uploads = f.forms("keys");
            assert_ne!(uploads[0]["challenge"], uploads[1]["challenge"]);
            assert_ne!(
                uploads[0]["certificate_chain"],
                uploads[1]["certificate_chain"]
            );
            assert_eq!(f.attestor.created.load(Ordering::SeqCst), 2);
            assert_eq!(f.attestor.deleted.lock().unwrap().len(), 1);
            assert_eq!(f.attestor.keys.lock().unwrap().len(), 1);
        }
        // Never a third key for one sign-in.
        let f = Fx::new("report");
        f.queue("keys", Step::Lose);
        f.queue("keys", Step::Lose);
        let result = f.login().await;
        assert_eq!(result.user.device_trust.as_deref(), Some("none"));
        assert_eq!(f.count("challenge"), 2);
        assert_eq!(f.attestor.created.load(Ordering::SeqCst), 2);
        assert!(f.attestor.keys.lock().unwrap().is_empty());
        assert!(f.key_record().is_none());
    });
}

#[test]
fn a_client_the_server_does_not_know_stops_before_link_is_opened() {
    block_on(async {
        for endpoint in ["challenge", "keys"] {
            let f = Fx::new("report");
            f.queue(
                endpoint,
                Step::Reply(401, json!({"error":"invalid_client"})),
            );
            assert_eq!(f.begin_with(&f.client).await.unwrap_err(), invalid_client());
            assert_eq!(f.client.restore().unwrap(), SessionStatus::SignedOut);
            assert!(f.attestor.keys.lock().unwrap().is_empty());
            assert!(f.key_record().is_none());
            // Nothing is left behind: the next attempt starts cleanly.
            f.login().await;
        }
    });
}

#[test]
fn an_unreadable_key_record_is_replaced() {
    block_on(async {
        let f = Fx::new("report");
        f.login().await;
        f.client.logout().await.unwrap();
        {
            let mut entries = f.store.entries.lock().unwrap();
            let entry = entries
                .iter_mut()
                .find(|(name, _)| name.starts_with("link.attest.v1."))
                .unwrap()
                .1;
            entry.1 = entry.1.replace("link.attest.v1.", "link.attest.v1.other");
        }
        let result = f.login().await;
        assert_eq!(result.user.device_trust.as_deref(), Some("verified"));
        assert_eq!(f.attestor.created.load(Ordering::SeqCst), 2);
        assert_eq!(f.count("keys"), 2);
    });
}

// ---- code exchange in "required" mode ------------------------------------

#[test]
fn required_mode_without_a_key_registers_once_and_repeats_the_exchange() {
    block_on(async {
        let f = Fx::new("required");
        f.queue("challenge", Step::Unreachable);
        let callback = f.begin().await;
        assert_eq!(f.names(), ["discovery", "challenge"]);
        let result = f.client.complete_sign_in(&callback).await.unwrap();
        assert_eq!(result.user.device_trust.as_deref(), Some("verified"));
        assert_eq!(
            f.names(),
            [
                "discovery",
                "challenge",
                "jwks",
                "token",
                "challenge",
                "keys",
                "token"
            ]
        );
        let exchanges = f.forms("token");
        assert!(!has_proof(&exchanges[0]) && has_proof(&exchanges[1]));
        // The refusal did not spend the code: the same code is sent again.
        assert_eq!(exchanges[0]["code"], exchanges[1]["code"]);
        assert_eq!(exchanges[0]["code_verifier"], exchanges[1]["code_verifier"]);
        assert!(matches!(
            f.restart().restore().unwrap(),
            SessionStatus::SignedIn { .. }
        ));
    });
}

#[test]
fn required_mode_refuses_a_device_that_cannot_get_a_key() {
    block_on(async {
        // No attestation at all on this device.
        let f = Fx::new("required");
        f.attestor.unsupported.store(true, Ordering::SeqCst);
        let callback = f.begin().await;
        assert_eq!(
            f.client.complete_sign_in(&callback).await.unwrap_err(),
            AuthError::AttestationRequired
        );
        assert_eq!(f.count("token"), 1);
        assert_eq!(f.client.restore().unwrap(), SessionStatus::SignedOut);

        // Both registrations of the sign-in were used before Link was opened.
        let f = Fx::new("required");
        f.queue("keys", Step::Lose);
        f.queue("keys", Step::Lose);
        let callback = f.begin().await;
        assert_eq!(
            f.client.complete_sign_in(&callback).await.unwrap_err(),
            AuthError::AttestationRequired
        );
        assert_eq!((f.count("challenge"), f.count("token")), (2, 1));

        // One registration left, and it fails too.
        let f = Fx::new("required");
        f.queue("challenge", Step::Unreachable);
        f.queue("keys", Step::Reply(400, refusal("attestation_invalid").1));
        let callback = f.begin().await;
        assert_eq!(
            f.client.complete_sign_in(&callback).await.unwrap_err(),
            AuthError::AttestationRequired
        );
        assert_eq!((f.count("challenge"), f.count("token")), (2, 1));

        // The application turned attestation off in the SDK.
        let f = Fx::new("required");
        let plain =
            SessionClient::with_clock(config(), f.server.clone(), f.store.clone(), f.clock.clone());
        let callback = f.begin_with(&plain).await.unwrap();
        assert_eq!(
            plain.complete_sign_in(&callback).await.unwrap_err(),
            AuthError::AttestationRequired
        );
    });
}

#[test]
fn required_mode_refuses_a_key_of_another_application_without_a_new_key() {
    block_on(async {
        let f = Fx::new("required");
        f.world().level = "mismatch";
        let callback = f.begin().await;
        assert_eq!(
            f.client.complete_sign_in(&callback).await.unwrap_err(),
            AuthError::AttestationRequired
        );
        assert_eq!((f.count("keys"), f.count("token")), (1, 1));
        assert!(has_proof(&f.forms("token")[0]));
        // The key itself is genuine and stays.
        assert!(f.key_record().is_some());
    });
}

#[test]
fn required_mode_can_let_unverified_devices_in() {
    block_on(async {
        let f = Fx::new("required");
        f.world().allow_unverified = true;
        f.attestor.unsupported.store(true, Ordering::SeqCst);
        let result = f.login().await;
        assert_eq!(result.user.device_trust.as_deref(), Some("none"));
        assert_eq!(f.count("token"), 1);
    });
}

#[test]
fn a_key_the_server_forgot_is_replaced_and_the_exchange_repeated() {
    block_on(async {
        let f = Fx::new("required");
        f.login().await;
        f.client.logout().await.unwrap();
        let old = f.key_record().unwrap()["key_id"].clone();
        f.world().keys.clear();
        f.clear_log();
        let result = f.login().await;
        assert_eq!(result.user.device_trust.as_deref(), Some("verified"));
        assert_eq!(
            f.names(),
            ["discovery", "jwks", "token", "challenge", "keys", "token"]
        );
        let exchanges = f.forms("token");
        assert_eq!(exchanges[0]["attest_key_id"], old);
        assert_ne!(exchanges[1]["attest_key_id"], old);
        assert_eq!(exchanges[0]["code"], exchanges[1]["code"]);
        assert_eq!(
            f.key_record().unwrap()["key_id"],
            exchanges[1]["attest_key_id"]
        );
        // The old hardware key is gone, the new one is the only one.
        assert_eq!(f.attestor.deleted.lock().unwrap().len(), 1);
        assert_eq!(f.attestor.keys.lock().unwrap().len(), 1);
    });
}

#[test]
fn a_revoked_key_is_deleted_and_the_person_signs_in_again() {
    block_on(async {
        let f = Fx::new("required");
        f.login().await;
        f.client.logout().await.unwrap();
        for key in f.world().keys.values_mut() {
            key.revoked = true;
        }
        let callback = f.begin().await;
        assert_eq!(
            f.client.complete_sign_in(&callback).await.unwrap_err(),
            AuthError::ReauthenticationRequired
        );
        assert!(f.key_record().is_none());
        assert!(f.attestor.keys.lock().unwrap().is_empty());
        assert_eq!(f.client.restore().unwrap(), SessionStatus::SignedOut);
        // The next sign-in registers a new key.
        let result = f.login().await;
        assert_eq!(result.user.device_trust.as_deref(), Some("verified"));
        assert_eq!(f.attestor.created.load(Ordering::SeqCst), 2);
    });
}

#[test]
fn a_refused_proof_fails_the_exchange_without_leaking_and_drops_the_key() {
    block_on(async {
        let f = Fx::new("required");
        f.login().await;
        f.client.logout().await.unwrap();
        f.attestor.wrong_signature.store(true, Ordering::SeqCst);
        let callback = f.begin().await;
        let error = f.client.complete_sign_in(&callback).await.unwrap_err();
        assert_eq!(error, invalid_client());
        assert!(!format!("{error:?} {error}").contains("DO-NOT-LEAK"));
        assert_eq!(f.count("token"), 2);
        assert!(f.key_record().is_none());
        f.attestor.wrong_signature.store(false, Ordering::SeqCst);
        f.login().await;
    });
}

#[test]
fn a_key_that_does_not_answer_or_is_gone_does_not_stop_the_sign_in() {
    block_on(async {
        // Report mode: the exchange goes out unsigned, the record stays.
        let f = Fx::new("report");
        f.login().await;
        f.client.logout().await.unwrap();
        *f.attestor.fail_sign.lock().unwrap() = Some(AttestorError::Unavailable);
        let result = f.login().await;
        assert_eq!(result.user.device_trust.as_deref(), Some("none"));
        assert!(f.key_record().is_some());
        assert!(f.journal().unwrap()["state"]["data"]
            .get("key_id")
            .is_none());
        // A later refresh is signed again and binds the session to the key.
        *f.attestor.fail_sign.lock().unwrap() = None;
        let refreshed = f.client.refresh().await.unwrap();
        assert_eq!(refreshed.user.device_trust.as_deref(), Some("verified"));
        assert!(f.journal().unwrap()["state"]["data"]["key_id"].is_string());

        // Required mode: a key that vanished from the device is registered anew.
        let f = Fx::new("required");
        f.login().await;
        f.client.logout().await.unwrap();
        f.attestor.keys.lock().unwrap().clear();
        f.clear_log();
        let result = f.login().await;
        assert_eq!(result.user.device_trust.as_deref(), Some("verified"));
        assert_eq!(
            f.names(),
            ["discovery", "jwks", "token", "challenge", "keys", "token"]
        );
    });
}

#[test]
fn signing_keys_are_fetched_before_the_code_is_spent() {
    block_on(async {
        let f = Fx::new("report");
        let callback = f.begin().await;
        f.queue("jwks", Step::Unreachable);
        assert_eq!(
            f.client.complete_sign_in(&callback).await.unwrap_err(),
            AuthError::Transport
        );
        assert_eq!(f.count("token"), 0);
        assert!(f.world().codes.is_empty());
    });
}

#[test]
fn cancelling_during_registration_cancels_the_sign_in_but_keeps_the_key() {
    block_on(async {
        let f = Fx::new("report");
        let (release, wait) = oneshot::channel();
        f.queue("keys", Step::Wait(wait));
        let mut starting = Box::pin(f.client.begin_sign_in(scopes()));
        assert!(futures::poll!(&mut starting).is_pending());
        f.client.cancel_sign_in().unwrap();
        release.send(()).unwrap();
        assert_eq!(starting.await.unwrap_err(), AuthError::Cancelled);
        assert_eq!(f.client.restore().unwrap(), SessionStatus::SignedOut);
        assert!(f.key_record().is_some());
        f.clear_log();
        f.login().await;
        assert_eq!(f.count("challenge"), 0);
    });
}

// ---- refresh -------------------------------------------------------------

#[test]
fn refresh_is_signed_by_the_session_key() {
    block_on(async {
        let f = Fx::new("report");
        let first = f.login().await;
        f.near_expiry();
        f.clear_log();
        let second = f.client.valid_session().await.unwrap();
        // Discovery and signing keys precede the request that spends the token.
        assert_eq!(f.names(), ["discovery", "jwks", "token"]);
        let form = &f.forms("token")[0];
        assert_eq!(form["attest_attempt"], "0");
        assert_eq!(form["refresh_token"], "refresh-3");
        assert_ne!(
            first.access_token.expose_secret(),
            second.access_token.expose_secret()
        );
        assert_eq!(second.user.device_trust.as_deref(), Some("verified"));
        assert_eq!(f.world().tokens["refresh-3"].attempt, Some(0));
    });
}

#[test]
fn a_lost_answer_keeps_the_session_and_the_refresh_is_repeated() {
    block_on(async {
        let f = Fx::new("report");
        f.login().await;
        f.queue("token", Step::Lose);
        assert_eq!(f.client.refresh().await.unwrap_err(), AuthError::Transport);
        // The attempt number was written before the request was sent.
        let journal = f.journal().unwrap();
        assert_eq!(journal["state"]["phase"], "refreshing");
        assert_eq!(journal["state"]["data"]["refresh_attempt"], 0);
        // The session is still there, also after a restart.
        let restarted = f.restart();
        assert!(matches!(
            restarted.restore().unwrap(),
            SessionStatus::SignedIn {
                can_refresh: true,
                ..
            }
        ));
        assert_eq!(
            restarted.begin_sign_in(scopes()).await.unwrap_err(),
            AuthError::SessionExists
        );
        let session = restarted.valid_session().await.unwrap();
        let requests = f.forms("token");
        let (lost, repeated) = (&requests[1], &requests[2]);
        assert_eq!(lost["refresh_token"], repeated["refresh_token"]);
        assert_eq!(lost["attest_attempt"], "0");
        assert_eq!(repeated["attest_attempt"], "1");
        assert_ne!(lost["attest_proof"], repeated["attest_proof"]);
        // The token issued in the lost answer is revoked, the new one is in use.
        let lost_successor = f
            .world()
            .tokens
            .iter()
            .find(|(_, row)| row.revoked)
            .map(|(name, _)| name.clone())
            .unwrap();
        assert_ne!(
            session.refresh_token.as_ref().unwrap().expose_secret(),
            lost_successor
        );
        assert_eq!(f.journal().unwrap()["state"]["phase"], "session");
        // And the session goes on.
        restarted.refresh().await.unwrap();
        assert_eq!(f.forms("token")[3]["attest_attempt"], "0");
        assert!(!f.world().sessions[0].revoked);
    });
}

#[test]
fn every_kind_of_missing_answer_is_repeatable() {
    block_on(async {
        let failures: [(fn() -> Step, AuthError); 5] = [
            (|| Step::Unreachable, AuthError::Transport),
            (|| Step::Lose, AuthError::Transport),
            (
                || Step::Reply(503, json!({"error":"temporarily_unavailable"})),
                AuthError::Http { status: 503 },
            ),
            (
                || Step::Reply(429, json!({"error":"temporarily_unavailable"})),
                AuthError::OAuth {
                    code: OAuthError::TemporarilyUnavailable,
                },
            ),
            (|| Step::Html(502), AuthError::InvalidResponse),
        ];
        for (step, error) in failures {
            let f = Fx::new("report");
            f.login().await;
            f.queue("token", step());
            assert_eq!(f.client.refresh().await.unwrap_err(), error);
            assert!(matches!(
                f.restart().restore().unwrap(),
                SessionStatus::SignedIn { .. }
            ));
            f.client.refresh().await.unwrap();
            assert_eq!(f.forms("token")[2]["attest_attempt"], "1");
        }
    });
}

#[test]
fn a_refresh_interrupted_by_process_death_is_repeated() {
    block_on(async {
        let f = Fx::new("report");
        f.login().await;
        let (_release, wait) = oneshot::channel();
        f.queue("token", Step::Wait(wait));
        let mut operation = Box::pin(f.client.refresh());
        assert!(futures::poll!(&mut operation).is_pending());
        drop(operation);
        let restarted = f.restart();
        restarted.valid_session().await.unwrap();
        assert_eq!(f.forms("token")[2]["attest_attempt"], "1");
    });
}

#[test]
fn the_refresh_is_repeated_eight_times_and_then_the_person_signs_in_again() {
    block_on(async {
        let f = Fx::new("report");
        f.login().await;
        for attempt in 0..=8 {
            f.queue("token", Step::Unreachable);
            assert_eq!(f.client.refresh().await.unwrap_err(), AuthError::Transport);
            assert_eq!(
                f.forms("token").last().unwrap()["attest_attempt"],
                attempt.to_string()
            );
            assert!(matches!(
                f.restart().restore().unwrap(),
                SessionStatus::SignedIn { .. }
            ));
        }
        let before = f.count("token");
        assert_eq!(
            f.client.refresh().await.unwrap_err(),
            AuthError::ReauthenticationRequired
        );
        assert_eq!(f.count("token"), before);
        assert_eq!(
            f.restart().restore().unwrap(),
            SessionStatus::ReauthenticationRequired
        );
        assert_eq!(
            f.client.valid_session().await.unwrap_err(),
            AuthError::ReauthenticationRequired
        );
        // The abandoned session is revoked by the next sign-in, as before.
        f.login().await;
        assert_eq!(f.count("revoke"), 1);
    });
}

#[test]
fn definite_refusals_end_the_session() {
    block_on(async {
        // (canned answer, error of the call, is the key deleted)
        let cases = [
            (
                refusal("retry_refused"),
                AuthError::OAuth {
                    code: OAuthError::InvalidGrant,
                },
                false,
            ),
            (
                invalid_grant(),
                AuthError::OAuth {
                    code: OAuthError::InvalidGrant,
                },
                false,
            ),
            (refusal("key_unknown"), invalid_client(), true),
            (refusal("key_revoked"), invalid_client(), true),
            (refusal("required"), AuthError::AttestationRequired, false),
            (
                (401, json!({"error":"invalid_client"})),
                invalid_client(),
                false,
            ),
        ];
        for (answer, error, key_deleted) in cases {
            let f = Fx::new("report");
            f.login().await;
            f.queue("token", Step::Reply(answer.0, answer.1.clone()));
            assert_eq!(f.client.refresh().await.unwrap_err(), error, "{}", answer.1);
            assert_eq!(
                f.restart().restore().unwrap(),
                SessionStatus::ReauthenticationRequired
            );
            assert_eq!(
                f.client.refresh().await.unwrap_err(),
                AuthError::ReauthenticationRequired
            );
            assert_eq!(f.count("token"), 2);
            assert_eq!(f.key_record().is_none(), key_deleted, "{}", answer.1);
            assert_eq!(f.attestor.keys.lock().unwrap().is_empty(), key_deleted);
        }
    });
}

#[test]
fn the_server_refuses_a_repeat_once_the_next_token_was_used() {
    block_on(async {
        // Not a canned answer: the test server follows the contract's rule.
        let f = Fx::new("report");
        f.login().await;
        f.queue("token", Step::Lose);
        assert_eq!(f.client.refresh().await.unwrap_err(), AuthError::Transport);
        // Somebody used the token from the lost answer.
        let successor = f
            .world()
            .tokens
            .iter()
            .find(|(_, row)| row.parent.is_some())
            .map(|(name, _)| name.clone())
            .unwrap();
        f.world().tokens.get_mut(&successor).unwrap().used = true;
        assert_eq!(
            f.client.refresh().await.unwrap_err(),
            AuthError::OAuth {
                code: OAuthError::InvalidGrant
            }
        );
        assert!(f.world().sessions[0].revoked);
        assert_eq!(
            f.restart().restore().unwrap(),
            SessionStatus::ReauthenticationRequired
        );
    });
}

#[test]
fn a_refused_proof_is_signed_once_more_and_then_ends_the_session() {
    block_on(async {
        // The second signature is accepted.
        let f = Fx::new("report");
        f.login().await;
        f.queue("token", Step::Reply(401, refusal("proof_invalid").1));
        f.client.refresh().await.unwrap();
        let requests = f.forms("token");
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[1]["attest_attempt"], "0");
        assert_eq!(requests[2]["attest_attempt"], "0");
        assert_eq!(requests[1]["refresh_token"], requests[2]["refresh_token"]);

        // Refused twice.
        let f = Fx::new("report");
        f.login().await;
        f.attestor.wrong_signature.store(true, Ordering::SeqCst);
        assert_eq!(f.client.refresh().await.unwrap_err(), invalid_client());
        assert_eq!(f.count("token"), 3);
        assert_eq!(
            f.restart().restore().unwrap(),
            SessionStatus::ReauthenticationRequired
        );
        // The refusals spent nothing on the server.
        assert!(f.world().tokens.values().all(|row| !row.used));
    });
}

#[test]
fn a_key_that_does_not_answer_leaves_a_bound_session_untouched() {
    block_on(async {
        let f = Fx::new("report");
        f.login().await;
        *f.attestor.fail_sign.lock().unwrap() = Some(AttestorError::Unavailable);
        assert_eq!(f.client.refresh().await.unwrap_err(), AuthError::Storage);
        assert_eq!(f.count("token"), 1);
        assert_eq!(f.journal().unwrap()["state"]["phase"], "session");
        *f.attestor.fail_sign.lock().unwrap() = None;
        f.client.refresh().await.unwrap();

        // Also while a repeat is pending: nothing is sent, the repeat stays possible.
        f.queue("token", Step::Lose);
        assert_eq!(f.client.refresh().await.unwrap_err(), AuthError::Transport);
        *f.attestor.fail_sign.lock().unwrap() = Some(AttestorError::Unavailable);
        let before = f.count("token");
        assert_eq!(f.client.refresh().await.unwrap_err(), AuthError::Storage);
        assert_eq!(f.count("token"), before);
        *f.attestor.fail_sign.lock().unwrap() = None;
        f.client.refresh().await.unwrap();
        assert_eq!(f.forms("token").last().unwrap()["attest_attempt"], "1");
    });
}

#[test]
fn a_key_lost_from_the_device_ends_a_bound_session() {
    block_on(async {
        let f = Fx::new("report");
        f.login().await;
        f.attestor.keys.lock().unwrap().clear();
        // Unsigned, so the server refuses without spending the token.
        assert_eq!(f.client.refresh().await.unwrap_err(), invalid_client());
        assert!(!has_proof(&f.forms("token")[1]));
        assert!(f.key_record().is_none());
        assert_eq!(
            f.restart().restore().unwrap(),
            SessionStatus::ReauthenticationRequired
        );

        // The same while a repeat is pending: it cannot be signed any more.
        let f = Fx::new("report");
        f.login().await;
        f.queue("token", Step::Lose);
        assert_eq!(f.client.refresh().await.unwrap_err(), AuthError::Transport);
        f.attestor.keys.lock().unwrap().clear();
        let before = f.count("token");
        assert_eq!(
            f.client.refresh().await.unwrap_err(),
            AuthError::ReauthenticationRequired
        );
        assert_eq!(f.count("token"), before);
        assert_eq!(
            f.restart().restore().unwrap(),
            SessionStatus::ReauthenticationRequired
        );
    });
}

#[test]
fn signing_keys_and_discovery_fail_before_the_refresh_token_is_spent() {
    block_on(async {
        for endpoint in ["discovery", "jwks"] {
            let f = Fx::new("report");
            f.login().await;
            f.queue(endpoint, Step::Unreachable);
            assert_eq!(f.client.refresh().await.unwrap_err(), AuthError::Transport);
            assert_eq!(f.count("token"), 1);
            assert_eq!(f.journal().unwrap()["state"]["phase"], "session");
            f.client.refresh().await.unwrap();
            assert_eq!(f.forms("token")[1]["attest_attempt"], "0");
        }
    });
}

#[test]
fn an_answer_that_fails_verification_ends_the_session_as_before() {
    block_on(async {
        let f = Fx::new("report");
        f.login().await;
        f.world().claims.insert("sub".into(), json!("someone-else"));
        assert_eq!(
            f.client.refresh().await.unwrap_err(),
            AuthError::InvalidIdToken
        );
        assert_eq!(
            f.restart().restore().unwrap(),
            SessionStatus::ReauthenticationRequired
        );
    });
}

#[test]
fn logout_revokes_a_session_whose_refresh_is_waiting_to_be_repeated() {
    block_on(async {
        let f = Fx::new("report");
        f.login().await;
        f.queue("token", Step::Lose);
        assert_eq!(f.client.refresh().await.unwrap_err(), AuthError::Transport);
        assert_eq!(f.client.logout().await.unwrap(), LogoutStatus::Revoked);
        assert_eq!(f.client.restore().unwrap(), SessionStatus::SignedOut);
        assert!(f.key_record().is_some());
    });
}

#[test]
fn a_journal_written_by_the_previous_version_is_still_a_session() {
    block_on(async {
        // 0.1.0 wrote no key_id, refresh_attempt, device_trust or attest_tries.
        let f = Fx::new("off");
        f.world().advertised = Value::Null;
        f.login().await;
        let journal = f.journal().unwrap();
        let data = journal["state"]["data"].as_object().unwrap();
        let mut fields: Vec<_> = data.keys().map(String::as_str).collect();
        fields.sort_unstable();
        assert_eq!(
            fields,
            [
                "access_token",
                "expires_at",
                "id_token",
                "refresh_token",
                "user"
            ]
        );
        let mut user: Vec<_> = data["user"].as_object().unwrap().keys().collect();
        user.sort_unstable();
        assert_eq!(
            user,
            [
                "granted_scopes",
                "issuer",
                "name",
                "picture",
                "preferred_username",
                "subject"
            ]
        );
        // The server turns attestation on later: the old session carries on.
        f.world().mode = "report";
        f.world().advertised = World::new("report").advertised;
        let refreshed = f.restart().refresh().await.unwrap();
        assert_eq!(refreshed.user.device_trust.as_deref(), Some("none"));
        assert!(!has_proof(&f.forms("token")[1]));
    });
}

// ---- ID token ------------------------------------------------------------

#[test]
fn device_trust_is_optional_and_unknown_claims_are_ignored() {
    block_on(async {
        for (claim, expected) in [
            (json!("verified"), Some("verified")),
            (json!("unlocked"), Some("unlocked")),
            (json!("mismatch"), Some("mismatch")),
            (json!("none"), Some("none")),
            (json!("a_later_level"), Some("a_later_level")),
            (Value::Null, None),
            (json!(7), None),
            (json!({"level":"verified"}), None),
            (json!("Not A Level"), None),
            (json!(""), None),
        ] {
            let f = Fx::new("report");
            {
                let mut world = f.world();
                world.claims.insert("device_trust".into(), claim.clone());
                world
                    .claims
                    .insert("some_future_claim".into(), json!({"nested":[1,2,3]}));
                world.claims.insert("another".into(), json!(true));
            }
            let result = f.login().await;
            assert_eq!(result.user.device_trust.as_deref(), expected, "{claim}");
            assert_eq!(result.user.subject, "attest-sub");
            assert_eq!(result.user.name.as_deref(), Some("Attested User"));
        }
    });
}
