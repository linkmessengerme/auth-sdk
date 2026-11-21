//! Device attestation, wire contract version 1: one hardware key per
//! installation, registered with the server once and used to sign every token
//! request. Nothing here can fail a sign-in on its own; without a key the
//! request goes out unsigned and the server decides.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    client::random_secret, http, AuthError, ClientConfig, HttpClient, HttpMethod, HttpRequest,
    OAuthError, SecureStore, StorageError, StoredEntry,
};

const PROOF_PREFIX: &str = "link-login-attest-v1";
/// Highest `attest_attempt` the server accepts: the first request and 8 retries.
pub(crate) const MAX_ATTEMPT: u8 = 8;
/// Key registrations (a new key with a new challenge) allowed for one sign-in.
const MAX_REGISTRATIONS: u8 = 2;
/// Both registration requests and the key creation share this budget.
const REGISTRATION_BUDGET: Duration = Duration::from_secs(10);
/// Less time than this is not worth starting a request with.
const MIN_STEP_MILLIS: u128 = 250;
const MAX_REGISTRATION_BODY: usize = 32 * 1024;
const MAX_CERTIFICATES: usize = 8;
const MAX_PROOF_BYTES: usize = 1024;
const CHALLENGE_BYTES: usize = 32;

/// What the platform returns for a key it has just created.
pub enum KeyAttestation {
    /// Android Key Attestation: DER certificates, the key's own certificate first.
    Android { certificate_chain: Vec<Vec<u8>> },
    /// Apple App Attest: `keyId` exactly as `generateKey` returned it, and the
    /// attestation object from `attestKey`.
    Apple {
        key_id: String,
        attestation: Vec<u8>,
    },
}

/// A new hardware key. `key_ref` is how the platform finds the key again: a
/// Keystore alias or an App Attest `keyId`.
pub struct AttestedKey {
    pub key_ref: String,
    pub attestation: KeyAttestation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AttestorError {
    /// No key this time: unsupported device, a hardware or platform-service failure.
    #[error("device attestation is unavailable")]
    Unavailable,
    /// The key no longer exists on the device and never will again.
    #[error("the attested key no longer exists")]
    KeyLost,
}

/// Hardware-backed signing key of this installation. Implement with
/// AndroidKeyStore key attestation or Apple App Attest; the supplied platform
/// adapters do. Private key material never crosses this interface.
#[async_trait]
pub trait DeviceAttestor: Send + Sync {
    /// Cheap and local. False where the platform cannot attest at all (Android 6,
    /// iOS 13, a simulator); nothing is requested from the server then.
    fn is_available(&self) -> bool;
    /// Create a sign-only P-256 key bound to the 32-byte `challenge`. `name` is a
    /// namespace for platform aliases. Give up after `timeout_millis`.
    async fn create_key(
        &self,
        name: &str,
        challenge: &[u8],
        timeout_millis: u32,
    ) -> Result<AttestedKey, AttestorError>;
    /// Android: ECDSA P-256 with SHA-256 over `message`, DER. Apple: the
    /// assertion for `clientDataHash = SHA-256(message)`.
    async fn sign(&self, key_ref: &str, message: &[u8]) -> Result<Vec<u8>, AttestorError>;
    /// Best effort; a key that cannot be deleted is simply forgotten.
    async fn delete_key(&self, key_ref: &str);
}

/// The server's `attestation_error`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AttestReason {
    Required,
    KeyUnknown,
    KeyRevoked,
    ProofInvalid,
    RetryRefused,
    Other,
}

impl AttestReason {
    pub(crate) fn parse(value: &str) -> Self {
        match value {
            "required" => Self::Required,
            "key_unknown" => Self::KeyUnknown,
            "key_revoked" => Self::KeyRevoked,
            "proof_invalid" => Self::ProofInvalid,
            "retry_refused" => Self::RetryRefused,
            _ => Self::Other,
        }
    }
}

/// `link_attestation` of the discovery document, as received.
#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct Advertised {
    versions: Vec<String>,
    challenge_endpoint: String,
    keys_endpoint: String,
}

impl Advertised {
    /// A block this SDK cannot read is treated as absent: the server's
    /// attestation settings must not be able to break sign-in.
    pub(crate) fn lenient<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Self>, D::Error> {
        let value = Option::<serde_json::Value>::deserialize(deserializer)?;
        Ok(value.and_then(|value| serde_json::from_value(value).ok()))
    }

    /// Version 1 endpoints, only on the configured API origin (the rule of
    /// `token_endpoint`). Anything else means "no attestation".
    pub(crate) fn endpoints(&self, config: &ClientConfig) -> Option<Endpoints> {
        if !self.versions.iter().any(|version| version == "1") {
            return None;
        }
        Some(Endpoints {
            challenge: config.endpoint(&self.challenge_endpoint).ok()?.into(),
            keys: config.endpoint(&self.keys_endpoint).ok()?.into(),
        })
    }
}

pub(crate) struct Endpoints {
    challenge: String,
    keys: String,
}

#[derive(Clone, Copy)]
pub(crate) enum Purpose {
    Code,
    Refresh,
}

/// The string a token request is signed over: six fields joined by LF, no
/// trailing LF. `secret` is the code or refresh token exactly as it is sent.
pub(crate) fn proof_message(
    purpose: Purpose,
    client_id: &str,
    key_id: &str,
    secret: &str,
    attempt: u8,
) -> Vec<u8> {
    let purpose = match purpose {
        Purpose::Code => "code",
        Purpose::Refresh => "refresh",
    };
    let secret_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()));
    format!("{PROOF_PREFIX}\n{purpose}\n{client_id}\n{key_id}\n{secret_hash}\n{attempt}")
        .into_bytes()
}

/// `attest_key_id`, `attest_attempt` and `attest_proof` of one token request.
pub(crate) struct Proof {
    pub key_id: String,
    attempt: u8,
    value: String,
}

impl Proof {
    pub(crate) fn append(&self, form: &mut url::form_urlencoded::Serializer<'_, String>) {
        form.append_pair("attest_key_id", &self.key_id)
            .append_pair("attest_attempt", &self.attempt.to_string())
            .append_pair("attest_proof", &self.value);
    }
}

pub(crate) enum Signing {
    Signed(Proof),
    /// The key is gone for good; its record has been removed.
    NoKey,
    /// The key exists but could not be used this time.
    Unavailable,
}

/// The saved key of this installation.
pub(crate) struct KeyHandle {
    revision: String,
    key_ref: String,
    pub(crate) key_id: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: u32,
    binding: String,
    key_ref: String,
    key_id: String,
    level: String,
}

enum Registration {
    Done(KeyHandle),
    /// The answer to the key upload was lost; a new key may be tried.
    Lost,
    Stopped,
}

pub(crate) struct Attestation {
    config: ClientConfig,
    transport: Arc<dyn HttpClient>,
    store: Arc<dyn SecureStore>,
    attestor: Arc<dyn DeviceAttestor>,
    /// `link.attest.v1.<digest>`: the record outlives the session journal,
    /// because the key belongs to the installation, not to a signed-in user.
    name: String,
}

impl Attestation {
    pub(crate) fn new(
        config: ClientConfig,
        transport: Arc<dyn HttpClient>,
        store: Arc<dyn SecureStore>,
        attestor: Arc<dyn DeviceAttestor>,
        digest: &str,
    ) -> Self {
        Self {
            config,
            transport,
            store,
            attestor,
            name: format!("link.attest.v1.{digest}"),
        }
    }

    /// The saved key, if storage can be read and holds a usable record.
    pub(crate) fn load(&self) -> Option<KeyHandle> {
        self.read().ok().flatten()
    }

    fn read(&self) -> Result<Option<KeyHandle>, StorageError> {
        let Some(entry) = self.store.load(&self.name)? else {
            return Ok(None);
        };
        let record = serde_json::from_str::<Record>(entry.payload.expose_secret())
            .ok()
            .filter(|record| {
                record.schema == 1
                    && record.binding == self.name
                    && valid_key_id(&record.key_id)
                    && valid_key_ref(&record.key_ref)
                    && valid_level(&record.level)
            });
        let Some(record) = record else {
            // An unreadable record would block registration forever.
            let _ = self
                .store
                .compare_exchange(&self.name, Some(&entry.revision), None);
            return Ok(None);
        };
        Ok(Some(KeyHandle {
            revision: entry.revision,
            key_ref: record.key_ref,
            key_id: record.key_id,
        }))
    }

    /// Remove a key the server refused or the device lost.
    pub(crate) async fn forget(&self, key: &KeyHandle) {
        let _ = self
            .store
            .compare_exchange(&self.name, Some(&key.revision), None);
        self.attestor.delete_key(&key.key_ref).await;
    }

    pub(crate) async fn sign(
        &self,
        key: &KeyHandle,
        purpose: Purpose,
        secret: &str,
        attempt: u8,
    ) -> Signing {
        let message = proof_message(
            purpose,
            self.config.client_id(),
            &key.key_id,
            secret,
            attempt,
        );
        match self.attestor.sign(&key.key_ref, &message).await {
            Ok(signature) if !signature.is_empty() && signature.len() <= MAX_PROOF_BYTES => {
                Signing::Signed(Proof {
                    key_id: key.key_id.clone(),
                    attempt,
                    value: URL_SAFE_NO_PAD.encode(signature),
                })
            }
            Ok(_) | Err(AttestorError::Unavailable) => Signing::Unavailable,
            Err(AttestorError::KeyLost) => {
                self.forget(key).await;
                Signing::NoKey
            }
        }
    }

    /// The saved key, or a newly registered one. `tries` counts registrations of
    /// one sign-in. `Err` only when the server does not know the client at all:
    /// the token endpoint would refuse the sign-in the same way.
    pub(crate) async fn ensure(
        &self,
        endpoints: &Endpoints,
        tries: &mut u8,
        retry_lost: bool,
    ) -> Result<Option<KeyHandle>, AuthError> {
        match self.read() {
            Ok(Some(key)) => return Ok(Some(key)),
            Ok(None) => (),
            // Without storage a new key could not be remembered.
            Err(_) => return Ok(None),
        }
        if !self.attestor.is_available() {
            return Ok(None);
        }
        let deadline = Instant::now() + REGISTRATION_BUDGET;
        while *tries < MAX_REGISTRATIONS {
            *tries += 1;
            match self.register(endpoints, deadline).await? {
                Registration::Done(key) => return Ok(Some(key)),
                Registration::Lost if retry_lost => continue,
                Registration::Lost | Registration::Stopped => break,
            }
        }
        Ok(None)
    }

    async fn register(
        &self,
        endpoints: &Endpoints,
        deadline: Instant,
    ) -> Result<Registration, AuthError> {
        // One-time challenge.
        let Some(timeout) = remaining(deadline) else {
            return Ok(Registration::Stopped);
        };
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", self.config.client_id())
            .finish()
            .into_bytes();
        let mut request = HttpRequest::new(HttpMethod::Post, endpoints.challenge.clone(), body);
        request.timeout_millis = timeout;
        let Ok(reply) = http::reply(self.transport.as_ref(), request).await else {
            return Ok(Registration::Stopped);
        };
        unknown_client(&reply)?;
        let text = |name: &str| reply.body.get(name).and_then(serde_json::Value::as_str);
        if reply.status != 200 || !matches!(text("mode"), Some("report" | "required")) {
            // Includes {"mode":"off"}.
            return Ok(Registration::Stopped);
        }
        let Some(challenge) = text("challenge").map(str::to_owned) else {
            return Ok(Registration::Stopped);
        };
        let Some(challenge_bytes) = URL_SAFE_NO_PAD
            .decode(&challenge)
            .ok()
            .filter(|bytes| bytes.len() == CHALLENGE_BYTES)
        else {
            return Ok(Registration::Stopped);
        };

        // Hardware key bound to the challenge.
        let Some(timeout) = remaining(deadline) else {
            return Ok(Registration::Stopped);
        };
        let Ok(created) = self
            .attestor
            .create_key(&self.name, &challenge_bytes, timeout)
            .await
        else {
            return Ok(Registration::Stopped);
        };
        // Upload. From here every failure deletes the key: its challenge is
        // spent and is part of the certificate.
        let body = registration_body(self.config.client_id(), &challenge, &created.attestation)
            .filter(|_| valid_key_ref(&created.key_ref));
        let timeout = remaining(deadline);
        let (Some(body), Some(timeout)) = (body, timeout) else {
            self.attestor.delete_key(&created.key_ref).await;
            return Ok(Registration::Stopped);
        };
        let mut request = HttpRequest::new(HttpMethod::Post, endpoints.keys.clone(), body);
        request.timeout_millis = timeout;
        let reply = match http::reply(self.transport.as_ref(), request).await {
            Ok(reply) => reply,
            Err(_) => {
                self.attestor.delete_key(&created.key_ref).await;
                return Ok(Registration::Lost);
            }
        };
        let text = |name: &str| reply.body.get(name).and_then(serde_json::Value::as_str);
        let accepted = match (reply.status, text("key_id"), text("level")) {
            (200, Some(key_id), Some(level)) if valid_key_id(key_id) && valid_level(level) => {
                Some((key_id.to_owned(), level.to_owned()))
            }
            _ => None,
        };
        let Some((key_id, level)) = accepted else {
            self.attestor.delete_key(&created.key_ref).await;
            unknown_client(&reply)?;
            return Ok(if reply.status >= 500 {
                Registration::Lost
            } else {
                Registration::Stopped
            });
        };
        Ok(match self.save(created.key_ref, key_id, level).await {
            Some(key) => Registration::Done(key),
            None => Registration::Stopped,
        })
    }

    async fn save(&self, key_ref: String, key_id: String, level: String) -> Option<KeyHandle> {
        let entry = random_secret().ok().and_then(|revision| {
            let payload = serde_json::to_string(&Record {
                schema: 1,
                binding: self.name.clone(),
                key_ref: key_ref.clone(),
                key_id: key_id.clone(),
                level,
            })
            .ok()?;
            Some(StoredEntry::new(
                revision.expose_secret().to_owned(),
                payload,
            ))
        });
        let revision = entry.as_ref().map(|entry| entry.revision.clone());
        let saved = match entry {
            Some(entry) => self.store.compare_exchange(&self.name, None, Some(entry)),
            None => Err(StorageError),
        };
        match (saved, revision) {
            (Ok(true), Some(revision)) => Some(KeyHandle {
                revision,
                key_ref,
                key_id,
            }),
            // Another instance registered first: its key is the installation's key.
            (Ok(false), _) => {
                self.attestor.delete_key(&key_ref).await;
                self.load()
            }
            _ => {
                self.attestor.delete_key(&key_ref).await;
                None
            }
        }
    }
}

/// The form of the key upload, or `None` when the platform's answer cannot be
/// sent as the contract describes it.
fn registration_body(
    client_id: &str,
    challenge: &str,
    attestation: &KeyAttestation,
) -> Option<Vec<u8>> {
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    form.append_pair("client_id", client_id);
    match attestation {
        KeyAttestation::Android { certificate_chain } => {
            if certificate_chain.is_empty()
                || certificate_chain.len() > MAX_CERTIFICATES
                || certificate_chain.iter().any(Vec::is_empty)
            {
                return None;
            }
            let chain = certificate_chain
                .iter()
                .map(|certificate| URL_SAFE_NO_PAD.encode(certificate))
                .collect::<Vec<_>>()
                .join(".");
            form.append_pair("platform", "android")
                .append_pair("challenge", challenge)
                .append_pair("certificate_chain", &chain);
        }
        KeyAttestation::Apple {
            key_id,
            attestation,
        } => {
            if key_id.is_empty() || attestation.is_empty() {
                return None;
            }
            form.append_pair("platform", "ios")
                .append_pair("challenge", challenge)
                .append_pair("apple_key_id", key_id)
                .append_pair("attestation", &URL_SAFE_NO_PAD.encode(attestation));
        }
    }
    let body = form.finish().into_bytes();
    (body.len() <= MAX_REGISTRATION_BODY).then_some(body)
}

fn unknown_client(reply: &http::Reply) -> Result<(), AuthError> {
    if reply.status == 401
        && reply.body.get("error").and_then(serde_json::Value::as_str) == Some("invalid_client")
    {
        return Err(AuthError::OAuth {
            code: OAuthError::InvalidClient,
        });
    }
    Ok(())
}

fn remaining(deadline: Instant) -> Option<u32> {
    let left = deadline.checked_duration_since(Instant::now())?.as_millis();
    (left >= MIN_STEP_MILLIS).then(|| u32::try_from(left).unwrap_or(u32::MAX))
}

/// Opaque to the SDK, but it is a field of the newline-separated proof message.
pub(crate) fn valid_key_id(value: &str) -> bool {
    (1..=32).contains(&value.len())
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

fn valid_key_ref(value: &str) -> bool {
    (1..=512).contains(&value.len()) && !value.bytes().any(|c| c.is_ascii_control())
}

/// `verified`, `unlocked`, `mismatch`, `none`; a later level must not need an SDK update.
pub(crate) fn valid_level(value: &str) -> bool {
    (1..=32).contains(&value.len()) && value.bytes().all(|c| c.is_ascii_lowercase() || c == b'_')
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// The contract's proof vectors: the message must match byte for byte.
    #[test]
    fn proof_message_matches_contract_vectors() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/proof-vectors.json")).unwrap();
        assert_eq!(vectors["prefix"], PROOF_PREFIX);
        let mut checked = 0;
        for group in ["valid", "valid_alternative", "invalid"] {
            for case in vectors[group].as_array().unwrap() {
                let purpose = match case["purpose"].as_str().unwrap() {
                    "code" => Purpose::Code,
                    "refresh" => Purpose::Refresh,
                    other => panic!("unknown purpose {other}"),
                };
                let message = proof_message(
                    purpose,
                    case["client_id"].as_str().unwrap(),
                    case["key_id"].as_str().unwrap(),
                    case["secret"].as_str().unwrap(),
                    u8::try_from(case["attempt"].as_u64().unwrap()).unwrap(),
                );
                // Only the valid cases carry the expected bytes; the invalid ones
                // are proofs that must not verify over the message built here.
                let Some(expected) = case["message_hex"].as_str() else {
                    continue;
                };
                let hex: String = message.iter().map(|byte| format!("{byte:02x}")).collect();
                assert_eq!(hex, expected, "case {}", case["name"]);
                assert_eq!(
                    String::from_utf8(message.clone()).unwrap(),
                    case["message_utf8"].as_str().unwrap()
                );
                let digest: String = Sha256::digest(&message)
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                assert_eq!(digest, case["client_data_hash_hex"].as_str().unwrap());
                checked += 1;
            }
        }
        assert_eq!(checked, 3);
    }

    /// The Android proofs of the vectors verify over the message built here,
    /// and only those the contract expects to: what `check_vectors.py` does.
    #[test]
    fn contract_vector_proofs_verify_over_the_message() {
        use p256::ecdsa::{signature::Verifier as _, Signature, VerifyingKey};
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/proof-vectors.json")).unwrap();
        let point: Vec<u8> = vectors["key"]["public_point_hex"]
            .as_str()
            .unwrap()
            .as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let public = VerifyingKey::from_sec1_bytes(&point).unwrap();
        let (mut valid, mut invalid) = (0, 0);
        for group in ["valid", "valid_alternative", "invalid"] {
            for case in vectors[group].as_array().unwrap() {
                let Some(proof) = case["android_proof"].as_str() else {
                    continue;
                };
                let message = proof_message(
                    if case["purpose"] == "code" {
                        Purpose::Code
                    } else {
                        Purpose::Refresh
                    },
                    case["client_id"].as_str().unwrap(),
                    case["key_id"].as_str().unwrap(),
                    case["secret"].as_str().unwrap(),
                    u8::try_from(case["attempt"].as_u64().unwrap()).unwrap(),
                );
                let verified = URL_SAFE_NO_PAD
                    .decode(proof)
                    .ok()
                    .and_then(|der| Signature::from_der(&der).ok())
                    .is_some_and(|signature| public.verify(&message, &signature).is_ok());
                assert_eq!(verified, case["expect"] == "valid", "case {}", case["name"]);
                if verified {
                    valid += 1;
                } else {
                    invalid += 1;
                }
            }
        }
        assert_eq!((valid, invalid), (3, 7));
    }

    #[test]
    fn contract_example_string() {
        assert_eq!(
            proof_message(
                Purpose::Code,
                "lk_client_sdk_test",
                "ak_Zm9yLXRlc3RzLW9ubHktMDE",
                "kq3v0oJ0v2yXoN1c7m8pQw4r5t6u7i8o9p0aSdFgHjK",
                0
            ),
            b"link-login-attest-v1\ncode\nlk_client_sdk_test\nak_Zm9yLXRlc3RzLW9ubHktMDE\nXxyD_JmNx3ORdvrnKkBa8pSX7s6LBku7DNHf-rnvQ8A\n0"
        );
    }

    #[test]
    fn identifiers_cannot_break_the_message_or_the_form() {
        assert!(valid_key_id("ak_Zm9yLXRlc3RzLW9ubHktMDE"));
        for bad in ["", "ak_\nx", "ak x", &"a".repeat(33)] {
            assert!(!valid_key_id(bad));
        }
        assert!(valid_level("verified") && valid_level("none"));
        assert!(!valid_level("Verified") && !valid_level(""));
    }
}
