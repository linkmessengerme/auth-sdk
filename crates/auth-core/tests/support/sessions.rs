use super::*;
use link_auth_core::{
    LogoutStatus, SecureStore, SessionClient, SessionStatus, StorageError, StoredEntry,
};
use std::sync::atomic::{AtomicBool, AtomicUsize};

#[path = "userinfo.rs"]
mod userinfo;

#[derive(Default)]
struct Store {
    entries: Mutex<HashMap<String, (String, String)>>,
    fail_load: AtomicBool,
    writes: AtomicUsize,
    fail_write_at: AtomicUsize,
}

impl SecureStore for Store {
    fn load(&self, key: &str) -> Result<Option<StoredEntry>, StorageError> {
        if self.fail_load.load(Ordering::SeqCst) {
            return Err(StorageError);
        }
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
        let write = self.writes.fetch_add(1, Ordering::SeqCst) + 1;
        if self.fail_write_at.load(Ordering::SeqCst) == write {
            return Err(StorageError);
        }
        let mut entries = self.entries.lock().unwrap();
        if entries.get(key).map(|e| e.0.as_str()) != expected {
            return Ok(false);
        }
        if let Some(value) = value {
            entries.insert(
                key.into(),
                (value.revision, value.payload.expose_secret().into()),
            );
        } else {
            entries.remove(key);
        }
        Ok(true)
    }
}

struct Fixture {
    client: SessionClient,
    server: Arc<Server>,
    clock: Arc<TestClock>,
    store: Arc<Store>,
}
impl Fixture {
    fn new() -> Self {
        let (_, server, clock) = fixture();
        let store = Arc::new(Store::default());
        let client = session(&server, &clock, &store);
        Self {
            client,
            server,
            clock,
            store,
        }
    }
    fn restart(&self) -> SessionClient {
        session(&self.server, &self.clock, &self.store)
    }
    fn near_expiry(&self) {
        self.clock.0.store(NOW + 3580, Ordering::SeqCst);
        self.server.state.lock().unwrap().now = NOW + 3580;
    }
    fn token_posts(&self) -> usize {
        self.server
            .state
            .lock()
            .unwrap()
            .requests
            .iter()
            .filter(|r| r.url.ends_with("/token"))
            .count()
    }
    async fn pending(&self) -> String {
        self.pending_scopes(vec![
            "openid".into(),
            "profile".into(),
            "offline_access".into(),
        ])
        .await
    }
    async fn pending_scopes(&self, scopes: Vec<String>) -> String {
        let request = self.client.begin_sign_in(scopes).await.unwrap();
        let params: HashMap<_, _> = Url::parse(&request.authorization_url)
            .unwrap()
            .query_pairs()
            .into_owned()
            .collect();
        self.server.state.lock().unwrap().nonce = params["nonce"].clone();
        let mut callback = Url::parse(REDIRECT).unwrap();
        callback
            .query_pairs_mut()
            .append_pair("code", "session-code")
            .append_pair("state", &params["state"])
            .append_pair("iss", ISSUER);
        callback.into()
    }
    async fn login(&self) {
        let cb = self.pending().await;
        self.client.complete_sign_in(&cb).await.unwrap();
    }
}

#[test]
fn backend_nonce_survives_restart_and_is_verified() {
    block_on(async {
        for length in [32, 64, 256] {
            for correct in [true, false] {
                let f = Fixture::new();
                let nonce = "n".repeat(length);
                let request = f
                    .client
                    .begin_sign_in_with_nonce(
                        vec!["openid".into(), "profile".into(), "offline_access".into()],
                        nonce.clone(),
                    )
                    .await
                    .unwrap();
                let params: HashMap<_, _> = Url::parse(&request.authorization_url)
                    .unwrap()
                    .query_pairs()
                    .into_owned()
                    .collect();
                assert_eq!(params["nonce"], nonce);
                assert_ne!(params["state"], nonce);
                f.server.state.lock().unwrap().nonce =
                    if correct { nonce } else { "wrong".repeat(10) };
                let mut callback = Url::parse(REDIRECT).unwrap();
                callback
                    .query_pairs_mut()
                    .append_pair("code", "session-code")
                    .append_pair("state", &params["state"])
                    .append_pair("iss", ISSUER);
                let restarted = f.restart();
                assert!(matches!(
                    restarted.restore().unwrap(),
                    SessionStatus::PendingLogin { .. }
                ));
                let result = restarted.complete_sign_in(callback.as_str()).await;
                if correct {
                    assert!(result.is_ok(), "{result:?}");
                } else {
                    assert!(matches!(result, Err(AuthError::InvalidIdToken)));
                }
            }
        }
    });
}

#[test]
fn invalid_backend_nonce_does_not_change_saved_session_or_make_requests() {
    block_on(async {
        let f = Fixture::new();
        f.login().await;
        let requests = f.server.state.lock().unwrap().requests.len();
        let writes = f.store.writes.load(Ordering::SeqCst);
        for nonce in [
            String::new(),
            "n".repeat(31),
            "n".repeat(257),
            "bad nonce".repeat(8),
            "é".repeat(32),
        ] {
            assert!(matches!(
                f.client
                    .begin_sign_in_with_nonce(vec!["openid".into()], nonce)
                    .await,
                Err(AuthError::InvalidNonce)
            ));
        }
        assert_eq!(f.server.state.lock().unwrap().requests.len(), requests);
        assert_eq!(f.store.writes.load(Ordering::SeqCst), writes);
        assert!(matches!(
            f.client.restore().unwrap(),
            SessionStatus::SignedIn { .. }
        ));
    });
}
fn session(server: &Arc<Server>, clock: &Arc<TestClock>, store: &Arc<Store>) -> SessionClient {
    session_with_config(server, clock, store, config_json())
}

fn session_with_config(
    server: &Arc<Server>,
    clock: &Arc<TestClock>,
    store: &Arc<Store>,
    config: Value,
) -> SessionClient {
    SessionClient::with_clock(
        ClientConfig::from_console_json(&config.to_string(), REDIRECT).unwrap(),
        server.clone(),
        store.clone(),
        clock.clone(),
    )
}

#[test]
fn regional_pending_restore_refresh_and_logout_keep_http_on_regional_api() {
    block_on(async {
        let mut f = Fixture::new();
        f.client = session_with_config(&f.server, &f.clock, &f.store, regional_config_json());
        regional_discovery(&f.server);
        let callback = f.pending().await;
        let restarted = session_with_config(&f.server, &f.clock, &f.store, regional_config_json());
        assert!(matches!(
            restarted.restore().unwrap(),
            SessionStatus::PendingLogin { .. }
        ));
        assert_eq!(
            restarted
                .complete_sign_in(&callback)
                .await
                .unwrap()
                .user
                .issuer,
            ISSUER
        );
        f.near_expiry();
        let restarted = session_with_config(&f.server, &f.clock, &f.store, regional_config_json());
        assert!(matches!(
            restarted.restore().unwrap(),
            SessionStatus::SignedIn { .. }
        ));
        let refreshed = restarted.valid_session().await.unwrap();
        assert_eq!(refreshed.user.issuer, ISSUER);
        assert_eq!(
            refreshed.refresh_token.unwrap().expose_secret(),
            "rotated-refresh-1"
        );
        assert_eq!(restarted.logout().await.unwrap(), LogoutStatus::Revoked);
        let state = f.server.state.lock().unwrap();
        assert!(state
            .requests
            .iter()
            .all(|r| Url::parse(&r.url).unwrap().origin()
                == Url::parse(REGIONAL_API).unwrap().origin()));
        assert_eq!(
            state
                .requests
                .iter()
                .filter(|r| r.url.ends_with("/token"))
                .count(),
            2
        );
        assert_eq!(
            state
                .requests
                .iter()
                .filter(|r| r.url.ends_with("/revoke"))
                .count(),
            1
        );
    });
}

#[test]
fn pending_login_and_session_survive_recreation() {
    block_on(async {
        let f = Fixture::new();
        let cb = f.pending().await;
        let restarted = f.restart();
        assert!(matches!(
            restarted.restore().unwrap(),
            SessionStatus::PendingLogin { .. }
        ));
        assert_eq!(
            restarted
                .complete_sign_in(&cb.replace("state=", "state=bad"))
                .await
                .unwrap_err(),
            AuthError::StateMismatch
        );
        restarted.complete_sign_in(&cb).await.unwrap();
        let restarted = f.restart();
        assert!(matches!(
            restarted.restore().unwrap(),
            SessionStatus::SignedIn {
                can_refresh: true,
                ..
            }
        ));
        assert_eq!(
            restarted.valid_session().await.unwrap().user.subject,
            "opaque-project-test-sub"
        );
        assert_eq!(f.token_posts(), 1);
        assert_eq!(
            restarted.complete_sign_in(&cb).await.unwrap_err(),
            AuthError::NoPendingLogin
        );
    });
}

#[test]
fn refresh_rotates_and_coalesces_concurrent_requests() {
    block_on(async {
        let f = Fixture::new();
        f.login().await;
        f.near_expiry();
        let (release, wait) = oneshot::channel();
        f.server.state.lock().unwrap().gate = Some(wait);
        let mut first = Box::pin(f.client.valid_session());
        assert!(futures::poll!(&mut first).is_pending());
        let mut second = Box::pin(f.client.valid_session());
        assert!(futures::poll!(&mut second).is_pending());
        release.send(()).unwrap();
        let (a, b) = futures::join!(first, second);
        assert_eq!(
            a.unwrap().refresh_token.unwrap().expose_secret(),
            "rotated-refresh-1"
        );
        assert_eq!(
            b.unwrap().refresh_token.unwrap().expose_secret(),
            "rotated-refresh-1"
        );
        assert_eq!(f.token_posts(), 2);
        assert!(matches!(
            f.restart().restore().unwrap(),
            SessionStatus::SignedIn { .. }
        ));
    });
}

#[test]
fn explicit_refresh_coalesces_and_separate_clients_cannot_reuse() {
    block_on(async {
        let f = Fixture::new();
        f.login().await;
        let (release, wait) = oneshot::channel();
        f.server.state.lock().unwrap().gate = Some(wait);
        let mut first = Box::pin(f.client.refresh());
        assert!(futures::poll!(&mut first).is_pending());
        let mut second = Box::pin(f.client.refresh());
        assert!(futures::poll!(&mut second).is_pending());
        assert_eq!(
            f.restart().refresh().await.unwrap_err(),
            AuthError::ReauthenticationRequired
        );
        release.send(()).unwrap();
        let (a, b) = futures::join!(first, second);
        a.unwrap();
        b.unwrap();
        assert_eq!(f.token_posts(), 2);
    });
}

#[test]
fn storage_failure_prevents_consuming_code_or_refresh() {
    block_on(async {
        let f = Fixture::new();
        let cb = f.pending().await;
        f.store
            .fail_write_at
            .store(f.store.writes.load(Ordering::SeqCst) + 1, Ordering::SeqCst);
        assert_eq!(
            f.client.complete_sign_in(&cb).await.unwrap_err(),
            AuthError::Storage
        );
        assert_eq!(f.token_posts(), 0);
        f.client.complete_sign_in(&cb).await.unwrap();
        f.store
            .fail_write_at
            .store(f.store.writes.load(Ordering::SeqCst) + 1, Ordering::SeqCst);
        assert_eq!(f.client.refresh().await.unwrap_err(), AuthError::Storage);
        assert_eq!(f.token_posts(), 1);
        f.client.refresh().await.unwrap();
        assert_eq!(f.token_posts(), 2);
    });
}

#[test]
fn failed_rotation_commit_and_dropped_future_never_restore_old_refresh() {
    block_on(async {
        for drop_future in [false, true] {
            let f = Fixture::new();
            f.login().await;
            if drop_future {
                let (_release, wait) = oneshot::channel();
                f.server.state.lock().unwrap().gate = Some(wait);
                let mut operation = Box::pin(f.client.refresh());
                assert!(futures::poll!(&mut operation).is_pending());
                drop(operation);
            } else {
                f.store
                    .fail_write_at
                    .store(f.store.writes.load(Ordering::SeqCst) + 2, Ordering::SeqCst);
                assert_eq!(f.client.refresh().await.unwrap_err(), AuthError::Storage);
            }
            assert_eq!(
                f.restart().restore().unwrap(),
                SessionStatus::ReauthenticationRequired
            );
            assert_eq!(
                f.restart().refresh().await.unwrap_err(),
                AuthError::ReauthenticationRequired
            );
            assert_eq!(f.token_posts(), 2);
        }
    });
}

#[test]
fn lost_refresh_response_requires_new_login_and_revokes_old_family() {
    block_on(async {
        let f = Fixture::new();
        f.login().await;
        f.server.state.lock().unwrap().fail_token = true;
        assert_eq!(f.client.refresh().await.unwrap_err(), AuthError::Transport);
        assert_eq!(
            f.restart().valid_session().await.unwrap_err(),
            AuthError::ReauthenticationRequired
        );
        assert_eq!(f.token_posts(), 2);
        f.server.state.lock().unwrap().fail_token = false;
        let restarted = f.restart();
        restarted
            .begin_sign_in(vec!["openid".into()])
            .await
            .unwrap();
        let state = f.server.state.lock().unwrap();
        assert_eq!(
            state
                .requests
                .iter()
                .filter(|r| r.url.ends_with("/revoke"))
                .count(),
            1
        );
        assert_eq!(
            state
                .requests
                .iter()
                .filter(|r| r.url.ends_with("/token"))
                .count(),
            2
        );
    });
}

#[test]
fn discovery_failure_leaves_refresh_unused_but_invalid_grant_does_not() {
    block_on(async {
        let f = Fixture::new();
        f.login().await;
        f.server.state.lock().unwrap().fail_discovery = true;
        assert_eq!(f.client.refresh().await.unwrap_err(), AuthError::Transport);
        assert_eq!(f.token_posts(), 1);
        {
            let mut state = f.server.state.lock().unwrap();
            state.fail_discovery = false;
            state.token_status = Some(400);
        }
        assert!(matches!(
            f.client.refresh().await.unwrap_err(),
            AuthError::OAuth { .. }
        ));
        assert_eq!(
            f.client.refresh().await.unwrap_err(),
            AuthError::ReauthenticationRequired
        );
        assert_eq!(f.token_posts(), 2);
    });
}

#[test]
fn refresh_preserves_subject_rejects_nonce_and_token_reuse() {
    block_on(async {
        for mode in 0..4 {
            let f = Fixture::new();
            f.login().await;
            {
                let mut s = f.server.state.lock().unwrap();
                match mode {
                    0 => {
                        s.claims.insert("sub".into(), json!("other-user"));
                    }
                    1 => {
                        s.claims.insert("nonce".into(), json!("unexpected"));
                    }
                    2 => {
                        s.token
                            .insert("refresh_token".into(), json!("refresh-secret"));
                    }
                    _ => {
                        s.token
                            .insert("scope".into(), json!("openid profile offline_access phone"));
                    }
                }
            }
            let error = f.client.refresh().await.unwrap_err();
            assert!(matches!(
                error,
                AuthError::InvalidIdToken | AuthError::InvalidTokenResponse
            ));
            assert_eq!(
                f.restart().restore().unwrap(),
                SessionStatus::ReauthenticationRequired
            );
        }
    });
}

#[test]
fn refresh_can_reduce_scopes_and_remove_offline_access() {
    block_on(async {
        let f = Fixture::new();
        f.login().await;
        {
            let mut state = f.server.state.lock().unwrap();
            state.token.insert("scope".into(), json!("openid"));
            state.token.insert("refresh_token".into(), Value::Null);
        }
        let result = f.client.refresh().await.unwrap();
        assert_eq!(result.user.granted_scopes, ["openid"]);
        assert!(result.user.name.is_none());
        assert!(result.refresh_token.is_none());
        assert_eq!(
            f.client.refresh().await.unwrap_err(),
            AuthError::ReauthenticationRequired
        );
        assert_eq!(f.token_posts(), 2);
    });
}

#[test]
fn logout_invalidates_inflight_refresh_and_cannot_overwrite_new_login() {
    block_on(async {
        let f = Fixture::new();
        f.login().await;
        let (release, wait) = oneshot::channel();
        f.server.state.lock().unwrap().gate = Some(wait);
        let mut operation = Box::pin(f.client.refresh());
        assert!(futures::poll!(&mut operation).is_pending());
        assert_eq!(f.client.logout().await.unwrap(), LogoutStatus::Revoked);
        assert_eq!(f.restart().restore().unwrap(), SessionStatus::SignedOut);
        let restarted = f.restart();
        restarted
            .begin_sign_in(vec!["openid".into()])
            .await
            .unwrap();
        release.send(()).unwrap();
        assert_eq!(operation.await.unwrap_err(), AuthError::Cancelled);
        assert!(matches!(
            restarted.restore().unwrap(),
            SessionStatus::PendingLogin { .. }
        ));
    });
}

#[test]
fn offline_logout_persists_tombstone_and_retries_only_revoke() {
    block_on(async {
        let f = Fixture::new();
        f.login().await;
        f.server.state.lock().unwrap().fail_revoke = true;
        assert_eq!(
            f.client.logout().await.unwrap(),
            LogoutStatus::RevocationPending
        );
        let restarted = f.restart();
        assert_eq!(
            restarted.restore().unwrap(),
            SessionStatus::RevocationPending
        );
        assert_eq!(
            restarted.valid_session().await.unwrap_err(),
            AuthError::ReauthenticationRequired
        );
        f.server.state.lock().unwrap().fail_revoke = false;
        assert_eq!(restarted.logout().await.unwrap(), LogoutStatus::Revoked);
        assert_eq!(f.token_posts(), 1);
        assert_eq!(f.restart().restore().unwrap(), SessionStatus::SignedOut);
    });
}

#[test]
fn storage_errors_and_foreign_payload_are_not_signed_out_or_authenticated() {
    block_on(async {
        let f = Fixture::new();
        f.login().await;
        f.store.fail_load.store(true, Ordering::SeqCst);
        assert_eq!(f.client.restore().unwrap_err(), AuthError::Storage);
        assert_eq!(f.client.logout().await.unwrap_err(), AuthError::Storage);
        f.store.fail_load.store(false, Ordering::SeqCst);
        let mut config = config_json();
        config["client_id"] = json!("other-client");
        let other = SessionClient::with_clock(
            ClientConfig::from_console_json(&config.to_string(), REDIRECT).unwrap(),
            f.server.clone(),
            f.store.clone(),
            f.clock.clone(),
        );
        assert_eq!(other.restore().unwrap(), SessionStatus::SignedOut);
        {
            let mut entries = f.store.entries.lock().unwrap();
            let value = entries.values_mut().next().unwrap();
            let mut payload: Value = serde_json::from_str(&value.1).unwrap();
            payload["binding"] = json!("other-client");
            value.1 = payload.to_string();
        }
        assert_eq!(
            f.client.restore().unwrap_err(),
            AuthError::InvalidStoredState
        );
    });
}

#[test]
fn expired_pending_and_cancelled_code_exchange_cannot_resume() {
    block_on(async {
        let f = Fixture::new();
        let cb = f.pending().await;
        let (_release, wait) = oneshot::channel();
        f.server.state.lock().unwrap().gate = Some(wait);
        let mut operation = Box::pin(f.client.complete_sign_in(&cb));
        assert!(futures::poll!(&mut operation).is_pending());
        drop(operation);
        assert_eq!(
            f.restart().restore().unwrap(),
            SessionStatus::ReauthenticationRequired
        );
        assert_eq!(
            f.restart().complete_sign_in(&cb).await.unwrap_err(),
            AuthError::NoPendingLogin
        );
        let f = Fixture::new();
        f.pending().await;
        f.clock.0.store(NOW + 600, Ordering::SeqCst);
        assert_eq!(f.restart().restore().unwrap(), SessionStatus::SignedOut);
    });
}

#[test]
fn updated_public_config_does_not_strand_an_existing_session() {
    block_on(async {
        let f = Fixture::new();
        f.login().await;
        let mut config = config_json();
        config["scopes"] = json!(["openid"]);
        let updated = SessionClient::with_clock(
            ClientConfig::from_console_json(&config.to_string(), REDIRECT).unwrap(),
            f.server.clone(),
            f.store.clone(),
            f.clock.clone(),
        );
        assert!(matches!(
            updated.restore().unwrap(),
            SessionStatus::SignedIn { .. }
        ));
        assert_eq!(updated.logout().await.unwrap(), LogoutStatus::Revoked);
        assert_eq!(f.restart().restore().unwrap(), SessionStatus::SignedOut);
    });
}

#[test]
fn native_callback_routing_uses_the_same_exact_uri_rules() {
    block_on(async {
        let f = Fixture::new();
        let callback = f.pending().await;
        assert!(f.client.is_callback_url(&callback));
        // Routing is not validation: state must still be checked at completion.
        assert!(f
            .client
            .is_callback_url(&callback.replace("state=", "state=bad")));
        for invalid in [
            callback.replace("/callback", "/callback/extra"),
            format!("{callback}&state=duplicate"),
            format!("{callback}&unregistered=value"),
            format!("{callback}#fragment"),
            "https://other.example.test/callback".into(),
        ] {
            assert!(!f.client.is_callback_url(&invalid));
        }
        f.client.complete_sign_in(&callback).await.unwrap();
        assert_eq!(f.token_posts(), 1);
    });
}
