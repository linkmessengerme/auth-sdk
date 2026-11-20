use super::*;

async fn phone_fixture() -> Fixture {
    let mut f = Fixture::new();
    let mut config = regional_config_json();
    let scopes = vec![
        "openid".into(),
        "profile".into(),
        "offline_access".into(),
        "phone".into(),
    ];
    config["scopes"] = json!(scopes);
    f.client = session_with_config(&f.server, &f.clock, &f.store, config);
    regional_discovery(&f.server);
    {
        let mut state = f.server.state.lock().unwrap();
        state
            .discovery
            .insert("scopes_supported".into(), json!(scopes));
        state
            .token
            .insert("scope".into(), json!("openid profile offline_access phone"));
    }
    let callback = f.pending_scopes(scopes).await;
    f.client.complete_sign_in(&callback).await.unwrap();
    f
}

#[test]
fn userinfo_is_fresh_scoped_subject_bound_and_never_persisted() {
    block_on(async {
        let f = phone_fixture().await;
        let stored = f.store.entries.lock().unwrap().clone();
        let before = f.server.state.lock().unwrap().requests.len();
        let info = f.client.get_user_info().await.unwrap();
        assert_eq!(info.subject, "opaque-project-test-sub");
        assert_eq!(info.name.as_deref(), Some("Current Name"));
        assert_eq!(info.phone_number.as_deref(), Some("+12025550123"));
        assert_eq!(info.phone_number_verified, None);
        assert!(!format!("{info:?}").contains("1202555"));
        {
            let mut state = f.server.state.lock().unwrap();
            assert_eq!(state.requests.len(), before + 1);
            let request = state.requests.last().unwrap();
            assert_eq!(request.url, format!("{REGIONAL_API}/oauth/v1/userinfo"));
            assert_eq!(request.method, link_auth_core::HttpMethod::Get);
            assert!(request.body.is_empty());
            assert!(request
                .headers
                .contains(&("Authorization".into(), "Bearer access-secret".into())));
            assert!(request
                .headers
                .contains(&("Cache-Control".into(), "no-store".into())));
            state.userinfo = Some(json!({"sub": info.subject})); // consent/phone can disappear
        }
        assert_eq!(f.client.get_user_info().await.unwrap().phone_number, None);
        assert_eq!(*f.store.entries.lock().unwrap(), stored);
    });
}

#[test]
fn userinfo_refreshes_before_reading_and_filters_ungranted_fields() {
    block_on(async {
        let f = Fixture::new();
        f.login().await;
        assert_eq!(f.client.get_user_info().await.unwrap().phone_number, None);
        f.near_expiry();
        {
            let mut state = f.server.state.lock().unwrap();
            state.token.insert("scope".into(), json!("openid"));
            state.token.insert("refresh_token".into(), Value::Null);
            state
                .token
                .insert("access_token".into(), json!("current-access"));
        }
        let info = f.client.get_user_info().await.unwrap();
        assert_eq!(info.name, None);
        assert_eq!(info.preferred_username, None);
        assert_eq!(info.picture, None);
        assert_eq!(info.phone_number, None);
        assert_eq!(f.token_posts(), 2);
        assert!(f
            .server
            .state
            .lock()
            .unwrap()
            .requests
            .last()
            .unwrap()
            .headers
            .contains(&("Authorization".into(), "Bearer current-access".into())));
    });
}

#[test]
fn userinfo_rejects_wrong_subject_invalid_fields_redirects_and_large_responses() {
    block_on(async {
        let f = phone_fixture().await;
        for body in [
            json!({"sub": "other-user", "phone_number": "+12025550123"}),
            json!({"name": "missing-sub"}),
            json!({"sub": "opaque-project-test-sub", "phone_number": 12025550123u64}),
            json!({"sub": "opaque-project-test-sub", "phone_number": "bad-number"}),
            json!({"sub": "opaque-project-test-sub", "phone_number_verified": "true"}),
        ] {
            f.server.state.lock().unwrap().userinfo = Some(body);
            assert_eq!(
                f.client.get_user_info().await.unwrap_err(),
                AuthError::InvalidResponse
            );
        }
        f.server.state.lock().unwrap().userinfo = None;
        f.server.state.lock().unwrap().redirect_response = true;
        assert_eq!(
            f.client.get_user_info().await.unwrap_err(),
            AuthError::InvalidResponse
        );
        f.server.state.lock().unwrap().redirect_response = false;
        f.server.state.lock().unwrap().oversized_response = true;
        assert_eq!(
            f.client.get_user_info().await.unwrap_err(),
            AuthError::InvalidResponse
        );
    });
}

#[test]
fn userinfo_errors_do_not_retry_or_return_cached_data() {
    block_on(async {
        let f = Fixture::new();
        assert_eq!(
            f.client.get_user_info().await.unwrap_err(),
            AuthError::ReauthenticationRequired
        );
        assert!(f.server.state.lock().unwrap().requests.is_empty());
        f.login().await;
        for status in [401, 403, 503] {
            f.server.state.lock().unwrap().userinfo_status = Some(status);
            let before = f.server.state.lock().unwrap().requests.len();
            assert_eq!(
                f.client.get_user_info().await.unwrap_err(),
                AuthError::Http { status }
            );
            assert_eq!(f.server.state.lock().unwrap().requests.len(), before + 1);
        }
        assert_eq!(f.token_posts(), 1);
    });
}

#[test]
fn userinfo_cannot_finish_after_logout_session_replacement_or_expiry() {
    block_on(async {
        for mode in 0..3 {
            let f = phone_fixture().await;
            let (release, wait) = oneshot::channel();
            f.server.state.lock().unwrap().userinfo_gate = Some(wait);
            let mut operation = Box::pin(f.client.get_user_info());
            assert!(futures::poll!(&mut operation).is_pending());
            match mode {
                0 => {
                    f.client.logout().await.unwrap();
                }
                1 => {
                    f.client.refresh().await.unwrap();
                }
                _ => {
                    f.clock.0.store(NOW + 3600, Ordering::SeqCst);
                }
            }
            release.send(()).unwrap();
            assert_eq!(
                operation.await.unwrap_err(),
                if mode == 2 {
                    AuthError::Expired
                } else {
                    AuthError::Cancelled
                }
            );
        }
    });
}
