use super::*;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

fn arguments(complete: bool) -> AuthLoginArgs {
    AuthLoginArgs {
        profile: "oauth-fixture".into(),
        client_id: Some("explicit-fixture-client".into()),
        scopes: vec!["scope-fixture".into()],
        account: Some("account-fixture".into()),
        complete,
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "One real token exchange matrix covers new login, supported reauthentication and concurrent foreign-kind replacement."
)]
async fn oauth_completion_preserves_new_and_existing_profiles_and_refuses_exchange_time_drift() {
    for case in ["new", "reauth", "foreign-drift"] {
        let root = tempfile::tempdir().expect("root");
        let store = authenticated_test_store(RuntimePaths::from_root(root.path()));
        let secrets = MemorySecretStore::default();
        let mut profiles = ProfilesConfig::default();
        profiles.profiles.insert(
            "retained".into(),
            ProfileMetadata::new("retained", ProfileKind::ApiToken, Some("retained-account")),
        );
        profiles.current_profile = Some("retained".into());
        if case == "reauth" {
            profiles.profiles.insert(
                "oauth-fixture".into(),
                ProfileMetadata::new("oauth-fixture", ProfileKind::OAuth, Some("account-fixture")),
            );
        }
        profiles.save(&store).expect("initial state");
        let retained = profiles.profiles["retained"].clone();
        begin_oauth_login(&store, &mut profiles, &secrets, arguments(false))
            .await
            .expect("PKCE begin");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback");
        let endpoint = format!("http://{}/token", listener.local_addr().expect("address"));
        let pending = profiles
            .pending_logins
            .get_mut("oauth-fixture")
            .expect("pending");
        pending.client.token_endpoint = endpoint;
        let state = pending.state.clone();
        profiles.save(&store).expect("local fixture endpoint");
        let drift_store = store.clone();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("exchange");
            let mut request = Vec::new();
            loop {
                let mut bytes = [0; 2048];
                let count = socket.read(&mut bytes).await.expect("read");
                assert!(count > 0 && request.len() < 16_384);
                request.extend_from_slice(&bytes[..count]);
                if let Some(boundary) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..boundary]);
                    let length: usize = headers
                        .lines()
                        .find_map(|line| {
                            line.to_lowercase()
                                .strip_prefix("content-length:")
                                .map(str::trim)
                                .and_then(|n| n.parse().ok())
                        })
                        .expect("length");
                    if request.len() >= boundary + 4 + length {
                        break;
                    }
                }
            }
            let request = String::from_utf8(request).expect("request text");
            assert!(request.starts_with("POST /token "));
            assert!(request.contains("grant_type=authorization_code"));
            assert!(request.contains("client_id=explicit-fixture-client"));
            assert!(request.contains("code_verifier="));
            if case == "foreign-drift" {
                let mut current = ProfilesConfig::load(&drift_store).expect("drift current");
                current.profiles.insert(
                    "oauth-fixture".into(),
                    ProfileMetadata::new(
                        "oauth-fixture",
                        ProfileKind::ApiToken,
                        Some("foreign-account"),
                    ),
                );
                current
                    .save(&drift_store)
                    .expect("inject concurrent foreign identity");
            }
            let body = r#"{"access_token":"fixture-oauth-access","refresh_token":"fixture-oauth-refresh","token_type":"bearer","expires_in":3600,"scope":"scope-fixture"}"#;
            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.expect("response");
        });
        let result =
            complete_oauth_login_using(&store, &mut profiles, &secrets, arguments(true), || {
                Ok(format!("{state} fixture-code"))
            })
            .await;
        server.await.expect("fixture server");
        let current = ProfilesConfig::load(&store).expect("durable state");
        assert_eq!(
            serde_json::to_value(&current.profiles["retained"]).expect("retained"),
            serde_json::to_value(retained).expect("original")
        );
        if case == "foreign-drift" {
            assert!(
                result
                    .expect_err("concurrent replacement")
                    .to_string()
                    .contains("profile state changed")
            );
            assert_eq!(
                current.profiles["oauth-fixture"].kind,
                ProfileKind::ApiToken
            );
            assert_eq!(
                current.profiles["oauth-fixture"].account_id.as_deref(),
                Some("foreign-account")
            );
            assert_eq!(current.current_profile.as_deref(), Some("retained"));
            assert!(
                secrets
                    .get("profile/oauth-fixture/oauth")
                    .expect("no installed tokens")
                    .is_none()
            );
            assert!(current.pending_logins.contains_key("oauth-fixture"));
        } else {
            result.expect("supported completion");
            let profile = &current.profiles["oauth-fixture"];
            assert_eq!(profile.kind, ProfileKind::OAuth);
            assert_eq!(profile.account_id.as_deref(), Some("account-fixture"));
            assert_eq!(current.current_profile.as_deref(), Some("oauth-fixture"));
            assert!(!current.pending_logins.contains_key("oauth-fixture"));
            let token = secrets
                .load_profile_oauth_tokens(profile)
                .expect("installed tokens");
            assert_eq!(token.access_token(), "fixture-oauth-access");
            assert!(
                secrets
                    .get("pending/oauth-fixture/pkce-verifier")
                    .expect("verifier removed")
                    .is_none()
            );
        }
    }
}
