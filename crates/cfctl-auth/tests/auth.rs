#![allow(clippy::expect_used, clippy::unwrap_used)]

use cfctl_auth::{
    AccountRef, AccountSelectionError, MemorySecretStore, OAuthClientConfig, OAuthTokenSet,
    PkceSession, ProfileKind, ProfileMetadata, SecretStore, exchange_authorization_code,
    refresh_oauth_tokens, resolve_account, revoke_oauth_token,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[test]
fn cloudflare_cli_oauth_uses_pkce_s256_and_never_embeds_a_client_secret() {
    let config = OAuthClientConfig::cfctl_public("public-client-id");
    let session = PkceSession::begin(&config, &["account.read", "workers-platform.write"])
        .expect("PKCE session");
    let url = session.authorization_url.as_str();

    assert!(url.starts_with("https://dash.cloudflare.com/oauth2/auth?"));
    assert!(url.contains("code_challenge_method=S256"));
    assert!(url.contains("client_id=public-client-id"));
    assert!(!url.contains("client_secret"));
    assert!(session.code_verifier.len() >= 43);
}

#[test]
fn secret_store_keeps_oauth_tokens_out_of_profile_metadata() {
    let store = MemorySecretStore::default();
    let tokens = OAuthTokenSet::from_json(
        r#"{"access_token":"access-value","refresh_token":"refresh-value","token_type":"Bearer","expires_in":3600,"scope":"workers-platform.read"}"#,
    )
    .expect("token response");
    store
        .store_oauth_tokens("default", &tokens)
        .expect("store tokens");

    let credential = store
        .load_credential("default", ProfileKind::OAuth)
        .expect("load credential");
    assert_eq!(credential.bearer_token(), Some("access-value"));
    assert!(!format!("{credential:?}").contains("access-value"));
}

#[test]
fn api_token_profiles_store_bearer_credentials_outside_profile_metadata() {
    let store = MemorySecretStore::default();
    store
        .store_api_token("default", "cf-api-token-value")
        .expect("store api token");
    let credential = store
        .load_credential("default", ProfileKind::ApiToken)
        .expect("load api token");
    assert_eq!(credential.bearer_token(), Some("cf-api-token-value"));
    assert!(!format!("{credential:?}").contains("cf-api-token-value"));
    let profile = ProfileMetadata::new("default", ProfileKind::ApiToken, Some("account-a"));
    assert!(!profile.emergency_only);
    assert!(profile.credential_generation_id.is_some());
    let json = serde_json::to_string(&profile).expect("profile serializes");
    assert!(!json.contains("cf-api-token-value"));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&json).expect("profile json")["kind"],
        "api_token"
    );
}

#[test]
fn immutable_api_token_slots_switch_profiles_without_overwriting_the_old_generation() {
    let store = MemorySecretStore::default();
    store
        .store_api_token("publisher", "legacy-token")
        .expect("store legacy token");
    let mut profile = ProfileMetadata::new("publisher", ProfileKind::ApiToken, Some("account-a"));
    assert_eq!(
        store
            .load_profile_credential(&profile)
            .expect("legacy profile credential")
            .bearer_token(),
        Some("legacy-token")
    );

    let slot_id = "11111111-1111-4111-8111-111111111111";
    store
        .store_api_token_slot(slot_id, "fresh-token")
        .expect("stage immutable slot");
    assert_eq!(
        store
            .load_profile_credential(&profile)
            .expect("unswitched profile still uses legacy credential")
            .bearer_token(),
        Some("legacy-token")
    );

    profile.api_token_slot_id = Some(slot_id.to_owned());
    assert_eq!(
        store
            .load_profile_credential(&profile)
            .expect("switched profile uses staged slot")
            .bearer_token(),
        Some("fresh-token")
    );
    store
        .delete_profile("publisher")
        .expect("retire legacy profile-keyed credential");
    assert_eq!(
        store
            .load_profile_credential(&profile)
            .expect("active immutable slot survives legacy cleanup")
            .bearer_token(),
        Some("fresh-token")
    );
    assert_eq!(
        store
            .locate_api_token("publisher")
            .expect("legacy credential location"),
        None
    );
    store
        .delete_api_token_slot(slot_id)
        .expect("delete retired slot");
    assert!(
        store.load_profile_credential(&profile).is_err(),
        "a removed active slot fails closed instead of falling back to stale profile material"
    );
}

#[test]
fn global_key_profiles_require_an_email_and_are_explicitly_emergency_only() {
    let store = MemorySecretStore::default();
    store
        .store_global_key("emergency", "owner@example.com", "global-key-value")
        .expect("store global key");
    let credential = store
        .load_credential("emergency", ProfileKind::GlobalKey)
        .expect("load global key");
    assert_eq!(credential.global_email(), Some("owner@example.com"));
    assert_eq!(credential.global_key(), Some("global-key-value"));
    assert!(ProfileMetadata::new("emergency", ProfileKind::GlobalKey, None).emergency_only);
}

#[test]
fn ambiguous_account_selection_fails_closed() {
    let accounts = vec![
        AccountRef::new("a", "Account A"),
        AccountRef::new("b", "Account B"),
    ];
    assert_eq!(
        resolve_account(&accounts, None, None),
        Err(AccountSelectionError::Ambiguous { count: 2 })
    );
    assert_eq!(
        resolve_account(&accounts, Some("b"), None)
            .expect("explicit account")
            .id,
        "b"
    );
}

#[test]
fn profile_metadata_contains_no_credentials() {
    let profile = ProfileMetadata::new("default", ProfileKind::OAuth, Some("account-a"));
    let json = serde_json::to_string(&profile).expect("profile serializes");
    assert!(!json.contains("access_token"));
    assert!(!json.contains("global_key"));
    assert!(json.contains("credential_generation_id"));
}

#[test]
fn pre_generation_profiles_remain_unbound_until_reauthentication() {
    let governed: ProfileMetadata = serde_json::from_str(
        r#"{"schema_version":1,"id":"default","kind":"api_token","account_id":"account-a","oauth_client_id":null,"oauth_scopes":[],"oauth_scope_inventory_hash":null,"emergency_only":false}"#,
    )
    .expect("old governed profile");
    assert!(governed.credential_generation_id.is_none());

    let legacy: ProfileMetadata = serde_json::from_str(
        r#"{"schema_version":1,"id":"legacy","kind":"wrangler_session","account_id":"account-a","oauth_client_id":null,"oauth_scopes":[],"oauth_scope_inventory_hash":null,"emergency_only":false}"#,
    )
    .expect("legacy profile");
    assert!(legacy.credential_generation_id.is_none());
}

#[test]
fn legacy_wrangler_session_metadata_is_readable_but_never_a_credential_lane() {
    let encoded = r#"{
        "schema_version": 1,
        "id": "legacy",
        "kind": "wrangler_session",
        "account_id": "account-a",
        "oauth_client_id": null,
        "oauth_scopes": [],
        "oauth_scope_inventory_hash": null,
        "emergency_only": false
    }"#;
    let profile: ProfileMetadata =
        serde_json::from_str(encoded).expect("legacy metadata remains readable for removal");
    assert_eq!(
        serde_json::to_value(&profile).expect("legacy metadata serializes")["kind"],
        "wrangler_session"
    );

    let error = MemorySecretStore::default()
        .load_credential(&profile.id, profile.kind)
        .expect_err("legacy Wrangler metadata is not an auth credential");
    assert!(error.to_string().contains("no longer supported"));
}

#[tokio::test]
async fn oauth_exchange_refresh_and_revoke_use_public_client_flows() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake OAuth server");
    let address = listener.local_addr().expect("OAuth server address");
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for response_body in [
            r#"{"access_token":"first","refresh_token":"refresh-one","token_type":"Bearer","expires_in":1,"scope":"account.read"}"#,
            r#"{"access_token":"second","token_type":"Bearer","expires_in":3600,"scope":"account.read"}"#,
            "",
        ] {
            let (mut stream, _) = listener.accept().await.expect("accept OAuth request");
            let mut buffer = vec![0_u8; 8192];
            let read = stream.read(&mut buffer).await.expect("read OAuth request");
            requests.push(String::from_utf8_lossy(&buffer[..read]).to_string());
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
                response_body.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write OAuth response");
        }
        requests
    });
    let endpoint = format!("http://{address}/oauth2");
    let config = OAuthClientConfig {
        client_id: "public-client".to_owned(),
        authorization_endpoint: format!("{endpoint}/auth"),
        token_endpoint: format!("{endpoint}/token"),
        revoke_endpoint: format!("{endpoint}/revoke"),
        redirect_uri: "https://cfctl.io/oauth/callback".to_owned(),
    };
    let client = reqwest::Client::new();
    let exchanged = exchange_authorization_code(&client, &config, "code-one", "verifier-one")
        .await
        .expect("exchange token");
    assert_eq!(exchanged.access_token(), "first");
    let refreshed = refresh_oauth_tokens(&client, &config, "refresh-one")
        .await
        .expect("refresh token");
    assert_eq!(refreshed.access_token(), "second");
    assert_eq!(refreshed.refresh_token(), Some("refresh-one"));
    revoke_oauth_token(&client, &config, "refresh-one")
        .await
        .expect("revoke token");
    let requests = server.await.expect("OAuth server joins");
    assert!(requests[0].contains("grant_type=authorization_code"));
    assert!(requests[0].contains("code_verifier=verifier-one"));
    assert!(requests[1].contains("grant_type=refresh_token"));
    assert!(requests[2].contains("token=refresh-one"));
    assert!(
        requests
            .iter()
            .all(|request| !request.contains("client_secret"))
    );
}
