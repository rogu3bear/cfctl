#![allow(clippy::expect_used)]
use super::{finish, prepare};
use cfctl_cloudflare::{CallInput, CloudflareResponseV1};
use cfctl_core::{
    CapabilityV1, ResponseBodyModeV1, ResponseContractV1, SelectorContractV1, SelectorV1,
    turnstile_secret,
};
use serde_json::json;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

fn capability() -> CapabilityV1 {
    let mut c = CapabilityV1::new(
        turnstile_secret::ID,
        "Widget",
        "GET",
        turnstile_secret::PATH,
    );
    c.product = "Turnstile".into();
    c.account_scope = "account".into();
    c.permissions = [
        "Turnstile Sites Write",
        "Turnstile Sites Read",
        "Account Settings Write",
        "Account Settings Read",
    ]
    .map(str::to_owned)
    .to_vec();
    c.selectors = ["account_id", "sitekey"]
        .map(|name| SelectorV1 {
            name: name.into(),
            location: "path".into(),
            required: true,
            value_type: "string".into(),
            description: None,
            contract: Some(SelectorContractV1 {
                schema: json!({"type":"string","maxLength":32}),
                query: None,
            }),
        })
        .to_vec();
    c.verification.strategy = turnstile_secret::VERIFY.into();
    c.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".into()],
        success_media_types: vec!["application/json".into()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    c
}

fn response(sitekey: &str) -> CloudflareResponseV1 {
    CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"sitekey":sitekey,"secret":"synthetic-private-widget","unexpected":"synthetic-private-widget"}),
        errors: vec![],
        result_info: Some(json!({"echo":"synthetic-private-widget"})),
        etag: Some("synthetic-private-widget".into()),
        cf_ray: None,
    }
}

#[test]
fn handoff_widget_secret_only_reaches_exclusive_private_sink() {
    let root = tempfile::tempdir().expect("temp");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private dir");
    let path = root.path().join("secret");
    let cap = capability();
    let mut file = prepare(&cap, Some(&path)).expect("private sink");
    assert_eq!(
        fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
        0o600
    );
    let input = CallInput {
        selectors: json!({"account_id":"account","sitekey":"widget"}),
        ..CallInput::default()
    };
    let safe = finish(response("widget"), &input, &mut file).expect("sink");
    assert!(safe.success);
    assert_eq!(
        fs::read_to_string(&path).expect("private value"),
        "synthetic-private-widget"
    );
    assert!(
        !serde_json::to_string(&safe)
            .expect("safe receipt")
            .contains("synthetic-private-widget")
    );
    assert!(prepare(&cap, Some(&path)).is_err());
    let link = root.path().join("link");
    symlink(&path, &link).expect("link");
    assert!(prepare(&cap, Some(&link)).is_err());
    assert!(prepare(&cap, None).is_err());
    assert!(super::super::secret_io::is_secret_output_capability(&cap));
    assert!(
        super::super::guide_generation::capability_call_argv(&cap)
            .iter()
            .any(|s| s == "--value-out")
    );
}

#[test]
fn handoff_widget_secret_rejects_identity_missing_value_and_unsafe_destination() {
    let root = tempfile::tempdir().expect("temp");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private dir");
    let cap = capability();
    let path = root.path().join("secret");
    let mut file = prepare(&cap, Some(&path)).expect("sink");
    let input = CallInput {
        selectors: json!({"sitekey":"widget"}),
        ..CallInput::default()
    };
    let safe = finish(response("other-widget"), &input, &mut file).expect("failure receipt");
    assert!(!safe.success);
    assert_eq!(fs::metadata(&path).expect("file").len(), 0);
    let mut missing = response("widget");
    missing
        .result
        .as_object_mut()
        .expect("object")
        .remove("secret");
    let failed = finish(missing, &input, &mut file).expect("safe missing-secret receipt");
    assert!(!failed.success);
    assert_eq!(failed.result["outcome"], "secret_missing");
    assert_eq!(fs::metadata(&path).expect("file").len(), 0);
    fs::create_dir(root.path().join(".git")).expect("git marker");
    assert!(prepare(&cap, Some(&root.path().join("in-repo"))).is_err());
    fs::remove_dir(root.path().join(".git")).expect("remove fixture");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).expect("public dir");
    assert!(prepare(&cap, Some(&root.path().join("unsafe"))).is_err());
}

#[tokio::test]
async fn handoff_widget_http_response_and_errors_never_echo_secret_material() {
    for malformed in [false, true] {
        let root = tempfile::tempdir().expect("temp");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private dir");
        let path = root.path().join("secret");
        let cap = capability();
        let mut sink = prepare(&cap, Some(&path)).expect("sink before request");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut bytes = [0; 8192];
            let len = socket.read(&mut bytes).await.expect("request");
            assert!(
                String::from_utf8_lossy(&bytes[..len])
                    .starts_with("GET /accounts/account/challenges/widgets/widget ")
            );
            let body = if malformed {
                "malformed synthetic-private-widget"
            } else {
                r#"{"success":true,"result":{"sitekey":"widget","secret":"synthetic-private-widget"},"errors":[]}"#
            };
            let wire = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(wire.as_bytes()).await.expect("response");
        });
        let executor =
            cfctl_cloudflare::Executor::new(reqwest::Client::new(), &format!("http://{address}"))
                .expect("executor");
        let input = CallInput {
            selectors: json!({"account_id":"account","sitekey":"widget"}),
            ..CallInput::default()
        };
        let result = super::fetch(
            &executor,
            &cap,
            &input,
            &cfctl_auth::AuthCredential::Bearer {
                token: "test-token".into(),
            },
            &mut sink,
        )
        .await;
        if malformed {
            let error = result
                .expect_err("malformed response fails closed")
                .to_string();
            assert!(!error.contains("synthetic-private-widget"));
            assert_eq!(fs::metadata(&path).expect("file").len(), 0);
        } else {
            let safe = result.expect("read");
            assert!(safe.success);
            assert_eq!(
                fs::read_to_string(&path).expect("private secret"),
                "synthetic-private-widget"
            );
            assert!(
                !serde_json::to_string(&safe)
                    .expect("receipt")
                    .contains("synthetic-private-widget")
            );
        }
        server.await.expect("server");
    }
}
