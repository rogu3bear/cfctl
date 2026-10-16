use super::{pages_deployment, pages_preview, verify_with_executor};
use crate::runtime::prelude::{
    AdapterStatus, AuthCredential, CapabilityV1, CatalogSnapshot, Executor, PlanV1,
    ResponseBodyModeV1, Value, json,
};
use cfctl_core::{ResponseContractV1, SelectorV1, hash_value};
use std::collections::BTreeMap;

const ID: &str = "22222222-2222-4222-8222-222222222222";
const COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn fixture() -> (CatalogSnapshot, PlanV1, Value, Value, Value) {
    let project = json!({"name":"aos-web","production_branch":"main","subdomain":"aos-web.pages.dev","source":null,
        "canonical_deployment":null,"deployment_configs":{"production":{"env_vars":{"PRIVATE":{"value":"do-not-retain"}}}}});
    let deployment = json!({"id":ID,"project_name":"aos-web","environment":"preview","url":"https://abc.aos-web.pages.dev",
        "aliases":["https://stage.aos-web.pages.dev"],"latest_stage":{"name":"deploy","status":"success"},
        "deployment_trigger":{"metadata":{"branch":"stage","commit_hash":COMMIT}}});
    let receipt = json!({"structured_output":{"deployment_id":ID,"pages_project":"aos-web","environment":"preview",
        "production_branch":"main","url":"https://abc.aos-web.pages.dev","alias":"https://stage.aos-web.pages.dev",
        "deployment_trigger":{"metadata":{"commit_hash":COMMIT}}}});
    let mut catalog = CatalogSnapshot {
        schema_version: 1,
        generated_at: chrono::Utc::now(),
        source_url: "fixture://pages".to_owned(),
        source_hash: "source".to_owned(),
        schema_hash: "catalog".to_owned(),
        capabilities: BTreeMap::new(),
    };
    cfctl_catalog::ingest_wrangler_pages_deploy_help(
        &mut catalog,
        "4.107.0",
        "wrangler pages deploy [directory] --project-name --branch --commit-hash --commit-message",
    );
    for (id, path) in [
        (
            pages_deployment::PROJECT_READ_CAPABILITY_ID,
            pages_deployment::PROJECT_DETAIL_PATH,
        ),
        (
            pages_deployment::DEPLOYMENT_READ_CAPABILITY_ID,
            pages_deployment::DEPLOYMENT_DETAIL_PATH,
        ),
    ] {
        let mut cap = CapabilityV1::new(id, "Pages read", "GET", path);
        cap.adapter_status = AdapterStatus::DynamicApi;
        cap.response_contract = Some(ResponseContractV1 {
            success_statuses: vec!["200".to_owned()],
            success_media_types: vec!["application/json".to_owned()],
            body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
        });
        cap.selectors = ["account_id", "project_name"]
            .into_iter()
            .chain(
                (id == pages_deployment::DEPLOYMENT_READ_CAPABILITY_ID).then_some("deployment_id"),
            )
            .map(|name| SelectorV1 {
                name: name.to_owned(),
                location: "path".to_owned(),
                required: true,
                value_type: "string".to_owned(),
                description: None,
                contract: None,
            })
            .collect();
        catalog.capabilities.insert(id.to_owned(), cap);
    }
    let cap = catalog
        .get(pages_deployment::DIRECT_UPLOAD_CAPABILITY_ID)
        .expect("upload")
        .clone();
    let mut plan =
        PlanV1::draft("profile-a", "account-a", "catalog", cap, json!({})).expect("plan");
    plan.input = json!({
        "selectors":{},"query":{"environment":"preview","project_name":"aos-web","branch":"stage","commit_hash":COMMIT}
    });
    let admission = json!({"schema_version":1,"source_capability_id":pages_deployment::PROJECT_READ_CAPABILITY_ID,
        "target_capability_id":pages_deployment::DIRECT_UPLOAD_CAPABILITY_ID,"account_id":"account-a","project_name":"aos-web",
        "source_mode":"direct_upload","source_mode_basis":"explicit_null_source","production_branch":"main",
        "deployment_environment":"preview","requested_branch":"stage","prior_deployment_ids":[],"prior_exact_identity_count":0,
        "protected_production":pages_preview::protected_snapshot(&project,"aos-web","main").expect("protected")});
    plan.targets = json!({"live_preconditions":{}});
    plan.targets["live_preconditions"][pages_deployment::PROJECT_STATE_PRECONDITION] =
        admission.clone();
    plan.precondition_hashes.insert(
        pages_deployment::PROJECT_STATE_PRECONDITION.to_owned(),
        hash_value(&admission).expect("hash"),
    );
    (catalog, plan, receipt, deployment, project)
}

async fn server(values: Vec<Value>) -> (Executor, tokio::task::JoinHandle<Vec<String>>) {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback fixture");
    let address = listener.local_addr().expect("address");
    let task = tokio::spawn(async move {
        let mut paths = Vec::new();
        for value in values {
            let (mut stream, _) =
                tokio::time::timeout(std::time::Duration::from_secs(10), listener.accept())
                    .await
                    .expect("bounded fixture request")
                    .expect("fixture request");
            let mut bytes = vec![0; 16384];
            let n = stream.read(&mut bytes).await.expect("request");
            let request = String::from_utf8(bytes[..n].to_vec()).expect("UTF8 request");
            paths.push(request.lines().next().expect("request line").to_owned());
            let body = json!({"success":true,"result":value,"errors":[]}).to_string();
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.expect("response");
        }
        paths
    });
    (
        Executor::new(
            reqwest::Client::new(),
            &format!("http://{address}/client/v4"),
        )
        .expect("fixture executor"),
        task,
    )
}

#[tokio::test]
async fn exact_preview_read_then_protected_project_join_returns_safe_typed_identity() {
    let (catalog, plan, receipt, deployment, project) = fixture();
    let (executor, task) = server(vec![deployment, project]).await;
    let identity = verify_with_executor(
        &catalog,
        &plan,
        &receipt,
        &AuthCredential::Bearer {
            token: "test-token".to_owned(),
        },
        &executor,
    )
    .await
    .expect("verified preview");
    assert_eq!(identity.deployment_id, ID);
    assert_eq!(identity.branch, "stage");
    assert!(identity.canonical_production_preserved);
    assert!(
        !serde_json::to_string(&identity)
            .expect("safe identity")
            .contains("do-not-retain")
    );
    let paths = task.await.expect("fixture complete");
    assert_eq!(
        paths,
        vec![
            format!(
                "GET /client/v4/accounts/account-a/pages/projects/aos-web/deployments/{ID} HTTP/1.1"
            ),
            "GET /client/v4/accounts/account-a/pages/projects/aos-web HTTP/1.1".to_owned()
        ]
    );
}

#[tokio::test]
async fn changed_production_after_exact_preview_success_still_fails() {
    let (catalog, plan, receipt, deployment, mut project) = fixture();
    project["production_branch"] = json!("stage");
    let (executor, task) = server(vec![deployment, project]).await;
    assert!(
        verify_with_executor(
            &catalog,
            &plan,
            &receipt,
            &AuthCredential::Bearer {
                token: "test-token".to_owned()
            },
            &executor
        )
        .await
        .is_err()
    );
    assert_eq!(task.await.expect("fixture complete").len(), 2);
}

#[tokio::test]
async fn old_id_and_rehashed_wrong_intent_refuse_before_any_read() {
    let (catalog, mut plan, receipt, _, _) = fixture();
    let executor = Executor::new(reqwest::Client::new(), "http://127.0.0.1:1/client/v4")
        .expect("unused executor");
    let admission =
        &mut plan.targets["live_preconditions"][pages_deployment::PROJECT_STATE_PRECONDITION];
    admission["prior_deployment_ids"] = json!([ID]);
    plan.precondition_hashes.insert(
        pages_deployment::PROJECT_STATE_PRECONDITION.to_owned(),
        hash_value(admission).expect("rebound fixture"),
    );
    let error = verify_with_executor(
        &catalog,
        &plan,
        &receipt,
        &AuthCredential::Bearer {
            token: "test-token".to_owned(),
        },
        &executor,
    )
    .await
    .expect_err("replay blocked");
    assert!(error.to_string().contains("existed before upload"));
    plan.input["query"]["branch"] = json!("main");
    assert!(
        verify_with_executor(
            &catalog,
            &plan,
            &receipt,
            &AuthCredential::Bearer {
                token: "test-token".to_owned()
            },
            &executor
        )
        .await
        .is_err()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn governed_preview_passes_branch_and_strips_local_intent_controls_from_helper_argv() {
    use std::os::unix::fs::PermissionsExt;
    let (catalog, plan, receipt, _, _) = fixture();
    let root = tempfile::tempdir().expect("fake helper");
    let program = root.path().join("wrangler");
    let basic = json!({"type":"pages-deploy","version":1,"pages_project":"aos-web","deployment_id":ID,"url":"https://abc.aos-web.pages.dev"});
    let mut detailed = receipt["structured_output"].clone();
    detailed["type"] = json!("pages-deploy-detailed");
    detailed["version"] = json!(1);
    std::fs::write(&program,format!("#!/bin/sh\nfor arg do\n case \"$arg\" in --environment*|--artifact-receipt*) exit 97;; esac\ndone\nprintf '%s\\n' \"$@\"\nprintf '%s\\n' '{basic}' '{detailed}' > \"$WRANGLER_OUTPUT_FILE_PATH\"\n")).expect("helper script");
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700))
        .expect("helper mode");
    let mut input: cfctl_cloudflare::CallInput = serde_json::from_value(plan.input).expect("input");
    input.query["argument"] = json!(root.path());
    input.query["artifact_receipt"] = json!("sha256:test-only-local-control");
    let result = crate::runtime::governed_cli::run_delegated_cli(
        catalog
            .get(pages_deployment::DIRECT_UPLOAD_CAPABILITY_ID)
            .expect("upload"),
        &input,
        &AuthCredential::Bearer {
            token: "fixture-token".to_owned(),
        },
        Some("account-a"),
        root.path(),
        Some(&program),
        Some(std::path::Path::new("/bin/sh")),
    )
    .await
    .expect("governed local fixture");
    assert_eq!(result["success"], true);
    let stdout = result["stdout"]
        .as_str()
        .expect("observed helper arguments");
    assert!(stdout.contains("--branch\nstage\n"));
    assert!(stdout.contains("--no-bundle"));
    assert!(!stdout.contains("environment"));
    assert!(!stdout.contains("artifact-receipt"));
    assert_eq!(result["structured_output"]["environment"], "preview");
}
