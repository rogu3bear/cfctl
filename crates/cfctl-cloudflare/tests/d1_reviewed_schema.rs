#![allow(clippy::expect_used)]

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use cfctl_auth::AuthCredential;
use cfctl_cloudflare::{
    CallInput, CloudflareError, Executor, validate_reviewed_schema_migration_sql,
};
use cfctl_core::{
    AdapterStatus, CapabilityAuthorityScopeV1, CapabilityV1, D1ApprovedMlnImportContractV1,
    EffectClass, PlanV1, ResponseBodyModeV1, ResponseContractV1, RiskClass, SelectorV1,
};
use md5::{Digest as _, Md5};
use serde_json::{Value, json};
use sha2::Sha256;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const ACCOUNT_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DATABASE_ID: &str = "11111111-2222-4333-8444-555555555555";
const SQL: &str = "PRAGMA foreign_keys = ON;\nCREATE TABLE licenses (id TEXT PRIMARY KEY);\nCREATE TABLE activations (id TEXT PRIMARY KEY, license_id TEXT REFERENCES licenses(id));\nCREATE INDEX idx_activations_license ON activations(license_id);\n";

fn capability() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        "d1-apply-reviewed-schema-migration",
        "Apply one reviewed Git schema migration to D1",
        "POST",
        "/accounts/{account_id}/d1/database/{database_id}/query",
    );
    capability.authority_scope = Some(CapabilityAuthorityScopeV1::ProviderGeneric);
    "D1".clone_into(&mut capability.product);
    "account".clone_into(&mut capability.account_scope);
    capability.adapter_status = AdapterStatus::Native;
    capability.mutating = true;
    capability.risk = RiskClass::Irreversible;
    capability.effect = EffectClass::DataWrite;
    capability.permissions = vec!["D1 Write".to_owned()];
    capability.selectors = ["account_id", "database_id"]
        .map(|name| SelectorV1 {
            name: name.to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        })
        .to_vec();
    capability.request_schema = Some(json!({
        "type":"object",
        "additionalProperties":false,
        "x-cfctl-body-required":true,
        "required":[
            "pre_recovery_anchor_operation_id",
            "pre_recovery_anchor_evidence_hash",
            "pre_recovery_anchor_output_sha256",
            "pre_recovery_anchor_bookmark_hash"
        ],
        "properties":{
            "pre_recovery_anchor_operation_id":{"type":"string"},
            "pre_recovery_anchor_evidence_hash":{"type":"string"},
            "pre_recovery_anchor_output_sha256":{"type":"string"},
            "pre_recovery_anchor_bookmark_hash":{"type":"string"}
        }
    }));
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec!["application/json".to_owned()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    capability.verification.required = true;
    "d1_reviewed_schema_batch_reports_every_statement_success"
        .clone_into(&mut capability.verification.strategy);
    capability.d1_approved_mln_import = Some(D1ApprovedMlnImportContractV1 {
        repository_id: String::new(),
        repository_head: String::new(),
        pre_import_capability_version: 0,
        pre_import_validator_contract_hash: String::new(),
        pre_import_fixed_query_sha256: String::new(),
        account_id: String::new(),
        database_id: String::new(),
        import_path: capability.path.clone(),
        migrations: Vec::new(),
        max_source_bytes: 1024 * 1024,
        max_response_bytes: 1024 * 1024,
        max_poll_attempts: 0,
        max_timeout_seconds: 10,
        upload_url_suffix: String::new(),
        requires_create_new_mode_0600_stage: true,
    });
    capability
}

fn input() -> CallInput {
    CallInput {
        selectors: json!({"account_id":ACCOUNT_ID,"database_id":DATABASE_ID}),
        query: json!({}),
        body: Some(json!({
            "pre_recovery_anchor_operation_id":"11111111-1111-4111-8111-111111111111",
            "pre_recovery_anchor_evidence_hash":format!("sha256:{}", "1".repeat(64)),
            "pre_recovery_anchor_output_sha256":format!("sha256:{}", "2".repeat(64)),
            "pre_recovery_anchor_bookmark_hash":format!("sha256:{}", "3".repeat(64))
        })),
        ..CallInput::default()
    }
}

#[test]
fn reviewed_schema_authorizer_accepts_only_bounded_create_ddl() {
    assert_eq!(
        validate_reviewed_schema_migration_sql(SQL).expect("closed DDL is admitted"),
        4
    );
    for forbidden in [
        "INSERT INTO licenses VALUES ('x');",
        "DROP TABLE licenses;",
        "ALTER TABLE licenses ADD COLUMN secret TEXT;",
        "ATTACH DATABASE '/tmp/other.db' AS other;",
        "PRAGMA writable_schema = ON;",
        "CREATE VIEW leak AS SELECT * FROM licenses;",
        "CREATE TRIGGER leak AFTER INSERT ON licenses BEGIN DELETE FROM licenses; END;",
        "CREATE VIRTUAL TABLE search USING fts5(body);",
        "CREATE TEMP TABLE hidden (id TEXT);",
        "SELECT load_extension('arbitrary');",
        "CREATE TABLE safe (id TEXT); REINDEX safe;",
    ] {
        let error = match validate_reviewed_schema_migration_sql(forbidden) {
            Err(error) => error,
            Ok(count) => panic!(
                "non-schema or extensible SQL was admitted with {count} counted statements: {forbidden}"
            ),
        };
        assert!(matches!(error, CloudflareError::InvalidRequestBody(_)));
    }
}

#[tokio::test]
async fn consumed_plan_posts_only_exact_reviewed_sql_and_verifies_every_statement() {
    let directory = tempfile::tempdir().expect("private stage directory");
    let stage_path = directory.path().join("0001_licensing_authority.sql");
    std::fs::write(&stage_path, SQL).expect("write stage");
    #[cfg(unix)]
    std::fs::set_permissions(&stage_path, std::fs::Permissions::from_mode(0o600))
        .expect("private stage mode");
    let sha256 = hex::encode(Sha256::digest(SQL.as_bytes()));
    let md5 = hex::encode(Md5::digest(SQL.as_bytes()));
    let source_authority_hash = format!("sha256:{}", "a".repeat(64));
    let targets = json!({"adapter":{"approved_mln_import":{
        "schema_version":1,
        "migration_id":source_authority_hash,
        "catalog_basename":"0001_licensing_authority.sql",
        "source_authority_hash":source_authority_hash,
        "bytes":SQL.len(),
        "sha256":format!("sha256:{sha256}"),
        "md5":md5,
        "stage_path":stage_path,
        "statement_count":4,
        "target":{"account_id":ACCOUNT_ID,"database_id":DATABASE_ID}
    }}});
    let input = input();
    let mut plan = PlanV1::draft(
        "profile",
        ACCOUNT_ID,
        "sha256:catalog",
        capability(),
        targets,
    )
    .expect("draft plan");
    plan.input = serde_json::to_value(&input).expect("plan input");
    plan.refresh_hash().expect("refresh plan");
    plan.approve(true, None).expect("approve plan");
    plan.mark_consumed().expect("consume plan");

    let response_body = json!({
        "success":true,
        "errors":[],
        "result":[
            {"success":true,"results":[],"meta":{"changed_db":false}},
            {"success":true,"results":[],"meta":{"changed_db":true}},
            {"success":true,"results":[],"meta":{"changed_db":true}},
            {"success":true,"results":[],"meta":{"changed_db":true}}
        ]
    })
    .to_string();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
    let address = listener.local_addr().expect("server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept request");
        let mut buffer = vec![0_u8; 16 * 1024];
        let read = stream.read(&mut buffer).await.expect("read request");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
            response_body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write response");
        request
    });
    let executor =
        Executor::new(reqwest::Client::new(), &format!("http://{address}")).expect("executor");
    let credential = AuthCredential::Bearer {
        token: "test-token".to_owned(),
    };
    let response = executor
        .execute_consumed_plan_with_input(&mut plan, "sha256:catalog", &credential, &input)
        .await
        .expect("execute reviewed schema migration");
    let verification = executor
        .verify_plan_with_input(&plan, &response, &input, &credential)
        .await
        .expect("verify reviewed schema migration");
    assert!(verification.passed, "{}", verification.basis);

    let request = server.await.expect("server result");
    assert!(request.starts_with(&format!(
        "POST /accounts/{ACCOUNT_ID}/d1/database/{DATABASE_ID}/query "
    )));
    let body = request
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .expect("request body");
    let body: Value = serde_json::from_str(body).expect("JSON request body");
    assert_eq!(body, json!({"sql":SQL}));
    assert!(!request.contains("pre_recovery_anchor"));

    let mut incomplete = response;
    incomplete
        .result
        .as_array_mut()
        .expect("result array")
        .pop();
    let rejected = executor
        .verify_plan_with_input(&plan, &incomplete, &input, &credential)
        .await
        .expect("verification returns a failed receipt");
    assert!(!rejected.passed);
}
