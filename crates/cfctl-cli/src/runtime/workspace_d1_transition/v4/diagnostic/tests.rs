#![allow(clippy::unwrap_used, clippy::expect_used, clippy::wildcard_imports)]
use super::*;
use cfctl_core::workspace_d1::transition::{Observation, Source};

fn mode(managed: bool) -> Declaration {
    let observation = Observation {
        capability_id: "fixture.diagnostic".into(),
        inventory: Source {
            path: "diagnostic.json".into(),
            sha256: format!("sha256:{}", "a".repeat(64)),
            git_blob_oid: "a".repeat(40),
        },
    };
    if managed {
        Declaration::ManagedD1ApplicationV1 {
            policy: observation.inventory.clone(),
            diagnostic: observation,
        }
    } else {
        Declaration::FullIntegrityV1 {
            diagnostic: observation,
        }
    }
}
fn inventory() -> D1ReadInventoryV1 {
    let mut inventory: D1ReadInventoryV1 = serde_json::from_str(include_str!(
        "../../../../../../cfctl-workspace/tests/fixtures/d1-reads/inventory.json"
    ))
    .unwrap();
    inventory.queries.truncate(1);
    let query = &mut inventory.queries[0];
    query.sql = "PRAGMA quick_check;".into();
    query.parameters.clear();
    query.requires.clear();
    query.output.min_rows = 1;
    query.output.max_rows = 1;
    query.output.columns = vec![cfctl_core::d1_read_inventory::D1ReadColumnV1 {
        name: "quick_check".into(),
        kind: D1ReadValueKindV1::Text,
        nullable: false,
        max_bytes: Some(2),
        allowed_values: Some(vec![json!("ok")]),
        min_integer: None,
        max_integer: None,
    }];
    inventory
}

#[test]
fn diagnostic_modes_cannot_cross_or_replace_boundary_integer_assertions() {
    let quick = inventory();
    output(&quick, &mode(true)).unwrap();
    assert!(output(&quick, &mode(false)).is_err());
    assert!(super::super::super::observations::assertion_outputs(&quick).is_err());
    let mut full = quick.clone();
    full.queries[0].sql = "SELECT integrity_check FROM pragma_integrity_check;".into();
    full.queries[0].output.columns[0].name = "integrity_check".into();
    output(&full, &mode(false)).unwrap();
    assert!(output(&full, &mode(true)).is_err());
    for mutation in 0..5 {
        let mut bad = quick.clone();
        match mutation {
            0 => bad.queries[0].output.columns[0].allowed_values = Some(vec![json!("OK")]),
            1 => bad.queries[0].output.columns[0].nullable = true,
            2 => bad.queries[0].output.max_rows = 2,
            3 => bad.queries[0].sql = "PRAGMA quick_check(1);".into(),
            _ => bad.queries[0].output.columns[0].name = "passed".into(),
        }
        assert!(output(&bad, &mode(true)).is_err());
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one complete private native receipt fixture and independent negative joins"
)]
fn private_diagnostic_joins_primary_result_source_build_and_time() {
    use cfctl_core::{
        AdapterStatus, CapabilityAuthorityScopeV1, CapabilityV1, EffectClass, EvidenceClass,
        EvidenceV1, OperationalProofOutcomeV1, OperationalProofScopeV1, RiskClass,
    };
    let generation = "22222222-2222-4222-8222-222222222222";
    let account = "a".repeat(32);
    let digest = format!("sha256:{}", "a".repeat(64));
    let mut inventory = inventory();
    inventory.query_count = 1;
    inventory.witness_count = 1;
    inventory.tables.clear();
    inventory.functions.clear();
    inventory.limits.max_total_response_bytes = 65_536;
    inventory.limits.max_elapsed_seconds = 30;
    inventory.queries[0].sha256 = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(inventory.queries[0].sql.as_bytes()))
    );
    inventory.queries[0].output.max_bytes = 65_536;
    inventory.private_output = Some(
        serde_json::from_value(json!({"schema_version":1,
        "format":D1_PRIVATE_FORMAT,"max_artifact_bytes":131_072,"require_primary":true}))
        .unwrap(),
    );
    let contract:cfctl_core::d1_read_inventory::WorkspaceD1ReadInventoryContractV1=serde_json::from_value(json!({
        "repository_root":"/fixture","repository_head":"a".repeat(40),"repository_tree":"b".repeat(40),
        "repository_origin":"https://example.invalid/app","operation_pack_sha256":digest,
        "operation":{"id":"fixture.diagnostic","title":"Diagnostic","description":"Storage diagnostic",
            "account_id":account,"database_id":"11111111-1111-4111-8111-111111111111","profile_id":"fixture",
            "source_revision":"a".repeat(40),"source":[{"path":"source.sql","sha256":digest}],
            "inventory_path":"diagnostic.json","inventory_sha256":digest},"inventory":inventory})).unwrap();
    let mut capability = CapabilityV1::new(
        "fixture.diagnostic",
        "Diagnostic",
        "POST",
        "/accounts/{account_id}/d1/database/{database_id}/query",
    );
    capability.authority_scope = Some(CapabilityAuthorityScopeV1::WorkspaceOwned);
    capability.adapter_status = AdapterStatus::Native;
    capability.effect = EffectClass::ReadOnly;
    capability.mutating = false;
    capability.risk = RiskClass::Read;
    capability.permissions = vec!["D1 Read".into()];
    capability.workspace_d1_read_inventory = Some(contract.clone());
    let input = CallInput {
        selectors: json!({"account_id":account,"database_id":contract.operation.database_id}),
        query: json!({}),
        body: Some(
            json!({"inventory_sha256":digest,"expected_credential_generation_id":generation}),
        ),
        ..CallInput::default()
    };
    let validated = d1_read_inventory::validate(&capability, &input).unwrap();
    let now = Utc::now();
    let build = crate::build_identity::current_build_info();
    let build_hash = hash_value(&serde_json::to_value(&build).unwrap()).unwrap();
    let scope = Scope {
        account: &account,
        profile: "fixture",
        generation,
        catalog: "catalog",
        build: &build_hash,
    };
    let query = &contract.inventory.queries[0];
    let contract_hash = hash_value(&serde_json::to_value(&contract).unwrap()).unwrap();
    let artifact: D1PrivateReadArtifactV1=serde_json::from_value(json!({"schema_version":1,"kind":D1_PRIVATE_FORMAT,
        "binding":{"contract":contract,"capability_id":capability.id,"catalog_schema_hash":"catalog",
            "contract_sha256":contract_hash,"build":build,"profile_id":"fixture","credential_generation_id":generation,
            "query_id":query.id,"query_sha256":query.sha256},"started_at":now-chrono::Duration::seconds(3),
        "completed_at":now-chrono::Duration::seconds(2),"transport":{"http_status":200,"response_bytes":512,
            "content_encoding":"identity","attempted_queries":1,"read_complete":true,"served_by_primary":true,
            "application_predicates_evaluated":false},"provider_response":{"success":true,"errors":[],"messages":[],
            "result":[{"success":true,"results":[{"quick_check":"ok"}],"meta":{"rows_read":1,"rows_written":0,
                "changes":0,"changed_db":false,"duration":0.1,"total_attempts":1,"served_by_primary":true}}]}})).unwrap();
    let value = json!({"kind":D1_PRIVATE_FORMAT,"capability_id":capability.id,"catalog_schema_hash":"catalog",
        "profile_id":"fixture","credential_generation_id":generation,"account_id":account,
        "database_id":contract.operation.database_id,"repository_head":contract.repository_head,"repository_tree":contract.repository_tree,
        "operation_pack_sha256":digest,"inventory_sha256":digest,"query_id":query.id,"query_sha256":query.sha256,
        "contract_sha256":contract_hash,"build":build,"classification":"complete_read","read_complete":true,
        "application_predicates_evaluated":false});
    let proof = OperationalProofV1::new(
        now - chrono::Duration::seconds(1),
        &capability.id,
        "catalog",
        "input",
        OperationalProofScopeV1::new(Some("fixture"), Some(&account), Some(generation)),
        OperationalProofOutcomeV1::Succeeded,
        EvidenceV1::new(EvidenceClass::LiveRead, &digest, "fixture"),
    );
    let earliest = now - chrono::Duration::seconds(5);
    private_value(&value, &artifact, &validated, &proof, &scope, earliest, now).unwrap();
    for mutation in 0..6 {
        let mut altered = serde_json::to_value(&artifact).unwrap();
        match mutation {
            0 => altered["transport"]["served_by_primary"] = json!(false),
            1 => altered["binding"]["contract"]["repository_head"] = json!("b".repeat(40)),
            2 => {
                altered["binding"]["credential_generation_id"] =
                    json!("33333333-3333-4333-8333-333333333333");
            }
            3 => {
                altered["provider_response"]["result"][0]["results"][0]["quick_check"] =
                    json!("OK");
            }
            4 => altered["completed_at"] = json!(now + chrono::Duration::seconds(1)),
            _ => altered["binding"]["query_sha256"] = json!(format!("sha256:{}", "b".repeat(64))),
        }
        let altered = serde_json::from_value(altered).unwrap();
        assert!(
            private_value(&value, &altered, &validated, &proof, &scope, earliest, now).is_err()
        );
    }
}
