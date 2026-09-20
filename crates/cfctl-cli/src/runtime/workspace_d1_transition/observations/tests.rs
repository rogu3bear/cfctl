#![allow(clippy::expect_used, clippy::unwrap_used, clippy::wildcard_imports)]
use super::*;
use cfctl_core::{
    AdapterStatus, CapabilityAuthorityScopeV1, CapabilityV1, EffectClass, EvidenceClass,
    EvidenceV1, OperationalProofOutcomeV1, OperationalProofScopeV1, RiskClass,
    d1_read_inventory::{D1_READ_COMPILER_VERSION, D1ReadColumnV1},
};
use sha2::{Digest, Sha256};

fn inventory() -> D1ReadInventoryV1 {
    let mut inventory: D1ReadInventoryV1 = serde_json::from_str(include_str!(
        "../../../../../cfctl-workspace/tests/fixtures/d1-reads/inventory.json"
    ))
    .unwrap();
    for query in &mut inventory.queries {
        query.sql = "SELECT 1 AS passed;".into();
        query.sha256 = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(query.sql.as_bytes()))
        );
        query.requires.clear();
        query.output.min_rows = 1;
        query.output.max_rows = 1;
        query.output.columns = vec![D1ReadColumnV1 {
            name: "passed".into(),
            kind: D1ReadValueKindV1::Integer,
            nullable: false,
            max_bytes: None,
            allowed_values: Some(vec![json!(1)]),
            min_integer: Some(1),
            max_integer: Some(1),
        }];
    }
    inventory
}

#[test]
fn transition_requires_an_explicit_complete_one_row_assertion_contract() {
    let good = inventory();
    assertion_outputs(&good).unwrap();
    for mutation in 0..6 {
        let mut bad = good.clone();
        match mutation {
            0 => bad.queries[0].output.min_rows = 0,
            1 => bad.queries[0].output.columns[0].allowed_values = None,
            2 => bad.queries[0].output.columns[0].nullable = true,
            3 => bad.queries[0].output.columns[0].name = "success".into(),
            4 => bad.queries[0].output.columns[0].max_integer = Some(2),
            _ => bad.queries.clear(),
        }
        assert!(assertion_outputs(&bad).is_err());
    }
}

fn fixture() -> (ValidatedD1ReadInventory, OperationalProofV1, Value) {
    let inventory = inventory();
    let digest = format!("sha256:{}", "a".repeat(64));
    let contract = serde_json::from_value(json!({
        "repository_root":"/fixture", "repository_head":"a".repeat(40),
        "repository_tree":"b".repeat(40), "repository_origin":"https://example.invalid/app",
        "operation_pack_sha256":digest,
        "operation":{
            "id":"fixture.boundary", "title":"Boundary", "description":"Reviewed assertions",
            "account_id":"a".repeat(32), "database_id":"11111111-2222-4333-8444-555555555555",
            "profile_id":"fixture", "source_revision":"a".repeat(40),
            "source":[{"path":"source.sql","sha256":digest}],
            "inventory_path":"boundary.json","inventory_sha256":digest
        }, "inventory":inventory
    }))
    .unwrap();
    let mut capability = CapabilityV1::new(
        "fixture.boundary",
        "Boundary",
        "POST",
        "/accounts/{account_id}/d1/database/{database_id}/query",
    );
    capability.authority_scope = Some(CapabilityAuthorityScopeV1::WorkspaceOwned);
    capability.adapter_status = AdapterStatus::Native;
    capability.mutating = false;
    capability.risk = RiskClass::Read;
    capability.effect = EffectClass::ReadOnly;
    capability.permissions = vec!["D1 Read".into()];
    capability.workspace_d1_read_inventory = Some(contract);
    let generation = "22222222-2222-4222-8222-222222222222";
    let input = CallInput {
        selectors: json!({"account_id":"a".repeat(32),"database_id":"11111111-2222-4333-8444-555555555555"}),
        query: json!({}),
        body: Some(
            json!({"inventory_sha256":digest,"expected_credential_generation_id":generation}),
        ),
        ..CallInput::default()
    };
    let validated = d1_read_inventory::validate(&capability, &input).unwrap();
    let contract = validated.contract();
    let results: Vec<_> = contract.inventory.queries.iter().map(|q| json!({
        "query_id":q.id,"query_sha256":q.sha256,"phase":q.phase,"witnesses":q.witnesses,
        "parameter_provenance":[],"status":"complete","attempted":true,
        "classification":"complete_read","http_status":200,"rows_read":1,"response_bytes":512,
        "receipt":{"success":true,"errors":[],"messages":[],"result":[{"success":true,
            "results":[{"passed":1}],"meta":{"rows_read":1,"rows_written":0,"changes":0,
                "changed_db":false,"duration":0.1,"total_attempts":1}}]}
    })).collect();
    let now = Utc::now();
    let value = json!({
        "kind":"workspace_d1_read_inventory_v1", "capability_id":"fixture.boundary",
        "catalog_schema_hash":"catalog","profile_id":"fixture","credential_generation_id":generation,
        "account_id":"a".repeat(32),"database_id":contract.operation.database_id,
        "repository_root":contract.repository_root,"repository_head":contract.repository_head,
        "repository_tree":contract.repository_tree,"source_revision":contract.operation.source_revision,
        "operation_pack_sha256":digest,"inventory_sha256":digest,
        "source_inputs":contract.operation.source,"contract_sha256":hash_value(&serde_json::to_value(contract).unwrap()).unwrap(),
        "build":{"fixture":true},"non_atomic_observations":true,
        "started_at":now-chrono::Duration::seconds(2),"completed_at":now-chrono::Duration::seconds(1),
        "execution":{"schema_version":1,"compiler_version":D1_READ_COMPILER_VERSION,
            "inventory_sha256":digest,"read_complete":true,"attempted_queries":results.len(),
            "unattempted_queries":0,"rows_read":results.len(),"response_bytes":results.len()*512,
            "hard_scan_or_currency_ceiling_established":false,"application_predicates_evaluated":false,
            "results":results}
    });
    let proof = OperationalProofV1::new(
        now,
        "fixture.boundary",
        "catalog",
        "input",
        OperationalProofScopeV1::new(Some("fixture"), Some(&"a".repeat(32)), Some(generation)),
        OperationalProofOutcomeV1::Succeeded,
        EvidenceV1::new(EvidenceClass::LiveRead, &digest, "fixture"),
    );
    (validated, proof, value)
}

#[test]
fn exact_native_observation_rejects_identity_result_predicate_and_time_substitution() {
    let (validated, proof, value) = fixture();
    let build = hash_value(&value["build"]).unwrap();
    let account = "a".repeat(32);
    let scope = Scope {
        account: &account,
        profile: "fixture",
        generation: "22222222-2222-4222-8222-222222222222",
        catalog: "catalog",
        build: &build,
    };
    let now = Utc::now();
    let earliest = now - chrono::Duration::seconds(10);
    validate_value(&value, &proof, &validated, &scope, earliest, now).unwrap();
    for path in [
        "database_id",
        "repository_head",
        "contract_sha256",
        "inventory_sha256",
        "capability_id",
        "credential_generation_id",
    ] {
        let mut bad = value.clone();
        bad[path] = json!("substituted");
        assert!(
            validate_value(&bad, &proof, &validated, &scope, earliest, now).is_err(),
            "{path}"
        );
    }
    for field in [json!(0), json!("1"), Value::Null] {
        let mut bad = value.clone();
        bad["execution"]["results"][0]["receipt"]["result"][0]["results"][0]["passed"] = field;
        assert!(validate_value(&bad, &proof, &validated, &scope, earliest, now).is_err());
    }
    let mut bad = value.clone();
    bad["execution"]["results"][0]["receipt"]["result"][0]["results"] = json!([]);
    assert!(validate_value(&bad, &proof, &validated, &scope, earliest, now).is_err());
    let mut bad = value.clone();
    bad["execution"]["results"].as_array_mut().unwrap().pop();
    assert!(validate_value(&bad, &proof, &validated, &scope, earliest, now).is_err());
    assert!(validate_value(&value, &proof, &validated, &scope, now, now).is_err());
}
