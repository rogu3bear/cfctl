use super::*;

pub(super) fn security_action_create_capability() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        SECURITY_IP_RULE_CREATE_ID,
        "Create expiring security action",
        "POST",
        SECURITY_IP_RULE_COLLECTION_PATH,
    );
    capability.product = "IP Access rules for a zone".to_owned();
    capability.permissions = vec![
        "Firewall Services Read".to_owned(),
        "Firewall Services Write".to_owned(),
    ];
    capability.selectors = vec![SelectorV1 {
        name: "zone_id".to_owned(),
        location: "path".to_owned(),
        required: true,
        value_type: "string".to_owned(),
        description: None,
        contract: None,
    }];
    capability.request_schema = Some(json!({
        "type":"object",
        "additionalProperties":false,
        "required":["configuration","mode","notes"],
        "properties":{
            "configuration":{"type":"object"},
            "mode":{"type":"string","enum":["managed_challenge","block"]},
            "notes":{"type":"string","maxLength":500}
        },
        "x-cfctl-body-required":true
    }));
    capability.risk = RiskClass::IdentityOrOwnership;
    capability.effect = EffectClass::ReversibleWrite;
    capability.verification.strategy =
        "parent_collection_contains_created_resource_id_and_planned_fields".to_owned();
    capability.created_collection_resource = Some(CreatedCollectionResourceContractV1 {
        collection_path: SECURITY_IP_RULE_COLLECTION_PATH.to_owned(),
        identity_selector: "rule_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: SECURITY_IP_RULE_STATE_CAPABILITY_ID.to_owned(),
        delete_capability_id: "ip-access-rules-for-a-zone-delete-an-ip-access-rule".to_owned(),
        verified_response_fields: vec![
            "configuration".to_owned(),
            "mode".to_owned(),
            "notes".to_owned(),
        ],
        requires_page_number_completion: true,
    });
    capability.rollback.supported = true;
    capability.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());
    capability.security_action = Some(SecurityActionContractV1 {
        kind: SecurityActionKindV1::CreateExpiring,
        input_schema: json!({
            "type":"object",
            "additionalProperties":false,
            "required":["actor","evidence_ref","reason","target"],
            "properties":{
                "action":{"type":"string","enum":["managed_challenge","block"]},
                "actor":{"type":"string","minLength":1,"maxLength":80},
                "evidence_ref":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
                "expires_at":{"type":"string","format":"date-time"},
                "reason":{"type":"string","minLength":4,"maxLength":160},
                "target":{"type":"object","additionalProperties":false,"required":["type","value"],"properties":{"type":{"type":"string","enum":["ip","ip_range","asn","country"]},"value":{"type":"string"}}},
                "operator_ip":{"type":"string"},
                "confirm_broad_scope":{"type":"boolean"},
                "confirm_block":{"type":"boolean"}
            },
            "x-cfctl-body-required":true
        }),
        default_action: Some("managed_challenge".to_owned()),
        allowed_actions: vec!["managed_challenge".to_owned(), "block".to_owned()],
        allowed_target_types: vec![
            "asn".to_owned(),
            "country".to_owned(),
            "ip".to_owned(),
            "ip_range".to_owned(),
        ],
        default_ttl_seconds: 86_400,
        max_ttl_seconds: 604_800,
        current_state_capability_id: SECURITY_IP_RULE_STATE_CAPABILITY_ID.to_owned(),
        safety_profile: SecurityActionSafetyProfileV1::TelemetryDerivedStrict,
    });
    capability
}

#[cfg(unix)]
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one end-to-end security regression proves private representations remain absent across subprocess receipts, retained evidence, verification, result envelopes, collision failures, immutable staging, and pre-launch drift rejection"
)]
pub(super) async fn private_worker_output_is_redacted_before_retained_surfaces() {
    use std::os::unix::fs::PermissionsExt;

    const PRIVATE_D1: &str = "11111111-1111-4111-8111-111111111111";
    const PRIVATE_SENDER: &str = "security@private.example";
    const PRIVATE_DOMAINS: &str = "sender.private.example,relay.private.example";
    const VERSION_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    let root = tempfile::tempdir().expect("private Worker boundary root");
    let template = root.path().join("wrangler.mail-router.toml");
    let production = root.path().join("wrangler.mail-router.production.toml");
    std::fs::write(
        &template,
        r#"name = "relay-router"
main = "worker.js"

send_email = [
  { name = "EMAIL" }
]

[vars]
MAILDESK_INBOUND_RELAY_MODE = "disabled"
MAILDESK_REPLY_RELAY_MODE = "disabled"
MAILDESK_VERIFIED_SENDER_DOMAINS = ""

[[d1_databases]]
binding = "MAILDESK_DB"
database_name = "maildesk"
database_id = "00000000-0000-4000-8000-000000000000"
"#,
    )
    .expect("tracked template");
    std::fs::write(
        &production,
        format!(
            r#"name = "relay-router"
main = "worker.js"

send_email = [
  {{ name = "EMAIL", allowed_sender_addresses = ["{PRIVATE_SENDER}"] }}
]

[vars]
MAILDESK_INBOUND_RELAY_MODE = "enabled"
MAILDESK_REPLY_RELAY_MODE = "disabled"
MAILDESK_VERIFIED_SENDER_DOMAINS = "{PRIVATE_DOMAINS}"

[[d1_databases]]
binding = "MAILDESK_DB"
database_name = "maildesk"
database_id = "{PRIVATE_D1}"
"#
        ),
    )
    .expect("private production config");
    std::fs::set_permissions(&production, std::fs::Permissions::from_mode(0o600))
        .expect("private production mode");
    std::fs::write(
        root.path().join(".gitignore"),
        "wrangler.mail-router.production.toml\n",
    )
    .expect("private production ignore");
    assert!(
        std::process::Command::new("git")
            .args(["init", "--quiet", "--initial-branch=main"])
            .current_dir(root.path())
            .status()
            .expect("git init")
            .success()
    );
    assert!(
        std::process::Command::new("git")
            .args(["add", ".gitignore", "wrangler.mail-router.toml"])
            .current_dir(root.path())
            .status()
            .expect("git add tracked template")
            .success()
    );
    assert!(
        std::process::Command::new("git")
            .args([
                "-c",
                "user.name=cfctl test",
                "-c",
                "user.email=cfctl-test@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "fixture",
            ])
            .current_dir(root.path())
            .status()
            .expect("git commit tracked template")
            .success()
    );

    let success_program = root.path().join("fake-wrangler-success.sh");
    std::fs::write(
        &success_program,
        format!(
            r#"#!/bin/sh
printf '%s\n' \
  'upload complete' \
  'Current Version ID: {VERSION_ID}' \
  'D1=({PRIVATE_D1}),{PRIVATE_D1}' \
  'allowed_sender_addresses=["{PRIVATE_SENDER}"] encoded=security%40private.example' \
  'MAILDESK_VERIFIED_SENDER_DOMAINS="{PRIVATE_DOMAINS}" again={PRIVATE_DOMAINS}' \
  '| MAILDESK_INBOUND_RELAY_MODE | enabled |' \
  '| MAILDESK_REPLY_RELAY_MODE | disabled |'
printf '%s\n' \
  'D1=({PRIVATE_D1}),{PRIVATE_D1}' \
  'allowed_sender_addresses=["{PRIVATE_SENDER}"] encoded=security%40private.example' \
  'MAILDESK_VERIFIED_SENDER_DOMAINS="{PRIVATE_DOMAINS}" again={PRIVATE_DOMAINS}' \
  '| MAILDESK_INBOUND_RELAY_MODE | enabled |' \
  '{{"MAILDESK_REPLY_RELAY_MODE":"disabled","ordinary":"diagnostic"}}' \
  '{{"name":"MAILDESK_INBOUND_RELAY_MODE","value":"enabled"}}' \
  '["MAILDESK_REPLY_RELAY_MODE","disabled"]' \
  '{{"diagnostic":"MAILDESK_INBOUND_RELAY_MODE=enabled"}}' \
  'MAILDESK_REPLY_RELAY_MODE' \
  'disabled' \
  'base64=c2VuZGVyLnByaXZhdGUuZXhhbXBsZQ==' \
  'hex=73656e6465722e707269766174652e6578616d706c65' \
  'punctuation:[sender.private.example];relay.private.example' \
  'credential=fixture-token' >&2
"#
        ),
    )
    .expect("fake Wrangler");
    std::fs::set_permissions(&success_program, std::fs::Permissions::from_mode(0o700))
        .expect("fake Wrangler mode");
    let cache = root.path().join("cache");
    std::fs::create_dir(&cache).expect("cache root");
    let mut capability =
        CapabilityV1::new("wrangler.deploy", "deploy Worker", "CLI", "wrangler deploy");
    capability.method = "CLI".to_owned();
    capability.adapter_status = AdapterStatus::DelegatedCli;
    let input = CallInput {
        selectors: json!({}),
        query: json!({"config": production.canonicalize().expect("canonical private config")}),
        ..CallInput::default()
    };
    let credential = AuthCredential::Bearer {
        token: "fixture-token".to_owned(),
    };
    let planned = worker_deployment::PlannedConfigExecution::Private {
        path: production.canonicalize().expect("canonical private config"),
        sha256: hex::encode(Sha256::digest(
            std::fs::read(&production).expect("private bytes"),
        )),
        template_path: template.canonicalize().expect("canonical template"),
        template_sha256: hex::encode(Sha256::digest(
            std::fs::read(&template).expect("template bytes"),
        )),
    };
    let receipt = super::run_delegated_cli_with_private_config_identity(
        &capability,
        &input,
        &credential,
        Some("fixture-account"),
        &cache,
        Some(&success_program),
        Some(Path::new("/bin/sh")),
        Some(&planned),
    )
    .await
    .expect("private Worker boundary receipt");
    assert_eq!(receipt["success"], true);
    assert_eq!(receipt["exit_status"], 0);
    assert_eq!(receipt["stdout"], "");
    assert_eq!(receipt["stderr"], "");
    assert_eq!(
        receipt["structured_output"]["produced_version_id"],
        VERSION_ID
    );
    assert_eq!(
        receipt["structured_output"]["provider_output_retained"],
        false
    );
    assert!(
        receipt["structured_output"]["diagnostic"]
            .as_str()
            .expect("safe categorical diagnostic")
            .contains("completed")
    );

    let private_values = [
        PRIVATE_D1,
        PRIVATE_SENDER,
        PRIVATE_DOMAINS,
        "sender.private.example",
        "relay.private.example",
        "security%40private.example",
        "enabled",
        "disabled",
        "fixture-token",
        "c2VuZGVyLnByaXZhdGUuZXhhbXBsZQ==",
        "73656e6465722e707269766174652e6578616d706c65",
    ];
    let assert_absent = |label: &str, value: &Value| {
        let rendered = serde_json::to_string(value).expect("retained JSON");
        for private in private_values {
            assert!(
                !rendered.contains(private),
                "{label} retained private material"
            );
        }
    };
    assert_absent("subprocess receipt", &receipt);

    let collision_program = root.path().join("fake-wrangler-version-collision.sh");
    std::fs::write(
        &collision_program,
        format!(
            "#!/bin/sh\nprintf '%s\\n' 'Current Version ID: {PRIVATE_D1}' 'Worker Version ID: {PRIVATE_D1}'\n"
        ),
    )
    .expect("private Worker version-collision fixture");
    std::fs::set_permissions(&collision_program, std::fs::Permissions::from_mode(0o700))
        .expect("private Worker version-collision fixture mode");
    for capability_id in ["wrangler.deploy", "wrangler.versions-upload"] {
        let collision_path = capability_id.replace('.', " ");
        let mut collision_capability = CapabilityV1::new(
            capability_id,
            "private Worker collision probe",
            "CLI",
            &collision_path,
        );
        collision_capability.method = "CLI".to_owned();
        collision_capability.adapter_status = AdapterStatus::DelegatedCli;
        let collision = super::run_delegated_cli_with_private_config_identity(
            &collision_capability,
            &input,
            &credential,
            Some("fixture-account"),
            &cache,
            Some(&collision_program),
            Some(Path::new("/bin/sh")),
            Some(&planned),
        )
        .await
        .expect("private Worker collision receipt");
        assert_eq!(collision["success"], false);
        assert_eq!(collision["stdout"], "");
        assert_eq!(collision["stderr"], "");
        assert_absent("private Worker collision receipt", &collision);
    }

    let state = tempfile::tempdir().expect("state root");
    let store = StateStore::open(RuntimePaths::from_root(state.path())).expect("state store");
    let evidence = store
        .write_evidence(EvidenceClass::Apply, &receipt)
        .expect("Apply evidence");
    let retained = store
        .read_evidence_value(&evidence.content_hash)
        .expect("retained Apply evidence");
    assert_absent("Apply evidence", &retained);
    let verification = json!({
        "passed": true,
        "basis": "typed private Wrangler projection matched the reviewed version",
        "version_id": receipt["structured_output"]["produced_version_id"],
        "provider_output_retained": false,
    });
    let verification_evidence = store
        .write_evidence(EvidenceClass::PostChangeVerification, &verification)
        .expect("PostChangeVerification evidence");
    assert_absent(
        "PostChangeVerification evidence",
        &store
            .read_evidence_value(&verification_evidence.content_hash)
            .expect("retained PostChangeVerification evidence"),
    );
    let envelope = ResultEnvelopeV2::success("plans run", receipt.clone()).with_evidence(evidence);
    assert_absent(
        "result envelope",
        &serde_json::to_value(envelope).expect("envelope JSON"),
    );

    let failure_program = root.path().join("fake-wrangler-failure.sh");
    std::fs::write(
        &failure_program,
        format!(
            "#!/bin/sh\nprintf '%s\\n' '{PRIVATE_D1}' '{PRIVATE_SENDER}' '{PRIVATE_DOMAINS}' 'enabled' 'c2VuZGVyLnByaXZhdGUuZXhhbXBsZQ==' >&2\nexit 9\n"
        ),
    )
    .expect("failing fake Wrangler");
    std::fs::set_permissions(&failure_program, std::fs::Permissions::from_mode(0o700))
        .expect("failing fake Wrangler mode");
    let failed = super::run_delegated_cli_with_private_config_identity(
        &capability,
        &input,
        &credential,
        Some("fixture-account"),
        &cache,
        Some(&failure_program),
        Some(Path::new("/bin/sh")),
        Some(&planned),
    )
    .await
    .expect("failed private Worker boundary receipt");
    assert_eq!(failed["success"], false);
    assert_eq!(failed["exit_status"], 9);
    assert_eq!(failed["stdout"], "");
    assert_eq!(failed["stderr"], "");
    assert_absent("failed subprocess receipt", &failed);

    let bound =
        worker_deployment::bind_private_config_for_execution(&capability, &input, Some(&planned))
            .expect("bind private execution config")
            .expect("private binding");

    let verification_stdout = format!(
        r#"{{"deployments":[{{"version_id":"{VERSION_ID}","percentage":100}}],"name":"MAILDESK_INBOUND_RELAY_MODE","value":"enabled","private":"{PRIVATE_D1}","encoded":"c2VuZGVyLnByaXZhdGUuZXhhbXBsZQ=="}}"#
    );
    let status_projection = super::private_deployment_status_projection(
        true,
        Some(0),
        verification_stdout.as_bytes(),
        VERSION_ID,
        &bound,
    );
    assert_eq!(status_projection["passed"], true);
    assert_absent("deployment-status projection", &status_projection);
    let version_id = "22222222-2222-4222-8222-222222222222";
    let expected_message = "source=abc artifact-sha256=def";
    let version_stdout = format!(
        r#"{{"id":"{version_id}","annotations":{{"workers/message":"{expected_message}"}},"private":"{PRIVATE_SENDER}","nested":"MAILDESK_REPLY_RELAY_MODE=disabled","hex":"73656e6465722e707269766174652e6578616d706c65"}}"#
    );
    let version_projection = super::private_version_projection(
        true,
        Some(0),
        version_stdout.as_bytes(),
        version_id,
        expected_message,
        &bound,
    );
    assert_eq!(version_projection["passed"], true);
    assert_absent("version-view projection", &version_projection);
    let opaque_parse_failure = super::private_version_projection(
        true,
        Some(0),
        format!("not-json {PRIVATE_DOMAINS} enabled").as_bytes(),
        version_id,
        expected_message,
        &bound,
    );
    assert_eq!(opaque_parse_failure["passed"], false);
    assert_absent("opaque verifier parse failure", &opaque_parse_failure);

    let status_collision = super::private_deployment_status_projection(
        true,
        Some(0),
        format!(r#"{{"deployments":[{{"version_id":"{PRIVATE_D1}","percentage":100}}]}}"#)
            .as_bytes(),
        PRIVATE_D1,
        &bound,
    );
    assert_eq!(status_collision["passed"], false);
    assert_absent("deployment-status identity collision", &status_collision);
    let version_collision = super::private_version_projection(
        true,
        Some(0),
        format!(r#"{{"id":"{PRIVATE_D1}","annotations":{{"workers/message":"safe"}}}}"#).as_bytes(),
        PRIVATE_D1,
        "safe",
        &bound,
    );
    assert_eq!(version_collision["passed"], false);
    assert_absent("version-view identity collision", &version_collision);

    let captured = std::fs::read(bound.path()).expect("captured immutable bytes");
    let original = std::fs::read(&production).expect("original private config");
    assert_eq!(captured, original);
    std::fs::write(
        &production,
        "[vars]\nMAILDESK_VERIFIED_SENDER_DOMAINS = \"drift.example\"\n",
    )
    .expect("transient drift");
    std::fs::write(&production, &original).expect("restore original bytes");
    assert_eq!(
        std::fs::read(bound.path()).expect("immutable execution bytes after A-B-A"),
        captured,
        "transient A-B-A changes to the source path cannot alter the staged execution bytes"
    );
    let private_alias = root.path().join("reviewed-private-alias.toml");
    std::fs::write(&private_alias, &original).expect("private alias bytes");
    std::fs::set_permissions(&private_alias, std::fs::Permissions::from_mode(0o600))
        .expect("private alias mode");
    let alias_path = private_alias
        .canonicalize()
        .expect("canonical private alias");
    let alias_sha256 = hex::encode(Sha256::digest(&original));
    let alias_template_path = template.canonicalize().expect("canonical alias template");
    let alias_template_sha256 = hex::encode(Sha256::digest(
        std::fs::read(&template).expect("alias template bytes"),
    ));
    let alias_plan = worker_deployment::PlannedConfigExecution::Private {
        path: alias_path.clone(),
        sha256: alias_sha256.clone(),
        template_path: alias_template_path.clone(),
        template_sha256: alias_template_sha256.clone(),
    };
    assert!(
        worker_deployment::bind_planned_config_path_for_execution(
            &private_alias.canonicalize().expect("canonical alias path"),
            &alias_plan,
        )
        .expect("private alias binding")
        .is_some(),
        "private authority must remain opaque regardless of filename"
    );
    let bad_template_plan = worker_deployment::PlannedConfigExecution::Private {
        path: alias_path.clone(),
        sha256: alias_sha256.clone(),
        template_path: alias_template_path,
        template_sha256: "f".repeat(64),
    };
    assert!(
        worker_deployment::bind_planned_config_path_for_execution(
            &private_alias
                .canonicalize()
                .expect("canonical bad-template path"),
            &bad_template_plan,
        )
        .is_err(),
        "planned template-hash drift must fail before launch"
    );
    let template_alias = root.path().join("template-alias.toml");
    std::os::unix::fs::symlink(&template, &template_alias).expect("template symlink");
    let symlink_template_plan = worker_deployment::PlannedConfigExecution::Private {
        path: alias_path,
        sha256: alias_sha256,
        template_path: template_alias,
        template_sha256: alias_template_sha256,
    };
    assert!(
        worker_deployment::bind_planned_config_path_for_execution(
            &private_alias
                .canonicalize()
                .expect("canonical symlink-template path"),
            &symlink_template_plan,
        )
        .is_err(),
        "template symlinks must fail the single-handle O_NOFOLLOW capture"
    );
    assert!(
        worker_deployment::bind_private_config_for_execution(
            &capability,
            &input,
            Some(&worker_deployment::PlannedConfigExecution::Private {
                path: production.canonicalize().expect("canonical drift path"),
                sha256: "f".repeat(64),
                template_path: template.canonicalize().expect("canonical drift template"),
                template_sha256: hex::encode(Sha256::digest(
                    std::fs::read(&template).expect("template bytes"),
                )),
            }),
        )
        .is_err(),
        "persistent identity drift must fail closed before subprocess launch"
    );
    let mut ambiguous_input = input.clone();
    ambiguous_input.selectors = json!({"argument": "--config=other.toml"});
    assert!(
        super::run_delegated_cli_with_private_config_identity(
            &capability,
            &ambiguous_input,
            &credential,
            Some("fixture-account"),
            &cache,
            Some(&success_program),
            Some(Path::new("/bin/sh")),
            Some(&planned),
        )
        .await
        .is_err(),
        "alternate private config arguments must fail before subprocess launch"
    );
}

pub(super) fn list_security_action_create_capability() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        SECURITY_LIST_MEMBER_CREATE_ID,
        "Add expiring List member",
        "POST",
        SECURITY_LIST_MEMBER_COLLECTION_PATH,
    );
    capability.product = "Lists".to_owned();
    capability.account_scope = "account".to_owned();
    capability.permissions = vec![
        "Account Filter Lists Edit".to_owned(),
        "Account Filter Lists Read".to_owned(),
    ];
    capability.selectors = ["account_id", "list_id"]
        .into_iter()
        .map(|name| SelectorV1 {
            name: name.to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        })
        .collect();
    capability.request_schema = Some(json!({
        "type":"array",
        "minItems":1,
        "maxItems":1,
        "items":{"type":"object"},
        "x-cfctl-body-required":true
    }));
    capability.risk = RiskClass::IdentityOrOwnership;
    capability.effect = EffectClass::ReversibleWrite;
    capability.verification.strategy =
        "async_list_operation_completes_and_correlated_member_exists".to_owned();
    capability.async_collection_mutation = Some(AsyncCollectionMutationContractV1 {
        operation_status_path: "/accounts/{account_id}/rules/lists/bulk_operations/{operation_id}"
            .to_owned(),
        operation_status_capability_id: "lists-get-bulk-operation-status".to_owned(),
        operation_id_selector: "operation_id".to_owned(),
        apply_operation_id_pointer: "/operation_id".to_owned(),
        status_operation_id_pointer: "/id".to_owned(),
        status_state_pointer: "/status".to_owned(),
        pending_states: vec!["pending".to_owned(), "running".to_owned()],
        completed_state: "completed".to_owned(),
        failed_state: "failed".to_owned(),
        max_poll_attempts: 30,
        poll_interval_ms: 1_000,
        collection_path: SECURITY_LIST_MEMBER_COLLECTION_PATH.to_owned(),
        collection_capability_id: "lists-get-list-items".to_owned(),
        collection_metadata_path: "/accounts/{account_id}/rules/lists/{list_id}".to_owned(),
        collection_metadata_capability_id: "lists-get-a-list".to_owned(),
        collection_item_identity_pointer: "/id".to_owned(),
        correlation_field: Some("comment".to_owned()),
        remove_capability_id: Some(SECURITY_LIST_MEMBER_REMOVE_ID.to_owned()),
        requires_cursor_completion: true,
    });
    capability.rollback.supported = true;
    capability.rollback.strategy =
        Some("remove_async_created_list_member_by_correlated_id".to_owned());
    capability.security_action = Some(SecurityActionContractV1 {
        kind: SecurityActionKindV1::AddExpiringListMember,
        input_schema: json!({
            "type":"object",
            "additionalProperties":false,
            "required":["actor","confirm_consumer_scope","evidence_ref","reason","target"],
            "properties":{
                "action":{"type":"string","enum":["managed_challenge","block"]},
                "actor":{"type":"string","minLength":1,"maxLength":80},
                "confirm_block":{"type":"boolean"},
                "confirm_broad_scope":{"type":"boolean"},
                "confirm_consumer_scope":{"type":"boolean"},
                "evidence_ref":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
                "expires_at":{"type":"string","format":"date-time"},
                "operator_ip":{"type":"string"},
                "reason":{"type":"string","minLength":4,"maxLength":160},
                "target":{"type":"object","additionalProperties":false,"required":["type","value"],"properties":{"type":{"type":"string","enum":["asn","hostname","ip","ip_range"]},"value":{"type":"string"}}}
            },
            "x-cfctl-body-required":true
        }),
        default_action: Some("managed_challenge".to_owned()),
        allowed_actions: vec!["managed_challenge".to_owned(), "block".to_owned()],
        allowed_target_types: vec![
            "asn".to_owned(),
            "hostname".to_owned(),
            "ip".to_owned(),
            "ip_range".to_owned(),
        ],
        default_ttl_seconds: 86_400,
        max_ttl_seconds: 604_800,
        current_state_capability_id: "lists-get-list-items".to_owned(),
        safety_profile: SecurityActionSafetyProfileV1::TelemetryDerivedStrict,
    });
    capability
}

#[test]
pub(super) fn list_security_action_requires_consumer_review_and_renders_one_correlated_item() {
    let capability = list_security_action_create_capability();
    assert!(capability.security_action_contract_supported());
    let mut input = CallInput {
        selectors: json!({
            "account_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "list_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        }),
        body: Some(json!({
            "actor":"operator@example.test",
            "confirm_consumer_scope":true,
            "evidence_ref":format!("sha256:{}", "a".repeat(64)),
            "reason":"Repeated malicious requests in a bounded telemetry window",
            "target":{"type":"hostname","value":"Example.COM"}
        })),
        ..CallInput::default()
    };
    let receipt = prepare_security_action_input(&capability, &mut input)
        .expect("safe List action")
        .expect("governance receipt");
    assert_eq!(receipt["kind"], "add_expiring_list_member");
    assert_eq!(receipt["expected_consumer_action"], "managed_challenge");
    assert_eq!(receipt["target"]["value"], "example.com");
    let wire = input
        .body
        .as_ref()
        .and_then(Value::as_array)
        .expect("wire array");
    assert_eq!(wire.len(), 1);
    assert_eq!(wire[0]["hostname"]["url_hostname"], "example.com");
    assert!(wire[0]["comment"].as_str().is_some_and(|comment| {
        comment.contains("cfctl_list_security_v1") && !comment.contains("example.com")
    }));

    let mut unreviewed = CallInput {
        selectors: input.selectors.clone(),
        body: Some(json!({
            "actor":"operator@example.test",
            "evidence_ref":format!("sha256:{}", "b".repeat(64)),
            "reason":"Suspicious source",
            "target":{"type":"ip","value":"1.1.1.1"}
        })),
        ..CallInput::default()
    };
    assert!(
        prepare_security_action_input(&capability, &mut unreviewed)
            .expect_err("consumer scope must be explicit")
            .to_string()
            .contains("confirm_consumer_scope")
    );

    let mut self_block = CallInput {
        selectors: input.selectors,
        body: Some(json!({
            "action":"block",
            "actor":"operator@example.test",
            "confirm_block":true,
            "confirm_consumer_scope":true,
            "evidence_ref":format!("sha256:{}", "c".repeat(64)),
            "operator_ip":"1.1.1.1",
            "reason":"Confirmed malicious source",
            "target":{"type":"ip","value":"1.1.1.1"}
        })),
        ..CallInput::default()
    };
    assert!(
        prepare_security_action_input(&capability, &mut self_block)
            .expect_err("self block must fail")
            .to_string()
            .contains("operator IP")
    );
}

#[test]
pub(super) fn list_security_preflight_rejects_live_duplicates_and_proves_cursor_completion() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let capability = list_security_action_create_capability();
    let mut input = CallInput {
        selectors: json!({
            "account_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "list_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        }),
        body: Some(json!({
            "actor":"operator@example.test",
            "confirm_consumer_scope":true,
            "evidence_ref":format!("sha256:{}", "e".repeat(64)),
            "reason":"Repeated malicious requests in a bounded telemetry window",
            "target":{"type":"ip","value":"1.1.1.1"}
        })),
        ..CallInput::default()
    };
    let receipt = prepare_security_action_input(&capability, &mut input)
        .expect("safe List action")
        .expect("governance receipt");
    let adapter_targets = json!({"security_action":receipt});
    let metadata = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","kind":"ip"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let duplicate = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!([{
            "id":"cccccccccccccccccccccccccccccccc",
            "comment":"preexisting",
            "ip":"1.1.1.1"
        }]),
        errors: Vec::new(),
        result_info: Some(json!({"cfctl_cursor_complete":true})),
        etag: None,
        cf_ray: None,
    };
    assert!(
        list_security_action_state_receipt(
            &store,
            &capability,
            &input,
            &adapter_targets,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &metadata,
            &duplicate,
        )
        .expect_err("duplicate target must fail")
        .to_string()
        .contains("already has 1")
    );

    let empty = CloudflareResponseV1 {
        result: json!([]),
        ..duplicate
    };
    let state = list_security_action_state_receipt(
        &store,
        &capability,
        &input,
        &adapter_targets,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        &metadata,
        &empty,
    )
    .expect("complete empty List state");
    assert_eq!(state["state"]["matching_member_count"], 0);
    assert_eq!(state["list_kind"], "ip");
    assert!(!state.to_string().contains("1.1.1.1"));
}

#[test]
pub(super) fn list_rectification_uses_only_correlated_verification_identity() {
    let capability = list_security_action_create_capability();
    let evidence_ref = format!("sha256:{}", "d".repeat(64));
    let expires_at = (Utc::now() + ChronoDuration::hours(1)).to_rfc3339();
    let security_action = json!({
        "schema_version":1,
        "kind":"add_expiring_list_member",
        "actor":"operator@example.test",
        "evidence_ref":evidence_ref,
        "expires_at":expires_at,
        "reason":"Bounded suspicious source",
    });
    let selectors = json!({
        "account_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "list_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    });
    let mut plan = PlanV1::draft(
        "profile-a",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "catalog-sha",
        capability,
        json!({"selectors":selectors,"adapter":{"security_action":security_action}}),
    )
    .expect("plan");
    plan.input = serde_json::to_value(CallInput {
        selectors,
        query: json!({}),
        body: Some(json!([{
            "comment":"correlated-audit-comment",
            "ip":"1.1.1.1"
        }])),
        ..CallInput::default()
    })
    .expect("input");
    plan.refresh_hash()
        .expect("refresh hash after binding input");
    plan.approve(true, None).expect("approve");
    plan.mark_consumed().expect("consume");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("attempt");
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::BoundaryResponsePersisted,
        json!({"success":true,"operation_id":"bulk-1"}),
    )
    .expect("boundary");
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::SecretSinkPersisted,
        json!({"completed":true}),
    )
    .expect("sink checkpoint");
    plan.record_transaction_stage(TransactionStageV1::VerificationAttemptPersisted)
        .expect("verification attempt");
    let member_id = "cccccccccccccccccccccccccccccccc";
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::VerificationResponsePersisted,
        json!({"state":"passed","resource_id":member_id}),
    )
    .expect("verification response");
    plan.status = PlanStatus::RectificationRequired;

    let request = compensation_request(&plan)
        .expect("request resolves")
        .expect("correlated compensation");
    assert_eq!(request.capability_id, SECURITY_LIST_MEMBER_REMOVE_ID);
    assert_eq!(request.expected_method, "DELETE");
    assert_eq!(
        request.input.body,
        Some(json!({"items":[{"id":member_id}]}))
    );
    assert_eq!(
        request
            .adapter_targets
            .pointer("/security_action/member_id"),
        Some(&json!(member_id))
    );
    assert_eq!(
        request
            .adapter_targets
            .pointer("/security_action/source_operation_id"),
        Some(&json!(plan.operation_id))
    );
}

pub(super) fn waf_security_action_create_capability() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        SECURITY_WAF_RULE_CREATE_ID,
        "Create expiring WAF action",
        "POST",
        "/zones/{zone_id}/rulesets/{ruleset_id}/rules",
    );
    capability.product = "WAF custom rules".to_owned();
    capability.permissions = vec!["Zone WAF Read".to_owned(), "Zone WAF Write".to_owned()];
    capability.request_schema = Some(json!({
        "type":"object",
        "additionalProperties":false,
        "required":["action","description","enabled","expression","ref"],
        "properties":{
            "action":{"type":"string","enum":["block","js_challenge","log","managed_challenge","skip"]},
            "action_parameters":{"type":"object"},
            "description":{"type":"string"},
            "enabled":{"type":"boolean","const":true},
            "expression":{"type":"string"},
            "ref":{"type":"string"}
        },
        "x-cfctl-body-required":true
    }));
    capability.risk = RiskClass::IdentityOrOwnership;
    capability.effect = EffectClass::ReversibleWrite;
    capability.cost.known = true;
    capability.cost.maximum = Some(0.0);
    capability.verification.required = true;
    capability.verification.strategy =
        "parent_object_contains_created_nested_resource_by_correlation".to_owned();
    capability.created_nested_resource = Some(CreatedNestedResourceContractV1 {
        parent_path: SECURITY_WAF_RULE_PARENT_PATH.to_owned(),
        items_pointer: "/rules".to_owned(),
        identity_selector: "rule_id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        correlation_field: "ref".to_owned(),
        read_capability_id: SECURITY_WAF_RULE_STATE_CAPABILITY_ID.to_owned(),
        delete_capability_id: "deleteZoneRulesetRule".to_owned(),
        delete_path: "/zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}".to_owned(),
        verified_response_fields: vec![
            "action".to_owned(),
            "action_parameters".to_owned(),
            "description".to_owned(),
            "enabled".to_owned(),
            "expression".to_owned(),
            "ref".to_owned(),
        ],
    });
    capability.rollback.supported = true;
    capability.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());
    capability.security_action = Some(SecurityActionContractV1 {
        kind: SecurityActionKindV1::CreateExpiring,
        input_schema: json!({
            "type":"object",
            "additionalProperties":false,
            "required":["actor","evidence_ref","reason","target"],
            "properties":{
                "action":{"type":"string","enum":["block","js_challenge","log","managed_challenge","skip"]},
                "actor":{"type":"string"},
                "evidence_ref":{"type":"string"},
                "expires_at":{"type":"string"},
                "reason":{"type":"string"},
                "target":{"type":"object","additionalProperties":false,"required":["type","value"],"properties":{"type":{"type":"string"},"value":{"type":"string"}}},
                "operator_ip":{"type":"string"},
                "confirm_broad_scope":{"type":"boolean"},
                "confirm_block":{"type":"boolean"},
                "confirm_skip":{"type":"boolean"},
                "confirm_enterprise_bot_management":{"type":"boolean"}
            },
            "x-cfctl-body-required":true
        }),
        default_action: Some("managed_challenge".to_owned()),
        allowed_actions: vec![
            "block".to_owned(),
            "js_challenge".to_owned(),
            "log".to_owned(),
            "managed_challenge".to_owned(),
            "skip".to_owned(),
        ],
        allowed_target_types: vec![
            "asn".to_owned(),
            "country".to_owned(),
            "hostname".to_owned(),
            "ip".to_owned(),
            "ip_range".to_owned(),
            "ja4".to_owned(),
            "path".to_owned(),
        ],
        default_ttl_seconds: 86_400,
        max_ttl_seconds: 604_800,
        current_state_capability_id: SECURITY_WAF_RULE_STATE_CAPABILITY_ID.to_owned(),
        safety_profile: SecurityActionSafetyProfileV1::TelemetryDerivedStrict,
    });
    capability
}

#[test]
pub(super) fn security_action_defaults_to_expiring_managed_challenge_and_compiles_exact_wire_body()
{
    let capability = security_action_create_capability();
    let mut input = CallInput {
        selectors: json!({"zone_id":"zone-a"}),
        body: Some(json!({
            "actor":"operator@example.test",
            "evidence_ref":format!("sha256:{}", "a".repeat(64)),
            "reason":"Repeated malicious requests in a bounded telemetry window",
            "target":{"type":"ip","value":"1.1.1.1"}
        })),
        ..CallInput::default()
    };
    let receipt = prepare_security_action_input(&capability, &mut input)
        .expect("safe action")
        .expect("governance receipt");
    assert_eq!(
        input.body.as_ref().and_then(|body| body.get("mode")),
        Some(&json!("managed_challenge"))
    );
    assert_eq!(
        input
            .body
            .as_ref()
            .and_then(|body| body.pointer("/configuration/value")),
        Some(&json!("1.1.1.1"))
    );
    assert_eq!(receipt.get("permanent_action"), Some(&json!(false)));
    assert_eq!(
        receipt.get("anonymous_identity_inferred"),
        Some(&json!(false))
    );
    assert!(receipt.get("expires_at").and_then(Value::as_str).is_some());
    validate_request_contract(&capability, &input).expect("compiled wire body");
}

#[test]
pub(super) fn security_action_rejects_self_block_broad_unconfirmed_scope_and_reserved_targets() {
    let capability = security_action_create_capability();
    let body = |action_target: Value| {
        json!({
            "action":"block",
            "actor":"operator@example.test",
            "evidence_ref":format!("sha256:{}", "b".repeat(64)),
            "reason":"Confirmed source abuse",
            "target":action_target,
            "operator_ip":"1.1.1.1",
            "confirm_block":true
        })
    };
    let mut self_block = CallInput {
        selectors: json!({"zone_id":"zone-a"}),
        body: Some(body(json!({"type":"ip","value":"1.1.1.1"}))),
        ..CallInput::default()
    };
    assert!(prepare_security_action_input(&capability, &mut self_block).is_err());

    let mut broad = CallInput {
        selectors: json!({"zone_id":"zone-a"}),
        body: Some(json!({
            "actor":"operator@example.test",
            "evidence_ref":format!("sha256:{}", "c".repeat(64)),
            "reason":"Suspicious ASN classification",
            "target":{"type":"asn","value":"AS13335"}
        })),
        ..CallInput::default()
    };
    assert!(prepare_security_action_input(&capability, &mut broad).is_err());

    let mut reserved = CallInput {
        selectors: json!({"zone_id":"zone-a"}),
        body: Some(json!({
            "actor":"operator@example.test",
            "evidence_ref":format!("sha256:{}", "d".repeat(64)),
            "reason":"Invalid private target",
            "target":{"type":"ip","value":"127.0.0.1"}
        })),
        ..CallInput::default()
    };
    assert!(prepare_security_action_input(&capability, &mut reserved).is_err());
}

#[test]
pub(super) fn waf_security_action_compiles_typed_target_and_rejects_unsafe_escalation() {
    let capability = waf_security_action_create_capability();
    assert!(
        capability.security_action_contract_supported(),
        "{:?}",
        capability.mutation_contract_gaps()
    );
    let mut input = CallInput {
        selectors: json!({"zone_id":"zone","ruleset_id":"ruleset"}),
        body: Some(json!({
            "actor":"operator@example.com",
            "evidence_ref":format!("sha256:{}", "a".repeat(64)),
            "reason":"suspicious repeated source",
            "target":{"type":"hostname","value":"EXAMPLE.COM"}
        })),
        ..CallInput::default()
    };
    let receipt = prepare_security_action_input(&capability, &mut input)
        .expect("bounded WAF action")
        .expect("security receipt");
    assert_eq!(receipt["kind"], "create_expiring_waf");
    assert_eq!(receipt["action"], "managed_challenge");
    assert_eq!(receipt["target"]["value"], "example.com");
    assert_eq!(
        input.body.as_ref().and_then(|body| body.get("expression")),
        Some(&json!("http.host eq \"example.com\""))
    );
    assert!(
        input
            .body
            .as_ref()
            .and_then(|body| body.get("ref"))
            .and_then(Value::as_str)
            .is_some_and(|reference| {
                reference.starts_with("cfctl_security_") && reference.len() == 39
            })
    );

    let mut unsafe_block = CallInput {
        selectors: json!({"zone_id":"zone","ruleset_id":"ruleset"}),
        body: Some(json!({
            "action":"block",
            "actor":"operator@example.com",
            "evidence_ref":format!("sha256:{}", "b".repeat(64)),
            "reason":"broad host block",
            "target":{"type":"hostname","value":"example.com"},
            "operator_ip":"8.8.8.8",
            "confirm_block":true
        })),
        ..CallInput::default()
    };
    assert!(prepare_security_action_input(&capability, &mut unsafe_block).is_err());

    let mut unsafe_skip = CallInput {
        selectors: json!({"zone_id":"zone","ruleset_id":"ruleset"}),
        body: Some(json!({
            "action":"skip",
            "actor":"operator@example.com",
            "evidence_ref":format!("sha256:{}", "c".repeat(64)),
            "reason":"skip managed WAF",
            "target":{"type":"ip","value":"8.8.4.4"}
        })),
        ..CallInput::default()
    };
    assert!(prepare_security_action_input(&capability, &mut unsafe_skip).is_err());

    let mut ja4_without_entitlement_ack = CallInput {
        selectors: json!({"zone_id":"zone","ruleset_id":"ruleset"}),
        body: Some(json!({
            "actor":"operator@example.com",
            "evidence_ref":format!("sha256:{}", "d".repeat(64)),
            "reason":"suspicious JA4 fingerprint",
            "target":{"type":"ja4","value":"t13d1516h2_8daaf6152771_02713d6af862"}
        })),
        ..CallInput::default()
    };
    assert!(prepare_security_action_input(&capability, &mut ja4_without_entitlement_ack).is_err());
}

#[test]
pub(super) fn waf_nested_creation_receipt_lifts_only_correlated_id_and_derives_exact_removal() {
    let capability = waf_security_action_create_capability();
    let reference = "cfctl_security_0123456789abcdef01234567";
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({}),
    )
    .expect("plan");
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"zone_id":"zone-a", "ruleset_id":"ruleset-a"}),
        body: Some(json!({
            "action":"managed_challenge",
            "description":"bounded action",
            "enabled":true,
            "expression":"ip.src eq 1.1.1.1",
            "ref":reference
        })),
        ..CallInput::default()
    })
    .expect("call input");
    plan.refresh_hash().expect("bind call input");
    plan.approve(true, None).expect("approve");
    plan.mark_consumed().expect("consume");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("attempt");
    let response = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({
            "id":"ruleset-a",
            "rules":[{
                "id":"rule-a",
                "action":"managed_challenge",
                "description":"bounded action",
                "enabled":true,
                "expression":"ip.src eq 1.1.1.1",
                "ref":reference
            }]
        }),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let apply_evidence = EvidenceV1::new(
        EvidenceClass::Apply,
        "sha256:waf-create-apply-receipt",
        "/tmp/waf-create-apply-receipt.json",
    );
    let artifact = boundary_response_artifact(&plan, &response, Some(&apply_evidence));
    assert_eq!(artifact["resource_id"], "rule-a");
    assert!(!artifact.to_string().contains(reference));
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::BoundaryResponsePersisted,
        artifact,
    )
    .expect("response receipt");
    plan.status = PlanStatus::RectificationRequired;

    let request = compensation_request(&plan)
        .expect("request resolves")
        .expect("compensation is supported");

    assert_eq!(request.capability_id, "deleteZoneRulesetRule");
    assert_eq!(request.expected_method, "DELETE");
    assert_eq!(
        request.expected_path,
        "/zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}"
    );
    assert_eq!(
        request.input.selectors,
        json!({
            "zone_id":"zone-a",
            "ruleset_id":"ruleset-a",
            "rule_id":"rule-a"
        })
    );
    assert_eq!(request.input.query, json!({}));
    assert!(request.input.body.is_none());
    assert_eq!(request.requested_account.as_deref(), Some("account-a"));
}

#[test]
pub(super) fn wrangler_deploy_receipt_and_status_bind_the_promoted_version() {
    let version_id = "11111111-2222-3333-4444-555555555555";
    let receipt = json!({
        "stdout": format!("Uploaded jkca-web-home\nCurrent Version ID: {version_id}\n")
    });
    assert_eq!(
        wrangler_deploy_version_id(&receipt).as_deref(),
        Some(version_id)
    );
    for rejected in [
        "safe-version-id",
        "73656e6465722e707269766174652e6578616d706c65",
        "c2VuZGVyLnByaXZhdGUuZXhhbXBsZQ",
        "11111111-2222-3333-4444-55555555555A",
        "{11111111-2222-3333-4444-555555555555}",
    ] {
        assert!(
            wrangler_deploy_version_id(&json!({
                "structured_output": {"produced_version_id": rejected},
                "stdout": format!("Current Version ID: {rejected}")
            }))
            .is_none(),
            "noncanonical Worker identity escaped into a typed receipt"
        );
        assert!(
            wrangler_worker_version_id(&json!({
                "structured_output": {"produced_version_id": rejected},
                "stdout": format!("Worker Version ID: {rejected}")
            }))
            .is_none(),
            "noncanonical upload identity escaped into a typed receipt"
        );
        assert!(
            wrangler_versions_deploy_version_id(&format!("{rejected}@100")).is_none(),
            "noncanonical promotion identity escaped plan admission"
        );
    }

    let promoted = json!([{
        "strategy": "percentage",
        "versions": [{"version_id": version_id, "percentage": 100}]
    }]);
    assert!(wrangler_status_has_promoted_version(&promoted, version_id));

    let partial = json!([{
        "versions": [{"version_id": version_id, "percentage": 25}]
    }]);
    assert!(!wrangler_status_has_promoted_version(&partial, version_id));
    let unbound = json!({"version_id": version_id});
    assert!(!wrangler_status_has_promoted_version(&unbound, version_id));
    assert!(!wrangler_status_has_promoted_version(
        &promoted,
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    ));
}

#[test]
pub(super) fn wrangler_worker_versions_receipts_and_targets_are_exact() {
    let version_id = "11111111-2222-3333-4444-555555555555";
    let receipt = json!({
        "stdout": format!("Uploaded leakbar\nWorker Version ID: {version_id}\n")
    });
    assert_eq!(
        wrangler_worker_version_id(&receipt).as_deref(),
        Some(version_id)
    );
    assert_eq!(
        wrangler_versions_deploy_version_id(&format!("{version_id}@100")).as_deref(),
        Some(version_id)
    );
    assert!(wrangler_versions_deploy_version_id(&format!("{version_id}@25")).is_none());
    assert!(wrangler_versions_deploy_version_id("not-a-version@100").is_none());
    assert!(wrangler_versions_deploy_version_id(&format!("{version_id}@100@100")).is_none());

    let readback = json!({
        "id": version_id,
        "annotations": {"workers/message": "release 88ef60c"}
    });
    assert!(wrangler_version_readback_matches(
        &readback,
        version_id,
        "release 88ef60c"
    ));
    assert!(!wrangler_version_readback_matches(
        &readback,
        version_id,
        "release other"
    ));
}

#[test]
pub(super) fn wrangler_worker_versions_inputs_require_absolute_config_and_full_traffic() {
    let mut upload = CapabilityV1::new(
        "wrangler.versions-upload",
        "upload",
        "POST",
        "wrangler versions upload",
    );
    upload.adapter_status = AdapterStatus::DelegatedCli;
    validate_wrangler_worker_versions_input(
        &upload,
        &json!({"config": "/srv/leakbar/web/wrangler.toml"}),
    )
    .expect("absolute upload config");
    assert!(
        validate_wrangler_worker_versions_input(&upload, &json!({"config": "web/wrangler.toml"}),)
            .is_err()
    );

    let mut deploy = upload;
    deploy.id = "wrangler.versions-deploy".to_owned();
    validate_wrangler_worker_versions_input(
        &deploy,
        &json!({
            "config": "/srv/leakbar/web/wrangler.toml",
            "argument": "11111111-2222-3333-4444-555555555555@100"
        }),
    )
    .expect("one exact full-traffic target");
    assert!(
        validate_wrangler_worker_versions_input(
            &deploy,
            &json!({
                "config": "/srv/leakbar/web/wrangler.toml",
                "argument": "11111111-2222-3333-4444-555555555555@50"
            }),
        )
        .is_err()
    );
}

#[test]
pub(super) fn wrangler_pages_artifact_admission_rejects_empty_and_symlinked_roots() {
    let mut capability = CapabilityV1::new(
        "wrangler.pages-deploy",
        "deploy Pages artifact",
        "POST",
        "wrangler pages deploy",
    );
    capability.method = "CLI".to_owned();
    capability.adapter_status = AdapterStatus::DelegatedCli;
    let root = tempfile::tempdir().expect("artifact parent");
    let artifact = root.path().join("site");
    std::fs::create_dir(&artifact).expect("empty artifact");
    let input = CallInput {
        query: json!({"argument": artifact}),
        ..CallInput::default()
    };
    assert!(
        plan_local_artifact_paths(&capability, &input).is_err(),
        "an empty Pages root cannot construct the required provider manifest"
    );

    std::fs::write(artifact.join("index.html"), b"ok").expect("artifact file");
    #[cfg(unix)]
    {
        let alias = root.path().join("site-alias");
        std::os::unix::fs::symlink(&artifact, &alias).expect("artifact root symlink");
        let input = CallInput {
            query: json!({"argument": alias}),
            ..CallInput::default()
        };
        assert!(
            plan_local_artifact_paths(&capability, &input).is_err(),
            "canonicalization must not erase Pages artifact symlink provenance"
        );
    }
}

#[test]
pub(super) fn pages_omitted_source_admission_is_hash_bound_to_exact_direct_evidence() {
    let mut capability = CapabilityV1::new(
        "wrangler.pages-deploy",
        "deploy Pages artifact",
        "POST",
        "wrangler pages deploy",
    );
    capability.method = "CLI".to_owned();
    capability.adapter_status = AdapterStatus::DelegatedCli;
    let input = CallInput {
        query: json!({
            "project_name":"aos-web",
            "branch":"main",
            "commit_hash":"0a2c0165ab176f744539be371314dea086b80933"
        }),
        ..CallInput::default()
    };
    let deployment_id = "ff88ab4a-f284-4f06-86e0-c8ae3b459b60";
    let receipt = json!({
        "schema_version":1,
        "source_capability_id":pages_deployment::PROJECT_READ_CAPABILITY_ID,
        "source_path":pages_deployment::PROJECT_DETAIL_PATH,
        "target_capability_id":"wrangler.pages-deploy",
        "account_id":"account-a",
        "project_name":"aos-web",
        "production_branch":"main",
        "source_mode":"direct_upload",
        "source_mode_basis":"omitted_source_exact_direct_deployment",
        "corroborating_deployment_id":deployment_id,
        "prior_deployment_ids":[deployment_id],
        "prior_exact_identity_count":0,
        "deployment_list_source_capability_id":pages_deployment::DEPLOYMENT_LIST_CAPABILITY_ID,
    });
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-a",
        capability,
        serde_json::to_value(&input).expect("input"),
    )
    .expect("Pages plan");
    plan.input = serde_json::to_value(input).expect("plan input");
    plan.targets = json!({
        "live_preconditions":{
            pages_deployment::PROJECT_STATE_PRECONDITION:receipt.clone()
        }
    });
    plan.precondition_hashes.insert(
        pages_deployment::PROJECT_STATE_PRECONDITION.to_owned(),
        hash_value(&receipt).expect("receipt hash"),
    );
    assert_eq!(
        required_pages_deployment_project_state_precondition(&plan)
            .expect("exact omitted-source receipt"),
        plan.precondition_hashes
            .get(pages_deployment::PROJECT_STATE_PRECONDITION)
            .map(String::as_str)
    );

    plan.targets["live_preconditions"][pages_deployment::PROJECT_STATE_PRECONDITION]["corroborating_deployment_id"] =
        Value::Null;
    assert!(
        required_pages_deployment_project_state_precondition(&plan).is_err(),
        "the omitted-source basis cannot survive without its exact deployment identity"
    );
}

#[cfg(unix)]
#[tokio::test]
pub(super) async fn wrangler_pages_boundary_requires_governed_structured_output() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().expect("boundary root");
    let program = root.path().join("wrangler");
    let id = "22222222-2222-4222-8222-222222222222";
    std::fs::write(
            &program,
            format!(
                "#!/bin/sh\nprintf '%s\\n' '{{\"type\":\"pages-deploy\",\"version\":1,\"pages_project\":\"aos-web\",\"deployment_id\":\"{id}\",\"url\":\"https://example.pages.dev\"}}' '{{\"type\":\"pages-deploy-detailed\",\"version\":1,\"pages_project\":\"aos-web\",\"deployment_id\":\"{id}\",\"url\":\"https://example.pages.dev\",\"environment\":\"production\",\"production_branch\":\"main\",\"deployment_trigger\":{{\"metadata\":{{\"commit_hash\":\"{}\"}}}}}}' > \"$WRANGLER_OUTPUT_FILE_PATH\"\n",
                "a".repeat(40)
            ),
        )
        .expect("fake Wrangler");
    let mut permissions = std::fs::metadata(&program)
        .expect("fake Wrangler metadata")
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&program, permissions).expect("fake Wrangler mode");
    let cache = root.path().join("cache");
    std::fs::create_dir(&cache).expect("cache");
    let mut capability = CapabilityV1::new(
        "wrangler.pages-deploy",
        "deploy Pages artifact",
        "POST",
        "wrangler pages deploy",
    );
    capability.method = "CLI".to_owned();
    capability.adapter_status = AdapterStatus::DelegatedCli;
    let receipt = super::run_delegated_cli(
            &capability,
            &CallInput {
                selectors: json!({}),
                query: json!({"argument": root.path(), "project_name":"aos-web", "branch":"main", "commit_hash":"a".repeat(40)}),
                ..CallInput::default()
            },
            &cfctl_auth::AuthCredential::Bearer {
                token: "fixture-token".to_owned(),
            },
            Some("fixture-account"),
            &cache,
            Some(&program),
            Some(Path::new("/bin/sh")),
        )
        .await
        .expect("governed boundary receipt");
    assert_eq!(receipt["success"], true);
    assert_eq!(receipt["structured_output"]["deployment_id"], id);

    std::fs::write(&program, "#!/bin/sh\nexit 0\n").expect("missing-output Wrangler");
    let mut permissions = std::fs::metadata(&program)
        .expect("missing-output metadata")
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&program, permissions).expect("missing-output mode");
    let receipt = super::run_delegated_cli(
        &capability,
        &CallInput {
            selectors: json!({}),
            query: json!({"argument": root.path()}),
            ..CallInput::default()
        },
        &cfctl_auth::AuthCredential::Bearer {
            token: "fixture-token".to_owned(),
        },
        Some("fixture-account"),
        &cache,
        Some(&program),
        Some(Path::new("/bin/sh")),
    )
    .await
    .expect("missing output remains a truthful receipt");
    assert_eq!(receipt["success"], false);
    assert!(receipt["structured_output_error"].is_string());
}
