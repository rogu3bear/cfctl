use cfctl_core::{
    AdapterStatus, CapabilityAuthorityScopeV1, CapabilityV1, EffectClass, Maturity, RiskClass,
    SelectorV1,
};

pub(super) fn workspace_d1_qualification_observer_capability() -> CapabilityV1 {
    let hash = serde_json::json!({"type":"string","pattern":"^sha256:[0-9a-f]{64}$"});
    let operation = serde_json::json!({
        "type":"string",
        "pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    });
    let mut capability = CapabilityV1::new(
        "workspace-d1-qualification-observe",
        "Bind one public D1 schema read to one qualification attempt",
        "POST",
        "/cfctl/workspace/d1/qualification/observe",
    );
    capability.description = Some(
        "Authenticate one existing public d1-schema-introspection OperationalProofV1 as a before or after schema/ledger observation of one exact current Founder migration PlanV2. The local derivation verifies the source call input and public Cloudflare response envelope, binds the attempted operation and plan hashes, and records a distinct LiveRead proof without crossing a provider boundary."
            .to_owned(),
    );
    capability.authority_scope = Some(CapabilityAuthorityScopeV1::ProviderGeneric);
    "D1".clone_into(&mut capability.product);
    "cfctl native workspace D1 qualification observer".clone_into(&mut capability.source);
    "local_authenticated_evidence".clone_into(&mut capability.account_scope);
    capability.mutating = false;
    capability.risk = RiskClass::Read;
    capability.effect = EffectClass::ReadOnly;
    capability.maturity = Maturity::GenerallyAvailable;
    capability.adapter_status = AdapterStatus::Native;
    capability.entitlement.available = Some(true);
    capability.verification.required = true;
    "operation_bound_public_d1_proof".clone_into(&mut capability.verification.strategy);
    capability.request_schema = Some(serde_json::json!({
        "type":"object","additionalProperties":false,"x-cfctl-body-required":true,
        "required":["schema_version","attempted_operation_id","attempted_plan_hash","phase","observation","source_proof_hash","source_assertion"],
        "properties":{
            "schema_version":{"type":"integer","const":1},
            "attempted_operation_id":operation,
            "attempted_plan_hash":hash.clone(),
            "phase":{"type":"string","enum":["before","after"]},
            "observation":{"type":"string","enum":["schema","ledger"]},
            "source_proof_hash":hash,
            "source_assertion":{"type":"object"}
        }
    }));
    capability.selectors = vec![
        SelectorV1 {
            name: "account_id".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: Some("Exact Cloudflare account identifier".to_owned()),
            contract: None,
        },
        SelectorV1 {
            name: "database_id".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: Some("Exact isolated D1 database identifier".to_owned()),
            contract: None,
        },
    ];
    capability
}

pub(super) fn workspace_d1_qualification_producer_capability() -> CapabilityV1 {
    let hash = serde_json::json!({"type":"string","pattern":"^sha256:[0-9a-f]{64}$"});
    let operation = serde_json::json!({
        "type":"string",
        "pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    });
    let proof_fields = [
        "get_database_proof_hash",
        "full_export_proof_hash",
        "bookmark_proof_hash",
        "ddl_failure_schema_before_proof_hash",
        "ddl_failure_schema_after_proof_hash",
        "ddl_failure_ledger_before_proof_hash",
        "ddl_failure_ledger_after_proof_hash",
        "ledger_failure_schema_before_proof_hash",
        "ledger_failure_schema_after_proof_hash",
        "ledger_failure_ledger_before_proof_hash",
        "ledger_failure_ledger_after_proof_hash",
        "cleanup_proof_hash",
    ];
    let operation_fields = [
        "create_database_operation_id",
        "success_apply_operation_id",
        "ddl_failure_apply_operation_id",
        "ledger_failure_apply_operation_id",
        "restore_operation_id",
        "delete_database_operation_id",
    ];
    let mut atomic_properties = serde_json::Map::new();
    for field in operation_fields {
        atomic_properties.insert(field.to_owned(), operation.clone());
    }
    for field in proof_fields {
        atomic_properties.insert(field.to_owned(), hash.clone());
    }
    let mut capability = CapabilityV1::new(
        "workspace-d1-qualification-produce",
        "Produce authenticated workspace D1 qualification joins",
        "POST",
        "/cfctl/workspace/d1/qualification/produce",
    );
    capability.description = Some(
        "Resolve an already-executed isolated D1 qualification from exact current PlanV2 identities, distinct authenticated before/after OperationalProofV1 observations, an exact-database not-found cleanup proof, and one authenticated Founder-owned behavioral canary EvidenceV1. The local producer accepts no raw receipt, SQL, provider output, caller-authored canary semantics, or secret key material; it invokes the existing closed validators and returns the two authenticated PostChangeVerification outer hashes plus six continuity joins. It performs no Cloudflare or Wrangler boundary and creates, approves, or runs no provider plan."
            .to_owned(),
    );
    capability.authority_scope = Some(CapabilityAuthorityScopeV1::ProviderGeneric);
    "D1".clone_into(&mut capability.product);
    "cfctl native workspace D1 qualification producer".clone_into(&mut capability.source);
    "local_authenticated_evidence".clone_into(&mut capability.account_scope);
    capability.aliases = vec![
        "produce a workspace D1 atomicity receipt and join a Founder canary".to_owned(),
        "finalize D1 migration qualification joins".to_owned(),
    ];
    capability.mutating = false;
    capability.risk = RiskClass::Read;
    capability.effect = EffectClass::ReadOnly;
    capability.maturity = Maturity::GenerallyAvailable;
    capability.adapter_status = AdapterStatus::Native;
    capability.entitlement.available = Some(true);
    capability.verification.required = true;
    "closed_authenticated_workspace_d1_qualification_validators"
        .clone_into(&mut capability.verification.strategy);
    capability.request_schema = Some(serde_json::json!({
        "type":"object","additionalProperties":false,"x-cfctl-body-required":true,
        "required":["schema_version","atomicity","old_worker_canary"],
        "properties":{
            "schema_version":{"type":"integer","const":1},
            "atomicity":{
                "type":"object","additionalProperties":false,
                "required":operation_fields.into_iter().chain(proof_fields).collect::<Vec<_>>(),
                "properties":atomic_properties,
            },
            "old_worker_canary":{
                "type":"object","additionalProperties":false,
                "required":["founder_canary_evidence_hash"],
                "properties":{
                    "founder_canary_evidence_hash":hash
                }
            }
        }
    }));
    capability
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::Utc;
    use serde_json::Value;

    use super::*;
    use crate::{CatalogSnapshot, ingest_native_control_capabilities};

    #[test]
    fn producer_is_local_non_mutating_and_accepts_only_closed_child_identities()
    -> Result<(), &'static str> {
        let capability = workspace_d1_qualification_producer_capability();
        assert_eq!(capability.id, "workspace-d1-qualification-produce");
        assert!(!capability.mutating);
        assert_eq!(capability.adapter_status, AdapterStatus::Native);
        assert!(capability.permissions.is_empty());
        let schema = capability
            .request_schema
            .ok_or("closed request schema is missing")?;
        assert_eq!(
            schema
                .pointer("/properties/atomicity/additionalProperties")
                .and_then(Value::as_bool),
            Some(false)
        );
        assert!(
            schema
                .pointer("/properties/atomicity/properties/atomicity_receipt")
                .is_none()
        );
        assert_eq!(
            schema
                .pointer("/properties/old_worker_canary/required/0",)
                .and_then(Value::as_str),
            Some("founder_canary_evidence_hash")
        );
        assert!(
            schema
                .pointer("/properties/old_worker_canary/properties/semantic_assertions_sha256",)
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn native_catalog_exposes_one_public_operation_bound_observation_capability()
    -> Result<(), &'static str> {
        let mut catalog = CatalogSnapshot {
            schema_version: 2,
            generated_at: Utc::now(),
            source_url: "fixture".to_owned(),
            source_hash: "fixture".to_owned(),
            schema_hash: String::new(),
            capabilities: BTreeMap::new(),
        };
        ingest_native_control_capabilities(&mut catalog).map_err(|_| "native catalog")?;

        let observer = catalog
            .get("workspace-d1-qualification-observe")
            .ok_or("public qualification observation capability")?;
        assert!(!observer.mutating);
        assert_eq!(observer.adapter_status, AdapterStatus::Native);
        assert!(observer.request_schema.is_some());
        Ok(())
    }
}
