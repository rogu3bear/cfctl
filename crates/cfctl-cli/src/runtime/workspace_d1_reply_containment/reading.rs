use super::super::{
    prelude::{AuthCredential, CallInput, CapabilityV1, ProfileMetadata, Result, StateStore},
    workspace_d1_config,
};
use super::{
    compiler::BoundCompiler,
    contract, planning, rebind_source, rejected, stage,
    transport::{self, Transport},
};
use cfctl_core::reply_lifecycle::containment::{
    ReplyContainmentPlanBindingV3, ReplyContainmentPriorReadV3,
    ReplyContainmentRequestV3 as Request,
    evidence::{NativeContainmentReadV3, NativeReadPhaseV3, ReadbackResultV3},
    observation::{ROW_KEYS, SourceObservationV3},
    sql,
};
use cfctl_core::{PlanStatus, ReplyContainmentOperationV3, ResultEnvelopeV2, TransactionStageV1};
use chrono::Utc;
use serde_json::{Map, Value, json};

pub(in crate::runtime) async fn read(
    store: &StateStore,
    capability: &CapabilityV1,
    input: &CallInput,
    credential: &AuthCredential,
    profile: &ProfileMetadata,
    account: &str,
    source: Option<&std::path::Path>,
) -> Result<Value> {
    rebind_source(store, capability)?;
    let c = contract(capability)?;
    let config = workspace_d1_config::validated_config(c.into(), input)?;
    if c.operation_kind == ReplyContainmentOperationV3::Read {
        if source.is_some()
            || input.body.is_some()
            || input.query.as_object().is_none_or(|v| v.len() != 5)
        {
            return Err(rejected());
        }
        return read_plan(store, input, credential, profile, account).await;
    }
    if c.operation_kind != ReplyContainmentOperationV3::PreRead
        || input.body.is_some()
        || input.query.as_object().is_none_or(|v| v.len() != 1)
    {
        return Err(rejected());
    }
    let value: Value = serde_json::from_slice(&stage::read_input(source.ok_or_else(rejected)?)?)?;
    let request = Request::from_value(value).map_err(|_| rejected())?;
    planning::validate_request_authority(&request, c, profile, account, &config.database_id)?;
    let compiler = BoundCompiler::new(store, c)?;
    let prepared = compiler.compile(&serde_json::to_value(&request)?, true)?;
    let expected = json!({"schema_version":3,"kind":"maildesk_reply_containment_pre_read_request",
        "request_sha256":cfctl_core::hash_value(&serde_json::to_value(&request)?)?,"request":request});
    if prepared != expected {
        return Err(rejected());
    }
    let producer = transport::producer(c)?;
    let transport = Transport {
        store,
        contract: c,
        config: &config,
        credential,
        account,
        producer: &producer,
    };
    let rows = transport
        .query(&sql::pre_read(&request).map_err(|_| rejected())?)
        .await?;
    if rows.len() != 1 {
        return Err(rejected());
    }
    let observation = SourceObservationV3::from_row(&rows[0]).map_err(|_| rejected())?;
    let prior = request
        .replacement
        .as_ref()
        .map(|replacement| {
            prior_read(
                store,
                &replacement.source_containment_read_content_hash,
                account,
                &config.database_id,
            )
        })
        .transpose()?;
    Ok(serde_json::to_value(
        observation
            .pre_read(&request, prior, Utc::now())
            .map_err(|_| rejected())?,
    )?)
}

fn prior_read(
    store: &StateStore,
    hash: &str,
    account: &str,
    database: &str,
) -> Result<ReplyContainmentPriorReadV3> {
    let read = store.load_reply_containment_read(hash, NativeReadPhaseV3::Readback)?;
    let result: ReadbackResultV3 = serde_json::from_value(read.body()["result"].clone())?;
    let plan = store.load_plan_v2(&result.containment_operation_id)?;
    validate_read_plan(&plan.plan)?;
    if result.status != "performed"
        || !result.containment_applied
        || !result.send_blocked
        || result.match_count != 1
        || plan.plan.status != PlanStatus::Verified
        || plan.plan.transaction_stage != TransactionStageV1::Closed
        || plan.plan.account_id != account
        || plan.plan.content_hash != result.plan_content_hash
        || plan
            .plan
            .approval
            .as_ref()
            .is_none_or(|approval| approval.approved_content_hash != plan.plan.content_hash)
        || planning::target(&plan.plan)?
            .pointer("/config/database_id")
            .and_then(Value::as_str)
            != Some(database)
    {
        return Err(rejected());
    }
    let (candidate, _) = planning::historical_candidate(store, &plan.plan)?;
    if candidate.compiled()["readback_binding"] != serde_json::to_value(&result.binding)?
        || candidate.semantic_bundle() != result.semantic_bundle_sha256
        || read.body()["result"]["authority"] != planning::target(&plan.plan)?["authority"]
    {
        return Err(rejected());
    }
    Ok(ReplyContainmentPriorReadV3 {
        read_content_hash: hash.into(),
        origin: NativeReadPhaseV3::Readback.producer().into(),
        read_operation_id: read.body()["operation_id"]
            .as_str()
            .ok_or_else(rejected)?
            .into(),
        plan: ReplyContainmentPlanBindingV3 {
            operation_id: plan.plan.operation_id,
            content_hash: plan.plan.content_hash,
        },
        candidate: candidate.request().candidate.clone(),
        binding: result.binding,
        observed_at: result.observed_at,
        performed: true,
        send_blocked: true,
    })
}

async fn read_plan(
    store: &StateStore,
    input: &CallInput,
    credential: &AuthCredential,
    profile: &ProfileMetadata,
    account: &str,
) -> Result<Value> {
    let operation = input.query["containment_operation_id"]
        .as_str()
        .ok_or_else(rejected)?;
    let plan = store.load_plan_v2(operation)?;
    validate_read_plan(&plan.plan)?;
    if plan.plan.capability.id != ReplyContainmentOperationV3::Apply.capability_id()
        || plan.plan.profile_id != profile.id
        || plan.plan.account_id != account
    {
        return Err(rejected());
    }
    let bound = planning::rebind(store, &plan.plan, false)?;
    for (key, expected) in [
        (
            "containment_transaction_sha256",
            bound.candidate.transaction(),
        ),
        ("semantic_bundle_sha256", bound.candidate.semantic_bundle()),
        ("plan_content_hash", plan.plan.content_hash.as_str()),
    ] {
        if input.query[key].as_str() != Some(expected) {
            return Err(rejected());
        }
    }
    if input.selectors["database_id"].as_str() != Some(bound.config.database_id.as_str())
        || input.query["config"].as_str() != Some(bound.config.path.as_str())
    {
        return Err(rejected());
    }
    read_bound(store, &plan.plan, &bound, credential).await
}

pub(super) async fn read_bound(
    store: &StateStore,
    plan: &cfctl_core::PlanV1,
    bound: &planning::BoundPlan,
    credential: &AuthCredential,
) -> Result<Value> {
    validate_read_plan(plan)?;
    let c = contract(&plan.capability)?;
    let transport = Transport {
        store,
        contract: c,
        config: &bound.config,
        credential,
        account: &plan.account_id,
        producer: &bound.producer,
    };
    let sql = sql::readback(&bound.candidate, &plan.operation_id, &plan.content_hash)
        .map_err(|_| rejected())?;
    let rows = transport.query(&sql).await?;
    if rows.len() != 1 {
        return Err(rejected());
    }
    let result = bound
        .candidate
        .readback(
            &rows[0],
            &ReplyContainmentPlanBindingV3 {
                operation_id: plan.operation_id.clone(),
                content_hash: plan.content_hash.clone(),
            },
            Utc::now(),
        )
        .map_err(|_| rejected())?;
    Ok(serde_json::to_value(result)?)
}

fn validate_read_plan(plan: &cfctl_core::PlanV1) -> Result<()> {
    use cfctl_core::{EffectClass, RiskClass};
    if plan.capability.id != ReplyContainmentOperationV3::Apply.capability_id()
        || plan.capability.risk != RiskClass::IdentityOrOwnership
        || plan.capability.effect != EffectClass::IdentityOrOwnership
        || matches!(
            plan.status,
            PlanStatus::Draft | PlanStatus::Approved | PlanStatus::Expired | PlanStatus::Cancelled
        )
        || plan
            .approval
            .as_ref()
            .is_none_or(|approval| approval.approved_content_hash != plan.content_hash)
    {
        return Err(rejected());
    }
    plan.validate_transaction_journal()?;
    for required in [
        TransactionStageV1::ConsumptionPersisted,
        TransactionStageV1::BoundaryAttemptPersisted,
    ] {
        if !plan.transaction_journal.iter().any(|checkpoint| {
            checkpoint.stage == required && checkpoint.plan_content_hash == plan.content_hash
        }) {
            return Err(rejected());
        }
    }
    if let Some(response) = plan.transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
        && (response["boundary_crossed"] == false || response["outcome"] == "not_attempted")
    {
        return Err(rejected());
    }
    Ok(())
}

pub(in crate::runtime) fn seal_read(
    store: &StateStore,
    envelope: &mut ResultEnvelopeV2,
) -> Result<()> {
    if !envelope.ok {
        return Ok(());
    }
    if envelope
        .attestation
        .as_ref()
        .is_none_or(|a| a.state != cfctl_core::AttestationStateV1::Attested)
    {
        return Err(rejected());
    }
    let read = NativeContainmentReadV3::new(envelope).map_err(|_| rejected())?;
    let evidence = store.write_reply_containment_read(&read)?;
    if read.phase() == NativeReadPhaseV3::Readback {
        envelope.result = json!({"schema_version":1,"kind":"maildesk_reply_containment_stored_read","content_hash":evidence.content_hash,"envelope":read.body()});
    }
    Ok(())
}

pub(in crate::runtime) fn project_private_query_rows(
    sql: &str,
    rows: &[Map<String, Value>],
) -> Option<Result<()>> {
    if !sql.starts_with("SELECT json_object('route_id',rr.route_id,")
        || !sql.contains(" AS cfctl_reply_containment_source,")
        || !sql.ends_with(" LIMIT 2")
    {
        return None;
    }
    Some((|| {
        if rows.len() > 2 {
            return Err(rejected());
        }
        let readback = sql.contains(" AS plan_count,");
        for row in rows {
            if row.len() != if readback { 9 } else { 6 }
                || !ROW_KEYS.iter().all(|key| row.contains_key(*key))
                || (readback
                    && !["plan_count", "route_quarantined", "replacement_matches"]
                        .iter()
                        .all(|key| row.contains_key(*key)))
            {
                return Err(rejected());
            }
            SourceObservationV3::from_row(row).map_err(|_| rejected())?;
            if readback
                && (row["plan_count"].as_u64().is_none()
                    || !matches!(row["route_quarantined"].as_u64(), Some(0 | 1))
                    || !(row["replacement_matches"].is_null()
                        || matches!(row["replacement_matches"].as_u64(), Some(0 | 1))))
            {
                return Err(rejected());
            }
        }
        Ok(())
    })())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfctl_core::{CapabilityV1, EffectClass, PlanV1, RiskClass};
    #[test]
    fn post_read_requires_consumed_approved_attempt_and_keeps_unknown_recoverable()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut capability = CapabilityV1::new(
            ReplyContainmentOperationV3::Apply.capability_id(),
            "Contain",
            "POST",
            "workspace",
        );
        capability.risk = RiskClass::IdentityOrOwnership;
        capability.effect = EffectClass::IdentityOrOwnership;
        capability.workspace_d1_reply_admission =
            Some(super::super::test_support::contract().into());
        let mut plan = PlanV1::draft(
            "profile:test",
            "account:test",
            "catalog",
            capability,
            json!({}),
        )?;
        assert!(validate_read_plan(&plan).is_err());
        plan.approve(true, None)?;
        assert!(validate_read_plan(&plan).is_err());
        plan.mark_consumed()?;
        assert!(validate_read_plan(&plan).is_err());
        plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)?;
        assert!(validate_read_plan(&plan).is_ok());
        let mut wrong = plan.clone();
        wrong
            .approval
            .as_mut()
            .ok_or("approval")?
            .approved_content_hash = "different".into();
        assert!(validate_read_plan(&wrong).is_err());
        let mut unknown = plan.clone();
        unknown.status = PlanStatus::RectificationRequired;
        unknown.record_transaction_stage_with_artifact(
            TransactionStageV1::BoundaryResponsePersisted,
            json!({"outcome":"no_receipt"}),
        )?;
        assert!(validate_read_plan(&unknown).is_ok());
        let mut not_attempted = plan;
        not_attempted.status = PlanStatus::RectificationRequired;
        not_attempted.record_transaction_stage_with_artifact(
            TransactionStageV1::BoundaryResponsePersisted,
            json!({"outcome":"not_attempted"}),
        )?;
        assert!(validate_read_plan(&not_attempted).is_err());
        Ok(())
    }
}
