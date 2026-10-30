use super::super::prelude::{AuthCredential, Result, StateStore};
use super::{contract, planning, reading, rejected, stage, transport::Transport};
use cfctl_core::reply_lifecycle::containment::{observation::SourceObservationV3, sql};
use cfctl_core::{BoundaryObservation, PlanV1};
use serde_json::{Value, json};

pub(in crate::runtime) async fn run(
    store: &StateStore,
    plan: &PlanV1,
    credential: &AuthCredential,
    boundary: &BoundaryObservation,
) -> Result<Value> {
    let bound = planning::rebind(store, plan, true)?;
    let c = contract(&plan.capability)?;
    let transport = Transport {
        store,
        contract: c,
        config: &bound.config,
        credential,
        account: &plan.account_id,
        producer: &bound.producer,
    };
    let rows = transport
        .query(&sql::pre_read(bound.candidate.request()).map_err(|_| rejected())?)
        .await?;
    if rows.len() != 1 {
        return Err(rejected());
    }
    let actual = SourceObservationV3::from_row(&rows[0]).map_err(|_| rejected())?;
    if serde_json::to_value(&actual.source)? != bound.candidate.compiled()["source_state"]
        || serde_json::to_value(&actual.attempt)?
            != bound.candidate.compiled()["attempt_observation"]
    {
        return Err(rejected());
    }
    let sql = sql::mutation(
        &bound.candidate,
        &plan.operation_id,
        &plan.content_hash,
        actual.private_provider_message_id(),
    )
    .map_err(|_| rejected())?;
    let path = stage::retain_sql(store, &bound.stage, &sql)?;
    let output = transport.apply(&path, boundary, plan).await;
    match output {
        Ok(output) => Ok(
            json!({"adapter":"maildesk_reply_containment_v3","success":output.success,"boundary_crossed":boundary.mutation_attempted(),
            "operation_id":plan.operation_id,"plan_content_hash":plan.content_hash,"sql_sha256":super::hash(sql.as_bytes()),
            "provider_output_retained":false,"body_returned":false,"retry_allowed":false}),
        ),
        Err(error) if !boundary.mutation_attempted() => Err(error),
        Err(_) => Ok(
            json!({"adapter":"maildesk_reply_containment_v3","success":false,"boundary_crossed":true,
            "operation_id":plan.operation_id,"plan_content_hash":plan.content_hash,"sql_sha256":super::hash(sql.as_bytes()),
            "failure_code":"CFCTL_CONTAINMENT_PROVIDER_RESULT_AMBIGUOUS","provider_output_retained":false,"body_returned":false,"retry_allowed":false}),
        ),
    }
}
pub(in crate::runtime) async fn verify(
    store: &StateStore,
    plan: &PlanV1,
    credential: &AuthCredential,
) -> Value {
    let result = async {
        let bound = planning::rebind(store, plan, false)?;
        reading::read_bound(store, plan, &bound, credential).await
    }
    .await;
    match result {
        Ok(receipt) => {
            json!({"passed":receipt["containment_applied"]==true,"basis":"one atomic containment outcome and preserved source history must match the immutable plan","readback":receipt})
        }
        Err(_) => {
            json!({"passed":false,"basis":"containment readback unavailable; reconcile the original operation without replay"})
        }
    }
}
