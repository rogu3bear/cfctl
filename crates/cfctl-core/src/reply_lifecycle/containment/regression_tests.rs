use super::{
    ReplyContainmentPlanBindingV3, ReplyContainmentRequestV3,
    evidence::NativeContainmentReadV3,
    observation::SourceObservationV3,
    sql,
    tests::{bind, fixture},
};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

fn row(value: &Value, private_id: Value, error: Value) -> Value {
    let source = &value["pre_read"]["result"]["source_state"];
    let attempt = &value["pre_read"]["result"]["attempt_observation"];
    json!({"cfctl_reply_containment_source":source.to_string(),"attempt_id":source["reply_admission"]["claimed_attempt_id"],
        "attempt_status":attempt["status"],"private_provider_message_id":private_id,
        "attempt_error_code":error,"attempt_updated_at":attempt["updated_at"]})
}

#[test]
fn observed_error_codes_accept_the_exact_owner_alphabet() -> Result<(), Box<dyn std::error::Error>>
{
    let value = fixture("post")?;
    let request = ReplyContainmentRequestV3::from_value(value["request"].clone())?;
    let now: DateTime<Utc> = serde_json::from_value(value["now"].clone())?;
    for code in ["_TEMP", "-1", ".retry", ":unknown", "A"]
        .into_iter()
        .map(str::to_owned)
        .chain(["x".repeat(96)])
    {
        let row = row(&value, Value::Null, json!(code));
        let observation = SourceObservationV3::from_row(row.as_object().ok_or("row")?)?;
        assert!(observation.pre_read(&request, None, now).is_ok());
    }
    for code in ["", "with spaces", "line\nbreak"]
        .into_iter()
        .map(str::to_owned)
        .chain(["x".repeat(97)])
    {
        let row = row(&value, Value::Null, json!(code));
        let observation = SourceObservationV3::from_row(row.as_object().ok_or("row")?)?;
        assert!(observation.pre_read(&request, None, now).is_err());
    }
    Ok(())
}

#[test]
fn native_seal_rejects_outer_authority_and_operation_substitution()
-> Result<(), Box<dyn std::error::Error>> {
    let value = fixture("pre")?;
    let native: crate::ResultEnvelopeV2 = serde_json::from_value(value["pre_read"].clone())?;
    assert!(NativeContainmentReadV3::new(&native).is_ok());
    let mut other = native.clone();
    other.profile_id = Some("profile:other".into());
    assert!(NativeContainmentReadV3::new(&other).is_err());
    other = native.clone();
    other.account_id = Some("account:other".into());
    assert!(NativeContainmentReadV3::new(&other).is_err());
    other = native.clone();
    other.result["authority"]["cfctl_build_sha256"] = json!("invalid");
    assert!(NativeContainmentReadV3::new(&other).is_err());
    let candidate = bind(&value)?;
    let mut observed = row(&value, Value::Null, Value::Null);
    let mut state = value["compiled"]["source_state"].clone();
    state["relay"]["revoked_at"] = value["request"]["requested_at"].clone();
    state["reply_admission"]["status"] = json!("revoked");
    state["reply_admission"]["terminal_at"] = value["request"]["requested_at"].clone();
    observed["cfctl_reply_containment_source"] = json!(state.to_string());
    observed["plan_count"] = json!(1);
    observed["route_quarantined"] = json!(1);
    observed["replacement_matches"] = Value::Null;
    let plan = ReplyContainmentPlanBindingV3 {
        operation_id: "mutation:test".into(),
        content_hash: format!("sha256:{}", "1".repeat(64)),
    };
    let result = candidate.readback(
        observed.as_object().ok_or("row")?,
        &plan,
        serde_json::from_value(value["now"].clone())?,
    )?;
    other = native;
    other.capability_id = Some("star-maildesk-cf.reply-containment-read".into());
    other.result = serde_json::to_value(result)?;
    other.operation_id = Some(plan.operation_id);
    assert!(NativeContainmentReadV3::new(&other).is_err());
    other.operation_id = Some("read:test".into());
    assert!(NativeContainmentReadV3::new(&other).is_ok());
    Ok(())
}

#[test]
fn nonnull_private_provider_id_is_exactly_compared_but_never_projected()
-> Result<(), Box<dyn std::error::Error>> {
    let value = fixture("nonnull")?;
    let candidate = bind(&value)?;
    let private = "provider:'reply/é";
    let observed = row(&value, json!(private), Value::Null);
    let observation = SourceObservationV3::from_row(observed.as_object().ok_or("row")?)?;
    let request = ReplyContainmentRequestV3::from_value(value["request"].clone())?;
    let projected = observation.pre_read(
        &request,
        None,
        serde_json::from_value(value["now"].clone())?,
    )?;
    assert!(!serde_json::to_string(&projected)?.contains(private));
    let plan_hash = format!("sha256:{}", "1".repeat(64));
    let sql = sql::mutation(
        &candidate,
        "mutation:test",
        &plan_hash,
        observation.private_provider_message_id(),
    )?;
    assert!(sql.contains("att.provider_message_id IS 'provider:''reply/é'"));
    super::tests::emit_fixture(
        &json!({"action":"nonnull","request":value["request"],"compiled":value["compiled"],"sql":sql,"pre_read_sql":sql::pre_read(candidate.request())?,"readback_sql":sql::readback(&candidate,"mutation:test",&plan_hash)?}),
    )?;
    for wrong in [None, Some(""), Some("provider:other")] {
        assert!(sql::mutation(&candidate, "mutation:test", &plan_hash, wrong).is_err());
    }
    Ok(())
}

#[test]
fn incomplete_one_row_readback_preserves_cardinality_and_ambiguity()
-> Result<(), Box<dyn std::error::Error>> {
    let value = fixture("post")?;
    let candidate = bind(&value)?;
    let mut observed = row(&value, Value::Null, Value::Null);
    observed["plan_count"] = json!(1);
    observed["route_quarantined"] = json!(0);
    observed["replacement_matches"] = Value::Null;
    let plan = ReplyContainmentPlanBindingV3 {
        operation_id: "mutation:test".into(),
        content_hash: format!("sha256:{}", "1".repeat(64)),
    };
    let result = candidate.readback(
        observed.as_object().ok_or("row")?,
        &plan,
        serde_json::from_value(value["now"].clone())?,
    )?;
    assert_eq!(result.match_count, 1);
    assert_eq!(result.status, "ambiguous");
    assert!(!result.containment_applied && !result.send_blocked && !result.replay_allowed);
    Ok(())
}
