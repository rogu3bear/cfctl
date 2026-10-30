use super::{CompiledReplyContainmentV3 as Candidate, ReplyContainmentRequestV3 as Request, sql};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use std::io::Write as _;

pub(super) fn fixture(name: &str) -> Result<Value, serde_json::Error> {
    serde_json::from_str(match name {
        "pre" => include_str!("tests/fixtures/pre_send_rollback.json"),
        "claimed" => include_str!("tests/fixtures/pre_send_claimed.json"),
        "nonnull" => include_str!("tests/fixtures/post_boundary_nonnull.json"),
        "post" => include_str!("tests/fixtures/post_boundary_containment.json"),
        "replacement" => include_str!("tests/fixtures/replacement.json"),
        _ => unreachable!("closed test fixture name"),
    })
}

pub(super) fn bind(value: &Value) -> Result<Candidate, Box<dyn std::error::Error>> {
    let request = Request::from_value(value["request"].clone())?;
    let now: DateTime<Utc> = serde_json::from_value(value["now"].clone())?;
    Ok(Candidate::bind(
        request,
        &value["pre_read"],
        &value["compiled"],
        now,
    )?)
}

#[test]
fn native_semantics_match_independent_committed_app_compiler()
-> Result<(), Box<dyn std::error::Error>> {
    for name in ["pre", "claimed", "post", "nonnull", "replacement"] {
        let fixture = fixture(name)?;
        assert_eq!(bind(&fixture)?.compiled(), &fixture["compiled"]);
    }
    Ok(())
}

#[test]
fn request_rejects_mixed_protocol_privacy_scope_and_missing_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let valid = fixture("pre")?["request"].clone();
    for (pointer, value) in [
        ("/schema_version", json!(2)),
        ("/candidate/dirty", json!(true)),
        ("/source/relay_id", json!("bad ref with whitespace")),
        ("/control_plane/cfctl_build_sha256", json!("a".repeat(64))),
        ("/requested_at", json!("2026-02-30T01:00:00Z")),
    ] {
        let mut request = valid.clone();
        *request
            .pointer_mut(pointer)
            .ok_or("missing fixture pointer")? = value;
        assert!(Request::from_value(request).is_err(), "accepted {pointer}");
    }
    let mut missing = valid.clone();
    missing
        .as_object_mut()
        .ok_or("fixture object")?
        .remove("source");
    assert!(Request::from_value(missing).is_err());
    let mut extra = valid;
    extra["provider_payload"] = json!("not permitted");
    assert!(Request::from_value(extra).is_err());
    Ok(())
}

#[test]
fn false_stale_mixed_and_changed_compiler_evidence_cannot_bind()
-> Result<(), Box<dyn std::error::Error>> {
    let valid = fixture("pre")?;
    for (pointer, replacement) in [
        ("/pre_read/schema_version", json!(1)),
        ("/pre_read/ok", json!(false)),
        ("/pre_read/performed", json!(false)),
        ("/pre_read/policy_decision/schema_version", json!(2)),
        (
            "/pre_read/policy_decision/disposition",
            json!("approval_required"),
        ),
        ("/pre_read/result/match_count", json!(0)),
        (
            "/pre_read/result/source_state/reply_admission/claimed_attempt_sha256",
            json!(format!("sha256:{}", "2".repeat(64))),
        ),
        (
            "/request/controller/correlation_sha256",
            json!(format!("sha256:{}", "1".repeat(64))),
        ),
        ("/pre_read/result/body_returned", json!(true)),
        (
            "/pre_read/result/observed_at",
            json!("2026-08-25T11:59:59.000Z"),
        ),
        (
            "/pre_read/result/observed_at",
            json!("2026-08-25T12:01:00.001Z"),
        ),
        (
            "/compiled/plan/records/1/preserve_original_row",
            json!(true),
        ),
        ("/compiled/send_blocked", json!(true)),
        (
            "/compiled/transaction_sha256",
            json!(format!("sha256:{}", "1".repeat(64))),
        ),
    ] {
        let mut value = valid.clone();
        // Last-member insertion is intentionally allowed only in this fixture
        // mutation so unknown compiler keys are tested as well.
        if pointer == "/compiled/plan/records/1/preserve_original_row" {
            value["compiled"]["plan"]["records"][1]["preserve_original_row"] = json!(true);
        } else {
            *value
                .pointer_mut(pointer)
                .ok_or("missing fixture pointer")? = replacement;
        }
        assert!(bind(&value).is_err(), "accepted {pointer}");
    }
    Ok(())
}

#[test]
fn pre_send_sql_has_whole_import_assertions_and_disjoint_plan_identity()
-> Result<(), Box<dyn std::error::Error>> {
    for name in ["pre", "claimed"] {
        let fixture = fixture(name)?;
        let candidate = bind(&fixture)?;
        let sql = sql::mutation(
            &candidate,
            "plan:fixture",
            &format!("sha256:{}", "1".repeat(64)),
            None,
        )?;
        assert!(sql.starts_with("SELECT CASE WHEN"));
        assert_eq!(sql.matches("ELSE json('{')").count(), 3);
        assert_eq!(
            sql.matches("INSERT INTO reply_containment_plan_records")
                .count(),
            2
        );
        assert_eq!(
            sql.matches("INSERT INTO route_outbound_quarantines")
                .count(),
            1
        );
        assert!(!sql.contains("BEGIN") && !sql.contains("DELETE") && !sql.contains("CREATE"));
        assert!(sql.contains("status IN ('admitted','claimed') AND provider_boundary_at IS NULL"));
        assert!(!sql.contains(candidate.semantic_bundle()));
        assert!(sql::mutation(&candidate, "plan:fixture", "1", None).is_err());
        // The exact native producer output is consumed by the app's real SQLite
        // fixture qualification, not a second handwritten copy of these effects.
        emit_fixture(
            &json!({"action":name,"request":fixture["request"],"source_state":fixture["compiled"]["source_state"],"sql":sql,"pre_read_sql":sql::pre_read(candidate.request())?}),
        )?;
    }
    Ok(())
}

#[test]
fn post_boundary_preserves_admission_and_replacement_preserves_quarantine()
-> Result<(), Box<dyn std::error::Error>> {
    for name in ["post", "replacement"] {
        let value = fixture(name)?;
        let candidate = bind(&value)?;
        let sql = sql::mutation(
            &candidate,
            "plan:fixture",
            &format!("sha256:{}", "1".repeat(64)),
            None,
        )?;
        assert!(!sql.contains("UPDATE reply_admissions"));
        if name == "post" {
            assert!(sql.contains("INSERT INTO route_outbound_quarantines"));
        } else {
            assert!(!sql.contains("INSERT INTO route_outbound_quarantines"));
            assert!(
                sql.find("INSERT INTO reply_relay_replacements") < sql.find("UPDATE reply_relays")
            );
            assert!(sql.contains("pr.outcome='performed'"));
        }
        assert!(
            sql::mutation(
                &candidate,
                "plan:fixture",
                &format!("sha256:{}", "1".repeat(64)),
                Some("changed-private-provider-id")
            )
            .is_err()
        );
        emit_fixture(
            &json!({"action":name,"request":value["request"],"source_state":value["compiled"]["source_state"],"attempt_observation":value["compiled"]["attempt_observation"],"prior_containment":value["compiled"]["prior_containment"],"sql":sql,"pre_read_sql":sql::pre_read(candidate.request())?}),
        )?;
    }
    Ok(())
}

pub(super) fn emit_fixture(value: &Value) -> std::io::Result<()> {
    if std::env::var("CFCTL_EMIT_CONTAINMENT_SQL").as_deref() == Ok("1") {
        writeln!(std::io::stdout().lock(), "CONTAINMENT_SQL_FIXTURE={value}")?;
    }
    Ok(())
}
