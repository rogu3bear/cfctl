//! Current read qualification must not weaken restore's write gate.
use super::super::super::r2_restore_credentials::{qualify, qualify_capture};
use super::*;
use cfctl_core::r2_recovery::CaptureRequestV2;

fn request(fixture: &Fixture) -> (CaptureRequestV2, RestoreRequestV1) {
    let restore: RestoreRequestV1 =
        serde_json::from_value(fixture.input.body.clone().unwrap()).unwrap();
    let capture = CaptureRequestV2 {
        schema_version: 2,
        window: CaptureWindowV1 {
            window_id: Uuid::new_v4().to_string(),
            opened_at: Utc::now() - Duration::seconds(1),
            expires_at: Utc::now() + Duration::minutes(10),
            recovery_binding_sha256: "e".repeat(64),
        },
        token_verification_evidence_hash: restore.token_verification_evidence_hash.clone(),
        token_policy_evidence_hash: restore.token_policy_evidence_hash.clone(),
    };
    (capture, restore)
}
fn read_policy(f: &Fixture, request: &mut CaptureRequestV2, change: impl FnOnce(&mut Value)) {
    let mut value = f
        .store
        .read_evidence_value(&request.token_policy_evidence_hash)
        .unwrap();
    value["result"]["policies"][0]["permission_groups"] =
        json!([{"name":"Workers R2 Storage Read"}]);
    change(&mut value["result"]);
    let input = CallInput {
        selectors: json!({"account_id":"a".repeat(32),"token_id":"1".repeat(32)}),
        query: json!({}),
        ..CallInput::default()
    };
    request.token_policy_evidence_hash = proof(
        &f.store,
        "fixture-account-policy",
        &f.catalog.schema_hash,
        &input,
        &f.profile,
        &value,
        Utc::now(),
    );
}
#[test]
fn account_storage_read_admits_capture_and_still_rejects_restore() {
    let f = fixture(false);
    let (mut capture, mut restore) = request(&f);
    read_policy(&f, &mut capture, |_| {});
    assert_eq!(
        qualify_capture(&f.store, &f.catalog, &f.profile, &"a".repeat(32), &capture).unwrap(),
        "1".repeat(32)
    );
    restore.token_policy_evidence_hash = capture.token_policy_evidence_hash;
    assert!(
        qualify(
            &f.store,
            &f.catalog,
            &f.profile,
            &"a".repeat(32),
            &restore,
            capture.window.expires_at
        )
        .is_err()
    );
}
#[test]
fn rejects_stale_wrong_generation_account_catalog_and_unsupported_policy() {
    let stale = fixture(true);
    assert!(
        qualify_capture(
            &stale.store,
            &stale.catalog,
            &stale.profile,
            &"a".repeat(32),
            &request(&stale).0
        )
        .is_err()
    );
    let f = fixture(false);
    let (capture, _) = request(&f);
    let mut profile = f.profile.clone();
    profile.credential_generation_id = Some("other-generation".into());
    assert!(qualify_capture(&f.store, &f.catalog, &profile, &"a".repeat(32), &capture).is_err());
    assert!(qualify_capture(&f.store, &f.catalog, &f.profile, &"b".repeat(32), &capture).is_err());
    let mut catalog = f.catalog.clone();
    catalog.schema_hash = "other-build-catalog".into();
    assert!(qualify_capture(&f.store, &catalog, &f.profile, &"a".repeat(32), &capture).is_err());
    for case in ["expiry", "deny", "conditional", "bucket", "token_id"] {
        let (mut capture, _) = request(&f);
        let end = capture.window.expires_at;
        read_policy(&f, &mut capture, |value| match case {
            "expiry" => value["expires_on"] = json!(end),
            "deny" => value["policies"][0]["effect"] = json!("deny"),
            "conditional" => {
                value["policies"][0]["condition"] = json!({"request.ip":["127.0.0.1"]});
            }
            "bucket" => {
                value["policies"][0]["resources"] =
                    json!({"com.cloudflare.edge.r2.bucket.fake":"*"});
            }
            _ => value["id"] = json!("2".repeat(32)),
        });
        assert!(
            qualify_capture(&f.store, &f.catalog, &f.profile, &"a".repeat(32), &capture).is_err(),
            "{case}"
        );
    }
}
