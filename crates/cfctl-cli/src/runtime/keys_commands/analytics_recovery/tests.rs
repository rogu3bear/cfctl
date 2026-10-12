#![allow(clippy::expect_used, clippy::unwrap_used)]
use super::*;
use cfctl_auth::ManagedApiTokenV1;
use cfctl_storage::RuntimePaths;
use chrono::{Duration, Utc};

pub(super) fn fixture() -> (
    KeyRenewAnalyticsProfileArgs,
    Request,
    ProfileMetadata,
    ProfileMetadata,
    StandingAuthorityV1,
) {
    let publisher = ProfileMetadata::new("publisher", ProfileKind::ApiToken, Some(&"a".repeat(32)));
    let minter = ProfileMetadata::new(
        "minter",
        ProfileKind::ApiToken,
        publisher.account_id.as_deref(),
    );
    let groups = vec![
        "b89a480218d04ceb98b4fe57ca29dc1f".to_owned(),
        "9c88f9c5bce24ce7af9a958ba9c504db".to_owned(),
    ];
    let authority = StandingAuthorityV1::draft(
        &"a".repeat(32),
        Some(&"b".repeat(32)),
        vec![
            "account-api-tokens-create-token".to_owned(),
            "account-api-tokens-delete-token".to_owned(),
        ],
        groups.clone(),
        &"c".repeat(64),
        168,
        "publisher-",
        2,
        Utc::now() + Duration::days(1),
    )
    .unwrap();
    let args = KeyRenewAnalyticsProfileArgs {
        profile: publisher.id.clone(),
        minter_profile: minter.id.clone(),
        account: "a".repeat(32),
        zone: "b".repeat(32),
        hostname: "example.com".to_owned(),
        permissions: groups.clone(),
        ttl_hours: 168,
        renew_before_hours: 24,
        name_prefix: "publisher-".to_owned(),
        under_policy: authority.authority_id.clone(),
        current_token_id: None,
        unmanaged_recovery: None,
        force: false,
    };
    let request = Request {
        schema_version: 1,
        profile: args.profile.clone(),
        publisher_generation: publisher.credential_generation_id.clone().unwrap(),
        minter_profile: args.minter_profile.clone(),
        minter_generation: minter.credential_generation_id.clone().unwrap(),
        account: args.account.clone(),
        zone: args.zone.clone(),
        hostname: args.hostname.clone(),
        authority_id: authority.authority_id.clone(),
        authority_content_hash: authority.content_hash.clone(),
        permission_group_ids: groups,
        ttl_hours: 168,
        old_token_disposition: OldTokenDisposition::UnknownNotRevoked,
    };
    (args, request, publisher, minter, authority)
}

#[test]
fn unknown_predecessor_request_rejects_claimed_cleanup_and_approval_flags() {
    let (_, request, _, _, _) = fixture();
    let value = serde_json::to_value(request).unwrap();
    for field in [
        "approved",
        "passed",
        "token_id",
        "token_value",
        "cleanup_verified",
    ] {
        let mut bad = value.clone();
        bad[field] = json!(true);
        assert!(serde_json::from_value::<Request>(bad).is_err(), "{field}");
    }
    let mut bad = value;
    bad["old_token_disposition"] = json!("revoked");
    assert!(serde_json::from_value::<Request>(bad).is_err());
}

#[test]
fn recovery_admission_rejects_generation_account_and_scope_drift() {
    let (args, request, publisher, minter, authority) = fixture();
    request
        .validate(&args, &publisher, &minter, &authority)
        .unwrap();
    let managed = activated(&publisher);
    assert!(
        request
            .validate(&args, &managed, &minter, &authority)
            .is_err()
    );
    let mut drift = publisher.clone();
    drift.credential_generation_id = Some(Uuid::new_v4().to_string());
    assert!(
        request
            .validate(&args, &drift, &minter, &authority)
            .is_err()
    );
    drift = publisher.clone();
    drift.account_id = Some("d".repeat(32));
    assert!(
        request
            .validate(&args, &drift, &minter, &authority)
            .is_err()
    );
    let mut drift_minter = minter.clone();
    drift_minter.credential_generation_id = Some(Uuid::new_v4().to_string());
    assert!(
        request
            .validate(&args, &publisher, &drift_minter, &authority)
            .is_err()
    );
    let mut drift_authority = authority.clone();
    drift_authority.content_hash = "e".repeat(64);
    assert!(
        request
            .validate(&args, &publisher, &minter, &drift_authority)
            .is_err()
    );
    let mut drift_request = request.clone();
    drift_request.hostname = "other.example.com".to_owned();
    assert!(
        drift_request
            .validate(&args, &publisher, &minter, &authority)
            .is_err()
    );
    drift_request = request;
    drift_request.permission_group_ids.push("extra".to_owned());
    assert!(
        drift_request
            .validate(&args, &publisher, &minter, &authority)
            .is_err()
    );
}

#[test]
fn activation_and_rollback_refuse_other_metadata_without_overwriting() {
    let (_, _, publisher, _, _) = fixture();
    require_unchanged(Some(&publisher), &publisher).unwrap();
    let mut changed = publisher.clone();
    changed.account_id = Some("f".repeat(32));
    assert!(require_unchanged(Some(&changed), &publisher).is_err());
    changed = publisher.clone();
    changed.emergency_only = true;
    assert!(require_unchanged(Some(&changed), &publisher).is_err());
    assert!(require_unchanged(None, &publisher).is_err());
    assert_ne!(changed, publisher);
}

fn open_session() -> (
    tempfile::TempDir,
    StateStore,
    KeyRenewAnalyticsProfileArgs,
    Session,
    ProfileMetadata,
) {
    let root = tempfile::tempdir().unwrap();
    let store = StateStore::open(RuntimePaths::from_root(
        &root.path().canonicalize().unwrap(),
    ))
    .unwrap();
    let (args, request, publisher, _, _) = fixture();
    let mut session = Session::open(&store, &args).unwrap();
    session.request = Some(request);
    (root, store, args, session, publisher)
}

fn claim(session: &mut Session, publisher: &ProfileMetadata) {
    // Journal mechanics only: these fixtures do not claim native PlanV2 proof.
    session
        .persist_attempt(publisher, &Uuid::new_v4().to_string())
        .unwrap();
}

fn reads(pass: bool) -> Vec<ResultEnvelopeV2> {
    (0..3)
        .map(|i| {
            let mut read = ResultEnvelopeV2::success("call", json!({"index":i}));
            read.performed = true;
            read.ok = pass;
            read
        })
        .collect()
}

pub(super) fn activated(publisher: &ProfileMetadata) -> ProfileMetadata {
    let mut active = publisher.clone();
    active.credential_generation_id = Some(Uuid::new_v4().to_string());
    active.api_token_slot_id = Some(Uuid::new_v4().to_string());
    active.managed_api_token = Some(ManagedApiTokenV1 {
        schema_version: 1,
        token_id: "fresh-child".to_owned(),
        expires_at: Utc::now() + Duration::days(7),
        standing_authority_id: Uuid::new_v4().to_string(),
        pending_revoke_token_id: None,
        pending_revoke_operation_id: None,
        pending_revoke_slot_id: None,
    });
    active
}

#[test]
fn pending_attempt_blocks_replay_and_competing_hourly_invocations() {
    let (_root, store, args, mut session, publisher) = open_session();
    assert!(
        Session::open(&store, &args).is_err(),
        "same-profile lock must exclude peers"
    );
    claim(&mut session, &publisher);
    assert!(
        session
            .persist_attempt(&publisher, &Uuid::new_v4().to_string())
            .is_err()
    );
    drop(session);
    assert!(
        Session::open(&store, &args).is_err(),
        "pending attempt must not mint again after process exit"
    );
}

#[test]
fn staged_or_active_failure_cannot_complete_or_clear_the_replay_fence() {
    let (_root, store, args, mut session, publisher) = open_session();
    claim(&mut session, &publisher);
    let active = activated(&publisher);
    session
        .retain_child("fresh-child", active.api_token_slot_id.as_deref().unwrap())
        .unwrap();
    assert!(
        session
            .complete(&active, &[], &reads(false), &reads(true))
            .is_err()
    );
    assert!(
        session
            .complete(&active, &[], &reads(true), &reads(false))
            .is_err()
    );
    assert!(
        session
            .complete(&active, &[], &reads(true)[..2], &reads(true))
            .is_err()
    );
    drop(session);
    assert!(Session::open(&store, &args).is_err());
}

#[test]
fn completed_bootstrap_preserves_unknown_cleanup_across_ordinary_renewal() {
    let (_root, store, args, mut session, publisher) = open_session();
    claim(&mut session, &publisher);
    let active = activated(&publisher);
    session
        .retain_child("fresh-child", active.api_token_slot_id.as_deref().unwrap())
        .unwrap();
    let mut wrong = active.clone();
    wrong.api_token_slot_id = Some(Uuid::new_v4().to_string());
    assert!(
        session
            .complete(&wrong, &[], &reads(true), &reads(true))
            .is_err()
    );
    session
        .complete(&active, &[], &reads(true), &reads(true))
        .unwrap();
    drop(session);
    let ordinary = Session::open(&store, &args).unwrap();
    assert!(ordinary.has_unknown_predecessor());
    assert!(!ordinary.is_unmanaged_recovery());
    let mut result = ResultEnvelopeV2::success(
        "keys renew-analytics-profile",
        json!({"state":"healthy_not_due"}),
    );
    ordinary.annotate(&mut result);
    assert_eq!(
        result.result["unmanaged_predecessor"]["cleanup_verified"],
        false
    );
    assert_eq!(
        result.result["unmanaged_predecessor"]["automatic_revoke_permitted"],
        false
    );
}

#[test]
#[cfg(unix)]
fn failed_profile_switch_preserves_installed_projection_and_replay_fence() {
    use std::os::unix::fs::PermissionsExt as _;
    let (_root, store, args, mut session, publisher) = open_session();
    claim(&mut session, &publisher);
    let mut profiles = super::super::ProfilesConfig::default();
    profiles
        .profiles
        .insert(args.profile.clone(), publisher.clone());
    profiles.save(&store).unwrap();
    let parent = store
        .paths()
        .profiles_file()
        .parent()
        .unwrap()
        .to_path_buf();
    let prior_mode = fs::metadata(&parent).unwrap().permissions();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o500)).unwrap();
    profiles
        .profiles
        .insert(args.profile.clone(), activated(&publisher));
    let failed = profiles.save(&store);
    fs::set_permissions(&parent, prior_mode).unwrap();
    assert!(
        failed.is_err(),
        "write refusal must not report a successful switch"
    );
    let installed = super::super::ProfilesConfig::load(&store).unwrap();
    assert_eq!(installed.profiles[&args.profile], publisher);
    drop(session);
    assert!(
        Session::open(&store, &args).is_err(),
        "failed switch must not permit another mint"
    );
}

#[test]
fn request_reader_refuses_directories_and_oversized_payloads() {
    let root = tempfile::tempdir().unwrap();
    assert!(read_request(root.path()).is_err());
    let oversized = root.path().join("request.json");
    fs::write(&oversized, vec![b' '; 65_537]).unwrap();
    assert!(read_request(&oversized).is_err());
}

#[test]
fn unrelated_two_group_policy_cannot_bootstrap_the_analytics_publisher() {
    let (mut args, mut request, publisher, minter, mut authority) = fixture();
    let unrelated = vec!["1".repeat(32), "2".repeat(32)];
    args.permissions = unrelated.clone();
    request.permission_group_ids = unrelated.clone();
    authority.permission_group_ids = unrelated;
    assert!(
        request
            .validate(&args, &publisher, &minter, &authority)
            .is_err()
    );
}

#[test]
#[cfg(unix)]
fn request_reader_refuses_a_symlink_without_reading_the_target() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let (_, request, _, _, _) = fixture();
    let target = root.path().join("target.json");
    fs::write(&target, serde_json::to_vec(&request).unwrap()).unwrap();
    let link = root.path().join("link.json");
    symlink(&target, &link).unwrap();
    assert!(read_request(&link).is_err());
    read_request(&target).unwrap();
}
