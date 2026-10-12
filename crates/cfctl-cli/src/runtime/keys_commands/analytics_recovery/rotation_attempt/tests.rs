#![allow(clippy::expect_used, clippy::unwrap_used)]
use super::super::tests::{activated, fixture};
use super::super::{Phase, Record, Session};
use super::*;
use cfctl_core::{
    CapabilityV1, PlanPinsV2, PlanV1, PlanV2, ResultEnvelopeV2, TransactionStageV1, hash_value,
};
use cfctl_storage::RuntimePaths;
use serde_json::json;
use uuid::Uuid;

struct Fixture {
    _root: tempfile::TempDir,
    store: StateStore,
    args: KeyRenewAnalyticsProfileArgs,
    session: Session,
    prior: ProfileMetadata,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let store = StateStore::open(RuntimePaths::from_root(
            &root.path().canonicalize().unwrap(),
        ))
        .unwrap();
        let (args, _, publisher, _, _) = fixture();
        let prior = activated(&publisher);
        let mut profiles = super::super::super::ProfilesConfig::default();
        profiles
            .profiles
            .insert(args.profile.clone(), prior.clone());
        profiles.save(&store).unwrap();
        let mut session = Session::open(&store, &args).unwrap();
        session.ordinary = Some(
            RotationAttempt::claim(
                &session.directory,
                None,
                &args,
                &prior,
                &Uuid::new_v4().to_string(),
            )
            .unwrap(),
        );
        Self {
            _root: root,
            store,
            args,
            session,
            prior,
        }
    }

    fn activate(&mut self) -> ProfileMetadata {
        let mut active = activated(&self.prior);
        active
            .managed_api_token
            .as_mut()
            .unwrap()
            .standing_authority_id = self.args.under_policy.clone();
        active.managed_api_token.as_mut().unwrap().token_id = "second-child".to_owned();
        self.session
            .retain_child("second-child", active.api_token_slot_id.as_deref().unwrap())
            .unwrap();
        self.session.retain_activation(&active).unwrap();
        self.save(&active);
        active
    }

    fn save(&self, profile: &ProfileMetadata) {
        let mut profiles = super::super::super::ProfilesConfig::load(&self.store).unwrap();
        profiles
            .profiles
            .insert(profile.id.clone(), profile.clone());
        profiles.save(&self.store).unwrap();
    }

    fn revoke(&self, token: &str, verified: bool) -> String {
        // Journal fixtures only; no provider proof is claimed by these tests.
        let mut plan = PlanV1::draft(
            &self.args.minter_profile,
            &self.args.account,
            "catalog-fixture",
            CapabilityV1::new(
                "account-api-tokens-delete-token",
                "Revoke",
                "DELETE",
                "/accounts/{account_id}/tokens/{token_id}",
            ),
            json!({}),
        )
        .unwrap();
        plan.input = json!({"selectors":{"token_id":token}});
        if verified {
            plan.status = PlanStatus::Verified;
        }
        plan.refresh_hash().unwrap();
        if verified {
            plan.record_transaction_stage(TransactionStageV1::Closed)
                .unwrap();
        }
        let operation = plan.operation_id.clone();
        let pins = PlanPinsV2 {
            build_identity_hash: "fixture-build".to_owned(),
            catalog_hash: plan.catalog_hash.clone(),
            credential_generation_id: Uuid::new_v4().to_string(),
            admission_policy_hash: "fixture-policy".to_owned(),
            authority_hash: None,
            workspace_graph_hash: "fixture-workspace".to_owned(),
            resource_observation_hashes: std::collections::BTreeMap::default(),
            cost_budget: None,
        };
        self.store
            .save_plan_v2(&PlanV2::new(plan, pins).unwrap())
            .unwrap();
        operation
    }
}

#[test]
fn interrupted_ordinary_mint_blocks_the_next_hourly_mint() {
    let f = Fixture::new();
    assert!(
        RotationAttempt::claim(
            &f.session.directory,
            f.session.ordinary.as_ref(),
            &f.args,
            &f.prior,
            &Uuid::new_v4().to_string()
        )
        .is_err()
    );
    drop(f.session);
    assert!(Session::open(&f.store, &f.args).is_err());
}

#[test]
fn cutover_without_durable_old_revoke_metadata_cannot_restart_rotation() {
    let mut f = Fixture::new();
    f.activate();
    drop(f.session);
    assert!(Session::open(&f.store, &f.args).is_err());
}

#[test]
fn pending_overlap_allows_only_exact_old_child_reconciliation() {
    let mut f = Fixture::new();
    let mut active = f.activate();
    let managed = active.managed_api_token.as_mut().unwrap();
    managed.pending_revoke_token_id =
        Some(f.prior.managed_api_token.as_ref().unwrap().token_id.clone());
    managed.pending_revoke_slot_id = f.prior.api_token_slot_id.clone();
    f.save(&active);
    drop(f.session);
    let session = Session::open(&f.store, &f.args).unwrap();
    assert!(
        RotationAttempt::claim(
            &session.directory,
            session.ordinary.as_ref(),
            &f.args,
            &active,
            &Uuid::new_v4().to_string()
        )
        .is_err()
    );
    drop(session);
    for drift in [
        "generation",
        "account",
        "old_token",
        "old_slot",
        "active_token",
    ] {
        let mut changed = active.clone();
        match drift {
            "generation" => changed.credential_generation_id = Some(Uuid::new_v4().to_string()),
            "account" => changed.account_id = Some("d".repeat(32)),
            "old_token" => {
                changed
                    .managed_api_token
                    .as_mut()
                    .unwrap()
                    .pending_revoke_token_id = Some("wrong".to_owned());
            }
            "old_slot" => {
                changed
                    .managed_api_token
                    .as_mut()
                    .unwrap()
                    .pending_revoke_slot_id = None;
            }
            _ => changed.managed_api_token.as_mut().unwrap().token_id = "wrong".to_owned(),
        }
        let mut profiles = super::super::super::ProfilesConfig::load(&f.store).unwrap();
        profiles.profiles.insert(f.args.profile.clone(), changed);
        profiles.save(&f.store).unwrap();
        assert!(Session::open(&f.store, &f.args).is_err(), "{drift}");
    }
}

#[test]
fn unverified_or_wrong_child_cleanup_does_not_clear_the_fence() {
    let mut f = Fixture::new();
    let active = f.activate();
    f.save(&f.prior);
    let wrong = f.revoke("unrelated", true);
    let pending = f.revoke("second-child", false);
    for operation in [wrong, pending] {
        assert!(
            f.session
                .close_ordinary(&f.store, &operation, &f.prior, true)
                .is_err()
        );
    }
    let exact = f.revoke("second-child", true);
    f.save(&active);
    assert!(
        f.session
            .close_ordinary(&f.store, &exact, &f.prior, true)
            .is_err(),
        "verified cleanup cannot overwrite or ignore a different installed profile"
    );
    f.save(&f.prior);
    assert!(
        f.session
            .close_ordinary(&f.store, &exact, &active, true)
            .is_err()
    );
    drop(f.session);
    assert!(Session::open(&f.store, &f.args).is_err());
}

#[test]
fn verified_fresh_child_cleanup_and_exact_prior_readback_close_attempt() {
    let mut f = Fixture::new();
    f.activate();
    f.save(&f.prior);
    let exact = f.revoke("second-child", true);
    f.session
        .close_ordinary(&f.store, &exact, &f.prior, true)
        .unwrap();
    drop(f.session);
    Session::open(&f.store, &f.args).unwrap();
}

#[test]
fn verified_old_child_revoke_and_exact_cutover_close_attempt() {
    let mut f = Fixture::new();
    let active = f.activate();
    let old = f.prior.managed_api_token.as_ref().unwrap().token_id.clone();
    let exact = f.revoke(&old, true);
    f.session
        .close_ordinary(&f.store, &exact, &active, false)
        .unwrap();
    drop(f.session);
    Session::open(&f.store, &f.args).unwrap();
}

#[test]
fn ordinary_rotation_preserves_the_unknown_bootstrap_predecessor_obligation() {
    let mut f = Fixture::new();
    let (_, request, publisher, _, _) = fixture();
    let record = Record {
        schema_version: 1,
        request_sha256: hash_value(&serde_json::to_value(&request).unwrap()).unwrap(),
        request,
        prior_profile: publisher,
        mint_operation_id: Uuid::new_v4().to_string(),
        phase: Phase::ActiveUnknownOld,
        new_token_id: Some("fresh-child".to_owned()),
        new_slot_id: f.prior.api_token_slot_id.clone(),
        active_profile: Some(f.prior.clone()),
        verification_evidence: Vec::new(),
    };
    f.session
        .directory
        .write(
            "unmanaged-recovery.json",
            &serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
    let active = f.activate();
    let old = f.prior.managed_api_token.as_ref().unwrap().token_id.clone();
    let exact = f.revoke(&old, true);
    f.session
        .close_ordinary(&f.store, &exact, &active, false)
        .unwrap();
    drop(f.session);
    let session = Session::open(&f.store, &f.args).unwrap();
    assert!(session.has_unknown_predecessor());
    let mut envelope =
        ResultEnvelopeV2::success("keys renew-analytics-profile", json!({"state":"rotated"}));
    session.annotate(&mut envelope);
    assert_eq!(
        envelope.result["unmanaged_predecessor"]["cleanup_verified"],
        false
    );
    assert_eq!(
        envelope.result["unmanaged_predecessor"]["automatic_revoke_permitted"],
        false
    );
}
