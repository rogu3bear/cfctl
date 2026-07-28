#![allow(clippy::expect_used)]

use cfctl_core::{
    DesiredResourceV1, EventCursorV1, EventEnvelopeV1, EventSignatureStatusV1,
    EventUpstreamIdentityV1, EvidenceClass, EvidenceV1, OwnershipRecordV1,
    ReconciliationJobStatusV1, RegistryObservationStatusV1, RegistryObservationV1, ResourceRefV1,
    ScopeKindV1, ScopeRefV1,
};
use cfctl_registry::{EventIngestDispositionV1, InventoryProviderV1, Registry, RegistryError};
use chrono::{Duration, Utc};
use serde_json::json;

fn account() -> ScopeRefV1 {
    ScopeRefV1::new(ScopeKindV1::Account, "account-a", None)
}

fn resource() -> ResourceRefV1 {
    ResourceRefV1::new(account(), "worker", "worker-a")
}

#[test]
fn registry_is_wal_backed_rebuildable_and_integrity_checked() {
    let root = tempfile::tempdir().expect("registry root");
    let mut registry = Registry::open(root.path()).expect("registry opens");
    registry.adopt_scope(&account()).expect("scope stores");
    registry
        .upsert_resource(&resource(), "source_config")
        .expect("resource stores");

    let status = registry.status().expect("status");
    assert_eq!(status.database_schema_version, 3);
    assert_eq!(status.journal_mode, "wal");
    assert_eq!(status.integrity, "ok");

    let backup = registry.rebuild_projection().expect("projection rebuilds");
    assert!(backup.is_file());
    assert!(registry.list_resources(None).expect("resources").is_empty());
    assert_eq!(registry.integrity_check().expect("integrity"), "ok");
}

#[test]
fn observations_are_redacted_versioned_and_do_not_replace_desired_state() {
    let root = tempfile::tempdir().expect("registry root");
    let mut registry = Registry::open(root.path()).expect("registry opens");
    let observed_at = Utc::now();
    let observation = RegistryObservationV1::new(
        resource(),
        observed_at,
        observed_at + Duration::minutes(5),
        "sha256:catalog",
        "workers-list",
        json!({"name":"worker-a","api_token":"must-not-persist"}),
        RegistryObservationStatusV1::Current,
        EvidenceV1::new(
            EvidenceClass::LiveRead,
            "sha256:evidence",
            "/evidence/read.json",
        ),
    )
    .expect("observation");
    registry
        .record_observation(&observation)
        .expect("observation stores");

    let history = registry
        .observation_history(&resource().key())
        .expect("history");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].schema_version, 1);
    assert_ne!(history[0].state["api_token"], "must-not-persist");
    assert!(
        registry
            .list_desired_resources()
            .expect("desired")
            .is_empty()
    );
}

#[test]
fn duplicate_owners_fail_closed_and_resource_locks_are_exclusive() {
    let root = tempfile::tempdir().expect("registry root");
    let mut registry = Registry::open(root.path()).expect("registry opens");
    registry
        .upsert_resource(&resource(), "desired_state")
        .expect("resource stores");
    let ownership = OwnershipRecordV1 {
        schema_version: 1,
        resource: resource(),
        owner: "team-a".to_owned(),
        repository: "/repo-a".to_owned(),
        deploy_lane: "wrangler".to_owned(),
        verifier: "workers-get".to_owned(),
        allowed_change_path: "repo".to_owned(),
    };
    registry
        .upsert_ownership(&ownership)
        .expect("first owner stores");
    let desired = DesiredResourceV1::new(
        resource(),
        json!({"name":"worker-a"}),
        "team-b",
        "wrangler",
        "workers-get",
        "repo",
        "/repo-b/wrangler.toml",
    )
    .expect("desired contract");
    assert!(matches!(
        registry.upsert_desired_resource(&desired),
        Err(RegistryError::DuplicateOwner { .. })
    ));

    let key = resource().key();
    registry
        .acquire_resource_lock(&key, "operation-a")
        .expect("first lock");
    assert!(matches!(
        registry.acquire_resource_lock(&key, "operation-b"),
        Err(RegistryError::ResourceLocked(_))
    ));
    assert!(
        registry
            .release_resource_lock(&key, "operation-a")
            .expect("release")
    );
}

#[test]
fn coverage_never_claims_complete_when_a_provider_is_blocked() {
    let root = tempfile::tempdir().expect("registry root");
    let registry = Registry::open(root.path()).expect("registry opens");
    registry
        .upsert_provider(&InventoryProviderV1 {
            schema_version: 1,
            resource_kind: "worker".to_owned(),
            scope_kind: "account".to_owned(),
            list_capability_id: "workers-list".to_owned(),
            detail_capability_id: Some("workers-get".to_owned()),
            pagination: "cursor".to_owned(),
            normalization_rule: "result[].id -> worker id".to_owned(),
            freshness_seconds: 300,
            permissions: vec!["Workers Scripts Read".to_owned()],
            status: "blocked".to_owned(),
            blocker: Some("profile lacks permission".to_owned()),
        })
        .expect("provider stores");
    let coverage = registry.coverage().expect("coverage");
    assert!(coverage.partial);
    assert_eq!(coverage.blocked_provider_count, 1);
    assert_eq!(coverage.blockers, vec!["profile lacks permission"]);
}

fn event(
    dedupe_key: &str,
    schema_version: u64,
    occurred_at: chrono::DateTime<Utc>,
) -> EventEnvelopeV1 {
    EventEnvelopeV1::new(
        EventUpstreamIdentityV1 {
            provider: "cloudflare".to_owned(),
            source: "access".to_owned(),
            event_type: "cf.access.application.created".to_owned(),
            event_id: dedupe_key.to_owned(),
            queue_id: Some("queue-a".to_owned()),
            subscription_id: Some("subscription-a".to_owned()),
        },
        schema_version,
        occurred_at,
        Utc::now(),
        Some(account()),
        dedupe_key,
        EventSignatureStatusV1::ProviderOriginated,
        Some("authority-a".to_owned()),
        Some(format!("cursor-{dedupe_key}")),
        vec![resource()],
        json!({"id":"worker-a","api_token":"must-not-persist"}),
        EvidenceV1::new(
            EvidenceClass::EventReceipt,
            &format!("sha256:{dedupe_key}"),
            &format!("/evidence/{dedupe_key}.json"),
        ),
    )
    .expect("event")
}

#[test]
fn event_ingest_is_deduplicated_reorder_safe_and_never_updates_observations() {
    let root = tempfile::tempdir().expect("registry root");
    let mut registry = Registry::open(root.path()).expect("registry opens");
    let now = Utc::now();
    let later = event("later", 1, now + Duration::minutes(1));
    let earlier = event("earlier", 1, now);

    let first = registry.ingest_event(&later).expect("later event commits");
    assert_eq!(first.disposition, EventIngestDispositionV1::Recorded);
    assert!(first.acknowledgement_permitted);
    assert_eq!(first.reconciliation_jobs.len(), 1);
    assert_eq!(
        first.reconciliation_jobs[0].status,
        ReconciliationJobStatusV1::Queued
    );
    registry
        .ingest_event(&earlier)
        .expect("earlier event commits");
    let duplicate = registry
        .ingest_event(&later)
        .expect("redelivery deduplicates");
    assert_eq!(duplicate.disposition, EventIngestDispositionV1::Duplicate);
    assert_eq!(registry.event_status().expect("status").event_count, 2);
    assert_eq!(registry.reconciliation_jobs().expect("jobs").len(), 2);
    assert!(
        registry
            .observation_history(&resource().key())
            .expect("observations")
            .is_empty()
    );
}

#[test]
fn unknown_event_schemas_are_retained_but_block_reconciliation() {
    let root = tempfile::tempdir().expect("registry root");
    let mut registry = Registry::open(root.path()).expect("registry opens");
    let result = registry
        .ingest_event(&event("future-schema", 99, Utc::now()))
        .expect("unknown schema is retained");
    assert!(result.acknowledgement_permitted);
    assert_eq!(
        result.reconciliation_jobs[0].status,
        ReconciliationJobStatusV1::BlockedUnknownSchema
    );
    let status = registry.event_status().expect("status");
    assert_eq!(status.event_count, 1);
    assert_eq!(status.blocked_job_count, 1);
}

#[test]
fn event_batch_collision_rolls_back_every_receipt_and_job() {
    let root = tempfile::tempdir().expect("registry root");
    let mut registry = Registry::open(root.path()).expect("registry opens");
    let first = event("batch-collision", 1, Utc::now());
    let collision = EventEnvelopeV1::new(
        first.upstream.clone(),
        first.upstream_schema_version,
        first.occurred_at,
        first.received_at,
        first.scope.clone(),
        first.dedupe_key.clone(),
        first.signature_status,
        first.operation_id.clone(),
        first.cursor.clone(),
        first.resource_refs.clone(),
        json!({"id":"different"}),
        first.evidence.clone(),
    )
    .expect("collision fixture");
    assert!(matches!(
        registry.ingest_event_batch(&[first, collision]),
        Err(RegistryError::EventDedupeCollision { .. })
    ));
    assert_eq!(registry.event_status().expect("status").event_count, 0);
    assert!(registry.reconciliation_jobs().expect("jobs").is_empty());
}

#[test]
fn projection_rebuild_preserves_the_durable_event_ledger_and_cursors() {
    let root = tempfile::tempdir().expect("registry root");
    let mut registry = Registry::open(root.path()).expect("registry opens");
    registry
        .ingest_event(&event("durable-event", 1, Utc::now()))
        .expect("event commits");
    let cursor = EventCursorV1 {
        schema_version: 1,
        source_key: "audit-v2:account-a".to_owned(),
        cursor: "cursor-a".to_owned(),
        overlap_seconds: 120,
        updated_at: Utc::now(),
    };
    registry.upsert_cursor(&cursor).expect("cursor stores");

    registry.rebuild_projection().expect("projection rebuilds");

    let status = registry.event_status().expect("event ledger status");
    assert_eq!(status.event_count, 1);
    assert_eq!(status.reconciliation_job_count, 1);
    assert_eq!(status.cursor_count, 1);
    assert_eq!(
        registry.cursor(&cursor.source_key).expect("cursor loads"),
        Some(cursor)
    );
}

#[test]
fn audit_cursor_persists_its_overlap_window() {
    let root = tempfile::tempdir().expect("registry root");
    let registry = Registry::open(root.path()).expect("registry opens");
    let cursor = EventCursorV1 {
        schema_version: 1,
        source_key: "audit-v2:account-a".to_owned(),
        cursor: "cursor-a".to_owned(),
        overlap_seconds: 120,
        updated_at: Utc::now(),
    };
    registry.upsert_cursor(&cursor).expect("cursor stores");
    assert_eq!(
        registry.cursor(&cursor.source_key).expect("cursor loads"),
        Some(cursor)
    );
}
