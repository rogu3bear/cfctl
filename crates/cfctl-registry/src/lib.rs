//! Rebuildable `SQLite` projection for Cloudflare scopes, resources, desired
//! state, ownership, coverage, events, policy metadata, and operation maturity.

use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use cfctl_core::{
    DesiredResourceV1, EventCursorV1, EventEnvelopeV1, EventSignatureStatusV1, OwnershipRecordV1,
    ReconciliationJobStatusV1, ReconciliationJobV1, RegistryCoverageV1,
    RegistryObservationStatusV1, RegistryObservationV1, ResourceRefV1, ScopeRefV1,
};
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension as _, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tempfile::NamedTempFile;
use thiserror::Error;
use uuid::Uuid;

const REGISTRY_SCHEMA_VERSION: i64 = 3;

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("registry I/O failed for {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("registry SQLite operation failed: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("registry JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error(
        "resource `{resource}` already has owner `{existing}`; refusing duplicate owner `{requested}`"
    )]
    DuplicateOwner {
        resource: String,
        existing: String,
        requested: String,
    },
    #[error("resource writer lock for `{0}` is already held")]
    ResourceLocked(String),
    #[error("registry integrity check failed: {0}")]
    Integrity(String),
    #[error("registry count was unexpectedly negative: {0}")]
    InvalidCount(i64),
    #[error("event dedupe key `{dedupe_key}` refers to different upstream content")]
    EventDedupeCollision { dedupe_key: String },
    #[error(transparent)]
    Core(#[from] cfctl_core::CoreError),
}

pub type Result<T> = std::result::Result<T, RegistryError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationIndexRecordV1 {
    pub schema_version: u8,
    pub capability_id: String,
    pub product: String,
    pub method: String,
    pub path: String,
    pub adapter_status: String,
    pub maturity: String,
    pub blocker: Option<String>,
    pub catalog_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryProviderV1 {
    pub schema_version: u8,
    pub resource_kind: String,
    pub scope_kind: String,
    pub list_capability_id: String,
    pub detail_capability_id: Option<String>,
    pub pagination: String,
    pub normalization_rule: String,
    pub freshness_seconds: u64,
    pub permissions: Vec<String>,
    pub status: String,
    pub blocker: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnindexableEvidenceV1 {
    pub evidence_key: String,
    pub reason: String,
    pub recorded_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryStatusV1 {
    pub schema_version: u8,
    pub database_path: PathBuf,
    pub database_schema_version: i64,
    pub journal_mode: String,
    pub integrity: String,
    pub last_sync_at: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventIngestDispositionV1 {
    Recorded,
    Duplicate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventIngestResultV1 {
    pub schema_version: u8,
    pub dedupe_key: String,
    pub disposition: EventIngestDispositionV1,
    pub reconciliation_jobs: Vec<ReconciliationJobV1>,
    pub acknowledgement_permitted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventLedgerStatusV1 {
    pub schema_version: u8,
    pub event_count: u64,
    pub reconciliation_job_count: u64,
    pub queued_job_count: u64,
    pub blocked_job_count: u64,
    pub cursor_count: u64,
    pub latest_received_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegistryExportV1 {
    pub schema_version: u8,
    pub exported_at: chrono::DateTime<Utc>,
    pub scopes: Vec<ScopeRefV1>,
    pub resources: Vec<ResourceRefV1>,
    pub desired_resources: Vec<DesiredResourceV1>,
    pub ownership: Vec<OwnershipRecordV1>,
    pub coverage: RegistryCoverageV1,
}

pub struct Registry {
    connection: Connection,
    database_path: PathBuf,
}

impl Registry {
    pub fn open(data_dir: &Path) -> Result<Self> {
        let registry_dir = data_dir.join("registry");
        fs::create_dir_all(&registry_dir).map_err(|source| io_error(&registry_dir, source))?;
        let database_path = registry_dir.join("registry-v1.sqlite3");
        let connection = Connection::open(&database_path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if (1..REGISTRY_SCHEMA_VERSION).contains(&version) {
            backup_connection(&connection, &registry_dir)?;
        }
        migrate(&connection)?;
        let registry = Self {
            connection,
            database_path,
        };
        registry.integrity_check()?;
        Ok(registry)
    }

    #[must_use]
    pub fn database_path(&self) -> &Path {
        &self.database_path
    }

    pub fn status(&self) -> Result<RegistryStatusV1> {
        let journal_mode = self
            .connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
        let database_schema_version =
            self.connection
                .query_row("PRAGMA user_version", [], |row| row.get(0))?;
        Ok(RegistryStatusV1 {
            schema_version: 1,
            database_path: self.database_path.clone(),
            database_schema_version,
            journal_mode,
            integrity: self.integrity_check()?,
            last_sync_at: self.metadata("last_sync_at")?,
        })
    }

    pub fn integrity_check(&self) -> Result<String> {
        let result: String = self
            .connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        if result != "ok" {
            return Err(RegistryError::Integrity(result));
        }
        Ok(result)
    }

    pub fn adopt_scope(&mut self, scope: &ScopeRefV1) -> Result<()> {
        let transaction = self.connection.transaction()?;
        upsert_scope(&transaction, scope)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn remove_scope(&self, scope: &ScopeRefV1) -> Result<bool> {
        Ok(self.connection.execute(
            "DELETE FROM scopes WHERE scope_key = ?1",
            params![scope.key()],
        )? > 0)
    }

    pub fn list_scopes(&self) -> Result<Vec<ScopeRefV1>> {
        query_json_rows(
            &self.connection,
            "SELECT scope_json FROM scopes ORDER BY scope_key",
            [],
        )
    }

    pub fn upsert_resource(&mut self, resource: &ResourceRefV1, origin: &str) -> Result<()> {
        let transaction = self.connection.transaction()?;
        upsert_scope(&transaction, &resource.scope)?;
        transaction.execute(
            "INSERT INTO resources(resource_key, scope_key, kind, resource_id, origin, resource_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(resource_key) DO UPDATE SET origin=excluded.origin, resource_json=excluded.resource_json",
            params![
                resource.key(),
                resource.scope.key(),
                resource.kind,
                resource.id,
                origin,
                encode(resource)?,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn list_resources(&self, kind: Option<&str>) -> Result<Vec<ResourceRefV1>> {
        if let Some(kind) = kind {
            query_json_rows(
                &self.connection,
                "SELECT resource_json FROM resources WHERE kind = ?1 ORDER BY resource_key",
                params![kind],
            )
        } else {
            query_json_rows(
                &self.connection,
                "SELECT resource_json FROM resources ORDER BY resource_key",
                [],
            )
        }
    }

    pub fn get_resource(&self, resource_key: &str) -> Result<Option<ResourceRefV1>> {
        query_optional_json(
            &self.connection,
            "SELECT resource_json FROM resources WHERE resource_key = ?1",
            params![resource_key],
        )
    }

    pub fn record_observation(&mut self, observation: &RegistryObservationV1) -> Result<()> {
        let transaction = self.connection.transaction()?;
        upsert_scope(&transaction, &observation.resource.scope)?;
        transaction.execute(
            "INSERT INTO resources(resource_key, scope_key, kind, resource_id, origin, resource_json)
             VALUES (?1, ?2, ?3, ?4, 'live_read', ?5)
             ON CONFLICT(resource_key) DO UPDATE SET resource_json=excluded.resource_json",
            params![
                observation.resource.key(),
                observation.resource.scope.key(),
                observation.resource.kind,
                observation.resource.id,
                encode(&observation.resource)?,
            ],
        )?;
        transaction.execute(
            "INSERT OR IGNORE INTO observations(
                resource_key, observed_at, fresh_until, state_hash, status, observation_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                observation.resource.key(),
                observation.observed_at.to_rfc3339(),
                observation.fresh_until.to_rfc3339(),
                observation.state_hash,
                observation_status(observation.status),
                encode(observation)?,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn observation_history(&self, resource_key: &str) -> Result<Vec<RegistryObservationV1>> {
        query_json_rows(
            &self.connection,
            "SELECT observation_json FROM observations WHERE resource_key = ?1 ORDER BY observed_at DESC, observation_id DESC",
            params![resource_key],
        )
    }

    /// Atomically retains an event and every reconciliation request derived
    /// from its normalized resource references. Callers may acknowledge the
    /// upstream message only after this method returns successfully.
    pub fn ingest_event(&mut self, event: &EventEnvelopeV1) -> Result<EventIngestResultV1> {
        self.ingest_event_batch(std::slice::from_ref(event))?
            .into_iter()
            .next()
            .ok_or_else(|| RegistryError::Integrity("event batch result was empty".to_owned()))
    }

    /// Atomically commits an entire pulled Queue batch. Exact duplicates are
    /// idempotent; any collision or job-insert failure rolls the whole batch
    /// back, so the caller never acknowledges a partially committed batch.
    pub fn ingest_event_batch(
        &mut self,
        events: &[EventEnvelopeV1],
    ) -> Result<Vec<EventIngestResultV1>> {
        if events.is_empty() {
            return Err(RegistryError::Integrity(
                "event batch must contain at least one receipt".to_owned(),
            ));
        }
        for event in events {
            event.validate()?;
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let results = events
            .iter()
            .map(|event| ingest_event_in_transaction(&transaction, event))
            .collect::<Result<Vec<_>>>()?;
        transaction.commit()?;
        Ok(results)
    }

    pub fn event_history(&self, limit: u32) -> Result<Vec<EventEnvelopeV1>> {
        let limit = i64::from(limit.clamp(1, 1_000));
        query_json_rows(
            &self.connection,
            "SELECT event_json FROM events ORDER BY received_at DESC, dedupe_key DESC LIMIT ?1",
            params![limit],
        )
    }

    pub fn enqueue_reconciliation(
        &mut self,
        resource: ResourceRefV1,
    ) -> Result<ReconciliationJobV1> {
        let job = ReconciliationJobV1::queued(resource, None);
        let transaction = self.connection.transaction()?;
        insert_reconciliation_job(&transaction, &job)?;
        transaction.commit()?;
        Ok(job)
    }

    pub fn reconciliation_jobs(&self) -> Result<Vec<ReconciliationJobV1>> {
        query_json_rows(
            &self.connection,
            "SELECT job_json FROM reconciliation_jobs ORDER BY job_id",
            [],
        )
    }

    pub fn upsert_cursor(&self, cursor: &EventCursorV1) -> Result<()> {
        if cursor.schema_version != 1
            || cursor.source_key.trim().is_empty()
            || cursor.cursor.trim().is_empty()
        {
            return Err(RegistryError::Integrity(
                "event cursor requires schema version 1, source key, and cursor".to_owned(),
            ));
        }
        self.connection.execute(
            "INSERT INTO cursors(source_key, cursor, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(source_key) DO UPDATE SET cursor=excluded.cursor, updated_at=excluded.updated_at",
            params![cursor.source_key, encode(cursor)?, cursor.updated_at.to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn cursor(&self, source_key: &str) -> Result<Option<EventCursorV1>> {
        query_optional_json(
            &self.connection,
            "SELECT cursor FROM cursors WHERE source_key = ?1",
            params![source_key],
        )
    }

    pub fn event_status(&self) -> Result<EventLedgerStatusV1> {
        Ok(EventLedgerStatusV1 {
            schema_version: 1,
            event_count: count(&self.connection, "SELECT COUNT(*) FROM events")?,
            reconciliation_job_count: count(
                &self.connection,
                "SELECT COUNT(*) FROM reconciliation_jobs",
            )?,
            queued_job_count: count(
                &self.connection,
                "SELECT COUNT(*) FROM reconciliation_jobs WHERE status = 'queued'",
            )?,
            blocked_job_count: count(
                &self.connection,
                "SELECT COUNT(*) FROM reconciliation_jobs WHERE status LIKE 'blocked_%'",
            )?,
            cursor_count: count(&self.connection, "SELECT COUNT(*) FROM cursors")?,
            latest_received_at: self.connection.query_row(
                "SELECT MAX(received_at) FROM events",
                [],
                |row| row.get(0),
            )?,
        })
    }

    pub fn upsert_desired_resource(&mut self, desired: &DesiredResourceV1) -> Result<()> {
        let transaction = self.connection.transaction()?;
        upsert_scope(&transaction, &desired.resource.scope)?;
        let key = desired.resource.key();
        let existing_owner: Option<String> = transaction
            .query_row(
                "SELECT owner FROM ownership WHERE resource_key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing_owner
            && existing != desired.owner
        {
            return Err(RegistryError::DuplicateOwner {
                resource: key,
                existing,
                requested: desired.owner.clone(),
            });
        }
        transaction.execute(
            "INSERT INTO resources(resource_key, scope_key, kind, resource_id, origin, resource_json)
             VALUES (?1, ?2, ?3, ?4, 'desired_state', ?5)
             ON CONFLICT(resource_key) DO UPDATE SET resource_json=excluded.resource_json",
            params![
                desired.resource.key(),
                desired.resource.scope.key(),
                desired.resource.kind,
                desired.resource.id,
                encode(&desired.resource)?,
            ],
        )?;
        transaction.execute(
            "INSERT INTO desired_resources(resource_key, manifest_hash, desired_json)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(resource_key) DO UPDATE SET manifest_hash=excluded.manifest_hash, desired_json=excluded.desired_json",
            params![desired.resource.key(), desired.manifest_hash, encode(desired)?],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn upsert_ownership(&self, ownership: &OwnershipRecordV1) -> Result<()> {
        let key = ownership.resource.key();
        let existing_owner: Option<String> = self
            .connection
            .query_row(
                "SELECT owner FROM ownership WHERE resource_key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing_owner
            && existing != ownership.owner
        {
            return Err(RegistryError::DuplicateOwner {
                resource: key,
                existing,
                requested: ownership.owner.clone(),
            });
        }
        self.connection.execute(
            "INSERT INTO ownership(resource_key, owner, ownership_json)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(resource_key) DO UPDATE SET owner=excluded.owner, ownership_json=excluded.ownership_json",
            params![ownership.resource.key(), ownership.owner, encode(ownership)?],
        )?;
        Ok(())
    }

    pub fn list_desired_resources(&self) -> Result<Vec<DesiredResourceV1>> {
        query_json_rows(
            &self.connection,
            "SELECT desired_json FROM desired_resources ORDER BY resource_key",
            [],
        )
    }

    pub fn list_ownership(&self) -> Result<Vec<OwnershipRecordV1>> {
        query_json_rows(
            &self.connection,
            "SELECT ownership_json FROM ownership ORDER BY resource_key",
            [],
        )
    }

    pub fn upsert_operation(&self, operation: &OperationIndexRecordV1) -> Result<()> {
        self.connection.execute(
            "INSERT INTO operation_index(capability_id, maturity, blocker, operation_json)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(capability_id) DO UPDATE SET maturity=excluded.maturity, blocker=excluded.blocker, operation_json=excluded.operation_json",
            params![
                operation.capability_id,
                operation.maturity,
                operation.blocker,
                encode(operation)?,
            ],
        )?;
        Ok(())
    }

    pub fn upsert_provider(&self, provider: &InventoryProviderV1) -> Result<()> {
        self.connection.execute(
            "INSERT INTO inventory_providers(resource_kind, status, blocker, provider_json)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(resource_kind) DO UPDATE SET status=excluded.status, blocker=excluded.blocker, provider_json=excluded.provider_json",
            params![
                provider.resource_kind,
                provider.status,
                provider.blocker,
                encode(provider)?,
            ],
        )?;
        Ok(())
    }

    pub fn record_unindexable_evidence(&self, evidence_key: &str, reason: &str) -> Result<()> {
        self.connection.execute(
            "INSERT INTO unindexable_evidence(evidence_key, reason, recorded_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(evidence_key) DO UPDATE SET reason=excluded.reason, recorded_at=excluded.recorded_at",
            params![evidence_key, reason, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn unindexable_evidence(&self) -> Result<Vec<UnindexableEvidenceV1>> {
        let mut statement = self.connection.prepare(
            "SELECT evidence_key, reason, recorded_at FROM unindexable_evidence ORDER BY evidence_key",
        )?;
        Ok(statement
            .query_map([], |row| {
                Ok(UnindexableEvidenceV1 {
                    evidence_key: row.get(0)?,
                    reason: row.get(1)?,
                    recorded_at: row.get(2)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn mark_sync_complete(&self) -> Result<()> {
        self.set_metadata("last_sync_at", &Utc::now().to_rfc3339())
    }

    pub fn coverage(&self) -> Result<RegistryCoverageV1> {
        let now = Utc::now().to_rfc3339();
        let provider_count = count(&self.connection, "SELECT COUNT(*) FROM inventory_providers")?;
        let blocked_provider_count = count(
            &self.connection,
            "SELECT COUNT(*) FROM inventory_providers WHERE status != 'available'",
        )?;
        let mut blockers = query_strings(
            &self.connection,
            "SELECT COALESCE(blocker, resource_kind || ' provider is not available')
             FROM inventory_providers WHERE status != 'available' ORDER BY resource_kind",
        )?;
        if provider_count == 0 {
            blockers.push("no live inventory providers are registered".to_owned());
        }
        Ok(RegistryCoverageV1 {
            schema_version: 1,
            as_of: Utc::now(),
            operation_count: count(&self.connection, "SELECT COUNT(*) FROM operation_index")?,
            scope_count: count(&self.connection, "SELECT COUNT(*) FROM scopes")?,
            resource_count: count(&self.connection, "SELECT COUNT(*) FROM resources")?,
            current_observation_count: count_with_param(
                &self.connection,
                "SELECT COUNT(*) FROM observations WHERE status = 'current' AND fresh_until >= ?1",
                &now,
            )?,
            stale_observation_count: count_with_param(
                &self.connection,
                "SELECT COUNT(*) FROM observations WHERE status != 'current' OR fresh_until < ?1",
                &now,
            )?,
            desired_resource_count: count(
                &self.connection,
                "SELECT COUNT(*) FROM desired_resources",
            )?,
            provider_count,
            blocked_provider_count,
            partial: provider_count == 0 || blocked_provider_count > 0,
            blockers,
        })
    }

    pub fn export(&self) -> Result<RegistryExportV1> {
        Ok(RegistryExportV1 {
            schema_version: 1,
            exported_at: Utc::now(),
            scopes: self.list_scopes()?,
            resources: self.list_resources(None)?,
            desired_resources: self.list_desired_resources()?,
            ownership: self.list_ownership()?,
            coverage: self.coverage()?,
        })
    }

    pub fn backup(&self) -> Result<PathBuf> {
        let registry_dir = self.database_path.parent().ok_or_else(|| {
            RegistryError::Integrity("registry database path has no parent".to_owned())
        })?;
        backup_connection(&self.connection, registry_dir)
    }

    pub fn rebuild_projection(&mut self) -> Result<PathBuf> {
        let backup = self.backup()?;
        let transaction = self.connection.transaction()?;
        transaction.execute_batch(
            "DELETE FROM observations;
             DELETE FROM resource_locks;
             DELETE FROM inventory_providers;
             DELETE FROM operation_index;
             DELETE FROM resources
               WHERE resource_key NOT IN (SELECT resource_key FROM desired_resources);",
        )?;
        transaction.execute("DELETE FROM metadata WHERE key = 'last_sync_at'", [])?;
        transaction.commit()?;
        self.integrity_check()?;
        Ok(backup)
    }

    pub fn acquire_resource_lock(&self, resource_key: &str, owner: &str) -> Result<()> {
        match self.connection.execute(
            "INSERT INTO resource_locks(resource_key, owner, acquired_at) VALUES (?1, ?2, ?3)",
            params![resource_key, owner, Utc::now().to_rfc3339()],
        ) {
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(error, _))
                if error.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Err(RegistryError::ResourceLocked(resource_key.to_owned()))
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn release_resource_lock(&self, resource_key: &str, owner: &str) -> Result<bool> {
        Ok(self.connection.execute(
            "DELETE FROM resource_locks WHERE resource_key = ?1 AND owner = ?2",
            params![resource_key, owner],
        )? > 0)
    }

    fn metadata(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .connection
            .query_row(
                "SELECT value FROM metadata WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?)
    }

    fn set_metadata(&self, key: &str, value: &str) -> Result<()> {
        self.connection.execute(
            "INSERT INTO metadata(key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, value],
        )?;
        Ok(())
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the versioned registry DDL stays together so each transactional migration is reviewable as one unit"
)]
fn migrate(connection: &Connection) -> Result<()> {
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == 0 {
        connection.execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE metadata(
               key TEXT PRIMARY KEY,
               value TEXT NOT NULL
             ) STRICT;
             CREATE TABLE scopes(
               scope_key TEXT PRIMARY KEY,
               kind TEXT NOT NULL,
               scope_id TEXT NOT NULL,
               parent_key TEXT REFERENCES scopes(scope_key) ON DELETE RESTRICT,
               scope_json TEXT NOT NULL
             ) STRICT;
             CREATE TABLE resources(
               resource_key TEXT PRIMARY KEY,
               scope_key TEXT NOT NULL REFERENCES scopes(scope_key) ON DELETE RESTRICT,
               kind TEXT NOT NULL,
               resource_id TEXT NOT NULL,
               origin TEXT NOT NULL,
               resource_json TEXT NOT NULL
             ) STRICT;
             CREATE TABLE observations(
               observation_id INTEGER PRIMARY KEY,
               resource_key TEXT NOT NULL REFERENCES resources(resource_key) ON DELETE RESTRICT,
               observed_at TEXT NOT NULL,
               fresh_until TEXT NOT NULL,
               state_hash TEXT NOT NULL,
               status TEXT NOT NULL,
               observation_json TEXT NOT NULL,
               UNIQUE(resource_key, state_hash, observed_at)
             ) STRICT;
             CREATE INDEX observations_resource_time
               ON observations(resource_key, observed_at DESC);
             CREATE TABLE desired_resources(
               resource_key TEXT PRIMARY KEY REFERENCES resources(resource_key) ON DELETE RESTRICT,
               manifest_hash TEXT NOT NULL,
               desired_json TEXT NOT NULL
             ) STRICT;
             CREATE TABLE ownership(
               resource_key TEXT PRIMARY KEY,
               owner TEXT NOT NULL,
               ownership_json TEXT NOT NULL
             ) STRICT;
             CREATE TABLE events(
               dedupe_key TEXT PRIMARY KEY,
               received_at TEXT NOT NULL,
               operation_id TEXT,
               authority_id TEXT,
               queue_id TEXT,
               subscription_id TEXT,
               event_json TEXT NOT NULL
             ) STRICT;
             CREATE TABLE cursors(
               source_key TEXT PRIMARY KEY,
               cursor TEXT NOT NULL,
               updated_at TEXT NOT NULL
             ) STRICT;
             CREATE TABLE reconciliation_jobs(
               job_id TEXT PRIMARY KEY,
               resource_key TEXT,
               status TEXT NOT NULL,
               job_json TEXT NOT NULL
             ) STRICT;
             CREATE TABLE admission_policy_bundles(
               bundle_id TEXT PRIMARY KEY,
               status TEXT NOT NULL,
               bundle_json TEXT NOT NULL
             ) STRICT;
             CREATE TABLE authorities(
               authority_id TEXT PRIMARY KEY,
               status TEXT NOT NULL,
               authority_json TEXT NOT NULL
             ) STRICT;
             CREATE TABLE operation_index(
               capability_id TEXT PRIMARY KEY,
               maturity TEXT NOT NULL,
               blocker TEXT,
               operation_json TEXT NOT NULL
             ) STRICT;
             CREATE TABLE inventory_providers(
               resource_kind TEXT PRIMARY KEY,
               status TEXT NOT NULL,
               blocker TEXT,
               provider_json TEXT NOT NULL
             ) STRICT;
             CREATE TABLE resource_locks(
               resource_key TEXT PRIMARY KEY,
               owner TEXT NOT NULL,
               acquired_at TEXT NOT NULL
             ) STRICT;
             CREATE TABLE unindexable_evidence(
               evidence_key TEXT PRIMARY KEY,
               reason TEXT NOT NULL,
               recorded_at TEXT NOT NULL
             ) STRICT;
             PRAGMA user_version = 3;
             COMMIT;",
        )?;
    } else if version == 1 {
        connection.execute_batch(
            "BEGIN IMMEDIATE;
             ALTER TABLE events ADD COLUMN authority_id TEXT;
             ALTER TABLE events ADD COLUMN queue_id TEXT;
             ALTER TABLE events ADD COLUMN subscription_id TEXT;
             ALTER TABLE events ADD COLUMN operation_id TEXT;
             PRAGMA user_version = 3;
             COMMIT;",
        )?;
    } else if version == 2 {
        connection.execute_batch(
            "BEGIN IMMEDIATE;
             ALTER TABLE events ADD COLUMN operation_id TEXT;
             PRAGMA user_version = 3;
             COMMIT;",
        )?;
    } else if version != REGISTRY_SCHEMA_VERSION {
        return Err(RegistryError::Integrity(format!(
            "unsupported registry schema version {version}; expected {REGISTRY_SCHEMA_VERSION}"
        )));
    }
    Ok(())
}

fn upsert_scope(transaction: &Transaction<'_>, scope: &ScopeRefV1) -> Result<()> {
    if let Some(parent) = &scope.parent {
        upsert_scope(transaction, parent)?;
    }
    transaction.execute(
        "INSERT INTO scopes(scope_key, kind, scope_id, parent_key, scope_json)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(scope_key) DO UPDATE SET scope_json=excluded.scope_json",
        params![
            scope.key(),
            scope.kind.as_str(),
            scope.id,
            scope.parent.as_ref().map(|parent| parent.key()),
            encode(scope)?,
        ],
    )?;
    Ok(())
}

fn observation_status(status: RegistryObservationStatusV1) -> &'static str {
    match status {
        RegistryObservationStatusV1::Current => "current",
        RegistryObservationStatusV1::Stale => "stale",
        RegistryObservationStatusV1::Partial => "partial",
        RegistryObservationStatusV1::PermissionDenied => "permission_denied",
        RegistryObservationStatusV1::Tombstone => "tombstone",
        RegistryObservationStatusV1::UnknownSchema => "unknown_schema",
    }
}

fn event_reconciliation_status(event: &EventEnvelopeV1) -> ReconciliationJobStatusV1 {
    if event.upstream_schema_version != 1 {
        ReconciliationJobStatusV1::BlockedUnknownSchema
    } else if matches!(
        event.signature_status,
        EventSignatureStatusV1::Invalid | EventSignatureStatusV1::Unknown
    ) {
        ReconciliationJobStatusV1::BlockedInvalidSignature
    } else {
        ReconciliationJobStatusV1::Queued
    }
}

fn reconciliation_status(status: ReconciliationJobStatusV1) -> &'static str {
    match status {
        ReconciliationJobStatusV1::Queued => "queued",
        ReconciliationJobStatusV1::Running => "running",
        ReconciliationJobStatusV1::Succeeded => "succeeded",
        ReconciliationJobStatusV1::Failed => "failed",
        ReconciliationJobStatusV1::BlockedUnknownSchema => "blocked_unknown_schema",
        ReconciliationJobStatusV1::BlockedInvalidSignature => "blocked_invalid_signature",
    }
}

fn insert_reconciliation_job(
    transaction: &Transaction<'_>,
    job: &ReconciliationJobV1,
) -> Result<()> {
    transaction.execute(
        "INSERT INTO reconciliation_jobs(job_id, resource_key, status, job_json)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            job.job_id,
            job.resource.key(),
            reconciliation_status(job.status),
            encode(job)?,
        ],
    )?;
    Ok(())
}

fn ingest_event_in_transaction(
    transaction: &Transaction<'_>,
    event: &EventEnvelopeV1,
) -> Result<EventIngestResultV1> {
    let existing: Option<EventEnvelopeV1> = query_optional_json(
        transaction,
        "SELECT event_json FROM events WHERE dedupe_key = ?1",
        params![event.dedupe_key],
    )?;
    if let Some(existing) = existing {
        if existing.upstream != event.upstream
            || existing.upstream_schema_version != event.upstream_schema_version
            || existing.payload_hash != event.payload_hash
        {
            return Err(RegistryError::EventDedupeCollision {
                dedupe_key: event.dedupe_key.clone(),
            });
        }
        return Ok(EventIngestResultV1 {
            schema_version: 1,
            dedupe_key: event.dedupe_key.clone(),
            disposition: EventIngestDispositionV1::Duplicate,
            reconciliation_jobs: event_jobs(transaction, &event.dedupe_key)?,
            acknowledgement_permitted: true,
        });
    }

    transaction.execute(
        "INSERT INTO events(
           dedupe_key, received_at, operation_id, authority_id, queue_id, subscription_id, event_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            event.dedupe_key,
            event.received_at.to_rfc3339(),
            event.operation_id,
            event.authority_id,
            event.upstream.queue_id,
            event.upstream.subscription_id,
            encode(event)?,
        ],
    )?;
    let mut jobs = Vec::with_capacity(event.resource_refs.len());
    for resource in &event.resource_refs {
        let mut job = ReconciliationJobV1::queued(resource.clone(), Some(event.dedupe_key.clone()));
        job.status = event_reconciliation_status(event);
        if job.status == ReconciliationJobStatusV1::BlockedUnknownSchema {
            job.error = Some(format!(
                "upstream schema version {} is not supported",
                event.upstream_schema_version
            ));
        } else if job.status == ReconciliationJobStatusV1::BlockedInvalidSignature {
            job.error = Some("event signature was invalid or could not be verified".to_owned());
        }
        insert_reconciliation_job(transaction, &job)?;
        jobs.push(job);
    }
    Ok(EventIngestResultV1 {
        schema_version: 1,
        dedupe_key: event.dedupe_key.clone(),
        disposition: EventIngestDispositionV1::Recorded,
        reconciliation_jobs: jobs,
        acknowledgement_permitted: true,
    })
}

fn event_jobs(transaction: &Transaction<'_>, dedupe_key: &str) -> Result<Vec<ReconciliationJobV1>> {
    let mut statement =
        transaction.prepare("SELECT job_json FROM reconciliation_jobs ORDER BY job_id")?;
    let encoded = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    encoded
        .iter()
        .map(|value| Ok(serde_json::from_str::<ReconciliationJobV1>(value)?))
        .filter(|result| {
            result.as_ref().map_or(true, |job| {
                job.event_dedupe_key.as_deref() == Some(dedupe_key)
            })
        })
        .collect()
}

fn encode<T: Serialize>(value: &T) -> Result<String> {
    Ok(serde_json::to_string(value)?)
}

fn query_json_rows<T, P>(connection: &Connection, sql: &str, params: P) -> Result<Vec<T>>
where
    T: DeserializeOwned,
    P: rusqlite::Params,
{
    let mut statement = connection.prepare(sql)?;
    let encoded = statement
        .query_map(params, |row| row.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    encoded
        .iter()
        .map(|value| Ok(serde_json::from_str(value)?))
        .collect()
}

fn query_optional_json<T, P>(connection: &Connection, sql: &str, params: P) -> Result<Option<T>>
where
    T: DeserializeOwned,
    P: rusqlite::Params,
{
    connection
        .query_row(sql, params, |row| row.get::<_, String>(0))
        .optional()?
        .map(|value| Ok(serde_json::from_str(&value)?))
        .transpose()
}

fn count(connection: &Connection, sql: &str) -> Result<u64> {
    let value: i64 = connection.query_row(sql, [], |row| row.get(0))?;
    u64::try_from(value).map_err(|_| RegistryError::InvalidCount(value))
}

fn count_with_param(connection: &Connection, sql: &str, value: &str) -> Result<u64> {
    let count: i64 = connection.query_row(sql, params![value], |row| row.get(0))?;
    u64::try_from(count).map_err(|_| RegistryError::InvalidCount(count))
}

fn query_strings(connection: &Connection, sql: &str) -> Result<Vec<String>> {
    let mut statement = connection.prepare(sql)?;
    Ok(statement
        .query_map([], |row| row.get(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?)
}

fn io_error(path: &Path, source: std::io::Error) -> RegistryError {
    RegistryError::Io {
        path: path.display().to_string(),
        source,
    }
}

fn backup_connection(connection: &Connection, registry_dir: &Path) -> Result<PathBuf> {
    let backup_dir = registry_dir.join("backups");
    fs::create_dir_all(&backup_dir).map_err(|source| io_error(&backup_dir, source))?;
    let destination = backup_dir.join(format!(
        "registry-{}-{}.sqlite3",
        Utc::now().format("%Y%m%dT%H%M%SZ"),
        Uuid::new_v4()
    ));
    let temporary =
        NamedTempFile::new_in(&backup_dir).map_err(|source| io_error(&backup_dir, source))?;
    let mut target = Connection::open(temporary.path())?;
    {
        let backup = rusqlite::backup::Backup::new(connection, &mut target)?;
        backup.run_to_completion(32, Duration::from_millis(10), None)?;
    }
    target.close().map_err(|(_, error)| error)?;
    temporary
        .persist(&destination)
        .map_err(|error| io_error(&destination, error.error))?;
    Ok(destination)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use cfctl_core::{
        EventEnvelopeV1, EventSignatureStatusV1, EventUpstreamIdentityV1, EvidenceClass,
        EvidenceV1, ResourceRefV1, ScopeKindV1, ScopeRefV1,
    };
    use chrono::Utc;
    use serde_json::json;

    use super::Registry;

    #[test]
    fn job_insert_failure_rolls_back_the_event_before_acknowledgement() {
        let root = tempfile::tempdir().expect("registry root");
        let mut registry = Registry::open(root.path()).expect("registry opens");
        registry
            .connection
            .execute_batch(
                "CREATE TRIGGER inject_job_failure
                 BEFORE INSERT ON reconciliation_jobs
                 BEGIN SELECT RAISE(ABORT, 'injected crash'); END;",
            )
            .expect("failure trigger installs");
        let scope = ScopeRefV1::new(ScopeKindV1::Account, "account-a", None);
        let now = Utc::now();
        let event = EventEnvelopeV1::new(
            EventUpstreamIdentityV1 {
                provider: "cloudflare".to_owned(),
                source: "access".to_owned(),
                event_type: "cf.access.application.created".to_owned(),
                event_id: "event-a".to_owned(),
                queue_id: Some("queue-a".to_owned()),
                subscription_id: Some("subscription-a".to_owned()),
            },
            1,
            now,
            now,
            Some(scope.clone()),
            "event-a",
            EventSignatureStatusV1::ProviderOriginated,
            Some("authority-a".to_owned()),
            None,
            vec![ResourceRefV1::new(scope, "access_application", "app-a")],
            json!({"id":"app-a"}),
            EvidenceV1::new(
                EvidenceClass::EventReceipt,
                "sha256:event-a",
                "/evidence/event-a.json",
            ),
        )
        .expect("event");
        assert!(registry.ingest_event(&event).is_err());
        assert_eq!(
            registry
                .event_status()
                .expect("status after failure")
                .event_count,
            0
        );
    }
}
