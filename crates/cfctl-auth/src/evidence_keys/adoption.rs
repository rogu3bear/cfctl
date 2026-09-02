use super::*;

pub const EVIDENCE_KEY_ADOPTION_PROTOCOL_ID: &str = "cfctl-evidence-key-adoption-v2";
pub const EVIDENCE_KEY_ADOPTION_PLAN_RECORD_VERSION: u8 = 2;
pub const EVIDENCE_KEY_ADOPTION_TERMINAL_VERSION: u8 = 1;
const CROSSING_COMMITMENT_VERSION: u8 = 1;
const POINTER_VERSION: u8 = 1;
const APPROVAL_MINUTES: i64 = 15;

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn platform_adoption_monotonic_ns() -> Result<u64> {
    #[cfg(target_os = "macos")]
    let clock_id = rustix::time::ClockId::Monotonic;
    #[cfg(target_os = "linux")]
    let clock_id = rustix::time::ClockId::Boottime;
    let value = rustix::time::clock_gettime(clock_id);
    let seconds = u64::try_from(value.tv_sec).map_err(|_| {
        AuthError::SecretStore("platform monotonic clock returned a negative value".to_owned())
    })?;
    let nanos = u64::try_from(value.tv_nsec).map_err(|_| {
        AuthError::SecretStore("platform monotonic clock returned invalid nanoseconds".to_owned())
    })?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|base| base.checked_add(nanos))
        .ok_or_else(|| AuthError::SecretStore("platform monotonic clock overflowed".to_owned()))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn platform_adoption_monotonic_ns() -> Result<u64> {
    Err(AuthError::SecretStore(
        "boot-scoped adoption clock is unsupported on this platform".to_owned(),
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceKeyAdoptionRuntimeIdentityV1 {
    pub validation_provider: String,
    pub requirement_text: String,
    pub requirement_sha256: String,
    pub dynamic_self_validation: String,
    pub protocol_identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceKeyAdoptionAcceptanceV1 {
    pub admission_source: String,
    pub source_candidate_identity: String,
    pub installed_artifact_identity: String,
    pub expected_architecture: String,
    pub expected_running_cdhash: String,
    pub expected_cdhash_algorithm: String,
    pub expected_cdhash_full_digest_provenance: String,
    pub requirement_text: String,
    pub requirement_utf8_hex: String,
    pub requirement_sha256: String,
}

impl EvidenceKeyAdoptionAcceptanceV1 {
    pub fn operator_supplied(
        source_candidate_identity: String,
        installed_artifact_identity: String,
        expected_architecture: String,
        expected_running_cdhash: String,
        expected_cdhash_algorithm: String,
        expected_cdhash_full_digest_provenance: String,
    ) -> Result<Self> {
        let cdhash = canonical_cdhash(&expected_running_cdhash)?;
        let requirement_text = format!("cdhash H\"{cdhash}\"");
        let requirement_utf8_hex = hex::encode(requirement_text.as_bytes());
        let requirement_sha256 = sha256(requirement_text.as_bytes());
        let acceptance = Self {
            admission_source: "operator_supplied".to_owned(),
            source_candidate_identity,
            installed_artifact_identity,
            expected_architecture,
            expected_running_cdhash: cdhash,
            expected_cdhash_algorithm,
            expected_cdhash_full_digest_provenance,
            requirement_text,
            requirement_utf8_hex,
            requirement_sha256,
        };
        validate_acceptance(&acceptance)?;
        Ok(acceptance)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceKeyAdoptionClockV1 {
    pub boot_identity: String,
    pub monotonic_ns: u64,
    pub wall_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceKeyAdoptionObservationV1 {
    pub marker_identity: Option<String>,
    pub authenticated_descriptor_count: usize,
    pub authenticated_proof_count: usize,
    pub runtime: EvidenceKeyAdoptionRuntimeIdentityV1,
    pub clock: EvidenceKeyAdoptionClockV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceKeyAdoptionPlanV1 {
    pub plan_id: String,
    pub status: EvidenceKeyStatusV1,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub state: String,
    pub next_action: String,
    pub accepted_runtime: EvidenceKeyAdoptionAcceptanceV1,
    pub runtime_validation: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanRecordV2 {
    version: u8,
    plan_id: String,
    location_identity: String,
    registry_byte_count: usize,
    registry_sha256: String,
    status: EvidenceKeyStatusV1,
    authenticated_descriptor_count: usize,
    authenticated_proof_count: usize,
    accepted_runtime: EvidenceKeyAdoptionAcceptanceV1,
    generation: u64,
    predecessor_pointer_sha256: Option<String>,
    boot_identity: String,
    monotonic_created_ns: u64,
    monotonic_deadline_ns: u64,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanPointerV1 {
    version: u8,
    plan_id: String,
    record_sha256: String,
    record_json: String,
    phase: String,
    generation: u64,
    predecessor_pointer_sha256: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminalV1 {
    version: u8,
    plan_id: String,
    record_sha256: String,
    outcome: String,
    at: DateTime<Utc>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CrossingCommitmentV1 {
    version: u8,
    plan_id: String,
    record_sha256: String,
    generation: u64,
    predecessor_pointer_sha256: Option<String>,
    boot_identity: String,
    monotonic_observed_ns: u64,
    wall_observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublicationOutcome {
    Clean,
    ResponseLossReconciled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdoptionPlanPersistenceStage {
    RecordResponseLossReconciled,
    RecordReadback,
    AllocatingPointerReadback,
    AllocatingPointerResponseLossReconciled,
    BeforeActivePointerPublication,
    ActivePointerResponseLossReconciled,
    ActivePointerReadback,
}

impl EvidenceKeyManager {
    pub(super) fn adoption_crossing_is_sealed_or_absent(&self) -> Result<bool> {
        let Some(pointer) = self.load_discoverable_pointer()? else {
            return Ok(true);
        };
        let (record, _) = self.record_for_pointer(&pointer)?;
        Ok(self.load_crossing_commitment(&record)?.is_some())
    }

    pub fn adoption_preview(
        &self,
        observation: &EvidenceKeyAdoptionObservationV1,
    ) -> Result<EvidenceKeyStatusV1> {
        Self::require_absent_marker_and_zero_artifacts(observation)?;
        validate_clock(&observation.clock)?;
        self.adoption_registry_binding().map(|(_, status)| status)
    }

    pub fn create_adoption_plan(
        &self,
        observation: &EvidenceKeyAdoptionObservationV1,
        acceptance: EvidenceKeyAdoptionAcceptanceV1,
    ) -> Result<EvidenceKeyAdoptionPlanV1> {
        self.create_adoption_plan_with_hook(observation, acceptance, |_| Ok(()))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the crash-consistent record and pointer publication sequence stays contiguous"
    )]
    fn create_adoption_plan_with_hook(
        &self,
        observation: &EvidenceKeyAdoptionObservationV1,
        acceptance: EvidenceKeyAdoptionAcceptanceV1,
        mut hook: impl FnMut(AdoptionPlanPersistenceStage) -> Result<()>,
    ) -> Result<EvidenceKeyAdoptionPlanV1> {
        validate_acceptance(&acceptance)?;
        let status = self.adoption_preview(observation)?;
        validate_runtime(&observation.runtime, &acceptance)?;
        if observation.runtime.dynamic_self_validation != "satisfied" {
            return Err(AuthError::SecretStore(
                "the calling process did not satisfy the exact operator-accepted requirement"
                    .to_owned(),
            ));
        }
        let pointer_slot = self.load_pointer()?;
        let prior_pointer = match pointer_slot.as_ref() {
            Some(current) => match self.load_record_optional(&current.plan_id)? {
                Some(_) => Some(current.clone()),
                None if current.phase == "allocating" => None,
                None => {
                    return Err(AuthError::SecretStore(
                        "active adoption pointer has no immutable plan record".to_owned(),
                    ));
                }
            },
            None => None,
        };
        if let Some(current) = &prior_pointer {
            let (current_record, _) = self.record_for_pointer(current)?;
            let current_plan =
                self.status_from_record(current_record.clone(), Some(current), observation)?;
            if current.phase == "allocating"
                && current_record.accepted_runtime == acceptance
                && matches!(
                    current_plan.state.as_str(),
                    "allocating_recoverable" | "marker_crossed"
                )
            {
                let active = self.activate_pointer(current, &current_record, &mut hook)?;
                return self.status_from_record(current_record, Some(&active), observation);
            }
            if current.phase == "active"
                && current_record.accepted_runtime == acceptance
                && matches!(current_plan.state.as_str(), "prepared" | "marker_crossed")
            {
                return Ok(current_plan);
            }
            if !matches!(
                current_plan.state.as_str(),
                "expired" | "completed" | "revoked"
            ) {
                return Err(AuthError::SecretStore(
                    "a prior adoption plan is not terminal or cleanly expired".to_owned(),
                ));
            }
        }
        let (registry, rebound) = self.adoption_registry_binding()?;
        if rebound != status {
            return Err(AuthError::SecretStore(
                "valid authority drifted during adoption planning".to_owned(),
            ));
        }
        let plan_id = Uuid::new_v4().to_string();
        // Even an allocating pointer whose record is absent is not an active
        // allocation, but its exact bytes remain part of the replacement
        // lineage. This makes recovery compare-and-set and predecessor-bound
        // instead of silently erasing evidence of the interrupted write.
        let generation = pointer_slot.as_ref().map_or(Ok(1), |pointer| {
            pointer.generation.checked_add(1).ok_or_else(|| {
                AuthError::SecretStore("adoption plan generation overflowed".to_owned())
            })
        })?;
        let predecessor_pointer_sha256 = pointer_slot.as_ref().map(pointer_digest).transpose()?;
        let deadline = observation
            .clock
            .monotonic_ns
            .checked_add(15 * 60 * 1_000_000_000)
            .ok_or_else(|| {
                AuthError::SecretStore("adoption monotonic deadline overflowed".to_owned())
            })?;
        let record = PlanRecordV2 {
            version: EVIDENCE_KEY_ADOPTION_PLAN_RECORD_VERSION,
            plan_id: plan_id.clone(),
            location_identity: self.location_identity.clone(),
            registry_byte_count: registry.len(),
            registry_sha256: sha256(registry.as_bytes()),
            status,
            authenticated_descriptor_count: 0,
            authenticated_proof_count: 0,
            accepted_runtime: acceptance,
            generation,
            predecessor_pointer_sha256: predecessor_pointer_sha256.clone(),
            boot_identity: observation.clock.boot_identity.clone(),
            monotonic_created_ns: observation.clock.monotonic_ns,
            monotonic_deadline_ns: deadline,
            created_at: observation.clock.wall_at,
            expires_at: observation.clock.wall_at + Duration::minutes(APPROVAL_MINUTES),
        };
        let encoded = serde_json::to_string(&record)?;
        let pointer = PlanPointerV1 {
            version: POINTER_VERSION,
            plan_id,
            record_sha256: sha256(encoded.as_bytes()),
            record_json: encoded.clone(),
            phase: "allocating".to_owned(),
            generation,
            predecessor_pointer_sha256,
        };
        let record_outcome = self.create_exact(
            &self.record_key(&record.plan_id)?,
            &encoded,
            "adoption plan record",
        )?;
        if record_outcome == PublicationOutcome::ResponseLossReconciled {
            hook(AdoptionPlanPersistenceStage::RecordResponseLossReconciled)?;
        }
        if self.load_record(&record.plan_id)? != record {
            return Err(AuthError::SecretStore(
                "adoption plan record exact readback failed".to_owned(),
            ));
        }
        hook(AdoptionPlanPersistenceStage::RecordReadback)?;
        let pointer_outcome = self.save_pointer(&pointer, pointer_slot.as_ref())?;
        if pointer_outcome == PublicationOutcome::ResponseLossReconciled {
            hook(AdoptionPlanPersistenceStage::AllocatingPointerResponseLossReconciled)?;
        }
        hook(AdoptionPlanPersistenceStage::AllocatingPointerReadback)?;
        let active = self.activate_pointer(&pointer, &record, &mut hook)?;
        self.status_from_record(record, Some(&active), observation)
    }

    pub fn current_adoption_plan(
        &self,
        observation: &EvidenceKeyAdoptionObservationV1,
    ) -> Result<Option<EvidenceKeyAdoptionPlanV1>> {
        self.load_discoverable_pointer()?
            .map(|pointer| {
                let (record, _) = self.record_for_pointer(&pointer)?;
                self.status_from_record(record, Some(&pointer), observation)
            })
            .transpose()
    }

    pub fn current_adoption_plan_id(&self) -> Result<Option<String>> {
        self.load_discoverable_pointer()
            .map(|pointer| pointer.map(|item| item.plan_id))
    }

    pub fn adoption_plan_acceptance(
        &self,
        plan_id: &str,
    ) -> Result<EvidenceKeyAdoptionAcceptanceV1> {
        Ok(self.load_record(plan_id)?.accepted_runtime)
    }

    pub fn adoption_plan_status(
        &self,
        plan_id: &str,
        observation: &EvidenceKeyAdoptionObservationV1,
    ) -> Result<EvidenceKeyAdoptionPlanV1> {
        let pointer = self.load_discoverable_pointer()?;
        let record = self.load_record(plan_id)?;
        self.status_from_record(record, pointer.as_ref(), observation)
    }

    pub fn revoke_adoption_plan(
        &self,
        plan_id: &str,
        observation: &EvidenceKeyAdoptionObservationV1,
    ) -> Result<EvidenceKeyAdoptionPlanV1> {
        let plan = self.adoption_plan_status(plan_id, observation)?;
        if plan.state != "prepared" && plan.state != "expired" {
            return Err(AuthError::SecretStore(
                "adoption cannot be revoked after marker crossing or conflict".to_owned(),
            ));
        }
        self.create_terminal(plan_id, "revoked", observation.clock.wall_at)?;
        self.adoption_plan_status(plan_id, observation)
    }

    pub fn prepare_adoption(
        &self,
        plan_id: &str,
        observation: &EvidenceKeyAdoptionObservationV1,
    ) -> Result<EvidenceKeyStatusV1> {
        let acceptance = self.adoption_plan_acceptance(plan_id)?;
        validate_runtime(&observation.runtime, &acceptance)?;
        if observation.runtime.dynamic_self_validation != "satisfied" {
            return Err(AuthError::SecretStore(
                "the calling process does not satisfy the exact operator-accepted requirement"
                    .to_owned(),
            ));
        }
        let plan = self.adoption_plan_status(plan_id, observation)?;
        if !matches!(
            plan.state.as_str(),
            "prepared" | "crossing_committed" | "marker_crossed" | "completed"
        ) {
            return Err(AuthError::SecretStore(format!(
                "adoption plan is {} and cannot execute",
                plan.state
            )));
        }
        self.require_current_plan_pointer(plan_id)?;
        Ok(plan.status)
    }

    pub fn commit_adoption_marker_crossing(
        &self,
        plan_id: &str,
        observation: &EvidenceKeyAdoptionObservationV1,
    ) -> Result<EvidenceKeyAdoptionPlanV1> {
        let acceptance = self.adoption_plan_acceptance(plan_id)?;
        validate_runtime(&observation.runtime, &acceptance)?;
        if observation.runtime.dynamic_self_validation != "satisfied" {
            return Err(AuthError::SecretStore(
                "adoption crossing commitment requires successful dynamic self-validation"
                    .to_owned(),
            ));
        }
        let pointer = self.load_discoverable_pointer()?.ok_or_else(|| {
            AuthError::SecretStore(
                "adoption crossing commitment requires a current canonical pointer".to_owned(),
            )
        })?;
        let (record, _) = self.record_for_pointer(&pointer)?;
        let root = record
            .status
            .state_root_identity
            .as_deref()
            .ok_or_else(|| {
                AuthError::SecretStore("adoption record omitted root identity".to_owned())
            })?;
        if observation.marker_identity.as_deref() != Some(root) {
            return Err(AuthError::SecretStore(
                "adoption crossing commitment requires the exact marker readback".to_owned(),
            ));
        }
        self.require_current_plan_pointer(plan_id)?;
        if self.load_crossing_commitment(&record)?.is_some() {
            return self.adoption_plan_status(plan_id, observation);
        }
        if !self.binding_matches(&record, observation)? {
            return Err(AuthError::SecretStore(
                "valid authority drifted before adoption crossing commitment".to_owned(),
            ));
        }
        if clock_state(&record, &observation.clock) != "prepared" {
            return Err(AuthError::SecretStore(
                "adoption crossing authorization expired before durable commitment".to_owned(),
            ));
        }
        let commitment = CrossingCommitmentV1 {
            version: CROSSING_COMMITMENT_VERSION,
            plan_id: record.plan_id.clone(),
            record_sha256: sha256(serde_json::to_string(&record)?.as_bytes()),
            generation: record.generation,
            predecessor_pointer_sha256: record.predecessor_pointer_sha256.clone(),
            boot_identity: observation.clock.boot_identity.clone(),
            monotonic_observed_ns: observation.clock.monotonic_ns,
            wall_observed_at: observation.clock.wall_at,
        };
        let encoded = serde_json::to_string(&commitment)?;
        self.create_exact(
            &self.crossing_commitment_key(plan_id)?,
            &encoded,
            "adoption crossing commitment",
        )?;
        let committed = self.adoption_plan_status(plan_id, observation)?;
        if committed.state != "marker_crossed" {
            return Err(AuthError::SecretStore(
                "adoption crossing commitment exact readback failed".to_owned(),
            ));
        }
        Ok(committed)
    }

    pub fn complete_adoption_plan(
        &self,
        plan_id: &str,
        observation: &EvidenceKeyAdoptionObservationV1,
    ) -> Result<EvidenceKeyAdoptionPlanV1> {
        let acceptance = self.adoption_plan_acceptance(plan_id)?;
        validate_runtime(&observation.runtime, &acceptance)?;
        if observation.runtime.dynamic_self_validation != "satisfied" {
            return Err(AuthError::SecretStore(
                "adoption completion requires successful dynamic self-validation".to_owned(),
            ));
        }
        let before = self.adoption_plan_status(plan_id, observation)?;
        if before.state == "completed" {
            self.require_current_plan_pointer(plan_id)?;
            return Ok(before);
        }
        if before.state != "marker_crossed" {
            return Err(AuthError::SecretStore(
                "adoption completion requires the exact crossed marker".to_owned(),
            ));
        }
        self.require_current_plan_pointer(plan_id)?;
        self.create_terminal(plan_id, "completed", observation.clock.wall_at)?;
        self.adoption_plan_status(plan_id, observation)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the ordered fail-closed adoption state projection stays visible in one place"
    )]
    fn status_from_record(
        &self,
        record: PlanRecordV2,
        pointer: Option<&PlanPointerV1>,
        observation: &EvidenceKeyAdoptionObservationV1,
    ) -> Result<EvidenceKeyAdoptionPlanV1> {
        validate_plan_record(&record, &record.plan_id)?;
        validate_clock(&observation.clock)?;
        let encoded = serde_json::to_string(&record)?;
        let record_sha256 = sha256(encoded.as_bytes());
        if let Some(pointer) = pointer.filter(|item| item.plan_id == record.plan_id)
            && (pointer.record_sha256 != record_sha256
                || pointer.version != POINTER_VERSION
                || pointer.generation != record.generation
                || pointer.predecessor_pointer_sha256 != record.predecessor_pointer_sha256
                || !matches!(pointer.phase.as_str(), "allocating" | "active"))
        {
            return Err(AuthError::SecretStore(
                "adoption plan pointer is inconsistent".to_owned(),
            ));
        }
        let completed = self.load_terminal(&record, "completed")?;
        let revoked = self.load_terminal(&record, "revoked")?;
        if completed.is_some() && revoked.is_some() {
            return Err(AuthError::SecretStore(
                "adoption terminal history conflicts".to_owned(),
            ));
        }
        let terminal = completed.or(revoked);
        let crossing = self.load_crossing_commitment(&record)?;
        let root = record
            .status
            .state_root_identity
            .as_deref()
            .ok_or_else(|| {
                AuthError::SecretStore("adoption record omitted root identity".to_owned())
            })?;
        let binding = self.binding_matches(&record, observation);
        let runtime = runtime_state(&observation.runtime, &record.accepted_runtime);
        let current_pointer_binds_record = pointer.is_some_and(|item| {
            item.plan_id == record.plan_id
                && item.record_sha256 == record_sha256
                && item.version == POINTER_VERSION
                && item.generation == record.generation
                && item.predecessor_pointer_sha256 == record.predecessor_pointer_sha256
                && matches!(item.phase.as_str(), "allocating" | "active")
        });
        let state = if observation
            .marker_identity
            .as_deref()
            .is_some_and(|marker| marker != root)
        {
            "conflict"
        } else if terminal
            .as_ref()
            .is_some_and(|item| item.outcome == "revoked")
        {
            "revoked"
        } else if binding.is_err() {
            "indeterminate"
        } else if !binding.unwrap_or(false) {
            "conflict"
        } else if terminal
            .as_ref()
            .is_some_and(|item| item.outcome == "completed")
        {
            if observation.marker_identity.as_deref() == Some(root) && crossing.is_some() {
                "completed"
            } else {
                "conflict"
            }
        } else if !current_pointer_binds_record {
            if observation.marker_identity.is_none()
                && clock_state(&record, &observation.clock) == "expired"
            {
                "expired"
            } else {
                "conflict"
            }
        } else if observation.marker_identity.as_deref() == Some(root) && crossing.is_some() {
            "marker_crossed"
        } else if observation.marker_identity.as_deref() == Some(root) {
            "conflict"
        } else if crossing.is_some() {
            "crossing_committed"
        } else if clock_state(&record, &observation.clock) != "prepared" {
            clock_state(&record, &observation.clock)
        } else if runtime == "indeterminate" {
            "indeterminate"
        } else if runtime != "satisfied" {
            "conflict"
        } else if pointer
            .is_some_and(|item| item.plan_id == record.plan_id && item.phase == "allocating")
        {
            "allocating_recoverable"
        } else {
            "prepared"
        };
        let completed_at = terminal
            .as_ref()
            .filter(|item| item.outcome == "completed")
            .map(|item| item.at);
        Ok(EvidenceKeyAdoptionPlanV1 {
            plan_id: record.plan_id,
            status: record.status,
            created_at: record.created_at,
            expires_at: record.expires_at,
            completed_at,
            state: state.to_owned(),
            next_action: match state {
                "prepared" => "execute_exact_plan",
                "allocating_recoverable" => "resume_exact_admission",
                "crossing_committed" | "marker_crossed" => "resume_same_plan_forward",
                "expired" => "create_successor_or_revoke",
                _ => "none",
            }
            .to_owned(),
            accepted_runtime: record.accepted_runtime,
            runtime_validation: runtime.to_owned(),
        })
    }

    fn require_current_plan_pointer(&self, plan_id: &str) -> Result<()> {
        let pointer = self.load_discoverable_pointer()?.ok_or_else(|| {
            AuthError::SecretStore(
                "adoption transition requires a current canonical plan pointer".to_owned(),
            )
        })?;
        if pointer.plan_id != plan_id {
            return Err(AuthError::SecretStore(
                "historical adoption plan cannot authorize a new transition".to_owned(),
            ));
        }
        let (record, persisted) = self.record_for_pointer(&pointer)?;
        if !persisted || record.plan_id != plan_id {
            return Err(AuthError::SecretStore(
                "adoption transition pointer does not bind the requested plan".to_owned(),
            ));
        }
        Ok(())
    }

    fn binding_matches(
        &self,
        record: &PlanRecordV2,
        observation: &EvidenceKeyAdoptionObservationV1,
    ) -> Result<bool> {
        let (registry, status) = self.adoption_registry_binding()?;
        Ok(record.location_identity == self.location_identity
            && self.required_backend == SecretBackend::PlatformKeyring
            && observation.authenticated_descriptor_count == record.authenticated_descriptor_count
            && observation.authenticated_proof_count == record.authenticated_proof_count
            && registry.len() == record.registry_byte_count
            && sha256(registry.as_bytes()) == record.registry_sha256
            && status == record.status)
    }

    fn require_absent_marker_and_zero_artifacts(
        observation: &EvidenceKeyAdoptionObservationV1,
    ) -> Result<()> {
        if observation.marker_identity.is_some()
            || observation.authenticated_descriptor_count != 0
            || observation.authenticated_proof_count != 0
        {
            return Err(AuthError::SecretStore(
                "adoption preview requires absent marker and zero authenticated artifacts"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    fn adoption_registry_binding(&self) -> Result<(String, EvidenceKeyStatusV1)> {
        if self.required_backend != SecretBackend::PlatformKeyring {
            return Err(AuthError::SecretStore(
                "adoption requires direct platform custody".to_owned(),
            ));
        }
        let key = self.registry_key();
        let encoded = self.store.get(&key)?.ok_or_else(|| {
            AuthError::SecretStore("adoption requires one canonical registry".to_owned())
        })?;
        if self.store.locate(&key)? != Some(SecretBackend::PlatformKeyring) {
            return Err(AuthError::SecretStore(
                "adoption registry backend is not canonical".to_owned(),
            ));
        }
        let registry: EvidenceKeyRegistryV1 = serde_json::from_str(&encoded)?;
        validate_registry(&registry)?;
        Ok((encoded, self.status_from_registry(&registry)))
    }

    fn pointer_key(&self) -> String {
        format!(
            "{REGISTRY_KEY_PREFIX}/{}/adoption-v2/current",
            self.location_identity
        )
    }
    fn record_key(&self, plan_id: &str) -> Result<String> {
        canonical_plan(plan_id).map(|id| {
            format!(
                "{REGISTRY_KEY_PREFIX}/{}/adoption-v2/records/{id}",
                self.location_identity
            )
        })
    }
    fn terminal_key(&self, plan_id: &str, outcome: &str) -> Result<String> {
        canonical_plan(plan_id).map(|id| {
            format!(
                "{REGISTRY_KEY_PREFIX}/{}/adoption-v2/terminals/{id}/{outcome}",
                self.location_identity
            )
        })
    }
    fn crossing_commitment_key(&self, plan_id: &str) -> Result<String> {
        canonical_plan(plan_id).map(|id| {
            format!(
                "{REGISTRY_KEY_PREFIX}/{}/adoption-v2/crossing-commitments/{id}",
                self.location_identity
            )
        })
    }

    fn save_pointer(
        &self,
        pointer: &PlanPointerV1,
        expected_existing: Option<&PlanPointerV1>,
    ) -> Result<PublicationOutcome> {
        validate_pointer(pointer)?;
        let encoded = serde_json::to_string(pointer)?;
        let expected = expected_existing.map(serde_json::to_string).transpose()?;
        let existing = self.store.get(&self.pointer_key())?;
        if existing != expected {
            return Err(AuthError::SecretStore(
                "adoption pointer changed before exact publication".to_owned(),
            ));
        }
        let put_result = self.store.put(&self.pointer_key(), &encoded);
        let readback = self.store.get(&self.pointer_key())?;
        if readback.as_deref() != Some(encoded.as_str()) {
            return Err(AuthError::SecretStore(
                "adoption pointer readback is indeterminate".to_owned(),
            ));
        }
        // A backend may report a response-loss error after crossing its write
        // boundary. Exact readback is the only admitted reconciliation.
        Ok(if put_result.is_err() {
            PublicationOutcome::ResponseLossReconciled
        } else {
            PublicationOutcome::Clean
        })
    }
    fn load_pointer(&self) -> Result<Option<PlanPointerV1>> {
        let Some(value) = self.store.get(&self.pointer_key())? else {
            return Ok(None);
        };
        let pointer: PlanPointerV1 = serde_json::from_str(&value)?;
        validate_pointer(&pointer)?;
        if serde_json::to_string(&pointer)? != value {
            return Err(AuthError::SecretStore(
                "adoption allocation pointer is not canonical".to_owned(),
            ));
        }
        Ok(Some(pointer))
    }

    fn load_discoverable_pointer(&self) -> Result<Option<PlanPointerV1>> {
        let Some(pointer) = self.load_pointer()? else {
            return Ok(None);
        };
        match self.load_record_optional(&pointer.plan_id)? {
            Some(_) => {
                let (_, persisted) = self.record_for_pointer(&pointer)?;
                if !persisted {
                    return Err(AuthError::SecretStore(
                        "adoption pointer record readback is indeterminate".to_owned(),
                    ));
                }
                Ok(Some(pointer))
            }
            None if pointer.phase == "allocating" => Ok(None),
            None => Err(AuthError::SecretStore(
                "active adoption pointer has no immutable plan record".to_owned(),
            )),
        }
    }
    fn create_exact(&self, key: &str, encoded: &str, label: &str) -> Result<PublicationOutcome> {
        if let Some(existing) = self.store.get(key)? {
            return if existing == encoded {
                Ok(PublicationOutcome::Clean)
            } else {
                Err(AuthError::SecretStore(format!(
                    "{label} identity collision"
                )))
            };
        }
        let put_result = self.store.put(key, encoded);
        if self.store.get(key)?.as_deref() != Some(encoded) {
            return Err(AuthError::SecretStore(format!(
                "{label} publication is indeterminate"
            )));
        }
        Ok(if put_result.is_err() {
            PublicationOutcome::ResponseLossReconciled
        } else {
            PublicationOutcome::Clean
        })
    }
    fn load_record(&self, plan_id: &str) -> Result<PlanRecordV2> {
        self.load_record_optional(plan_id)?
            .ok_or_else(|| AuthError::SecretStore("adoption plan record is missing".to_owned()))
    }
    fn load_record_optional(&self, plan_id: &str) -> Result<Option<PlanRecordV2>> {
        let Some(value) = self.store.get(&self.record_key(plan_id)?)? else {
            return Ok(None);
        };
        let record: PlanRecordV2 = serde_json::from_str(&value)?;
        validate_plan_record(&record, plan_id)?;
        if serde_json::to_string(&record)? != value {
            return Err(AuthError::SecretStore(
                "adoption plan record is not canonical".to_owned(),
            ));
        }
        Ok(Some(record))
    }
    fn record_for_pointer(&self, pointer: &PlanPointerV1) -> Result<(PlanRecordV2, bool)> {
        let canonical = record_from_pointer(pointer)?;
        let Some(value) = self.store.get(&self.record_key(&pointer.plan_id)?)? else {
            return Err(AuthError::SecretStore(
                "adoption pointer has no immutable plan record".to_owned(),
            ));
        };
        if value != pointer.record_json {
            return Err(AuthError::SecretStore(
                "adoption plan record conflicts with its allocating pointer".to_owned(),
            ));
        }
        let stored: PlanRecordV2 = serde_json::from_str(&value)?;
        validate_plan_record(&stored, &pointer.plan_id)?;
        if stored != canonical {
            return Err(AuthError::SecretStore(
                "adoption plan record conflicts with canonical pointer evidence".to_owned(),
            ));
        }
        Ok((stored, true))
    }
    fn activate_pointer(
        &self,
        pointer: &PlanPointerV1,
        record: &PlanRecordV2,
        hook: &mut impl FnMut(AdoptionPlanPersistenceStage) -> Result<()>,
    ) -> Result<PlanPointerV1> {
        let canonical = record_from_pointer(pointer)?;
        if &canonical != record {
            return Err(AuthError::SecretStore(
                "adoption allocating pointer does not bind the requested record".to_owned(),
            ));
        }
        let (readback, persisted) = self.record_for_pointer(pointer)?;
        if !persisted || readback != *record {
            return Err(AuthError::SecretStore(
                "adoption plan record exact readback failed".to_owned(),
            ));
        }
        hook(AdoptionPlanPersistenceStage::BeforeActivePointerPublication)?;
        let mut active = pointer.clone();
        "active".clone_into(&mut active.phase);
        let pointer_outcome = self.save_pointer(&active, Some(pointer))?;
        if pointer_outcome == PublicationOutcome::ResponseLossReconciled {
            hook(AdoptionPlanPersistenceStage::ActivePointerResponseLossReconciled)?;
        }
        let exact = self.load_pointer()?.ok_or_else(|| {
            AuthError::SecretStore(
                "active adoption pointer disappeared after publication".to_owned(),
            )
        })?;
        if exact != active {
            return Err(AuthError::SecretStore(
                "active adoption pointer exact readback failed".to_owned(),
            ));
        }
        hook(AdoptionPlanPersistenceStage::ActivePointerReadback)?;
        Ok(active)
    }
    fn create_terminal(&self, plan_id: &str, outcome: &str, at: DateTime<Utc>) -> Result<()> {
        let record = self.load_record(plan_id)?;
        let record_sha256 = sha256(serde_json::to_string(&record)?.as_bytes());
        let terminal = TerminalV1 {
            version: EVIDENCE_KEY_ADOPTION_TERMINAL_VERSION,
            plan_id: plan_id.to_owned(),
            record_sha256,
            outcome: outcome.to_owned(),
            at,
        };
        let encoded = serde_json::to_string(&terminal)?;
        let key = self.terminal_key(plan_id, outcome)?;
        match self.store.get(&key)? {
            Some(existing) if existing == encoded => Ok(()),
            Some(_) => Err(AuthError::SecretStore(
                "adoption terminal receipt conflicts".to_owned(),
            )),
            None => self
                .create_exact(&key, &encoded, "adoption terminal receipt")
                .map(|_| ()),
        }
    }
    fn load_terminal(&self, record: &PlanRecordV2, outcome: &str) -> Result<Option<TerminalV1>> {
        let Some(value) = self
            .store
            .get(&self.terminal_key(&record.plan_id, outcome)?)?
        else {
            return Ok(None);
        };
        let terminal: TerminalV1 = serde_json::from_str(&value)?;
        let digest = sha256(serde_json::to_string(record)?.as_bytes());
        if terminal.version != EVIDENCE_KEY_ADOPTION_TERMINAL_VERSION
            || terminal.plan_id != record.plan_id
            || terminal.record_sha256 != digest
            || terminal.outcome != outcome
        {
            return Err(AuthError::SecretStore(
                "adoption terminal receipt is malformed".to_owned(),
            ));
        }
        Ok(Some(terminal))
    }

    fn load_crossing_commitment(
        &self,
        record: &PlanRecordV2,
    ) -> Result<Option<CrossingCommitmentV1>> {
        let Some(value) = self
            .store
            .get(&self.crossing_commitment_key(&record.plan_id)?)?
        else {
            return Ok(None);
        };
        let commitment: CrossingCommitmentV1 = serde_json::from_str(&value)?;
        let record_sha256 = sha256(serde_json::to_string(record)?.as_bytes());
        let observed_clock = EvidenceKeyAdoptionClockV1 {
            boot_identity: commitment.boot_identity.clone(),
            monotonic_ns: commitment.monotonic_observed_ns,
            wall_at: commitment.wall_observed_at,
        };
        if commitment.version != CROSSING_COMMITMENT_VERSION
            || commitment.plan_id != record.plan_id
            || commitment.record_sha256 != record_sha256
            || commitment.generation != record.generation
            || commitment.predecessor_pointer_sha256 != record.predecessor_pointer_sha256
            || clock_state(record, &observed_clock) != "prepared"
            || serde_json::to_string(&commitment)? != value
        {
            return Err(AuthError::SecretStore(
                "adoption crossing commitment is malformed".to_owned(),
            ));
        }
        Ok(Some(commitment))
    }
}

fn validate_plan_record(record: &PlanRecordV2, expected_plan_id: &str) -> Result<()> {
    canonical_plan(expected_plan_id)?;
    if record.version != EVIDENCE_KEY_ADOPTION_PLAN_RECORD_VERSION
        || record.plan_id != expected_plan_id
        || record.location_identity.is_empty()
        || record
            .location_identity
            .bytes()
            .any(|byte| byte.is_ascii_whitespace())
        || record.registry_byte_count == 0
        || validate_identity("adoption registry digest", &record.registry_sha256).is_err()
        || !record.status.initialized
        || record.status.backend != Some(SecretBackend::PlatformKeyring)
        || record
            .status
            .state_root_identity
            .as_deref()
            .is_none_or(|identity| validate_identity("adoption root identity", identity).is_err())
        || record.status.active_generation_id.is_none()
        || record.generation == 0
        || (record.generation == 1 && record.predecessor_pointer_sha256.is_some())
        || (record.generation > 1
            && record
                .predecessor_pointer_sha256
                .as_deref()
                .is_none_or(|identity| {
                    validate_identity("adoption predecessor pointer", identity).is_err()
                }))
        || record.monotonic_deadline_ns <= record.monotonic_created_ns
        || record.expires_at <= record.created_at
    {
        return Err(AuthError::SecretStore(
            "adoption plan record is malformed".to_owned(),
        ));
    }
    validate_acceptance(&record.accepted_runtime)
}

fn validate_pointer_metadata(pointer: &PlanPointerV1) -> Result<()> {
    canonical_plan(&pointer.plan_id)?;
    if pointer.version != POINTER_VERSION
        || validate_identity("adoption record digest", &pointer.record_sha256).is_err()
        || pointer.record_json.is_empty()
        || pointer.generation == 0
        || (pointer.generation == 1 && pointer.predecessor_pointer_sha256.is_some())
        || (pointer.generation > 1
            && pointer
                .predecessor_pointer_sha256
                .as_deref()
                .is_none_or(|identity| {
                    validate_identity("adoption predecessor pointer", identity).is_err()
                }))
        || !matches!(pointer.phase.as_str(), "allocating" | "active")
    {
        return Err(AuthError::SecretStore(
            "adoption allocation pointer is malformed".to_owned(),
        ));
    }
    Ok(())
}

fn record_from_pointer(pointer: &PlanPointerV1) -> Result<PlanRecordV2> {
    validate_pointer_metadata(pointer)?;
    if sha256(pointer.record_json.as_bytes()) != pointer.record_sha256 {
        return Err(AuthError::SecretStore(
            "adoption pointer record digest is inconsistent".to_owned(),
        ));
    }
    let record: PlanRecordV2 = serde_json::from_str(&pointer.record_json)?;
    validate_plan_record(&record, &pointer.plan_id)?;
    if serde_json::to_string(&record)? != pointer.record_json
        || record.generation != pointer.generation
        || record.predecessor_pointer_sha256 != pointer.predecessor_pointer_sha256
    {
        return Err(AuthError::SecretStore(
            "adoption pointer canonical record evidence is inconsistent".to_owned(),
        ));
    }
    Ok(record)
}

fn validate_pointer(pointer: &PlanPointerV1) -> Result<()> {
    record_from_pointer(pointer).map(|_| ())
}

fn canonical_plan(value: &str) -> Result<String> {
    Uuid::parse_str(value)
        .ok()
        .filter(|id| id.to_string() == value)
        .map(|id| id.to_string())
        .ok_or_else(|| {
            AuthError::SecretStore("adoption plan identity must be a canonical UUID".to_owned())
        })
}
fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
fn validate_clock(clock: &EvidenceKeyAdoptionClockV1) -> Result<()> {
    if clock.boot_identity.is_empty() {
        return Err(AuthError::SecretStore(
            "adoption boot identity is unavailable".to_owned(),
        ));
    }
    Ok(())
}
fn canonical_cdhash(value: &str) -> Result<String> {
    if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AuthError::SecretStore(
            "expected running CDHash must be exactly 40 hexadecimal characters".to_owned(),
        ));
    }
    Ok(value.to_ascii_lowercase())
}
fn validate_acceptance(acceptance: &EvidenceKeyAdoptionAcceptanceV1) -> Result<()> {
    for (label, value) in [
        (
            "source candidate identity",
            acceptance.source_candidate_identity.as_str(),
        ),
        (
            "expected architecture",
            acceptance.expected_architecture.as_str(),
        ),
        (
            "expected CDHash algorithm",
            acceptance.expected_cdhash_algorithm.as_str(),
        ),
        (
            "expected CDHash full-digest provenance",
            acceptance.expected_cdhash_full_digest_provenance.as_str(),
        ),
    ] {
        if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err(AuthError::SecretStore(format!(
                "adoption {label} must be explicit and whitespace-free"
            )));
        }
    }
    if acceptance.admission_source != "operator_supplied"
        || acceptance.expected_running_cdhash
            != canonical_cdhash(&acceptance.expected_running_cdhash)?
        || acceptance.requirement_text
            != format!("cdhash H\"{}\"", acceptance.expected_running_cdhash)
        || acceptance.requirement_sha256 != sha256(acceptance.requirement_text.as_bytes())
        || acceptance.requirement_utf8_hex != hex::encode(acceptance.requirement_text.as_bytes())
    {
        return Err(AuthError::SecretStore(
            "operator-accepted adoption identity is malformed".to_owned(),
        ));
    }
    validate_identity(
        "adoption installed artifact",
        &acceptance.installed_artifact_identity,
    )
}
fn validate_runtime(
    runtime: &EvidenceKeyAdoptionRuntimeIdentityV1,
    acceptance: &EvidenceKeyAdoptionAcceptanceV1,
) -> Result<()> {
    if runtime.protocol_identity != EVIDENCE_KEY_ADOPTION_PROTOCOL_ID
        || runtime.validation_provider.is_empty()
        || !matches!(
            runtime.dynamic_self_validation.as_str(),
            "satisfied" | "not_satisfied" | "indeterminate"
        )
        || runtime.requirement_text != acceptance.requirement_text
        || runtime.requirement_sha256 != acceptance.requirement_sha256
    {
        return Err(AuthError::SecretStore(
            "adoption dynamic self-validation result is malformed or substituted".to_owned(),
        ));
    }
    Ok(())
}
fn runtime_state<'a>(
    runtime: &'a EvidenceKeyAdoptionRuntimeIdentityV1,
    acceptance: &EvidenceKeyAdoptionAcceptanceV1,
) -> &'a str {
    if validate_runtime(runtime, acceptance).is_err() {
        "indeterminate"
    } else {
        runtime.dynamic_self_validation.as_str()
    }
}
fn clock_state(record: &PlanRecordV2, now: &EvidenceKeyAdoptionClockV1) -> &'static str {
    if now.boot_identity != record.boot_identity {
        "expired"
    } else if now.monotonic_ns < record.monotonic_created_ns || now.wall_at < record.created_at {
        "indeterminate"
    } else if now.monotonic_ns >= record.monotonic_deadline_ns || now.wall_at >= record.expires_at {
        "expired"
    } else {
        "prepared"
    }
}
fn pointer_digest(pointer: &PlanPointerV1) -> Result<String> {
    Ok(sha256(serde_json::to_string(pointer)?.as_bytes()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use crate::MemorySecretStore;

    use super::*;

    #[derive(Default)]
    struct PlatformMemoryStore {
        inner: MemorySecretStore,
        fail_active_pointer_before_write: AtomicBool,
        fail_next_put_after_write: AtomicBool,
        puts: AtomicUsize,
    }

    impl SecretStore for PlatformMemoryStore {
        fn put(&self, key: &str, value: &str) -> Result<()> {
            self.puts.fetch_add(1, Ordering::AcqRel);
            if value.contains("\"phase\":\"active\"")
                && self
                    .fail_active_pointer_before_write
                    .swap(false, Ordering::AcqRel)
            {
                return Err(AuthError::SecretStore(
                    "injected crash before active pointer publication".to_owned(),
                ));
            }
            self.inner.put(key, value)?;
            if self.fail_next_put_after_write.swap(false, Ordering::AcqRel) {
                return Err(AuthError::SecretStore(
                    "injected response loss after publication".to_owned(),
                ));
            }
            Ok(())
        }

        fn get(&self, key: &str) -> Result<Option<String>> {
            self.inner.get(key)
        }

        fn delete(&self, key: &str) -> Result<()> {
            self.inner.delete(key)
        }

        fn locate(&self, key: &str) -> Result<Option<SecretBackend>> {
            Ok(self.inner.get(key)?.map(|_| SecretBackend::PlatformKeyring))
        }
    }

    fn acceptance(cdhash: char) -> EvidenceKeyAdoptionAcceptanceV1 {
        EvidenceKeyAdoptionAcceptanceV1::operator_supplied(
            format!("git:{}", "1".repeat(40)),
            format!("sha256:{}", "2".repeat(64)),
            "arm64".to_owned(),
            cdhash.to_string().repeat(40),
            "sha256-truncated-20".to_owned(),
            format!("sha256:{}", "3".repeat(64)),
        )
        .expect("operator acceptance")
    }

    fn runtime(
        acceptance: &EvidenceKeyAdoptionAcceptanceV1,
        state: &str,
    ) -> EvidenceKeyAdoptionRuntimeIdentityV1 {
        EvidenceKeyAdoptionRuntimeIdentityV1 {
            validation_provider: "injected_native_provider".to_owned(),
            requirement_text: acceptance.requirement_text.clone(),
            requirement_sha256: acceptance.requirement_sha256.clone(),
            dynamic_self_validation: state.to_owned(),
            protocol_identity: EVIDENCE_KEY_ADOPTION_PROTOCOL_ID.to_owned(),
        }
    }

    fn clock(boot: &str, monotonic_ns: u64, wall_seconds: i64) -> EvidenceKeyAdoptionClockV1 {
        EvidenceKeyAdoptionClockV1 {
            boot_identity: boot.to_owned(),
            monotonic_ns,
            wall_at: DateTime::from_timestamp(wall_seconds, 0).expect("test timestamp"),
        }
    }

    fn observation(
        acceptance: &EvidenceKeyAdoptionAcceptanceV1,
        state: &str,
        marker: Option<&str>,
        clock: EvidenceKeyAdoptionClockV1,
    ) -> EvidenceKeyAdoptionObservationV1 {
        EvidenceKeyAdoptionObservationV1 {
            marker_identity: marker.map(str::to_owned),
            authenticated_descriptor_count: 0,
            authenticated_proof_count: 0,
            runtime: runtime(acceptance, state),
            clock,
        }
    }

    fn manager() -> (Arc<PlatformMemoryStore>, EvidenceKeyManager, String) {
        let store = Arc::new(PlatformMemoryStore::default());
        let manager = EvidenceKeyManager::new(
            store.clone(),
            format!("sha256:{}", "4".repeat(64)),
            SecretBackend::PlatformKeyring,
        )
        .expect("manager");
        let root = format!("sha256:{}", "5".repeat(64));
        manager.initialize(&root).expect("valid authority");
        (store, manager, root)
    }

    #[test]
    fn six_state_projection_is_marker_time_runtime_and_terminal_aware() {
        let (_store, manager, root) = manager();
        let accepted = acceptance('a');
        let created = observation(&accepted, "satisfied", None, clock("boot-a", 100, 1_000));
        let plan = manager
            .create_adoption_plan(&created, accepted.clone())
            .expect("plan creates");
        assert_eq!(plan.state, "prepared");
        assert_eq!(plan.accepted_runtime.admission_source, "operator_supplied");

        let expired = observation(
            &accepted,
            "satisfied",
            None,
            clock("boot-a", 900_000_000_100, 1_899),
        );
        assert_eq!(
            manager
                .adoption_plan_status(&plan.plan_id, &expired)
                .expect("expiry status")
                .state,
            "expired"
        );
        let rollback = observation(&accepted, "satisfied", None, clock("boot-a", 99, 999));
        assert_eq!(
            manager
                .adoption_plan_status(&plan.plan_id, &rollback)
                .expect("rollback status")
                .state,
            "indeterminate"
        );
        let runtime_conflict = observation(
            &accepted,
            "not_satisfied",
            None,
            clock("boot-a", 101, 1_001),
        );
        assert_eq!(
            manager
                .adoption_plan_status(&plan.plan_id, &runtime_conflict)
                .expect("runtime status")
                .state,
            "conflict"
        );
        assert!(
            manager
                .prepare_adoption(&plan.plan_id, &runtime_conflict)
                .is_err()
        );

        let committed_marker = observation(
            &accepted,
            "satisfied",
            Some(&root),
            clock("boot-a", 101, 1_001),
        );
        manager
            .commit_adoption_marker_crossing(&plan.plan_id, &committed_marker)
            .expect("crossing commitment");

        let crossed_after_boot = observation(
            &accepted,
            "indeterminate",
            Some(&root),
            clock("boot-b", 1, 20_000),
        );
        assert_eq!(
            manager
                .adoption_plan_status(&plan.plan_id, &crossed_after_boot)
                .expect("crossed status is forward-only")
                .state,
            "marker_crossed"
        );
        let conflict = observation(
            &accepted,
            "satisfied",
            Some("sha256:conflicting-marker"),
            clock("boot-a", 101, 1_001),
        );
        assert_eq!(
            manager
                .adoption_plan_status(&plan.plan_id, &conflict)
                .expect("marker conflict")
                .state,
            "conflict"
        );

        let crossed = observation(
            &accepted,
            "satisfied",
            Some(&root),
            clock("boot-a", 102, 1_002),
        );
        manager
            .complete_adoption_plan(&plan.plan_id, &crossed)
            .expect("completion");
        assert_eq!(
            manager
                .adoption_plan_status(&plan.plan_id, &crossed)
                .expect("completed status")
                .state,
            "completed"
        );
    }

    #[test]
    fn revoked_and_expired_history_remains_id_addressable_across_successors() {
        let (_store, manager, _root) = manager();
        let first_acceptance = acceptance('a');
        let first_observation = observation(
            &first_acceptance,
            "satisfied",
            None,
            clock("boot-a", 100, 1_000),
        );
        let first = manager
            .create_adoption_plan(&first_observation, first_acceptance.clone())
            .expect("first plan");
        let revoked = manager
            .revoke_adoption_plan(&first.plan_id, &first_observation)
            .expect("revoke");
        assert_eq!(revoked.state, "revoked");

        let second_acceptance = acceptance('b');
        let second_observation = observation(
            &second_acceptance,
            "satisfied",
            None,
            clock("boot-a", 200, 1_100),
        );
        let second = manager
            .create_adoption_plan(&second_observation, second_acceptance.clone())
            .expect("successor plan");
        assert_ne!(first.plan_id, second.plan_id);
        assert_eq!(
            manager
                .adoption_plan_status(&first.plan_id, &first_observation)
                .expect("historical revoked plan")
                .state,
            "revoked"
        );

        let second_expired = observation(
            &second_acceptance,
            "satisfied",
            None,
            clock("boot-a", 900_000_000_200, 2_000),
        );
        assert_eq!(
            manager
                .adoption_plan_status(&second.plan_id, &second_expired)
                .expect("historical expiry")
                .state,
            "expired"
        );
        let third_acceptance = acceptance('c');
        manager
            .create_adoption_plan(
                &observation(
                    &third_acceptance,
                    "satisfied",
                    None,
                    clock("boot-a", 900_000_000_201, 2_001),
                ),
                third_acceptance,
            )
            .expect("successor after expiry");
        assert_eq!(
            manager
                .adoption_plan_status(&second.plan_id, &second_expired)
                .expect("expired record remains addressable")
                .state,
            "expired"
        );
    }

    #[test]
    fn expired_history_cannot_complete_after_successor_crosses_shared_marker() {
        let (store, manager, root) = manager();
        let first_acceptance = acceptance('a');
        let first_created = observation(
            &first_acceptance,
            "satisfied",
            None,
            clock("boot-a", 100, 1_000),
        );
        let first = manager
            .create_adoption_plan(&first_created, first_acceptance.clone())
            .expect("first plan");
        let first_expired = observation(
            &first_acceptance,
            "satisfied",
            None,
            clock("boot-a", 900_000_000_100, 1_900),
        );
        assert_eq!(
            manager
                .adoption_plan_status(&first.plan_id, &first_expired)
                .expect("first plan expires")
                .state,
            "expired"
        );

        let successor_acceptance = acceptance('b');
        let successor_created = observation(
            &successor_acceptance,
            "satisfied",
            None,
            clock("boot-a", 900_000_000_101, 1_901),
        );
        let successor = manager
            .create_adoption_plan(&successor_created, successor_acceptance.clone())
            .expect("successor plan");
        manager
            .prepare_adoption(&successor.plan_id, &successor_created)
            .expect("current successor prepares");
        let successor_crossed = observation(
            &successor_acceptance,
            "satisfied",
            Some(&root),
            clock("boot-a", 900_000_000_102, 1_902),
        );
        manager
            .commit_adoption_marker_crossing(&successor.plan_id, &successor_crossed)
            .expect("successor crossing commitment");
        assert_eq!(
            manager
                .adoption_plan_status(&successor.plan_id, &successor_crossed)
                .expect("current successor owns crossed marker")
                .state,
            "marker_crossed"
        );

        let historical_crossed = observation(
            &first_acceptance,
            "satisfied",
            Some(&root),
            clock("boot-a", 900_000_000_103, 1_903),
        );
        assert_eq!(
            manager
                .adoption_plan_status(&first.plan_id, &historical_crossed)
                .expect("historical status remains readable")
                .state,
            "conflict",
            "the authority-wide marker cannot make a historical record executable"
        );
        manager
            .prepare_adoption(&first.plan_id, &historical_crossed)
            .expect_err("historical plan cannot resume through successor marker");
        manager
            .complete_adoption_plan(&first.plan_id, &historical_crossed)
            .expect_err("historical plan cannot create a false completion receipt");
        assert_eq!(
            store
                .inner
                .get(
                    &manager
                        .terminal_key(&first.plan_id, "completed")
                        .expect("historical terminal key"),
                )
                .expect("historical terminal readback"),
            None
        );
    }

    #[test]
    fn marker_requires_a_durable_pre_expiry_crossing_commitment() {
        let (_store, manager, root) = manager();
        let accepted = acceptance('a');
        let created = observation(&accepted, "satisfied", None, clock("boot-a", 100, 1_000));
        let plan = manager
            .create_adoption_plan(&created, accepted.clone())
            .expect("plan");
        let expired_marker = observation(
            &accepted,
            "satisfied",
            Some(&root),
            clock("boot-a", 900_000_000_100, 1_900),
        );
        EvidenceMacProvider::status(&manager, Some(&root))
            .expect_err("an unsealed adoption blocks ordinary authority status");
        manager
            .authenticate(&root, "test-domain", b"payload")
            .expect_err("an unsealed adoption blocks new authenticated evidence");
        assert_eq!(
            manager
                .adoption_plan_status(&plan.plan_id, &expired_marker)
                .expect("matching marker without commitment is classified")
                .state,
            "conflict"
        );
        manager
            .complete_adoption_plan(&plan.plan_id, &expired_marker)
            .expect_err("an uncommitted marker cannot authorize completion");
    }

    #[test]
    fn crossing_commitment_is_admitted_before_expiry_and_recovers_forward_after_expiry() {
        let (_store, manager, root) = manager();
        let accepted = acceptance('a');
        let created = observation(&accepted, "satisfied", None, clock("boot-a", 100, 1_000));
        let plan = manager
            .create_adoption_plan(&created, accepted.clone())
            .expect("plan");
        let before_deadline = observation(
            &accepted,
            "satisfied",
            Some(&root),
            clock("boot-a", 900_000_000_099, 1_899),
        );
        let committed = manager
            .commit_adoption_marker_crossing(&plan.plan_id, &before_deadline)
            .expect("crossing commitment");
        assert_eq!(committed.state, "marker_crossed");
        EvidenceMacProvider::status(&manager, Some(&root))
            .expect("sealed marker re-enables ordinary authority status");

        let after_reboot = observation(
            &accepted,
            "satisfied",
            Some(&root),
            clock("boot-b", 1, 2_000),
        );
        assert_eq!(
            manager
                .adoption_plan_status(&plan.plan_id, &after_reboot)
                .expect("committed crossing survives expiry and reboot")
                .state,
            "marker_crossed"
        );
        assert_eq!(
            manager
                .complete_adoption_plan(&plan.plan_id, &after_reboot)
                .expect("same plan completes forward")
                .state,
            "completed"
        );
    }

    #[test]
    fn deadline_equality_cannot_seal_a_crossed_marker() {
        let (_store, manager, root) = manager();
        let accepted = acceptance('a');
        let created = observation(&accepted, "satisfied", None, clock("boot-a", 100, 1_000));
        let plan = manager
            .create_adoption_plan(&created, accepted.clone())
            .expect("plan");
        let at_deadline = observation(
            &accepted,
            "satisfied",
            Some(&root),
            clock("boot-a", 900_000_000_100, 1_900),
        );
        manager
            .commit_adoption_marker_crossing(&plan.plan_id, &at_deadline)
            .expect_err("deadline equality expires authorization");

        let successor_acceptance = acceptance('b');
        let successor = manager
            .create_adoption_plan(
                &observation(
                    &successor_acceptance,
                    "satisfied",
                    None,
                    clock("boot-a", 900_000_000_101, 1_901),
                ),
                successor_acceptance,
            )
            .expect("expired uncommitted plan permits successor");
        assert_ne!(successor.plan_id, plan.plan_id);
    }

    #[test]
    fn crossing_commitment_blocks_successor_while_marker_is_absent() {
        let (_store, manager, root) = manager();
        let accepted = acceptance('a');
        let created = observation(&accepted, "satisfied", None, clock("boot-a", 100, 1_000));
        let plan = manager
            .create_adoption_plan(&created, accepted.clone())
            .expect("plan");
        let crossed = observation(
            &accepted,
            "satisfied",
            Some(&root),
            clock("boot-a", 101, 1_001),
        );
        manager
            .commit_adoption_marker_crossing(&plan.plan_id, &crossed)
            .expect("crossing commitment");

        let successor_acceptance = acceptance('b');
        manager
            .create_adoption_plan(
                &observation(
                    &successor_acceptance,
                    "satisfied",
                    None,
                    clock("boot-b", 1, 2_000),
                ),
                successor_acceptance,
            )
            .expect_err("forward-only crossing commitment blocks a successor");
    }

    #[test]
    fn crossing_commitment_reconciles_only_exact_response_lost_publication() {
        let (store, manager, root) = manager();
        let accepted = acceptance('a');
        let created = observation(&accepted, "satisfied", None, clock("boot-a", 100, 1_000));
        let plan = manager
            .create_adoption_plan(&created, accepted)
            .expect("plan");
        let crossed = observation(
            &acceptance('a'),
            "satisfied",
            Some(&root),
            clock("boot-a", 101, 1_001),
        );
        store
            .fail_next_put_after_write
            .store(true, Ordering::Release);
        let committed = manager
            .commit_adoption_marker_crossing(&plan.plan_id, &crossed)
            .expect("exact readback reconciles response loss");
        assert_eq!(committed.state, "marker_crossed");

        let public = serde_json::to_string(&committed).expect("public plan json");
        for private_field in [
            "\"record_sha256\":",
            "\"generation\":",
            "\"predecessor_pointer_sha256\":",
            "\"monotonic_observed_ns\":",
            "\"wall_observed_at\":",
        ] {
            assert!(!public.contains(private_field));
        }
    }

    #[test]
    fn response_loss_is_reconciled_and_one_allocating_orphan_recovers_exactly() {
        let (store, manager, _root) = manager();
        let accepted = acceptance('d');
        let observed = observation(&accepted, "satisfied", None, clock("boot-a", 100, 1_000));
        store
            .fail_next_put_after_write
            .store(true, Ordering::Release);
        let first = manager
            .create_adoption_plan(&observed, accepted.clone())
            .expect("response-lost write reconciles by exact readback");
        manager
            .revoke_adoption_plan(&first.plan_id, &observed)
            .expect("first plan revokes");

        let successor = acceptance('e');
        let successor_observation =
            observation(&successor, "satisfied", None, clock("boot-a", 200, 1_100));
        store
            .fail_active_pointer_before_write
            .store(true, Ordering::Release);
        manager
            .create_adoption_plan(&successor_observation, successor.clone())
            .expect_err("crash leaves one allocating pointer and exact record");
        let recovered = manager
            .create_adoption_plan(&successor_observation, successor.clone())
            .expect("same admission recovers the exact allocating orphan");
        assert_eq!(recovered.state, "prepared");
        assert!(
            manager
                .create_adoption_plan(&successor_observation, acceptance('f'))
                .is_err(),
            "a different admission cannot capture the orphan"
        );
    }

    #[test]
    fn immutable_record_precedes_pointer_and_record_only_crash_allows_fresh_create() {
        for (crash_stage, inject_response_loss) in [
            (AdoptionPlanPersistenceStage::RecordReadback, false),
            (
                AdoptionPlanPersistenceStage::RecordResponseLossReconciled,
                true,
            ),
        ] {
            let (store, manager, _root) = manager();
            let accepted = acceptance('d');
            let observed = observation(&accepted, "satisfied", None, clock("boot-a", 100, 1_000));
            if inject_response_loss {
                store
                    .fail_next_put_after_write
                    .store(true, Ordering::Release);
            }
            let puts_before = store.puts.load(Ordering::Acquire);
            manager
                .create_adoption_plan_with_hook(&observed, accepted, |stage| {
                    if stage == crash_stage {
                        Err(AuthError::SecretStore(format!(
                            "injected crash at {stage:?}"
                        )))
                    } else {
                        Ok(())
                    }
                })
                .expect_err("record-only crash must interrupt before pointer publication");
            assert_eq!(
                store.puts.load(Ordering::Acquire) - puts_before,
                1,
                "only the create-only record may cross before the pointer"
            );
            assert_eq!(
                manager
                    .current_adoption_plan_id()
                    .expect("current allocation classification"),
                None,
                "a record without a pointer is not a discoverable allocation"
            );

            let successor = acceptance('e');
            let successor_observation =
                observation(&successor, "satisfied", None, clock("boot-a", 200, 1_100));
            manager
                .create_adoption_plan(&successor_observation, successor)
                .expect("an undiscoverable record-only orphan cannot wedge fresh creation");
        }
    }

    #[test]
    fn allocating_pointer_without_record_is_no_allocation_and_can_be_replaced_exactly() {
        let (store, manager, _root) = manager();
        let accepted = acceptance('d');
        let observed = observation(&accepted, "satisfied", None, clock("boot-a", 100, 1_000));
        manager
            .create_adoption_plan_with_hook(&observed, accepted, |stage| {
                if stage == AdoptionPlanPersistenceStage::AllocatingPointerReadback {
                    Err(AuthError::SecretStore(
                        "injected crash after allocating pointer readback".to_owned(),
                    ))
                } else {
                    Ok(())
                }
            })
            .expect_err("allocating pointer crash must interrupt");
        let stale_pointer = manager
            .load_pointer()
            .expect("stale pointer read")
            .expect("stale allocating pointer");
        store
            .inner
            .delete(
                &manager
                    .record_key(&stale_pointer.plan_id)
                    .expect("stale record key"),
            )
            .expect("simulate the legacy pointer-before-record crash boundary");
        assert_eq!(
            manager
                .current_adoption_plan_id()
                .expect("current allocation classification"),
            None,
            "a pointer without its immutable record is not an allocation"
        );

        let successor = acceptance('e');
        let successor_observation =
            observation(&successor, "satisfied", None, clock("boot-a", 200, 1_100));
        let created = manager
            .create_adoption_plan(&successor_observation, successor)
            .expect("fresh creation must replace the exact stale pointer slot");
        assert_ne!(created.plan_id, stale_pointer.plan_id);
        let replacement = manager
            .load_pointer()
            .expect("replacement pointer read")
            .expect("replacement pointer");
        assert_eq!(replacement.generation, stale_pointer.generation + 1);
        assert_eq!(
            replacement.predecessor_pointer_sha256,
            Some(pointer_digest(&stale_pointer).expect("stale pointer digest")),
            "fresh recovery remains authenticated to the exact interrupted pointer"
        );
    }

    #[test]
    fn allocating_pointer_recovers_after_every_persistence_boundary() {
        let cases = [
            AdoptionPlanPersistenceStage::AllocatingPointerReadback,
            AdoptionPlanPersistenceStage::AllocatingPointerResponseLossReconciled,
            AdoptionPlanPersistenceStage::BeforeActivePointerPublication,
            AdoptionPlanPersistenceStage::ActivePointerResponseLossReconciled,
            AdoptionPlanPersistenceStage::ActivePointerReadback,
        ];
        for crash_stage in cases {
            let (store, manager, _root) = manager();
            let accepted = acceptance('d');
            let observed = observation(&accepted, "satisfied", None, clock("boot-a", 100, 1_000));
            let crashed =
                manager.create_adoption_plan_with_hook(&observed, accepted.clone(), |stage| {
                    if crash_stage
                        == AdoptionPlanPersistenceStage::AllocatingPointerResponseLossReconciled
                        && stage == AdoptionPlanPersistenceStage::RecordReadback
                    {
                        store
                            .fail_next_put_after_write
                            .store(true, Ordering::Release);
                    }
                    if crash_stage
                        == AdoptionPlanPersistenceStage::ActivePointerResponseLossReconciled
                        && stage == AdoptionPlanPersistenceStage::BeforeActivePointerPublication
                    {
                        store
                            .fail_next_put_after_write
                            .store(true, Ordering::Release);
                    }
                    if stage == crash_stage {
                        return Err(AuthError::SecretStore(format!(
                            "injected crash at {stage:?}"
                        )));
                    }
                    Ok(())
                });
            assert!(crashed.is_err(), "stage {crash_stage:?} must interrupt");
            let plan_id = manager
                .current_adoption_plan_id()
                .expect("pointer remains readable")
                .expect("pointer identity remains");
            let current = manager
                .adoption_plan_status(&plan_id, &observed)
                .expect("interrupted plan remains addressable");
            assert!(
                matches!(
                    current.state.as_str(),
                    "allocating_recoverable" | "prepared"
                ),
                "stage {crash_stage:?} projected {}",
                current.state
            );
            assert!(
                manager
                    .create_adoption_plan(&observed, acceptance('e'))
                    .is_err(),
                "different admission must not capture stage {crash_stage:?}"
            );
            let recovered = manager
                .create_adoption_plan(&observed, accepted.clone())
                .expect("identical admission resumes");
            assert_eq!(recovered.plan_id, plan_id);
            assert_eq!(recovered.state, "prepared");
            let replay = manager
                .create_adoption_plan(&observed, accepted.clone())
                .expect("identical active replay is idempotent");
            assert_eq!(replay.plan_id, plan_id);
        }
    }

    #[test]
    fn conflicting_record_never_overwrites_allocating_pointer_evidence() {
        let (store, manager, _root) = manager();
        let accepted = acceptance('d');
        let observed = observation(&accepted, "satisfied", None, clock("boot-a", 100, 1_000));
        manager
            .create_adoption_plan_with_hook(&observed, accepted.clone(), |stage| {
                if stage == AdoptionPlanPersistenceStage::AllocatingPointerReadback {
                    Err(AuthError::SecretStore("injected crash".to_owned()))
                } else {
                    Ok(())
                }
            })
            .expect_err("pointer-only state injected");
        let pointer = manager
            .load_pointer()
            .expect("pointer read")
            .expect("allocating pointer");
        let key = manager.record_key(&pointer.plan_id).expect("record key");
        store
            .inner
            .put(&key, "{\"conflicting\":true}")
            .expect("inject collision");
        let puts_before = store.puts.load(Ordering::Acquire);
        assert!(manager.create_adoption_plan(&observed, accepted).is_err());
        assert_eq!(store.puts.load(Ordering::Acquire), puts_before);
        assert_eq!(
            store.inner.get(&key).expect("record readback").as_deref(),
            Some("{\"conflicting\":true}")
        );
    }

    #[test]
    fn malformed_public_acceptance_is_rejected_before_any_persistence_write() {
        let (store, manager, _root) = manager();
        let valid = acceptance('a');
        let observed = observation(&valid, "satisfied", None, clock("boot-a", 100, 1_000));
        let mut malformed = Vec::new();
        let mut value = valid.clone();
        value.admission_source = "derived".to_owned();
        malformed.push(value);
        let mutations: [fn(&mut EvidenceKeyAdoptionAcceptanceV1); 10] = [
            |value: &mut EvidenceKeyAdoptionAcceptanceV1| {
                value.source_candidate_identity.clear();
            },
            |value: &mut EvidenceKeyAdoptionAcceptanceV1| {
                value.source_candidate_identity = "git:bad identity".to_owned();
            },
            |value: &mut EvidenceKeyAdoptionAcceptanceV1| {
                value.installed_artifact_identity = "sha256:bad".to_owned();
            },
            |value: &mut EvidenceKeyAdoptionAcceptanceV1| {
                value.expected_architecture = " ".to_owned();
            },
            |value: &mut EvidenceKeyAdoptionAcceptanceV1| {
                value.expected_running_cdhash = "f".repeat(39);
            },
            |value: &mut EvidenceKeyAdoptionAcceptanceV1| {
                value.expected_cdhash_algorithm.clear();
            },
            |value: &mut EvidenceKeyAdoptionAcceptanceV1| {
                value.expected_cdhash_full_digest_provenance = "bad provenance".to_owned();
            },
            |value: &mut EvidenceKeyAdoptionAcceptanceV1| {
                value.requirement_text.push(' ');
            },
            |value: &mut EvidenceKeyAdoptionAcceptanceV1| {
                value.requirement_utf8_hex = "00".to_owned();
            },
            |value: &mut EvidenceKeyAdoptionAcceptanceV1| {
                value.requirement_sha256 = format!("sha256:{}", "0".repeat(64));
            },
        ];
        for mutate in mutations {
            let mut value = valid.clone();
            mutate(&mut value);
            malformed.push(value);
        }
        let puts_before = store.puts.load(Ordering::Acquire);
        for candidate in malformed {
            let serialized = serde_json::to_string(&candidate).expect("public value serializes");
            let deserialized: EvidenceKeyAdoptionAcceptanceV1 =
                serde_json::from_str(&serialized).expect("public value deserializes");
            assert!(
                manager
                    .create_adoption_plan(&observed, deserialized)
                    .is_err(),
                "malformed acceptance must fail at persistence boundary: {serialized}"
            );
            assert_eq!(store.puts.load(Ordering::Acquire), puts_before);
        }
    }

    #[test]
    fn dual_terminal_or_record_drift_is_never_projected_as_completed() {
        let (store, manager, root) = manager();
        let accepted = acceptance('a');
        let created = observation(&accepted, "satisfied", None, clock("boot-a", 100, 1_000));
        let plan = manager
            .create_adoption_plan(&created, accepted.clone())
            .expect("plan");
        let crossed = observation(
            &accepted,
            "satisfied",
            Some(&root),
            clock("boot-a", 101, 1_001),
        );
        manager
            .commit_adoption_marker_crossing(&plan.plan_id, &crossed)
            .expect("crossing commitment");
        manager
            .complete_adoption_plan(&plan.plan_id, &crossed)
            .expect("completed terminal");
        let record = manager.load_record(&plan.plan_id).expect("record");
        let revoked = TerminalV1 {
            version: EVIDENCE_KEY_ADOPTION_TERMINAL_VERSION,
            plan_id: plan.plan_id.clone(),
            record_sha256: sha256(
                serde_json::to_string(&record)
                    .expect("record json")
                    .as_bytes(),
            ),
            outcome: "revoked".to_owned(),
            at: crossed.clock.wall_at,
        };
        store
            .inner
            .put(
                &manager
                    .terminal_key(&plan.plan_id, "revoked")
                    .expect("terminal key"),
                &serde_json::to_string(&revoked).expect("terminal json"),
            )
            .expect("inject conflicting immutable event");
        assert!(
            manager
                .adoption_plan_status(&plan.plan_id, &crossed)
                .is_err()
        );
    }
}
