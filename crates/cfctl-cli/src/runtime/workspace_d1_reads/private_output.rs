//! Confidential destination custody and the metadata-only durable observation.
use super::{
    CapabilityV1, CatalogSnapshot, CliError, ErrorV1, EvidenceClass, ExecutedRead, ProfileMetadata,
    Result, ResultEnvelopeV2, StateStore, Utc, Uuid, ValidatedD1ReadInventory, VerificationState,
    credential_generation_for_read, json,
};
use cfctl_cloudflare::d1_read_inventory::{PrivateD1ReadResult, qualify_private_receipt};
use cfctl_core::d1_read_inventory::{
    D1_PRIVATE_FORMAT, D1PrivateReadArtifactV1, D1PrivateReadBindingV1, D1PrivateReadTransportV1,
};
use cfctl_storage::PrivateDirectory;
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    path::{Path, PathBuf},
    time::Instant,
};

pub(super) struct Destination {
    directory: PrivateDirectory,
    name: String,
    path: PathBuf,
}

pub(super) fn prepare(
    validated: &ValidatedD1ReadInventory,
    path: Option<&Path>,
) -> Result<Option<Destination>> {
    if validated.contract().inventory.private_output.is_none() {
        if path.is_some() {
            return Err(CliError::Input(
                "ordinary D1 reads do not accept alternate sinks".into(),
            ));
        }
        return Ok(None);
    }
    let path = path.ok_or_else(|| {
        CliError::Input("private D1 read requires --out <new-private-file>".into())
    })?;
    let parent = path.parent().ok_or_else(destination_error)?;
    let name = path
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or_else(destination_error)?;
    let directory = PrivateDirectory::open(parent).map_err(|_| destination_error())?;
    directory
        .require_new_file(name)
        .map_err(|_| destination_error())?;
    Ok(Some(Destination {
        directory,
        name: name.into(),
        path: path.into(),
    }))
}

fn destination_error() -> CliError {
    CliError::Input(
        "private output requires a new file in an existing canonical owned mode-0700 directory"
            .into(),
    )
}

struct BoundedBytes {
    bytes: Vec<u8>,
    maximum: usize,
}
impl Write for BoundedBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("private artifact bound exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "explicit source, credential, transport and output joins precede private publication"
)]
pub(super) fn persist(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    validated: &ValidatedD1ReadInventory,
    profile: &ProfileMetadata,
    started_at: chrono::DateTime<Utc>,
    mut result: PrivateD1ReadResult,
    destination: &Destination,
) -> Result<ExecutedRead> {
    let contract = validated.contract();
    let disposition = contract
        .inventory
        .private_output
        .as_ref()
        .ok_or_else(destination_error)?;
    let generation = credential_generation_for_read(profile)?;
    if capability.workspace_d1_read_inventory.as_ref() != Some(contract)
        || profile.id != contract.operation.profile_id
        || profile.account_id.as_deref() != Some(contract.operation.account_id.as_str())
        || generation != validated.call().expected_credential_generation_id
    {
        return Err(CliError::Input(
            "private read source or credential join drifted".into(),
        ));
    }
    let query = &contract.inventory.queries[0];
    let contract_sha256 = cfctl_core::hash_value(&serde_json::to_value(contract)?)?;
    let mut artifact_receipt = None;
    let mut possibly_published = false;
    if let Some(body) = result.provider_response.take() {
        let qualified = qualify_private_receipt(validated, result.http_status.unwrap_or(0), &body);
        if !result.attempted
            || result.classification != "complete_read"
            || qualified.ok() != Some(result.rows_read)
            || result.response_bytes == 0
            || result.response_bytes > query.output.max_bytes
        {
            result.classification = "provider_shape_or_output_policy_rejected";
        } else if Instant::now() >= result.deadline {
            result.classification = "run_deadline";
        } else {
            let artifact = D1PrivateReadArtifactV1 {
                schema_version: 1,
                kind: D1_PRIVATE_FORMAT.into(),
                binding: D1PrivateReadBindingV1 {
                    contract: contract.clone(),
                    capability_id: capability.id.clone(),
                    catalog_schema_hash: catalog.schema_hash.clone(),
                    contract_sha256: contract_sha256.clone(),
                    build: crate::build_identity::current_build_info(),
                    profile_id: profile.id.clone(),
                    credential_generation_id: Uuid::parse_str(&generation)
                        .map_err(|_| destination_error())?,
                    query_id: query.id.clone(),
                    query_sha256: query.sha256.clone(),
                },
                started_at,
                completed_at: Utc::now(),
                transport: D1PrivateReadTransportV1 {
                    http_status: 200,
                    response_bytes: result.response_bytes,
                    content_encoding: "identity".into(),
                    attempted_queries: 1,
                    read_complete: true,
                    served_by_primary: true,
                    application_predicates_evaluated: false,
                },
                provider_response: body,
            };
            (artifact_receipt, possibly_published, result.classification) = publish_artifact(
                &artifact,
                disposition.max_artifact_bytes,
                result.deadline,
                destination,
            );
        }
    } else if result.classification == "complete_read" {
        result.classification = "provider_shape_or_output_policy_rejected";
    }
    let complete = artifact_receipt.is_some();
    let value = json!({"kind":D1_PRIVATE_FORMAT,"schema_version":1,
        "capability_id":capability.id,"catalog_schema_hash":catalog.schema_hash,
        "build":crate::build_identity::current_build_info(),"profile_id":profile.id,
        "credential_generation_id":generation,"account_id":contract.operation.account_id,
        "database_id":contract.operation.database_id,"repository_head":contract.repository_head,
        "repository_tree":contract.repository_tree,"operation_pack_sha256":contract.operation_pack_sha256,
        "inventory_sha256":contract.operation.inventory_sha256,"contract_sha256":contract_sha256,
        "query_id":query.id,"query_sha256":query.sha256,"classification":result.classification,
        "attempted_queries":u64::from(result.attempted),"unattempted_queries":u64::from(!result.attempted),
        "http_status":result.http_status,"response_bytes":result.response_bytes,
        "rows_read":result.rows_read,"read_complete":complete,"application_predicates_evaluated":false,
        "artifact":artifact_receipt,"output_path":destination.path,"possibly_published":possibly_published});
    let class = if result.attempted {
        EvidenceClass::LiveRead
    } else {
        EvidenceClass::LocalProof
    };
    Ok(observe(
        store, capability, profile, value, class, generation,
    ))
}

fn observe(
    store: &StateStore,
    capability: &CapabilityV1,
    profile: &ProfileMetadata,
    mut value: serde_json::Value,
    class: EvidenceClass,
    generation: String,
) -> ExecutedRead {
    let mut complete = value["read_complete"] == json!(true);
    let attempted = value["attempted_queries"] == json!(1);
    let evidence = if let Ok(evidence) = store.write_observation_evidence(class, &value) {
        Some(evidence)
    } else {
        complete = false;
        value["classification"] = json!("private_observation_incomplete");
        value["read_complete"] = json!(false);
        value["artifact"] = serde_json::Value::Null;
        None
    };
    let mut envelope = ResultEnvelopeV2::success("call", value);
    if let Some(evidence) = evidence {
        envelope = envelope.with_evidence(evidence);
    }
    envelope.capability_id = Some(capability.id.clone());
    envelope.profile_id = Some(profile.id.clone());
    envelope.account_id.clone_from(&profile.account_id);
    envelope.ok = complete;
    envelope.performed = attempted;
    envelope.verification.state = VerificationState::NotApplicable;
    envelope.verification.basis = Some(
        "Private transport qualification only; the owner must validate application predicates."
            .into(),
    );
    if !complete {
        envelope.error=Some(ErrorV1 {code:"CFCTL_D1_PRIVATE_READ_INCOMPLETE".into(),
        message:"Private read or artifact custody did not qualify.".into(),
        next_step:Some("Inspect fixed classification and output custody before any separately authorized retry.".into())});
    }
    ExecutedRead {
        envelope,
        credential_generation_id: Some(generation),
    }
}

fn publish_artifact(
    artifact: &D1PrivateReadArtifactV1,
    maximum: u64,
    deadline: Instant,
    destination: &Destination,
) -> (Option<serde_json::Value>, bool, &'static str) {
    let Ok(maximum) = usize::try_from(maximum) else {
        return (None, false, "private_artifact_bound_rejected");
    };
    let mut buffer = BoundedBytes {
        bytes: Vec::new(),
        maximum,
    };
    if serde_json::to_writer(&mut buffer, artifact).is_err() {
        return (None, false, "private_artifact_bound_rejected");
    }
    if Instant::now() >= deadline {
        return (None, false, "run_deadline");
    }
    let sha256 = format!("sha256:{}", hex::encode(Sha256::digest(&buffer.bytes)));
    match destination
        .directory
        .publish_new_file(&destination.name, &buffer.bytes, deadline)
    {
        Ok(()) => (
            Some(json!({"path":destination.path,"bytes":buffer.bytes.len(),"sha256":sha256})),
            true,
            "complete_read",
        ),
        Err(error) => (
            None,
            error.published,
            if error.published {
                "private_custody_incomplete"
            } else {
                "private_publication_rejected"
            },
        ),
    }
}
