use std::{
    fs,
    fs::OpenOptions,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

use cfctl_auth::SecretStore;
use md5::Md5;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{CallInput, CapabilityV1, CliError, PlanV1, Result, StateStore, Uuid};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

const TARGET_KEY: &str = "r2_private_file_upload";
const STAGE_NAMESPACE: &str = "r2-private-upload";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PrivateStageBindingV1 {
    schema_version: u8,
    path: PathBuf,
    sha256: String,
    md5: String,
    bytes: u64,
}

pub(super) struct LoadedPrivateUpload {
    pub(super) bytes: Vec<u8>,
    pub(super) md5: String,
    pub(super) content_type: String,
}

pub(super) fn prepare_plan_target(
    store: &StateStore,
    secrets: &dyn SecretStore,
    capability: &CapabilityV1,
    input: &CallInput,
    source: &Path,
) -> Result<Option<Value>> {
    let Some(contract) = capability.r2_private_file_upload.as_ref() else {
        return Ok(None);
    };
    if input.if_none_match.as_deref() != Some("*") || !contract.require_if_none_match_star {
        return Err(CliError::Input(
            "private R2 upload requires the exact create-only precondition `--if-none-match '*'`"
                .to_owned(),
        ));
    }
    if input.selectors.get("Content-Length").is_some() {
        return Err(CliError::Input(
            "private R2 upload Content-Length is derived from the managed stage and must not be supplied"
                .to_owned(),
        ));
    }
    let content_type = selector(input, "Content-Type")?;
    if !contract
        .allowed_content_types
        .iter()
        .any(|allowed| allowed == content_type)
    {
        return Err(CliError::Input(format!(
            "private R2 upload Content-Type must be one of: {}",
            contract.allowed_content_types.join(", ")
        )));
    }
    let binding = stage_private_file(store, source, contract.max_source_bytes)?;
    let stage_ref = format!("{STAGE_NAMESPACE}/{}", Uuid::new_v4());
    if let Err(error) = secrets.put(&stage_ref, &serde_json::to_string(&binding)?) {
        let _ = fs::remove_file(&binding.path);
        return Err(error.into());
    }
    Ok(Some(json!({
        "schema_version":1,
        "stage_ref":stage_ref,
        "source_sha256":binding.sha256,
        "source_md5":binding.md5,
        "source_bytes":binding.bytes,
        "content_type":content_type,
        "create_only":true,
    })))
}

pub(super) fn validate_bound_plan(
    store: &StateStore,
    plan: &PlanV1,
    secrets: &dyn SecretStore,
) -> Result<()> {
    let Some(contract) = plan.capability.r2_private_file_upload.as_ref() else {
        return Ok(());
    };
    if contract.etag_algorithm != "md5" || !contract.require_if_none_match_star {
        return Err(CliError::Input(
            "private R2 upload contract drifted; create a new plan".to_owned(),
        ));
    }
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    if input.if_none_match.as_deref() != Some("*") {
        return Err(CliError::Input(
            "private R2 upload lost its create-only precondition; create a new plan".to_owned(),
        ));
    }
    let target = target(plan)?;
    if target.get("create_only").and_then(Value::as_bool) != Some(true) {
        return Err(CliError::Input(
            "private R2 upload target is not create-only; create a new plan".to_owned(),
        ));
    }
    let binding = load_binding(secrets, target)?;
    validate_binding(store, target, &binding, contract.max_source_bytes).map(|_| ())
}

pub(super) fn load(
    store: &StateStore,
    plan: &PlanV1,
    secrets: &dyn SecretStore,
) -> Result<LoadedPrivateUpload> {
    validate_bound_plan(store, plan, secrets)?;
    let target = target(plan)?;
    let binding = load_binding(secrets, target)?;
    let bytes = validate_binding(
        store,
        target,
        &binding,
        plan.capability
            .r2_private_file_upload
            .as_ref()
            .ok_or_else(|| CliError::Input("private R2 upload contract is missing".to_owned()))?
            .max_source_bytes,
    )?;
    Ok(LoadedPrivateUpload {
        bytes,
        md5: binding.md5,
        content_type: required_string(target, "content_type")?.to_owned(),
    })
}

pub(super) fn discard(store: &StateStore, plan: &PlanV1, secrets: &dyn SecretStore) -> Result<()> {
    let Some(target) = plan.targets.pointer(&format!("/adapter/{TARGET_KEY}")) else {
        return Ok(());
    };
    let stage_ref = required_string(target, "stage_ref")?;
    discard_reference(store, stage_ref, secrets)
}

pub(super) fn discard_reference(
    store: &StateStore,
    stage_ref: &str,
    secrets: &dyn SecretStore,
) -> Result<()> {
    let binding = secrets
        .get(stage_ref)?
        .map(|value| serde_json::from_str::<PrivateStageBindingV1>(&value))
        .transpose()?;
    if let Some(binding) = binding {
        let stage_root = store.paths().data_dir.join("private-stages");
        let stage_dir = binding.path.parent().ok_or_else(|| {
            CliError::Input("private R2 upload managed stage has no parent directory".to_owned())
        })?;
        if binding.path.file_name().and_then(|name| name.to_str()) != Some("payload")
            || stage_dir.parent() != Some(stage_root.as_path())
        {
            return Err(CliError::Input(
                "private R2 upload managed stage escaped its exact private directory".to_owned(),
            ));
        }
        match fs::remove_file(&binding.path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(CliError::Io {
                    path: binding.path.display().to_string(),
                    source,
                });
            }
        }
        match fs::remove_dir(stage_dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(CliError::Io {
                    path: stage_dir.display().to_string(),
                    source,
                });
            }
        }
    }
    secrets.delete(stage_ref)?;
    Ok(())
}

fn stage_private_file(
    store: &StateStore,
    source: &Path,
    maximum: u64,
) -> Result<PrivateStageBindingV1> {
    if !source.is_absolute()
        || source
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(CliError::Input(
            "private R2 upload source must be an absolute normalized path".to_owned(),
        ));
    }
    reject_symlink_components(source)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(source).map_err(|source_error| CliError::Io {
        path: source.display().to_string(),
        source: source_error,
    })?;
    let metadata = file.metadata().map_err(|source_error| CliError::Io {
        path: source.display().to_string(),
        source: source_error,
    })?;
    #[cfg(unix)]
    let private_mode = metadata.permissions().mode() & 0o777 == 0o600;
    #[cfg(not(unix))]
    let private_mode = true;
    if !metadata.is_file() || !private_mode || metadata.len() == 0 || metadata.len() > maximum {
        return Err(CliError::Input(format!(
            "private R2 upload source must be a non-empty regular mode-0600 file no larger than {maximum} bytes"
        )));
    }
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| CliError::Input("private R2 upload exceeds this host".to_owned()))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes)
        .map_err(|source_error| CliError::Io {
            path: source.display().to_string(),
            source: source_error,
        })?;
    if bytes.len() as u64 != metadata.len() {
        return Err(CliError::Input(
            "private R2 upload source changed while it was read".to_owned(),
        ));
    }
    let sha256 = hex::encode(Sha256::digest(&bytes));
    let md5 = hex::encode(Md5::digest(&bytes));
    let stage_dir = store
        .paths()
        .data_dir
        .join("private-stages")
        .join(Uuid::new_v4().to_string());
    fs::create_dir_all(&stage_dir).map_err(|source| CliError::Io {
        path: stage_dir.display().to_string(),
        source,
    })?;
    #[cfg(unix)]
    fs::set_permissions(&stage_dir, fs::Permissions::from_mode(0o700)).map_err(|source| {
        CliError::Io {
            path: stage_dir.display().to_string(),
            source,
        }
    })?;
    let stage_path = stage_dir.join("payload");
    let mut stage_options = OpenOptions::new();
    stage_options.write(true).create_new(true);
    #[cfg(unix)]
    stage_options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    let mut stage = stage_options
        .open(&stage_path)
        .map_err(|source| CliError::Io {
            path: stage_path.display().to_string(),
            source,
        })?;
    stage.write_all(&bytes).map_err(|source| CliError::Io {
        path: stage_path.display().to_string(),
        source,
    })?;
    stage.sync_all().map_err(|source| CliError::Io {
        path: stage_path.display().to_string(),
        source,
    })?;
    Ok(PrivateStageBindingV1 {
        schema_version: 1,
        path: stage_path,
        sha256,
        md5,
        bytes: metadata.len(),
    })
}

fn validate_binding(
    store: &StateStore,
    target: &Value,
    binding: &PrivateStageBindingV1,
    maximum: u64,
) -> Result<Vec<u8>> {
    let stage_root = store.paths().data_dir.join("private-stages");
    if binding.schema_version != 1
        || !binding.path.starts_with(&stage_root)
        || binding.bytes == 0
        || binding.bytes > maximum
        || required_string(target, "source_sha256")? != binding.sha256
        || required_string(target, "source_md5")? != binding.md5
        || target.get("source_bytes").and_then(Value::as_u64) != Some(binding.bytes)
    {
        return Err(CliError::Input(
            "private R2 upload stage binding drifted; create a new plan".to_owned(),
        ));
    }
    reject_symlink_components(&binding.path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(&binding.path).map_err(|source| CliError::Io {
        path: binding.path.display().to_string(),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| CliError::Io {
        path: binding.path.display().to_string(),
        source,
    })?;
    #[cfg(unix)]
    let private_mode = metadata.permissions().mode() & 0o777 == 0o600;
    #[cfg(not(unix))]
    let private_mode = true;
    if !metadata.is_file() || !private_mode || metadata.len() != binding.bytes {
        return Err(CliError::Input(
            "private R2 upload managed stage is no longer a matching mode-0600 regular file"
                .to_owned(),
        ));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|source| CliError::Io {
            path: binding.path.display().to_string(),
            source,
        })?;
    if bytes.len() as u64 != binding.bytes
        || hex::encode(Sha256::digest(&bytes)) != binding.sha256
        || hex::encode(Md5::digest(&bytes)) != binding.md5
    {
        return Err(CliError::Input(
            "private R2 upload managed stage content drifted; create a new plan".to_owned(),
        ));
    }
    Ok(bytes)
}

fn reject_symlink_components(path: &Path) -> Result<()> {
    let mut cursor = PathBuf::new();
    for component in path.components() {
        cursor.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&cursor).map_err(|source| CliError::Io {
            path: cursor.display().to_string(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            return Err(CliError::Input(format!(
                "private R2 upload path has symlink component `{}`",
                cursor.display()
            )));
        }
    }
    Ok(())
}

fn selector<'a>(input: &'a CallInput, name: &str) -> Result<&'a str> {
    input
        .selectors
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CliError::Input(format!("private R2 upload selector `{name}` is missing")))
}

fn target(plan: &PlanV1) -> Result<&Value> {
    plan.targets
        .pointer(&format!("/adapter/{TARGET_KEY}"))
        .ok_or_else(|| {
            CliError::Input("private R2 upload target is missing; create a new plan".to_owned())
        })
}

fn load_binding(secrets: &dyn SecretStore, target: &Value) -> Result<PrivateStageBindingV1> {
    let stage_ref = required_string(target, "stage_ref")?;
    let value = secrets.get(stage_ref)?.ok_or_else(|| {
        CliError::Input("private R2 upload managed stage reference is unavailable".to_owned())
    })?;
    Ok(serde_json::from_str(&value)?)
}

fn required_string<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CliError::Input(format!("private R2 upload target omitted `{field}`")))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use cfctl_auth::MemorySecretStore;
    use cfctl_core::{
        AdapterStatus, EffectClass, R2PrivateFileUploadContractV1, RiskClass, SelectorV1,
    };
    use cfctl_storage::RuntimePaths;

    use super::*;

    #[test]
    fn private_stage_keeps_path_and_bytes_out_of_plan_json() {
        let root = tempfile::tempdir_in("/private/tmp").expect("temporary root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
        let source = root.path().join("policy.json");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&source).expect("private source");
        file.write_all(br#"{"operator":"operator@example.com"}"#)
            .expect("write source");
        file.sync_all().expect("sync source");

        let mut capability = CapabilityV1::new(
            "r2-put-object",
            "Upload Object",
            "PUT",
            "/accounts/{account_id}/r2/buckets/{bucket_name}/objects/{object_key}",
        );
        capability.mutating = true;
        capability.adapter_status = AdapterStatus::DynamicApi;
        capability.risk = RiskClass::ScopedWrite;
        capability.effect = EffectClass::ReversibleWrite;
        capability.permissions = vec!["Workers R2 Storage Write".to_owned()];
        capability.selectors = ["account_id", "bucket_name", "object_key"]
            .map(|name| SelectorV1 {
                name: name.to_owned(),
                location: "path".to_owned(),
                required: true,
                value_type: "string".to_owned(),
                description: None,
                contract: None,
            })
            .into_iter()
            .chain([SelectorV1 {
                name: "Content-Type".to_owned(),
                location: "header".to_owned(),
                required: true,
                value_type: "string".to_owned(),
                description: None,
                contract: None,
            }])
            .collect();
        capability.r2_private_file_upload = Some(R2PrivateFileUploadContractV1 {
            max_source_bytes: 300_000_000,
            allowed_content_types: vec!["application/json".to_owned()],
            require_if_none_match_star: true,
            read_capability_id: "r2-get-object".to_owned(),
            delete_capability_id: "r2-delete-object".to_owned(),
            etag_algorithm: "md5".to_owned(),
        });
        let input = CallInput {
            selectors: json!({
                "account_id":"account",
                "bucket_name":"policy-bucket",
                "object_key":"config/policy/digest.json",
                "Content-Type":"application/json"
            }),
            if_none_match: Some("*".to_owned()),
            ..CallInput::default()
        };
        let secrets = MemorySecretStore::default();
        let target = prepare_plan_target(&store, &secrets, &capability, &input, &source)
            .expect("target")
            .expect("upload target");
        let stage_ref = required_string(&target, "stage_ref")
            .expect("stage ref")
            .to_owned();
        let mut plan =
            PlanV1::draft("profile", "account", "catalog", capability, json!({})).expect("plan");
        plan.input = serde_json::to_value(&input).expect("input");
        plan.targets = json!({"adapter":{"r2_private_file_upload":target}});
        let encoded = serde_json::to_string(&plan).expect("plan JSON");
        assert!(!encoded.contains(&source.display().to_string()));
        assert!(!encoded.contains("operator@example.com"));
        validate_bound_plan(&store, &plan, &secrets).expect("bound plan");
        let loaded = load(&store, &plan, &secrets).expect("managed bytes");
        assert_eq!(loaded.bytes, br#"{"operator":"operator@example.com"}"#);
        let stage_dir = load_binding(&secrets, &target)
            .expect("binding before discard")
            .path
            .parent()
            .expect("stage directory")
            .to_path_buf();
        discard(&store, &plan, &secrets).expect("discard stage");
        assert!(secrets.get(&stage_ref).expect("secret read").is_none());
        assert!(!stage_dir.exists());
    }

    #[test]
    fn caller_cannot_override_derived_content_length() {
        let root = tempfile::tempdir_in("/private/tmp").expect("temporary root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
        let source = root.path().join("policy.json");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&source).expect("private source");
        file.write_all(br#"{"routes":141}"#).expect("write source");
        file.sync_all().expect("sync source");
        let mut capability = CapabilityV1::new(
            "r2-put-object",
            "Upload Object",
            "PUT",
            "/accounts/{account_id}/r2/buckets/{bucket_name}/objects/{object_key}",
        );
        capability.r2_private_file_upload = Some(R2PrivateFileUploadContractV1 {
            max_source_bytes: 300_000_000,
            allowed_content_types: vec!["application/json".to_owned()],
            require_if_none_match_star: true,
            read_capability_id: "r2-get-object".to_owned(),
            delete_capability_id: "r2-delete-object".to_owned(),
            etag_algorithm: "md5".to_owned(),
        });
        let input = CallInput {
            selectors: json!({
                "Content-Type":"application/json",
                "Content-Length":"1"
            }),
            if_none_match: Some("*".to_owned()),
            ..CallInput::default()
        };
        let error = prepare_plan_target(
            &store,
            &MemorySecretStore::default(),
            &capability,
            &input,
            &source,
        )
        .expect_err("caller-provided content length must fail");
        assert!(error.to_string().contains("Content-Length is derived"));
    }
}
