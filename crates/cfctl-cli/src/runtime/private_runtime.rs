//! One explicit fresh local authority, with pointer-last publication and no
//! inheritance of approvals, standing grants, or authenticated proof caches.
use super::{CliError, Result};
use crate::{EvidenceKeyPrivateActivateArgs, profiles::ProfilesConfig};
use cfctl_auth::{
    EvidenceMacProvider as _, ProfileKind, SecretStore as _, export_fallback_profile,
};
use cfctl_core::{AdmissionPolicyBundleV1, ResultEnvelopeV2};
use cfctl_storage::{
    ArchivedRuntimeV1, PRIVATE_MODE_FILE, PrivateDirectory, PrivateFileSecretStore, RuntimePaths,
    StateStore, open_private_control, private_control, private_epoch_paths,
    publish_private_runtime,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::{collections::BTreeMap, fs, io::Read as _, path::Path};
use uuid::Uuid;

const CONFIG_FILES: &[&str] = &[
    "profiles.json",
    "workspace-manifest-v1.json",
    "workspace-roots.json",
    "workspace-accounts.json",
];
const DATA_FILES: &[&str] = &["catalog/catalog-v1.json"];
const MAX_SOURCE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransitionPlan {
    schema_version: u8,
    plan_id: String,
    source: ArchivedRuntimeV1,
    input_digest: String,
    carried_profiles: Vec<String>,
    missing_profiles: Vec<String>,
    excluded_profiles: Vec<String>,
    unsupported_grants: Vec<String>,
    copied_files: Vec<String>,
    history: BTreeMap<String, String>,
    constraints: Option<AdmissionPolicyBundleV1>,
}

struct Snapshot {
    input_digest: String,
    files: Vec<(bool, String, Vec<u8>)>,
    secrets: Vec<(String, String)>,
    carried_profiles: Vec<String>,
    missing_profiles: Vec<String>,
    excluded_profiles: Vec<String>,
    unsupported_grants: Vec<String>,
    history: BTreeMap<String, String>,
    constraints: Option<AdmissionPolicyBundleV1>,
}

fn input(message: &str) -> CliError {
    CliError::Input(message.to_owned())
}

fn read_source(root: &Path, relative: &str) -> Result<Option<Vec<u8>>> {
    let mut path = root.to_owned();
    for component in Path::new(relative).components() {
        let std::path::Component::Normal(component) = component else {
            return Err(input("invalid transition source path"));
        };
        path.push(component);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(input("transition source contains a symbolic link"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(input("transition source cannot be inspected")),
        }
    }
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK)
                .bits()
                .cast_signed(),
        )
        .open(&path)
        .map_err(|_| input("transition source cannot be opened"))?;
    let metadata = file
        .metadata()
        .map_err(|_| input("transition source cannot be inspected"))?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
        || metadata.len() > MAX_SOURCE_BYTES
    {
        return Err(input(
            "transition source is not an owned bounded regular file",
        ));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_SOURCE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| input("transition source cannot be read"))?;
    if bytes.len() as u64 > MAX_SOURCE_BYTES {
        return Err(input("transition source exceeds its bound"));
    }
    let current =
        fs::symlink_metadata(&path).map_err(|_| input("transition source disappeared"))?;
    if current.dev() != metadata.dev() || current.ino() != metadata.ino() {
        return Err(input("transition source changed during read"));
    }
    Ok(Some(bytes))
}

fn add_digest(digest: &mut Sha256, name: &str, bytes: &[u8]) {
    digest.update((name.len() as u64).to_be_bytes());
    digest.update(name.as_bytes());
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}

fn collect_history(paths: &RuntimePaths, digest: &mut Sha256) -> Result<BTreeMap<String, String>> {
    let mut history = BTreeMap::new();
    for directory in ["plans", "plans-v2", "authorities"] {
        let path = paths.data_dir.join(directory);
        let entries = match fs::read_dir(&path) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(input("old execution history cannot be inspected")),
        };
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|_| input("old execution history cannot be listed"))?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| input("invalid historical filename"))?;
            if Path::new(&name)
                .extension()
                .is_some_and(|extension| extension == "json")
            {
                names.push(name);
            }
        }
        names.sort();
        for name in names {
            let relative = format!("{directory}/{name}");
            let bytes = read_source(&paths.data_dir, &relative)?
                .ok_or_else(|| input("old execution history changed"))?;
            add_digest(digest, &relative, &bytes);
            if directory == "authorities" {
                continue;
            }
            let value: Value = serde_json::from_slice(&bytes)?;
            let plan = value.get("plan").unwrap_or(&value);
            let status = plan
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unclassified");
            if status == "running" {
                return Err(input(
                    "a historical execution is still running; resolve it before activating a new runtime",
                ));
            }
            history.insert(name.trim_end_matches(".json").to_owned(), status.to_owned());
        }
    }
    Ok(history)
}

fn snapshot(store: &StateStore) -> Result<Snapshot> {
    let paths = store.paths();
    let mut digest = Sha256::new();
    let mut files = Vec::new();
    for (config, names) in [(true, CONFIG_FILES), (false, DATA_FILES)] {
        let root = if config {
            &paths.config_dir
        } else {
            &paths.data_dir
        };
        for name in names {
            if let Some(bytes) = read_source(root, name)? {
                add_digest(&mut digest, &format!("{config}/{name}"), &bytes);
                files.push((config, (*name).to_owned(), bytes));
            }
        }
    }
    let profiles = files
        .iter()
        .find(|(config, name, _)| *config && name == "profiles.json")
        .map(|(_, _, bytes)| serde_json::from_slice::<ProfilesConfig>(bytes))
        .transpose()?
        .unwrap_or_default();
    if !profiles.pending_logins.is_empty() {
        return Err(input(
            "pending OAuth logins must finish or be cancelled before a private transition",
        ));
    }
    let fallback_path = paths.data_dir.join("auth/secrets");
    let fallback = match fs::symlink_metadata(&fallback_path) {
        Ok(_) => Some(PrivateDirectory::open(&fallback_path)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(input("fallback credential custody cannot be inspected")),
    };
    let mut result = Snapshot {
        input_digest: String::new(),
        files,
        secrets: Vec::new(),
        carried_profiles: Vec::new(),
        missing_profiles: Vec::new(),
        excluded_profiles: Vec::new(),
        unsupported_grants: Vec::new(),
        history: BTreeMap::new(),
        constraints: None,
    };
    carry_profiles(&mut result, &profiles, fallback.as_ref(), &mut digest)?;
    result.history = collect_history(paths, &mut digest)?;
    result.constraints = snapshot_constraints(store, &mut digest)?;
    result.input_digest = hex::encode(digest.finalize());
    Ok(result)
}

fn snapshot_constraints(
    store: &StateStore,
    digest: &mut Sha256,
) -> Result<Option<AdmissionPolicyBundleV1>> {
    let Some(pointer) = read_source(&store.paths().config_dir, "policy/admission/active.json")?
    else {
        return Ok(None);
    };
    add_digest(digest, "policy/admission/active.json", &pointer);
    let bundle = store
        .active_admission_policy()?
        .ok_or_else(|| input("active restrictive policy disappeared"))?;
    let path = format!("policy/admission/bundles/{}.json", bundle.bundle_id);
    let bytes = read_source(&store.paths().config_dir, &path)?
        .ok_or_else(|| input("active restrictive policy bundle disappeared"))?;
    add_digest(digest, &path, &bytes);
    let exact: AdmissionPolicyBundleV1 = serde_json::from_slice(&bytes)?;
    exact.validate()?;
    let selected: Value = serde_json::from_slice(&pointer)?;
    if exact != bundle
        || selected.get("bundle_id").and_then(Value::as_str) != Some(bundle.bundle_id.as_str())
        || selected.get("content_hash").and_then(Value::as_str)
            != Some(bundle.content_hash.as_str())
    {
        return Err(input("active restrictive policy changed during snapshot"));
    }
    Ok(Some(bundle))
}

fn carry_profiles(
    result: &mut Snapshot,
    profiles: &ProfilesConfig,
    fallback: Option<&PrivateDirectory>,
    digest: &mut Sha256,
) -> Result<()> {
    let mut selected_profiles = profiles.clone();
    for (id, profile) in &profiles.profiles {
        if !matches!(profile.kind, ProfileKind::ApiToken | ProfileKind::OAuth)
            || profile.emergency_only
            || profile.account_id.as_ref().is_none_or(String::is_empty)
        {
            result.excluded_profiles.push(id.clone());
            selected_profiles.profiles.remove(id);
            continue;
        }
        if let Some(managed) = &profile.managed_api_token {
            result
                .unsupported_grants
                .push(format!("{id}:{}", managed.standing_authority_id));
            if managed.pending_revoke_operation_id.is_some()
                || managed.pending_revoke_token_id.is_some()
            {
                return Err(input(
                    "a profile has an unfinished token revocation; resolve it before activation",
                ));
            }
        }
        let credential = export_fallback_profile(profile, |name| {
            let bytes = fallback
                .as_ref()
                .map(|directory| directory.read(name, 4 * 1024 * 1024))
                .transpose()?
                .flatten();
            bytes
                .map(|bytes| {
                    String::from_utf8(bytes).map_err(|_| {
                        cfctl_auth::AuthError::SecretStore(
                            "fallback credential is not UTF-8".to_owned(),
                        )
                    })
                })
                .transpose()
        })?;
        if let Some((key, value)) = credential {
            add_digest(digest, &key, value.as_bytes());
            result.secrets.push((key, value));
            result.carried_profiles.push(id.clone());
        } else {
            result.missing_profiles.push(id.clone());
        }
    }
    if selected_profiles
        .current_profile
        .as_ref()
        .is_some_and(|id| !selected_profiles.profiles.contains_key(id))
    {
        selected_profiles.current_profile = None;
    }
    let profile_bytes = serde_json::to_vec_pretty(&selected_profiles)?;
    result
        .files
        .retain(|(config, name, _)| !(*config && name == "profiles.json"));
    result
        .files
        .push((true, "profiles.json".to_owned(), profile_bytes));
    Ok(())
}

fn display(plan: &TransitionPlan) -> Value {
    json!({
        "schema_version": 1, "plan_id": plan.plan_id,
        "backend": "private_file", "continuity": "unavailable_fresh_authority",
        "trust_boundary": "Files are private to this OS user. Other software running as this user can access local credentials and signing authority.",
        "carried_profile_ids": plan.carried_profiles, "missing_profile_ids": plan.missing_profiles,
        "excluded_profile_ids": plan.excluded_profiles, "unsupported_standing_authority_references": plan.unsupported_grants,
        "credential_count": plan.carried_profiles.len(), "copied_files": plan.copied_files,
        "archived_operation_count": plan.history.len(), "archive_data_dir": plan.source.data_dir,
        "restrictive_rules_to_readmit": plan.constraints.as_ref().map(|bundle| &bundle.rules),
        "old_approvals_carried": false, "old_proofs_carried": false, "old_state_preserved": true,
        "activate_command": format!("cfctl auth evidence-key private-activate {} --yes --json", plan.plan_id)
    })
}

pub(super) fn preview(store: &StateStore) -> Result<ResultEnvelopeV2> {
    if store.private_origin().is_some() {
        return Err(input("private local storage is already selected"));
    }
    let current = snapshot(store)?;
    let id = Uuid::new_v4().to_string();
    let constraints = current
        .constraints
        .as_ref()
        .map(|bundle| AdmissionPolicyBundleV1::pending(bundle.name.clone(), bundle.rules.clone()))
        .transpose()?;
    let plan = TransitionPlan {
        schema_version: 1,
        plan_id: id.clone(),
        source: ArchivedRuntimeV1 {
            schema_version: 1,
            epoch_id: id.clone(),
            config_dir: store.paths().config_dir.clone(),
            data_dir: store.paths().data_dir.clone(),
            cache_dir: store.paths().cache_dir.clone(),
            continuity: "unavailable_fresh_authority".to_owned(),
        },
        input_digest: current.input_digest,
        carried_profiles: current.carried_profiles,
        missing_profiles: current.missing_profiles,
        excluded_profiles: current.excluded_profiles,
        unsupported_grants: current.unsupported_grants,
        copied_files: current
            .files
            .iter()
            .map(|(config, name, _)| format!("{}/{name}", if *config { "config" } else { "data" }))
            .collect(),
        history: current.history,
        constraints,
    };
    open_private_control(store.paths())?
        .write(&format!("plan-{id}.json"), &serde_json::to_vec(&plan)?)?;
    Ok(ResultEnvelopeV2::success(
        "auth.evidence-key.private-preview",
        display(&plan),
    ))
}

fn create_epoch(
    paths: &RuntimePaths,
    plan: &TransitionPlan,
    current: &Snapshot,
) -> Result<StateStore> {
    let destination = private_epoch_paths(paths, &plan.plan_id)?;
    let root = destination
        .data_dir
        .parent()
        .ok_or_else(|| input("private epoch root missing"))?;
    PrivateDirectory::create(root)?;
    for directory in [
        &destination.config_dir,
        &destination.data_dir,
        &destination.cache_dir,
    ] {
        PrivateDirectory::create(directory)?;
    }
    for relative in ["private-authority", "auth", "auth/secrets", "catalog"] {
        PrivateDirectory::create(&destination.data_dir.join(relative))?;
    }
    for (config, name, bytes) in &current.files {
        let root = if *config {
            &destination.config_dir
        } else {
            &destination.data_dir
        };
        let path = root.join(name);
        let parent = path
            .parent()
            .ok_or_else(|| input("transition file parent missing"))?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| input("transition filename invalid"))?;
        PrivateDirectory::open(parent)?.write(name, bytes)?;
    }
    let secrets = PrivateFileSecretStore::new(destination.data_dir.join("auth/secrets"));
    for (key, value) in &current.secrets {
        secrets.put(key, value)?;
    }
    PrivateDirectory::open(&destination.data_dir)?
        .write(PRIVATE_MODE_FILE, &serde_json::to_vec(&plan.source)?)?;
    let epoch = StateStore::open(destination)?;
    if let Some(pending) = &plan.constraints {
        let original = current
            .constraints
            .as_ref()
            .ok_or_else(|| input("confirmed restrictive policy is missing"))?;
        if pending.rules != original.rules || pending.name != original.name {
            return Err(input("confirmed restrictive rules differ from source"));
        }
        epoch.admit_private_constraints(pending)?;
    } else if current.constraints.is_some() {
        return Err(input("restrictive source policy cannot be omitted"));
    }
    let manager = epoch.platform_evidence_key_manager()?;
    if epoch.evidence_root_identity()?.is_none() {
        super::evidence_key_commands::initialize(&epoch, &manager)?;
    }
    let marker = epoch
        .evidence_root_identity()?
        .ok_or_else(|| input("new evidence authority lacks a root marker"))?;
    let status = manager.status(Some(&marker))?;
    if !status.initialized {
        return Err(input("new evidence authority is incomplete"));
    }
    Ok(epoch)
}

pub(super) fn activate(
    store: &StateStore,
    arguments: &EvidenceKeyPrivateActivateArgs,
) -> Result<ResultEnvelopeV2> {
    if !arguments.yes {
        return Err(input(
            "private activation requires the reviewed plan and --yes",
        ));
    }
    if Uuid::parse_str(&arguments.plan_id).is_err() || arguments.plan_id.len() != 36 {
        return Err(input("invalid private transition plan identity"));
    }
    let paths = if let Some(origin) = store.private_origin() {
        if origin.epoch_id != arguments.plan_id {
            return Err(input("a different private runtime is already selected"));
        }
        return Ok(ResultEnvelopeV2::success(
            "auth.evidence-key.private-activate",
            json!({"already_active": true, "plan_id": arguments.plan_id, "backend": "private_file", "data_dir": store.paths().data_dir}),
        ));
    } else {
        store.paths()
    };
    let bytes = open_private_control(paths)?
        .read(&format!("plan-{}.json", arguments.plan_id), 4 * 1024 * 1024)?
        .ok_or_else(|| input("private transition plan does not exist"))?;
    let plan: TransitionPlan = serde_json::from_slice(&bytes)?;
    if plan.schema_version != 1
        || plan.plan_id != arguments.plan_id
        || plan.source.config_dir != paths.config_dir
        || plan.source.data_dir != paths.data_dir
        || plan.source.cache_dir != paths.cache_dir
        || plan.source.epoch_id != plan.plan_id
    {
        return Err(input("private transition plan does not match this source"));
    }
    let current = snapshot(store)?;
    if current.input_digest != plan.input_digest {
        return Err(input(
            "source profiles, credentials, configuration or history changed; prepare a new private transition",
        ));
    }
    let epoch = create_epoch(paths, &plan, &current)?;
    // The global runtime lock is held by execute throughout this transition.
    // Old executables must also be quiesced by the operator before activation.
    if snapshot(store)?.input_digest != plan.input_digest {
        return Err(input(
            "source changed before pointer publication; old runtime remains selected",
        ));
    }
    publish_private_runtime(paths, &plan.plan_id)?;
    let mut result = display(&plan);
    result["activated"] = json!(true);
    result["data_dir"] = json!(epoch.paths().data_dir);
    let mut envelope = ResultEnvelopeV2::success("auth.evidence-key.private-activate", result);
    envelope.performed = true;
    Ok(envelope)
}

pub(super) fn history(store: &StateStore) -> Result<ResultEnvelopeV2> {
    let origin = store
        .private_origin()
        .ok_or_else(|| input("no archived runtime is selected"))?;
    let paths = RuntimePaths {
        config_dir: origin.config_dir.clone(),
        data_dir: origin.data_dir.clone(),
        cache_dir: origin.cache_dir.clone(),
    };
    let bytes = PrivateDirectory::open(&private_control(&paths))?
        .read(&format!("plan-{}.json", origin.epoch_id), 4 * 1024 * 1024)?
        .ok_or_else(|| input("private transition history is unavailable"))?;
    let plan: TransitionPlan = serde_json::from_slice(&bytes)?;
    Ok(ResultEnvelopeV2::success(
        "auth.evidence-key.private-history",
        json!({"operations": plan.history, "archive_data_dir": origin.data_dir, "authority": "historical_only", "replay_permitted": false, "continuity": origin.continuity}),
    ))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use cfctl_auth::{FileSecretStore, ProfileMetadata, SecretBackend};
    use cfctl_core::EvidenceClass;
    use cfctl_storage::selected_runtime;
    use std::sync::Arc;

    fn setup() -> (tempfile::TempDir, StateStore) {
        let root = tempfile::tempdir().expect("root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("store");
        (root, store)
    }
    fn plan_id(envelope: &ResultEnvelopeV2) -> String {
        envelope.result["plan_id"]
            .as_str()
            .expect("plan id")
            .to_owned()
    }

    #[test]
    fn private_fresh_activation_restarts_with_first_credential_and_authenticated_evidence() {
        let (_root, old) = setup();
        let id = plan_id(&preview(&old).expect("preview without platform"));
        activate(
            &old,
            &EvidenceKeyPrivateActivateArgs {
                plan_id: id.clone(),
                yes: true,
            },
        )
        .expect("activate");
        assert_eq!(old.evidence_root_identity().expect("old marker"), None);
        let paths = selected_runtime(old.paths().clone()).expect("selection");
        let store = StateStore::open(paths.clone()).expect("restart");
        let secrets = super::super::credential_resolution::platform_secrets(&store);
        assert!(secrets.is_private());
        secrets
            .put("profile/first/api-token", "test-only-token")
            .expect("empty first import");
        assert_eq!(
            secrets.locate("profile/first/api-token").expect("backend"),
            Some(SecretBackend::PrivateFile)
        );
        let second = StateStore::open(paths).expect("second restart");
        assert_eq!(
            super::super::credential_resolution::platform_secrets(&second)
                .get("profile/first/api-token")
                .expect("credential"),
            Some("test-only-token".to_owned())
        );
        let manager = Arc::new(
            second
                .platform_evidence_key_manager()
                .expect("local authority"),
        );
        let qualified = second
            .with_evidence_authenticator(manager)
            .expect("qualify");
        qualified
            .write_evidence(EvidenceClass::LiveRead, &json!({"fixture": true}))
            .expect("authenticated write");
        activate(
            &qualified,
            &EvidenceKeyPrivateActivateArgs {
                plan_id: id,
                yes: true,
            },
        )
        .expect("idempotent activation");
        assert_eq!(
            super::super::health_commands::platform_secret_store_health(&qualified)
                .expect("health")["keyring"],
            "not_selected"
        );
    }

    fn profile() -> ProfileMetadata {
        serde_json::from_value(json!({"schema_version":1,"id":"ordinary","kind":"api_token","account_id":"0123456789abcdef0123456789abcdef","oauth_client_id":null,"emergency_only":false})).expect("profile")
    }

    #[test]
    fn private_activation_carries_journal_selected_profile_and_preserves_history() {
        let (_root, old) = setup();
        let mut profiles = ProfilesConfig {
            current_profile: Some("ordinary".to_owned()),
            ..ProfilesConfig::default()
        };
        profiles.profiles.insert("ordinary".to_owned(), profile());
        profiles.save(&old).expect("profiles");
        let fallback = FileSecretStore::new(old.paths().data_dir.join("auth/secrets"));
        fallback
            .put("profile/ordinary/api-token", "fixture-token")
            .expect("fallback");
        fs::write(
            old.paths()
                .data_dir
                .join("plans/11111111-1111-4111-8111-111111111111.json"),
            br#"{"status":"failed","operation_id":"11111111-1111-4111-8111-111111111111"}"#,
        )
        .expect("historical plan");
        cfctl_auth::PlatformSecretStore::new(old.paths().data_dir.join("auth/secrets"))
            .put("profile/ordinary/api-token", "fixture-journal-token")
            .expect("existing fallback selects journal without native access");
        let before = fs::read(old.paths().profiles_file()).expect("old profiles");
        let id = plan_id(&preview(&old).expect("preview"));
        activate(
            &old,
            &EvidenceKeyPrivateActivateArgs {
                plan_id: id,
                yes: true,
            },
        )
        .expect("activate");
        let new = StateStore::open(selected_runtime(old.paths().clone()).expect("select"))
            .expect("new store");
        assert_eq!(
            fs::read(old.paths().profiles_file()).expect("preserved"),
            before
        );
        assert!(
            old.paths()
                .data_dir
                .join("plans/11111111-1111-4111-8111-111111111111.json")
                .is_file()
        );
        assert!(
            !new.paths()
                .data_dir
                .join("plans/11111111-1111-4111-8111-111111111111.json")
                .exists()
        );
        assert!(
            new.load_stored_plan_record("11111111-1111-4111-8111-111111111111")
                .expect_err("history is not execution authority")
                .to_string()
                .contains("historical state")
        );
        assert!(
            new.load_stored_plan_record("22222222-2222-4222-8222-222222222222")
                .expect_err("missing remains distinct")
                .to_string()
                .contains("does not exist")
        );
        assert_eq!(
            super::super::credential_resolution::platform_secrets(&new)
                .get("profile/ordinary/api-token")
                .expect("carried credential"),
            Some("fixture-journal-token".to_owned())
        );
    }

    #[test]
    fn private_activation_rejects_drift_and_resumes_staged_authority_without_rotation() {
        let (_root, old) = setup();
        let id = plan_id(&preview(&old).expect("preview"));
        let control = open_private_control(old.paths()).expect("control");
        let plan: TransitionPlan = serde_json::from_slice(
            &control
                .read(&format!("plan-{id}.json"), 4 * 1024 * 1024)
                .expect("read")
                .expect("plan"),
        )
        .expect("decode");
        let current = snapshot(&old).expect("snapshot");
        let staged = create_epoch(old.paths(), &plan, &current).expect("stage only");
        let marker = staged.evidence_root_identity().expect("marker");
        let generation = staged
            .platform_evidence_key_manager()
            .expect("manager")
            .status(marker.as_deref())
            .expect("status")
            .active_generation_id;
        assert_eq!(
            selected_runtime(old.paths().clone()).expect("old selected"),
            *old.paths()
        );
        fs::write(old.paths().config_dir.join("workspace-roots.json"), b"[]").expect("drift");
        assert!(
            activate(
                &old,
                &EvidenceKeyPrivateActivateArgs {
                    plan_id: id.clone(),
                    yes: true
                }
            )
            .is_err()
        );
        fs::remove_file(old.paths().config_dir.join("workspace-roots.json"))
            .expect("restore fixture");
        activate(
            &old,
            &EvidenceKeyPrivateActivateArgs {
                plan_id: id,
                yes: true,
            },
        )
        .expect("resume");
        let new = StateStore::open(selected_runtime(old.paths().clone()).expect("selection"))
            .expect("open");
        assert_eq!(
            new.platform_evidence_key_manager()
                .expect("manager")
                .status(new.evidence_root_identity().expect("marker").as_deref())
                .expect("status")
                .active_generation_id,
            generation
        );
    }
    #[test]
    fn private_transition_refuses_pending_login_running_execution_and_unconfirmed_activation() {
        let (_root, store) = setup();
        let id = plan_id(&preview(&store).expect("preview"));
        assert!(
            activate(
                &store,
                &EvidenceKeyPrivateActivateArgs {
                    plan_id: id,
                    yes: false
                }
            )
            .is_err()
        );
        let mut profiles = ProfilesConfig::default();
        profiles.pending_logins.insert(
            "pending".to_owned(),
            crate::profiles::PendingLogin {
                profile_id: "pending".to_owned(),
                state: "fixture-state".to_owned(),
                client: cfctl_auth::OAuthClientConfig::cfctl_public("fixture-client"),
                scopes: Vec::new(),
                account_id: None,
            },
        );
        profiles.save(&store).expect("pending login");
        assert!(
            preview(&store)
                .expect_err("pending login refused")
                .to_string()
                .contains("pending OAuth")
        );
        profiles.pending_logins.clear();
        profiles.save(&store).expect("clear fixture");
        fs::write(
            store
                .paths()
                .data_dir
                .join("plans/11111111-1111-4111-8111-111111111111.json"),
            br#"{"status":"running"}"#,
        )
        .expect("running fixture");
        assert!(
            preview(&store)
                .expect_err("active execution refused")
                .to_string()
                .contains("still running")
        );
        assert_eq!(
            selected_runtime(store.paths().clone()).expect("old selected"),
            *store.paths()
        );
    }
    #[test]
    fn private_transition_readmits_blocking_constraints_with_fresh_approval() {
        let (_root, old) = setup();
        let rules = vec![cfctl_core::AdmissionPolicyRuleV1 {
            rule_id: "block-access".to_owned(),
            capability_id: Some("access-example".to_owned()),
            product: None,
            effect: None,
            risk: None,
            disposition: cfctl_core::PolicyDisposition::Blocked,
            reason: "operator restriction".to_owned(),
        }];
        let bundle =
            AdmissionPolicyBundleV1::pending("local restrictions", rules.clone()).expect("bundle");
        old.create_admission_bundle(&bundle).expect("create");
        old.approve_admission_bundle(&bundle.bundle_id, true)
            .expect("approve");
        let _ = old
            .activate_admission_bundle(&bundle.bundle_id)
            .expect("activate");
        let prepared = preview(&old).expect("preview");
        assert_eq!(
            prepared.result["restrictive_rules_to_readmit"],
            serde_json::to_value(&rules).expect("rules")
        );
        let id = plan_id(&prepared);
        activate(
            &old,
            &EvidenceKeyPrivateActivateArgs {
                plan_id: id,
                yes: true,
            },
        )
        .expect("private activation");
        let new = StateStore::open(selected_runtime(old.paths().clone()).expect("select"))
            .expect("new store");
        let active = new
            .active_admission_policy()
            .expect("policy")
            .expect("restriction retained");
        assert_eq!(active.rules, rules);
        assert_ne!(active.bundle_id, bundle.bundle_id);
        assert!(active.approved_at.is_some());
    }
}
