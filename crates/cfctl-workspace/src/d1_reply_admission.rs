use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path, PathBuf},
};

use cfctl_core::{
    AdapterStatus, BillingModelV1, CapabilityAuthorityScopeV1, CapabilityV1, CostExposureV1,
    CostV1, EffectClass, EntitlementV1, Maturity, RiskClass, RollbackSpecV1, SelectorV1,
    VerificationSpecV1, WorkspaceD1ReplyAdmissionContractV1,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::{Result, WorkspaceError, git_blob, git_optional};

const PACK_RELATIVE_PATH: &str = ".cfctl/operations/d1-reply-admission.toml";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pack {
    schema_version: u8,
    operation: Vec<Operation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Operation {
    id: String,
    title: String,
    description: String,
    compiler_path: String,
    compiler_sha256: String,
    compiler_runtime: String,
    compiler_runtime_version: String,
    compiler_runtime_sha256: String,
    config_template: String,
    production_config: String,
    database_binding: String,
    wrangler_version: String,
    admission_table: String,
    input_contract: String,
    mutation_projection: Option<String>,
    projection: Option<String>,
    #[serde(default)]
    parameters: Vec<String>,
    caller_sql_allowed: bool,
    performs_on_call: Option<bool>,
    provider_output_retained: bool,
    body_returned: bool,
    recovery_capability_id: Option<String>,
    recovery_max_age_seconds: Option<u64>,
    rollback_capability_id: Option<String>,
}

pub fn load_workspace_d1_reply_admission_capability(
    roots: &[PathBuf],
    capability_id: &str,
) -> Result<Option<CapabilityV1>> {
    load_selected(&super::operation_identity::discover(roots)?, capability_id)
}

#[expect(
    clippy::too_many_lines,
    reason = "one loader binds the exact clean repository, operation pack, compiler, runtime, config, and closed capability variant"
)]
pub(super) fn load_selected(
    candidates: &[PathBuf],
    capability_id: &str,
) -> Result<Option<CapabilityV1>> {
    let repositories =
        super::operation_identity::select(candidates, PACK_RELATIVE_PATH, capability_id)?;
    let mut matches = Vec::new();
    for repository in &repositories {
        if !super::operation_identity::contains(
            &repository.path,
            PACK_RELATIVE_PATH,
            capability_id,
        )? {
            continue;
        }
        if repository.git.dirty {
            return Err(invariant(format!(
                "reply-admission operation repository `{}` must be clean",
                repository.path.display()
            )));
        }
        let head = repository
            .git
            .head
            .as_deref()
            .filter(|v| lower_hex(v, 40))
            .ok_or_else(|| {
                invariant("reply-admission operation repository has no canonical HEAD")
            })?;
        let origin = git_optional(&repository.path, &["config", "--get", "remote.origin.url"])?
            .filter(|v| !v.is_empty())
            .ok_or_else(|| invariant("reply-admission operation repository has no origin"))?;
        let pack_bytes = committed_file(&repository.path, Path::new(PACK_RELATIVE_PATH))?;
        let pack: Pack = toml::from_str(
            std::str::from_utf8(&pack_bytes)
                .map_err(|_| invariant("reply-admission operation pack is not UTF-8"))?,
        )
        .map_err(|e| invariant(format!("reply-admission operation pack is invalid: {e}")))?;
        if pack.schema_version != 1 {
            return Err(invariant(
                "reply-admission operation pack schema version is unsupported",
            ));
        }
        if pack
            .operation
            .iter()
            .map(|o| o.id.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            != pack.operation.len()
        {
            return Err(invariant(
                "reply-admission operation pack contains duplicate ids",
            ));
        }
        let Some(operation) = pack.operation.iter().find(|o| o.id == capability_id) else {
            continue;
        };
        validate(operation)?;
        let template_path = safe_relative(&operation.config_template)?;
        let template = committed_file(&repository.path, &template_path)?;
        let compiler_path = safe_relative(&operation.compiler_path)?;
        let compiler = committed_file(&repository.path, &compiler_path)?;
        if operation.compiler_sha256 != sha256(&compiler) {
            return Err(invariant(
                "reply-admission compiler bytes do not match the declared SHA-256",
            ));
        }
        let production = safe_relative(&operation.production_config)?;
        let contract = WorkspaceD1ReplyAdmissionContractV1 {
            operation_kind: if operation.id == "star-maildesk-cf.reply-admission-activate" {
                "activate"
            } else {
                "read"
            }
            .to_owned(),
            repository_root: repository.path.display().to_string(),
            repository_head: head.to_owned(),
            repository_origin: origin,
            operation_pack_path: PACK_RELATIVE_PATH.to_owned(),
            operation_pack_sha256: sha256(&pack_bytes),
            compiler_path: operation.compiler_path.clone(),
            compiler_sha256: operation.compiler_sha256.clone(),
            compiler_runtime: operation.compiler_runtime.clone(),
            compiler_runtime_version: operation.compiler_runtime_version.clone(),
            compiler_runtime_sha256: operation.compiler_runtime_sha256.clone(),
            config_template_path: operation.config_template.clone(),
            config_template_sha256: sha256(&template),
            production_config_path: production.display().to_string(),
            database_binding: operation.database_binding.clone(),
            wrangler_version: operation.wrangler_version.clone(),
            admission_table: operation.admission_table.clone(),
            input_contract: operation.input_contract.clone(),
            mutation_projection: operation.mutation_projection.clone().unwrap_or_default(),
            read_projection: operation.projection.clone(),
            read_parameters: operation.parameters.clone(),
            recovery_capability_id: operation.recovery_capability_id.clone().unwrap_or_default(),
            recovery_max_age_seconds: operation.recovery_max_age_seconds.unwrap_or_default(),
            rollback_capability_id: operation.rollback_capability_id.clone().unwrap_or_default(),
        };
        matches.push(capability(operation, contract));
    }
    match matches.len() {
        0 => Ok(None),
        1 => Ok(matches.pop()),
        n => Err(invariant(format!(
            "workspace operation id `{capability_id}` is ambiguous across {n} registered repositories"
        ))),
    }
}

fn validate(o: &Operation) -> Result<()> {
    let common = o.title.trim().is_empty()
        || o.description.trim().is_empty()
        || !identifier(&o.database_binding)
        || !identifier(&o.admission_table)
        || !version(&o.wrangler_version)
        || !is_sha256(&o.compiler_sha256)
        || o.compiler_runtime != "bun"
        || !version(&o.compiler_runtime_version)
        || !is_sha256(&o.compiler_runtime_sha256)
        || o.input_contract != "maildesk_reply_admission_compiler_input_v1"
        || o.caller_sql_allowed
        || o.provider_output_retained
        || o.body_returned;
    let exact = match o.id.as_str() {
        "star-maildesk-cf.reply-admission-activate" => {
            o.mutation_projection.as_deref() == Some("maildesk_reply_admission_insert_v1")
                && o.projection.is_none()
                && o.parameters.is_empty()
                && o.performs_on_call == Some(false)
                && o.recovery_capability_id.as_deref() == Some("d1-time-travel-get-bookmark")
                && o.recovery_max_age_seconds
                    .is_some_and(|age| (1..=600).contains(&age))
                && o.rollback_capability_id.as_deref() == Some("d1-restore-exact-bookmark")
        }
        "star-maildesk-cf.reply-admission-read" => {
            o.mutation_projection.is_none()
                && o.projection.as_deref() == Some("maildesk_reply_admission_read_v1")
                && o.parameters
                    == [
                        "transaction_sha256",
                        "activation_record_sha256",
                        "pre_send_identity_projection_sha256",
                        "activation_operation_id",
                    ]
                && o.performs_on_call.is_none()
                && o.recovery_capability_id.is_none()
                && o.recovery_max_age_seconds.is_none()
                && o.rollback_capability_id.is_none()
        }
        _ => false,
    };
    if common || !exact {
        return Err(invariant(
            "reply-admission operation declaration is invalid",
        ));
    }
    Ok(())
}

fn capability(o: &Operation, contract: WorkspaceD1ReplyAdmissionContractV1) -> CapabilityV1 {
    if o.id == "star-maildesk-cf.reply-admission-read" {
        return read_capability(o, contract);
    }
    let mut c = CapabilityV1::new(
        &o.id,
        &o.title,
        "POST",
        "wrangler d1 execute --file <private-stage>",
    );
    c.description = Some(o.description.clone());
    c.authority_scope = Some(CapabilityAuthorityScopeV1::WorkspaceOwned);
    "D1".clone_into(&mut c.product);
    "workspace-operation-pack-v1".clone_into(&mut c.source);
    "account".clone_into(&mut c.account_scope);
    c.selectors = ["account_id", "database_id", "config"]
        .into_iter()
        .map(|name| SelectorV1 {
            name: name.to_owned(),
            location: if name == "config" { "query" } else { "path" }.to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        })
        .collect();
    c.permissions = vec!["D1 Read".to_owned(), "D1 Write".to_owned()];
    c.mutating = true;
    c.risk = RiskClass::ScopedWrite;
    c.effect = EffectClass::DataWrite;
    c.maturity = Maturity::GenerallyAvailable;
    c.entitlement = EntitlementV1 {
        available: Some(true),
        source: Some(
            "workspace operation requires an existing provider-read D1 database".to_owned(),
        ),
        ..EntitlementV1::default()
    };
    c.cost = CostV1 {
        incremental: false,
        currency: None,
        maximum: None,
        basis: Some("bounded D1 row write".to_owned()),
        known: true,
        billing_model: BillingModelV1::UsageBased,
        exposure: CostExposureV1::DownstreamUsage,
        references: vec![],
    };
    c.verification = VerificationSpecV1 {
        required: true,
        strategy: "workspace_d1_reply_admission_exact_readback".to_owned(),
    };
    c.rollback = RollbackSpecV1 { supported: false, strategy: None, warning: Some("automatic replay and rollback are forbidden; use the separately approved exact recovery bookmark".to_owned()) };
    c.adapter_status = AdapterStatus::DelegatedCli;
    c.blocked_reason = None;
    c.workspace_d1_reply_admission = Some(contract);
    c
}

fn read_capability(o: &Operation, contract: WorkspaceD1ReplyAdmissionContractV1) -> CapabilityV1 {
    let mut c = CapabilityV1::new(
        &o.id,
        &o.title,
        "GET",
        "wrangler d1 execute [workspace-fixed-reply-admission-read]",
    );
    c.description = Some(o.description.clone());
    c.authority_scope = Some(CapabilityAuthorityScopeV1::WorkspaceOwned);
    "D1".clone_into(&mut c.product);
    "workspace-operation-pack-v1".clone_into(&mut c.source);
    "account".clone_into(&mut c.account_scope);
    c.selectors = ["account_id", "database_id", "config"]
        .into_iter()
        .chain(o.parameters.iter().map(String::as_str))
        .map(|name| SelectorV1 {
            name: name.to_owned(),
            location: if name == "config" || o.parameters.iter().any(|parameter| parameter == name)
            {
                "query"
            } else {
                "path"
            }
            .to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        })
        .collect();
    c.permissions = vec!["D1 Read".to_owned()];
    c.mutating = false;
    c.risk = RiskClass::Read;
    c.effect = EffectClass::ReadOnly;
    c.maturity = Maturity::GenerallyAvailable;
    c.entitlement = EntitlementV1 {
        available: Some(true),
        source: Some(
            "workspace operation requires an existing provider-read D1 database".to_owned(),
        ),
        ..EntitlementV1::default()
    };
    c.cost = CostV1 {
        incremental: false,
        currency: None,
        maximum: None,
        basis: Some("one fixed bounded D1 reply-admission projection".to_owned()),
        known: true,
        billing_model: BillingModelV1::UsageBased,
        exposure: CostExposureV1::DownstreamUsage,
        references: vec![],
    };
    c.verification = VerificationSpecV1 {
        required: true,
        strategy: "workspace_d1_reply_admission_body_free_read".to_owned(),
    };
    c.rollback = RollbackSpecV1 {
        supported: false,
        strategy: None,
        warning: None,
    };
    c.adapter_status = AdapterStatus::DelegatedCli;
    c.workspace_d1_reply_admission = Some(contract);
    c
}

fn committed_file(root: &Path, relative: &Path) -> Result<Vec<u8>> {
    let relative = safe_relative(relative.to_string_lossy().as_ref())?;
    reject_symlinks(root, &relative)?;
    let bytes =
        fs::read(root.join(&relative)).map_err(|e| super::io_error(&root.join(&relative), e))?;
    let committed = git_blob(root, &relative)?
        .ok_or_else(|| invariant("reply-admission operation input is not tracked at HEAD"))?;
    if bytes != committed {
        return Err(invariant(
            "reply-admission operation input differs from HEAD",
        ));
    }
    Ok(bytes)
}
fn reject_symlinks(root: &Path, relative: &Path) -> Result<()> {
    let mut p = root.to_path_buf();
    for c in relative.components() {
        p.push(c);
        if fs::symlink_metadata(&p)
            .map_err(|e| super::io_error(&p, e))?
            .file_type()
            .is_symlink()
        {
            return Err(invariant(
                "reply-admission operation input contains a symlink",
            ));
        }
    }
    Ok(())
}
fn safe_relative(v: &str) -> Result<PathBuf> {
    let p = PathBuf::from(v);
    if v.is_empty()
        || p.is_absolute()
        || p.components().any(|c| {
            matches!(
                c,
                Component::ParentDir
                    | Component::CurDir
                    | Component::RootDir
                    | Component::Prefix(_)
            )
        })
    {
        Err(invariant(
            "reply-admission operation paths must be normalized and relative",
        ))
    } else {
        Ok(p)
    }
}
fn identifier(v: &str) -> bool {
    (1..=128).contains(&v.len())
        && v.bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
fn version(v: &str) -> bool {
    let p = v.split('.').collect::<Vec<_>>();
    p.len() == 3
        && p.iter()
            .all(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
}
fn lower_hex(v: &str, n: usize) -> bool {
    v.len() == n
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn sha256(b: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(b)))
}
fn is_sha256(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|digest| lower_hex(digest, 64))
}
fn invariant(m: impl Into<String>) -> WorkspaceError {
    WorkspaceError::DiscoveryInvariant(m.into())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::{fs, process::Command};

    use tempfile::TempDir;

    use super::*;

    fn git(root: &Path, arguments: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(arguments)
            .status()
            .expect("git command");
        assert!(status.success());
    }

    fn fixture() -> TempDir {
        let root = tempfile::tempdir().expect("temp repository");
        git(root.path(), &["init", "-q"]);
        git(root.path(), &["config", "user.email", "test@example.com"]);
        git(root.path(), &["config", "user.name", "Test"]);
        git(
            root.path(),
            &[
                "remote",
                "add",
                "origin",
                "https://example.com/star-maildesk-cf.git",
            ],
        );
        fs::create_dir_all(root.path().join(".cfctl/operations")).expect("pack dir");
        fs::create_dir_all(root.path().join("scripts")).expect("scripts dir");
        let compiler = b"export const contract = 'maildesk_reply_admission_compiler_input_v1';\n";
        fs::write(
            root.path().join("scripts/reply-admission-receipt.ts"),
            compiler,
        )
        .expect("compiler");
        fs::write(
            root.path().join("wrangler.toml"),
            "name = \"template\"\n[[d1_databases]]\nbinding = \"DB\"\ndatabase_name = \"template-db\"\ndatabase_id = \"00000000-0000-0000-0000-000000000000\"\n",
        )
        .expect("config");
        fs::write(
            root.path().join(PACK_RELATIVE_PATH),
            format!(
                "schema_version = 1\n\n[[operation]]\nid = \"star-maildesk-cf.reply-admission-activate\"\ntitle = \"Activate one Maildesk reply admission\"\ndescription = \"Create one PlanV2 for one compiler-owned admission.\"\ncompiler_path = \"scripts/reply-admission-receipt.ts\"\ncompiler_sha256 = \"{}\"\ncompiler_runtime = \"bun\"\ncompiler_runtime_version = \"1.3.14\"\ncompiler_runtime_sha256 = \"sha256:{}\"\nconfig_template = \"wrangler.toml\"\nproduction_config = \"wrangler.production.toml\"\ndatabase_binding = \"DB\"\nwrangler_version = \"4.120.1\"\nadmission_table = \"reply_admissions\"\ninput_contract = \"maildesk_reply_admission_compiler_input_v1\"\nmutation_projection = \"maildesk_reply_admission_insert_v1\"\ncaller_sql_allowed = false\nperforms_on_call = false\nprovider_output_retained = false\nbody_returned = false\nrecovery_capability_id = \"d1-time-travel-get-bookmark\"\nrecovery_max_age_seconds = 600\nrollback_capability_id = \"d1-restore-exact-bookmark\"\n\n[[operation]]\nid = \"star-maildesk-cf.reply-admission-read\"\ntitle = \"Read one Maildesk reply admission\"\ndescription = \"Return one exact body-free active reply admission.\"\ncompiler_path = \"scripts/reply-admission-receipt.ts\"\ncompiler_sha256 = \"{}\"\ncompiler_runtime = \"bun\"\ncompiler_runtime_version = \"1.3.14\"\ncompiler_runtime_sha256 = \"sha256:{}\"\nconfig_template = \"wrangler.toml\"\nproduction_config = \"wrangler.production.toml\"\ndatabase_binding = \"DB\"\nwrangler_version = \"4.120.1\"\nadmission_table = \"reply_admissions\"\ninput_contract = \"maildesk_reply_admission_compiler_input_v1\"\nprojection = \"maildesk_reply_admission_read_v1\"\nparameters = [\"transaction_sha256\", \"activation_record_sha256\", \"pre_send_identity_projection_sha256\", \"activation_operation_id\"]\ncaller_sql_allowed = false\nprovider_output_retained = false\nbody_returned = false\n",
                sha256(compiler),
                "1".repeat(64),
                sha256(compiler),
                "1".repeat(64),
            ),
        )
        .expect("pack");
        git(root.path(), &["add", "."]);
        git(root.path(), &["commit", "-qm", "fixture"]);
        root
    }

    #[test]
    fn loads_one_closed_plan_v2_reply_admission() {
        let root = fixture();
        let capability = load_workspace_d1_reply_admission_capability(
            &[root.path().to_path_buf()],
            "star-maildesk-cf.reply-admission-activate",
        )
        .expect("load")
        .expect("capability");
        assert!(capability.mutating);
        assert_eq!(capability.effect, EffectClass::DataWrite);
        assert!(capability.verification_contract_supported());
        let contract = capability
            .workspace_d1_reply_admission
            .expect("reply-admission contract");
        assert_eq!(contract.admission_table, "reply_admissions");
        assert_eq!(
            contract.input_contract,
            "maildesk_reply_admission_compiler_input_v1"
        );
    }

    #[test]
    fn loads_one_closed_body_free_reply_admission_read() {
        let root = fixture();
        let capability = load_workspace_d1_reply_admission_capability(
            &[root.path().to_path_buf()],
            "star-maildesk-cf.reply-admission-read",
        )
        .expect("load")
        .expect("capability");
        assert!(!capability.mutating);
        assert_eq!(capability.effect, EffectClass::ReadOnly);
        assert_eq!(capability.permissions, ["D1 Read"]);
        assert!(capability.request_schema.is_none());
        assert!(capability.mutation_contract_gaps().is_empty());
        let contract = capability
            .workspace_d1_reply_admission
            .expect("reply-admission read contract");
        assert_eq!(contract.operation_kind, "read");
        assert_eq!(
            contract.read_projection.as_deref(),
            Some("maildesk_reply_admission_read_v1")
        );
        assert_eq!(
            contract.read_parameters,
            [
                "transaction_sha256",
                "activation_record_sha256",
                "pre_send_identity_projection_sha256",
                "activation_operation_id",
            ]
        );
    }

    #[test]
    fn dirty_unknown_and_compiler_drift_fail_closed() {
        let root = fixture();
        fs::write(root.path().join("untracked"), "dirty").expect("dirty file");
        let error = load_workspace_d1_reply_admission_capability(
            &[root.path().to_path_buf()],
            "star-maildesk-cf.reply-admission-activate",
        )
        .expect_err("dirty authority");
        assert!(error.to_string().contains("must be clean"));

        let root = fixture();
        let pack = root.path().join(PACK_RELATIVE_PATH);
        let mut declaration = fs::read_to_string(&pack).expect("pack");
        declaration.push_str("sql = \"DELETE FROM reply_admissions\"\n");
        fs::write(&pack, declaration).expect("smuggled field");
        git(root.path(), &["add", "."]);
        git(root.path(), &["commit", "-qm", "smuggle caller SQL"]);
        let error = load_workspace_d1_reply_admission_capability(
            &[root.path().to_path_buf()],
            "star-maildesk-cf.reply-admission-activate",
        )
        .expect_err("unknown field");
        assert!(error.to_string().contains("unknown field"));

        let root = fixture();
        fs::write(
            root.path().join("scripts/reply-admission-receipt.ts"),
            "drifted compiler\n",
        )
        .expect("compiler drift");
        git(root.path(), &["add", "."]);
        git(root.path(), &["commit", "-qm", "drift compiler"]);
        let error = load_workspace_d1_reply_admission_capability(
            &[root.path().to_path_buf()],
            "star-maildesk-cf.reply-admission-activate",
        )
        .expect_err("compiler hash drift");
        assert!(error.to_string().contains("compiler bytes"));
    }
}
