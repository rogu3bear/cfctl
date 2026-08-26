use std::{fs, path::PathBuf};

use cfctl_core::{
    AdapterStatus, BillingModelV1, CapabilityAuthorityScopeV1, CapabilityV1, CostExposureV1,
    CostV1, EffectClass, EntitlementV1, Maturity, RiskClass, RollbackSpecV1, SelectorV1,
    VerificationSpecV1, WorkspaceReplySubdomainIngressContractV1,
};
use sha2::{Digest, Sha256};

use super::{RegisteredRoot, Result, WorkspaceError, WorkspaceGraph, git_blob, git_optional};

pub const CAPABILITY_ID: &str = "star-maildesk-cf.reply-subdomain-ingress-read";
pub const ACTIVATE_CAPABILITY_ID: &str = "star-maildesk-cf.reply-subdomain-ingress-activate";
pub const PROJECTION: &str = "workspace_reply_subdomain_ingress_v1";
const SURFACE_PATH: &str = "ops/cfctl/maildesk-cf.surface.md";
const CONSUMER_PATH: &str = "scripts/maildesk-control-plane-capabilities.ts";

pub fn load_workspace_reply_subdomain_ingress_capability(
    roots: &[PathBuf],
    capability_id: &str,
) -> Result<Option<CapabilityV1>> {
    if !matches!(capability_id, CAPABILITY_ID | ACTIVATE_CAPABILITY_ID) {
        return Ok(None);
    }
    let operation_kind = if capability_id == ACTIVATE_CAPABILITY_ID {
        "activate"
    } else {
        "read"
    };
    let registered = roots
        .iter()
        .map(|path| RegisteredRoot::new(path))
        .collect::<Vec<_>>();
    let graph = WorkspaceGraph::discover(&registered)?;
    let mut matches = Vec::new();
    for repository in &graph.repositories {
        let surface_path = repository.path.join(SURFACE_PATH);
        let consumer_path = repository.path.join(CONSUMER_PATH);
        if !surface_path.is_file() || !consumer_path.is_file() {
            continue;
        }
        if repository.git.dirty {
            return Err(invariant(format!(
                "reply-subdomain ingress authority repository `{}` must be clean",
                repository.path.display()
            )));
        }
        let head = repository
            .git
            .head
            .as_deref()
            .filter(|value| lower_hex(value, 40))
            .ok_or_else(|| invariant("reply-subdomain ingress authority has no canonical HEAD"))?;
        let origin = git_optional(&repository.path, &["config", "--get", "remote.origin.url"])?
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invariant("reply-subdomain ingress authority has no origin"))?;
        let surface = committed_file(repository.path.as_path(), SURFACE_PATH)?;
        let consumer = committed_file(repository.path.as_path(), CONSUMER_PATH)?;
        validate_surface(&surface, operation_kind)?;
        validate_consumer(&consumer, operation_kind)?;
        matches.push(capability(WorkspaceReplySubdomainIngressContractV1 {
            operation_kind: operation_kind.to_owned(),
            repository_root: repository.path.display().to_string(),
            repository_head: head.to_owned(),
            repository_origin: origin,
            surface_path: SURFACE_PATH.to_owned(),
            surface_sha256: sha256(&surface),
            consumer_contract_path: CONSUMER_PATH.to_owned(),
            consumer_contract_sha256: sha256(&consumer),
            projection: PROJECTION.to_owned(),
        }));
    }
    match matches.len() {
        0 => Ok(None),
        1 => Ok(matches.pop()),
        count => Err(invariant(format!(
            "workspace operation id `{capability_id}` is ambiguous across {count} registered repositories"
        ))),
    }
}

fn capability(contract: WorkspaceReplySubdomainIngressContractV1) -> CapabilityV1 {
    if contract.operation_kind == "activate" {
        return activate_capability(contract);
    }
    let mut capability = CapabilityV1::new(
        CAPABILITY_ID,
        "Read one exact Maildesk reply-subdomain ingress",
        "GET",
        "workspace maildesk reply-subdomain ingress",
    );
    capability.description = Some(
        "Proves exact reply-subdomain DNS and the parent zone's one exact all-matcher Worker catch-all through bounded body-free reads."
            .to_owned(),
    );
    capability.authority_scope = Some(CapabilityAuthorityScopeV1::WorkspaceOwned);
    "Email Routing".clone_into(&mut capability.product);
    "workspace-maildesk-surface-v1".clone_into(&mut capability.source);
    "account".clone_into(&mut capability.account_scope);
    capability.selectors = ["account_id", "reply_domain", "worker_script_name"]
        .into_iter()
        .map(|name| SelectorV1 {
            name: name.to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        })
        .collect();
    capability.permissions = vec![
        "Zone Zone Read".to_owned(),
        "Zone Settings Read".to_owned(),
        "Email Routing Rules Read".to_owned(),
    ];
    capability.mutating = false;
    capability.risk = RiskClass::Read;
    capability.effect = EffectClass::ReadOnly;
    capability.maturity = Maturity::GenerallyAvailable;
    capability.entitlement = EntitlementV1 {
        available: Some(true),
        source: Some(
            "workspace source requires exact parent-zone resolution, exact subdomain-DNS readback, and direct parent-zone catch-all readback"
                .to_owned(),
        ),
        ..EntitlementV1::default()
    };
    capability.cost = CostV1 {
        incremental: false,
        currency: None,
        maximum: None,
        basis: Some(
            "bounded parent-zone resolution, one exact subdomain-DNS read, and one direct parent-zone catch-all read"
                .to_owned(),
        ),
        known: true,
        billing_model: BillingModelV1::None,
        exposure: CostExposureV1::None,
        references: Vec::new(),
    };
    capability.verification = VerificationSpecV1 {
        required: true,
        strategy: "workspace_reply_subdomain_ingress_body_free_read".to_owned(),
    };
    capability.rollback = RollbackSpecV1 {
        supported: false,
        strategy: None,
        warning: None,
    };
    capability.adapter_status = AdapterStatus::DelegatedCli;
    capability.workspace_reply_subdomain_ingress = Some(contract);
    capability
}

fn activate_capability(contract: WorkspaceReplySubdomainIngressContractV1) -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        ACTIVATE_CAPABILITY_ID,
        "Activate one exact Maildesk reply-subdomain ingress",
        "POST",
        "workspace maildesk reply-subdomain ingress activation",
    );
    capability.description = Some(
        "Uses Cloudflare's account routing planner to bind one exact subdomain catch-all, creates one PlanV2, and verifies exact DNS plus the parent-zone catch-all through body-free readback."
            .to_owned(),
    );
    capability.authority_scope = Some(CapabilityAuthorityScopeV1::WorkspaceOwned);
    "Email Routing".clone_into(&mut capability.product);
    "workspace-maildesk-surface-v1".clone_into(&mut capability.source);
    "account".clone_into(&mut capability.account_scope);
    capability.selectors = ["account_id", "reply_domain", "worker_script_name"]
        .into_iter()
        .map(|name| SelectorV1 {
            name: name.to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        })
        .collect();
    capability.permissions = vec![
        "Workers Scripts Read".to_owned(),
        "Email Routing Rules Read".to_owned(),
        "Email Routing Rules Write".to_owned(),
        "Zone Zone Read".to_owned(),
        "Zone Settings Read".to_owned(),
    ];
    capability.mutating = true;
    capability.risk = RiskClass::ScopedWrite;
    capability.effect = EffectClass::ReversibleWrite;
    capability.maturity = Maturity::GenerallyAvailable;
    capability.entitlement = EntitlementV1 {
        available: Some(true),
        source: Some("Cloudflare Email Routing subdomain and account-plan contracts".to_owned()),
        ..EntitlementV1::default()
    };
    capability.cost = CostV1 {
        incremental: false,
        currency: None,
        maximum: None,
        basis: Some("Email Routing rule planning and one catch-all update".to_owned()),
        known: true,
        billing_model: BillingModelV1::None,
        exposure: CostExposureV1::None,
        references: Vec::new(),
    };
    capability.verification = VerificationSpecV1 {
        required: true,
        strategy: "workspace_reply_subdomain_ingress_activation_body_free_readback".to_owned(),
    };
    capability.rollback = RollbackSpecV1 {
        supported: false,
        strategy: None,
        warning: Some(
            "On ambiguous apply or failed readback, do not replay; reconcile the exact subdomain catch-all and create a fresh explicit recovery plan."
                .to_owned(),
        ),
    };
    capability.adapter_status = AdapterStatus::DelegatedCli;
    capability.workspace_reply_subdomain_ingress = Some(contract);
    capability
}

fn validate_surface(bytes: &[u8], operation_kind: &str) -> Result<()> {
    let source = std::str::from_utf8(bytes)
        .map_err(|_| invariant("reply-subdomain ingress surface is not UTF-8"))?;
    let mut required = vec![
        CAPABILITY_ID,
        "`account_id`, `reply_domain`, and `worker_script_name`",
        PROJECTION,
        "`exact_reply_subdomain`",
        "`parent_zone_catch_all_to_worker_covering_exact_reply_subdomain`",
        "`provider_output_retained:false`",
        "`body_returned:false`",
    ];
    if operation_kind == "activate" {
        required.extend([
            ACTIVATE_CAPABILITY_ID,
            "`plan_v2_required`",
            "`account_plan_exactly_one_non_destructive_change`",
        ]);
    }
    for required in required {
        if !source.contains(required) {
            return Err(invariant(format!(
                "reply-subdomain ingress surface omitted `{required}`"
            )));
        }
    }
    Ok(())
}

fn validate_consumer(bytes: &[u8], operation_kind: &str) -> Result<()> {
    let source = std::str::from_utf8(bytes)
        .map_err(|_| invariant("reply-subdomain ingress consumer contract is not UTF-8"))?;
    if !source.contains(CAPABILITY_ID)
        || !source.contains(PROJECTION)
        || (operation_kind == "activate" && !source.contains(ACTIVATE_CAPABILITY_ID))
    {
        return Err(invariant(
            "reply-subdomain ingress consumer does not name the exact capability and projection",
        ));
    }
    Ok(())
}

fn committed_file(root: &std::path::Path, relative: &str) -> Result<Vec<u8>> {
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path).map_err(|error| super::io_error(&path, error))?;
    if metadata.file_type().is_symlink() {
        return Err(invariant(
            "reply-subdomain ingress authority input cannot be a symlink",
        ));
    }
    let bytes = fs::read(&path).map_err(|error| super::io_error(&path, error))?;
    let committed = git_blob(root, std::path::Path::new(relative))?.ok_or_else(|| {
        invariant("reply-subdomain ingress authority input is not tracked at HEAD")
    })?;
    if bytes != committed {
        return Err(invariant(
            "reply-subdomain ingress authority input differs from HEAD",
        ));
    }
    Ok(bytes)
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn invariant(message: impl Into<String>) -> WorkspaceError {
    WorkspaceError::DiscoveryInvariant(message.into())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::{fs, path::Path, process::Command};

    use tempfile::TempDir;

    use super::*;

    fn git(root: &Path, arguments: &[&str]) {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(root)
                .args(arguments)
                .status()
                .expect("git")
                .success()
        );
    }

    fn fixture() -> TempDir {
        let root = tempfile::tempdir().expect("repository");
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
        fs::create_dir_all(root.path().join("ops/cfctl")).expect("surface dir");
        fs::create_dir_all(root.path().join("scripts")).expect("scripts dir");
        fs::write(
            root.path().join(SURFACE_PATH),
            format!(
                "{CAPABILITY_ID}\n{ACTIVATE_CAPABILITY_ID}\n`account_id`, `reply_domain`, and `worker_script_name`\n{PROJECTION}\n`exact_reply_subdomain`\n`parent_zone_catch_all_to_worker_covering_exact_reply_subdomain`\n`provider_output_retained:false`\n`body_returned:false`\n`plan_v2_required`\n`account_plan_exactly_one_non_destructive_change`\n"
            ),
        )
        .expect("surface");
        fs::write(
            root.path().join(CONSUMER_PATH),
            format!("export const CAP = \"{CAPABILITY_ID}\";\nexport const ACTIVATE = \"{ACTIVATE_CAPABILITY_ID}\";\nexport const ADAPTER = \"{PROJECTION}\";\n"),
        )
        .expect("consumer");
        git(root.path(), &["add", "."]);
        git(root.path(), &["commit", "-qm", "fixture"]);
        root
    }

    #[test]
    fn loads_exact_body_free_workspace_capability() {
        let root = fixture();
        let capability = load_workspace_reply_subdomain_ingress_capability(
            &[root.path().to_path_buf()],
            CAPABILITY_ID,
        )
        .expect("load")
        .expect("capability");
        assert_eq!(
            capability.permissions,
            [
                "Zone Zone Read",
                "Zone Settings Read",
                "Email Routing Rules Read"
            ]
        );
        assert!(!capability.mutating);
        assert_eq!(capability.effect, EffectClass::ReadOnly);
        assert!(capability.request_schema.is_none());
        assert!(capability.verification_contract_supported());
        assert!(
            capability
                .description
                .as_deref()
                .is_some_and(|description| description
                    .contains("parent zone's one exact all-matcher Worker catch-all"))
        );
        assert!(
            capability
                .entitlement
                .source
                .as_deref()
                .is_some_and(|source| source.contains("direct parent-zone catch-all readback"))
        );
        assert!(
            capability
                .cost
                .basis
                .as_deref()
                .is_some_and(|basis| basis.contains("one direct parent-zone catch-all read"))
        );
        assert_eq!(
            capability
                .workspace_reply_subdomain_ingress
                .expect("contract")
                .projection,
            PROJECTION
        );
    }

    #[test]
    fn loads_exact_plan_v2_activation_capability() {
        let root = fixture();
        let capability = load_workspace_reply_subdomain_ingress_capability(
            &[root.path().to_path_buf()],
            ACTIVATE_CAPABILITY_ID,
        )
        .expect("load")
        .expect("capability");
        assert_eq!(
            capability.permissions,
            [
                "Workers Scripts Read",
                "Email Routing Rules Read",
                "Email Routing Rules Write",
                "Zone Zone Read",
                "Zone Settings Read",
            ]
        );
        assert!(capability.mutating);
        assert_eq!(capability.effect, EffectClass::ReversibleWrite);
        assert_eq!(capability.adapter_status, AdapterStatus::DelegatedCli);
        assert_eq!(
            capability
                .workspace_reply_subdomain_ingress
                .as_ref()
                .expect("contract")
                .operation_kind,
            "activate"
        );
        assert!(capability.verification_contract_supported());
        assert!(capability.mutation_contract_gaps().is_empty());
        assert!(
            capability
                .description
                .as_deref()
                .is_some_and(|description| description
                    .contains("parent-zone catch-all through body-free readback"))
        );
    }

    #[test]
    fn dirty_or_drifted_authority_fails_closed() {
        let root = fixture();
        fs::write(root.path().join("untracked"), "dirty").expect("dirty");
        let error = load_workspace_reply_subdomain_ingress_capability(
            &[root.path().to_path_buf()],
            CAPABILITY_ID,
        )
        .expect_err("dirty authority");
        assert!(error.to_string().contains("must be clean"));

        let root = fixture();
        fs::write(root.path().join(CONSUMER_PATH), "export const OTHER = 1;\n").expect("drift");
        git(root.path(), &["add", "."]);
        git(root.path(), &["commit", "-qm", "drift"]);
        let error = load_workspace_reply_subdomain_ingress_capability(
            &[root.path().to_path_buf()],
            CAPABILITY_ID,
        )
        .expect_err("consumer drift");
        assert!(error.to_string().contains("consumer"));
    }
}
