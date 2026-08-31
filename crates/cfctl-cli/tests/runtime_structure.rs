use std::{collections::BTreeSet, fs, path::Path};

const RUNTIME_SOURCE_LINE_CEILING: usize = 2_000;
const RUNTIME_FACADE_LINE_CEILING: usize = 650;

fn collect_rust_sources(path: &Path, sources: &mut Vec<std::path::PathBuf>) {
    if path.is_file() {
        if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push(path.to_owned());
        }
        return;
    }

    let mut entries = fs::read_dir(path)
        .unwrap_or_else(|error| panic!("read runtime source directory {}: {error}", path.display()))
        .map(|entry| match entry {
            Ok(entry) => entry.path(),
            Err(error) => panic!("read runtime source entry in {}: {error}", path.display()),
        })
        .collect::<Vec<_>>();
    entries.sort();
    for entry in entries {
        collect_rust_sources(&entry, sources);
    }
}

#[test]
fn runtime_sources_stay_below_the_decomposition_ceiling() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut sources = vec![manifest.join("src/runtime.rs")];
    collect_rust_sources(&manifest.join("src/runtime"), &mut sources);

    let oversized = sources
        .into_iter()
        .filter_map(|source| {
            let contents = fs::read_to_string(&source).unwrap_or_else(|error| {
                panic!("read runtime source {}: {error}", source.display())
            });
            let lines = contents.lines().count();
            (lines > RUNTIME_SOURCE_LINE_CEILING).then_some((source, lines))
        })
        .collect::<Vec<_>>();

    assert!(
        oversized.is_empty(),
        "runtime modules should aim for about 1,500 lines and must not exceed {RUNTIME_SOURCE_LINE_CEILING}: {oversized:#?}"
    );
}

#[test]
fn runtime_facade_stays_thin() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/runtime.rs");
    let contents = fs::read_to_string(&source)
        .unwrap_or_else(|error| panic!("read runtime facade {}: {error}", source.display()));
    let lines = contents.lines().count();
    assert!(
        lines <= RUNTIME_FACADE_LINE_CEILING,
        "runtime facade must stay at or below {RUNTIME_FACADE_LINE_CEILING} lines; found {lines}"
    );
}

fn is_test_source(runtime: &Path, source: &Path) -> bool {
    let relative = source.strip_prefix(runtime).unwrap_or_else(|error| {
        panic!("runtime source {} escaped root: {error}", source.display())
    });
    relative
        .components()
        .any(|component| component.as_os_str() == "tests")
        || relative.file_name().is_some_and(|name| name == "tests.rs")
}

fn starts_use_item(line: &str) -> bool {
    let line = line.trim_start();
    if line.starts_with("use ") {
        return true;
    }
    let Some(visibility) = line.strip_prefix("pub") else {
        return false;
    };
    if let Some(rest) = visibility.strip_prefix(' ') {
        return rest.starts_with("use ");
    }
    let Some(rest) = visibility.strip_prefix('(') else {
        return false;
    };
    let Some((_, rest)) = rest.split_once(')') else {
        return false;
    };
    rest.trim_start().starts_with("use ")
}

fn use_items(contents: &str) -> Vec<(usize, String)> {
    let mut items = Vec::new();
    let mut current = None::<(usize, String)>;
    for (index, line) in contents.lines().enumerate() {
        if let Some((start, item)) = current.as_mut() {
            item.push('\n');
            item.push_str(line);
            if line.contains(';') {
                items.push((*start, std::mem::take(item)));
                current = None;
            }
            continue;
        }
        if !starts_use_item(line) {
            continue;
        }
        if line.contains(';') {
            items.push((index + 1, line.to_owned()));
        } else {
            current = Some((index + 1, line.to_owned()));
        }
    }
    assert!(
        current.is_none(),
        "unterminated use item in inspected source"
    );
    items
}

fn normalize_use_item(item: &str) -> String {
    item.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn wildcard_use_items(contents: &str) -> Vec<(usize, String)> {
    use_items(contents)
        .into_iter()
        .filter(|(_, item)| item.contains('*'))
        .collect()
}

#[test]
fn production_runtime_dependencies_are_explicit() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let runtime = manifest.join("src/runtime");
    let facade = manifest.join("src/runtime.rs");
    let mut sources = vec![facade.clone()];
    collect_rust_sources(&runtime, &mut sources);

    let mut violations = Vec::new();
    for source in sources {
        if source != facade && is_test_source(&runtime, &source) {
            continue;
        }
        let contents = fs::read_to_string(&source)
            .unwrap_or_else(|error| panic!("read runtime source {}: {error}", source.display()));
        for (line, item) in wildcard_use_items(&contents) {
            violations.push(format!(
                "{}:{line} wildcard import `{}`",
                source.display(),
                normalize_use_item(&item)
            ));
        }
        let normalized = contents
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        let lint_contract = "#![deny(clippy::wildcard_imports)]";
        if source == facade && !normalized.contains(lint_contract) {
            violations.push(format!(
                "{} does not deny clippy::wildcard_imports for production modules",
                source.display()
            ));
        }
        let lint_mentions = if source == facade {
            normalized.replacen(lint_contract, "", 1)
        } else {
            normalized
        };
        if lint_mentions.contains("clippy::wildcard_imports") {
            violations.push(format!(
                "{} contains an additional wildcard-import lint level",
                source.display()
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "production runtime dependencies must name their owners explicitly: {violations:#?}"
    );
}

#[test]
fn wildcard_detector_covers_multiline_and_visibility_qualified_imports() {
    let fixture = r"
use a_long_module_path::{
    ExplicitType,
    *,
};
pub(super) use an_owner::*;
pub(crate) use explicit::{One, Two};
";
    let violations = wildcard_use_items(fixture);
    assert_eq!(violations.len(), 2, "fixture violations: {violations:#?}");
    assert_eq!(violations[0].0, 2);
    assert_eq!(violations[1].0, 6);
}

const ALLOWED_PRELUDE_IMPORTS: &str = r"
pub(super) use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::OsString,
    fs,
    fs::OpenOptions,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command as StdCommand, Stdio},
    time::Duration,
};
pub(super) use cfctl_agent::{AgentKind, AgentLauncher, InstallMode, InvocationContext};
pub(super) use cfctl_auth::{
    AuthCredential, EvidenceKeyManager, EvidenceKeyStatusV1, EvidenceMacProvider,
    ManagedApiTokenV1, OAuthClientConfig, PkceSession, PlatformSecretStore, ProfileKind,
    ProfileMetadata, SecretBackend, SecretStore,
};
pub(super) use cfctl_catalog::{CatalogIndex, CatalogSnapshot, OfficialTextFeedsV1};
pub(super) use cfctl_cloudflare::{
    CallInput, CloudflareError, CloudflareResponseV1, D1ImportCheckpointV1, Executor,
    OperationVerificationV1, R2LogRetrievalCredentials, R2PrivateUploadPayload,
};
pub(super) use cfctl_core::{
    AdapterStatus, AdmissionPolicyBundleStatusV1, AdmissionPolicyBundleV1, AdmissionPolicyRuleV1,
    CapabilityGuideStageV1, CapabilityGuideV1, CapabilityV1, DesiredResourceV1, EffectClass,
    ErrorV1, EvidenceClass, EvidenceV1, GuideActionV1, GuideContractStateV1, GuideTopicDocumentV1,
    GuideTopicV1, MoneyV1, OperationalProofOutcomeV1, OperationalProofV1, OwnershipRecordV1,
    PlanPinsV2, PlanStatus, PlanV1, PlanV2, PolicyDisposition, ResourceRefV1, ResponseBodyModeV1,
    ResultEnvelopeV2, RiskClass, ScopeKindV1, ScopeRefV1, SecurityActionKindV1,
    StandingAuthorityV1, TransactionStageV1, VerificationState,
};
pub(super) use cfctl_planner::{ImpactContext, PolicyEngine};
pub(super) use cfctl_registry::{InventoryProviderV1, OperationIndexRecordV1, Registry};
pub(super) use cfctl_storage::{RuntimePaths, StateStore, StoredPlanRecord};
pub(super) use cfctl_workspace::{RegisteredRoot, RepositoryNode, WorkspaceGraph};
pub(super) use chrono::{DateTime, Datelike, Duration as ChronoDuration, Utc};
pub(super) use futures_util::{StreamExt, stream};
pub(super) use md5::Md5;
pub(super) use serde::Deserialize;
pub(super) use serde_json::{Map, Value, json};
pub(super) use sha2::{Digest, Sha256};
pub(super) use tokio::process::Command as ProcessCommand;
pub(super) use uuid::Uuid;
pub(super) use walkdir::WalkDir;
pub(super) use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
pub(super) use crate::{
    AdmissionPolicyCommand, AgentsCommand, AuthCommand, AuthLoginArgs, CallArgs, CatalogCommand,
    Cli, CloudflarePolicyCommand, Command, DeploymentPlanSetCommand, DocsCommand,
    EventBridgeCommand, EventHistoryArgs, EventReconcileArgs, EventsCommand, EvidenceKeyCommand,
    EvidenceKeyRetireArgs, GuideArgs, GuideTopicArg, ImportApiTokenArgs, ImportGlobalKeyArgs,
    KeyMutationArgs, KeyPermissionArgs, KeyPolicyApproveArgs, KeyPolicyCommand,
    KeyPolicyCreateArgs, KeyPolicySelector, KeyRenewAnalyticsProfileArgs, KeyRevokeArgs,
    KeyRotateArgs, KeysCommand, MigrateCommand, PlanApproveArgs, PlanSelector, PlansCommand,
    PolicyCommand, ProfileSelector, RegistryCommand, RegistryDeclarationsCommand,
    RegistryOwnershipCommand, RegistryScopeArgs, RegistryScopeKindArg, RegistryScopesCommand,
    ResolveArgs, SearchArgs, WorkspaceCommand,
    profiles::{PendingLogin, ProfilesConfig},
};
pub(super) use super::{CliError, Result};
";

fn prelude_import_delta(contents: &str) -> (Vec<String>, Vec<String>) {
    let allowed = use_items(ALLOWED_PRELUDE_IMPORTS)
        .into_iter()
        .map(|(_, item)| normalize_use_item(&item))
        .collect::<BTreeSet<_>>();
    let actual = use_items(contents)
        .into_iter()
        .map(|(_, item)| normalize_use_item(&item))
        .collect::<BTreeSet<_>>();
    let unexpected = actual.difference(&allowed).cloned().collect();
    let missing = allowed.difference(&actual).cloned().collect();
    (unexpected, missing)
}

#[test]
fn runtime_prelude_contains_only_declared_vocabulary() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/runtime/prelude.rs");
    let contents = fs::read_to_string(&source)
        .unwrap_or_else(|error| panic!("read runtime prelude {}: {error}", source.display()));
    let (unexpected, missing) = prelude_import_delta(&contents);
    assert!(
        unexpected.is_empty() && missing.is_empty(),
        "runtime prelude imports must match the declared vocabulary allowlist; unexpected: {unexpected:#?}; missing: {missing:#?}"
    );

    let injected = format!("{contents}\npub(super) use super::execute_api_plan;\n");
    let (unexpected, missing) = prelude_import_delta(&injected);
    assert_eq!(
        unexpected,
        ["pub(super)usesuper::execute_api_plan;"],
        "a new behavioral export must fail closed until explicitly admitted"
    );
    assert!(missing.is_empty());
}
