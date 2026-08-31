//! Stable runtime vocabulary shared across ownership modules.
//!
//! This module may re-export foundational types, traits, macros, and CLI input
//! structures. It must not re-export runtime behavior, domain constants,
//! command handlers, provider helpers, or plan operations: those dependencies
//! belong to their owning modules and must be imported through explicit paths.

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

#[cfg(unix)]
pub(super) use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

pub(super) use crate::{
    AdmissionPolicyCommand, AgentsCommand, AuthCommand, AuthLoginArgs, CallArgs, CatalogCommand,
    Cli, CloudflarePolicyCommand, Command, DeploymentPlanSetCommand, DocsCommand,
    EventBridgeCommand, EventHistoryArgs, EventReconcileArgs, EventsCommand, EvidenceKeyCommand,
    EvidenceKeyRecoverArgs, EvidenceKeyRecoverPlanCommand, EvidenceKeyRecoverPlanSelector,
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
