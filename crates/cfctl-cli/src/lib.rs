//! Public command contract for the cfctl v2 binary.

use std::path::PathBuf;

use cfctl_core::{RETIRED_V1_PUBLIC_VERBS, RETIRED_V1_SURFACES};
use clap::{Args, CommandFactory as _, Parser, Subcommand, ValueEnum};

pub mod build_identity;
#[doc(hidden)]
pub mod build_support;
mod command_help;
mod profiles;
pub mod runtime;
mod telemetry_product;

#[derive(Debug, Parser)]
#[command(
    name = "cfctl",
    version,
    about = "Universal governed Cloudflare control plane",
    after_help = "Learn the whole command language at once: cfctl commands"
)]
pub struct Cli {
    /// Emit the stable `ResultEnvelopeV2` JSON contract.
    #[arg(long, global = true)]
    pub json: bool,
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Print the complete command map, grammar, and memorable starting paths.
    Commands,
    /// Manage credential profiles and login state.
    Auth(AuthArgs),
    /// Inspect and govern Cloudflare token lifecycles.
    Keys(KeysArgs),
    /// Discover the executable Cloudflare capability catalog.
    Catalog(CatalogArgs),
    /// Read live state or create a mutation plan.
    Call(CallArgs),
    /// Deterministically map a natural-language intent to a capability and the
    /// exact governed commands to run. Reads only; never mutates or launches an
    /// agent; fails closed when the match is ambiguous.
    Resolve(ResolveArgs),
    /// Explain a capability lifecycle or a system-level control-plane topic.
    Guide(GuideArgs),
    /// Review, approve, run, recover, and inspect durable plans.
    Plans(PlansArgs),
    /// Stage and activate local admission policy or inspect Cloudflare policy.
    Policy(PolicyArgs),
    /// Inspect and reconcile the local Cloudflare resource registry.
    Registry(RegistryArgs),
    /// Consume durable event receipts and enqueue bounded reconciliation.
    Events(EventsArgs),
    /// Register and inspect repository impact boundaries.
    Workspace(WorkspaceArgs),
    /// Install and verify managed agent guidance.
    Agents(AgentsArgs),
    /// Search current official Cloudflare documentation and changes.
    Docs(DocsArgs),
    /// Inspect local runtime, authentication, and catalog health.
    Doctor,
    /// Report the timestamp-free binary build identity.
    Version,
    /// Check for or install a newer cfctl version.
    Update(UpdateArgs),
    /// Import explicitly supported v1 state into the v2 runtime.
    Migrate(MigrateArgs),
}

#[derive(Debug, Args)]
pub struct AuthArgs {
    #[command(subcommand)]
    pub command: AuthCommand,
}

#[derive(Debug, Subcommand)]
pub enum AuthCommand {
    /// Start or complete OAuth login for one named profile.
    Login(AuthLoginArgs),
    /// Inspect the selected profile and its authentication state.
    Status(ProfileSelector),
    /// List configured profiles and the active selection.
    Profiles,
    /// Select the profile used when a command does not name one.
    Use(ProfileSelector),
    /// Repair one opaque credential through noninteractive platform access.
    RepairKeychainAccess(ProfileSelector),
    /// Remove one profile and its stored credential.
    Logout(ProfileSelector),
    /// Import an account-pinned API token from protected input.
    ImportApiToken(ImportApiTokenArgs),
    /// Import an emergency global API key from protected input.
    ImportGlobalKey(ImportGlobalKeyArgs),
    /// Manage the platform-held key that authenticates local evidence and proofs.
    EvidenceKey(EvidenceKeyArgs),
}

#[derive(Debug, Args)]
pub struct EvidenceKeyArgs {
    #[command(subcommand)]
    pub command: EvidenceKeyCommand,
}

#[derive(Debug, Subcommand)]
pub enum EvidenceKeyCommand {
    /// Prepare a private local storage transition, preserving old history separately.
    PrivatePreview,
    /// Activate the exact prepared fresh local authority without platform prompts.
    PrivateActivate(EvidenceKeyPrivateActivateArgs),
    /// Inspect archived operation identities without giving them execution authority.
    PrivateHistory,
    /// Preview marker-only adoption of one exact valid platform authority.
    AdoptPreview,
    /// Inspect adoption history; creation is held pending authenticated receipt support.
    AdoptPlan(EvidenceKeyAdoptPlanArgs),
    /// Held pending authenticated installed-identity receipt support.
    Adopt(EvidenceKeyAdoptArgs),
    /// Preview the exact non-secret initialization transition without creating a key.
    InitPreview,
    /// Initialize one platform-held evidence authority for this canonical state root.
    Init,
    /// Inspect the non-secret evidence-key lifecycle state without creating a key.
    Status,
    /// Generate a new active signing key and retain older keys for verification.
    Rotate,
    /// Delete one inactive key only when no local authenticated artifact uses it.
    Retire(EvidenceKeyRetireArgs),
    /// Preview recovery of one exact malformed canonical platform registry.
    RecoverPreview,
    /// Create, inspect, or revoke a private malformed-registry recovery plan.
    RecoverPlan(EvidenceKeyRecoverPlanArgs),
    /// Execute or resume one exact private malformed-registry recovery plan.
    Recover(EvidenceKeyRecoverArgs),
    /// Discard one unattributable, unused platform authority and initialize a fresh one.
    Reset(EvidenceKeyResetArgs),
}

#[derive(Debug, Args)]
pub struct EvidenceKeyPrivateActivateArgs {
    pub plan_id: String,
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct EvidenceKeyResetArgs {
    /// Confirm discarding the existing platform authority.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct EvidenceKeyAdoptArgs {
    /// Opaque random identity returned by adopt-plan create.
    pub plan_id: String,
    /// Confirm the protected marker-only transition.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct EvidenceKeyAdoptPlanArgs {
    #[command(subcommand)]
    pub command: EvidenceKeyAdoptPlanCommand,
}

#[derive(Debug, Subcommand)]
pub enum EvidenceKeyAdoptPlanCommand {
    /// Held pending authenticated installed-identity receipt support.
    Create,
    /// Inspect the current recoverable adoption plan without guessing its identity.
    Current,
    /// Inspect public lifecycle state for one opaque adoption plan.
    Status(EvidenceKeyAdoptPlanSelector),
    /// Revoke one unused adoption plan before its marker transition begins.
    Revoke(EvidenceKeyAdoptPlanSelector),
}

#[derive(Debug, Args)]
pub struct EvidenceKeyAdoptPlanSelector {
    pub plan_id: String,
}

#[derive(Debug, Args)]
pub struct EvidenceKeyRecoverArgs {
    /// Opaque random identity returned by recover-plan create.
    pub plan_id: String,
    /// Confirm the protected quarantine and replacement transition.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct EvidenceKeyRecoverPlanArgs {
    #[command(subcommand)]
    pub command: EvidenceKeyRecoverPlanCommand,
}

#[derive(Debug, Subcommand)]
pub enum EvidenceKeyRecoverPlanCommand {
    /// Create a short-lived private plan from the currently admissible malformed registry.
    Create,
    /// Inspect public lifecycle state for one opaque recovery plan.
    Status(EvidenceKeyRecoverPlanSelector),
    /// Immediately revoke one unused recovery plan before quarantine custody begins.
    Revoke(EvidenceKeyRecoverPlanSelector),
}

#[derive(Debug, Args)]
pub struct EvidenceKeyRecoverPlanSelector {
    pub plan_id: String,
}

#[derive(Debug, Args)]
pub struct EvidenceKeyRetireArgs {
    pub generation_id: String,
    /// Confirm deletion after the local authenticated-artifact impact count is zero.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct AuthLoginArgs {
    #[arg(long, default_value = "default")]
    pub profile: String,
    #[arg(
        long,
        env = "CFCTL_OAUTH_CLIENT_ID",
        help = "Cloudflare OAuth client id (required for OAuth; until public cfctl OAuth is promoted, prefer `auth import-api-token`)"
    )]
    pub client_id: Option<String>,
    #[arg(long = "scope", value_delimiter = ',')]
    pub scopes: Vec<String>,
    #[arg(long)]
    pub account: Option<String>,
    #[arg(long)]
    pub complete: bool,
}

#[derive(Debug, Args)]
pub struct ProfileSelector {
    #[arg(default_value = "default")]
    pub profile: String,
}

#[derive(Debug, Args)]
pub struct ImportApiTokenArgs {
    #[arg(long, default_value = "default")]
    pub profile: String,
    #[arg(
        long,
        help = "Pin the account this token is allowed to operate on; ambiguous multi-account selection fails closed"
    )]
    pub account: String,
    #[arg(
        long,
        help = "Read the API token from stdin; values in command arguments are forbidden"
    )]
    pub stdin: bool,
    #[arg(
        long,
        value_name = "PATH",
        help = "Read the API token from a mode-0600 file instead of stdin; avoids piping secrets through a build wrapper such as `./cfctl`"
    )]
    pub value_in: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ImportGlobalKeyArgs {
    #[arg(long, default_value = "emergency-global")]
    pub profile: String,
    #[arg(long)]
    pub email: String,
    #[arg(
        long,
        help = "Read the key from stdin; values in command arguments are forbidden"
    )]
    pub stdin: bool,
    #[arg(
        long,
        value_name = "PATH",
        help = "Read the global key from a mode-0600 file instead of stdin; avoids piping secrets through a build wrapper such as `./cfctl`"
    )]
    pub value_in: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct KeysArgs {
    #[command(subcommand)]
    pub command: KeysCommand,
}

#[derive(Debug, Subcommand)]
pub enum KeysCommand {
    /// Read the permission groups available to an account or user token.
    Permissions(KeyPermissionArgs),
    /// Create a narrowly scoped token through a governed plan.
    Mint(KeyMutationArgs),
    /// Replace a token and write its secret to a protected file.
    Rotate(KeyRotateArgs),
    /// Renew a managed analytics child and atomically switch one profile only
    /// after the staged child passes governed live reads.
    RenewAnalyticsProfile(KeyRenewAnalyticsProfileArgs),
    /// Revoke one account-owned or user-owned token.
    Revoke(KeyRevokeArgs),
    /// Create, inspect, approve, or revoke standing token authority.
    Policy(KeyPolicyArgs),
}

#[derive(Debug, Args)]
pub struct KeyPolicyArgs {
    #[command(subcommand)]
    pub command: KeyPolicyCommand,
}

#[derive(Debug, Subcommand)]
pub enum KeyPolicyCommand {
    /// Draft a bounded standing token policy from a fresh permission inventory.
    Create(KeyPolicyCreateArgs),
    /// Show effective status, remaining budget, lineage, and next action.
    List,
    /// Activate one exact reviewed authority ID with explicit `--yes`.
    Approve(KeyPolicyApproveArgs),
    /// Immediately close future admission under one authority ID.
    Revoke(KeyPolicySelector),
}

#[derive(Debug, Args)]
pub struct KeyPolicyCreateArgs {
    #[arg(long, help = "Explicit profile used for the live permission inventory")]
    pub profile: Option<String>,
    #[arg(long, help = "Pin the single account this authority may operate on")]
    pub account: String,
    #[arg(
        long,
        value_name = "ZONE_ID",
        help = "Also allow children bound to this one zone (com.cloudflare.api.account.zone.<ZONE_ID>); requires --account. Without it the authority is account-scoped only."
    )]
    pub zone: Option<String>,
    #[arg(
        long,
        help = "Name prefix every child token minted under this authority must carry"
    )]
    pub name_prefix: String,
    #[arg(
        long = "permission",
        help = "Permission group (id or exact name) children may request; repeatable"
    )]
    pub permissions: Vec<String>,
    #[arg(long, help = "Maximum child-token TTL in hours")]
    pub max_child_ttl_hours: u32,
    #[arg(long, help = "Maximum standing runs per rolling 24h window")]
    pub max_runs_per_day: u32,
    #[arg(
        long,
        default_value_t = 90,
        help = "Days until the authority itself expires"
    )]
    pub expires_days: u32,
}

#[derive(Debug, Args)]
pub struct KeyPolicyApproveArgs {
    pub authority_id: String,
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct KeyPolicySelector {
    pub authority_id: String,
}

#[derive(Debug, Args)]
pub struct KeyPermissionArgs {
    #[arg(long)]
    pub profile: Option<String>,
    #[arg(
        long,
        help = "Read the user-owned token permission inventory; --account remains the explicit resource and authority context"
    )]
    pub user: bool,
    #[arg(long)]
    pub account: String,
}

#[derive(Debug, Args)]
pub struct KeyMutationArgs {
    #[arg(long)]
    pub profile: Option<String>,
    #[arg(
        long,
        help = "Create a user-owned token scoped to the explicit --account resource"
    )]
    pub user: bool,
    #[arg(long)]
    pub name: String,
    #[arg(long = "permission")]
    pub permissions: Vec<String>,
    #[arg(long)]
    pub account: Option<String>,
    #[arg(
        long,
        value_name = "ZONE_ID",
        help = "Scope the token to a single zone (com.cloudflare.api.account.zone.<ZONE_ID>) instead of the whole account; requires --account and account-owned (not --user). Use for zone-scoped permission groups like Cache Purge or DNS Write."
    )]
    pub zone: Option<String>,
    #[arg(long)]
    pub ttl_hours: Option<u32>,
    #[arg(long)]
    pub value_out: Option<PathBuf>,
    #[arg(
        long,
        value_name = "AUTHORITY_ID",
        help = "Plan AND run unattended under an active standing authority whose bounds cover this mint"
    )]
    pub under_policy: Option<String>,
}

#[derive(Debug, Args)]
pub struct KeyRevokeArgs {
    #[arg(long, help = "Explicit profile used to plan and execute revocation")]
    pub profile: Option<String>,
    #[arg(
        long,
        help = "Revoke a user-owned token instead of an account-owned token"
    )]
    pub user: bool,
    #[arg(long)]
    pub id: String,
    #[arg(long)]
    pub account: Option<String>,
    #[arg(
        long,
        value_name = "AUTHORITY_ID",
        help = "Plan AND run unattended under an active standing authority; only tokens the authority minted may be revoked"
    )]
    pub under_policy: Option<String>,
}

#[derive(Debug, Args)]
pub struct KeyRotateArgs {
    #[arg(
        long,
        help = "Rotate a user-owned token instead of an account-owned token"
    )]
    pub user: bool,
    #[arg(long)]
    pub id: String,
    #[arg(long)]
    pub account: String,
    #[arg(long)]
    pub value_out: PathBuf,
}

#[derive(Debug, Args)]
pub struct KeyRenewAnalyticsProfileArgs {
    #[arg(long, help = "Existing publisher profile to renew in place")]
    pub profile: String,
    #[arg(
        long,
        help = "Profile authorized to mint and revoke account API tokens"
    )]
    pub minter_profile: String,
    #[arg(long)]
    pub account: String,
    #[arg(long, value_name = "ZONE_ID")]
    pub zone: String,
    #[arg(long, help = "Exact Web Analytics requestHost to verify")]
    pub hostname: String,
    #[arg(
        long = "permission",
        help = "Permission group (id or exact name) for the child; repeatable"
    )]
    pub permissions: Vec<String>,
    #[arg(long, default_value_t = 168)]
    pub ttl_hours: u32,
    #[arg(long, default_value_t = 24)]
    pub renew_before_hours: u32,
    #[arg(
        long,
        default_value = "jkca-public-activity-",
        help = "Standing-authority-bound prefix for generated child names"
    )]
    pub name_prefix: String,
    #[arg(long, value_name = "AUTHORITY_ID")]
    pub under_policy: String,
    #[arg(
        long,
        help = "Bootstrap-only active child ID when the profile predates managed rotation metadata"
    )]
    pub current_token_id: Option<String>,
    #[arg(
        long,
        help = "Renew even when the managed child is outside the renewal window"
    )]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct CatalogArgs {
    #[command(subcommand)]
    pub command: CatalogCommand,
}

#[derive(Debug, Subcommand)]
pub enum CatalogCommand {
    /// Refresh the local executable capability catalog.
    Sync,
    /// Search catalog capabilities by intent or feature.
    Search(SearchArgs),
    /// Show one capability's exact executable contract.
    Show(CapabilitySelector),
    /// Show changes between current and previous catalog snapshots.
    Changes,
    /// Report executable, delegated, UI, and blocked capability coverage.
    Coverage,
}

#[derive(Debug, Args)]
pub struct SearchArgs {
    pub query: String,
    #[arg(long, default_value_t = 25)]
    pub limit: usize,
}

#[derive(Debug, Args)]
pub struct CapabilitySelector {
    pub capability_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum GuideTopicArg {
    System,
    StandingAuthority,
}

#[derive(Debug, Args)]
pub struct GuideArgs {
    /// Catalog capability to explain through its exact 15-stage lifecycle.
    #[arg(
        value_name = "CAPABILITY_ID",
        required_unless_present = "topic",
        conflicts_with = "topic"
    )]
    pub capability_id: Option<String>,
    /// Explain the control-plane model or standing-authority lifecycle without loading the catalog.
    #[arg(
        long,
        value_enum,
        value_name = "TOPIC",
        required_unless_present = "capability_id",
        conflicts_with = "capability_id"
    )]
    pub topic: Option<GuideTopicArg>,
}

#[derive(Debug, Args)]
pub struct ResolveArgs {
    /// The natural-language goal, e.g. "enable email routing on example.com".
    pub intent: String,
    /// Account context to thread into the emitted command hints.
    #[arg(long)]
    pub account: Option<String>,
    /// Maximum number of candidate capabilities to report.
    #[arg(long, default_value_t = 5)]
    pub limit: usize,
}

#[derive(Debug, Args)]
pub struct CallArgs {
    pub capability_id: String,
    #[arg(long = "selector", value_parser = parse_key_value)]
    pub selectors: Vec<(String, String)>,
    #[arg(long = "query", value_parser = parse_key_value)]
    pub query: Vec<(String, String)>,
    #[arg(long, conflicts_with = "body_stdin")]
    pub body_json: Option<String>,
    #[arg(long)]
    pub body_stdin: bool,
    #[arg(long)]
    pub profile: Option<String>,
    #[arg(long)]
    pub account: Option<String>,
    #[arg(
        long,
        help = "Send an If-Match precondition bound into the request or plan"
    )]
    pub if_match: Option<String>,
    #[arg(
        long,
        help = "Send an If-None-Match precondition bound into the request or plan"
    )]
    pub if_none_match: Option<String>,
    #[arg(long, help = "Write a one-time secret result to a new mode-0600 file")]
    pub value_out: Option<PathBuf>,
    #[arg(
        long,
        value_name = "MODE_0600_JSON_PATH",
        help = "Read an operation-specific credential bundle from a mode-0600 JSON file; currently accepted only by governed R2 log retrieval"
    )]
    pub credential_in: Option<PathBuf>,
    #[arg(
        long,
        value_name = "NEW_PATH",
        conflicts_with = "value_out",
        help = "Stream a bounded analytics, governed log-retrieval, or D1 full-export result to a new mode-0600 file and return its hash receipt"
    )]
    pub out: Option<PathBuf>,
    #[arg(
        long,
        value_name = "MODE_0600_SOURCE_PATH",
        help = "Plan-creation-only source for an approved D1 operation or create-only private R2 upload; bytes never enter plan JSON"
    )]
    pub source_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct PlansArgs {
    #[command(subcommand)]
    pub command: PlansCommand,
}

#[derive(Debug, Subcommand)]
pub enum PlansCommand {
    /// Show one redacted, hash-bound plan.
    Show(PlanSelector),
    /// Approve one exact plan, with an explicit confirmation flag.
    Approve(PlanApproveArgs),
    /// Execute one approved plan across its pinned adapter boundary.
    Run(PlanSelector),
    /// Inspect durable execution, verification, and recovery state.
    Status(PlanSelector),
    /// Continue an interrupted plan only from its durable checkpoint.
    Resume(PlanSelector),
    /// Reconcile a plan whose provider-boundary outcome needs proof.
    Rectify(PlanSelector),
    /// Retire a draft or approved plan immediately without consuming it
    Cancel(PlanSelector),
    /// Compile and verify an immutable ordered set of independent child plans
    Bundle(DeploymentPlanSetArgs),
}

#[derive(Debug, Args)]
pub struct DeploymentPlanSetArgs {
    #[command(subcommand)]
    pub command: DeploymentPlanSetCommand,
}

#[derive(Debug, Subcommand)]
pub enum DeploymentPlanSetCommand {
    /// Compile a mode-0600 local specification into a body-free review receipt
    Create(DeploymentPlanSetCreateArgs),
    /// Show the immutable redacted bundle receipt and current child statuses
    Show(DeploymentPlanSetSelector),
    /// Revalidate source, pins, child plans, and live provider preconditions
    Verify(DeploymentPlanSetSelector),
}

#[derive(Debug, Args)]
pub struct DeploymentPlanSetCreateArgs {
    #[arg(long, value_name = "ABSOLUTE_MODE_0600_JSON")]
    pub source_file: PathBuf,
}

#[derive(Debug, Args)]
pub struct DeploymentPlanSetSelector {
    pub bundle_id: String,
}

#[derive(Debug, Args)]
pub struct PlanSelector {
    pub operation_id: String,
}

#[derive(Debug, Args)]
pub struct PlanApproveArgs {
    pub operation_id: String,
    #[arg(long)]
    pub yes: bool,
    #[arg(long)]
    pub max_cost: Option<String>,
}

#[derive(Debug, Args)]
pub struct WorkspaceArgs {
    #[command(subcommand)]
    pub command: WorkspaceCommand,
}

#[derive(Debug, Subcommand)]
pub enum WorkspaceCommand {
    /// Register one repository root and its optional account boundary.
    Add(WorkspaceAddArgs),
    /// Remove one explicitly registered repository root.
    Remove(WorkspaceRemoveArgs),
    /// Discover supported Cloudflare configuration in registered roots.
    Discover,
    /// Show relationships among registered roots and resources.
    Graph,
    /// Report workspace drift, impact, and ownership findings.
    Audit,
}

#[derive(Debug, Args)]
pub struct WorkspaceAddArgs {
    pub path: PathBuf,
    #[arg(long)]
    pub account: Option<String>,
}

#[derive(Debug, Args)]
pub struct WorkspaceRemoveArgs {
    pub path: PathBuf,
}

#[derive(Debug, Args)]
pub struct RegistryArgs {
    #[command(subcommand)]
    pub command: RegistryCommand,
}

#[derive(Debug, Subcommand)]
pub enum RegistryCommand {
    /// Discover and govern the registry's explicit scan boundaries.
    Scopes(RegistryScopesArgs),
    /// Reconcile configured scopes into the local resource projection.
    Sync,
    /// Report projection freshness and rebuild state.
    Status,
    /// Report provider-kind and field coverage of the projection.
    Coverage,
    /// List projected resources, optionally filtered by kind.
    List(RegistryListArgs),
    /// Show one projected resource by exact key.
    Get(RegistryResourceArgs),
    /// Show relationships among projected resources.
    Graph,
    /// Compare projected resources with registered source declarations.
    Diff(RegistryOptionalResourceArgs),
    /// Show durable history for one projected resource.
    History(RegistryResourceArgs),
    /// Export the redacted local registry projection.
    Export,
    /// Rebuild derived registry state from durable inputs.
    Rebuild,
    /// Validate, compare, or plan from repository declarations.
    Declarations(RegistryDeclarationsArgs),
    /// Inspect or check declared resource ownership.
    Ownership(RegistryOwnershipArgs),
}

#[derive(Debug, Args)]
pub struct RegistryScopesArgs {
    #[command(subcommand)]
    pub command: RegistryScopesCommand,
}

#[derive(Debug, Subcommand)]
pub enum RegistryScopesCommand {
    /// List explicitly adopted registry scopes.
    List,
    /// Discover candidate scopes without adopting them.
    Discover,
    /// Adopt one exact organization, account, zone, or resource scope.
    Adopt(RegistryScopeArgs),
    /// Remove one exact scope from future registry reconciliation.
    Remove(RegistryScopeArgs),
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum RegistryScopeKindArg {
    Organization,
    Account,
    Zone,
    Resource,
}

#[derive(Debug, Args)]
pub struct RegistryScopeArgs {
    #[arg(long, value_enum)]
    pub kind: RegistryScopeKindArg,
    #[arg(long)]
    pub id: String,
    #[arg(long, value_enum, requires = "parent_id")]
    pub parent_kind: Option<RegistryScopeKindArg>,
    #[arg(long, requires = "parent_kind")]
    pub parent_id: Option<String>,
}

#[derive(Debug, Args)]
pub struct RegistryListArgs {
    #[arg(long)]
    pub kind: Option<String>,
}

#[derive(Debug, Args)]
pub struct RegistryResourceArgs {
    #[arg(long)]
    pub resource: String,
}

#[derive(Debug, Args)]
pub struct RegistryOptionalResourceArgs {
    #[arg(long)]
    pub resource: Option<String>,
}

#[derive(Debug, Args)]
pub struct RegistryDeclarationsArgs {
    #[command(subcommand)]
    pub command: RegistryDeclarationsCommand,
}

#[derive(Debug, Subcommand)]
pub enum RegistryDeclarationsCommand {
    /// Validate registered repository declarations without planning changes.
    Validate,
    /// Compare declarations with the current registry projection.
    Diff(RegistryOptionalResourceArgs),
    /// Create governed plans for declaration drift.
    Plan(RegistryOptionalResourceArgs),
}

#[derive(Debug, Args)]
pub struct RegistryOwnershipArgs {
    #[command(subcommand)]
    pub command: RegistryOwnershipCommand,
}

#[derive(Debug, Args)]
pub struct PolicyArgs {
    #[command(subcommand)]
    pub command: PolicyCommand,
}

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Stage, review, approve, activate, or roll back local admission policy.
    Admission(AdmissionPolicyArgs),
    /// Read Cloudflare policy and create governed reconciliation plans.
    Cloudflare(CloudflarePolicyArgs),
}

#[derive(Debug, Args)]
pub struct AdmissionPolicyArgs {
    #[command(subcommand)]
    pub command: AdmissionPolicyCommand,
}

#[derive(Debug, Subcommand)]
pub enum AdmissionPolicyCommand {
    /// Stage a policy bundle from a local JSON file.
    Stage(FileInputArgs),
    /// List staged, approved, active, and retired bundles.
    List,
    /// Show one exact policy bundle.
    Show(BundleSelector),
    /// Compare one bundle with the active policy.
    Diff(BundleSelector),
    /// Approve one exact staged bundle with explicit confirmation.
    Approve(BundleApproveArgs),
    /// Make one approved bundle the active admission policy.
    Activate(BundleSelector),
    /// Restore a previously active bundle.
    Rollback(BundleSelector),
}

#[derive(Debug, Args)]
pub struct FileInputArgs {
    #[arg(long, value_name = "JSON_PATH")]
    pub file: PathBuf,
}

#[derive(Debug, Args)]
pub struct BundleSelector {
    pub bundle_id: String,
}

#[derive(Debug, Args)]
pub struct BundleApproveArgs {
    pub bundle_id: String,
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct CloudflarePolicyArgs {
    #[command(subcommand)]
    pub command: CloudflarePolicyCommand,
}

#[derive(Debug, Subcommand)]
pub enum CloudflarePolicyCommand {
    /// List policy-bearing resources from live Cloudflare state.
    List,
    /// Read live policy for one exact registered resource.
    Get(RegistryResourceArgs),
    /// Compare live policy with local declarations.
    Diff(RegistryOptionalResourceArgs),
    /// Create governed plans for policy drift.
    Plan(RegistryOptionalResourceArgs),
}

#[derive(Debug, Subcommand)]
pub enum RegistryOwnershipCommand {
    /// List declared owners for projected resources.
    List,
    /// Show the declared owner of one exact resource.
    Get(RegistryResourceArgs),
    /// Check ownership completeness and conflicts.
    Check,
}

#[derive(Debug, Args)]
pub struct EventsArgs {
    #[command(subcommand)]
    pub command: EventsCommand,
}

#[derive(Debug, Subcommand)]
pub enum EventsCommand {
    /// List configured event sources and their boundaries.
    Sources,
    /// Report event ingestion and reconciliation health.
    Status,
    /// Show bounded durable event history.
    History(EventHistoryArgs),
    /// Enqueue reconciliation for one exact resource.
    Reconcile(EventReconcileArgs),
    /// Inspect or prepare the governed event bridge.
    Bridge(EventBridgeArgs),
}

#[derive(Debug, Args)]
pub struct EventHistoryArgs {
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..=1000))]
    pub limit: u32,
}

#[derive(Debug, Args)]
pub struct EventReconcileArgs {
    #[arg(long)]
    pub resource: String,
}

#[derive(Debug, Args)]
pub struct EventBridgeArgs {
    #[command(subcommand)]
    pub command: EventBridgeCommand,
}

#[derive(Debug, Subcommand)]
pub enum EventBridgeCommand {
    /// Inspect bridge requirements without changing local or provider state.
    Inspect,
    /// Prepare a governed bridge plan without executing it.
    Prepare,
    /// Report the bridge's durable local status.
    Status,
}

#[derive(Debug, Args)]
pub struct AgentsArgs {
    #[command(subcommand)]
    pub command: AgentsCommand,
}

#[derive(Debug, Subcommand)]
pub enum AgentsCommand {
    /// Install managed cfctl guidance into detected agent homes.
    Install(AgentsInstallArgs),
    /// Check installed guidance against the running cfctl build.
    Doctor,
    /// Refresh previously installed managed guidance.
    Sync,
}

#[derive(Debug, Args)]
pub struct AgentsInstallArgs {
    #[arg(long)]
    pub all_detected: bool,
}

#[derive(Debug, Args)]
pub struct DocsArgs {
    #[command(subcommand)]
    pub command: DocsCommand,
}

#[derive(Debug, Subcommand)]
pub enum DocsCommand {
    /// Search the compact official Cloudflare documentation index.
    Search(SearchArgs),
    /// Show recent official Cloudflare documentation changes.
    Changes,
    /// Report documentation index coverage and freshness.
    Coverage,
}

#[derive(Debug, Args)]
pub struct UpdateArgs {
    #[arg(long)]
    pub check: bool,
}

#[derive(Debug, Args)]
pub struct MigrateArgs {
    #[command(subcommand)]
    pub command: MigrateCommand,
}

#[derive(Debug, Subcommand)]
pub enum MigrateCommand {
    /// Import explicitly supported non-secret state from the v1 runtime.
    V1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvocationMode {
    Deterministic,
    NaturalLanguage(String),
}

pub fn classify_invocation<I, S>(arguments: I) -> InvocationMode
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut arguments = arguments.into_iter().map(Into::into);
    let _program = arguments.next();
    let remaining: Vec<String> = arguments.filter(|argument| argument != "--json").collect();
    let Some(first) = remaining.first() else {
        return InvocationMode::Deterministic;
    };
    if first.starts_with('-')
        || is_known_subcommand(first)
        || is_retired_v1_command_shape(&remaining)
    {
        return InvocationMode::Deterministic;
    }
    // A bare single token is far more likely a mistyped subcommand than a
    // one-word natural-language request: route it to the deterministic parser
    // so clap fails closed with an unrecognized-subcommand error (and its
    // did-you-mean suggestion) instead of silently launching an agent.
    if remaining.len() == 1 && !first.contains(char::is_whitespace) {
        return InvocationMode::Deterministic;
    }
    InvocationMode::NaturalLanguage(remaining.join(" "))
}

fn is_retired_v1_command_shape(arguments: &[String]) -> bool {
    let Some(first) = arguments.first().map(String::as_str) else {
        return false;
    };
    if !RETIRED_V1_PUBLIC_VERBS.contains(&first) {
        return false;
    }
    let second = arguments.get(1).map(String::as_str);
    match first {
        "apply" | "can" | "classify" | "diff" | "explain" | "get" | "list" | "snapshot"
        | "verify" => second.is_some_and(|surface| RETIRED_V1_SURFACES.contains(&surface)),
        "audit" => {
            arguments.len() == 2
                && second.is_some_and(|scope| matches!(scope, "access" | "state" | "trust"))
        }
        "token" => second.is_some_and(|action| {
            matches!(action, "mint" | "permission-groups" | "revoke" | "rotate")
        }),
        _ => true,
    }
}

fn is_known_subcommand(name: &str) -> bool {
    // clap injects the `help` subcommand at parse time, so it is not visible
    // through `get_subcommands` here.
    name == "help"
        || Cli::command().get_subcommands().any(|command| {
            command.get_name() == name || command.get_all_aliases().any(|alias| alias == name)
        })
}

fn parse_key_value(value: &str) -> Result<(String, String), String> {
    let Some((key, value)) = value.split_once('=') else {
        return Err("expected KEY=VALUE".to_owned());
    };
    if key.is_empty() {
        return Err("selector key cannot be empty".to_owned());
    }
    Ok((key.to_owned(), value.to_owned()))
}

#[cfg(test)]
mod invocation_routing_tests {
    use super::{InvocationMode, classify_invocation};

    fn classify(arguments: &[&str]) -> InvocationMode {
        classify_invocation(arguments.iter().copied())
    }

    fn reaches_the_parser(arguments: &[&str]) -> bool {
        classify(arguments) == InvocationMode::Deterministic
    }

    #[test]
    fn an_empty_invocation_reaches_the_parser() {
        assert!(reaches_the_parser(&["cfctl"]));
        assert!(reaches_the_parser(&["cfctl", "--json"]));
    }

    #[test]
    fn a_leading_flag_reaches_the_parser() {
        for flag in ["--help", "-h", "--version", "-V"] {
            assert!(reaches_the_parser(&["cfctl", flag]), "{flag}");
        }
    }

    #[test]
    fn a_known_subcommand_reaches_the_parser() {
        for verb in ["doctor", "plans", "catalog", "auth", "keys", "help"] {
            assert!(reaches_the_parser(&["cfctl", verb]), "{verb}");
            assert!(
                reaches_the_parser(&["cfctl", verb, "status"]),
                "{verb} status"
            );
        }
    }

    #[test]
    fn a_mistyped_subcommand_reaches_the_parser_instead_of_the_agent() {
        // A bare unknown token is a typo, not intent: it must fail closed with
        // clap's unrecognized-subcommand error rather than launch an agent.
        for typo in ["not-a-real-verb", "doctr", "planz"] {
            assert!(reaches_the_parser(&["cfctl", typo]), "{typo}");
            assert!(
                reaches_the_parser(&["cfctl", typo, "--json"]),
                "{typo} --json"
            );
        }
    }

    #[test]
    fn a_retired_v1_command_shape_reaches_the_parser() {
        // RETIRED_V1_PUBLIC_VERBS exists so a stale multi-token v1 command
        // fails closed instead of being read as natural-language intent.
        for shape in [
            &["verify", "dns.record"][..],
            &["can", "dns.record", "delete"][..],
            &["list", "d1.database"][..],
            &["token", "mint"][..],
            &["audit", "trust"][..],
            &["surfaces", "list"][..],
            &["hostname", "apply", "example.com"][..],
        ] {
            let arguments: Vec<&str> = std::iter::once("cfctl")
                .chain(shape.iter().copied())
                .collect();
            assert!(reaches_the_parser(&arguments), "{shape:?}");
        }
    }

    #[test]
    fn a_retired_verb_used_as_prose_is_still_intent() {
        // The surface list is what separates `cfctl verify dns.record` (a dead
        // v1 command) from `verify my dns records` (a request). Without it the
        // whole retired-verb boundary would swallow ordinary English.
        assert_eq!(
            classify(&["cfctl", "verify", "my", "dns", "records"]),
            InvocationMode::NaturalLanguage("verify my dns records".to_owned())
        );
    }

    #[test]
    fn multi_word_input_is_routed_to_the_agent_lane() {
        let expected = InvocationMode::NaturalLanguage("make me a dns record".to_owned());
        assert_eq!(
            classify(&["cfctl", "make", "me", "a", "dns", "record"]),
            expected
        );
        assert_eq!(classify(&["cfctl", "make me a dns record"]), expected);
    }

    #[test]
    fn the_json_flag_never_changes_routing() {
        assert_eq!(
            classify(&["cfctl", "--json", "make", "me", "a", "record"]),
            classify(&["cfctl", "make", "me", "a", "record"])
        );
        assert_eq!(
            classify(&["cfctl", "make", "me", "a", "record", "--json"]),
            classify(&["cfctl", "make", "me", "a", "record"])
        );
    }
}
