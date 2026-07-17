//! Public command contract for the cfctl v2 binary.

use std::path::PathBuf;

use cfctl_core::{RETIRED_V1_PUBLIC_VERBS, RETIRED_V1_SURFACES};
use clap::{Args, CommandFactory as _, Parser, Subcommand, ValueEnum};

mod profiles;
pub mod runtime;

#[derive(Debug, Parser)]
#[command(
    name = "cfctl",
    version,
    about = "Universal governed Cloudflare control plane"
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
    /// Manage credential profiles and login state.
    Auth(AuthArgs),
    /// Inspect and govern Cloudflare token lifecycles.
    Keys(KeysArgs),
    /// Discover the executable Cloudflare capability catalog.
    Catalog(CatalogArgs),
    /// Read live state or create a mutation plan.
    Call(CallArgs),
    /// Explain a capability lifecycle or a system-level control-plane topic.
    Guide(GuideArgs),
    /// Review, approve, run, recover, and inspect durable plans.
    Plans(PlansArgs),
    /// Register and inspect repository impact boundaries.
    Workspace(WorkspaceArgs),
    /// Install and verify managed agent guidance.
    Agents(AgentsArgs),
    /// Search current official Cloudflare documentation and changes.
    Docs(DocsArgs),
    /// Inspect local runtime, authentication, and catalog health.
    Doctor,
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
    Login(AuthLoginArgs),
    Status(ProfileSelector),
    Profiles,
    Use(ProfileSelector),
    Logout(ProfileSelector),
    ImportApiToken(ImportApiTokenArgs),
    ImportGlobalKey(ImportGlobalKeyArgs),
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
    Permissions(KeyPermissionArgs),
    Mint(KeyMutationArgs),
    Rotate(KeyRotateArgs),
    Revoke(KeyRevokeArgs),
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
    #[arg(long, help = "Pin the single account this authority may operate on")]
    pub account: String,
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
    #[arg(
        long,
        help = "Read the user-owned token permission inventory; --account remains the explicit resource and authority context"
    )]
    pub user: bool,
    #[arg(long)]
    pub account: Option<String>,
}

#[derive(Debug, Args)]
pub struct KeyMutationArgs {
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
pub struct CatalogArgs {
    #[command(subcommand)]
    pub command: CatalogCommand,
}

#[derive(Debug, Subcommand)]
pub enum CatalogCommand {
    Sync,
    Search(SearchArgs),
    Show(CapabilitySelector),
    Changes,
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
}

#[derive(Debug, Args)]
pub struct PlansArgs {
    #[command(subcommand)]
    pub command: PlansCommand,
}

#[derive(Debug, Subcommand)]
pub enum PlansCommand {
    Show(PlanSelector),
    Approve(PlanApproveArgs),
    Run(PlanSelector),
    Status(PlanSelector),
    Resume(PlanSelector),
    Rectify(PlanSelector),
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
    Add(WorkspaceAddArgs),
    Discover,
    Graph,
    Audit,
}

#[derive(Debug, Args)]
pub struct WorkspaceAddArgs {
    pub path: PathBuf,
    #[arg(long)]
    pub account: Option<String>,
}

#[derive(Debug, Args)]
pub struct AgentsArgs {
    #[command(subcommand)]
    pub command: AgentsCommand,
}

#[derive(Debug, Subcommand)]
pub enum AgentsCommand {
    Install(AgentsInstallArgs),
    Doctor,
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
    Search(SearchArgs),
    Changes,
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
        "audit" => second.is_some_and(|scope| matches!(scope, "access" | "state" | "trust")),
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
