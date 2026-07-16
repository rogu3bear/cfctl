//! Public command contract for the cfctl v2 binary.

use std::path::PathBuf;

use clap::{Args, CommandFactory as _, Parser, Subcommand};

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
    Auth(AuthArgs),
    Keys(KeysArgs),
    Catalog(CatalogArgs),
    Call(CallArgs),
    Guide(GuideArgs),
    Plans(PlansArgs),
    Workspace(WorkspaceArgs),
    Agents(AgentsArgs),
    Docs(DocsArgs),
    Doctor,
    Update(UpdateArgs),
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
    ImportGlobalKey(ImportGlobalKeyArgs),
}

#[derive(Debug, Args)]
pub struct AuthLoginArgs {
    #[arg(long, default_value = "default")]
    pub profile: String,
    #[arg(long, env = "CFCTL_OAUTH_CLIENT_ID")]
    pub client_id: String,
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
}

#[derive(Debug, Args)]
pub struct KeyPermissionArgs {
    #[arg(long)]
    pub account: Option<String>,
}

#[derive(Debug, Args)]
pub struct KeyMutationArgs {
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
}

#[derive(Debug, Args)]
pub struct KeyRevokeArgs {
    #[arg(long)]
    pub id: String,
    #[arg(long)]
    pub account: Option<String>,
}

#[derive(Debug, Args)]
pub struct KeyRotateArgs {
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

#[derive(Debug, Args)]
pub struct GuideArgs {
    pub capability_id: String,
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
    if first.starts_with('-') || is_known_subcommand(first) {
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
