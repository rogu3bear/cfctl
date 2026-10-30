use super::super::{
    prelude::{AuthCredential, CliError, Result, StateStore},
    workspace_d1_config::ValidatedConfig,
    workspace_d1_execution,
};
use cfctl_core::{BoundaryObservation, WorkspaceD1ReplyContainmentContractV3};
use serde_json::Value;
use std::path::Path;

pub(super) fn producer(contract: &WorkspaceD1ReplyContainmentContractV3) -> Result<Value> {
    let path = Path::new(&contract.repository_root).join("node_modules/wrangler/bin/wrangler.js");
    let path = if path.is_file() {
        path
    } else {
        which::which("wrangler").map_err(|_| rejected())?
    };
    super::super::wrangler_producer::snapshot_declared_version(
        &path,
        &contract.wrangler_version,
        "d1 execute",
    )
}

pub(super) struct Transport<'a> {
    pub store: &'a StateStore,
    pub contract: &'a WorkspaceD1ReplyContainmentContractV3,
    pub config: &'a ValidatedConfig,
    pub credential: &'a AuthCredential,
    pub account: &'a str,
    pub producer: &'a Value,
}
impl Transport<'_> {
    pub(super) async fn query(&self, sql: &str) -> Result<Vec<serde_json::Map<String, Value>>> {
        let output = self
            .run(&["--command".into(), sql.into(), "--json".into()], None)
            .await?;
        if !output.success {
            return Err(rejected());
        }
        workspace_d1_execution::parse_query_rows(&output.stdout)
    }
    pub(super) async fn apply(
        &self,
        path: &Path,
        boundary: &BoundaryObservation,
        plan: &cfctl_core::PlanV1,
    ) -> Result<workspace_d1_execution::WranglerOutput> {
        self.run(
            &["--file".into(), path.to_string_lossy().into_owned()],
            Some((boundary, plan)),
        )
        .await
    }
    async fn run(
        &self,
        tail: &[String],
        mutation: Option<(&BoundaryObservation, &cfctl_core::PlanV1)>,
    ) -> Result<workspace_d1_execution::WranglerOutput> {
        if producer(self.contract)? != *self.producer {
            return Err(rejected());
        }
        // This follows the potentially long provider read and producer probe.
        // No mutation subprocess starts before the final local authority gate.
        if let Some((_, plan)) = mutation {
            super::planning::validate_dispatch(self.store, plan)?;
        }
        let executable = self.producer["executable"].as_str().ok_or_else(rejected)?;
        let interpreter = self
            .producer
            .pointer("/interpreter/path")
            .and_then(Value::as_str);
        let program = interpreter.unwrap_or(executable);
        let mut arguments = Vec::new();
        if interpreter.is_some() {
            arguments.push(executable.to_owned());
        }
        arguments.extend([
            "d1".into(),
            "execute".into(),
            self.config.database_name.clone(),
            "--remote".into(),
            "--config".into(),
            self.config.path.clone(),
        ]);
        arguments.extend_from_slice(tail);
        workspace_d1_execution::run_wrangler_program(
            Path::new(program),
            &arguments,
            Path::new(&self.contract.repository_root),
            self.credential,
            self.account,
            &self.store.paths().cache_dir,
            tokio::time::Duration::from_mins(5),
            Some(&self.config.sha256),
            Some(&self.contract.config_template_sha256),
            Some(&self.contract.database_binding),
            mutation.map(|(boundary, _)| boundary),
        )
        .await
    }
}
fn rejected() -> CliError {
    CliError::Input(
        "containment requires the exact bound Wrangler producer and complete private D1 result"
            .into(),
    )
}
