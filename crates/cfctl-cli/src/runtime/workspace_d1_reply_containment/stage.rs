use super::super::prelude::{CliError, Path, Result, StateStore};
use cfctl_storage::PrivateDirectory;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PrivateStage {
    schema_version: u8,
    stage_id: String,
    sha256: String,
    bytes: u64,
}
pub(super) fn read_input(path: &Path) -> Result<Vec<u8>> {
    cfctl_storage::capture_private_input(
        path,
        1024 * 1024,
        cfctl_storage::PrivateInputPermissions::OwnerReadWrite,
    )
    .map_err(|error| CliError::Input(error.to_string()))
}
pub(super) fn write(store: &StateStore, value: &Value) -> Result<PrivateStage> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.is_empty() || bytes.len() > 1024 * 1024 {
        return Err(super::rejected());
    }
    let stage = PrivateStage {
        schema_version: 1,
        stage_id: uuid::Uuid::new_v4().to_string(),
        sha256: super::hash(&bytes),
        bytes: bytes.len() as u64,
    };
    let dir = stages(store)?
        .create_new_directory(&stage.stage_id)
        .map_err(|_| super::rejected())?;
    publish(&dir, "candidate.json", &bytes, &stage.stage_id)?;
    Ok(stage)
}
pub(super) fn load(store: &StateStore, stage: &PrivateStage) -> Result<Value> {
    let dir = PrivateDirectory::open(&directory(store, stage)?).map_err(|_| super::rejected())?;
    let bytes = dir
        .read("candidate.json", 1024 * 1024)
        .map_err(|_| super::rejected())?
        .ok_or_else(super::rejected)?;
    if stage.schema_version != 1
        || stage.bytes != bytes.len() as u64
        || stage.sha256 != super::hash(&bytes)
    {
        return Err(super::rejected());
    }
    Ok(serde_json::from_slice(&bytes)?)
}
pub(super) fn retain_sql(store: &StateStore, stage: &PrivateStage, sql: &str) -> Result<PathBuf> {
    load(store, stage)?;
    let path = directory(store, stage)?;
    let dir = PrivateDirectory::open(&path).map_err(|_| super::rejected())?;
    // One immutable dispatch artifact. A retry never replaces prior bytes.
    publish(&dir, "containment.sql", sql.as_bytes(), &stage.stage_id)?;
    Ok(path.join("containment.sql"))
}

fn directory(store: &StateStore, stage: &PrivateStage) -> Result<PathBuf> {
    let parsed = uuid::Uuid::parse_str(&stage.stage_id).map_err(|_| super::rejected())?;
    if parsed.to_string() != stage.stage_id {
        return Err(super::rejected());
    }
    Ok(store
        .paths()
        .data_dir
        .join("reply-containment-stages-v3")
        .join(&stage.stage_id))
}
fn stages(store: &StateStore) -> Result<PrivateDirectory> {
    let parent = PrivateDirectory::open(&store.paths().data_dir).map_err(|_| {
        CliError::Input(
            "containment staging requires a canonical owned mode-0700 runtime data directory"
                .into(),
        )
    })?;
    parent
        .create_new_directory("reply-containment-stages-v3")
        .or_else(|_| PrivateDirectory::open(&parent.location().join("reply-containment-stages-v3")))
        .map_err(|_| super::rejected())
}
fn publish(dir: &PrivateDirectory, name: &str, bytes: &[u8], id: &str) -> Result<()> {
    dir.publish_new_file(name,bytes,Instant::now()+Duration::from_secs(10)).map_err(|error|CliError::Input(format!(
        "containment stage {id} publication failed (published={}); preserve the stage and reconcile before retry",error.published)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn stage_is_private_immutable_and_bound_to_its_bytes()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let paths =
            super::super::super::prelude::RuntimePaths::from_root(&root.path().canonicalize()?);
        PrivateDirectory::create(&paths.data_dir)?;
        let store = StateStore::open(paths)?;
        let value = json!({"private":"fixture"});
        let stage = write(&store, &value)?;
        assert_eq!(load(&store, &stage)?, value);
        let sql = retain_sql(&store, &stage, "SELECT 1;")?;
        assert!(retain_sql(&store, &stage, "SELECT 2;").is_err());
        assert_eq!(std::fs::read_to_string(sql)?, "SELECT 1;");
        std::fs::write(directory(&store, &stage)?.join("candidate.json"), b"{}")?;
        assert!(load(&store, &stage).is_err());
        Ok(())
    }
    #[test]
    fn staging_refuses_linked_parent_without_writing_target()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        let paths =
            super::super::super::prelude::RuntimePaths::from_root(&root.path().canonicalize()?);
        PrivateDirectory::create(&paths.data_dir)?;
        let store = StateStore::open(paths)?;
        std::os::unix::fs::symlink(
            outside.path(),
            store.paths().data_dir.join("reply-containment-stages-v3"),
        )?;
        assert!(write(&store, &json!({"private":"fixture"})).is_err());
        assert_eq!(std::fs::read_dir(outside.path())?.count(), 0);
        Ok(())
    }
}
