//! Route committed pack identities without loading unrelated execution inputs.
use super::{Result, WorkspaceError, git_blob};
use std::path::Path;

// Migration, projection, reply-admission and evidence packs share only this
// routing invariant. Their selected execution contracts remain independent.
pub(super) fn contains(repository: &Path, pack: &str, capability_id: &str) -> Result<bool> {
    let Some(bytes) = git_blob(repository, Path::new(pack))? else {
        return Ok(false);
    };
    let invalid = WorkspaceError::DiscoveryInvariant;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| invalid("committed operation pack is not UTF-8".to_owned()))?;
    let value: toml::Value = toml::from_str(text)
        .map_err(|error| invalid(format!("committed operation pack is invalid: {error}")))?;
    Ok(value
        .get("operation")
        .and_then(toml::Value::as_array)
        .is_some_and(|operations| {
            operations.iter().any(|operation| {
                operation.get("id").and_then(toml::Value::as_str) == Some(capability_id)
            })
        }))
}
