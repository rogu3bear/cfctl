//! Explicit, one-way importer for the quarantined v1 state archive.

use cfctl_core::hash_value;

use super::prelude::{
    EvidenceClass, MigrateCommand, Path, Result, ResultEnvelopeV2, StateStore, Value, env, fs, json,
};
use super::support::{cli_io, contains_sensitive_content, is_secret_path};

pub(super) fn migrate_command(
    store: &StateStore,
    command: MigrateCommand,
) -> Result<ResultEnvelopeV2> {
    match command {
        MigrateCommand::V1 => {
            let cwd = env::current_dir().map_err(|source| cli_io(Path::new("."), source))?;
            let mut imported = Vec::new();
            let mut skipped = Vec::new();
            let retained_repo_state = "compat/v1/state";
            let state_source = if cwd.join(retained_repo_state).is_dir() {
                retained_repo_state
            } else {
                "state"
            };
            for (source_root, import_label) in
                [(state_source, "state"), ("var/inventory", "var/inventory")]
            {
                let root = cwd.join(source_root);
                if !root.is_dir() {
                    continue;
                }
                for entry in walkdir::WalkDir::new(&root)
                    .follow_links(false)
                    .into_iter()
                    .filter_map(std::result::Result::ok)
                    .filter(|entry| entry.file_type().is_file())
                {
                    let path = entry.path();
                    if is_secret_path(path) {
                        skipped.push(json!({"source_path": path, "reason": "secret-shaped path"}));
                        continue;
                    }
                    let content =
                        fs::read_to_string(path).map_err(|source| cli_io(path, source))?;
                    if contains_sensitive_content(&content) {
                        skipped
                            .push(json!({"source_path": path, "reason": "secret-shaped content"}));
                        continue;
                    }
                    let content_hash = hash_value(&Value::String(content.clone()))?;
                    let digest = content_hash
                        .strip_prefix("sha256:")
                        .unwrap_or(&content_hash);
                    let Ok(source_relative) = path.strip_prefix(&root) else {
                        skipped.push(
                            json!({"source_path": path, "reason": "path escaped source root"}),
                        );
                        continue;
                    };
                    let destination = store.write_import(
                        &Path::new("v1")
                            .join(digest)
                            .join(import_label)
                            .join(source_relative),
                        content.as_bytes(),
                    )?;
                    let evidence = store.write_audit_evidence(
                        EvidenceClass::SourceConfig,
                        &json!({
                            "source_path": path,
                            "destination": destination,
                            "source_content_hash": content_hash,
                        }),
                    )?;
                    imported.push(json!({
                        "source_path": path,
                        "destination": destination,
                        "source_content_hash": content_hash,
                        "evidence": evidence,
                    }));
                }
            }
            Ok(ResultEnvelopeV2::success(
                "migrate v1",
                json!({
                    "imported": imported,
                    "skipped": skipped,
                    "credentials_imported": false,
                    "message": "V1 desired state and evidence were copied into content-addressed imports; secret-shaped files and credentials were not imported."
                }),
            ))
        }
    }
}
