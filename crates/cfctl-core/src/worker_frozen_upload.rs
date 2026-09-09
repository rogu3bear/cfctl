//! Immutable local inputs for the optional Worker frozen-artifact transport.
//!
//! The Worker target owns source/config identity; this companion binds the
//! complete file set and the deterministic projection consumed by Wrangler.
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const CAPABILITY_ID: &str = "wrangler.versions-upload";
pub const ARTIFACT_MODE: &str = "frozen-artifact";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenArtifactEntryV1 {
    /// Repository-relative UTF-8 path, without backslashes or control bytes.
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenArtifactManifestV1 {
    pub schema_version: u8,
    pub roots: Vec<String>,
    /// Directories are bound too, so additions/deletions cannot hide behind
    /// the file-only deployment digest used in existing release messages.
    pub directories: Vec<String>,
    pub entries: Vec<FrozenArtifactEntryV1>,
    /// Existing Worker artifact-set SHA-256, preserving release messages.
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenArtifactUploadV1 {
    pub schema_version: u8,
    pub artifact_mode: String,
    pub manifest: FrozenArtifactManifestV1,
    pub projection_sha256: String,
    pub custom_build_suppressed: bool,
    /// Bound executable, interpreter, package closure, and catalog source.
    pub producer: Value,
    /// Module edges resolved exclusively against the admitted file bytes.
    pub module_graph: Value,
}
