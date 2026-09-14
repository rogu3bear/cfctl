//! One fixed copy-public/esbuild recipe, authenticated as fresh reproduction.
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PRODUCER_ID: &str = "pages-artifact-reproduce";
pub const RECIPE: &str = "copy-public-esbuild-0.28.2-esm-es2022-v1";
pub const SCRIPT_HASH: &str = "823e37cf4d73a19a365ec922d8d0b09921e6a016a3cc765ac0d2b5abcf80131a";
pub const PACKAGE_HASH: &str = "da96c4042617a4bb1439012c121732adaa54c8584fd558372269085b9e23e4d5";
pub const LOCK_HASH: &str = "f8868a6778a59af0ddb9b4b5dc9917f93e69fcf4788a0fce328cb3a2330bbf22";
// Integrity of the platform package in the exact admitted lock, not a caller pin.
pub const ESBUILD_INTEGRITY: &str =
    "n4KqkOQrraxHJcgjM1RvwbigfQKIKJVpM7xp+KsxiyUSrRdIXnt73VhrPAx0fV44hgfmIVKjxMN9J1t5jySVkw==";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReproductionRequestV1 {
    pub repository: String,
    pub commit: String,
    pub tree: String,
    pub account_id: String,
    pub project_name: String,
    pub branch: String,
    pub artifact_directory: String,
    pub artifact_manifest_sha256: String,
    /// Local npm platform-package tarball; never downloaded or installed here.
    pub esbuild_package: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReproductionReceiptV1 {
    pub schema_version: u8,
    pub kind: String,
    pub recipe: String,
    pub request: ReproductionRequestV1,
    pub run_id: String,
    pub build_identity_hash: String,
    pub producer_contract_hash: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: chrono::DateTime<chrono::Utc>,
    pub materials_hash: String,
    pub esbuild_sha256: String,
    pub helper_tools: Value,
    pub environment: Value,
    pub artifact: Value,
}
