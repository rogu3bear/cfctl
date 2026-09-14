//! Fixed native reproduction, not an arbitrary-command attestation service.
use super::{CliError, Result, pages_deployment, pages_reproduction_process as process};
use base64::Engine;
use cfctl_core::{
    ResultEnvelopeV2, VerificationState, hash_value,
    pages_artifact::{self as contract, ReproductionReceiptV1, ReproductionRequestV1},
};
use cfctl_storage::StateStore;
use cfctl_workspace::WorkspaceGraph;
use process::rejected;
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha512};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Component, Path},
};

const MAX_FILE: u64 = 25 * 1024 * 1024;
const MAX_MATERIALS: u64 = 256 * 1024 * 1024;

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(super) fn environment() -> Value {
    json!({"PATH":"/usr/bin:/bin","LANG":"C","LC_ALL":"C","TZ":"UTC","git_environment":{"GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":"/dev/null","GIT_NO_REPLACE_OBJECTS":"1","GIT_NO_LAZY_FETCH":"1","GIT_ALLOW_PROTOCOL":""},"compiler_working_directory":"site","ambient_environment":false,"repository_scripts":false,"dependency_installation":false})
}

pub(super) fn build_hash() -> Result<String> {
    Ok(hash_value(&serde_json::to_value(
        crate::build_identity::current_build_info(),
    )?)?)
}

pub(super) fn producer_hash() -> Result<String> {
    Ok(hash_value(
        &json!({"recipe":contract::RECIPE,"implementation":include_str!("pages_reproduction.rs"),"process":include_str!("pages_reproduction_process.rs")}),
    )?)
}

pub(super) fn canonical_path(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|p| !matches!(p, Component::RootDir | Component::Normal(_)))
    {
        return Err(rejected());
    }
    pages_deployment::reject_symlink_components(path)?;
    if fs::canonicalize(path).map_err(|_| rejected())? != path {
        return Err(rejected());
    }
    Ok(())
}

pub(super) fn validate_source(
    graph: &WorkspaceGraph,
    request: &ReproductionRequestV1,
) -> Result<()> {
    let repo = Path::new(&request.repository);
    canonical_path(repo)?;
    if !graph.repositories.iter().any(|r| r.path == repo)
        || !hex_string(&request.commit, 40)
        || !hex_string(&request.tree, 40)
        || !hex_string(&request.account_id, 32)
        || !hex_string(&request.artifact_manifest_sha256, 64)
        || !cfctl_core::pages_projects::valid_project_name(&request.project_name)
        || !super::pages_source::git_branch_name_is_safe(&request.branch)
    {
        return Err(rejected());
    }
    let actual = process::git(
        repo,
        &[
            "rev-parse",
            "--verify",
            &format!("{}^{{tree}}", request.commit),
        ],
        128,
    )?;
    if actual != format!("{}\n", request.tree).as_bytes() {
        return Err(rejected());
    }
    Ok(())
}

pub(super) fn hex_string(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn materialize(request: &ReproductionRequestV1, root: &Path) -> Result<BTreeMap<String, String>> {
    let repo = Path::new(&request.repository);
    let tree = process::git(
        repo,
        &[
            "ls-tree",
            "-rz",
            "--full-tree",
            &request.commit,
            "--",
            "site",
            "scripts/build-site.mjs",
        ],
        4 * 1024 * 1024,
    )?;
    let mut materials = BTreeMap::new();
    let mut total = 0;
    for row in tree.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let row = std::str::from_utf8(row).map_err(|_| rejected())?;
        let (meta, name) = row.split_once('\t').ok_or_else(rejected)?;
        let fields = meta.split(' ').collect::<Vec<_>>();
        let path = Path::new(name);
        if fields.len() != 3
            || !matches!(fields[0], "100644" | "100755")
            || fields[1] != "blob"
            || !hex_string(fields[2], 40)
            || path
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
            || path
                .components()
                .any(|c| c.as_os_str() == "node_modules" || c.as_os_str() == ".git")
            || !(name.starts_with("site/") || name == "scripts/build-site.mjs")
            || materials.len() >= 20_000
        {
            return Err(rejected());
        }
        let bytes = process::git(repo, &["cat-file", "blob", fields[2]], MAX_FILE)?;
        total += bytes.len() as u64;
        if total > MAX_MATERIALS {
            return Err(rejected());
        }
        let destination = root.join(path);
        fs::create_dir_all(destination.parent().ok_or_else(rejected)?).map_err(|_| rejected())?;
        fs::write(destination, &bytes).map_err(|_| rejected())?;
        if materials.insert(name.into(), digest(&bytes)).is_some() {
            return Err(rejected());
        }
    }
    for (path, expected) in [
        ("scripts/build-site.mjs", contract::SCRIPT_HASH),
        ("site/package.json", contract::PACKAGE_HASH),
        ("site/bun.lock", contract::LOCK_HASH),
    ] {
        if materials.get(path).map(String::as_str) != Some(expected) {
            return Err(rejected());
        }
    }
    Ok(materials)
}

fn tool(request: &ReproductionRequestV1, root: &Path) -> Result<(std::path::PathBuf, String)> {
    if !cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        return Err(rejected());
    }
    let package = Path::new(&request.esbuild_package);
    canonical_path(package)?;
    if !fs::metadata(package).map_err(|_| rejected())?.is_file()
        || fs::metadata(package).map_err(|_| rejected())?.len() > MAX_FILE
    {
        return Err(rejected());
    }
    let bytes = fs::read(package).map_err(|_| rejected())?;
    if base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&bytes))
        != contract::ESBUILD_INTEGRITY
    {
        return Err(rejected());
    }
    let archive = root.join("verified-esbuild.tgz");
    fs::write(&archive, bytes).map_err(|_| rejected())?;
    // No archive path is extracted to the filesystem. Only this named member
    // of an integrity-pinned package is returned through bounded stdout.
    let executable = process::output(
        process::command(Path::new("/usr/bin/tar"), root)
            .arg("-xOf")
            .arg(&archive)
            .arg("package/bin/esbuild"),
        MAX_FILE,
    )?;
    let executable_hash = digest(&executable);
    let path = root.join("esbuild");
    fs::write(&path, executable).map_err(|_| rejected())?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(|_| rejected())?;
    if process::output(process::command(&path, root).arg("--version"), 128)? != b"0.28.2\n" {
        return Err(rejected());
    }
    Ok((path, executable_hash))
}

pub(super) fn portable_manifest(root: &Path) -> Result<Value> {
    let mut value = pages_deployment::manifest(root)?;
    value.as_object_mut().ok_or_else(rejected)?.remove("root");
    Ok(value)
}

pub(super) fn retained_digest(manifest: &Value) -> Result<String> {
    // The supported recipe's manifest hashes this ordered typed representation.
    #[derive(serde::Serialize)]
    struct Entry<'a> {
        path: &'a str,
        bytes: u64,
        sha256: &'a str,
    }
    let mut entries = manifest["entries"]
        .as_array()
        .ok_or_else(rejected)?
        .iter()
        .map(|e| {
            Ok(Entry {
                path: e["path"].as_str().ok_or_else(rejected)?,
                bytes: e["size"].as_u64().ok_or_else(rejected)?,
                sha256: e["sha256"].as_str().ok_or_else(rejected)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    // The source recipe inventories each directory recursively before visiting
    // its next sibling (feedback/index.html precedes feedback.js). The upload
    // manifest's full-path ordering is a different, independently bound format.
    entries.sort_by(|a, b| a.path.split('/').cmp(b.path.split('/')));
    Ok(digest(&serde_json::to_vec(&entries)?))
}

fn reproduce(request: &ReproductionRequestV1, scratch: &Path) -> Result<(Value, String, String)> {
    let source = scratch.join("source");
    fs::create_dir(&source).map_err(|_| rejected())?;
    let materials = materialize(request, &source).map_err(|_| {
        CliError::Input(
            "Pages reproduction Git materials or supported recipe failed admission".into(),
        )
    })?;
    let (executable, executable_hash) = tool(request, scratch).map_err(|_| {
        CliError::Input(
            "Pages reproduction compiler package failed lock-integrity/platform admission".into(),
        )
    })?;
    let output = source.join("build/site");
    fs::create_dir_all(&output).map_err(|_| rejected())?;
    for name in materials.keys().filter(|n| n.starts_with("site/public/")) {
        let destination = output.join(name.strip_prefix("site/public/").ok_or_else(rejected)?);
        fs::create_dir_all(destination.parent().ok_or_else(rejected)?).map_err(|_| rejected())?;
        fs::copy(source.join(name), destination).map_err(|_| rejected())?;
    }
    process::output(
        process::command(&executable, &source.join("site")).args([
            "worker.js",
            "--bundle",
            "--format=esm",
            "--platform=browser",
            "--target=es2022",
            "--outfile=../build/site/_worker.js",
            "--legal-comments=none",
            "--metafile=../build/metafile.json",
            "--tsconfig-raw={}",
        ]),
        4096,
    )?;
    let metadata: Value = serde_json::from_slice(
        &fs::read(source.join("build/metafile.json")).map_err(|_| rejected())?,
    )?;
    for name in metadata["inputs"].as_object().ok_or_else(rejected)?.keys() {
        if !materials.contains_key(&format!("site/{name}")) {
            return Err(rejected());
        }
    }
    // A dependency outside declared Git materials, or a tool/material change,
    // can never produce a successful authenticated receipt.
    for (name, hash) in &materials {
        if digest(&fs::read(source.join(name)).map_err(|_| rejected())?) != *hash {
            return Err(rejected());
        }
    }
    if digest(&fs::read(&executable).map_err(|_| rejected())?) != executable_hash {
        return Err(rejected());
    }
    Ok((
        portable_manifest(&output)?,
        hash_value(&serde_json::to_value(materials)?)?,
        executable_hash,
    ))
}

pub(super) fn run(
    store: &StateStore,
    graph: &WorkspaceGraph,
    request: ReproductionRequestV1,
) -> Result<ResultEnvelopeV2> {
    store.require_qualifying_evidence_authority()?;
    let helper_tools = process::helper_tools()?;
    validate_source(graph, &request)?;
    let archive = Path::new(&request.artifact_directory);
    canonical_path(archive)?;
    let expected = portable_manifest(archive)?;
    if retained_digest(&expected)? != request.artifact_manifest_sha256 {
        return Err(CliError::Input(
            "Pages retained artifact manifest hash differs from the requested recipe manifest"
                .into(),
        ));
    }
    let started_at = chrono::Utc::now();
    let scratch = tempfile::Builder::new()
        .prefix("cfctl-pages-reproduction-")
        .tempdir()
        .map_err(|_| rejected())?;
    let (artifact, materials_hash, esbuild_sha256) = reproduce(&request, scratch.path())?;
    if artifact != expected || portable_manifest(archive)? != expected {
        return Err(CliError::Input("Fresh Pages reproduction differs from the retained complete artifact; no qualifying receipt was issued".into()));
    }
    validate_source(graph, &request)?;
    if process::helper_tools()? != helper_tools {
        return Err(rejected());
    }
    let receipt = ReproductionReceiptV1 {
        schema_version: 1,
        kind: contract::PRODUCER_ID.into(),
        recipe: contract::RECIPE.into(),
        request,
        run_id: uuid::Uuid::new_v4().to_string(),
        build_identity_hash: build_hash()?,
        producer_contract_hash: producer_hash()?,
        started_at,
        completed_at: chrono::Utc::now(),
        materials_hash,
        esbuild_sha256,
        helper_tools,
        environment: environment(),
        artifact,
    };
    let evidence = store.write_pages_reproduction(&receipt)?;
    let value = serde_json::to_value(receipt)?;
    let mut envelope = ResultEnvelopeV2::success("call", value).with_evidence(evidence);
    envelope.capability_id = Some(contract::PRODUCER_ID.into());
    envelope.verification.state = VerificationState::Passed;
    envelope.verification.basis = Some("Fresh fixed native reproduction from Git objects equals every retained artifact byte; no provider request or historical-build attestation".into());
    Ok(envelope)
}
