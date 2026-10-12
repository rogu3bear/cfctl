#![allow(clippy::expect_used, clippy::wildcard_imports)]
use super::*;
use cfctl_core::d1_read_inventory::D1ReadSourceSelectionV1;
use serde_json::Value;
use std::io::Write as _;

#[tokio::test]
async fn selected_source_rejects_mutations_before_catalog_or_credential_access() {
    use clap::Parser as _;
    let (owner, _, _) = fixture(false);
    let runtime = tempfile::tempdir().expect("runtime");
    let store = super::super::super::tests::authenticated_test_store(RuntimePaths::from_root(
        runtime.path(),
    ));
    store
        .register_workspace(owner.path(), Some("a".repeat(32)))
        .expect("registered owner");
    let head = git(owner.path(), &["rev-parse", "HEAD"]);
    let tree = git(owner.path(), &["rev-parse", "HEAD^{tree}"]);
    let parsed = crate::Cli::try_parse_from([
        "cfctl",
        "call",
        "dns-records-delete",
        "--source-checkout",
        owner.path().to_str().expect("path"),
        "--source-head",
        &head,
        "--source-tree",
        &tree,
    ])
    .expect("public parser");
    let Some(crate::Command::Call(arguments)) = parsed.command else {
        panic!("call");
    };
    let error = Box::pin(super::super::super::call_command::call_command(
        &store, arguments,
    ))
    .await
    .expect_err("write source is not selectable");
    assert!(
        error
            .to_string()
            .contains("one registered D1 read operation owner")
    );
    assert!(
        !store.paths().catalog_file().exists(),
        "failed source admission must not refresh the catalog"
    );
}

#[tokio::test]
async fn ordinary_coverage_authenticates_selected_source_and_rejects_drift() {
    let (owner, input) = sign_layout_fixture();
    let worktree = tempfile::tempdir().expect("worktree parent");
    let selected = worktree.path().join("selected");
    git(
        owner.path(),
        &[
            "worktree",
            "add",
            "--detach",
            selected.to_str().expect("path"),
            "HEAD",
        ],
    );
    let selection = D1ReadSourceSelectionV1 {
        checkout_root: selected.display().to_string(),
        head: git(&selected, &["rev-parse", "HEAD"]),
        tree: git(&selected, &["rev-parse", "HEAD^{tree}"]),
    };
    fs::write(owner.path().join("source.txt"), "preserved owner work").expect("dirty owner");
    let runtime = tempfile::tempdir().expect("runtime");
    let store = super::super::super::tests::authenticated_test_store(RuntimePaths::from_root(
        runtime.path(),
    ));
    store
        .register_workspace(owner.path(), Some("a".repeat(32)))
        .expect("registered owner");
    let capability = cfctl_workspace::load_workspace_d1_read_from_checkout(
        &store.workspace_roots().expect("roots"),
        "example.d1-read-inventory",
        &selection,
        cfctl_workspace::WorkspaceOperationLoad::Execute,
    )
    .expect("selected native source");
    let (validated, observation) = persist_selected_observation(&store, &capability, &input);
    let public_coverage = super::super::super::catalog_commands::catalog_command(
        &store,
        crate::CatalogCommand::Coverage,
    )
    .await
    .expect("public coverage handler");
    let evidence = assert_current_projection(
        &store,
        &public_coverage,
        &observation,
        &input,
        &selection,
        &capability,
    );
    qualify_frozen_sign_consumer(&public_coverage, &evidence, &validated, &selection);
    // Coverage receives no source flags. It must revalidate the authenticated
    // stored binding, rather than treating a base-catalog hash as source proof.
    let pristine = fs::read(selected.join("source.txt")).expect("pristine fixture");
    fs::write(selected.join("source.txt"), "selected source drift").expect("write");
    let drift = super::super::super::catalog_commands::catalog_command(
        &store,
        crate::CatalogCommand::Coverage,
    )
    .await
    .expect("coverage after source drift");
    assert_eq!(
        drift.result["operational_proof"]["latest_scoped_observations"][0]["catalog_current"],
        false
    );
    fs::write(selected.join("source.txt"), pristine).expect("restore test fixture");
    let restored = super::super::super::catalog_commands::catalog_command(
        &store,
        crate::CatalogCommand::Coverage,
    )
    .await
    .expect("coverage after fixture restoration");
    assert_eq!(
        restored.result["operational_proof"]["latest_scoped_observations"][0]["catalog_current"],
        true
    );
    store
        .unregister_workspace(owner.path())
        .expect("withdraw registration");
    let withdrawn = super::super::super::catalog_commands::catalog_command(
        &store,
        crate::CatalogCommand::Coverage,
    )
    .await
    .expect("coverage after owner withdrawal");
    assert_eq!(
        withdrawn.result["operational_proof"]["latest_scoped_observations"][0]["catalog_current"],
        false
    );
}

fn sign_layout_fixture() -> (tempfile::TempDir, CallInput) {
    let (owner, _, input) = fixture(false);
    let inventory_path = ".cfctl/operations/sign-readiness.json";
    fs::rename(
        owner.path().join("inventory.json"),
        owner.path().join(inventory_path),
    )
    .expect("Sign consumer inventory layout");
    let pack_path = owner.path().join(".cfctl/operations/d1-reads.toml");
    let mut pack: toml::Value =
        toml::from_str(&fs::read_to_string(&pack_path).expect("committed pack"))
            .expect("pack TOML");
    pack["operation"][0]["inventory_path"] = toml::Value::String(inventory_path.to_owned());
    fs::write(
        &pack_path,
        toml::to_string(&pack).expect("pack serialization"),
    )
    .expect("Sign consumer pack path");
    commit(owner.path());
    (owner, input)
}

fn assert_current_projection(
    store: &StateStore,
    public_coverage: &ResultEnvelopeV2,
    observation: &ExecutedRead,
    input: &CallInput,
    selection: &D1ReadSourceSelectionV1,
    capability: &CapabilityV1,
) -> Value {
    let proof = &public_coverage.result["operational_proof"];
    let row = &proof["latest_scoped_observations"][0];
    assert_eq!(proof["source"], "local_redacted_evidence_index");
    assert_eq!(proof["proof_projection"]["candidate_failure_count"], 0);
    assert_eq!(row["catalog_current"], true);
    assert_eq!(row["credential_generation_current"], true);
    assert_eq!(row["outcome"], "succeeded");
    assert_eq!(
        row["evidence"]["content_hash"],
        observation.envelope.evidence[0].content_hash
    );
    assert_ne!(
        row["input_hash"],
        cfctl_core::hash_value(&serde_json::to_value(input).expect("input")).expect("hash")
    );
    let guide = super::super::super::guide_generation::guide_document(capability);
    let argv = guide.call_argv.expect("read guide");
    assert!(
        argv.windows(2)
            .any(|a| a == ["--source-head", &selection.head])
    );
    assert!(
        argv.windows(2)
            .any(|a| a == ["--source-tree", &selection.tree])
    );
    let evidence = store
        .read_evidence_value(observation.envelope.evidence[0].content_hash.as_str())
        .expect("authenticated body");
    assert_eq!(evidence["repository_head"], selection.head);
    assert_eq!(evidence["repository_tree"], selection.tree);
    assert!(evidence["source_binding"].is_object());
    evidence
}

fn qualify_frozen_sign_consumer(
    public_coverage: &ResultEnvelopeV2,
    evidence: &Value,
    validated: &ValidatedD1ReadInventory,
    selection: &D1ReadSourceSelectionV1,
) {
    // An explicitly selected application checkout lets the local qualification
    // profile exercise its unchanged consumer against this real authenticated
    // native projection. Portable runs still exercise the public handler above.
    if let Some(root) = std::env::var_os("CFCTL_SIGN_CONSUMER_ROOT") {
        let script = r"
import sys, json
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]) / 'scripts/lib'))
from sign_recovery_evidence import authenticated_body, read_population
p = json.load(sys.stdin)
projection = p['coverage']['result']['operational_proof']
row = projection['latest_scoped_observations'][0]
reference = {k: row[k] for k in ('capability_id','profile_id','credential_generation_id','input_hash','catalog_hash','observed_at')}
reference['evidence_hash'] = row['evidence']['content_hash']
window = {'opened_at': p['body']['started_at'], 'expires_at': row['observed_at']}
body = authenticated_body(projection['latest_scoped_observations'], reference, p['account'], window)
assert body == p['body']
declaration = {'target': {'account_id': p['account'], 'database_id': p['database']}, 'source': {'commit': p['head'], 'tree': p['tree']}}
queries = p['inventory']['queries']
expected = {queries[0]['id']: [{'name':'items'}], queries[1]['id']: [{'n':0}]}
read_population(body, declaration, Path(p['checkout']), p['inventory'], expected)
print('frozen Sign authenticated_body/read_population accepted native selected-source projection')
";
        let mut child = Command::new("python3")
            .args(["-c", script])
            .arg(root)
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("actual Sign consumer");
        let payload = json!({"coverage":public_coverage,"body":evidence,"account":validated.contract().operation.account_id,"database":validated.contract().operation.database_id,
            "head":selection.head,"tree":selection.tree,"checkout":selection.checkout_root,"inventory":validated.contract().inventory});
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(&serde_json::to_vec(&payload).expect("payload"))
            .expect("send actual projection");
        let output = child.wait_with_output().expect("consumer terminal");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("accepted native selected-source projection")
        );
    }
}

fn persist_selected_observation(
    store: &StateStore,
    capability: &CapabilityV1,
    input: &CallInput,
) -> (ValidatedD1ReadInventory, ExecutedRead) {
    let validated = d1_read_inventory::validate(capability, input).expect("native population");
    let mut catalog = catalog();
    catalog.refresh_hash().expect("valid catalog hash");
    store
        .write_json(&store.paths().catalog_file(), &catalog)
        .expect("cached catalog");
    let mut profiles = ProfilesConfig::default();
    profiles.profiles.insert(profile().id.clone(), profile());
    profiles.save(store).expect("profile generation");
    let attestation =
        super::super::super::plan_commands::observation_attestation(store, capability)
            .expect("authority");
    let scoped = store.with_observation_attestation(&attestation);
    let observation = persist(
        &scoped,
        &catalog,
        capability,
        &validated,
        &profile(),
        Utc::now(),
        &result(&validated),
    )
    .expect("actual native evidence");
    crate::telemetry_product::record_operational_proof(
        &scoped,
        &catalog,
        capability,
        input,
        Some(&profile().credential_generation_id.expect("generation")),
        &observation.envelope,
    )
    .expect("authenticated index");
    (validated, observation)
}
