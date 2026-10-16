use super::{ExpectedDeployment, protected_snapshot, verified_identity};
use serde_json::{Value, json};

const ID: &str = "22222222-2222-4222-8222-222222222222";
const COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn project() -> Value {
    json!({"name":"aos-web","production_branch":"main","subdomain":"aos-web.pages.dev",
        "canonical_deployment":{"id":"11111111-1111-4111-8111-111111111111",
            "project_name":"aos-web","environment":"production","url":"https://old.aos-web.pages.dev",
            "deployment_trigger":{"metadata":{"branch":"main","commit_hash":COMMIT}}},
        "deployment_configs":{"production":{"env_vars":{"PRIVATE":{"value":"must-not-project"}}}}})
}

fn deployment() -> Value {
    json!({"id":ID,"project_name":"aos-web","environment":"preview",
        "url":"https://abc123.aos-web.pages.dev","aliases":["https://provider-selected.aos-web.pages.dev"],
        "deployment_trigger":{"metadata":{"branch":"feature/Stage_Name","commit_hash":COMMIT}},
        "latest_stage":{"name":"deploy","status":"success"}})
}

fn helper() -> Value {
    // Wrangler 4.107's detailed receipt has production_branch and commit_hash,
    // but no deployment_trigger.metadata.branch. The exact API read proves it.
    json!({"deployment_id":ID,"pages_project":"aos-web","environment":"preview",
        "production_branch":"main","url":"https://abc123.aos-web.pages.dev",
        "alias":"https://provider-selected.aos-web.pages.dev",
        "deployment_trigger":{"metadata":{"commit_hash":COMMIT}}})
}

fn verify(deployment: &Value, helper: &Value, observed: &Value) -> bool {
    verified_identity(
        &ExpectedDeployment {
            account: "account-a",
            project: "aos-web",
            deployment_id: ID,
            branch: "feature/Stage_Name",
            commit: COMMIT,
        },
        helper,
        deployment,
        &protected_snapshot(&project(), "aos-web", "main").expect("protected"),
        observed,
    )
    .is_ok()
}

#[test]
fn exact_identity_projects_only_provider_urls_and_protected_production() {
    let protected = protected_snapshot(&project(), "aos-web", "main").expect("projection");
    assert!(!protected.to_string().contains("must-not-project"));
    let result = verified_identity(
        &ExpectedDeployment {
            account: "account-a",
            project: "aos-web",
            deployment_id: ID,
            branch: "feature/Stage_Name",
            commit: COMMIT,
        },
        &helper(),
        &deployment(),
        &protected,
        &project(),
    )
    .expect("exact preview");
    assert_eq!(
        result.branch_alias.as_deref(),
        Some("https://provider-selected.aos-web.pages.dev")
    );
    assert_eq!(result.immutable_url, "https://abc123.aos-web.pages.dev");
    assert!(result.canonical_production_preserved);
    assert!(
        !serde_json::to_string(&result)
            .expect("safe receipt")
            .contains("must-not-project")
    );
}

#[test]
fn changed_production_or_project_projection_refuses_success() {
    for pointer in [
        "/production_branch",
        "/canonical_deployment/id",
        "/canonical_deployment/deployment_trigger/metadata/commit_hash",
        "/subdomain",
        "/name",
    ] {
        let mut observed = project();
        *observed.pointer_mut(pointer).expect("fixture field") = json!("changed");
        assert!(!verify(&deployment(), &helper(), &observed), "{pointer}");
    }
    let mut absent = project();
    absent
        .as_object_mut()
        .expect("project")
        .remove("canonical_deployment");
    assert!(protected_snapshot(&absent, "aos-web", "main").is_err());
    absent["canonical_deployment"] = Value::Null;
    assert!(protected_snapshot(&absent, "aos-web", "main").is_ok());
}

#[test]
fn wrong_exact_identity_or_terminal_stage_cannot_pass() {
    for pointer in [
        "/id",
        "/project_name",
        "/environment",
        "/deployment_trigger/metadata/branch",
        "/deployment_trigger/metadata/commit_hash",
        "/latest_stage/name",
        "/latest_stage/status",
    ] {
        let mut value = deployment();
        *value.pointer_mut(pointer).expect("fixture field") = json!("wrong");
        assert!(!verify(&value, &helper(), &project()), "{pointer}");
    }
    let mut value = helper();
    value["production_branch"] = json!("feature/Stage_Name");
    assert!(!verify(&deployment(), &value, &project()));
}

#[test]
fn aliases_are_exact_provider_values_never_guessed_or_cross_project() {
    for alias in [
        "http://stage.aos-web.pages.dev",
        "https://stage.other.pages.dev",
        "https://stage.aos-web.pages.dev/path",
        "https://stage.aos-web.pages.dev?x=1",
        "https://user@stage.aos-web.pages.dev",
        "https://abc123.aos-web.pages.dev",
    ] {
        let mut value = deployment();
        value["aliases"] = json!([alias]);
        assert!(!verify(&value, &helper(), &project()), "{alias}");
    }
    for aliases in [
        json!([]),
        json!([null]),
        json!([
            "https://provider-selected.aos-web.pages.dev",
            "https://provider-selected.aos-web.pages.dev"
        ]),
    ] {
        let mut value = deployment();
        value["aliases"] = aliases;
        assert!(!verify(&value, &helper(), &project()));
    }
    let mut wrong_helper = helper();
    wrong_helper["alias"] = json!("https://guessed-stage.aos-web.pages.dev");
    assert!(!verify(&deployment(), &wrong_helper, &project()));
    wrong_helper
        .as_object_mut()
        .expect("helper")
        .remove("alias");
    assert!(verify(&deployment(), &wrong_helper, &project()));
    let mut multiple = deployment();
    multiple["aliases"] = json!([
        "https://one.aos-web.pages.dev",
        "https://two.aos-web.pages.dev"
    ]);
    assert!(!verify(&multiple, &wrong_helper, &project()));
}
