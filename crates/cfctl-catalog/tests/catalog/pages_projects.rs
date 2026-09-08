use super::{AdapterStatus, Value, json, normalize_openapi, pages_project_create_fixture};

const CREATE: &str = "pages-project-create-direct-upload";
const CONFIGURE: &str = "pages-project-add-production-variables";
const COLLECTION: &str = "/accounts/{account_id}/pages/projects";
const DETAIL: &str = "/accounts/{account_id}/pages/projects/{project_name}";

fn fixture() -> Value {
    let mut document = pages_project_create_fixture();
    let env_vars = json!({
        "type":"object",
        "additionalProperties":{
            "type":"object","nullable":true,
            "oneOf":[
                {"type":"object","required":["type","value"],"properties":{
                    "type":{"type":"string","enum":["plain_text"]},
                    "value":{"type":"string"}
                }},
                {"type":"object","required":["type","value"],"properties":{
                    "type":{"type":"string","enum":["secret_text"]},
                    "value":{"type":"string"}
                }}
            ]
        }
    });
    let configs = json!({"type":"object","properties":{
        "preview":{"allOf":[{"type":"object","properties":{"env_vars":env_vars}}]},
        "production":{"allOf":[{"type":"object","properties":{
            "env_vars":env_vars,
            "usage_model":{"type":"string","enum":["standard","bundled","unbound"]}
        }}]}
    }});
    for (path, method) in [(COLLECTION, "post"), (DETAIL, "get")] {
        let result = &mut document["paths"][path][method]["responses"]["200"]["content"]["application/json"]
            ["schema"]["properties"]["result"];
        result["required"] = json!(["id", "name", "production_branch"]);
        result["properties"]["id"] = json!({"type":"string"});
        result["properties"]["deployment_configs"] = configs.clone();
    }
    document["paths"][COLLECTION]["post"]["requestBody"]["content"]["application/json"]["schema"]
        ["properties"]["deployment_configs"] = configs.clone();
    document["paths"][DETAIL]["patch"] = json!({
        "operationId":"pages-project-update-project",
        "summary":"Update project",
        "tags":["Pages Project"],
        "x-api-token-group":["Pages Write"],
        "parameters":document["paths"][DETAIL]["get"]["parameters"],
        "requestBody":{"required":true,"content":{"application/json":{"schema":{
            "type":"object","properties":{"deployment_configs":configs}
        }}}},
        "responses":document["paths"][DETAIL]["get"]["responses"]
    });
    document
}

#[test]
fn pages_setup_catalog_preserves_git_create_and_adds_closed_direct_create() {
    let snapshot = normalize_openapi(&fixture()).expect("Pages fixture normalizes");
    let git = snapshot
        .get("pages-project-create-project")
        .expect("Git create");
    assert_eq!(git.adapter_status, AdapterStatus::DynamicApi);
    assert_eq!(
        git.request_schema.as_ref().expect("Git schema")["required"],
        json!(["name", "production_branch", "build_config", "source"])
    );
    let direct = snapshot
        .get(CREATE)
        .expect("direct-upload create must be discoverable");
    assert_eq!(direct.adapter_status, AdapterStatus::DynamicApi);
    let schema = direct.request_schema.as_ref().expect("direct schema");
    assert_eq!(schema["required"], json!(["name", "production_branch"]));
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["properties"].as_object().expect("fields").len(), 2);
    assert_eq!(
        schema["properties"]["production_branch"]["enum"],
        json!(["main"])
    );
    assert_eq!(direct.cost.maximum, Some(0.0));
    assert!(direct.verification_contract_supported());
    assert!(direct.mutation_contract_gaps().is_empty());
}

#[test]
fn pages_setup_catalog_adds_only_production_variables_with_input_secrecy() {
    let snapshot = normalize_openapi(&fixture()).expect("Pages fixture normalizes");
    let configure = snapshot
        .get(CONFIGURE)
        .expect("production variables must be discoverable");
    assert_eq!(configure.adapter_status, AdapterStatus::DynamicApi);
    let schema = configure
        .request_schema
        .as_ref()
        .expect("configuration schema");
    assert_eq!(schema["required"], json!(["deployment_configs"]));
    assert_eq!(schema["additionalProperties"], false);
    let configs = &schema["properties"]["deployment_configs"];
    assert_eq!(configs["required"], json!(["production"]));
    assert_eq!(configs["additionalProperties"], false);
    assert!(configs["properties"].get("preview").is_none());
    assert!(configure.request_object_field_is_write_only("deployment_configs"));
    assert_eq!(configure.cost.maximum, Some(0.0));
    assert!(configure.verification_contract_supported());
    assert!(configure.mutation_contract_gaps().is_empty());
}

#[test]
fn pages_setup_catalog_blocks_upstream_required_fields_and_readback_drift() {
    let mut source_required = fixture();
    source_required["paths"][COLLECTION]["post"]["requestBody"]["content"]["application/json"]["schema"]
        ["required"] = json!(["name", "production_branch", "source"]);
    let mut missing_id = fixture();
    missing_id["paths"][DETAIL]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
        ["properties"]["result"]["properties"]
        .as_object_mut()
        .expect("read fields")
        .remove("id");
    for document in [source_required, missing_id] {
        let snapshot = normalize_openapi(&document).expect("drift fixture normalizes");
        assert_eq!(
            snapshot
                .get(CREATE)
                .expect("blocked capability stays discoverable")
                .adapter_status,
            AdapterStatus::Blocked
        );
    }
    let mut wrong_type = fixture();
    wrong_type["paths"][DETAIL]["patch"]["requestBody"]["content"]["application/json"]["schema"]
        ["properties"]["deployment_configs"]["properties"]["production"]["allOf"][0]["properties"]
        ["env_vars"]["additionalProperties"]["oneOf"][1]["properties"]["value"]["type"] =
        json!("integer");
    let mut extra_required = fixture();
    extra_required["paths"][DETAIL]["patch"]["requestBody"]["content"]["application/json"]["schema"]
        ["properties"]["deployment_configs"]["properties"]["production"]["allOf"][0]["required"] =
        json!(["usage_model"]);
    for document in [wrong_type, extra_required] {
        let snapshot = normalize_openapi(&document).expect("drift fixture normalizes");
        assert_eq!(
            snapshot
                .get(CONFIGURE)
                .expect("blocked configuration")
                .adapter_status,
            AdapterStatus::Blocked
        );
        assert_eq!(
            snapshot
                .get("pages-project-update-project")
                .expect("broad update remains blocked")
                .adapter_status,
            AdapterStatus::Blocked
        );
    }
}
