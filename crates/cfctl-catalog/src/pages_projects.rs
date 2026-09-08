//! Upstream-derived, closed Pages direct-upload setup operations.
use super::{
    AdapterStatus, BTreeMap, BillingModelV1, CapabilityV1, CostExposureV1, CostV1,
    CreatedResourceContractV1, EffectClass, RiskClass, SamePathReadContractV1, Value,
    official_reference, refresh_dynamic_mutation_contract, request_schema_contract,
    schema_declares_path, success_response_declares_result_fields,
    success_response_declares_result_string_field,
};
use cfctl_core::pages_projects as contract;
use serde_json::json;

pub(super) fn finalize(document: &Value, capabilities: &mut BTreeMap<String, CapabilityV1>) {
    for (source_id, id, method, path) in [
        (
            "pages-project-create-project",
            contract::CREATE_ID,
            "POST",
            contract::COLLECTION,
        ),
        (
            "pages-project-update-project",
            contract::VARIABLES_ID,
            "PATCH",
            contract::DETAIL,
        ),
    ] {
        let Some(mut capability) = capabilities.get(source_id).cloned() else {
            continue;
        };
        let operation = document
            .get("paths")
            .and_then(|paths| paths.get(path))
            .and_then(|item| item.get(method.to_ascii_lowercase()));
        let source_schema =
            operation.and_then(|operation| request_schema_contract(document, operation));
        let creating = id == contract::CREATE_ID;
        let supported = capability.method == method
            && capability.path == path
            && capability.product == "Pages Project"
            && capability.account_scope == "account"
            && capability.permissions == ["Pages Write"]
            && companions_supported(document, capabilities, creating)
            && source_schema.as_ref().is_some_and(|schema| {
                if creating {
                    create_request_supported(schema)
                } else {
                    variables_request_supported(schema)
                }
            })
            && operation
                .is_some_and(|operation| response_supported(document, operation, !creating));
        id.clone_into(&mut capability.id);
        capability.created_resource = None;
        capability.same_path_read = None;
        capability.adapter_status = if supported {
            AdapterStatus::DynamicApi
        } else {
            AdapterStatus::Blocked
        };
        capability.blocked_reason = (!supported).then(||
            "schema drift: bounded Pages setup requires the exact upstream operation, account permissions, closed input subset and observable project readback".to_owned());
        capability.effect = EffectClass::ReversibleWrite;
        capability.cost = CostV1::default();
        capability.cost.billing_model = BillingModelV1::UsageBased;
        capability.cost.exposure = CostExposureV1::DownstreamUsage;
        capability.cost.basis = Some("the bounded API operation has no direct charge and changes no usage model or resource binding; later deployments and Pages Functions usage remain subject to the current account plan".to_owned());
        capability.cost.references = vec![official_reference(
            "Pages Functions pricing",
            "https://developers.cloudflare.com/pages/functions/pricing/",
        )];
        capability.verification.required = true;
        if creating {
            "Create one empty direct-upload Pages project".clone_into(&mut capability.title);
            capability.description = Some("Creates one project on main after exact native absence proof and an execution-boundary recheck. No Git source, automatic build, deployment configuration or deployment is included. Verification binds the returned project ID and a fresh exact-name GET with no Git/build setup.".to_owned());
            capability.aliases = vec!["create direct-upload Pages project".to_owned()];
            capability.request_schema = Some(contract::create_schema());
            capability.risk = RiskClass::CrossConfig;
            contract::CREATE_STRATEGY.clone_into(&mut capability.verification.strategy);
            capability.created_resource = Some(CreatedResourceContractV1 {
                detail_path: contract::DETAIL.to_owned(),
                identity_selector: "project_name".to_owned(),
                response_result_identity_pointer: "/name".to_owned(),
                read_capability_id: contract::READ_ID.to_owned(),
                delete_capability_id: contract::DELETE_ID.to_owned(),
                verified_response_fields: vec!["name".to_owned(), "production_branch".to_owned()],
            });
            capability.rollback.supported = true;
            capability.rollback.strategy =
                Some("delete_created_resource_by_returned_id".to_owned());
            capability.rollback.warning = Some("deleting the exact created project requires a separate reviewed and explicitly approved plan; later deployments would also be removed".to_owned());
        } else {
            "Add production variables to one Pages project".clone_into(&mut capability.title);
            capability.description = Some("Adds only absent production env_vars via protected body input. Fresh native reads at preparation and the execution boundary bind the project ID and unchanged configuration. Existing variables cannot be overwritten or deleted. No preview, Git/build, usage-model or resource-binding changes are admitted. Plain text is compared privately; secret values are write-only and verified by provider acceptance plus name/type readback, not by value or application usability.".to_owned());
            capability.aliases =
                vec!["add Pages production environment variables and secrets".to_owned()];
            capability.request_schema = Some(contract::variables_schema());
            capability.risk = RiskClass::SecretSensitive;
            contract::VARIABLES_STRATEGY.clone_into(&mut capability.verification.strategy);
            capability.same_path_read = Some(SamePathReadContractV1 {
                path: contract::DETAIL.to_owned(),
                read_capability_id: contract::READ_ID.to_owned(),
                verified_response_fields: vec!["deployment_configs".to_owned()],
            });
            capability.rollback.supported = false;
            capability.rollback.strategy = None;
            capability.rollback.warning = Some("removing or replacing variables requires a separately authorized operation; this add-only capability cannot perform compensation, and application usability requires a separately verified deployment".to_owned());
        }
        refresh_dynamic_mutation_contract(&mut capability);
        capabilities.insert(capability.id.clone(), capability);
    }
}

fn companions_supported(
    document: &Value,
    capabilities: &BTreeMap<String, CapabilityV1>,
    creating: bool,
) -> bool {
    let read = capabilities.get(contract::READ_ID);
    read.is_some_and(|read| {
        read.method == "GET"
            && read.path == contract::DETAIL
            && read.product == "Pages Project"
            && read.account_scope == "account"
            && !read.mutating
            && read.request_schema.is_none()
            && read
                .selectors
                .iter()
                .all(|selector| selector.location == "path")
    }) && document["paths"][contract::DETAIL]
        .get("get")
        .is_some_and(|operation| response_supported(document, operation, !creating))
        && (!creating
            || capabilities.get(contract::DELETE_ID).is_some_and(|delete| {
                delete.method == "DELETE"
                    && delete.path == contract::DETAIL
                    && delete.permissions == ["Pages Write"]
                    && delete.account_scope == "account"
            }))
}

fn response_supported(document: &Value, operation: &Value, with_variables: bool) -> bool {
    ["id", "name", "production_branch"]
        .iter()
        .all(|field| success_response_declares_result_string_field(document, operation, field))
        && success_response_declares_result_fields(document, operation, &["source", "build_config"])
        && (!with_variables
            || operation
                .get("responses")
                .and_then(Value::as_object)
                .is_some_and(|responses| {
                    responses
                        .iter()
                        .filter(|(status, _)| status.starts_with('2'))
                        .any(|(_, response)| {
                            response
                                .pointer("/content/application~1json/schema")
                                .is_some_and(|schema| {
                                    schema_declares_path(
                                        document,
                                        schema,
                                        &["result", "deployment_configs", "production", "env_vars"],
                                        0,
                                    )
                                })
                        })
                }))
}

/// Merge only object intersections. Ambiguous unions or conflicting definitions
/// do not establish a safe writable subset.
fn object_schema(schema: &Value) -> Option<Value> {
    if schema.get("oneOf").is_some()
        || schema.get("anyOf").is_some()
        || schema.get("type").is_some_and(|kind| kind != "object")
    {
        return None;
    }
    let mut result = schema.clone();
    result.as_object_mut()?.remove("allOf");
    for member in schema
        .get("allOf")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let member = object_schema(member)?;
        for (key, value) in member.as_object()? {
            match key.as_str() {
                "properties" => {
                    if result.get(key).is_none() {
                        result[key] = json!({});
                    }
                    for (name, property) in value.as_object()? {
                        if result[key]
                            .get(name)
                            .is_some_and(|existing| existing != property)
                        {
                            return None;
                        }
                        result[key][name] = property.clone();
                    }
                }
                "required" => {
                    if result.get(key).is_none() {
                        result[key] = json!([]);
                    }
                    let required = result[key].as_array_mut()?;
                    for field in value.as_array()? {
                        if !required.contains(field) {
                            required.push(field.clone());
                        }
                    }
                }
                _ => {
                    if result.get(key).is_some_and(|existing| existing != value) {
                        return None;
                    }
                    result[key] = value.clone();
                }
            }
        }
    }
    result.get("properties")?.as_object()?;
    Some(result)
}

fn required_subset(schema: &Value, allowed: &[&str]) -> bool {
    schema.get("required").is_none_or(|required| {
        required.as_array().is_some_and(|fields| {
            fields
                .iter()
                .all(|field| field.as_str().is_some_and(|name| allowed.contains(&name)))
        })
    })
}

fn create_request_supported(schema: &Value) -> bool {
    let Some(schema) = object_schema(schema) else {
        return false;
    };
    required_subset(&schema, &["name", "production_branch"])
        && schema["required"].as_array().is_some_and(|fields| {
            ["name", "production_branch"]
                .iter()
                .all(|field| fields.contains(&json!(field)))
        })
        && schema["properties"]["name"]["type"] == "string"
        && schema["properties"]["production_branch"]["type"] == "string"
        && schema["properties"]["production_branch"]
            .get("enum")
            .is_none_or(|values| {
                values
                    .as_array()
                    .is_some_and(|values| values.contains(&json!("main")))
            })
}

fn variables_request_supported(schema: &Value) -> bool {
    let mut current = schema.clone();
    for field in ["deployment_configs", "production", "env_vars"] {
        let Some(object) = object_schema(&current) else {
            return false;
        };
        if !required_subset(&object, &[field]) {
            return false;
        }
        let Some(child) = object["properties"].get(field) else {
            return false;
        };
        current = child.clone();
    }
    if current["type"] != "object" {
        return false;
    }
    let entry = &current["additionalProperties"];
    let Some(variants) = entry["oneOf"]
        .as_array()
        .filter(|variants| variants.len() == 2)
    else {
        return false;
    };
    ["plain_text", "secret_text"].iter().all(|kind| {
        variants.iter().any(|variant| {
            variant["type"] == "object"
                && required_subset(variant, &["type", "value"])
                && variant["required"].as_array().is_some_and(|fields| {
                    fields.len() == 2
                        && fields.contains(&json!("type"))
                        && fields.contains(&json!("value"))
                })
                && variant["properties"]["type"]["enum"] == json!([kind])
                && variant["properties"]["type"]["type"] == "string"
                && variant["properties"]["value"]["type"] == "string"
        })
    })
}
