//! Closed, initially deny-all Access application creation for Maildesk.
use super::{
    ACCESS_APP_COLLECTION_PATH, ACCESS_APP_DETAIL_PATH, ACCESS_APP_READ_CAPABILITY_ID,
    AdapterStatus, BTreeMap, BillingModelV1, CapabilityV1, CostExposureV1,
    CreatedResourceContractV1, EffectClass, KnowledgeReferenceV1, RiskClass, Value,
    access_application_missing_readback_fields, access_application_owned_whole_host_schema,
    access_application_read_identity_supported, access_application_source_request_body_compatible,
    refresh_dynamic_mutation_contract, success_response_declares_result_string_field,
};

pub const ACCESS_APP_CREATE_OWNED_ID: &str =
    "access-applications-create-owned-self-hosted-whole-host";

/// Explicit whole-host application state; policies are created separately after
/// the returned application identity has been verified. Deprecated duplicate
/// hostname fields are omitted because Cloudflare gives destinations precedence.
#[must_use]
pub fn access_application_create_owned_schema() -> Value {
    let mut schema = access_application_owned_whole_host_schema();
    let Some(required) = schema["required"].as_array_mut() else {
        return Value::Bool(false);
    };
    required.retain(|field| field != "self_hosted_domains");
    let required = required.clone();
    let Some(fields) = schema["properties"].as_object_mut() else {
        return Value::Bool(false);
    };
    fields.retain(|name, _| {
        required
            .iter()
            .any(|field| field.as_str() == Some(name.as_str()))
    });
    fields.insert(
        "policies".to_owned(),
        serde_json::json!({"type":"array","maxItems":0}),
    );
    fields.insert(
        "options_preflight_bypass".to_owned(),
        serde_json::json!({"type":"boolean","enum":[false]}),
    );
    schema
}

pub(super) fn finalize_owned_create(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    let Some(mut capability) = capabilities
        .get("access-applications-add-an-application")
        .cloned()
    else {
        return;
    };
    let schema = access_application_create_owned_schema();
    let Some(properties) = schema["properties"].as_object() else {
        return;
    };
    let mut fields = properties.keys().cloned().collect::<Vec<_>>();
    fields.sort();
    let source_schema = document.pointer("/paths/~1accounts~1{account_id}~1access~1apps/post/requestBody/content/application~1json/schema");
    let supported = capability.method == "POST"
        && capability.path == ACCESS_APP_COLLECTION_PATH
        && capability.account_scope == "account"
        && capability.product == "Access applications"
        && capability.created_resource.is_some()
        && document
            .pointer("/paths/~1accounts~1{account_id}~1access~1apps/post")
            .is_some_and(|operation| {
                success_response_declares_result_string_field(document, operation, "id")
            })
        && capabilities
            .get("access-applications-delete-an-access-application")
            .is_some_and(|delete| {
                delete.method == "DELETE" && delete.path == ACCESS_APP_DETAIL_PATH
            })
        && capabilities
            .get("access-applications-list-access-applications")
            .is_some_and(|read| {
                read.method == "GET"
                    && read.path == ACCESS_APP_COLLECTION_PATH
                    && read.account_scope == "account"
                    && !read.mutating
                    && read.request_schema.is_none()
            })
        && access_application_read_identity_supported(capabilities)
        && source_schema.is_some_and(|source| {
            access_application_source_request_body_compatible(document, source, &schema)
        })
        && access_application_missing_readback_fields(document, "self_hosted", &fields).is_empty();
    ACCESS_APP_CREATE_OWNED_ID.clone_into(&mut capability.id);
    "Create one owned whole-host Access application without policies"
        .clone_into(&mut capability.title);
    capability.description = Some("Creates one exact self-hosted hostname only after a complete account application inventory proves name and hostname absence. The initial empty policy set denies access; create the operator-group policy in a separate reviewed operation after app ID verification. No routes, reusable policies, bypass policies or account settings are changed.".to_owned());
    capability.aliases = vec!["create Maildesk whole-host Access application".to_owned()];
    capability.request_schema = Some(schema);
    capability.risk = RiskClass::IdentityOrOwnership;
    capability.effect = EffectClass::IdentityOrOwnership;
    capability.verification.required = true;
    "created_resource_contains_planned_fields_by_returned_id"
        .clone_into(&mut capability.verification.strategy);
    capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: ACCESS_APP_DETAIL_PATH.to_owned(),
        identity_selector: "app_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        read_capability_id: ACCESS_APP_READ_CAPABILITY_ID.to_owned(),
        delete_capability_id: "access-applications-delete-an-access-application".to_owned(),
        verified_response_fields: fields,
    });
    capability.adapter_status = if supported {
        AdapterStatus::DynamicApi
    } else {
        AdapterStatus::Blocked
    };
    capability.blocked_reason = (!supported).then(|| "schema drift: owned Access create requires the exact account POST, observable closed self-hosted fields and governed detail/delete contracts".to_owned());
    refresh_dynamic_mutation_contract(&mut capability);
    capabilities.insert(capability.id.clone(), capability);
}

/// Govern Access application creation. The delete side is already governed by
/// the generic exact-resource path; the get and list readbacks exist. Create
/// stays blocked under the generic binder because the request body is a 13-way
/// `anyOf` over app types with no universally-required field — the generic
/// union of variant fields is not an honest verified set. This finalizer binds
/// a curated created-resource contract over `name` and `type`, which are
/// present in every variant and declared on both the create and get responses,
/// and routes it to a dedicated curated-fields strategy. Update stays blocked:
/// there is no honest universal update-field contract across the union.
pub(super) fn finalize_access_application_create_contract(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    let read_supported = capabilities
        .get("access-applications-get-an-access-application")
        .is_some_and(|capability| {
            capability.method == "GET"
                && capability.path == ACCESS_APP_DETAIL_PATH
                && capability.product == "Access applications"
                && capability
                    .selectors
                    .iter()
                    .all(|selector| selector.location == "path")
        })
        && capabilities
            .get("access-applications-delete-an-access-application")
            .is_some_and(|capability| {
                capability.method == "DELETE" && capability.path == ACCESS_APP_DETAIL_PATH
            });
    if !read_supported {
        return;
    }
    // `name`, `type`, and the returned `id` must be observable on both the
    // create and the detail-read responses for the curated verification to be
    // honest.
    let create_operation = document.pointer("/paths/~1accounts~1{account_id}~1access~1apps/post");
    let read_operation =
        document.pointer("/paths/~1accounts~1{account_id}~1access~1apps~1{app_id}/get");
    let (Some(create_operation), Some(read_operation)) = (create_operation, read_operation) else {
        return;
    };
    let fields_observable =
        ["name", "type"].iter().all(|field| {
            success_response_declares_result_string_field(document, create_operation, field)
                && success_response_declares_result_string_field(document, read_operation, field)
        }) && success_response_declares_result_string_field(document, create_operation, "id")
            && success_response_declares_result_string_field(document, read_operation, "id");
    if !fields_observable {
        return;
    }
    let Some(capability) = capabilities.get_mut("access-applications-add-an-application") else {
        return;
    };
    if capability.method != "POST"
        || capability.path != ACCESS_APP_COLLECTION_PATH
        || capability.product != "Access applications"
        || capability.request_schema.is_none()
    {
        return;
    }
    // Access applications gate authentication in front of resources, so
    // creation is identity-affecting and must land approval-required, never
    // policy auto-execute.
    capability.risk = RiskClass::IdentityOrOwnership;
    capability.effect = EffectClass::IdentityOrOwnership;
    capability.cost = cfctl_core::CostV1::default();
    capability.cost.billing_model = BillingModelV1::Subscription;
    capability.cost.exposure = CostExposureV1::DownstreamUsage;
    capability.cost.basis = Some(
        "creating an Access application has no per-operation charge; Access is seat and plan billed, unaffected by the number of application objects"
            .to_owned(),
    );
    capability.cost.references = vec![KnowledgeReferenceV1 {
        title: "Cloudflare Access pricing".to_owned(),
        url: "https://developers.cloudflare.com/cloudflare-one/policies/access/".to_owned(),
        source: "official Cloudflare docs".to_owned(),
    }];
    capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: ACCESS_APP_DETAIL_PATH.to_owned(),
        identity_selector: "app_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        read_capability_id: "access-applications-get-an-access-application".to_owned(),
        delete_capability_id: "access-applications-delete-an-access-application".to_owned(),
        verified_response_fields: vec!["name".to_owned(), "type".to_owned()],
    });
    "created_access_application_contains_planned_fields_by_returned_id"
        .clone_into(&mut capability.verification.strategy);
    capability.rollback.supported = true;
    capability.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());
    capability.rollback.warning = Some(
        "compensation creates a separate exact Access application delete plan that must be reviewed and explicitly approved; deleting an application removes Access protection and can expose a routed hostname; keep the route dark or independently protected before approving compensation"
            .to_owned(),
    );
    refresh_dynamic_mutation_contract(capability);
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{access_application_owned_whole_host_schema, normalize_openapi};
    use serde_json::json;
    fn fixture() -> Value {
        let properties = json!({
            "name":{"type":"string"},"type":{"type":"string","enum":["self_hosted"]},"domain":{"type":"string"},
            "allowed_idps":{"type":"array","items":{"type":"string"}},
            "app_launcher_visible":{"type":"boolean"},"auto_redirect_to_identity":{"type":"boolean"},
            "destinations":{"type":"array","items":{"type":"object"}},
            "enable_binding_cookie":{"type":"boolean"},"http_only_cookie_attribute":{"type":"boolean"},
            "options_preflight_bypass":{"type":"boolean"},"policies":{"type":"array","items":{"type":"object"}},
            "session_duration":{"type":"string"}
        });
        let mut read_properties = properties.clone();
        read_properties["id"] = json!({"type":"string"});
        let envelope = json!({"type":"object","properties":{"success":{"type":"boolean"},"result":{"type":"object","properties":read_properties}}});
        let account =
            json!({"in":"path","name":"account_id","required":true,"schema":{"type":"string"}});
        let app = json!({"in":"path","name":"app_id","required":true,"schema":{"type":"string"}});
        let mut document =
            json!({"openapi":"3.0.0","info":{"title":"Access fixture","version":"1"},"paths":{}});
        for (method, id, path, params) in [
            (
                "post",
                "access-applications-add-an-application",
                ACCESS_APP_COLLECTION_PATH,
                json!([account.clone()]),
            ),
            (
                "get",
                ACCESS_APP_READ_CAPABILITY_ID,
                ACCESS_APP_DETAIL_PATH,
                json!([account.clone(), app.clone()]),
            ),
            (
                "delete",
                "access-applications-delete-an-access-application",
                ACCESS_APP_DETAIL_PATH,
                json!([account, app]),
            ),
        ] {
            document["paths"][path][method] = json!({"operationId":id,"summary":id,"tags":["Access applications"],
                "x-api-token-group":["Access: Apps and Policies Write"],"parameters":params,
                "responses":{"200":{"description":"OK","content":{"application/json":{"schema":envelope.clone()}}}}});
        }
        let mut list = document["paths"][ACCESS_APP_DETAIL_PATH]["get"].clone();
        list["operationId"] = json!("access-applications-list-access-applications");
        list["parameters"] =
            json!([{"in":"path","name":"account_id","required":true,"schema":{"type":"string"}}]);
        document["paths"][ACCESS_APP_COLLECTION_PATH]["get"] = list;
        document["paths"][ACCESS_APP_COLLECTION_PATH]["post"]["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{"type":"object","properties":properties}}}});
        document
    }
    #[test]
    fn owned_create_derives_closed_deny_all_identity_contract() {
        let snapshot = normalize_openapi(&fixture()).expect("valid test fixture");
        let capability = snapshot
            .get(ACCESS_APP_CREATE_OWNED_ID)
            .expect("valid test fixture");
        assert_eq!(
            capability.adapter_status,
            AdapterStatus::DynamicApi,
            "{:?}",
            capability.blocked_reason
        );
        assert!(
            capability.mutation_contract_gaps().is_empty(),
            "{:?}",
            capability.mutation_contract_gaps()
        );
        assert_eq!(capability.effect, EffectClass::IdentityOrOwnership);
        let schema = capability
            .request_schema
            .as_ref()
            .expect("valid test fixture");
        assert_eq!(schema["properties"]["policies"]["maxItems"], 0);
        assert!(schema["properties"].get("self_hosted_domains").is_none());
        assert_eq!(
            access_application_owned_whole_host_schema()["properties"]["policies"]["minItems"],
            1
        );
        assert!(
            capability
                .rollback
                .warning
                .as_ref()
                .expect("valid test fixture")
                .contains("expose")
        );
    }
    #[test]
    fn owned_create_blocks_when_provider_cannot_observe_or_accept_hostname() {
        for request in [true, false] {
            let mut document = fixture();
            if request {
                document["paths"][ACCESS_APP_COLLECTION_PATH]["post"]["requestBody"]["content"]["application/json"]
                    ["schema"]["properties"]["domain"] = json!({"type":"integer"});
            } else {
                document["paths"][ACCESS_APP_DETAIL_PATH]["get"]["responses"]["200"]["content"]["application/json"]["schema"]["properties"]["result"]["properties"].as_object_mut().expect("valid test fixture").remove("domain");
            }
            let snapshot = normalize_openapi(&document).expect("valid test fixture");
            assert_eq!(
                snapshot
                    .get(ACCESS_APP_CREATE_OWNED_ID)
                    .expect("valid test fixture")
                    .adapter_status,
                AdapterStatus::Blocked
            );
        }
    }
}
