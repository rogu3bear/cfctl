//! Bounded request-body and writable JSON-schema normalization.

use super::{CatalogError, Result, resolve_local_schema};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

pub(super) fn request_schema_contract(
    document: &Value,
    operation: &Value,
) -> Result<Option<Value>> {
    let Some(body) = operation.get("requestBody") else {
        return Ok(None);
    };
    let body = resolve_request_body(document, body, 0)?;
    if !body.is_object()
        || !body.get("content").is_some_and(Value::is_object)
        || body
            .get("required")
            .is_some_and(|required| !required.is_boolean())
    {
        return Err(CatalogError::InvalidRequestBodyObject);
    }
    let Some(schema) = body.pointer("/content/application~1json/schema") else {
        return Ok(None);
    };
    let mut active_references = BTreeSet::new();
    let mut contract =
        normalize_request_schema_contract(document, schema, 0, &mut active_references)
            .as_object()
            .cloned()
            .unwrap_or_default();
    contract.insert(
        "x-cfctl-body-required".to_owned(),
        body.get("required").cloned().unwrap_or(Value::Bool(false)),
    );
    Ok(Some(Value::Object(contract)))
}

// Request Body Objects and Reference Objects are distinct OpenAPI nodes. Resolve
// only local references, with the same sixteen-hop bound as response references.
// Invalid indirection must never look like an absent, optional request body.
fn resolve_request_body<'a>(
    document: &'a Value,
    body: &'a Value,
    depth: usize,
) -> Result<&'a Value> {
    let Some(reference) = body.get("$ref") else {
        return Ok(body);
    };
    let reference = reference.as_str().ok_or_else(|| {
        CatalogError::UnsupportedRequestBodyReference("non-string $ref".to_owned())
    })?;
    if depth >= MAX_REQUEST_SCHEMA_CONTRACT_DEPTH {
        return Err(CatalogError::RequestBodyReferenceDepth(
            reference.to_owned(),
        ));
    }
    let pointer = reference
        .strip_prefix('#')
        .filter(|pointer| pointer.starts_with('/'))
        .ok_or_else(|| CatalogError::UnsupportedRequestBodyReference(reference.to_owned()))?;
    let resolved = document
        .pointer(pointer)
        .ok_or_else(|| CatalogError::UnresolvedRequestBodyReference(reference.to_owned()))?;
    resolve_request_body(document, resolved, depth + 1)
}

pub(super) const MAX_REQUEST_SCHEMA_CONTRACT_DEPTH: usize = 16;

pub(super) fn normalize_request_schema_contract(
    document: &Value,
    schema: &Value,
    depth: usize,
    active_references: &mut BTreeSet<String>,
) -> Value {
    let reference = schema
        .get("$ref")
        .and_then(Value::as_str)
        .filter(|reference| reference.starts_with("#/"));
    let inserted_reference =
        reference.is_some_and(|reference| active_references.insert(reference.to_owned()));
    if reference.is_some() && !inserted_reference {
        return Value::Object(Map::new());
    }
    let resolved = resolve_local_schema(document, schema);
    let mut contract = Map::new();
    copy_request_schema_value_constraints(resolved, &mut contract);
    copy_request_schema_required(document, resolved, &mut contract);
    if let Some(additional) = resolved.get("additionalProperties") {
        let additional = if additional.is_object() {
            if depth < MAX_REQUEST_SCHEMA_CONTRACT_DEPTH {
                normalize_request_schema_contract(
                    document,
                    additional,
                    depth + 1,
                    active_references,
                )
            } else {
                Value::Object(Map::new())
            }
        } else {
            additional.clone()
        };
        contract.insert("additionalProperties".to_owned(), additional);
    }
    if depth < MAX_REQUEST_SCHEMA_CONTRACT_DEPTH {
        for composition in ["allOf", "oneOf", "anyOf"] {
            if let Some(members) = resolved.get(composition).and_then(Value::as_array) {
                contract.insert(
                    composition.to_owned(),
                    Value::Array(
                        members
                            .iter()
                            .map(|member| {
                                normalize_request_schema_contract(
                                    document,
                                    member,
                                    depth + 1,
                                    active_references,
                                )
                            })
                            .collect(),
                    ),
                );
            }
        }
        if let Some(properties) = resolved.get("properties").and_then(Value::as_object) {
            let properties = properties
                .iter()
                .filter(|(_, property)| !request_property_is_read_only(document, property))
                .map(|(name, property)| {
                    (
                        name.clone(),
                        normalize_request_schema_contract(
                            document,
                            property,
                            depth + 1,
                            active_references,
                        ),
                    )
                })
                .collect();
            contract.insert("properties".to_owned(), Value::Object(properties));
        }
        if let Some(items) = resolved.get("items") {
            contract.insert(
                "items".to_owned(),
                normalize_request_schema_contract(document, items, depth + 1, active_references),
            );
        }
    }
    if inserted_reference && let Some(reference) = reference {
        active_references.remove(reference);
    }
    Value::Object(contract)
}

fn copy_request_schema_value_constraints(resolved: &Value, contract: &mut Map<String, Value>) {
    for key in [
        "type",
        "writeOnly",
        "enum",
        "format",
        "nullable",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "minLength",
        "maxLength",
        "minItems",
        "maxItems",
        "uniqueItems",
        "minProperties",
        "maxProperties",
    ] {
        if let Some(value) = resolved.get(key) {
            contract.insert(key.to_owned(), value.clone());
        }
    }
    if let Some(multiple) = resolved
        .get("multipleOf")
        .filter(|value| value.as_f64().is_some_and(|multiple| multiple > 0.0))
    {
        contract.insert("multipleOf".to_owned(), multiple.clone());
    }
}

fn copy_request_schema_required(
    document: &Value,
    resolved: &Value,
    contract: &mut Map<String, Value>,
) {
    let Some(required) = resolved.get("required").and_then(Value::as_array) else {
        return;
    };
    let properties = resolved.get("properties").and_then(Value::as_object);
    let writable_required = required
        .iter()
        .filter(|entry| {
            entry.as_str().is_none_or(|name| {
                properties
                    .and_then(|properties| properties.get(name))
                    .is_none_or(|property| !request_property_is_read_only(document, property))
            })
        })
        .cloned()
        .collect();
    contract.insert("required".to_owned(), Value::Array(writable_required));
}

fn request_property_is_read_only(document: &Value, property: &Value) -> bool {
    resolve_local_schema(document, property)
        .get("readOnly")
        .and_then(Value::as_bool)
        == Some(true)
}
