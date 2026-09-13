//! Closed non-secret observations; never an effective isolation verdict.
use serde_json::{Value, json};

fn text(value: &Value) -> bool {
    value.as_str().is_some_and(|s| {
        !s.is_empty()
            && s.len() <= 512
            && s.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
            && !matches!(s, "[SUNK]" | "[REDACTED]")
    })
}

fn observed(value: Option<&Value>, valid: impl FnOnce(&Value) -> Option<Value>) -> Value {
    match value {
        None => json!({"state":"missing"}),
        Some(Value::Null) => json!({"state":"null"}),
        Some(v) => valid(v).map_or_else(
            || json!({"state":"unknown"}),
            |v| json!({"state":"observed","observed":v}),
        ),
    }
}

fn patterns(value: &Value) -> Option<Value> {
    let entries = value.as_array()?;
    if entries.len() > 256 || !entries.iter().all(text) {
        return None;
    }
    Some(Value::Array(
        entries.iter().map(|v| json!({"pattern":v})).collect(),
    ))
}

fn bindings(value: &Value, field: &str) -> Option<Value> {
    let entries = value.as_object()?;
    if entries.len() > 256 {
        return None;
    }
    let mut result = Vec::new();
    for (name, entry) in entries {
        if !super::valid_variable_name(name) {
            return None;
        }
        let id = entry.get(field)?.as_str()?;
        let valid = if field == "id" {
            id.len() == 36
                && id.bytes().enumerate().all(|(i, b)| {
                    if [8, 13, 18, 23].contains(&i) {
                        b == b'-'
                    } else {
                        b.is_ascii_hexdigit()
                    }
                })
        } else {
            (3..=63).contains(&id.len())
                && id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        };
        if !valid {
            return None;
        }
        result.push(json!({"binding":name,"resource_id":id}));
    }
    Some(Value::Array(result))
}

static INVALID_PARENT: Value = Value::String(String::new());

// Invalid ancestors carry their unavailable state to descendants.
fn child<'a>(parent: Option<&'a Value>, key: &str) -> Option<&'a Value> {
    match parent {
        Some(Value::Object(map)) => map.get(key),
        Some(Value::Null) => Some(&Value::Null),
        Some(_) => Some(&INVALID_PARENT),
        None => None,
    }
}

fn descend<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter()
        .try_fold(value, |parent, key| child(Some(parent), key))
}

fn environment(value: Option<&Value>) -> Value {
    observed(value, |v| {
        let env = v.as_object()?;
        Some(json!({
            "d1_databases":observed(env.get("d1_databases"), |v| bindings(v,"id")),
            "r2_buckets":observed(env.get("r2_buckets"), |v| bindings(v,"name")),
            "variables":observed(env.get("env_vars"), |v| {
                let vars=v.as_object()?;
                if vars.len()>256 {return None;}
                Some(Value::Array(vars.iter().map(|(name,entry)| json!({
                    "name":if super::valid_variable_name(name) {name.as_str()} else {"[UNRECOGNIZED]"},
                    "type":entry.get("type").and_then(Value::as_str).filter(|s| matches!(*s,"plain_text"|"secret_text"))
                })).collect()))
            })
        }))
    })
}

/// Must be called on the raw exact-project GET result before generic redaction.
/// The enclosing governed receipt binds account, profile, catalog and timestamp.
#[must_use]
pub fn configuration_metadata(project: &Value) -> Value {
    let source = descend(project, &["source", "config"]);
    let mut triggers = serde_json::Map::new();
    for key in [
        "deployments_enabled",
        "production_deployments_enabled",
        "pr_comments_enabled",
    ] {
        triggers.insert(
            key.into(),
            observed(child(source, key), |v| v.as_bool().map(Value::Bool)),
        );
    }
    for key in [
        "preview_branch_includes",
        "preview_branch_excludes",
        "path_includes",
        "path_excludes",
    ] {
        triggers.insert(key.into(), observed(child(source, key), patterns));
    }
    triggers.insert(
        "preview_deployment_setting".into(),
        observed(child(source, "preview_deployment_setting"), |v| {
            v.as_str()
                .filter(|s| matches!(*s, "all" | "none" | "custom"))
                .map(|s| json!(s))
        }),
    );
    json!({"schema_version":1,"provenance":"exact_project_get_observed_configuration",
        "effective_isolation":"unknown","precedence_resolved":false,
        "public_value_comparison":"not_admitted","binding_coverage":"d1_and_r2_only",
        "project_name":observed(project.get("name"), |v| v.as_str().filter(|s|super::valid_project_name(s)).map(|s|json!(s))),
        "production_branch":observed(project.get("production_branch"), |v|text(v).then(||v.clone())),
        "triggers":triggers,
        "production":environment(descend(project, &["deployment_configs", "production"])),
        "preview":environment(descend(project, &["deployment_configs", "preview"])),
        "top_level":environment(Some(project))})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_preserves_patterns_and_binding_identity_without_values() {
        let result = configuration_metadata(&json!({"name":"farm","production_branch":"main",
            "source":{"config":{"preview_branch_includes":["preview/*"],"deployments_enabled":true}},
            "deployment_configs":{"preview":{"d1_databases":{"DB":{"id":"11111111-2222-4333-8444-555555555555"}},
            "r2_buckets":{"BUCKET":{"name":"private-bucket"}},"env_vars":{"ACCESS_AUD":{"type":"secret_text","value":"CANARY"}}}}}));
        assert_eq!(
            result["triggers"]["preview_branch_includes"]["observed"][0]["pattern"],
            "preview/*"
        );
        assert_eq!(
            result["preview"]["observed"]["variables"]["observed"][0]["name"],
            "ACCESS_AUD"
        );
        assert_eq!(
            result["preview"]["observed"]["d1_databases"]["observed"][0]["resource_id"],
            "11111111-2222-4333-8444-555555555555"
        );
        assert!(!result.to_string().contains("CANARY"));
        assert_eq!(result["effective_isolation"], "unknown");
    }

    #[test]
    fn metadata_distinguishes_missing_null_empty_and_malformed() {
        let result = configuration_metadata(&json!({"deployment_configs":{"production":null,
            "preview":{"d1_databases":{},"r2_buckets":{"BAD":{"name":"CANARY/secret"}},"env_vars":"CANARY"}},
            "source":{"config":{"path_includes":["safe",42],"path_excludes":[]}}}));
        assert_eq!(result["production"]["state"], "null");
        assert_eq!(
            result["preview"]["observed"]["d1_databases"]["observed"],
            json!([])
        );
        assert_eq!(
            result["preview"]["observed"]["r2_buckets"]["state"],
            "unknown"
        );
        assert_eq!(result["triggers"]["path_includes"]["state"], "unknown");
        assert_eq!(result["triggers"]["path_excludes"]["observed"], json!([]));
        assert_eq!(
            result["triggers"]["deployments_enabled"]["state"],
            "missing"
        );
        assert!(!result.to_string().contains("CANARY"));
    }

    #[test]
    fn invalid_parent_states_are_not_missing_children() {
        for (parent, state) in [
            (Value::Null, "null"),
            (json!(42), "unknown"),
            (json!([]), "unknown"),
        ] {
            let result =
                configuration_metadata(&json!({"deployment_configs":parent,"source":parent}));
            assert_eq!(result["production"]["state"], state);
            assert_eq!(result["preview"]["state"], state);
            assert_eq!(result["triggers"]["deployments_enabled"]["state"], state);
            assert_eq!(result["triggers"]["path_includes"]["state"], state);
        }
    }
}
