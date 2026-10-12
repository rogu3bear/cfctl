//! Source oracle identity; native row/type validation remains with the read compiler.
use std::path::Path;

use cfctl_core::{
    d1_read_inventory::D1ReadInventoryV1, hash_value, workspace_d1::transition::Source,
};
use serde_json::Value;

use super::{Result, WorkspaceOperationLoad, invalid, source_bytes};

pub(super) fn bind(
    root: &Path,
    source: &Source,
    expected: &str,
    inventory: &D1ReadInventoryV1,
    mode: WorkspaceOperationLoad,
) -> Result<()> {
    let value: Value = serde_json::from_slice(&source_bytes(root, source, mode)?)
        .map_err(|_| invalid("qualification oracle is not JSON"))?;
    validate(&value, expected, inventory)
}

fn validate(value: &Value, expected: &str, inventory: &D1ReadInventoryV1) -> Result<()> {
    let entries = value.as_array().ok_or_else(|| {
        invalid("qualification oracle must be the complete native query population")
    })?;
    if entries.len() != inventory.queries.len()
        || hash_value(value).map_err(|_| invalid("qualification oracle digest failed"))? != expected
    {
        return Err(invalid(
            "qualification oracle population or semantic digest differs",
        ));
    }
    for (entry, query) in entries.iter().zip(&inventory.queries) {
        let rows = entry
            .get("rows")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("qualification oracle rows missing"))?;
        if entry.as_object().is_none_or(|object| object.len() != 3)
            || entry.get("query_id").and_then(Value::as_str) != Some(query.id.as_str())
            || entry.get("query_sha256").and_then(Value::as_str) != Some(query.sha256.as_str())
            || (rows.len() as u64) < query.output.min_rows
            || (rows.len() as u64) > query.output.max_rows
            || rows.iter().any(|row| {
                row.as_object().is_none_or(|object| {
                    object.len() != query.output.columns.len()
                        || query
                            .output
                            .columns
                            .iter()
                            .any(|column| !object.contains_key(&column.name))
                })
            })
        {
            return Err(invalid(
                "qualification oracle query order, source, rows or columns differ",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{D1ReadInventoryV1, Value, hash_value, validate};
    use serde_json::json;

    #[test]
    fn oracle_rejects_missing_query_reordered_identity_and_changed_digest() {
        let mut inventory: D1ReadInventoryV1 = serde_json::from_slice(include_bytes!(
            "../../tests/fixtures/d1-reads/inventory.json"
        ))
        .expect("inventory");
        inventory.queries.truncate(1);
        let query = &inventory.queries[0];
        let rows = (0..query.output.min_rows)
            .map(|_| {
                Value::Object(
                    query
                        .output
                        .columns
                        .iter()
                        .map(|column| (column.name.clone(), json!(null)))
                        .collect(),
                )
            })
            .collect::<Vec<_>>();
        let value = json!([{"query_id":query.id,"query_sha256":query.sha256,"rows":rows}]);
        let digest = hash_value(&value).expect("digest");
        assert!(validate(&value, &digest, &inventory).is_ok());
        assert!(validate(&value, &format!("sha256:{}", "0".repeat(64)), &inventory).is_err());
        assert!(
            validate(
                &json!([]),
                &hash_value(&json!([])).expect("digest"),
                &inventory
            )
            .is_err()
        );
        let changed = json!([{"query_id":"substitution","query_sha256":query.sha256,"rows":value[0]["rows"]}]);
        assert!(validate(&changed, &hash_value(&changed).expect("digest"), &inventory).is_err());
    }
}
