//! `SQLite`-authorized, immutable read populations and their sole Executor path.
mod diagnostic;
mod execution;
pub use diagnostic::FailedQueryDiagnostic;
mod parameters;
pub use execution::{PrivateD1ReadResult, qualify_private_receipt, validate_result};
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};

use cfctl_core::{
    AdapterStatus, CapabilityAuthorityScopeV1, CapabilityV1, EffectClass, RiskClass,
    d1_read_inventory::{
        D1ReadCallV1, D1ReadColumnV1, D1ReadInventoryV1, D1ReadQueryV1, D1ReadValueKindV1,
        WorkspaceD1ReadInventoryContractV1,
    },
};
use rusqlite::{
    Connection,
    hooks::{AuthAction, AuthContext, Authorization},
};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{CallInput, CloudflareError, Result, reviewed_schema_statement_count};

const PURE_FUNCTIONS: &[&str] = &[
    "abs",
    "avg",
    "char",
    "coalesce",
    "count",
    "date",
    "datetime",
    "glob",
    "group_concat",
    "hex",
    "ifnull",
    "iif",
    "instr",
    "json",
    "json_array",
    "json_array_length",
    "json_extract",
    "json_group_array",
    "json_group_object",
    "json_object",
    "json_patch",
    "json_quote",
    "json_type",
    "json_valid",
    "julianday",
    "length",
    "like",
    "lower",
    "ltrim",
    "max",
    "min",
    "nullif",
    "replace",
    "round",
    "rtrim",
    "strftime",
    "substr",
    "substring",
    "sum",
    "total",
    "trim",
    "typeof",
    "unicode",
    "unixepoch",
    "upper",
];

/// Private fields prevent callers constructing a partially validated population.
#[derive(Debug, Clone)]
pub struct ValidatedD1ReadInventory {
    contract: WorkspaceD1ReadInventoryContractV1,
    call: D1ReadCallV1,
}

impl ValidatedD1ReadInventory {
    #[must_use]
    pub const fn contract(&self) -> &WorkspaceD1ReadInventoryContractV1 {
        &self.contract
    }
    #[must_use]
    pub const fn call(&self) -> &D1ReadCallV1 {
        &self.call
    }
}

/// Run before profile selection or credential access. No provider or business SQL
/// is executed: `SQLite` prepares statements against compiler-created empty tables.
pub fn validate(capability: &CapabilityV1, input: &CallInput) -> Result<ValidatedD1ReadInventory> {
    let contract = capability
        .workspace_d1_read_inventory
        .as_ref()
        .ok_or_else(|| invalid("reviewed read contract missing"))?;
    if capability.id != contract.operation.id
        || capability.method != "POST"
        || capability.path != "/accounts/{account_id}/d1/database/{database_id}/query"
        || capability.authority_scope != Some(CapabilityAuthorityScopeV1::WorkspaceOwned)
        || capability.adapter_status != AdapterStatus::Native
        || capability.mutating
        || capability.risk != RiskClass::Read
        || capability.effect != EffectClass::ReadOnly
        || capability.permissions != ["D1 Read"]
        || input.selectors
            != serde_json::json!({"account_id":contract.operation.account_id,
            "database_id":contract.operation.database_id})
        || input.query.as_object().is_none_or(|q| !q.is_empty())
        || input.if_match.is_some()
        || input.if_none_match.is_some()
    {
        return Err(invalid(
            "reviewed read identity, target or selectors drifted",
        ));
    }
    let call: D1ReadCallV1 = serde_json::from_value(
        input
            .body
            .clone()
            .ok_or_else(|| invalid("reviewed read call body missing"))?,
    )
    .map_err(|_| {
        invalid("only inventory digest and expected credential generation are accepted")
    })?;
    if call.inventory_sha256 != contract.operation.inventory_sha256
        || uuid::Uuid::parse_str(&call.expected_credential_generation_id).is_err()
        || !lower_hex(&contract.repository_head, 40)
        || !lower_hex(&contract.repository_tree, 40)
        || !digest(&contract.operation_pack_sha256)
        || !digest(&call.inventory_sha256)
        || contract.repository_root.is_empty()
        || contract.repository_origin.is_empty()
    {
        return Err(invalid(
            "reviewed read source, digest or generation binding invalid",
        ));
    }
    validate_inventory(&contract.inventory)?;
    Ok(ValidatedD1ReadInventory {
        contract: contract.clone(),
        call,
    })
}

/// Also used by the Executor to revalidate immutable input at its boundary.
#[expect(
    clippy::too_many_lines,
    reason = "ordinary and committed-private bounds belong to the same complete pre-credential compiler gate"
)]
pub fn validate_inventory(inventory: &D1ReadInventoryV1) -> Result<()> {
    validate_private_disposition(inventory)?;
    let queries = &inventory.queries;
    let witness_count: usize = queries.iter().map(|q| q.witnesses.len()).sum();
    if inventory.schema_version != 1
        || queries.is_empty()
        || queries.len() > 512
        || inventory.query_count != queries.len() as u64
        || inventory.witness_count != witness_count as u64
        || witness_count == 0
        || witness_count > 1024
        || inventory.tables.len() > 512
        || inventory.functions.len() > PURE_FUNCTIONS.len()
        || !(1..=16 * 1024 * 1024).contains(&inventory.limits.max_total_response_bytes)
        || !(1..=600).contains(&inventory.limits.max_elapsed_seconds)
        || inventory.limits.stop_after_rows_read == 0
        || queries.iter().map(|q| q.sql.len()).sum::<usize>() > 4 * 1024 * 1024
    {
        return Err(invalid("read population or finite limits invalid"));
    }
    let connection = compile_schema(inventory)?;
    let mut ids = BTreeMap::new();
    let mut witness_ids = BTreeSet::new();
    let mut ordinals = BTreeSet::new();
    for query in queries {
        if !label(&query.id)
            || !label(&query.phase)
            || ids.contains_key(&query.id)
            || query.witnesses.is_empty()
            || query.sql.is_empty()
            || query.sql.len() > 8192
            || query.sql.as_bytes().contains(&0)
            || sha256(query.sql.as_bytes()) != query.sha256
            || reviewed_schema_statement_count(&query.sql) != Some(1)
            || !read_statement_shape(&query.sql)
            || !(1..=1000).contains(&query.output.max_rows)
            || query.output.min_rows > query.output.max_rows
            || query.parameters.len() > 16
            || !(512..=if inventory.private_output.is_some() {
                cfctl_core::d1_read_inventory::D1_PRIVATE_MAX_BYTES
            } else {
                65_536
            })
                .contains(&query.output.max_bytes)
            || query.output.columns.is_empty()
            || query.output.columns.len() > 64
        {
            return Err(invalid(
                "read query identity, statement, digest or output bounds invalid",
            ));
        }
        validate_witnesses(
            query,
            inventory.witness_count,
            &mut witness_ids,
            &mut ordinals,
        )?;
        for dependency in &query.requires {
            let prior: &&cfctl_core::d1_read_inventory::D1ReadQueryV1 = ids
                .get(&dependency.query_id)
                .ok_or_else(|| invalid("read dependency must name an earlier query"))?;
            match (&dependency.column, &dependency.equals) {
                (None, None) => {}
                (Some(column), Some(value))
                    if prior
                        .output
                        .columns
                        .iter()
                        .any(|c| &c.name == column && value_allowed(c, value)) => {}
                _ => {
                    return Err(invalid(
                        "read dependency must bind a declared prior result field",
                    ));
                }
            }
        }
        validate_parameters(query, &ids)?;
        let expected = query
            .output
            .columns
            .iter()
            .map(|c| c.name.as_str())
            .collect::<Vec<_>>();
        if expected.iter().copied().collect::<BTreeSet<_>>().len() != expected.len()
            || query.output.columns.iter().any(|c| {
                !valid_column(
                    c,
                    if inventory.private_output.is_some() {
                        query.output.max_bytes
                    } else {
                        8192
                    },
                )
            })
        {
            return Err(invalid("read output column policy invalid"));
        }
        let prepared = connection
            .prepare(&query.sql)
            .map_err(|_| invalid("read SQL is unsupported by the closed SQLite authorizer"))?;
        if !prepared.readonly()
            || prepared.parameter_count() != query.parameters.len()
            || query.parameters.iter().any(|parameter| {
                prepared.parameter_name(parameter.index as usize)
                    != Some(format!("?{}", parameter.index).as_str())
            })
            || prepared.column_names() != expected
        {
            return Err(invalid(
                "read SQL must match declared numbered parameters and exact output names and be read-only",
            ));
        }
        ids.insert(&query.id, query);
    }
    Ok(())
}

fn validate_witnesses<'a>(
    query: &'a D1ReadQueryV1,
    witness_count: u64,
    witness_ids: &mut BTreeSet<&'a str>,
    ordinals: &mut BTreeSet<u64>,
) -> Result<()> {
    for witness in &query.witnesses {
        if !label(&witness.id)
            || !label(&witness.group)
            || witness.source_reference.is_empty()
            || witness.source_reference.len() > 1024
            || !witness_ids.insert(witness.id.as_str())
            || !ordinals.insert(witness.ordinal)
            || witness.ordinal == 0
            || witness.ordinal > witness_count
        {
            return Err(invalid(
                "read witness population has gaps, duplicates or invalid references",
            ));
        }
    }
    Ok(())
}

fn validate_parameters(
    query: &D1ReadQueryV1,
    ids: &BTreeMap<&String, &D1ReadQueryV1>,
) -> Result<()> {
    for (offset, parameter) in query.parameters.iter().enumerate() {
        let prior: &&cfctl_core::d1_read_inventory::D1ReadQueryV1 =
            ids.get(&parameter.from_query).ok_or_else(|| {
                invalid("parameter must come from an earlier query in this inventory")
            })?;
        let source = prior
            .output
            .columns
            .iter()
            .find(|c| c.name == parameter.column)
            .ok_or_else(|| invalid("parameter source column is not declared"))?;
        let bounds_valid = if parameter.kind == D1ReadValueKindV1::Text {
            parameter
                .max_bytes
                .is_some_and(|n| n > 0 && n <= source.max_bytes.unwrap_or(0))
        } else {
            parameter.max_bytes.is_none() && !parameter.trim && !parameter.nonempty
        };
        if parameter.index as usize != offset + 1
            || parameter.row_index >= prior.output.max_rows
            || source.kind != parameter.kind
            || !bounds_valid
        {
            return Err(invalid(
                "parameter index, scalar type, row identity or bounds are invalid",
            ));
        }
    }
    Ok(())
}

fn compile_schema(inventory: &D1ReadInventoryV1) -> Result<Connection> {
    let connection =
        Connection::open_in_memory().map_err(|_| invalid("private SQLite compiler unavailable"))?;
    // SQLite owns this metadata table. Generate it through a private, empty
    // compiler table instead of permitting caller declarations of sqlite_*.
    connection
        .execute_batch(
            "CREATE TABLE __cfctl_sequence_fixture(id INTEGER PRIMARY KEY AUTOINCREMENT);",
        )
        .map_err(|_| invalid("compiler could not declare sequence metadata"))?;
    let mut tables = BTreeMap::<String, BTreeSet<String>>::new();
    for table in &inventory.tables {
        if !sql_identifier(&table.name)
            || table.name.to_ascii_lowercase().starts_with("sqlite_")
            || table.name.to_ascii_lowercase().starts_with("pragma_")
            || table.name.to_ascii_lowercase().starts_with("__cfctl_")
            || table.columns.is_empty()
            || table.columns.len() > 256
            || tables.contains_key(&table.name.to_ascii_lowercase())
            || table.columns.iter().any(|column| !sql_identifier(column))
        {
            return Err(invalid(
                "compile schema accepts declared ordinary table and column names only",
            ));
        }
        let columns = table
            .columns
            .iter()
            .map(|v| v.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        if columns.len() != table.columns.len() {
            return Err(invalid("duplicate compile column"));
        }
        let definitions = table
            .columns
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(",");
        connection
            .execute_batch(&format!("CREATE TABLE \"{}\" ({definitions});", table.name))
            .map_err(|_| invalid("compiler could not declare an empty table"))?;
        tables.insert(table.name.to_ascii_lowercase(), columns);
    }
    add_metadata_tables(&mut tables);
    let functions = inventory
        .functions
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if functions.len() != inventory.functions.len()
        || functions.iter().any(|f| !PURE_FUNCTIONS.contains(f))
    {
        return Err(invalid(
            "read function is not in the compiler-owned allowlist",
        ));
    }
    let functions = inventory.functions.clone();
    connection
        .authorizer(Some(move |context: AuthContext<'_>| {
            // This compiler creates no views or triggers. SQLite also uses accessor
            // names for ordinary CTEs; authorize their underlying reads normally.
            if context.database_name.is_some_and(|db| db != "main") {
                return Authorization::Deny;
            }
            let allowed = match context.action {
                AuthAction::Select => true,
                AuthAction::Read {
                    table_name,
                    column_name,
                } => tables
                    .get(&table_name.to_ascii_lowercase())
                    .is_some_and(|columns| {
                        column_name.is_empty()
                            || columns.contains(&column_name.to_ascii_lowercase())
                    }),
                AuthAction::Function { function_name } => functions
                    .iter()
                    .any(|f| f == &function_name.to_ascii_lowercase()),
                AuthAction::Pragma {
                    pragma_name,
                    pragma_value,
                } => {
                    let name = pragma_name.to_ascii_lowercase();
                    (name == "foreign_key_check" && pragma_value.is_none())
                        || ["table_info", "foreign_key_list", "foreign_key_check"]
                            .contains(&name.as_str())
                            && pragma_value.is_some_and(|table| {
                                tables.contains_key(&table.to_ascii_lowercase())
                            })
                }
                _ => false,
            };
            if allowed {
                Authorization::Allow
            } else {
                Authorization::Deny
            }
        }))
        .map_err(|_| invalid("SQLite read authorizer installation failed"))?;
    Ok(connection)
}

fn add_metadata_tables(tables: &mut BTreeMap<String, BTreeSet<String>>) {
    for table in ["sqlite_master", "sqlite_schema"] {
        tables.insert(
            table.into(),
            ["type", "name", "tbl_name", "rootpage", "sql"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        );
    }
    tables.insert(
        "sqlite_sequence".into(),
        ["name", "seq"].into_iter().map(str::to_owned).collect(),
    );
    for (table, columns) in [
        (
            "pragma_table_info",
            &[
                "cid",
                "name",
                "type",
                "notnull",
                "dflt_value",
                "pk",
                "arg",
                "schema",
            ][..],
        ),
        (
            "pragma_foreign_key_list",
            &[
                "id",
                "seq",
                "table",
                "from",
                "to",
                "on_update",
                "on_delete",
                "match",
                "arg",
                "schema",
            ][..],
        ),
        (
            "pragma_foreign_key_check",
            &["table", "rowid", "parent", "fkid", "arg", "schema"][..],
        ),
        (
            "pragma_index_list",
            &[
                "seq", "name", "unique", "origin", "partial", "arg", "schema",
            ][..],
        ),
        (
            "pragma_index_info",
            &["seqno", "cid", "name", "arg", "schema"][..],
        ),
    ] {
        tables.insert(
            table.into(),
            columns.iter().map(|v| (*v).to_owned()).collect(),
        );
    }
}

fn validate_private_disposition(inventory: &D1ReadInventoryV1) -> Result<()> {
    use cfctl_core::d1_read_inventory::{D1_PRIVATE_FORMAT, D1_PRIVATE_MAX_BYTES};
    let Some(private) = &inventory.private_output else {
        return Ok(());
    };
    if private.schema_version != 1
        || private.format != D1_PRIVATE_FORMAT
        || !private.require_primary
        || !(1..=D1_PRIVATE_MAX_BYTES).contains(&private.max_artifact_bytes)
        || inventory.queries.len() != 1
        || !(1..=30).contains(&inventory.limits.max_elapsed_seconds)
    {
        return Err(invalid("private read disposition or population invalid"));
    }
    let query = &inventory.queries[0];
    if !query.parameters.is_empty()
        || !query.requires.is_empty()
        || query.output.min_rows != 1
        || query.output.max_rows != 1
        || inventory.limits.max_total_response_bytes != query.output.max_bytes
    {
        return Err(invalid(
            "private read requires one independent query and one row",
        ));
    }
    Ok(())
}

fn valid_column(column: &D1ReadColumnV1, maximum: u64) -> bool {
    !column.name.is_empty()
        && column.name.len() <= 128
        && !column.name.chars().any(char::is_control)
        && match column.kind {
            D1ReadValueKindV1::Text => column.max_bytes.is_some_and(|n| (1..=maximum).contains(&n)),
            _ => column.max_bytes.is_none(),
        }
        && (column.kind == D1ReadValueKindV1::Integer
            || (column.min_integer.is_none() && column.max_integer.is_none()))
        && column
            .min_integer
            .zip(column.max_integer)
            .is_none_or(|(min, max)| min <= max)
        && column.allowed_values.as_ref().is_none_or(|values| {
            !values.is_empty()
                && values.len() <= 1024
                && values.iter().all(|value| value_kind_allowed(column, value))
        })
}

fn value_kind_allowed(column: &D1ReadColumnV1, value: &Value) -> bool {
    if value.is_null() {
        return column.nullable;
    }
    match column.kind {
        D1ReadValueKindV1::Integer => value.as_i64().is_some_and(|n| {
            column.min_integer.is_none_or(|min| n >= min)
                && column.max_integer.is_none_or(|max| n <= max)
        }),
        D1ReadValueKindV1::Real => value.is_f64() && value.as_f64().is_some_and(f64::is_finite),
        D1ReadValueKindV1::Boolean => value.is_boolean(),
        D1ReadValueKindV1::Text => value
            .as_str()
            .is_some_and(|s| s.len() as u64 <= column.max_bytes.unwrap_or(0) && !s.contains('\0')),
    }
}

fn value_allowed(column: &D1ReadColumnV1, value: &Value) -> bool {
    value_kind_allowed(column, value)
        && column
            .allowed_values
            .as_ref()
            .is_none_or(|values| values.contains(value))
}

fn lower_hex(value: &str, n: usize) -> bool {
    value.len() == n
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|v| lower_hex(v, 64))
}
fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
}
fn sql_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
fn read_statement_shape(sql: &str) -> bool {
    let (first, rest) = sql_word(sql);
    match first.to_ascii_lowercase().as_str() {
        "select" | "pragma" => true,
        "with" => !sql_word(rest).0.eq_ignore_ascii_case("recursive"),
        _ => false,
    }
}
fn sql_word(mut sql: &str) -> (&str, &str) {
    loop {
        sql = sql.trim_start();
        if let Some(comment) = sql.strip_prefix("--") {
            sql = comment.find(['\r', '\n']).map_or("", |i| &comment[i..]);
        } else if let Some(comment) = sql.strip_prefix("/*") {
            sql = comment.find("*/").map_or("", |i| &comment[i + 2..]);
        } else {
            break;
        }
    }
    let end = sql
        .bytes()
        .position(|b| !b.is_ascii_alphabetic())
        .unwrap_or(sql.len());
    (&sql[..end], &sql[end..])
}
fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
fn invalid(message: &str) -> CloudflareError {
    CloudflareError::InvalidRequestBody(message.into())
}
