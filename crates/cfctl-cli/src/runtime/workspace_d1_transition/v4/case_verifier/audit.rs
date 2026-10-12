use super::{Join, Result, invalid};
use cfctl_core::workspace_d1::transition::proofs::Population;

pub(super) fn population(join: &Join<'_, '_>, full_scan: bool) -> Result<()> {
    let population: Population = serde_json::from_value(
        join.store
            .read_evidence_value(&join.case.after.evidence_hash)?,
    )
    .map_err(|_| invalid("case audit lacks its native complete population"))?;
    let capability = crate::runtime::support::load_workspace_capability(
        join.store,
        &population.source_inventory.capability_id,
    )?
    .ok_or_else(|| invalid("case audit native inventory missing"))?;
    let inventory = &capability
        .workspace_d1_read_inventory
        .as_ref()
        .ok_or_else(|| invalid("case audit is not a native inventory"))?
        .inventory;
    if full_scan {
        for table in &inventory.tables {
            let from = format!("FROM \"{}\"", table.name);
            let queries: Vec<_> = inventory
                .queries
                .iter()
                .filter(|query| query.sql.contains(&from))
                .collect();
            if queries.is_empty()
                || queries
                    .iter()
                    .any(|query| !forced_complete_scan(&query.sql, &table.name))
            {
                return Err(invalid(
                    "full-scan case requires forced unsampled native reads of every declared table",
                ));
            }
        }
    } else {
        let exact = "SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE tbl_name<>'_cf_KV' ORDER BY type COLLATE BINARY,name COLLATE BINARY;";
        if !inventory.queries.iter().any(|query| {
            query.sql.trim() == exact
                && query
                    .output
                    .columns
                    .iter()
                    .map(|column| column.name.as_str())
                    .eq(["type", "name", "tbl_name", "sql"])
        }) {
            return Err(invalid(
                "schema-format case requires exact raw application schema rows",
            ));
        }
    }
    Ok(())
}

// Deliberately narrow source grammar for reviewed direct table populations.
// This validates forced, unsampled SQL; it does not observe the provider planner.
fn forced_complete_scan(sql: &str, table: &str) -> bool {
    let upper = sql.to_ascii_uppercase();
    let clause = format!(" FROM \"{table}\" NOT INDEXED ORDER BY ");
    let Some((projection, order)) = sql.trim().trim_end_matches(';').rsplit_once(&clause) else {
        return false;
    };
    sql.trim().starts_with("SELECT ")
        && !projection.to_ascii_uppercase().contains(" FROM ")
        && ![
            "--",
            "/*",
            "*/",
            " WHERE ",
            " LIMIT ",
            " OFFSET ",
            " JOIN ",
            " UNION ",
            " INTERSECT ",
            " EXCEPT ",
        ]
        .iter()
        .any(|token| upper.contains(token))
        && order.split(',').all(|term| {
            let Some(column) = term.trim().strip_suffix(" COLLATE BINARY") else {
                return false;
            };
            column.starts_with('"')
                && column.ends_with('"')
                && column.len() > 2
                && column[1..column.len() - 1]
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        })
}
#[cfg(test)]
mod tests {
    #[test]
    fn forced_scan_rejects_echoed_clauses_filters_sampling_and_indexed_reads() {
        let good = "SELECT id FROM \"persons\" NOT INDEXED ORDER BY \"id\" COLLATE BINARY;";
        assert!(super::forced_complete_scan(good, "persons"));
        for sql in [
            "SELECT id FROM \"persons\" ORDER BY \"id\" COLLATE BINARY;",
            "SELECT id FROM \"persons\" NOT INDEXED WHERE 0 ORDER BY \"id\" COLLATE BINARY;",
            "SELECT id FROM \"persons\" NOT INDEXED ORDER BY \"id\" COLLATE BINARY LIMIT 1;",
            "SELECT id FROM \"persons\" /* NOT INDEXED */ ORDER BY \"id\" COLLATE BINARY;",
            "SELECT id FROM \"persons\" NOT INDEXED ORDER BY \"id\" COLLATE BINARY; SELECT 1;",
        ] {
            assert!(!super::forced_complete_scan(sql, "persons"));
        }
    }
}
