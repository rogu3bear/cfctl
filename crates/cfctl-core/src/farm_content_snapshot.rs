//! Closed Farm content/provenance read contract. No caller-controlled SQL.
pub const CAPABILITY_ID: &str = "farm-content-provenance-snapshot";
pub const ACCOUNT_ID: &str = "ca30e922fda7f5578e49873542e4aaca";
pub const DATABASE_ID: &str = "2a220ff3-f718-430e-a45f-b0d186a46193";
pub const MAX_REVISIONS: usize = 1_000;
pub const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;
pub const TIMEOUT_SECONDS: u64 = 15;

// One SQLite statement observes both tables in one read transaction. A sentinel
// beyond the supported population makes overflow an explicit failure. Keeping
// fields_json as text preserves the application's exact serialized value.
pub const SNAPSHOT_SQL: &str = r"WITH
current_content AS (SELECT id,schema_version,version,fields_json,updated_by,updated_at FROM site_content ORDER BY id LIMIT 2),
revisions AS (SELECT version,schema_version,fields_json,saved_by,saved_at FROM site_content_revisions ORDER BY version LIMIT 1001)
SELECT json_object(
 'site_content',json((SELECT json_group_array(json_object('id',id,'schema_version',schema_version,'version',version,'fields_json',fields_json,'updated_by',updated_by,'updated_at',updated_at)) FROM current_content)),
 'site_content_revisions',json((SELECT json_group_array(json_object('version',version,'schema_version',schema_version,'fields_json',fields_json,'saved_by',saved_by,'saved_at',saved_at)) FROM revisions))
) AS snapshot_json";
