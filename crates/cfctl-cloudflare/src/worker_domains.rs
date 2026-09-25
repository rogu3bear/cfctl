//! Worker domains documents a single-page inventory, including an empty page
//! whose observed provider metadata has `per_page: 0` and no `total_pages`.
//! <https://developers.cloudflare.com/api/python/resources/workers/subresources/domains/methods/list/>

use crate::{CloudflareResponseV1, PreparedRequest};
use serde_json::Value;

pub(super) fn accept_empty_single_page(
    request: &PreparedRequest,
    response: &mut CloudflareResponseV1,
) -> bool {
    let segments = request.url.path_segments().map(Iterator::collect::<Vec<_>>);
    if !request.method.eq_ignore_ascii_case("GET")
        || !segments.as_deref().is_some_and(|segments| {
            matches!(segments, [.., "accounts", account, "workers", "domains"] if !account.is_empty())
        })
        || !request.url.query_pairs().all(|(name, _)| {
            matches!(name.as_ref(), "environment" | "hostname" | "service" | "zone_id" | "zone_name")
        })
        || response.status != 200
        || !response.success
        || !response.errors.is_empty()
        || !response.result.as_array().is_some_and(Vec::is_empty)
    {
        return false;
    }
    let Some(info) = response.result_info.as_mut().and_then(Value::as_object_mut) else {
        return false;
    };
    if ![
        ("page", 1),
        ("per_page", 0),
        ("count", 0),
        ("total_count", 0),
    ]
    .iter()
    .all(|(field, expected)| info.get(*field).and_then(Value::as_u64) == Some(*expected))
        || info.contains_key("cursor")
        || info.contains_key("cursors")
        || info
            .get("total_pages")
            .is_some_and(|value| !matches!(value.as_u64(), Some(0 | 1)))
    {
        return false;
    }
    // Preserve provider fields rather than inventing a nonzero page capacity.
    info.insert("cfctl_pages".to_owned(), Value::from(1));
    info.insert("cfctl_single_page_complete".to_owned(), Value::Bool(true));
    true
}
