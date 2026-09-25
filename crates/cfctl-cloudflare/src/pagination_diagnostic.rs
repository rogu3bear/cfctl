//! Body-free diagnostics for a rejected first page. Validation remains fail-closed.

use crate::{CloudflareError, CloudflareResponseV1, PreparedRequest};
use serde_json::Value;

pub(super) fn with_metadata(
    error: CloudflareError,
    request: &PreparedRequest,
    response: &CloudflareResponseV1,
) -> CloudflareError {
    let segments = request.url.path_segments().map(Iterator::collect::<Vec<_>>);
    let domains_list = segments.as_deref().is_some_and(|segments| {
        matches!(segments, [.., "accounts", account, "workers", "domains"] if !account.is_empty())
    });
    if !request.method.eq_ignore_ascii_case("GET")
        || !domains_list
        || !matches!(error, CloudflareError::PaginationMetadataInvalid)
    {
        return error;
    }
    CloudflareError::PaginationMetadataDiagnostic {
        summary: summary(response.result_info.as_ref(), &response.result),
    }
}

fn summary(info: Option<&Value>, result: &Value) -> String {
    // Never format provider values other than unsigned pagination integers.
    // Unexpected strings, objects, cursors, and result bodies can contain secrets.
    let mut fields = ["page", "per_page", "count", "total_count", "total_pages"]
        .map(|field| {
            let value = match info.and_then(|info| info.get(field)) {
                None => "absent".to_owned(),
                Some(value) => value
                    .as_u64()
                    .map_or_else(|| "invalid".to_owned(), |number| number.to_string()),
            };
            format!("{field}={value}")
        })
        .to_vec();
    for field in ["cursor", "cursors"] {
        let present = info.is_some_and(|info| info.get(field).is_some());
        fields.push(format!("{field}_present={present}"));
    }
    let items = result
        .as_array()
        .map_or_else(|| "non-array".to_owned(), |items| items.len().to_string());
    fields.push(format!("items={items}"));
    fields.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejected_metadata_exposes_shape_without_provider_strings_or_body() {
        let info = json!({
            "page": 1, "per_page": 0, "count": 0, "total_count": "secret-count",
            "total_pages": {"token": "secret-object"}, "cursor": "secret-cursor",
            "cursors": {"after": "secret-next"}, "unexpected": "secret-extra"
        });
        let diagnostic = summary(Some(&info), &json!([{"token": "secret-result"}]));
        assert_eq!(
            diagnostic,
            "page=1, per_page=0, count=0, total_count=invalid, total_pages=invalid, cursor_present=true, cursors_present=true, items=1"
        );
        assert!(!diagnostic.contains("secret"));
    }

    #[test]
    fn absent_metadata_and_non_array_result_are_explicit() {
        let diagnostic = summary(None, &json!({"token": "secret-result"}));
        assert!(diagnostic.contains("page=absent"));
        assert!(diagnostic.ends_with("items=non-array"));
        assert!(!diagnostic.contains("secret"));
    }
}
