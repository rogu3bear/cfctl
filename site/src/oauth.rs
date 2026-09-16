pub const MAX_STATE_BYTES: usize = 512;
pub const MAX_CODE_BYTES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallbackResult {
    Success(String),
    OAuthError,
    Invalid,
}

pub fn validate_callback(states: &[String], codes: &[String], errors: &[String]) -> CallbackResult {
    if !errors.is_empty() {
        return CallbackResult::OAuthError;
    }

    let ([state], [code]) = (states, codes) else {
        return CallbackResult::Invalid;
    };

    if !valid_piece(state, MAX_STATE_BYTES) || !valid_piece(code, MAX_CODE_BYTES) {
        return CallbackResult::Invalid;
    }

    CallbackResult::Success(format!("{state} {code}"))
}

/// `pagehide` always drops the one-time value. `pageshow` must not: browsers
/// fire it on ordinary load as well as back-forward cache restore, and the
/// ordinary load can run after the payload is shown. Restore is `persisted`.
pub fn clears_sensitive_callback_on_page_event(event_type: &str, persisted: bool) -> bool {
    match event_type {
        "pagehide" => true,
        "pageshow" => persisted,
        _ => false,
    }
}

fn valid_piece(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && !value.chars().any(|character| {
            character.is_whitespace() || character.is_control() || character == '\0'
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn accepts_exactly_one_bounded_state_and_code() {
        assert_eq!(
            validate_callback(&values(&["state-123"]), &values(&["code_456"]), &[]),
            CallbackResult::Success("state-123 code_456".to_owned())
        );
    }

    #[test]
    fn rejects_missing_empty_duplicate_and_whitespace_values() {
        assert_eq!(
            validate_callback(&[], &values(&["code"]), &[]),
            CallbackResult::Invalid
        );
        assert_eq!(
            validate_callback(&values(&[""]), &values(&["code"]), &[]),
            CallbackResult::Invalid
        );
        assert_eq!(
            validate_callback(&values(&["one", "two"]), &values(&["code"]), &[]),
            CallbackResult::Invalid
        );
        assert_eq!(
            validate_callback(&values(&["state"]), &values(&["bad code"]), &[]),
            CallbackResult::Invalid
        );
    }

    #[test]
    fn rejects_oversized_values_and_any_oauth_error() {
        assert_eq!(
            validate_callback(
                &values(&[&"s".repeat(MAX_STATE_BYTES + 1)]),
                &values(&["code"]),
                &[]
            ),
            CallbackResult::Invalid
        );
        assert_eq!(
            validate_callback(
                &values(&["state"]),
                &values(&["code"]),
                &values(&["access_denied"])
            ),
            CallbackResult::OAuthError
        );
    }

    #[test]
    fn ordinary_pageshow_keeps_the_payload_and_bfcache_restore_clears_it() {
        assert!(clears_sensitive_callback_on_page_event("pagehide", false));
        assert!(clears_sensitive_callback_on_page_event("pagehide", true));
        assert!(!clears_sensitive_callback_on_page_event("pageshow", false));
        assert!(clears_sensitive_callback_on_page_event("pageshow", true));
        assert!(!clears_sensitive_callback_on_page_event(
            "visibilitychange",
            true
        ));
    }
}
