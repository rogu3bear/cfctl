#![allow(clippy::expect_used)]

use cfctl_core::{BuildIdentitySourceV1, BuildInfoV1};

#[test]
fn build_info_v1_serializes_without_nondeterministic_fields() {
    let build = BuildInfoV1 {
        schema_version: 1,
        version: "2.0.0-alpha.1".to_owned(),
        git_commit: Some("0123456789abcdef0123456789abcdef01234567".to_owned()),
        identity_source: BuildIdentitySourceV1::ReleaseEnv,
    };
    let value = serde_json::to_value(build).expect("serialize build identity");
    assert_eq!(
        value,
        serde_json::json!({
            "schema_version": 1,
            "version": "2.0.0-alpha.1",
            "git_commit": "0123456789abcdef0123456789abcdef01234567",
            "identity_source": "release_env"
        })
    );
    assert!(value.get("generated_at").is_none());
    assert!(value.get("timestamp").is_none());
}
