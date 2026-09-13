//! Discovery for cfctl's optional artifact policy, consumed before Wrangler.
use cfctl_core::worker_frozen_upload::{ARTIFACT_MODE, CAPABILITY_ID};
use cfctl_core::{CapabilityV1, SelectorContractV1, SelectorV1};
use serde_json::json;

pub(super) fn attach(capability: &mut CapabilityV1) {
    if capability.id != CAPABILITY_ID {
        return;
    }
    capability.selectors.push(SelectorV1 {
        name: "artifact_mode".to_owned(),
        location: "query".to_owned(),
        required: false,
        value_type: "string".to_owned(),
        description: Some(
            "Set frozen-artifact to upload the exact admitted module/assets manifest through a private config projection with the custom build command suppressed; source/config/file/producer drift requires a new plan. Omit to preserve ordinary Wrangler build behavior."
                .to_owned(),
        ),
        contract: Some(SelectorContractV1 {
            schema: json!({"type": "string", "enum": [ARTIFACT_MODE]}),
            query: None,
        }),
    });
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn frozen_upload_is_an_optional_enum_on_the_existing_public_capability() {
        let mut snapshot = crate::CatalogSnapshot {
            schema_version: 2,
            generated_at: chrono::Utc::now(),
            source_url: "local fixture".to_owned(),
            source_hash: String::new(),
            schema_hash: String::new(),
            capabilities: std::collections::BTreeMap::new(),
        };
        crate::ingest_wrangler_worker_versions_help(
            &mut snapshot,
            "4.107.0",
            "wrangler versions upload [path] --config --message --name",
            "",
        );
        let capability = snapshot
            .capabilities
            .get(CAPABILITY_ID)
            .expect("public upload capability");
        let mode = capability
            .selectors
            .iter()
            .find(|selector| selector.name == "artifact_mode")
            .expect("discoverable mode");
        assert!(!mode.required);
        assert_eq!(mode.location, "query");
        assert_eq!(
            mode.contract.as_ref().expect("closed enum").schema,
            json!({"type": "string", "enum": ["frozen-artifact"]})
        );
        assert_eq!(capability.path, "wrangler versions upload");
        assert_eq!(
            capability.verification.strategy,
            "wrangler_worker_version_reports_expected_message"
        );
        assert_eq!(
            capability
                .selectors
                .iter()
                .filter(|selector| selector.name != "artifact_mode")
                .map(|selector| (selector.name.as_str(), selector.required))
                .collect::<Vec<_>>(),
            [
                ("config", true),
                ("message", true),
                ("argument", false),
                ("name", true)
            ]
        );
        assert!(
            capability
                .selectors
                .iter()
                .filter_map(|selector| selector.description.as_deref())
                .any(|description| description.contains("ordinary Wrangler build behavior"))
        );
    }
}
