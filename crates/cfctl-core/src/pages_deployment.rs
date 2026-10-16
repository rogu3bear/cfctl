//! Deployment intent and the safe identity projection consumed by Pages clients.

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PagesDeploymentEnvironmentV1 {
    #[default]
    Production,
    Preview,
}

impl PagesDeploymentEnvironmentV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::Preview => "preview",
        }
    }
}

/// A projection from exact provider deployment and protected-production reads.
/// It contains no environment-variable values or guessed branch alias.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PagesDeploymentVerificationV1 {
    pub schema_version: u32,
    pub account_id: String,
    pub project_name: String,
    pub deployment_id: String,
    pub environment: PagesDeploymentEnvironmentV1,
    pub branch: String,
    pub commit_hash: String,
    pub production_branch: String,
    pub immutable_url: String,
    pub aliases: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch_alias: Option<String>,
    /// The project production branch and canonical deployment matched their
    /// pre-upload projection; this does not attest DNS or user-visible health.
    pub canonical_production_preserved: bool,
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::PagesDeploymentEnvironmentV1;
    use serde_json::json;

    #[test]
    fn environment_is_a_closed_string_contract() {
        for (value, expected) in [
            ("production", PagesDeploymentEnvironmentV1::Production),
            ("preview", PagesDeploymentEnvironmentV1::Preview),
        ] {
            assert_eq!(
                serde_json::from_value::<PagesDeploymentEnvironmentV1>(json!(value))
                    .expect("known environment"),
                expected
            );
        }
        for value in [json!(null), json!(true), json!("Preview"), json!("staging")] {
            assert!(serde_json::from_value::<PagesDeploymentEnvironmentV1>(value).is_err());
        }
    }
}
