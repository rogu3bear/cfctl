//! After `keys mint`, the envelope `profile_id` is the mint parent.
//!
//! That parent (`minter`, or any Account API Tokens Write profile) is
//! mint-only. The launch PROFILE is the child import name
//! (`cfctl-site-release-*`). These fields make that split explicit so a
//! later `wrangler.versions-upload` cannot treat the mint parent as the
//! launch lane.
//!
//! Mint never writes `current_profile`. The child becomes current only
//! after `auth import-api-token`.

use cfctl_core::PlanV1;
#[cfg(test)]
use cfctl_core::ResultEnvelopeV2;
use serde_json::{Map, Value, json};

const ACCOUNT_API_TOKENS_CREATE_TOKEN: &str = "account-api-tokens-create-token";
const USER_API_TOKENS_CREATE_TOKEN: &str = "user-api-tokens-create-token";

struct MintChildLaunchLane {
    mint_parent_profile: String,
    launch_profile_id: String,
    install_child_argv: Vec<String>,
}

fn is_token_create_capability(id: &str) -> bool {
    matches!(
        id,
        ACCOUNT_API_TOKENS_CREATE_TOKEN | USER_API_TOKENS_CREATE_TOKEN
    )
}

fn mint_child_launch_lane(plan: &PlanV1) -> Option<MintChildLaunchLane> {
    if !is_token_create_capability(&plan.capability.id) {
        return None;
    }
    let launch_profile_id = minted_token_name(plan)?.to_owned();
    let mint_parent_profile = plan.profile_id.clone();
    Some(MintChildLaunchLane {
        install_child_argv: install_child_argv(&launch_profile_id, &plan.account_id),
        mint_parent_profile,
        launch_profile_id,
    })
}

fn install_child_argv(profile: &str, account: &str) -> Vec<String> {
    vec![
        "cfctl".to_owned(),
        "auth".to_owned(),
        "import-api-token".to_owned(),
        "--profile".to_owned(),
        profile.to_owned(),
        "--account".to_owned(),
        account.to_owned(),
        "--stdin".to_owned(),
    ]
}

/// Stamp the durable plan so `plans show` carries the same parent/child split.
pub(super) fn bind_mint_child_launch_lane_targets(plan: &mut PlanV1) {
    let Some(lane) = mint_child_launch_lane(plan) else {
        return;
    };
    plan.targets["mint_parent_profile"] = json!(lane.mint_parent_profile);
    plan.targets["launch_profile_id"] = json!(lane.launch_profile_id);
    plan.targets["install_child_argv"] = json!(lane.install_child_argv);
}

/// Annotate a keys-mint / plans-run result. No-op for other capabilities.
pub(super) fn attach_mint_child_launch_lane(result: &mut Value, plan: &PlanV1) {
    let Some(lane) = mint_child_launch_lane(plan) else {
        return;
    };
    let Some(object) = result.as_object_mut() else {
        return;
    };
    insert_mint_child_launch_lane(object, &lane);
}

/// Closed spelling: profile `wrangler.versions-upload` must use after mint.
///
/// Reads `launch_profile_id` from the command result. Never falls back to
/// `envelope.profile_id` (that field is the mint parent).
#[cfg(test)]
pub(super) fn wrangler_versions_upload_profile_from_mint_envelope(
    envelope: &ResultEnvelopeV2,
) -> Option<&str> {
    wrangler_versions_upload_profile_from_mint_result(&envelope.result)
}

#[cfg(test)]
fn wrangler_versions_upload_profile_from_mint_result(result: &Value) -> Option<&str> {
    result
        .get("launch_profile_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|profile| !profile.is_empty())
}

fn minted_token_name(plan: &PlanV1) -> Option<&str> {
    plan.input
        .get("body")
        .and_then(|body| body.get("name"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

fn insert_mint_child_launch_lane(object: &mut Map<String, Value>, lane: &MintChildLaunchLane) {
    object.insert(
        "mint_parent_profile".to_owned(),
        json!(lane.mint_parent_profile),
    );
    object.insert(
        "launch_profile_id".to_owned(),
        json!(lane.launch_profile_id),
    );
    object.insert(
        "install_child_argv".to_owned(),
        json!(lane.install_child_argv),
    );
    object.insert("next_step".to_owned(), json!(lane.next_step()));
    if let Some(Value::String(message)) = object.get_mut("message")
        && !message.contains("launch_profile_id")
    {
        message.push(' ');
        message.push_str(&lane.next_step());
    }
}

impl MintChildLaunchLane {
    fn next_step(&self) -> String {
        format!(
            "Install the child with `{}`. wrangler.versions-upload uses launch_profile_id `{}`, not mint_parent_profile `{}`. Do not select the mint parent as the launch profile.",
            self.install_child_argv.join(" "),
            self.launch_profile_id,
            self.mint_parent_profile
        )
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "unit tests bind the mint/launch split with explicit fixtures"
)]
mod tests {
    use super::{
        ACCOUNT_API_TOKENS_CREATE_TOKEN, attach_mint_child_launch_lane,
        wrangler_versions_upload_profile_from_mint_envelope,
    };
    use cfctl_core::{CapabilityV1, PlanV1, ResultEnvelopeV2};
    use serde_json::json;

    fn mint_plan(parent: &str, token_name: &str, account: &str) -> PlanV1 {
        let capability = CapabilityV1::new(
            ACCOUNT_API_TOKENS_CREATE_TOKEN,
            "Create Token",
            "POST",
            "/accounts/{account_id}/tokens",
        );
        let mut plan = PlanV1::draft(parent, account, "catalog-sha", capability, json!({}))
            .expect("draft mint plan");
        plan.input = json!({
            "selectors": {"account_id": account},
            "query": {},
            "body": {"name": token_name}
        });
        plan
    }

    #[test]
    fn mint_planned_with_profile_minter_does_not_report_minter_as_wrangler_versions_upload_profile()
    {
        let plan = mint_plan("minter", "cfctl-site-release-test", "account-a");
        let mut envelope = ResultEnvelopeV2::success(
            "keys mint",
            json!({
                "message": "Plan created. Review it, then approve the exact operation ID with y/n."
            }),
        );
        envelope.profile_id = Some(plan.profile_id.clone());
        envelope.account_id = Some(plan.account_id.clone());
        envelope.capability_id = Some(plan.capability.id.clone());
        attach_mint_child_launch_lane(&mut envelope.result, &plan);

        assert_eq!(envelope.profile_id.as_deref(), Some("minter"));
        assert_eq!(envelope.result["mint_parent_profile"], "minter");
        assert_eq!(
            envelope.result["launch_profile_id"],
            "cfctl-site-release-test"
        );
        assert_eq!(
            envelope.result["install_child_argv"],
            json!([
                "cfctl",
                "auth",
                "import-api-token",
                "--profile",
                "cfctl-site-release-test",
                "--account",
                "account-a",
                "--stdin"
            ])
        );
        assert_ne!(
            envelope.result["install_child_argv"][4], "minter",
            "install_child_argv --profile is the child, not the mint parent"
        );
        assert!(
            envelope.result.get("current_profile").is_none(),
            "mint must not auto-select minter or any other profile"
        );

        let upload_profile = wrangler_versions_upload_profile_from_mint_envelope(&envelope)
            .expect("mint result names the child launch profile");
        assert_eq!(upload_profile, "cfctl-site-release-test");
        assert_ne!(
            upload_profile, "minter",
            "wrangler.versions-upload must not use the mint parent"
        );
        assert_ne!(
            Some(upload_profile),
            envelope.profile_id.as_deref(),
            "envelope.profile_id remains the mint parent and is not the upload profile"
        );
        assert!(envelope.result["next_step"].as_str().is_some_and(|step| {
            step.contains("cfctl-site-release-test")
                && step.contains("minter")
                && !step.contains("auth use minter")
        }));
    }

    #[test]
    fn wrangler_versions_upload_profile_does_not_fall_back_to_envelope_profile_id() {
        let mut envelope = ResultEnvelopeV2::success("plans run", json!({"success": true}));
        envelope.profile_id = Some("minter".to_owned());
        assert!(wrangler_versions_upload_profile_from_mint_envelope(&envelope).is_none());
    }

    #[test]
    fn non_mint_plans_do_not_grow_a_child_launch_lane() {
        let capability = CapabilityV1::new(
            "wrangler.versions-upload",
            "Upload Worker version",
            "POST",
            "/accounts/{account_id}/workers/scripts/{script_name}/versions",
        );
        let mut plan = PlanV1::draft("minter", "account-a", "catalog-sha", capability, json!({}))
            .expect("draft upload plan");
        plan.input = json!({"body": {"name": "cfctl-site-release-test"}});
        let mut result = json!({"success": true});
        attach_mint_child_launch_lane(&mut result, &plan);
        assert!(result.get("launch_profile_id").is_none());
        assert!(result.get("mint_parent_profile").is_none());
        assert!(result.get("install_child_argv").is_none());
    }
}
