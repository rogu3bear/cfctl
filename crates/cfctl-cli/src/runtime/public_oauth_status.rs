//! Public OAuth status for the cfctl-site launch handoff.
//!
//! `oauth: unconfigured` may only be set from a named governed GET that can
//! prove public OAuth is disabled. Doctor prose, empty script secrets, and
//! ASSETS-only Worker settings are not that GET.
//!
//! Catalog: `oauth-clients-get` requires `oauth_client_id` and cannot prove
//! absence. Collection path `/accounts/{account_id}/oauth_clients` is
//! POST-only (`oauth-clients-create`). Do not enable OAuth here.

#![cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "launch oauth serializer is bound by tests until a catalog GET can prove public OAuth disabled"
    )
)]

use serde_json::{Value, json};

use super::CliError;

pub(super) const STATUS_UNCONFIGURED: &str = "unconfigured";
pub(super) const STATUS_UNPROVED: &str = "unproved";
pub(super) const OAUTH_CLIENTS_GET: &str = "oauth-clients-get";
pub(super) const WORKER_SETTINGS_GET: &str = "worker-script-get-settings";
pub(super) const WORKER_SECRETS_LIST: &str = "worker-list-script-secrets";
pub(super) const DOMAIN_DOES_NOT_ENABLE: &str =
    "cfctl.com ownership, site publication, and domain verification do not enable OAuth";

pub(super) enum OauthEvidence {
    Absent,
    DoctorProse,
    WorkerSettings {
        result: Value,
    },
    ScriptSecrets {
        result: Value,
    },
    GovernedGet {
        capability_id: String,
        result: Value,
    },
}

/// No catalog GET can prove public OAuth is disabled for `cfctl-site`.
/// `oauth-clients-get` is a detail GET and cannot prove absence.
pub(super) fn capability_that_proves_public_oauth_disabled() -> Option<&'static str> {
    None
}

pub(super) fn doctor_public_oauth() -> Value {
    json!({
        "status": STATUS_UNPROVED,
        "source_capability_id": Value::Null,
        "does_not_enable": DOMAIN_DOES_NOT_ENABLE,
    })
}

pub(super) fn serialize_oauth_handoff(evidence: &OauthEvidence) -> Result<Value, CliError> {
    let status = public_oauth_status(evidence);
    if status == STATUS_UNCONFIGURED && capability_that_proves_public_oauth_disabled().is_none() {
        return Err(CliError::Input(
            "oauth: unconfigured is not admitted without a named governed GET that proves public OAuth is disabled"
                .to_owned(),
        ));
    }
    Ok(json!({
        "schema_version": 1,
        "oauth": status,
        "source_capability_id": source_capability_id(evidence),
        "assets_only_bindings": assets_only_bindings(evidence),
        "empty_script_secrets": empty_script_secrets(evidence),
        "detail_get_cannot_prove_absence": detail_get_cannot_prove_absence(evidence),
    }))
}

pub(super) fn public_oauth_status(evidence: &OauthEvidence) -> &'static str {
    match evidence {
        OauthEvidence::GovernedGet { capability_id, .. }
            if capability_that_proves_public_oauth_disabled() == Some(capability_id.as_str()) =>
        {
            STATUS_UNCONFIGURED
        }
        OauthEvidence::DoctorProse
        | OauthEvidence::Absent
        | OauthEvidence::WorkerSettings { .. }
        | OauthEvidence::ScriptSecrets { .. }
        | OauthEvidence::GovernedGet { .. } => STATUS_UNPROVED,
    }
}

pub(super) fn worker_settings_are_assets_only(result: &Value) -> bool {
    if let Some(bindings) = result.get("bindings").and_then(Value::as_array) {
        return !bindings.is_empty() && bindings.iter().all(is_assets_binding);
    }
    result
        .pointer("/assets/binding")
        .and_then(Value::as_str)
        .is_some_and(|binding| binding == "ASSETS")
}

pub(super) fn script_secrets_are_empty(result: &Value) -> bool {
    result.as_array().is_some_and(Vec::is_empty)
        || result
            .get("secrets")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
}

fn is_assets_binding(item: &Value) -> bool {
    item.get("type").and_then(Value::as_str) == Some("assets")
}

fn source_capability_id(evidence: &OauthEvidence) -> Value {
    match evidence {
        OauthEvidence::GovernedGet { capability_id, .. } => json!(capability_id),
        OauthEvidence::WorkerSettings { .. } => json!(WORKER_SETTINGS_GET),
        OauthEvidence::ScriptSecrets { .. } => json!(WORKER_SECRETS_LIST),
        OauthEvidence::DoctorProse | OauthEvidence::Absent => Value::Null,
    }
}

fn assets_only_bindings(evidence: &OauthEvidence) -> Value {
    match evidence {
        OauthEvidence::WorkerSettings { result } => json!(worker_settings_are_assets_only(result)),
        _ => Value::Null,
    }
}

fn empty_script_secrets(evidence: &OauthEvidence) -> Value {
    match evidence {
        OauthEvidence::ScriptSecrets { result } => json!(script_secrets_are_empty(result)),
        _ => Value::Null,
    }
}

fn detail_get_cannot_prove_absence(evidence: &OauthEvidence) -> Value {
    match evidence {
        OauthEvidence::GovernedGet {
            capability_id,
            result,
        } => json!(capability_id == OAUTH_CLIENTS_GET && !result.is_null()),
        _ => Value::Null,
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "unit tests bind oauth:unproved with explicit ASSETS-only fixtures"
)]
mod tests {
    use super::{
        DOMAIN_DOES_NOT_ENABLE, OAUTH_CLIENTS_GET, OauthEvidence, STATUS_UNCONFIGURED,
        STATUS_UNPROVED, capability_that_proves_public_oauth_disabled, doctor_public_oauth,
        public_oauth_status, script_secrets_are_empty, serialize_oauth_handoff,
        worker_settings_are_assets_only,
    };
    use serde_json::json;

    fn assets_only_settings() -> serde_json::Value {
        json!({"bindings":[{"type":"assets","name":"ASSETS"}]})
    }

    #[test]
    fn assets_only_settings_do_not_authorize_oauth_unconfigured() {
        let settings = assets_only_settings();
        let secrets = json!([]);
        assert!(worker_settings_are_assets_only(&settings));
        assert!(script_secrets_are_empty(&secrets));

        let from_settings = serialize_oauth_handoff(&OauthEvidence::WorkerSettings {
            result: settings.clone(),
        })
        .expect("ASSETS-only settings serialize as unproved");
        assert_eq!(from_settings["oauth"], STATUS_UNPROVED);
        assert_eq!(from_settings["assets_only_bindings"], true);
        assert_ne!(from_settings["oauth"], STATUS_UNCONFIGURED);

        let from_secrets =
            serialize_oauth_handoff(&OauthEvidence::ScriptSecrets { result: secrets })
                .expect("empty script secrets serialize as unproved");
        assert_eq!(from_secrets["oauth"], STATUS_UNPROVED);
        assert_eq!(from_secrets["empty_script_secrets"], true);

        let from_doctor = serialize_oauth_handoff(&OauthEvidence::DoctorProse)
            .expect("doctor prose serializes as unproved");
        assert_eq!(from_doctor["oauth"], STATUS_UNPROVED);
        assert!(from_doctor["source_capability_id"].is_null());

        let from_absent = serialize_oauth_handoff(&OauthEvidence::Absent)
            .expect("absent evidence serializes as unproved");
        assert_eq!(from_absent["oauth"], STATUS_UNPROVED);

        let doctor = doctor_public_oauth();
        assert_eq!(doctor["status"], STATUS_UNPROVED);
        assert!(doctor["source_capability_id"].is_null());
        assert_eq!(doctor["does_not_enable"], DOMAIN_DOES_NOT_ENABLE);
        assert_ne!(doctor["status"], STATUS_UNCONFIGURED);
        assert!(
            !doctor["does_not_enable"]
                .as_str()
                .expect("note")
                .contains("disabled pending")
        );
    }

    #[test]
    fn oauth_clients_get_cannot_prove_public_oauth_disabled() {
        assert!(capability_that_proves_public_oauth_disabled().is_none());
        let status = public_oauth_status(&OauthEvidence::GovernedGet {
            capability_id: OAUTH_CLIENTS_GET.to_owned(),
            result: json!({"id":"client-a","visibility":"private"}),
        });
        assert_eq!(status, STATUS_UNPROVED);
        assert_ne!(status, STATUS_UNCONFIGURED);
        let handoff = serialize_oauth_handoff(&OauthEvidence::GovernedGet {
            capability_id: OAUTH_CLIENTS_GET.to_owned(),
            result: json!({"id":"client-a","visibility":"private"}),
        })
        .expect("oauth-clients-get serializes as unproved");
        assert_eq!(handoff["oauth"], STATUS_UNPROVED);
        assert_eq!(handoff["detail_get_cannot_prove_absence"], true);
    }

    #[test]
    fn launch_checklist_does_not_treat_disabled_as_a_live_read() {
        let checklist = include_str!("../../../../site/docs/LAUNCH_CHECKLIST.md");
        assert!(checklist.contains("`oauth: unproved`"));
        assert!(checklist.contains("oauth-clients-get"));
        assert!(
            !checklist.contains("public OAuth stays disabled"),
            "policy copy must not stand in for a governed GET"
        );
    }
}
