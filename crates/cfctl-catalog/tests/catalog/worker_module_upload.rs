use super::{AdapterStatus, normalize_openapi, worker_control_plane_fixture};
use serde_json::json;

#[test]
fn worker_module_upload_permissions_cannot_hide_missing_transport() {
    for permissions in [
        json!(["Workers Scripts Write"]),
        json!([
            "Workers Scripts Write",
            "Workers Admin",
            "Workers Editor",
            "Individual Workers Admin",
            "Individual Workers Editor"
        ]),
    ] {
        let mut document = worker_control_plane_fixture();
        let upload =
            &mut document["paths"]["/accounts/{account_id}/workers/scripts/{script_name}"]["put"];
        upload["x-api-token-group"] = permissions;
        let snapshot = normalize_openapi(&document).expect("current or legacy schema");
        let cap = snapshot
            .get(cfctl_core::worker_module_upload::ID)
            .expect("discovery is retained");
        assert_eq!(cap.adapter_status, AdapterStatus::Blocked);
        assert!(
            cap.mutation_contract_gaps()
                .iter()
                .any(|gap| gap == cfctl_core::worker_module_upload::BLOCKING_GAP)
        );
        assert_ne!(
            cap.verification.strategy,
            "worker_script_settings_id_matches_upload_response"
        );
        assert!(cap.request_schema.is_none());
    }
}
