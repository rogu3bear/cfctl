//! App creation owns absence evidence; it never borrows update ownership.
use super::access_ownership::access_application_collection_source_contract_supported;
use super::cloudflare_api::BASE_URL as API_BASE_URL;
use super::plan_secret::ACCESS_APP_LIST_CAPABILITY_ID;
use super::prelude::{
    AuthCredential, CallInput, CapabilityV1, CatalogSnapshot, CliError, EvidenceClass, EvidenceV1,
    Executor, PlanV1, Result, StateStore, Value, json,
};
use super::support::{capability_missing, http_client};
use cfctl_core::hash_value;

const PRECONDITION: &str = "access_application_absence";
pub(super) fn applies(capability: &CapabilityV1) -> bool {
    capability.id == cfctl_catalog::ACCESS_APP_CREATE_OWNED_ID
}

pub(super) async fn prepare(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: Option<&AuthCredential>,
) -> Result<Option<(Value, EvidenceV1)>> {
    if !applies(capability) {
        return Ok(None);
    }
    if capability.method != "POST"
        || capability.path != "/accounts/{account_id}/access/apps"
        || capability.account_scope != "account"
        || input.selectors.get("account_id").and_then(Value::as_str) != Some(account_id)
    {
        return Err(CliError::Input(
            "owned Access create identity drifted".to_owned(),
        ));
    }
    cfctl_cloudflare::validate_owned_access_create_input(input)?;
    let credential = credential
        .ok_or_else(|| CliError::Input("Access app absence needs scoped credentials".to_owned()))?;
    let source = catalog
        .get(ACCESS_APP_LIST_CAPABILITY_ID)
        .ok_or_else(|| capability_missing(ACCESS_APP_LIST_CAPABILITY_ID))?;
    if !access_application_collection_source_contract_supported(source) {
        return Err(CliError::Input(
            "Access application collection contract drifted".to_owned(),
        ));
    }
    let response = Executor::new(http_client()?, API_BASE_URL)?
        .read_access_application_inventory(
            source,
            &CallInput {
                selectors: input.selectors.clone(),
                query: json!({}),
                ..CallInput::default()
            },
            credential,
        )
        .await?;
    let receipt = cfctl_cloudflare::access_create_collection_receipt(input, &response, None)?;
    let evidence = store.write_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok(Some((receipt, evidence)))
}

fn pinned_absence_hash(plan: &PlanV1) -> Result<&str> {
    let expected = plan.precondition_hashes.get(PRECONDITION).ok_or_else(|| {
        CliError::Input("Access create plan omitted absence hash; replan".to_owned())
    })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/access_application_absence")
        .ok_or_else(|| {
            CliError::Input("Access create plan omitted absence receipt; replan".to_owned())
        })?;
    if hash_value(receipt)? != *expected {
        return Err(CliError::Input(
            "Access create absence receipt drifted; replan".to_owned(),
        ));
    }
    Ok(expected)
}

pub(super) async fn validate_live(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<Option<EvidenceV1>> {
    if !applies(&plan.capability) {
        return Ok(None);
    }
    let expected = pinned_absence_hash(plan)?;
    let (fresh, evidence) = prepare(
        store,
        catalog,
        &plan.capability,
        input,
        &plan.account_id,
        Some(credential),
    )
    .await?
    .ok_or_else(|| CliError::Input("Access create absence contract missing".to_owned()))?;
    if hash_value(&fresh)? != expected {
        return Err(CliError::Input(
            "Access application inventory changed after planning; mutation not attempted"
                .to_owned(),
        ));
    }
    Ok(Some(evidence))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{PRECONDITION, pinned_absence_hash};
    use cfctl_core::{CapabilityV1, PlanV1, hash_value};
    use serde_json::json;
    #[test]
    fn owned_create_requires_pinned_absence_before_any_live_read() {
        let capability = CapabilityV1::new(
            cfctl_catalog::ACCESS_APP_CREATE_OWNED_ID,
            "Owned application",
            "POST",
            "/accounts/{account_id}/access/apps",
        );
        let mut plan = PlanV1::draft("profile", "account", "catalog", capability, json!({}))
            .expect("valid test fixture");
        assert!(pinned_absence_hash(&plan).is_err());
        let receipt = json!({"collection_digest":"digest-a","candidate_count":0});
        plan.precondition_hashes.insert(
            PRECONDITION.to_owned(),
            hash_value(&receipt).expect("valid test fixture"),
        );
        assert!(pinned_absence_hash(&plan).is_err());
        plan.targets = json!({"live_preconditions":{PRECONDITION:receipt}});
        assert!(pinned_absence_hash(&plan).is_ok());
        plan.targets["live_preconditions"][PRECONDITION]["candidate_count"] = json!(1);
        assert!(pinned_absence_hash(&plan).is_err());
    }
}
