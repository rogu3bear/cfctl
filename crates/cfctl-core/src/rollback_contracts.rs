//! Detailed rollback predicates kept outside the exhaustive strategy registry.
use crate::{
    CapabilityV1, DNS_RECORD_DETAIL_PATH, DNS_RECORD_DETAIL_READ_CAPABILITY_ID,
    dns_record_update_request_contract_supported,
};

pub(super) fn dns_record_update(capability: &CapabilityV1) -> bool {
    matches!(
        (capability.id.as_str(), capability.method.as_str()),
        ("dns-records-for-a-zone-update-dns-record", "PUT")
            | ("dns-records-for-a-zone-patch-dns-record", "PATCH")
    ) && capability.product == "DNS Records for a Zone"
        && capability.path == DNS_RECORD_DETAIL_PATH
        && capability.account_scope == "zone"
        && capability.verification.strategy == "dns_record_details_match_planned_id_and_fields"
        && capability.verification_contract_supported()
        && dns_record_update_request_contract_supported(capability)
        && capability.same_path_read.as_ref().is_some_and(|read| {
            read.path == DNS_RECORD_DETAIL_PATH
                && read.read_capability_id == DNS_RECORD_DETAIL_READ_CAPABILITY_ID
                && read.verified_response_fields
                    == [
                        "comment",
                        "content",
                        "data",
                        "name",
                        "priority",
                        "private_routing",
                        "proxied",
                        "settings",
                        "tags",
                        "ttl",
                        "type",
                    ]
        })
}
