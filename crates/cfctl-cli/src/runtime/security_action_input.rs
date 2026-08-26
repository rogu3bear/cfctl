use super::import_planning::SECURITY_IP_RULE_CREATE_ID;
use super::import_planning::SECURITY_IP_RULE_REMOVE_ID;
use super::import_planning::SECURITY_LIST_MEMBER_CREATE_ID;
use super::import_planning::SECURITY_LIST_MEMBER_REMOVE_ID;
use super::import_planning::SECURITY_WAF_RULE_CREATE_ID;
use super::import_planning::SECURITY_WAF_RULE_REMOVE_ID;
use super::prelude::{
    CallInput, CapabilityV1, ChronoDuration, CliError, Map, Result, SecurityActionKindV1, Utc,
    Value, json,
};
use cfctl_cloudflare::validate_request_contract;
use cfctl_core::hash_value;

pub(super) fn validate_security_action_governance_input(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<()> {
    let contract = capability.security_action.as_ref().ok_or_else(|| {
        CliError::Input("security action capability omitted its governance contract".to_owned())
    })?;
    if !capability.security_action_contract_supported() {
        return Err(CliError::Input(
            "security action capability drifted from its governed safety contract".to_owned(),
        ));
    }
    let mut governance_capability = capability.clone();
    governance_capability.request_schema = Some(contract.input_schema.clone());
    validate_request_contract(&governance_capability, input)?;
    Ok(())
}

pub(super) fn security_action_string<'a>(
    body: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a str> {
    body.get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            CliError::Input(format!(
                "security action requires non-empty string field `{field}`"
            ))
        })
}

pub(super) fn ip_is_protected(address: std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(address) => {
            let octets = address.octets();
            address.is_unspecified()
                || address.is_loopback()
                || address.is_private()
                || address.is_link_local()
                || address.is_multicast()
                || address.is_broadcast()
                || address.is_documentation()
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                || (octets[0] == 198 && matches!(octets[1], 18 | 19))
        }
        std::net::IpAddr::V6(address) => {
            let segments = address.segments();
            address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || address.is_unique_local()
                || address.is_unicast_link_local()
                || segments[0] == 0x2001 && segments[1] == 0x0db8
        }
    }
}

pub(super) fn normalize_public_ip(value: &str) -> Result<std::net::IpAddr> {
    let address = value.parse::<std::net::IpAddr>().map_err(|_| {
        CliError::Input("security action target is not a valid IP address".to_owned())
    })?;
    if ip_is_protected(address) {
        return Err(CliError::Input(
            "security action refuses private, local, documentation, multicast, or reserved IP targets"
                .to_owned(),
        ));
    }
    Ok(address)
}

pub(super) fn normalize_bounded_ipv4_prefix(value: &str) -> Result<(String, u32, u8)> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| CliError::Input("IP range targets require CIDR notation".to_owned()))?;
    let address = address
        .parse::<std::net::Ipv4Addr>()
        .map_err(|_| CliError::Input("IP range target must be an IPv4 CIDR".to_owned()))?;
    if ip_is_protected(std::net::IpAddr::V4(address)) {
        return Err(CliError::Input(
            "security action refuses private, local, documentation, multicast, or reserved IP ranges"
                .to_owned(),
        ));
    }
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| CliError::Input("IP range prefix must be an integer".to_owned()))?;
    if !(24..=32).contains(&prefix) {
        return Err(CliError::Input(
            "security action limits IPv4 ranges to /24 or narrower; broader prefixes require a separately reviewed WAF rule"
                .to_owned(),
        ));
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    let network = u32::from(address) & mask;
    Ok((
        format!("{}/{prefix}", std::net::Ipv4Addr::from(network)),
        network,
        prefix,
    ))
}

pub(super) type NormalizedSecurityTarget = (String, String, String, bool, Option<(u32, u8)>);
pub(super) type OperatorSecurityTarget = (String, String, Option<(u32, u8)>);
pub(super) type NormalizedListSecurityTarget =
    (Value, Value, String, bool, Option<OperatorSecurityTarget>);
pub(super) type NormalizedWafSecurityTarget =
    (String, Value, String, bool, Option<OperatorSecurityTarget>);

pub(super) fn normalize_security_target(
    target: &Map<String, Value>,
) -> Result<NormalizedSecurityTarget> {
    let target_type = security_action_string(target, "type")?;
    let value = security_action_string(target, "value")?;
    match target_type {
        "ip" => {
            let address = normalize_public_ip(value)?;
            let wire_type = if address.is_ipv4() { "ip" } else { "ip6" };
            Ok((
                wire_type.to_owned(),
                address.to_string(),
                "one exact public IP address".to_owned(),
                false,
                None,
            ))
        }
        "ip_range" => {
            let (value, network, prefix) = normalize_bounded_ipv4_prefix(value)?;
            let addresses = 1_u64 << (32 - u32::from(prefix));
            Ok((
                "ip_range".to_owned(),
                value,
                format!("one IPv4 /{prefix} prefix ({addresses} addresses)"),
                true,
                Some((network, prefix)),
            ))
        }
        "asn" => {
            let numeric = value
                .trim()
                .trim_start_matches("AS")
                .trim_start_matches("as")
                .parse::<u32>()
                .ok()
                .filter(|value| *value > 0)
                .ok_or_else(|| {
                    CliError::Input("ASN target must be a positive AS number".to_owned())
                })?;
            Ok((
                "asn".to_owned(),
                format!("AS{numeric}"),
                "all traffic attributed by Cloudflare to one ASN".to_owned(),
                true,
                None,
            ))
        }
        "country" => {
            let country = value.to_ascii_uppercase();
            if country.len() != 2 || !country.bytes().all(|byte| byte.is_ascii_alphabetic()) {
                return Err(CliError::Input(
                    "country target must be a two-letter ISO country code".to_owned(),
                ));
            }
            Ok((
                "country".to_owned(),
                country,
                "all traffic classified by Cloudflare to one country".to_owned(),
                true,
                None,
            ))
        }
        _ => Err(CliError::Input(
            "security action target type must be `ip`, `ip_range`, `asn`, or `country`".to_owned(),
        )),
    }
}

pub(super) fn validate_operator_not_targeted(
    operator_ip: &str,
    target_type: &str,
    target_value: &str,
    target_prefix: Option<(u32, u8)>,
) -> Result<()> {
    let operator = normalize_public_ip(operator_ip)?;
    let self_targeted = match (target_type, operator) {
        ("ip" | "ip6", address) => address.to_string() == target_value,
        ("ip_range", std::net::IpAddr::V4(address)) => {
            target_prefix.is_some_and(|(network, prefix)| {
                let mask = u32::MAX << (32 - u32::from(prefix));
                u32::from(address) & mask == network
            })
        }
        _ => false,
    };
    if self_targeted {
        return Err(CliError::Input(
            "security action would directly target the declared operator IP; the plan was not created"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn security_expiry(
    supplied: Option<&str>,
    default_ttl_seconds: u64,
    max_ttl_seconds: u64,
) -> Result<(chrono::DateTime<Utc>, u64)> {
    let now = Utc::now();
    let expiry = supplied.map_or_else(
        || {
            i64::try_from(default_ttl_seconds)
                .ok()
                .map(|seconds| now + ChronoDuration::seconds(seconds))
                .ok_or_else(|| CliError::Input("security action TTL is invalid".to_owned()))
        },
        |value| {
            chrono::DateTime::parse_from_rfc3339(value)
                .map(|parsed| parsed.with_timezone(&Utc))
                .map_err(|_| {
                    CliError::Input("security action `expires_at` must be RFC3339".to_owned())
                })
        },
    )?;
    let ttl = (expiry - now).num_seconds();
    if ttl < 300 {
        return Err(CliError::Input(
            "security action expiry must be at least five minutes in the future".to_owned(),
        ));
    }
    let ttl = u64::try_from(ttl)
        .map_err(|_| CliError::Input("security action expiry must be in the future".to_owned()))?;
    if ttl > max_ttl_seconds {
        return Err(CliError::Input(format!(
            "security action expiry exceeds the governed maximum of {max_ttl_seconds} seconds"
        )));
    }
    Ok((expiry, ttl))
}

#[expect(
    clippy::too_many_lines,
    reason = "the security-action normalizer keeps all scope, expiry, self-block, and audit invariants visible in one fail-closed review boundary"
)]
pub(super) fn prepare_security_action_create(
    capability: &CapabilityV1,
    input: &mut CallInput,
) -> Result<Value> {
    let contract = capability
        .security_action
        .as_ref()
        .ok_or_else(|| CliError::Input("security action contract is missing".to_owned()))?;
    let body = input
        .body
        .as_ref()
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| CliError::Input("security action body must be an object".to_owned()))?;
    let actor = security_action_string(&body, "actor")?.to_owned();
    let evidence_ref = security_action_string(&body, "evidence_ref")?.to_owned();
    let reason = security_action_string(&body, "reason")?.trim().to_owned();
    if reason.chars().any(char::is_control) {
        return Err(CliError::Input(
            "security action reason cannot contain control characters".to_owned(),
        ));
    }
    let action = body
        .get("action")
        .and_then(Value::as_str)
        .or(contract.default_action.as_deref())
        .ok_or_else(|| CliError::Input("security action has no default action".to_owned()))?;
    if !contract
        .allowed_actions
        .iter()
        .any(|allowed| allowed == action)
    {
        return Err(CliError::Input(format!(
            "security action `{action}` is outside the governed allowlist"
        )));
    }
    let target = body
        .get("target")
        .and_then(Value::as_object)
        .ok_or_else(|| CliError::Input("security action target must be an object".to_owned()))?;
    let (target_type, target_value, blast_radius, broad, target_prefix) =
        normalize_security_target(target)?;
    let (expires_at, ttl_seconds) = security_expiry(
        body.get("expires_at").and_then(Value::as_str),
        contract.default_ttl_seconds,
        contract.max_ttl_seconds,
    )?;
    if broad {
        if body.get("confirm_broad_scope").and_then(Value::as_bool) != Some(true) {
            return Err(CliError::Input(
                "IP range, ASN, and country targets require `confirm_broad_scope: true` after reviewing the blast radius"
                    .to_owned(),
            ));
        }
        if action != "managed_challenge" || ttl_seconds > 3_600 {
            return Err(CliError::Input(
                "broad targets are limited to Managed Challenge for at most one hour; use a narrower target or a separately reviewed WAF design"
                    .to_owned(),
            ));
        }
    }
    if action == "block" {
        if body.get("confirm_block").and_then(Value::as_bool) != Some(true) {
            return Err(CliError::Input(
                "a block requires `confirm_block: true`; Managed Challenge is the default when confidence is incomplete"
                    .to_owned(),
            ));
        }
        let operator_ip = security_action_string(&body, "operator_ip")?;
        validate_operator_not_targeted(operator_ip, &target_type, &target_value, target_prefix)?;
        if ttl_seconds > 86_400 {
            return Err(CliError::Input(
                "blocks are limited to 24 hours; permanent blocks require a different explicitly escalated capability"
                    .to_owned(),
            ));
        }
    }
    let expires_at = expires_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let notes = serde_json::to_string(&json!({
        "cfctl_security_v1":{
            "actor":actor,
            "evidence_ref":evidence_ref,
            "expires_at":expires_at,
            "reason":reason,
        }
    }))?;
    if notes.len() > 500 {
        return Err(CliError::Input(
            "security action audit note exceeds the Cloudflare-safe 500-byte bound".to_owned(),
        ));
    }
    input.body = Some(json!({
        "configuration":{"target":target_type,"value":target_value},
        "mode":action,
        "notes":notes,
    }));
    Ok(json!({
        "schema_version":1,
        "kind":"create_expiring",
        "action":action,
        "actor":actor,
        "evidence_ref":evidence_ref,
        "expires_at":expires_at,
        "reason":reason,
        "target":{"type":target_type,"value":target_value},
        "blast_radius":blast_radius,
        "ttl_seconds":ttl_seconds,
        "managed_challenge_default":true,
        "permanent_action":false,
        "anonymous_identity_inferred":false,
        "self_block_checked":action == "block",
        "wire_note_hash":hash_value(&Value::String(notes))?,
    }))
}

pub(super) fn normalize_list_security_target(
    target: &Map<String, Value>,
) -> Result<NormalizedListSecurityTarget> {
    let target_type = security_action_string(target, "type")?;
    let raw = security_action_string(target, "value")?;
    match target_type {
        "ip" => {
            let address = normalize_public_ip(raw)?;
            let value = address.to_string();
            Ok((
                json!({"ip":value}),
                json!({"type":"ip","value":value}),
                "one exact public IP address".to_owned(),
                false,
                Some((
                    if address.is_ipv4() { "ip" } else { "ip6" }.to_owned(),
                    value,
                    None,
                )),
            ))
        }
        "ip_range" => {
            let (value, network, prefix) = normalize_bounded_ipv4_prefix(raw)?;
            let addresses = 1_u64 << (32 - u32::from(prefix));
            Ok((
                json!({"ip":value}),
                json!({"type":"ip_range","value":value}),
                format!("one IPv4 /{prefix} prefix ({addresses} addresses)"),
                true,
                Some(("ip_range".to_owned(), value, Some((network, prefix)))),
            ))
        }
        "asn" => {
            let numeric = raw
                .trim()
                .trim_start_matches("AS")
                .trim_start_matches("as")
                .parse::<u32>()
                .ok()
                .filter(|value| *value > 0)
                .ok_or_else(|| {
                    CliError::Input("ASN target must be a positive AS number".to_owned())
                })?;
            Ok((
                json!({"asn":numeric}),
                json!({"type":"asn","value":format!("AS{numeric}")}),
                "all traffic attributed by Cloudflare to one ASN".to_owned(),
                true,
                None,
            ))
        }
        "hostname" => {
            let hostname = match url::Host::parse(raw).map_err(|_| {
                CliError::Input("hostname target must be one valid exact hostname".to_owned())
            })? {
                url::Host::Domain(hostname) => hostname.to_ascii_lowercase(),
                _ => {
                    return Err(CliError::Input(
                        "hostname targets cannot be IP literals; use target type `ip`".to_owned(),
                    ));
                }
            };
            if hostname.len() > 253
                || hostname.starts_with('.')
                || hostname.ends_with('.')
                || hostname.contains('*')
            {
                return Err(CliError::Input(
                    "hostname target must be one normalized exact DNS hostname".to_owned(),
                ));
            }
            Ok((
                json!({"hostname":{"url_hostname":hostname}}),
                json!({"type":"hostname","value":hostname}),
                "all requests matching one exact hostname in every reviewed list consumer"
                    .to_owned(),
                false,
                None,
            ))
        }
        _ => Err(CliError::Input(
            "List security target type must be `ip`, `ip_range`, `asn`, or `hostname`".to_owned(),
        )),
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "list-backed enforcement requires one auditable boundary for consumer scope, target normalization, expiry, self-block, and receipt construction"
)]
pub(super) fn prepare_list_security_action_create(
    capability: &CapabilityV1,
    input: &mut CallInput,
) -> Result<Value> {
    let contract = capability
        .security_action
        .as_ref()
        .ok_or_else(|| CliError::Input("List security action contract is missing".to_owned()))?;
    let body = input
        .body
        .as_ref()
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| CliError::Input("List security action body must be an object".to_owned()))?;
    let actor = security_action_string(&body, "actor")?.to_owned();
    let evidence_ref = security_action_string(&body, "evidence_ref")?.to_owned();
    let reason = security_action_string(&body, "reason")?.trim().to_owned();
    if reason.chars().any(char::is_control) {
        return Err(CliError::Input(
            "List security action reason cannot contain control characters".to_owned(),
        ));
    }
    if body.get("confirm_consumer_scope").and_then(Value::as_bool) != Some(true) {
        return Err(CliError::Input(
            "List membership can affect every referencing rule; review those consumers and set `confirm_consumer_scope: true`"
                .to_owned(),
        ));
    }
    let action = body
        .get("action")
        .and_then(Value::as_str)
        .or(contract.default_action.as_deref())
        .ok_or_else(|| CliError::Input("List security action has no default action".to_owned()))?;
    if !contract
        .allowed_actions
        .iter()
        .any(|allowed| allowed == action)
    {
        return Err(CliError::Input(format!(
            "List consumer action `{action}` is outside the governed allowlist"
        )));
    }
    let target = body
        .get("target")
        .and_then(Value::as_object)
        .ok_or_else(|| CliError::Input("List security target must be an object".to_owned()))?;
    let (wire_target, normalized_target, blast_radius, broad, operator_target) =
        normalize_list_security_target(target)?;
    let (expires_at, ttl_seconds) = security_expiry(
        body.get("expires_at").and_then(Value::as_str),
        contract.default_ttl_seconds,
        contract.max_ttl_seconds,
    )?;
    if broad {
        if body.get("confirm_broad_scope").and_then(Value::as_bool) != Some(true) {
            return Err(CliError::Input(
                "prefix and ASN List targets require `confirm_broad_scope: true` after reviewing every consumer"
                    .to_owned(),
            ));
        }
        if action != "managed_challenge" || ttl_seconds > 3_600 {
            return Err(CliError::Input(
                "broad List targets are limited to an expected Managed Challenge action for at most one hour"
                    .to_owned(),
            ));
        }
    }
    if action == "block" {
        if body.get("confirm_block").and_then(Value::as_bool) != Some(true) {
            return Err(CliError::Input(
                "an expected block consumer requires `confirm_block: true`; Managed Challenge is the default"
                    .to_owned(),
            ));
        }
        let Some((wire_type, target_value, prefix)) = operator_target.as_ref() else {
            return Err(CliError::Input(
                "governed List block use is limited to one exact public IP; prefixes, ASNs, and hostnames use Managed Challenge"
                    .to_owned(),
            ));
        };
        if wire_type == "ip_range" {
            return Err(CliError::Input(
                "governed List block use is limited to one exact public IP; prefixes use Managed Challenge"
                    .to_owned(),
            ));
        }
        let operator_ip = security_action_string(&body, "operator_ip")?;
        validate_operator_not_targeted(operator_ip, wire_type, target_value, *prefix)?;
        if ttl_seconds > 86_400 {
            return Err(CliError::Input(
                "List-backed blocks are limited to 24 hours; permanent blocks require separate escalation"
                    .to_owned(),
            ));
        }
    }
    let expires_at = expires_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let target_hash = hash_value(&normalized_target)?;
    let audit = json!({
        "cfctl_list_security_v1":{
            "actor":actor,
            "evidence_ref":evidence_ref,
            "expected_consumer_action":action,
            "expires_at":expires_at,
            "reason":reason,
            "target_hash":target_hash,
        }
    });
    let comment = serde_json::to_string(&audit)?;
    if comment.len() > 500 {
        return Err(CliError::Input(
            "List security audit comment exceeds the Cloudflare-safe 500-byte bound".to_owned(),
        ));
    }
    let mut wire = wire_target.as_object().cloned().ok_or_else(|| {
        CliError::Input("normalized List target did not produce one wire item".to_owned())
    })?;
    wire.insert("comment".to_owned(), Value::String(comment.clone()));
    input.body = Some(Value::Array(vec![Value::Object(wire)]));
    Ok(json!({
        "schema_version":1,
        "kind":"add_expiring_list_member",
        "actor":actor,
        "evidence_ref":evidence_ref,
        "expires_at":expires_at,
        "reason":reason,
        "target":normalized_target,
        "target_hash":target_hash,
        "expected_consumer_action":action,
        "blast_radius":blast_radius,
        "ttl_seconds":ttl_seconds,
        "consumer_scope_confirmed":true,
        "managed_challenge_default":true,
        "permanent_action":false,
        "anonymous_identity_inferred":false,
        "self_block_checked":action == "block",
        "wire_comment_hash":hash_value(&Value::String(comment))?,
    }))
}

pub(super) fn prepare_list_security_action_remove(input: &mut CallInput) -> Result<Value> {
    let member_id = input
        .body
        .as_ref()
        .and_then(|body| body.get("member_id"))
        .and_then(Value::as_str)
        .filter(|identity| identity.len() == 32)
        .ok_or_else(|| {
            CliError::Input(
                "expired List member removal requires one 32-character member_id".to_owned(),
            )
        })?
        .to_owned();
    let mut receipt = prepare_security_action_remove(input, "remove_expired_list_member")?;
    input.body = Some(json!({"items":[{"id":member_id}]}));
    let receipt_object = receipt.as_object_mut().ok_or_else(|| {
        CliError::Input("security action removal did not produce an object receipt".to_owned())
    })?;
    receipt_object.insert("member_id".to_owned(), Value::String(member_id));
    Ok(receipt)
}

pub(super) fn rule_string_literal(value: &str) -> Result<String> {
    serde_json::to_string(value).map_err(CliError::from)
}

#[expect(
    clippy::too_many_lines,
    reason = "the closed WAF target matrix keeps every accepted target form and its blast-radius semantics together for auditability"
)]
pub(super) fn normalize_waf_security_target(
    target: &Map<String, Value>,
) -> Result<NormalizedWafSecurityTarget> {
    let target_type = security_action_string(target, "type")?;
    let raw = security_action_string(target, "value")?;
    match target_type {
        "ip" => {
            let address = normalize_public_ip(raw)?;
            let value = address.to_string();
            Ok((
                format!("ip.src eq {value}"),
                json!({"type":"ip","value":value}),
                "one exact public IP address".to_owned(),
                false,
                Some((
                    if address.is_ipv4() { "ip" } else { "ip6" }.to_owned(),
                    value,
                    None,
                )),
            ))
        }
        "ip_range" => {
            let (value, network, prefix) = normalize_bounded_ipv4_prefix(raw)?;
            let addresses = 1_u64 << (32 - u32::from(prefix));
            Ok((
                format!("ip.src in {{{value}}}"),
                json!({"type":"ip_range","value":value}),
                format!("one IPv4 /{prefix} prefix ({addresses} addresses)"),
                true,
                Some((
                    "ip_range".to_owned(),
                    value,
                    Some((network, prefix)),
                )),
            ))
        }
        "asn" => {
            let numeric = raw
                .trim()
                .trim_start_matches("AS")
                .trim_start_matches("as")
                .parse::<u32>()
                .ok()
                .filter(|value| *value > 0)
                .ok_or_else(|| CliError::Input("ASN target must be a positive AS number".to_owned()))?;
            Ok((
                format!("ip.src.asnum eq {numeric}"),
                json!({"type":"asn","value":format!("AS{numeric}")}),
                "all traffic attributed by Cloudflare to one ASN".to_owned(),
                true,
                None,
            ))
        }
        "country" => {
            let country = raw.to_ascii_uppercase();
            if country.len() != 2 || !country.bytes().all(|byte| byte.is_ascii_alphabetic()) {
                return Err(CliError::Input(
                    "country target must be a two-letter ISO country code".to_owned(),
                ));
            }
            Ok((
                format!("ip.src.country eq {}", rule_string_literal(&country)?),
                json!({"type":"country","value":country}),
                "all traffic classified by Cloudflare to one country".to_owned(),
                true,
                None,
            ))
        }
        "hostname" => {
            let hostname = match url::Host::parse(raw).map_err(|_| {
                CliError::Input("hostname target must be one valid exact hostname".to_owned())
            })? {
                url::Host::Domain(hostname) => hostname.to_ascii_lowercase(),
                _ => {
                    return Err(CliError::Input(
                        "hostname targets cannot be IP literals; use target type `ip`".to_owned(),
                    ));
                }
            };
            if hostname.len() > 253 || hostname.starts_with('.') || hostname.ends_with('.') {
                return Err(CliError::Input(
                    "hostname target must be one normalized DNS hostname".to_owned(),
                ));
            }
            Ok((
                format!("http.host eq {}", rule_string_literal(&hostname)?),
                json!({"type":"hostname","value":hostname}),
                "all requests to one exact hostname in the selected zone".to_owned(),
                false,
                None,
            ))
        }
        "path" => {
            if !raw.starts_with('/')
                || raw.len() > 2_048
                || raw.chars().any(char::is_control)
                || raw.contains('?')
                || raw.contains('#')
            {
                return Err(CliError::Input(
                    "path target must be one exact URI path beginning with `/`, without query, fragment, or control characters"
                        .to_owned(),
                ));
            }
            Ok((
                format!("http.request.uri.path eq {}", rule_string_literal(raw)?),
                json!({"type":"path","value":raw}),
                "all requests to one exact path across the selected zone".to_owned(),
                false,
                None,
            ))
        }
        "ja4" => {
            let fingerprint = raw.to_ascii_lowercase();
            if !(20..=64).contains(&fingerprint.len())
                || !fingerprint
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            {
                return Err(CliError::Input(
                    "JA4 target must be a 20-64 character lowercase alphanumeric/underscore fingerprint"
                        .to_owned(),
                ));
            }
            Ok((
                format!(
                    "cf.bot_management.ja4 eq {}",
                    rule_string_literal(&fingerprint)?
                ),
                json!({"type":"ja4","value":fingerprint}),
                "all requests with one exact JA4 fingerprint; Cloudflare requires Enterprise Bot Management"
                    .to_owned(),
                false,
                None,
            ))
        }
        _ => Err(CliError::Input(
            "WAF security target type must be `ip`, `ip_range`, `asn`, `country`, `hostname`, `path`, or `ja4`"
                .to_owned(),
        )),
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "WAF enforcement planning keeps evidence, target, action, scope, expiry, self-block, and escalation checks in one fail-closed review boundary"
)]
pub(super) fn prepare_waf_security_action_create(
    capability: &CapabilityV1,
    input: &mut CallInput,
) -> Result<Value> {
    let contract = capability
        .security_action
        .as_ref()
        .ok_or_else(|| CliError::Input("WAF security action contract is missing".to_owned()))?;
    let body = input
        .body
        .as_ref()
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| CliError::Input("WAF security action body must be an object".to_owned()))?;
    let actor = security_action_string(&body, "actor")?.to_owned();
    let evidence_ref = security_action_string(&body, "evidence_ref")?.to_owned();
    let reason = security_action_string(&body, "reason")?.trim().to_owned();
    if reason.chars().any(char::is_control) {
        return Err(CliError::Input(
            "security action reason cannot contain control characters".to_owned(),
        ));
    }
    let action = body
        .get("action")
        .and_then(Value::as_str)
        .or(contract.default_action.as_deref())
        .ok_or_else(|| CliError::Input("WAF security action has no default action".to_owned()))?;
    if !contract
        .allowed_actions
        .iter()
        .any(|allowed| allowed == action)
    {
        return Err(CliError::Input(format!(
            "WAF security action `{action}` is outside the governed allowlist"
        )));
    }
    let target = body
        .get("target")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CliError::Input("WAF security action target must be an object".to_owned())
        })?;
    let (expression, normalized_target, blast_radius, broad, operator_target) =
        normalize_waf_security_target(target)?;
    let (expires_at, ttl_seconds) = security_expiry(
        body.get("expires_at").and_then(Value::as_str),
        contract.default_ttl_seconds,
        contract.max_ttl_seconds,
    )?;
    if broad {
        if body.get("confirm_broad_scope").and_then(Value::as_bool) != Some(true) {
            return Err(CliError::Input(
                "IP range, ASN, and country WAF targets require `confirm_broad_scope: true` after reviewing the blast radius"
                    .to_owned(),
            ));
        }
        if action != "managed_challenge" || ttl_seconds > 3_600 {
            return Err(CliError::Input(
                "broad WAF targets are limited to Managed Challenge for at most one hour"
                    .to_owned(),
            ));
        }
    }
    if action == "block" {
        if body.get("confirm_block").and_then(Value::as_bool) != Some(true) {
            return Err(CliError::Input(
                "a WAF block requires `confirm_block: true`; Managed Challenge is the default when confidence is incomplete"
                    .to_owned(),
            ));
        }
        let Some((wire_type, target_value, prefix)) = operator_target.as_ref() else {
            return Err(CliError::Input(
                "governed WAF block is limited to one exact public IP; hostname, path, fingerprint, ASN, country, and prefix blocks require a separately reviewed policy design"
                    .to_owned(),
            ));
        };
        if wire_type == "ip_range" {
            return Err(CliError::Input(
                "governed WAF block is limited to one exact public IP; prefixes use Managed Challenge"
                    .to_owned(),
            ));
        }
        let operator_ip = security_action_string(&body, "operator_ip")?;
        validate_operator_not_targeted(operator_ip, wire_type, target_value, *prefix)?;
        if ttl_seconds > 86_400 {
            return Err(CliError::Input(
                "WAF blocks are limited to 24 hours; permanent blocks require separate escalation"
                    .to_owned(),
            ));
        }
    }
    if action == "skip"
        && (body.get("confirm_skip").and_then(Value::as_bool) != Some(true)
            || body.get("confirm_broad_scope").and_then(Value::as_bool) != Some(true)
            || ttl_seconds > 3_600)
    {
        return Err(CliError::Input(
                "skip requires `confirm_skip: true`, `confirm_broad_scope: true`, and an expiry within one hour; cfctl only skips the managed WAF phase"
                    .to_owned(),
            ));
    }
    if normalized_target.get("type").and_then(Value::as_str) == Some("ja4")
        && body
            .get("confirm_enterprise_bot_management")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err(CliError::Input(
            "JA4 targeting requires `confirm_enterprise_bot_management: true`; Cloudflare documents this field as Enterprise with Bot Management"
                .to_owned(),
        ));
    }
    let expires_at = expires_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let audit = json!({
        "cfctl_security_v1":{
            "actor":actor,
            "evidence_ref":evidence_ref,
            "expires_at":expires_at,
            "reason":reason,
            "target":normalized_target,
        }
    });
    let description = serde_json::to_string(&audit)?;
    if description.len() > 500 {
        return Err(CliError::Input(
            "WAF security action audit description exceeds the 500-byte governed bound".to_owned(),
        ));
    }
    let correlation_hash = hash_value(&json!({
        "action":action,
        "actor":actor,
        "evidence_ref":evidence_ref,
        "expires_at":expires_at,
        "reason":reason,
        "target":normalized_target,
    }))?;
    let ref_suffix = correlation_hash
        .strip_prefix("sha256:")
        .and_then(|hash| hash.get(..24))
        .ok_or_else(|| {
            CliError::Input("WAF security action correlation hash is invalid".to_owned())
        })?;
    let reference = format!("cfctl_security_{ref_suffix}");
    let mut wire = serde_json::Map::from_iter([
        ("action".to_owned(), Value::String(action.to_owned())),
        ("description".to_owned(), Value::String(description.clone())),
        ("enabled".to_owned(), Value::Bool(true)),
        ("expression".to_owned(), Value::String(expression.clone())),
        ("ref".to_owned(), Value::String(reference.clone())),
    ]);
    if action == "skip" {
        wire.insert(
            "action_parameters".to_owned(),
            json!({"phases":["http_request_firewall_managed"]}),
        );
    }
    input.body = Some(Value::Object(wire));
    Ok(json!({
        "schema_version":1,
        "kind":"create_expiring_waf",
        "action":action,
        "actor":actor,
        "evidence_ref":evidence_ref,
        "expires_at":expires_at,
        "reason":reason,
        "target":normalized_target,
        "expression":expression,
        "correlation_ref":reference,
        "blast_radius":blast_radius,
        "ttl_seconds":ttl_seconds,
        "managed_challenge_default":true,
        "permanent_action":false,
        "anonymous_identity_inferred":false,
        "self_block_checked":action == "block",
        "skip_scope":(action == "skip").then_some("http_request_firewall_managed"),
        "wire_description_hash":hash_value(&Value::String(description))?,
    }))
}

pub(super) fn prepare_security_action_remove(input: &mut CallInput, kind: &str) -> Result<Value> {
    let body = input
        .body
        .as_ref()
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| {
            CliError::Input("expired-action removal body must be an object".to_owned())
        })?;
    let actor = security_action_string(&body, "actor")?.to_owned();
    let evidence_ref = security_action_string(&body, "evidence_ref")?.to_owned();
    let expires_at = security_action_string(&body, "expires_at")?.to_owned();
    let reason = security_action_string(&body, "reason")?.trim().to_owned();
    let source_operation_id = security_action_string(&body, "source_operation_id")?.to_owned();
    let expiry = chrono::DateTime::parse_from_rfc3339(&expires_at)
        .map_err(|_| CliError::Input("removal `expires_at` must be RFC3339".to_owned()))?
        .with_timezone(&Utc);
    if expiry > Utc::now() {
        return Err(CliError::Input(
            "the security action has not reached its removal deadline; use the source operation's exact rollback only when early removal is intentionally required"
                .to_owned(),
        ));
    }
    input.body = None;
    Ok(json!({
        "schema_version":1,
        "kind":kind,
        "actor":actor,
        "evidence_ref":evidence_ref,
        "expires_at":expiry.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "reason":reason,
        "source_operation_id":source_operation_id,
        "anonymous_identity_inferred":false,
    }))
}

pub(super) fn prepare_security_action_input(
    capability: &CapabilityV1,
    input: &mut CallInput,
) -> Result<Option<Value>> {
    let Some(contract) = capability.security_action.as_ref() else {
        return Ok(None);
    };
    validate_security_action_governance_input(capability, input)?;
    let receipt = match (capability.id.as_str(), contract.kind) {
        (SECURITY_IP_RULE_CREATE_ID, SecurityActionKindV1::CreateExpiring) => {
            prepare_security_action_create(capability, input)?
        }
        (SECURITY_IP_RULE_REMOVE_ID, SecurityActionKindV1::RemoveExpired) => {
            prepare_security_action_remove(input, "remove_expired")?
        }
        (SECURITY_WAF_RULE_CREATE_ID, SecurityActionKindV1::CreateExpiring) => {
            prepare_waf_security_action_create(capability, input)?
        }
        (SECURITY_WAF_RULE_REMOVE_ID, SecurityActionKindV1::RemoveExpired) => {
            prepare_security_action_remove(input, "remove_expired_waf")?
        }
        (SECURITY_LIST_MEMBER_CREATE_ID, SecurityActionKindV1::AddExpiringListMember) => {
            prepare_list_security_action_create(capability, input)?
        }
        (SECURITY_LIST_MEMBER_REMOVE_ID, SecurityActionKindV1::RemoveExpiredListMember) => {
            prepare_list_security_action_remove(input)?
        }
        _ => {
            return Err(CliError::Input(
                "security action renderer is not implemented for this exact capability identity"
                    .to_owned(),
            ));
        }
    };
    Ok(Some(receipt))
}
