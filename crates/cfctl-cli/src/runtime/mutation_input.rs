use super::live_state_contracts::is_cloudflare_tunnel_configuration_mutation;
use super::live_state_contracts::is_warp_connector_configuration_mutation;
use super::prelude::{BTreeSet, CallInput, CapabilityV1, CliError, Map, Result, Value};
use super::secret_io::is_worker_script_secret_input_only_capability;

pub(super) fn validate_d1_database_create_semantics(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<()> {
    if capability.id != "d1-create-database" {
        return Ok(());
    }
    let Some(body) = input.body.as_ref().and_then(Value::as_object) else {
        return Ok(());
    };
    if body.contains_key("jurisdiction") && body.contains_key("primary_location_hint") {
        return Err(CliError::Input(
            "D1 database creation cannot combine `jurisdiction` with `primary_location_hint`: Cloudflare gives jurisdiction precedence and ignores the location hint; choose the hard jurisdiction boundary or the best-effort location hint"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate_cloudflare_tunnel_configuration_ingress(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<()> {
    if !is_cloudflare_tunnel_configuration_mutation(capability) {
        return Ok(());
    }
    let ingress = input
        .body
        .as_ref()
        .and_then(|body| body.pointer("/config/ingress"))
        .and_then(Value::as_array)
        .filter(|rules| !rules.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "Tunnel configuration requires at least one ingress rule and a final catch-all rule"
                    .to_owned(),
            )
        })?;
    for (index, rule) in ingress.iter().enumerate() {
        let service = rule
            .get("service")
            .and_then(Value::as_str)
            .filter(|service| !service.trim().is_empty())
            .ok_or_else(|| {
                CliError::Input(format!(
                    "Tunnel ingress rule {} requires a non-empty service",
                    index + 1
                ))
            })?;
        let _ = service;
        let matches_all_traffic =
            rule.get("hostname").and_then(Value::as_str) == Some("") && rule.get("path").is_none();
        if matches_all_traffic && index + 1 != ingress.len() {
            return Err(CliError::Input(format!(
                "Tunnel ingress rule {} is a catch-all, so every later rule is unreachable; move the catch-all to the end",
                index + 1
            )));
        }
        if index + 1 == ingress.len() && !matches_all_traffic {
            return Err(CliError::Input(
                "Tunnel configuration requires a final catch-all ingress rule with an empty hostname and no path"
                    .to_owned(),
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_warp_connector_configuration_semantics(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<()> {
    if !is_warp_connector_configuration_mutation(capability) {
        return Ok(());
    }
    let body = input
        .body
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CliError::Input("WARP Connector configuration requires a JSON object body".to_owned())
        })?;
    let mode = body.get("ha_mode").and_then(Value::as_str).ok_or_else(|| {
        CliError::Input("WARP Connector configuration requires string field `ha_mode`".to_owned())
    })?;
    let config = body.get("config").filter(|value| !value.is_null());
    match mode {
        "none" | "disabled" => {
            if config.is_some_and(|value| {
                value
                    .as_object()
                    .is_none_or(|configuration| !configuration.is_empty())
            }) {
                return Err(CliError::Input(format!(
                    "WARP Connector HA mode `{mode}` requires `config` to be omitted, null, or an empty object"
                )));
            }
        }
        "aws" => {
            let fnr_id = config
                .and_then(|value| value.get("fnr_id"))
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                    CliError::Input(
                        "WARP Connector HA mode `aws` requires a non-empty `config.fnr_id`"
                            .to_owned(),
                    )
                })?;
            let _ = fnr_id;
        }
        "local" => {
            let configuration = config.and_then(Value::as_object).ok_or_else(|| {
                CliError::Input("WARP Connector HA mode `local` requires `config.vips`".to_owned())
            })?;
            let mut addresses = BTreeSet::new();
            validate_warp_connector_vip_addresses(configuration, "vips", true, &mut addresses)?;
            validate_warp_connector_vip_addresses(
                configuration,
                "vips_previous",
                false,
                &mut addresses,
            )?;
        }
        _ => {
            return Err(CliError::Input(format!(
                "unsupported WARP Connector HA mode `{mode}`"
            )));
        }
    }
    Ok(())
}

pub(super) fn validate_worker_script_secret_semantics(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<()> {
    if !is_worker_script_secret_input_only_capability(capability) {
        return Ok(());
    }
    let body = input
        .body
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CliError::Input("Worker script secret input requires a JSON object body".to_owned())
        })?;
    let secret_type = body.get("type").and_then(Value::as_str).ok_or_else(|| {
        CliError::Input("Worker script secret input requires string field `type`".to_owned())
    })?;
    let has_base64 = body.contains_key("key_base64");
    let has_jwk = body.contains_key("key_jwk");
    if has_base64 && has_jwk {
        return Err(CliError::Input(
            "Worker script secret_key input accepts exactly one key material field: `key_base64` or `key_jwk`"
                .to_owned(),
        ));
    }
    match secret_type {
        "secret_text" => {
            if body.get("text").and_then(Value::as_str).is_none() {
                return Err(CliError::Input(
                    "Worker script secret_text input requires string field `text`".to_owned(),
                ));
            }
            if has_base64 || has_jwk {
                return Err(CliError::Input(
                    "Worker script secret_text accepts only `text`, never key material fields"
                        .to_owned(),
                ));
            }
        }
        "secret_key" => {
            let format = body.get("format").and_then(Value::as_str).ok_or_else(|| {
                CliError::Input(
                    "Worker script secret_key input requires string field `format`".to_owned(),
                )
            })?;
            if format == "jwk" {
                if !has_jwk || has_base64 {
                    return Err(CliError::Input(
                        "Worker script secret_key format `jwk` requires `key_jwk` and forbids `key_base64`"
                            .to_owned(),
                    ));
                }
            } else if matches!(format, "raw" | "pkcs8" | "spki") {
                if !has_base64 || has_jwk {
                    return Err(CliError::Input(format!(
                        "Worker script secret_key format `{format}` requires `key_base64` and forbids `key_jwk`"
                    )));
                }
            } else {
                return Err(CliError::Input(
                    "Worker script secret_key format must be one of `raw`, `pkcs8`, `spki`, or `jwk`"
                        .to_owned(),
                ));
            }
        }
        _ => {
            return Err(CliError::Input(
                "Worker script secret type must be `secret_text` or `secret_key`".to_owned(),
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_warp_connector_vip_addresses(
    configuration: &Map<String, Value>,
    field: &str,
    required: bool,
    addresses: &mut BTreeSet<std::net::IpAddr>,
) -> Result<()> {
    let Some(values) = configuration.get(field) else {
        return if required {
            Err(CliError::Input(format!(
                "WARP Connector HA mode `local` requires `config.{field}`"
            )))
        } else {
            Ok(())
        };
    };
    let values = values.as_array().ok_or_else(|| {
        CliError::Input(format!(
            "WARP Connector `config.{field}` must be an array of IP addresses"
        ))
    })?;
    for (index, value) in values.iter().enumerate() {
        let address = value
            .get("address")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                CliError::Input(format!(
                    "WARP Connector `config.{field}[{index}].address` must be a non-empty IP address"
                ))
            })?;
        let address_identity = address.parse::<std::net::IpAddr>().map_err(|_| {
            CliError::Input(format!(
                "WARP Connector `config.{field}[{index}].address` is not a valid IPv4 or IPv6 address"
            ))
        })?;
        if !addresses.insert(address_identity) {
            return Err(CliError::Input(format!(
                "WARP Connector IP address `{address}` is duplicated across the current and previous VIP sets"
            )));
        }
    }
    Ok(())
}
