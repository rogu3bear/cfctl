use super::delegated_execution::wrangler_versions_deploy_version_id;
use super::prelude::{
    BTreeMap, CallArgs, CallInput, CapabilityV1, CliError, Map, MoneyV1, Path, PlanStatus,
    ProfileMetadata, Result, StateStore, Value, VerificationState, env,
};
use super::support::cli_io;
use super::support::read_stdin;
use cfctl_core::redact_json;

pub(super) fn resolve_account_id(
    store: &StateStore,
    profile: &ProfileMetadata,
    requested: Option<&str>,
    input: &CallInput,
) -> Result<Option<String>> {
    let selector = input.selectors.get("account_id").and_then(Value::as_str);
    if let (Some(argument), Some(selector)) = (requested, selector)
        && argument != selector
    {
        return Err(CliError::Input(format!(
            "account selection is ambiguous: --account `{argument}` differs from selector `{selector}`"
        )));
    }
    if let Some(explicit) = requested.or(selector) {
        return Ok(Some(explicit.to_owned()));
    }

    let pins = store.workspace_manifest()?.account_pins();
    let cwd = env::current_dir().map_err(|source| cli_io(Path::new("."), source))?;
    let workspace_pin = pins
        .into_iter()
        .filter(|(root, _)| cwd.starts_with(root))
        .max_by_key(|(root, _)| root.components().count())
        .map(|(_, account)| account);
    if let (Some(workspace), Some(profile_account)) =
        (workspace_pin.as_deref(), profile.account_id.as_deref())
        && workspace != profile_account
    {
        return Err(CliError::Input(format!(
            "account selection is ambiguous: workspace pins `{workspace}` but profile `{}` pins `{profile_account}`; pass --account explicitly",
            profile.id
        )));
    }
    Ok(workspace_pin.or_else(|| profile.account_id.clone()))
}

pub(super) struct PreparedCallInput {
    pub(super) input: CallInput,
    pub(super) secret_body: Option<Value>,
}

pub(super) fn call_input(
    capability: &CapabilityV1,
    arguments: &CallArgs,
) -> Result<PreparedCallInput> {
    let selectors = object_from_pairs(&arguments.selectors);
    let query = query_object_from_pairs(capability, &arguments.query)?;
    validate_wrangler_worker_versions_input(capability, &query)?;
    let body = if arguments.body_stdin {
        Some(serde_json::from_str(&read_stdin()?)?)
    } else {
        arguments
            .body_json
            .as_deref()
            .map(serde_json::from_str)
            .transpose()?
    };
    let contains_secret = body
        .as_ref()
        .is_some_and(|value| request_body_contains_secret(capability, value));
    if contains_secret && !arguments.body_stdin {
        return Err(CliError::Input(
            "secret-shaped request fields are accepted only through `--body-stdin`, never command arguments"
                .to_owned(),
        ));
    }
    Ok(PreparedCallInput {
        input: CallInput {
            selectors,
            query,
            body: if contains_secret { None } else { body.clone() },
            if_match: arguments.if_match.clone(),
            if_none_match: arguments.if_none_match.clone(),
        },
        secret_body: contains_secret.then_some(body).flatten(),
    })
}

pub(super) fn validate_wrangler_worker_versions_input(
    capability: &CapabilityV1,
    query: &Value,
) -> Result<()> {
    if !matches!(
        capability.id.as_str(),
        "wrangler.versions-upload" | "wrangler.versions-deploy"
    ) {
        return Ok(());
    }
    let config = query.get("config").and_then(Value::as_str).ok_or_else(|| {
        CliError::Input("Worker Versions plans require a config selector".to_owned())
    })?;
    if !Path::new(config).is_absolute() {
        return Err(CliError::Input(
            "Worker Versions plans require an absolute Wrangler config path".to_owned(),
        ));
    }
    if capability.id == "wrangler.versions-deploy" {
        let spec = query
            .get("argument")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CliError::Input(
                    "Worker Versions deployment requires exactly one UUID@100 target".to_owned(),
                )
            })?;
        if wrangler_versions_deploy_version_id(spec).is_none() {
            return Err(CliError::Input(
                "Worker Versions deployment target must be exactly one UUID@100 value".to_owned(),
            ));
        }
    }
    Ok(())
}

pub(super) fn request_body_contains_secret(capability: &CapabilityV1, body: &Value) -> bool {
    redact_json(body) != *body
        || body.as_object().is_some_and(|fields| {
            fields
                .keys()
                .any(|field| capability.request_object_field_is_write_only(field))
        })
}

pub(super) fn query_object_from_pairs(
    capability: &CapabilityV1,
    pairs: &[(String, String)],
) -> Result<Value> {
    let mut grouped = BTreeMap::<String, Vec<String>>::new();
    for (name, value) in pairs {
        grouped.entry(name.clone()).or_default().push(value.clone());
    }
    let mut query = Map::new();
    for (name, values) in grouped {
        let array_typed = capability.selectors.iter().any(|selector| {
            selector.location == "query" && selector.name == name && selector.value_type == "array"
        });
        if array_typed {
            query.insert(
                name,
                Value::Array(values.into_iter().map(Value::String).collect()),
            );
        } else if values.len() == 1 {
            query.insert(name, Value::String(values[0].clone()));
        } else {
            return Err(CliError::Input(format!(
                "query control `{name}` is repeated but its catalog type is not an array"
            )));
        }
    }
    Ok(Value::Object(query))
}

pub(super) fn object_from_pairs(pairs: &[(String, String)]) -> Value {
    Value::Object(
        pairs
            .iter()
            .map(|(key, value)| (key.clone(), Value::String(value.clone())))
            .collect::<Map<String, Value>>(),
    )
}

pub(super) fn parse_callback(value: &str) -> Result<(String, String)> {
    if let Ok(document) = serde_json::from_str::<Value>(value) {
        let state = document.get("state").and_then(Value::as_str);
        let code = document.get("code").and_then(Value::as_str);
        if let (Some(state), Some(code)) = (state, code) {
            return Ok((state.to_owned(), code.to_owned()));
        }
    }
    let mut parts = value.split_whitespace();
    let state = parts.next();
    let code = parts.next();
    if let (Some(state), Some(code), None) = (state, code, parts.next()) {
        return Ok((state.to_owned(), code.to_owned()));
    }
    Err(CliError::Input(
        "callback stdin must be JSON with `state` and `code`, or exactly `STATE CODE`".to_owned(),
    ))
}

pub(super) fn parse_money(value: &str) -> Result<MoneyV1> {
    let (currency, amount) = value
        .split_once(':')
        .ok_or_else(|| CliError::Input("cost ceiling must be CURRENCY:AMOUNT".to_owned()))?;
    if currency.len() != 3
        || !currency
            .chars()
            .all(|character| character.is_ascii_alphabetic())
    {
        return Err(CliError::Input(
            "currency must be a three-letter code".to_owned(),
        ));
    }
    let amount = amount
        .parse::<f64>()
        .map_err(|_| CliError::Input("cost amount is not a number".to_owned()))?;
    if !amount.is_finite() || amount < 0.0 {
        return Err(CliError::Input(
            "cost amount must be finite and non-negative".to_owned(),
        ));
    }
    Ok(MoneyV1 {
        currency: currency.to_ascii_uppercase(),
        amount,
    })
}

pub(crate) fn verification_for_status(status: PlanStatus) -> VerificationState {
    match status {
        PlanStatus::Verified | PlanStatus::Rectified => VerificationState::Passed,
        PlanStatus::Failed => VerificationState::Failed,
        PlanStatus::RectificationRequired => VerificationState::Unsupported,
        _ => VerificationState::Pending,
    }
}
