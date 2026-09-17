//! Operator route surface for Worker `cfctl-site`.
//!
//! Three independent this-reads; none stands in for another:
//! 1. workers.dev host from `getWorker` `subdomain.url`
//! 2. `workers.domains.list` filtered to `service=cfctl-site`
//! 3. zone worker routes from `worker-routes-list-routes` whose script is
//!    `cfctl-site`
//!
//! `worker-routes-list-routes` needs `zone_id`. Missing zone inventory is not
//! `routes:[]`. Do not attach `cfctl.com` here.

#![cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "closed operator handoff assembled from getWorker, workers.domains.list, and worker-routes-list-routes this-reads"
    )
)]

use std::collections::BTreeSet;

use serde_json::{Value, json};

use super::CliError;

pub(super) const SERVICE_NAME: &str = "cfctl-site";
pub(super) const WORKERS_DEV_CAPABILITY_ID: &str = "getWorker";
pub(super) const CUSTOM_DOMAINS_CAPABILITY_ID: &str = "workers.domains.list";
pub(super) const ZONE_ROUTES_CAPABILITY_ID: &str = "worker-routes-list-routes";

pub(super) struct ZoneRouteRead {
    pub zone_id: String,
    pub result: Value,
}

pub(super) enum ZoneRoutesObservation {
    InventoryMissing,
    NotPerformed,
    Performed {
        zone_ids: Vec<String>,
        reads: Vec<ZoneRouteRead>,
    },
}

pub(super) fn workers_dev_call_argv(account_id: &str) -> Vec<String> {
    vec![
        "cfctl".to_owned(),
        "call".to_owned(),
        WORKERS_DEV_CAPABILITY_ID.to_owned(),
        "--selector".to_owned(),
        format!("account_id={account_id}"),
        "--selector".to_owned(),
        format!("worker_id={SERVICE_NAME}"),
        "--json".to_owned(),
    ]
}

pub(super) fn custom_domains_call_argv(account_id: &str) -> Vec<String> {
    vec![
        "cfctl".to_owned(),
        "call".to_owned(),
        CUSTOM_DOMAINS_CAPABILITY_ID.to_owned(),
        "--selector".to_owned(),
        format!("account_id={account_id}"),
        "--json".to_owned(),
    ]
}

pub(super) fn zone_routes_call_argv(zone_id: &str) -> Vec<String> {
    vec![
        "cfctl".to_owned(),
        "call".to_owned(),
        ZONE_ROUTES_CAPABILITY_ID.to_owned(),
        "--selector".to_owned(),
        format!("zone_id={zone_id}"),
        "--json".to_owned(),
    ]
}

pub(super) fn serialize_cfctl_site_route_surface(
    workers_dev: Option<&Value>,
    custom_domains: Option<&Value>,
    zone_routes: ZoneRoutesObservation,
) -> Result<Value, CliError> {
    let workers_dev = workers_dev.ok_or_else(|| {
        CliError::Input(
            "cfctl-site workers.dev host requires a getWorker this-read of subdomain.url; workers.domains.list is not that host"
                .to_owned(),
        )
    })?;
    let custom_domains = custom_domains.ok_or_else(|| {
        CliError::Input(
            "cfctl-site custom domains require workers.domains.list filtered to service=cfctl-site; zone routes are not that list"
                .to_owned(),
        )
    })?;
    let (zone_ids, routes) = match zone_routes {
        ZoneRoutesObservation::InventoryMissing => {
            return Err(CliError::Input(
                "cfctl-site zone worker routes require zone inventory for worker-routes-list-routes; missing inventory is not routes:[]"
                    .to_owned(),
            ));
        }
        ZoneRoutesObservation::NotPerformed => {
            return Err(CliError::Input(
                "cfctl-site zone worker routes require worker-routes-list-routes for each inventoried zone_id; skipping that read is not routes:[]"
                    .to_owned(),
            ));
        }
        ZoneRoutesObservation::Performed { zone_ids, reads } => {
            let routes = performed_zone_routes(&zone_ids, &reads)?;
            (zone_ids, routes)
        }
    };
    let handoff = json!({
        "schema_version": 1,
        "service": SERVICE_NAME,
        "workers_dev": {
            "source_capability_id": WORKERS_DEV_CAPABILITY_ID,
            "url": workers_dev_url(workers_dev)?,
        },
        "custom_domains": {
            "source_capability_id": CUSTOM_DOMAINS_CAPABILITY_ID,
            "filter": {"service": SERVICE_NAME},
            "items": custom_domains_for_service(custom_domains)?,
        },
        "routes": routes,
        "routes_source_capability_id": ZONE_ROUTES_CAPABILITY_ID,
        "routes_zone_ids": zone_ids,
    });
    admit_cfctl_site_route_surface(&handoff)?;
    Ok(handoff)
}

pub(super) fn admit_cfctl_site_route_surface(handoff: &Value) -> Result<(), CliError> {
    let object = handoff.as_object().ok_or_else(|| {
        CliError::Input("cfctl-site route surface handoff is not an object".to_owned())
    })?;
    refuse_empty_routes_without_zone_read(handoff)?;
    if object.len() != 7
        || handoff.get("schema_version").and_then(Value::as_u64) != Some(1)
        || handoff.get("service").and_then(Value::as_str) != Some(SERVICE_NAME)
    {
        return Err(CliError::Input(
            "cfctl-site route surface handoff is malformed".to_owned(),
        ));
    }
    admit_workers_dev_spelling(handoff)?;
    admit_custom_domains_spelling(handoff)?;
    admit_zone_routes_spelling(handoff)
}

fn refuse_empty_routes_without_zone_read(handoff: &Value) -> Result<(), CliError> {
    if handoff
        .get("routes")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
        && handoff
            .get("routes_source_capability_id")
            .and_then(Value::as_str)
            != Some(ZONE_ROUTES_CAPABILITY_ID)
    {
        return Err(CliError::Input(
            "routes:[] is not admitted unless worker-routes-list-routes ran against zone inventory"
                .to_owned(),
        ));
    }
    Ok(())
}

fn admit_workers_dev_spelling(handoff: &Value) -> Result<(), CliError> {
    let workers_dev = handoff
        .get("workers_dev")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CliError::Input(
                "cfctl-site workers.dev host is missing from the route surface".to_owned(),
            )
        })?;
    if workers_dev
        .get("source_capability_id")
        .and_then(Value::as_str)
        != Some(WORKERS_DEV_CAPABILITY_ID)
        || workers_dev
            .get("url")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err(CliError::Input(
            "cfctl-site workers.dev host must come from getWorker subdomain.url".to_owned(),
        ));
    }
    Ok(())
}

fn admit_custom_domains_spelling(handoff: &Value) -> Result<(), CliError> {
    let custom_domains = handoff
        .get("custom_domains")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CliError::Input(
                "cfctl-site custom domains are missing from the route surface".to_owned(),
            )
        })?;
    if custom_domains
        .get("source_capability_id")
        .and_then(Value::as_str)
        != Some(CUSTOM_DOMAINS_CAPABILITY_ID)
        || handoff
            .pointer("/custom_domains/filter/service")
            .and_then(Value::as_str)
            != Some(SERVICE_NAME)
        || !custom_domains.get("items").is_some_and(Value::is_array)
    {
        return Err(CliError::Input(
            "cfctl-site custom domains must come from workers.domains.list filtered to service=cfctl-site"
                .to_owned(),
        ));
    }
    Ok(())
}

fn admit_zone_routes_spelling(handoff: &Value) -> Result<(), CliError> {
    let routes = handoff
        .get("routes")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CliError::Input(
                "cfctl-site zone worker routes are missing from the route surface".to_owned(),
            )
        })?;
    if handoff
        .get("routes_source_capability_id")
        .and_then(Value::as_str)
        != Some(ZONE_ROUTES_CAPABILITY_ID)
        || handoff
            .get("routes_zone_ids")
            .and_then(Value::as_array)
            .is_none()
    {
        return Err(CliError::Input(
            "empty or present routes are not admitted unless worker-routes-list-routes ran against zone inventory"
                .to_owned(),
        ));
    }
    if routes.iter().any(|route| {
        route.get("script").and_then(Value::as_str) != Some(SERVICE_NAME)
            || route
                .get("zone_id")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
    }) {
        return Err(CliError::Input(
            "cfctl-site zone worker routes must name script=cfctl-site and the zone_id that was read"
                .to_owned(),
        ));
    }
    Ok(())
}

fn workers_dev_url(result: &Value) -> Result<String, CliError> {
    result
        .pointer("/subdomain/url")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            CliError::Input(
                "getWorker this-read omitted subdomain.url; workers.dev is not proved by workers.domains.list or zone routes"
                    .to_owned(),
            )
        })
}

fn custom_domains_for_service(result: &Value) -> Result<Vec<Value>, CliError> {
    Ok(result_array(result, CUSTOM_DOMAINS_CAPABILITY_ID)?
        .iter()
        .filter(|item| item.get("service").and_then(Value::as_str) == Some(SERVICE_NAME))
        .cloned()
        .collect())
}

fn performed_zone_routes(
    zone_ids: &[String],
    reads: &[ZoneRouteRead],
) -> Result<Vec<Value>, CliError> {
    let mut unique = BTreeSet::new();
    for zone_id in zone_ids {
        if zone_id.is_empty() || !unique.insert(zone_id.as_str()) {
            return Err(CliError::Input(
                "cfctl-site zone inventory must be distinct non-empty zone_id values".to_owned(),
            ));
        }
    }
    let mut by_zone = std::collections::BTreeMap::new();
    for read in reads {
        if !unique.contains(read.zone_id.as_str()) {
            return Err(CliError::Input(format!(
                "worker-routes-list-routes for `{}` is not in the zone inventory",
                read.zone_id
            )));
        }
        if by_zone
            .insert(read.zone_id.as_str(), &read.result)
            .is_some()
        {
            return Err(CliError::Input(format!(
                "worker-routes-list-routes was repeated for zone `{}`",
                read.zone_id
            )));
        }
    }
    let mut routes = Vec::new();
    for zone_id in zone_ids {
        let Some(result) = by_zone.get(zone_id.as_str()) else {
            return Err(CliError::Input(format!(
                "worker-routes-list-routes was not performed for zone `{zone_id}`; refuse routes:[]"
            )));
        };
        routes.extend(zone_routes_for_script(result, zone_id)?);
    }
    Ok(routes)
}

fn zone_routes_for_script(result: &Value, zone_id: &str) -> Result<Vec<Value>, CliError> {
    let mut routes = Vec::new();
    for item in result_array(result, ZONE_ROUTES_CAPABILITY_ID)? {
        if item.get("script").and_then(Value::as_str) != Some(SERVICE_NAME) {
            continue;
        }
        let mut route = item.clone();
        let object = route.as_object_mut().ok_or_else(|| {
            CliError::Input(
                "worker-routes-list-routes item is not an object; refuse routes:[]".to_owned(),
            )
        })?;
        object.insert("zone_id".to_owned(), json!(zone_id));
        routes.push(route);
    }
    Ok(routes)
}

fn result_array<'a>(result: &'a Value, capability_id: &str) -> Result<&'a [Value], CliError> {
    result.as_array().map(Vec::as_slice).ok_or_else(|| {
        CliError::Input(format!(
            "`{capability_id}` this-read did not return an array"
        ))
    })
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "unit tests bind the three route spellings with explicit fixtures"
)]
mod tests {
    use super::{
        CUSTOM_DOMAINS_CAPABILITY_ID, SERVICE_NAME, WORKERS_DEV_CAPABILITY_ID,
        ZONE_ROUTES_CAPABILITY_ID, ZoneRouteRead, ZoneRoutesObservation,
        admit_cfctl_site_route_surface, custom_domains_call_argv,
        serialize_cfctl_site_route_surface, workers_dev_call_argv, zone_routes_call_argv,
    };
    use serde_json::{Value, json};

    fn get_worker() -> Value {
        json!({"id":"worker-1","name":SERVICE_NAME,"subdomain":{"url":"https://cfctl-site.example.workers.dev"}})
    }

    fn domains_list() -> Value {
        json!([
            {"id":"domain-other","hostname":"other.example","service":"other-worker"},
            {"id":"domain-site","hostname":"docs.example","service":SERVICE_NAME}
        ])
    }

    #[test]
    fn serialize_refuses_empty_routes_when_zone_route_read_was_not_performed() {
        let error = serialize_cfctl_site_route_surface(
            Some(&get_worker()),
            Some(&domains_list()),
            ZoneRoutesObservation::NotPerformed,
        )
        .expect_err("unread zone routes must not serialize")
        .to_string();
        assert!(error.contains(ZONE_ROUTES_CAPABILITY_ID));
        assert!(error.contains("not routes:[]"));

        let missing = serialize_cfctl_site_route_surface(
            Some(&get_worker()),
            Some(&domains_list()),
            ZoneRoutesObservation::InventoryMissing,
        )
        .expect_err("missing zone inventory must not serialize")
        .to_string();
        assert!(missing.contains(ZONE_ROUTES_CAPABILITY_ID));
        assert!(missing.contains("not routes:[]"));

        let forged = json!({
            "schema_version": 1,
            "service": SERVICE_NAME,
            "workers_dev": {
                "source_capability_id": WORKERS_DEV_CAPABILITY_ID,
                "url": "https://cfctl-site.example.workers.dev"
            },
            "custom_domains": {
                "source_capability_id": CUSTOM_DOMAINS_CAPABILITY_ID,
                "filter": {"service": SERVICE_NAME},
                "items": []
            },
            "routes": []
        });
        let admit = admit_cfctl_site_route_surface(&forged)
            .expect_err("routes:[] without worker-routes-list-routes is not admitted")
            .to_string();
        assert!(admit.contains(ZONE_ROUTES_CAPABILITY_ID));
        assert_eq!(forged["routes"], json!([]));
    }

    #[test]
    fn serialize_emits_empty_routes_only_after_worker_routes_list_routes_ran() {
        let handoff = serialize_cfctl_site_route_surface(
            Some(&get_worker()),
            Some(&domains_list()),
            ZoneRoutesObservation::Performed {
                zone_ids: vec!["zone-a".to_owned()],
                reads: vec![ZoneRouteRead {
                    zone_id: "zone-a".to_owned(),
                    result: json!([
                        {"id":"route-other","pattern":"other.example/*","script":"other-worker"},
                    ]),
                }],
            },
        )
        .expect("zone-route read with no cfctl-site script is an honest empty set");
        assert_eq!(handoff["routes"], json!([]));
        assert_eq!(
            handoff["routes_source_capability_id"],
            ZONE_ROUTES_CAPABILITY_ID
        );
        assert_eq!(handoff["routes_zone_ids"], json!(["zone-a"]));
        admit_cfctl_site_route_surface(&handoff).expect("performed empty routes are admitted");
    }

    #[test]
    fn domains_list_service_filter_is_not_the_zone_route_surface() {
        let handoff = serialize_cfctl_site_route_surface(
            Some(&get_worker()),
            Some(&domains_list()),
            ZoneRoutesObservation::Performed {
                zone_ids: vec!["zone-a".to_owned()],
                reads: vec![ZoneRouteRead {
                    zone_id: "zone-a".to_owned(),
                    result: json!([
                        {"id":"route-site","pattern":"site.example/*","script":SERVICE_NAME},
                    ]),
                }],
            },
        )
        .expect("three spellings serialize independently");
        assert_eq!(
            handoff["workers_dev"]["source_capability_id"],
            WORKERS_DEV_CAPABILITY_ID
        );
        assert_eq!(
            handoff["custom_domains"]["source_capability_id"],
            CUSTOM_DOMAINS_CAPABILITY_ID
        );
        assert_eq!(
            handoff["custom_domains"]["items"].as_array().map(Vec::len),
            Some(1)
        );
        assert_eq!(
            handoff["custom_domains"]["items"][0]["hostname"],
            "docs.example"
        );
        assert_eq!(handoff["routes"].as_array().map(Vec::len), Some(1));
        assert_eq!(handoff["routes"][0]["pattern"], "site.example/*");
        assert_ne!(
            handoff["custom_domains"]["items"], handoff["routes"],
            "workers.domains.list must not stand in for worker-routes-list-routes"
        );
        assert_eq!(
            workers_dev_call_argv("account-a"),
            [
                "cfctl",
                "call",
                "getWorker",
                "--selector",
                "account_id=account-a",
                "--selector",
                "worker_id=cfctl-site",
                "--json"
            ]
        );
        assert_eq!(
            custom_domains_call_argv("account-a")[2],
            CUSTOM_DOMAINS_CAPABILITY_ID
        );
        assert_eq!(
            zone_routes_call_argv("zone-a"),
            [
                "cfctl",
                "call",
                "worker-routes-list-routes",
                "--selector",
                "zone_id=zone-a",
                "--json"
            ]
        );
        assert!(
            !custom_domains_call_argv("account-a")
                .iter()
                .any(|token| { token.contains("hostname=") || token.contains("cfctl.com") })
        );
    }

    #[test]
    fn inventoried_zone_without_worker_routes_list_routes_is_not_empty_routes() {
        let error = serialize_cfctl_site_route_surface(
            Some(&get_worker()),
            Some(&domains_list()),
            ZoneRoutesObservation::Performed {
                zone_ids: vec!["zone-a".to_owned(), "zone-b".to_owned()],
                reads: vec![ZoneRouteRead {
                    zone_id: "zone-a".to_owned(),
                    result: json!([]),
                }],
            },
        )
        .expect_err("skipping an inventoried zone must fail closed")
        .to_string();
        assert!(error.contains("zone-b"));
        assert!(error.contains(ZONE_ROUTES_CAPABILITY_ID));
        assert!(error.contains("refuse routes:[]"));
    }

    #[test]
    fn launch_checklist_names_the_three_route_spellings() {
        let checklist = include_str!("../../../../site/docs/LAUNCH_CHECKLIST.md");
        assert!(checklist.contains("getWorker"));
        assert!(checklist.contains("workers.domains.list"));
        assert!(checklist.contains("worker-routes-list-routes"));
        assert!(checklist.contains("Do not report `routes:[]` unless this read ran"));
        assert!(
            !checklist.contains("workers.domains.list filtered to hostname"),
            "do not add more domains.list filtering"
        );
    }
}
