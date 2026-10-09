//! Route-selected alternate query grammars. Legacy and Gmail behavior delegates
//! unchanged; GitHub has its own unique-name semantics and signed mode marker.
use crate::{DecisionRequest, RequestPathValidation, Route, Snapshot};
use reqwest::Url;
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub(crate) fn ordered_query(route: &Route) -> bool {
    crate::github_issues::selected(route) || crate::gmail_read::ordered_query(route)
}
pub(crate) fn mode(route: &Route) -> &'static str {
    if crate::github_issues::selected(route) {
        crate::github_issues::MODE
    } else {
        crate::request_query_compat::MODE
    }
}
pub(crate) fn allows_ordered_intake(snapshot: &Snapshot, principal: Option<&str>) -> bool {
    crate::gmail_read::allows_ordered_intake(snapshot, principal)
        || snapshot.routes.iter().any(|route| {
            crate::github_issues::selected(route)
                && crate::github_issues::validate_route(route).is_ok()
                && principal.is_none_or(|id| {
                    route
                        .principals
                        .iter()
                        .any(|allowed| allowed == "*" || allowed == id)
                })
        })
}
pub(crate) fn parse_ordered_target(
    method: &str,
    target: &str,
) -> Result<(RequestPathValidation, Url), String> {
    crate::gmail_read::parse_ordered_target(method, target)
        .or_else(|_| crate::github_issues::parse_target(method, target))
}
pub(crate) fn parse_target_for_route(
    snapshot: &Snapshot,
    method: &str,
    target: &str,
    client_ip: Option<&str>,
    headers: &BTreeMap<String, String>,
    authenticated_principal: Option<&str>,
) -> Result<(RequestPathValidation, Url), String> {
    if let Ok(parsed) = crate::parse_validated_absolute_target(target) {
        return Ok(parsed);
    }
    if let Ok(parsed) = crate::github_issues::parse_target(method, target) {
        let lowered = crate::lower_headers(headers);
        let principal = match authenticated_principal {
            Some(id) => snapshot
                .principals
                .iter()
                .find(|principal| principal.id == id),
            None => snapshot.identify_principal(client_ip, &lowered),
        }
        .ok_or("GitHub query principal unavailable")?;
        let matched = snapshot
            .match_route(&principal.id, method, &parsed.1)
            .ok_or("GitHub query route unavailable")?;
        crate::github_issues::admit_target(matched.route, method, &parsed.1)?;
        return Ok(parsed);
    }
    crate::gmail_read::parse_target_for_route(
        snapshot,
        method,
        target,
        client_ip,
        headers,
        authenticated_principal,
    )
}
pub(crate) fn apply_route_rewrite(
    route: &Route,
    url: &mut Url,
    rewrite: &Value,
) -> Result<(), String> {
    if !crate::github_issues::selected(route) {
        return crate::gmail_read::apply_route_rewrite(route, url, rewrite);
    }
    crate::github_issues::validate_route(route)?;
    if rewrite != &json!({}) {
        return Err("GitHub query rewrite refused".into());
    }
    let (_, parsed) = crate::github_issues::parse_target("GET", url.as_str())?;
    if parsed != *url {
        return Err("GitHub query changed before dispatch".into());
    }
    Ok(())
}
pub(crate) fn canonical_discard_headers(
    canonical: &Value,
    route: &Route,
) -> Result<Vec<String>, String> {
    if crate::github_issues::selected(route) {
        crate::github_issues::canonical_discard_headers(canonical, route)
    } else {
        crate::gmail_read::canonical_discard_headers(canonical, route)
    }
}
pub(crate) fn validate_canonical_url(
    canonical: &Value,
    route: &Route,
    method: &str,
    url: &Url,
) -> Result<(), String> {
    if crate::github_issues::selected(route) {
        crate::github_issues::validate_canonical_url(canonical, route, method, url)
    } else {
        crate::gmail_read::validate_canonical_url(canonical, route, method, url)
    }
}
pub(crate) fn provider_url_for_decision(
    snapshot: &Snapshot,
    decision: &Value,
    method: &str,
    original: &Url,
) -> Result<Url, String> {
    let principal = decision
        .get("principal_id")
        .and_then(Value::as_str)
        .ok_or("provider principal missing")?;
    let matched = snapshot
        .match_route(principal, method, original)
        .ok_or("provider route unavailable")?;
    if !crate::github_issues::selected(matched.route) {
        return crate::gmail_read::provider_url_for_decision(snapshot, decision, method, original);
    }
    if decision.get("route_id").and_then(Value::as_str) != Some(matched.route.id.as_str())
        || decision.get("rewrite") != Some(&json!({}))
    {
        return Err("GitHub provider route or rewrite differs".into());
    }
    validate_canonical_url(
        decision
            .get("canonical_request")
            .ok_or("GitHub canonical request missing")?,
        matched.route,
        method,
        original,
    )?;
    Ok(original.clone())
}
pub(crate) fn validate_built_request(
    canonical: &Value,
    route: &Route,
    original: &Url,
    built: &reqwest::blocking::Request,
) -> Result<(), &'static str> {
    if !crate::github_issues::selected(route) {
        return crate::gmail_read::validate_built_request(canonical, route, original, built);
    }
    if built.url().as_str() != original.as_str() || built.headers().contains_key("accept-encoding")
    {
        return Err("github_provider_request_changed_at_dispatch");
    }
    validate_canonical_url(canonical, route, built.method().as_str(), built.url())
        .map_err(|_| "github_provider_request_binding_invalid")
}

/// GitHub-specific checks run alongside, not instead of, generic header/media,
/// strict buffered JSON and exact body commitment validation.
pub(crate) fn validate_github_request(
    req: &DecisionRequest,
    headers: &BTreeMap<String, String>,
    url: &Url,
    route: &Route,
) -> Result<(), Value> {
    if crate::github_issues::selected(route) {
        crate::github_issues::validate_request(req, headers, url, route)
    } else {
        Ok(())
    }
}
