//! Signed, exact removal of a declared dummy header before ordinary credential injection.
//! This never rewrites bodies, substrings, authentication selectors, or the original
//! client-proof request. The retained late injection path still binds the signed plan.
use crate::{
    credential_injection_target, discard_header_alias, is_serverware_internal_header,
    is_standard_hop_by_hop_header, Credential, CredentialInjectionTarget, Principal, Route,
    Snapshot,
};
use reqwest::header::HeaderMap;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use zeroize::Zeroize;

const INVALID: &str = "credential_existing_header_policy_invalid";

/// The target is exclusively credential-defined; the dummy belongs to one rule.
fn validate_contract(
    raw: &Value,
    injection: &Value,
    target: &CredentialInjectionTarget,
) -> Result<(), String> {
    let kind = injection.get("type").and_then(Value::as_str);
    if !matches!(kind, Some("bearer" | "header")) {
        return Err(INVALID.into());
    }
    let CredentialInjectionTarget::Header(name) = target else {
        return Err(INVALID.into());
    };
    let alias = discard_header_alias(name);
    if is_standard_hop_by_hop_header(&alias)
        || is_serverware_internal_header(&alias)
        || matches!(
            alias.as_str(),
            "cookie" | "host" | "content-type" | "content-length" | "content-encoding"
        )
        || (kind == Some("header") && alias == "authorization")
    {
        return Err(INVALID.into());
    }
    let object = raw.as_object().ok_or(INVALID)?;
    if object.len() != 2 || object.get("mode").and_then(Value::as_str) != Some("replaceExact") {
        return Err(INVALID.into());
    }
    let expected = object
        .get("expectedValue")
        .and_then(Value::as_str)
        .ok_or(INVALID)?;
    if expected.is_empty()
        || expected.len() > 1024
        || expected.starts_with(' ')
        || expected.ends_with(' ')
        || !expected.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
    {
        return Err(INVALID.into());
    }
    Ok(())
}

fn profile<'a>(
    raw: Option<&'a Value>,
    credential: Option<&Credential>,
) -> Result<Option<(String, &'a str)>, &'static str> {
    let Some(raw) = raw else { return Ok(None) };
    let credential = credential.ok_or(INVALID)?;
    let target = credential_injection_target(&credential.injection).map_err(|_| INVALID)?;
    validate_contract(raw, &credential.injection, &target).map_err(|_| INVALID)?;
    let CredentialInjectionTarget::Header(name) = target else {
        return Err(INVALID);
    };
    let expected = raw
        .get("expectedValue")
        .and_then(Value::as_str)
        .ok_or(INVALID)?;
    Ok(Some((name, expected)))
}

fn request_header_collision(request: &Map<String, Value>, target: &str) -> bool {
    request
        .get("allowedHeaders")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .any(|name| discard_header_alias(name) == target)
        || request
            .get("requiredHeaders")
            .and_then(Value::as_object)
            .into_iter()
            .flat_map(|headers| headers.keys())
            .any(|name| discard_header_alias(name) == target)
        || request
            .get("discardHeaders")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .any(|name| discard_header_alias(name) == target)
}

pub(super) fn validate_policy_route(
    raw: Option<&Value>,
    credential: Option<&Credential>,
    request: &Map<String, Value>,
    assigned: &[Value],
    required_headers: &HashMap<String, HashSet<String>>,
) -> Result<(), String> {
    let Some((target, _)) = profile(raw, credential)? else {
        return Ok(());
    };
    let target = discard_header_alias(&target);
    if request_header_collision(request, &target) {
        return Err(INVALID.into());
    }
    let collides = assigned.iter().filter_map(Value::as_str).any(|id| {
        if id == "*" {
            required_headers
                .values()
                .any(|names| names.contains(&target))
        } else {
            required_headers
                .get(id)
                .is_some_and(|names| names.contains(&target))
        }
    });
    if collides {
        return Err("credential_existing_header_identity_collision".into());
    }
    Ok(())
}

/// Mutates only an owned request-policy/forwarding copy, after principal selection.
/// Validation completes before removal; denial leaves the entire input unchanged.
pub(super) fn remove_for_route(
    snapshot: &Snapshot,
    route: &Route,
    principal: &Principal,
    headers: &mut BTreeMap<String, String>,
) -> Result<(), &'static str> {
    let credential = route
        .credential_ref
        .as_ref()
        .and_then(|reference| snapshot.credentials.get(reference));
    let Some((target, expected)) = profile(route.credential_header.as_ref(), credential)? else {
        return Ok(());
    };
    let request = route
        .adapter_config
        .get("request")
        .and_then(Value::as_object)
        .ok_or(INVALID)?;
    let target_alias = discard_header_alias(&target);
    if request_header_collision(request, &target_alias)
        || route
            .discard_headers
            .iter()
            .any(|name| discard_header_alias(name) == target_alias)
    {
        return Err(INVALID);
    }
    if principal
        .required_headers
        .keys()
        .any(|name| discard_header_alias(name) == target_alias)
    {
        return Err("credential_existing_header_identity_collision");
    }
    let mut candidates = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(&target));
    let Some((name, actual)) = candidates.next() else {
        return Err("credential_existing_header_missing");
    };
    if candidates.next().is_some() {
        return Err("credential_existing_header_ambiguous");
    }
    if actual != expected {
        return Err("credential_existing_header_mismatch");
    }
    let name = name.clone();
    if let Some((mut name, mut value)) = headers.remove_entry(&name) {
        name.zeroize();
        value.zeroize();
    }
    Ok(())
}

/// The original wire request is retained until client proof/observation capture.
/// Revalidate its placeholder against the active signed plan before provider filtering.
pub(super) fn remove_for_decision(
    snapshot: &Snapshot,
    decision: &Value,
    principal: &Principal,
    headers: &mut BTreeMap<String, String>,
) -> Result<(), &'static str> {
    let planned = decision.pointer("/injection/plan");
    let route = decision
        .get("route_id")
        .and_then(Value::as_str)
        .and_then(|id| snapshot.routes.iter().find(|route| route.id == id));
    if route.is_none_or(|route| route.credential_header.is_none()) {
        return Ok(());
    }
    let route = route.ok_or(INVALID)?;
    let credential = route
        .credential_ref
        .as_ref()
        .and_then(|reference| snapshot.credentials.get(reference))
        .ok_or(INVALID)?;
    if decision.get("allowed").and_then(Value::as_bool) != Some(true)
        || decision.get("policy_hash").and_then(Value::as_str) != Some(snapshot.hash.as_str())
        || decision.get("snapshot_epoch").and_then(Value::as_u64) != Some(snapshot.epoch)
        || decision.get("credential_ref").and_then(Value::as_str) != route.credential_ref.as_deref()
        || planned != Some(&credential.injection)
        || !route
            .principals
            .iter()
            .any(|id| id == "*" || id == &principal.id)
    {
        return Err(INVALID);
    }
    remove_for_route(snapshot, route, principal, headers)
}

pub(super) fn require_late_target_absent(
    headers: &HeaderMap,
    route: &Route,
    credential: &Credential,
) -> Result<(), String> {
    if let Some((target, _)) = profile(route.credential_header.as_ref(), Some(credential))? {
        if headers.contains_key(target.as_str()) {
            return Err("credential_injection_header_collision".into());
        }
    }
    Ok(())
}

pub(super) fn denial_status(code: &str) -> u16 {
    match code {
        "credential_existing_header_missing" | "credential_existing_header_mismatch" => 403,
        "credential_existing_header_ambiguous" => 400,
        _ => 500,
    }
}

#[cfg(test)]
#[path = "credential_header_replacement_tests.rs"]
mod tests;
