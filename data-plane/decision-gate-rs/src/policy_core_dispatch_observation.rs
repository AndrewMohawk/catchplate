//! Credential-free, effect-free originals from the actual pure evaluator.
//! These describe planned request semantics, never execution authorization.
use super::*;

pub(super) fn no_dispatch(outcome: &PolicyOutcome) -> Value {
    json!({"domain":"catchplate.policyShadowNoDispatch/v1","outcome":outcome})
}

pub(super) fn response_constraints(route: &Route) -> Result<Value, String> {
    let constraints = route.constraints.iter().filter(|value|constraint_phase_includes(value,"response"))
        .map(|value|policy_route_authority::canonical(value).map(|bytes|sha256_prefixed(bytes.as_bytes())))
        .collect::<Result<std::collections::BTreeSet<_>,_>>()?;
    Ok(json!({
        "domain":"catchplate.policyShadowNativeResponseConstraints/v1",
        "routeSha256":sha256_prefixed(route.id.as_bytes()),
        "adapterTypeSha256":sha256_prefixed(route.adapter_type.as_bytes()),
        "adapterConfigSha256":sha256_prefixed(policy_route_authority::canonical(&route.adapter_config)?.as_bytes()),
        "constraintSha256s":constraints,
    }))
}

pub(super) fn dispatch(request: &DecisionRequest, forwarded: &BTreeMap<String,String>,
    url: &Url, principal: &Principal, route: &Route, operation: &Value, injection: &Value)
    -> Result<Value,String>
{
    // The caller has admitted the actual body and converged the adapter rewrite.
    // Hash public request components separately; do not retain raw credentials,
    // request headers/query/body, policy hash, lane or a resolved secret version.
    let body_length = request.forwarded_body_length
        .unwrap_or(u64::try_from(request.body.len()).map_err(|_|"dispatch body length overflow")?);
    Ok(json!({
        "domain":"catchplate.policyShadowCredentialFreeDispatch/v1",
        "principalSha256":sha256_prefixed(principal.id.as_bytes()),
        "routeSha256":sha256_prefixed(route.id.as_bytes()),
        "request":{
            "method":request.method,"scheme":url.scheme(),
            "authoritySha256":sha256_prefixed(canonical_authority(url).as_bytes()),
            "pathSha256":sha256_prefixed(url.path().as_bytes()),
            "querySha256":digest_json_ensure_ascii(&json!(query_pairs(url))),
            "headersSha256":digest_json_ensure_ascii(&json!(forwarded)),
            "bodySha256":body_sha(request),"bodyLength":body_length,
        },
        "operationSha256":digest_json_ensure_ascii(operation),
        "credentialSlotSha256":route.credential_ref.as_deref().map(|value|sha256_prefixed(value.as_bytes())),
        "injectionPolicySha256":sha256_prefixed(policy_route_authority::canonical(injection)?.as_bytes()),
    }))
}

/// Preserve the actually classified route/operation when a later pure
/// constraint denies it. A denial has no outgoing dispatch projection.
pub(super) fn matched_denial(mut evaluation: PolicyEvaluation, principal: &Principal,
    route: &Route, operation: &Value) -> Result<PolicyEvaluation,String>
{
    if !matches!(&evaluation.disposition, PureDisposition::Deny{..} | PureDisposition::Indeterminate{..}) {
        return Err("matched denial received a dispatching plan".into());
    }
    evaluation.route_id = Some(route.id.clone());
    evaluation.evaluated_principal_id = Some(principal.id.clone());
    evaluation.operation = Some(operation.clone());
    evaluation.response_constraints = Some(response_constraints(route)?);
    Ok(evaluation)
}
