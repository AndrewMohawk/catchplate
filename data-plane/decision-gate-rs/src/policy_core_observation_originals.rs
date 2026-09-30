//! Original public comparison material, captured by the actual worker.
//! These documents are not readiness verdicts or effect capabilities. The
//! enclosing real custody append authenticates them; missing fields are never
//! reconstructed from an opaque digest or given a zero latency sample.
use super::*;
use std::time::Instant;

const MAX_ORIGINAL_BYTES: usize = 8 * 1024;
const MAX_ORIGINAL_NODES: usize = 512;
// Conservative modeled charge for bounded retained originals, a serializing
// event copy and temporary worker copies. This does not claim measured RSS.
pub(super) const RETENTION_BYTES: usize = 512 * 1024;

pub(super) fn elapsed(started: Instant) -> Option<u64> {
    Instant::now().checked_duration_since(started)?.as_nanos().try_into().ok()
        .filter(|nanos: &u64| *nanos <= i64::MAX as u64)
}

pub(super) fn bounded(value: Value) -> Result<Arc<Value>, String> {
    fn count(value: &Value, remaining: &mut usize, depth: usize) -> Result<(), String> {
        if depth > 32 || *remaining == 0 { return Err("native observation original exceeds node bound".into()); }
        *remaining -= 1;
        match value {
            Value::Array(items) => for item in items { count(item, remaining, depth + 1)?; },
            Value::Object(items) => for item in items.values() { count(item, remaining, depth + 1)?; },
            _ => {}
        }
        Ok(())
    }
    let mut remaining = MAX_ORIGINAL_NODES;
    count(&value, &mut remaining, 0)?;
    if canonical_json_bytes(&value).map_err(shadow_error)?.len() > MAX_ORIGINAL_BYTES {
        return Err("native observation original exceeds byte bound".into());
    }
    Ok(Arc::new(value))
}

fn evaluation(snapshot: &PolicyPlanSnapshot, value: &PolicyEvaluation, principal: Option<&str>)
    -> Result<Value, String>
{
    let plan = match &value.plan {
        SeparatedPolicyPlan::Active(plan) => {
            if plan.semantic_commitment().map_err(shadow_error)?.as_str() != value.semantic_sha256 {
                return Err("active observation plan changed".into());
            }
            serde_json::to_value(plan)
        }
        SeparatedPolicyPlan::Candidate(plan) => {
            if plan.semantic_commitment().map_err(shadow_error)?.as_str() != value.semantic_sha256 {
                return Err("candidate observation plan changed".into());
            }
            serde_json::to_value(plan)
        }
    }.map_err(|_| "observation plan serialization")?;
    if value.snapshot_hash != snapshot.snapshot.hash {
        return Err("observation evaluation belongs to another snapshot".into());
    }
    // Early deny/indeterminate paths currently may not retain a classified
    // route+operation. Preserve absence; this is not an evaluated authority
    // binding and cannot qualify for native readiness.
    if principal.is_some() && value.evaluated_principal_id.as_deref().is_some_and(|actual|Some(actual)!=principal) {
        return Err("observation authenticated principal differs from actual evaluator".into());
    }
    let authority = value.evaluated_principal_id.as_deref().and_then(|principal|
        snapshot.observed_authority_binding(value, principal).ok());
    Ok(json!({
        "snapshotSha256": value.snapshot_hash,
        "routeSha256": value.route_id.as_deref().map(|id| sha256_prefixed(id.as_bytes())),
        "operationSha256": value.operation.as_ref().map(digest_json_ensure_ascii),
        "policyPlanSha256": value.semantic_sha256,
        "disposition": value.disposition_label(),
        "policyPlan": plan,
        "authorityBinding": authority,
        "dispatchProjection": value.dispatch_projection,
        "responseConstraints": value.response_constraints,
    }))
}

pub(super) fn terminal(lifecycle: &ShadowRequestLifecycle, pending: &PendingActiveDecision,
    effect_results: &Value, terminal_evidence: &[ActiveEffectTerminalEvidence], status: u16)
    -> Result<Arc<Value>, String>
{
    bounded(json!({
        "pureActiveEvaluation": evaluation(&lifecycle.generation.active, &pending.active_evaluation,
            lifecycle.facts.authenticated_principal_id.as_deref())?,
        "finalActiveEnforcement": {
            "effectResults": effect_results,
            "terminalEvidence": terminal_evidence,
            "returnedHttpStatus": status,
            "finalizedAtUnixNanos": checked_epoch_ms_to_unix_nanos(checked_epoch_ms(now_epoch_ms())?)?,
            "dispatchAuthorized": pending.dispatch_authorized,
        },
    }))
}

fn samples(lifecycle: &ShadowRequestLifecycle, active_nanos: Option<u64>,
    candidate_nanos: Option<u64>, response_nanos: Option<u64>) -> Result<Value, String>
{
    serde_json::to_value(policy_shadow::LatencySamples::new(
        lifecycle.facts.capture_nanos, active_nanos,
        candidate_nanos, response_nanos, elapsed(lifecycle.facts.capture_started),
    ).map_err(shadow_error)?).map_err(|_| "observation latency serialization".into())
}

pub(super) fn request(lifecycle: &ShadowRequestLifecycle, active: &FinalActiveDecision,
    candidate: &PolicyEvaluation, candidate_nanos: Option<u64>)
    -> Result<Arc<Value>, String>
{
    let original = active.native_original.as_ref().ok_or("actual native terminal original missing")?;
    let mut value=json!({
        "apiVersion": "serverware.nativeRequestObservationOriginal/v2",
        "pureActiveEvaluation": original["pureActiveEvaluation"],
        "candidateEvaluation": evaluation(&lifecycle.generation.candidate, candidate,
            lifecycle.facts.authenticated_principal_id.as_deref())?,
        "finalActiveEnforcement": original["finalActiveEnforcement"],
        "factsCapturedAtUnixNanos": checked_epoch_ms_to_unix_nanos(lifecycle.facts.captured_at_epoch_ms)?,
        "latencySamples": samples(lifecycle, active.active_evaluation_nanos, candidate_nanos, None)?,
    });
    if let Some(opening)=lifecycle.native_observation.as_ref().filter(|value|value.requires_protected_request()) {
        let facts=super::native_request_facts::capture(lifecycle,candidate)?;
        // Reject a plainly oversized original before the one HMAC effect.
        bounded(value.clone())?;
        let protected=opening.protected_request(&facts,
            checked_epoch_ms_to_unix_nanos(lifecycle.facts.captured_at_epoch_ms)?)?
            .ok_or("native early sampling requires a genuine later facts commitment")?;
        value["apiVersion"]=json!("serverware.nativeRequestObservationOriginal/v3");
        value["protectedRequest"]=protected;
        value["latencySamples"]=samples(lifecycle,active.active_evaluation_nanos,candidate_nanos,None)?;
    }
    bounded(value)
}

pub(super) fn response(job: &ShadowResponseJob, candidate_validation: Value,
    active_nanos: Option<u64>, candidate_nanos: Option<u64>, response_nanos: Option<u64>)
    -> Result<Arc<Value>, String>
{
    let original = job.response_original.as_ref().ok_or("actual native response original missing")?;
    bounded(json!({
        "apiVersion": "serverware.nativeResponseObservationOriginal/v2",
        "response": {
            "responseFacts": original["responseFacts"],
            "boundActiveValidation": original["boundActiveValidation"],
            "activeValidation": original["activeValidation"],
            "candidateValidation": candidate_validation,
        },
        "latencySamples": samples(&job.lifecycle, active_nanos, candidate_nanos, response_nanos)?,
    }))
}
