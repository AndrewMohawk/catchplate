"""Exact active evaluation and final enforcement evidence over retained ingress."""
from catchplate import authority_policy_canary as profile
from catchplate import authority_transition_policy_canary_custody as custody
from catchplate.authority_transition_policy_canary_membership import record, integers
from catchplate.authority_transition_policy_canary_state import exact, apply_verification


def active(state, value):
    from catchplate import db
    item = record(value, db._POLICY_CANARY_ACTIVE_DECISION_FIELDS)
    profile.text(item.pop("actor_id"), 1024)
    integers(item, ("assignment_revision", "membership_revision", "member_ordinal", "ingress_sequence"),
        ("captured_at_epoch_ns", "decision_at_epoch_ns"))
    if item["returned_http_status"] is not None:
        db._candidate_authority_int("returned HTTP status", item["returned_http_status"], minimum=100, maximum=599)
    db._candidate_authority_int("dispatch authorization", item["upstream_dispatch_authorized"], maximum=1)
    profile.require(item["decision_status"] in {"evaluated", "unavailable"} and item["active_outcome"] in db._POLICY_AUTHORITY_OUTCOMES
        and item["final_active_outcome"] in {"allow", "deny", "conditional", "error"})
    if item["decision_status"] == "evaluated":
        profile.require(all(item[name] is not None for name in ("active_evaluation_digest", "returned_http_status", "active_dispatch_commitment_digest"))
            and item["active_unavailable_reason"] is None and item["active_unavailable_marker_digest"] is None)
    else:
        profile.require(item["active_outcome"] == "indeterminate" and item["active_evaluation_digest"] is None
            and item["active_unavailable_reason"] in db._POLICY_AUTHORITY_ERROR_REASONS and item["active_unavailable_marker_digest"] is not None
            and item["final_active_outcome"] == "error" and item["returned_http_status"] is None
            and item["upstream_dispatch_authorized"] == 0 and item["active_dispatch_commitment_digest"] is None)
    profile.require(item["final_active_outcome"] == "allow" or item["upstream_dispatch_authorized"] == 0)
    payload = custody.wire(item, "active_decision")
    result = payload["result"]
    profile.require(type(result) is dict and payload["generationId"] == item["generation_id_digest"]
        and payload["capturedAtUnixNanos"] == item["captured_at_epoch_ns"] and payload["decisionAtUnixNanos"] == item["decision_at_epoch_ns"])
    if result.get("status") == "finalized":
        profile.require(set(result) == {"status", "pureActiveEvaluation", "effectResolution"} and item["decision_status"] == "evaluated")
        evaluation = db._candidate_authority_strict_object("pure active evaluation", result["pureActiveEvaluation"], frozenset({
            "outcome", "policyPlan", "policyPlanSha256", "reasonSetSha256", "obligationsSha256", "effectIntentsSha256",
            "dispatchCommitmentSha256", "effectRequirements", "evaluationNanos"}))
        effect = db._candidate_authority_strict_object("active effect resolution", result["effectResolution"], frozenset({
            "finalizationBindingSha256", "resolvedEffectIntentsSha256", "effectRequirements", "terminalEvidence", "effectResultCommitmentsRootSha256",
            "finalOutcome", "returnedHttpStatus", "upstreamDispatchAuthorized", "finalizedAtUnixNanos"}))
        profile.require(evaluation["outcome"] == item["active_outcome"] and profile.sha256(profile.canonical(evaluation)) == item["active_evaluation_digest"]
            and evaluation["dispatchCommitmentSha256"] == item["active_dispatch_commitment_digest"]
            and effect["finalOutcome"] == item["final_active_outcome"] and effect["returnedHttpStatus"] == item["returned_http_status"]
            and type(effect["upstreamDispatchAuthorized"]) is bool and int(effect["upstreamDispatchAuthorized"]) == item["upstream_dispatch_authorized"]
            and effect["finalizedAtUnixNanos"] == item["decision_at_epoch_ns"])
    else:
        profile.require(set(result) == {"status", "reason", "unavailableMarkerSha256"} and result["status"] == "unavailable"
            and item["decision_status"] == "unavailable" and result["reason"] == item["active_unavailable_reason"]
            and result["unavailableMarkerSha256"] == item["active_unavailable_marker_digest"])
    exact(item, state.runtime_context(item), custody.RUNTIME)
    custody.observing(state, item)
    ingress = state.one("policy_canary_ingress_observations", **custody.identity(item, custody.INSTANCE + ("ingress_sequence",)))
    exact(item, ingress, ("ingress_envelope_digest", "ingress_payload_digest", "custody_evidence_envelope_digest", "custody_verification_receipt_digest"))
    profile.require((ingress["accounting_outcome"] == "evaluated") == (item["decision_status"] == "evaluated"))
    if item["custody_evidence_envelope_digest"] is not None:
        held = state.one("policy_canary_custody_evidence", custody_evidence_envelope_digest=item["custody_evidence_envelope_digest"],
            verification_receipt_digest=item["custody_verification_receipt_digest"])
        custody.reverify(state, held, current=False)
    else:
        profile.require(item["custody_verification_receipt_digest"] is None)
    apply_verification(item, state.runtime("active_decision", item, "active_decision",
        db._candidate_authority_signed_record(item, current_prefix="active_decision")), interval=True)
    state.put("policy_canary_active_decisions", item)
    return item
