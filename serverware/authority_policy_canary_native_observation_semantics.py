"""Pure native result derivation from admitted originals, never a trust oracle.

The protected detail owner verifies signatures, current/historical assignment,
publication, complete receipt order and the installed classifier before calling
evaluated. It binds RESULT_PROFILE and the returned result to those originals.
No Fleet envelope, native receipt, approval or missing semantic fact is made
here. Refusal is incomplete evidence, not an excluded/successful observation.
"""
import re

from serverware import authority_policy_canary as p
from serverware import authority_policy_canary_native_opening as f
from serverware import authority_policy_canary_native_observation_originals as originals
from serverware import authority_policy_canary_native_pilot as pilot
from serverware import authority_policy_canary_native_comparison as comparison

RESULT_PROFILE = "serverware.nativePolicyObservationResult/v1"


def _data(kind, value):
    return f.material("serverware.nativePolicyObservation" + kind + "/v1", value)


def _requirements(plan):
    required = {"trust-freshness", "final-request", "terminal-response"}
    for effect in plan["effectIntents"]:
        required.update(originals.INTENT_REQUIREMENTS[effect["kind"]])
    if plan["outcome"]["kind"] in {"permit", "conditional"}:
        required.update(("dispatch-authorization", "dispatch-terminal"))
    if plan["responseValidationCommitments"]:
        required.add("response-validation")
    return {"requirements": [value for value in originals.REQUIREMENTS if value in required]}


def _summary(value, sample, candidate):
    plan = value["policyPlan"]
    originals.integer(sample)
    p.require(value["dispatchProjection"] is not None, "actual pure dispatch/no-dispatch original is missing")
    result = {"outcome": value["disposition"], "policyPlanSha256": value["policyPlanSha256"],
        "reasonSetSha256": _data("Reasons", plan["outcome"]),
        "obligationsSha256": _data("Obligations", {name: plan[name] for name in
            ("requestRewriteCommitments", "responseValidationCommitments", "effectIntents")}),
        "effectIntentsSha256": (f.material("serverware.activeEffectIntents/v1", plan["effectIntents"])
            if not candidate else _data("CandidateEffectIntents", plan["effectIntents"])),
        "dispatchCommitmentSha256": originals.hashed(value["dispatchProjection"]), "evaluationNanos": sample}
    if candidate:
        result.update({name: plan[name] for name in ("evaluationPurpose", "effectCapabilitiesAvailable", "effectIntentsExecuted")})
    else:
        result.update(policyPlan=plan, effectRequirements=_requirements(plan))
    return result


def _media(value):
    """Same media-type projection as actual canonical_response_content_type."""
    if value is None:
        return None
    p.require(type(value) is str and value.isascii() and len(value) <= 1024,
        "actual candidate released media type is unavailable")
    media = value.split(";", 1)[0].strip().translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"))
    return media if re.fullmatch(r"[a-z0-9!#$&^_.+\-]+/[a-z0-9!#$&^_.+\-]+", media) else "application/octet-stream"


def _bound(evaluation, constraints, commitment, outcome, validation):
    return {"policySnapshotSha256": evaluation["snapshotSha256"], "responseConstraintsRootSha256": originals.hashed(constraints),
        "exactResponseCommitmentSha256": commitment, "outcome": outcome, "validationResultSha256": originals.hashed(validation)}


def _response(request, response, terminal_receipt, active, candidate):
    final = request["finalActiveEnforcement"]
    terminal = originals.decoded(terminal_receipt)
    fixed = comparison.fixed_class(terminal["activeDisposition"], final["dispatchAuthorized"], candidate["outcome"],
        active["dispatchCommitmentSha256"], candidate["dispatchCommitmentSha256"])
    if response is None:
        p.require(not final["dispatchAuthorized"] and fixed in {"not-applicable-both-deny", "not-applicable-active-not-dispatched"},
            "dispatched request lacks its genuine response observation")
        marker = _data("NoResponse", {"terminalReceiptSha256": terminal_receipt["signed_receipt_sha256"],
            "requestOriginalSha256": originals.hashed(request), "classification": fixed})
        return {**{name: None for name in comparison.EXACT}, "classification": fixed, "captureMode": "not-dispatched",
            "unavailableMarkerSha256": marker, "responseProofSha256": _data("NoResponseProof", marker)}
    p.require(response["apiVersion"] == originals.RESPONSE_V2,
        "full native comparison requires the actual released entity/media successor")
    value = response["response"]
    facts, released, validated = value["responseFacts"], value["activeValidation"], value["candidateValidation"]
    commitment = f.material("serverware.policyShadowExactResponse/v1", [facts["status"], facts["bodyLength"],
        facts["bodySha256"], facts["physicalHeaderCount"], facts["physicalHeadersSha256"]])
    active_bound = _bound(request["pureActiveEvaluation"], request["pureActiveEvaluation"]["responseConstraints"],
        commitment, "accepted", released)
    candidate_bound = _bound(request["candidateEvaluation"], request["candidateEvaluation"]["responseConstraints"],
        commitment, validated["outcome"], validated)
    if fixed is not None:
        kind = fixed
    elif released["releasedContentTypeState"] == "unavailable":
        kind = "not-comparable-candidate-validator-unavailable"
    elif validated["outcome"] == "rejected":
        kind = "comparable-validation-divergence"
    else:
        same = (released["releasedEntitySha256"] == validated["candidateReleasedBodySha256"]
            and released["releasedEntityBytes"] == validated["candidateReleasedBodyBytes"]
            and released["releasedStatus"] == validated["status"]
            and released["releasedContentType"] == _media(validated["candidateReleasedContentType"]))
        kind = ("comparable-identical" if active_bound["validationResultSha256"] == candidate_bound["validationResultSha256"]
            else "comparable-validation-match") if same else "comparable-validation-divergence"
    return {"classification": kind, "captureMode": "bounded-exact", "upstreamStatus": facts["status"],
        "exactResponseBodyBytes": facts["bodyLength"], "exactResponseBodySha256": facts["bodySha256"],
        "physicalResponseHeaderCount": facts["physicalHeaderCount"], "physicalResponseHeadersSha256": facts["physicalHeadersSha256"],
        "exactResponseCommitmentSha256": commitment, "activeValidation": active_bound, "candidateValidation": candidate_bound,
        "unavailableMarkerSha256": None, "transportCaptureReceiptSha256": facts["transportCaptureReceiptSha256"],
        "runtimeAttestationSha256": facts["runtimeAttestationSha256"], "peerIdentitySha256": facts["peerIdentitySha256"],
        "physicalResponseFraming": facts["framing"], "responseProofSha256": f.material("serverware.policyShadowAuthenticatedResponseProof/v1",
            [commitment, facts["transportCaptureReceiptSha256"], facts["runtimeAttestationSha256"], facts["peerIdentitySha256"], facts["framing"]])}


def _obligation(assignment, binding, active, candidate, response):
    assigned = [item for item in assignment["responseValidationObligations"] if item["routeSha256"] == binding["routeSha256"]]
    p.require(len(assigned) <= 1)
    if not assigned:
        return None
    scope = {name: assigned[0][name] for name in ("routeSha256", "obligationRootSha256")}
    if response["captureMode"] == "not-dispatched":
        return {"disposition": "not-applicable-active-not-dispatched", **scope,
            "activeOutcome": active["outcome"], "candidateOutcome": candidate["outcome"],
            "notApplicableSha256": f.material("serverware.policyShadowResponseObligationNotApplicable/v1",
                [scope["routeSha256"], scope["obligationRootSha256"], active["outcome"], candidate["outcome"]])}
    value = {"disposition": "applied", **scope,
        "activeConstraintsRootSha256": response["activeValidation"]["responseConstraintsRootSha256"],
        "candidateConstraintsRootSha256": response["candidateValidation"]["responseConstraintsRootSha256"],
        "exactResponseCommitmentSha256": response["exactResponseCommitmentSha256"]}
    value["appliedObligationsRootSha256"] = f.framed("serverware.policyShadowAppliedResponseObligations/v1",
        *(value[name].encode("ascii") for name in ("obligationRootSha256", "activeConstraintsRootSha256",
            "candidateConstraintsRootSha256", "exactResponseCommitmentSha256")))
    return value


def evaluated(request_original, response_original_or_none, *, terminal_receipt, request_receipt,
        response_receipt, assignment, compiler_payload, publication):
    """Derive the closed full result only from already admitted current scope.

    Receipt parameters are the exact originals returned by the fixed receiver,
    not caller-created verification booleans. This pure API performs no intake,
    admission, signing, effects, clock reads or authority expansion itself.
    """
    from serverware import db
    request, response = request_original, response_original_or_none
    p.require(request["apiVersion"] in {originals.REQUEST_V2, originals.REQUEST_V3},
        "old original profile does not contain full native semantic inputs")
    event = originals.decoded(request_receipt)
    terminal = originals.decoded(terminal_receipt)
    p.require(event["observationOriginal"] == request and event["event"] == "candidate-evaluated"
        and terminal["event"] in {"active-pre-dispatch-terminal", "response-terminal-appended"})
    if response is None:
        p.require(response_receipt is None)
    else:
        p.require(response_receipt is not None and originals.decoded(response_receipt)["observationOriginal"] == response)
    for receipt in (request_receipt,) + (() if response_receipt is None else (response_receipt,)):
        p.require(all(receipt[name] == terminal_receipt[name] for name in
            ("generation_id", "ingress_sequence", "request_binding_sha256", "request_commitment_sha256")))
    p.require(compiler_payload["assignmentSha256"] == publication["assignment_envelope_digest"]
        and compiler_payload["assignmentPayloadSha256"] == publication["assignment_payload_digest"]
        and compiler_payload["assignmentRevision"] == assignment["assignmentRevision"]
        and compiler_payload["canaryId"] == assignment["canaryId"]
        and compiler_payload["policyIdentity"] == assignment["policyIdentity"]
        and compiler_payload["expectedLoadedSnapshots"] == assignment["expectedLoadedSnapshots"])
    pure, candidate_original = request["pureActiveEvaluation"], request["candidateEvaluation"]
    binding = candidate_original["authorityBinding"]
    p.require(binding is not None and pure["authorityBinding"] is not None,
        "full native evaluation needs actual installed classifier bindings in both lanes")
    p.require(binding["principalSha256"] == pure["authorityBinding"]["principalSha256"],
        "actual lane evaluations belong to different authenticated principals")
    for lane, value in (("active", pure), ("candidate", candidate_original)):
        p.require(value["snapshotSha256"] == publication[lane + "_policy_hash"]
            == assignment["expectedLoadedSnapshots"][lane]["compiledSnapshotSha256"]
            and value["responseConstraints"] is not None)
        # The fixed receiver has already recomputed these exact route originals
        # under its authenticated state/work budget; do not repeat acquisition
        # or turn this pure derivation into another independent trust pass.
    samples = dict(request["latencySamples"])
    if response is not None:
        # Request evaluator samples remain from that actual request evaluation;
        # the separate response worker contributes only its actual elapsed
        # response validation and end-to-end duration, never a guessed zero.
        later = response["latencySamples"]
        p.require(later["factsCaptureNanos"] == samples["factsCaptureNanos"]
            and later["activeEvaluationNanos"] == samples["activeEvaluationNanos"]
            and later["responseValidationNanos"] is not None and later["shadowTotalNanos"] is not None
            and samples["shadowTotalNanos"] is not None and later["shadowTotalNanos"] >= samples["shadowTotalNanos"])
        samples["responseValidationNanos"], samples["shadowTotalNanos"] = later["responseValidationNanos"], later["shadowTotalNanos"]
    originals.latency(samples)
    p.require(all(samples[name] is not None for name in ("factsCaptureNanos", "activeEvaluationNanos", "candidateEvaluationNanos", "shadowTotalNanos"))
        and all(value is None or value <= samples["shadowTotalNanos"] for value in samples.values()))
    active = _summary(pure, samples["activeEvaluationNanos"], False)
    candidate = _summary(candidate_original, samples["candidateEvaluationNanos"], True)
    final = request["finalActiveEnforcement"]
    p.require(terminal["activeDisposition"] in {"allow", "deny", "conditional", "error"}
        and final["dispatchAuthorized"] == (terminal["event"] == "response-terminal-appended"))
    if terminal["activeDisposition"] == "allow":
        p.require(final["dispatchAuthorized"] and all(value["terminalState"] == "completed" for value in final["terminalEvidence"]))
    else:
        p.require(not final["dispatchAuthorized"], "non-allow final disposition cannot claim dispatch permission")
    resolved = {"finalizationBindingSha256": _data("FinalizationBinding", {
            "terminalReceiptSha256": terminal_receipt["signed_receipt_sha256"], "requestReceiptSha256": request_receipt["signed_receipt_sha256"],
            "finalOriginal": final}), "resolvedEffectIntentsSha256": active["effectIntentsSha256"],
        "effectRequirements": active["effectRequirements"], "terminalEvidence": final["terminalEvidence"],
        "effectResultCommitmentsRootSha256": db._policy_shadow_merkle_root([(n, originals.hashed(value)) for n, value in enumerate(final["terminalEvidence"], 1)]),
        "finalOutcome": terminal["activeDisposition"], "returnedHttpStatus": final["returnedHttpStatus"],
        "upstreamDispatchAuthorized": final["dispatchAuthorized"], "finalizedAtUnixNanos": final["finalizedAtUnixNanos"]}
    analysis = compiler_payload["authorityAnalysis"]
    cells = db._policy_authority_semantic_expansion_cells("approved native expansion", analysis["expansionCells"], maximum=128, allow_empty=True)
    selected = [value for value in cells if all(value[name] == binding[name] for name in
        ("routeSha256", "operation", "compiledSemanticProfileSha256", "requestAuthorityClass"))
        and value["activeOutcome"] == active["outcome"] and value["candidateOutcome"] == candidate["outcome"]]
    if analysis["mode"] == "no-expansion":
        p.require(not cells and compiler_payload["pilotRestrictions"] == {"mode": "not-applicable"}
            and (active["outcome"], candidate["outcome"]) not in db._POLICY_AUTHORITY_EXPANDING_TRANSITIONS)
    else:
        p.require(analysis["mode"] == "approved-expansion")
        pilot.validate(compiler_payload["pilotRestrictions"])
        p.require(compiler_payload["pilotRestrictions"]["cells"] == cells
            and ((active["outcome"], candidate["outcome"]) not in db._POLICY_AUTHORITY_EXPANDING_TRANSITIONS or selected))
    compared = _response(request, response, terminal_receipt, active, candidate)
    obligation = _obligation(assignment, binding, active, candidate, compared)
    comparison.validate("derived native response", compared, obligation=obligation,
        active_snapshot_digest=pure["snapshotSha256"], candidate_snapshot_digest=candidate_original["snapshotSha256"],
        final_active_outcome=resolved["finalOutcome"], upstream_dispatch_authorized=int(resolved["upstreamDispatchAuthorized"]),
        active_dispatch_commitment_digest=active["dispatchCommitmentSha256"], candidate_dispatch_commitment_digest=candidate["dispatchCommitmentSha256"],
        candidate_outcome=candidate["outcome"])
    return {"status": "evaluated", "pureActiveEvaluation": active, "finalActiveEnforcement": resolved,
        "candidateEvaluation": candidate, "authorityBinding": binding,
        "derivedExpansion": {"cells": selected, "cellsRootSha256": db._policy_shadow_merkle_root([(n, value["cellSha256"]) for n, value in enumerate(selected, 1)])},
        "pilotMembership": pilot.membership(compiler_payload["pilotRestrictions"], binding, selected),
        "responseObligation": obligation, "responseComparison": compared, "latencySamples": samples}
