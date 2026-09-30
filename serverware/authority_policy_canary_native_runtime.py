"""Actual terminal/evaluator custody originals. No legacy signer alias or readiness projection."""
from serverware import authority_policy_canary as profile
from serverware import authority_policy_canary_native_opening as opening

SCHEMA = "serverware.nativeCustodyRuntimeObservation/v1"
RESPONSE_SCHEMA = "serverware.nativeCustodyResponseObservation/v1"
FIELDS = opening.FIELDS - {"opening_receipt"} | {"receipt", "opening_receipt_sha256", "terminal_receipt_sha256"}
RESPONSE_FIELDS = FIELDS | {"request_observation_receipt_sha256"}
EVENT_FIELDS = frozenset({"domain", "ingressSequence", "requestBindingSha256", "requestCommitmentSha256", "event", "phase",
    "terminalDetailSha256", "activePlanSha256", "finalActiveDecisionSha256", "activeEffectResultsSha256", "candidatePlanSha256",
    "activeDisposition", "candidateDisposition", "responseFactsSha256", "activeResponseValidationSha256",
    "candidateResponseValidationSha256", "decisionAtUnixNanos", "dispatchFinalRequestSha256", "dispatchEffectAuthoritySha256"})


def verify(value, *, kind, assignment, context, publication, opening_record, terminal_record, now, request_record=None):
    response = type(value) is dict and value.get("apiVersion") == RESPONSE_SCHEMA
    profile.require(type(value) is dict and set(value) == (RESPONSE_FIELDS if response else FIELDS)
        and value["apiVersion"] == (RESPONSE_SCHEMA if response else SCHEMA)
        and len(profile.canonical(value)) <= opening.MAX_RECORD)
    profile.digest(value["opening_receipt_sha256"])
    receipt = value["receipt"]
    profile.require(type(receipt) is dict and set(receipt) == opening.RECEIPT_FIELDS and receipt["disposition"] == "appended")
    for name in opening.RECEIPT_FIELDS - {"ingress_sequence", "event_ordinal", "predecessor_event_ordinal", "event_phase", "disposition",
            "canonical_event_bytes", "trusted_observed_at_unix_nanos", "signature"}:
        profile.digest(receipt[name])
    for name in ("ingress_sequence", "event_ordinal", "predecessor_event_ordinal", "trusted_observed_at_unix_nanos"):
        profile.epoch(receipt[name])
    profile.require(receipt["ingress_sequence"] > 0 and receipt["event_ordinal"] == receipt["predecessor_event_ordinal"] + 1)
    raw = receipt["canonical_event_bytes"]
    profile.require(type(raw) is list and 0 < len(raw) <= 16 * 1024 and all(type(v) is int and 0 <= v <= 255 for v in raw))
    raw = bytes(raw)
    event = profile.document(raw, 16 * 1024)
    profile.require(profile.canonical(event) == raw and profile.sha256(raw) == receipt["event_sha256"]
        and type(event) is dict and set(event) == EVENT_FIELDS and event["domain"] == "serverware.policyShadowRuntimeAccountingEvent/v1")
    association = {"ingressSequence": receipt["ingress_sequence"], "requestBindingSha256": receipt["request_binding_sha256"],
        "requestCommitmentSha256": receipt["request_commitment_sha256"], "phase": receipt["event_phase"]}
    profile.require(profile.canonical({key: event[key] for key in association}) == profile.canonical(association))
    for name in EVENT_FIELDS - {"domain", "ingressSequence", "event", "phase", "activeDisposition", "candidateDisposition", "decisionAtUnixNanos"}:
        if event[name] is not None:
            profile.digest(event[name])
    for name in ("finalActiveDecisionSha256", "activeEffectResultsSha256"):
        profile.digest(event[name])
    if response:
        profile.require(event["activePlanSha256"] is None, "response original must not synthesize a missing active-plan field")
    else:
        profile.digest(event["activePlanSha256"])
    profile.require(event["activeDisposition"] in {"allow", "deny", "conditional", "error"}
        and all(event[name] is None for name in ("terminalDetailSha256", "decisionAtUnixNanos", "dispatchFinalRequestSha256", "dispatchEffectAuthoritySha256")))
    previous = opening_record["opening_receipt"]
    profile.require(value["opening_receipt_sha256"] == previous["signed_receipt_sha256"])
    for name in ("generation_id", "ingress_sequence", "request_binding_sha256", "request_commitment_sha256"):
        profile.require(receipt[name] == previous[name])
    # Associations are immutable protected originals, not a caller's receipt
    # hash assertion. Other concurrent ingress can occupy intervening ordinals;
    # this does not claim a complete global spool range.
    if kind == "active-decision":
        profile.require(not response and request_record is None and terminal_record is None and value["terminal_receipt_sha256"] is None
            and (receipt["event_phase"], event["event"]) in {
                ("pre-dispatch-terminal", "active-pre-dispatch-terminal"), ("post-dispatch-terminal", "response-terminal-appended")}
            and all(event[name] is None for name in ("candidatePlanSha256", "candidateDisposition", "candidateResponseValidationSha256")))
        role, coverage = "terminal-append", "terminal-active-commitments"
    elif response:
        profile.require(kind == "shadow-observation" and terminal_record is not None and request_record is not None
            and receipt["event_phase"] == "response" and event["event"] == "response-evaluated")
        terminal = terminal_record["receipt"]
        previous = request_record["receipt"]
        profile.require(terminal["event_phase"] == "post-dispatch-terminal"
            and value["terminal_receipt_sha256"] == terminal["signed_receipt_sha256"]
            and value["request_observation_receipt_sha256"] == previous["signed_receipt_sha256"])
        terminal_event = profile.document(bytes(terminal["canonical_event_bytes"]), 16 * 1024)
        request_event = profile.document(bytes(previous["canonical_event_bytes"]), 16 * 1024)
        for name in ("finalActiveDecisionSha256", "activeEffectResultsSha256", "activeDisposition",
                "responseFactsSha256", "activeResponseValidationSha256"):
            profile.require(event[name] == terminal_event[name], "response comparison differs from actual terminal capture")
        for name in ("candidatePlanSha256", "candidateDisposition"):
            profile.require(event[name] == request_event[name], "response comparison differs from actual request evaluation")
        for name in ("candidatePlanSha256", "responseFactsSha256", "activeResponseValidationSha256", "candidateResponseValidationSha256"):
            profile.digest(event[name])
        role, coverage = "ledger-append", "candidate-response-observation"
    else:
        profile.require(kind == "shadow-observation" and request_record is None and terminal_record is not None
            and receipt["event_phase"] == "candidate" and event["event"] == "candidate-evaluated"
            and event["candidateDisposition"] in {"permit", "deny", "conditional", "indeterminate"}
            and all(event[name] is None for name in ("responseFactsSha256", "activeResponseValidationSha256", "candidateResponseValidationSha256")))
        profile.digest(event["candidatePlanSha256"])
        previous = terminal_record["receipt"]
        profile.require(value["terminal_receipt_sha256"] == previous["signed_receipt_sha256"])
        prior_event = profile.document(bytes(previous["canonical_event_bytes"]), 16 * 1024)
        for name in ("activePlanSha256", "finalActiveDecisionSha256", "activeEffectResultsSha256", "activeDisposition"):
            profile.require(event[name] == prior_event[name])
        role, coverage = "ledger-append", "candidate-request-observation"
    window = assignment["observationWindow"]
    observed = receipt["trusted_observed_at_unix_nanos"]
    profile.require(receipt["generation_id"] == publication["generation_id_digest"]
        and receipt["event_ordinal"] > previous["event_ordinal"]
        and observed >= previous["trusted_observed_at_unix_nanos"]
        and window["startsAtUnixNanos"] <= observed < window["endsAtUnixNanos"]
        and 0 <= now - observed <= window["maximumEvidenceAgeNanos"]
        and now < min(assignment["expiresAtUnixNanos"], window["endsAtUnixNanos"]))
    message = opening.verify_receipt_signature(value, receipt, assignment=assignment, context=context, publication=publication, role=role)
    result = {"apiVersion": value["apiVersion"], "generationId": receipt["generation_id"], "ingressSequence": receipt["ingress_sequence"],
        "openingReceiptSha256": value["opening_receipt_sha256"], "receiptSha256": receipt["signed_receipt_sha256"],
        "signatureMessageSha256": profile.sha256(message), "recordSha256": profile.sha256(profile.canonical(value)), "coverage": coverage}
    if response:
        result["requestObservationReceiptSha256"] = value["request_observation_receipt_sha256"]
    return result
