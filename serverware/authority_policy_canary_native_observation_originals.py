"""Closed preimages inside genuine native accounting signatures.

These are not ObservationResult, effect capabilities or readiness verdicts.
The callers retain signature/current-purpose/complete-prefix admission; this
module checks the exact producer preimages and protected predecessor joins.
"""
import re

from serverware import authority_policy_canary as p
from serverware import authority_policy_canary_native_opening as opening

EVENT_V1 = "serverware.policyShadowRuntimeAccountingEvent/v1"
EVENT_V2 = "serverware.policyShadowRuntimeAccountingEvent/v2"
REQUEST = "serverware.nativeRequestObservationOriginal/v1"
RESPONSE = "serverware.nativeResponseObservationOriginal/v1"
REQUEST_V2 = "serverware.nativeRequestObservationOriginal/v2"
REQUEST_V3 = "serverware.nativeRequestObservationOriginal/v3"
RESPONSE_V2 = "serverware.nativeResponseObservationOriginal/v2"
MAX_BYTES, MAX_NODES, MAX_DEPTH = 8 * 1024, 512, 32
LATENCY = frozenset({"factsCaptureNanos", "activeEvaluationNanos", "candidateEvaluationNanos",
    "responseValidationNanos", "shadowTotalNanos"})
EVALUATION = frozenset({"snapshotSha256", "routeSha256", "operationSha256", "policyPlanSha256",
    "disposition", "policyPlan", "authorityBinding"})
PLAN = frozenset({"outcome", "requestRewriteCommitments", "responseValidationCommitments", "effectIntents"})
BINDING = frozenset({"principalSha256", "routeSha256", "operation", "compiledSemanticProfileSha256", "requestAuthorityClass"})
INTENTS = {
    "materialize-credential": ("credentialSlotSha256", "destination"),
    "require-gmail-prior-search-proof": ("routeSha256", "gmailUserSha256", "messageIdSha256", "maximumAgeDays"),
    "resolve-gmail-metadata-fanout": ("routeSha256", "maximumAgeDays", "maximumMessages"),
    "resolve-credential-version": ("credentialSlotSha256", "credentialClaimSha256"),
    "refresh-oauth-credential": ("credentialSlotSha256", "oauthAuthoritySha256"),
    "exchange-oauth-credential": ("credentialSlotSha256", "oauthAuthoritySha256"),
    "mint-oauth-credential": ("credentialSlotSha256", "oauthAuthoritySha256"),
    "acquire-credential-lease": ("credentialSlotSha256", "leasePolicySha256"),
    "decrypt-credential": ("credentialSlotSha256", "decryptionContextSha256"),
    "inject-credential": ("credentialSlotSha256", "injectionCommitmentSha256"),
    "bind-idempotency-key": ("idempotencyCommitmentSha256",),
    "resolve-recovery-state": ("recoveryCommitmentSha256",),
    "require-jit-approval": ("approvalPolicySha256",),
    "reserve-quota": ("counterSha256", "claimSha256", "weightedUnits"),
    "reserve-durable-budget": ("budgetSha256", "claimSha256", "weightedUnits"),
}
CONDITIONAL = frozenset({"resolve-credential-version", "refresh-oauth-credential", "exchange-oauth-credential",
    "mint-oauth-credential", "resolve-recovery-state", "require-gmail-prior-search-proof",
    "resolve-gmail-metadata-fanout", "require-jit-approval", "reserve-quota", "reserve-durable-budget"})
# Actual Rust enum declaration order, not lexical sorting.
REQUIREMENTS = ("trust-freshness", "gmail-prior-search-proof", "gmail-metadata-fanout", "jit-grant",
    "quota-reserve", "quota-terminal", "durable-budget-reserve", "durable-budget-terminal", "credential-version",
    "credential-lease", "credential-decrypt", "credential-injection", "oauth-refresh", "oauth-exchange", "oauth-mint",
    "idempotency-binding", "recovery-resolution", "final-request", "dispatch-authorization", "dispatch-terminal",
    "response-validation", "terminal-response")
INTENT_REQUIREMENTS = dict(zip(INTENTS, (
    ("credential-lease", "credential-decrypt", "credential-injection"), ("gmail-prior-search-proof",),
    ("gmail-metadata-fanout",), ("credential-version",), ("oauth-refresh",), ("oauth-exchange",), ("oauth-mint",),
    ("credential-lease",), ("credential-decrypt",), ("credential-injection",), ("idempotency-binding",),
    ("recovery-resolution",), ("jit-grant",), ("quota-reserve", "quota-terminal"),
    ("durable-budget-reserve", "durable-budget-terminal"))))


def exact(value, fields):
    p.require(type(value) is dict and set(value) == set(fields), "native observation original shape mismatch")
    return value


def integer(value, minimum=0, maximum=2**63 - 1):
    p.require(type(value) is int and minimum <= value <= maximum)
    return value


def identifier(value):
    p.require(type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,255}", value) is not None)


def hashed(value):
    return p.sha256(p.canonical(value))


def bounded(value):
    pending, nodes = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        p.require(nodes <= MAX_NODES and depth <= MAX_DEPTH)
        if type(item) is dict:
            p.require(all(type(key) is str for key in item))
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
        else:
            p.require(item is None or type(item) in {str, int, bool})
    p.require(len(p.canonical(value)) <= MAX_BYTES)
    return nodes


def event_shape(event, fields):
    p.require(type(event) is dict)
    if event.get("domain") == EVENT_V1:
        exact(event, fields)
        return False
    exact(event, fields | {"observationOriginal"})
    p.require(event["domain"] == EVENT_V2 and event["observationOriginal"] is not None
        and (event["event"], event["phase"]) in {("candidate-evaluated", "candidate"), ("response-evaluated", "response")})
    return True


def plan(value, candidate):
    exact(value, PLAN | ({"evaluationPurpose", "effectCapabilitiesAvailable", "effectIntentsExecuted"} if candidate else set()))
    outcome = value["outcome"]
    p.require(type(outcome) is dict and outcome.get("kind") in {"permit", "conditional", "deny", "indeterminate"})
    exact(outcome, {"kind"} if outcome["kind"] == "permit" else {"kind", "reason"})
    if "reason" in outcome:
        identifier(outcome["reason"])
    if candidate:
        p.require(value["evaluationPurpose"] == "candidate-shadow" and value["effectCapabilitiesAvailable"] is False
            and value["effectIntentsExecuted"] is False, "candidate original is not no-effect evaluation")
    for field in ("requestRewriteCommitments", "responseValidationCommitments"):
        items = value[field]
        p.require(type(items) is list and len(items) <= 128)
        for item in items:
            p.digest(item)
        p.require(len(set(items)) == len(items))
    effects = value["effectIntents"]
    p.require(type(effects) is list and len(effects) <= 128)
    selected = []
    for effect in effects:
        p.require(type(effect) is dict and type(effect.get("kind")) is str)
        kind = effect["kind"]
        if candidate:
            p.require(kind.startswith("would-"))
            kind = kind[6:]
            if kind == "use-active-gmail-metadata-evidence":
                kind = "resolve-gmail-metadata-fanout"
            else:
                p.require(kind != "resolve-gmail-metadata-fanout")
        p.require(kind in INTENTS)
        exact(effect, {"kind", *INTENTS[kind]})
        for name in INTENTS[kind]:
            if name.endswith("Sha256"):
                p.digest(effect[name])
            elif name == "destination":
                identifier(effect[name])
            else:
                integer(effect[name], 1)
        selected.append(kind)
    conditional = bool(CONDITIONAL.intersection(selected))
    p.require(not (outcome["kind"] == "conditional" and not conditional)
        and not (outcome["kind"] == "permit" and conditional))
    if outcome["kind"] in {"deny", "indeterminate"}:
        p.require(not any(value[name] for name in PLAN - {"outcome"}))
    return selected


def evaluation(value, candidate, *, detailed=False):
    exact(value, EVALUATION | ({"dispatchProjection", "responseConstraints"} if detailed else set()))
    for name in ("snapshotSha256", "policyPlanSha256"):
        p.digest(value[name])
    for name in ("routeSha256", "operationSha256"):
        if value[name] is not None:
            p.digest(value[name])
    plan(value["policyPlan"], candidate)
    p.require(value["disposition"] == value["policyPlan"]["outcome"]["kind"]
        and value["policyPlanSha256"] == opening.material(
            "serverware.candidatePolicyPlan/v1" if candidate else "serverware.activePolicyPlan/v1", value["policyPlan"]))
    binding = value["authorityBinding"]
    if binding is not None:
        exact(binding, BINDING)
        for name in ("principalSha256", "routeSha256", "compiledSemanticProfileSha256"):
            p.digest(binding[name])
        p.require(binding["operation"] in {"read", "search", "write", "publish", "delete", "administrative"}
            and binding["requestAuthorityClass"] == ("read" if binding["operation"] in {"read", "search"} else "write")
            and binding["routeSha256"] == value["routeSha256"] and value["operationSha256"] is not None)
    if detailed:
        dispatch, constraints = value["dispatchProjection"], value["responseConstraints"]
        if dispatch is not None:
            p.require(type(dispatch) is dict)
            if dispatch.get("domain") == "serverware.policyShadowNoDispatch/v1":
                exact(dispatch, {"domain", "outcome"})
                p.require(dispatch["outcome"] == value["policyPlan"]["outcome"]
                    and value["disposition"] in {"deny", "indeterminate"})
            else:
                exact(dispatch, {"domain", "principalSha256", "routeSha256", "request", "operationSha256",
                    "credentialSlotSha256", "injectionPolicySha256"})
                p.require(dispatch["domain"] == "serverware.policyShadowCredentialFreeDispatch/v1"
                    and value["disposition"] in {"permit", "conditional"}
                    and dispatch["routeSha256"] == value["routeSha256"]
                    and dispatch["operationSha256"] == value["operationSha256"])
                for name in ("principalSha256", "routeSha256", "operationSha256", "injectionPolicySha256"):
                    p.digest(dispatch[name])
                if dispatch["credentialSlotSha256"] is not None:
                    p.digest(dispatch["credentialSlotSha256"])
                if binding is not None:
                    p.require(dispatch["principalSha256"] == binding["principalSha256"])
                request = exact(dispatch["request"], {"method", "scheme", "authoritySha256", "pathSha256",
                    "querySha256", "headersSha256", "bodySha256", "bodyLength"})
                p.require(type(request["method"]) is str and re.fullmatch(r"[A-Z!#$%&'*+.^_`|~-]{1,64}", request["method"]) is not None
                    and request["scheme"] in {"http", "https"})
                integer(request["bodyLength"])
                for name in ("authoritySha256", "pathSha256", "querySha256", "headersSha256", "bodySha256"):
                    p.digest(request[name])
        if constraints is not None:
            exact(constraints, {"domain", "routeSha256", "adapterTypeSha256", "adapterConfigSha256", "constraintSha256s"})
            p.require(constraints["domain"] == "serverware.policyShadowNativeResponseConstraints/v1"
                and constraints["routeSha256"] == value["routeSha256"])
            for name in ("routeSha256", "adapterTypeSha256", "adapterConfigSha256"):
                p.digest(constraints[name])
            digests = constraints["constraintSha256s"]
            p.require(type(digests) is list and len(digests) <= 128 and digests == sorted(set(digests)))
            for digest in digests:
                p.digest(digest)


def latency(value):
    exact(value, LATENCY)
    for sample in value.values():
        if sample is not None:
            integer(sample)


def request_original(value, event, observed):
    fields = {"apiVersion", "pureActiveEvaluation", "candidateEvaluation", "finalActiveEnforcement",
        "factsCapturedAtUnixNanos", "latencySamples"}
    p.require(type(value) is dict)
    exact(value, fields | ({"protectedRequest"} if value.get("apiVersion") == REQUEST_V3 else set()))
    p.require(value["apiVersion"] in {REQUEST, REQUEST_V2, REQUEST_V3})
    active, candidate, final = (value[name] for name in ("pureActiveEvaluation", "candidateEvaluation", "finalActiveEnforcement"))
    evaluation(active, False, detailed=value["apiVersion"] in {REQUEST_V2, REQUEST_V3})
    evaluation(candidate, True, detailed=value["apiVersion"] in {REQUEST_V2, REQUEST_V3})
    if value["apiVersion"] == REQUEST_V3:
        from serverware import authority_policy_canary_native_request_commitment as protected
        protected.shape(value["protectedRequest"])
    p.require(active["policyPlanSha256"] == event["activePlanSha256"]
        and candidate["policyPlanSha256"] == event["candidatePlanSha256"]
        and candidate["disposition"] == event["candidateDisposition"])
    exact(final, {"effectResults", "terminalEvidence", "returnedHttpStatus", "finalizedAtUnixNanos", "dispatchAuthorized"})
    integer(final["returnedHttpStatus"], 200, 599)
    p.require(type(final["dispatchAuthorized"]) is bool)
    p.require(integer(value["factsCapturedAtUnixNanos"], 1) <= integer(final["finalizedAtUnixNanos"], 1) <= observed)
    effects = exact(final["effectResults"], {"domain", "activePlanSha256", "explicitCommitments", "terminalResponseSha256",
        "exactResponseFactsSha256", "activeResponseValidationSha256", "gmailMetadataEvidenceSha256", "terminalEffectCommitments"})
    p.require(effects["domain"] == "serverware.policyShadowFinalEffectResults/v2"
        and effects["activePlanSha256"] == active["policyPlanSha256"] and hashed(effects) == event["activeEffectResultsSha256"])
    for name in ("terminalResponseSha256", "exactResponseFactsSha256", "activeResponseValidationSha256", "gmailMetadataEvidenceSha256"):
        if effects[name] is not None:
            p.digest(effects[name])
    p.digest(effects["terminalResponseSha256"])
    for name in ("explicitCommitments", "terminalEffectCommitments"):
        p.require(type(effects[name]) is list and len(effects[name]) <= 128)
        for item in effects[name]:
            p.digest(item)
    terminal = final["terminalEvidence"]
    p.require(type(terminal) is list and len(terminal) <= len(REQUIREMENTS))
    requirements = {"trust-freshness", "final-request", "terminal-response"}
    for kind in plan(active["policyPlan"], False):
        requirements.update(INTENT_REQUIREMENTS[kind])
    if active["disposition"] in {"permit", "conditional"}:
        requirements.update(("dispatch-authorization", "dispatch-terminal"))
    if active["policyPlan"]["responseValidationCommitments"]:
        requirements.add("response-validation")
    ordered = []
    for item in terminal:
        exact(item, {"requirement", "terminalState", "resultSha256"})
        p.digest(item["resultSha256"])
        p.require(item["requirement"] in REQUIREMENTS and item["terminalState"] in {
            "completed", "denied", "failed", "cancelled", "provider-outcome-unknown", "recovery-required", "not-reached"})
        ordered.append(item["requirement"])
        if item["requirement"] in {"trust-freshness", "final-request", "terminal-response"}:
            p.require(item["terminalState"] != "not-reached")
        field = {"response-validation": "activeResponseValidationSha256", "terminal-response": "terminalResponseSha256",
            "gmail-metadata-fanout": "gmailMetadataEvidenceSha256"}.get(item["requirement"])
        if field:
            p.require((item["terminalState"] == "completed" and effects[field] == item["resultSha256"])
                or (item["terminalState"] != "completed" and effects[field] is None))
    p.require(ordered == [item for item in REQUIREMENTS if item in requirements]
        and effects["terminalEffectCommitments"] == [hashed({"domain": "serverware.policyShadowTypedTerminalEffect/v1", **item}) for item in terminal])
    p.require(event["finalActiveDecisionSha256"] == hashed({"domain": "serverware.policyShadowFinalActiveOutcome/v2",
        "activePlanSha256": active["policyPlanSha256"], "outcome": event["activeDisposition"],
        "returnedHttpStatus": final["returnedHttpStatus"], "dispatchAuthorized": final["dispatchAuthorized"],
        "effectResultsSha256": event["activeEffectResultsSha256"], "terminalResponseSha256": effects["terminalResponseSha256"]}))
    latency(value["latencySamples"])
    p.require(value["latencySamples"]["responseValidationNanos"] is None)


def response_original(value, event, observed):
    exact(value, {"apiVersion", "response", "latencySamples"})
    p.require(value["apiVersion"] in {RESPONSE, RESPONSE_V2})
    response = exact(value["response"], {"responseFacts", "boundActiveValidation", "activeValidation", "candidateValidation"})
    facts, bound, active, candidate = (response[name] for name in ("responseFacts", "boundActiveValidation", "activeValidation", "candidateValidation"))
    exact(facts, {"domain", "capturedAtEpochMs", "status", "physicalHeaderCount", "physicalHeadersSha256", "rawResponseHeadBytes",
        "rawResponseBodySha256", "rawResponseBodyBytes", "bodySha256", "bodyLength", "transportCaptureReceiptSha256",
        "runtimeAttestationSha256", "peerIdentitySha256", "framing", "mode"})
    p.require(facts["domain"] == "serverware.policyShadowExactResponseFacts/v1" and facts["mode"] == "bounded-exact"
        and facts["framing"] in {"no-body", "content-length", "chunked", "close-delimited"})
    integer(facts["status"], 100, 599)
    p.require(integer(facts["capturedAtEpochMs"], 1) * 1_000_000 <= observed)
    for name in ("physicalHeaderCount", "rawResponseHeadBytes", "rawResponseBodyBytes", "bodyLength"):
        integer(facts[name])
    for name in ("physicalHeadersSha256", "rawResponseBodySha256", "bodySha256", "transportCaptureReceiptSha256",
            "runtimeAttestationSha256", "peerIdentitySha256"):
        p.digest(facts[name])
    exact(bound, {"domain", "activePolicySnapshotSha256", "responseObligationRootSha256", "responseFactsSha256", "activeValidationSha256"})
    released_fields = {"domain", "outcome", "inspectionReceiptSha256", "finalEnvelopeVerificationSha256", "releaseRetrievalReceiptSha256", "releasedResponseSha256"}
    successor = value["apiVersion"] == RESPONSE_V2
    exact(active, released_fields | ({"releasedEntitySha256", "releasedEntityBytes", "releasedStatus", "releasedContentType",
        "releasedContentTypeState", "releaseMode", "releasedParsedResponseSha256"} if successor else set()))
    p.require(bound["domain"] == "serverware.policyShadowBoundActiveResponseValidation/v1"
        and active["domain"] == ("serverware.policyShadowNativeReleasedResponse/v2" if successor else "serverware.policyShadowNativeReleasedResponse/v1")
        and active["outcome"] == "released")
    for item, names in ((bound, set(bound) - {"domain"}), (active, released_fields - {"domain", "outcome"})):
        for name in names:
            p.digest(item[name])
    if successor:
        p.digest(active["releasedEntitySha256"]); p.digest(active["releasedParsedResponseSha256"])
        integer(active["releasedEntityBytes"]); integer(active["releasedStatus"], 100, 599)
        p.require(active["releaseMode"] == "native-immutable-exact"
            and active["releasedContentTypeState"] in {"absent", "present", "unavailable"})
        media = active["releasedContentType"]
        if active["releasedContentTypeState"] == "present":
            p.require(type(media) is str and len(media) <= 1024
                and re.fullmatch(r"[a-z0-9!#$&^_.+\-]+/[a-z0-9!#$&^_.+\-]+", media) is not None)
        else:
            p.require(media is None)
    p.require(hashed(facts) == event["responseFactsSha256"] == bound["responseFactsSha256"]
        and hashed(active) == bound["activeValidationSha256"] and hashed(bound) == event["activeResponseValidationSha256"])
    exact(candidate, {"domain", "outcome", "routeIdSha256", "capturedAtEpochMs", "status", "bodySha256", "physicalHeadersSha256",
        "activeGmailMetadataEvidenceSha256", "generationResponseObligationRootSha256", "responseObligationsSha256", "responsePolicySha256",
        "candidateReleasedBodySha256", "candidateReleasedBodyBytes", "candidateReleasedContentType", "candidateReleaseMode", "rejectionSha256"})
    p.require(candidate["domain"] == "serverware.policyShadowCandidateResponseValidation/v1"
        and candidate["outcome"] in {"accepted", "rejected"} and hashed(candidate) == event["candidateResponseValidationSha256"])
    for name in ("capturedAtEpochMs", "status", "physicalHeadersSha256"):
        p.require(type(candidate[name]) is type(facts[name]) and candidate[name] == facts[name])
    for name in ("routeIdSha256", "bodySha256", "generationResponseObligationRootSha256", "responseObligationsSha256", "responsePolicySha256"):
        p.digest(candidate[name])
    for name in ("activeGmailMetadataEvidenceSha256", "candidateReleasedBodySha256", "rejectionSha256"):
        if candidate[name] is not None:
            p.digest(candidate[name])
    p.require(candidate["generationResponseObligationRootSha256"] == bound["responseObligationRootSha256"])
    if candidate["activeGmailMetadataEvidenceSha256"] is None:
        p.require(candidate["bodySha256"] == facts["bodySha256"])
    if candidate["outcome"] == "accepted":
        p.digest(candidate["candidateReleasedBodySha256"])
        integer(candidate["candidateReleasedBodyBytes"])
        p.require(candidate["candidateReleaseMode"] in {"passthrough", "json-projection", "gmail-validation-disabled", "headers-only"}
            and candidate["rejectionSha256"] is None)
        if candidate["candidateReleasedContentType"] is not None:
            p.require(type(candidate["candidateReleasedContentType"]) is str)
    else:
        p.digest(candidate["rejectionSha256"])
        p.require(all(candidate[name] is None for name in ("candidateReleasedBodySha256", "candidateReleasedBodyBytes",
            "candidateReleasedContentType", "candidateReleaseMode")))
    latency(value["latencySamples"])


def validate_event(event, receipt):
    """Called only after exact event framing; v1 bytes remain uninterpreted here."""
    if event["domain"] != EVENT_V2:
        return
    value = event["observationOriginal"]
    bounded(value)
    observed = integer(receipt["trusted_observed_at_unix_nanos"], 1)
    p.require(event["activeDisposition"] in {"allow", "deny", "conditional", "error"}
        and event["candidateDisposition"] in {"permit", "deny", "conditional", "indeterminate"}
        and all(event[name] is None for name in ("terminalDetailSha256", "decisionAtUnixNanos",
            "dispatchFinalRequestSha256", "dispatchEffectAuthoritySha256")))
    for name in ("finalActiveDecisionSha256", "activeEffectResultsSha256", "candidatePlanSha256"):
        p.digest(event[name])
    if event["event"] == "candidate-evaluated":
        p.digest(event["activePlanSha256"])
        p.require(all(event[name] is None for name in ("responseFactsSha256", "activeResponseValidationSha256", "candidateResponseValidationSha256")))
        request_original(value, event, observed)
    else:
        p.require(event["activePlanSha256"] is None and event["activeDisposition"] == "allow",
            "selected native released-response original differs from final enforcement")
        response_original(value, event, observed)


def decoded(receipt):
    return p.document(bytes(receipt["canonical_event_bytes"]), 16 * 1024)


def retained_constraints(state, evaluated, raw):
    """Recompute the v2 rule originals from the actual signed installed route."""
    from serverware import policy_route_authority as classifier
    selected = [route for route in raw["routes"] if classifier.text_digest(route["id"]) == evaluated["routeSha256"]]
    p.require(len(selected) == 1, "native response constraint route is not an exact installed route")
    route = selected[0]
    state.charge(len(raw["routes"]) + 2 * ((len(classifier.canonical(route)) + 255) // 256))
    rules = route.get("constraints")
    # Actual loader maps omitted/null constraints to its empty retained list.
    rules = [] if rules is None else rules
    digests = sorted({classifier.digest(value) for value in rules
        if value.get("type") == "traversalBudget" or value.get("phase", "request") in {"response", "both"}})
    expected = {"domain": "serverware.policyShadowNativeResponseConstraints/v1", "routeSha256": evaluated["routeSha256"],
        "adapterTypeSha256": classifier.text_digest(route["adapter"]["type"]),
        "adapterConfigSha256": classifier.digest(route["adapter"]["config"]), "constraintSha256s": digests}
    p.require(evaluated["responseConstraints"] == expected, "native response constraints differ from signed installed rules")
    dispatch = evaluated["dispatchProjection"]
    if dispatch is not None and dispatch["domain"] == "serverware.policyShadowCredentialFreeDispatch/v1":
        credential = route.get("credentialRef")
        p.require(dispatch["credentialSlotSha256"] == (None if credential is None else classifier.text_digest(credential)))
    return expected


def validate_protected_originals(state, record, receipts, publication, load, *, assignment, context):
    """After actual receipt signatures/current scope admission, join originals.

    Individual callers supply protected opening/terminal/request predecessors;
    cumulative callers supply the complete authenticated prefix. Returned data
    remains partial preimages, never a verification token or readiness result.
    """
    p.require(type(receipts) in {list, tuple} and len(receipts) <= 64)
    events = [(decoded(receipt), receipt) for receipt in receipts]
    selected = {receipt["ingress_sequence"] for event, receipt in events
        if type(event) is dict and event.get("domain") == EVENT_V2}
    if not selected:
        return {}
    terminals, requests, responses, pair = {}, {}, {}, None
    openings = {}
    for event, receipt in events:
        if type(event) is list:
            p.require(receipt["ingress_sequence"] not in openings, "duplicate protected opening")
            openings[receipt["ingress_sequence"]] = (event, receipt)
            continue
        if type(event) is not dict or receipt["ingress_sequence"] not in selected:
            continue
        sequence = receipt["ingress_sequence"]
        if event["event"] in {"active-pre-dispatch-terminal", "response-terminal-appended"}:
            p.require(sequence not in terminals, "observation repeats a terminal predecessor")
            terminals[sequence] = (event, receipt)
        if event["domain"] != EVENT_V2:
            continue
        original = event["observationOriginal"]
        state.charge(2 * bounded(original) + 4)
        validate_event(event, receipt)
        terminal, terminal_receipt = terminals.get(sequence, (None, None))
        p.require(terminal is not None, "detailed observation lacks its actual earlier terminal original")
        for name in ("generation_id", "ingress_sequence", "request_binding_sha256", "request_commitment_sha256"):
            p.require(receipt[name] == terminal_receipt[name])
        p.require(terminal_receipt["event_ordinal"] < receipt["event_ordinal"]
            and terminal_receipt["trusted_observed_at_unix_nanos"] <= receipt["trusted_observed_at_unix_nanos"])
        for name in ("finalActiveDecisionSha256", "activeEffectResultsSha256", "activeDisposition"):
            p.require(event[name] == terminal[name])
        if event["event"] == "candidate-evaluated":
            p.require(sequence not in requests and event["activePlanSha256"] == terminal["activePlanSha256"])
            final = original["finalActiveEnforcement"]
            p.require(final["finalizedAtUnixNanos"] <= terminal_receipt["trusted_observed_at_unix_nanos"]
                and final["dispatchAuthorized"] == (terminal["event"] == "response-terminal-appended")
                and final["effectResults"]["exactResponseFactsSha256"] == terminal["responseFactsSha256"]
                and final["effectResults"]["activeResponseValidationSha256"] == terminal["activeResponseValidationSha256"])
            for lane, name in (("active", "pureActiveEvaluation"), ("candidate", "candidateEvaluation")):
                evaluated = original[name]
                p.require(evaluated["snapshotSha256"] == publication[lane + "_policy_hash"])
                if evaluated["authorityBinding"] is not None:
                    from serverware import authority_transition_policy_canary_route_authority as classifier
                    if pair is None:
                        pair = classifier.retained_pair(state, record)
                    classifier.require_binding(pair, lane, evaluated["authorityBinding"])
                if original["apiVersion"] in {REQUEST_V2, REQUEST_V3} and evaluated["responseConstraints"] is not None:
                    from serverware import db
                    management = db.loads(publication["management_request_json"], None)
                    retained_constraints(state, evaluated, management[lane + "PolicyBundle"])
            if original["apiVersion"] == REQUEST_V3:
                from serverware import authority_policy_canary_native_request_commitment as protected
                p.require(sequence in openings, "later facts computation lacks its exact signed early opening")
                protected.verify(state, record, original, receipt, openings[sequence],
                    assignment=assignment, context=context, publication=publication)
            requests[sequence] = (event, receipt)
        else:
            p.require(sequence not in responses and sequence in requests and terminal["event"] == "response-terminal-appended")
            request, request_receipt = requests[sequence]
            p.require(request_receipt["event_ordinal"] < receipt["event_ordinal"]
                and request_receipt["trusted_observed_at_unix_nanos"] <= receipt["trusted_observed_at_unix_nanos"])
            for name in ("candidatePlanSha256", "candidateDisposition"):
                p.require(event[name] == request[name])
            for name in ("responseFactsSha256", "activeResponseValidationSha256"):
                p.require(event[name] == terminal[name])
            comparison = original["response"]
            prior = request["observationOriginal"]
            p.require((original["apiVersion"] == RESPONSE_V2) == (prior["apiVersion"] in {REQUEST_V2, REQUEST_V3}),
                "native observation successor cannot mix prior preimage profiles")
            candidate = comparison["candidateValidation"]
            p.require(comparison["boundActiveValidation"]["activePolicySnapshotSha256"] == publication["active_policy_hash"]
                and comparison["boundActiveValidation"]["responseObligationRootSha256"] == load["responseValidationObligationsRootSha256"]
                and candidate["routeIdSha256"] == prior["candidateEvaluation"]["routeSha256"]
                and candidate["responseObligationsSha256"] == hashed({"domain": "serverware.policyShadowCandidateResponseObligations/v1",
                    "commitments": prior["candidateEvaluation"]["policyPlan"]["responseValidationCommitments"]})
                and comparison["activeValidation"]["releasedResponseSha256"] == prior["finalActiveEnforcement"]["effectResults"]["terminalResponseSha256"]
                and candidate["activeGmailMetadataEvidenceSha256"] == prior["finalActiveEnforcement"]["effectResults"]["gmailMetadataEvidenceSha256"]
                and prior["factsCapturedAtUnixNanos"] <= comparison["responseFacts"]["capturedAtEpochMs"] * 1_000_000
                <= prior["finalActiveEnforcement"]["finalizedAtUnixNanos"])
            responses[sequence] = (event, receipt)
    return {sequence: {"request": requests[sequence], "response": responses.get(sequence)} for sequence in requests}
