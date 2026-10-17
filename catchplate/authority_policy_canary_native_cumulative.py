"""Complete native receipt-prefix accounting; not a readiness or seal verdict."""
from catchplate import authority_policy_canary as profile
from catchplate import authority_policy_canary_native_opening as opening
from catchplate import authority_policy_canary_native_runtime as runtime
from catchplate import authority_policy_canary_native_observation_originals as observations

SCHEMA = "catchplate.nativeCumulativeCheckpoint/v1"
MAX_RECORD = 768 * 1024
FIELDS = opening.FIELDS - {"opening_receipt", "signing_public_key_base64url"} | {
    "checkpoint_sequence", "previous_checkpoint_sha256", "heartbeat", "heartbeat_sha256",
    "interval_receipt_sha256", "accounting", "signing_public_keys"}
ACCOUNTING_FIELDS = frozenset({"generationId", "baselineEventOrdinal", "baselineHeadSha256", "lastEventOrdinal",
    "lastHeadSha256", "observedAtUnixNanos", "originalCount", "receiptRootSha256", "eventRootSha256",
    "counters", "lastIngress", "originals"})
LABELS = ("admitted", "active-pre-dispatch-terminal", "response-terminal-appended", "dispatch-barrier-appended",
    "response-capture-enqueued", "candidate-evaluated", "response-evaluated", "sampled-out", "transport-excluded",
    "unsupported-required-ingress", "cleanup-quarantined", "failure")
PHASES = frozenset({"ingress-open", "capture", "decision", "pre-dispatch-terminal", "dispatch-barrier",
    "post-dispatch-terminal", "response", "candidate", "range-closure"})
ROLES = frozenset({"ingress-admission", "dispatch-barrier", "terminal-append", "ledger-append"})
EVENT_PHASES = {"active-pre-dispatch-terminal": {"pre-dispatch-terminal"},
    "response-terminal-appended": {"post-dispatch-terminal"}, "dispatch-barrier-appended": {"dispatch-barrier"},
    "response-capture-enqueued": {"response"}, "candidate-evaluated": {"candidate"}, "response-evaluated": {"response"},
    "sampled-out": {"ingress-open"}, "transport-excluded": {"ingress-open"}, "unsupported-required-ingress": {"ingress-open"},
    "cleanup-quarantined": {"response"}, "failure": PHASES}


def integer(value):
    profile.require(type(value) is int and 0 <= value <= 9_223_372_036_854_775_807)
    return value


def event_original(receipt, generation, assignment):
    """Retain all original bytes, including failure/exclusion observations."""
    profile.require(type(receipt) is dict and set(receipt) == opening.RECEIPT_FIELDS
        and receipt["disposition"] == "appended" and receipt["event_phase"] in PHASES)
    for name in opening.RECEIPT_FIELDS - {"ingress_sequence", "event_ordinal", "predecessor_event_ordinal", "event_phase",
            "disposition", "canonical_event_bytes", "trusted_observed_at_unix_nanos", "signature"}:
        profile.digest(receipt[name])
    for name in ("ingress_sequence", "event_ordinal", "predecessor_event_ordinal", "trusted_observed_at_unix_nanos"):
        integer(receipt[name])
    profile.require(receipt["ingress_sequence"] > 0 and receipt["event_ordinal"] == receipt["predecessor_event_ordinal"] + 1)
    raw = receipt["canonical_event_bytes"]
    profile.require(type(raw) is list and 0 < len(raw) <= 16 * 1024 and all(type(v) is int and 0 <= v <= 255 for v in raw))
    raw = bytes(raw)
    event = profile.document(raw, 16 * 1024)
    profile.require(profile.canonical(event) == raw and profile.sha256(raw) == receipt["event_sha256"])
    if type(event) is list:
        if len(event) == 4 and event[0] == opening.EARLY_EVENT:
            opening.early_sampling(event, receipt, generation)
            return "admitted"
        profile.require(len(event) == 4 and event[0] == "catchplate.policyShadowIngressAdmissionEvent/v1"
            and profile.canonical(event[1]) == profile.canonical(generation)
            and event[2] == receipt["trusted_observed_at_unix_nanos"] and receipt["event_phase"] == "ingress-open")
        sample = event[3]
        profile.require(type(sample) is dict and set(sample) == {"generationId", "requestBindingSha256", "ingressSequence",
            "samplingBasisPoints", "requestCommitmentSha256", "decision"})
        expected = {"generationId": receipt["generation_id"], "requestBindingSha256": receipt["request_binding_sha256"],
            "ingressSequence": receipt["ingress_sequence"], "samplingBasisPoints": assignment["observationWindow"]["samplingBasisPoints"],
            "requestCommitmentSha256": receipt["request_commitment_sha256"], "decision": sample["decision"]}
        profile.require(profile.canonical(sample) == profile.canonical(expected)
            and sample["decision"] in {"included", "excluded-by-assignment"})
        return "admitted"
    observations.event_shape(event, runtime.EVENT_FIELDS)
    observations.validate_event(event, receipt)
    profile.require(event["event"] in EVENT_PHASES and event["phase"] in EVENT_PHASES[event["event"]])
    for field, name in (("ingressSequence", "ingress_sequence"), ("requestBindingSha256", "request_binding_sha256"),
            ("requestCommitmentSha256", "request_commitment_sha256"), ("phase", "event_phase")):
        profile.require(type(event[field]) is type(receipt[name]) and event[field] == receipt[name])
    for name in runtime.EVENT_FIELDS - {"domain", "ingressSequence", "event", "phase", "activeDisposition", "candidateDisposition", "decisionAtUnixNanos"}:
        if event[name] is not None:
            profile.digest(event[name])
    profile.require(event["activeDisposition"] in {None, "allow", "deny", "conditional", "error"}
        and event["candidateDisposition"] in {None, "permit", "deny", "conditional", "indeterminate"})
    if event["decisionAtUnixNanos"] is not None:
        integer(event["decisionAtUnixNanos"])
        profile.require(event["decisionAtUnixNanos"] <= receipt["trusted_observed_at_unix_nanos"])
    return event["event"]


def verify(value, *, assignment, load, context, publication, now):
    profile.require(type(value) is dict and set(value) == FIELDS and value["apiVersion"] == SCHEMA
        and len(profile.canonical(value)) <= MAX_RECORD)
    sequence = integer(value["checkpoint_sequence"])
    profile.require(1 <= sequence <= 32 and (sequence == 1) == (value["previous_checkpoint_sha256"] is None))
    if value["previous_checkpoint_sha256"] is not None:
        profile.digest(value["previous_checkpoint_sha256"])
    for name in ("heartbeat_sha256", "interval_receipt_sha256"):
        profile.digest(value[name])
    heartbeat = value["heartbeat"]
    profile.require(type(heartbeat) is dict and heartbeat.get("apiVersion") == "catchplate.nativePolicyShadowHeartbeat/v1"
        and value["heartbeat_sha256"] == profile.sha256(profile.canonical(heartbeat)))
    for name in opening.FIELDS - {"apiVersion", "opening_receipt", "signing_public_key_base64url"}:
        profile.require(heartbeat[name] == value[name])
    accounting, public = value["accounting"], value["signing_public_keys"]
    profile.require(type(accounting) is dict and set(accounting) == ACCOUNTING_FIELDS
        and type(public) is dict and 1 <= len(public) <= 4 and set(public) <= ROLES)
    for name in ("baselineEventOrdinal", "lastEventOrdinal", "observedAtUnixNanos", "originalCount"):
        integer(accounting[name])
    for name in ("generationId", "baselineHeadSha256", "lastHeadSha256", "receiptRootSha256", "eventRootSha256"):
        profile.digest(accounting[name])
    originals = accounting["originals"]
    profile.require(type(originals) is list and 1 <= len(originals) <= 64 and accounting["originalCount"] == len(originals)
        and len(profile.canonical(originals)) <= 512 * 1024
        and accounting["baselineEventOrdinal"] == load["authoritativeLedgerEventOrdinal"]
        and accounting["baselineHeadSha256"] == load["authoritativeLedgerHeadSha256"]
        and accounting["lastEventOrdinal"] == accounting["baselineEventOrdinal"] + len(originals)
        and accounting["generationId"] == publication["generation_id_digest"])
    window, observed = assignment["observationWindow"], accounting["observedAtUnixNanos"]
    profile.require(window["startsAtUnixNanos"] <= observed < window["endsAtUnixNanos"]
        and 0 <= now - observed <= window["maximumEvidenceAgeNanos"]
        and now < min(assignment["expiresAtUnixNanos"], load["expiresAtUnixNanos"], window["endsAtUnixNanos"]))
    statement = heartbeat["evidence"]["statement"]
    for name, field in (("generationId", "generationId"), ("baselineEventOrdinal", "baselineEventOrdinal"),
            ("baselineHeadSha256", "baselineHeadSha256"), ("eventOrdinal", "lastEventOrdinal"), ("headSha256", "lastHeadSha256"),
            ("originalCount", "originalCount"), ("observedAtUnixNanos", "observedAtUnixNanos")):
        profile.require(type(statement[name]) is type(accounting[field]) and statement[name] == accounting[field])
    generation = opening._generation(assignment, load, context, publication)
    previous = accounting["baselineHeadSha256"]
    counters, used_roles, ingress, last_ingress = dict.fromkeys(LABELS, 0), set(), {}, None
    expected_ingress = load["ingressRangeStartSequence"]
    for ordinal, receipt in enumerate(originals, accounting["baselineEventOrdinal"] + 1):
        label = event_original(receipt, generation, assignment)
        profile.require(receipt["generation_id"] == accounting["generationId"] and receipt["event_ordinal"] == ordinal
            and receipt["predecessor_head_sha256"] == previous
            and window["startsAtUnixNanos"] <= receipt["trusted_observed_at_unix_nanos"] <= observed
            and len(profile.canonical(receipt)) <= 64 * 1024)
        if label == "admitted":
            profile.require(receipt["ingress_sequence"] == expected_ingress)
            expected_ingress += 1
            ingress[receipt["ingress_sequence"]] = receipt
            last_ingress = {"ingressSequence": receipt["ingress_sequence"], "openingReceiptSha256": receipt["signed_receipt_sha256"]}
        else:
            opening_original = ingress.get(receipt["ingress_sequence"])
            profile.require(opening_original is not None and all(receipt[name] == opening_original[name]
                for name in ("generation_id", "request_binding_sha256", "request_commitment_sha256"))
                and receipt["trusted_observed_at_unix_nanos"] >= opening_original["trusted_observed_at_unix_nanos"],
                "cumulative event has no genuine preceding opening")
        role = {"ingress-open": "ingress-admission", "dispatch-barrier": "dispatch-barrier",
            "pre-dispatch-terminal": "terminal-append", "post-dispatch-terminal": "terminal-append"}.get(receipt["event_phase"], "ledger-append")
        profile.require(role in public)
        opening.verify_receipt_signature({"signing_public_key_base64url": public[role]}, receipt,
            assignment=assignment, context=context, publication=publication, role=role)
        used_roles.add(role)
        counters[label] += 1
        previous = receipt["resulting_head_sha256"]
    profile.require(used_roles == set(public) and previous == accounting["lastHeadSha256"]
        and accounting["receiptRootSha256"] == opening._merkle([receipt["signed_receipt_sha256"] for receipt in originals])
        and accounting["eventRootSha256"] == opening._merkle([receipt["event_sha256"] for receipt in originals])
        and profile.canonical(accounting["counters"]) == profile.canonical(counters)
        and profile.canonical(accounting["lastIngress"]) == profile.canonical(last_ingress)
        and statement["lastIngressSequence"] == (last_ingress["ingressSequence"] if last_ingress else None)
        and statement["openingReceiptSha256"] == (last_ingress["openingReceiptSha256"] if last_ingress else None))
    return {"apiVersion": SCHEMA, "generationId": accounting["generationId"], "checkpointSequence": sequence,
        "baselineEventOrdinal": accounting["baselineEventOrdinal"], "lastEventOrdinal": accounting["lastEventOrdinal"],
        "lastHeadSha256": accounting["lastHeadSha256"], "originalCount": len(originals), "counters": counters,
        "heartbeatSha256": value["heartbeat_sha256"], "recordSha256": profile.sha256(profile.canonical(value)),
        "coverage": "complete-native-prefix-not-readiness"}
