"""Typed monotonic custody and ingress transitions; no runtime SQL fallback."""
from catchplate import authority_policy_canary as profile
from catchplate import authority_transition_policy_canary_handoff as handoffs
from catchplate.authority_transition_policy_canary_state import exact, apply_verification
from catchplate.authority_transition_policy_canary_membership import record, integers

INSTANCE = ("canary_id", "instance_id", "boot_id")
MEMBER = ("assignment_envelope_digest", "assignment_payload_digest", "assignment_revision", "fleet_id", "membership_revision",
    "membership_root_digest", "member_ordinal", "member_id")
RUNTIME = MEMBER + ("load_receipt_envelope_digest", "load_receipt_payload_digest", "policy_identity_digest", "runtime_identity_digest")
HEAD = ("assignment_envelope_digest", "member_ordinal", "canary_id", "instance_id", "boot_id", "generation_id_digest")
CUSTODY_REFERENCE = ("custody_generation_id_digest", "custody_request_binding_digest", "custody_request_commitment_digest",
    "custody_opening_spill_receipt_digest", "custody_evidence_envelope_digest", "custody_evidence_payload_digest", "custody_verification_receipt_digest")


def identity(item, fields):
    return {name: item[name] for name in fields}


def wire(item, prefix):
    from catchplate import db
    parsed = db._policy_shadow_direct_envelope_components(prefix, db.loads(item[prefix + "_envelope_json"], None))
    profile.require(all(parsed[name] == item[prefix + "_" + name] for name in ("envelope_digest", "payload_digest", "payload_json", "envelope_json")))
    return parsed["payload"]


def observation_window(context):
    from catchplate import db
    original, _ = db._candidate_authority_json("assigned observation window", context["observation_window_json"], context["observation_window_digest"])
    return db._candidate_authority_strict_object("assigned observation window", db.loads(original, None), frozenset({
        "startsAtUnixNanos", "endsAtUnixNanos", "sealDeadlineUnixNanos", "minimumDurationNanos", "firstIngressSequence",
        "samplingBasisPoints", "requestCommitmentKeyId", "requestCommitmentKeyEpoch", "maximumEvidenceAgeNanos", "maximumHeartbeatGapNanos"}))


def observing(state, item):
    profile.require(state.one("policy_canary_instance_heads", **identity(item, INSTANCE))["status"] == "observing",
        "canary observation requires the exact observing instance head")


def reverify(state, item, *, current):
    from catchplate import db
    wire(item, "custody_evidence")
    receipt = state.one("policy_runtime_evidence_verifications", verification_receipt_digest=item["verification_receipt_digest"], evidence_kind="custody_evidence")
    exact(item, receipt, ("assignment_envelope_digest", "member_ordinal", "signature_digest", "record_binding_digest"))
    profile.require(receipt["envelope_digest"] == item["custody_evidence_envelope_digest"] and receipt["payload_digest"] == item["custody_evidence_payload_digest"])
    signed = {name: value for name, value in item.items() if name not in {"issued_at_epoch_ns", "expires_at_epoch_ns", "created_transition_digest"}}
    state.runtime("custody_evidence", item, "custody_evidence", db._candidate_authority_signed_record(signed, current_prefix="custody_evidence"),
        historical=not current, persist=False)
    if current:
        head = state.one("policy_canary_custody_heads", **identity(item, HEAD))
        exact(item, head, ("custody_sequence", "custody_evidence_envelope_digest", "ingress_sequence"))
        profile.require(head["custody_head_digest"] == item["resulting_custody_head_digest"])


def custody(state, value):
    from catchplate import db
    item = record(value, db._POLICY_CANARY_CUSTODY_EVIDENCE_FIELDS)
    actor = profile.text(item.pop("actor_id"), 1024)
    profile.text(item["custody_evidence_id"], 256)
    integers(item, ("assignment_revision", "membership_revision", "member_ordinal", "custody_sequence", "ingress_sequence"),
        ("previous_custody_sequence", "trusted_time_epoch_ns"))
    for name in INSTANCE + ("member_id",):
        profile.text(item[name], 256)
    profile.require(item["sampling_decision"] in {"included", "excluded-by-assignment"})
    context = state.runtime_context(item)
    exact(item, context, MEMBER + ("tee_measurement_digest", "runtime_identity_digest"))
    publication = state.one("policy_shadow_generation_publications", **identity(item, INSTANCE + ("assignment_envelope_digest", "member_ordinal")))
    handoffs.generation(state, publication)
    profile.require(publication["generation_id_digest"] == item["generation_id_digest"] and publication["custody_sequence"] == publication["ingress_sequence"] == 0)
    head = state.one("policy_canary_custody_heads", optional=True, **identity(item, HEAD))
    previous = 0 if head is None else head["custody_sequence"]
    profile.require(item["custody_sequence"] == previous + 1 and item["previous_custody_sequence"] == previous
        and item["previous_custody_head_digest"] == (publication["custody_high_water_digest"] if head is None else head["custody_head_digest"])
        and (head is None or item["ingress_sequence"] > head["ingress_sequence"])
        and item["resulting_custody_head_digest"] == db._policy_canary_custody_head_digest(item))
    checked = state.runtime("custody_evidence", item, "custody_evidence", db._candidate_authority_signed_record(item, current_prefix="custody_evidence"))
    apply_verification(item, checked, interval=True)
    maximum_age = db._candidate_authority_int("maximum custody age", observation_window(context)["maximumEvidenceAgeNanos"], minimum=1)
    profile.require(0 <= item["issued_at_epoch_ns"] - item["trusted_time_epoch_ns"] <= maximum_age)
    item["created_transition_digest"] = state.transition(event_type="policy.custody_evidence.verified", entity_kind="custody_evidence",
        entity_id=item["custody_evidence_envelope_digest"], entity_revision=item["custody_sequence"],
        state_digest=item["resulting_custody_head_digest"], previous_state_digest=item["previous_custody_head_digest"], actor_id=actor,
        evidence={"immutableRetrievalProofDigest": item["immutable_retrieval_proof_digest"], "ingressSequence": item["ingress_sequence"],
            "verificationReceiptDigest": item["verification_receipt_digest"]}, created_at_epoch_ns=item["issued_at_epoch_ns"])
    state.put("policy_canary_custody_evidence", item)
    state.put("policy_canary_custody_heads", {**identity(item, HEAD), "custody_sequence": item["custody_sequence"],
        "custody_head_digest": item["resulting_custody_head_digest"], "custody_evidence_envelope_digest": item["custody_evidence_envelope_digest"],
        "ingress_sequence": item["ingress_sequence"], "updated_at_epoch_ns": item["issued_at_epoch_ns"]}, replace=True)
    return item


def ingress(state, value):
    from catchplate import db
    item = record(value, db._POLICY_CANARY_INGRESS_OBSERVATION_FIELDS)
    profile.text(item.pop("actor_id"), 1024)
    integers(item, ("assignment_revision", "membership_revision", "member_ordinal", "ingress_sequence"), ("observed_at_epoch_ns",))
    for name in INSTANCE + ("member_id",):
        profile.text(item[name], 256)
    profile.require(item["sampling_decision"] in {"included", "excluded-by-assignment"}
        and item["accounting_outcome"] in {"evaluated", "dropped", "error", "excluded", "transport-excluded"})
    excluded = item["sampling_decision"] == "excluded-by-assignment"
    profile.require(excluded == (item["accounting_outcome"] == "excluded")
        and (not excluded or (item["request_commitment_digest"] is not None and item["unavailable_marker_digest"] is None)))
    context = state.runtime_context(item)
    exact(item, context, RUNTIME)
    window = observation_window(context)
    payload = wire(item, "ingress")
    facts = db._policy_shadow_ingress_facts_state("controlled ingress", payload, assignment_payload_digest=item["assignment_payload_digest"],
        assignment_revision=item["assignment_revision"], ingress_sequence=item["ingress_sequence"],
        observed_at_epoch_ns=item["observed_at_epoch_ns"], observation_window=window)
    accounting = payload["accountingOutcome"]
    profile.require(type(accounting) is dict and accounting.get("status") == item["accounting_outcome"])
    status, unavailable = accounting["status"], None
    if status in {"evaluated", "transport-excluded"}:
        profile.require(set(accounting) == {"status"})
    elif status in {"dropped", "error"}:
        profile.require(set(accounting) == {"status", "reason", "unavailableMarkerSha256"})
        unavailable = profile.digest(accounting["unavailableMarkerSha256"])
    else:
        profile.require(set(accounting) == {"status", "reason"} and accounting["reason"] == "deterministic-assignment-sampling")
    facts_unavailable = facts["unavailable_marker_digest"]
    profile.require(item["sampling_decision"] == payload["samplingDecision"] and item["request_commitment_digest"] == facts["request_commitment_digest"]
        and item["unavailable_marker_digest"] == (unavailable or facts_unavailable)
        and (unavailable is None or facts_unavailable is None or unavailable == facts_unavailable)
        and (facts["state"] != "captured" or payload["samplingDecision"] == facts["sampling_decision"]))
    if facts["state"] == "captured":
        profile.require(all(item[name] is not None for name in CUSTODY_REFERENCE))
        held = state.one("policy_canary_custody_evidence", custody_evidence_envelope_digest=item["custody_evidence_envelope_digest"],
            custody_evidence_payload_digest=item["custody_evidence_payload_digest"], verification_receipt_digest=item["custody_verification_receipt_digest"])
        exact(item, held, MEMBER + INSTANCE + ("runtime_identity_digest", "ingress_sequence", "request_commitment_digest", "sampling_decision"))
        profile.require(item["custody_request_commitment_digest"] == item["request_commitment_digest"]
            and held["generation_id_digest"] == item["custody_generation_id_digest"] and held["request_binding_digest"] == item["custody_request_binding_digest"]
            and held["opening_spill_receipt_digest"] == item["custody_opening_spill_receipt_digest"] and held["trusted_time_epoch_ns"] == item["observed_at_epoch_ns"])
        reverify(state, held, current=True)
    else:
        profile.require(all(item[name] is None for name in CUSTODY_REFERENCE))
    first = db._candidate_authority_int("first ingress sequence", window["firstIngressSequence"], minimum=1)
    profile.require(window["startsAtUnixNanos"] <= item["observed_at_epoch_ns"] < window["endsAtUnixNanos"])
    observing(state, item)
    previous_rows = state.matching("policy_canary_ingress_observations", **identity(item, INSTANCE))
    previous = max(previous_rows, key=lambda row: row["ingress_sequence"]) if previous_rows else None
    profile.require(item["ingress_sequence"] == (first if previous is None else previous["ingress_sequence"] + 1)
        and (previous is None or item["observed_at_epoch_ns"] >= previous["observed_at_epoch_ns"]))
    apply_verification(item, state.runtime("ingress_observation", item, "ingress", db._candidate_authority_signed_record(item, current_prefix="ingress")), interval=True)
    profile.require(item["observed_at_epoch_ns"] <= item["issued_at_epoch_ns"])
    state.put("policy_canary_ingress_observations", item)
    return item
