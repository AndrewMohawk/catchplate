"""Complete native fleet readiness derivation inside authenticated intake.

Missing detailed observations or final seals are implementation prerequisites,
never successful zero-count evidence. The output is retained by the existing
protected intake journal. It does not mutate a legacy Fleet readiness row or
consume activation/human approval authority.
"""
from catchplate import authority_policy_canary as p
from catchplate import authority_policy_canary_native_readiness as profile
from catchplate import authority_policy_canary_native_readiness_counters as counts
from catchplate import authority_transition_policy_canary_current as current
from catchplate.authority_transition_policy_canary_state import exact


def _committed_records(state, canary):
    records = []
    for row in state.rows(p.TABLE):
        if row["canary_id"] != canary:
            continue
        p.row_original(row)
        batch = p.batch(row["batch_original"])
        result = p.result(p.document(row["result_original"].encode("ascii"), p.MAX_RESULT))
        p.require(len(batch["events"]) == len(result["results"]))
        state.charge(len(batch["events"]) + 1)
        for event, outcome in zip(batch["events"], result["results"], strict=True):
            digest = p.sha256(p.canonical(event["record"]))
            p.require(outcome["kind"] == event["kind"] and outcome["recordSha256"] == digest)
            stored = p.document(outcome["storedOriginal"].encode("ascii"), p.MAX_RESULT)
            records.append((event["kind"], event["record"], stored, digest))
    return records


def _final(state, record):
    # These fixed source owners are paired prerequisites, not optional plugins
    # or caller callbacks. Missing implementations refuse the actual request.
    try:
        from catchplate import authority_transition_policy_canary_native_finalization as finalization
    except ImportError as error:
        raise ValueError("native finalization evidence producer is unavailable") from error
    return finalization.validate_readiness_checkpoint(state, record, include_observations=True)


def _details(state, record, compiler, admitted):
    try:
        from catchplate import authority_transition_policy_canary_native_detail as detail
    except ImportError as error:
        raise ValueError("native detailed-observation producer is unavailable") from error
    return detail.readiness_observations(state, record, compiler, admitted=admitted)


def _member(state, checkpoint, compiler, committed):
    from catchplate import db
    admitted = _final(state, checkpoint)
    p.require(type(admitted) is dict and set(admitted) == {"context", "assignment", "load", "publication", "accounting", "seal", "observations"})
    context, assignment, load = (admitted[name] for name in ("context", "assignment", "load"))
    accounting, seal = admitted["accounting"], admitted["seal"]
    p.require(seal is not None and checkpoint["accounting"] == accounting and checkpoint["seal"] == seal,
        "an open cumulative prefix is not native readiness")
    window = assignment["observationWindow"]
    load_row = state.one("policy_canary_load_receipts", canary_id=checkpoint["canary_id"],
        instance_id=checkpoint["instance_id"], boot_id=checkpoint["boot_id"])
    load_verification = state.one("policy_runtime_evidence_verifications",
        verification_receipt_digest=load_row["verification_receipt_digest"])
    start = max(load_verification["verified_at_epoch_ns"], window["startsAtUnixNanos"])
    end = window["endsAtUnixNanos"]
    p.require(load["loadedAtUnixNanos"] <= start < end and end - start >= window["minimumDurationNanos"])
    # The finalization owner verifies the real drain/census and complete chain.
    # Readiness checks its independently authenticated coverage against the
    # ORIGINAL signed observation window; receipt arrival never starts a clock.
    p.require(seal["coverageStartedAtUnixNanos"] <= start and seal["windowEndsAtUnixNanos"] == end
        and seal["sealDeadlineUnixNanos"] == window["sealDeadlineUnixNanos"]
        and end <= seal["admissionClosedAtUnixNanos"] <= seal["drainedAtUnixNanos"] <= accounting["observedAtUnixNanos"]
        <= window["sealDeadlineUnixNanos"])
    from catchplate import authority_transition_policy_canary_native_finalization as finalization
    heartbeats = finalization.heartbeat_originals(state, checkpoint["heartbeat"])
    heartbeats.sort(key=lambda record: record["evidence"]["statement"]["heartbeatSequence"])
    p.require(heartbeats and p.sha256(p.canonical(heartbeats[-1])) == checkpoint["heartbeat_sha256"])
    previous, previous_digest = None, accounting["generationId"]
    for sequence, heartbeat in enumerate(heartbeats, 1):
        statement = heartbeat["evidence"]["statement"]
        observed = statement["observedAtUnixNanos"]
        lower = start if previous is None else max(previous, start)
        p.require(statement["heartbeatSequence"] == sequence and statement["previousHeartbeatSha256"] == previous_digest
            and (previous is None or observed >= previous)
            and max(0, min(observed, end) - min(lower, end)) <= window["maximumHeartbeatGapNanos"])
        previous, previous_digest = observed, p.sha256(p.canonical(heartbeat))
    p.require(previous >= end, "native heartbeat originals do not cover the whole original observation window")
    originals = accounting["originals"]
    p.require(type(originals) is list and len(originals) == accounting["originalCount"] <= 64)
    opening = []
    for receipt in originals:
        event = p.document(bytes(receipt["canonical_event_bytes"]), 16384)
        if type(event) is list and len(event) == 4 and event[0] in {"catchplate.policyShadowIngressAdmissionEvent/v1", "catchplate.nativeShadowIngressAdmissionEvent/v1"}:
            opening.append(receipt)
    # The exact admitted-event marker is joined to the real receipt codec; no
    # event count supplied by a checkpoint can stand in for this list.
    p.require(len(opening) == accounting["counters"]["admitted"] > 0)
    observations = _details(state, checkpoint, compiler, admitted)
    p.require(type(observations) is tuple and len(observations) == len(opening))
    state.charge(64 + 32 * len(observations))
    first = window["firstIngressSequence"]
    p.require([value["ingressSequence"] for value in observations] == list(range(first, first + len(observations)))
        and [value["ingress_sequence"] for value in opening] == list(range(first, first + len(opening))))
    contract = state.one("policy_canary_assignments", canary_id=checkpoint["canary_id"])
    aggregate = counts.aggregate(observations, contract, compiler)
    analysis = db.loads(compiler["analysis_payload_json"], None)
    counts.requirements(aggregate, assignment, analysis["authorityAnalysis"], analysis["pilotRestrictions"],
        member=True, duration=end - start)
    evaluated = sum(value["result"]["status"] == "evaluated" for value in observations)
    p.require(accounting["counters"]["active-pre-dispatch-terminal"] + accounting["counters"]["response-terminal-appended"]
        == evaluated and not any(accounting["counters"][name] for name in
            ("unsupported-required-ingress", "cleanup-quarantined", "failure")), "native final lifecycle is incomplete")
    member = {name: context[name] for name in ("member_ordinal", "member_id", "instance_id", "boot_id", "membership_root_digest")}
    member.update(checkpointSha256=p.sha256(p.canonical(checkpoint)), generationId=accounting["generationId"],
        finalLedgerHeadSha256=accounting["lastHeadSha256"], finalLedgerEventOrdinal=accounting["lastEventOrdinal"],
        receiptRootSha256=accounting["receiptRootSha256"], eventRootSha256=accounting["eventRootSha256"],
        observationsRootSha256=db._policy_shadow_merkle_root([(value["ingressSequence"], value["recordSha256"]) for value in observations]),
        sealSha256=p.sha256(p.canonical(seal)), coverageStartedAtUnixNanos=start, coverageClosedAtUnixNanos=end,
        aggregateCounters=aggregate)
    return member, assignment


def apply(state, value):
    return _derive(state, value)


def revalidate_retained(state, *, request, original):
    """Recompute an actual retained result without replacing its original clock.

    The caller obtains both originals from one authenticated consumed intake
    row. No supplied result or a successful prior status can confer permission.
    """
    p.require(type(original) is dict and original.get("apiVersion") == profile.RESULT
        and original["recordSha256"] == p.sha256(p.canonical(request)))
    computed = _derive(state, request, retained_core=original["core"])
    p.require(computed == original, "retained native readiness differs from current complete authority")
    return computed


def _derive(state, value, *, retained_core=None):
    from catchplate import db
    from catchplate import authority_policy_canary_native_opening as opening
    value = profile.request(value)
    policy = value["readiness_policy"]
    p.require(policy["deploymentId"] == state.statement["deploymentId"]
        and policy["issuedAtEpochNs"] <= state.now < policy["expiresAtEpochNs"])
    assignment_row = state.one("policy_canary_assignments", canary_id=value["canary_id"])
    exact(value, assignment_row, ("assignment_envelope_digest", "assignment_payload_digest"))
    state.static("canary_assignment", assignment_row, "assignment",
        db._candidate_authority_signed_record(assignment_row, current_prefix="assignment"), persist=False)
    assignment = opening.assignment_payload(db.loads(assignment_row["assignment_payload_json"], None))
    canary = state.one("policy_canaries", canary_id=value["canary_id"])
    p.require(all(canary[name] == assignment_row[name] for name in set(canary) & set(assignment_row)
        if name not in {"created_transition_digest"}))
    signed_members = db._validate_policy_assignment_contract({**canary, **assignment_row})
    head = state.one("policy_canary_heads", canary_id=value["canary_id"])
    if retained_core is not None:
        from catchplate import authority_transition_policy_native_activation_state as activation
        head = activation.readiness_predecessor(state, retained_core)
    p.require(head["status"] == "sealing" and type(head["head_revision"]) is int and 0 < head["head_revision"] < 2**63 - 1)
    compiler = state.one("policy_compiler_authority_analyses", canary_id=value["canary_id"],
        assignment_envelope_digest=value["assignment_envelope_digest"], assignment_payload_digest=value["assignment_payload_digest"])
    state.static("compiler_analysis", compiler, "analysis",
        db._candidate_authority_signed_record(compiler, current_prefix="analysis"), persist=False)
    analysis = db.loads(compiler["analysis_payload_json"], None)
    p.require(analysis["policyIdentity"] == assignment["policyIdentity"]
        and analysis["expectedLoadedSnapshots"] == assignment["expectedLoadedSnapshots"])
    members = sorted(state.matching("policy_canary_assignment_members", assignment_envelope_digest=value["assignment_envelope_digest"]),
        key=lambda row: row["member_ordinal"])
    p.require(1 <= len(members) == canary["expected_instance_count"] == len(signed_members) == len(assignment["fleet"]["members"]) <= profile.MAX_FLEET
        and [member["member_ordinal"] for member in members] == list(range(1, len(members) + 1)))
    for member, signed in zip(members, signed_members, strict=True):
        p.require(member["member_ordinal"] == signed["ordinal"] and member["member_leaf_digest"] == signed["member_leaf_digest"]
            and member["member_canonical_json"] == signed["member_json"]
            and all(member[name] == signed[name] for name in ("member_id", "instance_id", "boot_id"))
            and member["attestation_receipt_envelope_digest"] == signed["attestation"]["envelopeDigest"])
    state.charge(64 + 32 * len(members))
    records = _committed_records(state, value["canary_id"])
    p.require(retained_core is not None or not any(kind == "readiness" and record.get("apiVersion") == profile.REQUEST
        and stored.get("core", {}).get("predecessorCanaryStateSha256") == head["head_state_digest"]
        for kind, record, stored, _ in records), "native readiness already has a retained outcome; inspect, never retry")
    selected, summaries = [], []
    for member in members:
        candidates = [record for kind, record, stored, digest in records if kind == "checkpoint"
            and record.get("apiVersion") == "catchplate.nativeCumulativeCheckpoint/v2"
            and record.get("seal") is not None and record.get("instance_id") == member["instance_id"]
            and record.get("boot_id") == member["boot_id"] and record.get("assignment_envelope_digest") == value["assignment_envelope_digest"]]
        p.require(len(candidates) == 1, "every exact fleet member requires its unique consumed final native seal")
        checkpoint = candidates[0]
        summary, actual_assignment = _member(state, checkpoint, compiler, records)
        p.require(actual_assignment == assignment and all(summary[name] == member[name] for name in
            ("member_ordinal", "member_id", "instance_id", "boot_id", "membership_root_digest")))
        selected.append(checkpoint); summaries.append(summary)
    p.require(any(p.sha256(p.canonical(record)) == value["final_checkpoint_sha256"]
        and record["instance_id"] == value["instance_id"] and record["boot_id"] == value["boot_id"] for record in selected),
        "readiness trigger is not an actual consumed final checkpoint")
    aggregate = counts.merge([member["aggregateCounters"] for member in summaries])
    window = assignment["observationWindow"]
    rates = counts.requirements(aggregate, assignment, analysis["authorityAnalysis"], analysis["pilotRestrictions"],
        member=False, duration=window["endsAtUnixNanos"] - window["startsAtUnixNanos"])
    high = current.committed_policy(state)
    identity = assignment["policyIdentity"]
    p.require(high is not None and high["policy_hash"] == identity["predecessorPolicySha256"]
        and high["sequence"] == identity["predecessorPolicySequence"]
        and high["rollback_epoch"] == canary["predecessor_rollback_epoch"]
        and high["policy_id"] == canary["policy_id"], "native readiness predecessor is not the finalized current publication")
    expires = min(policy["expiresAtEpochNs"], assignment_row["expires_at_epoch_ns"], compiler["expires_at_epoch_ns"],
        state.now + policy["maximumReadinessAgeNanos"])
    issued = state.now
    if retained_core is not None:
        issued = p.epoch(retained_core["issuedAtUnixNanos"])
        original_expiry = p.epoch(retained_core["expiresAtUnixNanos"])
        p.require(issued <= state.now < original_expiry <= expires
            and original_expiry - issued <= policy["maximumReadinessAgeNanos"])
        expires = original_expiry
    p.require(state.now < expires and all(0 <= state.now - item["accounting"]["observedAtUnixNanos"]
        <= window["maximumEvidenceAgeNanos"] for item in selected))
    core = {"apiVersion": profile.CORE, "canaryId": value["canary_id"],
        "assignmentSha256": value["assignment_envelope_digest"], "assignmentPayloadSha256": value["assignment_payload_digest"],
        "predecessorCanaryRevision": head["head_revision"], "predecessorCanaryStateSha256": head["head_state_digest"],
        "designatedReadyRevision": head["head_revision"] + 1, "policyIdentity": identity,
        "compilerAnalysisSha256": compiler["analysis_envelope_digest"], "compilerAnalysisPayloadSha256": compiler["analysis_payload_digest"],
        "authorityAnalysis": analysis["authorityAnalysis"], "pilotRestrictions": analysis["pilotRestrictions"],
        "fleet": assignment["fleet"], "memberEvidence": summaries,
        "memberEvidenceRootSha256": db._policy_shadow_merkle_root([(member["member_ordinal"], p.sha256(p.canonical(member))) for member in summaries]),
        "aggregateCounters": aggregate, "readinessThresholds": assignment["readinessThresholds"], "calculatedRates": rates,
        "responseValidationObligationsRootSha256": assignment["responseValidationObligationsRootSha256"],
        "trustCheckpoint": current.trust_checkpoint(state, issued), "currentPublication": high,
        "readinessPolicySha256": p.sha256(p.canonical(policy)), "issuedAtUnixNanos": issued, "expiresAtUnixNanos": expires}
    result = {"apiVersion": profile.RESULT, "recordSha256": p.sha256(p.canonical(value)),
        "coverage": "complete-native-fleet-readiness-derived", "core": core, "coreSha256": p.sha256(p.canonical(core)),
        "okForAction": False, "activationApprovalConsumed": False, "automaticRetryAllowed": False}
    p.require(len(p.canonical(result)) <= profile.MAX_RESULT)
    return result
