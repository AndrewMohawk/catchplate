"""Native READY provenance from real complete-root-authenticated intake rows."""
from serverware import authority_policy_canary as p
from serverware import authority_policy_native_activation as profile
from serverware import authority_policy_canary_native_readiness as readiness
from serverware import authority_transition_policy_canary_native_readiness as derivation


def ready_payload(core, result_sha256):
    p.require(type(core["designatedReadyRevision"]) is int
        and core["designatedReadyRevision"] == core["predecessorCanaryRevision"] + 1
        and 0 < core["designatedReadyRevision"] < 2**63 - 1)
    return {"apiVersion": profile.READY, "canaryId": core["canaryId"], "assignmentSha256": core["assignmentSha256"],
        "previousRevision": core["predecessorCanaryRevision"], "previousStateSha256": core["predecessorCanaryStateSha256"],
        "revision": core["designatedReadyRevision"], "readinessCoreSha256": p.sha256(p.canonical(core)),
        "readinessResultSha256": result_sha256, "expiresAtUnixNanos": core["expiresAtUnixNanos"]}


def ready_row(value):
    p.require(type(value) is dict and set(value) == profile.READY_FIELDS)
    result = profile.canonical_original(value["readiness_result_original"], readiness.MAX_RESULT)
    p.require(result["apiVersion"] == readiness.RESULT and result["coreSha256"] == p.sha256(p.canonical(result["core"]))
        and result["okForAction"] is False and result["activationApprovalConsumed"] is False and result["automaticRetryAllowed"] is False)
    core = result["core"]
    actual = ready_payload(core, p.sha256(p.canonical(result)))
    p.require(profile.canonical_original(value["ready_original"], 16384) == actual
        and value["ready_state_digest"] == p.sha256(p.canonical(actual)) and value["canary_id"] == core["canaryId"]
        and value["ready_revision"] == core["designatedReadyRevision"] and value["expires_at_epoch_ns"] == core["expiresAtUnixNanos"])
    for name in ("readiness_record_sha256", "configuration_digest", "activation_policy_sha256", "transition_digest"):
        p.digest(value[name])
    p.epoch(value["created_at_epoch_ns"]); p.identifier(value["readiness_request_id"])
    return result, actual


def readiness_predecessor(state, core):
    head = state.one("policy_canary_heads", canary_id=core["canaryId"])
    predecessor = {"canary_id": core["canaryId"], "head_revision": core["predecessorCanaryRevision"],
        "head_state_digest": core["predecessorCanaryStateSha256"], "status": "sealing"}
    p.require(all(head[name] == value for name, value in predecessor.items()))
    native_head = state.one(profile.HEAD_TABLE, optional=True, canary_id=core["canaryId"])
    if native_head is not None:
        row = state.one(profile.READY_TABLE, canary_id=core["canaryId"])
        retained, _ = ready_row(row)
        p.require(native_head["source_profile"] == "native-policy-activation/v1" and native_head["status"] == "ready"
            and native_head["head_revision"] == row["ready_revision"] and native_head["head_state_digest"] == row["ready_state_digest"]
            and native_head["predecessor_revision"] == head["head_revision"] and native_head["predecessor_state_digest"] == head["head_state_digest"]
            and retained["core"] == core)
    return predecessor


def retained_readiness(state, request_id):
    row = state.one(p.TABLE, request_id=request_id)
    p.row_original(row)
    batch = p.batch(row["batch_original"])
    result = p.result(profile.canonical_original(row["result_original"], p.MAX_RESULT))
    p.require(len(batch["events"]) == result["accepted"] == len(result["results"]) == 1)
    event, outcome = batch["events"][0], result["results"][0]
    request = readiness.request(event["record"])
    p.require(event["kind"] == outcome["kind"] == "readiness" and outcome["recordSha256"] == p.sha256(p.canonical(request)))
    original = profile.canonical_original(outcome["storedOriginal"], readiness.MAX_RESULT)
    p.require(row["canary_id"] == request["canary_id"] and original["recordSha256"] == outcome["recordSha256"])
    derivation.revalidate_retained(state, request=request, original=original)
    return row, request, original


def associated_intent(state, values):
    from serverware import db
    bound = profile.intent(values["request"])
    row, request, result = retained_readiness(state, bound["readinessRequestId"])
    core = result["core"]
    p.require(bound["canaryId"] == row["canary_id"] and bound["readinessResultSha256"] == p.sha256(p.canonical(result))
        and bound["readinessCoreSha256"] == result["coreSha256"] and bound["trustCheckpoint"] == core["trustCheckpoint"]
        and bound["readyStateSha256"] == p.sha256(p.canonical(ready_payload(core, bound["readinessResultSha256"])))
        and bound["issuedAtUnixNanos"] == core["issuedAtUnixNanos"] and bound["expiresAtUnixNanos"] == core["expiresAtUnixNanos"])
    generation = state.one("policy_shadow_generation_publications", canary_id=bound["canaryId"],
        generation_publication_envelope_digest=bound["generationPublicationEnvelopeSha256"])
    publication = db.loads(generation["generation_publication_payload_json"], None)
    p.require(generation["generation_id_digest"] == bound["generationId"]
        and generation["assignment_envelope_digest"] == core["assignmentSha256"]
        and publication["custody"]["publicationRevision"] == bound["publicationBefore"]["revision"]
        and any(member["generationId"] == bound["generationId"] and member["instance_id"] == generation["instance_id"]
            and member["boot_id"] == generation["boot_id"] for member in core["memberEvidence"]))
    before, after = bound["publicationBefore"], bound["publicationAfter"]
    high, identity = core["currentPublication"], core["policyIdentity"]
    p.require(before["policySha256"] == high["policy_hash"] and before["policySequence"] == high["sequence"]
        and before["rollbackEpoch"] == high["rollback_epoch"] and after["policySha256"] == identity["candidatePolicySha256"]
        and after["policySequence"] == identity["candidatePolicySequence"] and after["rollbackEpoch"] == identity["rollbackEpoch"])
    policy = profile.validate_policy(values["activation_policy"])
    p.require(policy["issuedAtEpochNs"] <= state.now < policy["expiresAtEpochNs"]
        and {"canaryId": core["canaryId"], "assignmentSha256": core["assignmentSha256"]} in policy["canaries"]
        and bound["expiresAtUnixNanos"] <= policy["expiresAtEpochNs"]
        and bound["expiresAtUnixNanos"] - bound["issuedAtUnixNanos"] <= policy["maximumActivationNanos"])
    retained = state.one(profile.READY_TABLE, optional=True, canary_id=bound["canaryId"])
    if retained is not None:
        p.require(retained["configuration_digest"] == values["control_plane_configuration_digest"]
            and retained["activation_policy_sha256"] == p.sha256(p.canonical(policy))
            and retained["readiness_request_id"] == row["request_id"]
            and retained["readiness_record_sha256"] == result["recordSha256"]
            and retained["readiness_result_original"] == p.canonical(result).decode("ascii"))
    assignment = state.one("policy_canary_assignments", canary_id=bound["canaryId"])
    assigned = db.loads(assignment["assignment_payload_json"], None)
    return row, result, generation, assigned
