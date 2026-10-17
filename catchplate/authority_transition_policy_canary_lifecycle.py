"""Exact signed canary/instance successors; STAGED is not READY authority."""
from catchplate import authority_policy_canary as profile
from catchplate.authority_transition_policy_canary_membership import record, integers
from catchplate.authority_transition_policy_canary_state import exact, apply_verification


def _prepare(value, *, instance):
    from catchplate import db
    fields = db._POLICY_CANARY_INSTANCE_REVISION_FIELDS if instance else db._POLICY_CANARY_REVISION_FIELDS
    item = record(value, fields)
    actor = db._candidate_authority_text("state actor", item.pop("actor_id"), maximum=1024)
    event = db._candidate_authority_text("state event", item.pop("event_type"), maximum=256)
    for name in (("canary_id", "member_id", "instance_id", "boot_id") if instance else ("canary_id",)):
        db._candidate_authority_text(name, item[name], maximum=256)
    integers(item, ("revision", "membership_revision", "member_ordinal") if instance else ("revision",))
    for name in ("previous_revision", "checkpoint_sequence"):
        if item.get(name) is not None:
            db._candidate_authority_int(name, item[name], minimum=1)
    for name in ("created_at_epoch_ns", "observation_started_at_epoch_ns", "sealed_at_epoch_ns", "terminal_at_epoch_ns"):
        if item.get(name) is not None:
            db._candidate_authority_int(name, item[name])
    db._candidate_authority_canonical_json("state envelope", item["state_envelope_json"])
    db._candidate_authority_json("state payload", item["state_payload_json"], item["state_digest"])
    return item, actor, event


def _successor(item, head, transitions, terminals, initial):
    profile.require(item["status"] in set(transitions) | terminals)
    if head is None:
        profile.require(item["revision"] == 1 and item["status"] == initial
            and all(item[name] is None for name in ("previous_revision", "previous_status", "previous_state_digest")))
    else:
        profile.require(item["revision"] == head["head_revision"] + 1 and item["previous_revision"] == head["head_revision"]
            and item["previous_status"] == head["status"] and item["previous_state_digest"] == head["head_state_digest"]
            and item["status"] in transitions.get(head["status"], frozenset()), "canary revision is not its exact legal CAS successor")
    if item["status"] in terminals:
        profile.require(item["terminal_from_status"] == item["previous_status"] and item["terminal_at_epoch_ns"] is not None)
    else:
        profile.require(item["terminal_from_status"] is None and item["terminal_at_epoch_ns"] is None)


def canary_revision(state, value):
    from catchplate import db
    item, actor, event = _prepare(value, instance=False)
    verified = state.static("canary_state", item, "state", db._candidate_authority_signed_record(
        {**item, "actor_id": actor, "event_type": event}, current_prefix="state"))
    apply_verification(item, verified)
    head = state.one("policy_canary_heads", optional=True, canary_id=item["canary_id"])
    _successor(item, head, db._POLICY_CANARY_TRANSITIONS, db._POLICY_CANARY_TERMINAL_STATUSES, "staged")
    state.one("policy_canaries", canary_id=item["canary_id"])
    if item["status"] == "ready":
        readiness = state.one("policy_canary_readiness", canary_id=item["canary_id"], predecessor_canary_revision=item["previous_revision"],
            predecessor_canary_state_digest=item["previous_state_digest"], designated_ready_revision=item["revision"],
            readiness_envelope_digest=item["readiness_envelope_digest"], readiness_payload_digest=item["readiness_payload_digest"])
        exact(item, readiness, ("assignment_envelope_digest", "assignment_payload_digest", "sealed_checkpoint_root_digest", "sealed_instance_set_digest"))
        profile.require(item["previous_status"] == "sealing")
        signed = {name: readiness[name] for name in db._POLICY_CANARY_READINESS_FIELDS if name != "actor_id"}
        state.static("readiness", readiness, "readiness", db._candidate_authority_signed_record(signed, current_prefix="readiness"))
    else:
        profile.require(item["readiness_envelope_digest"] is None and item["readiness_payload_digest"] is None)
    transition = state.transition(event_type=event, entity_kind="canary", entity_id=item["canary_id"], entity_revision=item["revision"],
        state_digest=item["state_digest"], previous_state_digest=item["previous_state_digest"], actor_id=actor,
        evidence={"status": item["status"], "assignmentPayloadDigest": item["assignment_payload_digest"],
            "readinessPayloadDigest": item["readiness_payload_digest"]}, created_at_epoch_ns=item["created_at_epoch_ns"])
    result = {**item, "transition_digest": transition, "transition_entity_kind": "canary", "transition_event_type": event}
    state.put("policy_canary_revisions", result)
    state.put("policy_canary_heads", {"canary_id": item["canary_id"], "head_revision": item["revision"],
        "head_state_digest": item["state_digest"], "status": item["status"], "updated_at_epoch_ns": item["created_at_epoch_ns"]}, replace=True)
    return result


def instance_revision(state, value):
    from catchplate import db
    item, actor, event = _prepare(value, instance=True)
    identity = {name: item[name] for name in ("canary_id", "instance_id", "boot_id")}
    context = state.runtime_context(item, require_load=item["status"] != "assigned")
    exact(item, context, ("fleet_id", "membership_revision", "membership_root_digest", "member_ordinal", "member_id",
        "assignment_envelope_digest", "assignment_payload_digest"))
    state.one("policy_canary_instances", **identity)
    if item["load_receipt_envelope_digest"] is not None:
        exact(item, context, ("load_receipt_envelope_digest", "load_receipt_payload_digest"))
    verified = state.runtime("canary_instance_state", item, "state", db._candidate_authority_signed_record(
        {**item, "actor_id": actor, "event_type": event}, current_prefix="state"))
    apply_verification(item, verified)
    head = state.one("policy_canary_instance_heads", optional=True, **identity)
    _successor(item, head, db._POLICY_CANARY_INSTANCE_TRANSITIONS, db._POLICY_CANARY_INSTANCE_TERMINAL_STATUSES, "assigned")
    if item["status"] in {"sealing", "sealed"}:
        profile.require(item["sealed_at_epoch_ns"] is not None and item["created_at_epoch_ns"] <= item["sealed_at_epoch_ns"])
        checkpoint = state.one("policy_canary_checkpoint_heads", **identity)
        exact(item, checkpoint, ("checkpoint_sequence", "checkpoint_envelope_digest", "checkpoint_payload_digest"))
        if item["status"] == "sealing":
            profile.require(checkpoint["sealed"] == 0, "checkpoint is already sealed")
            state.put("policy_canary_checkpoint_heads", {**checkpoint, "sealed": 1,
                "sealed_at_epoch_ns": item["sealed_at_epoch_ns"], "updated_at_epoch_ns": item["created_at_epoch_ns"]}, replace=True)
        else:
            profile.require(checkpoint["sealed"] == 1)
    entity_id = "/".join(identity.values())
    transition = state.transition(event_type=event, entity_kind="canary_instance", entity_id=entity_id, entity_revision=item["revision"],
        state_digest=item["state_digest"], previous_state_digest=item["previous_state_digest"], actor_id=actor,
        evidence={"status": item["status"], "loadReceiptPayloadDigest": item["load_receipt_payload_digest"],
            "checkpointPayloadDigest": item["checkpoint_payload_digest"]}, created_at_epoch_ns=item["created_at_epoch_ns"])
    result = {**item, "transition_digest": transition, "transition_entity_kind": "canary_instance", "transition_entity_id": entity_id,
        "transition_event_type": event}
    state.put("policy_canary_instance_revisions", result)
    state.put("policy_canary_instance_heads", {**identity, "head_revision": item["revision"], "head_state_digest": item["state_digest"],
        "status": item["status"], "updated_at_epoch_ns": item["created_at_epoch_ns"]}, replace=True)
    return result
