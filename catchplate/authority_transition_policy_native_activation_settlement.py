"""Definite native publication settlement; timeout/absence cannot unlock a hold."""
from datetime import timezone
from catchplate import authority_policy_canary as p
from catchplate import authority_policy_native_activation as profile
from catchplate import authority_native_activation_hold as hold
from catchplate import authority_native_activation_publication as publication
from catchplate import authority_transition_policy_native_activation_state as originals
from catchplate import authority_transition_core as core
from catchplate import authority_transition_quota as shared


def retained(state, value):
    selected = state.one(profile.PREPARATION_TABLE, canary_id=value["request"]["canaryId"])
    prepared = profile.prepared(profile.canonical_original(selected["prepared_original"]))
    ready = state.one(profile.READY_TABLE, canary_id=selected["canary_id"])
    readiness, ready_payload = originals.ready_row(ready)
    active_hold = hold.original(state.one(hold.TABLE, scope=hold.SCOPE))
    p.require(selected["activation_id"] == prepared["activationId"] == value["request"]["activationId"]
        and selected["replay_id"] == prepared["replayId"] == value["request"]["replayId"]
        and selected["prepared_sha256"] == p.sha256(p.canonical(prepared)) == active_hold["prepared_sha256"]
        and active_hold["phase"] == "held" and active_hold["activation_id"] == prepared["activationId"]
        and active_hold["prepare_request_digest"] == selected["request_digest"]
        and active_hold["configuration_digest"] == prepared["controlPlaneConfigurationSha256"] == value["control_plane_configuration_digest"]
        and selected["approval_id"] == value["approval_id"] and selected["requester_id"] == value["actor_id"]
        and profile.canonical_original(prepared["readinessOriginal"]) == readiness
        and profile.canonical_original(prepared["readyOriginal"]) == ready_payload
        and prepared["activationPolicySha256"] == p.sha256(p.canonical(value["activation_policy"])))
    for name in profile.INTENT_FIELDS - {"apiVersion"}:
        p.require(value["request"][name] == prepared[name])
    head = state.one(profile.HEAD_TABLE, canary_id=selected["canary_id"])
    p.require(head["status"] == "ready" and head["head_revision"] == ready_payload["revision"]
        and head["head_state_digest"] == prepared["readyStateSha256"] and head["head_revision"] < 2**63 - 1)
    assignment = state.one("policy_canary_assignments", canary_id=selected["canary_id"])
    p.require(assignment["assignment_envelope_digest"] == prepared["assignmentSha256"]
        and assignment["assignment_payload_digest"] == prepared["assignmentPayloadSha256"])
    assigned = profile.canonical_original(assignment["assignment_payload_json"])
    return selected, prepared, readiness, ready_payload, active_hold, assigned


def transition(context, state, value):
    from catchplate import db
    from catchplate import authority_transition_policy_native_activation as approval
    phase = context.operation.removeprefix(profile.PREFIX)
    p.require(phase in {"record-inclusion", "finalize"} and context.verified_webauthn_evidence is None)
    preparation, prepared, readiness, ready, active_hold, assigned = retained(state, value)
    approval_selected = context.exact("control_plane_approvals", {"id": value["approval_id"]})
    row = shared._row(approval_selected, "native consumed approval")
    authn = approval.provenance(row)
    p.require(row["status"] == "consumed" and row["requester_id"] == row["consumed_by"] == value["actor_id"]
        and row["approved_by"] not in (None, value["actor_id"]) and row["action"] == profile.ACTION and row["resource_id"] == profile.RESOURCE
        and p.canonical(row).decode("ascii") == value["approval_original"] == prepared["approvalOriginal"]
        and authn["consumptionDigest"] == preparation["request_digest"] and authn["credentialPolicy"] == value["credential_policy"])
    shared._require_role(context, subject_id=row["approved_by"], required_role=profile.ROLE)
    audits = approval.completed_audits(context, value, {"request", "decide", "consume"})
    p.require(state.one(profile.FINALIZATION_TABLE, optional=True, canary_id=prepared["canaryId"]) is None)
    event = {"apiVersion": "catchplate.nativePolicyActivationAudit/v1", "operation": context.operation,
        "requestDigest": context.request_digest, "activationId": prepared["activationId"], "approvalId": value["approval_id"],
        "preparedSha256": preparation["prepared_sha256"]}
    audit_mutations, audit_digest, replay = shared._audit_mutations(context, event_type=context.operation,
        actor_type="admin", actor_id=value["actor_id"], event=event)
    p.require(not replay)
    if phase == "record-inclusion":
        p.require(preparation["publication_original"] is None)
        native = profile.native_request(value["native_request"])
        request, response = (profile.canonical_original(native[name], profile.MAX_NATIVE)
            for name in ("prepareRequestOriginal", "prepareResponseOriginal"))
        p.require(native["requestId"] == prepared["activationId"] and native["replayId"] == prepared["replayId"]
            and request["operation"] == response["operation"] == profile.PREFIX + "consume"
            and response["schema"] == profile.RESPONSE_SCHEMA and response["result"]["preparedOriginal"] == preparation["prepared_original"]
            and response["result"]["preparedSha256"] == preparation["prepared_sha256"]
            and response["result"]["requestDigest"] == preparation["request_digest"])
        request_sha = p.sha256(p.canonical(native))
        publication.verify(value["publication_original"], prepared=prepared, request_sha256=request_sha,
            assignment=assigned, policy=value["activation_policy"])
        state.put(profile.PREPARATION_TABLE, {**preparation, "publication_original": value["publication_original"],
            "publication_sha256": p.sha256(value["publication_original"].encode("ascii")), "publication_request_sha256": request_sha,
            "publication_audit_id": shared._audit_identity(context.operation, context.request_digest), "publication_audit_digest": audit_digest}, replace=True)
    else:
        p.require(preparation["publication_original"] is not None)
        publication.verify(preparation["publication_original"], prepared=prepared, request_sha256=preparation["publication_request_sha256"],
            assignment=assigned, policy=value["activation_policy"])
        published_audit = shared._row(context.exact("metadata_audit_outbox", {"id": preparation["publication_audit_id"]}), "publication audit")
        p.require(published_audit["status"] == "audited" and published_audit["audited_at"] is not None
            and published_audit["last_error"] is None and published_audit["event_digest"] == preparation["publication_audit_digest"]
            and published_audit["event_type"] == profile.PREFIX + "record-inclusion")
        p.digest(published_audit["audit_event_hash"])
        published_event = profile.canonical_original(published_audit["event_json"])
        p.require(published_event["activationId"] == prepared["activationId"] and published_event["approvalId"] == value["approval_id"]
            and published_event["preparedSha256"] == preparation["prepared_sha256"]
            and published_audit["event_digest"] == core.framed_digest("catchplate.metadataAuditOutboxEvent/v1", published_audit["event_json"].encode("ascii")))
        audits.append(published_audit)
        high = state.one("policy_high_water", scope="active")
        before, after = prepared["publicationBefore"], prepared["publicationAfter"]
        p.require(high["policy_hash"] == before["policySha256"] and high["sequence"] == before["policySequence"]
            and high["rollback_epoch"] == before["rollbackEpoch"])
        canary = state.one("policy_canaries", canary_id=prepared["canaryId"])
        artifact = state.one("policy_candidate_artifacts", artifact_envelope_digest=canary["artifact_envelope_digest"])
        p.require(artifact["policy_hash"] == after["policySha256"] and artifact["policy_sequence"] == after["policySequence"]
            and artifact["rollback_epoch"] == after["rollbackEpoch"] and artifact["policy_id"] == high["policy_id"]
            and artifact["scope"] == "active" and state.one("policy_publications", optional=True, policy_hash=after["policySha256"]) is None)
        # The protected hold excluded all conflicting authority mutations after
        # PREPARE. These actual retained completed outbox rows are captured by
        # this transaction; a caller's audit digest is never enough.
        final = {"apiVersion": "catchplate.nativePolicyActivationFinalization/v1", "activationId": prepared["activationId"],
            "canaryId": prepared["canaryId"], "preparedSha256": preparation["prepared_sha256"],
            "publicationSha256": preparation["publication_sha256"], "publicationAfter": after,
            "auditsSha256": p.sha256(p.canonical(audits)), "finalizedAtUnixNanos": state.now}
        final_sha = p.sha256(p.canonical(final))
        timestamp = context.database_now.astimezone(timezone.utc).isoformat()
        state.put(profile.FINALIZATION_TABLE, {"canary_id": prepared["canaryId"], "activation_id": prepared["activationId"],
            "prepared_sha256": preparation["prepared_sha256"], "publication_sha256": preparation["publication_sha256"],
            "policy_id": high["policy_id"], "policy_hash": after["policySha256"], "policy_sequence": after["policySequence"],
            "rollback_epoch": after["rollbackEpoch"], "artifact_envelope_digest": artifact["artifact_envelope_digest"],
            "activation_policy_original": p.canonical(value["activation_policy"]).decode("ascii"),
            "audit_originals_json": p.canonical(audits).decode("ascii"), "finalization_original": p.canonical(final).decode("ascii"),
            "finalization_digest": final_sha, "request_digest": context.request_digest,
            "audit_outbox_id": shared._audit_identity(context.operation, context.request_digest), "audit_event_digest": audit_digest,
            "finalized_at_epoch_ns": state.now})
        state.put("policy_high_water", {**high, "policy_hash": after["policySha256"], "sequence": after["policySequence"],
            "rollback_epoch": after["rollbackEpoch"], "updated_at": timestamp}, replace=True)
        state.put("policy_publications", {"policy_hash": after["policySha256"], "scope": "active", "policy_id": high["policy_id"],
            "sequence": after["policySequence"], "rollback_epoch": after["rollbackEpoch"], "status": "committed",
            "previous_policy_hash": before["policySha256"], "created_at": timestamp, "committed_at": timestamp, "updated_at": timestamp})
        head = state.one(profile.HEAD_TABLE, canary_id=prepared["canaryId"])
        state.put(profile.HEAD_TABLE, {**head, "status": "active", "head_revision": head["head_revision"] + 1,
            "head_state_digest": final_sha, "updated_at_epoch_ns": state.now}, replace=True)
        state.put(hold.TABLE, hold.original({**active_hold, "phase": "published", "publication_sha256": preparation["publication_sha256"],
            "finalization_digest": final_sha}), replace=True)
    mutations = [core.mutation(operation=context.operation, selected=context.exact(table, tables_key(table, changed)), row=changed)
        for (table, _), changed in state.changed.items()]
    result = {"ok": True, "operation": context.operation, "requestDigest": context.request_digest, "auditEventDigest": audit_digest,
        "idempotentReplay": False, "approval": db.row_to_control_plane_approval(row), "preparedOriginal": preparation["prepared_original"],
        "preparedSha256": preparation["prepared_sha256"], "readyOriginal": p.canonical(ready).decode("ascii")}
    return core.KernelTransition(mutations=tuple(mutations) + audit_mutations, result=result, work_units=state.work_units + 256)


def tables_key(table, row):
    from catchplate import authority_policy_canary_tables
    return authority_policy_canary_tables.key(table, row)


def committed_policy(state, high, published):
    """Actual protected native association, never a legacy status-only alias."""
    matches = state.matching(profile.FINALIZATION_TABLE, policy_id=high["policy_id"], policy_hash=high["policy_hash"],
        policy_sequence=high["sequence"], rollback_epoch=high["rollback_epoch"])
    p.require(len(matches) <= 1)
    if not matches:
        return None
    final = matches[0]
    preparation = state.one(profile.PREPARATION_TABLE, canary_id=final["canary_id"])
    prepared = profile.prepared(profile.canonical_original(preparation["prepared_original"]))
    ready, ready_payload = originals.ready_row(state.one(profile.READY_TABLE, canary_id=final["canary_id"]))
    native_head = state.one(profile.HEAD_TABLE, canary_id=final["canary_id"])
    legacy_head = state.one("policy_canary_heads", canary_id=final["canary_id"])
    p.require(native_head["source_profile"] == "native-policy-activation/v1" and native_head["status"] == "active"
        and native_head["head_revision"] == ready_payload["revision"] + 1 and native_head["head_state_digest"] == final["finalization_digest"]
        and legacy_head["status"] == "sealing" and legacy_head["head_revision"] == native_head["predecessor_revision"] == ready_payload["previousRevision"]
        and legacy_head["head_state_digest"] == native_head["predecessor_state_digest"] == ready_payload["previousStateSha256"]
        and final["activation_id"] == prepared["activationId"] == preparation["activation_id"]
        and final["prepared_sha256"] == preparation["prepared_sha256"] == p.sha256(p.canonical(prepared))
        and final["publication_sha256"] == preparation["publication_sha256"] == p.sha256(preparation["publication_original"].encode("ascii"))
        and prepared["readinessOriginal"] == p.canonical(ready).decode("ascii")
        and published["previous_policy_hash"] == prepared["publicationBefore"]["policySha256"])
    assigned = profile.canonical_original(state.one("policy_canary_assignments", canary_id=final["canary_id"])["assignment_payload_json"])
    policy = profile.canonical_original(final["activation_policy_original"], 16384)
    p.require(p.sha256(p.canonical(policy)) == prepared["activationPolicySha256"])
    receipt = publication.verify(preparation["publication_original"], prepared=prepared,
        request_sha256=preparation["publication_request_sha256"], assignment=assigned, policy=policy)
    audits = profile.completed_audit_originals(final["audit_originals_json"])
    p.require(type(audits) is list and len(audits) == 4 and len({row["id"] for row in audits}) == 4
        and all(row["status"] == "audited" and row["audited_at"] is not None and row["audit_event_hash"] is not None for row in audits))
    from catchplate import authority_transition_policy_native_activation as approval
    consumed = profile.canonical_original(prepared["approvalOriginal"])
    provenance = approval.provenance(consumed)
    p.require(consumed["id"] == preparation["approval_id"] and consumed["status"] == "consumed"
        and consumed["requester_id"] == consumed["consumed_by"] == preparation["requester_id"]
        and consumed["approved_by"] not in (None, consumed["requester_id"])
        and provenance["consumptionDigest"] == preparation["request_digest"])
    expected_audits = {profile.PREFIX + phase: shared._audit_identity(profile.PREFIX + phase, provenance[name])
        for phase, name in (("request", "requestDigest"), ("decide", "decisionDigest"), ("consume", "consumptionDigest"))}
    expected_audits[profile.PREFIX + "record-inclusion"] = preparation["publication_audit_id"]
    p.require({row["event_type"]: row["id"] for row in audits} == expected_audits)
    for row in audits:
        p.digest(row["audit_event_hash"])
        event = profile.canonical_original(row["event_json"])
        p.require(row["last_error"] is None and event["activationId"] == prepared["activationId"]
            and event["approvalId"] == consumed["id"]
            and row["event_digest"] == core.framed_digest("catchplate.metadataAuditOutboxEvent/v1", row["event_json"].encode("ascii")))
        if row["event_type"] == profile.PREFIX + "record-inclusion":
            p.require(row["event_digest"] == preparation["publication_audit_digest"] and event["preparedSha256"] == preparation["prepared_sha256"])
    terminal = profile.canonical_original(final["finalization_original"])
    p.require(terminal == {"apiVersion": "catchplate.nativePolicyActivationFinalization/v1", "activationId": prepared["activationId"],
        "canaryId": prepared["canaryId"], "preparedSha256": final["prepared_sha256"], "publicationSha256": final["publication_sha256"],
        "publicationAfter": prepared["publicationAfter"], "auditsSha256": p.sha256(p.canonical(audits)),
        "finalizedAtUnixNanos": final["finalized_at_epoch_ns"]} and p.sha256(p.canonical(terminal)) == final["finalization_digest"]
        and receipt["publicationAfter"]["policySha256"] == high["policy_hash"]
        and receipt["publicationAfter"]["policySequence"] == high["sequence"] and receipt["publicationAfter"]["rollbackEpoch"] == high["rollback_epoch"])
    return {**high, "preparation_digest": final["prepared_sha256"], "activation_attempt_id": final["activation_id"],
        "finalization_digest": final["finalization_digest"], "inclusion_identity_set_digest": terminal["auditsSha256"],
        "publication_receipt_payload_digest": p.sha256(p.canonical(receipt)), "consumption_digest": preparation["request_digest"]}
