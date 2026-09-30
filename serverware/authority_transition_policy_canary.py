"""One ordered, bounded, all-or-nothing transaction for all twelve evidence kinds."""
from dataclasses import dataclass
from datetime import timezone
from types import MappingProxyType

from serverware import authority_policy_canary as profile
from serverware import authority_policy_canary_tables as tables
from serverware import authority_primary_contract as primary
from serverware import authority_transition_core as core
from serverware import authority_transition_quota as shared
from serverware import authority_transition_policy_canary_membership as membership
from serverware import authority_transition_policy_canary_lifecycle as lifecycle
from serverware import authority_transition_policy_canary_handoff as handoff
from serverware import authority_transition_policy_canary_custody as custody
from serverware import authority_transition_policy_canary_active as active
from serverware import authority_transition_policy_canary_shadow as shadow
from serverware import authority_transition_policy_canary_compiler as compiler
from serverware import authority_transition_policy_canary_delivery as delivery
from serverware import authority_transition_policy_canary_native_opening as native_opening
from serverware import authority_policy_canary_native_opening as opening_profile
from serverware import authority_policy_canary_native_runtime as runtime_profile
from serverware import authority_transition_policy_canary_native_runtime as native_runtime
from serverware import authority_transition_policy_canary_native_heartbeat as native_heartbeat
from serverware import authority_policy_canary_heartbeat_policy as heartbeat_profile
from serverware import authority_policy_canary_native_checkpoint as checkpoint_profile
from serverware import authority_transition_policy_canary_native_checkpoint as native_checkpoint
from serverware import authority_policy_canary_native_cumulative as cumulative_profile
from serverware import authority_transition_policy_canary_native_cumulative as native_cumulative
from serverware.authority_transition_policy_canary_state import State


def _program(values, database_now, request_digest, snapshot):
    from serverware import db
    original = profile.batch(values["batch_original"])
    signed = values["native_evidence"]["statement"]
    state = State(snapshot, original["events"], database_now, signed)
    profile.require(signed["issuedAtEpochNs"] <= state.now < signed["expiresAtEpochNs"])
    profile.require(not state.matching(profile.TABLE, request_id=original["requestId"]),
        "native intake identity already exists; exact inspection does not reenter intake")
    delivery.require_claimed(state, values)
    handlers = {"assignment": membership.assignment, "canary-revision": lifecycle.canary_revision,
        "load-receipt": membership.load_receipt, "runtime-attestation-handoff": handoff.handoff, "custody": custody.custody,
        "ingress": custody.ingress, "active-decision": active.active, "shadow-observation": shadow.shadow,
        "instance-revision": lifecycle.instance_revision, "compiler-analysis": compiler.compiler_analysis}
    results = []
    for event in original["events"]:
        item, kind = event["record"], event["kind"]
        for field, expected in (("instance_id", signed["instanceId"]), ("boot_id", signed["canaryBootId"]),
                ("assignment_envelope_digest", signed["canaryAssignmentSha256"])):
            profile.require(field not in item or item[field] == expected, "native sender cannot select another assigned evidence lane")
        if kind == "custody" and item.get("apiVersion") == heartbeat_profile.RECORD:
            profile.require(len(original["events"]) == 1, "native heartbeat owns one original batch")
            stored = native_heartbeat.apply(state, item)
        elif kind == "custody" and item.get("apiVersion") == opening_profile.SCHEMA:
            profile.require(len(original["events"]) == 1, "native opening owns one indivisible original batch")
            stored = native_opening.apply(state, item)
        elif kind in {"active-decision", "shadow-observation"} and item.get("apiVersion") in {runtime_profile.SCHEMA, runtime_profile.RESPONSE_SCHEMA}:
            profile.require(len(original["events"]) == 1, "native runtime observation owns one indivisible original batch")
            stored = native_runtime.apply(state, item, kind)
        elif kind == "checkpoint" and item.get("apiVersion") == checkpoint_profile.SCHEMA:
            profile.require(len(original["events"]) == 1, "native checkpoint owns one indivisible original batch")
            stored = native_checkpoint.apply(state, item)
        elif kind == "checkpoint" and item.get("apiVersion") == cumulative_profile.SCHEMA:
            profile.require(len(original["events"]) == 1, "native cumulative checkpoint owns one indivisible original")
            stored = native_cumulative.apply(state, item)
        elif kind == "checkpoint":
            stored = db.stage_policy_canary_checkpoint(item, _controlled_state=state)
        elif kind == "readiness":
            stored = db.stage_policy_canary_readiness(item, _controlled_state=state)
        else:
            stored = handlers[kind](state, item)
        results.append({"kind": kind, "recordSha256": profile.sha256(profile.canonical(item)), "storedOriginal": profile.canonical(stored).decode("ascii")})
        state.charge(1)
    event = {"operation": profile.OP_INTAKE, "requestId": original["requestId"], "batchSha256": signed["batchSha256"],
        "canaryId": signed["canaryId"], "instanceId": signed["instanceId"], "purposeAssignmentSha256": signed["purposeAssignmentSha256"],
        "nativeEvidenceSha256": profile.sha256(profile.canonical(values["native_evidence"])), "accepted": len(results)}
    event_json = profile.canonical(event).decode("ascii")
    event_digest = core.framed_digest("serverware.metadataAuditOutboxEvent/v1", event_json.encode("ascii"))
    timestamp = database_now.astimezone(timezone.utc).isoformat()
    state.put("metadata_audit_outbox", {"id": shared._audit_identity(profile.OP_INTAKE, request_digest),
        "event_type": "policy.canary.controlled_evidence.intake", "actor_type": "native", "actor_id": signed["holderId"],
        "event_json": event_json, "event_digest": event_digest, "storage_format_version": 1, "status": "pending",
        "claim_id": None, "claimed_at": None, "attempts": 0, "audited_at": None, "audit_event_hash": None, "last_error": None, "created_at": timestamp})
    result = profile.result({"ok": True, "operation": profile.OP_INTAKE, "requestDigest": request_digest, "auditEventDigest": event_digest,
        "idempotentReplay": False, "accepted": len(results), "results": results})
    row = {"request_id": original["requestId"], "canary_id": signed["canaryId"], "instance_id": signed["instanceId"], "boot_id": signed["canaryBootId"],
        "purpose_assignment_digest": signed["purposeAssignmentSha256"], "canary_assignment_digest": signed["canaryAssignmentSha256"],
        "configuration_digest": values["control_plane_configuration_digest"], "batch_sha256": signed["batchSha256"], "batch_original": values["batch_original"],
        "native_evidence_original": profile.canonical(values["native_evidence"]).decode("ascii"), "request_digest": request_digest,
        "result_original": profile.canonical(result).decode("ascii"), "audit_event_digest": event_digest,
        "issued_at_epoch_ns": signed["issuedAtEpochNs"], "expires_at_epoch_ns": signed["expiresAtEpochNs"], "created_at": timestamp}
    record_original = profile.row_original(row).decode("ascii")
    profile.require(len(profile.canonical({"apiVersion": profile.RESULT_SCHEMA, "requestId": original["requestId"], "batchSha256": signed["batchSha256"],
        "status": "committed", "result": result, "recordOriginal": record_original})) <= profile.MAX_RESPONSE,
        "complete intake acknowledgement exceeds the original response budget")
    state.put(profile.TABLE, row)
    delivery.consume(state, values, result, request_digest)
    return state, result


@dataclass(frozen=True, slots=True)
class CanaryIntakeKernel:
    operation: str = profile.OP_INTAKE
    permits_empty_mutation: bool = False

    @property
    def handler(self):
        return "serverware_policy_authority_policy_canary_evidence_intake"

    @property
    def program_id(self):
        return core.transition_program_id(self.operation, self.handler)

    def queries(self, *, arguments, database_now, request_digest):
        values = profile.arguments(self.operation, arguments, typed=True)
        snapshot = profile.document(values["before_original"].encode("ascii"), profile.MAX_ARGUMENT)
        # This untrusted preflight computes only a closed query program. The
        # planner proves complete before-roots and the kernel repeats it below.
        state, _ = _program(values, database_now, request_digest, snapshot)
        queries = [core.BoundedQuery(query_id=core.query_program_id(self.operation, "complete_population", table), table=table,
            predicates=(), order_by=tuple(core.QueryOrder(name) for name in primary.PRIMARY_KEY_COLUMNS[table]),
            maximum_rows=len(snapshot[table]) + 1, proof_primitive="bounded-limit-plus-one", work_units=len(snapshot[table]) + 1)
            for table in tables.TABLES]
        for ordinal, ((table, identity), row) in enumerate(sorted(state.changed.items())):
            if table not in state.before or identity not in state.before[table]:
                queries.append(shared._query(operation=self.operation, name="new_original_" + str(ordinal), table=table,
                    key=tables.key(table, row), require_absence=True))
        profile.require(sum(query.maximum_rows for query in queries) <= profile.LIMITS["queryRows"],
            "whole canary batch cannot fit its original query budget")
        return tuple(queries)

    def transition(self, context):
        values = profile.arguments(self.operation, context.arguments, typed=True)
        expected = profile.document(values["before_original"].encode("ascii"), profile.MAX_ARGUMENT)
        # The planner has verified complete populations against its actual
        # transaction roots. Compare every original, not a caller row digest.
        actual = {table: sorted((shared._row(selected, "canary " + table) for selected in context.present_rows(table)),
            key=lambda row: profile.canonical(tables.key(table, row))) for table in tables.TABLES}
        profile.require(actual == expected, "native canary prestate changed or was incomplete")
        state, result = _program(values, context.database_now, context.request_digest, actual)
        mutations = []
        # The writer applies the signed array in order. Preserve the actual
        # predecessor/audit insertion order, then publish each coalesced head
        # after every immutable successor it references has been inserted.
        changes = tuple(state.changed.items())
        ordered = tuple(item for item in changes if item[0][0] not in tables.HEAD_TABLES)
        ordered += tuple(item for item in changes if item[0][0] in tables.HEAD_TABLES)
        for (table, _), row in ordered:
            selected = context.exact(table, tables.key(table, row))
            prior = state.before.get(table, {}).get(profile.canonical(tables.key(table, row)))
            profile.require(selected["present"] is (prior is not None) and (prior is None or selected["row"] == prior))
            mutations.append(core.mutation(operation=self.operation, selected=selected, row=row))
        profile.require(0 < len(mutations) <= profile.LIMITS["mutations"])
        return core.KernelTransition(mutations=tuple(mutations), result=result, work_units=state.work_units)


KERNELS = MappingProxyType({profile.OP_INTAKE: CanaryIntakeKernel()})
