"""Actual protected prepare/read/claim, with no contact or uncertainty reset."""
from dataclasses import dataclass
from types import MappingProxyType

from catchplate import authority_policy_canary as intake
from catchplate import authority_policy_canary_delivery as profile
from catchplate import authority_policy_canary_delivery_policy as policy
from catchplate import authority_transition_core as core
from catchplate import authority_transition_quota as shared


def _selected(context, table, key):
    selected = context.exact(table, key)
    row = None if not selected["present"] else shared._row(selected, "canary delivery " + table)
    if row is not None:
        if table in profile.TABLES: profile.row_original(table, row)
        elif table == intake.TABLE: intake.row_original(row)
    return selected, row


def _key(signed):
    return profile.head_id(signed["deploymentId"], signed["canaryId"], signed["instanceId"])


@dataclass(frozen=True, slots=True)
class DeliveryKernel:
    operation: str
    permits_empty_mutation: bool = False

    @property
    def handler(self):
        return "catchplate_policy_authority_" + self.operation.replace(".", "_")

    @property
    def program_id(self):
        return core.transition_program_id(self.operation, self.handler)

    def queries(self, *, arguments, database_now, request_digest):
        del database_now
        values = profile.arguments(self.operation, arguments, typed=True)
        request, signed = values["request"], values["native_evidence"]["statement"]
        prepared = self.operation == profile.OP_PREPARE
        count = len(profile.parts(signed["slotId"], request["httpOriginal"])) if prepared else request["partCount"]
        result = [shared._query(operation=self.operation, name="slot", table=profile.SLOTS,
            key={"id": signed["slotId"]}, require_absence=prepared),
            shared._query(operation=self.operation, name="head", table=profile.HEADS, key={"id": _key(signed)}),
            shared._query(operation=self.operation, name="intake", table=intake.TABLE, key={"request_id": signed["slotId"]})]
        for ordinal in range(count):
            result.append(shared._query(operation=self.operation, name="part_" + str(ordinal), table=profile.PARTS,
                key={"slot_id": signed["slotId"], "ordinal": ordinal}, require_absence=prepared))
        result.append(shared._audit_query(self.operation, request_digest))
        profile.require(sum(item.maximum_rows for item in result) <= profile.LIMITS["queryRows"])
        return tuple(result)

    def transition(self, context):
        from catchplate import authority_policy_canary_delivery_completion as completion
        values = profile.arguments(self.operation, context.arguments, typed=True)
        signed, request = values["native_evidence"]["statement"], values["request"]
        admission = context.canary_delivery_admission
        profile.require(type(admission) is policy._Admission)
        now, stamp = shared._database_epoch_ns(context.database_now), context.database_now.isoformat()
        admission.verify(self.operation, values, now)
        slot_selected, slot = _selected(context, profile.SLOTS, {"id": signed["slotId"]})
        head_selected, head = _selected(context, profile.HEADS, {"id": _key(signed)})
        _, committed = _selected(context, intake.TABLE, {"request_id": signed["slotId"]})
        effects = []
        if self.operation == profile.OP_PREPARE:
            profile.require(slot is None and committed is None)
            if head is None:
                profile.require(request["expectedHeadSha256"] is None)
                sequence = 1
            else:
                profile.require(head["status"] == "consumed" and head["sequence"] < 2**63 - 1
                    and request["expectedHeadSha256"] == profile.sha256(profile.row_original(profile.HEADS, head)),
                    "unresolved delivery head cannot expire, reset or be bypassed")
                sequence = head["sequence"] + 1
            original = request["httpOriginal"]
            prepared = profile.http_original(original)["nativeEvidence"]["statement"]
            profile.require(prepared["issuedAtEpochNs"] <= now < prepared["expiresAtEpochNs"])
            parts = profile.parts(signed["slotId"], original)
            slot = {"id": signed["slotId"], "head_id": _key(signed), "deployment_id": signed["deploymentId"],
                "canary_id": signed["canaryId"], "instance_id": signed["instanceId"], "holder_id": signed["holderId"],
                "native_boot_id": signed["bootId"], "key_id": signed["keyId"], "delivery_assignment_digest": signed["purposeAssignmentSha256"],
                "intake_assignment_digest": prepared["purposeAssignmentSha256"], "canary_assignment_digest": signed["canaryAssignmentSha256"],
                "canary_boot_id": signed["canaryBootId"], "configuration_digest": values["control_plane_configuration_digest"],
                "http_sha256": signed["httpSha256"], "http_byte_count": len(original.encode("ascii")), "part_count": len(parts),
                "status": "prepared", "prepare_request_digest": context.request_digest,
                "prepare_evidence_original": profile.canonical(values["native_evidence"]).decode("ascii"),
                "claim_request_digest": None, "claim_evidence_original": None, "prepare_completion_sha256": None,
                "read_completion_sha256": None, "intake_request_digest": None, "intake_result_sha256": None,
                "issued_at_epoch_ns": prepared["issuedAtEpochNs"], "expires_at_epoch_ns": prepared["expiresAtEpochNs"],
                "created_at": stamp, "updated_at": stamp}
            head = {"id": _key(signed), "deployment_id": signed["deploymentId"], "canary_id": signed["canaryId"],
                "instance_id": signed["instanceId"], "sequence": sequence, "slot_id": slot["id"], "status": "prepared", "updated_at": stamp}
            # Exact original first belongs to this same atomic slot commit;
            # no partially inserted part confers a completed preparation.
            effects.append(core.mutation(operation=self.operation, selected=slot_selected, row=slot))
            for row in parts:
                selected = context.exact(profile.PARTS, {"slot_id": row["slot_id"], "ordinal": row["ordinal"]})
                profile.require(selected["present"] is False)
                effects.append(core.mutation(operation=self.operation, selected=selected, row=row))
            effects.append(core.mutation(operation=self.operation, selected=head_selected, row=head))
        elif slot is None:
            profile.require(self.operation == profile.OP_RECOVER and committed is None)
            original = None
            # Unknown remains an authenticated absence observation only. It
            # neither releases the current head nor permits another contact.
            for ordinal in range(request["partCount"]):
                profile.require(context.exact(profile.PARTS, {"slot_id": signed["slotId"], "ordinal": ordinal})["present"] is False)
        else:
            admission.require_slot_reader(slot, signed, now)
            profile.require(slot["http_sha256"] == request["httpSha256"] and slot["part_count"] == request["partCount"]
                and slot["expires_at_epoch_ns"] == signed["originalExpiresAtEpochNs"] and head is not None)
            rows = [_selected(context, profile.PARTS, {"slot_id": slot["id"], "ordinal": ordinal})[1]
                for ordinal in range(slot["part_count"])]
            original = profile.reassemble(slot, rows)
            if slot["status"] != "consumed":
                profile.require(head["slot_id"] == slot["id"] and head["status"] == slot["status"] and committed is None)
            else:
                profile.require(committed is not None and committed["request_digest"] == slot["intake_request_digest"]
                    and profile.sha256(committed["result_original"].encode("ascii")) == slot["intake_result_sha256"])
            if self.operation == profile.OP_CLAIM:
                profile.require(slot["status"] == head["status"] == "prepared" and head["slot_id"] == slot["id"]
                    and slot["issued_at_epoch_ns"] <= now < slot["expires_at_epoch_ns"]
                    and slot["configuration_digest"] == values["control_plane_configuration_digest"]
                    and request["slotSha256"] == profile.sha256(profile.row_original(profile.SLOTS, slot))
                    and request["headSha256"] == profile.sha256(profile.row_original(profile.HEADS, head)))
                completion.verify_claim_originals(values, slot=slot, head=head, http_original=original, admission=admission, now=now)
                slot = {**slot, "status": "claimed", "claim_request_digest": context.request_digest,
                    "claim_evidence_original": profile.canonical(values["native_evidence"]).decode("ascii"),
                    "prepare_completion_sha256": profile.sha256(request["prepareCompletionOriginal"].encode("ascii")),
                    "read_completion_sha256": profile.sha256(request["readCompletionOriginal"].encode("ascii")), "updated_at": stamp}
                head = {**head, "status": "claimed", "updated_at": stamp}
                effects.extend((core.mutation(operation=self.operation, selected=slot_selected, row=slot),
                    core.mutation(operation=self.operation, selected=head_selected, row=head)))
        observation = {"slotOriginal": None if slot is None else profile.row_original(profile.SLOTS, slot).decode("ascii"),
            "headOriginal": None if head is None else profile.row_original(profile.HEADS, head).decode("ascii"),
            "httpOriginal": original, "intakeOriginal": None if committed is None else intake.row_original(committed).decode("ascii")}
        event = {"operation": self.operation, "requestId": signed["requestId"], "slotId": signed["slotId"], "httpSha256": signed["httpSha256"],
            "status": "unknown" if slot is None else slot["status"], "nativeEvidenceSha256": profile.sha256(profile.canonical(values["native_evidence"]))}
        audits, audit_digest, replay = shared._audit_mutations(context, event_type=self.operation, actor_type="native",
            actor_id=signed["holderId"], event=event)
        profile.require(not replay)
        effects.extend(audits)
        result = profile.result({"ok": True, "operation": self.operation, "requestDigest": context.request_digest,
            "auditEventDigest": audit_digest, "idempotentReplay": False, "status": event["status"], "observation": observation})
        profile.require(0 < len(effects) <= profile.LIMITS["mutations"])
        # Charge bounded original processing as well as emitted mutations.
        # Each of the at most two historical root verifications separately
        # retains the real root engine's unchanged metric limits.
        work = 128 + 4 * len(effects) + (len(profile.canonical(values)) + 1023) // 1024
        profile.require(work <= profile.LIMITS["workUnits"])
        return core.KernelTransition(mutations=tuple(effects), result=result, work_units=work)


def require_claimed(state, values):
    from catchplate.authority_transition_policy_canary_state import State
    profile.require(type(state) is State)
    signed = values["native_evidence"]["statement"]
    selected = state.matching(profile.SLOTS, id=signed["requestId"])
    heads = state.matching(profile.HEADS, id=_key(signed))
    profile.require(len(selected) == len(heads) == 1, "intake has no exact prior protected delivery claim")
    slot, head = selected[0], heads[0]
    profile.row_original(profile.SLOTS, slot); profile.row_original(profile.HEADS, head)
    original = profile.canonical({"apiVersion": intake.HTTP_SCHEMA, "batchOriginal": values["batch_original"],
        "nativeEvidence": values["native_evidence"]}).decode("ascii")
    profile.require(slot["status"] == head["status"] == "claimed" and head["slot_id"] == slot["id"]
        and slot["head_id"] == head["id"] and slot["http_sha256"] == profile.sha256(original.encode("ascii"))
        and slot["http_byte_count"] == len(original.encode("ascii")) and slot["holder_id"] == signed["holderId"]
        and slot["native_boot_id"] == signed["bootId"] and slot["key_id"] == signed["keyId"]
        and slot["intake_assignment_digest"] == signed["purposeAssignmentSha256"]
        and slot["canary_assignment_digest"] == signed["canaryAssignmentSha256"] and slot["canary_boot_id"] == signed["canaryBootId"]
        and slot["configuration_digest"] == values["control_plane_configuration_digest"]
        and slot["issued_at_epoch_ns"] == signed["issuedAtEpochNs"] <= state.now < signed["expiresAtEpochNs"] == slot["expires_at_epoch_ns"])
    return slot, head


def consume(state, values, result, request_digest):
    slot, head = require_claimed(state, values)
    stamp = state.database_now.isoformat()
    state.put(profile.SLOTS, {**slot, "status": "consumed", "intake_request_digest": request_digest,
        "intake_result_sha256": profile.sha256(profile.canonical(result)), "updated_at": stamp}, replace=True)
    state.put(profile.HEADS, {**head, "status": "consumed", "updated_at": stamp}, replace=True)


KERNELS = MappingProxyType({operation: DeliveryKernel(operation) for operation in profile.OPERATIONS})
