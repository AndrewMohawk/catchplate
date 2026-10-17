"""Atomic hardware-authorized request and distinct-person static rotation approval.

Only the source-fixed public candidate is reviewed. Its historic execution
window supplies no authority: every request/decision consumes a fresh actual
assertion. The existing protected approval aggregate is changed only on
insertion, matching the generic approval family's retained-row accounting.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import math
import time
from types import MappingProxyType

from catchplate import authority_static_credential_rotation_approval as profile
from catchplate import authority_static_credential_rotate as rotation
from catchplate import authority_transition_core as core
from catchplate import authority_transition_quota as shared
from catchplate import authority_transition_webauthn as assertions
from catchplate import authority_transition_oauth_activation as hardware


def _epoch(value):
    profile.require(type(value) is str)
    instant = datetime.fromisoformat(value)
    profile.require(instant.tzinfo is not None and instant.utcoffset() == timezone.utc.utcoffset(instant))
    return shared._database_epoch_ns(instant)


def _stamp(value):
    return datetime.fromtimestamp(value // 1_000_000_000, timezone.utc).replace(
        microsecond=value % 1_000_000_000 // 1000).isoformat()


def _role(context, actor, allowed):
    rotation._actor(actor)
    row = shared._row(context.exact("rbac_role_bindings", {"subject_id": actor}), "current static rotation approval role")
    raw = row.get("roles_json")
    profile.require(type(raw) is str)
    roles = json.loads(raw)
    profile.require(profile.canonical(roles).decode("ascii") == raw)
    if type(roles) is dict:
        roles = roles.get("roles")
    profile.require(row.get("subject_id") == actor and row.get("status") == "active"
        and type(roles) is list and all(type(role) is str for role in roles)
        and bool(set(roles).intersection(allowed)), "Current static rotation approval role is required")


def _approval_id(operation, values, request_digest):
    return values["approval_id"] if operation == profile.OP_DECIDE else core.deterministic_uuid(
        operation=operation, request_digest=request_digest, purpose="static-credential-rotation-approval")


@dataclass(frozen=True, slots=True)
class StaticCredentialRotationApprovalKernel:
    operation: str
    permits_empty_mutation: bool = False

    @property
    def handler(self):
        return "catchplate_policy_authority_credential_static_rotation_approval_" + (
            "request" if self.operation == profile.OP_REQUEST else "decide")

    @property
    def program_id(self):
        return core.transition_program_id(self.operation, self.handler)

    def queries(self, **kwargs):
        raise core.TransitionKernelError("Static rotation approval requires locally verified fresh hardware evidence")

    def queries_with_evidence(self, *, arguments, database_now, request_digest, evidence):
        del database_now
        values = profile.arguments(self.operation, arguments, typed=True)
        item_id = _approval_id(self.operation, values, request_digest)
        queries = [shared._query(operation=self.operation, name="static_rotation_approval", table="control_plane_approvals",
            key={"id": item_id}, require_absence=self.operation == profile.OP_REQUEST),
            shared._role_query(self.operation, "actor_role", values["actor_id"])]
        if self.operation == profile.OP_REQUEST:
            queries.append(shared._aggregate_query(self.operation, "approval_capacity", "control-plane-approvals", "global"))
        else:
            queries.append(shared._role_query(self.operation, "requester_role", core.SelectedRowFieldReference(
                "control_plane_approvals", {"id": item_id}, "requester_id")))
        for name, table, field in (("actor_hardware", "webauthn_credentials", "credentialRecordId"),
                ("actor_challenge", "webauthn_challenges", "challengeId")):
            core.require_text(evidence.get(field), field, maximum_bytes=1024)
            queries.append(shared._query(operation=self.operation, name=name, table=table, key={"id": evidence[field]}))
        queries.extend(assertions._trust_queries(self.operation, work=None))
        queries.append(shared._audit_query(self.operation, request_digest))
        return tuple(queries)

    def transition(self, context):
        values = profile.arguments(self.operation, context.arguments, typed=True)
        selected_policy = getattr(context, "static_credential_rotation_policy", None)
        profile.require(type(selected_policy) is dict)
        now = shared._database_epoch_ns(context.database_now)
        profile.verify_request_context(self.operation, values, selected_policy=selected_policy,
            expected_configuration_digest=getattr(context, "static_credential_configuration_digest", None), now_epoch_ns=now)
        request = values["request"]
        retained = profile.candidate(request["candidateOriginal"]) if self.operation == profile.OP_REQUEST else None
        original_row = profile.approval_row(request["approvalOriginal"]) if retained is None else None
        candidate_digest = rotation.approval_payload_digest(retained, candidate=True) if retained is not None else original_row["payload_digest"]
        item_id = _approval_id(self.operation, values, context.request_digest)
        actor = values["actor_id"]
        _role(context, actor, rotation.REQUESTER_ROLES if self.operation == profile.OP_REQUEST else rotation.APPROVER_ROLES)
        evidence = context.verified_webauthn_evidence
        profile.require(type(evidence) is dict)
        hardware._hardware(shared._row(context.exact("webauthn_credentials", {"id": evidence["credentialRecordId"]}),
            "actual static rotation approval hardware"), values["credential_policy"])
        policy = values["credential_policy"]
        profile.require(evidence["rpId"] == policy["rpId"] and evidence["origin"] in policy["origins"]
            and request["issuedAtEpochNs"] <= evidence["verifiedAtEpochNs"] <= now
            < evidence["expiresAtEpochNs"] <= request["expiresAtEpochNs"]
            and evidence["expiresAtEpochNs"] - evidence["verifiedAtEpochNs"]
            <= policy["maxAssertionAgeSeconds"] * 1_000_000_000)
        profile.digest(evidence["verifiedAssertionReceiptDigest"])
        mutations = list(assertions._assertion_mutations(context, {"actor_id": actor}))
        selected = context.exact("control_plane_approvals", {"id": item_id})
        stamp = context.database_now.astimezone(timezone.utc).isoformat()
        if self.operation == profile.OP_REQUEST:
            profile.require(not selected["present"], "Static rotation approval request identity was already used")
            expiry = min(now + request["ttlSeconds"] * 1_000_000_000, retained["request"]["expiresAtEpochNs"])
            expires_at = _stamp(expiry)
            profile.require(now < _epoch(expires_at))
            provenance = {"schema": profile.PROVENANCE_SCHEMA, "candidateSha256": candidate_digest,
                "controlPlaneConfigurationDigest": values["control_plane_configuration_digest"],
                "credentialPolicy": policy, "requestDigest": context.request_digest,
                "requestEvidenceDigest": evidence["verifiedAssertionReceiptDigest"], "decisionDigest": None,
                "decisionEvidenceDigest": None, "consumptionDigest": None, "consumptionEvidenceDigest": None}
            row = {"id": item_id, "action": rotation.ACTION, "resource_id": retained["request"]["credentialId"],
                "payload_digest": candidate_digest, "status": "pending", "requester_id": actor,
                "requested_at": stamp, "expires_at": expires_at, "request_json": profile.approval_request(retained, candidate=True),
                "approved_by": None, "approved_at": None, "consumed_by": None, "consumed_at": None,
                "decision_note": None, "approver_webauthn_credential_id": None}
            mutations.append(shared._aggregate_update(context, kind="control-plane-approvals", partition="global",
                live_delta=1, active_delta=1, next_sequence_delta=1, minimum_expiry_epoch_ns=_epoch(expires_at)))
        else:
            row = shared._row(selected, "actual static rotation approval")
            profile.require(profile.canonical(row) == profile.canonical(original_row)
                and row["id"] == item_id and row["requester_id"] != actor,
                "Static rotation approval target changed or already has a decision")
            requested_at, expiry = _epoch(row["requested_at"]), _epoch(row["expires_at"])
            profile.require(requested_at <= now < request["expiresAtEpochNs"] <= expiry,
                "Static rotation approval decision crossed its original expiry")
            _role(context, row["requester_id"], rotation.REQUESTER_ROLES)
            provenance = profile.provenance(row["approval_authn"])
            profile.require(provenance["candidateSha256"] == candidate_digest and provenance["credentialPolicy"] == policy
                and all(provenance[name] is None for name in ("decisionDigest", "decisionEvidenceDigest", "consumptionDigest", "consumptionEvidenceDigest")))
            provenance = {**provenance, "decisionDigest": context.request_digest,
                "decisionEvidenceDigest": evidence["verifiedAssertionReceiptDigest"]}
            row = {**row, "status": "approved" if values["decision"] == "approve" else "denied",
                "approved_by": actor, "approved_at": stamp if values["decision"] == "approve" else None,
                "approver_webauthn_credential_id": evidence["credentialRecordId"]}
        row = {**row, "approval_authn": profile.canonical(provenance).decode("ascii")}
        profile.provenance(row["approval_authn"])
        mutations.append(core.mutation(operation=self.operation, selected=selected, row=row))
        audit, audit_digest, replay = shared._audit_mutations(context, event_type=self.operation,
            actor_type="admin", actor_id=actor,
            event={"schema": "catchplate.staticCredentialRotationApprovalAudit/v1", "operation": self.operation,
                "requestDigest": context.request_digest, "approvalId": item_id, "actorId": actor,
                "candidateSha256": candidate_digest, "request": json.loads(row["request_json"]),
                "provenance": provenance, "decision": values.get("decision")})
        profile.require(not replay, "Static rotation approval audit identity was already used")
        return core.KernelTransition(mutations=tuple(mutations) + audit,
            result={"ok": True, "operation": self.operation, "requestDigest": context.request_digest,
                "auditEventDigest": audit_digest, "idempotentReplay": False,
                "approval": {**shared._control_public(row), "request": json.loads(row["request_json"])},
                "candidateSha256": candidate_digest, "auditState": "controlled_pending"}, work_units=1024)


KERNELS = MappingProxyType({operation: StaticCredentialRotationApprovalKernel(operation) for operation in profile.OPERATIONS})


def _original_copy(value, work, depth=0, ancestors=frozenset()):
    """Family-local finite JSON copy; do not narrow valid public metadata.

    The generic SQL copier intentionally excludes floats and NUL-bearing text.
    Static metadata/name originals do not. Meter these literal finite values
    against the same invocation work, without changing that generic profile.
    """
    from catchplate.authority_query_read_work import MAX_JSON_DEPTH

    profile.require(depth <= MAX_JSON_DEPTH)
    kind = type(value)
    if kind is float:
        profile.require(math.isfinite(value))
        work.charge(json_nodes=1, input_bytes=len(profile.canonical(value)))
        return value
    if kind is str:
        # Stored metadata may contain escaped surrogates. ASCII JSON preserves
        # them exactly; the generic UTF-8 string admission is intentionally not
        # this purpose's domain. Charge a lower bound before allocating bytes.
        work.charge(json_nodes=1, input_bytes=len(value) + 2)
        work.charge(input_bytes=len(profile.canonical(value)) - len(value) - 2)
        return value
    if value is None or kind in (bool, int):
        work.prepare_encoding(value)
        return value
    profile.require(kind in (dict, list, tuple) and id(value) not in ancestors)
    work.charge(json_nodes=1, input_bytes=2 + max(0, len(value) - 1) + (len(value) if kind is dict else 0))
    branch = ancestors | {id(value)}
    if kind is dict:
        result = {}
        for key, item in value.items():
            profile.require(type(key) is str)
            result[_original_copy(key, work, depth + 1, branch)] = _original_copy(item, work, depth + 1, branch)
        return result
    items = [_original_copy(item, work, depth + 1, branch) for item in value]
    return tuple(items) if kind is tuple else items


def _verify_static_rotation_plan(*, operation, payload, arguments, verified_native_evidence,
        verified_webauthn_evidence, rotation_policy, configuration_digest, deadline_ns, now_epoch_ns, work):
    """Replay these three source programs only, after actual plan/root admission."""
    from catchplate import authority_audit_capacity as capacity
    from catchplate import authority_challenge_retention as retention
    from catchplate.authority_query_read_work import _ValidationWork

    is_rotate = operation == rotation.OPERATION
    profile.digest(configuration_digest)
    profile.require(operation in profile.OPERATIONS or is_rotate)
    profile.require(type(work) is _ValidationWork and type(payload) is dict and type(arguments) is dict
        and type(verified_webauthn_evidence) is dict and type(rotation_policy) is dict
        and (type(verified_native_evidence) is dict if is_rotate else verified_native_evidence is None))
    core.require_integer(deadline_ns, "original static deadline", minimum=1, maximum=2**63 - 1)
    core.require_integer(now_epoch_ns, "current static verifier time", minimum=1, maximum=2**63 - 1)
    expires = None

    def check():
        current = time.time_ns()
        profile.require(time.monotonic_ns() < deadline_ns and now_epoch_ns <= current
            and (expires is None or current < expires), "Static plan crossed its original execution bound")

    def equal(left, right):
        first, second = _original_copy(left, work), _original_copy(right, work)
        profile.require(profile.canonical(first) == profile.canonical(second),
            "Static plan differs from held originals or source effects")

    check()
    owned = _original_copy({"payload": payload, "arguments": arguments, "native": verified_native_evidence,
        "hardware": verified_webauthn_evidence, "policy": rotation_policy, "configurationDigest": configuration_digest}, work)
    plan, evidence, native = owned["payload"], owned["hardware"], owned["native"]
    contract = rotation if is_rotate else profile
    values = contract.arguments(operation, owned["arguments"], typed="businessIntent" in owned["arguments"])
    typed, measured, projection = plan["typedRequest"], plan["measuredPlan"], plan["authorizationProjection"]
    profile.require(typed["operation"] == measured["operation"] == operation)
    equal(contract.arguments(operation, typed["arguments"], typed=True), values)
    equal(plan["webauthnEvidence"], evidence)
    if is_rotate:
        equal(plan["staticCredentialRotationEvidence"], native)
    else:
        profile.require("staticCredentialRotationEvidence" not in plan)
    request_digest = contract.request_digest(operation, values)
    profile.require(typed["requestDigest"] == measured["requestDigest"] == evidence["requestDigest"] == request_digest
        and measured["deadlineMonotonicNs"] == deadline_ns)
    expires = measured["deadlineEpochNs"]
    core.require_integer(expires, "signed static expiry", minimum=1, maximum=2**63 - 1)
    selected, mutations = plan["selectedBusinessRows"], plan["mutationPlan"]
    # The real assertion computation always proposes this exact challenge CAS.
    # Its literal signed timestamp is a replay cutoff, NOT a new DB observation.
    work.prepare_scan(mutations)
    challenges = [item for item in mutations if item["table"] == "webauthn_challenges"
        and item["key"] == {"id": evidence["challengeId"]}]
    profile.require(len(challenges) == 1 and challenges[0]["operation"] == "UPDATE"
        and type(challenges[0]["row"]) is dict)
    stamp = challenges[0]["row"]["used_at"]
    cutoff = _epoch(stamp)
    request = values["request"]
    issued = request["executionIssuedAtEpochNs" if is_rotate else "issuedAtEpochNs"]
    request_expiry = request["executionExpiresAtEpochNs" if is_rotate else "expiresAtEpochNs"]
    profile.require(issued <= projection["createdAtEpochNs"] <= cutoff <= now_epoch_ns
        and evidence["verifiedAtEpochNs"] <= cutoff and now_epoch_ns < expires
        and projection["expiresAtEpochNs"] == expires <= request_expiry
        and expires <= evidence["expiresAtEpochNs"])
    if is_rotate:
        profile.require(native["statement"]["issuedAtEpochNs"] <= cutoff
            and expires <= native["statement"]["expiresAtEpochNs"])
    check()
    context = core.KernelContext(operation, typed["arguments"], tuple(selected), datetime.fromisoformat(stamp),
        request_digest, verified_webauthn_evidence=evidence, static_credential_rotation_policy=owned["policy"],
        verified_static_credential_rotation_evidence=native, static_credential_configuration_digest=owned["configurationDigest"])
    if is_rotate:
        from catchplate.authority_transition_static_credential_rotate import StaticCredentialRotateKernel
        kernel = StaticCredentialRotateKernel()
    else:
        kernel = StaticCredentialRotationApprovalKernel(operation)
    transition = kernel.transition(context)
    check()
    expanded = retention.expand_mutations(context, transition.mutations, work=work)
    expected = capacity._finalize_capacity(context, expanded, work=work)
    expected = sorted(expected, key=lambda item: (item["table"], item["keyDigest"], item["operation"]))
    equal(mutations, expected)
    equal(plan["expectedResult"], transition.result)
    queries = capacity.add_capacity_query(operation, kernel.queries_with_evidence(arguments=typed["arguments"],
        database_now=context.database_now, request_digest=request_digest, evidence=evidence))
    profile.require(measured["workUnits"] == capacity.transition_work_units(operation=operation,
        query_work_units=sum(query.work_units for query in queries), kernel_work_units=transition.work_units,
        mutations=tuple(expected)))
    check()


def verify_static_rotation_approval_plan(*, operation, payload, arguments, verified_webauthn_evidence,
        rotation_policy, configuration_digest, deadline_ns, now_epoch_ns, work):
    profile.require(operation in profile.OPERATIONS)
    _verify_static_rotation_plan(operation=operation, payload=payload, arguments=arguments, verified_native_evidence=None,
        verified_webauthn_evidence=verified_webauthn_evidence, rotation_policy=rotation_policy,
        configuration_digest=configuration_digest, deadline_ns=deadline_ns, now_epoch_ns=now_epoch_ns, work=work)
