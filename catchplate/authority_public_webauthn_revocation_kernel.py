"""Public aggregate effects from genuine retained prestate, never permission.

The dedicated verifier authenticates the public authorization before the real
planner acquires these rows. Approval consumption and the complete cascade
share one protected transition; there is no pre-consumption in an HTTP writer.
"""
from __future__ import annotations

import hashlib
import json
from datetime import timezone

from catchplate import authority_contract
from catchplate import authority_public_webauthn_revocation as public
from catchplate import authority_transition_core as core
from catchplate import authority_transition_webauthn as legacy
from catchplate.authority_query_read_work import _ValidationWork


def _role_query(name, subject):
    return core.BoundedQuery(query_id=core.query_program_id(public.OPERATION, name, "rbac_role_bindings"),
        table="rbac_role_bindings", predicates=(core.QueryPredicate("subject_id", "eq", subject),),
        order_by=(core.QueryOrder("subject_id"),), maximum_rows=1, absent_key={"subject_id": subject})


def queries(*, arguments, cutoff_us, request_digest, evidence, work):
    public._require(type(work) is _ValidationWork)
    bound = public.binding(evidence) if public.is_public(evidence) else evidence
    public.binding_shape(bound)
    values = legacy._arguments(arguments, work=work)
    if bound["credentialRecordId"] is not None:
        generated = legacy.WebAuthnCredentialRevokeKernel()._queries_with_evidence_at_cutoff(
            arguments=arguments, cutoff_us=cutoff_us, request_digest=request_digest,
            evidence={key: bound[key] for key in ("credentialRecordId", "challengeId")}, work=work)
        work.prepare_copy(generated)
        result = list(generated)
    else:
        result = list(legacy._cascade_queries_at_cutoff(operation=public.OPERATION,
            values=values, cutoff_us=cutoff_us, request_digest=request_digest, work=work))
        # Keep the six complete predicates. No assertion/trust point is made
        # up when the independently signed policy explicitly disables MFA.
        result.append(legacy.authority_complete_query._bind_query(public.OPERATION,
            "pending_trust_publications", arguments=values, cutoff_us=cutoff_us, work=work))
    for name, subject in (("public_requester_role", bound["actorId"]),
            ("public_approver_role", bound["approvedBy"])):
        if subject is not None and subject.startswith("oidc:"):
            result.append(_role_query(name, subject))
    approval_id = bound["approvalId"]
    if approval_id is not None:
        result.append(legacy._exact_query(public.OPERATION, "public_authorizing_approval",
            "control_plane_approvals", approval_id))
        if approval_id not in values["control_plane_approval_ids"]:
            result.append(legacy._exact_query(public.OPERATION, "public_approval_consumption_audit",
                "metadata_audit_outbox", legacy._audit_id(public.OPERATION, request_digest, approval_id, work=work)))
        credential = bound["approvalCredentialRecordId"]
        if credential is not None and credential not in (values["record_id"], bound["credentialRecordId"]):
            result.append(legacy._exact_query(public.OPERATION, "public_approving_credential",
                "webauthn_credentials", credential))
    spec = authority_contract.operation_spec(public.OPERATION)
    public._require(sum(query.maximum_rows for query in result) <= spec["maximumBusinessQueryRows"]
        and sum(query.work_units for query in result) <= spec["maximumBusinessWorkUnits"])
    legacy._prepare_complete_copies(tuple(result), work)
    return core.close_queries(public.OPERATION, tuple(result))


def _current_roles(context, user_id, signed_roles, *, work):
    if not user_id.startswith("oidc:"):
        # Preserve existing static administrator modes. Their current token
        # and role configuration belong to the actual cold HTTP/verifier path.
        return set(signed_roles)
    row = legacy._row(legacy._exact(context, "rbac_role_bindings", {"subject_id": user_id}, work=work), work=work)
    raw = row.get("roles_json")
    public._require(type(raw) is str and len(raw) <= 4096 and row.get("status") == "active")
    work.prepare_scan(raw)
    work.charge(json_nodes=len(raw))
    roles = json.loads(raw)
    public._require(type(roles) is list and len(roles) <= 32
        and all(type(role) is str and 1 <= len(role) <= 128 for role in roles))
    work.prepare_encoding(roles)
    public._require(core.canonical_bytes(roles).decode("ascii") == raw)
    return set(roles)


def _credential_policy(row, policy, user_id):
    public._require(row.get("user_id") == user_id and row.get("revoked_at") is None,
        "public revocation assertion credential is not the current actor's")
    actual = row.get("authenticator_class")
    classes = {actual} if type(actual) is str else set()
    if "yubikey" in classes:
        classes.add("hardware")
    allowed = policy.get("allowedAuthenticatorClasses")
    if allowed is not None:
        public._require(bool(classes & set(allowed)), "public revocation credential class is not allowed")
    if policy.get("requireHardwareAttestation") is True:
        public._require(row.get("attestation_trusted") in (True, 1)
            and bool(classes & {"hardware", "yubikey"}),
            "public revocation requires an actually trusted hardware credential")


def transition(context, values, *, work):
    public._require(type(work) is _ValidationWork and type(context) is core.KernelContext)
    evidence = context.verified_webauthn_evidence
    public.shape(evidence)
    actor, policy, approval = evidence["actor"], evidence["policy"], evidence["approval"]
    public._require(actor["userId"] == values["actor_id"])
    target = legacy._row(legacy._exact(context, "webauthn_credentials", {"id": values["record_id"]}, work=work), work=work)
    roles = _current_roles(context, actor["userId"], actor["roles"], work=work)
    public._require(bool(roles & {"admin", "approver"})
        and (target.get("user_id") == actor["userId"] or "admin" in roles),
        "public revocation lacks current self/admin authority")
    if evidence["assertion"] is not None:
        signer = legacy._row(legacy._exact(context, "webauthn_credentials",
            {"id": evidence["assertion"]["credentialRecordId"]}, work=work), work=work)
        _credential_policy(signer, policy["credentialPolicy"], actor["userId"])
    credential_id = target.get("credential_id")
    public._text(credential_id, 4096)
    work.prepare_utf8(credential_id)
    work.charge(hashes=1, input_bytes=len(credential_id.encode("utf-8")))
    payload = {"credential_record_id": values["record_id"],
        "credential_id_sha256": "sha256:" + hashlib.sha256(credential_id.encode("utf-8")).hexdigest(),
        "credential_user_id": target.get("user_id"), "label": target.get("label"),
        "attestation_root_sha256": target.get("attestation_root_sha256"), "reason": values["reason"]}
    public._require(public.original_sha256(payload, work=work) == evidence["payloadDigest"])
    audit = values["audit_event"]
    public._require(type(audit) is dict and audit.get("payload_digest") == evidence["payloadDigest"]
        and all(audit.get(key) == value for key, value in payload.items()))
    consumed_id, approval_mutations = None, ()
    if approval is not None:
        from catchplate import authority_public_revocation_approval as approval_profile
        consumed_id = approval["id"]
        selected = legacy._exact(context, "control_plane_approvals", {"id": consumed_id}, work=work)
        row = legacy._row(selected, work=work)
        provenance_raw = row.get("approval_authn")
        public._require(type(provenance_raw) is str and len(provenance_raw.encode("utf-8")) <= 16 * 1024)
        work.prepare_scan(provenance_raw)
        work.charge(json_nodes=len(provenance_raw))
        provenance = json.loads(provenance_raw)
        public._object(provenance, frozenset({"schema", "policy", "requestDigest", "requestEvidenceDigest",
            "decisionDigest", "decisionEvidenceDigest"}))
        public._require(provenance["schema"] == approval_profile.PROVENANCE_SCHEMA and provenance["policy"] == policy
            and core.canonical_bytes(provenance).decode("ascii") == provenance_raw)
        for digest in (provenance["requestDigest"], provenance["decisionDigest"]):
            public.core.require_digest(digest, "public approval actual request")
        for evidence_digest in (provenance["requestEvidenceDigest"], provenance["decisionEvidenceDigest"]):
            if policy["mfaRequired"]:
                public.core.require_digest(evidence_digest, "public approval actual assertion")
            else:
                public._require(evidence_digest is None)
        public._require(public.original_sha256(row, work=work) == approval["originalSha256"])
        public._require(row.get("action") == public.OPERATION and row.get("resource_id") == values["record_id"]
            and row.get("payload_digest") == evidence["payloadDigest"] and row.get("requester_id") == actor["userId"]
            and row.get("approved_by") == approval["approvedBy"] and row.get("approved_by") != actor["userId"]
            and row.get("status") == "approved" and legacy._utc(row.get("expires_at"), "approval expiry", work=work) > context.database_now
            and row.get("approver_webauthn_credential_id") == approval["credentialRecordId"])
        public._require("admin" in _current_roles(context, approval["approvedBy"], ("admin",), work=work))
        if policy["mfaRequired"]:
            public._require(approval["credentialRecordId"] is not None)
        if approval["credentialRecordId"] is not None:
            credential = legacy._row(legacy._exact(context, "webauthn_credentials",
                {"id": approval["credentialRecordId"]}, work=work), work=work)
            _credential_policy(credential, policy["credentialPolicy"], approval["approvedBy"])
        now = context.database_now.astimezone(timezone.utc).isoformat()
        work.prepare_copy(row)
        approval_mutations = (legacy._mutation(context, selected,
            {**row, "status": "consumed", "consumed_by": actor["userId"], "consumed_at": now}, work=work),
            legacy._audit_mutation(context, subject=consumed_id, event_type="control_plane.approval.consumed",
                actor_type="admin", actor_id=actor["userId"], event={"approval_id": consumed_id,
                    "action": public.OPERATION, "resource_id": values["record_id"],
                    "payload_digest": evidence["payloadDigest"], "approved_by": approval["approvedBy"]}, work=work))
    cascade = legacy._plan_credential_cascade(context, values, work=work, consumed_approval_id=consumed_id)
    mutations = {(item["table"], item["keyDigest"]): item for item in (*cascade.mutations, *approval_mutations)}
    if evidence["assertion"] is not None:
        nested = core.KernelContext(operation=context.operation, arguments=context.arguments,
            selected_rows=context.selected_rows, database_now=context.database_now,
            request_digest=context.request_digest, verified_webauthn_evidence=evidence["assertion"],
            query_reads=context.query_reads)
        for item in legacy._assertion_mutations(nested, values, work=work):
            key = item["table"], item["keyDigest"]
            if key in mutations:
                previous = mutations[key]
                public._require(item["table"] == "webauthn_credentials" and previous["expectedRow"] == item["expectedRow"])
                work.prepare_copy(previous["row"])
                merged = {**previous["row"], **{field: item["row"][field] for field in ("sign_count", "last_used_at", "updated_at")}}
                item = {**previous, "row": merged}
            mutations[key] = item
    work.prepare_copy(cascade.result)
    result = dict(cascade.result)
    work.prepare_copy(result["credential"])
    result["credential"] = dict(result["credential"])
    for item in mutations.values():
        if item["table"] == "webauthn_credentials" and item["key"] == {"id": values["record_id"]}:
            for field in ("sign_count", "last_used_at", "updated_at"):
                result["credential"][field] = item["row"].get(field)
    work.prepare_copy(tuple(mutations.values()))
    ordered = tuple(sorted(mutations.values(), key=lambda item: (item["table"], item["keyDigest"], item["operation"])))
    units = cascade.work_units + 32 + len(context.selected_rows) + 4 * len(approval_mutations)
    spec = authority_contract.operation_spec(public.OPERATION)
    public._require(len(ordered) <= spec["maximumBusinessMutations"] and units <= spec["maximumBusinessWorkUnits"])
    return legacy._transition_result(mutations=ordered, result=result, work_units=units, work=work)
