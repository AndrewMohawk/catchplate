"""Purpose-bound publication approvals using real verified assertion originals.

The legacy physical-evidence kernels remain unchanged. These operations do not
claim that a verifier signature alone establishes hardware: current proved trust,
credential policy, raw assertion bytes and the retained HTTP owner's independent
physical-attestation validation must all agree. No filesystem effect occurs here.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import timedelta, timezone
from types import MappingProxyType

from catchplate import authority_publication_approval as profile
from catchplate import authority_transition_core as core
from catchplate import authority_transition_quota as shared
from catchplate import authority_transition_webauthn as assertion_rows


def _values(operation, arguments):
    try:
        return profile.operation_profile(operation).arguments(operation, arguments, typed=True)
    except (TypeError, ValueError) as exc:
        raise core.TransitionKernelError("publication approval input is not closed") from exc


def _approval_id(operation, values, request_digest):
    return values["approval_id"] or core.deterministic_uuid(
        operation=operation, request_digest=request_digest, purpose="publication-approval")


def _row(context, approval_id):
    selected = context.exact("control_plane_approvals", {"id": approval_id})
    return selected, shared._row(selected, "publication approval")


def _public(row):
    return {**shared._control_public(row), "request": json.loads(row["request_json"])}


def _authn(row, purpose):
    value = shared._canonical_stored_mapping(row["approval_authn"], "publication approval provenance")
    if (set(value) != {"schema", "requestDigest", "requestEvidenceDigest", "credentialPolicy",
            "decisionDigest", "decisionEvidenceDigest", "consumptionDigest", "consumptionEvidenceDigest", "completionSha256"}
            or value.get("schema") != purpose.PROVENANCE_SCHEMA):
        raise core.TransitionKernelError("approval was not created by the publication profile")
    return value


@dataclass(frozen=True, slots=True)
class PublicationApprovalKernel:
    operation: str
    permits_empty_mutation: bool = False

    @property
    def handler(self):
        return profile.operation_profile(self.operation).HANDLER_PREFIX + self.operation.split(".")[-1]

    @property
    def program_id(self):
        return core.transition_program_id(self.operation, self.handler)

    def queries(self, *, arguments, database_now, request_digest):
        if self.operation in profile.assertion_operations():
            raise core.TransitionKernelError("publication operation requires pinned assertion originals")
        return self._queries(arguments, database_now, request_digest, None)

    def queries_with_evidence(self, *, arguments, database_now, request_digest, evidence):
        if self.operation not in profile.assertion_operations():
            raise core.TransitionKernelError("publication settlement cannot acquire assertion authority")
        return self._queries(arguments, database_now, request_digest, evidence)

    def _queries(self, arguments, database_now, request_digest, evidence):
        purpose = profile.operation_profile(self.operation)
        del database_now
        values = _values(self.operation, arguments)
        item_id = _approval_id(self.operation, values, request_digest)
        queries = [shared._query(operation=self.operation, name="approval", table="control_plane_approvals", key={"id": item_id}),
            shared._role_query(self.operation, "actor_role", values["actor_id"])]
        if self.operation == purpose.PREFIX + "request":
            queries.append(shared._aggregate_query(self.operation, "approval_capacity", "control-plane-approvals", "global"))
        else:
            # Only exact fields of an already authenticated selected row become
            # subsequent selectors; no caller-supplied approver identity.
            role_column = "requester_id" if self.operation.endswith("decide") else "approved_by"
            queries.append(shared._role_query(self.operation, "other_role", core.SelectedRowFieldReference(
                "control_plane_approvals", {"id": item_id}, role_column)))
        if evidence is not None:
            for name, table, field in (("credential", "webauthn_credentials", "credentialRecordId"),
                    ("challenge", "webauthn_challenges", "challengeId")):
                core.require_text(evidence.get(field), field, maximum_bytes=1024)
                queries.append(shared._query(operation=self.operation, name=name, table=table, key={"id": evidence[field]}))
            queries.extend(assertion_rows._trust_queries(self.operation, work=None))
        queries.append(shared._audit_query(self.operation, request_digest))
        return tuple(queries)

    def transition(self, context):
        purpose = profile.operation_profile(self.operation)
        values = _values(self.operation, context.arguments)
        item_id = _approval_id(self.operation, values, context.request_digest)
        actor = values["actor_id"]
        shared._require_role(context, subject_id=actor, required_role=purpose.ROLE)
        now = context.database_now.astimezone(timezone.utc)
        now_s = now.isoformat()
        mutations = []
        evidence = context.verified_webauthn_evidence
        if self.operation in purpose.ASSERTION_OPERATIONS:
            if evidence is None:
                raise core.TransitionKernelError("publication requires independently pinned assertion verification")
            credential = shared._row(context.exact("webauthn_credentials", {"id": evidence["credentialRecordId"]}), "credential")
            policy = values["credential_policy"]
            allowed = set(policy["allowedAuthenticatorClasses"])
            classes = {credential.get("authenticator_class")}
            if "yubikey" in classes:
                classes.add("hardware")
            if (not classes.intersection(allowed) or not classes.intersection({"yubikey", "hardware"})
                    or credential.get("attestation_trusted") not in (True, 1)
                    or not credential.get("attestation_leaf_sha256") or not credential.get("attestation_root_sha256")
                    or evidence["rpId"] != policy["rpId"] or evidence["origin"] not in policy["origins"]
                    or evidence["expiresAtEpochNs"] - evidence["verifiedAtEpochNs"] > policy["maxAssertionAgeSeconds"] * 1_000_000_000):
                raise core.TransitionKernelError("publication hardware/current authenticator policy differs")
            # The shared computation rechecks the exact current challenge,
            # counter, credential key, proved published trust high-water and
            # withdrawal inventory before constructing the two atomic CASes.
            mutations.extend(assertion_rows._assertion_mutations(context, {"actor_id": actor}))
        elif evidence is not None:
            raise core.TransitionKernelError("settlement is not a new assertion grant")

        if self.operation == purpose.PREFIX + "request":
            selected = context.exact("control_plane_approvals", {"id": item_id})
            if selected.get("present") is not False:
                raise core.TransitionKernelError("publication request identity is already used")
            expires = now + timedelta(seconds=300)
            provenance = {"schema": purpose.PROVENANCE_SCHEMA, "requestDigest": context.request_digest,
                "requestEvidenceDigest": evidence["verifiedAssertionReceiptDigest"], "credentialPolicy": values["credential_policy"],
                "decisionDigest": None, "decisionEvidenceDigest": None, "consumptionDigest": None, "consumptionEvidenceDigest": None,
                "completionSha256": None}
            row = {"id": item_id, "action": values["action"], "resource_id": purpose.RESOURCE,
                "payload_digest": values["payload_digest"], "requester_id": actor, "request_json": profile.canonical(values["request"]).decode("ascii"),
                "status": "pending", "requested_at": now_s, "expires_at": expires.isoformat(), "approved_by": None,
                "approved_at": None, "consumed_by": None, "consumed_at": None, "decision_note": None,
                "approver_webauthn_credential_id": None, "approval_authn": profile.canonical(provenance).decode("ascii")}
            mutations.append(shared._aggregate_update(context, kind="control-plane-approvals", partition="global",
                live_delta=1, active_delta=1, next_sequence_delta=1,
                minimum_expiry_epoch_ns=shared._database_epoch_ns(expires)))
        else:
            selected, row = _row(context, item_id)
            provenance = _authn(row, purpose)
            if (row["action"] != values["action"] or row["resource_id"] != purpose.RESOURCE
                    or row["payload_digest"] != values["payload_digest"]
                    or row["request_json"] != profile.canonical(values["request"]).decode("ascii")
                    or row["expires_at"] <= now_s):
                raise core.TransitionKernelError("publication approval exact binding or original expiry changed")
            if self.operation.endswith("decide"):
                if row["status"] != "pending" or row["requester_id"] == actor:
                    raise core.TransitionKernelError("publication approval is not a fresh distinct-person decision")
                shared._require_role(context, subject_id=row["requester_id"], required_role=purpose.ROLE)
                if values["credential_policy"] != provenance["credentialPolicy"]:
                    raise core.TransitionKernelError("publication credential policy drifted")
                provenance = {**provenance, "decisionDigest": context.request_digest,
                    "decisionEvidenceDigest": evidence["verifiedAssertionReceiptDigest"]}
                row = {**row, "status": "approved", "approved_by": actor, "approved_at": now_s,
                    "approver_webauthn_credential_id": evidence["credentialRecordId"]}
            else:
                if row["requester_id"] != actor or row["approved_by"] in (None, actor):
                    raise core.TransitionKernelError("publication approval requester/approver binding changed")
                shared._require_role(context, subject_id=row["approved_by"], required_role=purpose.ROLE)
                if self.operation.endswith("consume"):
                    if row["status"] != "approved" or provenance["consumptionDigest"] is not None:
                        raise core.TransitionKernelError("publication approval was already consumed or is not approved")
                    if values["credential_policy"] != provenance["credentialPolicy"]:
                        raise core.TransitionKernelError("publication credential policy drifted")
                    provenance = {**provenance, "consumptionDigest": context.request_digest,
                        "consumptionEvidenceDigest": evidence["verifiedAssertionReceiptDigest"]}
                    row = {**row, "status": "consumed", "consumed_by": actor, "consumed_at": now_s}
                else:
                    if (row["status"] != "consumed" or row["consumed_by"] != actor
                            or provenance["consumptionDigest"] != values["consumption_request_digest"]
                            or provenance["completionSha256"] is not None):
                        raise core.TransitionKernelError("publication settlement is not the exact fresh consumed operation")
                    provenance = {**provenance, "completionSha256": values["completion_sha256"]}
            row = {**row, "approval_authn": profile.canonical(provenance).decode("ascii")}
        mutations.append(core.mutation(operation=self.operation, selected=selected, row=row))
        audit, audit_digest, replay = shared._audit_mutations(context,
            event_type=purpose.AUDIT_PREFIX + self.operation.split(".")[-1], actor_type="admin", actor_id=actor,
            event={"schema": "catchplate.publicationApprovalAudit/v1", "operation": self.operation,
                "requestDigest": context.request_digest, "approvalId": item_id, "actorId": actor,
                "action": values["action"], "resourceId": purpose.RESOURCE, "payloadDigest": values["payload_digest"],
                "request": values["request"], "provenance": provenance})
        if replay:
            raise core.TransitionKernelError("publication audit cannot replay a file effect")
        return core.KernelTransition(mutations=tuple(mutations) + audit,
            result={"ok": True, "approval": _public(row), "operation": self.operation, "requestDigest": context.request_digest,
                "auditEventDigest": audit_digest, "idempotentReplay": False}, work_units=64)


KERNELS = MappingProxyType({operation: PublicationApprovalKernel(operation) for operation in profile.OPERATIONS})
