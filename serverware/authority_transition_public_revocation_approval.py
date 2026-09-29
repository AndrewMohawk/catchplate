"""Fixed approval rows, actual assertion CASes and audit in one protected write.

The serving verifier independently authenticates current requester/approver
originals and enrolled policy. These kernels recheck the actual target, current
OIDC roles, exact approval prestate and genuine assertion evidence. A static
admin mode remains the verifier's actual authenticated input, never an invented
OIDC role. Final consumption belongs exclusively to the public-v5 cascade.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import timedelta, timezone
from types import MappingProxyType

from serverware import authority_public_revocation_approval as profile
from serverware import authority_public_webauthn_revocation_kernel as public_kernel
from serverware import authority_transition_core as core
from serverware import authority_transition_quota as shared
from serverware import authority_transition_webauthn as assertions


def _item_id(operation, values, request_digest):
    return values["approval_id"] or core.deterministic_uuid(operation=operation,
        request_digest=request_digest, purpose="public-webauthn-revocation-approval")


def _roles(context, actor, supplied):
    if not actor.startswith("oidc:"):
        return set(supplied)
    row = shared._row(context.exact("rbac_role_bindings", {"subject_id": actor}), "current public approval actor")
    roles = row.get("roles_json")
    profile.public._require(type(roles) is str and len(roles) <= 4096 and row.get("status") == "active")
    parsed = json.loads(roles)
    profile.public._require(type(parsed) is list and len(parsed) <= 32
        and all(type(role) is str and 1 <= len(role) <= 128 for role in parsed)
        and core.canonical_bytes(parsed).decode("ascii") == roles)
    return set(parsed)


@dataclass(frozen=True, slots=True)
class PublicRevocationApprovalKernel:
    operation: str
    permits_empty_mutation: bool = False

    @property
    def handler(self):
        return profile.handler(self.operation)

    @property
    def program_id(self):
        return core.transition_program_id(self.operation, self.handler)

    def queries(self, *, arguments, database_now, request_digest):
        if self.operation in profile.ASSERTION_OPERATIONS:
            raise core.TransitionKernelError("public approval requires genuine assertion originals")
        return self._queries(arguments, request_digest, None)

    def queries_with_evidence(self, *, arguments, database_now, request_digest, evidence):
        if self.operation not in profile.ASSERTION_OPERATIONS:
            raise core.TransitionKernelError("identity-only approval cannot acquire assertion authority")
        return self._queries(arguments, request_digest, evidence)

    def _queries(self, arguments, request_digest, evidence):
        values = profile.arguments(self.operation, arguments, typed=True)
        item = _item_id(self.operation, values, request_digest)
        queries = [shared._query(operation=self.operation, name="approval", table="control_plane_approvals", key={"id": item}),
            shared._query(operation=self.operation, name="target", table="webauthn_credentials", key={"id": values["resource_id"]}),
            shared._audit_query(self.operation, request_digest)]
        if values["actor_id"].startswith("oidc:"):
            queries.append(shared._role_query(self.operation, "actor_role", values["actor_id"]))
        if values["approval_id"] is None:
            queries.append(shared._aggregate_query(self.operation, "approval_capacity", "control-plane-approvals", "global"))
        if evidence is not None:
            for name, table, field in (("signer", "webauthn_credentials", "credentialRecordId"),
                    ("challenge", "webauthn_challenges", "challengeId")):
                profile.public._text(evidence.get(field))
                if table != "webauthn_credentials" or evidence[field] != values["resource_id"]:
                    queries.append(shared._query(operation=self.operation, name=name, table=table, key={"id": evidence[field]}))
            queries.extend(assertions._trust_queries(self.operation, work=None))
        return tuple(queries)

    def transition(self, context):
        values = profile.arguments(self.operation, context.arguments, typed=True)
        actor, policy = values["actor_id"], values["mutation_policy"]
        requesting = values["approval_id"] is None
        roles = _roles(context, actor, values["actor_roles"])
        profile.public._require(bool(roles & ({"admin", "approver"} if requesting else {"admin"})))
        target = shared._row(context.exact("webauthn_credentials", {"id": values["resource_id"]}), "revocation target")
        profile.public._require(target.get("revoked_at") is None
            and (not requesting or target.get("user_id") == actor or "admin" in roles))
        bound = values["request"]
        import hashlib
        profile.public._require(bound["credential_id_sha256"] == "sha256:" + hashlib.sha256(
            target["credential_id"].encode("utf-8")).hexdigest()
            and bound["credential_user_id"] == target["user_id"] and bound["label"] == target["label"]
            and bound["attestation_root_sha256"] == target.get("attestation_root_sha256"))
        evidence, mutations = context.verified_webauthn_evidence, []
        profile.public._require((evidence is not None) == policy["mfaRequired"])
        if evidence is not None:
            signer = shared._row(context.exact("webauthn_credentials", {"id": evidence["credentialRecordId"]}), "actual approval signer")
            public_kernel._credential_policy(signer, policy["credentialPolicy"], actor)
            mutations.extend(assertions._assertion_mutations(context, {"actor_id": actor}))
        item = _item_id(self.operation, values, context.request_digest)
        selected = context.exact("control_plane_approvals", {"id": item})
        now = context.database_now.astimezone(timezone.utc)
        if requesting:
            profile.public._require(selected.get("present") is False)
            expires = now + timedelta(seconds=values["ttl_seconds"])
            provenance = {"schema": profile.PROVENANCE_SCHEMA, "policy": policy,
                "requestDigest": context.request_digest,
                "requestEvidenceDigest": None if evidence is None else evidence["verifiedAssertionReceiptDigest"],
                "decisionDigest": None, "decisionEvidenceDigest": None}
            row = {"id": item, "action": profile.public.OPERATION, "resource_id": values["resource_id"],
                "payload_digest": values["payload_digest"], "requester_id": actor,
                "request_json": core.canonical_bytes(bound).decode("ascii"), "status": "pending",
                "requested_at": now.isoformat(), "expires_at": expires.isoformat(),
                "approved_by": None, "approved_at": None, "consumed_by": None, "consumed_at": None,
                "decision_note": None, "approval_authn": core.canonical_bytes(provenance).decode("ascii"),
                "approver_webauthn_credential_id": None}
            mutations.append(shared._aggregate_update(context, kind="control-plane-approvals", partition="global",
                live_delta=1, active_delta=1, next_sequence_delta=1,
                minimum_expiry_epoch_ns=shared._database_epoch_ns(expires)))
        else:
            row = shared._row(selected, "actual pending public approval")
            provenance = shared._canonical_stored_mapping(row["approval_authn"], "public approval original")
            profile.public._require(set(provenance) == {"schema", "policy", "requestDigest", "requestEvidenceDigest",
                    "decisionDigest", "decisionEvidenceDigest"}
                and provenance["schema"] == profile.PROVENANCE_SCHEMA and provenance["policy"] == policy
                and row["status"] == "pending" and row["requester_id"] != actor
                and row["action"] == profile.public.OPERATION and row["resource_id"] == values["resource_id"]
                and row["payload_digest"] == values["payload_digest"]
                and row["request_json"] == core.canonical_bytes(bound).decode("ascii")
                and assertions._utc(row["expires_at"], "approval expiry") > now)
            provenance = {**provenance, "decisionDigest": context.request_digest,
                "decisionEvidenceDigest": None if evidence is None else evidence["verifiedAssertionReceiptDigest"]}
            row = {**row, "status": "approved", "approved_by": actor, "approved_at": now.isoformat(),
                "decision_note": values["note"], "approval_authn": core.canonical_bytes(provenance).decode("ascii"),
                "approver_webauthn_credential_id": None if evidence is None else evidence["credentialRecordId"]}
        mutations.append(core.mutation(operation=self.operation, selected=selected, row=row))
        audit, audit_digest, replay = shared._audit_mutations(context,
            event_type="control_plane.public_revocation_approval." + ("requested" if requesting else "approved"),
            actor_type="admin", actor_id=actor, event={"approvalId": item, "payloadDigest": values["payload_digest"],
                "requestDigest": context.request_digest, "mfaRequired": policy["mfaRequired"]})
        profile.public._require(replay is False)
        return core.KernelTransition(mutations=tuple(mutations) + audit,
            result={"ok": True, "approval": {**shared._control_public(row), "request": bound},
                "operation": self.operation, "requestDigest": context.request_digest,
                "auditEventDigest": audit_digest, "idempotentReplay": False},
            work_units=32 + len(mutations) + len(audit))


KERNELS = MappingProxyType({operation: PublicRevocationApprovalKernel(operation) for operation in profile.OPERATIONS})
