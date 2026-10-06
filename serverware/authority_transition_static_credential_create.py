"""Atomic static creation from independently verified native custody originals.

This kernel has no plaintext, KEK, signing or encryption interface. Its owner
must supply the root-selected creation policy and the literal native evidence
that it independently verified for this execution. Structural joins here are
not a substitute for that verification or for the service's pre-capability
reverification. Registration and those owner joins are deliberately external.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from types import MappingProxyType

from serverware import authority_static_credential_create as profile
from serverware import authority_static_credential_approval as approval_profile
from serverware import authority_static_credential_custody as custody
from serverware import authority_transition_core as core
from serverware import authority_transition_quota as shared
from serverware import authority_transition_webauthn as assertions
from serverware import authority_transition_oauth_activation as hardware
from serverware import authority_credential_currentness as currentness
from serverware import authority_webauthn_trust as trust


_APPROVAL_FIELDS = approval_profile.ROW_FIELDS


def _epoch(value):
    profile.require(type(value) is str)
    instant = datetime.fromisoformat(value)
    profile.require(instant.tzinfo is not None and instant.utcoffset() == timezone.utc.utcoffset(instant))
    return shared._database_epoch_ns(instant)


def _approval_request(values):
    return approval_profile.approval_request(values)


def _role(context, actor, allowed):
    profile._actor(actor)
    binding = shared._row(context.exact("rbac_role_bindings", {"subject_id": actor}),
        "current static credential role")
    raw = binding.get("roles_json")
    profile.require(type(raw) is str)
    roles = json.loads(raw)
    profile.require(profile.canonical(roles).decode("ascii") == raw)
    if type(roles) is dict:
        roles = roles.get("roles")
    profile.require(binding.get("subject_id") == actor and binding.get("status") == "active"
        and type(roles) is list and all(type(role) is str for role in roles)
        and bool(set(roles).intersection(allowed)), "Current static credential role is required")


def _approval_mutations(context, values, now, stamp):
    item_id = values["approval_id"]
    if item_id is None:
        return ()
    selected = context.exact("control_plane_approvals", {"id": item_id})
    row = shared._row(selected, "actual static credential approval")
    request = values["request"]
    profile.require(set(row) == _APPROVAL_FIELDS and row["id"] == item_id
        and row["action"] == profile.ACTION and row["resource_id"] == request["credentialId"]
        and row["payload_digest"] == profile.approval_payload_digest(values)
        and row["request_json"] == _approval_request(values)
        and row["requester_id"] == values["actor_id"] and row["status"] == "approved"
        and row["consumed_by"] is None and row["consumed_at"] is None,
        "Approval is not an unused review of this exact static candidate")
    approver = row["approved_by"]
    profile.require(approver != values["actor_id"], "Static creation requires a distinct approver")
    _role(context, approver, profile.APPROVER_ROLES)
    profile.require(request["issuedAtEpochNs"] <= _epoch(row["requested_at"])
        <= _epoch(row["approved_at"]) <= now < request["executionExpiresAtEpochNs"]
        <= _epoch(row["expires_at"]) <= request["expiresAtEpochNs"],
        "Static approval or execution crossed its original interval")
    provenance = approval_profile.provenance(row["approval_authn"])
    profile.require(provenance["candidateSha256"] == row["payload_digest"]
        and provenance["credentialPolicy"] == values["credential_policy"]
        and provenance["decisionDigest"] is not None and provenance["decisionEvidenceDigest"] is not None
        and provenance["consumptionDigest"] is None and provenance["consumptionEvidenceDigest"] is None,
        "Static creation requires its purpose-fixed, unconsumed hardware approval")
    credential_id = row["approver_webauthn_credential_id"]
    core.require_text(credential_id, "approval authenticator", maximum_bytes=1024)
    credential = shared._row(context.exact("webauthn_credentials", {"id": credential_id}),
        "current approving hardware")
    hardware._hardware(credential, values["credential_policy"])
    profile.require(credential["id"] == credential_id and credential["user_id"] == approver)
    # The fresh requester assertion independently validates this very same
    # proved high-water/publication pair. Also retain current approver trust.
    publications = context.present_rows(trust.PUBLICATION_TABLE)
    profile.require(len(publications) == 1)
    publication = shared._row(publications[0], "current physical trust publication")
    withdrawn = json.loads(publication["withdrawn_credential_ids_json"])
    profile.require(publication["status"] == "published" and type(withdrawn) is list
        and credential["attestation_trust_bundle_digest"] == publication["bundle_digest"]
        and credential["attestation_trust_bundle_sequence"] == publication["sequence"]
        and credential["id"] not in withdrawn and credential["credential_id"] not in withdrawn,
        "Approver hardware is not currently trusted")
    # No standalone consume dispatch, expiry rewrite, or replay of a consumed
    # approval: this CAS commits only with the three new identity rows below.
    receipt = context.verified_webauthn_evidence["verifiedAssertionReceiptDigest"]
    profile.digest(receipt)
    provenance = {**provenance, "consumptionDigest": context.request_digest, "consumptionEvidenceDigest": receipt}
    return (core.mutation(operation=context.operation, selected=selected,
        row={**row, "status": "consumed", "consumed_by": values["actor_id"], "consumed_at": stamp,
            "approval_authn": profile.canonical(provenance).decode("ascii")}),)


@dataclass(frozen=True, slots=True)
class StaticCredentialCreateKernel:
    operation: str = profile.OPERATION
    permits_empty_mutation: bool = False

    @property
    def handler(self):
        return "serverware_policy_authority_credential_static_create"

    @property
    def program_id(self):
        return core.transition_program_id(self.operation, self.handler)

    def queries(self, **kwargs):
        raise core.TransitionKernelError("Static creation requires locally verified hardware and native custody")

    def queries_with_evidence(self, *, arguments, database_now, request_digest, evidence):
        del database_now
        values = profile.arguments(self.operation, arguments, typed=True)
        item_id = values["request"]["credentialId"]
        queries = [shared._role_query(self.operation, "actor_role", values["actor_id"])]
        for name, table, key in (("new_credential", "credentials", {"id": item_id}),
                ("new_generation", "credential_generations", {"credential_id": item_id}),
                ("new_currentness", currentness.ROOT_TABLE, {"id": currentness.root_id(item_id, 1)})):
            queries.append(shared._query(operation=self.operation, name=name, table=table,
                key=key, require_absence=True))
        for name, table, field in (("actor_hardware", "webauthn_credentials", "credentialRecordId"),
                ("actor_challenge", "webauthn_challenges", "challengeId")):
            core.require_text(evidence.get(field), field, maximum_bytes=1024)
            queries.append(shared._query(operation=self.operation, name=name, table=table, key={"id": evidence[field]}))
        queries.extend(assertions._trust_queries(self.operation, work=None))
        if values["approval_id"] is not None:
            key = {"id": values["approval_id"]}
            queries.append(shared._query(operation=self.operation, name="static_approval",
                table="control_plane_approvals", key=key))
            queries.append(shared._role_query(self.operation, "approver_role",
                core.SelectedRowFieldReference("control_plane_approvals", key, "approved_by")))
            queries.append(shared._query(operation=self.operation, name="approver_hardware", table="webauthn_credentials",
                key={"id": core.SelectedRowFieldReference("control_plane_approvals", key, "approver_webauthn_credential_id")}))
        queries.append(shared._audit_query(self.operation, request_digest))
        return tuple(queries)

    def transition(self, context):
        values = profile.arguments(self.operation, context.arguments, typed=True)
        selected_policy = getattr(context, "static_credential_creation_policy", None)
        proof = getattr(context, "verified_static_credential_custody_evidence", None)
        profile.require(type(selected_policy) is dict and type(proof) is dict,
            "Static creation requires independently admitted policy and locally verified custody originals")
        now = shared._database_epoch_ns(context.database_now)
        profile.verify_request_context(self.operation, values, selected_policy=selected_policy, now_epoch_ns=now)
        # This repeats exact original/context joins only. Both authority owners
        # must actually run custody.verify_original before supplying this field.
        custody.bind_originals(arguments=values, evidence=proof, now_epoch_ns=now)
        request = values["request"]
        native = profile.generation(request["nativeGenerationOriginal"])
        actor, item_id = values["actor_id"], request["credentialId"]
        _role(context, actor, profile.REQUESTER_ROLES)
        evidence = context.verified_webauthn_evidence
        profile.require(isinstance(evidence, dict))
        credential = shared._row(context.exact("webauthn_credentials", {"id": evidence["credentialRecordId"]}),
            "current creating hardware")
        policy = values["credential_policy"]
        hardware._hardware(credential, policy)
        profile.require(evidence["rpId"] == policy["rpId"] and evidence["origin"] in policy["origins"]
            and request["executionIssuedAtEpochNs"] <= evidence["verifiedAtEpochNs"] <= now
            < evidence["expiresAtEpochNs"] <= request["executionExpiresAtEpochNs"]
            and evidence["expiresAtEpochNs"] - evidence["verifiedAtEpochNs"]
            <= policy["maxAssertionAgeSeconds"] * 1_000_000_000)
        authn = tuple(assertions._assertion_mutations(context, {"actor_id": actor}))
        selected = context.exact("credentials", {"id": item_id})
        generation = context.exact("credential_generations", {"credential_id": item_id})
        root = context.exact(currentness.ROOT_TABLE, {"id": currentness.root_id(item_id, 1)})
        profile.require(not selected["present"] and not generation["present"] and not root["present"],
            "Static credential identity, generation or currentness already exists")
        stamp = context.database_now.astimezone(timezone.utc).isoformat()
        approval = _approval_mutations(context, values, now, stamp)
        created = {"id": item_id, "name": request["name"], "kind": request["kind"], **native["envelope"],
            "metadata": profile.canonical(request["metadata"]).decode("ascii"), "lifecycle_status": "active",
            "revocation_error": None, "revocation_requested_at": None, "created_at": stamp, "updated_at": stamp}
        candidate_digest = profile.approval_payload_digest(values)
        native_digest = profile.sha256(request["nativeGenerationOriginal"].encode("ascii"))
        audit, audit_digest, replay = shared._audit_mutations(context, event_type=self.operation,
            actor_type="admin", actor_id=actor,
            event={"schema": "serverware.staticCredentialCreationAudit/v1", "operation": self.operation,
                "requestDigest": context.request_digest, "credentialId": item_id, "credentialVersion": 1,
                "candidateSha256": candidate_digest, "intentSha256": native["intentSha256"],
                "nativeGenerationSha256": native_digest,
                "custodyStatementSha256": profile.sha256(profile.canonical(proof["statement"])),
                "approvalId": values["approval_id"]})
        profile.require(not replay, "Static creation audit identity was already used")
        mutations = (core.mutation(operation=self.operation, selected=selected, row=created),
            core.mutation(operation=self.operation, selected=generation,
                row={"credential_id": item_id, "last_version": 1, "updated_at": stamp}),
            core.mutation(operation=self.operation, selected=root,
                row=currentness.new_root(item_id, 1, context.request_digest, stamp))) + approval + authn + audit
        public = {name: created[name] for name in ("id", "name", "kind", "credential_version",
            "lifecycle_status", "created_at", "updated_at")}
        public["metadata"] = json.loads(created["metadata"])
        return core.KernelTransition(mutations=mutations,
            result={"ok": True, "operation": self.operation, "requestDigest": context.request_digest,
                "auditEventDigest": audit_digest, "idempotentReplay": False, "credential": public,
                "approvalId": values["approval_id"], "candidateSha256": candidate_digest,
                "auditState": "controlled_pending"}, work_units=1024)


KERNELS = MappingProxyType({profile.OPERATION: StaticCredentialCreateKernel()})


def verify_static_create_plan(*, payload, arguments, verified_native_evidence, verified_webauthn_evidence,
        creation_policy, deadline_ns, now_epoch_ns, work):
    """Exact source effects after independent native, signed-plan and root checks."""
    from serverware.authority_transition_static_credential_approval import _verify_static_plan

    _verify_static_plan(operation=profile.OPERATION, payload=payload, arguments=arguments,
        verified_native_evidence=verified_native_evidence, verified_webauthn_evidence=verified_webauthn_evidence,
        creation_policy=creation_policy, deadline_ns=deadline_ns, now_epoch_ns=now_epoch_ns, work=work)
