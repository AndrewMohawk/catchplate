"""Actual protected approval, precontact fence and verified-certificate CAS.

The legacy Setup row remains revision three. This distinct successor records
only issuance. A pending/unknown row is never reset on timeout or lost output.
"""
from dataclasses import dataclass
from datetime import timezone
from types import MappingProxyType

from serverware import authority_setup_native_enrollment as p
from serverware import authority_transition_core as core
from serverware import authority_transition_quota as q
from serverware import authority_transition_webauthn as assertion
from serverware import authority_transition_oauth_activation as hardware
from serverware import authority_transition_credential_currentness as currentness


def _approval_id(operation, values, request_digest):
    return values["approval_id"] or core.deterministic_uuid(operation=operation,
        request_digest=request_digest, purpose="native-setup-enrollment-approval")


def _row(context, table, key):
    return q._row(context.exact(table, key), "native Setup " + table)


def _current(context, values, intent):
    session = _row(context, "setup_sessions", {"id": intent["sessionId"]})
    continuation = _row(context, p.candidate.TABLE, {"session_id": intent["sessionId"]})
    p.require(p.sha256(p.setup.row_original(session)) == intent["setupSha256"]
        and p.sha256(p.candidate.row_original(continuation)) == intent["continuationSha256"]
        and session["revision"] == 3 and session["phase"] == "credential_activated" and session["status"] == "active"
        and session["terminal_at"] is None and session["owner_id"] == continuation["owner_id"] == intent["ownerId"]
        and session["current_assignee_id"] in {None, intent["ownerId"]}
        and continuation["setup_original"] == p.setup.row_original(session).decode("ascii")
        and continuation["configuration_digest"] == values["control_plane_configuration_digest"]
        and p.setup.epoch(session["expires_at"]) >= intent["expiresAtEpochNs"])
    for name, field in (("assignment_digest", "assignmentSha256"), ("policy_hash", "policyHash"),
            ("route_policy_digest", "routePolicyDigest"), ("credential_id", "credentialId"), ("credential_version", "credentialVersion")):
        p.require(continuation[name] == intent[field])
    p.require(session["principal_id"] == intent["principalId"])
    credential = _row(context, "credentials", {"id": intent["credentialId"]})
    generation = _row(context, "credential_generations", {"credential_id": intent["credentialId"]})
    _, root = currentness.require_root(context, intent["credentialId"], intent["credentialVersion"])
    p.require(credential["lifecycle_status"] == "active" and credential["credential_version"] == generation["last_version"]
        == intent["credentialVersion"] and root["status"] == "open")
    high = _row(context, "policy_high_water", {"scope": "active"})
    publication = _row(context, "policy_publications", {"policy_hash": intent["policyHash"]})
    artifact = _row(context, "policy_candidate_artifacts", {"artifact_envelope_digest": continuation["artifact_envelope_digest"]})
    p.require(high["policy_hash"] == publication["policy_hash"] == artifact["policy_hash"] == intent["policyHash"]
        and publication["scope"] == artifact["scope"] == "active" and publication["status"] == "committed"
        and high["policy_id"] == publication["policy_id"] == artifact["policy_id"]
        and high["sequence"] == publication["sequence"] == artifact["policy_sequence"]
        and high["rollback_epoch"] == publication["rollback_epoch"] == artifact["rollback_epoch"])
    q._require_role(context, subject_id=intent["ownerId"], required_role="credential_owner")
    q._require_role(context, subject_id=intent["ownerId"], required_role="policy_author")


@dataclass(frozen=True, slots=True)
class Kernel:
    operation: str
    permits_empty_mutation: bool = False

    @property
    def handler(self):
        return "serverware_policy_authority_" + self.operation.replace(".", "_").replace("-", "_")

    @property
    def program_id(self):
        return core.transition_program_id(self.operation, self.handler)

    def queries(self, *, arguments, database_now, request_digest):
        p.require(self.operation == p.COMPLETE, "native enrollment ceremony needs original assertion evidence")
        return self._queries(arguments, request_digest, None)

    def queries_with_evidence(self, *, arguments, database_now, request_digest, evidence):
        p.require(self.operation in p.ASSERTION_OPERATIONS)
        return self._queries(arguments, request_digest, evidence)

    def _queries(self, arguments, request_digest, evidence):
        v = p.arguments(self.operation, arguments, typed=True); i = p.intent(v["intent_original"])
        aid = _approval_id(self.operation, v, request_digest)
        exact = lambda name, table, key: q._query(operation=self.operation, name=name, table=table, key=key)
        queries = [exact("setup", "setup_sessions", {"id": i["sessionId"]}),
            exact("continuation", p.candidate.TABLE, {"session_id": i["sessionId"]}),
            exact("native_enrollment", p.TABLE, {"session_id": i["sessionId"]}),
            exact("approval", "control_plane_approvals", {"id": aid}),
            exact("credential", "credentials", {"id": i["credentialId"]}),
            exact("version", "credential_generations", {"credential_id": i["credentialId"]}),
            currentness.root_query(self.operation, i["credentialId"], i["credentialVersion"]),
            exact("high_water", "policy_high_water", {"scope": "active"}),
            exact("publication", "policy_publications", {"policy_hash": i["policyHash"]}),
            exact("artifact", "policy_candidate_artifacts", {"artifact_envelope_digest": core.SelectedRowFieldReference(
                p.candidate.TABLE, {"session_id": i["sessionId"]}, "artifact_envelope_digest")}),
            q._role_query(self.operation, "requester", i["ownerId"]), q._audit_query(self.operation, request_digest)]
        if self.operation == p.REQUEST:
            queries.append(q._aggregate_query(self.operation, "capacity", "control-plane-approvals", "global"))
        if self.operation == p.DECIDE:
            queries.append(q._role_query(self.operation, "approver", v["actor_id"]))
        if self.operation in {p.PREPARE, p.COMPLETE}:
            queries.extend((q._role_query(self.operation, "approver", core.SelectedRowFieldReference("control_plane_approvals", {"id": aid}, "approved_by")),
                exact("approver_key", "webauthn_credentials", {"id": core.SelectedRowFieldReference(
                    "control_plane_approvals", {"id": aid}, "approver_webauthn_credential_id")})))
        if evidence is not None:
            for name, table, field in (("request_key", "webauthn_credentials", "credentialRecordId"), ("challenge", "webauthn_challenges", "challengeId")):
                p.setup.text(evidence.get(field), 1024)
                queries.append(exact(name, table, {"id": evidence[field]}))
        queries.extend(assertion._trust_queries(self.operation, work=None))
        return tuple(queries)

    def transition(self, context):
        v = p.arguments(self.operation, context.arguments, typed=True); i = p.intent(v["intent_original"])
        now = q._database_epoch_ns(context.database_now)
        p.require(i["issuedAtEpochNs"] <= now < i["expiresAtEpochNs"])
        _current(context, v, i)
        aid = _approval_id(self.operation, v, context.request_digest)
        selection = context.exact("control_plane_approvals", {"id": aid})
        slot = context.exact(p.TABLE, {"session_id": i["sessionId"]})
        binding, resource, digest = p.binding_from_intent(v["intent_original"])
        stamp = context.database_now.astimezone(timezone.utc).isoformat()
        effects = []
        if self.operation in p.ASSERTION_OPERATIONS:
            evidence = context.verified_webauthn_evidence
            p.require(evidence is not None)
            key = _row(context, "webauthn_credentials", {"id": evidence["credentialRecordId"]})
            hardware._hardware(key, v["credential_policy"])
            effects.extend(assertion._assertion_mutations(context, {"actor_id": v["actor_id"]}))
        if self.operation == p.REQUEST:
            p.require(not selection["present"] and not slot["present"])
            from datetime import datetime
            expiry = datetime.fromtimestamp(i["expiresAtEpochNs"] // 1_000_000_000, timezone.utc).isoformat()
            approval = {"id": aid, "action": binding["action"], "resource_id": resource, "payload_digest": digest,
                "status": "pending", "requester_id": i["ownerId"], "requested_at": stamp, "expires_at": expiry,
                "request_json": p.canonical(binding).decode("ascii"), "approved_by": None, "approved_at": None,
                "consumed_by": None, "consumed_at": None, "decision_note": None,
                "approval_authn": p.canonical({"schema": "serverware.setupNativeEnrollmentApproval/v1", "requestEvidence": dict(evidence)}).decode("ascii"),
                "approver_webauthn_credential_id": None}
            effects.append(q._aggregate_update(context, kind="control-plane-approvals", partition="global",
                live_delta=1, active_delta=1, next_sequence_delta=1, minimum_expiry_epoch_ns=i["expiresAtEpochNs"]))
        else:
            approval = q._row(selection, "native enrollment original approval")
            p.require(approval["action"] == binding["action"] and approval["resource_id"] == resource
                and approval["payload_digest"] == digest and approval["request_json"] == p.canonical(binding).decode("ascii")
                and approval["requester_id"] == i["ownerId"] and p.setup.epoch(approval["expires_at"]) > now)
            if self.operation == p.DECIDE:
                p.require(approval["status"] == "pending" and not slot["present"])
                q._require_role(context, subject_id=v["actor_id"], required_role="approver")
                approval = {**approval, "status": "approved", "approved_by": v["actor_id"], "approved_at": stamp,
                    "approval_authn": p.canonical({"schema": "serverware.setupNativeEnrollmentDecision/v1", "evidence": dict(evidence)}).decode("ascii"),
                    "approver_webauthn_credential_id": evidence["credentialRecordId"]}
            else:
                p.require(approval["approved_by"] != i["ownerId"])
                q._require_role(context, subject_id=approval["approved_by"], required_role="approver")
                key = _row(context, "webauthn_credentials", {"id": approval["approver_webauthn_credential_id"]})
                authn = p.setup.document(approval["approval_authn"].encode("ascii"), 131072)
                p.require(set(authn) == {"schema", "evidence"} and authn["schema"] == "serverware.setupNativeEnrollmentDecision/v1"
                    and key["user_id"] == approval["approved_by"])
                hardware._hardware(key, v["credential_policy"])
                assertion._assertion_trust(context, key, authn["evidence"], work=None)
                if self.operation == p.PREPARE:
                    p.require(approval["status"] == "approved" and not slot["present"])
                    approval = {**approval, "status": "consumed", "consumed_by": i["ownerId"], "consumed_at": stamp}
                    row = {"session_id": i["sessionId"], "revision": 0, "phase": "issuance_unknown", "owner_id": i["ownerId"],
                        "intent_original": v["intent_original"], "intent_sha256": p.sha256(v["intent_original"].encode("ascii")),
                        "approval_id": aid, "approval_original": p.canonical(approval).decode("ascii"),
                        "prepare_request_digest": context.request_digest, "certificate_original": None, "certificate_sha256": None,
                        "association_original": None, "complete_request_digest": None,
                        "configuration_digest": v["control_plane_configuration_digest"], "created_at": stamp,
                        "expires_at": i["expiresAtEpochNs"], "completed_at": None}
                else:
                    p.require(approval["status"] == "consumed" and approval["consumed_by"] == i["ownerId"])
                    row = q._row(slot, "original native enrollment contact fence"); p.row_original(row)
                    p.require(row["phase"] == "issuance_unknown" and row["intent_original"] == v["intent_original"]
                        and row["approval_id"] == aid and row["approval_original"] == p.canonical(approval).decode("ascii")
                        and row["configuration_digest"] == v["control_plane_configuration_digest"])
                    row = {**row, "revision": 1, "phase": "certificate_issued", "certificate_original": v["certificate_original"],
                        "certificate_sha256": p.sha256(p.original(v["certificate_original"], 65536)),
                        "association_original": p.canonical(p.association(v["intent_original"], v["certificate_original"])).decode("ascii"),
                        "complete_request_digest": context.request_digest, "completed_at": stamp}
                p.row_original(row)
                effects.append(core.mutation(operation=self.operation, selected=slot, row=row))
        if self.operation != p.COMPLETE:
            effects.append(core.mutation(operation=self.operation, selected=selection, row=approval))
        audit, audit_digest, replay = q._audit_mutations(context, event_type=self.operation, actor_type="admin", actor_id=v["actor_id"],
            event={"schema": "serverware.setupNativeEnrollmentAudit/v1", "requestDigest": context.request_digest,
                "sessionId": i["sessionId"], "approvalId": aid, "intentSha256": p.sha256(v["intent_original"].encode("ascii")),
                "certificateSha256": None if self.operation != p.COMPLETE else row["certificate_sha256"]})
        p.require(not replay)
        return core.KernelTransition(mutations=tuple(effects) + audit,
            result={"ok": True, "operation": self.operation, "requestDigest": context.request_digest,
                "auditEventDigest": audit_digest, "idempotentReplay": False, "approvalId": aid,
                "enrollmentOriginal": None if self.operation in {p.REQUEST, p.DECIDE} else p.row_original(row).decode("ascii")}, work_units=4096)


KERNELS = MappingProxyType({operation: Kernel(operation) for operation in p.OPERATIONS})
