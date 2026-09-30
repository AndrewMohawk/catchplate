"""Protected precontact fence and authenticated actual-host readback CAS."""
from dataclasses import dataclass
from datetime import timezone
from types import MappingProxyType

from serverware import authority_setup_native_ca as p
from serverware import authority_transition_setup_native_enrollment as issued
from serverware import authority_transition_core as core, authority_transition_quota as q
from serverware import authority_transition_webauthn as assertion
from serverware import authority_transition_oauth_activation as hardware
from serverware import authority_transition_credential_currentness as currentness


def _originals(values):
    row = p.enrollment.setup.document(values["enrollment_original"].encode("ascii"), p.enrollment.MAX_ROW_BYTES)
    return row, p.enrollment.intent(row["intent_original"])


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
        p.require(self.operation == p.COMPLETE)
        return self._queries(arguments, request_digest, None)

    def queries_with_evidence(self, *, arguments, database_now, request_digest, evidence):
        p.require(self.operation == p.PREPARE)
        return self._queries(arguments, request_digest, evidence)

    def _queries(self, arguments, request_digest, evidence):
        values = p.arguments(self.operation, arguments, typed=True); row, i = _originals(values)
        exact = lambda name, table, key: q._query(operation=self.operation, name=name, table=table, key=key)
        aid = row["approval_id"]
        queries = [exact("ca", p.TABLE, {"session_id": i["sessionId"]}), exact("issued", p.enrollment.TABLE, {"session_id": i["sessionId"]}),
            exact("setup", "setup_sessions", {"id": i["sessionId"]}), exact("continuation", p.enrollment.candidate.TABLE, {"session_id": i["sessionId"]}),
            exact("approval", "control_plane_approvals", {"id": aid}), exact("credential", "credentials", {"id": i["credentialId"]}),
            exact("generation", "credential_generations", {"credential_id": i["credentialId"]}),
            currentness.root_query(self.operation, i["credentialId"], i["credentialVersion"]),
            exact("high", "policy_high_water", {"scope": "active"}), exact("publication", "policy_publications", {"policy_hash": i["policyHash"]}),
            exact("artifact", "policy_candidate_artifacts", {"artifact_envelope_digest": core.SelectedRowFieldReference(p.enrollment.candidate.TABLE,
                {"session_id": i["sessionId"]}, "artifact_envelope_digest")}),
            q._role_query(self.operation, "owner", i["ownerId"]),
            q._role_query(self.operation, "original_approver", core.SelectedRowFieldReference("control_plane_approvals", {"id": aid}, "approved_by")),
            exact("approver_key", "webauthn_credentials", {"id": core.SelectedRowFieldReference("control_plane_approvals", {"id": aid}, "approver_webauthn_credential_id")}),
            q._audit_query(self.operation, request_digest)]
        if evidence is not None:
            for label, table, field in (("request_key", "webauthn_credentials", "credentialRecordId"), ("challenge", "webauthn_challenges", "challengeId")):
                p.enrollment.setup.text(evidence.get(field), 1024)
                queries.append(exact(label, table, {"id": evidence[field]}))
        queries.extend(assertion._trust_queries(self.operation, work=None))
        return tuple(queries)

    def transition(self, context):
        values = p.arguments(self.operation, context.arguments, typed=True); enrollment, i = _originals(values)
        now = q._database_epoch_ns(context.database_now)
        p.require(i["issuedAtEpochNs"] <= now < i["expiresAtEpochNs"])
        issued._current(context, values, i)
        found = q._row(context.exact(p.enrollment.TABLE, {"session_id": i["sessionId"]}), "actual issued native enrollment")
        p.require(p.enrollment.row_original(found).decode("ascii") == values["enrollment_original"])
        approval = q._row(context.exact("control_plane_approvals", {"id": enrollment["approval_id"]}), "original issuance two-person approval")
        p.require(p.canonical(approval).decode("ascii") == enrollment["approval_original"] and approval["status"] == "consumed"
            and approval["consumed_by"] == i["ownerId"] and approval["approved_by"] != i["ownerId"])
        q._require_role(context, subject_id=approval["approved_by"], required_role="approver")
        key = q._row(context.exact("webauthn_credentials", {"id": approval["approver_webauthn_credential_id"]}), "current issuance approver key")
        evidence = p.enrollment.setup.document(approval["approval_authn"].encode("ascii"), 131072)
        p.require(set(evidence) == {"schema", "evidence"} and evidence["schema"] == "serverware.setupNativeEnrollmentDecision/v1"
            and key["user_id"] == approval["approved_by"])
        hardware._hardware(key, values["credential_policy"]); assertion._assertion_trust(context, key, evidence["evidence"], work=None)
        # CA permission is the independently admitted installation grant. This
        # retained issuance approval is provenance, never a purpose conversion.
        grant = p.enrollment.setup.document(p.enrollment.original(values["installation_original"], p.installation.MAX_BYTES), p.installation.MAX_BYTES)["payload"]
        p.require(grant["issuedAtEpochNs"] <= now < grant["expiresAtEpochNs"])
        selected = context.exact(p.TABLE, {"session_id": i["sessionId"]})
        stamp = context.database_now.astimezone(timezone.utc).isoformat()
        mutations = []
        if self.operation == p.PREPARE:
            p.require(not selected["present"] and context.verified_webauthn_evidence is not None)
            key = q._row(context.exact("webauthn_credentials", {"id": context.verified_webauthn_evidence["credentialRecordId"]}), "actual CA requester key")
            hardware._hardware(key, values["credential_policy"])
            mutations.extend(assertion._assertion_mutations(context, {"actor_id": values["actor_id"]}))
            prepared = {"apiVersion": p.PREPARED, "attemptId": core.deterministic_uuid(operation=self.operation,
                request_digest=context.request_digest, purpose="native-setup-ca-installation"), "sessionId": i["sessionId"],
                "enrollmentSha256": p.sha256(values["enrollment_original"].encode("ascii")), "intentSha256": enrollment["intent_sha256"],
                "certificateSha256": enrollment["certificate_sha256"], "associationSha256": p.sha256(enrollment["association_original"].encode("ascii")),
                "installationAuthorizationSha256": p.sha256(p.enrollment.original(values["installation_original"], p.installation.MAX_BYTES)),
                "hostKeyId": values["host_key_id"], "nonceSha256": p.sha256(b"serverware.setupNativeCaInstallNonce/v1\0" + context.request_digest.encode("ascii")),
                "issuedAtEpochNs": now, "expiresAtEpochNs": min(i["expiresAtEpochNs"], grant["expiresAtEpochNs"])}
            original = p.canonical(prepared).decode("ascii"); p.prepared(original)
            row = {"session_id": i["sessionId"], "revision": 0, "phase": "installation_unknown", "owner_id": i["ownerId"],
                "enrollment_sha256": prepared["enrollmentSha256"], "installation_original": values["installation_original"],
                "host_key_id": values["host_key_id"], "prepared_original": original, "prepared_sha256": p.sha256(original.encode("ascii")),
                "prepare_request_digest": context.request_digest, "observation_original": None, "observation_sha256": None,
                "complete_request_digest": None, "configuration_digest": values["control_plane_configuration_digest"], "created_at": stamp, "completed_at": None}
        else:
            row = q._row(selected, "original native CA contact fence"); p.row_original(row)
            prepared = p.prepared(row["prepared_original"])
            observation = p.observation(values["observation_original"])["payload"]
            p.require(row["phase"] == "installation_unknown" and row["owner_id"] == values["actor_id"]
                and row["configuration_digest"] == values["control_plane_configuration_digest"]
                and row["installation_original"] == values["installation_original"] and row["host_key_id"] == values["host_key_id"]
                and row["enrollment_sha256"] == p.sha256(values["enrollment_original"].encode("ascii"))
                and observation["preparedSha256"] == row["prepared_sha256"]
                and prepared["issuedAtEpochNs"] <= observation["observedBeforeEpochNs"] <= observation["observedAfterEpochNs"] <= now < prepared["expiresAtEpochNs"])
            row = {**row, "revision": 1, "phase": "ca_readback_authenticated", "observation_original": values["observation_original"],
                "observation_sha256": p.sha256(values["observation_original"].encode("ascii")), "complete_request_digest": context.request_digest, "completed_at": stamp}
        p.row_original(row)
        mutations.append(core.mutation(operation=self.operation, selected=selected, row=row))
        audit, audit_digest, replay = q._audit_mutations(context, event_type=self.operation, actor_type="admin", actor_id=values["actor_id"],
            event={"schema": "serverware.setupNativeCaInstallationAudit/v1", "sessionId": i["sessionId"], "requestDigest": context.request_digest,
                "preparedSha256": row["prepared_sha256"], "observationSha256": row["observation_sha256"]})
        p.require(not replay)
        return core.KernelTransition(mutations=tuple(mutations) + audit, result={"ok": True, "operation": self.operation,
            "requestDigest": context.request_digest, "auditEventDigest": audit_digest, "idempotentReplay": False,
            "installationOriginal": p.row_original(row).decode("ascii")}, work_units=4096)


KERNELS = MappingProxyType({op: Kernel(op) for op in p.OPERATIONS})
