"""Actual nonce reservation and one-use native evidence CAS over current roots."""
from dataclasses import dataclass
from datetime import timezone
from types import MappingProxyType

from serverware import authority_setup_native_runtime as p
from serverware import authority_setup_native_runtime_policy as policy
from serverware import authority_setup_native_runtime_capture as capture
from serverware import authority_transition_setup_native_canary as predecessor
from serverware import authority_transition_setup_native_enrollment as issued
from serverware import authority_transition_core as core, authority_transition_quota as q
from serverware import authority_transition_credential_currentness as currentness
from serverware import authority_transition_webauthn as assertion
from serverware import authority_transition_oauth_activation as hardware


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
        values = p.arguments(self.operation, arguments, typed=True); a = p.association(values["association_original"])
        scope = policy.scope(p.enrollment.setup.document(values["scope_original"].encode("ascii"), 32768))
        sid, cid, credential = a["session_id"], a["canary_id"], scope["credentialId"]
        exact = lambda name, table, key: q._query(operation=self.operation, name=name, table=table, key=key)
        queries = [exact("slot", p.TABLE, {"session_id": sid}), exact("association", p.canary.TABLE, {"session_id": sid}),
            exact("setup", "setup_sessions", {"id": sid}), exact("continuation", p.enrollment.candidate.TABLE, {"session_id": sid}),
            exact("enrollment", p.enrollment.TABLE, {"session_id": sid}), exact("installation", p.canary.ca.TABLE, {"session_id": sid}),
            exact("credential", "credentials", {"id": credential}), exact("generation", "credential_generations", {"credential_id": credential}),
            currentness.root_query(self.operation, credential, scope["credentialVersion"]), exact("high", "policy_high_water", {"scope": "active"}),
            exact("publication", "policy_publications", {"policy_hash": a["policy_hash"]}),
            exact("artifact", "policy_candidate_artifacts", {"artifact_envelope_digest": core.SelectedRowFieldReference(p.enrollment.candidate.TABLE, {"session_id": sid}, "artifact_envelope_digest")}),
            exact("association_audit", "metadata_audit_outbox", {"id": q._audit_identity(p.canary.RECORD, a["request_digest"])}),
            q._role_query(self.operation, "owner", values["actor_id"]), q._audit_query(self.operation, request_digest)]
        for table in (p.canary.activation.PREPARATION_TABLE, p.canary.activation.READY_TABLE, p.canary.activation.HEAD_TABLE,
                "policy_canary_heads", "policy_canary_assignments"):
            queries.append(exact(table, table, {"canary_id": cid}))
        queries.append(core.BoundedQuery(query_id=core.query_program_id(self.operation, "finalizations", p.canary.activation.FINALIZATION_TABLE),
            table=p.canary.activation.FINALIZATION_TABLE, predicates=(core.QueryPredicate("policy_hash", "eq", a["policy_hash"]),),
            order_by=(core.QueryOrder("canary_id"),), maximum_rows=2, proof_primitive="bounded-limit-plus-one", work_units=2, page_size=1))
        if evidence is not None:
            for label, table, field in (("request_key", "webauthn_credentials", "credentialRecordId"), ("challenge", "webauthn_challenges", "challengeId")):
                p.enrollment.setup.text(evidence.get(field), 1024)
                queries.append(exact(label, table, {"id": evidence[field]}))
            queries.extend(assertion._trust_queries(self.operation, work=None))
        else:
            # The original successful prepare is itself completed/audited.
            queries.append(exact("prepare_audit", "metadata_audit_outbox", {"id": core.SelectedRowFieldReference(
                p.TABLE, {"session_id": sid}, "prepare_audit_id")}))
        return tuple(queries)

    def transition(self, context):
        values = p.arguments(self.operation, context.arguments, typed=True); a = p.association(values["association_original"])
        scope = policy.scope(p.enrollment.setup.document(values["scope_original"].encode("ascii"), 32768))
        sid, now = a["session_id"], q._database_epoch_ns(context.database_now)
        row = lambda table, key: predecessor._row(context, table, key)
        actual = row(p.canary.TABLE, {"session_id": sid})
        p.require(p.canary.row_original(actual).decode("ascii") == values["association_original"])
        audit, _ = predecessor._completed_audit(context, q._audit_identity(p.canary.RECORD, a["request_digest"]),
            p.canary.RECORD, a["request_digest"], session=sid)
        p.require(audit["event_digest"] == a["audit_event_digest"])
        enrolled, installed = row(p.enrollment.TABLE, {"session_id": sid}), row(p.canary.ca.TABLE, {"session_id": sid})
        i = p.enrollment.intent(enrolled["intent_original"])
        p.require(p.sha256(p.enrollment.row_original(enrolled)) == a["enrollment_sha256"]
            and p.sha256(p.canary.ca.row_original(installed)) == a["installation_sha256"])
        issued._current(context, values, i)
        grant = p.enrollment.setup.document(p.enrollment.original(i["authorization"], 32768), 32768)["payload"]
        p.require(scope["nativeAssignment"]["caCertificateSha256"] == grant["runtimeCaCertificateSha256"]
            and scope["nativeAssignment"]["caPublicKeySpkiSha256"] == grant["runtimeCaSpkiSha256"])
        p.require(scope["sessionId"] == sid and scope["principalId"] == i["principalId"] and scope["credentialId"] == i["credentialId"]
            and scope["credentialVersion"] == i["credentialVersion"] and scope["nativeAssignment"]["policyHash"] == i["policyHash"] == a["policy_hash"]
            and scope["routeId"] == row("setup_sessions", {"id": sid})["route_id"]
            and scope["issuedAtEpochNs"] <= now < scope["expiresAtEpochNs"])
        view = predecessor._PublicationRows(context)
        p.require(len(view.matching(p.canary.activation.FINALIZATION_TABLE, policy_hash=a["policy_hash"])) == 1)
        committed = predecessor.native.committed_policy(view, row("policy_high_water", {"scope": "active"}), row("policy_publications", {"policy_hash": a["policy_hash"]}))
        p.require(committed is not None and committed["finalization_digest"] == a["finalization_sha256"])
        selection = context.exact(p.TABLE, {"session_id": sid})
        stamp = context.database_now.astimezone(timezone.utc).isoformat(); mutations = []
        if self.operation == p.PREPARE:
            p.require(not selection["present"] and context.verified_webauthn_evidence is not None)
            evidence = context.verified_webauthn_evidence
            hardware._hardware(row("webauthn_credentials", {"id": evidence["credentialRecordId"]}), values["credential_policy"])
            challenge = row("webauthn_challenges", {"id": evidence["challengeId"]})
            mutations.extend(assertion._assertion_mutations(context, {"actor_id": values["actor_id"]}))
            attempt = {"apiVersion": p.PREPARED, "attemptId": core.deterministic_uuid(operation=self.operation,
                request_digest=context.request_digest, purpose="native-setup-runtime-capture"), "sessionId": sid,
                "associationSha256": p.sha256(values["association_original"].encode("ascii")), "scopeSha256": p.sha256(values["scope_original"].encode("ascii")),
                "nonce": p.nonce(challenge["challenge"], context.request_digest), "principalId": scope["principalId"], "routeId": scope["routeId"],
                "policyHash": a["policy_hash"], "credentialId": scope["credentialId"], "credentialVersion": scope["credentialVersion"],
                "clientRequestSha256": p.sha256(capture.r.utf8(scope["clientRequest"])), "issuedAtEpochNs": now,
                "expiresAtEpochNs": min(now + scope["maximumAttemptNanos"], scope["expiresAtEpochNs"], p.enrollment.setup.epoch(row("setup_sessions", {"id": sid})["expires_at"]))}
            original = p.canonical(attempt).decode("ascii"); p.prepared(original)
            record = {"session_id": sid, "revision": 0, "phase": "capture_outcome_unknown", "owner_id": values["actor_id"],
                "association_sha256": attempt["associationSha256"], "scope_original": values["scope_original"],
                "attempt_original": original, "attempt_sha256": p.sha256(original.encode("ascii")),
                "prepare_request_digest": context.request_digest, "prepare_audit_id": q._audit_identity(self.operation, context.request_digest),
                "capture_original_base64url": None, "capture_sha256": None, "result_original": None, "complete_request_digest": None,
                "configuration_digest": values["control_plane_configuration_digest"], "created_at": stamp, "completed_at": None}
        else:
            record = q._row(selection, "actual original nonce reservation"); p.row_original(record)
            attempt = p.prepared(record["attempt_original"])
            p.require(record["phase"] == "capture_outcome_unknown" and record["owner_id"] == values["actor_id"]
                and record["configuration_digest"] == values["control_plane_configuration_digest"] and record["attempt_original"] == values["attempt_original"]
                and record["association_sha256"] == p.sha256(values["association_original"].encode("ascii"))
                and attempt["scopeSha256"] == p.sha256(values["scope_original"].encode("ascii"))
                and attempt["issuedAtEpochNs"] <= now < attempt["expiresAtEpochNs"])
            predecessor._completed_audit(context, record["prepare_audit_id"], p.PREPARE, record["prepare_request_digest"], session=sid)
            original = p.enrollment.original(values["capture_original_base64url"], p.MAX_CAPTURE)
            # Both original-verifier and planner invoke capture.verify under the
            # actual signed purpose. This is only its fixed result projection.
            result = capture.projection(original, attempt)
            record = {**record, "revision": 1, "phase": "runtime_evidence_recorded", "capture_original_base64url": values["capture_original_base64url"],
                "capture_sha256": p.sha256(original), "result_original": p.canonical(result).decode("ascii"),
                "complete_request_digest": context.request_digest, "completed_at": stamp}
        raw = p.row_original(record)
        mutations.append(core.mutation(operation=self.operation, selected=selection, row=record))
        audits, audit_digest, replay = q._audit_mutations(context, event_type=self.operation, actor_type="admin", actor_id=values["actor_id"],
            event={"schema": "serverware.setupNativeRuntimeAudit/v1", "sessionId": sid, "requestDigest": context.request_digest,
                "attemptSha256": record["attempt_sha256"], "captureSha256": record["capture_sha256"]})
        p.require(not replay)
        return core.KernelTransition(mutations=tuple(mutations) + audits, result={"ok": True, "operation": self.operation,
            "requestDigest": context.request_digest, "auditEventDigest": audit_digest, "idempotentReplay": False,
            "runtimeOriginal": raw.decode("ascii")}, work_units=4096)


KERNELS = MappingProxyType({op: Kernel(op) for op in p.OPERATIONS})
