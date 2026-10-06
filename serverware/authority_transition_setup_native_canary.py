"""Consume actual completed native publication history into one Setup slot."""
from dataclasses import dataclass
from datetime import timezone
from types import MappingProxyType

from serverware import authority_setup_native_canary as p
from serverware import authority_transition_core as core, authority_transition_quota as q
from serverware import authority_transition_setup_native_enrollment as issued
from serverware import authority_transition_credential_currentness as currentness
from serverware import authority_transition_webauthn as assertion
from serverware import authority_transition_oauth_activation as hardware
from serverware import authority_transition_policy_native_activation_settlement as native


class _PublicationRows:
    """Narrow adapter over genuine query proofs, not supplied success records."""
    TABLES = frozenset({p.activation.FINALIZATION_TABLE, p.activation.PREPARATION_TABLE, p.activation.READY_TABLE,
        p.activation.HEAD_TABLE, "policy_canary_heads", "policy_canary_assignments"})

    def __init__(self, context):
        self.context = context

    def matching(self, table, **fields):
        p.require(table in self.TABLES)
        rows = [q._row(row, "native committed publication original") for row in self.context.present_rows(table)]
        return [row for row in rows if all(row.get(name) == value for name, value in fields.items())]

    def one(self, table, *, optional=False, **fields):
        rows = self.matching(table, **fields)
        p.require(len(rows) == 1 or optional and not rows)
        return rows[0] if rows else None


def _row(context, table, key):
    return q._row(context.exact(table, key), "native Setup canary " + table)


def _completed_audit(context, identity, operation, request_digest, *, session=None):
    row = _row(context, "metadata_audit_outbox", {"id": identity})
    p.require(row["id"] == q._audit_identity(operation, request_digest) and row["event_type"] == operation
        and row["status"] == "audited" and row["audited_at"] is not None and row["audit_event_hash"] is not None
        and row["last_error"] is None and row["claim_id"] is None and row["claimed_at"] is None)
    p.digest(row["audit_event_hash"])
    event = p.activation.canonical_original(row["event_json"])
    p.require(event["requestDigest"] == request_digest
        and row["event_digest"] == core.framed_digest("serverware.metadataAuditOutboxEvent/v1", row["event_json"].encode("ascii"))
        and p.enrollment.setup.epoch(row["audited_at"]) <= q._database_epoch_ns(context.database_now))
    if session is not None:
        p.require(event["sessionId"] == session)
    return row, event


@dataclass(frozen=True, slots=True)
class Kernel:
    operation: str = p.RECORD
    permits_empty_mutation: bool = False

    @property
    def handler(self):
        return "serverware_policy_authority_setup_native_canary_record"

    @property
    def program_id(self):
        return core.transition_program_id(self.operation, self.handler)

    def queries(self, **kwargs):
        raise core.TransitionKernelError("native Setup association requires fresh owner hardware")

    def queries_with_evidence(self, *, arguments, database_now, request_digest, evidence):
        v = p.arguments(self.operation, arguments, typed=True); r = v["request"]
        sid, cid = r["sessionId"], r["canaryId"]
        ref = lambda table, key, field: core.SelectedRowFieldReference(table, key, field)
        exact = lambda name, table, key: q._query(operation=self.operation, name=name, table=table, key=key)
        continuation = {"session_id": sid}
        credential_id, credential_version = r["credentialId"], r["credentialVersion"]
        enrollment_approval, native_approval = r["enrollmentApprovalId"], r["nativeApprovalId"]
        queries = [exact("slot", p.TABLE, continuation), exact("setup", "setup_sessions", {"id": sid}),
            exact("continuation", p.enrollment.candidate.TABLE, continuation), exact("enrollment", p.enrollment.TABLE, continuation),
            exact("ca", p.ca.TABLE, continuation), exact("credential", "credentials", {"id": credential_id}),
            exact("generation", "credential_generations", {"credential_id": credential_id}),
            currentness.root_query(self.operation, credential_id, credential_version),
            exact("high", "policy_high_water", {"scope": "active"}), exact("published", "policy_publications", {"policy_hash": r["policyHash"]}),
            exact("artifact", "policy_candidate_artifacts", {"artifact_envelope_digest": ref(p.enrollment.candidate.TABLE, continuation, "artifact_envelope_digest")}),
            exact("original_generation", "policy_shadow_generation_publications", {"generation_publication_envelope_digest": ref(
                p.enrollment.candidate.TABLE, continuation, "generation_publication_digest")}),
            exact("enrollment_approval", "control_plane_approvals", {"id": enrollment_approval}),
            exact("native_approval", "control_plane_approvals", {"id": native_approval}),
            q._role_query(self.operation, "owner", v["actor_id"]),
            q._role_query(self.operation, "enrollment_approver", ref("control_plane_approvals", {"id": enrollment_approval}, "approved_by")),
            q._role_query(self.operation, "native_requester", ref("control_plane_approvals", {"id": native_approval}, "requester_id")),
            q._role_query(self.operation, "native_approver", ref("control_plane_approvals", {"id": native_approval}, "approved_by")),
            q._audit_query(self.operation, request_digest)]
        for table in (p.activation.PREPARATION_TABLE, p.activation.READY_TABLE, p.activation.HEAD_TABLE,
                "policy_canary_heads", "policy_canary_assignments"):
            queries.append(exact(table, table, {"canary_id": cid}))
        # Complete policy-hash range: two rows is already ambiguity, never choose
        # a caller-favoured canary from a potentially nonunique terminal set.
        queries.append(core.BoundedQuery(query_id=core.query_program_id(self.operation, "finalizations", p.activation.FINALIZATION_TABLE),
            table=p.activation.FINALIZATION_TABLE, predicates=(core.QueryPredicate("policy_hash", "eq", r["policyHash"]),),
            order_by=(core.QueryOrder("canary_id"),), maximum_rows=2, proof_primitive="bounded-limit-plus-one", work_units=2, page_size=1))
        for index, identity in enumerate(r["auditIds"]):
            queries.append(exact("completed_audit_" + str(index), "metadata_audit_outbox", {"id": identity}))
        for name, table, field in (("request_key", "webauthn_credentials", "credentialRecordId"), ("challenge", "webauthn_challenges", "challengeId")):
            p.enrollment.setup.text(evidence.get(field), 1024)
            queries.append(exact(name, table, {"id": evidence[field]}))
        queries.extend(assertion._trust_queries(self.operation, work=None))
        return tuple(queries)

    def transition(self, context):
        v = p.arguments(self.operation, context.arguments, typed=True); r = v["request"]
        sid, cid, now = r["sessionId"], r["canaryId"], q._database_epoch_ns(context.database_now)
        p.require(r["issuedAtEpochNs"] <= now < r["expiresAtEpochNs"])
        enrolled = _row(context, p.enrollment.TABLE, {"session_id": sid})
        installed = _row(context, p.ca.TABLE, {"session_id": sid})
        i = p.enrollment.intent(enrolled["intent_original"])
        p.require(enrolled["phase"] == "certificate_issued" and installed["phase"] == "ca_readback_authenticated"
            and p.sha256(p.enrollment.row_original(enrolled)) == r["enrollmentSha256"] == installed["enrollment_sha256"]
            and p.sha256(p.ca.row_original(installed)) == r["installationSha256"]
            and enrolled["owner_id"] == installed["owner_id"] == v["actor_id"] == i["ownerId"]
            and enrolled["configuration_digest"] == installed["configuration_digest"] == v["control_plane_configuration_digest"])
        issued._current(context, v, i)
        session = _row(context, "setup_sessions", {"id": sid})
        continuation = _row(context, p.enrollment.candidate.TABLE, {"session_id": sid})
        p.require(p.sha256(p.enrollment.setup.row_original(session)) == r["setupSha256"] == i["setupSha256"]
            and p.sha256(p.enrollment.candidate.row_original(continuation)) == r["continuationSha256"] == i["continuationSha256"]
            and continuation["canary_id"] == cid and continuation["policy_hash"] == r["policyHash"]
            and continuation["credential_id"] == r["credentialId"] and continuation["credential_version"] == r["credentialVersion"]
            and r["expiresAtEpochNs"] <= p.enrollment.setup.epoch(session["expires_at"]))
        # Historical source effects had to finish inside their actual original
        # windows. This metadata association does not extend any old allowance.
        ca_prepared = p.ca.prepared(installed["prepared_original"])
        observed = p.ca.observation(installed["observation_original"])["payload"]
        p.require(i["issuedAtEpochNs"] <= p.enrollment.setup.epoch(enrolled["completed_at"]) < i["expiresAtEpochNs"]
            and ca_prepared["issuedAtEpochNs"] <= observed["observedBeforeEpochNs"] <= observed["observedAfterEpochNs"]
            <= p.enrollment.setup.epoch(installed["completed_at"]) < ca_prepared["expiresAtEpochNs"]
            and observed["preparedSha256"] == installed["prepared_sha256"]
            and observed["certificateSha256"] == enrolled["certificate_sha256"])
        enrollment_approval = _row(context, "control_plane_approvals", {"id": enrolled["approval_id"]})
        p.require(enrolled["approval_id"] == r["enrollmentApprovalId"]
            and p.canonical(enrollment_approval).decode("ascii") == enrolled["approval_original"]
            and enrollment_approval["status"] == "consumed" and enrollment_approval["consumed_by"] == v["actor_id"]
            and enrollment_approval["approved_by"] not in (None, v["actor_id"]))
        q._require_role(context, subject_id=enrollment_approval["approved_by"], required_role="approver")
        high = _row(context, "policy_high_water", {"scope": "active"})
        published = _row(context, "policy_publications", {"policy_hash": r["policyHash"]})
        view = _PublicationRows(context)
        p.require(len(view.matching(p.activation.FINALIZATION_TABLE, policy_hash=r["policyHash"])) == 1)
        current = native.committed_policy(view, high, published)
        p.require(current is not None and current["finalization_digest"] == r["finalizationSha256"])
        final = view.one(p.activation.FINALIZATION_TABLE, canary_id=cid)
        preparation = view.one(p.activation.PREPARATION_TABLE, canary_id=cid)
        prepared = p.activation.prepared(p.activation.canonical_original(preparation["prepared_original"]))
        p.require(final["publication_sha256"] == r["publicationSha256"]
            and p.sha256(final["activation_policy_original"].encode("ascii")) == r["activationPolicySha256"]
            and final["artifact_envelope_digest"] == continuation["artifact_envelope_digest"]
            and prepared["controlPlaneConfigurationSha256"] == v["control_plane_configuration_digest"]
            and prepared["assignmentSha256"] == continuation["assignment_envelope_digest"]
            and prepared["generationPublicationEnvelopeSha256"] == continuation["generation_publication_digest"])
        generation = _row(context, "policy_shadow_generation_publications", {
            "generation_publication_envelope_digest": continuation["generation_publication_digest"]})
        p.require(generation["generation_id_digest"] == prepared["generationId"] and generation["canary_id"] == cid)
        native_approval = _row(context, "control_plane_approvals", {"id": preparation["approval_id"]})
        p.require(preparation["approval_id"] == r["nativeApprovalId"]
            and p.canonical(native_approval).decode("ascii") == prepared["approvalOriginal"])
        for actor in (native_approval["requester_id"], native_approval["approved_by"]):
            q._require_role(context, subject_id=actor, required_role=p.activation.ROLE)
        p.require(p.audit_ids(enrolled, installed, final) == r["auditIds"])
        for operation, row, field in ((p.enrollment.PREPARE, enrolled, "prepare_request_digest"),
                (p.enrollment.COMPLETE, enrolled, "complete_request_digest"), (p.ca.PREPARE, installed, "prepare_request_digest"),
                (p.ca.COMPLETE, installed, "complete_request_digest")):
            _completed_audit(context, q._audit_identity(operation, row[field]), operation, row[field], session=sid)
        for old in p.activation.completed_audit_originals(final["audit_originals_json"]):
            event = p.activation.canonical_original(old["event_json"])
            actual, _ = _completed_audit(context, old["id"], old["event_type"], event["requestDigest"])
            p.require(actual == old)
        terminal, event = _completed_audit(context, final["audit_outbox_id"], p.activation.PREFIX + "finalize", final["request_digest"])
        p.require(terminal["event_digest"] == final["audit_event_digest"] and event["activationId"] == final["activation_id"]
            and event["preparedSha256"] == final["prepared_sha256"])
        evidence = context.verified_webauthn_evidence
        p.require(evidence is not None)
        hardware._hardware(_row(context, "webauthn_credentials", {"id": evidence["credentialRecordId"]}), v["credential_policy"])
        slot = context.exact(p.TABLE, {"session_id": sid})
        p.require(not slot["present"], "native Setup association exists; inspect without replay")
        audit, audit_digest, replay = q._audit_mutations(context, event_type=self.operation, actor_type="admin", actor_id=v["actor_id"],
            event={"schema": "serverware.setupNativeCanaryAudit/v1", "requestDigest": context.request_digest,
                "sessionId": sid, "canaryId": cid, "finalizationSha256": r["finalizationSha256"], "installationSha256": r["installationSha256"]})
        p.require(not replay)
        row = {"session_id": sid, "revision": 0, "phase": "canary_publication_associated", "owner_id": v["actor_id"],
            "setup_sha256": r["setupSha256"], "continuation_sha256": r["continuationSha256"], "enrollment_sha256": r["enrollmentSha256"],
            "installation_sha256": r["installationSha256"], "canary_id": cid, "finalization_sha256": r["finalizationSha256"],
            "publication_sha256": r["publicationSha256"], "policy_hash": r["policyHash"], "request_original": p.canonical(v).decode("ascii"),
            "request_digest": context.request_digest, "configuration_digest": v["control_plane_configuration_digest"],
            "audit_event_digest": audit_digest, "associated_at": context.database_now.astimezone(timezone.utc).isoformat()}
        raw = p.row_original(row)
        return core.KernelTransition(mutations=(core.mutation(operation=self.operation, selected=slot, row=row),)
            + tuple(assertion._assertion_mutations(context, {"actor_id": v["actor_id"]})) + audit,
            result={"ok": True, "operation": self.operation, "requestDigest": context.request_digest,
                "auditEventDigest": audit_digest, "idempotentReplay": False, "associationOriginal": raw.decode("ascii")}, work_units=4096)


KERNELS = MappingProxyType({p.RECORD: Kernel()})
