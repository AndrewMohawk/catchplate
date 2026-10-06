"""Actual controlled Setup creation and factual audit settlement.

Issuance and activation use the same protected session/event CAS helpers. A
settle cannot advance a session, grant provider contact or consume approval.
"""
from dataclasses import dataclass
from types import MappingProxyType
from serverware import authority_oauth_setup as profile
from serverware import authority_oauth_activation_policy as enrollment
from serverware import authority_transition_core as core
from serverware import authority_transition_quota as shared
from serverware import authority_transition_webauthn as assertion
from serverware import authority_transition_oauth_activation as activation
from serverware import authority_transition_oauth_setup_rows as rows
from serverware import authority_oauth_retirement_succession_current as succession


def _handler(operation):
    return "serverware_policy_authority_" + operation.replace(".", "_").replace("-", "_")


@dataclass(frozen=True, slots=True)
class CreateKernel:
    operation: str = profile.OP_CREATE
    permits_empty_mutation: bool = False

    @property
    def handler(self):
        return _handler(self.operation)

    @property
    def program_id(self):
        return core.transition_program_id(self.operation, self.handler)

    def queries(self, **kwargs):
        raise core.TransitionKernelError("Setup creation requires actual current hardware evidence")

    def queries_with_evidence(self, *, arguments, database_now, request_digest, evidence):
        del database_now
        values = profile.arguments(self.operation, arguments, typed=True)
        session_id = values["resource_id"]
        provider = enrollment.enrollment_document(profile.activation.enrollment_bytes(values["enrollment_original"]))["payload"]["providerId"]
        queries = [shared._query(operation=self.operation, name="setup", table="setup_sessions", key={"id": session_id}, require_absence=True),
            shared._role_query(self.operation, "actor_role", values["actor_id"]),
            core.BoundedQuery(query_id=core.query_program_id(self.operation, "complete_population", "setup_sessions"),
                table="setup_sessions", predicates=(), order_by=(core.QueryOrder("id"),), maximum_rows=65,
                proof_primitive="bounded-limit-plus-one", work_units=65, page_size=64)]
        queries.append(succession.query(self.operation, provider))
        for name, table, field in (("assertion_credential", "webauthn_credentials", "credentialRecordId"),
                ("assertion_challenge", "webauthn_challenges", "challengeId")):
            core.require_text(evidence.get(field), field, maximum_bytes=1024)
            queries.append(shared._query(operation=self.operation, name=name, table=table, key={"id": evidence[field]}))
        queries.extend(assertion._trust_queries(self.operation, work=None))
        queries.extend(rows.event_queries(self.operation, session_id, 0))
        queries.append(shared._audit_query(self.operation, request_digest))
        return tuple(queries)

    def transition(self, context):
        values = profile.arguments(self.operation, context.arguments, typed=True)
        request, actor = values["request"], values["actor_id"]
        now = shared._database_epoch_ns(context.database_now)
        profile.require(request["issuedAtEpochNs"] <= now < request["issuedAtEpochNs"] + 30_000_000_000
            and now < request["expiresAtEpochNs"] and not context.exact("setup_sessions", {"id": values["resource_id"]})["present"])
        shared._require_role(context, subject_id=actor, required_role="credential_owner")
        # The actual planner reconstructs the full protected Setup root first.
        # Retained/expired sessions are not free slots; no implicit pruning.
        profile.require(len(context.present_rows("setup_sessions")) < 64, "complete Setup capacity is full")
        evidence = context.verified_webauthn_evidence
        profile.require(evidence is not None)
        credential = shared._row(context.exact("webauthn_credentials", {"id": evidence["credentialRecordId"]}), "actual Setup creator hardware")
        activation._hardware(credential, values["credential_policy"])
        profile.require(evidence["rpId"] == values["credential_policy"]["rpId"]
            and evidence["origin"] in values["credential_policy"]["origins"]
            and evidence["expiresAtEpochNs"] - evidence["verifiedAtEpochNs"] <= values["credential_policy"]["maxAssertionAgeSeconds"] * 1_000_000_000)
        raw = profile.activation.enrollment_bytes(values["enrollment_original"])
        application = enrollment.enrollment_document(raw)["payload"]
        succession.require_unassigned(context, application["providerId"])
        profile.require(application["providerId"] == request["providerId"]
            and application["issuedAtEpochNs"] <= now < application["expiresAtEpochNs"]
            and request["expiresAtEpochNs"] <= application["expiresAtEpochNs"])
        row = rows.new_row(context, values)
        audit, audit_digest, replay = shared._audit_mutations(context, event_type="setup.oauth.create", actor_type="admin", actor_id=actor,
            event={"schema": "serverware.oauthSetupAudit/v1", "operation": self.operation, "requestDigest": context.request_digest,
                "sessionId": row["id"], "setupPostSha256": profile.sha256(profile.row_original(row)), "request": request})
        profile.require(not replay)
        effects = rows.mutations(context, None, row, transition="create", actor=actor, updates={}, audit_digest=audit_digest,
            provider=request["providerId"], enrollment_sha256=request["enrollmentSha256"])
        result = {"ok": True, "operation": self.operation, "requestDigest": context.request_digest,
            "auditEventDigest": audit_digest, "idempotentReplay": False, "setupOriginal": profile.row_original(row).decode("ascii"),
            "setupEventId": profile.event_id(row["id"], 1), "auditState": "controlled_pending"}
        return core.KernelTransition(mutations=effects + tuple(assertion._assertion_mutations(context, {"actor_id": actor})) + audit,
            result=result, work_units=512)


@dataclass(frozen=True, slots=True)
class AuditSettleKernel:
    operation: str = profile.OP_SETTLE
    permits_empty_mutation: bool = False

    @property
    def handler(self):
        return _handler(self.operation)

    @property
    def program_id(self):
        return core.transition_program_id(self.operation, self.handler)

    def queries(self, *, arguments, database_now, request_digest):
        del database_now
        values = profile.arguments(self.operation, arguments, typed=True)
        key = {"id": values["event_id"]}
        return (shared._query(operation=self.operation, name="setup_event", table="setup_session_events", key=key),
            shared._query(operation=self.operation, name="setup_audit_link", table=profile.AUDIT_LINK_TABLE, key=key),
            shared._query(operation=self.operation, name="actual_completed_outbox", table="metadata_audit_outbox",
                key={"id": core.SelectedRowFieldReference(profile.AUDIT_LINK_TABLE, key, "outbox_id")}),
            shared._audit_query(self.operation, request_digest))

    def transition(self, context):
        values = profile.arguments(self.operation, context.arguments, typed=True)
        key = {"id": values["event_id"]}
        selected = context.exact("setup_session_events", key)
        event = shared._row(selected, "exact controlled Setup event")
        link = shared._row(context.exact(profile.AUDIT_LINK_TABLE, key), "exact immutable Setup audit link")
        profile.require(set(event) == profile.EVENT_FIELDS and set(link) == profile.AUDIT_LINK_FIELDS
            and event["id"] == link["id"] == link["event_id"] and event["session_id"] == link["session_id"]
            and event["id"] == profile.event_id(event["session_id"], event["sequence"])
            and event["audit_status"] == "controlled_pending" and event["audit_attempts"] == 0
            and all(event[name] is None for name in ("audit_claim_id", "audit_claimed_at", "audited_at", "audit_event_hash", "audit_last_error")))
        document = profile.document(event["event_json"].encode("ascii"), profile.MAX_EVENT_BYTES)
        profile.require(event["payload_digest"] == profile.sha256(profile.canonical(document))
            and document["details"]["authorityRequestDigest"] == link["request_digest"]
            and shared._audit_identity(document["details"]["authorityOperation"], link["request_digest"]) == link["outbox_id"])
        outbox = shared._row(context.exact("metadata_audit_outbox", {"id": link["outbox_id"]}), "genuine completed metadata audit")
        profile.require(outbox["status"] == "audited" and outbox["event_digest"] == link["outbox_event_digest"]
            and outbox["audited_at"] is not None and outbox["audit_event_hash"] is not None
            and outbox["claim_id"] is None and outbox["claimed_at"] is None
            and profile.epoch(outbox["audited_at"]) <= shared._database_epoch_ns(context.database_now))
        profile.digest(outbox["audit_event_hash"])
        actual = shared._canonical_stored_mapping(outbox["event_json"], "completed Setup audit original")
        profile.require(actual["requestDigest"] == link["request_digest"]
            and actual["setupPostSha256"] == document["details"]["setupPostSha256"])
        after = {**event, "audit_status": "audited", "audited_at": outbox["audited_at"], "audit_event_hash": outbox["audit_event_hash"]}
        audit, digest, replay = shared._audit_mutations(context, event_type="setup.oauth.audit-settle", actor_type="control_plane", actor_id=None,
            event={"schema": "serverware.oauthSetupAuditSettlement/v1", "requestDigest": context.request_digest,
                "eventId": event["id"], "outboxId": outbox["id"], "auditEventHash": outbox["audit_event_hash"]})
        profile.require(not replay)
        return core.KernelTransition(mutations=(core.mutation(operation=self.operation, selected=selected, row=after),) + audit,
            result={"ok": True, "operation": self.operation, "requestDigest": context.request_digest, "auditEventDigest": digest,
                "idempotentReplay": False, "eventId": event["id"], "auditState": "audited", "auditEventHash": outbox["audit_event_hash"]}, work_units=128)


KERNELS = MappingProxyType({profile.OP_CREATE: CreateKernel(), profile.OP_SETTLE: AuditSettleKernel()})
