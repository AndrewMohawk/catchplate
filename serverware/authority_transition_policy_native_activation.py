"""Native READY and hardware two-person preparation over complete real roots.

The returned prepared original is not a currentness lease. Its actual atomic
hold mutation and the source-admitted writer exclusion are required as well.
"""
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType

from serverware import authority_policy_canary as p
from serverware import authority_policy_canary_tables as tables
from serverware import authority_policy_native_activation as profile
from serverware import authority_native_activation_hold as hold
from serverware import authority_primary_contract as primary
from serverware import authority_transition_core as core
from serverware import authority_transition_quota as shared
from serverware import authority_transition_webauthn as assertions
from serverware import authority_transition_policy_native_activation_state as originals
from serverware.authority_transition_policy_canary_state import State

PROVENANCE_FIELDS = frozenset({"schema", "requestDigest", "requestEvidenceDigest", "credentialPolicy",
    "decisionDigest", "decisionEvidenceDigest", "consumptionDigest", "consumptionEvidenceDigest"})


def values(operation, arguments):
    return profile.arguments(operation, arguments, typed=True)


def approval_id(operation, value, digest):
    return value["approval_id"] or core.deterministic_uuid(operation=operation, request_digest=digest, purpose="native-policy-activation-approval")


def provenance(row):
    value = profile.canonical_original(row["approval_authn"], 16384)
    p.require(set(value) == PROVENANCE_FIELDS and value["schema"] == profile.PROVENANCE)
    return value


def state_from(value, database_now, snapshot):
    rows = [row for row in snapshot[p.TABLE] if row["request_id"] == value["request"]["readinessRequestId"]]
    p.require(len(rows) == 1)
    p.row_original(rows[0])
    batch = p.batch(rows[0]["batch_original"])
    evidence = p.evidence(profile.canonical_original(rows[0]["native_evidence_original"], 131072))
    return State(snapshot, batch["events"], database_now, evidence["statement"])


def _audit_keys(value):
    if value["approval_original"] is None:
        return ()
    row = profile.canonical_original(value["approval_original"])
    authn = provenance(row)
    return tuple((phase, shared._audit_identity(profile.PREFIX + phase, authn[name]))
        for phase, name in (("request", "requestDigest"), ("decide", "decisionDigest"), ("consume", "consumptionDigest"))
        if authn[name] is not None)


def completed_audits(context, value, phases):
    retained = []
    for phase, identity in _audit_keys(value):
        if phase not in phases:
            continue
        row = shared._row(context.exact("metadata_audit_outbox", {"id": identity}), "native activation audit")
        p.require(row["status"] == "audited" and row["audited_at"] is not None and row["audit_event_hash"] is not None
            and row["last_error"] is None and row["event_type"] == profile.PREFIX + phase)
        p.digest(row["audit_event_hash"])
        event = profile.canonical_original(row["event_json"])
        p.require(event["activationId"] == value["request"]["activationId"] and event["approvalId"] == value["approval_id"]
            and row["event_digest"] == core.framed_digest("serverware.metadataAuditOutboxEvent/v1", row["event_json"].encode("ascii")))
        retained.append(row)
    p.require(len(retained) == len(phases))
    return retained


def _assertion(context, value):
    evidence = context.verified_webauthn_evidence
    p.require(evidence is not None)
    credential = shared._row(context.exact("webauthn_credentials", {"id": evidence["credentialRecordId"]}), "native publisher credential")
    policy = value["credential_policy"]
    classes = {credential.get("authenticator_class")}
    if "yubikey" in classes:
        classes.add("hardware")
    p.require(classes.intersection(policy["allowedAuthenticatorClasses"]) and classes.intersection({"hardware", "yubikey"})
        and credential.get("attestation_trusted") in (True, 1) and credential.get("attestation_leaf_sha256")
        and credential.get("attestation_root_sha256") and evidence["rpId"] == policy["rpId"]
        and evidence["origin"] in policy["origins"] and evidence["userPresent"] is True and evidence["userVerified"] is True
        and 0 < evidence["expiresAtEpochNs"] - evidence["verifiedAtEpochNs"] <= policy["maxAssertionAgeSeconds"] * 1_000_000_000)
    return evidence, assertions._assertion_mutations(context, {"actor_id": value["actor_id"]})


@dataclass(frozen=True, slots=True)
class NativeActivationKernel:
    operation: str
    permits_empty_mutation: bool = False

    @property
    def handler(self):
        return "serverware_policy_authority_native_policy_activation_" + self.operation.removeprefix(profile.PREFIX).replace("-", "_")

    @property
    def program_id(self):
        return core.transition_program_id(self.operation, self.handler)

    def queries(self, *, arguments, database_now, request_digest):
        p.require(self.operation not in profile.ASSERTION_OPERATIONS)
        return self._queries(arguments, database_now, request_digest, None)

    def queries_with_evidence(self, *, arguments, database_now, request_digest, evidence):
        p.require(self.operation in profile.ASSERTION_OPERATIONS)
        return self._queries(arguments, database_now, request_digest, evidence)

    def _queries(self, arguments, database_now, request_digest, evidence):
        value = values(self.operation, arguments)
        snapshot = profile.canonical_original(value["before_original"], profile.MAX_BEFORE)
        state_from(value, database_now, snapshot)
        item_id = approval_id(self.operation, value, request_digest)
        queries = [core.BoundedQuery(query_id=core.query_program_id(self.operation, "complete_population", table), table=table,
            predicates=(), order_by=tuple(core.QueryOrder(name) for name in primary.PRIMARY_KEY_COLUMNS[table]),
            maximum_rows=max(1, len(snapshot[table])) + 1, proof_primitive="bounded-limit-plus-one",
            work_units=max(1, len(snapshot[table])) + 1, page_size=max(1, len(snapshot[table])))
            for table in tables.TABLES]
        for table, key in ((profile.READY_TABLE, {"canary_id": value["request"]["canaryId"]}),
                (profile.HEAD_TABLE, {"canary_id": value["request"]["canaryId"]}),
                (profile.PREPARATION_TABLE, {"canary_id": value["request"]["canaryId"]}),
                (profile.FINALIZATION_TABLE, {"canary_id": value["request"]["canaryId"]}), (hold.TABLE, {"scope": hold.SCOPE}),
                ("policy_publications", {"policy_hash": value["request"]["publicationAfter"]["policySha256"]})):
            if not any(all(row[name] == item for name, item in key.items()) for row in snapshot[table]):
                queries.append(shared._query(operation=self.operation, name="new_" + table, table=table, key=key, require_absence=True))
        queries.extend((shared._query(operation=self.operation, name="approval", table="control_plane_approvals", key={"id": item_id}),
            shared._role_query(self.operation, "actor_role", value["actor_id"]), shared._audit_query(self.operation, request_digest)))
        if self.operation == profile.PREFIX + "request":
            queries.append(shared._aggregate_query(self.operation, "approval_capacity", "control-plane-approvals", "global"))
        else:
            field = "requester_id" if self.operation.endswith("decide") else "approved_by"
            queries.append(shared._role_query(self.operation, "other_role", core.SelectedRowFieldReference("control_plane_approvals", {"id": item_id}, field)))
        for phase, identity in _audit_keys(value):
            queries.append(shared._query(operation=self.operation, name="prior_audit_" + phase, table="metadata_audit_outbox", key={"id": identity}))
        preparations = [row for row in snapshot[profile.PREPARATION_TABLE] if row["canary_id"] == value["request"]["canaryId"]]
        if preparations and preparations[0]["publication_audit_id"] is not None:
            queries.append(shared._query(operation=self.operation, name="publication_audit", table="metadata_audit_outbox",
                key={"id": preparations[0]["publication_audit_id"]}))
        if evidence is not None:
            for table, field in (("webauthn_credentials", "credentialRecordId"), ("webauthn_challenges", "challengeId")):
                queries.append(shared._query(operation=self.operation, name=table, table=table, key={"id": evidence[field]}))
            queries.extend(assertions._trust_queries(self.operation, work=None))
        # The framework adds its genuine audit-capacity selection separately.
        p.require(sum(query.maximum_rows for query in queries) < 256 and sum(query.work_units for query in queries) < 8192)
        return tuple(queries)

    def transition(self, context):
        from serverware import db
        value = values(self.operation, context.arguments)
        expected = profile.canonical_original(value["before_original"], profile.MAX_BEFORE)
        actual = {table: sorted((shared._row(row, "native activation " + table) for row in context.present_rows(table)),
            key=lambda row: p.canonical(tables.key(table, row))) for table in tables.TABLES}
        p.require(expected == actual, "native activation complete current population changed")
        state = state_from(value, context.database_now, actual)
        shared._require_role(context, subject_id=value["actor_id"], required_role=profile.ROLE)
        phase = self.operation.removeprefix(profile.PREFIX)
        if phase not in {"request", "decide", "consume"}:
            from serverware import authority_transition_policy_native_activation_settlement as settlement
            return settlement.transition(context, state, value)
        intake, result, generation, assignment = originals.associated_intent(state, value)
        item_id = approval_id(self.operation, value, context.request_digest)
        selected = context.exact("control_plane_approvals", {"id": item_id})
        evidence, auth_mutations = _assertion(context, value)
        mutations = list(auth_mutations)
        timestamp = context.database_now.astimezone(timezone.utc).isoformat()
        expires = value["request"]["expiresAtUnixNanos"]
        expiry = datetime.fromtimestamp(expires // 1_000_000_000, timezone.utc).replace(microsecond=(expires % 1_000_000_000) // 1000).isoformat()
        p.require(shared._database_epoch_ns(context.database_now) < expires)
        existing_hold = state.one(hold.TABLE, optional=True, scope=hold.SCOPE)
        p.require(existing_hold is None or hold.original(existing_hold)["phase"] == "published", "another native publication is unresolved")
        ready = originals.ready_payload(result["core"], value["request"]["readinessResultSha256"])
        bound = p.canonical(value["request"]).decode("ascii")
        if phase == "request":
            p.require(selected["present"] is False and state.one(profile.READY_TABLE, optional=True, canary_id=ready["canaryId"]) is None)
            head = state.one("policy_canary_heads", canary_id=ready["canaryId"])
            p.require(head["status"] == "sealing" and head["head_revision"] == ready["previousRevision"]
                and head["head_state_digest"] == ready["previousStateSha256"])
            state.put(profile.READY_TABLE, {"canary_id": ready["canaryId"], "ready_revision": ready["revision"],
                "ready_state_digest": p.sha256(p.canonical(ready)), "readiness_request_id": intake["request_id"],
                "readiness_record_sha256": result["recordSha256"], "readiness_result_original": p.canonical(result).decode("ascii"),
                "ready_original": p.canonical(ready).decode("ascii"), "configuration_digest": value["control_plane_configuration_digest"],
                "activation_policy_sha256": p.sha256(p.canonical(value["activation_policy"])), "transition_digest": context.request_digest,
                "created_at_epoch_ns": state.now, "expires_at_epoch_ns": expires})
            # A real CAS of the retained legacy sealing predecessor, never an
            # invented Fleet-signed revision. Native state has its own head.
            mutations.append(core.mutation(operation=self.operation, selected=context.exact("policy_canary_heads", {"canary_id": ready["canaryId"]}), row=head))
            state.put(profile.HEAD_TABLE, {"canary_id": ready["canaryId"], "source_profile": "native-policy-activation/v1",
                "predecessor_revision": ready["previousRevision"], "predecessor_state_digest": ready["previousStateSha256"],
                "head_revision": ready["revision"], "head_state_digest": value["request"]["readyStateSha256"], "status": "ready",
                "ready_state_digest": value["request"]["readyStateSha256"], "updated_at_epoch_ns": state.now})
            authn = {"schema": profile.PROVENANCE, "requestDigest": context.request_digest,
                "requestEvidenceDigest": evidence["verifiedAssertionReceiptDigest"], "credentialPolicy": value["credential_policy"],
                "decisionDigest": None, "decisionEvidenceDigest": None, "consumptionDigest": None, "consumptionEvidenceDigest": None}
            row = {"id": item_id, "action": profile.ACTION, "resource_id": profile.RESOURCE,
                "payload_digest": p.sha256(bound.encode("ascii")), "requester_id": value["actor_id"], "request_json": bound,
                "status": "pending", "requested_at": timestamp, "expires_at": expiry, "approved_by": None, "approved_at": None,
                "consumed_by": None, "consumed_at": None, "decision_note": None, "approver_webauthn_credential_id": None,
                "approval_authn": p.canonical(authn).decode("ascii")}
            mutations.append(shared._aggregate_update(context, kind="control-plane-approvals", partition="global", live_delta=1,
                active_delta=1, next_sequence_delta=1, minimum_expiry_epoch_ns=expires))
        else:
            row = shared._row(selected, "native approval")
            p.require(p.canonical(row).decode("ascii") == value["approval_original"] and row["action"] == profile.ACTION
                and row["resource_id"] == profile.RESOURCE and row["request_json"] == bound and row["payload_digest"] == p.sha256(bound.encode("ascii"))
                and row["expires_at"] == expiry and timestamp < expiry)
            authn = provenance(row)
            p.require(authn["credentialPolicy"] == value["credential_policy"])
            if phase == "decide":
                p.require(row["status"] == "pending" and row["requester_id"] != value["actor_id"])
                shared._require_role(context, subject_id=row["requester_id"], required_role=profile.ROLE)
                authn = {**authn, "decisionDigest": context.request_digest, "decisionEvidenceDigest": evidence["verifiedAssertionReceiptDigest"]}
                row = {**row, "status": "approved", "approved_by": value["actor_id"], "approved_at": timestamp,
                    "approver_webauthn_credential_id": evidence["credentialRecordId"]}
            else:
                p.require(row["status"] == "approved" and row["requester_id"] == value["actor_id"]
                    and row["approved_by"] not in (None, value["actor_id"]) and authn["consumptionDigest"] is None)
                shared._require_role(context, subject_id=row["approved_by"], required_role=profile.ROLE)
                completed_audits(context, value, {"request", "decide"})
                authn = {**authn, "consumptionDigest": context.request_digest, "consumptionEvidenceDigest": evidence["verifiedAssertionReceiptDigest"]}
                row = {**row, "status": "consumed", "consumed_by": value["actor_id"], "consumed_at": timestamp}
            row = {**row, "approval_authn": p.canonical(authn).decode("ascii")}
        prepared_original, prepared_sha = None, None
        audit, audit_digest, replay = shared._audit_mutations(context, event_type=self.operation, actor_type="admin", actor_id=value["actor_id"],
            event={"apiVersion": "serverware.nativePolicyActivationAudit/v1", "operation": self.operation, "requestDigest": context.request_digest,
                "activationId": value["request"]["activationId"], "approvalId": item_id, "intentSha256": p.sha256(bound.encode("ascii")), "provenance": authn})
        p.require(not replay)
        if phase == "consume":
            prepared = profile.prepared({"apiVersion": profile.PREPARED, **{name: value["request"][name] for name in (
                "activationId", "replayId", "canaryId", "generationId", "generationPublicationEnvelopeSha256", "readyStateSha256",
                "readinessRequestId", "readinessResultSha256", "readinessCoreSha256", "publicationBefore", "publicationAfter", "trustCheckpoint",
                "issuedAtUnixNanos", "expiresAtUnixNanos")}, "assignmentSha256": result["core"]["assignmentSha256"],
                "assignmentPayloadSha256": result["core"]["assignmentPayloadSha256"], "assignmentRevision": assignment["assignmentRevision"],
                "authorityKeyIndependenceSha256": assignment["authorityKeyIndependence"]["independenceRootSha256"],
                "approvalOriginal": p.canonical(row).decode("ascii"), "readinessOriginal": p.canonical(result).decode("ascii"),
                "readyOriginal": p.canonical(ready).decode("ascii"), "controlPlaneConfigurationSha256": value["control_plane_configuration_digest"],
                "activationPolicySha256": p.sha256(p.canonical(value["activation_policy"]))})
            prepared_original, prepared_sha = p.canonical(prepared).decode("ascii"), p.sha256(p.canonical(prepared))
            p.require(state.one(profile.PREPARATION_TABLE, optional=True, canary_id=ready["canaryId"]) is None)
            state.put(profile.PREPARATION_TABLE, {"canary_id": ready["canaryId"], "activation_id": prepared["activationId"], "replay_id": prepared["replayId"],
                "approval_id": item_id, "requester_id": value["actor_id"], "prepared_original": prepared_original, "prepared_sha256": prepared_sha,
                "request_digest": context.request_digest, "audit_outbox_id": shared._audit_identity(self.operation, context.request_digest), "audit_event_digest": audit_digest,
                "publication_original": None, "publication_sha256": None, "publication_request_sha256": None,
                "publication_audit_id": None, "publication_audit_digest": None})
            state.put(hold.TABLE, hold.original({"scope": hold.SCOPE, "phase": "held", "canary_id": ready["canaryId"], "activation_id": prepared["activationId"],
                "prepared_sha256": prepared_sha, "prepare_request_digest": context.request_digest, "configuration_digest": value["control_plane_configuration_digest"],
                "guard_sha256": hold.GUARD_SHA256, "issued_at_epoch_ns": prepared["issuedAtUnixNanos"], "expires_at_epoch_ns": prepared["expiresAtUnixNanos"],
                "publication_sha256": None, "finalization_digest": None}), replace=existing_hold is not None)
        mutations.append(core.mutation(operation=self.operation, selected=selected, row=row))
        for (table, _), changed in state.changed.items():
            mutations.append(core.mutation(operation=self.operation, selected=context.exact(table, tables.key(table, changed)), row=changed))
        result = {"ok": True, "operation": self.operation, "requestDigest": context.request_digest, "auditEventDigest": audit_digest,
            "idempotentReplay": False, "approval": db.row_to_control_plane_approval(row), "preparedOriginal": prepared_original,
            "preparedSha256": prepared_sha, "readyOriginal": p.canonical(ready).decode("ascii")}
        p.require(set(result) == profile.RESULT_FIELDS)
        return core.KernelTransition(mutations=tuple(mutations) + audit, result=result, work_units=state.work_units + 96)


KERNELS = MappingProxyType({operation: NativeActivationKernel(operation) for operation in profile.OPERATIONS})
