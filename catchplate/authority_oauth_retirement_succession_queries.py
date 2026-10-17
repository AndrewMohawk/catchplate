"""Finite real source acquisition; no arbitrary table or proof subtraction."""
from catchplate import authority_oauth_retirement_succession as p
from catchplate import authority_oauth_retirement_succession_records as records
from catchplate import authority_oauth_retirement_succession_snapshots as snapshots
from catchplate import authority_credential_currentness as current
from catchplate import authority_oauth_exchange as exchange
from catchplate import authority_transition_credential_currentness as currentness
from catchplate import authority_transition_core as core
from catchplate import authority_transition_quota as shared
from catchplate import authority_transition_webauthn as assertion


def approval_id(operation, values, request_digest):
    return values["approval_id"] or core.deterministic_uuid(operation=operation, request_digest=request_digest, purpose="oauth-succession-approval")


def build(operation, arguments, request_digest, evidence):
    values = p.arguments(operation, arguments, typed=True)
    grant = p.grant_document(p.decoded(values["authorization_original"], p.MAX_GRANT_BYTES))["payload"]
    identifier = grant["authorizationId"]
    result = [shared._query(operation=operation, name="succession_authorization", table=p.JOURNAL_TABLE,
        key={"id": identifier}, require_absence=operation == p.OP_AUTHORIZE),
        shared._role_query(operation, "actor_role", values["actor_id"]), records.head_query(operation, grant["providerId"])]
    if operation == p.OP_AUTHORIZE:
        result.append(core.BoundedQuery(query_id=core.query_program_id(operation, "complete_population", p.JOURNAL_TABLE),
            table=p.JOURNAL_TABLE, predicates=(), order_by=(core.QueryOrder("id"),), maximum_rows=p.MAX_HISTORY + 1,
            proof_primitive="bounded-limit-plus-one", work_units=p.MAX_HISTORY + 1))
    if operation in p.SNAPSHOT_OPERATIONS or operation in {p.OP_AUTHORIZE_DECIDE, p.OP_FENCE}:
        result.extend(snapshots.queries(operation, identifier))
    if operation not in p.SNAPSHOT_OPERATIONS:
        for index, pin in enumerate(grant["affectedLineages"]):
            result.extend((shared._query(operation=operation, name="succession_credential_" + str(index), table="credentials", key={"id": pin["credentialId"]}),
                shared._query(operation=operation, name="succession_generation_" + str(index), table="credential_generations", key={"credential_id": pin["credentialId"]})))
            if operation not in {p.OP_AUTHORIZE, p.OP_AUTHORIZE_DECIDE}:
                root_key = {"id": current.root_id(pin["credentialId"], pin["credentialVersion"])}
                result.extend((currentness.root_query(operation, pin["credentialId"], pin["credentialVersion"], name="succession_root_" + str(index)),
                    shared._query(operation=operation, name="succession_barrier_" + str(index), table=current.BARRIER_TABLE,
                        key={"id": core.SelectedRowFieldReference(current.ROOT_TABLE, root_key, "barrier_id")})))
        if operation in {p.OP_AUTHORIZE, p.OP_AUTHORIZE_DECIDE, p.OP_FENCE}:
            result.extend(records.predecessor_queries(operation, grant["predecessors"]))
    if operation not in p.SNAPSHOT_OPERATIONS and operation not in {p.OP_AUTHORIZE, p.OP_AUTHORIZE_DECIDE}:
        result.append(shared._query(operation=operation, name="succession_scope", table=p.SCOPE_TABLE,
            key={"id": identifier}, require_absence=operation == p.OP_FENCE))
    if operation in p.NATIVE_OPERATIONS | {p.OP_REQUEST, p.OP_DECIDE, p.OP_ACTIVATE}:
        for index, pin in enumerate(grant["materials"]):
            claim = p.material_claim_id(identifier, pin["materialId"])
            result.append(shared._query(operation=operation, name="succession_material_" + str(index), table=p.MATERIAL_TABLE,
                key={"id": claim}, require_absence=operation == p.OP_MATERIAL and values["request"]["materialId"] == pin["materialId"]))
            for purpose in pin["tokenPurposes"]:
                result.append(shared._query(operation=operation, name="succession_contact_" + str(index) + "_" + purpose,
                    table=p.ATTEMPT_TABLE, key={"id": p.attempt_id(claim, purpose)}))
        result.extend(shared._query(operation=operation, name=name, table=table, key={"id": identifier}, require_absence=operation == p.OP_PREPARE)
            for name, table in (("succession_custody", p.TABLE), ("succession_exchange", exchange.TABLE)))
        result.append(shared._query(operation=operation, name="succession_next_association", table=p.ASSOCIATION_TABLE,
            key={"id": p.association_id(grant["credentialId"], grant["credentialVersion"] + 1)}, require_absence=operation == p.OP_ACTIVATE))
        result.append(shared._query(operation=operation, name="succession_previous_association", table=p.ASSOCIATION_TABLE,
            key={"id": p.association_id(grant["credentialId"], grant["credentialVersion"])}))
    if operation == p.OP_PREPARE:
        result.append(core.BoundedQuery(query_id=core.query_program_id(operation, "complete_population", exchange.TABLE),
            table=exchange.TABLE, predicates=(), order_by=(core.QueryOrder("id"),), maximum_rows=p.MAX_HISTORY + 1,
            proof_primitive="bounded-limit-plus-one", work_units=p.MAX_HISTORY + 1))
    if evidence is not None:
        p.require(operation in p.ASSERTION_OPERATIONS)
        for name, table, field in (("assertion_credential", "webauthn_credentials", "credentialRecordId"), ("assertion_challenge", "webauthn_challenges", "challengeId")):
            core.require_text(evidence.get(field), field, maximum_bytes=1024)
            result.append(shared._query(operation=operation, name=name, table=table, key={"id": evidence[field]}))
        result.extend(assertion._trust_queries(operation, work=None))
    else:
        p.require(operation not in p.ASSERTION_OPERATIONS)
    if operation in p.ASSERTION_OPERATIONS | {p.OP_FENCE}:
        item = approval_id(operation, values, request_digest)
        result.append(shared._query(operation=operation, name="approval", table="control_plane_approvals", key={"id": item},
            require_absence=operation in {p.OP_AUTHORIZE, p.OP_REQUEST}))
        if operation in {p.OP_AUTHORIZE, p.OP_REQUEST}:
            result.append(shared._aggregate_query(operation, "approval_capacity", "control-plane-approvals", "global"))
        else:
            result.append(shared._role_query(operation, "other_role", core.SelectedRowFieldReference("control_plane_approvals", {"id": item},
                "requester_id" if operation in {p.OP_AUTHORIZE_DECIDE, p.OP_DECIDE} else "approved_by")))
        if operation in {p.OP_ACTIVATE, p.OP_FENCE}:
            result.append(shared._query(operation=operation, name="approver_credential", table="webauthn_credentials",
                key={"id": core.SelectedRowFieldReference("control_plane_approvals", {"id": item}, "approver_webauthn_credential_id")}))
            if operation == p.OP_FENCE:
                result.extend(assertion._trust_queries(operation, work=None))
                result.append(shared._query(operation=operation, name="requester_credential", table="webauthn_credentials",
                    key={"id": core.SelectedRowFieldReference(p.JOURNAL_TABLE, {"id": identifier}, "requester_credential_id")}))
    if operation == p.OP_ACTIVATE:
        result.append(currentness.root_query(operation, grant["credentialId"], grant["credentialVersion"] + 1,
            absent=True, name="next_currentness_root"))
    result.append(shared._audit_query(operation, request_digest))
    # There is no aggregate query-row subtraction. A snapshot reads <=65
    # source rows. Other phases read fixed exact points; PREPARE additionally
    # proves its complete <=64 exchange history. The actual contract validator
    # still meters every acquisition and enforces MAX_QUERY_PROOFS=256.
    return tuple(result)
