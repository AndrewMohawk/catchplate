"""Unregistered exact-PK registration evidence admission query/kernel adapters.

The owning composition must authenticate every selected primary row and the
current roots, admit the ceremony/trust snapshot and enrollment authorization,
and hold independent signer pins and current database time. This module runs
the real original registration and evidence verification itself; neither a
KernelContext nor a supplied evidence status is admission authority.

The only proposed business effect is an INSERT of the exact verified v2
evidence row. An identical unused verified row proposes no mutation after the
same genuine verification. No challenge, credential, session, trust or outbox
row is changed; final registration separately proves and consumes its complete
sibling/history populations. There is no capacity query, SQL, signing, clock,
durable receipt, registry activation or additional work allowance here.
"""
from __future__ import annotations

from catchplate import authority_webauthn_registration_admission as admission


registration, evidence = admission.registration, admission.evidence
authority, core, trust = registration.authority, registration.core, registration.trust
OPERATION = "webauthn.registration.evidence.admit"
HANDLER = "admit_webauthn_registration_evidence"
MAX_SELECTED_ROWS = 5
_ARGUMENT_FIELDS = frozenset({"evidence_digest", "registration_challenge_id",
    "published_publication_id", "oidc_session_id", "businessIntent"})


class WebAuthnRegistrationAdmissionTransitionError(ValueError):
    pass


def _arguments(arguments, work):
    registration._closed(arguments, _ARGUMENT_FIELDS, "evidence admission arguments")
    registration._digest(arguments["evidence_digest"])
    for name in ("registration_challenge_id", "published_publication_id"):
        registration._text(arguments[name], name, 4096, work)
    if arguments["oidc_session_id"] is not None:
        registration._text(arguments["oidc_session_id"], "OIDC session ID", 4096, work)
    work.prepare_copy(arguments)
    semantic = {name: value for name, value in arguments.items() if name != "businessIntent"}
    registration._same(arguments["businessIntent"],
        authority._synthesize_business_intent(OPERATION, semantic, work=work), work,
        "evidence admission business intent")
    return arguments


def _query_recipe_on_work(*, arguments, work):
    """Return four exact PK declarations, plus the optional exact OIDC PK."""
    ledger = evidence.capture._SharedLedger(work)
    arguments = _arguments(evidence.capture._JSONCapture(ledger,
        maximum_bytes=authority.MAX_REQUEST_BYTES).visit(arguments), work)
    values = [("evidence", evidence.EVIDENCE_TABLE, "evidence_digest", arguments["evidence_digest"]),
        ("registration_challenge", "webauthn_challenges", "id", arguments["registration_challenge_id"]),
        ("trust_high_water", trust.HIGH_WATER_TABLE, "authority_scope", trust.AUTHORITY_SCOPE),
        ("published_publication", trust.PUBLICATION_TABLE, "id", arguments["published_publication_id"])]
    if arguments["oidc_session_id"] is not None:
        values.append(("pending_oidc_session", "oidc_browser_sessions", "id", arguments["oidc_session_id"]))
    queries = tuple(core.BoundedQuery(query_id=core.query_program_id(OPERATION, name, table),
        table=table, predicates=(core.QueryPredicate(column, "eq", value),),
        order_by=(core.QueryOrder(column),), maximum_rows=1, absent_key={column: value})
        for name, table, column, value in values)
    spec = authority.operation_spec(OPERATION)
    if (len(queries) > MAX_SELECTED_ROWS or len(queries) > spec["maximumBusinessQueryRows"]
            or sum(query.work_units for query in queries) > spec["maximumBusinessWorkUnits"]):
        raise WebAuthnRegistrationAdmissionTransitionError("registration admission queries exceed their source bound")
    return core.close_queries(OPERATION, queries)


def _kernel_transition_on_work(context, *, envelope_bytes, client_data_json,
        attestation_object, credential_id, transports, scope, verification_context,
        expected_authorization, public_key, expected_signer_identity,
        expected_signer_spki_digest, maximum_age_ns, maximum_clock_skew_ns, work):
    """Reverify original ceremony/evidence and propose one insertion or no-op.

    Current time comes only from the independently held context database UTC;
    the actual verification_context supplies the separate historical ceremony
    instant. The semantic composer owns that context and every remaining raw
    ceremony input before any native constructor/parser/key callback. No
    successful claims tuple, verified-row DTO or signer is accepted here.
    """
    ledger = evidence.capture._SharedLedger(work)
    if (type(context) is not core.KernelContext or type(context.operation) is not str
            or context.operation != OPERATION or type(context.arguments) is not dict
            or type(context.selected_rows) is not tuple
            or not 4 <= len(context.selected_rows) <= MAX_SELECTED_ROWS
            or any(type(item) is not dict for item in context.selected_rows)):
        raise WebAuthnRegistrationAdmissionTransitionError("registration admission requires an exact bounded context")
    request_digest, database_now = context.request_digest, context.database_now
    core.require_digest(request_digest, "registration evidence admission request digest")
    now_ns = registration._now(database_now)
    registration._integer(maximum_age_ns, "admission maximum age", 1, authority.VERIFIER_RESPONSE_MAX_AGE_NS)
    registration._integer(maximum_clock_skew_ns, "admission clock skew", 0, authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    registration._digest(expected_signer_spki_digest)
    if type(scope) is not admission.production.attestation.CeremonyScope:
        raise WebAuthnRegistrationAdmissionTransitionError("registration admission has no exact ceremony scope")
    work.prepare_copy(context.selected_rows)
    owned = evidence.capture._JSONCapture(ledger).visit({
        "arguments": context.arguments, "selected": list(context.selected_rows),
        "authorization": expected_authorization, "identity": expected_signer_identity})
    arguments = _arguments(owned["arguments"], work)
    evidence._identity(owned["identity"])
    expected_count = 4 + int(arguments["oidc_session_id"] is not None)
    spec = authority.operation_spec(OPERATION)
    if len(owned["selected"]) != expected_count or expected_count > spec["maximumBusinessQueryRows"]:
        raise WebAuthnRegistrationAdmissionTransitionError("registration admission selection is not its exact PK inventory")
    for selected in owned["selected"]:
        evidence.plan.contract._object(selected, evidence.capture._SELECTED_FIELDS, "registration admission selection")
        core.require_digest(selected["keyDigest"], "registration admission selected key digest")
        if (type(selected["table"]) is not str or type(selected["key"]) is not dict
                or type(selected["present"]) is not bool
                or (selected["present"] and type(selected["row"]) is not dict)
                or (not selected["present"] and selected["row"] is not None)):
            raise WebAuthnRegistrationAdmissionTransitionError("registration admission selection is not exact row data")
    work.prepare_copy(owned["selected"])
    held = core.KernelContext(OPERATION, arguments, tuple(owned["selected"]), database_now, request_digest)
    selected_evidence = held._exact(evidence.EVIDENCE_TABLE, {"evidence_digest": arguments["evidence_digest"]}, work=work)
    challenge = held._exact("webauthn_challenges", {"id": arguments["registration_challenge_id"]}, work=work)
    high = held._exact(trust.HIGH_WATER_TABLE, {"authority_scope": trust.AUTHORITY_SCOPE}, work=work)
    published = held._exact(trust.PUBLICATION_TABLE, {"id": arguments["published_publication_id"]}, work=work)
    for selected in (challenge, high, published):
        if selected["present"] is not True:
            raise WebAuthnRegistrationAdmissionTransitionError("registration admission requires its challenge and predecessor rows")
    session = None
    if arguments["oidc_session_id"] is not None:
        selected = held._exact("oidc_browser_sessions", {"id": arguments["oidc_session_id"]}, work=work)
        if selected["present"] is not True:
            raise WebAuthnRegistrationAdmissionTransitionError("registration admission requires its pending OIDC session")
        session = selected["row"]
        registration._same(session.get("id"), arguments["oidc_session_id"], work, "admission OIDC row identity")
    registration._same(scope.challenge_id, arguments["registration_challenge_id"], work, "admission ceremony challenge")
    registration._same(published["row"].get("id"), arguments["published_publication_id"], work,
        "admission published row identity")
    actual_digest = evidence._evidence_digest_on_work(envelope_bytes, work)
    registration._same(actual_digest, arguments["evidence_digest"], work, "admission original evidence identity")
    selected, proposed = admission._admit_on_work(envelope_bytes=envelope_bytes,
        selected_evidence=selected_evidence, client_data_json=client_data_json,
        attestation_object=attestation_object, credential_id=credential_id, transports=transports,
        scope=scope, verification_context=verification_context, challenge_row=challenge["row"],
        expected_authorization=owned["authorization"], high_water_row=high["row"],
        published_row=published["row"], oidc_session_row=session, sibling_challenge_ids=[],
        public_key=public_key, expected_signer_identity=owned["identity"],
        expected_signer_spki_digest=expected_signer_spki_digest, now_epoch_ns=now_ns,
        maximum_age_ns=maximum_age_ns, maximum_clock_skew_ns=maximum_clock_skew_ns, work=work)
    if proposed is None:
        mutations = ()
    else:
        if selected["present"] is not False:
            raise WebAuthnRegistrationAdmissionTransitionError("registration evidence admission cannot update a row")
        work.prepare_copy(selected["key"])
        work.prepare_copy(proposed)
        mutations = (core.mutation(operation=OPERATION, selected=selected, row=proposed),)
    if len(mutations) > spec["maximumBusinessMutations"]:
        raise WebAuthnRegistrationAdmissionTransitionError("registration evidence admission exceeds its mutation bound")
    business_work = 8 + expected_count + 4 * len(mutations)
    if business_work > spec["maximumBusinessWorkUnits"]:
        raise WebAuthnRegistrationAdmissionTransitionError("registration evidence admission exceeds its work bound")
    result = {"evidence_digest": actual_digest,
        "admission": "already-retained" if proposed is None else "proposed-insert"}
    work.prepare_encoding(result)
    return core.KernelTransition(mutations=mutations, result=result, work_units=business_work)
