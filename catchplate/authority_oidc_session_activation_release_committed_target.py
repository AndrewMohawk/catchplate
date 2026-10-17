"""Bounded release-target comparison, not original or commit admission.

Inputs are ordinary data. The original-consuming caller must authenticate the
packet, replay, commit, completion and state ACK, then separately join the full
activation provenance. No returned dictionary is a proof or release capability.
"""
from __future__ import annotations

from catchplate import authority_oidc_session_activation_completion_admission as activation_admission
from catchplate import authority_oidc_session_activation_delivery_execution_expectations as expectations_wire
from catchplate import authority_oidc_session_activation_release_intent as intent
from catchplate import authority_successor_execution_packet as packet
from catchplate import authority_successor_execution_recovery_packet as recovery_packet
from catchplate import authority_transition_oidc_session_activation_delivery as consumption


assertion, registration = consumption.assertion, consumption.registration
core, capacity, delivery = consumption.core, consumption.capacity, consumption.delivery
evidence = registration.evidence
OPERATION = consumption.OPERATION
_PROJECTED_FIELDS = frozenset({"operation", "requestDigest", "operationId", "selectedRows",
    "mutations", "result", "workUnits", "marker"})
_RESULT_FIELDS = frozenset({"schema", "status", "deliveryId", "sessionId", "userId",
    "credentialId", "credentialRecordId", "challengeId", "assertionDigest", "newTokenDigest",
    "deliveryEnvelopeDigest", "consumedAt", "tokenReleased"})
_EVENT_FIELDS = frozenset({"delivery_id", "session_id", "user_id", "credential_record_id",
    "challenge_id", "assertion_digest", "delivery_envelope_digest", "trust_high_water_digest",
    "consumed_at"})
_AUDIT_FIELDS = frozenset({"id", "event_type", "actor_type", "actor_id", "event_json",
    "event_digest", "storage_format_version", "status", "claim_id", "claimed_at", "attempts",
    "audited_at", "audit_event_hash", "last_error", "created_at"})
MAX_EVENT_BYTES = 128 * 1024


class OidcSessionActivationReleaseCommittedTargetError(ValueError):
    pass


def _fail(message):
    raise OidcSessionActivationReleaseCommittedTargetError(message)


def _scope_digest_on_work(delivery_scope, work):
    """Fingerprint the exact eleven fields; this does not authenticate them."""
    owned = assertion._Capture(evidence.capture._SharedLedger(work),
        maximum_bytes=intent.MAX_BYTES).visit(delivery_scope)
    intent.bootstrap._scope(owned, work)
    return evidence.plan._frame(activation_admission.DELIVERY_SCOPE_DOMAIN,
        (registration._wire(owned, work),), work)


def _capture(packet_payload, expectations, expected_release, work):
    registration._closed(packet_payload, packet.PACKET_FIELDS, "release target packet data")
    expectations_wire._shape(expectations)
    registration._closed(expected_release, intent.RELEASE_FIELDS, "release target expectations")
    if (type(packet_payload["selectedRows"]) is not list
            or len(packet_payload["selectedRows"]) != consumption.MAX_SELECTED_ROWS
            or type(packet_payload["mutations"]) is not list or len(packet_payload["mutations"]) != 3):
        _fail("release target requires the exact consume row/effect inventory")
    # Opaque packet originals and complete vectors are admitted by the caller;
    # they are not copied or treated as proof by this target-only projection.
    # All graphs used below are detached together before hashing any commitment.
    projected = {name: packet_payload[name] for name in _PROJECTED_FIELDS}
    return assertion._Capture(evidence.capture._SharedLedger(work),
        maximum_bytes=packet.MAX_BYTES).visit({"packet": projected,
            "expectations": expectations, "release": expected_release})


def _selected_inventory(rows, work):
    seen = set()
    work.prepare_scan(rows)
    for selected in rows:
        registration._closed(selected, capacity._SELECTED_FIELDS, "release target selected row")
        registration._text(selected["table"], "release target table", 128, work)
        registration._digest(selected["keyDigest"])
        if type(selected["key"]) is not dict or type(selected["present"]) is not bool:
            _fail("release target selected key/presence is malformed")
        if ((selected["present"] and type(selected["row"]) is not dict)
                or (not selected["present"] and selected["row"] is not None)):
            _fail("release target selected row presence differs")
        identity = (selected["table"], selected["keyDigest"])
        work.prepare_comparison(identity, tuple(seen))
        if identity in seen:
            _fail("release target selected identity is duplicated")
        seen.add(identity)


def _selected(rows, table, key, present, work):
    matches = []
    work.prepare_scan(rows)
    for selected in rows:
        work.prepare_comparison((selected["table"], selected["key"]), (table, key))
        if selected["table"] == table and selected["key"] == key:
            matches.append(selected)
    if len(matches) != 1 or matches[0]["present"] is not present:
        _fail("release target selected identity/presence does not match")
    return matches[0]


def _mutations(entries, work):
    owned = {}
    work.prepare_scan(entries)
    for item in entries:
        registration._closed(item, capacity._MUTATION_FIELDS, "release target mutation")
        table = item["table"]
        if type(table) is not str or table not in (
                "oidc_session_activation_deliveries", capacity.OUTBOX_TABLE, capacity.AGGREGATE_TABLE):
            _fail("release target mutation table is outside the exact consume effects")
        if table in owned or type(item["row"]) is not dict:
            _fail("release target mutation is duplicated or malformed")
        owned[table] = item
    if len(owned) != 3:
        _fail("release target omits an actual consume mutation")
    return owned


def _mutation_matches(actual, selected, after, work):
    work.prepare_copy(selected["key"])
    if selected["present"]:
        work.prepare_copy(selected["row"])
    work.prepare_copy(after)
    expected = core.mutation(operation=OPERATION, selected=selected, row=after)
    registration._same(actual, expected, work, "release target source mutation")


def _audit_on_work(mutation, selected, arguments, request_digest, envelope_digest, consumed_at, work):
    audit = mutation["row"]
    registration._closed(audit, _AUDIT_FIELDS, "release target deterministic audit")
    registration._integer(audit["storage_format_version"], "release target audit format", 2, 2)
    registration._integer(audit["attempts"], "release target audit attempts", 0, 0)
    encoded = audit["event_json"]
    registration._text(encoded, "release target audit event", MAX_EVENT_BYTES, work)
    work.charge(input_bytes=len(encoded))
    try:
        original = encoded.encode("ascii")
    except UnicodeError as exc:
        raise OidcSessionActivationReleaseCommittedTargetError("release target audit is not canonical ASCII") from exc
    event = evidence.wire._decode_object(original, work=work,
        maximum_bytes=MAX_EVENT_BYTES, maximum_nodes=64, maximum_depth=2)
    registration._closed(event, _EVENT_FIELDS, "release target audit event")
    registration._digest(event["trust_high_water_digest"])
    expected_event = {"delivery_id": arguments["delivery_id"], "session_id": arguments["session_id"],
        "user_id": arguments["user_id"], "credential_record_id": arguments["credential_record_id"],
        "challenge_id": arguments["challenge_id"], "assertion_digest": arguments["assertion_digest"],
        "delivery_envelope_digest": envelope_digest,
        "trust_high_water_digest": event["trust_high_water_digest"], "consumed_at": consumed_at}
    registration._same(event, expected_event, work, "release target audit binding")
    event_raw = registration._wire(expected_event, work)
    registration._same(original, event_raw, work, "release target audit canonical original")
    audit_id = core._deterministic_uuid(operation=OPERATION, request_digest=request_digest,
        purpose=consumption.AUDIT_PURPOSE, work=work)
    expected = {"id": audit_id, "event_type": "oidc.browser_session.activation_delivery_consumed",
        "actor_type": "admin", "actor_id": arguments["user_id"], "event_json": encoded,
        "event_digest": evidence.plan._frame("catchplate.metadataAuditOutboxEvent/v1", (event_raw,), work),
        "storage_format_version": 2, "status": "pending", "claim_id": None, "claimed_at": None,
        "attempts": 0, "audited_at": None, "audit_event_hash": None, "last_error": None,
        "created_at": consumed_at}
    _mutation_matches(mutation, selected, expected, work)


def _match_on_work(*, packet_payload, expectations, expected_release, work):
    """Compare ordinary owned data; the caller supplies every proof obligation."""
    held = _capture(packet_payload, expectations, expected_release, work)
    payload, release = held["packet"], held["release"]
    expected = expectations_wire._capture_on_work(held["expectations"], work=work)
    request = expected["request"]
    arguments = consumption._arguments(request["arguments"], work)
    registration._same((payload["operation"], payload["requestDigest"], payload["operationId"]),
        (OPERATION, request["requestDigest"], request["operationId"]), work, "release target consume request")
    for field in intent.RELEASE_FIELDS - {"deliveryScope", "consumeBinding"}:
        registration._digest(release[field])
    registration._closed(release["consumeBinding"], intent.contract.CONSUME_BINDING_FIELDS,
        "release target consume identities")
    for value in release["consumeBinding"].values():
        registration._digest(value)
    registration._same(release["consumeRequestDigest"], request["requestDigest"], work,
        "release target consume identity")
    created_ns, expires_ns = intent.bootstrap._scope(release["deliveryScope"], work)
    # These are consistency derivations from the *expected* full hash, not a
    # way to recover/authenticate that hash from the truncated delivery UUID.
    activation_id = evidence.plan._frame("catchplate.policyAuthorityOperation/v2",
        (evidence.plan._ascii(intent.bootstrap.ACTIVATION_OPERATION, work),
         evidence.plan._ascii(release["activationRequestDigest"], work)), work)
    registration._same(release["activationOperationId"], activation_id, work, "release activation operation")
    delivery_id = core._deterministic_uuid(operation=intent.bootstrap.ACTIVATION_OPERATION,
        request_digest=release["activationRequestDigest"],
        purpose=consumption.activation.DELIVERY_PURPOSE, work=work)
    registration._same(arguments["delivery_id"], delivery_id, work, "release activation delivery identity")

    rows, entries = payload["selectedRows"], payload["mutations"]
    _selected_inventory(rows, work)
    selected = _selected(rows, "oidc_session_activation_deliveries", {"id": delivery_id}, True, work)
    row = selected["row"]
    registration._closed(row, consumption._DELIVERY_FIELDS, "release target original delivery")
    registration._same((row["id"], row["session_id"], row["credential_record_id"], row["challenge_id"],
        row["old_token_digest"], row["new_token_digest"], row["assertion_digest"], row["consumed_at"]),
        (delivery_id, arguments["session_id"], arguments["credential_record_id"], arguments["challenge_id"],
         arguments["old_token_digest"], arguments["new_token_digest"], arguments["assertion_digest"], None),
        work, "release target original delivery binding")
    session = _selected(rows, "oidc_browser_sessions", {"id": arguments["session_id"]}, True, work)["row"]
    credential = _selected(rows, "webauthn_credentials",
        {"id": arguments["credential_record_id"]}, True, work)["row"]
    registration._closed(session, assertion._SESSION_FIELDS, "release target session")
    registration._closed(credential, assertion._CREDENTIAL_FIELDS, "release target credential")
    registration._same((session["id"], session["user_id"], session["token_digest"],
        session["bound_webauthn_credential_id"], credential["id"], credential["credential_id"], credential["user_id"]),
        (arguments["session_id"], arguments["user_id"], arguments["new_token_digest"],
         arguments["credential_record_id"], arguments["credential_record_id"], arguments["credential_id"], arguments["user_id"]),
        work, "release target session/credential subjects")
    scope = {"deliveryId": row["id"], "userId": arguments["user_id"], "sessionId": row["session_id"],
        "credentialId": arguments["credential_id"], "credentialRecordId": row["credential_record_id"],
        "challengeId": row["challenge_id"], "assertionDigest": row["assertion_digest"],
        "oldTokenDigest": row["old_token_digest"], "newTokenDigest": row["new_token_digest"],
        "createdAt": row["created_at"], "expiresAt": row["expires_at"]}
    registration._same(scope, release["deliveryScope"], work, "release target complete delivery scope")
    envelope_digest = consumption._ciphertext_on_work(row, work)
    registration._same(envelope_digest, release["deliveryEnvelopeDigest"], work, "release target ciphertext")
    result = payload["result"]
    registration._closed(result, _RESULT_FIELDS, "release target consume result")
    if result["tokenReleased"] is not False:
        _fail("release target consumption result must not claim token release")
    consumed_at = result["consumedAt"]
    consumed = registration._utc(consumed_at, "release target original consumption", work)
    if consumed.isoformat() != consumed_at or not created_ns <= registration._now(consumed) < expires_ns:
        _fail("release target consumption lies outside the original delivery interval")
    expected_result = {"schema": consumption.RESULT_SCHEMA, "status": "delivery-consumption-effects-derived",
        "deliveryId": delivery_id, "sessionId": arguments["session_id"], "userId": arguments["user_id"],
        "credentialId": arguments["credential_id"], "credentialRecordId": arguments["credential_record_id"],
        "challengeId": arguments["challenge_id"], "assertionDigest": arguments["assertion_digest"],
        "newTokenDigest": arguments["new_token_digest"], "deliveryEnvelopeDigest": envelope_digest,
        "consumedAt": consumed_at, "tokenReleased": False}
    registration._same(result, expected_result, work, "release target exact consume result")
    mutations = _mutations(entries, work)
    work.prepare_copy(row)
    after = {**row, "consumed_at": consumed_at}
    _mutation_matches(mutations["oidc_session_activation_deliveries"], selected, after, work)
    audit_id = core._deterministic_uuid(operation=OPERATION, request_digest=request["requestDigest"],
        purpose=consumption.AUDIT_PURPOSE, work=work)
    audit_selected = _selected(rows, capacity.OUTBOX_TABLE, {"id": audit_id}, False, work)
    _audit_on_work(mutations[capacity.OUTBOX_TABLE], audit_selected, arguments,
        request["requestDigest"], envelope_digest, consumed_at, work)
    capacity._validate_capacity_transition(operation=OPERATION, selected_rows=rows, mutations=entries, work=work)
    effects_digest = recovery_packet._effects_digest_on_work(selected_rows=rows, mutations=entries,
        result=result, work_units=payload["workUnits"], work=work)
    registration._same(effects_digest, release["consumeBinding"]["effectsDigest"], work,
        "release target exact effects identity")
    marker = payload["marker"]
    registration._closed(marker, frozenset(registration.authority.CURRENT_ROOT_COMMIT_MARKER_COLUMNS),
        "release target marker data")
    registration._same((marker["pending_decision_digest"], marker["after_vector_digest"]),
        (release["consumeBinding"]["pendingDecisionDigest"], release["consumeBinding"]["afterVectorDigest"]),
        work, "release target marker identities")
    # Packet/completion identities, marker/vector authenticity and the four
    # full predecessor provenance facts remain the original verifier's joins.
    return release
