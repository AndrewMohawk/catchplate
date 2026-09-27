"""Pure original/proof-derived one-use activation delivery consumption.

The caller independently admits subject, current policy/trust, complete roots,
database clock and activation/completion provenance. Actual primary and complete
range proofs are replayed here, and the original old token is hashed here: a
claimed digest or successful result cannot replace either obligation.

This worker derives a delivery CAS, deterministic audit and real shared capacity
CAS. It neither decrypts ciphertext nor executes SQL, releases a token, supplies
fresh public consent or treats consumed_at as a committed-release receipt.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable
import time

from serverware import authority_oidc_session_activation_delivery_reads as reads
from serverware import authority_transition_oidc_session_activation as activation


assertion, registration = activation.assertion, activation.registration
core, support, capacity, delivery = activation.core, activation.support, activation.capacity, activation.delivery
OPERATION = "oidc.session.activation-delivery.consume"
RESULT_SCHEMA = "serverware.oidcSessionActivationDeliveryConsumptionEffects/v1"
AUDIT_PURPOSE = "activation-delivery-consume-audit"
MAX_SELECTED_ROWS = 10
_ARGUMENT_FIELDS = frozenset({"delivery_id", "session_id", "user_id", "credential_id",
    "credential_record_id", "challenge_id", "old_token_digest", "new_token_digest",
    "assertion_digest", "businessIntent"})
_DELIVERY_FIELDS = frozenset({"id", "session_id", "old_token_digest", "new_token_digest",
    "assertion_digest", "challenge_id", "credential_record_id", "encrypted_active_token",
    "created_at", "expires_at", "consumed_at"})


class OidcSessionActivationDeliveryConsumptionError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _FullTransition:
    """Same-call effects/liveness; no API accepts this as a proof input."""

    transition: core.KernelTransition
    live: Callable[[], int]
    valid_until_epoch_ns: int


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _HistoricalFullTransition:
    transition: core.KernelTransition
    live: Callable[[], int]
    valid_until_epoch_ns: int
    historical_plan_interval: tuple


def _historical_interval(value):
    if type(value) is not tuple or len(value) != 2:
        _fail("consume history requires an exact original plan interval")
    issued, expires = value
    registration._integer(issued, "original consume plan issue", 1)
    registration._integer(expires, "original consume plan expiry", 1)
    if issued >= expires:
        _fail("original consume plan interval is empty")
    return value


def _fail(message):
    raise OidcSessionActivationDeliveryConsumptionError(message)


def _arguments(values, work):
    registration._closed(values, _ARGUMENT_FIELDS, "activation delivery consumption arguments")
    for field, maximum in (("delivery_id", 128), ("session_id", 128), ("user_id", 1024),
            ("credential_id", 1366), ("credential_record_id", 1024), ("challenge_id", 1024)):
        registration._text(values[field], field, maximum, work)
    registration._encoded_original(values["credential_id"], 1024, work, minimum=1)
    for field in ("old_token_digest", "new_token_digest", "assertion_digest"):
        registration._digest(values[field])
    work.prepare_comparison(values["old_token_digest"], values["new_token_digest"])
    if values["old_token_digest"] == values["new_token_digest"]:
        _fail("activation delivery consumption requires the original token rotation")
    work.prepare_copy(values)
    semantic = {name: value for name, value in values.items() if name != "businessIntent"}
    expected = registration.authority._synthesize_business_intent(OPERATION, semantic, work=work)
    registration._same(values["businessIntent"], expected, work, "delivery consumption business intent")
    return values


def _ciphertext_on_work(row, work):
    """Validate only the exact stored original framing; never decrypt or claim AEAD."""
    value = row["encrypted_active_token"]
    registration._text(value, "activation delivery ciphertext", len(delivery.STORED_PREFIX) + 134, work)
    if len(value) != len(delivery.STORED_PREFIX) + 134 or not value.startswith(delivery.STORED_PREFIX):
        _fail("activation delivery uses an unknown ciphertext format")
    work.charge(input_bytes=len(value))
    original = registration._encoded_original(value[len(delivery.STORED_PREFIX):],
        delivery.ENVELOPE_BYTES, work, minimum=delivery.ENVELOPE_BYTES)
    delivery._envelope(original, work)
    return assertion._digest(original, work)


def _rows_on_work(context, values, old_token, policy, trust_policy, now_ns, work):
    """Derive current state from this invocation's genuinely proof-owned rows."""
    selected_delivery = context._exact("oidc_session_activation_deliveries",
        {"id": values["delivery_id"]}, work=work)
    selected_session = context._exact("oidc_browser_sessions", {"id": values["session_id"]}, work=work)
    selected_credential = context._exact("webauthn_credentials",
        {"id": values["credential_record_id"]}, work=work)
    selected_challenge = context._exact("webauthn_challenges", {"id": values["challenge_id"]}, work=work)
    row, session, credential, challenge = (support._row(item, work=work)
        for item in (selected_delivery, selected_session, selected_credential, selected_challenge))
    registration._closed(row, _DELIVERY_FIELDS, "activation delivery current row")
    registration._closed(session, assertion._SESSION_FIELDS, "activation delivery active session")
    registration._closed(credential, assertion._CREDENTIAL_FIELDS, "activation delivery credential")
    registration._closed(challenge, registration._CHALLENGE_FIELDS, "activation delivery challenge")
    assertion._row_text(row, integers=set(), nullable={"consumed_at"}, work=work)
    assertion._row_text(session, integers={"activation_trust_bundle_sequence"},
        nullable={"pending_expires_at", "revoked_at", "revocation_reason"}, work=work)
    assertion._row_text(credential,
        integers={"sign_count", "attestation_trusted", "attestation_trust_bundle_sequence"},
        nullable={"dev_private_key_pem", "last_used_at", "revoked_at", "revoked_by", "revocation_reason",
            "revocation_source"}, work=work)
    assertion._row_text(challenge, integers=set(), nullable={"approval_request_id", "used_at"}, work=work)
    registration._same((row["id"], row["session_id"], row["credential_record_id"], row["challenge_id"],
        row["old_token_digest"], row["new_token_digest"], row["assertion_digest"]),
        (values["delivery_id"], values["session_id"], values["credential_record_id"], values["challenge_id"],
         values["old_token_digest"], values["new_token_digest"], values["assertion_digest"]), work,
        "current delivery exact independent request")
    registration._same((session["id"], session["user_id"], session["token_digest"],
        session["bound_webauthn_credential_id"], credential["id"], credential["credential_id"],
        credential["user_id"], challenge["id"], challenge["user_id"], challenge["scope_key"]),
        (values["session_id"], values["user_id"], values["new_token_digest"], values["credential_record_id"],
         values["credential_record_id"], values["credential_id"], values["user_id"], values["challenge_id"],
         values["user_id"], values["session_id"]), work, "delivery current session and credential binding")
    if row["consumed_at"] is not None:
        _fail("activation delivery has already been consumed")
    if (session["status"] != "active" or session["pending_expires_at"] is not None
            or session["revoked_at"] is not None or session["revocation_reason"] is not None):
        _fail("activation delivery session is not currently active and unrevoked")
    if any(credential[name] is not None for name in (
            "revoked_at", "revoked_by", "revocation_reason", "revocation_source", "dev_private_key_pem")):
        _fail("activation delivery credential is revoked or development-scoped")
    registration._integer(credential["sign_count"], "current credential counter", 0, 2**32 - 1)
    registration._encoded_original(credential["public_key_cose"], 4096, work)
    if (challenge["challenge_type"] != "oidc-session-binding" or challenge["used_at"] is None
            or challenge["approval_request_id"] is not None):
        _fail("activation delivery requires its actually used original binding challenge")
    registration._digest(session["oidc_token_digest"])
    registration._digest(session["activation_trust_bundle_digest"])
    activation_sequence = registration._integer(session["activation_trust_bundle_sequence"],
        "session activation trust sequence", 1)
    if session["activation_authenticator_class"] not in assertion._CLASSES:
        _fail("activation delivery session has an unknown original authenticator class")
    # Hash the actual original possession bytes on the same work. Neither
    # selected row content nor a request-supplied digest proves possession.
    registration._same(assertion._digest(old_token, work), values["old_token_digest"], work,
        "activation delivery actual old-token possession")
    delivery_created = assertion._time(row["created_at"], "delivery creation", work)
    delivery_expires = assertion._time(row["expires_at"], "delivery expiry", work)
    session_expires = assertion._time(session["expires_at"], "active session expiry", work)
    provider_expires = assertion._time(session["provider_expires_at"], "provider expiry", work)
    if not (delivery_created <= now_ns < delivery_expires <= session_expires <= provider_expires
            and 0 < delivery_expires - delivery_created <= delivery.MAX_DELIVERY_LIFETIME_NS):
        _fail("activation delivery or active session interval is expired or inconsistent")
    for name in ("created_at", "expires_at"):
        canonical = registration._utc(row[name], name, work).isoformat()
        registration._same(row[name], canonical, work, "canonical delivery original time")
    registration._same((session["activated_at"], challenge["used_at"]),
        (row["created_at"], row["created_at"]), work, "original activation and challenge-use time")
    session_created = assertion._time(session["created_at"], "session creation", work)
    session_updated = assertion._time(session["updated_at"], "session update", work)
    challenge_created = assertion._time(challenge["created_at"], "challenge creation", work)
    challenge_expires = assertion._time(challenge["expires_at"], "original challenge expiry", work)
    if not (session_created <= delivery_created <= session_updated <= now_ns
            and challenge_created <= delivery_created < challenge_expires):
        _fail("activation delivery row chronology differs from the original activation")
    for name in ("created_at", "updated_at", "attestation_verified_at"):
        if assertion._time(credential[name], name, work) > now_ns:
            _fail("activation delivery credential time is after current database time")
    if (credential["last_used_at"] is None
            or not delivery_created <= assertion._time(credential["last_used_at"], "credential last use", work) <= now_ns):
        _fail("activation delivery credential does not retain its original activation use")
    # Validate the original used challenge's actual payload/hash without
    # replaying it as a fresh assertion or requiring its old expiry to be live.
    work.prepare_utf8(challenge["payload_json"])
    payload = assertion._json(challenge["payload_json"].encode("utf-8"), work, 64 * 1024)
    registration._closed(payload, assertion._PAYLOAD_FIELDS, "delivery original challenge payload")
    if type(payload["v"]) is not int or payload["v"] != 1:
        _fail("activation delivery original challenge version differs")
    registration._same((payload["type"], payload["session_id"], payload["user_id"], payload["session_expires_at"]),
        ("serverware.oidc_session_binding", values["session_id"], values["user_id"], session["expires_at"]),
        work, "activation delivery original challenge subject")
    pending_expiry = assertion._time(payload["pending_expires_at"], "original pending expiry", work)
    if not delivery_created < pending_expiry <= session_expires:
        _fail("activation delivery original pending interval differs")
    registration._encoded_original(payload["nonce"], 24, work, minimum=24)
    original_challenge = registration._encoded_original(challenge["challenge"], 32, work, minimum=32)
    payload_digest = assertion._digest(assertion.attestation._canonical(payload, _work=work), work)
    work.charge(input_bytes=len(original_challenge))
    registration._same("sha256:" + original_challenge.hex(), payload_digest, work,
        "activation delivery original binding payload hash")
    activation._rbac_scope(context, session, values["user_id"], now_ns, work)
    trust_digest = activation._trust_scope(context, trust_policy, now_ns, work)
    status = assertion._current_trust(credential, policy, trust_policy, work)
    if activation_sequence > trust_policy["currentBundleSequence"]:
        _fail("activation delivery session names a future trust publication")
    if activation_sequence == trust_policy["currentBundleSequence"]:
        registration._same((session["activation_trust_bundle_digest"], session["activation_authenticator_class"]),
            (trust_policy["currentBundleDigest"], status.effective_authenticator_class), work,
            "activation delivery matching current trust publication")
    # Older original session trust metadata may remain legitimate after a
    # publication advances; the actual credential must still pass CURRENT
    # independently admitted trust and class/hardware policy above.
    envelope_digest = _ciphertext_on_work(row, work)
    return selected_delivery, row, trust_digest, envelope_digest, min(delivery_expires, session_expires, provider_expires)


def _full_original_transition_on_work(context, *, old_token_bytes,
        expected_delivery_id, expected_user_id, expected_session_id, expected_credential_id,
        expected_credential_record_id, expected_challenge_id, authn_policy, trust_policy,
        business_before_roots, authorization_before_roots, before_proofs, read_heads, query_frontiers,
        live_window, transport_deadline_ns, work, historical_plan_interval):
    """Reverify original current proofs and possession, then derive three effects."""
    ledger = registration.capture._SharedLedger(work)
    historical = (None if historical_plan_interval is None
        else _historical_interval(historical_plan_interval))
    if (type(context) is not core.KernelContext or context.operation != OPERATION
            or type(context.selected_rows) is not tuple or len(context.selected_rows) != MAX_SELECTED_ROWS
            or context.verified_webauthn_evidence is not None):
        _fail("activation delivery context is not the fixed original-input profile")
    token = assertion._token(old_token_bytes, work)
    window = assertion.clock._validate(live_window)
    registration._integer(transport_deadline_ns, "activation delivery inherited deadline", 1)
    bound = min(window[4], transport_deadline_ns)
    database_now = context.database_now
    now_ns = registration._now(database_now)
    query_reads = context.query_reads
    work.prepare_copy(context.selected_rows)
    owned = assertion._Capture(ledger, maximum_bytes=assertion.MAX_CONTEXT_BYTES).visit({
        "arguments": context.arguments, "selected": list(context.selected_rows),
        "requestDigest": context.request_digest, "delivery": expected_delivery_id,
        "user": expected_user_id, "session": expected_session_id, "credential": expected_credential_id,
        "record": expected_credential_record_id, "challenge": expected_challenge_id,
        "policy": authn_policy, "trust": trust_policy})
    work.prepare_copy(owned["selected"])
    selected = tuple(owned["selected"])
    # The genuine read worker detaches every remaining proof/root/query graph
    # before hashing or native callbacks; it admits actual primary membership
    # and all seven complete ranges, never a previous successful result.
    admitted = reads._admit_on_work(arguments=owned["arguments"], request_digest=owned["requestDigest"],
        database_now=database_now, selected_rows=selected, query_reads=query_reads,
        business_before_roots=business_before_roots, authorization_before_roots=authorization_before_roots,
        before_proofs=before_proofs, read_heads=read_heads, query_frontiers=query_frontiers, work=work)
    if type(admitted) is not reads._AdmittedReads:
        _fail("activation delivery requires actual original proof admission")
    registration._same(admitted.arguments, owned["arguments"], work, "proof-owned delivery arguments")
    registration._same(admitted.selected_rows, selected, work, "proof-owned delivery selected rows")
    values = _arguments(admitted.arguments, work)
    registration._digest(owned["requestDigest"])
    registration._same((values["delivery_id"], values["user_id"], values["session_id"],
        values["credential_id"], values["credential_record_id"], values["challenge_id"]),
        (owned["delivery"], owned["user"], owned["session"], owned["credential"], owned["record"],
         owned["challenge"]), work, "independent delivery consumption subject")
    current = core.KernelContext(OPERATION, values, admitted.selected_rows, database_now,
        owned["requestDigest"], query_reads=admitted.query_reads)
    last_epoch, last_monotonic = window[0], window[2]
    processing_until = min(window[3], window[0] + bound - window[1])
    valid_until = processing_until if historical is None else historical[1]

    def live():
        nonlocal last_epoch, last_monotonic
        epoch = assertion.clock._check_on_work(window, work=work)
        monotonic = registration.evidence.production._callback(work, time.monotonic_ns)
        registration._integer(monotonic, "activation delivery monotonic sample", 1)
        if (epoch < last_epoch or monotonic < last_monotonic or monotonic >= bound
                or epoch >= processing_until or (historical is None and epoch >= valid_until)):
            _fail("activation delivery consumption window expired or reversed")
        if (historical is None and not window[0] - window[6] <= now_ns <= epoch + window[6]
                or historical is not None and now_ns > epoch + window[6]
                or now_ns >= valid_until):
            _fail("activation delivery database time is outside its current processing scope")
        last_epoch, last_monotonic = epoch, monotonic
        return epoch

    live()
    selected_delivery, row, trust_digest, envelope_digest, row_expiry = _rows_on_work(
        current, values, token, owned["policy"], owned["trust"], now_ns, work)
    if historical is not None and historical[1] > row_expiry:
        _fail("historical consume plan outlived its actual original delivery/session")
    valid_until = min(valid_until, row_expiry) if historical is None else row_expiry
    live()
    audit_id = core._deterministic_uuid(operation=OPERATION, request_digest=current.request_digest,
        purpose=AUDIT_PURPOSE, work=work)
    audit_selected = current._exact(capacity.OUTBOX_TABLE, {"id": audit_id}, work=work)
    if audit_selected["present"] is not False:
        _fail("activation delivery consumption audit identity already exists")
    now_iso = database_now.isoformat()
    work.prepare_copy(row)
    consumed = {**row, "consumed_at": now_iso}
    event = {"delivery_id": values["delivery_id"], "session_id": values["session_id"],
        "user_id": values["user_id"], "credential_record_id": values["credential_record_id"],
        "challenge_id": values["challenge_id"], "assertion_digest": values["assertion_digest"],
        "delivery_envelope_digest": envelope_digest, "trust_high_water_digest": trust_digest,
        "consumed_at": now_iso}
    event_raw = registration._wire(event, work)
    work.charge(input_bytes=len(event_raw))
    audit = {"id": audit_id, "event_type": "oidc.browser_session.activation_delivery_consumed",
        "actor_type": "admin", "actor_id": values["user_id"], "event_json": event_raw.decode("ascii"),
        "event_digest": registration.evidence.plan._frame("serverware.metadataAuditOutboxEvent/v1", (event_raw,), work),
        "storage_format_version": 2, "status": "pending", "claim_id": None, "claimed_at": None,
        "attempts": 0, "audited_at": None, "audit_event_hash": None, "last_error": None, "created_at": now_iso}
    result = {"schema": RESULT_SCHEMA, "status": "delivery-consumption-effects-derived",
        "deliveryId": values["delivery_id"], "sessionId": values["session_id"], "userId": values["user_id"],
        "credentialId": values["credential_id"], "credentialRecordId": values["credential_record_id"],
        "challengeId": values["challenge_id"], "assertionDigest": values["assertion_digest"],
        "newTokenDigest": values["new_token_digest"], "deliveryEnvelopeDigest": envelope_digest,
        "consumedAt": now_iso, "tokenReleased": False}
    effects = ((selected_delivery, consumed), (audit_selected, audit))
    spec = registration.authority.operation_spec(OPERATION)
    work.prepare_scan(current.selected_rows)
    business_rows = sum(not (item["table"] == capacity.AGGREGATE_TABLE
        and item["key"] == {"aggregate_id": capacity.AGGREGATE_ID}) for item in current.selected_rows)
    if business_rows > spec["maximumBusinessQueryRows"] or len(effects) > spec["maximumBusinessMutations"]:
        _fail("activation delivery consumption exceeds its source business inventory")
    mutations = []
    for selected_row, after in effects:
        work.prepare_copy(selected_row["key"])
        if selected_row["present"] is True:
            work.prepare_copy(selected_row["row"])
        work.prepare_copy(after)
        mutations.append(core.mutation(operation=OPERATION, selected=selected_row, row=after))
    work.prepare_copy(mutations)
    business = tuple(mutations)
    business_work = 8 + business_rows + 4 * len(business)
    if business_work > spec["maximumBusinessWorkUnits"]:
        _fail("activation delivery consumption exceeds its source business work")
    live()
    finalized = capacity._finalize_capacity(current, business, work=work)
    if len(finalized) != 3 or len(finalized) > spec["maximumMutations"]:
        _fail("activation delivery consumption lacks its three actual source mutations")
    queries = reads._queries(arguments=current.arguments,
        cutoff_us=reads.complete.cutoff_microseconds(database_now), request_digest=current.request_digest, work=work)
    total_work = capacity.transition_work_units(OPERATION,
        query_work_units=sum(query.work_units for query in queries),
        kernel_work_units=business_work, mutations=finalized)
    work.prepare_copy(finalized)
    ordered = sorted(finalized, key=lambda item: (item["table"], item["keyDigest"], item["operation"]))
    work.prepare_copy(ordered)
    work.prepare_encoding(result)
    transition = core.KernelTransition(mutations=tuple(ordered), result=result, work_units=total_work)
    live()
    completed = (_FullTransition(transition, live, valid_until) if historical is None else
        _HistoricalFullTransition(transition, live, valid_until, historical))
    live()
    return completed


def _full_transition_with_liveness_on_work(context, *, old_token_bytes,
        expected_delivery_id, expected_user_id, expected_session_id, expected_credential_id,
        expected_credential_record_id, expected_challenge_id, authn_policy, trust_policy,
        business_before_roots, authorization_before_roots, before_proofs, read_heads, query_frontiers,
        live_window, transport_deadline_ns, work):
    return _full_original_transition_on_work(context, old_token_bytes=old_token_bytes,
        expected_delivery_id=expected_delivery_id, expected_user_id=expected_user_id,
        expected_session_id=expected_session_id, expected_credential_id=expected_credential_id,
        expected_credential_record_id=expected_credential_record_id, expected_challenge_id=expected_challenge_id,
        authn_policy=authn_policy, trust_policy=trust_policy, business_before_roots=business_before_roots,
        authorization_before_roots=authorization_before_roots, before_proofs=before_proofs,
        read_heads=read_heads, query_frontiers=query_frontiers, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work, historical_plan_interval=None)


def _full_transition_historical_on_work(context, *, old_token_bytes,
        expected_delivery_id, expected_user_id, expected_session_id, expected_credential_id,
        expected_credential_record_id, expected_challenge_id, authn_policy, trust_policy,
        business_before_roots, authorization_before_roots, before_proofs, read_heads, query_frontiers,
        historical_plan_interval, live_window, transport_deadline_ns, work):
    """Replay original semantics; the original expiry never becomes a clock."""
    interval = _historical_interval(historical_plan_interval)
    return _full_original_transition_on_work(context, old_token_bytes=old_token_bytes,
        expected_delivery_id=expected_delivery_id, expected_user_id=expected_user_id,
        expected_session_id=expected_session_id, expected_credential_id=expected_credential_id,
        expected_credential_record_id=expected_credential_record_id, expected_challenge_id=expected_challenge_id,
        authn_policy=authn_policy, trust_policy=trust_policy, business_before_roots=business_before_roots,
        authorization_before_roots=authorization_before_roots, before_proofs=before_proofs,
        read_heads=read_heads, query_frontiers=query_frontiers, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work, historical_plan_interval=interval)


def _full_transition_on_work(context, *, old_token_bytes,
        expected_delivery_id, expected_user_id, expected_session_id, expected_credential_id,
        expected_credential_record_id, expected_challenge_id, authn_policy, trust_policy,
        business_before_roots, authorization_before_roots, before_proofs, read_heads, query_frontiers,
        live_window, transport_deadline_ns, work):
    """Original-only kernel result; shared capacity/query work is already included."""
    actual = _full_transition_with_liveness_on_work(context, old_token_bytes=old_token_bytes,
        expected_delivery_id=expected_delivery_id, expected_user_id=expected_user_id,
        expected_session_id=expected_session_id, expected_credential_id=expected_credential_id,
        expected_credential_record_id=expected_credential_record_id, expected_challenge_id=expected_challenge_id,
        authn_policy=authn_policy, trust_policy=trust_policy, business_before_roots=business_before_roots,
        authorization_before_roots=authorization_before_roots, before_proofs=before_proofs,
        read_heads=read_heads, query_frontiers=query_frontiers, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work)
    actual.live()
    return actual.transition
