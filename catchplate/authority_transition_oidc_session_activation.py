"""Private original-replaying activation business effects, not an executor.

Genuine primary and complete-query proofs are replayed on independently supplied
roots, then the actual original assertion and encrypted delivery are verified.
Root/currentness, policy/key admission, retained-finalization ownership and the
database clock remain the protected caller's responsibilities. No CAS-success
carrier, legacy database helper, registered transition, SQL or token delivery is
accepted or performed here. The full private adapter additionally invokes the
real shared audit-capacity finalizer; it still proves no committed execution.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable
import time

from catchplate import authority_oidc_session_activation as assertion
from catchplate import authority_oidc_session_activation_reads as reads
from catchplate import authority_audit_capacity as capacity
from catchplate import oidc_session_activation_delivery as delivery
from catchplate import rbac


registration = assertion.registration
core, support = registration.core, registration.support
OPERATION = "oidc.session.activate"
RESULT_SCHEMA = "catchplate.oidcSessionActivationEffects/v1"
DELIVERY_PURPOSE = "activation-delivery"
AUDIT_PURPOSE = "activation-audit"
MAX_SELECTED_ROWS = 10
_ARGUMENT_FIELDS = frozenset({"session_id", "user_id", "credential_id", "credential_record_id",
    "challenge_id", "old_token_digest", "new_token_digest", "assertion_digest",
    "delivery_ttl_seconds", "businessIntent"})
_RBAC_STATE_FIELDS = frozenset({"authority_id", "generation", "state_digest", "binding_table_revision",
    "verified_binding_table_revision", "updated_at"})
_RBAC_BINDING_FIELDS = frozenset({"subject_id", "roles_json", "status", "generation", "binding_digest",
    "updated_at", "updated_by", "reason", "deprovisioned_at", "deprovisioned_by"})
_HIGH_FIELDS = frozenset({"authority_scope", "rollback_epoch", "publication_sequence", "publication_digest",
    "metadata_blob_digest", "revocation_set_digest", "witness_receipt_digest", "witness_sequence",
    "updated_at_epoch_ns"})
_PUBLICATION_FIELDS = frozenset({"id", "scope", "previous_bundle_digest", "bundle_digest", "sequence",
    "rollback_epoch", "signing_key_id", "bundle_json", "payload_digest", "actor_id",
    "withdrawn_credential_ids_json", "audit_event_json", "status", "attempts", "last_error",
    "created_at", "published_at"})


class OidcSessionActivationTransitionError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False)
class _FullTransition:
    transition: core.KernelTransition
    live: Callable[[], int]
    valid_until_epoch_ns: int


@dataclass(frozen=True, slots=True, repr=False)
class _HistoricalFullTransition:
    """Historical effects and current processing guard; never live authority."""
    transition: core.KernelTransition
    live: Callable[[], int]
    valid_until_epoch_ns: int
    historical_plan_interval: tuple


def _fail(message):
    raise OidcSessionActivationTransitionError(message)


def _arguments(values, work):
    registration._closed(values, _ARGUMENT_FIELDS, "activation arguments")
    for field, maximum in (("session_id", 128), ("user_id", 1024), ("credential_id", 1366),
            ("credential_record_id", 1024), ("challenge_id", 1024)):
        registration._text(values[field], field, maximum, work)
    registration._encoded_original(values["credential_id"], 1024, work, minimum=1)
    for field in ("old_token_digest", "new_token_digest", "assertion_digest"):
        registration._digest(values[field])
    if values["old_token_digest"] == values["new_token_digest"]:
        _fail("activation arguments do not rotate the token")
    registration._integer(values["delivery_ttl_seconds"], "delivery lifetime", 5, 60)
    work.prepare_copy(values)
    semantic = {field: value for field, value in values.items() if field != "businessIntent"}
    expected = registration.authority._synthesize_business_intent(OPERATION, semantic, work=work)
    registration._same(values["businessIntent"], expected, work, "activation business intent")
    return values


def _roles(raw, work):
    registration._text(raw, "selected roles", 4096, work)
    value = support._stored_json(raw, work=work)
    if type(value) is not list or not 1 <= len(value) <= len(rbac.VALID_RBAC_ROLES):
        _fail("activation roles are not a bounded nonempty list")
    work.prepare_copy(value)
    normalized = assertion.attestation._native(work, lambda: rbac.normalize_rbac_roles(value))
    registration._same(value, normalized, work, "canonical role ordering")
    registration._same(raw, assertion.attestation._canonical(value, _work=work).decode("ascii"), work,
        "canonical role encoding")
    return value


def _rbac_scope(context, session, user, now_ns, work):
    state = support._row(context._exact("rbac_authority_state", {"authority_id": 1}, work=work), work=work)
    binding = support._row(context._exact("rbac_role_bindings", {"subject_id": user}, work=work), work=work)
    registration._closed(state, _RBAC_STATE_FIELDS, "activation RBAC state")
    registration._closed(binding, _RBAC_BINDING_FIELDS, "activation RBAC binding")
    if type(state["authority_id"]) is not int or state["authority_id"] != 1:
        _fail("activation RBAC authority identity changed")
    generation = registration._integer(state["generation"], "RBAC authority generation", 0)
    for field in ("binding_table_revision", "verified_binding_table_revision"):
        registration._integer(state[field], field, 0)
    registration._same(state["binding_table_revision"], state["verified_binding_table_revision"], work,
        "verified RBAC table revision")
    registration._digest(state["state_digest"])
    registration._digest(binding["binding_digest"])
    registration._same(binding["subject_id"], user, work, "RBAC subject")
    if (binding["status"] != "active" or binding["deprovisioned_at"] is not None
            or binding["deprovisioned_by"] is not None
            or not 1 <= registration._integer(binding["generation"], "role generation", 1) <= generation):
        _fail("activation subject is not currently active in selected RBAC state")
    for row in (state, binding):
        if assertion._time(row["updated_at"], "RBAC update", work) > now_ns:
            _fail("activation RBAC update is after the admitted database time")
    roles = _roles(binding["roles_json"], work)
    registration._same(_roles(session["roles_json"], work), roles, work, "current session roles")
    # The genuine row format's digest covers these exact canonical fields;
    # this consistency check does not authenticate the global RBAC checkpoint.
    registration._text(binding["updated_by"], "RBAC updater", 1024, work)
    if binding["reason"] is not None:
        registration._text(binding["reason"], "RBAC reason", 500, work)
    material = {"subject_id": user, "roles": roles, "status": "active",
        "generation": binding["generation"], "updated_at": binding["updated_at"],
        "updated_by": binding["updated_by"], "reason": binding["reason"]}
    registration._same(binding["binding_digest"],
        assertion._digest(assertion.attestation._canonical(material, _work=work), work), work,
        "selected role binding digest")


def _trust_scope(context, policy, now_ns, work):
    trust = registration.trust
    high = support._row(context._exact(trust.HIGH_WATER_TABLE,
        {"authority_scope": trust.AUTHORITY_SCOPE}, work=work), work=work)
    registration._closed(high, _HIGH_FIELDS, "activation trust high-water")
    registration._same(high["authority_scope"], trust.AUTHORITY_SCOPE, work, "trust scope")
    # Use the actual high-water validator; the independently supplied policy
    # must already represent the genuinely admitted complete signed bundle.
    document = trust.high_water_document(rollback_epoch=high["rollback_epoch"],
        sequence=high["publication_sequence"], publication_digest=high["publication_digest"],
        metadata_blob_digest=high["metadata_blob_digest"], revocation_set_digest=high["revocation_set_digest"],
        witness_receipt_digest=high["witness_receipt_digest"], witness_sequence=high["witness_sequence"])
    registration._integer(high["updated_at_epoch_ns"], "trust update", 1)
    if high["updated_at_epoch_ns"] > now_ns:
        _fail("activation trust update is after the admitted database time")
    work.prepare_copy(context.selected_rows)
    publications = tuple(item for item in context.selected_rows
        if item["table"] == trust.PUBLICATION_TABLE and item["present"] is True)
    if len(publications) != 1:
        _fail("activation needs one exact published trust predecessor")
    publication = support._row(publications[0], work=work)
    registration._closed(publication, _PUBLICATION_FIELDS, "activation trust publication")
    registration._integer(publication["rollback_epoch"], "publication rollback epoch", 0)
    registration._integer(publication["sequence"], "publication sequence", 1)
    registration._same((publication["scope"], publication["status"], publication["bundle_digest"],
        publication["payload_digest"], publication["rollback_epoch"], publication["sequence"]),
        ("global", "published", high["publication_digest"], high["metadata_blob_digest"],
         high["rollback_epoch"], high["publication_sequence"]), work, "published trust high-water")
    registration._same((policy.get("currentBundleDigest"), policy.get("currentBundleSequence")),
        (high["publication_digest"], high["publication_sequence"]), work, "independent current trust policy")
    for field in ("created_at", "published_at"):
        if assertion._time(publication[field], "trust publication time", work) > now_ns:
            _fail("activation trust publication is after the admitted database time")
    return trust.high_water_digest(document, work=work)


def _business_originals_on_work(context, *, assertion_bytes, old_token_bytes, new_token_bytes,
        delivery_envelope_bytes, delivery_custody_key, expected_user_id, expected_session_id,
        expected_credential_id, expected_credential_record_id, expected_challenge_id,
        rp_id, origin, authn_policy, trust_policy, business_before_roots, authorization_before_roots,
        before_proofs, read_heads, query_frontiers, live_window, work, transport_deadline_ns=None,
        historical_plan_interval=None, _current=None):
    """Replay originals once and retain only this call's owned context and clock.

    Raw QueryRead records come from the exact context; raw primary/range proofs
    and independently admitted roots are mandatory separate inputs. The genuine
    reads worker is invoked here, not an externally supplied successful result.
    No entrypoint accepts the returned private context/effects/liveness carrier.
    """
    ledger = registration.capture._SharedLedger(work)
    historical = (None if historical_plan_interval is None
        else assertion._historical_interval(historical_plan_interval))
    if (type(context) is not core.KernelContext or context.operation != OPERATION
            or type(context.selected_rows) is not tuple or len(context.selected_rows) != MAX_SELECTED_ROWS
            or context.verified_webauthn_evidence is not None):
        _fail("activation context is not the fixed original-input profile")
    if (type(assertion_bytes) is not bytes or not 2 <= len(assertion_bytes) <= assertion.MAX_ASSERTION_BYTES
            or type(delivery_envelope_bytes) is not bytes or len(delivery_envelope_bytes) != delivery.ENVELOPE_BYTES
            or type(delivery_custody_key) is not bytes or len(delivery_custody_key) != 32):
        _fail("activation assertion or delivery original exceeds its exact profile")
    old_token_bytes, new_token_bytes = assertion._token(old_token_bytes, work), assertion._token(new_token_bytes, work)
    window = assertion.clock._validate(live_window)
    bound = window[4]
    if transport_deadline_ns is not None:
        registration._integer(transport_deadline_ns, "activation inherited deadline", 1)
        bound = min(bound, transport_deadline_ns)
    database_now = context.database_now
    if historical is not None and (type(database_now) is not datetime or database_now.tzinfo is not timezone.utc):
        _fail("activation historical database cutoff is not an exact original UTC value")
    now_ns = registration._now(database_now)
    if historical is not None and not 0 < now_ns < historical[1]:
        _fail("activation historical database cutoff does not precede original plan expiry")
    query_reads = context.query_reads
    work.prepare_copy(context.selected_rows)
    owned = assertion._Capture(ledger, maximum_bytes=assertion.MAX_CONTEXT_BYTES).visit({
        "arguments": context.arguments, "selected": list(context.selected_rows), "requestDigest": context.request_digest,
        "user": expected_user_id, "session": expected_session_id, "credential": expected_credential_id,
        "record": expected_credential_record_id, "challenge": expected_challenge_id,
        "rpId": rp_id, "origin": origin, "policy": authn_policy, "trust": trust_policy})
    # The reads worker owns all proof/root/query-record originals before any
    # declaration hashes/native callbacks. Our policy/original scope is already
    # detached. No clock callback runs ahead of that proof ownership boundary.
    admitted = reads._admit_on_work(arguments=owned["arguments"], request_digest=owned["requestDigest"],
        database_now=database_now, selected_rows=tuple(owned["selected"]), query_reads=query_reads,
        business_before_roots=business_before_roots, authorization_before_roots=authorization_before_roots,
        before_proofs=before_proofs, read_heads=read_heads, query_frontiers=query_frontiers, work=work)
    registration._same(admitted.arguments, owned["arguments"], work, "proof-owned activation arguments")
    registration._same(admitted.selected_rows, tuple(owned["selected"]), work, "proof-owned selected rows")
    values = _arguments(admitted.arguments, work)
    registration._digest(owned["requestDigest"])
    registration._same((values["user_id"], values["session_id"], values["credential_id"],
        values["credential_record_id"], values["challenge_id"]),
        (owned["user"], owned["session"], owned["credential"], owned["record"], owned["challenge"]), work,
        "independent activation subject")
    current = core.KernelContext(OPERATION, values, admitted.selected_rows, database_now,
        owned["requestDigest"], query_reads=admitted.query_reads)
    last_epoch, last_monotonic = window[0], window[2]

    def live():
        nonlocal last_epoch, last_monotonic
        epoch = assertion.clock._check_on_work(window, work=work)
        monotonic = registration.evidence.production._callback(work, lambda: time.monotonic_ns())
        registration._integer(monotonic, "activation monotonic sample", 1)
        if epoch < last_epoch or monotonic < last_monotonic or monotonic >= bound:
            _fail("activation transition deadline expired or reversed")
        last_epoch, last_monotonic = epoch, monotonic
        if historical is None:
            if not window[0] - window[6] <= now_ns <= epoch + window[6] or now_ns >= window[3]:
                _fail("activation database time is outside the original processing scope")
        elif now_ns > epoch + window[6] or historical[0] > epoch + window[6]:
            _fail("activation historical database cutoff or issue is in the future")
        return epoch

    live = delivery._join_current(live, _current, work)
    live()
    session_selected = current._exact("oidc_browser_sessions", {"id": values["session_id"]}, work=work)
    challenge_selected = current._exact("webauthn_challenges", {"id": values["challenge_id"]}, work=work)
    credential_selected = current._exact("webauthn_credentials", {"id": values["credential_record_id"]}, work=work)
    session, challenge, credential = (support._row(item, work=work)
        for item in (session_selected, challenge_selected, credential_selected))
    assertion_arguments = dict(assertion_bytes=assertion_bytes, session_row=session,
        challenge_row=challenge, credential_row=credential, expected_user_id=owned["user"],
        expected_session_id=owned["session"], expected_credential_id=owned["credential"],
        rp_id=owned["rpId"], origin=owned["origin"], authn_policy=owned["policy"], trust_policy=owned["trust"],
        old_token_bytes=old_token_bytes, new_token_bytes=new_token_bytes, live_window=window, work=work,
        transport_deadline_ns=bound)
    if historical is None:
        intent = assertion._derive_on_work(**assertion_arguments)
    else:
        intent = assertion._derive_historical_on_work(**assertion_arguments,
            original_database_now_epoch_ns=now_ns, historical_plan_interval=historical, _current=_current)
    registration._same((intent["subject"]["credentialRecordId"], intent["subject"]["challengeId"],
        intent["sessionCas"]["expectedTokenDigest"], intent["sessionCas"]["newTokenDigest"], intent["assertionDigest"]),
        (values["credential_record_id"], values["challenge_id"], values["old_token_digest"],
         values["new_token_digest"], values["assertion_digest"]), work, "original assertion/token argument binding")
    if now_ns >= intent["validUntilEpochNs"]:
        _fail("activation database time exceeds original assertion scope")
    for row, fields in ((session, ("created_at", "updated_at")), (challenge, ("created_at",)),
            (credential, ("created_at", "updated_at", "attestation_verified_at"))):
        for field in fields:
            if assertion._time(row[field], field, work) > now_ns:
                _fail("activation effect time precedes its selected row")
    if credential["last_used_at"] is not None and assertion._time(credential["last_used_at"], "last use", work) > now_ns:
        _fail("activation effect time precedes the credential last use")
    _rbac_scope(current, session, values["user_id"], now_ns, work)
    trust_digest = _trust_scope(current, owned["trust"], now_ns, work)
    delivery_id = core._deterministic_uuid(operation=OPERATION, request_digest=current.request_digest,
        purpose=DELIVERY_PURPOSE, work=work)
    audit_id = core._deterministic_uuid(operation=OPERATION, request_digest=current.request_digest,
        purpose=AUDIT_PURPOSE, work=work)
    delivery_selected = current._exact("oidc_session_activation_deliveries", {"id": delivery_id}, work=work)
    audit_selected = current._exact("metadata_audit_outbox", {"id": audit_id}, work=work)
    if delivery_selected["present"] or audit_selected["present"]:
        _fail("activation delivery or audit identity has already been used")
    now_iso = database_now.isoformat()
    delivery_expiry = min(database_now + timedelta(seconds=values["delivery_ttl_seconds"]),
        registration._utc(session["expires_at"], "session expiry", work)).isoformat()
    scope = {"deliveryId": delivery_id, "userId": values["user_id"], "sessionId": values["session_id"],
        "credentialId": values["credential_id"], "credentialRecordId": values["credential_record_id"],
        "challengeId": values["challenge_id"], "assertionDigest": values["assertion_digest"],
        "oldTokenDigest": values["old_token_digest"], "newTokenDigest": values["new_token_digest"],
        "createdAt": now_iso, "expiresAt": delivery_expiry}
    delivery_arguments = dict(envelope_bytes=delivery_envelope_bytes,
        custody_key=delivery_custody_key, scope=scope, live_window=window, work=work, transport_deadline_ns=bound)
    if historical is None:
        delivery_row = delivery._delivery_row_on_work(**delivery_arguments)
    else:
        delivery_row = delivery._delivery_row_historical_on_work(**delivery_arguments,
            historical_plan_interval=historical, _current=_current)
    work.prepare_copy(challenge)
    used_challenge = {**challenge, "used_at": now_iso}
    work.prepare_copy(credential)
    updated_credential = {**credential, "sign_count": intent["credentialCas"]["newSignCount"],
        "last_used_at": now_iso, "updated_at": now_iso}
    activation = intent["sessionCas"]
    work.prepare_copy(session)
    updated_session = {**session, "token_digest": activation["newTokenDigest"], "status": "active",
        "bound_webauthn_credential_id": values["credential_record_id"], "activated_at": now_iso,
        "updated_at": now_iso, "pending_expires_at": None,
        "activation_trust_bundle_digest": activation["activationTrustBundleDigest"],
        "activation_trust_bundle_sequence": activation["activationTrustBundleSequence"],
        "activation_authenticator_class": activation["activationAuthenticatorClass"]}
    event = {"session_id": values["session_id"], "user_id": values["user_id"],
        "challenge_id": values["challenge_id"], "expires_at": session["expires_at"],
        "authenticator_class": activation["activationAuthenticatorClass"],
        "trust_bundle_digest": activation["activationTrustBundleDigest"],
        "trust_bundle_sequence": activation["activationTrustBundleSequence"],
        "trust_high_water_digest": trust_digest, "assertion_digest": values["assertion_digest"],
        "delivery_id": delivery_id}
    event_raw = registration._wire(event, work)
    work.charge(input_bytes=len(event_raw))
    audit = {"id": audit_id, "event_type": "oidc.browser_session.activated", "actor_type": "admin",
        "actor_id": values["user_id"], "event_json": event_raw.decode("ascii"),
        "event_digest": registration.evidence.plan._frame("catchplate.metadataAuditOutboxEvent/v1", (event_raw,), work),
        "storage_format_version": 2, "status": "pending", "claim_id": None, "claimed_at": None,
        "attempts": 0, "audited_at": None, "audit_event_hash": None, "last_error": None, "created_at": now_iso}
    effects = ((challenge_selected, used_challenge), (credential_selected, updated_credential),
        (session_selected, updated_session), (delivery_selected, delivery_row), (audit_selected, audit))
    result = {"schema": RESULT_SCHEMA, "status": "activation-effects-derived", "sessionId": values["session_id"],
        "credentialRecordId": values["credential_record_id"], "deliveryId": delivery_id,
        "assertionDigest": values["assertion_digest"], "sessionActivated": False}
    work.prepare_copy(effects)
    work.prepare_encoding(result)
    valid_until = min(intent["validUntilEpochNs"], assertion._time(delivery_expiry, "delivery expiry", work))
    epoch = live()
    if historical is None and epoch >= valid_until:
        _fail("activation originals expired before effect derivation finished")
    if historical is not None and historical[1] > valid_until:
        _fail("activation historical plan exceeds original assertion or delivery lifetime")
    return current, effects, result, live, valid_until


def _business_on_work(context, *, assertion_bytes, old_token_bytes, new_token_bytes,
        delivery_envelope_bytes, delivery_custody_key, expected_user_id, expected_session_id,
        expected_credential_id, expected_credential_record_id, expected_challenge_id,
        rp_id, origin, authn_policy, trust_policy, business_before_roots, authorization_before_roots,
        before_proofs, read_heads, query_frontiers, live_window, work, transport_deadline_ns=None):
    """Retain the original live-only business API and its unchanged time rules."""
    return _business_originals_on_work(context,
        assertion_bytes=assertion_bytes, old_token_bytes=old_token_bytes, new_token_bytes=new_token_bytes,
        delivery_envelope_bytes=delivery_envelope_bytes, delivery_custody_key=delivery_custody_key,
        expected_user_id=expected_user_id, expected_session_id=expected_session_id,
        expected_credential_id=expected_credential_id, expected_credential_record_id=expected_credential_record_id,
        expected_challenge_id=expected_challenge_id, rp_id=rp_id, origin=origin, authn_policy=authn_policy,
        trust_policy=trust_policy, business_before_roots=business_before_roots,
        authorization_before_roots=authorization_before_roots, before_proofs=before_proofs,
        read_heads=read_heads, query_frontiers=query_frontiers, live_window=live_window, work=work,
        transport_deadline_ns=transport_deadline_ns)


def _transition_on_work(context, *, assertion_bytes, old_token_bytes, new_token_bytes,
        delivery_envelope_bytes, delivery_custody_key, expected_user_id, expected_session_id,
        expected_credential_id, expected_credential_record_id, expected_challenge_id,
        rp_id, origin, authn_policy, trust_policy, business_before_roots, authorization_before_roots,
        before_proofs, read_heads, query_frontiers, live_window, work, transport_deadline_ns=None):
    """Preserve the five-business-effect API; no framework counter is appended here."""
    _owned, effects, result, _live, _valid_until = _business_on_work(context,
        assertion_bytes=assertion_bytes, old_token_bytes=old_token_bytes, new_token_bytes=new_token_bytes,
        delivery_envelope_bytes=delivery_envelope_bytes, delivery_custody_key=delivery_custody_key,
        expected_user_id=expected_user_id, expected_session_id=expected_session_id,
        expected_credential_id=expected_credential_id, expected_credential_record_id=expected_credential_record_id,
        expected_challenge_id=expected_challenge_id, rp_id=rp_id, origin=origin, authn_policy=authn_policy,
        trust_policy=trust_policy, business_before_roots=business_before_roots,
        authorization_before_roots=authorization_before_roots, before_proofs=before_proofs,
        read_heads=read_heads, query_frontiers=query_frontiers, live_window=live_window, work=work,
        transport_deadline_ns=transport_deadline_ns)
    return effects, result


def _full_transition_with_liveness_on_work(context, *, assertion_bytes, old_token_bytes, new_token_bytes,
        delivery_envelope_bytes, delivery_custody_key, expected_user_id, expected_session_id,
        expected_credential_id, expected_credential_record_id, expected_challenge_id,
        rp_id, origin, authn_policy, trust_policy, business_before_roots, authorization_before_roots,
        before_proofs, read_heads, query_frontiers, live_window, work, transport_deadline_ns=None):
    """Derive the full transition and retain this invocation's original liveness.

    work_units ALREADY includes the actual query declarations and framework
    units. A future planner must not finalize capacity or add those units again.
    This is not a registered factory, after-root proof, signed plan or SQL result.
    """
    owned, effects, result, live, valid_until = _business_on_work(context,
        assertion_bytes=assertion_bytes, old_token_bytes=old_token_bytes, new_token_bytes=new_token_bytes,
        delivery_envelope_bytes=delivery_envelope_bytes, delivery_custody_key=delivery_custody_key,
        expected_user_id=expected_user_id, expected_session_id=expected_session_id,
        expected_credential_id=expected_credential_id, expected_credential_record_id=expected_credential_record_id,
        expected_challenge_id=expected_challenge_id, rp_id=rp_id, origin=origin, authn_policy=authn_policy,
        trust_policy=trust_policy, business_before_roots=business_before_roots,
        authorization_before_roots=authorization_before_roots, before_proofs=before_proofs,
        read_heads=read_heads, query_frontiers=query_frontiers, live_window=live_window, work=work,
        transport_deadline_ns=transport_deadline_ns)
    return _finish_full_transition(owned, effects, result, live, valid_until, work)


def _finish_full_transition(owned, effects, result, live, valid_until, work,
                            *, historical_plan_interval=None):
    """Finalize actual same-call effects once; never consume an external carrier."""
    historical = historical_plan_interval

    def check():
        epoch = live()
        if historical is None and epoch >= valid_until:
            _fail("activation originals expired during full transition derivation")
        if historical is not None and historical[1] > valid_until:
            _fail("activation historical plan exceeds its original transition lifetime")

    # Everything below uses the actual proof-owned context from the same call,
    # never the caller's possibly changed context/rows or a successful DTO input.
    spec = registration.authority.operation_spec(OPERATION)
    work.prepare_scan(owned.selected_rows)
    business_rows = sum(not (item["table"] == capacity.AGGREGATE_TABLE
        and item["key"] == {"aggregate_id": capacity.AGGREGATE_ID}) for item in owned.selected_rows)
    if (business_rows > spec["maximumBusinessQueryRows"] or len(effects) != 5
            or len(effects) > spec["maximumBusinessMutations"]):
        _fail("activation business effect inventory exceeds its source allowance")
    mutations, addresses = [], set()
    for selected, after in effects:
        address = selected["table"], registration._digest(selected["keyDigest"])
        if address in addresses or selected["table"] == capacity.AGGREGATE_TABLE:
            _fail("activation business effects duplicate a row or supply the framework counter")
        addresses.add(address)
        # These are the actual three copies made by core.mutation. That real
        # renderer selects the exact source-owned INSERT/UPDATE template.
        work.prepare_copy(selected["key"])
        if selected["present"] is True:
            work.prepare_copy(selected["row"])
        work.prepare_copy(after)
        mutations.append(core.mutation(operation=OPERATION, selected=selected, row=after))
    work.prepare_copy(mutations)
    business = tuple(mutations)
    business_work = 8 + business_rows + 4 * len(business)
    if business_work > spec["maximumBusinessWorkUnits"]:
        _fail("activation kernel exceeds its business work allowance")
    check()
    # The common finalizer validates the real existing capacity row, derives
    # the complete outbox delta and appends its own full-row CAS. Missing/full/
    # malformed capacity is an error; this adapter never initializes a counter.
    finalized = capacity._finalize_capacity(owned, business, work=work)
    if len(finalized) != 6 or len(finalized) > spec["maximumMutations"]:
        _fail("activation full transition does not contain the six source mutations")
    queries = reads._queries(arguments=owned.arguments,
        cutoff_us=reads.complete.cutoff_microseconds(owned.database_now),
        request_digest=owned.request_digest, work=work)
    total_work = capacity.transition_work_units(OPERATION,
        query_work_units=sum(query.work_units for query in queries),
        kernel_work_units=business_work, mutations=finalized)
    work.prepare_copy(finalized)
    ordered = sorted(finalized, key=lambda item: (item["table"], item["keyDigest"], item["operation"]))
    work.prepare_copy(ordered)
    planned = tuple(ordered)
    work.prepare_encoding(result)
    transition = core.KernelTransition(mutations=planned, result=result, work_units=total_work)
    check()
    if historical is not None:
        return _HistoricalFullTransition(transition, live, valid_until, historical)
    return _FullTransition(transition, live, valid_until)


def _full_transition_historical_on_work(context, *, assertion_bytes, old_token_bytes, new_token_bytes,
        delivery_envelope_bytes, delivery_custody_key, expected_user_id, expected_session_id,
        expected_credential_id, expected_credential_record_id, expected_challenge_id,
        rp_id, origin, authn_policy, trust_policy, business_before_roots, authorization_before_roots,
        before_proofs, read_heads, query_frontiers, historical_plan_interval,
        live_window, work, transport_deadline_ns=None, _current=None):
    """Reverify historical originals and effects with a separate current guard.

    The authenticated plan's interval and original UTC database cutoff constrain
    original semantics algebraically. The supplied current processing window is
    never reopened, backdated or compared to historical row/delivery expiry.
    This returns data only, not execution, token release or retry permission.
    """
    historical = assertion._historical_interval(historical_plan_interval)
    owned, effects, result, live, valid_until = _business_originals_on_work(context,
        assertion_bytes=assertion_bytes, old_token_bytes=old_token_bytes, new_token_bytes=new_token_bytes,
        delivery_envelope_bytes=delivery_envelope_bytes, delivery_custody_key=delivery_custody_key,
        expected_user_id=expected_user_id, expected_session_id=expected_session_id,
        expected_credential_id=expected_credential_id, expected_credential_record_id=expected_credential_record_id,
        expected_challenge_id=expected_challenge_id, rp_id=rp_id, origin=origin, authn_policy=authn_policy,
        trust_policy=trust_policy, business_before_roots=business_before_roots,
        authorization_before_roots=authorization_before_roots, before_proofs=before_proofs,
        read_heads=read_heads, query_frontiers=query_frontiers, live_window=live_window, work=work,
        transport_deadline_ns=transport_deadline_ns, historical_plan_interval=historical,
        _current=_current)
    return _finish_full_transition(owned, effects, result, live, valid_until, work,
        historical_plan_interval=historical)


def _full_transition_on_work(context, *, assertion_bytes, old_token_bytes, new_token_bytes,
        delivery_envelope_bytes, delivery_custody_key, expected_user_id, expected_session_id,
        expected_credential_id, expected_credential_record_id, expected_challenge_id,
        rp_id, origin, authn_policy, trust_policy, business_before_roots, authorization_before_roots,
        before_proofs, read_heads, query_frontiers, live_window, work, transport_deadline_ns=None):
    """Preserve the original full-transition projection, not a SQL result."""
    return _full_transition_with_liveness_on_work(context,
        assertion_bytes=assertion_bytes, old_token_bytes=old_token_bytes, new_token_bytes=new_token_bytes,
        delivery_envelope_bytes=delivery_envelope_bytes, delivery_custody_key=delivery_custody_key,
        expected_user_id=expected_user_id, expected_session_id=expected_session_id,
        expected_credential_id=expected_credential_id, expected_credential_record_id=expected_credential_record_id,
        expected_challenge_id=expected_challenge_id, rp_id=rp_id, origin=origin, authn_policy=authn_policy,
        trust_policy=trust_policy, business_before_roots=business_before_roots,
        authorization_before_roots=authorization_before_roots, before_proofs=before_proofs,
        read_heads=read_heads, query_frontiers=query_frontiers, live_window=live_window, work=work,
        transport_deadline_ns=transport_deadline_ns).transition
