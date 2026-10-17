"""Original-bound current-root observation for delivery-consumption planning.

The fresh query commits the exact consume request, original token possession,
independent subject/policy scope and complete root vector. Both plan producers
and receivers repeat signature verification and exact projection. This is an
observation by the enrolled state owner, not a lock, off-host witness, caller
permission, SQL commit or authority to decrypt. No replacement work/window,
nonce generation, transport or successful input is used. The distinct historical
entry authenticates original observation facts, never current state authority.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import authority_current_root_delivery_head as head
from catchplate import authority_current_root_vector as vector
from catchplate import authority_oidc_session_activation as assertion
from catchplate import authority_oidc_session_activation_delivery_writes as writes
from catchplate import authority_primary_contract as primary
from catchplate import authority_request_commitment as commitment


registration, evidence = assertion.registration, assertion.registration.evidence
OPERATION = writes.OPERATION
CONTEXT_DOMAIN = "catchplate.oidcSessionActivationDeliveryPlanningStateContext/v1"
SCOPE_FIELDS = frozenset({"deliveryId", "userId", "sessionId", "credentialId",
    "credentialRecordId", "challengeId", "authenticationPolicy", "trustPolicy",
    "configurationDigest", "plannerIdentity", "plannerSpkiDigest", "maximumPlanAgeNs",
    "maximumClockSkewNs", "deadlineEpochNs"})


class OidcSessionActivationDeliveryStateError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False)
class _ProjectedRoots:
    vector_bytes: bytes
    vector_digest: str
    business_before_roots: tuple
    authorization_before_roots: tuple
    expected_counted_heads: tuple


def _fail(message):
    raise OidcSessionActivationDeliveryStateError(message)


def _original(raw, maximum, label):
    if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
        _fail("delivery planning state " + label + " is not bounded immutable original bytes")
    return raw


def _project_on_work(*, vector_bytes, expected_vector_digest, work):
    """Validate the entire fixed vector before projecting the consume subset."""
    ledger = evidence.capture._SharedLedger(work)
    original = _original(vector_bytes, vector.MAX_BYTES, "complete vector")
    registration._digest(expected_vector_digest)
    document = vector._decode_on_work(original, work=work)
    actual_digest = vector.framing._frame(vector.IDENTITY_DOMAIN, (original,), work)
    registration._same(actual_digest, expected_vector_digest, work, "delivery complete-vector identity")
    contracts = primary.primary_table_contracts(OPERATION)
    identities, _ = writes._identities()
    work.prepare_scan(document)
    primary_rows = {item["table"]: item for item in document["primaryRoots"]}
    counted_rows = {item["indexId"]: item for item in document["countedRoots"]}
    selected = {
        "business": [primary_rows[item.table] for item in contracts if item.root_class == "business"],
        "authorization": [primary_rows[item.table] for item in contracts if item.root_class == "authorization"],
        "heads": [{name: counted_rows[identity][name] for name in
            ("indexId", "indexRevision", "rootDigest", "leafCount")} for identity in identities],
    }
    owned = evidence.capture._JSONCapture(ledger, maximum_bytes=vector.MAX_BYTES).visit(selected)
    writes._heads(owned["heads"])
    return _ProjectedRoots(original, actual_digest, tuple(owned["business"]),
        tuple(owned["authorization"]), tuple(owned["heads"]))


def _context_digest_on_work(*, request, scope, old_token_bytes, complete_root_vector_bytes, work):
    ledger = evidence.capture._SharedLedger(work)
    original_vector = _original(complete_root_vector_bytes, vector.MAX_BYTES, "complete vector")
    old = assertion._token(old_token_bytes, work)
    # Both external graphs are detached before typed commitments/native hashing.
    owned = assertion._Capture(ledger, maximum_bytes=assertion.MAX_CONTEXT_BYTES).visit({
        "request": request, "scope": scope})
    actual, expected = owned["request"], owned["scope"]
    registration._closed(expected, SCOPE_FIELDS, "delivery planning state scope")
    registration._text(expected["deliveryId"], "delivery ID", 128, work)
    for name in ("configurationDigest", "plannerSpkiDigest"):
        registration._digest(expected[name])
    evidence._identity(expected["plannerIdentity"])
    registration._integer(expected["maximumPlanAgeNs"], "delivery state plan age", 1,
        evidence.authority.VERIFIER_RESPONSE_MAX_AGE_NS)
    registration._integer(expected["maximumClockSkewNs"], "delivery state clock skew", 0,
        evidence.authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    registration._integer(expected["deadlineEpochNs"], "delivery state deadline", 1)
    if type(actual) is not dict or actual.get("operation") != OPERATION:
        _fail("delivery head context requires the distinct consume request")
    digest = commitment._typed_request_digest(actual, work=work)
    registration._same(actual["requestDigest"], digest, work, "delivery head request digest")
    operation_id = evidence.plan._frame("catchplate.policyAuthorityOperation/v2",
        (evidence.plan._ascii(OPERATION, work), evidence.plan._ascii(digest, work)), work)
    registration._same(actual["operationId"], operation_id, work, "delivery head operation ID")
    arguments = writes.consumption._arguments(actual["arguments"], work)
    for field, name in (("delivery_id", "deliveryId"), ("user_id", "userId"),
            ("session_id", "sessionId"), ("credential_id", "credentialId"),
            ("credential_record_id", "credentialRecordId"), ("challenge_id", "challengeId")):
        registration._same(arguments[field], expected[name], work, "delivery head independent " + name)
    registration._same(arguments["old_token_digest"], assertion._digest(old, work), work,
        "delivery head original token possession")
    vector._decode_on_work(original_vector, work=work)
    original_context = evidence.capability._wire(owned, ledger,
        assertion.MAX_CONTEXT_BYTES, assertion.MAX_CONTEXT_NODES)
    return evidence.plan._frame(CONTEXT_DOMAIN, (original_context, old, original_vector), work)


def _verify_on_work(*, request, scope, old_token_bytes, complete_root_vector_bytes,
        query_bytes, observation_bytes, enrollment_bytes, root_public_key, now_epoch_ns, work):
    """Verify this exact fresh consume observation; never renew its interval."""
    ledger = evidence.capture._SharedLedger(work)
    original_query = _original(query_bytes, head.MAX_QUERY_BYTES, "query")
    original_observation = _original(observation_bytes, head.MAX_BYTES, "observation")
    original_enrollment = _original(enrollment_bytes,
        head.authorization.MAX_ENROLLMENT_BYTES, "enrollment")
    original_vector = _original(complete_root_vector_bytes, vector.MAX_BYTES, "complete vector")
    key, now = root_public_key, now_epoch_ns
    head.authorization._public(key)
    registration._integer(now, "delivery head admission time", 1)
    old = assertion._token(old_token_bytes, work)
    owned = assertion._Capture(ledger, maximum_bytes=assertion.MAX_CONTEXT_BYTES).visit({
        "request": request, "scope": scope})
    context_digest = _context_digest_on_work(request=owned["request"], scope=owned["scope"],
        old_token_bytes=old, complete_root_vector_bytes=original_vector, work=work)
    query = head._decode_query_on_work(original_query, work=work)
    vector_digest = vector.framing._frame(vector.IDENTITY_DOMAIN, (original_vector,), work)
    registration._same(query["contextDigest"], context_digest, work, "delivery head original context")
    registration._same(query["expectedVectorDigest"], vector_digest, work, "delivery head complete vector")
    payload = head._verify_on_work(observation_bytes=original_observation, query_bytes=original_query,
        enrollment_bytes=original_enrollment, root_public_key=key, now_epoch_ns=now, work=work)
    if payload["pendingRequestDigest"] is not None or payload["pendingDecisionDigest"] is not None:
        _fail("delivery planning cannot admit an outstanding state reservation")
    if now >= min(payload["expiresAtEpochNs"], owned["scope"]["deadlineEpochNs"]):
        _fail("delivery planning observation or independent scope has expired")
    return payload


def _verify_historical_on_work(*, request, scope, old_token_bytes, complete_root_vector_bytes,
        query_bytes, observation_bytes, enrollment_bytes, root_public_key,
        historical_plan_interval, live_window, transport_deadline_ns, work):
    """Authenticate original state and its possible original planning overlap.

    The composing plan receiver authenticates the interval's plan signature.
    Neither endpoint of that interval is passed to a live verifier or clock.
    """
    from catchplate import oidc_session_activation_delivery as lifetime

    ledger = evidence.capture._SharedLedger(work)
    original_query = _original(query_bytes, head.MAX_QUERY_BYTES, "historical query")
    original_observation = _original(observation_bytes, head.MAX_BYTES, "historical observation")
    original_enrollment = _original(enrollment_bytes, head.authorization.MAX_ENROLLMENT_BYTES,
        "historical enrollment")
    original_vector = _original(complete_root_vector_bytes, vector.MAX_BYTES, "historical vector")
    key = root_public_key
    head.authorization._public(key)
    interval = writes.consumption._historical_interval(historical_plan_interval)
    old = assertion._token(old_token_bytes, work)
    owned = assertion._Capture(ledger, maximum_bytes=assertion.MAX_CONTEXT_BYTES).visit({
        "request": request, "scope": scope})
    context_digest = _context_digest_on_work(request=owned["request"], scope=owned["scope"],
        old_token_bytes=old, complete_root_vector_bytes=original_vector, work=work)
    issued, expires = interval
    expected = owned["scope"]
    if expires - issued > expected["maximumPlanAgeNs"] or expires > expected["deadlineEpochNs"]:
        _fail("historical consume interval exceeds independently admitted scope")
    query = head._decode_query_on_work(original_query, work=work)
    vector_digest = vector.framing._frame(vector.IDENTITY_DOMAIN, (original_vector,), work)
    registration._same(query["contextDigest"], context_digest, work, "historical consume context")
    registration._same(query["expectedVectorDigest"], vector_digest, work, "historical consume vector")
    window, current = lifetime._window(live_window, transport_deadline_ns, work)
    if issued > current() + expected["maximumClockSkewNs"]:
        _fail("historical consume plan is issued in the current future")
    payload, enrollment = head._verify_historical_with_enrollment_on_work(
        observation_bytes=original_observation, query_bytes=original_query,
        enrollment_bytes=original_enrollment, root_public_key=key,
        live_window=window, transport_deadline_ns=transport_deadline_ns, work=work)
    if payload["pendingRequestDigest"] is not None or payload["pendingDecisionDigest"] is not None:
        _fail("historical consume planning observation contained a reservation")
    # A plan records its processing opening; observation can follow that
    # opening. Require actual original overlap, not fictitious old-clock use.
    observed_issue, observed_expiry = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    lower = max(issued, observed_issue - enrollment.payload["maxClockSkewNs"])
    upper = min(expires, observed_expiry, observed_issue + enrollment.payload["maxControlAgeNs"] + 1)
    if lower >= upper or expires > observed_expiry:
        _fail("historical consume plan exceeded its actual original observation")
    if issued > current() + expected["maximumClockSkewNs"]:
        _fail("historical consume issue changed relative to the current clock")
    return payload
