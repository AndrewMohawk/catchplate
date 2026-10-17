"""Original-bound planning state, not permission to execute an activation.

The actual caller generates a fresh challenge and independently admits the
state enrollment, root key and complete vector. Both plan production and
receiving replay verify those originals again. A signed observation proves
only the enrolled owner's state at observation time; it neither locks that
state nor supplies off-host rollback resistance or one-use execution authority.
No I/O, nonce generation, new work allowance or renewed clock window is here.
"""
from __future__ import annotations

from dataclasses import dataclass
import time

from catchplate import authority_current_root_head as head
from catchplate import authority_current_root_vector as vector
from catchplate import authority_index_heads as index_heads
from catchplate import authority_oidc_session_activation as assertion
from catchplate import authority_oidc_session_activation_writes as writes
from catchplate import authority_primary_contract as primary


registration, evidence = assertion.registration, assertion.registration.evidence
OPERATION = "oidc.session.activate"
CONTEXT_DOMAIN = "catchplate.oidcSessionActivationPlanningStateContext/v1"
SCOPE_FIELDS = frozenset({"userId", "sessionId", "credentialId", "credentialRecordId", "challengeId",
    "rpId", "origin", "authenticationPolicy", "trustPolicy", "configurationDigest",
    "plannerIdentity", "plannerSpkiDigest", "maximumPlanAgeNs", "maximumClockSkewNs", "deadlineEpochNs"})


class OidcSessionActivationStateError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False)
class _ProjectedRoots:
    """Original-derived ordinary data, never an admitted authority carrier."""

    vector_bytes: bytes
    vector_digest: str
    business_before_roots: tuple
    authorization_before_roots: tuple
    expected_counted_heads: tuple


def _fail(message):
    raise OidcSessionActivationStateError(message)


def _original(raw, maximum, label):
    if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
        _fail("activation state " + label + " is not a bounded immutable original")
    return raw


def _project_on_work(*, vector_bytes, expected_vector_digest, work):
    """Validate the entire original before selecting any activation roots."""
    evidence.capture._SharedLedger(work)
    original = _original(vector_bytes, vector.MAX_BYTES, "complete vector")
    registration._digest(expected_vector_digest)
    document = vector._decode_on_work(original, work=work)
    actual_digest = vector.framing._frame(vector.IDENTITY_DOMAIN, (original,), work)
    registration._same(actual_digest, expected_vector_digest, work, "activation complete-vector identity")
    contracts = primary.primary_table_contracts(OPERATION)
    business = tuple(item.table for item in contracts if item.root_class == "business")
    authorization = tuple(item.table for item in contracts if item.root_class == "authorization")
    identities = index_heads._activation_ids(include_write_heads=True)
    if len(identities) != writes.HEAD_COUNT:
        _fail("activation state projection is not the fixed thirteen-head union")
    work.prepare_scan(document)
    primary_rows = {item["table"]: item for item in document["primaryRoots"]}
    counted_rows = {item["indexId"]: item for item in document["countedRoots"]}
    selected = {
        "business": [primary_rows[table] for table in business],
        "authorization": [primary_rows[table] for table in authorization],
        "heads": [{name: counted_rows[identity][name] for name in
            ("indexId", "indexRevision", "rootDigest", "leafCount")} for identity in identities],
    }
    owned = evidence.capture._JSONCapture(evidence.capture._SharedLedger(work),
        maximum_bytes=vector.MAX_BYTES).visit(selected)
    writes._heads(owned["heads"])
    return _ProjectedRoots(original, actual_digest, tuple(owned["business"]),
        tuple(owned["authorization"]), tuple(owned["heads"]))


def _context_digest_on_work(*, scope, assertion_bytes, old_token_bytes,
        complete_root_vector_bytes, work):
    """Bind the challenge to exact subject/policy/input originals, not a DTO."""
    original_assertion = _original(assertion_bytes, assertion.MAX_ASSERTION_BYTES, "assertion")
    original_vector = _original(complete_root_vector_bytes, vector.MAX_BYTES, "complete vector")
    old = assertion._token(old_token_bytes, work)
    owned = assertion._Capture(evidence.capture._SharedLedger(work),
        maximum_bytes=assertion.MAX_CONTEXT_BYTES).visit(scope)
    registration._closed(owned, SCOPE_FIELDS, "activation planning state scope")
    for name in ("configurationDigest", "plannerSpkiDigest"):
        registration._digest(owned[name])
    evidence._identity(owned["plannerIdentity"])
    for name in ("maximumPlanAgeNs", "deadlineEpochNs"):
        registration._integer(owned[name], "activation state " + name, 1)
    registration._integer(owned["maximumClockSkewNs"], "activation state clock skew", 0)
    # Genuine full-vector decoding rejects source/manifest/inventory drift.
    vector._decode_on_work(original_vector, work=work)
    scope_bytes = evidence.capability._wire(owned, evidence.capture._SharedLedger(work),
        assertion.MAX_CONTEXT_BYTES, assertion.MAX_CONTEXT_NODES)
    return evidence.plan._frame(CONTEXT_DOMAIN,
        (scope_bytes, original_assertion, old, original_vector), work)


def _verify_on_work(*, scope, assertion_bytes, old_token_bytes, complete_root_vector_bytes,
        query_bytes, observation_bytes, enrollment_bytes, root_public_key, now_epoch_ns, work):
    """Repeat original signatures and reject a pending or mismatched state.

    The preserved challenge is not regenerated for retained replay. Such a
    replay authenticates the original observation only within its unchanged
    interval; it is not a new observation or a check at execution time.
    """
    original_query = _original(query_bytes, head.MAX_QUERY_BYTES, "head query")
    original_observation = _original(observation_bytes, head.MAX_BYTES, "head observation")
    original_enrollment = _original(enrollment_bytes,
        head.authorization.MAX_ENROLLMENT_BYTES, "enrollment")
    original_vector = _original(complete_root_vector_bytes, vector.MAX_BYTES, "complete vector")
    original_assertion = _original(assertion_bytes, assertion.MAX_ASSERTION_BYTES, "assertion")
    held_key, held_now = root_public_key, now_epoch_ns
    head.authorization._public(held_key)
    registration._integer(held_now, "activation head admission time", 1)
    old = assertion._token(old_token_bytes, work)
    owned = assertion._Capture(evidence.capture._SharedLedger(work),
        maximum_bytes=assertion.MAX_CONTEXT_BYTES).visit(scope)
    expected_context = _context_digest_on_work(scope=owned, assertion_bytes=original_assertion,
        old_token_bytes=old, complete_root_vector_bytes=original_vector, work=work)
    query = head._decode_query_on_work(original_query, work=work)
    expected_vector = vector.framing._frame(vector.IDENTITY_DOMAIN, (original_vector,), work)
    registration._same(query["contextDigest"], expected_context, work, "activation head original context")
    registration._same(query["expectedVectorDigest"], expected_vector, work, "activation head independent vector")
    payload = head._verify_on_work(observation_bytes=original_observation, query_bytes=original_query,
        enrollment_bytes=original_enrollment, root_public_key=held_key,
        now_epoch_ns=held_now, work=work)
    if payload["pendingRequestDigest"] is not None or payload["pendingDecisionDigest"] is not None:
        _fail("activation planning cannot admit an outstanding state reservation")
    if held_now >= min(payload["expiresAtEpochNs"], owned["deadlineEpochNs"]):
        _fail("activation planning state original interval is expired")
    return payload


def _verify_historical_on_work(*, scope, assertion_bytes, old_token_bytes, complete_root_vector_bytes,
        query_bytes, observation_bytes, enrollment_bytes, root_public_key,
        historical_plan_interval, live_window, transport_deadline_ns, work, _current=None):
    """Join original state history to a separately authenticated plan interval.

    The caller must authenticate the original plan signature before supplying
    its issue/expiry tuple. This helper authenticates all state originals and
    their exact context, not that caller's plan signature. The returned dict
    is history, never a current observation, live lease or execution permission.
    """
    evidence.capture._SharedLedger(work)
    original_query = _original(query_bytes, head.MAX_QUERY_BYTES, "historical head query")
    original_observation = _original(observation_bytes, head.MAX_BYTES, "historical head observation")
    original_enrollment = _original(enrollment_bytes,
        head.authorization.MAX_ENROLLMENT_BYTES, "historical enrollment")
    original_vector = _original(complete_root_vector_bytes, vector.MAX_BYTES, "historical complete vector")
    original_assertion = _original(assertion_bytes, assertion.MAX_ASSERTION_BYTES, "historical assertion")
    held_key = root_public_key
    head.authorization._public(held_key)
    if type(historical_plan_interval) is not tuple or len(historical_plan_interval) != 2:
        _fail("historical activation plan interval must be an exact original pair")
    issued, expires = historical_plan_interval
    registration._integer(issued, "historical activation plan issue", 1)
    registration._integer(expires, "historical activation plan expiry", 1)
    window = assertion.clock._validate(live_window)
    registration._integer(transport_deadline_ns, "historical activation inherited deadline", 1)
    bound = min(window[4], transport_deadline_ns)
    old = assertion._token(old_token_bytes, work)
    owned = assertion._Capture(evidence.capture._SharedLedger(work),
        maximum_bytes=assertion.MAX_CONTEXT_BYTES).visit(scope)
    registration._closed(owned, SCOPE_FIELDS, "historical activation planning state scope")
    registration._integer(owned["maximumPlanAgeNs"], "historical activation plan age", 1,
        evidence.authority.VERIFIER_RESPONSE_MAX_AGE_NS)
    registration._integer(owned["maximumClockSkewNs"], "historical activation plan skew", 0,
        evidence.authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    registration._integer(owned["deadlineEpochNs"], "historical activation original deadline", 1)
    if not 0 < expires - issued <= owned["maximumPlanAgeNs"] or expires > owned["deadlineEpochNs"]:
        _fail("historical activation plan interval exceeds its independent original scope")
    # Capture every caller graph and original before current clock/key work.
    expected_context = _context_digest_on_work(scope=owned, assertion_bytes=original_assertion,
        old_token_bytes=old, complete_root_vector_bytes=original_vector, work=work)
    query = head._decode_query_on_work(original_query, work=work)
    expected_vector = vector.framing._frame(vector.IDENTITY_DOMAIN, (original_vector,), work)
    registration._same(query["contextDigest"], expected_context, work, "historical activation head original context")
    registration._same(query["expectedVectorDigest"], expected_vector, work, "historical activation head independent vector")
    last_epoch, last_monotonic = window[0], window[2]

    def current():
        nonlocal last_epoch, last_monotonic
        now = assertion.clock._check_on_work(window, work=work)
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        registration._integer(monotonic, "historical activation processing monotonic time", 1)
        if now < last_epoch or monotonic < last_monotonic or monotonic >= bound:
            _fail("historical activation state processing expired or its clocks reversed")
        if issued > now + owned["maximumClockSkewNs"]:
            _fail("historical activation plan is issued in the current future")
        last_epoch, last_monotonic = now, monotonic
        return now

    if _current is not None:
        from catchplate import oidc_session_activation_delivery as delivery

        current = delivery._join_current(current, _current, work)
    current()
    payload, enrollment = head._verify_historical_with_enrollment_on_work(
        observation_bytes=original_observation, query_bytes=original_query,
        enrollment_bytes=original_enrollment, root_public_key=held_key,
        live_window=window, transport_deadline_ns=bound, work=work)
    current()
    if payload["pendingRequestDigest"] is not None or payload["pendingDecisionDigest"] is not None:
        _fail("historical activation planning state had an outstanding reservation")
    observed_issue, observed_expiry = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    # The plan records the processing OPENING, not its signing time. The head
    # can therefore be observed afterward. Require a nonempty possible original
    # processing overlap under the actual enrolled head policy, not a claim
    # that the head was already live at opening. These algebraic endpoints are
    # never supplied to a clock or to the live head verifier. Head age is an
    # inclusive integer-nanosecond bound, whereas both expiries are exclusive.
    lower = max(issued, observed_issue - enrollment.payload["maxClockSkewNs"])
    upper = min(expires, observed_expiry,
        observed_issue + enrollment.payload["maxControlAgeNs"] + 1)
    if lower >= upper or expires > observed_expiry:
        _fail("historical activation plan is outside its original observed state interval")
    current()
    return payload
