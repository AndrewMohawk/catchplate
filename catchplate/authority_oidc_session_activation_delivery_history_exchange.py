"""Historical consume caller/grant originals before one private proof replay.

Original signatures and interval algebra never renew execution permission.
Current processing uses the supplied real window/work, not an old issue time.
Only the actual completion-purpose provenance owner may reach private replay;
no successful carrier, generic replay family or live-expiry bypass is accepted.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import authority_oidc_session_activation_delivery_execution_authorization as caller
from catchplate import authority_oidc_session_activation_delivery_execution_grant as grants
from catchplate import authority_oidc_session_activation_delivery_execution_grant_admission as identities
from catchplate import authority_oidc_session_activation_delivery_execution_history as history


authorization, plan, shape = caller.authorization, caller.plan, caller.shape
capture, clock, evidence = caller.capture, caller.clock, caller.evidence
OPERATION = caller.OPERATION
MAX_ORIGINAL_BYTES = caller.MAX_ORIGINAL_BYTES


class DeliveryHistoryExchangeError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _HistoricalExchange:
    """Actual same-call facts; no API accepts this as original authority."""

    authorization_digest: str
    grant_digest: str
    database_id: str
    generation_digest: str
    replayed: history._HistoricalReplayedDelivery
    live: object


def _bytes_equal(actual, expected, work, label):
    if type(actual) is not bytes or type(expected) is not bytes:
        raise DeliveryHistoryExchangeError("historical consume " + label + " is not original bytes")
    work.charge(input_bytes=len(actual) + len(expected))
    if actual != expected:
        raise DeliveryHistoryExchangeError("historical consume " + label + " differs")


def _verify_on_work(*, originals, expectations, before_vector_bytes, authorization_bytes,
        grant_bytes, authorization_enrollment_bytes, grant_enrollment_bytes,
        current_root_enrollment_bytes, root_public_key, planner_public_key,
        operation_public_key, configuration_digest, activation_expectations,
        activation_scope, activation_planner_public_key, historical_custody, bundle_key,
        live_window, transport_deadline_ns, work):
    """Admit original controls, replay once, then join actual historical claims."""
    ledger = capture._SharedLedger(work)
    if type(originals) is not tuple or len(originals) != 2:
        raise DeliveryHistoryExchangeError("historical consume requires immutable plan/ciphertext raw2")
    signed = authorization._original(originals[0], caller.contract.MAX_BYTES, "historical consume plan")
    ciphertext = caller.bundle._bounded_frame(originals[1])
    raw2 = signed, ciphertext
    before = authorization._original(before_vector_bytes, caller.vector.MAX_BYTES, "historical consume before vector")
    caller_raw = authorization._original(authorization_bytes,
        caller.MAX_AUTHORIZATION_BYTES, "historical consume caller authorization")
    grant_raw = authorization._original(grant_bytes, grants.MAX_GRANT_BYTES, "historical consume grant")
    caller_enrollment = authorization._original(authorization_enrollment_bytes,
        caller.MAX_ENROLLMENT_BYTES, "historical consume caller enrollment")
    grant_enrollment = authorization._original(grant_enrollment_bytes,
        caller.enrollments.MAX_ENROLLMENT_BYTES, "historical consume grant enrollment")
    state_enrollment = authorization._original(current_root_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "historical consume state enrollment")
    total = sum(len(raw) for raw in (*raw2, before, caller_raw, grant_raw,
        caller_enrollment, grant_enrollment, state_enrollment))
    if total > MAX_ORIGINAL_BYTES:
        raise DeliveryHistoryExchangeError("historical consume originals exceed the whole-inventory bound")
    root, planner, operation_key, activation_planner, config = (root_public_key, planner_public_key,
        operation_public_key, activation_planner_public_key, configuration_digest)
    for public in (root, planner, operation_key, activation_planner):
        authorization._public(public)
    shape._digest(config)
    owner, private_key = historical_custody, bundle_key
    if type(owner) is not history.custody.OidcSessionActivationHistoryCustody:
        raise DeliveryHistoryExchangeError("historical consume requires the actual completion provenance owner")
    if type(private_key) is not bytes or len(private_key) != caller.bundle.KEY_BYTES:
        raise DeliveryHistoryExchangeError("historical consume requires an independent exact bundle key")
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    bound = min(window[4], transport_deadline_ns)
    work.charge(input_bytes=total + len(private_key))
    owned = caller.consume.assertion._Capture(ledger,
        maximum_bytes=caller.consume.assertion.MAX_CONTEXT_BYTES).visit({
            "expectations": expectations, "activationExpectations": activation_expectations,
            "activationScope": activation_scope})
    # Every external graph, original, key and actual-owner reference is held
    # before typed commitments, clock sampling or any native key callback.
    expected = caller.expectations_wire._capture_on_work(owned["expectations"], work=work)
    history._scope(expected, window, work)
    caller.registration._closed(owned["activationScope"], caller.consume._ACTIVATION_SCOPE_FIELDS,
        "historical consume independent activation scope")
    plan._same(expected["scope"]["configurationDigest"], config, work,
        "historical consume independent configuration")
    history.custody.OidcSessionActivationHistoryCustody.require_consume_completion_on_work(owner, work=work)
    held = caller._Inputs(raw2, before, caller_enrollment, state_enrollment, grant_enrollment,
        root, planner, operation_key, config, expected, window, bound)
    processing = caller._clock(held, work)
    caller_payload = caller_policy = grant_payload = grant_policy = replayed = None

    def current():
        first, _first_mono = processing()
        if replayed is not None:
            replay_now = replayed.live()
            shape._integer(replay_now, minimum=1)
            now, _mono = processing()
            if not first <= replay_now <= now:
                raise DeliveryHistoryExchangeError("historical consume processing reversed across replay")
        else:
            now = first
        if (caller_payload is not None
                and caller_payload["issuedAtEpochNs"] > now + caller_policy["maximumClockSkewNs"]):
            raise DeliveryHistoryExchangeError("historical consume caller issue is in the current future")
        if (grant_payload is not None
                and grant_payload["issuedAtEpochNs"] > now + grant_policy["maximumClockSkewNs"]):
            raise DeliveryHistoryExchangeError("historical consume grant issue is in the current future")
        return now

    current()
    enrolled_caller = caller._enrollment(held, work)
    caller_envelope = caller._read(caller_raw, enrollment=False, work=work)
    caller_payload, caller_policy = caller_envelope["payload"], enrolled_caller.payload
    caller.primitives._signature(caller_envelope, enrolled_caller.caller_public_key,
        caller.MAX_AUTHORIZATION_BYTES, work)
    for name in caller._SCOPE_FIELDS:
        plan._same(caller_payload[name], caller_policy[name], work, "historical consume caller scope " + name)
    plan._same(caller_payload["authorizationEnrollmentDigest"], enrolled_caller.enrollment_digest,
        work, "historical consume caller enrollment")
    plan._same(caller_payload["callerMeasurementDigest"], caller_policy["callerKey"]["measurementDigest"],
        work, "historical consume caller measurement")
    authorization._interval(caller_payload, caller_policy["maximumAgeNs"])
    current()
    known_plan, plan_digest = history._authenticate(signed, expected["request"],
        expected["scope"], planner, current, work)
    facts = {name: expected["request"][name] for name in ("requestDigest", "operationId")}
    facts.update({"planDigest": plan_digest,
        "retainedRecordDigest": plan._frame(caller.bundle.RECORD_IDENTITY_DOMAIN, raw2, work),
        "journalDigest": expected["journalDigest"],
        "beforeVectorDigest": caller.vector._digest_on_work(before, work=work)})
    for name in caller._FACT_FIELDS:
        plan._same(caller_payload[name], facts[name], work, "historical consume caller original " + name)
    caller_issued, caller_expires = caller_payload["issuedAtEpochNs"], caller_payload["expiresAtEpochNs"]
    if not known_plan["issuedAtEpochNs"] <= caller_issued < caller_expires <= known_plan["expiresAtEpochNs"]:
        raise DeliveryHistoryExchangeError("historical consume caller escapes its original plan interval")
    authorization_digest = plan._frame(caller.REQUEST_IDENTITY_DOMAIN, (caller_raw,), work)
    caller.primitives._unchanged(caller_raw, caller_envelope, caller.MAX_AUTHORIZATION_BYTES, work)
    current()

    enrolled_grant = caller.enrollments._admit_enrollment_on_work(grant_enrollment_bytes=grant_enrollment,
        current_root_enrollment_bytes=state_enrollment, root_public_key=root, work=work)
    caller.primitives._separate(enrolled_grant.authorizer_public_key, (planner, operation_key), work)
    grant_policy = enrolled_grant.payload
    grant_payload, grant_digest = grants._verify_signature_on_work(grant_raw,
        enrolled_grant.authorizer_public_key, work)
    # _frames is only the neutral immutable-byte descriptor helper. Neither
    # live admission nor a live receiving-custody result is used in this path.
    frames = identities._frames(raw2, work)
    bindings = {"schema": grants.GRANT_PAYLOAD_SCHEMA, "sourceRevision": grants.authority.SOURCE_REVISION,
        "grantEnrollmentDigest": enrolled_grant.enrollment_digest,
        "currentRootEnrollmentDigest": grant_policy["currentRootEnrollmentDigest"],
        "configurationDigest": config, "databaseId": grant_policy["databaseId"],
        "generationDigest": grant_policy["generationDigest"],
        "authorizerMeasurementDigest": grant_policy["authorizer"]["measurementDigest"],
        "operation": OPERATION, "requestDigest": facts["requestDigest"], "operationId": facts["operationId"],
        "requestAuthorizationDigest": authorization_digest, "journalDigest": facts["journalDigest"],
        "retainedRecordDigest": facts["retainedRecordDigest"], "planDigest": facts["planDigest"],
        "beforeVectorDigest": facts["beforeVectorDigest"], "originalFrames": frames}
    for name, value in bindings.items():
        plan._same(grant_payload[name], value, work, "historical consume grant independent control " + name)
    for name in ("databaseId", "generationDigest", "currentRootEnrollmentDigest", "grantEnrollmentDigest"):
        plan._same(grant_payload[name], caller_policy[name], work, "historical consume grant/caller scope " + name)
    authorization._interval(grant_payload, grant_policy["maximumGrantAgeNs"])
    if (grant_payload["issuedAtEpochNs"] != known_plan["issuedAtEpochNs"]
            or grant_payload["originalIssuedAtEpochNs"] != known_plan["issuedAtEpochNs"]
            or grant_payload["originalExpiresAtEpochNs"] != known_plan["expiresAtEpochNs"]
            or grant_payload["expiresAtEpochNs"] > caller_expires):
        raise DeliveryHistoryExchangeError("historical consume grant renews original plan/caller authority")
    current()

    # All original caller/root/grant signatures and public commitments above
    # precede private opening. The full proof/provenance replay occurs once.
    replayed = history._replay_on_work(envelope_bytes=signed, encrypted_originals_bytes=ciphertext,
        expected_request=expected["request"], expected_scope=expected["scope"],
        expected_journal_digest=expected["journalDigest"], state_enrollment_bytes=state_enrollment,
        before_vector_bytes=before, activation_expectations=owned["activationExpectations"],
        activation_scope=owned["activationScope"], planner_public_key=planner,
        activation_planner_public_key=activation_planner, operation_public_key=operation_key,
        state_root_public_key=root, historical_custody=owner, bundle_key=private_key,
        live_window=window, transport_deadline_ns=bound, work=work)
    if type(replayed) is not history._HistoricalReplayedDelivery:
        raise DeliveryHistoryExchangeError("historical consume lacks its genuine same-call proof replay")
    current()
    shape._literal(replayed.operation, OPERATION)
    plan._same(replayed.request, expected["request"], work, "historical consume replayed request")
    if type(replayed.originals) is not tuple or len(replayed.originals) != 2:
        raise DeliveryHistoryExchangeError("historical consume replay lost its raw2 originals")
    for actual, original in zip(replayed.originals, raw2):
        _bytes_equal(actual, original, work, "replayed plan/ciphertext")
    _bytes_equal(replayed.before_vector_bytes, before, work, "replayed before vector")
    issued, expires = replayed.original_interval
    claims = {"operation": replayed.operation, "requestDigest": replayed.request["requestDigest"],
        "operationId": replayed.request["operationId"], "retainedRecordDigest": replayed.retained_record_digest,
        "planDigest": replayed.plan_digest, "beforeVectorDigest": replayed.before_vector_digest,
        "afterVectorDigest": replayed.after_vector_digest,
        "resultDigest": evidence.plan._json_digest(identities._RESULT_DOMAIN, replayed.result, ledger),
        "originalFrames": frames, "originalIssuedAtEpochNs": issued, "originalExpiresAtEpochNs": expires}
    for name, value in claims.items():
        plan._same(grant_payload[name], value, work, "historical consume grant genuine replay " + name)
    if not (grant_payload["issuedAtEpochNs"] == issued <= caller_issued < caller_expires <= expires
            and grant_payload["expiresAtEpochNs"] <= caller_expires):
        raise DeliveryHistoryExchangeError("historical consume replay escapes original post-plan authority")
    # Expired originals remain historical data. Never intersect the real
    # processing deadline with their expired plan/caller/grant intervals.
    current()
    result = _HistoricalExchange(authorization_digest, grant_digest,
        caller_policy["databaseId"], caller_policy["generationDigest"], replayed, current)
    current()
    return result
