"""Historical caller, encrypted plan and grant originals in one bounded call.

This is a private primitive for a future independently admitted historical
receiving role. It takes actual originals and independent scope/keys, never
successful admission carriers, caller-chosen clocks or a grant locator as
proof. All cryptographic/semantic replay shares the actual current processing
window and allowance; expired originals supply no renewed execution authority.

No reservation/ACK admission, SQL, immutable commit read, completion signing,
state publication, token release or public recovery is implemented here.
Generic activation historical completion deliberately remains rejected.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import authority_oidc_session_activation_execution_authorization as caller
from catchplate import authority_oidc_session_activation_execution_history as history


authorization, grants, plan, shape = caller.authorization, caller.grants, caller.plan, caller.shape
clock, evidence = history.clock, history.evidence
OPERATION = history.OPERATION
MAX_ORIGINAL_BYTES = history.MAX_ORIGINAL_BYTES


class OidcSessionActivationHistoryExchangeError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _HistoricalExchange:
    """Genuine same-call facts, not an accepted downstream authority input."""

    authorization_digest: str
    grant_digest: str
    database_id: str
    generation_digest: str
    replayed: history._HistoricalReplayedPlan
    live: object


def _verify_on_work(*, originals, expectations, before_vector_bytes, authorization_bytes,
        grant_bytes, authorization_enrollment_bytes, grant_enrollment_bytes,
        current_root_enrollment_bytes, root_public_key, planner_public_key,
        operation_public_key, configuration_digest, bundle_key, delivery_custody_key,
        live_window, transport_deadline_ns, work, _current=None):
    """Authenticate originals, rederive actual effects, then join every grant claim."""
    evidence.capture._SharedLedger(work)
    raw2, before = grants.replay._originals(OPERATION, originals, before_vector_bytes)
    caller_raw = authorization._original(authorization_bytes,
        caller.MAX_AUTHORIZATION_BYTES, "historical activation caller")
    grant_raw = authorization._original(grant_bytes, grants.MAX_GRANT_BYTES,
        "historical activation grant")
    caller_enrollment = authorization._original(authorization_enrollment_bytes,
        caller.MAX_ENROLLMENT_BYTES, "historical activation caller enrollment")
    grant_enrollment = authorization._original(grant_enrollment_bytes,
        grants.MAX_ENROLLMENT_BYTES, "historical activation grant enrollment")
    state_enrollment = authorization._original(current_root_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "historical activation state enrollment")
    if sum(len(raw) for raw in (*raw2, before, caller_raw, grant_raw,
            caller_enrollment, grant_enrollment, state_enrollment)) > MAX_ORIGINAL_BYTES:
        raise OidcSessionActivationHistoryExchangeError("historical activation exchange exceeds its aggregate bound")
    root, planner, operation_key, config = (root_public_key, planner_public_key,
        operation_public_key, configuration_digest)
    for key in (root, planner, operation_key):
        authorization._public(key)
    shape._digest(config)
    if (type(bundle_key) is not bytes or len(bundle_key) != 32
            or type(delivery_custody_key) is not bytes or len(delivery_custody_key) != 32):
        raise OidcSessionActivationHistoryExchangeError("historical activation exchange requires exact private keys")
    held_bundle, held_delivery = bundle_key, delivery_custody_key
    work.charge(input_bytes=64)
    if held_bundle == held_delivery:
        raise OidcSessionActivationHistoryExchangeError("historical activation private key purposes coincide")
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    bound = min(window[4], transport_deadline_ns)
    owned = caller.expectations_wire._capture_on_work(expectations, work=work)
    history._expectations(owned["request"], owned["scope"], window, work)
    plan._same(owned["scope"]["configurationDigest"], config, work,
        "historical activation independent configuration")
    _window, processing = history.delivery._window(window, bound, work)
    processing = history.delivery._join_current(processing, _current, work)
    authorized = replayed = None

    def current():
        samples = []
        if authorized is not None:
            samples.append(authorized.live())
        if replayed is not None:
            samples.append(replayed.live())
        samples.append(processing())
        if any(later < earlier for earlier, later in zip(samples, samples[1:])):
            raise OidcSessionActivationHistoryExchangeError("historical activation processing reversed across replay")
        return samples[-1]

    current()
    authorized = caller._verify_historical_on_work(authorization_bytes=caller_raw,
        authorization_enrollment_bytes=caller_enrollment, current_root_enrollment_bytes=state_enrollment,
        grant_enrollment_bytes=grant_enrollment, root_public_key=root, configuration_digest=config,
        planner_public_key=planner, operation_public_key=operation_key, originals=raw2,
        expectations=owned, before_vector_bytes=before, live_window=window,
        transport_deadline_ns=bound, work=work)
    if type(authorized) is not caller._HistoricalAuthorization:
        raise OidcSessionActivationHistoryExchangeError("historical activation requires actual caller admission")
    current()
    # Authenticate the original grant before private-bundle opening. Full
    # replay below, not this signature or an alleged result, derives claims.
    grant, grant_digest = grants._verify_historical_control_on_work(grant_bytes=grant_raw,
        grant_enrollment_bytes=grant_enrollment, current_root_enrollment_bytes=state_enrollment,
        root_public_key=root, planner_public_key=planner, operation_public_key=operation_key,
        expected_authorization_digest=authorized.authorization_digest, work=work)
    current()
    replayed = history._replay_on_work(envelope_bytes=raw2[0], encrypted_originals_bytes=raw2[1],
        expected_request=owned["request"], expected_scope=owned["scope"],
        expected_journal_digest=owned["journalDigest"], planner_public_key=planner,
        state_enrollment_bytes=state_enrollment, state_root_public_key=root,
        bundle_key=held_bundle, delivery_custody_key=held_delivery, before_vector_bytes=before,
        live_window=window, transport_deadline_ns=bound, work=work, _current=_current)
    if type(replayed) is not history._HistoricalReplayedPlan:
        raise OidcSessionActivationHistoryExchangeError("historical activation requires genuine original replay")
    current()
    expected_claims = grants._replay_claims(replayed, work)
    for name, expected in expected_claims.items():
        plan._same(grant[name], expected, work, "historical activation grant actual replay " + name)
    for name, expected in (("operation", OPERATION), ("requestDigest", authorized.request_digest),
            ("operationId", authorized.operation_id), ("planDigest", authorized.plan_digest),
            ("retainedRecordDigest", authorized.retained_record_digest),
            ("beforeVectorDigest", authorized.before_vector_digest),
            ("databaseId", authorized.database_id), ("generationDigest", authorized.generation_digest),
            ("currentRootEnrollmentDigest", authorized.current_root_enrollment_digest),
            ("grantEnrollmentDigest", authorized.grant_enrollment_digest)):
        plan._same(grant[name], expected, work, "historical activation grant independent original " + name)
    issued, expires = replayed.original_interval
    if not (grant["issuedAtEpochNs"] == issued <= authorized.issued_at_epoch_ns
            < authorized.expires_at_epoch_ns <= expires
            and grant["expiresAtEpochNs"] <= authorized.expires_at_epoch_ns):
        raise OidcSessionActivationHistoryExchangeError("historical activation grant renews original post-plan authority")
    # Plan issue was authenticated against original scope skew, independently
    # of the current processing bracket. Equal grant issue preserves that time.
    current()
    result = _HistoricalExchange(authorized.authorization_digest, grant_digest,
        authorized.database_id, authorized.generation_digest, replayed, current)
    current()
    return result
