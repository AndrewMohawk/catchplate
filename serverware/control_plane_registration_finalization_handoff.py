"""Present-purpose SQL execution from genuine retained finalization ownership.

The public handler authenticates the current actor/session and separately admits
the finalization-execution purpose. This facade independently repeats the real
grant, associated signer/evidence and acknowledged completion replay under the
cold owner lock. No incoming subject/admission dictionary substitutes for it.

The dedicated private SQL caller joins the retained raw13, independently pinned
pending scope and genuine original admission before its durable local claim and
single exchange. Returned bounded raw4 is retained before semantic acceptance.
Only an observed-commit returns success here; that unsigned observation neither
completes current-root finalization nor activates an OIDC session. No uncertainty
or exception clears an attempt, renews permission or grants automatic retry.
"""
from __future__ import annotations

from serverware import control_plane_registration_finalization_reservation as retained
from serverware import control_plane_registration_finalization_sql as sql


startup, evidence, clock = retained.startup, retained.evidence, retained.clock
custody_client, journal, handoff = retained.custody_client, retained.journal, retained.handoff


class RetainedFinalizationSqlOutcomeError(ValueError):
    """Submitted locator only; no claim about durability, noncommit or retry."""

    __slots__ = ("local_digest",)

    def __init__(self, local_digest):
        self.local_digest = journal._digest(local_digest)
        super().__init__("finalization SQL outcome is not established; automatic retry is not allowed")


def _inspect_on_owner(owner, digest, *, live_window, transport_deadline_ns, work):
    """Genuine same-call subject plus original bytes, never a reusable proof."""
    callback = evidence.production._callback
    if (type(owner) is not startup._EnrollmentOwner
            or not callback(work, lambda: owner.finalization_sql_enabled)):
        raise startup.EnrollmentStartupError("retained finalization SQL is not cold-enabled")
    material, binding, custody = owner._material, owner._binding, owner._custody
    # This actual helper replays full finalization authorization/plan/grant,
    # the associated evidence completion and original signer, then compares
    # the entire request reconstructed from THAT signer. A local link alone
    # and the enrollment's historical authorization mode are not ownership.
    subject, grant, window, bound, retained_live, original_bytes = retained._inspect_on_owner(
        owner, digest, live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)
    raw13 = sql._retained_originals(owner, digest, work=work)
    work.charge(input_bytes=sum(len(raw) for raw in (*grant, *raw13[:10])))
    if raw13[:10] != grant:
        raise startup.EnrollmentStartupError("finalization SQL association changed during ownership replay")
    original_bytes += sum(len(raw) for raw in raw13[10:])
    observed = callback(work,
        lambda: custody_client.ControlPlaneCustodyClient.load_registration_finalization_outcomes(
            custody, digest))
    if (observed.finalization_digest != digest
            or observed.source_revision != evidence.authority.SOURCE_REVISION):
        raise startup.EnrollmentStartupError("finalization SQL outcomes differ from the replayed source scope")
    if observed.sql_outcome is not None:
        original_bytes += sum(len(raw) for raw in observed.sql_outcome.originals)
    if original_bytes > evidence.authority.MAX_RESULT_BYTES:
        raise startup.EnrollmentStartupError("finalization SQL complete retained inventory exceeds its bound")

    def current():
        retained_live()
        if (owner._material is not material or owner._binding is not binding
                or owner._custody is not custody
                or not callback(work, lambda: owner.finalization_sql_enabled)):
            raise startup.EnrollmentStartupError("finalization SQL cold scope changed during retained replay")
        callback(work, lambda: sql.transport._check_deadline(bound))
        retained_live()

    current()
    return subject, raw13, window, bound, current, original_bytes, observed


def _run(local_digest, *, expected_user_id=None, expected_session_id=None, dispatch):
    from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

    startup._require_pid()
    digest = journal._digest(local_digest)
    if type(dispatch) is not bool:
        raise startup.EnrollmentStartupError("finalization SQL mode is not source selected")
    if dispatch:
        expected_user_id, expected_session_id = handoff._expected_subject(expected_user_id, expected_session_id)
    work = _ValidationWork(QueryReadValidationLimits())
    callback = evidence.production._callback
    try:
        owner = callback(work, startup.require_started)
        if (type(owner) is not startup._EnrollmentOwner
                or not callback(work, lambda: owner.finalization_sql_enabled)
                or not callback(work, lambda: owner.sql_handoff_enabled)
                or callback(work, retained.subjects.custody_startup.require_started) is not owner._custody):
            raise startup.EnrollmentStartupError("finalization SQL requires actual enabled cold owners")
        material, binding, custody = owner._material, owner._binding, owner._custody
        endpoint = sql.transport._endpoint(material.finalization.sql_endpoint)
        window = clock._open_on_work(deadline_epoch_ns=binding.attestation_interval[1],
            maximum_lifetime_ns=min(binding.maximum_deadline_ns, int(endpoint[1] * 1_000_000_000),
                evidence.authority.VERIFIER_RESPONSE_MAX_AGE_NS),
            maximum_clock_skew_ns=material.issuer_policy["maximumClockSkewNs"], work=work)
        startup._require_pid()
        with startup._LOCK:
            if (owner._material is not material or owner._binding is not binding
                    or owner._custody is not custody or callback(work, startup.require_started) is not owner
                    or callback(work, retained.subjects.custody_startup.require_started) is not custody):
                raise startup.EnrollmentStartupError("finalization SQL owners changed before inspection")
            subject, raw13, window, bound, current, original_bytes, observed = _inspect_on_owner(
                owner, digest, live_window=window, transport_deadline_ns=window[4], work=work)
            if not dispatch:
                current()
                return subject
            evidence.plan._same(subject["userId"], expected_user_id, work,
                "finalization SQL differs from the independently authenticated current user")
            evidence.plan._same(subject["sessionId"], expected_session_id, work,
                "finalization SQL differs from the independently authenticated current session")
            if observed.sql_attempt is not None:
                raise RetainedFinalizationSqlOutcomeError(digest)
            current()
            # The private caller independently rejoins raw13, admits original
            # pending scope, then claims before one send and records the raw4.
            # The same-call subject is not passed as an authority object.
            response = startup._EnrollmentOwner._request_registration_finalization_sql(owner,
                local_digest=digest, originals=raw13, live_window=window,
                transport_deadline_ns=bound, work=work)
            response = sql.transport._originals(response, response=True)
            if original_bytes + sum(len(raw) for raw in response) > evidence.authority.MAX_RESULT_BYTES:
                raise startup.EnrollmentStartupError("finalization SQL exchange exceeds its complete retained bound")
            current()
            if response[0] != b"observed-commit":
                raise RetainedFinalizationSqlOutcomeError(digest)
            return digest, response
    except Exception as exc:
        if dispatch:
            raise RetainedFinalizationSqlOutcomeError(digest) from exc
        raise


def inspect_retained_finalization_sql_subject(local_digest):
    """Return seven genuinely replayed subject scalars, not present permission."""
    return _run(local_digest, dispatch=False)


def execute_retained_registration_finalization(local_digest, *, expected_user_id, expected_session_id):
    """Return (local grant ID, unsigned observed-commit) after durable retention."""
    return _run(local_digest, expected_user_id=expected_user_id,
        expected_session_id=expected_session_id, dispatch=True)
