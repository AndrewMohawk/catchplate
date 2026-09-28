"""Genuine retained-subject replay for separately authorized history recovery.

Historical signer and planning/grant originals prove their original subject,
not a present actor's permission. The fixed HTTP handler must authenticate that
actor and admit the separate recovery purpose. Dispatch repeats this replay
against actual cold-owner custody, then compares independently admitted caller
scalars. No public successful subject object can replace that replay.

Current processing is bounded by cold-owner attestation and one work/window.
No historical issue time is a clock and no original expiry is renewed. This
module does not dispatch, sign, execute SQL or finalize credentials.
"""
from __future__ import annotations

import time

from serverware import control_plane_registration_handoff_subject as live_subject
from serverware import control_plane_registration_history as history


execution, custody_client, custody_startup = (
    live_subject.execution, live_subject.custody_client, live_subject.custody_startup)
startup, evidence, clock = execution.startup, execution.evidence, execution.clock


class RegistrationRecoverySubjectError(ValueError):
    pass


def _open_on_work(work):
    """Open only present processing from actual independently cold-admitted scope."""
    startup._require_pid()
    callback = evidence.production._callback
    owner = callback(work, startup.require_started)
    if (type(owner) is not startup._EnrollmentOwner
            or not callback(work, lambda: owner.sql_handoff_enabled)
            or callback(work, custody_startup.require_started) is not owner._custody):
        raise RegistrationRecoverySubjectError("registration recovery is not cold-enabled")
    material, binding = owner._material, owner._binding
    endpoint = material.execution.completion_endpoint
    window = clock._open_on_work(deadline_epoch_ns=binding.attestation_interval[1],
        maximum_lifetime_ns=min(binding.maximum_deadline_ns, int(endpoint[1] * 1_000_000_000),
            evidence.authority.VERIFIER_RESPONSE_MAX_AGE_NS),
        maximum_clock_skew_ns=material.issuer_policy["maximumClockSkewNs"], work=work)
    if (owner._material is not material or owner._binding is not binding
            or callback(work, startup.require_started) is not owner
            or callback(work, custody_startup.require_started) is not owner._custody):
        raise RegistrationRecoverySubjectError("registration recovery startup changed")
    clock._check_on_work(window, work=work)
    return owner, material, binding, window


def _scope_on_owner(owner, *, live_window, work, transport_deadline_ns=None):
    """Preserve the caller window while rechecking the actual cold owner."""
    startup._require_pid()
    evidence.capture._SharedLedger(work)
    window = clock._validate(live_window)
    shape = evidence.plan.contract
    if transport_deadline_ns is not None:
        shape._integer(transport_deadline_ns, minimum=1)
    inherited = window[4] if transport_deadline_ns is None else min(window[4], transport_deadline_ns)
    if type(owner) is not startup._EnrollmentOwner:
        raise RegistrationRecoverySubjectError("registration recovery requires the actual cold owner")
    custody, binding, material = owner._custody, owner._binding, owner._material
    if type(custody) is not custody_client.ControlPlaneCustodyClient:
        raise RegistrationRecoverySubjectError("registration recovery requires actual retained custody")
    common, endpoint, _private, deadline, bound, owner_live = execution._scope(owner,
        deadline_epoch_ns=window[3], deadline_ns=inherited,
        work=work, _endpoint_kind="completion")
    last_epoch, last_monotonic = window[0], window[2]
    callback = evidence.production._callback

    def current():
        nonlocal last_epoch, last_monotonic
        owner_live()
        if (owner._material is not material or owner._binding is not binding
                or owner._custody is not custody
                or callback(work, startup.require_started) is not owner
                or callback(work, custody_startup.require_started) is not custody
                or callback(work, lambda: custody_client._snapshot(custody)) is not binding):
            raise RegistrationRecoverySubjectError("registration recovery cold owners changed")
        now = clock._check_on_work(window, work=work)
        monotonic = callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if now < last_epoch or monotonic < last_monotonic or now >= deadline or monotonic >= bound:
            raise RegistrationRecoverySubjectError("registration recovery processing expired or reversed")
        last_epoch, last_monotonic = now, monotonic
        owner_live()
        return now

    current()
    return common, endpoint, window, bound, current


def _replay_material_on_owner(owner, local_digest, *, live_window, work,
        transport_deadline_ns=None, _additional_original_bytes=0, _include_outcomes=False):
    """Resolve and replay originals; the real recovery caller keeps this scope."""
    return history._replay_on_owner(owner, local_digest, live_window=live_window, work=work,
        transport_deadline_ns=transport_deadline_ns,
        _additional_original_bytes=_additional_original_bytes, _include_outcomes=_include_outcomes)


def _replay_on_owner(owner, local_digest, *, live_window, work, transport_deadline_ns=None):
    """Preserve the existing scalar-only inspection interface."""
    material = _replay_material_on_owner(owner, local_digest, live_window=live_window,
        work=work, transport_deadline_ns=transport_deadline_ns)
    material.current()
    return material.subject, material.original_bytes


def _inspect_on_owner(owner, local_digest, *, live_window, work, transport_deadline_ns=None):
    """Return the seven subject scalars, never an admission token."""
    result, _original_bytes = _replay_on_owner(owner, local_digest,
        live_window=live_window, work=work, transport_deadline_ns=transport_deadline_ns)
    return result


def inspect_retained_registration_recovery_subject(local_digest):
    """Public-handler lookup; authenticates original subject, not present permission."""
    from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

    digest = live_subject.journal._digest(local_digest)
    work = _ValidationWork(QueryReadValidationLimits())
    owner, material, binding, window = _open_on_work(work)
    startup._require_pid()
    with startup._LOCK:
        if owner._material is not material or owner._binding is not binding:
            raise RegistrationRecoverySubjectError("registration recovery startup changed before inspection")
        result = _inspect_on_owner(owner, digest, live_window=window,
            work=work, transport_deadline_ns=window[4])
        now = clock._check_on_work(window, work=work)
        archived = material.registration_history
        if (archived is not None
                and not archived.valid_from_epoch_ns <= now < archived.valid_until_epoch_ns):
            raise RegistrationRecoverySubjectError("registration history expired before subject return")
        return result
