"""One conservative live window for configured evidence-plan production.

Actual epoch samples are bracketed by actual monotonic samples. The earliest
opening bracket fixes the monotonic deadline once; later checks cannot renew
it. Clock lookup and invocation preserve the existing work on success and
failure. This is a local elapsed-time check, not a trusted hardware clock,
historical authority, process watchdog or guarantee against suspension after
the last sample. No caller-provided clock or replacement allowance is used.
"""
from __future__ import annotations

import time

from catchplate import authority_webauthn_evidence as evidence


class WebAuthnEvidencePlanClockError(ValueError):
    pass


def _sample_on_work(work):
    evidence.capture._SharedLedger(work)
    before = evidence.production._callback(work, lambda: time.monotonic_ns())
    epoch = evidence.production._callback(work, lambda: time.time_ns())
    after = evidence.production._callback(work, lambda: time.monotonic_ns())
    for value in (before, epoch, after):
        evidence.plan.contract._integer(value, minimum=1)
    if after < before:
        raise WebAuthnEvidencePlanClockError("evidence plan monotonic clock reversed within its sample")
    return before, epoch, after


def _validate(window):
    if type(window) is not tuple or len(window) != 7:
        raise WebAuthnEvidencePlanClockError("evidence plan live window is not an exact immutable tuple")
    epoch, before, after, deadline, monotonic_deadline, lifetime, skew = window
    shape = evidence.plan.contract
    for value in (epoch, before, after, deadline, monotonic_deadline):
        shape._integer(value, minimum=1)
    shape._integer(lifetime, evidence.authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    shape._integer(skew, evidence.authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    if (after < before or deadline <= epoch or deadline > epoch + lifetime
            or monotonic_deadline != before + deadline - epoch
            or after >= monotonic_deadline):
        raise WebAuthnEvidencePlanClockError("evidence plan live window is inconsistent or already expired")
    return window


def _open_on_work(*, deadline_epoch_ns, maximum_lifetime_ns, maximum_clock_skew_ns, work):
    """Clip an admitted deadline once, including time spent sampling clocks."""
    evidence.capture._SharedLedger(work)
    shape = evidence.plan.contract
    shape._integer(deadline_epoch_ns, minimum=1)
    shape._integer(maximum_lifetime_ns, evidence.authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    shape._integer(maximum_clock_skew_ns, evidence.authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    before, epoch, after = _sample_on_work(work)
    deadline = min(deadline_epoch_ns, epoch + maximum_lifetime_ns)
    return _validate((epoch, before, after, deadline, before + deadline - epoch,
        maximum_lifetime_ns, maximum_clock_skew_ns))


def _deadline_epoch_ns(window):
    return _validate(window)[3]


def _check_on_work(window, *, work):
    """Return a fresh epoch sample only inside the unchanged dual-clock window."""
    epoch, before, after, deadline, monotonic_deadline, _lifetime, skew = _validate(window)
    current_before, current_epoch, current_after = _sample_on_work(work)
    if (current_before < after or current_epoch >= deadline
            or current_after >= monotonic_deadline):
        raise WebAuthnEvidencePlanClockError("evidence plan live deadline expired or monotonic clock reversed")
    # The epoch instant can lie anywhere inside each monotonic bracket. This
    # interval accounts for sampling latency even when allowed skew is zero.
    lower = epoch + current_before - after - skew
    upper = epoch + current_after - before + skew
    if not lower <= current_epoch <= upper:
        raise WebAuthnEvidencePlanClockError("evidence plan epoch and monotonic clocks diverged")
    return current_epoch
