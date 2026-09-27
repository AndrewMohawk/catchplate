"""Narrow an original processing bracket without sampling or renewing time."""
from __future__ import annotations

from serverware import authority_webauthn_evidence_plan_clock as clock


def _narrow(live_window, *, deadline_epoch_ns, maximum_lifetime_ns, maximum_clock_skew_ns):
    original = clock._validate(live_window)
    shape = clock.evidence.plan.contract
    shape._integer(deadline_epoch_ns, minimum=1)
    shape._integer(maximum_lifetime_ns, clock.evidence.authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    shape._integer(maximum_clock_skew_ns, clock.evidence.authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    age = min(original[5], maximum_lifetime_ns)
    skew = min(original[6], maximum_clock_skew_ns)
    deadline = min(original[3], deadline_epoch_ns, original[0] + age)
    return clock._validate((*original[:3], deadline,
        original[1] + deadline - original[0], age, skew))
