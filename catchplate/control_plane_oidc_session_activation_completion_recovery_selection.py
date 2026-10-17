"""Read-only pre-intent claim/prepared selection, never target authority.

The genuine historical inspector must authenticate the selected originals and
bind their target and old-token possession independently. No SQL, completion,
retry, journal publication or release is performed by this selector.
"""
from __future__ import annotations

import time

from catchplate import control_plane_oidc_session_activation_execution as execution
from catchplate.authority_query_read_work import _ValidationWork


startup, custody, clock = execution.startup, execution.custody, execution.clock
MAX_ORIGINAL_BYTES = 64 * 1024**2
METADATA_RESERVATION_BYTES = custody.journal._COMPLETION_RECOVERY_TARGET_FIXED_BYTES


def _select_on_owner(owner, *, local_digest, live_window, transport_deadline_ns,
        work, current, _additional_original_bytes=0):
    """Return None or exact (dispatch claim, prepared raw5 record) DATA.

    Additional bytes only consume the existing 64 MiB representation ceiling;
    they neither renew work nor grant authority. The original owner-scope
    current must not reselect records or reacquire the journal I/O lock. Invoke
    directly because the bounded loader charges this same work itself.
    """
    if (type(owner) is not startup._EnrollmentOwner or type(work) is not _ValidationWork
            or not callable(current)):
        execution._fail("completion recovery selection requires actual owner and original work")
    if (type(_additional_original_bytes) is not int
            or not 0 <= _additional_original_bytes < MAX_ORIGINAL_BYTES):
        execution._fail("completion recovery selection remaining capacity differs")
    target = custody.journal._digest(local_digest)
    window = clock._validate(live_window)
    bound = transport_deadline_ns
    if type(bound) is not int or not window[2] < bound <= window[4]:
        execution._fail("completion recovery selection cannot widen its original deadline")
    parent, binding, retained = owner._material, owner._binding, owner._custody
    limits = work.limits
    ceilings = limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes
    observed_epoch, observed_monotonic = window[0], window[2]

    def guarded():
        nonlocal observed_epoch, observed_monotonic
        current()
        if (owner._material is not parent or owner._binding is not binding or owner._custody is not retained
                or work.limits is not limits
                or ceilings != (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)):
            execution._fail("completion recovery selection original owner or work changed")
        receipt = execution.production._callback(work, lambda: startup._continuity(owner))
        epoch = clock._check_on_work(window, work=work)
        monotonic = execution.production._callback(work, time.monotonic_ns)
        if (type(receipt) is not int or epoch < receipt or epoch < observed_epoch
                or monotonic < observed_monotonic or monotonic >= bound):
            execution._fail("completion recovery selection original lifetime changed")
        observed_epoch, observed_monotonic = epoch, monotonic
        current()
        return epoch

    guarded()
    selected = custody.ControlPlaneCustodyClient.load_oidc_session_activation_completion_recovery_target(
        retained, target, work=work, current=guarded,
        maximum_original_bytes=MAX_ORIGINAL_BYTES - _additional_original_bytes)
    guarded()
    return selected
