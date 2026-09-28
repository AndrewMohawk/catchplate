"""Read-only exact recovery target originals, never a successful permission.

Only the actual admitted owner's unique target index is used. Selection neither
authenticates the intent nor repeats activation, completion, SQL or release.
The recovery actor must independently replay finalization and admit historical
intent/possession before deriving its own target and fresh WebAuthn binding.
"""
from __future__ import annotations

import time

from serverware import control_plane_oidc_session_activation_execution as execution
from serverware.authority_query_read_work import _ValidationWork


startup, custody, clock = execution.startup, execution.custody, execution.clock


def _select_on_owner(owner, *, local_digest, live_window, transport_deadline_ns, work, current,
        maximum_original_bytes=None):
    """Return None or (dispatch claim, consume claim, intent record) DATA.

    ``current`` is the original owner-scope guard. It must not recursively
    select records, replay target admission or acquire the custody I/O lock.
    The same work is charged directly; never wrap this call in a stable native
    callback or replace its allowance/window after an unavailable result.
    """
    if (type(owner) is not startup._EnrollmentOwner or type(work) is not _ValidationWork
            or not callable(current)):
        execution._fail("recovery selection requires the actual owner and original work")
    if maximum_original_bytes is not None and (type(maximum_original_bytes) is not int
            or not 0 < maximum_original_bytes <= 64 * 1024 * 1024):
        execution._fail("recovery selection remaining original capacity differs")
    target = custody.journal._digest(local_digest)
    window = clock._validate(live_window)
    bound = transport_deadline_ns
    if type(bound) is not int or not window[2] < bound <= window[4]:
        execution._fail("recovery selection cannot widen its original deadline")
    parent, binding, retained = owner._material, owner._binding, owner._custody
    limits = work.limits
    ceilings = limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes
    observed_epoch = window[0]
    observed_monotonic = window[2]

    def guarded():
        nonlocal observed_epoch, observed_monotonic
        current()
        if (owner._material is not parent or owner._binding is not binding or owner._custody is not retained
                or work.limits is not limits
                or ceilings != (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)):
            execution._fail("recovery selection original owner or work changed")
        receipt = execution.production._callback(work, lambda: startup._continuity(owner))
        epoch = clock._check_on_work(window, work=work)
        monotonic = execution.production._callback(work, time.monotonic_ns)
        if (type(receipt) is not int or epoch < receipt or epoch < observed_epoch
                or monotonic < observed_monotonic or monotonic >= bound):
            execution._fail("recovery selection original lifetime changed")
        observed_epoch, observed_monotonic = epoch, monotonic
        current()
        return epoch

    guarded()
    selected = custody.ControlPlaneCustodyClient.load_oidc_session_activation_recovery_target(
        retained, target, work=work, current=guarded,
        maximum_original_bytes=maximum_original_bytes)
    guarded()
    return selected
