"""One data-only historical consume receipt after genuine normal cleanup.

The actual completion receiver remains live through actor/trust cleanup. Its
closed guard is never revived: finish checks the retained source association,
normal-exit markers and final original deadline before releasing fixed data.
No token, cookie, current-session authority or signed-send capability is made.
"""
from __future__ import annotations

import os
import threading
import time

from fastapi.responses import JSONResponse

from serverware import control_plane_oidc_session_activation_completion_recovery_actor as actors
from serverware import control_plane_oidc_session_activation_completion_recovery_consume_completion as completing
from serverware import control_plane_oidc_session_activation_completion_recovery_http as framing


execution, actor = actors.execution, actors.actor
POST_PATH = actors.CONSUME_PATH
RESPONSE_SCHEMA = "serverware.oidcSessionActivationCompletionRecoveryConsumeResponse/v1"
RESPONSE_RESERVATION_BYTES = 16 * 1024
HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff"}
_MAX_BODY_BYTES = 1024
_CONSTRUCTION = object()


def _fail():
    execution._fail("fresh consume completion response is unavailable")


def _data(status, dispatch_state=None):
    result = {"schema": RESPONSE_SCHEMA, "purpose": "consume", "status": status,
        "sessionState": "unknown", "tokenReleased": False, "automaticRetryAllowed": False}
    if dispatch_state is not None:
        result["dispatchState"] = dispatch_state
    return result


def _rejected_response(*, status_code=503):
    code = status_code if type(status_code) is int and status_code in framing._STATUSES else 503
    return JSONResponse(status_code=code, headers=HEADERS,
        content=_data("consume-rejected-before-dispatch", "not-started"))


def _unknown_response():
    return JSONResponse(status_code=503, headers=HEADERS,
        content=_data("consume-outcome-unknown", "unknown"))


class _StagedConsumeResponse:
    """Privately associated historical fact; never an incoming success DTO."""

    __slots__ = ("_construction", "_active", "_actor", "_completion", "_completion_seal",
        "_owner", "_parent", "_binding", "_custody", "_root", "_work", "_request", "_asgi",
        "_original", "_response", "_after", "_lifetime", "_acknowledged", "_seal",
        "_pid", "_thread", "_limits", "_ceilings", "_metrics", "_window", "_bound",
        "_epoch", "_monotonic", "_phase")

    def __init__(self):
        _fail()

    def _identity(self, *, closed):
        from serverware import control_plane_oidc_session_activation_completion_recovery_consume as source

        active, scope, completion = self._active, self._actor, self._completion
        refs = tuple(getattr(self, name) for name in _SEALED_FIELDS)
        if (type(self) is not _StagedConsumeResponse or self._construction is not _CONSTRUCTION
                or type(self._seal) is not tuple or len(self._seal) != len(refs)
                or any(actual is not held for actual, held in zip(refs, self._seal))
                or type(active) is not source._ConsumeAttempt or type(scope) is not actors._CompletionActorScope
                or type(completion) is not completing._ConsumeCompletion
                or completion._active is not active or completion._seal is not self._completion_seal
                or completion.response is not self._response or completion.after is not self._after
                or completion._lifetime is not self._lifetime
                or active.actor is not scope or active._owner is not self._owner
                or active._parent is not self._parent or active._binding is not self._binding
                or active._custody is not self._custody or active._root is not self._root
                or active._work is not self._work or active._phase != "completion-observed"
                or active._response_spent is not True or active._completion_spent is not True
                or active._public_response is not self or active._public_response_seal is not self
                or execution.startup._owner is not self._owner
                or self._owner._material is not self._parent or self._owner._binding is not self._binding
                or self._owner._custody is not self._custody or self._owner._activation_permission is not None
                or self._binding.runtime_root_public_key is not self._root
                or scope._owner is not self._owner or scope._work is not self._work
                or scope._purpose != "consume" or scope._purpose is not scope._purpose_pin
                or scope._profile != "activation" or scope._request is not self._request
                or scope._original is not self._original or self._request.scope is not self._asgi
                or getattr(self._request.state, framing.ORIGINAL_STATE_NAME, None) is not self._original
                or self._request.method != "POST" or self._asgi.get("path") != POST_PATH
                or self._asgi.get("query_string", b"") != b""
                or self._acknowledged is not (self._response[0] == b"acknowledged")
                or os.getpid() != self._pid or threading.get_ident() != self._thread):
            _fail()
        if closed:
            if (self._phase != "finishing" or active._closed is not True or active._normal_exit is not True
                    or scope._normal_exit is not True or scope._active is not False or scope._authorized is not False
                    or scope._old_token is not None or scope._completion_receiving_current is not None
                    or source._ACTIVE is not None or actors._ACTIVE is not None or actor._ACTIVE is not None
                    or active._originals is not None or active._originals_seal is not None
                    or active._input_grants is not None or active._input_grants_seal is not None
                    or active._input_material is not None or active._input_material_seal is not None
                    or active._plan is not None or active._authorization is not None
                    or active._authorization_seal is not None or active._dispatch is not None
                    or active._dispatch_seal is not None or active._completion is not None
                    or active._completion_seal is not None or active._lifetime.guards):
                _fail()
        elif (self._phase != "staged" or active._closed is not False or active._normal_exit is not False
                or source._ACTIVE is not active or actors._ACTIVE is not scope or actor._ACTIVE is not None
                or scope._active is not True or scope._authorized is not True or scope._normal_exit is not False
                or active._completion is not completion or active._completion_seal is not completion):
            _fail()

    def _ledger(self):
        execution.capture._SharedLedger(self._work)
        limits, metrics = self._work.limits, self._work.metrics
        if (limits is not self._limits
                or self._ceilings != (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
                or metrics.hash_work < self._metrics.hash_work
                or metrics.input_bytes < self._metrics.input_bytes
                or metrics.json_nodes < self._metrics.json_nodes):
            _fail()
        self._metrics = metrics

    def _floors(self, epoch, monotonic):
        if (type(epoch) is not int or type(monotonic) is not int
                or epoch < self._epoch or monotonic < self._monotonic
                or epoch >= self._window[3] or monotonic >= self._bound):
            _fail()
        self._epoch, self._monotonic = epoch, monotonic

    def _current_on_active(self, active):
        """Root's exact cleanup hook, never an ancestor of its own receiver."""
        from serverware import control_plane_oidc_session_activation_completion_recovery_consume as source

        self._identity(closed=False)
        self._ledger()
        if active is not self._active:
            _fail()
        # Do not call active._terminal_current: it selected this exact hook.
        source._ConsumeAttempt._current(active)
        completing._require_completion(self._completion)
        epoch = self._completion.current()
        selected = execution.clock._validate(self._lifetime.window)
        bound = self._lifetime.bound
        if (type(bound) is not int or not 0 < bound <= min(self._bound, selected[4])
                or selected[:3] != self._window[:3]
                or any(new > old for new, old in zip(selected[3:], self._window[3:]))):
            _fail()
        self._window, self._bound = selected, bound
        sampled = execution.production._callback(self._work, time.monotonic_ns)
        self._floors(epoch, sampled)
        self._ledger()
        self._identity(closed=False)
        return epoch

    def _finished_current(self):
        # This is a historical data receipt, not present session authority.
        # Both source-owned normal markers include the genuine final receiver
        # checks and cleanup. No invalidated actor or child guard is invoked.
        self._identity(closed=True)
        self._ledger()
        epoch = execution.clock._check_on_work(self._window, work=self._work)
        monotonic = execution.production._callback(self._work, time.monotonic_ns)
        self._floors(epoch, monotonic)
        self._ledger()
        self._identity(closed=True)

    def finish(self):
        if self._phase != "staged":
            _fail()
        self._phase = "finishing"
        try:
            self._finished_current()
            self._work.charge(input_bytes=RESPONSE_RESERVATION_BYTES, json_nodes=64)
            self._finished_current()
            if self._acknowledged:
                response = execution.production._callback(self._work, lambda: JSONResponse(
                    status_code=200, headers=HEADERS,
                    content=_data("consume-completion-acknowledged")))
            else:
                response = execution.production._callback(self._work, _unknown_response)
            self._finished_current()
            if (type(response) is not JSONResponse or type(response.body) is not bytes
                    or not 2 <= len(response.body) <= _MAX_BODY_BYTES
                    or response.status_code != (200 if self._acknowledged else 503)
                    or any(name.lower() == b"set-cookie" for name, _value in response.raw_headers)):
                _fail()
            self._phase = "finished"
            return response
        except BaseException:
            self._phase = "failed"
            raise


_SEALED_FIELDS = ("_active", "_actor", "_completion", "_completion_seal", "_owner", "_parent",
    "_binding", "_custody", "_root", "_work", "_request", "_asgi", "_original", "_response",
    "_after", "_lifetime", "_acknowledged")


def _response_on_active(active):
    from serverware import control_plane_oidc_session_activation_completion_recovery_consume as source

    source._require_response_call(active)
    selected = completing._require_completion(active._completion)
    scope = active.actor
    if (type(active) is not source._ConsumeAttempt or source._ACTIVE is not active
            or type(scope) is not actors._CompletionActorScope or selected._active is not active
            or active._completion_seal is not selected or active._public_response is not None
            or active._public_response_seal is not None or active._response_spent is not True
            or scope._purpose != "consume" or scope._profile != "activation"
            or type(selected.response) is not tuple or len(selected.response) != 4
            or any(type(raw) is not bytes for raw in selected.response)
            or type(selected.original_reservation_bytes) is not int
            or not RESPONSE_RESERVATION_BYTES <= selected.original_reservation_bytes <= source.MAX_ORIGINAL_BYTES
            or scope._future_original_bytes < RESPONSE_RESERVATION_BYTES):
        _fail()
    staged = object.__new__(_StagedConsumeResponse)
    staged._construction, staged._active, staged._actor = _CONSTRUCTION, active, scope
    staged._completion, staged._completion_seal = selected, selected._seal
    staged._owner, staged._parent, staged._binding = active._owner, active._parent, active._binding
    staged._custody, staged._root, staged._work = active._custody, active._root, active._work
    staged._request, staged._asgi, staged._original = scope._request, scope._request.scope, scope._original
    staged._response, staged._after, staged._lifetime = selected.response, selected.after, selected._lifetime
    staged._acknowledged = selected.response[0] == b"acknowledged"
    staged._pid, staged._thread = os.getpid(), threading.get_ident()
    work = staged._work
    staged._limits, staged._metrics = work.limits, work.metrics
    staged._ceilings = (work.limits.max_hashes, work.limits.max_input_bytes, work.limits.max_json_nodes)
    staged._window, staged._bound = selected.window, selected.deadline_ns
    staged._epoch, staged._monotonic = selected._lifetime.epoch, selected._lifetime.monotonic
    staged._phase = "staged"
    staged._seal = tuple(getattr(staged, name) for name in _SEALED_FIELDS)
    active._public_response = active._public_response_seal = staged
    staged._current_on_active(active)
    return staged
