"""One bounded HTTP request through the actual live activation continuation.

The original Request and body enter once. Permission, private effects and
cookie staging remain in one scope; neither a returned permission carrier nor
an independently supplied token can enter this orchestration. The async route
calls this bounded synchronous core on its own thread, without transferring
the live permission to a worker or renewing its allowance.
"""
from __future__ import annotations

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from serverware import oidc_session_activation_http_contract as contract
from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork


ORIGINAL_STATE_NAME = "oidc_session_activation_bytes"
HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff"}
_REJECTED_STATUSES = frozenset({400, 401, 403, 404, 405, 409, 413, 415, 422, 429, 503})
_REQUIRED_CONFIGURATION = ("activation_planning", "activation_execution",
    "consume_execution", "consume_input_acquisition", "release_intent",
    "release_proof", "release_proof_acquisition", "release_handoff", "release_grant_acquisition")


def _rejected_response(*, status_code=503, local_digest=None):
    """Fixed pre-core/pre-dispatch refusal, never exception text or headers."""
    status = status_code if type(status_code) is int and status_code in _REJECTED_STATUSES else 503
    try:
        content = contract.rejected_before_dispatch(local_digest)
    except ValueError:
        content = contract.rejected_before_dispatch()
    return JSONResponse(status_code=status, headers=HEADERS, content=content)


def _unknown_response(local_digest=None):
    """No cookie mutation and no inference that uncertain effects were absent."""
    try:
        content = contract.outcome_unknown(local_digest)
    except ValueError:
        content = contract.outcome_unknown()
    return JSONResponse(status_code=503, headers=HEADERS, content=content)


def _require_complete_configuration(permission):
    """Refusal-only preflight, not readiness or replacement original admission."""
    from serverware import control_plane_oidc_session_activation_execution as execution

    if type(permission) is not execution._ActivationPermission:
        execution._fail("activation HTTP requires the actual live permission")
    permission._current()
    owner, parent = permission._owner, permission._owner._material
    if any(getattr(parent, name, None) is None for name in _REQUIRED_CONFIGURATION):
        execution._fail("activation HTTP requires its complete independently configured continuation")
    for policy in (parent.activation_execution, parent.consume_execution):
        if any(getattr(policy, name, None) is None for name in (
                "authorizer_endpoint", "reservation_endpoint", "reservation_predecessor",
                "sql_endpoint", "completion_endpoint")):
            execution._fail("activation HTTP requires all fixed execution and completion endpoints")
    if (parent.consume_execution.release_hints is not True
            or any(getattr(parent.activation_execution, name, None) is None for name in (
                "consume_planner_endpoint", "consume_planner_public_key", "consume_planner_measurement_digest"))
            or owner._consume_key is None or owner._intent_key is None):
        execution._fail("activation HTTP requires its original consume and release-intent custody")
    permission._current()


def _activate(request, *, activation_bytes):
    """Run one complete same-permission sequence; return only its HTTP result."""
    from serverware import control_plane_enrollment_startup as startup
    from serverware import control_plane_oidc_session_activation_execution as execution
    from serverware import control_plane_oidc_session_activation_delivery as delivery

    if (type(request) is not Request or type(activation_bytes) is not bytes
            or not 2 <= len(activation_bytes) <= contract.MAX_REQUEST_BYTES
            or getattr(request.state, ORIGINAL_STATE_NAME, None) is not activation_bytes):
        return _rejected_response(status_code=400)
    dispatched, local_digest = False, None
    try:
        work = _ValidationWork(QueryReadValidationLimits())
        # Open once before parsing or native owner/key work. These source-bound
        # reservations cover the strict decoder, owned graph and two separate
        # projections; no charging callback contains the private pipeline.
        owner, window = execution._open_on_work(work)
        work.charge(input_bytes=4 * len(activation_bytes) + 2 * contract.MAX_PERMISSION_BYTES
            + 2 * contract.MAX_PLANNING_ASSERTION_BYTES,
            json_nodes=8 * contract._JSON_LIMITS.max_total_nodes)
        execution.clock._check_on_work(window, work=work)
        try:
            permission_bytes, assertion_bytes, challenge_id = contract.request_originals(activation_bytes)
        except (ValueError, RecursionError):
            return _rejected_response(status_code=400)
        execution.clock._check_on_work(window, work=work)
        with startup._EnrollmentOwner._oidc_session_activation_permission(owner,
                request=request, permission_bytes=permission_bytes, live_window=window,
                transport_deadline_ns=window[4], work=work) as permission:
            local_digest = permission._target[2]["localDigest"]
            _require_complete_configuration(permission)
            # Deliberately precedes the durable pre-planner claim: after this
            # source-controlled boundary every failure is conservatively
            # unknown, even if the first socket was never reached. Permission
            # assertion/CAS effects before it are not activation dispatch.
            dispatched = True
            permission.dispatch_completion(assertion_bytes=assertion_bytes,
                expected_challenge_id=challenge_id)
            permission.acquire_and_prepare_consume()
            permission.authorize_consume()
            permission.dispatch_consume()
            permission.complete_consume()
            permission.authorize_release_intent()
            permission.prove_release()
            # The genuine delivery helper owns the final grant acquisition and
            # verified token locally; no token DTO crosses this orchestrator.
            staged = delivery._response_on_permission(permission)
            if type(staged) is not delivery._StagedResponse:
                execution._fail("activation HTTP lost its actual staged response owner")
        # Normal context cleanup must succeed before this can return a cookie.
        # Its source-owned guard retains the exact narrowed receiver lifetime
        # after permission revocation and onward to the real send boundary.
        return staged.finish()
    except HTTPException as exc:
        if not dispatched:
            from serverware import control_plane_oidc_session_activation_approval as approval

            negotiation = approval._response_for(exc, action=approval.ACTIVATION_ACTION)
            if negotiation is not None:
                return negotiation
            return _rejected_response(status_code=exc.status_code, local_digest=local_digest)
        return _unknown_response(local_digest)
    except Exception:
        if not dispatched:
            return _rejected_response(local_digest=local_digest)
        return _unknown_response(local_digest)
