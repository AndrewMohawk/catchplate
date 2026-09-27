"""Private caller continuation for the separately enrolled execution purpose.

Only the existing cold enrollment owner supplies configuration, original
enrollments, endpoint and the NEW caller key. Real application authentication,
current role/session/CSRF admission and consent to this purpose must precede
issuance; old evidence-signing permission and original byte containers are not
substitutes. Public custody-only routes do not invoke this continuation.

One inherited work allowance and absolute deadline cover each call. Received
grant originals undergo genuine local replay/signature/scope verification.
The explicit nested-v2 reservation method can request a durable state reserve;
v1 grant methods and existing public preparation routes cannot. No method here
writes SQL, stores an execution-attempt marker or finalizes a credential.
Nested-v3 scope also supplies fixed endpoints to the separate retained-original
handoff module; it does not silently promote an older caller profile.
No environment discovery, key fallback, automatic retry or renewal exists.
"""
from __future__ import annotations

import time

from serverware import control_plane_enrollment_startup as startup
from serverware import authority_registration_execution_authorization as authorization
from serverware import authority_registration_execution_issuance as issuance
from serverware import authority_registration_execution_response as receiving
from serverware import authority_registration_execution_transport as transport
from serverware import authority_webauthn_evidence_custody_configuration as configuration


evidence, clock = issuance.evidence, issuance.clock


def _scope(owner, *, deadline_epoch_ns, deadline_ns, work, _endpoint_kind="authorizer"):
    """Hold actual cold inputs; returned local settings are not a proof token."""
    startup._require_pid()
    if type(owner) is not startup._EnrollmentOwner:
        raise startup.EnrollmentStartupError("execution caller requires the actual cold enrollment owner")
    material, binding, private = owner._material, owner._binding, owner._execution_key
    if material is None or material.execution is None or private is None:
        raise startup.EnrollmentStartupError("separate registration execution permission is disabled")
    execution = material.execution
    if (material.issuer_policy is None or owner._private_key is None
            or binding.caller_uid != 65532 or owner._execution_key_fd != execution.caller_private_key_fd
            or material.configuration_digest != binding.configuration_digest):
        raise startup.EnrollmentStartupError("registration execution cold scope differs")
    shape = evidence.plan.contract
    shape._integer(deadline_epoch_ns, minimum=1)
    shape._integer(deadline_ns, minimum=1)
    deadline, inherited = deadline_epoch_ns, deadline_ns
    if type(_endpoint_kind) is not str or _endpoint_kind not in (
            "authorizer", "reserver", "sql", "completion"):
        raise startup.EnrollmentStartupError("registration execution purpose is not source-selected")
    endpoint = execution.authorizer_endpoint
    if _endpoint_kind == "reserver":
        if execution.reservation_endpoint is None or execution.reservation_predecessor is None:
            raise startup.EnrollmentStartupError("registration reservation is not independently cold-enabled")
        endpoint = execution.reservation_endpoint
    elif _endpoint_kind in ("sql", "completion"):
        if (execution.sql_endpoint is None or execution.completion_endpoint is None
                or execution.current_pending is None or execution.completion_packet_digest is None):
            raise startup.EnrollmentStartupError("registration handoff is not independently cold-enabled")
        endpoint = execution.sql_endpoint if _endpoint_kind == "sql" else execution.completion_endpoint
    ledger = evidence.capture._SharedLedger(work)
    common = {
        "payload": issuance.configuration._ConfigurationCapture(ledger,
            maximum_bytes=issuance.response.authority.MAX_REQUEST_BYTES).visit(material.configuration_payload),
        "configuration_digest": material.configuration_digest,
        "generation": evidence.capture._JSONCapture(ledger).visit(material.generation),
        "runtime_role_identities": evidence.capture._JSONCapture(ledger,
            maximum_bytes=8192).visit(material.runtime_role_identities),
        "authorization_enrollment_bytes": execution.authorization_enrollment_bytes,
        "current_root_enrollment_bytes": execution.current_root_enrollment_bytes,
        "grant_enrollment_bytes": execution.grant_enrollment_bytes,
        "root_public_key": binding.runtime_root_public_key,
    }
    startup._live(owner, work=work)
    window = clock._open_on_work(deadline_epoch_ns=min(deadline, binding.attestation_interval[1]),
        maximum_lifetime_ns=min(binding.maximum_deadline_ns,
            int(endpoint[1] * 1_000_000_000), evidence.authority.VERIFIER_RESPONSE_MAX_AGE_NS),
        maximum_clock_skew_ns=material.issuer_policy["maximumClockSkewNs"], work=work)
    bound = min(window[4], inherited)
    last_epoch, last_monotonic = window[0], window[2]

    def live():
        nonlocal last_epoch, last_monotonic
        startup._live(owner, work=work)
        if (owner._material is not material or owner._binding is not binding
                or material.execution is not execution or owner._execution_key is not private):
            raise startup.EnrollmentStartupError("registration execution caller changed during its operation")
        now = clock._check_on_work(window, work=work)
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if now < last_epoch or monotonic < last_monotonic or monotonic >= bound:
            raise startup.EnrollmentStartupError("registration execution caller expired or its clocks reversed")
        last_epoch, last_monotonic = now, monotonic

    live()
    return common, endpoint, private, window[3], bound, live


def _authorize_on_owner(owner, *, request_originals, response_originals,
        deadline_epoch_ns, deadline_ns, work):
    """Sign the exact reconstructed request after real application admission."""
    request_raw = issuance.response.wire._request_originals(request_originals)
    response_raw = issuance.response.wire._response_originals(response_originals)
    common, _endpoint, private, deadline, bound, live = _scope(owner,
        deadline_epoch_ns=deadline_epoch_ns, deadline_ns=deadline_ns, work=work)
    original = issuance._produce_on_configuration(**common,
        request_originals=request_raw, response_originals=response_raw,
        caller_private_key=private, deadline_epoch_ns=deadline, transport_deadline_ns=bound, work=work)
    live()
    return original


def _request_on_owner(owner, *, authorization_bytes, request_originals,
        response_originals, before_vector_bytes, deadline_epoch_ns, deadline_ns, work):
    """Authenticate caller permission, exchange once, then admit original grant."""
    if (type(request_originals) is not tuple or len(request_originals) != 3
            or type(response_originals) is not tuple or len(response_originals) != 4):
        raise startup.EnrollmentStartupError("execution caller requires original planning request3/response4")
    originals = transport._originals((authorization_bytes, *request_originals,
        *response_originals, before_vector_bytes), transport.REQUEST_LIMITS)
    common, endpoint, _private, deadline, bound, live = _scope(owner,
        deadline_epoch_ns=deadline_epoch_ns, deadline_ns=deadline_ns, work=work)
    configured = configuration._capture_on_work(purpose="registration", payload=common["payload"],
        configuration_digest=common["configuration_digest"], generation=common["generation"],
        runtime_role_identities=common["runtime_role_identities"], work=work)
    checked = authorization._verify_on_work(authorization_bytes=originals[0],
        authorization_enrollment_bytes=common["authorization_enrollment_bytes"],
        current_root_enrollment_bytes=common["current_root_enrollment_bytes"],
        grant_enrollment_bytes=common["grant_enrollment_bytes"], root_public_key=common["root_public_key"],
        configuration_digest=common["configuration_digest"], planner_public_key=configured.pins[1],
        evidence_public_key=configured.pins[4], deadline_epoch_ns=deadline,
        transport_deadline_ns=bound, work=work)
    deadline, bound = min(deadline, checked.expires_at_epoch_ns), min(bound, checked.deadline_ns)
    live()
    # Actual socket calls and errors preserve the same allowance. Endpoint
    # authority is from v3 root admission, never from a browser or returned plan.
    returned = evidence.production._callback(work,
        lambda: transport._socket_request(endpoint, originals=originals, deadline_ns=bound))
    live()
    grant = receiving._verify_on_configuration(**common, request_originals=originals[1:4],
        response_originals=originals[4:8], before_vector_bytes=originals[8],
        authorization_bytes=originals[0], grant_bytes=returned, deadline_epoch_ns=deadline,
        transport_deadline_ns=bound, work=work)
    live()
    transport._check_deadline(bound)
    return grant


def _reserve_on_owner(owner, *, originals, deadline_epoch_ns, deadline_ns, work):
    """Exchange exact raw10 once; independently authenticate returned raw3.

    The actual application must first admit its present caller and permission
    to reserve. Only nested-v2 cold material supplies endpoint/predecessor pins.
    Even authentic returned originals are not independently current pending
    authority, permission to execute SQL or a credential-finalization result.
    """
    from serverware import authority_registration_reservation_transport as reserve_wire
    from serverware import authority_registration_reservation_response as reserve_response

    held = reserve_wire._originals(originals, response=False)
    common, endpoint, _private, deadline, bound, live = _scope(owner,
        deadline_epoch_ns=deadline_epoch_ns, deadline_ns=deadline_ns, work=work, _endpoint_kind="reserver")
    predecessor = owner._material.execution.reservation_predecessor
    # Authenticate the original permission/grant before any side-effecting
    # reserve request. Received signatures will be independently checked again
    # with the actual returned computation and state acknowledgment afterward.
    receiving._verify_on_configuration(**common, authorization_bytes=held[0],
        request_originals=held[1:4], response_originals=held[4:8],
        before_vector_bytes=held[8], grant_bytes=held[9], deadline_epoch_ns=deadline,
        transport_deadline_ns=bound, work=work)
    live()
    returned = evidence.production._callback(work,
        lambda: reserve_wire._socket_request(endpoint, originals=held, deadline_ns=bound))
    live()
    response = reserve_response._verify_on_configuration(**common, originals=held,
        response_originals=returned, expected_predecessor_sequence=predecessor[0],
        expected_predecessor_head_digest=predecessor[1], expected_fence=predecessor[2],
        deadline_epoch_ns=deadline, transport_deadline_ns=bound, work=work)
    live()
    reserve_wire._check_deadline(bound)
    return response
