"""One fixed internal verifier-to-planner JIT planning ingress.

The actual listener admits its configured Unix peer before the fixed prefix.
This owner samples one real receiving window, distinct from the authenticated
sender bracket. The signed-request owner retains both live bounds and actual
peer/boot/generation ownership through native production and final raw reply.
No incoming field selects a role, signer, route, producer or work allowance.
Planning is not current-root, capability, reservation or execution admission.
"""
from __future__ import annotations

from catchplate import authority_jit_compound_wire as wire
from catchplate import authority_jit_original_service as pages
from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork


class JitCompoundIngressError(ValueError):
    pass


def _require(value):
    if not value:
        raise JitCompoundIngressError("JIT planning ingress lost its measured planner owner")


def serve_process(process, connection, *, prefix, deadline_ns):
    """Borrow the admitted listener socket; return no execution authority."""
    from catchplate import authority_service as service
    from catchplate import authority_jit_compound_request_service as requests

    _require(type(process) is service.AuthorityProcess
        and process.role_name == "planner"
        and process.process_mode == "policy-authority-planner"
        and type(prefix) is bytes and prefix == wire.transport.REQUEST_MAGIC)
    # One source-fixed original ingress allowance. The real producer owns its
    # separate finite child schedule, never a caller-provided replenishment.
    work = _ValidationWork(QueryReadValidationLimits())
    work.charge(input_bytes=65536, json_nodes=2048)
    configured, check_owner = pages._configured_on_work(process, local_role="planner", work=work)
    receiver = pages._receiving_window(deadline_ns=deadline_ns, configured=configured, work=work)
    receiving_deadline = min(deadline_ns, receiver[4])

    def current(active_work):
        _require(wire.evidence.production._callback(active_work,
            lambda: check_owner(active_work)) is None)
        pages.clock._check_on_work(receiver, work=active_work)

    current(work)
    request = wire.receive_request(connection, prefix=prefix,
        deadline_ns=receiving_deadline, work=work)
    current(work)
    # Actual signature verification, original bracket admission and the
    # socket's real peer/PID/boot/generation joins occur in this sole owner.
    with requests.receive_request_on_work(process, connection,
            control_bytes=request.control_bytes, request_bytes=request.request_bytes,
            receiver_window=receiver, transport_deadline_ns=receiving_deadline,
            check=current, work=work) as owner:
        originals = owner.produce(work=work)
        owner.check(work)
        wire.send_reply(connection, originals=originals,
            request_bytes=request.request_bytes, deadline_ns=owner.deadline_ns,
            check=lambda: owner.check(work), work=work, processing_owner=owner)
        owner.check(work)
    current(work)
