"""New finalization custody plan and its SAME complete before-vector.

The actual measured verifier reconstructs the request from genuine signer
request8/response2 and bounded sibling hints. Its fixed complete-read branch
uses the configured verifier PostgreSQL owner ONCE, projects every operation
primary/count root from those exact canonical vector bytes, and signs that
planning request. Genuine planner response/replay, custody intent and relay
then produce raw7 alongside the original vector. No input supplies roots.

The existing raw7-only preparation remains unchanged. This fixed private path
retains the caller's work and original receipt/epoch/monotonic bounds, but does
not grant currentness, reserve, retain, execute SQL, finalize a credential or
activate a session. Protected driver/hard timeout exclusions remain unchanged.
"""
from __future__ import annotations

from catchplate import authority_webauthn_registration_finalization_preparation as preparation


def _prepare_on_work(process, *, request_originals, response_originals,
        sibling_challenge_ids, deadline_epoch_ns, work, transport_deadline_ns=None):
    """Return original custody raw7 plus the exact actual complete before-vector."""
    from catchplate import authority_webauthn_registration_finalization_execution_caller as caller

    result = preparation._prepare_core(process, request_originals=request_originals,
        response_originals=response_originals, sibling_challenge_ids=sibling_challenge_ids,
        deadline_epoch_ns=deadline_epoch_ns, work=work,
        transport_deadline_ns=transport_deadline_ns, execution=True)
    return caller._response_originals(result)
