"""Private original-bound finalization SQL request under cold pending pins.

Present execution permission and retained subject ownership must be separately
admitted before this method; provisioning, grant preparation and reservation
are not that permission. This method creates neither a public route nor a
local attempt/outcome record. Its future retained facade must own those gates.

The actual cold owner supplies root-admitted v3 endpoint/current-pending scope.
Genuine raw10/raw3 admission precedes a single transport. An observed marker
must match the exact eighteen fields derived from original verified replay.
Returned raw4 remains an unsigned local observation, not signed completion,
independent action-time currentness or permission to activate an OIDC session.
"""
from __future__ import annotations

from serverware import authority_registration_finalization_sql_admission as admission
from serverware import authority_registration_finalization_sql_transport as transport
from serverware import authority_successor_execution_owner as owners
from serverware import control_plane_registration_finalization_execution as caller


startup, evidence = caller.startup, caller.evidence


def _request_on_owner(owner, *, originals, live_window, transport_deadline_ns, work):
    """Return bounded joined raw4 after one dispatch; never retain or retry it."""
    held = transport._originals(originals, response=False)
    caller.shape._integer(transport_deadline_ns, minimum=1)
    common, _key, window, bound, owner_live = caller._scope(owner,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)
    material = owner._material.finalization
    endpoint, pending = material.sql_endpoint, material.current_pending
    if endpoint is None or pending is None:
        raise startup.EnrollmentStartupError("finalization SQL requires explicit nested v3 cold scope")
    endpoint = transport._endpoint(endpoint)
    sequence, head, fence = pending
    # Start the endpoint cap at the inherited invocation opening, not after
    # original verification. Actual admission can only narrow it again.
    bound = min(bound, window[1] + int(endpoint[1] * 1_000_000_000))
    owner_live()
    transport._check_deadline(bound)
    admitted = admission._admit_on_configuration(**common, originals=held[:10],
        reservation_originals=held[10:], expected_pending_sequence=sequence,
        expected_pending_head_digest=head, expected_fence=fence,
        live_window=window, transport_deadline_ns=bound, work=work)
    bound = min(bound, admitted.deadline_ns)

    def current():
        owner_live()
        admitted.live()
        evidence.production._callback(work, lambda: transport._check_deadline(bound))
        owner_live()

    current()
    returned = evidence.production._callback(work,
        lambda: transport._socket_request(endpoint, originals=held, deadline_ns=bound))
    returned = transport._originals(returned, response=True)
    current()
    enrollment_originals = tuple(common[name] for name in (
        "authorization_enrollment_bytes", "grant_enrollment_bytes", "current_root_enrollment_bytes"))
    if sum(len(raw) for raw in (*held, *returned, *enrollment_originals)) > evidence.authority.MAX_RESULT_BYTES:
        raise startup.EnrollmentStartupError("finalization SQL complete exchange exceeds its source bound")
    # These are reported custody locators, not independently verified packet
    # provenance. Both absent is allowed only for the closed uncertain shape.
    if returned[1]:
        evidence.plan._same(returned[1].decode("ascii"), head, work,
            "finalization SQL observation differs from independent pending scope")
    if returned[0] == b"observed-commit":
        marker_raw = owners._marker_on_work(returned[3].decode("ascii"), head, work)
        marker = admission.current_root.wire._decode_object(marker_raw, work=work,
            maximum_bytes=4096, maximum_nodes=64, maximum_depth=2)
        evidence.plan._same(marker, admitted.marker_expectation, work,
            "finalization SQL marker differs from complete original replay")
    current()
    return returned
