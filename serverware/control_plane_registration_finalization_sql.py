"""Private original-bound finalization SQL request under cold pending pins.

Present execution permission and retained subject ownership must be separately
admitted before this method; provisioning, grant preparation and reservation
are not that permission. The retained facade repeats genuine subject ownership
before entering this method. A supplied local locator must match actual retained
raw13; it is not an authority token. The method owns the irreversible local
dispatch claim and opaque outcome append through the actual custody client.

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
custody_client, journal = caller.custody_client, caller.custody_client.journal


def _retained_originals(owner, local_digest, *, work):
    """Read the actual complete local chain and raw13, not successful authority."""
    from serverware import control_plane_registration_finalization_records as records
    from serverware import control_plane_registration_finalization_reservation_records as reservations

    digest = journal._digest(local_digest)
    callback = evidence.production._callback
    custody = owner._custody
    association = callback(work,
        lambda: custody_client.ControlPlaneCustodyClient.load_registration_finalization_preparation(
            custody, digest))
    reserved = callback(work,
        lambda: custody_client.ControlPlaneCustodyClient.load_registration_finalization_reservation(
            custody, digest))
    record = association[0]
    if (record.digest != digest or (record.family, record.selector) != (records.FAMILY, records.OPERATION)
            or record.source_revision != evidence.authority.SOURCE_REVISION
            or type(reserved) is not reservations.FinalizationReservationRecord
            or reserved.finalization_digest != digest or reserved.source_revision != record.source_revision):
        raise startup.EnrollmentStartupError("finalization SQL requires its actual retained grant and reservation")
    return transport._originals(record.originals + reserved.originals, response=False)


def _request_on_owner(owner, *, local_digest, originals, live_window, transport_deadline_ns, work):
    """Claim once, retain returned raw4, then admit its observation; never retry."""
    digest = journal._digest(local_digest)
    held = transport._originals(originals, response=False)
    caller.shape._integer(transport_deadline_ns, minimum=1)
    common, _key, window, bound, owner_live = caller._scope(owner,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)
    material = owner._material.finalization
    endpoint, pending = material.sql_endpoint, material.current_pending
    if endpoint is None or pending is None and material.context_directory is None:
        raise startup.EnrollmentStartupError("finalization SQL requires explicit nested v3 cold scope")
    endpoint = transport._endpoint(endpoint)
    # Start the endpoint cap at the inherited invocation opening, not after
    # original verification. Actual admission can only narrow it again.
    bound = min(bound, window[1] + int(endpoint[1] * 1_000_000_000))
    owner_live()
    transport._check_deadline(bound)
    retained = _retained_originals(owner, digest, work=work)
    work.charge(input_bytes=sum(len(raw) for raw in (*held, *retained)))
    if held != retained:
        raise startup.EnrollmentStartupError("finalization SQL originals differ from the claimed local association")
    if material.context_directory is not None:
        from serverware import authority_local_registration_context as contexts
        from serverware import control_plane_registration_finalization_reservation as subjects
        subject, grant, window, bound, subject_live, _ = subjects._inspect_on_owner(owner, digest,
            live_window=window, transport_deadline_ns=bound, work=work)
        if grant != held[:10]:
            raise startup.EnrollmentStartupError("local finalization context differs from retained grant")
        selected = contexts._admit_on_owner(owner, purpose="finalization", local_digest=digest, stage="execute",
            common=common, originals=grant, reserved=held[10:], subject=subject,
            deadline_epoch_ns=window[3], deadline_ns=bound, work=work)
        pending = contexts._selected_scope(owner, "finalization", digest).current_pending
        window, bound = contexts._narrow(selected, window, bound)
        subject_live()
    sequence, head, fence = pending
    custody = owner._custody
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
    # The journal rechecks the complete original/reservation association and
    # atomically publishes its fsynced no-replacement claim. Any later failure
    # leaves it spent, even before the transport sends its first byte.
    evidence.production._callback(work,
        lambda: custody_client.ControlPlaneCustodyClient.claim_registration_finalization_sql_attempt(
            custody, digest))
    current()
    returned = evidence.production._callback(work,
        lambda: transport._socket_request(endpoint, originals=held, deadline_ns=bound))
    returned = transport._originals(returned, response=True)
    # Preserve a bounded opaque response BEFORE semantic and invocation-time
    # acceptance, including uncertainty or a later mismatching marker. Storage
    # verifies its own live owner/journal, not a refreshed execution window.
    evidence.production._callback(work,
        lambda: custody_client.ControlPlaneCustodyClient.append_registration_finalization_sql_outcome(
            custody, digest, returned))
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
