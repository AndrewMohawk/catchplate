"""One guarded private release exchange, never a retry or response proof.

The actual startup owns the accepted socket and all private resources. This
service supplies only fixed transport dispatch and a real startup guard; callers
cannot supply policy, a callback, a replacement allowance or a successful DTO.
"""
from __future__ import annotations

from serverware import oidc_session_activation_release_startup as startup
from serverware import oidc_session_activation_release_transport as transport


class ReleaseServiceError(RuntimeError):
    pass


def _fail(message):
    raise ReleaseServiceError(message)


def serve_once(started):
    """Return True only after one success response and established socket close."""
    if type(started) is not startup._StartedRelease:
        _fail("release service requires the actual cold startup owner")
    try:
        profile = startup._StartedRelease.request_profile(started)
        if profile not in (startup.bootstrap.LIVE_PROFILE, startup.bootstrap.RECOVERY_PROFILE):
            _fail("release service has no root-selected request profile")
        work, window, bound = startup._StartedRelease.processing_context(started)

        def current():
            nonlocal window, bound
            held = startup._StartedRelease.processing_context(started)
            actual = startup.clock._validate(held[1])
            startup.shape._integer(held[2], minimum=1)
            if (held[0] is not work or actual[:3] != window[:3]
                    or any(right > left for left, right in zip(window[3:], actual[3:]))
                    or held[2] > bound or held[2] > actual[4]):
                _fail("release service cannot renew its original processing allowance")
            window, bound = actual, held[2]

        current()
        connection = startup._StartedRelease.accept_on_work(started)
        current()
        originals = transport._recv_request(connection, expected_profile=profile,
            deadline_ns=bound, work=work, current=current)
        current()
        identity = transport._request_identity_on_work(originals, profile=profile,
            deadline_ns=bound, work=work, current=current)
        current()
        if profile == startup.bootstrap.LIVE_PROFILE:
            if len(originals) != 7 or originals[0] != transport.LIVE_PURPOSE:
                _fail("release service request differs from its fixed live profile")
            token = startup._StartedRelease.open_committed_on_work(started,
                proof_bytes=originals[1], proof_enrollment_bytes=originals[2],
                intent_bytes=originals[3], intent_enrollment_bytes=originals[4],
                old_token_bytes=originals[5], envelope_bytes=originals[6])
        else:
            if len(originals) != 8 or originals[0] != transport.RECOVERY_PURPOSE:
                _fail("release service request differs from its fixed recovery profile")
            token = startup._StartedRelease.recover_on_work(started,
                proof_bytes=originals[1], proof_enrollment_bytes=originals[2],
                intent_bytes=originals[3], intent_enrollment_bytes=originals[4],
                old_token_bytes=originals[5], envelope_bytes=originals[6],
                record_bytes=originals[7])
        # The actual operation may narrow the lifetime to admitted intent/proof
        # expiry. Carry that pair through every send chunk and terminal guard.
        current()
        response = transport._originals((identity, token), response=True)
        transport._send_response(connection, response, deadline_ns=bound,
            work=work, current=current)
        current()
        startup._StartedRelease.close_connection(started)
        current()
        return True
    except BaseException:
        # No error frame can be sent after failed admission or a poisoned owner.
        # Cleanup preserves retained outcomes; its sticky failure reaches runner.
        try:
            startup._StartedRelease.close(started)
        except BaseException:
            pass
        raise
