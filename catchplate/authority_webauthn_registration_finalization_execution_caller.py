"""Distinct fixed raw11 -> raw8 finalization execution-planning exchange.

Signer request8/response2 and one canonical sibling-hint original are the only
request bodies. The real verifier returns custody raw7 plus the exact complete
before-vector used for that plan's root projections. Configuration and the
original deadline are independently supplied; no incoming roots, keys, actor,
historical expectations or success carrier are accepted by this protocol.

Only the source-fixed prefix selects this profile. The existing preparation
raw7 exchange remains separate. Actual relay/verifier scope, peer admission,
one work allowance, half-close/EOF and original deadline checks are shared,
not replaced. This framing does not authenticate the returned originals or
reserve, retain, execute, finalize, establish latest currentness or retry.
"""
from __future__ import annotations

from catchplate import authority_current_root_vector as vector
from catchplate import authority_webauthn_registration_finalization_caller as preparation


REQUEST_MAGIC = b"SWRFXQ01"
RESPONSE_MAGIC = b"SWRFXR01"
MAX_REQUEST_BYTES = preparation.MAX_REQUEST_BYTES
MAX_RESPONSE_BYTES = preparation.MAX_RESPONSE_BYTES
MAX_HINTS_BYTES = preparation.MAX_HINTS_BYTES
AuthorityTransportError = preparation.AuthorityTransportError
_request_lengths = preparation._request_lengths
_request_originals = preparation._request_originals
_hints_on_work = preparation._hints_on_work
_check_deadline = preparation._check_deadline
_recv_prefix = preparation._recv_prefix
_epoch_deadline = preparation._epoch_deadline
_receipt_interval = preparation._receipt_interval


def _response_lengths(lengths):
    if (type(lengths) is not tuple or len(lengths) != 8
            or type(lengths[7]) is not int or not 2 <= lengths[7] <= vector.MAX_BYTES):
        raise AuthorityTransportError("finalization execution plan requires eight bounded originals")
    preparation._response_lengths(lengths[:7])
    if sum(lengths) > MAX_RESPONSE_BYTES:
        raise AuthorityTransportError("finalization execution plan exceeds its original aggregate bound")


def _response_originals(originals):
    if (type(originals) is not tuple or len(originals) != 8
            or any(type(raw) is not bytes for raw in originals)):
        raise AuthorityTransportError("finalization execution plan requires exact original raw8")
    _response_lengths(tuple(len(raw) for raw in originals))
    preparation._response_originals(originals[:7])
    return originals


def _recv_request(connection, *, deadline_ns, prefix):
    return preparation._recv_request_profile(connection,
        deadline_ns=deadline_ns, prefix=prefix, execution=True)


def _send_response(connection, originals, *, deadline_ns):
    return preparation._send_response_profile(connection, originals,
        deadline_ns=deadline_ns, execution=True)


def _socket_request(path, *, configuration_digest, deadline_epoch_ns, originals,
        deadline_ns, expected_peer_uid, expected_peer_gid):
    return preparation._socket_request_profile(path, configuration_digest=configuration_digest,
        deadline_epoch_ns=deadline_epoch_ns, originals=originals, deadline_ns=deadline_ns,
        expected_peer_uid=expected_peer_uid, expected_peer_gid=expected_peer_gid, execution=True)


def _serve_relay(trust, connection, *, deadline_ns, prefix):
    return preparation._serve_relay_profile(trust, connection,
        deadline_ns=deadline_ns, prefix=prefix, execution=True)


def _serve_verifier(process, connection, *, deadline_ns, prefix):
    return preparation._serve_verifier_profile(process, connection,
        deadline_ns=deadline_ns, prefix=prefix, execution=True)
