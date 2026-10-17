"""Closed public reservation projections, never result authentication.

The caller must select these functions only after the actual reservation
facade succeeds or returns its typed unavailable outcome. Canonical local-ID
and bounded raw3 carrier checks do not authenticate originals, establish a
current head, authorize execution or permit retry. No original response bytes
or acknowledgment-derived authority are included in these public dictionaries.
"""
from __future__ import annotations

from catchplate import authority_registration_reservation_transport as transport


_HEX = frozenset("0123456789abcdef")


def _local_digest(value):
    if (type(value) is not str or len(value) != 71 or not value.startswith("sha256:")
            or any(character not in _HEX for character in value[7:])):
        raise ValueError("registration reservation local ID is not canonical SHA-256")
    return value


def accepted(local_digest, response_originals):
    """Project the actual successful facade result without exposing originals.

    These are carrier checks only; arbitrary bounded bytes cannot substitute
    for the caller's genuine original verification and successful facade call.
    """
    digest = _local_digest(local_digest)
    try:
        transport._originals(response_originals, response=True)
    except transport.AuthorityTransportError:
        raise ValueError("registration reservation response is not the bounded original raw3") from None
    return {
        "schema": "catchplate.webAuthnRegistrationReservation/v1",
        "status": "reservation-acknowledged",
        "purpose": "reserve-registration-evidence-execution",
        "localDigest": digest,
        "registrationCompleted": False,
        "executionStarted": False,
        "currentnessEstablished": False,
        "automaticRetryAllowed": False,
    }


def unavailable(local_digest=None):
    """Keep an uncertain remote outcome unknown, never failure or retry proof."""
    digest = None if local_digest is None else _local_digest(local_digest)
    detail = {
        "error": "registration_reservation_unavailable",
        "registrationCompleted": False,
        "executionStarted": False,
        "currentnessEstablished": False,
        "automaticRetryAllowed": False,
        "remoteState": "unknown",
    }
    if digest is not None:
        detail["localDigest"] = digest
    return detail
