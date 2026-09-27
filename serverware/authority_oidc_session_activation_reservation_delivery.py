"""Separate activation-only durable reserve delivery, not execution authority.

Cold original enrollment and record recovery share the caller's existing
work/window and required inherited deadline. The actual journal belongs to
this owner; its directory and independently current local checkpoint are
admitted separately from the state predecessor/head/fence. No AES custody,
grant/result carrier, arbitrary codec or operation is accepted.

Enqueue authenticates and retains the exact signed request/snapshot before
network; explicit delivery authenticates and retains the exact state receipt
before return. No automatic retry, regenerated reserve, expiry renewal, SQL,
completion or token release occurs. Explicit unchanged state recovery does not
establish historical execution authority or independently current pending head.
"""
from __future__ import annotations

from serverware import authority_registration_reservation_delivery as shared
from serverware import authority_oidc_session_activation_reservation_records as records


OidcSessionActivationReservationDeliveryError = shared.RegistrationReservationDeliveryError
OidcSessionActivationReservationObservation = shared.RegistrationReservationObservation
OidcSessionActivationReservationOriginals = shared.RegistrationReservationOriginals


class OidcSessionActivationReservationDelivery(shared._RegistrationReservationDeliveryBase):
    """Fixed oidc.session.activate owner with mandatory supplied allowance."""

    __slots__ = ()

    def __init__(self, *, journal, enrollment_bytes, root_public_key,
            expected_local_sequence, expected_local_head_digest,
            live_window, work, transport_deadline_ns):
        self._initialize(journal=journal, enrollment_bytes=enrollment_bytes,
            root_public_key=root_public_key, expected_local_sequence=expected_local_sequence,
            expected_local_head_digest=expected_local_head_digest, live_window=live_window,
            work=work, transport_deadline_ns=transport_deadline_ns)
