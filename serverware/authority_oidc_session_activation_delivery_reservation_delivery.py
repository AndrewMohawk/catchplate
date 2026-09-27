"""Consume-only first-exact reserve/snapshot/ACK retention and delivery.

The fourth source-fixed owner uses the actual state journal and dedicated
consume record codec. Original root enrollment and local checkpoint admission
share the caller's supplied work/window/deadline. A caller-selected codec,
subclass, success object or fresh allowance cannot select this profile.

An exact signed request and snapshot are durable before explicit state I/O;
the authentic exact ACK is durable before return. Uncertainty leaves the
request pending or poisons local publication. There is no automatic resend,
replacement signature, SQL execution, current-pending claim or token output.
"""
from __future__ import annotations

from serverware import authority_registration_reservation_delivery as shared
from serverware import authority_oidc_session_activation_delivery_reservation_records as records


OidcSessionActivationDeliveryReservationDeliveryError = shared.RegistrationReservationDeliveryError
OidcSessionActivationDeliveryReservationObservation = shared.RegistrationReservationObservation
OidcSessionActivationDeliveryReservationOriginals = shared.RegistrationReservationOriginals


class OidcSessionActivationDeliveryReservationDelivery(shared._RegistrationReservationDeliveryBase):
    """Fixed consume owner; local recovery never supplies action authority."""

    __slots__ = ()

    def __init__(self, *, journal, enrollment_bytes, root_public_key,
            expected_local_sequence, expected_local_head_digest,
            live_window, work, transport_deadline_ns):
        self._initialize(journal=journal, enrollment_bytes=enrollment_bytes,
            root_public_key=root_public_key, expected_local_sequence=expected_local_sequence,
            expected_local_head_digest=expected_local_head_digest, live_window=live_window,
            work=work, transport_deadline_ns=transport_deadline_ns)
