"""Separate finalization-only durable reservation owner, never SQL authority.

An actual CurrentRootJournal and independently current local checkpoint are
mandatory. The private shared state machine selects this exact class's fixed
finalization record profile; there is no supplied operation, codec or factory.
Its directory must be independent of evidence reservation/state/completion/SQL
journals. Signed request/snapshot precede network delivery; authenticated state
acknowledgment is durable before return. Same-original recovery neither renews
expiry nor turns a receipt into an independently current state checkpoint.
"""
from __future__ import annotations

from catchplate import authority_registration_reservation_delivery as shared
from catchplate import authority_registration_finalization_reservation_records as records


FinalizationReservationDeliveryError = shared.RegistrationReservationDeliveryError
FinalizationReservationObservation = shared.RegistrationReservationObservation
FinalizationReservationOriginals = shared.RegistrationReservationOriginals


class FinalizationReservationDelivery(shared._RegistrationReservationDeliveryBase):
    """Fixed registration.finalize request/ack delivery with no retry or SQL."""

    __slots__ = ()
