"""Opaque finalization reservation originals bound to a retained grant locator.

The source token is the actual complete finalization/evidence/signer chain's
retained source, not the current implementation revision. Canonical framing
and content identity authenticate no signatures, remote currentness, caller
permission or successful finalization. No attempt or dispatch marker exists.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

from serverware import authority_registration_finalization_reservation_transport as transport
from serverware import control_plane_custody_records as records


MAGIC = b"SWCPV001"
IDENTITY_DOMAIN = "serverware.controlPlaneRegistrationFinalizationReservationRecord/v1"
_PREFIX_BYTES = 10
_COUNT = 3
_MAX_HEADER_BYTES = _PREFIX_BYTES + records.MAX_SOURCE_REVISION_BYTES + 32 + _COUNT * 8
MAX_RECORD_BYTES = transport.MAX_RESPONSE_BYTES + _MAX_HEADER_BYTES
_HEX = frozenset("0123456789abcdef")
CustodyRecordError = records.CustodyRecordError


@dataclass(frozen=True, slots=True, repr=False)
class FinalizationReservationRecord:
    """Retained original bytes and local identity only, never an admitted token."""

    source_revision: str
    finalization_digest: str
    originals: tuple[bytes, bytes, bytes]
    digest: str


def _local_digest(value):
    if (type(value) is not str or len(value) != 71 or not value.startswith("sha256:")
            or any(character not in _HEX for character in value[7:])):
        raise CustodyRecordError("finalization reservation locator is not canonical SHA256")
    return bytes.fromhex(value[7:])


def _lengths(lengths):
    try:
        transport._response_lengths(lengths)
    except transport.AuthorityTransportError as exc:
        raise CustodyRecordError("finalization reservation originals exceed their fixed bounds") from exc


def _originals(originals):
    try:
        return transport._originals(originals, response=True)
    except transport.AuthorityTransportError as exc:
        raise CustodyRecordError("finalization reservation requires exact immutable raw3") from exc


def _digest(encoded):
    domain = IDENTITY_DOMAIN.encode("ascii")
    digest = hashlib.sha256()
    digest.update(len(domain).to_bytes(2, "big"))
    digest.update(domain)
    digest.update(len(encoded).to_bytes(8, "big"))
    digest.update(encoded)
    return "sha256:" + digest.hexdigest()


def encode(finalization_digest, originals, *, source_revision):
    """Return ordinary record and exact bytes after all inventory bounds."""
    held = _originals(originals)
    locator = _local_digest(finalization_digest)
    source = records._source_revision(source_revision)
    encoded = b"".join((MAGIC, len(source).to_bytes(2, "big"), source, locator,
        b"".join(len(raw).to_bytes(8, "big") for raw in held), *held))
    if len(encoded) > MAX_RECORD_BYTES:
        raise CustodyRecordError("finalization reservation exceeds its framed bound")
    return FinalizationReservationRecord(source_revision, finalization_digest,
        held, _digest(encoded)), encoded


def decode(encoded):
    """Keep exact bounded originals/source, with no outcome or currentness claim."""
    if (type(encoded) is not bytes
            or not _PREFIX_BYTES + 1 + 32 + _COUNT * 8 <= len(encoded) <= MAX_RECORD_BYTES):
        raise CustodyRecordError("finalization reservation is not bounded immutable bytes")
    if encoded[:8] != MAGIC:
        raise CustodyRecordError("finalization reservation record version is unsupported")
    source_length = int.from_bytes(encoded[8:10], "big")
    if not 1 <= source_length <= records.MAX_SOURCE_REVISION_BYTES:
        raise CustodyRecordError("finalization reservation source length is invalid")
    digest_offset = _PREFIX_BYTES + source_length
    vector_offset = digest_offset + 32
    body_offset = vector_offset + _COUNT * 8
    if body_offset > len(encoded):
        raise CustodyRecordError("finalization reservation header is truncated")
    lengths = tuple(int.from_bytes(encoded[offset:offset + 8], "big")
        for offset in range(vector_offset, body_offset, 8))
    _lengths(lengths)
    if body_offset + sum(lengths) != len(encoded):
        raise CustodyRecordError("finalization reservation is truncated or has trailing bytes")
    try:
        source_revision = encoded[_PREFIX_BYTES:digest_offset].decode("ascii")
    except UnicodeError as exc:
        raise CustodyRecordError("finalization reservation source token is not ASCII") from exc
    records._source_revision(source_revision)
    finalization_digest = "sha256:" + encoded[digest_offset:vector_offset].hex()
    bodies, offset = [], body_offset
    for size in lengths:
        bodies.append(encoded[offset:offset + size])
        offset += size
    return FinalizationReservationRecord(source_revision, finalization_digest,
        _originals(tuple(bodies)), _digest(encoded))
