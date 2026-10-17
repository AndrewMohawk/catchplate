"""Bounded opaque originals and a local SQL-dispatch claim, never authority.

The fixed frame is magic8, kind u8, source-length u16, source ASCII, preparation
SHA256 raw32, the source-fixed count of u64 body lengths, then exact original
bodies and EOF. The journal supplies the preparation's retained source token;
it is not replaced by the current implementation revision. The content digest
authenticates no signature, remote outcome, current head or action permission.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

from catchplate import authority_registration_reservation_transport as reservation
from catchplate import authority_registration_execution_sql_transport as sql
from catchplate import authority_registration_completion_transport as completion
from catchplate import control_plane_custody_records as records


MAGIC = b"SWCPO001"
IDENTITY_DOMAIN = "catchplate.controlPlaneRegistrationOutcomeRecord/v1"
KINDS = ("reservation", "sql-claimed", "sql-outcome", "completion-outcome", "completion-reconciled")
_COUNTS = (3, 0, 4, 4, 4)
_PREFIX_BYTES = 11
_MAX_HEADER_BYTES = _PREFIX_BYTES + records.MAX_SOURCE_REVISION_BYTES + 32 + 4 * 8
MAX_RECORD_BYTES = max(reservation.MAX_RESPONSE_BYTES, sql.MAX_RESPONSE_BYTES,
    completion.MAX_RESPONSE_BYTES) + _MAX_HEADER_BYTES
MAX_CLAIM_BYTES = _PREFIX_BYTES + records.MAX_SOURCE_REVISION_BYTES + 32
_HEX = frozenset("0123456789abcdef")
CustodyRecordError = records.CustodyRecordError


@dataclass(frozen=True, slots=True, repr=False)
class RegistrationOutcomeRecord:
    """Local original-byte data only, not an authenticated successful carrier."""

    source_revision: str
    local_digest: str
    kind: str
    originals: tuple[bytes, ...]
    digest: str


@dataclass(frozen=True, slots=True, repr=False)
class RegistrationOutcomes:
    """One preparation's retained local history; missing is not remote failure."""

    source_revision: str
    local_digest: str
    reservation: RegistrationOutcomeRecord | None
    sql_attempt: RegistrationOutcomeRecord | None
    sql_outcome: RegistrationOutcomeRecord | None
    completion_outcome: RegistrationOutcomeRecord | None
    completion_reconciled: RegistrationOutcomeRecord | None = None


def _local_digest(value):
    if (type(value) is not str or len(value) != 71 or not value.startswith("sha256:")
            or any(character not in _HEX for character in value[7:])):
        raise CustodyRecordError("registration outcome preparation identity is not canonical SHA256")
    return bytes.fromhex(value[7:])


def _profile(kind):
    if type(kind) is not str or kind not in KINDS:
        raise CustodyRecordError("registration outcome kind is not source fixed")
    return KINDS.index(kind)


def _lengths(profile, lengths):
    if type(lengths) is not tuple or len(lengths) != _COUNTS[profile]:
        raise CustodyRecordError("registration outcome length inventory differs")
    try:
        if profile == 0:
            reservation._response_lengths(lengths)
        elif profile == 2:
            sql._response_lengths(lengths)
        elif profile in (3, 4):
            completion._response_lengths(lengths)
    except reservation.AuthorityTransportError as exc:
        raise CustodyRecordError("registration outcome originals exceed their fixed bounds") from exc


def _originals(profile, originals):
    if (type(originals) is not tuple or len(originals) != _COUNTS[profile]
            or any(type(raw) is not bytes for raw in originals)):
        raise CustodyRecordError("registration outcome requires exact immutable original bytes")
    _lengths(profile, tuple(len(raw) for raw in originals))
    try:
        if profile == 0:
            reservation._originals(originals, response=True)
        elif profile == 2:
            sql._originals(originals, response=True)
        elif profile in (3, 4):
            completion._originals(originals, response=True)
    except reservation.AuthorityTransportError as exc:
        raise CustodyRecordError("registration outcome original carrier differs") from exc
    if profile == 4 and originals[0] != b"acknowledged":
        raise CustodyRecordError("registration reconciliation requires acknowledged originals")
    return originals


def _digest(encoded):
    domain = IDENTITY_DOMAIN.encode("ascii")
    digest = hashlib.sha256()
    digest.update(len(domain).to_bytes(2, "big"))
    digest.update(domain)
    digest.update(len(encoded).to_bytes(8, "big"))
    digest.update(encoded)
    return "sha256:" + digest.hexdigest()


def encode(kind, local_digest, originals, *, source_revision):
    """Return ordinary record data and canonical bytes; verify no authority."""
    profile = _profile(kind)
    held = _originals(profile, originals)
    local = _local_digest(local_digest)
    source = records._source_revision(source_revision)
    encoded = b"".join((MAGIC, bytes((profile,)), len(source).to_bytes(2, "big"), source,
        local, b"".join(len(raw).to_bytes(8, "big") for raw in held), *held))
    if len(encoded) > MAX_RECORD_BYTES:
        raise CustodyRecordError("registration outcome exceeds its framed bound")
    return RegistrationOutcomeRecord(source_revision, local_digest, kind, held, _digest(encoded)), encoded


def decode(encoded):
    """Keep exact bounded originals/source, never infer fresh success or scope."""
    if (type(encoded) is not bytes
            or not _PREFIX_BYTES + 1 + 32 <= len(encoded) <= MAX_RECORD_BYTES):
        raise CustodyRecordError("registration outcome is not bounded immutable bytes")
    if encoded[:8] != MAGIC or encoded[8] >= len(KINDS):
        raise CustodyRecordError("registration outcome version or kind is unsupported")
    profile = encoded[8]
    source_length = int.from_bytes(encoded[9:11], "big")
    if not 1 <= source_length <= records.MAX_SOURCE_REVISION_BYTES:
        raise CustodyRecordError("registration outcome source length is invalid")
    digest_offset = _PREFIX_BYTES + source_length
    vector_offset = digest_offset + 32
    body_offset = vector_offset + _COUNTS[profile] * 8
    if body_offset > len(encoded):
        raise CustodyRecordError("registration outcome header is truncated")
    lengths = tuple(int.from_bytes(encoded[offset:offset + 8], "big")
        for offset in range(vector_offset, body_offset, 8))
    _lengths(profile, lengths)
    if body_offset + sum(lengths) != len(encoded):
        raise CustodyRecordError("registration outcome is truncated or has trailing bytes")
    try:
        source_revision = encoded[_PREFIX_BYTES:digest_offset].decode("ascii")
    except UnicodeError as exc:
        raise CustodyRecordError("registration outcome source token is not ASCII") from exc
    records._source_revision(source_revision)
    local_digest = "sha256:" + encoded[digest_offset:vector_offset].hex()
    bodies, offset = [], body_offset
    for size in lengths:
        bodies.append(encoded[offset:offset + size])
        offset += size
    originals = _originals(profile, tuple(bodies))
    return RegistrationOutcomeRecord(source_revision, local_digest, KINDS[profile],
        originals, _digest(encoded))
