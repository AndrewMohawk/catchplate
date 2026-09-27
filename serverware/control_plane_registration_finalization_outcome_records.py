"""Opaque finalization SQL observations and an irreversible local claim.

The frame is magic8, kind u8, source-length u16, retained source ASCII,
finalization preparation SHA256 raw32, fixed-count u64 body lengths, bodies
and exact EOF. Claim and outcome have distinct content-identity domains;
neither domain authenticates permission, SQL success or a current head.
There is no clock, signature verification, filesystem or transport here.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

from serverware import authority_registration_finalization_sql_transport as sql
from serverware import control_plane_custody_records as records


MAGIC = b"SWCPX001"
CLAIM_IDENTITY_DOMAIN = "serverware.controlPlaneRegistrationFinalizationSqlClaimRecord/v1"
OUTCOME_IDENTITY_DOMAIN = "serverware.controlPlaneRegistrationFinalizationSqlOutcomeRecord/v1"
KINDS = ("sql-claimed", "sql-outcome")
_DOMAINS = (CLAIM_IDENTITY_DOMAIN, OUTCOME_IDENTITY_DOMAIN)
_COUNTS = (0, 4)
_PREFIX_BYTES = 11
MAX_CLAIM_BYTES = _PREFIX_BYTES + records.MAX_SOURCE_REVISION_BYTES + 32
MAX_RECORD_BYTES = MAX_CLAIM_BYTES + 4 * 8 + sql.MAX_RESPONSE_BYTES
_HEX = frozenset("0123456789abcdef")
CustodyRecordError = records.CustodyRecordError


@dataclass(frozen=True, slots=True, repr=False)
class FinalizationOutcomeRecord:
    """Ordinary retained bytes only, never a successful-admission carrier."""

    source_revision: str
    finalization_digest: str
    kind: str
    originals: tuple[bytes, ...]
    digest: str


@dataclass(frozen=True, slots=True, repr=False)
class FinalizationOutcomes:
    """Missing outcomes do not establish nonexecution or permit another send."""

    source_revision: str
    finalization_digest: str
    sql_attempt: FinalizationOutcomeRecord | None
    sql_outcome: FinalizationOutcomeRecord | None


def _local_digest(value):
    if (type(value) is not str or len(value) != 71 or not value.startswith("sha256:")
            or any(character not in _HEX for character in value[7:])):
        raise CustodyRecordError("finalization outcome preparation identity is not canonical SHA256")
    return bytes.fromhex(value[7:])


def _profile(kind):
    if type(kind) is not str or kind not in KINDS:
        raise CustodyRecordError("finalization outcome kind is not source fixed")
    return KINDS.index(kind)


def _lengths(profile, lengths):
    if type(lengths) is not tuple or len(lengths) != _COUNTS[profile]:
        raise CustodyRecordError("finalization outcome length inventory differs")
    if profile == 1:
        try:
            sql._response_lengths(lengths)
        except sql.AuthorityTransportError as exc:
            raise CustodyRecordError("finalization outcome originals exceed their fixed bounds") from exc


def _originals(profile, originals):
    if (type(originals) is not tuple or len(originals) != _COUNTS[profile]
            or any(type(raw) is not bytes for raw in originals)):
        raise CustodyRecordError("finalization outcome requires exact immutable original bytes")
    _lengths(profile, tuple(len(raw) for raw in originals))
    if profile == 1:
        try:
            sql._originals(originals, response=True)
        except sql.AuthorityTransportError as exc:
            raise CustodyRecordError("finalization outcome original carrier differs") from exc
    return originals


def _digest(profile, encoded):
    domain = _DOMAINS[profile].encode("ascii")
    digest = hashlib.sha256()
    digest.update(len(domain).to_bytes(2, "big"))
    digest.update(domain)
    digest.update(len(encoded).to_bytes(8, "big"))
    digest.update(encoded)
    return "sha256:" + digest.hexdigest()


def encode(kind, finalization_digest, originals, *, source_revision):
    """Capture bounded immutable bytes and the retained original source token."""
    profile = _profile(kind)
    held = _originals(profile, originals)
    local = _local_digest(finalization_digest)
    source = records._source_revision(source_revision)
    encoded = b"".join((MAGIC, bytes((profile,)), len(source).to_bytes(2, "big"), source,
        local, b"".join(len(raw).to_bytes(8, "big") for raw in held), *held))
    maximum = MAX_CLAIM_BYTES if profile == 0 else MAX_RECORD_BYTES
    if len(encoded) > maximum:
        raise CustodyRecordError("finalization outcome exceeds its framed bound")
    return FinalizationOutcomeRecord(source_revision, finalization_digest, kind, held,
        _digest(profile, encoded)), encoded


def decode(encoded):
    """Preserve exact source/originals; reject unknown, short or trailing data."""
    if (type(encoded) is not bytes
            or not _PREFIX_BYTES + 1 + 32 <= len(encoded) <= MAX_RECORD_BYTES):
        raise CustodyRecordError("finalization outcome is not bounded immutable bytes")
    if encoded[:8] != MAGIC or encoded[8] >= len(KINDS):
        raise CustodyRecordError("finalization outcome version or kind is unsupported")
    profile = encoded[8]
    source_length = int.from_bytes(encoded[9:11], "big")
    if not 1 <= source_length <= records.MAX_SOURCE_REVISION_BYTES:
        raise CustodyRecordError("finalization outcome source length is invalid")
    digest_offset = _PREFIX_BYTES + source_length
    vector_offset = digest_offset + 32
    body_offset = vector_offset + _COUNTS[profile] * 8
    if body_offset > len(encoded):
        raise CustodyRecordError("finalization outcome header is truncated")
    lengths = tuple(int.from_bytes(encoded[offset:offset + 8], "big")
        for offset in range(vector_offset, body_offset, 8))
    _lengths(profile, lengths)
    if body_offset + sum(lengths) != len(encoded):
        raise CustodyRecordError("finalization outcome is truncated or has trailing bytes")
    try:
        source_revision = encoded[_PREFIX_BYTES:digest_offset].decode("ascii")
    except UnicodeError as exc:
        raise CustodyRecordError("finalization outcome source token is not ASCII") from exc
    records._source_revision(source_revision)
    finalization_digest = "sha256:" + encoded[digest_offset:vector_offset].hex()
    bodies, offset = [], body_offset
    for size in lengths:
        bodies.append(encoded[offset:offset + size])
        offset += size
    originals = _originals(profile, tuple(bodies))
    return FinalizationOutcomeRecord(source_revision, finalization_digest, KINDS[profile],
        originals, _digest(profile, encoded))
