"""Fixed opaque activation originals beneath one irreversible local claim.

No record authenticates permission, grant, reservation, SQL success or current
state. The codec retains ciphertext and public originals, never the pending
cookie, permission assertion or returned token. It has no clocks or filesystem.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

from serverware import authority_contract as authority
from serverware import authority_current_root_vector as vector
from serverware import authority_oidc_session_activation_execution_authorizer_transport as grant
from serverware import authority_oidc_session_activation_reservation_transport as reserve
from serverware import authority_oidc_session_activation_sql_transport as sql
from serverware import authority_oidc_session_activation_completion_transport as completion
from serverware import control_plane_custody_records as records
from serverware import control_plane_oidc_session_activation_dispatch_attempt as attempts


MAGIC = b"SWCAO001"
# Append-only profile indices: all five original encodings/domains stay fixed.
KINDS = ("prepared", "grant", "reserved", "sql-claimed", "sql-outcome", "completion-outcome")
_COUNTS = (5, 1, 3, 0, 4, 4)
_PREFIX_BYTES = 11
_MAX_HEADER_BYTES = _PREFIX_BYTES + records.MAX_SOURCE_REVISION_BYTES + 32
_BODY_MAXIMA = (authority.MAX_RESULT_BYTES, grant.MAX_RESPONSE_BYTES,
    reserve.MAX_RESPONSE_BYTES, 0, sql.MAX_RESPONSE_BYTES, completion.MAX_RESPONSE_BYTES)
_MAXIMA = tuple(_MAX_HEADER_BYTES + count * 8 + maximum
    for count, maximum in zip(_COUNTS, _BODY_MAXIMA))
(MAX_PREPARED_BYTES, MAX_GRANT_BYTES, MAX_RESERVATION_BYTES, MAX_SQL_CLAIM_BYTES,
    MAX_SQL_OUTCOME_BYTES, MAX_COMPLETION_OUTCOME_BYTES) = _MAXIMA
MAX_RECORD_BYTES = max(_MAXIMA)
MAX_LOAD_IO_BYTES = attempts.MAX_RECORD_BYTES + sum(_MAXIMA)
_DOMAINS = tuple("serverware.controlPlaneOidcSessionActivationRecord/" + kind + "/v1"
    for kind in KINDS)
CustodyRecordError = records.CustodyRecordError


@dataclass(frozen=True, slots=True, repr=False)
class ActivationRecord:
    """Ordinary exact bytes, not an admission result or retry permission."""

    source_revision: str
    finalization_digest: str
    kind: str
    originals: tuple[bytes, ...]
    digest: str


@dataclass(frozen=True, slots=True, repr=False)
class ActivationRecords:
    """Read-only prefix; a missing observation never proves nonexecution."""

    source_revision: str
    finalization_digest: str
    prepared: ActivationRecord | None
    grant: ActivationRecord | None
    reservation: ActivationRecord | None
    sql_attempt: ActivationRecord | None
    sql_outcome: ActivationRecord | None
    completion_outcome: ActivationRecord | None = None


def _profile(kind):
    if type(kind) is not str or kind not in KINDS:
        raise CustodyRecordError("activation stage is not source fixed")
    return KINDS.index(kind)


def _maximum(kind):
    return _MAXIMA[_profile(kind)]


def _lengths(profile, lengths):
    if (type(lengths) is not tuple or len(lengths) != _COUNTS[profile]
            or any(type(size) is not int or size < 0 for size in lengths)):
        raise CustodyRecordError("activation stage length inventory differs")
    try:
        if profile == 0:
            grant._lengths(lengths[:4], response=False)
            if not 2 <= lengths[4] <= vector.MAX_BYTES:
                raise CustodyRecordError("activation before vector exceeds its fixed bound")
        elif profile == 1:
            grant._lengths(lengths, response=True)
        elif profile == 2:
            reserve._lengths(lengths, response=True)
        elif profile == 4:
            sql._response_lengths(lengths)
        elif profile == 5:
            completion._response_lengths(lengths)
        if sum(lengths) > _BODY_MAXIMA[profile]:
            raise CustodyRecordError("activation stage exceeds its aggregate bound")
    except grant.AuthorityTransportError as exc:
        raise CustodyRecordError("activation stage exceeds its original frame bounds") from exc


def _originals(profile, originals):
    if (type(originals) is not tuple or len(originals) != _COUNTS[profile]
            or any(type(raw) is not bytes for raw in originals)):
        raise CustodyRecordError("activation stage requires exact immutable originals")
    _lengths(profile, tuple(len(raw) for raw in originals))
    try:
        if profile == 0:
            grant._originals(originals[:4], response=False)
        elif profile == 1:
            grant._originals(originals, response=True)
        elif profile == 2:
            reserve._originals(originals, response=True)
        elif profile == 4:
            sql._originals(originals, response=True)
        elif profile == 5:
            completion._originals(originals, response=True)
    except grant.AuthorityTransportError as exc:
        raise CustodyRecordError("activation stage original carrier differs") from exc
    return originals


def _append_io_bytes(kind, originals):
    """Precharge before a stable callback; this helper performs no I/O/hash.

    Reserve the largest source header, the original claim read and three exact
    stage frames for publication/readback or an existing-slot comparison.
    """
    profile = _profile(kind)
    held = _originals(profile, originals)
    size = _MAX_HEADER_BYTES + 8 * len(held) + sum(len(raw) for raw in held)
    return attempts.MAX_RECORD_BYTES + 3 * size


def _digest(profile, original):
    domain = _DOMAINS[profile].encode("ascii")
    digest = hashlib.sha256()
    digest.update(len(domain).to_bytes(2, "big"))
    digest.update(domain)
    digest.update(len(original).to_bytes(8, "big"))
    digest.update(original)
    return "sha256:" + digest.hexdigest()


def encode(kind, finalization_digest, originals, *, source_revision):
    profile = _profile(kind)
    held = _originals(profile, originals)
    local = attempts._digest_bytes(finalization_digest)
    source = records._source_revision(source_revision)
    if source_revision != authority.SOURCE_REVISION:
        raise CustodyRecordError("activation stage publication requires the current source cohort")
    encoded = b"".join((MAGIC, bytes((profile,)), len(source).to_bytes(2, "big"), source,
        local, b"".join(len(raw).to_bytes(8, "big") for raw in held), *held))
    if len(encoded) > _MAXIMA[profile]:
        raise CustodyRecordError("activation stage exceeds its framed bound")
    return ActivationRecord(source_revision, finalization_digest, kind, held,
        _digest(profile, encoded)), encoded


def decode(original):
    """Preserve historical source metadata; do not grant live continuation."""
    if (type(original) is not bytes
            or not _PREFIX_BYTES + 1 + 32 <= len(original) <= MAX_RECORD_BYTES
            or original[:8] != MAGIC or original[8] >= len(KINDS)):
        raise CustodyRecordError("activation stage is not a bounded supported original")
    profile = original[8]
    if len(original) > _MAXIMA[profile]:
        raise CustodyRecordError("activation stage exceeds its fixed profile bound")
    source_length = int.from_bytes(original[9:11], "big")
    if not 1 <= source_length <= records.MAX_SOURCE_REVISION_BYTES:
        raise CustodyRecordError("activation stage source length differs")
    digest_offset = _PREFIX_BYTES + source_length
    vector_offset = digest_offset + 32
    body_offset = vector_offset + 8 * _COUNTS[profile]
    if body_offset > len(original):
        raise CustodyRecordError("activation stage header is truncated")
    lengths = tuple(int.from_bytes(original[offset:offset + 8], "big")
        for offset in range(vector_offset, body_offset, 8))
    _lengths(profile, lengths)
    if body_offset + sum(lengths) != len(original):
        raise CustodyRecordError("activation stage is truncated or has trailing bytes")
    try:
        source_revision = original[_PREFIX_BYTES:digest_offset].decode("ascii")
    except UnicodeError as exc:
        raise CustodyRecordError("activation stage source is not ASCII") from exc
    records._source_revision(source_revision)
    local = "sha256:" + original[digest_offset:vector_offset].hex()
    bodies, offset = [], body_offset
    for size in lengths:
        bodies.append(original[offset:offset + size])
        offset += size
    held = _originals(profile, tuple(bodies))
    return ActivationRecord(source_revision, local, KINDS[profile], held,
        _digest(profile, original))
