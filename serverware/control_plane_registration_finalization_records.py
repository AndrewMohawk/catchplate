"""Opaque finalization grant raw10, separate from evidence-grant retention.

The exact originals are dedicated caller authorization, custody raw7, complete
before vector and signed grant. This codec authenticates none of them. A local
content digest is neither a grant identity nor permission to reserve/execute.
Every original/group/aggregate bound precedes body slicing or joining. The
original source token survives decoding without any replay compatibility claim.
"""
from __future__ import annotations

import hashlib

from serverware import authority_contract as authority
from serverware import authority_registration_finalization_transport as transport
from serverware import authority_webauthn_transition_custody_transport as custody
from serverware import control_plane_custody_records as records


PREPARED_RECORD_MAGIC = b"SWCPF001"
IDENTITY_DOMAIN = "serverware.controlPlaneRegistrationFinalizationGrantRecord/v1"
FAMILY = "registration-finalization"
OPERATION = "webauthn.registration.finalize"
MAX_SOURCE_REVISION_BYTES = records.MAX_SOURCE_REVISION_BYTES
_ORIGINAL_COUNT = 10
_PREFIX_BYTES = 10
_MAX_HEADER_BYTES = _PREFIX_BYTES + MAX_SOURCE_REVISION_BYTES + _ORIGINAL_COUNT * 8
MAX_RECORD_BYTES = transport.MAX_BYTES + _MAX_HEADER_BYTES
CustodyRecordError = records.CustodyRecordError


def _lengths(lengths):
    try:
        if type(lengths) is not tuple or len(lengths) != _ORIGINAL_COUNT:
            raise CustodyRecordError("finalization retention requires ten original lengths")
        transport._lengths(lengths[:9], transport.REQUEST_LIMITS)
        transport._lengths(lengths[9:], transport.RESPONSE_LIMITS)
        custody._validate_lengths(lengths[1:8])
        if sum(lengths) > transport.MAX_BYTES:
            raise CustodyRecordError("finalization originals exceed their combined retention bound")
    except transport.AuthorityTransportError as exc:
        raise CustodyRecordError("finalization originals exceed their fixed retention bounds") from exc


def _digest(encoded):
    domain = IDENTITY_DOMAIN.encode("ascii")
    digest = hashlib.sha256()
    digest.update(len(domain).to_bytes(2, "big"))
    digest.update(domain)
    digest.update(len(encoded).to_bytes(8, "big"))
    digest.update(encoded)
    return "sha256:" + digest.hexdigest()


def encode(originals):
    """Return (local content digest, framed bytes), never an admitted result."""
    if (type(originals) is not tuple or len(originals) != _ORIGINAL_COUNT
            or any(type(raw) is not bytes for raw in originals)):
        raise CustodyRecordError("finalization retention requires an exact immutable raw10 tuple")
    held = originals
    lengths = tuple(len(raw) for raw in held)
    _lengths(lengths)
    source = records._source_revision(authority.SOURCE_REVISION)
    header = (PREPARED_RECORD_MAGIC + len(source).to_bytes(2, "big") + source
        + b"".join(size.to_bytes(8, "big") for size in lengths))
    if len(header) + sum(lengths) > MAX_RECORD_BYTES:
        raise CustodyRecordError("finalization record exceeds its framed byte bound")
    encoded = b"".join((header, *held))
    return _digest(encoded), encoded


def decode_prepared(encoded_bytes):
    """Retain the original source and bodies as an ordinary PreparedRecord."""
    if (type(encoded_bytes) is not bytes
            or not _PREFIX_BYTES <= len(encoded_bytes) <= MAX_RECORD_BYTES):
        raise CustodyRecordError("finalization record is not bounded immutable bytes")
    original = encoded_bytes
    if original[:8] != PREPARED_RECORD_MAGIC:
        raise CustodyRecordError("finalization record magic is unsupported")
    source_length = int.from_bytes(original[8:10], "big")
    if not 1 <= source_length <= MAX_SOURCE_REVISION_BYTES:
        raise CustodyRecordError("finalization source revision length is invalid")
    vector_offset = _PREFIX_BYTES + source_length
    body_offset = vector_offset + _ORIGINAL_COUNT * 8
    if body_offset > len(original):
        raise CustodyRecordError("finalization record header is truncated")
    lengths = tuple(int.from_bytes(original[offset:offset + 8], "big")
        for offset in range(vector_offset, body_offset, 8))
    _lengths(lengths)
    if body_offset + sum(lengths) != len(original):
        raise CustodyRecordError("finalization bodies are truncated or have trailing bytes")
    try:
        source_revision = original[_PREFIX_BYTES:vector_offset].decode("ascii")
    except UnicodeError as exc:
        raise CustodyRecordError("finalization source revision is not ASCII") from exc
    records._source_revision(source_revision)
    bodies = []
    offset = body_offset
    for size in lengths:
        bodies.append(original[offset:offset + size])
        offset += size
    return records.PreparedRecord(FAMILY, OPERATION, source_revision, tuple(bodies), _digest(original))
