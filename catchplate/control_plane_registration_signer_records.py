"""Opaque original signer request8/response2 retention, not finalization.

This fixed profile preserves the exact exchange needed by later genuine replay.
Its local digest authenticates neither the signer nor enrollment, ceremony,
grant association, current scope or execution permission. Decoding preserves
the original source revision without promising cross-source replay support.

The frame is magic8, source-length2, source ASCII bytes, ten unsigned big-endian
length8 values, then the exact signer request8 and response2. Existing signer
body/group and combined raw10 bounds apply before slicing or joining bodies.
No JSON decoding, clock, key, I/O or replacement work allowance is used here.
The legacy five profiles and the distinct execution-grant profile are unchanged.
"""
from __future__ import annotations

import hashlib

from catchplate import authority_contract as authority
from catchplate import authority_webauthn_registration_custody_caller as transport
from catchplate import control_plane_custody_records as records


PREPARED_RECORD_MAGIC = b"SWCPS001"
IDENTITY_DOMAIN = "catchplate.controlPlaneRegistrationSignerExchangeRecord/v1"
FAMILY = "registration-signer"
OPERATION = "webauthn.registration.evidence.admit"
MAX_SOURCE_REVISION_BYTES = records.MAX_SOURCE_REVISION_BYTES
_ORIGINAL_COUNT = 10
_PREFIX_BYTES = 8 + 2
_MAX_HEADER_BYTES = _PREFIX_BYTES + MAX_SOURCE_REVISION_BYTES + _ORIGINAL_COUNT * 8
MAX_RECORD_BYTES = transport.MAX_REQUEST_BYTES + _MAX_HEADER_BYTES
CustodyRecordError = records.CustodyRecordError


def _lengths(lengths):
    """Use the actual fixed signer and combined raw10 transport bounds."""
    try:
        transport._request_lengths(lengths)
    except (transport.AuthorityTransportError,
            transport.signer_wire.WebAuthnRegistrationSignerWireError) as exc:
        raise CustodyRecordError("registration signer originals exceed their fixed retention bounds") from exc


def _digest(encoded):
    # This is only the framed local byte identity, not a signer/grant identity.
    domain = IDENTITY_DOMAIN.encode("ascii")
    digest = hashlib.sha256()
    digest.update(len(domain).to_bytes(2, "big"))
    digest.update(domain)
    digest.update(len(encoded).to_bytes(8, "big"))
    digest.update(encoded)
    return "sha256:" + digest.hexdigest()


def encode(originals):
    """Return (local digest, frame) for immutable signer request8/response2."""
    if (type(originals) is not tuple or len(originals) != _ORIGINAL_COUNT
            or any(type(raw) is not bytes for raw in originals)):
        raise CustodyRecordError("registration signer retention requires an exact immutable raw10 tuple")
    held = originals
    lengths = tuple(len(raw) for raw in held)
    _lengths(lengths)
    source = records._source_revision(authority.SOURCE_REVISION)
    header = (PREPARED_RECORD_MAGIC + len(source).to_bytes(2, "big") + source
        + b"".join(size.to_bytes(8, "big") for size in lengths))
    if len(header) + sum(lengths) > MAX_RECORD_BYTES:
        raise CustodyRecordError("registration signer record exceeds its framed byte bound")
    encoded = b"".join((header, *held))
    return _digest(encoded), encoded


def decode_prepared(encoded_bytes):
    """Preserve exact originals/source in PreparedRecord, never a proof token."""
    if (type(encoded_bytes) is not bytes
            or not _PREFIX_BYTES <= len(encoded_bytes) <= MAX_RECORD_BYTES):
        raise CustodyRecordError("registration signer record is not bounded immutable bytes")
    original = encoded_bytes
    if original[:8] != PREPARED_RECORD_MAGIC:
        raise CustodyRecordError("registration signer record version is unsupported")
    source_length = int.from_bytes(original[8:10], "big")
    if not 1 <= source_length <= MAX_SOURCE_REVISION_BYTES:
        raise CustodyRecordError("registration signer source revision length is invalid")
    vector_offset = _PREFIX_BYTES + source_length
    body_offset = vector_offset + _ORIGINAL_COUNT * 8
    if body_offset > len(original):
        raise CustodyRecordError("registration signer record header is truncated")
    # Only the bounded length inventory is sliced before all original body
    # sizes, groups and the exact frame total are admitted.
    lengths = tuple(int.from_bytes(original[offset:offset + 8], "big")
        for offset in range(vector_offset, body_offset, 8))
    _lengths(lengths)
    if body_offset + sum(lengths) != len(original):
        raise CustodyRecordError("registration signer bodies are truncated or have trailing bytes")
    try:
        source_revision = original[_PREFIX_BYTES:vector_offset].decode("ascii")
    except UnicodeError as exc:
        raise CustodyRecordError("registration signer source revision is not ASCII") from exc
    records._source_revision(source_revision)
    bodies = []
    offset = body_offset
    for size in lengths:
        bodies.append(original[offset:offset + size])
        offset += size
    return records.PreparedRecord(FAMILY, OPERATION, source_revision, tuple(bodies), _digest(original))
