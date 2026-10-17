"""Exact-original raw10 retention for the registration execution grant family.

This separate binary profile does not change the five legacy custody profiles.
Its local content digest authenticates no caller, signature, replay, current
root, remote commit or permission to execute. Decoding preserves the original
source token without asserting that this implementation can replay that source.

The frame is magic8, source-length2, source ASCII bytes, ten unsigned big-endian
length8 values, then the exact originals: caller authorization, planning
request3, planning response4, complete before vector and signed grant. All body,
group and aggregate bounds precede body slicing or joining. No JSON, key,
clock, network, filesystem or replacement work allowance is used here.
"""
from __future__ import annotations

import hashlib

from catchplate import authority_contract as authority
from catchplate import authority_registration_execution_transport as transport
from catchplate import authority_webauthn_evidence_plan_transport as planning_transport
from catchplate import control_plane_custody_records as records


PREPARED_RECORD_MAGIC = b"SWCPG001"
IDENTITY_DOMAIN = "catchplate.controlPlaneRegistrationExecutionGrantRecord/v1"
FAMILY = "registration-execution"
OPERATION = "webauthn.registration.evidence.admit"
MAX_SOURCE_REVISION_BYTES = records.MAX_SOURCE_REVISION_BYTES
_ORIGINAL_COUNT = 10
_PREFIX_BYTES = 8 + 2
_MAX_HEADER_BYTES = _PREFIX_BYTES + MAX_SOURCE_REVISION_BYTES + _ORIGINAL_COUNT * 8
MAX_RECORD_BYTES = transport.MAX_BYTES + _MAX_HEADER_BYTES
_LIMITS = transport.REQUEST_LIMITS + transport.RESPONSE_LIMITS
CustodyRecordError = records.CustodyRecordError


def _lengths(lengths):
    """Admit the full fixed vector before any original body allocation."""
    try:
        transport._lengths(lengths, _LIMITS)
        # Retain both actual planning group constraints as well as the tighter
        # combined raw10 aggregate and per-object execution transport bounds.
        planning_transport._lengths(lengths[1:4], planning_transport._REQUEST_LIMITS)
        planning_transport._lengths(lengths[4:8], planning_transport._RESPONSE_LIMITS)
    except transport.AuthorityTransportError as exc:
        raise CustodyRecordError("execution grant originals exceed their fixed retention bounds") from exc


def _digest(encoded):
    # This local identity is not a signature/plan/request/grant identity.
    domain = IDENTITY_DOMAIN.encode("ascii")
    digest = hashlib.sha256()
    digest.update(len(domain).to_bytes(2, "big"))
    digest.update(domain)
    digest.update(len(encoded).to_bytes(8, "big"))
    digest.update(encoded)
    return "sha256:" + digest.hexdigest()


def encode(originals):
    """Return (local content digest, framed bytes) for exactly ten originals."""
    if (type(originals) is not tuple or len(originals) != _ORIGINAL_COUNT
            or any(type(raw) is not bytes for raw in originals)):
        raise CustodyRecordError("execution grant retention requires an exact immutable raw10 tuple")
    # An exact tuple of exact bytes cannot change during the native hash calls.
    held = originals
    lengths = tuple(len(raw) for raw in held)
    _lengths(lengths)
    source = records._source_revision(authority.SOURCE_REVISION)
    header = (PREPARED_RECORD_MAGIC + len(source).to_bytes(2, "big") + source
        + b"".join(size.to_bytes(8, "big") for size in lengths))
    if len(header) + sum(lengths) > MAX_RECORD_BYTES:
        raise CustodyRecordError("execution grant record exceeds its framed byte bound")
    encoded = b"".join((header, *held))
    return _digest(encoded), encoded


def decode_prepared(encoded_bytes):
    """Return the existing PreparedRecord data type, never a verified carrier."""
    if (type(encoded_bytes) is not bytes
            or not _PREFIX_BYTES <= len(encoded_bytes) <= MAX_RECORD_BYTES):
        raise CustodyRecordError("execution grant record is not bounded immutable bytes")
    original = encoded_bytes
    if original[:8] != PREPARED_RECORD_MAGIC:
        raise CustodyRecordError("execution grant record version is unsupported")
    source_length = int.from_bytes(original[8:10], "big")
    if not 1 <= source_length <= MAX_SOURCE_REVISION_BYTES:
        raise CustodyRecordError("execution grant source revision length is invalid")
    vector_offset = _PREFIX_BYTES + source_length
    body_offset = vector_offset + _ORIGINAL_COUNT * 8
    if body_offset > len(original):
        raise CustodyRecordError("execution grant record header is truncated")
    # Only the bounded header is sliced before the full length vector and
    # exact frame total pass admission; no untrusted body length allocates.
    lengths = tuple(int.from_bytes(original[offset:offset + 8], "big")
        for offset in range(vector_offset, body_offset, 8))
    _lengths(lengths)
    if body_offset + sum(lengths) != len(original):
        raise CustodyRecordError("execution grant bodies are truncated or have trailing bytes")
    try:
        source_revision = original[_PREFIX_BYTES:vector_offset].decode("ascii")
    except UnicodeError as exc:
        raise CustodyRecordError("execution grant source revision is not ASCII") from exc
    records._source_revision(source_revision)
    bodies = []
    offset = body_offset
    for size in lengths:
        bodies.append(original[offset:offset + size])
        offset += size
    held = tuple(bodies)
    digest = _digest(original)
    return records.PreparedRecord(FAMILY, OPERATION, source_revision, held, digest)
