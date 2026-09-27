"""Bounded local commit-marker bytes for registration preparation records.

This association links an execution-record content digest to a signer-record
content digest. It authenticates neither record and proves no signature,
permission, delivery, currentness or SQL result. The journal must independently
require both originals, their exact families and a shared source revision,
publish the marker only afterward, and reject reassociation on recovery/load.

The fixed wire is magic8, source-length u16 big-endian, source ASCII, execution
SHA256 raw32, signer SHA256 raw32, and exact EOF. No JSON, keys, clocks, hashing,
filesystem, work allowance or fallback is involved. Historical source tokens
are preserved as data, never silently replaced with the current revision.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_contract as authority
from serverware import control_plane_custody_records as records


MAGIC = b"SWCPL001"
MAX_ASSOCIATION_BYTES = 330
_PREFIX_BYTES = 10
_DIGEST_BYTES = 32
_HEX = frozenset("0123456789abcdef")
CustodyRecordError = records.CustodyRecordError


@dataclass(frozen=True, slots=True)
class RegistrationPreparationAssociation:
    """Local original-byte association only, not an authenticated carrier."""

    source_revision: str
    execution_digest: str
    signer_digest: str


def _digest_bytes(value):
    if (type(value) is not str or len(value) != 71 or not value.startswith("sha256:")
            or any(character not in _HEX for character in value[7:])):
        raise CustodyRecordError("registration association digest is not canonical SHA256 text")
    return bytes.fromhex(value[7:])


def encode(execution_digest, signer_digest):
    """Return ordinary association data and its exact bounded marker bytes."""
    execution = _digest_bytes(execution_digest)
    signer = _digest_bytes(signer_digest)
    revision = authority.SOURCE_REVISION
    source = records._source_revision(revision)
    encoded = MAGIC + len(source).to_bytes(2, "big") + source + execution + signer
    if len(encoded) > MAX_ASSOCIATION_BYTES:
        raise CustodyRecordError("registration association exceeds its fixed byte bound")
    return RegistrationPreparationAssociation(revision, execution_digest, signer_digest), encoded


def decode(encoded):
    """Decode immutable originals, retaining their original source token."""
    if (type(encoded) is not bytes
            or not _PREFIX_BYTES + 1 + 2 * _DIGEST_BYTES <= len(encoded) <= MAX_ASSOCIATION_BYTES):
        raise CustodyRecordError("registration association is not bounded immutable bytes")
    if encoded[:8] != MAGIC:
        raise CustodyRecordError("registration association magic is unsupported")
    source_length = int.from_bytes(encoded[8:10], "big")
    if not 1 <= source_length <= records.MAX_SOURCE_REVISION_BYTES:
        raise CustodyRecordError("registration association source length is invalid")
    digest_offset = _PREFIX_BYTES + source_length
    if len(encoded) != digest_offset + 2 * _DIGEST_BYTES:
        raise CustodyRecordError("registration association is truncated or has trailing bytes")
    try:
        revision = encoded[_PREFIX_BYTES:digest_offset].decode("ascii")
    except UnicodeError as exc:
        raise CustodyRecordError("registration association source is not ASCII") from exc
    records._source_revision(revision)
    execution = "sha256:" + encoded[digest_offset:digest_offset + _DIGEST_BYTES].hex()
    signer = "sha256:" + encoded[digest_offset + _DIGEST_BYTES:].hex()
    return RegistrationPreparationAssociation(revision, execution, signer)
