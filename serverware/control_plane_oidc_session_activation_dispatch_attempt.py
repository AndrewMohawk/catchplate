"""Token-free metadata for one irreversible pre-planner activation claim.

The retained finalization locator, not a new plan or permission challenge,
keys the slot. No marker authenticates ownership, permission or an outcome.
Historical source metadata survives decoding only as ordinary retained data.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_contract as authority
from serverware import control_plane_custody_records as records


MAGIC = b"SWCAD001"
KIND = "activation-dispatch-claimed"
_PREFIX_BYTES = 10
_DIGEST_BYTES = 3 * 32
MAX_RECORD_BYTES = _PREFIX_BYTES + records.MAX_SOURCE_REVISION_BYTES + _DIGEST_BYTES
# The original caller precharges before the stable native journal callback.
MAX_CLAIM_IO_BYTES = 3 * MAX_RECORD_BYTES
_HEX = frozenset("0123456789abcdef")
CustodyRecordError = records.CustodyRecordError


@dataclass(frozen=True, slots=True, repr=False)
class ActivationDispatchAttemptRecord:
    """Immutable public metadata, never an accepted authority carrier."""

    finalization_digest: str
    request_binding_digest: str
    authorization_enrollment_digest: str
    source_revision: str


def _digest_bytes(value):
    if (type(value) is not str or len(value) != 71 or not value.startswith("sha256:")
            or any(character not in _HEX for character in value[7:])):
        raise CustodyRecordError("activation dispatch identity is not canonical SHA256")
    return bytes.fromhex(value[7:])


def encode(*, finalization_digest, request_binding_digest,
        authorization_enrollment_digest, source_revision):
    """Own exact immutable scalars before filesystem or other callbacks."""
    values = (finalization_digest, request_binding_digest, authorization_enrollment_digest)
    digests = tuple(_digest_bytes(value) for value in values)
    source = records._source_revision(source_revision)
    if source_revision != authority.SOURCE_REVISION:
        raise CustodyRecordError("activation dispatch requires the current source cohort")
    encoded = MAGIC + len(source).to_bytes(2, "big") + source + b"".join(digests)
    if len(encoded) > MAX_RECORD_BYTES:
        raise CustodyRecordError("activation dispatch exceeds its fixed metadata bound")
    return ActivationDispatchAttemptRecord(*values, source_revision), encoded


def decode(original_bytes):
    """Read bounded exact metadata and EOF, without granting new dispatch."""
    if (type(original_bytes) is not bytes
            or not _PREFIX_BYTES + 1 + _DIGEST_BYTES <= len(original_bytes) <= MAX_RECORD_BYTES):
        raise CustodyRecordError("activation dispatch is not bounded immutable metadata")
    original = original_bytes
    if original[:8] != MAGIC:
        raise CustodyRecordError("activation dispatch format differs")
    source_length = int.from_bytes(original[8:10], "big")
    if (not 1 <= source_length <= records.MAX_SOURCE_REVISION_BYTES
            or len(original) != _PREFIX_BYTES + source_length + _DIGEST_BYTES):
        raise CustodyRecordError("activation dispatch source or exact length differs")
    offset = _PREFIX_BYTES + source_length
    try:
        source_revision = original[_PREFIX_BYTES:offset].decode("ascii")
    except UnicodeError as exc:
        raise CustodyRecordError("activation dispatch source is not ASCII") from exc
    records._source_revision(source_revision)
    digests = tuple("sha256:" + original[index:index + 32].hex()
        for index in range(offset, len(original), 32))
    return ActivationDispatchAttemptRecord(*digests, source_revision)
