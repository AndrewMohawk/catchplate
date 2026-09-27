"""Fixed token-free metadata for one local release-client dispatch claim.

This codec grants no permission and carries no request, response or token.
The exact client-authorization digest keys the irreversible journal slot;
fresh independently issued root authorization is a different slot, not a retry
under the old grant. Decoding preserves the original source token as data.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_contract as authority
from serverware import control_plane_custody_records as records


MAGIC = b"SWCPR001"
KIND = "release-client-claimed"
LIVE_PROFILE = "live-release"
RECOVERY_PROFILE = "recovery"
_PROFILES = (LIVE_PROFILE, RECOVERY_PROFILE)
_PREFIX_BYTES = 11
_DIGEST_BYTES = 4 * 32
MAX_RECORD_BYTES = _PREFIX_BYTES + records.MAX_SOURCE_REVISION_BYTES + _DIGEST_BYTES
# The configured caller charges before the stable native journal callback.
MAX_CLAIM_IO_BYTES = 3 * MAX_RECORD_BYTES
_HEX = frozenset("0123456789abcdef")
CustodyRecordError = records.CustodyRecordError


@dataclass(frozen=True, slots=True, repr=False)
class ReleaseAttemptRecord:
    """Ordinary immutable metadata, never an authority or success carrier."""

    client_authorization_digest: str
    request_identity: str
    profile: str
    server_bootstrap_digest: str
    expected_outcome_digest: str
    source_revision: str


def _digest_bytes(value):
    if (type(value) is not str or len(value) != 71 or not value.startswith("sha256:")
            or any(character not in _HEX for character in value[7:])):
        raise CustodyRecordError("release attempt identity is not canonical SHA256")
    return bytes.fromhex(value[7:])


def encode(*, client_authorization_digest, request_identity, profile,
        server_bootstrap_digest, expected_outcome_digest):
    """Capture only exact immutable public scalars before filesystem callbacks."""
    if type(profile) is not str or profile not in _PROFILES:
        raise CustodyRecordError("release attempt profile is not source fixed")
    values = (client_authorization_digest, request_identity,
        server_bootstrap_digest, expected_outcome_digest)
    digests = tuple(_digest_bytes(value) for value in values)
    source_revision = authority.SOURCE_REVISION
    source = records._source_revision(source_revision)
    encoded = (MAGIC + bytes((_PROFILES.index(profile),))
        + len(source).to_bytes(2, "big") + source + b"".join(digests))
    if len(encoded) > MAX_RECORD_BYTES:
        raise CustodyRecordError("release attempt exceeds its fixed metadata bound")
    return ReleaseAttemptRecord(values[0], values[1], profile,
        values[2], values[3], source_revision), encoded


def decode(original_bytes):
    """Decode exact bounded metadata and EOF, without admitting any authority."""
    if (type(original_bytes) is not bytes
            or not _PREFIX_BYTES + 1 + _DIGEST_BYTES <= len(original_bytes) <= MAX_RECORD_BYTES):
        raise CustodyRecordError("release attempt is not bounded immutable metadata")
    original = original_bytes
    if original[:8] != MAGIC or original[8] not in (0, 1):
        raise CustodyRecordError("release attempt format or profile differs")
    source_length = int.from_bytes(original[9:11], "big")
    if (not 1 <= source_length <= records.MAX_SOURCE_REVISION_BYTES
            or len(original) != _PREFIX_BYTES + source_length + _DIGEST_BYTES):
        raise CustodyRecordError("release attempt source or exact length differs")
    offset = _PREFIX_BYTES + source_length
    try:
        source_revision = original[_PREFIX_BYTES:offset].decode("ascii")
    except UnicodeError as exc:
        raise CustodyRecordError("release attempt source is not ASCII") from exc
    records._source_revision(source_revision)
    digests = tuple("sha256:" + original[index:index + 32].hex()
        for index in range(offset, len(original), 32))
    return ReleaseAttemptRecord(digests[0], digests[1], _PROFILES[original[8]],
        digests[2], digests[3], source_revision)
