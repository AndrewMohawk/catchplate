"""Bounded unsigned local readback observations, without authority claims.

A record binds an existing local prepared identity to successful readback
metadata. It contains no original plan bodies, signature, terminal business
state, absence proof or permission to send again. The caller must perform the
real fresh read and exact-original comparison before requesting publication.
Decoding a source token is not historical replay compatibility admission.

Version one: magic8, local-digest32, retained-digest32, positive-I63-time8,
configuration-digest32, source-length2, source ASCII bytes (1..256).
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_contract as authority
from serverware import control_plane_custody_records as records


OBSERVATION_MAGIC = b"SWCPO001"
_HEADER_BYTES = 8 + 32 + 32 + 8 + 32 + 2
MAX_OBSERVATION_BYTES = _HEADER_BYTES + records.MAX_SOURCE_REVISION_BYTES
_HEX = frozenset("0123456789abcdef")


class CustodyObservationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Observation:
    """Ordinary first-readback metadata, never an authentication carrier."""

    local_digest: str
    retained_record_digest: str
    retained_at_epoch_ns: int
    configuration_digest: str
    source_revision: str


def _digest(value):
    if (type(value) is not str or len(value) != 71 or not value.startswith("sha256:")
            or any(character not in _HEX for character in value[7:])):
        raise CustodyObservationError("observation digest is not canonical SHA-256")
    return value


def _time(value):
    if type(value) is not int or not 1 <= value <= (1 << 63) - 1:
        raise CustodyObservationError("observation retention time is not a positive I63 integer")
    return value


def _source(value):
    try:
        return records._source_revision(value)
    except records.CustodyRecordError as exc:
        raise CustodyObservationError("observation source is not a bounded ASCII token") from exc


def encode_observation(localdigest, *, retained_record_digest, retained_at_epoch_ns,
        configuration_digest):
    """Own exact scalars and stamp the observation's actual current source."""
    local_digest = _digest(localdigest)
    retained_record_digest = _digest(retained_record_digest)
    retained_at_epoch_ns = _time(retained_at_epoch_ns)
    configuration_digest = _digest(configuration_digest)
    source_revision = authority.SOURCE_REVISION
    source = _source(source_revision)
    observation = Observation(local_digest, retained_record_digest,
        retained_at_epoch_ns, configuration_digest, source_revision)
    encoded = (OBSERVATION_MAGIC + bytes.fromhex(local_digest[7:])
        + bytes.fromhex(retained_record_digest[7:]) + retained_at_epoch_ns.to_bytes(8, "big")
        + bytes.fromhex(configuration_digest[7:]) + len(source).to_bytes(2, "big") + source)
    return observation, encoded


def decode_observation(encoded_bytes):
    """Read the exact immutable first observation without changing its source."""
    if (type(encoded_bytes) is not bytes
            or not _HEADER_BYTES + 1 <= len(encoded_bytes) <= MAX_OBSERVATION_BYTES
            or encoded_bytes[:8] != OBSERVATION_MAGIC):
        raise CustodyObservationError("observation frame is not bounded version-one bytes")
    source_length = int.from_bytes(encoded_bytes[112:114], "big")
    if (not 1 <= source_length <= records.MAX_SOURCE_REVISION_BYTES
            or len(encoded_bytes) != _HEADER_BYTES + source_length):
        raise CustodyObservationError("observation source length or trailing bytes are invalid")
    try:
        source_revision = encoded_bytes[_HEADER_BYTES:].decode("ascii")
    except UnicodeError as exc:
        raise CustodyObservationError("observation source is not ASCII") from exc
    _source(source_revision)
    retained_at = _time(int.from_bytes(encoded_bytes[72:80], "big"))
    return Observation("sha256:" + encoded_bytes[8:40].hex(),
        "sha256:" + encoded_bytes[40:72].hex(), retained_at,
        "sha256:" + encoded_bytes[80:112].hex(), source_revision)
