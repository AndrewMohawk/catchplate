"""Final local publication linking finalization to an existing evidence pair.

Magic8, source-length u16, bounded source ASCII, then finalization/evidence/
signer raw SHA256 values and exact EOF. No originals are duplicated. The owner
must reread the evidence association and all three records, check their fixed
families/source, and publish this marker last. A link proves no signatures,
permission, one-use consumption, currentness or credential finalization.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_contract as authority
from serverware import control_plane_custody_records as records
from serverware import control_plane_registration_associations as evidence_associations


MAGIC = b"SWCPM001"
MAX_ASSOCIATION_BYTES = 362
_PREFIX_BYTES = 10
_DIGEST_BYTES = 32
CustodyRecordError = records.CustodyRecordError


@dataclass(frozen=True, slots=True)
class RegistrationFinalizationAssociation:
    """Opaque local relationship, not evidence that the originals were replayed."""

    source_revision: str
    finalization_digest: str
    evidence_digest: str
    signer_digest: str


def encode(finalization_digest, evidence_digest, signer_digest):
    held = (finalization_digest, evidence_digest, signer_digest)
    digests = tuple(evidence_associations._digest_bytes(value) for value in held)
    if len(set(held)) != 3:
        raise CustodyRecordError("finalization association requires three distinct local identities")
    revision = authority.SOURCE_REVISION
    source = records._source_revision(revision)
    encoded = MAGIC + len(source).to_bytes(2, "big") + source + b"".join(digests)
    if len(encoded) > MAX_ASSOCIATION_BYTES:
        raise CustodyRecordError("finalization association exceeds its fixed byte bound")
    return RegistrationFinalizationAssociation(revision, *held), encoded


def decode(encoded):
    if (type(encoded) is not bytes
            or not _PREFIX_BYTES + 1 + 3 * _DIGEST_BYTES <= len(encoded) <= MAX_ASSOCIATION_BYTES):
        raise CustodyRecordError("finalization association is not bounded immutable bytes")
    if encoded[:8] != MAGIC:
        raise CustodyRecordError("finalization association magic is unsupported")
    source_length = int.from_bytes(encoded[8:10], "big")
    if not 1 <= source_length <= records.MAX_SOURCE_REVISION_BYTES:
        raise CustodyRecordError("finalization association source length is invalid")
    digest_offset = _PREFIX_BYTES + source_length
    if len(encoded) != digest_offset + 3 * _DIGEST_BYTES:
        raise CustodyRecordError("finalization association is truncated or has trailing bytes")
    try:
        revision = encoded[_PREFIX_BYTES:digest_offset].decode("ascii")
    except UnicodeError as exc:
        raise CustodyRecordError("finalization association source is not ASCII") from exc
    records._source_revision(revision)
    digests = tuple("sha256:" + encoded[offset:offset + _DIGEST_BYTES].hex()
        for offset in range(digest_offset, len(encoded), _DIGEST_BYTES))
    if len(set(digests)) != 3:
        raise CustodyRecordError("finalization association local identities overlap")
    return RegistrationFinalizationAssociation(revision, *digests)
