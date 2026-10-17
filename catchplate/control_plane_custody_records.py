"""Opaque, exact-original prepared records for local caller retention.

This binary codec authenticates nothing. A content digest identifies stored
bytes, not a verifier, historical configuration, successful replay, remote
commit or permission to forward. Decoding retains the original source token
without claiming that the current implementation can replay that source.

Version one is: magic8, discriminator1, source-length2, source ASCII bytes,
six or seven unsigned big-endian length8 values, then the exact originals.
All original lengths and the aggregate are admitted by the real fixed custody
transport validators before any original body is sliced or joined. No JSON,
base64, clock, key, network, filesystem or replacement work allowance is used.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

from catchplate import authority_contract as authority
from catchplate import authority_webauthn_evidence_custody_transport as evidence_transport
from catchplate import authority_webauthn_transition_custody_transport as transition_transport


PREPARED_RECORD_MAGIC = b"SWCPR001"
IDENTITY_DOMAIN = "catchplate.controlPlaneCustodyPreparedRecord/v1"
MAX_SOURCE_REVISION_BYTES = 256
_PREFIX_BYTES = 8 + 1 + 2
_MAX_HEADER_BYTES = _PREFIX_BYTES + MAX_SOURCE_REVISION_BYTES + 7 * 8
MAX_RECORD_BYTES = max(evidence_transport.MAX_REQUEST_BYTES,
    transition_transport.MAX_REQUEST_BYTES) + _MAX_HEADER_BYTES
_PROFILES = (
    ("evidence", "registration", 6),
    ("evidence", "installation", 6),
    ("transition", "webauthn.registration.finalize", 7),
    ("transition", "webauthn.trust.stage", 7),
    ("transition", "webauthn.trust.complete", 7),
)
_REVISION_CHARACTERS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._/-")


class CustodyRecordError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class PreparedRecord:
    """Local byte inventory, not an admission or successful replay carrier."""

    family: str
    selector: str
    source_revision: str
    originals: tuple[bytes, ...]
    digest: str


def _source_revision(value):
    if (type(value) is not str or not 1 <= len(value) <= MAX_SOURCE_REVISION_BYTES
            or any(character not in _REVISION_CHARACTERS for character in value)
            or not value[0].isascii() or not value[0].isalnum()):
        raise CustodyRecordError("prepared source revision is not a bounded ASCII token")
    return value.encode("ascii")


def _profile(family, selector):
    if type(selector) is not str:
        raise CustodyRecordError("prepared operation selector is not exact text")
    for index, profile in enumerate(_PROFILES, 1):
        if profile[:2] == (family, selector):
            return index, profile
    raise CustodyRecordError("prepared operation is not one of the fixed five")


def _lengths(family, lengths):
    try:
        if family == "evidence":
            evidence_transport._validate_lengths(lengths)
        else:
            transition_transport._validate_lengths(lengths)
    except evidence_transport.AuthorityTransportError as exc:
        raise CustodyRecordError("prepared originals exceed their fixed custody bounds") from exc


def _digest(encoded):
    # Length framing keeps this local content identity distinct from every
    # plan, request, record, signature and transport digest domain.
    domain = IDENTITY_DOMAIN.encode("ascii")
    digest = hashlib.sha256()
    digest.update(len(domain).to_bytes(2, "big"))
    digest.update(domain)
    digest.update(len(encoded).to_bytes(8, "big"))
    digest.update(encoded)
    return "sha256:" + digest.hexdigest()


def _encode(family, selector, originals):
    discriminator, profile = _profile(family, selector)
    if (type(originals) is not tuple or len(originals) != profile[2]
            or any(type(raw) is not bytes for raw in originals)):
        raise CustodyRecordError("prepared custody originals are not the exact byte tuple")
    lengths = tuple(len(raw) for raw in originals)
    _lengths(family, lengths)
    source = _source_revision(authority.SOURCE_REVISION)
    header = (PREPARED_RECORD_MAGIC + bytes((discriminator,))
        + len(source).to_bytes(2, "big") + source
        + b"".join(size.to_bytes(8, "big") for size in lengths))
    if len(header) + sum(lengths) > MAX_RECORD_BYTES:
        raise CustodyRecordError("prepared record exceeds its framed byte bound")
    encoded = b"".join((header, *originals))
    return _digest(encoded), encoded


def encode_evidence(purpose, originals):
    """Retain raw6: intent, relay, envelope, inputs, evaluation context, history."""
    return _encode("evidence", purpose, originals)


def encode_transition(operation, originals):
    """Retain raw7: intent, relay, envelope, proof, inputs, context, history."""
    return _encode("transition", operation, originals)


def decode_prepared(encoded_bytes):
    """Decode bounded opaque originals; reject truncation and trailing bytes."""
    if type(encoded_bytes) is not bytes or not _PREFIX_BYTES <= len(encoded_bytes) <= MAX_RECORD_BYTES:
        raise CustodyRecordError("prepared record is not bounded immutable bytes")
    if encoded_bytes[:8] != PREPARED_RECORD_MAGIC:
        raise CustodyRecordError("prepared record version is unsupported")
    discriminator = encoded_bytes[8]
    if not 1 <= discriminator <= len(_PROFILES):
        raise CustodyRecordError("prepared record discriminator is unsupported")
    family, selector, count = _PROFILES[discriminator - 1]
    source_length = int.from_bytes(encoded_bytes[9:11], "big")
    if not 1 <= source_length <= MAX_SOURCE_REVISION_BYTES:
        raise CustodyRecordError("prepared source revision length is invalid")
    vector_offset = _PREFIX_BYTES + source_length
    body_offset = vector_offset + count * 8
    if body_offset > len(encoded_bytes):
        raise CustodyRecordError("prepared record header is truncated")
    # Only the fixed, bounded header is sliced before the complete original
    # length vector and exact total have passed admission.
    lengths = tuple(int.from_bytes(encoded_bytes[offset:offset + 8], "big")
        for offset in range(vector_offset, body_offset, 8))
    _lengths(family, lengths)
    if body_offset + sum(lengths) != len(encoded_bytes):
        raise CustodyRecordError("prepared record bodies are truncated or have trailing bytes")
    try:
        source_revision = encoded_bytes[_PREFIX_BYTES:vector_offset].decode("ascii")
    except UnicodeError as exc:
        raise CustodyRecordError("prepared source revision is not ASCII") from exc
    _source_revision(source_revision)
    originals = []
    offset = body_offset
    for size in lengths:
        originals.append(encoded_bytes[offset:offset + size])
        offset += size
    return PreparedRecord(family, selector, source_revision, tuple(originals), _digest(encoded_bytes))
