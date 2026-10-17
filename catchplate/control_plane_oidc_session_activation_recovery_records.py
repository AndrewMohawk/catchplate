"""Token-free recovery acquisition claims and exact opaque grant retention.

A fresh independently authorized issuer policy has a separate local slot. No
claim, including an identical recovered claim, grants permission to retry. This
codec stores no request, token, cookie or assertion and authenticates no grant.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import authority_contract as authority
from catchplate import control_plane_custody_records as records
from catchplate import control_plane_oidc_session_activation_consume_records as consume
from catchplate import authority_oidc_session_activation_release_recovery_grant_transport as transport


MAGIC = b"SWCOR001"
KINDS = ("claimed", "grants")
FILE_KINDS = ("activation-recovery-grant-claimed", "activation-recovery-grants")
SLOT_DOMAIN = "catchplate.controlPlaneOidcSessionActivationRecoveryGrantSlot/v1"
_DOMAINS = tuple("catchplate.controlPlaneOidcSessionActivationRecoveryGrantRecord/" + kind + "/v1"
    for kind in KINDS)
_PREFIX_BYTES = 11
_DIGEST_BYTES = 5 * 32
_MAX_HEADER_BYTES = _PREFIX_BYTES + records.MAX_SOURCE_REVISION_BYTES + _DIGEST_BYTES
RESPONSE_LIMITS = transport.RESPONSE_LIMITS
MAX_CLAIM_BYTES = _MAX_HEADER_BYTES
MAX_GRANTS_BYTES = _MAX_HEADER_BYTES + 24 + sum(RESPONSE_LIMITS)
MAX_RECORD_BYTES = MAX_GRANTS_BYTES
MAX_CLAIM_IO_BYTES = (consume.activation.MAX_RECORD_BYTES + consume.MAX_CLAIM_BYTES
    + consume.MAX_RELEASE_INTENT_BYTES + 3 * MAX_CLAIM_BYTES)
CustodyRecordError = records.CustodyRecordError


@dataclass(frozen=True, slots=True, repr=False)
class RecoveryGrantRecord:
    """Ordinary local metadata, never permission or a durable-store witness."""

    source_revision: str
    finalization_digest: str
    activation_authorization_digest: str
    release_intent_digest: str
    issuer_policy_digest: str
    intent_record_digest: str
    slot_digest: str
    kind: str
    originals: tuple[bytes, ...]
    digest: str


@dataclass(frozen=True, slots=True, repr=False)
class RecoveryGrantRecords:
    claim: RecoveryGrantRecord
    grants: RecoveryGrantRecord | None


def _slot_digest(finalization_digest, activation_authorization_digest,
        release_intent_digest, issuer_policy_digest):
    values = tuple(consume.activation._digest_bytes(value) for value in (
        finalization_digest, activation_authorization_digest, release_intent_digest, issuer_policy_digest))
    return consume._framed_digest(SLOT_DOMAIN, values)


def _maximum(kind):
    if type(kind) is not str or kind not in KINDS:
        raise CustodyRecordError("recovery retention kind is not source fixed")
    return MAX_CLAIM_BYTES if kind == "claimed" else MAX_GRANTS_BYTES


def _originals(originals):
    if (type(originals) is not tuple or len(originals) != 3
            or any(type(raw) is not bytes or len(raw) > maximum
                for raw, maximum in zip(originals, RESPONSE_LIMITS))):
        raise CustodyRecordError("recovery grant retention requires bounded opaque original raw3")
    return originals


def _append_io_bytes(originals):
    held = _originals(originals)
    return MAX_CLAIM_BYTES + 3 * (_MAX_HEADER_BYTES + 24 + sum(map(len, held)))


def _intent_identity(original):
    """Hash-only original identity using the actual intent's framed domain."""
    intent = consume.intent
    if type(original) is not bytes or not 2 <= len(original) <= intent.MAX_BYTES:
        raise CustodyRecordError("recovery intent identity requires the retained bounded original")
    return intent.plan.core.framed_digest(intent.IDENTITY_DOMAIN, original)


def encode(kind, *, finalization_digest, activation_authorization_digest,
        release_intent_digest, issuer_policy_digest, intent_record_digest,
        originals, source_revision):
    maximum = _maximum(kind)
    if kind == "claimed":
        if type(originals) is not tuple or originals:
            raise CustodyRecordError("recovery acquisition claim contains no original body")
        held = ()
    else:
        held = _originals(originals)
    scalars = (finalization_digest, activation_authorization_digest,
        release_intent_digest, issuer_policy_digest, intent_record_digest)
    digests = tuple(consume.activation._digest_bytes(value) for value in scalars)
    source = records._source_revision(source_revision)
    if source_revision != authority.SOURCE_REVISION:
        raise CustodyRecordError("recovery publication requires the current source cohort")
    profile = KINDS.index(kind)
    encoded = b"".join((MAGIC, bytes((profile,)), len(source).to_bytes(2, "big"), source,
        *digests, *(len(raw).to_bytes(8, "big") for raw in held), *held))
    if len(encoded) > maximum:
        raise CustodyRecordError("recovery retention exceeds its framed byte bound")
    return RecoveryGrantRecord(source_revision, *scalars,
        consume._framed_digest(SLOT_DOMAIN, digests[:4]), kind, held,
        consume._framed_digest(_DOMAINS[profile], (encoded,))), encoded


def decode(original):
    """Check exact framing and content identity, not signatures or authority."""
    if (type(original) is not bytes
            or not _PREFIX_BYTES + 1 + _DIGEST_BYTES <= len(original) <= MAX_RECORD_BYTES
            or original[:8] != MAGIC or original[8] not in (0, 1)):
        raise CustodyRecordError("recovery record is not bounded supported original bytes")
    profile = original[8]
    source_size = int.from_bytes(original[9:11], "big")
    if not 1 <= source_size <= records.MAX_SOURCE_REVISION_BYTES:
        raise CustodyRecordError("recovery source length differs")
    offset = _PREFIX_BYTES + source_size
    vector = offset + _DIGEST_BYTES
    body = vector + (24 if profile else 0)
    if body > len(original) or len(original) > _maximum(KINDS[profile]):
        raise CustodyRecordError("recovery record header or bound differs")
    lengths = tuple(int.from_bytes(original[index:index + 8], "big")
        for index in range(vector, body, 8))
    if (any(size > maximum for size, maximum in zip(lengths, RESPONSE_LIMITS))
            or body + sum(lengths) != len(original)):
        raise CustodyRecordError("recovery record is oversized, truncated or has trailing bytes")
    try:
        source = original[_PREFIX_BYTES:offset].decode("ascii")
    except UnicodeError as exc:
        raise CustodyRecordError("recovery source revision is not ASCII") from exc
    records._source_revision(source)
    identifiers = tuple(original[index:index + 32] for index in range(offset, vector, 32))
    scalars = tuple("sha256:" + raw.hex() for raw in identifiers)
    originals, cursor = [], body
    for size in lengths:
        originals.append(original[cursor:cursor + size])
        cursor += size
    held = _originals(tuple(originals)) if profile else ()
    return RecoveryGrantRecord(source, *scalars,
        consume._framed_digest(SLOT_DOMAIN, identifiers[:4]), KINDS[profile], held,
        consume._framed_digest(_DOMAINS[profile], (original,)))
