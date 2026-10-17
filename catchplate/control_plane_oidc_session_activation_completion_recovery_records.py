"""Token-free completion-recovery attempts and separate opaque responses.

One target/phase slot can be attempted once, including across restart or a fresh
actor. Retention never authenticates completion and never overwrites an original
activation/consume outcome. No request, cookie, assertion or token is stored.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import authority_contract as authority
from catchplate import control_plane_custody_records as records
from catchplate import control_plane_oidc_session_activation_records as activation
from catchplate import control_plane_oidc_session_activation_consume_records as consume


MAGIC = b"SWCCRC01"
PHASES = ("activation", "consume")
KINDS = ("claimed", "response")
FILE_KINDS = ("activation-completion-recovery-claimed", "activation-completion-recovery-response")
SLOT_DOMAIN = "catchplate.controlPlaneOidcSessionActivationCompletionRecoverySlot/v1"
_DOMAINS = tuple("catchplate.controlPlaneOidcSessionActivationCompletionRecoveryRecord/" + kind + "/v1"
    for kind in KINDS)
_PREFIX_BYTES = 13
_DIGEST_BYTES = 5 * 32
_MAX_HEADER_BYTES = _PREFIX_BYTES + records.MAX_SOURCE_REVISION_BYTES + _DIGEST_BYTES
RESPONSE_LIMITS = (activation.completion.RESPONSE_LIMITS,
    consume.completion.RESPONSE_LIMITS + consume.hints.LIMITS)
MAX_CLAIM_BYTES = _MAX_HEADER_BYTES
MAX_RESPONSE_BYTES = tuple(_MAX_HEADER_BYTES + 8 * len(limits) + sum(limits)
    for limits in RESPONSE_LIMITS)
MAX_RECORD_BYTES = max(MAX_RESPONSE_BYTES)
MAX_CLAIM_IO_BYTES = 3 * MAX_CLAIM_BYTES
METADATA_RESERVATION_BYTES = 16 * 1024
MAX_ORIGINAL_BYTES = 64 * 1024**2
CustodyRecordError = records.CustodyRecordError


@dataclass(frozen=True, slots=True, repr=False)
class CompletionRecoveryRecord:
    source_revision: str
    finalization_digest: str
    phase: str
    authorization_digest: str
    packet_digest: str
    recovery_configuration_digest: str
    predecessor_completion_digest: str | None
    slot_digest: str
    kind: str
    originals: tuple[bytes, ...]
    digest: str


@dataclass(frozen=True, slots=True, repr=False)
class CompletionRecoveryRecords:
    claim: CompletionRecoveryRecord
    response: CompletionRecoveryRecord | None


def _phase(phase):
    if type(phase) is not str or phase not in PHASES:
        raise CustodyRecordError("completion recovery phase is not source fixed")
    return PHASES.index(phase)


def _slot_digest(finalization_digest, phase):
    _phase(phase)
    return consume._framed_digest(SLOT_DOMAIN,
        (activation.attempts._digest_bytes(finalization_digest), phase.encode("ascii")))


def _maximum(phase, kind):
    profile = _phase(phase)
    if type(kind) is not str or kind not in KINDS:
        raise CustodyRecordError("completion recovery record kind is not source fixed")
    return MAX_CLAIM_BYTES if kind == "claimed" else MAX_RESPONSE_BYTES[profile]


def _originals(phase, originals):
    limits = RESPONSE_LIMITS[_phase(phase)]
    if (type(originals) is not tuple or len(originals) != len(limits)
            or any(type(raw) is not bytes or len(raw) > maximum
                for raw, maximum in zip(originals, limits))):
        raise CustodyRecordError("completion recovery response requires exact opaque bounded originals")
    return originals


def _append_io_bytes(phase, originals):
    held = _originals(phase, originals)
    return MAX_CLAIM_BYTES + 3 * (_MAX_HEADER_BYTES + 8 * len(held) + sum(map(len, held)))


def encode(kind, *, finalization_digest, phase, authorization_digest, packet_digest,
        recovery_configuration_digest, predecessor_completion_digest, originals, source_revision):
    maximum = _maximum(phase, kind)
    profile = _phase(phase)
    if kind == "claimed":
        if type(originals) is not tuple or originals:
            raise CustodyRecordError("completion recovery attempt contains no body")
        held = ()
    else:
        held = _originals(phase, originals)
    scalars = finalization_digest, authorization_digest, packet_digest, recovery_configuration_digest
    digests = tuple(activation.attempts._digest_bytes(value) for value in scalars)
    prior = (bytes(32) if predecessor_completion_digest is None
        else activation.attempts._digest_bytes(predecessor_completion_digest))
    source = records._source_revision(source_revision)
    if source_revision != authority.SOURCE_REVISION:
        raise CustodyRecordError("completion recovery publication requires the current source cohort")
    encoded = b"".join((MAGIC, bytes((KINDS.index(kind), profile,
        int(predecessor_completion_digest is not None))), len(source).to_bytes(2, "big"),
        source, *digests, prior, *(len(raw).to_bytes(8, "big") for raw in held), *held))
    if len(encoded) > maximum:
        raise CustodyRecordError("completion recovery record exceeds its fixed bound")
    return CompletionRecoveryRecord(source_revision, finalization_digest, phase, *scalars[1:],
        predecessor_completion_digest, _slot_digest(finalization_digest, phase), kind, held,
        consume._framed_digest(_DOMAINS[KINDS.index(kind)], (encoded,))), encoded


def decode(original):
    """Check framing and original identity only; never admit reconciliation."""
    if (type(original) is not bytes
            or not _PREFIX_BYTES + 1 + _DIGEST_BYTES <= len(original) <= MAX_RECORD_BYTES
            or original[:8] != MAGIC or original[8] not in (0, 1)
            or original[9] not in (0, 1) or original[10] not in (0, 1)):
        raise CustodyRecordError("completion recovery record is not bounded supported bytes")
    kind, phase = KINDS[original[8]], PHASES[original[9]]
    source_size = int.from_bytes(original[11:13], "big")
    if not 1 <= source_size <= records.MAX_SOURCE_REVISION_BYTES:
        raise CustodyRecordError("completion recovery source length differs")
    offset = _PREFIX_BYTES + source_size
    vector = offset + _DIGEST_BYTES
    count = 0 if kind == "claimed" else len(RESPONSE_LIMITS[original[9]])
    body = vector + 8 * count
    if body > len(original) or len(original) > _maximum(phase, kind):
        raise CustodyRecordError("completion recovery record header or maximum differs")
    lengths = tuple(int.from_bytes(original[index:index + 8], "big")
        for index in range(vector, body, 8))
    if (any(size > maximum for size, maximum in zip(lengths, RESPONSE_LIMITS[original[9]]))
            or body + sum(lengths) != len(original)):
        raise CustodyRecordError("completion recovery record is oversized, truncated or has trailing bytes")
    try:
        source = original[_PREFIX_BYTES:offset].decode("ascii")
    except UnicodeError as exc:
        raise CustodyRecordError("completion recovery source is not ASCII") from exc
    records._source_revision(source)
    identifiers = tuple(original[index:index + 32] for index in range(offset, vector, 32))
    scalars = tuple("sha256:" + raw.hex() for raw in identifiers[:4])
    if not original[10] and identifiers[4] != bytes(32):
        raise CustodyRecordError("completion recovery absent predecessor encoding differs")
    prior = "sha256:" + identifiers[4].hex() if original[10] else None
    bodies, cursor = [], body
    for size in lengths:
        bodies.append(original[cursor:cursor + size])
        cursor += size
    held = _originals(phase, tuple(bodies)) if count else ()
    return CompletionRecoveryRecord(source, scalars[0], phase, *scalars[1:], prior,
        _slot_digest(scalars[0], phase), kind, held,
        consume._framed_digest(_DOMAINS[original[8]], (original,)))
