"""Token-free consume-planning claim and opaque original response retention.

One separate logical claim has eighteen possible physical files, subject to the
unchanged global physical/quota ceilings. These records
contain public/ciphertext originals and one-use SQL/intent/proof claims, never the old
token or prepare request. Shape and content identity admit no permission,
plan, grant, committed SQL result or authenticated completion.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

from catchplate import authority_contract as authority
from catchplate import authority_oidc_session_activation_delivery_completion_transport as completion
from catchplate import authority_oidc_session_activation_delivery_execution_authorization as caller
from catchplate import authority_oidc_session_activation_delivery_execution_authorizer_transport as grant
from catchplate import authority_oidc_session_activation_delivery_planner_transport as transport
from catchplate import authority_oidc_session_activation_delivery_reservation_transport as reserve
from catchplate import authority_oidc_session_activation_delivery_sql_transport as sql
from catchplate import authority_oidc_session_activation_consume_input_transport as inputs
from catchplate import authority_oidc_session_activation_release_hints as hints
from catchplate import authority_oidc_session_activation_release_proof_transport as proof_response
from catchplate import control_plane_custody_records as records
from catchplate import control_plane_oidc_session_activation_dispatch_attempt as activation
from catchplate import oidc_session_activation_release_intent as intent
from catchplate import oidc_session_activation_release_client_authorization as release_client
from catchplate import oidc_session_activation_release_proof_bootstrap as proof_setup


MAGIC = b"SWCOC001"
# Appended indices preserve every earlier domain and encoded original.
KINDS = ("claimed", "prepared", "exported", "authorized", "grant", "reserved",
    "sql-claimed", "sql-outcome", "completion-outcome", "completion-hints",
    "release-intent-claimed", "release-intent", "release-proof-claimed", "release-proof", "release-grants", "inputs",
    "release-proof-setup", "release-grants-claimed")
_COUNTS = (0, 6, 7, 1, 1, 3, 0, 4, 4, 2, 0, 1, 0, 4, 2, 2, 1, 0)
SLOT_DOMAIN = "catchplate.controlPlaneOidcSessionActivationConsumeSlot/v1"
_DOMAINS = tuple("catchplate.controlPlaneOidcSessionActivationConsumeRecord/" + kind + "/v1"
    for kind in KINDS)
_PREFIX_BYTES = 11
_MAX_HEADER_BYTES = _PREFIX_BYTES + records.MAX_SOURCE_REVISION_BYTES + 64
_BODY_MAXIMA = (0, transport.MAX_RESPONSE_BYTES, transport.MAX_EXPORT_RESPONSE_BYTES,
    caller.MAX_AUTHORIZATION_BYTES, grant.MAX_RESPONSE_BYTES, reserve.MAX_RESPONSE_BYTES,
    0, sql.MAX_RESPONSE_BYTES, completion.MAX_RESPONSE_BYTES, sum(hints.LIMITS), 0,
    intent.MAX_BYTES, 0, proof_response.MAX_RESPONSE_BYTES,
    release_client.MAX_BYTES + release_client.MAX_SERVER_BOOTSTRAP_BYTES, inputs.MAX_RESPONSE_BYTES,
    proof_setup.MAX_BYTES, 0)
_MAXIMA = tuple(_MAX_HEADER_BYTES + count * 8 + maximum
    for count, maximum in zip(_COUNTS, _BODY_MAXIMA))
(MAX_CLAIM_BYTES, MAX_PREPARED_BYTES, MAX_EXPORTED_BYTES, MAX_AUTHORIZED_BYTES,
    MAX_GRANT_BYTES, MAX_RESERVATION_BYTES, MAX_SQL_CLAIM_BYTES, MAX_SQL_OUTCOME_BYTES,
    MAX_COMPLETION_OUTCOME_BYTES, MAX_COMPLETION_HINTS_BYTES,
    MAX_RELEASE_INTENT_CLAIM_BYTES, MAX_RELEASE_INTENT_BYTES,
    MAX_RELEASE_PROOF_CLAIM_BYTES, MAX_RELEASE_PROOF_BYTES, MAX_RELEASE_GRANTS_BYTES,
    MAX_INPUTS_BYTES, MAX_RELEASE_PROOF_SETUP_BYTES, MAX_RELEASE_GRANTS_CLAIM_BYTES) = _MAXIMA
MAX_RECORD_BYTES = max(_MAXIMA)
MAX_CLAIM_IO_BYTES = activation.MAX_RECORD_BYTES + 3 * MAX_CLAIM_BYTES
MAX_LOAD_IO_BYTES = activation.MAX_RECORD_BYTES + sum(_MAXIMA)
COMPLETION_RECOVERY_METADATA_BYTES = 16 * 1024
COMPLETION_RECOVERY_RELEASE_KINDS = ("release-intent-claimed", "release-intent",
    "release-proof-claimed", "release-proof-setup", "release-proof")
COMPLETION_RECOVERY_GRANT_KINDS = ("release-grants-claimed", "release-grants")
CustodyRecordError = records.CustodyRecordError


@dataclass(frozen=True, slots=True, repr=False)
class ConsumeRecord:
    """Ordinary metadata/originals; neither admitted authority nor a retry token."""

    source_revision: str
    finalization_digest: str
    activation_authorization_digest: str
    slot_digest: str
    kind: str
    originals: tuple[bytes, ...]
    digest: str


@dataclass(frozen=True, slots=True, repr=False)
class ConsumeRecords:
    claim: ConsumeRecord
    prepared: ConsumeRecord | None
    exported: ConsumeRecord | None
    authorized: ConsumeRecord | None = None
    grant: ConsumeRecord | None = None
    reservation: ConsumeRecord | None = None
    sql_attempt: ConsumeRecord | None = None
    sql_outcome: ConsumeRecord | None = None
    completion_outcome: ConsumeRecord | None = None
    completion_hints: ConsumeRecord | None = None
    release_intent_attempt: ConsumeRecord | None = None
    release_intent: ConsumeRecord | None = None
    release_proof_attempt: ConsumeRecord | None = None
    release_proof: ConsumeRecord | None = None
    release_grants: ConsumeRecord | None = None
    inputs: ConsumeRecord | None = None
    release_proof_setup: ConsumeRecord | None = None
    release_grants_attempt: ConsumeRecord | None = None


def _framed_digest(domain, bodies):
    encoded_domain = domain.encode("ascii")
    digest = hashlib.sha256()
    digest.update(len(encoded_domain).to_bytes(2, "big"))
    digest.update(encoded_domain)
    for original in bodies:
        digest.update(len(original).to_bytes(8, "big"))
        digest.update(original)
    return "sha256:" + digest.hexdigest()


def _slot_digest(finalization_digest, activation_authorization_digest):
    # Own both exact immutable scalars before hashing either one.
    bodies = tuple(activation._digest_bytes(value)
        for value in (finalization_digest, activation_authorization_digest))
    return _framed_digest(SLOT_DOMAIN, bodies)


def _profile(kind):
    if type(kind) is not str or kind not in KINDS:
        raise CustodyRecordError("consume retention kind is not source fixed")
    return KINDS.index(kind)


def _maximum(kind):
    return _MAXIMA[_profile(kind)]


def _lengths(profile, lengths):
    if (type(lengths) is not tuple or len(lengths) != _COUNTS[profile]
            or any(type(size) is not int or size < 0 for size in lengths)):
        raise CustodyRecordError("consume retention length inventory differs")
    try:
        if profile in (1, 2):
            transport._response_lengths(lengths, export=profile == 2)
        elif profile == 3:
            if not 2 <= lengths[0] <= caller.MAX_AUTHORIZATION_BYTES:
                raise CustodyRecordError("consume caller original exceeds its fixed byte bound")
        elif profile == 4:
            grant._lengths(lengths, response=True)
        elif profile == 5:
            reserve._lengths(lengths, response=True)
        elif profile == 7:
            sql._response_lengths(lengths)
        elif profile == 8:
            completion._response_lengths(lengths)
        elif profile == 9:
            if any(size > maximum for size, maximum in zip(lengths, hints.LIMITS)):
                raise CustodyRecordError("unsigned completion hint exceeds its fixed byte bound")
        elif profile == 11:
            if not 2 <= lengths[0] <= intent.MAX_BYTES:
                raise CustodyRecordError("release intent original exceeds its fixed byte bound")
        elif profile == 13:
            if any(size > maximum for size, maximum in zip(lengths, proof_response.RESPONSE_LIMITS)):
                raise CustodyRecordError("release proof response exceeds its fixed byte bounds")
        elif profile == 14:
            if (lengths[0] > release_client.MAX_BYTES
                    or lengths[1] > release_client.MAX_SERVER_BOOTSTRAP_BYTES):
                raise CustodyRecordError("release grant originals exceed their fixed byte bounds")
        elif profile == 15:
            inputs._response_lengths(lengths)
        elif profile == 16:
            if lengths[0] > proof_setup.MAX_BYTES:
                raise CustodyRecordError("release proof setup original exceeds its fixed byte bound")
        if sum(lengths) > _BODY_MAXIMA[profile]:
            raise CustodyRecordError("consume stage exceeds its fixed aggregate bound")
    except transport.AuthorityTransportError as exc:
        raise CustodyRecordError("consume response exceeds its fixed byte bounds") from exc


def _originals(profile, originals):
    if (type(originals) is not tuple or len(originals) != _COUNTS[profile]
            or any(type(raw) is not bytes for raw in originals)):
        raise CustodyRecordError("consume retention requires exact immutable response originals")
    _lengths(profile, tuple(len(raw) for raw in originals))
    try:
        if profile in (1, 2):
            transport._originals(originals, response=True, export=profile == 2)
        elif profile == 4:
            grant._originals(originals, response=True)
        elif profile == 5:
            reserve._originals(originals, response=True)
        elif profile == 7:
            sql._originals(originals, response=True)
        elif profile == 8:
            completion._originals(originals, response=True)
        if profile == 1 and originals[0] not in (b"prepared", b"uncertain"):
            raise CustodyRecordError("consume preparation cannot retain a verify-retained response")
    except transport.AuthorityTransportError as exc:
        raise CustodyRecordError("consume response carrier differs") from exc
    return originals


def _append_io_bytes(kind, originals):
    """Precharge fixed claim reads and bounded publication/readback, no I/O/hash."""
    profile = _profile(kind)
    if profile == 0:
        raise CustodyRecordError("consume claim uses its fixed MAX_CLAIM_IO_BYTES")
    held = _originals(profile, originals)
    size = _MAX_HEADER_BYTES + 8 * len(held) + sum(len(raw) for raw in held)
    return activation.MAX_RECORD_BYTES + MAX_CLAIM_BYTES + 3 * size


def _completion_recovery_publication_bytes(kind, originals):
    """Publication/readback reservation only; selected history is additional."""
    if kind not in COMPLETION_RECOVERY_RELEASE_KINDS + COMPLETION_RECOVERY_GRANT_KINDS:
        raise CustodyRecordError("completion recovery release kind is not source fixed")
    held = _originals(_profile(kind), originals)
    return 3 * (_MAX_HEADER_BYTES + 8 * len(held) + sum(len(raw) for raw in held))


def encode(kind, *, finalization_digest, activation_authorization_digest,
        originals, source_revision):
    profile = _profile(kind)
    held = _originals(profile, originals)
    identifiers = tuple(activation._digest_bytes(value)
        for value in (finalization_digest, activation_authorization_digest))
    source = records._source_revision(source_revision)
    if source_revision != authority.SOURCE_REVISION:
        raise CustodyRecordError("consume publication requires the current source cohort")
    encoded = b"".join((MAGIC, bytes((profile,)), len(source).to_bytes(2, "big"), source,
        *identifiers, b"".join(len(raw).to_bytes(8, "big") for raw in held), *held))
    if len(encoded) > _MAXIMA[profile]:
        raise CustodyRecordError("consume response exceeds its fixed framed bound")
    slot = _framed_digest(SLOT_DOMAIN, identifiers)
    return ConsumeRecord(source_revision, finalization_digest, activation_authorization_digest,
        slot, kind, held, _framed_digest(_DOMAINS[profile], (encoded,))), encoded


def decode(original):
    """Bound before slicing; preserve historical originals without live authority."""
    if (type(original) is not bytes
            or not _PREFIX_BYTES + 1 + 64 <= len(original) <= MAX_RECORD_BYTES
            or original[:8] != MAGIC or original[8] >= len(KINDS)):
        raise CustodyRecordError("consume record is not bounded supported original bytes")
    profile = original[8]
    if len(original) > _MAXIMA[profile]:
        raise CustodyRecordError("consume record exceeds its fixed profile bound")
    source_length = int.from_bytes(original[9:11], "big")
    if not 1 <= source_length <= records.MAX_SOURCE_REVISION_BYTES:
        raise CustodyRecordError("consume source length differs")
    digest_offset = _PREFIX_BYTES + source_length
    vector_offset = digest_offset + 64
    body_offset = vector_offset + 8 * _COUNTS[profile]
    if body_offset > len(original):
        raise CustodyRecordError("consume record header is truncated")
    lengths = tuple(int.from_bytes(original[offset:offset + 8], "big")
        for offset in range(vector_offset, body_offset, 8))
    _lengths(profile, lengths)
    if body_offset + sum(lengths) != len(original):
        raise CustodyRecordError("consume record is truncated or has trailing bytes")
    try:
        source_revision = original[_PREFIX_BYTES:digest_offset].decode("ascii")
    except UnicodeError as exc:
        raise CustodyRecordError("consume record source is not ASCII") from exc
    records._source_revision(source_revision)
    identifiers = (original[digest_offset:digest_offset + 32], original[digest_offset + 32:vector_offset])
    finalization_digest, authorization_digest = ("sha256:" + raw.hex() for raw in identifiers)
    bodies, offset = [], body_offset
    for size in lengths:
        bodies.append(original[offset:offset + size])
        offset += size
    held = _originals(profile, tuple(bodies))
    return ConsumeRecord(source_revision, finalization_digest, authorization_digest,
        _framed_digest(SLOT_DOMAIN, identifiers), KINDS[profile], held,
        _framed_digest(_DOMAINS[profile], (original,)))
