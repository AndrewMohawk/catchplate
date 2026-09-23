"""Pinned signatures plus local initialization recomputation, never installation.

Trust and expected facts must come from an independently trusted controller,
not the request, the database under examination, or these signed envelopes.
Signatures authenticate issuer claims, not physical fencing, actual measured
execution, checkpoint currentness, administrative independence or nonce use.
This module has no clock, I/O, signing, persistence or installer operation.
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from serverware import authority_audit_capacity as capacity
from serverware import authority_audit_initialization as initialization
from serverware import authority_audit_initialization_signatures as signatures
from serverware import authority_contract
from serverware import authority_transition_core as core
from serverware.authority_primary_contract import PRIMARY_KEY_COLUMNS
from serverware.authority_radix_mutation import PrimaryRadixMutationError, PrimaryRoot


SCHEMA = "serverware.metadataAuditInitializationEvidence/v1"
MAXIMUM_LIFETIME_NS = 300_000_000_000
VERIFICATION_BOUNDARY = "pinned-signatures-and-local-recomputation"
_DIGEST_BINDINGS = (
    ("database_identity_digest", "databaseIdentityDigest"),
    ("database_generation_digest", "databaseGenerationDigest"),
    ("source_contract_digest", "sourceContractDigest"),
    ("schema_contract_digest", "schemaContractDigest"),
    ("initializer_measurement_digest", "initializerMeasurementDigest"),
    ("operation_id", "operationId"),
    ("nonce_digest", "nonceDigest"),
    ("fence_id", "fenceId"),
    ("writer_inventory_digest", "writerInventoryDigest"),
    ("fence_evidence_digest", "fenceEvidenceDigest"),
    ("initialization_ancestry_digest", "initializationAncestryDigest"),
)
_OTHER_BINDINGS = (
    ("fence_generation", "fenceGeneration"),
    ("checkpoint_sequence", "checkpointSequence"),
    ("checkpoint_predecessor_digest", "checkpointPredecessorDigest"),
    ("initialized_at_epoch_ns", "initializedAtEpochNs"),
)
_COMMON_FIELDS = frozenset({
    "schema", "purpose", "sourceRevision", "preparationProfile",
    "operationManifestDigest", "trustPolicyDigest", "authorityIdentityDigest",
    "authorityMeasurementDigest", "authorityAttestationDigest", "binding",
    "issuedAtEpochNs", "expiresAtEpochNs",
})
_CHECKPOINT_FIELDS = _COMMON_FIELDS | frozenset({
    "beforeRoots", "tableKeyContracts", "initializationDisposition",
})
_AUTHORIZATION_FIELDS = _COMMON_FIELDS | frozenset({
    "checkpointEnvelopeDigest", "preparationDigest", "counterRowDigest", "afterRoots",
})


class AuditInitializationAdmissionError(ValueError):
    pass


def _digest(value: Any) -> None:
    if type(value) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        raise AuditInitializationAdmissionError("audit initialization expected digest is invalid")


def _integer(value: Any, *, minimum: int = 0) -> None:
    if type(value) is not int or not minimum <= value <= capacity.MAX_INTEGER:
        raise AuditInitializationAdmissionError("audit initialization integer is outside its exact bound")


def _canonical(value: Any) -> bytes:
    try:
        return capacity.canonical_audit_json(value)
    except (capacity.AuditCapacityError, ValueError, RecursionError) as exc:
        raise AuditInitializationAdmissionError("audit initialization value is not bounded lossless JSON") from exc


def _copy_pin(pin: signatures.InitializationSignerPin) -> signatures.InitializationSignerPin:
    if type(pin) is not signatures.InitializationSignerPin:
        raise AuditInitializationAdmissionError("audit initialization signer pin has the wrong type")
    try:
        return signatures.InitializationSignerPin(
            pin.role, pin.public_key_der, pin.authority_identity_digest,
            pin.measurement_digest, pin.attestation_receipt_digest,
        )
    except (AttributeError, signatures.AuditInitializationSignatureError) as exc:
        raise AuditInitializationAdmissionError("audit initialization signer pin is invalid") from exc


@dataclass(frozen=True, slots=True)
class AuditInitializationTrust:
    """Explicit integration pins, not evidence of their trusted provisioning."""

    checkpoint_signer: signatures.InitializationSignerPin
    authorization_signer: signatures.InitializationSignerPin
    policy_digest: str
    not_before_epoch_ns: int
    not_after_epoch_ns: int
    maximum_lifetime_ns: int

    def __post_init__(self) -> None:
        checkpoint = _copy_pin(self.checkpoint_signer)
        authorization = _copy_pin(self.authorization_signer)
        if (checkpoint.role != "checkpoint" or authorization.role != "authorization"
                or checkpoint.public_key_der == authorization.public_key_der
                or checkpoint.authority_identity_digest == authorization.authority_identity_digest):
            raise AuditInitializationAdmissionError("audit initialization signer roles are not separated")
        _digest(self.policy_digest)
        _integer(self.not_before_epoch_ns)
        _integer(self.not_after_epoch_ns)
        _integer(self.maximum_lifetime_ns, minimum=1)
        if (self.not_before_epoch_ns >= self.not_after_epoch_ns
                or self.maximum_lifetime_ns > MAXIMUM_LIFETIME_NS):
            raise AuditInitializationAdmissionError("audit initialization trust interval is invalid")


@dataclass(frozen=True, slots=True)
class AuditInitializationExpectation:
    """Controller-owned expected facts; matching them does not prove they occurred."""

    database_identity_digest: str
    database_generation_digest: str
    source_contract_digest: str
    schema_contract_digest: str
    initializer_measurement_digest: str
    operation_id: str
    nonce_digest: str
    fence_id: str
    writer_inventory_digest: str
    fence_evidence_digest: str
    initialization_ancestry_digest: str
    fence_generation: int
    checkpoint_sequence: int
    checkpoint_predecessor_digest: str | None
    initialized_at_epoch_ns: int

    def __post_init__(self) -> None:
        for field, _ in _DIGEST_BINDINGS:
            _digest(getattr(self, field))
        _integer(self.fence_generation, minimum=1)
        _integer(self.checkpoint_sequence, minimum=1)
        _integer(self.initialized_at_epoch_ns)
        if self.checkpoint_sequence == 1:
            if self.checkpoint_predecessor_digest is not None:
                raise AuditInitializationAdmissionError("audit initialization first checkpoint has a predecessor")
        else:
            _digest(self.checkpoint_predecessor_digest)

    def json_projection(self) -> dict[str, Any]:
        return {wire: getattr(self, field) for field, wire in _DIGEST_BINDINGS + _OTHER_BINDINGS}


def _context_snapshots(
    trust: AuditInitializationTrust, expectation: AuditInitializationExpectation,
) -> tuple[AuditInitializationTrust, AuditInitializationExpectation]:
    if type(trust) is not AuditInitializationTrust or type(expectation) is not AuditInitializationExpectation:
        raise AuditInitializationAdmissionError("audit initialization context has the wrong type")
    try:
        accepted_trust = AuditInitializationTrust(
            _copy_pin(trust.checkpoint_signer), _copy_pin(trust.authorization_signer),
            trust.policy_digest, trust.not_before_epoch_ns, trust.not_after_epoch_ns,
            trust.maximum_lifetime_ns,
        )
        accepted_expectation = AuditInitializationExpectation(**{
            field: getattr(expectation, field) for field, _ in _DIGEST_BINDINGS + _OTHER_BINDINGS
        })
    except AttributeError as exc:
        raise AuditInitializationAdmissionError("audit initialization context is incomplete") from exc
    return accepted_trust, accepted_expectation


def _root_snapshot(root: PrimaryRoot, table: str) -> PrimaryRoot:
    if type(root) is not PrimaryRoot:
        raise AuditInitializationAdmissionError("audit initialization root has the wrong type")
    try:
        accepted = PrimaryRoot(root.table, root.root_revision, root.root_digest, root.leaf_count)
    except (AttributeError, PrimaryRadixMutationError) as exc:
        raise AuditInitializationAdmissionError("audit initialization root is invalid") from exc
    if accepted.table != table:
        raise AuditInitializationAdmissionError("audit initialization root has the wrong table")
    return accepted


def _payload(
    envelope: dict[str, Any], fields: frozenset[str], trust: AuditInitializationTrust,
    expectation: AuditInitializationExpectation, now: int,
) -> dict[str, Any]:
    # Purpose, payload schema and authority identity/measurement/attestation pins
    # have already been checked by the signature helper, for this exact role.
    payload = envelope["payload"]
    if (set(payload) != fields
            or payload["sourceRevision"] != authority_contract.SOURCE_REVISION
            or payload["preparationProfile"] != initialization.PROFILE
            or payload["operationManifestDigest"] != authority_contract.OPERATION_MANIFEST_DIGEST
            or payload["trustPolicyDigest"] != trust.policy_digest
            or _canonical(payload["binding"]) != _canonical(expectation.json_projection())):
        raise AuditInitializationAdmissionError("audit initialization payload fields or bindings differ")
    issued, expires = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    _integer(issued)
    _integer(expires)
    if (not trust.not_before_epoch_ns <= issued <= now < expires <= trust.not_after_epoch_ns
            or expires - issued > trust.maximum_lifetime_ns):
        raise AuditInitializationAdmissionError("audit initialization envelope is outside its validity interval")
    return payload


@dataclass(frozen=True, slots=True)
class AuditInitializationEvidence:
    """Immutable evidence serialization, not an unforgeable verification token.

    Direct construction validates representation only, never signatures, proof
    relationships, currentness or permission to install. Consumers requiring
    this calculation must call verify_audit_initialization_evidence themselves.
    """

    preparation: initialization.AuditCapacityInitializationPreparation
    checkpoint_bytes: bytes
    authorization_bytes: bytes
    verified_at_epoch_ns: int

    def __post_init__(self) -> None:
        _integer(self.verified_at_epoch_ns)
        if type(self.preparation) is not initialization.AuditCapacityInitializationPreparation:
            raise AuditInitializationAdmissionError("audit initialization evidence preparation has the wrong type")
        try:
            initialization.AuditCapacityInitializationPreparation(self.preparation.canonical_bytes)
            signatures.envelope_digest(self.checkpoint_bytes, role="checkpoint")
            signatures.envelope_digest(self.authorization_bytes, role="authorization")
            # Representation checks are deliberately not signature admission.
            for raw in (self.checkpoint_bytes, self.authorization_bytes):
                if _canonical(json.loads(raw)) != raw:
                    raise AuditInitializationAdmissionError("audit initialization evidence envelope is not canonical")
        except (initialization.AuditCapacityInitializationError,
                signatures.AuditInitializationSignatureError, AttributeError,
                ValueError, UnicodeError, RecursionError) as exc:
            raise AuditInitializationAdmissionError("audit initialization evidence representation is invalid") from exc
        _canonical(self.json_projection())

    def json_projection(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "checkpoint": json.loads(self.checkpoint_bytes),
            "checkpointEnvelopeDigest": signatures.envelope_digest(self.checkpoint_bytes, role="checkpoint"),
            "authorization": json.loads(self.authorization_bytes),
            "authorizationEnvelopeDigest": signatures.envelope_digest(self.authorization_bytes, role="authorization"),
            "preparation": self.preparation.json_projection(),
            "preparationDigest": self.preparation.digest,
            "verifiedAtEpochNs": self.verified_at_epoch_ns,
            "verificationBoundary": VERIFICATION_BOUNDARY,
            "installationPermitted": False,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical(self.json_projection())

    @property
    def digest(self) -> str:
        return core.framed_digest(SCHEMA, self.canonical_bytes)


def verify_audit_initialization_evidence(
    checkpoint_bytes: bytes, authorization_bytes: bytes, *,
    trust: AuditInitializationTrust, expectation: AuditInitializationExpectation,
    now_epoch_ns: int, outbox_root: PrimaryRoot,
    outbox_records: Iterable[dict[str, Any]], aggregate_root: PrimaryRoot,
    aggregate_absence: dict[str, Any],
) -> AuditInitializationEvidence:
    """Verify pinned issuer claims and recompute the actual proof stream.

    Time is checked only at the supplied instant. The offline job owner must
    enforce deadlines/resource bounds and recheck live authority at actual
    commit. Repeating these inputs is allowed: no nonce or ancestry is consumed.
    Valid signatures do not turn a false checkpoint claim into physical truth.
    """
    accepted_trust, accepted_expectation = _context_snapshots(trust, expectation)
    _integer(now_epoch_ns)
    outbox_before = _root_snapshot(outbox_root, capacity.OUTBOX_TABLE)
    aggregate_before = _root_snapshot(aggregate_root, capacity.AGGREGATE_TABLE)
    try:
        checkpoint_envelope = signatures.verify_initialization_envelope(
            checkpoint_bytes, role="checkpoint", pin=accepted_trust.checkpoint_signer,
        )
        authorization_envelope = signatures.verify_initialization_envelope(
            authorization_bytes, role="authorization", pin=accepted_trust.authorization_signer,
        )
    except signatures.AuditInitializationSignatureError as exc:
        raise AuditInitializationAdmissionError("audit initialization signed evidence is invalid") from exc
    checkpoint = _payload(checkpoint_envelope, _CHECKPOINT_FIELDS,
        accepted_trust, accepted_expectation, now_epoch_ns)
    authorization = _payload(authorization_envelope, _AUTHORIZATION_FIELDS,
        accepted_trust, accepted_expectation, now_epoch_ns)
    before_roots = [root.json_projection() for root in sorted(
        (outbox_before, aggregate_before), key=lambda root: root.table)]
    table_keys = {root.table: list(PRIMARY_KEY_COLUMNS[root.table])
                  for root in (outbox_before, aggregate_before)}
    if (checkpoint["initializationDisposition"] != "initial-install-only"
            or _canonical(checkpoint["beforeRoots"]) != _canonical(before_roots)
            or _canonical(checkpoint["tableKeyContracts"]) != _canonical(table_keys)
            or authorization["checkpointEnvelopeDigest"] != signatures.envelope_digest(
                checkpoint_bytes, role="checkpoint")
            or authorization["issuedAtEpochNs"] < checkpoint["issuedAtEpochNs"]
            or authorization["expiresAtEpochNs"] > checkpoint["expiresAtEpochNs"]):
        raise AuditInitializationAdmissionError("audit initialization checkpoint or authorization linkage differs")
    for field in ("preparationDigest", "counterRowDigest"):
        _digest(authorization[field])
    # The complete inventory and absence proof are always verified here. No
    # caller-constructed observation/preparation/Verified dataclass is accepted.
    try:
        preparation = initialization.prepare_audit_capacity_initialization(
            outbox_root=outbox_before, outbox_records=outbox_records,
            aggregate_root=aggregate_before, aggregate_absence=aggregate_absence,
            initialized_at_epoch_ns=accepted_expectation.initialized_at_epoch_ns,
        )
    except initialization.AuditCapacityInitializationError as exc:
        raise AuditInitializationAdmissionError("audit initialization preparation failed") from exc
    computed = preparation.json_projection()
    if (authorization["preparationDigest"] != preparation.digest
            or authorization["counterRowDigest"] != computed["counterRowDigest"]
            or _canonical(authorization["afterRoots"]) != _canonical(computed["afterRoots"])):
        raise AuditInitializationAdmissionError("audit initialization authorization differs from recomputation")
    return AuditInitializationEvidence(preparation, checkpoint_bytes, authorization_bytes, now_epoch_ns)
