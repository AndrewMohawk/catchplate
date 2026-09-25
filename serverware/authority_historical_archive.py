"""Startup-only root admission of retained-plan verification history.

The current independently admitted root authorizes exact historical trust
snapshots and configuration roots. Each entry still undergoes genuine package,
configuration and cohort verification. No stored plan enrolls a key, no live
high-water changes, and current lookup authorization does not renew history.

Startup freezes every retained graph transitively. Request work captures only
immutable references and bounded metadata; only the selected graph is thawed,
with actual node and byte charges before allocation. These ordinary records
are not admission tokens: the real service startup establishes provenance.
"""
from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from serverware import authority_artifact_spec as artifact
from serverware import authority_attestation_cohort as cohort
from serverware import authority_contract as authority
from serverware import authority_revocation_configuration as configuration
from serverware import authority_webauthn_evidence_policy as evidence_policy
from serverware import authority_webauthn_transition_policy as transition_policy


SCHEMA = "serverware.signedAuthorityHistoricalArchive/v1"
PURPOSE = "verify-retained-authority-plans"
SIGNED_CONFIG_SCHEMA = "serverware.signedPolicyAuthorityServiceConfiguration/v6"
MAX_BYTES = 4 * 1024 * 1024
MAX_ENTRIES = 16
_PAYLOAD_FIELDS = {"schema", "purpose", "sourceRevision", "configurationDigest",
    "generationDigest", "issuedAtEpochNs", "expiresAtEpochNs", "entries"}
_ENTRY_FIELDS = {"configurationEnvelope", "artifactPackage", "artifactTrustState",
    "configurationRootPublicKeyBase64Url", "attestationCohort", "validFromEpochNs",
    "validUntilEpochNs", "configurationDigest"}
_CONFIG_FIELDS = {"schema", "sourceRevision", "roles", "runtimeUid", "runtimeGid",
    "roleBindingDigests", "roleRuntimeClosureDigests", "packageVersions", "launchNonceDigest",
    "queryManifestDigest", "generationSequence", "generationBindingDigest",
    "generationPredecessorDigest", "generationMinimumRollbackSequence", "credentialReleaseTrust",
    "replayWitness", "webauthn", "executorSessionIdentityDigest", "executorRole",
    "executorTlsClientDn", "executorTlsClientSerial", "executorTlsIssuerDn",
    "issuerCredentialIssuanceDigest", "executorCredentialIssuanceDigest"}
_OPTIONAL_FIELDS = {evidence_policy.FIELD, transition_policy.FIELD}
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
capture = configuration.capability.capture


class HistoricalArchiveError(ValueError):
    pass


def _object(value, fields, label):
    if type(value) is not dict or any(type(key) is not str for key in value) or set(value) != fields:
        raise HistoricalArchiveError(label + " is not a closed object")
    return value


def _interval(start, end):
    cohort._positive(start, "historical interval start")
    cohort._positive(end, "historical interval end")
    if start >= end:
        raise HistoricalArchiveError("historical interval is not increasing")
    return start, end


def _freeze(value, depth=0, remaining=None):
    """Own exact startup JSON as immutable tagged trees, never cached counts."""
    if remaining is None:
        remaining = [capture.MAX_TOTAL_JSON_NODES]
    remaining[0] -= 1
    if depth > capture.MAX_JSON_DEPTH or remaining[0] < 0:
        raise HistoricalArchiveError("historical JSON exceeds its structural bound")
    kind = type(value)
    if kind is dict:
        if any(type(key) is not str for key in value):
            raise HistoricalArchiveError("historical JSON member is not exact text")
        return ("object", tuple((_freeze(key, depth + 1, remaining),
            _freeze(child, depth + 1, remaining)) for key, child in value.items()))
    if kind is list:
        return ("array", tuple(_freeze(child, depth + 1, remaining) for child in value))
    if kind is str:
        if (len(value) > MAX_BYTES or any(ord(char) == 0 or 0xD800 <= ord(char) <= 0xDFFF
                for char in value)):
            raise HistoricalArchiveError("historical text is not bounded lossless JSON")
    elif kind is int:
        if value.bit_length() > 16384:
            raise HistoricalArchiveError("historical integer is not bounded")
    elif kind is float:
        if not math.isfinite(value):
            raise HistoricalArchiveError("historical configuration float is not finite")
    elif value is not None and kind is not bool:
        raise HistoricalArchiveError("historical JSON has an unsupported scalar")
    return value


def _plain(tree):
    """Startup-only thaw; request code uses the genuinely metered thaw below."""
    if type(tree) is not tuple:
        return tree
    tag, values = tree
    if tag == "object":
        return {key: _plain(value) for key, value in values}
    return [_plain(value) for value in values]


@dataclass(frozen=True, slots=True)
class _HistoricalSnapshot:
    payload: dict
    configuration_digest: str
    generation: dict
    runtime_role_identities: dict
    valid_from_epoch_ns: int
    valid_until_epoch_ns: int


HistoricalSnapshot = _HistoricalSnapshot


@dataclass(frozen=True, slots=True, init=False)
class _FrozenSnapshot:
    payload: object
    configuration_digest: str
    generation: object
    runtime_role_identities: object
    valid_from_epoch_ns: int
    valid_until_epoch_ns: int
    planner_receipt_digest: str
    generation_digest: str

    def __init__(self, snapshot):
        if type(snapshot) is not _HistoricalSnapshot:
            raise HistoricalArchiveError("historical snapshot is not an exact local record")
        digest = cohort._digest(snapshot.configuration_digest, "historical configuration")
        start, end = _interval(snapshot.valid_from_epoch_ns, snapshot.valid_until_epoch_ns)
        generation = _object(snapshot.generation, set(configuration._GENERATION_FIELDS), "historical generation")
        runtime = _object(snapshot.runtime_role_identities,
            set(configuration._RUNTIME_FIELDS), "historical runtime identities")
        _object(runtime["roles"], set(cohort.ROLES), "historical runtime role inventory")
        if (type(snapshot.payload) is not dict or snapshot.payload.get("schema") != configuration.CONFIG_SCHEMA
                or snapshot.payload.get("sourceRevision") != authority.SOURCE_REVISION
                or generation["schema"] != configuration.GENERATION_SCHEMA
                or runtime["schema"] != configuration.RUNTIME_ROLE_IDENTITIES_SCHEMA
                or runtime["configurationDigest"] != digest
                or runtime["generationDigest"] != generation["digest"]
                or runtime["generationSequence"] != generation["sequence"]):
            raise HistoricalArchiveError("historical snapshot scope is inconsistent")
        for role in cohort.ROLES:
            identity = _object(runtime["roles"][role], set(configuration._RUNTIME_ROLE_FIELDS),
                "historical runtime role")
            for pin in identity.values():
                cohort._digest(pin, "historical runtime role pin")
        generation_digest = cohort._digest(generation["digest"], "historical generation")
        receipt = runtime["roles"]["planner"]["attestationReceiptDigest"]
        remaining = [capture.MAX_TOTAL_JSON_NODES]
        for name, value in (("payload", snapshot.payload), ("generation", generation),
                ("runtime_role_identities", runtime)):
            object.__setattr__(self, name, _freeze(value, remaining=remaining))
        for name, value in (("configuration_digest", digest), ("generation_digest", generation_digest),
                ("planner_receipt_digest", receipt), ("valid_from_epoch_ns", start), ("valid_until_epoch_ns", end)):
            object.__setattr__(self, name, value)


@dataclass(frozen=True, slots=True)
class HistoryArchive:
    archive_bytes: bytes
    records: tuple[_FrozenSnapshot, ...]
    valid_from_epoch_ns: int
    valid_until_epoch_ns: int


@dataclass(frozen=True, slots=True)
class _CapturedArchive:
    records: tuple[_FrozenSnapshot, ...]
    valid_from_epoch_ns: int
    valid_until_epoch_ns: int


def _canonical_document(raw):
    if type(raw) is not bytes or not 2 <= len(raw) <= MAX_BYTES:
        raise HistoricalArchiveError("historical archive is not bounded original bytes")
    try:
        value = json.loads(raw, object_pairs_hook=cohort._unique_object,
            parse_constant=cohort._reject_constant)
        # Traverse before canonical allocation and any native key callback.
        owned = _plain(_freeze(value))
        if artifact.canonical_json_bytes(owned) != raw:
            raise HistoricalArchiveError("historical archive originals are not canonical")
        return owned
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise HistoricalArchiveError("historical archive JSON is invalid") from exc


def _epoch_ns(timestamp):
    value = artifact._require_timestamp(timestamp, name="historical generation time")
    delta = value - _EPOCH
    return (delta.days * 86400 + delta.seconds) * 1_000_000_000


def _timestamp_floor(epoch_ns):
    cohort._positive(epoch_ns, "historical artifact evaluation time")
    return (_EPOCH + timedelta(seconds=epoch_ns // 1_000_000_000)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _generation(package, verified):
    statement, bundle = package["generation"], package["bundle"]
    return {"schema": configuration.GENERATION_SCHEMA,
        "sequence": verified.generation_sequence, "digest": verified.generation_digest,
        "predecessorDigest": verified.predecessor_digest,
        "minimumRollbackSequence": verified.minimum_rollback_sequence,
        "operationManifestDigest": verified.operation_manifest_digest,
        "configurationPayloadBindings": statement["configurationPayloadBindings"],
        "configurationBindingDigest": artifact.configuration_generation_binding_digest(statement),
        "roleBindingDigests": artifact.role_binding_digests(bundle["roleManifests"])}


def _configuration(entry, generation, root_key):
    envelope = _object(entry["configurationEnvelope"], {"schema", "payload", "signature"},
        "historical configuration envelope")
    payload = envelope["payload"]
    if (envelope["schema"] != SIGNED_CONFIG_SCHEMA or type(payload) is not dict
            or not _CONFIG_FIELDS <= set(payload) or not set(payload) - _CONFIG_FIELDS <= _OPTIONAL_FIELDS
            or payload.get("schema") != configuration.CONFIG_SCHEMA
            or payload.get("sourceRevision") != authority.SOURCE_REVISION):
        raise HistoricalArchiveError("historical configuration shape or supported source changed")
    # Root verification uses the existing service NUL-domain protocol, not
    # the separately framed artifact-package digest protocol.
    cohort._verify_signature(envelope, root_key)
    payload_bytes = artifact.canonical_json_bytes(payload)
    digest = cohort._domain_digest(configuration.CONFIG_SCHEMA, payload_bytes)
    raw = artifact.canonical_json_bytes(envelope)
    file_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    expected = {"fileDigest": file_digest, "payloadDigest": digest,
        "payloadSchema": configuration.CONFIG_SCHEMA, "role": "authority-service"}
    if (digest != entry["configurationDigest"] or expected not in generation["configurationPayloadBindings"]
            or payload["generationSequence"] != generation["sequence"]
            or payload["generationBindingDigest"] != generation["configurationBindingDigest"]
            or payload["generationPredecessorDigest"] != generation["predecessorDigest"]
            or payload["generationMinimumRollbackSequence"] != generation["minimumRollbackSequence"]):
        raise HistoricalArchiveError("historical configuration differs from its exact admitted generation")
    for policy in (evidence_policy, transition_policy):
        if policy.FIELD in payload:
            policy.validate_policy(payload[policy.FIELD], webauthn=payload["webauthn"])
    return payload, digest


def _entry(entry):
    _object(entry, _ENTRY_FIELDS, "historical archive entry")
    start, end = _interval(entry["validFromEpochNs"], entry["validUntilEpochNs"])
    cohort._digest(entry["configurationDigest"], "archived configuration")
    package, state = entry["artifactPackage"], entry["artifactTrustState"]
    # These pins come from the already root-authenticated exact trust state,
    # never from the package being checked or from an incoming retained plan.
    trusted = artifact.validate_trust_state(state)
    arguments = {"historical_trust_state": state,
        "expected_package_digest": trusted["currentPackageDigest"],
        "expected_generation_digest": trusted["currentGenerationDigest"],
        "expected_generation_sequence": trusted["currentSequence"]}
    verified = artifact.verify_historical_artifact_package(package,
        validation_time=_timestamp_floor(start), **arguments)
    artifact.verify_historical_artifact_package(package,
        validation_time=_timestamp_floor(end - 1), **arguments)
    statement = package["generation"]
    if start < _epoch_ns(statement["validFrom"]) or end > _epoch_ns(statement["validUntil"]):
        raise HistoricalArchiveError("historical authorization exceeds the generation interval")
    root_raw = artifact.strict_base64url_decode(entry["configurationRootPublicKeyBase64Url"],
        name="historical configuration root", decoded_size=32)
    root_key = Ed25519PublicKey.from_public_bytes(root_raw)
    generation = _generation(package, verified)
    payload, digest = _configuration(entry, generation, root_key)
    # Versions are the signed configuration's declaration joined to cohort
    # claims, not an independently measured historical package inventory.
    admitted = cohort._admit_at_evaluation_time(
        original_bytes=artifact.canonical_json_bytes(entry["attestationCohort"]),
        configuration_payload=payload, configuration_digest=digest, root_public_key=root_key,
        generation_statement=statement, expected_generation_digest=verified.generation_digest,
        expected_package_digest=verified.package_digest,
        role_manifests=package["bundle"]["roleManifests"], package_versions=payload["packageVersions"],
        evaluation_epoch_ns=start)
    if start < admitted.valid_from_epoch_ns or end > admitted.valid_until_epoch_ns:
        raise HistoricalArchiveError("historical authorization exceeds the attestation cohort interval")
    runtime_roles = {}
    for role, receipt_bytes, receipt_digest in admitted.receipts:
        receipt = json.loads(receipt_bytes)["payload"]
        runtime_roles[role] = {"measurementDigest": receipt["measurementDigest"],
            "responseSigningSpkiDigest": receipt["responseSigningSpkiDigest"],
            "attestationReceiptDigest": receipt_digest}
    runtime = {"schema": configuration.RUNTIME_ROLE_IDENTITIES_SCHEMA,
        "configurationDigest": digest, "generationSequence": admitted.generation_sequence,
        "generationDigest": admitted.generation_digest, "cohortDigest": admitted.cohort_digest,
        "roles": runtime_roles}
    return _FrozenSnapshot(_HistoricalSnapshot(payload, digest, generation, runtime, start, end))


def _admit_on_startup(*, original_bytes, current_snapshot, current_root_public_key, now_epoch_ns):
    """Authenticate the whole archive before considering historical key bytes."""
    original, key = original_bytes, current_root_public_key
    now = cohort._positive(now_epoch_ns, "archive admission time")
    if not isinstance(key, Ed25519PublicKey):
        raise HistoricalArchiveError("archive current root is not independently admitted Ed25519")
    current = _FrozenSnapshot(current_snapshot)
    envelope = _canonical_document(original)
    payload = cohort._envelope(envelope, SCHEMA, _PAYLOAD_FIELDS)
    entries = payload["entries"]
    if type(entries) is not list or len(entries) > MAX_ENTRIES:
        raise HistoricalArchiveError("historical archive entries exceed the fixed bound")
    cohort._verify_signature(envelope, key)
    start, end = _interval(payload["issuedAtEpochNs"], payload["expiresAtEpochNs"])
    if (payload["purpose"] != PURPOSE or payload["sourceRevision"] != authority.SOURCE_REVISION
            or payload["configurationDigest"] != current.configuration_digest
            or payload["generationDigest"] != current.generation_digest
            or start < current.valid_from_epoch_ns or end > current.valid_until_epoch_ns
            or not start <= now < end):
        raise HistoricalArchiveError("historical archive differs from current admitted scope or validity")
    records, previous = [current], None
    current_selector = current.configuration_digest, current.planner_receipt_digest
    for value in entries:
        record = _entry(value)
        selector = record.configuration_digest, record.planner_receipt_digest
        if (selector == current_selector or previous is not None and selector <= previous):
            raise HistoricalArchiveError("historical archive selectors are not sorted and unique")
        records.append(record)
        previous = selector
    return HistoryArchive(original, tuple(records), start, end)


def _capture_on_work(archive, *, work):
    """Hold immutable startup records and charged metadata before callbacks."""
    ledger = capture._SharedLedger(work)
    if type(archive) is not HistoryArchive:
        raise HistoricalArchiveError("historical archive is not an exact local owner")
    records, start, end = archive.records, archive.valid_from_epoch_ns, archive.valid_until_epoch_ns
    if type(records) is not tuple or not 1 <= len(records) <= MAX_ENTRIES + 1:
        raise HistoricalArchiveError("historical archive record inventory is invalid")
    _interval(start, end)
    # Fixed source-bounded references, not all potentially large payloads.
    owned = []
    ledger.charge(json_nodes=1, input_bytes=2 + max(0, len(records) - 1))
    metadata = capture._JSONCapture(ledger, maximum_bytes=16384)
    metadata.visit([start, end])
    for record in records:
        if type(record) is not _FrozenSnapshot:
            raise HistoricalArchiveError("historical archive record type changed")
        metadata.visit([record.configuration_digest, record.planner_receipt_digest,
            record.valid_from_epoch_ns, record.valid_until_epoch_ns])
        owned.append(record)
    return _CapturedArchive(tuple(owned), start, end)


class _Thaw(configuration._ConfigurationCapture):
    """Charge the actual selected immutable tree before each allocation."""

    def visit(self, value, depth=0, ancestors=frozenset()):
        if type(value) is not tuple:
            return super().visit(value, depth, ancestors)
        if (depth > capture.MAX_JSON_DEPTH or len(value) != 2
                or value[0] not in ("object", "array") or type(value[1]) is not tuple):
            raise HistoricalArchiveError("historical immutable tree is invalid")
        tag, children = value
        self.ledger.charge(json_nodes=1)
        self.nodes += 1
        minimum_nodes = len(children) * (2 if tag == "object" else 1)
        maximum_nodes = getattr(self.ledger, "maximum_json_nodes", capture.MAX_TOTAL_JSON_NODES)
        if minimum_nodes > maximum_nodes - self.ledger.json_nodes:
            raise HistoricalArchiveError("historical selected JSON exceeds its node bound")
        self._bytes(2 + max(0, len(children) - 1) + (len(children) if tag == "object" else 0))
        if tag == "object":
            result = {}
            for pair in children:
                if type(pair) is not tuple or len(pair) != 2 or type(pair[0]) is not str:
                    raise HistoricalArchiveError("historical immutable member is invalid")
                key = self.visit(pair[0], depth + 1)
                child = self.visit(pair[1], depth + 1)
                result[key] = child
            return result
        result = []
        for child in children:
            result.append(self.visit(child, depth + 1))
        return result


def _lookup_on_work(snapshots, *, configuration_digest, planner_attestation_receipt_digest,
        evaluation_epoch_ns, work):
    """Select independently admitted history without adopting plan claims."""
    ledger = capture._SharedLedger(work)
    if type(snapshots) is not _CapturedArchive:
        raise HistoricalArchiveError("historical lookup requires this call's captured archive")
    cohort._digest(configuration_digest, "requested historical configuration")
    cohort._digest(planner_attestation_receipt_digest, "requested historical planner receipt")
    cohort._positive(evaluation_epoch_ns, "original historical evaluation time")
    records = snapshots.records
    if type(records) is not tuple or not 1 <= len(records) <= MAX_ENTRIES + 1:
        raise HistoricalArchiveError("historical lookup record inventory is invalid")
    capture._JSONCapture(ledger).visit([configuration_digest, planner_attestation_receipt_digest, evaluation_epoch_ns])
    selected = None
    for record in records:
        if type(record) is not _FrozenSnapshot:
            raise HistoricalArchiveError("historical lookup record type changed")
        ledger.charge(json_nodes=1, input_bytes=len(record.configuration_digest) + len(record.planner_receipt_digest))
        if (record.configuration_digest == configuration_digest
                and record.planner_receipt_digest == planner_attestation_receipt_digest):
            if selected is not None:
                raise HistoricalArchiveError("historical lookup selector is ambiguous")
            selected = record
    if selected is None or not selected.valid_from_epoch_ns <= evaluation_epoch_ns < selected.valid_until_epoch_ns:
        raise HistoricalArchiveError("historical lookup is not authorized at the original evaluation time")
    thaw = _Thaw(ledger, maximum_bytes=authority.MAX_RESULT_BYTES)
    return _HistoricalSnapshot(thaw.visit(selected.payload), selected.configuration_digest,
        thaw.visit(selected.generation), thaw.visit(selected.runtime_role_identities),
        selected.valid_from_epoch_ns, selected.valid_until_epoch_ns)


def _lookup_control_on_work(snapshots, *, configuration_digest, generation_digest,
        issued_at_epoch_ns, work):
    """Locate an already-admitted static control key, not admitted history.

    An unauthenticated ORIGINAL INTENT header may supply these locators. They
    select only startup root-admitted records and never enroll a key. Multiple
    eligible cohorts under one canonically verified configuration/generation
    have the same static verifier keys; the first eligible inventory entry is
    deterministic and sufficient only to bootstrap signature verification.

    After authenticating the original control, the caller MUST resolve its
    actual planner receipt and historical expectations through _lookup_on_work
    and join every control interval to that selected snapshot. This result is
    not a substitute for those joins, current archive lifetime enforcement,
    original signature authentication or genuine historical plan replay.
    """
    ledger = capture._SharedLedger(work)
    if type(snapshots) is not _CapturedArchive:
        raise HistoricalArchiveError("control lookup requires this call's captured archive")
    cohort._digest(configuration_digest, "original control configuration locator")
    cohort._digest(generation_digest, "original control generation locator")
    cohort._positive(issued_at_epoch_ns, "original control issue locator")
    records = snapshots.records
    if type(records) is not tuple or not 1 <= len(records) <= MAX_ENTRIES + 1:
        raise HistoricalArchiveError("control lookup record inventory is invalid")
    metadata = capture._JSONCapture(ledger, maximum_bytes=16384)
    metadata.visit([configuration_digest, generation_digest, issued_at_epoch_ns])
    selected = None
    for record in records:
        if type(record) is not _FrozenSnapshot:
            raise HistoricalArchiveError("control lookup record type changed")
        metadata.visit([record.configuration_digest, record.generation_digest,
            record.valid_from_epoch_ns, record.valid_until_epoch_ns])
        if (selected is None and record.configuration_digest == configuration_digest
                and record.generation_digest == generation_digest
                and record.valid_from_epoch_ns <= issued_at_epoch_ns < record.valid_until_epoch_ns):
            selected = record
    if selected is None:
        raise HistoricalArchiveError("original control has no already-admitted historical key locator")
    thaw = _Thaw(ledger, maximum_bytes=authority.MAX_RESULT_BYTES)
    return _HistoricalSnapshot(thaw.visit(selected.payload), selected.configuration_digest,
        thaw.visit(selected.generation), thaw.visit(selected.runtime_role_identities),
        selected.valid_from_epoch_ns, selected.valid_until_epoch_ns)
