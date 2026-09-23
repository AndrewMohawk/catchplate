"""Pure, purpose-specific audit-initialization signature admission.

Pins are independent trusted integration inputs, never selected by an envelope.
Verification authenticates the signed claims and their pin bindings only. It
does not establish actual measurements, independent administration, root
currentness, writer fencing, installation, or authority to insert a counter.
There is no clock, database, filesystem, key provisioning, or signing operation.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from serverware import authority_artifact_spec as artifacts


CHECKPOINT_SCHEMA = "serverware.metadataAuditInitializationCheckpoint/v1"
AUTHORIZATION_SCHEMA = "serverware.metadataAuditInitializationAuthorization/v1"
CHECKPOINT_PAYLOAD_SCHEMA = "serverware.metadataAuditInitializationCheckpointPayload/v1"
AUTHORIZATION_PAYLOAD_SCHEMA = "serverware.metadataAuditInitializationAuthorizationPayload/v1"
CHECKPOINT_PURPOSE = "metadata-audit-initialization-checkpoint"
AUTHORIZATION_PURPOSE = "metadata-audit-initialization-authorization"
CHECKPOINT_SIGNATURE_DOMAIN = "serverware.metadataAuditInitializationCheckpointSignature/v1"
AUTHORIZATION_SIGNATURE_DOMAIN = "serverware.metadataAuditInitializationAuthorizationSignature/v1"
CHECKPOINT_ENVELOPE_DOMAIN = "serverware.metadataAuditInitializationCheckpointEnvelope/v1"
AUTHORIZATION_ENVELOPE_DOMAIN = "serverware.metadataAuditInitializationAuthorizationEnvelope/v1"
MAX_ENVELOPE_BYTES = 65_536
MAX_PUBLIC_KEY_BYTES = 1024
MAX_JSON_DEPTH = 16
MAX_JSON_NODES = 4096
_MIN_INTEGER = -(2**63)
_MAX_INTEGER = 2**63 - 1
_ENVELOPE_FIELDS = frozenset({
    "schema", "payload", "signerKeyId", "algorithm", "signatureBase64Url",
})
_ROLE_CONTRACTS = MappingProxyType({
    "checkpoint": (CHECKPOINT_SCHEMA, CHECKPOINT_PAYLOAD_SCHEMA, CHECKPOINT_PURPOSE,
                   CHECKPOINT_SIGNATURE_DOMAIN, CHECKPOINT_ENVELOPE_DOMAIN),
    "authorization": (AUTHORIZATION_SCHEMA, AUTHORIZATION_PAYLOAD_SCHEMA, AUTHORIZATION_PURPOSE,
                      AUTHORIZATION_SIGNATURE_DOMAIN, AUTHORIZATION_ENVELOPE_DOMAIN),
})


class AuditInitializationSignatureError(ValueError):
    pass


def _role_contract(role: str) -> tuple[str, str, str, str, str]:
    if type(role) is not str or role not in _ROLE_CONTRACTS:
        raise AuditInitializationSignatureError("audit initialization signer role is invalid")
    return _ROLE_CONTRACTS[role]


def _digest_pin(value: str) -> None:
    if type(value) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        raise AuditInitializationSignatureError("audit initialization authority digest pin is invalid")


def _public_key(raw: bytes) -> Ed25519PublicKey:
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_PUBLIC_KEY_BYTES:
        raise AuditInitializationSignatureError("audit initialization SPKI bytes are invalid or oversized")
    try:
        key = serialization.load_der_public_key(raw)
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise AuditInitializationSignatureError("audit initialization SPKI is not valid DER") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise AuditInitializationSignatureError("audit initialization SPKI must be Ed25519")
    if key.public_bytes(serialization.Encoding.DER,
                        serialization.PublicFormat.SubjectPublicKeyInfo) != raw:
        raise AuditInitializationSignatureError("audit initialization SPKI DER is not canonical")
    return key


@dataclass(frozen=True, slots=True)
class InitializationSignerPin:
    role: str
    public_key_der: bytes
    authority_identity_digest: str
    measurement_digest: str
    attestation_receipt_digest: str

    def __post_init__(self) -> None:
        _role_contract(self.role)
        _public_key(self.public_key_der)
        for value in (self.authority_identity_digest, self.measurement_digest,
                      self.attestation_receipt_digest):
            _digest_pin(value)

    @property
    def key_id(self) -> str:
        return "sha256:" + hashlib.sha256(self.public_key_der).hexdigest()


def _pin_snapshot(pin: InitializationSignerPin) -> InitializationSignerPin:
    if type(pin) is not InitializationSignerPin:
        raise AuditInitializationSignatureError("audit initialization signer pin has the wrong type")
    # Frozen dataclasses are not authority tokens. Validate a fresh snapshot,
    # including pins manufactured without calling the normal constructor.
    try:
        return InitializationSignerPin(pin.role, pin.public_key_der,
            pin.authority_identity_digest, pin.measurement_digest,
            pin.attestation_receipt_digest)
    except AttributeError as exc:
        raise AuditInitializationSignatureError("audit initialization signer pin is incomplete") from exc


def _bounded_raw(raw: bytes) -> None:
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_ENVELOPE_BYTES:
        raise AuditInitializationSignatureError("audit initialization envelope bytes are invalid or oversized")


def _integer_token(token: str) -> int:
    digits = token[1:] if token.startswith("-") else token
    # Reject before int conversion, independent of Python's process-wide digit
    # limit. Canonical comparison below also denies the JSON spelling -0.
    if len(digits) > 19:
        raise AuditInitializationSignatureError("audit initialization JSON integer exceeds signed64")
    value = int(token, 10)
    if not _MIN_INTEGER <= value <= _MAX_INTEGER:
        raise AuditInitializationSignatureError("audit initialization JSON integer exceeds signed64")
    return value


def _reject_number(_: str) -> Any:
    raise AuditInitializationSignatureError("audit initialization JSON requires integer numbers")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuditInitializationSignatureError("audit initialization JSON contains duplicate keys")
        result[key] = value
    return result


def _bounded_graph(value: dict[str, Any]) -> None:
    # Root depth is one; object keys and values each count as nodes at the
    # following depth. Only the parser-owned graph reaches this traversal.
    stack = [(value, 1)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if depth > MAX_JSON_DEPTH or nodes > MAX_JSON_NODES:
            raise AuditInitializationSignatureError("audit initialization JSON exceeds its graph bound")
        if type(item) is str:
            if any(ord(char) == 0 or 0xD800 <= ord(char) <= 0xDFFF for char in item):
                raise AuditInitializationSignatureError("audit initialization JSON contains NUL or surrogate")
        elif item is None or type(item) is bool:
            pass
        elif type(item) is int:
            if not _MIN_INTEGER <= item <= _MAX_INTEGER:
                raise AuditInitializationSignatureError("audit initialization JSON integer exceeds signed64")
        elif type(item) is dict:
            if (len(item) * 2 > MAX_JSON_NODES - nodes - len(stack)
                    or any(type(key) is not str for key in item)):
                raise AuditInitializationSignatureError("audit initialization JSON exceeds its graph bound")
            stack.extend((child, depth + 1) for pair in item.items() for child in pair)
        elif type(item) is list:
            if len(item) > MAX_JSON_NODES - nodes - len(stack):
                raise AuditInitializationSignatureError("audit initialization JSON exceeds its graph bound")
            stack.extend((child, depth + 1) for child in item)
        else:
            raise AuditInitializationSignatureError("audit initialization value is not lossless JSON")


def _canonical_envelope(raw: bytes) -> dict[str, Any]:
    _bounded_raw(raw)
    try:
        document = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_object,
            parse_int=_integer_token, parse_float=_reject_number, parse_constant=_reject_number)
    except AuditInitializationSignatureError:
        raise
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise AuditInitializationSignatureError("audit initialization envelope is not strict ASCII JSON") from exc
    if type(document) is not dict:
        raise AuditInitializationSignatureError("audit initialization envelope is not an object")
    _bounded_graph(document)
    try:
        canonical = artifacts.canonical_json_bytes(document)
    except (artifacts.ArtifactContractError, UnicodeError, RecursionError) as exc:
        raise AuditInitializationSignatureError("audit initialization envelope is not canonical JSON") from exc
    if raw != canonical:
        raise AuditInitializationSignatureError("audit initialization envelope bytes are not canonical")
    return document


def verify_initialization_envelope(
    raw: bytes, *, role: str, pin: InitializationSignerPin,
) -> dict[str, Any]:
    """Return an owned envelope only after purpose/pin/signature admission.

    The consumer must close all remaining payload fields, bind its expected
    plan/checkpoint and enforce explicit time, ancestry and replay policy.
    Mutability of this returned snapshot conveys no authority to another API.
    """
    schema, payload_schema, purpose, signature_domain, _ = _role_contract(role)
    accepted_pin = _pin_snapshot(pin)
    if accepted_pin.role != role:
        raise AuditInitializationSignatureError("audit initialization signer pin role differs")
    document = _canonical_envelope(raw)
    if set(document) != _ENVELOPE_FIELDS:
        raise AuditInitializationSignatureError("audit initialization envelope fields are not closed")
    if (document["schema"] != schema or document["algorithm"] != "Ed25519"
            or document["signerKeyId"] != accepted_pin.key_id):
        raise AuditInitializationSignatureError("audit initialization envelope role, algorithm or key differs")
    payload = document["payload"]
    if (type(payload) is not dict or payload.get("schema") != payload_schema
            or payload.get("purpose") != purpose
            or payload.get("authorityIdentityDigest") != accepted_pin.authority_identity_digest
            or payload.get("authorityMeasurementDigest") != accepted_pin.measurement_digest
            or payload.get("authorityAttestationDigest") != accepted_pin.attestation_receipt_digest):
        raise AuditInitializationSignatureError("audit initialization payload purpose or authority pins differ")
    signature = document["signatureBase64Url"]
    if type(signature) is not str or len(signature) != 86:
        raise AuditInitializationSignatureError("audit initialization signature encoding has the wrong length")
    message = artifacts.domain_digest(signature_domain,
        artifacts.canonical_json_bytes(payload)).encode("ascii")
    raw_key = _public_key(accepted_pin.public_key_der).public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    try:
        artifacts.verify_ed25519_signature(raw_key, signature, message,
            name=f"audit initialization {role}")
    except (artifacts.ArtifactContractError, UnsupportedAlgorithm) as exc:
        raise AuditInitializationSignatureError("audit initialization signature verification failed") from exc
    return document


def envelope_digest(raw: bytes, *, role: str) -> str:
    """Compute a role-domain digest of bounded original bytes, not admission.

    This function deliberately does not parse or verify a signature. Only a
    successful verify_initialization_envelope call authenticates those bytes;
    even that result does not prove their claims occurred in the real world.
    """
    contract = _role_contract(role)
    _bounded_raw(raw)
    return artifacts.domain_digest(contract[4], raw)
