"""Bounded registration cryptography with explicit, immutable inputs.

This module has no database, filesystem, configuration or clock access. A
caller supplies ceremony scope, trust-root provenance and one verification
instant. Results are local cryptographic computations, NOT authenticated row
selection, enrollment permission, signed external evidence or authority receipts.
JSON/CBOR are decoded using the existing registration semantics; original bytes
are retained for signature verification, never reconstructed from parsed values.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import uuid
from dataclasses import InitVar, dataclass, fields
from datetime import datetime, timedelta, timezone
from typing import Any

import cbor2
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtensionOID, ObjectIdentifier

from catchplate.authority_query_read_work import (
    MAX_HASHES, MAX_INPUT_BYTES, MAX_JSON_NODES,
    QueryReadValidationLimits, QueryReadWorkError, _ValidationWork,
)

UP_FLAG = 0x01
UV_FLAG = 0x04
AT_FLAG = 0x40
ES256_ALG = -7
EC2_KTY = 2
P256_CRV = 1
MAX_CLIENT_DATA_JSON_BYTES = 16 * 1024
MAX_AUTHENTICATOR_DATA_BYTES = 64 * 1024
MAX_ATTESTATION_OBJECT_BYTES = 256 * 1024
MAX_COSE_PUBLIC_KEY_BYTES = 4 * 1024
MAX_CREDENTIAL_ID_BYTES = 1024
MAX_ATTESTATION_CHAIN_CERTIFICATES = 5
MAX_ATTESTATION_CERTIFICATE_BYTES = 64 * 1024
MAX_ATTESTATION_CHAIN_BYTES = 256 * 1024
MAX_TRUST_ROOTS = 256
MAX_TRUST_SNAPSHOT_BYTES = 2 * 1024 * 1024
MAX_AUTHORIZATION_BYTES = 64 * 1024
FIDO_AAGUID_EXTENSION = ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4")
YUBIKEY_AAGUIDS = frozenset({
    "2fc0579f-8113-47ea-b116-bb5a8db9202a",
    "fa2b99dc-9e39-4257-8f92-4a30d23c4118",
    "ee041bce-25e5-4cdb-8f86-897fd6418464",
    "cb69481e-8ff7-4039-93ec-0a2729a154a8",
})


class WebAuthnError(ValueError):
    pass


def _require_work(work) -> None:
    if work is None:
        return
    if (type(work) is not _ValidationWork or type(work.limits) is not QueryReadValidationLimits
            or any(type(value) is not int or not 1 <= value <= maximum for value, maximum in (
                (work.limits.max_hashes, MAX_HASHES), (work.limits.max_input_bytes, MAX_INPUT_BYTES),
                (work.limits.max_json_nodes, MAX_JSON_NODES)))
            or any(type(value) is not int or not 0 <= value <= maximum for value, maximum in (
                (work.hash_work, work.limits.max_hashes), (work.input_bytes, work.limits.max_input_bytes),
                (work.json_nodes, work.limits.max_json_nodes)))):
        raise QueryReadWorkError("WebAuthn attestation work is not the original valid shared meter")


def _native(work, call):
    """Bounded native work is not represented as fabricated H/B/N work.

    Call sites bound source inputs before entry and inspect/charge outputs.
    JSON/CBOR/X509/EC internals and native allocations are outside this meter;
    this is not a CPU, memory, deadline or whole-crypto resource guarantee.
    A failing native call aborts the invocation without refunding prior work.
    """
    _require_work(work)
    before = None if work is None else (work.limits, work.limits.max_hashes,
        work.limits.max_input_bytes, work.limits.max_json_nodes,
        work.hash_work, work.input_bytes, work.json_nodes)
    try:
        return call()
    finally:
        # Chain verification may try another root after an ordinary native
        # signature failure. Such a failure must not hide meter mutation.
        if work is not None:
            _require_work(work)
            if (work.limits is not before[0]
                    or (work.limits.max_hashes, work.limits.max_input_bytes, work.limits.max_json_nodes,
                        work.hash_work, work.input_bytes, work.json_nodes) != before[1:]):
                raise QueryReadWorkError("WebAuthn native operation changed the shared work meter")


def _decoded_work(value, work, depth=0, ancestors=frozenset()) -> None:
    """Charge actual native output traversal before using its contents.

    The private measured route admits ordinary finite scalar/container graphs,
    not CBOR semantic-tag objects, cycles or deeper-than-source graphs. Public
    unmetered calls retain the existing decoder behavior unchanged.
    """
    if work is None:
        return
    _require_work(work)
    if depth > 128:
        raise WebAuthnError("WebAuthn decoded graph exceeds the source depth")
    work.charge(json_nodes=1)
    kind = type(value)
    if value is None or kind is bool:
        work.charge(input_bytes=1)
    elif kind is int:
        if value.bit_length() > 16384:
            raise WebAuthnError("WebAuthn decoded integer exceeds the source bound")
        work.charge(input_bytes=max(1, (value.bit_length() + 7) // 8))
    elif kind is float:
        work.charge(input_bytes=8)
    elif kind is bytes:
        work.charge(input_bytes=len(value))
    elif kind is str:
        work.prepare_utf8(value)
    elif kind in (dict, list, tuple, set, frozenset):
        if id(value) in ancestors:
            raise WebAuthnError("WebAuthn decoded graph contains a cycle")
        nested = ancestors | {id(value)}
        if kind is dict:
            for key, child in value.items():
                _decoded_work(key, work, depth + 1, nested)
                _decoded_work(child, work, depth + 1, nested)
        else:
            for child in value:
                _decoded_work(child, work, depth + 1, nested)
    else:
        raise WebAuthnError("WebAuthn native decoder returned an unsupported measured graph type")


def sha256_prefixed(value: bytes, *, _work=None) -> str:
    _require_work(_work)
    if _work is not None:
        _work.charge(hashes=1, input_bytes=len(value))
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _text(value: str, label: str, maximum: int, *, empty: bool = False, _work=None) -> None:
    _require_work(_work)
    if _work is not None:
        if type(value) is not str or len(value) > maximum:
            raise WebAuthnError(f"WebAuthn {label} is not bounded exact text")
        _work.prepare_utf8(value)
    try:
        valid = isinstance(value, str) and (empty or bool(value)) and len(value.encode("utf-8")) <= maximum
    except UnicodeEncodeError:
        valid = False
    if not valid:
        raise WebAuthnError(f"WebAuthn {label} is invalid or oversized")


def _bytes(value: bytes, label: str, maximum: int, *, _work=None) -> None:
    _require_work(_work)
    if not isinstance(value, bytes) or not 1 <= len(value) <= maximum:
        raise WebAuthnError(f"WebAuthn {label} is invalid or oversized")
    if _work is not None:
        if type(value) is not bytes:
            raise WebAuthnError(f"WebAuthn {label} is not exact bytes")
        _work.charge(input_bytes=len(value))


def _digest(value: str | None, label: str) -> None:
    if value is not None and (not isinstance(value, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None):
        raise WebAuthnError(f"WebAuthn {label} digest is invalid")


def _canonical(value: Any, *, _work=None) -> bytes:
    _require_work(_work)
    try:
        if _work is not None:
            return _work.wire(value)
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise WebAuthnError("WebAuthn context is not canonical JSON") from exc


def _commitment(domain: str, value: Any, *, _work=None) -> str:
    # Local context commitment only. This is not an authority signing domain.
    encoded = _canonical(value, _work=_work)
    if _work is not None:
        _work.prepare_utf8(domain)
        _work.charge(input_bytes=len(domain) + 1 + len(encoded))
    return sha256_prefixed(domain.encode("ascii") + b"\x00" + encoded, _work=_work)


@dataclass(frozen=True, slots=True)
class CeremonyScope:
    challenge_id: str
    challenge: str
    user_id: str
    label: str
    authorization_json: bytes
    _work: InitVar[_ValidationWork | None] = None

    def __post_init__(self, _work) -> None:
        for field in ("challenge_id", "challenge", "user_id"):
            _text(getattr(self, field), field, 4096, _work=_work)
        _text(self.label, "label", 4096, empty=True, _work=_work)
        _bytes(self.authorization_json, "authorization context", MAX_AUTHORIZATION_BYTES, _work=_work)
        try:
            authorization = _native(_work, lambda: json.loads(self.authorization_json))
            _decoded_work(authorization, _work)
        except (ValueError, UnicodeError) as exc:
            raise WebAuthnError("WebAuthn authorization context is invalid") from exc
        if _canonical(authorization, _work=_work) != self.authorization_json:
            raise WebAuthnError("WebAuthn authorization context is not canonical")

    def commitment(self, *, _work=None) -> str:
        return _commitment("catchplate.webauthnRegistrationCeremonyContext/v1", {
            "challengeId": self.challenge_id, "challenge": self.challenge,
            "userId": self.user_id, "label": self.label,
            "authorizationJsonSha256": sha256_prefixed(self.authorization_json, _work=_work),
        }, _work=_work)


@dataclass(frozen=True, slots=True)
class TrustRootSnapshot:
    certificate_der: bytes
    certificate_sha256: str
    authenticator_class: str | None
    aaguids: frozenset[str]
    bundle_digest: str | None
    bundle_sequence: int | None
    bundle_rollback_epoch: int | None
    _work: InitVar[_ValidationWork | None] = None

    def __post_init__(self, _work) -> None:
        _bytes(self.certificate_der, "trust root certificate", MAX_ATTESTATION_CERTIFICATE_BYTES, _work=_work)
        if self.certificate_sha256 != sha256_prefixed(self.certificate_der, _work=_work):
            raise WebAuthnError("WebAuthn trust root certificate digest mismatch")
        if self.authenticator_class is not None:
            _text(self.authenticator_class, "trust root class", 128, _work=_work)
        if not isinstance(self.aaguids, frozenset) or len(self.aaguids) > 1024:
            raise WebAuthnError("WebAuthn trust root AAGUID set is invalid or oversized")
        for aaguid in self.aaguids:
            _text(aaguid, "trust root AAGUID", 128, _work=_work)
        _digest(self.bundle_digest, "trust bundle")
        for value in (self.bundle_sequence, self.bundle_rollback_epoch):
            if value is not None and (type(value) is not int or not 0 <= value <= 2**63 - 1):
                raise WebAuthnError("WebAuthn trust bundle counter is invalid")

    def commitment_fields(self, *, _work=None) -> dict[str, Any]:
        _decoded_work(self.aaguids, _work)
        return {
            "certificateSha256": self.certificate_sha256,
            "authenticatorClass": self.authenticator_class,
            "aaguids": sorted(self.aaguids), "bundleDigest": self.bundle_digest,
            "bundleSequence": self.bundle_sequence,
            "bundleRollbackEpoch": self.bundle_rollback_epoch,
        }


@dataclass(frozen=True, slots=True)
class VerificationContext:
    rp_id: str
    origin: str
    verified_at: datetime
    trust_roots: tuple[TrustRootSnapshot, ...]
    _work: InitVar[_ValidationWork | None] = None

    def __post_init__(self, _work) -> None:
        _text(self.rp_id, "RP ID", 4096, _work=_work)
        _text(self.origin, "origin", 8192, _work=_work)
        if not isinstance(self.verified_at, datetime) or self.verified_at.utcoffset() != timedelta(0):
            raise WebAuthnError("WebAuthn verification time must be explicit aware UTC")
        object.__setattr__(self, "verified_at", self.verified_at.replace(tzinfo=timezone.utc))
        if not isinstance(self.trust_roots, tuple) or len(self.trust_roots) > MAX_TRUST_ROOTS:
            raise WebAuthnError("WebAuthn trust snapshot is invalid or oversized")
        total = 0
        for root in self.trust_roots:
            if not isinstance(root, TrustRootSnapshot):
                raise WebAuthnError("WebAuthn trust snapshot root is invalid")
            total += len(root.certificate_der) + len(_canonical(root.commitment_fields(_work=_work), _work=_work))
            if total > MAX_TRUST_SNAPSHOT_BYTES:
                raise WebAuthnError("WebAuthn trust snapshot is oversized")

    def commitment(self, *, _work=None) -> str:
        return _commitment("catchplate.webauthnRegistrationVerificationContext/v1", {
            "rpId": self.rp_id, "origin": self.origin,
            "verifiedAt": self.verified_at.isoformat(),
            "trustRoots": [root.commitment_fields(_work=_work) for root in self.trust_roots],
        }, _work=_work)


@dataclass(frozen=True, slots=True)
class AttestationResult:
    fmt: str
    trusted: bool
    trust_path: tuple[str, ...] = ()
    leaf_sha256: str | None = None
    root_sha256: str | None = None
    trust_bundle_digest: str | None = None
    trust_bundle_sequence: int | None = None
    trust_class: str | None = None
    verified_at: str | None = None

    def legacy_dict(self) -> dict[str, Any]:
        # Fresh mutable projection for existing callers; never shares a list.
        return {
            "fmt": self.fmt, "trusted": self.trusted,
            "trust_path": list(self.trust_path), "leaf_sha256": self.leaf_sha256,
            "root_sha256": self.root_sha256,
            "trust_bundle_digest": self.trust_bundle_digest,
            "trust_bundle_sequence": self.trust_bundle_sequence,
            "trust_class": self.trust_class, "verified_at": self.verified_at,
        }


@dataclass(frozen=True, slots=True)
class ParsedRegistration:
    client_data_json: bytes
    attestation_object: bytes
    scope: CeremonyScope
    rp_id: str
    origin: str
    credential_id: str
    credential_id_raw: bytes
    public_key_cose: bytes
    auth_data: bytes
    aaguid_raw: bytes
    sign_count: int
    user_verified: bool
    needs_trust_roots: bool
    transports: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RegistrationAttestationResult:
    credential_id: str
    public_key_cose: bytes
    sign_count: int
    user_verified: bool
    aaguid: str
    authenticator_class: str
    transports: tuple[str, ...]
    attestation: AttestationResult
    client_data_sha256: str
    attestation_object_sha256: str
    ceremony_scope_sha256: str
    verification_context_sha256: str


def parse_client_data(raw: bytes, expected_type: str, *, origin: str, _work=None) -> dict[str, Any]:
    _bytes(raw, "clientDataJSON", MAX_CLIENT_DATA_JSON_BYTES, _work=_work)
    try:
        value = _native(_work, lambda: json.loads(raw))
        _decoded_work(value, _work)
    except (ValueError, UnicodeError) as exc:
        raise WebAuthnError("invalid clientDataJSON") from exc
    if not isinstance(value, dict):
        raise WebAuthnError("invalid clientDataJSON")
    if value.get("type") != expected_type:
        raise WebAuthnError(f"unexpected WebAuthn clientDataJSON type {value.get('type')}")
    if value.get("origin") != origin:
        raise WebAuthnError("WebAuthn origin mismatch")
    if value.get("crossOrigin"):
        raise WebAuthnError("cross-origin WebAuthn assertions are not accepted")
    return value


def parse_authenticator_data(auth_data: bytes, *, rp_id: str, _work=None) -> dict[str, Any]:
    if not isinstance(auth_data, bytes) or not 37 <= len(auth_data) <= MAX_AUTHENTICATOR_DATA_BYTES:
        raise WebAuthnError("authenticatorData is too short")
    if _work is not None:
        _work.prepare_utf8(rp_id)
        _work.charge(input_bytes=len(auth_data))
    rp_bytes = rp_id.encode("utf-8")
    if _work is not None:
        _work.charge(hashes=1, input_bytes=len(rp_bytes))
    if auth_data[:32] != hashlib.sha256(rp_bytes).digest():
        raise WebAuthnError("WebAuthn RP ID hash mismatch")
    flags = auth_data[32]
    if not flags & UP_FLAG:
        raise WebAuthnError("authenticator user presence flag missing")
    return {
        "flags": flags, "user_present": bool(flags & UP_FLAG),
        "user_verified": bool(flags & UV_FLAG),
        "attested_credential_data": bool(flags & AT_FLAG),
        "sign_count": int.from_bytes(auth_data[33:37], "big"),
    }


def _attestation_object(raw: bytes, *, _work=None) -> dict[str, Any]:
    _bytes(raw, "attestation object", MAX_ATTESTATION_OBJECT_BYTES, _work=_work)
    try:
        value = _native(_work, lambda: cbor2.loads(raw))
        _decoded_work(value, _work)
    except (ValueError, TypeError) as exc:
        raise WebAuthnError("WebAuthn attestation object is invalid") from exc
    if not isinstance(value, dict):
        raise WebAuthnError("WebAuthn attestation object is invalid")
    return value


def needs_trust_roots(attestation: dict[str, Any]) -> bool:
    fmt = attestation.get("fmt")
    if fmt not in ("packed", "fido-u2f"):
        return False
    statement = attestation.get("attStmt") or {}
    if not isinstance(statement, dict):
        raise WebAuthnError("WebAuthn attestation statement is invalid")
    return fmt == "fido-u2f" or (fmt == "packed" and bool(statement.get("x5c")))


def parse_registration_data(
    client_data_json: bytes, attestation_object: bytes, credential_id: str,
    *, scope: CeremonyScope, rp_id: str, origin: str,
    transports: tuple[str, ...] = (), _work=None,
) -> ParsedRegistration:
    _require_work(_work)
    if not isinstance(scope, CeremonyScope):
        raise WebAuthnError("WebAuthn ceremony scope is invalid")
    _text(rp_id, "RP ID", 4096, _work=_work)
    _text(origin, "origin", 8192, _work=_work)
    _text(credential_id, "credential ID", 2048, _work=_work)
    if not isinstance(transports, tuple) or len(transports) > 16:
        raise WebAuthnError("WebAuthn transports are invalid or oversized")
    for transport in transports:
        _text(transport, "transport", 2048, empty=True, _work=_work)
    client = parse_client_data(client_data_json, "webauthn.create", origin=origin, _work=_work)
    if client.get("challenge") != scope.challenge:
        raise WebAuthnError("registration challenge scope mismatch")
    attestation = _attestation_object(attestation_object, _work=_work)
    auth_data = attestation.get("authData")
    parsed = parse_authenticator_data(auth_data, rp_id=rp_id, _work=_work)
    if not parsed["attested_credential_data"]:
        raise WebAuthnError("registration missing attested credential data")
    if len(auth_data) < 55:
        raise WebAuthnError("registration authenticator data is truncated")
    aaguid = auth_data[37:53]
    credential_length = int.from_bytes(auth_data[53:55], "big")
    if not 1 <= credential_length <= MAX_CREDENTIAL_ID_BYTES:
        raise WebAuthnError("registration credential ID is oversized")
    end = 55 + credential_length
    if len(auth_data) <= end:
        raise WebAuthnError("registration credential data is truncated")
    if _work is not None:
        # Exact slices, base64 encoder, ASCII decode and trailing-strip output.
        encoded_length = 4 * ((credential_length + 2) // 3)
        _work.charge(input_bytes=16 + credential_length + len(auth_data) - end + 3 * encoded_length)
    credential_raw = auth_data[55:end]
    if credential_id != base64.urlsafe_b64encode(credential_raw).decode("ascii").rstrip("="):
        raise WebAuthnError("registration response credential id does not match attested credential id")
    public_key_cose = auth_data[end:]
    _bytes(public_key_cose, "COSE public key", MAX_COSE_PUBLIC_KEY_BYTES, _work=_work)
    return ParsedRegistration(
        client_data_json, attestation_object, scope, rp_id, origin,
        credential_id, credential_raw, public_key_cose, auth_data, aaguid,
        parsed["sign_count"], parsed["user_verified"], needs_trust_roots(attestation),
        transports,
    )


def public_key_from_cose(public_key_cose: bytes, *, _work=None) -> ec.EllipticCurvePublicKey:
    if not 1 <= len(public_key_cose) <= MAX_COSE_PUBLIC_KEY_BYTES:
        raise WebAuthnError("WebAuthn COSE public key is oversized")
    if _work is not None:
        _work.charge(input_bytes=len(public_key_cose))
    key = _native(_work, lambda: cbor2.loads(public_key_cose))
    _decoded_work(key, _work)
    if not isinstance(key, dict) or key.get(1) != EC2_KTY or key.get(3) != ES256_ALG or key.get(-1) != P256_CRV:
        raise WebAuthnError("only ES256/P-256 WebAuthn credentials are supported")
    try:
        x = int.from_bytes(key[-2], "big")
        y = int.from_bytes(key[-3], "big")
        return _native(_work, lambda: ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key())
    except (KeyError, TypeError, ValueError) as exc:
        raise WebAuthnError("WebAuthn COSE public key is invalid") from exc


def classify_authenticator(aaguid: str | None, trusted: bool, trust_class: str | None = None) -> str:
    if not trusted:
        return "unknown"
    if trust_class in {"yubikey", "hardware", "platform"}:
        return trust_class
    return "yubikey" if aaguid in YUBIKEY_AAGUIDS else "hardware"


def cert_digest(cert: x509.Certificate, *, _work=None) -> str:
    raw = _native(_work, lambda: cert.public_bytes(serialization.Encoding.DER))
    if _work is not None:
        _bytes(raw, "serialized certificate", MAX_ATTESTATION_CERTIFICATE_BYTES, _work=_work)
    return sha256_prefixed(raw, _work=_work)


def not_before(cert: x509.Certificate) -> datetime:
    value = getattr(cert, "not_valid_before_utc", None)
    return value if value is not None else cert.not_valid_before.replace(tzinfo=timezone.utc)


def not_after(cert: x509.Certificate) -> datetime:
    value = getattr(cert, "not_valid_after_utc", None)
    return value if value is not None else cert.not_valid_after.replace(tzinfo=timezone.utc)


def verify_cert_time(cert: x509.Certificate, verified_at: datetime) -> None:
    if verified_at < not_before(cert) or verified_at > not_after(cert):
        raise WebAuthnError("WebAuthn attestation certificate is not currently valid")


def verify_cert_signature(child: x509.Certificate, issuer: x509.Certificate, *, _work=None) -> None:
    public_key = _native(_work, issuer.public_key)
    signature = _native(_work, lambda: child.signature)
    material = _native(_work, lambda: child.tbs_certificate_bytes)
    if _work is not None:
        _bytes(signature, "certificate signature", MAX_ATTESTATION_CERTIFICATE_BYTES, _work=_work)
        _bytes(material, "certificate signature material", MAX_ATTESTATION_CERTIFICATE_BYTES, _work=_work)
    try:
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            _native(_work, lambda: public_key.verify(signature, material, ec.ECDSA(child.signature_hash_algorithm)))
        elif isinstance(public_key, rsa.RSAPublicKey):
            _native(_work, lambda: public_key.verify(signature, material, padding.PKCS1v15(), child.signature_hash_algorithm))
        else:
            raise WebAuthnError("unsupported WebAuthn attestation certificate key type")
    except InvalidSignature as exc:
        raise WebAuthnError("WebAuthn attestation certificate chain signature invalid") from exc


def is_ca(cert: x509.Certificate) -> bool:
    try:
        return bool(cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca)
    except x509.ExtensionNotFound:
        return False


def aaguid_from_cert(cert: x509.Certificate) -> bytes | None:
    try:
        raw = cert.extensions.get_extension_for_oid(FIDO_AAGUID_EXTENSION).value.value
    except x509.ExtensionNotFound:
        return None
    if len(raw) == 16:
        return raw
    if len(raw) >= 18 and raw[0] == 0x04 and raw[1] == 0x10:
        return raw[2:18]
    return None


def verify_aaguid_extension(cert: x509.Certificate, aaguid: bytes) -> None:
    actual = aaguid_from_cert(cert)
    if actual is not None and actual != aaguid:
        raise WebAuthnError("WebAuthn attestation certificate AAGUID mismatch")


def certs_from_x5c(x5c: Any, *, _work=None) -> list[x509.Certificate]:
    if not isinstance(x5c, list) or not 1 <= len(x5c) <= MAX_ATTESTATION_CHAIN_CERTIFICATES:
        raise WebAuthnError("WebAuthn attestation x5c must be a certificate list")
    certs = []
    total = 0
    for item in x5c:
        if not isinstance(item, bytes) or not 1 <= len(item) <= MAX_ATTESTATION_CERTIFICATE_BYTES:
            raise WebAuthnError("WebAuthn attestation x5c contains a non-certificate item")
        total += len(item)
        if total > MAX_ATTESTATION_CHAIN_BYTES:
            raise WebAuthnError("WebAuthn attestation certificate chain is oversized")
        if _work is not None:
            _work.charge(input_bytes=len(item))
        certs.append(_native(_work, lambda: x509.load_der_x509_certificate(item)))
    return certs


def verify_x5c_chain(certs: list[x509.Certificate], aaguid: bytes, context: VerificationContext, *, _work=None) -> dict[str, Any]:
    untrusted = {
        "trusted": False, "path": [cert_digest(cert, _work=_work) for cert in certs],
        "root_sha256": None, "bundle_digest": None,
        "bundle_sequence": None, "authenticator_class": None,
    }
    if not certs:
        return untrusted
    for cert in certs:
        verify_cert_time(cert, context.verified_at)
    if is_ca(certs[0]):
        raise WebAuthnError("WebAuthn attestation leaf certificate must not be a CA")
    for issuer in certs[1:]:
        if not is_ca(issuer):
            raise WebAuthnError("WebAuthn attestation intermediate certificate must be a CA")
    for child, issuer in zip(certs, certs[1:]):
        if child.issuer != issuer.subject:
            raise WebAuthnError("WebAuthn attestation certificate issuer mismatch")
        verify_cert_signature(child, issuer, _work=_work)
    tail = certs[-1]
    for root in context.trust_roots:
        if root.aaguids and str(uuid.UUID(bytes=aaguid)) not in root.aaguids:
            continue
        if _work is not None:
            _work.charge(input_bytes=len(root.certificate_der))
        root_cert = _native(_work, lambda: x509.load_der_x509_certificate(root.certificate_der))
        verify_cert_time(root_cert, context.verified_at)
        path = [cert_digest(cert, _work=_work) for cert in certs]
        if cert_digest(tail, _work=_work) == root.certificate_sha256:
            if not is_ca(root_cert):
                continue
        elif tail.issuer == root_cert.subject and is_ca(root_cert):
            try:
                verify_cert_signature(tail, root_cert, _work=_work)
            except WebAuthnError:
                continue
            path.append(root.certificate_sha256)
        else:
            continue
        return {
            "trusted": True, "path": path, "root_sha256": root.certificate_sha256,
            "bundle_digest": root.bundle_digest, "bundle_sequence": root.bundle_sequence,
            "authenticator_class": root.authenticator_class,
        }
    return untrusted


def verify_es256_signature(public_key: Any, signature: bytes, signed_data: bytes, error: str, *, _work=None) -> None:
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise WebAuthnError("WebAuthn ES256 attestation key must be an elliptic-curve key")
    try:
        if _work is not None:
            _bytes(signature, "attestation signature", MAX_ATTESTATION_OBJECT_BYTES, _work=_work)
            _bytes(signed_data, "attestation signed material", MAX_AUTHENTICATOR_DATA_BYTES + 32, _work=_work)
        _native(_work, lambda: public_key.verify(signature, signed_data, ec.ECDSA(hashes.SHA256())))
    except InvalidSignature as exc:
        raise WebAuthnError(error) from exc


def _chain_result(fmt: str, certs: list[x509.Certificate], aaguid: bytes, context: VerificationContext, *, _work=None) -> AttestationResult:
    chain = verify_x5c_chain(certs, aaguid, context, _work=_work)
    return AttestationResult(
        fmt, bool(chain["trusted"]), tuple(chain["path"]), cert_digest(certs[0], _work=_work),
        chain["root_sha256"], chain["bundle_digest"], chain["bundle_sequence"],
        chain["authenticator_class"], context.verified_at.isoformat() if chain["trusted"] else None,
    )


def verify_packed_attestation(
    attestation: dict[str, Any], auth_data: bytes, client_hash: bytes,
    aaguid: bytes, public_key: ec.EllipticCurvePublicKey,
    *, context: VerificationContext, _work=None,
) -> AttestationResult:
    statement = attestation.get("attStmt") or {}
    if not isinstance(statement, dict):
        raise WebAuthnError("WebAuthn attestation statement is invalid")
    if statement.get("alg") != ES256_ALG:
        raise WebAuthnError("only ES256 packed WebAuthn attestation is supported")
    signature = statement.get("sig")
    if not isinstance(signature, bytes):
        raise WebAuthnError("packed WebAuthn attestation missing signature")
    x5c = statement.get("x5c")
    if x5c:
        certs = certs_from_x5c(x5c, _work=_work)
        verify_aaguid_extension(certs[0], aaguid)
        if _work is not None:
            _work.charge(input_bytes=len(auth_data) + len(client_hash))
        verify_es256_signature(_native(_work, certs[0].public_key), signature, auth_data + client_hash,
            "packed WebAuthn attestation signature invalid", _work=_work)
        return _chain_result("packed", certs, aaguid, context, _work=_work)
    if _work is not None:
        _work.charge(input_bytes=len(auth_data) + len(client_hash))
    verify_es256_signature(public_key, signature, auth_data + client_hash,
        "packed self-attestation signature invalid", _work=_work)
    return AttestationResult("packed", False)


def verify_fido_u2f_attestation(
    attestation: dict[str, Any], client_hash: bytes, aaguid: bytes,
    credential_id_raw: bytes, public_key: ec.EllipticCurvePublicKey,
    *, context: VerificationContext, _work=None,
) -> AttestationResult:
    statement = attestation.get("attStmt") or {}
    if not isinstance(statement, dict):
        raise WebAuthnError("WebAuthn attestation statement is invalid")
    signature = statement.get("sig")
    if not isinstance(signature, bytes):
        raise WebAuthnError("fido-u2f WebAuthn attestation missing signature")
    certs = certs_from_x5c(statement.get("x5c"), _work=_work)
    verify_aaguid_extension(certs[0], aaguid)
    numbers = _native(_work, public_key.public_numbers)
    if _work is not None:
        _work.prepare_utf8(context.rp_id)
        _work.charge(input_bytes=65 + 32 + len(client_hash) + len(credential_id_raw) + 66)
    uncompressed = b"\x04" + numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big")
    rp_bytes = context.rp_id.encode("utf-8")
    if _work is not None:
        _work.charge(hashes=1, input_bytes=len(rp_bytes))
    signed = b"\x00" + hashlib.sha256(rp_bytes).digest() + client_hash + credential_id_raw + uncompressed
    verify_es256_signature(_native(_work, certs[0].public_key), signature, signed,
        "fido-u2f WebAuthn attestation signature invalid", _work=_work)
    return _chain_result("fido-u2f", certs, aaguid, context, _work=_work)


def verify_attestation_statement(
    attestation: dict[str, Any], auth_data: bytes, client_data_raw: bytes,
    aaguid: bytes, credential_id_raw: bytes, public_key_cose: bytes,
    *, context: VerificationContext, _work=None,
) -> AttestationResult:
    """Shared cryptography; recovery supplies its own independently checked scope."""
    fmt = attestation.get("fmt")
    public_key = public_key_from_cose(public_key_cose, _work=_work)
    if _work is not None:
        _work.charge(hashes=1, input_bytes=len(client_data_raw))
    client_hash = hashlib.sha256(client_data_raw).digest()
    if fmt == "packed":
        return verify_packed_attestation(attestation, auth_data, client_hash, aaguid, public_key, context=context, _work=_work)
    if fmt == "fido-u2f":
        return verify_fido_u2f_attestation(attestation, client_hash, aaguid, credential_id_raw, public_key, context=context, _work=_work)
    # Preserve ordinary registration's untrusted none/unknown formats.
    normalized_fmt = str(fmt or "unknown")
    _text(normalized_fmt, "attestation format", MAX_ATTESTATION_OBJECT_BYTES, _work=_work)
    return AttestationResult(normalized_fmt, False)


def verify_registration_attestation(parsed: ParsedRegistration, context: VerificationContext, *, _work=None) -> RegistrationAttestationResult:
    _require_work(_work)
    if not isinstance(parsed, ParsedRegistration) or not isinstance(context, VerificationContext):
        raise WebAuthnError("WebAuthn registration verification context is invalid")
    # Parsed dataclasses are not an authority capability. Recompute every
    # derived field from retained bytes so replace()/direct construction cannot
    # splice a different key, counter, ID, flags, root-loading hint or RP scope.
    expected = parse_registration_data(
        parsed.client_data_json, parsed.attestation_object, parsed.credential_id,
        scope=parsed.scope, rp_id=context.rp_id, origin=context.origin,
        transports=parsed.transports, _work=_work,
    )
    if _work is not None:
        for value in (parsed, expected):
            # Dataclass equality really compares retained raw fields too, not
            # merely their previously computed hashes. Reserve that scan.
            for field in fields(ParsedRegistration):
                member = getattr(value, field.name)
                if field.name == "scope":
                    _decoded_work((member.challenge_id, member.challenge, member.user_id,
                        member.label, member.authorization_json), _work)
                else:
                    _decoded_work(member, _work)
    if parsed != expected or any(
        type(getattr(parsed, field.name)) is not type(getattr(expected, field.name))
        for field in fields(ParsedRegistration)
    ):
        raise WebAuthnError("WebAuthn parsed registration binding changed")
    parsed = expected
    attestation = verify_attestation_statement(
        _attestation_object(parsed.attestation_object, _work=_work), parsed.auth_data,
        parsed.client_data_json, parsed.aaguid_raw, parsed.credential_id_raw,
        parsed.public_key_cose, context=context, _work=_work,
    )
    aaguid = str(uuid.UUID(bytes=parsed.aaguid_raw))
    return RegistrationAttestationResult(
        parsed.credential_id, parsed.public_key_cose, parsed.sign_count,
        parsed.user_verified, aaguid,
        classify_authenticator(aaguid, attestation.trusted, attestation.trust_class),
        parsed.transports, attestation, sha256_prefixed(parsed.client_data_json, _work=_work),
        sha256_prefixed(parsed.attestation_object, _work=_work), parsed.scope.commitment(_work=_work), context.commitment(_work=_work),
    )
