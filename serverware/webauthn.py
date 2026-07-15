from __future__ import annotations

import base64
import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any

import cbor2
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtensionOID, ObjectIdentifier

from serverware import db
from serverware.config import (
    DEV_AUTHENTICATOR_ENABLED,
    WEBAUTHN_ORIGIN,
    WEBAUTHN_RP_ID,
    WEBAUTHN_RP_NAME,
)
from serverware.policy_bundle import canonical_json
from serverware.webauthn_trust import TrustRoot, WebAuthnTrustError, load_trust_roots


UP_FLAG = 0x01
UV_FLAG = 0x04
AT_FLAG = 0x40
ES256_ALG = -7
EC2_KTY = 2
P256_CRV = 1
YUBIKEY_AAGUIDS = {
    "2fc0579f-8113-47ea-b116-bb5a8db9202a",
    "fa2b99dc-9e39-4257-8f92-4a30d23c4118",
    "ee041bce-25e5-4cdb-8f86-897fd6418464",
    "cb69481e-8ff7-4039-93ec-0a2729a154a8",
}
FIDO_AAGUID_EXTENSION = ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4")


class WebAuthnError(ValueError):
    pass


def b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64ud(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def _sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _json_b64(value: dict[str, Any]) -> str:
    return b64u(json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _rp_hash() -> bytes:
    return _sha256(WEBAUTHN_RP_ID.encode("utf-8"))


def _parse_client_data(client_data_b64: str, expected_type: str) -> tuple[dict[str, Any], bytes]:
    raw = b64ud(client_data_b64)
    try:
        client_data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise WebAuthnError("invalid clientDataJSON") from exc
    if client_data.get("type") != expected_type:
        raise WebAuthnError(f"unexpected WebAuthn clientDataJSON type {client_data.get('type')}")
    if client_data.get("origin") != WEBAUTHN_ORIGIN:
        raise WebAuthnError("WebAuthn origin mismatch")
    if client_data.get("crossOrigin"):
        raise WebAuthnError("cross-origin WebAuthn assertions are not accepted")
    return client_data, raw


def _parse_authenticator_data(auth_data: bytes) -> dict[str, Any]:
    if len(auth_data) < 37:
        raise WebAuthnError("authenticatorData is too short")
    if auth_data[:32] != _rp_hash():
        raise WebAuthnError("WebAuthn RP ID hash mismatch")
    flags = auth_data[32]
    if not flags & UP_FLAG:
        raise WebAuthnError("authenticator user presence flag missing")
    return {
        "flags": flags,
        "user_present": bool(flags & UP_FLAG),
        "user_verified": bool(flags & UV_FLAG),
        "attested_credential_data": bool(flags & AT_FLAG),
        "sign_count": int.from_bytes(auth_data[33:37], "big"),
    }


def _aaguid_to_text(value: bytes) -> str:
    return str(uuid.UUID(bytes=value))


def _classify_authenticator(aaguid: str | None, attestation_trusted: bool, trust_class: str | None = None) -> str:
    if not attestation_trusted:
        return "unknown"
    if trust_class in {"yubikey", "hardware", "platform"}:
        return trust_class
    if aaguid in YUBIKEY_AAGUIDS:
        return "yubikey"
    return "hardware"


def _public_key_from_cose(public_key_cose: bytes) -> ec.EllipticCurvePublicKey:
    key = cbor2.loads(public_key_cose)
    if key.get(1) != EC2_KTY or key.get(3) != ES256_ALG or key.get(-1) != P256_CRV:
        raise WebAuthnError("only ES256/P-256 WebAuthn credentials are supported")
    x = int.from_bytes(key[-2], "big")
    y = int.from_bytes(key[-3], "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def _cose_from_public_key(public_key: ec.EllipticCurvePublicKey) -> bytes:
    numbers = public_key.public_numbers()
    return cbor2.dumps(
        {
            1: EC2_KTY,
            3: ES256_ALG,
            -1: P256_CRV,
            -2: numbers.x.to_bytes(32, "big"),
            -3: numbers.y.to_bytes(32, "big"),
        }
    )


def _u2f_uncompressed_public_key(public_key: ec.EllipticCurvePublicKey) -> bytes:
    numbers = public_key.public_numbers()
    return b"\x04" + numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big")


def _credential_descriptor(credential: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "public-key",
        "id": credential["credential_id"],
        "transports": credential.get("transports") or ["usb", "nfc", "ble", "internal"],
    }


def _cert_digest(cert: x509.Certificate) -> str:
    return _sha256_prefixed(cert.public_bytes(serialization.Encoding.DER))


def _not_before(cert: x509.Certificate) -> datetime:
    value = getattr(cert, "not_valid_before_utc", None)
    if value is not None:
        return value
    return cert.not_valid_before.replace(tzinfo=timezone.utc)


def _not_after(cert: x509.Certificate) -> datetime:
    value = getattr(cert, "not_valid_after_utc", None)
    if value is not None:
        return value
    return cert.not_valid_after.replace(tzinfo=timezone.utc)


def _verify_cert_time(cert: x509.Certificate) -> None:
    now = datetime.now(timezone.utc)
    if now < _not_before(cert) or now > _not_after(cert):
        raise WebAuthnError("WebAuthn attestation certificate is not currently valid")


def _verify_cert_signature(child: x509.Certificate, issuer: x509.Certificate) -> None:
    public_key = issuer.public_key()
    try:
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))
        elif isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(child.signature, child.tbs_certificate_bytes, padding.PKCS1v15(), child.signature_hash_algorithm)
        else:
            raise WebAuthnError("unsupported WebAuthn attestation certificate key type")
    except InvalidSignature as exc:
        raise WebAuthnError("WebAuthn attestation certificate chain signature invalid") from exc


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        return bool(cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca)
    except x509.ExtensionNotFound:
        return False


def _aaguid_from_cert(cert: x509.Certificate) -> bytes | None:
    try:
        raw = cert.extensions.get_extension_for_oid(FIDO_AAGUID_EXTENSION).value.value
    except x509.ExtensionNotFound:
        return None
    if len(raw) == 16:
        return raw
    if len(raw) >= 18 and raw[0] == 0x04 and raw[1] == 0x10:
        return raw[2:18]
    return None


def _verify_aaguid_extension(cert: x509.Certificate, aaguid: bytes) -> None:
    cert_aaguid = _aaguid_from_cert(cert)
    if cert_aaguid is not None and cert_aaguid != aaguid:
        raise WebAuthnError("WebAuthn attestation certificate AAGUID mismatch")


def _root_allows_aaguid(root: TrustRoot, aaguid: bytes) -> bool:
    if not root.aaguids:
        return True
    return _aaguid_to_text(aaguid) in root.aaguids


def _verify_x5c_chain(certs: list[x509.Certificate], aaguid: bytes) -> dict[str, Any]:
    if not certs:
        return {"trusted": False, "path": [], "root_sha256": None, "bundle_digest": None, "bundle_sequence": None, "authenticator_class": None}
    for cert in certs:
        _verify_cert_time(cert)
    leaf = certs[0]
    try:
        if _is_ca(leaf):
            raise WebAuthnError("WebAuthn attestation leaf certificate must not be a CA")
        for issuer in certs[1:]:
            if not _is_ca(issuer):
                raise WebAuthnError("WebAuthn attestation intermediate certificate must be a CA")
        for child, issuer in zip(certs, certs[1:]):
            if child.issuer != issuer.subject:
                raise WebAuthnError("WebAuthn attestation certificate issuer mismatch")
            _verify_cert_signature(child, issuer)
    except WebAuthnError:
        raise

    try:
        trusted_roots = load_trust_roots()
    except WebAuthnTrustError as exc:
        raise WebAuthnError(str(exc)) from exc
    if not trusted_roots:
        return {
            "trusted": False,
            "path": [_cert_digest(cert) for cert in certs],
            "root_sha256": None,
            "bundle_digest": None,
            "bundle_sequence": None,
            "authenticator_class": None,
        }
    chain_tail = certs[-1]
    for root in trusted_roots:
        root_cert = root.cert
        if not _root_allows_aaguid(root, aaguid):
            continue
        _verify_cert_time(root_cert)
        if _cert_digest(chain_tail) == _cert_digest(root_cert):
            if not _is_ca(root_cert):
                continue
            return {
                "trusted": True,
                "path": [_cert_digest(cert) for cert in certs],
                "root_sha256": root.certificate_sha256,
                "bundle_digest": root.bundle_digest,
                "bundle_sequence": root.bundle_sequence,
                "authenticator_class": root.authenticator_class,
            }
        if chain_tail.issuer == root_cert.subject and _is_ca(root_cert):
            try:
                _verify_cert_signature(chain_tail, root_cert)
            except WebAuthnError:
                continue
            return {
                "trusted": True,
                "path": [_cert_digest(cert) for cert in certs] + [root.certificate_sha256],
                "root_sha256": root.certificate_sha256,
                "bundle_digest": root.bundle_digest,
                "bundle_sequence": root.bundle_sequence,
                "authenticator_class": root.authenticator_class,
            }
    return {
        "trusted": False,
        "path": [_cert_digest(cert) for cert in certs],
        "root_sha256": None,
        "bundle_digest": None,
        "bundle_sequence": None,
        "authenticator_class": None,
    }


def _certs_from_x5c(x5c: Any) -> list[x509.Certificate]:
    if not isinstance(x5c, list):
        raise WebAuthnError("WebAuthn attestation x5c must be a certificate list")
    certs: list[x509.Certificate] = []
    for item in x5c:
        if not isinstance(item, bytes):
            raise WebAuthnError("WebAuthn attestation x5c contains a non-certificate item")
        certs.append(x509.load_der_x509_certificate(item))
    return certs


def _verify_es256_signature(public_key: Any, signature: bytes, signed_data: bytes, error: str) -> None:
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise WebAuthnError("WebAuthn ES256 attestation key must be an elliptic-curve key")
    try:
        public_key.verify(signature, signed_data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise WebAuthnError(error) from exc


def _verify_packed_attestation(
    attestation: dict[str, Any],
    auth_data: bytes,
    client_data_hash: bytes,
    aaguid: bytes,
    credential_public_key: ec.EllipticCurvePublicKey,
) -> dict[str, Any]:
    att_stmt = attestation.get("attStmt") or {}
    if att_stmt.get("alg") != ES256_ALG:
        raise WebAuthnError("only ES256 packed WebAuthn attestation is supported")
    signature = att_stmt.get("sig")
    if not isinstance(signature, bytes):
        raise WebAuthnError("packed WebAuthn attestation missing signature")
    signed_data = auth_data + client_data_hash
    x5c = att_stmt.get("x5c")
    if x5c:
        certs = _certs_from_x5c(x5c)
        leaf = certs[0]
        _verify_aaguid_extension(leaf, aaguid)
        _verify_es256_signature(leaf.public_key(), signature, signed_data, "packed WebAuthn attestation signature invalid")
        chain = _verify_x5c_chain(certs, aaguid)
        return {
            "fmt": "packed",
            "trusted": bool(chain["trusted"]),
            "trust_path": chain["path"],
            "leaf_sha256": _cert_digest(leaf),
            "root_sha256": chain["root_sha256"],
            "trust_bundle_digest": chain["bundle_digest"],
            "trust_bundle_sequence": chain["bundle_sequence"],
            "trust_class": chain["authenticator_class"],
            "verified_at": db.iso_now() if chain["trusted"] else None,
        }
    _verify_es256_signature(
        credential_public_key,
        signature,
        signed_data,
        "packed self-attestation signature invalid",
    )
    return {
        "fmt": "packed",
        "trusted": False,
        "trust_path": [],
        "leaf_sha256": None,
        "root_sha256": None,
        "trust_bundle_digest": None,
        "trust_bundle_sequence": None,
        "trust_class": None,
        "verified_at": None,
    }


def _verify_fido_u2f_attestation(
    attestation: dict[str, Any],
    client_data_hash: bytes,
    aaguid: bytes,
    credential_id_raw: bytes,
    credential_public_key: ec.EllipticCurvePublicKey,
) -> dict[str, Any]:
    att_stmt = attestation.get("attStmt") or {}
    signature = att_stmt.get("sig")
    if not isinstance(signature, bytes):
        raise WebAuthnError("fido-u2f WebAuthn attestation missing signature")
    certs = _certs_from_x5c(att_stmt.get("x5c"))
    leaf = certs[0]
    _verify_aaguid_extension(leaf, aaguid)
    signed_data = b"\x00" + _rp_hash() + client_data_hash + credential_id_raw + _u2f_uncompressed_public_key(credential_public_key)
    _verify_es256_signature(leaf.public_key(), signature, signed_data, "fido-u2f WebAuthn attestation signature invalid")
    chain = _verify_x5c_chain(certs, aaguid)
    return {
        "fmt": "fido-u2f",
        "trusted": bool(chain["trusted"]),
        "trust_path": chain["path"],
        "leaf_sha256": _cert_digest(leaf),
        "root_sha256": chain["root_sha256"],
        "trust_bundle_digest": chain["bundle_digest"],
        "trust_bundle_sequence": chain["bundle_sequence"],
        "trust_class": chain["authenticator_class"],
        "verified_at": db.iso_now() if chain["trusted"] else None,
    }


def _verify_attestation_statement(
    attestation: dict[str, Any],
    auth_data: bytes,
    client_data_raw: bytes,
    aaguid: bytes,
    credential_id_raw: bytes,
    public_key_cose: bytes,
) -> dict[str, Any]:
    fmt = attestation.get("fmt")
    credential_public_key = _public_key_from_cose(public_key_cose)
    client_data_hash = _sha256(client_data_raw)
    if fmt == "packed":
        return _verify_packed_attestation(attestation, auth_data, client_data_hash, aaguid, credential_public_key)
    if fmt == "fido-u2f":
        return _verify_fido_u2f_attestation(attestation, client_data_hash, aaguid, credential_id_raw, credential_public_key)
    if fmt == "none":
        return {
            "fmt": "none",
            "trusted": False,
            "trust_path": [],
            "leaf_sha256": None,
            "root_sha256": None,
            "trust_bundle_digest": None,
            "trust_bundle_sequence": None,
            "trust_class": None,
            "verified_at": None,
        }
    return {
        "fmt": str(fmt or "unknown"),
        "trusted": False,
        "trust_path": [],
        "leaf_sha256": None,
        "root_sha256": None,
        "trust_bundle_digest": None,
        "trust_bundle_sequence": None,
        "trust_class": None,
        "verified_at": None,
    }


def registration_options(
    user_id: str,
    label: str,
    *,
    authorization: dict[str, Any] | None = None,
) -> dict[str, Any]:
    nonce = b64u(os.urandom(32))
    challenge = b64u(_sha256(canonical_json({"type": "register", "user": user_id, "nonce": nonce}).encode("utf-8")))
    db.create_webauthn_challenge(
        challenge=challenge,
        challenge_type="registration",
        user_id=user_id,
        payload={
            "type": "registration",
            "user_id": user_id,
            "label": label,
            "nonce": nonce,
            "authorization": authorization,
        },
        ttl_seconds=300,
    )
    return {
        "publicKey": {
            "rp": {"name": WEBAUTHN_RP_NAME, "id": WEBAUTHN_RP_ID},
            "user": {"id": b64u(user_id.encode("utf-8")), "name": user_id, "displayName": user_id},
            "challenge": challenge,
            "pubKeyCredParams": [{"type": "public-key", "alg": ES256_ALG}],
            "timeout": 300000,
            "attestation": "direct",
            "authenticatorSelection": {
                "residentKey": "discouraged",
                "userVerification": "preferred",
                "authenticatorAttachment": "cross-platform",
            },
        },
        "serverware": {
            "authorizationMode": (authorization or {}).get("mode"),
            "payloadDigest": (authorization or {}).get("payload_digest"),
        },
    }


def verify_registration(
    user_id: str,
    label: str,
    response: dict[str, Any],
    *,
    require_authorization: bool = False,
) -> dict[str, Any]:
    credential_id = response.get("id") or response.get("rawId")
    if not isinstance(credential_id, str):
        raise WebAuthnError("registration response missing credential id")
    attestation = cbor2.loads(b64ud(response["response"]["attestationObject"]))
    client_data, client_data_raw = _parse_client_data(response["response"]["clientDataJSON"], "webauthn.create")
    challenge = db.claim_webauthn_challenge(
        client_data["challenge"],
        challenge_type="registration",
        user_id=user_id,
    )
    if not challenge:
        raise WebAuthnError("registration challenge not found or expired")
    authorization = challenge.get("payload", {}).get("authorization")
    if require_authorization:
        if not isinstance(authorization, dict) or authorization.get("mode") not in {
            "bootstrap-token",
            "development-bootstrap",
            "existing-webauthn",
        }:
            raise WebAuthnError("registration challenge lacks enrollment authorization")
        if not isinstance(authorization.get("payload_digest"), str):
            raise WebAuthnError("registration challenge authorization is not digest-bound")
    auth_data = attestation.get("authData")
    parsed = _parse_authenticator_data(auth_data)
    if not parsed["attested_credential_data"]:
        raise WebAuthnError("registration missing attested credential data")
    cursor = 37
    aaguid_raw = auth_data[cursor:cursor + 16]
    aaguid = _aaguid_to_text(aaguid_raw)
    cursor += 16
    credential_len = int.from_bytes(auth_data[cursor:cursor + 2], "big")
    cursor += 2
    credential_id_raw = auth_data[cursor:cursor + credential_len]
    registered_credential_id = b64u(credential_id_raw)
    if credential_id != registered_credential_id:
        raise WebAuthnError(
            "registration response credential id does not match attested credential id"
        )
    if db.get_webauthn_credential(
        registered_credential_id, include_revoked=True
    ) is not None:
        raise WebAuthnError(
            "WebAuthn credential ID was already registered and cannot be reused"
        )
    cursor += credential_len
    public_key_cose = auth_data[cursor:]
    attestation_result = _verify_attestation_statement(
        attestation,
        auth_data,
        client_data_raw,
        aaguid_raw,
        credential_id_raw,
        public_key_cose,
    )
    attestation_trusted = bool(attestation_result["trusted"])
    try:
        stored = db.create_webauthn_credential(
            credential_id=registered_credential_id,
            user_id=user_id,
            label=label,
            public_key_cose=b64u(public_key_cose),
            sign_count=parsed["sign_count"],
            aaguid=aaguid,
            authenticator_class=_classify_authenticator(aaguid, attestation_trusted, attestation_result.get("trust_class")),
            attestation_fmt=attestation_result["fmt"],
            attestation_trusted=attestation_trusted,
            attestation_trust_path=attestation_result["trust_path"],
            attestation_leaf_sha256=attestation_result["leaf_sha256"],
            attestation_root_sha256=attestation_result["root_sha256"],
            attestation_trust_bundle_digest=attestation_result.get("trust_bundle_digest"),
            attestation_trust_bundle_sequence=attestation_result.get("trust_bundle_sequence"),
            attestation_verified_at=attestation_result["verified_at"],
            transports=response.get("transports") or [],
        )
    except ValueError as exc:
        raise WebAuthnError(str(exc)) from exc
    redacted = _redact_credential(stored)
    if require_authorization:
        redacted["_registration_authorization"] = authorization
    return redacted


def _approval_challenge_payload(
    approval: dict[str, Any],
    user_id: str,
    review_receipt: dict[str, Any],
) -> dict[str, Any]:
    redacted_display = approval.get("redacted_display") or {}
    return {
        "v": 2,
        "type": "serverware.approval.reviewed",
        "approval_id": approval["id"],
        "user_id": user_id,
        "route_id": approval.get("route_id"),
        "credential_ref": approval.get("credential_id"),
        "credential_version": approval.get("credential_version"),
        "policy_hash": approval.get("policy_hash"),
        "request_digest": approval.get("request_digest"),
        "operation_digest": approval.get("operation_digest"),
        "approval_expires_at": approval.get("expires_at"),
        "grant_ttl_seconds": approval.get("grant_ttl_seconds"),
        "grant_max_uses": approval.get("grant_max_uses"),
        "consume_mode": "forwardStart",
        "redacted_display_digest": "sha256:" + hashlib.sha256(canonical_json(redacted_display).encode("utf-8")).hexdigest(),
        "review_receipt_id": review_receipt["id"],
        "review_digest": review_receipt["review_digest"],
        "review_receipt_expires_at": review_receipt["expires_at"],
        "nonce": b64u(os.urandom(24)),
    }


def approval_options(
    approval: dict[str, Any],
    user_id: str,
    authn_policy: dict[str, Any],
    review_receipt: dict[str, Any],
) -> dict[str, Any]:
    payload = _approval_challenge_payload(approval, user_id, review_receipt)
    challenge = b64u(_sha256(canonical_json(payload).encode("utf-8")))
    challenge_row = db.create_webauthn_challenge(
        challenge=challenge,
        challenge_type="approval",
        user_id=user_id,
        approval_request_id=approval["id"],
        payload=payload,
        ttl_seconds=120,
    )
    credentials = _credential_descriptors_for_policy(user_id, authn_policy)
    return {
        "publicKey": {
            "challenge": challenge,
            "rpId": WEBAUTHN_RP_ID,
            "allowCredentials": credentials,
            "timeout": 120000,
            "userVerification": authn_policy.get("userVerification", "required"),
        },
        "serverware": {
            "challenge_id": challenge_row["id"],
            "payload": payload,
            "payload_digest": "sha256:" + hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest(),
        },
    }


def control_plane_mutation_options(
    *,
    user_id: str,
    action: str,
    resource_id: str | None,
    payload_digest: str,
    authn_policy: dict[str, Any],
) -> dict[str, Any]:
    payload = {
        "v": 1,
        "type": "serverware.control_plane_mutation",
        "user_id": user_id,
        "action": action,
        "resource_id": resource_id,
        "payload_digest": payload_digest,
        "nonce": b64u(os.urandom(24)),
    }
    challenge = b64u(_sha256(canonical_json(payload).encode("utf-8")))
    challenge_row = db.create_webauthn_challenge(
        challenge=challenge,
        challenge_type="control-plane-mutation",
        user_id=user_id,
        payload=payload,
        ttl_seconds=120,
    )
    credentials = _credential_descriptors_for_policy(user_id, authn_policy)
    return {
        "publicKey": {
            "challenge": challenge,
            "rpId": WEBAUTHN_RP_ID,
            "allowCredentials": credentials,
            "timeout": 120000,
            "userVerification": authn_policy.get("userVerification", "required"),
        },
        "serverware": {
            "challenge_id": challenge_row["id"],
            "payload": payload,
            "payload_digest": "sha256:" + hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest(),
        },
    }


def credential_trust_status(
    credential: dict[str, Any], *, trust_roots: list[TrustRoot] | None = None
) -> dict[str, Any]:
    enrollment_trusted = bool(credential.get("attestation_trusted"))
    stored_class = str(credential.get("authenticator_class") or "unknown")
    if (
        stored_class == "dev"
        and DEV_AUTHENTICATOR_ENABLED
        and credential.get("dev_private_key_pem")
    ):
        return {
            "enrollment_trusted": enrollment_trusted,
            "currently_trusted": enrollment_trusted,
            "reason": "development_authenticator" if enrollment_trusted else "not_attested",
            "effective_authenticator_class": "dev" if enrollment_trusted else "unknown",
            "current_trust_bundle_digest": credential.get(
                "attestation_trust_bundle_digest"
            ),
            "current_trust_bundle_sequence": credential.get(
                "attestation_trust_bundle_sequence"
            ),
        }
    if not enrollment_trusted:
        return {
            "enrollment_trusted": False,
            "currently_trusted": False,
            "reason": "not_attested",
            "effective_authenticator_class": "unknown",
            "current_trust_bundle_digest": None,
            "current_trust_bundle_sequence": None,
        }
    root_digest = credential.get("attestation_root_sha256")
    if not root_digest:
        return {
            "enrollment_trusted": True,
            "currently_trusted": False,
            "reason": "attestation_root_missing",
            "effective_authenticator_class": "unknown",
            "current_trust_bundle_digest": None,
            "current_trust_bundle_sequence": None,
        }
    roots = load_trust_roots() if trust_roots is None else trust_roots
    root = next(
        (item for item in roots if item.certificate_sha256 == root_digest), None
    )
    if root is None:
        return {
            "enrollment_trusted": True,
            "currently_trusted": False,
            "reason": "trust_root_withdrawn",
            "effective_authenticator_class": "unknown",
            "current_trust_bundle_digest": None,
            "current_trust_bundle_sequence": None,
        }
    aaguid = str(credential.get("aaguid") or "").lower()
    if root.aaguids and aaguid not in {item.lower() for item in root.aaguids}:
        return {
            "enrollment_trusted": True,
            "currently_trusted": False,
            "reason": "aaguid_no_longer_trusted",
            "effective_authenticator_class": "unknown",
            "current_trust_bundle_digest": root.bundle_digest,
            "current_trust_bundle_sequence": root.bundle_sequence,
        }
    if root.authenticator_class and root.authenticator_class != stored_class:
        return {
            "enrollment_trusted": True,
            "currently_trusted": False,
            "reason": "authenticator_class_changed",
            "effective_authenticator_class": "unknown",
            "current_trust_bundle_digest": root.bundle_digest,
            "current_trust_bundle_sequence": root.bundle_sequence,
        }
    return {
        "enrollment_trusted": True,
        "currently_trusted": True,
        "reason": "trusted_by_current_root",
        "effective_authenticator_class": stored_class,
        "current_trust_bundle_digest": root.bundle_digest,
        "current_trust_bundle_sequence": root.bundle_sequence,
        "current_trust_root_id": root.id,
        "current_trust_root_sha256": root.certificate_sha256,
    }


def _credential_descriptors_for_policy(
    user_id: str, authn_policy: dict[str, Any]
) -> list[dict[str, Any]]:
    credentials = db.list_webauthn_credentials(user_id)
    roots: list[TrustRoot] | None = None
    if any(
        item.get("attestation_trusted")
        and not (
            item.get("authenticator_class") == "dev"
            and DEV_AUTHENTICATOR_ENABLED
            and item.get("dev_private_key_pem")
        )
        for item in credentials
    ):
        try:
            roots = load_trust_roots()
        except WebAuthnTrustError:
            return []
    eligible: list[dict[str, Any]] = []
    for item in credentials:
        try:
            _allowed_authenticator(item, authn_policy, trust_roots=roots)
        except WebAuthnError:
            continue
        eligible.append(_credential_descriptor(item))
    return eligible


def _allowed_authenticator(
    credential: dict[str, Any],
    authn_policy: dict[str, Any],
    *,
    trust_roots: list[TrustRoot] | None = None,
) -> dict[str, Any]:
    try:
        trust = credential_trust_status(credential, trust_roots=trust_roots)
    except WebAuthnTrustError as exc:
        raise WebAuthnError(f"WebAuthn attestation trust unavailable: {exc}") from exc
    allowed = set(authn_policy.get("allowedAuthenticatorClasses") or [])
    credential_classes = {trust["effective_authenticator_class"]}
    if trust["currently_trusted"] and trust["effective_authenticator_class"] != "platform":
        credential_classes.add("hardware")
    if allowed and not allowed.intersection(credential_classes):
        if trust["reason"] == "trust_root_withdrawn":
            raise WebAuthnError("authenticator attestation trust root was withdrawn")
        raise WebAuthnError(
            f"authenticator class {trust['effective_authenticator_class']} is not allowed"
        )
    if authn_policy.get("requireHardwareAttestation") and not trust["currently_trusted"]:
        if trust["reason"] == "trust_root_withdrawn":
            raise WebAuthnError("authenticator attestation trust root was withdrawn")
        raise WebAuthnError("trusted hardware attestation required")
    return trust


def _verify_assertion_signature(credential: dict[str, Any], response: dict[str, Any], authn_policy: dict[str, Any]) -> dict[str, Any]:
    client_data, client_data_raw = _parse_client_data(response["clientDataJSON"], "webauthn.get")
    auth_data = b64ud(response["authenticatorData"])
    parsed = _parse_authenticator_data(auth_data)
    if authn_policy.get("userVerification") == "required" and not parsed["user_verified"]:
        raise WebAuthnError("user verification required")
    public_key = _public_key_from_cose(b64ud(credential["public_key_cose"]))
    signed = auth_data + _sha256(client_data_raw)
    try:
        public_key.verify(b64ud(response["signature"]), signed, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise WebAuthnError("WebAuthn assertion signature invalid") from exc
    if parsed["sign_count"] and credential["sign_count"] and parsed["sign_count"] <= credential["sign_count"]:
        raise WebAuthnError("authenticator sign counter did not advance")
    return {"client_data": client_data, "parsed": parsed}


def verify_approval_assertion(
    approval: dict[str, Any],
    user_id: str,
    authn_policy: dict[str, Any],
    assertion: dict[str, Any],
    review_receipt: dict[str, Any],
) -> dict[str, Any]:
    credential_id = assertion.get("id") or assertion.get("rawId")
    credential = db.get_webauthn_credential(credential_id)
    if not credential:
        raise WebAuthnError("registered WebAuthn credential not found")
    if credential["user_id"] != user_id:
        raise WebAuthnError("WebAuthn credential belongs to a different user")
    trust = _allowed_authenticator(credential, authn_policy)

    response = assertion.get("response") or {}
    verified = _verify_assertion_signature(credential, response, authn_policy)
    client_data = verified["client_data"]
    parsed = verified["parsed"]
    challenge = db.claim_webauthn_challenge(
        client_data["challenge"],
        challenge_type="approval",
        user_id=user_id,
        approval_request_id=approval["id"],
    )
    if not challenge:
        raise WebAuthnError("approval challenge not found or expired")
    payload = challenge["payload"]
    for field in (
        "approval_id",
        "request_digest",
        "operation_digest",
        "credential_ref",
        "credential_version",
        "policy_hash",
        "approval_expires_at",
        "grant_ttl_seconds",
        "grant_max_uses",
        "review_receipt_id",
        "review_digest",
        "review_receipt_expires_at",
    ):
        if payload.get(field) != {
            "approval_id": approval["id"],
            "request_digest": approval.get("request_digest"),
            "operation_digest": approval.get("operation_digest"),
            "credential_ref": approval.get("credential_id"),
            "credential_version": approval.get("credential_version"),
            "policy_hash": approval.get("policy_hash"),
            "approval_expires_at": approval.get("expires_at"),
            "grant_ttl_seconds": approval.get("grant_ttl_seconds"),
            "grant_max_uses": approval.get("grant_max_uses"),
            "review_receipt_id": review_receipt["id"],
            "review_digest": review_receipt["review_digest"],
            "review_receipt_expires_at": review_receipt["expires_at"],
        }[field]:
            raise WebAuthnError(f"approval challenge {field} mismatch")
    expected_display_digest = "sha256:" + hashlib.sha256(
        canonical_json(approval.get("redacted_display") or {}).encode("utf-8")
    ).hexdigest()
    if payload.get("redacted_display_digest") != expected_display_digest:
        raise WebAuthnError("approval challenge redacted_display_digest mismatch")

    if not db.compare_and_swap_webauthn_sign_count(
        credential_id,
        expected_sign_count=credential["sign_count"],
        new_sign_count=parsed["sign_count"],
    ):
        raise WebAuthnError("authenticator sign counter changed concurrently")
    return {
        "method": "webauthn",
        "user_id": user_id,
        "credential_id": credential_id,
        "credential_record_id": credential["id"],
        "authenticator_class": credential["authenticator_class"],
        "aaguid": credential.get("aaguid"),
        "attestation_trusted": trust["currently_trusted"],
        "attestation_enrollment_trusted": trust["enrollment_trusted"],
        "attestation_trust_reason": trust["reason"],
        "effective_authenticator_class": trust["effective_authenticator_class"],
        "current_trust_bundle_digest": trust.get("current_trust_bundle_digest"),
        "current_trust_bundle_sequence": trust.get("current_trust_bundle_sequence"),
        "attestation_root_sha256": credential.get("attestation_root_sha256"),
        "user_present": parsed["user_present"],
        "user_verified": parsed["user_verified"],
        "sign_count": parsed["sign_count"],
        "challenge_id": challenge["id"],
        "review_receipt_id": review_receipt["id"],
        "review_digest": review_receipt["review_digest"],
    }


def verify_control_plane_mutation_assertion(
    *,
    user_id: str,
    action: str,
    resource_id: str | None,
    payload_digest: str,
    authn_policy: dict[str, Any],
    assertion: dict[str, Any],
) -> dict[str, Any]:
    credential_id = assertion.get("id") or assertion.get("rawId")
    credential = db.get_webauthn_credential(credential_id)
    if not credential:
        raise WebAuthnError("registered WebAuthn credential not found")
    if credential["user_id"] != user_id:
        raise WebAuthnError("WebAuthn credential belongs to a different user")
    trust = _allowed_authenticator(credential, authn_policy)

    response = assertion.get("response") or {}
    verified = _verify_assertion_signature(credential, response, authn_policy)
    client_data = verified["client_data"]
    parsed = verified["parsed"]
    challenge = db.claim_webauthn_challenge(
        client_data["challenge"],
        challenge_type="control-plane-mutation",
        user_id=user_id,
    )
    if not challenge:
        raise WebAuthnError("control-plane mutation challenge not found or expired")
    payload = challenge["payload"]
    expected = {
        "type": "serverware.control_plane_mutation",
        "user_id": user_id,
        "action": action,
        "resource_id": resource_id,
        "payload_digest": payload_digest,
    }
    for field, expected_value in expected.items():
        if payload.get(field) != expected_value:
            raise WebAuthnError(f"control-plane mutation challenge {field} mismatch")

    if not db.compare_and_swap_webauthn_sign_count(
        credential_id,
        expected_sign_count=credential["sign_count"],
        new_sign_count=parsed["sign_count"],
    ):
        raise WebAuthnError("authenticator sign counter changed concurrently")
    return {
        "method": "webauthn",
        "user_id": user_id,
        "credential_id": credential_id,
        "credential_record_id": credential["id"],
        "authenticator_class": credential["authenticator_class"],
        "aaguid": credential.get("aaguid"),
        "attestation_trusted": trust["currently_trusted"],
        "attestation_enrollment_trusted": trust["enrollment_trusted"],
        "attestation_trust_reason": trust["reason"],
        "effective_authenticator_class": trust["effective_authenticator_class"],
        "current_trust_bundle_digest": trust.get("current_trust_bundle_digest"),
        "current_trust_bundle_sequence": trust.get("current_trust_bundle_sequence"),
        "attestation_root_sha256": credential.get("attestation_root_sha256"),
        "user_present": parsed["user_present"],
        "user_verified": parsed["user_verified"],
        "sign_count": parsed["sign_count"],
        "challenge_id": challenge["id"],
        "control_plane_action": action,
        "resource_id": resource_id,
        "payload_digest": payload_digest,
    }


def create_dev_credential(user_id: str, label: str = "Docker dev authenticator") -> dict[str, Any]:
    if not DEV_AUTHENTICATOR_ENABLED:
        raise WebAuthnError("dev authenticator is disabled")
    private_key = ec.generate_private_key(ec.SECP256R1())
    credential_id = b64u(os.urandom(32))
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    stored = db.create_webauthn_credential(
        credential_id=credential_id,
        user_id=user_id,
        label=label,
        public_key_cose=b64u(_cose_from_public_key(private_key.public_key())),
        sign_count=0,
        aaguid="00000000-0000-0000-0000-000000000000",
        authenticator_class="dev",
        attestation_fmt="serverware-dev-hardware-fixture",
        attestation_trusted=True,
        attestation_trust_path=["serverware-dev-hardware-fixture"],
        attestation_leaf_sha256="sha256:" + "d" * 64,
        attestation_root_sha256="sha256:" + "d" * 64,
        attestation_trust_bundle_digest="sha256:" + "d" * 64,
        attestation_trust_bundle_sequence=1,
        attestation_verified_at=db.iso_now(),
        transports=["internal"],
        dev_private_key_pem=private_pem,
    )
    return _redact_credential(stored)


def dev_assertion(challenge: str) -> dict[str, Any]:
    if not DEV_AUTHENTICATOR_ENABLED:
        raise WebAuthnError("dev authenticator is disabled")
    challenge_row = db.get_unused_webauthn_challenge(challenge)
    if not challenge_row:
        raise WebAuthnError("challenge not found or expired")
    credentials = [item for item in db.list_webauthn_credentials(challenge_row["user_id"]) if item.get("dev_private_key_pem")]
    if not credentials:
        raise WebAuthnError("no dev authenticator registered")
    credential = credentials[0]
    private_key = serialization.load_pem_private_key(credential["dev_private_key_pem"].encode("ascii"), password=None)
    next_count = int(credential["sign_count"] or 0) + 1
    auth_data = _rp_hash() + bytes([UP_FLAG | UV_FLAG]) + next_count.to_bytes(4, "big")
    client_data = {
        "type": "webauthn.get",
        "challenge": challenge,
        "origin": WEBAUTHN_ORIGIN,
        "crossOrigin": False,
    }
    client_data_raw = json.dumps(client_data, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = private_key.sign(auth_data + _sha256(client_data_raw), ec.ECDSA(hashes.SHA256()))
    return {
        "id": credential["credential_id"],
        "rawId": credential["credential_id"],
        "type": "public-key",
        "response": {
            "clientDataJSON": b64u(client_data_raw),
            "authenticatorData": b64u(auth_data),
            "signature": b64u(signature),
            "userHandle": _json_b64({"user_id": challenge_row["user_id"]}),
        },
    }


def _redact_credential(credential: dict[str, Any]) -> dict[str, Any]:
    item = dict(credential)
    item.pop("public_key_cose", None)
    item.pop("dev_private_key_pem", None)
    return item
