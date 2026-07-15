from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import threading
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any
from urllib.parse import urlparse

import cbor2
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.x509.oid import ExtensionOID, ObjectIdentifier

from serverware import db
from serverware.config import (
    DEV_AUTHENTICATOR_ENABLED,
    POLICY_SIGNING_KEY_PATH,
    POLICY_SIGNING_PUBLIC_KEY_PATH,
    RESPONSE_SIGNING_KEY_PATH,
    SETUP_ENROLLMENT_VERIFIER_KEY_ID,
    SETUP_ENROLLMENT_VERIFIER_PUBLIC_KEY_PATH,
    SETUP_FINAL_AUTHORITY_KEY_ID,
    SETUP_FINAL_AUTHORITY_PUBLIC_KEY_PATH,
    SETUP_HARDWARE_VERIFIER_KEY_ID,
    SETUP_HARDWARE_VERIFIER_PUBLIC_KEY_PATH,
    TEE_QUOTE_SIGNING_KEY_PATH,
    WEBAUTHN_ORIGIN,
    WEBAUTHN_RECOVERY_AUDIENCE,
    WEBAUTHN_RECOVERY_ENABLED,
    WEBAUTHN_RECOVERY_EXCLUDE_CREDENTIALS_MAX_BYTES,
    WEBAUTHN_RECOVERY_EXCLUDE_CREDENTIALS_MAX_COUNT,
    WEBAUTHN_RECOVERY_ROOT_KEY_ID,
    WEBAUTHN_RECOVERY_ROOT_PROVIDER,
    WEBAUTHN_RECOVERY_ROOT_PUBLIC_KEY_PATH,
    WEBAUTHN_RECOVERY_TTL_SECONDS,
    WEBAUTHN_RP_ID,
    WEBAUTHN_RP_NAME,
    WEBAUTHN_TRUST_BUNDLE_PATH,
    WEBAUTHN_TRUST_BUNDLE_STATE_PATH,
    WEBAUTHN_TRUST_SIGNING_KEY_PATH,
    WEBAUTHN_TRUST_SIGNING_PUBLIC_KEY_PATH,
)
from serverware.policy_bundle import canonical_json
from serverware.webauthn_trust import (
    TrustRoot,
    WebAuthnTrustError,
    load_trust_roots,
    trust_read_locked,
    trust_roots_from_bundle,
    verify_trust_bundle,
)


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
MAX_CLIENT_DATA_JSON_BYTES = 16 * 1024
MAX_AUTHENTICATOR_DATA_BYTES = 64 * 1024
MAX_ATTESTATION_OBJECT_BYTES = 256 * 1024
MAX_COSE_PUBLIC_KEY_BYTES = 4 * 1024
MAX_CREDENTIAL_ID_BYTES = 1024
MAX_ATTESTATION_CHAIN_CERTIFICATES = 5
MAX_ATTESTATION_CERTIFICATE_BYTES = 64 * 1024
MAX_ATTESTATION_CHAIN_BYTES = 256 * 1024
MAX_TRUST_BUNDLE_BYTES = 2 * 1024 * 1024
MAX_TRUST_STATE_BYTES = 64 * 1024
MAX_TRUST_PUBLIC_KEY_BYTES = 16 * 1024
_TRUST_ROOT_CACHE_MAX_ENTRIES = 4
_TRUST_ROOT_CACHE_LOCK = threading.RLock()
_TRUST_ROOT_CACHE: OrderedDict[tuple[str, str, str], tuple[dict[str, Any], ...]] = (
    OrderedDict()
)


class WebAuthnError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class WebAuthnRecoveryRoot:
    provider: str
    key_id: str
    public_key: Ed25519PublicKey


def _read_recovery_public_key_file() -> bytes:
    path = WEBAUTHN_RECOVERY_ROOT_PUBLIC_KEY_PATH
    if path is None or not path.is_absolute():
        raise WebAuthnError(
            "WebAuthn recovery root public key must use an absolute path"
        )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise WebAuthnError(
            "WebAuthn recovery root must be a readable non-symlink file"
        ) from exc
    try:
        before = os.fstat(descriptor)
        mode = stat.S_IMODE(before.st_mode)
        if not stat.S_ISREG(before.st_mode):
            raise WebAuthnError("WebAuthn recovery root must be a regular file")
        if not 1 <= before.st_size <= 16 * 1024:
            raise WebAuthnError(
                "WebAuthn recovery root must contain between 1 and 16384 bytes"
            )
        if mode & 0o022 or (before.st_uid == os.geteuid() and mode & 0o200):
            raise WebAuthnError(
                "WebAuthn recovery root must not be mutable by the runtime identity"
            )
        chunks: list[bytes] = []
        remaining = 16 * 1024 + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or len(payload) != before.st_size
        ):
            raise WebAuthnError("WebAuthn recovery root changed while being read")
        return payload
    finally:
        os.close(descriptor)


@lru_cache(maxsize=1)
def webauthn_recovery_root() -> WebAuthnRecoveryRoot:
    if not WEBAUTHN_RECOVERY_ENABLED:
        raise WebAuthnError("WebAuthn recovery is disabled")
    if (
        re.fullmatch(r"sha256:[0-9a-f]{64}", WEBAUTHN_RECOVERY_ROOT_KEY_ID)
        is None
    ):
        raise WebAuthnError(
            "WebAuthn recovery root key ID must be a lowercase SHA-256 digest"
        )
    if not 3 <= len(WEBAUTHN_RECOVERY_ROOT_PROVIDER) <= 128:
        raise WebAuthnError("WebAuthn recovery root provider is invalid")
    if not WEBAUTHN_RECOVERY_AUDIENCE or len(WEBAUTHN_RECOVERY_AUDIENCE) > 512:
        raise WebAuthnError("WebAuthn recovery audience is invalid")
    try:
        public_key = serialization.load_pem_public_key(
            _read_recovery_public_key_file()
        )
    except (TypeError, ValueError) as exc:
        raise WebAuthnError(
            "WebAuthn recovery root is not a valid PEM public key"
        ) from exc
    if not isinstance(public_key, Ed25519PublicKey):
        raise WebAuthnError("WebAuthn recovery root must be Ed25519")
    key_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    actual_key_id = _sha256_prefixed(key_der)
    if not secrets_compare(actual_key_id, WEBAUTHN_RECOVERY_ROOT_KEY_ID):
        raise WebAuthnError(
            "WebAuthn recovery root does not match its configured key ID"
        )
    return WebAuthnRecoveryRoot(
        provider=WEBAUTHN_RECOVERY_ROOT_PROVIDER,
        key_id=actual_key_id,
        public_key=public_key,
    )


def secrets_compare(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left, right)


def _read_bounded_trust_file(path: Any, maximum_bytes: int) -> bytes:
    if not path.exists():
        return b""
    try:
        with path.open("rb") as handle:
            raw = handle.read(maximum_bytes + 1)
    except OSError as exc:
        raise WebAuthnTrustError(f"WebAuthn trust file is unreadable: {path}") from exc
    if len(raw) > maximum_bytes:
        raise WebAuthnTrustError(f"WebAuthn trust file exceeds its size limit: {path}")
    return raw


def _trust_cache_material() -> tuple[tuple[str, str, str], bytes]:
    bundle_raw = _read_bounded_trust_file(
        WEBAUTHN_TRUST_BUNDLE_PATH, MAX_TRUST_BUNDLE_BYTES
    )
    state_raw = _read_bounded_trust_file(
        WEBAUTHN_TRUST_BUNDLE_STATE_PATH, MAX_TRUST_STATE_BYTES
    )
    public_key_raw = _read_bounded_trust_file(
        WEBAUTHN_TRUST_SIGNING_PUBLIC_KEY_PATH, MAX_TRUST_PUBLIC_KEY_BYTES
    )
    return (
        (
            _sha256_prefixed(bundle_raw),
            _sha256_prefixed(state_raw),
            _sha256_prefixed(public_key_raw),
        ),
        bundle_raw,
    )


def _validate_cached_trust_time(bundle_raw: bytes) -> None:
    try:
        bundle = json.loads(bundle_raw)
        metadata = bundle.get("metadata") or {}
        valid_from_raw = metadata.get("validFrom")
        valid_until_raw = metadata.get("validUntil")
        valid_from = (
            datetime.fromisoformat(str(valid_from_raw).replace("Z", "+00:00"))
            if valid_from_raw
            else None
        )
        valid_until = (
            datetime.fromisoformat(str(valid_until_raw).replace("Z", "+00:00"))
            if valid_until_raw
            else None
        )
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise WebAuthnTrustError("WebAuthn trust bundle time window is invalid") from exc
    now = datetime.now(timezone.utc)
    if valid_from is not None and (
        valid_from.tzinfo is None or now < valid_from.astimezone(timezone.utc)
    ):
        raise WebAuthnTrustError("WebAuthn trust bundle is not valid yet")
    if valid_until is not None and (
        valid_until.tzinfo is None or now > valid_until.astimezone(timezone.utc)
    ):
        raise WebAuthnTrustError("WebAuthn trust bundle is expired")


def _load_trust_roots_cached() -> list[TrustRoot]:
    if not WEBAUTHN_TRUST_BUNDLE_PATH.exists():
        return load_trust_roots()
    try:
        for _ in range(2):
            before_key, before_bundle = _trust_cache_material()
            with _TRUST_ROOT_CACHE_LOCK:
                cached = _TRUST_ROOT_CACHE.get(before_key)
                if cached is not None:
                    _validate_cached_trust_time(before_bundle)
                    _TRUST_ROOT_CACHE.move_to_end(before_key)
                    return list(cached)
            roots = load_trust_roots()
            after_key, after_bundle = _trust_cache_material()
            if before_bundle != after_bundle or before_key[2] != after_key[2]:
                continue
            _validate_cached_trust_time(after_bundle)
            with _TRUST_ROOT_CACHE_LOCK:
                _TRUST_ROOT_CACHE[after_key] = tuple(roots)
                _TRUST_ROOT_CACHE.move_to_end(after_key)
                while len(_TRUST_ROOT_CACHE) > _TRUST_ROOT_CACHE_MAX_ENTRIES:
                    _TRUST_ROOT_CACHE.popitem(last=False)
            return list(roots)
    except Exception:
        with _TRUST_ROOT_CACHE_LOCK:
            _TRUST_ROOT_CACHE.clear()
        raise
    raise WebAuthnTrustError("WebAuthn trust bundle changed during verification")


def _public_key_id_from_file(path: Any) -> str | None:
    try:
        if path is None or not path.exists():
            return None
        raw = path.read_bytes()
        try:
            key = serialization.load_pem_public_key(raw)
        except ValueError:
            private_key = serialization.load_pem_private_key(raw, password=None)
            key = private_key.public_key()
        der = key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return _sha256_prefixed(der)
    except (OSError, TypeError, ValueError) as exc:
        raise WebAuthnError(f"online signing key is unreadable or invalid: {path}") from exc


def validate_webauthn_recovery_configuration(
    *, production: bool, additional_online_key_ids: dict[str, str] | None = None
) -> None:
    if not WEBAUTHN_RECOVERY_ENABLED:
        if production:
            raise WebAuthnError("production requires offline WebAuthn recovery")
        return
    root = webauthn_recovery_root()
    online_identities = {
        "setup enrollment verifier": SETUP_ENROLLMENT_VERIFIER_KEY_ID,
        "setup hardware verifier": SETUP_HARDWARE_VERIFIER_KEY_ID,
        "setup final authority": SETUP_FINAL_AUTHORITY_KEY_ID,
        "setup enrollment verifier public key": _public_key_id_from_file(
            SETUP_ENROLLMENT_VERIFIER_PUBLIC_KEY_PATH
        ),
        "setup hardware verifier public key": _public_key_id_from_file(
            SETUP_HARDWARE_VERIFIER_PUBLIC_KEY_PATH
        ),
        "setup final authority public key": _public_key_id_from_file(
            SETUP_FINAL_AUTHORITY_PUBLIC_KEY_PATH
        ),
        "response signing key": _public_key_id_from_file(RESPONSE_SIGNING_KEY_PATH),
        "policy signing key": _public_key_id_from_file(POLICY_SIGNING_KEY_PATH),
        "policy signing public key": _public_key_id_from_file(
            POLICY_SIGNING_PUBLIC_KEY_PATH
        ),
        "development quote signing key": _public_key_id_from_file(
            TEE_QUOTE_SIGNING_KEY_PATH
        ),
        "WebAuthn trust signing key": _public_key_id_from_file(
            WEBAUTHN_TRUST_SIGNING_KEY_PATH
        ),
        "WebAuthn trust signing public key": _public_key_id_from_file(
            WEBAUTHN_TRUST_SIGNING_PUBLIC_KEY_PATH
        ),
    }
    online_identities.update(additional_online_key_ids or {})
    collision = next(
        (
            name
            for name, key_id in online_identities.items()
            if key_id and secrets_compare(root.key_id, key_id)
        ),
        None,
    )
    if collision is not None:
        raise WebAuthnError(
            "WebAuthn recovery root must not reuse the online "
            f"{collision} identity"
        )
    if production:
        audience = urlparse(WEBAUTHN_RECOVERY_AUDIENCE)
        if (
            audience.scheme != "https"
            or not audience.hostname
            or audience.hostname in {"localhost", "127.0.0.1", "::1"}
            or audience.hostname.endswith(".example")
        ):
            raise WebAuthnError(
                "production WebAuthn recovery audience must be a non-placeholder HTTPS deployment URL"
            )


def _current_webauthn_recovery_trust() -> dict[str, Any]:
    if db.get_pending_webauthn_trust_publication() is not None:
        raise WebAuthnError(
            "WebAuthn recovery is unavailable while trust publication is pending"
        )
    if not WEBAUTHN_TRUST_BUNDLE_PATH.exists():
        raise WebAuthnError(
            "WebAuthn recovery requires an installed signed trust bundle"
        )
    try:
        bundle = json.loads(WEBAUTHN_TRUST_BUNDLE_PATH.read_text(encoding="utf-8"))
        info = verify_trust_bundle(bundle, update_state=False)
        roots = trust_roots_from_bundle(bundle, update_state=False)
    except (OSError, json.JSONDecodeError, WebAuthnTrustError) as exc:
        raise WebAuthnError("WebAuthn recovery trust bundle is unhealthy") from exc
    if (
        not roots
        or info["sequence"] < 1
        or re.fullmatch(r"sha256:[0-9a-f]{64}", str(info["digest"])) is None
        or re.fullmatch(
            r"sha256:[0-9a-f]{64}", str(info["signing_key_id"] or "")
        )
        is None
    ):
        raise WebAuthnError("WebAuthn recovery trust bundle is incomplete")
    return info


def b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64ud(value: str, *, maximum_bytes: int = 1024 * 1024) -> bytes:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > ((maximum_bytes + 2) // 3) * 4
        or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None
    ):
        raise WebAuthnError("WebAuthn base64url input is invalid or oversized")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise WebAuthnError("WebAuthn base64url input is invalid") from exc
    if len(decoded) > maximum_bytes or b64u(decoded) != value:
        raise WebAuthnError("WebAuthn base64url input is non-canonical or oversized")
    return decoded


def _sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def _sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _json_b64(value: dict[str, Any]) -> str:
    return b64u(json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _rp_hash() -> bytes:
    return _sha256(WEBAUTHN_RP_ID.encode("utf-8"))


def _parse_client_data(client_data_b64: str, expected_type: str) -> tuple[dict[str, Any], bytes]:
    raw = b64ud(client_data_b64, maximum_bytes=MAX_CLIENT_DATA_JSON_BYTES)
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
    if not isinstance(auth_data, bytes) or not 37 <= len(auth_data) <= MAX_AUTHENTICATOR_DATA_BYTES:
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
    if not 1 <= len(public_key_cose) <= MAX_COSE_PUBLIC_KEY_BYTES:
        raise WebAuthnError("WebAuthn COSE public key is oversized")
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
    if (
        not isinstance(x5c, list)
        or not 1 <= len(x5c) <= MAX_ATTESTATION_CHAIN_CERTIFICATES
    ):
        raise WebAuthnError("WebAuthn attestation x5c must be a certificate list")
    certs: list[x509.Certificate] = []
    total_bytes = 0
    for item in x5c:
        if not isinstance(item, bytes) or not 1 <= len(item) <= MAX_ATTESTATION_CERTIFICATE_BYTES:
            raise WebAuthnError("WebAuthn attestation x5c contains a non-certificate item")
        total_bytes += len(item)
        if total_bytes > MAX_ATTESTATION_CHAIN_BYTES:
            raise WebAuthnError("WebAuthn attestation certificate chain is oversized")
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
        scope_key=_sha256_prefixed(
            canonical_json(
                {
                    "authorization": authorization,
                    "label": label,
                    "user_id": user_id,
                }
            ).encode("utf-8")
        ),
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


@trust_read_locked
def recovery_registration_options(
    *,
    pending_token_digest: str,
    oidc_session_id: str,
    user_id: str,
    label: str,
    reason: str,
    auth_policy_digest: str,
) -> dict[str, Any]:
    root = webauthn_recovery_root()
    trust = _current_webauthn_recovery_trust()
    history = db.list_webauthn_credentials(
        user_id,
        include_revoked=True,
        limit=WEBAUTHN_RECOVERY_EXCLUDE_CREDENTIALS_MAX_COUNT + 1,
    )
    if len(history) > WEBAUTHN_RECOVERY_EXCLUDE_CREDENTIALS_MAX_COUNT:
        raise WebAuthnError(
            "credential history exceeds the recovery excludeCredentials count limit"
        )
    exclude_credentials = [
        {
            "id": str(item["credential_id"]),
            "type": "public-key",
            "transports": item.get("transports") or [],
        }
        for item in history
    ]
    if (
        len(canonical_json(exclude_credentials).encode("utf-8"))
        > WEBAUTHN_RECOVERY_EXCLUDE_CREDENTIALS_MAX_BYTES
    ):
        raise WebAuthnError(
            "credential history exceeds the recovery excludeCredentials size limit"
        )
    try:
        ceremony = db.create_webauthn_recovery_ceremony(
            recovery_id=str(uuid.uuid4()),
            nonce=b64u(os.urandom(32)),
            pending_token_digest=pending_token_digest,
            oidc_session_id=oidc_session_id,
            user_id=user_id,
            label=label,
            reason=reason,
            trust_bundle_digest=str(trust["digest"]),
            trust_bundle_sequence=int(trust["sequence"]),
            trust_bundle_rollback_epoch=int(trust["rollback_epoch"]),
            trust_signing_key_id=str(trust["signing_key_id"]),
            auth_policy_digest=auth_policy_digest,
            recovery_root_key_id=root.key_id,
            recovery_root_provider=root.provider,
            recovery_audience=WEBAUTHN_RECOVERY_AUDIENCE,
            rp_id=WEBAUTHN_RP_ID,
            origin=WEBAUTHN_ORIGIN,
            ttl_seconds=WEBAUTHN_RECOVERY_TTL_SECONDS,
        )
    except db.WebAuthnRecoveryError as exc:
        raise WebAuthnError(str(exc)) from exc
    challenge = ceremony["challenge"]
    timeout_ms = max(
        1,
        int(
            (
                datetime.fromisoformat(str(ceremony["expires_at"]))
                - datetime.now(timezone.utc)
            ).total_seconds()
            * 1000
        ),
    )
    return {
        "recoveryId": ceremony["id"],
        "publicKey": {
            "rp": {"name": WEBAUTHN_RP_NAME, "id": WEBAUTHN_RP_ID},
            "user": {
                "id": b64u(user_id.encode("utf-8")),
                "name": user_id,
                "displayName": user_id,
            },
            "challenge": challenge["challenge"],
            "pubKeyCredParams": [{"type": "public-key", "alg": ES256_ALG}],
            "timeout": timeout_ms,
            "attestation": "direct",
            "excludeCredentials": exclude_credentials,
            "authenticatorSelection": {
                "residentKey": "discouraged",
                "userVerification": "required",
                "authenticatorAttachment": "cross-platform",
            },
        },
        "serverware": {
            "recoveryId": ceremony["id"],
            "challengeId": ceremony["challenge_id"],
            "expiresAt": ceremony["expires_at"],
            "rootKeyId": root.key_id,
            "rootProvider": root.provider,
            "audience": WEBAUTHN_RECOVERY_AUDIENCE,
            "trustBundleDigest": trust["digest"],
            "trustBundleSequence": trust["sequence"],
        },
    }


def _verify_recovery_registration_candidate(
    *,
    recovery_id: str,
    user_id: str,
    response: dict[str, Any],
    current_trust: dict[str, Any],
    allowed_authenticator_classes: tuple[str, ...],
) -> dict[str, Any]:
    ceremony = db.get_webauthn_recovery_ceremony(recovery_id)
    if ceremony is None or ceremony["status"] not in {
        "pending_candidate",
        "prepared",
    }:
        raise WebAuthnError("recovery ceremony is not live")
    if ceremony["user_id"] != user_id:
        raise WebAuthnError("recovery subject mismatch")
    nested = response.get("response")
    if not isinstance(nested, dict):
        raise WebAuthnError("registration response is invalid")
    credential_id = response.get("id") or response.get("rawId")
    if not isinstance(credential_id, str):
        raise WebAuthnError("registration response missing credential id")
    try:
        attestation_raw = b64ud(
            nested["attestationObject"],
            maximum_bytes=MAX_ATTESTATION_OBJECT_BYTES,
        )
        client_data_b64 = nested["clientDataJSON"]
        attestation = cbor2.loads(attestation_raw)
        client_data, client_data_raw = _parse_client_data(
            client_data_b64, "webauthn.create"
        )
    except (KeyError, TypeError, ValueError, cbor2.CBORDecodeError) as exc:
        if isinstance(exc, WebAuthnError):
            raise
        raise WebAuthnError("recovery registration response is invalid") from exc
    challenge_value = client_data.get("challenge")
    if not isinstance(challenge_value, str):
        raise WebAuthnError("recovery registration challenge is invalid")
    challenge = db.get_unused_webauthn_challenge(
        challenge_value,
        challenge_type="recovery-registration",
        user_id=user_id,
    )
    if (
        not challenge
        or challenge.get("approval_request_id") is not None
        or challenge["id"] != ceremony["challenge_id"]
    ):
        raise WebAuthnError("recovery registration challenge not found or expired")
    challenge_payload = challenge.get("payload")
    if not isinstance(challenge_payload, dict) or set(challenge_payload) != {
        "v",
        "type",
        "recovery_id",
        "nonce",
        "user_id",
        "oidc_session_id",
        "pending_expires_at",
        "credential_history_digest",
        "trust_bundle_digest",
        "auth_policy_digest",
    }:
        raise WebAuthnError("recovery registration challenge payload is invalid")
    if (
        challenge_payload["v"] != 1
        or challenge_payload["type"]
        != "serverware.webauthn_recovery_registration"
        or challenge_payload["recovery_id"] != recovery_id
        or challenge_payload["nonce"] != ceremony["nonce"]
        or challenge_payload["user_id"] != user_id
        or challenge_payload["oidc_session_id"] != ceremony["oidc_session_id"]
        or challenge_payload["pending_expires_at"]
        != ceremony["pending_expires_at"]
        or challenge_payload["credential_history_digest"]
        != ceremony["credential_history_digest"]
        or challenge_payload["trust_bundle_digest"] != current_trust["digest"]
        or challenge_payload["auth_policy_digest"]
        != ceremony["auth_policy_digest"]
    ):
        raise WebAuthnError("recovery registration challenge scope mismatch")
    auth_data = attestation.get("authData")
    if not isinstance(auth_data, bytes):
        raise WebAuthnError("recovery registration authenticator data is invalid")
    parsed = _parse_authenticator_data(auth_data)
    if not parsed["attested_credential_data"]:
        raise WebAuthnError("recovery registration lacks attested credential data")
    if not parsed["user_verified"]:
        raise WebAuthnError("recovery registration requires user verification")
    cursor = 37
    if len(auth_data) < cursor + 18:
        raise WebAuthnError("recovery registration authenticator data is truncated")
    aaguid_raw = auth_data[cursor : cursor + 16]
    aaguid = _aaguid_to_text(aaguid_raw)
    cursor += 16
    credential_len = int.from_bytes(auth_data[cursor : cursor + 2], "big")
    cursor += 2
    if (
        credential_len <= 0
        or credential_len > MAX_CREDENTIAL_ID_BYTES
        or len(auth_data) <= cursor + credential_len
    ):
        raise WebAuthnError("recovery registration credential data is truncated")
    credential_id_raw = auth_data[cursor : cursor + credential_len]
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
    authenticator_class = _classify_authenticator(
        aaguid,
        attestation_trusted,
        attestation_result.get("trust_class"),
    )
    allowed = set(allowed_authenticator_classes) or {"yubikey", "hardware"}
    if (
        not attestation_trusted
        or authenticator_class not in allowed
        or authenticator_class not in {"yubikey", "hardware"}
    ):
        raise WebAuthnError(
            "recovery registration requires currently trusted hardware attestation"
        )
    if (
        attestation_result.get("trust_bundle_digest") != current_trust["digest"]
        or int(attestation_result.get("trust_bundle_sequence") or 0)
        != int(current_trust["sequence"])
    ):
        raise WebAuthnError("recovery registration attestation trust generation changed")
    transports = response.get("transports") or nested.get("transports") or []
    if (
        not isinstance(transports, list)
        or any(not isinstance(item, str) or len(item) > 64 for item in transports)
        or len(transports) > 16
    ):
        raise WebAuthnError("recovery registration transports are invalid")
    public_key_cose_b64 = b64u(public_key_cose)
    return {
        "credentialId": registered_credential_id,
        "credentialIdDigest": _sha256_prefixed(
            registered_credential_id.encode("utf-8")
        ),
        "publicKeyCose": public_key_cose_b64,
        "publicKeyCoseDigest": _sha256_prefixed(public_key_cose),
        "signCount": int(parsed["sign_count"]),
        "userVerified": True,
        "aaguid": aaguid,
        "authenticatorClass": authenticator_class,
        "attestationFormat": str(attestation_result["fmt"]),
        "attestationTrusted": True,
        "attestationTrustPath": list(attestation_result["trust_path"]),
        "attestationLeafSha256": attestation_result["leaf_sha256"],
        "attestationRootSha256": attestation_result["root_sha256"],
        "attestationObjectDigest": _sha256_prefixed(attestation_raw),
        "clientDataJsonDigest": _sha256_prefixed(client_data_raw),
        "responseDigest": _sha256_prefixed(
            canonical_json(response).encode("utf-8")
        ),
        "trustBundleDigest": str(current_trust["digest"]),
        "trustBundleSequence": int(current_trust["sequence"]),
        "trustBundleRollbackEpoch": int(current_trust["rollback_epoch"]),
        "trustSigningKeyId": str(current_trust["signing_key_id"]),
        "transports": sorted(set(transports)),
    }


@trust_read_locked
def prepare_recovery_registration(
    *,
    recovery_id: str,
    pending_token_digest: str,
    user_id: str,
    response: dict[str, Any],
    allowed_authenticator_classes: tuple[str, ...],
) -> dict[str, Any]:
    webauthn_recovery_root()
    trust = _current_webauthn_recovery_trust()
    candidate = _verify_recovery_registration_candidate(
        recovery_id=recovery_id,
        user_id=user_id,
        response=response,
        current_trust=trust,
        allowed_authenticator_classes=allowed_authenticator_classes,
    )
    try:
        witness_last_sequence = db.get_webauthn_recovery_witness_sequence(
            root_key_id=WEBAUTHN_RECOVERY_ROOT_KEY_ID,
            user_id=user_id,
        )
        ceremony = db.prepare_webauthn_recovery_candidate(
            recovery_id=recovery_id,
            pending_token_digest=pending_token_digest,
            candidate=candidate,
            witness_last_sequence=witness_last_sequence,
        )
    except (db.WebAuthnRecoveryError, db.RecoveryWitnessError) as exc:
        raise WebAuthnError(str(exc)) from exc
    return {
        "recoveryId": recovery_id,
        "statement": ceremony["statement"],
        "canonicalStatement": canonical_json(ceremony["statement"]),
        "statementDigest": ceremony["statement_digest"],
        "expiresAt": ceremony["statement"]["expiresAt"],
        "root": ceremony["statement"]["root"],
    }


def _verify_offline_recovery_authorization(
    *,
    expected_statement: dict[str, Any],
    expected_statement_digest: str,
    authorization: dict[str, Any],
    root: WebAuthnRecoveryRoot,
) -> tuple[dict[str, Any], dict[str, Any], str, str]:
    if set(authorization) != {"statement", "signature"}:
        raise WebAuthnError("recovery authorization fields are invalid")
    statement = authorization.get("statement")
    signature_value = authorization.get("signature")
    if not isinstance(statement, dict) or statement != expected_statement:
        raise WebAuthnError("recovery authorization statement mismatch")
    if not isinstance(signature_value, str) or not signature_value.startswith(
        "ed25519:"
    ):
        raise WebAuthnError("recovery authorization signature must use Ed25519")
    canonical_statement = canonical_json(statement).encode("ascii")
    if _sha256_prefixed(canonical_statement) != expected_statement_digest:
        raise WebAuthnError("recovery authorization statement is not canonical")
    try:
        not_before = datetime.fromisoformat(str(statement["notBefore"]))
        expires_at = datetime.fromisoformat(str(statement["expiresAt"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise WebAuthnError("recovery authorization time window is invalid") from exc
    now = datetime.now(timezone.utc)
    if (
        not_before.tzinfo is None
        or expires_at.tzinfo is None
        or now < not_before.astimezone(timezone.utc)
        or now >= expires_at.astimezone(timezone.utc)
    ):
        raise WebAuthnError("recovery authorization is not currently valid")
    signature_text = signature_value.split(":", 1)[1]
    try:
        signature = b64ud(signature_text)
    except (ValueError, TypeError) as exc:
        raise WebAuthnError("recovery authorization signature is invalid") from exc
    if len(signature) != 64 or b64u(signature) != signature_text:
        raise WebAuthnError("recovery authorization signature encoding is invalid")
    try:
        root.public_key.verify(signature, canonical_statement)
    except InvalidSignature as exc:
        raise WebAuthnError(
            "recovery authorization signature verification failed"
        ) from exc
    normalized_authorization = {
        "statement": statement,
        "signature": signature_value,
    }
    return (
        statement,
        normalized_authorization,
        _sha256_prefixed(
            canonical_json(normalized_authorization).encode("ascii")
        ),
        _sha256_prefixed(signature),
    )


@trust_read_locked
def verify_recovery_registration(
    *,
    recovery_id: str,
    pending_token_digest: str,
    user_id: str,
    response: dict[str, Any],
    authorization: dict[str, Any],
    auth_policy_digest: str,
    allowed_authenticator_classes: tuple[str, ...],
) -> dict[str, Any]:
    root = webauthn_recovery_root()
    trust = _current_webauthn_recovery_trust()
    ceremony = db.get_webauthn_recovery_ceremony(recovery_id)
    if ceremony is None or ceremony["status"] != "prepared":
        raise WebAuthnError("recovery ceremony is not prepared")
    candidate = _verify_recovery_registration_candidate(
        recovery_id=recovery_id,
        user_id=user_id,
        response=response,
        current_trust=trust,
        allowed_authenticator_classes=allowed_authenticator_classes,
    )
    if candidate != ceremony.get("candidate"):
        raise WebAuthnError("recovery candidate changed after offline preparation")
    statement_subject = (ceremony.get("statement") or {}).get("subject") or {}
    if not secrets_compare(
        str(statement_subject.get("pendingTokenDigest") or ""),
        pending_token_digest,
    ):
        raise WebAuthnError("recovery pending_token_digest binding changed")
    if ceremony.get("auth_policy_digest") != auth_policy_digest:
        raise WebAuthnError("recovery authorization policy binding changed")
    (
        statement,
        normalized_authorization,
        authorization_digest,
        signature_digest,
    ) = _verify_offline_recovery_authorization(
        expected_statement=ceremony["statement"],
        expected_statement_digest=ceremony["statement_digest"],
        authorization=authorization,
        root=root,
    )
    try:
        finalized = db.finalize_webauthn_recovery_registration(
            recovery_id=recovery_id,
            pending_token_digest=pending_token_digest,
            candidate=candidate,
            statement=statement,
            authorization=normalized_authorization,
            authorization_digest=authorization_digest,
            signature_digest=signature_digest,
            current_trust=trust,
            auth_policy_digest=auth_policy_digest,
        )
    except Exception as exc:
        db.invalidate_witnessed_webauthn_recovery(
            recovery_id=recovery_id,
            ceremony_type="replacement-registration",
            authorization=normalized_authorization,
            authorization_digest=authorization_digest,
            signature_digest=signature_digest,
        )
        if not isinstance(
            exc, (db.WebAuthnRecoveryError, db.RecoveryWitnessError, ValueError)
        ):
            raise
        raise WebAuthnError(str(exc)) from exc
    return {
        "recoveryId": recovery_id,
        "credential": _redact_credential(finalized["credential"]),
        "rootSequence": finalized["ceremony"]["root_sequence"],
        "sessionState": "pending_webauthn",
        "ordinaryAssertionRequired": True,
    }


@trust_read_locked
def prepare_lost_active_key_revocation(
    *,
    pending_token_digest: str,
    oidc_session_id: str,
    user_id: str,
    reason: str,
    auth_policy_digest: str,
) -> dict[str, Any]:
    root = webauthn_recovery_root()
    trust = _current_webauthn_recovery_trust()
    if not 1 <= len(reason) <= 500:
        raise WebAuthnError("lost-key decommission reason is invalid")
    try:
        witness_last_sequence = db.get_webauthn_recovery_witness_sequence(
            root_key_id=root.key_id,
            user_id=user_id,
        )
        ceremony = db.create_webauthn_recovery_revocation(
            revocation_id=str(uuid.uuid4()),
            nonce=b64u(os.urandom(32)),
            pending_token_digest=pending_token_digest,
            oidc_session_id=oidc_session_id,
            user_id=user_id,
            reason=reason,
            trust=trust,
            auth_policy_digest=auth_policy_digest,
            recovery_root_key_id=root.key_id,
            recovery_root_provider=root.provider,
            recovery_audience=WEBAUTHN_RECOVERY_AUDIENCE,
            rp_id=WEBAUTHN_RP_ID,
            origin=WEBAUTHN_ORIGIN,
            ttl_seconds=WEBAUTHN_RECOVERY_TTL_SECONDS,
            witness_last_sequence=witness_last_sequence,
        )
    except (db.WebAuthnRecoveryError, db.RecoveryWitnessError) as exc:
        raise WebAuthnError(str(exc)) from exc
    return {
        "revocationId": ceremony["id"],
        "statement": ceremony["statement"],
        "canonicalStatement": canonical_json(ceremony["statement"]),
        "statementDigest": ceremony["statement_digest"],
        "expiresAt": ceremony["expires_at"],
        "root": ceremony["statement"]["root"],
    }


@trust_read_locked
def verify_lost_active_key_revocation(
    *,
    revocation_id: str,
    pending_token_digest: str,
    user_id: str,
    authorization: dict[str, Any],
    auth_policy_digest: str,
) -> dict[str, Any]:
    root = webauthn_recovery_root()
    trust = _current_webauthn_recovery_trust()
    ceremony = db.get_webauthn_recovery_revocation(revocation_id)
    if (
        ceremony is None
        or ceremony["status"] != "prepared"
        or ceremony["user_id"] != user_id
    ):
        raise WebAuthnError("lost-key decommission ceremony is not live")
    statement_subject = (ceremony.get("statement") or {}).get("subject") or {}
    if not secrets_compare(
        str(statement_subject.get("pendingTokenDigest") or ""),
        pending_token_digest,
    ):
        raise WebAuthnError("recovery pending_token_digest binding changed")
    if ceremony.get("auth_policy_digest") != auth_policy_digest:
        raise WebAuthnError("recovery authorization policy binding changed")
    (
        statement,
        normalized_authorization,
        authorization_digest,
        signature_digest,
    ) = _verify_offline_recovery_authorization(
        expected_statement=ceremony["statement"],
        expected_statement_digest=ceremony["statement_digest"],
        authorization=authorization,
        root=root,
    )
    try:
        finalized = db.finalize_webauthn_recovery_revocation(
            revocation_id=revocation_id,
            pending_token_digest=pending_token_digest,
            statement=statement,
            authorization=normalized_authorization,
            authorization_digest=authorization_digest,
            signature_digest=signature_digest,
            current_trust=trust,
            auth_policy_digest=auth_policy_digest,
        )
    except Exception as exc:
        db.invalidate_witnessed_webauthn_recovery(
            recovery_id=revocation_id,
            ceremony_type="lost-active-key-decommission",
            authorization=normalized_authorization,
            authorization_digest=authorization_digest,
            signature_digest=signature_digest,
        )
        if not isinstance(
            exc, (db.WebAuthnRecoveryError, db.RecoveryWitnessError, ValueError)
        ):
            raise
        raise WebAuthnError(str(exc)) from exc
    return {
        "revocationId": revocation_id,
        "revokedCredential": _redact_credential(finalized["revoked"]["credential"]),
        "rootSequence": int(ceremony["root_sequence"]),
        "sessionState": "pending_webauthn",
        "recoveryRequired": True,
    }


@trust_read_locked
def verify_registration(
    user_id: str,
    label: str,
    response: dict[str, Any],
    *,
    require_authorization: bool = False,
    expected_authorization: dict[str, Any] | None = None,
) -> dict[str, Any]:
    credential_id = response.get("id") or response.get("rawId")
    if not isinstance(credential_id, str):
        raise WebAuthnError("registration response missing credential id")
    attestation = cbor2.loads(
        b64ud(
            response["response"]["attestationObject"],
            maximum_bytes=MAX_ATTESTATION_OBJECT_BYTES,
        )
    )
    client_data, client_data_raw = _parse_client_data(response["response"]["clientDataJSON"], "webauthn.create")
    challenge_value = client_data.get("challenge")
    if not isinstance(challenge_value, str):
        raise WebAuthnError("registration challenge is invalid")
    challenge = db.get_unused_webauthn_challenge(
        challenge_value,
        challenge_type="registration",
        user_id=user_id,
    )
    if not challenge or challenge.get("approval_request_id") is not None:
        raise WebAuthnError("registration challenge not found or expired")
    challenge_payload = challenge.get("payload", {})
    if (
        challenge_payload.get("type") != "registration"
        or challenge_payload.get("user_id") != user_id
        or challenge_payload.get("label") != label
    ):
        raise WebAuthnError("registration challenge scope mismatch")
    authorization = challenge_payload.get("authorization")
    if require_authorization:
        if not isinstance(authorization, dict) or authorization.get("mode") not in {
            "bootstrap-token",
            "development-bootstrap",
            "existing-webauthn",
            "oidc-session-first-enrollment",
        }:
            raise WebAuthnError("registration challenge lacks enrollment authorization")
        if not isinstance(authorization.get("payload_digest"), str):
            raise WebAuthnError("registration challenge authorization is not digest-bound")
    if expected_authorization is not None:
        if not isinstance(authorization, dict):
            raise WebAuthnError("registration challenge lacks expected authorization")
        for field, expected_value in expected_authorization.items():
            if authorization.get(field) != expected_value:
                raise WebAuthnError(
                    f"registration challenge authorization {field} mismatch"
                )
    auth_data = attestation.get("authData")
    parsed = _parse_authenticator_data(auth_data)
    if not parsed["attested_credential_data"]:
        raise WebAuthnError("registration missing attested credential data")
    cursor = 37
    aaguid_raw = auth_data[cursor:cursor + 16]
    aaguid = _aaguid_to_text(aaguid_raw)
    cursor += 16
    credential_len = int.from_bytes(auth_data[cursor:cursor + 2], "big")
    if credential_len <= 0 or credential_len > MAX_CREDENTIAL_ID_BYTES:
        raise WebAuthnError("registration credential ID is oversized")
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
        finalized = db.finalize_webauthn_registration(
            challenge=challenge_value,
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
    if finalized is None:
        raise WebAuthnError("registration challenge not found or expired")
    stored = finalized["credential"]
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
    credentials = _credential_descriptors_for_policy(user_id, authn_policy)
    if not credentials:
        raise WebAuthnError("no currently eligible WebAuthn credential is available")
    payload = _approval_challenge_payload(approval, user_id, review_receipt)
    challenge = b64u(_sha256(canonical_json(payload).encode("utf-8")))
    challenge_row = db.create_webauthn_challenge(
        challenge=challenge,
        challenge_type="approval",
        user_id=user_id,
        approval_request_id=approval["id"],
        scope_key=str(approval["id"]),
        payload=payload,
        ttl_seconds=120,
    )
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
    approval_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    credentials = _credential_descriptors_for_policy(user_id, authn_policy)
    if not credentials:
        raise WebAuthnError("no currently eligible WebAuthn credential is available")
    payload = {
        "v": 2 if approval_context else 1,
        "type": "serverware.control_plane_mutation",
        "user_id": user_id,
        "action": action,
        "resource_id": resource_id,
        "payload_digest": payload_digest,
        "nonce": b64u(os.urandom(24)),
    }
    if approval_context:
        payload.update(
            {
                "control_plane_approval_id": approval_context["id"],
                "approval_requester_id": approval_context["requester_id"],
                "approval_expires_at": approval_context["expires_at"],
                "decision": "approve",
            }
        )
    challenge = b64u(_sha256(canonical_json(payload).encode("utf-8")))
    challenge_row = db.create_webauthn_challenge(
        challenge=challenge,
        challenge_type="control-plane-mutation",
        user_id=user_id,
        payload=payload,
        scope_key=_sha256_prefixed(
            canonical_json(
                {
                    "action": action,
                    "approval_id": (
                        approval_context.get("id") if approval_context else None
                    ),
                    "payload_digest": payload_digest,
                    "resource_id": resource_id,
                    "user_id": user_id,
                }
            ).encode("utf-8")
        ),
        ttl_seconds=120,
    )
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


def oidc_session_binding_options(
    *,
    session_id: str,
    user_id: str,
    session_expires_at: str,
    pending_expires_at: str,
    authn_policy: dict[str, Any],
    ttl_seconds: int,
) -> dict[str, Any]:
    credentials = _credential_descriptors_for_policy(user_id, authn_policy)
    if not credentials:
        raise WebAuthnError(
            "no currently eligible WebAuthn credential is available for session binding"
        )
    payload = {
        "v": 1,
        "type": "serverware.oidc_session_binding",
        "session_id": session_id,
        "user_id": user_id,
        "session_expires_at": session_expires_at,
        "pending_expires_at": pending_expires_at,
        "nonce": b64u(os.urandom(24)),
    }
    challenge = b64u(_sha256(canonical_json(payload).encode("utf-8")))
    try:
        challenge_row = db.create_oidc_session_binding_challenge(
            challenge=challenge,
            user_id=user_id,
            session_id=session_id,
            payload=payload,
            ttl_seconds=ttl_seconds,
        )
    except db.MetadataStoreError as exc:
        raise WebAuthnError(str(exc)) from exc
    return {
        "publicKey": {
            "challenge": challenge,
            "rpId": WEBAUTHN_RP_ID,
            "allowCredentials": credentials,
            "timeout": ttl_seconds * 1000,
            "userVerification": authn_policy.get("userVerification", "required"),
        },
        "serverware": {
            "challenge_id": challenge_row["id"],
            "payload_digest": _sha256_prefixed(
                canonical_json(payload).encode("utf-8")
            ),
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
    roots = _load_trust_roots_cached() if trust_roots is None else trust_roots
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
            roots = _load_trust_roots_cached()
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


@trust_read_locked
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


@trust_read_locked
def verify_control_plane_mutation_assertion(
    *,
    user_id: str,
    action: str,
    resource_id: str | None,
    payload_digest: str,
    authn_policy: dict[str, Any],
    assertion: dict[str, Any],
    approval_context: dict[str, Any] | None = None,
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
    if approval_context:
        expected.update(
            {
                "control_plane_approval_id": approval_context["id"],
                "approval_requester_id": approval_context["requester_id"],
                "approval_expires_at": approval_context["expires_at"],
                "decision": "approve",
            }
        )
    for field, expected_value in expected.items():
        if payload.get(field) != expected_value:
            raise WebAuthnError(f"control-plane mutation challenge {field} mismatch")

    if not db.compare_and_swap_webauthn_sign_count(
        credential_id,
        expected_sign_count=credential["sign_count"],
        new_sign_count=parsed["sign_count"],
    ):
        raise WebAuthnError("authenticator sign counter changed concurrently")
    evidence = {
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
    if approval_context:
        evidence.update(
            {
                "control_plane_approval_id": approval_context["id"],
                "approval_requester_id": approval_context["requester_id"],
                "approval_expires_at": approval_context["expires_at"],
                "decision": "approve",
            }
        )
    return evidence


@trust_read_locked
def verify_oidc_session_binding_assertion(
    *,
    old_token_digest: str,
    new_token_digest: str,
    session_id: str,
    user_id: str,
    session_expires_at: str,
    pending_expires_at: str,
    authn_policy: dict[str, Any],
    assertion: dict[str, Any],
    encrypted_active_token: str,
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
    assertion_digest = _sha256_prefixed(
        canonical_json(assertion).encode("utf-8")
    )
    activation = db.finalize_oidc_browser_session_activation(
        old_token_digest=old_token_digest,
        new_token_digest=new_token_digest,
        session_id=session_id,
        user_id=user_id,
        expires_at=session_expires_at,
        pending_expires_at=pending_expires_at,
        challenge=client_data["challenge"],
        credential_id=credential_id,
        credential_record_id=credential["id"],
        expected_sign_count=credential["sign_count"],
        new_sign_count=parsed["sign_count"],
        assertion_digest=assertion_digest,
        encrypted_active_token=encrypted_active_token,
        trust_bundle_digest=trust.get("current_trust_bundle_digest"),
        trust_bundle_sequence=trust.get("current_trust_bundle_sequence"),
        authenticator_class=trust["effective_authenticator_class"],
    )
    if not activation.get("ok"):
        raise WebAuthnError(
            "OIDC session activation failed: " + str(activation.get("reason"))
        )
    return {
        "method": "webauthn",
        "user_id": user_id,
        "credential_id": credential_id,
        "credential_record_id": credential["id"],
        "authenticator_class": credential["authenticator_class"],
        "effective_authenticator_class": trust["effective_authenticator_class"],
        "attestation_trusted": trust["currently_trusted"],
        "attestation_trust_reason": trust["reason"],
        "user_present": parsed["user_present"],
        "user_verified": parsed["user_verified"],
        "sign_count": parsed["sign_count"],
        "challenge_id": activation["challenge_id"],
        "session_id": session_id,
        "session": activation["session"],
    }


def oidc_session_assertion_binding(assertion: dict[str, Any]) -> dict[str, str]:
    if not isinstance(assertion, dict):
        raise WebAuthnError("WebAuthn assertion is invalid")
    response = assertion.get("response")
    if not isinstance(response, dict):
        raise WebAuthnError("WebAuthn assertion response is invalid")
    client_data, _ = _parse_client_data(
        response.get("clientDataJSON"), "webauthn.get"
    )
    challenge = client_data.get("challenge")
    if not isinstance(challenge, str) or re.fullmatch(
        r"[A-Za-z0-9_-]{43}", challenge
    ) is None:
        raise WebAuthnError("WebAuthn assertion challenge is invalid")
    return {
        "assertion_digest": _sha256_prefixed(
            canonical_json(assertion).encode("utf-8")
        ),
        "challenge": challenge,
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
