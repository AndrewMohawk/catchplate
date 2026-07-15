from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import shlex
import stat
import subprocess
import threading
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable, Mapping

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from serverware.config import MASTER_KEY_PATH, MASTER_KEY_UNSEAL_COMMAND, RELEASE_CHANNEL, ensure_data_dirs


_DEVELOPMENT_RELEASE_CHANNELS = {"dev", "development", "local", "test"}
_UNSEAL_OUTPUT_MAX_BYTES = 64 * 1024
_BOUND_SECRET_ENVELOPE_VERSION = "serverware.boundSecret/v1"
_BOUND_SECRET_KEYRING_MAX_KEYS = 8
_BOUND_SECRET_HISTORICAL_KEYRING_VERSION = (
    "serverware.boundSecretHistoricalKeyring/v1"
)
_BOUND_SECRET_HISTORICAL_KEYRING_MAX_BYTES = 64 * 1024
_TEST_BOUND_SECRET_KEY_NAME = "bound-secret-test.key"
_TEST_BOUND_SECRET_KEY_LOCK = threading.Lock()
_MASTER_KEY_RELEASE_RECEIPT_DIGEST: str | None = None


def _production_release() -> bool:
    return RELEASE_CHANNEL.strip().lower() not in _DEVELOPMENT_RELEASE_CHANNELS


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _unseal_environment() -> dict[str, str]:
    allowed = {
        "PATH",
        "HOME",
        "LANG",
        "LC_ALL",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "AWS_ROLE_ARN",
        "AWS_ROLE_SESSION_NAME",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_EC2_METADATA_DISABLED",
        "SERVERWARE_AWS_CLI",
        "SERVERWARE_AWS_KMS_MATERIALS_FILE",
        "SERVERWARE_AWS_KMS_TIMEOUT_SECONDS",
        "SERVERWARE_NITRO_NSM_UNSEAL_COMMAND_TEMPLATE",
        "SERVERWARE_NITRO_NSM_UNSEAL_OUTPUT_FORMAT",
        "SERVERWARE_NITRO_NSM_UNSEAL_TIMEOUT_SECONDS",
    }
    return {name: value for name, value in os.environ.items() if name in allowed}


def _release_handle(release: dict[str, Any]) -> str:
    external = release.get("external_release")
    if not isinstance(external, dict):
        return ""
    value = external.get("release_handle")
    return value if isinstance(value, str) else ""


def _validate_nitro_unseal_bindings(release: dict[str, Any], output: dict[str, Any]) -> None:
    external = release.get("external_release")
    if not isinstance(external, dict) or external.get("provider") != "aws-nitro-kms-policy":
        return
    kms_release = external.get("kms_release")
    if not isinstance(kms_release, dict) or kms_release.get("provider") != "aws-kms-recipient":
        raise ValueError("production Nitro broker KEK release is missing AWS KMS Recipient evidence")
    key_provider = kms_release.get("key_provider")
    expected = {
        "provider": "aws-nitro-kms-recipient-unseal",
        "attestationDocumentSha256": kms_release.get("attestation_document_sha256"),
        "recipientPublicKeySha256": kms_release.get("recipient_public_key_sha256"),
        "kmsKeyId": key_provider.get("key_id") if isinstance(key_provider, dict) else None,
        "ciphertextBlobSha256": kms_release.get("ciphertext_blob_sha256"),
        "recipientCiphertextSha256": kms_release.get("recipient_ciphertext_sha256"),
    }
    if any(not isinstance(value, str) or not value for value in expected.values()):
        raise ValueError("production Nitro broker KEK release has incomplete ciphertext bindings")
    if any(output.get(field) != value for field, value in expected.items()):
        raise ValueError("master-key unseal response does not match AWS Nitro/KMS release evidence")


def _unseal_master_key(release: dict[str, Any]) -> bytes:
    if not MASTER_KEY_UNSEAL_COMMAND:
        raise ValueError("production requires SERVERWARE_MASTER_KEY_UNSEAL_COMMAND")
    release_receipt_digest = _digest(
        json.dumps(release, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    )
    request = {
        "apiVersion": "serverware.masterKeyUnsealRequest/v1",
        "kind": "MasterKeyUnseal",
        "material": "broker-kek",
        "releaseHandle": _release_handle(release),
        "releaseReceiptDigest": release_receipt_digest,
        "releaseReceipt": release,
    }
    request["requestDigest"] = _digest(
        json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    )
    try:
        result = subprocess.run(
            shlex.split(MASTER_KEY_UNSEAL_COMMAND),
            input=(json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode(
                "utf-8"
            ),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_unseal_environment(),
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise ValueError("master-key unseal command could not be executed") from exc
    if result.returncode != 0:
        detail = result.stderr[:2048].decode("utf-8", errors="replace").strip()
        raise ValueError(f"master-key unseal command failed with exit {result.returncode}: {detail}")
    if len(result.stdout) > _UNSEAL_OUTPUT_MAX_BYTES:
        raise ValueError("master-key unseal command output exceeds 64 KiB")
    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("master-key unseal command returned invalid JSON") from exc
    allowed_fields = {
        "apiVersion",
        "kind",
        "ok",
        "material",
        "requestDigest",
        "releaseHandle",
        "keyB64",
        "provider",
        "attestationDocumentSha256",
        "recipientPublicKeySha256",
        "kmsKeyId",
        "ciphertextBlobSha256",
        "recipientCiphertextSha256",
    }
    if not isinstance(output, dict) or set(output) - allowed_fields:
        raise ValueError("master-key unseal command returned an invalid object shape")
    expected = {
        "apiVersion": "serverware.unsealedMaterial/v1",
        "kind": "UnsealedMaterial",
        "ok": True,
        "material": "broker-kek",
        "requestDigest": request["requestDigest"],
        "releaseHandle": request["releaseHandle"],
    }
    if any(output.get(field) != value for field, value in expected.items()):
        raise ValueError("master-key unseal command response is not bound to the release request")
    for field in ("provider", "attestationDocumentSha256", "recipientPublicKeySha256", "kmsKeyId"):
        if not isinstance(output.get(field), str) or not output[field]:
            raise ValueError(f"master-key unseal command response is missing {field}")
    for field in ("attestationDocumentSha256", "recipientPublicKeySha256"):
        value = output[field]
        if len(value) != 71 or not value.startswith("sha256:"):
            raise ValueError(f"master-key unseal command response has invalid {field}")
    _validate_nitro_unseal_bindings(release, output)
    raw_key = output.get("keyB64")
    if not isinstance(raw_key, str) or not raw_key:
        raise ValueError("master-key unseal command response is missing keyB64")
    try:
        key = base64.urlsafe_b64decode(raw_key + "=" * (-len(raw_key) % 4))
    except Exception as exc:
        raise ValueError("master-key unseal command keyB64 is invalid") from exc
    if len(key) != 32:
        raise ValueError("master-key unseal command must return exactly 32 key bytes")
    return key


def _decode_env_key(value: str) -> bytes:
    raw = value.strip()
    if len(raw) == 64:
        try:
            decoded = bytes.fromhex(raw)
            if len(decoded) == 32:
                return decoded
        except ValueError:
            pass
    try:
        decoded = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    except Exception as exc:
        raise ValueError("SERVERWARE_MASTER_KEY must be 32 bytes as urlsafe-base64 or 64 hex chars") from exc
    if len(decoded) != 32:
        raise ValueError("SERVERWARE_MASTER_KEY must decode to 32 bytes")
    return decoded


@lru_cache(maxsize=1)
def load_master_key() -> bytes:
    global _MASTER_KEY_RELEASE_RECEIPT_DIGEST
    release: dict[str, Any] | None = None
    if os.getenv("SERVERWARE_KEY_RELEASE_REQUIRED", "1") == "1":
        from serverware.key_release import ensure_material_released

        release = ensure_material_released("broker-kek")
        _MASTER_KEY_RELEASE_RECEIPT_DIGEST = _digest(
            canonical_json_bytes(release)
        )
    env_key = os.getenv("SERVERWARE_MASTER_KEY")
    if _production_release():
        if env_key:
            raise ValueError("SERVERWARE_MASTER_KEY is forbidden in production")
        if MASTER_KEY_PATH.exists():
            raise ValueError(f"persistent plaintext master key {MASTER_KEY_PATH} is forbidden in production")
        if release is None or release.get("key_release_provider") != "external-command":
            raise ValueError("production broker KEK requires an external attested key-release receipt")
        return _unseal_master_key(release)
    if env_key:
        return _decode_env_key(env_key)

    ensure_data_dirs()
    if MASTER_KEY_PATH.exists():
        key = MASTER_KEY_PATH.read_bytes()
        if len(key) != 32:
            raise ValueError(f"{MASTER_KEY_PATH} must contain exactly 32 bytes")
        return key

    key = os.urandom(32)
    MASTER_KEY_PATH.write_bytes(key)
    os.chmod(MASTER_KEY_PATH, 0o600)
    return key


def encrypt_secret(plaintext: str) -> str:
    nonce = os.urandom(12)
    ciphertext = AESGCM(load_master_key()).encrypt(nonce, plaintext.encode("utf-8"), None)
    return "v1:" + base64.urlsafe_b64encode(nonce).decode("ascii") + ":" + base64.urlsafe_b64encode(ciphertext).decode("ascii")


def decrypt_secret(value: str) -> str:
    version, nonce_b64, ciphertext_b64 = value.split(":", 2)
    if version != "v1":
        raise ValueError(f"unsupported secret version: {version}")
    nonce = base64.urlsafe_b64decode(nonce_b64)
    ciphertext = base64.urlsafe_b64decode(ciphertext_b64)
    plaintext = AESGCM(load_master_key()).decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


@dataclass(frozen=True)
class BoundSecretKeyring:
    active_key_id: str
    keys: Mapping[str, bytes]

    def __post_init__(self) -> None:
        keys = dict(self.keys)
        if not 1 <= len(keys) <= _BOUND_SECRET_KEYRING_MAX_KEYS:
            raise ValueError("bound secret keyring must contain between 1 and 8 keys")
        if self.active_key_id not in keys:
            raise ValueError("bound secret keyring has no active key")
        for key_id, key in keys.items():
            if (
                not isinstance(key_id, str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", key_id) is None
                or not isinstance(key, bytes)
                or len(key) != 32
                or not hmac.compare_digest(key_id, _bound_secret_key_id(key))
            ):
                raise ValueError("bound secret keyring entry is invalid")
        object.__setattr__(self, "keys", keys)


def _bound_secret_key_id(key: bytes) -> str:
    return "sha256:" + hashlib.sha256(key).hexdigest()


def build_bound_secret_keyring(
    active_key: bytes, historical_keys: Iterable[bytes] = ()
) -> BoundSecretKeyring:
    material = [active_key, *historical_keys]
    if not 1 <= len(material) <= _BOUND_SECRET_KEYRING_MAX_KEYS:
        raise ValueError("bound secret keyring must contain between 1 and 8 keys")
    keys: dict[str, bytes] = {}
    for key in material:
        if not isinstance(key, bytes) or len(key) != 32:
            raise ValueError("bound secret keyring entries must contain 32-byte keys")
        keys[_bound_secret_key_id(key)] = key
    return BoundSecretKeyring(
        active_key_id=_bound_secret_key_id(active_key),
        keys=keys,
    )


def _decode_historical_master_key(value: Any) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError("historical master-key material must be non-empty base64")
    try:
        key = _b64d(value)
    except Exception as exc:
        raise ValueError("historical master-key material is not valid base64") from exc
    if len(key) != 32:
        raise ValueError("historical master-key material must decode to 32 bytes")
    return key


def build_bound_secret_historical_keyring_receipt(
    *,
    active_key: bytes,
    historical_keys: Iterable[bytes],
    broker_release_receipt_digest: str,
) -> dict[str, Any]:
    if (
        not isinstance(broker_release_receipt_digest, str)
        or re.fullmatch(
            r"sha256:[0-9a-f]{64}", broker_release_receipt_digest
        )
        is None
    ):
        raise ValueError("broker release receipt digest is invalid")
    active_key_id = _bound_secret_key_id(active_key)
    encoded_keys: dict[str, str] = {}
    for key in historical_keys:
        if not isinstance(key, bytes) or len(key) != 32:
            raise ValueError("historical master-key material must contain 32-byte keys")
        key_id = _bound_secret_key_id(key)
        if key_id == active_key_id:
            continue
        encoded_keys[key_id] = _b64e(key)
    if len(encoded_keys) >= _BOUND_SECRET_KEYRING_MAX_KEYS:
        raise ValueError("historical master-key keyring exceeds 7 keys")
    payload = {
        "version": _BOUND_SECRET_HISTORICAL_KEYRING_VERSION,
        "kind": "BoundSecretHistoricalKeyring",
        "active_key_id": active_key_id,
        "broker_release_receipt_digest": broker_release_receipt_digest,
        "historical_keys": encoded_keys,
    }
    receipt_hmac = "sha256:" + hmac.new(
        active_key,
        canonical_json_bytes(payload),
        hashlib.sha256,
    ).hexdigest()
    return {**payload, "receipt_hmac": receipt_hmac}


def _load_production_historical_master_keys(
    *, active_key: bytes
) -> list[bytes]:
    configured = os.getenv(
        "SERVERWARE_HISTORICAL_MASTER_KEYRING_FILE", ""
    ).strip()
    if not configured:
        return []
    path = Path(configured)
    if not path.is_absolute():
        raise ValueError(
            "production historical master-key keyring must be an absolute regular file"
        )
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise ValueError(
            "production historical master-key keyring requires no-follow file support"
        )
    flags = os.O_RDONLY | no_follow | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ValueError(
            "production historical master-key keyring could not be read"
        ) from exc
    try:
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode):
            raise ValueError(
                "production historical master-key keyring must be a regular file"
            )
        if file_stat.st_uid not in {0, os.geteuid()}:
            raise ValueError(
                "production historical master-key keyring owner is not trusted"
            )
        if file_stat.st_mode & 0o077:
            raise ValueError(
                "production historical master-key keyring permissions are too broad"
            )
        if file_stat.st_size > _BOUND_SECRET_HISTORICAL_KEYRING_MAX_BYTES:
            raise ValueError("production historical master-key keyring is too large")
        with os.fdopen(fd, "rb", closefd=True) as handle:
            fd = -1
            raw = handle.read(_BOUND_SECRET_HISTORICAL_KEYRING_MAX_BYTES + 1)
        if len(raw) > _BOUND_SECRET_HISTORICAL_KEYRING_MAX_BYTES:
            raise ValueError("production historical master-key keyring is too large")
    finally:
        if fd >= 0:
            os.close(fd)
    try:
        receipt = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(
            "production historical master-key keyring receipt is invalid"
        ) from exc
    if not isinstance(receipt, dict) or set(receipt) != {
        "version",
        "kind",
        "active_key_id",
        "broker_release_receipt_digest",
        "historical_keys",
        "receipt_hmac",
    }:
        raise ValueError(
            "production historical master-key keyring receipt has an invalid shape"
        )
    release_digest = _MASTER_KEY_RELEASE_RECEIPT_DIGEST
    active_key_id = _bound_secret_key_id(active_key)
    historical = receipt.get("historical_keys")
    if (
        receipt.get("version") != _BOUND_SECRET_HISTORICAL_KEYRING_VERSION
        or receipt.get("kind") != "BoundSecretHistoricalKeyring"
        or receipt.get("active_key_id") != active_key_id
        or not isinstance(release_digest, str)
        or receipt.get("broker_release_receipt_digest") != release_digest
        or not isinstance(historical, dict)
        or len(historical) >= _BOUND_SECRET_KEYRING_MAX_KEYS
    ):
        raise ValueError(
            "production historical master-key keyring receipt binding is invalid"
        )
    payload = {key: value for key, value in receipt.items() if key != "receipt_hmac"}
    expected_hmac = "sha256:" + hmac.new(
        active_key,
        canonical_json_bytes(payload),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(str(receipt.get("receipt_hmac")), expected_hmac):
        raise ValueError(
            "production historical master-key keyring receipt authentication failed"
        )
    keys: list[bytes] = []
    for key_id, encoded_key in historical.items():
        if (
            not isinstance(key_id, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", key_id) is None
        ):
            raise ValueError(
                "production historical master-key keyring entry is invalid"
            )
        key = _decode_historical_master_key(encoded_key)
        if (
            key_id == active_key_id
            or not hmac.compare_digest(key_id, _bound_secret_key_id(key))
        ):
            raise ValueError(
                "production historical master-key keyring entry binding is invalid"
            )
        keys.append(key)
    return keys


def _load_test_bound_secret_key() -> bytes:
    """Load isolated test storage material without releasing the broker KEK."""
    ensure_data_dirs()
    path = MASTER_KEY_PATH.with_name(_TEST_BOUND_SECRET_KEY_NAME)
    with _TEST_BOUND_SECRET_KEY_LOCK:
        if path.exists():
            key = path.read_bytes()
        else:
            key = os.urandom(32)
            try:
                with path.open("xb") as handle:
                    handle.write(key)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(path, 0o600)
            except FileExistsError:
                key = path.read_bytes()
        if len(key) != 32:
            raise ValueError(f"{path} must contain exactly 32 bytes")
        return key


def load_bound_secret_keyring() -> BoundSecretKeyring:
    # Unit-level test policy fixtures intentionally do not activate a signed policy.
    # Keep their metadata encryption independent from broker material so the broker
    # release gate remains fail-closed and production follows the attested path.
    if (
        RELEASE_CHANNEL.strip().lower() == "test"
        and os.getenv("SERVERWARE_KEY_RELEASE_REQUIRED", "1") == "1"
    ):
        active_key = _load_test_bound_secret_key()
    else:
        active_key = load_master_key()
    configured = os.getenv("SERVERWARE_HISTORICAL_MASTER_KEYS", "").strip()
    if _production_release():
        if configured:
            raise ValueError(
                "SERVERWARE_HISTORICAL_MASTER_KEYS is forbidden in production"
            )
        return build_bound_secret_keyring(
            active_key,
            _load_production_historical_master_keys(active_key=active_key),
        )
    if not configured:
        return build_bound_secret_keyring(active_key)
    try:
        historical = json.loads(configured)
    except json.JSONDecodeError as exc:
        raise ValueError("SERVERWARE_HISTORICAL_MASTER_KEYS must be a JSON object") from exc
    if not isinstance(historical, dict):
        raise ValueError("SERVERWARE_HISTORICAL_MASTER_KEYS must be a JSON object")
    if len(historical) >= _BOUND_SECRET_KEYRING_MAX_KEYS:
        raise ValueError("historical master-key keyring exceeds 7 keys")
    historical_keys: list[bytes] = []
    for key_id, encoded_key in historical.items():
        if (
            not isinstance(key_id, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", key_id) is None
        ):
            raise ValueError("historical master-key key ID is invalid")
        key = _decode_historical_master_key(encoded_key)
        if not hmac.compare_digest(key_id, _bound_secret_key_id(key)):
            raise ValueError("historical master-key key ID does not match its material")
        historical_keys.append(key)
    return build_bound_secret_keyring(active_key, historical_keys)


def _bound_secret_aad(
    *, key_id: str, purpose: str, binding: Mapping[str, Any]
) -> bytes:
    return canonical_json_bytes(
        {
            "version": _BOUND_SECRET_ENVELOPE_VERSION,
            "algorithm": "AES-256-GCM",
            "key_id": key_id,
            "purpose": purpose,
            "binding": dict(binding),
        }
    )


def encrypt_bound_secret(
    plaintext: str,
    *,
    purpose: str,
    binding: Mapping[str, Any],
    keyring: BoundSecretKeyring,
) -> str:
    if not isinstance(plaintext, str):
        raise ValueError("bound secret plaintext must be a string")
    if not isinstance(purpose, str) or not purpose:
        raise ValueError("bound secret purpose must be non-empty")
    key = keyring.keys.get(keyring.active_key_id)
    if key is None:
        raise ValueError("bound secret keyring has no active key")
    aad = _bound_secret_aad(
        key_id=keyring.active_key_id,
        purpose=purpose,
        binding=binding,
    )
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), aad)
    return json.dumps(
        {
            "version": _BOUND_SECRET_ENVELOPE_VERSION,
            "algorithm": "AES-256-GCM",
            "key_id": keyring.active_key_id,
            "purpose": purpose,
            "aad_digest": _digest(aad),
            "nonce": _b64e(nonce),
            "ciphertext": _b64e(ciphertext),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def decrypt_bound_secret(
    value: str,
    *,
    purpose: str,
    binding: Mapping[str, Any],
    keyring: BoundSecretKeyring,
) -> str:
    try:
        envelope = json.loads(value)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("bound secret envelope is invalid") from exc
    if not isinstance(envelope, dict) or set(envelope) != {
        "version",
        "algorithm",
        "key_id",
        "purpose",
        "aad_digest",
        "nonce",
        "ciphertext",
    }:
        raise ValueError("bound secret envelope has an invalid shape")
    if (
        envelope.get("version") != _BOUND_SECRET_ENVELOPE_VERSION
        or envelope.get("algorithm") != "AES-256-GCM"
    ):
        raise ValueError("bound secret envelope version is unsupported")
    if envelope.get("purpose") != purpose:
        raise ValueError("bound secret envelope purpose does not match")
    key_id = envelope.get("key_id")
    if not isinstance(key_id, str):
        raise ValueError("bound secret envelope key ID is invalid")
    key = keyring.keys.get(key_id)
    if key is None:
        raise ValueError("bound secret envelope references an unavailable key ID")
    aad = _bound_secret_aad(key_id=key_id, purpose=purpose, binding=binding)
    if not hmac.compare_digest(str(envelope.get("aad_digest")), _digest(aad)):
        raise ValueError("bound secret envelope binding does not match")
    try:
        plaintext = AESGCM(key).decrypt(
            _b64d(str(envelope["nonce"])),
            _b64d(str(envelope["ciphertext"])),
            aad,
        )
        return plaintext.decode("utf-8")
    except Exception as exc:
        raise ValueError("bound secret envelope authentication failed") from exc


def bound_secret_envelope_key_id(value: str) -> str:
    try:
        envelope = json.loads(value)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("bound secret envelope is invalid") from exc
    if (
        not isinstance(envelope, dict)
        or envelope.get("version") != _BOUND_SECRET_ENVELOPE_VERSION
        or envelope.get("algorithm") != "AES-256-GCM"
        or set(envelope)
        != {
            "version",
            "algorithm",
            "key_id",
            "purpose",
            "aad_digest",
            "nonce",
            "ciphertext",
        }
        or not isinstance(envelope.get("key_id"), str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", envelope["key_id"])
        is None
    ):
        raise ValueError("bound secret envelope has an invalid key binding")
    return str(envelope["key_id"])


def decrypt_legacy_secret_with_keyring(
    value: str, *, keyring: BoundSecretKeyring
) -> str:
    try:
        version, nonce_b64, ciphertext_b64 = value.split(":", 2)
        if version != "v1":
            raise ValueError("legacy secret envelope version is unsupported")
        nonce = base64.urlsafe_b64decode(nonce_b64)
        ciphertext = base64.urlsafe_b64decode(ciphertext_b64)
    except Exception as exc:
        raise ValueError("legacy secret envelope is invalid") from exc
    key_ids = [
        keyring.active_key_id,
        *sorted(key_id for key_id in keyring.keys if key_id != keyring.active_key_id),
    ]
    for key_id in key_ids:
        try:
            return AESGCM(keyring.keys[key_id]).decrypt(
                nonce, ciphertext, None
            ).decode("utf-8")
        except Exception:
            continue
    raise ValueError("legacy secret envelope authentication failed")


def _b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def encrypt_credential_lease_envelope(
    *,
    recipient_public_key: bytes,
    recipient_nonce: bytes,
    aad: dict[str, Any],
    plaintext: dict[str, Any],
) -> dict[str, str]:
    recipient_key = X25519PublicKey.from_public_bytes(recipient_public_key)
    ephemeral_key = X25519PrivateKey.generate()
    shared_secret = ephemeral_key.exchange(recipient_key)
    aad_bytes = canonical_json_bytes(aad)
    envelope_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=recipient_nonce,
        info=b"serverware:credential-lease-envelope:v2\0" + hashlib.sha256(aad_bytes).digest(),
    ).derive(shared_secret)
    aead_nonce = os.urandom(12)
    ciphertext = AESGCM(envelope_key).encrypt(
        aead_nonce,
        canonical_json_bytes(plaintext),
        aad_bytes,
    )
    server_public_key = ephemeral_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return {
        "serverEphemeralPublicKey": _b64e(server_public_key),
        "aeadNonce": _b64e(aead_nonce),
        "ciphertext": _b64e(ciphertext),
        "ciphertextSha256": "sha256:" + hashlib.sha256(ciphertext).hexdigest(),
    }


def local_kek_id() -> str:
    if _production_release():
        prefix = "attested-memory-kek"
    else:
        prefix = "attested-dev-kek" if os.getenv("SERVERWARE_KEY_RELEASE_REQUIRED", "1") == "1" else "local-master-key"
    return f"{prefix}:" + hashlib.sha256(load_master_key()).hexdigest()[:24]


def encrypt_secret_envelope(plaintext: str, *, credential_id: str, credential_version: int) -> dict[str, str]:
    dek = os.urandom(32)
    dek_nonce = os.urandom(12)
    secret_nonce = os.urandom(12)
    dek_aad = f"serverware:dek:{credential_id}:v{credential_version}".encode("utf-8")
    secret_aad = f"serverware:secret:{credential_id}:v{credential_version}".encode("utf-8")
    encrypted_dek = AESGCM(load_master_key()).encrypt(dek_nonce, dek, dek_aad)
    secret_ciphertext = AESGCM(dek).encrypt(secret_nonce, plaintext.encode("utf-8"), secret_aad)
    return {
        "secret_kek_id": local_kek_id(),
        "encrypted_dek": "v1:" + _b64e(dek_nonce) + ":" + _b64e(encrypted_dek),
        "secret_nonce": "v1:" + _b64e(secret_nonce),
        "secret_ciphertext": "v1:" + _b64e(secret_ciphertext),
    }


def decrypt_secret_envelope(row: Any) -> str:
    credential_id = row["id"]
    credential_version = int(row["credential_version"])
    encrypted_dek_value = row["encrypted_dek"]
    secret_nonce_value = row["secret_nonce"]
    secret_ciphertext_value = row["secret_ciphertext"]
    if not encrypted_dek_value or not secret_nonce_value or not secret_ciphertext_value:
        return decrypt_secret(row["encrypted_secret"])

    dek_version, dek_nonce_b64, encrypted_dek_b64 = encrypted_dek_value.split(":", 2)
    secret_nonce_version, secret_nonce_b64 = secret_nonce_value.split(":", 1)
    secret_version, secret_ciphertext_b64 = secret_ciphertext_value.split(":", 1)
    if dek_version != "v1" or secret_nonce_version != "v1" or secret_version != "v1":
        raise ValueError("unsupported envelope secret version")

    dek_aad = f"serverware:dek:{credential_id}:v{credential_version}".encode("utf-8")
    secret_aad = f"serverware:secret:{credential_id}:v{credential_version}".encode("utf-8")
    dek = AESGCM(load_master_key()).decrypt(_b64d(dek_nonce_b64), _b64d(encrypted_dek_b64), dek_aad)
    plaintext = AESGCM(dek).decrypt(_b64d(secret_nonce_b64), _b64d(secret_ciphertext_b64), secret_aad)
    return plaintext.decode("utf-8")
