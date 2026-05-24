from __future__ import annotations

import base64
import hashlib
import os
from functools import lru_cache
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from serverware.config import MASTER_KEY_PATH, ensure_data_dirs


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
    if os.getenv("SERVERWARE_KEY_RELEASE_REQUIRED", "1") == "1":
        from serverware.key_release import ensure_material_released

        ensure_material_released("broker-kek")
    env_key = os.getenv("SERVERWARE_MASTER_KEY")
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


def _b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def local_kek_id() -> str:
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
