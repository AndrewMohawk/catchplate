"""Original at-rest row projection for the separately selected enclave broker.

This module has no key loader or decryption path. Shape checks are not KMS,
enclave or provider evidence; the actual recipient must open and admit the
authenticated ciphertext before using any secret.
"""
from __future__ import annotations

import base64
import json
import math


MAX_CIPHERTEXT_BYTES = 1024 * 1024 + 16
MAX_METADATA_BYTES = 32 * 1024


def _require(value):
    if not value:
        raise ValueError("credential ciphertext original is invalid")


def _pairs(items):
    value = {}
    for key, item in items:
        _require(key not in value)
        value[key] = item
    return value


def metadata(original):
    _require(type(original) is str and 1 <= len(original.encode("utf-8")) <= MAX_METADATA_BYTES)
    value = json.loads(original, object_pairs_hook=_pairs,
        parse_constant=lambda _: _require(False), parse_float=_finite_float)
    _require(type(value) is dict)
    return value


def _finite_float(original):
    value = float(original)
    _require(math.isfinite(value))
    return value


def _encoded(value, *, exact=None, maximum=MAX_CIPHERTEXT_BYTES):
    _require(type(value) is str and 1 <= len(value) <= 4 * ((maximum + 2) // 3))
    # Ordinary crypto.py envelopes are unpadded; native writers are padded.
    # Padding here is decoder input only: row_projection retains every original.
    raw = base64.b64decode((value + "=" * (-len(value) % 4)).encode("ascii"), altchars=b"-_", validate=True)
    canonical = base64.urlsafe_b64encode(raw).decode("ascii")
    _require(1 <= len(raw) <= maximum and (exact is None or len(raw) == exact)
        and value in (canonical, canonical.rstrip("=")))
    return raw


def row_projection(row):
    """Use actual row values, preserving ciphertext strings without normalization."""
    identifier, version = row["id"], row["credential_version"]
    _require(type(identifier) is str and 1 <= len(identifier.encode("utf-8")) <= 256
        and type(version) is int and 1 <= version <= 2**63 - 1
        and row["encrypted_secret"] == "envelope:v2"
        and row["lifecycle_status"] == "active")
    for name in ("secret_kek_id", "secret_updated_at"):
        _require(type(row[name]) is str and 1 <= len(row[name].encode("utf-8")) <= 256)
    dek, nonce, ciphertext = row["encrypted_dek"], row["secret_nonce"], row["secret_ciphertext"]
    _require(type(dek) is str and type(nonce) is str and type(ciphertext) is str)
    # Bound before splitting/decoding; no legacy encrypted_secret fallback.
    _require(len(dek) <= 128 and len(nonce) <= 32
        and len(ciphertext) <= 3 + 4 * ((MAX_CIPHERTEXT_BYTES + 2) // 3))
    parts = dek.split(":")
    _require(len(parts) == 3 and parts[0] == "v1")
    _encoded(parts[1], exact=12, maximum=12)
    _encoded(parts[2], exact=48, maximum=48)
    _require(nonce.startswith("v1:") and ciphertext.startswith("v1:"))
    _encoded(nonce[3:], exact=12, maximum=12)
    _require(len(_encoded(ciphertext[3:])) >= 17)
    return {"credentialId": identifier, "credentialVersion": version,
        "secretKekId": row["secret_kek_id"], "encryptedDek": dek,
        "secretNonce": nonce, "secretCiphertext": ciphertext,
        "secretUpdatedAt": row["secret_updated_at"]}
