from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from serverware.config import (
    SETUP_ENROLLMENT_VERIFIER_KEY_ID,
    SETUP_ENROLLMENT_VERIFIER_PROVIDER,
    SETUP_ENROLLMENT_VERIFIER_PUBLIC_KEY_PATH,
    SETUP_FINAL_AUTHORITY_KEY_ID,
    SETUP_FINAL_AUTHORITY_PROVIDER,
    SETUP_FINAL_AUTHORITY_PUBLIC_KEY_PATH,
    SETUP_HARDWARE_VERIFIER_KEY_ID,
    SETUP_HARDWARE_VERIFIER_PROVIDER,
    SETUP_HARDWARE_VERIFIER_PUBLIC_KEY_PATH,
)
from serverware.setup_receipts import Ed25519TrustRoot, FinalChallengeTrust


_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_PUBLIC_KEY_BYTES = 16 * 1024


class SetupReceiptTrustConfigurationError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class SetupReceiptTrustProfile:
    enrollment_verifier: Ed25519TrustRoot
    hardware_verifier: Ed25519TrustRoot
    final_authority: Ed25519TrustRoot
    canonical_bytes: bytes
    digest: str

    @property
    def final_challenge_trust(self) -> FinalChallengeTrust:
        return FinalChallengeTrust(
            authority=self.final_authority,
            hardware_verifier=self.hardware_verifier,
        )


def _snapshot_regular_file(path: Path, *, label: str) -> bytes:
    if not path.is_absolute():
        raise SetupReceiptTrustConfigurationError(f"{label} path must be absolute")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SetupReceiptTrustConfigurationError(
            f"{label} must be a readable non-symlink file"
        ) from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise SetupReceiptTrustConfigurationError(f"{label} must be a regular file")
        if not 1 <= before.st_size <= _MAX_PUBLIC_KEY_BYTES:
            raise SetupReceiptTrustConfigurationError(
                f"{label} must contain between 1 and {_MAX_PUBLIC_KEY_BYTES} bytes"
            )
        chunks: list[bytes] = []
        remaining = _MAX_PUBLIC_KEY_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_before != identity_after or len(payload) != before.st_size:
            raise SetupReceiptTrustConfigurationError(f"{label} changed while being read")
        return payload
    finally:
        os.close(descriptor)


def _trusted_root(
    *,
    path: Path | None,
    expected_key_id: str,
    provider: str,
    label: str,
) -> Ed25519TrustRoot:
    if path is None or not expected_key_id or not provider:
        raise SetupReceiptTrustConfigurationError(
            f"{label} path, expected key ID, and provider must all be configured"
        )
    if _SHA256_RE.fullmatch(expected_key_id) is None:
        raise SetupReceiptTrustConfigurationError(
            f"{label} expected key ID must be a lowercase SHA-256 digest"
        )
    snapshot = _snapshot_regular_file(path, label=label)
    try:
        public_key = serialization.load_pem_public_key(snapshot)
    except (TypeError, ValueError):
        try:
            public_key = serialization.load_der_public_key(snapshot)
        except (TypeError, ValueError) as exc:
            raise SetupReceiptTrustConfigurationError(
                f"{label} is not a valid PEM or DER public key"
            ) from exc
    if not isinstance(public_key, Ed25519PublicKey):
        raise SetupReceiptTrustConfigurationError(f"{label} must be an Ed25519 public key")
    public_key_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    actual_key_id = "sha256:" + hashlib.sha256(public_key_der).hexdigest()
    if not hmac.compare_digest(actual_key_id, expected_key_id):
        raise SetupReceiptTrustConfigurationError(
            f"{label} does not match its independently configured expected key ID"
        )
    return Ed25519TrustRoot(provider=provider, public_key_spki_der=public_key_der)


def build_setup_receipt_trust_profile(
    *,
    enrollment_verifier: Ed25519TrustRoot,
    hardware_verifier: Ed25519TrustRoot,
    final_authority: Ed25519TrustRoot,
) -> SetupReceiptTrustProfile:
    if len({enrollment_verifier.key_id, hardware_verifier.key_id, final_authority.key_id}) != 3:
        raise SetupReceiptTrustConfigurationError(
            "enrollment, hardware, and final receipt roles require distinct keys"
        )
    if len({enrollment_verifier.provider, hardware_verifier.provider, final_authority.provider}) != 3:
        raise SetupReceiptTrustConfigurationError(
            "enrollment, hardware, and final receipt roles require distinct providers"
        )
    document = {
        "apiVersion": "serverware.setupReceiptTrustProfile/v1",
        "enrollmentVerifier": {
            "provider": enrollment_verifier.provider,
            "keyId": enrollment_verifier.key_id,
        },
        "hardwareVerifier": {
            "provider": hardware_verifier.provider,
            "keyId": hardware_verifier.key_id,
        },
        "finalAuthority": {
            "provider": final_authority.provider,
            "keyId": final_authority.key_id,
        },
    }
    canonical = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return SetupReceiptTrustProfile(
        enrollment_verifier=enrollment_verifier,
        hardware_verifier=hardware_verifier,
        final_authority=final_authority,
        canonical_bytes=canonical,
        digest="sha256:" + hashlib.sha256(canonical).hexdigest(),
    )


@lru_cache(maxsize=1)
def setup_receipt_trust_profile() -> SetupReceiptTrustProfile:
    return build_setup_receipt_trust_profile(
        enrollment_verifier=_trusted_root(
            path=SETUP_ENROLLMENT_VERIFIER_PUBLIC_KEY_PATH,
            expected_key_id=SETUP_ENROLLMENT_VERIFIER_KEY_ID,
            provider=SETUP_ENROLLMENT_VERIFIER_PROVIDER,
            label="setup enrollment verifier public key",
        ),
        hardware_verifier=_trusted_root(
            path=SETUP_HARDWARE_VERIFIER_PUBLIC_KEY_PATH,
            expected_key_id=SETUP_HARDWARE_VERIFIER_KEY_ID,
            provider=SETUP_HARDWARE_VERIFIER_PROVIDER,
            label="setup hardware verifier public key",
        ),
        final_authority=_trusted_root(
            path=SETUP_FINAL_AUTHORITY_PUBLIC_KEY_PATH,
            expected_key_id=SETUP_FINAL_AUTHORITY_KEY_ID,
            provider=SETUP_FINAL_AUTHORITY_PROVIDER,
            label="setup final authority public key",
        ),
    )


__all__ = [
    "SetupReceiptTrustConfigurationError",
    "SetupReceiptTrustProfile",
    "build_setup_receipt_trust_profile",
    "setup_receipt_trust_profile",
]
