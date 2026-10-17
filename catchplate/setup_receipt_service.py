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

from catchplate.attestation import (
    AttestationContractError,
    NitroVerificationTrust,
    load_nitro_verification_trust,
)
from catchplate.config import (
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
from catchplate.setup_receipts import Ed25519TrustRoot, FinalChallengeTrust


_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_PUBLIC_KEY_BYTES = 16 * 1024
_MAX_NITRO_TRUST_BUNDLE_BYTES = 512 * 1024


class SetupReceiptTrustConfigurationError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class SetupReceiptTrustProfile:
    enrollment_verifier: Ed25519TrustRoot
    hardware_verifier: Ed25519TrustRoot
    hardware_subproof: Ed25519TrustRoot | None
    proxy_subproof: Ed25519TrustRoot | None
    final_authority: Ed25519TrustRoot
    canonical_bytes: bytes
    digest: str

    @property
    def final_challenge_trust(self) -> FinalChallengeTrust:
        return FinalChallengeTrust(
            authority=self.final_authority,
            hardware_verifier=self.hardware_verifier,
        )


def _snapshot_regular_file(
    path: Path, *, label: str, maximum: int = _MAX_PUBLIC_KEY_BYTES
) -> bytes:
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
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_mode & 0o022
        ):
            raise SetupReceiptTrustConfigurationError(
                f"{label} must be a single-link regular file without group/world write"
            )
        if not 1 <= before.st_size <= maximum:
            raise SetupReceiptTrustConfigurationError(
                f"{label} must contain between 1 and {maximum} bytes"
            )
        chunks: list[bytes] = []
        remaining = maximum + 1
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


def _setup_nitro_trust() -> NitroVerificationTrust:
    path_text = os.getenv("CATCHPLATE_SETUP_NITRO_TRUST_BUNDLE_PATH", "")
    expected_sha256 = os.getenv(
        "CATCHPLATE_SETUP_NITRO_TRUST_BUNDLE_SHA256", ""
    )
    if (
        not path_text
        or not expected_sha256
        or _SHA256_RE.fullmatch(expected_sha256) is None
    ):
        raise SetupReceiptTrustConfigurationError(
            "setup Nitro trust-bundle path and digest must be configured"
        )
    path = Path(path_text)
    if (
        not path.is_absolute()
        or ".." in path.parts
        or os.path.normpath(path_text) != path_text
    ):
        raise SetupReceiptTrustConfigurationError(
            "setup Nitro trust-bundle path must be normalized and absolute"
        )
    raw = _snapshot_regular_file(
        path,
        label="setup Nitro trust bundle",
        maximum=_MAX_NITRO_TRUST_BUNDLE_BYTES,
    )
    try:
        return load_nitro_verification_trust(
            raw, expected_sha256=expected_sha256
        )
    except AttestationContractError as exc:
        raise SetupReceiptTrustConfigurationError(
            "setup Nitro trust bundle failed strict validation"
        ) from exc


def _bind_nitro_trust(
    root: Ed25519TrustRoot, nitro: NitroVerificationTrust
) -> Ed25519TrustRoot:
    return Ed25519TrustRoot(
        provider=root.provider,
        public_key_spki_der=root.public_key_spki_der,
        nitro_verification_trust=nitro,
    )


def build_setup_receipt_trust_profile(
    *,
    enrollment_verifier: Ed25519TrustRoot,
    hardware_verifier: Ed25519TrustRoot,
    final_authority: Ed25519TrustRoot,
    hardware_subproof: Ed25519TrustRoot | None = None,
    proxy_subproof: Ed25519TrustRoot | None = None,
) -> SetupReceiptTrustProfile:
    nitro_trust = hardware_verifier.nitro_verification_trust
    if hardware_subproof is not None:
        raise SetupReceiptTrustConfigurationError(
            "separate Ed25519 hardware verdict trust is not accepted"
        )
    if nitro_trust is None and proxy_subproof is not None:
        raise SetupReceiptTrustConfigurationError(
            "proxy subproof trust requires raw Nitro trust"
        )
    roots = tuple(
        root
        for root in (
            enrollment_verifier,
            hardware_verifier,
            hardware_subproof,
            proxy_subproof,
            final_authority,
        )
        if root is not None
    )
    if len({root.key_id for root in roots}) != len(roots):
        raise SetupReceiptTrustConfigurationError(
            "all setup receipt and subproof roles require distinct keys"
        )
    if len({root.provider for root in roots}) != len(roots):
        raise SetupReceiptTrustConfigurationError(
            "all setup receipt and subproof roles require distinct providers"
        )
    document = {
        "apiVersion": (
            "catchplate.setupReceiptTrustProfile/v3"
            if nitro_trust is not None
            else "catchplate.setupReceiptTrustProfile/v1"
        ),
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
    if nitro_trust is not None:
        if proxy_subproof is None:
            raise SetupReceiptTrustConfigurationError(
                "raw Nitro setup verification requires independent proxy subproof trust"
            )
        document["nitroHardwareIdentity"] = {
            "apiVersion": "catchplate.setupNitroTrustBundle/v1",
            "trustBundleSha256": nitro_trust.bundle_sha256,
            "expectedModuleId": nitro_trust.expected_module_id,
            "expectedEifSha384": nitro_trust.expected_eif_sha384,
            "expectedPcrs": {
                name: value
                for name, value in zip(
                    ("PCR0", "PCR1", "PCR2"),
                    nitro_trust.expected_pcrs,
                    strict=True,
                )
            },
            "verificationContract": (
                "direct-cose-sign1-es384-aws-chain-crl-time-pcr-nonce-user-data"
            ),
            "custodyScope": "not-established-by-hardware-identity",
        }
        document["proxySubproof"] = {
            "provider": proxy_subproof.provider,
            "keyId": proxy_subproof.key_id,
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
        hardware_subproof=hardware_subproof,
        proxy_subproof=proxy_subproof,
        final_authority=final_authority,
        canonical_bytes=canonical,
        digest="sha256:" + hashlib.sha256(canonical).hexdigest(),
    )


@lru_cache(maxsize=1)
def setup_receipt_trust_profile() -> SetupReceiptTrustProfile:
    nitro_trust = _setup_nitro_trust()
    hardware_verifier = _bind_nitro_trust(
        _trusted_root(
            path=SETUP_HARDWARE_VERIFIER_PUBLIC_KEY_PATH,
            expected_key_id=SETUP_HARDWARE_VERIFIER_KEY_ID,
            provider=SETUP_HARDWARE_VERIFIER_PROVIDER,
            label="setup hardware verifier public key",
        ),
        nitro_trust,
    )
    return build_setup_receipt_trust_profile(
        enrollment_verifier=_trusted_root(
            path=SETUP_ENROLLMENT_VERIFIER_PUBLIC_KEY_PATH,
            expected_key_id=SETUP_ENROLLMENT_VERIFIER_KEY_ID,
            provider=SETUP_ENROLLMENT_VERIFIER_PROVIDER,
            label="setup enrollment verifier public key",
        ),
        hardware_verifier=hardware_verifier,
        hardware_subproof=None,
        proxy_subproof=_trusted_root(
            path=Path(os.environ["CATCHPLATE_SETUP_PROXY_SUBPROOF_PUBLIC_KEY_PATH"])
            if os.getenv("CATCHPLATE_SETUP_PROXY_SUBPROOF_PUBLIC_KEY_PATH")
            else None,
            expected_key_id=os.getenv(
                "CATCHPLATE_SETUP_PROXY_SUBPROOF_KEY_ID", ""
            ),
            provider=os.getenv(
                "CATCHPLATE_SETUP_PROXY_SUBPROOF_PROVIDER", ""
            ),
            label="setup proxy subproof public key",
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
