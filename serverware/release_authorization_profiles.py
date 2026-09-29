"""Closed release representation profiles; these confer no actor privilege."""

from __future__ import annotations

import hashlib
import json
import unicodedata


LEGACY_BINDING_V2 = "serverware.releaseAuthorizationBinding/v2"
NATIVE_BINDING_V1 = "serverware.nativeReleaseAuthorizationBinding/v1"
NATIVE_BINDING_V2 = "serverware.nativeReleaseAuthorizationBinding/v2"
BINDING_VERSIONS = frozenset({None, LEGACY_BINDING_V2, NATIVE_BINDING_V1, NATIVE_BINDING_V2})
DURABLE_BINDING_VERSIONS = frozenset({LEGACY_BINDING_V2, NATIVE_BINDING_V2})
NATIVE_BINDING_VERSIONS = frozenset({NATIVE_BINDING_V1, NATIVE_BINDING_V2})


def request_profile(api_version: str, operation: str) -> tuple[bool, bool]:
    if operation not in {"Prepare", "Reserve", "Dispatch", "Complete"}:
        raise ValueError("unsupported release authorization operation")
    for native in (False, True):
        if operation == "Prepare" and not native:
            continue
        family = "nativeReleaseAuthorization" if native else "releaseAuthorization"
        for durable in (False, True):
            if api_version == f"serverware.{family}{operation}/v{2 if durable else 1}":
                return native, durable
    raise ValueError("unsupported release authorization request profile")


def binding_version(*, native: bool, durable: bool) -> str | None:
    if type(native) is not bool or type(durable) is not bool:
        raise ValueError("release authorization profile must be explicit")
    if native:
        return NATIVE_BINDING_V2 if durable else NATIVE_BINDING_V1
    return LEGACY_BINDING_V2 if durable else None


def response_version(*, native: bool, durable: bool) -> str:
    binding_version(native=native, durable=durable)
    family = "nativeReleaseAuthorizationResponse" if native else "releaseAuthorization"
    return f"serverware.{family}/v{2 if durable else 1}"


def native_principal(value: str) -> str:
    try:
        valid = (
            type(value) is str
            and bool(value)
            and value == value.strip()
            and len(value.encode("utf-8")) <= 1024
            and not any(unicodedata.category(character) == "Cc" for character in value)
        )
    except UnicodeError:
        valid = False
    if not valid:
        raise ValueError("native release principal must be trimmed UTF-8 of 1..1024 bytes without controls")
    return value


def approver_policy_sha256(policy: dict | None) -> str:
    """Hash the normalized original value, including JSON null when JIT is off."""
    original = json.dumps(policy, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    return "sha256:" + hashlib.sha256(original.encode("ascii")).hexdigest()


def require_native_approver_policy(policy: dict | None) -> None:
    # The legacy normalizer permits arbitrary positive Python integers. The
    # separately versioned native wire uses the receiver's exact u64 range.
    if policy is not None:
        sequence = policy["credentialPolicy"]["minimumTrustBundleSequence"]
        if sequence is not None and (type(sequence) is not int or not 1 <= sequence <= (1 << 64) - 1):
            raise ValueError("native approver trust bundle sequence exceeds u64")
