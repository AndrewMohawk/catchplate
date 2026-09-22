#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from serverware.policy_bundle import (  # noqa: E402
    PolicyBundleError,
    compile_policy_bundle,
    policy_hash,
)
from verify_attestation import (  # noqa: E402
    spki_hash_from_public_key_pem,
    verify_policy_signature,
)


REPORT_API_VERSION = "serverware.productionPolicyIdentityVerification/v1"
REPORT_KIND = "ProductionPolicyIdentityVerification"
MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_PUBLIC_KEY_BYTES = 64 * 1024
MAX_BEARER_TTL_MS = 24 * 60 * 60 * 1000
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SIGNATURE_RE = re.compile(r"^ed25519:[A-Za-z0-9_-]{86}$")
TOKEN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
UNIVERSAL_NETWORKS = {"0.0.0.0/0", "::/0"}
LIMITATIONS = [
    "Bounded bearer identity is an interim control and remains replayable until expiry.",
    "A stored digest cannot prove bearer entropy; production issuance must generate high-entropy material.",
    "mTLS/SPIFFE workload identity is not implemented; this verifier does not claim non-spoofability.",
]


def _known_weak_bearer_digests() -> frozenset[str]:
    weak_values = (
        b"",
        b"password",
        b"password123",
        b"secret",
        b"token",
        b"changeme",
        b"default",
        b"demo-agent-proxy-token",
        b"demo-bound-proxy-token",
    )
    return frozenset("sha256:" + hashlib.sha256(value).hexdigest() for value in weak_values)


KNOWN_WEAK_BEARER_DIGESTS = _known_weak_bearer_digests()


class VerificationError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise VerificationError("invalid_arguments", "required verifier arguments are missing or invalid")


def issue(
    code: str,
    message: str,
    *,
    path: str | None = None,
    principal_id: str | None = None,
) -> dict[str, str]:
    result = {"code": code, "message": message}
    if path is not None:
        result["path"] = path
    if principal_id is not None:
        result["principalId"] = principal_id
    return result


def _identity_result(
    *,
    accepted: bool,
    principals: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    principal_summaries = principals or []
    return {
        "status": "accepted_interim_control" if accepted else "rejected",
        "control": "bounded_bearer_interim" if accepted else "none",
        "interim": accepted,
        "nonSpoofable": False,
        "principalCount": len(principal_summaries),
        "principals": principal_summaries,
        "limitations": list(LIMITATIONS),
    }


def report(
    *,
    ok: bool,
    issues: list[dict[str, str]],
    policy: dict[str, Any] | None = None,
    principals: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "apiVersion": REPORT_API_VERSION,
        "kind": REPORT_KIND,
        "mode": "production",
        "ok": ok,
        "outputScope": "policy_identity_metadata_only",
        "secretsRedacted": True,
        "policy": policy,
        "identity": _identity_result(accepted=ok, principals=principals),
        "issues": issues,
    }


def _reject_json_constant(value: str) -> None:
    raise VerificationError("invalid_json", "policy bundle must use strict JSON values")


def reject_duplicate_json_object_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError("duplicate_json_key", "policy bundle contains a duplicate JSON object key")
        result[key] = value
    return result


def load_policy_bundle(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise VerificationError("input_read_failed", "policy bundle could not be read") from exc
    return load_policy_bundle_bytes(raw)


def load_policy_bundle_bytes(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_INPUT_BYTES:
        raise VerificationError("input_too_large", "policy bundle exceeds the verifier input limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VerificationError("invalid_encoding", "policy bundle must be UTF-8") from exc
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=reject_duplicate_json_object_keys,
            parse_constant=_reject_json_constant,
        )
    except VerificationError:
        raise
    except json.JSONDecodeError as exc:
        raise VerificationError("invalid_json", "policy bundle is not valid JSON") from exc
    if not isinstance(parsed, dict):
        raise VerificationError("invalid_bundle_type", "policy bundle must be a JSON object")
    return parsed


def file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def load_trusted_public_key(path: Path) -> tuple[str, str]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise VerificationError("trust_root_read_failed", "trusted policy public key could not be read") from exc
    return load_trusted_public_key_bytes(raw)


def load_trusted_public_key_bytes(raw: bytes) -> tuple[str, str]:
    if len(raw) > MAX_PUBLIC_KEY_BYTES:
        raise VerificationError("trust_root_invalid", "trusted policy public key is invalid")
    if b"PRIVATE KEY" in raw:
        raise VerificationError("trust_root_invalid", "trusted policy key must contain public key material only")
    try:
        public_key_pem = raw.decode("ascii")
        public_key = serialization.load_pem_public_key(raw)
    except (UnicodeDecodeError, ValueError, TypeError) as exc:
        raise VerificationError("trust_root_invalid", "trusted policy public key is invalid") from exc
    if not isinstance(public_key, Ed25519PublicKey):
        raise VerificationError("trust_root_invalid", "trusted policy public key must be Ed25519")
    return public_key_pem, spki_hash_from_public_key_pem(public_key_pem)


def _strict_signature_shape(bundle: dict[str, Any]) -> None:
    metadata = bundle.get("metadata")
    if not isinstance(metadata, dict):
        raise VerificationError("metadata_missing", "signed policy bundle metadata is missing or invalid")
    signature = metadata.get("signature")
    if not isinstance(signature, str) or SIGNATURE_RE.fullmatch(signature) is None:
        raise VerificationError("signature_malformed", "policy bundle signature is not a canonical Ed25519 signature")


def _safe_principal_id(item: Any, index: int) -> str | None:
    if not isinstance(item, dict):
        return None
    value = item.get("id")
    if not isinstance(value, str) or not value:
        return None
    return value


def _identity_shape_issues(bundle: dict[str, Any]) -> list[dict[str, str]]:
    issues: list[dict[str, str]] = []
    principals = bundle.get("principals")
    if not isinstance(principals, list):
        return issues
    for index, item in enumerate(principals):
        if not isinstance(item, dict):
            continue
        principal_id = _safe_principal_id(item, index)
        proxy = item.get("proxyAuthorization")
        if not isinstance(proxy, dict):
            continue
        token_digest = proxy.get("tokenSha256")
        if not isinstance(token_digest, str) or SHA256_RE.fullmatch(token_digest) is None:
            issues.append(
                issue(
                    "malformed_bearer_digest",
                    "structured bearer token digest must be canonical sha256",
                    path=f"principals[{index}].proxyAuthorization.tokenSha256",
                    principal_id=principal_id,
                )
            )
        if "expiresAtEpochMs" in proxy:
            expiry = proxy.get("expiresAtEpochMs")
            if isinstance(expiry, bool) or not isinstance(expiry, int) or expiry < 1:
                issues.append(
                    issue(
                        "malformed_bearer_expiry",
                        "structured bearer expiry must be a positive epoch-millisecond integer",
                        path=f"principals[{index}].proxyAuthorization.expiresAtEpochMs",
                        principal_id=principal_id,
                    )
                )
    return issues


def _network_strings(raw_cidrs: Any) -> list[str]:
    if not isinstance(raw_cidrs, list):
        return []
    return [str(ipaddress.ip_network(value, strict=False)) for value in raw_cidrs]


def _networks_overlap(left: list[str], right: list[str]) -> bool:
    left_networks = [ipaddress.ip_network(value) for value in left]
    right_networks = [ipaddress.ip_network(value) for value in right]
    return any(
        first.version == second.version and first.overlaps(second)
        for first in left_networks
        for second in right_networks
    )


def _weak_digest(token_digest: str) -> bool:
    if token_digest in KNOWN_WEAK_BEARER_DIGESTS:
        return True
    digest_hex = token_digest.split(":", 1)[1]
    return len(set(digest_hex)) <= 2


def _header_binding_issues(
    headers: Any,
    *,
    index: int,
    principal_id: str,
) -> list[dict[str, str]]:
    if not isinstance(headers, dict):
        return []
    issues: list[dict[str, str]] = []
    seen_names: set[str] = set()
    weak_values = {"demo", "test", "default", "changeme", "secret", "password", "token"}
    for name, value in headers.items():
        normalized_name = str(name).strip().lower()
        if normalized_name in seen_names:
            issues.append(
                issue(
                    "duplicate_header_binding",
                    "principal repeats an identity header using a case-insensitive name",
                    path=f"principals[{index}].requiredHeaders",
                    principal_id=principal_id,
                )
            )
        seen_names.add(normalized_name)
        if (
            HEADER_NAME_RE.fullmatch(str(name)) is None
            or not isinstance(value, str)
            or len(value) < 8
            or len(value) > 256
            or value.strip().lower() in weak_values
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            issues.append(
                issue(
                    "weak_header_binding",
                    "principal identity header binding is empty, malformed, placeholder-like, or too short",
                    path=f"principals[{index}].requiredHeaders",
                    principal_id=principal_id,
                )
            )
    return issues


def inspect_production_identities(
    bundle: dict[str, Any],
    *,
    now_epoch_ms: int,
    max_bearer_ttl_ms: int = MAX_BEARER_TTL_MS,
) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    issues: list[dict[str, str]] = []
    summaries: list[dict[str, Any]] = []
    digest_owners: dict[str, str] = {}
    token_id_owners: dict[str, str] = {}
    weak_binding_owners: dict[tuple[tuple[str, ...], tuple[tuple[str, str], ...]], str] = {}
    principal_ids: set[str] = set()

    for index, item in enumerate(bundle.get("principals") or []):
        if not isinstance(item, dict):
            continue
        principal_id = _safe_principal_id(item, index) or f"principal-index-{index}"
        path = f"principals[{index}]"
        if principal_id in principal_ids:
            issues.append(
                issue(
                    "duplicate_principal_id",
                    "principal id must be unique",
                    path=f"{path}.id",
                    principal_id=principal_id,
                )
            )
        principal_ids.add(principal_id)

        raw_source_cidrs = item.get("sourceCidrs")
        raw_headers = item.get("requiredHeaders")
        source_cidrs = _network_strings(raw_source_cidrs)
        headers = raw_headers if isinstance(raw_headers, dict) else {}
        has_cidrs = bool(source_cidrs)
        has_headers = bool(headers)
        proxy = item.get("proxyAuthorization")

        issues.extend(_header_binding_issues(headers, index=index, principal_id=principal_id))

        normalized_headers = tuple(sorted((str(name).lower(), str(value)) for name, value in headers.items()))
        weak_binding = (tuple(sorted(source_cidrs)), normalized_headers)
        if has_cidrs or has_headers:
            prior_weak_owner = weak_binding_owners.get(weak_binding)
            if prior_weak_owner is not None and prior_weak_owner != principal_id:
                issues.append(
                    issue(
                        "reused_weak_binding",
                        "multiple principals reuse the same weak CIDR/header selector binding",
                        path=path,
                        principal_id=principal_id,
                    )
                )
            else:
                weak_binding_owners[weak_binding] = principal_id

        if proxy is None:
            if has_cidrs and has_headers:
                code = "ambiguous_multiple_weak_selectors"
                message = "principal combines multiple weak selectors without a bounded bearer identity"
            elif has_headers:
                code = "header_only_principal"
                message = "header-only principals are forbidden in production"
            elif has_cidrs:
                code = "cidr_only_principal"
                message = "CIDR-only principals are forbidden in production"
            else:
                code = "identity_selector_missing"
                message = "principal has no production identity selector"
            issues.append(issue(code, message, path=path, principal_id=principal_id))
            continue

        if isinstance(proxy, str):
            issues.append(
                issue(
                    "legacy_exact_proxy_secret",
                    "legacy exact proxy authorization secrets are forbidden in production",
                    path=f"{path}.proxyAuthorization",
                    principal_id=principal_id,
                )
            )
            continue
        if not isinstance(proxy, dict):
            issues.append(
                issue(
                    "structured_bearer_required",
                    "principal must use a structured bounded bearer identity",
                    path=f"{path}.proxyAuthorization",
                    principal_id=principal_id,
                )
            )
            continue

        token_id = proxy.get("tokenId")
        token_digest = proxy.get("tokenSha256")
        bearer_source_cidrs = _network_strings(proxy.get("sourceCidrs"))
        expiry = proxy.get("expiresAtEpochMs")

        if not isinstance(token_id, str) or TOKEN_ID_RE.fullmatch(token_id) is None:
            issues.append(
                issue(
                    "weak_token_identifier",
                    "bounded bearer tokenId must be a stable 8-128 character identifier",
                    path=f"{path}.proxyAuthorization.tokenId",
                    principal_id=principal_id,
                )
            )
        else:
            prior_token_id_owner = token_id_owners.get(token_id)
            if prior_token_id_owner is not None and prior_token_id_owner != principal_id:
                issues.append(
                    issue(
                        "duplicate_token_id",
                        "bounded bearer tokenId is assigned to multiple principals",
                        path=f"{path}.proxyAuthorization.tokenId",
                        principal_id=principal_id,
                    )
                )
            else:
                token_id_owners[token_id] = principal_id

        if isinstance(token_digest, str) and SHA256_RE.fullmatch(token_digest):
            if _weak_digest(token_digest):
                issues.append(
                    issue(
                        "weak_bearer_digest",
                        "bounded bearer digest is a known weak value or a non-random sentinel",
                        path=f"{path}.proxyAuthorization.tokenSha256",
                        principal_id=principal_id,
                    )
                )
            prior_digest_owner = digest_owners.get(token_digest)
            if prior_digest_owner is not None and prior_digest_owner != principal_id:
                issues.append(
                    issue(
                        "reused_bearer_digest",
                        "bounded bearer digest is assigned to multiple principals",
                        path=f"{path}.proxyAuthorization.tokenSha256",
                        principal_id=principal_id,
                    )
                )
            else:
                digest_owners[token_digest] = principal_id

        if not bearer_source_cidrs:
            issues.append(
                issue(
                    "bearer_source_binding_missing",
                    "bounded bearer identity must include at least one source CIDR",
                    path=f"{path}.proxyAuthorization.sourceCidrs",
                    principal_id=principal_id,
                )
            )

        for field_name, cidrs in (("sourceCidrs", source_cidrs), ("proxyAuthorization.sourceCidrs", bearer_source_cidrs)):
            if any(value in UNIVERSAL_NETWORKS for value in cidrs):
                issues.append(
                    issue(
                        "universal_source_cidr",
                        "universal source CIDRs are forbidden in production identity bindings",
                        path=f"{path}.{field_name}",
                        principal_id=principal_id,
                    )
                )
            if len(cidrs) != len(set(cidrs)):
                issues.append(
                    issue(
                        "duplicate_source_binding",
                        "principal repeats an equivalent source CIDR binding",
                        path=f"{path}.{field_name}",
                        principal_id=principal_id,
                    )
                )

        if source_cidrs and bearer_source_cidrs:
            if set(source_cidrs).intersection(bearer_source_cidrs):
                issues.append(
                    issue(
                        "duplicate_source_binding",
                        "principal repeats the same source binding at principal and bearer scope",
                        path=path,
                        principal_id=principal_id,
                    )
                )
            if not _networks_overlap(source_cidrs, bearer_source_cidrs):
                issues.append(
                    issue(
                        "disjoint_source_bindings",
                        "principal and bearer source bindings do not overlap",
                        path=path,
                        principal_id=principal_id,
                    )
                )

        if expiry is None:
            issues.append(
                issue(
                    "bearer_expiry_missing",
                    "bounded bearer identity must include an expiry",
                    path=f"{path}.proxyAuthorization.expiresAtEpochMs",
                    principal_id=principal_id,
                )
            )
        elif isinstance(expiry, int) and not isinstance(expiry, bool):
            if expiry <= now_epoch_ms:
                issues.append(
                    issue(
                        "bearer_expired",
                        "bounded bearer identity is expired",
                        path=f"{path}.proxyAuthorization.expiresAtEpochMs",
                        principal_id=principal_id,
                    )
                )
            elif expiry - now_epoch_ms > max_bearer_ttl_ms:
                issues.append(
                    issue(
                        "bearer_expiry_overlong",
                        "bounded bearer validity exceeds the production maximum of 24 hours",
                        path=f"{path}.proxyAuthorization.expiresAtEpochMs",
                        principal_id=principal_id,
                    )
                )

        if not any(candidate.get("principalId") == principal_id for candidate in issues):
            summaries.append(
                {
                    "id": principal_id,
                    "identityControl": "bounded_bearer_interim",
                    "expiresAtEpochMs": expiry,
                }
            )

    return issues, summaries


def verify_production_policy_identity(
    bundle: dict[str, Any],
    trusted_public_key_pem: str,
    *,
    trusted_public_key_hash: str | None = None,
    now_epoch_ms: int | None = None,
) -> dict[str, Any]:
    now_ms = int(time.time() * 1000) if now_epoch_ms is None else now_epoch_ms
    try:
        _strict_signature_shape(bundle)
        actual_key_hash = spki_hash_from_public_key_pem(trusted_public_key_pem)
        if trusted_public_key_hash is not None and trusted_public_key_hash != actual_key_hash:
            raise VerificationError(
                "trust_root_digest_mismatch",
                "provided policy trust-root digest does not match the trusted public key",
            )
        metadata = bundle["metadata"]
        signing_key_id = metadata.get("signingKeyId")
        if not isinstance(signing_key_id, str) or SHA256_RE.fullmatch(signing_key_id) is None:
            raise VerificationError(
                "malformed_signing_key_digest",
                "policy metadata signingKeyId must be canonical sha256",
            )
        if signing_key_id != actual_key_hash:
            raise VerificationError(
                "untrusted_signing_key",
                "policy signing key does not match the pinned trust root",
            )
        try:
            verify_policy_signature(bundle, trusted_public_key_pem)
        except Exception as exc:
            raise VerificationError(
                "signature_verification_failed",
                "policy bundle signature verification failed",
            ) from exc

        shape_issues = _identity_shape_issues(bundle)
        try:
            compile_policy_bundle(bundle, validate_schema=True, verify_signature=False)
        except (PolicyBundleError, KeyError, TypeError, ValueError) as exc:
            if shape_issues:
                return report(ok=False, issues=shape_issues)
            raise VerificationError(
                "policy_validation_failed",
                "signed policy bundle failed existing schema or semantic validation",
            ) from exc

        policy_summary = {
            "id": metadata.get("id"),
            "sequence": metadata.get("sequence"),
            "rollbackEpoch": metadata.get("rollbackEpoch"),
            "hash": policy_hash(bundle),
            "signingKeyId": signing_key_id,
        }
        identity_issues, principal_summaries = inspect_production_identities(bundle, now_epoch_ms=now_ms)
        if identity_issues:
            return report(ok=False, issues=identity_issues, policy=policy_summary)
        return report(ok=True, issues=[], policy=policy_summary, principals=principal_summaries)
    except VerificationError as exc:
        return report(ok=False, issues=[issue(exc.code, exc.message)])


def build_parser() -> argparse.ArgumentParser:
    parser = JsonArgumentParser(
        description="Verify production PolicyBundle identity strength against a pinned Ed25519 trust root."
    )
    parser.add_argument("--bundle", required=True, type=Path, help="signed PolicyBundle JSON artifact")
    parser.add_argument(
        "--trusted-public-key",
        required=True,
        type=Path,
        help="pinned Ed25519 policy-signing public key PEM",
    )
    parser.add_argument(
        "--out",
        type=Path,
        help="private persisted verification artifact consumed by production preflight and completion",
    )
    return parser


def persisted_report(
    result: dict[str, Any],
    *,
    bundle_path: Path,
    trusted_public_key_path: Path,
    trusted_public_key_hash: str,
) -> dict[str, Any]:
    return persisted_report_bytes(
        result,
        bundle_bytes=bundle_path.read_bytes(),
        trusted_public_key_bytes=trusted_public_key_path.read_bytes(),
        trusted_public_key_hash=trusted_public_key_hash,
    )


def persisted_report_bytes(
    result: dict[str, Any],
    *,
    bundle_bytes: bytes,
    trusted_public_key_bytes: bytes,
    trusted_public_key_hash: str,
) -> dict[str, Any]:
    bound = dict(result)
    bound["artifactBindings"] = {
        "policyBundle": {
            "sha256": "sha256:" + hashlib.sha256(bundle_bytes).hexdigest(),
            "runtimePolicyHash": (result.get("policy") or {}).get("hash"),
        },
        "trustedPublicKey": {
            "sha256": "sha256:" + hashlib.sha256(trusted_public_key_bytes).hexdigest(),
            "spkiSha256": trusted_public_key_hash,
        },
    }
    return bound


def write_private(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def verify_persisted_report(
    *,
    bundle_path: Path,
    trusted_public_key_path: Path,
    report_path: Path,
) -> dict[str, Any]:
    try:
        bundle_bytes = bundle_path.read_bytes()
        trusted_public_key_bytes = trusted_public_key_path.read_bytes()
        report_bytes = report_path.read_bytes()
    except OSError as exc:
        raise VerificationError("input_read_failed", "policy identity evidence could not be read") from exc
    return verify_persisted_report_bytes(
        bundle_bytes=bundle_bytes,
        trusted_public_key_bytes=trusted_public_key_bytes,
        report_bytes=report_bytes,
    )


def verify_persisted_report_bytes(
    *,
    bundle_bytes: bytes,
    trusted_public_key_bytes: bytes,
    report_bytes: bytes,
) -> dict[str, Any]:
    bundle = load_policy_bundle_bytes(bundle_bytes)
    public_key_pem, public_key_hash = load_trusted_public_key_bytes(trusted_public_key_bytes)
    current = verify_production_policy_identity(
        bundle,
        public_key_pem,
        trusted_public_key_hash=public_key_hash,
    )
    if current.get("ok") is not True:
        raise VerificationError("policy_identity_rejected", "current production policy identity verification failed")
    expected = persisted_report_bytes(
        current,
        bundle_bytes=bundle_bytes,
        trusted_public_key_bytes=trusted_public_key_bytes,
        trusted_public_key_hash=public_key_hash,
    )
    actual = load_policy_bundle_bytes(report_bytes)
    if actual != expected:
        raise VerificationError(
            "stale_identity_verification",
            "persisted production policy identity verification does not match the current policy and trust root",
        )
    policy = expected.get("policy") or {}
    bindings = expected["artifactBindings"]
    return {
        "ok": True,
        "reportSha256": "sha256:" + hashlib.sha256(report_bytes).hexdigest(),
        "policyBundleSha256": bindings["policyBundle"]["sha256"],
        "policyHash": policy.get("hash"),
        "policyId": policy.get("id"),
        "policySequence": policy.get("sequence"),
        "policyRollbackEpoch": policy.get("rollbackEpoch"),
        "signingKeyId": policy.get("signingKeyId"),
        "trustedPublicKeySha256": bindings["trustedPublicKey"]["sha256"],
        "trustedPublicKeySpkiSha256": bindings["trustedPublicKey"]["spkiSha256"],
        "identityControl": (expected.get("identity") or {}).get("control"),
        "nonSpoofable": (expected.get("identity") or {}).get("nonSpoofable"),
    }


def main(argv: list[str] | None = None) -> int:
    args: argparse.Namespace | None = None
    try:
        args = build_parser().parse_args(argv)
        try:
            bundle_bytes = args.bundle.read_bytes()
        except OSError as exc:
            raise VerificationError("input_read_failed", "policy bundle could not be read") from exc
        try:
            trusted_public_key_bytes = args.trusted_public_key.read_bytes()
        except OSError as exc:
            raise VerificationError("trust_root_read_failed", "trusted policy public key could not be read") from exc
        bundle = load_policy_bundle_bytes(bundle_bytes)
        public_key_pem, public_key_hash = load_trusted_public_key_bytes(trusted_public_key_bytes)
        result = verify_production_policy_identity(
            bundle,
            public_key_pem,
            trusted_public_key_hash=public_key_hash,
        )
        result = persisted_report_bytes(
            result,
            bundle_bytes=bundle_bytes,
            trusted_public_key_bytes=trusted_public_key_bytes,
            trusted_public_key_hash=public_key_hash,
        )
    except VerificationError as exc:
        result = report(ok=False, issues=[issue(exc.code, exc.message)])
    except Exception:
        result = report(
            ok=False,
            issues=[issue("verification_failed", "production policy identity verification failed closed")],
        )
    if args is not None and args.out is not None:
        write_private(args.out, result)
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
