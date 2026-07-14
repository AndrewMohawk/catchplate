from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import shutil
import shlex
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from serverware import __version__, db
from serverware.config import (
    DATA_PLANE_LEASE_RECIPIENT_ATTESTATION_REQUIRED,
    DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND,
    EXPECTED_DATA_PLANE_BINARY_DIGEST,
    IMAGE_SIGNATURES_PATH,
    KEY_RELEASE_ALLOW_DEBUG,
    KEY_RELEASE_REQUIRED,
    KEY_RELEASE_REQUIRE_DATA_PLANE_DIGEST,
    MASTER_KEY_UNSEAL_COMMAND,
    MITMPROXY_CONF_DIR,
    NITRO_NSM_UNSEAL_COMMAND_TEMPLATE,
    POLICY_MIN_ROLLBACK_EPOCH,
    POLICY_MIN_SEQUENCE,
    RELEASE_CHANNEL,
    RELEASE_PROVENANCE_PATH,
    SECRET_LEASE_TTL_SECONDS,
    TEE_PLATFORM,
    TEE_QUOTE_COMMAND,
    TEE_QUOTE_PROVIDER,
    TEE_QUOTE_SIGNING_KEY_PATH,
    TEE_QUOTE_VERIFY_COMMAND,
    WEB_TLS_CERT_FILE,
    ensure_data_dirs,
)
from serverware.policy_bundle import get_policy_snapshot, policy_public_key_hash, policy_public_key_pem
from serverware.response_identity import response_public_key_info


_TEE_HELPER_ENV_NAMES = (
    "PATH",
    "LANG",
    "LC_ALL",
    "TZ",
    "SERVERWARE_DATA_DIR",
    "SERVERWARE_EXTERNAL_TEE_FIXTURE_KEY",
    "SERVERWARE_NITRO_ALLOW_DEBUG",
    "SERVERWARE_NITRO_ALLOW_DEBUG_RELEASE",
    "SERVERWARE_NITRO_ALLOWED_MATERIALS",
    "SERVERWARE_NITRO_ATTESTATION_COMMAND",
    "SERVERWARE_NITRO_ATTESTATION_DOCUMENT",
    "SERVERWARE_NITRO_ATTESTATION_DOCUMENT_B64",
    "SERVERWARE_NITRO_CLOCK_SKEW_SECONDS",
    "SERVERWARE_NITRO_EXPECTED_PCRS",
    "SERVERWARE_NITRO_FIXTURE",
    "SERVERWARE_NITRO_FIXTURE_DEBUG",
    "SERVERWARE_NITRO_FIXTURE_DIR",
    "SERVERWARE_NITRO_FIXTURE_PCRS",
    "SERVERWARE_NITRO_KMS_FIXTURE_KEY",
    "SERVERWARE_NITRO_KMS_RELEASE_COMMAND",
    "SERVERWARE_NITRO_KMS_TIMEOUT_SECONDS",
    "SERVERWARE_NITRO_MAX_AGE_SECONDS",
    "SERVERWARE_NITRO_REQUIRE_KMS_COMMAND",
    "SERVERWARE_NITRO_ROOT_CERT",
    "SERVERWARE_NITRO_ROOT_CERT_PEM",
    "SERVERWARE_NITRO_ROOT_SHA256",
)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _run_json_command(command: str, payload: dict[str, Any], label: str) -> dict[str, Any]:
    if not command:
        raise ValueError(f"{label} is not configured")
    helper_env = {
        key: os.environ[key]
        for key in _TEE_HELPER_ENV_NAMES
        if key in os.environ
    }
    with tempfile.TemporaryFile() as helper_stdin, tempfile.TemporaryFile() as helper_stdout:
        helper_stdin.write((canonical_json(payload) + "\n").encode("utf-8"))
        helper_stdin.seek(0)
        process = subprocess.Popen(
            shlex.split(command),
            stdin=helper_stdin,
            stdout=helper_stdout,
            stderr=subprocess.DEVNULL,
            env=helper_env,
            start_new_session=True,
        )
        deadline = time.monotonic() + 10.0
        while process.poll() is None:
            if os.fstat(helper_stdout.fileno()).st_size > 64 * 1024:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                raise ValueError(f"{label} output exceeds 64 KiB")
            if time.monotonic() >= deadline:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                raise ValueError(f"{label} timed out")
            time.sleep(0.005)
        if process.returncode != 0:
            raise ValueError(f"{label} rejected the request")
        helper_stdout.seek(0)
        raw_output = helper_stdout.read(64 * 1024 + 1)
    if len(raw_output) > 64 * 1024:
        raise ValueError(f"{label} output exceeds 64 KiB")
    try:
        value = json.loads(raw_output.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must return a JSON object")
    return value


def _load_dev_quote_key() -> Ed25519PrivateKey:
    ensure_data_dirs()
    if TEE_QUOTE_SIGNING_KEY_PATH.exists():
        return serialization.load_pem_private_key(TEE_QUOTE_SIGNING_KEY_PATH.read_bytes(), password=None)
    key = Ed25519PrivateKey.generate()
    TEE_QUOTE_SIGNING_KEY_PATH.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(TEE_QUOTE_SIGNING_KEY_PATH, 0o600)
    return key


def quote_public_key_info() -> dict[str, str]:
    public_key = _load_dev_quote_key().public_key()
    pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {"pem": pem, "spki_sha256": sha256_prefixed(der)}


def runtime_manifest() -> dict[str, Any]:
    return {
        "mode": "dev" if TEE_QUOTE_PROVIDER == "dev-signed-quote" else "tee",
        "tee_quote_provider": TEE_QUOTE_PROVIDER,
        "tee_platform": TEE_PLATFORM,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "serverware_version": __version__,
        "policy_signing_key_id": policy_public_key_hash(),
        "policy_high_water_store": db.metadata_store_backend_name(),
        "policy_minimum_sequence": POLICY_MIN_SEQUENCE,
        "policy_minimum_rollback_epoch": POLICY_MIN_ROLLBACK_EPOCH,
        "release_channel": RELEASE_CHANNEL,
        "key_release_required": KEY_RELEASE_REQUIRED,
        "key_release_require_data_plane_digest": KEY_RELEASE_REQUIRE_DATA_PLANE_DIGEST,
        "master_key_source": "memory-unseal-command" if MASTER_KEY_UNSEAL_COMMAND else "development-local",
        "master_key_persisted_in_production": False,
        "master_key_unseal_command_sha256": (
            sha256_prefixed(MASTER_KEY_UNSEAL_COMMAND.encode("utf-8")) if MASTER_KEY_UNSEAL_COMMAND else None
        ),
        "master_key_unseal_command_measurement": _command_artifact_measurements(MASTER_KEY_UNSEAL_COMMAND),
        "nitro_nsm_unseal_command_sha256": (
            sha256_prefixed(NITRO_NSM_UNSEAL_COMMAND_TEMPLATE.encode("utf-8"))
            if NITRO_NSM_UNSEAL_COMMAND_TEMPLATE
            else None
        ),
        "nitro_nsm_unseal_command_measurement": _command_artifact_measurements(
            NITRO_NSM_UNSEAL_COMMAND_TEMPLATE
        ),
        "expected_data_plane_binary_digest": EXPECTED_DATA_PLANE_BINARY_DIGEST,
        "credential_lease_protocol": "serverware.credentialLeaseEnvelope/v2",
        "credential_lease_transport": "recipient-bound-encrypted-pull",
        "credential_lease_ttl_seconds": SECRET_LEASE_TTL_SECONDS,
        "credential_lease_recipient_attestation_required": DATA_PLANE_LEASE_RECIPIENT_ATTESTATION_REQUIRED,
        "credential_lease_recipient_verifier_command_sha256": (
            sha256_prefixed(DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND.encode("utf-8"))
            if DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND
            else None
        ),
        "credential_lease_recipient_verifier_measurement": _command_artifact_measurements(
            DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND
        ),
        "plaintext_credential_delivery": False,
    }


def runtime_manifest_digest(manifest: dict[str, Any] | None = None) -> str:
    value = runtime_manifest() if manifest is None else manifest
    return sha256_prefixed(repr(sorted(value.items())).encode("utf-8"))


def ca_spki_hash() -> str | None:
    ca_path = MITMPROXY_CONF_DIR / "mitmproxy-ca-cert.pem"
    if not ca_path.exists():
        return None
    cert = x509.load_pem_x509_certificate(ca_path.read_bytes())
    der = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256_prefixed(der)


def service_tls_spki_hash() -> str | None:
    if not WEB_TLS_CERT_FILE:
        return None
    cert_path = Path(WEB_TLS_CERT_FILE)
    if not cert_path.is_file():
        raise ValueError("configured service TLS certificate is unavailable")
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    der = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256_prefixed(der)


def _command_artifact_measurements(command: str) -> dict[str, Any] | None:
    if not command:
        return None
    artifacts: list[dict[str, Any]] = []
    seen: set[Path] = set()
    for value in shlex.split(command):
        candidate = Path(value)
        if not candidate.is_file() and len(candidate.parts) == 1:
            resolved = shutil.which(value)
            candidate = Path(resolved) if resolved else candidate
        if not candidate.is_file():
            continue
        resolved = candidate.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        raw = resolved.read_bytes()
        artifacts.append(
            {"path": str(resolved), "sha256": sha256_prefixed(raw), "size_bytes": len(raw)}
        )
    return {
        "command_sha256": sha256_prefixed(command.encode("utf-8")),
        "artifacts": artifacts,
    }


def release_provenance_digest() -> str | None:
    if not RELEASE_PROVENANCE_PATH.exists():
        return None
    raw = RELEASE_PROVENANCE_PATH.read_bytes()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return sha256_prefixed(raw)
    digest = data.get("provenance_digest") if isinstance(data, dict) else None
    return digest if isinstance(digest, str) and digest.startswith("sha256:") else sha256_prefixed(raw)


def image_signatures_digest() -> str | None:
    if not IMAGE_SIGNATURES_PATH.exists():
        return None
    raw = IMAGE_SIGNATURES_PATH.read_bytes()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return sha256_prefixed(raw)
    digest = data.get("image_signature_bundle_digest") if isinstance(data, dict) else None
    return digest if isinstance(digest, str) and digest.startswith("sha256:") else sha256_prefixed(raw)


def release_provenance_document() -> dict[str, Any] | None:
    if not RELEASE_PROVENANCE_PATH.exists():
        return None
    try:
        value = json.loads(RELEASE_PROVENANCE_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def image_signatures_document() -> dict[str, Any] | None:
    if not IMAGE_SIGNATURES_PATH.exists():
        return None
    try:
        value = json.loads(IMAGE_SIGNATURES_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def source_tree_digest() -> str | None:
    document = release_provenance_document()
    source_tree = ((document or {}).get("provenance") or {}).get("source_tree") or {}
    digest = source_tree.get("digest") if isinstance(source_tree, dict) else None
    return digest if isinstance(digest, str) and digest.startswith("sha256:") else None


def _unsigned_quote(payload: dict[str, Any]) -> dict[str, Any]:
    copied = json.loads(json.dumps(payload))
    copied.pop("signature", None)
    return copied


def sign_quote(claims: dict[str, Any]) -> dict[str, Any]:
    if TEE_QUOTE_PROVIDER != "dev-signed-quote":
        quote = _run_json_command(TEE_QUOTE_COMMAND, {"claims": claims}, "TEE quote command")
        quote.setdefault("version", 1)
        quote.setdefault("provider", TEE_QUOTE_PROVIDER)
        quote.setdefault("tee_platform", TEE_PLATFORM)
        quote_claims = quote.get("claims")
        if not isinstance(quote_claims, dict):
            raise ValueError("TEE quote command must return normalized claims")
        return quote
    key = _load_dev_quote_key()
    key_info = quote_public_key_info()
    quote = {
        "version": 1,
        "provider": "dev-signed-quote",
        "tee_platform": "none-dev",
        "issued_at_ms": int(time.time() * 1000),
        "debug": True,
        "quote_signing_key_id": key_info["spki_sha256"],
        "quote_signing_public_key_pem": key_info["pem"],
        "claims": claims,
    }
    quote["signature"] = "ed25519:" + b64e(key.sign(canonical_json(_unsigned_quote(quote)).encode("utf-8")))
    return quote


def verify_quote_signature(quote: dict[str, Any]) -> None:
    if quote.get("provider") != "dev-signed-quote":
        if not TEE_QUOTE_VERIFY_COMMAND:
            raise ValueError("external TEE quote verification command is not configured")
        return
    signature = quote.get("signature")
    public_key_pem = quote.get("quote_signing_public_key_pem")
    if not isinstance(signature, str) or not signature.startswith("ed25519:"):
        raise ValueError("quote is missing an ed25519 signature")
    if not isinstance(public_key_pem, str):
        raise ValueError("quote is missing public key")
    public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    try:
        public_key.verify(b64d(signature.split(":", 1)[1]), canonical_json(_unsigned_quote(quote)).encode("utf-8"))
    except InvalidSignature as exc:
        raise ValueError("quote signature verification failed") from exc
    key_info_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if quote.get("quote_signing_key_id") != sha256_prefixed(key_info_der):
        raise ValueError("quote signing key id does not match public key")


def verify_attestation_quote(attestation: dict[str, Any]) -> dict[str, Any]:
    quote = attestation.get("quote")
    if not isinstance(quote, dict):
        raise ValueError("attestation quote is missing")
    if quote.get("provider") == "dev-signed-quote":
        verify_quote_signature(quote)
        claims = quote.get("claims")
    else:
        verified = _run_json_command(
            TEE_QUOTE_VERIFY_COMMAND,
            {"attestation": attestation},
            "TEE quote verification command",
        )
        claims = verified.get("claims", verified)
    if not isinstance(claims, dict):
        raise ValueError("attestation quote claims are missing")
    return claims


def attestation_document(nonce: str | None = None) -> dict[str, Any]:
    snapshot = get_policy_snapshot()
    metadata = snapshot.raw.get("metadata") if snapshot else {}
    manifest = runtime_manifest()
    policy_hash = snapshot.hash if snapshot else None
    rollback_epoch = metadata.get("rollbackEpoch") if isinstance(metadata, dict) else None
    policy_sequence = metadata.get("sequence") if isinstance(metadata, dict) else None
    high_water = db.get_policy_high_water() if snapshot else None
    if snapshot:
        expected_high_water = {
            "policy_id": metadata.get("id"),
            "sequence": policy_sequence,
            "rollback_epoch": rollback_epoch,
            "policy_hash": policy_hash,
        }
        if not high_water or any(high_water.get(key) != value for key, value in expected_high_water.items()):
            raise ValueError("active policy does not match the persisted policy high-water record")
    high_water_evidence = (
        {
            "store": db.metadata_store_backend_name(),
            "policyId": high_water["policy_id"],
            "sequence": high_water["sequence"],
            "rollbackEpoch": high_water["rollback_epoch"],
            "policyHash": high_water["policy_hash"],
            "updatedAt": high_water["updated_at"],
        }
        if high_water
        else None
    )
    high_water_digest = (
        sha256_prefixed(canonical_json(high_water_evidence).encode("utf-8"))
        if high_water_evidence
        else None
    )
    ca_hash = ca_spki_hash()
    provenance_digest = release_provenance_digest()
    image_signature_digest = image_signatures_digest()
    source_digest = source_tree_digest()
    service_tls_spki = service_tls_spki_hash()
    response_key_info = response_public_key_info()
    data_plane_digest = EXPECTED_DATA_PLANE_BINARY_DIGEST
    quote_claims = {
        "nonce": nonce,
        "runtime_manifest_digest": runtime_manifest_digest(manifest),
        "policy_bundle_digest": policy_hash,
        "policy_sequence": policy_sequence,
        "policy_high_water_digest": high_water_digest,
        "policy_signing_key_id": metadata.get("signingKeyId") if isinstance(metadata, dict) else None,
        "ca_intermediate_spki_sha256": ca_hash,
        "data_plane_binary_digest": data_plane_digest,
        "service_tls_spki_sha256": service_tls_spki,
        "rollback_epoch": rollback_epoch,
        "provenance_digest": provenance_digest,
        "image_signatures_digest": image_signature_digest,
        "source_tree_digest": source_digest,
        "response_signing_key_id": response_key_info["spki_sha256"],
        "release_channel": RELEASE_CHANNEL,
        "debug": TEE_QUOTE_PROVIDER == "dev-signed-quote",
        "key_release_required": KEY_RELEASE_REQUIRED,
        "key_release_allow_debug": KEY_RELEASE_ALLOW_DEBUG,
        "materials": ["broker-kek", "decision-gate-ca"],
        "sealing_public_key_id": quote_public_key_info()["spki_sha256"],
    }
    quote = sign_quote(quote_claims)
    assurance = {
        "class": "development-consistency" if quote_claims["debug"] else "host-supplied-quote",
        "hardware_proof": False,
        "workload_custody_proven": False,
        "tls_peer_binding_proven": False,
        "fact_origin": "host-supplied",
        "completion_eligible": False,
        "reason": (
            "The current document correlates signed runtime facts but does not prove that "
            "policy enforcement, credential custody, and response generation ran inside one measured TEE."
        ),
    }
    return {
        "tee_platform": quote.get("tee_platform", TEE_PLATFORM),
        "quote": quote,
        "runtime_manifest": manifest,
        "runtime_manifest_digest": quote_claims["runtime_manifest_digest"],
        "policy_bundle_digest": policy_hash,
        "policy_sequence": policy_sequence,
        "policy_high_water": high_water_evidence,
        "policy_high_water_digest": high_water_digest,
        "policy_bundle_signature": metadata.get("signature") if isinstance(metadata, dict) else None,
        "policy_signing_key_id": metadata.get("signingKeyId") if isinstance(metadata, dict) else None,
        "policy_signing_public_key_pem": policy_public_key_pem(),
        "ca_intermediate_spki_sha256": ca_hash,
        "data_plane_binary_digest": data_plane_digest,
        "service_tls_spki_sha256": service_tls_spki,
        "rollback_epoch": rollback_epoch,
        "provenance_digest": provenance_digest,
        "image_signatures_digest": image_signature_digest,
        "source_tree_digest": source_digest,
        "response_signing_key_id": response_key_info["spki_sha256"],
        "response_signing_public_key_pem": response_key_info["pem"],
        "release_channel": RELEASE_CHANNEL,
        "nonce": nonce,
        "tls_exporter_binding": None,
        "assurance": assurance,
    }
