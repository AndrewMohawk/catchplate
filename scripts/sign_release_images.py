#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shlex
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

import catchplate_source_tree
import verify_production_readiness
import sigstore_json
from catchplate.http_client import request_bytes

FIXTURE_COMMAND_MARKERS = ("fixture", "cosign_fixture.py", "sigstore_fixture.py")


def canonical_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=True)


def sha256_prefixed_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_prefixed_json(value: Any) -> str:
    return sha256_prefixed_bytes(canonical_json(value).encode("utf-8"))


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def request_json(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    payload: Any | None = None,
    ca_bundle: Path | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    data = None if payload is None else canonical_json(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    if payload is not None:
        req.add_header("Content-Type", "application/json")
    context = ssl.create_default_context(cafile=str(ca_bundle)) if ca_bundle else None
    return json.loads(
        request_bytes(req, timeout=timeout, max_bytes=8 * 1024 * 1024, context=context).body
    )


def validate_production_anchor(url: str, token: str, ca_bundle: Path | None) -> None:
    parsed = urllib.parse.urlparse(url)
    hostname = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not hostname:
        raise ValueError("production image transparency anchor must be an HTTPS URL")
    if hostname in {"localhost", "127.0.0.1", "::1"} or hostname.endswith(".localhost"):
        raise ValueError("production image transparency anchor must not be loopback")
    if len(token) < 32:
        raise ValueError("production image transparency anchor token must be at least 32 characters")
    if ca_bundle and not ca_bundle.is_file():
        raise ValueError(f"production image transparency anchor CA bundle does not exist: {ca_bundle}")


def load_signing_key(path: Path) -> Ed25519PrivateKey:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    key = Ed25519PrivateKey.generate()
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(path, 0o600)
    return key


def public_key_info(key: Ed25519PrivateKey) -> dict[str, str]:
    public_key = key.public_key()
    pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {"pem": pem, "spki_sha256": sha256_prefixed_bytes(der)}


def load_trusted_release_key(path: Path) -> tuple[Ed25519PublicKey, str]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("release provenance trust root must be an existing regular non-symlink file")
    if path.stat().st_size > 65536:
        raise ValueError("release provenance trust root exceeds 65536 bytes")
    try:
        key = serialization.load_pem_public_key(path.read_bytes())
    except (TypeError, ValueError) as exc:
        raise ValueError("release provenance trust root is not a valid PEM public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("release provenance trust root must be an Ed25519 public key")
    der = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return key, sha256_prefixed_bytes(der)


def verify_release_transparency(
    document: dict[str, Any],
    *,
    expected_provider: str,
    expected_log_id: str,
    trusted_external_public_key_pem: str,
) -> None:
    import verify_release_completion

    transparency = document.get("transparency")
    if not isinstance(transparency, dict):
        raise ValueError("production release provenance is missing transparency evidence")
    verify_release_completion.transparency_record_binding(
        transparency,
        anchor_key="anchor_response",
        inclusion_key="inclusion_proof",
        expected_type="release.provenance.v2",
        expected_fields={
            "provenance_digest": document.get("provenance_digest"),
            "release_signing_key_id": document.get("release_signing_key_id"),
            "signature": document.get("signature"),
        },
        expected_external_provider=expected_provider,
        expected_external_log_id=expected_log_id,
        trusted_external_public_key_pem=trusted_external_public_key_pem,
        label="production release provenance",
    )


def verify_release_provenance(
    document: dict[str, Any],
    *,
    trusted_public_key_path: Path | None = None,
    require_transparency: bool = False,
    external_checkpoint_trusted_key_path: Path | None = None,
    expected_external_checkpoint_provider: str = "",
    expected_external_checkpoint_log_id: str = "",
) -> None:
    provenance = document.get("provenance")
    if not isinstance(provenance, dict):
        raise ValueError("release provenance document is missing provenance")
    production_source = "catchplate-digest-pinned-production-release"
    if provenance.get("source") == production_source and provenance.get("version") != 2:
        raise ValueError("production release provenance payload must use version 2")
    if require_transparency and (
        provenance.get("source") != production_source
        or provenance.get("version") != 2
    ):
        raise ValueError(
            "production image signing requires digest-pinned production provenance version 2"
        )
    expected_digest = sha256_prefixed_json(provenance)
    if document.get("provenance_digest") != expected_digest:
        raise ValueError("release provenance digest mismatch")
    signature = document.get("signature")
    public_key_pem = document.get("release_signing_public_key_pem")
    if not isinstance(signature, str) or not signature.startswith("ed25519:"):
        raise ValueError("release provenance is missing ed25519 signature")
    if not isinstance(public_key_pem, str):
        raise ValueError("release provenance is missing release signing public key")
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ValueError("release provenance contains an invalid public key") from exc
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("release provenance public key must be Ed25519")
    embedded_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    embedded_key_id = sha256_prefixed_bytes(embedded_der)
    if document.get("release_signing_key_id") != embedded_key_id:
        raise ValueError("release provenance signing key ID does not match its embedded public key")
    verification_key = public_key
    if trusted_public_key_path is not None:
        verification_key, trusted_key_id = load_trusted_release_key(trusted_public_key_path)
        if trusted_key_id != embedded_key_id:
            raise ValueError("release provenance signer does not match the independent trust root")
    try:
        verification_key.verify(b64d(signature.split(":", 1)[1]), canonical_json(provenance).encode("utf-8"))
    except InvalidSignature as exc:
        raise ValueError("release provenance signature verification failed") from exc
    if require_transparency:
        if external_checkpoint_trusted_key_path is None:
            raise ValueError("production image signing requires an external checkpoint trust root")
        external_key, external_key_id = load_trusted_release_key(external_checkpoint_trusted_key_path)
        if not expected_external_checkpoint_provider:
            raise ValueError("production image signing requires the expected external checkpoint provider")
        if expected_external_checkpoint_log_id != external_key_id:
            raise ValueError("external checkpoint log ID does not match its independent trust root")
        external_public_key_pem = external_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        verify_release_transparency(
            document,
            expected_provider=expected_external_checkpoint_provider,
            expected_log_id=expected_external_checkpoint_log_id,
            trusted_external_public_key_pem=external_public_key_pem,
        )


def verify_current_source_tree(provenance: dict[str, Any], *, root: Path = ROOT) -> str:
    source_tree = provenance.get("source_tree")
    if not isinstance(source_tree, dict):
        raise ValueError("release provenance is missing source tree identity")
    recorded = source_tree.get("digest")
    current = catchplate_source_tree.source_tree_digest(root)
    if recorded != current:
        raise ValueError(
            f"release provenance source tree is stale: recorded={recorded} current={current}"
        )
    return current


def signature_payload(bundle: dict[str, Any]) -> dict[str, Any]:
    copied = json.loads(json.dumps(bundle))
    metadata = copied.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("signature", None)
        metadata.pop("transparency", None)
        metadata.pop("bundleSigstore", None)
    copied.pop("image_signature_bundle_digest", None)
    copied.pop("bundle_signature", None)
    return copied


def cosign_compatible_statement_metadata(*, production: bool) -> str:
    if production:
        return (
            "in-toto Statement v1 per image; production release channels require cosign/Sigstore "
            "with the configured pinned KMS/HSM key"
        )
    return "in-toto Statement v1 per image"


def sign_value(key: Ed25519PrivateKey, value: Any) -> str:
    return "ed25519:" + b64e(key.sign(canonical_json(value).encode("utf-8")))


def run_json_command(command: str, payload: dict[str, Any], *, timeout: int = 60) -> dict[str, Any]:
    result = subprocess.run(
        shlex.split(command),
        cwd=ROOT,
        input=canonical_json(payload).encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace") or result.stdout.decode("utf-8", errors="replace")
        raise RuntimeError(f"external signing command failed with exit {result.returncode}: {detail[-2000:]}")
    try:
        response = sigstore_json.parse_json(result.stdout)
    except Exception as exc:
        raise RuntimeError("external signing command returned invalid JSON") from exc
    if response.get("ok") is not True:
        raise RuntimeError(f"external signing command denied signing: {response}")
    return response


def command_mentions(raw: str, *needles: str) -> bool:
    try:
        words = shlex.split(raw)
    except ValueError:
        words = raw.split()
    lowered = " ".join(words).lower()
    return any(needle.lower() in lowered for needle in needles)


def validate_production_sigstore_configuration(
    *,
    production_refs: bool,
    signature_provider: str,
    image_sign_command: str,
    image_verify_command: str,
    require_transparency: bool,
    cosign_binary: str | None = None,
) -> None:
    if not production_refs:
        return
    if signature_provider != "sigstore-command":
        raise ValueError("production image refs must be signed with CATCHPLATE_IMAGE_SIGNATURE_PROVIDER=sigstore-command")
    if not image_sign_command.strip():
        raise ValueError("production image refs require CATCHPLATE_IMAGE_SIGN_COMMAND")
    if not image_verify_command.strip():
        raise ValueError("production image refs require CATCHPLATE_IMAGE_VERIFY_COMMAND")
    if not require_transparency:
        raise ValueError("production image refs require CATCHPLATE_REQUIRE_SIGSTORE_TRANSPARENCY=1")
    if command_mentions(image_sign_command, *FIXTURE_COMMAND_MARKERS):
        raise ValueError("production image signing command must not use fixture helpers")
    if command_mentions(image_verify_command, *FIXTURE_COMMAND_MARKERS):
        raise ValueError("production image verification command must not use fixture helpers")
    selected_cosign = cosign_binary if cosign_binary is not None else os.getenv("CATCHPLATE_COSIGN_BINARY", "cosign")
    if command_mentions(selected_cosign, *FIXTURE_COMMAND_MARKERS):
        raise ValueError("production image signing must not use fixture cosign helpers")


def preload_env_file(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--env-file", default="")
    args, _ = parser.parse_known_args(argv)
    if not args.env_file:
        return

    import run_production_readiness

    loaded = run_production_readiness.load_env_file(ROOT / args.env_file)
    for key, value in loaded.items():
        os.environ.setdefault(key, value)


def validate_sigstore_response(response: dict[str, Any], *, statement_digest: str, require_transparency: bool) -> None:
    if response.get("statement_digest") != statement_digest:
        raise RuntimeError(f"external signature statement digest mismatch: {response}")
    if not response.get("signature"):
        raise RuntimeError(f"external signature is missing signature material: {response}")
    if not response.get("key_provider"):
        raise RuntimeError(f"external signature is missing key_provider binding: {response}")
    if require_transparency:
        sigstore_json.validate(response, scope="response")
        transparency = response.get("transparency") or {}
        required = {"log_id", "entry_uuid", "integrated_time", "inclusion_proof"}
        missing = sorted(required - set(transparency))
        if missing:
            raise RuntimeError(f"external signature is missing transparency fields {missing}: {response}")


def validate_sigstore_verify_response(
    verify: dict[str, Any],
    *,
    signature_response: dict[str, Any],
    statement_digest: str,
    require_transparency: bool,
) -> None:
    if verify.get("ok") is not True:
        raise RuntimeError(f"external signature verification failed: {verify}")
    if verify.get("statement_digest") != statement_digest:
        raise RuntimeError(f"external signature verifier returned a different statement digest: {verify}")
    if verify.get("key_provider") != signature_response.get("key_provider"):
        raise RuntimeError(f"external signature verifier returned a different key provider: {verify}")
    if require_transparency:
        if verify.get("verified_transparency") is not True:
            raise RuntimeError(f"external signature verifier did not prove transparency: {verify}")
        verified_transparency = verify.get("transparency") if isinstance(verify.get("transparency"), dict) else {}
        sigstore_json.validate(verified_transparency, scope="transparency")
        signed_transparency = signature_response.get("transparency") if isinstance(signature_response.get("transparency"), dict) else {}
        for key in ("log_id", "entry_uuid", "integrated_time", "log_index", "inclusion_proof"):
            if signed_transparency.get(key) != verified_transparency.get(key):
                raise RuntimeError(f"external signature verifier returned different transparency {key}: {verify}")


def external_sign_statement(
    *,
    command: str,
    verify_command: str | None,
    require_transparency: bool,
    kind: str,
    service: str,
    image_id: str | None,
    statement: dict[str, Any],
) -> dict[str, Any]:
    statement_digest = sha256_prefixed_bytes(
        sigstore_json.statement_json(statement, kind=kind).encode("utf-8")
    )
    payload = {
        "apiVersion": "catchplate.sigstoreSignRequest/v1",
        "kind": kind,
        "service": service,
        "image_id": image_id,
        "statement": statement,
        "statement_digest": statement_digest,
    }
    response = run_json_command(command, payload)
    validate_sigstore_response(response, statement_digest=statement_digest, require_transparency=require_transparency)
    if verify_command:
        verify = run_json_command(
            verify_command,
            {
                "apiVersion": "catchplate.sigstoreVerifyRequest/v1",
                "kind": kind,
                "service": service,
                "image_id": image_id,
                "statement": statement,
                "statement_digest": statement_digest,
                "signature_response": response,
            },
        )
        validate_sigstore_verify_response(
            verify,
            signature_response=response,
            statement_digest=statement_digest,
            require_transparency=require_transparency,
        )
    return response


def statement_for_image(
    *,
    service: str,
    image: dict[str, Any],
    provenance: dict[str, Any],
    provenance_digest: str,
    release_signing_key_id: str,
) -> dict[str, Any]:
    sbom = provenance["sbom"]["cyclonedx"]
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://catchplate.local/attestations/oci-image/v1",
        "subject": [
            {
                "name": service,
                "digest": {"sha256": str(image["image_id"]).split(":", 1)[1]},
            }
        ],
        "predicate": {
            "image_id": image["image_id"],
            "repo_tags": image.get("repo_tags") or [],
            "repo_digests": image.get("repo_digests") or [],
            "os": image.get("os"),
            "architecture": image.get("architecture"),
            "created": image.get("created"),
            "provenance_digest": provenance_digest,
            "release_signing_key_id": release_signing_key_id,
            "source_tree_digest": provenance["source_tree"]["digest"],
            "compose_config_sha256": provenance["compose_config_sha256"],
            "sbom_cyclonedx_sha256": sbom["sha256"],
            "sbom_cyclonedx_components": sbom["components"],
        },
    }


def image_refs_from_env() -> list[str]:
    return [item.strip() for item in os.getenv("CATCHPLATE_PRODUCTION_IMAGES", "").split(",") if item.strip()]


def image_refs_from_env_file(path: Path) -> list[str]:
    import merge_production_images_env

    raw = merge_production_images_env.load_images_fragment(path)
    return [item["ref"] for item in merge_production_images_env.validate_production_images(raw)]


def service_name_from_ref(ref: str) -> str:
    name = ref.split("@", 1)[0].rstrip("/").split("/")[-1]
    return name.replace(":", "-") or "production-image"


def production_image_inventory(refs: list[str]) -> dict[str, dict[str, Any]]:
    images: dict[str, dict[str, Any]] = {}
    for index, ref in enumerate(refs):
        if "@sha256:" not in ref:
            raise ValueError(f"production image ref must be immutable and digest-pinned: {ref}")
        digest = "sha256:" + ref.rsplit("@sha256:", 1)[1]
        service = service_name_from_ref(ref)
        if service in images:
            service = f"{service}-{index + 1}"
        images[service] = {
            "image_id": digest,
            "repo_tags": [],
            "repo_digests": [ref],
            "created": None,
            "os": "linux",
            "architecture": None,
        }
    return images


def write_container_file(service: str, path: str, data: bytes) -> None:
    command = f"cat > {shlex.quote(path)}"
    subprocess.run(
        ["docker", "compose", "exec", "-T", service, "sh", "-c", command],
        cwd=ROOT,
        input=data,
        check=True,
    )


def main() -> None:
    preload_env_file()
    parser = argparse.ArgumentParser(description="Sign release Docker images and publish signatures to the transparency log.")
    parser.add_argument("--env-file", default="", help="Strict production readiness env file to load before resolving signer defaults.")
    parser.add_argument("--provenance", default=".tmp/release-provenance.json")
    parser.add_argument("--out", default=".tmp/image-signatures.json")
    parser.add_argument("--key", default=".tmp/image-signing-ed25519.pem")
    parser.add_argument("--container-out", default="/data/image-signatures.json")
    parser.add_argument("--base", default=os.getenv("BASE", "http://localhost:3000"))
    parser.add_argument("--gate", default=os.getenv("DECISION_GATE_BASE", "http://localhost:9090"))
    parser.add_argument("--anchor", default=os.getenv("CATCHPLATE_RELEASE_ANCHOR_BASE", os.getenv("AUDIT_ANCHOR_BASE", "http://localhost:9100")))
    parser.add_argument("--anchor-ca-bundle", default=os.getenv("CATCHPLATE_RELEASE_ANCHOR_CA_BUNDLE", ""))
    parser.add_argument(
        "--anchor-token",
        default=os.getenv("CATCHPLATE_AUDIT_ANCHOR_TOKEN"),
        help="development-only direct audit-anchor token",
    )
    parser.add_argument(
        "--anchor-token-file",
        default=os.getenv("CATCHPLATE_AUDIT_ANCHOR_TOKEN_FILE"),
        help="production audit-anchor-token file",
    )
    parser.add_argument("--signature-provider", default=os.getenv("CATCHPLATE_IMAGE_SIGNATURE_PROVIDER", "dev-ed25519"))
    parser.add_argument("--image-sign-command", default=os.getenv("CATCHPLATE_IMAGE_SIGN_COMMAND", ""))
    parser.add_argument("--image-verify-command", default=os.getenv("CATCHPLATE_IMAGE_VERIFY_COMMAND", ""))
    parser.add_argument(
        "--release-signing-trusted-key",
        default=os.getenv("CATCHPLATE_RELEASE_PROVENANCE_TRUSTED_PUBLIC_KEY", ""),
        help="Independent Ed25519 public trust root required before production image signing.",
    )
    parser.add_argument(
        "--external-checkpoint-trusted-key",
        default=os.getenv("CATCHPLATE_EXTERNAL_CHECKPOINT_TRUSTED_PUBLIC_KEY", ""),
        help="Independent Ed25519 trust root for production transparency checkpoints.",
    )
    parser.add_argument(
        "--external-checkpoint-provider",
        default=os.getenv("CATCHPLATE_TRANSPARENCY_EXPECTED_PROVIDER", ""),
    )
    parser.add_argument(
        "--external-checkpoint-log-id",
        default=os.getenv("CATCHPLATE_TRANSPARENCY_EXPECTED_LOG_ID", ""),
    )
    parser.add_argument("--production-image", action="append", default=[], help="Digest-pinned production image ref to sign instead of Compose image inventory.")
    parser.add_argument("--production-images-env", default="", help="Strict env fragment containing CATCHPLATE_PRODUCTION_IMAGES refs to sign.")
    parser.add_argument(
        "--require-sigstore-transparency",
        action="store_true",
        default=os.getenv("CATCHPLATE_REQUIRE_SIGSTORE_TRANSPARENCY", "0").lower() in {"1", "true", "yes"},
    )
    args = parser.parse_args()

    env_production_refs = image_refs_from_env()
    if args.production_images_env:
        if args.production_image or env_production_refs:
            raise ValueError("--production-images-env cannot be combined with --production-image or CATCHPLATE_PRODUCTION_IMAGES")
        production_refs = image_refs_from_env_file(ROOT / args.production_images_env)
    else:
        production_refs = args.production_image or env_production_refs
    trusted_release_key = Path(args.release_signing_trusted_key) if args.release_signing_trusted_key else None
    if trusted_release_key is not None and not trusted_release_key.is_absolute():
        trusted_release_key = ROOT / trusted_release_key
    external_checkpoint_trusted_key = (
        Path(args.external_checkpoint_trusted_key) if args.external_checkpoint_trusted_key else None
    )
    if external_checkpoint_trusted_key is not None and not external_checkpoint_trusted_key.is_absolute():
        external_checkpoint_trusted_key = ROOT / external_checkpoint_trusted_key
    if production_refs and trusted_release_key is None:
        raise ValueError(
            "production image signing requires CATCHPLATE_RELEASE_PROVENANCE_TRUSTED_PUBLIC_KEY "
            "or --release-signing-trusted-key"
        )
    anchor_sources: dict[str, str] = {}
    if args.anchor_token is not None:
        anchor_sources["CATCHPLATE_AUDIT_ANCHOR_TOKEN"] = args.anchor_token
    if args.anchor_token_file is not None:
        anchor_sources["CATCHPLATE_AUDIT_ANCHOR_TOKEN_FILE"] = args.anchor_token_file
    if production_refs:
        args.anchor_token = (
            verify_production_readiness.load_service_credential_for_tool(
                anchor_sources,
                "CATCHPLATE_AUDIT_ANCHOR_TOKEN",
                require_file=True,
            )
        )
    elif anchor_sources:
        local_uid = os.geteuid()
        local_gid = os.getegid()
        args.anchor_token = (
            verify_production_readiness.load_service_credential_for_tool(
                anchor_sources,
                "CATCHPLATE_AUDIT_ANCHOR_TOKEN",
                require_file=False,
                expected_control_plane_uid=local_uid,
                expected_control_plane_gid=local_gid,
                expected_shared_owner_uid=local_uid,
                expected_shared_gid=local_gid,
            )
        )
    else:
        args.anchor_token = "dev-audit-anchor-token"
    provenance_path = ROOT / args.provenance
    document = json.loads(provenance_path.read_text(encoding="utf-8"))
    verify_release_provenance(
        document,
        trusted_public_key_path=trusted_release_key,
        require_transparency=bool(production_refs),
        external_checkpoint_trusted_key_path=external_checkpoint_trusted_key,
        expected_external_checkpoint_provider=args.external_checkpoint_provider,
        expected_external_checkpoint_log_id=args.external_checkpoint_log_id,
    )
    provenance = document["provenance"]
    verify_current_source_tree(provenance)
    provenance_digest = document["provenance_digest"]
    images = production_image_inventory(production_refs) if production_refs else provenance.get("images") or {}
    if not images:
        raise ValueError("release provenance contains no image inventory")
    anchor_ca_bundle = Path(args.anchor_ca_bundle) if args.anchor_ca_bundle else None
    if anchor_ca_bundle and not anchor_ca_bundle.is_absolute():
        anchor_ca_bundle = ROOT / anchor_ca_bundle
    if production_refs:
        validate_production_anchor(args.anchor, args.anchor_token, anchor_ca_bundle)

    signature_provider = args.signature_provider.strip()
    if signature_provider not in {"dev-ed25519", "sigstore-command"}:
        raise ValueError(f"unsupported image signature provider: {signature_provider}")
    if signature_provider == "sigstore-command" and not args.image_sign_command.strip():
        raise ValueError("sigstore-command image signing requires CATCHPLATE_IMAGE_SIGN_COMMAND or --image-sign-command")
    validate_production_sigstore_configuration(
        production_refs=bool(production_refs),
        signature_provider=signature_provider,
        image_sign_command=args.image_sign_command,
        image_verify_command=args.image_verify_command,
        require_transparency=args.require_sigstore_transparency,
    )
    key = None
    key_info = {"spki_sha256": None, "pem": None}
    if signature_provider == "dev-ed25519":
        key = load_signing_key(ROOT / args.key)
        key_info = public_key_info(key)
    created_at = datetime.now(timezone.utc).isoformat()
    image_entries = []
    for service in sorted(images):
        statement = statement_for_image(
            service=service,
            image=images[service],
            provenance=provenance,
            provenance_digest=provenance_digest,
            release_signing_key_id=document["release_signing_key_id"],
        )
        statement_digest = sha256_prefixed_json(statement)
        entry = {
            "service": service,
            "image_id": images[service]["image_id"],
            "statement": statement,
            "statement_digest": statement_digest,
        }
        if signature_provider == "sigstore-command":
            sigstore = external_sign_statement(
                command=args.image_sign_command,
                verify_command=args.image_verify_command or None,
                require_transparency=args.require_sigstore_transparency,
                kind="oci-image-statement",
                service=service,
                image_id=images[service]["image_id"],
                statement=statement,
            )
            entry["signature"] = sigstore["signature"]
            entry["sigstore"] = sigstore
        else:
            assert key is not None
            entry["signature"] = sign_value(key, statement)
        image_entries.append(entry)
    if signature_provider == "sigstore-command":
        key_ids = {
            ((item.get("sigstore") or {}).get("key_provider") or {}).get("key_id")
            for item in image_entries
        }
        key_ids.discard(None)
        if not key_ids:
            raise RuntimeError("external image signatures did not report a key_provider.key_id")
        if len(key_ids) != 1:
            raise RuntimeError(f"external image signatures used multiple signing keys: {sorted(key_ids)}")
        image_signing_key_id = next(iter(key_ids))
    else:
        image_signing_key_id = key_info["spki_sha256"]

    bundle: dict[str, Any] = {
        "apiVersion": "catchplate.imageSignatures/v1",
        "kind": "ImageSignatureBundle",
        "metadata": {
            "createdAt": created_at,
            "provenanceDigest": provenance_digest,
            "releaseSigningKeyId": document["release_signing_key_id"],
            "imageSigningKeyId": image_signing_key_id,
            "imageSigningPublicKeyPem": key_info["pem"],
            "sourceTreeDigest": provenance["source_tree"]["digest"],
            "composeConfigSha256": provenance["compose_config_sha256"],
            "sbomCyclonedxSha256": provenance["sbom"]["cyclonedx"]["sha256"],
            "mode": "sigstore-command-image-signing" if signature_provider == "sigstore-command" else "catchplate-dev-ed25519-image-signing",
            "signatureProvider": signature_provider,
            "sigstoreTransparencyRequired": bool(args.require_sigstore_transparency),
            "cosignCompatibleStatement": cosign_compatible_statement_metadata(production=bool(production_refs)),
        },
        "images": image_entries,
    }
    if signature_provider == "sigstore-command":
        bundle_signature = external_sign_statement(
            command=args.image_sign_command,
            verify_command=args.image_verify_command or None,
            require_transparency=args.require_sigstore_transparency,
            kind="image-signature-bundle",
            service="__bundle__",
            image_id=None,
            statement=signature_payload(bundle),
        )
        if (bundle_signature.get("key_provider") or {}).get("key_id") != image_signing_key_id:
            raise RuntimeError(f"bundle signature key does not match image signature key: {bundle_signature}")
        bundle["metadata"]["bundleSigstore"] = bundle_signature
        bundle["metadata"]["signature"] = bundle_signature["signature"]
        bundle["bundle_signature"] = bundle_signature
    else:
        assert key is not None
        bundle["metadata"]["signature"] = sign_value(key, signature_payload(bundle))
    bundle_digest = sha256_prefixed_bytes(
        sigstore_json.statement_json(signature_payload(bundle), kind="image-signature-bundle").encode("utf-8")
    )
    bundle["image_signature_bundle_digest"] = bundle_digest

    record = {
        "type": "release.image_signatures.v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "provenance_digest": provenance_digest,
        "image_signature_bundle_digest": bundle_digest,
        "image_signing_key_id": image_signing_key_id,
        "image_signature_provider": signature_provider,
        "release_signing_key_id": document["release_signing_key_id"],
        "images": {item["service"]: item["image_id"] for item in image_entries},
        "signature": bundle["metadata"]["signature"],
    }
    anchor_headers = {"X-Catchplate-Audit-Anchor-Token": args.anchor_token}
    anchor_response = request_json(
        f"{args.anchor.rstrip('/')}/anchors",
        method="POST",
        headers=anchor_headers,
        payload={"records": [record]},
        ca_bundle=anchor_ca_bundle,
        timeout=60,
    )
    accepted = (anchor_response.get("anchors") or [{}])[0]
    sequence = accepted.get("sequence")
    inclusion = request_json(
        f"{args.anchor.rstrip('/')}/anchors/inclusion/{sequence}",
        headers=anchor_headers,
        ca_bundle=anchor_ca_bundle,
        timeout=60,
    )
    if inclusion.get("verified") is not True:
        raise RuntimeError(f"image signature transparency inclusion proof did not verify: {inclusion}")
    if (inclusion.get("item") or {}).get("record", {}).get("image_signature_bundle_digest") != bundle_digest:
        raise RuntimeError(f"image signature inclusion proof returned the wrong record: {inclusion}")
    bundle["metadata"]["transparency"] = {
        "record": record,
        "anchorResponse": anchor_response,
        "inclusionProof": inclusion,
    }

    out_path = ROOT / args.out
    sigstore_json.validate(bundle, scope="image-signatures", label="image signatures")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if not production_refs:
        write_container_file("catchplate", args.container_out, out_path.read_bytes())
        deadline = time.time() + 10
        control = gate = gate_health = {}
        while time.time() < deadline:
            control = request_json(f"{args.base.rstrip('/')}/attestation?nonce=image-signatures-control")
            gate = request_json(f"{args.gate.rstrip('/')}/attestation?nonce=image-signatures-gate")
            gate_health = request_json(f"{args.gate.rstrip('/')}/healthz")
            gate_context = gate_health.get("attested_response_context") or {}
            if (
                control.get("image_signatures_digest") == bundle_digest
                and gate.get("image_signatures_digest") == bundle_digest
                and gate_context.get("image_signatures_digest") == bundle_digest
            ):
                break
            time.sleep(0.25)
        if control.get("image_signatures_digest") != bundle_digest:
            raise RuntimeError(f"control-plane attestation did not bind image signatures digest: {control}")
        if gate.get("image_signatures_digest") != bundle_digest:
            raise RuntimeError(f"decision-gate attestation did not bind image signatures digest: {gate}")
        if (gate_health.get("attested_response_context") or {}).get("image_signatures_digest") != bundle_digest:
            raise RuntimeError(
                f"decision-gate signed response context did not bind image signatures digest: {gate_health}"
            )
        if (control.get("quote") or {}).get("claims", {}).get("image_signatures_digest") != bundle_digest:
            raise RuntimeError(f"control-plane quote did not bind image signatures digest: {control}")

    print(
        json.dumps(
            {
                "ok": True,
                "image_signatures": "pass",
                "production": bool(production_refs),
                "out": args.out,
                "image_signature_bundle_digest": bundle_digest,
                "image_signing_key_id": image_signing_key_id,
                "image_signature_provider": signature_provider,
                "images": len(image_entries),
                "provenance_digest": provenance_digest,
                "release_signing_key_id": document["release_signing_key_id"],
                "transparency_mode": anchor_response.get("mode"),
                "inclusion_verified": inclusion.get("verified") is True,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        raise SystemExit(f"release image signing failed: {exc}") from exc
