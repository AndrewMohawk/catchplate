#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shlex
import subprocess
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parent.parent
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


def request_json(url: str, *, method: str = "GET", headers: dict[str, str] | None = None, payload: Any | None = None) -> dict[str, Any]:
    data = None if payload is None else canonical_json(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    if payload is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.loads(response.read())


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


def verify_release_provenance(document: dict[str, Any]) -> None:
    provenance = document.get("provenance")
    if not isinstance(provenance, dict):
        raise ValueError("release provenance document is missing provenance")
    expected_digest = sha256_prefixed_json(provenance)
    if document.get("provenance_digest") != expected_digest:
        raise ValueError("release provenance digest mismatch")
    signature = document.get("signature")
    public_key_pem = document.get("release_signing_public_key_pem")
    if not isinstance(signature, str) or not signature.startswith("ed25519:"):
        raise ValueError("release provenance is missing ed25519 signature")
    if not isinstance(public_key_pem, str):
        raise ValueError("release provenance is missing release signing public key")
    public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    try:
        public_key.verify(b64d(signature.split(":", 1)[1]), canonical_json(provenance).encode("utf-8"))
    except InvalidSignature as exc:
        raise ValueError("release provenance signature verification failed") from exc


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
        response = json.loads(result.stdout.decode("utf-8"))
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
        raise ValueError("production image refs must be signed with SERVERWARE_IMAGE_SIGNATURE_PROVIDER=sigstore-command")
    if not image_sign_command.strip():
        raise ValueError("production image refs require SERVERWARE_IMAGE_SIGN_COMMAND")
    if not image_verify_command.strip():
        raise ValueError("production image refs require SERVERWARE_IMAGE_VERIFY_COMMAND")
    if not require_transparency:
        raise ValueError("production image refs require SERVERWARE_REQUIRE_SIGSTORE_TRANSPARENCY=1")
    if command_mentions(image_sign_command, *FIXTURE_COMMAND_MARKERS):
        raise ValueError("production image signing command must not use fixture helpers")
    if command_mentions(image_verify_command, *FIXTURE_COMMAND_MARKERS):
        raise ValueError("production image verification command must not use fixture helpers")
    selected_cosign = cosign_binary if cosign_binary is not None else os.getenv("SERVERWARE_COSIGN_BINARY", "cosign")
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
    statement_digest = sha256_prefixed_json(statement)
    payload = {
        "apiVersion": "serverware.sigstoreSignRequest/v1",
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
                "apiVersion": "serverware.sigstoreVerifyRequest/v1",
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
        "predicateType": "https://serverware.local/attestations/oci-image/v1",
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
    return [item.strip() for item in os.getenv("SERVERWARE_PRODUCTION_IMAGES", "").split(",") if item.strip()]


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
    parser.add_argument("--anchor", default=os.getenv("AUDIT_ANCHOR_BASE", "http://localhost:9100"))
    parser.add_argument("--anchor-token", default=os.getenv("SERVERWARE_AUDIT_ANCHOR_TOKEN", "dev-audit-anchor-token"))
    parser.add_argument("--signature-provider", default=os.getenv("SERVERWARE_IMAGE_SIGNATURE_PROVIDER", "dev-ed25519"))
    parser.add_argument("--image-sign-command", default=os.getenv("SERVERWARE_IMAGE_SIGN_COMMAND", ""))
    parser.add_argument("--image-verify-command", default=os.getenv("SERVERWARE_IMAGE_VERIFY_COMMAND", ""))
    parser.add_argument("--production-image", action="append", default=[], help="Digest-pinned production image ref to sign instead of Compose image inventory.")
    parser.add_argument("--production-images-env", default="", help="Strict env fragment containing SERVERWARE_PRODUCTION_IMAGES refs to sign.")
    parser.add_argument(
        "--require-sigstore-transparency",
        action="store_true",
        default=os.getenv("SERVERWARE_REQUIRE_SIGSTORE_TRANSPARENCY", "0").lower() in {"1", "true", "yes"},
    )
    args = parser.parse_args()

    provenance_path = ROOT / args.provenance
    document = json.loads(provenance_path.read_text(encoding="utf-8"))
    verify_release_provenance(document)
    provenance = document["provenance"]
    provenance_digest = document["provenance_digest"]
    env_production_refs = image_refs_from_env()
    if args.production_images_env:
        if args.production_image or env_production_refs:
            raise ValueError("--production-images-env cannot be combined with --production-image or SERVERWARE_PRODUCTION_IMAGES")
        production_refs = image_refs_from_env_file(ROOT / args.production_images_env)
    else:
        production_refs = args.production_image or env_production_refs
    images = production_image_inventory(production_refs) if production_refs else provenance.get("images") or {}
    if not images:
        raise ValueError("release provenance contains no image inventory")

    signature_provider = args.signature_provider.strip()
    if signature_provider not in {"dev-ed25519", "sigstore-command"}:
        raise ValueError(f"unsupported image signature provider: {signature_provider}")
    if signature_provider == "sigstore-command" and not args.image_sign_command.strip():
        raise ValueError("sigstore-command image signing requires SERVERWARE_IMAGE_SIGN_COMMAND or --image-sign-command")
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
        "apiVersion": "serverware.imageSignatures/v1",
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
            "mode": "sigstore-command-image-signing" if signature_provider == "sigstore-command" else "serverware-dev-ed25519-image-signing",
            "signatureProvider": signature_provider,
            "sigstoreTransparencyRequired": bool(args.require_sigstore_transparency),
            "cosignCompatibleStatement": "in-toto Statement v1 per image; production release channels should use cosign/Sigstore keyless or KMS signing",
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
    bundle_digest = sha256_prefixed_json(signature_payload(bundle))
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
    anchor_headers = {"X-Serverware-Audit-Anchor-Token": args.anchor_token}
    anchor_response = request_json(
        f"{args.anchor.rstrip('/')}/anchors",
        method="POST",
        headers=anchor_headers,
        payload={"records": [record]},
    )
    accepted = (anchor_response.get("anchors") or [{}])[0]
    sequence = accepted.get("sequence")
    inclusion = request_json(f"{args.anchor.rstrip('/')}/anchors/inclusion/{sequence}", headers=anchor_headers)
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
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_container_file("serverware", args.container_out, out_path.read_bytes())

    deadline = time.time() + 10
    control = gate = {}
    while time.time() < deadline:
        control = request_json(f"{args.base.rstrip('/')}/attestation?nonce=image-signatures-control")
        gate = request_json(f"{args.gate.rstrip('/')}/attestation?nonce=image-signatures-gate")
        if control.get("image_signatures_digest") == bundle_digest and gate.get("image_signatures_digest") == bundle_digest:
            break
        time.sleep(0.25)
    if control.get("image_signatures_digest") != bundle_digest:
        raise RuntimeError(f"control-plane attestation did not bind image signatures digest: {control}")
    if gate.get("image_signatures_digest") != bundle_digest:
        raise RuntimeError(f"decision-gate attestation did not bind image signatures digest: {gate}")
    if (control.get("quote") or {}).get("claims", {}).get("image_signatures_digest") != bundle_digest:
        raise RuntimeError(f"control-plane quote did not bind image signatures digest: {control}")

    print(
        json.dumps(
            {
                "ok": True,
                "image_signatures": "pass",
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
