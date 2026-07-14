#!/usr/bin/env python3
from __future__ import annotations

import json
import base64
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import build_production_images
import production_release_input_preflight
import run_production_readiness
import test_production_release_input_preflight
import verify_production_policy_identity

ROOT = Path(__file__).resolve().parent.parent
SOURCE_TREE_DIGEST = build_production_images.source_tree_digest()


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_prefixed_json(value: Any) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def sha256_prefixed_bytes(value: bytes) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(value).hexdigest()


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


KMS_MATERIAL_FIXTURES: dict[str, dict[str, Any]] = {
    "broker-kek": {
        "key_id": "arn:aws:kms:us-east-1:111122223333:key/1",
        "ciphertext": b"broker-ciphertext",
        "encryption_context": {"material": "broker-kek", "service": "serverware"},
    },
    "decision-gate-ca": {
        "key_id": "arn:aws:kms:us-east-1:111122223333:key/2",
        "ciphertext": b"ca-ciphertext",
        "encryption_context": {"material": "decision-gate-ca", "service": "serverware"},
    },
}


def kms_materials_document() -> dict[str, Any]:
    return {
        material: {
            "key_id": str(config["key_id"]),
            "ciphertext_blob_b64": base64.b64encode(config["ciphertext"]).decode("ascii"),
            "encryption_context": config["encryption_context"],
        }
        for material, config in KMS_MATERIAL_FIXTURES.items()
    }


def kms_material_binding(material: str) -> dict[str, str]:
    config = KMS_MATERIAL_FIXTURES[material]
    return {
        "key_id_sha256": sha256_prefixed_bytes(str(config["key_id"]).encode("utf-8")),
        "ciphertext_blob_sha256": sha256_prefixed_bytes(config["ciphertext"]),
        "encryption_context_sha256": sha256_prefixed_json(config["encryption_context"]),
    }


def release_key_info() -> dict[str, Any]:
    key = Ed25519PrivateKey.from_private_bytes(b"\x09" * 32)
    return ed25519_key_info(key)


def transparency_key_info() -> dict[str, Any]:
    key = Ed25519PrivateKey.from_private_bytes(b"\x07" * 32)
    return ed25519_key_info(key)


def external_receipt_key_info() -> dict[str, Any]:
    key = Ed25519PrivateKey.from_private_bytes(b"\x06" * 32)
    return ed25519_key_info(key)


def ed25519_key_info(key: Ed25519PrivateKey) -> dict[str, Any]:
    public_key = key.public_key()
    pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {"key": key, "public_key_pem": pem, "key_id": sha256_prefixed_bytes(der)}


def image_signature_bundle_digest(document: dict[str, Any]) -> str:
    copied = json.loads(json.dumps(document))
    copied.pop("image_signature_bundle_digest", None)
    copied.pop("bundle_signature", None)
    metadata = copied.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("signature", None)
        metadata.pop("transparency", None)
        metadata.pop("bundleSigstore", None)
    return sha256_prefixed_json(copied)


def refresh_sigstore_bundle_digest(sigstore: dict[str, Any], statement_digest: str) -> None:
    bundle = sigstore.get("bundle")
    if not isinstance(bundle, dict):
        return
    message_signature = bundle.get("messageSignature")
    if not isinstance(message_signature, dict):
        return
    message_digest = message_signature.get("messageDigest")
    if isinstance(message_digest, dict):
        message_digest["digest"] = statement_digest.split(":", 1)[1]


def refresh_image_signature_bundle(summary: dict[str, Any], document: dict[str, Any]) -> None:
    bundle_digest = image_signature_bundle_digest(document)
    document["image_signature_bundle_digest"] = bundle_digest
    bundle_sigstore = document.get("bundle_signature")
    if isinstance(bundle_sigstore, dict):
        bundle_sigstore["statement_digest"] = bundle_digest
        refresh_sigstore_bundle_digest(bundle_sigstore, bundle_digest)
        metadata = document.get("metadata")
        if isinstance(metadata, dict):
            metadata["bundleSigstore"] = bundle_sigstore
    summary["image_signature_bundle_digest"] = bundle_digest
    refresh_image_transparency_record(document)


def refresh_image_statements_and_bundle(summary: dict[str, Any], document: dict[str, Any]) -> None:
    for image in document.get("images") or []:
        if not isinstance(image, dict):
            continue
        statement = image.get("statement")
        if not isinstance(statement, dict):
            continue
        statement_digest = sha256_prefixed_json(statement)
        image["statement_digest"] = statement_digest
        sigstore = image.get("sigstore")
        if isinstance(sigstore, dict):
            sigstore["statement_digest"] = statement_digest
            refresh_sigstore_bundle_digest(sigstore, statement_digest)
    refresh_image_signature_bundle(summary, document)


def refresh_release_provenance(summary: dict[str, Any], document: dict[str, Any]) -> None:
    key_info = release_key_info()
    provenance = document["provenance"]
    provenance_digest = sha256_prefixed_json(provenance)
    signature = "ed25519:" + b64e(key_info["key"].sign(canonical_json(provenance).encode("utf-8")))
    document["provenance_digest"] = provenance_digest
    document["signature"] = signature
    document["release_signing_key_id"] = key_info["key_id"]
    document["release_signing_public_key_pem"] = key_info["public_key_pem"]
    document["transparency"] = transparency_for_record(
        {
            "type": "release.provenance.v1",
            "provenance_digest": provenance_digest,
            "signature": signature,
            "release_signing_key_id": key_info["key_id"],
        }
    )
    summary["provenance_digest"] = provenance_digest
    summary["release_signing_key_id"] = key_info["key_id"]


def sha256_file(path: Path) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def digest(char: str) -> str:
    return "sha256:" + char * 64


POLICY_DIGEST = digest("8")


PROXY_CLIENT_NONCE = b64e(b"n" * 32)
PROXY_TLS_CHANNEL_BINDING = b64e(b"t" * 32)
PROXY_REQUEST_DIGEST = digest("1")
PROXY_OPERATION_DIGEST = digest("2")
PROXY_SERVER_INSTANCE_ID = "spiffe://prod.serverware.dev/decision-gate/instance-01"
PROXY_TLS_PEER_LEAF_CERTIFICATE_DIGEST = digest("a")


def proxy_response_key_info() -> dict[str, Any]:
    return ed25519_key_info(Ed25519PrivateKey.from_private_bytes(b"\x05" * 32))


def proxy_collector_key_info() -> dict[str, Any]:
    return ed25519_key_info(Ed25519PrivateKey.from_private_bytes(b"\x06" * 32))


def alternate_proxy_collector_key_info() -> dict[str, Any]:
    return ed25519_key_info(Ed25519PrivateKey.from_private_bytes(b"\x07" * 32))


def proxy_vendor_verifier_key_info() -> dict[str, Any]:
    return ed25519_key_info(Ed25519PrivateKey.from_private_bytes(b"\x04" * 32))


def alternate_proxy_vendor_verifier_key_info() -> dict[str, Any]:
    return ed25519_key_info(Ed25519PrivateKey.from_private_bytes(b"\x03" * 32))


def sign_proxy_vendor_verifier_statement(
    document: dict[str, Any],
    verifier_key_info: dict[str, Any] | None = None,
) -> None:
    key_info = verifier_key_info or proxy_vendor_verifier_key_info()
    trusted_verifier = document["vendor_tee"]["trusted_verifier"]
    statement = trusted_verifier["statement"]
    statement["verifier_key_id"] = key_info["key_id"]
    trusted_verifier["signature"] = "ed25519:" + b64e(
        key_info["key"].sign(canonical_json(statement).encode("utf-8"))
    )


def sign_proxy_external_capture(
    document: dict[str, Any],
    collector_key_info: dict[str, Any] | None = None,
) -> None:
    key_info = collector_key_info or proxy_collector_key_info()
    external_capture = document["external_capture"]
    document["collector_signature"] = {
        "algorithm": "Ed25519",
        "key_id": key_info["key_id"],
        "public_key_pem": key_info["public_key_pem"],
        "signature": "ed25519:"
        + b64e(key_info["key"].sign(canonical_json(external_capture).encode("utf-8"))),
    }


def resign_proxy_response_proof(
    document: dict[str, Any],
    *,
    verifier_key_info: dict[str, Any] | None = None,
    sync_attested_claims: bool = True,
) -> None:
    response_key = proxy_response_key_info()
    server_statement = document["server_statement"]
    server_statement_digest = sha256_prefixed_json(server_statement)
    document["external_capture"]["server_statement_sha256"] = server_statement_digest
    sign_proxy_external_capture(document)
    document["server_signature"] = {
        "algorithm": "Ed25519",
        "key_id": response_key["key_id"],
        "public_key_pem": response_key["public_key_pem"],
        "signature": "ed25519:"
        + b64e(response_key["key"].sign(canonical_json(server_statement).encode("utf-8"))),
    }

    vendor_tee = document["vendor_tee"]
    vendor_tee["quote_sha256"] = sha256_prefixed_json(vendor_tee["quote"])
    statement = vendor_tee["trusted_verifier"]["statement"]
    statement.pop("proof_evidence_sha256", None)
    statement.update(
        {
            "tee_platform": vendor_tee["platform"],
            "quote_provider": vendor_tee["provider"],
            "vendor_quote_sha256": vendor_tee["quote_sha256"],
            "server_statement_sha256": server_statement_digest,
            "response_signing_key_id": response_key["key_id"],
        }
    )
    if sync_attested_claims:
        response = server_statement["response"]
        tls_channel_binding = server_statement["tls_channel_binding"]
        server_instance = server_statement["server_instance"]
        statement["attested_claims"] = {
            "server_statement_sha256": server_statement_digest,
            "server_statement_api_version": server_statement["apiVersion"],
            "issued_at_unix": server_statement["issued_at_unix"],
            "client_nonce_sha256": sha256_prefixed_bytes(b64d(server_statement["client_nonce"])),
            "client_request_digest": server_statement["client_request_digest"],
            "request_digest": server_statement["request_digest"],
            "operation_digest": server_statement["operation_digest"],
            "response_status": response["status"],
            "selected_response_headers_digest": response["selected_headers_digest"],
            "response_body_digest": response["body_digest"],
            "policy_digest": server_statement["policy_digest"],
            "runtime_manifest_digest": server_statement["runtime_manifest_digest"],
            "data_plane_binary_digest": server_statement["data_plane_binary_digest"],
            "release_digest": server_statement["release_digest"],
            "server_instance_id": server_instance["id"],
            "server_instance_identity_digest": server_instance["identity_digest"],
            "tls_channel_binding_type": tls_channel_binding["type"],
            "tls_channel_binding_sha256": sha256_prefixed_json(tls_channel_binding),
            "response_signing_key_id": response_key["key_id"],
        }
    sign_proxy_vendor_verifier_statement(document, verifier_key_info)


def proxy_response_proof(provenance_digest: str, *, now: int | None = None) -> dict[str, Any]:
    captured_at = int(time.time()) if now is None else now
    body = b'{"ok":true,"source":"production-proxy"}'
    body_digest = sha256_prefixed_bytes(body)
    client_request = {
        "apiVersion": "serverware.clientProofRequest/v1",
        "method": "GET",
        "scheme": "https",
        "authority": "api.example.test",
        "path": "/v1/resource",
        "query": [["limit", "10"]],
        "headers": {"accept": "application/json"},
        "body_sha256": sha256_prefixed_bytes(b""),
    }
    client_request_digest = sha256_prefixed_json(client_request)
    selected_headers = {
        "content-length": str(len(body)),
        "content-type": "application/json",
        "x-serverware-client-request-digest": client_request_digest,
        "x-serverware-policy-hash": POLICY_DIGEST,
        "x-serverware-request-digest": PROXY_REQUEST_DIGEST,
        "x-serverware-operation-digest": PROXY_OPERATION_DIGEST,
        "x-serverware-response-body-sha256": body_digest,
    }
    response = {
        "status": 200,
        "selected_headers": selected_headers,
        "selected_headers_digest": sha256_prefixed_json(selected_headers),
        "body_digest": body_digest,
    }
    tls_channel_binding = {
        "type": "tls-exporter",
        "value": PROXY_TLS_CHANNEL_BINDING,
    }
    document = {
        "apiVersion": "serverware.proxyResponseProof/v2",
        "kind": "ServerwareProxyResponseProof",
        "external_capture": {
            "apiVersion": "serverware.proxyResponseCapture/v1",
            "environment": "production",
            "collection_mode": "external-client-capture",
            "captured_at_unix": captured_at,
            "client_nonce": PROXY_CLIENT_NONCE,
            "client_request": client_request,
            "client_request_digest": client_request_digest,
            "request_digest": PROXY_REQUEST_DIGEST,
            "operation_digest": PROXY_OPERATION_DIGEST,
            "response": json.loads(json.dumps(response)),
            "tls_channel_binding": json.loads(json.dumps(tls_channel_binding)),
            "tls_peer": {
                "spiffe_id": PROXY_SERVER_INSTANCE_ID,
                "leaf_certificate_sha256": PROXY_TLS_PEER_LEAF_CERTIFICATE_DIGEST,
            },
            "server_statement_sha256": digest("0"),
        },
        "collector_signature": {},
        "server_statement": {
            "apiVersion": "serverware.proxyResponseStatement/v1",
            "issued_at_unix": captured_at,
            "client_nonce": PROXY_CLIENT_NONCE,
            "client_request_digest": client_request_digest,
            "request_digest": PROXY_REQUEST_DIGEST,
            "operation_digest": PROXY_OPERATION_DIGEST,
            "response": json.loads(json.dumps(response)),
            "tls_channel_binding": json.loads(json.dumps(tls_channel_binding)),
            "policy_digest": POLICY_DIGEST,
            "runtime_manifest_digest": digest("7"),
            "data_plane_binary_digest": digest("9"),
            "release_digest": provenance_digest,
            "server_instance": {
                "id": PROXY_SERVER_INSTANCE_ID,
                "identity_digest": sha256_prefixed_bytes(PROXY_SERVER_INSTANCE_ID.encode("utf-8")),
            },
        },
        "server_signature": {},
        "vendor_tee": {
            "platform": "aws-nitro",
            "provider": "aws-nitro-enclaves",
            "quote": {
                "format": "aws-nitro-attestation-document",
                "body_b64": b64e(b"test-only opaque vendor quote bytes " * 4),
            },
            "trusted_verifier": {
                "apiVersion": "serverware.vendorTeeVerification/v1",
                "kind": "ServerwareVendorTeeVerification",
                "statement": {
                    "outcome": "verified",
                    "environment": "production",
                    "trust_basis": "vendor-root-certificate-chain",
                    "vendor_quote_verified": True,
                    "certificate_chain_verified": True,
                    "revocation_checked": True,
                    "debug": False,
                    "verified_at_unix": captured_at,
                    "expires_at_unix": captured_at + 300,
                },
            },
        },
    }
    resign_proxy_response_proof(document)
    return document


def clone_document(value: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(value))


def benchmark_document(*, p99_ms: float = 9.0) -> dict[str, Any]:
    return {
        "candidate": "rust-decision-gate",
        "requests": 1000,
        "warmup": 100,
        "p50_ms": 1.0,
        "p95_ms": 5.0,
        "p99_ms": p99_ms,
        "data_plane_binary_digest": digest("9"),
        "policy_hash": POLICY_DIGEST,
        "runtime_manifest_digest": digest("7"),
        "attestation_nonce_before": "benchmark-nonce-before",
        "attestation_nonce_after": "benchmark-nonce-after",
    }


def production_image_refs(control_digest: str = digest("6"), gate_digest: str = digest("7")) -> list[str]:
    return [
        "registry.prod.serverware.dev/serverware/control@" + control_digest,
        "registry.prod.serverware.dev/serverware/decision-gate@" + gate_digest,
    ]


def production_images_env_value(control_digest: str = digest("6"), gate_digest: str = digest("7")) -> str:
    return ",".join(production_image_refs(control_digest, gate_digest))


def write_production_env_files(
    tmp: Path,
    *,
    readiness_value: str | None = None,
    images_value: str | None = None,
) -> None:
    selected_images_value = images_value or production_images_env_value()
    selected_readiness_value = readiness_value or selected_images_value
    (tmp / "production-images.env").write_text(
        f"SERVERWARE_PRODUCTION_IMAGES={selected_images_value}\n",
        encoding="utf-8",
    )
    (tmp / "production.env").write_text(
        f"SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST={digest('9')}\n"
        f"SERVERWARE_DATA_PLANE_INSTANCE_ID={PROXY_SERVER_INSTANCE_ID}\n"
        f"SERVERWARE_PROXY_PROOF_COLLECTOR_KEY_ID={proxy_collector_key_info()['key_id']}\n"
        f"SERVERWARE_PROXY_PROOF_VERIFIER_KEY_ID={proxy_vendor_verifier_key_info()['key_id']}\n"
        f"SERVERWARE_PRODUCTION_IMAGES={selected_readiness_value}\n",
        encoding="utf-8",
    )
    write_production_config_files(tmp)


def redacted_environment_summary(tmp: Path) -> dict[str, Any]:
    return {
        "env_keys": [
            "SERVERWARE_DATA_PLANE_INSTANCE_ID",
            "SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST",
            "SERVERWARE_PRODUCTION_IMAGES",
            "SERVERWARE_PROXY_PROOF_COLLECTOR_KEY_ID",
            "SERVERWARE_PROXY_PROOF_VERIFIER_KEY_ID",
        ],
        "production_readiness_env_path": str(tmp / "production.env"),
        "production_readiness_env_sha256": sha256_file(tmp / "production.env"),
        "production_images_env_path": str(tmp / "production-images.env"),
        "production_images_env_sha256": sha256_file(tmp / "production-images.env"),
        "secret_values_redacted": True,
    }


def production_config_document(path: Path) -> dict[str, Any]:
    tmp = path.parent
    return {
        "ok": True,
        "production_readiness": "pass",
        "mode": "config",
        "checks": [
            "no-dev-fixtures",
            "control-plane-auth",
            "nitro",
            "attested-credential-delivery",
            "cosign-sigstore",
            "external-transparency",
            "apparmor",
            "shared-stores",
            "agent-egress",
            "production-images-no-shell",
        ],
        "environment": redacted_environment_summary(tmp),
        "live": None,
        "result_path": str(path),
    }


def production_config_semantic_sha256(path: Path) -> str:
    parsed = json.loads(path.read_text(encoding="utf-8"))
    parsed.pop("result_path", None)
    parsed.pop("result_sha256", None)
    return sha256_prefixed_json(parsed)


def write_production_config_files(tmp: Path) -> None:
    for name in ("production-readiness-config.json", "production-host-preflight-config.json"):
        path = tmp / name
        write(path, production_config_document(path))


def hash_to_bytes(value: str) -> bytes:
    return bytes.fromhex(value.split(":", 1)[1])


def node_hash(left: str, right: str) -> str:
    return sha256_prefixed_bytes(b"\x01" + hash_to_bytes(left) + hash_to_bytes(right))


def transparency_leaf_payload(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "anchor_id": item.get("anchor_id"),
        "sequence": item.get("sequence"),
        "received_at": item.get("received_at"),
        "record": item.get("record"),
        "record_digest": item.get("record_digest"),
    }


def transparency_leaf_hash(item: dict[str, Any]) -> str:
    return sha256_prefixed_bytes(b"\x00" + canonical_json(transparency_leaf_payload(item)).encode("utf-8"))


def signed_tree_head(*, tree_size: int, tree_head_hash: str) -> dict[str, Any]:
    key_info = transparency_key_info()
    payload = {
        "version": "serverware.transparencyLog/v1",
        "tree_size": tree_size,
        "tree_head_hash": tree_head_hash,
        "created_at": "2026-05-26T00:00:00+00:00",
        "log_id": key_info["key_id"],
    }
    payload["signature"] = "ed25519:" + b64e(key_info["key"].sign(canonical_json(payload).encode("utf-8")))
    payload["public_key_pem"] = key_info["public_key_pem"]
    return payload


def signed_external_receipt(payload: dict[str, Any]) -> dict[str, Any]:
    key_info = external_receipt_key_info()
    return {
        "kind": "ed25519-signed-checkpoint",
        "payload": payload,
        "signature": "ed25519:" + b64e(key_info["key"].sign(canonical_json(payload).encode("utf-8"))),
        "public_key_pem": key_info["public_key_pem"],
    }


def external_checkpoint(*, provider: str = "managed-prod-log", log_id: str | None = None) -> dict[str, Any]:
    selected_log_id = log_id or str(external_receipt_key_info()["key_id"])
    receipt_payload = {"provider": provider, "log_id": selected_log_id}
    return {
        "accepted": 1,
        "mode": "external-managed-transparency-log",
        "anchors": [
            {
                "external_checkpoint": {
                    "ok": True,
                    "provider": provider,
                    "log_id": selected_log_id,
                    "external_sequence": 42,
                    "receipt": signed_external_receipt(receipt_payload),
                }
            }
        ],
    }


def transparency_for_record(
    record: dict[str, Any],
    *,
    provider: str = "managed-prod-log",
    log_id: str | None = None,
    anchor_key: str = "anchor_response",
    inclusion_key: str = "inclusion_proof",
) -> dict[str, Any]:
    selected_log_id = log_id or str(external_receipt_key_info()["key_id"])
    record_digest = sha256_prefixed_json(record)
    item = {
        "anchor_id": "fixture-anchor",
        "sequence": 1,
        "received_at": "2026-05-26T00:00:00+00:00",
        "record": record,
        "record_digest": record_digest,
    }
    leaf_hash = transparency_leaf_hash(item)
    tree_size = 1
    tree_head_hash = leaf_hash
    sth = signed_tree_head(tree_size=tree_size, tree_head_hash=tree_head_hash)
    checkpoint = {
        "ok": True,
        "provider": provider,
        "log_id": selected_log_id,
        "external_sequence": 42,
    }
    checkpoint["receipt"] = signed_external_receipt(
        {
            "provider": provider,
            "log_id": selected_log_id,
            "record_digest": record_digest,
            "leaf_hash": leaf_hash,
            "tree_head_hash": tree_head_hash,
            "tree_size": tree_size,
        }
    )
    checkpoint["signature"] = checkpoint["receipt"]["signature"]
    anchor_response = {
        "accepted": 1,
        "mode": "external-managed-transparency-log",
        "anchors": [
            {
                "sequence": 1,
                "record_digest": record_digest,
                "leaf_hash": leaf_hash,
                "tree_head_hash": tree_head_hash,
                "tree_size": tree_size,
                "signed_tree_head": sth,
                "external_checkpoint": checkpoint,
            }
        ],
    }
    inclusion = {
        "verified": True,
        "sequence": 1,
        "record_digest": record_digest,
        "leaf_hash": leaf_hash,
        "tree_size": tree_size,
        "tree_head_hash": tree_head_hash,
        "signed_tree_head": sth,
        "proof": [],
        "item": {
            **item,
            "leaf_hash": leaf_hash,
            "tree_size": tree_size,
            "tree_head_hash": tree_head_hash,
            "signed_tree_head": sth,
            "external_checkpoint": checkpoint,
        },
    }
    return {"record": record, anchor_key: anchor_response, inclusion_key: inclusion}


def sigstore_bundle(*, statement_digest: str, signature: str, log_id: str = digest("4"), log_index: int = 1) -> dict[str, Any]:
    inclusion_proof = {"treeSize": log_index + 1, "logIndex": log_index, "rootHash": digest("a"), "hashes": []}
    return {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "messageSignature": {
            "messageDigest": {"algorithm": "sha256", "digest": statement_digest.split(":", 1)[1]},
            "signature": signature,
        },
        "verificationMaterial": {
            "tlogEntries": [
                {
                    "entryUUID": f"entry-{log_index}",
                    "integratedTime": 1779830000 + log_index,
                    "logId": {"keyId": log_id},
                    "logIndex": log_index,
                    "inclusionProof": inclusion_proof,
                }
            ]
        },
    }


def sigstore_proof(*, statement_digest: str, signature: str, log_id: str = digest("4"), log_index: int = 1) -> dict[str, Any]:
    bundle = sigstore_bundle(statement_digest=statement_digest, signature=signature, log_id=log_id, log_index=log_index)
    entry = bundle["verificationMaterial"]["tlogEntries"][0]
    return {
        "ok": True,
        "provider": "cosign",
        "signature": signature,
        "statement_digest": statement_digest,
        "key_provider": {"type": "sigstore-keyless", "key_id": digest("3")},
        "transparency": {
            "log_id": log_id,
            "entry_uuid": entry["entryUUID"],
            "integrated_time": entry["integratedTime"],
            "log_index": entry["logIndex"],
            "inclusion_proof": entry["inclusionProof"],
        },
        "bundle": bundle,
    }


def refresh_image_transparency_record(document: dict[str, Any]) -> None:
    metadata = document.get("metadata")
    if not isinstance(metadata, dict):
        return
    record = {
        "type": "release.image_signatures.v1",
        "provenance_digest": metadata.get("provenanceDigest"),
        "image_signature_bundle_digest": document.get("image_signature_bundle_digest"),
        "image_signing_key_id": metadata.get("imageSigningKeyId") or digest("3"),
        "image_signature_provider": metadata.get("signatureProvider"),
        "release_signing_key_id": metadata.get("releaseSigningKeyId"),
        "signature": metadata.get("signature"),
        "images": {
            item["service"]: item["image_id"]
            for item in document.get("images") or []
            if isinstance(item, dict) and item.get("service") and item.get("image_id")
        },
    }
    metadata["transparency"] = transparency_for_record(
        record,
        anchor_key="anchorResponse",
        inclusion_key="inclusionProof",
    )


def nitro_evidence(provenance_digest: str) -> dict[str, Any]:
    releases = []
    for material in ("broker-kek", "decision-gate-ca"):
        config = KMS_MATERIAL_FIXTURES[material]
        binding = kms_material_binding(material)
        releases.append(
            {
                "ok": True,
                "provider": "aws-nitro-kms-policy",
                "material": material,
                "release_handle": digest("a"),
                "kms_command_required": True,
                "kms_request_digest": digest("b"),
                "kms_release": {
                    "ok": True,
                    "provider": "aws-kms-recipient",
                    "material": material,
                    "request_digest": digest("b"),
                    "release_handle": digest("a"),
                    "ciphertext_blob_sha256": binding["ciphertext_blob_sha256"],
                    "encryption_context_sha256": binding["encryption_context_sha256"],
                    "material_handle": digest("c"),
                    "recipient_ciphertext_sha256": digest("c"),
                    "attestation_document_sha256": digest("e"),
                    "key_provider": {"type": "aws-kms", "key_id": str(config["key_id"])},
                    "audit": {
                        "ciphertext_blob_sha256": binding["ciphertext_blob_sha256"],
                        "encryption_context_sha256": binding["encryption_context_sha256"],
                    },
                },
            }
        )
    return {
        "apiVersion": "serverware.nitroKmsEvidence/v1",
        "kind": "NitroKmsEvidence",
        "ok": True,
        "provider": "aws-nitro-enclaves",
        "tee_platform": "aws-nitro",
        "claims": {
            "sha256": digest("d"),
            "fields": {
                "materials": ["broker-kek", "decision-gate-ca"],
                "debug": False,
                "release_channel": "prod",
                "policy_bundle_digest": POLICY_DIGEST,
                "policy_sequence": 12,
                "policy_high_water_digest": digest("6"),
                "runtime_manifest_digest": digest("7"),
                "data_plane_binary_digest": digest("9"),
                "provenance_digest": provenance_digest,
                "source_tree_digest": SOURCE_TREE_DIGEST,
                "response_signing_key_id": proxy_response_key_info()["key_id"],
            },
        },
        "quote": {"provider": "aws-nitro-enclaves", "tee_platform": "aws-nitro", "debug": False},
        "nitro": {
            "provider": "aws-nitro-enclaves",
            "tee_platform": "aws-nitro",
            "verified": True,
            "debug": False,
            "raw_attestation_document_sha256": digest("e"),
        },
        "release_materials": releases,
        "config": {
            "kms_command_required": True,
            "fixtures_allowed_for_test": False,
            "attestation_command_sha256": digest("f"),
            "kms_release_command_sha256": digest("0"),
        },
        "redaction": {"raw_attestation_document_b64": "omitted", "plaintext_material": "rejected"},
    }


def production_readiness(nitro: dict[str, Any], tmp: Path) -> dict[str, Any]:
    checks = [
        "no-dev-fixtures",
        "control-plane-auth",
        "nitro",
        "attested-credential-delivery",
        "cosign-sigstore",
        "external-transparency",
        "apparmor",
        "shared-stores",
        "agent-egress",
        "production-images-no-shell",
    ]
    return {
        "ok": True,
        "production_readiness": "pass",
        "mode": "live",
        "checks": checks,
        "environment": redacted_environment_summary(tmp),
        "live": {
            "sigstore": {
                "ok": True,
                "key_id": digest("3"),
                "transparency_log_id": digest("4"),
                "entry_uuid": "entry",
            },
            "external_transparency": {
                "ok": True,
                "provider": "managed-prod-log",
                "log_id": external_receipt_key_info()["key_id"],
                "external_sequence": 10,
            },
            "shared_stores": {
                "ok": True,
                "stores": {
                    "metadata": {"ok": True, "tables": ["credentials"]},
                    "grant": {"ok": True, "tables": ["approval_grants"]},
                    "audit": {"ok": True, "tables": ["serverware_audit_events"]},
                },
            },
            "nitro": nitro,
            "production_images_no_shell": {
                "ok": True,
                "images": [
                    "registry.prod.serverware.dev/serverware/control@sha256:" + "6" * 64,
                    "registry.prod.serverware.dev/serverware/decision-gate@sha256:" + "7" * 64,
                ],
            },
            "apparmor": {"ok": True},
        },
    }


def release_provenance() -> tuple[dict[str, Any], dict[str, Any]]:
    key_info = release_key_info()
    provenance = {
        "source": "serverware-digest-pinned-production-release",
        "source_tree": {"digest": SOURCE_TREE_DIGEST},
        "compose_config_sha256": digest("4"),
        "compose": {"file": "docker-compose.production.yml", "sha256": digest("4")},
        "sbom": {"cyclonedx": {"sha256": digest("5"), "components": 204}},
        "anchor_chain": {"ok": True, "mode": "signed-merkle-transparency-log"},
    }
    provenance_digest = sha256_prefixed_json(provenance)
    signature = "ed25519:" + b64e(key_info["key"].sign(canonical_json(provenance).encode("utf-8")))
    record = {
        "type": "release.provenance.v1",
        "provenance_digest": provenance_digest,
        "signature": signature,
        "release_signing_key_id": key_info["key_id"],
    }
    document = {
        "provenance": provenance,
        "provenance_digest": provenance_digest,
        "signature": signature,
        "release_signing_key_id": key_info["key_id"],
        "release_signing_public_key_pem": key_info["public_key_pem"],
        "transparency": transparency_for_record(record),
    }
    summary = {
        "ok": True,
        "release_provenance": "pass",
        "anchored": True,
        "inclusion_verified": True,
        "provenance_digest": provenance_digest,
        "release_signing_key_id": key_info["key_id"],
        "transparency_mode": "signed-merkle-transparency-log",
    }
    return summary, document


def image_signatures(
    provenance_digest: str,
    release_signing_key_id: str | None = None,
    source_tree_digest: str = SOURCE_TREE_DIGEST,
) -> tuple[dict[str, Any], dict[str, Any]]:
    selected_release_key_id = release_signing_key_id or release_key_info()["key_id"]
    control_ref = "registry.prod.serverware.dev/serverware/control@sha256:" + "6" * 64
    gate_ref = "registry.prod.serverware.dev/serverware/decision-gate@sha256:" + "7" * 64
    base_predicate = {
        "provenance_digest": provenance_digest,
        "release_signing_key_id": selected_release_key_id,
        "source_tree_digest": source_tree_digest,
        "compose_config_sha256": digest("4"),
        "sbom_cyclonedx_sha256": digest("5"),
        "sbom_cyclonedx_components": 204,
    }
    payload = {
        "apiVersion": "serverware.imageSignatures/v1",
        "kind": "ImageSignatures",
        "metadata": {
            "provenanceDigest": provenance_digest,
            "releaseSigningKeyId": selected_release_key_id,
            "signatureProvider": "sigstore-command",
            "sigstoreTransparencyRequired": True,
            "sourceTreeDigest": source_tree_digest,
            "composeConfigSha256": digest("4"),
            "sbomCyclonedxSha256": digest("5"),
        },
        "images": [
            {
                "service": "serverware",
                "image_id": digest("6"),
                "statement": {
                    "subject": [{"name": "serverware", "digest": {"sha256": "6" * 64}}],
                    "predicate": {**base_predicate, "image_id": digest("6"), "repo_digests": [control_ref]},
                },
                "sigstore": {
                },
            },
            {
                "service": "decision-gate",
                "image_id": digest("7"),
                "statement": {
                    "subject": [{"name": "decision-gate", "digest": {"sha256": "7" * 64}}],
                    "predicate": {**base_predicate, "image_id": digest("7"), "repo_digests": [gate_ref]},
                },
                "sigstore": {
                },
            }
        ],
    }
    for index, image in enumerate(payload["images"], start=1):
        statement_digest = sha256_prefixed_json(image["statement"])
        signature = "sigstore:test:" + str(image["service"])
        image["signature"] = signature
        image["statement_digest"] = statement_digest
        image["sigstore"] = sigstore_proof(statement_digest=statement_digest, signature=signature, log_index=index)
    bundle_digest = sha256_prefixed_json(payload)
    bundle_sigstore = sigstore_proof(statement_digest=bundle_digest, signature="sigstore:test:bundle", log_index=3)
    document = dict(payload)
    document["image_signature_bundle_digest"] = bundle_digest
    document["bundle_signature"] = bundle_sigstore
    document["metadata"] = dict(document["metadata"])
    document["metadata"]["signature"] = bundle_sigstore["signature"]
    document["metadata"]["bundleSigstore"] = bundle_sigstore
    image_record = {
        "type": "release.image_signatures.v1",
        "provenance_digest": provenance_digest,
        "image_signature_bundle_digest": bundle_digest,
        "image_signing_key_id": digest("3"),
        "image_signature_provider": "sigstore-command",
        "release_signing_key_id": selected_release_key_id,
        "signature": bundle_sigstore["signature"],
        "images": {item["service"]: item["image_id"] for item in document["images"]},
    }
    document["metadata"]["transparency"] = transparency_for_record(
        image_record,
        anchor_key="anchorResponse",
        inclusion_key="inclusionProof",
    )
    summary = {
        "ok": True,
        "image_signatures": "pass",
        "image_signature_provider": "sigstore-command",
        "inclusion_verified": True,
        "provenance_digest": provenance_digest,
        "release_signing_key_id": selected_release_key_id,
        "image_signature_bundle_digest": bundle_digest,
        "image_signing_key_id": digest("3"),
        "images": 2,
    }
    return summary, document


def write(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def production_images_build() -> dict[str, Any]:
    return {
        "apiVersion": "serverware.productionImagesBuild/v1",
        "kind": "ProductionImagesBuild",
        "ok": True,
        "metadata": {"source_tree_digest": SOURCE_TREE_DIGEST},
        "no_shell": {"ok": True},
        "images": [
            {"service": "serverware-control", "dockerfile": "Dockerfile.production", "image_id": digest("a")},
            {
                "service": "serverware-decision-gate",
                "dockerfile": "data-plane/decision-gate-rs/Dockerfile.production",
                "image_id": digest("b"),
                "binary_digest": digest("9"),
            },
        ],
    }


def production_images_published() -> dict[str, Any]:
    control_ref = "registry.prod.serverware.dev/serverware/control@sha256:" + "6" * 64
    gate_ref = "registry.prod.serverware.dev/serverware/decision-gate@sha256:" + "7" * 64
    return {
        "apiVersion": "serverware.productionImagesPublished/v1",
        "kind": "ProductionImagesPublished",
        "ok": True,
        "source_build_file": ".tmp/production-images-build.json",
        "images": [
            {
                "service": "serverware-control",
                "local_image_id": digest("a"),
                "tag": "registry.prod.serverware.dev/serverware/control:production-candidate",
                "repo_digest": control_ref,
                "remote_image_id": digest("c"),
            },
            {
                "service": "serverware-decision-gate",
                "local_image_id": digest("b"),
                "tag": "registry.prod.serverware.dev/serverware/decision-gate:production-candidate",
                "repo_digest": gate_ref,
                "remote_image_id": digest("d"),
                "binary_digest": digest("9"),
            },
        ],
        "remote_no_shell": {"ok": True},
        "env": {"SERVERWARE_PRODUCTION_IMAGES": ",".join([control_ref, gate_ref])},
    }


def file_summary(path: Path, label: str) -> dict[str, Any]:
    return {
        "label": label,
        "path": str(path),
        "exists": True,
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def production_host_preflight(tmp: Path, source_tree_digest: str = SOURCE_TREE_DIGEST) -> dict[str, Any]:
    control_ref = "registry.prod.serverware.dev/serverware/control@sha256:" + "6" * 64
    gate_ref = "registry.prod.serverware.dev/serverware/decision-gate@sha256:" + "7" * 64
    policy_identity = verify_production_policy_identity.verify_persisted_report(
        bundle_path=tmp / "policy-bundle.json",
        trusted_public_key_path=tmp / "policy-signing.pub.pem",
        report_path=tmp / "production-policy-identity-verification.json",
    )
    activation = production_release_input_preflight.verify_externally_signed_report(
        report_path=tmp / "policy-activation-verification.json",
        signature_path=tmp / "policy-activation-verification.signature.json",
        trusted_public_key_path=tmp / "policy-activation-verification.pub.pem",
        purpose=production_release_input_preflight.ACTIVATION_PURPOSE,
        api_version=production_release_input_preflight.ACTIVATION_API_VERSION,
        kind=production_release_input_preflight.ACTIVATION_KIND,
    )
    reproducibility = production_release_input_preflight.verify_externally_signed_report(
        report_path=tmp / "reproducible-build-verification.json",
        signature_path=tmp / "reproducible-build-verification.signature.json",
        trusted_public_key_path=tmp / "reproducible-build-verification.pub.pem",
        purpose=production_release_input_preflight.REPRODUCIBILITY_PURPOSE,
        api_version=production_release_input_preflight.REPRODUCIBILITY_API_VERSION,
        kind=production_release_input_preflight.REPRODUCIBILITY_KIND,
    )
    return {
        "apiVersion": "serverware.productionHostPreflight/v1",
        "kind": "ProductionHostPreflight",
        "ok": True,
        "checks": {
            "host": {
                "ok": True,
                "skipped": False,
                "system": "Linux",
                "machine": "x86_64",
                "linux": True,
                "nitro_nsm_device": True,
                "apparmor_sysfs": True,
            },
            "runtime_trust_materials": {
                "ok": True,
                "skipped": False,
                "tls_files": ["ca.pem", "serverware.crt", "serverware.key"],
                "anchor_tls_files": ["audit-anchor.crt", "audit-anchor.key"],
                "helper_files": [
                    "control-plane-attestation-verify",
                    "lease-recipient-attest",
                    "lease-recipient-verify",
                    "nsm-attest",
                    "nsm-unseal",
                    "response-proof-attest",
                ],
                "proof_files": [
                    "proof-collector.key.pem",
                    "proof-collector.pub.pem",
                    "proxy-ca.pem",
                    "proxy-proof-verifier.pub.pem",
                ],
                "proof_collector_files": ["serverware-proof-client"],
                "proof_collector_private_key_mode": "0o600",
                "proof_collector_key_id": proxy_collector_key_info()["key_id"],
                "proof_verifier_key_id": proxy_vendor_verifier_key_info()["key_id"],
                "private_key_mode": "0o600",
                "certificate_not_after": "2035-01-01T00:00:00+00:00",
                "secret_values_redacted": True,
            },
            "production_env": {
                "ok": True,
                "path": str(tmp / "production.env"),
                "file": file_summary(tmp / "production.env", "production-readiness-env"),
                "env_keys": sorted(run_production_readiness.load_env_file(tmp / "production.env")),
                "config_gate": {
                    "ok": True,
                    "out": str(tmp / "production-host-preflight-config.json"),
                    "file": file_summary(tmp / "production-host-preflight-config.json", "production-readiness-config"),
                    "result_sha256": sha256_file(tmp / "production-host-preflight-config.json"),
                    "semantic_sha256": production_config_semantic_sha256(tmp / "production-host-preflight-config.json"),
                    "secret_values_redacted": True,
                },
                "secret_values_redacted": True,
            },
            "production_images_env": {
                "ok": True,
                "path": str(tmp / "production-images.env"),
                "file": file_summary(tmp / "production-images.env", "production-images-env"),
                "status": "valid",
                "images": [
                    {"ref": control_ref, "repository": "registry.prod.serverware.dev/serverware/control", "name": "control", "digest": digest("6")},
                    {
                        "ref": gate_ref,
                        "repository": "registry.prod.serverware.dev/serverware/decision-gate",
                        "name": "decision-gate",
                        "digest": digest("7"),
                    },
                ],
                "image_digests": [digest("6"), digest("7")],
                "secret_values_redacted": True,
            },
            "production_images_env_merge": {
                "ok": True,
                "key": "SERVERWARE_PRODUCTION_IMAGES",
                "production_env_has_key": True,
                "matches_images_env": True,
                "secret_values_redacted": True,
            },
            "production_compose": {
                "ok": True,
                "skipped": False,
                "file": "docker-compose.production.yml",
                "sha256": digest("4"),
                "secret_values_redacted": True,
            },
            "release_security_evidence": {
                "ok": True,
                "secret_values_redacted": True,
                "policy_identity": policy_identity,
                "policy_activation": {key: value for key, value in activation.items() if key != "report"},
                "reproducible_builds": {
                    **{key: value for key, value in reproducibility.items() if key != "report"},
                    "scope": reproducibility["report"]["scope"],
                    "sourceTreeDigest": reproducibility["report"]["source_tree_digest"],
                    "productionBuildBound": True,
                },
                "benchmarkPolicyBound": True,
            },
            "release_artifact_mounts": {
                "ok": True,
                "artifacts": [
                    {
                        "label": "release-provenance",
                        "matches_approved_artifact": True,
                        "sha256": sha256_file(tmp / "release-provenance.json"),
                    },
                    {
                        "label": "image-signatures",
                        "matches_approved_artifact": True,
                        "sha256": sha256_file(tmp / "image-signatures.json"),
                    },
                ],
                "secret_values_redacted": True,
            },
            "release_artifacts": {
                "ok": True,
                "production_images": {
                    "file": file_summary(tmp / "production-images-build.json", "production-images-build"),
                    "source_tree_digest": source_tree_digest,
                    "images": [
                        {"service": "serverware-control", "image_id": digest("a")},
                        {"service": "serverware-decision-gate", "image_id": digest("b")},
                    ],
                    "no_shell": "pass",
                },
                "production_images_published": {
                    "ok": True,
                    "file": file_summary(tmp / "production-images-published.json", "production-images-published"),
                    "repo_digests": [control_ref, gate_ref],
                    "image_digests": [digest("6"), digest("7")],
                },
                "release_provenance": {
                    "digest": json.loads((tmp / "release-provenance-summary.json").read_text(encoding="utf-8"))["provenance_digest"],
                    "file": file_summary(tmp / "release-provenance-summary.json", "release-provenance-summary"),
                },
                "release_provenance_document": {
                    **file_summary(tmp / "release-provenance.json", "release-provenance"),
                    "provenance_digest": json.loads((tmp / "release-provenance-summary.json").read_text(encoding="utf-8"))["provenance_digest"],
                    "source_tree_digest": source_tree_digest,
                },
                "image_signatures_summary": {
                    "digest": json.loads((tmp / "image-signatures-summary.json").read_text(encoding="utf-8"))["image_signature_bundle_digest"],
                    "file": file_summary(tmp / "image-signatures-summary.json", "image-signatures-summary"),
                },
                "image_signatures": {
                    "file": file_summary(tmp / "image-signatures.json", "image-signatures"),
                    "covers_published_production_images": True,
                    "covers_published_production_image_refs": True,
                    "signed_image_ids": [digest("6"), digest("7")],
                    "signed_repo_digests": [control_ref, gate_ref],
                },
                "bench": {
                    "file": file_summary(tmp / "decision-gate-rs-bench.json", "decision-gate-bench"),
                    "candidate": "rust-decision-gate",
                    "requests": 1000,
                    "p99_ms": json.loads((tmp / "decision-gate-rs-bench.json").read_text(encoding="utf-8"))["p99_ms"],
                    "data_plane_binary_digest": json.loads(
                        (tmp / "decision-gate-rs-bench.json").read_text(encoding="utf-8")
                    )["data_plane_binary_digest"],
                    "target_p99_ms": 20.0,
                },
            },
            "kms_materials": {
                "ok": True,
                "path": str(tmp / "kms-materials.json"),
                "exists": True,
                "mode": "0o600",
                "file": file_summary(tmp / "kms-materials.json", "kms-materials"),
                "materials": [
                    {
                        "material": "broker-kek",
                        **kms_material_binding("broker-kek"),
                    },
                    {
                        "material": "decision-gate-ca",
                        **kms_material_binding("decision-gate-ca"),
                    },
                ],
                "secret_values_redacted": True,
            },
        },
        "failures": [],
        "next_command": "make run-production-readiness PRODUCTION_READINESS_ENV=ops/production-readiness.env",
        "secret_values_redacted": True,
    }


def run_verifier(
    tmp: Path,
    *extra: str,
    allow_host_bypass: bool = True,
    include_proxy_proof: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    env = os.environ.copy()
    if allow_host_bypass:
        env["SERVERWARE_TEST_ONLY_ALLOW_PREFLIGHT_BYPASS"] = "1"
    proxy_proof_args = (
        [
            "--proxy-response-proof",
            str(tmp / "proxy-response-proof.json"),
            "--proxy-proof-verifier-public-key",
            str(tmp / "proxy-vendor-verifier-public-key.pem"),
            "--proxy-collector-public-key",
            str(tmp / "proxy-collector-public-key.pem"),
            "--proxy-server-instance-id",
            PROXY_SERVER_INSTANCE_ID,
            "--proxy-client-nonce",
            PROXY_CLIENT_NONCE,
            "--proxy-request-digest",
            PROXY_REQUEST_DIGEST,
            "--proxy-operation-digest",
            PROXY_OPERATION_DIGEST,
            "--proxy-tls-channel-binding",
            PROXY_TLS_CHANNEL_BINDING,
        ]
        if include_proxy_proof
        else []
    )
    return subprocess.run(
        [
            sys.executable,
            "scripts/verify_release_completion.py",
            *(["--skip-current-host-check"] if allow_host_bypass else []),
            "--production-readiness",
            str(tmp / "production-readiness.json"),
            "--production-readiness-config",
            str(tmp / "production-readiness-config.json"),
            "--production-readiness-env",
            str(tmp / "production.env"),
            "--production-host-preflight",
            str(tmp / "production-host-preflight.json"),
            "--nitro-evidence",
            str(tmp / "nitro-kms-evidence.json"),
            "--production-images-build",
            str(tmp / "production-images-build.json"),
            "--production-images-env",
            str(tmp / "production-images.env"),
            "--production-images-published",
            str(tmp / "production-images-published.json"),
            "--release-provenance-summary",
            str(tmp / "release-provenance-summary.json"),
            "--release-provenance",
            str(tmp / "release-provenance.json"),
            "--image-signatures-summary",
            str(tmp / "image-signatures-summary.json"),
            "--image-signatures",
            str(tmp / "image-signatures.json"),
            "--bench",
            str(tmp / "decision-gate-rs-bench.json"),
            "--policy-bundle",
            str(tmp / "policy-bundle.json"),
            "--policy-trusted-public-key",
            str(tmp / "policy-signing.pub.pem"),
            "--policy-identity-verification",
            str(tmp / "production-policy-identity-verification.json"),
            "--policy-activation-verification",
            str(tmp / "policy-activation-verification.json"),
            "--policy-activation-signature",
            str(tmp / "policy-activation-verification.signature.json"),
            "--policy-activation-trusted-public-key",
            str(tmp / "policy-activation-verification.pub.pem"),
            "--reproducible-build-verification",
            str(tmp / "reproducible-build-verification.json"),
            "--reproducible-build-signature",
            str(tmp / "reproducible-build-verification.signature.json"),
            "--reproducible-build-trusted-public-key",
            str(tmp / "reproducible-build-verification.pub.pem"),
            "--kms-materials",
            str(tmp / "kms-materials.json"),
            *proxy_proof_args,
            *extra,
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=env,
    )


def detail(result: subprocess.CompletedProcess[bytes]) -> str:
    return result.stdout.decode("utf-8", errors="replace") + result.stderr.decode("utf-8", errors="replace")


def expect_proxy_proof_failure(
    tmp: Path,
    document: dict[str, Any],
    expected_error: str,
    label: str,
    *extra: str,
) -> None:
    write(tmp / "proxy-response-proof.json", document)
    rejected = run_verifier(tmp, *extra)
    if rejected.returncode == 0 or expected_error not in detail(rejected):
        raise AssertionError(f"completion verifier accepted {label}: {detail(rejected)}")


def test_proxy_response_proof_requirements(
    tmp: Path,
    valid_document: dict[str, Any],
    provenance_digest: str,
) -> None:
    missing = run_verifier(tmp, include_proxy_proof=False)
    if missing.returncode == 0 or "production completion requires --proxy-response-proof" not in detail(missing):
        raise AssertionError(f"completion verifier accepted absent proxy proof evidence: {detail(missing)}")

    wrong_version = clone_document(valid_document)
    wrong_version["apiVersion"] = "serverware.proxyResponseProof/v1"
    expect_proxy_proof_failure(tmp, wrong_version, "proxy response proof has wrong apiVersion", "a legacy v1 proxy proof")

    wrong_capture_version = clone_document(valid_document)
    wrong_capture_version["external_capture"]["apiVersion"] = "serverware.proxyResponseCapture/v0"
    expect_proxy_proof_failure(
        tmp,
        wrong_capture_version,
        "external capture has wrong apiVersion",
        "a proxy proof with a legacy external capture",
    )

    tampered_client_request = clone_document(valid_document)
    tampered_client_request["external_capture"]["client_request"]["path"] = "/v1/other-resource"
    sign_proxy_external_capture(tampered_client_request)
    expect_proxy_proof_failure(
        tmp,
        tampered_client_request,
        "external client request digest mismatch",
        "a collector-signed capture with a tampered client request",
    )

    wrong_statement_version = clone_document(valid_document)
    wrong_statement_version["server_statement"]["apiVersion"] = "serverware.proxyResponseStatement/v0"
    resign_proxy_response_proof(wrong_statement_version)
    expect_proxy_proof_failure(
        tmp,
        wrong_statement_version,
        "server statement has wrong apiVersion",
        "a proxy proof with a legacy server statement",
    )

    development = clone_document(valid_document)
    development["external_capture"]["environment"] = "development"
    expect_proxy_proof_failure(tmp, development, "is not production evidence", "development proxy capture")

    self_reported = clone_document(valid_document)
    self_reported["external_capture"]["collection_mode"] = "rust-self-report"
    expect_proxy_proof_failure(tmp, self_reported, "absent, dev, or self-reported", "Rust self-reported proxy capture")

    self_reported_statement = clone_document(valid_document)
    self_reported_statement["server_statement"]["collection_mode"] = "server-self-reported"
    resign_proxy_response_proof(self_reported_statement)
    expect_proxy_proof_failure(
        tmp,
        self_reported_statement,
        "server statement fields do not match the contract",
        "a self-reported field smuggled into the server statement",
    )

    missing_server_signature = clone_document(valid_document)
    missing_server_signature["server_signature"] = {}
    expect_proxy_proof_failure(
        tmp,
        missing_server_signature,
        "server signature fields do not match the contract",
        "a proxy statement without a server signature",
    )

    untrusted_collector = clone_document(valid_document)
    sign_proxy_external_capture(untrusted_collector, alternate_proxy_collector_key_info())
    expect_proxy_proof_failure(
        tmp,
        untrusted_collector,
        "collector signing key does not match the configured trust root",
        "an external capture signed by an untrusted collector",
    )

    tampered_signed_capture = clone_document(valid_document)
    tampered_signed_capture["external_capture"]["tls_peer"]["leaf_certificate_sha256"] = digest("b")
    expect_proxy_proof_failure(
        tmp,
        tampered_signed_capture,
        "external capture collector signature verification failed",
        "an external capture changed after collector signing",
    )

    unsigned_headers = clone_document(valid_document)
    unsigned_headers["external_capture"]["response"]["selected_headers"]["x-serverware-request-id"] = "tampered"
    expect_proxy_proof_failure(
        tmp,
        unsigned_headers,
        "selected response headers digest mismatch",
        "tampered external capture headers",
    )

    missing_selected_header = clone_document(valid_document)
    missing_headers = missing_selected_header["external_capture"]["response"]["selected_headers"]
    del missing_headers["content-length"]
    missing_selected_header["external_capture"]["response"]["selected_headers_digest"] = sha256_prefixed_json(
        missing_headers
    )
    sign_proxy_external_capture(missing_selected_header)
    expect_proxy_proof_failure(
        tmp,
        missing_selected_header,
        "missing required selected response headers",
        "a collector-signed capture missing content-length",
    )

    extra_selected_header = clone_document(valid_document)
    extra_headers = extra_selected_header["external_capture"]["response"]["selected_headers"]
    extra_headers["x-serverware-request-id"] = "unexpected"
    extra_selected_header["external_capture"]["response"]["selected_headers_digest"] = sha256_prefixed_json(
        extra_headers
    )
    sign_proxy_external_capture(extra_selected_header)
    expect_proxy_proof_failure(
        tmp,
        extra_selected_header,
        "unexpected selected response headers",
        "a collector-signed capture with an extra selected header",
    )

    capture_body_mismatch = clone_document(valid_document)
    capture_body_mismatch["external_capture"]["response"]["body_digest"] = digest("0")
    capture_body_headers = capture_body_mismatch["external_capture"]["response"]["selected_headers"]
    capture_body_headers["x-serverware-response-body-sha256"] = digest("0")
    capture_body_mismatch["external_capture"]["response"]["selected_headers_digest"] = sha256_prefixed_json(
        capture_body_headers
    )
    sign_proxy_external_capture(capture_body_mismatch)
    expect_proxy_proof_failure(
        tmp,
        capture_body_mismatch,
        "external capture response does not match server statement",
        "an external response body that differs from the server statement",
    )

    capture_statement_digest_mismatch = clone_document(valid_document)
    capture_statement_digest_mismatch["external_capture"]["server_statement_sha256"] = digest("0")
    sign_proxy_external_capture(capture_statement_digest_mismatch)
    expect_proxy_proof_failure(
        tmp,
        capture_statement_digest_mismatch,
        "external capture server statement digest mismatch",
        "an external capture bound to another server statement",
    )

    invalid_tls_peer_leaf_digest = clone_document(valid_document)
    invalid_tls_peer_leaf_digest["external_capture"]["tls_peer"]["leaf_certificate_sha256"] = "invalid"
    sign_proxy_external_capture(invalid_tls_peer_leaf_digest)
    expect_proxy_proof_failure(
        tmp,
        invalid_tls_peer_leaf_digest,
        "TLS peer leaf certificate digest must be a sha256-prefixed digest",
        "an external capture with an invalid TLS peer certificate digest",
    )

    mismatched_tls_peer = clone_document(valid_document)
    mismatched_tls_peer["external_capture"]["tls_peer"]["spiffe_id"] = (
        "spiffe://prod.serverware.dev/decision-gate/instance-02"
    )
    sign_proxy_external_capture(mismatched_tls_peer)
    expect_proxy_proof_failure(
        tmp,
        mismatched_tls_peer,
        "TLS peer SPIFFE ID does not match expected server instance",
        "a collector-signed capture from another TLS peer",
    )

    forged_server_signature = clone_document(valid_document)
    forged_server_signature["server_signature"]["signature"] = "ed25519:AAAA"
    expect_proxy_proof_failure(
        tmp,
        forged_server_signature,
        "server statement signature verification failed",
        "a forged proxy server statement signature",
    )

    mismatched_server_key_id = clone_document(valid_document)
    mismatched_server_key_id["server_signature"]["key_id"] = digest("0")
    expect_proxy_proof_failure(
        tmp,
        mismatched_server_key_id,
        "server statement signing key id mismatch",
        "a server signature with an unrelated key id",
    )

    stale = proxy_response_proof(provenance_digest, now=int(time.time()) - 600)
    expect_proxy_proof_failure(tmp, stale, "external capture is stale", "a stale external proxy capture")

    stale_statement = clone_document(valid_document)
    stale_statement["server_statement"]["issued_at_unix"] = int(time.time()) - 600
    resign_proxy_response_proof(stale_statement)
    expect_proxy_proof_failure(tmp, stale_statement, "server statement is stale", "a stale server statement")

    unsuccessful = clone_document(valid_document)
    unsuccessful["external_capture"]["response"]["status"] = 503
    unsuccessful["server_statement"]["response"]["status"] = 503
    resign_proxy_response_proof(unsuccessful)
    expect_proxy_proof_failure(tmp, unsuccessful, "successful production response status", "a failed proxy response")

    bad_header_digest = clone_document(valid_document)
    bad_header_digest["external_capture"]["response"]["selected_headers_digest"] = digest("0")
    bad_header_digest["server_statement"]["response"]["selected_headers_digest"] = digest("0")
    resign_proxy_response_proof(bad_header_digest)
    expect_proxy_proof_failure(
        tmp,
        bad_header_digest,
        "selected response headers digest mismatch",
        "a signed but incorrect selected response headers digest",
    )

    for field, expected_error in (
        ("policy_digest", "proxy response server statement policy digest mismatch"),
        ("runtime_manifest_digest", "proxy response server statement runtime manifest digest mismatch"),
        ("data_plane_binary_digest", "proxy response server statement data plane binary digest mismatch"),
        ("release_digest", "proxy response server statement release digest mismatch"),
    ):
        mismatched = clone_document(valid_document)
        mismatched["server_statement"][field] = digest("0")
        resign_proxy_response_proof(mismatched)
        expect_proxy_proof_failure(tmp, mismatched, expected_error, f"a proxy proof with a mismatched {field}")

    bad_instance = clone_document(valid_document)
    bad_instance["server_statement"]["server_instance"]["identity_digest"] = digest("0")
    resign_proxy_response_proof(bad_instance)
    expect_proxy_proof_failure(
        tmp,
        bad_instance,
        "server instance identity digest mismatch",
        "a mismatched server instance identity",
    )

    mismatched_nonce = clone_document(valid_document)
    mismatched_nonce["server_statement"]["client_nonce"] = b64e(b"s" * 32)
    resign_proxy_response_proof(mismatched_nonce)
    expect_proxy_proof_failure(
        tmp,
        mismatched_nonce,
        "external capture client_nonce does not match server statement",
        "a client nonce mismatch between capture and statement",
    )

    mismatched_request = clone_document(valid_document)
    mismatched_request["server_statement"]["request_digest"] = digest("0")
    resign_proxy_response_proof(mismatched_request)
    expect_proxy_proof_failure(
        tmp,
        mismatched_request,
        "external capture request_digest does not match server statement",
        "a request digest mismatch between capture and statement",
    )

    mismatched_operation = clone_document(valid_document)
    mismatched_operation["server_statement"]["operation_digest"] = digest("0")
    resign_proxy_response_proof(mismatched_operation)
    expect_proxy_proof_failure(
        tmp,
        mismatched_operation,
        "external capture operation_digest does not match server statement",
        "an operation digest mismatch between capture and statement",
    )

    mismatched_response = clone_document(valid_document)
    mismatched_response["server_statement"]["response"]["body_digest"] = digest("0")
    resign_proxy_response_proof(mismatched_response)
    expect_proxy_proof_failure(
        tmp,
        mismatched_response,
        "external capture response does not match server statement",
        "a response mismatch between capture and statement",
    )

    mismatched_tls = clone_document(valid_document)
    mismatched_tls["server_statement"]["tls_channel_binding"]["value"] = b64e(b"s" * 32)
    resign_proxy_response_proof(mismatched_tls)
    expect_proxy_proof_failure(
        tmp,
        mismatched_tls,
        "external capture tls_channel_binding does not match server statement",
        "a TLS channel mismatch between capture and statement",
    )

    missing_quote = clone_document(valid_document)
    missing_quote["vendor_tee"]["quote"] = None
    expect_proxy_proof_failure(tmp, missing_quote, "missing a non-null vendor TEE quote", "a null vendor TEE quote")

    tampered_quote = clone_document(valid_document)
    tampered_quote["vendor_tee"]["quote"]["body_b64"] = b64e(b"tampered opaque vendor quote bytes " * 4)
    expect_proxy_proof_failure(tmp, tampered_quote, "vendor quote digest mismatch", "an unsigned vendor quote")

    development_quote = clone_document(valid_document)
    development_quote["vendor_tee"]["provider"] = "dev-self-reported"
    resign_proxy_response_proof(development_quote)
    expect_proxy_proof_failure(tmp, development_quote, "not a production identifier", "a development TEE provider")

    missing_verifier = clone_document(valid_document)
    missing_verifier["vendor_tee"]["trusted_verifier"] = {}
    expect_proxy_proof_failure(
        tmp,
        missing_verifier,
        "vendor verifier result has wrong apiVersion",
        "a vendor quote without a trusted verifier outcome",
    )

    rejected_outcome = clone_document(valid_document)
    rejected_outcome["vendor_tee"]["trusted_verifier"]["statement"]["outcome"] = "rejected"
    sign_proxy_vendor_verifier_statement(rejected_outcome)
    expect_proxy_proof_failure(tmp, rejected_outcome, "outcome is not verified", "a rejected vendor verifier outcome")

    unverified_quote = clone_document(valid_document)
    unverified_quote["vendor_tee"]["trusted_verifier"]["statement"]["vendor_quote_verified"] = False
    sign_proxy_vendor_verifier_statement(unverified_quote)
    expect_proxy_proof_failure(tmp, unverified_quote, "vendor quote was not verified", "an unverified vendor quote")

    unchecked_revocation = clone_document(valid_document)
    unchecked_revocation["vendor_tee"]["trusted_verifier"]["statement"]["revocation_checked"] = False
    sign_proxy_vendor_verifier_statement(unchecked_revocation)
    expect_proxy_proof_failure(
        tmp,
        unchecked_revocation,
        "revocation status was not checked",
        "a vendor receipt without revocation checking",
    )

    debug_quote = clone_document(valid_document)
    debug_quote["vendor_tee"]["trusted_verifier"]["statement"]["debug"] = True
    sign_proxy_vendor_verifier_statement(debug_quote)
    expect_proxy_proof_failure(tmp, debug_quote, "accepted debug mode", "a debug-mode vendor quote")

    forged_verifier = clone_document(valid_document)
    forged_verifier["vendor_tee"]["trusted_verifier"]["signature"] = "ed25519:AAAA"
    expect_proxy_proof_failure(
        tmp,
        forged_verifier,
        "trusted vendor verifier signature verification failed",
        "a forged vendor verifier receipt",
    )

    untrusted_verifier = clone_document(valid_document)
    resign_proxy_response_proof(
        untrusted_verifier,
        verifier_key_info=alternate_proxy_vendor_verifier_key_info(),
    )
    expect_proxy_proof_failure(
        tmp,
        untrusted_verifier,
        "verifier key is not the configured trust root",
        "a verifier receipt signed by an untrusted key",
    )

    legacy_verifier_binding = clone_document(valid_document)
    legacy_verifier_statement = legacy_verifier_binding["vendor_tee"]["trusted_verifier"]["statement"]
    legacy_verifier_statement["proof_evidence_sha256"] = legacy_verifier_statement.pop("server_statement_sha256")
    sign_proxy_vendor_verifier_statement(legacy_verifier_binding)
    expect_proxy_proof_failure(
        tmp,
        legacy_verifier_binding,
        "legacy proof evidence digest binding",
        "a vendor verifier receipt using the v1 evidence binding",
    )

    mismatched_response_key = clone_document(valid_document)
    mismatched_response_key["vendor_tee"]["trusted_verifier"]["statement"]["response_signing_key_id"] = digest("0")
    sign_proxy_vendor_verifier_statement(mismatched_response_key)
    expect_proxy_proof_failure(
        tmp,
        mismatched_response_key,
        "did not bind the response signing key",
        "a vendor receipt bound to another response signing key",
    )

    mismatched_claim = clone_document(valid_document)
    mismatched_claim["vendor_tee"]["trusted_verifier"]["statement"]["attested_claims"]["request_digest"] = digest("0")
    sign_proxy_vendor_verifier_statement(mismatched_claim)
    expect_proxy_proof_failure(
        tmp,
        mismatched_claim,
        "attested claim request_digest mismatch",
        "a vendor quote that did not attest the request digest",
    )

    missing_claim = clone_document(valid_document)
    del missing_claim["vendor_tee"]["trusted_verifier"]["statement"]["attested_claims"]["issued_at_unix"]
    sign_proxy_vendor_verifier_statement(missing_claim)
    expect_proxy_proof_failure(
        tmp,
        missing_claim,
        "attested claim issued_at_unix mismatch",
        "a vendor receipt missing a server statement claim",
    )

    extra_claim = clone_document(valid_document)
    extra_claim["vendor_tee"]["trusted_verifier"]["statement"]["attested_claims"]["self_reported"] = True
    sign_proxy_vendor_verifier_statement(extra_claim)
    expect_proxy_proof_failure(
        tmp,
        extra_claim,
        "attested claims do not exactly match the server statement",
        "a vendor receipt with an unbound self-reported claim",
    )

    expired_verifier = clone_document(valid_document)
    expired_verifier["vendor_tee"]["trusted_verifier"]["statement"]["verified_at_unix"] = int(time.time()) - 100
    expired_verifier["vendor_tee"]["trusted_verifier"]["statement"]["expires_at_unix"] = int(time.time()) - 1
    sign_proxy_vendor_verifier_statement(expired_verifier)
    expect_proxy_proof_failure(
        tmp,
        expired_verifier,
        "trusted vendor verifier receipt is expired",
        "an expired vendor verifier receipt",
    )

    write(tmp / "proxy-response-proof.json", valid_document)
    wrong_nonce = b64e(b"x" * 32)
    rejected_nonce = run_verifier(tmp, "--proxy-client-nonce", wrong_nonce)
    if rejected_nonce.returncode == 0 or "client nonce mismatch" not in detail(rejected_nonce):
        raise AssertionError(f"completion verifier accepted a proof for another client nonce: {detail(rejected_nonce)}")
    rejected_request = run_verifier(tmp, "--proxy-request-digest", digest("0"))
    if rejected_request.returncode == 0 or "canonical request digest mismatch" not in detail(rejected_request):
        raise AssertionError(f"completion verifier accepted a proof for another request: {detail(rejected_request)}")
    rejected_operation = run_verifier(tmp, "--proxy-operation-digest", digest("0"))
    if rejected_operation.returncode == 0 or "operation digest mismatch" not in detail(rejected_operation):
        raise AssertionError(f"completion verifier accepted a proof for another operation: {detail(rejected_operation)}")
    rejected_tls = run_verifier(tmp, "--proxy-tls-channel-binding", b64e(b"z" * 32))
    if rejected_tls.returncode == 0 or "TLS channel binding mismatch" not in detail(rejected_tls):
        raise AssertionError(f"completion verifier accepted a proof from another TLS channel: {detail(rejected_tls)}")

    prefix_only_spiffe = "spiffe://prod.serverware.dev/decision-gate"
    rejected_instance = run_verifier(tmp, "--proxy-server-instance-id", prefix_only_spiffe)
    instance_error = detail(rejected_instance)
    if rejected_instance.returncode == 0 or not any(
        message in instance_error
        for message in (
            "proxy response expected server instance does not match the signed production environment",
            "TLS peer SPIFFE ID does not match expected server instance",
        )
    ):
        raise AssertionError(
            f"completion verifier accepted a prefix-only expected server SPIFFE ID: {instance_error}"
        )

    duplicate_json = json.dumps(valid_document, sort_keys=True)
    api_version_field = '"apiVersion": "serverware.proxyResponseProof/v2"'
    if api_version_field not in duplicate_json:
        raise AssertionError("proxy proof fixture did not contain its expected apiVersion field")
    (tmp / "proxy-response-proof.json").write_text(
        duplicate_json.replace(api_version_field, f"{api_version_field}, {api_version_field}", 1),
        encoding="utf-8",
    )
    rejected_duplicate = run_verifier(tmp)
    if rejected_duplicate.returncode == 0 or "duplicate JSON object key: apiVersion" not in detail(rejected_duplicate):
        raise AssertionError(f"completion verifier accepted duplicate JSON object keys: {detail(rejected_duplicate)}")

    write(tmp / "proxy-response-proof.json", valid_document)


def main() -> None:
    global POLICY_DIGEST
    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        production_build = production_images_build()
        reproduced_images = []
        for image in production_build["images"]:
            item = {"service": image["service"], "image_id": image["image_id"]}
            if image["service"] == "serverware-decision-gate":
                item["rust_binary_sha256"] = image["binary_digest"]
            reproduced_images.append(item)
        _, POLICY_DIGEST = test_production_release_input_preflight.release_security_fixture(
            tmp,
            source_tree_digest=SOURCE_TREE_DIGEST,
            images=reproduced_images,
        )
        provenance_summary, provenance_document = release_provenance()
        nitro = nitro_evidence(provenance_summary["provenance_digest"])
        image_summary, image_document = image_signatures(provenance_summary["provenance_digest"])
        write_production_env_files(tmp)
        write(tmp / "production-readiness.json", production_readiness(nitro, tmp))
        write(tmp / "nitro-kms-evidence.json", nitro)
        write(tmp / "production-images-build.json", production_build)
        write(tmp / "production-images-published.json", production_images_published())
        write(tmp / "release-provenance-summary.json", provenance_summary)
        write(tmp / "release-provenance.json", provenance_document)
        write(tmp / "image-signatures-summary.json", image_summary)
        write(tmp / "image-signatures.json", image_document)
        write(tmp / "kms-materials.json", kms_materials_document())
        write(
            tmp / "decision-gate-rs-bench.json",
            benchmark_document(),
        )
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        valid_proxy_response_proof = proxy_response_proof(provenance_summary["provenance_digest"])
        write(tmp / "proxy-response-proof.json", valid_proxy_response_proof)
        (tmp / "proxy-vendor-verifier-public-key.pem").write_text(
            proxy_vendor_verifier_key_info()["public_key_pem"],
            encoding="ascii",
        )
        (tmp / "proxy-collector-public-key.pem").write_text(
            proxy_collector_key_info()["public_key_pem"],
            encoding="ascii",
        )
        out_path = tmp / "completion-proof.json"
        result = run_verifier(tmp, "--out", str(out_path))
        if result.returncode != 0:
            raise AssertionError(f"completion verifier failed: {detail(result)}")
        proof = json.loads(result.stdout.decode("utf-8"))
        if proof.get("ok") is not True or not out_path.exists() or not proof.get("proof_sha256", "").startswith("sha256:"):
            raise AssertionError(f"completion verifier did not write a valid proof: {proof}")
        proxy_summary = proof.get("production_proxy_response_proof") or {}
        if proof.get("apiVersion") != "serverware.completionProof/v2" or not all(
            proxy_summary.get(field) is True
            for field in (
                "vendor_quote_verified",
                "collector_signature_verified",
                "server_statement_signature_verified",
                "fresh_client_nonce_bound",
                "authenticated_external_client_capture_bound",
                "release_artifacts_bound",
            )
        ):
            raise AssertionError(f"completion verifier omitted verified production proxy proof bindings: {proof}")

        test_proxy_response_proof_requirements(
            tmp,
            valid_proxy_response_proof,
            provenance_summary["provenance_digest"],
        )

        rejected_host_bypass = run_verifier(tmp, "--skip-current-host-check", allow_host_bypass=False)
        if rejected_host_bypass.returncode == 0 or "--skip-current-host-check is test-only" not in detail(rejected_host_bypass):
            raise AssertionError(f"completion verifier accepted host bypass without test-only opt-in: {detail(rejected_host_bypass)}")

        stale_config_preflight = production_host_preflight(tmp)
        write(tmp / "production-host-preflight.json", stale_config_preflight)
        write(tmp / "production-readiness-config.json", {**production_config_document(tmp / "production-readiness-config.json"), "checks": ["nitro"]})
        rejected_config = run_verifier(tmp)
        if rejected_config.returncode == 0 or "production config gate artifact omitted required checks" not in detail(rejected_config):
            raise AssertionError(f"completion verifier accepted a weak config gate artifact: {detail(rejected_config)}")
        write_production_config_files(tmp)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        forged_preflight_config = production_host_preflight(tmp)
        forged_preflight_config["checks"]["production_env"]["config_gate"]["semantic_sha256"] = digest("9")
        write(tmp / "production-host-preflight.json", forged_preflight_config)
        rejected_forged_config = run_verifier(tmp)
        if rejected_forged_config.returncode == 0 or "config gate semantic digest mismatch" not in detail(rejected_forged_config):
            raise AssertionError(f"completion verifier accepted forged preflight config digest: {detail(rejected_forged_config)}")
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        mismatched_readiness_env = production_readiness(nitro, tmp)
        mismatched_readiness_env["environment"]["production_readiness_env_sha256"] = digest("9")
        write(tmp / "production-readiness.json", mismatched_readiness_env)
        rejected_readiness_env = run_verifier(tmp)
        if rejected_readiness_env.returncode == 0 or "production readiness env digest does not match current production readiness env" not in detail(rejected_readiness_env):
            raise AssertionError(f"completion verifier accepted readiness from another env: {detail(rejected_readiness_env)}")
        write(tmp / "production-readiness.json", production_readiness(nitro, tmp))
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        mismatched_config_env = production_config_document(tmp / "production-readiness-config.json")
        mismatched_config_env["environment"]["production_images_env_sha256"] = digest("9")
        write(tmp / "production-readiness-config.json", mismatched_config_env)
        rejected_config_env = run_verifier(tmp)
        if rejected_config_env.returncode == 0 or "production config gate image env digest does not match production host preflight" not in detail(rejected_config_env):
            raise AssertionError(f"completion verifier accepted config gate from another image env: {detail(rejected_config_env)}")
        write_production_config_files(tmp)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        same_value = production_images_env_value()
        (tmp / "production.env").write_text(f"# semantic equivalent rewrite\nSERVERWARE_PRODUCTION_IMAGES='{same_value}'\n", encoding="utf-8")
        rejected_stale_env_preflight = run_verifier(tmp)
        if (
            rejected_stale_env_preflight.returncode == 0
            or "production host preflight production env digest does not match current production readiness env"
            not in detail(rejected_stale_env_preflight)
        ):
            raise AssertionError(f"completion verifier accepted stale production env preflight evidence: {detail(rejected_stale_env_preflight)}")
        write_production_env_files(tmp)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        (tmp / "production-images.env").write_text(f"# semantic equivalent rewrite\nSERVERWARE_PRODUCTION_IMAGES='{same_value}'\n", encoding="utf-8")
        rejected_stale_images_env_preflight = run_verifier(tmp)
        if (
            rejected_stale_images_env_preflight.returncode == 0
            or "production host preflight production images env digest does not match current production images env"
            not in detail(rejected_stale_images_env_preflight)
        ):
            raise AssertionError(f"completion verifier accepted stale production images env preflight evidence: {detail(rejected_stale_images_env_preflight)}")
        write_production_env_files(tmp)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        write_production_env_files(tmp, readiness_value=production_image_refs()[0])
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_env_merge = run_verifier(tmp)
        if (
            rejected_env_merge.returncode == 0
            or "production readiness env SERVERWARE_PRODUCTION_IMAGES does not match production images env"
            not in detail(rejected_env_merge)
        ):
            raise AssertionError(f"completion verifier accepted mismatched production env files: {detail(rejected_env_merge)}")
        write_production_env_files(tmp)

        stale_images_value = production_images_env_value(control_digest=digest("8"), gate_digest=digest("7"))
        write_production_env_files(tmp, images_value=stale_images_value)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_current_images = run_verifier(tmp)
        if rejected_current_images.returncode == 0 or "current production images env refs do not match readiness" not in detail(rejected_current_images):
            raise AssertionError(f"completion verifier accepted stale current production image env: {detail(rejected_current_images)}")
        write_production_env_files(tmp)

        stale_source_tree = digest("9")
        stale_provenance_summary, stale_provenance_document = release_provenance()
        stale_provenance_document["provenance"]["source_tree"]["digest"] = stale_source_tree
        refresh_release_provenance(stale_provenance_summary, stale_provenance_document)
        stale_image_summary, stale_image_document = image_signatures(
            stale_provenance_summary["provenance_digest"],
            source_tree_digest=stale_source_tree,
        )
        stale_build = production_images_build()
        stale_build["metadata"]["source_tree_digest"] = stale_source_tree
        write(tmp / "production-images-build.json", stale_build)
        write(tmp / "release-provenance-summary.json", stale_provenance_summary)
        write(tmp / "release-provenance.json", stale_provenance_document)
        write(tmp / "image-signatures-summary.json", stale_image_summary)
        write(tmp / "image-signatures.json", stale_image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp, source_tree_digest=stale_source_tree))
        rejected_stale_source = run_verifier(tmp)
        if rejected_stale_source.returncode == 0 or "source tree digest does not match current source tree" not in detail(rejected_stale_source):
            raise AssertionError(f"completion verifier accepted stale source-tree artifacts: {detail(rejected_stale_source)}")
        write(tmp / "production-images-build.json", production_images_build())
        write(tmp / "release-provenance-summary.json", provenance_summary)
        write(tmp / "release-provenance.json", provenance_document)
        write(tmp / "image-signatures-summary.json", image_summary)
        write(tmp / "image-signatures.json", image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        bad_provenance_document = json.loads(json.dumps(provenance_document))
        bad_provenance_document["signature"] = "ed25519:test"
        write(tmp / "release-provenance.json", bad_provenance_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_provenance_signature = run_verifier(tmp)
        if rejected_provenance_signature.returncode == 0 or "release provenance signature verification failed" not in detail(rejected_provenance_signature):
            raise AssertionError(f"completion verifier accepted forged release provenance: {detail(rejected_provenance_signature)}")
        write(tmp / "release-provenance.json", provenance_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        bad_provenance_document = json.loads(json.dumps(provenance_document))
        release_checkpoint = bad_provenance_document["transparency"]["anchor_response"]["anchors"][0]["external_checkpoint"]
        release_checkpoint["log_id"] = digest("a")
        release_checkpoint["receipt"]["payload"]["log_id"] = digest("a")
        write(tmp / "release-provenance.json", bad_provenance_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_release_log = run_verifier(tmp)
        rejected_release_log_detail = detail(rejected_release_log)
        if rejected_release_log.returncode == 0 or not (
            "release provenance external transparency log does not match live readiness" in rejected_release_log_detail
            or "release provenance external transparency receipt public key does not match log id" in rejected_release_log_detail
        ):
            raise AssertionError(f"completion verifier accepted release provenance from another external log: {detail(rejected_release_log)}")
        write(tmp / "release-provenance.json", provenance_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        bad_provenance_document = json.loads(json.dumps(provenance_document))
        release_checkpoint = bad_provenance_document["transparency"]["anchor_response"]["anchors"][0]["external_checkpoint"]
        release_checkpoint["receipt"]["signature"] = "ed25519:test"
        write(tmp / "release-provenance.json", bad_provenance_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_release_receipt = run_verifier(tmp)
        if rejected_release_receipt.returncode == 0 or "release provenance external transparency receipt signature verification failed" not in detail(rejected_release_receipt):
            raise AssertionError(f"completion verifier accepted release provenance with a forged external receipt: {detail(rejected_release_receipt)}")
        write(tmp / "release-provenance.json", provenance_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        bad_provenance_document = json.loads(json.dumps(provenance_document))
        bad_provenance_document["transparency"]["record"]["provenance_digest"] = digest("0")
        write(tmp / "release-provenance.json", bad_provenance_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_release_record = run_verifier(tmp)
        if rejected_release_record.returncode == 0 or "release provenance transparency record provenance_digest mismatch" not in detail(rejected_release_record):
            raise AssertionError(f"completion verifier accepted release provenance with a swapped transparency record: {detail(rejected_release_record)}")
        write(tmp / "release-provenance.json", provenance_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        bad_provenance_document = json.loads(json.dumps(provenance_document))
        bad_provenance_document["transparency"]["inclusion_proof"]["proof"] = [{"side": "right", "hash": digest("0")}]
        write(tmp / "release-provenance.json", bad_provenance_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_release_merkle = run_verifier(tmp)
        if rejected_release_merkle.returncode == 0 or "release provenance transparency Merkle inclusion proof did not verify" not in detail(rejected_release_merkle):
            raise AssertionError(f"completion verifier accepted release provenance with a bad Merkle proof: {detail(rejected_release_merkle)}")
        write(tmp / "release-provenance.json", provenance_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        bad_image_summary, bad_image_document = image_signatures(provenance_summary["provenance_digest"])
        image_checkpoint = bad_image_document["metadata"]["transparency"]["anchorResponse"]["anchors"][0]["external_checkpoint"]
        image_checkpoint["log_id"] = digest("a")
        image_checkpoint["receipt"]["payload"]["log_id"] = digest("a")
        write(tmp / "image-signatures-summary.json", bad_image_summary)
        write(tmp / "image-signatures.json", bad_image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_image_log = run_verifier(tmp)
        rejected_image_log_detail = detail(rejected_image_log)
        if rejected_image_log.returncode == 0 or not (
            "image signature bundle external transparency log does not match live readiness" in rejected_image_log_detail
            or "image signature bundle external transparency receipt public key does not match log id" in rejected_image_log_detail
        ):
            raise AssertionError(f"completion verifier accepted image signatures from another external log: {detail(rejected_image_log)}")
        write(tmp / "image-signatures-summary.json", image_summary)
        write(tmp / "image-signatures.json", image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        bad_image_summary, bad_image_document = image_signatures(provenance_summary["provenance_digest"])
        image_checkpoint = bad_image_document["metadata"]["transparency"]["anchorResponse"]["anchors"][0]["external_checkpoint"]
        image_checkpoint["receipt"]["signature"] = "ed25519:test"
        write(tmp / "image-signatures-summary.json", bad_image_summary)
        write(tmp / "image-signatures.json", bad_image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_image_receipt = run_verifier(tmp)
        if rejected_image_receipt.returncode == 0 or "image signature bundle external transparency receipt signature verification failed" not in detail(rejected_image_receipt):
            raise AssertionError(f"completion verifier accepted image signatures with a forged external receipt: {detail(rejected_image_receipt)}")
        write(tmp / "image-signatures-summary.json", image_summary)
        write(tmp / "image-signatures.json", image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        bad_image_summary, bad_image_document = image_signatures(provenance_summary["provenance_digest"])
        bad_image_document["images"][0]["sigstore"]["bundle"]["messageSignature"]["messageDigest"]["digest"] = "0" * 64
        refresh_image_signature_bundle(bad_image_summary, bad_image_document)
        write(tmp / "image-signatures-summary.json", bad_image_summary)
        write(tmp / "image-signatures.json", bad_image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_image_bundle_digest = run_verifier(tmp)
        if rejected_image_bundle_digest.returncode == 0 or "image serverware Sigstore bundle digest mismatch" not in detail(rejected_image_bundle_digest):
            raise AssertionError(f"completion verifier accepted image signatures with a forged Sigstore bundle digest: {detail(rejected_image_bundle_digest)}")
        write(tmp / "image-signatures-summary.json", image_summary)
        write(tmp / "image-signatures.json", image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        bad_image_summary, bad_image_document = image_signatures(provenance_summary["provenance_digest"])
        bad_image_document["metadata"]["transparency"]["record"]["image_signature_bundle_digest"] = digest("0")
        write(tmp / "image-signatures-summary.json", bad_image_summary)
        write(tmp / "image-signatures.json", bad_image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_image_record = run_verifier(tmp)
        if rejected_image_record.returncode == 0 or "image signature bundle transparency record image_signature_bundle_digest mismatch" not in detail(rejected_image_record):
            raise AssertionError(f"completion verifier accepted image signatures with a swapped transparency record: {detail(rejected_image_record)}")
        write(tmp / "image-signatures-summary.json", image_summary)
        write(tmp / "image-signatures.json", image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        bad_image_summary, bad_image_document = image_signatures(provenance_summary["provenance_digest"])
        bad_image_document["metadata"]["transparency"]["inclusionProof"]["signed_tree_head"]["signature"] = "ed25519:test"
        bad_image_document["metadata"]["transparency"]["anchorResponse"]["anchors"][0]["signed_tree_head"] = bad_image_document["metadata"]["transparency"]["inclusionProof"]["signed_tree_head"]
        write(tmp / "image-signatures-summary.json", bad_image_summary)
        write(tmp / "image-signatures.json", bad_image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_image_sth = run_verifier(tmp)
        if rejected_image_sth.returncode == 0 or "image signature bundle signed tree head signature verification failed" not in detail(rejected_image_sth):
            raise AssertionError(f"completion verifier accepted image signatures with a forged signed tree head: {detail(rejected_image_sth)}")
        write(tmp / "image-signatures-summary.json", image_summary)
        write(tmp / "image-signatures.json", image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        mismatched_nitro = nitro_evidence(provenance_summary["provenance_digest"])
        mismatched_nitro["nitro"]["raw_attestation_document_sha256"] = digest("9")
        for release in mismatched_nitro["release_materials"]:
            release["kms_release"]["attestation_document_sha256"] = digest("9")
        write(tmp / "nitro-kms-evidence.json", mismatched_nitro)
        rejected_nitro = run_verifier(tmp)
        if rejected_nitro.returncode == 0 or "does not match live readiness attestation" not in detail(rejected_nitro):
            raise AssertionError(f"completion verifier accepted mismatched Nitro evidence: {detail(rejected_nitro)}")
        write(tmp / "nitro-kms-evidence.json", nitro)

        mismatched_command = nitro_evidence(provenance_summary["provenance_digest"])
        mismatched_command["config"]["kms_release_command_sha256"] = digest("9")
        write(tmp / "nitro-kms-evidence.json", mismatched_command)
        rejected_command = run_verifier(tmp)
        if rejected_command.returncode == 0 or "command hashes do not match live readiness" not in detail(rejected_command):
            raise AssertionError(f"completion verifier accepted mismatched Nitro/KMS commands: {detail(rejected_command)}")
        write(tmp / "nitro-kms-evidence.json", nitro)

        mismatched_request_digest = nitro_evidence(provenance_summary["provenance_digest"])
        mismatched_request_digest["release_materials"][0]["kms_release"]["request_digest"] = digest("9")
        write(tmp / "nitro-kms-evidence.json", mismatched_request_digest)
        rejected_request_digest = run_verifier(tmp)
        if rejected_request_digest.returncode == 0 or "KMS request digest mismatch" not in detail(rejected_request_digest):
            raise AssertionError(f"completion verifier accepted mismatched KMS request digest: {detail(rejected_request_digest)}")
        write(tmp / "nitro-kms-evidence.json", nitro)

        mismatched_recipient_handle = nitro_evidence(provenance_summary["provenance_digest"])
        mismatched_recipient_handle["release_materials"][0]["kms_release"]["material_handle"] = digest("9")
        write(tmp / "nitro-kms-evidence.json", mismatched_recipient_handle)
        rejected_recipient_handle = run_verifier(tmp)
        if rejected_recipient_handle.returncode == 0 or "material handle does not match recipient ciphertext digest" not in detail(rejected_recipient_handle):
            raise AssertionError(f"completion verifier accepted mismatched recipient ciphertext handle: {detail(rejected_recipient_handle)}")
        write(tmp / "nitro-kms-evidence.json", nitro)

        mismatched_recipient_attestation = nitro_evidence(provenance_summary["provenance_digest"])
        mismatched_recipient_attestation["release_materials"][0]["kms_release"]["attestation_document_sha256"] = digest("9")
        write(tmp / "nitro-kms-evidence.json", mismatched_recipient_attestation)
        rejected_recipient_attestation = run_verifier(tmp)
        if rejected_recipient_attestation.returncode == 0 or "KMS release attestation digest does not match Nitro evidence" not in detail(rejected_recipient_attestation):
            raise AssertionError(f"completion verifier accepted mismatched KMS Recipient attestation: {detail(rejected_recipient_attestation)}")
        write(tmp / "nitro-kms-evidence.json", nitro)

        mismatched_kms_preflight = production_host_preflight(tmp)
        mismatched_kms_preflight["checks"]["kms_materials"]["materials"][0]["key_id_sha256"] = digest("9")
        write(tmp / "production-host-preflight.json", mismatched_kms_preflight)
        rejected_kms = run_verifier(tmp)
        if rejected_kms.returncode == 0 or "KMS material bindings" not in detail(rejected_kms):
            raise AssertionError(f"completion verifier accepted mismatched KMS material bindings: {detail(rejected_kms)}")
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        mismatched_kms_ciphertext = production_host_preflight(tmp)
        mismatched_kms_ciphertext["checks"]["kms_materials"]["materials"][0]["ciphertext_blob_sha256"] = digest("9")
        write(tmp / "production-host-preflight.json", mismatched_kms_ciphertext)
        rejected_kms_ciphertext = run_verifier(tmp)
        if rejected_kms_ciphertext.returncode == 0 or "KMS material bindings" not in detail(rejected_kms_ciphertext):
            raise AssertionError(f"completion verifier accepted mismatched KMS ciphertext binding: {detail(rejected_kms_ciphertext)}")
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        stale_kms_preflight = production_host_preflight(tmp)
        write(tmp / "production-host-preflight.json", stale_kms_preflight)
        changed_materials = kms_materials_document()
        changed_materials["broker-kek"]["ciphertext_blob_b64"] = base64.b64encode(b"same-key-different-ciphertext").decode("ascii")
        write(tmp / "kms-materials.json", changed_materials)
        rejected_kms_file = run_verifier(tmp)
        if rejected_kms_file.returncode == 0 or "KMS materials digest does not match current KMS materials file" not in detail(rejected_kms_file):
            raise AssertionError(f"completion verifier accepted stale KMS materials file evidence: {detail(rejected_kms_file)}")
        write(tmp / "kms-materials.json", kms_materials_document())
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        forged_kms_preflight = production_host_preflight(tmp)
        changed_materials = kms_materials_document()
        changed_materials["broker-kek"]["ciphertext_blob_b64"] = base64.b64encode(b"same-key-forged-preflight-ciphertext").decode("ascii")
        write(tmp / "kms-materials.json", changed_materials)
        forged_kms_preflight["checks"]["kms_materials"]["file"] = file_summary(tmp / "kms-materials.json", "kms-materials")
        write(tmp / "production-host-preflight.json", forged_kms_preflight)
        rejected_forged_kms_preflight = run_verifier(tmp)
        if rejected_forged_kms_preflight.returncode == 0 or "KMS material bindings do not match current KMS materials file" not in detail(rejected_forged_kms_preflight):
            raise AssertionError(f"completion verifier accepted forged KMS preflight material bindings: {detail(rejected_forged_kms_preflight)}")
        write(tmp / "kms-materials.json", kms_materials_document())
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        malformed_kms_materials = kms_materials_document()
        malformed_kms_materials["broker-kek"]["ciphertext_blob_b64"] = "not-valid-@@@@"
        write(tmp / "kms-materials.json", malformed_kms_materials)
        malformed_kms_preflight = production_host_preflight(tmp)
        malformed_kms_preflight["checks"]["kms_materials"]["file"] = file_summary(tmp / "kms-materials.json", "kms-materials")
        write(tmp / "production-host-preflight.json", malformed_kms_preflight)
        rejected_malformed_kms = run_verifier(tmp)
        if rejected_malformed_kms.returncode == 0 or "ciphertext blob is invalid base64" not in detail(rejected_malformed_kms):
            raise AssertionError(f"completion verifier accepted malformed KMS ciphertext base64: {detail(rejected_malformed_kms)}")
        write(tmp / "kms-materials.json", kms_materials_document())
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        unauthorized_kms_materials = kms_materials_document()
        unauthorized_kms_materials["debug-material"] = {
            "key_id": "arn:aws:kms:us-east-1:111122223333:key/debug",
            "ciphertext_blob_b64": base64.b64encode(b"debug-ciphertext").decode("ascii"),
            "encryption_context": {"material": "debug-material", "service": "serverware"},
        }
        write(tmp / "kms-materials.json", unauthorized_kms_materials)
        unauthorized_kms_preflight = production_host_preflight(tmp)
        unauthorized_kms_preflight["checks"]["kms_materials"]["file"] = file_summary(tmp / "kms-materials.json", "kms-materials")
        write(tmp / "production-host-preflight.json", unauthorized_kms_preflight)
        rejected_unauthorized_kms = run_verifier(tmp)
        if rejected_unauthorized_kms.returncode == 0 or "unauthorized materials" not in detail(rejected_unauthorized_kms):
            raise AssertionError(f"completion verifier accepted unauthorized KMS materials: {detail(rejected_unauthorized_kms)}")
        write(tmp / "kms-materials.json", kms_materials_document())
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        slow_bench = benchmark_document(p99_ms=21.0)
        write(tmp / "decision-gate-rs-bench.json", slow_bench)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected = run_verifier(tmp)
        if rejected.returncode == 0 or "p99" not in detail(rejected):
            raise AssertionError(f"completion verifier accepted a slow benchmark: {detail(rejected)}")

        write(
            tmp / "decision-gate-rs-bench.json",
            benchmark_document(),
        )
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        stale_preflight_bench = benchmark_document(p99_ms=10.0)
        write(tmp / "decision-gate-rs-bench.json", stale_preflight_bench)
        rejected_stale = run_verifier(tmp)
        if rejected_stale.returncode == 0 or "preflight bench digest" not in detail(rejected_stale):
            raise AssertionError(f"completion verifier accepted stale preflight evidence: {detail(rejected_stale)}")
        write(
            tmp / "decision-gate-rs-bench.json",
            benchmark_document(),
        )
        skipped_config_preflight = production_host_preflight(tmp)
        skipped_config_preflight["checks"]["production_env"]["config_gate"]["skipped"] = True
        write(tmp / "production-host-preflight.json", skipped_config_preflight)
        rejected_skipped_config = run_verifier(tmp)
        if rejected_skipped_config.returncode == 0 or "skipped the config gate" not in detail(rejected_skipped_config):
            raise AssertionError(f"completion verifier accepted a skipped preflight config gate: {detail(rejected_skipped_config)}")

        mismatched_publish = production_images_published()
        mismatched_publish["images"][0]["local_image_id"] = digest("c")
        write(tmp / "production-images-published.json", mismatched_publish)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_publish = run_verifier(tmp)
        if rejected_publish.returncode == 0 or "published production images do not match current no-shell build" not in detail(rejected_publish):
            raise AssertionError(f"completion verifier accepted a publish manifest from another build: {detail(rejected_publish)}")

        write(tmp / "production-images-published.json", production_images_published())
        bad_image_summary, bad_image_document = image_signatures(provenance_summary["provenance_digest"])
        bad_image_summary["image_signing_key_id"] = digest("d")
        write(tmp / "image-signatures-summary.json", bad_image_summary)
        write(tmp / "image-signatures.json", bad_image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_signing_key = run_verifier(tmp)
        if rejected_signing_key.returncode == 0 or "image signing key does not match live Sigstore key" not in detail(rejected_signing_key):
            raise AssertionError(f"completion verifier accepted image signatures from another signing key: {detail(rejected_signing_key)}")

        bad_image_summary, bad_image_document = image_signatures(provenance_summary["provenance_digest"])
        bad_image_document["images"][0]["sigstore"]["transparency"]["log_id"] = digest("c")
        refresh_image_signature_bundle(bad_image_summary, bad_image_document)
        write(tmp / "image-signatures-summary.json", bad_image_summary)
        write(tmp / "image-signatures.json", bad_image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_rekor = run_verifier(tmp)
        if rejected_rekor.returncode == 0 or "transparency log does not match live Rekor log" not in detail(rejected_rekor):
            raise AssertionError(f"completion verifier accepted image signatures from another Rekor log: {detail(rejected_rekor)}")

        bad_image_summary, bad_image_document = image_signatures(provenance_summary["provenance_digest"])
        bad_image_document["images"][0]["statement"]["predicate"]["repo_digests"] = []
        refresh_image_statements_and_bundle(bad_image_summary, bad_image_document)
        write(tmp / "image-signatures-summary.json", bad_image_summary)
        write(tmp / "image-signatures.json", bad_image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_refs = run_verifier(tmp)
        if rejected_refs.returncode == 0 or "published production image refs" not in detail(rejected_refs):
            raise AssertionError(f"completion verifier accepted image signatures without published refs: {detail(rejected_refs)}")

        bad_image_summary, bad_image_document = image_signatures(provenance_summary["provenance_digest"])
        bad_image_document["images"][0]["sigstore"]["statement_digest"] = digest("0")
        refresh_image_signature_bundle(bad_image_summary, bad_image_document)
        write(tmp / "image-signatures-summary.json", bad_image_summary)
        write(tmp / "image-signatures.json", bad_image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_statement_digest = run_verifier(tmp)
        if rejected_statement_digest.returncode == 0 or "Sigstore statement digest mismatch" not in detail(rejected_statement_digest):
            raise AssertionError(f"completion verifier accepted a Sigstore proof for another statement: {detail(rejected_statement_digest)}")

        bad_image_summary, bad_image_document = image_signatures(provenance_summary["provenance_digest"])
        bad_image_document["images"][0]["sigstore"]["key_provider"]["key_id"] = digest("0")
        refresh_image_signature_bundle(bad_image_summary, bad_image_document)
        write(tmp / "image-signatures-summary.json", bad_image_summary)
        write(tmp / "image-signatures.json", bad_image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_sigstore_key = run_verifier(tmp)
        if rejected_sigstore_key.returncode == 0 or "Sigstore signing key mismatch" not in detail(rejected_sigstore_key):
            raise AssertionError(f"completion verifier accepted a per-image Sigstore proof from another key: {detail(rejected_sigstore_key)}")

        bad_image_summary, bad_image_document = image_signatures(provenance_summary["provenance_digest"])
        bad_image_document["images"][0]["signature"] = "sigstore:test:other"
        refresh_image_signature_bundle(bad_image_summary, bad_image_document)
        write(tmp / "image-signatures-summary.json", bad_image_summary)
        write(tmp / "image-signatures.json", bad_image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_sigstore_signature = run_verifier(tmp)
        if rejected_sigstore_signature.returncode == 0 or "Sigstore signature mismatch" not in detail(rejected_sigstore_signature):
            raise AssertionError(f"completion verifier accepted a mismatched per-image signature: {detail(rejected_sigstore_signature)}")

        bad_image_summary, bad_image_document = image_signatures(provenance_summary["provenance_digest"])
        bad_image_document["metadata"]["signature"] = "sigstore:test:other"
        write(tmp / "image-signatures-summary.json", bad_image_summary)
        write(tmp / "image-signatures.json", bad_image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_bundle_signature = run_verifier(tmp)
        if rejected_bundle_signature.returncode == 0 or "metadata signature mismatch" not in detail(rejected_bundle_signature):
            raise AssertionError(f"completion verifier accepted a mismatched bundle signature: {detail(rejected_bundle_signature)}")

        bad_image_summary, bad_image_document = image_signatures(provenance_summary["provenance_digest"])
        bad_image_document["bundle_signature"]["statement_digest"] = digest("0")
        bad_image_document["metadata"]["bundleSigstore"] = bad_image_document["bundle_signature"]
        write(tmp / "image-signatures-summary.json", bad_image_summary)
        write(tmp / "image-signatures.json", bad_image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_bundle_digest = run_verifier(tmp)
        if rejected_bundle_digest.returncode == 0 or "bundle Sigstore statement digest mismatch" not in detail(rejected_bundle_digest):
            raise AssertionError(f"completion verifier accepted a bundle Sigstore proof for another payload: {detail(rejected_bundle_digest)}")

        bad_image_summary, bad_image_document = image_signatures(provenance_summary["provenance_digest"])
        bad_image_document["images"][0]["statement"]["predicate"]["release_signing_key_id"] = digest("0")
        refresh_image_statements_and_bundle(bad_image_summary, bad_image_document)
        write(tmp / "image-signatures-summary.json", bad_image_summary)
        write(tmp / "image-signatures.json", bad_image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_release_key = run_verifier(tmp)
        if rejected_release_key.returncode == 0 or "statement release signing key mismatch" not in detail(rejected_release_key):
            raise AssertionError(f"completion verifier accepted image signatures from another release key: {detail(rejected_release_key)}")

        bad_image_summary, bad_image_document = image_signatures(provenance_summary["provenance_digest"])
        bad_image_document["images"][0]["statement"]["predicate"]["source_tree_digest"] = digest("0")
        refresh_image_statements_and_bundle(bad_image_summary, bad_image_document)
        write(tmp / "image-signatures-summary.json", bad_image_summary)
        write(tmp / "image-signatures.json", bad_image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_source = run_verifier(tmp)
        if rejected_source.returncode == 0 or "source tree digest mismatch" not in detail(rejected_source):
            raise AssertionError(f"completion verifier accepted image signatures with wrong source binding: {detail(rejected_source)}")

    print(canonical_json({"ok": True, "release_completion": "pass"}))


if __name__ == "__main__":
    main()
