#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_prefixed_json(value: Any) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def digest(char: str) -> str:
    return "sha256:" + char * 64


def nitro_evidence() -> dict[str, Any]:
    releases = []
    for material, key_char in (("broker-kek", "1"), ("decision-gate-ca", "2")):
        releases.append(
            {
                "ok": True,
                "provider": "aws-nitro-kms-policy",
                "material": material,
                "release_handle": digest("a"),
                "kms_command_required": True,
                "kms_release": {
                    "ok": True,
                    "provider": "aws-kms-recipient",
                    "material": material,
                    "request_digest": digest("b"),
                    "release_handle": digest("a"),
                    "material_handle": digest("c"),
                    "key_provider": {"type": "aws-kms", "key_id": f"arn:aws:kms:us-east-1:111122223333:key/{key_char}"},
                },
            }
        )
    return {
        "apiVersion": "serverware.nitroKmsEvidence/v1",
        "kind": "NitroKmsEvidence",
        "ok": True,
        "provider": "aws-nitro-enclaves",
        "tee_platform": "aws-nitro",
        "claims": {"sha256": digest("d"), "fields": {"materials": ["broker-kek", "decision-gate-ca"], "debug": False}},
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


def production_readiness(nitro: dict[str, Any]) -> dict[str, Any]:
    checks = [
        "no-dev-fixtures",
        "control-plane-auth",
        "nitro",
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
                "log_id": digest("5"),
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
                    "registry.example/serverware/control@sha256:" + "6" * 64,
                    "registry.example/serverware/decision-gate@sha256:" + "7" * 64,
                ],
            },
            "apparmor": {"ok": True},
        },
    }


def release_provenance() -> tuple[dict[str, Any], dict[str, Any]]:
    provenance = {
        "source_tree": {"digest": digest("8")},
        "anchor_chain": {"ok": True, "mode": "signed-merkle-transparency-log"},
    }
    provenance_digest = sha256_prefixed_json(provenance)
    document = {
        "provenance": provenance,
        "provenance_digest": provenance_digest,
        "signature": "ed25519:test",
        "release_signing_key_id": digest("9"),
        "release_signing_public_key_pem": "public",
        "transparency": {"inclusion_verified": True},
    }
    summary = {
        "ok": True,
        "release_provenance": "pass",
        "anchored": True,
        "inclusion_verified": True,
        "provenance_digest": provenance_digest,
        "release_signing_key_id": digest("9"),
        "transparency_mode": "signed-merkle-transparency-log",
    }
    return summary, document


def image_signatures(provenance_digest: str) -> tuple[dict[str, Any], dict[str, Any]]:
    payload = {
        "apiVersion": "serverware.imageSignatures/v1",
        "kind": "ImageSignatures",
        "metadata": {
            "provenanceDigest": provenance_digest,
            "signatureProvider": "sigstore-command",
            "sigstoreTransparencyRequired": True,
        },
        "images": [
            {
                "service": "serverware",
                "image_id": digest("6"),
                "statement_digest": digest("b"),
                "statement": {"predicate": {"provenance_digest": provenance_digest}},
                "sigstore": {
                    "ok": True,
                    "provider": "cosign",
                    "transparency": {"log_id": digest("c"), "inclusion_proof": {"treeSize": 1}},
                },
            },
            {
                "service": "decision-gate",
                "image_id": digest("7"),
                "statement_digest": digest("e"),
                "statement": {"predicate": {"provenance_digest": provenance_digest}},
                "sigstore": {
                    "ok": True,
                    "provider": "cosign",
                    "transparency": {"log_id": digest("f"), "inclusion_proof": {"treeSize": 1}},
                },
            }
        ],
    }
    bundle_digest = sha256_prefixed_json(payload)
    document = dict(payload)
    document["image_signature_bundle_digest"] = bundle_digest
    document["bundle_signature"] = {"ok": True}
    summary = {
        "ok": True,
        "image_signatures": "pass",
        "image_signature_provider": "sigstore-command",
        "inclusion_verified": True,
        "provenance_digest": provenance_digest,
        "image_signature_bundle_digest": bundle_digest,
        "image_signing_key_id": digest("d"),
        "images": 2,
    }
    return summary, document


def write(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def run_verifier(tmp: Path, *extra: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            sys.executable,
            "scripts/verify_release_completion.py",
            "--production-readiness",
            str(tmp / "production-readiness.json"),
            "--nitro-evidence",
            str(tmp / "nitro-kms-evidence.json"),
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
            *extra,
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def detail(result: subprocess.CompletedProcess[bytes]) -> str:
    return result.stdout.decode("utf-8", errors="replace") + result.stderr.decode("utf-8", errors="replace")


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        nitro = nitro_evidence()
        provenance_summary, provenance_document = release_provenance()
        image_summary, image_document = image_signatures(provenance_summary["provenance_digest"])
        write(tmp / "production-readiness.json", production_readiness(nitro))
        write(tmp / "nitro-kms-evidence.json", nitro)
        write(tmp / "release-provenance-summary.json", provenance_summary)
        write(tmp / "release-provenance.json", provenance_document)
        write(tmp / "image-signatures-summary.json", image_summary)
        write(tmp / "image-signatures.json", image_document)
        write(
            tmp / "decision-gate-rs-bench.json",
            {"candidate": "rust-decision-gate", "requests": 1000, "p50_ms": 1.0, "p95_ms": 5.0, "p99_ms": 9.0},
        )
        out_path = tmp / "completion-proof.json"
        result = run_verifier(tmp, "--out", str(out_path))
        if result.returncode != 0:
            raise AssertionError(f"completion verifier failed: {detail(result)}")
        proof = json.loads(result.stdout.decode("utf-8"))
        if proof.get("ok") is not True or not out_path.exists() or not proof.get("proof_sha256", "").startswith("sha256:"):
            raise AssertionError(f"completion verifier did not write a valid proof: {proof}")

        slow_bench = {"candidate": "rust-decision-gate", "requests": 1000, "p99_ms": 21.0}
        write(tmp / "decision-gate-rs-bench.json", slow_bench)
        rejected = run_verifier(tmp)
        if rejected.returncode == 0 or "p99" not in detail(rejected):
            raise AssertionError(f"completion verifier accepted a slow benchmark: {detail(rejected)}")

    print(canonical_json({"ok": True, "release_completion": "pass"}))


if __name__ == "__main__":
    main()
