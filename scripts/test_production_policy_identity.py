#!/usr/bin/env python3
from __future__ import annotations

import base64
import copy
import hashlib
import importlib
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))

verifier = importlib.import_module("verify_production_policy_identity")

from serverware.policy_bundle import canonical_json, demo_policy_bundle, signature_payload  # noqa: E402


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


class ProductionPolicyIdentityVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now_ms = 1_800_000_000_000
        self.private_key = Ed25519PrivateKey.from_private_bytes(b"\x1d" * 32)
        public_key = self.private_key.public_key()
        self.public_key_pem = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        public_key_der = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.public_key_hash = sha256(public_key_der)

    def principal(
        self,
        *,
        principal_id: str = "agent:payments",
        token_id: str = "payments-agent-01",
        token: bytes = b"test-only-high-entropy-bearer-material-01",
        source_cidrs: list[str] | None = None,
        expiry: Any = None,
    ) -> dict[str, Any]:
        if source_cidrs is None:
            source_cidrs = ["10.42.7.19/32"]
        if expiry is None:
            expiry = self.now_ms + 60 * 60 * 1000
        return {
            "id": principal_id,
            "proxyAuthorization": {
                "scheme": "Bearer",
                "tokenId": token_id,
                "tokenSha256": sha256(token),
                "sourceCidrs": source_cidrs,
                "expiresAtEpochMs": expiry,
            },
        }

    def bundle(self, principals: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        bundle = demo_policy_bundle()
        bundle["metadata"] = {
            "id": "serverware-production",
            "sequence": 17,
            "rollbackEpoch": 4,
            "signingKeyId": self.public_key_hash,
        }
        bundle["principals"] = principals or [self.principal()]
        bundle["routes"] = [copy.deepcopy(bundle["routes"][0])]
        bundle["routes"][0]["principals"] = [principal["id"] for principal in bundle["principals"]]
        return self.sign(bundle)

    def sign(self, bundle: dict[str, Any]) -> dict[str, Any]:
        signed = copy.deepcopy(bundle)
        signed.setdefault("metadata", {})["signingKeyId"] = signed.get("metadata", {}).get(
            "signingKeyId", self.public_key_hash
        )
        signed["metadata"].pop("signature", None)
        payload = canonical_json(signature_payload(signed)).encode("utf-8")
        signed["metadata"]["signature"] = "ed25519:" + b64e(self.private_key.sign(payload))
        return signed

    def verify(self, bundle: dict[str, Any]) -> dict[str, Any]:
        return verifier.verify_production_policy_identity(
            bundle,
            self.public_key_pem,
            trusted_public_key_hash=self.public_key_hash,
            now_epoch_ms=self.now_ms,
        )

    def assert_rejected(self, bundle: dict[str, Any], code: str) -> dict[str, Any]:
        result = self.verify(bundle)
        self.assertFalse(result["ok"], result)
        self.assertIn(code, {item["code"] for item in result["issues"]}, result)
        self.assertEqual(result["identity"]["status"], "rejected")
        self.assertFalse(result["identity"]["nonSpoofable"])
        return result

    def mutate_and_sign(self, mutation: Any) -> dict[str, Any]:
        bundle = self.bundle()
        bundle["metadata"].pop("signature")
        mutation(bundle)
        return self.sign(bundle)

    def test_accepts_valid_bounded_bearer_as_interim_control(self) -> None:
        result = self.verify(self.bundle())

        self.assertTrue(result["ok"], result)
        self.assertEqual(result["identity"]["status"], "accepted_interim_control")
        self.assertEqual(result["identity"]["control"], "bounded_bearer_interim")
        self.assertTrue(result["identity"]["interim"])
        self.assertFalse(result["identity"]["nonSpoofable"])
        self.assertIn("mTLS/SPIFFE workload identity is not implemented", " ".join(result["identity"]["limitations"]))
        self.assertEqual(result["identity"]["principalCount"], 1)

    def test_rejects_header_only_principal(self) -> None:
        bundle = self.bundle([{"id": "agent:header", "requiredHeaders": {"X-Agent-Identity": "header-value-123"}}])
        self.assert_rejected(bundle, "header_only_principal")

    def test_rejects_cidr_only_principal(self) -> None:
        bundle = self.bundle([{"id": "agent:cidr", "sourceCidrs": ["10.42.7.19/32"]}])
        self.assert_rejected(bundle, "cidr_only_principal")

    def test_rejects_ambiguous_multiple_weak_selectors(self) -> None:
        bundle = self.bundle(
            [
                {
                    "id": "agent:weak-combination",
                    "sourceCidrs": ["10.42.7.19/32"],
                    "requiredHeaders": {"X-Agent-Identity": "header-value-123"},
                }
            ]
        )
        self.assert_rejected(bundle, "ambiguous_multiple_weak_selectors")

    def test_rejects_legacy_exact_proxy_secret_without_disclosing_it(self) -> None:
        secret = "Bearer production-secret-that-must-not-appear"
        bundle = self.bundle([{"id": "agent:legacy", "proxyAuthorization": secret}])
        result = self.assert_rejected(bundle, "legacy_exact_proxy_secret")
        self.assertNotIn(secret, json.dumps(result, sort_keys=True))

    def test_rejects_universal_source_cidr_at_principal_or_bearer_scope(self) -> None:
        for scope in ("principal", "bearer"):
            with self.subTest(scope=scope):
                principal = self.principal()
                if scope == "principal":
                    principal["sourceCidrs"] = ["0.0.0.0/0"]
                else:
                    principal["proxyAuthorization"]["sourceCidrs"] = ["::/0"]
                self.assert_rejected(self.bundle([principal]), "universal_source_cidr")

    def test_rejects_absent_expired_and_overlong_bearer_expiry(self) -> None:
        cases = {
            "bearer_expiry_missing": lambda principal: principal["proxyAuthorization"].pop("expiresAtEpochMs"),
            "bearer_expired": lambda principal: principal["proxyAuthorization"].__setitem__(
                "expiresAtEpochMs", self.now_ms
            ),
            "bearer_expiry_overlong": lambda principal: principal["proxyAuthorization"].__setitem__(
                "expiresAtEpochMs", self.now_ms + verifier.MAX_BEARER_TTL_MS + 1
            ),
        }
        for code, mutation in cases.items():
            with self.subTest(code=code):
                principal = self.principal()
                mutation(principal)
                self.assert_rejected(self.bundle([principal]), code)

    def test_rejects_missing_bearer_source_binding(self) -> None:
        principal = self.principal()
        principal["proxyAuthorization"].pop("sourceCidrs")
        self.assert_rejected(self.bundle([principal]), "bearer_source_binding_missing")

    def test_rejects_weak_bearer_digest(self) -> None:
        principal = self.principal(token=b"password")
        self.assert_rejected(self.bundle([principal]), "weak_bearer_digest")

    def test_rejects_reused_bearer_digest_across_principals(self) -> None:
        first = self.principal()
        second = self.principal(
            principal_id="agent:billing",
            token_id="billing-agent-01",
            source_cidrs=["10.42.7.20/32"],
        )
        self.assert_rejected(self.bundle([first, second]), "reused_bearer_digest")

    def test_rejects_duplicate_token_id_across_principals(self) -> None:
        first = self.principal()
        second = self.principal(
            principal_id="agent:billing",
            token_id="payments-agent-01",
            token=b"test-only-high-entropy-bearer-material-02",
            source_cidrs=["10.42.7.20/32"],
        )
        self.assert_rejected(self.bundle([first, second]), "duplicate_token_id")

    def test_rejects_duplicate_source_and_header_bindings(self) -> None:
        duplicate_source = self.principal(source_cidrs=["10.42.7.19/32", "10.42.7.19/32"])
        self.assert_rejected(self.bundle([duplicate_source]), "duplicate_source_binding")

        duplicate_header = self.principal()
        duplicate_header["requiredHeaders"] = {
            "X-Agent-Identity": "identity-value-one",
            "x-agent-identity": "identity-value-two",
        }
        self.assert_rejected(self.bundle([duplicate_header]), "duplicate_header_binding")

    def test_rejects_reused_weak_binding(self) -> None:
        first = {"id": "agent:one", "requiredHeaders": {"X-Agent-Identity": "shared-value-123"}}
        second = {"id": "agent:two", "requiredHeaders": {"X-Agent-Identity": "shared-value-123"}}
        self.assert_rejected(self.bundle([first, second]), "reused_weak_binding")

    def test_rejects_malformed_expiry_and_token_digest(self) -> None:
        malformed_expiry = self.principal(expiry="tomorrow")
        self.assert_rejected(self.bundle([malformed_expiry]), "malformed_bearer_expiry")

        malformed_digest = self.principal()
        malformed_digest["proxyAuthorization"]["tokenSha256"] = "sha256:not-a-digest"
        self.assert_rejected(self.bundle([malformed_digest]), "malformed_bearer_digest")

    def test_rejects_malformed_signing_key_digest(self) -> None:
        bundle = self.bundle()
        bundle["metadata"].pop("signature")
        bundle["metadata"]["signingKeyId"] = "sha256:bad"
        self.assert_rejected(self.sign(bundle), "malformed_signing_key_digest")

    def test_rejects_tampered_signature_and_wrong_trust_root(self) -> None:
        tampered = self.bundle()
        tampered["metadata"]["sequence"] += 1
        self.assert_rejected(tampered, "signature_verification_failed")

        other_key = Ed25519PrivateKey.from_private_bytes(b"\x2a" * 32).public_key()
        other_pem = other_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        result = verifier.verify_production_policy_identity(
            self.bundle(),
            other_pem,
            trusted_public_key_hash=verifier.spki_hash_from_public_key_pem(other_pem),
            now_epoch_ms=self.now_ms,
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["issues"][0]["code"], "untrusted_signing_key")

    def test_strict_json_loader_rejects_duplicate_keys_and_non_finite_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bundle.json"
            path.write_text('{"apiVersion":"one","apiVersion":"two"}', encoding="utf-8")
            with self.assertRaises(verifier.VerificationError) as duplicate:
                verifier.load_policy_bundle(path)
            self.assertEqual(duplicate.exception.code, "duplicate_json_key")

            path.write_text('{"expiresAtEpochMs":NaN}', encoding="utf-8")
            with self.assertRaises(verifier.VerificationError) as non_finite:
                verifier.load_policy_bundle(path)
            self.assertEqual(non_finite.exception.code, "invalid_json")

    def test_cli_output_is_machine_readable_redacted_and_identity_scoped(self) -> None:
        secret = "Bearer cli-secret-that-must-not-appear"
        bundle = self.bundle([{"id": "agent:legacy", "proxyAuthorization": secret}])
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            bundle_path = temp / "policy.json"
            key_path = temp / "policy-signing-public.pem"
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
            key_path.write_text(self.public_key_pem, encoding="ascii")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS / "verify_production_policy_identity.py"),
                    "--bundle",
                    str(bundle_path),
                    "--trusted-public-key",
                    str(key_path),
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

        self.assertEqual(completed.returncode, 1, completed)
        self.assertEqual(completed.stderr, "")
        output = json.loads(completed.stdout)
        self.assertEqual(
            set(output),
            {
                "apiVersion",
                "kind",
                "mode",
                "ok",
                "outputScope",
                "secretsRedacted",
                "policy",
                "identity",
                "issues",
                "artifactBindings",
            },
        )
        self.assertEqual(output["outputScope"], "policy_identity_metadata_only")
        self.assertTrue(output["secretsRedacted"])
        serialized = json.dumps(output, sort_keys=True)
        self.assertNotIn(secret, serialized)
        for forbidden in ('"credentials":', '"routes":'):
            self.assertNotIn(forbidden, serialized)

    def test_persisted_report_is_bound_to_exact_bundle_and_trust_root(self) -> None:
        self.now_ms = int(time.time() * 1000)
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            bundle_path = temp / "policy.json"
            key_path = temp / "policy.pub.pem"
            report_path = temp / "identity.json"
            bundle = self.bundle()
            bundle_path.write_text(json.dumps(bundle, sort_keys=True) + "\n", encoding="utf-8")
            key_path.write_text(self.public_key_pem, encoding="ascii")
            result = self.verify(bundle)
            verifier.write_private(
                report_path,
                verifier.persisted_report(
                    result,
                    bundle_path=bundle_path,
                    trusted_public_key_path=key_path,
                    trusted_public_key_hash=self.public_key_hash,
                ),
            )
            summary = verifier.verify_persisted_report(
                bundle_path=bundle_path,
                trusted_public_key_path=key_path,
                report_path=report_path,
            )
            self.assertEqual(summary["policyHash"], result["policy"]["hash"])
            bundle_path.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(verifier.VerificationError, "does not match"):
                verifier.verify_persisted_report(
                    bundle_path=bundle_path,
                    trusted_public_key_path=key_path,
                    report_path=report_path,
                )

    def test_success_output_scope_omits_identity_selectors_and_secrets(self) -> None:
        result = self.verify(self.bundle())
        self.assertTrue(result["ok"], result)
        self.assertEqual(
            set(result["identity"]["principals"][0]),
            {"id", "identityControl", "expiresAtEpochMs"},
        )
        serialized = json.dumps(result, sort_keys=True)
        for forbidden in (
            "test-only-high-entropy-bearer-material-01",
            "tokenSha256",
            "tokenId",
            "sourceCidrs",
            "requiredHeaders",
            "credentials",
            "routes",
        ):
            self.assertNotIn(forbidden, serialized)


if __name__ == "__main__":
    unittest.main(verbosity=2)
