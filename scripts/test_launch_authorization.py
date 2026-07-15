#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import unittest
from copy import deepcopy
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from jsonschema import Draft202012Validator

import launch_authorization as protocol


ROOT = Path(__file__).resolve().parents[1]
NOW = 1_800_000_000


def digest(character: str) -> str:
    return "sha256:" + character * 64


def request_fixture() -> dict[str, Any]:
    return {
        "apiVersion": protocol.REQUEST_API_VERSION,
        "kind": protocol.REQUEST_KIND,
        "launcherNonce": "0" * 64,
        "bootIdSha256": digest("1"),
        "launcherSha256": digest("2"),
        "manifestSha256": digest("3"),
        "releaseProvenanceSha256": digest("4"),
        "provenanceDigest": digest("5"),
        "reproducibleBuildVerificationSha256": digest("6"),
        "sourceTreeDigest": digest("7"),
        "deploymentAudience": "prod:us-east-1.host_01",
        "deploymentIdentitySha256": digest("8"),
        "releaseSequence": 41,
        "rollbackEpoch": 0,
    }


def public_spki(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def schema(name: str) -> dict[str, Any]:
    return json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))


class LaunchAuthorizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        cls.other_private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        cls.spki = public_spki(cls.private_key)
        cls.other_spki = public_spki(cls.other_private_key)
        cls.key_id = protocol.spki_key_id(cls.spki)

    def authorization(
        self,
        *,
        request: dict[str, Any] | None = None,
        private_key: Ed25519PrivateKey | None = None,
        issued_at: int = NOW,
        expires_at: int = NOW + 30,
    ) -> dict[str, Any]:
        return protocol.sign_launch_authorization(
            request or request_fixture(),
            private_key=private_key or self.private_key,
            authorization_id="a" * 64,
            issued_at_unix_seconds=issued_at,
            expires_at_unix_seconds=expires_at,
        )

    def resign(
        self,
        document: dict[str, Any],
        *,
        private_key: Ed25519PrivateKey | None = None,
        domain: bytes = protocol.AUTHORIZATION_DOMAIN,
    ) -> dict[str, Any]:
        copied = deepcopy(document)
        unsigned = {
            "apiVersion": copied["apiVersion"],
            "kind": copied["kind"],
            "statement": copied["statement"],
        }
        copied["signature"] = protocol.canonical_base64url(
            (private_key or self.private_key).sign(
                domain + protocol.canonical_json_bytes(unsigned)
            )
        )
        return copied

    def verify(
        self,
        document: dict[str, Any],
        *,
        spki: bytes | None = None,
        expected_request_sha256: str | None = None,
        expected_authority_key_id: str | None = None,
        now: int = NOW,
    ) -> protocol.VerifiedLaunchAuthorization:
        return protocol.verify_launch_authorization(
            protocol.canonical_json_bytes(document),
            authority_public_key_spki_der=spki or self.spki,
            expected_request_sha256=(
                expected_request_sha256
                if expected_request_sha256 is not None
                else protocol.launch_authorization_request_sha256(request_fixture())
            ),
            expected_authority_key_id=(
                expected_authority_key_id
                if expected_authority_key_id is not None
                else protocol.spki_key_id(spki or self.spki)
            ),
            now_unix_seconds=now,
        )

    def test_valid_request_signing_and_verification(self) -> None:
        request = request_fixture()
        expected_request_digest = "sha256:" + hashlib.sha256(
            protocol.REQUEST_API_VERSION.encode("ascii")
            + b"\0"
            + protocol.canonical_json_bytes(request)
        ).hexdigest()
        self.assertEqual(
            protocol.launch_authorization_request_sha256(request),
            expected_request_digest,
        )
        document = self.authorization(request=request)
        verified = self.verify(
            document,
            expected_request_sha256=expected_request_digest,
        )
        self.assertEqual(verified.authorization_id, "a" * 64)
        self.assertEqual(verified.authority_key_id, self.key_id)
        self.assertEqual(verified.request_sha256, expected_request_digest)
        self.assertEqual(verified.issued_at_unix_seconds, NOW)
        self.assertEqual(verified.expires_at_unix_seconds, NOW + 30)
        self.assertEqual(verified.use_limit, 1)

        signature = base64.urlsafe_b64decode(document["signature"] + "==")
        self.private_key.public_key().verify(
            signature,
            protocol.AUTHORIZATION_API_VERSION.encode("ascii")
            + b"\0"
            + protocol.canonical_json_bytes(
                {
                    "apiVersion": document["apiVersion"],
                    "kind": document["kind"],
                    "statement": document["statement"],
                }
            ),
        )

    def test_schemas_are_valid_closed_and_accept_valid_documents(self) -> None:
        fixtures = (
            ("launch-authorization-request.v1.schema.json", request_fixture()),
            ("launch-authorization.v1.schema.json", self.authorization()),
        )
        for name, document in fixtures:
            loaded = schema(name)
            Draft202012Validator.check_schema(loaded)
            validator = Draft202012Validator(loaded)
            validator.validate(document)

            hostile = deepcopy(document)
            hostile["unknown"] = True
            with self.subTest(schema=name, boundary="top-level"), self.assertRaises(Exception):
                validator.validate(hostile)

            object_schemas: list[dict[str, Any]] = []

            def collect(value: Any) -> None:
                if isinstance(value, dict):
                    if value.get("type") == "object":
                        object_schemas.append(value)
                    for item in value.values():
                        collect(item)
                elif isinstance(value, list):
                    for item in value:
                        collect(item)

            collect(loaded)
            self.assertTrue(object_schemas, name)
            self.assertTrue(
                all(item.get("additionalProperties") is False for item in object_schemas),
                name,
            )

        envelope_validator = Draft202012Validator(
            schema("launch-authorization.v1.schema.json")
        )
        nested = self.authorization()
        nested["statement"]["unknown"] = True
        with self.assertRaises(Exception):
            envelope_validator.validate(nested)

    def test_strict_parser_rejects_malformed_duplicate_and_non_integer_json(self) -> None:
        invalid = (
            b"",
            b"[]",
            b"{} trailing",
            b"\xef\xbb\xbf{}",
            b'{"x":"\xff"}',
            b'{"x":1.0}',
            b'{"x":1e3}',
            b'{"x":NaN}',
            b'{"x":9007199254740992}',
            b'{"x":1,"x":2}',
            b'{"statement":{"x":1,"x":2}}',
        )
        for raw in invalid:
            with self.subTest(raw=raw), self.assertRaises(protocol.LaunchAuthorizationError):
                protocol.parse_strict_json_object(raw)
        with self.assertRaises(protocol.LaunchAuthorizationError):
            protocol.parse_strict_json_object(bytearray(b"{}"))  # type: ignore[arg-type]
        with self.assertRaises(protocol.LaunchAuthorizationError):
            protocol.canonical_json_bytes({"x": 1.0})
        with self.assertRaises(protocol.LaunchAuthorizationError):
            protocol.canonical_json_bytes({"x": protocol.MAX_SAFE_INTEGER + 1})

    def test_canonical_byte_helper_and_verifier_reject_noncanonical_bytes(self) -> None:
        document = self.authorization()
        canonical = protocol.canonical_json_bytes(document)
        self.assertEqual(protocol.require_canonical_json_bytes(canonical), document)

        variants = (
            json.dumps(document, indent=2, sort_keys=True).encode("ascii"),
            canonical + b"\n",
            json.dumps(document, separators=(",", ":"), sort_keys=False).encode("ascii"),
        )
        for raw in variants:
            with self.subTest(raw=raw[:40]), self.assertRaises(
                protocol.LaunchAuthorizationError
            ):
                protocol.require_canonical_json_bytes(raw)
            with self.assertRaises(protocol.LaunchAuthorizationError):
                protocol.verify_launch_authorization(
                    raw,
                    authority_public_key_spki_der=self.spki,
                    expected_request_sha256=protocol.launch_authorization_request_sha256(
                        request_fixture()
                    ),
                    expected_authority_key_id=self.key_id,
                    now_unix_seconds=NOW,
                )

    def test_request_contract_rejects_malformed_unknown_and_unsafe_values(self) -> None:
        cases: list[dict[str, Any]] = []

        def changed(field: str, value: Any) -> dict[str, Any]:
            candidate = request_fixture()
            candidate[field] = value
            return candidate

        unknown = request_fixture()
        unknown["unknown"] = True
        cases.append(unknown)
        non_string_key = request_fixture()
        non_string_key[1] = True  # type: ignore[index]
        cases.append(non_string_key)
        missing = request_fixture()
        missing.pop("manifestSha256")
        cases.append(missing)
        cases.extend(
            (
                changed("apiVersion", protocol.REQUEST_API_VERSION + "x"),
                changed("kind", protocol.REQUEST_KIND + "x"),
                changed("launcherNonce", "A" * 64),
                changed("launcherNonce", "0" * 63),
                changed("bootIdSha256", "1" * 64),
                changed("launcherSha256", "sha256:" + "A" * 64),
                changed("deploymentAudience", ""),
                changed("deploymentAudience", "Prod"),
                changed("deploymentAudience", "prod/us"),
                changed("deploymentAudience", "prod-\N{SNOWMAN}"),
                changed("deploymentAudience", "a" * 129),
                changed("releaseSequence", 0),
                changed("releaseSequence", True),
                changed("releaseSequence", protocol.MAX_SAFE_INTEGER + 1),
                changed("rollbackEpoch", -1),
                changed("rollbackEpoch", False),
            )
        )
        for candidate in cases:
            with self.subTest(candidate=candidate), self.assertRaises(
                protocol.LaunchAuthorizationError
            ):
                protocol.validate_launch_authorization_request(candidate)

    def test_every_request_field_is_covered_by_the_request_digest(self) -> None:
        original = request_fixture()
        expected = protocol.launch_authorization_request_sha256(original)
        mutations: dict[str, Any] = {
            "launcherNonce": "f" * 64,
            "bootIdSha256": digest("9"),
            "launcherSha256": digest("a"),
            "manifestSha256": digest("b"),
            "releaseProvenanceSha256": digest("c"),
            "provenanceDigest": digest("d"),
            "reproducibleBuildVerificationSha256": digest("e"),
            "sourceTreeDigest": digest("f"),
            "deploymentAudience": "prod:us-west-2.host_02",
            "deploymentIdentitySha256": digest("0"),
            "releaseSequence": 42,
            "rollbackEpoch": 1,
        }
        for field, value in mutations.items():
            candidate = deepcopy(original)
            candidate[field] = value
            with self.subTest(field=field):
                self.assertNotEqual(
                    protocol.launch_authorization_request_sha256(candidate), expected
                )

    def test_envelope_and_statement_contracts_are_exact(self) -> None:
        valid = self.authorization()
        cases: list[dict[str, Any]] = []

        unknown = deepcopy(valid)
        unknown["unknown"] = True
        cases.append(unknown)
        nested_unknown = deepcopy(valid)
        nested_unknown["statement"]["unknown"] = True
        cases.append(nested_unknown)
        missing = deepcopy(valid)
        missing["statement"].pop("requestSha256")
        cases.append(missing)

        def changed(path: str, value: Any) -> dict[str, Any]:
            candidate = deepcopy(valid)
            if path in {"apiVersion", "kind", "signature"}:
                candidate[path] = value
            else:
                candidate["statement"][path] = value
            return candidate

        cases.extend(
            (
                changed("apiVersion", protocol.AUTHORIZATION_API_VERSION + "x"),
                changed("kind", protocol.AUTHORIZATION_KIND + "x"),
                changed("authorizationId", "A" * 64),
                changed("authorityKeyId", "f" * 64),
                changed("requestSha256", "sha256:" + "F" * 64),
                changed("issuedAtUnixSeconds", 0),
                changed("issuedAtUnixSeconds", True),
                changed("expiresAtUnixSeconds", protocol.MAX_SAFE_INTEGER + 1),
                changed("useLimit", 2),
                changed("useLimit", True),
            )
        )
        for candidate in cases:
            with self.subTest(candidate=candidate), self.assertRaises(
                protocol.LaunchAuthorizationError
            ):
                protocol.validate_launch_authorization(candidate)

    def test_signature_must_be_canonical_unpadded_base64url_for_64_bytes(self) -> None:
        valid = self.authorization()
        signatures = (
            valid["signature"] + "=",
            "ed25519:" + valid["signature"],
            "A" * 85,
            "A" * 85 + "B",
            "!" + valid["signature"][1:],
        )
        for signature in signatures:
            candidate = deepcopy(valid)
            candidate["signature"] = signature
            with self.subTest(signature=signature), self.assertRaises(
                protocol.LaunchAuthorizationError
            ):
                protocol.validate_launch_authorization(candidate)

    def test_wrong_signature_key_and_domain_are_rejected(self) -> None:
        valid = self.authorization()
        corrupted = deepcopy(valid)
        signature = base64.urlsafe_b64decode(corrupted["signature"] + "==")
        corrupted["signature"] = protocol.canonical_base64url(
            bytes([signature[0] ^ 1]) + signature[1:]
        )
        with self.assertRaisesRegex(protocol.LaunchAuthorizationError, "signature"):
            self.verify(corrupted)

        for domain in (b"", b"serverware.wrongLaunchAuthorization/v1\0"):
            wrong_domain = self.resign(valid, domain=domain)
            with self.subTest(domain=domain), self.assertRaisesRegex(
                protocol.LaunchAuthorizationError, "signature"
            ):
                self.verify(wrong_domain)

        with self.assertRaisesRegex(protocol.LaunchAuthorizationError, "signature"):
            self.verify(
                valid,
                spki=self.other_spki,
                expected_authority_key_id=protocol.spki_key_id(self.other_spki),
            )

    def test_validity_future_skew_and_expiry_boundaries(self) -> None:
        self.verify(self.authorization(issued_at=NOW + 5, expires_at=NOW + 30))
        with self.assertRaisesRegex(protocol.LaunchAuthorizationError, "future skew"):
            self.verify(self.authorization(issued_at=NOW + 6, expires_at=NOW + 30))
        with self.assertRaisesRegex(protocol.LaunchAuthorizationError, "expired"):
            self.verify(self.authorization(issued_at=NOW - 30, expires_at=NOW))
        with self.assertRaisesRegex(protocol.LaunchAuthorizationError, "30 seconds"):
            self.authorization(issued_at=NOW, expires_at=NOW + 31)
        with self.assertRaisesRegex(protocol.LaunchAuthorizationError, "after issuance"):
            self.authorization(issued_at=NOW, expires_at=NOW)

    def test_use_limit_is_exactly_one_even_when_resigned(self) -> None:
        candidate = self.authorization()
        candidate["statement"]["useLimit"] = 2
        candidate = self.resign(candidate)
        with self.assertRaisesRegex(protocol.LaunchAuthorizationError, "useLimit"):
            self.verify(candidate)

    def test_expected_request_and_authority_bindings_are_required(self) -> None:
        valid = self.authorization()
        with self.assertRaisesRegex(protocol.LaunchAuthorizationError, "request digest"):
            self.verify(valid, expected_request_sha256=digest("f"))
        with self.assertRaisesRegex(protocol.LaunchAuthorizationError, "trusted authority"):
            self.verify(valid, expected_authority_key_id=digest("f"))

        wrong_request = deepcopy(valid)
        wrong_request["statement"]["requestSha256"] = digest("f")
        wrong_request = self.resign(wrong_request)
        with self.assertRaisesRegex(protocol.LaunchAuthorizationError, "request digest"):
            self.verify(wrong_request)

        wrong_authority = deepcopy(valid)
        wrong_authority["statement"]["authorityKeyId"] = digest("f")
        wrong_authority = self.resign(wrong_authority)
        with self.assertRaisesRegex(protocol.LaunchAuthorizationError, "authority key ID"):
            self.verify(wrong_authority)

    def test_spki_key_id_uses_canonical_der_and_requires_ed25519(self) -> None:
        self.assertEqual(
            self.key_id,
            "sha256:" + hashlib.sha256(self.spki).hexdigest(),
        )
        pem = self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        x25519_der = X25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        for value in (pem, x25519_der, bytearray(self.spki)):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(
                protocol.LaunchAuthorizationError
            ):
                protocol.spki_key_id(value)  # type: ignore[arg-type]

    def test_authorization_for_a_different_valid_request_cannot_be_rebound(self) -> None:
        original = request_fixture()
        changed = request_fixture()
        changed["manifestSha256"] = digest("f")
        authorization = self.authorization(request=changed)
        with self.assertRaisesRegex(protocol.LaunchAuthorizationError, "request digest"):
            self.verify(
                authorization,
                expected_request_sha256=protocol.launch_authorization_request_sha256(
                    original
                ),
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
