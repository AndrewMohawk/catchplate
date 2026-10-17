#!/usr/bin/env python3
from __future__ import annotations

import ast
import json
import tempfile
import sys
import unittest
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from catchplate.setup_receipts import (  # noqa: E402
    COMPLETION_IDENTITY_API_VERSION,
    ENROLLMENT_CHECKS,
    ENROLLMENT_RECEIPT_API_VERSION,
    HARDWARE_CHECKS,
    HARDWARE_VERIFICATION_API_VERSION,
    Ed25519TrustRoot,
    EnrollmentReceiptExpected,
    FinalChallengeTrust,
    FixedClock,
    HardwareVerificationExpected,
    JsonLimits,
    ReceiptBindingError,
    ReceiptContractError,
    ReceiptErrorCode,
    ReceiptParseError,
    ReceiptSignatureError,
    ReceiptTimeError,
    ReceiptTrustError,
    ReceiptVerificationError,
    SetupAssignment,
    canonical_base64url,
    canonical_json_bytes,
    derive_setup_completion_identity,
    parse_strict_json_object,
    sha256_digest,
    spki_key_id,
    verify_enrollment_verifier_receipt,
    verify_final_challenge_receipt,
    verify_setup_hardware_verification,
)
from catchplate.setup_receipt_service import (  # noqa: E402
    SetupReceiptTrustConfigurationError,
    _trusted_root,
    build_setup_receipt_trust_profile,
)


NOW = 2_000_000_000
SETUP_ID = "11111111-1111-4111-8111-111111111111"
ENROLLMENT_RECEIPT_ID = "22222222-2222-4222-8222-222222222222"
ENROLLMENT_SESSION_ID = "33333333-3333-4333-8333-333333333333"
HARDWARE_RECEIPT_ID = "44444444-4444-4444-8444-444444444444"


def digest(label: str) -> str:
    return sha256_digest(label.encode("ascii"))


def key_fixture(seed: int, provider: str) -> tuple[Ed25519PrivateKey, Ed25519TrustRoot]:
    private_key = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, Ed25519TrustRoot(provider, der)


ENROLLMENT_KEY, ENROLLMENT_TRUST = key_fixture(1, "independent-enrollment-verifier")
HARDWARE_KEY, HARDWARE_TRUST = key_fixture(2, "independent-hardware-verifier")
FINAL_KEY, FINAL_TRUST_ROOT = key_fixture(3, "off-host-final-authority")
ROGUE_KEY, ROGUE_TRUST = key_fixture(4, "rogue-provider")
CLOCK = FixedClock(NOW)

ASSIGNMENT = SetupAssignment(
    principal_id="user:setup-owner",
    route_id="route.gmail.read",
    credential_id="credential:google-primary",
    credential_version=7,
    policy_hash=digest("policy"),
    route_policy_digest=digest("route-policy"),
)
ENROLLMENT_EXPECTED = EnrollmentReceiptExpected(
    receipt_id=ENROLLMENT_RECEIPT_ID,
    setup_session_id=SETUP_ID,
    assignment=ASSIGNMENT,
    enrollment_session_id=ENROLLMENT_SESSION_ID,
    enrollment_packet_sha256=digest("enrollment-packet"),
    verifier_nonce_sha256=digest("verifier-nonce"),
    trust_profile_sha256=digest("trust-profile"),
)
HARDWARE_EXPECTED = HardwareVerificationExpected(
    receipt_id=HARDWARE_RECEIPT_ID,
    setup_session_id=SETUP_ID,
    assignment=ASSIGNMENT,
    runtime_evidence_sha256=digest("runtime-evidence"),
    challenge=bytes(range(32)),
    hardware_assurance_sha256=digest("hardware-assurance-document"),
    hardware_statement_sha256=digest("hardware-assurance-statement"),
    release_identity_sha256=digest("release-identity"),
    current_host_identity_sha256=digest("current-host-identity"),
    proxy_server_statement_sha256=digest("proxy-server-statement"),
    trust_profile_sha256=digest("trust-profile"),
)


def sign_document(
    api_version: str,
    kind: str,
    statement: dict[str, Any],
    private_key: Ed25519PrivateKey,
    trust: Ed25519TrustRoot,
) -> dict[str, Any]:
    signature = private_key.sign(canonical_json_bytes(statement))
    return {
        "apiVersion": api_version,
        "kind": kind,
        "statement": statement,
        "signing_key_id": trust.key_id,
        "signature": "ed25519:" + canonical_base64url(signature),
    }


def raw_document(document: dict[str, Any], *, pretty: bool = False) -> bytes:
    if pretty:
        return json.dumps(document, indent=2, ensure_ascii=True).encode("ascii")
    return canonical_json_bytes(document)


def enrollment_statement() -> dict[str, Any]:
    return {
        "receipt_id": ENROLLMENT_EXPECTED.receipt_id,
        "setup_session_id": ENROLLMENT_EXPECTED.setup_session_id,
        "assignment": ASSIGNMENT.as_document(),
        "assignment_digest": ASSIGNMENT.digest,
        "enrollment_session_id": ENROLLMENT_EXPECTED.enrollment_session_id,
        "enrollment_packet_sha256": ENROLLMENT_EXPECTED.enrollment_packet_sha256,
        "verifier_nonce_sha256": ENROLLMENT_EXPECTED.verifier_nonce_sha256,
        "trust_profile_sha256": ENROLLMENT_EXPECTED.trust_profile_sha256,
        "verifier_provider": ENROLLMENT_TRUST.provider,
        "decision": "verified",
        "checks": list(ENROLLMENT_CHECKS),
        "issued_at_unix": NOW - 10,
        "expires_at_unix": NOW + 300,
    }


def hardware_statement() -> dict[str, Any]:
    return {
        "receipt_id": HARDWARE_EXPECTED.receipt_id,
        "setup_session_id": HARDWARE_EXPECTED.setup_session_id,
        "assignment": ASSIGNMENT.as_document(),
        "assignment_digest": ASSIGNMENT.digest,
        "runtime_evidence_sha256": HARDWARE_EXPECTED.runtime_evidence_sha256,
        "challenge": HARDWARE_EXPECTED.challenge_base64url,
        "challenge_sha256": HARDWARE_EXPECTED.challenge_sha256,
        "hardware_assurance_sha256": HARDWARE_EXPECTED.hardware_assurance_sha256,
        "hardware_statement_sha256": HARDWARE_EXPECTED.hardware_statement_sha256,
        "hardware_verifier_provider": HARDWARE_TRUST.provider,
        "hardware_verifier_key_id": HARDWARE_TRUST.key_id,
        "release_identity_sha256": HARDWARE_EXPECTED.release_identity_sha256,
        "current_host_identity_sha256": HARDWARE_EXPECTED.current_host_identity_sha256,
        "proxy_server_statement_sha256": HARDWARE_EXPECTED.proxy_server_statement_sha256,
        "trust_profile_sha256": HARDWARE_EXPECTED.trust_profile_sha256,
        "decision": "verified",
        "checks": list(HARDWARE_CHECKS),
        "issued_at_unix": NOW,
        "expires_at_unix": NOW + 300,
    }


def enrollment_document(statement: dict[str, Any] | None = None) -> dict[str, Any]:
    return sign_document(
        ENROLLMENT_RECEIPT_API_VERSION,
        "EnrollmentVerifierReceipt",
        statement or enrollment_statement(),
        ENROLLMENT_KEY,
        ENROLLMENT_TRUST,
    )


def hardware_document(statement: dict[str, Any] | None = None) -> dict[str, Any]:
    return sign_document(
        HARDWARE_VERIFICATION_API_VERSION,
        "SetupHardwareVerification",
        statement or hardware_statement(),
        HARDWARE_KEY,
        HARDWARE_TRUST,
    )


def verify_enrollment(document: dict[str, Any], **kwargs: Any) -> Any:
    return verify_enrollment_verifier_receipt(
        raw_document(document),
        trust=kwargs.get("trust", ENROLLMENT_TRUST),
        expected=kwargs.get("expected", ENROLLMENT_EXPECTED),
        clock=kwargs.get("clock", CLOCK),
    )


def verify_hardware(document: dict[str, Any], **kwargs: Any) -> Any:
    return verify_setup_hardware_verification(
        raw_document(document),
        trust=kwargs.get("trust", HARDWARE_TRUST),
        expected=kwargs.get("expected", HARDWARE_EXPECTED),
        clock=kwargs.get("clock", CLOCK),
    )


def valid_completion() -> Any:
    return derive_setup_completion_identity(
        verify_enrollment(enrollment_document()),
        verify_hardware(hardware_document()),
    )


def final_statement(completion: Any | None = None) -> dict[str, Any]:
    identity = completion or valid_completion()
    return {
        "authority_provider": FINAL_TRUST_ROOT.provider,
        "consumption_id": "consumption:setup-final-001",
        "status": "consumed",
        "issued_at_unix": NOW + 1,
        "expires_at_unix": NOW + 301,
        "challenge_nonce_sha256": identity.challenge_sha256,
        "completion_identity_sha256": identity.digest_sha256,
        "release_identity_sha256": identity.release_identity_sha256,
        "hardware_verifier_key_id": identity.hardware_verifier_key_id,
        "current_host_identity_sha256": identity.current_host_identity_sha256,
        "proxy_server_statement_sha256": identity.proxy_server_statement_sha256,
    }


def final_document(completion: Any | None = None) -> dict[str, Any]:
    return sign_document(
        "catchplate.finalChallengeReceipt/v1",
        "FinalChallengeConsumption",
        final_statement(completion),
        FINAL_KEY,
        FINAL_TRUST_ROOT,
    )


def resign(
    document: dict[str, Any],
    private_key: Ed25519PrivateKey,
    trust: Ed25519TrustRoot,
) -> dict[str, Any]:
    copied = deepcopy(document)
    copied["signing_key_id"] = trust.key_id
    copied["signature"] = "ed25519:" + canonical_base64url(
        private_key.sign(canonical_json_bytes(copied["statement"]))
    )
    return copied


def load_schema(name: str) -> dict[str, Any]:
    return json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))


class StrictParserTests(unittest.TestCase):
    def assert_parse_error(
        self, raw: Any, limits: JsonLimits | None = None
    ) -> ReceiptParseError:
        with self.assertRaises(ReceiptParseError) as caught:
            parse_strict_json_object(raw, limits=limits or JsonLimits())
        self.assertIsInstance(caught.exception.code, ReceiptErrorCode)
        return caught.exception

    def test_parser_returns_deeply_frozen_values(self) -> None:
        parsed = parse_strict_json_object(b'{"a":{"b":[1,"two"]}}')
        self.assertIsInstance(parsed, MappingProxyType)
        self.assertIsInstance(parsed["a"], MappingProxyType)
        self.assertEqual(parsed["a"]["b"], (1, "two"))  # type: ignore[index]
        with self.assertRaises(TypeError):
            parsed["new"] = "forbidden"  # type: ignore[index]

    def test_parser_rejects_mutable_bytes_bom_invalid_utf8_and_non_object(self) -> None:
        cases = [
            bytearray(b"{}"),
            b"\xef\xbb\xbf{}",
            b'{"x":"\xff"}',
            b"[]",
            b"",
            b"{} trailing",
        ]
        for raw in cases:
            with self.subTest(raw=raw):
                self.assert_parse_error(raw)

    def test_parser_rejects_duplicate_keys_at_any_depth(self) -> None:
        self.assert_parse_error(b'{"a":1,"a":2}')
        self.assert_parse_error(b'{"outer":{"a":1,"a":2}}')

    def test_parser_rejects_floats_and_non_finite_numbers(self) -> None:
        for raw in (
            b'{"x":1.0}',
            b'{"x":1e3}',
            b'{"x":NaN}',
            b'{"x":Infinity}',
            b'{"x":-Infinity}',
        ):
            with self.subTest(raw=raw):
                self.assert_parse_error(raw)

    def test_parser_enforces_every_resource_bound(self) -> None:
        self.assert_parse_error(b'{"a":"12345"}', JsonLimits(max_string_bytes=4))
        self.assert_parse_error(b'{"a":9223372036854775808}')
        self.assert_parse_error(b'{"a":1,"b":2}', JsonLimits(max_object_keys=1))
        self.assert_parse_error(
            b'{"a":{"b":1},"c":{"d":2}}',
            JsonLimits(max_total_keys=3),
        )
        self.assert_parse_error(b'{"a":[1,2]}', JsonLimits(max_array_items=1))
        self.assert_parse_error(b'{"a":{"b":{"c":1}}}', JsonLimits(max_depth=3))
        self.assert_parse_error(b'{"a":[1]}', JsonLimits(max_total_nodes=2))
        self.assert_parse_error(b'{"a":1}', JsonLimits(max_bytes=6))

    def test_parser_rejects_surrogate_escape(self) -> None:
        self.assert_parse_error(b'{"x":"\\ud800"}')


class TrustAndConfigurationTests(unittest.TestCase):
    def test_spki_key_id_is_sha256_of_canonical_der(self) -> None:
        self.assertEqual(
            ENROLLMENT_TRUST.key_id, sha256_digest(ENROLLMENT_TRUST.public_key_spki_der)
        )
        self.assertEqual(
            spki_key_id(ENROLLMENT_TRUST.public_key_spki_der), ENROLLMENT_TRUST.key_id
        )

    def test_trust_rejects_pem_non_ed25519_and_mutable_key_bytes(self) -> None:
        pem = ENROLLMENT_KEY.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        x25519_der = (
            X25519PrivateKey.generate()
            .public_key()
            .public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        for key in (pem, x25519_der, bytearray(ENROLLMENT_TRUST.public_key_spki_der)):
            with (
                self.subTest(key_type=type(key).__name__),
                self.assertRaises(ReceiptTrustError),
            ):
                Ed25519TrustRoot("provider", key)  # type: ignore[arg-type]

    def test_trust_rejects_malformed_or_non_distinct_providers_and_keys(self) -> None:
        with self.assertRaises(ReceiptTrustError):
            Ed25519TrustRoot(
                "provider with spaces", ENROLLMENT_TRUST.public_key_spki_der
            )
        with self.assertRaises(ReceiptTrustError):
            FinalChallengeTrust(ENROLLMENT_TRUST, ENROLLMENT_TRUST)
        _, same_provider = key_fixture(9, HARDWARE_TRUST.provider)
        with self.assertRaises(ReceiptTrustError):
            FinalChallengeTrust(same_provider, HARDWARE_TRUST)

    def test_expected_objects_require_immutable_challenge_and_canonical_ids(
        self,
    ) -> None:
        with self.assertRaises(ReceiptContractError):
            replace(HARDWARE_EXPECTED, challenge=bytearray(range(32)))  # type: ignore[arg-type]
        with self.assertRaises(ReceiptContractError):
            replace(
                ENROLLMENT_EXPECTED,
                setup_session_id="AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
            )


class EnrollmentReceiptTests(unittest.TestCase):
    def test_valid_receipt_returns_only_frozen_verified_projection(self) -> None:
        projection = verify_enrollment(enrollment_document())
        self.assertEqual(projection.assignment, ASSIGNMENT)
        self.assertEqual(projection.verifier_key_id, ENROLLMENT_TRUST.key_id)
        self.assertEqual(projection.checks, ENROLLMENT_CHECKS)
        self.assertNotIn("verified", projection.__dataclass_fields__)
        with self.assertRaises(FrozenInstanceError):
            projection.decision = "denied"  # type: ignore[misc]

    def test_receipt_digest_is_independent_of_transport_whitespace(self) -> None:
        document = enrollment_document()
        canonical_projection = verify_enrollment(document)
        pretty_projection = verify_enrollment_verifier_receipt(
            raw_document(document, pretty=True),
            trust=ENROLLMENT_TRUST,
            expected=ENROLLMENT_EXPECTED,
            clock=CLOCK,
        )
        self.assertEqual(
            canonical_projection.receipt_sha256, pretty_projection.receipt_sha256
        )

    def test_unknown_fields_are_rejected_at_every_object_layer(self) -> None:
        mutations: list[Callable[[dict[str, Any]], None]] = [
            lambda doc: doc.__setitem__("verified", True),
            lambda doc: doc["statement"].__setitem__("verified", True),
            lambda doc: doc["statement"]["assignment"].__setitem__("verified", True),
        ]
        for mutate in mutations:
            document = enrollment_document()
            mutate(document)
            document = resign(document, ENROLLMENT_KEY, ENROLLMENT_TRUST)
            with (
                self.subTest(document=document),
                self.assertRaises(ReceiptContractError),
            ):
                verify_enrollment(document)

    def test_signature_tampering_and_rogue_signers_are_rejected(self) -> None:
        tampered = enrollment_document()
        tampered["statement"]["issued_at_unix"] -= 1
        with self.assertRaises(ReceiptSignatureError):
            verify_enrollment(tampered)
        rogue = sign_document(
            ENROLLMENT_RECEIPT_API_VERSION,
            "EnrollmentVerifierReceipt",
            enrollment_statement(),
            ROGUE_KEY,
            ROGUE_TRUST,
        )
        with self.assertRaises(ReceiptTrustError):
            verify_enrollment(rogue)

    def test_all_expected_bindings_are_checked_after_a_valid_signature(self) -> None:
        field_mutations: dict[str, Callable[[dict[str, Any]], None]] = {
            "receipt": lambda statement: statement.__setitem__(
                "receipt_id", HARDWARE_RECEIPT_ID
            ),
            "setup": lambda statement: statement.__setitem__(
                "setup_session_id", ENROLLMENT_SESSION_ID
            ),
            "assignment": lambda statement: statement["assignment"].__setitem__(
                "credentialVersion", 8
            ),
            "assignment_digest": lambda statement: statement.__setitem__(
                "assignment_digest", digest("wrong")
            ),
            "enrollment_session": lambda statement: statement.__setitem__(
                "enrollment_session_id", SETUP_ID
            ),
            "packet": lambda statement: statement.__setitem__(
                "enrollment_packet_sha256", digest("wrong")
            ),
            "nonce": lambda statement: statement.__setitem__(
                "verifier_nonce_sha256", digest("wrong")
            ),
            "trust_profile": lambda statement: statement.__setitem__(
                "trust_profile_sha256", digest("wrong")
            ),
            "provider": lambda statement: statement.__setitem__(
                "verifier_provider", "other-provider"
            ),
        }
        for label, mutate in field_mutations.items():
            statement = enrollment_statement()
            mutate(statement)
            with self.subTest(label=label), self.assertRaises(ReceiptBindingError):
                verify_enrollment(enrollment_document(statement))

    def test_decision_and_checks_are_an_exact_signed_contract(self) -> None:
        variants = []
        denied = enrollment_statement()
        denied["decision"] = "denied"
        variants.append(denied)
        missing = enrollment_statement()
        missing["checks"] = missing["checks"][:-1]
        variants.append(missing)
        reordered = enrollment_statement()
        reordered["checks"][0], reordered["checks"][1] = (
            reordered["checks"][1],
            reordered["checks"][0],
        )
        variants.append(reordered)
        duplicated = enrollment_statement()
        duplicated["checks"][-1] = duplicated["checks"][0]
        variants.append(duplicated)
        for statement in variants:
            with (
                self.subTest(checks=statement["checks"]),
                self.assertRaises(ReceiptContractError),
            ):
                verify_enrollment(enrollment_document(statement))

    def test_time_contract_rejects_expiry_future_long_interval_and_boolean(
        self,
    ) -> None:
        variants = []
        for issued, expires in (
            (NOW - 100, NOW),
            (NOW + 31, NOW + 60),
            (NOW - 1, NOW + 901),
            (True, NOW + 1),
        ):
            statement = enrollment_statement()
            statement["issued_at_unix"] = issued
            statement["expires_at_unix"] = expires
            variants.append(statement)
        for statement in variants:
            with self.subTest(statement=statement), self.assertRaises(ReceiptTimeError):
                verify_enrollment(enrollment_document(statement))

    def test_signature_must_be_canonical_unpadded_base64url(self) -> None:
        for suffix in ("=", "+", "/"):
            document = enrollment_document()
            document["signature"] += suffix
            with self.subTest(suffix=suffix), self.assertRaises(ReceiptContractError):
                verify_enrollment(document)


class HardwareReceiptTests(unittest.TestCase):
    def test_valid_hardware_receipt_binds_exact_hardware_identity(self) -> None:
        projection = verify_hardware(hardware_document())
        self.assertEqual(
            projection.challenge_base64url,
            canonical_base64url(HARDWARE_EXPECTED.challenge),
        )
        self.assertEqual(projection.hardware_verifier_key_id, HARDWARE_TRUST.key_id)
        self.assertEqual(
            projection.hardware_assurance_sha256,
            HARDWARE_EXPECTED.hardware_assurance_sha256,
        )
        self.assertEqual(
            projection.hardware_statement_sha256,
            HARDWARE_EXPECTED.hardware_statement_sha256,
        )
        self.assertEqual(projection.checks, HARDWARE_CHECKS)

    def test_all_hardware_bindings_are_checked_after_a_valid_signature(self) -> None:
        fields = (
            "runtime_evidence_sha256",
            "challenge_sha256",
            "hardware_assurance_sha256",
            "hardware_statement_sha256",
            "hardware_verifier_key_id",
            "release_identity_sha256",
            "current_host_identity_sha256",
            "proxy_server_statement_sha256",
            "trust_profile_sha256",
        )
        for field in fields:
            statement = hardware_statement()
            statement[field] = digest("wrong-" + field)
            with self.subTest(field=field), self.assertRaises(ReceiptBindingError):
                verify_hardware(hardware_document(statement))
        statement = hardware_statement()
        statement["hardware_verifier_provider"] = "wrong-provider"
        with self.assertRaises(ReceiptBindingError):
            verify_hardware(hardware_document(statement))

    def test_hardware_challenge_requires_exact_canonical_value(self) -> None:
        for challenge in (
            HARDWARE_EXPECTED.challenge_base64url + "=",
            canonical_base64url(b"x" * 31),
            canonical_base64url(b"x" * 33),
        ):
            statement = hardware_statement()
            statement["challenge"] = challenge
            with (
                self.subTest(challenge=challenge),
                self.assertRaises(ReceiptVerificationError),
            ):
                verify_hardware(hardware_document(statement))

    def test_hardware_boolean_verified_is_never_accepted_as_evidence(self) -> None:
        statement = hardware_statement()
        statement["verified"] = True
        with self.assertRaises(ReceiptContractError):
            verify_hardware(hardware_document(statement))
        document = hardware_document()
        document["verified"] = True
        with self.assertRaises(ReceiptContractError):
            verify_hardware(resign(document, HARDWARE_KEY, HARDWARE_TRUST))

    def test_hardware_checks_are_exact_and_signed(self) -> None:
        statement = hardware_statement()
        statement["checks"] = list(reversed(statement["checks"]))
        with self.assertRaises(ReceiptContractError):
            verify_hardware(hardware_document(statement))


class CompletionIdentityTests(unittest.TestCase):
    def test_completion_identity_is_deterministic_schema_valid_and_complete(
        self,
    ) -> None:
        first = valid_completion()
        second = valid_completion()
        self.assertEqual(first.canonical_bytes, second.canonical_bytes)
        self.assertEqual(first.digest_sha256, second.digest_sha256)
        self.assertEqual(first.digest_sha256, sha256_digest(first.canonical_bytes))
        document = json.loads(first.canonical_bytes)
        self.assertEqual(document["apiVersion"], COMPLETION_IDENTITY_API_VERSION)
        self.assertEqual(document["assignment_digest"], ASSIGNMENT.digest)
        self.assertEqual(
            document["hardware_verification"]["proxy_server_statement_sha256"],
            HARDWARE_EXPECTED.proxy_server_statement_sha256,
        )
        schema = load_schema("setup-completion-identity.v1.schema.json")
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(document)

    def test_completion_document_is_deeply_frozen(self) -> None:
        completion = valid_completion()
        document = completion.document
        self.assertIsInstance(document, MappingProxyType)
        with self.assertRaises(TypeError):
            document["kind"] = "forged"  # type: ignore[index]
        with self.assertRaises(FrozenInstanceError):
            completion.digest_sha256 = digest("forged")  # type: ignore[misc]

    def test_completion_rejects_cross_receipt_mismatches(self) -> None:
        enrollment = verify_enrollment(enrollment_document())
        hardware = verify_hardware(hardware_document())
        variants = (
            replace(hardware, setup_session_id=ENROLLMENT_SESSION_ID),
            replace(hardware, assignment=replace(ASSIGNMENT, credential_version=8)),
            replace(hardware, trust_profile_sha256=digest("different-trust-profile")),
            replace(hardware, issued_at_unix=enrollment.issued_at_unix - 1),
        )
        for variant in variants:
            with self.subTest(variant=variant), self.assertRaises(ReceiptBindingError):
                derive_setup_completion_identity(enrollment, variant)

    def test_completion_rejects_unverified_input_types(self) -> None:
        with self.assertRaises(ReceiptBindingError):
            derive_setup_completion_identity(ENROLLMENT_EXPECTED, HARDWARE_EXPECTED)  # type: ignore[arg-type]


class FinalChallengeTests(unittest.TestCase):
    def final_trust(self) -> FinalChallengeTrust:
        return FinalChallengeTrust(FINAL_TRUST_ROOT, HARDWARE_TRUST)

    def verify_final(
        self, document: dict[str, Any], completion: Any | None = None, **kwargs: Any
    ) -> Any:
        return verify_final_challenge_receipt(
            raw_document(document),
            trust=kwargs.get("trust", self.final_trust()),
            completion=completion or valid_completion(),
            clock=kwargs.get("clock", CLOCK),
        )

    def test_valid_final_receipt_binds_derived_completion(self) -> None:
        completion = valid_completion()
        projection = self.verify_final(final_document(completion), completion)
        self.assertEqual(
            projection.completion_identity_sha256, completion.digest_sha256
        )
        self.assertEqual(projection.authority_key_id, FINAL_TRUST_ROOT.key_id)
        self.assertEqual(projection.hardware_verifier_key_id, HARDWARE_TRUST.key_id)

    def test_final_receipt_rejects_every_signed_binding_mismatch(self) -> None:
        completion = valid_completion()
        fields = (
            "challenge_nonce_sha256",
            "completion_identity_sha256",
            "release_identity_sha256",
            "hardware_verifier_key_id",
            "current_host_identity_sha256",
            "proxy_server_statement_sha256",
        )
        for field in fields:
            statement = final_statement(completion)
            statement[field] = digest("wrong-" + field)
            document = sign_document(
                "catchplate.finalChallengeReceipt/v1",
                "FinalChallengeConsumption",
                statement,
                FINAL_KEY,
                FINAL_TRUST_ROOT,
            )
            with self.subTest(field=field), self.assertRaises(ReceiptBindingError):
                self.verify_final(document, completion)

    def test_final_receipt_requires_consumed_status_and_pinned_provider(self) -> None:
        for field, value in (
            ("status", "verified"),
            ("authority_provider", "lookalike-authority"),
        ):
            statement = final_statement()
            statement[field] = value
            document = sign_document(
                "catchplate.finalChallengeReceipt/v1",
                "FinalChallengeConsumption",
                statement,
                FINAL_KEY,
                FINAL_TRUST_ROOT,
            )
            with self.subTest(field=field), self.assertRaises(ReceiptBindingError):
                self.verify_final(document)

    def test_final_receipt_rejects_rogue_authority_and_hardware_trust(self) -> None:
        rogue_document = sign_document(
            "catchplate.finalChallengeReceipt/v1",
            "FinalChallengeConsumption",
            final_statement(),
            ROGUE_KEY,
            ROGUE_TRUST,
        )
        with self.assertRaises(ReceiptTrustError):
            self.verify_final(rogue_document)
        trust = FinalChallengeTrust(FINAL_TRUST_ROOT, ENROLLMENT_TRUST)
        with self.assertRaises(ReceiptTrustError):
            self.verify_final(final_document(), trust=trust)

    def test_final_receipt_rejects_unknown_verified_boolean(self) -> None:
        statement = final_statement()
        statement["verified"] = True
        document = sign_document(
            "catchplate.finalChallengeReceipt/v1",
            "FinalChallengeConsumption",
            statement,
            FINAL_KEY,
            FINAL_TRUST_ROOT,
        )
        with self.assertRaises(ReceiptContractError):
            self.verify_final(document)

    def test_final_receipt_enforces_time_and_order(self) -> None:
        completion = valid_completion()
        cases = (
            (NOW - 1, NOW),
            (NOW + 31, NOW + 100),
            (completion.hardware_issued_at_unix - 1, NOW + 1),
            (NOW, NOW + 901),
        )
        for issued_at, expires_at in cases:
            statement = final_statement(completion)
            statement["issued_at_unix"] = issued_at
            statement["expires_at_unix"] = expires_at
            document = sign_document(
                "catchplate.finalChallengeReceipt/v1",
                "FinalChallengeConsumption",
                statement,
                FINAL_KEY,
                FINAL_TRUST_ROOT,
            )
            with (
                self.subTest(issued_at=issued_at, expires_at=expires_at),
                self.assertRaises(ReceiptTimeError),
            ):
                self.verify_final(document, completion)


class SchemaAndIsolationTests(unittest.TestCase):
    def test_receipt_schemas_accept_valid_documents_and_reject_unknown_fields(
        self,
    ) -> None:
        fixtures = (
            ("setup-enrollment-verifier-receipt.v2.schema.json", enrollment_document()),
            ("setup-hardware-verification.v1.schema.json", hardware_document()),
        )
        for schema_name, document in fixtures:
            schema = load_schema(schema_name)
            Draft202012Validator.check_schema(schema)
            validator = Draft202012Validator(schema)
            validator.validate(document)
            hostile = deepcopy(document)
            hostile["statement"]["verified"] = True
            with self.subTest(schema=schema_name), self.assertRaises(Exception):
                validator.validate(hostile)

    def test_schemas_are_closed_at_every_object_definition(self) -> None:
        for name in (
            "setup-enrollment-verifier-receipt.v2.schema.json",
            "setup-hardware-verification.v1.schema.json",
            "setup-completion-identity.v1.schema.json",
        ):
            schema = load_schema(name)
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

            collect(schema)
            self.assertTrue(object_schemas)
            self.assertTrue(
                all(
                    item.get("additionalProperties") is False for item in object_schemas
                ),
                name,
            )

    def test_core_imports_no_environment_path_network_process_or_database_modules(
        self,
    ) -> None:
        source_path = ROOT / "catchplate" / "setup_receipts.py"
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0])
        forbidden = {
            "asyncio",
            "http",
            "os",
            "pathlib",
            "requests",
            "socket",
            "sqlite3",
            "subprocess",
            "urllib",
        }
        self.assertFalse(imported & forbidden, imported & forbidden)

    def test_errors_are_typed_and_do_not_echo_attacker_values(self) -> None:
        marker = "DO-NOT-ECHO-ATTACKER-CONTENT"
        raw = ('{"%s":1,"%s":2}' % (marker, marker)).encode("ascii")
        with self.assertRaises(ReceiptParseError) as caught:
            parse_strict_json_object(raw)
        self.assertNotIn(marker, str(caught.exception))
        self.assertEqual(caught.exception.code, ReceiptErrorCode.INVALID_JSON)


class TrustSnapshotServiceTests(unittest.TestCase):
    def test_trust_profile_requires_three_distinct_roles(self) -> None:
        profile = build_setup_receipt_trust_profile(
            enrollment_verifier=ENROLLMENT_TRUST,
            hardware_verifier=HARDWARE_TRUST,
            final_authority=FINAL_TRUST_ROOT,
        )
        self.assertEqual(profile.digest, sha256_digest(profile.canonical_bytes))
        self.assertEqual(
            profile.final_challenge_trust.authority.key_id, FINAL_TRUST_ROOT.key_id
        )
        with self.assertRaises(SetupReceiptTrustConfigurationError):
            build_setup_receipt_trust_profile(
                enrollment_verifier=ENROLLMENT_TRUST,
                hardware_verifier=HARDWARE_TRUST,
                final_authority=Ed25519TrustRoot(
                    "separate-final-provider", HARDWARE_TRUST.public_key_spki_der
                ),
            )

    def test_trust_root_uses_one_non_symlink_snapshot_and_expected_spki(self) -> None:
        with tempfile.TemporaryDirectory(prefix="catchplate-setup-trust-") as temporary:
            root = Path(temporary)
            key_path = root / "enrollment.pub.pem"
            key_path.write_bytes(
                ENROLLMENT_KEY.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            trusted = _trusted_root(
                path=key_path,
                expected_key_id=ENROLLMENT_TRUST.key_id,
                provider=ENROLLMENT_TRUST.provider,
                label="test enrollment key",
            )
            self.assertEqual(trusted, ENROLLMENT_TRUST)
            with self.assertRaises(SetupReceiptTrustConfigurationError):
                _trusted_root(
                    path=key_path,
                    expected_key_id=ROGUE_TRUST.key_id,
                    provider=ENROLLMENT_TRUST.provider,
                    label="test enrollment key",
                )
            symlink = root / "enrollment-link.pub.pem"
            symlink.symlink_to(key_path)
            with self.assertRaises(SetupReceiptTrustConfigurationError):
                _trusted_root(
                    path=symlink,
                    expected_key_id=ENROLLMENT_TRUST.key_id,
                    provider=ENROLLMENT_TRUST.provider,
                    label="test enrollment key",
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
