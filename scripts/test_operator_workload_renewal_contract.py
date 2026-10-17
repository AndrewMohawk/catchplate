#!/usr/bin/env python3
"""Offline wire/cryptography checks, not issuance, replay-store or proxy proof.

Keys are generated locally for this process. No configuration, database,
network, child process, provider, or deployment is used. API framing and
duplicate-key admission belong to the real API tests, not this dict DTO suite.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from catchplate import operator_workload_renewal as wire


def no_external_work(event, _args):
    if event.startswith(("socket.", "subprocess.")):
        raise AssertionError("network and child processes forbidden in wire tests")


sys.addaudithook(no_external_work)

NOW = 1_900_000_000_000
APP = "12345678-1234-4234-8234-123456789abc"
ENROLLMENT = "22345678-1234-4234-8234-123456789abc"
OPERATION = "32345678-1234-4234-8234-123456789abc"
OTHER = "42345678-1234-4234-8234-123456789abc"
AUDIENCE = "https://proxy.example.test/v1/workload/renew"
DOMAIN = b"catchplate.workload-token-renewal/v1\x00POST /v1/workload/renew\x00"


def canonical(value):
    # Independent serialization oracle; never delegates signing to wire helpers.
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("ascii")


def fields(**changes):
    return {"schema": "catchplate.workloadTokenRenewal/v1", "audience": AUDIENCE,
        "application_id": APP, "enrollment_id": ENROLLMENT,
        "expected_token_generation": 7, "operation_id": OPERATION,
        "issued_at_epoch_ms": NOW, "expires_at_epoch_ms": NOW + 60_000,
        "token_sha256": "sha256:" + "a" * 64,
        "token_expires_at_epoch_ms": NOW + 3_600_000, **changes}


class RenewalContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = Ed25519PrivateKey.generate()
        cls.other_key = Ed25519PrivateKey.generate()
        cls.public = cls.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        cls.other_public = cls.other_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    def signed(self, *, key=None, domain=DOMAIN, **changes):
        value = fields(**changes)
        signature = (key or self.key).sign(domain + canonical(value)).hex()
        return {**value, "signature": signature}

    def parsed(self, **changes):
        return wire.RenewalRequest.model_validate(self.signed(**changes))

    def enrollment(self, **changes):
        return {"expected_revision": 1, "expected_policy_hash": "sha256:" + "b" * 64,
            "id": APP, "public_key": self.public,
            "enrollment_lifetime_seconds": 30 * 86400,
            "token_lifetime_seconds": 3600, **changes}

    def assert_model_refused(self, value, model=wire.RenewalRequest):
        with self.assertRaises(ValidationError):
            model.model_validate(value)

    def assert_proof_refused(self, value, *, public=None, audience=AUDIENCE):
        with self.assertRaises(ValueError) as caught:
            value.verify(self.public if public is None else public, audience)
        self.assertEqual(str(caught.exception), "renewal proof refused")

    def test_exact_domain_canonical_bytes_and_digest(self):
        request = self.parsed()
        original = fields()
        expected_bytes = DOMAIN + canonical(original)
        self.assertEqual(wire.DOMAIN, DOMAIN)
        self.assertEqual(request.signed_fields(), original)
        self.assertEqual(request.signing_bytes(), expected_bytes)
        self.assertEqual(request.request_digest(), "sha256:" + hashlib.sha256(expected_bytes).hexdigest())
        self.key.public_key().verify(bytes.fromhex(request.signature), expected_bytes)
        request.verify(self.public, AUDIENCE)

    def test_object_order_does_not_change_signature_or_replay_digest(self):
        value = self.signed()
        reordered = dict(reversed(list(value.items())))
        request = wire.RenewalRequest.model_validate(reordered)
        request.verify(self.public, AUDIENCE)
        self.assertEqual(request.request_digest(), self.parsed().request_digest())
        self.assertEqual(request.signing_bytes(), self.parsed().signing_bytes())

    def test_each_required_field_and_unknown_field_is_refused(self):
        value = self.signed()
        for field in value:
            with self.subTest(missing=field):
                self.assert_model_refused({key: item for key, item in value.items() if key != field})
        for field in ("token", "private_key", "public_key", "provider_secret", "permissions",
                "policy_hash", "enrollment_lifetime_seconds", "unexpected"):
            with self.subTest(extra=field):
                self.assert_model_refused({**value, field: "not-an-authority-field"})

    def test_numeric_fields_are_strict_bounded_integers(self):
        value = self.signed()
        for field in ("expected_token_generation", "issued_at_epoch_ms", "expires_at_epoch_ms",
                "token_expires_at_epoch_ms"):
            for bad in (True, False, None, str(value[field]), float(value[field]), 0, -1,
                    wire.MAX_INTEGER + 1):
                with self.subTest(field=field, value=bad):
                    self.assert_model_refused({**value, field: bad})
        self.assert_model_refused({**value, "expected_token_generation": wire.MAX_INTEGER})
        self.assertEqual(self.parsed(expected_token_generation=wire.MAX_INTEGER - 1)
            .expected_token_generation, wire.MAX_INTEGER - 1)

    def test_canonical_identifiers_are_required(self):
        value = self.signed()
        for field in ("application_id", "enrollment_id", "operation_id"):
            for bad in (APP.upper(), APP.replace("-", ""), "{" + APP + "}", " " + APP,
                    APP + "\n", "not-a-uuid", None, 7):
                with self.subTest(field=field, value=bad):
                    self.assert_model_refused({**value, field: bad})

    def test_schema_verifier_signature_and_audience_bounds(self):
        value = self.signed()
        cases = {"schema": ("catchplate.workloadTokenRenewal/v2", value["schema"] + "\n", "", None),
            "token_sha256": ("a" * 64, "sha256:" + "A" * 64, "sha256:" + "a" * 63,
                "sha256:" + "g" * 64, value["token_sha256"] + "\n", None),
            "signature": ("a" * 127, "a" * 129, "A" * 128, "g" * 128,
                value["signature"] + "\n", None),
            "audience": ("", "a" * 513, None, 7)}
        for field, values in cases.items():
            for bad in values:
                with self.subTest(field=field, value=bad):
                    self.assert_model_refused({**value, field: bad})

    def test_each_variable_signed_field_is_cryptographically_bound(self):
        value = self.signed()
        changes = {"audience": "https://other.example.test/v1/workload/renew",
            "application_id": OTHER, "enrollment_id": OTHER, "expected_token_generation": 8,
            "operation_id": OTHER, "issued_at_epoch_ms": NOW + 1,
            "expires_at_epoch_ms": NOW + 59_999, "token_sha256": "sha256:" + "c" * 64,
            "token_expires_at_epoch_ms": NOW + 3_600_001}
        digest = self.parsed().request_digest()
        for field, change in changes.items():
            with self.subTest(field=field):
                request = wire.RenewalRequest.model_validate({**value, field: change})
                # Matching the tampered audience avoids relying on the audience
                # equality check instead of actually checking its signature.
                self.assert_proof_refused(request, audience=request.audience)
                self.assertNotEqual(request.request_digest(), digest)

    def test_valid_signature_cannot_cross_audience_key_or_route_domain(self):
        request = self.parsed()
        for audience in (AUDIENCE + "/", AUDIENCE + "?x=1", AUDIENCE.replace("https:", "http:"),
                AUDIENCE.replace("proxy.example.test", "other.example.test"),
                "https://proxy.example.test/api/operator-demo/workloads/renew"):
            with self.subTest(audience=audience):
                self.assert_proof_refused(request, audience=audience)
        self.assert_proof_refused(request, public=self.other_public)
        for domain in (b"", DOMAIN.replace(b"POST", b"GET"), DOMAIN.replace(b"/v1/", b"/v2/"),
                DOMAIN.replace(b"renewal/v1", b"enrollment/v1")):
            with self.subTest(domain=domain):
                self.assert_proof_refused(wire.RenewalRequest.model_validate(self.signed(domain=domain)))

    def test_invalid_key_material_and_signature_have_fixed_error(self):
        request = self.parsed()
        for key in ("", "aa", "g" * 64, "a" * 62, "a" * 66, 7):
            with self.subTest(key=key):
                self.assert_proof_refused(request, public=key)
        tampered = bytearray.fromhex(request.signature)
        tampered[0] ^= 1
        invalid = wire.RenewalRequest.model_validate({**self.signed(), "signature": tampered.hex()})
        self.assert_proof_refused(invalid)
        with self.assertRaises(InvalidSignature):
            self.key.public_key().verify(bytes(tampered), request.signing_bytes())

    def test_digest_is_not_a_substitute_for_signature_verification(self):
        valid = self.parsed()
        bad = bytearray.fromhex(valid.signature)
        bad[-1] ^= 1
        invalid = wire.RenewalRequest.model_validate({**valid.model_dump(), "signature": bad.hex()})
        self.assertEqual(valid.request_digest(), invalid.request_digest())
        self.assert_proof_refused(invalid)
        # Different operations or tokens cannot recover the same receipt.
        self.assertNotEqual(valid.request_digest(), self.parsed(operation_id=OTHER).request_digest())
        self.assertNotEqual(valid.request_digest(), self.parsed(token_sha256="sha256:" + "c" * 64).request_digest())

    def test_request_interval_is_positive_and_at_most_one_minute(self):
        for expires in (NOW, NOW - 1, NOW + 60_001):
            with self.subTest(expires=expires):
                self.assert_model_refused(self.signed(expires_at_epoch_ms=expires))
        for delta in (1, 60_000):
            self.assertEqual(self.parsed(expires_at_epoch_ms=NOW + delta).expires_at_epoch_ms, NOW + delta)
        for expires in (NOW, NOW - 1):
            self.assert_model_refused(self.signed(token_expires_at_epoch_ms=expires))

    def test_exact_freshness_and_clock_skew_boundaries(self):
        request = self.parsed()
        for now in (NOW - 5_000, NOW, NOW + 59_999):
            request.check_fresh(now)
        for now in (NOW - 5_001, NOW + 60_000, NOW + 60_001):
            with self.subTest(now=now), self.assertRaises(ValueError) as caught:
                request.check_fresh(now)
            self.assertEqual(str(caught.exception), "renewal request expired or not yet valid")

    def test_replay_never_changes_signed_absolute_deadlines(self):
        request = self.parsed()
        original = request.model_dump()
        digest = request.request_digest()
        for now in (NOW, NOW + 30_000, NOW + 59_999):
            request.check_fresh(now)
            request.verify(self.public, AUDIENCE)
            self.assertEqual(request.model_dump(), original)
            self.assertEqual(request.request_digest(), digest)
        with self.assertRaises(ValueError):
            request.check_fresh(NOW + 60_000)
        # Historical proof remains verifiable; only the transactional replay
        # owner can recover a receipt. This is not permission to issue again.
        request.verify(self.public, AUDIENCE)
        self.assertEqual(request.model_dump(), original)

    def test_enrollment_defaults_and_finite_bounds(self):
        base = self.enrollment()
        del base["enrollment_lifetime_seconds"]
        del base["token_lifetime_seconds"]
        value = wire.EnrollmentInput.model_validate(base)
        self.assertEqual(value.enrollment_lifetime_seconds, 30 * 86400)
        self.assertEqual(value.token_lifetime_seconds, 3600)
        for lifetime in (86400, 90 * 86400):
            self.assertEqual(wire.EnrollmentInput.model_validate(self.enrollment(
                enrollment_lifetime_seconds=lifetime)).enrollment_lifetime_seconds, lifetime)
        for lifetime in (3600, 86400):
            self.assertEqual(wire.EnrollmentInput.model_validate(self.enrollment(
                token_lifetime_seconds=lifetime)).token_lifetime_seconds, lifetime)

    def test_enrollment_is_strict_closed_and_canonical(self):
        required = ("expected_revision", "expected_policy_hash", "id", "public_key")
        for missing in required:
            with self.subTest(missing=missing):
                self.assert_model_refused({key: value for key, value in self.enrollment().items()
                    if key != missing}, wire.EnrollmentInput)
        for changes in ({"enrollment_lifetime_seconds": 86399},
                {"enrollment_lifetime_seconds": 90 * 86400 + 1},
                {"token_lifetime_seconds": 3599}, {"token_lifetime_seconds": 86401},
                {"token_lifetime_seconds": "3600"}, {"enrollment_lifetime_seconds": True},
                {"expected_revision": True}, {"expected_revision": "1"},
                {"id": APP.upper()}, {"public_key": "A" * 64}, {"public_key": "g" * 64},
                {"public_key": "a" * 62}, {"public_key": self.public + "\n"},
                {"private_key": "not-accepted"}, {"overlap_seconds": 86400}):
            with self.subTest(changes=changes):
                self.assert_model_refused(self.enrollment(**changes), wire.EnrollmentInput)

    def test_public_key_fingerprint_matches_actual_key_bytes(self):
        self.assertEqual(wire.key_fingerprint(self.public),
            "sha256:" + hashlib.sha256(bytes.fromhex(self.public)).hexdigest())
        self.assertNotEqual(wire.key_fingerprint(self.public), wire.key_fingerprint(self.other_public))

    def test_gate_descriptor_has_exact_keys_values_and_types(self):
        expected = {"schema": "catchplate.proxyTokenRenewal/v1", "path": "/v1/workload/renew",
            "overlap_seconds": 300, "max_request_bytes": 4096, "max_response_bytes": 8192}
        self.assertEqual(wire.gate_descriptor(), expected)
        self.assertTrue(wire.gate_descriptor_matches(expected))
        for field in expected:
            self.assertFalse(wire.gate_descriptor_matches({key: value for key, value in expected.items()
                if key != field}))
        self.assertFalse(wire.gate_descriptor_matches({**expected, "enabled": True}))
        for field in ("overlap_seconds", "max_request_bytes", "max_response_bytes"):
            for bad in (float(expected[field]), str(expected[field]), True, None, expected[field] + 1):
                with self.subTest(field=field, value=bad):
                    self.assertFalse(wire.gate_descriptor_matches({**expected, field: bad}))
        for bad in (None, [], tuple(expected.items())):
            self.assertFalse(wire.gate_descriptor_matches(bad))
        first = wire.gate_descriptor()
        first["path"] = "/other"
        self.assertEqual(wire.gate_descriptor(), expected)

    def test_signature_not_in_repr_or_safe_validation_error(self):
        request = self.parsed()
        self.assertNotIn(request.signature, repr(request))
        bad = {**self.signed(), "signature": "A" * 128}
        with self.assertRaises(ValidationError) as caught:
            wire.RenewalRequest.model_validate(bad)
        self.assertNotIn(bad["signature"], str(caught.exception))
        self.assertNotIn(bad["signature"], repr(caught.exception))
        safe = caught.exception.errors(include_input=False, include_context=False)
        self.assertNotIn(bad["signature"], json.dumps(safe))

    def test_pure_contract_does_not_import_runtime_or_mutate_authority(self):
        self.parsed().verify(self.public, AUDIENCE)
        for name in ("catchplate.config", "catchplate.db", "catchplate.runtime",
                "catchplate.operator_catalog_store", "catchplate.operator_catalog_mutations"):
            self.assertNotIn(name, sys.modules)
        for name in ("renew", "enroll", "publish", "revoke", "materialize"):
            self.assertFalse(hasattr(wire, name))


if __name__ == "__main__":
    unittest.main()
