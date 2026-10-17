#!/usr/bin/env python3
"""Actual typed commitments on synthetic requests; no signature/SQL authority."""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from catchplate import authority_challenge_plan_request as source
from catchplate import authority_query_read_work as measured


def work(**limits):
    return measured._ValidationWork(measured.QueryReadValidationLimits(**limits))


def fixture(operation="webauthn.challenge.maintain", **changes):
    arguments = dict(challenge_type="registration", user_id="synthetic-user", scope_key="scope")
    if operation.endswith("maintain"):
        arguments["replace_scope"] = True
    else:
        arguments.update(challenge_id="01234567-89ab-4def-8123-456789abcdef", challenge="A" * 43,
            payload={"label": "synthetic-key"}, approval_request_id=None, ttl_seconds=300,
            created_at="2026-01-01T00:00:00+00:00", expires_at="2026-01-01T00:05:00+00:00")
    arguments.update(changes)
    typed = {**arguments, "businessIntent": source.authority.synthesize_business_intent(operation, arguments)}
    request = dict(schema=source.shape.TYPED_REQUEST_SCHEMA, operation=operation,
        operationId="sha256:" + "0" * 64, requestDigest="sha256:" + "0" * 64,
        handler=source.authority.operation_spec(operation)["handler"],
        operationManifestDigest=source.authority.OPERATION_MANIFEST_DIGEST, arguments=typed)
    return resign(request)


def resign(request):
    digest = source.commitment._typed_request_digest(request, work=None)
    request.update(requestDigest=digest, operationId=source.commitment.operation_id(request["operation"], digest))
    return request


def capture(request, meter=None):
    return source.capture_request(source.commitment.canonical_bytes(request), work=meter or work())


class ChallengePlanRequestControls(unittest.TestCase):
    def test_owned_exact_subjects_and_original_create_replacement(self):
        for operation in sorted(source.OPERATIONS):
            for scope in (None, "scope"):
                original = fixture(operation, scope_key=scope)
                owned = capture(original)
                self.assertEqual(owned, original)
                self.assertIsNot(owned, original)
                self.assertIsNot(owned["arguments"], original["arguments"])
                subject = source.context_subject(owned, work=work())
                self.assertEqual(subject, dict(operation=operation, operationId=owned["operationId"],
                    requestDigest=owned["requestDigest"], challengeType="registration", userId="synthetic-user",
                    scopeKey=scope, replaceScope=True if operation.endswith("maintain") else scope is not None))
                original["arguments"]["user_id"] = "changed"
                self.assertEqual(owned["arguments"]["user_id"], "synthetic-user")
        subject = source.context_subject(capture(fixture(replace_scope=False)), work=work())
        self.assertIs(subject["replaceScope"], False)

    def test_closed_envelope_commitment_and_subject_rechecks(self):
        original = fixture()
        for field, value in (("schema", "other"), ("operation", "webauthn.challenge.consume"),
                ("handler", "other"), ("operationManifestDigest", "sha256:" + "f" * 64),
                ("requestDigest", "sha256:" + "f" * 64), ("operationId", "sha256:" + "f" * 64),
                ("capabilityId", "sha256:" + "f" * 64), ("currentRoot", {})):
            with self.subTest(field=field):
                value_request = copy.deepcopy(original)
                value_request[field] = value
                with self.assertRaises(ValueError):
                    capture(value_request)
        for field in original:
            value_request = copy.deepcopy(original)
            del value_request[field]
            with self.assertRaises(ValueError):
                capture(value_request)
        owned = capture(original)
        owned["arguments"]["scope_key"] = "another"
        with self.assertRaises(ValueError):
            source.context_subject(owned, work=work())

    def test_exact_maintain_boolean_closed_arguments_and_intent(self):
        for replacement in (0, 1, None, "true", []):
            with self.subTest(value=replacement), self.assertRaises(ValueError):
                capture(fixture(replace_scope=replacement))
        for extra in (dict(cutoff_us=1), dict(rootDigest="sha256:" + "1" * 64), dict(count=0)):
            with self.assertRaises(ValueError):
                capture(fixture(**extra))
        value = fixture(replace_scope=False)
        value["arguments"]["businessIntent"]["arguments"]["replace_scope"] = 0
        # The real historical equality aliases these scalars; this helper must not.
        resign(value)
        with self.assertRaises(ValueError):
            capture(value)

    def test_create_source_limits_and_canonical_utc_interval(self):
        for changes in (dict(challenge_id="legacy-id"), dict(challenge="A" * 31), dict(challenge="!" * 43),
                dict(ttl_seconds=True), dict(ttl_seconds=29), dict(ttl_seconds=301),
                dict(created_at="2026-01-01T00:00:00Z"), dict(expires_at="2026-01-01T00:05:01+00:00"),
                dict(payload={"x": "A" * (64 * 1024)}), dict(user_id="é" * 257),
                dict(scope_key="é" * 257), dict(challenge_type="x" * 65)):
            with self.subTest(changes=tuple(changes)), self.assertRaises(ValueError):
                capture(fixture("webauthn.challenge.create", **changes))
        for ttl in (30, 300):
            expiry = "2026-01-01T00:00:30+00:00" if ttl == 30 else "2026-01-01T00:05:00+00:00"
            capture(fixture("webauthn.challenge.create", ttl_seconds=ttl, expires_at=expiry,
                payload={"x": "A" * (64 * 1024 - 8)}, user_id="é" * 256))

    def test_canonical_original_bytes_and_measured_lossless_domain(self):
        raw = source.commitment.canonical_bytes(fixture())
        for invalid in (raw + b" ", b'{"schema":"first",' + raw[1:], bytearray(raw), b"[]",
                b"{" + b" " * source.MAX_REQUEST_BYTES + b"}"):
            with self.assertRaises(ValueError):
                source.capture_request(invalid, work=work())
        for payload in ({"x": 1.5}, {"x": "\x00"}, {"x": "\ud800"}):
            value = fixture("webauthn.challenge.create", payload=payload)
            with self.assertRaises(ValueError):
                capture(value)

    def test_policy_payload_binding_and_shared_budget_are_not_replaced(self):
        value = fixture("webauthn.challenge.create")
        arguments = value["arguments"]
        identifier = "sha256:" + "1" * 64
        domain = "catchplate.policyAuthorityWebAuthnChallengeId/v1"
        payload = dict(schema="catchplate.policyAuthorityWebAuthnChallenge/v1", operationId=identifier,
            rpId="example.invalid", origin="https://example.invalid", issuedAtEpochNs=1767225600000000000,
            expiresAtEpochNs=1767225900000000000, credentialId=None)
        identity = source.commitment.framed_digest(domain, identifier.encode("ascii"), arguments["challenge"].encode("ascii"))
        good = fixture("webauthn.challenge.create", challenge_type="policy_authority", scope_key=identifier,
            challenge_id=identity, payload=payload)
        meter = work()
        capture(good, meter)
        first = meter.metrics
        source.context_subject(good, work=meter)
        self.assertGreater(meter.metrics.hash_work, first.hash_work)
        self.assertGreater(meter.metrics.input_bytes, first.input_bytes)
        for changes in (dict(challenge_id="01234567-89ab-4def-8123-456789abcdef"),
                dict(scope_key="wrong"), dict(payload={**payload, "issuedAtEpochNs": True})):
            selected = dict(challenge_type="policy_authority", scope_key=identifier, challenge_id=identity, payload=payload)
            selected.update(changes)
            with self.assertRaises(ValueError):
                capture(fixture("webauthn.challenge.create", **selected))
        with self.assertRaises(ValueError):
            capture(good, work(max_input_bytes=128))
        with self.assertRaises(ValueError):
            source.capture_request(source.commitment.canonical_bytes(good), work=object())


if __name__ == "__main__":
    unittest.main()
