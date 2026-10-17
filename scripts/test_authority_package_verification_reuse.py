#!/usr/bin/env python3
"""Per-call package reuse with real signatures over synthetic descriptions.

The history fixture supplies actual Ed25519 signatures and verifier results,
not installed files, live authority, a launched role or durable witness proof.
Counting wrappers call the actual validators/crypto. No success is fabricated.
Plain JSON ownership is not a concurrent-mutation guarantee; deterministic
mutation seams below check refusal and unknown-object fallback, not atomicity.
"""
from collections import UserDict
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.authority_history_roundtrip_fixture import build_package
from catchplate import authority_artifact_spec as spec

NOW = "2026-10-10T12:00:00Z"
OTHER = "sha256:" + "f" * 64
SIGNATURE_NAMES = [
    "trust document", "trust document", "artifact-bundle package",
    "generation package", "stable snapshot", "complete closure",
    "supply-chain provenance", "witness checkpoint",
]


def canonical_copy(value):
    return json.loads(spec.canonical_json_bytes(value))


def plain_digest(domain, value):
    return spec.domain_digest(domain, spec.canonical_json_bytes(value))


class PackageVerificationReuseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = build_package(now_datetime=datetime(2026, 10, 10, 12,
            tzinfo=timezone.utc))
        if fixture["verified"].disposition != "CurrentExactRetry":
            raise AssertionError("synthetic package did not pass real verification")
        # Decode like the real launch input. deepcopy alone preserves aliases
        # intentionally shared by the fixture builder, which use fallback.
        cls.package = canonical_copy(fixture["package"])
        cls.trust = canonical_copy(fixture["trust_state"])

    def inputs(self):
        return deepcopy(self.package), deepcopy(self.trust)

    def verify(self, package, state, *, instant=NOW):
        return spec.verify_signed_artifact_package(package,
            trust_state=state, validation_time=instant)

    def initial_state(self, package, state):
        initial = deepcopy(state)
        checkpoint = package["generation"]["witnessCheckpoint"]["payload"]
        initial.update(currentGenerationSequence=-1,
            currentGenerationDigest=None, currentPackageDigest=None,
            acceptedPackageDigests=[], acceptedGenerationDigests=[],
            acceptedEvidenceDigests=[], revokedKeyIds=[])
        initial["witness"].update(currentSequence=-1, currentTreeSize=0,
            currentCheckpointDigest=checkpoint["previousCheckpointDigest"],
            currentRootDigest=checkpoint["previousRootDigest"])
        return initial

    def test_actual_verification_preserves_digest_messages_and_input_bytes(self):
        package, state = self.inputs()
        before = spec.canonical_json_bytes(package)
        bundle_digest = plain_digest(spec.ARTIFACT_BUNDLE_DIGEST_DOMAIN, package["bundle"])
        generation_digest = plain_digest(spec.GENERATION_DIGEST_DOMAIN, package["generation"])
        expected_messages = [spec.domain_digest(spec.PACKAGE_SIGNATURE_DOMAIN,
            spec.canonical_json_bytes(dict(schema=spec.SIGNED_PACKAGE_SCHEMA,
                purpose=purpose, artifactBundleDigest=bundle_digest,
                generationDigest=generation_digest))).encode("ascii")
            for purpose in ("artifact-bundle", "generation")]
        with patch.object(spec, "verify_ed25519_signature",
                wraps=spec.verify_ed25519_signature) as crypto:
            result = self.verify(package, state)
        self.assertEqual([call.kwargs["name"] for call in crypto.call_args_list], SIGNATURE_NAMES)
        self.assertEqual([call.args[2] for call in crypto.call_args_list[2:4]], expected_messages)
        self.assertEqual(result.package_digest,
            spec.domain_digest(spec.SIGNED_PACKAGE_DIGEST_DOMAIN, before))
        self.assertEqual(result.artifact_bundle_digest, bundle_digest)
        self.assertEqual(result.generation_digest, generation_digest)
        self.assertEqual(result.role_set_digest, package["generation"]["roleSetDigest"])
        self.assertEqual(result.witness_checkpoint_digest,
            spec.witness_checkpoint_digest(package["generation"]["witnessCheckpoint"]))
        self.assertEqual(result.disposition, "CurrentExactRetry")
        self.assertEqual(dict(result.package), package)
        self.assertEqual(spec.canonical_json_bytes(package), before)

    def test_one_bundle_pass_per_successor_or_retry_call_no_cross_call_cache(self):
        package, state = self.inputs()
        bundle = package["bundle"]
        generation = package["generation"]
        initial = self.initial_state(package, state)
        self.assertTrue(spec._plain_package_json(package))
        self.assertTrue(spec._plain_package_json(state))
        with patch.object(spec, "validate_artifact_bundle", wraps=spec.validate_artifact_bundle) as validate, \
                patch.object(spec, "artifact_bundle_digest", wraps=spec.artifact_bundle_digest) as digest, \
                patch.object(spec, "canonical_json_bytes", wraps=spec.canonical_json_bytes) as canonical, \
                patch.object(spec, "package_signature_message", wraps=spec.package_signature_message) as public_message, \
                patch.object(spec, "signed_artifact_package_digest", wraps=spec.signed_artifact_package_digest) as public_digest:
            for count, (selected, disposition) in enumerate(
                    ((initial, "Successor"), (state, "CurrentExactRetry"), (state, "CurrentExactRetry")), 1):
                self.assertEqual(self.verify(package, selected).disposition, disposition)
                self.assertEqual(validate.call_count, count)
                self.assertEqual(digest.call_count, count)
                self.assertIs(validate.call_args.args[0], bundle)
                self.assertEqual(sum(call.args[0] is bundle for call in canonical.call_args_list), count)
                self.assertEqual(sum(call.args[0] is generation for call in canonical.call_args_list), count)
                self.assertEqual(sum(call.args[0] is package for call in canonical.call_args_list), 2 * count)
            public_message.assert_not_called()
            public_digest.assert_not_called()
            bundle["files"][0]["size"] = -1
            with self.assertRaises(spec.ArtifactContractError):
                self.verify(package, state)
            self.assertEqual(validate.call_count, 4)

    def test_each_real_signature_check_refuses_corruption_on_a_later_call(self):
        package, state = self.inputs()
        self.verify(package, state)
        original = spec.verify_ed25519_signature
        for selected in range(len(SIGNATURE_NAMES)):
            calls = []

            def corrupt(public_key, signature, message, *, name):
                index = len(calls)
                calls.append(name)
                if index == selected:
                    raw = spec.strict_base64url_decode(signature, name="test signature", decoded_size=64)
                    signature = spec.strict_base64url_encode(bytes([raw[0] ^ 1]) + raw[1:])
                return original(public_key, signature, message, name=name)

            with self.subTest(signature=selected), patch.object(spec,
                    "verify_ed25519_signature", side_effect=corrupt):
                with self.assertRaisesRegex(spec.ArtifactContractError, "signature verification failed"):
                    self.verify(package, state)
                self.assertEqual(calls, SIGNATURE_NAMES[:selected + 1])
        # This fixture has no migration rows; it does not claim migration
        # signature coverage or installed/live authority acceptance.
        self.assertEqual(self.verify(package, state).disposition, "CurrentExactRetry")

    def test_actual_changed_package_signature_is_not_accepted_with_new_replay_hash(self):
        for index in (0, 1):
            package, state = self.inputs()
            self.verify(package, state)
            package["signatures"][index]["signatureBase64Url"] = spec.strict_base64url_encode(b"x" * 64)
            changed = plain_digest(spec.SIGNED_PACKAGE_DIGEST_DOMAIN, package)
            state.update(currentPackageDigest=changed, acceptedPackageDigests=[changed])
            with self.subTest(signature=index), self.assertRaisesRegex(
                    spec.ArtifactContractError, "package signature verification failed"):
                self.verify(package, state)

    def test_later_calls_recheck_time_revocation_trust_and_evidence_high_water(self):
        package, state = self.inputs()
        self.verify(package, state)
        cases = []
        revoked = deepcopy(state)
        revoked["revokedKeyIds"] = [package["signatures"][0]["keyId"]]
        cases.append(("revoked", revoked, NOW))
        root_expired = deepcopy(state)
        root_expired["rootKeys"][0]["notAfter"] = "2026-10-10T11:59:59Z"
        cases.append(("root-expired", root_expired, NOW))
        missing_evidence = deepcopy(state)
        missing_evidence["acceptedEvidenceDigests"] = []
        cases.append(("missing-evidence", missing_evidence, NOW))
        changed_package = deepcopy(state)
        changed_package.update(currentPackageDigest=OTHER, acceptedPackageDigests=[OTHER])
        cases.append(("changed-package-high-water", changed_package, NOW))
        changed_witness = deepcopy(state)
        changed_witness["witness"]["currentRootDigest"] = OTHER
        cases.append(("changed-witness", changed_witness, NOW))
        cases.extend((("future", state, "2026-10-10T12:30:01Z"),
                      ("not-yet-valid", state, "2026-10-10T11:57:59Z")))
        for label, selected, instant in cases:
            with self.subTest(refusal=label), self.assertRaises(spec.ArtifactContractError):
                self.verify(package, selected, instant=instant)
        self.assertEqual(self.verify(package, state).disposition, "CurrentExactRetry")

    def test_bounded_malformed_package_refuses_before_package_encoding_or_trust(self):
        for oversized in (False, True):
            package, state = self.inputs()
            if oversized:
                package["bundle"]["files"] = [package["bundle"]["files"][0]] * (spec.MAX_BUNDLE_FILES + 1)
            else:
                package["bundle"]["files"][0]["size"] = -1
            with self.assertRaises(spec.ArtifactContractError) as expected:
                spec.validate_signed_artifact_package(package)
            with patch.object(spec, "canonical_json_bytes", wraps=spec.canonical_json_bytes) as canonical, \
                    patch.object(spec, "validate_trust_state", wraps=spec.validate_trust_state) as trust:
                with self.assertRaises(spec.ArtifactContractError) as actual:
                    self.verify(package, state)
                self.assertEqual(str(actual.exception), str(expected.exception))
                trust.assert_not_called()
                self.assertFalse(any(call.args[0] is package for call in canonical.call_args_list))

    def test_persistent_mutation_during_real_crypto_is_refused_before_return(self):
        original = spec.verify_ed25519_signature
        for selected_name in ("artifact-bundle package", "witness checkpoint"):
            package, state = self.inputs()
            changed = []

            def mutate(public_key, signature, message, *, name):
                result = original(public_key, signature, message, name=name)
                if name == selected_name:
                    package["bundle"]["sbom"]["format"] = "changed-after-validation"
                    changed.append(True)
                return result

            with self.subTest(stage=selected_name), patch.object(spec,
                    "verify_ed25519_signature", side_effect=mutate):
                with self.assertRaisesRegex(spec.ArtifactContractError,
                        "signed package changed during verification"):
                    self.verify(package, state)
                self.assertEqual(changed, [True])

    def test_reentrant_signature_or_trust_mapping_keeps_old_mutation_refusal(self):
        for location in ("signature", "trust"):
            package, state = self.inputs()
            state = self.initial_state(package, state)
            changed = []

            class MutatingDict(dict):
                def __getitem__(self, key):
                    if key == ("purpose" if location == "signature" else "schema") and not changed:
                        package["bundle"]["sbom"]["format"] = "changed-before-package-digest"
                        changed.append(True)
                    return super().__getitem__(key)

            if location == "signature":
                package["signatures"][0] = MutatingDict(package["signatures"][0])
            else:
                state = MutatingDict(state)
            with self.subTest(location=location), patch.object(spec,
                    "artifact_bundle_digest", wraps=spec.artifact_bundle_digest) as digest:
                with self.assertRaises(spec.ArtifactContractError):
                    self.verify(package, state)
                self.assertEqual(changed, [True])
                self.assertGreaterEqual(digest.call_count, 2)

    def test_valid_unknown_objects_keep_original_five_pass_path(self):
        class PlainSubclass(dict):
            pass

        for location in ("package", "trust", "signature"):
            package, state = self.inputs()
            if location == "package":
                package = PlainSubclass(package)
            elif location == "trust":
                state = UserDict(state)
            else:
                package["signatures"][0] = PlainSubclass(package["signatures"][0])
            with self.subTest(location=location), patch.object(spec,
                    "validate_artifact_bundle", wraps=spec.validate_artifact_bundle) as validate, \
                    patch.object(spec, "package_signature_message", wraps=spec.package_signature_message) as message:
                result = self.verify(package, state)
                self.assertEqual(result.package_digest, self.trust["currentPackageDigest"])
                self.assertEqual(validate.call_count, 5)
                self.assertEqual(message.call_count, 2)

    def test_eligibility_bounds_do_not_call_unknown_objects_or_grant_admission(self):
        comparisons = []

        class UnknownType(type):
            def __eq__(self, other):
                comparisons.append(other)
                raise AssertionError("eligibility invoked metaclass equality")

        class UnknownValue(metaclass=UnknownType):
            pass

        self.assertFalse(spec._plain_package_json(UnknownValue()))
        self.assertEqual(comparisons, [])

        class Unknown(dict):
            def __iter__(self):
                raise AssertionError("eligibility invoked unknown iteration")

            def values(self):
                raise AssertionError("eligibility invoked unknown values")

        self.assertFalse(spec._plain_package_json(Unknown()))
        cycle = []
        cycle.append(cycle)
        self.assertFalse(spec._plain_package_json(cycle))
        shared = []
        self.assertFalse(spec._plain_package_json([shared, shared]))
        deep = None
        for _ in range(66):
            deep = [deep]
        self.assertFalse(spec._plain_package_json(deep))
        self.assertFalse(spec._plain_package_json([None] * 1_000_001))
        self.assertFalse(spec._plain_package_json({1: "not-a-string-key"}))
        self.assertFalse(spec._plain_package_json(1.5))
        self.assertTrue(spec._plain_package_json(dict(values=[None, True, 1, "text"])))
        with self.assertRaises(spec.ArtifactContractError):
            self.verify({}, self.trust)


if __name__ == "__main__":
    unittest.main()
