#!/usr/bin/env python3
"""Real synthetic package codecs/validators, not installed or live admission.

The existing roundtrip fixture creates in-memory test signatures and passes
the real package verifier. No pilot originals, database, service or owner is
used. Reuse is tested on independently owned plain JSON, not reentrant Mapping
objects or concurrently mutated inputs; these controls make no speedup claim.
"""
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.authority_history_roundtrip_fixture import build_package
from serverware import authority_artifact_spec as spec

PURPOSES = ("artifact-bundle", "generation")


def original_message(purpose, bundle, generation):
    """The pre-reuse formula, using the unchanged real validation helpers."""
    if purpose not in spec.SIGNATURE_PURPOSES:
        raise spec.ArtifactContractError("signature purpose is not recognized")
    spec.validate_artifact_bundle(bundle)
    spec.validate_generation_statement(
        generation, expected_bundle_digest=spec.artifact_bundle_digest(bundle))
    bound = {
        "schema": spec.SIGNED_PACKAGE_SCHEMA,
        "purpose": purpose,
        "artifactBundleDigest": spec.artifact_bundle_digest(bundle),
        "generationDigest": spec.generation_statement_digest(generation),
    }
    return spec.domain_digest(
        spec.PACKAGE_SIGNATURE_DOMAIN,
        spec.canonical_json_bytes(bound),
    ).encode("ascii")


class PackageSignatureDigestReuseControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Construct one real verified synthetic package before installing any
        # counting spies. Discard fixture signing keys; keep only plain JSON.
        fixture = build_package()
        if fixture["verified"].disposition != "CurrentExactRetry":
            raise AssertionError("synthetic package did not pass real verification")
        package = json.loads(spec.canonical_json_bytes(fixture["package"]))
        cls.bundle = package["bundle"]
        cls.generation = package["generation"]

    def inputs(self):
        return deepcopy((self.bundle, self.generation))

    def test_both_purposes_keep_original_signature_message_bytes(self):
        messages = []
        for purpose in PURPOSES:
            with self.subTest(purpose=purpose):
                bundle, generation = self.inputs()
                before = spec.canonical_json_bytes([bundle, generation])
                expected = original_message(purpose, bundle, generation)
                actual = spec.package_signature_message(purpose, bundle, generation)
                self.assertEqual(actual, expected)
                self.assertEqual(spec.canonical_json_bytes([bundle, generation]), before)
                messages.append(actual)
        self.assertNotEqual(messages[0], messages[1])

    def test_each_message_validates_and_serializes_bundle_exactly_once(self):
        for purpose in PURPOSES:
            with self.subTest(purpose=purpose):
                bundle, generation = self.inputs()
                with patch.object(spec, "artifact_bundle_digest", wraps=spec.artifact_bundle_digest) as digest, \
                        patch.object(spec, "validate_artifact_bundle", wraps=spec.validate_artifact_bundle) as validate, \
                        patch.object(spec, "canonical_json_bytes", wraps=spec.canonical_json_bytes) as canonical:
                    spec.package_signature_message(purpose, bundle, generation)
                self.assertEqual(digest.call_count, 1)
                self.assertIs(digest.call_args.args[0], bundle)
                self.assertEqual(validate.call_count, 1)
                self.assertIs(validate.call_args.args[0], bundle)
                self.assertEqual(sum(call.args[0] is bundle for call in canonical.call_args_list), 1)

    def test_invalid_purpose_bundle_and_generation_keep_real_refusals(self):
        malformed_bundle, generation = self.inputs()
        malformed_bundle["files"][0]["size"] = -1
        bundle, mismatched_generation = self.inputs()
        mismatched_generation["artifactBundleDigest"] = "sha256:" + "0" * 64
        cases = [("purpose", "unrecognized", None, None)]
        for purpose in PURPOSES:
            cases.extend((("bundle", purpose, malformed_bundle, generation),
                          ("generation", purpose, bundle, mismatched_generation)))
        for label, purpose, selected_bundle, selected_generation in cases:
            with self.subTest(refusal=label, purpose=purpose):
                with self.assertRaises(spec.ArtifactContractError) as old:
                    original_message(purpose, selected_bundle, selected_generation)
                with self.assertRaises(spec.ArtifactContractError) as current:
                    spec.package_signature_message(purpose, selected_bundle, selected_generation)
                self.assertEqual(str(current.exception), str(old.exception))
        with patch.object(spec, "artifact_bundle_digest", wraps=spec.artifact_bundle_digest) as digest:
            with self.assertRaises(spec.ArtifactContractError):
                spec.package_signature_message("unrecognized", None, None)
            digest.assert_not_called()

    def test_later_calls_recompute_and_reject_changed_originals(self):
        bundle, generation = self.inputs()
        with patch.object(spec, "artifact_bundle_digest", wraps=spec.artifact_bundle_digest) as digest, \
                patch.object(spec, "validate_artifact_bundle", wraps=spec.validate_artifact_bundle) as validate:
            first = spec.package_signature_message(PURPOSES[0], bundle, generation)
            second = spec.package_signature_message(PURPOSES[0], bundle, generation)
            self.assertEqual(first, second)
            self.assertEqual(digest.call_count, 2)
            self.assertEqual(validate.call_count, 2)
            bundle["files"][0]["size"] = -1
            with self.assertRaises(spec.ArtifactContractError):
                spec.package_signature_message(PURPOSES[0], bundle, generation)
            self.assertEqual(digest.call_count, 3)
            self.assertEqual(validate.call_count, 3)


if __name__ == "__main__":
    unittest.main()
