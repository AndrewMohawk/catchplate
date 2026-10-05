#!/usr/bin/env python3
"""UNRUN signed JIT parent and genuine retained-original replay controls.

Independent synthetic trees, actual ES256 and actual Ed25519 cross the source
boundaries. Only local clocks are doubled. These controls do not establish
native currentness, configured signing, durable custody, all-input capacity,
public routing or deployed execution authority.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import authority_jit_compound_plan as source
from serverware.authority_query_read_work import QueryReadValidationLimits
from test_authority_jit_compound import originals, replay
from test_authority_jit_connected_originals import canonical, connected_fixture, meter


AGE = 1_000_000
DEADLINE = AGE + 10


class JitCompoundPlanControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.case = connected_fixture()
        cls.pages, cls.receipt_digest = originals(cls.case)
        cls.epoch = cls.case["database_cutoff_us"] * 1000
        cls.window = (cls.epoch, 10, 10, cls.epoch + AGE, DEADLINE, AGE, 0)
        cls.private = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        cls.public = cls.private.public_key()
        cls.spki = source.evidence.keys._spki_on_work(cls.public, meter())
        cls.request_bytes = canonical(cls.case["request"])
        cls.expected = dict(requestDigest=cls.case["request"]["requestDigest"],
            operationId=cls.case["request"]["operationId"], configurationDigest="sha256:" + "a" * 64,
            plannerIdentity={name: "sha256:" + digit * 64 for name, digit in (
                ("sessionIdentityDigest", "b"), ("measurementDigest", "c"),
                ("attestationReceiptDigest", "d"))}, plannerSpkiDigest=cls.spki,
            assertionPolicy=copy.deepcopy(cls.case["assertion_policy"]),
            businessBeforeRoots=[value.json_projection() for value in cls.case["business_before_roots"]],
            authorizationBeforeRoots=[value.json_projection()
                for value in cls.case["authorization_before_roots"]],
            countedBeforeHeads=[dict(indexId=value.index_id, indexRevision=value.index_revision,
                rootDigest=value.index_root.digest, leafCount=value.index_root.count)
                for value in cls.case["counted_before_heads"]],
            databaseCutoffUs=cls.case["database_cutoff_us"], originalDeadlineNs=DEADLINE,
            maximumPlanAgeNs=AGE, maximumClockSkewNs=0)
        # Actual raw engines produce the context/manifest. No successful
        # observation is an argument to either the signer or verifier.
        with patch.object(source.clock.time, "monotonic_ns", return_value=10), \
                patch.object(source.clock.time, "time_ns", return_value=cls.epoch):
            actual = replay(cls.case, cls.pages, deadline=DEADLINE)
            cls.context_bytes = actual.context_bytes
            cls.manifest_bytes = actual.original_manifest_bytes
            cls.envelope_bytes = source._sign_parent_on_work(request_bytes=cls.request_bytes,
                context_bytes=cls.context_bytes, manifest_bytes=cls.manifest_bytes,
                expectations=cls.expected, planner_private_key=cls.private, planner_public_key=cls.public,
                issued_at_epoch_ns=cls.epoch, expires_at_epoch_ns=cls.epoch + AGE,
                live_window=cls.window, work=meter())

    def inputs(self):
        return dict(envelope_bytes=self.envelope_bytes, request_bytes=self.request_bytes,
            context_bytes=self.context_bytes, manifest_bytes=self.manifest_bytes,
            expectations=copy.deepcopy(self.expected), planner_public_key=self.public,
            live_window=self.window,
            read_original=lambda kind, ordinal, work: self.pages[kind, ordinal],
            check=lambda stage: None, work=meter())

    def verify(self, **changes):
        values = self.inputs()
        values.update(changes)
        with patch.object(source.clock.time, "monotonic_ns", return_value=10), \
                patch.object(source.clock.time, "time_ns", return_value=self.epoch):
            return source.verify_retained(**values)

    def sign(self, manifest_bytes):
        with patch.object(source.clock.time, "monotonic_ns", return_value=10), \
                patch.object(source.clock.time, "time_ns", return_value=self.epoch):
            return source._sign_parent_on_work(request_bytes=self.request_bytes,
                context_bytes=self.context_bytes, manifest_bytes=manifest_bytes,
                expectations=copy.deepcopy(self.expected), planner_private_key=self.private,
                planner_public_key=self.public, issued_at_epoch_ns=self.epoch,
                expires_at_epoch_ns=self.epoch + AGE, live_window=self.window, work=meter())

    def test_real_signature_and_every_raw_original_recompute_actual_result_and_both_root_classes(self):
        visited = []
        def read(kind, ordinal, work):
            visited.append((kind, ordinal))
            return self.pages[kind, ordinal]
        actual = self.verify(read_original=read)
        self.assertIs(type(actual), source.VerifiedJitCompoundPlan)
        self.assertEqual(actual.envelope_bytes, self.envelope_bytes)
        self.assertEqual(actual.context_bytes, self.context_bytes)
        self.assertEqual(actual.manifest_bytes, self.manifest_bytes)
        self.assertEqual(actual.plan_digest, source.evidence.plan._frame(
            source.IDENTITY_DOMAIN, (self.envelope_bytes,), meter()))
        self.assertEqual(actual.replay.transition.result["assertion_receipt_digest"], self.receipt_digest)
        self.assertEqual(len(actual.replay.transition.mutations), 3)
        self.assertEqual(len(actual.replay.indexed_result.primary.business_after_roots), 4)
        self.assertEqual(actual.replay.indexed_result.primary.authorization_after_roots,
            self.case["authorization_before_roots"])
        self.assertEqual(len(actual.replay.indexed_result.after_heads), 12)
        self.assertEqual(set(visited), set(self.pages))
        self.assertEqual(len(visited), len(self.pages))
        self.assertEqual(actual.replay.total_acquisition, source.compound.PhysicalMetrics(0, 0, 0, 0))
        envelope = json.loads(self.envelope_bytes)
        self.assertEqual(set(envelope["payload"]), source.PAYLOAD_FIELDS)
        self.assertEqual(len(envelope["payload"]), 16)
        self.assertEqual(envelope["payload"]["issuedAtEpochNs"], self.epoch)
        self.assertEqual(envelope["payload"]["expiresAtEpochNs"], self.epoch + AGE)

    def test_independent_pins_exact_types_original_bytes_and_signature_precede_raw_reads(self):
        for defect in ("request", "policy", "classes", "counter", "canonical", "signature", "key"):
            values = self.inputs()
            visited = []
            values["read_original"] = lambda kind, ordinal, work: visited.append((kind, ordinal))
            if defect == "request":
                values["expectations"]["requestDigest"] = "sha256:" + "0" * 64
            elif defect == "policy":
                values["expectations"]["assertionPolicy"]["origin"] = "https://independent.invalid"
            elif defect == "classes":
                expected = values["expectations"]
                expected["businessBeforeRoots"], expected["authorizationBeforeRoots"] = (
                    expected["authorizationBeforeRoots"], expected["businessBeforeRoots"])
            elif defect == "counter":
                values["expectations"]["countedBeforeHeads"][0]["indexRevision"] = True
            elif defect == "canonical":
                values["envelope_bytes"] = b" " + values["envelope_bytes"]
            elif defect == "signature":
                envelope = json.loads(values["envelope_bytes"])
                envelope["signatureBase64Url"] = "A" * 86
                values["envelope_bytes"] = canonical(envelope)
            else:
                values["planner_public_key"] = Ed25519PrivateKey.from_private_bytes(b"z" * 32).public_key()
            with self.subTest(defect=defect), \
                    patch.object(source.clock.time, "monotonic_ns", return_value=10), \
                    patch.object(source.clock.time, "time_ns", return_value=self.epoch):
                with self.assertRaises((ValueError, InvalidSignature)):
                    source.verify_retained(**values)
            self.assertEqual(visited, [])

    def test_even_a_genuine_signature_cannot_substitute_a_claimed_result_for_full_raw_replay(self):
        manifest = json.loads(self.manifest_bytes)
        manifest["result"]["assertion_receipt_digest"] = "sha256:" + "0" * 64
        original = canonical(manifest)
        envelope = self.sign(original)
        visited = []
        def read(kind, ordinal, work):
            visited.append((kind, ordinal))
            return self.pages[kind, ordinal]
        with self.assertRaises(source.JitCompoundPlanError):
            self.verify(envelope_bytes=envelope, manifest_bytes=original, read_original=read)
        # Failure is the literal final manifest join after all genuine engines,
        # not an early refusal which accidentally avoids testing replay.
        self.assertEqual(set(visited), set(self.pages))
        self.assertEqual(len(visited), len(self.pages))
        damaged = dict(self.pages)
        proof = source.compound.frames.decode_proof(damaged["primary-proof", 7], work=meter())
        proof["rootDigest"] = "sha256:" + "f" * 64
        damaged["primary-proof", 7] = source.compound.frames.encode_proof(proof, work=meter())
        visited.clear()
        def bad_proof(kind, ordinal, work):
            visited.append((kind, ordinal))
            return damaged[kind, ordinal]
        with self.assertRaises(ValueError):
            self.verify(read_original=bad_proof)
        self.assertEqual(visited[-1], ("primary-proof", 7))
        self.assertFalse(any(kind == "index-frontier" for kind, _ordinal in visited))

    def test_later_shorter_receiver_preserves_original_interval_and_refuses_its_own_earlier_expiry(self):
        window = (self.epoch + 90, 100, 100, self.epoch + 100, 110, AGE, 0)
        values = self.inputs()
        values["live_window"] = window
        now = [105, self.epoch + 95]
        with patch.object(source.clock.time, "monotonic_ns", side_effect=lambda: now[0]), \
                patch.object(source.clock.time, "time_ns", side_effect=lambda: now[1]):
            actual = source.verify_retained(**values)
        self.assertEqual(actual.envelope_bytes, self.envelope_bytes)
        self.assertEqual(json.loads(actual.context_bytes)["originalDeadlineNs"], DEADLINE)
        visited = []
        def expire(kind, ordinal, work):
            visited.append((kind, ordinal))
            now[:] = (110, self.epoch + 100)
            return self.pages[kind, ordinal]
        values = self.inputs()
        values.update(live_window=window, read_original=expire)
        with patch.object(source.clock.time, "monotonic_ns", side_effect=lambda: now[0]), \
                patch.object(source.clock.time, "time_ns", side_effect=lambda: now[1]):
            with self.assertRaises(ValueError):
                source.verify_retained(**values)
        self.assertEqual(len(visited), 1)
        values = self.inputs()
        with patch.object(source.clock.time, "monotonic_ns", return_value=DEADLINE), \
                patch.object(source.clock.time, "time_ns", return_value=self.epoch + AGE):
            with self.assertRaises(ValueError):
                source.verify_retained(**values)

    def test_callbacks_cannot_replace_reset_spend_parent_return_verdict_or_mask_first_failure(self):
        for defect in ("limits", "reset", "parent", "verdict", "check", "exception"):
            values = self.inputs()
            parent = values["work"]
            visited = []
            sentinel = KeyboardInterrupt("synthetic original callback failure")
            def read(kind, ordinal, work):
                visited.append((kind, ordinal))
                if defect == "limits": work.limits = QueryReadValidationLimits()
                elif defect == "reset": work.input_bytes = 0
                elif defect == "parent": parent.charge(json_nodes=1)
                elif defect == "verdict": return {"verified": True}
                elif defect == "exception": raise sentinel
                return self.pages[kind, ordinal]
            values["read_original"] = read
            if defect == "check": values["check"] = lambda stage: True
            with self.subTest(defect=defect), \
                    patch.object(source.clock.time, "monotonic_ns", return_value=10), \
                    patch.object(source.clock.time, "time_ns", return_value=self.epoch):
                with self.assertRaises(KeyboardInterrupt if defect == "exception" else ValueError) as failed:
                    source.verify_retained(**values)
                if defect == "exception": self.assertIs(failed.exception, sentinel)
            self.assertEqual(len(visited), 0 if defect == "check" else 1)

    def test_external_expectation_alias_mutation_does_not_change_owned_replay_inputs(self):
        values = self.inputs()
        expected = values["expectations"]
        visited = []
        def read(kind, ordinal, work):
            visited.append((kind, ordinal))
            if len(visited) == 1:
                expected["plannerIdentity"].clear()
                expected["assertionPolicy"].clear()
                expected["businessBeforeRoots"].clear()
                expected["authorizationBeforeRoots"].clear()
                expected["countedBeforeHeads"].clear()
                expected["originalDeadlineNs"] = 1
            return self.pages[kind, ordinal]
        values["read_original"] = read
        with patch.object(source.clock.time, "monotonic_ns", return_value=10), \
                patch.object(source.clock.time, "time_ns", return_value=self.epoch):
            actual = source.verify_retained(**values)
        self.assertEqual(actual.replay.transition.result["assertion_receipt_digest"], self.receipt_digest)
        self.assertEqual(actual.manifest_bytes, self.manifest_bytes)
        self.assertEqual(len(visited), len(self.pages))


if __name__ == "__main__":
    unittest.main()
