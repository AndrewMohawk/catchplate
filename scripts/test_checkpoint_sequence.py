#!/usr/bin/env python3
"""Offline real-key checkpoint contracts; no publisher, authority or network."""
from __future__ import annotations

import copy
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import mock_open, patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import transparency_checkpoint as adapter
import verify_release_completion as completion


def wire(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


class CheckpointSequenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.key = Ed25519PrivateKey.generate()
        cls.key_info = adapter.public_key_info(cls.key.public_key())
        cls.other_key = Ed25519PrivateKey.generate()
        cls.other_info = adapter.public_key_info(cls.other_key.public_key())

    def setUp(self) -> None:
        self.provider = "local-sequence-contract-test"
        self.environment = patch.dict(os.environ, {
            "SERVERWARE_TRANSPARENCY_REQUIRE_VERIFIABLE_RECEIPT": "1",
            "SERVERWARE_TRANSPARENCY_EXPECTED_PROVIDER": self.provider,
            "SERVERWARE_TRANSPARENCY_EXPECTED_LOG_ID": self.key_info["log_id"],
        })
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.checkpoint = {
            "version": adapter.CHECKPOINT_VERSION, "sequence": 3, "tree_size": 1,
            "tree_head_hash": "sha256:" + "a" * 64, "record_digest": "sha256:" + "b" * 64,
            "leaf_hash": "sha256:" + "c" * 64,
            "signed_tree_head": {"tree_size": 1, "tree_head_hash": "sha256:" + "a" * 64},
        }
        # This slice authenticates the external receipt. Whole-log inclusion,
        # source-tree-head authenticity and release provenance are separate gates.
        self.publication = adapter.publication_request(self.checkpoint)

    def response(self, sequence: int = 1) -> dict:
        payload = adapter.receipt_payload(
            provider=self.provider, log_id=self.key_info["log_id"], external_sequence=sequence,
            request_digest=self.publication["request_digest"],
            checkpoint_digest=self.publication["checkpoint_digest"], checkpoint=self.checkpoint,
        )
        receipt = {
            "kind": "ed25519-signed-checkpoint", "payload": payload,
            "public_key_pem": self.key_info["public_key_pem"],
            "signature": adapter.sign_receipt(self.key, payload),
        }
        return {
            "ok": True, "provider": self.provider, "mode": "external-managed-transparency-log",
            "log_id": self.key_info["log_id"], "external_sequence": sequence,
            "checkpoint_digest": self.publication["checkpoint_digest"],
            "request_digest": self.publication["request_digest"],
            "tree_size": self.checkpoint["tree_size"], "tree_head_hash": self.checkpoint["tree_head_hash"],
            "receipt": receipt,
        }

    def sign_changed_payload(self, response: dict) -> None:
        # Independent signing deliberately bypasses producer validation to test
        # whether even genuinely signed malformed values fail at both consumers.
        response["receipt"]["signature"] = "ed25519:" + adapter.b64e(
            self.key.sign(wire(response["receipt"]["payload"]))
        )

    def normalize(self, response: dict) -> dict:
        return adapter.normalized_response(
            response, self.checkpoint, self.publication["request_digest"], require_verifiable_receipt=True,
        )

    def expected_receipt_fields(self) -> dict:
        return {
            **{field: self.checkpoint[field] for field in ("record_digest", "leaf_hash", "tree_head_hash", "tree_size")},
            "source_sequence": self.checkpoint["sequence"],
        }

    def verify(self, response: dict, *, expected_fields: dict | None = None) -> dict:
        return completion.verify_external_checkpoint_receipt(
            response, expected_provider=self.provider, expected_log_id=self.key_info["log_id"],
            trusted_public_key_pem=self.key_info["public_key_pem"],
            expected_fields=self.expected_receipt_fields() if expected_fields is None else expected_fields,
            label="local fixture",
        )

    def test_valid_end_to_end_sequence_boundaries_preserve_signed_bytes(self) -> None:
        self.assertEqual(adapter.MAX_CHECKPOINT_INTEGER, 9_007_199_254_740_991)
        for sequence in (1, 42, adapter.MAX_CHECKPOINT_INTEGER):
            with self.subTest(sequence=sequence):
                response = self.response(sequence)
                before = copy.deepcopy(response)
                normalized = self.normalize(response)
                self.assertEqual(normalized["external_sequence"], sequence)
                self.assertEqual(wire(normalized["receipt"]), wire(before["receipt"]))
                self.assertEqual(self.verify(normalized)["external_sequence"], sequence)
                self.assertEqual(response, before)

    def test_wrapper_and_signed_sequences_require_exact_bounded_positive_ints(self) -> None:
        invalid = [None, 0, -1, True, False, "1", "0", "+1", "01", 1.0, adapter.MAX_CHECKPOINT_INTEGER + 1]
        for location in ("wrapper", "signed"):
            for value in invalid:
                with self.subTest(location=location, value=value):
                    response = self.response()
                    target = response if location == "wrapper" else response["receipt"]["payload"]
                    target["external_sequence"] = value
                    if location == "signed":
                        self.sign_changed_payload(response)
                    expected = "external checkpoint sequence" if location == "wrapper" else "external checkpoint receipt sequence"
                    with self.assertRaisesRegex(SystemExit, expected + " must be an integer between 1 and 9007199254740991"):
                        self.normalize(response)
                    with self.assertRaisesRegex(ValueError, expected + " must be an integer between 1 and 9007199254740991"):
                        self.verify(response)

    def test_missing_sequence_is_not_defaulted_or_taken_from_other_layer(self) -> None:
        for location in ("wrapper", "signed"):
            with self.subTest(location=location):
                response = self.response()
                target = response if location == "wrapper" else response["receipt"]["payload"]
                del target["external_sequence"]
                if location == "signed":
                    self.sign_changed_payload(response)
                adapter_error = "requires exactly one of external_sequence or checkpoint_id" if location == "wrapper" else "receipt sequence must be an integer"
                completion_error = "external checkpoint sequence must be an integer" if location == "wrapper" else "receipt sequence must be an integer"
                with self.assertRaisesRegex(SystemExit, adapter_error):
                    self.normalize(response)
                with self.assertRaisesRegex(ValueError, completion_error):
                    self.verify(response)

    def test_signed_local_counters_require_exact_bounded_positive_ints(self) -> None:
        self.assertEqual(self.verify(self.normalize(self.response()))["external_sequence"], 1)
        invalid = [None, 0, -1, True, False, "1", "3", 1.0, 3.0, adapter.MAX_CHECKPOINT_INTEGER + 1]
        for field in ("tree_size", "source_sequence"):
            for value in invalid:
                with self.subTest(field=field, value=value):
                    response = self.response()
                    response["receipt"]["payload"][field] = value
                    self.sign_changed_payload(response)
                    with self.assertRaisesRegex(SystemExit, f"external checkpoint receipt {field} must be an integer between 1 and 9007199254740991"):
                        self.normalize(response)
                    with self.assertRaisesRegex(ValueError, f"external transparency receipt {field} must be an integer between 1 and 9007199254740991"):
                        self.verify(response)
            response = self.response()
            del response["receipt"]["payload"][field]
            self.sign_changed_payload(response)
            with self.assertRaisesRegex(SystemExit, f"external checkpoint receipt {field} must be an integer"):
                self.normalize(response)
            with self.assertRaisesRegex(ValueError, f"external transparency receipt {field} must be an integer"):
                self.verify(response)

    def test_trusted_expected_local_counters_are_not_equality_coerced(self) -> None:
        response = self.response()
        for field in ("tree_size", "source_sequence"):
            for value in (None, True, 1.0, 3.0, "1", 0, adapter.MAX_CHECKPOINT_INTEGER + 1):
                with self.subTest(field=field, expected=value):
                    expected = self.expected_receipt_fields()
                    expected[field] = value
                    with self.assertRaisesRegex(SystemExit, f"expected external checkpoint receipt {field} must be an integer"):
                        adapter.verify_ed25519_receipt(response["receipt"], expected, self.key_info["log_id"])
                    with self.assertRaisesRegex(ValueError, f"expected external transparency receipt {field} must be an integer"):
                        self.verify(response, expected_fields=expected)

    def test_wrapper_mismatch_and_synchronized_unsigned_tamper_are_distinct(self) -> None:
        response = self.response()
        response["external_sequence"] = 2
        with self.assertRaisesRegex(SystemExit, "receipt external_sequence does not match request"):
            self.normalize(response)
        with self.assertRaisesRegex(ValueError, "external checkpoint receipt sequence mismatch"):
            self.verify(response)
        response["receipt"]["payload"]["external_sequence"] = 2
        with self.assertRaisesRegex(SystemExit, "receipt signature did not verify"):
            self.normalize(response)
        with self.assertRaisesRegex(ValueError, "external transparency receipt signature verification failed"):
            self.verify(response)
        self.sign_changed_payload(response)
        self.assertEqual(self.verify(self.normalize(response))["external_sequence"], 2)

    def test_checkpoint_id_is_only_a_single_bounded_transport_alias(self) -> None:
        response = self.response(42)
        response["checkpoint_id"] = response.pop("external_sequence")
        normalized = self.normalize(response)
        self.assertNotIn("checkpoint_id", normalized)
        self.assertEqual(self.verify(normalized)["external_sequence"], 42)
        for value in (True, "42", 0, adapter.MAX_CHECKPOINT_INTEGER + 1):
            with self.subTest(alias=value):
                malformed = copy.deepcopy(response)
                malformed["checkpoint_id"] = value
                with self.assertRaisesRegex(SystemExit, "external checkpoint sequence must be an integer"):
                    self.normalize(malformed)
        for alias in (42, 43):
            with self.subTest(dual_alias=alias):
                response = self.response(42)
                response["checkpoint_id"] = alias
                with self.assertRaisesRegex(SystemExit, "requires exactly one of external_sequence or checkpoint_id"):
                    self.normalize(response)
                with self.assertRaisesRegex(ValueError, "must use external_sequence, not checkpoint_id"):
                    self.verify(response)
        response = self.response()
        response["receipt"]["payload"]["checkpoint_id"] = 1
        self.sign_changed_payload(response)
        with self.assertRaisesRegex(SystemExit, "receipt must use external_sequence, not checkpoint_id"):
            self.normalize(response)
        with self.assertRaisesRegex(ValueError, "must use external_sequence, not checkpoint_id"):
            self.verify(response)

    def test_independent_key_and_provider_pins_remain_required(self) -> None:
        response = self.response()
        response["log_id"] = self.other_info["log_id"]
        response["receipt"]["payload"]["log_id"] = self.other_info["log_id"]
        response["receipt"]["public_key_pem"] = self.other_info["public_key_pem"]
        response["receipt"]["signature"] = adapter.sign_receipt(self.other_key, response["receipt"]["payload"])
        with self.assertRaisesRegex(SystemExit, "did not match SERVERWARE_TRANSPARENCY_EXPECTED_LOG_ID"):
            self.normalize(response)
        with self.assertRaisesRegex(ValueError, "not the independently trusted log key"):
            self.verify(response)
        response = self.response()
        response["provider"] = "another-provider"
        response["receipt"]["payload"]["provider"] = response["provider"]
        self.sign_changed_payload(response)
        with self.assertRaisesRegex(SystemExit, "did not match SERVERWARE_TRANSPARENCY_EXPECTED_PROVIDER"):
            self.normalize(response)
        with self.assertRaisesRegex(ValueError, "not the trusted provider"):
            self.verify(response)

    def test_signer_response_form_keeps_the_same_authenticated_sequence(self) -> None:
        response = self.response(42)
        receipt = response.pop("receipt")
        response.update({"receipt_payload": receipt["payload"], "signature": receipt["signature"],
                         "public_key_pem": receipt["public_key_pem"]})
        self.assertEqual(self.verify(self.normalize(response))["external_sequence"], 42)
        response["external_sequence"] = 43
        with self.assertRaisesRegex(SystemExit, "receipt external_sequence does not match request"):
            self.normalize(response)

    def test_producer_rejects_invalid_sequences_before_signing(self) -> None:
        for sequence in (None, 0, True, "1", 1.0, adapter.MAX_CHECKPOINT_INTEGER + 1):
            with self.subTest(sequence=sequence):
                with self.assertRaisesRegex(SystemExit, "external checkpoint sequence must be an integer"):
                    self.response(sequence)
                payload = self.response()["receipt"]["payload"]
                payload["external_sequence"] = sequence
                key = SimpleNamespace(sign=lambda _: self.fail("invalid sequence reached signer"))
                with self.assertRaisesRegex(SystemExit, "receipt sequence must be an integer"):
                    adapter.sign_receipt(key, payload)
        for field in ("sequence", "tree_size"):
            for invalid in (True, "1", 0, adapter.MAX_CHECKPOINT_INTEGER + 1):
                checkpoint = copy.deepcopy(self.checkpoint)
                checkpoint[field] = invalid
                with self.assertRaisesRegex(SystemExit, f"checkpoint {field} must be an integer"):
                    adapter.publication_request(checkpoint)

    def test_disabled_verification_fails_before_http_fixture_or_signing_side_effects(self) -> None:
        response = self.response()
        with patch.object(adapter, "verify_ed25519_receipt") as verify:
            with self.assertRaisesRegex(SystemExit, "opaque checkpoint receipts are unsupported"):
                adapter.normalized_response(response, self.checkpoint, self.publication["request_digest"], require_verifiable_receipt=False)
            verify.assert_not_called()
        with patch.dict(os.environ, {"SERVERWARE_TRANSPARENCY_REQUIRE_VERIFIABLE_RECEIPT": "0"}):
            with patch.object(adapter.urllib.request, "urlopen") as post, patch.object(adapter, "load_private_key") as key, patch.object(adapter, "sign_receipt") as sign, patch.object(Path, "mkdir") as mkdir:
                for operation in (
                    lambda: adapter.checkpoint_http(self.checkpoint, "https://unused.invalid/checkpoint"),
                    lambda: adapter.checkpoint_fixture(self.checkpoint),
                ):
                    with self.assertRaisesRegex(SystemExit, "must remain enabled"):
                        operation()
                post.assert_not_called()
                key.assert_not_called()
                sign.assert_not_called()
                mkdir.assert_not_called()
            with patch.object(adapter, "read_stdin_object") as read, patch.object(adapter, "checkpoint_fixture") as fixture, patch.object(adapter, "checkpoint_http") as http:
                with self.assertRaisesRegex(SystemExit, "must remain enabled"):
                    adapter.command_checkpoint(SimpleNamespace(mode="fixture", url=None))
                with self.assertRaisesRegex(SystemExit, "must remain enabled"):
                    adapter.command_verify()
                read.assert_not_called()
                fixture.assert_not_called()
                http.assert_not_called()

    def test_duplicate_sequence_json_is_rejected_before_interpretation(self) -> None:
        raw = '{"external_sequence":1,"external_sequence":2}'
        with patch.object(adapter.sys, "stdin", io.StringIO(raw)):
            with self.assertRaisesRegex(ValueError, "duplicate JSON object key: external_sequence"):
                adapter.read_stdin_object()
        with self.assertRaisesRegex(ValueError, "duplicate JSON"):
            completion.load_json_bytes(raw.encode("utf-8"), Path("local-checkpoint.json"), "checkpoint")

    def test_exhausted_fixture_sequence_does_not_sign_or_append(self) -> None:
        opened = mock_open()
        with patch.object(Path, "mkdir"), patch.object(Path, "open", opened), patch.object(adapter.fcntl, "flock"), patch.object(adapter, "fixture_log_last_sequence_from_handle", return_value=adapter.MAX_CHECKPOINT_INTEGER), patch.object(adapter, "load_private_key") as key, patch.object(adapter, "sign_receipt") as sign:
            with self.assertRaisesRegex(SystemExit, "external checkpoint sequence must be an integer"):
                adapter.checkpoint_fixture(self.checkpoint)
            key.assert_not_called()
            sign.assert_not_called()
            opened.return_value.write.assert_not_called()

    def test_fixture_replay_requires_exact_nested_tree_size(self) -> None:
        response = self.response()
        record = {
            **response, "version": adapter.RECEIPT_VERSION,
            "received_at": "2026-09-22T00:00:00+00:00", "source_mode": None,
            "source_sequence": self.checkpoint["sequence"],
            "record_digest": self.checkpoint["record_digest"], "leaf_hash": self.checkpoint["leaf_hash"],
            "signed_tree_head": copy.deepcopy(self.checkpoint["signed_tree_head"]),
            "signature": response["receipt"]["signature"],
            "public_key_pem": response["receipt"]["public_key_pem"],
        }
        adapter.validate_fixture_log_record(record, 1, 1)
        for invalid in (True, 1.0, "1", 0, adapter.MAX_CHECKPOINT_INTEGER + 1):
            with self.subTest(nested_size=invalid):
                changed = copy.deepcopy(record)
                changed["signed_tree_head"]["tree_size"] = invalid
                with self.assertRaisesRegex(SystemExit, "signed tree size must be an integer between 1 and 9007199254740991"):
                    adapter.validate_fixture_log_record(changed, 1, 1)


if __name__ == "__main__":
    unittest.main()
