#!/usr/bin/env python3
"""Pure traversal response evidence, not reserve/dispatch/commit integration proof."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def unavailable_dependency(name: str) -> ModuleType:
    dependency = ModuleType(name)

    def reject_access(attribute: str) -> None:
        raise AssertionError(f"pure response test accessed {name}.{attribute}")

    dependency.__getattr__ = reject_access
    return dependency


# Load the actual producer, not an extracted copy. The missing authority kernels
# remain a startup blocker. No DB/runtime operation may be silently stubbed into
# success, and these pure functions must not access either dependency.
MODULE_NAME = "traversal_response_evidence_policy_engine_unit"
SPEC = importlib.util.spec_from_file_location(MODULE_NAME, ROOT / "catchplate/policy_engine.py")
assert SPEC is not None and SPEC.loader is not None
policy_engine = importlib.util.module_from_spec(SPEC)
with mock.patch.dict(sys.modules, {
    MODULE_NAME: policy_engine,
    "catchplate.db": unavailable_dependency("catchplate.db"),
    "catchplate.runtime": unavailable_dependency("catchplate.runtime"),
}):
    SPEC.loader.exec_module(policy_engine)


LINEAGE_DIGEST = "sha256:" + "a" * 64
REQUEST_CURSOR_DIGEST = "sha256:" + "b" * 64


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


class TraversalResponseEvidenceTests(unittest.TestCase):
    def flow(self, cursor_field: str = "next", record_field: str = "items") -> SimpleNamespace:
        return SimpleNamespace(metadata={
            # Presence selects the pure producer. This marker is not a validated
            # reservation and is never presented to an authority operation.
            "catchplate_durable_policy_reservation": object(),
            "catchplate_durable_policy_claims": [{
                "type": "traversalBudget",
                "constraint_id": "traversal-response",
                "lineage_digest": LINEAGE_DIGEST,
                "request_cursor_digest": REQUEST_CURSOR_DIGEST,
                "response_cursor_field": cursor_field,
                "record_count_field": record_field,
            }],
        })

    def assert_evidence(self, body: bytes, count: int, cursor: str | None,
                        cursor_field: str = "next", record_field: str = "items") -> None:
        decision, evidence = policy_engine._prepare_durable_response_evidence(
            self.flow(cursor_field, record_field), validated_decoded_body=body)
        self.assertTrue(decision.allowed, decision)
        next_digest = digest(cursor.encode("utf-8")) if cursor is not None else None
        expected = [{
            "constraint_id": "traversal-response",
            "lineage_digest": LINEAGE_DIGEST,
            "request_cursor_digest": REQUEST_CURSOR_DIGEST,
            "response_digest": digest(body),
            "next_cursor_digest": next_digest,
            "record_count": count,
            "decoded_bytes": len(body),
            "validation": "passed",
        }]
        self.assertEqual(evidence, expected)
        # The same explicit preimage is asserted in the Rust companion; neither
        # side derives its expected projection from the returned evidence.
        canonical = (
            '[{"constraint_id":"traversal-response",'
            f'"decoded_bytes":{len(body)},"lineage_digest":"{LINEAGE_DIGEST}",'
            f'"next_cursor_digest":{json.dumps(next_digest)},"record_count":{count},'
            f'"request_cursor_digest":"{REQUEST_CURSOR_DIGEST}",'
            f'"response_digest":"{digest(body)}","validation":"passed"}}]'
        ).encode("ascii")
        actual_canonical = json.dumps(evidence, ensure_ascii=True, sort_keys=True,
                                      separators=(",", ":")).encode("ascii")
        self.assertEqual(actual_canonical, canonical)
        self.assertEqual(digest(actual_canonical), digest(canonical))

    def assert_denied(self, body: bytes, detail: str, cursor_field: str = "next",
                      record_field: str = "items") -> None:
        decision, evidence = policy_engine._prepare_durable_response_evidence(
            self.flow(cursor_field, record_field), validated_decoded_body=body)
        self.assertFalse(decision.allowed, decision)
        self.assertEqual(decision.status_code, 502)
        self.assertEqual(decision.payload, {
            "error": "traversal_response_evidence_invalid", "detail": detail,
        })
        self.assertEqual(evidence, [])
        self.assertNotIn("must-not-escape", json.dumps(decision.payload))

    def test_exact_empty_single_and_nested_record_arrays(self) -> None:
        self.assert_evidence(b'{"items":[]}', 0, None)
        self.assert_evidence(b'{"items":[{"id":"one"}],"next":"c2"}', 1, "c2")
        self.assert_evidence(
            '{"page":{"items":[{"id":"é"},null,[1,2]],"next":"café"}}'.encode("utf-8"),
            3, "café", "page.next", "page.items")

    def test_missing_null_and_bounded_string_cursor(self) -> None:
        for body in (b'{"items":[]}', b'{"items":[],"next":null}'):
            with self.subTest(body=body):
                self.assert_evidence(body, 0, None)
        cursor = "é" * 2048
        body = json.dumps({"items": [], "next": cursor}, ensure_ascii=False,
                          separators=(",", ":")).encode("utf-8")
        self.assert_evidence(body, 0, cursor)

    def test_invalid_cursor_types_and_utf8_byte_bound(self) -> None:
        for cursor in ([], {"secret": "must-not-escape"}, "", True, 1,
                       "x" * 4097, "é" * 2049):
            with self.subTest(type=type(cursor).__name__, length=len(str(cursor))):
                body = json.dumps({"items": [], "next": cursor}, ensure_ascii=False,
                                  separators=(",", ":")).encode("utf-8")
                self.assert_denied(body, "traversal response cursor is invalid")

    def test_record_field_is_required_and_must_be_an_array(self) -> None:
        self.assert_denied(b'{}', "traversal response record evidence is missing")
        for records in (None, "records", 1, True, {}):
            with self.subTest(records=records):
                self.assert_denied(json.dumps({"items": records}).encode("ascii"),
                                   "traversal response record evidence is missing")

    def test_object_only_paths_preserve_absent_intermediate_semantics(self) -> None:
        for page in (None, [], "scalar"):
            with self.subTest(page=page):
                body = json.dumps({"items": [], "page": page}).encode("ascii")
                self.assert_evidence(body, 0, None, "page.next", "items")
                self.assert_denied(body, "traversal response record evidence is missing",
                                   "page.next", "page.items")

    def test_nonobject_and_malformed_json_produce_no_evidence(self) -> None:
        for body in (b'[]', b'null', b'1', b'"scalar"'):
            with self.subTest(body=body):
                self.assert_denied(body, "traversal response must be a JSON object")
        for body in (b'{', b'{"items":[],"items":[]}'):
            with self.subTest(body=body):
                decision, evidence = policy_engine._prepare_durable_response_evidence(
                    self.flow(), validated_decoded_body=body)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.status_code, 502)
                self.assertEqual(decision.payload["error"], "traversal_response_evidence_invalid")
                self.assertEqual(evidence, [])


if __name__ == "__main__":
    unittest.main()
