"""UNRUN raw JIT store components/source controls, not native PG durability."""
from __future__ import annotations

import ast
import hashlib
import inspect
import unittest
from unittest import mock

from serverware import authority_contract as authority
from serverware import authority_jit_original_frames as frames
from serverware import authority_jit_primary_chunks as chunks
from serverware.authority_query_read_work import _ValidationWork, QueryReadValidationLimits
from serverware.authority_store import jit_original_pages as pages


def work():
    return _ValidationWork(QueryReadValidationLimits())


def binding(body=b"[]", **changes):
    value = dict(parent_plan_digest="sha256:" + "1" * 64,
        original_manifest_digest="sha256:" + "2" * 64,
        source_revision=authority.SOURCE_REVISION, operation="jit.assertion.issue",
        operation_id="sha256:" + "3" * 64, request_digest="sha256:" + "4" * 64,
        configuration_digest="sha256:" + "5" * 64,
        page_kind="primary-chunk", page_ordinal=0,
        body_digest="sha256:" + hashlib.sha256(body).hexdigest(), body_byte_count=len(body))
    value.update(changes)
    return value


class JitOriginalPageControls(unittest.TestCase):
    def test_exact_source_kind_ordinal_and_framing_bounds(self):
        for kind, ordinal, maximum in (("primary-chunk", 230, 262400),
                ("primary-proof", 7, 131072), ("index-frontier", 11, 4194304)):
            for last in (0, ordinal):
                original = binding(page_kind=kind, page_ordinal=last, body_byte_count=maximum)
                owned = pages._binding(original, work())
                self.assertEqual(owned, original)
                self.assertIsNot(owned, original)
            for changes in ({"page_ordinal": ordinal + 1}, {"body_byte_count": maximum + 1}):
                with self.subTest(kind=kind, changes=changes), self.assertRaises(pages.JitOriginalPageError):
                    pages._binding(binding(page_kind=kind, **changes), work())
        for changes in ({"page_ordinal": True}, {"page_ordinal": -1}, {"page_kind": "receipt"},
                {"operation": "jit.decide"}, {"source_revision": "old-source"},
                {"body_byte_count": True}, {"body_byte_count": 1}, {"body_digest": "sha256:" + "F" * 64},
                {"parent_plan_digest": "sha256:" + "0" * 64 + "\n"}, {"accepted": True}):
            with self.subTest(changes=changes), self.assertRaises(pages.JitOriginalPageError):
                pages._binding(binding(**changes), work())

    def test_context_only_read_returns_untrusted_bytes_not_a_manifest_verdict(self):
        original = b'{"raw":"synthetic original"}'
        selected = binding(original, page_kind="index-frontier", page_ordinal=11)
        context = {name: selected[name] for name in pages.CONTEXT_FIELDS}
        held = pages._context(context, work())
        self.assertEqual(held, context)
        self.assertIsNot(held, context)
        row = dict(selected, body_bytes=original, retained_at_epoch_ns=17)
        self.assertIs(pages._readback(row, held, work(), original_context=True), original)
        different = b'{"raw":"different internally consistent, still untrusted"}'
        changed = dict(row, body_bytes=different, body_byte_count=len(different),
            body_digest="sha256:" + hashlib.sha256(different).hexdigest())
        self.assertIs(pages._readback(changed, held, work(), original_context=True), different)
        with self.assertRaises(pages.JitOriginalPageError):
            pages._readback(changed, selected, work(), original=original)
        for field, value in (("parent_plan_digest", "sha256:" + "6" * 64),
                ("original_manifest_digest", "sha256:" + "7" * 64),
                ("operation_id", "sha256:" + "8" * 64), ("request_digest", "sha256:" + "9" * 64),
                ("configuration_digest", "sha256:" + "a" * 64), ("operation", "jit.decide"),
                ("source_revision", "old-source"), ("page_kind", "primary-proof"),
                ("page_ordinal", True), ("body_byte_count", True),
                ("body_digest", "sha256:" + "f" * 64), ("body_bytes", memoryview(original)),
                ("retained_at_epoch_ns", True), ("accepted", True)):
            with self.subTest(field=field), self.assertRaises(pages.JitOriginalPageError):
                pages._readback(dict(row, **{field: value}), held, work(), original_context=True)
        with self.assertRaises(pages.JitOriginalPageError):
            pages._context(dict(context, body_digest=selected["body_digest"]), work())

    def test_raw_hash_and_comparison_use_original_work_before_hashing(self):
        original = b'{"raw":"component bytes"}'
        selected = binding(original)
        meter = work()
        self.assertIs(pages._body(original, selected, meter), original)
        self.assertEqual(meter.hash_work, 1)
        self.assertGreater(meter.input_bytes, len(original))
        tiny = _ValidationWork(QueryReadValidationLimits(max_input_bytes=len(original) - 1))
        with mock.patch.object(pages.hashlib, "sha256") as hashed:
            with self.assertRaises(ValueError):
                pages._body(original, selected, tiny)
            hashed.assert_not_called()
        for changed in (original + b" ", original[:-1] + b" ", memoryview(original)):
            with self.subTest(kind=type(changed)), self.assertRaises(pages.JitOriginalPageError):
                pages._body(changed, selected, work())

    def test_original_deadline_owner_check_and_cancellation_cannot_be_replaced(self):
        called = []
        with mock.patch.object(pages.time, "monotonic_ns", side_effect=(10, 19)):
            pages._live(20, lambda: called.append("checked"), work())
        self.assertEqual(called, ["checked"])
        for times in ((20,), (10, 20), (10, 9)):
            with mock.patch.object(pages.time, "monotonic_ns", side_effect=times):
                with self.assertRaises(pages.JitOriginalPageError):
                    pages._live(20, lambda: None, work())
        meter = work()
        def replace():
            meter.limits = QueryReadValidationLimits()
        def spend():
            meter.charge(input_bytes=1)
        for callback in (replace, spend, lambda: True):
            with mock.patch.object(pages.time, "monotonic_ns", return_value=10):
                with self.assertRaises(ValueError):
                    pages._live(20, callback, meter)
        cancellation = KeyboardInterrupt()
        def cancel():
            raise cancellation
        with mock.patch.object(pages.time, "monotonic_ns", return_value=10):
            with self.assertRaises(KeyboardInterrupt) as caught:
                pages._live(20, cancel, work())
        self.assertIs(caught.exception, cancellation)

    def test_closed_ddl_and_genuine_lifecycle_without_installation_or_commit(self):
        tree = ast.parse(inspect.getsource(pages))
        calls = [ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)]
        for name in ("lifecycle._admit", "lifecycle._call", "lifecycle._scope", "lifecycle._guard"):
            self.assertIn(name, calls)
        self.assertFalse(any(name.rsplit(".", 1)[-1] in {"connect", "commit", "rollback", "sleep"} for name in calls))
        self.assertNotIn("_ValidationWork", calls)
        self.assertEqual((len(pages.CONTEXT_FIELDS), len(pages.BINDING_FIELDS), len(pages.COLUMNS)), (9, 11, 13))
        self.assertEqual(pages.MAX_CHUNK_BYTES, frames.MAX_CHUNK_BYTES)
        self.assertEqual(pages.MAX_PROOF_BYTES, frames.MAX_PROOF_BYTES)
        self.assertEqual(pages.MAX_BODY_BYTES, frames.MAX_INDEX_BYTES)
        self.assertEqual(pages.MAX_CHUNK_ORDINAL, 7 * chunks.MAX_ROW_DATA_CHUNKS - 1)
        self.assertEqual(pages._SELECT.split(" WHERE ")[1],
            "parent_plan_digest=%s AND original_manifest_digest=%s AND page_kind=%s AND page_ordinal=%s")
        self.assertIn("ON CONFLICT (parent_plan_digest, original_manifest_digest, page_kind, page_ordinal) DO NOTHING",
            pages._INSERT)
        ddl = pages.installation_sql()
        for clause in (pages.TABLE, "body_bytes BYTEA", "octet_length(body_bytes) = body_byte_count",
                "BETWEEN 2 AND 4194304", "BETWEEN 0 AND 230", "body_byte_count <= 262400",
                "BETWEEN 0 AND 7", "body_byte_count <= 131072", "BETWEEN 0 AND 11",
                "operation = 'jit.assertion.issue'", authority.SOURCE_REVISION):
            self.assertIn(clause, ddl)
        self.assertNotIn("GRANT ", ddl)
        store = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_store")
        text = ast.unparse(store)
        self.assertLess(text.index("owned ="), text.index("_live("))
        self.assertLess(text.index("_body("), text.index("_live("))
        self.assertLess(text.index("cursor.execute(_INSERT"), text.index("cursor.execute(_SELECT"))
        self.assertIn("_readback(row, owned, work, original=original_body", text)


if __name__ == "__main__":
    unittest.main()
