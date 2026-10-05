"""Raw-page component controls; not a fabricated PostgreSQL admission test."""
from __future__ import annotations

import ast
import hashlib
import inspect
import unittest
from unittest import mock

from serverware import authority_contract as authority
from serverware.authority_query_read_work import _ValidationWork, QueryReadValidationLimits
from serverware.authority_store import recovery_history_pages as pages


def work():
    return _ValidationWork(QueryReadValidationLimits())


def binding(body=b"{}"):
    return dict(parent_plan_digest="sha256:" + "1" * 64, history_manifest_digest="sha256:" + "2" * 64,
        source_revision=authority.SOURCE_REVISION, operation="webauthn.recovery.create",
        operation_id="sha256:" + "3" * 64, request_digest="sha256:" + "4" * 64,
        configuration_digest="sha256:" + "5" * 64, page_kind="count", page_ordinal=0,
        body_digest="sha256:" + hashlib.sha256(body).hexdigest(), body_byte_count=len(body))


class RecoveryHistoryPageTests(unittest.TestCase):
    def test_closed_binding_and_literal_raw_readback(self):
        original = b'{"raw":"synthetic proof bytes, not a verdict"}'
        selected = binding(original)
        budget = work()
        held = pages._binding(selected, budget)
        self.assertIsNot(held, selected)
        row = dict(held, body_bytes=original, retained_at_epoch_ns=17)
        self.assertIs(pages._readback(row, held, budget, original=original), original)
        for name, value in (("parent_plan_digest", "sha256:" + "6" * 64),
                ("history_manifest_digest", "sha256:" + "7" * 64), ("page_ordinal", True),
                ("source_revision", "old-source"), ("body_bytes", original + b" "),
                ("body_bytes", original[:-1] + b" "),
                ("body_bytes", memoryview(original)), ("retained_at_epoch_ns", True)):
            with self.subTest(field=name, value_type=type(value).__name__):
                wrong = dict(row, **{name: value})
                with self.assertRaises(pages.RecoveryHistoryPageError):
                    pages._readback(wrong, held, work(), original=original)
        for name, value in (("page_ordinal", 1), ("page_ordinal", True),
                ("body_byte_count", pages.MAX_BODY_BYTES + 1), ("operation", "webauthn.recovery.invalidate"),
                ("source_revision", "old-source"), ("accepted", True)):
            with self.subTest(binding_field=name):
                with self.assertRaises(pages.RecoveryHistoryPageError):
                    pages._binding(dict(selected, **{name: value}), work())
        for ordinal in (0, pages.MAX_ROW_PAGES - 1):
            pages._binding(dict(selected, page_kind="row", page_ordinal=ordinal), work())
        for ordinal in (-1, pages.MAX_ROW_PAGES):
            with self.assertRaises(pages.RecoveryHistoryPageError):
                pages._binding(dict(selected, page_kind="row", page_ordinal=ordinal), work())
        with self.assertRaises(pages.RecoveryHistoryPageError):
            pages._body(b"[]", held, work())

    def test_original_deadline_and_work_survive_owner_callbacks(self):
        called = []
        budget = work()
        with mock.patch.object(pages.time, "monotonic_ns", side_effect=(10, 19)):
            pages._live(20, lambda: called.append("checked"), budget)
        self.assertEqual(called, ["checked"])
        for times in ((20,), (21,), (10, 20), (10, 9)):
            with self.subTest(times=times), mock.patch.object(pages.time, "monotonic_ns", side_effect=times):
                with self.assertRaises(pages.RecoveryHistoryPageError):
                    pages._live(20, lambda: None, work())
        def substitute():
            budget.limits = QueryReadValidationLimits()
        with mock.patch.object(pages.time, "monotonic_ns", return_value=10):
            with self.assertRaises(ValueError):
                pages._live(20, substitute, budget)

    def test_source_uses_real_lifecycle_and_no_connection_or_commit(self):
        # This checks integration shape only, not successful native PG behavior.
        source = inspect.getsource(pages)
        tree = ast.parse(source)
        calls = [ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)]
        for name in ("lifecycle._admit", "lifecycle._call", "lifecycle._scope", "lifecycle._guard"):
            self.assertIn(name, calls)
        self.assertFalse(any(name.rsplit(".", 1)[-1] in {"connect", "commit", "rollback", "sleep"} for name in calls))
        self.assertEqual(len(pages.COLUMNS), 13)
        self.assertIn("ON CONFLICT (parent_plan_digest, history_manifest_digest, page_kind, page_ordinal) DO NOTHING", pages._INSERT)
        ddl = pages.installation_sql()
        self.assertIn("body_bytes BYTEA", ddl)
        self.assertIn("octet_length(body_bytes) = body_byte_count", ddl)
        self.assertIn("BETWEEN 1 AND 4194304", ddl)
        self.assertIn("BETWEEN 0 AND 9999", ddl)
        self.assertIn(authority.SOURCE_REVISION, ddl)
        self.assertNotIn("GRANT ", ddl)


if __name__ == "__main__":
    unittest.main()
