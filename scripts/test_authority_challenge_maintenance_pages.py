"""Maintenance raw-page component controls, not native PostgreSQL admission."""
from __future__ import annotations

import ast
import hashlib
import inspect
from pathlib import Path
import unittest
from unittest import mock

from serverware import authority_contract as authority
from serverware.authority_query_read_work import _ValidationWork, QueryReadValidationLimits
from serverware.authority_store import challenge_maintenance_pages as pages


def work():
    return _ValidationWork(QueryReadValidationLimits())


def binding(body=b"{}", **changes):
    result = dict(parent_plan_digest="sha256:" + "1" * 64,
        maintenance_manifest_digest="sha256:" + "2" * 64,
        source_revision=authority.SOURCE_REVISION, operation="webauthn.challenge.maintain",
        operation_id="sha256:" + "3" * 64, request_digest="sha256:" + "4" * 64,
        configuration_digest="sha256:" + "5" * 64, phase_ordinal=0, page_kind="count",
        index_id="", page_ordinal=0, body_digest="sha256:" + hashlib.sha256(body).hexdigest(),
        body_byte_count=len(body))
    result.update(changes)
    return result


class ChallengeMaintenancePageTests(unittest.TestCase):
    def test_closed_phase_kind_index_and_ordinal_bindings(self):
        for operation in ("webauthn.challenge.create", "webauthn.challenge.maintain"):
            for phase in range(8):
                for kind in ("count", "range", "rank", "primary", "write", "candidate"):
                    allowed = (phase != 7 or kind == "count") and (
                        kind != "write" or phase not in (3, 7)) and (kind != "rank" or phase in (2, 6))
                    maximum = {"count": 2, "range": 0, "rank": 0, "primary": 255, "write": 5120,
                               "candidate": 24}[kind]
                    indexes = pages.INDEX_IDS if kind == "write" else ("",)
                    for index in indexes:
                        for ordinal in (0, maximum):
                            selected = binding(operation=operation, phase_ordinal=phase,
                                page_kind=kind, index_id=index, page_ordinal=ordinal)
                            with self.subTest(operation=operation, phase=phase, kind=kind, index=index, ordinal=ordinal):
                                if allowed:
                                    held = pages._binding(selected, work())
                                    self.assertEqual(held, selected)
                                    self.assertIsNot(held, selected)
                                else:
                                    with self.assertRaises(pages.ChallengeMaintenancePageError):
                                        pages._binding(selected, work())
        for changes in ({"phase_ordinal": True}, {"phase_ordinal": -1}, {"phase_ordinal": 8},
                {"operation": "webauthn.challenge.claim"}, {"page_kind": "row"},
                {"page_ordinal": True}, {"page_ordinal": -1}, {"page_ordinal": 3},
                {"index_id": pages.INDEX_IDS[0]}, {"page_kind": "write", "index_id": ""},
                {"page_kind": "write", "index_id": pages.INDEX_IDS[0], "page_ordinal": 5121},
                {"page_kind": "primary", "page_ordinal": 256},
                {"page_kind": "candidate", "page_ordinal": 25},
                {"page_kind": "range", "page_ordinal": 1}, {"source_revision": "old-source"},
                {"body_byte_count": 0}, {"body_byte_count": pages.MAX_BODY_BYTES + 1}, {"accepted": True}):
            with self.subTest(changes=tuple(changes)):
                with self.assertRaises(pages.ChallengeMaintenancePageError):
                    pages._binding(binding(**changes), work())

    def test_context_only_read_checks_untrusted_framing_not_parent_digest_authority(self):
        original = b'{"raw":"candidate component original"}'
        selected = binding(original, phase_ordinal=6, page_kind="candidate", page_ordinal=24)
        context = {name: selected[name] for name in pages.CONTEXT_FIELDS}
        held = pages._context(context, work())
        self.assertEqual(held, context)
        self.assertIsNot(held, context)
        row = dict(selected, body_bytes=original, retained_at_epoch_ns=17)
        self.assertIs(pages._readback(row, held, work(), original_context=True), original)
        # A different internally consistent stored body is still UNTRUSTED raw
        # evidence. Only the caller's complete manifest-chain replay admits it.
        changed = b'{"raw":"different untrusted stored bytes"}'
        different = dict(row, body_bytes=changed, body_byte_count=len(changed),
            body_digest="sha256:" + hashlib.sha256(changed).hexdigest())
        self.assertIs(pages._readback(different, held, work(), original_context=True), changed)
        with self.assertRaises(pages.ChallengeMaintenancePageError):
            pages._readback(different, selected, work())
        for name, value in (("parent_plan_digest", "sha256:" + "6" * 64),
                ("maintenance_manifest_digest", "sha256:" + "7" * 64), ("source_revision", "old-source"),
                ("operation", "webauthn.challenge.create"), ("operation_id", "sha256:" + "8" * 64),
                ("request_digest", "sha256:" + "9" * 64), ("configuration_digest", "sha256:" + "a" * 64),
                ("phase_ordinal", True), ("page_kind", "primary"), ("index_id", "unexpected"),
                ("page_ordinal", 23), ("body_digest", "sha256:" + "f" * 64),
                ("body_byte_count", True), ("body_byte_count", 0),
                ("body_byte_count", pages.MAX_BODY_BYTES + 1), ("body_bytes", memoryview(original)),
                ("retained_at_epoch_ns", True), ("accepted", True)):
            with self.subTest(field=name):
                with self.assertRaises(pages.ChallengeMaintenancePageError):
                    pages._readback(dict(row, **{name: value}), held, work(), original_context=True)
        for changes in ({"body_digest": selected["body_digest"]}, {"body_byte_count": 2},
                {"page_ordinal": True}, {"phase_ordinal": 7}, {"page_ordinal": 25}):
            with self.subTest(context_fields=tuple(changes)):
                with self.assertRaises(pages.ChallengeMaintenancePageError):
                    pages._context(dict(context, **changes), work())
        with self.assertRaises(pages.ChallengeMaintenancePageError):
            pages._readback({name: value for name, value in row.items() if name != "body_digest"},
                            held, work(), original_context=True)

    def test_raw_readback_and_original_deadline_reject_changed_evidence(self):
        original = b'{"raw":"component evidence, not a proof verdict"}'
        held = pages._binding(binding(original), work())
        row = dict(held, body_bytes=original, retained_at_epoch_ns=17)
        self.assertIs(pages._readback(row, held, work(), original=original), original)
        for name, value in (("maintenance_manifest_digest", "sha256:" + "6" * 64),
                ("parent_plan_digest", "sha256:" + "7" * 64), ("phase_ordinal", 1),
                ("page_kind", "range"), ("index_id", "unexpected"), ("page_ordinal", True),
                ("body_bytes", original + b" "), ("body_bytes", original[:-1] + b" "),
                ("body_bytes", memoryview(original)), ("retained_at_epoch_ns", True)):
            with self.subTest(field=name):
                with self.assertRaises(pages.ChallengeMaintenancePageError):
                    pages._readback(dict(row, **{name: value}), held, work(), original=original)
        called = []
        with mock.patch.object(pages.time, "monotonic_ns", side_effect=(10, 19)):
            pages._live(20, lambda: called.append("checked"), work())
        self.assertEqual(called, ["checked"])
        for times in ((20,), (10, 20), (10, 9)):
            with mock.patch.object(pages.time, "monotonic_ns", side_effect=times):
                with self.assertRaises(pages.ChallengeMaintenancePageError):
                    pages._live(20, lambda: None, work())
        budget = work()
        def replace_limits():
            budget.limits = QueryReadValidationLimits()
        with mock.patch.object(pages.time, "monotonic_ns", return_value=10):
            with self.assertRaises(ValueError):
                pages._live(20, replace_limits, budget)
        def cancel():
            raise KeyboardInterrupt()
        with mock.patch.object(pages.time, "monotonic_ns", return_value=10):
            with self.assertRaises(KeyboardInterrupt):
                pages._live(20, cancel, work())

    def test_exact_source_rosters_ddl_and_genuine_lifecycle_join(self):
        source = inspect.getsource(pages)
        tree = ast.parse(source)
        calls = [ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)]
        for name in ("lifecycle._admit", "lifecycle._call", "lifecycle._scope", "lifecycle._guard"):
            self.assertIn(name, calls)
        self.assertFalse(any(name.rsplit(".", 1)[-1] in {"connect", "commit", "rollback", "sleep"} for name in calls))
        self.assertEqual((len(pages.CONTEXT_FIELDS), len(pages.BINDING_FIELDS), len(pages.COLUMNS)), (11, 13, 15))
        root = Path(__file__).resolve().parents[1] / "serverware"
        def literal(path, name):
            selected = ast.parse(path.read_text())
            return next(ast.literal_eval(node.value) for node in selected.body
                if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == name
                    for target in node.targets))
        self.assertEqual(pages.PHASES, literal(root / "authority_challenge_compound.py", "PHASES"))
        self.assertEqual(pages.INDEX_IDS, literal(root / "authority_challenge_frontier_reader.py", "INDEX_IDS"))
        self.assertEqual(pages.MAX_WRITE_ORDINAL, (1 + 160 * 512 - 1) // 16)
        self.assertEqual(pages.MAX_CANDIDATE_ORDINAL,
                         literal(root / "authority_challenge_candidate_reader.py", "MAX_ORDINAL"))
        original = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "read_original")
        self.assertEqual(tuple(argument.arg for argument in original.args.kwonlyargs),
                         ("context", "connection", "original_deadline_ns", "check", "work"))
        dispatch = original.body[-1].value
        self.assertEqual(ast.unparse(dispatch.func), "_store")
        self.assertIs(next(ast.literal_eval(value.value) for value in dispatch.keywords
                           if value.arg == "original_context"), True)
        self.assertIn("ON CONFLICT (parent_plan_digest, maintenance_manifest_digest, phase_ordinal, page_kind, index_id, page_ordinal) DO NOTHING", pages._INSERT)
        self.assertEqual(pages._SELECT.split(" WHERE ")[1],
            "parent_plan_digest=%s AND maintenance_manifest_digest=%s AND phase_ordinal=%s "
            "AND page_kind=%s AND index_id=%s AND page_ordinal=%s")
        ddl = pages.installation_sql()
        for clause in ("body_bytes BYTEA", "octet_length(body_bytes) = body_byte_count",
                "BETWEEN 1 AND 4194304", "BETWEEN 0 AND 5120", "BETWEEN 0 AND 255", "BETWEEN 0 AND 2",
                "page_kind = 'candidate' AND page_ordinal BETWEEN 0 AND 24",
                "page_kind <> 'write' OR phase_ordinal NOT IN (3, 7)",
                "phase_ordinal <> 7 OR page_kind = 'count'", "page_kind <> 'rank' OR phase_ordinal IN (2, 6)",
                authority.SOURCE_REVISION):
            self.assertIn(clause, ddl)
        self.assertNotIn("GRANT ", ddl)


if __name__ == "__main__":
    unittest.main()
