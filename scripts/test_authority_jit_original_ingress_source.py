#!/usr/bin/env python3
"""Nonimporting actual ingress linkage; not peer, signature or runtime proof.

The production module still requires genuine successor registry/handler closure.
These source controls do not substitute a shim for importing that runtime.
"""
from __future__ import annotations

import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def read(path):
    target = ROOT / path
    if target.stat().st_size > 2 * 1024 * 1024:
        raise AssertionError("source inspection exceeds its fixed bound")
    return ast.parse(target.read_bytes(), filename=path)


def definition(tree, name):
    values = [node for node in tree.body if isinstance(node, (ast.ClassDef, ast.FunctionDef))
        and node.name == name]
    if len(values) != 1:
        raise AssertionError("source definition is not unique: " + name)
    return values[0]


def calls(tree, name):
    return [node for node in ast.walk(tree) if isinstance(node, ast.Call) and ast.unparse(node.func) == name]


class JitOriginalIngressSourceControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = read("catchplate/authority_service.py")
        cls.method = definition(definition(cls.module, "AuthorityServer"), "_serve_connection")
        cls.scope = next(node for node in cls.method.body if isinstance(node, ast.Try))
        cls.route = next(node for node in cls.scope.body if isinstance(node, ast.If)
            and ast.unparse(node.test) == "prefix == jit_original_transport.REQUEST_MAGIC")

    def test_literal_transport_magic_and_import_are_distinct_from_shared_pages(self):
        imports = [alias for node in self.module.body if isinstance(node, ast.ImportFrom)
            and node.module == "catchplate" for alias in node.names
            if alias.name == "authority_jit_original_transport"]
        self.assertEqual(len(imports), 1)
        self.assertEqual(imports[0].asname, "jit_original_transport")
        actual = read("catchplate/authority_jit_original_transport.py")
        constants = {target.id: ast.literal_eval(node.value) for node in actual.body
            if isinstance(node, ast.Assign) for target in node.targets
            if isinstance(target, ast.Name) and target.id in {"REQUEST_MAGIC", "RESPONSE_MAGIC"}}
        self.assertEqual(constants, {"REQUEST_MAGIC": b"SWJO\x00\x00\x00\x01",
            "RESPONSE_MAGIC": b"SWJR\x00\x00\x00\x01"})
        self.assertTrue(any(isinstance(node, ast.If)
            and ast.unparse(node.test) == "prefix == retained_page_transport.REQUEST_MAGIC"
            for node in self.scope.body))

    def test_actual_peer_gate_precedes_prefix_and_all_detached_dispatch(self):
        peer = calls(self.method, "_peer_identity")
        prefix = calls(self.method, "writer_transport._recv_prefix")
        self.assertEqual((len(peer), len(prefix)), (1, 1))
        admission = next(node for node in self.scope.body if isinstance(node, ast.If)
            and ast.unparse(node.test) == "uid != self.peer_uid or gid != self.peer_gid")
        self.assertLess(peer[0].lineno, admission.lineno)
        self.assertLess(admission.end_lineno, prefix[0].lineno)
        self.assertLess(prefix[0].lineno, self.route.lineno)
        clauses = {ast.unparse(node.test) for node in admission.body if isinstance(node, ast.If)}
        self.assertIn("self.process.role_name != 'planner-writer'", clauses)
        self.assertIn("uid != int(verifier['serviceUid']) or gid != int(verifier['serviceGid'])", clauses)

    def test_writer_reservation_exception_cannot_enter_jit_detached_protocol(self):
        detached = next(node for node in self.scope.body if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "detached" for target in node.targets))
        self.assertIsInstance(detached.value, ast.Compare)
        self.assertEqual(ast.unparse(detached.value.left), "prefix")
        members = [ast.unparse(node) for node in detached.value.comparators[0].elts]
        self.assertEqual(members.count("jit_original_transport.REQUEST_MAGIC"), 1)
        refusal = next(node for node in self.scope.body if isinstance(node, ast.If)
            and ast.unparse(node.test) == "writer_reservation_peer and (detached or prefix in public_revocation_wire.REQUEST_MAGICS)")
        self.assertTrue(any(isinstance(node, ast.Raise) for node in refusal.body))
        self.assertLess(detached.lineno, refusal.lineno)
        self.assertLess(refusal.end_lineno, self.route.lineno)

    def test_exact_borrowed_socket_prefix_and_original_deadline_are_delegated_once(self):
        delegated = calls(self.method, "authority_jit_original_service.serve_process")
        self.assertEqual(len(delegated), 1)
        self.assertEqual(ast.unparse(delegated[0]),
            "authority_jit_original_service.serve_process(self.process, connection, deadline_ns=deadline_ns, prefix=prefix)")
        self.assertEqual(ast.unparse(self.route.body[0]), "from catchplate import authority_jit_original_service")
        self.assertIsInstance(self.route.body[-1], ast.Return)
        self.assertIsNone(self.route.body[-1].value)
        self.assertEqual(len(self.route.body), 3)
        self.assertLess(self.route.end_lineno, calls(self.method, "json.loads")[0].lineno)

    def test_detached_failure_closes_without_legacy_response_or_retry(self):
        self.assertEqual(len(self.scope.handlers), 1)
        handler = self.scope.handlers[0]
        self.assertIsInstance(handler.body[0], ast.If)
        self.assertEqual(ast.unparse(handler.body[0].test), "detached")
        self.assertEqual(len(handler.body[0].body), 1)
        self.assertIsInstance(handler.body[0].body[0], ast.Return)
        self.assertEqual([ast.unparse(node) for node in self.scope.finalbody], ["connection.close()"])
        self.assertFalse(any(isinstance(node, (ast.For, ast.While)) for node in ast.walk(self.route)))


if __name__ == "__main__":
    unittest.main()
