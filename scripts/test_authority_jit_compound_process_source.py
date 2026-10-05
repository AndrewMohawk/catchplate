#!/usr/bin/env python3
"""UNRUN nonimporting private-process linkage controls, not runtime admission.

No AuthorityProcess import or synthetic successful production is used. The
private delegate does not activate a public route, authorize a request/root,
replace jit.decide, or admit an execution result.
"""
from __future__ import annotations

import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
FIELDS = ("request", "business_before_roots", "authorization_before_roots",
    "expected_counted_heads", "live_window", "original_deadline_ns", "check", "work")


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


class JitCompoundProcessSourceControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = read("serverware/authority_service.py")
        cls.process = definition(cls.module, "AuthorityProcess")
        cls.method = definition(cls.process, "_produce_jit_compound")
        cls.service = definition(read("serverware/authority_jit_compound_service.py"),
            "_produce_on_work")

    def test_private_signature_matches_actual_service_without_optional_substitutes(self):
        for function, receiver in ((self.method, "self"), (self.service, "process")):
            self.assertEqual([arg.arg for arg in function.args.args], [receiver])
            self.assertEqual(tuple(arg.arg for arg in function.args.kwonlyargs), FIELDS)
            self.assertEqual(function.args.posonlyargs, [])
            self.assertEqual(function.args.defaults, [])
            self.assertEqual(function.args.kw_defaults, [None] * len(FIELDS))
            self.assertIsNone(function.args.vararg)
            self.assertIsNone(function.args.kwarg)
        self.assertTrue(self.method.name.startswith("_produce_"))

    def test_only_lazy_import_and_literal_return_delegate(self):
        self.assertEqual(len(self.method.body), 3)
        self.assertIsInstance(self.method.body[0], ast.Expr)
        self.assertIsInstance(self.method.body[0].value, ast.Constant)
        self.assertIn("request/root admission and execution stay upstream",
            self.method.body[0].value.value)
        imported = self.method.body[1]
        self.assertIsInstance(imported, ast.ImportFrom)
        self.assertEqual(imported.module, "serverware")
        self.assertEqual(imported.level, 0)
        self.assertEqual([(alias.name, alias.asname) for alias in imported.names],
            [("authority_jit_compound_service", "jit")])
        self.assertIsInstance(self.method.body[2], ast.Return)
        self.assertEqual(self.method.decorator_list, [])

    def test_same_process_and_every_original_are_forwarded_exactly_once(self):
        calls = [node for node in ast.walk(self.method) if isinstance(node, ast.Call)]
        self.assertEqual(len(calls), 1)
        delegated = calls[0]
        self.assertIs(self.method.body[2].value, delegated)
        self.assertEqual(ast.unparse(delegated.func), "jit._produce_on_work")
        self.assertEqual([ast.unparse(value) for value in delegated.args], ["self"])
        self.assertEqual([(item.arg, ast.unparse(item.value)) for item in delegated.keywords],
            [(name, name) for name in FIELDS])

    def test_delegate_is_not_a_public_dispatch_or_execution_route(self):
        # This slice deliberately has no activation call site. A future
        # independently admitted route must update this boundary explicitly.
        for method_name in ("handle", "_handle_runtime", "_handle_plan", "_execute_v9_operation"):
            method = definition(self.process, method_name)
            self.assertFalse(any(isinstance(node, ast.Attribute)
                and node.attr == "_produce_jit_compound" for node in ast.walk(method)))
            self.assertFalse(any(isinstance(node, ast.ImportFrom)
                and any(alias.name == "authority_jit_compound_service" for alias in node.names)
                for node in ast.walk(method)))
        self.assertFalse(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "_produce_jit_compound" for node in ast.walk(self.module)))


if __name__ == "__main__":
    unittest.main()
