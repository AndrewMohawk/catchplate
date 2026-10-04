#!/usr/bin/env python3
"""Focused generic-API classification controls; no app startup or authority calls."""
from __future__ import annotations

import ast
import copy
from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace
import unittest

from fastapi import HTTPException
from serverware import authority_contract


SOURCE = Path(__file__).resolve().parents[1] / "serverware/app.py"
CATEGORIES = (
    "_CONTROLLED_AUTHORITY_OPERATOR_ROLES",
    "_SPECIALIZED_AUTHORITY_OPERATIONS",
    "_INTERNAL_ONLY_AUTHORITY_OPERATIONS",
    "_DEDICATED_WORKFLOW_AUTHORITY_OPERATIONS",
)
GUARD_ERROR = "authority API operation classification is incomplete"


@lru_cache(maxsize=1)
def app_source():
    return ast.parse(SOURCE.read_text(encoding="utf-8"))


def classifications(operations=None):
    names = {*CATEGORIES, "_KNOWN_AUTHORITY_OPERATION_CLASSIFICATIONS"}
    nodes = [node for node in app_source().body
             if isinstance(node, ast.Assign)
             and any(isinstance(target, ast.Name) and target.id in names
                     for target in node.targets)]
    assert len(nodes) == len(names)
    guards = [node for node in app_source().body
              if isinstance(node, ast.If)
              and any(isinstance(part, ast.Constant) and part.value == GUARD_ERROR
                      for part in ast.walk(node))]
    assert len(guards) == 1
    roles = next(node for node in app_source().body
                 if isinstance(node, ast.FunctionDef)
                 and node.name == "_authority_operator_roles")
    namespace = {"authority_contract": SimpleNamespace(
        OPERATIONS=authority_contract.OPERATIONS if operations is None else operations)}
    exec(compile(ast.Module(body=[*nodes, *guards, roles], type_ignores=[]),
                 str(SOURCE), "exec"), namespace)
    return namespace


def generic_route_prefix(name, namespace):
    """Execute the real denial prefix only, before any DB/custody operation."""
    function = copy.deepcopy(next(node for node in app_source().body
                                 if isinstance(node, ast.FunctionDef) and node.name == name))
    variable = ("required_roles" if name == "authority_webauthn_challenge"
                else "allowed_roles")
    stop = next(index for index, node in enumerate(function.body)
                if isinstance(node, ast.If) and any(
                    isinstance(part, ast.Compare)
                    and isinstance(part.left, ast.Name) and part.left.id == variable
                    and len(part.ops) == 1 and isinstance(part.ops[0], ast.Is)
                    and isinstance(part.comparators[0], ast.Constant)
                    and part.comparators[0].value is None
                    for part in ast.walk(node.test)))
    function.body = function.body[:stop + 1]
    function.decorator_list = []
    function.returns = None
    function.args.defaults = []
    for argument in function.args.args:
        argument.annotation = None
    namespace.update(authority_contract=authority_contract, HTTPException=HTTPException)
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(SOURCE), "exec"), namespace)
    return namespace[name]


class AuthorityApiClassificationTests(unittest.TestCase):
    def test_full_app_import_registers_attestation_without_response_model(self):
        # Import registers routes; never enter the ASGI lifespan or call a handler.
        from serverware import app

        routes = [route for route in app._fastapi_app.routes
                  if getattr(route, "path", None) == "/attestation"
                  and "GET" in route.methods]
        self.assertEqual(len(routes), 1)
        self.assertIsNone(routes[0].response_model)
        self.assertIsNone(routes[0].response_field)

    def test_actual_registry_has_explicit_disjoint_classifications(self):
        namespace = classifications()
        groups = [set(namespace[name]) for name in CATEGORIES]
        self.assertEqual(len(namespace[CATEGORIES[-1]]), 147)
        for index, group in enumerate(groups):
            for other in groups[index + 1:]:
                self.assertFalse(group & other)
        known = namespace["_KNOWN_AUTHORITY_OPERATION_CLASSIFICATIONS"]
        self.assertTrue(known <= set(authority_contract.OPERATIONS))
        self.assertTrue(all(operation in known or operation.startswith("policy.")
                            for operation in authority_contract.OPERATIONS))

    def test_dedicated_and_internal_operations_have_no_generic_roles(self):
        namespace = classifications()
        denied = namespace[CATEGORIES[-1]] | namespace[CATEGORIES[-2]]
        for operation in denied:
            with self.subTest(operation=operation):
                self.assertIsNone(namespace["_authority_operator_roles"](operation))

    def test_both_generic_routes_deny_dedicated_operations_before_effects(self):
        namespace = classifications()
        challenge = generic_route_prefix("authority_webauthn_challenge", namespace)
        execute = generic_route_prefix("execute_control_plane_authority_operation", namespace)

        def roles_must_not_be_consulted(_):
            raise AssertionError("dedicated operation reached generic role evaluation")

        identity = SimpleNamespace(has_any_role=roles_must_not_be_consulted)
        for operation in namespace[CATEGORIES[-1]]:
            payload = SimpleNamespace(operation=operation)
            with self.subTest(operation=operation):
                with self.assertRaises(HTTPException) as denied:
                    execute(SimpleNamespace(), payload, identity)
                self.assertEqual(denied.exception.status_code, 400)
                with self.assertRaises(HTTPException) as denied:
                    challenge(payload, identity)
                expected = 403 if authority_contract.operation_spec(operation)["assertionRequired"] else 400
                self.assertEqual(denied.exception.status_code, expected)

    def test_existing_operator_roles_and_policy_fallback_are_preserved(self):
        namespace = classifications()
        roles = namespace["_authority_operator_roles"]
        for operation, expected in namespace[CATEGORIES[0]].items():
            self.assertEqual(roles(operation), expected)
        self.assertEqual(roles("rbac.binding.mutate"), frozenset({"admin"}))
        self.assertEqual(roles("policy.activation.prepare"), frozenset({"policy_publisher"}))
        self.assertIsNone(roles("unclassified.synthetic-operation"))

    def test_unknown_or_retired_operation_still_fails_completeness_guard(self):
        actual = set(authority_contract.OPERATIONS)
        for operations in (actual | {"setup.synthetic-new-operation"},
                           actual - {"setup.policy.bind-candidate"}):
            with self.subTest(operations_changed=len(operations)):
                with self.assertRaisesRegex(RuntimeError, GUARD_ERROR):
                    classifications(operations)


if __name__ == "__main__":
    unittest.main()
