#!/usr/bin/env python3
"""Dependency-free source contract checks; not connected API/store proof.

The separate retained-store suite exercises actual ASGI authentication, JSON
parsing and transactions. These checks pin the small transport integration and
execute only the actual profile admission function, with its Google selector
replaced by an inert module. No configured application imports or runtime I/O.
"""
import ast
from pathlib import Path
import sys
from types import ModuleType
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "catchplate/operator_catalog_api.py"
DEMO = ROOT / "catchplate/operator_demo.py"
BASE = "/api/operator-demo/proxy/upstreams"


def parsed(path):
    return ast.parse(path.read_text(), filename=str(path))


def function(tree, name):
    return next(node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name)


def calls(node, name):
    return [item for item in ast.walk(node) if isinstance(item, ast.Call)
        and isinstance(item.func, ast.Name) and item.func.id == name]


def attribute(node):
    return node.value.id + "." + node.attr if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) else None


class UpstreamApiContractTests(unittest.TestCase):
    def setUp(self):
        self.api = parsed(API)

    def test_four_exact_routes_and_existing_administrator_dependency(self):
        expected = {"upstream_setup_review": ("get", "/proxy/upstreams"),
            "prepare_upstream_setup": ("post", "/proxy/upstreams"),
            "upstream_setup_status": ("get", "/proxy/upstreams/{operation_id}"),
            "cancel_upstream_setup": ("post", "/proxy/upstreams/cancel")}
        observed = {}
        for node in self.api.body:
            if not isinstance(node, ast.AsyncFunctionDef):
                continue
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Call) and decorator.args and isinstance(decorator.args[0], ast.Constant):
                    path = decorator.args[0].value
                    if isinstance(path, str) and path.startswith("/proxy/upstreams"):
                        observed[node.name] = (decorator.func.attr, path)
                        dependency = calls(node.args, "Depends")
                        self.assertEqual(len(dependency), 1)
                        self.assertEqual(dependency[0].args[0].id, "_admin_identity")
        self.assertEqual(observed, expected)

    def test_prepare_cancel_have_exact_models_limits_and_actor_source(self):
        for name, model, maximum, operation, created in (
                ("prepare_upstream_setup", "PrepareInput", 8192, "prepare", True),
                ("cancel_upstream_setup", "CancelInput", 2048, "cancel", False)):
            node = function(self.api, name)
            admit = calls(node, "_admit")[0]
            self.assertEqual([(item.arg, ast.literal_eval(item.value)) for item in admit.keywords], [("mutation", True)])
            payload = calls(node, "_payload")[0]
            self.assertEqual(attribute(payload.args[1]), "setup." + model)
            self.assertEqual(ast.literal_eval(payload.args[2]), maximum)
            result = calls(node, "_upstream_setup_result")[0]
            self.assertEqual(attribute(result.args[0]), "setup." + operation)
            self.assertEqual(result.args[1].id, "payload")
            self.assertEqual(attribute(result.args[2]), "identity.user_id")
            self.assertEqual([(item.arg, ast.literal_eval(item.value)) for item in result.keywords], [("created", True)] if created else [])
            self.assertLess(admit.lineno, payload.lineno)
            self.assertLess(payload.lineno, result.lineno)

    def test_reads_admit_before_core_and_status_validates_canonical_locator(self):
        for name, operation in (("upstream_setup_review", "review"), ("upstream_setup_status", "status")):
            node = function(self.api, name)
            admission = calls(node, "_upstream_setup_read_admission")[0]
            result = calls(node, "_upstream_setup_result")[0]
            self.assertEqual(attribute(result.args[0]), "setup." + operation)
            self.assertEqual(attribute(result.args[-1]), "identity.user_id")
            self.assertLess(admission.lineno, result.lineno)
            if operation == "status":
                validate = calls(node, "_identifier")[0]
                self.assertEqual(validate.args[0].id, "operation_id")
                self.assertLess(validate.lineno, result.lineno)
        read = function(self.api, "_upstream_setup_read_admission")
        self.assertEqual([(item.arg, ast.literal_eval(item.value)) for item in calls(read, "_admit")[0].keywords], [("mutation", False)])
        literal = {node.value for node in ast.walk(read) if isinstance(node, ast.Constant) and isinstance(node.value, str)}
        self.assertTrue({"transfer-encoding", "content-length", "0", "upstream setup status accepts no body"} <= literal)

    def test_core_failure_and_response_failure_have_fixed_no_store_outcomes(self):
        node = function(self.api, "_upstream_setup_result")
        rejection = calls(node, "_reject")
        self.assertEqual(sorted(ast.literal_eval(item.args[0]) for item in rejection), [404, 409, 422, 503, 503, 503])
        for item in rejection:
            self.assertIsInstance(item.args[1], ast.Constant)
        response = calls(node, "JSONResponse")[0]
        self.assertEqual(next(item.value.id for item in response.keywords if item.arg == "headers"), "_HEADERS")
        self.assertEqual(len(calls(node, "_blocking")), 1)
        self.assertFalse(any(isinstance(item, (ast.For, ast.While)) for item in ast.walk(node)), "transport must not replay core mutations")
        imports = [item for item in ast.walk(node) if isinstance(item, ast.ImportFrom)]
        self.assertEqual({item.module for item in imports}, {"catchplate", "catchplate.operator_catalog_schema"})

    def test_profile_admits_only_the_new_scoped_mutations(self):
        node = function(parsed(DEMO), "request_allowed")
        package, google = ModuleType("catchplate"), ModuleType("catchplate.operator_catalog_oauth_profile")
        google.selected = lambda: False
        package.operator_catalog_oauth_profile = google
        namespace = {}
        with patch.dict(sys.modules, {"catchplate": package, "catchplate.operator_catalog_oauth_profile": google}):
            exec(compile(ast.Module(body=[node], type_ignores=[]), str(DEMO), "exec"), namespace)
            allowed = namespace["request_allowed"]
            self.assertTrue(allowed("GET", BASE))
            self.assertTrue(allowed("POST", BASE))
            self.assertTrue(allowed("POST", BASE + "/cancel"))
            self.assertTrue(allowed("GET", BASE + "/10000000-0000-4000-8000-000000000001"))
            for method in ("PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
                self.assertFalse(allowed(method, BASE))
            for path in (BASE + "/prepare", BASE + "/apply", BASE + "/restart", BASE + "/10000000-0000-4000-8000-000000000001"):
                self.assertFalse(allowed("POST", path))
            self.assertFalse(allowed("GET", BASE + "/cancel"))
            self.assertFalse(allowed("POST", "/api/oauth/callback/google"))
        mutations = next(node for node in self.api.body if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "MUTATION_PATHS" for target in node.targets))
        strings = {node.value for node in ast.walk(mutations) if isinstance(node, ast.Constant) and isinstance(node.value, str)}
        self.assertTrue({"/proxy/upstreams", "/proxy/upstreams/cancel"} <= strings)


if __name__ == "__main__":
    unittest.main()
