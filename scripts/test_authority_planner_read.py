"""Narrow extraction controls; no planner, native database or dispatch success.

The compatibility control executes only the actual direct import statements,
not the gated planner module. The separate import control uses a fresh Python
process and the genuine read module, without substitutes or registry changes.
"""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path
import subprocess
import sys
import unittest

from serverware import authority_planner_read as source


ROOT = Path(__file__).resolve().parents[1]
MODULE = "serverware.authority_planner_read"
# Exact original definition bytes, including decorators and one final newline,
# captured immediately before the mechanical extraction. No function AST or
# predicate was changed; only its owning module and compatibility imports move.
ORIGINALS = {
    "_require_digest": "534dbd969f50ebd37f0156557aeb184fa5f8f5bba7344035a04f5ec8435ce891",
    "PlannerIdentity": "d7f6225faee86d3d8333dc8a676372ed7c2b22756800a9e709ae972093e1a96e",
    "PlannerTrace": "7fec3c230e4ca2dd03e7e63aab3ad0a368510510c821d7deac0d1e9d6ef9ec0e",
    "_validate_database_identity": "dc6dc34db16e020edd16d01c045354a3bd9968c33f139c021fa95d1e8a7f640f",
    "_load_manifest": "914ee58c7fc3c7d5902685e95e504d72ce4583fd6d3d8b72b01298261bcf0ba5",
    "_load_authorization_manifest": "3aba5675d1041558ca6b2794cec1f2391ba8565667a10ad1f27da7360ca906c1",
    "_source_admission_work": "5e6d035cd3da78e54fa2225ff41e62948bdc2526515897cb0d29973503acf985",
}


def document(name):
    raw = (ROOT / "serverware" / (name + ".py")).read_text("utf-8")
    return raw, ast.parse(raw)


def definition(tree, name):
    return next(node for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name == name)


class PlannerReadExtractionControls(unittest.TestCase):
    def test_moved_bodies_preserve_exact_original_source(self):
        raw, tree = document("authority_planner_read")
        lines = raw.splitlines(keepends=True)
        definitions = {node.name: node for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
        self.assertEqual(set(definitions), set(ORIGINALS))
        for name, expected in ORIGINALS.items():
            node = definitions[name]
            start = min([node.lineno, *(value.lineno for value in node.decorator_list)])
            original = "".join(lines[start - 1:node.end_lineno]).encode("utf-8")
            with self.subTest(name=name):
                self.assertEqual(hashlib.sha256(original).hexdigest(), expected)

    def test_actual_compatibility_imports_bind_the_same_objects(self):
        for module, names in (
            ("authority_planner", set(ORIGINALS) - {"_source_admission_work"}),
            ("authority_challenge_planning", {"_source_admission_work"}),
        ):
            _raw, tree = document(module)
            imports = [node for node in tree.body
                if isinstance(node, ast.ImportFrom) and node.module == MODULE]
            self.assertEqual(len(imports), 1)
            self.assertEqual({entry.name for entry in imports[0].names}, names)
            self.assertTrue(all(entry.asname is None for entry in imports[0].names))
            self.assertFalse(any(isinstance(node, (ast.FunctionDef, ast.ClassDef))
                and node.name in names for node in tree.body))
            namespace = {}
            # Exercise the real import statement itself; this is not a fake
            # planner module and never changes sys.modules or registry state.
            exec(compile(ast.Module(body=imports, type_ignores=[]),
                str(ROOT / "serverware" / (module + ".py")), "exec"), namespace)
            for name in names:
                self.assertIs(namespace[name], getattr(source, name))

    def test_real_read_import_does_not_import_planner_or_registry(self):
        script = (
            "import sys; sys.path.insert(0, sys.argv[1]); "
            "from serverware import authority_planner_read as source; "
            "assert source.PlannerTrace.__module__ == 'serverware.authority_planner_read'; "
            "assert 'serverware.authority_planner' not in sys.modules; "
            "assert 'serverware.authority_transition_registry' not in sys.modules; "
            "assert 'serverware.authority_service' not in sys.modules"
        )
        completed = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(ROOT)],
            check=False, capture_output=True, text=True, timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_private_trace_still_requires_exact_source_scope(self):
        operation = "jit.assertion.issue"
        default = source.PlannerTrace(operation=operation)
        with self.assertRaises(source.AuthorityPlannerError):
            default.read("webauthn_credentials",
                {"profile": "serverware.policyAuthorityJitPrimaryChunkRead/v1"})
        for arguments in (
            {"operation": "webauthn.challenge.create", "_jit_successor": True},
            {"operation": operation, "_jit_successor": 1},
            {"operation": operation, "_jit_successor": True, "_complete_queries": True},
        ):
            with self.assertRaises(source.AuthorityPlannerError):
                source.PlannerTrace(**arguments)
        trace = source.PlannerTrace(operation=operation, _jit_successor=True)
        self.assertEqual(len(trace.business_reads), 4)
        self.assertEqual(len(trace.selection_reads - trace.business_reads), 4)
        trace.read(source.authority_index_heads.HEAD_TABLE, {
            "profile": source.authority_index_heads.READ_PROFILE,
            "indexIds": list(source.authority_index_heads._jit_receipt_ids()), "rowLimit": 13,
        })
        self.assertEqual(len(trace._entries), 1)
        with self.assertRaises(source.AuthorityPlannerError):
            trace.write("policy_high_water", {"scope": "system"})

    def test_native_edges_move_but_full_registry_and_admission_gates_remain(self):
        _raw, native = document("authority_jit_compound_planning")
        imports = [node for node in ast.walk(native) if isinstance(node, ast.ImportFrom)]
        self.assertTrue(any(node.module == "serverware" and any(entry.name == "authority_planner_read"
            and entry.asname == "planner" for entry in node.names) for node in imports))
        self.assertTrue(any(node.module == MODULE and any(entry.name == "_source_admission_work"
            for entry in node.names) for node in imports))
        self.assertFalse(any(node.module == "serverware.authority_challenge_planning"
            or node.module == "serverware" and any(entry.name == "authority_planner"
                for entry in node.names) for node in imports))
        _raw, compound = document("authority_jit_compound")
        trace_imports = [node for node in ast.walk(compound) if isinstance(node, ast.ImportFrom)
            and any(entry.name == "PlannerTrace" for entry in node.names)]
        self.assertEqual(len(trace_imports), 1)
        self.assertEqual(trace_imports[0].module, MODULE)

        _raw, registry = document("authority_transition_registry")
        closure = ast.unparse(definition(registry, "_registry_closure_errors"))
        self.assertIn("_EXPECTED_SUCCESSOR_OPERATIONS - set(SUCCESSOR_PROGRAMS)", closure)
        self.assertIn("set(SUCCESSOR_PROGRAMS) - _EXPECTED_SUCCESSOR_OPERATIONS", closure)
        self.assertIn("set(authority_contract.OPERATION_REGISTRY)", closure)
        guards = [node for node in registry.body if isinstance(node, ast.If)
            and ast.unparse(node.test) == "_CLOSURE_ERRORS"]
        self.assertEqual(len(guards), 1)
        self.assertIsInstance(guards[0].body[0], ast.Raise)
        self.assertIn("authority transition registry is not closed:", ast.unparse(guards[0]))
        self.assertTrue(any(isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "_CLOSURE_ERRORS"
                for target in node.targets)
            and ast.unparse(node.value) == "_registry_closure_errors()" for node in registry.body))

        _raw, planner = document("authority_planner")
        self.assertTrue(any(isinstance(node, ast.ImportFrom) and node.module == "serverware"
            and any(entry.name == "authority_transition_registry" for entry in node.names)
            for node in planner.body))
        self.assertIn("authority_transition_registry.LEGACY_PLANNABLE_OPERATIONS",
            ast.unparse(definition(planner, "typed_request_digest")))
        self.assertIn("authority_transition_registry.LEGACY_PLANNABLE_OPERATIONS",
            ast.unparse(definition(planner, "validate_planner_request")))
        self.assertIn("set(enabled_operations) - set(authority_transition_registry.LEGACY_PLANNABLE_OPERATIONS)",
            ast.unparse(definition(planner, "MeasuredPlanner")))
        self.assertTrue(any(isinstance(node, ast.If)
            and ast.unparse(node.test) == "set(PLANNING_PROGRAMS) != set(authority_transition_registry.LEGACY_PLANNABLE_OPERATIONS)"
            and isinstance(node.body[0], ast.Raise) for node in planner.body))
        _raw, service = document("authority_service")
        self.assertTrue(any(isinstance(node, ast.ImportFrom) and node.module == "serverware"
            and any(entry.name == "authority_transition_registry" for entry in node.names)
            for node in service.body))
        self.assertIn("authority_transition_registry.PLANNABLE_OPERATIONS",
            ast.unparse(definition(service, "MeasuredConfiguration")))


if __name__ == "__main__":
    unittest.main()
