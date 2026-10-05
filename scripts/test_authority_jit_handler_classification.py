"""JIT source handler classification, not registry or native execution admission."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path
import unittest

from serverware import authority_contract as authority
from serverware import authority_jit_assertion_receipt as receipt


OPERATION = "jit.assertion.issue"
HANDLER = "serverware_policy_authority_jit_assertion_issue"


class JitHandlerClassificationControls(unittest.TestCase):
    def test_successor_uses_sql_family_without_a_fabricated_python_handler(self):
        spec = authority.operation_spec(OPERATION)
        self.assertEqual(spec["handler"], HANDLER)
        self.assertEqual(receipt.HANDLER, HANDLER)
        self.assertEqual(receipt.OPERATION, OPERATION)
        self.assertEqual(spec["planningMode"], "typed-successor-planning")
        self.assertEqual(authority.SQL_HANDLER_TO_OPERATION[HANDLER], OPERATION)
        self.assertNotIn(OPERATION, authority.HANDLER_TO_OPERATION.values())
        self.assertNotIn("issue_jit_assertion_receipt", authority.HANDLER_TO_OPERATION)

    def test_source_operation_changes_only_its_handler_not_its_requirements(self):
        tree = ast.parse(Path(authority.__file__).read_text("utf-8"))
        calls = [value for node in ast.walk(tree) if isinstance(node, ast.Dict)
            for key, value in zip(node.keys, node.values)
            if isinstance(key, ast.Constant) and key.value == OPERATION
            and isinstance(value, ast.Call)]
        self.assertEqual(len(calls), 1)
        call = calls[0]
        self.assertEqual(ast.dump(call.func), "Name(id='_spec', ctx=Load())")
        self.assertEqual([ast.literal_eval(value) for value in call.args], [HANDLER])
        keywords = "\n".join(ast.dump(value, include_attributes=False) for value in call.keywords)
        # Actual pre-correction keyword source from checkpoint45e5d5bd.
        self.assertEqual(hashlib.sha256(keywords.encode("ascii")).hexdigest(),
            "ab752e2bd5d77475e088dc481d42e8459e1da1f71b74aa6c0248430b1533c011")
        spec = authority.operation_spec(OPERATION)
        self.assertEqual(spec["webauthn"], "raw-assertion-verified-by-successor-kernel")
        self.assertIs(spec["approverPolicyRequired"], True)
        self.assertEqual(spec["maximumBusinessMutations"], 3)
        self.assertEqual(set(spec["businessWrites"]), {
            "webauthn_challenges", "webauthn_credentials", "jit_webauthn_assertion_receipts"})

    def test_generated_executor_stays_operation_bound_and_separate_from_handler_label(self):
        grant = authority.SQL_GRANT_MANIFEST[OPERATION]
        self.assertEqual(grant["businessHandler"], HANDLER)
        function = grant["executorHandler"]
        self.assertNotEqual(function, HANDLER)
        self.assertEqual(authority.EXECUTOR_FUNCTION_TO_OPERATION[function], OPERATION)
        self.assertEqual(authority.EXECUTOR_HANDLER_TO_OPERATIONS[function], (OPERATION,))
        self.assertIn((function, authority.EXECUTOR_ARGUMENT_TYPES, OPERATION),
            authority.EXECUTOR_FUNCTION_SIGNATURES)
        self.assertEqual(grant["executorIdentityArguments"], authority.EXECUTOR_ARGUMENT_TYPES)


if __name__ == "__main__":
    unittest.main()
