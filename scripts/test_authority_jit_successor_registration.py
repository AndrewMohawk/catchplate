"""Source registration controls, not measured admission or native execution.

The inert factory uses real component classes with synthetic configuration.
The complete real registry closes with recovery explicitly disabled. Negative
controls change only one actual registration, never the operation contract or
successful admission behavior.
"""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import runpy
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from serverware import authority_contract as contract
from serverware import authority_successor_programs as source
from serverware import authority_jit_compound_production as production
from test_authority_jit_compound_production import producer


OPERATION = "jit.assertion.issue"
DISABLED_RECOVERY = frozenset({
    "webauthn.recovery.create", "webauthn.recovery.candidate",
    "webauthn.recovery.finalize", "webauthn.recovery.expire",
    "webauthn.recovery.prune", "webauthn.recovery.invalidate",
})


class JitSuccessorRegistrationControls(unittest.TestCase):
    def test_exact_program_describes_signed_original_owner(self):
        program = source.PROGRAMS[OPERATION]
        self.assertIs(type(program), source.SuccessorPlanningProgram)
        self.assertEqual(program.operation, OPERATION)
        self.assertEqual(program.handler, contract.operation_spec(OPERATION)["handler"])
        self.assertEqual(program.program_id, contract.transition_program_id(OPERATION))
        self.assertEqual(program.planning_mode, "typed-successor-planning")
        self.assertEqual(program.result_kind, "signed-originals")
        self.assertIs(program.factory, source._jit_assertion)
        self.assertIsNone(program.kernel_factory)
        self.assertIsNone(program.plan_factory)

    def test_factory_retains_real_inert_components_without_acquisition(self):
        selected = producer()
        result = source.PROGRAMS[OPERATION].factory(
            read_planner=selected._read_planner, page_caller=selected._page_caller)
        self.assertIs(type(result), production._JitCompoundProducer)
        self.assertIs(result._read_planner, selected._read_planner)
        self.assertIs(result._page_caller, selected._page_caller)
        self.assertFalse(result._used)
        self.assertFalse(selected._used)

    def test_factory_refuses_non_components_without_fallback(self):
        selected = producer()
        for reader, caller in ((object(), selected._page_caller),
                (selected._read_planner, object())):
            with self.assertRaises(production.JitCompoundProductionError):
                source.PROGRAMS[OPERATION].factory(read_planner=reader, page_caller=caller)

    def test_full_real_registry_closes_and_recovery_remains_explicitly_denied(self):
        expected = {name for name in contract.OPERATION_REGISTRY
            if contract.operation_spec(name)["planningMode"] == "typed-successor-planning"}
        self.assertEqual(expected, set(source.PROGRAMS))
        loaded = runpy.run_path(str(ROOT / "serverware" / "authority_transition_registry.py"))
        self.assertEqual(loaded["_CLOSURE_ERRORS"], ())
        self.assertEqual(loaded["_registry_closure_errors"](), ())
        self.assertIs(loaded["SUCCESSOR_PROGRAMS"], source.PROGRAMS)
        self.assertIs(loaded["successor_program"](OPERATION), source.PROGRAMS[OPERATION])
        for operation in sorted(DISABLED_RECOVERY):
            with self.subTest(operation=operation):
                self.assertEqual(contract.operation_spec(operation)["planningMode"], "intentionally-disabled")
                self.assertIn(operation, contract.INTENTIONALLY_DISABLED_OPERATIONS)
                self.assertNotIn(operation, loaded["PLANNABLE_OPERATIONS"])
                self.assertNotIn(operation, loaded["KERNELS"])
                self.assertNotIn(operation, source.PROGRAMS)
                self.assertEqual(dict(loaded["INTENTIONALLY_DISABLED_MANIFEST"][operation]), {
                    "schema": "serverware.policyAuthorityDisabledOperation/v1",
                    "operation": operation, "status": "intentionally-disabled",
                    "admissionDisposition": "deny", "kernelRegistered": False,
                    "code": "recovery-not-implemented", "externalAuthorityRequired": False,
                    "details": ("recovery is unavailable until its complete configured "
                        "successor planning and execution path is implemented",),
                })
                with self.assertRaises(ValueError):
                    loaded["successor_program"](operation)
        self.assertNotIn("jit.decide", source.PROGRAMS)

    def test_removing_one_enabled_program_refuses_actual_registry_closure(self):
        programs = dict(source.PROGRAMS)
        programs.pop(OPERATION)
        with patch.object(source, "PROGRAMS", programs), self.assertRaises(RuntimeError) as caught:
            runpy.run_path(str(ROOT / "serverware" / "authority_transition_registry.py"))
        self.assertIn("missing successor programs=[jit.assertion.issue]", str(caught.exception))
        self.assertIn("uncovered operation contracts=[jit.assertion.issue]", str(caught.exception))

    def test_disabled_recovery_cannot_be_registered_as_a_successor(self):
        for operation in sorted(DISABLED_RECOVERY):
            candidate = replace(source.PROGRAMS[OPERATION], operation=operation,
                handler=contract.operation_spec(operation)["handler"],
                program_id=contract.transition_program_id(operation),
                result_kind="read-acquisition")
            with self.subTest(operation=operation), patch.object(source, "PROGRAMS",
                    {**source.PROGRAMS, operation: candidate}), self.assertRaises(RuntimeError) as caught:
                runpy.run_path(str(ROOT / "serverware" / "authority_transition_registry.py"))
            diagnostic = str(caught.exception)
            self.assertIn("unexpected successor programs=[" + operation + "]", diagnostic)
            self.assertIn("disabled operations are plannable=[" + operation + "]", diagnostic)
            self.assertIn("planning-mode", diagnostic)


if __name__ == "__main__":
    unittest.main()
