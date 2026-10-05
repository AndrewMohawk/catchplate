"""Source registration controls, not measured admission or native execution.

The inert factory uses real component classes with synthetic configuration.
The complete registry must still reject its actual missing recovery programs;
no registry, kernel, module or operation roster is substituted for that check.
"""
from __future__ import annotations

from pathlib import Path
import runpy
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from serverware import authority_contract as contract
from serverware import authority_successor_programs as source
from serverware import authority_jit_compound_production as production
from test_authority_jit_compound_production import producer


OPERATION = "jit.assertion.issue"
MISSING_RECOVERY = frozenset({
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

    def test_full_registry_still_refuses_actual_missing_recovery_programs(self):
        expected = {name for name in contract.OPERATION_REGISTRY
            if contract.operation_spec(name)["planningMode"] == "typed-successor-planning"}
        self.assertEqual(expected - set(source.PROGRAMS), MISSING_RECOVERY)
        with self.assertRaises(RuntimeError) as caught:
            runpy.run_path(str(ROOT / "serverware" / "authority_transition_registry.py"))
        diagnostic = str(caught.exception)
        self.assertIn("authority transition registry is not closed:", diagnostic)
        self.assertIn("missing successor programs=[" + ", ".join(sorted(MISSING_RECOVERY)) + "]",
            diagnostic)
        self.assertNotIn(OPERATION, diagnostic)
        self.assertNotIn("jit.decide", source.PROGRAMS)


if __name__ == "__main__":
    unittest.main()
