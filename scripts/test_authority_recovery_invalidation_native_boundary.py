"""Real recovery native setup reaches connection, never simulated SQL success.

The actual configured plan owner and read planner are used without replacing
their admission, read, or replay methods. A raised connection boundary cannot
produce or sign a plan and poisons the one-shot owner. Full operation-registry
closure remains required by real public planner and service entry points.
"""
from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from catchplate import authority_recovery_invalidation_plan_owner as source
from test_authority_recovery_invalidation_plan import (
    clocks, materials, meter, owner, produce_arguments,
)


class NativeConnectionBoundary(BaseException):
    pass


class RecoveryInvalidationNativeBoundaryControls(unittest.TestCase):
    def test_real_native_setup_stops_before_connection_and_never_signs_on_failure(self):
        parts = materials(absent=True)
        producer, work = owner(parts), meter()
        arguments = produce_arguments(parts, work)
        with clocks(parts[5]), patch.object(source.planning.physical, "_connect",
                side_effect=NativeConnectionBoundary()) as connection, \
                patch.object(source.plan, "_produce_on_work",
                    side_effect=AssertionError("failed native read reached signing")) as signing:
            with self.assertRaises(NativeConnectionBoundary):
                producer.produce(**arguments)
            connection.assert_called_once()
            self.assertIs(connection.call_args.args[0], work)
            self.assertGreater(work.hash_work, 0)
            self.assertGreater(work.input_bytes, 0)
            self.assertTrue(producer._used)
            self.assertTrue(producer._failed)
            with self.assertRaises(ValueError):
                producer.produce(**arguments)
            connection.assert_called_once()
            signing.assert_not_called()

    def test_wrong_operation_refuses_before_connection_or_signing(self):
        parts = materials(absent=True)
        producer, work = owner(parts), meter()
        arguments = produce_arguments(parts, work)
        arguments["request"]["operation"] = "jit.assertion.issue"
        with clocks(parts[5]), patch.object(source.planning.physical, "_connect") as connection, \
                patch.object(source.plan, "_produce_on_work") as signing:
            with self.assertRaises(source.plan.proof.RecoveryInvalidationError):
                producer.produce(**arguments)
            connection.assert_not_called()
            signing.assert_not_called()


if __name__ == "__main__":
    unittest.main()
