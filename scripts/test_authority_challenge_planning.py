#!/usr/bin/env python3
"""Inert configuration, original guards and fixed setup trace components.

Native production is not invoked or replaced with a successful producer DTO.
Clock/callback doubles below prove only these local guard behaviors. Source
controls describe the native wiring, not live TLS/SQL, signing or admission.
"""
from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from catchplate import authority_challenge_planning as source
from catchplate import authority_query_read_work as measured


def digest(value):
    return "sha256:" + value * 64


def work():
    return measured._ValidationWork(measured.QueryReadValidationLimits())


def arguments():
    private = Ed25519PrivateKey.from_private_bytes(b"\x17" * 32)
    identity = dict(zip(source._IDENTITY_FIELDS, (digest("1"), digest("2"), digest("3"))))
    return dict(operation="webauthn.challenge.maintain", read_dsn="host=synthetic.invalid dbname=synthetic",
        connect_timeout_seconds=2, database_identity=("synthetic_planner", "CN=synthetic", "17", "CN=syntheticCA",
            *(identity[name] for name in source._IDENTITY_FIELDS)),
        planner_private_key=private, planner_public_key=private.public_key(), planner_identity=identity,
        planner_spki_digest=digest("4"), configuration_digest=digest("5"),
        maintenance_policy={"schema": source.policy.SCHEMA,
            **{name: bounds[0] for name, bounds in source.policy._BOUNDS.items()}},
        maximum_plan_age_ns=1000, maximum_clock_skew_ns=0)


def guard(owner, check=lambda: None, meter=None):
    # Pure clock fixture: epoch10000, mono opening10..11, deadline11000/1010.
    return source._Guard(owner, owner._configured, (10000, 10, 11, 11000, 1010, 1000, 0),
        900, check, meter or work())


class ChallengePlanningControls(unittest.TestCase):
    def test_inert_owned_configuration_and_exact_identity_policy(self):
        original = arguments()
        with patch.object(source.physical, "_connect", side_effect=AssertionError("no native connection")):
            owner = source.MaintenancePlanner(**original)
        original["planner_identity"]["measurementDigest"] = digest("a")
        original["maintenance_policy"]["maximumRetained"] = 999
        self.assertEqual(owner._configured[6][1], digest("2"))
        self.assertEqual(dict(zip(source._POLICY_FIELDS, owner._configured[9]))["maximumRetained"], 100)
        with self.assertRaises(FrozenInstanceError):
            owner._configured = ()
        for changes in (dict(connect_timeout_seconds=True), dict(connect_timeout_seconds=1),
                dict(connect_timeout_seconds=301), dict(read_dsn="host=x\npassword=hidden"),
                dict(operation="webauthn.challenge.consume"), dict(maximum_plan_age_ns=True),
                dict(planner_identity=dict(zip(source._IDENTITY_FIELDS, (digest("6"), digest("2"), digest("3"))))),
                dict(maintenance_policy={"schema": source.policy.SCHEMA})):
            selected = arguments()
            selected.update(changes)
            with self.subTest(fields=tuple(changes)), self.assertRaises(ValueError):
                source.MaintenancePlanner(**selected)

    def test_original_deadline_work_and_callback_are_not_replaceable(self):
        owner = source.MaintenancePlanner(**arguments())
        with patch.object(source.time, "monotonic_ns", return_value=20), \
                patch.object(source.plan.clock, "_check_on_work", return_value=10020):
            held = guard(owner)
            held.check()
            held._original = (*held._original[:3], 901, *held._original[4:])
            with self.assertRaises(ValueError):
                held.check()
            with self.assertRaises(ValueError):
                held.check()
            meter = work()
            held = guard(owner, lambda: setattr(meter, "hash_work", 0), meter)
            meter.charge(hashes=1)
            with self.assertRaises(ValueError):
                held.check()
            held = guard(owner, lambda: True)
            with self.assertRaises(ValueError):
                held.check()
        with patch.object(source.time, "monotonic_ns", return_value=900), \
                patch.object(source.plan.clock, "_check_on_work", return_value=10020):
            with self.assertRaises(ValueError):
                guard(owner).check()

    def test_cancellation_reentry_and_exact_native_transaction_tuple(self):
        class Cancel(BaseException):
            pass

        failure = Cancel()

        def cancel():
            raise failure

        owner = source.MaintenancePlanner(**arguments())
        with patch.object(source.time, "monotonic_ns", return_value=20), \
                patch.object(source.plan.clock, "_check_on_work", return_value=10020):
            held = guard(owner, cancel)
            with self.assertRaises(Cancel) as caught:
                held.check()
            self.assertIs(caught.exception, failure)
            self.assertTrue(held._failed)
            held = guard(owner, lambda: held.check())
            with self.assertRaises(ValueError):
                held.check()
        original = (160000, 123, "5/9", "serializable", "on", "on", "2s", "2s", "2s")
        source._same_transaction(original, original)
        for changed in ((160000, 123, "5/10", *original[3:]),
                (True, *original[1:]), (*original[:4], "off", *original[5:]), original[:-1]):
            with self.assertRaises(ValueError):
                source._same_transaction(changed, original)

    def test_fixed_ten_select_setup_trace_no_audit_completion_claim(self):
        trace = source._Trace("webauthn.challenge.maintain", work())
        sequence = [(source.transaction_source._TRANSACTION_TABLE,
            {"profile": source.transaction_source._TRANSACTION_PROFILE, "rowLimit": 2})]
        sequence += [(table, {"operation": trace.operation, "setupOrdinal": ordinal, "rowLimit": 2})
            for ordinal, table in enumerate(source._CATALOG, 1)]
        sequence += [(source.roots.PRIMARY_TABLE,
            {"profile": source._PRIMARY_PROFILE, "tableNames": ["webauthn_challenges"], "rowLimit": 2}),
            (source.heads.HEAD_TABLE, {"profile": source.heads.READ_PROFILE,
                "indexIds": list(source.manifests.WRITE_IDS), "rowLimit": 10}),
            ("pg_catalog.clock_timestamp", {"profile": source._CLOCK_PROFILE, "rowLimit": 2})]
        sequence += [sequence[0], sequence[0]]
        for table, key in sequence:
            trace.read(table, key)
        self.assertEqual(trace.position, 10)
        with self.assertRaises(ValueError):
            trace.read(*sequence[0])
        with self.assertRaises(ValueError):
            source._Trace(trace.operation, work()).read(*sequence[1])

    def test_native_wiring_uses_original_transaction_and_closes_before_return(self):
        text = Path(source.__file__).read_text(encoding="utf-8")
        tree = ast.parse(text)
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "MaintenancePlanner")
        produce = next(node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == "produce")
        calls = [ast.unparse(node.func) for node in ast.walk(produce) if isinstance(node, ast.Call)]
        self.assertIn("psycopg.connect", calls)
        self.assertIn("planner._validate_database_identity", calls)
        self.assertIn("planner._load_manifest", calls)
        self.assertIn("planner._load_authorization_manifest", calls)
        self.assertIn("snapshots.MaintenanceAcquisition", calls)
        self.assertIn("plan.produce_maintenance_parent", calls)
        self.assertNotIn("plan.clock._open_on_work", calls)
        body = ast.get_source_segment(text, produce)
        self.assertLess(body.index("setup.execute(physical._SET_TRANSACTION)"),
            body.index("original_transaction = setup.transaction_identity()"))
        self.assertLess(body.index("original_transaction = setup.transaction_identity()"),
            body.index("planner._validate_database_identity"))
        self.assertGreater(body.rindex("setup.transaction_identity()"), body.index("plan.produce_maintenance_parent"))
        self.assertLess(body.index("connection.closed is True"), body.index("return result"))


if __name__ == "__main__":
    unittest.main()
