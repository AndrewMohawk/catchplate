"""UNRUN source/owner controls; no successful native production is simulated.

Synthetic configured objects and native clock doubles exercise original-owner
refusals. One genuine native setup stops at its connection boundary. Source
controls pin the direct acquisition/seal/sign/persist/replay call order. No SQL,
durability, currentness, authority or full-producer acceptance is claimed.
"""
from __future__ import annotations

import ast
from contextlib import contextmanager
import inspect
import os
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from serverware import authority_jit_compound_production as source
from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork


EPOCH, MONO = 1_000_000_000_000, 1_000_000
WINDOW = (EPOCH, MONO, MONO + 1, EPOCH + 1_000_000, MONO + 1_000_000,
    1_000_000, 1_000_000)
DEADLINE = MONO + 500_000


def digest(value):
    return "sha256:" + value * 64


def work():
    return _ValidationWork(QueryReadValidationLimits())


def producer(*, role="planner", owner_check=lambda meter: None):
    private = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    verifier = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    identity = (digest("1"), digest("2"), digest("3"))
    configured = source.configuration._PageConfiguration(local_role=role,
        planner_identity=identity, verifier_identity=(digest("4"), digest("5"), digest("6")),
        planner_public_key=private.public_key(), planner_spki_digest=digest("7"),
        verifier_public_key=verifier.public_key(), verifier_spki_digest=digest("8"),
        configuration_digest=digest("9"), generation_sequence=1, generation_digest=digest("a"),
        maximum_age_ns=WINDOW[5], maximum_clock_skew_ns=WINDOW[6],
        planner_endpoint=("/synthetic/planner.sock", 1000, 1000),
        writer_endpoint=("/synthetic/writer.sock", 1001, 1001), private_key=private, persistence=None)
    caller = object.__new__(source.service._PageCaller)
    for name, value in (("_configured", configured), ("_check_owner", owner_check),
            ("_window", WINDOW), ("_held", (configured, owner_check, WINDOW)),
            ("_identity", (os.getpid(), threading.get_ident()))):
        object.__setattr__(caller, name, value)
    native = source.planning.JitCompoundReadPlanner(read_dsn="host=synthetic.invalid dbname=synthetic",
        connect_timeout_seconds=2, database_identity=("synthetic_planner", "CN=synthetic", "17",
            "CN=syntheticCA", *identity), assertion_policy={"rp_id": "synthetic.invalid",
            "origin": "https://synthetic.invalid", "maximum_assertion_age_seconds": 30})
    return source._JitCompoundProducer(read_planner=native, page_caller=caller)


@contextmanager
def clocks(*, elapsed=10, epoch_elapsed=None):
    with patch.object(source.time, "monotonic_ns", return_value=MONO + elapsed), \
            patch.object(source.clock.time, "time_ns", return_value=EPOCH + (
                elapsed if epoch_elapsed is None else epoch_elapsed)):
        yield


def invocation(check=lambda stage: None):
    selected, meter = producer(), work()
    owner = source._Production(selected, WINDOW, DEADLINE, check, meter)
    return selected, meter, owner


class NativeBoundary(BaseException):
    pass


class JitCompoundProductionControls(unittest.TestCase):
    def test_constructor_is_inert_exact_and_planner_only(self):
        with patch.object(source.planning.physical, "_connect", side_effect=AssertionError("native")), \
                patch.object(source.service._PageCaller, "_live", side_effect=AssertionError("clock")):
            value = producer()
            self.assertFalse(value._used)
        with self.assertRaises(ValueError):
            producer(role="verifier")
        with self.assertRaises(ValueError):
            source._JitCompoundProducer(read_planner=object(), page_caller=object())
        value._read_planner = object()
        with self.assertRaises(ValueError):
            value._local()

    def test_invalid_actual_request_stops_before_native_and_owner_is_one_shot(self):
        value = producer()
        arguments = dict(request={}, business_before_roots=({},) * 4,
            authorization_before_roots=({},) * 4, expected_counted_heads=({},) * 12,
            live_window=WINDOW, original_deadline_ns=DEADLINE, check=lambda stage: None, work=work())
        with patch.object(source.planning.physical, "_connect") as native:
            with self.assertRaises(ValueError):
                value.produce(**arguments)
            self.assertTrue(value._used)
            with self.assertRaises(ValueError):
                value.produce(**arguments)
            native.assert_not_called()

    def test_genuine_setup_reaches_connection_only_and_never_seals_on_failure(self):
        from test_authority_jit_connected_originals import connected_fixture
        case = connected_fixture()
        value = producer()
        observed = []
        heads = tuple({"indexId": head.index_id, "indexRevision": head.index_revision,
            "rootDigest": head.index_root.digest, "leafCount": head.index_root.count}
            for head in case["counted_before_heads"])
        with clocks(), patch.object(source.planning.physical, "_connect", side_effect=NativeBoundary()) as native, \
                patch.object(source.spool_source._JitOriginalSpool, "seal", side_effect=AssertionError("seal")) as seal:
            with self.assertRaises(NativeBoundary):
                value.produce(request=case["request"],
                    business_before_roots=tuple(root.json_projection() for root in case["business_before_roots"]),
                    authorization_before_roots=tuple(root.json_projection() for root in case["authorization_before_roots"]),
                    expected_counted_heads=heads, live_window=WINDOW, original_deadline_ns=DEADLINE,
                    check=lambda stage: observed.append(stage), work=work())
            native.assert_called_once()
            seal.assert_not_called()
        self.assertTrue(observed)
        self.assertTrue(all(type(stage) is source._ProductionStage and stage.name == "native"
            for stage in observed))

    def test_original_shorter_epoch_monotonic_and_process_bounds_are_not_renewed(self):
        for change in (lambda owner: setattr(owner, "deadline", DEADLINE + 1),
                lambda owner: setattr(owner, "expires", owner.expires + 1),
                lambda owner: setattr(owner, "process", (-1, -1))):
            _selected, meter, owner = invocation()
            change(owner)
            with clocks(), self.assertRaises(ValueError):
                owner.live(meter)
        for values in (dict(elapsed=500_000), dict(elapsed=10, epoch_elapsed=600_000)):
            _selected, meter, owner = invocation()
            # Both cases remain within the broader WINDOW; original shorter
            # bounds still refuse. The second is within its selected skew.
            with clocks(**values), self.assertRaises(ValueError):
                owner.live(meter)

    def test_fixed_stage_order_original_limits_counters_and_late_spending(self):
        _selected, _meter, owner = invocation()
        owner.freeze(1)
        with clocks(), self.assertRaises(ValueError):
            with owner.stage("sign"):
                self.fail("skipped source seal")
        for replace_limits in (False, True):
            _selected, _meter, owner = invocation()
            owner.freeze(1)
            with clocks(), self.assertRaises(ValueError):
                with owner.stage("seal") as stage:
                    stage.work.charge(input_bytes=8)
                    owner.live(stage.work)
                    if replace_limits:
                        stage.work.limits = QueryReadValidationLimits()
                    else:
                        stage.work.input_bytes = 7
                    owner.live(stage.work)
            self.assertTrue(owner.failed)
        _selected, _meter, owner = invocation()
        owner.freeze(1)
        with clocks():
            with owner.stage("seal") as stage:
                stage.work.charge(input_bytes=1)
            stage.work.charge(input_bytes=1)
            with self.assertRaises(ValueError):
                owner.local()

    def test_sealed_work_identity_cannot_be_replaced_by_equal_counters(self):
        _selected, _meter, owner = invocation()
        owner.freeze(1)
        with clocks():
            with owner.stage("seal") as stage:
                stage.work.charge(input_bytes=1)
            original = stage.work
            replacement = work()
            replacement.limits = original.limits
            for name in source._COUNTERS:
                setattr(replacement, name, getattr(original, name))
            object.__setattr__(stage, "work", replacement)
            original.charge(input_bytes=1)
            with self.assertRaises(ValueError):
                owner.local()

    def test_callback_cancellation_parent_spend_and_reentry_poison(self):
        for mode in ("cancel", "parent", "reentry"):
            holder = {}
            def check(stage):
                if mode == "cancel":
                    raise NativeBoundary()
                if mode == "parent":
                    holder["meter"].charge(input_bytes=1)
                else:
                    holder["owner"].checked(stage)
            _selected, meter, owner = invocation(check)
            holder.update(meter=meter, owner=owner)
            owner.freeze(1)
            expected_error = NativeBoundary if mode == "cancel" else ValueError
            with clocks(), self.assertRaises(expected_error):
                with owner.stage("seal"):
                    self.fail("callback refusal required")
            self.assertTrue(owner.failed)

    def test_source_calls_real_components_in_order_and_rechecks_after_output(self):
        text = inspect.getsource(source._JitCompoundProducer.produce)
        order = [text.index(value) for value in ("native = self._read_planner.acquire_pass(",
            "spool.seal(", "plan._sign_parent_on_work(", "self._page_caller.persist(", "plan.verify_retained(")]
        self.assertEqual(order, sorted(order))
        self.assertEqual(text.count(".acquire_pass("), 1)
        self.assertIn('"maximumPlanAgeNs": owner.window[5]', text)
        self.assertIn('"maximumClockSkewNs": owner.window[6]', text)
        self.assertIn("result = owner.finish(native, verified)\n            owner.live(work)\n            return result", text)
        module = ast.parse(inspect.getsource(source))
        creates = [node for node in ast.walk(module) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name) and node.func.id == "_ValidationWork"]
        self.assertEqual(len(creates), 1)
        self.assertNotIn("_open_on_work", inspect.getsource(source))
        self.assertIn("stage.work.charge(input_bytes=2 * 1024 * 1024, json_nodes=131072)",
            inspect.getsource(source.compound._Invocation._stage))


if __name__ == "__main__":
    unittest.main()
