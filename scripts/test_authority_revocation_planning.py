#!/usr/bin/env python3
"""Truthful inert observed-planning ownership and driver-guard components.

The real configuration/capture helpers and guarded cursor components are the
subjects. Genuine keys, signed fixture evidence and full root observations
supply input data, not admission or a successful planner result. This fixture
never calls produce_observed, imports the active planner, replaces a registry,
extracts a production body, or stubs a successful proof/producer. Synthetic
driver events establish only the particular guard/cleanup behavior tested.
All controls are authored source, not executed verification evidence.
"""
from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate import authority_query_read_work as accounting
from catchplate import authority_revocation_planning as planning
import test_authority_revocation_capability_producer as key_oracle
import test_authority_revocation_observed as observed_oracle
import test_authority_revocation_plan as oracle
import test_authority_revocation_roots as root_oracle
import test_authority_revocation_verifier as verifier_oracle


IDENTITY_FIELDS = ("sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest")
CALL_FIELDS = ("expectedCapabilityId", "expectedPlannerTransactionId", "expectedFence",
    "expectedApproverPolicyDigest", "reservedAtEpochNs", "deadlineEpochNs", "deadlineMonotonicNs",
    "nowEpochNs", "nowMonotonicNs")
CONFIGURED_FIELDS = ("expectedPlannerIdentity", "expectedVerifierIdentity", "maximumAssertionAgeNs",
    "maximumPlanAgeNs", "maximumClockSkewNs")


class PlanningFixture:
    def __init__(self):
        self.verifier = verifier_oracle.VerifierFixture(approval=False, include_audit=False)
        self.handoff = self.verifier.handoff
        self.request = copy.deepcopy(self.handoff.request)
        self.evidence = copy.deepcopy(self.handoff.plan.semantic.receipt.evidence)
        self.context = copy.deepcopy(self.verifier.context)
        self.inventory = self.handoff.inventory
        self.database_identity = ("fixture_planner_read", "CN=fixture-planner", "17", "CN=fixture-ca",
            *(self.handoff.plan.identity[name] for name in IDENTITY_FIELDS))

    def constructor_arguments(self):
        plan = self.handoff.plan
        return {"read_dsn": "postgresql://fixture-planner-read.invalid/fixture", "connect_timeout_seconds": 2,
            "database_identity": self.database_identity, "planner_private_key": plan.key,
            "planner_public_key": plan.key.public_key(), "verifier_public_key": plan.semantic.receipt.key.public_key(),
            "expected_verifier_identity": copy.deepcopy(plan.semantic.receipt.identity),
            "maximum_assertion_age_ns": 90_000_000_000, "maximum_plan_age_ns": 30_000_000_000,
            "maximum_clock_skew_ns": 5_000_000_000}

    def arguments(self):
        return {"request": self.request, "evidence": self.evidence, "context": self.context,
            "root_inventory": self.inventory}

    def expected_context(self):
        return {**copy.deepcopy(self.context),
            "expectedPlannerIdentity": dict(zip(IDENTITY_FIELDS, self.database_identity[4:])),
            "expectedVerifierIdentity": copy.deepcopy(self.handoff.plan.semantic.receipt.identity),
            "maximumAssertionAgeNs": 90_000_000_000, "maximumPlanAgeNs": 30_000_000_000,
            "maximumClockSkewNs": 5_000_000_000}


def independent_capture_work(fixture):
    # Actual CopyBudget scalar rules: strings1L1N, int/bool/null3L3N;
    # containers pay their real conservative separators. No proof/hash pass.
    return observed_oracle.add(observed_oracle.copy_cost({"request": fixture.request,
            "evidence": fixture.evidence, "context": fixture.context}),
        observed_oracle.copy_cost(observed_oracle.capture_graph(fixture.handoff.primary, fixture.handoff.heads)))


class Driver:
    """Method/attribute event model, not SQL or connection admission."""

    def __init__(self, callback=None):
        self.closed, self.autocommit = False, False
        self.pgconn = object()
        self.info = SimpleNamespace(transaction_status=2)
        self.callback, self.events, self.calls = callback, [], []
        self.rows = [{"fixture": 1}, {"fixture": 2}]
        self.result = Result(self)
        self.cursor = Cursor(self)
        self.closes = 0

    def event(self, name):
        self.events.append(name)
        if self.callback is not None: self.callback(name)

    def close(self):
        self.closes += 1
        self.closed = True
        self.event("close")


class Cursor:
    def __init__(self, driver):
        self.driver = driver

    @property
    def execute(self):
        self.driver.event("execute.lookup")
        return self._execute

    def _execute(self, *arguments):
        self.driver.calls.append(arguments)
        self.driver.event("execute.call")
        return self.driver.result


class Result:
    def __init__(self, driver):
        self.driver = driver

    @property
    def fetchone(self):
        self.driver.event("fetchone.lookup")
        def fetch():
            self.driver.event("fetchone.call")
            return self.driver.rows[0]
        return fetch

    @property
    def fetchall(self):
        self.driver.event("fetchall.lookup")
        def fetch():
            self.driver.event("fetchall.call")
            return self.driver.rows
        return fetch

    @property
    def fetchmany(self):
        self.driver.event("fetchmany.lookup")
        def fetch(size):
            self.driver.calls.append(("fetchmany", size))
            self.driver.event("fetchmany.call")
            return self.driver.rows[:size]
        return fetch


class Scope:
    """Explicit context event model; never represents a planner transaction."""

    def __init__(self, callback=None, *, suppress=False):
        self.callback, self.suppress = callback, suppress
        self.enters = self.exits = self.commits = self.rollbacks = 0
        self.errors = []

    def __enter__(self):
        self.enters += 1
        if self.callback is not None: self.callback("enter")
        return self

    def __exit__(self, kind, error, traceback):
        self.exits += 1
        self.errors.append(error)
        if kind is None: self.commits += 1
        else: self.rollbacks += 1
        if self.callback is not None: self.callback("exit")
        return self.suppress


class RevocationPlanningTests(unittest.TestCase):
    def owner(self, fixture, **changes):
        return planning.RevocationObservedPlanner(**{**fixture.constructor_arguments(), **changes})

    def capture(self, fixture, *, owner=None, meter=None, **changes):
        owner = self.owner(fixture) if owner is None else owner
        return planning._capture_planning_inputs(owner._snapshot_configuration(),
            work=observed_oracle.work() if meter is None else meter, **{**fixture.arguments(), **changes})

    def test_inert_constructor_owns_exact_ten_settings_without_key_callbacks(self):
        fixture, events = PlanningFixture(), []
        supplied = fixture.constructor_arguments()
        private = key_oracle._ObservedPrivateKey(supplied["planner_private_key"],
            callback=lambda: events.append("sign"), public_callback=lambda: events.append("derive"))
        planner = key_oracle._ObservedPublicBytes(supplied["planner_public_key"], callback=lambda: events.append("planner DER"))
        verifier = key_oracle._ObservedPublicBytes(supplied["verifier_public_key"], callback=lambda: events.append("verifier DER"))
        supplied.update(planner_private_key=private, planner_public_key=planner, verifier_public_key=verifier)
        owner = planning.RevocationObservedPlanner(**supplied)
        snapshot = owner._snapshot_configuration()
        self.assertEqual(len(snapshot), 10)
        self.assertEqual(snapshot[:3], (supplied["read_dsn"], 2, fixture.database_identity))
        self.assertIs(snapshot[3], private)
        self.assertIs(snapshot[4], planner)
        self.assertIs(snapshot[5], verifier)
        self.assertEqual(snapshot[6:], (tuple(supplied["expected_verifier_identity"][name] for name in IDENTITY_FIELDS),
            90_000_000_000, 30_000_000_000, 5_000_000_000))
        supplied["expected_verifier_identity"].clear()
        self.assertIs(owner._snapshot_configuration(), snapshot)
        self.assertEqual((events, private.calls, planner.calls, verifier.calls), ([], 0, 0, 0))
        with self.assertRaises(FrozenInstanceError): owner._configuration = ()

    def test_constructor_bounds_and_identity_policy_inventory_are_not_caller_extensions(self):
        fixture = PlanningFixture()
        invalid = [("read_dsn", value) for value in (None, "", "x" * 65537)]
        invalid.extend(("connect_timeout_seconds", value) for value in (True, 0, 1, 1.25, 1.999, 2.0, 301))
        invalid.extend((name, object()) for name in ("planner_private_key", "planner_public_key", "verifier_public_key"))
        invalid.extend(("maximum_assertion_age_ns", value) for value in (True, 0, 1.0, 2**63))
        invalid.extend(("maximum_plan_age_ns", value) for value in (True, 0, 30_000_000_001))
        invalid.extend(("maximum_clock_skew_ns", value) for value in (True, 0, 5_000_000_001))
        invalid.extend(("database_identity", value) for value in (list(fixture.database_identity),
            fixture.database_identity[:-1], (*fixture.database_identity, "extra"),
            ("", *fixture.database_identity[1:]), (*fixture.database_identity[:4], "bad", *fixture.database_identity[5:])))
        for name, value in invalid:
            with self.subTest(field=name, value=type(value).__name__), self.assertRaises(ValueError):
                self.owner(fixture, **{name: value})
        for identity in ({}, {**fixture.handoff.plan.semantic.receipt.identity, "extra": oracle.sha(b"extra")}):
            with self.assertRaises(ValueError): self.owner(fixture, expected_verifier_identity=identity)
        for timeout in (2, 300):
            self.assertEqual(self.owner(fixture, connect_timeout_seconds=timeout)._snapshot_configuration()[1], timeout)
        with self.assertRaises(TypeError): self.owner(fixture, persistence=object())
        with self.assertRaises(TypeError): self.owner(fixture, producer=lambda: None)

    def test_real_capture_owns_request_evidence_context_and_full_seven_two_nine_observations(self):
        fixture = PlanningFixture()
        expected = independent_capture_work(fixture)
        meter = observed_oracle.work((1, expected[1], expected[2]))
        owned, context, inventory = self.capture(fixture, meter=meter)
        self.assertEqual(owned, {"request": fixture.request, "evidence": fixture.evidence, "context": fixture.context})
        self.assertEqual(context, fixture.expected_context())
        self.assertEqual(set(context), set(CALL_FIELDS + CONFIGURED_FIELDS))
        self.assertEqual(inventory, fixture.inventory)
        self.assertIsNot(inventory, fixture.inventory)
        self.assertEqual((len(inventory.business_roots), len(inventory.authorization_roots), len(inventory.counted_heads)), (7, 2, 9))
        self.assertEqual(planning.observed._inventory_before(inventory),
            observed_oracle.expected_before(fixture.handoff.primary, fixture.handoff.heads))
        self.assertEqual(observed_oracle.metrics(meter), expected)
        self.assertEqual(expected[0], 0)
        self.assertEqual((len(fixture.handoff.acquisition[0].calls), fixture.handoff.acquisition[4].returned_rows), (2, 18))

    def test_closed_nine_field_input_cannot_supply_roots_cutoff_keys_or_configured_context(self):
        fixture = PlanningFixture()
        contexts = [{**fixture.context, name: fixture.expected_context()[name]} for name in CONFIGURED_FIELDS]
        contexts.extend({**fixture.context, name: None} for name in ("expectedBefore", "databaseCutoffUs", "database_now"))
        contexts.extend({name: value for name, value in fixture.context.items() if name != omitted} for omitted in CALL_FIELDS)
        contexts.extend({**fixture.context, name: True} for name in ("expectedFence", "nowEpochNs", "nowMonotonicNs"))
        contexts.extend(({**fixture.context, "expectedCapabilityId": "sha256:" + "A" * 64},
            {**fixture.context, "nowEpochNs": fixture.context["deadlineEpochNs"]},
            {**fixture.context, "deadlineMonotonicNs": fixture.context["nowMonotonicNs"]}))
        for context in contexts:
            with self.subTest(context_fields=tuple(context)), self.assertRaises(ValueError):
                self.capture(fixture, context=context)
        for changes in ({"request": None}, {"evidence": None}, {"root_inventory": object()}, {"context": []}):
            with self.assertRaises(ValueError): self.capture(fixture, **changes)
        for name in ("planner_public_key", "planner_private_key", "verifier_public_key", "opener", "producer"):
            with self.assertRaises(TypeError): self.capture(fixture, **{name: object()})

    def test_capture_detaches_original_aliases_and_retains_full_source_inventory(self):
        fixture = PlanningFixture()
        expected_request, expected_evidence = copy.deepcopy(fixture.request), copy.deepcopy(fixture.evidence)
        expected_context = fixture.expected_context()
        expected_before = observed_oracle.expected_before(fixture.handoff.primary, fixture.handoff.heads)
        owned, context, inventory = self.capture(fixture)
        fixture.request["arguments"]["reason"] = "changed after ownership"
        fixture.evidence.clear()
        fixture.context.clear()
        object.__setattr__(fixture.inventory.business_roots[0], "root_digest", oracle.sha(b"changed original root"))
        object.__setattr__(fixture.inventory.counted_heads[-1].index_root, "digest", oracle.sha(b"changed original head"))
        self.assertEqual((owned["request"], owned["evidence"]), (expected_request, expected_evidence))
        self.assertEqual(context, expected_context)
        self.assertEqual(planning.observed._inventory_before(inventory), expected_before)
        self.assertEqual(len(inventory.counted_heads), 9)
        owned["request"]["arguments"]["reason"] = "owned local change"
        self.assertEqual(expected_request["arguments"]["reason"], fixture.handoff.request["arguments"]["reason"])

    def test_capture_rejects_malformed_inventory_and_json_without_claiming_evidence_verification(self):
        fixture = PlanningFixture()
        inventory = fixture.inventory
        variants = (replace(inventory, business_roots=inventory.business_roots[:-1]),
            replace(inventory, authorization_roots=tuple(reversed(inventory.authorization_roots))),
            replace(inventory, counted_heads=(*inventory.counted_heads, inventory.counted_heads[0])),
            replace(inventory, business_roots=(replace(inventory.business_roots[0], root_revision=True), *inventory.business_roots[1:])),
            replace(inventory, counted_heads=(replace(inventory.counted_heads[0], index_revision=True), *inventory.counted_heads[1:])))
        for value in variants:
            with self.assertRaises(ValueError): self.capture(fixture, root_inventory=value)
        for value in (1.0, object(), b"not JSON"):
            with self.assertRaises(ValueError): self.capture(fixture, evidence={"nested": value})
        cycle = {}
        cycle["cycle"] = cycle
        with self.assertRaises(ValueError): self.capture(fixture, evidence=cycle)
        # This boundary owns evidence; the real lazy producer must verify it.
        # A copied invalid signature is deliberately NOT called authenticated.
        damaged = {**fixture.evidence, "verifierSignatureBase64url": oracle.encoded(bytes(64))}
        owner = self.owner(fixture)
        owned, context, captured = self.capture(fixture, owner=owner, evidence=damaged)
        self.assertEqual(owned["evidence"], damaged)
        self.assertEqual(context, fixture.expected_context())
        self.assertEqual(captured, inventory)
        object.__setattr__(owner, "_configuration", owner._snapshot_configuration()[:-1])
        with self.assertRaises(ValueError): owner._snapshot_configuration()

    def test_literal_zero_hash_capture_exact_prior_short_and_repeat_allowances(self):
        fixture = PlanningFixture()
        expected = independent_capture_work(fixture)
        self.assertEqual(expected[0], 0)
        for prior in ((0, 0, 0), (1, 17, 11)):
            for deficit in (None, 1, 2):
                maximum = [max(1, prior[0]), prior[1] + expected[1], prior[2] + expected[2]]
                if deficit is not None: maximum[deficit] -= 1
                meter = observed_oracle.work(tuple(maximum))
                meter.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
                limits = meter.limits
                with self.subTest(prior=prior, deficit=deficit), \
                        patch.object(accounting._ValidationWork, "__init__", side_effect=AssertionError("capture allocated replacement work")):
                    if deficit is None:
                        self.capture(fixture, meter=meter)
                        self.assertEqual(observed_oracle.metrics(meter), observed_oracle.add(prior, expected))
                    else:
                        with self.assertRaises(ValueError): self.capture(fixture, meter=meter)
                self.assertIs(meter.limits, limits)
                self.assertEqual(meter.hash_work, prior[0])
                self.assertTrue(all(start <= used <= ceiling for start, used, ceiling in
                    zip(prior, observed_oracle.metrics(meter), maximum)))
        for deficit in (None, 1, 2):
            maximum = [1, 2 * expected[1], 2 * expected[2]]
            if deficit is not None: maximum[deficit] -= 1
            meter = observed_oracle.work(tuple(maximum))
            limits = meter.limits
            self.capture(fixture, meter=meter)
            first = observed_oracle.metrics(meter)
            self.assertEqual(first, expected)
            if deficit is None:
                self.capture(fixture, meter=meter)
                self.assertEqual(observed_oracle.metrics(meter), observed_oracle.add(expected, expected))
            else:
                with self.assertRaises(ValueError): self.capture(fixture, meter=meter)
                self.assertTrue(all(left <= right for left, right in zip(first, observed_oracle.metrics(meter))))
            self.assertIs(meter.limits, limits)
        for mode in ("float", "negative", "foreign_limits"):
            meter = observed_oracle.work()
            if mode == "float": meter.json_nodes = 0.0
            if mode == "negative": meter.input_bytes = -1
            if mode == "foreign_limits": meter.limits = object()
            with self.subTest(mode=mode), self.assertRaises(ValueError): self.capture(fixture, meter=meter)

    def test_genuine_root_reader_then_capture_share_independent_all_three_budget_ceilings(self):
        fixture = PlanningFixture()
        primary, heads = fixture.handoff.primary, fixture.handoff.heads
        reader_expected = root_oracle.independent_work(primary, heads)
        expected = observed_oracle.add(reader_expected["total"], independent_capture_work(fixture))
        self.assertEqual(expected[0], 84)
        for prior in ((0, 0, 0), (1, 17, 11)):
            full = observed_oracle.add(prior, expected)
            for deficit in (None, 0, 1, 2):
                maximum = tuple(value - int(index == deficit) for index, value in enumerate(full))
                meter = observed_oracle.work(maximum)
                meter.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
                limits = meter.limits
                acquisition = root_oracle.inventory_fixture(primary_values=primary, head_values=heads, meter=meter)
                def acquire_and_capture():
                    inventory = root_oracle.acquire(acquisition)
                    return self.capture(fixture, meter=meter, root_inventory=inventory)
                with self.subTest(prior=prior, deficit=deficit):
                    if deficit is None:
                        _, context, inventory = acquire_and_capture()
                        self.assertEqual(context, fixture.expected_context())
                        self.assertEqual(inventory, fixture.inventory)
                        self.assertEqual(observed_oracle.metrics(meter), full)
                        self.assertEqual(root_oracle.physical(acquisition[4]), reader_expected["physical"])
                    else:
                        with self.assertRaises(ValueError): acquire_and_capture()
                        self.assertTrue(all(start <= used <= ceiling for start, used, ceiling in
                            zip(prior, observed_oracle.metrics(meter), maximum)))
                self.assertIs(meter.limits, limits)

    def test_actual_cursor_result_wrappers_guard_calls_without_owning_or_authenticating_rows(self):
        meter, driver = observed_oracle.work(), Driver()
        meter.charge(hashes=1, input_bytes=17, json_nodes=11)
        before = observed_oracle.metrics(meter)
        cursor = planning._ReadCursor(driver.cursor, driver, driver.pgconn, meter)
        result = cursor.execute("SELECT fixture", ("literal",))
        self.assertIs(type(result), planning._ReadResult)
        self.assertIs(result.fetchone(), driver.rows[0])
        self.assertIs(result.fetchall(), driver.rows)
        self.assertEqual(result.fetchmany(1), driver.rows[:1])
        cursor.execute("SELECT other fixture")
        self.assertEqual(driver.calls, [("SELECT fixture", ("literal",)), ("fetchmany", 1), ("SELECT other fixture",)])
        self.assertEqual(driver.events, ["execute.lookup", "execute.call", "fetchone.lookup", "fetchone.call",
            "fetchall.lookup", "fetchall.call", "fetchmany.lookup", "fetchmany.call", "execute.lookup", "execute.call"])
        self.assertEqual(observed_oracle.metrics(meter), before)
        self.assertEqual((driver.closed, driver.info.transaction_status, driver.closes), (False, 2, 0))
        # These wrappers intentionally return borrowed driver rows. Actual
        # acquisition owns and validates them; the wrapper is not that proof.
        driver.rows[0]["fixture"] = 99
        self.assertEqual(result.fetchone()["fixture"], 99)
        failure = RuntimeError("native driver failure")
        def fail(event):
            if event == "fetchone.call": raise failure
        driver.callback = fail
        with self.assertRaises(RuntimeError) as raised: result.fetchone()
        self.assertIs(raised.exception, failure)

    def test_cursor_getters_and_calls_cannot_spend_refund_retype_or_replace_work(self):
        for stage in ("execute.lookup", "execute.call", "fetchone.lookup", "fetchone.call",
                "fetchall.lookup", "fetchall.call", "fetchmany.lookup", "fetchmany.call"):
            for mode in ("spend", "refund", "float", "replace"):
                with self.subTest(stage=stage, mode=mode):
                    meter, poison = observed_oracle.work(), []
                    meter.charge(hashes=1, input_bytes=17, json_nodes=11)
                    entering_limits = meter.limits
                    def corrupt(event):
                        if event != stage: return
                        if mode == "spend": meter.charge(input_bytes=1)
                        elif mode == "refund": meter.input_bytes -= 1
                        elif mode == "float": meter.json_nodes = float(meter.json_nodes)
                        else: meter.limits = accounting.QueryReadValidationLimits()
                        poison.append((observed_oracle.metrics(meter), meter.limits))
                    driver = Driver(corrupt)
                    cursor = planning._ReadCursor(driver.cursor, driver, driver.pgconn, meter)
                    with self.assertRaises(ValueError):
                        result = cursor.execute("SELECT fixture")
                        method = stage.split(".")[0]
                        if method == "fetchmany": result.fetchmany(1)
                        elif method != "execute": getattr(result, method)()
                    self.assertEqual(len(poison), 1)
                    self.assertEqual(observed_oracle.metrics(meter), poison[0][0])
                    self.assertIs(meter.limits, poison[0][1])
                    if mode == "float": self.assertIs(type(meter.json_nodes), float)
                    if mode == "replace": self.assertIsNot(meter.limits, entering_limits)

    def test_cursor_and_result_identity_and_active_connection_changes_deny(self):
        for field, value in (("closed", True), ("autocommit", True), ("status", 0), ("status", True),
                ("status", 2.0), ("pgconn", None), ("pgconn", object())):
            meter, driver = observed_oracle.work(), Driver()
            cursor = planning._ReadCursor(driver.cursor, driver, driver.pgconn, meter)
            if field == "status": driver.info.transaction_status = value
            else: setattr(driver, field, value)
            with self.subTest(field=field, value=type(value).__name__), self.assertRaises(ValueError):
                cursor.execute("SELECT fixture")
            self.assertEqual(driver.events, [])
        for stage in ("execute.lookup", "execute.call", "fetchmany.lookup", "fetchmany.call"):
            for field in ("_cursor", "_connection", "_raw", "_work", "_identity", "pgconn", "status"):
                with self.subTest(stage=stage, field=field):
                    meter, driver = observed_oracle.work(), Driver()
                    cursor = planning._ReadCursor(driver.cursor, driver, driver.pgconn, meter)
                    def mutate(event):
                        if event != stage: return
                        if field == "pgconn": driver.pgconn = object()
                        elif field == "status": driver.info.transaction_status = 0
                        elif field == "_identity": cursor._identity = tuple(list(cursor._identity))
                        else: setattr(cursor, field, object())
                    driver.callback = mutate
                    with self.assertRaises(ValueError): cursor.execute("SELECT fixture").fetchmany(1)
                    self.assertEqual(observed_oracle.metrics(meter), (0, 0, 0))
            for field in ("_result", "_cursor", "_identity"):
                if not stage.startswith("fetchmany"): continue
                meter, driver = observed_oracle.work(), Driver()
                cursor = planning._ReadCursor(driver.cursor, driver, driver.pgconn, meter)
                result = cursor.execute("SELECT fixture")
                def mutate_result(event):
                    if event != stage: return
                    value = tuple(list(result._identity)) if field == "_identity" else object()
                    setattr(result, field, value)
                driver.callback = mutate_result
                with self.subTest(stage=stage, result_field=field), self.assertRaises(ValueError): result.fetchmany(1)
                self.assertEqual(observed_oracle.metrics(meter), (0, 0, 0))

    def test_reused_connection_scope_helpers_preserve_first_failure_and_post_exit_uncertainty(self):
        # These are the actual helpers used by the shared read body, exercised
        # separately. They do not execute that body or establish a transaction.
        meter, driver = observed_oracle.work(), Driver()
        def poisoned_open():
            meter.charge(input_bytes=1)
            return driver
        with self.assertRaises(ValueError): planning.reader._connect(meter, poisoned_open)
        self.assertEqual((driver.closed, driver.closes), (True, 1))
        self.assertEqual(observed_oracle.metrics(meter), (0, 1, 0))

        failure = RuntimeError("body failed first")
        meter, scope = observed_oracle.work(), Scope(suppress=True)
        with self.assertRaises(RuntimeError) as raised:
            with planning.reader._context(scope, meter):
                meter.json_nodes = 0.0
                raise failure
        self.assertIs(raised.exception, failure)
        self.assertEqual((scope.enters, scope.exits, scope.commits, scope.rollbacks), (1, 1, 0, 1))
        self.assertIs(scope.errors[0], failure)
        self.assertIs(type(meter.json_nodes), float)

        for stage in ("enter", "exit"):
            meter = observed_oracle.work()
            def corrupt(event):
                if event == stage: meter.charge(input_bytes=1)
            scope = Scope(corrupt)
            with self.subTest(stage=stage), self.assertRaises(ValueError):
                with planning.reader._context(scope, meter): pass
            # A returned enter is cleaned up; an already-completed exit is not
            # repeated. Its modeled commit cannot be undone by the work guard.
            self.assertEqual((scope.enters, scope.exits), (1, 1))
            self.assertEqual((scope.commits, scope.rollbacks), (0, 1) if stage == "enter" else (1, 0))
            self.assertEqual(observed_oracle.metrics(meter), (0, 1, 0))
        failure = RuntimeError("enter failed before returning")
        def broken_enter(event):
            if event == "enter": raise failure
        scope = Scope(broken_enter)
        with self.assertRaises(RuntimeError) as raised:
            with planning.reader._context(scope, observed_oracle.work()): pass
        self.assertIs(raised.exception, failure)
        self.assertEqual((scope.enters, scope.exits, scope.commits, scope.rollbacks), (1, 0, 0, 0))


if __name__ == "__main__":
    unittest.main()
