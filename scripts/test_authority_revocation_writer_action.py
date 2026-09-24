#!/usr/bin/env python3
"""Inert action ownership/policy components over genuine configuration keys.

These controls do not import the active service/db/registry, call a store, or
manufacture successful admission. The component composition uses the actual
capture, policy, configuration and key workers and returns their real immutable
owner. Startup separately covers its genuine two-replay custody suffix behind
the existing db/registry gate. No execution evidence is asserted here.
"""
from __future__ import annotations

import copy
from datetime import date, datetime, timedelta, timezone, tzinfo
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_contract as authority
from serverware import authority_query_read_work as accounting
from serverware import authority_revocation_configuration as configuration
from serverware import authority_revocation_persistence as persistence
from serverware import authority_revocation_writer_action as action
from serverware import authority_revocation_writer_configuration as mapper
import test_authority_revocation_capability_producer as key_oracle
import test_authority_revocation_plan as oracle
import test_authority_revocation_retention as record_oracle
import test_authority_revocation_wire as wire_oracle
import test_authority_revocation_writer_configuration as configuration_oracle


ARGUMENT_FIELDS = ("envelope_bytes", "evaluation_context_bytes", "planned_at_epoch_ns",
                   "envelope_id", "planner_transaction_id")
EXPECTATION_FIELDS = ("expected_request", "expected_capability_id", "expected_planner_transaction_id",
    "expected_fence", "reserved_at_epoch_ns", "deadline_epoch_ns", "deadline_monotonic_ns",
    "now_epoch_ns", "now_monotonic_ns", "database_now", "maximum_assertion_age_ns",
    "maximum_plan_age_ns", "maximum_clock_skew_ns", "expected_before", "expected_approver_policy_digest")
POLICY_FIELDS = ("maximum_assertion_age_ns", "maximum_plan_age_ns", "maximum_clock_skew_ns")


class WriterActionFixture:
    def __init__(self):
        self.configuration = configuration_oracle.WriterConfigurationFixture()
        self.refresh()

    def refresh(self):
        # Adding the writer role changes the configuration-bound verifier
        # identity. Re-sign the real receipt and original plan chain only in
        # this independent fixture, never reconstruct production stored bytes.
        self.configuration.commit_payload()
        self.configuration.verifier.rebuild_originals()
        self.plan = self.configuration.verifier.handoff.plan
        self.arguments = {"envelope_bytes": oracle.wire(self.plan.envelope),
            "evaluation_context_bytes": oracle.wire(record_oracle.record_context(self.plan)),
            "planned_at_epoch_ns": self.plan.now_epoch_ns,
            "envelope_id": oracle.sha(b"measured private writer action envelope"),
            "planner_transaction_id": self.plan.planner_transaction_id}
        all_inputs = wire_oracle.expectations(self.plan)
        self.expectations = {name: all_inputs[name] for name in EXPECTATION_FIELDS}

    def supplied(self):
        return {**self.arguments, **self.expectations}


def independent_prefix_work(fixture):
    """Literal walks/comparisons; no production counters or observed results."""
    claims, payload = fixture.expectations, fixture.configuration.payload
    capture = oracle.graph_cost({name: claims[name] for name in EXPECTATION_FIELDS if name != "database_now"}, 1, 1)
    identity = oracle.canonical_comparison(fixture.arguments["planner_transaction_id"], claims["expected_planner_transaction_id"])
    caller = tuple(claims[name] for name in POLICY_FIELDS)
    measured = (payload["webauthn"]["maximumChallengeAgeNs"],
        min(payload["roles"]["verifier"]["maximumInternalAgeNs"], 30_000_000_000), 5_000_000_000)
    policy = oracle.canonical_comparison(caller, measured)
    full_configuration = oracle.graph_cost(payload, 1, 1)
    factory = configuration_oracle.independent_factory_work(fixture.configuration)["total"]
    return {"capture": capture, "identity": identity, "configuration": full_configuration,
        "policy": policy, "factory": factory,
        "total": oracle.add(capture, identity, full_configuration, policy, factory)}


def compose_components(fixture, work, *, after_capture=None):
    """Actual inert components in service order, not a service/launch model.

    The optional test-only hook observes the ownership boundary; it cannot
    supply a verifier/owner result. Production exposes no such action callback.
    """
    args, expectations = action._capture_action_inputs(work=work, **fixture.supplied())
    digest, dsn = fixture.configuration.digest, fixture.configuration.persistence_dsn
    owned_payload = configuration._ConfigurationCapture(configuration.capability.capture._SharedLedger(work),
        maximum_bytes=authority.MAX_REQUEST_BYTES).visit(fixture.configuration.payload)
    action._assert_policy_on_work(owned_payload, expectations, work)
    if after_capture is not None:
        configuration.production._callback(work, after_capture)
    owner = mapper._persistence_from_configuration_on_work(payload=owned_payload,
        configuration_digest=digest, generation=fixture.configuration.generation,
        persistence_dsn=dsn, work=work)
    return args, expectations, owner


class RevocationWriterActionTests(unittest.TestCase):
    def work(self, limits=None):
        return accounting._ValidationWork(accounting.QueryReadValidationLimits(*(limits or ())))

    def test_capture_owns_exact_fourteen_graph_fields_and_preserves_original_utc_and_bytes(self):
        fixture, meter = WriterActionFixture(), self.work()
        expected = independent_prefix_work(fixture)
        originals, claims = fixture.arguments.copy(), copy.deepcopy(fixture.expectations)
        args, owned = action._capture_action_inputs(work=meter, **fixture.supplied())
        self.assertIs(type(args), dict)
        self.assertIs(type(owned), dict)
        self.assertEqual(set(args), set(ARGUMENT_FIELDS))
        self.assertEqual(set(owned), set(EXPECTATION_FIELDS))
        self.assertEqual((len(args), len(owned)), (5, 15))
        self.assertEqual(args, originals)
        for name in ("envelope_bytes", "evaluation_context_bytes"):
            self.assertIs(args[name], originals[name])
        self.assertIs(owned["database_now"], fixture.expectations["database_now"])
        self.assertEqual(owned, claims)
        self.assertEqual(expected["identity"], (0, 438, 4))
        self.assertEqual(oracle.units(meter.metrics), oracle.add(expected["capture"], expected["identity"]))
        fixture.expectations["expected_request"].clear()
        fixture.expectations["expected_before"].clear()
        self.assertEqual(owned, claims)
        self.assertNotIn("planner_public_key", owned)

    def test_exact_utc_validation_rejects_aliases_and_preserves_pre_epoch_microseconds(self):
        class DateTimeSubclass(datetime):
            pass

        class EqualUtc(tzinfo):
            def utcoffset(self, instant): return timedelta(0)
            def dst(self, instant): return timedelta(0)

        fixture = WriterActionFixture()
        original = fixture.expectations["database_now"]
        invalid = (None, False, 0, date(2024, 1, 1), original.replace(tzinfo=None),
            original.astimezone(timezone(timedelta(hours=1))), original.replace(tzinfo=EqualUtc()),
            DateTimeSubclass(2024, 1, 1, tzinfo=timezone.utc))
        for instant in invalid:
            meter = self.work()
            with self.subTest(kind=type(instant).__name__), self.assertRaises(ValueError):
                action._capture_action_inputs(work=meter, **{**fixture.supplied(), "database_now": instant})
            self.assertEqual(oracle.units(meter.metrics), (0, 0, 0))
        for instant in (datetime(1969, 12, 31, 23, 59, 59, 999999, tzinfo=timezone.utc),
                        datetime(1970, 1, 1, tzinfo=timezone.utc), original):
            meter = self.work()
            _, owned = action._capture_action_inputs(work=meter,
                **{**fixture.supplied(), "database_now": instant})
            self.assertIs(owned["database_now"], instant)
            self.assertEqual(oracle.units(meter.metrics), oracle.add(
                independent_prefix_work(fixture)["capture"], (0, 438, 4)))
        # This is capture/type validity, not fresh-clock or retained proof
        # authority; the unchanged genuine store will verify the signed cutoff.

    def test_raw_shapes_closed_expectations_and_independent_ids_deny_without_keys(self):
        fixture = WriterActionFixture()
        invalid = ({"envelope_bytes": bytearray(fixture.arguments["envelope_bytes"])},
            {"envelope_bytes": b"x"}, {"evaluation_context_bytes": memoryview(b"{}")},
            {"evaluation_context_bytes": b""}, {"planned_at_epoch_ns": True},
            {"planned_at_epoch_ns": 0}, {"planned_at_epoch_ns": 2**63},
            {"envelope_id": False}, {"planner_transaction_id": "not a digest"},
            {"expected_planner_transaction_id": False}, {"planner_public_key": fixture.plan.key.public_key()},
            {"persistence_dsn": "postgresql://untrusted.invalid/x"}, {"verified_record": {}},
            {"writer_database_identity": fixture.configuration.expected_database_identity()})
        for changed in invalid:
            with self.subTest(fields=tuple(changed)), patch.object(Ed25519PublicKey, "from_public_bytes",
                    wraps=Ed25519PublicKey.from_public_bytes) as keys:
                with self.assertRaises(ValueError):
                    action._capture_action_inputs(work=self.work(), **{**fixture.supplied(), **changed})
            self.assertEqual(keys.call_count, 0)
        for missing in ("expected_request", "database_now", "maximum_plan_age_ns"):
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                action._capture_action_inputs(work=self.work(),
                    **{name: value for name, value in fixture.supplied().items() if name != missing})
        for field in ("planner_transaction_id", "expected_planner_transaction_id"):
            meter, supplied = self.work(), fixture.supplied()
            supplied[field] = oracle.sha(b"different independent id")
            with self.subTest(field=field), self.assertRaises(ValueError):
                action._capture_action_inputs(work=meter, **supplied)
            expected = oracle.add(independent_prefix_work(fixture)["capture"], oracle.canonical_comparison(
                supplied["planner_transaction_id"], supplied["expected_planner_transaction_id"]))
            self.assertEqual(oracle.units(meter.metrics), expected)

    def test_policy_uses_exact_challenge_verifier_age_and_source_skew_without_overwriting_claims(self):
        for challenge, verifier_age, planner_age in ((90_000_000_000, 60_000_000_000, 1),
                                                    (7_000_000_000, 9_000_000_000, 2)):
            fixture = WriterActionFixture()
            payload = fixture.configuration.payload
            payload["webauthn"]["maximumChallengeAgeNs"] = challenge
            payload["roles"]["verifier"]["maximumInternalAgeNs"] = verifier_age
            payload["roles"]["planner"]["maximumInternalAgeNs"] = planner_age
            fixture.refresh()
            expected, before = independent_prefix_work(fixture), copy.deepcopy(fixture.expectations)
            meter = self.work()
            result = action._assert_policy_on_work(payload, fixture.expectations, meter)
            self.assertIsNone(result)
            self.assertEqual(fixture.expectations, before)
            self.assertEqual(oracle.units(meter.metrics), expected["policy"])
            for name in POLICY_FIELDS:
                changed = {**fixture.expectations, name: fixture.expectations[name] + 1}
                with self.subTest(field=name), self.assertRaises(ValueError):
                    action._assert_policy_on_work(payload, changed, self.work())

    def test_real_component_composition_returns_two_genuine_keys_and_original_configuration_pins(self):
        fixture = WriterActionFixture()
        expected = independent_prefix_work(fixture)
        meter = self.work(expected["total"])
        with patch.object(Ed25519PublicKey, "from_public_bytes", wraps=Ed25519PublicKey.from_public_bytes) as keys:
            args, owned, owner = compose_components(fixture, meter)
        self.assertIs(type(owner), persistence.RevocationPlannerPersistence)
        self.assertEqual((args, owned), (fixture.arguments, fixture.expectations))
        self.assertEqual(owner._snapshot_configuration()[4:],
                         (*fixture.configuration.expected_identities(), fixture.configuration.expected_database_identity()))
        self.assertEqual((keys.call_count, expected["total"][0]), (2, 4))
        self.assertEqual(oracle.units(meter.metrics), expected["total"])
        self.assertFalse(hasattr(meter, "_revocation_packaging_owner"))

    def test_bounded_json_shapes_and_policy_alias_types_are_not_normalized(self):
        fixture = WriterActionFixture()
        changes = ({"expected_fence": True}, {"reserved_at_epoch_ns": 1.0},
            {"maximum_clock_skew_ns": -1}, {"maximum_plan_age_ns": 0},
            {"expected_approver_policy_digest": "not a digest"}, {"expected_before": {}},
            {"expected_request": {**fixture.expectations["expected_request"], "verified": True}})
        for changed in changes:
            with self.subTest(fields=tuple(changed)), self.assertRaises(action.RevocationWriterActionError):
                action._capture_action_inputs(work=self.work(), **{**fixture.supplied(), **changed})
        for field in POLICY_FIELDS:
            for invalid in (False, 1.0, "1", 2**63):
                with self.subTest(field=field, kind=type(invalid).__name__), self.assertRaises(ValueError):
                    action._assert_policy_on_work(fixture.configuration.payload,
                        {**fixture.expectations, field: invalid}, self.work())
        for path in (("webauthn", "maximumChallengeAgeNs"), ("roles", "verifier", "maximumInternalAgeNs")):
            for invalid in (None, False, 0, 1.0, "1", 2**63):
                payload = copy.deepcopy(fixture.configuration.payload)
                target = payload
                for name in path[:-1]: target = target[name]
                target[path[-1]] = invalid
                with self.subTest(path=path, kind=type(invalid).__name__), self.assertRaises(ValueError):
                    action._assert_policy_on_work(payload, fixture.expectations, self.work())

    def test_original_byte_local_limits_are_checked_before_graph_capture(self):
        fixture = WriterActionFixture()
        for module, attribute, field in ((action.retention.plan.contract, "MAX_PAYLOAD_BYTES", "envelope_bytes"),
                                         (action.retention, "MAX_CONTEXT_BYTES", "evaluation_context_bytes")):
            actual = len(fixture.arguments[field])
            for maximum in (actual, actual - 1):
                meter = self.work()
                with self.subTest(field=field, maximum=maximum), patch.object(module, attribute, maximum):
                    if maximum == actual:
                        args, _ = action._capture_action_inputs(work=meter, **fixture.supplied())
                        self.assertIs(args[field], fixture.arguments[field])
                    else:
                        with self.assertRaises(action.RevocationWriterActionError):
                            action._capture_action_inputs(work=meter, **fixture.supplied())
                        self.assertEqual(oracle.units(meter.metrics), (0, 0, 0))

    def test_full_action_and_configuration_are_owned_before_intervening_callback(self):
        fixture, meter = WriterActionFixture(), self.work()
        original_args, original_expectations = fixture.arguments.copy(), copy.deepcopy(fixture.expectations)
        original_dsn, identities = fixture.configuration.persistence_dsn, fixture.configuration.expected_identities()
        expected = independent_prefix_work(fixture)["total"]

        def mutate():
            fixture.expectations["expected_request"].clear()
            fixture.expectations["expected_before"].clear()
            fixture.arguments.clear()
            fixture.configuration.payload.clear()
            fixture.configuration.persistence_dsn = "postgresql://replaced.invalid/later"
            fixture.configuration.digest = oracle.sha(b"late borrowed digest")

        args, owned, owner = compose_components(fixture, meter, after_capture=mutate)
        self.assertEqual((args, owned), (original_args, original_expectations))
        self.assertEqual(owner._snapshot_configuration()[0], original_dsn)
        self.assertEqual(owner._snapshot_configuration()[4:6], identities)
        self.assertEqual(oracle.units(meter.metrics), expected)
        # Launch/generation has deliberately not been fabricated by this hook.
        # Its selected bindings are captured by the real mapper on entry.

    def test_each_actual_key_callback_cannot_retarget_captured_action_or_configuration(self):
        for target in ("construct:planner", "der:planner", "construct:verifier", "der:verifier"):
            fixture, meter, events = WriterActionFixture(), self.work(), []
            original_args, original_expectations = fixture.arguments.copy(), copy.deepcopy(fixture.expectations)
            original_dsn, identities = fixture.configuration.persistence_dsn, fixture.configuration.expected_identities()
            database, expected = fixture.configuration.expected_database_identity(), independent_prefix_work(fixture)["total"]
            constructed, changed = [], []
            construct = Ed25519PublicKey.from_public_bytes

            def event(name):
                events.append(name)
                if name == target:
                    fixture.expectations["expected_request"].clear()
                    fixture.expectations["expected_before"].clear()
                    fixture.arguments.clear()
                    fixture.configuration.payload.clear()
                    fixture.configuration.generation.clear()
                    fixture.configuration.persistence_dsn = "postgresql://replaced.invalid/later"
                    changed.append(name)

            def observed_key(raw):
                key = construct(raw)
                name = "planner" if not constructed else "verifier"
                constructed.append(raw)
                event("construct:" + name)
                return key_oracle._ObservedPublicBytes(key, callback=lambda: event("der:" + name))

            with self.subTest(target=target), patch.object(Ed25519PublicKey, "from_public_bytes", side_effect=observed_key):
                args, owned, owner = compose_components(fixture, meter)
            self.assertEqual(changed, [target])
            self.assertEqual(events, ["construct:planner", "der:planner", "construct:verifier", "der:verifier"])
            self.assertEqual((args, owned), (original_args, original_expectations))
            self.assertEqual(owner._snapshot_configuration()[0], original_dsn)
            self.assertEqual(owner._snapshot_configuration()[4:], (*identities, database))
            self.assertEqual(oracle.units(meter.metrics), expected)

    def test_callback_meter_poison_and_native_failures_preserve_original_failure_and_work(self):
        for stage in ("boundary", "construct", "der"):
            for mode in ("spend", "refund", "float", "replace"):
                fixture, meter, poisoned = WriterActionFixture(), self.work(), []
                meter.charge(hashes=1, input_bytes=17, json_nodes=11)
                construct, constructed = Ed25519PublicKey.from_public_bytes, []

                def poison():
                    if mode == "spend": meter.charge(input_bytes=1)
                    elif mode == "refund": meter.input_bytes -= 1
                    elif mode == "float": meter.json_nodes = float(meter.json_nodes)
                    else: meter.limits = accounting.QueryReadValidationLimits()
                    poisoned.append((meter.metrics, meter.limits))

                def observed_key(raw):
                    key = construct(raw)
                    constructed.append(raw)
                    if stage == "construct":
                        poison()
                        return key
                    return key_oracle._ObservedPublicBytes(key, callback=poison) if stage == "der" else key

                with self.subTest(stage=stage, mode=mode), \
                        patch.object(Ed25519PublicKey, "from_public_bytes", side_effect=observed_key):
                    with self.assertRaises(ValueError):
                        compose_components(fixture, meter, after_capture=poison if stage == "boundary" else None)
                self.assertEqual(len(poisoned), 1)
                self.assertEqual(meter.metrics, poisoned[0][0])
                self.assertIs(meter.limits, poisoned[0][1])
                if mode == "float": self.assertIs(type(meter.json_nodes), float)
                self.assertEqual(len(constructed), 0 if stage == "boundary" else 1)
                self.assertFalse(hasattr(meter, "_revocation_packaging_owner"))
        failure = RuntimeError("native action component callback failed")
        fixture = WriterActionFixture()
        with patch.object(Ed25519PublicKey, "from_public_bytes", side_effect=failure):
            with self.assertRaises(RuntimeError) as raised:
                compose_components(fixture, self.work())
        self.assertIs(raised.exception, failure)

    def test_exact_prior_and_each_short_component_budget_never_replace_caller_work(self):
        fixture = WriterActionFixture()
        prefix = independent_prefix_work(fixture)
        for route in ("capture", "composition"):
            total = oracle.add(prefix["capture"], prefix["identity"]) if route == "capture" else prefix["total"]
            for prior, dimension in (((0, 0, 0), None), ((1, 7, 5), None), ((2, 23, 7), None),
                                     ((2, 23, 7), 0), ((2, 23, 7), 1), ((2, 23, 7), 2)):
                if route == "capture" and dimension == 0:
                    continue  # Zero-H capture does not invent a hash requirement.
                limits = list(oracle.add(prior, total))
                if route == "capture": limits[0] = max(1, limits[0])
                if dimension is not None: limits[dimension] -= 1
                meter = self.work(limits)
                meter.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
                entering = meter.limits
                with self.subTest(route=route, prior=prior, dimension=dimension), \
                        patch.object(accounting._ValidationWork, "__init__", side_effect=AssertionError("new allowance")):
                    def invoke():
                        return action._capture_action_inputs(work=meter, **fixture.supplied()) if route == "capture" else compose_components(fixture, meter)
                    if dimension is None:
                        invoke()
                        self.assertEqual(oracle.units(meter.metrics), oracle.add(prior, total))
                    else:
                        with self.assertRaises(ValueError): invoke()
                        self.assertTrue(all(start <= used <= maximum for start, used, maximum in zip(
                            prior, oracle.units(meter.metrics), limits)))
                self.assertIs(meter.limits, entering)
                self.assertFalse(hasattr(meter, "_revocation_packaging_owner"))

    def test_repeated_component_composition_spends_each_four_hash_factory_again(self):
        fixture, prior = WriterActionFixture(), (2, 23, 7)
        total = independent_prefix_work(fixture)["total"]
        self.assertEqual(total[0], 4)
        for dimension in (None, 0, 1, 2):
            limits = list(oracle.add(prior, total, total))
            if dimension is not None: limits[dimension] -= 1
            meter = self.work(limits)
            meter.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
            entering = meter.limits
            with self.subTest(dimension=dimension):
                first = compose_components(fixture, meter)
                self.assertEqual(oracle.units(meter.metrics), oracle.add(prior, total))
                if dimension is None:
                    second = compose_components(fixture, meter)
                    self.assertEqual(first[:2], second[:2])
                    self.assertIsNot(first[2], second[2])
                    self.assertEqual(oracle.units(meter.metrics), oracle.add(prior, total, total))
                else:
                    with self.assertRaises(ValueError): compose_components(fixture, meter)
                    self.assertTrue(all(start <= used <= maximum for start, used, maximum in zip(
                        oracle.add(prior, total), oracle.units(meter.metrics), limits)))
            self.assertIs(meter.limits, entering)
            self.assertFalse(hasattr(meter, "_revocation_packaging_owner"))


if __name__ == "__main__":
    unittest.main()
