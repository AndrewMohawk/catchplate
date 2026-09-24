#!/usr/bin/env python3
"""Real private writer prefix with an explicit failing pre-database boundary.

Independent measured-setting graphs are not a signed configuration load or an
active service launch. The actual mapper, clocks, signatures, policy join and
fixed atomic preflight run here. A RuntimeError sentinel stops the real runner
boundary: it never returns successful custody or replaces a proof verdict.
Startup separately retains the actual db/registry gate and both real replays.
This is authored, unexecuted component source, not socket or live PG evidence.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_contract as authority
from serverware import authority_query_read_work as accounting
from serverware import authority_revocation_configuration as configuration
from serverware import authority_revocation_persistence as persistence
from serverware import authority_revocation_writer_composition as composition
from serverware import authority_revocation_writer_configuration as mapper
import test_authority_revocation_plan as oracle
import test_authority_revocation_writer_action as action_oracle
import test_authority_revocation_writer_commitment as commitment_oracle
import test_authority_revocation_writer_configuration as mapper_oracle


ORIGINAL_FIELDS = ("intent_bytes", "relay_bytes", "envelope_bytes", "evaluation_context_bytes",
                   "historical_expectations_bytes")


class CompositionFixture(commitment_oracle.CommitmentFixture):
    def __init__(self):
        super().__init__()
        self.action.configuration.payload["roles"]["planner-writer"]["maximumInternalAgeNs"] = 60_000_000_000
        self.refresh_configuration()

    def refresh_configuration(self):
        # A new writer-age field changes the full configuration digest, hence
        # its verifier identity and both genuine original receipt/plan bytes.
        self.action.refresh()
        self.plan = self.action.plan
        self.configuration_digest = self.action.configuration.digest
        self.generation_sequence = self.action.configuration.generation["sequence"]
        self.generation_digest = self.action.configuration.generation["digest"]
        self.maximum_age = self.action.configuration.payload["roles"]["planner-writer"]["maximumInternalAgeNs"]
        self.rebuild()

    def originals(self):
        return {"intent_bytes": self.intent_bytes, "relay_bytes": self.relay_bytes,
            "envelope_bytes": self.action.arguments["envelope_bytes"],
            "evaluation_context_bytes": self.action.arguments["evaluation_context_bytes"],
            "historical_expectations_bytes": self.history_bytes}


def prepare_components(fixture, work):
    """Actual capture+mapper components; not measured-service admission.

    Capture immutable original references and all current scalar pins before
    the real mapper's key callbacks. The service's launch/descriptor/generation
    provenance is source-linked separately, never emulated as successful here.
    """
    originals = fixture.originals()
    payload, digest = fixture.action.configuration.payload, fixture.configuration_digest
    generation, dsn = fixture.action.configuration.generation, fixture.action.configuration.persistence_dsn
    owned = configuration._ConfigurationCapture(configuration.capability.capture._SharedLedger(work),
        maximum_bytes=authority.MAX_REQUEST_BYTES).visit(payload)
    sequence, generation_digest = owned["generationSequence"], owned["generationDigest"]
    age = owned["roles"]["planner-writer"]["maximumInternalAgeNs"]
    owner = mapper._persistence_from_configuration_on_work(payload=owned,
        configuration_digest=digest, generation=generation, persistence_dsn=dsn, work=work)
    fixed = owner._snapshot_configuration()
    return owner, fixed, {**originals, "owned_payload": owned, "configuration_digest": digest,
        "generation_sequence": sequence, "generation_digest": generation_digest, "maximum_age_ns": age}


def independent_prefix_work(fixture):
    """Independent literal schedules, including the extra worker-owned copy."""
    copy_config = oracle.graph_cost(fixture.action.configuration.payload, 1, 1)
    factory = mapper_oracle.independent_factory_work(fixture.action.configuration)["total"]
    receiver = commitment_oracle.independent_work(fixture)["receiver"]["total"]
    policy = action_oracle.independent_prefix_work(fixture.action)["policy"]
    identity = oracle.canonical_comparison(fixture.action.arguments["planner_transaction_id"],
        fixture.action.expectations["expected_planner_transaction_id"])
    preparation = oracle.add(copy_config, factory)
    before_atomic = oracle.add(copy_config, receiver, policy)
    worker = oracle.add(before_atomic, identity)
    return {"configuration": copy_config, "factory": factory, "receiver": receiver,
        "policy": policy, "identity": identity, "preparation": preparation,
        "before_atomic": before_atomic, "worker": worker, "total": oracle.add(preparation, worker)}


class RevocationWriterCompositionTests(unittest.TestCase):
    def work(self, limits=None):
        return accounting._ValidationWork(accounting.QueryReadValidationLimits(*(limits or ())))

    def prepared(self, fixture):
        return prepare_components(fixture, self.work())

    def stop_before_database(self, fixed, arguments, meter, *, fixture, clock=None):
        """Observe the actual preflight then raise; never forge a success."""
        failure, observed = RuntimeError("explicit pre-database fixture stop"), []
        custody = {name: arguments[name] for name in ("intent_bytes", "relay_bytes",
            "historical_expectations_bytes", "configuration_digest", "generation_sequence", "generation_digest")}

        def stop(configuration, operation, inputs, expectations, work):
            self.assertIs(configuration, fixed)
            self.assertIs(operation, persistence._persist_and_reserve_request_on_connection)
            self.assertIs(work, meter)
            self.assertEqual({name: inputs[name] for name in custody}, custody)
            self.assertEqual(set(inputs), set(fixture.action.arguments) | set(custody))
            observed.append((inputs, expectations))
            raise failure

        def sample(name, value):
            if clock is not None: clock(name)
            return value

        with patch.object(composition.time, "monotonic_ns", side_effect=lambda: sample("monotonic", fixture.now_mono)), \
                patch.object(composition.time, "time_ns", side_effect=lambda: sample("epoch", fixture.now_epoch)), \
                patch.object(persistence, "_run_on_configuration", side_effect=stop), \
                self.assertRaises(RuntimeError) as raised:
            composition._persist_commitments_on_configuration(fixed, work=meter, **arguments)
        self.assertIs(raised.exception, failure)
        self.assertEqual(len(observed), 1)
        return observed[0]

    def test_real_prefix_preserves_originals_fixed_seven_pins_and_current_writer_policy(self):
        fixture = CompositionFixture()
        expected = independent_prefix_work(fixture)
        meter, clocks = self.work(expected["total"]), []
        owner, fixed, arguments = prepare_components(fixture, meter)
        self.assertEqual(oracle.units(meter.metrics), expected["preparation"])
        with patch.object(composition.commitment, "_verify_commitments_on_work",
                wraps=composition.commitment._verify_commitments_on_work) as authenticate:
            inputs, historical = self.stop_before_database(fixed, arguments, meter, fixture=fixture, clock=clocks.append)
        self.assertEqual(clocks, ["monotonic", "epoch"])
        self.assertEqual(authenticate.call_count, 1)
        called = authenticate.call_args.kwargs
        self.assertIs(called["planner_public_key"], fixed[2])
        self.assertIs(called["verifier_public_key"], fixed[3])
        self.assertIs(called["work"], meter)
        self.assertEqual((called["maximum_age_ns"], called["maximum_clock_skew_ns"]), (60_000_000_000, 5_000_000_000))
        self.assertEqual(historical["maximum_plan_age_ns"], 30_000_000_000)
        self.assertEqual({name: inputs[name] for name in fixture.action.arguments}, fixture.action.arguments)
        self.assertEqual(historical, fixture.action.expectations)
        self.assertEqual(fixed, owner._snapshot_configuration())
        self.assertEqual(oracle.units(meter.metrics), expected["total"])
        self.assertEqual((expected["factory"][0], expected["receiver"][0], expected["total"][0]), (4, 8, 12))
        for name in ("envelope_bytes", "evaluation_context_bytes"):
            self.assertIs(inputs[name], fixture.action.arguments[name])

    def test_worker_owns_policy_and_held_configuration_before_both_clock_callbacks(self):
        for stage in ("monotonic", "epoch"):
            fixture = CompositionFixture()
            owner, fixed, arguments = self.prepared(fixture)
            expected = independent_prefix_work(fixture)["worker"]
            meter, original, changed = self.work(expected), copy.deepcopy(fixture.action.expectations), []

            def mutate(name):
                if name != stage: return
                arguments["owned_payload"].clear()
                fixture.action.configuration.payload.clear()
                fixture.action.expectations["expected_request"].clear()
                fixture.action.expectations["expected_before"].clear()
                object.__setattr__(owner, "persistence_dsn", "postgresql://changed.invalid/db")
                object.__setattr__(owner, "planner_public_key", fixture.plan.other_key.public_key())
                object.__setattr__(owner, "_database_identity", ("invalid", "x", "y", "z"))
                changed.append(name)

            with self.subTest(stage=stage):
                _, observed = self.stop_before_database(fixed, arguments, meter, fixture=fixture, clock=mutate)
                self.assertEqual(changed, [stage])
                self.assertEqual(observed, original)
                self.assertEqual(oracle.units(meter.metrics), expected)

    def test_clock_exceptions_and_work_poison_deny_before_authentication_or_runner(self):
        for stage in ("monotonic", "epoch"):
            for poison in (False, True):
                fixture = CompositionFixture()
                _, fixed, arguments = self.prepared(fixture)
                meter, changed = self.work(), []
                failure = RuntimeError("original native clock error")
                replacement = accounting.QueryReadValidationLimits()

                def sample(name, value):
                    if name == stage:
                        if not poison: raise failure
                        meter.input_bytes -= 1
                        meter.limits = replacement
                        changed.append(oracle.units(meter.metrics))
                    return value

                with self.subTest(stage=stage, poison=poison), \
                        patch.object(composition.time, "monotonic_ns", side_effect=lambda: sample("monotonic", fixture.now_mono)), \
                        patch.object(composition.time, "time_ns", side_effect=lambda: sample("epoch", fixture.now_epoch)), \
                        patch.object(composition.commitment, "_verify_commitments_on_work",
                            wraps=composition.commitment._verify_commitments_on_work) as authenticate, \
                        patch.object(persistence, "_run_on_configuration", side_effect=AssertionError("database reached")) as runner:
                    with self.assertRaises(ValueError if poison else RuntimeError) as raised:
                        composition._persist_commitments_on_configuration(fixed, work=meter, **arguments)
                    self.assertEqual((authenticate.call_count, runner.call_count), (0, 0))
                if poison:
                    self.assertEqual(oracle.units(meter.metrics), changed[0])
                    self.assertIs(meter.limits, replacement)
                else: self.assertIs(raised.exception, failure)
                self.assertFalse(hasattr(meter, "_revocation_packaging_owner"))

    def test_original_types_and_fixed_pins_deny_before_clocks_or_database(self):
        fixture = CompositionFixture()
        _, fixed, arguments = self.prepared(fixture)
        changes = [{name: bytearray(arguments[name])} for name in ORIGINAL_FIELDS]
        changes += [{name: b"x"} for name in ORIGINAL_FIELDS]
        changes += [{"configuration_digest": False}, {"generation_sequence": True},
            {"generation_digest": "not a digest"}, {"maximum_age_ns": 0},
            {"maximum_age_ns": True}, {"owned_payload": []}]
        for changed in changes:
            meter = self.work()
            with self.subTest(fields=tuple(changed)), \
                    patch.object(composition.time, "monotonic_ns", side_effect=AssertionError("clock reached")) as clock, \
                    patch.object(persistence, "_run_on_configuration", side_effect=AssertionError("database reached")) as runner:
                with self.assertRaises(ValueError):
                    composition._persist_commitments_on_configuration(fixed, work=meter, **{**arguments, **changed})
                self.assertEqual((clock.call_count, runner.call_count, oracle.units(meter.metrics)), (0, 0, (0, 0, 0)))
        for replacement in (fixed[:6], list(fixed), (*fixed[:6], ("wrong", "x", "y", "z"))):
            with self.subTest(configuration=type(replacement).__name__), self.assertRaises(ValueError):
                composition._persist_commitments_on_configuration(replacement, work=self.work(), **arguments)

    def test_authentication_current_clocks_and_signed_historical_policy_deny_before_runner(self):
        for mode in ("signature", "body", "generation", "stale", "policy"):
            fixture = CompositionFixture()
            if mode == "signature":
                fixture.relay["signature"] = "A" * 86
                fixture.relay_bytes = oracle.wire(fixture.relay)
            if mode == "policy":
                fixture.action.expectations["maximum_plan_age_ns"] += 1
                fixture.rebuild()
            _, fixed, arguments = self.prepared(fixture)
            if mode == "body": arguments["envelope_bytes"] += b" "
            if mode == "generation": arguments["generation_digest"] = oracle.sha(b"wrong independent generation")
            epoch = fixture.action.expectations["deadline_epoch_ns"] if mode == "stale" else fixture.now_epoch
            with self.subTest(mode=mode), \
                    patch.object(composition.time, "monotonic_ns", return_value=fixture.now_mono), \
                    patch.object(composition.time, "time_ns", return_value=epoch), \
                    patch.object(composition.action, "_assert_policy_on_work", wraps=composition.action._assert_policy_on_work) as policy, \
                    patch.object(persistence, "_run_on_configuration", side_effect=AssertionError("database reached")) as runner:
                with self.assertRaises(ValueError):
                    composition._persist_commitments_on_configuration(fixed, work=self.work(), **arguments)
                self.assertEqual(runner.call_count, 0)
                self.assertEqual(policy.call_count, int(mode == "policy"))
        # The worker's ordinary tuple/payload are preconditions supplied by
        # the real upstream mapper. It does not pretend to re-enroll a forged
        # configuration or authenticate the physical source of either clock.

    def test_genuine_authentication_callbacks_keep_held_keys_and_worker_owned_policy(self):
        for target in ("planner.export", "verifier.export", "planner.verify", "verifier.verify"):
            fixture = CompositionFixture()
            owner, fixed, arguments = self.prepared(fixture)
            expected, original, events = independent_prefix_work(fixture)["worker"], copy.deepcopy(fixture.action.expectations), []

            def mutate(stage):
                events.append(stage)
                if stage != target: return
                arguments["owned_payload"].clear()
                fixture.action.configuration.payload.clear()
                object.__setattr__(owner, "persistence_dsn", "postgresql://late-owner.invalid/db")
                object.__setattr__(owner, "verifier_public_key", fixture.plan.other_key.public_key())

            keys = commitment_oracle.observed_keys(fixture, mutate)
            held = (*fixed[:2], keys["planner_public_key"], keys["verifier_public_key"], *fixed[4:])
            meter = self.work(expected)
            with self.subTest(stage=target):
                _, observed = self.stop_before_database(held, arguments, meter, fixture=fixture)
                self.assertEqual(observed, original)
                self.assertEqual(events, ["planner.export", "verifier.export", "planner.verify", "verifier.verify"])
                self.assertEqual(oracle.units(meter.metrics), expected)

    def test_prefix_exact_prior_and_each_short_axis_never_allocate_another_work(self):
        for composed in (False, True):
            fixture = CompositionFixture()
            expected = independent_prefix_work(fixture)["total" if composed else "worker"]
            prepared = self.prepared(fixture)
            for prior in ((0, 0, 0), (3, 17, 11)):
                for axis in (None, 0, 1, 2):
                    limits = list(oracle.add(prior, expected))
                    if axis is not None: limits[axis] -= 1
                    meter = self.work(tuple(limits))
                    meter.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
                    failure, calls = RuntimeError("bounded prefix stop"), []

                    def stop(*args):
                        calls.append(args)
                        raise failure

                    with self.subTest(composed=composed, prior=prior, axis=axis), \
                            patch.object(accounting._ValidationWork, "__init__", side_effect=AssertionError("new allowance")), \
                            patch.object(composition.time, "monotonic_ns", return_value=fixture.now_mono), \
                            patch.object(composition.time, "time_ns", return_value=fixture.now_epoch), \
                            patch.object(persistence, "_run_on_configuration", side_effect=stop):
                        with self.assertRaises(RuntimeError if axis is None else ValueError) as raised:
                            _, fixed, arguments = prepare_components(fixture, meter) if composed else prepared
                            composition._persist_commitments_on_configuration(fixed, work=meter, **arguments)
                        if axis is None:
                            self.assertIs(raised.exception, failure)
                            self.assertEqual(len(calls), 1)
                            self.assertEqual(oracle.units(meter.metrics), oracle.add(prior, expected))
                        else: self.assertEqual(calls, [])
                    self.assertFalse(hasattr(meter, "_revocation_packaging_owner"))

    def test_repeated_prefix_reauthenticates_on_remaining_allowance_without_success_token(self):
        fixture = CompositionFixture()
        expected = independent_prefix_work(fixture)["total"]
        for axis in (None, 0, 1, 2):
            limits = list(oracle.add(expected, expected))
            if axis is not None: limits[axis] -= 1
            meter = self.work(tuple(limits))
            _, fixed, arguments = prepare_components(fixture, meter)
            with self.subTest(axis=axis):
                self.stop_before_database(fixed, arguments, meter, fixture=fixture)
                self.assertEqual(oracle.units(meter.metrics), expected)
                if axis is None:
                    _, second, supplied = prepare_components(fixture, meter)
                    self.stop_before_database(second, supplied, meter, fixture=fixture)
                    self.assertEqual(oracle.units(meter.metrics), oracle.add(expected, expected))
                else:
                    with patch.object(composition.time, "monotonic_ns", return_value=fixture.now_mono), \
                            patch.object(composition.time, "time_ns", return_value=fixture.now_epoch), \
                            patch.object(persistence, "_run_on_configuration", side_effect=AssertionError("runner reached")) as runner:
                        with self.assertRaises(ValueError):
                            _, second, supplied = prepare_components(fixture, meter)
                            composition._persist_commitments_on_configuration(second, work=meter, **supplied)
                        self.assertEqual(runner.call_count, 0)
                self.assertFalse(hasattr(meter, "_revocation_packaging_owner"))


if __name__ == "__main__":
    unittest.main()
