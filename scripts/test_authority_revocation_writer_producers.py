#!/usr/bin/env python3
"""Configured real handoff/signing components with independent byte/work oracles.

Literal local configuration is not measured launch admission. Full independent
root populations come through the actual two-read worker on a deterministic
cursor, not PostgreSQL. Actual configured handoff, retained proof, Ed25519
signing and verification remain mandatory; no successful observation replaces
them. Producers have no socket operation; the final real-client chain models
OS I/O only and supplies no database custody or current-root evidence.
Authored source only: no execution evidence is asserted here.
"""
from __future__ import annotations

import copy
from contextlib import contextmanager
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate import authority_query_read_work as accounting
from catchplate import authority_revocation_retention as retention
from catchplate import authority_revocation_writer_client as client
from catchplate import authority_revocation_writer_producers as producers
import test_authority_revocation_plan as oracle
import test_authority_revocation_observed as observed_oracle
import test_authority_revocation_verifier as verifier_oracle
import test_authority_revocation_writer_acknowledgment as key_oracle
import test_authority_revocation_writer_action as action_oracle
import test_authority_revocation_writer_commitment as commitment_oracle
import test_authority_revocation_writer_client as client_oracle


class ProducerFixture(client_oracle.ClientFixture):
    def configuration_arguments(self):
        return {"payload": self.action.configuration.payload,
            "configuration_digest": self.configuration_digest,
            "generation": self.action.configuration.generation}

    def intent_inputs(self):
        verifier = self.action.configuration.verifier
        return {**self.configuration_arguments(), **verifier.arguments(),
            **{name: self.action.arguments[name] for name in
                ("envelope_bytes", "evaluation_context_bytes", "planned_at_epoch_ns", "envelope_id", "planner_transaction_id")},
            "verifier_private_key": self.verifier_key}

    def relay_inputs(self):
        return {**self.configuration_arguments(), "intent_bytes": self.intent_bytes,
            "envelope_bytes": self.action.arguments["envelope_bytes"],
            "evaluation_context_bytes": self.action.arguments["evaluation_context_bytes"],
            "historical_expectations_bytes": self.history_bytes,
            "planner_private_key": self.planner_key}


def independent_work(fixture):
    """Literal new capture/comparison passes plus genuine existing work recipes."""
    add, verifier = oracle.add, fixture.action.configuration.verifier
    configuration = oracle.graph_cost(verifier.payload, 1, 1)
    factory = verifier_oracle.independent_factory_work(verifier)["total"]
    capture = observed_oracle.copy_cost({"expectedRequest": verifier.handoff.request, "context": verifier.context})
    inventory = observed_oracle.copy_cost(observed_oracle.capture_graph(verifier.handoff.primary, verifier.handoff.heads))
    identity = oracle.canonical_comparison(fixture.action.arguments["planner_transaction_id"],
        verifier.context["expectedPlannerTransactionId"])
    handoff = verifier_oracle.independent_owner_work(verifier)
    history = action_oracle.independent_prefix_work(fixture.action)
    controls = commitment_oracle.independent_work(fixture)
    prefix = add(capture, identity, inventory, configuration, factory)
    before_signer = add(prefix, handoff["total"], history["capture"], history["identity"])
    total = add(before_signer, controls["intent"]["total"])
    peak = add(prefix, handoff["admission"])
    intent = {"capture": capture, "inventory": inventory, "identity": identity,
        "prefix": prefix, "handoff": handoff, "history": add(history["capture"], history["identity"]),
        "before_signer": before_signer, "control": controls["intent"], "total": total,
        "admission": tuple(max(values) for values in zip(total, peak))}
    relay_total = add(configuration, factory, controls["relay"]["total"])
    return {"configuration": configuration, "factory": factory, "intent": intent,
        "relay": {"prefix": add(configuration, factory), "control": controls["relay"],
            "total": relay_total, "admission": relay_total}}


@contextmanager
def clock_scope(fixture, callback=lambda _stage: None):
    def sample(stage, value):
        callback(stage)
        return value

    with patch.object(producers.time, "monotonic_ns", side_effect=lambda: sample("monotonic", fixture.now_mono)) as mono, \
            patch.object(producers.time, "time_ns", side_effect=lambda: sample("epoch", fixture.now_epoch)) as epoch:
        yield mono, epoch


@contextmanager
def observed_keys(callback=lambda _stage: None):
    actual, keys = Ed25519PublicKey.from_public_bytes, []

    def construct(raw):
        role = "planner" if not keys else "verifier"
        key = actual(raw)
        callback(role + ".constructor")
        wrapped = key_oracle._PublicKey(key, callback, role=role)
        keys.append(wrapped)
        return wrapped

    with patch.object(Ed25519PublicKey, "from_public_bytes", side_effect=construct):
        yield keys


class RevocationWriterProducerTests(unittest.TestCase):
    def work(self, limits=None):
        return accounting._ValidationWork(accounting.QueryReadValidationLimits(*(limits or ())))

    def intent(self, fixture, meter=None, **changes):
        return producers._produce_intent_on_configuration(work=self.work() if meter is None else meter,
            **{**fixture.intent_inputs(), **changes})

    def relay(self, fixture, meter=None, **changes):
        return producers._produce_relay_on_configuration(work=self.work() if meter is None else meter,
            **{**fixture.relay_inputs(), **changes})

    def test_configured_intent_replays_real_originals_before_signing_literal_history_and_control(self):
        fixture, meter, stages = ProducerFixture(), self.work(), []
        expected = independent_work(fixture)["intent"]
        actual_replay = retention._verify_record_on_work

        def replay(**arguments):
            result = actual_replay(**arguments)
            stages.append("replay")
            return result

        def private_event(stage):
            if stage == "sign":
                self.assertEqual(stages, ["replay", "monotonic", "epoch"])
                stages.append("sign")

        private = key_oracle._PrivateKey(fixture.verifier_key, private_event)
        with clock_scope(fixture, stages.append) as (mono, epoch), observed_keys() as keys, \
                patch.object(retention, "_verify_record_on_work", side_effect=replay) as retained, \
                patch.object(retention.plan.mixed, "_verify", wraps=retention.plan.mixed._verify) as proof:
            result = self.intent(fixture, meter, verifier_private_key=private)
        self.assertIs(type(result), tuple)
        self.assertEqual(result, (fixture.intent_bytes, fixture.history_bytes))
        self.assertTrue(all(type(raw) is bytes for raw in result))
        self.assertEqual(stages, ["replay", "monotonic", "epoch", "sign"])
        self.assertEqual((retained.call_count, proof.call_count, private.signatures), (1, 1, 1))
        self.assertEqual([key.verifications for key in keys], [2, 2])
        self.assertIs(retained.call_args.kwargs["work"], meter)
        self.assertIs(retained.call_args.kwargs["envelope_bytes"], fixture.action.arguments["envelope_bytes"])
        self.assertIs(retained.call_args.kwargs["evaluation_context_bytes"], fixture.action.arguments["evaluation_context_bytes"])
        self.assertEqual(retained.call_args.kwargs["expected_before"], fixture.action.expectations["expected_before"])
        mono.assert_called_once()
        epoch.assert_called_once()
        self.assertEqual(oracle.units(meter.metrics), expected["total"])
        self.assertFalse(hasattr(meter, "_revocation_packaging_owner"))
        # The actual source reader observed all populations independently;
        # neither this unsigned inventory carrier nor the result is admission.
        acquired = fixture.action.configuration.verifier.handoff.acquisition
        self.assertEqual((len(acquired[0].calls), acquired[4].returned_rows), (2, 18))
        self.assertEqual(set(fixture.intent), set(commitment_oracle.OUTER_FIELDS))
        self.assertEqual(set(fixture.intent["payload"]), set(commitment_oracle.INTENT_FIELDS))
        self.assertEqual(set(fixture.history), set(commitment_oracle.HISTORY_FIELDS))

    def test_configured_relay_authenticates_original_intent_and_bodies_without_claiming_another_replay(self):
        fixture, meter = ProducerFixture(), self.work()
        private = key_oracle._PrivateKey(fixture.planner_key)
        with clock_scope(fixture), observed_keys() as keys, \
                patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as retained:
            raw = self.relay(fixture, meter, planner_private_key=private)
        self.assertIs(type(raw), bytes)
        self.assertEqual(raw, fixture.relay_bytes)
        self.assertEqual([key.verifications for key in keys], [1, 1])
        self.assertEqual(private.signatures, 1)
        retained.assert_not_called()
        self.assertEqual(oracle.units(meter.metrics), independent_work(fixture)["relay"]["total"])
        self.assertEqual(set(fixture.relay), set(commitment_oracle.OUTER_FIELDS))
        self.assertEqual(set(fixture.relay["payload"]), set(commitment_oracle.RELAY_FIELDS))
        # Genuine producer output is consumed as original bytes, not a proof
        # DTO; the relay reauthenticates the intent on the same allowance.
        meter, expected = self.work(), independent_work(fixture)
        with clock_scope(fixture), patch.object(retention, "_verify_record_on_work",
                wraps=retention._verify_record_on_work) as retained:
            intent_raw, history_raw = self.intent(fixture, meter)
            relayed = self.relay(fixture, meter, intent_bytes=intent_raw,
                historical_expectations_bytes=history_raw)
        self.assertEqual((intent_raw, history_raw, relayed),
            (fixture.intent_bytes, fixture.history_bytes, fixture.relay_bytes))
        self.assertEqual(retained.call_count, 1)
        self.assertEqual(oracle.units(meter.metrics), oracle.add(expected["intent"]["total"], expected["relay"]["total"]))

    def test_fixed_original_inputs_and_independent_ids_deny_before_keys_clocks_or_signing(self):
        class BytesSubclass(bytes):
            pass

        fixture = ProducerFixture()
        for route, names in (("intent", ("envelope_bytes", "evaluation_context_bytes")),
                ("relay", ("intent_bytes", "envelope_bytes", "evaluation_context_bytes", "historical_expectations_bytes"))):
            for name in names:
                for value in (None, "{}", bytearray(b"{}"), BytesSubclass(b"{}"), b"", b"x"):
                    meter = self.work()
                    with self.subTest(route=route, name=name, kind=type(value).__name__), clock_scope(fixture) as clocks, \
                            patch.object(Ed25519PublicKey, "from_public_bytes", wraps=Ed25519PublicKey.from_public_bytes) as keys:
                        with self.assertRaises(ValueError):
                            getattr(self, route)(fixture, meter, **{name: value})
                    keys.assert_not_called()
                    for clock in clocks: clock.assert_not_called()
                    self.assertEqual(oracle.units(meter.metrics), (0, 0, 0))
        for name, value in (("planned_at_epoch_ns", False), ("planned_at_epoch_ns", 0),
                ("envelope_id", "sha256:" + "A" * 64), ("planner_transaction_id", None)):
            with self.subTest(name=name, value=value), clock_scope(fixture) as clocks, observed_keys() as keys:
                with self.assertRaises(ValueError):
                    self.intent(fixture, **{name: value})
            self.assertEqual(keys, [])
            for clock in clocks: clock.assert_not_called()
        meter = self.work()
        with clock_scope(fixture) as clocks, observed_keys() as keys:
            with self.assertRaises(ValueError):
                self.intent(fixture, meter, planner_transaction_id=oracle.sha(b"independently wrong planner ID"))
        expected = independent_work(fixture)["intent"]
        self.assertEqual(oracle.units(meter.metrics), oracle.add(expected["capture"], expected["identity"]))
        self.assertEqual(keys, [])
        for clock in clocks: clock.assert_not_called()
        for route in ("intent", "relay"):
            for name in ("verified_handoff", "expected_before", "verifier_public_key", "planner_public_key",
                    "maximum_age_ns", "clock", "limits", "operation", "persistence_dsn"):
                with self.subTest(route=route, extra=name), clock_scope(fixture) as clocks:
                    with self.assertRaises(TypeError):
                        getattr(self, route)(fixture, **{name: object()})
                for clock in clocks: clock.assert_not_called()

    def test_genuine_false_plan_or_receipt_and_bad_signature_never_reach_intent_signing(self):
        for mode in ("false_result", "false_receipt", "plan_signature"):
            fixture = ProducerFixture()
            if mode == "false_result":
                fixture.plan.payload["expectedResult"] = {"false": "signed but not genuine transition output"}
                fixture.plan.rehash()
            elif mode == "false_receipt":
                fixture.plan.payload["webauthnEvidence"]["verifierSignatureBase64url"] = oracle.encoded(bytes(64))
                fixture.plan.payload["webauthnEvidence"]["verifierSignatureDigest"] = oracle.sha(bytes(64))
                fixture.plan.payload["authorizationProjection"]["assertionEvidenceDigest"] = oracle.framed(
                    "catchplate.policyAuthorityWebAuthnAssertionEvidence/v1", oracle.wire(fixture.plan.payload["webauthnEvidence"]))
                fixture.plan.rehash()
            else:
                fixture.plan.envelope["signatureBase64Url"] = oracle.encoded(bytes(64))
            fixture.action.arguments["envelope_bytes"] = oracle.wire(fixture.plan.envelope)
            private = key_oracle._PrivateKey(fixture.verifier_key)
            with self.subTest(mode=mode), clock_scope(fixture) as clocks, \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                    patch.object(oracle.assertion, "_verify_receipt_signature",
                        wraps=oracle.assertion._verify_receipt_signature) as receipt, \
                    patch.object(oracle.candidate.WebAuthnCredentialRevokeKernel, "_transition",
                        wraps=oracle.candidate.WebAuthnCredentialRevokeKernel()._transition) as kernel:
                with self.assertRaises(ValueError):
                    self.intent(fixture, verifier_private_key=private)
            self.assertEqual(private.signatures, 0)
            self.assertEqual(replay.call_count, int(mode != "plan_signature"))
            self.assertEqual(receipt.call_count, int(mode != "plan_signature"))
            self.assertEqual(kernel.call_count, int(mode == "false_result"))
            for clock in clocks: clock.assert_not_called()

    def test_full_configuration_roles_source_generation_and_key_pins_deny_before_signing(self):
        for route in ("intent", "relay"):
            for mode in ("changed_graph", "source", "generation", "role", "age", "response_pin", "raw_key"):
                fixture = ProducerFixture()
                configuration = fixture.action.configuration
                payload = configuration.payload
                if mode == "changed_graph": payload["unusedConfiguration"]["nested"].append("uncommitted")
                elif mode == "source": payload["sourceRevision"] = "foreign revision"
                elif mode == "generation": configuration.generation["digest"] = oracle.sha(b"foreign launch")
                elif mode == "role": payload["roles"]["planner-writer"]["processMode"] = "policy-authority-planner"
                elif mode == "age": payload["roles"]["planner-writer"]["maximumInternalAgeNs"] = False
                elif mode == "response_pin": payload["roles"]["verifier"]["responseSigningSpkiDigest"] = oracle.sha(b"wrong pin")
                elif mode == "raw_key": payload["roles"]["verifier"]["signingPublicKeyBase64Url"] = "!invalid"
                if mode not in ("changed_graph", "generation"):
                    configuration.commit_payload()
                    fixture.configuration_digest = configuration.digest
                signer_name = "verifier_private_key" if route == "intent" else "planner_private_key"
                private = key_oracle._PrivateKey(fixture.verifier_key if route == "intent" else fixture.planner_key)
                with self.subTest(route=route, mode=mode), clock_scope(fixture) as clocks, \
                        patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
                    with self.assertRaises(producers.RevocationWriterProducerError):
                        getattr(self, route)(fixture, **{signer_name: private})
                self.assertEqual(private.signatures, 0)
                replay.assert_not_called()
                for clock in clocks: clock.assert_not_called()

    def test_request_context_and_full_inventory_remain_independent_of_signed_plan_claims(self):
        for mode in ("request", "context", "injected_before", "root", "inventory_type"):
            fixture = ProducerFixture()
            arguments = fixture.intent_inputs()
            if mode == "request":
                arguments["expected_request"] = copy.deepcopy(arguments["expected_request"])
                arguments["expected_request"]["requestDigest"] = oracle.sha(b"other independent request")
            elif mode == "context":
                arguments["context"] = {**arguments["context"], "expectedFence": arguments["context"]["expectedFence"] + 1}
            elif mode == "injected_before":
                arguments["context"] = {**arguments["context"], "expectedBefore": fixture.action.expectations["expected_before"]}
            elif mode == "root":
                arguments["root_inventory"] = copy.deepcopy(arguments["root_inventory"])
                object.__setattr__(arguments["root_inventory"].business_roots[0], "root_digest",
                    oracle.sha(b"independent conflicting root"))
            else:
                arguments["root_inventory"] = {"successful": "not an inventory"}
            private = key_oracle._PrivateKey(fixture.verifier_key)
            arguments["verifier_private_key"] = private
            with self.subTest(mode=mode), clock_scope(fixture) as clocks:
                with self.assertRaises(producers.RevocationWriterProducerError):
                    producers._produce_intent_on_configuration(work=self.work(), **arguments)
            self.assertEqual(private.signatures, 0)
            for clock in clocks: clock.assert_not_called()

    def test_real_signer_pairing_and_authenticated_relay_bindings_cannot_be_replaced(self):
        for route in ("intent", "relay"):
            for mode in ("wrong_pair", "false_signature"):
                fixture = ProducerFixture()
                actual_key = fixture.verifier_key if route == "intent" else fixture.planner_key
                private = (key_oracle._PrivateKey(fixture.plan.other_key) if mode == "wrong_pair"
                    else key_oracle._PrivateKey(actual_key, signing_key=fixture.plan.other_key))
                name = "verifier_private_key" if route == "intent" else "planner_private_key"
                with self.subTest(route=route, mode=mode), clock_scope(fixture):
                    with self.assertRaises(producers.RevocationWriterProducerError):
                        getattr(self, route)(fixture, **{name: private})
                self.assertEqual(private.signatures, int(mode == "false_signature"))
        for mode in ("signature", "plan", "context", "history", "configuration", "generation", "header"):
            fixture = ProducerFixture()
            arguments = fixture.relay_inputs()
            if mode in ("plan", "context", "history"):
                field = {"plan": "envelope_bytes", "context": "evaluation_context_bytes",
                    "history": "historical_expectations_bytes"}[mode]
                arguments[field] += b" "
            else:
                if mode == "signature": fixture.intent["signature"] = oracle.encoded(bytes(64))
                elif mode == "configuration": fixture.intent["configurationDigest"] = oracle.sha(b"other configuration")
                elif mode == "generation": fixture.intent["payload"]["generationSequence"] += 1
                elif mode == "header": fixture.intent["parentEnvelopeId"] = oracle.sha(b"other parent")
                arguments["intent_bytes"] = (oracle.wire(fixture.intent) if mode == "signature"
                    else commitment_oracle.sign_control(fixture.intent, fixture.verifier_key))
            private = key_oracle._PrivateKey(fixture.planner_key)
            arguments["planner_private_key"] = private
            with self.subTest(mode=mode), clock_scope(fixture), \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
                with self.assertRaises(producers.RevocationWriterProducerError):
                    producers._produce_relay_on_configuration(work=self.work(), **arguments)
            self.assertEqual(private.signatures, 0)
            replay.assert_not_called()

    def test_post_handoff_clock_samples_preserve_history_and_enforce_strict_role_age_minima(self):
        for route, roles in (("intent", ("verifier", "planner", "planner-writer")),
                ("relay", ("planner", "planner-writer"))):
            for name in roles:
                fixture = ProducerFixture()
                fixture.action.configuration.payload["roles"][name]["maximumInternalAgeNs"] = 25_000_000_000
                fixture.refresh_configuration()
                with self.subTest(route=route, role=name), clock_scope(fixture), \
                        patch.object(producers.commitment, "_fresh", wraps=producers.commitment._fresh) as fresh:
                    actual = getattr(self, route)(fixture)
                self.assertEqual(actual, (fixture.intent_bytes, fixture.history_bytes) if route == "intent" else fixture.relay_bytes)
                self.assertEqual(fresh.call_count, 1)
                self.assertEqual(fresh.call_args.args[4:], (25_000_000_000, 5_000_000_000))
        fixture = ProducerFixture()
        planned = fixture.action.arguments["planned_at_epoch_ns"]
        historical = fixture.history_bytes
        fixture.now_epoch += 1
        fixture.now_mono += 1
        fixture.issued_epoch, fixture.issued_mono = fixture.now_epoch, fixture.now_mono
        fixture.rebuild()
        with clock_scope(fixture):
            raw, history = self.intent(fixture)
        self.assertEqual((raw, history), (fixture.intent_bytes, historical))
        self.assertEqual(fixture.intent["payload"]["plannedAtEpochNs"], planned)
        self.assertNotEqual(fixture.intent["issuedAtEpochNs"], fixture.history["now_epoch_ns"])
        for route in ("intent", "relay"):
            for mode in ("stale", "future_mono", "future_epoch", "inconsistent"):
                fixture = ProducerFixture()
                if mode == "stale":
                    fixture.now_epoch += 20_000_000_000
                    fixture.now_mono += 20_000_000_000
                elif mode == "future_mono": fixture.now_mono -= 1
                elif mode == "future_epoch": fixture.now_epoch -= 5_000_000_001
                else: fixture.now_epoch += 6_000_000_000
                private = key_oracle._PrivateKey(fixture.verifier_key if route == "intent" else fixture.planner_key)
                name = "verifier_private_key" if route == "intent" else "planner_private_key"
                with self.subTest(route=route, mode=mode), clock_scope(fixture), \
                        patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
                    with self.assertRaises(producers.RevocationWriterProducerError):
                        getattr(self, route)(fixture, **{name: private})
                self.assertEqual(private.signatures, 0)
                self.assertEqual(replay.call_count, int(route == "intent"))

    def test_caller_graphs_roots_and_genuine_handoff_result_are_detached_before_callbacks(self):
        actual_handoff = producers.verifier.RevocationPlanVerifier.verify_handoff
        for route in ("intent", "relay"):
            for target in ("planner.constructor", "verifier.der", "monotonic", "epoch", "derive", "sign"):
                fixture, mutated, results = ProducerFixture(), [], []
                arguments = fixture.intent_inputs() if route == "intent" else fixture.relay_inputs()
                expected = (fixture.intent_bytes, fixture.history_bytes) if route == "intent" else fixture.relay_bytes

                def capture_result(owner, **inputs):
                    result = actual_handoff(owner, **inputs)
                    results.append(result)
                    return result

                def mutate(stage):
                    if stage != target or mutated: return
                    mutated.append(stage)
                    arguments["payload"]["roles"].clear()
                    arguments["generation"].clear()
                    for field in ("expected_request", "context"):
                        if field in arguments: arguments[field].clear()
                    if "root_inventory" in arguments:
                        object.__setattr__(arguments["root_inventory"].business_roots[0],
                            "root_digest", oracle.sha(b"changed caller root after capture"))
                    for field in ("intent_bytes", "envelope_bytes", "evaluation_context_bytes", "historical_expectations_bytes"):
                        if field in arguments: arguments[field] = b"changed caller byte reference"
                    for result in results:
                        result.expected_context.clear()
                        result.retained_record.context.clear()

                private = key_oracle._PrivateKey(fixture.verifier_key if route == "intent" else fixture.planner_key, mutate)
                arguments["verifier_private_key" if route == "intent" else "planner_private_key"] = private
                operation = producers._produce_intent_on_configuration if route == "intent" else producers._produce_relay_on_configuration
                with self.subTest(route=route, target=target), clock_scope(fixture, mutate), observed_keys(mutate), \
                        patch.object(producers.verifier.RevocationPlanVerifier, "verify_handoff", new=capture_result):
                    actual = operation(work=self.work(), **arguments)
                self.assertEqual(actual, expected)
                self.assertEqual(mutated, [target])
                self.assertEqual(private.signatures, 1)
                self.assertEqual(len(results), int(route == "intent"))
                if route == "intent" and target in ("monotonic", "epoch", "derive", "sign"):
                    self.assertEqual(results[0].expected_context, {})

    def test_native_clock_and_key_failures_and_work_poison_never_return_signed_success(self):
        for route in ("intent", "relay"):
            for target, mode in (("monotonic", "native"), ("epoch", "native"),
                    ("planner.constructor", "native"), ("sign", "native"),
                    ("planner.constructor", "spend"), ("monotonic", "refund"),
                    ("derive", "type"), ("sign", "limits")):
                fixture, meter, seen = ProducerFixture(), self.work(), []
                error = OSError("native producer observation failed")

                def damage(stage):
                    if stage != target: return
                    if mode == "native": raise error
                    if mode == "spend": meter.hash_work += 1
                    elif mode == "refund": meter.input_bytes -= 1
                    elif mode == "type": meter.json_nodes = False
                    elif mode == "limits": meter.limits = accounting.QueryReadValidationLimits()
                    seen.append((meter.hash_work, meter.input_bytes, meter.json_nodes, meter.limits))

                private = key_oracle._PrivateKey(fixture.verifier_key if route == "intent" else fixture.planner_key, damage)
                name = "verifier_private_key" if route == "intent" else "planner_private_key"
                with self.subTest(route=route, target=target, mode=mode), clock_scope(fixture, damage), observed_keys(damage):
                    with self.assertRaises(OSError if mode == "native" else producers.RevocationWriterProducerError) as caught:
                        getattr(self, route)(fixture, meter, **{name: private})
                if mode == "native": self.assertIs(caught.exception, error)
                else:
                    self.assertEqual(len(seen), 1)
                    self.assertEqual((meter.hash_work, meter.input_bytes, meter.json_nodes), seen[0][:3])
                    self.assertIs(meter.limits, seen[0][3])
                self.assertEqual(private.signatures, int(target == "sign"))
                self.assertFalse(hasattr(meter, "_revocation_packaging_owner"))

    def test_exact_prior_and_every_short_axis_preserve_the_genuine_remaining_clamped_child(self):
        fixture = ProducerFixture()
        expected = independent_work(fixture)
        mixed, initialize = retention.plan.mixed, accounting._ValidationWork.__init__
        actual_mixed = mixed._verify
        for route in ("intent", "relay"):
            for prior in ((0, 0, 0), (3, 17, 11)):
                for axis in (None, 0, 1, 2):
                    maximum = list(oracle.add(prior, expected[route]["admission"]))
                    if axis is not None: maximum[axis] -= 1
                    meter = self.work(tuple(maximum))
                    meter.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
                    original_limits, clamps, children = meter.limits, [], []

                    def observe_mixed(owned, ledger, raw_decode_bytes, captured):
                        self.assertIs(ledger.work, meter)
                        clamps.append(ledger.remaining())
                        return actual_mixed(owned, ledger, raw_decode_bytes, captured)

                    def child(instance, limits):
                        self.assertEqual(route, "intent")
                        self.assertEqual(len(clamps), 1)
                        self.assertEqual(children, [])
                        self.assertIsNot(instance, meter)
                        self.assertEqual((limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes), clamps[0])
                        initialize(instance, limits)
                        children.append(instance)

                    with self.subTest(route=route, prior=prior, axis=axis), clock_scope(fixture), \
                            patch.object(mixed, "_verify", new=observe_mixed), \
                            patch.object(accounting._ValidationWork, "__init__", new=child):
                        if axis is None:
                            result = getattr(self, route)(fixture, meter)
                            self.assertEqual(result, (fixture.intent_bytes, fixture.history_bytes) if route == "intent" else fixture.relay_bytes)
                            self.assertEqual(oracle.units(meter.metrics), oracle.add(prior, expected[route]["total"]))
                            self.assertEqual((len(clamps), len(children)), (1, 1) if route == "intent" else (0, 0))
                        else:
                            with self.assertRaises(producers.RevocationWriterProducerError):
                                getattr(self, route)(fixture, meter)
                            self.assertLessEqual(len(children), int(route == "intent"))
                            self.assertTrue(all(start <= used <= limit for start, used, limit in
                                zip(prior, oracle.units(meter.metrics), maximum)))
                    self.assertIs(meter.limits, original_limits)
                    self.assertFalse(hasattr(meter, "_revocation_packaging_owner"))

    def test_explicit_repeated_producer_calls_reverify_and_resign_without_resetting_allowance(self):
        fixture = ProducerFixture()
        expected = independent_work(fixture)
        for route in ("intent", "relay"):
            required = oracle.add(expected[route]["total"], expected[route]["admission"])
            for axis in (None, 0, 1, 2):
                maximum = list(required)
                if axis is not None: maximum[axis] -= 1
                self.assertTrue(all(limit >= first for limit, first in zip(maximum, expected[route]["admission"])))
                meter = self.work(tuple(maximum))
                original_limits = meter.limits
                private = key_oracle._PrivateKey(fixture.verifier_key if route == "intent" else fixture.planner_key)
                name = "verifier_private_key" if route == "intent" else "planner_private_key"
                with self.subTest(route=route, axis=axis), clock_scope(fixture), \
                        patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
                    first = getattr(self, route)(fixture, meter, **{name: private})
                    self.assertEqual(first, (fixture.intent_bytes, fixture.history_bytes) if route == "intent" else fixture.relay_bytes)
                    self.assertEqual(oracle.units(meter.metrics), expected[route]["total"])
                    self.assertEqual(private.signatures, 1)
                    if axis is None:
                        second = getattr(self, route)(fixture, meter, **{name: private})
                        self.assertEqual(second, first)
                        self.assertEqual(oracle.units(meter.metrics), oracle.add(expected[route]["total"], expected[route]["total"]))
                        self.assertEqual(private.signatures, 2)
                        self.assertEqual(replay.call_count, 2 if route == "intent" else 0)
                    else:
                        with self.assertRaises(producers.RevocationWriterProducerError):
                            getattr(self, route)(fixture, meter, **{name: private})
                        self.assertTrue(all(spent <= used <= limit for spent, used, limit in
                            zip(expected[route]["total"], oracle.units(meter.metrics), maximum)))
                self.assertIs(meter.limits, original_limits)
                self.assertFalse(hasattr(meter, "_revocation_packaging_owner"))

    def test_produced_originals_survive_send_failure_and_explicit_client_retry_without_regeneration(self):
        fixture = ProducerFixture()
        verifier_key, planner_key = key_oracle._PrivateKey(fixture.verifier_key), key_oracle._PrivateKey(fixture.planner_key)
        intent_work, relay_work = self.work(), self.work()
        with clock_scope(fixture):
            intent_raw, history_raw = self.intent(fixture, intent_work, verifier_private_key=verifier_key)
            relay_raw = self.relay(fixture, relay_work, planner_private_key=planner_key,
                intent_bytes=intent_raw, historical_expectations_bytes=history_raw)
        originals = {**fixture.originals(), "intent_bytes": intent_raw,
            "historical_expectations_bytes": history_raw, "relay_bytes": relay_raw}
        retained_originals = originals.copy()
        self.assertEqual(originals, fixture.originals())
        expected_ack = client_oracle.expected_ack(fixture)
        arguments = {**fixture.arguments(), **originals}
        failure = OSError("modeled response failed after the complete request was sent")
        failed_work = self.work()
        failed_limits = failed_work.limits
        expected_client = client_oracle.independent_client_work(fixture)
        expected_request = b"".join(client_oracle.transport_oracle.request_segments(
            tuple(originals[name] for name in client_oracle.transport_oracle.NAMES)))
        expected = independent_work(fixture)
        self.assertEqual(oracle.units(intent_work.metrics), expected["intent"]["total"])
        self.assertEqual(oracle.units(relay_work.metrics), expected["relay"]["total"])
        with patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                patch.object(producers, "_produce_intent_on_configuration",
                    side_effect=AssertionError("transport retry must not regenerate intent")), \
                patch.object(producers, "_produce_relay_on_configuration",
                    side_effect=AssertionError("transport retry must not regenerate relay")):
            # The OS model has accepted the complete request and half-close
            # before its first response read fails. No database commit or
            # real peer delivery is established by those observations.
            with client_oracle.exchange(fixture, raw=expected_ack, fail_at="recv", failure=failure) as (failed, opened, _clock):
                with self.assertRaises(OSError) as caught:
                    client._send_on_configuration(work=failed_work, **arguments)
            self.assertIs(caught.exception, failure)
            opened.assert_called_once()
            self.assertEqual(failed.close_count, 1)
            self.assertEqual(failed.counts["shutdown"], 1)
            self.assertEqual(b"".join(failed.sent), expected_request)
            self.assertEqual(oracle.units(failed_work.metrics), expected_client["pre_socket"])
            self.assertEqual(originals, retained_originals)
            # An explicit new send owns its own invocation allowance. It does
            # not rewind the failed invocation or use its completed proof.
            retried_work = self.work()
            with client_oracle.exchange(fixture, raw=expected_ack) as (sent, opened, _clock):
                raw = client._send_on_configuration(work=retried_work, **arguments)
            opened.assert_called_once()
            self.assertEqual(raw, expected_ack)
            self.assertEqual(replay.call_count, 2)
            self.assertEqual(oracle.units(retried_work.metrics), expected_client["total"])
            self.assertEqual(b"".join(sent.sent), expected_request)
        self.assertEqual((verifier_key.signatures, planner_key.signatures), (1, 1))
        self.assertEqual(originals, retained_originals)
        self.assertEqual(oracle.units(failed_work.metrics), expected_client["pre_socket"])
        self.assertIs(failed_work.limits, failed_limits)


if __name__ == "__main__":
    unittest.main()
