#!/usr/bin/env python3
"""Inert planner configuration consistency and real key/ownership components.

These independent mappings are not MeasuredConfiguration.load, launch or
database admission. Genuine fixture keys and signed evidence remain real, but
this suite never imports the gated planner or invokes produce_observed. Raw
input capture plus configured mapping is only that explicit private prefix,
not execution of the service adapter, a producer, SQL or a successful proof.
All controls are authored source; none are executed preparation evidence.
"""
from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError
import math
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate import authority_query_read_work as accounting
from catchplate import authority_revocation_planner_configuration as mapper
from catchplate import authority_revocation_planning as planning
from catchplate import authority_revocation_verifier as verifier
import test_authority_revocation_capability_producer as key_oracle
import test_authority_revocation_configuration as configuration_oracle
import test_authority_revocation_observed as observed_oracle
import test_authority_revocation_plan as oracle
import test_authority_revocation_verifier as verifier_oracle


IDENTITY_FIELDS = ("sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest")
DATABASE_FIELDS = ("databaseRole", "tlsClientDn", "tlsClientSerial", "tlsIssuerDn")


class PlannerConfigurationFixture:
    """Independent complete mapping commitment, not measured launch evidence."""

    def __init__(self):
        self.verifier = verifier_oracle.VerifierFixture(approval=False, include_audit=False)
        self.payload, self.generation = self.verifier.payload, self.verifier.generation
        self.payload["roles"]["planner"].update(databaseRole="fixture_planner_read",
            tlsClientDn="CN=fixture-planner", tlsClientSerial="17", tlsIssuerDn="CN=fixture-ca")
        self.read_dsn = "postgresql://fixture-planner-read.invalid/fixture"
        self.commit_payload()
        self.verifier.rebuild_originals()
        self.handoff = self.verifier.handoff
        self.request = copy.deepcopy(self.handoff.request)
        self.evidence = copy.deepcopy(self.handoff.plan.semantic.receipt.evidence)
        self.context = copy.deepcopy(self.verifier.context)
        self.inventory = self.handoff.inventory

    def commit_payload(self):
        self.verifier.commit_payload()
        self.digest = self.verifier.digest

    def arguments(self):
        return {"payload": self.payload, "configuration_digest": self.digest, "generation": self.generation,
            "read_dsn": self.read_dsn, "planner_private_key": self.handoff.plan.key}

    def call_arguments(self):
        return {"request": self.request, "evidence": self.evidence, "context": self.context,
            "root_inventory": self.inventory}

    def expected_database_identity(self):
        planner = self.payload["roles"]["planner"]
        return tuple(planner[name] for name in DATABASE_FIELDS) + (
            planner["plannerSessionIdentityDigest"], planner["measurementDigest"], planner["attestationReceiptDigest"])


def independent_factory_work(fixture):
    """Existing literal4H mapping plus two raw32 exports and full comparison.

    The reused .55 oracle derives every pass from independent JSON and fixed
    framing/codec recipes, never receiver metrics. The sender's only added
    successful work is64 exported bytes plus64 compared bytes, with no sign.
    """
    base = verifier_oracle.independent_factory_work(fixture.verifier)
    return {**base, "signer_binding": (0, 128, 0),
        "total": oracle.add(base["total"], (0, 128, 0))}


def independent_call_capture(fixture):
    return oracle.add(observed_oracle.copy_cost({"request": fixture.request,
        "evidence": fixture.evidence, "context": fixture.context}),
        observed_oracle.copy_cost(observed_oracle.capture_graph(fixture.handoff.primary, fixture.handoff.heads)))


class RevocationPlannerConfigurationTests(unittest.TestCase):
    def work(self, limits=None):
        return accounting._ValidationWork(accounting.QueryReadValidationLimits(*(limits or ())))

    def build(self, fixture, meter=None, **changes):
        return mapper._planner_from_configuration_on_work(work=self.work() if meter is None else meter,
            **{**fixture.arguments(), **changes})

    def prefix(self, fixture, meter, *, capture):
        # An explicit inert composition, not a call to AuthorityProcess or to
        # the gated producer. Both helpers repeat their real owned boundaries.
        if capture:
            owned, inventory = planning._capture_planning_call_inputs(work=meter, **fixture.call_arguments())
            self.assertEqual(owned["context"], fixture.context)
            self.assertEqual(inventory, fixture.inventory)
        return self.build(fixture, meter)

    def test_real_mapper_returns_exact_read_only_owner_and_seven_scalar_database_identity(self):
        fixture = PlannerConfigurationFixture()
        owner = self.build(fixture)
        self.assertIs(type(owner), planning.RevocationObservedPlanner)
        snapshot = owner._snapshot_configuration()
        self.assertEqual(len(snapshot), 10)
        self.assertEqual(snapshot[:3], (fixture.read_dsn, 2, fixture.expected_database_identity()))
        self.assertIs(snapshot[3], fixture.handoff.plan.key)
        self.assertEqual(tuple(configuration_oracle.raw_key(key) for key in snapshot[4:6]), (
            configuration_oracle.raw_key(fixture.handoff.plan.key.public_key()),
            configuration_oracle.raw_key(fixture.handoff.plan.semantic.receipt.key.public_key())))
        expected_verifier = fixture.verifier.expected_verifier_identity()
        self.assertEqual(snapshot[6:], (tuple(expected_verifier[name] for name in IDENTITY_FIELDS),
            90_000_000_000, 30_000_000_000, 5_000_000_000))
        with self.assertRaises(FrozenInstanceError): owner._configuration = ()

    def test_historical_policy_matches_receiver_and_not_planner_internal_request_age(self):
        for assertion, receiver_age, planner_age in ((90_000_000_000, 60_000_000_000, 1),
                (45_000_000_000, 15_000_000_000, 60_000_000_000), (1, 1, 30_000_000_000)):
            fixture = PlannerConfigurationFixture()
            fixture.payload["webauthn"]["maximumChallengeAgeNs"] = assertion
            fixture.payload["roles"]["verifier"]["maximumInternalAgeNs"] = receiver_age
            fixture.payload["roles"]["planner"]["maximumInternalAgeNs"] = planner_age
            fixture.commit_payload()
            sender = self.build(fixture)._snapshot_configuration()
            receiver = verifier._verifier_from_configuration_on_work(payload=fixture.payload,
                configuration_digest=fixture.digest, generation=fixture.generation, work=self.work())._snapshot_configuration()
            self.assertEqual(sender[7:], (assertion, min(receiver_age, 30_000_000_000), 5_000_000_000))
            self.assertEqual(sender[7:], receiver[4:7])
            self.assertEqual(sender[2][4:], receiver[2])
            self.assertEqual(sender[6], receiver[3])

    def test_timeout_uses_owned_finite_source_range_before_flooring(self):
        for timeout, expected in ((2, 2), (2.0, 2), (2.5, 2), (299.999, 299), (300, 300)):
            fixture = PlannerConfigurationFixture()
            fixture.payload["roles"]["planner"]["databaseConnectTimeoutSeconds"] = timeout
            fixture.commit_payload()
            meter = self.work()
            self.assertEqual(self.build(fixture, meter)._snapshot_configuration()[1], expected)
            self.assertEqual(oracle.units(meter.metrics), independent_factory_work(fixture)["total"])
        for timeout in (None, False, True, 0, 1, 1.25, 1.999, 300.001, "2", float("nan"), float("inf"), float("-inf")):
            fixture = PlannerConfigurationFixture()
            fixture.payload["roles"]["planner"]["databaseConnectTimeoutSeconds"] = timeout
            if type(timeout) is not float or math.isfinite(timeout):
                fixture.commit_payload()
            with self.subTest(timeout=timeout), patch.object(Ed25519PublicKey, "from_public_bytes",
                    wraps=Ed25519PublicKey.from_public_bytes) as constructed:
                with self.assertRaises(ValueError): self.build(fixture)
            self.assertEqual(constructed.call_count, 0)

    def test_full_configuration_and_role_source_bindings_fail_before_key_callbacks(self):
        for mode in ("unused", "digest", "schema", "revision", "planner_mode", "verifier_mode", "response_pin", "manifest"):
            fixture = PlannerConfigurationFixture()
            if mode == "unused": fixture.payload["unusedConfiguration"]["nested"].append("changed")
            elif mode == "digest": fixture.digest = oracle.sha(b"foreign configuration")
            else:
                if mode == "schema": fixture.payload["schema"] = "foreign/v1"
                if mode == "revision": fixture.payload["sourceRevision"] = "foreign revision"
                if mode.endswith("_mode"): fixture.payload["roles"][mode[:-5]]["processMode"] = "policy-authority-issuer"
                if mode == "response_pin": fixture.payload["roles"]["planner"]["responseSigningSpkiDigest"] = oracle.sha(b"other response key")
                if mode == "manifest": fixture.payload["queryManifestDigest"] = oracle.sha(b"other query source")
                fixture.commit_payload()
            private = key_oracle._ObservedPrivateKey(fixture.handoff.plan.key,
                public_callback=lambda: self.fail("private key callback before configuration denial"))
            with self.subTest(mode=mode), patch.object(Ed25519PublicKey, "from_public_bytes",
                    wraps=Ed25519PublicKey.from_public_bytes) as constructed:
                with self.assertRaises(ValueError): self.build(fixture, planner_private_key=private)
            self.assertEqual((constructed.call_count, private.calls), (0, 0))

    def test_selected_launch_generation_membership_and_rollback_binding_are_not_claimed_provenance(self):
        for mode in ("zero", "bool", "digest", "predecessor", "floor", "manifest", "absent", "empty", "duplicate", "unsorted"):
            fixture = PlannerConfigurationFixture()
            launch = fixture.generation
            if mode == "zero": launch["sequence"] = 0
            if mode == "bool": launch["sequence"] = True
            if mode == "digest": launch["configurationBindingDigest"] = oracle.sha(b"foreign generation intent")
            if mode == "predecessor": launch["predecessorDigest"] = oracle.sha(b"foreign predecessor")
            if mode == "floor": launch["minimumRollbackSequence"] = 4
            if mode == "manifest": launch["operationManifestDigest"] = oracle.sha(b"foreign operation source")
            if mode == "absent": launch["configurationPayloadBindings"] = [configuration_oracle.configuration_binding(oracle.sha(b"foreign configuration"))]
            if mode == "empty": launch["configurationPayloadBindings"] = []
            if mode == "duplicate": launch["configurationPayloadBindings"] = [configuration_oracle.configuration_binding(fixture.digest), configuration_oracle.configuration_binding(fixture.digest)]
            if mode == "unsorted": launch["configurationPayloadBindings"] = sorted(
                [configuration_oracle.configuration_binding(fixture.digest), configuration_oracle.configuration_binding(oracle.sha(b"second"))],
                key=lambda binding: binding["fileDigest"], reverse=True)
            with self.subTest(mode=mode), patch.object(Ed25519PublicKey, "from_public_bytes",
                    wraps=Ed25519PublicKey.from_public_bytes) as constructed:
                with self.assertRaises(ValueError): self.build(fixture)
            self.assertEqual(constructed.call_count, 0)
        fixture = PlannerConfigurationFixture()
        fixture.generation["unusedStatement"] = object()
        meter = self.work()
        self.assertEqual(self.build(fixture, meter)._snapshot_configuration()[2], fixture.expected_database_identity())
        self.assertEqual(oracle.units(meter.metrics), independent_factory_work(fixture)["total"])

    def test_database_identity_policy_and_signer_are_closed_configuration_not_call_overrides(self):
        for field in DATABASE_FIELDS:
            for value in (None, "", "bad\x00value"):
                fixture = PlannerConfigurationFixture()
                fixture.payload["roles"]["planner"][field] = value
                fixture.commit_payload()
                with self.subTest(field=field, value=value), self.assertRaises(ValueError): self.build(fixture)
        for location, field in (("webauthn", "maximumChallengeAgeNs"), ("verifier", "maximumInternalAgeNs")):
            for value in (True, 0, -1, 1.0, "1", 2**63):
                fixture = PlannerConfigurationFixture()
                target = fixture.payload[location] if location == "webauthn" else fixture.payload["roles"][location]
                target[field] = value
                fixture.commit_payload()
                with self.subTest(location=location, value=value), self.assertRaises(ValueError): self.build(fixture)
        fixture = PlannerConfigurationFixture()
        for dsn in (None, "", "bad\x00dsn", "x" * 65537):
            with self.assertRaises(ValueError): self.build(fixture, read_dsn=dsn)
        for key in (None, object(), fixture.handoff.plan.key.public_key()):
            with self.assertRaises(ValueError): self.build(fixture, planner_private_key=key)
        for name in ("writer_dsn", "verifier_public_key", "expected_before", "producer", "opener"):
            with self.assertRaises(TypeError): self.build(fixture, **{name: object()})

    def test_real_private_key_correspondence_and_canonical_key_transports_require_no_signature(self):
        fixture, events = PlannerConfigurationFixture(), []
        private = key_oracle._ObservedPrivateKey(fixture.handoff.plan.key,
            public_callback=lambda: events.append("derive"))
        meter = self.work()
        owner = self.build(fixture, meter, planner_private_key=private)
        self.assertIs(owner._snapshot_configuration()[3], private)
        self.assertEqual((events, private.calls), (["derive"], 0))
        self.assertEqual(oracle.units(meter.metrics), independent_factory_work(fixture)["total"])
        with self.assertRaises(ValueError): self.build(fixture, planner_private_key=fixture.handoff.plan.other_key)
        for role in ("planner", "verifier"):
            for mode in ("codec", "spki"):
                fixture = PlannerConfigurationFixture()
                target = fixture.payload["roles"][role]
                if mode == "codec": target["signingPublicKeyBase64Url"] = "." * 43
                else: target["signingSpkiDigest"] = target["responseSigningSpkiDigest"] = oracle.sha(b"wrong DER pin")
                fixture.commit_payload()
                with self.subTest(role=role, mode=mode), self.assertRaises(ValueError): self.build(fixture)

    def test_full_config_and_generation_are_detached_before_real_key_callbacks(self):
        fixture, changes = PlannerConfigurationFixture(), []
        expected_identity = fixture.expected_database_identity()
        expected_verifier = fixture.verifier.expected_verifier_identity()
        expected = independent_factory_work(fixture)["total"]
        original_dsn, original_key = fixture.read_dsn, fixture.handoff.plan.key
        meter, construct = self.work(expected), Ed25519PublicKey.from_public_bytes
        def observed_key(raw):
            key = construct(raw)
            if not changes:
                changes.append("first real key constructor")
                fixture.payload.clear()
                fixture.generation.clear()
                fixture.read_dsn = "postgresql://changed.invalid/changed"
            return key
        with patch.object(Ed25519PublicKey, "from_public_bytes", side_effect=observed_key) as constructed:
            owner = self.build(fixture, meter)
        snapshot = owner._snapshot_configuration()
        self.assertEqual((changes, constructed.call_count), (["first real key constructor"], 2))
        self.assertEqual(snapshot[:3], (original_dsn, 2, expected_identity))
        self.assertIs(snapshot[3], original_key)
        self.assertEqual(snapshot[6], tuple(expected_verifier[name] for name in IDENTITY_FIELDS))
        self.assertEqual(oracle.units(meter.metrics), expected)

    def test_raw_caller_capture_precedes_mapper_callbacks_without_becoming_a_success_token(self):
        fixture = PlannerConfigurationFixture()
        original = copy.deepcopy({"request": fixture.request, "evidence": fixture.evidence, "context": fixture.context})
        before = observed_oracle.expected_before(fixture.handoff.primary, fixture.handoff.heads)
        expected = oracle.add(independent_call_capture(fixture), independent_factory_work(fixture)["total"])
        meter = self.work(expected)
        owned, inventory = planning._capture_planning_call_inputs(work=meter, **fixture.call_arguments())
        events, construct = [], Ed25519PublicKey.from_public_bytes
        def observed_key(raw):
            key = construct(raw)
            if not events:
                events.append("mutate borrowed caller graphs")
                fixture.request.clear()
                fixture.evidence.clear()
                fixture.context.clear()
                object.__setattr__(fixture.inventory.business_roots[0], "root_digest", oracle.sha(b"changed caller root"))
                object.__setattr__(fixture.inventory.counted_heads[0].index_root, "digest", oracle.sha(b"changed caller head"))
            return key
        with patch.object(Ed25519PublicKey, "from_public_bytes", side_effect=observed_key):
            owner = self.build(fixture, meter)
        self.assertIs(type(owner), planning.RevocationObservedPlanner)
        self.assertEqual(events, ["mutate borrowed caller graphs"])
        self.assertEqual(owned, original)
        self.assertEqual(planning.observed._inventory_before(inventory), before)
        self.assertIsNot(inventory, fixture.inventory)
        self.assertEqual(oracle.units(meter.metrics), expected)
        # The raw helper owns JSON, not request/evidence signatures or policy.
        # The configured owner still validates and copies again before its
        # lazy producer. No successful producer or runtime adapter is invoked.
        fixture = PlannerConfigurationFixture()
        damaged = {**fixture.evidence, "verifierSignatureBase64url": oracle.encoded(bytes(64))}
        owned, _ = planning._capture_planning_call_inputs(work=self.work(),
            **{**fixture.call_arguments(), "evidence": damaged})
        self.assertEqual(owned["evidence"], damaged)
        for field in ("expectedBefore", "expectedPlannerIdentity", "maximumPlanAgeNs", "databaseCutoffUs"):
            with self.assertRaises(ValueError):
                planning._capture_planning_call_inputs(work=self.work(),
                    **{**fixture.call_arguments(), "context": {**fixture.context, field: None}})

    def test_every_actual_key_callback_rejects_poison_without_repair_or_signing(self):
        stages = ("construct:planner", "planner:1", "construct:verifier", "verifier:1",
            "derive", "derived:1", "planner:2")
        for stage in stages:
            for mode in ("spend", "refund", "float", "replace"):
                with self.subTest(stage=stage, mode=mode):
                    fixture, meter = PlannerConfigurationFixture(), self.work()
                    meter.charge(hashes=1, input_bytes=17, json_nodes=11)
                    entering, poison, constructed, events = meter.limits, [], [], []
                    serializations = {"planner": 0, "verifier": 0, "derived": 0}
                    construct = Ed25519PublicKey.from_public_bytes
                    def event(name):
                        events.append(name)
                        if name != stage: return
                        if mode == "spend": meter.charge(input_bytes=1)
                        elif mode == "refund": meter.input_bytes -= 1
                        elif mode == "float": meter.json_nodes = float(meter.json_nodes)
                        else: meter.limits = accounting.QueryReadValidationLimits()
                        poison.append((oracle.units(meter.metrics), meter.limits))
                    def serialized(role):
                        serializations[role] += 1
                        event(role + ":" + str(serializations[role]))
                    def observed_key(raw):
                        key = construct(raw)
                        role = "planner" if not constructed else "verifier"
                        constructed.append(raw)
                        event("construct:" + role)
                        return key_oracle._ObservedPublicBytes(key, callback=lambda: serialized(role))
                    derived = key_oracle._ObservedPublicBytes(fixture.handoff.plan.key.public_key(),
                        callback=lambda: serialized("derived"))
                    private = key_oracle._ObservedPrivateKey(fixture.handoff.plan.key,
                        public_callback=lambda: event("derive"), public_output=derived)
                    with patch.object(Ed25519PublicKey, "from_public_bytes", side_effect=observed_key):
                        with self.assertRaises(mapper.RevocationPlannerConfigurationError):
                            self.build(fixture, meter, planner_private_key=private)
                    self.assertEqual((events[-1], len(poison), private.calls), (stage, 1, 0))
                    self.assertEqual(oracle.units(meter.metrics), poison[0][0])
                    self.assertIs(meter.limits, poison[0][1])
                    if mode == "float": self.assertIs(type(meter.json_nodes), float)
                    if mode == "replace": self.assertIsNot(meter.limits, entering)

    def test_signer_binding_precharges_raw_exports_and_denies_wrong_output_or_callback_error(self):
        fixture = PlannerConfigurationFixture()
        private_key, public_key = fixture.handoff.plan.key, fixture.handoff.plan.key.public_key()
        for side in ("derived", "admitted"):
            for value in (b"x" * 31, b"x" * 33, "x" * 32, bytearray(32), bytes(32)):
                wrapped = key_oracle._ObservedPublicBytes(public_key, transform=lambda raw: value)
                private = key_oracle._ObservedPrivateKey(private_key,
                    public_output=wrapped if side == "derived" else None)
                meter = self.work((1, 128, 1))
                with self.subTest(side=side, value=type(value).__name__), self.assertRaises(ValueError):
                    mapper._bind_signer(private, wrapped if side == "admitted" else public_key, meter)
                self.assertEqual((oracle.units(meter.metrics), private.calls), ((0, 128, 0), 0))
        events = []
        private = key_oracle._ObservedPrivateKey(private_key, public_callback=lambda: events.append("derive"))
        with self.assertRaises(ValueError): mapper._bind_signer(private, public_key, self.work((1, 127, 1)))
        self.assertEqual((events, private.calls), ([], 0))
        failure = RuntimeError("native key derivation failure")
        def fail(): raise failure
        private = key_oracle._ObservedPrivateKey(private_key, public_callback=fail)
        with self.assertRaises(RuntimeError) as raised: self.build(fixture, planner_private_key=private)
        self.assertIs(raised.exception, failure)

    def test_independent_four_hash_factory_and_owned_prefix_exact_prior_and_each_short_budget(self):
        fixture = PlannerConfigurationFixture()
        factory = independent_factory_work(fixture)
        self.assertEqual((factory["total"][0], factory["signer_binding"]), (4, (0, 128, 0)))
        self.assertEqual(independent_call_capture(fixture)[0], 0)
        for capture in (False, True):
            expected = oracle.add(factory["total"], independent_call_capture(fixture) if capture else (0, 0, 0))
            for prior in ((0, 0, 0), (1, 17, 11)):
                full = oracle.add(prior, expected)
                for deficit in (None, 0, 1, 2):
                    maximum = tuple(value - int(index == deficit) for index, value in enumerate(full))
                    meter = self.work(maximum)
                    meter.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
                    limits = meter.limits
                    with self.subTest(capture=capture, prior=prior, deficit=deficit), \
                            patch.object(accounting._ValidationWork, "__init__",
                                side_effect=AssertionError("inert mapper allocated replacement work")):
                        if deficit is None:
                            owner = self.prefix(fixture, meter, capture=capture)
                            self.assertIs(type(owner), planning.RevocationObservedPlanner)
                            self.assertEqual(oracle.units(meter.metrics), full)
                        else:
                            with self.assertRaises(ValueError): self.prefix(fixture, meter, capture=capture)
                    self.assertIs(meter.limits, limits)
                    self.assertTrue(all(start <= used <= ceiling for start, used, ceiling in
                        zip(prior, oracle.units(meter.metrics), maximum)))
                    self.assertFalse(hasattr(meter, "_revocation_packaging_owner"))
        for mode in ("float", "negative", "limits"):
            meter = self.work()
            if mode == "float": meter.json_nodes = 0.0
            elif mode == "negative": meter.input_bytes = -1
            else: meter.limits = object()
            with self.subTest(mode=mode), self.assertRaises(ValueError): self.build(fixture, meter)

    def test_repeated_factory_and_prefix_pay_again_and_fail_on_actual_remaining_allowance(self):
        fixture = PlannerConfigurationFixture()
        for capture in (False, True):
            expected = oracle.add(independent_factory_work(fixture)["total"],
                independent_call_capture(fixture) if capture else (0, 0, 0))
            full = oracle.add(expected, expected)
            for deficit in (None, 0, 1, 2):
                maximum = tuple(value - int(index == deficit) for index, value in enumerate(full))
                meter = self.work(maximum)
                limits = meter.limits
                with self.subTest(capture=capture, deficit=deficit), \
                        patch.object(Ed25519PublicKey, "from_public_bytes",
                            wraps=Ed25519PublicKey.from_public_bytes) as constructed, \
                        patch.object(accounting._ValidationWork, "__init__",
                            side_effect=AssertionError("repeat mapper allocated replacement work")):
                    first = self.prefix(fixture, meter, capture=capture)
                    self.assertEqual(oracle.units(meter.metrics), expected)
                    self.assertEqual(constructed.call_count, 2)
                    if deficit is None:
                        second = self.prefix(fixture, meter, capture=capture)
                        self.assertIsNot(first, second)
                        self.assertEqual(constructed.call_count, 4)
                        self.assertEqual(oracle.units(meter.metrics), full)
                    else:
                        with self.assertRaises(ValueError): self.prefix(fixture, meter, capture=capture)
                        self.assertTrue(all(left <= used <= ceiling for left, used, ceiling in
                            zip(expected, oracle.units(meter.metrics), maximum)))
                self.assertIs(meter.limits, limits)


if __name__ == "__main__":
    unittest.main()
