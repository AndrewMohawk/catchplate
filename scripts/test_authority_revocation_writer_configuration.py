#!/usr/bin/env python3
"""Inert writer configuration consistency and genuine public-key components.

These independent mappings are not MeasuredConfiguration.load, an active
launch, descriptor custody or database/TLS admission. The real mapper returns
the real persistence owner, but this suite never calls persist/read/reserve,
imports the active database/service/registry, or substitutes a successful proof.
It covers factory configuration only, not future action-input ownership.
All controls are authored source; no execution evidence is asserted here.
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

from serverware import authority_query_read_work as accounting
from serverware import authority_revocation_persistence as persistence
from serverware import authority_revocation_writer_configuration as mapper
import test_authority_revocation_capability_producer as key_oracle
import test_authority_revocation_configuration as configuration_oracle
import test_authority_revocation_plan as oracle
import test_authority_revocation_verifier as verifier_oracle


IDENTITY_FIELDS = ("sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest")
DATABASE_FIELDS = ("databaseRole", "tlsClientDn", "tlsClientSerial", "tlsIssuerDn")
WRITER_ALIASES = ("plannerSessionIdentityDigest", "plannerSigningSpkiDigest", "plannerSigningPublicKeyBase64Url")
PLANNER_ALIASES = ("plannerSessionIdentityDigest", "signingSpkiDigest", "signingPublicKeyBase64Url")
WRITER_ROLE = "serverware_policy_authority_planner_writer"


class WriterConfigurationFixture:
    """Independent complete commitment; never an admitted service process."""

    def __init__(self):
        self.verifier = verifier_oracle.VerifierFixture(approval=False, include_audit=False)
        self.payload, self.generation = self.verifier.payload, self.verifier.generation
        planner = self.payload["roles"]["planner"]
        self.payload["roles"]["planner-writer"] = {
            "processMode": "policy-authority-planner-writer", "databaseRole": WRITER_ROLE,
            "tlsClientDn": "CN=fixture-writer", "tlsClientSerial": "23", "tlsIssuerDn": "CN=fixture-writer-ca",
            "measurementDigest": oracle.sha(b"independent writer measurement"),
            "attestationReceiptDigest": oracle.sha(b"independent writer attestation"),
            "responseSigningSpkiDigest": configuration_oracle.spki(self.verifier.handoff.plan.other_key.public_key()),
            "databaseConnectTimeoutSeconds": 2.5,
            **dict(zip(WRITER_ALIASES, (planner[name] for name in PLANNER_ALIASES))),
        }
        self.persistence_dsn = "postgresql://fixture-writer.invalid/fixture"
        self.commit_payload()

    def commit_payload(self):
        self.verifier.commit_payload()
        self.digest = self.verifier.digest

    def arguments(self):
        return {"payload": self.payload, "configuration_digest": self.digest,
            "generation": self.generation, "persistence_dsn": self.persistence_dsn}

    def aliases(self, writer):
        role = self.payload["roles"]["planner-writer" if writer else "planner"]
        return tuple(role[name] for name in (WRITER_ALIASES if writer else PLANNER_ALIASES))

    def expected_database_identity(self):
        writer = self.payload["roles"]["planner-writer"]
        return tuple(writer[name] for name in DATABASE_FIELDS)

    def expected_identities(self):
        planner = self.payload["roles"]["planner"]
        planner_identity = (planner["plannerSessionIdentityDigest"], planner["measurementDigest"],
                            planner["attestationReceiptDigest"])
        verifier = self.verifier.expected_verifier_identity()
        return planner_identity, tuple(verifier[name] for name in IDENTITY_FIELDS)


def independent_factory_work(fixture):
    """Literal four-hash configuration recipe plus one full alias comparison.

    The existing independent oracle counts complete input graph passes,
    canonical raw32 decode, actual DER44 serialization/hash and framed verifier
    identity. The writer adds one tuple3 comparison, no third key or signer.
    No expected count is obtained by running the mapper or reading its metrics.
    """
    base = verifier_oracle.independent_factory_work(fixture.verifier)
    aliases = oracle.canonical_comparison(fixture.aliases(True), fixture.aliases(False))
    return {**base, "writer_aliases": aliases, "total": oracle.add(base["total"], aliases)}


class RevocationWriterConfigurationTests(unittest.TestCase):
    def work(self, limits=None):
        return accounting._ValidationWork(accounting.QueryReadValidationLimits(*(limits or ())))

    def build(self, fixture, meter=None, **changes):
        return mapper._persistence_from_configuration_on_work(work=self.work() if meter is None else meter,
            **{**fixture.arguments(), **changes})

    def test_real_factory_returns_immutable_seven_pins_with_independent_writer_identity(self):
        fixture, meter = WriterConfigurationFixture(), self.work()
        expected = independent_factory_work(fixture)
        with patch.object(Ed25519PublicKey, "from_public_bytes",
                wraps=Ed25519PublicKey.from_public_bytes) as constructed:
            owner = self.build(fixture, meter)
        self.assertIs(type(owner), persistence.RevocationPlannerPersistence)
        snapshot = owner._snapshot_configuration()
        self.assertEqual(len(snapshot), 7)
        self.assertEqual(snapshot[:2], (fixture.persistence_dsn, 2))
        plan = fixture.verifier.handoff.plan
        self.assertEqual(tuple(configuration_oracle.raw_key(key) for key in snapshot[2:4]),
            (configuration_oracle.raw_key(plan.key.public_key()),
             configuration_oracle.raw_key(plan.semantic.receipt.key.public_key())))
        self.assertEqual(snapshot[4:], (*fixture.expected_identities(), fixture.expected_database_identity()))
        self.assertNotEqual(snapshot[4][1:], (fixture.payload["roles"]["planner-writer"]["measurementDigest"],
                                            fixture.payload["roles"]["planner-writer"]["attestationReceiptDigest"]))
        self.assertEqual((constructed.call_count, expected["total"][0], expected["writer_aliases"]),
                         (2, 4, (0, 1170, 16)))
        self.assertEqual(oracle.units(meter.metrics), expected["total"])
        with self.assertRaises(FrozenInstanceError): owner.persistence_dsn = "replacement"

    def test_writer_response_pin_is_separate_and_planner_aliases_must_match_before_crypto(self):
        fixture = WriterConfigurationFixture()
        self.assertNotEqual(fixture.payload["roles"]["planner-writer"]["responseSigningSpkiDigest"],
                            fixture.payload["roles"]["planner"]["signingSpkiDigest"])
        self.assertEqual(self.build(fixture)._snapshot_configuration()[4:],
                         (*fixture.expected_identities(), fixture.expected_database_identity()))
        for field in WRITER_ALIASES:
            fixture = WriterConfigurationFixture()
            writer = fixture.payload["roles"]["planner-writer"]
            writer[field] = (oracle.encoded(configuration_oracle.raw_key(fixture.verifier.handoff.plan.other_key.public_key()))
                if field == "plannerSigningPublicKeyBase64Url" else oracle.sha(b"different planner alias"))
            fixture.commit_payload()
            with self.subTest(field=field), patch.object(Ed25519PublicKey, "from_public_bytes",
                    wraps=Ed25519PublicKey.from_public_bytes) as constructed:
                with self.assertRaises(mapper.RevocationWriterConfigurationError) as raised:
                    self.build(fixture)
            self.assertEqual(constructed.call_count, 0)
            self.assertIn("planner aliases", str(raised.exception.__cause__))

    def test_complete_configuration_source_roles_and_manifest_deny_before_key_callbacks(self):
        cases = ("unused", "digest", "schema", "revision", "roles", "planner", "verifier", "planner-writer",
                 "response:planner", "response:verifier", "query_manifest", "writer_response")
        for mode in cases:
            fixture = WriterConfigurationFixture()
            if mode == "unused": fixture.payload["unusedConfiguration"]["nested"].append("changed")
            elif mode == "digest": fixture.digest = oracle.sha(b"different pinned full configuration")
            else:
                if mode == "schema": fixture.payload["schema"] = "foreign/v1"
                elif mode == "revision": fixture.payload["sourceRevision"] = "foreign revision"
                elif mode == "roles": fixture.payload["roles"] = []
                elif mode in {"planner", "verifier", "planner-writer"}:
                    fixture.payload["roles"][mode]["processMode"] = "policy-authority-executor"
                elif mode.startswith("response:"):
                    fixture.payload["roles"][mode.split(":")[1]]["responseSigningSpkiDigest"] = oracle.sha(b"other response")
                elif mode == "query_manifest": fixture.payload["queryManifestDigest"] = oracle.sha(b"other source manifest")
                elif mode == "writer_response": fixture.payload["roles"]["planner-writer"]["responseSigningSpkiDigest"] = False
                fixture.commit_payload()
            with self.subTest(mode=mode), patch.object(Ed25519PublicKey, "from_public_bytes",
                    wraps=Ed25519PublicKey.from_public_bytes) as constructed:
                with self.assertRaises(mapper.RevocationWriterConfigurationError): self.build(fixture)
            self.assertEqual(constructed.call_count, 0)

        for name in ("planner", "verifier", "planner-writer"):
            for field in ("measurementDigest", "attestationReceiptDigest", "responseSigningSpkiDigest"):
                fixture = WriterConfigurationFixture()
                fixture.payload["roles"][name][field] = False
                fixture.commit_payload()
                with self.subTest(role=name, field=field), patch.object(Ed25519PublicKey, "from_public_bytes",
                        wraps=Ed25519PublicKey.from_public_bytes) as constructed:
                    with self.assertRaises(mapper.RevocationWriterConfigurationError): self.build(fixture)
                self.assertEqual(constructed.call_count, 0)

    def test_launch_generation_membership_and_rollback_bindings_are_not_admission_tokens(self):
        for mode in ("zero", "bool", "digest", "predecessor", "floor", "manifest", "absent", "empty", "duplicate", "unsorted"):
            fixture = WriterConfigurationFixture()
            generation = fixture.generation
            if mode == "zero": generation["sequence"] = 0
            elif mode == "bool": generation["sequence"] = True
            elif mode == "digest": generation["configurationBindingDigest"] = oracle.sha(b"other generation intent")
            elif mode == "predecessor": generation["predecessorDigest"] = oracle.sha(b"other predecessor")
            elif mode == "floor": generation["minimumRollbackSequence"] = 4
            elif mode == "manifest": generation["operationManifestDigest"] = oracle.sha(b"other operation manifest")
            elif mode == "absent": generation["configurationPayloadBindings"] = [configuration_oracle.configuration_binding(oracle.sha(b"other configuration"))]
            elif mode == "empty": generation["configurationPayloadBindings"] = []
            elif mode == "duplicate": generation["configurationPayloadBindings"] = [configuration_oracle.configuration_binding(fixture.digest), configuration_oracle.configuration_binding(fixture.digest)]
            else: generation["configurationPayloadBindings"] = sorted(
                [configuration_oracle.configuration_binding(fixture.digest), configuration_oracle.configuration_binding(oracle.sha(b"second configuration"))],
                key=lambda binding: binding["fileDigest"], reverse=True)
            with self.subTest(mode=mode), patch.object(Ed25519PublicKey, "from_public_bytes",
                    wraps=Ed25519PublicKey.from_public_bytes) as constructed:
                with self.assertRaises(mapper.RevocationWriterConfigurationError): self.build(fixture)
            self.assertEqual(constructed.call_count, 0)
        fixture = WriterConfigurationFixture()
        fixture.generation["unusedStatement"] = object()
        meter = self.work()
        self.assertEqual(self.build(fixture, meter)._snapshot_configuration()[6], fixture.expected_database_identity())
        self.assertEqual(oracle.units(meter.metrics), independent_factory_work(fixture)["total"])

    def test_timeout_admits_finite_two_through_three_hundred_before_flooring(self):
        for timeout, expected in ((2, 2), (2.0, 2), (2.5, 2), (299.999, 299), (300, 300)):
            fixture = WriterConfigurationFixture()
            fixture.payload["roles"]["planner-writer"]["databaseConnectTimeoutSeconds"] = timeout
            fixture.commit_payload()
            meter = self.work()
            self.assertEqual(self.build(fixture, meter)._snapshot_configuration()[1], expected)
            self.assertEqual(oracle.units(meter.metrics), independent_factory_work(fixture)["total"])
        for timeout in (None, False, True, 0, 1, 1.25, 1.999, 300.001, "2", float("nan"), float("inf"), float("-inf")):
            fixture = WriterConfigurationFixture()
            fixture.payload["roles"]["planner-writer"]["databaseConnectTimeoutSeconds"] = timeout
            if type(timeout) is not float or math.isfinite(timeout): fixture.commit_payload()
            with self.subTest(timeout=timeout), patch.object(Ed25519PublicKey, "from_public_bytes",
                    wraps=Ed25519PublicKey.from_public_bytes) as constructed:
                with self.assertRaises(mapper.RevocationWriterConfigurationError): self.build(fixture)
            self.assertEqual(constructed.call_count, 0)

    def test_writer_tls_role_and_descriptor_are_bounded_before_any_key_callback(self):
        for field in DATABASE_FIELDS:
            values = (None, False, "", "bad\x00value", "\ud800", "x" * 4097, "\u00e9" * 2049)
            if field == "databaseRole": values += ("serverware_policy_authority_planner",)
            for value in values:
                fixture = WriterConfigurationFixture()
                fixture.payload["roles"]["planner-writer"][field] = value
                fixture.commit_payload()
                with self.subTest(field=field, value=type(value).__name__), \
                        patch.object(Ed25519PublicKey, "from_public_bytes",
                                     wraps=Ed25519PublicKey.from_public_bytes) as constructed:
                    with self.assertRaises(mapper.RevocationWriterConfigurationError): self.build(fixture)
                self.assertEqual(constructed.call_count, 0)
        fixture = WriterConfigurationFixture()
        for dsn in (None, False, "", "bad\x00dsn", "bad\ndsn", "bad\rdsn", "\ud800", "x" * 65537, "\u00e9" * 32769):
            with self.subTest(dsn=type(dsn).__name__), patch.object(Ed25519PublicKey, "from_public_bytes",
                    wraps=Ed25519PublicKey.from_public_bytes) as constructed:
                with self.assertRaises(mapper.RevocationWriterConfigurationError): self.build(fixture, persistence_dsn=dsn)
            self.assertEqual(constructed.call_count, 0)

    def test_two_canonical_public_keys_require_their_actual_spki_and_exact_der_output(self):
        for name in ("planner", "verifier"):
            for mode in ("alphabet", "padding", "size", "spki"):
                fixture = WriterConfigurationFixture()
                role = fixture.payload["roles"][name]
                if mode == "alphabet": role["signingPublicKeyBase64Url"] = "." * 43
                elif mode == "padding": role["signingPublicKeyBase64Url"] += "="
                elif mode == "size": role["signingPublicKeyBase64Url"] = oracle.encoded(bytes(31))
                else: role["signingSpkiDigest"] = role["responseSigningSpkiDigest"] = oracle.sha(b"wrong actual DER")
                if name == "planner":
                    fixture.payload["roles"]["planner-writer"].update(
                        zip(WRITER_ALIASES, (role[field] for field in PLANNER_ALIASES)))
                fixture.commit_payload()
                with self.subTest(name=name, mode=mode), self.assertRaises(mapper.RevocationWriterConfigurationError):
                    self.build(fixture)
        for index in (1, 2):
            for value in (b"x" * 43, b"x" * 45, "x" * 44, bytearray(44), b"x" * 44):
                fixture, constructed = WriterConfigurationFixture(), []
                construct = Ed25519PublicKey.from_public_bytes
                def observed_key(raw):
                    key = construct(raw)
                    constructed.append(raw)
                    return key_oracle._ObservedPublicBytes(key, transform=lambda actual: value) if len(constructed) == index else key
                with self.subTest(index=index, value=type(value).__name__), \
                        patch.object(Ed25519PublicKey, "from_public_bytes", side_effect=observed_key):
                    with self.assertRaises(mapper.RevocationWriterConfigurationError): self.build(fixture)
                self.assertEqual(len(constructed), index)

    def test_factory_has_no_per_call_key_identity_policy_or_operation_override(self):
        fixture = WriterConfigurationFixture()
        for name in ("planner_private_key", "planner_public_key", "verifier_public_key",
                     "expected_planner_identity", "expected_verifier_identity", "writer_database_identity",
                     "connect_timeout_seconds", "expected_request", "expected_before", "database_now",
                     "maximum_plan_age_ns", "operation", "opener", "read_dsn"):
            with self.subTest(name=name), patch.object(Ed25519PublicKey, "from_public_bytes",
                    wraps=Ed25519PublicKey.from_public_bytes) as constructed:
                with self.assertRaises(TypeError): self.build(fixture, **{name: object()})
            self.assertEqual(constructed.call_count, 0)
        owner = self.build(fixture)
        self.assertEqual(len(owner._snapshot_configuration()), 7)
        for name in ("planner_private_key", "maximum_plan_age_ns", "expected_before", "database_now"):
            self.assertFalse(hasattr(owner, name))

    def test_full_configuration_generation_and_descriptor_are_owned_before_each_key_callback(self):
        for target in ("construct:planner", "der:planner", "construct:verifier", "der:verifier"):
            fixture = WriterConfigurationFixture()
            identities, database = fixture.expected_identities(), fixture.expected_database_identity()
            descriptor = fixture.persistence_dsn
            original = copy.deepcopy(fixture.payload)
            expected = independent_factory_work(fixture)["total"]
            meter, events, changed, constructed = self.work(expected), [], [], []
            construct = Ed25519PublicKey.from_public_bytes
            def event(name):
                events.append(name)
                if name == target and not changed:
                    changed.append(name)
                    fixture.payload.clear()
                    fixture.generation.clear()
                    fixture.persistence_dsn = "postgresql://different.invalid/later"
            def observed_key(raw):
                key = construct(raw)
                name = "planner" if not constructed else "verifier"
                constructed.append(raw)
                event("construct:" + name)
                return key_oracle._ObservedPublicBytes(key, callback=lambda: event("der:" + name))
            with self.subTest(target=target), patch.object(Ed25519PublicKey, "from_public_bytes", side_effect=observed_key):
                owner = self.build(fixture, meter)
            snapshot = owner._snapshot_configuration()
            self.assertEqual(events, ["construct:planner", "der:planner", "construct:verifier", "der:verifier"])
            self.assertEqual(changed, [target])
            self.assertEqual(snapshot[:2], (descriptor, 2))
            self.assertEqual(snapshot[4:], (*identities, database))
            self.assertEqual(tuple(oracle.encoded(raw) for raw in constructed), tuple(
                original["roles"][name]["signingPublicKeyBase64Url"] for name in ("planner", "verifier")))
            self.assertEqual(oracle.units(meter.metrics), expected)
            self.assertFalse(hasattr(meter, "_revocation_packaging_owner"))

    def test_each_real_key_callback_rejects_meter_poison_without_repair_or_new_owner(self):
        for index in (1, 2):
            for stage in ("construction", "serialization"):
                for mode in ("spend", "refund", "float", "replace"):
                    fixture, meter = WriterConfigurationFixture(), self.work()
                    meter.charge(hashes=1, input_bytes=17, json_nodes=11)
                    entering, poison, constructed = meter.limits, [], []
                    construct = Ed25519PublicKey.from_public_bytes
                    def corrupt():
                        if mode == "spend": meter.charge(input_bytes=1)
                        elif mode == "refund": meter.input_bytes -= 1
                        elif mode == "float": meter.json_nodes = float(meter.json_nodes)
                        else: meter.limits = accounting.QueryReadValidationLimits()
                        poison.append((oracle.units(meter.metrics), meter.limits))
                    def observed_key(raw):
                        key = construct(raw)
                        constructed.append(raw)
                        if len(constructed) != index: return key
                        if stage == "construction":
                            corrupt()
                            return key
                        return key_oracle._ObservedPublicBytes(key, callback=corrupt)
                    with self.subTest(index=index, stage=stage, mode=mode), \
                            patch.object(Ed25519PublicKey, "from_public_bytes", side_effect=observed_key):
                        with self.assertRaises(mapper.RevocationWriterConfigurationError): self.build(fixture, meter)
                    self.assertEqual((len(constructed), len(poison)), (index, 1))
                    self.assertEqual(oracle.units(meter.metrics), poison[0][0])
                    self.assertIs(meter.limits, poison[0][1])
                    if mode == "float": self.assertIs(type(meter.json_nodes), float)
                    if mode == "replace": self.assertIsNot(meter.limits, entering)
                    self.assertFalse(hasattr(meter, "_revocation_packaging_owner"))
        failure = RuntimeError("native key callback failure")
        def fail(): raise failure
        fixture, construct = WriterConfigurationFixture(), Ed25519PublicKey.from_public_bytes
        with patch.object(Ed25519PublicKey, "from_public_bytes",
                side_effect=lambda raw: key_oracle._ObservedPublicBytes(construct(raw), callback=fail)):
            with self.assertRaises(RuntimeError) as raised: self.build(fixture)
        self.assertIs(raised.exception, failure)

    def test_independent_four_hash_full_byte_node_recipe_exact_prior_and_each_short_budget(self):
        fixture = WriterConfigurationFixture()
        expected = independent_factory_work(fixture)
        self.assertEqual((expected["total"][0], expected["writer_aliases"]), (4, (0, 1170, 16)))
        for prior in ((0, 0, 0), (1, 17, 11)):
            full = oracle.add(prior, expected["total"])
            for deficit in (None, 0, 1, 2):
                maximum = tuple(value - int(index == deficit) for index, value in enumerate(full))
                meter = self.work(maximum)
                meter.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
                limits = meter.limits
                # This factory has no proof replay or remaining-clamped proof
                # child. A new allowance here would be a real boundary defect.
                with self.subTest(prior=prior, deficit=deficit), \
                        patch.object(accounting._ValidationWork, "__init__",
                            side_effect=AssertionError("inert writer factory allocated replacement work")):
                    if deficit is None:
                        self.assertIs(type(self.build(fixture, meter)), persistence.RevocationPlannerPersistence)
                        self.assertEqual(oracle.units(meter.metrics), full)
                    else:
                        with self.assertRaises(ValueError): self.build(fixture, meter)
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

    def test_repeat_mapping_pays_again_and_uses_only_the_actual_remaining_allowance(self):
        fixture = WriterConfigurationFixture()
        expected = independent_factory_work(fixture)["total"]
        full = oracle.add(expected, expected)
        for deficit in (None, 0, 1, 2):
            maximum = tuple(value - int(index == deficit) for index, value in enumerate(full))
            meter = self.work(maximum)
            limits = meter.limits
            with self.subTest(deficit=deficit), \
                    patch.object(Ed25519PublicKey, "from_public_bytes",
                                 wraps=Ed25519PublicKey.from_public_bytes) as constructed, \
                    patch.object(accounting._ValidationWork, "__init__",
                        side_effect=AssertionError("repeat writer factory allocated replacement work")):
                first = self.build(fixture, meter)
                self.assertEqual((constructed.call_count, oracle.units(meter.metrics)), (2, expected))
                if deficit is None:
                    second = self.build(fixture, meter)
                    self.assertIsNot(first, second)
                    self.assertEqual((constructed.call_count, oracle.units(meter.metrics)), (4, full))
                else:
                    with self.assertRaises(ValueError): self.build(fixture, meter)
                    self.assertTrue(all(left <= used <= ceiling for left, used, ceiling in
                        zip(expected, oracle.units(meter.metrics), maximum)))
            self.assertIs(meter.limits, limits)
            self.assertFalse(hasattr(meter, "_revocation_packaging_owner"))


if __name__ == "__main__":
    unittest.main()
