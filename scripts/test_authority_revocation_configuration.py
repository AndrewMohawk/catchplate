#!/usr/bin/env python3
"""Configured mapping consistency and genuine private issuer composition.

The inert factory receives independently authored mappings and commitments.
That does not simulate MeasuredConfiguration.load, root/launch admission, mTLS
or PostgreSQL privileges. The composed path uses a statement/transaction model
only; actual Ed25519, original-byte verification and retained proof replay run
through their real workers when these authored controls are eventually run.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_contract
from serverware import authority_query_read_work as accounting
from serverware import authority_revocation_configuration as configuration
from serverware import authority_revocation_issuance as configured
from serverware import authority_revocation_retention as retention
from serverware.authority_store import planner_connection as admission
import test_authority_revocation_capability as capability_oracle
import test_authority_revocation_capability_producer as signer_oracle
import test_authority_revocation_invocation as invocation_oracle
import test_authority_revocation_issuer as issuer_oracle
import test_authority_revocation_issuance as issuance_oracle
import test_authority_revocation_plan as oracle


CONFIG_SCHEMA = "serverware.policyAuthorityServiceConfiguration/v6"
GENERATION_SCHEMA = "serverware.authorityGenerationLaunchContext/v4"
VERIFIER_SESSION = "serverware.policyAuthorityVerifierSession/v2"
ISSUER_SESSION = "serverware.policyAuthorityCapabilityIssuerSession/v1"
GENERATION_FIELDS = ("schema", "sequence", "digest", "predecessorDigest", "minimumRollbackSequence",
    "operationManifestDigest", "configurationPayloadBindings", "configurationBindingDigest", "roleBindingDigests")
ROLE_NAMES = ("verifier", "planner", "planner-writer", "issuer", "executor")


def raw_key(key):
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def spki(key):
    return oracle.sha(key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))


def configuration_binding(digest):
    """Independent synthetic file identity; never measured launch admission."""
    file_bytes = oracle.wire({"fixtureConfigurationDigest": digest})
    return {"fileDigest": oracle.sha(file_bytes), "payloadDigest": digest,
        "payloadSchema": CONFIG_SCHEMA, "role": "authority-service"}


def fixture_role_pins(domain):
    """Synthetic component pins, not admitted static roles or runtime closures."""
    return {role: oracle.sha(domain + role.encode("ascii")) for role in sorted(ROLE_NAMES)}


class ConfigurationFixture:
    """Local source-independent commitments, not an admitted service process."""
    def __init__(self):
        self.invocation = invocation_oracle.InvocationFixture()
        cap = self.invocation.capability
        planner_identity, verifier_identity = cap.plan.identity, cap.plan.semantic.receipt.identity
        roles = {}
        for name, key, identity in (("planner", cap.plan.key.public_key(), planner_identity),
                ("verifier", cap.key.public_key(), verifier_identity)):
            roles[name] = {"processMode": "policy-authority-" + name,
                "measurementDigest": identity["measurementDigest"],
                "attestationReceiptDigest": identity["attestationReceiptDigest"],
                "signingPublicKeyBase64Url": oracle.encoded(raw_key(key)),
                "signingSpkiDigest": spki(key), "responseSigningSpkiDigest": spki(key),
                "requestTimeoutSeconds": 1.25, "databaseConnectTimeoutSeconds": 2.5}
        roles["planner"]["plannerSessionIdentityDigest"] = planner_identity["sessionIdentityDigest"]
        roles["issuer"] = {"processMode": "policy-authority-issuer", "databaseRole": "serverware_policy_capability_issuer",
            "tlsClientDn": "CN=fixture-issuer", "tlsClientSerial": "73", "tlsIssuerDn": "CN=fixture-ca",
            "measurementDigest": oracle.sha(b"configured issuer measurement"),
            "attestationReceiptDigest": oracle.sha(b"configured issuer attestation"),
            "maximumInternalAgeNs": 60_000_000_000, "requestTimeoutSeconds": 1.25,
            "databaseConnectTimeoutSeconds": 2.5}
        self.payload = {"schema": CONFIG_SCHEMA, "sourceRevision": authority_contract.SOURCE_REVISION,
            "roles": roles, "generationSequence": 3,
            "roleBindingDigests": fixture_role_pins(b"fixture static role:"),
            "roleRuntimeClosureDigests": fixture_role_pins(b"fixture static closure:"),
            "generationBindingDigest": oracle.sha(b"configured generation intent"),
            "generationPredecessorDigest": oracle.sha(b"configured generation predecessor"),
            "generationMinimumRollbackSequence": 2,
            "issuerCredentialIssuanceDigest": oracle.sha(b"configured issuer credential issuance"),
            "replayWitness": {"identityDigest": cap.witness_identity,
                "signingPublicKeyBase64Url": oracle.encoded(raw_key(cap.witness_key.public_key())), "requestTimeoutSeconds": 0.75},
            "unusedConfiguration": {"label": "entire original mapping is committed", "nested": [1, "雪"]}}
        self.payload["issuerSessionIdentityDigest"] = oracle.framed(ISSUER_SESSION,
            *(value.encode("utf-8") for value in self.issuer_frames()))
        self.generation = {"schema": GENERATION_SCHEMA, "sequence": 3, "digest": cap.generation_digest,
            "predecessorDigest": self.payload["generationPredecessorDigest"], "minimumRollbackSequence": 2,
            "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST, "configurationPayloadBindings": [],
            "configurationBindingDigest": self.payload["generationBindingDigest"],
            "roleBindingDigests": {**self.payload["roleBindingDigests"], "witness": oracle.sha(b"fixture witness role")}}
        self.commit_payload()
        self.rebuild_originals()

    def issuer_frames(self):
        issuer = self.payload["roles"]["issuer"]
        return tuple(issuer[name] for name in ("databaseRole", "tlsClientDn", "tlsClientSerial", "tlsIssuerDn",
            "measurementDigest", "attestationReceiptDigest")) + (self.payload["issuerCredentialIssuanceDigest"],)

    def commit_payload(self):
        self.digest = oracle.framed(CONFIG_SCHEMA, oracle.wire(self.payload))
        self.generation["configurationPayloadBindings"] = [configuration_binding(self.digest)]

    def expected_verifier_identity(self):
        verifier = self.payload["roles"]["verifier"]
        return {"sessionIdentityDigest": oracle.framed(VERIFIER_SESSION,
                *(value.encode("utf-8") for value in (self.digest, verifier["measurementDigest"], verifier["attestationReceiptDigest"]))),
            "measurementDigest": verifier["measurementDigest"], "attestationReceiptDigest": verifier["attestationReceiptDigest"]}

    def expected_pins(self):
        issuer = self.payload["roles"]["issuer"]
        return {"measurementDigest": issuer["measurementDigest"], "attestationReceiptDigest": issuer["attestationReceiptDigest"],
            "credentialIssuanceDigest": self.payload["issuerCredentialIssuanceDigest"],
            "maximumAgeNs": min(issuer["maximumInternalAgeNs"], 30_000_000_000), "maximumClockSkewNs": 5_000_000_000}

    def rebuild_originals(self):
        cap = self.invocation.capability
        plan, receipt = cap.plan, cap.plan.semantic.receipt
        receipt.identity = self.expected_verifier_identity()
        receipt.evidence = receipt.sign({**receipt.evidence,
            "verifierSessionIdentityDigest": receipt.identity["sessionIdentityDigest"],
            "verifierMeasurementDigest": receipt.identity["measurementDigest"],
            "verifierAttestationReceiptDigest": receipt.identity["attestationReceiptDigest"],
            "expiresAtEpochNs": receipt.now + 10_000_000_000})
        plan.semantic._context()
        plan.deadline_epoch_ns = plan.now_epoch_ns + 20_000_000_000
        plan.deadline_monotonic_ns = plan.now_monotonic_ns + 20_000_000_000
        plan.rebuild_payload()
        cap.signer_identity = copy.deepcopy(receipt.identity)
        cap.configuration_digest = self.digest
        cap.issuer_identity = self.payload["issuerSessionIdentityDigest"]
        cap.witness_request.update(configurationDigest=self.digest, deadlineMonotonicNs=plan.deadline_monotonic_ns)
        cap.sign_request()
        cap.witness_receipt.update(deadlineMonotonicNs=plan.deadline_monotonic_ns,
            canonicalRequestDigest=oracle.framed(capability_oracle.REQUEST_SCHEMA, oracle.wire(cap.witness_request)))
        cap.sign_receipt()
        cap.rebuild()
        supplied = issuer_oracle.call_inputs(cap)
        self.invocation.historical = {name: value for name, value in supplied.items() if name in issuer_oracle.HISTORICAL_FIELDS}
        self.invocation.pins = self.expected_pins()
        self.invocation.rebuild()

    def arguments(self):
        return {"payload": self.payload, "configuration_digest": self.digest, "generation": self.generation}


def independent_configuration_work(fixture):
    """Pass counts over independent JSON, never observed factory metrics."""
    add, graph, same = oracle.add, oracle.graph_cost, oracle.canonical_comparison
    payload, generation = fixture.payload, fixture.generation
    launch = {name: generation[name] for name in GENERATION_FIELDS}
    joined = (generation["sequence"], generation["configurationBindingDigest"], generation["predecessorDigest"],
        generation["minimumRollbackSequence"], generation["operationManifestDigest"])
    role_pins = tuple(payload["roleBindingDigests"][role] for role in ROLE_NAMES)
    phases = {"capture": add(graph(payload, 1, 1), graph(launch, 1, 1)),
        "commitment": add(graph(payload), oracle.frame_cost(CONFIG_SCHEMA, (oracle.wire(payload),)),
            same(fixture.digest, fixture.digest)),
        "generation": add(same(joined, joined), graph(generation["configurationPayloadBindings"]),
            graph(generation["roleBindingDigests"]), same(role_pins, role_pins))}
    keys = []
    for role in (payload["roles"]["planner"], payload["roles"]["verifier"]):
        keys.extend((same(role["responseSigningSpkiDigest"], role["signingSpkiDigest"]),
            issuance_oracle.persistence_oracle.codec_decode(bytes(32)), (1, 88, 0),
            same(role["signingSpkiDigest"], role["signingSpkiDigest"])))
    keys.append(issuance_oracle.persistence_oracle.codec_decode(bytes(32)))
    phases["keys"] = add(*keys)
    verifier = payload["roles"]["verifier"]
    verifier_frames = (fixture.digest, verifier["measurementDigest"], verifier["attestationReceiptDigest"])
    sessions = []
    for domain, frames in ((VERIFIER_SESSION, verifier_frames), (ISSUER_SESSION, fixture.issuer_frames())):
        sessions.extend((*[oracle.utf8_cost(value) for value in frames],
            oracle.frame_cost(domain, tuple(value.encode("utf-8") for value in frames))))
    phases["sessions"] = add(*sessions,
        same(payload["issuerSessionIdentityDigest"], payload["issuerSessionIdentityDigest"]))
    return {**phases, "total": add(*(phases[name] for name in ("capture", "commitment", "generation", "keys", "sessions")))}


class RevocationConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.old_namespace = admission._DB_GLOBALS
        admission.bind_db_globals({"MetadataStoreError": issuance_oracle.persistence_oracle.StoreError})

    def tearDown(self):
        admission._DB_GLOBALS = self.old_namespace

    def work(self, limits=None):
        return accounting._ValidationWork(accounting.QueryReadValidationLimits(*(limits or ())))

    def build(self, fixture, work=None, **changes):
        return configuration._issuer_from_configuration_on_work(work=self.work() if work is None else work,
            **{**fixture.arguments(), **changes})

    def issue(self, fixture, owner, work, connection):
        cap = fixture.invocation.capability
        def opener():
            connection.event("open")
            return connection
        with patch.object(configured.time, "time_ns", return_value=cap.plan.now_epoch_ns), \
                patch.object(configured.time, "monotonic_ns", return_value=cap.plan.now_monotonic_ns):
            return configured._issue_invocation_on_configuration(owner._snapshot_configuration(),
                envelope_bytes=fixture.invocation.raw, work=work, opener=opener)

    def test_real_key_decoding_and_independent_configuration_sessions_map_exact_twelve_pins(self):
        fixture = ConfigurationFixture()
        expected_work = independent_configuration_work(fixture)["total"]
        work = self.work(expected_work)
        owner = self.build(fixture, work)
        self.assertIs(type(owner), configured.RevocationCapabilityIssuer)
        expected = issuer_oracle.constructor_inputs(fixture.invocation.capability, fixture.expected_pins())
        identities = ("sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest")
        pins = ("measurementDigest", "attestationReceiptDigest", "credentialIssuanceDigest", "maximumAgeNs", "maximumClockSkewNs")
        independent = (expected["planner_public_key"], expected["verifier_public_key"], expected["witness_public_key"],
            tuple(expected["expected_planner_identity"][name] for name in identities),
            tuple(expected["expected_verifier_identity"][name] for name in identities),
            expected["expected_issuer_session_identity_digest"], tuple(expected["issuer_pins"][name] for name in pins),
            expected["expected_configuration_digest"], expected["expected_witness_identity_digest"],
            expected["expected_generation_sequence"], expected["expected_generation_digest"],
            tuple(fixture.payload["roles"]["issuer"][name] for name in (
                "databaseRole", "tlsClientDn", "tlsClientSerial", "tlsIssuerDn", "databaseConnectTimeoutSeconds")))
        actual = owner._snapshot_configuration()
        self.assertEqual(tuple(raw_key(key) for key in actual[:3]), tuple(raw_key(key) for key in independent[:3]))
        self.assertEqual(actual[3:], independent[3:])
        self.assertEqual(actual[6][3:], (30_000_000_000, 5_000_000_000))
        self.assertEqual(actual[7], oracle.framed(CONFIG_SCHEMA, oracle.wire(fixture.payload)))
        self.assertEqual(expected_work[0], 5)
        self.assertEqual(oracle.units(work.metrics), expected_work)

    def test_factory_then_original_invocation_replays_genuine_capability_and_retained_plan_once(self):
        fixture = ConfigurationFixture()
        prefix = independent_configuration_work(fixture)["total"]
        downstream = invocation_oracle.independent_invocation_work(fixture.invocation)["composed"]
        work = self.work(oracle.add(prefix, downstream["admission"]))
        owner = self.build(fixture, work)
        cap = fixture.invocation.capability
        connection = issuer_oracle.Connection(cap, fixture.expected_pins())
        def opener():
            connection.event("open")
            return connection
        with patch.object(configured.time, "time_ns", return_value=cap.plan.now_epoch_ns), \
                patch.object(configured.time, "monotonic_ns", return_value=cap.plan.now_monotonic_ns), \
                patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                patch.object(retention.plan.mixed, "_verify", wraps=retention.plan.mixed._verify) as mixed:
            result = configured._issue_invocation_on_configuration(owner._snapshot_configuration(),
                envelope_bytes=fixture.invocation.raw, work=work, opener=opener)
        self.assertEqual(result, issuance_oracle.expected_receipt(cap))
        self.assertEqual((replay.call_count, mixed.call_count), (1, 1))
        self.assertIs(replay.call_args.kwargs["work"], work)
        self.assertEqual(connection.rows(), issuance_oracle.expected_load(cap, fixture.expected_pins(), issued=True))
        self.assertEqual((connection.outer_commits, connection.outer_rollbacks, connection.closes), (1, 0, 1))
        self.assertEqual(oracle.units(work.metrics), oracle.add(prefix, downstream["total"]))

    def test_full_original_mapping_commitment_and_role_pins_deny_before_key_callbacks(self):
        for mode in ("unused", "digest", "schema", "revision", "role", "response_pin"):
            with self.subTest(mode=mode):
                fixture = ConfigurationFixture()
                if mode == "unused":
                    fixture.payload["unusedConfiguration"]["nested"].append("changed")
                elif mode == "digest":
                    fixture.digest = oracle.sha(b"different independent commitment")
                else:
                    if mode == "schema": fixture.payload["schema"] = "wrong"
                    if mode == "revision": fixture.payload["sourceRevision"] = "wrong"
                    if mode == "role": fixture.payload["roles"]["issuer"]["processMode"] = "policy-authority-verifier"
                    if mode == "response_pin": fixture.payload["roles"]["planner"]["responseSigningSpkiDigest"] = oracle.sha(b"other response")
                    fixture.commit_payload()
                with patch.object(Ed25519PublicKey, "from_public_bytes", wraps=Ed25519PublicKey.from_public_bytes) as decoded:
                    with self.assertRaises(configuration.RevocationConfigurationError): self.build(fixture)
                self.assertEqual(decoded.call_count, 0)

    def test_launch_generation_joins_and_exact_sorted_membership_cannot_be_substituted(self):
        for mode in ("zero", "bool", "digest", "predecessor", "floor", "manifest", "absent", "duplicate", "unsorted", "empty"):
            with self.subTest(mode=mode):
                fixture = ConfigurationFixture()
                launch = fixture.generation
                if mode == "zero": launch["sequence"] = 0
                if mode == "bool": launch["sequence"] = True
                if mode == "digest": launch["configurationBindingDigest"] = oracle.sha(b"different generation intent")
                if mode == "predecessor": launch["predecessorDigest"] = oracle.sha(b"different predecessor")
                if mode == "floor": launch["minimumRollbackSequence"] = 4
                if mode == "manifest": launch["operationManifestDigest"] = oracle.sha(b"different manifest")
                if mode == "absent": launch["configurationPayloadBindings"] = [configuration_binding(oracle.sha(b"other config"))]
                if mode == "duplicate": launch["configurationPayloadBindings"] = [configuration_binding(fixture.digest), configuration_binding(fixture.digest)]
                if mode == "unsorted": launch["configurationPayloadBindings"] = sorted(
                    [configuration_binding(fixture.digest), configuration_binding(oracle.sha(b"other config"))],
                    key=lambda binding: binding["fileDigest"], reverse=True)
                if mode == "empty": launch["configurationPayloadBindings"] = []
                with patch.object(Ed25519PublicKey, "from_public_bytes", wraps=Ed25519PublicKey.from_public_bytes) as decoded:
                    with self.assertRaises(configuration.RevocationConfigurationError): self.build(fixture)
                self.assertEqual(decoded.call_count, 0)

    def test_foreign_generation_keys_invalid_work_and_unselected_context_do_not_gain_authority(self):
        comparisons = []
        class ForeignKey(str):
            __hash__ = str.__hash__
            def __eq__(self, other):
                comparisons.append(other)
                return str.__eq__(self, other)
        fixture = ConfigurationFixture()
        generation = dict(fixture.generation)
        value = generation.pop("schema")
        generation[ForeignKey("schema")] = value
        with patch.object(Ed25519PublicKey, "from_public_bytes", wraps=Ed25519PublicKey.from_public_bytes) as decoded:
            with self.assertRaises(configuration.RevocationConfigurationError): self.build(fixture, generation=generation)
        self.assertEqual((comparisons, decoded.call_count), ([], 0))
        for invalid in (None, object(), True):
            with self.assertRaises(ValueError):
                configuration._issuer_from_configuration_on_work(**fixture.arguments(), work=invalid)
        for count in (21,):
            excessive = {**fixture.generation, **{str(index): None for index in range(count - len(fixture.generation))}}
            with self.assertRaises(configuration.RevocationConfigurationError): self.build(fixture, generation=excessive)
        # Unused launch statement bodies are neither parsed nor made evidence.
        fixture.generation["unusedStatement"] = object()
        work = self.work()
        owner = self.build(fixture, work)
        self.assertEqual(owner._snapshot_configuration()[7], fixture.digest)
        self.assertEqual(oracle.units(work.metrics), independent_configuration_work(fixture)["total"])

    def test_original_fractional_configuration_spelling_is_preserved_and_nonfinite_values_deny(self):
        for value in (1.0, 1.25, -0.0, 1e-20):
            with self.subTest(value=value):
                fixture = ConfigurationFixture()
                fixture.payload["unusedConfiguration"]["fraction"] = value
                fixture.commit_payload()
                work = self.work()
                owner = self.build(fixture, work)
                self.assertEqual(owner._snapshot_configuration()[7], oracle.framed(CONFIG_SCHEMA, oracle.wire(fixture.payload)))
                self.assertEqual(oracle.units(work.metrics), independent_configuration_work(fixture)["total"])
        for value in (float("nan"), float("inf"), float("-inf")):
            fixture = ConfigurationFixture()
            fixture.payload["roles"]["issuer"]["requestTimeoutSeconds"] = value
            with patch.object(Ed25519PublicKey, "from_public_bytes", wraps=Ed25519PublicKey.from_public_bytes) as decoded:
                with self.assertRaisesRegex(configuration.RevocationConfigurationError, "not finite"):
                    self.build(fixture)
            self.assertEqual(decoded.call_count, 0)

    def test_key_codec_spki_and_every_issuer_session_frame_remain_independently_bound(self):
        for role in ("planner", "verifier"):
            for field, value in (("signingPublicKeyBase64Url", "." * 43),
                    ("signingPublicKeyBase64Url", oracle.encoded(bytes(range(32, 64)))),
                    ("signingSpkiDigest", oracle.sha(b"wrong spki"))):
                fixture = ConfigurationFixture()
                fixture.payload["roles"][role][field] = value
                if field == "signingSpkiDigest": fixture.payload["roles"][role]["responseSigningSpkiDigest"] = value
                fixture.commit_payload()
                with self.assertRaises(configuration.RevocationConfigurationError): self.build(fixture)
        for field in ("databaseRole", "tlsClientDn", "tlsClientSerial", "tlsIssuerDn", "measurementDigest", "attestationReceiptDigest", "issuerCredentialIssuanceDigest"):
            fixture = ConfigurationFixture()
            target = fixture.payload if field == "issuerCredentialIssuanceDigest" else fixture.payload["roles"]["issuer"]
            target[field] = oracle.sha(b"different pin") if field.endswith("Digest") else "different"
            fixture.commit_payload()
            with self.assertRaisesRegex(configuration.RevocationConfigurationError, "configuration failed"):
                self.build(fixture)

    def test_measured_age_can_only_tighten_and_factory_owner_does_not_borrow_input_graphs(self):
        for age in (1, 15_000_000_000, 30_000_000_000, 60_000_000_000):
            fixture = ConfigurationFixture()
            fixture.payload["roles"]["issuer"]["maximumInternalAgeNs"] = age
            fixture.commit_payload()
            owner = self.build(fixture)
            snapshot = owner._snapshot_configuration()
            self.assertEqual(snapshot[6][3:], (min(age, 30_000_000_000), 5_000_000_000))
            fixture.payload["roles"]["issuer"]["maximumInternalAgeNs"] = 9_000_000_000_000
            fixture.payload["roles"]["planner"].clear()
            fixture.generation.clear()
            self.assertIs(owner._snapshot_configuration(), snapshot)

    def test_both_input_graphs_are_owned_before_actual_key_construction_and_serialization(self):
        for phase in ("construction", "serialization"):
            fixture = ConfigurationFixture()
            expected = independent_configuration_work(fixture)["total"]
            expected_owner = self.build(fixture)._snapshot_configuration()
            work, mutations = self.work(expected), []
            original = Ed25519PublicKey.from_public_bytes
            def mutate():
                if not mutations:
                    mutations.append(phase)
                    fixture.payload["roles"]["issuer"].clear()
                    fixture.payload["roles"]["verifier"].clear()
                    fixture.payload["unusedConfiguration"].clear()
                    fixture.generation["configurationPayloadBindings"].clear()
            def construct(raw):
                actual = original(raw)
                if phase == "construction":
                    mutate()
                    return actual
                return signer_oracle._ObservedPublicBytes(actual, callback=mutate)
            with patch.object(Ed25519PublicKey, "from_public_bytes", side_effect=construct) as decoded:
                owner = self.build(fixture, work)
            actual = owner._snapshot_configuration()
            self.assertEqual(decoded.call_count, 3)
            self.assertEqual(mutations, [phase])
            self.assertEqual(tuple(raw_key(key) for key in actual[:3]), tuple(raw_key(key) for key in expected_owner[:3]))
            self.assertEqual(actual[3:], expected_owner[3:])
            self.assertEqual(oracle.units(work.metrics), expected)

    def test_real_key_callbacks_cannot_spend_refund_retype_replace_or_corrupt_spki(self):
        for phase in ("construction", "serialization"):
            for mutation in ("spend", "refund", "float", "replace"):
                with self.subTest(phase=phase, mutation=mutation):
                    fixture, work = ConfigurationFixture(), self.work()
                    limits, observed = work.limits, []
                    original = Ed25519PublicKey.from_public_bytes
                    def tamper():
                        if mutation == "spend": work.charge(input_bytes=1)
                        if mutation == "refund": work.input_bytes -= 1
                        if mutation == "float": work.json_nodes = float(work.json_nodes)
                        if mutation == "replace": work.limits = accounting.QueryReadValidationLimits()
                        observed.append((work.hash_work, work.input_bytes, work.json_nodes, work.limits))
                    def construct(raw):
                        actual = original(raw)
                        if phase == "construction":
                            tamper()
                            return actual
                        return signer_oracle._ObservedPublicBytes(actual, callback=tamper)
                    with patch.object(Ed25519PublicKey, "from_public_bytes", side_effect=construct) as decoded:
                        with self.assertRaises(configuration.RevocationConfigurationError): self.build(fixture, work)
                    self.assertEqual((decoded.call_count, len(observed)), (1, 1))
                    self.assertEqual((work.hash_work, work.input_bytes, work.json_nodes), observed[0][:3])
                    self.assertIs(work.limits, observed[0][3])
                    if mutation == "float": self.assertIs(type(work.json_nodes), float)
                    if mutation == "replace": self.assertIsNot(work.limits, limits)
        for value in (b"x" * 43, b"x" * 45, "x" * 44, b"x" * 44):
            fixture = ConfigurationFixture()
            original = Ed25519PublicKey.from_public_bytes
            def construct(raw):
                return signer_oracle._ObservedPublicBytes(original(raw), transform=lambda _actual: value)
            with patch.object(Ed25519PublicKey, "from_public_bytes", side_effect=construct) as decoded:
                with self.assertRaises(configuration.RevocationConfigurationError): self.build(fixture)
            self.assertEqual(decoded.call_count, 1)

    def test_exact_prior_and_minus_one_factory_and_composed_budgets_use_the_original_work(self):
        for composed in (False, True):
            for prior in ((0, 0, 0), (1, 17, 3)):
                fixture = ConfigurationFixture()
                pure = independent_configuration_work(fixture)["total"]
                downstream = invocation_oracle.independent_invocation_work(fixture.invocation)["composed"]
                admission_cost = oracle.add(pure, downstream["admission"]) if composed else pure
                total_cost = oracle.add(pure, downstream["total"]) if composed else pure
                for deficit in (None, 0, 1, 2):
                    with self.subTest(composed=composed, prior=prior, deficit=deficit):
                        maximum = list(oracle.add(prior, admission_cost))
                        if deficit is not None: maximum[deficit] -= 1
                        work = self.work(tuple(maximum))
                        limits = work.limits
                        work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
                        connection = issuer_oracle.Connection(fixture.invocation.capability, fixture.expected_pins())
                        def invoke():
                            owner = self.build(fixture, work)
                            return self.issue(fixture, owner, work, connection) if composed else owner
                        if deficit is None:
                            actual = invoke()
                            if composed: self.assertEqual(actual, issuance_oracle.expected_receipt(fixture.invocation.capability))
                            self.assertEqual(oracle.units(work.metrics), oracle.add(prior, total_cost))
                        else:
                            with self.assertRaises(ValueError): invoke()
                            self.assertEqual(connection.outer_commits, 0)
                        self.assertIs(work.limits, limits)
                        self.assertTrue(all(before <= spent <= ceiling for before, spent, ceiling in
                            zip(prior, oracle.units(work.metrics), maximum)))

    def test_repeated_factory_and_authenticated_retry_consume_remaining_work_not_fresh_allowances(self):
        fixture = ConfigurationFixture()
        pure = independent_configuration_work(fixture)["total"]
        work = self.work(oracle.add(pure, pure))
        limits = work.limits
        with patch.object(accounting._ValidationWork, "__init__", side_effect=AssertionError("factory allocated new work")):
            self.build(fixture, work)
            owner = self.build(fixture, work)
            with self.assertRaises(ValueError): self.build(fixture, work)
        self.assertEqual(oracle.units(work.metrics), oracle.add(pure, pure))
        self.assertIs(work.limits, limits)

        cap = fixture.invocation.capability
        first = invocation_oracle.independent_invocation_work(fixture.invocation)
        retry = issuer_oracle.independent_owner_work(cap, fixture.expected_pins(), issued=True)
        retry_total = oracle.add(first["receiver"]["total"], retry["total"])
        retry_peak = oracle.add(first["receiver"]["total"], retry["admission"])
        prefix = oracle.add(pure, first["composed"]["total"])
        maximum = tuple(max(left, right) for left, right in zip(
            oracle.add(pure, first["composed"]["admission"]), oracle.add(prefix, retry_peak)))
        work = self.work(maximum)
        limits = work.limits
        owner = self.build(fixture, work)
        first_connection = issuer_oracle.Connection(cap, fixture.expected_pins())
        second_connection = issuer_oracle.Connection(cap, fixture.expected_pins(), issued=True)
        with patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
            self.issue(fixture, owner, work, first_connection)
            self.assertEqual(first_connection.rows(), second_connection.rows())
            self.issue(fixture, owner, work, second_connection)
        self.assertEqual(replay.call_count, 2)
        self.assertEqual(oracle.units(work.metrics), oracle.add(prefix, retry_total))
        self.assertIs(work.limits, limits)
        third = issuer_oracle.Connection(cap, fixture.expected_pins(), issued=True)
        with self.assertRaises(ValueError): self.issue(fixture, owner, work, third)
        self.assertEqual(third.outer_commits, 0)


if __name__ == "__main__":
    unittest.main()
