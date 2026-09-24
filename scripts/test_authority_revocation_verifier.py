#!/usr/bin/env python3
"""Configured verifier mapping and genuine original-byte handoff components.

These independent local mappings are not MeasuredConfiguration admission or
an active launch. Root observations come from the genuine two-read worker on
a deterministic cursor, not a privileged database. Real Ed25519 and retained
proof workers remain mandatory. No service import, successful proof stub,
persistence receipt, physical-clock provenance or public route is claimed.
Authored source only; execution belongs to the frozen verification lane.
"""
from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_contract as authority
from serverware import authority_query_read_work as accounting
from serverware import authority_revocation_verifier as verifier
from serverware import authority_revocation_retention as retention
import test_authority_revocation_configuration as configuration_oracle
import test_authority_revocation_capability_producer as signer_oracle
import test_authority_revocation_handoff as handoff_oracle
import test_authority_revocation_observed as observed_oracle
import test_authority_revocation_persistence as persistence_oracle
import test_authority_revocation_plan as oracle
import test_authority_revocation_retention as record_oracle


CONFIG_SCHEMA = "serverware.policyAuthorityServiceConfiguration/v2"
GENERATION_SCHEMA = "serverware.authorityGenerationLaunchContext/v1"
VERIFIER_SESSION = "serverware.policyAuthorityVerifierSession/v2"
GENERATION_FIELDS = ("schema", "sequence", "digest", "predecessorDigest",
    "minimumRollbackSequence", "operationManifestDigest", "configurationDigests")
IDENTITY_FIELDS = ("sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest")
CONFIGURED_FIELDS = ("expectedPlannerIdentity", "expectedVerifierIdentity", "maximumAssertionAgeNs",
    "maximumPlanAgeNs", "maximumClockSkewNs")
CALL_FIELDS = ("expectedCapabilityId", "expectedPlannerTransactionId", "expectedFence",
    "expectedApproverPolicyDigest", "reservedAtEpochNs", "deadlineEpochNs", "deadlineMonotonicNs",
    "nowEpochNs", "nowMonotonicNs")


class VerifierFixture:
    """Commit literal mappings and genuinely re-sign affected original graphs."""

    def __init__(self, **options):
        self.handoff = handoff_oracle.HandoffFixture(**options)
        plan, receipt = self.handoff.plan, self.handoff.plan.semantic.receipt
        roles = {}
        for name, key, identity in (("planner", plan.key.public_key(), plan.identity),
                ("verifier", receipt.key.public_key(), receipt.identity)):
            roles[name] = {"processMode": "policy-authority-" + name,
                "measurementDigest": identity["measurementDigest"],
                "attestationReceiptDigest": identity["attestationReceiptDigest"],
                "signingPublicKeyBase64Url": oracle.encoded(configuration_oracle.raw_key(key)),
                "signingSpkiDigest": configuration_oracle.spki(key),
                "responseSigningSpkiDigest": configuration_oracle.spki(key),
                "requestTimeoutSeconds": 1.25, "databaseConnectTimeoutSeconds": 2.5,
                "maximumInternalAgeNs": 60_000_000_000}
        roles["planner"]["plannerSessionIdentityDigest"] = plan.identity["sessionIdentityDigest"]
        self.payload = {"schema": CONFIG_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
            "roles": roles, "queryManifestDigest": oracle.source_manifest_digest(),
            "generationSequence": 3, "generationDigest": oracle.sha(b"verifier generation"),
            "generationPredecessorDigest": oracle.sha(b"verifier predecessor"),
            "generationMinimumRollbackSequence": 2,
            "webauthn": {"maximumChallengeAgeNs": 90_000_000_000},
            "unusedConfiguration": {"label": "full original mapping", "nested": [1, "雪", -0.0]}}
        self.generation = {"schema": GENERATION_SCHEMA, "sequence": 3,
            "digest": self.payload["generationDigest"],
            "predecessorDigest": self.payload["generationPredecessorDigest"],
            "minimumRollbackSequence": 2, "operationManifestDigest": authority.OPERATION_MANIFEST_DIGEST,
            "configurationDigests": []}
        self.commit_payload()
        self.rebuild_originals()

    def commit_payload(self):
        self.digest = oracle.framed(CONFIG_SCHEMA, oracle.wire(self.payload))
        self.generation["configurationDigests"] = [self.digest]

    def expected_verifier_identity(self):
        role = self.payload["roles"]["verifier"]
        return {"sessionIdentityDigest": oracle.framed(VERIFIER_SESSION,
                *(value.encode("utf-8") for value in (self.digest, role["measurementDigest"], role["attestationReceiptDigest"]))),
            "measurementDigest": role["measurementDigest"], "attestationReceiptDigest": role["attestationReceiptDigest"]}

    def rebuild_originals(self):
        plan, receipt = self.handoff.plan, self.handoff.plan.semantic.receipt
        planner = self.payload["roles"]["planner"]
        plan.identity = {"sessionIdentityDigest": planner["plannerSessionIdentityDigest"],
            "measurementDigest": planner["measurementDigest"], "attestationReceiptDigest": planner["attestationReceiptDigest"]}
        receipt.identity = self.expected_verifier_identity()
        receipt.evidence = receipt.sign({**receipt.evidence,
            "verifierSessionIdentityDigest": receipt.identity["sessionIdentityDigest"],
            "verifierMeasurementDigest": receipt.identity["measurementDigest"],
            "verifierAttestationReceiptDigest": receipt.identity["attestationReceiptDigest"],
            "expiresAtEpochNs": receipt.now + 10_000_000_000})
        plan.semantic._context()
        plan.maximum_assertion_age_ns = self.payload["webauthn"]["maximumChallengeAgeNs"]
        plan.maximum_plan_age_ns = min(self.payload["roles"]["verifier"]["maximumInternalAgeNs"], 30_000_000_000)
        plan.maximum_clock_skew_ns = 5_000_000_000
        plan.deadline_epoch_ns = plan.now_epoch_ns + 20_000_000_000
        plan.deadline_monotonic_ns = plan.now_monotonic_ns + 20_000_000_000
        plan.rebuild_payload()
        self.handoff.expected_context = oracle.production_context(plan)
        self.handoff.context = {name: copy.deepcopy(value) for name, value in self.handoff.expected_context.items()
            if name != "expectedBefore"}
        self.context = {name: copy.deepcopy(self.handoff.context[name]) for name in CALL_FIELDS}
        self.handoff.refresh_bytes()

    def factory_arguments(self):
        return {"payload": self.payload, "configuration_digest": self.digest, "generation": self.generation}

    def arguments(self):
        return {"envelope_bytes": self.handoff.raw, "evaluation_context_bytes": self.handoff.context_raw,
            "expected_request": self.handoff.request, "context": self.context, "root_inventory": self.handoff.inventory}

    def constructor_arguments(self):
        plan = self.handoff.plan
        return {"planner_public_key": plan.key.public_key(), "verifier_public_key": plan.semantic.receipt.key.public_key(),
            "expected_planner_identity": copy.deepcopy(plan.identity),
            "expected_verifier_identity": self.expected_verifier_identity(),
            "maximum_assertion_age_ns": self.payload["webauthn"]["maximumChallengeAgeNs"],
            "maximum_plan_age_ns": min(self.payload["roles"]["verifier"]["maximumInternalAgeNs"], 30_000_000_000),
            "maximum_clock_skew_ns": 5_000_000_000, "expected_configuration_digest": self.digest,
            "expected_generation_sequence": 3, "expected_generation_digest": self.generation["digest"]}


def independent_factory_work(fixture):
    """Four actual hashes and literal complete configuration pass recipes."""
    add, graph, same = oracle.add, oracle.graph_cost, oracle.canonical_comparison
    payload, generation = fixture.payload, fixture.generation
    launch = {name: generation[name] for name in GENERATION_FIELDS}
    joined = (generation["sequence"], generation["digest"], generation["predecessorDigest"],
        generation["minimumRollbackSequence"], generation["operationManifestDigest"])
    phases = {"capture": add(graph(payload, 1, 1), graph(launch, 1, 1)),
        "commitment": add(graph(payload), oracle.frame_cost(CONFIG_SCHEMA, (oracle.wire(payload),)),
            same(fixture.digest, fixture.digest)),
        "generation": add(same(joined, joined), graph(generation["configurationDigests"]))}
    keys = [same(payload["queryManifestDigest"], oracle.source_manifest_digest())]
    for role in (payload["roles"]["planner"], payload["roles"]["verifier"]):
        keys.extend((same(role["responseSigningSpkiDigest"], role["signingSpkiDigest"]),
            persistence_oracle.codec_decode(bytes(32)), (1, 88, 0),
            same(role["signingSpkiDigest"], role["signingSpkiDigest"])))
    phases["keys"] = add(*keys)
    role = payload["roles"]["verifier"]
    frames = (fixture.digest, role["measurementDigest"], role["attestationReceiptDigest"])
    phases["session"] = add(*(oracle.utf8_cost(value) for value in frames),
        oracle.frame_cost(VERIFIER_SESSION, tuple(value.encode("utf-8") for value in frames)))
    return {**phases, "total": add(*(phases[name] for name in ("capture", "commitment", "generation", "keys", "session")))}


def independent_owner_work(fixture):
    prefix = oracle.add(observed_oracle.copy_cost({"expectedRequest": fixture.handoff.request, "context": fixture.context}),
        observed_oracle.copy_cost(observed_oracle.capture_graph(fixture.handoff.primary, fixture.handoff.heads)))
    inner = handoff_oracle.independent_work(fixture.handoff)
    return {"capture": prefix, "total": oracle.add(prefix, inner["total"]),
        "admission": oracle.add(prefix, inner["admission"])}


class RevocationVerifierTests(unittest.TestCase):
    def build(self, fixture, meter=None, **changes):
        return verifier._verifier_from_configuration_on_work(work=handoff_oracle.work() if meter is None else meter,
            **{**fixture.factory_arguments(), **changes})

    def verify(self, fixture, owner=None, meter=None, **changes):
        if owner is None:
            owner = self.build(fixture)
        return owner.verify_handoff(work=handoff_oracle.work() if meter is None else meter,
            **{**fixture.arguments(), **changes})

    def test_full_configuration_maps_exact_two_keys_identities_and_measured_policy_ten_tuple(self):
        fixture = VerifierFixture(approval=False, include_audit=False)
        expected = independent_factory_work(fixture)["total"]
        meter = handoff_oracle.work(expected)
        owner = self.build(fixture, meter)
        self.assertIs(type(owner), verifier.RevocationPlanVerifier)
        snapshot = owner._snapshot_configuration()
        self.assertEqual(len(snapshot), 10)
        self.assertEqual(tuple(configuration_oracle.raw_key(key) for key in snapshot[:2]),
            (configuration_oracle.raw_key(fixture.handoff.plan.key.public_key()),
             configuration_oracle.raw_key(fixture.handoff.plan.semantic.receipt.key.public_key())))
        self.assertEqual(snapshot[2:], (tuple(fixture.handoff.plan.identity[name] for name in IDENTITY_FIELDS),
            tuple(fixture.expected_verifier_identity()[name] for name in IDENTITY_FIELDS),
            90_000_000_000, 30_000_000_000, 5_000_000_000, fixture.digest, 3, fixture.generation["digest"]))
        self.assertEqual(expected[0], 4)
        self.assertEqual(handoff_oracle.units(meter), expected)
        with self.assertRaises(FrozenInstanceError): owner._configuration = ()

    def test_factory_and_owner_replay_original_bytes_two_planner_signatures_and_one_proof(self):
        fixture = VerifierFixture(approval=False, include_audit=False)
        prefix, downstream = independent_factory_work(fixture)["total"], independent_owner_work(fixture)
        meter = handoff_oracle.work(oracle.add(prefix, downstream["admission"]))
        events, construct = [], Ed25519PublicKey.from_public_bytes
        def observed_key(raw):
            role = "planner" if not events else "assertion"
            events.append("construct:" + role)
            return oracle._CallbackPublicKey(construct(raw), lambda: events.append(role))
        with patch.object(Ed25519PublicKey, "from_public_bytes", side_effect=observed_key):
            owner = self.build(fixture, meter)
        with patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                patch.object(retention.plan.semantics.retained, "_compute_and_package",
                    wraps=retention.plan.semantics.retained._compute_and_package) as proof:
            result = self.verify(fixture, owner, meter)
        self.assertEqual(events, ["construct:planner", "construct:assertion", "planner", "planner", "assertion"])
        self.assertEqual((replay.call_count, proof.call_count), (1, 1))
        self.assertIs(replay.call_args.kwargs["work"], meter)
        self.assertIs(replay.call_args.kwargs["envelope_bytes"], fixture.handoff.raw)
        self.assertIs(replay.call_args.kwargs["evaluation_context_bytes"], fixture.handoff.context_raw)
        self.assertEqual(result.expected_context, fixture.handoff.expected_context)
        self.assertEqual(result.database_now, fixture.handoff.plan.semantic.database_now)
        self.assertEqual(result.retained_record.header,
            record_oracle.record_header(fixture.handoff.plan, fixture.handoff.raw, fixture.handoff.context_raw))
        self.assertEqual((result.metrics.planner_signature_attempts, result.metrics.semantic_replays), (2, 1))
        self.assertEqual(handoff_oracle.units(meter), oracle.add(prefix, downstream["total"]))

    def test_full_commitment_source_roles_and_manifest_deny_before_key_callbacks(self):
        for mode in ("unused", "digest", "schema", "revision", "planner_mode", "verifier_mode",
                "response_pin", "query_manifest"):
            with self.subTest(mode=mode):
                fixture = VerifierFixture(approval=False, include_audit=False)
                if mode == "unused": fixture.payload["unusedConfiguration"]["nested"].append("changed")
                elif mode == "digest": fixture.digest = oracle.sha(b"wrong independently pinned configuration")
                else:
                    if mode == "schema": fixture.payload["schema"] = "wrong"
                    if mode == "revision": fixture.payload["sourceRevision"] = "wrong"
                    if mode.endswith("_mode"):
                        fixture.payload["roles"][mode[:-5]]["processMode"] = "policy-authority-issuer"
                    if mode == "response_pin":
                        fixture.payload["roles"]["verifier"]["responseSigningSpkiDigest"] = oracle.sha(b"other response")
                    if mode == "query_manifest": fixture.payload["queryManifestDigest"] = oracle.sha(b"other source manifest")
                    fixture.commit_payload()
                with patch.object(Ed25519PublicKey, "from_public_bytes", wraps=Ed25519PublicKey.from_public_bytes) as decoded:
                    with self.assertRaises(verifier.RevocationVerifierError): self.build(fixture)
                self.assertEqual(decoded.call_count, 0)

    def test_launch_binding_sorted_membership_and_foreign_keys_are_checked_before_crypto(self):
        for mode in ("zero", "bool", "digest", "predecessor", "floor", "manifest", "absent", "empty", "duplicate", "unsorted"):
            with self.subTest(mode=mode):
                fixture = VerifierFixture(approval=False, include_audit=False)
                launch = fixture.generation
                if mode == "zero": launch["sequence"] = 0
                if mode == "bool": launch["sequence"] = True
                if mode == "digest": launch["digest"] = oracle.sha(b"other generation")
                if mode == "predecessor": launch["predecessorDigest"] = oracle.sha(b"other predecessor")
                if mode == "floor": launch["minimumRollbackSequence"] = 4
                if mode == "manifest": launch["operationManifestDigest"] = oracle.sha(b"other operations")
                if mode == "absent": launch["configurationDigests"] = [oracle.sha(b"other config")]
                if mode == "empty": launch["configurationDigests"] = []
                if mode == "duplicate": launch["configurationDigests"] = [fixture.digest, fixture.digest]
                if mode == "unsorted":
                    launch["configurationDigests"] = sorted([fixture.digest, oracle.sha(b"other config")], reverse=True)
                with patch.object(Ed25519PublicKey, "from_public_bytes", wraps=Ed25519PublicKey.from_public_bytes) as decoded:
                    with self.assertRaises(verifier.RevocationVerifierError): self.build(fixture)
                self.assertEqual(decoded.call_count, 0)
        comparisons = []
        class ForeignKey(str):
            __hash__ = str.__hash__
            def __eq__(self, other):
                comparisons.append(other)
                return str.__eq__(self, other)
        fixture = VerifierFixture(approval=False, include_audit=False)
        launch = dict(fixture.generation)
        schema = launch.pop("schema")
        launch[ForeignKey("schema")] = schema
        with patch.object(Ed25519PublicKey, "from_public_bytes", wraps=Ed25519PublicKey.from_public_bytes) as decoded:
            with self.assertRaises(verifier.RevocationVerifierError): self.build(fixture, generation=launch)
        self.assertEqual((comparisons, decoded.call_count), ([], 0))
        # Extra unselected launch statement contents are not new proof inputs.
        fixture.generation["unusedStatement"] = object()
        meter = handoff_oracle.work()
        owner = self.build(fixture, meter)
        self.assertEqual(owner._snapshot_configuration()[7], fixture.digest)
        self.assertEqual(handoff_oracle.units(meter), independent_factory_work(fixture)["total"])

    def test_measured_assertion_age_is_not_capped_plan_age_only_tightens_and_float_config_is_exact(self):
        for assertion_age, internal_age in ((1, 1), (45_000_000_000, 15_000_000_000),
                (90_000_000_000, 30_000_000_000), (300_000_000_000, 60_000_000_000)):
            fixture = VerifierFixture(approval=False, include_audit=False)
            fixture.payload["webauthn"]["maximumChallengeAgeNs"] = assertion_age
            fixture.payload["roles"]["verifier"]["maximumInternalAgeNs"] = internal_age
            fixture.commit_payload()
            self.assertEqual(self.build(fixture)._snapshot_configuration()[4:7],
                (assertion_age, min(internal_age, 30_000_000_000), 5_000_000_000))
        for role, field in (("webauthn", "maximumChallengeAgeNs"), ("verifier", "maximumInternalAgeNs")):
            for value in (0, -1, True, 1.0, "1", 2**63):
                fixture = VerifierFixture(approval=False, include_audit=False)
                target = fixture.payload["webauthn"] if role == "webauthn" else fixture.payload["roles"][role]
                target[field] = value
                fixture.commit_payload()
                with self.subTest(role=role, value=value), self.assertRaises(verifier.RevocationVerifierError):
                    self.build(fixture)
        for fraction in (1.0, 1.25, -0.0, 1e-20):
            fixture = VerifierFixture(approval=False, include_audit=False)
            fixture.payload["unusedConfiguration"]["fraction"] = fraction
            fixture.commit_payload()
            meter = handoff_oracle.work()
            owner = self.build(fixture, meter)
            self.assertEqual(owner._snapshot_configuration()[7], oracle.framed(CONFIG_SCHEMA, oracle.wire(fixture.payload)))
            self.assertEqual(handoff_oracle.units(meter), independent_factory_work(fixture)["total"])
        for value in (float("nan"), float("inf"), float("-inf")):
            fixture = VerifierFixture(approval=False, include_audit=False)
            fixture.payload["roles"]["verifier"]["requestTimeoutSeconds"] = value
            with self.assertRaises(verifier.RevocationVerifierError): self.build(fixture)

    def test_real_configured_key_roles_require_canonical_raw_transport_and_matching_spki(self):
        for role in ("planner", "verifier"):
            for mode in ("codec", "wrong_spki", "different_pinned_key"):
                with self.subTest(role=role, mode=mode):
                    fixture = VerifierFixture(approval=False, include_audit=False)
                    entry = fixture.payload["roles"][role]
                    if mode == "codec": entry["signingPublicKeyBase64Url"] = "." * 43
                    elif mode == "wrong_spki":
                        entry["signingSpkiDigest"] = entry["responseSigningSpkiDigest"] = oracle.sha(b"wrong DER pin")
                    else:
                        other = fixture.handoff.plan.other_key.public_key()
                        entry["signingPublicKeyBase64Url"] = oracle.encoded(configuration_oracle.raw_key(other))
                        entry["signingSpkiDigest"] = entry["responseSigningSpkiDigest"] = configuration_oracle.spki(other)
                    fixture.commit_payload()
                    if mode != "different_pinned_key":
                        with self.assertRaises(verifier.RevocationVerifierError): self.build(fixture)
                        continue
                    # The new configuration is internally coherent. Genuine
                    # originals still use the real prior private key, not an
                    # approval callback, and therefore cannot authenticate.
                    fixture.rebuild_originals()
                    owner = self.build(fixture)
                    with patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
                        with self.assertRaises(ValueError): self.verify(fixture, owner)
                    self.assertEqual(replay.call_count, 0 if role == "planner" else 1)

    def test_public_owner_context_is_closed_and_cannot_override_configured_identities_or_policy(self):
        fixture = VerifierFixture(approval=False, include_audit=False)
        owner = self.build(fixture)
        contexts = [fixture.handoff.context, {**fixture.context, "databaseCutoffUs": fixture.handoff.plan.semantic.cutoff_us}]
        contexts.extend({**fixture.context, name: fixture.handoff.context[name]} for name in CONFIGURED_FIELDS)
        contexts.extend({name: value for name, value in fixture.context.items() if name != omitted} for omitted in CALL_FIELDS)
        contexts.extend({**fixture.context, field: True} for field in ("expectedFence", "nowEpochNs", "nowMonotonicNs"))
        with patch.object(verifier.handoff, "_verify_observed_plan_handoff_on_work",
                wraps=verifier.handoff._verify_observed_plan_handoff_on_work) as raw:
            for context in contexts:
                with self.subTest(fields=tuple(context)), self.assertRaises(ValueError): self.verify(fixture, owner, context=context)
            for changes in ({"envelope_bytes": bytearray(fixture.handoff.raw)},
                    {"evaluation_context_bytes": memoryview(fixture.handoff.context_raw)},
                    {"expected_request": None}, {"root_inventory": object()}):
                with self.assertRaises(ValueError): self.verify(fixture, owner, **changes)
            for name in ("planner_public_key", "verifier_public_key", "database_now", "opener", "configuration"):
                with self.assertRaises(TypeError): self.verify(fixture, owner, **{name: object()})
        self.assertEqual(raw.call_count, 0)
        with self.assertRaises(ValueError): self.verify(fixture, owner, meter=object())
        invalid = fixture.constructor_arguments()
        invalid["maximum_plan_age_ns"] = 30_000_000_001
        with self.assertRaises(ValueError): verifier.RevocationPlanVerifier(**invalid)
        invalid = fixture.constructor_arguments()
        invalid["maximum_clock_skew_ns"] = 5_000_000_001
        with self.assertRaises(ValueError): verifier.RevocationPlanVerifier(**invalid)

    def test_original_wire_cutoff_and_resigned_false_result_still_reach_real_handoff_guards(self):
        for mode in ("noncanonical", "bad_signature", "unsigned_cutoff", "signed_disagreement", "context_cutoff", "false_result"):
            with self.subTest(mode=mode):
                fixture = VerifierFixture(approval=False, include_audit=False)
                plan = fixture.handoff.plan
                if mode == "bad_signature": plan.resign(key=plan.other_key)
                if mode == "unsigned_cutoff": plan.envelope["payload"]["rootTransition"]["cutoffUs"] += 1
                if mode == "signed_disagreement":
                    plan.payload["rootTransition"]["cutoffUs"] += 1
                    plan.rehash()
                if mode == "false_result":
                    plan.payload["expectedResult"]["revoked"] = not plan.payload["expectedResult"]["revoked"]
                    plan.rehash()
                fixture.handoff.refresh_bytes()
                if mode == "noncanonical": fixture.handoff.raw = b" " + fixture.handoff.raw
                if mode == "context_cutoff":
                    context = record_oracle.record_context(plan)
                    context["databaseCutoffUs"] += 1
                    fixture.handoff.context_raw = oracle.wire(context)
                owner = self.build(fixture)
                with patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                        patch.object(retention.plan.semantics.retained, "_compute_and_package",
                            wraps=retention.plan.semantics.retained._compute_and_package) as proof:
                    with self.assertRaises(ValueError): self.verify(fixture, owner)
                self.assertEqual(replay.call_count, 1 if mode in ("context_cutoff", "false_result") else 0)
                self.assertEqual(proof.call_count, 1 if mode == "false_result" else 0)

    def test_every_independent_context_pin_request_and_selected_root_remains_binding(self):
        fixture = VerifierFixture(approval=False, include_audit=False)
        owner = self.build(fixture)
        for field in CALL_FIELDS:
            context = copy.deepcopy(fixture.context)
            value = context[field]
            context[field] = value + 1 if type(value) is int else oracle.sha(b"changed independent pin")
            with self.subTest(field=field), self.assertRaises(ValueError): self.verify(fixture, owner, context=context)
        request = copy.deepcopy(fixture.handoff.request)
        request["arguments"]["reason"] = "independently different request"
        with self.assertRaises(ValueError): self.verify(fixture, owner, expected_request=request)
        for kind in ("business", "authorization", "counted"):
            inventory = copy.deepcopy(fixture.handoff.inventory)
            if kind == "counted":
                head = next(head for head in inventory.counted_heads if head.index_id in fixture.handoff.selected_ids)
                object.__setattr__(head.index_root, "digest", oracle.sha(b"different independent root"))
            else:
                roots = inventory.business_roots if kind == "business" else inventory.authorization_roots
                object.__setattr__(roots[0], "root_digest", oracle.sha(b"different independent root"))
            with self.subTest(kind=kind), self.assertRaises(ValueError): self.verify(fixture, owner, root_inventory=inventory)

    def test_configuration_graphs_are_owned_before_actual_key_construction_and_serialization(self):
        for stage in ("construction", "serialization"):
            fixture = VerifierFixture(approval=False, include_audit=False)
            expected = independent_factory_work(fixture)["total"]
            expected_snapshot = self.build(fixture)._snapshot_configuration()
            meter, mutations = handoff_oracle.work(expected), []
            construct = Ed25519PublicKey.from_public_bytes
            def mutate():
                if not mutations:
                    mutations.append(stage)
                    fixture.payload["roles"]["planner"].clear()
                    fixture.payload["roles"]["verifier"].clear()
                    fixture.payload["webauthn"].clear()
                    fixture.payload["unusedConfiguration"].clear()
                    fixture.generation["configurationDigests"].clear()
            def observed_key(raw):
                key = construct(raw)
                if stage == "construction":
                    mutate()
                    return key
                return signer_oracle._ObservedPublicBytes(key, callback=mutate)
            with patch.object(Ed25519PublicKey, "from_public_bytes", side_effect=observed_key) as decoded:
                owner = self.build(fixture, meter)
            snapshot = owner._snapshot_configuration()
            self.assertEqual(decoded.call_count, 2)
            self.assertEqual(mutations, [stage])
            self.assertEqual(tuple(configuration_oracle.raw_key(key) for key in snapshot[:2]),
                tuple(configuration_oracle.raw_key(key) for key in expected_snapshot[:2]))
            self.assertEqual(snapshot[2:], expected_snapshot[2:])
            self.assertEqual(handoff_oracle.units(meter), expected)

    def test_both_real_key_callbacks_guard_work_and_exact_spki_without_refund(self):
        for key_index in (1, 2):
            for stage in ("construction", "serialization"):
                for mode in ("spend", "refund", "float", "replace"):
                    with self.subTest(key_index=key_index, stage=stage, mode=mode):
                        fixture, meter = VerifierFixture(approval=False, include_audit=False), handoff_oracle.work()
                        entering_limits, poison, calls = meter.limits, [], []
                        construct = Ed25519PublicKey.from_public_bytes
                        def corrupt():
                            if mode == "spend": meter.charge(input_bytes=1)
                            elif mode == "refund": meter.input_bytes -= 1
                            elif mode == "float": meter.json_nodes = float(meter.json_nodes)
                            else: meter.limits = accounting.QueryReadValidationLimits()
                            poison.append((handoff_oracle.units(meter), meter.limits))
                        def observed_key(raw):
                            key = construct(raw)
                            calls.append(raw)
                            if len(calls) != key_index: return key
                            if stage == "construction":
                                corrupt()
                                return key
                            return signer_oracle._ObservedPublicBytes(key, callback=corrupt)
                        with patch.object(Ed25519PublicKey, "from_public_bytes", side_effect=observed_key):
                            with self.assertRaises(verifier.RevocationVerifierError): self.build(fixture, meter)
                        self.assertEqual((len(calls), len(poison)), (key_index, 1))
                        self.assertEqual(handoff_oracle.units(meter), poison[0][0])
                        self.assertIs(meter.limits, poison[0][1])
                        if mode == "float": self.assertIs(type(meter.json_nodes), float)
                        if mode == "replace": self.assertIsNot(meter.limits, entering_limits)
        for value in (b"x" * 43, b"x" * 45, "x" * 44, b"x" * 44):
            fixture = VerifierFixture(approval=False, include_audit=False)
            construct = Ed25519PublicKey.from_public_bytes
            def observed_key(raw):
                return signer_oracle._ObservedPublicBytes(construct(raw), transform=lambda actual: value)
            with patch.object(Ed25519PublicKey, "from_public_bytes", side_effect=observed_key) as decoded:
                with self.assertRaises(verifier.RevocationVerifierError): self.build(fixture)
            self.assertEqual(decoded.call_count, 1)

    def test_owner_snapshot_and_caller_graphs_are_detached_before_signature_callbacks(self):
        fixture = VerifierFixture(approval=False, include_audit=False)
        expected = independent_owner_work(fixture)
        original_context = copy.deepcopy(fixture.handoff.expected_context)
        raw, context_raw = fixture.handoff.raw, fixture.handoff.context_raw
        meter, changes = handoff_oracle.work(expected["admission"]), []
        def mutate_originals():
            if changes: return
            changes.append("bootstrap")
            fixture.context.clear()
            fixture.handoff.request["arguments"]["reason"] = "changed after capture"
            object.__setattr__(fixture.handoff.inventory.business_roots[0], "root_digest", oracle.sha(b"changed primary"))
            object.__setattr__(fixture.handoff.inventory.counted_heads[0].index_root, "digest", oracle.sha(b"changed head"))
            fixture.handoff.raw, fixture.handoff.context_raw = b"{}", b"{}"
            supplied["expected_planner_identity"].clear()
            supplied["expected_verifier_identity"].clear()
            object.__setattr__(owner, "_configuration", ())
        supplied = fixture.constructor_arguments()
        key = oracle._CallbackPublicKey(fixture.handoff.plan.key.public_key(), mutate_originals)
        supplied["planner_public_key"] = key
        owner = verifier.RevocationPlanVerifier(**supplied)
        result = self.verify(fixture, owner, meter)
        self.assertEqual((changes, key.calls), (["bootstrap"], 2))
        self.assertEqual(result.expected_context, original_context)
        self.assertEqual(result.retained_record.envelope_bytes, raw)
        self.assertEqual(result.retained_record.context_bytes, context_raw)
        self.assertEqual(handoff_oracle.units(meter), expected["total"])
        result.expected_context["expectedPlannerIdentity"].clear()
        result.expected_context["expectedBefore"]["businessBeforeRoots"].clear()
        self.assertEqual(result.retained_record.context["expectedPlannerIdentity"], original_context["expectedPlannerIdentity"])
        self.assertEqual(result.retained_record.context["expectedBefore"], original_context["expectedBefore"])
        with self.assertRaises(ValueError): owner._snapshot_configuration()

    def test_actual_signature_callbacks_preserve_poison_and_respect_real_retained_unwind(self):
        for stage in ("bootstrap", "retained-planner", "assertion"):
            for mode in ("spend", "refund", "float", "replace"):
                with self.subTest(stage=stage, mode=mode):
                    fixture, meter = VerifierFixture(approval=False, include_audit=False), handoff_oracle.work()
                    meter.charge(hashes=1, input_bytes=17, json_nodes=11)
                    entering_limits, poison, planner_calls = meter.limits, [], []
                    def corrupt():
                        if mode == "spend": meter.charge(input_bytes=1)
                        elif mode == "refund": meter.hash_work -= 1
                        elif mode == "float": meter.input_bytes = float(meter.input_bytes)
                        else: meter.limits = accounting.QueryReadValidationLimits()
                        poison.append((handoff_oracle.units(meter), meter.limits))
                    def planner_callback():
                        planner_calls.append(stage)
                        if stage == "bootstrap" and len(planner_calls) == 1 or stage == "retained-planner" and len(planner_calls) == 2:
                            corrupt()
                    supplied = fixture.constructor_arguments()
                    supplied["planner_public_key"] = oracle._CallbackPublicKey(fixture.handoff.plan.key.public_key(), planner_callback)
                    supplied["verifier_public_key"] = oracle._CallbackPublicKey(fixture.handoff.plan.semantic.receipt.key.public_key(),
                        corrupt if stage == "assertion" else lambda: None)
                    owner = verifier.RevocationPlanVerifier(**supplied)
                    with self.assertRaises(ValueError): self.verify(fixture, owner, meter)
                    self.assertEqual(len(poison), 1)
                    self.assertEqual(handoff_oracle.units(meter), poison[0][0])
                    if mode == "float": self.assertIs(type(meter.input_bytes), float)
                    if stage == "bootstrap":
                        self.assertIs(meter.limits, poison[0][1])
                        if mode == "replace": self.assertIsNot(meter.limits, entering_limits)
                    else:
                        # Genuine retained cleanup restores its entering limit
                        # reference only. The poisoned counters are not repaired.
                        self.assertIs(meter.limits, entering_limits)
                    self.assertFalse(hasattr(meter, "_revocation_packaging_owner"))

    def test_independent_exact_prior_and_each_short_budget_preserve_real_remaining_child(self):
        fixture = VerifierFixture(approval=False, include_audit=False)
        factory, downstream = independent_factory_work(fixture)["total"], independent_owner_work(fixture)
        prepared_owner = self.build(fixture)
        for mode in ("factory", "owner", "composed"):
            total = factory if mode == "factory" else downstream["total"]
            admission = factory if mode == "factory" else downstream["admission"]
            if mode == "composed":
                total, admission = oracle.add(factory, total), oracle.add(factory, admission)
            for prior in ((0, 0, 0), (3, 17, 11)):
                full = oracle.add(prior, admission)
                for deficit in (None, 0, 1, 2):
                    maximum = tuple(value - int(index == deficit) for index, value in enumerate(full))
                    meter = handoff_oracle.work(maximum)
                    meter.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
                    entering_limits, clamps, children = meter.limits, [], []
                    initialize = accounting._ValidationWork.__init__
                    mixed = retention.plan.semantics.retained.mixed
                    actual_mixed = mixed._verify
                    def initialize_child(instance, child_limits):
                        # The actual mixed worker intentionally creates one
                        # remaining-clamped child. Delegate it, never replace
                        # the successful proof or ban its required allocation.
                        self.assertEqual(len(clamps), 1)
                        self.assertEqual(children, [])
                        self.assertEqual((child_limits.max_hashes, child_limits.max_input_bytes,
                            child_limits.max_json_nodes), clamps[0])
                        self.assertIsNot(instance, meter)
                        initialize(instance, child_limits)
                        children.append(instance)
                    def verify_mixed(owned, ledger, raw_decode_bytes, capture):
                        self.assertIs(ledger.work, meter)
                        clamps.append(ledger.remaining())
                        return actual_mixed(owned, ledger, raw_decode_bytes, capture)
                    def invoke():
                        owner = self.build(fixture, meter) if mode != "owner" else prepared_owner
                        return owner if mode == "factory" else self.verify(fixture, owner, meter)
                    with self.subTest(mode=mode, prior=prior, deficit=deficit), \
                            patch.object(accounting._ValidationWork, "__init__", new=initialize_child), \
                            patch.object(mixed, "_verify", new=verify_mixed):
                        if deficit is None:
                            result = invoke()
                            if mode != "factory": self.assertEqual(result.expected_context, fixture.handoff.expected_context)
                            self.assertEqual(handoff_oracle.units(meter), oracle.add(prior, total))
                            self.assertEqual((len(clamps), len(children)), (0, 0) if mode == "factory" else (1, 1))
                        else:
                            with self.assertRaises(ValueError): invoke()
                            self.assertLessEqual(len(children), 1)
                    self.assertIs(meter.limits, entering_limits)
                    self.assertFalse(hasattr(meter, "_revocation_packaging_owner"))
                    self.assertTrue(all(start <= used <= ceiling for start, used, ceiling in
                        zip(prior, handoff_oracle.units(meter), maximum)))

    def test_repeated_factory_and_owner_use_remaining_allowance_and_repeat_genuine_replay(self):
        fixture = VerifierFixture(approval=False, include_audit=False)
        factory, downstream = independent_factory_work(fixture)["total"], independent_owner_work(fixture)
        prepared_owner = self.build(fixture)
        for mode in ("factory", "owner", "composed"):
            total = factory if mode == "factory" else downstream["total"]
            admission = factory if mode == "factory" else downstream["admission"]
            if mode == "composed":
                total, admission = oracle.add(factory, total), oracle.add(factory, admission)
            twice = oracle.add(total, admission)
            for deficit in (None, 0, 1, 2):
                maximum = tuple(value - int(index == deficit) for index, value in enumerate(twice))
                meter = handoff_oracle.work(maximum)
                entering_limits = meter.limits
                def invoke():
                    owner = self.build(fixture, meter) if mode != "owner" else prepared_owner
                    return owner if mode == "factory" else self.verify(fixture, owner, meter)
                with self.subTest(mode=mode, deficit=deficit), \
                        patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                        patch.object(retention.plan.semantics.retained, "_compute_and_package",
                            wraps=retention.plan.semantics.retained._compute_and_package) as proof:
                    first = invoke()
                    self.assertEqual(handoff_oracle.units(meter), total)
                    if deficit is None:
                        second = invoke()
                        if mode != "factory":
                            self.assertEqual(second.retained_record.record_digest, first.retained_record.record_digest)
                        self.assertEqual(handoff_oracle.units(meter), oracle.add(total, total))
                        self.assertEqual((replay.call_count, proof.call_count), (0, 0) if mode == "factory" else (2, 2))
                    else:
                        with self.assertRaises(ValueError): invoke()
                        self.assertTrue(all(first_cost <= used <= ceiling for first_cost, used, ceiling in
                            zip(total, handoff_oracle.units(meter), maximum)))
                self.assertIs(meter.limits, entering_limits)
                self.assertFalse(hasattr(meter, "_revocation_packaging_owner"))


if __name__ == "__main__":
    unittest.main()
