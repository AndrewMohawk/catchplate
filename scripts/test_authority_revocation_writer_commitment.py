#!/usr/bin/env python3
"""Independent detached controls, genuine signatures and actual custody replay.

The local graphs/keys are fixture inputs, not measured launch admission. The
optional five-record SQL model below is not PostgreSQL, TLS/ACL or service
admission. It calls the real atomic helper and real proof workers; no successful
verification token is substituted. These controls prove no socket framing,
durable acknowledgement/retry custody, physical clock or current-root truth.
All controls are authored source, not execution evidence.
"""
from __future__ import annotations

import copy
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_contract as authority
from serverware import authority_query_read_work as accounting
from serverware import authority_revocation_persistence as persistence
from serverware import authority_revocation_retention as retention
from serverware import authority_revocation_writer_action as action
from serverware import authority_revocation_writer_commitment as commitment
from serverware.authority_store import planner_connection as admission
import test_authority_revocation_capability as signature_oracle
import test_authority_revocation_capability_producer as key_oracle
import test_authority_revocation_persistence as persistence_oracle
import test_authority_revocation_plan as oracle
import test_authority_revocation_reservation as reservation_oracle
import test_authority_revocation_wire as wire_oracle
import test_authority_revocation_writer_action as action_oracle


OUTER_SCHEMA = "serverware.policyAuthorityInternalEnvelope/v3"
INTENT_SCHEMA = "serverware.policyAuthorityRevocationWriterIntent/v1"
RELAY_SCHEMA = "serverware.policyAuthorityRevocationWriterRelay/v1"
INTENT_PURPOSE = "authorize-revocation-writer-custody"
RELAY_PURPOSE = "relay-revocation-writer-custody"
INTENT_ID_DOMAIN = "serverware.policyAuthorityRevocationWriterIntentEnvelope/v1"
RELAY_ID_DOMAIN = "serverware.policyAuthorityRevocationWriterRelayEnvelope/v1"
OUTER_FIELDS = ("schema", "envelopeId", "parentEnvelopeId", "purpose", "configurationDigest",
    "issuedAtEpochNs", "issuedMonotonicNs", "deadlineMonotonicNs", "fence", "payload", "signature")
INTENT_FIELDS = ("schema", "sourceRevision", "generationSequence", "generationDigest", "capabilityId",
    "plannerTransactionId", "executionEnvelopeId", "plannedAtEpochNs", "databaseCutoffUs",
    "planEnvelopeDigest", "planEnvelopeByteCount", "evaluationContextDigest", "evaluationContextByteCount",
    "historicalExpectationsDigest", "historicalExpectationsByteCount")
RELAY_FIELDS = ("schema", "sourceRevision", "generationSequence", "generationDigest",
    "verifierIntentDigest", "verifierIntentByteCount")
HISTORY_FIELDS = ("expected_request", "expected_capability_id", "expected_planner_transaction_id",
    "expected_fence", "reserved_at_epoch_ns", "deadline_epoch_ns", "deadline_monotonic_ns", "now_epoch_ns",
    "now_monotonic_ns", "maximum_assertion_age_ns", "maximum_plan_age_ns", "maximum_clock_skew_ns",
    "expected_before", "expected_approver_policy_digest")
PHASES = ("capture", "transport", "key_binding", "authentication", "bindings", "signing")


def cutoff_us(instant):
    delta = instant - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def unsigned(envelope):
    return {name: value for name, value in envelope.items() if name != "signature"}


def sign_control(envelope, key):
    """Independent existing NUL/u64 domain recipe, not the new producer."""
    envelope["signature"] = oracle.encoded(key.sign(
        oracle.framed(OUTER_SCHEMA, oracle.wire(unsigned(envelope))).encode("ascii")))
    return oracle.wire(envelope)


class CommitmentFixture:
    def __init__(self):
        self.action = action_oracle.WriterActionFixture()
        self.plan = self.action.plan
        self.verifier_key, self.planner_key = self.plan.semantic.receipt.key, self.plan.key
        self.configuration_digest = self.action.configuration.digest
        self.generation_sequence = self.action.configuration.generation["sequence"]
        self.generation_digest = self.action.configuration.generation["digest"]
        self.issued_epoch, self.issued_mono = self.plan.now_epoch_ns, self.plan.now_monotonic_ns
        self.now_epoch, self.now_mono = self.issued_epoch, self.issued_mono
        self.maximum_age = 30_000_000_000
        self.rebuild()

    def rebuild(self):
        self.history = {name: copy.deepcopy(self.action.expectations[name]) for name in HISTORY_FIELDS}
        self.history_bytes = oracle.wire(self.history)
        self.rebuild_intent()

    def rebuild_intent(self):
        args, claims = self.action.arguments, self.action.expectations
        self.intent_id = oracle.framed(INTENT_ID_DOMAIN,
            args["envelope_id"].encode("ascii"), args["planner_transaction_id"].encode("ascii"))
        payload = {"schema": INTENT_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
            "generationSequence": self.generation_sequence, "generationDigest": self.generation_digest,
            "capabilityId": claims["expected_capability_id"], "plannerTransactionId": args["planner_transaction_id"],
            "executionEnvelopeId": args["envelope_id"], "plannedAtEpochNs": args["planned_at_epoch_ns"],
            "databaseCutoffUs": cutoff_us(claims["database_now"]),
            "planEnvelopeDigest": oracle.sha(args["envelope_bytes"]), "planEnvelopeByteCount": len(args["envelope_bytes"]),
            "evaluationContextDigest": oracle.sha(args["evaluation_context_bytes"]),
            "evaluationContextByteCount": len(args["evaluation_context_bytes"]),
            "historicalExpectationsDigest": oracle.sha(self.history_bytes),
            "historicalExpectationsByteCount": len(self.history_bytes)}
        self.intent = self.outer(payload, self.intent_id, args["planner_transaction_id"], INTENT_PURPOSE,
            self.issued_epoch, self.issued_mono)
        self.resign_intent()

    def outer(self, payload, identity, parent, purpose, epoch, mono):
        return {"schema": OUTER_SCHEMA, "envelopeId": identity, "parentEnvelopeId": parent, "purpose": purpose,
            "configurationDigest": self.configuration_digest, "issuedAtEpochNs": epoch, "issuedMonotonicNs": mono,
            "deadlineMonotonicNs": self.action.expectations["deadline_monotonic_ns"],
            "fence": self.action.expectations["expected_fence"], "payload": payload}

    def resign_intent(self, key=None):
        self.intent_bytes = sign_control(self.intent, self.verifier_key if key is None else key)
        self.rebuild_relay()

    def rebuild_relay(self):
        self.relay_id = oracle.framed(RELAY_ID_DOMAIN, self.intent["envelopeId"].encode("ascii"))
        payload = {"schema": RELAY_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
            "generationSequence": self.generation_sequence, "generationDigest": self.generation_digest,
            "verifierIntentDigest": oracle.sha(self.intent_bytes), "verifierIntentByteCount": len(self.intent_bytes)}
        self.relay = self.outer(payload, self.relay_id, self.intent["envelopeId"], RELAY_PURPOSE,
            self.now_epoch, self.now_mono)
        self.resign_relay()

    def resign_relay(self, key=None):
        self.relay_bytes = sign_control(self.relay, self.planner_key if key is None else key)

    def intent_arguments(self):
        return {**self.action.supplied(), "verifier_private_key": self.verifier_key,
            "verifier_public_key": self.verifier_key.public_key(), "planner_public_key": self.planner_key.public_key(),
            "configuration_digest": self.configuration_digest, "generation_sequence": self.generation_sequence,
            "generation_digest": self.generation_digest, "issued_at_epoch_ns": self.issued_epoch,
            "issued_monotonic_ns": self.issued_mono}

    def relay_arguments(self):
        return {"intent_bytes": self.intent_bytes, "envelope_bytes": self.action.arguments["envelope_bytes"],
            "evaluation_context_bytes": self.action.arguments["evaluation_context_bytes"],
            "historical_expectations_bytes": self.history_bytes, "planner_private_key": self.planner_key,
            "planner_public_key": self.planner_key.public_key(), "verifier_public_key": self.verifier_key.public_key(),
            "expected_configuration_digest": self.configuration_digest,
            "expected_generation_sequence": self.generation_sequence, "expected_generation_digest": self.generation_digest,
            "now_epoch_ns": self.now_epoch, "now_monotonic_ns": self.now_mono,
            "maximum_age_ns": self.maximum_age, "maximum_clock_skew_ns": 5_000_000_000}

    def receiver_arguments(self):
        return {"relay_bytes": self.relay_bytes,
            **{name: value for name, value in self.relay_arguments().items() if name != "planner_private_key"}}


def control_transport(raw, envelope):
    return oracle.add(wire_oracle.decoder_units(raw, envelope), oracle.graph_cost(envelope, 4, 4),
        (0, 2 * len(raw), 0), oracle.graph_cost(unsigned(envelope)))


def control_signing(envelope):
    bare = unsigned(envelope)
    return oracle.add(oracle.graph_cost(bare, 6, 4), oracle.graph_cost(envelope), (0, 566, 0),
        oracle.frame_cost(OUTER_SCHEMA, (oracle.wire(bare),)), (0, 142, 2))


def independent_work(fixture):
    """Literal graph/codec/hash/frame schedule, never observed output metrics.

    No plan/context base64 occurs in this detached protocol. The only codec
    charge is each actual fixed Ed25519 signature transport. Raw bodies get
    their own SHA-256/count binding, with history decoded at root depth zero.
    """
    add, graph, same = oracle.add, oracle.graph_cost, oracle.canonical_comparison
    zero = (0, 0, 0)
    args, claims, intent, relay = fixture.action.arguments, fixture.action.expectations, fixture.intent, fixture.relay
    raw_bodies = (args["envelope_bytes"], args["evaluation_context_bytes"], fixture.history_bytes)
    identity = same(args["planner_transaction_id"], claims["expected_planner_transaction_id"])
    intent_id = add((0, 2 * 142, 2 * 2), oracle.frame_cost(INTENT_ID_DOMAIN,
        (args["envelope_id"].encode("ascii"), args["planner_transaction_id"].encode("ascii"))))
    relay_id = add((0, 142, 2), oracle.frame_cost(RELAY_ID_DOMAIN, (fixture.intent_id.encode("ascii"),)))
    configured = (fixture.configuration_digest, fixture.generation_sequence, fixture.generation_digest)
    joined = (fixture.intent_id, args["planner_transaction_id"], claims["expected_fence"],
        claims["deadline_monotonic_ns"], claims["expected_capability_id"], claims["expected_planner_transaction_id"])
    body_hashes = add(*((1, len(raw), 0) for raw in raw_bodies))
    body_joins = add(*(same((oracle.sha(raw), len(raw)), (oracle.sha(raw), len(raw))) for raw in raw_bodies))
    history_read = add(wire_oracle.decoder_units(fixture.history_bytes, fixture.history),
        graph(fixture.history), (0, 2 * len(fixture.history_bytes), 0), graph(fixture.history, 1, 1), identity)
    bound_intent = add(same(configured, configured), body_hashes, body_joins, history_read, intent_id, same(joined, joined))
    produced = {"capture": add(graph(fixture.history, 1, 1), identity), "transport": graph(fixture.history),
        "key_binding": (0, 224, 0), "authentication": zero,
        "bindings": add(body_hashes, intent_id), "signing": control_signing(intent)}
    relayed = {"capture": zero, "transport": control_transport(fixture.intent_bytes, intent),
        "key_binding": (0, 224, 0), "authentication": signature_oracle.signature_work(OUTER_SCHEMA, unsigned(intent)),
        "bindings": add(bound_intent, (1, len(fixture.intent_bytes), 0), relay_id), "signing": control_signing(relay)}
    relay_join = (fixture.relay_id, fixture.intent_id, claims["expected_fence"], claims["deadline_monotonic_ns"])
    intent_commitment = (oracle.sha(fixture.intent_bytes), len(fixture.intent_bytes))
    received = {"capture": zero,
        "transport": add(control_transport(fixture.relay_bytes, relay), control_transport(fixture.intent_bytes, intent)),
        "key_binding": (0, 128, 0),
        "authentication": add(*(signature_oracle.signature_work(OUTER_SCHEMA, unsigned(value)) for value in (relay, intent))),
        "bindings": add(bound_intent, same(configured, configured), (1, len(fixture.intent_bytes), 0),
            same(intent_commitment, intent_commitment), relay_id, same(relay_join, relay_join)), "signing": zero}
    for phases in (produced, relayed, received):
        phases["total"] = add(*(phases[name] for name in PHASES))
    return {"intent": produced, "relay": relayed, "receiver": received,
        "pipeline": add(produced["total"], relayed["total"], received["total"])}


@contextmanager
def modeled_store_namespace(fixture):
    """Mechanical SQL/clock/key-source model, never a successful proof verdict.

    The original module namespace is restored even after failure. The real
    public-key constructor and real signature verifier still consume the raw
    fixture key; neither db/service/registry nor their admission is replaced.
    """
    original = admission._DB_GLOBALS
    raw_key = fixture.verifier_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    try:
        admission.bind_db_globals({"PostgresMetadataConnection": persistence_oracle.Facade,
            "MetadataStoreError": persistence_oracle.StoreError,
            "_METADATA_STORE_AUTHORITY_PLANNER_WRITER_ROLE": "fixture-planner-writer",
            "_POLICY_AUTHORITY_VERIFIER_RESPONSE_MAX_AGE_NS": 30_000_000_000,
            "_POLICY_AUTHORITY_VERIFIER_MAX_CLOCK_SKEW_NS": 5_000_000_000,
            "_policy_authority_verifier_public_key": lambda: raw_key,
            "Ed25519PublicKey": Ed25519PublicKey, "InvalidSignature": InvalidSignature})
        with patch.object(admission.time, "time_ns", return_value=fixture.plan.now_epoch_ns), \
                patch.object(admission.time, "monotonic_ns", return_value=fixture.plan.now_monotonic_ns):
            yield
    finally:
        admission._DB_GLOBALS = original


def atomic_components(fixture, received, recorder, work):
    """Actual .62 inert prefix plus private .61 helper, not a service runner.

    Ordinary authenticated output is copied into an ordinary fixture input;
    the action captures/validates it again and the configured owner owns its
    independent pins. No connection opener or public owner method is modeled.
    In particular this path does not charge/claim the .61 public ID preflight.
    """
    supplied = copy.copy(fixture.action)
    supplied.arguments, supplied.expectations = received.arguments, received.expectations
    args, expectations, owner = action_oracle.compose_components(supplied, work)
    expectations = persistence._inputs_from_configuration(owner._snapshot_configuration(), expectations, work)
    return persistence._persist_and_reserve_on_connection(connection=persistence_oracle.Facade(recorder),
        work=work, **args, **expectations)


def independent_atomic_work(fixture, *, retry=False):
    """Actual component suffix, excluding nonexistent public/driver phases."""
    prefix = action_oracle.independent_prefix_work(fixture.action)["total"]
    external = {name: value for name, value in wire_oracle.expectations(fixture.plan).items()
        if name not in {"planner_public_key", "verifier_public_key", "database_now"}}
    prefix = oracle.add(prefix, oracle.graph_cost(external, 1, 1))
    persisted = persistence_oracle.independent_store_metrics(fixture.plan,
        fixture.action.arguments["planned_at_epoch_ns"], mode="retry" if retry else "new")
    reserved = reservation_oracle.independent_reservation_work(fixture.plan, fixture.action.arguments["envelope_id"])
    total = oracle.add(prefix, persisted["total"], reserved["total"])
    peaks = (total, oracle.add(prefix, persisted["admission"]),
        oracle.add(prefix, persisted["total"], reserved["admission"]))
    return {"total": total, "admission": tuple(max(values) for values in zip(*peaks))}


class _RoleKey(oracle._CallbackPublicKey):
    """Observe actual raw exports and cryptographic verdicts without stubbing."""
    def __init__(self, key, name, callback):
        super().__init__(key, lambda: callback(name + ".verify"))
        self.name, self.observer = name, callback

    def public_bytes(self, encoding, format):
        result = self.key.public_bytes(encoding, format)
        self.observer(self.name + ".export")
        return result


def observed_keys(fixture, callback):
    planner = _RoleKey(fixture.planner_key.public_key(), "planner", callback)
    verifier = _RoleKey(fixture.verifier_key.public_key(), "verifier", callback)
    private = {}
    for name, key in (("planner", fixture.planner_key), ("verifier", fixture.verifier_key)):
        private[name + "_private_key"] = key_oracle._ObservedPrivateKey(key,
            callback=lambda name=name: callback(name + ".sign"),
            public_callback=lambda name=name: callback(name + ".derive"),
            public_output=_RoleKey(key.public_key(), name + ".derived", callback))
    return {"planner_public_key": planner, "verifier_public_key": verifier, **private}


class RevocationWriterCommitmentTests(unittest.TestCase):
    def work(self, limits=None):
        return accounting._ValidationWork(accounting.QueryReadValidationLimits(*(limits or ())))

    def produce(self, fixture, work=None, **changes):
        return commitment._produce_intent_on_work(work=self.work() if work is None else work,
            **{**fixture.intent_arguments(), **changes})

    def relay(self, fixture, work=None, **changes):
        return commitment._produce_relay_on_work(work=self.work() if work is None else work,
            **{**fixture.relay_arguments(), **changes})

    def verify(self, fixture, work=None, **changes):
        return commitment._verify_commitments_on_work(work=self.work() if work is None else work,
            **{**fixture.receiver_arguments(), **changes})

    def test_independent_original_controls_keep_complete_headers_and_detached_bodies(self):
        fixture = CommitmentFixture()
        expected = independent_work(fixture)
        meter = self.work(expected["pipeline"])
        self.assertNotEqual(fixture.verifier_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                            fixture.planner_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        produced = self.produce(fixture, meter)
        self.assertEqual((produced.intent_bytes, produced.historical_expectations_bytes),
                         (fixture.intent_bytes, fixture.history_bytes))
        self.assertEqual(oracle.units(meter.metrics), expected["intent"]["total"])
        attempts = []
        verifier = oracle._CallbackPublicKey(fixture.verifier_key.public_key(), lambda: attempts.append("verifier"))
        planner = oracle._CallbackPublicKey(fixture.planner_key.public_key(), lambda: attempts.append("planner"))
        relay = self.relay(fixture, meter, verifier_public_key=verifier, planner_public_key=planner,
            intent_bytes=produced.intent_bytes, historical_expectations_bytes=produced.historical_expectations_bytes)
        self.assertEqual(relay.relay_bytes, fixture.relay_bytes)
        self.assertEqual(attempts, ["verifier", "planner"])
        attempts.clear()
        with patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
            received = self.verify(fixture, meter, verifier_public_key=verifier, planner_public_key=planner,
                intent_bytes=produced.intent_bytes, relay_bytes=relay.relay_bytes,
                historical_expectations_bytes=produced.historical_expectations_bytes)
        self.assertEqual(attempts, ["planner", "verifier"])
        self.assertEqual(replay.call_count, 0)
        self.assertEqual((received.intent_envelope, received.relay_envelope), (fixture.intent, fixture.relay))
        self.assertEqual((set(received.intent_envelope), set(received.relay_envelope)),
                         (set(OUTER_FIELDS), set(OUTER_FIELDS)))
        self.assertEqual((set(fixture.intent["payload"]), set(fixture.relay["payload"]), set(fixture.history)),
                         (set(INTENT_FIELDS), set(RELAY_FIELDS), set(HISTORY_FIELDS)))
        self.assertEqual(tuple(map(len, (fixture.intent, fixture.intent["payload"], fixture.relay["payload"], fixture.history))),
                         (11, 15, 6, 14))
        for field, original in (("intent_bytes", produced.intent_bytes), ("relay_bytes", relay.relay_bytes),
                ("envelope_bytes", fixture.action.arguments["envelope_bytes"]),
                ("evaluation_context_bytes", fixture.action.arguments["evaluation_context_bytes"]),
                ("historical_expectations_bytes", produced.historical_expectations_bytes)):
            self.assertIs(getattr(received, field), original)
        self.assertEqual(received.arguments, fixture.action.arguments)
        self.assertEqual(received.expectations, fixture.action.expectations)
        self.assertIs(type(received.expectations["database_now"]), datetime)
        self.assertIs(received.expectations["database_now"].tzinfo, timezone.utc)
        for result, name, counts in ((produced, "intent", (1, 1)), (relay, "relay", (1, 2)),
                                     (received, "receiver", (0, 2))):
            for phase in PHASES:
                self.assertEqual(oracle.units(getattr(result.metrics, phase)), expected[name][phase])
            self.assertEqual((result.metrics.signing_attempts, result.metrics.signature_verifications), counts)
        self.assertEqual(tuple(expected[name]["total"][0] for name in ("intent", "relay", "receiver")), (5, 8, 8))
        self.assertEqual(oracle.units(meter.metrics), expected["pipeline"])
        self.assertEqual((received.metrics.total_hashes, received.metrics.total_input_bytes,
                          received.metrics.total_json_nodes), expected["pipeline"])

    def test_stable_ids_are_domain_separated_not_body_or_timestamp_dependent(self):
        fixture = CommitmentFixture()
        old = (fixture.intent_id, fixture.relay_id, fixture.intent_bytes, fixture.relay_bytes)
        fixture.action.arguments["planned_at_epoch_ns"] += 1
        fixture.action.arguments["envelope_bytes"] += b" "
        fixture.issued_epoch += 1
        fixture.issued_mono += 1
        fixture.now_epoch += 1
        fixture.now_mono += 1
        fixture.rebuild()
        self.assertEqual((fixture.intent_id, fixture.relay_id), old[:2])
        self.assertNotEqual((fixture.intent_bytes, fixture.relay_bytes), old[2:])
        self.assertNotEqual(fixture.intent_id, fixture.action.arguments["envelope_id"])
        self.assertNotEqual(fixture.relay_id, fixture.intent_id)
        self.assertEqual(self.produce(fixture).intent_bytes, fixture.intent_bytes)
        self.assertEqual(self.verify(fixture).arguments, fixture.action.arguments)
        # A stable address is not durable exact-byte retry custody. The pure
        # protocol deliberately does not claim to reject a later re-signing.

    def test_each_genuinely_signed_header_join_and_payload_pin_is_enforced(self):
        digest = oracle.sha(b"different signed header")
        changes = (("outer", "envelopeId", digest), ("outer", "parentEnvelopeId", digest),
            ("outer", "configurationDigest", digest), ("outer", "fence", 99),
            ("outer", "deadlineMonotonicNs", 1), ("outer", "purpose", "persist-plan"),
            ("outer", "schema", "serverware.policyAuthorityInternalEnvelope/v2"),
            ("payload", "sourceRevision", "unaccepted-source"), ("payload", "generationSequence", 99),
            ("payload", "generationDigest", digest), ("payload", "schema", "unknown/v1"))
        for target in ("intent", "relay"):
            for area, field, value in changes:
                fixture = CommitmentFixture()
                envelope = getattr(fixture, target)
                (envelope if area == "outer" else envelope["payload"])[field] = value
                getattr(fixture, "resign_" + target)()
                with self.subTest(target=target, area=area, field=field), self.assertRaises(ValueError):
                    self.verify(fixture)
        for field in ("capabilityId", "plannerTransactionId", "executionEnvelopeId"):
            fixture = CommitmentFixture()
            fixture.intent["payload"][field] = digest
            fixture.resign_intent()
            with self.subTest(intent=field), self.assertRaises(ValueError):
                self.verify(fixture)

    def test_receiver_pins_and_distinct_roles_cannot_be_replaced_by_signed_claims(self):
        fixture = CommitmentFixture()
        changes = ({"expected_configuration_digest": oracle.sha(b"other configuration")},
            {"expected_generation_sequence": fixture.generation_sequence + 1},
            {"expected_generation_digest": oracle.sha(b"other generation")},
            {"verifier_public_key": fixture.planner_key.public_key()},
            {"planner_public_key": fixture.verifier_key.public_key()},
            {"verifier_public_key": fixture.planner_key.public_key(), "planner_public_key": fixture.verifier_key.public_key()},
            {"verifier_public_key": fixture.plan.other_key.public_key()},
            {"planner_public_key": fixture.plan.other_key.public_key()})
        for changed in changes:
            with self.subTest(fields=tuple(changed)), self.assertRaises(ValueError):
                self.verify(fixture, **changed)
        for target in ("intent", "relay"):
            changed = CommitmentFixture()
            getattr(changed, "resign_" + target)(changed.planner_key if target == "intent" else changed.verifier_key)
            with self.subTest(signer=target), self.assertRaises(ValueError): self.verify(changed)
        with self.assertRaises(ValueError):
            self.produce(fixture, verifier_private_key=fixture.planner_key)
        with self.assertRaises(ValueError):
            self.relay(fixture, planner_private_key=fixture.verifier_key)
        with self.assertRaises(ValueError):
            self.produce(fixture, planner_public_key=fixture.verifier_key.public_key())

    def test_noncanonical_controls_and_closed_payloads_deny_without_normalization(self):
        for target in ("intent", "relay"):
            fixture = CommitmentFixture()
            original = getattr(fixture, target + "_bytes")
            bad = (b" " + original, original.replace(b'"schema":', b'"schema" :', 1),
                original[:-1] + b',"schema":"duplicate"}', original[:-1] + b'\x00}',
                bytearray(original), memoryview(original), b"x")
            for raw in bad:
                with self.subTest(target=target, kind=type(raw).__name__), self.assertRaises(ValueError):
                    self.verify(fixture, **{target + "_bytes": raw})
            for area in ("outer", "payload"):
                for mode in ("missing", "extra"):
                    changed = CommitmentFixture()
                    envelope = getattr(changed, target)
                    value = envelope if area == "outer" else envelope["payload"]
                    if mode == "missing": value.pop("schema")
                    else: value["successfulProof"] = True
                    getattr(changed, "resign_" + target)()
                    with self.subTest(target=target, area=area, mode=mode), self.assertRaises(ValueError):
                        self.verify(changed)
        fixture = CommitmentFixture()
        for area, field in (("outer", "fence"), ("outer", "issuedAtEpochNs"),
                ("payload", "plannedAtEpochNs"), ("payload", "planEnvelopeByteCount")):
            for value in (True, 1.0, 0, -1, 2**63):
                changed = CommitmentFixture()
                (changed.intent if area == "outer" else changed.intent["payload"])[field] = value
                changed.resign_intent()
                with self.subTest(area=area, field=field, value=value), self.assertRaises(ValueError):
                    self.verify(changed)

    def test_original_body_counts_hashes_and_relay_intent_binding_are_mandatory(self):
        fixture = CommitmentFixture()
        for name in ("envelope_bytes", "evaluation_context_bytes", "historical_expectations_bytes"):
            original = fixture.receiver_arguments()[name]
            changed = original[:-1] + bytes((original[-1] ^ 1,))
            self.assertEqual(len(changed), len(original))
            with self.subTest(body=name), self.assertRaises(ValueError): self.verify(fixture, **{name: changed})
        for target, fields in (("intent", ("planEnvelopeDigest", "planEnvelopeByteCount", "evaluationContextDigest",
                "evaluationContextByteCount", "historicalExpectationsDigest", "historicalExpectationsByteCount")),
                ("relay", ("verifierIntentDigest", "verifierIntentByteCount"))):
            for name in fields:
                changed = CommitmentFixture()
                payload = getattr(changed, target)["payload"]
                payload[name] = payload[name] + 1 if name.endswith("ByteCount") else oracle.sha(b"wrong original")
                getattr(changed, "resign_" + target)()
                with self.subTest(target=target, field=name), self.assertRaises(ValueError): self.verify(changed)
        changed = CommitmentFixture()
        old_relay = changed.relay_bytes
        changed.intent["issuedAtEpochNs"] -= 1
        changed.resign_intent()
        with self.assertRaises(ValueError): self.verify(changed, relay_bytes=old_relay)

    def test_signed_utc_cutoff_roundtrips_negative_zero_and_positive_microseconds(self):
        for microseconds in (-1, 0, 1, 999999, 1_000_007):
            fixture = CommitmentFixture()
            instant = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=microseconds)
            fixture.action.expectations["database_now"] = instant
            fixture.rebuild()
            actual = self.produce(fixture)
            self.assertEqual(actual.intent_bytes, fixture.intent_bytes)
            self.assertEqual(self.verify(fixture).expectations["database_now"], instant)
            self.assertEqual(fixture.intent["payload"]["databaseCutoffUs"], microseconds)
        for value in (True, 1.0, -(2**63) - 1, 2**63, -(2**63), 2**63 - 1):
            fixture = CommitmentFixture()
            fixture.intent["payload"]["databaseCutoffUs"] = value
            fixture.resign_intent()
            with self.subTest(value=value), self.assertRaises(ValueError): self.verify(fixture)
        fixture = CommitmentFixture()
        for instant in (fixture.action.expectations["database_now"].replace(tzinfo=None),
                fixture.action.expectations["database_now"].astimezone(timezone(timedelta(hours=1))), False):
            with self.subTest(instant=instant), self.assertRaises(ValueError):
                self.produce(fixture, database_now=instant)
        # A valid signed UTC claim is not proof it matches the retained plan's
        # signed cutoff or a physically observed database clock.

    def test_history_is_closed_owned_canonical_data_not_receiver_clock_or_policy(self):
        for mode in ("missing", "extra", "float", "wrong_id", "wrong_fence", "wrong_deadline", "space"):
            fixture = CommitmentFixture()
            if mode == "missing": fixture.history.pop("expected_request")
            elif mode == "extra": fixture.history["database_now"] = 0
            elif mode == "float": fixture.history["now_epoch_ns"] = 1.5
            elif mode == "wrong_id": fixture.history["expected_capability_id"] = oracle.sha(b"foreign history")
            elif mode == "wrong_fence": fixture.history["expected_fence"] += 1
            elif mode == "wrong_deadline": fixture.history["deadline_monotonic_ns"] -= 1
            fixture.history_bytes = oracle.wire(fixture.history) + (b" " if mode == "space" else b"")
            fixture.rebuild_intent()
            with self.subTest(mode=mode), self.assertRaises(ValueError): self.verify(fixture)
        fixture = CommitmentFixture()
        fixture.action.expectations["maximum_assertion_age_ns"] += 1
        fixture.rebuild()
        received = self.verify(fixture)
        self.assertEqual(received.expectations["maximum_assertion_age_ns"], fixture.action.expectations["maximum_assertion_age_ns"])
        with self.assertRaises(ValueError):
            action._assert_policy_on_work(fixture.action.configuration.payload, received.expectations, self.work())
        # Sender authentication preserves historical claims; the later .62
        # comparison to measured policy remains a separate mandatory gate.

    def test_independent_current_writer_clocks_age_and_fixed_source_skew_are_required(self):
        fixture = CommitmentFixture()
        self.verify(fixture)
        invalid = ({"now_epoch_ns": False}, {"now_monotonic_ns": 1.0}, {"maximum_age_ns": True},
            {"maximum_age_ns": 0}, {"maximum_age_ns": 1}, {"maximum_clock_skew_ns": 5_000_000_001},
            {"maximum_clock_skew_ns": 4_999_999_999}, {"maximum_clock_skew_ns": True},
            {"now_epoch_ns": fixture.now_epoch - 5_000_000_001},
            {"now_monotonic_ns": fixture.now_mono - 1},
            {"now_epoch_ns": fixture.now_epoch + fixture.maximum_age + 1},
            {"now_monotonic_ns": fixture.action.expectations["deadline_monotonic_ns"]},
            {"now_epoch_ns": fixture.action.expectations["deadline_epoch_ns"]},
            {"now_epoch_ns": fixture.now_epoch + 5_000_000_001})
        for changed in invalid:
            with self.subTest(fields=tuple(changed)), self.assertRaises(ValueError): self.verify(fixture, **changed)
        for target in ("intent", "relay"):
            for field, value in (("issuedAtEpochNs", fixture.now_epoch + 5_000_000_001),
                    ("issuedMonotonicNs", fixture.now_mono + 1),
                    ("issuedAtEpochNs", fixture.now_epoch - fixture.maximum_age - 1)):
                changed = CommitmentFixture()
                getattr(changed, target)[field] = value
                getattr(changed, "resign_" + target)()
                with self.subTest(target=target, field=field), self.assertRaises(ValueError): self.verify(changed)

    def test_detached_bodies_preserve_large_local_inputs_without_embedded_wrapper_limits(self):
        fixture = CommitmentFixture()
        fixture.action.arguments["envelope_bytes"] = b"x" * (4 * 1024 * 1024 + 1)
        fixture.rebuild()
        self.assertEqual(self.produce(fixture).intent_bytes, fixture.intent_bytes)
        self.assertEqual(self.relay(fixture).relay_bytes, fixture.relay_bytes)
        self.assertIs(self.verify(fixture).envelope_bytes, fixture.action.arguments["envelope_bytes"])
        self.assertLess(len(fixture.intent_bytes), 4096)
        # This opaque local body is intentionally not a valid plan. None of
        # these independent component calls is a transport or replay verdict.
        for variant in ("bytes", "nodes", "depth"):
            fixture = CommitmentFixture()
            if variant == "bytes": value = "x" * (4 * 1024 * 1024 + 1)
            elif variant == "nodes": value = list(range(4097))
            else:
                value = 0
                for _ in range(125): value = [value]
            fixture.action.expectations["expected_request"]["arguments"]["detachedFixture"] = value
            fixture.rebuild()
            with self.subTest(variant=variant):
                produced = self.produce(fixture)
                self.assertEqual(produced.historical_expectations_bytes, fixture.history_bytes)
                self.assertEqual(self.verify(fixture).expectations, fixture.action.expectations)
                self.assertLess(len(fixture.intent_bytes), 4096)
            if variant == "depth":
                # History root0/request1/arguments2/value3: 125 lists place
                # the leaf at depth128, not at an embedded-control offset.
                fixture.action.expectations["expected_request"]["arguments"]["detachedFixture"] = [value]
                fixture.rebuild()
                with self.assertRaises(ValueError): self.produce(fixture)
                with self.assertRaises(ValueError): self.verify(fixture)

    def test_authenticated_false_plan_or_receipt_cannot_substitute_for_actual_atomic_replay(self):
        for mode in ("valid", "false_result", "false_receipt"):
            fixture, recorder, meter = CommitmentFixture(), reservation_oracle.Recorder(), self.work()
            if mode == "false_result":
                fixture.plan.payload["expectedResult"] = {"false": "genuinely signed and completely recommitted"}
                fixture.plan.rehash()
            elif mode == "false_receipt":
                fixture.plan.payload["webauthnEvidence"]["verifierSignatureBase64url"] = oracle.encoded(bytes(64))
                fixture.plan.payload["webauthnEvidence"]["verifierSignatureDigest"] = oracle.sha(bytes(64))
                fixture.plan.payload["authorizationProjection"]["assertionEvidenceDigest"] = oracle.framed(
                    "serverware.policyAuthorityWebAuthnAssertionEvidence/v1", oracle.wire(fixture.plan.payload["webauthnEvidence"]))
                fixture.plan.rehash()
            fixture.action.arguments["envelope_bytes"] = oracle.wire(fixture.plan.envelope)
            fixture.rebuild()
            # Both outer signatures and all three body commitments are real
            # and correct even for the semantically false signed originals.
            self.assertEqual(self.relay(fixture).relay_bytes, fixture.relay_bytes)
            received = self.verify(fixture, meter)
            before, original_namespace = recorder.snapshot(), admission._DB_GLOBALS
            with self.subTest(mode=mode), modeled_store_namespace(fixture), \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                    patch.object(retention.plan.mixed, "_verify", wraps=retention.plan.mixed._verify) as proof, \
                    patch.object(oracle.assertion, "_verify_receipt_signature",
                        wraps=oracle.assertion._verify_receipt_signature) as receipt_signature, \
                    patch.object(oracle.candidate.WebAuthnCredentialRevokeKernel, "_transition",
                        wraps=oracle.candidate.WebAuthnCredentialRevokeKernel()._transition) as kernel:
                if mode == "valid":
                    retained, reserved = atomic_components(fixture, received, recorder, meter)
                    parent, sidecar = persistence_oracle.expected_rows(fixture.plan, fixture.plan.now_epoch_ns)
                    assertion, projection = persistence_oracle.expected_authorization_rows(fixture.plan)
                    expected = reservation_oracle.expected_envelope(fixture.plan, fixture.action.arguments["envelope_id"])
                    self.assertEqual(recorder.snapshot(), (parent, sidecar,
                        {assertion["assertion_evidence_digest"]: assertion},
                        {projection["authorization_projection_digest"]: projection},
                        {fixture.action.arguments["envelope_id"]: expected}))
                    self.assertEqual(reserved, expected)
                    self.assertEqual(retained["exactEnvelopeBytes"], fixture.action.arguments["envelope_bytes"])
                    self.assertEqual((replay.call_count, proof.call_count, kernel.call_count), (2, 2, 2))
                    self.assertEqual((recorder.releases, recorder.rollbacks), (3, 0))
                else:
                    with self.assertRaises(ValueError): atomic_components(fixture, received, recorder, meter)
                    self.assertEqual(replay.call_count, 1)
                    self.assertEqual(recorder.snapshot(), before)
                    self.assertEqual((recorder.releases, recorder.rollbacks), (0, 1))
                    if mode == "false_result": self.assertEqual(kernel.call_count, 1)
                    if mode == "false_receipt": self.assertEqual(receipt_signature.call_count, 1)
                for call in replay.call_args_list: self.assertIs(call.kwargs["work"], meter)
            self.assertIs(admission._DB_GLOBALS, original_namespace)
        # Three modeled releases are common/persist/reserve only. The real
        # configured driver/outer transaction remain covered by startup, not
        # invented here. Every rejected first replay restores all five sets.

    def test_fixed_local_bounds_and_complete_output_reservation_precede_signing(self):
        fixture = CommitmentFixture()
        expected = independent_work(fixture)
        for phase, method, key_field, key in (("intent", self.produce, "verifier_private_key", fixture.verifier_key),
                                             ("relay", self.relay, "planner_private_key", fixture.planner_key)):
            # Exact and one-below use literal output accounting; no encoder
            # observation supplies the expected allowance. Every deficit must
            # precede the actual private signing callback, including B/N tails.
            for axis in (None, 0, 1, 2):
                limits = list(expected[phase]["total"])
                if axis is not None: limits[axis] -= 1
                meter, signer = self.work(tuple(limits)), key_oracle._ObservedPrivateKey(key)
                with self.subTest(phase=phase, axis=axis):
                    if axis is None:
                        method(fixture, meter, **{key_field: signer})
                        self.assertEqual(signer.calls, 1)
                    else:
                        with self.assertRaises(ValueError): method(fixture, meter, **{key_field: signer})
                        self.assertEqual(signer.calls, 0)
        for module, name, size in ((commitment, "MAX_CONTROL_BYTES", max(len(fixture.intent_bytes), len(fixture.relay_bytes))),
                (commitment.plan.contract, "MAX_PAYLOAD_BYTES", len(fixture.action.arguments["envelope_bytes"])),
                (retention, "MAX_CONTEXT_BYTES", len(fixture.action.arguments["evaluation_context_bytes"])),
                (commitment, "MAX_HISTORY_BYTES", len(fixture.history_bytes))):
            with self.subTest(bound=name), patch.object(module, name, size):
                # MAX_PAYLOAD_BYTES is also the wire decoder's absolute
                # ceiling. Lowering it must not manufacture an unrelated
                # receiver failure from its unchanged history/control limits.
                # The opaque plan boundary is exercised by its real producer
                # and raw-body guard; the other local bounds use the receiver.
                if name != "MAX_PAYLOAD_BYTES": self.verify(fixture)
                commitment._body_bounds(fixture.action.arguments["envelope_bytes"],
                    fixture.action.arguments["evaluation_context_bytes"], fixture.history_bytes)
                self.assertEqual(self.produce(fixture).intent_bytes, fixture.intent_bytes)
            with self.subTest(bound=name, short=True), patch.object(module, name, size - 1):
                meter, events = self.work(), []
                keys = observed_keys(fixture, events.append)
                with self.assertRaises(ValueError):
                    self.verify(fixture, meter, **{name: keys[name] for name in ("planner_public_key", "verifier_public_key")})
                self.assertEqual(events, [])
                self.assertEqual(oracle.units(meter.metrics), (0, 0, 0))
        signer = key_oracle._ObservedPrivateKey(fixture.planner_key)
        changed = fixture.intent_bytes[:-1] + b" "
        with self.assertRaises(ValueError): self.relay(fixture, intent_bytes=changed, planner_private_key=signer)
        self.assertEqual(signer.calls, 0)

    def test_all_real_key_callbacks_observe_owned_claims_and_original_byte_inputs(self):
        routes = (("intent", self.produce, ("verifier.derive", "verifier.derived.export", "verifier.export",
                    "planner.export", "verifier.sign", "verifier.verify")),
            ("relay", self.relay, ("planner.derive", "planner.derived.export", "planner.export",
                    "verifier.export", "verifier.verify", "planner.sign", "planner.verify")),
            ("receiver", self.verify, ("planner.export", "verifier.export", "planner.verify", "verifier.verify")))
        for phase, method, stages in routes:
            for target in stages:
                fixture = CommitmentFixture()
                expected = independent_work(fixture)[phase]["total"]
                originals = (fixture.intent_bytes, fixture.relay_bytes, fixture.history_bytes,
                    fixture.action.arguments.copy(), copy.deepcopy(fixture.action.expectations))
                events = []

                def mutate(stage):
                    events.append(stage)
                    if stage != target: return
                    fixture.action.expectations["expected_request"].clear()
                    fixture.action.expectations["expected_before"].clear()
                    fixture.action.arguments.clear()
                    fixture.history.clear()
                    fixture.intent.clear()
                    fixture.relay.clear()
                    fixture.intent_bytes = fixture.relay_bytes = fixture.history_bytes = b"{}"
                    fixture.configuration_digest = oracle.sha(b"caller changed after ownership")
                    fixture.generation_sequence = fixture.now_epoch = fixture.now_mono = 1

                keys, meter = observed_keys(fixture, mutate), self.work(expected)
                changes = {name: keys[name] for name in ("planner_public_key", "verifier_public_key")}
                if phase != "receiver": changes[("verifier" if phase == "intent" else "planner") + "_private_key"] = keys[
                    ("verifier" if phase == "intent" else "planner") + "_private_key"]
                with self.subTest(phase=phase, stage=target):
                    result = method(fixture, meter, **changes)
                    self.assertEqual(events, list(stages))
                    if phase == "intent":
                        self.assertEqual((result.intent_bytes, result.historical_expectations_bytes), (originals[0], originals[2]))
                    elif phase == "relay": self.assertEqual(result.relay_bytes, originals[1])
                    else:
                        self.assertEqual((result.intent_bytes, result.relay_bytes, result.historical_expectations_bytes), originals[:3])
                        self.assertEqual((result.arguments, result.expectations), originals[3:])
                    self.assertEqual(oracle.units(meter.metrics), expected)

    def test_callback_meter_poison_and_native_exceptions_are_not_refunded_or_suppressed(self):
        routes = (("intent", self.produce, ("verifier.derive", "verifier.derived.export", "verifier.export",
                    "planner.export", "verifier.sign", "verifier.verify")),
            ("relay", self.relay, ("planner.derive", "planner.derived.export", "planner.export",
                    "verifier.export", "verifier.verify", "planner.sign", "planner.verify")),
            ("receiver", self.verify, ("planner.export", "verifier.export", "planner.verify", "verifier.verify")))
        for phase, method, stages in routes:
            for target in stages:
                fixture, meter, seen = CommitmentFixture(), self.work(), []
                replacement = accounting.QueryReadValidationLimits()

                def poison(stage):
                    if stage != target: return
                    meter.input_bytes -= 1
                    meter.limits = replacement
                    seen.append((meter.hash_work, meter.input_bytes, meter.json_nodes))

                keys = observed_keys(fixture, poison)
                changes = {name: keys[name] for name in ("planner_public_key", "verifier_public_key")}
                if phase != "receiver": changes[("verifier" if phase == "intent" else "planner") + "_private_key"] = keys[
                    ("verifier" if phase == "intent" else "planner") + "_private_key"]
                with self.subTest(phase=phase, stage=target), self.assertRaises(ValueError): method(fixture, meter, **changes)
                self.assertEqual(len(seen), 1)
                self.assertEqual(oracle.units(meter.metrics), seen[0])
                self.assertIs(meter.limits, replacement)
                self.assertFalse(hasattr(meter, "_revocation_packaging_owner"))
            fixture, meter = CommitmentFixture(), self.work()
            failure = RuntimeError("native key failure must remain the first error")

            def fail(stage):
                if stage == stages[-1]: raise failure

            keys = observed_keys(fixture, fail)
            changes = {name: keys[name] for name in ("planner_public_key", "verifier_public_key")}
            if phase != "receiver": changes[("verifier" if phase == "intent" else "planner") + "_private_key"] = keys[
                ("verifier" if phase == "intent" else "planner") + "_private_key"]
            with self.subTest(phase=phase, native=True), self.assertRaises(RuntimeError) as raised: method(fixture, meter, **changes)
            self.assertIs(raised.exception, failure)
            self.assertGreater(meter.input_bytes, 0)

    def test_pure_components_exact_prior_and_each_axis_short_share_the_original_work(self):
        fixture = CommitmentFixture()
        expected = independent_work(fixture)
        for phase, method in (("intent", self.produce), ("relay", self.relay), ("receiver", self.verify)):
            total = expected[phase]["total"]
            for prior in ((0, 0, 0), (3, 17, 11)):
                for axis in (None, 0, 1, 2):
                    limits = list(oracle.add(prior, total))
                    if axis is not None: limits[axis] -= 1
                    meter = self.work(tuple(limits))
                    meter.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
                    with self.subTest(phase=phase, prior=prior, axis=axis), \
                            patch.object(accounting._ValidationWork, "__init__", side_effect=AssertionError("new allowance")):
                        if axis is None:
                            result = method(fixture, meter)
                            self.assertEqual(oracle.units(meter.metrics), oracle.add(prior, total))
                            self.assertEqual((result.metrics.total_hashes, result.metrics.total_input_bytes,
                                result.metrics.total_json_nodes), oracle.add(prior, total))
                        else:
                            with self.assertRaises(ValueError): method(fixture, meter)
                    self.assertFalse(hasattr(meter, "_revocation_packaging_owner"))
        # These pure paths allocate no proof child. The separate replay test
        # below deliberately permits the genuine remaining-clamped child.

    def test_repeated_authentication_spends_all_three_remaining_axes_again(self):
        fixture = CommitmentFixture()
        expected = independent_work(fixture)
        for phase, method in (("intent", self.produce), ("relay", self.relay), ("receiver", self.verify)):
            total = expected[phase]["total"]
            for axis in (None, 0, 1, 2):
                limits = list(oracle.add(total, total))
                if axis is not None: limits[axis] -= 1
                meter, events = self.work(tuple(limits)), []
                keys = observed_keys(fixture, events.append)
                changes = {name: keys[name] for name in ("planner_public_key", "verifier_public_key")}
                if phase != "receiver": changes[("verifier" if phase == "intent" else "planner") + "_private_key"] = keys[
                    ("verifier" if phase == "intent" else "planner") + "_private_key"]
                with self.subTest(phase=phase, axis=axis):
                    method(fixture, meter, **changes)
                    self.assertEqual(oracle.units(meter.metrics), total)
                    before = len(events)
                    if axis is None:
                        method(fixture, meter, **changes)
                        self.assertEqual(oracle.units(meter.metrics), oracle.add(total, total))
                        self.assertEqual(events[:before], events[before:])
                    else:
                        with self.assertRaises(ValueError): method(fixture, meter, **changes)
                        self.assertTrue(all(value >= spent for value, spent in zip(oracle.units(meter.metrics), total)))
                    self.assertFalse(hasattr(meter, "_revocation_packaging_owner"))

    def test_receiver_and_actual_atomic_components_preserve_exact_shifted_proof_budget(self):
        fixture = CommitmentFixture()
        authenticate, suffix = independent_work(fixture)["receiver"]["total"], independent_atomic_work(fixture)
        total, peak = oracle.add(authenticate, suffix["total"]), oracle.add(authenticate, suffix["admission"])
        for prior in ((0, 0, 0), (3, 17, 11)):
            for axis in (None, 0, 1, 2):
                limits = list(oracle.add(prior, peak))
                if axis is not None: limits[axis] -= 1
                meter, recorder = self.work(tuple(limits)), reservation_oracle.Recorder()
                meter.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
                before, children = recorder.snapshot(), []
                original_verify, constructor = retention.plan.mixed._verify, accounting._ValidationWork.__init__

                def observe_constructor(child, child_limits):
                    children.append(child_limits)
                    return constructor(child, child_limits)

                def observe_proof(owned, ledger, raw_decode_bytes, captured):
                    self.assertIs(ledger.work, meter)
                    count = len(children)
                    remaining = ledger.remaining()
                    result = original_verify(owned, ledger, raw_decode_bytes, captured)
                    self.assertEqual(len(children), count + 1)
                    child = children[-1]
                    self.assertEqual((child.max_hashes, child.max_input_bytes, child.max_json_nodes), remaining)
                    return result

                with self.subTest(prior=prior, axis=axis), modeled_store_namespace(fixture), \
                        patch.object(accounting._ValidationWork, "__init__", observe_constructor), \
                        patch.object(retention.plan.mixed, "_verify", side_effect=observe_proof) as proof:
                    if axis is None:
                        received = self.verify(fixture, meter)
                        atomic_components(fixture, received, recorder, meter)
                        self.assertEqual((proof.call_count, len(children)), (2, 2))
                        self.assertEqual(oracle.units(meter.metrics), oracle.add(prior, total))
                        self.assertEqual((recorder.releases, recorder.rollbacks), (3, 0))
                    else:
                        with self.assertRaises(ValueError):
                            received = self.verify(fixture, meter)
                            atomic_components(fixture, received, recorder, meter)
                        self.assertLessEqual(len(children), 2)
                        self.assertEqual(recorder.snapshot(), before)
                self.assertFalse(hasattr(meter, "_revocation_packaging_owner"))


if __name__ == "__main__":
    unittest.main()
