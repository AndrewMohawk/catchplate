#!/usr/bin/env python3
"""Configured issuer ownership with genuine replay and a transaction model.

The private explicit opener supplies an already-admitted connection recorder;
it does not prove the real connector, PostgreSQL, mTLS, grants or native commit.
The actual configured snapshot, ownership worker, store, original-byte parsers,
three capability/witness signatures and retained proof replay are never replaced
by successful-result stubs. The public lazy connector is source-linked by the
separate test_authority_revocation_issuer_source.py fixture.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_query_read_work as accounting
from serverware import authority_revocation_capability as capability
from serverware import authority_revocation_issuance as configured
from serverware import authority_revocation_retention as retention
from serverware.authority_store import planner_connection as admission
from serverware.authority_store import revocation_capability as store
import test_authority_revocation_capability as capability_oracle
import test_authority_revocation_issuance as issuance_oracle
import test_authority_revocation_plan as oracle


IDENTITY_FIELDS = ("sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest")
HISTORICAL_FIELDS = frozenset({"expected_request", "expected_capability_id", "expected_planner_transaction_id",
    "expected_fence", "reserved_at_epoch_ns", "deadline_epoch_ns", "deadline_monotonic_ns", "now_epoch_ns",
    "now_monotonic_ns", "database_now", "maximum_assertion_age_ns", "maximum_plan_age_ns",
    "maximum_clock_skew_ns", "expected_before", "expected_approver_policy_digest"})


def role_bound_fixture():
    fixture = capability_oracle.CapabilityFixture()
    # Match the actual service role: the admitted assertion verifier is also
    # the capability/request signer. Re-sign all affected original documents;
    # retaining an old successful capability observation would be insufficient.
    fixture.key = fixture.plan.semantic.receipt.key
    fixture.signer_identity = copy.deepcopy(fixture.plan.semantic.receipt.identity)
    fixture.sign_request()
    fixture.witness_receipt["canonicalRequestDigest"] = oracle.framed(
        capability_oracle.REQUEST_SCHEMA, oracle.wire(fixture.witness_request))
    fixture.sign_receipt()
    fixture.rebuild()
    return fixture


def constructor_inputs(fixture, pins):
    return {"planner_public_key": fixture.plan.key.public_key(),
        "verifier_public_key": fixture.plan.semantic.receipt.key.public_key(),
        "witness_public_key": fixture.witness_key.public_key(),
        "expected_planner_identity": copy.deepcopy(fixture.plan.identity),
        "expected_verifier_identity": copy.deepcopy(fixture.plan.semantic.receipt.identity),
        "expected_issuer_session_identity_digest": fixture.issuer_identity,
        "issuer_pins": copy.deepcopy(pins), "expected_configuration_digest": fixture.configuration_digest,
        "expected_witness_identity_digest": fixture.witness_identity,
        "expected_generation_sequence": fixture.generation_sequence,
        "expected_generation_digest": fixture.generation_digest,
        "database_pins": ("serverware_policy_capability_issuer", "CN=fixture-issuer", "1", "CN=fixture-ca", 2)}


def call_inputs(fixture):
    historical = fixture.arguments()["retention_expectations"]
    return {"envelope_bytes": fixture.raw, "witness_request_bytes": oracle.wire(fixture.witness_request),
        "expected_execution_envelope_id": fixture.execution_envelope_id,
        "expected_witness_receipt_digest": fixture.witness_receipt_digest,
        **{name: value for name, value in historical.items() if name in HISTORICAL_FIELDS}}


def independent_owner_work(fixture, pins, *, issued=False, prior_witness=False):
    inner = issuance_oracle.independent_issuance_work(fixture, pins,
        issued=issued, prior_witness=prior_witness)
    capture = oracle.add(oracle.graph_cost(capability_oracle.capture_graph(fixture), 1, 1),
        oracle.graph_cost(pins, 1, 1))
    returned = issuance_oracle.expected_receipt(fixture)
    tail = oracle.add(oracle.graph_cost(returned), oracle.graph_cost(returned["capabilityId"], 4, 4))
    total = oracle.add(capture, inner["total"], tail)
    peak = oracle.add(capture, inner["admission"])
    return {"capture": capture, "inner": inner, "tail": tail, "total": total,
        "admission": tuple(max(a, b) for a, b in zip(total, peak))}


class Connection(issuance_oracle.Recorder):
    """Outer transaction model around the existing inner savepoint model."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.outer_commits = self.outer_rollbacks = self.closes = 0
        self.outer_before = None

    def __enter__(self):
        self.outer_before = self.snapshot()
        self.event("connection.enter")
        return self

    def __exit__(self, kind, error, traceback):
        try:
            if kind is not None:
                (self.parent, self.sidecar, self.assertions, self.projections,
                    self.envelopes, self.capabilities, self.capability_records, self.witnesses) = self.outer_before
                self.outer_rollbacks += 1
                self.event("connection.rollback")
            else:
                self.outer_commits += 1
                self.event("connection.commit")
        finally:
            self.close()
        return False

    def close(self):
        self.closes += 1
        self.closed, self.info.transaction_status = True, 0
        self.event("connection.close")


class RevocationIssuerTests(unittest.TestCase):
    def setUp(self):
        self.old_namespace = admission._DB_GLOBALS
        admission.bind_db_globals({"MetadataStoreError": issuance_oracle.persistence_oracle.StoreError})

    def tearDown(self):
        admission._DB_GLOBALS = self.old_namespace

    def work(self, limits=None):
        return accounting._ValidationWork(accounting.QueryReadValidationLimits(*(limits or ())))

    def owner(self, fixture, pins, **changes):
        return configured.RevocationCapabilityIssuer(**{**constructor_inputs(fixture, pins), **changes})

    def issue(self, fixture, connection, *, owner=None, work=None, supplied=None, opener=None,
              epoch=None, monotonic=None, configuration=None):
        if configuration is None:
            if owner is None:
                owner = self.owner(fixture, connection.pins)
            configuration = owner._snapshot_configuration()
        supplied = call_inputs(fixture) if supplied is None else supplied
        invocation = {name: supplied[name] for name in ("envelope_bytes", "witness_request_bytes",
            "expected_execution_envelope_id", "expected_witness_receipt_digest")}
        expectations = {name: value for name, value in supplied.items() if name not in invocation}
        def open_connection():
            connection.event("open")
            return connection
        with patch.object(store.time, "time_ns", return_value=fixture.plan.now_epoch_ns, side_effect=epoch), \
                patch.object(store.time, "monotonic_ns", return_value=fixture.plan.now_monotonic_ns, side_effect=monotonic):
            return configured._run_on_configuration(configuration, **invocation, expectations=expectations,
                work=self.work() if work is None else work, opener=open_connection if opener is None else opener)

    def test_role_bound_original_signatures_replay_once_before_outer_commit(self):
        fixture, pins = role_bound_fixture(), issuance_oracle.issuer_pins()
        connection = Connection(fixture, pins)
        expected = independent_owner_work(fixture, pins)
        work = self.work(expected["admission"])
        signatures = []
        owner = self.owner(fixture, pins,
            planner_public_key=oracle._CallbackPublicKey(fixture.plan.key.public_key(), lambda: signatures.append("planner")),
            verifier_public_key=oracle._CallbackPublicKey(fixture.key.public_key(), lambda: signatures.append("verifier")),
            witness_public_key=oracle._CallbackPublicKey(fixture.witness_key.public_key(), lambda: signatures.append("witness")))
        with patch.object(store, "_issue_on_connection", wraps=store._issue_on_connection) as stored, \
                patch.object(capability, "_verify_signed_capability_on_work",
                    wraps=capability._verify_signed_capability_on_work) as verified, \
                patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                patch.object(retention.plan.mixed, "_verify", wraps=retention.plan.mixed._verify) as proof:
            result = self.issue(fixture, connection, owner=owner, work=work)
        self.assertEqual((stored.call_count, verified.call_count, replay.call_count, proof.call_count), (1, 1, 1, 1))
        self.assertEqual(signatures, ["verifier", "verifier", "witness", "planner", "verifier"])
        self.assertIs(stored.call_args.kwargs["work"], work)
        self.assertIs(verified.call_args.kwargs["work"], work)
        self.assertIs(stored.call_args.kwargs["connection"], connection)
        self.assertIs(stored.call_args.kwargs["envelope_bytes"], fixture.raw)
        self.assertIs(stored.call_args.kwargs["retention_expectations"]["database_now"], fixture.plan.semantic.database_now)
        self.assertEqual(result, issuance_oracle.expected_receipt(fixture))
        self.assertEqual(connection.rows(), issuance_oracle.expected_load(fixture, pins, issued=True))
        self.assertEqual(oracle.units(work.metrics), expected["total"])
        self.assertEqual((connection.loads, connection.stores, connection.releases, connection.rollbacks), (2, 1, 1, 0))
        self.assertEqual((connection.outer_commits, connection.outer_rollbacks, connection.closes), (1, 0, 1))
        order = ("open", "connection.enter", "savepoint.enter", "store", "savepoint.release", "connection.commit", "connection.close")
        positions = [connection.events.index(event) for event in order]
        self.assertEqual(positions, sorted(positions))
        self.assertTrue(connection.closed)
        self.assertEqual(connection.info.transaction_status, 0)

    def test_prior_witness_and_exact_retry_preserve_custody_and_each_reverify(self):
        for issued, prior_witness in ((False, True), (True, False)):
            fixture, pins = role_bound_fixture(), issuance_oracle.issuer_pins()
            connection = Connection(fixture, pins, issued=issued, prior_witness=prior_witness)
            expected = independent_owner_work(fixture, pins, issued=issued, prior_witness=prior_witness)
            work, before = self.work(expected["admission"]), connection.snapshot()
            with self.subTest(issued=issued), patch.object(retention, "_verify_record_on_work",
                    wraps=retention._verify_record_on_work) as replay:
                self.assertEqual(self.issue(fixture, connection, work=work), issuance_oracle.expected_receipt(fixture))
            self.assertEqual(replay.call_count, 1)
            self.assertEqual(oracle.units(work.metrics), expected["total"])
            self.assertEqual(connection.witnesses, before[-1])
            if issued:
                self.assertEqual(connection.snapshot(), before)
            self.assertEqual((connection.outer_commits, connection.closes), (1, 1))

    def test_constructor_copies_exact_identity_and_policy_scalars_without_key_serialization(self):
        fixture, pins = role_bound_fixture(), issuance_oracle.issuer_pins()
        supplied = constructor_inputs(fixture, pins)
        owner = configured.RevocationCapabilityIssuer(**supplied)
        original = owner._snapshot_configuration()
        self.assertIs(type(original), tuple)
        self.assertEqual(len(original), 12)
        self.assertEqual(original[11], supplied["database_pins"])
        self.assertEqual(original[3], tuple(fixture.plan.identity[name] for name in IDENTITY_FIELDS))
        self.assertEqual(original[4], tuple(fixture.plan.semantic.receipt.identity[name] for name in IDENTITY_FIELDS))
        self.assertEqual(original[6], tuple(pins[name] for name in ("measurementDigest", "attestationReceiptDigest",
            "credentialIssuanceDigest", "maximumAgeNs", "maximumClockSkewNs")))
        for name in ("expected_planner_identity", "expected_verifier_identity"):
            supplied[name]["measurementDigest"] = oracle.sha(b"mutated caller identity")
        supplied["issuer_pins"]["maximumAgeNs"] = 1
        supplied["database_pins"] = ("serverware_policy_capability_issuer", "CN=changed", "2", "CN=changed-ca", 3)
        self.assertIs(owner._snapshot_configuration(), original)
        self.assertNotEqual(original[11], supplied["database_pins"])
        connection = Connection(fixture, pins)
        self.assertEqual(self.issue(fixture, connection, owner=owner), issuance_oracle.expected_receipt(fixture))
        with self.assertRaises((AttributeError, TypeError)):
            owner._configuration = tuple(reversed(original))

    def test_constructor_and_snapshot_reject_foreign_or_malformed_configuration(self):
        fixture, pins = role_bound_fixture(), issuance_oracle.issuer_pins()
        class ForeignPin(str):
            def __eq__(self, other):
                raise AssertionError("foreign database pin callback")
        for name, value in (("planner_public_key", object()), ("verifier_public_key", object()),
                ("witness_public_key", object()), ("expected_generation_sequence", True),
                ("expected_generation_sequence", 0), ("expected_issuer_session_identity_digest", "bad"),
                ("expected_witness_identity_digest", None), ("expected_generation_digest", "sha256:" + "G" * 64),
                ("expected_planner_identity", {}), ("expected_verifier_identity", {**fixture.signer_identity, "extra": None}),
                ("issuer_pins", {**pins, "maximumAgeNs": True}), ("issuer_pins", {**pins, "extra": None}),
                ("database_pins", None), ("database_pins", ["serverware_policy_capability_issuer", "dn", "1", "ca", 2]),
                ("database_pins", ("wrong_role", "dn", "1", "ca", 2)),
                ("database_pins", (ForeignPin("serverware_policy_capability_issuer"), "dn", "1", "ca", 2)),
                ("database_pins", ("serverware_policy_capability_issuer", "", "1", "ca", 2)),
                ("database_pins", ("serverware_policy_capability_issuer", "dn", "1", "ca", True)),
                ("database_pins", ("serverware_policy_capability_issuer", "dn", "1", "ca", float("nan")))):
            with self.subTest(field=name), self.assertRaises(ValueError):
                self.owner(fixture, pins, **{name: value})
        owner = self.owner(fixture, pins)
        original = owner._snapshot_configuration()
        class ForeignTuple(tuple):
            def __iter__(self):
                raise AssertionError("foreign configuration callback")
        for value in (list(original), original[:-1], original + (None,), ForeignTuple(original),
                (*original[:3], list(original[3]), *original[4:]),
                (*original[:6], (*original[6][:-1], True), *original[7:])):
            object.__setattr__(owner, "_configuration", value)
            with self.subTest(kind=type(value).__name__), self.assertRaises(ValueError):
                owner._snapshot_configuration()
        class ForeignOwner(configured.RevocationCapabilityIssuer):
            def __getattribute__(self, name):
                if name == "_configuration":
                    raise AssertionError("foreign owner callback")
                return super().__getattribute__(name)
        with self.assertRaises(ValueError):
            configured.RevocationCapabilityIssuer._snapshot_configuration(object.__new__(ForeignOwner))

    def test_class_and_caller_mutation_after_snapshot_cannot_retarget_configured_invocation(self):
        for phase in ("opener", "signature"):
            fixture, pins = role_bound_fixture(), issuance_oracle.issuer_pins()
            connection, supplied = Connection(fixture, pins), call_inputs(fixture)
            changed = []
            owner = None
            def mutate():
                if changed:
                    return
                changed.append(phase)
                replacement = list(owner._snapshot_configuration())
                replacement[:3] = [fixture.other_key.public_key()] * 3
                replacement[3] = replacement[4] = (oracle.sha(b"replacement identity"),) * 3
                replacement[5] = replacement[7] = replacement[8] = replacement[10] = oracle.sha(b"replacement pin")
                replacement[6] = (oracle.sha(b"replacement issuer"),) * 3 + (1, 0)
                replacement[9] += 1
                object.__setattr__(owner, "_configuration", tuple(replacement))
                supplied["expected_request"]["arguments"]["actor_id"] = "replacement actor"
                supplied["expected_before"]["indexBeforeHeads"][0]["rootDigest"] = oracle.sha(b"replacement root")
                supplied["now_epoch_ns"] = 1
            owner = self.owner(fixture, pins, verifier_public_key=oracle._CallbackPublicKey(
                fixture.key.public_key(), mutate if phase == "signature" else lambda: None))
            def opener():
                connection.event("open")
                if phase == "opener":
                    mutate()
                return connection
            with self.subTest(phase=phase):
                self.assertEqual(self.issue(fixture, connection, owner=owner, supplied=supplied, opener=opener),
                    issuance_oracle.expected_receipt(fixture))
            self.assertEqual(changed, [phase])
            self.assertEqual(connection.rows(), issuance_oracle.expected_load(fixture, pins, issued=True))
            self.assertEqual((connection.outer_commits, connection.closes), (1, 1))

    def test_closed_historical_inventory_cannot_override_configuration_or_private_plumbing(self):
        fixture, pins = role_bound_fixture(), issuance_oracle.issuer_pins()
        owner = self.owner(fixture, pins)
        original = call_inputs(fixture)
        self.assertEqual(set(original) - {"envelope_bytes", "witness_request_bytes",
            "expected_execution_envelope_id", "expected_witness_receipt_digest"}, HISTORICAL_FIELDS)
        variants = [(name, object()) for name in ("planner_public_key", "verifier_public_key", "witness_public_key",
            "expected_planner_identity", "expected_verifier_identity", "expected_signer_identity", "issuer_pins",
            "expected_configuration_digest", "opener", "connection", "operation", "successfulRecord")]
        for name, value in variants:
            connection = Connection(fixture, pins)
            supplied = {**original, name: value}
            work = self.work()
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.issue(fixture, connection, owner=owner, supplied=supplied, work=work)
            self.assertEqual((connection.events, connection.statements), ([], []))
            self.assertEqual(oracle.units(work.metrics), (0, 0, 0))
        for omitted in HISTORICAL_FIELDS:
            connection = Connection(fixture, pins)
            supplied = {name: value for name, value in original.items() if name != omitted}
            with self.subTest(omitted=omitted), self.assertRaises(ValueError):
                self.issue(fixture, connection, owner=owner, supplied=supplied)
            self.assertEqual(connection.events, [])
        for field, value in (("envelope_bytes", fixture.envelope), ("witness_request_bytes", b"x"),
                ("expected_execution_envelope_id", "bad"), ("expected_witness_receipt_digest", None)):
            connection = Connection(fixture, pins)
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.issue(fixture, connection, owner=owner, supplied={**original, field: value})
            self.assertEqual(connection.events, [])
        for invalid_work in (None, object()):
            connection = Connection(fixture, pins)
            with self.subTest(work=type(invalid_work).__name__), self.assertRaises(ValueError):
                configured._run_on_configuration(owner._snapshot_configuration(),
                    envelope_bytes=fixture.raw, witness_request_bytes=oracle.wire(fixture.witness_request),
                    expected_execution_envelope_id=fixture.execution_envelope_id,
                    expected_witness_receipt_digest=fixture.witness_receipt_digest,
                    expectations={name: original[name] for name in HISTORICAL_FIELDS},
                    work=invalid_work, opener=lambda: connection)
            self.assertEqual(connection.events, [])

    def test_wrong_configured_keys_and_authentically_resigned_false_plan_never_commit(self):
        for case in ("planner", "verifier", "witness", "false_plan", "signer_identity"):
            fixture, pins = role_bound_fixture(), issuance_oracle.issuer_pins()
            changes = {}
            if case in ("planner", "verifier", "witness"):
                changes[case + "_public_key"] = fixture.other_key.public_key()
            elif case == "signer_identity":
                changes["expected_verifier_identity"] = {**fixture.signer_identity,
                    "measurementDigest": oracle.sha(b"different independently configured verifier")}
            else:
                fixture.plan.payload["expectedResultDigest"] = oracle.sha(b"false signed plan result")
                fixture.plan.resign()
                fixture.rebuild()
            owner, connection = self.owner(fixture, pins, **changes), Connection(fixture, pins)
            before = connection.snapshot()
            with self.subTest(case=case), patch.object(retention.plan.mixed, "_verify",
                    wraps=retention.plan.mixed._verify) as proof, self.assertRaises(ValueError):
                self.issue(fixture, connection, owner=owner)
            self.assertEqual(proof.call_count, int(case == "false_plan"))
            self.assertEqual(connection.stores, 0)
            self.assertEqual(connection.snapshot(), before)
            self.assertEqual((connection.rollbacks, connection.outer_rollbacks, connection.outer_commits, connection.closes), (1, 1, 0, 1))

    def test_partial_store_return_and_readback_failures_roll_back_inner_and_outer_owners(self):
        fixture, pins = role_bound_fixture(), issuance_oracle.issuer_pins()
        for failure in ("witness", "capability", "sidecar", "identity", "readback"):
            connection = Connection(fixture, pins)
            if failure in ("witness", "capability", "sidecar"):
                connection.fail_after = failure
            elif failure == "identity":
                connection.receipt_override = lambda row: {**row, "capabilityId": oracle.sha(b"wrong result identity")}
            else:
                def corrupt(rows, count):
                    if count == 2:
                        rows = copy.deepcopy(rows)
                        rows["retainedCapability"]["signer_key_digest"] = oracle.sha(b"wrong readback")
                    return rows
                connection.load_override = corrupt
            before = connection.snapshot()
            with self.subTest(failure=failure), patch.object(retention, "_verify_record_on_work",
                    wraps=retention._verify_record_on_work) as replay, self.assertRaises(ValueError):
                self.issue(fixture, connection)
            self.assertEqual((replay.call_count, connection.stores), (1, 1))
            self.assertEqual(connection.snapshot(), before)
            self.assertEqual((connection.rollbacks, connection.releases), (1, 0))
            self.assertEqual((connection.outer_rollbacks, connection.outer_commits, connection.closes), (1, 0, 1))
            order = ("savepoint.rollback", "connection.rollback", "connection.close")
            positions = [connection.events.index(event) for event in order]
            self.assertEqual(positions, sorted(positions))

    def test_current_expiry_on_new_and_existing_issued_custody_never_commits(self):
        fixture, pins = role_bound_fixture(), issuance_oracle.issuer_pins()
        for issued in (False, True):
            for late in (False, True):
                connection = Connection(fixture, pins, issued=issued)
                epochs = [fixture.plan.deadline_epoch_ns]
                if late:
                    epochs.insert(0, fixture.plan.now_epoch_ns)
                before = connection.snapshot()
                with self.subTest(issued=issued, late=late), self.assertRaisesRegex(
                        store.RevocationCapabilityIssuanceError, "current deadline"):
                    self.issue(fixture, connection, epoch=epochs)
                self.assertEqual(connection.stores, int(late))
                self.assertEqual(connection.snapshot(), before)
                self.assertEqual((connection.rollbacks, connection.outer_rollbacks, connection.closes), (1, 1, 1))
                self.assertEqual(connection.outer_commits, 0)

    def test_connection_returned_before_failed_opener_guard_is_closed_without_entering(self):
        fixture, pins = role_bound_fixture(), issuance_oracle.issuer_pins()
        for mutation in ("spend", "refund", "float", "limits"):
            connection, work = Connection(fixture, pins), self.work()
            changed = []
            def opener():
                connection.event("open")
                if mutation == "spend":
                    work.charge(input_bytes=1)
                elif mutation == "refund":
                    work.input_bytes -= 1
                elif mutation == "float":
                    work.input_bytes = float(work.input_bytes)
                else:
                    work.limits = accounting.QueryReadValidationLimits()
                changed.append((work.hash_work, work.input_bytes, work.json_nodes, work.limits))
                return connection
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.issue(fixture, connection, work=work, opener=opener)
            self.assertEqual(connection.events, ["open", "connection.close"])
            self.assertEqual(connection.statements, [])
            self.assertEqual((connection.outer_commits, connection.outer_rollbacks, connection.closes), (0, 0, 1))
            self.assertEqual((work.hash_work, work.input_bytes, work.json_nodes), changed[0][:3])
            self.assertIs(work.limits, changed[0][3])
        connection, work = Connection(fixture, pins), self.work()
        first = RuntimeError("original opener failure before any returned handle")
        def failed_open():
            raise first
        with self.assertRaises(RuntimeError) as raised:
            self.issue(fixture, connection, work=work, opener=failed_open)
        self.assertIs(raised.exception, first)
        self.assertEqual((connection.events, connection.closes), ([], 0))

    def test_entered_connection_guard_failure_rolls_back_and_closes_without_store(self):
        fixture, pins = role_bound_fixture(), issuance_oracle.issuer_pins()
        for mutation in ("meter", "inactive", "autocommit"):
            connection, work = Connection(fixture, pins), self.work()
            changed = []
            def enter(event):
                if event != "connection.enter":
                    return
                if mutation == "meter":
                    work.charge(input_bytes=1)
                    changed.append(oracle.units(work.metrics))
                elif mutation == "inactive":
                    connection.info.transaction_status = 0
                else:
                    connection.autocommit = True
            connection.on_event = enter
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.issue(fixture, connection, work=work)
            self.assertEqual(connection.statements, [])
            self.assertEqual((connection.rollbacks, connection.outer_rollbacks, connection.closes), (0, 1, 1))
            self.assertNotIn("connection.commit", connection.events)
            if mutation == "meter":
                self.assertEqual(oracle.units(work.metrics), changed[0])

    def test_real_key_callback_meter_or_connection_corruption_denies_with_outer_cleanup(self):
        fixture, pins = role_bound_fixture(), issuance_oracle.issuer_pins()
        for mutation in ("spend", "refund", "float", "limits", "raw"):
            connection, work = Connection(fixture, pins), self.work()
            changed = []
            def corrupt():
                if changed:
                    return
                if mutation == "spend":
                    work.charge(input_bytes=1)
                elif mutation == "refund":
                    work.input_bytes -= 1
                elif mutation == "float":
                    work.input_bytes = float(work.input_bytes)
                elif mutation == "limits":
                    work.limits = accounting.QueryReadValidationLimits()
                else:
                    connection.pgconn = object()
                changed.append((work.hash_work, work.input_bytes, work.json_nodes))
            owner = self.owner(fixture, pins, verifier_public_key=oracle._CallbackPublicKey(fixture.key.public_key(), corrupt))
            before = connection.snapshot()
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.issue(fixture, connection, owner=owner, work=work)
            self.assertEqual(connection.snapshot(), before)
            self.assertEqual((connection.stores, connection.rollbacks, connection.outer_rollbacks, connection.closes), (0, 1, 1, 1))
            self.assertEqual(len(changed), 1)
            if mutation != "raw":
                self.assertEqual((work.hash_work, work.input_bytes, work.json_nodes), changed[0])

    def test_outer_result_is_owned_before_normal_commit_callback(self):
        fixture, pins = role_bound_fixture(), issuance_oracle.issuer_pins()
        connection = Connection(fixture, pins)
        borrowed = []
        actual = store._issue_on_connection
        def observe(**kwargs):
            value = actual(**kwargs)
            borrowed.append(value)
            return value
        def mutate(event):
            if event == "connection.commit":
                borrowed[0]["capabilityId"] = oracle.sha(b"released inner result alias")
        connection.on_event = mutate
        with patch.object(store, "_issue_on_connection", side_effect=observe) as called:
            result = self.issue(fixture, connection)
        self.assertEqual(called.call_count, 1)
        self.assertEqual(result, issuance_oracle.expected_receipt(fixture))
        self.assertIsNot(result, borrowed[0])
        self.assertNotEqual(result, borrowed[0])
        self.assertEqual((connection.outer_commits, connection.closes), (1, 1))

    def test_post_commit_exit_failure_is_not_misreported_as_a_rolled_back_invocation(self):
        fixture, pins = role_bound_fixture(), issuance_oracle.issuer_pins()
        expected = independent_owner_work(fixture, pins)
        for failure in ("meter", "cleanup_error"):
            connection, work = Connection(fixture, pins), self.work()
            original = RuntimeError("driver reports an error after its commit")
            def after_commit(event):
                if event != "connection.commit":
                    return
                if failure == "meter":
                    work.charge(input_bytes=1)
                else:
                    raise original
            connection.on_event = after_commit
            error_type = ValueError if failure == "meter" else RuntimeError
            with self.subTest(failure=failure), patch.object(retention, "_verify_record_on_work",
                    wraps=retention._verify_record_on_work) as replay, self.assertRaises(error_type) as raised:
                self.issue(fixture, connection, work=work)
            if failure == "cleanup_error":
                self.assertIs(raised.exception, original)
            self.assertEqual(replay.call_count, 1)
            self.assertEqual(connection.rows(), issuance_oracle.expected_load(fixture, pins, issued=True))
            self.assertEqual((connection.releases, connection.rollbacks), (1, 0))
            self.assertEqual((connection.outer_commits, connection.outer_rollbacks, connection.closes), (1, 0, 1))
            self.assertEqual(connection.events.count("connection.commit"), 1)
            self.assertNotIn("connection.rollback", connection.events)
            self.assertEqual(oracle.units(work.metrics), oracle.add(expected["total"],
                (0, 1, 0) if failure == "meter" else (0, 0, 0)))

    def test_exact_prior_and_minus_one_quota_cover_capture_replay_and_outer_result(self):
        fixture, pins = role_bound_fixture(), issuance_oracle.issuer_pins()
        expected = independent_owner_work(fixture, pins)
        for prior in ((0, 0, 0), (1, 17, 3)):
            maximum = oracle.add(prior, expected["admission"])
            work, connection = self.work(maximum), Connection(fixture, pins)
            work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
            entering = work.limits
            self.assertEqual(self.issue(fixture, connection, work=work), issuance_oracle.expected_receipt(fixture))
            self.assertEqual(oracle.units(work.metrics), oracle.add(prior, expected["total"]))
            self.assertIs(work.limits, entering)
            for axis in range(3):
                limits = list(maximum)
                limits[axis] -= 1
                work, connection = self.work(tuple(limits)), Connection(fixture, pins)
                work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
                entering, before = work.limits, connection.snapshot()
                with self.subTest(prior=prior, axis=axis), self.assertRaises(ValueError):
                    self.issue(fixture, connection, work=work)
                self.assertEqual(connection.snapshot(), before)
                self.assertEqual(connection.outer_commits, 0)
                self.assertIs(work.limits, entering)
                self.assertTrue(all(value <= limit for value, limit in zip(oracle.units(work.metrics), limits)))

    def test_repeated_outer_owners_share_remaining_work_and_repeat_genuine_replay(self):
        fixture, pins = role_bound_fixture(), issuance_oracle.issuer_pins()
        first = independent_owner_work(fixture, pins)
        retry = independent_owner_work(fixture, pins, issued=True)
        limits = tuple(max(a, b) for a, b in zip(first["admission"], oracle.add(first["total"], retry["admission"])))
        work, owner = self.work(limits), self.owner(fixture, pins)
        one, two = Connection(fixture, pins), Connection(fixture, pins, issued=True)
        with patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
            self.assertEqual(self.issue(fixture, one, owner=owner, work=work), issuance_oracle.expected_receipt(fixture))
            self.assertEqual(one.snapshot(), two.snapshot())
            self.assertEqual(self.issue(fixture, two, owner=owner, work=work), issuance_oracle.expected_receipt(fixture))
        self.assertEqual(replay.call_count, 2)
        self.assertEqual(oracle.units(work.metrics), oracle.add(first["total"], retry["total"]))
        self.assertEqual((one.outer_commits, two.outer_commits, one.closes, two.closes), (1, 1, 1, 1))
        three = Connection(fixture, pins, issued=True)
        before = three.snapshot()
        with self.assertRaises(ValueError):
            self.issue(fixture, three, owner=owner, work=work)
        self.assertEqual(three.snapshot(), before)
        self.assertEqual(three.outer_commits, 0)


if __name__ == "__main__":
    unittest.main()
