#!/usr/bin/env python3
"""Genuine capability replay over a private issuer statement/rollback model.

The recorder is an already-admitted-connection fixture, not PostgreSQL, a live
issuer connector, mTLS, grants, row locking or a successful ACL substitute.
Cryptographic signatures, retained proofs and kernel execution remain genuine;
expected SQL rows are independently derived from original fixture documents.
"""
from __future__ import annotations

import copy
from contextlib import contextmanager
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate import authority_contract
from catchplate import authority_query_read_work as accounting
from catchplate import authority_revocation_capability as capability
from catchplate import authority_revocation_retention as retention
from catchplate.authority_store import planner_connection as admission
from catchplate.authority_store import revocation_capability as issuance
import test_authority_revocation_capability as capability_oracle
import test_authority_revocation_persistence as persistence_oracle
import test_authority_revocation_plan as oracle
import test_authority_revocation_reservation as reservation_oracle


LOAD_KEYS = frozenset({"planner", "retainedPlan", "execution", "assertion", "projection",
                       "capability", "retainedCapability", "witness"})
RECEIPT_FIELDS = frozenset({"capabilityId", "capabilityDigest", "capabilityRecordDigest"})
LOAD_SQL = ("SELECT catchplate_metadata.catchplate_policy_authority_load_revocation_issuance("
    + ", ".join(("%s",) * 6) + ") AS issuance")
STORE_SQL = ("SELECT catchplate_metadata.catchplate_policy_authority_issue_revocation_capability("
    + ", ".join(("%s",) * 8) + ") AS issuance")


def issuer_pins():
    return {"measurementDigest": oracle.sha(b"independently configured issuer measurement"),
        "attestationReceiptDigest": oracle.sha(b"independently configured issuer attestation"),
        "credentialIssuanceDigest": oracle.sha(b"independently configured issuer credential issuance"),
        "maximumAgeNs": 300_000_000_000, "maximumClockSkewNs": 1_000_000_000}


def expected_custody(fixture, pins):
    """Literal 44/20/15 rows, never a production row materializer or verdict."""
    payload, witness = fixture.payload, fixture.witness_receipt
    header = capability_oracle.expected_header(fixture)
    record_digest = oracle.framed(capability_oracle.RECORD_SCHEMA, oracle.wire(header))
    parent = {
        "capability_id": payload["capabilityId"], "capability_protocol": "revocation-v4",
        "capability_record_digest": record_digest, "capability_digest": header["capabilityDigest"],
        "envelope_id": payload["envelopeId"], "operation": "webauthn.credential.revoke",
        "operation_id": payload["operationId"], "handler_name": "revoke_webauthn_credential",
        "request_digest": payload["requestDigest"], "operation_manifest_digest": payload["operationManifestDigest"],
        "query_manifest_digest": payload["queryManifestDigest"], "authority_root_set_digest": payload["authorityRootSetDigest"],
        "authority_snapshot_digest": payload["authoritySnapshotDigest"], "approver_policy_digest": payload["approverPolicyDigest"],
        "webauthn_receipt_json": oracle.wire(payload["webauthnReceipt"]).decode("ascii"),
        "webauthn_receipt_digest": payload["webauthnReceiptDigest"],
        "webauthn_trust_high_water_digest": payload["webauthnTrustHighWaterDigest"],
        "witness_reservation_digest": payload["witnessReservationDigest"], "witness_sequence": payload["witnessSequence"],
        "witness_head_digest": payload["witnessHeadDigest"], "deadline_monotonic_ns": payload["deadlineMonotonicNs"],
        "fence": payload["fence"], "issued_monotonic_ns": payload["issuedMonotonicNs"],
        "issued_at_epoch_ns": payload["issuedAtEpochNs"], "expires_at_epoch_ns": payload["expiresAtEpochNs"],
        "issuer_session_identity_digest": payload["issuerSessionIdentityDigest"],
        "issuer_measurement_digest": pins["measurementDigest"], "issuer_attestation_receipt_digest": pins["attestationReceiptDigest"],
        "issuer_credential_issuance_digest": pins["credentialIssuanceDigest"],
        "status": "issued", "writer_token_digest": None, "reserved_at_epoch_ns": None,
        "reserved_transaction_id": None, "result_digest": None, "commit_receipt_digest": None,
        "committed_at_epoch_ns": None, "failure_digest": None, "failed_at_epoch_ns": None,
        "expected_result_digest": payload["expectedResultDigest"], "planner_transaction_id": payload["plannerTransactionId"],
        "authorization_projection_digest": payload["authorizationProjectionDigest"],
        "selected_business_rows_digest": payload["selectedBusinessRowsDigest"],
        "mutation_plan_digest": payload["mutationPlanDigest"], "deadline_epoch_ns": payload["deadlineEpochNs"],
    }
    sidecar = {
        "capability_id": payload["capabilityId"], "capability_protocol": "revocation-v4",
        "capability_record_digest": record_digest, "planner_transaction_id": payload["plannerTransactionId"],
        "plan_protocol": "revocation-v4", "retained_record_digest": fixture.retained_digest,
        "execution_envelope_id": payload["envelopeId"], "capability_digest": header["capabilityDigest"],
        "root_transition_digest": payload["rootTransitionDigest"], "authority_snapshot_digest": payload["authoritySnapshotDigest"],
        "exact_request_bytes_digest": oracle.sha(fixture.execution_bytes), "exact_capability_base64url": oracle.encoded(fixture.raw),
        "exact_capability_bytes_digest": oracle.sha(fixture.raw), "exact_capability_byte_count": len(fixture.raw),
        "signer_key_digest": header["signerKeyDigest"], "witness_key_digest": header["witnessKeyDigest"],
        "exact_witness_request_base64url": oracle.encoded(oracle.wire(fixture.witness_request)),
        "exact_witness_request_bytes_digest": oracle.sha(oracle.wire(fixture.witness_request)),
        "exact_witness_request_byte_count": len(oracle.wire(fixture.witness_request)),
        "source_revision": authority_contract.SOURCE_REVISION,
    }
    witness_row = {
        "witness_receipt_digest": fixture.witness_receipt_digest, "witness_identity_digest": witness["witnessIdentityDigest"],
        "witness_sequence": witness["sequence"], "witness_head_digest": witness["headDigest"],
        "predecessor_head_digest": witness["predecessorHeadDigest"],
        "predecessor_receipt_digest": witness["predecessorReceiptDigest"],
        "log_predecessor_head_digest": witness["logPredecessorHeadDigest"], "phase": "reserve",
        "operation": "webauthn.credential.revoke", "request_digest": witness["requestDigest"],
        "capability_id": witness["capabilityId"], "result_digest": None, "fence": witness["fence"],
        "receipt_json": oracle.wire(witness).decode("ascii"), "recorded_at_epoch_ns": witness["issuedAtEpochNs"],
    }
    return parent, sidecar, witness_row


def expected_load(fixture, pins, *, issued=False, prior_witness=False):
    parent, retained = persistence_oracle.expected_rows(fixture.plan, fixture.plan.now_epoch_ns)
    assertion, projection = persistence_oracle.expected_authorization_rows(fixture.plan)
    writer, capability_record, witness = expected_custody(fixture, pins)
    return {"planner": parent, "retainedPlan": retained,
        "execution": reservation_oracle.expected_envelope(fixture.plan, fixture.execution_envelope_id),
        "assertion": assertion, "projection": projection,
        "capability": writer if issued else None, "retainedCapability": capability_record if issued else None,
        "witness": witness if issued or prior_witness else None}


def expected_receipt(fixture):
    header = capability_oracle.expected_header(fixture)
    return {"capabilityId": fixture.payload["capabilityId"], "capabilityDigest": header["capabilityDigest"],
        "capabilityRecordDigest": oracle.framed(capability_oracle.RECORD_SCHEMA, oracle.wire(header))}


def expected_load_parameters(fixture, pins):
    return (fixture.plan.planner_transaction_id, fixture.execution_envelope_id,
        fixture.payload["capabilityId"], pins["measurementDigest"], pins["attestationReceiptDigest"],
        pins["credentialIssuanceDigest"])


def expected_store_parameters(fixture, pins):
    header = capability_oracle.expected_header(fixture)
    return (oracle.encoded(fixture.raw), oracle.encoded(oracle.wire(fixture.witness_request)),
        expected_receipt(fixture)["capabilityRecordDigest"], header["signerKeyDigest"], header["witnessKeyDigest"],
        pins["measurementDigest"], pins["attestationReceiptDigest"], pins["credentialIssuanceDigest"])


def arguments(fixture, pins):
    supplied = fixture.arguments()
    for name in ("retained_envelope_bytes", "evaluation_context_bytes", "execution_request_bytes"):
        del supplied[name]
    return {**supplied, "issuer_pins": copy.deepcopy(pins)}


def independent_issuance_work(fixture, pins, *, issued=False, prior_witness=False):
    """Literal successful owner passes plus the existing genuine replay peak.

    Neither production row builders nor observed metrics determine this oracle.
    Fixed SQL columns/scaffolding, driver and cryptographic internals are not
    claimed as H/B/N; all variable copies, codecs and comparisons are included.
    """
    add, graph = oracle.add, oracle.graph_cost
    before = expected_load(fixture, pins, issued=issued, prior_witness=prior_witness)
    after = expected_load(fixture, pins, issued=True)
    load_arguments = dict(zip(("plannerTransactionId", "executionEnvelopeId", "capabilityId",
        "measurementDigest", "attestationReceiptDigest", "credentialIssuanceDigest"),
        expected_load_parameters(fixture, pins)))
    store_arguments = dict(zip(("capabilityBase64Url", "witnessRequestBase64Url", "recordDigest",
        "signerKeyDigest", "witnessKeyDigest", "measurementDigest", "attestationReceiptDigest",
        "credentialIssuanceDigest"), expected_store_parameters(fixture, pins)))
    capture = add(graph(capability_oracle.capture_graph(fixture), 1, 1), graph(pins, 1, 1))
    prefix = add(capture, graph(load_arguments), *(graph(row) for row in before.values() if row is not None),
        *(persistence_oracle.codec_decode(raw) for raw in (
            fixture.retained_bytes, fixture.context_bytes, fixture.execution_bytes)))
    replay = capability_oracle.independent_capability_work(fixture)
    plan = fixture.plan
    authorization = persistence_oracle.independent_authorization_work(plan)
    bindings = add(graph(plan.payload["selectedBusinessRows"], 3, 2), graph(plan.payload["mutationPlan"], 3, 2),
        *(persistence_oracle.codec_encode(raw) for raw in (
            fixture.retained_bytes, fixture.context_bytes, oracle.wire(plan.payload))),
        authorization["materialized"], authorization["joined"],
        graph(fixture.execution_request), (1, len(fixture.execution_bytes), 0),
        persistence_oracle.codec_encode(fixture.execution_bytes),
        graph(fixture.payload["webauthnReceipt"], 3, 2), graph(fixture.witness_receipt, 3, 2),
        persistence_oracle.codec_encode(fixture.raw),
        persistence_oracle.codec_encode(oracle.wire(fixture.witness_request)))
    comparisons = add(*(persistence_oracle.scalar_comparisons(row)
        for row in before.values() if row is not None))
    returned = expected_receipt(fixture)
    suffix = add(bindings, comparisons, graph(store_arguments), graph(returned),
        persistence_oracle.scalar_comparisons(returned),
        *(add(graph(row), persistence_oracle.scalar_comparisons(row)) for row in after.values()))
    total = add(prefix, replay["total"], suffix)
    peak = add(prefix, replay["admission"])
    return {"capture": capture, "prefix": prefix, "replay": replay, "suffix": suffix,
        "total": total, "admission": tuple(max(a, b) for a, b in zip(total, peak))}


class Recorder(reservation_oracle.Recorder):
    """Admitted-connection precondition only; SQL bodies and ACLs are not run."""

    def __init__(self, fixture, pins, *, issued=False, prior_witness=False):
        super().__init__()
        self.fixture, self.pins = fixture, copy.deepcopy(pins)
        self.seed(fixture.plan, fixture.plan.now_epoch_ns)
        self.envelopes[fixture.execution_envelope_id] = reservation_oracle.expected_envelope(
            fixture.plan, fixture.execution_envelope_id)
        writer, sidecar, witness = expected_custody(fixture, pins)
        self.capabilities = {writer["capability_id"]: writer} if issued else {}
        self.capability_records = {sidecar["capability_id"]: sidecar} if issued else {}
        self.witnesses = {witness["witness_receipt_digest"]: witness} if issued or prior_witness else {}
        self.closed, self.autocommit = False, False
        self.pgconn, self.info = object(), SimpleNamespace(transaction_status=2)
        self.fail_after = None
        self.load_override, self.receipt_override = None, None
        self.loads = self.stores = 0

    def snapshot(self):
        return copy.deepcopy((self.parent, self.sidecar, self.assertions, self.projections,
            self.envelopes, self.capabilities, self.capability_records, self.witnesses))

    @contextmanager
    def transaction(self):
        before = self.snapshot()
        try:
            self.event("savepoint.enter")
            yield self
        except BaseException:
            (self.parent, self.sidecar, self.assertions, self.projections,
                self.envelopes, self.capabilities, self.capability_records, self.witnesses) = before
            self.rollbacks += 1
            self.event("savepoint.rollback")
            raise
        else:
            self.releases += 1
            self.event("savepoint.release")

    def cursor(self):
        return Cursor(self)

    def rows(self):
        fixture = self.fixture
        projection = self.projections.get(self.parent["authorization_projection_digest"])
        evidence = None if projection is None else self.assertions.get(projection["assertion_evidence_digest"])
        value = {"planner": self.parent, "retainedPlan": self.sidecar,
            "execution": self.envelopes.get(fixture.execution_envelope_id), "assertion": evidence,
            "projection": projection, "capability": self.capabilities.get(fixture.payload["capabilityId"]),
            "retainedCapability": self.capability_records.get(fixture.payload["capabilityId"]),
            "witness": self.witnesses.get(fixture.witness_receipt_digest)}
        if self.load_override is not None:
            value = self.load_override(value, self.loads)
        return value if self.return_aliases else copy.deepcopy(value)

    def insert_model(self):
        # This is a deterministic row/conflict/rollback model, not execution of
        # the definer, a uniqueness constraint, current fence or an ACL verdict.
        writer, sidecar, witness = expected_custody(self.fixture, self.pins)
        for name, table, row, identity in (("witness", self.witnesses, witness, witness["witness_receipt_digest"]),
                ("capability", self.capabilities, writer, writer["capability_id"]),
                ("sidecar", self.capability_records, sidecar, sidecar["capability_id"])):
            existing = table.get(identity)
            if existing is not None and existing != row:
                raise persistence_oracle.StoreError("synthetic issuer custody conflict")
            table.setdefault(identity, copy.deepcopy(row))
            self.event("store." + name)
            if self.fail_after == name:
                raise persistence_oracle.StoreError("synthetic failure after " + name)


class Cursor:
    def __init__(self, recorder):
        self.recorder, self.result = recorder, None

    def __enter__(self):
        self.recorder.event("cursor.enter")
        return self

    def __exit__(self, *exc):
        self.recorder.event("cursor.exit")
        return False

    def execute(self, sql, parameters=()):
        r = self.recorder
        r.statements.append((sql, parameters))
        if r.callback is not None:
            r.callback(sql, parameters)
        if sql == LOAD_SQL:
            if parameters != expected_load_parameters(r.fixture, r.pins):
                raise AssertionError("issuer load escaped exact six-argument independent identity")
            r.loads += 1
            r.event("load")
            self.result = {"issuance": r.rows()}
        elif sql == STORE_SQL:
            if parameters != expected_store_parameters(r.fixture, r.pins):
                raise AssertionError("issuer store escaped exact original-byte eight-argument binding")
            r.stores += 1
            r.event("store")
            r.insert_model()
            receipt = expected_receipt(r.fixture)
            self.result = {"issuance": receipt if r.receipt_override is None else r.receipt_override(receipt)}
        else:
            raise AssertionError("issuer recorder accepts only the two fixed definer calls: " + sql)
        return self

    def fetchone(self):
        self.recorder.event("fetchone")
        return self.result


class RevocationIssuanceTests(unittest.TestCase):
    def setUp(self):
        self.old_namespace = admission._DB_GLOBALS
        # Only the real shared error factory is bound. No role admission,
        # connector, verifier or SQL success function is substituted here.
        admission.bind_db_globals({"MetadataStoreError": persistence_oracle.StoreError})

    def tearDown(self):
        admission._DB_GLOBALS = self.old_namespace

    def work(self, limits=None):
        return accounting._ValidationWork(accounting.QueryReadValidationLimits(*(limits or ())))

    def issue(self, fixture, recorder, work=None, *, epoch=None, monotonic=None, supplied=None, **changes):
        supplied = arguments(fixture, recorder.pins) if supplied is None else supplied
        supplied = {**supplied, **changes}
        with patch.object(issuance.time, "time_ns", return_value=fixture.plan.now_epoch_ns,
                side_effect=epoch), patch.object(issuance.time, "monotonic_ns",
                return_value=fixture.plan.now_monotonic_ns, side_effect=monotonic):
            return issuance._issue_on_connection(connection=recorder,
                work=self.work() if work is None else work, **supplied)

    def assert_no_custody(self, recorder):
        self.assertEqual((recorder.capabilities, recorder.capability_records, recorder.witnesses), ({}, {}, {}))

    def test_genuine_three_signatures_and_retained_replay_precede_exact_custody(self):
        fixture, pins = capability_oracle.CapabilityFixture(), issuer_pins()
        recorder = Recorder(fixture, pins)
        expected = independent_issuance_work(fixture, pins)
        work = self.work(expected["admission"])
        attempts = []
        supplied = arguments(fixture, pins)
        supplied["signer_public_key"] = oracle._CallbackPublicKey(fixture.key.public_key(),
            lambda: attempts.append("signer"))
        supplied["witness_public_key"] = oracle._CallbackPublicKey(fixture.witness_key.public_key(),
            lambda: attempts.append("witness"))
        with patch.object(capability, "_verify_signed_capability_on_work",
                wraps=capability._verify_signed_capability_on_work) as verified, \
                patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                patch.object(retention.plan.mixed, "_verify", wraps=retention.plan.mixed._verify) as proof, \
                patch.object(retention.plan.semantics, "_derive_revocation_effects",
                    wraps=retention.plan.semantics._derive_revocation_effects) as effects:
            actual = self.issue(fixture, recorder, work, supplied=supplied)
        self.assertEqual((verified.call_count, replay.call_count, proof.call_count, effects.call_count), (1, 1, 1, 1))
        self.assertEqual(attempts, ["signer", "signer", "witness"])
        self.assertIs(verified.call_args.kwargs["work"], work)
        self.assertEqual(verified.call_args.kwargs["retained_envelope_bytes"], fixture.retained_bytes)
        self.assertEqual(verified.call_args.kwargs["evaluation_context_bytes"], fixture.context_bytes)
        self.assertEqual(verified.call_args.kwargs["execution_request_bytes"], fixture.execution_bytes)
        self.assertEqual(actual, expected_receipt(fixture))
        self.assertEqual(recorder.rows(), expected_load(fixture, pins, issued=True))
        self.assertEqual(tuple(map(len, recorder.rows().values())), (30, 12, 28, 35, 21, 44, 20, 15))
        self.assertEqual([sql for sql, _ in recorder.statements], [LOAD_SQL, STORE_SQL, LOAD_SQL])
        self.assertEqual((recorder.loads, recorder.stores, recorder.rollbacks, recorder.releases), (2, 1, 0, 1))
        self.assertEqual(oracle.units(work.metrics), expected["total"])
        self.assertFalse(recorder.closed)
        self.assertEqual(recorder.info.transaction_status, 2)

    def test_authentic_prior_witness_and_exact_issued_retry_reverify_without_repair(self):
        for issued, prior_witness in ((False, True), (True, False)):
            fixture, pins = capability_oracle.CapabilityFixture(), issuer_pins()
            recorder = Recorder(fixture, pins, issued=issued, prior_witness=prior_witness)
            before = recorder.snapshot()
            expected = independent_issuance_work(fixture, pins, issued=issued, prior_witness=prior_witness)
            work = self.work(expected["admission"])
            with self.subTest(issued=issued), patch.object(retention, "_verify_record_on_work",
                    wraps=retention._verify_record_on_work) as replay:
                self.assertEqual(self.issue(fixture, recorder, work), expected_receipt(fixture))
            self.assertEqual(replay.call_count, 1)
            self.assertEqual(oracle.units(work.metrics), expected["total"])
            self.assertEqual(recorder.rows(), expected_load(fixture, pins, issued=True))
            if issued:
                self.assertEqual(recorder.snapshot(), before)
            else:
                self.assertEqual(recorder.witnesses, before[-1])
            saved = recorder.snapshot()
            with self.assertRaisesRegex(issuance.RevocationCapabilityIssuanceError, "current deadline"):
                self.issue(fixture, recorder, epoch=[fixture.plan.deadline_epoch_ns])
            self.assertEqual(recorder.snapshot(), saved)
            self.assertEqual(recorder.stores, 1)

    def test_original_transport_aliases_and_loaded_codec_corruption_never_issue(self):
        for part in ("capability", "request", "plan", "context", "wrapper", "base64", "count"):
            fixture, pins = capability_oracle.CapabilityFixture(), issuer_pins()
            recorder = Recorder(fixture, pins)
            supplied = arguments(fixture, pins)
            if part in ("capability", "request"):
                name = "envelope_bytes" if part == "capability" else "witness_request_bytes"
                supplied[name] += b" "
            elif part == "base64":
                recorder.sidecar["exact_envelope_base64url"] = "!" + recorder.sidecar["exact_envelope_base64url"][1:]
            elif part == "count":
                recorder.sidecar["exact_envelope_byte_count"] += 1
            else:
                table, field, count, raw = {
                    "plan": (recorder.sidecar, "exact_envelope_base64url", "exact_envelope_byte_count", fixture.retained_bytes),
                    "context": (recorder.sidecar, "evaluation_context_base64url", "evaluation_context_byte_count", fixture.context_bytes),
                    "wrapper": (recorder.envelopes[fixture.execution_envelope_id], "exact_request_base64url",
                        "exact_request_byte_count", fixture.execution_bytes)}[part]
                table[field], table[count] = oracle.encoded(raw + b" "), len(raw) + 1
            with self.subTest(part=part), self.assertRaises(ValueError):
                self.issue(fixture, recorder, supplied=supplied)
            self.assertEqual(recorder.stores, 0)
            self.assert_no_custody(recorder)
            self.assertEqual(recorder.rollbacks, 1)

    def test_real_signature_and_resigned_false_proof_denials_precede_store(self):
        for part in ("capability", "request", "witness", "proof"):
            fixture, pins = capability_oracle.CapabilityFixture(), issuer_pins()
            if part == "capability":
                fixture.resign(key=fixture.other_key)
            elif part == "request":
                fixture.sign_request(key=fixture.other_key)
                fixture.witness_receipt["canonicalRequestDigest"] = oracle.framed(
                    capability_oracle.REQUEST_SCHEMA, oracle.wire(fixture.witness_request))
                fixture.sign_receipt()
                fixture.rebuild()
            elif part == "witness":
                fixture.sign_receipt(key=fixture.other_key)
                fixture.rebuild()
            else:
                fixture.plan.payload["expectedResultDigest"] = oracle.sha(b"genuinely signed false result")
                fixture.plan.resign()
                fixture.rebuild()
            recorder = Recorder(fixture, pins)
            with self.subTest(part=part), patch.object(retention.plan.mixed, "_verify",
                    wraps=retention.plan.mixed._verify) as proof, self.assertRaises(ValueError):
                self.issue(fixture, recorder)
            self.assertEqual(proof.call_count, int(part == "proof"))
            self.assertEqual(recorder.stores, 0)
            self.assert_no_custody(recorder)

    def test_every_loaded_row_is_closed_exact_scalar_data_before_replay(self):
        for row_name in LOAD_KEYS:
            for corruption in ("missing", "extra", "bool", "subclass"):
                fixture, pins = capability_oracle.CapabilityFixture(), issuer_pins()
                recorder = Recorder(fixture, pins, issued=True)
                def corrupt(rows, _count, name=row_name, kind=corruption):
                    rows = copy.deepcopy(rows)
                    row = rows[name]
                    if kind == "missing":
                        del row[next(iter(row))]
                    elif kind == "extra":
                        row["untrusted"] = None
                    elif kind == "bool":
                        row[next(iter(row))] = True
                    else:
                        rows[name] = type("ForeignRow", (dict,), {})(row)
                    return rows
                recorder.load_override = corrupt
                with self.subTest(row=row_name, corruption=corruption), patch.object(capability,
                        "_verify_signed_capability_on_work", wraps=capability._verify_signed_capability_on_work) as verify, \
                        self.assertRaises(issuance.RevocationCapabilityIssuanceError):
                    self.issue(fixture, recorder)
                self.assertEqual((verify.call_count, recorder.stores), (0, 0))

    def test_shape_valid_conflicts_across_all_eight_rows_reach_real_replay_then_deny(self):
        fields = {"planner": "authority_snapshot_digest", "retainedPlan": "retained_record_digest",
            "execution": "exact_request_bytes_digest", "assertion": "verified_assertion_receipt_digest",
            "projection": "authorization_projection_digest", "capability": "issuer_measurement_digest",
            "retainedCapability": "signer_key_digest", "witness": "receipt_json"}
        for row_name, field in fields.items():
            fixture, pins = capability_oracle.CapabilityFixture(), issuer_pins()
            recorder = Recorder(fixture, pins, issued=True)
            def corrupt(rows, _count, name=row_name, column=field):
                rows = copy.deepcopy(rows)
                self.assertIn(column, rows[name])
                rows[name][column] = oracle.sha(b"different independent custody")
                return rows
            recorder.load_override = corrupt
            before = recorder.snapshot()
            with self.subTest(row=row_name), patch.object(retention.plan.mixed, "_verify",
                    wraps=retention.plan.mixed._verify) as proof, self.assertRaises(persistence_oracle.StoreError):
                self.issue(fixture, recorder)
            self.assertEqual((proof.call_count, recorder.stores), (1, 0))
            self.assertEqual(recorder.snapshot(), before)

    def test_partial_existing_custody_denies_and_authentic_prior_witness_must_match(self):
        for absent in ("capability", "retainedCapability", "witness"):
            fixture, pins = capability_oracle.CapabilityFixture(), issuer_pins()
            recorder = Recorder(fixture, pins, issued=True)
            def corrupt(rows, _count, name=absent):
                return {**rows, name: None}
            recorder.load_override = corrupt
            with self.subTest(absent=absent), self.assertRaisesRegex(
                    issuance.RevocationCapabilityIssuanceError, "custody is incomplete"):
                self.issue(fixture, recorder)
            self.assertEqual(recorder.stores, 0)
        fixture, pins = capability_oracle.CapabilityFixture(), issuer_pins()
        recorder = Recorder(fixture, pins, prior_witness=True)
        recorder.witnesses[fixture.witness_receipt_digest]["recorded_at_epoch_ns"] += 1
        before = recorder.snapshot()
        with patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                self.assertRaises(persistence_oracle.StoreError):
            self.issue(fixture, recorder)
        self.assertEqual((replay.call_count, recorder.stores), (1, 0))
        self.assertEqual(recorder.snapshot(), before)

    def test_partial_writes_bad_returned_identity_and_reread_conflicts_roll_back_all_rows(self):
        for failure in ("witness", "capability", "sidecar", "identity", "identity_extra", "reread", "missing"):
            fixture, pins = capability_oracle.CapabilityFixture(), issuer_pins()
            recorder = Recorder(fixture, pins)
            if failure in ("witness", "capability", "sidecar"):
                recorder.fail_after = failure
            elif failure == "identity":
                recorder.receipt_override = lambda row: {**row, "capabilityId": oracle.sha(b"foreign return")}
            elif failure == "identity_extra":
                recorder.receipt_override = lambda row: {**row, "success": True}
            else:
                def corrupt(rows, count, kind=failure):
                    rows = copy.deepcopy(rows)
                    if count == 2:
                        if kind == "missing":
                            rows["witness"] = None
                        else:
                            rows["capability"]["capability_digest"] = oracle.sha(b"wrong readback")
                    return rows
                recorder.load_override = corrupt
            before = recorder.snapshot()
            with self.subTest(failure=failure), patch.object(retention, "_verify_record_on_work",
                    wraps=retention._verify_record_on_work) as replay, self.assertRaises(ValueError):
                self.issue(fixture, recorder)
            self.assertEqual((replay.call_count, recorder.stores, recorder.rollbacks, recorder.releases), (1, 1, 1, 0))
            self.assertEqual(recorder.snapshot(), before)
            self.assert_no_custody(recorder)

    def test_current_dual_clocks_are_rechecked_after_store_and_never_rewrite_history(self):
        fixture, pins = capability_oracle.CapabilityFixture(), issuer_pins()
        for stage in ("before", "after"):
            for clock in ("epoch", "monotonic", "inconsistent", "bool"):
                recorder = Recorder(fixture, pins)
                now_epoch, now_mono = fixture.plan.now_epoch_ns, fixture.plan.now_monotonic_ns
                bad_epoch = (True if clock == "bool" else now_epoch + pins["maximumClockSkewNs"] + 1
                    if clock == "inconsistent" else fixture.plan.deadline_epoch_ns)
                epochs = ([bad_epoch] if stage == "before" else [now_epoch, bad_epoch])
                monos = ([fixture.plan.deadline_monotonic_ns] if stage == "before"
                    else [now_mono, fixture.plan.deadline_monotonic_ns])
                changes = {"monotonic": monos} if clock == "monotonic" else {"epoch": epochs}
                before = recorder.snapshot()
                with self.subTest(stage=stage, clock=clock), self.assertRaisesRegex(
                        issuance.RevocationCapabilityIssuanceError, "current (deadline|clock)"):
                    self.issue(fixture, recorder, **changes)
                self.assertEqual(recorder.stores, int(stage == "after"))
                self.assertEqual(recorder.snapshot(), before)
                self.assertEqual((recorder.rollbacks, recorder.releases), (1, 0))

    def test_expectation_and_issuer_graphs_are_owned_before_first_driver_callback(self):
        fixture, pins = capability_oracle.CapabilityFixture(), issuer_pins()
        recorder, supplied = Recorder(fixture, pins), arguments(fixture, pins)
        expected = expected_receipt(fixture)
        callbacks = []
        def mutate(sql, _parameters):
            if callbacks:
                return
            callbacks.append(sql)
            supplied["issuer_pins"]["measurementDigest"] = oracle.sha(b"late issuer")
            supplied["issuer_pins"]["maximumAgeNs"] = 1
            supplied["expected_signer_identity"]["measurementDigest"] = oracle.sha(b"late signer")
            supplied["retention_expectations"]["expected_request"]["arguments"]["actor_id"] = "late actor"
            supplied["retention_expectations"]["expected_before"]["indexBeforeHeads"][0]["rootDigest"] = oracle.sha(b"late root")
        recorder.callback = mutate
        actual = self.issue(fixture, recorder, supplied=supplied)
        self.assertEqual(actual, expected)
        self.assertEqual(callbacks, [LOAD_SQL])
        self.assertEqual(recorder.rows(), expected_load(fixture, pins, issued=True))

    def test_loaded_rows_and_returned_identity_detach_before_later_callbacks(self):
        fixture, pins = capability_oracle.CapabilityFixture(), issuer_pins()
        recorder = Recorder(fixture, pins)
        recorder.return_aliases = True
        borrowed = {}
        def expose(rows, count):
            if count == 1:
                # Simulate driver-owned buffers, separately from stored rows.
                borrowed["rows"] = copy.deepcopy(rows)
                return borrowed["rows"]
            return rows
        recorder.load_override = expose
        def after_signature():
            borrowed["rows"]["planner"]["request_digest"] = oracle.sha(b"borrowed planner changed")
            borrowed["rows"]["retainedPlan"]["exact_envelope_base64url"] = "invalidated buffer"
            borrowed["rows"]["assertion"]["evidence_json"] = "invalidated buffer"
        supplied = arguments(fixture, pins)
        supplied["signer_public_key"] = oracle._CallbackPublicKey(fixture.key.public_key(), after_signature)
        def expose_identity(row):
            borrowed["identity"] = row
            return row
        recorder.receipt_override = expose_identity
        def change_identity(sql, _parameters):
            if sql == LOAD_SQL and recorder.loads == 1:
                borrowed["identity"]["capabilityId"] = oracle.sha(b"borrowed identity changed")
        recorder.callback = change_identity
        actual = self.issue(fixture, recorder, supplied=supplied)
        self.assertEqual(actual, expected_receipt(fixture))
        self.assertNotEqual(actual, borrowed["identity"])
        self.assertIsNot(actual, borrowed["identity"])
        self.assertEqual(recorder.rows(), expected_load(fixture, pins, issued=True))

    def test_driver_meter_changes_are_terminal_and_never_refunded(self):
        for phase in ("load", "store", "reread"):
            for mutation in ("spend", "refund", "float", "limits"):
                fixture, pins = capability_oracle.CapabilityFixture(), issuer_pins()
                recorder, work = Recorder(fixture, pins), self.work()
                original_limits, changed = work.limits, []
                def corrupt(sql, _parameters, selected=phase, kind=mutation):
                    current = "store" if sql == STORE_SQL else "load" if recorder.loads == 0 else "reread"
                    if current != selected or changed:
                        return
                    if kind == "spend":
                        work.charge(input_bytes=1)
                    elif kind == "refund":
                        work.input_bytes -= 1
                    elif kind == "float":
                        work.input_bytes = float(work.input_bytes)
                    else:
                        work.limits = accounting.QueryReadValidationLimits()
                    changed.append((work.hash_work, work.input_bytes, work.json_nodes, work.limits))
                recorder.callback = corrupt
                before = recorder.snapshot()
                with self.subTest(phase=phase, mutation=mutation), self.assertRaises(ValueError):
                    self.issue(fixture, recorder, work)
                self.assertEqual(len(changed), 1)
                self.assertEqual((work.hash_work, work.input_bytes, work.json_nodes), changed[0][:3])
                self.assertIs(work.limits, changed[0][3])
                if mutation != "limits":
                    self.assertIs(work.limits, original_limits)
                self.assertEqual(recorder.snapshot(), before)
                self.assertEqual((recorder.rollbacks, recorder.releases), (1, 0))

    def test_active_raw_transaction_identity_survives_neither_driver_nor_crypto_replacement(self):
        for phase in ("enter", "load", "signature", "store", "reread"):
            for field, replacement in (("pgconn", object()), ("closed", True), ("autocommit", True),
                    ("status", 0), ("status", True)):
                fixture, pins = capability_oracle.CapabilityFixture(), issuer_pins()
                recorder, supplied = Recorder(fixture, pins), arguments(fixture, pins)
                changes = []
                def mutate():
                    if changes:
                        return
                    changes.append(phase)
                    if field == "status":
                        recorder.info.transaction_status = replacement
                    else:
                        setattr(recorder, field, replacement)
                if phase == "enter":
                    recorder.on_event = lambda event: mutate() if event == "savepoint.enter" else None
                elif phase == "signature":
                    supplied["signer_public_key"] = oracle._CallbackPublicKey(fixture.key.public_key(), mutate)
                else:
                    def callback(sql, _parameters):
                        current = "store" if sql == STORE_SQL else "load" if recorder.loads == 0 else "reread"
                        if current == phase:
                            mutate()
                    recorder.callback = callback
                before = recorder.snapshot()
                with self.subTest(phase=phase, field=field, replacement=replacement), self.assertRaisesRegex(
                        issuance.RevocationCapabilityIssuanceError, "original active issuer transaction"):
                    self.issue(fixture, recorder, supplied=supplied)
                self.assertEqual(changes, [phase])
                self.assertEqual(recorder.snapshot(), before)
                self.assertEqual((recorder.rollbacks, recorder.releases), (1, 0))
                if phase in ("enter", "load", "signature"):
                    self.assertEqual(recorder.stores, 0)

    def test_closed_admission_rejects_tokens_foreign_pins_work_and_inactive_transactions(self):
        fixture, pins = capability_oracle.CapabilityFixture(), issuer_pins()
        variants = ("bytes", "pins_extra", "pins_missing", "pins_bool", "expectations_extra",
            "key", "none_work", "foreign_work", "inactive")
        for case in variants:
            recorder, supplied, work = Recorder(fixture, pins), arguments(fixture, pins), self.work()
            if case == "bytes":
                supplied["envelope_bytes"] = fixture.envelope
            elif case == "pins_extra":
                supplied["issuer_pins"]["successfulAdmission"] = True
            elif case == "pins_missing":
                del supplied["issuer_pins"]["measurementDigest"]
            elif case == "pins_bool":
                supplied["issuer_pins"]["maximumAgeNs"] = True
            elif case == "expectations_extra":
                supplied["retention_expectations"]["verifiedRecord"] = fixture.plan.payload
            elif case == "key":
                supplied["signer_public_key"] = object()
            elif case == "none_work":
                work = None
            elif case == "foreign_work":
                work = object()
            else:
                recorder.info.transaction_status = 0
            with self.subTest(case=case), self.assertRaises(ValueError):
                issuance._issue_on_connection(connection=recorder, work=work, **supplied)
            self.assertEqual(recorder.statements, [])
            self.assertEqual(recorder.events, [])

    def test_exact_prior_spent_and_minus_one_limits_use_the_original_whole_ledger(self):
        fixture, pins = capability_oracle.CapabilityFixture(), issuer_pins()
        expected = independent_issuance_work(fixture, pins)
        prior = (1, 17, 3)
        for prefix in ((0, 0, 0), prior):
            admitted = oracle.add(prefix, expected["admission"])
            work, recorder = self.work(admitted), Recorder(fixture, pins)
            work.charge(hashes=prefix[0], input_bytes=prefix[1], json_nodes=prefix[2])
            original = work.limits
            self.assertEqual(self.issue(fixture, recorder, work), expected_receipt(fixture))
            self.assertIs(work.limits, original)
            self.assertEqual(oracle.units(work.metrics), oracle.add(prefix, expected["total"]))
            for axis in range(3):
                limits = list(admitted)
                limits[axis] -= 1
                work, recorder = self.work(tuple(limits)), Recorder(fixture, pins)
                work.charge(hashes=prefix[0], input_bytes=prefix[1], json_nodes=prefix[2])
                original = work.limits
                before = recorder.snapshot()
                with self.subTest(prior=prefix, axis=axis), self.assertRaises(ValueError):
                    self.issue(fixture, recorder, work)
                self.assertIs(work.limits, original)
                self.assertEqual(recorder.snapshot(), before)
                self.assert_no_custody(recorder)
                self.assertTrue(all(spent <= limit for spent, limit in zip(oracle.units(work.metrics), limits)))

    def test_repeated_issuance_replays_again_on_remaining_allowance_without_a_new_meter(self):
        fixture, pins = capability_oracle.CapabilityFixture(), issuer_pins()
        first = independent_issuance_work(fixture, pins)
        second = independent_issuance_work(fixture, pins, issued=True)
        limits = tuple(max(a, b) for a, b in zip(first["admission"], oracle.add(first["total"], second["admission"])))
        work, recorder = self.work(limits), Recorder(fixture, pins)
        original = work.limits
        with patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
            one = self.issue(fixture, recorder, work)
            two = self.issue(fixture, recorder, work)
        self.assertEqual((one, two), (expected_receipt(fixture), expected_receipt(fixture)))
        self.assertEqual(replay.call_count, 2)
        self.assertEqual(oracle.units(work.metrics), oracle.add(first["total"], second["total"]))
        self.assertIs(work.limits, original)
        self.assertEqual((recorder.loads, recorder.stores, recorder.releases), (4, 2, 2))
        saved = recorder.snapshot()
        with self.assertRaises(ValueError):
            self.issue(fixture, recorder, work)
        self.assertEqual(recorder.snapshot(), saved)
        self.assertIs(work.limits, original)


if __name__ == "__main__":
    unittest.main()
