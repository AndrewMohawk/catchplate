#!/usr/bin/env python3
"""Real retained replay before private execution reservation over a SQL recorder.

The independent fixture supplies genuine signatures, complete proofs and kernel
effects. The recorder models returned rows and savepoint rollback, not native
PostgreSQL, locks, ACLs, current roots, capability admission or execution.
"""
from __future__ import annotations

import copy
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_contract
from serverware import authority_query_read_work as accounting
from serverware import authority_revocation_retention as retention
from serverware.authority_store import planner_connection as admission
from serverware.authority_store import revocation_execution as reservation
from serverware.authority_store import revocation_retention as store
import test_authority_revocation_persistence as persistence_oracle
import test_authority_revocation_plan as oracle
import test_authority_revocation_wire as wire_oracle


TABLE = "serverware_metadata.policy_authority_execution_envelopes"
RESERVATION_FIELDS = (
    "envelope_id", "parent_envelope_id", "purpose", "operation", "operation_id",
    "request_digest", "capability_id", "planner_transaction_id", "authorization_projection_digest",
    "operation_contract_digest", "exact_request_base64url", "exact_request_bytes_digest",
    "exact_request_byte_count", "deadline_monotonic_ns", "deadline_epoch_ns", "fence", "status",
    "reserved_at_epoch_ns", "source_revision",
)
TERMINAL_FIELDS = (
    "exact_response_base64url", "exact_response_bytes_digest", "exact_response_byte_count",
    "result_digest", "terminal_receipt_json", "terminal_receipt_digest", "failure_code",
    "failure_digest", "terminal_at_epoch_ns",
)
FIELDS = (*RESERVATION_FIELDS, *TERMINAL_FIELDS)


@dataclass(frozen=True, slots=True)
class _RequestCeiling:
    MAX_REQUEST_BYTES: int


def expected_request(fixture):
    parent, _ = persistence_oracle.expected_rows(fixture, fixture.now_epoch_ns)
    return {"schema": "serverware.policyAuthorityRevocationExecutionRequest/v1",
        "planProtocol": "revocation-v4", "retainedRecordDigest": parent["retained_record_digest"],
        "rootTransitionDigest": fixture.payload["measuredPlan"]["rootTransitionDigest"],
        "typedRequest": copy.deepcopy(fixture.semantic.request)}


def expected_envelope(fixture, envelope_id):
    """Literal existing SQL row, independent of the new reservation producer."""
    measured, raw = fixture.payload["measuredPlan"], oracle.wire(expected_request(fixture))
    return {"envelope_id": envelope_id, "parent_envelope_id": fixture.planner_transaction_id,
        "purpose": "execute-v9", "operation": "webauthn.credential.revoke",
        "operation_id": measured["operationId"], "request_digest": measured["requestDigest"],
        "capability_id": measured["capabilityId"], "planner_transaction_id": fixture.planner_transaction_id,
        "authorization_projection_digest": measured["authorizationProjectionDigest"],
        "operation_contract_digest": authority_contract.OPERATION_MANIFEST_DIGEST,
        "exact_request_base64url": oracle.encoded(raw), "exact_request_bytes_digest": oracle.sha(raw),
        "exact_request_byte_count": len(raw), "deadline_monotonic_ns": fixture.deadline_monotonic_ns,
        "deadline_epoch_ns": fixture.deadline_epoch_ns, "fence": fixture.fence, "status": "reserved",
        "reserved_at_epoch_ns": fixture.reserved_at_epoch_ns, "source_revision": authority_contract.SOURCE_REVISION,
        **{name: None for name in TERMINAL_FIELDS}}


def independent_reservation_work(fixture, envelope_id):
    """Existing real replay oracle plus literal new capture/transport/row work."""
    replay = persistence_oracle.independent_store_metrics(fixture, fixture.now_epoch_ns, mode="read")
    external = {name: value for name, value in wire_oracle.expectations(fixture).items()
                if name not in {"planner_public_key", "verifier_public_key", "database_now"}}
    capture = oracle.graph_cost(external, 1, 1)
    request, row = expected_request(fixture), expected_envelope(fixture, envelope_id)
    raw = oracle.wire(request)
    transport = oracle.add(oracle.graph_cost(request), (1, len(raw), 0), persistence_oracle.codec_encode(raw))
    rows = oracle.add(oracle.graph_cost(row, 4, 4), persistence_oracle.scalar_comparisons(row))
    total = oracle.add(capture, replay["total"], transport, rows)
    peak = oracle.add(capture, replay["admission"])
    return {"total": total, "admission": tuple(max(a, b) for a, b in zip(peak, total)),
        "capture": capture, "replay": replay, "transport": transport, "rows": rows}


class Recorder(persistence_oracle.Recorder):
    """Five-record savepoint model, with explicit execution-row uniqueness."""
    def __init__(self):
        super().__init__()
        self.envelopes = {}
        self.missing_envelope_read = False
        self.events = []
        self.on_event = None

    def event(self, value):
        self.events.append(value)
        if self.on_event is not None:
            self.on_event(value)

    def cursor(self):
        return Cursor(self)

    def snapshot(self):
        return copy.deepcopy((self.parent, self.sidecar, self.assertions, self.projections, self.envelopes))

    @contextmanager
    def transaction(self):
        before = self.snapshot()
        try:
            self.event("savepoint.enter")
            yield self
        except BaseException:
            self.parent, self.sidecar, self.assertions, self.projections, self.envelopes = before
            self.rollbacks += 1
            self.event("savepoint.rollback")
            raise
        else:
            self.releases += 1
            self.event("savepoint.release")


class Cursor(persistence_oracle.Cursor):
    def execute(self, sql, parameters=()):
        r = self.recorder
        if not (sql.startswith("INSERT INTO " + TABLE) or " FROM " + TABLE in sql):
            return super().execute(sql, parameters)
        r.statements.append((sql, parameters))
        if r.callback is not None:
            r.callback(sql, parameters)
        self.result, self.rowcount = None, -1
        if sql.startswith("INSERT INTO " + TABLE):
            expected = ("INSERT INTO " + TABLE + " (" + ", ".join(RESERVATION_FIELDS)
                + ") VALUES (" + ", ".join(("%s",) * len(RESERVATION_FIELDS))
                + ") ON CONFLICT (envelope_id) DO NOTHING")
            if sql != expected or len(parameters) != len(RESERVATION_FIELDS):
                raise AssertionError("execution INSERT escaped its exact column/parameter closure")
            row = {**dict(zip(RESERVATION_FIELDS, parameters)), **{name: None for name in TERMINAL_FIELDS}}
            for identity, old in r.envelopes.items():
                if identity != row["envelope_id"] and (old["capability_id"] == row["capability_id"]
                        or old["planner_transaction_id"] == row["planner_transaction_id"]
                        or all(old[name] == row[name] for name in ("purpose", "request_digest", "fence"))):
                    raise persistence_oracle.StoreError("synthetic execution uniqueness conflict")
            r.envelopes.setdefault(row["envelope_id"], row)
            self.rowcount = 0
        else:
            expected = ("SELECT " + ", ".join(FIELDS) + " FROM " + TABLE
                + " WHERE envelope_id = %s FOR UPDATE")
            if sql != expected or len(parameters) != 1:
                raise AssertionError("execution read is not the closed locked row")
            row = None if r.missing_envelope_read else r.envelopes.get(parameters[0])
            self.result = row if r.return_aliases or row is None else row.copy()
        return self


class RevocationReservationTests(unittest.TestCase):
    def setUp(self):
        self.old_namespace = admission._DB_GLOBALS
        admission.bind_db_globals({"PostgresMetadataConnection": persistence_oracle.Facade,
            "MetadataStoreError": persistence_oracle.StoreError,
            "_METADATA_STORE_AUTHORITY_PLANNER_WRITER_ROLE": "fixture-planner-writer",
            "_POLICY_AUTHORITY_VERIFIER_RESPONSE_MAX_AGE_NS": 300_000_000_000,
            "_POLICY_AUTHORITY_VERIFIER_MAX_CLOCK_SKEW_NS": 1_000_000_000})

    def tearDown(self):
        admission._DB_GLOBALS = self.old_namespace

    def fixture(self):
        fixture = oracle.PlanFixture(approval=False, include_audit=False)
        recorder = Recorder()
        recorder.seed(fixture, fixture.now_epoch_ns)
        return fixture, recorder

    def work(self, limits=None):
        return accounting._ValidationWork(accounting.QueryReadValidationLimits(*(limits or ())))

    def reserve(self, fixture, recorder, work=None, *, epoch=None, monotonic=None,
                epoch_sequence=None, **changes):
        supplied = {"envelope_id": oracle.sha(b"private revocation execution envelope"),
            "planner_transaction_id": fixture.planner_transaction_id,
            "connection": persistence_oracle.Facade(recorder),
            "work": self.work() if work is None else work, **wire_oracle.expectations(fixture)}
        supplied.update(changes)
        with patch.object(admission.time, "time_ns", return_value=(fixture.now_epoch_ns if epoch is None else epoch),
                side_effect=epoch_sequence), patch.object(admission.time, "monotonic_ns",
                return_value=(fixture.now_monotonic_ns if monotonic is None else monotonic)):
            return reservation.reserve_revocation_execution_envelope(**supplied)

    def test_real_replay_precedes_exact_five_field_request_and_locked_reservation(self):
        fixture, recorder = self.fixture()
        before = recorder.snapshot()
        envelope_id = oracle.sha(b"private revocation execution envelope")
        expected = expected_envelope(fixture, envelope_id)
        metrics = independent_reservation_work(fixture, envelope_id)
        work = self.work(metrics["admission"])
        with patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as verify, \
                patch.object(retention.plan.mixed, "_verify", wraps=retention.plan.mixed._verify) as proof:
            actual = self.reserve(fixture, recorder, work)
        self.assertEqual((verify.call_count, proof.call_count), (1, 1))
        self.assertIs(verify.call_args.kwargs["work"], work)
        self.assertEqual(actual, expected)
        self.assertEqual(recorder.envelopes, {envelope_id: expected})
        self.assertEqual(recorder.snapshot()[:4], before[:4])
        self.assertEqual((len(expected_request(fixture)), len(expected), len(TERMINAL_FIELDS)), (5, 28, 9))
        self.assertEqual(set(expected_request(fixture)), {"schema", "planProtocol", "retainedRecordDigest",
            "rootTransitionDigest", "typedRequest"})
        statements = [sql for sql, _ in recorder.statements]
        insert = next(i for i, sql in enumerate(statements) if sql.startswith("INSERT INTO " + TABLE))
        for table in (persistence_oracle.PARENT, persistence_oracle.SIDECAR,
                      persistence_oracle.ASSERTION, persistence_oracle.PROJECTION):
            self.assertLess(next(i for i, sql in enumerate(statements) if " FROM " + table in sql), insert)
        self.assertFalse(any(sql.startswith(("UPDATE ", "DELETE ")) for sql in statements))
        self.assertEqual(sum(sql.startswith("INSERT ") for sql in statements), 1)
        self.assertEqual(recorder.events, ["savepoint.enter", "savepoint.release"])
        self.assertEqual((recorder.rollbacks, recorder.releases), (0, 1))
        self.assertEqual(oracle.units(work.metrics), metrics["total"])
        # Lower, never enlarge, only this module's wrapper ceiling lookup.
        # Historical custody materializers separately use MAX_REQUEST_BYTES
        # and retain their original source module and source allowance.
        size = len(oracle.wire(expected_request(fixture)))
        self.assertLess(size, 4 * 1024 * 1024)
        self.assertLess(len(oracle.wire(fixture.semantic.request)), size - 1)
        make_expected = reservation._expected_reservation
        for maximum in (size, size - 1):
            bounded = Recorder()
            bounded.seed(fixture, fixture.now_epoch_ns)
            before = bounded.snapshot()

            with self.subTest(wrapper_limit=maximum), \
                    patch.object(reservation, "authority", _RequestCeiling(maximum)), \
                    patch.object(reservation, "_expected_reservation", wraps=make_expected) as rendered, \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as verified, \
                    patch.object(retention.plan.mixed, "_verify", wraps=retention.plan.mixed._verify) as proof:
                if maximum == size:
                    self.assertEqual(self.reserve(fixture, bounded), expected)
                else:
                    with self.assertRaisesRegex(ValueError, "wire or node ceiling"):
                        self.reserve(fixture, bounded)
                    self.assertEqual(bounded.snapshot(), before)
                    self.assertFalse(any(sql.startswith("INSERT ") for sql, _ in bounded.statements))
            self.assertEqual(verified.call_count, 1)
            self.assertEqual(rendered.call_count, 1)
            self.assertEqual(proof.call_count, 1)

    def test_identical_reserved_retry_replays_original_evidence_without_replacement(self):
        fixture, recorder = self.fixture()
        envelope_id = oracle.sha(b"private revocation execution envelope")
        expected = expected_envelope(fixture, envelope_id)
        recorder.envelopes[envelope_id] = copy.deepcopy(expected)
        before = recorder.snapshot()
        work = self.work()
        with patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as verify:
            actual = self.reserve(fixture, recorder, work)
        self.assertEqual(verify.call_count, 1)
        self.assertEqual(actual, expected)
        self.assertEqual(recorder.snapshot(), before)
        self.assertEqual((recorder.rollbacks, recorder.releases), (0, 1))
        recorder.statements.clear()
        with self.assertRaisesRegex(ValueError, "stale or inconsistent"):
            self.reserve(fixture, recorder, epoch=fixture.deadline_epoch_ns)
        self.assertEqual(recorder.snapshot(), before)
        self.assertFalse(any(sql.startswith("INSERT ") for sql, _ in recorder.statements))
        self.assertEqual((recorder.rollbacks, recorder.releases), (1, 1))

    def test_independent_exact_preconsumed_and_each_minus_one_use_original_work(self):
        fixture, _ = self.fixture()
        identity, prior = oracle.sha(b"private revocation execution envelope"), (3, 37, 5)
        expected = independent_reservation_work(fixture, identity)
        for existing in (False, True):
            for dimension in (None, 0, 1, 2):
                recorder = Recorder()
                recorder.seed(fixture, fixture.now_epoch_ns)
                if existing:
                    recorder.envelopes[identity] = expected_envelope(fixture, identity)
                before = recorder.snapshot()
                limits = list(oracle.add(prior, expected["admission"]))
                if dimension is not None:
                    limits[dimension] -= 1
                work = self.work(limits)
                work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
                entering = work.limits
                with self.subTest(existing=existing, dimension=dimension), \
                        patch.object(retention.plan.retained._PackagingLedger, "__init__",
                            side_effect=AssertionError("new outer work allowance")):
                    if dimension is None:
                        self.assertEqual(self.reserve(fixture, recorder, work), expected_envelope(fixture, identity))
                        self.assertEqual(oracle.units(work.metrics), oracle.add(prior, expected["total"]))
                    else:
                        with self.assertRaises(ValueError):
                            self.reserve(fixture, recorder, work)
                        self.assertEqual(recorder.snapshot(), before)
                        self.assertTrue(all(start <= used <= maximum for start, used, maximum
                            in zip(prior, oracle.units(work.metrics), limits)))
                self.assertIs(work.limits, entering)
                self.assertFalse(hasattr(work, "_revocation_packaging_owner"))

    def test_two_real_reservations_accumulate_work_and_replay_twice_without_cached_success(self):
        fixture, recorder = self.fixture()
        identity, prior = oracle.sha(b"private revocation execution envelope"), (2, 23, 7)
        expected = independent_reservation_work(fixture, identity)
        limits = oracle.add(prior, expected["total"], expected["admission"])
        work = self.work(limits)
        work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
        entering = work.limits
        with patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as verify, \
                patch.object(retention.plan.mixed, "_verify", wraps=retention.plan.mixed._verify) as proof:
            first = self.reserve(fixture, recorder, work)
            second = self.reserve(fixture, recorder, work)
        self.assertEqual(first, second)
        self.assertEqual((verify.call_count, proof.call_count), (2, 2))
        self.assertTrue(all(call.kwargs["work"] is work for call in verify.call_args_list))
        self.assertEqual(oracle.units(work.metrics), oracle.add(prior, expected["total"], expected["total"]))
        self.assertIs(work.limits, entering)
        self.assertEqual((recorder.rollbacks, recorder.releases), (0, 2))

    def test_every_reservation_scalar_and_terminal_null_is_compared_on_retry(self):
        fixture, _ = self.fixture()
        envelope_id = oracle.sha(b"private revocation execution envelope")
        original = expected_envelope(fixture, envelope_id)
        cases = [(name, value + 1 if type(value) is int else "different" if value is not None else "unexpected")
                 for name, value in original.items()]
        cases += [(name, True) for name in ("exact_request_byte_count", "fence", "reserved_at_epoch_ns")]
        cases += [("fence", float(original["fence"])), ("extra", None)]
        for name, value in cases:
            recorder = Recorder()
            recorder.seed(fixture, fixture.now_epoch_ns)
            recorder.envelopes[envelope_id] = {**original, name: value}
            before = recorder.snapshot()
            with self.subTest(field=name, value_type=type(value).__name__), self.assertRaises(persistence_oracle.StoreError):
                self.reserve(fixture, recorder)
            self.assertEqual(recorder.snapshot(), before)
            self.assertEqual((recorder.rollbacks, recorder.releases), (1, 0))

    def test_consumed_parent_and_terminal_envelope_never_become_reserved_retries(self):
        fixture, _ = self.fixture()
        for target, state in (("parent", "consumed"), ("parent", "failed"),
                              ("envelope", "committed"), ("envelope", "failed")):
            recorder = Recorder()
            recorder.seed(fixture, fixture.now_epoch_ns)
            if target == "parent":
                recorder.parent["status"] = state
            else:
                identity = oracle.sha(b"private revocation execution envelope")
                response = oracle.wire({"status": state})
                terminal = {**expected_envelope(fixture, identity), "status": state,
                    "exact_response_base64url": oracle.encoded(response),
                    "exact_response_bytes_digest": oracle.sha(response),
                    "exact_response_byte_count": len(response), "terminal_at_epoch_ns": fixture.now_epoch_ns}
                if state == "committed":
                    receipt = oracle.wire({"status": "committed", "envelopeId": identity})
                    terminal.update(result_digest=fixture.payload["expectedResultDigest"],
                        terminal_receipt_json=receipt.decode("ascii"), terminal_receipt_digest=oracle.sha(receipt))
                else:
                    terminal.update(failure_code="fixture-failure", failure_digest=oracle.framed(
                        "serverware.policyAuthorityExecutionFailure/v1", b"fixture-failure"))
                # Real table status/nullability shapes, not a claim that this
                # synthetic terminal response passed an execution consumer.
                recorder.envelopes[identity] = terminal
            before = recorder.snapshot()
            with self.subTest(target=target, state=state), self.assertRaises(persistence_oracle.StoreError):
                self.reserve(fixture, recorder)
            self.assertEqual(recorder.snapshot(), before)
            self.assertEqual(recorder.rollbacks, 1)

    def test_genuine_signature_or_semantic_failure_cannot_insert_execution_envelope(self):
        for failure in ("signature", "result"):
            fixture, recorder = self.fixture()
            if failure == "signature":
                fixture.resign(key=fixture.other_key)
            else:
                fixture.payload["expectedResult"] = {"false": True}
                fixture.rehash()
            recorder.seed(fixture, fixture.now_epoch_ns)
            before = recorder.snapshot()
            with self.subTest(failure=failure), \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as verify, \
                    self.assertRaises(retention.RevocationRetentionError):
                self.reserve(fixture, recorder)
            self.assertEqual(verify.call_count, 1)
            self.assertEqual(recorder.snapshot(), before)
            self.assertFalse(any(sql.startswith("INSERT ") for sql, _ in recorder.statements))
            self.assertEqual(recorder.rollbacks, 1)

    def test_missing_wrong_protocol_or_incomplete_custody_is_denial_not_not_found(self):
        fixture, _ = self.fixture()
        for failure in ("absent", "v3", "reserved", "sidecar", "assertion", "projection"):
            recorder = Recorder()
            recorder.seed(fixture, fixture.now_epoch_ns)
            if failure == "absent":
                recorder.parent = None
            elif failure == "v3":
                recorder.parent["plan_protocol"] = "v3"
            elif failure == "reserved":
                recorder.parent["status"] = "reserved"
            elif failure == "sidecar":
                recorder.sidecar = None
            elif failure == "assertion":
                recorder.assertions.clear()
            else:
                recorder.projections.clear()
            before = recorder.snapshot()
            with self.subTest(failure=failure), self.assertRaises(persistence_oracle.StoreError):
                self.reserve(fixture, recorder)
            self.assertEqual(recorder.snapshot(), before)
            self.assertFalse(any(sql.startswith("INSERT ") for sql, _ in recorder.statements))

    def test_current_deadline_checks_precede_insert_and_late_expiry_rolls_it_back(self):
        fixture, _ = self.fixture()
        cases = (
            {"epoch": fixture.deadline_epoch_ns},
            {"monotonic": fixture.deadline_monotonic_ns},
            {"epoch": fixture.now_epoch_ns + 2 * fixture.maximum_clock_skew_ns},
            {"epoch_sequence": (fixture.now_epoch_ns, fixture.deadline_epoch_ns)},
        )
        for index, clocks in enumerate(cases):
            recorder = Recorder()
            recorder.seed(fixture, fixture.now_epoch_ns)
            before = recorder.snapshot()
            with self.subTest(index=index), self.assertRaisesRegex(ValueError, "stale or inconsistent"):
                self.reserve(fixture, recorder, **clocks)
            self.assertEqual(recorder.snapshot(), before)
            self.assertEqual((recorder.rollbacks, recorder.releases), (1, 0))
            self.assertEqual(any(sql.startswith("INSERT INTO " + TABLE) for sql, _ in recorder.statements), index == 3)

    def test_external_graphs_and_borrowed_replay_rows_are_owned_before_later_callbacks(self):
        fixture, recorder = self.fixture()
        recorder.return_aliases = True
        external = wire_oracle.expectations(fixture)
        expected = expected_envelope(fixture, oracle.sha(b"private revocation execution envelope"))

        def callback(sql, parameters):
            if sql == "SHOW transaction_isolation":
                external["expected_request"]["arguments"].clear()
                external["expected_before"]["indexBeforeHeads"].clear()
            elif " FROM " + persistence_oracle.SIDECAR in sql:
                recorder.parent["selected_business_rows_json"] = "[]"
            elif " FROM " + persistence_oracle.PROJECTION in sql:
                next(iter(recorder.assertions.values()))["evidence_json"] = "{}"

        recorder.callback = callback
        result = self.reserve(fixture, recorder, **external)
        self.assertEqual(result, expected)
        self.assertEqual(external["expected_request"]["arguments"], {})
        self.assertEqual(recorder.parent["selected_business_rows_json"], "[]")
        self.assertEqual(next(iter(recorder.assertions.values()))["evidence_json"], "{}")
        borrowed = Recorder()
        borrowed.seed(fixture, fixture.now_epoch_ns)
        borrowed.return_aliases = True
        clocks = []

        def final_clock():
            clocks.append(fixture.now_epoch_ns)
            if len(clocks) == 2:
                # The execution row has already been copied and compared;
                # driver-owned alias changes cannot change the returned row.
                next(iter(borrowed.envelopes.values()))["fence"] += 100
            return fixture.now_epoch_ns

        actual = self.reserve(fixture, borrowed, epoch_sequence=final_clock)
        self.assertEqual(len(clocks), 2)
        self.assertEqual(actual, expected)
        self.assertEqual(next(iter(borrowed.envelopes.values()))["fence"], fixture.fence + 100)

    def test_driver_meter_mutation_denies_and_rolls_back_without_counter_refunds(self):
        fixture, _ = self.fixture()
        for corruption in ("spend", "refund", "float", "limits"):
            recorder, work = Recorder(), self.work()
            recorder.seed(fixture, fixture.now_epoch_ns)
            before = recorder.snapshot()
            observed = []

            def callback(sql, parameters):
                if not sql.startswith("INSERT INTO " + TABLE):
                    return
                observed.append(oracle.units(work.metrics))
                if corruption == "spend":
                    work.charge(json_nodes=1)
                elif corruption == "refund":
                    work.input_bytes -= 1
                elif corruption == "float":
                    work.json_nodes = float(work.json_nodes)
                else:
                    object.__setattr__(work.limits, "max_input_bytes", work.limits.max_input_bytes + 1)

            recorder.callback = callback
            with self.subTest(corruption=corruption), self.assertRaises(ValueError):
                self.reserve(fixture, recorder, work)
            self.assertEqual(len(observed), 1)
            self.assertEqual(recorder.snapshot(), before)
            self.assertEqual(recorder.rollbacks, 1)
            self.assertEqual(work.hash_work, observed[0][0])
            self.assertGreater(work.input_bytes, 0)
            if corruption == "refund":
                self.assertEqual(work.input_bytes, observed[0][1] - 1)
            elif corruption == "float":
                self.assertIs(type(work.json_nodes), float)

    def test_savepoint_entry_cannot_substitute_a_different_real_replay_connection(self):
        fixture, recorder = self.fixture()
        other = Recorder()
        other.seed(fixture, fixture.now_epoch_ns)
        original, foreign = recorder.snapshot(), other.snapshot()
        facade = persistence_oracle.Facade(recorder)

        def entered(event):
            if event == "savepoint.enter":
                facade.raw_connection = other

        recorder.on_event = entered
        with self.assertRaisesRegex(persistence_oracle.StoreError, "connection differs"):
            self.reserve(fixture, recorder, connection=facade)
        self.assertEqual(recorder.snapshot(), original)
        self.assertEqual(other.snapshot(), foreign)
        self.assertEqual((recorder.rollbacks, recorder.releases, other.rollbacks, other.releases), (1, 0, 0, 0))
        for connection in (recorder, other):
            self.assertFalse(any(" FROM " + persistence_oracle.PARENT in sql or sql.startswith("INSERT ")
                                 for sql, _ in connection.statements))

    def test_real_signature_and_late_sql_callbacks_cannot_change_active_connection_custody(self):
        fixture, _ = self.fixture()
        for phase in ("planner_signature", "receipt_signature", "envelope_read", "inactive"):
            recorder, other = Recorder(), Recorder()
            recorder.seed(fixture, fixture.now_epoch_ns)
            other.seed(fixture, fixture.now_epoch_ns)
            original, foreign = recorder.snapshot(), other.snapshot()
            facade = persistence_oracle.Facade(recorder)
            changed = []

            def replace():
                changed.append(phase)
                if phase == "inactive":
                    facade.in_transaction = False
                else:
                    facade.raw_connection = other

            changes = {}
            if phase in ("planner_signature", "receipt_signature"):
                key = fixture.key.public_key() if phase == "planner_signature" else fixture.semantic.receipt.key.public_key()
                changes["planner_public_key" if phase == "planner_signature" else "verifier_public_key"] = \
                    oracle._CallbackPublicKey(key, replace)
            else:
                def callback(sql, parameters):
                    if " FROM " + TABLE in sql:
                        replace()
                recorder.callback = callback
            with self.subTest(phase=phase), self.assertRaises(persistence_oracle.StoreError):
                self.reserve(fixture, recorder, connection=facade, **changes)
            self.assertEqual(changed, [phase])
            self.assertEqual(recorder.snapshot(), original)
            self.assertEqual(other.snapshot(), foreign)
            self.assertEqual(recorder.rollbacks, 1)
            self.assertEqual(other.statements, [])
            inserted = any(sql.startswith("INSERT INTO " + TABLE) for sql, _ in recorder.statements)
            self.assertEqual(inserted, phase in ("envelope_read", "inactive"))

    def test_missing_reread_and_other_unique_identity_conflicts_preserve_all_prior_rows(self):
        fixture, _ = self.fixture()
        for failure in ("missing", "unique"):
            recorder = Recorder()
            recorder.seed(fixture, fixture.now_epoch_ns)
            if failure == "missing":
                recorder.missing_envelope_read = True
            else:
                other = oracle.sha(b"previous execution envelope")
                recorder.envelopes[other] = expected_envelope(fixture, other)
            before = recorder.snapshot()
            with self.subTest(failure=failure), self.assertRaises(persistence_oracle.StoreError):
                self.reserve(fixture, recorder)
            self.assertEqual(recorder.snapshot(), before)
            self.assertEqual(recorder.rollbacks, 1)

    def test_closed_api_identity_work_and_transaction_guards_precede_reservation_dml(self):
        fixture, _ = self.fixture()
        changes = (
            {"envelope_id": "bad"}, {"envelope_id": True}, {"planner_transaction_id": "bad"},
            {"planner_transaction_id": oracle.sha(b"other planner transaction")},
            {"work": None}, {"work": object()}, {"connection": object()},
            {"verified_record": object()}, {"parent_envelope_id": fixture.planner_transaction_id},
            {"_expected_raw": object()},
        )
        for change in changes:
            recorder = Recorder()
            recorder.seed(fixture, fixture.now_epoch_ns)
            before = recorder.snapshot()
            with self.subTest(fields=tuple(change)), self.assertRaises((TypeError, ValueError)):
                # Call directly so None is the supplied invalid meter, not the
                # convenience helper's request for an ordinary fresh test work.
                reservation.reserve_revocation_execution_envelope(**{
                    "envelope_id": oracle.sha(b"private revocation execution envelope"),
                    "planner_transaction_id": fixture.planner_transaction_id,
                    "connection": persistence_oracle.Facade(recorder), "work": self.work(),
                    **wire_oracle.expectations(fixture), **change})
            self.assertEqual(recorder.snapshot(), before)
            self.assertFalse(any(sql.startswith("INSERT ") for sql, _ in recorder.statements))
        recorder = Recorder()
        recorder.seed(fixture, fixture.now_epoch_ns)
        with self.assertRaisesRegex(ValueError, "expectations are not closed"):
            store.read_revocation_planner_record(planner_transaction_id=fixture.planner_transaction_id,
                connection=persistence_oracle.Facade(recorder), work=self.work(),
                _expected_raw=recorder, **wire_oracle.expectations(fixture))
        self.assertEqual(recorder.statements, [])
        for field, value in (("isolation", "read committed"), ("role", "wrong-role"),
                             ("read_only", "on"), ("deferrable", "on"), ("in_transaction", False)):
            recorder = Recorder()
            recorder.seed(fixture, fixture.now_epoch_ns)
            facade = persistence_oracle.Facade(recorder)
            setattr(facade if field == "in_transaction" else recorder, field, value)
            with self.subTest(field=field), self.assertRaises(persistence_oracle.StoreError):
                self.reserve(fixture, recorder, connection=facade)
            self.assertFalse(any(sql.startswith("INSERT ") for sql, _ in recorder.statements))


if __name__ == "__main__":
    unittest.main()
