#!/usr/bin/env python3
"""Real signed ACK helpers over a seven-set SQL lifecycle recorder.

Independent wire/row construction is ordinary fixture data, not authenticated
replay or database admission. Startup separately runs both real replays and
the genuine db/registry gate. These authored fixtures have not been executed.
The recorder observes SQL/rollback, not live PostgreSQL commit or TLS evidence.
"""
from __future__ import annotations

import copy
from contextlib import contextmanager
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate import authority_query_read_work as accounting
from catchplate import authority_revocation_writer_acknowledgment as acknowledgment
from catchplate.authority_store import planner_connection as admission
from catchplate.authority_store import revocation_writer_acknowledgment as ack_store
import test_authority_revocation_plan as oracle
import test_authority_revocation_persistence as persistence_oracle
import test_authority_revocation_reservation as reservation_oracle
import test_authority_revocation_writer_acknowledgment as ack_oracle
import test_authority_revocation_writer_composition as composition_oracle
import test_authority_revocation_writer_request as request_oracle


SCHEMA = "catchplate.policyAuthorityRevocationWriterAcknowledgment/v1"
ID_DOMAIN = "catchplate.policyAuthorityRevocationWriterAcknowledgmentIdentity/v1"
TABLE = "catchplate_metadata.policy_authority_revocation_writer_acknowledgments"
FIELDS = ("ack_envelope_id", "intent_envelope_id", "configuration_digest", "generation_sequence",
    "generation_digest", "writer_response_spki_digest", "exact_ack_base64url",
    "exact_ack_bytes_digest", "exact_ack_byte_count", "source_revision")
SELECT = "SELECT " + ", ".join(FIELDS) + " FROM " + TABLE + " WHERE intent_envelope_id = %s"
INSERT = ("INSERT INTO " + TABLE + " (" + ", ".join(FIELDS) + ") VALUES ("
    + ", ".join(("%s",) * len(FIELDS)) + ") ON CONFLICT (intent_envelope_id) DO NOTHING")


def request_fields(fixture):
    return {name: value for name, value in request_oracle.expected_row(fixture).items()
        if name not in {"exact_intent_base64url", "exact_relay_base64url", "historical_expectations_base64url"}}


def expected_bytes(fixture):
    request = request_fields(fixture)
    unsigned = {"schema": SCHEMA,
        "acknowledgmentId": oracle.framed(ID_DOMAIN, request["intent_envelope_id"].encode("ascii")),
        "purpose": "acknowledge-revocation-writer-custody", "custodyState": "retained-and-reserved",
        "writerResponseSpkiDigest": fixture.writer_spki_digest, "request": request}
    message = oracle.framed(SCHEMA, oracle.wire(unsigned)).encode("ascii")
    return oracle.wire({**unsigned, "signatureBase64Url": oracle.encoded(fixture.writer_key.sign(message))})


def expected_row(fixture):
    request, raw = request_fields(fixture), expected_bytes(fixture)
    return {"ack_envelope_id": oracle.framed(ID_DOMAIN, request["intent_envelope_id"].encode("ascii")),
        "intent_envelope_id": request["intent_envelope_id"],
        "configuration_digest": request["configuration_digest"],
        "generation_sequence": request["generation_sequence"], "generation_digest": request["generation_digest"],
        "writer_response_spki_digest": fixture.writer_spki_digest,
        "exact_ack_base64url": oracle.encoded(raw), "exact_ack_bytes_digest": oracle.sha(raw),
        "exact_ack_byte_count": len(raw), "source_revision": request["source_revision"]}


def independent_ack_storage_work(fixture, *, existing=False):
    row, raw, add = expected_row(fixture), expected_bytes(fixture), oracle.add
    prefix = {name: value for name, value in row.items()
        if name not in {"exact_ack_base64url", "exact_ack_bytes_digest", "exact_ack_byte_count"}}
    identity = add(oracle.utf8_cost(row["intent_envelope_id"]),
        oracle.frame_cost(ID_DOMAIN, (row["intent_envelope_id"].encode("ascii"),)))
    crypto = ack_oracle.independent_ack_work(request_fields(fixture), fixture.writer_spki_digest, raw)
    readback = add(oracle.graph_cost(row), persistence_oracle.scalar_comparisons(prefix),
        persistence_oracle.codec_decode(raw), (1, len(raw), 0),
        persistence_oracle.scalar_comparisons({"exact_ack_bytes_digest": row["exact_ack_bytes_digest"]}),
        crypto["verify"]["total"])
    create = (0, 0, 0) if existing else add(crypto["sign"]["total"], persistence_oracle.codec_encode(raw),
        (1, len(raw), 0), oracle.graph_cost(row))
    final = (0, 0, 0) if existing else persistence_oracle.scalar_comparisons(row)
    total = add(identity, create, readback, final)
    return {"identity": identity, "create": create, "readback": readback, "total": total,
        "admission": total}


class Recorder(request_oracle.Recorder):
    """Opt-in seventh set; original five/six-set fixture IDs remain intact."""
    def __init__(self):
        super().__init__()
        self.acknowledgments = {}
        self.ack_reads = 0
        self.missing_ack_readback = False

    def cursor(self):
        return Cursor(self)

    def snapshot(self):
        return copy.deepcopy((self.parent, self.sidecar, self.assertions,
            self.projections, self.envelopes, self.requests, self.acknowledgments))

    @contextmanager
    def transaction(self):
        before = self.snapshot()
        try:
            self.event("savepoint.enter")
            yield self
        except BaseException:
            (self.parent, self.sidecar, self.assertions, self.projections,
                self.envelopes, self.requests, self.acknowledgments) = before
            self.rollbacks += 1
            self.event("savepoint.rollback")
            raise
        else:
            self.releases += 1
            self.event("savepoint.release")


class Cursor(request_oracle.Cursor):
    def execute(self, sql, parameters=()):
        if not (sql.startswith("INSERT INTO " + TABLE) or " FROM " + TABLE in sql):
            return super().execute(sql, parameters)
        recorder = self.recorder
        recorder.statements.append((sql, parameters))
        if recorder.callback is not None:
            recorder.callback(sql, parameters)
        self.result, self.rowcount = None, -1
        if sql == INSERT and len(parameters) == len(FIELDS):
            row = dict(zip(FIELDS, parameters))
            parent = recorder.requests.get(row["intent_envelope_id"])
            if parent is None or any(parent[name] != row[name] for name in
                    ("intent_envelope_id", "configuration_digest", "generation_sequence", "generation_digest", "source_revision")):
                raise persistence_oracle.StoreError("synthetic ACK request-scope conflict")
            if any(old["ack_envelope_id"] == row["ack_envelope_id"] and identity != row["intent_envelope_id"]
                    for identity, old in recorder.acknowledgments.items()):
                raise persistence_oracle.StoreError("synthetic global ACK identity conflict")
            recorder.acknowledgments.setdefault(row["intent_envelope_id"], row)
            self.rowcount = 0
        elif sql == SELECT and len(parameters) == 1:
            recorder.ack_reads += 1
            row = recorder.acknowledgments.get(parameters[0])
            if recorder.missing_ack_readback and recorder.ack_reads >= 2:
                row = None
            self.result = row if recorder.return_aliases or row is None else row.copy()
        else:
            raise AssertionError("ACK custody escaped its exact SQL closure")
        return self


class RevocationWriterAckStorageTests(unittest.TestCase):
    def setUp(self):
        old = admission._DB_GLOBALS
        self.addCleanup(setattr, admission, "_DB_GLOBALS", old)
        admission.bind_db_globals({"MetadataStoreError": persistence_oracle.StoreError})

    def work(self, limits=None):
        return accounting._ValidationWork(accounting.QueryReadValidationLimits(*(limits or ())))

    def fixture(self, *, existing=False):
        fixture, recorder = composition_oracle.CompositionFixture(), Recorder()
        recorder.seed(fixture.plan, fixture.action.arguments["planned_at_epoch_ns"])
        identity = fixture.action.arguments["envelope_id"]
        recorder.envelopes[identity] = reservation_oracle.expected_envelope(fixture.plan, identity)
        request = request_oracle.expected_row(fixture)
        recorder.requests[request["intent_envelope_id"]] = request
        if existing:
            recorder.acknowledgments[request["intent_envelope_id"]] = expected_row(fixture)
        return fixture, recorder

    def persist(self, fixture, recorder, work):
        with recorder.transaction():
            return ack_store._persist(recorder.cursor(), request_oracle.expected_row(fixture),
                writer_private_key=fixture.writer_key, writer_public_key=fixture.writer_key.public_key(),
                writer_response_spki_digest=fixture.writer_spki_digest, work=work)

    def test_new_child_is_genuinely_signed_and_stored_readback_verified_then_exact_retry_never_resigns(self):
        fixture, recorder = self.fixture()
        with patch.object(acknowledgment, "_sign_on_work", wraps=acknowledgment._sign_on_work) as sign, \
                patch.object(acknowledgment, "_verify_on_work", wraps=acknowledgment._verify_on_work) as verify:
            raw = self.persist(fixture, recorder, self.work())
            self.assertEqual(raw, expected_bytes(fixture))
            self.assertEqual((sign.call_count, verify.call_count), (1, 1))
            before = recorder.snapshot()
            retry = self.persist(fixture, recorder, self.work())
        self.assertEqual((sign.call_count, verify.call_count), (1, 2))
        self.assertEqual(retry, raw)
        self.assertEqual(recorder.snapshot(), before)
        self.assertEqual([sql for sql, _ in recorder.statements], [SELECT, INSERT, SELECT, SELECT])
        self.assertEqual(recorder.acknowledgments, {expected_row(fixture)["intent_envelope_id"]: expected_row(fixture)})

    def test_every_stored_field_conflict_denies_without_overwrite_or_resigning(self):
        for name in FIELDS:
            fixture, recorder = self.fixture(existing=True)
            row = recorder.acknowledgments[expected_row(fixture)["intent_envelope_id"]]
            value = row[name]
            row[name] = value + 1 if type(value) is int else (
                oracle.sha(b"other ACK scalar") if value.startswith("sha256:") else
                ("A" if value[0] != "A" else "B") + value[1:])
            before = recorder.snapshot()
            with self.subTest(field=name), patch.object(acknowledgment, "_sign_on_work",
                    side_effect=AssertionError("existing ACK was re-signed")), self.assertRaises(ValueError):
                self.persist(fixture, recorder, self.work())
            self.assertEqual(recorder.snapshot(), before)
            self.assertFalse(any(sql == INSERT for sql, _ in recorder.statements))

    def test_corrupted_signature_with_recomputed_storage_digest_still_requires_real_crypto(self):
        import json

        fixture, recorder = self.fixture(existing=True)
        envelope = json.loads(expected_bytes(fixture))
        envelope["signatureBase64Url"] = "A" * 86
        raw = oracle.wire(envelope)
        row = recorder.acknowledgments[expected_row(fixture)["intent_envelope_id"]]
        row.update(exact_ack_base64url=oracle.encoded(raw), exact_ack_bytes_digest=oracle.sha(raw),
            exact_ack_byte_count=len(raw))
        before = recorder.snapshot()
        with patch.object(acknowledgment, "_sign_on_work", side_effect=AssertionError("retry signing")), \
                patch.object(acknowledgment, "_verify_on_work", wraps=acknowledgment._verify_on_work) as verify, \
                self.assertRaises(ValueError):
            self.persist(fixture, recorder, self.work())
        self.assertEqual(verify.call_count, 1)
        self.assertEqual(recorder.snapshot(), before)

    def test_missing_readback_and_driver_failures_roll_back_new_child_without_speculative_return(self):
        for mode in ("missing", "exception", "counter", "limits"):
            fixture, recorder = self.fixture()
            work, returned, failure = self.work(), [], RuntimeError("ACK insert driver failed")
            before = recorder.snapshot()
            if mode == "missing": recorder.missing_ack_readback = True

            def callback(sql, parameters):
                if sql != INSERT: return
                if mode == "exception": raise failure
                if mode == "counter": work.input_bytes -= 1
                if mode == "limits": work.limits = accounting.QueryReadValidationLimits()

            recorder.callback = callback
            with self.subTest(mode=mode), self.assertRaises(RuntimeError if mode == "exception" else ValueError) as raised:
                returned.append(self.persist(fixture, recorder, work))
            if mode == "exception": self.assertIs(raised.exception, failure)
            self.assertEqual(returned, [])
            self.assertEqual(recorder.snapshot(), before)
            self.assertEqual((recorder.rollbacks, recorder.releases), (1, 0))

    def test_unbounded_nonclosed_driver_rows_fail_before_copy_or_codec(self):
        for mode in ("missing", "extra", "count", "huge", "alias"):
            fixture, recorder = self.fixture(existing=True)
            identity = expected_row(fixture)["intent_envelope_id"]
            row = recorder.acknowledgments[identity]
            if mode == "missing": row.pop("exact_ack_bytes_digest")
            elif mode == "extra": row["commitAt"] = 1
            elif mode == "count": row["exact_ack_byte_count"] = True
            elif mode == "huge": row["exact_ack_base64url"] = "A" * 21847
            else: row["generation_sequence"] = float(row["generation_sequence"])
            with self.subTest(mode=mode), patch.object(accounting._ValidationWork, "prepare_copy",
                    side_effect=AssertionError("unbounded row copy")), self.assertRaises(ValueError):
                self.persist(fixture, recorder, self.work())

    def test_exact_prior_short_axes_and_repeated_calls_share_only_the_original_work(self):
        for existing in (False, True):
            for prior, axis in (((0, 0, 0), None), ((3, 17, 11), None),
                    ((3, 17, 11), 0), ((3, 17, 11), 1), ((3, 17, 11), 2)):
                fixture, recorder = self.fixture(existing=existing)
                expected = independent_ack_storage_work(fixture, existing=existing)["total"]
                limits = list(oracle.add(prior, expected))
                if axis is not None: limits[axis] -= 1
                work = self.work(limits)
                work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
                before, entering = recorder.snapshot(), work.limits
                with self.subTest(existing=existing, prior=prior, axis=axis), \
                        patch.object(accounting._ValidationWork, "__init__", side_effect=AssertionError("replacement ACK allowance")):
                    if axis is None:
                        self.assertEqual(self.persist(fixture, recorder, work), expected_bytes(fixture))
                        self.assertEqual(oracle.units(work.metrics), oracle.add(prior, expected))
                    else:
                        with self.assertRaises(ValueError): self.persist(fixture, recorder, work)
                        self.assertEqual(recorder.snapshot(), before)
                self.assertIs(work.limits, entering)
        for axis in (None, 0, 1, 2):
            fixture, recorder = self.fixture()
            new = independent_ack_storage_work(fixture)["total"]
            retry = independent_ack_storage_work(fixture, existing=True)["total"]
            limits = list(oracle.add(new, retry))
            if axis is not None: limits[axis] -= 1
            work = self.work(limits)
            self.persist(fixture, recorder, work)
            before = recorder.snapshot()
            if axis is None:
                self.persist(fixture, recorder, work)
                self.assertEqual(oracle.units(work.metrics), oracle.add(new, retry))
            else:
                with self.assertRaises(ValueError): self.persist(fixture, recorder, work)
            self.assertEqual(recorder.snapshot(), before)
            self.assertFalse(hasattr(work, "_revocation_packaging_owner"))


if __name__ == "__main__":
    unittest.main()
