#!/usr/bin/env python3
"""Native PostgreSQL/Python parity for the compact audit-capacity component.

An external approved runner must supply a disposable, owned mode-0700 Unix
socket and UTF8 database. This script starts no engine and imports no DB facade
or kernel registry. It installs the actual shared SQL in one random schema and
removes only that schema. Independent fixtures carry real source template IDs,
but are NOT complete operation plans or authenticated before-root evidence.

The function validates supplied values; it performs no business/counter DML.
These checks do not establish initial counts, delivery authority, current roots,
all-writer coverage, transaction maintenance, installed-manifest admission, or
production planner integration. Raw duplicate/numeric-token admission precedes
JSONB and remains the caller's separate obligation.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path

import psycopg
from psycopg import sql


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware.native_postgres_results import run_native_fixture

from serverware import authority_audit_capacity as capacity
from serverware import authority_contract
from serverware import authority_transition_core as core
from serverware.authority_store.audit_capacity_sql import (
    AUDIT_CAPACITY_FUNCTION_NAME,
    audit_capacity_function_sql,
)
from serverware.authority_store.wire_json_sql import wire_json_function_sql
from test_authority_root_transition_postgres import production_digest_functions
from test_webauthn_trust_projection_postgres import local_connection_parameters


CONNECTION_PARAMETERS: dict[str, str | int] | None = None
OPERATION = "policy.activation.prepare"
TABLE = "policy_authority_bounded_aggregate_states"
OUTBOX = "metadata_audit_outbox"
KIND = "metadata-audit-outbox-global-capacity-v1"
LIMIT = 100_000
MAX_INTEGER = 2**63 - 1
NOW_NS = 2_000_000_000
_DEFAULT_WORK = object()


def fixture_work(operation: str, changes: object) -> int:
    # Independent minimum accounting: one business unit, one framework query
    # for a participating operation, one counter mutation if any outbox is touched.
    if operation not in authority_contract.OPERATIONS:
        return 1
    participates = OUTBOX in authority_contract.operation_spec(operation)["businessWrites"]
    touched = isinstance(changes, (list, tuple)) and any(
        isinstance(item, dict) and item.get("table") == OUTBOX for item in changes)
    return 1 + int(participates) + int(touched)


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
                      sort_keys=True, separators=(",", ":"))


def framed(domain: str, *frames: bytes) -> str:
    # Independent byte framing, not either validator's digest helper.
    digest = hashlib.sha256(domain.encode("ascii") + b"\0")
    for frame in frames:
        digest.update(len(frame).to_bytes(8, "big"))
        digest.update(frame)
    return "sha256:" + digest.hexdigest()


PARTITION = framed("serverware.metadataAuditOutboxCapacityPartition/v1", b"global")
IDENTITY = KIND + ":" + PARTITION
EMPTY_EXPIRY = framed("serverware.policyAuthorityAggregateExpiryIndex/v1", b"[]")


def refresh_state(row: dict) -> dict:
    state = {
        "schema": "serverware.policyAuthorityAggregateState/v1",
        "aggregateId": row["aggregate_id"], "aggregateKind": row["aggregate_kind"],
        "partitionDigest": row["partition_digest"], "revision": row["revision"],
        "liveCount": row["live_count"], "activeCount": row["active_count"],
        "capacityLimit": row["capacity_limit"],
        "reservedUnits": json.loads(row["reserved_units_json"]),
        "committedUnits": json.loads(row["committed_units_json"]),
        "nextSequence": row["next_sequence"],
        "minimumExpiryEpochNs": row["minimum_expiry_epoch_ns"],
        "expiryIndexRootDigest": row["expiry_index_root_digest"],
        "workPageId": row["work_page_id"],
    }
    row["state_json"] = canonical(state)
    row["state_digest"] = framed("serverware.policyAuthorityAggregateState/v1",
                                  row["state_json"].encode("ascii"))
    return row


def counter_row(**changes: object) -> dict:
    return refresh_state({
        "aggregate_id": IDENTITY, "aggregate_kind": KIND, "partition_digest": PARTITION,
        "revision": 7, "live_count": 0, "active_count": 0, "capacity_limit": LIMIT,
        "reserved_units_json": "{}", "committed_units_json": "{}", "next_sequence": 19,
        "minimum_expiry_epoch_ns": None, "expiry_index_root_digest": EMPTY_EXPIRY,
        "work_page_id": None, "updated_at_epoch_ns": 1_000_000_000,
        "source_revision": authority_contract.SOURCE_REVISION, **changes,
    })


def outbox_row(item_id: str = "audit-one", status: object = "pending") -> dict:
    event = canonical({"event": item_id})
    return {
        "id": item_id, "event_type": "component.audit", "actor_type": "admin", "actor_id": "owner",
        "event_json": event,
        "event_digest": framed("serverware.metadataAuditOutboxEvent/v1", event.encode("ascii")),
        "storage_format_version": 2, "status": status, "claim_id": None, "claimed_at": None,
        "attempts": 0, "audited_at": None, "audit_event_hash": None, "last_error": None,
        "created_at": "1970-01-01T00:00:02+00:00",
    }


def selected(table: str, key: dict, row: dict | None) -> dict:
    return {
        "table": table, "key": copy.deepcopy(key),
        "keyDigest": framed("serverware.policyAuthorityBusinessKey/v1",
                            table.encode("ascii"), canonical(key).encode("ascii")),
        "present": row is not None, "row": copy.deepcopy(row), "contractSelector": None,
    }


def mutation(selection: dict, row: dict | None, *, operation: str = OPERATION) -> dict:
    kind = "DELETE" if row is None else "UPDATE" if selection["present"] else "INSERT"
    templates = [item for item in authority_contract.operation_spec(operation)["mutationTemplates"]
                 if item["table"] == selection["table"] and item["mutation"] == kind]
    if len(templates) != 1:
        raise AssertionError("fixture requires one actual source mutation template")
    return {
        "templateId": templates[0]["templateId"], "operation": kind,
        "table": selection["table"], "key": copy.deepcopy(selection["key"]),
        "keyDigest": selection["keyDigest"], "expectedRow": copy.deepcopy(selection["row"]),
        "row": copy.deepcopy(row),
    }


def fixture(images: list[tuple[dict | None, dict]], *, before: dict | None = None,
            timestamp: int = NOW_NS) -> tuple[list[dict], list[dict]]:
    before = counter_row() if before is None else before
    selections = [selected(TABLE, {"aggregate_id": IDENTITY}, before)]
    changes = []
    delta = inserted = 0
    for old, new in images:
        choice = selected(OUTBOX, {"id": new["id"]}, old)
        selections.append(choice)
        changes.append(mutation(choice, new))
        delta += int(new["status"] in ("pending", "claimed"))
        delta -= int(old is not None and old["status"] in ("pending", "claimed"))
        inserted += int(old is None)
    if images:
        after = refresh_state({**before, "revision": before["revision"] + 1,
            "live_count": before["live_count"] + delta,
            "active_count": before["active_count"] + delta,
            "next_sequence": before["next_sequence"] + inserted,
            "updated_at_epoch_ns": timestamp})
        changes.append(mutation(selections[0], after))
    return selections, changes


class AuthorityGlobalAuditCapacityPostgresTests(unittest.TestCase):
    @classmethod
    def connection(cls) -> psycopg.Connection:
        if CONNECTION_PARAMETERS is None:
            raise RuntimeError("this real-engine component requires --postgres-dsn")
        return psycopg.connect(**CONNECTION_PARAMETERS, autocommit=True)

    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = "serverware_audit_capacity_" + uuid.uuid4().hex
        cls.namespace = '"' + cls.schema + '"'
        with cls.connection() as connection:
            if connection.execute("SELECT inet_server_addr(), getdatabaseencoding()").fetchone() != (None, "UTF8"):
                raise RuntimeError("component fixture requires a UTF8 database over a Unix socket")
            connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(cls.schema)))
        cls.addClassCleanup(cls.drop_schema)
        with cls.connection() as connection:
            for statement in production_digest_functions(cls.namespace):
                connection.execute(statement)
            connection.execute(wire_json_function_sql(cls.namespace))
            connection.execute(audit_capacity_function_sql(cls.namespace))

    @classmethod
    def drop_schema(cls) -> None:
        with cls.connection() as connection:
            connection.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(cls.schema)))

    def sql_validate(self, selections: object, changes: object, *, operation: str = OPERATION,
                     work_units: object = _DEFAULT_WORK) -> None:
        if work_units is _DEFAULT_WORK:
            work_units = fixture_work(operation, changes)
        with self.connection() as connection:
            connection.execute(
                f"SELECT {self.namespace}.{AUDIT_CAPACITY_FUNCTION_NAME}(%s,%s::jsonb,%s::jsonb,%s)",
                (operation, canonical(selections), canonical(changes), work_units),
            ).fetchone()

    def assert_accept(self, selections: object, changes: object, *, operation: str = OPERATION,
                      work_units: object = _DEFAULT_WORK) -> None:
        if work_units is _DEFAULT_WORK:
            work_units = fixture_work(operation, changes)
        original = copy.deepcopy((selections, changes))
        self.assertIsNone(capacity.validate_capacity_transition(
            operation=operation, selected_rows=selections, mutations=changes))
        self.assertIsNone(capacity.validate_transition_work_units(operation, work_units, changes))
        self.sql_validate(selections, changes, operation=operation, work_units=work_units)
        self.assertEqual((selections, changes), original)

    def assert_reject(self, selections: object, changes: object, *, operation: str = OPERATION,
                      sql_message: str = "audit capacity|lossless integer") -> None:
        with self.assertRaises(capacity.AuditCapacityError):
            capacity.validate_capacity_transition(operation=operation, selected_rows=selections, mutations=changes)
        # A SQL type/parser error is not an accepted substitute for the guard.
        with self.assertRaisesRegex(psycopg.errors.RaiseException, sql_message):
            self.sql_validate(selections, changes, operation=operation)

    def test_installed_signature_invoker_mode_and_source_identity(self) -> None:
        self.assertEqual((capacity.AGGREGATE_ID, capacity.PARTITION_DIGEST, capacity.EMPTY_EXPIRY_DIGEST),
                         (IDENTITY, PARTITION, EMPTY_EXPIRY))
        self.assertEqual((capacity.MAX_PENDING, capacity.MAX_COUNTER_BYTES), (LIMIT, 4096))
        with self.connection() as connection:
            result = connection.execute(
                "SELECT p.provolatile,p.proisstrict,p.prosecdef,p.prorettype::regtype::text,"
                "pg_catalog.oidvectortypes(p.proargtypes),p.proconfig "
                "FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace "
                "WHERE n.nspname=%s AND p.proname=%s", (self.schema, AUDIT_CAPACITY_FUNCTION_NAME),
            ).fetchall()
            self.assertEqual(connection.execute(
                "SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n "
                "ON n.oid=c.relnamespace WHERE n.nspname=%s", (self.schema,),
            ).fetchone(), (0,))
        self.assertEqual(result, [("v", False, False, "void", "text, jsonb, jsonb, bigint",
                                  [f"search_path=pg_catalog, {self.schema}, pg_temp"])])
        # This checks the installed component, not production grants/manifest admission.

    def test_one_and_seven_inserts_match_independent_rows_and_real_producer(self) -> None:
        for count in (1, 7):
            with self.subTest(count=count):
                selections, changes = fixture([(None, outbox_row(f"audit-{index}")) for index in range(count)],
                    before=counter_row(live_count=LIMIT-count, active_count=LIMIT-count))
                self.assert_accept(selections, changes)
                self.assertEqual(changes[-1]["row"]["live_count"], LIMIT)
                self.assertEqual(changes[-1]["row"]["next_sequence"], 19 + count)
                context = core.KernelContext(operation=OPERATION, arguments={}, selected_rows=tuple(selections),
                    database_now=datetime(1970, 1, 1, 0, 0, 2, tzinfo=timezone.utc),
                    request_digest="sha256:" + "a" * 64)
                self.assertEqual(capacity.finalize_capacity(context, tuple(changes[:-1])), tuple(changes))

    def test_all_existing_status_pairs_and_same_value_updates(self) -> None:
        for old_status in ("pending", "claimed", "audited"):
            for new_status in ("pending", "claimed", "audited"):
                with self.subTest(old=old_status, new=new_status):
                    old = outbox_row(status=old_status)
                    initial = int(old_status != "audited")
                    selections, changes = fixture([(old, {**old, "status": new_status})],
                        before=counter_row(live_count=initial, active_count=initial))
                    if old_status == "audited" and new_status != "audited":
                        self.assert_reject(selections, changes, sql_message="status transition is invalid")
                    else:
                        self.assert_accept(selections, changes)
                        self.assertEqual(changes[-1]["row"]["live_count"], int(new_status != "audited"))
                        self.assertEqual(changes[-1]["row"]["next_sequence"], 19)
                        self.assertEqual(changes[-1]["row"]["revision"], 8)

    def test_mixed_net_zero_batch_still_advances_insert_sequence(self) -> None:
        old = outbox_row("delivered", "claimed")
        selections, changes = fixture([(old, {**old, "status": "audited"}), (None, outbox_row("fresh"))],
            before=counter_row(live_count=LIMIT, active_count=LIMIT))
        self.assert_accept(selections, changes)
        self.assertEqual((changes[-1]["row"]["live_count"], changes[-1]["row"]["next_sequence"]), (LIMIT, 20))

    def test_empty_replay_requires_valid_selected_counter_and_no_counter_mutation(self) -> None:
        selections, changes = fixture([], before=counter_row(live_count=LIMIT, active_count=LIMIT))
        self.assert_accept(selections, changes)
        self.assert_reject([], [], sql_message="lacks global selection")
        absent = selected(TABLE, {"aggregate_id": IDENTITY}, None)
        self.assert_reject([absent], [], sql_message="global selection is crossed or absent")
        self.assert_reject(selections, [mutation(selections[0], counter_row())],
                           sql_message="global mutation closure is incomplete")

    def test_insert_status_and_invalid_old_or_new_status_reject(self) -> None:
        for status in ("claimed", "audited", "unknown", "", None, False, 1, [], {}):
            with self.subTest(status=status):
                self.assert_reject(*fixture([(None, outbox_row(status=status))]),
                                   sql_message="status transition is invalid")
        for field in ("expectedRow", "row"):
            selections, changes = fixture([(outbox_row(), outbox_row(status="claimed"))],
                before=counter_row(live_count=1, active_count=1))
            changes[0][field]["status"] = "unrecognized"
            if field == "expectedRow":
                selections[1]["row"]["status"] = "unrecognized"
            self.assert_reject(selections, changes, sql_message="status transition is invalid")

    def test_capacity_underflow_and_overflow_reject(self) -> None:
        self.assert_reject(*fixture([(None, outbox_row())], before=counter_row(live_count=LIMIT, active_count=LIMIT)))
        old = outbox_row()
        self.assert_reject(*fixture([(old, {**old, "status": "audited"})], before=counter_row()))

    def test_revision_and_insert_sequence_bigint_overflow_reject(self) -> None:
        for changes in ({"revision": MAX_INTEGER}, {"next_sequence": MAX_INTEGER}):
            with self.subTest(changes=changes):
                self.assert_reject(*fixture([(None, outbox_row())], before=counter_row(**changes)))
        # An existing-row update increments revision but not the insertion counter.
        old = outbox_row()
        selections, changes = fixture([(old, {**old, "status": "claimed"})],
            before=counter_row(live_count=1, active_count=1, next_sequence=MAX_INTEGER))
        self.assert_accept(selections, changes)

    def test_time_is_monotonic_input_not_an_authenticated_clock(self) -> None:
        self.assert_reject(*fixture([(None, outbox_row())], timestamp=999_999_999),
                           sql_message="derived transition is outside its bound")
        self.assert_accept(*fixture([(None, outbox_row())], timestamp=1_000_000_000))
        self.assert_accept(*fixture([(None, outbox_row())], timestamp=MAX_INTEGER))

    def test_selected_presence_null_and_closed_field_types(self) -> None:
        for contract_selector in ("caller-selected-contract", "x" * 8192):
            selections, changes = fixture([(None, outbox_row())])
            selections[0]["contractSelector"] = contract_selector
            self.assert_reject(selections, changes, sql_message="global selection is crossed or absent")
        for value in (None, 0, 1, "false", [], {}):
            selections, changes = fixture([(None, outbox_row())])
            selections[1]["present"] = value
            self.assert_reject(selections, changes, sql_message="selected presence is not exact")
        for target, value in (("row", {}), ("contractSelector", False)):
            selections, changes = fixture([(None, outbox_row())])
            selections[1][target] = value
            self.assert_reject(selections, changes)
        for omitted in ("present", "row", "keyDigest"):
            selections, changes = fixture([(None, outbox_row())])
            del selections[1][omitted]
            self.assert_reject(selections, changes, sql_message="selected record is not exact")
        selections, changes = fixture([(None, outbox_row())])
        selections[1]["extra"] = None
        self.assert_reject(selections, changes, sql_message="selected record is not exact")

    def test_exact_keys_digests_missing_and_duplicate_selected_identities(self) -> None:
        selections, changes = fixture([(None, outbox_row())])
        self.assert_reject(selections + [copy.deepcopy(selections[1])], changes, sql_message="identity is duplicated")
        self.assert_reject(selections[:1], changes, sql_message="before or after image is not exact")
        for key in ({"wrong": "audit-one"}, {"id": "audit-one", "extra": 1}, {"id": None}, {"id": True}):
            bad = copy.deepcopy(selections)
            bad[1] = selected(OUTBOX, key, None)
            self.assert_reject(bad, changes)
        for index in (0, 1):
            bad = copy.deepcopy(selections)
            bad[index]["keyDigest"] = "sha256:" + "0" * 64
            self.assert_reject(bad, changes, sql_message="selected record is not exact")

    def test_mutation_closure_cas_template_and_key_movement(self) -> None:
        old = outbox_row()
        baseline = fixture([(old, {**old, "status": "claimed"})],
            before=counter_row(live_count=1, active_count=1))
        for field, value in (("expectedRow", None), ("row", None), ("templateId", "not-source"),
                             ("operation", "INSERT"), ("keyDigest", "sha256:" + "0" * 64)):
            selections, changes = copy.deepcopy(baseline)
            changes[0][field] = value
            self.assert_reject(selections, changes)
        selections, changes = copy.deepcopy(baseline)
        changes[0]["row"]["id"] = "moved"
        self.assert_reject(selections, changes, sql_message="mutation moves its key")
        selections, changes = copy.deepcopy(baseline)
        changes[0]["expectedRow"]["attempts"] = 2
        self.assert_reject(selections, changes, sql_message="before or after image is not exact")
        selections, changes = copy.deepcopy(baseline)
        self.assert_reject(selections, [*changes, copy.deepcopy(changes[0])],
                           sql_message="identity is duplicated")
        for field in ("row", "expectedRow", "operation"):
            selections, changes = copy.deepcopy(baseline)
            del changes[0][field]
            self.assert_reject(selections, changes, sql_message="mutation record is not exact")

    def test_missing_duplicate_and_coherently_altered_counter_mutations(self) -> None:
        selections, changes = fixture([(None, outbox_row())])
        self.assert_reject(selections, changes[:-1], sql_message="global mutation closure is incomplete")
        self.assert_reject(selections, changes + [copy.deepcopy(changes[-1])], sql_message="identity is duplicated")
        for field, value in (("live_count", 2), ("next_sequence", 21), ("revision", 9)):
            altered = copy.deepcopy(changes)
            altered[-1]["row"][field] = value
            if field == "live_count":
                altered[-1]["row"]["active_count"] = value
            refresh_state(altered[-1]["row"])
            self.assert_reject(selections, altered, sql_message="derived after row is not exact")

    def test_self_consistent_alternative_counter_profiles_reject(self) -> None:
        for field, value in (("capacity_limit", LIMIT-1), ("capacity_limit", LIMIT+1),
                ("aggregate_kind", "metadata-audit-outbox-capacity"), ("partition_digest", "sha256:" + "0"*64),
                ("active_count", 1), ("reserved_units_json", '{"old-operation":1}'),
                ("committed_units_json", '{"old-operation":1}'), ("minimum_expiry_epoch_ns", 1),
                ("work_page_id", "old-page"), ("source_revision", "old-source")):
            with self.subTest(field=field, value=value):
                self.assert_reject(*fixture([], before=counter_row(**{field: value})),
                                   sql_message="global profile is invalid")
        before = counter_row()
        before["extra"] = None
        self.assert_reject(*fixture([], before=before), sql_message="global row is not closed")

    def test_counter_integers_never_accept_boolean_string_or_fraction(self) -> None:
        for field in ("revision", "live_count", "active_count", "capacity_limit", "next_sequence", "updated_at_epoch_ns"):
            for value in (True, False, "1", None, 1.0, 0.5, -1, MAX_INTEGER+1):
                with self.subTest(field=field, value=value):
                    before = counter_row(**{field: value})
                    self.assert_reject(*fixture([], before=before))

    def test_state_bytes_and_hash_are_both_exact(self) -> None:
        for field in ("state_json", "state_digest"):
            before = counter_row()
            before[field] = "{}" if field == "state_json" else "sha256:" + "0" * 64
            self.assert_reject(*fixture([], before=before), sql_message="state framing is invalid")
        before = counter_row()
        before["state_json"] = json.dumps(json.loads(before["state_json"]), sort_keys=True, indent=1)
        before["state_digest"] = framed("serverware.policyAuthorityAggregateState/v1", before["state_json"].encode())
        self.assert_reject(*fixture([], before=before), sql_message="state framing is invalid")

    def test_compact_byte_ceiling_applies_to_complete_row(self) -> None:
        before = counter_row()
        self.assertLess(len(canonical(before)), 4096)
        before["state_json"] = " " * 4097
        self.assert_reject(*fixture([], before=before), sql_message="compact byte bound")

    def test_nonparticipant_and_unrelated_mutations_are_not_global_audit_work(self) -> None:
        operation = "webauthn.counter.cas"
        self.assert_accept([], [], operation=operation)
        # Only source key/CAS shape belongs to this component, not the full
        # credential business schema, authentication or counter authorization.
        choice = selected("webauthn_credentials", {"id": "credential-one"},
                          {"id": "credential-one", "sign_count": 1, "status": "not-an-outbox-status"})
        change = mutation(choice, {**choice["row"], "sign_count": 2}, operation=operation)
        self.assert_accept([choice], [change], operation=operation)
        self.assert_reject([selected(TABLE, {"aggregate_id": IDENTITY}, counter_row())], [], operation=operation)
        # This nonparticipant actually permits aggregate reads, so it reaches
        # the reserved-identity guard rather than the earlier table allowlist.
        self.assert_reject([selected(TABLE, {"aggregate_id": IDENTITY}, counter_row())], [],
            operation="policy.activation.record-inclusion", sql_message="nonparticipant selected the reserved global row")
        self.assert_reject([], [], operation="unregistered.operation")
        self.assert_reject({}, [], operation=operation)
        self.assert_reject([], {}, operation=operation)

    def test_participating_operation_keeps_unrelated_aggregate_changes_separate(self) -> None:
        selections, changes = fixture([])
        old = {"aggregate_id": "independent-business-counter", "business": [True, 1, None, {"雪": "🙂"}]}
        choice = selected(TABLE, {"aggregate_id": old["aggregate_id"]}, old)
        self.assert_accept([*selections, choice], [mutation(choice, {**old, "business": False})])
        # A row cannot alias the reserved partition under another business key.
        alias = {**old, "partition_digest": PARTITION}
        self.assert_reject([*selections, selected(TABLE, {"aggregate_id": old["aggregate_id"]}, alias)], [])

    def test_operation_inventory_caps_are_enforced_before_duplicate_walk(self) -> None:
        spec = authority_contract.operation_spec(OPERATION)
        selections, changes = fixture([(None, outbox_row())])
        self.assert_reject([copy.deepcopy(selections[0]) for _ in range(spec["maximumQueryRows"]+1)], [],
                           sql_message="operation bound is exceeded")
        self.assert_reject(selections, [copy.deepcopy(changes[0]) for _ in range(spec["maximumMutations"]+1)],
                           sql_message="operation bound is exceeded")

    def test_unicode_outbox_id_byte_boundary_and_wire_digest_parity(self) -> None:
        for identity in ("clé-雪🙂", "🙂" * 64, "a" * 256):
            self.assert_accept(*fixture([(None, outbox_row(identity))]))
        for identity in ("", "🙂" * 64 + "a", "a" * 257):
            self.assert_reject(*fixture([(None, outbox_row(identity))]), sql_message="outbox selector is not exact")

    def test_delete_arithmetic_does_not_create_an_unavailable_source_template(self) -> None:
        old = outbox_row()
        selections, changes = fixture([(old, {**old, "status": "audited"})],
            before=counter_row(live_count=1, active_count=1))
        self.assert_accept(selections, changes)
        self.assertFalse(any(item["table"] == OUTBOX and item["mutation"] == "DELETE"
            for item in authority_contract.operation_spec(OPERATION)["mutationTemplates"]))
        changes[0].update(operation="DELETE", row=None)
        self.assert_reject(selections, changes, sql_message="outside the source template")

    def test_sql_null_inputs_reject_and_jsonb_is_not_raw_token_admission(self) -> None:
        with self.connection() as connection:
            for values in ((None, "[]", "[]", 2), (OPERATION, None, "[]", 2), (OPERATION, "[]", None, 2)):
                with self.assertRaisesRegex(psycopg.errors.RaiseException, "source-bounded arrays"):
                    connection.execute(
                        f"SELECT {self.namespace}.{AUDIT_CAPACITY_FUNCTION_NAME}(%s,%s::jsonb,%s::jsonb,%s)", values)
            selections, changes = fixture([])
            with self.assertRaisesRegex(psycopg.errors.RaiseException, "actual transition work bound is exceeded"):
                connection.execute(
                    f"SELECT {self.namespace}.{AUDIT_CAPACITY_FUNCTION_NAME}(%s,%s::jsonb,%s::jsonb,%s)",
                    (OPERATION, canonical(selections), canonical(changes), None))
            # PostgreSQL has already discarded duplicate key and integer exponent
            # spellings. This is a boundary check, not guard acceptance of raw wire.
            self.assertEqual(connection.execute(
                "SELECT %s::jsonb, %s::jsonb", ('{"n":1,"n":2}', '1e2')
            ).fetchone(), ({"n": 2}, 100))

    def test_required_work_charges_actual_framework_and_preserves_business_ceiling(self) -> None:
        cases = ((OPERATION, fixture([(None, outbox_row())]), 2),
                 (OPERATION, fixture([]), 1), ("webauthn.counter.cas", ([], []), 0))
        for operation, (selections, changes), overhead in cases:
            maximum = authority_contract.operation_spec(operation)["maximumBusinessWorkUnits"] + overhead
            self.assertEqual(fixture_work(operation, changes), 1 + overhead)
            for work in (1 + overhead, maximum):
                self.assert_accept(selections, changes, operation=operation, work_units=work)
            for work in (0, overhead, maximum + 1):
                with self.subTest(operation=operation, work=work):
                    # Valid transition baseline: these must reach work admission.
                    capacity.validate_capacity_transition(operation=operation, selected_rows=selections, mutations=changes)
                    with self.assertRaisesRegex(capacity.AuditCapacityError, "work exceeds its business/framework bound"):
                        capacity.validate_transition_work_units(operation, work, changes)
                    with self.assertRaisesRegex(psycopg.errors.RaiseException, "actual transition work bound is exceeded"):
                        self.sql_validate(selections, changes, operation=operation, work_units=work)

    def test_work_token_types_and_bigint_coercion_are_separate_boundaries(self) -> None:
        selections, changes = fixture([(None, outbox_row())])
        self.assert_accept(selections, changes, work_units=3)
        for work in (True, False, "3", None, 3.0):
            with self.assertRaisesRegex(capacity.AuditCapacityError, "work exceeds its business/framework bound"):
                capacity.validate_transition_work_units(OPERATION, work, changes)
        # The installed bigint API does not retain the original signed JSON
        # token type. The actual caller must keep its strict raw/canonical guard.
        self.sql_validate(selections, changes, work_units="3")
        with self.assertRaises(psycopg.ProgrammingError):
            self.sql_validate(selections, changes, work_units=True)
        with self.connection() as connection:
            with self.assertRaises(psycopg.errors.NumericValueOutOfRange):
                connection.execute(
                    f"SELECT {self.namespace}.{AUDIT_CAPACITY_FUNCTION_NAME}(%s,%s::jsonb,%s::jsonb,%s::bigint)",
                    (OPERATION, canonical(selections), canonical(changes), MAX_INTEGER + 1))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--postgres-dsn", required=True)
    parser.add_argument("--prepared-result")
    arguments, test_arguments = parser.parse_known_args()
    CONNECTION_PARAMETERS = local_connection_parameters(arguments.postgres_dsn)
    run_native_fixture("scripts/test_authority_global_audit_capacity_postgres.py",
        argv=[sys.argv[0], *test_arguments], result_path=arguments.prepared_result)
