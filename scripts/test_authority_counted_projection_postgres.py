#!/usr/bin/env python3
"""Real fixed counted projections in a rollback-only prepared PostgreSQL schema.

An external approved harness supplies PG16/UTF8 on an owned mode-0700 Unix
socket. This fixture starts no engine, imports no database facade and installs
only the actual renderers' functions inside one SERIALIZABLE transaction. No
business table, writer trigger, head, bootstrap, authority or operation is
installed. Independent literal descriptors and hash framing supply expected
keys and full-row commitments; production projection results are not oracles.

The SQL input is already JSONB. These controls do not establish original-byte
parsing, duplicate-member rejection, physical resource bounds or all-writer
maintenance. Every fixture-created schema and function is rolled back.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
import unittest
import uuid
from contextlib import contextmanager
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate.native_postgres_results import run_native_fixture
from catchplate.authority_store.counted_hash_sql import counted_hash_functions_sql
from catchplate.authority_store.counted_projection_sql import counted_projection_functions_sql
from catchplate.authority_store.primary_tree_sql import framed_digest_function_sql
from catchplate.authority_store.wire_json_sql import wire_json_function_sql
import test_authority_index_join as oracle
from test_authority_root_transition_postgres import production_digest_functions
from test_webauthn_trust_projection_postgres import local_connection_parameters


CONNECTION_PARAMETERS: dict[str, str | int] | None = None
INDEX_IDS = (
    "webauthn_credential_id", "webauthn_credential_user_history", "webauthn_credential_live_trust",
    "webauthn_registration_unused_global", "webauthn_registration_unused_user",
    "webauthn_session_credential_status", "webauthn_grant_approver_active",
    "webauthn_control_approval_approved", "webauthn_publication_bundle_digest",
    "webauthn_publication_status", "webauthn_publication_generation",
)
EXPIRY = "1970-01-01T00:00:00.000001+00:00"
I64_MIN, I64_MAX = -(2**63), 2**63 - 1


def sample_row(index_id: str) -> dict:
    table = oracle.descriptor(index_id)["table"]
    fields = {
        "webauthn_credentials": {"credential_id": "credential", "user_id": "user", "revoked_at": None,
                                 "attestation_trusted": 1, "sign_count": 7},
        "webauthn_challenges": {"challenge_type": "registration", "used_at": None, "expires_at": EXPIRY,
                                "user_id": "user", "approval_request_id": "not-filtered"},
        "oidc_browser_sessions": {"bound_webauthn_credential_id": "credential-record", "status": "active",
                                  "expires_at": "1969-01-01T00:00:00+00:00"},
        "approval_grants": {"approver_webauthn_credential_id": "credential-record", "state": "active",
                            "remaining_uses": 0, "expires_at": "1969-01-01T00:00:00+00:00"},
        "control_plane_approvals": {"approver_webauthn_credential_id": "credential-record", "status": "approved",
                                    "expires_at": "1969-01-01T00:00:00+00:00"},
        "webauthn_trust_publications": {"scope": "global", "status": "pending", "bundle_digest": "bundle",
                                       "rollback_epoch": 0, "sequence": 1},
    }[table]
    return {"id": "record", **fields, "fixture_payload": {"retained": [True, None, 2]}}


def expected_projection(index_id: str, row: dict, *, expiry_us: int = 1) -> list[dict]:
    profile = oracle.expected_profile(index_id)
    key_bytes = json.dumps({"id": row["id"]}, ensure_ascii=True, allow_nan=False,
                           sort_keys=True, separators=(",", ":")).encode("ascii")
    material = b"catchplate.policyAuthorityBusinessKey/v1\0"
    for frame in (profile.table.encode("ascii"), key_bytes):
        material += len(frame).to_bytes(8, "big") + frame
    key_digest = "sha256:" + hashlib.sha256(material).hexdigest()
    row_digest = oracle.framed("catchplate.policyAuthorityAuthenticatedRow/v1",
                               profile.table.encode("ascii"), oracle.utf8_json(row))
    leaf = oracle.expected_leaf(profile, row, {"keyDigest": key_digest},
                                {"rowDigest": row_digest}, expiry_us=expiry_us)
    return [] if leaf is None else [{"index_key": leaf.key, "primary_id": row["id"],
                                    "primary_key_digest": key_digest, "primary_row_digest": row_digest}]


class AuthorityCountedProjectionPostgresTests(unittest.TestCase):
    def setUp(self) -> None:
        if CONNECTION_PARAMETERS is None:
            raise RuntimeError("requires an externally prepared --postgres-dsn")
        self.connection = psycopg.connect(**CONNECTION_PARAMETERS, autocommit=False)
        self.addCleanup(self.rollback_and_close)
        self.connection.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        self.connection.execute("SET LOCAL statement_timeout = '5s'")
        self.connection.execute("SET LOCAL lock_timeout = '250ms'")
        self.connection.execute("SET LOCAL idle_in_transaction_session_timeout = '10s'")
        environment = self.connection.execute(
            "SELECT pg_catalog.inet_server_addr(), pg_catalog.getdatabaseencoding(), "
            "pg_catalog.current_setting('server_version_num')::integer, current_user = session_user, "
            "pg_catalog.current_setting('transaction_isolation')"
        ).fetchone()
        if (environment is None or environment[0] is not None or environment[1] != "UTF8"
                or not 160000 <= environment[2] < 170000 or environment[3] is not True
                or environment[4] != "serializable"):
            raise RuntimeError("requires a direct Unix-socket PG16/UTF8 serializable session")
        self.schema = "counted_projection_" + uuid.uuid4().hex
        self.namespace = '"' + self.schema + '"'
        self.connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(self.schema)))
        self.connection.execute(sql.SQL("REVOKE ALL ON SCHEMA {} FROM PUBLIC").format(sql.Identifier(self.schema)))
        self.connection.execute(sql.SQL("SET LOCAL search_path TO {}, pg_catalog").format(sql.Identifier(self.schema)))
        # Actual canonical JSON + NUL-domain SQL, not replacement fixture SQL.
        for statement in production_digest_functions(self.namespace):
            self.connection.execute(statement)
        self.connection.execute(framed_digest_function_sql(self.namespace))
        self.connection.execute(wire_json_function_sql(self.namespace))
        for statement in (*counted_hash_functions_sql(self.namespace),
                          *counted_projection_functions_sql(self.namespace)):
            self.connection.execute(statement)

    def rollback_and_close(self) -> None:
        try:
            self.connection.rollback()
        finally:
            self.connection.close()

    def function(self, suffix: str) -> sql.Identifier:
        return sql.Identifier(self.schema, "catchplate_policy_authority_" + suffix)

    @contextmanager
    def rollback_variant(self):
        self.connection.execute("SAVEPOINT counted_projection_variant")
        try:
            yield
        finally:
            self.connection.execute("ROLLBACK TO SAVEPOINT counted_projection_variant")
            self.connection.execute("RELEASE SAVEPOINT counted_projection_variant")

    def project(self, index_id, row) -> list[dict]:
        with self.connection.cursor(row_factory=dict_row) as cursor:
            return cursor.execute(sql.SQL("SELECT * FROM {}(%s,%s)").format(self.function("counted_project")),
                                  (index_id, Jsonb(row))).fetchall()

    def scalar(self, suffix: str, value):
        return self.connection.execute(sql.SQL("SELECT {}(%s)").format(self.function(suffix)),
                                       (value,)).fetchone()[0]

    def assert_projection(self, index_id: str, row: dict, *, expiry_us: int = 1) -> list[dict]:
        actual = self.project(index_id, row)
        self.assertEqual(actual, expected_projection(index_id, row, expiry_us=expiry_us))
        return actual

    def assert_denied(self, index_id, row, message: str) -> None:
        with self.rollback_variant():
            with self.assertRaisesRegex(psycopg.Error, message):
                self.project(index_id, row)

    def test_all_eleven_fixed_profiles_match_independent_full_commitments(self):
        self.assertEqual(len(INDEX_IDS), 11)
        for index_id in INDEX_IDS:
            with self.subTest(index_id=index_id):
                result = self.assert_projection(index_id, sample_row(index_id))
                self.assertEqual(len(result), 1)
                self.assertEqual(result[0]["index_key"][-64:], result[0]["primary_key_digest"][7:])

    def test_full_row_only_changes_keep_keys_but_change_every_member_commitment(self):
        for index_id in INDEX_IDS:
            with self.subTest(index_id=index_id):
                before = sample_row(index_id)
                after = copy.deepcopy(before)
                after["fixture_payload"]["retained"].append("changed")
                old, new = self.assert_projection(index_id, before)[0], self.assert_projection(index_id, after)[0]
                self.assertEqual(old["index_key"], new["index_key"])
                self.assertEqual(old["primary_key_digest"], new["primary_key_digest"])
                self.assertNotEqual(old["primary_row_digest"], new["primary_row_digest"])

    def test_unicode_controls_empty_ids_and_unmodified_primary_framing(self):
        index_id = "webauthn_credential_id"
        for identity in ("", "\"\\\n\t\b\f\r\x01", "é", "e\u0301", "🙂"):
            with self.subTest(identity=identity):
                row = sample_row(index_id)
                row.update(id=identity, credential_id=identity, fixture_payload={"雪": [identity, True, None]})
                actual = self.assert_projection(index_id, row)[0]
                auth_key = oracle.framed("catchplate.policyAuthorityAuthenticatedKey/v1", b"webauthn_credentials",
                                         oracle.utf8_json({"id": identity}))
                self.assertNotEqual(actual["primary_key_digest"], auth_key)
        first = self.assert_projection(index_id, {**sample_row(index_id), "credential_id": "é"})[0]
        second = self.assert_projection(index_id, {**sample_row(index_id), "credential_id": "e\u0301"})[0]
        self.assertNotEqual(first["index_key"][:64], second["index_key"][:64])

    def test_null_empty_bindings_and_nullable_membership_are_distinct(self):
        for index_id, field in (("webauthn_session_credential_status", "bound_webauthn_credential_id"),
                                ("webauthn_grant_approver_active", "approver_webauthn_credential_id"),
                                ("webauthn_control_approval_approved", "approver_webauthn_credential_id")):
            row = sample_row(index_id)
            self.assertEqual(self.assert_projection(index_id, {**row, field: None}), [])
            self.assertEqual(len(self.assert_projection(index_id, {**row, field: ""})), 1)
        index_id = "webauthn_credential_live_trust"
        row = sample_row(index_id)
        self.assertEqual(len(self.assert_projection(index_id, row)), 1)
        self.assertEqual(self.assert_projection(index_id, {**row, "revoked_at": ""}), [])

    def test_session_status_partitions_and_nonselector_expiry_are_exact(self):
        index_id = "webauthn_session_credential_status"
        row = sample_row(index_id)
        active = self.assert_projection(index_id, row)[0]
        pending = self.assert_projection(index_id, {**row, "status": "pending_webauthn"})[0]
        self.assertNotEqual(active["index_key"][:64], pending["index_key"][:64])
        self.assertEqual(self.assert_projection(index_id, {**row, "status": "revoked"}), [])
        # Expiry is deliberately not a membership filter in these profiles.
        for name in (index_id, "webauthn_grant_approver_active", "webauthn_control_approval_approved"):
            self.assertEqual(len(self.assert_projection(name, sample_row(name))), 1)

    def test_nonmembers_return_no_leaf_without_weakening_reference_checks(self):
        cases = (("webauthn_credential_live_trust", "attestation_trusted", 0),
                 ("webauthn_registration_unused_global", "challenge_type", "assertion"),
                 ("webauthn_registration_unused_user", "used_at", ""),
                 ("webauthn_grant_approver_active", "state", "expired"),
                 ("webauthn_control_approval_approved", "status", "rejected"))
        for index_id, field, value in cases:
            with self.subTest(index_id=index_id):
                row = {**sample_row(index_id), field: value}
                self.assertEqual(self.assert_projection(index_id, row), [])
                del row["id"]
                self.assert_denied(index_id, row, "counted referenced field is missing")

    def test_text_byte_limit_is_utf8_and_never_truncates(self):
        index_id = "webauthn_credential_id"
        for field in ("id", "credential_id"):
            for value in ("x" * 4096, "é" * 2048, "🙂" * 1024):
                self.assertEqual(len(self.assert_projection(index_id, {**sample_row(index_id), field: value})), 1)
                self.assert_denied(index_id, {**sample_row(index_id), field: value + "x"},
                                   "counted text exceeds its UTF8 byte bound")
        # PostgreSQL rejects U+0000 before the renderer receives JSONB.
        with self.rollback_variant():
            with self.assertRaises(psycopg.Error):
                self.project(index_id, {**sample_row(index_id), "id": "a\0b"})

    def test_expiry_codec_matches_literal_microseconds_and_ignores_session_timezone(self):
        cases = (("0001-01-01T00:00:00+00:00", -62135596800000000),
                 ("1969-12-31T23:59:59.999999+00:00", -1),
                 ("1970-01-01T00:00:00+00:00", 0), (EXPIRY, 1),
                 ("2000-02-29T00:00:00+00:00", 951782400000000),
                 ("9999-12-31T23:59:59.999999+00:00", 253402300799999999))
        self.connection.execute("SET LOCAL TIME ZONE 'America/New_York'")
        for text, micros in cases:
            with self.subTest(text=text):
                self.assertEqual(self.scalar("counted_expiry_micros", text), micros)
                for index_id in ("webauthn_registration_unused_global", "webauthn_registration_unused_user"):
                    self.assert_projection(index_id, {**sample_row(index_id), "expires_at": text}, expiry_us=micros)

    def test_noncanonical_or_invalid_expiry_is_rejected_even_for_nonmembers(self):
        invalid = (None, "", "1970-01-01T00:00:00Z", "1970-01-01T00:00:00.000000+00:00",
                   "1970-01-01T00:00:00.1+00:00", "1970-01-01T00:00:00+01:00",
                   "0000-01-01T00:00:00+00:00", "1900-02-29T00:00:00+00:00",
                   "2000-02-30T00:00:00+00:00", "1970-01-01T24:00:00+00:00",
                   "1970-01-01T00:00:60+00:00", EXPIRY + "\n")
        for value in invalid:
            with self.subTest(value=value), self.rollback_variant():
                with self.assertRaises(psycopg.Error):
                    self.scalar("counted_expiry_micros", value)
        index_id = "webauthn_registration_unused_global"
        self.assert_denied(index_id, {**sample_row(index_id), "used_at": "used", "expires_at": "not-a-time"},
                           "counted expiry is not canonical UTC")
        self.assert_projection(index_id, sample_row(index_id))

    def test_signed_order_has_exact_signed64_boundaries_and_lexical_order(self):
        values = (I64_MIN, I64_MIN + 1, -1, 0, 1, I64_MAX - 1, I64_MAX)
        actual = [self.scalar("counted_signed_order", value) for value in values]
        self.assertEqual(actual, [f"{value + 2**63:016x}" for value in values])
        self.assertEqual(actual, sorted(actual))
        with self.rollback_variant():
            with self.assertRaisesRegex(psycopg.Error, "counted signed order is null"):
                self.scalar("counted_signed_order", None)

    def test_generation_pair_order_and_int64_bounds_match_independent_codec(self):
        index_id = "webauthn_publication_generation"
        pairs = ((I64_MIN, I64_MIN), (I64_MIN, I64_MAX), (-1, 0), (0, I64_MIN), (0, 0), (I64_MAX, I64_MAX))
        keys = []
        for epoch, sequence in pairs:
            row = {**sample_row(index_id), "rollback_epoch": epoch, "sequence": sequence}
            keys.append(self.assert_projection(index_id, row)[0]["index_key"])
        self.assertEqual(keys, sorted(keys))
        for field in ("rollback_epoch", "sequence"):
            for value in (I64_MIN - 1, I64_MAX + 1, True, "1", 1.5, None):
                self.assert_denied(index_id, {**sample_row(index_id), field: value}, "counted integer")

    def test_attestation_integer_contract_preserves_signed_int32_not_boolean_aliases(self):
        index_id = "webauthn_credential_live_trust"
        for value in (-(2**31), -1, 0, 1, 2**31 - 1):
            expected_size = 0 if value == 0 else 1
            self.assertEqual(len(self.assert_projection(index_id, {**sample_row(index_id), "attestation_trusted": value})), expected_size)
        for value in (-(2**31) - 1, 2**31, True, False, "1", 1.5, None, []):
            self.assert_denied(index_id, {**sample_row(index_id), "attestation_trusted": value}, "counted integer")

    def test_source_identity_and_row_object_types_are_closed(self):
        for identity in (None, "", "unknown", "webauthn_credential_id ", "x" * 129):
            self.assert_denied(identity, sample_row("webauthn_credential_id"), "counted index identity")
        for value in (None, [], "row", 1, True):
            self.assert_denied("webauthn_credential_id", value, "counted source row must be an actual object")
        with self.rollback_variant():
            with self.assertRaisesRegex(psycopg.Error, "counted source row must be an actual object"):
                self.connection.execute(sql.SQL("SELECT * FROM {}(%s,NULL::jsonb)").format(self.function("counted_project")),
                                        ("webauthn_credential_id",)).fetchall()
        self.assert_projection("webauthn_credential_id", sample_row("webauthn_credential_id"))

    def test_every_referenced_field_is_required_and_wrong_text_types_are_rejected(self):
        for index_id in INDEX_IDS:
            for field, kind in oracle.descriptor(index_id)["rowFields"]:
                with self.subTest(index_id=index_id, field=field):
                    row = sample_row(index_id)
                    del row[field]
                    self.assert_denied(index_id, row, "counted referenced field is missing")
                    if kind not in ("int32", "int64"):
                        self.assert_denied(index_id, {**sample_row(index_id), field: 1}, "counted text has a nonstring type")

    def test_publication_scope_and_enums_are_exact_not_silent_nonmembers(self):
        for index_id in ("webauthn_publication_bundle_digest", "webauthn_publication_status", "webauthn_publication_generation"):
            for status in ("pending", "published"):
                self.assert_projection(index_id, {**sample_row(index_id), "status": status})
            for field, value in (("scope", "GLOBAL"), ("scope", ""), ("status", "revoked"), ("status", "Published")):
                self.assert_denied(index_id, {**sample_row(index_id), field: value}, "counted text is outside its source enum")
        index_id = "webauthn_session_credential_status"
        self.assert_denied(index_id, {**sample_row(index_id), "bound_webauthn_credential_id": None, "status": "unknown"},
                           "counted text is outside its source enum")

    def test_full_row_lossless_and_depth_guards_precede_membership_return(self):
        index_id = "webauthn_credential_live_trust"
        for excluded in (False, True):
            row = {**sample_row(index_id), "attestation_trusted": 0 if excluded else 1}
            self.assert_denied(index_id, {**row, "unindexed": {"fraction": 1.25}},
                               "authority wire JSON requires lossless integer numbers")
            nested = None
            for _ in range(128):
                nested = [nested]
            self.assert_denied(index_id, {**row, "unindexed": nested}, "authority wire JSON depth bound exceeded")
        self.assert_projection(index_id, sample_row(index_id))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--postgres-dsn", required=True)
    parser.add_argument("--prepared-result")
    arguments, test_arguments = parser.parse_known_args()
    CONNECTION_PARAMETERS = local_connection_parameters(arguments.postgres_dsn)
    run_native_fixture("scripts/test_authority_counted_projection_postgres.py",
                       argv=[sys.argv[0], *test_arguments], result_path=arguments.prepared_result)
