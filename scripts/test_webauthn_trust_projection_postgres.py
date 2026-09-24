#!/usr/bin/env python3
"""Real PostgreSQL coverage of the shared v9 trust projection, not full v9.

An external prepared runner owns a disposable no-network PostgreSQL engine and
its lifecycle. This test accepts only its local Unix socket, creates one random
schema, and drops that exact schema. It never starts Docker, provisions trust,
imports the blocked registry, or substitutes a successful authority admission.
The table declarations come from the pure production schema source; the executed
projection comes from the same helper interpolated into the production executor.
The credential-policy expression uses the real production wire/domain functions;
its claim-equality predicate is component coverage, not the enclosing CAS guard.
Root authentication, predicate completeness, the full executor, and migrations
are deliberately outside this engineering proof boundary.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware.native_postgres_results import run_native_fixture

from serverware import authority_webauthn_trust as trust
from serverware.authority_store.webauthn_trust_sql import (
    locked_webauthn_trust_projection,
    webauthn_credential_policy_sql,
)
from serverware.authority_store.metadata_schema_source import metadata_base_schema_source
from serverware.authority_store.wire_json_sql import wire_json_function_sql


CONNECTION_PARAMETERS: dict[str, str | int] | None = None
PUBLICATIONS = "webauthn_trust_publications"
HIGH_WATER = "webauthn_trust_publication_high_water"
POLICY_DOMAIN = "serverware.policyAuthorityCredentialPolicy/v1"
HIGH_WATER_DOMAIN = "serverware.webauthnTrustHighWater/v1"


def local_connection_parameters(dsn: str) -> dict[str, str | int]:
    # libpq environment/service configuration must not silently redirect this
    # engineering fixture or weaken its fixed timeouts and Unix-socket boundary.
    if any(name.startswith("PG") for name in os.environ):
        raise ValueError("PostgreSQL fixture forbids ambient PG configuration")
    parameters = conninfo_to_dict(dsn)
    if set(parameters) - {"host", "port", "dbname", "user"}:
        raise ValueError("PostgreSQL fixture DSN has unsupported override fields")
    if not all(parameters.get(name) for name in ("host", "dbname", "user")):
        raise ValueError("PostgreSQL fixture DSN requires host, dbname, and user")
    host = parameters["host"]
    socket_directory = Path(host)
    if (
        not socket_directory.is_absolute()
        or host == "/"
        or str(socket_directory.resolve()) != host
        or "," in host
    ):
        raise ValueError("PostgreSQL fixture requires one exact local Unix socket directory")
    info = socket_directory.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise ValueError("PostgreSQL fixture socket directory must be owned and mode 0700")
    port = parameters.get("port", "5432")
    if re.fullmatch(r"[1-9][0-9]{0,4}", port) is None or int(port) > 65535:
        raise ValueError("PostgreSQL fixture port is invalid")
    return {
        **parameters,
        "port": port,
        "connect_timeout": 5,
        "options": (
            "-cstatement_timeout=5000 -clock_timeout=250 "
            "-cidle_in_transaction_session_timeout=10000"
        ),
        "sslmode": "disable",
        "gssencmode": "disable",
        "passfile": "/dev/null",
        "application_name": "serverware-trust-projection-fixture",
    }


def production_table_declarations() -> list[str]:
    source_path = ROOT / "serverware/authority_store/metadata_schema_source.py"
    if source_path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("database schema source exceeds fixture bound")
    declaration = metadata_base_schema_source()
    statements = []
    for table in (PUBLICATIONS, HIGH_WATER):
        matches = re.findall(
            rf"CREATE TABLE IF NOT EXISTS\s+{re.escape(table)}\s*\(.*?\n\s+\);",
            declaration,
            flags=re.DOTALL,
        )
        if len(matches) != 1:
            raise ValueError(f"production declaration for {table} is not exact")
        statements.append(matches[0])
    return statements


def digest(character: str) -> str:
    return "sha256:" + character * 64


def policy_wire(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
                      sort_keys=True, separators=(",", ":"))


def policy_commitment(domain: str, value: object) -> str:
    """Independent expected framing, never a substitute SQL implementation."""
    body = policy_wire(value).encode("ascii")
    return "sha256:" + hashlib.sha256(domain.encode("ascii") + b"\0"
        + len(body).to_bytes(8, "big") + body).hexdigest()


def policy_high_water() -> dict:
    return {"schema": HIGH_WATER_DOMAIN, "rollbackEpoch": 2, "sequence": 7,
        "publicationDigest": digest("a"), "metadataBlobDigest": digest("b"),
        "revocationSetDigest": digest("c"), "witnessReceiptDigest": digest("d"),
        "witnessSequence": 11}


def policy_credential() -> dict:
    return {"id": "credential-record", "credential_id": "credential-public-id",
        "user_id": "fixture-actor", "authenticator_class": "security-key",
        "aaguid": "fixture-aaguid", "attestation_trusted": 1,
        "attestation_leaf_sha256": None, "attestation_root_sha256": digest("e"),
        "attestation_trust_bundle_digest": digest("a"),
        "attestation_trust_bundle_sequence": 7, "public_key_cose": "synthetic-key-雪🙂"}


def independent_policy(row: dict) -> dict:
    return {"schema": POLICY_DOMAIN, "credentialRecordId": row["id"],
        "credentialId": row["credential_id"], "userId": row["user_id"],
        "authenticatorClass": row["authenticator_class"], "aaguid": row["aaguid"],
        "attestationTrusted": bool(row["attestation_trusted"]),
        "attestationLeafDigest": row["attestation_leaf_sha256"],
        "attestationRootDigest": row["attestation_root_sha256"],
        "trustBundleDigest": digest("a"), "trustBundleSequence": 7,
        "trustRollbackEpoch": 2,
        "trustHighWaterDigest": policy_commitment(HIGH_WATER_DOMAIN, policy_high_water()),
        "revocationSetDigest": digest("c"), "trustWitnessReceiptDigest": digest("d"),
        "publicKeyDigest": "sha256:" + hashlib.sha256(row["public_key_cose"].encode("utf-8")).hexdigest()}


class WebAuthnTrustProjectionPostgresTests(unittest.TestCase):
    @classmethod
    def connection(cls, *, autocommit: bool = True) -> psycopg.Connection:
        if CONNECTION_PARAMETERS is None:
            raise RuntimeError("this real-engine test requires --postgres-dsn")
        connection = psycopg.connect(**CONNECTION_PARAMETERS, autocommit=autocommit)
        connection.isolation_level = psycopg.IsolationLevel.SERIALIZABLE
        return connection

    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = "serverware_trust_projection_" + uuid.uuid4().hex
        cls.namespace = '"' + cls.schema + '"'
        with cls.connection() as connection:
            if connection.execute("SELECT inet_server_addr(), getdatabaseencoding()").fetchone() != (None, "UTF8"):
                raise RuntimeError("PostgreSQL fixture must use a UTF8 database over a Unix socket")
            connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(cls.schema)))
        cls.addClassCleanup(cls.drop_schema)
        with cls.connection() as connection:
            connection.execute(
                sql.SQL("SET search_path TO {}, pg_catalog").format(sql.Identifier(cls.schema))
            )
            for declaration in production_table_declarations():
                connection.execute(declaration)
            # This existing bounded extractor reads the actual installer SQL.
            # Delay its import: that fixture imports our connection admission.
            # No replacement SQL digest or blocked database facade is loaded.
            from test_authority_root_transition_postgres import production_digest_functions
            for declaration in production_digest_functions(cls.namespace):
                connection.execute(declaration)
            connection.execute(wire_json_function_sql(cls.namespace))
            connection.execute(
                f"""
                CREATE FUNCTION {cls.namespace}.project_trust()
                RETURNS pg_catalog.jsonb LANGUAGE plpgsql
                SET search_path = pg_catalog
                AS $projection_fixture$
                DECLARE
                    trust_high_water record;
                    trust_publication record;
                BEGIN
                    {locked_webauthn_trust_projection(cls.namespace)}
                    RETURN pg_catalog.to_jsonb(trust_publication);
                END;
                $projection_fixture$;
                """
            )
            connection.execute(
                f"""
                CREATE FUNCTION {cls.namespace}.project_credential_policy(
                    input_row pg_catalog.jsonb, expected_claim text, high_water_digest text
                ) RETURNS TABLE(policy pg_catalog.jsonb, policy_wire text,
                                policy_digest text, claim_matches boolean)
                LANGUAGE plpgsql SET search_path = pg_catalog
                AS $credential_policy_fixture$
                DECLARE
                    trust_high_water record;
                    trust_publication record;
                    credential_mutation record;
                    assertion_evidence record;
                    computed_trust_high_water_digest text := high_water_digest;
                BEGIN
                    {locked_webauthn_trust_projection(cls.namespace)}
                    SELECT pg_catalog.jsonb_build_object('expectedRow', input_row) AS value
                    INTO STRICT credential_mutation;
                    SELECT input_row->>'id' AS credential_record_id,
                           input_row->>'credential_id' AS credential_id
                    INTO STRICT assertion_evidence;
                    policy := {webauthn_credential_policy_sql()};
                    policy_wire := {cls.namespace}.serverware_policy_authority_wire_json(policy);
                    policy_digest := {cls.namespace}.serverware_policy_authority_domain_digest(
                        '{POLICY_DOMAIN}', policy_wire);
                    -- This is the active guard's equality predicate only.
                    -- It is not the full executor, its row CAS, or a write.
                    claim_matches := policy_digest = expected_claim;
                    RETURN NEXT;
                END;
                $credential_policy_fixture$;
                """
            )

    @classmethod
    def drop_schema(cls) -> None:
        with cls.connection() as connection:
            connection.execute(
                sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(cls.schema))
            )

    def setUp(self) -> None:
        with self.connection() as connection:
            connection.execute(
                sql.SQL("TRUNCATE {}.{}, {}.{}").format(
                    sql.Identifier(self.schema), sql.Identifier(PUBLICATIONS),
                    sql.Identifier(self.schema), sql.Identifier(HIGH_WATER),
                )
            )
            connection.execute(
                f"""INSERT INTO {self.namespace}.{PUBLICATIONS}
                    (id, scope, bundle_digest, sequence, rollback_epoch,
                     signing_key_id, bundle_json, payload_digest, actor_id,
                     withdrawn_credential_ids_json, audit_event_json, status,
                     created_at, published_at)
                    VALUES (%s, 'global', %s, 7, 2, 'fixture-key', '{{}}',
                            %s, 'fixture-actor', %s, '{{}}', 'published',
                            '2026-09-22T00:00:00Z', '2026-09-22T00:00:00Z')""",
                ("publication-a", digest("a"), digest("b"), '["revoked-record"]'),
            )
            connection.execute(
                f"""INSERT INTO {self.namespace}.{HIGH_WATER}
                    (authority_scope, rollback_epoch, publication_sequence,
                     publication_digest, metadata_blob_digest, revocation_set_digest,
                     witness_receipt_digest, witness_sequence, updated_at_epoch_ns)
                    VALUES ('webauthn-metadata', 2, 7, %s, %s, %s, %s, 11, 1)""",
                (digest("a"), digest("b"), digest("c"), digest("d")),
            )

    def projection(self, connection: psycopg.Connection | None = None) -> dict:
        if connection is not None:
            return connection.execute(f"SELECT {self.namespace}.project_trust()").fetchone()[0]
        with self.connection() as local:
            return self.projection(local)

    def update(self, table: str, field: str, value: object) -> None:
        with self.connection() as connection:
            connection.execute(
                sql.SQL("UPDATE {}.{} SET {} = %s").format(
                    sql.Identifier(self.schema), sql.Identifier(table), sql.Identifier(field)
                ),
                (value,),
            )

    def credential_policy(self, row: dict, *, claim: str | None) -> tuple:
        # The high-water digest is an independently constructed fixture input,
        # not an assertion that this component has admitted a current root.
        with self.connection() as connection:
            return connection.execute(
                f"SELECT * FROM {self.namespace}.project_credential_policy(%s::jsonb, %s, %s)",
                (policy_wire(row), claim, policy_commitment(HIGH_WATER_DOMAIN, policy_high_water())),
            ).fetchone()

    def assert_policy_parity(self, row: dict) -> tuple:
        expected = independent_policy(row)
        expected_digest = policy_commitment(POLICY_DOMAIN, expected)
        high_water = policy_high_water()
        self.assertEqual(trust.high_water_digest(high_water),
                         policy_commitment(HIGH_WATER_DOMAIN, high_water))
        actual_python = trust.credential_policy_document(credential=row,
            high_water=high_water, trust_high_water_digest=expected["trustHighWaterDigest"])
        self.assertEqual(actual_python, expected)
        self.assertEqual(trust.credential_policy_digest(actual_python), expected_digest)
        actual_sql = self.credential_policy(row, claim=expected_digest)
        self.assertEqual(actual_sql, (expected, policy_wire(expected), expected_digest, True))
        return actual_sql

    def test_exact_projection_uses_real_publication_and_high_water_columns(self) -> None:
        self.assertEqual(self.projection(), {
            "bundle_digest": digest("a"), "sequence": 7, "rollback_epoch": 2,
            "payload_digest": digest("b"),
            "withdrawn_credential_ids_json": '["revoked-record"]',
            "publication_digest": digest("a"), "metadata_blob_digest": digest("b"),
            "revocation_set_digest": digest("c"), "witness_receipt_digest": digest("d"),
            "witness_sequence": 11,
        })

    def test_join_mismatches_and_unpublished_status_are_denied(self) -> None:
        for table, field, invalid in (
            (HIGH_WATER, "rollback_epoch", 3),
            (HIGH_WATER, "publication_sequence", 8),
            (HIGH_WATER, "publication_digest", digest("e")),
            (HIGH_WATER, "metadata_blob_digest", digest("f")),
            (PUBLICATIONS, "status", "pending"),
        ):
            with self.subTest(table=table, field=field):
                self.setUp()
                self.update(table, field, invalid)
                with self.assertRaises(psycopg.errors.NoDataFound):
                    self.projection()

    def test_missing_either_row_is_denied(self) -> None:
        for table in (HIGH_WATER, PUBLICATIONS):
            with self.subTest(table=table):
                self.setUp()
                with self.connection() as connection:
                    connection.execute(sql.SQL("DELETE FROM {}.{}").format(
                        sql.Identifier(self.schema), sql.Identifier(table)
                    ))
                with self.assertRaises(psycopg.errors.NoDataFound):
                    self.projection()

    def test_matching_values_on_different_publications_cannot_be_combined(self) -> None:
        self.update(PUBLICATIONS, "sequence", 8)
        with self.connection() as connection:
            connection.execute(
                f"""INSERT INTO {self.namespace}.{PUBLICATIONS}
                    SELECT 'publication-b', scope, previous_bundle_digest,
                           %s, 7, rollback_epoch, signing_key_id, bundle_json,
                           payload_digest, actor_id, withdrawn_credential_ids_json,
                           audit_event_json, status, attempts, last_error,
                           created_at, published_at
                    FROM {self.namespace}.{PUBLICATIONS}""",
                (digest("e"),),
            )
        with self.assertRaises(psycopg.errors.NoDataFound):
            self.projection()

    def test_witness_and_revocation_values_are_from_the_same_locked_high_water(self) -> None:
        before = self.projection()
        for field, value in (
            ("revocation_set_digest", digest("e")),
            ("witness_receipt_digest", digest("f")),
            ("witness_sequence", 12),
        ):
            self.update(HIGH_WATER, field, value)
            before[field] = value
            self.assertEqual(self.projection(), before)
        # This proves projection, not that these changed values authenticate.
        # The unchanged full executor compares their digest to signed evidence.

    def test_both_rows_remain_write_locked_until_transaction_ends(self) -> None:
        for table, field in ((HIGH_WATER, "witness_sequence"), (PUBLICATIONS, "attempts")):
            with self.subTest(table=table), self.connection(autocommit=False) as holder:
                self.assertEqual(holder.execute("SHOW transaction_isolation").fetchone(), ("serializable",))
                self.projection(holder)
                update = sql.SQL("UPDATE {}.{} SET {} = {}").format(
                    sql.Identifier(self.schema), sql.Identifier(table),
                    sql.Identifier(field), sql.Identifier(field),
                )
                with self.connection() as waiter:
                    with self.assertRaises(psycopg.errors.LockNotAvailable):
                        waiter.execute(update)
                    holder.rollback()
                    self.assertEqual(waiter.execute(update).rowcount, 1)

    def test_namespace_matches_existing_quoted_identifier_contract(self) -> None:
        self.assertIn('"serverware_metadata".', locked_webauthn_trust_projection('"serverware_metadata"'))
        for invalid in (None, "serverware_metadata", '"a"; SELECT 1', '"a-b"', '"A"', '"' + "a" * 129 + '"'):
            with self.subTest(namespace=invalid), self.assertRaises(ValueError):
                locked_webauthn_trust_projection(invalid)

    def test_connection_admission_rejects_tcp_and_configuration_overrides(self) -> None:
        for dsn, message in (
            ("host=127.0.0.1 dbname=postgres user=serverware", "one exact local Unix socket"),
            ("host=localhost dbname=postgres user=serverware", "one exact local Unix socket"),
            ("host=/ dbname=postgres user=serverware", "one exact local Unix socket"),
            ("hostaddr=127.0.0.1 dbname=postgres user=serverware", "unsupported override"),
            ("service=fixture", "unsupported override"),
            ("options=-cstatement_timeout=0", "unsupported override"),
            ("dbname=postgres user=serverware", "requires host, dbname, and user"),
        ):
            with self.subTest(dsn=dsn), patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(ValueError, message):
                    local_connection_parameters(dsn)
        with patch.dict(os.environ, {"PGSERVICE": "redirect"}, clear=True):
            with self.assertRaisesRegex(ValueError, "forbids ambient PG configuration"):
                local_connection_parameters("host=/fixture dbname=postgres user=serverware")

    def test_credential_policy_sql_matches_independent_sixteen_field_python_wire_and_digest(self) -> None:
        row = policy_credential()
        expected = independent_policy(row)
        self.assertEqual(len(expected), 16)
        self.assertEqual(set(expected), {
            "schema", "credentialRecordId", "credentialId", "userId", "authenticatorClass",
            "aaguid", "attestationTrusted", "attestationLeafDigest", "attestationRootDigest",
            "trustBundleDigest", "trustBundleSequence", "trustRollbackEpoch",
            "trustHighWaterDigest", "revocationSetDigest", "trustWitnessReceiptDigest", "publicKeyDigest",
        })
        actual = self.assert_policy_parity(row)
        self.assertTrue(actual[1].isascii())
        self.assertEqual(actual[0]["publicKeyDigest"], "sha256:" +
            hashlib.sha256("synthetic-key-雪🙂".encode("utf-8")).hexdigest())

    def test_aaguid_only_change_rejects_old_claim_in_component_predicate(self) -> None:
        row = policy_credential()
        before = self.assert_policy_parity(row)
        changed = {**row, "aaguid": "different-aaguid-雪"}
        after = self.assert_policy_parity(changed)
        self.assertEqual({key for key in before[0] if before[0][key] != after[0][key]}, {"aaguid"})
        self.assertNotEqual(before[1], after[1])
        self.assertNotEqual(before[2], after[2])
        wrong = self.credential_policy(changed, claim=before[2])
        self.assertEqual(wrong[:3], after[:3])
        self.assertIs(wrong[3], False)
        self.assertIs(self.credential_policy(changed, claim=digest("f"))[3], False)
        self.assertIsNone(self.credential_policy(changed, claim=None)[3])
        old_fifteen_fields = {key: value for key, value in before[0].items() if key != "aaguid"}
        self.assertIs(self.credential_policy(row,
            claim=policy_commitment(POLICY_DOMAIN, old_fifteen_fields))[3], False)
        # FALSE/UNKNOWN cannot satisfy this component's SQL equality. No
        # enclosing executor rejection, DML rollback or full-row CAS was run.

    def test_nullable_and_text_aaguid_values_preserve_exact_json_policy(self) -> None:
        commitments = []
        for value in (None, "", "null", "aaguid-雪🙂", 'quote"slash\\'):
            with self.subTest(aaguid=value):
                actual = self.assert_policy_parity({**policy_credential(), "aaguid": value})
                self.assertEqual(actual[0]["aaguid"], value)
                commitments.append(actual[2])
        self.assertEqual(len(set(commitments)), len(commitments))

    def test_missing_and_nonstring_aaguid_expose_expression_not_row_admission(self) -> None:
        row = policy_credential()
        null_row = {**row, "aaguid": None}
        null_policy = self.assert_policy_parity(null_row)
        missing = {key: value for key, value in row.items() if key != "aaguid"}
        self.assertEqual(self.credential_policy(missing, claim=null_policy[2]), null_policy)
        for malformed in (missing, *({**row, "aaguid": value} for value in (True, 7, [], {}))):
            with self.subTest(aaguid=malformed.get("aaguid", "missing")), \
                    self.assertRaises(trust.WebAuthnTrustError):
                trust.credential_policy_document(credential=malformed,
                    high_water=policy_high_water(), trust_high_water_digest=independent_policy(row)["trustHighWaterDigest"])
        for value in (True, 7, [], {}):
            malformed = {**row, "aaguid": value}
            expected = independent_policy(malformed)
            claim = policy_commitment(POLICY_DOMAIN, expected)
            self.assertEqual(self.credential_policy(malformed, claim=claim),
                             (expected, policy_wire(expected), claim, True))
        # JSON projection intentionally preserves these inputs. The fragment
        # cannot prove presence/type or replacement equality with stored TEXT;
        # those are the enclosing executor's separate row boundary, which this
        # component does not execute.


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--postgres-dsn", required=True)
    parser.add_argument("--prepared-result")
    arguments, test_arguments = parser.parse_known_args()
    CONNECTION_PARAMETERS = local_connection_parameters(arguments.postgres_dsn)
    run_native_fixture("scripts/test_webauthn_trust_projection_postgres.py",
        argv=[sys.argv[0], *test_arguments], result_path=arguments.prepared_result)
