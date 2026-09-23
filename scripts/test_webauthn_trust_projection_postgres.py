#!/usr/bin/env python3
"""Real PostgreSQL coverage of the shared v9 trust projection, not full v9.

An external prepared runner owns a disposable no-network PostgreSQL engine and
its lifecycle. This test accepts only its local Unix socket, creates one random
schema, and drops that exact schema. It never starts Docker, provisions trust,
imports the blocked registry, or substitutes a successful authority admission.
The table declarations come from the pure production schema source; the executed
projection comes from the same helper interpolated into the production executor.
Root authentication, predicate completeness, the full executor, and migrations
are deliberately outside this engineering proof boundary.
"""
from __future__ import annotations

import argparse
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

from serverware.authority_store.webauthn_trust_sql import (
    locked_webauthn_trust_projection,
)
from serverware.authority_store.metadata_schema_source import metadata_base_schema_source


CONNECTION_PARAMETERS: dict[str, str | int] | None = None
PUBLICATIONS = "webauthn_trust_publications"
HIGH_WATER = "webauthn_trust_publication_high_water"


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
            if connection.execute("SELECT inet_server_addr()").fetchone() != (None,):
                raise RuntimeError("PostgreSQL fixture must use a Unix socket")
            connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(cls.schema)))
        cls.addClassCleanup(cls.drop_schema)
        with cls.connection() as connection:
            connection.execute(
                sql.SQL("SET search_path TO {}, pg_catalog").format(sql.Identifier(cls.schema))
            )
            for declaration in production_table_declarations():
                connection.execute(declaration)
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--postgres-dsn", required=True)
    parser.add_argument("--prepared-result")
    arguments, test_arguments = parser.parse_known_args()
    CONNECTION_PARAMETERS = local_connection_parameters(arguments.postgres_dsn)
    run_native_fixture("scripts/test_webauthn_trust_projection_postgres.py",
        argv=[sys.argv[0], *test_arguments], result_path=arguments.prepared_result)
