#!/usr/bin/env python3
"""Source fixtures for the actual fresh-only counted installation helper.

The deterministic connection checks statement scheduling and supplies explicit
catalog/head records. It is not a SQL parser or PostgreSQL execution claim.
Profile/genesis commitments use independent literal descriptor/tree oracles;
native transaction, lock and rollback behavior belongs to the native fixture.
All methods are authored, not executed in the source-only implementation phase.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate.authority_store import counted_installation as installation
from catchplate.authority_store import counted_hash_sql, counted_projection_sql
from catchplate.authority_store import counted_path_sql, counted_maintenance_sql, counted_store_sql
import test_authority_index_join as profile_oracle
import test_authority_index_range as tree_oracle


NAMESPACE = '"counted_installation_fixture"'
SOURCES = ("approval_grants", "control_plane_approvals", "oidc_browser_sessions",
    "oidc_session_activation_deliveries",
    "webauthn_challenges", "webauthn_credentials", "webauthn_trust_publications")
STORES = ("policy_authority_counted_index_heads", "policy_authority_counted_index_leaves",
          "policy_authority_counted_index_nodes")
FIELDS = ("index_id", "table_name", "counted_profile", "projection_digest",
          "projection_manifest_digest", "index_revision", "root_digest", "leaf_count")
INDEX_IDS = (
    "webauthn_credential_id", "webauthn_credential_user_history", "webauthn_credential_live_trust",
    "webauthn_registration_unused_global", "webauthn_registration_unused_user",
    "webauthn_session_credential_status", "webauthn_grant_approver_active",
    "webauthn_control_approval_approved", "webauthn_publication_bundle_digest",
    "webauthn_publication_status", "webauthn_publication_generation",
    "oidc_session_token_digest", "oidc_activation_delivery_session_id",
    "oidc_activation_delivery_old_token_digest", "oidc_activation_delivery_new_token_digest",
    "oidc_activation_delivery_assertion_digest", "oidc_activation_delivery_challenge_id",
)
I64 = 2**63 - 1


def descriptor(index_id):
    """Extend the independent oracle locally, never using the source registry."""
    if index_id in INDEX_IDS[:11]:
        return profile_oracle.descriptor(index_id)
    table, field, membership = {
        "oidc_session_token_digest": ("oidc_browser_sessions", "token_digest",
                                      "all-rows-including-expired-or-revoked"),
        "oidc_activation_delivery_session_id": ("oidc_session_activation_deliveries", "session_id",
                                                "all-rows-including-expired-or-consumed"),
        "oidc_activation_delivery_old_token_digest": ("oidc_session_activation_deliveries", "old_token_digest",
                                                      "all-rows-including-expired-or-consumed"),
        "oidc_activation_delivery_new_token_digest": ("oidc_session_activation_deliveries", "new_token_digest",
                                                      "all-rows-including-expired-or-consumed"),
        "oidc_activation_delivery_assertion_digest": ("oidc_session_activation_deliveries", "assertion_digest",
                                                      "all-rows-including-expired-or-consumed"),
        "oidc_activation_delivery_challenge_id": ("oidc_session_activation_deliveries", "challenge_id",
                                                  "all-rows-including-expired-or-consumed"),
    }[index_id]
    # The shared literal oracle supplies only the common descriptor vocabulary.
    result = profile_oracle.descriptor("webauthn_credential_id")
    result.update(indexId=index_id, table=table, rowFields=[["id", "text"], [field, "text"]],
                  selectorFields=[[field, "text"]], membership=membership,
                  partitionFields=[field], orderCodec="zero16", intervalRule="whole-equality-partition")
    return result


def expected_heads():
    manifest = profile_oracle.framed("catchplate.policyAuthorityIndexProjectionManifest/v1",
        profile_oracle.utf8_json([descriptor(name) for name in INDEX_IDS]))
    result = []
    for name in sorted(INDEX_IDS):
        document = descriptor(name)
        profile = profile_oracle.contract.IndexProfile(name, document["table"], profile_oracle.framed(
            "catchplate.policyAuthorityIndexProjectionDescriptor/v1", profile_oracle.utf8_json(document)))
        result.append({"index_id": name, "table_name": profile.table,
            "counted_profile": "catchplate.policyAuthorityCountedIndex/v1",
            "projection_digest": profile.projection_digest, "projection_manifest_digest": manifest,
            "index_revision": 0, "root_digest": tree_oracle.empty(profile, "")[0], "leaf_count": 0})
    return result


def catalog(store_count=0):
    names = sorted((*SOURCES, *STORES))
    return [{"relation_name": name, "relation_oid": 1000 + names.index(name),
        "relation_kind": "r", "persistence": "p", "is_partition": False,
        "has_inheritance": False} for name in names if name in SOURCES or name in STORES[:store_count]]


class Rows:
    def __init__(self, connection, rows):
        self.connection, self.rows = connection, rows

    def fetchmany(self, maximum):
        self.connection.fetch_bounds.append(maximum)
        # Deliberately do not truncate: the helper must reject an adapter that
        # returns an over-bound catalog/head result, independently of SQL LIMIT.
        return copy.deepcopy(self.rows)


class Connection:
    in_transaction = True

    def __init__(self, *, existing=False, catalogues=None, heads=None, populated=()):
        self.catalogue = catalog(3 if existing else 0)
        self.catalogues = list(copy.deepcopy(catalogues or []))
        self.heads = copy.deepcopy(expected_heads() if existing and heads is None else heads or [])
        self.populated = set(populated)
        self.statements, self.fetch_bounds = [], []
        self.ddl = counted_store_sql.counted_store_ddl(NAMESPACE)
        self.fail_sql = None

    def execute(self, sql, parameters=None):
        self.statements.append((sql, parameters))
        if sql == self.fail_sql:
            raise RuntimeError("fixture statement failure")
        if sql.startswith("SELECT relation.relname::pg_catalog.text"):
            if parameters != (NAMESPACE[1:-1], *sorted((*SOURCES, *STORES))):
                raise AssertionError("catalog query did not bind the exact source inventory")
            if not sql.endswith('ORDER BY relation.relname COLLATE "C" LIMIT 11'):
                raise AssertionError("catalog query is not bounded")
            return Rows(self, self.catalogues.pop(0) if self.catalogues else self.catalogue)
        if sql in {f'LOCK TABLE ONLY {NAMESPACE}."{name}" IN SHARE ROW EXCLUSIVE MODE'
                   for name in (*SOURCES, *STORES)}:
            if parameters is not None:
                raise AssertionError("fixed lock unexpectedly has parameters")
            return Rows(self, [])
        probes = {f'SELECT 1 AS present FROM ONLY {NAMESPACE}."{name}" LIMIT 1': name for name in SOURCES}
        if sql in probes:
            return Rows(self, [{"present": 1}] if probes[sql] in self.populated else [])
        if sql in self.ddl:
            name = STORES[self.ddl.index(sql)]
            self.catalogue += [row for row in catalog(3) if row["relation_name"] == name]
            return Rows(self, [])
        expected_insert = (f'INSERT INTO {NAMESPACE}."{STORES[0]}" (' + ", ".join(FIELDS)
                           + ") VALUES (" + ", ".join("?" for _ in FIELDS) + ")")
        if sql == expected_insert:
            if type(parameters) is not tuple or len(parameters) != 8:
                raise AssertionError("head insert is not the exact eight source fields")
            self.heads.append(dict(zip(FIELDS, parameters)))
            return Rows(self, [])
        if sql.startswith("SELECT CASE WHEN") and sql.endswith(f'FROM {NAMESPACE}."{STORES[0]}" AS head LIMIT 18'):
            if parameters is not None:
                raise AssertionError("head inventory must not filter corrupt or unknown rows")
            for name in FIELDS:
                if f" AS {name}" not in sql:
                    raise AssertionError("head inventory omitted a fixed column")
            return Rows(self, self.heads)
        raise AssertionError("unexpected SQL: " + sql)


def mutations(connection):
    return [sql for sql, _ in connection.statements
            if sql.lstrip().startswith(("CREATE ", "INSERT ", "UPDATE ", "DELETE ", "DROP ", "ALTER "))]


class AuthorityCountedInstallationTests(unittest.TestCase):
    def prepare(self, connection):
        return installation.prepare_counted_store(connection, NAMESPACE)

    def test_fresh_schedule_locks_every_source_before_empty_probes_and_real_ddl(self):
        connection = Connection()
        self.assertIsNone(self.prepare(connection))
        sql = [item[0] for item in connection.statements]
        self.assertEqual(len(sql), 37)
        self.assertEqual(sql[1:8], [f'LOCK TABLE ONLY {NAMESPACE}."{name}" IN SHARE ROW EXCLUSIVE MODE'
                                   for name in SOURCES])
        self.assertEqual(sql[9:16], [f'SELECT 1 AS present FROM ONLY {NAMESPACE}."{name}" LIMIT 1'
                                    for name in SOURCES])
        self.assertEqual(tuple(sql[16:19]), counted_store_sql.counted_store_ddl(NAMESPACE))
        self.assertEqual(connection.heads, expected_heads())
        self.assertEqual(len(connection.heads), 17)
        self.assertEqual(connection.fetch_bounds, [11, 11, *([1] * 7), 18])
        self.assertEqual(len(mutations(connection)), 20)
        self.assertFalse(any(statement.strip().startswith(("BEGIN", "COMMIT", "ROLLBACK", "GRANT", "REVOKE"))
                             for statement in sql))

    def test_existing_complete_heads_never_seed_or_probe_source_populations(self):
        heads = expected_heads()
        heads[0].update(index_revision=I64, leaf_count=I64, root_digest="sha256:" + "f" * 64)
        heads[1]["index_revision"] = 7  # Empty is legitimate after nonzero history.
        connection = Connection(existing=True, heads=list(reversed(heads)), populated=SOURCES)
        self.assertIsNone(self.prepare(connection))
        self.assertFalse(mutations(connection))
        self.assertFalse(any("SELECT 1 AS present" in sql for sql, _ in connection.statements))
        locks = [sql for sql, _ in connection.statements if sql.startswith("LOCK ")]
        self.assertEqual(locks, [f'LOCK TABLE ONLY {NAMESPACE}."{name}" IN SHARE ROW EXCLUSIVE MODE'
                                for name in (*SOURCES, *sorted(STORES))])
        self.assertEqual(connection.fetch_bounds, [11, 11, 11, 18])

    def test_every_populated_source_denies_fresh_genesis_before_any_store_write(self):
        for name in SOURCES:
            with self.subTest(table=name):
                connection = Connection(populated=(name,))
                with self.assertRaisesRegex(installation.CountedInstallationError, "offline restage"):
                    self.prepare(connection)
                self.assertFalse(mutations(connection))
                self.assertEqual(len([sql for sql, _ in connection.statements if sql.startswith("LOCK ")]), 7)

    def test_partial_store_and_missing_source_inventories_deny_without_repair(self):
        for rows in (catalog(1), catalog(2), catalog(0)[1:], catalog(3)[1:]):
            connection = Connection(catalogues=[rows])
            with self.assertRaises(installation.CountedInstallationError):
                self.prepare(connection)
            self.assertFalse(mutations(connection))

    def test_wrong_relation_kinds_persistence_partition_and_inheritance_are_closed(self):
        for name in (SOURCES[0], STORES[0]):
            for field, value in (("relation_kind", "v"), ("relation_kind", "p"),
                                 ("relation_kind", "f"), ("persistence", "t"),
                                 ("persistence", "u"), ("is_partition", True),
                                 ("is_partition", 0), ("has_inheritance", True)):
                with self.subTest(table=name, field=field, value=value):
                    rows = catalog(3)
                    next(row for row in rows if row["relation_name"] == name)[field] = value
                    connection = Connection(existing=True, catalogues=[rows])
                    with self.assertRaises(installation.CountedInstallationError):
                        self.prepare(connection)
                    self.assertFalse(mutations(connection))

    def test_catalog_rows_are_closed_unique_bounded_and_have_exact_oids(self):
        bad_rows = []
        for delta in ({"relation_oid": True}, {"relation_oid": 0}, {"relation_oid": 2**32},
                      {"relation_name": "unknown"}, {"relation_name": "x" * 64}, {"extra": 1}):
            rows = catalog(0)
            rows[0].update(delta)
            bad_rows.append(rows)
        bad_rows += [catalog(0) + [catalog(0)[0]], catalog(3) + [catalog(3)[0]]]
        for rows in bad_rows:
            connection = Connection(catalogues=[rows])
            with self.assertRaises(installation.CountedInstallationError):
                self.prepare(connection)
            self.assertEqual(len(connection.statements), 1)

    def test_existing_missing_extra_duplicate_or_unknown_heads_are_never_filled(self):
        heads = expected_heads()
        unknown = copy.deepcopy(heads)
        unknown[0]["index_id"] = "unknown"
        for rows in (heads[:-1], heads + [heads[0]], [heads[0], *heads[0:-1]], unknown):
            connection = Connection(existing=True, heads=rows)
            with self.assertRaises(installation.CountedInstallationError):
                self.prepare(connection)
            self.assertFalse(mutations(connection))

    def test_existing_eleven_head_store_is_rejected_without_repair(self):
        heads = [row for row in expected_heads() if row["index_id"] in INDEX_IDS[:11]]
        self.assertEqual(len(heads), 11)
        connection = Connection(existing=True, heads=heads)
        with self.assertRaisesRegex(installation.CountedInstallationError, "complete seventeen-head inventory"):
            self.prepare(connection)
        self.assertFalse(mutations(connection))

    def test_changed_source_profile_cardinality_or_duplicate_identity_precedes_sql(self):
        for identities in (INDEX_IDS[:-1], (*INDEX_IDS, INDEX_IDS[0]), (INDEX_IDS[0], *INDEX_IDS[:-1])):
            connection = Connection()
            with mock.patch.object(installation.projection, "INDEX_IDS", identities):
                with self.assertRaisesRegex(installation.CountedInstallationError, "source inventory changed"):
                    self.prepare(connection)
            self.assertEqual(connection.statements, [])

    def test_existing_source_profile_manifest_and_closed_head_shapes_are_exact(self):
        for delta in ({"table_name": "other"}, {"counted_profile": "other"},
                      {"projection_digest": "sha256:" + "0" * 64},
                      {"projection_manifest_digest": "sha256:" + "0" * 64},
                      {"extra": 1}, {"index_id": None}, {"index_id": "x" * 129}):
            heads = expected_heads()
            heads[0].update(delta)
            connection = Connection(existing=True, heads=heads)
            with self.assertRaises(installation.CountedInstallationError):
                self.prepare(connection)
            self.assertFalse(mutations(connection))

    def test_existing_revision_count_and_canonical_empty_equivalence_are_exact(self):
        for delta in ({"index_revision": True}, {"index_revision": -1}, {"index_revision": I64 + 1},
                      {"leaf_count": False}, {"leaf_count": -1}, {"leaf_count": I64 + 1},
                      {"leaf_count": 1}, {"root_digest": "sha256:" + "f" * 64},
                      {"index_revision": 1, "leaf_count": 1}, {"root_digest": "sha256:" + "F" * 64},
                      {"root_digest": None}, {"root_digest": "x" * 72}):
            heads = expected_heads()
            heads[0].update(delta)
            connection = Connection(existing=True, heads=heads)
            with self.assertRaises(installation.CountedInstallationError):
                self.prepare(connection)
            self.assertFalse(mutations(connection))

    def test_source_and_existing_store_identity_cannot_change_across_locks(self):
        source_changed = catalog(0)
        source_changed[0]["relation_oid"] += 20
        store_changed = catalog(3)
        next(row for row in store_changed if row["relation_name"] == STORES[0])["relation_oid"] += 20
        for catalogues in ((catalog(0), source_changed), (catalog(3), catalog(0)),
                           (catalog(3), store_changed), (catalog(3), catalog(3), store_changed)):
            connection = Connection(existing=True, catalogues=catalogues)
            with self.assertRaises(installation.CountedInstallationError):
                self.prepare(connection)
            self.assertFalse(mutations(connection))

    def test_complete_store_appearing_while_source_lock_waits_is_validated_not_recreated(self):
        connection = Connection(existing=True, catalogues=[catalog(0), catalog(3), catalog(3)])
        self.assertIsNone(self.prepare(connection))
        self.assertFalse(mutations(connection))
        self.assertEqual(connection.fetch_bounds, [11, 11, 11, 18])

    def test_exact_namespace_and_active_transaction_guards_precede_sql(self):
        for namespace in (None, "public", '"a";SELECT 1', '"A"', '"' + "a" * 64 + '"'):
            connection = Connection()
            with self.assertRaises(installation.CountedInstallationError):
                installation.prepare_counted_store(connection, namespace)
            self.assertEqual(connection.statements, [])
        for state in (False, None, 1, "active"):
            connection = Connection()
            connection.in_transaction = state
            with self.assertRaises(installation.CountedInstallationError):
                self.prepare(connection)
            self.assertEqual(connection.statements, [])

    def test_statement_failure_propagates_without_transaction_control_or_repair(self):
        connection = Connection()
        connection.fail_sql = connection.ddl[1]
        with self.assertRaisesRegex(RuntimeError, "fixture statement failure"):
            self.prepare(connection)
        self.assertEqual(connection.statements[-1][0], connection.ddl[1])
        self.assertEqual(connection.heads, [])
        self.assertFalse(any(sql.startswith(("COMMIT", "ROLLBACK", "DROP", "DELETE"))
                             for sql, _ in connection.statements))

    def test_function_aggregation_and_source_contract_use_real_renderers_and_independent_genesis(self):
        expected_functions = (counted_hash_sql.counted_hash_functions_sql(NAMESPACE)
            + counted_projection_sql.counted_projection_functions_sql(NAMESPACE)
            + counted_path_sql.counted_path_functions_sql(NAMESPACE)
            + counted_maintenance_sql.counted_maintenance_functions_sql(NAMESPACE))
        self.assertEqual(len(expected_functions), 11)
        self.assertEqual(installation.counted_functions_sql(NAMESPACE), expected_functions)
        contract = installation.counted_installation_contract()
        self.assertEqual(set(contract), {"schema", "profile", "sourceTables", "storeTables", "ddl", "functions", "genesisHeads"})
        self.assertEqual(contract["schema"], "catchplate.policyAuthorityCountedInstallation/v1")
        self.assertEqual(contract["profile"], "transaction-locked-fresh-empty-or-exact-existing-no-repair/v1")
        self.assertEqual(contract["sourceTables"], list(SOURCES))
        self.assertEqual(contract["storeTables"], list(STORES))
        self.assertEqual(contract["genesisHeads"], expected_heads())
        canonical = '"catchplate_metadata"'
        self.assertEqual(contract["ddl"], list(counted_store_sql.counted_store_ddl(canonical)))
        self.assertEqual(contract["functions"], list(
            counted_hash_sql.counted_hash_functions_sql(canonical)
            + counted_projection_sql.counted_projection_functions_sql(canonical)
            + counted_path_sql.counted_path_functions_sql(canonical)
            + counted_maintenance_sql.counted_maintenance_functions_sql(canonical)))
        contract["genesisHeads"][0]["leaf_count"] = 5
        self.assertEqual(installation.counted_installation_contract()["genesisHeads"], expected_heads())

    def test_delivery_dispatch_uses_exact_five_profiles_and_rejects_six(self):
        table = "oidc_session_activation_deliveries"
        delivery_ids = (
            "oidc_activation_delivery_assertion_digest", "oidc_activation_delivery_challenge_id",
            "oidc_activation_delivery_new_token_digest", "oidc_activation_delivery_old_token_digest",
            "oidc_activation_delivery_session_id",
        )
        sql, = counted_maintenance_sql.counted_maintenance_functions_sql(NAMESPACE)
        prefix = f"WHEN '{table}' THEN ARRAY["
        cases = [line.strip() for line in sql.splitlines() if line.strip().startswith(prefix)]
        self.assertEqual(cases, [prefix + ", ".join(f"'{name}'" for name in delivery_ids) + "]::text[]"])
        real_index_ids = counted_maintenance_sql.projection.index_ids_for_table
        # Refusal-only source perturbation, not an admitted production profile.
        with mock.patch.object(counted_maintenance_sql.projection, "index_ids_for_table",
                side_effect=lambda name: (*delivery_ids, "oidc_activation_delivery_extra")
                if name == table else real_index_ids(name)):
            with self.assertRaisesRegex(ValueError, "fanout exceeds its fixed bound"):
                counted_maintenance_sql.counted_maintenance_functions_sql(NAMESPACE)


if __name__ == "__main__":
    unittest.main()
