"""PostgreSQL storage definitions for the fixed counted-index profiles.

These fresh-table definitions create no heads, privileges, triggers or defaults.
A head is only a counted-index checkpoint descriptor: association with primary
roots, complete population and enrollment require a separately admitted vector.
The dedicated tables are not primary-tree business or authorization tables.
The separate installer owns fresh-empty preparation and exact restart checks.

DDL enforces local representation, fixed source identity and bounded commitment
keys. It cannot prove record revisions are at most the locked head revision,
node/leaf hash agreement, full tree reconstruction or primary-row membership.
Those cross-row invariants still require maintenance and admission. In
particular, an absent head must not be interpreted as an enrolled empty tree.
"""
from __future__ import annotations

import re

from serverware import authority_index_contract as contract
from serverware import authority_index_projection as projection


COUNTED_STORE_TABLES = (
    "policy_authority_counted_index_heads",
    "policy_authority_counted_index_leaves",
    "policy_authority_counted_index_nodes",
)
COUNTED_HEAD_COLUMNS = (
    "index_id", "table_name", "counted_profile", "projection_digest",
    "projection_manifest_digest", "index_revision", "root_digest", "leaf_count",
)
COUNTED_LEAF_COLUMNS = (
    "index_id", "projection_digest", "index_key", "primary_id",
    "primary_key_digest", "primary_row_digest", "index_revision",
)
COUNTED_NODE_COLUMNS = (
    "index_id", "projection_digest", "depth", "path_prefix", "node_digest",
    "subtree_count", "index_revision",
)


def _digest_check(column: str) -> str:
    # Only the fixed source column names below call this private renderer.
    return (
        f"pg_catalog.octet_length({column}) = 71 "
        f"AND pg_catalog.substr({column}, 1, 7) COLLATE \"C\" = 'sha256:' COLLATE \"C\" "
        f"AND pg_catalog.translate(pg_catalog.substr({column}, 8), "
        "'0123456789abcdef', '') COLLATE \"C\" = '' COLLATE \"C\""
    )


def counted_store_ddl(namespace: str) -> tuple[str, str, str]:
    """Render heads, leaves and nodes in order for an exact quoted namespace.

    Both canonical and fixture namespaces use the same definitions. Source
    profile and empty-root literals are derived in Python; table creation does
    not depend on installing any PostgreSQL counted-hash functions.
    """
    if type(namespace) is not str or re.fullmatch(r'"[a-z][a-z0-9_]{0,62}"', namespace) is None:
        raise ValueError("counted store namespace must be an exact quoted identifier")
    profiles = tuple(projection.profile_for(index_id) for index_id in projection.INDEX_IDS)
    manifest_digest = projection.projection_manifest_digest()
    # All embedded values are validated source identifiers/canonical digests,
    # never caller-provided SQL or enrollment records.
    identities = ",\n                    ".join(
        f"('{profile.index_id}', '{profile.table}', '{profile.projection_digest}')"
        for profile in profiles
    )
    empty_roots = ",\n                    ".join(
        f"('{profile.index_id}', '{contract.empty_node(profile, '').digest}')"
        for profile in profiles
    )
    heads, leaves, nodes = (f'{namespace}."{table}"' for table in COUNTED_STORE_TABLES)
    return (
        f"""
        CREATE TABLE {heads} (
            index_id TEXT COLLATE "C" NOT NULL,
            table_name TEXT COLLATE "C" NOT NULL,
            counted_profile TEXT COLLATE "C" NOT NULL,
            projection_digest TEXT COLLATE "C" NOT NULL,
            projection_manifest_digest TEXT COLLATE "C" NOT NULL,
            index_revision BIGINT NOT NULL,
            root_digest TEXT COLLATE "C" NOT NULL,
            leaf_count BIGINT NOT NULL,
            CONSTRAINT counted_heads_pk PRIMARY KEY (index_id),
            CONSTRAINT counted_heads_projection_key UNIQUE (index_id, projection_digest),
            CONSTRAINT counted_heads_identity CHECK (
                (index_id, table_name, projection_digest) IN (
                    {identities}
                )
            ),
            CONSTRAINT counted_heads_profile CHECK (counted_profile = '{contract.PROFILE}'),
            CONSTRAINT counted_heads_manifest CHECK (projection_manifest_digest = '{manifest_digest}'),
            CONSTRAINT counted_heads_revision CHECK (index_revision >= 0),
            CONSTRAINT counted_heads_digest CHECK ({_digest_check('root_digest')}),
            CONSTRAINT counted_heads_count CHECK (leaf_count >= 0),
            CONSTRAINT counted_heads_genesis CHECK (index_revision <> 0 OR leaf_count = 0),
            CONSTRAINT counted_heads_empty_root CHECK (
                (leaf_count = 0) = ((index_id, root_digest) IN (
                    {empty_roots}
                ))
            )
        )
        """,
        f"""
        CREATE TABLE {leaves} (
            index_id TEXT COLLATE "C" NOT NULL,
            projection_digest TEXT COLLATE "C" NOT NULL,
            index_key TEXT COLLATE "C" NOT NULL,
            primary_id TEXT COLLATE "C" NOT NULL,
            primary_key_digest TEXT COLLATE "C" NOT NULL,
            primary_row_digest TEXT COLLATE "C" NOT NULL,
            index_revision BIGINT NOT NULL,
            CONSTRAINT counted_leaves_pk PRIMARY KEY (index_id, index_key),
            CONSTRAINT counted_leaves_primary_key UNIQUE (index_id, primary_key_digest),
            CONSTRAINT counted_leaves_head FOREIGN KEY (index_id, projection_digest)
                REFERENCES {heads} (index_id, projection_digest)
                ON UPDATE NO ACTION ON DELETE NO ACTION NOT DEFERRABLE INITIALLY IMMEDIATE,
            CONSTRAINT counted_leaves_key CHECK (
                pg_catalog.octet_length(index_key) = 160
                AND pg_catalog.translate(index_key, '0123456789abcdef', '') COLLATE "C" = '' COLLATE "C"
            ),
            CONSTRAINT counted_leaves_primary_id CHECK (
                pg_catalog.octet_length(pg_catalog.convert_to(primary_id, 'UTF8')) BETWEEN 0 AND 4096
            ),
            CONSTRAINT counted_leaves_key_digest CHECK ({_digest_check('primary_key_digest')}),
            CONSTRAINT counted_leaves_row_digest CHECK ({_digest_check('primary_row_digest')}),
            CONSTRAINT counted_leaves_suffix CHECK (
                pg_catalog.substr(index_key, 97) COLLATE "C" = pg_catalog.substr(primary_key_digest, 8) COLLATE "C"
            ),
            CONSTRAINT counted_leaves_revision CHECK (index_revision > 0)
        )
        """,
        f"""
        CREATE TABLE {nodes} (
            index_id TEXT COLLATE "C" NOT NULL,
            projection_digest TEXT COLLATE "C" NOT NULL,
            depth INTEGER NOT NULL,
            path_prefix TEXT COLLATE "C" NOT NULL,
            node_digest TEXT COLLATE "C" NOT NULL,
            subtree_count BIGINT NOT NULL,
            index_revision BIGINT NOT NULL,
            CONSTRAINT counted_nodes_pk PRIMARY KEY (index_id, depth, path_prefix),
            CONSTRAINT counted_nodes_head FOREIGN KEY (index_id, projection_digest)
                REFERENCES {heads} (index_id, projection_digest)
                ON UPDATE NO ACTION ON DELETE NO ACTION NOT DEFERRABLE INITIALLY IMMEDIATE,
            CONSTRAINT counted_nodes_depth CHECK (depth BETWEEN 1 AND 160),
            CONSTRAINT counted_nodes_prefix CHECK (
                pg_catalog.octet_length(path_prefix) = depth
                AND pg_catalog.translate(path_prefix, '0123456789abcdef', '') COLLATE "C" = '' COLLATE "C"
            ),
            CONSTRAINT counted_nodes_digest CHECK ({_digest_check('node_digest')}),
            CONSTRAINT counted_nodes_count CHECK (
                subtree_count > 0 AND subtree_count <= CASE
                    WHEN depth BETWEEN 145 AND 160 THEN (1::bigint << (4 * (160 - depth)))
                    ELSE 9223372036854775807::bigint
                END
            ),
            CONSTRAINT counted_nodes_revision CHECK (index_revision > 0)
        )
        """,
    )
