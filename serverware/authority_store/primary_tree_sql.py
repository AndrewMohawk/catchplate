"""Exact source-installed SQL for the persisted primary authenticated tree.

These renderers do not connect, install, bootstrap roots, attach triggers, grant
privileges, or authenticate root currentness. The installer and native component
fixtures use the same definitions. The tree serializer deliberately retains its
UTF-8 PostgreSQL JSON spelling; it is not the ASCII canonical wire serializer.
Function body whitespace and substitution names are retained from db.py so the
existing source fingerprints can audit this extraction.
"""
from __future__ import annotations

import re

from serverware import authority_contract


TREE_JSON_MAX_BYTES = 72 * 1024 * 1024
_POLICY_AUTHORITY_VERIFIER_RESPONSE_MAX_BYTES = TREE_JSON_MAX_BYTES
_POLICY_AUTHORITY_AUTHENTICATED_TREE_DEPTH = authority_contract.TREE_DEPTH
_POLICY_AUTHORITY_AUTHENTICATED_TREE_RADIX = authority_contract.TREE_RADIX


def _namespace(namespace: str) -> str:
    if type(namespace) is not str or re.fullmatch(
        r'"[a-z][a-z0-9_]{0,62}"', namespace
    ) is None:
        raise ValueError("primary tree namespace must be an exact quoted identifier")
    return namespace


def canonical_json_function_sql(namespace: str) -> str:
    """Render the existing bounded UTF-8 persisted-tree JSON serializer."""
    guard_namespace = _namespace(namespace)
    return f"""
            CREATE OR REPLACE FUNCTION {guard_namespace}.
                serverware_policy_authority_canonical_json(
                    input_value pg_catalog.jsonb
                )
            RETURNS text
            LANGUAGE plpgsql
            IMMUTABLE
            STRICT
            SET search_path = pg_catalog, {guard_namespace}, pg_temp
            AS $serverware_canonical$
            DECLARE
                value_kind text;
                rendered text;
            BEGIN
                value_kind := pg_catalog.jsonb_typeof(input_value);
                IF value_kind = 'object' THEN
                    SELECT '{{' || COALESCE(
                        pg_catalog.string_agg(
                            pg_catalog.to_jsonb(member.key)::text || ':' ||
                            {guard_namespace}.
                                serverware_policy_authority_canonical_json(
                                    member.value
                                ),
                            ',' ORDER BY member.key COLLATE "C"
                        ),
                        ''
                    ) || '}}'
                    INTO rendered
                    FROM pg_catalog.jsonb_each(input_value) AS member;
                ELSIF value_kind = 'array' THEN
                    SELECT '[' || COALESCE(
                        pg_catalog.string_agg(
                            {guard_namespace}.
                                serverware_policy_authority_canonical_json(
                                    member.value
                                ),
                            ',' ORDER BY member.ordinality
                        ),
                        ''
                    ) || ']'
                    INTO rendered
                    FROM pg_catalog.jsonb_array_elements(input_value)
                        WITH ORDINALITY AS member(value, ordinality);
                ELSIF value_kind IN (
                    'string', 'number', 'boolean', 'null'
                ) THEN
                    rendered := input_value::text;
                ELSE
                    RAISE EXCEPTION
                        'authority canonical JSON type is unsupported';
                END IF;
                IF pg_catalog.octet_length(rendered) >
                    {_POLICY_AUTHORITY_VERIFIER_RESPONSE_MAX_BYTES}
                THEN
                    RAISE EXCEPTION
                        'authority canonical JSON exceeds its fixed bound';
                END IF;
                RETURN rendered;
            END;
            $serverware_canonical$
            """


def framed_digest_function_sql(namespace: str) -> str:
    """Render the existing domain-length and frame-length tree digest helper."""
    guard_namespace = _namespace(namespace)
    return f"""
            CREATE OR REPLACE FUNCTION {guard_namespace}.
                serverware_policy_authority_framed_digest(
                    digest_domain text,
                    VARIADIC digest_frames text[]
                )
            RETURNS text
            LANGUAGE plpgsql
            IMMUTABLE
            STRICT
            SET search_path = pg_catalog, {guard_namespace}, pg_temp
            AS $serverware_framed_digest$
            DECLARE
                digest_material bytea;
                encoded_domain bytea;
                encoded_frame bytea;
                frame text;
            BEGIN
                IF pg_catalog.octet_length(digest_domain) NOT BETWEEN 1 AND 256
                    OR pg_catalog.cardinality(digest_frames) NOT BETWEEN 1 AND 8
                THEN
                    RAISE EXCEPTION
                        'authority framed digest is outside its fixed bound';
                END IF;
                encoded_domain :=
                    pg_catalog.convert_to(digest_domain, 'UTF8');
                digest_material := pg_catalog.int8send(
                    pg_catalog.octet_length(encoded_domain)::bigint
                ) || encoded_domain;
                FOREACH frame IN ARRAY digest_frames LOOP
                    IF frame IS NULL THEN
                        RAISE EXCEPTION
                            'authority framed digest frame cannot be null';
                    END IF;
                    encoded_frame := pg_catalog.convert_to(frame, 'UTF8');
                    IF pg_catalog.octet_length(encoded_frame) >
                        {_POLICY_AUTHORITY_VERIFIER_RESPONSE_MAX_BYTES}
                    THEN
                        RAISE EXCEPTION
                            'authority framed digest frame exceeds its bound';
                    END IF;
                    digest_material := digest_material ||
                        pg_catalog.int8send(
                            pg_catalog.octet_length(encoded_frame)::bigint
                        ) || encoded_frame;
                END LOOP;
                RETURN 'sha256:' || pg_catalog.encode(
                    pg_catalog.sha256(digest_material), 'hex'
                );
            END;
            $serverware_framed_digest$
            """


def authenticated_tree_functions_sql(
    namespace: str, *, manifest_digest: str
) -> tuple[str, ...]:
    """Render empty, apply and trigger definitions, in dependency order.

    The manifest digest and 64-level/16-way dimensions are source-owned inputs;
    this renderer does not establish that a supplied digest is trusted. Existing
    root bootstrap, trigger attachments, root CAS and ACL admission stay with
    their respective installer and transaction callers.
    """
    guard_namespace = _namespace(namespace)
    if type(manifest_digest) is not str or re.fullmatch(
        r"sha256:[0-9a-f]{64}", manifest_digest
    ) is None:
        raise ValueError("primary tree manifest digest must be canonical SHA-256")
    authority_query_manifest_digest_sql = manifest_digest
    return (
        f"""
            CREATE OR REPLACE FUNCTION {guard_namespace}.
                serverware_policy_authority_authenticated_empty(
                    empty_depth integer
                )
            RETURNS text
            LANGUAGE plpgsql
            IMMUTABLE
            STRICT
            SET search_path = pg_catalog, {guard_namespace}, pg_temp
            AS $serverware_authenticated_empty$
            DECLARE
                empty_child text;
                empty_children pg_catalog.jsonb;
            BEGIN
                IF empty_depth NOT BETWEEN 0 AND
                    {_POLICY_AUTHORITY_AUTHENTICATED_TREE_DEPTH}
                THEN
                    RAISE EXCEPTION
                        'authenticated-tree empty depth is invalid';
                END IF;
                IF empty_depth =
                    {_POLICY_AUTHORITY_AUTHENTICATED_TREE_DEPTH}
                THEN
                    RETURN {guard_namespace}.
                        serverware_policy_authority_framed_digest(
                            'serverware.policyAuthorityAuthenticatedEmptyLeaf/v1',
                            empty_depth::text
                        );
                END IF;
                empty_child := {guard_namespace}.
                    serverware_policy_authority_authenticated_empty(
                        empty_depth + 1
                    );
                SELECT pg_catalog.jsonb_agg(
                    empty_child ORDER BY ordinal
                )
                INTO empty_children
                FROM pg_catalog.generate_series(
                    1,
                    {_POLICY_AUTHORITY_AUTHENTICATED_TREE_RADIX}
                ) AS ordinal;
                RETURN {guard_namespace}.
                    serverware_policy_authority_framed_digest(
                        'serverware.policyAuthorityAuthenticatedNode/v1',
                        empty_depth::text,
                        {guard_namespace}.
                            serverware_policy_authority_canonical_json(
                                empty_children
                            )
                    );
            END;
            $serverware_authenticated_empty$
            """,
        f"""
            CREATE OR REPLACE FUNCTION {guard_namespace}.
                serverware_policy_authority_authenticated_apply(
                    authenticated_table text,
                    authenticated_key pg_catalog.jsonb,
                    authenticated_row pg_catalog.jsonb,
                    mutation_operation text
                )
            RETURNS void
            LANGUAGE plpgsql
            SECURITY DEFINER
            VOLATILE
            SET search_path = pg_catalog, {guard_namespace}, pg_temp
            AS $serverware_authenticated_apply$
            DECLARE
                current_root record;
                existing_leaf record;
                canonical_key text;
                canonical_row text;
                authenticated_key_digest text;
                row_digest text;
                leaf_digest text;
                parent_digest text;
                previous_root_digest text;
                child_digests pg_catalog.jsonb;
                empty_child text;
                empty_children pg_catalog.jsonb;
                current_prefix text;
                new_revision bigint;
                new_leaf_count bigint;
                current_depth integer;
                child_count integer;
                now_epoch_ns numeric;
            BEGIN
                IF mutation_operation NOT IN ('INSERT', 'UPDATE', 'DELETE')
                    OR pg_catalog.jsonb_typeof(authenticated_key) <> 'object'
                    OR (
                        authenticated_row IS NOT NULL
                        AND pg_catalog.jsonb_typeof(authenticated_row) <>
                            'object'
                    )
                THEN
                    RAISE EXCEPTION
                        'authenticated-tree mutation is invalid';
                END IF;
                SELECT *
                INTO current_root
                FROM {guard_namespace}.
                    policy_authority_authenticated_table_roots AS root
                WHERE root.table_name = authenticated_table
                FOR UPDATE;
                IF NOT FOUND
                    OR current_root.manifest_digest <>
                        '{authority_query_manifest_digest_sql}'
                    OR current_root.tree_depth <>
                        {_POLICY_AUTHORITY_AUTHENTICATED_TREE_DEPTH}
                    OR current_root.tree_radix <>
                        {_POLICY_AUTHORITY_AUTHENTICATED_TREE_RADIX}
                THEN
                    RAISE EXCEPTION
                        'authenticated-tree root contract is unavailable';
                END IF;
                canonical_key := {guard_namespace}.
                    serverware_policy_authority_canonical_json(
                        authenticated_key
                    );
                authenticated_key_digest := {guard_namespace}.
                    serverware_policy_authority_framed_digest(
                        'serverware.policyAuthorityAuthenticatedKey/v1',
                        authenticated_table,
                        canonical_key
                    );
                SELECT *
                INTO existing_leaf
                FROM {guard_namespace}.
                    policy_authority_authenticated_leaves AS leaf
                WHERE leaf.table_name = authenticated_table
                  AND leaf.key_digest = authenticated_key_digest
                FOR UPDATE;
                IF FOUND
                    AND existing_leaf.key_json IS DISTINCT FROM canonical_key
                THEN
                    RAISE EXCEPTION
                        'authenticated-tree canonical key digest collision';
                END IF;
                IF (
                    mutation_operation = 'INSERT'
                    AND existing_leaf IS NOT NULL
                ) OR (
                    mutation_operation = 'UPDATE'
                    AND existing_leaf IS NULL
                ) OR (
                    mutation_operation = 'DELETE'
                    AND (
                        existing_leaf IS NULL
                        OR authenticated_row IS NOT NULL
                    )
                ) OR (
                    mutation_operation IN ('INSERT', 'UPDATE')
                    AND authenticated_row IS NULL
                ) THEN
                    RAISE EXCEPTION
                        'authenticated-tree mutation lifecycle is not exact';
                END IF;
                previous_root_digest := current_root.root_digest;
                new_revision := current_root.root_revision + 1;
                new_leaf_count := current_root.leaf_count;
                IF authenticated_row IS NULL THEN
                    DELETE FROM {guard_namespace}.
                        policy_authority_authenticated_leaves
                    WHERE table_name = authenticated_table
                      AND key_digest = authenticated_key_digest;
                    DELETE FROM {guard_namespace}.
                        policy_authority_authenticated_tree_nodes
                    WHERE table_name = authenticated_table
                      AND depth =
                        {_POLICY_AUTHORITY_AUTHENTICATED_TREE_DEPTH}
                      AND path_prefix = pg_catalog.substr(
                            authenticated_key_digest, 8,
                            {_POLICY_AUTHORITY_AUTHENTICATED_TREE_DEPTH}
                      );
                    new_leaf_count := new_leaf_count - 1;
                    row_digest := NULL;
                ELSE
                    canonical_row := {guard_namespace}.
                        serverware_policy_authority_canonical_json(
                            authenticated_row
                        );
                    row_digest := {guard_namespace}.
                        serverware_policy_authority_framed_digest(
                            'serverware.policyAuthorityAuthenticatedRow/v1',
                            authenticated_table,
                            canonical_row
                        );
                    leaf_digest := {guard_namespace}.
                        serverware_policy_authority_framed_digest(
                            'serverware.policyAuthorityAuthenticatedLeaf/v1',
                            authenticated_table,
                            authenticated_key_digest,
                            canonical_key,
                            row_digest
                        );
                    INSERT INTO {guard_namespace}.
                        policy_authority_authenticated_leaves (
                            table_name, key_digest, key_json, row_digest,
                            leaf_digest, root_revision
                        ) VALUES (
                            authenticated_table, authenticated_key_digest,
                            canonical_key,
                            row_digest, leaf_digest, new_revision
                        )
                    ON CONFLICT (table_name, key_digest) DO UPDATE
                    SET key_json = EXCLUDED.key_json,
                        row_digest = EXCLUDED.row_digest,
                        leaf_digest = EXCLUDED.leaf_digest,
                        root_revision = EXCLUDED.root_revision;
                    INSERT INTO {guard_namespace}.
                        policy_authority_authenticated_tree_nodes (
                            table_name, depth, path_prefix, node_digest,
                            root_revision
                        ) VALUES (
                            authenticated_table,
                            {_POLICY_AUTHORITY_AUTHENTICATED_TREE_DEPTH},
                            pg_catalog.substr(
                                authenticated_key_digest, 8,
                                {_POLICY_AUTHORITY_AUTHENTICATED_TREE_DEPTH}
                            ),
                            leaf_digest, new_revision
                        )
                    ON CONFLICT (table_name, depth, path_prefix) DO UPDATE
                    SET node_digest = EXCLUDED.node_digest,
                        root_revision = EXCLUDED.root_revision;
                    IF existing_leaf IS NULL THEN
                        new_leaf_count := new_leaf_count + 1;
                    END IF;
                END IF;
                empty_child := {guard_namespace}.
                    serverware_policy_authority_authenticated_empty(
                        {_POLICY_AUTHORITY_AUTHENTICATED_TREE_DEPTH}
                    );
                FOR current_depth IN REVERSE
                    {_POLICY_AUTHORITY_AUTHENTICATED_TREE_DEPTH - 1}..0
                LOOP
                    current_prefix := pg_catalog.substr(
                        authenticated_key_digest, 8, current_depth
                    );
                    SELECT
                        pg_catalog.jsonb_agg(
                            COALESCE(
                                node.node_digest,
                                empty_child
                            )
                            ORDER BY child.ordinality
                        ),
                        pg_catalog.count(node.node_digest)
                    INTO child_digests, child_count
                    FROM pg_catalog.unnest(
                        ARRAY[
                            '0','1','2','3','4','5','6','7',
                            '8','9','a','b','c','d','e','f'
                        ]::text[]
                    ) WITH ORDINALITY AS child(value, ordinality)
                    LEFT JOIN {guard_namespace}.
                        policy_authority_authenticated_tree_nodes AS node
                      ON node.table_name = authenticated_table
                     AND node.depth = current_depth + 1
                     AND node.path_prefix =
                        current_prefix || child.value;
                    IF child_count = 0 AND current_depth > 0 THEN
                        DELETE FROM {guard_namespace}.
                            policy_authority_authenticated_tree_nodes
                        WHERE table_name = authenticated_table
                          AND depth = current_depth
                          AND path_prefix = current_prefix;
                    ELSE
                        parent_digest := {guard_namespace}.
                            serverware_policy_authority_framed_digest(
                                'serverware.policyAuthorityAuthenticatedNode/v1',
                                current_depth::text,
                                {guard_namespace}.
                                    serverware_policy_authority_canonical_json(
                                        child_digests
                                    )
                            );
                        INSERT INTO {guard_namespace}.
                            policy_authority_authenticated_tree_nodes (
                                table_name, depth, path_prefix, node_digest,
                                root_revision
                            ) VALUES (
                                authenticated_table, current_depth,
                                current_prefix, parent_digest, new_revision
                            )
                        ON CONFLICT (
                            table_name, depth, path_prefix
                        ) DO UPDATE
                        SET node_digest = EXCLUDED.node_digest,
                            root_revision = EXCLUDED.root_revision;
                    END IF;
                    -- At depth d, empty_child is E[d+1]. Advance the same
                    -- empty ladder once, including when DELETE prunes a node.
                    SELECT pg_catalog.jsonb_agg(
                        empty_child ORDER BY ordinal
                    )
                    INTO empty_children
                    FROM pg_catalog.generate_series(
                        1,
                        {_POLICY_AUTHORITY_AUTHENTICATED_TREE_RADIX}
                    ) AS ordinal;
                    empty_child := {guard_namespace}.
                        serverware_policy_authority_framed_digest(
                            'serverware.policyAuthorityAuthenticatedNode/v1',
                            current_depth::text,
                            {guard_namespace}.
                                serverware_policy_authority_canonical_json(
                                    empty_children
                                )
                        );
                END LOOP;
                SELECT node_digest
                INTO parent_digest
                FROM {guard_namespace}.
                    policy_authority_authenticated_tree_nodes
                WHERE table_name = authenticated_table
                  AND depth = 0
                  AND path_prefix = '';
                parent_digest := COALESCE(
                    parent_digest,
                    empty_child
                );
                now_epoch_ns := pg_catalog.floor(
                    pg_catalog.extract(
                        'epoch', pg_catalog.clock_timestamp()
                    ) * 1000000000
                );
                UPDATE {guard_namespace}.
                    policy_authority_authenticated_table_roots
                SET root_revision = new_revision,
                    root_digest = parent_digest,
                    leaf_count = new_leaf_count,
                    updated_at_epoch_ns = now_epoch_ns
                WHERE table_name = authenticated_table
                  AND root_revision = current_root.root_revision;
                IF NOT FOUND THEN
                    RAISE EXCEPTION
                        'authenticated-tree root CAS failed';
                END IF;
                INSERT INTO {guard_namespace}.
                    policy_authority_authenticated_root_revisions (
                        table_name, root_revision, previous_root_digest,
                        root_digest, leaf_count, mutation_operation,
                        mutation_key_digest, mutation_row_digest,
                        transaction_id, committed_at_epoch_ns
                    ) VALUES (
                        authenticated_table, new_revision,
                        previous_root_digest, parent_digest, new_leaf_count,
                        mutation_operation, authenticated_key_digest,
                        row_digest,
                        pg_catalog.txid_current()::text,
                        now_epoch_ns
                    );
            END;
            $serverware_authenticated_apply$
            """,
        f"""
            CREATE OR REPLACE FUNCTION {guard_namespace}.
                serverware_policy_authority_authenticated_trigger()
            RETURNS trigger
            LANGUAGE plpgsql
            SECURITY DEFINER
            VOLATILE
            SET search_path = pg_catalog, {guard_namespace}, pg_temp
            AS $serverware_authenticated_trigger$
            DECLARE
                old_row pg_catalog.jsonb;
                new_row pg_catalog.jsonb;
                old_key pg_catalog.jsonb;
                new_key pg_catalog.jsonb;
                argument_ordinal integer;
                maintains_counted boolean;
            BEGIN
                old_row := CASE
                    WHEN TG_OP IN ('UPDATE', 'DELETE')
                    THEN pg_catalog.to_jsonb(OLD)
                    ELSE NULL
                END;
                new_row := CASE
                    WHEN TG_OP IN ('INSERT', 'UPDATE')
                    THEN pg_catalog.to_jsonb(NEW)
                    ELSE NULL
                END;
                -- Fixed source closure, never caller-selected trigger arguments.
                -- Nonindexed relations do not invoke counted-store functions.
                maintains_counted := TG_TABLE_NAME IN (
                    'webauthn_credentials', 'webauthn_challenges',
                    'oidc_browser_sessions', 'approval_grants',
                    'control_plane_approvals', 'webauthn_trust_publications'
                );
                IF TG_NARGS < 1 THEN
                    RAISE EXCEPTION
                        'authenticated-tree trigger has no key columns';
                END IF;
                FOR argument_ordinal IN 0..TG_NARGS - 1 LOOP
                    IF old_row IS NOT NULL THEN
                        old_key := COALESCE(
                            old_key, '{{}}'::pg_catalog.jsonb
                        ) || pg_catalog.jsonb_build_object(
                            TG_ARGV[argument_ordinal],
                            old_row->TG_ARGV[argument_ordinal]
                        );
                    END IF;
                    IF new_row IS NOT NULL THEN
                        new_key := COALESCE(
                            new_key, '{{}}'::pg_catalog.jsonb
                        ) || pg_catalog.jsonb_build_object(
                            TG_ARGV[argument_ordinal],
                            new_row->TG_ARGV[argument_ordinal]
                        );
                    END IF;
                END LOOP;
                IF TG_OP = 'UPDATE' AND old_key <> new_key THEN
                    PERFORM {guard_namespace}.
                        serverware_policy_authority_authenticated_apply(
                            TG_TABLE_NAME, old_key, NULL, 'DELETE'
                        );
                    IF maintains_counted THEN
                        PERFORM {guard_namespace}.
                            serverware_policy_authority_counted_apply_event(
                                TG_TABLE_NAME, 'DELETE', old_row, NULL
                            );
                    END IF;
                    PERFORM {guard_namespace}.
                        serverware_policy_authority_authenticated_apply(
                            TG_TABLE_NAME, new_key, new_row, 'INSERT'
                        );
                    IF maintains_counted THEN
                        PERFORM {guard_namespace}.
                            serverware_policy_authority_counted_apply_event(
                                TG_TABLE_NAME, 'INSERT', NULL, new_row
                            );
                    END IF;
                ELSE
                    PERFORM {guard_namespace}.
                        serverware_policy_authority_authenticated_apply(
                            TG_TABLE_NAME,
                            COALESCE(new_key, old_key),
                            new_row,
                            TG_OP
                        );
                    IF maintains_counted THEN
                        PERFORM {guard_namespace}.
                            serverware_policy_authority_counted_apply_event(
                                TG_TABLE_NAME, TG_OP, old_row, new_row
                            );
                    END IF;
                END IF;
                RETURN COALESCE(NEW, OLD);
            END;
            $serverware_authenticated_trigger$
            """,
    )
