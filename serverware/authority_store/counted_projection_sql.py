"""Fixed PostgreSQL counted-index row codecs, not installed writer authority.

Render only; no connection, schema mutation, trigger, bootstrap or grant. These
functions derive lookup/key/full-row commitments from actual supplied JSONB and
the eleven source profiles. The primary row-trigger source supplies real
OLD/NEW records; installed head and transaction admission remain separate.
JSONB has already lost duplicate fields and normalized some number spellings;
these functions cannot replace original-byte or installed column admission.
"""
from __future__ import annotations

from serverware import authority_contract
from serverware import authority_index_projection as projection
from serverware.authority_store.primary_tree_sql import _namespace
from serverware.authority_store.wire_json_sql import WIRE_JSON_MAX_DEPTH, WIRE_JSON_MAX_NODES


COUNTED_PROJECTION_FUNCTION_NAMES = (
    "serverware_policy_authority_counted_expiry_micros",
    "serverware_policy_authority_counted_signed_order",
    "serverware_policy_authority_counted_challenge_id_order",
    "serverware_policy_authority_counted_field",
    "serverware_policy_authority_counted_project",
)


def counted_projection_functions_sql(namespace: str) -> tuple[str, ...]:
    """Return fixed invoker definitions, after real primary/wire/counted hashes.

    Requires canonical_json, framed_digest, domain_digest, wire_walk, wire_json
    and counted_profile in the same admitted namespace. No caller supplies a
    profile descriptor, a projection program or either primary commitment.
    """
    namespace = _namespace(namespace)
    branches = []
    for index_id in projection.INDEX_IDS:
        definition = projection._definition(index_id)
        arguments = ",\n                    ".join(
            f"'{name}', {namespace}.serverware_policy_authority_counted_field("
            f"source_row, '{name}', '{kind}')" for name, kind in definition.row_fields
        )
        branches.append(f"WHEN '{index_id}' THEN\n"
                        f"                typed_fields := pg_catalog.jsonb_build_object({arguments});")
    field_branches = "\n            ".join(branches)
    return (
        f"""
        CREATE OR REPLACE FUNCTION {namespace}.serverware_policy_authority_counted_expiry_micros(value text)
        RETURNS bigint LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER
        SET search_path = pg_catalog
        AS $counted_expiry$
        DECLARE
            instant timestamp without time zone;
            micros integer := 0;
            rendered text;
            elapsed numeric;
        BEGIN
            IF value IS NULL OR pg_catalog.octet_length(value) NOT IN (25,32)
                OR value COLLATE "C" !~ '^[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}T[0-9]{{2}}:[0-9]{{2}}:[0-9]{{2}}([.][0-9]{{6}})?[+]00:00$'
            THEN RAISE EXCEPTION 'counted expiry is not canonical UTC'; END IF;
            IF pg_catalog.substring(value,1,4)::integer NOT BETWEEN 1 AND 9999
                OR pg_catalog.substring(value,12,2)::integer NOT BETWEEN 0 AND 23
                OR pg_catalog.substring(value,15,2)::integer NOT BETWEEN 0 AND 59
                OR pg_catalog.substring(value,18,2)::integer NOT BETWEEN 0 AND 59
            THEN RAISE EXCEPTION 'counted expiry calendar or clock is invalid'; END IF;
            IF pg_catalog.octet_length(value) = 32 THEN
                micros := pg_catalog.substring(value,21,6)::integer;
                IF micros = 0 THEN RAISE EXCEPTION 'counted expiry zero fraction is not canonical'; END IF;
            END IF;
            instant := pg_catalog.make_timestamp(
                pg_catalog.substring(value,1,4)::integer, pg_catalog.substring(value,6,2)::integer,
                pg_catalog.substring(value,9,2)::integer, pg_catalog.substring(value,12,2)::integer,
                pg_catalog.substring(value,15,2)::integer, pg_catalog.substring(value,18,2)::integer
            ) + micros * INTERVAL '1 microsecond';
            rendered := pg_catalog.to_char(instant, 'YYYY-MM-DD"T"HH24:MI:SS')
                || CASE WHEN micros = 0 THEN '' ELSE '.' || pg_catalog.lpad(micros::text,6,'0') END || '+00:00';
            IF rendered COLLATE "C" IS DISTINCT FROM value COLLATE "C" THEN
                RAISE EXCEPTION 'counted expiry calendar spelling changed';
            END IF;
            elapsed := EXTRACT(EPOCH FROM (instant - TIMESTAMP '1970-01-01 00:00:00')) * 1000000;
            IF elapsed <> pg_catalog.trunc(elapsed) OR elapsed NOT BETWEEN
                -9223372036854775808::numeric AND 9223372036854775807::numeric
            THEN RAISE EXCEPTION 'counted expiry microseconds exceed signed64'; END IF;
            RETURN elapsed::bigint;
        END;
        $counted_expiry$
        """,
        f"""
        CREATE OR REPLACE FUNCTION {namespace}.serverware_policy_authority_counted_signed_order(value bigint)
        RETURNS text LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER
        SET search_path = pg_catalog
        AS $counted_order$
        DECLARE encoded bytea;
        BEGIN
            IF value IS NULL THEN RAISE EXCEPTION 'counted signed order is null'; END IF;
            encoded := pg_catalog.int8send(value);
            -- Flip the sign bit: exactly signed64 + 2^63, without an
            -- overflowing bigint addition or a floating-point conversion.
            encoded := pg_catalog.set_byte(encoded,0,pg_catalog.get_byte(encoded,0) # 128);
            RETURN pg_catalog.encode(encoded,'hex');
        END;
        $counted_order$
        """,
        f"""
        CREATE OR REPLACE FUNCTION {namespace}.serverware_policy_authority_counted_challenge_id_order(value text)
        RETURNS text LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER
        SET search_path = pg_catalog
        AS $counted_challenge_id$
        BEGIN
            -- Fresh source contract only. This never hashes an arbitrary ID
            -- into a tie key or adopts a historical custom-ID population.
            IF value IS NOT NULL AND pg_catalog.octet_length(value) = 36 AND
                value COLLATE "C" ~ '^[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}$'
            THEN RETURN '00' || pg_catalog.replace(value, '-', '') || pg_catalog.repeat('0',46);
            ELSIF value IS NOT NULL AND pg_catalog.octet_length(value) = 71 AND
                value COLLATE "C" ~ '^sha256:[0-9a-f]{{64}}$'
            THEN RETURN '01' || pg_catalog.substring(value,8) || pg_catalog.repeat('0',14);
            END IF;
            RAISE EXCEPTION 'fresh challenge source requires canonical UUID36 or sha256 ID; legacy adoption is forbidden';
        END;
        $counted_challenge_id$
        """,
        f"""
        CREATE OR REPLACE FUNCTION {namespace}.serverware_policy_authority_counted_field(
            source_row jsonb, field_name text, field_kind text
        ) RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER
        SET search_path = pg_catalog
        AS $counted_field$
        DECLARE
            value jsonb;
            scalar text;
            kind text;
            integer_value numeric;
            choices text[];
        BEGIN
            IF source_row IS NULL OR pg_catalog.jsonb_typeof(source_row) <> 'object'
                OR field_name IS NULL OR field_kind IS NULL OR NOT (source_row ? field_name)
            THEN RAISE EXCEPTION 'counted referenced field is missing'; END IF;
            value := source_row->field_name;
            kind := pg_catalog.jsonb_typeof(value);
            IF field_kind COLLATE "C" IN ('nullable-text','nullable-utc-expiry') AND kind = 'null'
            THEN RETURN value; END IF;
            IF field_kind COLLATE "C" IN ('int32','int64','reference-mask') THEN
                IF kind <> 'number' THEN
                    RAISE EXCEPTION 'counted integer is not an exact bounded signed value';
                END IF;
                scalar := value::text;
                IF pg_catalog.octet_length(scalar) > 20
                    OR scalar COLLATE "C" !~ '^-?(0|[1-9][0-9]*)$'
                THEN RAISE EXCEPTION 'counted integer is not an exact bounded signed value'; END IF;
                integer_value := scalar::numeric;
                IF (field_kind COLLATE "C" = 'int32' AND integer_value NOT BETWEEN -2147483648 AND 2147483647)
                    OR (field_kind COLLATE "C" = 'reference-mask' AND integer_value NOT BETWEEN 0 AND 7)
                    OR integer_value NOT BETWEEN -9223372036854775808::numeric AND 9223372036854775807::numeric
                THEN RAISE EXCEPTION 'counted integer exceeds its source range'; END IF;
                RETURN pg_catalog.to_jsonb(integer_value::bigint);
            END IF;
            IF kind <> 'string' THEN RAISE EXCEPTION 'counted text has a nonstring type'; END IF;
            scalar := value #>> '{{}}';
            IF pg_catalog.octet_length(scalar) > {projection.MAX_TEXT_BYTES} THEN
                RAISE EXCEPTION 'counted text exceeds its UTF8 byte bound';
            END IF;
            CASE field_kind COLLATE "C"
                WHEN 'text' THEN RETURN value;
                WHEN 'nullable-text' THEN RETURN value;
                WHEN 'challenge-id' THEN
                    PERFORM {namespace}.serverware_policy_authority_counted_challenge_id_order(scalar);
                    RETURN value;
                WHEN 'utc-expiry', 'nullable-utc-expiry' THEN RETURN pg_catalog.to_jsonb(
                    {namespace}.serverware_policy_authority_counted_expiry_micros(scalar));
                WHEN 'session-status' THEN choices := ARRAY['pending_webauthn','active','revoked'];
                WHEN 'live-session-status' THEN choices := ARRAY['pending_webauthn','active'];
                WHEN 'publication-status' THEN choices := ARRAY['pending','published'];
                WHEN 'global-scope' THEN choices := ARRAY['global'];
                ELSE RAISE EXCEPTION 'counted field codec is not source admitted';
            END CASE;
            IF NOT (scalar COLLATE "C" = ANY(choices)) THEN
                RAISE EXCEPTION 'counted text is outside its source enum';
            END IF;
            RETURN value;
        END;
        $counted_field$
        """,
        f"""
        CREATE OR REPLACE FUNCTION {namespace}.serverware_policy_authority_counted_project(
            index_identity text, source_row jsonb
        ) RETURNS TABLE(index_key text, primary_id text, primary_key_digest text, primary_row_digest text)
        LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER
        SET search_path = pg_catalog
        AS $counted_project$
        DECLARE
            source_table text;
            source_projection text;
            typed_fields jsonb;
            partition_fields jsonb := '{{}}'::jsonb;
            partition_json text;
            partition_digest text;
            ordering_key text := pg_catalog.repeat('0',32);
            challenge_ordered boolean := FALSE;
            challenge_timestamp bigint;
            binding text;
        BEGIN
            IF source_row IS NULL OR pg_catalog.jsonb_typeof(source_row) <> 'object' THEN
                RAISE EXCEPTION 'counted source row must be an actual object';
            END IF;
            SELECT profile.table_name, profile.projection_digest INTO STRICT source_table, source_projection
            FROM {namespace}.serverware_policy_authority_counted_profile(index_identity) AS profile;
            CASE index_identity COLLATE "C"
            {field_branches}
                ELSE RAISE EXCEPTION 'counted projection is not source admitted';
            END CASE;
            -- The primary evaluator admits only bounded lossless JSON. This
            -- real measurement also bounds unknown full-row fields before the
            -- persisted-tree serializer is used; it is not a JSONB parser or
            -- detoast/allocation bound and does not authenticate membership.
            PERFORM * FROM {namespace}.serverware_policy_authority_wire_walk(
                source_row, {WIRE_JSON_MAX_DEPTH}, {WIRE_JSON_MAX_NODES}, {authority_contract.MAX_RESULT_BYTES}, FALSE);
            CASE index_identity COLLATE "C"
                WHEN 'webauthn_credential_id' THEN
                    partition_fields := pg_catalog.jsonb_build_object('credential_id',typed_fields->'credential_id');
                WHEN 'webauthn_credential_user_history' THEN
                    partition_fields := pg_catalog.jsonb_build_object('user_id',typed_fields->'user_id');
                WHEN 'webauthn_credential_live_trust' THEN
                    IF typed_fields->'revoked_at' <> 'null'::jsonb OR (typed_fields->>'attestation_trusted')::bigint = 0
                    THEN RETURN; END IF;
                WHEN 'webauthn_registration_unused_global', 'webauthn_registration_unused_user' THEN
                    IF (typed_fields->>'challenge_type') COLLATE "C" <> 'registration'
                        OR typed_fields->'used_at' <> 'null'::jsonb THEN RETURN; END IF;
                    ordering_key := {namespace}.serverware_policy_authority_counted_signed_order(
                        (typed_fields->>'expires_at')::bigint) || pg_catalog.repeat('0',16);
                    IF index_identity COLLATE "C" = 'webauthn_registration_unused_user' THEN
                        partition_fields := pg_catalog.jsonb_build_object('user_id',typed_fields->'user_id');
                    END IF;
                WHEN 'webauthn_session_credential_status' THEN
                    binding := typed_fields->>'bound_webauthn_credential_id';
                    IF binding IS NULL OR (typed_fields->>'status') COLLATE "C" NOT IN ('pending_webauthn','active')
                    THEN RETURN; END IF;
                    partition_fields := pg_catalog.jsonb_build_object('credential_record_id',binding,'status',typed_fields->'status');
                WHEN 'webauthn_grant_approver_active', 'webauthn_control_approval_approved' THEN
                    binding := typed_fields->>'approver_webauthn_credential_id';
                    IF binding IS NULL THEN RETURN; END IF;
                    IF index_identity COLLATE "C" = 'webauthn_grant_approver_active' THEN
                        IF (typed_fields->>'state') COLLATE "C" <> 'active' THEN RETURN; END IF;
                    ELSE
                        IF (typed_fields->>'status') COLLATE "C" <> 'approved' THEN RETURN; END IF;
                    END IF;
                    partition_fields := pg_catalog.jsonb_build_object('credential_record_id',binding);
                WHEN 'webauthn_publication_bundle_digest' THEN
                    partition_fields := pg_catalog.jsonb_build_object('bundle_digest',typed_fields->'bundle_digest');
                WHEN 'webauthn_publication_status' THEN
                    partition_fields := pg_catalog.jsonb_build_object('status',typed_fields->'status');
                WHEN 'webauthn_publication_generation' THEN
                    ordering_key := {namespace}.serverware_policy_authority_counted_signed_order(
                        (typed_fields->>'rollback_epoch')::bigint)
                        || {namespace}.serverware_policy_authority_counted_signed_order((typed_fields->>'sequence')::bigint);
                WHEN 'webauthn_challenge_unused_global', 'webauthn_challenge_unused_user' THEN
                    IF typed_fields->'used_at' <> 'null'::jsonb THEN RETURN; END IF;
                    challenge_ordered := TRUE;
                    challenge_timestamp := (typed_fields->>'expires_at')::bigint;
                    IF index_identity COLLATE "C" = 'webauthn_challenge_unused_user' THEN
                        partition_fields := pg_catalog.jsonb_build_object('user_id',typed_fields->'user_id');
                    END IF;
                WHEN 'webauthn_challenge_created_global', 'webauthn_challenge_created_user' THEN
                    challenge_ordered := TRUE;
                    challenge_timestamp := (typed_fields->>'created_at')::bigint;
                    IF index_identity COLLATE "C" = 'webauthn_challenge_created_user' THEN
                        partition_fields := pg_catalog.jsonb_build_object('user_id',typed_fields->'user_id');
                    END IF;
                WHEN 'webauthn_challenge_terminal_unreferenced_global' THEN
                    IF typed_fields->'used_at' = 'null'::jsonb
                        OR (typed_fields->>'retention_reference_mask')::bigint <> 0 THEN RETURN; END IF;
                    challenge_ordered := TRUE;
                    challenge_timestamp := (typed_fields->>'used_at')::bigint;
                WHEN 'webauthn_challenge_scope_unused' THEN
                    IF typed_fields->'used_at' <> 'null'::jsonb THEN RETURN; END IF;
                    challenge_ordered := TRUE;
                    partition_fields := pg_catalog.jsonb_build_object(
                        'challenge_type',typed_fields->'challenge_type', 'user_id',typed_fields->'user_id',
                        'scope_key',typed_fields->'scope_key');
                WHEN 'webauthn_challenge_value' THEN
                    challenge_ordered := TRUE;
                    partition_fields := pg_catalog.jsonb_build_object('challenge',typed_fields->'challenge');
                ELSE RAISE EXCEPTION 'counted membership is not source admitted';
            END CASE;
            primary_id := typed_fields->>'id';
            primary_key_digest := {namespace}.serverware_policy_authority_domain_digest(
                'serverware.policyAuthorityBusinessKey/v1', source_table,
                {namespace}.serverware_policy_authority_wire_json(pg_catalog.jsonb_build_object('id',primary_id)));
            primary_row_digest := {namespace}.serverware_policy_authority_framed_digest(
                'serverware.policyAuthorityAuthenticatedRow/v1', source_table,
                {namespace}.serverware_policy_authority_canonical_json(source_row));
            partition_json := {namespace}.serverware_policy_authority_canonical_json(partition_fields);
            IF pg_catalog.octet_length(partition_json) > {projection.MAX_PARTITION_BYTES} THEN
                RAISE EXCEPTION 'counted canonical partition exceeds its byte bound';
            END IF;
            partition_digest := {namespace}.serverware_policy_authority_framed_digest(
                '{projection.PARTITION_DOMAIN}', '{projection.COUNTED_PROFILE}', index_identity,
                source_table, source_projection, partition_json);
            IF challenge_ordered THEN
                ordering_key := CASE WHEN challenge_timestamp IS NULL THEN pg_catalog.repeat('0',16)
                    ELSE {namespace}.serverware_policy_authority_counted_signed_order(challenge_timestamp) END;
                index_key := pg_catalog.substring(partition_digest,8) || ordering_key
                    || {namespace}.serverware_policy_authority_counted_challenge_id_order(primary_id);
            ELSE
                index_key := pg_catalog.substring(partition_digest,8) || ordering_key
                    || pg_catalog.substring(primary_key_digest,8);
            END IF;
            RETURN NEXT;
        END;
        $counted_project$
        """,
    )
