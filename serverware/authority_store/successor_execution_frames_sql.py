"""Source-fixed native read-frame custody fragments, not plan admission.

The existing protected issuer replays originals before calling these fragments.
SQL retains opaque literal frames and rechecks their committed framing at final
packet issuance and execution. It neither verifies native signatures nor stores
session possession. Only one bounded original leaf is reassembled at a time.
The deferred packet FK makes incomplete uploads uncommittable; final packet
issuance closes the stream, and appends after issuance are refused.
"""
from __future__ import annotations

from serverware import authority_contract as authority
from serverware import authority_native_jit_review_plan_stream as stream
from serverware.authority_store import current_root_execution_sql as effects
from serverware.authority_store.revocation_retained_sql import _closed, _literal


OPERATION = "jit.review-open.receipt.issue"
_COLUMNS = ("pending_decision_digest", "packet_digest", "frame_ordinal",
    "byte_count", "bytes_digest", "frame_bytes", "issuer_identity_digest")


def _source():
    contract = authority.SUCCESSOR_EXECUTION_FRAME_CONTRACT
    if (authority.SUCCESSOR_EXECUTION_FRAME_TABLE != "policy_authority_successor_execution_frames"
            or authority.SUCCESSOR_EXECUTION_FRAME_COLUMNS != _COLUMNS
            or contract["operation"] != OPERATION or contract["manifestPlanPosition"] != 4
            or contract["maximumFrameBytes"] != stream.FRAME_BYTES
            or contract["maximumStreamBytes"] != stream.MAX_ORIGINAL_BYTES
            or contract["maximumFrames"] != stream.MAX_FRAMES
            or tuple(authority.SUCCESSOR_EXECUTION_FUNCTION_SIGNATURES[authority.SUCCESSOR_FRAME_FUNCTION])
                != ("text", "text", "bigint", "bytea")):
        raise ValueError("successor native stream source closure changed")
    return authority.SUCCESSOR_EXECUTION_FRAME_TABLE


def declarations_sql(namespace):
    return f"""
        sxf_row {namespace}.{_source()}%ROWTYPE;
        sxf_manifest jsonb; sxf_descriptor jsonb; sxf_item jsonb;
        sxf_manifest_raw bytea; sxf_leaf bytea;
        sxf_manifest_text text; sxf_manifest_canonical text; sxf_digest text;
        sxf_maxima bigint[]; sxf_row_chunks bigint; sxf_data_chunks bigint;
        sxf_leaf_index bigint; sxf_leaf_size bigint; sxf_leaf_offset bigint;
        sxf_ordinal bigint; sxf_total bigint; sxf_count bigint; sxf_byte_count bigint;
        sxf_stored_count bigint; sxf_stored_bytes bigint; sxf_last_ordinal bigint;
        sxf_same_identity boolean;
    """


def append_body_sql(namespace, *, live):
    table = _source()
    parent = authority.SUCCESSOR_EXECUTION_CUSTODY_TABLE
    return f"""
        IF supplied_pending_decision_digest IS NULL OR supplied_packet_digest IS NULL
            OR supplied_pending_decision_digest COLLATE "C" !~ '^sha256:[0-9a-f]{{64}}$'
            OR supplied_packet_digest COLLATE "C" !~ '^sha256:[0-9a-f]{{64}}$'
            OR supplied_frame_ordinal IS NULL OR supplied_frame_ordinal NOT BETWEEN 0 AND {stream.MAX_FRAMES - 1}
            OR supplied_frame IS NULL OR pg_catalog.octet_length(supplied_frame) NOT BETWEEN 1 AND {stream.FRAME_BYTES}
        THEN RAISE EXCEPTION 'successor native frame transport is not source bounded'; END IF;
        IF EXISTS (SELECT 1 FROM {namespace}.{parent} AS stored
                WHERE stored.pending_decision_digest = supplied_pending_decision_digest
                   OR stored.packet_digest = supplied_packet_digest)
        THEN RAISE EXCEPTION 'successor native stream is already closed'; END IF;
        SELECT pg_catalog.count(*), COALESCE(pg_catalog.sum(stored.byte_count), 0),
            pg_catalog.max(stored.frame_ordinal),
            COALESCE(pg_catalog.bool_and(stored.packet_digest = supplied_packet_digest
                AND stored.issuer_identity_digest = sxe_session_identity), TRUE)
            INTO STRICT sxf_stored_count, sxf_stored_bytes, sxf_last_ordinal, sxf_same_identity
            FROM {namespace}.{table} AS stored
            WHERE stored.pending_decision_digest = supplied_pending_decision_digest;
        sxf_byte_count := pg_catalog.octet_length(supplied_frame);
        IF sxf_stored_count IS DISTINCT FROM supplied_frame_ordinal
            OR (sxf_stored_count > 0 AND sxf_last_ordinal IS DISTINCT FROM supplied_frame_ordinal - 1)
            OR sxf_same_identity IS NOT TRUE
            OR sxf_stored_bytes + sxf_byte_count > {stream.MAX_ORIGINAL_BYTES}
        THEN RAISE EXCEPTION 'successor native frame is duplicate, out of order or exceeds stream bounds'; END IF;
        sxf_digest := 'sha256:' || pg_catalog.encode(pg_catalog.sha256(supplied_frame), 'hex');
        {live()}
        INSERT INTO {namespace}.{table} ({', '.join(_COLUMNS)}) VALUES (
            supplied_pending_decision_digest, supplied_packet_digest, supplied_frame_ordinal,
            sxf_byte_count, sxf_digest, supplied_frame, sxe_session_identity);
        {live()}
        RETURN QUERY SELECT supplied_frame_ordinal, sxf_byte_count, sxf_digest;
    """


def closure_body_sql(namespace, *, integer, digests, live):
    """Validate the final compact packet's exact stream, never all-stream join."""
    table = _source()
    root_maxima = ", ".join(str(maximum) for _name, maximum in stream._ROOTS)
    return f"""
        SELECT pg_catalog.count(*), COALESCE(pg_catalog.sum(stored.byte_count), 0)
            INTO STRICT sxf_stored_count, sxf_stored_bytes
            FROM {namespace}.{table} AS stored
            WHERE stored.pending_decision_digest = crx_marker->>'pending_decision_digest';
        IF crx_operation <> {_literal(OPERATION)} THEN
            IF sxf_stored_count <> 0
            THEN RAISE EXCEPTION 'non-native successor packet has unexpected frame custody'; END IF;
        ELSE
            IF sxf_stored_count NOT BETWEEN 1 AND {stream.MAX_FRAMES}
                OR sxf_stored_bytes NOT BETWEEN 1 AND {stream.MAX_ORIGINAL_BYTES}
            THEN RAISE EXCEPTION 'successor native stream inventory is not bounded'; END IF;
            -- _originals already authenticated this bounded raw5 transport;
            -- decode the manifest explicitly instead of relying on a scratch
            -- variable left over by another packet/control parser.
            sxf_manifest_raw := pg_catalog.decode(pg_catalog.translate(
                sxe_packet->'originals'->'plan'->4->>'base64Url', '-_', '+/')
                || pg_catalog.repeat('=', (4 - pg_catalog.length(
                    sxe_packet->'originals'->'plan'->4->>'base64Url') % 4) % 4), 'base64');
            IF pg_catalog.octet_length(sxf_manifest_raw) NOT BETWEEN 2 AND {stream.MAX_MANIFEST_BYTES}
            THEN RAISE EXCEPTION 'successor native manifest is not bounded'; END IF;
            sxf_manifest_text := pg_catalog.convert_from(sxf_manifest_raw, 'UTF8');
            IF pg_catalog.length(sxf_manifest_text) IS DISTINCT FROM pg_catalog.octet_length(sxf_manifest_text)
            THEN RAISE EXCEPTION 'successor native manifest is not canonical ASCII'; END IF;
            sxf_manifest := sxf_manifest_text::jsonb;
            {effects._wire(namespace, 'sxf_manifest', 'sxf_manifest_canonical', stream.MAX_MANIFEST_BYTES, 4096, 6)}
            IF sxf_manifest_canonical IS DISTINCT FROM sxf_manifest_text
                OR NOT {_closed('sxf_manifest', ('schema', 'read', 'rowChunkCounts', 'originals'))}
                OR sxf_manifest->>'schema' IS DISTINCT FROM {_literal(stream.SCHEMA)}
                OR NOT {_closed("sxf_manifest->'read'", ('schema', 'operation', 'requestDigest', 'databaseNowEpochNs', 'trustPublicationId'))}
                OR sxf_manifest->'read'->>'schema' IS DISTINCT FROM {_literal(stream.reads.SCHEMA)}
                OR sxf_manifest->'read'->>'operation' IS DISTINCT FROM crx_operation
                OR sxf_manifest->'read'->>'requestDigest' IS DISTINCT FROM crx_request_digest
                OR pg_catalog.jsonb_typeof(sxf_manifest->'read'->'trustPublicationId') IS DISTINCT FROM 'string'
                OR pg_catalog.length(sxf_manifest->'read'->>'trustPublicationId') NOT BETWEEN 1 AND 1024
                OR pg_catalog.jsonb_typeof(sxf_manifest->'rowChunkCounts') IS DISTINCT FROM 'array'
                OR pg_catalog.jsonb_typeof(sxf_manifest->'originals') IS DISTINCT FROM 'array'
            THEN RAISE EXCEPTION 'successor native manifest shape or scope changed'; END IF;
            {integer("sxf_manifest->'read'->'databaseNowEpochNs'", minimum=1)}
            IF pg_catalog.jsonb_array_length(sxf_manifest->'rowChunkCounts') <> 13
            THEN RAISE EXCEPTION 'successor native manifest row schedule changed'; END IF;
            sxf_maxima := ARRAY[{root_maxima}]::bigint[]; sxf_data_chunks := 0;
            FOR sxf_item IN SELECT item.value
                FROM pg_catalog.jsonb_array_elements(sxf_manifest->'rowChunkCounts') WITH ORDINALITY
                    AS item(value, ordinal) ORDER BY item.ordinal
            LOOP
                {integer('sxf_item', minimum=1, maximum=98)}
                sxf_row_chunks := (sxf_item #>> '{{}}')::bigint;
                sxf_data_chunks := sxf_data_chunks + sxf_row_chunks;
                IF sxf_data_chunks > {stream.reads.chunks.MAX_TOTAL_DATA_CHUNKS + 13}
                THEN RAISE EXCEPTION 'successor native manifest chunk schedule exceeds source'; END IF;
                FOR sxf_count IN 1..sxf_row_chunks LOOP
                    sxf_maxima := pg_catalog.array_append(sxf_maxima, {2 * stream.reads.chunks.CHUNK_BYTES + 2048}::bigint);
                END LOOP;
                sxf_maxima := pg_catalog.array_append(sxf_maxima, {stream.reads.MAX_PROOF_BYTES}::bigint);
            END LOOP;
            IF pg_catalog.jsonb_array_length(sxf_manifest->'originals') IS DISTINCT FROM pg_catalog.cardinality(sxf_maxima)
                OR pg_catalog.cardinality(sxf_maxima) > {stream.MAX_ORIGINALS}
            THEN RAISE EXCEPTION 'successor native manifest leaf schedule changed'; END IF;
            sxf_ordinal := 0; sxf_total := 0;
            FOR sxf_descriptor, sxf_leaf_index IN SELECT item.value, item.ordinal
                FROM pg_catalog.jsonb_array_elements(sxf_manifest->'originals') WITH ORDINALITY
                    AS item(value, ordinal) ORDER BY item.ordinal
            LOOP
                IF NOT {_closed('sxf_descriptor', ('byteCount', 'sha256'))}
                THEN RAISE EXCEPTION 'successor native leaf descriptor is not exact'; END IF;
                {integer("sxf_descriptor->'byteCount'", minimum=2)}
                {digests(("sxf_descriptor->'sha256'",))}
                sxf_leaf_size := (sxf_descriptor->>'byteCount')::bigint;
                sxf_total := sxf_total + sxf_leaf_size;
                IF sxf_leaf_size > sxf_maxima[sxf_leaf_index] OR sxf_total > {stream.MAX_ORIGINAL_BYTES}
                THEN RAISE EXCEPTION 'successor native original exceeds its source bound'; END IF;
                sxf_leaf := ''::bytea; sxf_leaf_offset := 0;
                WHILE sxf_leaf_offset < sxf_leaf_size LOOP
                    {live()}
                    IF sxf_ordinal >= {stream.MAX_FRAMES}
                    THEN RAISE EXCEPTION 'successor native frame count exceeds source'; END IF;
                    SELECT stored.* INTO STRICT sxf_row FROM {namespace}.{table} AS stored
                        WHERE stored.pending_decision_digest = crx_marker->>'pending_decision_digest'
                          AND stored.packet_digest = sxe_packet_digest
                          AND stored.frame_ordinal = sxf_ordinal;
                    sxf_byte_count := LEAST({stream.FRAME_BYTES}, sxf_leaf_size - sxf_leaf_offset);
                    IF sxf_row.byte_count IS DISTINCT FROM sxf_byte_count
                        OR pg_catalog.octet_length(sxf_row.frame_bytes) IS DISTINCT FROM sxf_byte_count
                        OR sxf_row.issuer_identity_digest IS DISTINCT FROM sxe_issuer_identity
                        OR sxf_row.bytes_digest IS DISTINCT FROM 'sha256:'
                            || pg_catalog.encode(pg_catalog.sha256(sxf_row.frame_bytes), 'hex')
                    THEN RAISE EXCEPTION 'successor native frame original or issuer changed'; END IF;
                    sxf_leaf := sxf_leaf || sxf_row.frame_bytes;
                    sxf_leaf_offset := sxf_leaf_offset + sxf_byte_count;
                    sxf_ordinal := sxf_ordinal + 1;
                END LOOP;
                IF 'sha256:' || pg_catalog.encode(pg_catalog.sha256(sxf_leaf), 'hex')
                        IS DISTINCT FROM sxf_descriptor->>'sha256'
                THEN RAISE EXCEPTION 'successor native leaf literal commitment changed'; END IF;
                -- Discard each bounded leaf before processing the next one.
                sxf_leaf := NULL;
            END LOOP;
            IF sxf_ordinal IS DISTINCT FROM sxf_stored_count OR sxf_total IS DISTINCT FROM sxf_stored_bytes
            THEN RAISE EXCEPTION 'successor native stream has missing or extra frames'; END IF;
        END IF;
        {live()}
    """
