"""Bounded tentative maintenance originals, not execution authority.

These are PG DDL and a statement fragment, never an installed callable gate.
The genuine surrounding issuer owns role/TLS/catalog admission, its original
SERIALIZABLE transaction and deadline, and the real replay that emitted each
body. Only that owner may seal after checking the complete sequence and chain.
An existing digest or an exact readback is not proof or a capability.

The owner's actual complete-step and sealed-absence predicates must participate
in the same SERIALIZABLE sealing transaction; this fragment alone is not a
cross-transaction parent lock. No business row, root, grant, clock, connection,
transaction commit or ACL is created here. PG parsing/detoast/wire traversal is
not Python shared-work accounting. Byte limits precede parsing, and the genuine
bounded ASCII wire walker must return the exact original text afterwards.
"""
from __future__ import annotations

from catchplate import authority_challenge_execution_stream as stream
from catchplate import authority_challenge_pass as source_pass
from catchplate.authority_store import challenge_maintenance_effects_sql as effects
from catchplate.authority_store.mutation_sql import _schema_name
from catchplate.authority_store.revocation_retained_sql import _closed, _literal
from catchplate.authority_store.wire_json_sql import WIRE_JSON_MAX_DEPTH, WIRE_JSON_MAX_NODES


STEP_TABLE = "policy_authority_challenge_execution_steps"
CUSTODY_TABLE = "policy_authority_challenge_execution_custody"
STEP_COLUMNS = ("pending_decision_digest", "step_ordinal", "descriptor_json",
    "body_json", "issuer_identity_digest")
CUSTODY_COLUMNS = ("pending_decision_digest", "packet_digest", "packet_json", "issuer_identity_digest")
MAX_STEPS = 1548
MAX_DESCRIPTOR_BYTES = 512
MAX_BODY_BYTES = 4 * 1024 * 1024
MAX_PACKET_BYTES = 8 * 1024 * 1024
_PHASES = (0, 1, 2, 4, 5, 6)
_DESCRIPTOR_FIELDS = ("kind", "phaseOrdinal", "rowOrdinal", "byteCount", "digest")
_ROOT_FIELDS = ("table", "rootRevision", "rootDigest", "leafCount")
_HEAD_FIELDS = ("indexId", "table", "countedProfile", "projectionDigest",
    "projectionManifestDigest", "indexRevision", "rootDigest", "rootCount")
_ROW_FIELDS = ("schema", "phaseOrdinal", "rowOrdinal", "mutation", "primaryBefore", "primaryAfter")
_PHASE_FIELDS = ("schema", "phaseOrdinal", "rowCount", "primaryRoot", "indexHeads")
_MUTATION_FIELDS = ("templateId", "operation", "table", "key", "keyDigest", "expectedRow", "row")


def _source():
    if (stream.MAX_STEPS != MAX_STEPS or stream.MAX_BODY_BYTES != MAX_BODY_BYTES
            or stream.PHASES != _PHASES or stream._DESCRIPTOR_FIELDS != _DESCRIPTOR_FIELDS
            or stream._PHASE_FIELDS != frozenset(_PHASE_FIELDS)):
        raise ValueError("maintenance custody stream source changed")
    return effects._source()


def installation_sql(namespace: str) -> str:
    """Return two exact PG tables only; the caller owns installation/closure."""
    _schema_name(namespace)
    return f"""
        CREATE TABLE {namespace}.{STEP_TABLE} (
            pending_decision_digest TEXT NOT NULL CHECK (
                pg_catalog.octet_length(pending_decision_digest) = 71
                AND pending_decision_digest COLLATE "C" ~ '^sha256:[0-9a-f]{{64}}$'),
            step_ordinal INTEGER NOT NULL CHECK (step_ordinal BETWEEN 0 AND {MAX_STEPS - 1}),
            descriptor_json TEXT NOT NULL CHECK (
                pg_catalog.octet_length(descriptor_json) BETWEEN 2 AND {MAX_DESCRIPTOR_BYTES}
                AND pg_catalog.length(descriptor_json) = pg_catalog.octet_length(descriptor_json)),
            body_json TEXT NOT NULL CHECK (
                pg_catalog.octet_length(body_json) BETWEEN 2 AND {MAX_BODY_BYTES}
                AND pg_catalog.length(body_json) = pg_catalog.octet_length(body_json)),
            issuer_identity_digest TEXT NOT NULL CHECK (
                pg_catalog.octet_length(issuer_identity_digest) = 71
                AND issuer_identity_digest COLLATE "C" ~ '^sha256:[0-9a-f]{{64}}$'),
            PRIMARY KEY (pending_decision_digest, step_ordinal)
        );
        CREATE TABLE {namespace}.{CUSTODY_TABLE} (
            pending_decision_digest TEXT NOT NULL PRIMARY KEY CHECK (
                pg_catalog.octet_length(pending_decision_digest) = 71
                AND pending_decision_digest COLLATE "C" ~ '^sha256:[0-9a-f]{{64}}$'),
            packet_digest TEXT NOT NULL CHECK (
                pg_catalog.octet_length(packet_digest) = 71
                AND packet_digest COLLATE "C" ~ '^sha256:[0-9a-f]{{64}}$'),
            packet_json TEXT NOT NULL CHECK (
                pg_catalog.octet_length(packet_json) BETWEEN 2 AND {MAX_PACKET_BYTES}
                AND pg_catalog.length(packet_json) = pg_catalog.octet_length(packet_json)),
            issuer_identity_digest TEXT NOT NULL CHECK (
                pg_catalog.octet_length(issuer_identity_digest) = 71
                AND issuer_identity_digest COLLATE "C" ~ '^sha256:[0-9a-f]{{64}}$')
        );
    """


def declarations_sql() -> str:
    """Six fixed cxs_* inputs followed by scratch; no caller SQL identifiers."""
    return """
        cxs_pending_decision_digest text; cxs_step_ordinal integer;
        cxs_descriptor_json text; cxs_body_json text;
        cxs_issuer_identity_digest text; cxs_deadline_epoch_ns bigint;
        cxs_descriptor jsonb; cxs_body jsonb; cxs_root jsonb; cxs_head jsonb;
        cxs_kind text; cxs_phase integer; cxs_ordinal integer;
        cxs_ids text[]; cxs_projection text; cxs_position integer;
        cxs_measured record; cxs_rendered record; cxs_stored record;
    """


def _live():
    return """
        IF cxs_deadline_epoch_ns IS NULL OR cxs_deadline_epoch_ns <= 0
            OR pg_catalog.floor(EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000000000)
                >= cxs_deadline_epoch_ns
        THEN RAISE EXCEPTION 'maintenance custody original deadline expired'; END IF;
    """


def _wire(namespace, value, original, maximum, *, nodes=WIRE_JSON_MAX_NODES, depth=WIRE_JSON_MAX_DEPTH):
    return f"""
        SELECT * INTO STRICT cxs_measured FROM {namespace}.catchplate_policy_authority_wire_walk(
            {value}, {depth}, {nodes}, {maximum}, FALSE);
        SELECT * INTO STRICT cxs_rendered FROM {namespace}.catchplate_policy_authority_wire_walk(
            {value}, {depth}, cxs_measured.visited_nodes, cxs_measured.emitted_bytes, TRUE);
        IF cxs_rendered.visited_nodes IS DISTINCT FROM cxs_measured.visited_nodes
            OR cxs_rendered.emitted_bytes IS DISTINCT FROM cxs_measured.emitted_bytes
            OR pg_catalog.octet_length(cxs_rendered.rendered) IS DISTINCT FROM cxs_measured.emitted_bytes
            OR cxs_rendered.rendered COLLATE "C" IS DISTINCT FROM {original} COLLATE "C"
        THEN RAISE EXCEPTION 'maintenance custody original is not canonical ASCII'; END IF;
    """


def _integer(expression, maximum=2**63 - 1):
    return f"""
        IF pg_catalog.jsonb_typeof({expression}) IS DISTINCT FROM 'number'
            OR ({expression} #>> '{{}}') COLLATE "C" !~ '^(0|[1-9][0-9]{{0,18}})$'
        THEN RAISE EXCEPTION 'maintenance custody integer type differs'; END IF;
        IF ({expression} #>> '{{}}')::numeric NOT BETWEEN 0 AND {maximum}
        THEN RAISE EXCEPTION 'maintenance custody integer bound differs'; END IF;
    """


def _digest(expression):
    return f"""
        IF pg_catalog.jsonb_typeof({expression}) IS DISTINCT FROM 'string'
            OR ({expression} #>> '{{}}') COLLATE "C" !~ '^sha256:[0-9a-f]{{64}}$'
        THEN RAISE EXCEPTION 'maintenance custody digest differs'; END IF;
    """


def _root(namespace):
    return f"""
        IF NOT {_closed('cxs_root', _ROOT_FIELDS)}
            OR cxs_root->>'table' COLLATE "C" IS DISTINCT FROM '{effects.TABLE}' COLLATE "C"
        THEN RAISE EXCEPTION 'maintenance custody primary descriptor differs'; END IF;
        {_integer("cxs_root->'rootRevision'")}
        {_integer("cxs_root->'leafCount'")}
        {_digest("cxs_root->'rootDigest'")}
        IF ((cxs_root->>'leafCount')::bigint = 0) IS DISTINCT FROM (
                cxs_root->>'rootDigest' = {namespace}.catchplate_policy_authority_authenticated_empty(0))
            OR ((cxs_root->>'rootRevision')::bigint = 0 AND (cxs_root->>'leafCount')::bigint <> 0)
        THEN RAISE EXCEPTION 'maintenance custody primary empty convention differs'; END IF;
    """


def _row_body(namespace, templates):
    return f"""
        IF NOT {_closed('cxs_body', _ROW_FIELDS)}
            OR cxs_body->>'schema' COLLATE "C" IS DISTINCT FROM {_literal(source_pass.ROW_EFFECT_SCHEMA)} COLLATE "C"
        THEN RAISE EXCEPTION 'maintenance custody row body is not source closed'; END IF;
        {_integer("cxs_body->'rowOrdinal'", 255)}
        IF cxs_body->'rowOrdinal' IS DISTINCT FROM cxs_descriptor->'rowOrdinal'
            OR NOT {_closed("cxs_body->'mutation'", _MUTATION_FIELDS)}
            OR cxs_body->'mutation'->>'table' COLLATE "C" IS DISTINCT FROM '{effects.TABLE}' COLLATE "C"
        THEN RAISE EXCEPTION 'maintenance custody row coordinates differ'; END IF;
        IF cxs_phase IN (0, 4) THEN
            IF cxs_body->'mutation'->>'operation' COLLATE "C" IS DISTINCT FROM 'UPDATE' COLLATE "C"
                OR cxs_body->'mutation'->>'templateId' COLLATE "C" IS DISTINCT FROM {_literal(templates['UPDATE'])} COLLATE "C"
            THEN RAISE EXCEPTION 'maintenance custody expire template differs'; END IF;
        ELSE
            IF cxs_body->'mutation'->>'operation' COLLATE "C" IS DISTINCT FROM 'DELETE' COLLATE "C"
                OR cxs_body->'mutation'->>'templateId' COLLATE "C" IS DISTINCT FROM {_literal(templates['DELETE'])} COLLATE "C"
            THEN RAISE EXCEPTION 'maintenance custody prune template differs'; END IF;
        END IF;
        cxs_root := cxs_body->'primaryBefore';
        {_root(namespace)}
        cxs_root := cxs_body->'primaryAfter';
        {_root(namespace)}
    """


def _phase_body(namespace, ids):
    cases = "\n".join(f"WHEN {_literal(identity)} THEN {_literal(effects.projection.profile_for(identity).projection_digest)}"
        for identity in ids)
    return f"""
        IF NOT {_closed('cxs_body', _PHASE_FIELDS)}
            OR cxs_body->>'schema' COLLATE "C" IS DISTINCT FROM {_literal(source_pass.PHASE_EFFECT_SCHEMA)} COLLATE "C"
            OR pg_catalog.jsonb_typeof(cxs_body->'indexHeads') IS DISTINCT FROM 'array'
            OR cxs_ordinal <> 0
        THEN RAISE EXCEPTION 'maintenance custody phase body is not source closed'; END IF;
        {_integer("cxs_body->'rowCount'", 256)}
        IF pg_catalog.jsonb_array_length(cxs_body->'indexHeads') <> 9
        THEN RAISE EXCEPTION 'maintenance custody phase head inventory differs'; END IF;
        cxs_root := cxs_body->'primaryRoot';
        {_root(namespace)}
        cxs_ids := ARRAY[{', '.join(_literal(identity) for identity in ids)}]::text[];
        FOR cxs_head, cxs_position IN SELECT item.value, item.ordinal::integer
            FROM pg_catalog.jsonb_array_elements(cxs_body->'indexHeads')
                WITH ORDINALITY AS item(value, ordinal) ORDER BY item.ordinal
        LOOP
            cxs_projection := CASE cxs_ids[cxs_position] {cases} ELSE NULL END;
            IF NOT {_closed('cxs_head', _HEAD_FIELDS)}
                OR cxs_head->>'indexId' COLLATE "C" IS DISTINCT FROM cxs_ids[cxs_position] COLLATE "C"
                OR cxs_head->>'table' COLLATE "C" IS DISTINCT FROM '{effects.TABLE}' COLLATE "C"
                OR cxs_head->>'countedProfile' COLLATE "C" IS DISTINCT FROM {_literal(effects.projection.COUNTED_PROFILE)} COLLATE "C"
                OR cxs_head->>'projectionDigest' COLLATE "C" IS DISTINCT FROM cxs_projection COLLATE "C"
                OR cxs_head->>'projectionManifestDigest' COLLATE "C"
                    IS DISTINCT FROM {_literal(effects.projection.projection_manifest_digest())} COLLATE "C"
            THEN RAISE EXCEPTION 'maintenance custody head source differs'; END IF;
            {_integer("cxs_head->'indexRevision'")}
            {_integer("cxs_head->'rootCount'")}
            {_digest("cxs_head->'rootDigest'")}
            IF (cxs_head->>'rootCount')::bigint > (cxs_root->>'leafCount')::bigint
                OR ((cxs_head->>'indexRevision')::bigint = 0 AND (cxs_head->>'rootCount')::bigint <> 0)
                OR ((cxs_head->>'rootCount')::bigint = 0) IS DISTINCT FROM (
                    cxs_head->>'rootDigest' = {namespace}.catchplate_policy_authority_counted_empty(cxs_ids[cxs_position], ''))
            THEN RAISE EXCEPTION 'maintenance custody head root convention differs'; END IF;
        END LOOP;
    """


def _unsealed(namespace):
    return f"""
        IF EXISTS (SELECT 1 FROM {namespace}.{CUSTODY_TABLE} AS sealed
            WHERE sealed.pending_decision_digest = cxs_pending_decision_digest)
        THEN RAISE EXCEPTION 'maintenance custody is already sealed'; END IF;
    """


def validation_body_sql(namespace: str) -> str:
    """Same bounded original validator for retention, sealing and consumption."""
    _schema_name(namespace)
    ids, templates = _source()
    return f"""
        {_live()}
        IF cxs_pending_decision_digest IS NULL OR cxs_issuer_identity_digest IS NULL
            OR pg_catalog.octet_length(cxs_pending_decision_digest) <> 71
            OR pg_catalog.octet_length(cxs_issuer_identity_digest) <> 71
            OR cxs_pending_decision_digest COLLATE "C" !~ '^sha256:[0-9a-f]{{64}}$'
            OR cxs_issuer_identity_digest COLLATE "C" !~ '^sha256:[0-9a-f]{{64}}$'
            OR cxs_step_ordinal IS NULL OR cxs_step_ordinal NOT BETWEEN 0 AND {MAX_STEPS - 1}
            OR cxs_descriptor_json IS NULL OR cxs_body_json IS NULL
            OR pg_catalog.octet_length(cxs_descriptor_json) NOT BETWEEN 2 AND {MAX_DESCRIPTOR_BYTES}
            OR pg_catalog.octet_length(cxs_body_json) NOT BETWEEN 2 AND {MAX_BODY_BYTES}
            OR pg_catalog.length(cxs_descriptor_json) IS DISTINCT FROM pg_catalog.octet_length(cxs_descriptor_json)
            OR pg_catalog.length(cxs_body_json) IS DISTINCT FROM pg_catalog.octet_length(cxs_body_json)
        THEN RAISE EXCEPTION 'maintenance custody original framing differs'; END IF;
        cxs_descriptor := cxs_descriptor_json::pg_catalog.jsonb;
        cxs_body := cxs_body_json::pg_catalog.jsonb;
        {_wire(namespace, 'cxs_descriptor', 'cxs_descriptor_json', MAX_DESCRIPTOR_BYTES, nodes=16, depth=2)}
        {_wire(namespace, 'cxs_body', 'cxs_body_json', MAX_BODY_BYTES)}
        IF NOT {_closed('cxs_descriptor', _DESCRIPTOR_FIELDS)}
            OR pg_catalog.jsonb_typeof(cxs_descriptor->'kind') IS DISTINCT FROM 'string'
        THEN RAISE EXCEPTION 'maintenance custody descriptor is not source closed'; END IF;
        {_integer("cxs_descriptor->'phaseOrdinal'", 6)}
        {_integer("cxs_descriptor->'rowOrdinal'", 255)}
        {_integer("cxs_descriptor->'byteCount'", MAX_BODY_BYTES)}
        {_digest("cxs_descriptor->'digest'")}
        cxs_kind := cxs_descriptor->>'kind';
        cxs_phase := (cxs_descriptor->>'phaseOrdinal')::integer;
        cxs_ordinal := (cxs_descriptor->>'rowOrdinal')::integer;
        IF cxs_kind COLLATE "C" NOT IN ('phase-before', 'row', 'phase-after')
            OR cxs_phase NOT IN (0, 1, 2, 4, 5, 6)
            OR (cxs_descriptor->>'byteCount')::bigint IS DISTINCT FROM pg_catalog.octet_length(cxs_body_json)::bigint
            OR cxs_descriptor->>'digest' COLLATE "C" IS DISTINCT FROM (
                'sha256:' || pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(cxs_body_json, 'UTF8')), 'hex')) COLLATE "C"
        THEN RAISE EXCEPTION 'maintenance custody actual body commitment differs'; END IF;
        IF pg_catalog.jsonb_typeof(cxs_body) IS DISTINCT FROM 'object'
        THEN RAISE EXCEPTION 'maintenance custody body must be a source object'; END IF;
        {_integer("cxs_body->'phaseOrdinal'", 6)}
        IF cxs_body->'phaseOrdinal' IS DISTINCT FROM cxs_descriptor->'phaseOrdinal'
        THEN RAISE EXCEPTION 'maintenance custody body phase differs'; END IF;
        IF cxs_kind COLLATE "C" = 'row' COLLATE "C" THEN
            {_row_body(namespace, templates)}
        ELSE
            {_phase_body(namespace, ids)}
        END IF;
        {_live()}
    """


def step_body_sql(namespace: str) -> str:
    """Validate/store one tentative original; owner alone closes/seals sequence."""
    _schema_name(namespace)
    return f"""
        {validation_body_sql(namespace)}
        {_unsealed(namespace)}
        INSERT INTO {namespace}.{STEP_TABLE} ({', '.join(STEP_COLUMNS)})
            VALUES (cxs_pending_decision_digest, cxs_step_ordinal, cxs_descriptor_json,
                cxs_body_json, cxs_issuer_identity_digest)
            ON CONFLICT (pending_decision_digest, step_ordinal) DO NOTHING;
        SELECT stored.* INTO STRICT cxs_stored FROM {namespace}.{STEP_TABLE} AS stored
            WHERE stored.pending_decision_digest = cxs_pending_decision_digest
                AND stored.step_ordinal = cxs_step_ordinal FOR UPDATE;
        IF cxs_stored.pending_decision_digest COLLATE "C" IS DISTINCT FROM cxs_pending_decision_digest COLLATE "C"
            OR cxs_stored.step_ordinal IS DISTINCT FROM cxs_step_ordinal
            OR cxs_stored.descriptor_json COLLATE "C" IS DISTINCT FROM cxs_descriptor_json COLLATE "C"
            OR cxs_stored.body_json COLLATE "C" IS DISTINCT FROM cxs_body_json COLLATE "C"
            OR cxs_stored.issuer_identity_digest COLLATE "C" IS DISTINCT FROM cxs_issuer_identity_digest COLLATE "C"
        THEN RAISE EXCEPTION 'maintenance custody immutable original readback differs'; END IF;
        {_unsealed(namespace)}
        {_live()}
    """
