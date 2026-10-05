"""Protected tentative-step, complete-seal and identifier-only maintenance SQL.

Only a genuinely admitted original-byte issuer may retain and seal. SQL checks
the exact retained framing and commitments, not Ed25519 or proof truth. The
issuer's fixed native owner must replay once while streaming its same-call
effects into ONE SERIALIZABLE transaction, then seal only the actual completed
packet. On error that whole transaction aborts. A digest or prepared Python
carrier is not a public input to the issuer owner.

The distinct executor accepts only pending/packet identities. It loads sealed
protected custody, checks every raw step and source sequence, compares complete
locked before roots, performs the real row CAS and trigger updates, checks all
intermediate roots and complete after roots, and writes one unique marker in
ONE transaction. Tentative prefixes have no execution path. Complete-step and
sealed-absence predicate reads remain in SERIALIZABLE transactions, closing
concurrent append/seal conflicts without a caller mutex or advisory-lock DTO.

This renderer installs/grants nothing. Independently admitted complete catalog,
role/TLS, native transaction, original clocks and durable no-retry attempt
ownership belong to the actual fixed native caller. SQL parsing/trigger work
is not Python H/B/N accounting; inherited finite waits are not a syscall or
hostile-owner guarantee. There is no exception recovery, retry or internal
commit, and a returned marker is not a postcommit receipt.
"""
from __future__ import annotations

import re
import textwrap

from serverware import authority_challenge_execution_contract as contract
from serverware import authority_contract as authority
from serverware.authority_store import challenge_execution_custody_sql as custody
from serverware.authority_store import challenge_execution_packet_sql as packet
from serverware.authority_store import challenge_maintenance_effects_sql as rows
from serverware.authority_store import current_root_execution_sql as roots
from serverware.authority_store import successor_execution_sql as admission
from serverware.authority_store.mutation_sql import _schema_name
from serverware.authority_store.revocation_retained_sql import _literal


def _selectors():
    return """
        IF cxe_pending_decision_digest IS NULL OR cxe_packet_digest IS NULL
            OR cxe_pending_decision_digest COLLATE "C" !~ '^sha256:[0-9a-f]{64}$'
            OR cxe_packet_digest COLLATE "C" !~ '^sha256:[0-9a-f]{64}$'
        THEN RAISE EXCEPTION 'maintenance custody selectors are not exact'; END IF;
    """


def _steps(namespace, *, apply):
    if type(apply) is not bool:
        raise ValueError("maintenance effects selection is source fixed")
    before = rows.phase_roots_body_sql(namespace, stage="before") if apply else ""
    after = rows.phase_roots_body_sql(namespace, stage="after") if apply else ""
    mutation = (roots._wire(namespace, "cxs_body->'mutation'", "cme_mutation_json", rows.MAX_MUTATION_BYTES)
        + rows.row_body_sql(namespace)) if apply else ""
    return f"""
        cxg_seen := 0; cxg_position := 1; cxg_expected := NULL; cxg_rows := 0;
        cxg_total := 0; cxg_previous_primary := NULL;
        cxg_phases := ARRAY[0, 1, 2, 4, 5, 6]::integer[];
        FOR cxg_step IN SELECT stored.* FROM {namespace}.{custody.STEP_TABLE} AS stored
            WHERE stored.pending_decision_digest = cxe_pending_decision_digest
            ORDER BY stored.step_ordinal LIMIT {custody.MAX_STEPS + 1} FOR UPDATE
        LOOP
            IF cxg_seen >= {custody.MAX_STEPS}
                OR cxg_seen >= (cxe_stream->>'stepCount')::integer
                OR cxg_step.step_ordinal IS DISTINCT FROM cxg_seen
                OR cxg_step.issuer_identity_digest IS DISTINCT FROM cxg_issuer_identity
                OR cxg_step.pending_decision_digest IS DISTINCT FROM cxe_pending_decision_digest
            THEN RAISE EXCEPTION 'maintenance stored step identity or complete count differs'; END IF;
            cxs_pending_decision_digest := cxe_pending_decision_digest;
            cxs_step_ordinal := cxg_seen; cxs_descriptor_json := cxg_step.descriptor_json;
            cxs_body_json := cxg_step.body_json; cxs_issuer_identity_digest := cxg_issuer_identity;
            cxs_deadline_epoch_ns := cxe_deadline_epoch_ns;
            {custody.validation_body_sql(namespace)}
            IF cxs_descriptor IS DISTINCT FROM cxe_stream->'steps'->cxg_seen
                OR cxg_position > 6 OR cxs_phase IS DISTINCT FROM cxg_phases[cxg_position]
            THEN RAISE EXCEPTION 'maintenance stored step differs from its sealed descriptor'; END IF;
            cme_phase_ordinal := cxs_phase; cme_row_ordinal := cxs_ordinal;
            cme_deadline_epoch_ns := cxe_deadline_epoch_ns;
            IF cxs_kind = 'phase-before' THEN
                IF cxg_expected IS NOT NULL OR cxs_ordinal <> 0
                THEN RAISE EXCEPTION 'maintenance phase opening is out of order'; END IF;
                cxg_expected := (cxs_body->>'rowCount')::integer; cxg_rows := 0;
                IF cxg_previous_primary IS NOT NULL
                    AND cxg_previous_primary IS DISTINCT FROM cxs_body->'primaryRoot'
                THEN RAISE EXCEPTION 'maintenance primary phase chain differs'; END IF;
                cxg_previous_primary := cxs_body->'primaryRoot';
                cme_phase_before := pg_catalog.jsonb_build_object(
                    'primaryRoot', cxs_body->'primaryRoot', 'indexHeads', cxs_body->'indexHeads');
                {before}
            ELSIF cxs_kind = 'row' THEN
                IF cxg_expected IS NULL OR cxg_rows >= cxg_expected OR cxs_ordinal <> cxg_rows
                    OR cxs_body->'primaryBefore' IS DISTINCT FROM cxg_previous_primary
                THEN RAISE EXCEPTION 'maintenance row sequence or primary chain differs'; END IF;
                cme_primary_before := cxs_body->'primaryBefore';
                cme_primary_after := cxs_body->'primaryAfter';
                {mutation}
                cxg_previous_primary := cxs_body->'primaryAfter'; cxg_rows := cxg_rows + 1;
            ELSE
                IF cxg_expected IS NULL OR cxg_rows <> cxg_expected OR cxs_ordinal <> 0
                    OR (cxs_body->>'rowCount')::integer IS DISTINCT FROM cxg_expected
                    OR cxs_body->'primaryRoot' IS DISTINCT FROM cxg_previous_primary
                THEN RAISE EXCEPTION 'maintenance phase closure differs'; END IF;
                cme_phase_after := pg_catalog.jsonb_build_object(
                    'primaryRoot', cxs_body->'primaryRoot', 'indexHeads', cxs_body->'indexHeads');
                {after}
                cxg_position := cxg_position + 1; cxg_expected := NULL;
            END IF;
            cxg_seen := cxg_seen + 1;
            cxg_total := cxg_total + pg_catalog.octet_length(cxg_step.body_json)::bigint;
        END LOOP;
        IF cxg_seen IS DISTINCT FROM (cxe_stream->>'stepCount')::integer
            OR cxg_total IS DISTINCT FROM (cxe_stream->>'totalBodyBytes')::bigint
            OR cxg_position <> 7 OR cxg_expected IS NOT NULL
        THEN RAISE EXCEPTION 'maintenance stored raw stream is incomplete'; END IF;
    """


def functions_sql(namespace: str, *, owner_role: str, issuer_pins: tuple, executor_pins: tuple) -> str:
    """Three fixed functions only; explicit cold installation/ACLs are separate."""
    _schema_name(namespace)
    if (type(owner_role) is not str or re.fullmatch(r"[a-z][a-z0-9_]{0,62}", owner_role) is None
            or owner_role in (contract.ISSUER_ROLE, contract.EXECUTOR_ROLE)
            or contract.OPERATION != rows.OPERATION or custody.MAX_STEPS != 1548):
        raise ValueError("maintenance execution source or owner is not exact")
    issuer_pins, executor_pins = admission._pins(issuer_pins), admission._pins(executor_pins)
    if issuer_pins[3:] == executor_pins[3:]:
        raise ValueError("maintenance issuer and executor TLS principals must be distinct")
    issuer_identity = (f"{namespace}.serverware_policy_authority_domain_digest("
        + ", ".join(_literal(value) for value in (contract.ISSUER_IDENTITY_DOMAIN,
            contract.ISSUER_ROLE, *issuer_pins[3:], *issuer_pins[:3])) + ")")
    declarations = f"""
        {custody.declarations_sql()}
        {packet.declarations_sql()}
        {roots.current_root_execution_declarations_sql()}
        {rows.declarations_sql()}
        cxg_custody record; cxg_step record; cxg_seen integer; cxg_position integer;
        cxg_expected integer; cxg_rows integer; cxg_total bigint; cxg_phases integer[];
        cxg_previous_primary jsonb; cxg_issuer_identity text;
        sxe_statement_ms bigint; sxe_lock_ms bigint; sxe_idle_ms bigint; sxe_deadline numeric;
        sxe_tls boolean; sxe_dn text; sxe_serial text; sxe_issuer_dn text; sxe_session_identity text;
    """
    step = f"""
        IF supplied_deadline_epoch_ns IS NULL OR supplied_deadline_epoch_ns <= 0
        THEN RAISE EXCEPTION 'maintenance step lacks its original bound'; END IF;
        cxs_pending_decision_digest := supplied_pending_decision_digest;
        cxs_step_ordinal := supplied_step_ordinal; cxs_descriptor_json := supplied_descriptor_json;
        cxs_body_json := supplied_body_json; cxs_issuer_identity_digest := sxe_session_identity;
        cxs_deadline_epoch_ns := LEAST(sxe_deadline, supplied_deadline_epoch_ns)::bigint;
        {custody.step_body_sql(namespace)}
        RETURN cxs_step_ordinal;
    """
    bind = f"""
        cxe_pending_decision_digest := supplied_pending_decision_digest;
        cxe_packet_digest := supplied_packet_digest; cxe_deadline_epoch_ns := sxe_deadline::bigint;
        cxg_issuer_identity := {issuer_identity};
        {_selectors()}
    """
    exact = """
        IF cxg_custody.pending_decision_digest IS DISTINCT FROM cxe_pending_decision_digest
            OR cxg_custody.packet_digest IS DISTINCT FROM cxe_packet_digest
            OR cxg_custody.packet_json IS DISTINCT FROM cxe_packet_json
            OR cxg_custody.issuer_identity_digest IS DISTINCT FROM cxg_issuer_identity
        THEN RAISE EXCEPTION 'maintenance protected custody original differs'; END IF;
    """
    seal = f"""
        {bind}
        IF sxe_session_identity IS DISTINCT FROM cxg_issuer_identity
        THEN RAISE EXCEPTION 'maintenance actual issuer identity changed'; END IF;
        cxe_packet_json := supplied_packet_json;
        {packet.packet_body_sql(namespace)}
        cxs_pending_decision_digest := cxe_pending_decision_digest;
        {custody._unsealed(namespace)}
        {_steps(namespace, apply=False)}
        INSERT INTO {namespace}.{custody.CUSTODY_TABLE} ({', '.join(custody.CUSTODY_COLUMNS)})
            VALUES (cxe_pending_decision_digest, cxe_packet_digest, cxe_packet_json, cxg_issuer_identity);
        SELECT stored.* INTO STRICT cxg_custody FROM {namespace}.{custody.CUSTODY_TABLE} AS stored
            WHERE stored.pending_decision_digest = cxe_pending_decision_digest FOR UPDATE;
        {exact}
        sxe_deadline := LEAST(sxe_deadline, cxe_deadline_epoch_ns);
        {admission._live()}
        RETURN QUERY SELECT cxe_pending_decision_digest, cxe_packet_digest, cxe_issued, cxe_expires;
    """
    execute = f"""
        {bind}
        SELECT stored.* INTO STRICT cxg_custody FROM {namespace}.{custody.CUSTODY_TABLE} AS stored
            WHERE stored.pending_decision_digest = cxe_pending_decision_digest FOR UPDATE;
        cxe_packet_json := cxg_custody.packet_json;
        {exact}
        {packet.packet_body_sql(namespace)}
        crx_operation := '{contract.OPERATION}'; crx_request_digest := cxe_stream->>'requestDigest';
        crx_operation_id := cxe_stream->>'operationId'; crx_marker := cxe_marker;
        crx_before_vector_json := cxe_before_vector_json; crx_after_vector_json := cxe_after_vector_json;
        crx_result_json := cxe_result_json; crx_deadline_epoch_ns := cxe_deadline_epoch_ns;
        {roots.maintenance_execution_begin_sql(namespace)}
        {_steps(namespace, apply=True)}
        {roots.maintenance_execution_finish_sql(namespace)}
        sxe_deadline := LEAST(sxe_deadline, cxe_deadline_epoch_ns);
        {admission._live()}
        RETURN crx_marker_json;
    """
    definitions = (
        (contract.STEP_FUNCTION, "supplied_pending_decision_digest text, supplied_step_ordinal integer, "
            "supplied_descriptor_json text, supplied_body_json text, supplied_deadline_epoch_ns bigint",
            "integer", contract.ISSUER_ROLE, issuer_pins, contract.ISSUER_IDENTITY_DOMAIN, step),
        (contract.SEAL_FUNCTION, "supplied_pending_decision_digest text, supplied_packet_digest text, supplied_packet_json text",
            "TABLE(pending_decision_digest text, packet_digest text, issued_at_epoch_ns bigint, expires_at_epoch_ns bigint)",
            contract.ISSUER_ROLE, issuer_pins, contract.ISSUER_IDENTITY_DOMAIN, seal),
        (contract.EXECUTE_FUNCTION, "supplied_pending_decision_digest text, supplied_packet_digest text",
            "text", contract.EXECUTOR_ROLE, executor_pins, contract.EXECUTOR_IDENTITY_DOMAIN, execute),
    )
    return "\n".join(textwrap.dedent(f"""
        CREATE OR REPLACE FUNCTION {namespace}.{name}({parameters}) RETURNS {returns}
        LANGUAGE plpgsql SECURITY DEFINER VOLATILE
        SET search_path = pg_catalog, {namespace}, pg_temp
        AS $serverware_challenge_execution$
        DECLARE
            {declarations}
        BEGIN
            {admission._admission(namespace, role, owner_role, pins, domain)}
            {body}
        END;
        $serverware_challenge_execution$;
    """) for name, parameters, returns, role, pins, domain, body in definitions)
