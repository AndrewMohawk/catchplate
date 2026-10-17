"""Source-installed, deferred equality guard for inline retention commitments.

This guard never fills or repairs a challenge row. Actual measured writers must
derive and explicitly mutate the inline fields; this independent SQL check
rejoins the real reference originals at the end of the same transaction. Root
currentness, writer admission and before/after proof checks remain mandatory.
"""
from __future__ import annotations

import re


FUNCTION_NAME = "catchplate_policy_authority_challenge_retention_guard"
SOURCE_TABLES = (
    "jit_webauthn_assertion_receipts",
    "policy_activation_webauthn_assertions",
    "webauthn_challenges",
    "webauthn_recovery_ceremonies",
)
INLINE_FIELDS = (
    "retention_recovery_id", "retention_recovery_row_digest",
    "retention_jit_receipt_digest", "retention_jit_row_digest",
    "retention_activation_receipt_digest", "retention_activation_row_digest",
    "retention_reference_mask",
)


def _namespace(value: str) -> str:
    if type(value) is not str or re.fullmatch(r'"[a-z][a-z0-9_]{0,62}"', value) is None:
        raise ValueError("challenge retention namespace is not source bounded")
    return value


def challenge_retention_function_sql(namespace: str) -> str:
    namespace = _namespace(namespace)
    comparisons = " OR\n                ".join(
        f"actual->'{field}' IS DISTINCT FROM expected->'{field}'" for field in INLINE_FIELDS
    )
    sources = ", ".join(f"'{table}'" for table in SOURCE_TABLES)
    # Deferred firing occurs after the admitted writer has returned to its
    # restricted caller. Read the fixed reference originals as the existing
    # source-owned, non-login function owner, without granting callers SELECT.
    return f"""
        CREATE OR REPLACE FUNCTION {namespace}.{FUNCTION_NAME}()
        RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path = pg_catalog, {namespace}, pg_temp
        AS $challenge_retention_guard$
        DECLARE
            old_id text;
            new_id text;
            target_challenge_id text;
            actual jsonb;
            recovery jsonb;
            jit jsonb;
            activation jsonb;
            expected jsonb;
        BEGIN
            IF TG_TABLE_SCHEMA COLLATE "C" <> '{namespace[1:-1]}' COLLATE "C"
                OR TG_TABLE_NAME COLLATE "C" NOT IN ({sources})
                OR TG_OP COLLATE "C" NOT IN ('INSERT', 'UPDATE', 'DELETE')
                OR TG_WHEN <> 'AFTER' OR TG_LEVEL <> 'ROW' OR TG_NARGS <> 0
            THEN RAISE EXCEPTION 'challenge retention guard source is not exact'; END IF;
            IF TG_OP IN ('UPDATE', 'DELETE') THEN
                old_id := pg_catalog.to_jsonb(OLD)->>
                    CASE WHEN TG_TABLE_NAME = 'webauthn_challenges' THEN 'id' ELSE 'challenge_id' END;
            END IF;
            IF TG_OP IN ('INSERT', 'UPDATE') THEN
                new_id := pg_catalog.to_jsonb(NEW)->>
                    CASE WHEN TG_TABLE_NAME = 'webauthn_challenges' THEN 'id' ELSE 'challenge_id' END;
            END IF;
            IF (TG_OP <> 'INSERT' AND old_id IS NULL)
                OR (TG_OP <> 'DELETE' AND new_id IS NULL)
            THEN RAISE EXCEPTION 'challenge retention source identity is absent'; END IF;
            FOR target_challenge_id IN
                SELECT DISTINCT value COLLATE "C" FROM (VALUES (old_id), (new_id)) AS ids(value)
                WHERE value IS NOT NULL
            LOOP
                SELECT pg_catalog.to_jsonb(source_row) INTO actual
                    FROM {namespace}.webauthn_challenges AS source_row
                    WHERE source_row.id = target_challenge_id;
                -- Each source relation has an independently admitted UNIQUE
                -- challenge_id constraint. No status or expiry filter is used.
                SELECT pg_catalog.to_jsonb(source_row) INTO recovery
                    FROM {namespace}.webauthn_recovery_ceremonies AS source_row
                    WHERE source_row.challenge_id = target_challenge_id;
                SELECT pg_catalog.to_jsonb(source_row) INTO jit
                    FROM {namespace}.jit_webauthn_assertion_receipts AS source_row
                    WHERE source_row.challenge_id = target_challenge_id;
                SELECT pg_catalog.to_jsonb(source_row) INTO activation
                    FROM {namespace}.policy_activation_webauthn_assertions AS source_row
                    WHERE source_row.challenge_id = target_challenge_id;
                IF actual IS NULL THEN
                    IF recovery IS NOT NULL OR jit IS NOT NULL OR activation IS NOT NULL THEN
                        RAISE EXCEPTION 'challenge retention source survives its challenge';
                    END IF;
                    CONTINUE;
                END IF;
                expected := pg_catalog.jsonb_build_object(
                    'retention_recovery_id', recovery->>'id',
                    'retention_recovery_row_digest', CASE WHEN recovery IS NULL THEN NULL ELSE
                        {namespace}.catchplate_policy_authority_framed_digest(
                            'catchplate.policyAuthorityAuthenticatedRow/v1',
                            'webauthn_recovery_ceremonies',
                            {namespace}.catchplate_policy_authority_canonical_json(recovery)) END,
                    'retention_jit_receipt_digest', jit->>'assertion_receipt_digest',
                    'retention_jit_row_digest', CASE WHEN jit IS NULL THEN NULL ELSE
                        {namespace}.catchplate_policy_authority_framed_digest(
                            'catchplate.policyAuthorityAuthenticatedRow/v1',
                            'jit_webauthn_assertion_receipts',
                            {namespace}.catchplate_policy_authority_canonical_json(jit)) END,
                    'retention_activation_receipt_digest', activation->>'assertion_receipt_digest',
                    'retention_activation_row_digest', CASE WHEN activation IS NULL THEN NULL ELSE
                        {namespace}.catchplate_policy_authority_framed_digest(
                            'catchplate.policyAuthorityAuthenticatedRow/v1',
                            'policy_activation_webauthn_assertions',
                            {namespace}.catchplate_policy_authority_canonical_json(activation)) END,
                    'retention_reference_mask',
                        CASE WHEN recovery IS NULL THEN 0 ELSE 1 END +
                        CASE WHEN jit IS NULL THEN 0 ELSE 2 END +
                        CASE WHEN activation IS NULL THEN 0 ELSE 4 END);
                IF {comparisons}
                THEN RAISE EXCEPTION 'challenge retention original join differs'; END IF;
            END LOOP;
            RETURN NULL;
        END;
        $challenge_retention_guard$
    """


def challenge_retention_installation_sql(namespace: str) -> tuple[str, ...]:
    """Fresh-only installation, not a migration or initial-population assertion.

    The surrounding bootstrap owns its transaction and writer exclusion. The
    source installer does not adopt, scan, repair or backfill an existing store.
    """
    namespace = _namespace(namespace)
    nonempty = " OR ".join(
        f"EXISTS (SELECT 1 FROM {namespace}.{table} LIMIT 1)" for table in SOURCE_TABLES
    )
    preflight = f"""
        DO $challenge_retention_fresh$
        BEGIN
            IF {nonempty} THEN
                RAISE EXCEPTION 'challenge retention installation requires empty source tables';
            END IF;
        END;
        $challenge_retention_fresh$
    """
    triggers = tuple(
        f"CREATE CONSTRAINT TRIGGER catchplate_retention_{ordinal} "
        f"AFTER INSERT OR UPDATE OR DELETE ON {namespace}.{table} "
        f"DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION "
        f"{namespace}.{FUNCTION_NAME}()"
        for ordinal, table in enumerate(SOURCE_TABLES)
    )
    return (preflight, challenge_retention_function_sql(namespace), *triggers)
