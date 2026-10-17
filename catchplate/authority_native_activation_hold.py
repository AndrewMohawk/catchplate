"""Durable exclusive publication intent at both genuine writer effect paths.

The original window restricts the native effect; it NEVER unlocks this row.
Unknown native effects leave it held. Only a verified publication finalization
can publish the terminal row. The whole actual SQL function/privilege closure
must be independently admitted; a dictionary with this digest is not a hold.
"""
from catchplate import authority_policy_canary as p

TABLE = "policy_native_activation_holds"
SCOPE = "native-policy-publication"
FIELDS = frozenset({"scope", "phase", "canary_id", "activation_id", "prepared_sha256", "prepare_request_digest",
    "configuration_digest", "guard_sha256", "issued_at_epoch_ns", "expires_at_epoch_ns", "publication_sha256", "finalization_digest"})
EXEMPT = ("metadata_audit_outbox", "policy_authority_bounded_aggregate_states", "policy_authority_transition_audits")
CONTRACT = {"apiVersion": "catchplate.nativePolicyActivationEffectGuard/v1", "scope": SCOPE,
    "authority": "all-source-admitted-controlled-business-and-authorization-mutations",
    "serialization": "exclusive-held-table-lock-before-any-business-mutation",
    "exemptTables": list(EXEMPT), "ownerOperations": ["native-policy-activation.record-inclusion", "native-policy-activation.finalize"],
    "expiryUnlockAllowed": False, "unknownEffectUnlockAllowed": False}
GUARD_SHA256 = p.sha256(p.canonical(CONTRACT))


def original(value):
    p.require(type(value) is dict and set(value) == FIELDS and value["scope"] == SCOPE
        and value["phase"] in {"held", "published"} and value["guard_sha256"] == GUARD_SHA256)
    p.text(value["canary_id"], 256); p.identifier(value["activation_id"])
    for name in ("prepared_sha256", "prepare_request_digest", "configuration_digest"):
        p.digest(value[name])
    p.require(0 < p.epoch(value["expires_at_epoch_ns"]) - p.epoch(value["issued_at_epoch_ns"]) <= 300_000_000_000)
    for name in ("publication_sha256", "finalization_digest"):
        p.require(value[name] is None if value["phase"] == "held" else type(value[name]) is str)
        if value[name] is not None:
            p.digest(value[name])
    return value


def sql(namespace, *, operation_sql, mutations_sql):
    # Expressions are finite source call sites, never packet text.
    p.require(operation_sql in {"capability.operation", "crx_operation"}
        and mutations_sql in {"planner.mutation_plan_json::pg_catalog.jsonb", "crx_mutations"})
    from catchplate.authority_store.mutation_sql import _schema_name
    _schema_name(namespace)
    exempt = ",".join("'" + table + "'" for table in EXEMPT)
    return f"""
        -- Both real writers acquire this before any business mutation. The
        -- relation lock covers absence too: concurrent PREPARE cannot slip
        -- between a check and an unrelated authority/root update.
        LOCK TABLE {namespace}.{TABLE} IN EXCLUSIVE MODE;
        IF EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements({mutations_sql}) m
          JOIN {namespace}.policy_native_canary_heads h ON h.canary_id = m->'key'->>'canary_id'
          WHERE m->>'table' = 'policy_canary_heads'
            AND (m->>'operation' <> 'UPDATE' OR m->'row' IS DISTINCT FROM m->'expectedRow'))
        THEN RAISE EXCEPTION 'native canary successor cannot be advanced by a legacy head'; END IF;
        IF EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements({mutations_sql}) m
            WHERE m->>'table' = '{TABLE}') AND {operation_sql} NOT IN
                ('native-policy-activation.consume','native-policy-activation.finalize')
        THEN RAISE EXCEPTION 'native publication hold has no generic mutation permission'; END IF;
        IF EXISTS (SELECT 1 FROM {namespace}.{TABLE} h WHERE h.scope = '{SCOPE}' AND h.phase = 'held')
          AND EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements({mutations_sql}) m
            WHERE m->>'table' NOT IN ({exempt}))
          AND NOT (
            ({operation_sql} = 'native-policy-activation.record-inclusion'
              AND NOT EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements({mutations_sql}) m
                WHERE m->>'table' NOT IN ({exempt}, 'policy_native_activation_preparations'))
              AND EXISTS (SELECT 1 FROM {namespace}.{TABLE} h,
                  pg_catalog.jsonb_array_elements({mutations_sql}) m
                WHERE h.scope = '{SCOPE}' AND h.phase = 'held'
                  AND m->>'table' = 'policy_native_activation_preparations' AND m->>'operation' = 'UPDATE'
                  AND m->'expectedRow'->>'activation_id' = h.activation_id
                  AND m->'row'->>'activation_id' = h.activation_id
                  AND m->'expectedRow'->>'prepared_sha256' = h.prepared_sha256
                  AND m->'row'->>'prepared_sha256' = h.prepared_sha256))
            OR ({operation_sql} = 'native-policy-activation.finalize'
              AND EXISTS (SELECT 1 FROM {namespace}.{TABLE} h,
                  pg_catalog.jsonb_array_elements({mutations_sql}) m,
                  pg_catalog.jsonb_array_elements({mutations_sql}) f
                WHERE h.scope = '{SCOPE}' AND h.phase = 'held'
                  AND m->>'table' = '{TABLE}' AND m->>'operation' = 'UPDATE'
                  AND m->'expectedRow' = to_jsonb(h) AND m->'row'->>'phase' = 'published'
                  AND ((m->'row') - 'phase' - 'publication_sha256' - 'finalization_digest') =
                    (to_jsonb(h) - 'phase' - 'publication_sha256' - 'finalization_digest')
                  AND f->>'table' = 'policy_native_activation_finalizations' AND f->>'operation' = 'INSERT'
                  AND f->'row'->>'activation_id' = h.activation_id
                  AND f->'row'->>'prepared_sha256' = h.prepared_sha256
                  AND f->'row'->>'publication_sha256' = m->'row'->>'publication_sha256'
                  AND f->'row'->>'finalization_digest' = m->'row'->>'finalization_digest')))
        THEN RAISE EXCEPTION 'native publication current-root hold is unresolved'; END IF;
    """
