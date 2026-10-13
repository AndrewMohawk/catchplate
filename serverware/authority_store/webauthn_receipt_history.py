"""Retain the admitted raw WebAuthn receipt inside the JIT executor transaction.

This is framework history, not a receipt producer or business mutation. Fresh
execution calls it only after the existing signed-evidence, current-trust and
challenge/counter CAS guards. A later failed mutation or commit rolls it back.
Committed replay only checks the original history; it cannot repair or backfill
it and does not require historical evidence to remain currently unexpired.
"""
from __future__ import annotations

from serverware.authority_store.mutation_sql import _schema_name
from serverware.authority_store.webauthn_receipt_binding import RECEIPT_FIELDS, _exact_keys


TABLE = "policy_authority_webauthn_assertion_receipts"
_CAPABILITY_COLUMNS = (
    ("assertion_receipt_digest", "webauthn_receipt_digest"),
    ("capability_id", "capability_id"),
    ("operation_id", "operation_id"),
    ("operation", "operation"),
    ("request_digest", "request_digest"),
    ("receipt_json", "webauthn_receipt_json"),
)
_RECEIPT_COLUMNS = (
    ("challenge_id", "challengeId"),
    ("credential_record_id", "credentialRecordId"),
    ("credential_id", "credentialId"),
    ("credential_policy_digest", "credentialPolicyDigest"),
    ("trust_high_water_digest", "trustHighWaterDigest"),
    ("client_data_json_digest", "clientDataJSONDigest"),
    ("authenticator_data_digest", "authenticatorDataDigest"),
    ("signature_digest", "signatureDigest"),
    ("flags", "flags"),
    ("prior_counter", "priorCounter"),
    ("counter", "counter"),
    ("verified_at_epoch_ns", "verifiedAtEpochNs"),
)


def _history_sql(namespace: str, *, retain: bool) -> str:
    _schema_name(namespace)
    projection = ",\n                ".join(
        [f"'{column}', pg_catalog.to_jsonb(capability.{field})"
         for column, field in _CAPABILITY_COLUMNS]
        + [f"'{column}', historical_original->'{field}'"
           for column, field in _RECEIPT_COLUMNS]
    )
    columns = tuple(column for column, _ in _CAPABILITY_COLUMNS + _RECEIPT_COLUMNS)
    insert = f"""
            INSERT INTO {namespace}.{TABLE} ({', '.join(columns)})
            SELECT {', '.join('projected.' + column for column in columns)}
            FROM pg_catalog.jsonb_populate_record(
                NULL::{namespace}.{TABLE}, historical_expected) AS projected
            ON CONFLICT (assertion_receipt_digest) DO NOTHING;
    """ if retain else ""
    return f"""
        IF capability.operation IN ('jit.decide', 'jit.deny') THEN
            DECLARE
                historical_original pg_catalog.jsonb;
                historical_expected pg_catalog.jsonb;
                historical_observed pg_catalog.jsonb;
            BEGIN
                historical_original := capability.webauthn_receipt_json::pg_catalog.jsonb;
                IF ({_exact_keys('capability.webauthn_receipt_json::pg_catalog.json', RECEIPT_FIELDS)}
                    AND historical_original->>'schema' = 'serverware.policyAuthorityWebAuthnReceipt/v1'
                    AND historical_original->'operationId' = pg_catalog.to_jsonb(capability.operation_id)
                    AND historical_original->'trustHighWaterDigest' =
                        pg_catalog.to_jsonb(capability.webauthn_trust_high_water_digest)
                    AND historical_original->'userPresent' = 'true'::pg_catalog.jsonb
                    AND historical_original->'userVerified' = 'true'::pg_catalog.jsonb
                    AND capability.webauthn_receipt_json =
                        {namespace}.serverware_policy_authority_wire_json(historical_original)
                    AND capability.webauthn_receipt_digest =
                        {namespace}.serverware_policy_authority_domain_digest(
                            'serverware.policyAuthorityWebAuthnReceipt/v1',
                            capability.webauthn_receipt_json)
                ) IS NOT TRUE THEN
                    RAISE EXCEPTION 'authority JIT raw WebAuthn history binding changed';
                END IF;
                historical_expected := pg_catalog.jsonb_build_object(
                    {projection});
                {insert}
                SELECT pg_catalog.to_jsonb(retained) INTO historical_observed
                FROM {namespace}.{TABLE} AS retained
                WHERE retained.assertion_receipt_digest = capability.webauthn_receipt_digest
                FOR UPDATE;
                IF historical_observed IS DISTINCT FROM historical_expected THEN
                    RAISE EXCEPTION 'authority JIT WebAuthn history is absent or not exact';
                END IF;
            END;
        END IF;
    """


def retain_webauthn_receipt_sql(namespace: str) -> str:
    """Insert/check exact admitted history; fixed executor `capability` alias.

    The caller owns the SERIALIZABLE transaction and all authorization/CAS
    checks. This fragment neither commits nor consumes a capability. Existing
    unique constraints reject conflicts on any other historical identity.
    """
    return _history_sql(namespace, retain=True)


def assert_webauthn_receipt_history_sql(namespace: str) -> str:
    """Read-only exact history check for an already-admitted committed replay."""
    return _history_sql(namespace, retain=False)
