"""Bind the two retained v9 WebAuthn originals without conflating their hashes.

The capability carries a WebAuthnReceipt/v1. The planner retains a separately
signed VerifiedWebAuthnAssertionReceipt/v1 and hashes that complete signed
document as AssertionEvidence/v1. These are three different commitments.

This SQL is only a storage/commit join. Actual ES256 and pinned verifier
signature checks remain in the existing producer and evidence-persistence
path. The executor must still check current trust and the exact challenge and
credential before/after CAS rows. No receipt is synthesized or persisted here.
"""
from __future__ import annotations

from serverware.authority_store.mutation_sql import _schema_name


# Keep the actual producer field families distinct. The evidence has no schema
# member; its signed domain names the family instead.
RECEIPT_FIELDS = (
    "schema", "operationId", "challengeDigest", "challengeId",
    "challengeRowDigest", "credentialRecordId", "credentialId",
    "credentialBindingDigest", "credentialPolicyDigest", "trustHighWaterDigest",
    "clientDataJSONDigest", "authenticatorDataDigest", "signatureDigest",
    "flags", "priorCounter", "counter", "userPresent", "userVerified",
    "verifiedAtEpochNs",
)
_EVIDENCE_COLUMNS = (
    ("operation", "operation"), ("operationId", "operation_id"),
    ("requestDigest", "request_digest"), ("capabilityId", "capability_id"),
    ("challengeId", "challenge_id"), ("challengeDigest", "challenge_digest"),
    ("clientChallengeDigest", "client_challenge_digest"),
    ("credentialRecordId", "credential_record_id"), ("credentialId", "credential_id"),
    ("credentialPolicyDigest", "credential_policy_digest"),
    ("authenticatorDataBase64url", "authenticator_data_base64url"),
    ("authenticatorDataDigest", "authenticator_data_digest"),
    ("clientDataJSONBase64url", "client_data_json_base64url"),
    ("clientDataJSONDigest", "client_data_json_digest"),
    ("signatureBase64url", "signature_base64url"), ("signatureDigest", "signature_digest"),
    ("rpId", "rp_id"), ("rpIdHashDigest", "rp_id_hash_digest"), ("origin", "origin"),
    ("flags", "flags"), ("priorCounter", "prior_counter"), ("counter", "counter"),
    ("trustHighWaterDigest", "trust_high_water_digest"),
    ("metadataPublicationSequence", "metadata_publication_sequence"),
    ("verifierSessionIdentityDigest", "verifier_session_identity_digest"),
    ("verifierMeasurementDigest", "verifier_measurement_digest"),
    ("verifierAttestationReceiptDigest", "verifier_attestation_receipt_digest"),
    ("verifiedAssertionReceiptDigest", "verified_assertion_receipt_digest"),
    ("verifiedAtEpochNs", "verified_at_epoch_ns"), ("expiresAtEpochNs", "expires_at_epoch_ns"),
)
EVIDENCE_FIELDS = tuple(field for field, _ in _EVIDENCE_COLUMNS) + (
    "userPresent", "userVerified", "verifierSignatureBase64url", "verifierSignatureDigest",
)
_RECEIPT_COLUMNS = tuple(
    (field, column) for field, column in _EVIDENCE_COLUMNS if field in RECEIPT_FIELDS
)


def _exact_keys(original: str, fields: tuple[str, ...]) -> str:
    # json preserves repeated keys. A jsonb-only roster could silently discard
    # them before comparing the exact canonical bytes.
    expected = ", ".join("'" + field + "'" for field in sorted(fields))
    return f"""(CASE WHEN pg_catalog.json_typeof({original})
        IS DISTINCT FROM 'object' THEN FALSE ELSE
        (SELECT pg_catalog.array_agg(key ORDER BY key COLLATE "C")
         FROM pg_catalog.json_object_keys({original}) AS key)
        IS NOT DISTINCT FROM ARRAY[{expected}]::text[] END)"""


def receipt_evidence_binding_sql(namespace: str) -> str:
    """Return the production predicate for fixed `capability`/`evidence` rows.

    These are the existing executor aliases, not caller-selected expressions.
    The inner WHERE admits only TRUE: absent/null fields cannot authenticate a
    row. JSON equality against to_jsonb also refuses numeric strings and bools
    in the actual integer columns without lossy text casts.
    """
    _schema_name(namespace)
    columns = "\n                AND ".join(
        f"bound.original->'{field}' = pg_catalog.to_jsonb(evidence.{column})"
        for field, column in _EVIDENCE_COLUMNS
    )
    receipt_columns = "\n                AND ".join(
        f"bound.receipt->'{field}' = pg_catalog.to_jsonb(evidence.{column})"
        for field, column in _RECEIPT_COLUMNS
    )
    return f"""(EXISTS (
        SELECT 1
        FROM (SELECT capability.webauthn_receipt_json::pg_catalog.jsonb AS receipt,
                     evidence.evidence_json::pg_catalog.jsonb AS original) AS bound
        WHERE {_exact_keys('capability.webauthn_receipt_json::pg_catalog.json', RECEIPT_FIELDS)}
          AND {_exact_keys('evidence.evidence_json::pg_catalog.json', EVIDENCE_FIELDS)}
          AND capability.webauthn_receipt_json =
                {namespace}.serverware_policy_authority_wire_json(bound.receipt)
          AND evidence.evidence_json =
                {namespace}.serverware_policy_authority_wire_json(bound.original)
          AND capability.webauthn_receipt_digest =
                {namespace}.serverware_policy_authority_domain_digest(
                    'serverware.policyAuthorityWebAuthnReceipt/v1',
                    capability.webauthn_receipt_json)
          AND evidence.verified_assertion_receipt_digest =
                {namespace}.serverware_policy_authority_domain_digest(
                    'serverware.policyAuthorityVerifiedWebAuthnAssertionReceipt/v1',
                    {namespace}.serverware_policy_authority_wire_json(
                        bound.original - ARRAY['verifiedAssertionReceiptDigest',
                            'verifierSignatureBase64url', 'verifierSignatureDigest']::text[]))
          AND evidence.assertion_evidence_digest =
                {namespace}.serverware_policy_authority_domain_digest(
                    'serverware.policyAuthorityWebAuthnAssertionEvidence/v1',
                    evidence.evidence_json)
          AND bound.receipt->>'schema' = 'serverware.policyAuthorityWebAuthnReceipt/v1'
          AND bound.receipt->'operationId' = pg_catalog.to_jsonb(capability.operation_id)
          AND bound.original->'operation' = pg_catalog.to_jsonb(capability.operation)
          AND bound.original->'requestDigest' = pg_catalog.to_jsonb(capability.request_digest)
          AND bound.original->'capabilityId' = pg_catalog.to_jsonb(capability.capability_id)
          AND bound.original->'trustHighWaterDigest' =
                pg_catalog.to_jsonb(capability.webauthn_trust_high_water_digest)
          AND bound.receipt->>'challengeRowDigest' ~ '^sha256:[0-9a-f]{{64}}$'
          AND bound.receipt->>'credentialBindingDigest' ~ '^sha256:[0-9a-f]{{64}}$'
          AND bound.receipt->'userPresent' = 'true'::pg_catalog.jsonb
          AND bound.receipt->'userVerified' = 'true'::pg_catalog.jsonb
          AND bound.original->'userPresent' = 'true'::pg_catalog.jsonb
          AND bound.original->'userVerified' = 'true'::pg_catalog.jsonb
          AND evidence.user_present = 1 AND evidence.user_verified = 1
          AND {receipt_columns}
          AND {columns}
    ))"""
