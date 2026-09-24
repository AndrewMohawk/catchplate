"""The v9 executor's WebAuthn trust SQL, without registry imports.

This joins publication content to its high-water record; it does not establish
an independently authenticated database root or predicate-completeness proof.
The rendered block is part of the installed executor function definition and
therefore its exact structural manifest. Existing v9 databases with the old
definition still require the separately reviewed repair contract.
"""
from __future__ import annotations

import re
import textwrap


def webauthn_credential_policy_sql() -> str:
    """Return the executor's fixed sixteen-field credential policy expression.

    The enclosing SQL supplies credential_mutation.value, assertion_evidence,
    trust_publication and computed_trust_high_water_digest. No caller-selected
    SQL or identifier is accepted. The executor retains the actual wire/domain
    commitment and its locked full-row CAS admission around this expression.

    Nullable row fields use JSON projection, not text coercion: an AAGUID is
    committed as its original JSON scalar. This fragment is not a row validator;
    a missing field projects to JSON null here but still differs from the full
    stored row at the executor's exact expectedRow CAS check.
    """
    return textwrap.dedent(
        """
        pg_catalog.jsonb_build_object(
            'schema', 'serverware.policyAuthorityCredentialPolicy/v1',
            'credentialRecordId', assertion_evidence.credential_record_id,
            'credentialId', assertion_evidence.credential_id,
            'userId', credential_mutation.value->'expectedRow'->>'user_id',
            'authenticatorClass',
                credential_mutation.value->'expectedRow'->>'authenticator_class',
            'aaguid', credential_mutation.value->'expectedRow'->'aaguid',
            'attestationTrusted',
                (credential_mutation.value->'expectedRow'->>'attestation_trusted')::bigint = 1,
            'attestationLeafDigest',
                credential_mutation.value->'expectedRow'->'attestation_leaf_sha256',
            'attestationRootDigest',
                credential_mutation.value->'expectedRow'->'attestation_root_sha256',
            'trustBundleDigest', trust_publication.bundle_digest,
            'trustBundleSequence', trust_publication.sequence,
            'trustRollbackEpoch', trust_publication.rollback_epoch,
            'trustHighWaterDigest', computed_trust_high_water_digest,
            'revocationSetDigest', trust_publication.revocation_set_digest,
            'trustWitnessReceiptDigest', trust_publication.witness_receipt_digest,
            'publicKeyDigest', 'sha256:' || pg_catalog.encode(
                pg_catalog.sha256(pg_catalog.convert_to(
                    credential_mutation.value->'expectedRow'->>'public_key_cose',
                    'UTF8'
                )),
                'hex'
            )
        )
        """
    ).strip()


def locked_webauthn_trust_projection(namespace: str) -> str:
    """Render PL/pgSQL assigning the caller's two declared record variables.

    Accept precisely the quoted namespace produced by the authority schema's
    identifier helper. Keep the high-water-first lock order and both row locks
    until the enclosing serializable executor transaction ends.
    """
    if not isinstance(namespace, str) or re.fullmatch(
        r'"[a-z][a-z0-9_]{0,127}"', namespace
    ) is None:
        raise ValueError("WebAuthn trust namespace must be an exact quoted identifier")
    return textwrap.dedent(
        f"""
        SELECT *
        INTO STRICT trust_high_water
        FROM {namespace}.webauthn_trust_publication_high_water
        WHERE authority_scope = 'webauthn-metadata'
        FOR UPDATE;
        SELECT
            publication.bundle_digest,
            publication.sequence,
            publication.rollback_epoch,
            publication.payload_digest,
            publication.withdrawn_credential_ids_json,
            high_water.publication_digest,
            high_water.metadata_blob_digest,
            high_water.revocation_set_digest,
            high_water.witness_receipt_digest,
            high_water.witness_sequence
        INTO STRICT trust_publication
        FROM {namespace}.webauthn_trust_publication_high_water AS high_water
        JOIN {namespace}.webauthn_trust_publications AS publication
          ON publication.rollback_epoch = high_water.rollback_epoch
         AND publication.sequence = high_water.publication_sequence
         AND publication.bundle_digest = high_water.publication_digest
         AND publication.payload_digest = high_water.metadata_blob_digest
        WHERE high_water.authority_scope = 'webauthn-metadata'
          AND publication.status = 'published'
        FOR UPDATE OF publication, high_water;
        """
    )
