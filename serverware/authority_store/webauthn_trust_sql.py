"""The v9 executor's locked WebAuthn trust projection, without registry imports.

This joins publication content to its high-water record; it does not establish
an independently authenticated database root or predicate-completeness proof.
The rendered block is part of the installed executor function definition and
therefore its exact structural manifest. Existing v9 databases with the old
definition still require the separately reviewed repair contract.
"""
from __future__ import annotations

import re
import textwrap


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
