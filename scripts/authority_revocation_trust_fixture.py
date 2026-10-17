"""Independent synthetic trust rows and credential-policy commitment recipes.

Only stdlib is imported. These literal SQL images and independent SHA framing
are test data, not production builders, signatures, currentness or authority.
"""
from __future__ import annotations

import hashlib
import json


def wire(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
        separators=(",", ":"), allow_nan=False).encode("ascii")


def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def framed(domain, *frames):
    material = domain.encode("ascii") + b"\0"
    return digest(material + b"".join(len(frame).to_bytes(8, "big") + frame for frame in frames))


def trust_rows():
    publication_digest = digest(b"fixture metadata publication")
    metadata_digest = digest(b"fixture metadata payload")
    witness_digest = digest(b"fixture metadata witness")
    publication = {"id": "fixture-publication-uuid", "scope": "global", "previous_bundle_digest": None,
        "bundle_digest": publication_digest, "sequence": 1, "rollback_epoch": 0,
        "signing_key_id": "fixture-trust-key", "bundle_json": "{}", "payload_digest": metadata_digest,
        "actor_id": "user", "withdrawn_credential_ids_json": "[]", "audit_event_json": "{}",
        "status": "published", "attempts": 0, "last_error": None,
        "created_at": "1970-01-01T00:00:01+00:00", "published_at": "1970-01-01T00:00:01+00:00"}
    high_water = {"authority_scope": "webauthn-metadata", "rollback_epoch": 0,
        "publication_sequence": 1, "publication_digest": publication_digest, "metadata_blob_digest": metadata_digest,
        "revocation_set_digest": framed("catchplate.webauthnRevocationSet/v1", wire([])),
        "witness_receipt_digest": witness_digest, "witness_sequence": 1, "updated_at_epoch_ns": 1_000_000_000}
    return {"webauthn_trust_publications": [publication],
        "webauthn_trust_publication_high_water": [high_water]}


def trust_high_water_document(high_water):
    return {"schema": "catchplate.webauthnTrustHighWater/v1", "rollbackEpoch": high_water["rollback_epoch"],
        "sequence": high_water["publication_sequence"], "publicationDigest": high_water["publication_digest"],
        "metadataBlobDigest": high_water["metadata_blob_digest"], "revocationSetDigest": high_water["revocation_set_digest"],
        "witnessReceiptDigest": high_water["witness_receipt_digest"], "witnessSequence": high_water["witness_sequence"]}


def credential_fields():
    publication = trust_rows()["webauthn_trust_publications"][0]
    return {"public_key_cose": "fixture-public-key-cose", "authenticator_class": "security-key", "aaguid": None,
        "attestation_leaf_sha256": None, "attestation_root_sha256": None,
        "attestation_trust_bundle_digest": publication["bundle_digest"],
        "attestation_trust_bundle_sequence": publication["sequence"]}


def credential_policy_document(row, high_water):
    return {"schema": "catchplate.policyAuthorityCredentialPolicy/v1",
        "credentialRecordId": row["id"], "credentialId": row["credential_id"], "userId": row["user_id"],
        "authenticatorClass": row["authenticator_class"], "aaguid": row["aaguid"],
        "attestationTrusted": bool(row["attestation_trusted"]),
        "trustBundleDigest": row["attestation_trust_bundle_digest"],
        "trustBundleSequence": row["attestation_trust_bundle_sequence"],
        "attestationLeafDigest": row["attestation_leaf_sha256"],
        "attestationRootDigest": row["attestation_root_sha256"],
        "trustRollbackEpoch": high_water["rollback_epoch"],
        "trustHighWaterDigest": framed("catchplate.webauthnTrustHighWater/v1", wire(trust_high_water_document(high_water))),
        "revocationSetDigest": high_water["revocation_set_digest"],
        "trustWitnessReceiptDigest": high_water["witness_receipt_digest"],
        "publicKeyDigest": digest(row["public_key_cose"].encode("utf-8"))}


def selected_rows():
    result = []
    for table, population in trust_rows().items():
        row = population[0]
        column = "authority_scope" if table.endswith("_high_water") else "id"
        key = {column: row[column]}
        result.append({"table": table, "key": key,
            "keyDigest": framed("catchplate.policyAuthorityBusinessKey/v1", table.encode("ascii"), wire(key)),
            "present": True, "row": row, "contractSelector": None})
    return tuple(result)
