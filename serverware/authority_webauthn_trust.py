"""Shared WebAuthn high-water commitment, without service or registry imports.

The document is the actual verifier service's trust binding. Recomputing it
does not prove a row, publication status, pending absence or root currentness.
The optional private work object is supplied by an already-owning composer.
"""
from __future__ import annotations

import hashlib

from serverware import authority_transition_core as core
from serverware.authority_query_read_work import _ValidationWork, QueryReadWorkError


DOMAIN = "serverware.webauthnTrustHighWater/v1"
POLICY_DOMAIN = "serverware.policyAuthorityCredentialPolicy/v1"
HIGH_WATER_TABLE = "webauthn_trust_publication_high_water"
PUBLICATION_TABLE = "webauthn_trust_publications"
AUTHORITY_SCOPE = "webauthn-metadata"
_FIELDS = frozenset({"schema", "rollbackEpoch", "sequence", "publicationDigest",
    "metadataBlobDigest", "revocationSetDigest", "witnessReceiptDigest", "witnessSequence"})
_DIGEST_FIELDS = ("publicationDigest", "metadataBlobDigest", "revocationSetDigest", "witnessReceiptDigest")
_POLICY_FIELDS = frozenset({"schema", "credentialRecordId", "credentialId", "userId",
    "authenticatorClass", "aaguid", "attestationTrusted", "trustBundleDigest", "trustBundleSequence",
    "attestationLeafDigest", "attestationRootDigest", "trustRollbackEpoch", "trustHighWaterDigest",
    "revocationSetDigest", "trustWitnessReceiptDigest", "publicKeyDigest"})
_I64_MAX = 2**63 - 1


class WebAuthnTrustError(ValueError):
    pass


def _validate(document) -> None:
    if (type(document) is not dict or len(document) != len(_FIELDS)
            or any(type(name) is not str for name in document) or set(document) != _FIELDS
            or type(document["schema"]) is not str or document["schema"] != DOMAIN):
        raise WebAuthnTrustError("WebAuthn trust high-water document is not source closed")
    for name, minimum in (("rollbackEpoch", 0), ("sequence", 1), ("witnessSequence", 1)):
        if type(document[name]) is not int or not minimum <= document[name] <= _I64_MAX:
            raise WebAuthnTrustError("WebAuthn trust high-water integer is outside signed64 source bounds")
    for name in _DIGEST_FIELDS:
        value = document[name]
        if (type(value) is not str or len(value) != 71 or value[:7] != "sha256:"
                or any(character not in "0123456789abcdef" for character in value[7:])):
            raise WebAuthnTrustError("WebAuthn trust high-water digest is not canonical")


def high_water_document(*, rollback_epoch, sequence, publication_digest,
                        metadata_blob_digest, revocation_set_digest,
                        witness_receipt_digest, witness_sequence) -> dict:
    """Construct the genuine service's fixed eight-field trust document."""
    document = {
        "schema": DOMAIN, "rollbackEpoch": rollback_epoch, "sequence": sequence,
        "publicationDigest": publication_digest, "metadataBlobDigest": metadata_blob_digest,
        "revocationSetDigest": revocation_set_digest, "witnessReceiptDigest": witness_receipt_digest,
        "witnessSequence": witness_sequence,
    }
    _validate(document)
    return document


def high_water_digest(document, *, work: _ValidationWork | None = None) -> str:
    """Encode and hash the source document; no fresh allowance or proof result."""
    if work is not None and type(work) is not _ValidationWork:
        raise QueryReadWorkError("WebAuthn trust commitment requires the exact shared meter")
    _validate(document)
    return _document_digest(DOMAIN, document, work)


def _document_digest(domain, document, work) -> str:
    if work is not None:
        size, _ = work.prepare_encoding(document)
        work.prepare_utf8(domain)
        work.charge(hashes=1, input_bytes=9 + size)
    return core.framed_digest(domain, core.canonical_bytes(document))


def _validate_policy(document) -> None:
    if (type(document) is not dict or len(document) != len(_POLICY_FIELDS)
            or any(type(name) is not str for name in document) or set(document) != _POLICY_FIELDS
            or type(document["schema"]) is not str or document["schema"] != POLICY_DOMAIN):
        raise WebAuthnTrustError("WebAuthn credential policy is not source closed")
    for name in ("credentialRecordId", "credentialId", "userId", "authenticatorClass"):
        if type(document[name]) is not str or not document[name]:
            raise WebAuthnTrustError("WebAuthn credential policy text is not exact")
    if document["aaguid"] is not None and type(document["aaguid"]) is not str:
        raise WebAuthnTrustError("WebAuthn credential policy AAGUID is not nullable text")
    if type(document["attestationTrusted"]) is not bool:
        raise WebAuthnTrustError("WebAuthn credential policy trusted flag is not boolean")
    for name, minimum in (("trustBundleSequence", 1), ("trustRollbackEpoch", 0)):
        if type(document[name]) is not int or not minimum <= document[name] <= _I64_MAX:
            raise WebAuthnTrustError("WebAuthn credential policy integer is outside source bounds")
    for name in ("trustBundleDigest", "attestationLeafDigest", "attestationRootDigest",
                 "trustHighWaterDigest", "revocationSetDigest", "trustWitnessReceiptDigest", "publicKeyDigest"):
        value = document[name]
        if value is None and name in ("attestationLeafDigest", "attestationRootDigest"):
            continue
        if (type(value) is not str or len(value) != 71 or value[:7] != "sha256:"
                or any(character not in "0123456789abcdef" for character in value[7:])):
            raise WebAuthnTrustError("WebAuthn credential policy digest is not canonical")


def credential_policy_document(*, credential, high_water, trust_high_water_digest,
                               work: _ValidationWork | None = None) -> dict:
    """Build the real service policy and hash its exact stored public-key text.

    Fixed-field projection is source scaffolding, not a deep copy of the row.
    Public-key work is UTF-8 measurement/encoding plus its raw hash input and
    one SHA: 3U bytes, two scalar nodes. Digest encoding is charged separately.
    """
    if work is not None and type(work) is not _ValidationWork:
        raise QueryReadWorkError("WebAuthn credential policy requires the exact shared meter")
    _validate(high_water)
    if (type(credential) is not dict or len(credential) > 64
            or any(name not in credential for name in (
                "id", "credential_id", "user_id", "authenticator_class", "aaguid",
                "attestation_trusted", "attestation_trust_bundle_digest", "attestation_trust_bundle_sequence",
                "attestation_leaf_sha256", "attestation_root_sha256", "public_key_cose"))):
        raise WebAuthnTrustError("WebAuthn credential policy source is not a bounded exact row")
    public_key = credential.get("public_key_cose")
    trusted = credential.get("attestation_trusted")
    if type(public_key) is not str or type(trusted) not in (int, bool):
        raise WebAuthnTrustError("WebAuthn credential policy key or trusted flag is not exact")
    if work is not None:
        size = work.prepare_utf8(public_key)
        work.charge(hashes=1, input_bytes=size)
    public_key_digest = "sha256:" + hashlib.sha256(public_key.encode("utf-8")).hexdigest()
    document = {
        "schema": POLICY_DOMAIN, "credentialRecordId": credential["id"],
        "credentialId": credential["credential_id"], "userId": credential["user_id"],
        "authenticatorClass": credential["authenticator_class"], "aaguid": credential["aaguid"],
        "attestationTrusted": bool(trusted),
        "trustBundleDigest": credential["attestation_trust_bundle_digest"],
        "trustBundleSequence": credential["attestation_trust_bundle_sequence"],
        "attestationLeafDigest": credential["attestation_leaf_sha256"],
        "attestationRootDigest": credential["attestation_root_sha256"],
        "trustRollbackEpoch": high_water["rollbackEpoch"],
        "trustHighWaterDigest": trust_high_water_digest,
        "revocationSetDigest": high_water["revocationSetDigest"],
        "trustWitnessReceiptDigest": high_water["witnessReceiptDigest"],
        "publicKeyDigest": public_key_digest,
    }
    _validate_policy(document)
    return document


def credential_policy_digest(document, *, work: _ValidationWork | None = None) -> str:
    if work is not None and type(work) is not _ValidationWork:
        raise QueryReadWorkError("WebAuthn credential policy requires the exact shared meter")
    _validate_policy(document)
    return _document_digest(POLICY_DOMAIN, document, work)
