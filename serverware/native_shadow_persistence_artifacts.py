"""Closed public persistence inputs and separate operational grant authoring.

No key generation, attestation, storage write, or conversion of Retrieval
permission. Only the actual input owner calls this after durable preparation;
native admission independently verifies current assignment/trust and storage.
"""
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from serverware import native_shadow_key_admission_profile as admission
from serverware import native_shadow_nitro_profile as p
from serverware import native_shadow_retrieval_artifacts as data

GRANT_DOMAIN = "serverware.nativeShadowPersistenceServiceAssignment.signature/v1"


def fresh_originals(*, genesis_original, genesis_sha256, journal_original, journal_sha256,
                    scope_original, guest):
    """Validate independently supplied originals; do not manufacture a genesis."""
    p.require(type(genesis_original) is bytes and 1 <= len(genesis_original) <= 16384
        and type(journal_original) is bytes and 1 <= len(journal_original) <= 1024)
    scope = data.scope_original(scope_original)
    p.guest(guest)
    p.require(p.sha(genesis_original) == p.digest(genesis_sha256)
        and p.sha(journal_original) == p.digest(journal_sha256))
    genesis = p.fields(p.document(genesis_original, 16384), ("apiVersion", "proofScopeSha256", "guest"))
    journal = p.fields(p.document(journal_original, 1024), ("genesisSha256", "headSequence", "headSha256"))
    p.require(genesis["apiVersion"] == "serverware.nativeShadowPersistenceGenesis/v1"
        and genesis["proofScopeSha256"] == scope["binding_sha256"] and genesis["guest"] == guest
        and journal["genesisSha256"] == genesis_sha256
        and type(journal["headSequence"]) is int and journal["headSequence"] == 0
        and journal["headSha256"] == genesis_sha256)
    return journal


def sign_service_grant(*, configuration_original, configuration_sha256, scope_original, scope_sha256,
                       peer_original, peer_sha256, guest, journal_original, journal_sha256,
                       permissions, issued_at, expires_at, now, signing_key):
    """The existing independent supervisor explicitly authorizes Store/Verify.

    The grant is not inferred from key possession, from the C9 delivery signer,
    from Retrieval permission, or from a local journal's existence.
    """
    p.require(type(configuration_original) is bytes and 1 <= len(configuration_original) <= p.MAX_CONFIG
        and type(scope_original) is bytes and 1 <= len(scope_original) <= 16384
        and type(peer_original) is bytes and 1 <= len(peer_original) <= 4096
        and type(journal_original) is bytes and 1 <= len(journal_original) <= 1024)
    p.require(p.sha(configuration_original) == p.digest(configuration_sha256)
        and p.sha(scope_original) == p.digest(scope_sha256)
        and p.sha(peer_original) == p.digest(peer_sha256)
        and p.sha(journal_original) == p.digest(journal_sha256))
    configuration = p.document(configuration_original, p.MAX_CONFIG)
    admitted, keys = admission.authorization(configuration, now)
    scope, peer = data.scope_original(scope_original), data._peer(peer_original)
    journal = p.fields(p.document(journal_original, 1024), ("genesisSha256", "headSequence", "headSha256"))
    p.digest(journal["genesisSha256"]); p.digest(journal["headSha256"])
    p.integer(journal["headSequence"], minimum=0, maximum=128)
    p.require(type(permissions) is list and permissions in
        (["verify-persistence"], ["store-dispatch-original", "verify-persistence"]))
    p.require(admitted["guest"] == guest and guest["serviceRole"] == "production-bridge"
        and peer["uid"] != guest["uid"]
        and "custody-store-response" in configuration["authorization"]["payload"]["localRoles"])
    for target, source in (("assignment_id", "assignmentId"), ("assignment_payload_sha256", "assignmentPayloadSha256"),
            ("assignment_revision", "assignmentRevision"), ("execution_closure_manifest_sha256", "executionClosureManifestSha256"),
            ("structurally_verified_seccomp_policy_sha256", "structurallyVerifiedSeccompPolicySha256"),
            ("asserted_custody_key_set_root_sha256", "fullKeySetRootSha256")):
        p.require(scope[target] == admitted[source])
    for name, role in (("store_response_authority", "custody-store-response"),
                       ("retrieval_response_authority", "custody-retrieval-response")):
        expected = keys[p.ROLES.index(role)]
        p.require(scope[name] == {"role": role, "key_id": expected["keyId"],
            "key_spki_sha256": expected["keySpkiSha256"], "key_material_sha256": expected["keyMaterialSha256"]})
    p.freshness(issued_at, expires_at, now)
    p.require(expires_at <= min(configuration[name]["payload"]["expiresAtUnixNanos"]
        for name in ("authorization", "admissionAuthorization")))
    supervisor = keys[p.ROLES.index("custody-supervisor-capability")]
    p.require(isinstance(signing_key, Ed25519PrivateKey))
    public = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p.require(p.encoded(public) == supervisor["publicKeyBase64url"])
    checkpoint = configuration["trustCheckpoint"]
    payload = {"apiVersion": "serverware.nativeShadowPersistenceServiceAssignment/v1",
        "purpose": "native-shadow-receipt-persistence", "permissions": list(permissions), "guest": guest,
        "assignmentPayloadSha256": admitted["assignmentPayloadSha256"],
        "keyAuthorizationSha256": admitted["keyAuthorizationSha256"],
        "proofScopeOriginalBase64url": p.encoded(scope_original), "journal": journal, "expectedPeer": peer,
        "trustCheckpointId": checkpoint["checkpointId"], "revocationGeneration": checkpoint["revocationGeneration"],
        "revocationRootSha256": checkpoint["revocationRootSha256"], "issuedAtUnixNanos": issued_at,
        "expiresAtUnixNanos": expires_at, "signingKeyId": supervisor["keyId"],
        "signingKeySpkiSha256": supervisor["keySpkiSha256"]}
    message = p.preimage(GRANT_DOMAIN, payload)
    signature = signing_key.sign(message)
    p.public_key(supervisor).verify(signature, message)
    raw = p.canonical({"payload": payload, "signature": p.encoded(signature)})
    p.require(len(raw) <= 65536)
    return raw
