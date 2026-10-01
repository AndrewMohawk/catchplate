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
COMPLETED_GRANT_API = "serverware.nativeShadowPersistenceServiceAssignment/v2"
COMPLETED_GRANT_DOMAIN = "serverware.nativeShadowPersistenceServiceAssignment.signature/v2"
COMPLETED_PERMISSIONS = ("store-dispatch-original", "verify-persistence", "verify-completed-invocation")


def require_permissions(permissions, *, completed_invocations=False):
    p.require(type(completed_invocations) is bool and type(permissions) is list)
    p.require(permissions == list(COMPLETED_PERMISSIONS) if completed_invocations else permissions in
        (["verify-persistence"], ["store-dispatch-original", "verify-persistence"]))


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


def _service_grant_payload(*, configuration_original, configuration_sha256, scope_original, scope_sha256,
                          peer_original, peer_sha256, guest, journal_original, journal_sha256,
                          permissions, issued_at, expires_at, now, assignment_payload_original=None,
                          completed_invocations=False):
    """One fixed public validation recipe shared by signing and receiving."""
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
    require_permissions(permissions, completed_invocations=completed_invocations)
    p.require(admitted["guest"] == guest and guest["serviceRole"] == "production-bridge"
        and peer["uid"] != guest["uid"]
        and "custody-store-response" in configuration["authorization"]["payload"]["localRoles"])
    data.require_admitted_scope(scope, admitted, assignment_payload_original=assignment_payload_original)
    for name, role in (("store_response_authority", "custody-store-response"),
                       ("retrieval_response_authority", "custody-retrieval-response")):
        expected = keys[p.ROLES.index(role)]
        p.require(scope[name] == {"role": role, "key_id": expected["keyId"],
            "key_spki_sha256": expected["keySpkiSha256"], "key_material_sha256": expected["keyMaterialSha256"]})
    p.freshness(issued_at, expires_at, now)
    p.require(expires_at <= min(configuration[name]["payload"]["expiresAtUnixNanos"]
        for name in ("authorization", "admissionAuthorization")))
    supervisor = keys[p.ROLES.index("custody-supervisor-capability")]
    checkpoint = configuration["trustCheckpoint"]
    payload = {"apiVersion": COMPLETED_GRANT_API if completed_invocations else "serverware.nativeShadowPersistenceServiceAssignment/v1",
        "purpose": "native-shadow-receipt-persistence", "permissions": list(permissions), "guest": guest,
        "assignmentPayloadSha256": admitted["assignmentPayloadSha256"],
        "keyAuthorizationSha256": admitted["keyAuthorizationSha256"],
        "proofScopeOriginalBase64url": p.encoded(scope_original), "journal": journal, "expectedPeer": peer,
        "trustCheckpointId": checkpoint["checkpointId"], "revocationGeneration": checkpoint["revocationGeneration"],
        "revocationRootSha256": checkpoint["revocationRootSha256"], "issuedAtUnixNanos": issued_at,
        "expiresAtUnixNanos": expires_at, "signingKeyId": supervisor["keyId"],
        "signingKeySpkiSha256": supervisor["keySpkiSha256"]}
    return payload, supervisor


def verify_service_grant(*, signed_grant_original, configuration_original, configuration_sha256,
                         scope_original, scope_sha256, peer_original, peer_sha256, guest,
                         journal_original, journal_sha256, now, assignment_payload_original=None,
                         completed_invocations=False):
    """Admit exact independent Store/Verify bytes, not a local success claim."""
    signed = p.fields(p.document(signed_grant_original, 65536), ("payload", "signature"))
    supplied = signed["payload"]
    p.require(type(supplied) is dict)
    payload, supervisor = _service_grant_payload(configuration_original=configuration_original,
        configuration_sha256=configuration_sha256, scope_original=scope_original, scope_sha256=scope_sha256,
        peer_original=peer_original, peer_sha256=peer_sha256, guest=guest,
        journal_original=journal_original, journal_sha256=journal_sha256,
        permissions=supplied["permissions"], issued_at=supplied["issuedAtUnixNanos"],
        expires_at=supplied["expiresAtUnixNanos"], now=now, assignment_payload_original=assignment_payload_original,
        completed_invocations=completed_invocations)
    # Canonical bytes also preserve JSON integer/bool distinctions; ordinary
    # Python mapping equality alone would equate 1 and true in nested originals.
    p.require(p.canonical(supplied) == p.canonical(payload))
    domain = COMPLETED_GRANT_DOMAIN if completed_invocations else GRANT_DOMAIN
    p.public_key(supervisor).verify(p.decoded(signed["signature"], size=64), p.preimage(domain, payload))
    return signed_grant_original, supervisor


def sign_service_grant(*, configuration_original, configuration_sha256, scope_original, scope_sha256,
                       peer_original, peer_sha256, guest, journal_original, journal_sha256,
                       permissions, issued_at, expires_at, now, signing_key, assignment_payload_original=None,
                       completed_invocations=False):
    """The existing independent supervisor explicitly authorizes Store/Verify.

    The grant is not inferred from key possession, from the C9 delivery signer,
    from Retrieval permission, or from a local journal's existence.
    """
    payload, supervisor = _service_grant_payload(configuration_original=configuration_original,
        configuration_sha256=configuration_sha256, scope_original=scope_original, scope_sha256=scope_sha256,
        peer_original=peer_original, peer_sha256=peer_sha256, guest=guest,
        journal_original=journal_original, journal_sha256=journal_sha256,
        permissions=permissions, issued_at=issued_at, expires_at=expires_at, now=now,
        assignment_payload_original=assignment_payload_original, completed_invocations=completed_invocations)
    p.require(isinstance(signing_key, Ed25519PrivateKey))
    public = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p.require(p.encoded(public) == supervisor["publicKeyBase64url"])
    message = p.preimage(COMPLETED_GRANT_DOMAIN if completed_invocations else GRANT_DOMAIN, payload)
    signature = signing_key.sign(message)
    p.public_key(supervisor).verify(signature, message)
    raw = p.canonical({"payload": payload, "signature": p.encoded(signature)})
    p.require(len(raw) <= 65536)
    return raw
