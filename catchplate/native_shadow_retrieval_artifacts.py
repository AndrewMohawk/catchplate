"""Offline, closed retrieval artifacts; never a runtime custody owner.

Inputs are independently retained public originals. Signing is an explicit
operator action using an already provisioned supervisor key; nothing here
generates keys, asserts attestation, or turns admission into service permission.
"""
from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from catchplate import native_shadow_key_admission_profile as admission
from catchplate import native_shadow_nitro_profile as p

MAX_OBJECT = 1024 * 1024
MAX_OBJECTS = 16
MAX_MANIFEST = 24 * 1024 * 1024
GRANT_DOMAIN = "catchplate.nativeShadowRetrievalServiceAssignment.signature/v1"
SCOPE_VALUES = ("assignment_id", "assignment_payload_sha256", "assignment_revision", "authority_id",
    "storage_realm_sha256", "retrieval_namespace_sha256", "authority_key_independence_sha256",
    "production_configuration_binding_sha256", "asserted_custody_key_set_root_sha256",
    "execution_closure_manifest_sha256", "structurally_verified_seccomp_policy_sha256")
SCOPE_FIELDS = SCOPE_VALUES + ("store_response_authority", "retrieval_response_authority", "binding_sha256")
SCOPE_SET_API = "catchplate.policyShadowProductionCustodyProofScope/v2"
SCOPE_SET_VALUES = ("execution_closure_set_root_sha256", "structurally_verified_seccomp_set_root_sha256")
SCOPE_SET_FIELDS = SCOPE_FIELDS + ("api_version",) + SCOPE_SET_VALUES
RECEIPT_ROLES = frozenset(("ingress-admission", "unavailable-ingress", "dispatch-barrier", "active-effect-barrier",
    "active-effect-commit", "terminal-append", "ledger-append", "spool-compaction", "publication-reconciliation",
    "activation-publication"))
PEER_FIELDS = ("uid", "gid", "pid", "processIdentitySha256", "startTimeTicks", "executableDevice",
    "executableInode", "executableLength", "executableSha256", "cgroupPathSha256", "cgroupMountId", "cgroupInode",
    "securityLabelSha256", "configurationGenerationSha256")
OBJECT_FIELDS = ("apiVersion", "proofScopeSha256", "signerRole", "canonicalReceiptPayloadBase64url",
    "signedAuthorityPayloadBase64url")
MANIFEST_FIELDS = ("apiVersion", "proofScopeOriginalBase64url", "objectOriginalsBase64url")
FRESH_MANIFEST_API = "catchplate.nativeShadowRetrievalStoreManifest/v2"
FRESH_INITIALIZATION = "fresh-ledger"


def scope_original(raw):
    value = p.document(raw, 16384)
    p.require(type(value) is dict)
    successor = "api_version" in value
    p.fields(value, SCOPE_SET_FIELDS if successor else SCOPE_FIELDS)
    if successor:
        p.require(value["api_version"] == SCOPE_SET_API)
    values = SCOPE_VALUES + (SCOPE_SET_VALUES if successor else ())
    for name in values + ("binding_sha256",):
        if name == "assignment_revision":
            p.integer(value[name])
        else:
            p.require(p.digest(value[name]) != p.sha(b""))
    for name, role in (("store_response_authority", "custody-store-response"),
                       ("retrieval_response_authority", "custody-retrieval-response")):
        key = p.fields(value[name], ("role", "key_id", "key_spki_sha256", "key_material_sha256"))
        p.require(key["role"] == role)
        for field in ("key_id", "key_spki_sha256", "key_material_sha256"):
            p.digest(key[field])
    domain = SCOPE_SET_API.encode("ascii") if successor else b"catchplate.policyShadowProductionCustodyProofScope/v1"
    p.require(value["binding_sha256"] == p.framed(domain, (p.canonical([value[name] for name in values]),)))
    return value


def require_assignment_scope(scope, assignment_payload_original):
    """Compare a v2 scope to exact supplied assignment bytes, not approve them.

    Callers must authenticate the assignment's signature or bind these bytes to
    their actual signed key authorization. The old bridge anchors remain leaves.
    """
    from catchplate import authority_policy_canary_native_opening as opening
    p.require(scope.get("api_version") == SCOPE_SET_API
        and type(assignment_payload_original) is bytes and 0 < len(assignment_payload_original) <= 4 * 1024 * 1024)
    assignment = opening.assignment_payload(p.document(assignment_payload_original, 4 * 1024 * 1024), version=2)
    p.require(p.sha(assignment_payload_original) == scope["assignment_payload_sha256"])
    authority = assignment["custodyAuthority"]
    expected = {
        "assignment_id": assignment["assignmentId"], "assignment_revision": assignment["assignmentRevision"],
        "authority_id": authority["authorityId"], "storage_realm_sha256": authority["storageRealmSha256"],
        "retrieval_namespace_sha256": authority["retrievalNamespaceSha256"],
        "authority_key_independence_sha256": assignment["authorityKeyIndependence"]["independenceRootSha256"],
        "execution_closure_manifest_sha256": authority["executionClosureManifestSha256"],
        "structurally_verified_seccomp_policy_sha256": authority["structurallyVerifiedSeccompPolicySha256"],
        "execution_closure_set_root_sha256": assignment["nativeClosureSet"]["setRootSha256"],
        "structurally_verified_seccomp_set_root_sha256": assignment["nativeClosureSet"]["seccompSetRootSha256"],
    }
    _, expected["asserted_custody_key_set_root_sha256"] = opening._keys(assignment)
    p.require(p.canonical({name: scope[name] for name in expected}) == p.canonical(expected))
    return assignment


def require_admitted_scope(scope, admitted, *, assignment_payload_original=None):
    """Join roots through actual signed key-authorization assignment bytes.

    v2 does not equate an endpoint's individual key-admission leaf with the
    bridge anchors. Full role membership remains a native closure-owner check.
    """
    for target, source in (("assignment_id", "assignmentId"), ("assignment_payload_sha256", "assignmentPayloadSha256"),
            ("assignment_revision", "assignmentRevision"), ("asserted_custody_key_set_root_sha256", "fullKeySetRootSha256")):
        p.require(scope[target] == admitted[source])
    if scope.get("api_version") == SCOPE_SET_API:
        require_assignment_scope(scope, assignment_payload_original)
    else:
        for target, source in (("execution_closure_manifest_sha256", "executionClosureManifestSha256"),
                ("structurally_verified_seccomp_policy_sha256", "structurallyVerifiedSeccompPolicySha256")):
            p.require(scope[target] == admitted[source])


def _authority(scope, role, receipt):
    p.require(role in RECEIPT_ROLES and type(receipt) is bytes and 1 <= len(receipt) <= MAX_OBJECT)
    if scope.get("api_version") == SCOPE_SET_API:
        return p.canonical(["catchplate.policyShadowAssignmentBoundCustodyReceipt/v2", scope["binding_sha256"],
            scope["execution_closure_manifest_sha256"], scope["structurally_verified_seccomp_policy_sha256"],
            scope["execution_closure_set_root_sha256"], scope["structurally_verified_seccomp_set_root_sha256"],
            role, p.sha(receipt)])
    return p.canonical(["catchplate.policyShadowAssignmentBoundCustodyReceipt/v1", scope["binding_sha256"],
        scope["execution_closure_manifest_sha256"], scope["structurally_verified_seccomp_policy_sha256"],
        role, p.sha(receipt)])


def object_original(scope_raw, role, receipt_raw, authority_raw):
    """Package supplied originals, without manufacturing a receipt/signature."""
    scope = scope_original(scope_raw)
    p.require(type(authority_raw) is bytes and 1 <= len(authority_raw) <= 16384
        and authority_raw == _authority(scope, role, receipt_raw))
    raw = p.canonical({"apiVersion": "catchplate.nativeShadowImmutableRetrievalObject/v1",
        "proofScopeSha256": p.sha(scope_raw), "signerRole": role,
        "canonicalReceiptPayloadBase64url": p.encoded(receipt_raw),
        "signedAuthorityPayloadBase64url": p.encoded(authority_raw)})
    p.require(len(raw) <= MAX_OBJECT)
    return raw


def object_locator(scope_raw, raw):
    scope = scope_original(scope_raw)
    value = p.fields(p.document(raw, MAX_OBJECT), OBJECT_FIELDS)
    receipt = p.decoded(value["canonicalReceiptPayloadBase64url"], maximum=MAX_OBJECT)
    authority = p.decoded(value["signedAuthorityPayloadBase64url"], maximum=16384)
    p.require(raw == object_original(scope_raw, value["signerRole"], receipt, authority))
    identifier = p.framed(b"catchplate.nativeShadowImmutableRetrievalId/v1",
        (scope["retrieval_namespace_sha256"].encode("ascii"), raw))
    proof = p.framed(b"catchplate.nativeShadowImmutableRetrievalProof/v1", (scope_raw,
        p.canonical(value["signerRole"]), identifier.encode("ascii"), receipt, authority))
    return {"retrievalIdSha256": identifier, "proofSha256": proof,
        "objectSha256": p.sha(raw), "filename": identifier[7:] + ".json"}


def manifest_original(scope_raw, originals):
    p.require(type(originals) in (tuple, list) and 1 <= len(originals) <= MAX_OBJECTS)
    locators = [object_locator(scope_raw, raw) for raw in originals]
    p.require(len({item["filename"] for item in locators}) == len(originals))
    raw = p.canonical({"apiVersion": "catchplate.nativeShadowRetrievalStoreManifest/v1",
        "proofScopeOriginalBase64url": p.encoded(scope_raw),
        "objectOriginalsBase64url": [p.encoded(original) for original in originals]})
    p.require(len(raw) <= MAX_MANIFEST)
    return raw


def fresh_ledger_manifest_original(scope_raw):
    """Select an explicitly empty initial ledger profile, not receipt evidence.

    The native grant and actual ledger genesis must independently admit this
    initialization. This public manifest creates neither of those authorities.
    Legacy manifest_original deliberately continues to require real objects.
    """
    scope = scope_original(scope_raw)
    p.require(scope.get("api_version") == SCOPE_SET_API)
    raw = p.canonical({"apiVersion": FRESH_MANIFEST_API,
        "proofScopeOriginalBase64url": p.encoded(scope_raw),
        "initialization": FRESH_INITIALIZATION, "objectOriginalsBase64url": []})
    p.require(len(raw) <= MAX_MANIFEST)
    return raw


def _manifest(raw, expected_sha256):
    p.require(type(raw) is bytes and 1 <= len(raw) <= MAX_MANIFEST)
    p.require(p.sha(raw) == p.digest(expected_sha256))
    value = p.document(raw, MAX_MANIFEST)
    p.require(type(value) is dict)
    fresh = value.get("apiVersion") == FRESH_MANIFEST_API
    p.fields(value, MANIFEST_FIELDS + (("initialization",) if fresh else ()))
    scope = p.decoded(value["proofScopeOriginalBase64url"], maximum=16384)
    items = value["objectOriginalsBase64url"]
    if fresh:
        p.require(value["initialization"] == FRESH_INITIALIZATION
            and type(items) is list and items == []
            and raw == fresh_ledger_manifest_original(scope))
        return FRESH_INITIALIZATION, []
    p.require(type(items) is list and 1 <= len(items) <= MAX_OBJECTS)
    originals = [p.decoded(item, maximum=MAX_OBJECT) for item in items]
    p.require(raw == manifest_original(scope, originals))
    return None, [(object_locator(scope, original), original) for original in originals]


def manifest_objects(raw, expected_sha256):
    """Validate the complete pin/profile; return only actual supplied objects."""
    return _manifest(raw, expected_sha256)[1]


def manifest_initialization(raw, expected_sha256):
    """Fully validate a pinned manifest; return None or 'fresh-ledger'.

    This is a source-selected data profile, not signature or service authority.
    """
    return _manifest(raw, expected_sha256)[0]


def _peer(raw):
    value = p.fields(p.document(raw, 4096), PEER_FIELDS)
    for name in ("uid", "gid"):
        p.integer(value[name], maximum=(1 << 32) - 1)
    p.integer(value["pid"], maximum=(1 << 31) - 1)
    for name in ("startTimeTicks", "executableDevice", "executableInode", "cgroupMountId", "cgroupInode"):
        p.integer(value[name])
    p.integer(value["executableLength"], maximum=256 * 1024 * 1024)
    for name in ("processIdentitySha256", "executableSha256", "cgroupPathSha256", "securityLabelSha256",
                 "configurationGenerationSha256"):
        p.require(p.digest(value[name]) != p.sha(b""))
    parts = [value[name].to_bytes(4, "big") for name in ("uid", "gid", "pid")]
    parts.extend(value[name].to_bytes(8, "big") for name in
        ("startTimeTicks", "executableDevice", "executableInode", "executableLength"))
    parts.extend((p.raw_digest(value["executableSha256"]), value["cgroupPathSha256"].encode("ascii"),
        value["cgroupMountId"].to_bytes(8, "big"), value["cgroupInode"].to_bytes(8, "big"),
        value["securityLabelSha256"].encode("ascii"), value["configurationGenerationSha256"].encode("ascii")))
    p.require(value["processIdentitySha256"] == p.framed(b"catchplate.policyCustodyPeerProcessIdentity/v4", parts))
    return value


def sign_service_grant(*, configuration_original, configuration_sha256, scope_raw, scope_sha256,
                       peer_original, peer_sha256, issued_at, expires_at, now, signing_key,
                       assignment_payload_original=None):
    """Explicit separate operational grant, not a key-admission conversion.

    Public pins/time must come from the independent operator. Native service
    admission still rechecks the live assignment, trust, clock and actual peer.
    The private key is an existing opaque key object, never an argv/file seed.
    """
    p.require(type(configuration_original) is bytes and 1 <= len(configuration_original) <= p.MAX_CONFIG
        and type(scope_raw) is bytes and 1 <= len(scope_raw) <= 16384
        and type(peer_original) is bytes and 1 <= len(peer_original) <= 4096)
    p.require(p.sha(configuration_original) == p.digest(configuration_sha256)
        and p.sha(scope_raw) == p.digest(scope_sha256) and p.sha(peer_original) == p.digest(peer_sha256))
    configuration = p.document(configuration_original, p.MAX_CONFIG)
    admitted, keys = admission.authorization(configuration, now)
    scope, peer = scope_original(scope_raw), _peer(peer_original)
    guest = admitted["guest"]
    p.require(guest["serviceRole"] == "production-bridge" and guest["uid"] != peer["uid"]
        and "custody-retrieval-response" in configuration["authorization"]["payload"]["localRoles"])
    require_admitted_scope(scope, admitted, assignment_payload_original=assignment_payload_original)
    for name, role in (("store_response_authority", "custody-store-response"),
                       ("retrieval_response_authority", "custody-retrieval-response")):
        expected = keys[p.ROLES.index(role)]
        p.require(scope[name] == {"role": role, "key_id": expected["keyId"],
            "key_spki_sha256": expected["keySpkiSha256"], "key_material_sha256": expected["keyMaterialSha256"]})
    p.freshness(issued_at, expires_at, now)
    p.require(expires_at <= min(configuration[name]["payload"]["expiresAtUnixNanos"]
        for name in ("authorization", "admissionAuthorization")))
    supervisor = keys[-1]
    p.require(isinstance(signing_key, Ed25519PrivateKey))
    public = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p.require(p.encoded(public) == supervisor["publicKeyBase64url"])
    checkpoint = configuration["trustCheckpoint"]
    payload = {"apiVersion": "catchplate.nativeShadowRetrievalServiceAssignment/v1",
        "purpose": "native-shadow-immutable-retrieval", "guest": guest,
        "assignmentPayloadSha256": admitted["assignmentPayloadSha256"],
        "keyAuthorizationSha256": admitted["keyAuthorizationSha256"],
        "proofScopeOriginalBase64url": p.encoded(scope_raw), "expectedPeer": peer,
        "trustCheckpointId": checkpoint["checkpointId"], "revocationGeneration": checkpoint["revocationGeneration"],
        "revocationRootSha256": checkpoint["revocationRootSha256"], "issuedAtUnixNanos": issued_at,
        "expiresAtUnixNanos": expires_at, "signingKeyId": supervisor["keyId"],
        "signingKeySpkiSha256": supervisor["keySpkiSha256"]}
    signature = signing_key.sign(p.preimage(GRANT_DOMAIN, payload))
    p.public_key(supervisor).verify(signature, p.preimage(GRANT_DOMAIN, payload))
    result = p.canonical({"payload": payload, "signature": p.encoded(signature)})
    p.require(len(result) <= 65536)
    return result
