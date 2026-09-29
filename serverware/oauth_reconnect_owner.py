"""Cold signed replacement inventory; never a browser-supplied trust root."""
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from serverware import authority_oauth_reconnect as profile

STARTUP_SCHEMA = "serverware.oauthApplicationStartup/v4"
INVENTORY_SCHEMA = "serverware.oauthFamilyReconnectInventory/v1"
MAX_INVENTORY_BYTES = 1024 * 1024


def admit(config, *, binding, used, originals, applications, enrollment_key, opening, source_revision):
    """Called only by the fixed OAuth startup with actual admitted descriptors."""
    from serverware import oauth_application_owner as application
    item = config["reconnect"]
    profile.require(type(item) is dict and set(item) == {"rootFd", "rootSha256", "grantsFd", "grantsSha256"}
        and applications and enrollment_key is not None)
    held = []
    for descriptor, maximum, pin in ((item["rootFd"], application.MAX_ROOT_BYTES, item["rootSha256"]),
            (item["grantsFd"], MAX_INVENTORY_BYTES, item["grantsSha256"])):
        application._fd(descriptor)
        profile.require(descriptor not in used and descriptor in binding.inherited_descriptors)
        used.add(descriptor)
        original = application._Original(descriptor, maximum)
        profile.require(profile.sha256(original.raw) == application._digest(pin))
        held.append(original); originals.append(original)
    root = serialization.load_pem_public_key(held[0].raw)
    profile.require(isinstance(root, Ed25519PublicKey) and root.public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo) == held[0].raw)
    def der(key):
        return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    profile.require(der(root) not in {der(enrollment_key), der(binding.runtime_root_public_key)})
    value = profile.document(held[1].raw, MAX_INVENTORY_BYTES)
    profile.require(set(value) == {"schema", "authorizations"} and value["schema"] == INVENTORY_SCHEMA
        and type(value["authorizations"]) is list and 1 <= len(value["authorizations"]) <= 16)
    grants, order = {}, []
    for envelope in value["authorizations"]:
        raw = profile.canonical(envelope); grant = profile.grant_document(raw)["payload"]
        root.verify(profile.decoded(envelope["signatureBase64Url"], 64, 64),
            profile.GRANT_SCHEMA.encode("ascii") + b"\0" + profile.canonical(grant))
        app = applications.get(grant["providerId"])
        profile.require(app is not None and grant["sourceRevision"] == source_revision
            and grant["configurationDigest"] == binding.configuration_digest == app[0]["configurationDigest"]
            and grant["deploymentId"] == app[0]["deploymentId"] and grant["clientId"] == app[0]["clientId"]
            and grant["enrollmentSha256"] == profile.sha256(app[1])
            and app[0]["issuedAtEpochNs"] <= grant["issuedAtEpochNs"] <= opening < grant["expiresAtEpochNs"] <= app[0]["expiresAtEpochNs"])
        order.append(grant["authorizationId"]); grants[grant["authorizationId"]] = raw
    profile.require(order == sorted(set(order)))
    return grants


def selected():
    from serverware import oauth_application_owner as application
    owner = application.require_started()
    if owner is None:
        return False
    owner.check()
    return owner._reconnect is not None


def original(identifier):
    from serverware import oauth_application_owner as application
    profile.identifier(identifier)
    owner = application.require_started()
    profile.require(owner is not None)
    owner.check()
    profile.require(owner._reconnect is not None and identifier in owner._reconnect)
    raw = owner._reconnect[identifier]
    profile.grant_document(raw)
    return owner, raw


def inventory_for(actor):
    from serverware import oauth_application_owner as application
    owner = application.require_started()
    profile.require(owner is not None)
    owner.check(); profile.require(owner._reconnect is not None)
    return [profile.grant_document(raw)["payload"] for raw in owner._reconnect.values()
        if profile.grant_document(raw)["payload"]["requesterId"] == actor]
