"""Cold, independently signed successor inventory; no browser trust roots."""
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from catchplate import authority_oauth_retirement_succession as p

STARTUP_SCHEMA = "catchplate.oauthApplicationStartup/v5"
INVENTORY_SCHEMA = "catchplate.oauthRetiredScopeSuccessionInventory/v1"
MAX_INVENTORY_BYTES = 2 * 1024 * 1024 + 8192


def admit(config, *, binding, used, originals, applications, enrollment_key, opening, source_revision):
    from catchplate import oauth_application_owner as application
    item = config["retiredScopeSuccession"]
    p.require(config["schema"] == STARTUP_SCHEMA and type(item) is dict
        and set(item) == {"rootFd", "rootSha256", "grantsFd", "grantsSha256"} and applications and enrollment_key is not None)
    held = []
    for descriptor, maximum, pin in ((item["rootFd"], application.MAX_ROOT_BYTES, item["rootSha256"]),
            (item["grantsFd"], MAX_INVENTORY_BYTES, item["grantsSha256"])):
        application._fd(descriptor)
        p.require(descriptor not in used and descriptor in binding.inherited_descriptors)
        used.add(descriptor)
        original = application._Original(descriptor, maximum)
        p.require(p.sha256(original.raw) == application._digest(pin))
        held.append(original); originals.append(original)
    root = serialization.load_pem_public_key(held[0].raw)
    p.require(isinstance(root, Ed25519PublicKey) and root.public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo) == held[0].raw)
    def der(key):
        return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    p.require(der(root) not in {der(enrollment_key), der(binding.runtime_root_public_key)})
    value = p.document(held[1].raw, MAX_INVENTORY_BYTES)
    p.require(set(value) == {"schema", "authorizations"} and value["schema"] == INVENTORY_SCHEMA
        and type(value["authorizations"]) is list and 1 <= len(value["authorizations"]) <= 16)
    grants, order = {}, []
    for envelope in value["authorizations"]:
        raw = p.canonical(envelope); grant = p.grant_document(raw)["payload"]
        root.verify(p.decoded(envelope["signatureBase64Url"], 64, 64), p.GRANT_SCHEMA.encode("ascii") + b"\0" + p.canonical(grant))
        app = applications.get(grant["providerId"])
        p.require(app is not None and grant["sourceRevision"] == source_revision
            and grant["configurationDigest"] == binding.configuration_digest == app[0]["configurationDigest"]
            and grant["deploymentId"] == app[0]["deploymentId"] and grant["clientId"] == app[0]["clientId"]
            and grant["enrollmentSha256"] == p.sha256(app[1])
            and app[0]["issuedAtEpochNs"] <= grant["issuedAtEpochNs"] <= opening < grant["admissionExpiresAtEpochNs"]
            and grant["expiresAtEpochNs"] <= app[0]["expiresAtEpochNs"])
        order.append(grant["authorizationId"]); grants[grant["authorizationId"]] = raw
    p.require(order == sorted(set(order)))
    return grants


def selected():
    from catchplate import oauth_application_owner as application
    owner = application.require_started()
    if owner is None:
        return False
    owner.check()
    return owner._succession is not None


def original(identifier):
    from catchplate import oauth_application_owner as application
    p.identifier(identifier); owner = application.require_started(); p.require(owner is not None)
    owner.check(); p.require(owner._succession is not None and identifier in owner._succession)
    raw = owner._succession[identifier]; p.grant_document(raw)
    return owner, raw


def inventory_for(actor):
    from catchplate import oauth_application_owner as application
    owner = application.require_started(); p.require(owner is not None)
    owner.check(); p.require(owner._succession is not None)
    return [p.grant_document(raw)["payload"] for raw in owner._succession.values()
        if p.grant_document(raw)["payload"]["requesterId"] == actor]
