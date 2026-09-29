"""Independent measured exchange enrollment root and capacity policy."""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from serverware import authority_oauth_activation_policy as enrollment
from serverware import authority_oauth_exchange as profile

FIELD = "oauthExchangePolicy"
SCHEMA = "serverware.oauthExchangeAuthorityPolicy/v1"
FIELDS = enrollment.FIELDS | {"pendingCapacity", "revocationCapacity"}


def validate_policy(value, *, payload, root_key=None):
    enabled = any(set(role.get("enabledOperations", ())) & profile.OPERATIONS for role in payload["roles"].values())
    if value is None:
        profile.require(not enabled, "OAuth exchange requires its independently configured enrollment policy")
        return None
    profile.require(type(value) is dict and set(value) == FIELDS and value["schema"] == SCHEMA)
    enrollment._identifier(value["deploymentId"])
    profile.digest(value["controlPlaneConfigurationDigest"])
    profile.digest(value["enrollmentRootSpkiSha256"])
    profile.require(all(type(value[name]) is int and 1 <= value[name] <= 64 for name in ("pendingCapacity", "revocationCapacity")))
    key = Ed25519PublicKey.from_public_bytes(enrollment._b64(value["enrollmentRootPublicKeyBase64Url"], 32))
    pin = enrollment._spki(key)
    profile.require(pin == value["enrollmentRootSpkiSha256"])
    if root_key is not None:
        profile.require(pin != enrollment._spki(root_key), "OAuth enrollment root differs from configuration root")
    for role in payload["roles"].values():
        for name, item in role.items():
            if name.endswith("SpkiDigest") or name.endswith("SpkiSha256"):
                profile.require(pin != item, "OAuth enrollment root differs from authority role keys")
    for name in ("webauthnEnrollmentAuthorization", "webauthnEvidenceAdmission", "webauthnTransitions"):
        other = payload.get(name)
        if type(other) is dict:
            profile.require(pin not in other.values(), "OAuth enrollment root is purpose-separated")
    # Sharing the actual OAuth enrollment root with activation is intentional;
    # neither operation family inherits the other's enabled-operation grant.
    activation = payload.get(enrollment.FIELD)
    if activation is not None:
        profile.require(all(value[name] == activation[name] for name in enrollment.FIELDS - {"schema"}),
            "OAuth exchange and activation enrollment scopes differ")
    return key


def verify_original(operation, arguments, *, configuration_payload, root_key, now_epoch_ns):
    values = profile.arguments(operation, arguments, typed="businessIntent" in arguments)
    policy = configuration_payload.get(FIELD)
    key = validate_policy(policy, payload=configuration_payload, root_key=root_key)
    profile.require(key is not None, "OAuth exchange enrollment authority is disabled")
    raw = profile.enrollment_bytes(values["enrollment_original"])
    from serverware import authority_oauth_measured_exchange_policy as measured
    profile.require(not measured.owns_enrollment(configuration_payload.get(measured.FIELD), raw),
        "measured initial issuance cannot use the parent-plaintext exchange profile")
    envelope = enrollment.enrollment_document(raw)
    payload = envelope["payload"]
    profile.require(type(now_epoch_ns) is int and payload["issuedAtEpochNs"] <= now_epoch_ns < payload["expiresAtEpochNs"]
        and payload["sourceRevision"] == configuration_payload["sourceRevision"]
        and payload["configurationDigest"] == policy["controlPlaneConfigurationDigest"]
        and payload["deploymentId"] == policy["deploymentId"], "OAuth exchange enrollment scope or original interval differs")
    key.verify(enrollment._b64(envelope["signatureBase64Url"], 64),
        enrollment.ENROLLMENT_SCHEMA.encode("ascii") + b"\0" + profile.canonical(payload))
    profile.require(values["request"]["limits"] == {name: policy[name] for name in ("pendingCapacity", "revocationCapacity")},
        "OAuth exchange current capacity policy differs")
    if operation == profile.OP_PREPARE:
        request = values["request"]
        profile.require(request["limits"] == {name: policy[name] for name in ("pendingCapacity", "revocationCapacity")}
            and request["providerId"] == payload["providerId"] and request["redirectUri"] == payload["redirectUri"]
            and payload["issuedAtEpochNs"] <= request["issuedAtEpochNs"] <= now_epoch_ns < request["contactExpiresAtEpochNs"]
            and now_epoch_ns - request["issuedAtEpochNs"] <= 30_000_000_000
            and request["pendingExpiresAtEpochNs"] <= payload["expiresAtEpochNs"],
            "OAuth consent differs from signed enrollment, capacity, or original bounds")
