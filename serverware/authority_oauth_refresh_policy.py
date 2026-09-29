"""Explicit signed-configuration permission for bounded automatic due refresh."""
from serverware import authority_oauth_activation_policy as enrollment
from serverware import authority_oauth_refresh as profile

FIELD = "oauthRefreshPolicy"
SCHEMA = "serverware.oauthRefreshAuthorityPolicy/v1"
FIELDS = enrollment.FIELDS | {"dueWithinSeconds", "operationMaxSeconds", "revocationCapacity"}


def validate_policy(value, *, payload, root_key=None):
    enabled = any(set(role.get("enabledOperations", ())) & profile.OPERATIONS for role in payload["roles"].values())
    if value is None:
        profile.require(not enabled, "automatic OAuth refresh requires its explicit signed purpose policy")
        return None
    profile.require(type(value) is dict and set(value) == FIELDS and value["schema"] == SCHEMA)
    profile.limits({name: value[name] for name in ("dueWithinSeconds", "operationMaxSeconds", "revocationCapacity")})
    # Reuse the exact enrollment-key separation checks, not activation permission.
    # The actual measured configuration's independent signature authenticates
    # this purpose block and separately enabled fixed operations.
    enrollment_view = {name: value[name] for name in enrollment.FIELDS}
    enrollment_view["schema"] = enrollment.SCHEMA
    key = enrollment.validate_policy(enrollment_view, payload=payload, root_key=root_key)
    cleanup = payload.get("oauthRevocationPolicy")
    if type(cleanup) is dict:
        profile.require(enrollment._spki(key) != cleanup.get("grantRootSpkiSha256"),
            "OAuth enrollment identity is separate from cleanup effect authority")
    return key


def verify_original(operation, arguments, *, configuration_payload, root_key, now_epoch_ns):
    values = profile.arguments(operation, arguments, typed="businessIntent" in arguments)
    policy = configuration_payload.get(FIELD)
    key = validate_policy(policy, payload=configuration_payload, root_key=root_key)
    profile.require(key is not None)
    raw = profile.enrollment_bytes(values["enrollment_original"])
    signed = enrollment.enrollment_document(raw)
    original = signed["payload"]
    profile.require(type(now_epoch_ns) is int and original["issuedAtEpochNs"] <= now_epoch_ns < original["expiresAtEpochNs"]
        and original["sourceRevision"] == configuration_payload["sourceRevision"]
        and original["configurationDigest"] == policy["controlPlaneConfigurationDigest"]
        and original["deploymentId"] == policy["deploymentId"]
        and values["request"]["limits"] == {name: policy[name] for name in ("dueWithinSeconds", "operationMaxSeconds", "revocationCapacity")})
    key.verify(enrollment._b64(signed["signatureBase64Url"], 64), enrollment.ENROLLMENT_SCHEMA.encode("ascii") + b"\0" + profile.canonical(original))
    if operation == profile.OP_CLAIM:
        request = values["request"]
        profile.require(original["issuedAtEpochNs"] <= request["issuedAtEpochNs"] <= now_epoch_ns < request["contactExpiresAtEpochNs"]
            and request["retentionExpiresAtEpochNs"] <= original["expiresAtEpochNs"])
