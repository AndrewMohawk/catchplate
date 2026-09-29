"""Independent purpose admission for the Setup candidate successor."""
from serverware import authority_setup_policy as profile
from serverware import authority_publication_approval as assertions

FIELD = "setupPolicyContinuationPolicy"
SCHEMA = "serverware.setupPolicyContinuationAuthorityPolicy/v1"
FIELDS = frozenset({"schema", "controlPlaneConfigurationDigest", "credentialPolicy", "operationMaxSeconds", "maximumArgumentBytes"})


def validate_policy(value, *, payload, root_key=None):
    del root_key
    enabled = any(set(role.get("enabledOperations", ())) & profile.OPERATIONS for role in payload["roles"].values())
    if value is None:
        profile.require(not enabled, "Setup policy continuation needs separate signed purpose admission")
        return None
    profile.require(type(value) is dict and set(value) == FIELDS and value["schema"] == SCHEMA)
    profile.digest(value["controlPlaneConfigurationDigest"])
    assertions.policy(value["credentialPolicy"])
    profile.require(type(value["operationMaxSeconds"]) is int and 1 <= value["operationMaxSeconds"] <= 30
        and value["maximumArgumentBytes"] == profile.MAX_ARGUMENT_BYTES)
    return value


def verify_original(operation, arguments, *, configuration_payload, root_key, now_epoch_ns):
    values = profile.arguments(operation, arguments, typed="businessIntent" in arguments)
    policy = validate_policy(configuration_payload.get(FIELD), payload=configuration_payload, root_key=root_key)
    request = values["request"]
    profile.require(policy is not None and values["control_plane_configuration_digest"] == policy["controlPlaneConfigurationDigest"]
        and values["credential_policy"] == policy["credentialPolicy"]
        and request["issuedAtEpochNs"] <= now_epoch_ns < request["expiresAtEpochNs"]
        <= request["issuedAtEpochNs"] + policy["operationMaxSeconds"] * 1_000_000_000)
