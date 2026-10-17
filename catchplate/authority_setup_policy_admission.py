"""Independent purpose admission for the Setup candidate successor."""
from catchplate import authority_setup_policy as profile
from catchplate import authority_publication_approval as assertions

FIELD = "setupPolicyContinuationPolicy"
SCHEMA = "catchplate.setupPolicyContinuationAuthorityPolicy/v2"
FIELDS = frozenset({"schema", "credentialPolicy", "operationMaxSeconds", "maximumArgumentBytes"})


def validate_policy(value, *, payload, root_key=None):
    del root_key
    enabled = any(set(role.get("enabledOperations", ())) & profile.OPERATIONS for role in payload["roles"].values())
    if value is None:
        profile.require(not enabled, "Setup policy continuation needs separate signed purpose admission")
        return None
    profile.require(type(value) is dict and set(value) == FIELDS and value["schema"] == SCHEMA)
    assertions.policy(value["credentialPolicy"])
    profile.require(type(value["operationMaxSeconds"]) is int and 1 <= value["operationMaxSeconds"] <= 30
        and value["maximumArgumentBytes"] == profile.MAX_ARGUMENT_BYTES)
    return value


def verify_original(operation, arguments, *, configuration_payload, root_key, now_epoch_ns):
    from catchplate.authority_policy_canary_policy import full_configuration_digest

    values = profile.arguments(operation, arguments, typed="businessIntent" in arguments)
    policy = validate_policy(configuration_payload.get(FIELD), payload=configuration_payload, root_key=root_key)
    request = values["request"]
    profile.require(policy is not None and values["control_plane_configuration_digest"] == full_configuration_digest(configuration_payload)
        and values["credential_policy"] == policy["credentialPolicy"]
        and request["issuedAtEpochNs"] <= now_epoch_ns < request["expiresAtEpochNs"]
        <= request["issuedAtEpochNs"] + policy["operationMaxSeconds"] * 1_000_000_000)
    if set(request) == profile.ROTATED_STATIC_REQUEST_FIELDS:
        selected = profile.rotated_selection(configuration_payload, root_key)
        profile.require(selected["configurationDigest"] == values["control_plane_configuration_digest"])
