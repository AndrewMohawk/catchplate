"""Independently signed, purpose-only candidate intake configuration."""
from serverware import authority_policy_candidate as profile
from serverware import authority_publication_approval as assertions

FIELD = "policyCandidateIntakePolicy"
SCHEMA = "serverware.policyCandidateIntakeAuthorityPolicy/v1"
FIELDS = frozenset({"schema", "controlPlaneConfigurationDigest", "credentialPolicy", "assignments",
    "operationMaxSeconds", "maximumOriginalBytes"})
ASSIGNMENT_FIELDS = frozenset({"instanceId", "bootId", "shadowKeySha256", "runtimeConfigSha256"})


def validate_policy(value, *, payload, root_key=None):
    del root_key
    enabled = any(set(role.get("enabledOperations", ())) & profile.OPERATIONS for role in payload["roles"].values())
    if value is None:
        profile.require(not enabled, "candidate intake requires separate signed purpose admission")
        return None
    profile.require(type(value) is dict and set(value) == FIELDS and value["schema"] == SCHEMA)
    profile.digest(value["controlPlaneConfigurationDigest"])
    assertions.policy(value["credentialPolicy"])
    profile.require(type(value["operationMaxSeconds"]) is int and 1 <= value["operationMaxSeconds"] <= 30
        and value["maximumOriginalBytes"] == profile.MAX_ORIGINAL_BYTES)
    entries = value["assignments"]
    profile.require(type(entries) is list and 1 <= len(entries) <= 64)
    identities = []
    for entry in entries:
        profile.require(type(entry) is dict and set(entry) == ASSIGNMENT_FIELDS)
        profile.text(entry["instanceId"], 256)
        for name in ASSIGNMENT_FIELDS - {"instanceId"}:
            profile.digest(entry[name])
        identities.append((entry["instanceId"], entry["bootId"], entry["shadowKeySha256"]))
    profile.require(identities == sorted(set(identities)))
    return value


def verify_original(operation, arguments, *, configuration_payload, root_key, now_epoch_ns):
    values = profile.arguments(operation, arguments, typed="businessIntent" in arguments)
    selected = validate_policy(configuration_payload.get(FIELD), payload=configuration_payload, root_key=root_key)
    profile.require(selected is not None and values["control_plane_configuration_digest"] == selected["controlPlaneConfigurationDigest"])
    if operation == profile.OP_CLAIM:
        request = values["request"]
        context = request["context"]
        profile.require(values["credential_policy"] == selected["credentialPolicy"]
            and request["issuedAtEpochNs"] <= now_epoch_ns < request["expiresAtEpochNs"]
            <= request["issuedAtEpochNs"] + selected["operationMaxSeconds"] * 1_000_000_000)
    elif operation == profile.OP_PUBLISH:
        row = profile.scalar.document(values["request"]["claimOriginal"].encode("ascii"), 2 * profile.MAX_ORIGINAL_BYTES)
        context = profile.scalar.document(row["context_json"].encode("ascii"), 8192)
        profile.require(row["actor_id"] == values["actor_id"] and row["configuration_digest"] == values["control_plane_configuration_digest"]
            and row["issued_at_epoch_ns"] <= now_epoch_ns < row["expires_at_epoch_ns"]
            <= row["issued_at_epoch_ns"] + selected["operationMaxSeconds"] * 1_000_000_000)
    matches = [entry for entry in selected["assignments"] if all(entry[name] == context[name]
        for name in ("instanceId", "bootId", "shadowKeySha256"))]
    profile.require(len(matches) == 1)
    request = profile.management_original(values["request"]["managementRequestOriginal"] if operation == profile.OP_CLAIM
        else row["management_request_json"])
    from serverware import db
    original = db._policy_shadow_runtime_attestation_handoff_components(request["runtimeAttestation"])
    profile.require(original["role_record"]["runtimeConfigSha256"] == matches[0]["runtimeConfigSha256"],
        "candidate runtime configuration must match independently admitted original")
