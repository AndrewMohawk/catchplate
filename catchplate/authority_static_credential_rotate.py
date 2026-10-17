"""Closed, separately admitted static N+1 rotation originals.

Ciphertext wrappers and historical provenance are acquisition data. Only the
controlled transition over authenticated rows, a consumed drain barrier and
fresh purpose-specific native/hardware evidence can authorize an update.
"""
from collections.abc import Mapping
from datetime import datetime, timezone
import json

from catchplate import authority_static_credential_create as creation
from catchplate import native_static_credential_rotation as material

canonical, policy, metadata = creation.canonical, creation.policy, creation.metadata
require, digest, sha256, identifier = creation.require, creation.digest, creation.sha256, creation.identifier
_actor, _kek_id = creation._actor, creation._kek_id
KINDS, REQUESTER_ROLES, APPROVER_ROLES = creation.KINDS, creation.REQUESTER_ROLES, creation.APPROVER_ROLES
MAX_SECRET_BYTES = creation.MAX_SECRET_BYTES
MAX_ARGUMENT_BYTES = creation.MAX_ARGUMENT_BYTES
MAX_GENERATION_BYTES = creation.MAX_GENERATION_BYTES
MAX_RETAINED_INTENT_SECONDS = creation.MAX_RETAINED_INTENT_SECONDS
OPERATION = "credential.static.rotate"
ACTION = "credential.update"
OPERATIONS = ASSERTION_OPERATIONS = frozenset({OPERATION})
FIELD = "staticCredentialRotationPolicy"
SCHEMA = "catchplate.staticCredentialRotationAuthorityPolicy/v1"
INTENT_SCHEMA = "catchplate.staticCredentialRotationIntent/v1"
GENERATION_SCHEMA = "catchplate.nativeStaticCredentialRotationGeneration/v1"
NATIVE_CUSTODY_PURPOSE = "catchplate.nativeStaticCredentialRotationStatement/v1"
FIELDS = creation.FIELDS
INTENT_FIELDS = frozenset({"credentialId", "previousCredentialVersion", "credentialVersion",
    "previousCredentialSha256", "previousCurrentnessOriginRequestDigest", "previousProvenanceOriginal",
    "name", "kind", "metadata", "issuedAtEpochNs", "expiresAtEpochNs"})
EXECUTION_FIELDS = frozenset({"executionIssuedAtEpochNs", "executionExpiresAtEpochNs",
    "predecessorBarrierSha256", "predecessorCurrentnessRootSha256"})
REQUEST_FIELDS = INTENT_FIELDS | EXECUTION_FIELDS | {"nativeGenerationOriginal"}
GENERATION_FIELDS = creation.GENERATION_FIELDS
POLICY_FIELDS = creation.POLICY_FIELDS | {"nativeCustodyPurpose"}


def _intent_request(value):
    from catchplate import static_credential_provenance_values as provenance

    require(type(value) is dict and set(value) == INTENT_FIELDS)
    identifier(value["credentialId"])
    previous, successor = value["previousCredentialVersion"], value["credentialVersion"]
    require(type(previous) is int and type(successor) is int
        and 1 <= previous < 2**63 - 1 and successor == previous + 1
        and type(value["kind"]) is str and value["kind"] in KINDS and type(value["name"]) is str)
    value["name"].encode("utf-8", errors="strict")
    metadata(value["metadata"])
    require(value["metadata"].get("oauth") is not True)
    digest(value["previousCredentialSha256"])
    digest(value["previousCurrentnessOriginRequestDigest"])
    parsed = provenance.generation_original(value["previousProvenanceOriginal"])
    statement = provenance.generation_evidence(value["previousProvenanceOriginal"])["statement"]
    require(statement["credentialId"] == value["credentialId"] and statement["credentialVersion"] == previous
        and provenance.request_digest(parsed) == value["previousCurrentnessOriginRequestDigest"])
    issued, expires = value["issuedAtEpochNs"], value["expiresAtEpochNs"]
    require(type(issued) is int and type(expires) is int and 0 < issued < expires <= 2**63 - 1
        and expires - issued <= MAX_RETAINED_INTENT_SECONDS * 1_000_000_000
        and len(canonical(value)) <= MAX_ARGUMENT_BYTES)
    return value


def intent_original(*, actor_id, configuration_digest, credential_policy, request):
    _actor(actor_id); digest(configuration_digest); policy(credential_policy)
    _intent_request(request)
    raw = canonical({"apiVersion": INTENT_SCHEMA, "operation": OPERATION, "actorId": actor_id,
        "controlPlaneConfigurationDigest": configuration_digest, "credentialPolicy": credential_policy,
        "request": request})
    require(len(raw) <= MAX_ARGUMENT_BYTES)
    return raw


def generation(original):
    """Literal output syntax only; this does not authenticate its producer."""
    require(type(original) is str and original.isascii() and 0 < len(original) <= MAX_GENERATION_BYTES)

    def pairs(items):
        result = {}
        for name, item in items:
            require(name not in result)
            result[name] = item
        return result

    value = json.loads(original, object_pairs_hook=pairs, parse_constant=lambda _: require(False))
    require(type(value) is dict and set(value) == GENERATION_FIELDS and canonical(value).decode("ascii") == original
        and value["apiVersion"] == GENERATION_SCHEMA and value["purpose"] == OPERATION)
    _actor(value["actorId"]); digest(value["controlPlaneConfigurationDigest"])
    digest(value["intentSha256"]); identifier(value["credentialId"])
    require(type(value["credentialVersion"]) is int and 2 <= value["credentialVersion"] <= 2**63 - 1)
    material.envelope_fields(value["envelope"])
    require(value["envelope"]["credential_version"] == value["credentialVersion"])
    return value


def arguments(operation, value, *, typed=False, candidate=False):
    require(operation == OPERATION and isinstance(value, Mapping) and type(typed) is bool and type(candidate) is bool)
    require(not candidate or not typed and value.get("approval_id") is None)
    allowed = FIELDS | ({"businessIntent", "authn_evidence"} if typed else set())
    require(FIELDS <= set(value) <= allowed and (not typed or "businessIntent" in value))
    request = value["request"]
    require(type(request) is dict and set(request) == REQUEST_FIELDS)
    intent = intent_original(actor_id=value["actor_id"], configuration_digest=value["control_plane_configuration_digest"],
        credential_policy=value["credential_policy"], request={name: request[name] for name in INTENT_FIELDS})
    native = generation(request["nativeGenerationOriginal"])
    require(native["actorId"] == value["actor_id"]
        and native["controlPlaneConfigurationDigest"] == value["control_plane_configuration_digest"]
        and native["intentSha256"] == sha256(intent) and native["credentialId"] == request["credentialId"]
        and native["credentialVersion"] == request["credentialVersion"])
    delta = datetime.fromisoformat(native["envelope"]["secret_updated_at"]) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    sealed_ns = (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000
    issued, expires = request["executionIssuedAtEpochNs"], request["executionExpiresAtEpochNs"]
    require(type(issued) is int and type(expires) is int
        and request["issuedAtEpochNs"] <= sealed_ns <= issued < expires <= request["expiresAtEpochNs"]
        and expires - issued <= 30_000_000_000)
    if not candidate or request["predecessorBarrierSha256"] is not None or request["predecessorCurrentnessRootSha256"] is not None:
        digest(request["predecessorBarrierSha256"]); digest(request["predecessorCurrentnessRootSha256"])
    if value["approval_id"] is not None:
        identifier(value["approval_id"])
    result = {name: value[name] for name in FIELDS}
    require(len(canonical(result)) <= MAX_ARGUMENT_BYTES)
    return result


def approval_payload_digest(value, *, candidate=False):
    values = arguments(OPERATION, value, typed="businessIntent" in value, candidate=candidate)
    candidate = {name: values[name] for name in FIELDS - {"approval_id", "request"}}
    candidate["request"] = {name: item for name, item in values["request"].items() if name not in EXECUTION_FIELDS}
    return sha256(canonical({"action": ACTION, **candidate}))


def validate_policy(value, *, payload=None, root_key=None):
    del root_key
    approval_ops = {"credential.static.rotation-approval-request", "credential.static.rotation-approval-decide"}
    if value is None and payload is not None:
        require(not any(set(role.get("enabledOperations", ())) & (OPERATIONS | approval_ops)
            for role in payload["roles"].values()), "Static rotation requires its own signed purpose policy")
        return None
    require(type(value) is dict and set(value) == POLICY_FIELDS and value["schema"] == SCHEMA
        and value["nativeCustodyPurpose"] == NATIVE_CUSTODY_PURPOSE)
    policy(value["credentialPolicy"]); _kek_id(value["nativeSecretKekId"])
    require(type(value["operationMaxSeconds"]) is int and 1 <= value["operationMaxSeconds"] <= 30
        and type(value["maximumArgumentBytes"]) is int and value["maximumArgumentBytes"] == MAX_ARGUMENT_BYTES
        and type(value["maximumSecretBytes"]) is int and value["maximumSecretBytes"] == MAX_SECRET_BYTES
        and type(value["intentMaxSeconds"]) is int and 1 <= value["intentMaxSeconds"] <= MAX_RETAINED_INTENT_SECONDS
        and type(value["twoPersonRequired"]) is bool)
    if payload is not None:
        if any(set(role.get("enabledOperations", ())) & approval_ops for role in payload["roles"].values()):
            require(value["twoPersonRequired"] is True)
        from catchplate import authority_credential_currentness_policy as currentness
        require(payload.get(currentness.FIELD, {}).get("schema") == currentness.ROTATION_POSTBOOT_SCHEMA,
            "Static rotation requires separately selected successor currentness provenance")
    return value


def request_digest(operation, value):
    from catchplate import authority_contract as contract
    from catchplate import authority_request_commitment as commitment
    values = arguments(operation, value, typed="businessIntent" in value)
    typed = {**values, "businessIntent": contract.synthesize_business_intent(operation, values)}
    return commitment.framed_digest("catchplate.policyAuthorityV9Request/v1", canonical({
        "schema": "catchplate.policyAuthorityV9Authorization/v1", "operation": operation,
        "handler": contract.operation_spec(operation)["handler"],
        "operationManifestDigest": contract.OPERATION_MANIFEST_DIGEST,
        "arguments": commitment._authorization_arguments(typed)}))


def verify_request_context(operation, arguments_value, *, selected_policy, expected_configuration_digest, now_epoch_ns):
    digest(expected_configuration_digest)
    selected = validate_policy(selected_policy)
    values = arguments(operation, arguments_value, typed="businessIntent" in arguments_value)
    request = values["request"]
    require(type(now_epoch_ns) is int and 0 < now_epoch_ns <= 2**63 - 1
        and values["control_plane_configuration_digest"] == expected_configuration_digest
        and values["credential_policy"] == selected["credentialPolicy"]
        and request["expiresAtEpochNs"] - request["issuedAtEpochNs"] <= selected["intentMaxSeconds"] * 1_000_000_000
        and request["executionIssuedAtEpochNs"] <= now_epoch_ns < request["executionExpiresAtEpochNs"]
        <= request["executionIssuedAtEpochNs"] + selected["operationMaxSeconds"] * 1_000_000_000
        and (values["approval_id"] is not None) == selected["twoPersonRequired"]
        and generation(request["nativeGenerationOriginal"])["envelope"]["secret_kek_id"] == selected["nativeSecretKekId"])


def verify_original(operation, arguments_value, *, configuration_payload, root_key, now_epoch_ns):
    from catchplate.authority_policy_canary_policy import full_configuration_digest
    selected = validate_policy(configuration_payload.get(FIELD), payload=configuration_payload, root_key=root_key)
    require(selected is not None)
    verify_request_context(operation, arguments_value, selected_policy=selected,
        expected_configuration_digest=full_configuration_digest(configuration_payload), now_epoch_ns=now_epoch_ns)
