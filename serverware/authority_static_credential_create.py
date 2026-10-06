"""Public formats and root-selected purpose policy for native static creation.

The native generation wrapper below is an owner output, not signed
evidence or a producer identity. Matching its intent, KEK label and ciphertext
shape proves neither native custody nor approval. The actual broker owner and
independently admitted signer/TEE/configuration assignment must authenticate
this original. The protected kernel must then re-read current
roles/hardware, prove fresh credential/generation/currentness identities and
atomically consume any required distinct-person approval with the insert.
Retaining an immutable candidate does not renew a prior execution or resolve
an uncertain commit; a future owner must independently fence those outcomes.

No secret, plaintext digest, key loader, encryption call or SQL belongs here.
Provider labels remain operator metadata, never verified provider identity.
"""
from collections.abc import Mapping
from datetime import datetime, timezone
import hashlib
import json
import uuid

from serverware.authority_publication_approval import canonical, policy
from serverware.authority_setup_bind_credential import metadata
from serverware import native_static_credential as material

OPERATION = "credential.static.create"
ACTION = "credential.create"
OPERATIONS = ASSERTION_OPERATIONS = frozenset({OPERATION})
FIELD = "staticCredentialCreationPolicy"
SCHEMA = "serverware.staticCredentialCreationAuthorityPolicy/v1"
INTENT_SCHEMA = "serverware.staticCredentialCreationIntent/v1"
GENERATION_SCHEMA = "serverware.nativeStaticCredentialGeneration/v1"
MAX_SECRET_BYTES = material.MAX_SECRET_BYTES
MAX_ARGUMENT_BYTES = 2 * 1024 * 1024
MAX_GENERATION_BYTES = (MAX_SECRET_BYTES * 4 + 2) // 3 + 8192
# The existing generic controlled approval request accepts TTL 1..3600 seconds.
# This bounds retained candidate validity, not a native operation or proof.
MAX_RETAINED_INTENT_SECONDS = 3600
KINDS = frozenset({"bearer", "basic", "header", "query", "cookie"})
REQUESTER_ROLES = frozenset({"admin", "policy_author", "credential_owner"})
APPROVER_ROLES = frozenset({"admin", "credential_owner"})
FIELDS = frozenset({"actor_id", "control_plane_configuration_digest",
    "credential_policy", "request", "approval_id"})
INTENT_FIELDS = frozenset({"credentialId", "credentialVersion", "name", "kind",
    "metadata", "issuedAtEpochNs", "expiresAtEpochNs"})
EXECUTION_FIELDS = frozenset({"executionIssuedAtEpochNs", "executionExpiresAtEpochNs"})
REQUEST_FIELDS = INTENT_FIELDS | EXECUTION_FIELDS | {"nativeGenerationOriginal"}
GENERATION_FIELDS = frozenset({"apiVersion", "purpose", "actorId",
    "controlPlaneConfigurationDigest", "intentSha256", "credentialId",
    "credentialVersion", "envelope"})
POLICY_FIELDS = frozenset({"schema", "controlPlaneConfigurationDigest",
    "credentialPolicy", "operationMaxSeconds", "maximumArgumentBytes",
    "maximumSecretBytes", "twoPersonRequired", "nativeSecretKekId", "intentMaxSeconds"})


def require(value, message="Static credential creation format or context differs"):
    if not value:
        raise ValueError(message)


def digest(value):
    require(type(value) is str and len(value) == 71 and value.startswith("sha256:")
        and all(c in "0123456789abcdef" for c in value[7:]) and value[7:] != "0" * 64)
    return value


def sha256(raw):
    require(type(raw) is bytes)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def identifier(value):
    require(type(value) is str and len(value) == 36 and str(uuid.UUID(value)) == value)
    return value


def _actor(value):
    require(type(value) is str and value.startswith("oidc:") and value == value.strip()
        and 0 < len(value.encode("utf-8")) <= 512
        and not any(ord(c) < 32 or ord(c) == 127 for c in value))


def _kek_id(value):
    require(type(value) is str and value.startswith("attested-memory-kek:")
        and len(value) == 44 and all(c in "0123456789abcdef" for c in value[-24:]))


def _intent_request(value):
    require(type(value) is dict and set(value) == INTENT_FIELDS)
    identifier(value["credentialId"])
    require(type(value["credentialVersion"]) is int and value["credentialVersion"] == 1
        and type(value["kind"]) is str and value["kind"] in KINDS
        and type(value["name"]) is str)
    # Existing name values are not stripped, normalized or replaced. The
    # closed original's byte bound, not a new label rule, bounds this text.
    value["name"].encode("utf-8", errors="strict")
    metadata(value["metadata"])
    require(value["metadata"].get("oauth") is not True,
        "Managed OAuth credentials require their verified provider flow")
    issued, expires = value["issuedAtEpochNs"], value["expiresAtEpochNs"]
    require(type(issued) is int and type(expires) is int
        and 0 < issued < expires <= 2**63 - 1
        and expires - issued <= MAX_RETAINED_INTENT_SECONDS * 1_000_000_000)
    require(len(canonical(value)) <= MAX_ARGUMENT_BYTES)
    return value


def intent_original(*, actor_id, configuration_digest, credential_policy, request):
    """Immutable pre-sealing intent and retention interval, never execution."""
    _actor(actor_id)
    digest(configuration_digest)
    policy(credential_policy)
    _intent_request(request)
    raw = canonical({"apiVersion": INTENT_SCHEMA, "operation": OPERATION,
        "actorId": actor_id, "controlPlaneConfigurationDigest": configuration_digest,
        "credentialPolicy": credential_policy, "request": request})
    require(len(raw) <= MAX_ARGUMENT_BYTES)
    return raw


def generation(original):
    """Decode the planned literal output; this is NOT producer verification."""
    require(type(original) is str and 0 < len(original) <= MAX_GENERATION_BYTES)
    raw = original.encode("ascii")

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "Static generation contains duplicate fields")
            result[key] = value
        return result

    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: require(False))
    require(type(value) is dict and set(value) == GENERATION_FIELDS and canonical(value) == raw
        and value["apiVersion"] == GENERATION_SCHEMA and value["purpose"] == OPERATION)
    _actor(value["actorId"])
    digest(value["controlPlaneConfigurationDigest"])
    digest(value["intentSha256"])
    identifier(value["credentialId"])
    require(type(value["credentialVersion"]) is int and value["credentialVersion"] == 1)
    # Exact existing seven-field DB envelope and 1 MiB ciphertext bound only;
    # no decryption, byte provenance or confidential UTF-8 claim is made here.
    material.envelope_fields(value["envelope"])
    return value


def arguments(operation, value, *, typed=False):
    require(operation == OPERATION and isinstance(value, Mapping) and type(typed) is bool)
    allowed = FIELDS | ({"businessIntent", "authn_evidence"} if typed else set())
    require(FIELDS <= set(value) <= allowed and (not typed or "businessIntent" in value))
    request = value["request"]
    require(type(request) is dict and set(request) == REQUEST_FIELDS)
    original_intent = intent_original(actor_id=value["actor_id"],
        configuration_digest=value["control_plane_configuration_digest"],
        credential_policy=value["credential_policy"],
        request={name: request[name] for name in INTENT_FIELDS})
    native = generation(request["nativeGenerationOriginal"])
    require(native["actorId"] == value["actor_id"]
        and native["controlPlaneConfigurationDigest"] == value["control_plane_configuration_digest"]
        and native["intentSha256"] == sha256(original_intent)
        and native["credentialId"] == request["credentialId"]
        and native["credentialVersion"] == request["credentialVersion"])
    stamp = datetime.fromisoformat(native["envelope"]["secret_updated_at"])
    delta = stamp - datetime(1970, 1, 1, tzinfo=timezone.utc)
    sealed_ns = (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000
    issued, expires = request["executionIssuedAtEpochNs"], request["executionExpiresAtEpochNs"]
    require(type(issued) is int and type(expires) is int
        and request["issuedAtEpochNs"] <= sealed_ns <= issued < expires <= request["expiresAtEpochNs"]
        and expires - issued <= 30_000_000_000)
    if value["approval_id"] is not None:
        identifier(value["approval_id"])
    original = {name: value[name] for name in FIELDS}
    require(len(canonical(original)) <= MAX_ARGUMENT_BYTES)
    return original


def approval_payload_digest(value):
    """Bind the full candidate, excluding locator and fresh execution interval.

    A future approval owner must use this for both request and consumption;
    it must not reinterpret the old plaintext-bearing HTTP payload digest.
    Approval delay changes neither the original intent nor its ciphertext,
    configuration, hardware policy or fixed retained expiry. Every subsequent
    execution still requires its own genuinely authorized short-lived request.
    """
    values = arguments(OPERATION, value, typed="businessIntent" in value)
    candidate = {name: values[name] for name in FIELDS - {"approval_id", "request"}}
    candidate["request"] = {name: item for name, item in values["request"].items()
        if name not in EXECUTION_FIELDS}
    return sha256(canonical({"action": ACTION, **candidate}))


def validate_policy(value, *, payload=None, root_key=None):
    """Validate the selected policy; this is not native custody verification."""
    del root_key
    if value is None and payload is not None:
        selected_operations = OPERATIONS | {"credential.static.approval-request", "credential.static.approval-decide"}
        require(not any(set(role.get("enabledOperations", ())) & selected_operations
            for role in payload["roles"].values()), "Static creation requires explicit signed purpose admission")
        return None
    require(type(value) is dict and set(value) == POLICY_FIELDS and value["schema"] == SCHEMA)
    digest(value["controlPlaneConfigurationDigest"])
    policy(value["credentialPolicy"])
    _kek_id(value["nativeSecretKekId"])
    require(type(value["operationMaxSeconds"]) is int and 1 <= value["operationMaxSeconds"] <= 30
        and type(value["maximumArgumentBytes"]) is int and value["maximumArgumentBytes"] == MAX_ARGUMENT_BYTES
        and type(value["maximumSecretBytes"]) is int and value["maximumSecretBytes"] == MAX_SECRET_BYTES
        and type(value["intentMaxSeconds"]) is int
        and 1 <= value["intentMaxSeconds"] <= MAX_RETAINED_INTENT_SECONDS
        and type(value["twoPersonRequired"]) is bool)
    if payload is not None and any(set(role.get("enabledOperations", ()))
            & {"credential.static.approval-request", "credential.static.approval-decide"}
            for role in payload["roles"].values()):
        require(value["twoPersonRequired"] is True,
            "Static approval operations require the signed two-person creation policy")
    return value


def request_digest(operation, value):
    from serverware import authority_contract as contract
    from serverware import authority_request_commitment as commitment

    values = arguments(operation, value, typed="businessIntent" in value)
    typed = {**values, "businessIntent": contract.synthesize_business_intent(operation, values)}
    return commitment.framed_digest("serverware.policyAuthorityV9Request/v1", canonical({
        "schema": "serverware.policyAuthorityV9Authorization/v1", "operation": operation,
        "handler": contract.operation_spec(operation)["handler"],
        "operationManifestDigest": contract.OPERATION_MANIFEST_DIGEST,
        "arguments": commitment._authorization_arguments(typed)}))


def verify_original(operation, arguments_value, *, configuration_payload, root_key, now_epoch_ns):
    """Check the actual selected policy; the owner separately verifies custody."""
    selected = validate_policy(configuration_payload.get(FIELD),
        payload=configuration_payload, root_key=root_key)
    require(selected is not None, "Static credential creation purpose is not selected")
    verify_request_context(operation, arguments_value, selected_policy=selected, now_epoch_ns=now_epoch_ns)


def verify_request_context(operation, arguments_value, *, selected_policy, now_epoch_ns):
    """Selected request context, deliberately not native custody verification.

    The caller must select twoPersonRequired from the actual configured global
    credential.create policy, never HTTP input. An approval ID is only a
    locator: current roles, distinct actors, hardware provenance, exact payload,
    unconsumed row and atomic consumption remain the protected kernel's work.
    Its approval expiry must be clipped to the retained intent expiry, and its
    actual execution deadline must also be clipped to that original approval.
    Neither the KEK label nor this wrapper supplies native provenance.
    A historical producer proof must not be treated as current assignment
    authority. Retained validity cannot extend its original interval or permit
    retry/renewal of a prior uncertain execution.
    """
    selected = validate_policy(selected_policy)
    values = arguments(operation, arguments_value, typed="businessIntent" in arguments_value)
    request = values["request"]
    require(type(now_epoch_ns) is int and 0 < now_epoch_ns <= 2**63 - 1
        and values["control_plane_configuration_digest"] == selected["controlPlaneConfigurationDigest"]
        and values["credential_policy"] == selected["credentialPolicy"]
        and request["expiresAtEpochNs"] - request["issuedAtEpochNs"]
        <= selected["intentMaxSeconds"] * 1_000_000_000
        and request["executionIssuedAtEpochNs"] <= now_epoch_ns < request["executionExpiresAtEpochNs"]
        <= request["executionIssuedAtEpochNs"] + selected["operationMaxSeconds"] * 1_000_000_000
        and (values["approval_id"] is not None) == selected["twoPersonRequired"]
        and generation(request["nativeGenerationOriginal"])["envelope"]["secret_kek_id"] == selected["nativeSecretKekId"])
