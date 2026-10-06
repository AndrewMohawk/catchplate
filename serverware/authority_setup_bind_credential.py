"""Closed originals for provider-independent Setup credential binding.

Only the bounded public credential generation projection travels in these
originals. The purpose kernel must independently prove the current session,
credential generation/currentness, participant roles, hardware and event root.
This contract neither creates credentials nor grants provider authority.
"""
from collections.abc import Mapping
import json

from serverware import authority_oauth_setup as setup
from serverware import authority_publication_approval as assertions

canonical, digest, sha256 = setup.canonical, setup.digest, setup.sha256
text, epoch, identifier = setup.text, setup.epoch, setup.identifier
policy = assertions.policy
row_original = setup.row_original
ROW_FIELDS, EVENT_FIELDS = setup.ROW_FIELDS, setup.EVENT_FIELDS
AUDIT_LINK_FIELDS, AUDIT_LINK_TABLE = setup.AUDIT_LINK_FIELDS, setup.AUDIT_LINK_TABLE
MAX_ROW_BYTES, MAX_EVENT_BYTES = setup.MAX_ROW_BYTES, setup.MAX_EVENT_BYTES
MAX_CREDENTIAL_BYTES = 32 * 1024
MAX_ARGUMENT_BYTES = 128 * 1024
MAX_HTTP_REQUEST = MAX_HTTP_RESPONSE = 1024 * 1024
MAX_EVENTS = 128
OPERATION = "setup.session.bind-credential"
OP_SETTLE = "setup.session.bind-credential-audit-settle"
OPERATIONS = frozenset({OPERATION, OP_SETTLE})
ASSERTION_OPERATIONS = frozenset({OPERATION})
HTTP_SCHEMA = "serverware.setupCredentialBindingRequest/v1"
OPTIONS_SCHEMA = "serverware.setupCredentialBindingOptions/v1"
MFA_FIELD = "setupCredentialBindingProfile"
FIELD = "setupCredentialBindingPolicy"
SCHEMA = "serverware.setupCredentialBindingAuthorityPolicy/v1"
FIELDS = frozenset({"actor_id", "control_plane_configuration_digest", "credential_policy", "request"})
REQUEST_FIELDS = frozenset({"sessionOriginal", "credentialOriginal", "issuedAtEpochNs", "expiresAtEpochNs"})
CREDENTIAL_FIELDS = frozenset({"id", "kind", "credential_version", "metadata", "lifecycle_status"})
POLICY_FIELDS = frozenset({"schema", "controlPlaneConfigurationDigest", "credentialPolicy",
    "operationMaxSeconds", "maximumArgumentBytes", "maximumEvents"})
MUTATION_ROLES = frozenset({"admin", "attestation_operator", "attestation_reviewer",
    "credential_owner", "policy_author", "policy_publisher"})

# Exact existing db.validate_credential_metadata bounds and sensitive-name
# semantics, retained here without importing a database/runtime owner.
_METADATA_MAX_BYTES, _METADATA_MAX_KEYS, _METADATA_MAX_DEPTH = 16 * 1024, 128, 8
_SENSITIVE_METADATA_KEYS = frozenset({
    "access_token", "api_secret", "api_key", "apikey", "auth_token", "authorization",
    "bearer_token", "client_secret", "cookie", "credential", "credentials", "id_token",
    "password", "passwd", "private_key", "proxy_authorization", "refresh_token", "secret",
    "secret_key", "session_cookie", "session_token", "set_cookie", "signing_key", "token"})
_SENSITIVE_METADATA_COMPACT = frozenset(
    "".join(character for character in key if character.isalnum()) for key in _SENSITIVE_METADATA_KEYS)
_SENSITIVE_METADATA_SUFFIXES = ("apikey", "authorization", "cookie", "credential", "credentials",
    "password", "passwd", "privatekey", "secret", "signingkey", "token")


def require(value, message="Setup credential binding original or scope differs"):
    if not value:
        raise ValueError(message)


def row(original):
    require(type(original) is str)
    raw = original.encode("ascii")
    require(0 < len(raw) <= MAX_ROW_BYTES)
    value = setup.document(raw, MAX_ROW_BYTES)
    require(row_original(value) == raw)
    return value


def metadata(value):
    """Validate already-decoded public metadata without normalizing its values."""
    require(type(value) is dict, "Credential metadata must be an object")
    key_count = 0

    def walk(item, depth):
        nonlocal key_count
        require(depth <= _METADATA_MAX_DEPTH, "Credential metadata exceeds its nesting bound")
        if isinstance(item, dict):
            key_count += len(item)
            require(key_count <= _METADATA_MAX_KEYS, "Credential metadata exceeds its key bound")
            for key, child in item.items():
                require(isinstance(key, str) and key and len(key.encode("utf-8")) <= 256,
                    "Credential metadata key is not bounded public text")
                compact = "".join(character for character in key.strip().lower() if character.isalnum())
                require(compact not in _SENSITIVE_METADATA_COMPACT
                    and not compact.endswith(_SENSITIVE_METADATA_SUFFIXES),
                    "Credential metadata key may contain secret material")
                walk(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                walk(child, depth + 1)

    walk(value, 0)
    # Match finite JSON, including finite fractional values and the exact
    # canonical ASCII size; do not import an unrelated integer-only codec.
    require(len(canonical(value)) <= _METADATA_MAX_BYTES, "Credential metadata exceeds 16 KiB")
    return value


def credential_original(value):
    require(isinstance(value, Mapping) and set(value) == CREDENTIAL_FIELDS)
    owned = dict(value)
    identifier(owned["id"])
    require(type(owned["kind"]) is str and type(owned["credential_version"]) is int
        and 1 <= owned["credential_version"] <= 2**63 - 1 and owned["lifecycle_status"] == "active")
    metadata(owned["metadata"])
    raw = canonical(owned)
    require(0 < len(raw) <= MAX_CREDENTIAL_BYTES)
    return raw


def credential(original):
    require(type(original) is str)
    raw = original.encode("ascii")
    require(0 < len(raw) <= MAX_CREDENTIAL_BYTES)

    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "Credential original has duplicate fields")
            value[key] = item
        return value

    value = json.loads(raw.decode("ascii"), object_pairs_hook=pairs,
        parse_constant=lambda _: require(False, "Credential original is not finite JSON"))
    require(type(value) is dict and credential_original(value) == raw)
    return value


def arguments(operation, value, *, typed=False):
    require(operation in OPERATIONS and isinstance(value, Mapping) and type(typed) is bool)
    if operation == OP_SETTLE:
        require(set(value) == {"event_id"} | ({"businessIntent"} if typed else set()))
        identifier(value["event_id"])
        return {"event_id": value["event_id"]}
    allowed = FIELDS | ({"businessIntent", "authn_evidence"} if typed else set())
    require(FIELDS <= set(value) <= allowed and (not typed or "businessIntent" in value))
    text(value["actor_id"], 512)
    require(value["actor_id"].startswith("oidc:"))
    digest(value["control_plane_configuration_digest"])
    policy(value["credential_policy"])
    request = value["request"]
    require(type(request) is dict and set(request) == REQUEST_FIELDS)
    session = row(request["sessionOriginal"])
    require(session["status"] == "active" and session["phase"] == "created"
        and session["terminal_at"] is None and session["credential_id"] is None
        and session["credential_version"] is None and session["revision"] < 2**63 - 1)
    credential(request["credentialOriginal"])
    issued, expires = request["issuedAtEpochNs"], request["expiresAtEpochNs"]
    require(type(issued) is int and type(expires) is int
        and 0 < issued < expires <= 2**63 - 1 and expires - issued <= 30_000_000_000
        and epoch(session["created_at"]) <= issued and expires <= epoch(session["expires_at"]))
    original = {name: value[name] for name in FIELDS}
    require(len(canonical(original)) <= MAX_ARGUMENT_BYTES)
    return original


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


def validate_policy(value, *, payload, root_key=None):
    del root_key
    enabled = any(set(role.get("enabledOperations", ())) & OPERATIONS for role in payload["roles"].values())
    if value is None:
        require(not enabled, "Setup credential binding requires explicit signed purpose admission")
        return None
    require(type(value) is dict and set(value) == POLICY_FIELDS and value["schema"] == SCHEMA)
    digest(value["controlPlaneConfigurationDigest"])
    policy(value["credentialPolicy"])
    require(type(value["operationMaxSeconds"]) is int and 1 <= value["operationMaxSeconds"] <= 30
        and type(value["maximumArgumentBytes"]) is int and value["maximumArgumentBytes"] == MAX_ARGUMENT_BYTES
        and type(value["maximumEvents"]) is int and 1 <= value["maximumEvents"] <= MAX_EVENTS)
    return value


def verify_original(operation, arguments_value, *, configuration_payload, root_key, now_epoch_ns):
    values = arguments(operation, arguments_value, typed="businessIntent" in arguments_value)
    require(type(now_epoch_ns) is int and 0 < now_epoch_ns <= 2**63 - 1)
    selected = validate_policy(configuration_payload.get(FIELD), payload=configuration_payload, root_key=root_key)
    require(selected is not None, "Setup credential binding purpose is not selected")
    if operation == OP_SETTLE:
        # Only the exact audited binding outbox can settle its linked event.
        # This is not fresh credential/provider/publication authorization.
        return
    request = values["request"]
    require(values["control_plane_configuration_digest"] == selected["controlPlaneConfigurationDigest"]
        and values["credential_policy"] == selected["credentialPolicy"]
        and request["issuedAtEpochNs"] <= now_epoch_ns < request["expiresAtEpochNs"]
        <= request["issuedAtEpochNs"] + selected["operationMaxSeconds"] * 1_000_000_000)
