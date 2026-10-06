"""Purpose-fixed, provider-independent protected Setup tracking creation.

The independently signed policy explicitly selects bounded whole-table
capacities. These originals confer no provider, credential, policy publication
or enrollment authority. Tracking TTL is separate from the short original
authorization interval; the actual kernel derives creation time and blank
bindings from its current transaction, roles and verified hardware evidence.
"""
from collections.abc import Mapping

from serverware import authority_oauth_setup as setup
from serverware import authority_publication_approval as assertions

canonical, digest, sha256 = setup.canonical, setup.digest, setup.sha256
text, epoch, identifier = setup.text, setup.epoch, setup.identifier
policy = assertions.policy
row_original = setup.row_original
ROW_FIELDS, EVENT_FIELDS = setup.ROW_FIELDS, setup.EVENT_FIELDS
AUDIT_LINK_FIELDS, AUDIT_LINK_TABLE = setup.AUDIT_LINK_FIELDS, setup.AUDIT_LINK_TABLE
MAX_ROW_BYTES, MAX_EVENT_BYTES = setup.MAX_ROW_BYTES, setup.MAX_EVENT_BYTES
MAX_ARGUMENT_BYTES = 128 * 1024
MAX_HTTP_REQUEST = MAX_HTTP_RESPONSE = 1024 * 1024
MAX_SESSIONS, MAX_EVENTS = 64, 128
MIN_SESSION_TTL_SECONDS, MAX_SESSION_TTL_SECONDS = 300, 604800
OPERATION = "setup.session.create"
OP_SETTLE = "setup.session.create-audit-settle"
OPERATIONS = frozenset({OPERATION, OP_SETTLE})
ASSERTION_OPERATIONS = frozenset({OPERATION})
HTTP_SCHEMA = "serverware.setupTrackingCreationRequest/v1"
OPTIONS_SCHEMA = "serverware.setupTrackingCreationOptions/v1"
MFA_FIELD = "setupTrackingCreationProfile"
FIELD = "setupTrackingCreationPolicy"
SCHEMA = "serverware.setupTrackingCreationAuthorityPolicy/v2"
FIELDS = frozenset({"actor_id", "control_plane_configuration_digest", "credential_policy", "request"})
REQUEST_FIELDS = frozenset({"sessionId", "templateId", "principalId", "routeId", "routePolicyDigest",
    "ttlSeconds", "issuedAtEpochNs", "expiresAtEpochNs"})
POLICY_FIELDS = frozenset({"schema", "credentialPolicy",
    "operationMaxSeconds", "maximumArgumentBytes", "maximumSessions", "maximumEvents",
    "maximumActiveSessions", "maximumSessionTtlSeconds"})
MUTATION_ROLES = frozenset({"admin", "policy_author", "policy_publisher", "credential_owner"})


def require(value, message="Setup tracking creation original or scope differs"):
    if not value:
        raise ValueError(message)


def row(original):
    require(type(original) is str)
    raw = original.encode("ascii")
    require(0 < len(raw) <= MAX_ROW_BYTES)
    value = setup.document(raw, MAX_ROW_BYTES)
    require(row_original(value) == raw)
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
    identifier(request["sessionId"])
    for name in ("templateId", "principalId", "routeId"):
        if request[name] is not None:
            text(request[name], 512)
    if request["routePolicyDigest"] is not None:
        digest(request["routePolicyDigest"])
        require(request["routeId"] is not None)
    ttl = request["ttlSeconds"]
    require(type(ttl) is int and MIN_SESSION_TTL_SECONDS <= ttl <= MAX_SESSION_TTL_SECONDS)
    issued, expires = request["issuedAtEpochNs"], request["expiresAtEpochNs"]
    require(type(issued) is int and type(expires) is int
        and 0 < issued < expires <= 2**63 - 1 and expires - issued <= 30_000_000_000)
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
        require(not enabled, "Setup tracking creation requires explicit signed purpose admission")
        return None
    require(type(value) is dict and set(value) == POLICY_FIELDS and value["schema"] == SCHEMA)
    policy(value["credentialPolicy"])
    require(type(value["operationMaxSeconds"]) is int and 1 <= value["operationMaxSeconds"] <= 30
        and type(value["maximumArgumentBytes"]) is int and value["maximumArgumentBytes"] == MAX_ARGUMENT_BYTES
        and type(value["maximumSessions"]) is int and 1 <= value["maximumSessions"] <= MAX_SESSIONS
        and type(value["maximumEvents"]) is int and 1 <= value["maximumEvents"] <= MAX_EVENTS
        and type(value["maximumActiveSessions"]) is int
        and 1 <= value["maximumActiveSessions"] <= value["maximumSessions"]
        and type(value["maximumSessionTtlSeconds"]) is int
        and MIN_SESSION_TTL_SECONDS <= value["maximumSessionTtlSeconds"] <= MAX_SESSION_TTL_SECONDS)
    return value


def verify_original(operation, arguments_value, *, configuration_payload, root_key, now_epoch_ns):
    from serverware.authority_policy_canary_policy import full_configuration_digest

    values = arguments(operation, arguments_value, typed="businessIntent" in arguments_value)
    require(type(now_epoch_ns) is int and 0 < now_epoch_ns <= 2**63 - 1)
    selected = validate_policy(configuration_payload.get(FIELD), payload=configuration_payload, root_key=root_key)
    require(selected is not None, "Setup tracking creation purpose is not selected")
    if operation == OP_SETTLE:
        # The separate factual kernel requires the exact already-audited
        # creation outbox original; settlement does not grant a human action.
        return
    request = values["request"]
    require(values["control_plane_configuration_digest"] == full_configuration_digest(configuration_payload)
        and values["credential_policy"] == selected["credentialPolicy"]
        and request["ttlSeconds"] <= selected["maximumSessionTtlSeconds"]
        and request["issuedAtEpochNs"] <= now_epoch_ns < request["expiresAtEpochNs"]
        <= request["issuedAtEpochNs"] + selected["operationMaxSeconds"] * 1_000_000_000)
