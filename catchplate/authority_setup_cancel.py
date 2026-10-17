"""Purpose-fixed Setup tracking cancellation and factual audit settlement.

The independently signed policy selects a bounded complete-event-table profile.
These public originals grant no credential, provider, publication or rollback
authority. The actual kernel proves current rows, roles and hardware evidence.
"""
from collections.abc import Mapping

from catchplate import authority_oauth_setup as setup
from catchplate import authority_publication_approval as assertions

canonical, digest, sha256 = setup.canonical, setup.digest, setup.sha256
text, epoch, identifier = setup.text, setup.epoch, setup.identifier
policy = assertions.policy
row_original = setup.row_original
EVENT_FIELDS, AUDIT_LINK_FIELDS = setup.EVENT_FIELDS, setup.AUDIT_LINK_FIELDS
AUDIT_LINK_TABLE = setup.AUDIT_LINK_TABLE
MAX_ROW_BYTES, MAX_EVENT_BYTES = setup.MAX_ROW_BYTES, setup.MAX_EVENT_BYTES
MAX_ARGUMENT_BYTES = 128 * 1024
MAX_HTTP_REQUEST = MAX_HTTP_RESPONSE = 1024 * 1024
MAX_EVENTS = 128
OPERATION = "setup.session.cancel"
OP_SETTLE = "setup.session.audit-settle"
OPERATIONS = frozenset({OPERATION, OP_SETTLE})
ASSERTION_OPERATIONS = frozenset({OPERATION})
HTTP_SCHEMA = "catchplate.setupTrackingCancellationRequest/v1"
OPTIONS_SCHEMA = "catchplate.setupTrackingCancellationOptions/v1"
MFA_FIELD = "setupTrackingCancellationProfile"
FIELD = "setupTrackingCancellationPolicy"
SCHEMA = "catchplate.setupTrackingCancellationAuthorityPolicy/v2"
FIELDS = frozenset({"actor_id", "control_plane_configuration_digest", "credential_policy", "request"})
REQUEST_FIELDS = frozenset({"sessionOriginal", "reason", "issuedAtEpochNs", "expiresAtEpochNs"})
POLICY_FIELDS = frozenset({"schema", "credentialPolicy",
    "operationMaxSeconds", "maximumArgumentBytes", "maximumEvents"})
MUTATION_ROLES = frozenset({"admin", "attestation_operator", "attestation_reviewer",
    "credential_owner", "policy_author", "policy_publisher"})


def require(value, message="Setup tracking cancellation original or scope differs"):
    if not value:
        raise ValueError(message)


def row(original):
    require(type(original) is str)
    raw = original.encode("ascii")
    require(0 < len(raw) <= MAX_ROW_BYTES)
    value = setup.document(raw, MAX_ROW_BYTES)
    require(row_original(value) == raw)
    return value


def reason(value):
    if value is not None:
        # Preserve the existing API character and DB UTF-8/control bounds.
        # Refuse noncanonical text; never silently trim the approved original.
        text(value, 2048)
        require(len(value) <= 2000)
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
    require(session["status"] == "active" and session["terminal_at"] is None
        and session["revision"] < 2**63 - 1)
    reason(request["reason"])
    issued, expires = request["issuedAtEpochNs"], request["expiresAtEpochNs"]
    require(type(issued) is int and type(expires) is int
        and 0 < issued < expires <= 2**63 - 1 and expires - issued <= 30_000_000_000
        and epoch(session["created_at"]) <= issued and expires <= epoch(session["expires_at"]))
    original = {name: value[name] for name in FIELDS}
    require(len(canonical(original)) <= MAX_ARGUMENT_BYTES)
    return original


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


def validate_policy(value, *, payload, root_key=None):
    del root_key
    enabled = any(set(role.get("enabledOperations", ())) & OPERATIONS for role in payload["roles"].values())
    if value is None:
        require(not enabled, "Setup tracking cancellation requires explicit signed purpose admission")
        return None
    require(type(value) is dict and set(value) == POLICY_FIELDS and value["schema"] == SCHEMA)
    policy(value["credentialPolicy"])
    require(type(value["operationMaxSeconds"]) is int and 1 <= value["operationMaxSeconds"] <= 30
        and type(value["maximumArgumentBytes"]) is int and value["maximumArgumentBytes"] == MAX_ARGUMENT_BYTES
        and type(value["maximumEvents"]) is int and 1 <= value["maximumEvents"] <= MAX_EVENTS)
    return value


def verify_original(operation, arguments_value, *, configuration_payload, root_key, now_epoch_ns):
    from catchplate.authority_policy_canary_policy import full_configuration_digest

    values = arguments(operation, arguments_value, typed="businessIntent" in arguments_value)
    require(type(now_epoch_ns) is int and 0 < now_epoch_ns <= 2**63 - 1)
    selected = validate_policy(configuration_payload.get(FIELD), payload=configuration_payload, root_key=root_key)
    require(selected is not None, "Setup tracking cancellation purpose is not selected")
    if operation == OP_SETTLE:
        # Only the exact already-audited outbox original can settle its linked
        # event. No session transition, human grant or provider contact follows.
        return
    request = values["request"]
    require(values["control_plane_configuration_digest"] == full_configuration_digest(configuration_payload)
        and values["credential_policy"] == selected["credentialPolicy"]
        and request["issuedAtEpochNs"] <= now_epoch_ns < request["expiresAtEpochNs"]
        <= request["issuedAtEpochNs"] + selected["operationMaxSeconds"] * 1_000_000_000)
