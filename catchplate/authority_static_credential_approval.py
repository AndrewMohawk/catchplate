"""Purpose-fixed public review of a retained static credential candidate.

The candidate's old execution interval is descriptive, never authorization for
requesting or deciding approval. Each operation has its own short original
interval and hardware assertion. These formats neither seal a secret nor
authenticate native custody; creation independently verifies that custody.
"""
import json
from datetime import datetime, timezone

from catchplate import authority_static_credential_create as creation

canonical, require, digest, sha256 = creation.canonical, creation.require, creation.digest, creation.sha256
identifier, policy = creation.identifier, creation.policy
OP_REQUEST = "credential.static.approval-request"
OP_DECIDE = "credential.static.approval-decide"
OPERATIONS = ASSERTION_OPERATIONS = frozenset({OP_REQUEST, OP_DECIDE})
FIELD = creation.FIELD
MAX_ARGUMENT_BYTES = creation.MAX_ARGUMENT_BYTES
MAX_REVIEW_BYTES = 1024 * 1024
HTTP_SCHEMA = "catchplate.staticCredentialApprovalRequest/v1"
OPTIONS_SCHEMA = "catchplate.staticCredentialApprovalOptions/v1"
MFA_FIELD = "staticCredentialApprovalProfile"
REVIEW_SCHEMA = "catchplate.staticCredentialCreationApprovalRequest/v1"
PROVENANCE_SCHEMA = "catchplate.staticCredentialApprovalProvenance/v1"
FIELDS = creation.FIELDS
REQUEST_FIELDS = frozenset({"candidateOriginal", "issuedAtEpochNs", "expiresAtEpochNs"})
PROVENANCE_FIELDS = frozenset({"schema", "credentialPolicy", "controlPlaneConfigurationDigest", "candidateSha256", "requestDigest",
    "requestEvidenceDigest", "decisionDigest", "decisionEvidenceDigest", "consumptionDigest", "consumptionEvidenceDigest"})
ROW_FIELDS = frozenset({"id", "action", "resource_id", "payload_digest", "status", "requester_id",
    "requested_at", "expires_at", "request_json", "approved_by", "approved_at", "consumed_by",
    "consumed_at", "decision_note", "approval_authn", "approver_webauthn_credential_id"})


def candidate(original):
    require(type(original) is str)
    raw = original.encode("ascii")
    require(0 < len(raw) <= MAX_ARGUMENT_BYTES)
    value = json.loads(raw, parse_constant=lambda _: require(False))
    require(type(value) is dict and set(value) == creation.FIELDS
        and value["approval_id"] is None and canonical(value) == raw,
        "Static approval requires the exact original unapproved candidate")
    creation.arguments(creation.OPERATION, value)
    return value


def approval_request(values):
    """One exact compact review shared by request, decision and consumption."""
    values = creation.arguments(creation.OPERATION, values, typed="businessIntent" in values)
    request = values["request"]
    native = creation.generation(request["nativeGenerationOriginal"])
    document = {"apiVersion": REVIEW_SCHEMA,
        **{name: request[name] for name in ("credentialId", "credentialVersion", "name", "kind",
            "metadata", "issuedAtEpochNs", "expiresAtEpochNs")},
        "intentSha256": native["intentSha256"],
        "nativeGenerationSha256": sha256(request["nativeGenerationOriginal"].encode("ascii")),
        "candidateSha256": creation.approval_payload_digest(values)}
    raw = canonical(document)
    require(len(raw) <= MAX_REVIEW_BYTES, "Static approval review exceeds the existing request bound")
    return raw.decode("ascii")


def provenance(original):
    require(type(original) is str and 0 < len(original.encode("ascii")) <= MAX_ARGUMENT_BYTES)
    value = json.loads(original, parse_constant=lambda _: require(False))
    require(type(value) is dict and set(value) == PROVENANCE_FIELDS
        and value["schema"] == PROVENANCE_SCHEMA and canonical(value).decode("ascii") == original)
    policy(value["credentialPolicy"])
    for name in ("controlPlaneConfigurationDigest", "candidateSha256", "requestDigest", "requestEvidenceDigest"):
        digest(value[name])
    for left, right in (("decisionDigest", "decisionEvidenceDigest"),
            ("consumptionDigest", "consumptionEvidenceDigest")):
        require((value[left] is None) == (value[right] is None))
        if value[left] is not None:
            digest(value[left]); digest(value[right])
    require(value["consumptionDigest"] is None or value["decisionDigest"] is not None)
    return value


def epoch(original):
    require(type(original) is str)
    value = datetime.fromisoformat(original)
    require(value.tzinfo is not None and value.utcoffset() == timezone.utc.utcoffset(value))
    delta = value - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000


def approval_row(original):
    """Exact public storage row, not the lossy collection presentation."""
    require(type(original) is str and 0 < len(original.encode("ascii")) <= MAX_ARGUMENT_BYTES)
    value = json.loads(original, parse_constant=lambda _: require(False))
    require(type(value) is dict and set(value) == ROW_FIELDS and canonical(value).decode("ascii") == original)
    identifier(value["id"]); identifier(value["resource_id"])
    creation._actor(value["requester_id"])
    require(value["action"] == creation.ACTION and value["status"] == "pending"
        and all(value[name] is None for name in ("approved_by", "approved_at", "consumed_by", "consumed_at",
            "decision_note", "approver_webauthn_credential_id")))
    review_original = value["request_json"]
    require(type(review_original) is str and 0 < len(review_original.encode("ascii")) <= MAX_REVIEW_BYTES)
    review = json.loads(review_original, parse_constant=lambda _: require(False))
    require(type(review) is dict and set(review) == creation.INTENT_FIELDS | {
        "apiVersion", "intentSha256", "nativeGenerationSha256", "candidateSha256"}
        and review["apiVersion"] == REVIEW_SCHEMA and canonical(review).decode("ascii") == review_original)
    creation._intent_request({name: review[name] for name in creation.INTENT_FIELDS})
    for name in ("intentSha256", "nativeGenerationSha256", "candidateSha256"):
        digest(review[name])
    proof = provenance(value["approval_authn"])
    require(value["resource_id"] == review["credentialId"]
        and value["payload_digest"] == review["candidateSha256"] == proof["candidateSha256"]
        and all(proof[name] is None for name in ("decisionDigest", "decisionEvidenceDigest", "consumptionDigest", "consumptionEvidenceDigest"))
        and review["issuedAtEpochNs"] <= epoch(value["requested_at"]) < epoch(value["expires_at"]) <= review["expiresAtEpochNs"]
        and epoch(value["expires_at"]) - epoch(value["requested_at"]) <= 3_600_000_000_000)
    return value


def approval_original(row):
    original = canonical(row).decode("ascii")
    approval_row(original)
    return original


def arguments(operation, value, *, typed=False):
    require(operation in OPERATIONS and type(value) is dict and type(typed) is bool)
    fields = FIELDS | ({"decision"} if operation == OP_DECIDE else set())
    allowed = fields | ({"businessIntent", "authn_evidence"} if typed else set())
    require(fields <= set(value) <= allowed and (not typed or "businessIntent" in value))
    creation._actor(value["actor_id"])
    digest(value["control_plane_configuration_digest"])
    policy(value["credential_policy"])
    request = value["request"]
    required = REQUEST_FIELDS | {"ttlSeconds"} if operation == OP_REQUEST else {
        "approvalOriginal", "issuedAtEpochNs", "expiresAtEpochNs"}
    require(type(request) is dict and set(request) == required)
    issued, expires = request["issuedAtEpochNs"], request["expiresAtEpochNs"]
    require(type(issued) is int and type(expires) is int and 0 < issued < expires <= 2**63 - 1
        and expires - issued <= 30_000_000_000)
    if operation == OP_REQUEST:
        retained = candidate(request["candidateOriginal"])
        require(retained["control_plane_configuration_digest"] == value["control_plane_configuration_digest"]
            and retained["credential_policy"] == value["credential_policy"]
            and retained["request"]["executionIssuedAtEpochNs"] <= issued
            and expires <= retained["request"]["expiresAtEpochNs"])
        require(value["approval_id"] is None and value["actor_id"] == retained["actor_id"]
            and type(request["ttlSeconds"]) is int and 1 <= request["ttlSeconds"] <= 3600)
        approval_request(retained)
    else:
        identifier(value["approval_id"])
        row = approval_row(request["approvalOriginal"])
        proof = provenance(row["approval_authn"])
        require(row["id"] == value["approval_id"] and value["actor_id"] != row["requester_id"]
            and value["decision"] in ("approve", "deny") and epoch(row["requested_at"]) <= issued
            and expires <= epoch(row["expires_at"])
            and proof["controlPlaneConfigurationDigest"] == value["control_plane_configuration_digest"]
            and proof["credentialPolicy"] == value["credential_policy"])
    original = {name: value[name] for name in fields}
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


def verify_request_context(operation, arguments_value, *, selected_policy, expected_configuration_digest, now_epoch_ns):
    selected = creation.validate_policy(selected_policy)
    digest(expected_configuration_digest)
    values = arguments(operation, arguments_value, typed="businessIntent" in arguments_value)
    request = values["request"]
    if operation == OP_REQUEST:
        intent = candidate(request["candidateOriginal"])["request"]
        require(creation.generation(intent["nativeGenerationOriginal"])["envelope"]["secret_kek_id"] == selected["nativeSecretKekId"])
    else:
        intent = json.loads(approval_row(request["approvalOriginal"])["request_json"])
    require(selected["twoPersonRequired"] is True
        and values["control_plane_configuration_digest"] == expected_configuration_digest
        and values["credential_policy"] == selected["credentialPolicy"]
        and intent["expiresAtEpochNs"] - intent["issuedAtEpochNs"] <= selected["intentMaxSeconds"] * 1_000_000_000
        and type(now_epoch_ns) is int and request["issuedAtEpochNs"] <= now_epoch_ns < request["expiresAtEpochNs"]
        <= request["issuedAtEpochNs"] + selected["operationMaxSeconds"] * 1_000_000_000,
        "Static approval lacks its current explicitly selected purpose and short execution interval")


def verify_original(operation, arguments_value, *, configuration_payload, root_key, now_epoch_ns):
    del root_key  # The caller independently verifies this configuration root.
    require(type(configuration_payload) is dict and FIELD in configuration_payload)
    from catchplate.authority_policy_canary_policy import full_configuration_digest
    verify_request_context(operation, arguments_value,
        selected_policy=configuration_payload[FIELD],
        expected_configuration_digest=full_configuration_digest(configuration_payload), now_epoch_ns=now_epoch_ns)
