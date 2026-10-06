"""Purpose-fixed public review of a retained static credential rotation candidate.

The candidate's old execution interval is descriptive, never authorization for
requesting or deciding approval. Each operation has its own short original
interval and hardware assertion. These formats neither seal a secret nor
authenticate native custody; rotation independently verifies that custody.
"""
import json
from datetime import datetime, timezone

from serverware import authority_static_credential_rotate as rotation

canonical, require, digest, sha256 = rotation.canonical, rotation.require, rotation.digest, rotation.sha256
identifier, policy = rotation.identifier, rotation.policy
OP_REQUEST = "credential.static.rotation-approval-request"
OP_DECIDE = "credential.static.rotation-approval-decide"
OPERATIONS = ASSERTION_OPERATIONS = frozenset({OP_REQUEST, OP_DECIDE})
FIELD = rotation.FIELD
MAX_ARGUMENT_BYTES = rotation.MAX_ARGUMENT_BYTES
MAX_REVIEW_BYTES = 1024 * 1024
HTTP_SCHEMA = "serverware.staticCredentialRotationApprovalRequest/v1"
OPTIONS_SCHEMA = "serverware.staticCredentialRotationApprovalOptions/v1"
MFA_FIELD = "staticCredentialRotationApprovalProfile"
REVIEW_SCHEMA = "serverware.staticCredentialRotationReview/v1"
PROVENANCE_SCHEMA = "serverware.staticCredentialRotationApprovalProvenance/v1"
FIELDS = rotation.FIELDS
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
    require(type(value) is dict and set(value) == rotation.FIELDS
        and value["approval_id"] is None and canonical(value) == raw,
        "Static rotation approval requires the exact original unapproved candidate")
    rotation.arguments(rotation.OPERATION, value, candidate=True)
    return value


def approval_request(values, *, candidate=False):
    """One exact compact review shared by request, decision and consumption."""
    values = rotation.arguments(rotation.OPERATION, values, typed="businessIntent" in values, candidate=candidate)
    request = values["request"]
    native = rotation.generation(request["nativeGenerationOriginal"])
    document = {"apiVersion": REVIEW_SCHEMA,
        **{name: request[name] for name in rotation.INTENT_FIELDS - {"previousProvenanceOriginal"}},
        "previousProvenanceSha256": sha256(request["previousProvenanceOriginal"].encode("ascii")),
        "intentSha256": native["intentSha256"],
        "nativeGenerationSha256": sha256(request["nativeGenerationOriginal"].encode("ascii")),
        "candidateSha256": rotation.approval_payload_digest(values, candidate=candidate)}
    raw = canonical(document)
    require(len(raw) <= MAX_REVIEW_BYTES, "Static rotation approval review exceeds the existing request bound")
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


def _review_intent(review):
    """Validate compact public review without inventing an omitted provenance."""
    identifier(review["credentialId"])
    previous, current = review["previousCredentialVersion"], review["credentialVersion"]
    require(type(previous) is int and type(current) is int and 1 <= previous < current <= 2**63 - 1
        and current == previous + 1 and type(review["kind"]) is str and review["kind"] in rotation.KINDS
        and type(review["name"]) is str)
    review["name"].encode("utf-8", errors="strict")
    rotation.metadata(review["metadata"])
    require(review["metadata"].get("oauth") is not True)
    for name in ("previousCredentialSha256", "previousCurrentnessOriginRequestDigest", "previousProvenanceSha256"):
        digest(review[name])
    issued, expires = review["issuedAtEpochNs"], review["expiresAtEpochNs"]
    require(type(issued) is int and type(expires) is int and 0 < issued < expires <= 2**63 - 1
        and expires - issued <= rotation.MAX_RETAINED_INTENT_SECONDS * 1_000_000_000)


def approval_row(original):
    """Exact public storage row, not the lossy collection presentation."""
    require(type(original) is str and 0 < len(original.encode("ascii")) <= MAX_ARGUMENT_BYTES)
    value = json.loads(original, parse_constant=lambda _: require(False))
    require(type(value) is dict and set(value) == ROW_FIELDS and canonical(value).decode("ascii") == original)
    identifier(value["id"]); identifier(value["resource_id"])
    rotation._actor(value["requester_id"])
    require(value["action"] == rotation.ACTION and value["status"] == "pending"
        and all(value[name] is None for name in ("approved_by", "approved_at", "consumed_by", "consumed_at",
            "decision_note", "approver_webauthn_credential_id")))
    review_original = value["request_json"]
    require(type(review_original) is str and 0 < len(review_original.encode("ascii")) <= MAX_REVIEW_BYTES)
    review = json.loads(review_original, parse_constant=lambda _: require(False))
    require(type(review) is dict and set(review) == (rotation.INTENT_FIELDS - {"previousProvenanceOriginal"}) | {
        "apiVersion", "previousProvenanceSha256", "intentSha256", "nativeGenerationSha256", "candidateSha256"}
        and review["apiVersion"] == REVIEW_SCHEMA and canonical(review).decode("ascii") == review_original)
    _review_intent(review)
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
    rotation._actor(value["actor_id"])
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
        approval_request(retained, candidate=True)
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
    from serverware import authority_contract as contract
    from serverware import authority_request_commitment as commitment

    values = arguments(operation, value, typed="businessIntent" in value)
    typed = {**values, "businessIntent": contract.synthesize_business_intent(operation, values)}
    return commitment.framed_digest("serverware.policyAuthorityV9Request/v1", canonical({
        "schema": "serverware.policyAuthorityV9Authorization/v1", "operation": operation,
        "handler": contract.operation_spec(operation)["handler"],
        "operationManifestDigest": contract.OPERATION_MANIFEST_DIGEST,
        "arguments": commitment._authorization_arguments(typed)}))


def verify_request_context(operation, arguments_value, *, selected_policy, expected_configuration_digest, now_epoch_ns):
    selected = rotation.validate_policy(selected_policy)
    digest(expected_configuration_digest)
    values = arguments(operation, arguments_value, typed="businessIntent" in arguments_value)
    request = values["request"]
    if operation == OP_REQUEST:
        intent = candidate(request["candidateOriginal"])["request"]
        require(rotation.generation(intent["nativeGenerationOriginal"])["envelope"]["secret_kek_id"] == selected["nativeSecretKekId"])
    else:
        intent = json.loads(approval_row(request["approvalOriginal"])["request_json"])
    require(selected["twoPersonRequired"] is True
        and values["control_plane_configuration_digest"] == expected_configuration_digest
        and values["credential_policy"] == selected["credentialPolicy"]
        and intent["expiresAtEpochNs"] - intent["issuedAtEpochNs"] <= selected["intentMaxSeconds"] * 1_000_000_000
        and type(now_epoch_ns) is int and request["issuedAtEpochNs"] <= now_epoch_ns < request["expiresAtEpochNs"]
        <= request["issuedAtEpochNs"] + selected["operationMaxSeconds"] * 1_000_000_000,
        "Static rotation approval lacks its current explicitly selected purpose and short execution interval")


def verify_original(operation, arguments_value, *, configuration_payload, root_key, now_epoch_ns):
    del root_key  # The caller independently verifies this configuration root.
    require(type(configuration_payload) is dict and FIELD in configuration_payload)
    from serverware.authority_policy_canary_policy import full_configuration_digest
    verify_request_context(operation, arguments_value,
        selected_policy=configuration_payload[FIELD],
        expected_configuration_digest=full_configuration_digest(configuration_payload), now_epoch_ns=now_epoch_ns)
