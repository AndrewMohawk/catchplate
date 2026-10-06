"""Closed association of actual protected native history, not new readiness."""
from collections.abc import Mapping

from serverware import authority_setup_native_enrollment as enrollment
from serverware import authority_setup_native_ca as ca
from serverware import authority_policy_native_activation as activation

canonical, require, digest, sha256 = enrollment.canonical, enrollment.require, enrollment.digest, enrollment.sha256
RECORD = "setup.native-canary.record"
OPERATIONS = ASSERTION_OPERATIONS = frozenset({RECORD})
TABLE = "setup_native_canary_associations"
HTTP = "serverware.setupNativeCanaryRequest/v1"
REQUEST = "serverware.setupNativeCanaryAssociation/v1"
ROTATED_REQUEST = "serverware.setupNativeCanaryAssociation/v2"
OPTIONS = "serverware.setupNativeCanaryOptions/v1"
MAX_ARGUMENT_BYTES = 16384
FIELDS = frozenset({"actor_id", "control_plane_configuration_digest", "credential_policy", "request"})
REQUEST_FIELDS = frozenset({"apiVersion", "sessionId", "setupSha256", "continuationSha256", "enrollmentSha256",
    "installationSha256", "canaryId", "finalizationSha256", "publicationSha256", "policyHash", "activationPolicySha256",
    "credentialId", "credentialVersion", "enrollmentApprovalId", "nativeApprovalId", "auditIds", "issuedAtEpochNs", "expiresAtEpochNs"})
ROTATED_REQUEST_FIELDS = REQUEST_FIELDS | {"rotationAuditId"}
ROW_FIELDS = frozenset({"session_id", "revision", "phase", "owner_id", "setup_sha256", "continuation_sha256",
    "enrollment_sha256", "installation_sha256", "canary_id", "finalization_sha256", "publication_sha256", "policy_hash",
    "request_original", "request_digest", "configuration_digest", "audit_event_digest", "associated_at"})


def request(value):
    require(type(value) is dict)
    rotated = value.get("apiVersion") == ROTATED_REQUEST
    require(set(value) == (ROTATED_REQUEST_FIELDS if rotated else REQUEST_FIELDS)
        and value["apiVersion"] == (ROTATED_REQUEST if rotated else REQUEST))
    if rotated:
        enrollment.setup.identifier(value["rotationAuditId"])
    enrollment.setup.identifier(value["sessionId"]); enrollment.setup.text(value["canaryId"], 256)
    enrollment.setup.identifier(value["credentialId"])
    enrollment.setup.identifier(value["enrollmentApprovalId"]); enrollment.setup.identifier(value["nativeApprovalId"])
    require(type(value["credentialVersion"]) is int and (2 <= value["credentialVersion"] <= 2**63-1
        if value["apiVersion"] == ROTATED_REQUEST else value["credentialVersion"] == 1))
    for name in REQUEST_FIELDS - {"apiVersion", "sessionId", "canaryId", "credentialId", "credentialVersion", "enrollmentApprovalId", "nativeApprovalId", "auditIds", "issuedAtEpochNs", "expiresAtEpochNs"}:
        digest(value[name])
    audits = value["auditIds"]
    require(type(audits) is list and len(audits) == 9 and audits == sorted(set(audits)))
    for identity in audits:
        enrollment.setup.identifier(identity)
    before, after = value["issuedAtEpochNs"], value["expiresAtEpochNs"]
    require(type(before) is int and type(after) is int and 0 < before < after <= 2**63 - 1
        and after - before <= 30_000_000_000 and len(canonical(value)) <= 8192)
    return value


def arguments(operation, value, *, typed=False):
    require(operation == RECORD and isinstance(value, Mapping))
    allowed = FIELDS | ({"businessIntent", "authn_evidence"} if typed else set())
    require(FIELDS <= set(value) <= allowed and (not typed or "businessIntent" in value))
    enrollment.setup.text(value["actor_id"], 1024); require(value["actor_id"].startswith("oidc:"))
    digest(value["control_plane_configuration_digest"]); enrollment.hardware.policy(value["credential_policy"])
    request(value["request"])
    result = {name: value[name] for name in FIELDS}
    require(len(canonical(result)) <= MAX_ARGUMENT_BYTES)
    return result


def verify_original(operation, value, *, configuration_payload, root_key, now_epoch_ns):
    """Independently select the existing cold purposes; no uploaded verdict."""
    values = arguments(operation, value, typed="businessIntent" in value)
    from serverware import authority_policy_canary_policy as configuration
    require(values["control_plane_configuration_digest"] == configuration.full_configuration_digest(configuration_payload)
        and values["request"]["issuedAtEpochNs"] <= now_epoch_ns < values["request"]["expiresAtEpochNs"])
    ca_policy = ca.validate_policy(configuration_payload.get(ca.FIELD), payload=configuration_payload, root_key=root_key)
    active = activation.validate_policy(configuration_payload.get(activation.FIELD), payload=configuration_payload, root_key=root_key)
    require(ca_policy is not None and active is not None and ca_policy["credentialPolicy"] == values["credential_policy"]
        and sha256(canonical(active)) == values["request"]["activationPolicySha256"])
    # Old effect intervals are not renewed. The kernel checks authentic stored
    # completed effects and current roots; this operation only records history.


def audit_ids(enrolled, installed, final):
    from serverware import authority_transition_quota as q
    retained = activation.completed_audit_originals(final["audit_originals_json"])
    require(type(retained) is list and len(retained) == 4)
    identities = [row["id"] for row in retained] + [final["audit_outbox_id"]]
    identities.extend(q._audit_identity(operation, row[field]) for operation, row, field in (
        (enrollment.PREPARE, enrolled, "prepare_request_digest"), (enrollment.COMPLETE, enrolled, "complete_request_digest"),
        (ca.PREPARE, installed, "prepare_request_digest"), (ca.COMPLETE, installed, "complete_request_digest")))
    require(len(set(identities)) == 9)
    return sorted(identities)


def row_original(value):
    require(type(value) is dict and set(value) == ROW_FIELDS and type(value["revision"]) is int and value["revision"] == 0
        and value["phase"] == "canary_publication_associated")
    args = arguments(RECORD, enrollment.setup.document(value["request_original"].encode("ascii"), MAX_ARGUMENT_BYTES))
    r = args["request"]
    require(value["owner_id"] == args["actor_id"] and value["configuration_digest"] == args["control_plane_configuration_digest"])
    for name, field in (("session_id", "sessionId"), ("setup_sha256", "setupSha256"), ("continuation_sha256", "continuationSha256"),
            ("enrollment_sha256", "enrollmentSha256"), ("installation_sha256", "installationSha256"), ("canary_id", "canaryId"),
            ("finalization_sha256", "finalizationSha256"), ("publication_sha256", "publicationSha256"), ("policy_hash", "policyHash")):
        require(value[name] == r[field])
    digest(value["request_digest"]); digest(value["audit_event_digest"])
    require(r["issuedAtEpochNs"] <= enrollment.setup.epoch(value["associated_at"]) < r["expiresAtEpochNs"])
    raw = canonical(value); require(len(raw) <= 32768); return raw


def public(row):
    if row is None:
        return None
    row_original(row)
    return {"revision": row["revision"], "phase": row["phase"], "canaryId": row["canary_id"], "policyHash": row["policy_hash"],
        "finalizationSha256": row["finalization_sha256"], "publicationSha256": row["publication_sha256"],
        "requestDigest": row["request_digest"], "associatedAtEpochNs": enrollment.setup.epoch(row["associated_at"])}


def request_digest(operation, value):
    from serverware import authority_contract as contract, authority_request_commitment as commitment
    values = arguments(operation, value, typed="businessIntent" in value)
    typed = {**values, "businessIntent": contract.synthesize_business_intent(operation, values)}
    return commitment.framed_digest("serverware.policyAuthorityV9Request/v1", canonical({"schema": "serverware.policyAuthorityV9Authorization/v1",
        "operation": operation, "handler": contract.operation_spec(operation)["handler"], "operationManifestDigest": contract.OPERATION_MANIFEST_DIGEST,
        "arguments": commitment._authorization_arguments(typed)}))
