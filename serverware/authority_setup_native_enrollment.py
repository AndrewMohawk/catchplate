"""Native issuer originals bound to a protected Setup successor, not CA install."""
import base64
from collections.abc import Mapping

from serverware import authority_setup_policy as candidate
from serverware import authority_oauth_setup as setup
from serverware import authority_publication_approval as hardware

canonical, require, digest, sha256 = setup.canonical, setup.require, setup.digest, setup.sha256
REQUEST = "setup.native-enrollment.request"
DECIDE = "setup.native-enrollment.decide"
PREPARE = "setup.native-enrollment.prepare"
COMPLETE = "setup.native-enrollment.complete"
OPERATIONS = frozenset({REQUEST, DECIDE, PREPARE, COMPLETE})
ASSERTION_OPERATIONS = OPERATIONS - {COMPLETE}
TABLE = "setup_native_enrollments"
SCHEMA = "serverware.setupNativeEnrollmentIntent/v1"
HTTP_SCHEMA = "serverware.setupNativeEnrollmentRequest/v1"
MAX_INTENT = 1200000
MAX_ARGUMENT_BYTES = 1400000
MAX_ROW_BYTES = 1500000
FIELDS = frozenset({"actor_id", "control_plane_configuration_digest", "credential_policy",
    "intent_original", "approval_id", "certificate_original"})
INTENT_FIELDS = frozenset({"apiVersion", "sessionId", "ownerId", "setupSha256", "continuationSha256",
    "assignmentSha256", "policyHash", "routePolicyDigest", "principalId", "credentialId",
    "credentialVersion", "issuerBootstrap", "authorization", "packet", "request",
    "issuedAtEpochNs", "expiresAtEpochNs"})
ROW_FIELDS = frozenset({"session_id", "revision", "phase", "owner_id", "intent_original",
    "intent_sha256", "approval_id", "approval_original", "prepare_request_digest",
    "certificate_original", "certificate_sha256", "association_original", "complete_request_digest",
    "configuration_digest", "created_at", "expires_at", "completed_at"})


def encoded(raw):
    require(type(raw) is bytes and raw)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def original(value, maximum):
    require(type(value) is str and 1 <= len(value) <= (maximum * 8 + 5) // 6 and value.isascii())
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except ValueError:
        raise ValueError("native Setup original encoding differs") from None
    require(1 <= len(raw) <= maximum and encoded(raw) == value)
    return raw


def intent(text):
    require(type(text) is str and text.isascii())
    value = setup.document(text.encode("ascii"), MAX_INTENT)
    require(set(value) == INTENT_FIELDS and value["apiVersion"] == SCHEMA)
    for field in ("setupSha256", "continuationSha256", "assignmentSha256", "policyHash", "routePolicyDigest"):
        digest(value[field])
    setup.identifier(value["sessionId"]); setup.identifier(value["credentialId"])
    setup.text(value["ownerId"], 1024); require(value["ownerId"].startswith("oidc:"))
    setup.text(value["principalId"], 1024)
    require(type(value["credentialVersion"]) is int and value["credentialVersion"] == 1)
    for field, limit in (("issuerBootstrap", 131072), ("authorization", 32768), ("packet", 524288), ("request", 65536)):
        original(value[field], limit)
    before, after = candidate.candidate.epoch(value["issuedAtEpochNs"]), candidate.candidate.epoch(value["expiresAtEpochNs"])
    require(0 < after - before <= 300_000_000_000)
    return value


def arguments(operation, value, *, typed=False):
    require(operation in OPERATIONS and isinstance(value, Mapping))
    allowed = FIELDS | ({"businessIntent", "authn_evidence"} if typed else set())
    require(FIELDS <= set(value) <= allowed and (not typed or "businessIntent" in value))
    setup.text(value["actor_id"], 1024); require(value["actor_id"].startswith("oidc:"))
    digest(value["control_plane_configuration_digest"])
    hardware.policy(value["credential_policy"])
    selected = intent(value["intent_original"])
    require((value["actor_id"] != selected["ownerId"]) if operation == DECIDE else (value["actor_id"] == selected["ownerId"]))
    if operation == REQUEST:
        require(value["approval_id"] is None)
    else:
        setup.identifier(value["approval_id"])
    if operation != COMPLETE:
        require(value["certificate_original"] is None)
    else:
        original(value["certificate_original"], 65536)
    result = {name: value[name] for name in FIELDS}
    require(len(canonical(result)) <= MAX_ARGUMENT_BYTES)
    return result


def binding_from_intent(text):
    # Data projection only: both independent roles admit the complete signed
    # originals before this deterministic kernel is invoked.
    import json
    selected = intent(text)
    grant = json.loads(original(selected["authorization"], 32768))["payload"]
    binding = {"action": "setup.native-enrollment.issue", "intentSha256": sha256(text.encode("ascii")),
        "sessionId": selected["sessionId"], "assignmentSha256": selected["assignmentSha256"],
        "authorizationSha256": sha256(original(selected["authorization"], 32768)),
        "requestSha256": sha256(original(selected["request"], 65536)),
        "issuerCertificateSha256": grant["issuerCertificateSha256"], "principalId": selected["principalId"]}
    return binding, selected["sessionId"], sha256(canonical(binding))


def association(intent_original, certificate_original):
    import json
    value = intent(intent_original)
    grant = json.loads(original(value["authorization"], 32768))["payload"]
    return {"schema": "serverware.workloadIdentityIssuerResponse/v1",
        "authorizationDigest": sha256(original(value["authorization"], 32768)),
        "requestDigest": sha256(original(value["request"], 65536)),
        "issuerCertificateDigest": grant["issuerCertificateSha256"],
        "certificateSha256": sha256(original(certificate_original, 65536)), "serialNumber": grant["serialNumber"]}


def row_original(row):
    require(type(row) is dict and set(row) == ROW_FIELDS)
    value = intent(row["intent_original"])
    require(row["session_id"] == value["sessionId"] and row["intent_sha256"] == sha256(row["intent_original"].encode("ascii"))
        and type(row["revision"]) is int and row["revision"] in (0, 1)
        and row["phase"] == ("issuance_unknown" if row["revision"] == 0 else "certificate_issued")
        and row["expires_at"] == value["expiresAtEpochNs"] and row["owner_id"] == value["ownerId"])
    for name in ("intent_sha256", "prepare_request_digest", "configuration_digest"):
        digest(row[name])
    setup.text(row["owner_id"], 1024); setup.text(row["approval_id"], 64)
    setup.document(row["approval_original"].encode("ascii"), 131072)
    setup.epoch(row["created_at"])
    if row["revision"] == 0:
        require(all(row[name] is None for name in ("certificate_original", "certificate_sha256", "association_original", "complete_request_digest", "completed_at")))
    else:
        require(sha256(original(row["certificate_original"], 65536)) == row["certificate_sha256"])
        require(row["association_original"] == canonical(association(row["intent_original"], row["certificate_original"])).decode("ascii"))
        digest(row["complete_request_digest"]); setup.epoch(row["completed_at"])
    raw = canonical(row); require(len(raw) <= MAX_ROW_BYTES)
    return raw


def request_digest(operation, values):
    from serverware import authority_contract as contract
    from serverware import authority_request_commitment as commitment
    values = arguments(operation, values, typed="businessIntent" in values)
    typed = {**values, "businessIntent": contract.synthesize_business_intent(operation, values)}
    return commitment.framed_digest("serverware.policyAuthorityV9Request/v1", canonical({
        "schema": "serverware.policyAuthorityV9Authorization/v1", "operation": operation,
        "handler": contract.operation_spec(operation)["handler"], "operationManifestDigest": contract.OPERATION_MANIFEST_DIGEST,
        "arguments": commitment._authorization_arguments(typed)}))
