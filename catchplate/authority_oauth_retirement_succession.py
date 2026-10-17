"""Closed retired-scope succession originals; data is never reopening authority.

Old retirement fences, contact attempts and currentness roots are immutable
predecessors. Only the independently admitted new purpose can name a fresh
candidate and consume its real distinct-person approval into a new generation.
"""
from collections.abc import Mapping
import uuid

from catchplate import authority_oauth_activation as activation
from catchplate import authority_oauth_refresh as refresh
from catchplate import authority_oauth_measured_exchange as issuance
from catchplate import authority_oauth_measured_pending_retirement as scalar
from catchplate import native_oauth_exchange as material
from catchplate import native_oauth_refresh as common
from catchplate import authority_oauth_retirement_succession_catalog as catalog

canonical, require, digest, sha256 = common.canonical, common.require, common.digest, common.sha
document, encoded, decoded = common.document, common.encoded, common.decoded
GRANT_SCHEMA = "catchplate.oauthRetiredScopeSuccessionAuthorization/v1"
SIGNED_GRANT_SCHEMA = "catchplate.signedOAuthRetiredScopeSuccessionAuthorization/v1"
PURPOSE = "measured-oauth-retired-scope-succession"
ACTION = "credential.oauth.retirement-succession"
NATIVE_ACTION = "credential.oauth.measured-succession"
OPTIONS_SCHEMA = "catchplate.oauthRetiredScopeSuccessionOptions/v1"
PROVENANCE_SCHEMA = "catchplate.oauthRetiredScopeSuccessionApproval/v1"
STATEMENT = "catchplate.nativeOAuthSuccessionStatement/v1"
SIGN_OPERATION = "nativeOAuthRetiredScopeSuccession.sign/v1"
SIGNATURE_DOMAIN = STATEMENT.encode("ascii") + b"\0"
ATTESTATION_DOMAIN = b"catchplate/native-oauth-retired-scope-succession-attestation/v1\0"
HTTP_SCHEMA = "catchplate.nativeOAuthSuccessionRequest/v1"
HTTP_RESPONSE = "catchplate.nativeOAuthSuccessionResponse/v1"
RUNTIME_RESPONSE = "catchplate.policyAuthorityRetiredScopeSuccessionRuntimeResponse/v1"
HTTP_PATH = "/api/data-plane/oauth-succession"
HUMAN_PREFIX = "/api/oauth/succession"
INTENT_SCHEMA = "catchplate.nativeOAuthSuccessionIntent/v1"
STATE_SCHEMA = "catchplate.nativeOAuthSuccessionState/v1"
REDIRECT_SCHEMA = "catchplate.nativeOAuthSuccessionAuthorizationRedirect/v1"
RECOVERY_REQUEST = "catchplate.nativeOAuthSuccessionRecoveryOriginalRequest/v1"
RECOVERY_RESPONSE = "catchplate.nativeOAuthSuccessionRecoveryOriginalResponse/v1"
NATIVE_CONFIGURATION = "catchplate.nativeOAuthSuccessionConfiguration/v1"
# Native follow-on producer contract, not a constructor of native authority.
# The actual helper must independently admit these cold originals and retained
# purpose/key/KEK/TLS owners; the control plane never supplies a live owner.
CONFIGURATION_FIELDS = frozenset({"apiVersion", "sourceRevision", "authorityRootPublicKey", "authorityRootSpkiSha256",
    "authorityConfigurationOriginal", "controlPlaneConfigurationDigest", "deploymentId", "instanceId", "limits",
    "successionLimits", "windows", "applications", "historicalApplications", "recoveryTargets", "callbackOrigin", "portalOrigin", "browserVsockPort"})
HISTORICAL_APPLICATION_FIELDS = frozenset({"enrollmentSha256", "enrollmentRootSpkiSha256", "application"})
STATE_FIELDS = material.STATE_FIELDS | {"successionBinding"}
MAX_NATIVE_CONFIGURATION = 2 * 1024 * 1024

OP_AUTHORIZE = "oauth.succession.authorize"
OP_AUTHORIZE_DECIDE = "oauth.succession.decide"
OP_FENCE = "oauth.succession.fence"
OP_REQUEST = "oauth.succession.activation-request"
OP_DECIDE = "oauth.succession.activation-decide"
OP_ACTIVATE = "oauth.succession.activate"
OP_INSPECT = "oauth.measured-succession.inspect"
OP_MATERIAL = "oauth.measured-succession.material-claim"
OP_CONTACT = "oauth.measured-succession.contact"
OP_FINISH = "oauth.measured-succession.finish"
OP_RECOVER = "oauth.measured-succession.recover"
OP_PREPARE = "oauth.measured-succession.prepare"
OP_CLAIM = "oauth.measured-succession.claim"
OP_CAPTURE = "oauth.measured-succession.capture"
OP_STAGE = "oauth.measured-succession.stage"
OP_CANCEL = "oauth.measured-succession.cancel"
# Closed acquisition programs, not an incoming table selector. Every part is
# independently complete; FENCE later compares all 28 original current roots.
SNAPSHOT_PARTS = catalog.SNAPSHOT_PARTS
SNAPSHOT_OPERATIONS = {"oauth.succession.snapshot." + part: part for part in SNAPSHOT_PARTS}
SNAPSHOT_TABLE = "oauth_retirement_succession_snapshots"
FRESH_OPERATIONS = frozenset({OP_PREPARE, OP_CLAIM, OP_CAPTURE, OP_STAGE, OP_CANCEL})
MATERIAL_OPERATIONS = frozenset({OP_INSPECT, OP_MATERIAL, OP_CONTACT, OP_FINISH})
NATIVE_OPERATIONS = FRESH_OPERATIONS | MATERIAL_OPERATIONS | {OP_RECOVER}
ASSERTION_OPERATIONS = frozenset({OP_AUTHORIZE, OP_AUTHORIZE_DECIDE, OP_REQUEST, OP_DECIDE, OP_ACTIVATE})
OPERATIONS = NATIVE_OPERATIONS | ASSERTION_OPERATIONS | {OP_FENCE} | SNAPSHOT_OPERATIONS.keys()

HEAD_TABLE = "oauth_retirement_scope_heads"
SCOPE_TABLE = "oauth_retirement_scopes"
JOURNAL_TABLE = "oauth_retirement_successions"
TABLE = "oauth_measured_succession_custody"
MATERIAL_TABLE = "oauth_retirement_succession_materials"
ATTEMPT_TABLE = "oauth_retirement_succession_attempts"
ASSOCIATION_TABLE = "oauth_retirement_successor_generations"
MAX_MATERIALS, MAX_AFFECTED_LINEAGES, MAX_POPULATION, MAX_HISTORY = 16, 7, 16, 64
MAX_GRANT_BYTES, MAX_ARGUMENT_BYTES, MAX_ROW_BYTES = 128 * 1024, 2 * 1024 * 1024, 4 * 1024 * 1024
MAX_HTTP_REQUEST, MAX_HTTP_RESPONSE, MAX_CANDIDATE_BYTES = 3 * 1024 * 1024, 8 * 1024 * 1024, 512 * 1024
# Separate exact-original ceilings leave room for base64url request/response,
# the 128 KiB grant and target metadata inside one complete 8 MiB handoff.
# The kernel result ceiling is checked before any protected mutation commits.
MAX_KERNEL_RESULT = 1024 * 1024
MAX_RUNTIME_RESPONSE = 11 * 1024 * 1024 // 4
MAX_TRANSPORT_BYTES = 384 * 1024
LIMITS = {"materialCapacity": MAX_MATERIALS, "affectedLineageCapacity": MAX_AFFECTED_LINEAGES,
    "populationCapacity": MAX_POPULATION, "historyCapacity": MAX_HISTORY, "authorizationMaxSeconds": 3600}

SOURCE_KINDS = frozenset({"initial-capture", "setup-capture", "reconnect-capture", "succession-capture", "initial-pending",
    "setup-pending", "reconnect-candidate", "succession-candidate", "refresh-issued", "refresh-superseded", "credential-current"})
PREDECESSOR_KINDS = frozenset({"refresh-family", "pending-family", "provider-capture", "reconnect-fence", "succession"})
PREDECESSOR_FIELDS = frozenset({"kind", "id", "rowSha256", "journalSha256"})
MATERIAL_PIN_FIELDS = frozenset({"materialId", "sourceKind", "sourceId", "sourceVersion", "sourceRowSha256", "custodyRowSha256",
    "tokenSecretSha256", "tokenEnvelopeSha256", "enrollmentSha256", "tokenPurposes"})
LINEAGE_FIELDS = scalar.LINEAGE_FIELDS | {"predecessorKind", "predecessorId", "predecessorSha256"}
GRANT_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "authorizationId", "configurationDigest", "deploymentId",
    "providerId", "scope", "predecessors", "previousHeadSha256", "credentialId", "credentialVersion", "credentialRowSha256",
    "generationRowSha256", "providerSubject", "providerAccount", "clientId", "enrollmentSha256", "requesterId", "scopes",
    "metadataSha256", "affectedLineages", "materials", "exchangeOrigins", "inventoryRoots", "issuedAtEpochNs", "admissionExpiresAtEpochNs", "contactExpiresAtEpochNs",
    "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs", "expiresAtEpochNs"})
HUMAN_FIELDS = activation.FIELDS | {"authorization_original"}
FIELDS = issuance.FIELDS | {"authorization_original"}
STATEMENT_FIELDS = issuance.STATEMENT_FIELDS | {"authorizationSha256", "scopeRowSha256", "materialId"}
BINDING_FIELDS = frozenset({"authorizationSha256", "scopeRowSha256", "materialClosureSha256", "credentialId",
    "credentialVersion", "providerSubject", "providerAccount", "expiresAtEpochNs"})
INTENT_FIELDS = material.INTENT_FIELDS | {"authorizationOriginal", "scopeRequestOriginal", "scopeResponseOriginal"}
REQUEST_FIELDS = {
    **{operation: frozenset({"authorizationRowSha256"}) for operation in SNAPSHOT_OPERATIONS},
    OP_AUTHORIZE: frozenset({"authorizationSha256", "credentialId", "credentialVersion"}),
    OP_AUTHORIZE_DECIDE: frozenset({"authorizationSha256", "authorizationRowSha256"}),
    OP_FENCE: frozenset({"authorizationRowSha256", "currentnessBarriers", "issuedAtEpochNs", "expiresAtEpochNs"}),
    OP_INSPECT: frozenset({"scopeRowSha256", "materialId", "issuedAtEpochNs", "expiresAtEpochNs"}),
    OP_MATERIAL: frozenset({"scopeRowSha256", "materialId", "materialOriginalSha256", "ownerNonceSha256"}),
    OP_CONTACT: frozenset({"scopeRowSha256", "materialId", "materialRowSha256", "ownerNonce", "tokenPurpose", "contactRequestSha256"}),
    OP_FINISH: frozenset({"scopeRowSha256", "materialId", "attemptRowSha256", "ownerNonce", "tokenPurpose", "transportOriginal"}),
    OP_RECOVER: frozenset({"scopeRowSha256", "materialId", "custodyRowSha256", "issuedAtEpochNs", "expiresAtEpochNs"}),
    **{operation: issuance.REQUEST_FIELDS["oauth.measured-exchange." + operation.rsplit(".", 1)[1]] | {"scopeRowSha256"}
       for operation in FRESH_OPERATIONS},
    **{operation: frozenset({"authorizationSha256", "candidateSha256"}) for operation in (OP_REQUEST, OP_DECIDE, OP_ACTIVATE)},
}


def identifier(value):
    require(type(value) is str and str(uuid.UUID(value)) == value)
    return value


def head_id(provider):
    require(provider in {"google", "x"})
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "catchplate.oauthRetiredScopeHead/v1:" + provider))


def snapshot_id(authorization_id, part):
    identifier(authorization_id); require(part in SNAPSHOT_PARTS)
    return str(uuid.uuid5(uuid.UUID(authorization_id), "catchplate.oauthRetiredScopeSnapshot/v1:" + part))


def snapshot_limit(part):
    require(part in SNAPSHOT_PARTS)
    return MAX_POPULATION if part in {"credentials", "pending", "setup", "exchanges", "refreshes", "work"} else 32 if part in {"family-fences", "pending-fences"} else MAX_HISTORY


def inventory_roots(values):
    require(type(values) is list and [item.get("part") for item in values if type(item) is dict] == sorted(SNAPSHOT_PARTS))
    for item in values:
        require(type(item) is dict and set(item) == {"part", "root"})
        root = item["root"]
        require(type(root) is dict and set(root) == {"table", "rootRevision", "rootDigest", "leafCount"}
            and root["table"] == SNAPSHOT_PARTS[item["part"]])
        require(type(root["rootRevision"]) is int and 0 <= root["rootRevision"] <= 2**63 - 1
            and type(root["leafCount"]) is int and 0 <= root["leafCount"] <= snapshot_limit(item["part"]))
        digest(root["rootDigest"])
    return values


def material_id(kind, source_id, version):
    require(kind in SOURCE_KINDS); identifier(source_id)
    refresh._version(version)
    return str(uuid.uuid5(uuid.UUID(source_id), "catchplate.oauthRetiredMaterial/v1:" + kind + ":" + str(version)))


def attempt_id(item, purpose):
    identifier(item); require(purpose in {"access", "refresh"})
    return str(uuid.uuid5(uuid.UUID(item), "catchplate.oauthRetiredMaterialContact/v1:" + purpose))


def material_claim_id(authorization_id, material_id):
    identifier(authorization_id); identifier(material_id)
    return str(uuid.uuid5(uuid.UUID(authorization_id), "catchplate.oauthRetiredMaterialClaim/v1:" + material_id))


def association_id(credential_id, version):
    identifier(credential_id); refresh._version(version)
    return str(uuid.uuid5(uuid.UUID(credential_id), "catchplate.oauthRetirementSuccessor/v1:" + str(version)))


def lineages(values):
    require(type(values) is list and 1 <= len(values) <= MAX_AFFECTED_LINEAGES)
    order = []
    for value in values:
        require(type(value) is dict and set(value) == LINEAGE_FIELDS)
        scalar.lineages([{name: value[name] for name in scalar.LINEAGE_FIELDS}])
        require(value["predecessorKind"] in PREDECESSOR_KINDS | {"active"})
        if value["predecessorKind"] == "active":
            require(value["predecessorId"] is None and value["predecessorSha256"] is None)
        else:
            identifier(value["predecessorId"]); digest(value["predecessorSha256"])
        order.append(value["credentialId"])
    require(order == sorted(set(order)))
    return values


def materials(values):
    require(type(values) is list and len(values) <= MAX_MATERIALS)
    order = []
    for value in values:
        require(type(value) is dict and set(value) == MATERIAL_PIN_FIELDS
            and value["materialId"] == material_id(value["sourceKind"], value["sourceId"], value["sourceVersion"]))
        for name in ("sourceRowSha256", "tokenEnvelopeSha256", "enrollmentSha256"):
            digest(value[name])
        if value["tokenSecretSha256"] is None:
            require(value["sourceKind"] == "credential-current")
        else:
            digest(value["tokenSecretSha256"])
        if value["sourceKind"] not in {"credential-current", "reconnect-candidate", "succession-candidate"}:
            require(value["sourceVersion"] == 1)
        if value["custodyRowSha256"] is not None:
            digest(value["custodyRowSha256"])
        require(type(value["tokenPurposes"]) is list and value["tokenPurposes"] in [["access"], ["refresh"], ["access", "refresh"]])
        order.append(value["materialId"])
    require(order == sorted(set(order)))
    return values


def payload(value):
    require(type(value) is dict and set(value) == GRANT_FIELDS and value["schema"] == GRANT_SCHEMA
        and value["purpose"] == PURPOSE and value["providerId"] in {"google", "x"})
    identifier(value["authorizationId"]); identifier(value["credentialId"])
    refresh._version(value["credentialVersion"]); require(value["credentialVersion"] < 2**63 - 1)
    for name in ("configurationDigest", "credentialRowSha256", "generationRowSha256", "enrollmentSha256", "metadataSha256"):
        digest(value[name]); require(value[name] != "sha256:" + "0" * 64)
    if value["previousHeadSha256"] is not None:
        digest(value["previousHeadSha256"])
    for name, maximum in (("sourceRevision", 128), ("deploymentId", 128), ("providerSubject", 512),
            ("providerAccount", 512), ("clientId", 2048), ("requesterId", 512)):
        material.text(value[name], maximum)
    require(value["requesterId"].startswith("oidc:"))
    require(type(value["scopes"]) is list and value["scopes"] == sorted(set(value["scopes"])))
    common.scopes(" ".join(value["scopes"]))
    scope = value["scope"]
    require(type(scope) is dict and set(scope) == {"kind", "providerId", "providerSubject", "externalImpactAuthorized"}
        and scope["kind"] in {"family", "provider"} and scope["providerId"] == value["providerId"]
        and scope["externalImpactAuthorized"] is True
        and scope["providerSubject"] == (value["providerSubject"] if scope["kind"] == "family" else None))
    predecessors = value["predecessors"]
    require(type(predecessors) is list and 1 <= len(predecessors) <= MAX_AFFECTED_LINEAGES + 3)
    order = []
    for predecessor in predecessors:
        require(type(predecessor) is dict and set(predecessor) == PREDECESSOR_FIELDS and predecessor["kind"] in PREDECESSOR_KINDS)
        identifier(predecessor["id"]); digest(predecessor["rowSha256"]); digest(predecessor["journalSha256"])
        order.append((predecessor["kind"], predecessor["id"]))
    require(order == sorted(set(order)))
    if any(item["kind"] == "provider-capture" for item in predecessors):
        require(scope["kind"] == "provider", "a provider retirement cannot be narrowed by a family-only successor grant")
    members = lineages(value["affectedLineages"]); materials(value["materials"]); inventory_roots(value["inventoryRoots"])
    origins = value["exchangeOrigins"]
    require(type(origins) is list and len(origins) <= MAX_POPULATION)
    order = []
    for entry in origins:
        require(type(entry) is dict and set(entry) == {"exchangeId", "sourceKind", "custodyRowSha256"}
            and entry["sourceKind"] in {"initial", "setup", "reconnect", "succession"})
        identifier(entry["exchangeId"]); digest(entry["custodyRowSha256"]); order.append(entry["exchangeId"])
    require(order == sorted(set(order)))
    target = [entry for entry in members if entry["credentialId"] == value["credentialId"]]
    require(len(target) == 1 and all(target[0][name] == value[name]
        for name in ("credentialVersion", "credentialRowSha256", "generationRowSha256")))
    if value["providerId"] == "google":
        require(all(len(item["tokenPurposes"]) == 1 for item in value["materials"]))
    for name in ("issuedAtEpochNs", "admissionExpiresAtEpochNs", "contactExpiresAtEpochNs", "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs", "expiresAtEpochNs"):
        common.integer(value[name])
    start, contact, retained, pending, end = (value[name] for name in
        ("issuedAtEpochNs", "contactExpiresAtEpochNs", "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs", "expiresAtEpochNs"))
    require(start < contact <= retained <= pending <= end <= start + 3600_000_000_000
        and contact - start <= 600_000_000_000 and retained - contact <= 600_000_000_000)
    require(start < value["admissionExpiresAtEpochNs"] <= contact)
    require(len(canonical(value)) <= MAX_GRANT_BYTES - 512)
    return value


def grant_document(raw):
    value = document(raw, MAX_GRANT_BYTES)
    require(set(value) == {"schema", "payload", "signatureBase64Url"} and value["schema"] == SIGNED_GRANT_SCHEMA)
    payload(value["payload"]); decoded(value["signatureBase64Url"], 64, 64)
    return value


def sign_authorization(value, signing_key):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from catchplate import authority_contract
    require(isinstance(signing_key, Ed25519PrivateKey) and value["sourceRevision"] == authority_contract.SOURCE_REVISION)
    raw = canonical(payload(value))
    return canonical({"schema": SIGNED_GRANT_SCHEMA, "payload": value,
        "signatureBase64Url": encoded(signing_key.sign(GRANT_SCHEMA.encode("ascii") + b"\0" + raw))})


def binding(value):
    require(type(value) is dict and set(value) == BINDING_FIELDS)
    for name in ("authorizationSha256", "scopeRowSha256", "materialClosureSha256"):
        digest(value[name])
    identifier(value["credentialId"]); refresh._version(value["credentialVersion"])
    require(value["credentialVersion"] < 2**63 - 1)
    material.text(value["providerSubject"], 512); material.text(value["providerAccount"], 512)
    common.integer(value["expiresAtEpochNs"])
    return value


def intent(value):
    require(type(value) is dict and set(value) == INTENT_FIELDS and value["schema"] == INTENT_SCHEMA
        and len(canonical(value)) <= MAX_HTTP_RESPONSE)
    grant = grant_document(decoded(value["authorizationOriginal"], MAX_GRANT_BYTES))["payload"]
    require(value["providerId"] == grant["providerId"] and value["requesterId"] == grant["requesterId"]
        and value["scopes"] == grant["scopes"] and type(value["metadata"]) is dict
        and sha256(canonical(value["metadata"])) == grant["metadataSha256"])
    activation.policy(value["credentialPolicy"]); material.text(value["credentialName"], 256)
    decoded(value["scopeRequestOriginal"], MAX_HTTP_REQUEST); decoded(value["scopeResponseOriginal"], MAX_RUNTIME_RESPONSE)
    return value


def request_binding(operation, value, grant):
    require(operation in OPERATIONS and type(value) is dict and set(value) == REQUEST_FIELDS[operation])
    if operation in NATIVE_OPERATIONS:
        digest(value["scopeRowSha256"])
    if operation in FRESH_OPERATIONS:
        projected = {name: item for name, item in value.items() if name != "scopeRowSha256"}
        if operation == OP_STAGE:
            identifier(value["exchangeId"]); issuance.limits(value["limits"]); decoded(value["ownerNonce"], 32, 32)
            for name in ("exchangeRowSha256", "tokenSecretSha256", "identityRawSha256", "payloadDigest"):
                digest(value[name])
            refresh.envelope(value["tokenEnvelope"], grant["credentialVersion"] + 1)
            issuance.legacy.envelope(value["identityRawEnvelope"])
            require(type(value["metadata"]) is dict and type(value["review"]) is dict
                and len(canonical(value["metadata"])) <= 32768 and len(canonical(value["review"])) <= 16384)
            require(value["recoveryRequestDigest"] is None, "observation-only recovery cannot authorize staging")
        else:
            issuance.request_binding("oauth.measured-exchange." + operation.rsplit(".", 1)[1], projected)
        require(value["exchangeId"] == grant["authorizationId"])
        if operation == OP_PREPARE:
            require(value["providerId"] == grant["providerId"] and value["enrollmentSha256"] == grant["enrollmentSha256"]
                and value["scopes"] == grant["scopes"] and all(value[name] == grant[name]
                    for name in ("contactExpiresAtEpochNs", "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs")))
    elif operation in MATERIAL_OPERATIONS | {OP_RECOVER}:
        item = value["materialId"]
        require(item is None and operation == OP_RECOVER or item in {pin["materialId"] for pin in grant["materials"]})
        for name in ("materialOriginalSha256", "materialRowSha256", "ownerNonceSha256", "contactRequestSha256", "attemptRowSha256"):
            if name in value:
                digest(value[name])
        if "ownerNonce" in value:
            decoded(value["ownerNonce"], 32, 32)
        if "tokenPurpose" in value:
            pin = next(pin for pin in grant["materials"] if pin["materialId"] == item)
            require(value["tokenPurpose"] in pin["tokenPurposes"])
        if operation == OP_FINISH:
            raw = decoded(value["transportOriginal"], MAX_TRANSPORT_BYTES)
            transport(raw, document(raw, MAX_TRANSPORT_BYTES)["requestSha256"])
        if operation == OP_RECOVER:
            require(value["custodyRowSha256"] is None or type(value["custodyRowSha256"]) is str)
            if value["custodyRowSha256"] is not None:
                digest(value["custodyRowSha256"])
    elif operation == OP_AUTHORIZE:
        require(value["credentialId"] == grant["credentialId"] and value["credentialVersion"] == grant["credentialVersion"])
    elif operation == OP_FENCE:
        digest(value["authorizationRowSha256"])
        active = [{name: item[name] for name in scalar.LINEAGE_FIELDS} for item in grant["affectedLineages"] if item["predecessorKind"] == "active"]
        scalar.barriers(value["currentnessBarriers"], active)
    elif operation == OP_AUTHORIZE_DECIDE or operation in SNAPSHOT_OPERATIONS:
        digest(value["authorizationRowSha256"])
    else:
        digest(value["candidateSha256"])
    if "authorizationSha256" in value:
        digest(value["authorizationSha256"])
    if "expiresAtEpochNs" in value:
        common.integer(value["issuedAtEpochNs"]); common.integer(value["expiresAtEpochNs"])
        require(0 < value["expiresAtEpochNs"] - value["issuedAtEpochNs"] <= 30_000_000_000
            and value["expiresAtEpochNs"] <= grant["expiresAtEpochNs"])
    return dict(value)


def input_sha256(value):
    return sha256(canonical({name: value[name] for name in FIELDS - {"native_evidence"}}))


def evidence(value):
    require(type(value) is dict and set(value) == {"statement", "signature", "nativeKeyEvidence"})
    statement = value["statement"]
    require(type(statement) is dict and set(statement) == STATEMENT_FIELDS and statement["apiVersion"] == STATEMENT)
    for name in ("authorizationSha256", "scopeRowSha256"):
        digest(statement[name])
    if statement["materialId"] is not None:
        identifier(statement["materialId"])
    require(statement["phase"] in {operation.rsplit(".", 1)[1] for operation in NATIVE_OPERATIONS})
    # Only scalar checking is shared. Original succession signature/domain and
    # actual assignment verification remain separate in the policy owner.
    projection = {name: statement[name] for name in issuance.STATEMENT_FIELDS}
    projection["apiVersion"], projection["phase"] = issuance.STATEMENT, "draft"
    issuance.evidence({**value, "statement": projection})
    return value


def arguments(operation, value, *, typed=False):
    require(operation in OPERATIONS and isinstance(value, Mapping))
    fields = FIELDS if operation in NATIVE_OPERATIONS else HUMAN_FIELDS
    require(fields <= set(value) <= fields | ({"businessIntent", "authn_evidence"} if typed else set())
        and (not typed or "businessIntent" in value))
    raw = decoded(value["authorization_original"], MAX_GRANT_BYTES); grant = grant_document(raw)["payload"]
    request = request_binding(operation, value["request"], grant)
    require(value["resource_id"] == grant["authorizationId"] and value["payload_digest"] == sha256(canonical(request))
        and value["action"] == (NATIVE_ACTION if operation in NATIVE_OPERATIONS else ACTION))
    material.text(value["actor_id"], 512); require(value["actor_id"].startswith("oidc:"))
    if operation not in {OP_AUTHORIZE_DECIDE, OP_DECIDE}:
        require(value["actor_id"] == grant["requesterId"])
    activation.policy(value["credential_policy"])
    if operation in {OP_AUTHORIZE_DECIDE, OP_FENCE, OP_DECIDE, OP_ACTIVATE}:
        identifier(value["approval_id"])
    else:
        require(value["approval_id"] is None)
    if "authorizationSha256" in request:
        require(request["authorizationSha256"] == sha256(raw))
    enrollment_sha = sha256(activation.enrollment_bytes(value["enrollment_original"]))
    if operation in MATERIAL_OPERATIONS | {OP_RECOVER} and request["materialId"] is not None:
        pin = next(pin for pin in grant["materials"] if pin["materialId"] == request["materialId"])
        require(enrollment_sha == pin["enrollmentSha256"])
    else:
        require(enrollment_sha == grant["enrollmentSha256"])
    if operation in NATIVE_OPERATIONS:
        require(value["control_plane_configuration_digest"] == grant["configurationDigest"] and type(value["assignment_original"]) is dict)
        proof = evidence(value["native_evidence"])["statement"]
        require(proof["phase"] == operation.rsplit(".", 1)[1] and proof["exchangeId"] == grant["authorizationId"]
            and proof["authorizationSha256"] == sha256(raw) and proof["scopeRowSha256"] == request["scopeRowSha256"]
            and proof["materialId"] == request.get("materialId") and proof["inputSha256"] == input_sha256(value)
            and proof["providerId"] == grant["providerId"] and proof["enrollmentSha256"] == enrollment_sha
            and grant["issuedAtEpochNs"] <= proof["issuedAtEpochNs"] < proof["expiresAtEpochNs"] <= grant["expiresAtEpochNs"])
    result = {name: value[name] for name in fields}
    require(len(canonical(result)) <= MAX_ARGUMENT_BYTES)
    return result


def request_digest(operation, value):
    from catchplate import authority_request_commitment as commitment
    return commitment.oauth_retirement_succession_request_digest(operation, value)


TRANSPORT_SCHEMA = "catchplate.nativeOAuthSuccessionTransport/v1"
TRANSPORT_FIELDS = scalar.TRANSPORT_FIELDS


def transport(raw, request_sha256):
    value = document(raw, MAX_TRANSPORT_BYTES)
    require(set(value) == TRANSPORT_FIELDS and value["schema"] == TRANSPORT_SCHEMA and value["requestSha256"] == request_sha256)
    common.integer(value["receivedAtEpochNs"]); digest(value["rawResponseSha256"])
    refresh.envelope(value["rawResponseEnvelope"], 1)
    status = value["status"]
    require(status is None or type(status) is int and 200 <= status <= 599)
    return "unknown" if status is None else "accepted" if 200 <= status < 300 else "rejected"
