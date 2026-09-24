"""Closed shapes for a separate signed evidence-admission observation plan.

Callers must first own the whole lossless JSON graph within the existing byte,
node and depth ceilings. These validators neither capture nor encode, hash,
parse, verify a signature, allocate work, sample time or authenticate roots.
Source-only manifest pins are computed once at import, outside request work.

The two fixed operations retain their exact-PK, INSERT-only business programs.
Generic primary-proof/row shape helpers below do not extend the revocation-v4
protocol or the older v3 plan. Genuine query associations, proof transitions,
original-input and kernel replay, and independent request/configuration/key/
root/time admission remain mandatory. Shape acceptance returns no authority
token, execution capability, reservation, fence or durable custody receipt.
"""
from __future__ import annotations

from serverware import authority_contract as authority
from serverware import authority_primary_contract as primary
from serverware import authority_revocation_bundle_contract as retained
from serverware import authority_revocation_plan_contract as shape


PLAN_SCHEMA = "serverware.policyAuthorityWebAuthnEvidenceAdmissionPlan/v1"
ENVELOPE_SCHEMA = "serverware.signedPolicyAuthorityWebAuthnEvidenceAdmissionPlan/v1"
PROTOCOL = "webauthn-evidence-admission-v1"
SIGNATURE_DOMAIN = ENVELOPE_SCHEMA
IDENTITY_DOMAIN = "serverware.policyAuthorityWebAuthnEvidenceAdmissionPlanIdentity/v1"
MAX_BYTES = shape.MAX_PAYLOAD_BYTES
MAX_NODES = shape.MAX_JSON_NODES
MAX_DEPTH = shape.MAX_JSON_DEPTH
OPERATIONS = frozenset({"webauthn.registration.evidence.admit", "webauthn.trust.installation.admit"})
EVIDENCE_TABLE = "policy_authority_external_evidence_receipts"
PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "protocol", "operation",
    "operationManifestDigest", "queryManifestDigest", "authorizationManifestDigest",
    "handlerContractDigest", "configurationDigest", "plannerIdentity", "plannerSpkiDigest",
    "request", "databaseCutoffUs", "inputsDigest", "businessBeforeRoots",
    "authorizationBeforeRoots", "businessAfterRoots", "authorizationAfterRoots",
    "selectedRows", "beforeProofs", "queryReads", "transition", "issuedAtEpochNs", "expiresAtEpochNs"})
ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
TRANSITION_FIELDS = frozenset({"mutations", "result", "kernelWorkUnits", "workUnits"})
RESULT_FIELDS = frozenset({"evidence_digest", "admission"})
QUERY_READ_FIELDS = retained._READ_FIELDS
QUERY_ADDRESS_FIELDS = retained._ADDRESS_FIELDS
QUERY_MANIFEST_DIGEST = primary.source_query_manifest_digest()
AUTHORIZATION_MANIFEST_DIGEST = primary.source_authorization_manifest_digest()
_SPECS = {operation: authority.operation_spec(operation) for operation in OPERATIONS}
HANDLER_DIGESTS = {operation: authority.handler_contract_digest(operation) for operation in OPERATIONS}
_BUSINESS_TABLES = {operation: tuple(sorted(set(spec["businessReads"]) | set(spec["businessWrites"])))
    for operation, spec in _SPECS.items()}
_AUTHORIZATION_TABLES = {operation: tuple(sorted(spec["authorizationReads"]))
    for operation, spec in _SPECS.items()}
_INSERT_TEMPLATES = {operation: frozenset(template["templateId"] for template in spec["mutationTemplates"]
    if template["table"] == EVIDENCE_TABLE and template["mutation"] == "INSERT")
    for operation, spec in _SPECS.items()}


class WebAuthnEvidencePlanContractError(ValueError):
    pass


def _roots(values, tables):
    retained._array(values, len(tables), "evidence plan primary roots", minimum=len(tables))
    for root, table in zip(values, tables):
        shape._object(root, retained.primary_wire.ROOT_FIELDS, "evidence plan primary root")
        shape._literal(root["table"], table)
        shape._integer(root["rootRevision"])
        shape._integer(root["leafCount"])
        shape._digest(root["rootDigest"])


def _key(value, table):
    retained._key(value)
    shape._object(value, frozenset(primary.PRIMARY_KEY_COLUMNS[table]), "evidence plan source primary key")


def _request(value, operation, spec):
    shape._object(value, shape.TYPED_REQUEST_FIELDS, "evidence plan typed request")
    shape._literal(value["schema"], shape.TYPED_REQUEST_SCHEMA)
    shape._literal(value["operation"], operation)
    shape._literal(value["handler"], spec["handler"])
    shape._literal(value["operationManifestDigest"], authority.OPERATION_MANIFEST_DIGEST)
    for field in ("operationId", "requestDigest"):
        shape._digest(value[field])
    shape._bounded_object(value["arguments"], retained.complete.MAX_ARGUMENT_FIELDS, "evidence plan arguments")


def _reads(values, maximum, tables):
    retained._array(values, maximum, "evidence plan query reads", minimum=1)
    for record in values:
        shape._object(record, QUERY_READ_FIELDS, "evidence plan query read")
        shape._text(record["queryId"], 1024)
        # Strict ASCII encoding and genuine QueryRead constructors belong to
        # the metered restoration helper; nested query meaning is not parsed.
        for field in ("declaredQueryJson", "resolvedQueryJson"):
            shape._text(record[field], MAX_BYTES, minimum=2)
        shape._integer(record["returnedRowCount"], 1)
        retained._array(record["addresses"], 1, "evidence plan query address", minimum=1)
        address = record["addresses"][0]
        shape._object(address, QUERY_ADDRESS_FIELDS, "evidence plan query address")
        shape._text(address["table"])
        if address["table"] not in tables:
            raise WebAuthnEvidencePlanContractError("evidence plan query table is outside the source inventory")
        shape._text(address["keyJson"], MAX_BYTES, minimum=2)
        shape._digest(address["keyDigest"])
        retained._boolean(address["present"])


def _transition(value, operation, spec):
    shape._object(value, TRANSITION_FIELDS, "evidence plan transition")
    shape._array(value["mutations"], spec["maximumBusinessMutations"], "evidence plan mutations")
    for mutation in value["mutations"]:
        shape._object(mutation, retained._MUTATION_FIELDS, "evidence plan mutation")
        shape._literal(mutation["table"], EVIDENCE_TABLE)
        shape._literal(mutation["operation"], "INSERT")
        shape._digest(mutation["templateId"])
        if mutation["templateId"] not in _INSERT_TEMPLATES[operation]:
            raise WebAuthnEvidencePlanContractError("evidence plan mutation template differs from its operation")
        _key(mutation["key"], EVIDENCE_TABLE)
        shape._digest(mutation["keyDigest"])
        if mutation["expectedRow"] is not None or type(mutation["row"]) is not dict:
            raise WebAuthnEvidencePlanContractError("evidence plan mutation is not absent-to-present")
    shape._object(value["result"], RESULT_FIELDS, "evidence plan result")
    shape._digest(value["result"]["evidence_digest"])
    shape._text(value["result"]["admission"], 16)
    if value["result"]["admission"] not in ("proposed-insert", "already-retained"):
        raise WebAuthnEvidencePlanContractError("evidence plan result is not a fixed admission proposal")
    shape._integer(value["kernelWorkUnits"], spec["maximumBusinessWorkUnits"], minimum=1)
    shape._integer(value["workUnits"], spec["maximumWorkUnits"], minimum=1)


def validate_payload_shape(value) -> None:
    """Validate owned closed data only; all cryptographic joins remain external."""
    try:
        shape._object(value, PAYLOAD_FIELDS, "evidence admission plan")
        shape._literal(value["schema"], PLAN_SCHEMA)
        shape._literal(value["sourceRevision"], authority.SOURCE_REVISION)
        shape._literal(value["protocol"], PROTOCOL)
        operation = value["operation"]
        if type(operation) is not str or operation not in OPERATIONS:
            raise WebAuthnEvidencePlanContractError("evidence plan operation is not source fixed")
        spec = _SPECS[operation]
        for field, expected in (("operationManifestDigest", authority.OPERATION_MANIFEST_DIGEST),
                ("queryManifestDigest", QUERY_MANIFEST_DIGEST),
                ("authorizationManifestDigest", AUTHORIZATION_MANIFEST_DIGEST),
                ("handlerContractDigest", HANDLER_DIGESTS[operation])):
            shape._literal(value[field], expected)
        for field in ("configurationDigest", "plannerSpkiDigest", "inputsDigest"):
            shape._digest(value[field])
        shape.validate_identity_shape(value["plannerIdentity"])
        shape._integer(value["databaseCutoffUs"], minimum=1)
        for field in ("issuedAtEpochNs", "expiresAtEpochNs"):
            shape._integer(value[field], minimum=1)
        if not 0 < value["expiresAtEpochNs"] - value["issuedAtEpochNs"] <= authority.VERIFIER_RESPONSE_MAX_AGE_NS:
            raise WebAuthnEvidencePlanContractError("evidence plan lifetime exceeds its source bound")
        _request(value["request"], operation, spec)
        for prefix, tables in (("business", _BUSINESS_TABLES[operation]),
                               ("authorization", _AUTHORIZATION_TABLES[operation])):
            _roots(value[prefix + "BeforeRoots"], tables)
            _roots(value[prefix + "AfterRoots"], tables)
        tables = _BUSINESS_TABLES[operation] + _AUTHORIZATION_TABLES[operation]
        maximum = spec["maximumBusinessQueryRows"]
        retained._array(value["selectedRows"], maximum, "evidence plan selected rows", minimum=1)
        retained._array(value["beforeProofs"], maximum, "evidence plan before proofs", minimum=1)
        for selected in value["selectedRows"]:
            shape._object(selected, retained._SELECTED_FIELDS, "evidence plan selected row")
            shape._text(selected["table"])
            if selected["table"] not in tables:
                raise WebAuthnEvidencePlanContractError("evidence plan selected table is outside the source inventory")
            _key(selected["key"], selected["table"])
            shape._digest(selected["keyDigest"])
            retained._boolean(selected["present"])
            if (selected["contractSelector"] is not None
                    or selected["present"] and type(selected["row"]) is not dict
                    or not selected["present"] and selected["row"] is not None):
                raise WebAuthnEvidencePlanContractError("evidence plan selection is not an exact PK observation")
        for proof in value["beforeProofs"]:
            retained._proof(proof)
            if proof["table"] not in tables:
                raise WebAuthnEvidencePlanContractError("evidence plan proof table is outside the source inventory")
            _key(proof["key"], proof["table"])
        _reads(value["queryReads"], maximum, tables)
        _transition(value["transition"], operation, spec)
    except ValueError as exc:
        if isinstance(exc, WebAuthnEvidencePlanContractError):
            raise
        raise WebAuthnEvidencePlanContractError("evidence admission plan shape is invalid") from exc


def validate_envelope_shape(value) -> None:
    """Close an owned signed envelope without authenticating its signature."""
    try:
        shape._object(value, ENVELOPE_FIELDS, "signed evidence admission plan")
        shape._literal(value["schema"], ENVELOPE_SCHEMA)
        shape._base64url(value["signatureBase64Url"], signature=True)
        validate_payload_shape(value["payload"])
    except ValueError as exc:
        if isinstance(exc, WebAuthnEvidencePlanContractError):
            raise
        raise WebAuthnEvidencePlanContractError("signed evidence admission plan shape is invalid") from exc
