"""Hash-free shapes for disjoint revoke-only measured-plan v4/v5 transports.

Callers must first own the entire lossless JSON graph through bounded capture:
64 MiB, one million nodes and depth 128. These checks neither measure that
aggregate nor parse, copy, encode, hash, verify signatures or sample a clock.
Rows, arguments, results and embedded QueryRead strings keep their actual raw
values for the genuine semantic verifier. Shape acceptance returns no token.
Existing v3 producers, readers and registry admission are unchanged.
"""
from __future__ import annotations

from serverware import authority_contract
from serverware import authority_revocation_bundle_contract as retained


OPERATION = "webauthn.credential.revoke"
PLANNER_RESPONSE_SCHEMA = "serverware.policyAuthorityPlannerResponse/v4"
MEASURED_PLAN_SCHEMA = "serverware.policyAuthorityMeasuredPlan/v4"
SIGNED_MEASURED_PLAN_SCHEMA = "serverware.signedPolicyAuthorityMeasuredPlan/v4"
SNAPSHOT_DOMAIN = "serverware.policyAuthoritySnapshot/v4"
PUBLIC_PLANNER_RESPONSE_SCHEMA = "serverware.policyAuthorityPlannerResponse/v5"
PUBLIC_MEASURED_PLAN_SCHEMA = "serverware.policyAuthorityMeasuredPlan/v5"
PUBLIC_SIGNED_MEASURED_PLAN_SCHEMA = "serverware.signedPolicyAuthorityMeasuredPlan/v5"
PUBLIC_SNAPSHOT_DOMAIN = "serverware.policyAuthoritySnapshot/v5"
TYPED_REQUEST_SCHEMA = "serverware.policyAuthorityV9Request/v1"
PLANNER_TRACE_SCHEMA = "serverware.policyAuthorityPlannerTrace/v1"
MAX_PAYLOAD_BYTES = 64 * 1024 * 1024
MAX_JSON_NODES = 1_000_000
MAX_JSON_DEPTH = 128
MAX_AUTHORIZATION_SOURCES = 64
MAX_TRACE_KEY_FIELDS = 32
MAX_TEXT_CHARS = 4096
I64_MAX = 2**63 - 1
_SPEC = authority_contract.operation_spec(OPERATION)
MAX_SELECTED_ROWS = _SPEC["maximumQueryRows"]
MAX_MUTATIONS = _SPEC["maximumMutations"]
MAX_WORK_UNITS = _SPEC["maximumWorkUnits"]
MAX_TRACE_ENTRIES = 4096 + 69

PAYLOAD_FIELDS = frozenset({
    "schema", "measuredPlan", "typedRequest", "selectedBusinessRows", "mutationPlan",
    "queryMultiproofs", "queryMultiproofsDigest", "plannerTrace", "plannerTraceDigest",
    "authorizationProjection", "webauthnEvidence", "expectedResult", "expectedResultDigest",
    "plannerIdentity", "rootTransition", "revocationProofBundle",
})
MEASURED_PLAN_FIELDS = frozenset({
    "schema", "plannerTransactionId", "operation", "operationId", "requestDigest",
    "capabilityId", "sourceRevision", "authoritySchemaVersion", "operationContractDigest",
    "operationManifestDigest", "handlerContractDigest", "queryManifestDigest",
    "selectedBusinessRowsDigest", "mutationPlanDigest", "workUnits",
    "authorityRootSetBeforeDigest", "authorizationProjectionDigest", "authoritySnapshotDigest",
    "rootTransitionDigest", "deadlineMonotonicNs", "deadlineEpochNs", "fence",
})
SIGNED_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
IDENTITY_FIELDS = frozenset({"sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest"})
TYPED_REQUEST_FIELDS = frozenset({"schema", "operation", "operationId", "requestDigest",
    "handler", "operationManifestDigest", "arguments"})
AUTHORIZATION_PROJECTION_FIELDS = frozenset({
    "plannerTransactionId", "operation", "operationId", "requestDigest", "capabilityId",
    "authorizationReads", "sourceRows", "sourceHighWaterDigest", "approverPolicyDigest",
    "assertionEvidenceDigest", "verifierSessionIdentityDigest", "verifierMeasurementDigest",
    "verifierAttestationReceiptDigest", "createdAtEpochNs", "expiresAtEpochNs",
})
AUTHORIZATION_SOURCE_FIELDS = frozenset({"table", "selector", "present", "row", "rowDigest"})
TRACE_FIELDS = frozenset({"schema", "operation", "entries"})
TRACE_ENTRY_FIELDS = frozenset({"ordinal", "access", "table", "key"})
SNAPSHOT_FRAME_FIELDS = (
    "operation", "operationId", "requestDigest", "queryManifestDigest",
    "authorityRootSetBeforeDigest", "authorizationProjectionDigest",
    "selectedBusinessRowsDigest", "mutationPlanDigest", "rootTransitionDigest",
)
PLAN_DIGEST_FIELDS = MEASURED_PLAN_FIELDS - {
    "schema", "operation", "sourceRevision", "authoritySchemaVersion", "workUnits",
    "deadlineMonotonicNs", "deadlineEpochNs", "fence",
}
EVIDENCE_DIGEST_FIELDS = frozenset({
    "operationId", "requestDigest", "capabilityId", "challengeDigest", "clientChallengeDigest",
    "credentialPolicyDigest", "authenticatorDataDigest", "clientDataJSONDigest", "signatureDigest",
    "rpIdHashDigest", "trustHighWaterDigest", "verifierSessionIdentityDigest",
    "verifierMeasurementDigest", "verifierAttestationReceiptDigest",
    "verifiedAssertionReceiptDigest", "verifierSignatureDigest",
})
EVIDENCE_TEXT_FIELDS = frozenset({"operation", "challengeId", "credentialRecordId", "credentialId", "rpId", "origin"})
EVIDENCE_ENCODED_FIELDS = frozenset({"authenticatorDataBase64url", "clientDataJSONBase64url",
    "signatureBase64url", "verifierSignatureBase64url"})
EVIDENCE_INTEGER_FIELDS = frozenset({"flags", "priorCounter", "counter", "metadataPublicationSequence",
    "verifiedAtEpochNs", "expiresAtEpochNs"})
EVIDENCE_FIELDS = (EVIDENCE_DIGEST_FIELDS | EVIDENCE_TEXT_FIELDS | EVIDENCE_ENCODED_FIELDS
                   | EVIDENCE_INTEGER_FIELDS | {"userPresent", "userVerified"})
_BASE64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


class RevocationPlanContractError(ValueError):
    pass


def _object(value, fields, label):
    if (type(value) is not dict or len(value) != len(fields)
            or any(type(name) is not str or len(name) > 64 for name in value)
            or set(value) != fields):
        raise RevocationPlanContractError(f"revocation plan {label} is not a closed object")


def _bounded_object(value, maximum, label):
    if (type(value) is not dict or len(value) > maximum
            or any(type(name) is not str or len(name) > 128 for name in value)):
        raise RevocationPlanContractError(f"revocation plan {label} is not a bounded object")


def _array(value, maximum, label):
    if type(value) is not list or len(value) > maximum:
        raise RevocationPlanContractError(f"revocation plan {label} is not a bounded array")


def _text(value, maximum=128, *, minimum=1):
    if type(value) is not str or not minimum <= len(value) <= maximum:
        raise RevocationPlanContractError("revocation plan text is not an exact bounded string")


def _literal(value, expected):
    if type(value) is not str or value != expected:
        raise RevocationPlanContractError("revocation plan source schema, revision or operation changed")


def _integer(value, maximum=I64_MAX, *, minimum=0):
    if type(value) is not int or not minimum <= value <= maximum:
        raise RevocationPlanContractError("revocation plan integer is not an exact bounded value")


def _digest(value):
    _text(value, 71, minimum=71)
    if value[:7] != "sha256:" or any(character not in "0123456789abcdef" for character in value[7:]):
        raise RevocationPlanContractError("revocation plan digest is not canonical SHA-256")


def _base64url(value, *, signature=False):
    _text(value, 86 if signature else authority_contract.MAX_REQUEST_BYTES)
    if (signature and len(value) != 86 or len(value) % 4 == 1
            or any(character not in _BASE64URL for character in value)
            or len(value) % 4 == 2 and _BASE64URL.index(value[-1]) % 16
            or len(value) % 4 == 3 and _BASE64URL.index(value[-1]) % 4):
        raise RevocationPlanContractError("revocation plan bytes are not canonical unpadded base64url")


def _json_root(value):
    # Deep lossless admission and total bounds belong to the mandatory owned
    # capture. A generic kernel result is not narrowed to one business recipe.
    if type(value) is dict:
        if len(value) > MAX_JSON_NODES:
            raise RevocationPlanContractError("revocation plan result object is too large")
    elif type(value) is list:
        _array(value, MAX_JSON_NODES, "result")
    elif type(value) is str:
        _text(value, MAX_PAYLOAD_BYTES, minimum=0)
    elif type(value) is int:
        if value.bit_length() > 16384:
            raise RevocationPlanContractError("revocation plan result integer is too large")
    elif value is not None and type(value) is not bool:
        raise RevocationPlanContractError("revocation plan result is not lossless JSON")


def validate_identity_shape(value) -> None:
    _object(value, IDENTITY_FIELDS, "identity")
    for item in value.values():
        _digest(item)


def profile(public):
    if type(public) is not bool:
        raise RevocationPlanContractError("revocation profile is not explicit")
    return ((PUBLIC_PLANNER_RESPONSE_SCHEMA, PUBLIC_MEASURED_PLAN_SCHEMA,
        PUBLIC_SIGNED_MEASURED_PLAN_SCHEMA, PUBLIC_SNAPSHOT_DOMAIN) if public else
        (PLANNER_RESPONSE_SCHEMA, MEASURED_PLAN_SCHEMA, SIGNED_MEASURED_PLAN_SCHEMA, SNAPSHOT_DOMAIN))


def validate_measured_plan_shape(value, *, public=False) -> None:
    _object(value, MEASURED_PLAN_FIELDS, "measured plan")
    _literal(value["schema"], profile(public)[1])
    _literal(value["operation"], OPERATION)
    _literal(value["sourceRevision"], authority_contract.SOURCE_REVISION)
    _integer(value["authoritySchemaVersion"], authority_contract.SCHEMA_VERSION,
             minimum=authority_contract.SCHEMA_VERSION)
    _integer(value["workUnits"], MAX_WORK_UNITS, minimum=1)
    for name in ("deadlineMonotonicNs", "deadlineEpochNs", "fence"):
        _integer(value[name], minimum=1)
    for name in PLAN_DIGEST_FIELDS:
        _digest(value[name])


def _request(value):
    _object(value, TYPED_REQUEST_FIELDS, "typed request")
    _literal(value["schema"], TYPED_REQUEST_SCHEMA)
    _literal(value["operation"], OPERATION)
    _literal(value["handler"], _SPEC["handler"])
    for name in ("operationId", "requestDigest", "operationManifestDigest"):
        _digest(value[name])
    _bounded_object(value["arguments"], retained.complete.MAX_ARGUMENT_FIELDS, "arguments")


def authorization_digest_profile(public):
    if type(public) is not bool:
        raise RevocationPlanContractError("authorization digest profile is not source fixed")
    return (("requestAuthorizationDigest", "serverware.publicWebAuthnRevocationAuthorizationIdentity/v1")
        if public else ("assertionEvidenceDigest", "serverware.policyAuthorityWebAuthnAssertionEvidence/v1"))


def _projection(value, *, public=False):
    fields = ((AUTHORIZATION_PROJECTION_FIELDS - {"assertionEvidenceDigest"}) | {"requestAuthorizationDigest"}
        if public else AUTHORIZATION_PROJECTION_FIELDS)
    _object(value, fields, "authorization projection")
    _literal(value["operation"], OPERATION)
    _array(value["authorizationReads"], MAX_AUTHORIZATION_SOURCES, "authorization tables")
    _array(value["sourceRows"], MAX_AUTHORIZATION_SOURCES, "authorization sources")
    for table in value["authorizationReads"]:
        _text(table)
    for row in value["sourceRows"]:
        _object(row, AUTHORIZATION_SOURCE_FIELDS, "authorization source")
        _text(row["table"])
        retained._key(row["selector"])
        retained._boolean(row["present"])
        retained._row(row["row"])
        _digest(row["rowDigest"])
    for name in fields - {
        "operation", "authorizationReads", "sourceRows", "approverPolicyDigest",
        "createdAtEpochNs", "expiresAtEpochNs",
    }:
        _digest(value[name])
    if value["approverPolicyDigest"] is not None:
        _digest(value["approverPolicyDigest"])
    for name in ("createdAtEpochNs", "expiresAtEpochNs"):
        _integer(value[name], minimum=1)


def _evidence(value, *, public=False):
    if public:
        from serverware import authority_public_webauthn_revocation as authorization
        authorization.shape(value)
        return
    _object(value, EVIDENCE_FIELDS, "assertion evidence")
    _literal(value["operation"], OPERATION)
    for name in EVIDENCE_DIGEST_FIELDS:
        _digest(value[name])
    for name in EVIDENCE_TEXT_FIELDS:
        _text(value[name], MAX_TEXT_CHARS)
    for name in EVIDENCE_INTEGER_FIELDS:
        _integer(value[name])
    for name in ("userPresent", "userVerified"):
        retained._boolean(value[name])
    for name in EVIDENCE_ENCODED_FIELDS:
        _base64url(value[name], signature=name == "verifierSignatureBase64url")


def _trace(value):
    _object(value, TRACE_FIELDS, "trace")
    _literal(value["schema"], PLANNER_TRACE_SCHEMA)
    _literal(value["operation"], OPERATION)
    _array(value["entries"], MAX_TRACE_ENTRIES, "trace entries")
    for ordinal, entry in enumerate(value["entries"]):
        _object(entry, TRACE_ENTRY_FIELDS, "trace entry")
        _integer(entry["ordinal"], ordinal, minimum=ordinal)
        _text(entry["access"], 5)
        if entry["access"] not in ("read", "write"):
            raise RevocationPlanContractError("revocation plan trace access is unknown")
        _text(entry["table"])
        if entry["key"] is not None or entry["access"] == "write":
            _bounded_object(entry["key"], MAX_TRACE_KEY_FIELDS, "trace key")
    # Table permissions, exact physical markers, business/framework partition
    # and mechanical read/write suffix checks remain genuine verifier duties.


def validate_payload_shape(value) -> None:
    """Check an owned v4/v5 payload's shape, not its bindings or authority."""
    _object(value, PAYLOAD_FIELDS, "payload")
    public = value["schema"] == PUBLIC_PLANNER_RESPONSE_SCHEMA
    _literal(value["schema"], profile(public)[0])
    validate_measured_plan_shape(value["measuredPlan"], public=public)
    # Admit all outer collection bounds before traversing retained proof data.
    _array(value["selectedBusinessRows"], MAX_SELECTED_ROWS, "selected rows")
    _array(value["mutationPlan"], MAX_MUTATIONS, "mutations")
    _array(value["queryMultiproofs"], MAX_SELECTED_ROWS, "primary proofs")
    _object(value["plannerTrace"], TRACE_FIELDS, "trace")
    _array(value["plannerTrace"]["entries"], MAX_TRACE_ENTRIES, "trace entries")
    _request(value["typedRequest"])
    validate_identity_shape(value["plannerIdentity"])
    _json_root(value["expectedResult"])
    for name in ("queryMultiproofsDigest", "plannerTraceDigest", "expectedResultDigest"):
        _digest(value[name])
    try:
        retained.validate_bundle_shape(value["revocationProofBundle"])
        retained.validate_transition_shape(value["rootTransition"])
        if (retained.public_binding(value["revocationProofBundle"]["inputs"]["assertionBinding"]) != public
                or retained.public_binding(value["rootTransition"]["assertionBinding"]) != public):
            raise RevocationPlanContractError("revocation plan and proof profiles differ")
        for selected in value["selectedBusinessRows"]:
            retained._object(selected, retained._SELECTED_FIELDS, "selected row")
            retained._text(selected["table"])
            retained._key(selected["key"])
            retained._digest(selected["keyDigest"])
            retained._boolean(selected["present"])
            retained._row(selected["row"])
            if selected["contractSelector"] is not None:
                raise RevocationPlanContractError("revocation plan selector is not source admitted")
        for mutation in value["mutationPlan"]:
            retained._object(mutation, retained._MUTATION_FIELDS, "mutation")
            retained._text(mutation["templateId"])
            retained._text(mutation["table"])
            _text(mutation["operation"], 6)
            if mutation["operation"] not in ("INSERT", "UPDATE", "DELETE"):
                raise RevocationPlanContractError("revocation plan mutation opcode is unknown")
            retained._key(mutation["key"])
            retained._digest(mutation["keyDigest"])
            retained._row(mutation["expectedRow"])
            retained._row(mutation["row"])
        for proof in value["queryMultiproofs"]:
            retained._proof(proof)
        _projection(value["authorizationProjection"], public=public)
        _evidence(value["webauthnEvidence"], public=public)
    except retained.RevocationBundleContractError as exc:
        raise RevocationPlanContractError("revocation plan retained evidence shape is invalid") from exc
    _trace(value["plannerTrace"])


def validate_signed_envelope_shape(value) -> None:
    """Close an owned envelope without decoding or verifying its signature."""
    _object(value, SIGNED_ENVELOPE_FIELDS, "signed envelope")
    _object(value["payload"], PAYLOAD_FIELDS, "payload")
    public = value["payload"]["schema"] == PUBLIC_PLANNER_RESPONSE_SCHEMA
    _literal(value["schema"], profile(public)[2])
    _base64url(value["signatureBase64Url"], signature=True)
    validate_payload_shape(value["payload"])
