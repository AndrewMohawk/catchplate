"""Closed shapes for detached signed successor transition plans.

Callers first own the entire lossless graph on the original work allowance.
These bounded source checks do not encode, hash, verify signatures or proofs,
sample clocks, enroll keys, or admit request/root/history authority. In
particular, the nested proof expectations remain independently supplied data;
their presence in a signed context does not establish their provenance.

Only the three actual successor transition proof operations are supported.
No legacy v3, revocation-v4, evidence-admission protocol or execution gate is
widened. Genuine original-input, proof and semantic replay remains mandatory.
"""
from __future__ import annotations

from serverware import authority_webauthn_transition_proof as proof


authority = proof.inputs.authority
shape = proof.contract.shape
SCHEMA = "serverware.policyAuthorityWebAuthnTransitionPlan/v1"
PAYLOAD_SCHEMA = SCHEMA
ENVELOPE_SCHEMA = "serverware.policyAuthorityWebAuthnTransitionPlanEnvelope/v1"
SIGNATURE_DOMAIN = "serverware.policyAuthorityWebAuthnTransitionPlanSignature/v1"
IDENTITY_DOMAIN = "serverware.policyAuthorityWebAuthnTransitionPlanIdentity/v1"
MAX_BYTES, MAX_NODES, MAX_DEPTH = proof.contract.MAX_BYTES, proof.contract.MAX_NODES, proof.contract.MAX_DEPTH
OPERATIONS = proof.contract.OPERATIONS
EXPECTATION_FIELDS = frozenset({"proofExpectations", "configurationDigest", "plannerIdentity",
    "plannerSpkiDigest", "maximumPlanAgeNs"})
PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "operation", "configurationDigest",
    "plannerIdentity", "plannerSpkiDigest", "proofDigest", "proofByteCount", "inputsDigest",
    "inputsByteCount", "contextDigest", "contextByteCount", "issuedAtEpochNs", "expiresAtEpochNs"})
ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})


class WebAuthnTransitionPlanContractError(ValueError):
    pass


def _policy(policy, operation):
    """Close all purpose pins before any caller invokes a key callback."""
    # The actual proof validator already closes this exact operation-specific
    # object and validates its four time/age/skew scalars. No default policy is
    # filled in here, and no field is adopted from a received proof.
    if operation == proof.registration.OPERATION:
        shape.validate_identity_shape(policy["signerIdentity"])
        shape._digest(policy["signerSpkiDigest"])
        for field, maximum in (("rpId", 4096), ("origin", 8192)):
            shape._text(policy[field], maximum)
            if "\x00" in policy[field]:
                raise WebAuthnTransitionPlanContractError("registration policy text contains NUL")
        # Actual UTF-8 byte bounds are also enforced by the metered genuine
        # registration replay, rather than an unmetered encoder in this shape.
    elif operation == proof.stage.OPERATION:
        shape.validate_identity_shape(policy["verifierIdentity"])
        for field in ("capabilityId", "candidateSigningKeyId"):
            shape._digest(policy[field])
        for field in ("developmentEnabled", "requireApproval", "requireApproverWebauthn"):
            if type(policy[field]) is not bool:
                raise WebAuthnTransitionPlanContractError("trust-stage policy flags must be exact booleans")
    elif operation == proof.completion.OPERATION:
        shape.validate_identity_shape(policy["installerIdentity"])
        for field in ("installerSpkiDigest", "installationTargetDigest"):
            shape._digest(policy[field])
        stage = policy["committedStage"]
        fields = proof.completion.completion._STAGE_FIELDS
        shape._object(stage, fields, "independently admitted committed stage")
        for field in fields - {"witnessSequence"}:
            shape._digest(stage[field])
        shape._integer(stage["witnessSequence"], minimum=1)
    else:
        raise WebAuthnTransitionPlanContractError("transition plan operation is not source fixed")


def _validate_expectations(expected):
    """Validate the complete independently owned five-field context, not trust."""
    try:
        shape._object(expected, EXPECTATION_FIELDS, "independent transition plan expectations")
        for field in ("configurationDigest", "plannerSpkiDigest"):
            shape._digest(expected[field])
        shape.validate_identity_shape(expected["plannerIdentity"])
        shape._integer(expected["maximumPlanAgeNs"], authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
        nested = expected["proofExpectations"]
        operation = proof._validate_expectations(nested)
        proof.contract._request(nested["request"], operation)
        for field, tables in (("businessBeforeRoots", proof.contract.BUSINESS_TABLES[operation]),
                ("authorizationBeforeRoots", proof.contract.AUTHORIZATION_TABLES[operation])):
            proof.contract._roots(nested[field], tables)
        identities = proof.contract._head_ids(operation, nested["request"]["arguments"])
        proof.contract._heads(nested["countedBeforeHeads"], identities)
        _policy(nested["policy"], operation)
        # The genuine three workers require positive I64 nanoseconds and join
        # this historical DB cutoff to the same admitted invocation instant.
        # Validate that shape/relation without sampling or changing any time.
        cutoff_ns = nested["databaseCutoffUs"] * 1000
        shape._integer(cutoff_ns, minimum=1)
        policy = nested["policy"]
        if (cutoff_ns >= policy["deadlineEpochNs"]
                or abs(cutoff_ns - policy["nowEpochNs"]) > policy["maximumClockSkewNs"]):
            raise WebAuthnTransitionPlanContractError("transition plan cutoff differs from independent history")
        return operation
    except ValueError as exc:
        if isinstance(exc, WebAuthnTransitionPlanContractError):
            raise
        raise WebAuthnTransitionPlanContractError("independent transition plan expectations are invalid") from exc


def validate_payload_shape(value):
    """Close detached commitments without authenticating their originals."""
    try:
        shape._object(value, PAYLOAD_FIELDS, "successor transition plan")
        shape._literal(value["schema"], SCHEMA)
        shape._literal(value["sourceRevision"], authority.SOURCE_REVISION)
        if type(value["operation"]) is not str or value["operation"] not in OPERATIONS:
            raise WebAuthnTransitionPlanContractError("transition plan operation is not source fixed")
        shape.validate_identity_shape(value["plannerIdentity"])
        for field in ("configurationDigest", "plannerSpkiDigest", "proofDigest", "inputsDigest", "contextDigest"):
            shape._digest(value[field])
        for field in ("proofByteCount", "inputsByteCount", "contextByteCount"):
            shape._integer(value[field], MAX_BYTES, minimum=2)
        for field in ("issuedAtEpochNs", "expiresAtEpochNs"):
            shape._integer(value[field], minimum=1)
        if not 0 < value["expiresAtEpochNs"] - value["issuedAtEpochNs"] <= authority.VERIFIER_RESPONSE_MAX_AGE_NS:
            raise WebAuthnTransitionPlanContractError("transition plan lifetime exceeds the source bound")
    except ValueError as exc:
        if isinstance(exc, WebAuthnTransitionPlanContractError):
            raise
        raise WebAuthnTransitionPlanContractError("successor transition plan shape is invalid") from exc


def validate_envelope_shape(value):
    """Close the original signed envelope; signature verification is separate."""
    try:
        shape._object(value, ENVELOPE_FIELDS, "signed successor transition plan")
        shape._literal(value["schema"], ENVELOPE_SCHEMA)
        shape._base64url(value["signatureBase64Url"], signature=True)
        validate_payload_shape(value["payload"])
    except ValueError as exc:
        if isinstance(exc, WebAuthnTransitionPlanContractError):
            raise
        raise WebAuthnTransitionPlanContractError("signed successor transition plan shape is invalid") from exc
