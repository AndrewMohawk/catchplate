"""Closed token-free consume-plan bytes, never release or execution authority.

All original proofs, possession and current/provenance authority are replayed
by the distinct plan owner. This module supplies only bounded source metadata,
canonical framing and commitments on the caller's existing work allowance.
"""
from __future__ import annotations

from serverware import authority_contract as authority
from serverware import authority_primary_contract as primary
from serverware import authority_revocation_plan_contract as shape
from serverware import authority_webauthn_evidence as evidence


OPERATION = "oidc.session.activation-delivery.consume"
SCHEMA = PAYLOAD_SCHEMA = "serverware.policyAuthorityOidcSessionActivationDeliveryPlan/v1"
ENVELOPE_SCHEMA = "serverware.signedPolicyAuthorityOidcSessionActivationDeliveryPlan/v1"
SIGNATURE_DOMAIN = "serverware.policyAuthorityOidcSessionActivationDeliveryPlanSignature/v1"
IDENTITY_DOMAIN = "serverware.policyAuthorityOidcSessionActivationDeliveryPlanIdentity/v1"
PROOF_DOMAIN = "serverware.policyAuthorityOidcSessionActivationDeliveryProof/v1"
CONTEXT_DOMAIN = "serverware.policyAuthorityOidcSessionActivationDeliveryContext/v1"
INPUTS_DOMAIN = "serverware.policyAuthorityOidcSessionActivationDeliveryPrivateInputs/v1"
TRANSITION_DOMAIN = "serverware.policyAuthorityOidcSessionActivationDeliveryTransition/v1"
MAX_BYTES, MAX_NODES, MAX_DEPTH = 16 * 1024, 128, 4
MAX_ORIGINAL_BYTES = authority.MAX_RESULT_BYTES
PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "operation", "requestDigest", "operationId",
    "operationManifestDigest", "queryManifestDigest", "authorizationManifestDigest", "handlerContractDigest",
    "configurationDigest", "plannerIdentity", "plannerSpkiDigest", "proofDigest", "proofByteCount",
    "contextDigest", "contextByteCount", "inputsDigest", "inputsByteCount", "transitionDigest",
    "transitionByteCount", "issuedAtEpochNs", "expiresAtEpochNs"})
ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
_BODY_PROFILES = (("proof", PROOF_DOMAIN), ("context", CONTEXT_DOMAIN),
    ("inputs", INPUTS_DOMAIN), ("transition", TRANSITION_DOMAIN))
_OPERATION_MANIFEST_DIGEST = authority.OPERATION_MANIFEST_DIGEST
_QUERY_MANIFEST_DIGEST = primary.source_query_manifest_digest()
_AUTHORIZATION_MANIFEST_DIGEST = primary.source_authorization_manifest_digest()
_HANDLER_CONTRACT_DIGEST = authority.handler_contract_digest(OPERATION)


class OidcSessionActivationDeliveryPlanContractError(ValueError):
    pass


def _fail(message):
    raise OidcSessionActivationDeliveryPlanContractError(message)


def _source_fields():
    return {"schema": SCHEMA, "sourceRevision": authority.SOURCE_REVISION, "operation": OPERATION,
        "operationManifestDigest": _OPERATION_MANIFEST_DIGEST,
        "queryManifestDigest": _QUERY_MANIFEST_DIGEST,
        "authorizationManifestDigest": _AUTHORIZATION_MANIFEST_DIGEST,
        "handlerContractDigest": _HANDLER_CONTRACT_DIGEST}


def validate_payload_shape(value):
    shape._object(value, PAYLOAD_FIELDS, "activation delivery plan payload")
    for field, expected in _source_fields().items():
        shape._literal(value[field], expected)
    for field in ("requestDigest", "operationId", "configurationDigest", "plannerSpkiDigest"):
        shape._digest(value[field])
    shape.validate_identity_shape(value["plannerIdentity"])
    total = 0
    for prefix, _domain in _BODY_PROFILES:
        shape._digest(value[prefix + "Digest"])
        count = value[prefix + "ByteCount"]
        shape._integer(count, MAX_ORIGINAL_BYTES, minimum=2)
        total += count
    if total > MAX_ORIGINAL_BYTES:
        _fail("delivery plan detached commitments exceed the original aggregate bound")
    for field in ("issuedAtEpochNs", "expiresAtEpochNs"):
        shape._integer(value[field], minimum=1)
    if not 0 < value["expiresAtEpochNs"] - value["issuedAtEpochNs"] <= authority.VERIFIER_RESPONSE_MAX_AGE_NS:
        _fail("delivery plan lifetime exceeds the source ceiling")


def validate_envelope_shape(value):
    shape._object(value, ENVELOPE_FIELDS, "activation delivery plan envelope")
    shape._literal(value["schema"], ENVELOPE_SCHEMA)
    shape._base64url(value["signatureBase64Url"], signature=True)
    validate_payload_shape(value["payload"])


class _Capture(evidence.capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            _fail("delivery plan exceeds its closed structure bound")
        result = super().visit(value, depth, ancestors)
        if self.nodes > MAX_NODES:
            _fail("delivery plan exceeds its closed node bound")
        return result


def _capture(value, *, envelope=False, work):
    if type(envelope) is not bool:
        _fail("delivery plan wire selector is not an exact boolean")
    owned = _Capture(evidence.capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(value)
    (validate_envelope_shape if envelope else validate_payload_shape)(owned)
    return owned


def _encode_on_work(value, *, envelope=False, work):
    owned = _capture(value, envelope=envelope, work=work)
    return evidence.capability._wire(owned, evidence.capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _decode_on_work(raw, *, envelope=False, work):
    if type(envelope) is not bool or type(raw) is not bytes or not 2 <= len(raw) <= MAX_BYTES:
        _fail("delivery plan requires a bounded immutable original and fixed wire selector")
    evidence.capture._SharedLedger(work)
    value = evidence.wire._decode_object(raw, work=work, maximum_bytes=MAX_BYTES,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    owned = _capture(value, envelope=envelope, work=work)
    evidence.capability._canonical(raw, owned, evidence.capture._SharedLedger(work), MAX_BYTES, MAX_NODES)
    return owned


def _body_commitments_on_work(*, proof_bytes, context_bytes, inputs_bytes, transition_bytes, work):
    """Commit held originals; inputs_bytes contains only closed digest/count facts."""
    evidence.capture._SharedLedger(work)
    originals = (proof_bytes, context_bytes, inputs_bytes, transition_bytes)
    if (any(type(raw) is not bytes or not 2 <= len(raw) <= MAX_ORIGINAL_BYTES for raw in originals)
            or sum(len(raw) for raw in originals) > MAX_ORIGINAL_BYTES):
        _fail("delivery plan bodies exceed their immutable original bounds")
    result = {}
    for (prefix, domain), raw in zip(_BODY_PROFILES, originals):
        result[prefix + "Digest"] = evidence.plan._frame(domain, (raw,), work)
        result[prefix + "ByteCount"] = len(raw)
    return result
