"""Closed token-free activation plan wire, not signature or replay authority.

The original owner supplies actual-original commitments and independently
admitted request/configuration/key/time scopes. This module only owns bounded
graphs, canonically encodes/decodes them and commits exact detached bytes. It
does not admit those scopes, expose secret originals, sign, replay, sample a
clock, write custody or allocate another work allowance.
"""
from __future__ import annotations

from catchplate import authority_contract as authority
from catchplate import authority_primary_contract as primary
from catchplate import authority_revocation_plan_contract as shape
from catchplate import authority_webauthn_evidence as evidence


OPERATION = "oidc.session.activate"
SCHEMA = "catchplate.policyAuthorityOidcSessionActivationPlan/v2"
PAYLOAD_SCHEMA = SCHEMA
ENVELOPE_SCHEMA = "catchplate.signedPolicyAuthorityOidcSessionActivationPlan/v2"
SIGNATURE_DOMAIN = "catchplate.policyAuthorityOidcSessionActivationPlanSignature/v2"
IDENTITY_DOMAIN = "catchplate.policyAuthorityOidcSessionActivationPlanIdentity/v2"
PROOF_DOMAIN = "catchplate.policyAuthorityOidcSessionActivationProof/v1"
CONTEXT_DOMAIN = "catchplate.policyAuthorityOidcSessionActivationContext/v1"
INPUTS_DOMAIN = "catchplate.policyAuthorityOidcSessionActivationPrivateInputs/v2"
TRANSITION_DOMAIN = "catchplate.policyAuthorityOidcSessionActivationTransition/v1"
MAX_BYTES = 16 * 1024
MAX_NODES = 128
MAX_DEPTH = 4
MAX_ORIGINAL_BYTES = authority.MAX_RESULT_BYTES

PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "operation", "requestDigest", "operationId",
    "operationManifestDigest", "queryManifestDigest", "authorizationManifestDigest", "handlerContractDigest",
    "configurationDigest", "plannerIdentity", "plannerSpkiDigest", "proofDigest", "proofByteCount",
    "contextDigest", "contextByteCount", "inputsDigest", "inputsByteCount", "transitionDigest",
    "transitionByteCount", "issuedAtEpochNs", "expiresAtEpochNs"})
ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
_BODY_PROFILES = (
    ("proof", PROOF_DOMAIN), ("context", CONTEXT_DOMAIN),
    ("inputs", INPUTS_DOMAIN), ("transition", TRANSITION_DOMAIN),
)
# Source-derived static pins match the existing manifest producers. They are
# not learned from a plan, database or incoming evaluation context.
_OPERATION_MANIFEST_DIGEST = authority.OPERATION_MANIFEST_DIGEST
_QUERY_MANIFEST_DIGEST = primary.source_query_manifest_digest()
_AUTHORIZATION_MANIFEST_DIGEST = primary.source_authorization_manifest_digest()
_HANDLER_CONTRACT_DIGEST = authority.handler_contract_digest(OPERATION)


class OidcSessionActivationPlanContractError(ValueError):
    pass


def _fail(message):
    raise OidcSessionActivationPlanContractError(message)


def _source_fields():
    """Fresh fixed source metadata only, not currentness or caller authority."""
    return {"schema": SCHEMA, "sourceRevision": authority.SOURCE_REVISION, "operation": OPERATION,
        "operationManifestDigest": _OPERATION_MANIFEST_DIGEST,
        "queryManifestDigest": _QUERY_MANIFEST_DIGEST,
        "authorizationManifestDigest": _AUTHORIZATION_MANIFEST_DIGEST,
        "handlerContractDigest": _HANDLER_CONTRACT_DIGEST}


def validate_payload_shape(value):
    """Validate an already owned exact payload without any native callback."""
    shape._object(value, PAYLOAD_FIELDS, "activation plan payload")
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
        _fail("activation plan detached byte counts exceed the original aggregate bound")
    for field in ("issuedAtEpochNs", "expiresAtEpochNs"):
        shape._integer(value[field], minimum=1)
    if not 0 < value["expiresAtEpochNs"] - value["issuedAtEpochNs"] <= authority.VERIFIER_RESPONSE_MAX_AGE_NS:
        _fail("activation plan lifetime exceeds its source bound")


def validate_envelope_shape(value):
    """Close the envelope; its signature is not verified by this function."""
    shape._object(value, ENVELOPE_FIELDS, "activation plan envelope")
    shape._literal(value["schema"], ENVELOPE_SCHEMA)
    shape._base64url(value["signatureBase64Url"], signature=True)
    validate_payload_shape(value["payload"])


class _Capture(evidence.capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            _fail("activation plan exceeds its closed structure bound")
        result = super().visit(value, depth, ancestors)
        if self.nodes > MAX_NODES:
            _fail("activation plan exceeds its closed node bound")
        return result


def _capture(value, *, envelope=False, work):
    """Own one bounded graph before the caller invokes signatures or replay."""
    if type(envelope) is not bool:
        _fail("activation plan wire selector is not an exact boolean")
    ledger = evidence.capture._SharedLedger(work)
    owned = _Capture(ledger, maximum_bytes=MAX_BYTES).visit(value)
    if envelope:
        validate_envelope_shape(owned)
    else:
        validate_payload_shape(owned)
    return owned


def _encode_on_work(value, *, envelope=False, work):
    """Return canonical original bytes, never a signed/admitted observation."""
    owned = _capture(value, envelope=envelope, work=work)
    return evidence.capability._wire(owned, evidence.capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _decode_on_work(raw, *, envelope=False, work):
    """Reject duplicate/noncanonical/unknown fields on the original allowance."""
    if type(envelope) is not bool:
        _fail("activation plan wire selector is not an exact boolean")
    evidence.capture._SharedLedger(work)
    if type(raw) is not bytes or not 2 <= len(raw) <= MAX_BYTES:
        _fail("activation plan requires bounded immutable original bytes")
    value = evidence.wire._decode_object(raw, work=work, maximum_bytes=MAX_BYTES,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    owned = _capture(value, envelope=envelope, work=work)
    evidence.capability._canonical(raw, owned, evidence.capture._SharedLedger(work), MAX_BYTES, MAX_NODES)
    return owned


def _body_commitments_on_work(*, proof_bytes, context_bytes, inputs_bytes, transition_bytes, work):
    """Commit exact held bodies without accepting their alleged digests.

    inputs_bytes is the owner's canonical digest/count projection of actual
    originals, NOT an encoding of old/new token plaintext or the custody key.
    The owner must enforce that closed projection before invoking this opaque
    byte helper. No detached graph is decoded or semantically admitted here.
    """
    evidence.capture._SharedLedger(work)
    originals = (proof_bytes, context_bytes, inputs_bytes, transition_bytes)
    if any(type(raw) is not bytes or not 2 <= len(raw) <= MAX_ORIGINAL_BYTES for raw in originals):
        _fail("activation plan bodies are not bounded immutable originals")
    if sum(len(raw) for raw in originals) > MAX_ORIGINAL_BYTES:
        _fail("activation plan bodies exceed the original aggregate bound")
    # Complete original inventory and every exact immutable body are held
    # before the first native digest callback can run.
    result = {}
    for (prefix, domain), raw in zip(_BODY_PROFILES, originals):
        result[prefix + "Digest"] = evidence.plan._frame(domain, (raw,), work)
        result[prefix + "ByteCount"] = len(raw)
    return result
