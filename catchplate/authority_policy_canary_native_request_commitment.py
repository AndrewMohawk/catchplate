"""Actual later facts computation; never the earlier native sampling HMAC.

The independently assigned native Ledger key signs this existing computation
purpose. The receiver checks the full original and exact protected generation;
it does not recompute HMAC, claim storage from a SELECT, or grant any effect.
"""
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from catchplate import authority_policy_canary as p
from catchplate import authority_policy_canary_native_opening as opening
from catchplate import authority_policy_canary_native_observation_originals as originals

PROFILE = "catchplate.nativeProtectedRequestCommitment/v1"
COMPUTATION = "catchplate.nativeShadowCommitRequestComputation/v1"
DISPATCH = "catchplate.policyCustodyProductionDispatch/v4"
DOMAIN = b"catchplate.nativeShadowCommitRequestComputation.signature/v1"
BINDING = ("apiVersion", "operation", "operationIdSha256", "requestSha256", "durableRequestSha256",
    "terminationFenceSha256", "productionConfigurationBindingSha256", "kernelDriverIdentitySha256",
    "retainedDescriptorSetSha256", "driverGenerationReceiptSha256", "openedAtBoottimeNanos",
    "operationDeadlineBoottimeNanos", "cleanupDeadlineBoottimeNanos", "replayIdSha256")


def artifact(value, kind):
    originals.exact(value, {"apiVersion", "kind", "canonicalBytesBase64", "canonicalBytesLength",
        "canonicalBytesSha256", "artifactSha256"})
    p.require(value["apiVersion"] == DISPATCH and value["kind"] == kind)
    raw = p.decoded(value["canonicalBytesBase64"], originals.MAX_BYTES)
    p.require(0 < len(raw) == originals.integer(value["canonicalBytesLength"], 1)
        and p.sha256(raw) == value["canonicalBytesSha256"]
        and value["artifactSha256"] == opening.material("catchplate.policyCustodyProductionArtifact/v4",
            [DISPATCH, kind, len(raw), value["canonicalBytesSha256"]]))
    decoded = p.document(raw, originals.MAX_BYTES)
    p.require(p.canonical(decoded) == raw)
    originals.bounded(decoded)
    return decoded


def shape(value):
    originals.exact(value, {"apiVersion", "openingReceiptSha256", "samplingCommitmentSha256", "computationOriginal"})
    p.require(value["apiVersion"] == PROFILE)
    p.digest(value["openingReceiptSha256"]); p.digest(value["samplingCommitmentSha256"])
    computation = originals.exact(value["computationOriginal"], {"apiVersion", "nativeGrantSha256",
        "request", "result", "resultSha256", "computedAtBoottimeNanos", "signatureBase64url"})
    p.require(computation["apiVersion"] == COMPUTATION)
    p.digest(computation["nativeGrantSha256"])
    request = originals.exact(computation["request"], {"operation", "body"})
    p.require(request["operation"] == "commit-request")
    body = originals.exact(request["body"], {"binding", "facts", "context"})
    binding = originals.exact(body["binding"], set(BINDING) | {"bindingSha256"})
    p.require(binding["apiVersion"] == DISPATCH and binding["operation"] == "commit-request")
    for name in BINDING[2:10] + ("replayIdSha256", "bindingSha256"):
        p.digest(binding[name])
    opened, deadline, cleanup = (originals.integer(binding[name], 1) for name in BINDING[10:13])
    p.require(opened <= originals.integer(computation["computedAtBoottimeNanos"], 1) < deadline < cleanup
        and binding["bindingSha256"] == opening.material("catchplate.policyCustodyProductionDispatchBinding/v4",
            [binding[name] for name in BINDING])
        and binding["replayIdSha256"] == opening.material("catchplate.policyCustodyProductionReplay/v4",
            [binding[name] for name in ("operation", "operationIdSha256", "requestSha256",
                "durableRequestSha256", "productionConfigurationBindingSha256")]))
    facts = artifact(body["facts"], "protected-request-facts")
    context = artifact(body["context"], "request-commitment-context")
    result = originals.exact(computation["result"], {"outcome", "body"})
    p.require(result["outcome"] == "artifact" and p.sha256(p.canonical(result)) == computation["resultSha256"])
    commitment = artifact(result["body"], "request-commitment")
    originals.exact(facts, {"method", "scheme", "authority", "pathCommitment", "queryCommitment", "headerCommitments",
        "bodyCommitment", "principalCommitment", "credentialCommitment", "routeSha256", "compiledSemanticProfileSha256", "operation"})
    originals.identifier(facts["method"])
    p.require(facts["scheme"] in {"http", "https"} and facts["operation"] in {
        "read", "search", "write", "publish", "delete", "administrative"})
    # This new producer commits the original authority/path/query/headers/body;
    # it never substitutes the credential-bearing rewritten dispatch.
    for name in ("authority", "pathCommitment", "bodyCommitment", "principalCommitment", "routeSha256",
            "compiledSemanticProfileSha256"):
        p.digest(facts[name])
    for name in ("queryCommitment", "credentialCommitment"):
        if facts[name] is not None:
            p.digest(facts[name])
    p.require(type(facts["headerCommitments"]) is list and len(facts["headerCommitments"]) <= 128)
    for item in facts["headerCommitments"]:
        p.digest(item)
    originals.exact(context, {"assignment_payload_sha256", "assignment_revision", "boot_id_sha256",
        "ingress_sequence", "observed_at_unix_nanos"})
    p.digest(context["assignment_payload_sha256"]); p.digest(context["boot_id_sha256"])
    for name in ("assignment_revision", "ingress_sequence", "observed_at_unix_nanos"):
        originals.integer(context[name], 1)
    originals.exact(commitment, {"algorithm", "domain", "keyId", "keyEpoch", "assignmentPayloadSha256",
        "assignmentRevision", "bootIdSha256", "ingressSequence", "observedAtUnixNanos", "commitment"})
    p.require(commitment["algorithm"] == "HMAC-SHA-256"
        and commitment["domain"] == "catchplate.policyShadowRequestCommitment/v1")
    tag = commitment["commitment"]
    p.require(type(tag) is str and len(tag) == 76 and tag.startswith("hmac-sha256:")
        and all(byte in "0123456789abcdef" for byte in tag[12:]))
    for native, retained in (("assignmentPayloadSha256", "assignment_payload_sha256"),
            ("assignmentRevision", "assignment_revision"), ("bootIdSha256", "boot_id_sha256"),
            ("ingressSequence", "ingress_sequence"), ("observedAtUnixNanos", "observed_at_unix_nanos")):
        p.require(commitment[native] == context[retained])
    p.digest(commitment["keyId"])
    for name in ("keyEpoch", "assignmentRevision", "ingressSequence", "observedAtUnixNanos"):
        originals.integer(commitment[name], 1)
    p.digest(commitment["assignmentPayloadSha256"]); p.digest(commitment["bootIdSha256"])
    p.decoded(computation["signatureBase64url"], 64, length=64)
    return facts, commitment, binding


def verify(state, record, request_original, receipt, opened, *, assignment, context, publication):
    """Fixed caller has already admitted exact receipt/assignment originals."""
    from catchplate import db, policy_route_authority
    protected = request_original["protectedRequest"]
    # Account for bounded decoded artifact work and the complete assigned-key
    # inventory before hashing/verification. No global kernel ceiling changes.
    state.charge(768 + len(assignment["authorityKeyIndependence"]["bindings"]))
    facts, commitment, binding = shape(protected)
    opening_event, opening_receipt = opened
    p.require(opening_event[0] == opening.EARLY_EVENT
        and opening.early_sampling(opening_event, opening_receipt, opening_event[1]) == "included"
        and protected["openingReceiptSha256"] == opening_receipt["signed_receipt_sha256"]
        and protected["samplingCommitmentSha256"] == opening_receipt["request_commitment_sha256"]
        and receipt["request_commitment_sha256"] == opening_receipt["request_commitment_sha256"]
        and opening_receipt["event_ordinal"] < receipt["event_ordinal"]
        and request_original["factsCapturedAtUnixNanos"] <= receipt["trusted_observed_at_unix_nanos"])
    window = assignment["observationWindow"]
    p.require(commitment["assignmentPayloadSha256"] == context["assignment_payload_digest"]
        and commitment["assignmentRevision"] == assignment["assignmentRevision"]
        and commitment["bootIdSha256"] == context["boot_id"]
        and commitment["ingressSequence"] == receipt["ingress_sequence"] == opening_receipt["ingress_sequence"]
        and commitment["observedAtUnixNanos"] == request_original["factsCapturedAtUnixNanos"]
        and window["startsAtUnixNanos"] <= commitment["observedAtUnixNanos"] < window["endsAtUnixNanos"]
        and commitment["keyId"] == window["requestCommitmentKeyId"]
        and commitment["keyEpoch"] == window["requestCommitmentKeyEpoch"])
    authority = request_original["candidateEvaluation"]["authorityBinding"]
    p.require(authority is not None)
    for fact, name in (("principalCommitment", "principalSha256"), ("routeSha256", "routeSha256"),
            ("compiledSemanticProfileSha256", "compiledSemanticProfileSha256"), ("operation", "operation")):
        p.require(facts[fact] == authority[name])
    management = db.loads(publication["management_request_json"], None)
    routes = management["candidatePolicyBundle"]["routes"]
    selected = [route for route in routes if policy_route_authority.text_digest(route["id"]) == facts["routeSha256"]]
    p.require(len(selected) == 1)
    slot = selected[0].get("credentialRef")
    p.require(facts["credentialCommitment"] == (None if slot is None else policy_route_authority.text_digest(slot)))
    evidence = db.loads(publication["generation_evidence_json"], None)
    p.require(binding["productionConfigurationBindingSha256"] == evidence["custody"]["custodyConfigurationSha256"])
    # Full current assignment pins the actual native Ledger key, not a caller
    # supplied verification key or a legacy Fleet signing permission.
    state.charge(len(routes) + len(facts["headerCommitments"]))
    key, _ = opening._keys(assignment, "custody-ledger-append")
    public = record["signing_public_keys"]["ledger-append"] if "signing_public_keys" in record else record["signing_public_key_base64url"]
    verifier = Ed25519PublicKey.from_public_bytes(p.decoded(public, 32, length=32))
    der = verifier.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    p.require(key["keyId"] == receipt["signing_key_id"] and key["keySpkiSha256"] == receipt["signing_key_spki_sha256"] == p.sha256(der)
        and key["keyMaterialSha256"] == opening.framed("catchplate.policyAuthorityPublicKeyMaterial/v1", b"ed25519", der))
    computation = protected["computationOriginal"]
    payload = p.canonical([computation[name] for name in ("apiVersion", "nativeGrantSha256", "request",
        "result", "resultSha256", "computedAtBoottimeNanos")])
    message = b"catchplate-signature-v1\0" + len(DOMAIN).to_bytes(8, "big") + DOMAIN + len(payload).to_bytes(8, "big") + payload
    verifier.verify(p.decoded(computation["signatureBase64url"], 64, length=64), message)
    return p.sha256(p.canonical(commitment))
