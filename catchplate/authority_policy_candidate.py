"""Closed candidate intake originals, separate from activation and Setup CAS.

Identifiers and receipt hashes are commitments, never caller evidence of a
successful native operation. No operation permits candidate traffic.
"""
from collections.abc import Mapping
import re

from catchplate import authority_oauth_setup as scalar
from catchplate import authority_publication_approval as assertions

canonical, require, digest, sha256 = scalar.canonical, scalar.require, scalar.digest, scalar.sha256
OP_CLAIM = "policy.candidate.generation-claim"
OP_PUBLISH = "policy.candidate.generation-publish"
OPERATIONS = frozenset({OP_CLAIM, OP_PUBLISH})
ASSERTION_OPERATIONS = frozenset({OP_CLAIM})
TABLE = "policy_shadow_generation_claims"
OPTIONS_SCHEMA = "catchplate.policyCandidateIntakeOptions/v1"
HTTP_SCHEMA = "catchplate.policyCandidateIntakeRequest/v1"
MAX_ORIGINAL_BYTES = 1024 * 1024
MAX_ARGUMENT_BYTES = 3 * 1024 * 1024
FIELDS = frozenset({"actor_id", "control_plane_configuration_digest", "request", "credential_policy"})
CONTEXT_FIELDS = frozenset({"candidateId", "canaryId", "artifactEnvelopeDigest", "assignmentEnvelopeDigest",
    "loadReceiptEnvelopeDigest", "runtimeAttestationHandoffDigest", "instanceId", "bootId", "memberOrdinal", "shadowKeySha256"})
CLAIM_FIELDS = frozenset({"context", "managementRequestOriginal", "issuedAtEpochNs", "expiresAtEpochNs"})
ROW_FIELDS = frozenset({"request_id", "replay_id", "management_handoff_id", "actor_id", "configuration_digest",
    "context_json", "management_request_json", "request_identity_digest", "payload_digest", "request_digest",
    "issued_at_epoch_ns", "expires_at_epoch_ns", "created_at", "publication_envelope_digest"})
MANAGEMENT_FIELDS = frozenset({"apiVersion", "activePolicyBundle", "candidatePolicyBundle", "assignment", "loadReceipt",
    "requestId", "runtimeAttestation", "managementHandoffId", "replayId"})


def text(value, maximum=512):
    return scalar.text(value, maximum)


def epoch(value):
    require(type(value) is int and 0 < value <= 9_223_372_036_854_775_807)
    return value


def context(value):
    require(type(value) is dict and set(value) == CONTEXT_FIELDS)
    for name in CONTEXT_FIELDS - {"candidateId", "canaryId", "instanceId", "memberOrdinal"}:
        digest(value[name])
    for name in ("candidateId", "canaryId", "instanceId"):
        text(value[name], 256)
    require(type(value["memberOrdinal"]) is int and 1 <= value["memberOrdinal"] <= 64)
    return dict(value)


def management_original(value):
    require(type(value) is str and 0 < len(value) <= MAX_ORIGINAL_BYTES)
    raw = value.encode("ascii")
    document = scalar.document(raw, MAX_ORIGINAL_BYTES)
    require(type(document) is dict and set(document) == MANAGEMENT_FIELDS
        and document["apiVersion"] == "catchplate.policyShadowGenerationInstall/v2"
        and canonical(document) == raw)
    scalar.identifier(document["requestId"])
    require(re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", document["requestId"]) is not None)
    for name, prefix in (("replayId", "replay:"), ("managementHandoffId", "handoff:")):
        require(type(document[name]) is str and document[name].startswith(prefix))
        digest("sha256:" + document[name][len(prefix):])
    require(all(type(document[name]) is dict for name in
        ("activePolicyBundle", "candidatePolicyBundle", "assignment", "loadReceipt", "runtimeAttestation")))
    return document


def claim_request(value):
    require(type(value) is dict and set(value) == CLAIM_FIELDS)
    context(value["context"]); management_original(value["managementRequestOriginal"])
    issued, expires = epoch(value["issuedAtEpochNs"]), epoch(value["expiresAtEpochNs"])
    require(issued % 1000 == 0 and expires % 1000 == 0 and 0 < expires - issued <= 30_000_000_000)
    return dict(value)


def arguments(operation, value, *, typed=False):
    require(operation in OPERATIONS and isinstance(value, Mapping))
    fields = FIELDS if operation == OP_CLAIM else FIELDS - {"credential_policy"}
    allowed = fields | ({"businessIntent"} if typed else set())
    if typed and operation == OP_CLAIM:
        allowed |= {"authn_evidence"}
    require(fields <= set(value) <= allowed and (not typed or "businessIntent" in value))
    text(value["actor_id"], 1024); digest(value["control_plane_configuration_digest"])
    if operation == OP_CLAIM:
        require(value["actor_id"].startswith("oidc:"))
        assertions.policy(value["credential_policy"])
        claim_request(value["request"])
    elif operation == OP_PUBLISH:
        request = value["request"]
        require(type(request) is dict and set(request) == {"claimOriginal", "record", "verificationInputs"})
        require(type(request["claimOriginal"]) is str)
        row_original(scalar.document(request["claimOriginal"].encode("ascii"), 2 * MAX_ORIGINAL_BYTES))
        require(type(request["record"]) is dict)
        require(type(request["verificationInputs"]) is dict and set(request["verificationInputs"]) == {
            "generation_runtime_attestation_verification", "generation_publication"})
        from catchplate import db
        for prestate in request["verificationInputs"].values():
            require(type(prestate) is dict and set(prestate) == {"key", "head", "revocationSequence"}
                and type(prestate["key"]) is dict and set(prestate["key"]) == set(db._POLICY_AUTHORITY_TRUSTED_KEY_COLUMNS)
                and type(prestate["head"]) is dict and set(prestate["head"]) == set(db._POLICY_AUTHORITY_TRUSTED_KEY_HEAD_COLUMNS)
                and type(prestate["revocationSequence"]) is int and 0 <= prestate["revocationSequence"] <= 9_223_372_036_854_775_807)
    original = {name: value[name] for name in fields}
    require(len(canonical(original)) <= MAX_ARGUMENT_BYTES)
    return original


def row_original(row):
    value = dict(row)
    require(set(value) == ROW_FIELDS)
    scalar.identifier(value["request_id"])
    request = management_original(value["management_request_json"])
    require(all(value[column] == request[field] for column, field in
        (("request_id", "requestId"), ("replay_id", "replayId"), ("management_handoff_id", "managementHandoffId"))))
    require(value["payload_digest"] == sha256(value["management_request_json"].encode("ascii")))
    context(scalar.document(value["context_json"].encode("ascii"), 8192))
    for name in ("configuration_digest", "request_identity_digest", "request_digest"):
        digest(value[name])
    text(value["actor_id"], 1024); scalar.epoch(value["created_at"])
    require(0 < epoch(value["expires_at_epoch_ns"]) - epoch(value["issued_at_epoch_ns"]) <= 30_000_000_000)
    if value["publication_envelope_digest"] is not None:
        digest(value["publication_envelope_digest"])
    raw = canonical(value)
    require(len(raw) <= 2 * MAX_ORIGINAL_BYTES)
    return raw


def generation_identity(*, actor, bound, request, originals):
    identity_request = {name: value for name, value in request.items() if name not in {"replayId", "managementHandoffId"}}
    return {"activePolicyBundleSha256": originals["active_bundle_digest"],
        "activePolicySha256": originals["active"]["policy_hash"], "actorId": actor,
        "assignmentSha256": bound["assignmentEnvelopeDigest"], "bootIdSha256": bound["bootId"],
        "candidateId": bound["candidateId"], "candidatePolicyBundleSha256": originals["candidate_bundle_digest"],
        "candidatePolicySha256": originals["artifact"]["policy_hash"], "canaryId": bound["canaryId"],
        "instanceId": bound["instanceId"], "loadReceiptSha256": bound["loadReceiptEnvelopeDigest"],
        "requestId": request["requestId"], "requestIdentitySha256": sha256(canonical(identity_request)),
        "runtimeAttestationChainSha256": originals["handoff"]["attestation_chain_digest"]}


def request_digest(operation, value):
    from catchplate import authority_contract as contract
    from catchplate import authority_request_commitment as commitment
    values = arguments(operation, value, typed="businessIntent" in value)
    typed = {**values, "businessIntent": contract.synthesize_business_intent(operation, values)}
    return commitment.framed_digest("catchplate.policyAuthorityV9Request/v1", canonical({
        "schema": "catchplate.policyAuthorityV9Authorization/v1", "operation": operation,
        "handler": contract.operation_spec(operation)["handler"], "operationManifestDigest": contract.OPERATION_MANIFEST_DIGEST,
        "arguments": commitment._authorization_arguments(typed)}))
