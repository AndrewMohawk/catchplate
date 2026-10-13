"""Purpose-specific native compound JIT sealing proof admission.

The verifier and planner each call verify_original with their own admitted
configuration and retained original deadline before native pending retention.
It checks real assignment/signature/Nitro evidence, not a supplied success
carrier, and grants neither an execution capability nor pending-row,
review-open or release rights. The compound writer remains separately gated;
no service is enabled here.
"""
from __future__ import annotations

import hashlib
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from scripts import verify_nitro_tee as nitro
from serverware import authority_contract as contract
from serverware import authority_credential_currentness_policy as native
from serverware import authority_native_jit_review_assignment as assignment
from serverware import authority_release_private_request as private
from serverware import native_jit_review_material as material

FIELD = assignment.FIELD
SCHEMA = "serverware.nativeJitReviewCustodyAuthorityPolicy/v1"
TRUST_SCHEMA = "serverware.nativeJitReviewNativeTrustRoots/v1"
STATEMENT_SCHEMA = "serverware.nativeReleaseJitReviewStatement/v1"
SIGN_OPERATION = "nativeReleaseJitReview.sign/v1"
SIGNATURE_DOMAIN = STATEMENT_SCHEMA.encode("ascii") + b"\0"
ATTESTATION_DOMAIN = b"serverware/native-release-jit-review-attestation/v1\0"
MAX_POLICY_BYTES = 512 * 1024
MAX_EVIDENCE_BYTES = 128 * 1024
MAX_ORIGINAL_BYTES = 512 * 1024
MAX_PAIR_BYTES = 1024 * 1024
POLICY_FIELDS = frozenset({"schema", "sourceContractDigest", "reservationTtlSeconds",
    "operationMaxSeconds", "attemptCapacity", "trustRoots", "deploymentId", "assignmentAuthorizer", "target"})
IDENTITY_FIELDS = frozenset({"holderId", "bootId", "keyId", "controlPlaneResponseSigningKeyId",
    "releaseRecordSha256", "policyHash", "configurationSha256", "caCertificateSha256",
    "caPublicKeySpkiSha256", "expectedBinaryDigest"})
BINDING_FIELDS = IDENTITY_FIELDS | {"sourceContractDigest", "controlPlaneConfigurationDigest", "ownerScopeDigest",
    "deploymentId", "instanceId", "requestDigest", "operationId", "publicRequestSha256", "pairSha256",
    "secretKekId", "challenge", "issuedAtEpochNs", "expiresAtEpochNs", "documentExpiresAtEpochNs",
    "parentRequestSha256", "parentRequestDigest", "parentOperationId"}
STATEMENT_FIELDS = BINDING_FIELDS | {"apiVersion", "operation"}
_SCOPE_DIGESTS = ("releaseRecordSha256", "policyHash", "configurationSha256",
    "caCertificateSha256", "caPublicKeySpkiSha256")
canonical, sha256, require = assignment.canonical, assignment.sha256, assignment.require
AdmissionError = assignment.AdmissionError


def _trust(value):
    require(type(value) is dict and value.get("apiVersion") == TRUST_SCHEMA)
    # Reuse only common Nitro certificate grammar. All roots still come from
    # this independently admitted JIT purpose, never the currentness policy.
    return native._trust({**value, "apiVersion": native.TRUST_SCHEMA})


@assignment.checked
def validate_policy(value, *, payload, root_key=None):
    """Optional cold purpose; existing release configurations stay unchanged."""
    if value is None:
        require(type(payload) is dict and FIELD not in payload)
        return None
    require(type(value) is dict)
    selected = assignment.document(canonical(value).decode("ascii"), MAX_POLICY_BYTES)
    require(set(selected) == POLICY_FIELDS and selected["schema"] == SCHEMA
        and selected["sourceContractDigest"] == contract.OPERATION_MANIFEST_DIGEST)
    assignment.digest(selected["sourceContractDigest"])
    assignment.deployment(selected["deploymentId"])
    assignment.integer(selected["reservationTtlSeconds"], maximum=300)
    assignment.integer(selected["operationMaxSeconds"], maximum=30)
    assignment.integer(selected["attemptCapacity"], maximum=16)
    _trust(selected["trustRoots"])
    target = assignment.target(selected["target"])
    assignment.authorizer(selected["assignmentAuthorizer"], payload=payload, root_key=root_key,
        response_key_id=target["controlPlaneResponseSigningKeyId"])
    return selected


def _statement(value):
    require(type(value) is dict and set(value) == STATEMENT_FIELDS
        and value["apiVersion"] == STATEMENT_SCHEMA and value["operation"] == SIGN_OPERATION)
    non_digests = {"bootId", "deploymentId", "instanceId", "secretKekId", "challenge",
        "issuedAtEpochNs", "expiresAtEpochNs", "documentExpiresAtEpochNs"}
    for name in BINDING_FIELDS - non_digests:
        assignment.digest(value[name])
    require(assignment.decoded(value["bootId"], 32, 32) != bytes(32)
        and assignment.decoded(value["challenge"], 32, 32) != bytes(32))
    assignment.deployment(value["deploymentId"])
    require(assignment.text(value["instanceId"], 4096).startswith("spiffe://"))
    assignment.kek(value["secretKekId"])
    issued, expires, documents = (assignment.integer(value[name]) for name in
        ("issuedAtEpochNs", "expiresAtEpochNs", "documentExpiresAtEpochNs"))
    require(issued < expires <= documents and expires - issued <= 30_000_000_000)
    return value


@assignment.checked
def authority_evidence(value):
    """Closed literal evidence only; this parser does not verify provenance."""
    proof = assignment.document(value, MAX_EVIDENCE_BYTES)
    require(set(proof) == {"statement", "signature", "nativeKeyEvidence", "assignmentOriginal"})
    _statement(proof["statement"])
    require(type(proof["signature"]) is str and proof["signature"].startswith("ed25519:"))
    assignment.decoded(proof["signature"][8:], 64, 64)
    evidence = proof["nativeKeyEvidence"]
    require(type(evidence) is dict and set(evidence) ==
        {"apiVersion", "responseProofPublicKey", "attestationDocumentB64"}
        and evidence["apiVersion"] == "serverware.nativeResponseProofKeyEvidence/v1")
    require(assignment.decoded(evidence["responseProofPublicKey"], 32, 32) != bytes(32))
    assignment.decoded(evidence["attestationDocumentB64"], 12 * 1024)
    assignment.original(proof["assignmentOriginal"])
    return proof


def _broker_configuration(policy, selected_assignment, configuration_digest):
    selected = selected_assignment["assignment"]
    return {"apiVersion": "serverware.nativeJitReviewConfiguration/v1",
        "sourceContractDigest": policy["sourceContractDigest"],
        "controlPlaneConfigurationDigest": configuration_digest,
        "deploymentId": policy["deploymentId"], "instanceId": selected["instanceId"],
        "secretKekId": selected["secretKekId"], "attemptCapacity": policy["attemptCapacity"],
        "identity": {name: selected[name] for name in IDENTITY_FIELDS}}


def _originals(runtime_original, parent_original, child_original, pair_original):
    runtime = assignment.document(runtime_original, MAX_ORIGINAL_BYTES)
    parent = assignment.document(parent_original, MAX_ORIGINAL_BYTES)
    child = assignment.document(child_original, MAX_ORIGINAL_BYTES)
    pair = assignment.document(pair_original, MAX_PAIR_BYTES)
    derived = private.derive_native_requests(runtime)
    require(canonical(derived.parent_request).decode("ascii") == parent_original
        and canonical(derived.child_request).decode("ascii") == child_original)
    _public, documents = private.validate_runtime_input(runtime)
    require(type(pair) is dict and set(pair) == material.PAIR_FIELDS
        and pair["schema"] == material.RELEASE_PAIR_SCHEMA)
    scope = material.validate_release_scope(pair["scope"])
    require(canonical(scope["publicRequest"]) == canonical(child)
        and scope["parentRequestSha256"] == sha256(parent_original.encode("ascii")))
    # The verifier does not own the KEK and never decrypts. The exact signed
    # pair commits to both original plaintexts; the real broker sealed/readback
    # owner and fresh measured-key signature are independently verified below.
    _owned, plaintexts = material._private(scope, documents)
    items = pair["items"]
    require(type(items) is list and len(items) == 2)
    for index, (kind, purpose) in enumerate((("approval-secret-json/v1", "jit-canonical-request"),
            ("approval-review-json/v1", "jit-redacted-display"))):
        item, raw = items[index], plaintexts[index]
        require(type(item) is dict and set(item) == material.ITEM_FIELDS
            and item["opaqueId"] == material._identity(child["requestDigest"], purpose)
            and item["valueKind"] == kind and item["plaintextSha256"] == sha256(raw)
            and type(item["plaintextBytes"]) is int and item["plaintextBytes"] == len(raw))
        material._decoded(item["wrappedKeyNonce"], 12, 12)
        material._decoded(item["wrappedKey"], 48, 48)
        material._decoded(item["ciphertextNonce"], 12, 12)
        material._decoded(item["ciphertext"], material.MAX_PLAINTEXT_BYTES + 16, len(raw) + 16)
    return parent, child, pair


def _bind(policy, selected_assignment, proof, parent, child, pair,
        parent_original, child_original, pair_original, configuration_digest):
    item, selected = proof["statement"], selected_assignment["assignment"]
    parent_arguments, scope = parent["arguments"], pair["scope"]
    require(parent_arguments["native_profile"] is True and parent_arguments["policy_aware_profile"] is False
        and parent_arguments["require_jit_grant"] is True and parent_arguments["now_epoch_ms"] is None
        and type(parent_arguments["reservation_ttl_seconds"]) is int
        and parent_arguments["reservation_ttl_seconds"] == policy["reservationTtlSeconds"]
        and parent_arguments["actor_id"] == selected["instanceId"]
        and parent_arguments["durable_policy_binding"]["actorId"] == selected["instanceId"]
        and parent_arguments["policy_hash"] == selected["policyHash"])
    for name in IDENTITY_FIELDS | {"instanceId", "secretKekId"}:
        require(item[name] == selected[name])
    broker = _broker_configuration(policy, selected_assignment, configuration_digest)
    require(item["deploymentId"] == policy["deploymentId"]
        and item["sourceContractDigest"] == policy["sourceContractDigest"]
        and item["controlPlaneConfigurationDigest"] == configuration_digest
        and item["ownerScopeDigest"] == sha256(canonical(broker))
        and item["parentRequestSha256"] == sha256(parent_original.encode("ascii"))
        and item["parentRequestDigest"] == parent["requestDigest"]
        and item["parentOperationId"] == parent["operationId"]
        and item["requestDigest"] == child["requestDigest"] and item["operationId"] == child["operationId"]
        and item["publicRequestSha256"] == sha256(child_original.encode("ascii"))
        and item["pairSha256"] == sha256(pair_original.encode("ascii"))
        and pair["keyId"] == selected["secretKekId"])
    for name in ("sourceContractDigest", "controlPlaneConfigurationDigest", "ownerScopeDigest",
            "parentRequestSha256", "issuedAtEpochNs", "documentExpiresAtEpochNs"):
        require(scope[name] == item[name])
    require(scope["sealExpiresAtEpochNs"] == item["expiresAtEpochNs"]
        and selected_assignment["issuedAtEpochNs"] <= item["issuedAtEpochNs"]
        < item["expiresAtEpochNs"] <= selected_assignment["expiresAtEpochNs"]
        and item["expiresAtEpochNs"] - item["issuedAtEpochNs"] <= policy["operationMaxSeconds"] * 1_000_000_000
        and item["documentExpiresAtEpochNs"] <= item["issuedAtEpochNs"]
            + child["arguments"]["pending_ttl_seconds"] * 1_000_000_000)


@assignment.checked
def verify_original(*, runtime_original, parent_original, child_original, pair_original,
        evidence_original, configuration_payload, root_key, now_epoch_ns, deadline_monotonic_ns):
    """Real cryptographic admission against the caller's original live bound.

    No verified object escapes. Neither this call nor its literal evidence can
    stand in for current DB roots, a writer capability or review disclosure.
    """
    from serverware.authority_policy_canary_policy import full_configuration_digest

    before_mono, before_wall = time.monotonic_ns(), time.time_ns()
    require(before_mono < assignment.integer(deadline_monotonic_ns)
        and assignment.integer(now_epoch_ns) <= before_wall)
    policy = validate_policy(configuration_payload.get(FIELD), payload=configuration_payload, root_key=root_key)
    require(policy is not None)
    configuration_digest = full_configuration_digest(configuration_payload)
    proof = authority_evidence(evidence_original)
    selected_assignment = assignment.verify_original(proof["assignmentOriginal"],
        configuration_payload=configuration_payload, root_key=root_key, now_epoch_ns=before_wall)
    parent, child, pair = _originals(runtime_original, parent_original, child_original, pair_original)
    _bind(policy, selected_assignment, proof, parent, child, pair,
        parent_original, child_original, pair_original, configuration_digest)
    item, expected = proof["statement"], selected_assignment["assignment"]
    require(item["issuedAtEpochNs"] <= now_epoch_ns <= before_wall < item["expiresAtEpochNs"])
    # Clip only this verification's local bound. A shorter seal or assignment
    # interval does not require replacing or extending the caller's original
    # deadline; sampling happens once so elapsed work can never renew the cap.
    effective_deadline = min(deadline_monotonic_ns,
        before_mono + item["expiresAtEpochNs"] - before_wall)
    raw_key = assignment.decoded(proof["nativeKeyEvidence"]["responseProofPublicKey"], 32, 32)
    key = Ed25519PublicKey.from_public_bytes(raw_key)
    require(sha256(key.public_bytes(serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)) == expected["keyId"])
    signature = assignment.decoded(proof["signature"][8:], 64, 64)
    statement_raw = canonical(item)
    key.verify(signature, SIGNATURE_DOMAIN + statement_raw)
    nonce = hashlib.sha256(ATTESTATION_DOMAIN + assignment.decoded(item["challenge"], 32, 32)
        + hashlib.sha256(statement_raw).digest() + signature).digest()
    boot_binding = hashlib.sha256(b"serverware/native-proof-custody-boot/v1\0"
        + assignment.decoded(expected["bootId"], 32, 32) + bytes.fromhex(expected["keyId"][7:])
        + bytes.fromhex(expected["controlPlaneResponseSigningKeyId"][7:])).digest()
    user_data = b"serverware/enclave-runtime-key-binding/v1\0\x04" + b"".join(
        bytes.fromhex(expected[name][7:]) for name in _SCOPE_DIGESTS) + hashlib.sha256(raw_key).digest() + boot_binding
    document = assignment.decoded(proof["nativeKeyEvidence"]["attestationDocumentB64"], 12 * 1024)
    roots, crls, certificate_profile = _trust(policy["trustRoots"])
    verified, _, _, _, _ = nitro._verify_nitro_document_common(document, claims=None,
        expected_user_data_bytes=user_data, challenge=nonce, expected_pcrs=expected["expectedPcrs"],
        expected_eif=expected["expectedEif"], roots=roots, crls=crls, certificate_profile=certificate_profile,
        expected_module_id=expected["expectedModuleId"], now=before_wall // 1_000_000_000,
        max_age=expected["maxAgeSeconds"], future_skew=expected["futureSkewSeconds"], native_profile=True)
    require(type(verified["public_key"]) is bytes and verified["public_key"] == raw_key)
    after_wall, after_mono = time.time_ns(), time.monotonic_ns()
    require(before_mono <= after_mono < effective_deadline
        and before_wall <= after_wall < item["expiresAtEpochNs"]
        and full_configuration_digest(configuration_payload) == configuration_digest)
