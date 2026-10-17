"""Closed public originals for protected review opening, never admission.

Native challenge/preparation authentication belongs to the independently
configured custody verifier. Authorizations and commit acknowledgments have
different signature domains and keys. This module has no signing or execution
API: accepting an arbitrary public key does not establish its authority.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from catchplate import authority_native_jit_review_assignment as grammar
from catchplate import authority_native_jit_review_custody as sealing

AUTHORIZE = "jit.review-open.authorize"
RECEIPT = "jit.review-open.receipt.issue"
OPERATIONS = (AUTHORIZE, RECEIPT)
CHALLENGE_SCHEMA = "catchplate.nativeJitReviewOpeningChallenge/v1"
PREPARATION_SCHEMA = "catchplate.nativeJitReviewOpeningPreparation/v1"
PREPARATION_OPERATION = "nativeJitReviewOpen.prepare/v1"
AUTHORIZATION_SCHEMA = "catchplate.nativeJitReviewOpeningAuthorization/v1"
ACKNOWLEDGMENT_SCHEMA = "catchplate.nativeJitReviewOpeningCommitAcknowledgment/v1"
REVIEW_FORMAT = "catchplate.nativeJitImmutableReview/v1"
IDENTITY_FIELDS = sealing.IDENTITY_FIELDS | {"browserCertificateSha256", "browserPublicKeySpkiSha256"}
MAX_NATIVE_ORIGINAL = 128 * 1024
MAX_AUTHORITY_ORIGINAL = 64 * 1024
# Three canonical ASCII originals are JSON-string encoded once more. Every
# original byte can require two transport bytes; retain explicit wrapper room.
MAX_HTTP_REQUEST = 2 * (2 * MAX_NATIVE_ORIGINAL + MAX_AUTHORITY_ORIGINAL) + 1024
MAX_HTTP_RESPONSE = 5 * 1024 * 1024
MAX_INTERVAL_NS = 30 * 1_000_000_000
NATIVE_FIELDS = frozenset({"statement", "signature", "nativeKeyEvidence", "assignmentOriginal"})
AUTHORITY_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
CHALLENGE_FIELDS = frozenset({"schema", "reviewId", "approvalRequestId", "sourceContractDigest",
    "controlPlaneConfigurationDigest", "openingAssignmentSha256", "ownerScopeDigest", "identity",
    "nativeOrigin", "portalOrigin", "browserNonceCommitment", "recipientPublicKey", "challenge",
    "issuedAtEpochNs", "expiresAtEpochNs"})
SCOPE_FIELDS = frozenset({"reviewId", "approvalRequestId", "reviewerId", "sessionId",
    "credentialRecordId", "challengeSha256", "parentOriginalSha256", "childOriginalSha256",
    "pairSha256", "sealProofSha256", "sealedSourceContractDigest", "sourceContractDigest",
    "controlPlaneConfigurationDigest", "openingAssignmentSha256", "ownerScopeDigest",
    "browserNonceCommitment", "recipientPublicKey", "documentExpiresAtEpochNs",
    "approvalExpiresAtEpochNs", "sessionExpiresAtEpochNs", "assignmentExpiresAtEpochNs"})
AUTHORIZATION_FIELDS = frozenset({"schema", "operation", "requestDigest", "scope",
    "currentRootVectorDigest", "currentRootHeadDigest", "currentRootSequence",
    "issuedAtEpochNs", "expiresAtEpochNs"})
PREPARATION_FIELDS = frozenset({"schema", "operation", "authorizationSha256", "scope",
    "identity", "reviewDigest", "reviewFormat", "preparedAtEpochNs", "expiresAtEpochNs"})
ACKNOWLEDGMENT_FIELDS = frozenset({"schema", "operation", "requestDigest", "authorizationSha256",
    "preparationSha256", "scope", "reviewDigest", "receiptId", "receiptExpiresAtEpochNs",
    "commitMarkerSha256", "completionReceiptSha256", "afterRootVectorDigest",
    "committedAtEpochNs", "expiresAtEpochNs"})
AUTHORIZE_ARGUMENTS = frozenset({"approval_request_id", "session_id", "challenge_sha256", "businessIntent"})
RECEIPT_ARGUMENTS = AUTHORIZE_ARGUMENTS | {"authorization_sha256", "preparation_sha256"}


def _closed(value, fields):
    grammar.require(type(value) is dict and set(value) == fields)


def _origin(value):
    grammar.text(value, 2048)
    parsed = urlsplit(value)
    grammar.require(parsed.scheme == "https" and parsed.hostname is not None
        and parsed.username is None and parsed.password is None and not parsed.path
        and not parsed.query and not parsed.fragment and value == "https://" + parsed.netloc)
    return value


def _identity(value):
    _closed(value, IDENTITY_FIELDS)
    for name in IDENTITY_FIELDS - {"bootId"}:
        grammar.digest(value[name])
    grammar.require(grammar.decoded(value["bootId"], 32, 32) != bytes(32))


def _interval(value, issued="issuedAtEpochNs"):
    start, end = grammar.integer(value[issued]), grammar.integer(value["expiresAtEpochNs"])
    grammar.require(start < end <= start + MAX_INTERVAL_NS)
    return start, end


def validate_scope(value):
    """Validate public bindings only; no row, key or possession is admitted."""
    _closed(value, SCOPE_FIELDS)
    texts = {"reviewId": 128, "approvalRequestId": 128, "reviewerId": 1024,
        "sessionId": 128, "credentialRecordId": 1024}
    epochs = {name for name in SCOPE_FIELDS if name.endswith("EpochNs")}
    for name, maximum in texts.items():
        grammar.text(value[name], maximum)
    for name in epochs:
        grammar.integer(value[name])
    grammar.require(grammar.decoded(value["recipientPublicKey"], 32, 32) != bytes(32))
    for name in SCOPE_FIELDS - texts.keys() - epochs - {"recipientPublicKey"}:
        grammar.digest(value[name])
    return value


def scope_expiry(value):
    validate_scope(value)
    return min(value[name] for name in SCOPE_FIELDS if name.endswith("EpochNs"))


def validate_challenge_statement(value):
    _closed(value, CHALLENGE_FIELDS)
    grammar.require(value["schema"] == CHALLENGE_SCHEMA)
    for name in ("reviewId", "approvalRequestId"):
        grammar.text(value[name], 128)
    for name in ("sourceContractDigest", "controlPlaneConfigurationDigest",
            "openingAssignmentSha256", "ownerScopeDigest", "browserNonceCommitment"):
        grammar.digest(value[name])
    for name in ("recipientPublicKey", "challenge"):
        grammar.require(grammar.decoded(value[name], 32, 32) != bytes(32))
    _identity(value["identity"])
    _origin(value["nativeOrigin"])
    _origin(value["portalOrigin"])
    grammar.require(value["nativeOrigin"] != value["portalOrigin"])
    _interval(value)
    return value


def validate_preparation_statement(value):
    _closed(value, PREPARATION_FIELDS)
    grammar.require(value["schema"] == PREPARATION_SCHEMA
        and value["operation"] == PREPARATION_OPERATION and value["reviewFormat"] == REVIEW_FORMAT)
    for name in ("authorizationSha256", "reviewDigest"):
        grammar.digest(value[name])
    _identity(value["identity"])
    _, end = _interval(value, "preparedAtEpochNs")
    grammar.require(end <= scope_expiry(value["scope"]))
    return value


def parse_native_original(original, *, purpose):
    """Own exact literal bytes; signatures/quotes remain unverified here."""
    proof = grammar.document(original, MAX_NATIVE_ORIGINAL)
    _closed(proof, NATIVE_FIELDS)
    if purpose == "challenge":
        validate_challenge_statement(proof["statement"])
    elif purpose == "preparation":
        validate_preparation_statement(proof["statement"])
    else:
        grammar.require(False)
    grammar.require(type(proof["signature"]) is str and proof["signature"].startswith("ed25519:"))
    grammar.decoded(proof["signature"][8:], 64, 64)
    evidence = proof["nativeKeyEvidence"]
    _closed(evidence, {"apiVersion", "responseProofPublicKey", "attestationDocumentB64"})
    grammar.require(evidence["apiVersion"] == "catchplate.nativeResponseProofKeyEvidence/v1")
    grammar.require(grammar.decoded(evidence["responseProofPublicKey"], 32, 32) != bytes(32))
    grammar.decoded(evidence["attestationDocumentB64"], 12 * 1024)
    # The opening assignment has its own grammar/signature, not the old seal assignment.
    grammar.document(proof["assignmentOriginal"], 64 * 1024)
    return proof


def validate_challenge_original(original):
    return parse_native_original(original, purpose="challenge")


def validate_preparation_original(original):
    return parse_native_original(original, purpose="preparation")


def _authority_original(original, *, acknowledgment):
    envelope = grammar.document(original, MAX_AUTHORITY_ORIGINAL)
    _closed(envelope, AUTHORITY_FIELDS)
    schema = ACKNOWLEDGMENT_SCHEMA if acknowledgment else AUTHORIZATION_SCHEMA
    grammar.require(envelope["schema"] == schema.replace("catchplate.native", "catchplate.signedNative", 1))
    value = envelope["payload"]
    _closed(value, ACKNOWLEDGMENT_FIELDS if acknowledgment else AUTHORIZATION_FIELDS)
    grammar.require(value["schema"] == schema and value["operation"] == (RECEIPT if acknowledgment else AUTHORIZE))
    grammar.digest(value["requestDigest"])
    _, end = _interval(value, "committedAtEpochNs" if acknowledgment else "issuedAtEpochNs")
    grammar.require(end <= scope_expiry(value["scope"]))
    if acknowledgment:
        for name in ("authorizationSha256", "preparationSha256", "reviewDigest", "commitMarkerSha256",
                "completionReceiptSha256", "afterRootVectorDigest"):
            grammar.digest(value[name])
        grammar.text(value["receiptId"], 128)
        grammar.require(end <= grammar.integer(value["receiptExpiresAtEpochNs"]) <= scope_expiry(value["scope"]))
    else:
        grammar.digest(value["currentRootVectorDigest"])
        grammar.digest(value["currentRootHeadDigest"])
        grammar.integer(value["currentRootSequence"], minimum=0)
    grammar.decoded(envelope["signatureBase64Url"], 64, 64)
    return envelope


def validate_authorization_original(original):
    return _authority_original(original, acknowledgment=False)


def validate_acknowledgment_original(original):
    return _authority_original(original, acknowledgment=True)


def _verify(envelope, public_key, now_epoch_ns):
    grammar.require(isinstance(public_key, Ed25519PublicKey))
    payload = envelope["payload"]
    start = payload["committedAtEpochNs"] if payload["operation"] == RECEIPT else payload["issuedAtEpochNs"]
    grammar.require(start <= grammar.integer(now_epoch_ns) < payload["expiresAtEpochNs"])
    public_key.verify(grammar.decoded(envelope["signatureBase64Url"], 64, 64),
        payload["schema"].encode("ascii") + b"\0" + grammar.canonical(payload))
    return envelope


def verify_authorization_original(original, *, public_key, now_epoch_ns):
    """Verify this domain only; the caller must independently admit the key/scope."""
    return _verify(validate_authorization_original(original), public_key, now_epoch_ns)


def verify_commit_acknowledgment_original(original, *, public_key, now_epoch_ns):
    """Verify a purpose-bound ACK; no generic verifier response is accepted."""
    return _verify(validate_acknowledgment_original(original), public_key, now_epoch_ns)
