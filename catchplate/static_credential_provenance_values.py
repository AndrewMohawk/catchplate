"""Closed historical static-proof values for the measured rotation helper.

These are the existing syntax and identity checks, not signature verification,
Nitro admission, authenticated history, current rows or permission to rotate.
Verifier-facing compatibility functions share this parser; their cryptographic
and row checks remain in the authority modules. No contract/SQL/Nitro module is
imported by this leaf or selected while parsing a predecessor.
"""
import base64
import hashlib
import re
import urllib.parse

from catchplate import authority_oauth_activation as activation
from catchplate import authority_static_credential_create as creation
from catchplate import native_oauth_refresh as codec

canonical, digest, require = creation.canonical, creation.digest, creation.require
SCHEMA = "catchplate.staticCredentialCreationProvenance/v1"
ROTATION_SCHEMA = "catchplate.staticCredentialRotationProvenance/v1"
MAX_ORIGINAL_BYTES = 40 * 1024
MAX_EVIDENCE_BYTES = 32 * 1024
FIELDS = frozenset({"apiVersion", "creationRequestDigest", "nativeEvidenceOriginal"})
ROTATION_FIELDS = frozenset({"apiVersion", "rotationRequestDigest", "nativeEvidenceOriginal"})
CREATION_STATEMENT_SCHEMA = "catchplate.nativeStaticCredentialGenerationStatement/v1"
ROTATION_STATEMENT_SCHEMA = "catchplate.nativeStaticCredentialRotationStatement/v1"
CREATION_STATEMENT_FIELDS = frozenset({"apiVersion", "operation", "holderId", "bootId", "keyId",
    "controlPlaneResponseSigningKeyId", "deploymentId", "instanceId",
    "controlPlaneConfigurationDigest", "actorId", "credentialId", "credentialVersion",
    "intentSha256", "generationSha256", "inputSha256", "secretKekId",
    "generationCreatedAtEpochNs", "challenge", "policyHash", "dataPlaneBinarySha256",
    "intakeOrigin", "portalOrigin", "ingressLeafCertificateSha256", "ingressLeafSpkiSha256",
    "issuedAtEpochNs", "expiresAtEpochNs"})
ROTATION_STATEMENT_FIELDS = CREATION_STATEMENT_FIELDS | {
    "previousCredentialVersion", "previousCredentialSha256", "previousCurrentnessOriginRequestDigest",
    "previousProvenanceSha256", "predecessorBarrierSha256", "predecessorCurrentnessRootSha256"}
_DIGEST_FIELDS = ("holderId", "keyId", "controlPlaneResponseSigningKeyId", "controlPlaneConfigurationDigest",
    "intentSha256", "generationSha256", "inputSha256", "policyHash", "dataPlaneBinarySha256",
    "ingressLeafCertificateSha256", "ingressLeafSpkiSha256")
_ROTATION_DIGEST_FIELDS = ("previousCredentialSha256", "previousCurrentnessOriginRequestDigest",
    "previousProvenanceSha256", "predecessorBarrierSha256", "predecessorCurrentnessRootSha256")


def _integer(value):
    require(type(value) is int and 0 < value <= 2**63 - 1)
    return value


def _text(value, maximum):
    require(type(value) is str and 0 < len(value.encode("utf-8")) <= maximum
        and value == value.strip() and not any(ord(c) < 32 or ord(c) == 127 for c in value))
    return value


def origin(value):
    _text(value, 2048)
    parsed = urllib.parse.urlsplit(value)
    require(parsed.scheme == "https" and parsed.hostname and parsed.username is None
        and parsed.password is None and parsed.path == "" and parsed.query == ""
        and parsed.fragment == "" and parsed.netloc == parsed.netloc.lower()
        and parsed.port is None and not parsed.netloc.endswith(":443"))
    return value


def decoded(value, maximum, exact=None):
    require(type(value) is str and 0 < len(value) <= (maximum * 4 + 2) // 3
        and re.fullmatch(r"[A-Za-z0-9_-]+", value) is not None)
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    require(len(raw) <= maximum and (exact is None or len(raw) == exact)
        and base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == value)
    return raw


def _holder_id(boot_id, key_id):
    # Exact authority_credential_currentness.{digest,encoded,holder_id}
    # checks and domain, without importing its authority transition graph.
    activation.digest(key_id)
    activation.require(key_id != "sha256:" + "0" * 64)
    activation.require(type(boot_id) is str and re.fullmatch(r"[A-Za-z0-9_-]+", boot_id) is not None)
    raw = base64.urlsafe_b64decode(boot_id + "=" * (-len(boot_id) % 4))
    activation.require(len(raw) == 32 and base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == boot_id
        and raw != bytes(32))
    return "sha256:" + hashlib.sha256(b"catchplate/credential-currentness-holder/v1\0"
        + raw + bytes.fromhex(key_id[7:])).hexdigest()


def _evidence(value, *, rotation):
    """The old two scalar parsers, differing only in purpose/version fields."""
    require(type(value) is dict and set(value) == {"statement", "signature", "nativeKeyEvidence"})
    item = value["statement"]
    fields = ROTATION_STATEMENT_FIELDS if rotation else CREATION_STATEMENT_FIELDS
    schema = ROTATION_STATEMENT_SCHEMA if rotation else CREATION_STATEMENT_SCHEMA
    operation = "credential.static.rotate" if rotation else creation.OPERATION
    require(type(item) is dict and set(item) == fields
        and item["apiVersion"] == schema and item["operation"] == operation)
    for name in _DIGEST_FIELDS + (_ROTATION_DIGEST_FIELDS if rotation else ()):
        digest(item[name])
    require(item["holderId"] == _holder_id(item["bootId"], item["keyId"]))
    creation._actor(item["actorId"])
    creation.identifier(item["credentialId"])
    creation._kek_id(item["secretKekId"])
    if rotation:
        require(type(item["previousCredentialVersion"]) is int and type(item["credentialVersion"]) is int
            and 1 <= item["previousCredentialVersion"] < 2**63 - 1
            and item["credentialVersion"] == item["previousCredentialVersion"] + 1)
    else:
        require(type(item["credentialVersion"]) is int and item["credentialVersion"] == 1)
    require(type(item["deploymentId"]) is str
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", item["deploymentId"]) is not None)
    require(_text(item["instanceId"], 4096).startswith("spiffe://"))
    origin(item["intakeOrigin"]); origin(item["portalOrigin"])
    require(item["intakeOrigin"] != item["portalOrigin"])
    require(decoded(item["challenge"], 32, 32) != bytes(32))
    _integer(item["generationCreatedAtEpochNs"])
    issued, expires = _integer(item["issuedAtEpochNs"]), _integer(item["expiresAtEpochNs"])
    require(item["generationCreatedAtEpochNs"] <= issued < expires <= issued + 30_000_000_000)
    require(type(value["signature"]) is str and value["signature"].startswith("ed25519:"))
    decoded(value["signature"][8:], 64, 64)
    key = value["nativeKeyEvidence"]
    require(type(key) is dict and set(key) == {"apiVersion", "responseProofPublicKey", "attestationDocumentB64"}
        and key["apiVersion"] == "catchplate.nativeResponseProofKeyEvidence/v1"
        and decoded(key["responseProofPublicKey"], 32, 32) != bytes(32))
    decoded(key["attestationDocumentB64"], 12 * 1024)
    require(len(canonical(value)) <= MAX_EVIDENCE_BYTES)
    return value


def creation_evidence(value):
    return _evidence(value, rotation=False)


def rotation_evidence(value):
    return _evidence(value, rotation=True)


def original(value):
    """Closed creation original, not verification of its historical claim."""
    require(type(value) is str and value.isascii() and 0 < len(value) <= MAX_ORIGINAL_BYTES)
    parsed = codec.document(value.encode("ascii"), MAX_ORIGINAL_BYTES)
    require(set(parsed) == FIELDS and parsed["apiVersion"] == SCHEMA)
    digest(parsed["creationRequestDigest"])
    native = parsed["nativeEvidenceOriginal"]
    require(type(native) is str and native.isascii() and 0 < len(native) <= MAX_EVIDENCE_BYTES)
    creation_evidence(codec.document(native.encode("ascii"), MAX_EVIDENCE_BYTES))
    return parsed


def evidence(value):
    parsed = original(value)
    return creation_evidence(codec.document(parsed["nativeEvidenceOriginal"].encode("ascii"), MAX_EVIDENCE_BYTES))


def generation_original(value):
    """Explicit creation/rotation syntax dispatch, never a fresh verdict."""
    require(type(value) is str and value.isascii() and 0 < len(value) <= MAX_ORIGINAL_BYTES)
    parsed = codec.document(value.encode("ascii"), MAX_ORIGINAL_BYTES)
    if parsed.get("apiVersion") == SCHEMA:
        return original(value)
    require(set(parsed) == ROTATION_FIELDS and parsed["apiVersion"] == ROTATION_SCHEMA)
    digest(parsed["rotationRequestDigest"])
    native = parsed["nativeEvidenceOriginal"]
    require(type(native) is str and native.isascii() and 0 < len(native) <= MAX_EVIDENCE_BYTES)
    rotation_evidence(codec.document(native.encode("ascii"), MAX_EVIDENCE_BYTES))
    return parsed


def request_digest(parsed):
    return parsed["creationRequestDigest"] if parsed["apiVersion"] == SCHEMA else parsed["rotationRequestDigest"]


def generation_evidence(value):
    parsed = generation_original(value)
    if parsed["apiVersion"] == SCHEMA:
        return evidence(value)
    return rotation_evidence(codec.document(parsed["nativeEvidenceOriginal"].encode("ascii"), MAX_EVIDENCE_BYTES))
