"""Independent cold selection and native proof admission for review opening.

Opening is a separate purpose from sealing. Neither an expired seal assignment,
a hash-consistent retained pair nor a generic control-plane response selects it.
The broker receives this configuration only through its actual measured parent;
authority callers independently validate their root-admitted configuration.
"""
from __future__ import annotations

import hashlib
import time
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from scripts import verify_nitro_tee as nitro
from serverware import authority_contract as contract
from serverware import authority_credential_currentness_policy as native
from serverware import authority_native_jit_review_assignment as grammar
from serverware import authority_request_commitment as commitment

FIELD = "nativeJitReviewOpeningPolicy"
SCHEMA = "serverware.nativeJitReviewOpeningPolicy/v1"
TRUST_SCHEMA = "serverware.nativeJitReviewOpeningNativeTrustRoots/v1"
ASSIGNMENT_SCHEMA = "serverware.nativeJitReviewOpeningAssignment/v1"
SIGNED_ASSIGNMENT_SCHEMA = "serverware.signedNativeJitReviewOpeningAssignment/v1"
CONFIG = "serverware.nativeJitReviewOpenConfiguration/v1"
MAX_POLICY_BYTES = 512 * 1024
MAX_CONFIG_BYTES = 640 * 1024
POLICY_FIELDS = frozenset({"schema", "sourceContractDigest", "deploymentId",
    "operationMaxSeconds", "attemptCapacity", "trustRoots", "assignmentAuthorizer",
    "target", "authorizerKey", "commitOwnerKey", "nativeOrigin", "portalOrigin"})
CONFIG_FIELDS = frozenset({"apiVersion", "sourceContractDigest",
    "controlPlaneConfigurationDigest", "policy", "assignmentOriginal"})
BROWSER_FIELDS = frozenset({"browserCertificateSha256", "browserPublicKeySpkiSha256"})
IDENTITY_FIELDS = frozenset({"holderId", "bootId", "keyId", "controlPlaneResponseSigningKeyId",
    "releaseRecordSha256", "policyHash", "configurationSha256", "caCertificateSha256",
    "caPublicKeySpkiSha256", "expectedBinaryDigest"})
_QUOTE_FIELDS = ("releaseRecordSha256", "policyHash", "configurationSha256",
    "caCertificateSha256", "caPublicKeySpkiSha256")
canonical, sha256, require = grammar.canonical, grammar.sha256, grammar.require
AdmissionError = grammar.AdmissionError


def origin(value):
    grammar.text(value, 2048)
    parsed = urlsplit(value)
    require(parsed.scheme == "https" and parsed.hostname is not None
        and parsed.username is None and parsed.password is None and not parsed.path
        and not parsed.query and not parsed.fragment and parsed.port in (None, 443)
        and value == "https://" + parsed.netloc and parsed.netloc == parsed.netloc.lower()
        and parsed.netloc.isascii() and not parsed.netloc.endswith(":443"))
    return value


def purpose_key(value):
    require(type(value) is dict and set(value) == {"keyId", "publicKeyBase64Url"})
    raw = grammar.decoded(value["publicKeyBase64Url"], 32, 32)
    require(raw != bytes(32))
    key = Ed25519PublicKey.from_public_bytes(raw)
    require(grammar.digest(value["keyId"]) == sha256(key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)))
    return key


def _assignment_key(value):
    require(type(value) is dict and set(value) == grammar.AUTHORIZER_FIELDS)
    raw = value["publicKeyPem"].encode("ascii")
    require(0 < len(raw) <= 4096)
    key = serialization.load_pem_public_key(raw)
    require(isinstance(key, Ed25519PublicKey)
        and key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo) == raw
        and grammar.digest(value["publicKeyPemSha256"]) == sha256(raw)
        and grammar.digest(value["publicKeySpkiSha256"]) == sha256(key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)))
    return key


def _trust(value):
    require(type(value) is dict and value.get("apiVersion") == TRUST_SCHEMA)
    return native._trust({**value, "apiVersion": native.TRUST_SCHEMA})


def _policy(value):
    selected = grammar.document(canonical(value).decode("ascii"), MAX_POLICY_BYTES)
    require(set(selected) == POLICY_FIELDS and selected["schema"] == SCHEMA
        and selected["sourceContractDigest"] == contract.OPERATION_MANIFEST_DIGEST)
    grammar.digest(selected["sourceContractDigest"])
    grammar.deployment(selected["deploymentId"])
    grammar.integer(selected["operationMaxSeconds"], maximum=30)
    grammar.integer(selected["attemptCapacity"], maximum=16)
    _trust(selected["trustRoots"])
    grammar.target(selected["target"])
    _assignment_key(selected["assignmentAuthorizer"])
    purpose_key(selected["authorizerKey"])
    purpose_key(selected["commitOwnerKey"])
    keys = {selected[name]["keyId"] for name in ("authorizerKey", "commitOwnerKey")}
    require(len(keys) == 2 and not keys & {
        selected["assignmentAuthorizer"]["publicKeySpkiSha256"],
        selected["target"]["controlPlaneResponseSigningKeyId"]}
        and selected["assignmentAuthorizer"]["publicKeySpkiSha256"]
            != selected["target"]["controlPlaneResponseSigningKeyId"])
    origin(selected["nativeOrigin"]); origin(selected["portalOrigin"])
    require(selected["nativeOrigin"] != selected["portalOrigin"])
    return selected


@grammar.checked
def validate_policy(value, *, payload, root_key=None):
    if value is None:
        require(type(payload) is dict and FIELD not in payload)
        return None
    selected = _policy(value)
    excluded = grammar.excluded_keys(payload, root_key)
    grammar.authorizer(selected["assignmentAuthorizer"], payload=payload, root_key=root_key,
        response_key_id=selected["target"]["controlPlaneResponseSigningKeyId"])
    require(not excluded & {selected[name]["keyId"] for name in ("authorizerKey", "commitOwnerKey")})
    return selected


@grammar.checked
def parse_assignment_original(original):
    """Closed opening assignment grammar only; not authenticated selection."""
    envelope = grammar.document(original, grammar.MAX_ORIGINAL_BYTES)
    require(set(envelope) == {"schema", "payload", "signature"}
        and envelope["schema"] == SIGNED_ASSIGNMENT_SCHEMA)
    value = envelope["payload"]
    require(type(value) is dict and set(value) == grammar.PAYLOAD_FIELDS
        and value["schema"] == ASSIGNMENT_SCHEMA)
    grammar.digest(value["sourceContractDigest"])
    grammar.digest(value["controlPlaneConfigurationDigest"])
    grammar.deployment(value["deploymentId"])
    selected = value["assignment"]
    require(type(selected) is dict and set(selected) == grammar.ASSIGNMENT_FIELDS)
    native._assignment({name: selected[name] for name in native.ASSIGNMENT_FIELDS})
    grammar.target({name: selected[name] for name in grammar.TARGET_FIELDS})
    issued, expires = (grammar.integer(value[name]) for name in ("issuedAtEpochNs", "expiresAtEpochNs"))
    require(0 < expires - issued <= grammar.MAX_INTERVAL_NS)
    grammar.decoded(envelope["signature"], 64, 64)
    return envelope


@grammar.checked
def verify_assignment_original(original, *, policy, configuration_digest, now_epoch_ns):
    """Verify this independently signed selection, not a current read grant."""
    policy = _policy(policy)
    envelope = parse_assignment_original(original)
    value, selected = envelope["payload"], envelope["payload"]["assignment"]
    require(value["sourceContractDigest"] == policy["sourceContractDigest"]
        and value["controlPlaneConfigurationDigest"] == grammar.digest(configuration_digest)
        and value["deploymentId"] == policy["deploymentId"]
        and value["issuedAtEpochNs"] <= grammar.integer(now_epoch_ns) < value["expiresAtEpochNs"]
        and canonical({name: selected[name] for name in grammar.TARGET_FIELDS}) == canonical(policy["target"]))
    require(selected["keyId"] not in {policy["assignmentAuthorizer"]["publicKeySpkiSha256"],
        selected["controlPlaneResponseSigningKeyId"], policy["authorizerKey"]["keyId"], policy["commitOwnerKey"]["keyId"]})
    _assignment_key(policy["assignmentAuthorizer"]).verify(grammar.decoded(envelope["signature"], 64, 64),
        commitment.framed_digest(SIGNED_ASSIGNMENT_SCHEMA, canonical(value)).encode("ascii"))
    return value


def broker_configuration(policy, assignment_original, configuration_digest):
    return {"apiVersion": CONFIG, "sourceContractDigest": policy["sourceContractDigest"],
        "controlPlaneConfigurationDigest": configuration_digest,
        "policy": policy, "assignmentOriginal": assignment_original}


@grammar.checked
def validate_broker_configuration(value, *, now_epoch_ns):
    """FD3 grammar/signature checks; the native parent owns cold admission."""
    config = grammar.document(canonical(value).decode("ascii"), MAX_CONFIG_BYTES)
    require(set(config) == CONFIG_FIELDS and config["apiVersion"] == CONFIG)
    policy = _policy(config["policy"])
    require(config["sourceContractDigest"] == policy["sourceContractDigest"])
    selected = verify_assignment_original(config["assignmentOriginal"], policy=policy,
        configuration_digest=config["controlPlaneConfigurationDigest"], now_epoch_ns=now_epoch_ns)
    return config, selected


def _native_proof(original, *, purpose, policy, configuration_digest, now_epoch_ns):
    from serverware import authority_native_jit_review_open_contract as wire

    proof = wire.parse_native_original(original, purpose=purpose)
    item = proof["statement"]
    selected = verify_assignment_original(proof["assignmentOriginal"], policy=policy,
        configuration_digest=configuration_digest, now_epoch_ns=now_epoch_ns)
    expected = selected["assignment"]
    scope = item if purpose == "challenge" else item["scope"]
    broker = broker_configuration(policy, proof["assignmentOriginal"], configuration_digest)
    require(type(item["identity"]) is dict and set(item["identity"]) == IDENTITY_FIELDS | BROWSER_FIELDS)
    for name in BROWSER_FIELDS:
        grammar.digest(item["identity"][name])
    require({name: item["identity"][name] for name in IDENTITY_FIELDS} == {name: expected[name] for name in IDENTITY_FIELDS}
        and scope["sourceContractDigest"] == policy["sourceContractDigest"]
        and scope["controlPlaneConfigurationDigest"] == configuration_digest
        and scope["openingAssignmentSha256"] == sha256(proof["assignmentOriginal"].encode("ascii"))
        and scope["ownerScopeDigest"] == sha256(canonical(broker)))
    issued = item["issuedAtEpochNs"] if purpose == "challenge" else item["preparedAtEpochNs"]
    expires = item["expiresAtEpochNs"]
    require(selected["issuedAtEpochNs"] <= issued <= now_epoch_ns < expires <= selected["expiresAtEpochNs"]
        and expires - issued <= policy["operationMaxSeconds"] * 1_000_000_000)
    if purpose == "challenge":
        require(item["nativeOrigin"] == policy["nativeOrigin"] and item["portalOrigin"] == policy["portalOrigin"])
    else:
        require(scope["assignmentExpiresAtEpochNs"] == selected["expiresAtEpochNs"])
    raw_key = grammar.decoded(proof["nativeKeyEvidence"]["responseProofPublicKey"], 32, 32)
    key = Ed25519PublicKey.from_public_bytes(raw_key)
    require(sha256(key.public_bytes(serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)) == expected["keyId"])
    signature = grammar.decoded(proof["signature"][8:], 64, 64)
    statement_raw = canonical(item)
    key.verify(signature, item["schema"].encode("ascii") + b"\0" + statement_raw)
    domain = ("serverware/native-jit-review-open-" + purpose + "-attestation/v1").encode("ascii") + b"\0"
    nonce = hashlib.sha256(domain + hashlib.sha256(statement_raw).digest() + signature).digest()
    boot_binding = hashlib.sha256(b"serverware/native-proof-custody-boot/v1\0"
        + grammar.decoded(expected["bootId"], 32, 32) + bytes.fromhex(expected["keyId"][7:])
        + bytes.fromhex(expected["controlPlaneResponseSigningKeyId"][7:])).digest()
    user_data = b"serverware/enclave-runtime-key-binding/v1\0\x04" + b"".join(
        bytes.fromhex(expected[name][7:]) for name in _QUOTE_FIELDS) + hashlib.sha256(raw_key).digest() + boot_binding
    roots, crls, certificate_profile = _trust(policy["trustRoots"])
    verified, _, _, _, _ = nitro._verify_nitro_document_common(
        grammar.decoded(proof["nativeKeyEvidence"]["attestationDocumentB64"], 12 * 1024), claims=None,
        expected_user_data_bytes=user_data, challenge=nonce, expected_pcrs=expected["expectedPcrs"],
        expected_eif=expected["expectedEif"], roots=roots, crls=crls, certificate_profile=certificate_profile,
        expected_module_id=expected["expectedModuleId"], now=now_epoch_ns // 1_000_000_000,
        max_age=expected["maxAgeSeconds"], future_skew=expected["futureSkewSeconds"], native_profile=True)
    require(type(verified["public_key"]) is bytes and verified["public_key"] == raw_key)
    return proof


@grammar.checked
def verify_native_original(original, *, purpose, configuration_payload, root_key,
        now_epoch_ns, deadline_monotonic_ns):
    """Independently verify a challenge/preparation, never current-read rights."""
    from serverware.authority_policy_canary_policy import full_configuration_digest

    require(purpose in {"challenge", "preparation"})
    before_mono, before_wall = time.monotonic_ns(), time.time_ns()
    require(before_mono < grammar.integer(deadline_monotonic_ns)
        and grammar.integer(now_epoch_ns) <= before_wall)
    policy = validate_policy(configuration_payload.get(FIELD), payload=configuration_payload, root_key=root_key)
    require(policy is not None)
    digest = full_configuration_digest(configuration_payload)
    proof = _native_proof(original, purpose=purpose, policy=policy,
        configuration_digest=digest, now_epoch_ns=before_wall)
    expected = grammar.document(proof["assignmentOriginal"], grammar.MAX_ORIGINAL_BYTES)["payload"]["assignment"]
    require(expected["keyId"] not in grammar.excluded_keys(configuration_payload, root_key))
    item = proof["statement"]
    require((item["issuedAtEpochNs"] if purpose == "challenge" else item["preparedAtEpochNs"]) <= now_epoch_ns)
    deadline = min(deadline_monotonic_ns, before_mono + item["expiresAtEpochNs"] - before_wall)
    after_wall, after_mono = time.time_ns(), time.monotonic_ns()
    require(before_mono <= after_mono < deadline and before_wall <= after_wall < item["expiresAtEpochNs"]
        and full_configuration_digest(configuration_payload) == digest)
    return proof
