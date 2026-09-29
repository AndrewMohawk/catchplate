"""Purpose-fixed audit assignments and original role-4 verification.

The independently signed audit policy authorizes authorship, not the truth of
the reported event or an application's independently observed execution.
"""
import base64
import hashlib
import json
import math
import re
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID
from serverware import authority_credential_currentness as common
from serverware import authority_credential_currentness_policy as native
from serverware import authority_oauth_refresh as original
from scripts import verify_nitro_tee as nitro

SCHEMA = "serverware.nativeAuditStatement/v1"
POLICY_SCHEMA = "serverware.measuredAuditAuthorityPolicy/v1"
STARTUP_SCHEMA = "serverware.measuredAuditStartup/v1"
MAX_ENVELOPE = 1536 * 1024
MAX_EVENTS = 1024 * 1024
canonical, sha256, require, digest = common.canonical, common.sha256, common.require, common.digest
document = original.document
FIELDS = frozenset({"apiVersion", "action", "deploymentId", "instanceId", "epochId", "assignmentSha256", "bootId", "keyId",
    "controlPlaneResponseSigningKeyId", "policyHash", "dataPlaneBinarySha256", "clientCertificateSha256", "clientSpkiSha256",
    "workloadUri", "sequence", "previousBatchSha256", "batchSha256", "eventsBase64url", "issuedAtEpochNs", "expiresAtEpochNs", "challenge"})
ASSIGNMENT_FIELDS = frozenset({"epochId", "instanceId", "native", "workloadCaCertificatePem", "initialSequence",
    "previousBatchSha256", "previousAssignmentSha256", "pendingBatchSha256"})


def component(value):
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9._-]{1,128}", value) is not None)
    return value


def uri(deployment, instance):
    return "spiffe://serverware.audit/" + component(deployment) + "/" + component(instance)


def decode(value, maximum):
    require(type(value) is str and len(value) <= (maximum * 4 + 2) // 3)
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    require(len(raw) <= maximum and base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == value)
    return raw


def event_document(raw):
    # Event number spellings are signed as raw bytes, not cross-language
    # canonical numbers. Preserve legacy finite numeric values in the projection.
    require(type(raw) is bytes and 0 < len(raw) <= MAX_EVENTS)
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result); result[key] = value
        return result
    def invalid(value): raise ValueError("audit event has a non-JSON numeric constant")
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    remaining = 65536
    def visit(item, depth):
        nonlocal remaining
        remaining -= 1; require(remaining >= 0 and depth <= 16)
        if type(item) is dict:
            for key, child in item.items(): require(type(key) is str); visit(child, depth + 1)
        elif type(item) is list:
            for child in item: visit(child, depth + 1)
        elif type(item) is float: require(math.isfinite(item))
        elif type(item) is int: require(-(2**63) <= item < 2**64)
        else: require(item is None or type(item) in {str, bool})
    visit(value, 0)
    return value


def policy(value, root):
    require(type(value) is dict and set(value) == {"schema", "sourceRevision", "configurationDigest", "deploymentId",
        "issuedAtEpochNs", "expiresAtEpochNs", "trustRoots", "assignments"} and value["schema"] == POLICY_SCHEMA)
    digest(value["configurationDigest"]); component(value["deploymentId"])
    require(type(value["sourceRevision"]) is str and 1 <= len(value["sourceRevision"]) <= 256)
    require(type(value["issuedAtEpochNs"]) is int and type(value["expiresAtEpochNs"]) is int
        and 0 < value["issuedAtEpochNs"] < value["expiresAtEpochNs"] <= value["issuedAtEpochNs"] + 86_400_000_000_000)
    trust = value["trustRoots"]
    require(type(trust) is dict and trust.get("apiVersion") == "serverware.measuredAuditNativeTrustRoots/v1")
    # Reuse only the unchanged PKI parsing primitive, not currentness permission.
    native._trust({**trust, "apiVersion": native.TRUST_SCHEMA})
    assignments = value["assignments"]
    require(type(assignments) is list and 1 <= len(assignments) <= 32)
    keys, epochs, instances = set(), set(), set()
    root_id = sha256(root.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
    for item in assignments:
        require(type(item) is dict and set(item) == ASSIGNMENT_FIELDS)
        common.identifier(item["epochId"]); component(item["instanceId"]); common.version(item["initialSequence"])
        require(item["initialSequence"] < 2**63 - 1)
        expected = native._assignment(item["native"])
        require(expected["keyId"] != root_id and expected["keyId"] != expected["controlPlaneResponseSigningKeyId"])
        for name in ("previousBatchSha256", "previousAssignmentSha256", "pendingBatchSha256"):
            if item[name] is not None: digest(item[name])
        require((item["initialSequence"] == 1) == (item["previousBatchSha256"] is None))
        if item["previousAssignmentSha256"] is None:
            require(item["initialSequence"] == 1 and item["pendingBatchSha256"] is None)
        require(type(item["workloadCaCertificatePem"]) is str and 0 < len(item["workloadCaCertificatePem"]) <= 65536)
        pem = item["workloadCaCertificatePem"].encode("ascii")
        ca = x509.load_pem_x509_certificate(pem)
        require(ca.public_bytes(serialization.Encoding.PEM) == pem and nitro.basic_constraints(ca, "audit workload CA").ca
            and sha256(ca.public_bytes(serialization.Encoding.DER)) == expected["caCertificateSha256"]
            and sha256(ca.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)) == expected["caPublicKeySpkiSha256"])
        assignment_id = sha256(canonical(item))
        require(assignment_id not in keys and item["epochId"] not in epochs and item["instanceId"] not in instances)
        keys.add(assignment_id); epochs.add(item["epochId"]); instances.add(item["instanceId"])
    require(len(canonical(value)) <= 2 * 1024 * 1024)
    return value


def envelope(raw):
    value = document(raw, MAX_ENVELOPE)
    require(type(value) is dict and set(value) == {"statement", "signature", "nativeKeyEvidence"} and canonical(value) == raw)
    s = value["statement"]
    require(type(s) is dict and set(s) == FIELDS and s["apiVersion"] == SCHEMA
        and s["action"] in {"hello", "prepare", "commit"})
    component(s["deploymentId"]); component(s["instanceId"]); common.identifier(s["epochId"]); common.version(s["sequence"])
    require(s["sequence"] < 2**63 - 1)
    require(s["workloadUri"] == uri(s["deploymentId"], s["instanceId"]))
    for name in ("assignmentSha256", "keyId", "controlPlaneResponseSigningKeyId", "policyHash", "dataPlaneBinarySha256",
        "clientCertificateSha256", "clientSpkiSha256"):
        digest(s[name])
    for name in ("previousBatchSha256", "batchSha256"):
        if s[name] is not None: digest(s[name])
    common.encoded(s["bootId"], 32); common.encoded(s["challenge"], 32)
    require(type(s["issuedAtEpochNs"]) is int and type(s["expiresAtEpochNs"]) is int
        and 0 < s["issuedAtEpochNs"] < s["expiresAtEpochNs"] <= s["issuedAtEpochNs"] + 30_000_000_000)
    if s["action"] == "prepare":
        require(s["batchSha256"] is None and bool(decode(s["eventsBase64url"], MAX_EVENTS)))
    else:
        require(s["eventsBase64url"] is None and (s["batchSha256"] is None) == (s["action"] == "hello"))
    require(type(value["signature"]) is str and value["signature"].startswith("ed25519:"))
    common.encoded(value["signature"][8:], 64)
    evidence = value["nativeKeyEvidence"]
    require(type(evidence) is dict and set(evidence) == {"apiVersion", "attestationDocumentB64", "responseProofPublicKey"}
        and evidence["apiVersion"] == "serverware.nativeResponseProofKeyEvidence/v1")
    return value


def sign_policy(value, signing_key):
    """Offline authority producer; its key is never accepted by HTTP intake."""
    require(isinstance(signing_key, Ed25519PrivateKey))
    admitted = policy(value, signing_key.public_key())
    signature = signing_key.sign(POLICY_SCHEMA.encode("ascii") + b"\0" + canonical(admitted))
    return canonical({"schema":"serverware.signedMeasuredAuditAuthorityPolicy/v1", "payload":admitted,
        "signatureBase64Url":base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")})


def verify(raw, value, assignment, peer_der, now):
    signed = envelope(raw); s = signed["statement"]; expected = assignment["native"]
    require(s["assignmentSha256"] == sha256(canonical(assignment)) and s["epochId"] == assignment["epochId"]
        and s["instanceId"] == assignment["instanceId"] and s["deploymentId"] == value["deploymentId"]
        and value["issuedAtEpochNs"] <= now < value["expiresAtEpochNs"]
        and s["issuedAtEpochNs"] <= now < s["expiresAtEpochNs"])
    for name in ("bootId", "keyId", "controlPlaneResponseSigningKeyId", "policyHash"):
        require(s[name] == expected[name])
    require(s["dataPlaneBinarySha256"] == expected["expectedBinaryDigest"])
    # TLS supplied actual possession; independently repeat the signed issuer,
    # exact workload SAN and original validity joins, including reused sessions.
    leaf = x509.load_der_x509_certificate(peer_der)
    ca = x509.load_pem_x509_certificate(assignment["workloadCaCertificatePem"].encode("ascii"))
    require(leaf.issuer == ca.subject and isinstance(ca.public_key(), ec.EllipticCurvePublicKey)
        and not nitro.basic_constraints(leaf, "audit TLS leaf").ca)
    ca.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(leaf.signature_hash_algorithm))
    require(int(leaf.not_valid_before_utc.timestamp()) * 1_000_000_000 <= now < int(leaf.not_valid_after_utc.timestamp()) * 1_000_000_000
        and int(ca.not_valid_before_utc.timestamp()) * 1_000_000_000 <= now < int(ca.not_valid_after_utc.timestamp()) * 1_000_000_000)
    require(list(leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) == [ExtendedKeyUsageOID.CLIENT_AUTH]
        and list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value) == [x509.UniformResourceIdentifier(s["workloadUri"])])
    require(sha256(peer_der) == s["clientCertificateSha256"] and sha256(leaf.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)) == s["clientSpkiSha256"])
    evidence = signed["nativeKeyEvidence"]; raw_key = common.encoded(evidence["responseProofPublicKey"], 32)
    key = Ed25519PublicKey.from_public_bytes(raw_key)
    require(sha256(key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)) == expected["keyId"])
    signature = common.encoded(signed["signature"][8:], 64); statement = canonical(s)
    key.verify(signature, SCHEMA.encode("ascii") + b"\0" + hashlib.sha256(statement).digest())
    nonce = hashlib.sha256(b"serverware/native-audit-attestation/v1\0" + common.encoded(s["challenge"], 32)
        + hashlib.sha256(statement).digest() + signature).digest()
    boot = hashlib.sha256(b"serverware/native-proof-custody-boot/v1\0" + common.encoded(expected["bootId"], 32)
        + bytes.fromhex(expected["keyId"][7:]) + bytes.fromhex(expected["controlPlaneResponseSigningKeyId"][7:])).digest()
    user_data = b"serverware/enclave-runtime-key-binding/v1\0\x04" + b"".join(bytes.fromhex(expected[name][7:])
        for name in native._SCOPE_DIGESTS[:5]) + hashlib.sha256(raw_key).digest() + boot
    trust = {**value["trustRoots"], "apiVersion": native.TRUST_SCHEMA}
    roots, crls, certificates = native._trust(trust)
    quote = nitro.b64url_decode(evidence["attestationDocumentB64"], "audit native original", max_bytes=12 * 1024)
    verified, _, _, _, _ = nitro._verify_nitro_document_common(quote, claims=None, expected_user_data_bytes=user_data,
        challenge=nonce, expected_pcrs=expected["expectedPcrs"], expected_eif=expected["expectedEif"], roots=roots, crls=crls,
        certificate_profile=certificates, expected_module_id=expected["expectedModuleId"], now=now // 1_000_000_000,
        max_age=expected["maxAgeSeconds"], future_skew=expected["futureSkewSeconds"], native_profile=True)
    require(verified["public_key"] == raw_key)
    return signed
