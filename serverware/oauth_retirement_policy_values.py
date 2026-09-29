"""Portable retirement policy originals, not independent policy admission.

Extracted data predicates used by both purpose-specific CP policies and native
receipt consumers. Only stdlib and pinned cryptography enter this dependency;
NSM verification, storage, currentness and phase authority stay with callers.
"""
import base64
import hashlib
import json
import re
import uuid
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from serverware.oauth_retirement_values import text

TRUST_SCHEMA = "serverware.credentialCurrentnessNativeTrustRoots/v1"
NATIVE_ASSIGNMENT_FIELDS = frozenset({"holderId", "bootId", "keyId", "controlPlaneResponseSigningKeyId",
    "releaseRecordSha256", "policyHash", "configurationSha256", "caCertificateSha256", "caPublicKeySpkiSha256",
    "expectedBinaryDigest", "expectedPcrs", "expectedEif", "expectedModuleId", "maxAgeSeconds", "futureSkewSeconds"})
SCOPE_DIGESTS = ("releaseRecordSha256", "policyHash", "configurationSha256", "caCertificateSha256",
    "caPublicKeySpkiSha256", "expectedBinaryDigest")
APPLICATION_ASSIGNMENT_FIELDS = NATIVE_ASSIGNMENT_FIELDS | {"instanceId", "providerId", "enrollmentSha256",
    "applicationMaterialSha256", "secretKekId", "providerTlsRootSha256"}
ENROLLMENT_SCHEMA = "serverware.oauthApplicationEnrollment/v1"
ENROLLMENT_ENVELOPE_SCHEMA = "serverware.signedOAuthApplicationEnrollment/v1"
ENROLLMENT_FIELDS = frozenset({"schema", "sourceRevision", "configurationDigest", "deploymentId", "applicationId",
    "providerId", "providerFamilyNamespace", "providerFamilyGeneration", "clientId", "redirectUri",
    "clientMaterialSha256", "providerConfigurationSha256", "issuedAtEpochNs", "expiresAtEpochNs"})
MAX_ENROLLMENT_BYTES = 64 * 1024


def require(value, message="retirement policy originals differ"):
    if not value:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


def sha256(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def digest(value):
    require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None)
    return value


def identifier(value):
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is not None)


def uuid_value(value):
    require(type(value) is str and str(uuid.UUID(value)) == value)
    return value


def unb64(value, maximum, *, exact=None):
    require(type(value) is str and 1 <= len(value) <= (maximum * 4 + 2) // 3
        and re.fullmatch(r"[A-Za-z0-9_-]+", value) is not None)
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    require(1 <= len(raw) <= maximum and base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == value
        and (exact is None or len(raw) == exact))
    return raw


def spki(key):
    return sha256(key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result)
        result[key] = value
    return result


def document(raw, maximum):
    """Exact original pending-retirement bounded data grammar, no floats."""
    require(type(raw) is bytes and 2 <= len(raw) <= maximum)
    value = json.loads(raw.decode("ascii"), object_pairs_hook=pairs, parse_constant=lambda _: require(False))
    def visit(item, depth=0):
        require(depth <= 8)
        if type(item) is dict:
            require(len(item) <= 32)
            for child in item.values():
                visit(child, depth + 1)
        elif type(item) is list:
            require(len(item) <= 128)
            for child in item:
                visit(child, depth + 1)
        else:
            require(item is None or type(item) in (str, int, bool))
    visit(value)
    require(type(value) is dict and canonical(value) == raw)
    return value


def trust_roots(value):
    """Native trust-root shape/certificate parsing, NOT quote verification."""
    require(type(value) is dict and set(value) == {"apiVersion", "awsNitroRootCertificatesPem", "awsNitroCrlsDerBase64url", "nitroCertificateProfile"}
        and value["apiVersion"] == TRUST_SCHEMA and value["awsNitroCrlsDerBase64url"] == []
        and len(canonical(value)) <= 128 * 1024)
    items = value["awsNitroRootCertificatesPem"]
    require(type(items) is list and 1 <= len(items) <= 16)
    roots = []
    for pem in items:
        require(type(pem) is str and 1 <= len(pem) <= 64 * 1024)
        raw = pem.encode("ascii")
        cert = x509.load_pem_x509_certificate(raw)
        require(cert.public_bytes(serialization.Encoding.PEM) == raw
            and cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        roots.append(cert)
    require(len({sha256(root.public_bytes(serialization.Encoding.DER)) for root in roots}) == len(roots))
    certificates = value["nitroCertificateProfile"]
    require(type(certificates) is dict and set(certificates) == {"profileId", "allowedLeafExtendedKeyUsageOids"}
        and certificates["profileId"] == "aws-nitro-attestation-pki-native-v1")
    oids = certificates["allowedLeafExtendedKeyUsageOids"]
    require(type(oids) is list and len(oids) <= 32
        and all(type(oid) is str and len(oid) <= 128 and re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", oid) is not None for oid in oids)
        and oids == sorted(set(oids)))
    return roots, [], certificates


def native_assignment(value):
    require(type(value) is dict and set(value) == NATIVE_ASSIGNMENT_FIELDS)
    for name in ("holderId", "keyId", "controlPlaneResponseSigningKeyId") + SCOPE_DIGESTS:
        digest(value[name]); require(value[name] != "sha256:" + "0" * 64)
    boot = unb64(value["bootId"], 32, exact=32); require(boot != bytes(32))
    require(value["holderId"] == sha256(b"serverware/credential-currentness-holder/v1\0" + boot + bytes.fromhex(value["keyId"][7:])))
    pcrs = value["expectedPcrs"]
    require(type(pcrs) is dict and 3 <= len(pcrs) <= 32 and {"PCR0", "PCR1", "PCR2"} <= set(pcrs))
    for name, pin in pcrs.items():
        require(type(name) is str and re.fullmatch(r"PCR(?:[0-9]|[12][0-9]|3[01])", name) is not None
            and isinstance(pin, str) and re.fullmatch(r"sha384:[0-9a-f]{96}", pin) is not None)
        if name in {"PCR0", "PCR1", "PCR2"}:
            require(pin != "sha384:" + "0" * 96)
    require(isinstance(value["expectedEif"], str) and re.fullmatch(r"sha384:[0-9a-f]{96}", value["expectedEif"]) is not None
        and value["expectedEif"] == pcrs["PCR0"])
    text(value["expectedModuleId"], 256)
    require(type(value["maxAgeSeconds"]) is int and 1 <= value["maxAgeSeconds"] <= 300
        and type(value["futureSkewSeconds"]) is int and 0 <= value["futureSkewSeconds"] <= 30)
    return value


def enrollment_document(raw):
    require(type(raw) is bytes and 2 <= len(raw) <= MAX_ENROLLMENT_BYTES)
    value = json.loads(raw.decode("ascii"), object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite enrollment")))
    require(type(value) is dict and set(value) == {"schema", "payload", "signatureBase64Url"}
        and value["schema"] == ENROLLMENT_ENVELOPE_SCHEMA and canonical(value) == raw)
    payload = value["payload"]
    require(type(payload) is dict and set(payload) == ENROLLMENT_FIELDS and payload["schema"] == ENROLLMENT_SCHEMA)
    for field in ("deploymentId", "applicationId", "providerFamilyNamespace"):
        identifier(payload[field])
    for field in ("configurationDigest", "clientMaterialSha256", "providerConfigurationSha256"):
        digest(payload[field]); require(payload[field] != "sha256:" + "0" * 64)
    for field, bound in (("sourceRevision", 128), ("clientId", 2048), ("redirectUri", 4096)):
        text(payload[field], bound)
    uri = urlsplit(payload["redirectUri"])
    require(uri.scheme == "https" and uri.hostname and not uri.username and not uri.password and not uri.fragment)
    require(payload["providerId"] in ("google", "x"))
    for field in ("providerFamilyGeneration", "issuedAtEpochNs", "expiresAtEpochNs"):
        require(type(payload[field]) is int and 1 <= payload[field] <= 9_223_372_036_854_775_807)
    require(payload["issuedAtEpochNs"] < payload["expiresAtEpochNs"])
    unb64(value["signatureBase64Url"], 64, exact=64)
    return value
