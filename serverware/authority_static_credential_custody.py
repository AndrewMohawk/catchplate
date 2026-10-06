"""Purpose-fixed static-generation proof under independently signed policy.

This module does not register an operation or enable the preliminary creation
profile. The caller must already have authenticated the actual configuration
payload. A literal generation wrapper, KEK label, old quote or structural join
is never native provenance. Only verify_original performs this family's native
signature and Nitro admission; it returns no transferable success carrier.

The generation timestamp remains its original sealing time. The separate fresh
statement binds the exact current execution and its retained generation. It
does not renew the generation, grant SQL permission, resolve commit uncertainty
or replace current human hardware/approval and atomic identity-absence checks.
"""
import base64
from datetime import datetime, timezone
import hashlib
import re
import urllib.parse

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from scripts import verify_nitro_tee as nitro
from serverware import authority_credential_currentness as current
from serverware import authority_credential_currentness_policy as native
from serverware import authority_static_credential_create as profile

canonical, sha256, digest, require = profile.canonical, profile.sha256, profile.digest, profile.require
FIELD = "staticCredentialCustodyPolicy"
SCHEMA = "serverware.staticCredentialCustodyAuthorityPolicy/v1"
TRUST_SCHEMA = "serverware.staticCredentialNativeTrustRoots/v1"
STATEMENT_SCHEMA = "serverware.nativeStaticCredentialGenerationStatement/v1"
SIGN_OPERATION = "nativeStaticCredentialGeneration.sign/v1"
SIGNATURE_DOMAIN = STATEMENT_SCHEMA.encode("ascii") + b"\0"
ATTESTATION_DOMAIN = b"serverware/native-static-credential-generation-attestation/v1\0"
MAX_EVIDENCE_BYTES = 32 * 1024
MAX_POLICY_BYTES = 512 * 1024
POLICY_FIELDS = frozenset({"schema", "deploymentId", "controlPlaneConfigurationDigest",
    "operationMaxSeconds", "trustRoots", "assignments"})
ASSIGNMENT_FIELDS = native.ASSIGNMENT_FIELDS | {
    "instanceId", "secretKekId", "intakeOrigin", "portalOrigin"}
STATEMENT_FIELDS = frozenset({"apiVersion", "operation", "holderId", "bootId", "keyId",
    "controlPlaneResponseSigningKeyId", "deploymentId", "instanceId",
    "controlPlaneConfigurationDigest", "actorId", "credentialId", "credentialVersion",
    "intentSha256", "generationSha256", "inputSha256", "secretKekId",
    "generationCreatedAtEpochNs", "challenge", "policyHash", "dataPlaneBinarySha256",
    "intakeOrigin", "portalOrigin", "ingressLeafCertificateSha256", "ingressLeafSpkiSha256",
    "issuedAtEpochNs", "expiresAtEpochNs"})
_SCOPE_DIGESTS = ("releaseRecordSha256", "policyHash", "configurationSha256",
    "caCertificateSha256", "caPublicKeySpkiSha256")


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


def _evidence(value):
    """Closed scalar/byte checks only; this is not proof verification."""
    require(type(value) is dict and set(value) == {"statement", "signature", "nativeKeyEvidence"})
    item = value["statement"]
    require(type(item) is dict and set(item) == STATEMENT_FIELDS
        and item["apiVersion"] == STATEMENT_SCHEMA and item["operation"] == profile.OPERATION)
    for name in ("holderId", "keyId", "controlPlaneResponseSigningKeyId", "controlPlaneConfigurationDigest",
            "intentSha256", "generationSha256", "inputSha256", "policyHash", "dataPlaneBinarySha256",
            "ingressLeafCertificateSha256", "ingressLeafSpkiSha256"):
        digest(item[name])
    require(item["holderId"] == current.holder_id(item["bootId"], item["keyId"]))
    profile._actor(item["actorId"])
    profile.identifier(item["credentialId"])
    profile._kek_id(item["secretKekId"])
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
        and key["apiVersion"] == "serverware.nativeResponseProofKeyEvidence/v1"
        and decoded(key["responseProofPublicKey"], 32, 32) != bytes(32))
    decoded(key["attestationDocumentB64"], 12 * 1024)
    require(len(canonical(value)) <= MAX_EVIDENCE_BYTES)
    return value


evidence = _evidence


def input_sha256(arguments):
    values = profile.arguments(profile.OPERATION, arguments, typed="businessIntent" in arguments)
    return sha256(canonical(values))


def _bind(values, proof, now_epoch_ns):
    _integer(now_epoch_ns)
    item, request = proof["statement"], values["request"]
    original = request["nativeGenerationOriginal"].encode("ascii")
    generation = profile.generation(request["nativeGenerationOriginal"])
    stamp = datetime.fromisoformat(generation["envelope"]["secret_updated_at"])
    delta = stamp - datetime(1970, 1, 1, tzinfo=timezone.utc)
    generation_ns = (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000
    require(item["inputSha256"] == sha256(canonical(values))
        and item["generationSha256"] == sha256(original)
        and item["intentSha256"] == generation["intentSha256"]
        and item["actorId"] == values["actor_id"]
        and item["controlPlaneConfigurationDigest"] == values["control_plane_configuration_digest"]
        and item["credentialId"] == request["credentialId"]
        and item["credentialVersion"] == request["credentialVersion"]
        and item["secretKekId"] == generation["envelope"]["secret_kek_id"]
        and item["generationCreatedAtEpochNs"] == generation_ns
        and request["executionIssuedAtEpochNs"] <= item["issuedAtEpochNs"] <= now_epoch_ns
        < item["expiresAtEpochNs"] <= request["executionExpiresAtEpochNs"],
        "Static native proof differs from its literal generation or current execution")


def bind_originals(*, arguments, evidence, now_epoch_ns):
    """Kernel rejoin for independently verified literal evidence, not a verdict.

    Calling this on caller-supplied evidence is insufficient. The actual
    authority service must run verify_original on those same originals before
    issuing capability and clip its original deadline to the statement expiry.
    """
    values = profile.arguments(profile.OPERATION, arguments, typed="businessIntent" in arguments)
    _bind(values, _evidence(evidence), now_epoch_ns)


def _trust(value):
    require(type(value) is dict and set(value) == {"apiVersion", "awsNitroRootCertificatesPem",
        "awsNitroCrlsDerBase64url", "nitroCertificateProfile"} and value["apiVersion"] == TRUST_SCHEMA
        and value["awsNitroCrlsDerBase64url"] == [] and len(canonical(value)) <= 128 * 1024)
    pems = value["awsNitroRootCertificatesPem"]
    require(type(pems) is list and 1 <= len(pems) <= nitro.MAX_CERTIFICATES)
    roots = []
    for pem in pems:
        require(type(pem) is str and 0 < len(pem) <= nitro.MAX_CERT_BYTES)
        raw = pem.encode("ascii")
        cert = x509.load_pem_x509_certificate(raw)
        require(cert.public_bytes(serialization.Encoding.PEM) == raw
            and nitro.basic_constraints(cert, "static credential Nitro root").ca)
        roots.append(cert)
    require(len({nitro.certificate_sha256(root) for root in roots}) == len(roots))
    certificates = value["nitroCertificateProfile"]
    require(type(certificates) is dict and set(certificates) == {"profileId", "allowedLeafExtendedKeyUsageOids"}
        and certificates["profileId"] == "aws-nitro-attestation-pki-native-v1")
    oids = certificates["allowedLeafExtendedKeyUsageOids"]
    require(type(oids) is list and len(oids) <= 32
        and all(type(oid) is str and len(oid) <= 128 and re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", oid) is not None for oid in oids)
        and oids == sorted(set(oids)))
    return roots, [], certificates


def validate_policy(value, *, payload, root_key=None):
    """Require this separate purpose in an already authenticated configuration."""
    enabled = any(profile.OPERATION in role.get("enabledOperations", ()) for role in payload["roles"].values())
    if value is None:
        require(not enabled, "Static creation requires explicit native custody policy")
        return None
    require(type(value) is dict and set(value) == POLICY_FIELDS and value["schema"] == SCHEMA
        and type(value["deploymentId"]) is str
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value["deploymentId"]) is not None
        and len(canonical(value)) <= MAX_POLICY_BYTES)
    digest(value["controlPlaneConfigurationDigest"])
    require(type(value["operationMaxSeconds"]) is int and 1 <= value["operationMaxSeconds"] <= 30)
    _trust(value["trustRoots"])
    creation = profile.validate_policy(payload.get(profile.FIELD))
    require(value["controlPlaneConfigurationDigest"] == creation["controlPlaneConfigurationDigest"])
    forbidden = set()
    if root_key is not None:
        forbidden.add(sha256(root_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)))
    for role in payload["roles"].values():
        forbidden.update(item for name, item in role.items()
            if (name.endswith("SpkiDigest") or name.endswith("SpkiSha256")) and type(item) is str)
    assignments = value["assignments"]
    require(type(assignments) is list and 1 <= len(assignments) <= 32)
    identities = []
    for assignment in assignments:
        require(type(assignment) is dict and set(assignment) == ASSIGNMENT_FIELDS)
        # Reuse only the existing holder/PCR/EIF scalar contract, not its
        # operation policy, receipt, enrollment or permission.
        native._assignment({name: assignment[name] for name in native.ASSIGNMENT_FIELDS})
        require(assignment["keyId"] not in forbidden
            and assignment["keyId"] != assignment["controlPlaneResponseSigningKeyId"])
        require(_text(assignment["instanceId"], 4096).startswith("spiffe://"))
        profile._kek_id(assignment["secretKekId"])
        require(assignment["secretKekId"] == creation["nativeSecretKekId"])
        origin(assignment["intakeOrigin"]); origin(assignment["portalOrigin"])
        require(assignment["intakeOrigin"] != assignment["portalOrigin"])
        identities.append(assignment["holderId"])
    require(identities == sorted(set(identities)))
    return value


def verify_original(operation, arguments, *, evidence, configuration_payload, root_key, now_epoch_ns):
    """Verify original native bytes; no admission DTO or authority escapes.

    The caller owns signed configuration admission and the original cumulative
    request deadline. It must check that deadline after verification and before
    capability issuance; neither old generation time nor a quote renews it.
    """
    require(operation == profile.OPERATION and root_key is not None)
    values = profile.arguments(operation, arguments, typed="businessIntent" in arguments)
    selected = validate_policy(configuration_payload.get(FIELD), payload=configuration_payload, root_key=root_key)
    require(selected is not None)
    profile.verify_request_context(operation, values, selected_policy=configuration_payload[profile.FIELD], now_epoch_ns=now_epoch_ns)
    proof = _evidence(evidence)
    _bind(values, proof, now_epoch_ns)
    item = proof["statement"]
    assignments = [entry for entry in selected["assignments"] if entry["holderId"] == item["holderId"]]
    require(len(assignments) == 1, "Static producer has no independently admitted current assignment")
    expected = assignments[0]
    require(item["deploymentId"] == selected["deploymentId"]
        and item["controlPlaneConfigurationDigest"] == selected["controlPlaneConfigurationDigest"]
        and item["expiresAtEpochNs"] <= item["issuedAtEpochNs"] + selected["operationMaxSeconds"] * 1_000_000_000)
    for name in ("bootId", "keyId", "controlPlaneResponseSigningKeyId", "policyHash", "instanceId",
            "secretKekId", "intakeOrigin", "portalOrigin"):
        require(item[name] == expected[name])
    require(item["dataPlaneBinarySha256"] == expected["expectedBinaryDigest"])
    # Leaf digests are measured BrowserTls owner output signed below, not a
    # certificate or TLS identity accepted independently from an HTTP caller.
    raw_key = decoded(proof["nativeKeyEvidence"]["responseProofPublicKey"], 32, 32)
    key = Ed25519PublicKey.from_public_bytes(raw_key)
    require(sha256(key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)) == expected["keyId"])
    signature = decoded(proof["signature"][8:], 64, 64)
    statement_raw = canonical(item)
    key.verify(signature, SIGNATURE_DOMAIN + statement_raw)
    nonce = hashlib.sha256(ATTESTATION_DOMAIN + decoded(item["challenge"], 32, 32)
        + hashlib.sha256(statement_raw).digest() + signature).digest()
    boot_binding = hashlib.sha256(b"serverware/native-proof-custody-boot/v1\0"
        + current.encoded(expected["bootId"], 32) + bytes.fromhex(expected["keyId"][7:])
        + bytes.fromhex(expected["controlPlaneResponseSigningKeyId"][7:])).digest()
    user_data = b"serverware/enclave-runtime-key-binding/v1\0\x04" + b"".join(
        bytes.fromhex(expected[name][7:]) for name in _SCOPE_DIGESTS) + hashlib.sha256(raw_key).digest() + boot_binding
    document = decoded(proof["nativeKeyEvidence"]["attestationDocumentB64"], 12 * 1024)
    roots, crls, certificate_profile = _trust(selected["trustRoots"])
    verified, _, _, _, _ = nitro._verify_nitro_document_common(document, claims=None,
        expected_user_data_bytes=user_data, challenge=nonce, expected_pcrs=expected["expectedPcrs"],
        expected_eif=expected["expectedEif"], roots=roots, crls=crls, certificate_profile=certificate_profile,
        expected_module_id=expected["expectedModuleId"], now=now_epoch_ns // 1_000_000_000,
        max_age=expected["maxAgeSeconds"], future_skew=expected["futureSkewSeconds"], native_profile=True)
    require(type(verified["public_key"]) is bytes and verified["public_key"] == raw_key)
