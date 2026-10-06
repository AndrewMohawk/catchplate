"""Independently admitted native-holder evidence, never a quoted-success DTO.

Only the actual measured configuration supplies roots and complete assignments.
Both verifier and planner call this before SQL or persisted-plan admission.
"""
import hashlib
import re

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from scripts import verify_nitro_tee as nitro
from serverware import authority_credential_currentness as profile
from serverware import authority_oauth_refresh as refresh

FIELD = "credentialCurrentnessPolicy"
SCHEMA = "serverware.credentialCurrentnessAuthorityPolicy/v2"
POSTBOOT_SCHEMA = "serverware.credentialCurrentnessAuthorityPolicy/v3"
TRUST_SCHEMA = "serverware.credentialCurrentnessNativeTrustRoots/v1"
FIELDS = frozenset({"schema", "deploymentId", "operationMaxSeconds", "maximumHolders", "trustRoots", "holders"})
POSTBOOT_FIELDS = (FIELDS - {"holders"}) | {"targets", "assignmentAuthorizer"}
ASSIGNMENT_FIELDS = frozenset({"holderId", "bootId", "keyId", "controlPlaneResponseSigningKeyId", "releaseRecordSha256", "policyHash", "configurationSha256", "caCertificateSha256", "caPublicKeySpkiSha256", "expectedBinaryDigest", "expectedPcrs", "expectedEif", "expectedModuleId", "maxAgeSeconds", "futureSkewSeconds"})
_SCOPE_DIGESTS = ("releaseRecordSha256", "policyHash", "configurationSha256", "caCertificateSha256", "caPublicKeySpkiSha256", "expectedBinaryDigest")


def _trust(value):
    profile.require(type(value) is dict and set(value) == {"apiVersion", "awsNitroRootCertificatesPem", "awsNitroCrlsDerBase64url", "nitroCertificateProfile"}
        and value["apiVersion"] == TRUST_SCHEMA and value["awsNitroCrlsDerBase64url"] == []
        and len(profile.canonical(value)) <= 128 * 1024)
    items = value["awsNitroRootCertificatesPem"]
    profile.require(type(items) is list and 1 <= len(items) <= nitro.MAX_CERTIFICATES)
    roots = []
    for pem in items:
        profile.require(type(pem) is str and 1 <= len(pem) <= nitro.MAX_CERT_BYTES)
        raw = pem.encode("ascii")
        cert = x509.load_pem_x509_certificate(raw)
        profile.require(cert.public_bytes(serialization.Encoding.PEM) == raw and nitro.basic_constraints(cert, "currentness Nitro root").ca)
        roots.append(cert)
    profile.require(len({nitro.certificate_sha256(root) for root in roots}) == len(roots))
    certificates = value["nitroCertificateProfile"]
    profile.require(type(certificates) is dict and set(certificates) == {"profileId", "allowedLeafExtendedKeyUsageOids"}
        and certificates["profileId"] == "aws-nitro-attestation-pki-native-v1")
    oids = certificates["allowedLeafExtendedKeyUsageOids"]
    profile.require(type(oids) is list and len(oids) <= 32
        and all(type(oid) is str and len(oid) <= 128 and re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", oid) is not None for oid in oids)
        and oids == sorted(set(oids)))
    return roots, [], certificates


def _assignment(value):
    profile.require(type(value) is dict and set(value) == ASSIGNMENT_FIELDS)
    for name in ("holderId", "keyId", "controlPlaneResponseSigningKeyId") + _SCOPE_DIGESTS:
        profile.digest(value[name])
        profile.require(value[name] != "sha256:" + "0" * 64)
    profile.require(value["holderId"] == profile.holder_id(value["bootId"], value["keyId"]))
    pcrs = value["expectedPcrs"]
    profile.require(type(pcrs) is dict and 3 <= len(pcrs) <= 32 and {"PCR0", "PCR1", "PCR2"} <= set(pcrs))
    for name, digest in pcrs.items():
        profile.require(type(name) is str and re.fullmatch(r"PCR(?:[0-9]|[12][0-9]|3[01])", name) is not None)
        nitro.require_sha384(digest, name)
        if name in {"PCR0", "PCR1", "PCR2"}:
            profile.require(digest != "sha384:" + "0" * 96)
    nitro.require_sha384(value["expectedEif"], "currentness EIF")
    profile.require(value["expectedEif"] == pcrs["PCR0"])
    refresh.text(value["expectedModuleId"], 256)
    profile.require(type(value["maxAgeSeconds"]) is int and 1 <= value["maxAgeSeconds"] <= 300
        and type(value["futureSkewSeconds"]) is int and 0 <= value["futureSkewSeconds"] <= 30)
    return value


def validate_policy(value, *, payload, root_key=None):
    enabled = any(set(role.get("enabledOperations", ())) & (profile.OPERATIONS | refresh.OPERATIONS) for role in payload["roles"].values())
    if value is None:
        profile.require(not enabled, "strict currentness operations and refresh require an explicit measured-holder policy")
        return None
    profile.require(type(value) is dict
        and ((set(value) == FIELDS and value["schema"] == SCHEMA)
            or (set(value) == POSTBOOT_FIELDS and value["schema"] == POSTBOOT_SCHEMA))
        and type(value["deploymentId"]) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value["deploymentId"]) is not None)
    profile.require(type(value["operationMaxSeconds"]) is int and 1 <= value["operationMaxSeconds"] <= 30
        and type(value["maximumHolders"]) is int and value["maximumHolders"] == profile.MAX_ROWS)
    _trust(value["trustRoots"])
    if value["schema"] == POSTBOOT_SCHEMA:
        from serverware import authority_credential_currentness_assignment as assignment
        targets = value["targets"]
        profile.require(type(targets) is list and 1 <= len(targets) <= value["maximumHolders"])
        ids = [assignment.target(item)["targetId"] for item in targets]
        profile.require(ids == sorted(set(ids)) and len(profile.canonical(value)) <= 512 * 1024)
        assignment.authorizer(value["assignmentAuthorizer"], payload=payload, root_key=root_key, targets=targets)
        return value
    holders = value["holders"]
    profile.require(type(holders) is list and 1 <= len(holders) <= value["maximumHolders"])
    ids = []
    excluded = set()
    if root_key is not None:
        excluded.add(profile.sha256(root_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)))
    for role in payload["roles"].values():
        for name, item in role.items():
            if name.endswith("SpkiDigest") or name.endswith("SpkiSha256"):
                if type(item) is str:
                    excluded.add(item)
    for holder in holders:
        _assignment(holder)
        profile.require(holder["keyId"] not in excluded and holder["keyId"] != holder["controlPlaneResponseSigningKeyId"],
            "native holder key cannot be an authority/configuration/control-plane signing key")
        ids.append(holder["holderId"])
    profile.require(ids == sorted(set(ids)) and len(profile.canonical(value)) <= 512 * 1024)
    return value


def _holder(policy, holder_id):
    profile.require(policy["schema"] == SCHEMA, "Postboot currentness requires its separate signed original")
    matches = [item for item in policy["holders"] if item["holderId"] == holder_id]
    profile.require(len(matches) == 1, "holder has no independently admitted current assignment")
    return matches[0]


def verify_original(operation, arguments, *, configuration_payload, root_key, now_epoch_ns):
    from serverware.authority_policy_canary_policy import full_configuration_digest
    values = profile.arguments(operation, arguments, typed="businessIntent" in arguments)
    policy = validate_policy(configuration_payload.get(FIELD), payload=configuration_payload, root_key=root_key)
    profile.require(policy is not None and type(now_epoch_ns) is int and now_epoch_ns > 0
        and values["control_plane_configuration_digest"] == full_configuration_digest(configuration_payload),
        "actual custody configuration differs from the independently admitted currentness policy")
    request = values["request"]
    selected = None
    if policy["schema"] == POSTBOOT_SCHEMA and operation in profile.ASSIGNMENT_OPERATIONS:
        from serverware import authority_credential_currentness_assignment as assignment
        profile.require("assignment_original" in values, "Postboot currentness assignment original is absent")
        selected = assignment.verify_original(values["assignment_original"],
            configuration_payload=configuration_payload, root_key=root_key, now_epoch_ns=now_epoch_ns)
    else:
        profile.require("assignment_original" not in values, "Legacy or drain-only currentness cannot accept a postboot original")
    if operation in {profile.OP_CHALLENGE, profile.OP_QUIESCE}:
        profile.require(request["issuedAtEpochNs"] <= now_epoch_ns < request["expiresAtEpochNs"]
            <= request["issuedAtEpochNs"] + policy["operationMaxSeconds"] * 1_000_000_000)
        if operation == profile.OP_CHALLENGE:
            if selected is None:
                _holder(policy, request["holderId"])
            else:
                profile.require(request["holderId"] == selected["assignment"]["holderId"]
                    and selected["issuedAtEpochNs"] <= request["issuedAtEpochNs"]
                    < request["expiresAtEpochNs"] <= selected["expiresAtEpochNs"])
        return
    if operation == profile.OP_ADMIT:
        return
    envelope = profile.evidence(request["evidence"])
    statement = envelope["statement"]
    expected = _holder(policy, statement["holderId"]) if selected is None else selected["assignment"]
    if selected is not None:
        profile.require(statement["holderId"] == expected["holderId"]
            and selected["issuedAtEpochNs"] <= statement["issuedAtEpochNs"]
            < statement["expiresAtEpochNs"] <= selected["expiresAtEpochNs"])
    profile.require(statement["deploymentId"] == policy["deploymentId"]
        and statement["issuedAtEpochNs"] <= now_epoch_ns < statement["expiresAtEpochNs"]
        <= statement["issuedAtEpochNs"] + policy["operationMaxSeconds"] * 1_000_000_000)
    for name in ("bootId", "keyId", "controlPlaneResponseSigningKeyId", "policyHash"):
        profile.require(statement[name] == expected[name])
    profile.require(statement["dataPlaneBinarySha256"] == expected["expectedBinaryDigest"])
    native = envelope["nativeKeyEvidence"]
    raw_key = profile.encoded(native["responseProofPublicKey"], 32)
    profile.require(raw_key != bytes(32))
    key = Ed25519PublicKey.from_public_bytes(raw_key)
    spki = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    profile.require(profile.sha256(spki) == expected["keyId"])
    signature = profile.encoded(envelope["signature"][8:], 64)
    statement_bytes = profile.canonical(statement)
    key.verify(signature, profile.SIGNATURE_DOMAIN + statement_bytes)
    nonce = hashlib.sha256(profile.ATTESTATION_DOMAIN + profile.encoded(statement["challenge"], 32)
        + hashlib.sha256(statement_bytes).digest() + signature).digest()
    boot_binding = hashlib.sha256(b"serverware/native-proof-custody-boot/v1\0" + profile.encoded(expected["bootId"], 32)
        + bytes.fromhex(expected["keyId"][7:]) + bytes.fromhex(expected["controlPlaneResponseSigningKeyId"][7:])).digest()
    user_data = b"serverware/enclave-runtime-key-binding/v1\0\x04" + b"".join(bytes.fromhex(expected[name][7:])
        for name in _SCOPE_DIGESTS[:5]) + hashlib.sha256(raw_key).digest() + boot_binding
    document = nitro.b64url_decode(native["attestationDocumentB64"], "original currentness role-4 quote", max_bytes=12 * 1024)
    profile.require(bool(document))
    roots, crls, certificates = _trust(policy["trustRoots"])
    verified, _, _, _, _ = nitro._verify_nitro_document_common(document, claims=None,
        expected_user_data_bytes=user_data, challenge=nonce, expected_pcrs=expected["expectedPcrs"],
        expected_eif=expected["expectedEif"], roots=roots, crls=crls, certificate_profile=certificates,
        expected_module_id=expected["expectedModuleId"], now=now_epoch_ns // 1_000_000_000,
        max_age=expected["maxAgeSeconds"], future_skew=expected["futureSkewSeconds"], native_profile=True)
    profile.require(type(verified["public_key"]) is bytes and verified["public_key"] == raw_key)
    # No transferable verified/success object escapes this admission boundary.
