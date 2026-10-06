#!/usr/bin/env python3
"""Inert selector/signature controls plus one real sealed-public-FD CLI call.

All keys/certificates are synthetic in-memory test material. The minimal signed
payload exercises public owner joins, not full runtime configuration admission.
No cold owner, hardware, assignment, service, database or enclave is started.
"""
import base64
import copy
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "scripts")]
import prepare_static_credential_portal as producer
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID
from serverware import authority_static_credential_assignment as assignment
from serverware import authority_credential_currentness_policy as currentness

C, H = producer.creation.profile.canonical, producer.creation.profile.sha256
B = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
PEM = lambda key: key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
SPKI = lambda key: key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def fixture(purpose):
    owner = producer.creation if purpose == "creation" else producer.rotation
    profile, proof = owner.profile, owner.proof
    root, delegated = [Ed25519PrivateKey.from_private_bytes(bytes([i]) * 32) for i in (1, 2)]
    ca = Ed25519PrivateKey.from_private_bytes(bytes([3]) * 32)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic selector fixture")])
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca.public_key())
        .serial_number(1).not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2040, 1, 1, tzinfo=timezone.utc))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(ca, None))
    target = {field: H(field.encode()) for field in assignment.TARGET_FIELDS}
    target.update(expectedPcrs={"PCR" + str(i): "sha384:" + "1" * 96 for i in range(3)},
        expectedEif="sha384:" + "1" * 96, maxAgeSeconds=30, futureSkewSeconds=0,
        instanceId="spiffe://fixture/native", secretKekId="attested-memory-kek:" + "1" * 24,
        intakeOrigin="https://native.example", portalOrigin="https://portal.example")
    policy = {"schema": profile.SCHEMA, "credentialPolicy": {"rpId": "portal.example", "origins": ["https://portal.example"],
        "allowedAuthenticatorClasses": ["hardware"], "hardwareRequired": True, "requireUserPresence": True,
        "requireUserVerification": True, "maxAssertionAgeSeconds": 30}, "operationMaxSeconds": 30,
        "maximumArgumentBytes": profile.MAX_ARGUMENT_BYTES, "maximumSecretBytes": profile.MAX_SECRET_BYTES,
        "nativeSecretKekId": target["secretKekId"],
        "intentMaxSeconds": 3600, "twoPersonRequired": False}
    if purpose == "rotation": policy["nativeCustodyPurpose"] = profile.NATIVE_CUSTODY_PURPOSE
    operations = set(profile.OPERATIONS)
    if purpose == "rotation": operations |= {producer.currentness.OP_QUIESCE, producer.currentness.OP_ADMIT}
    payload = {"schema": owner.AUTHORITY_SCHEMA, "sourceRevision": producer.contract.SOURCE_REVISION,
        "roles": {"planner": {"enabledOperations": sorted(operations)}}, profile.FIELD: policy,
        proof.FIELD: {"schema": proof.SCHEMA, "deploymentId": "fixture", "operationMaxSeconds": 30,
            "target": target, "assignmentAuthorizer": {"publicKeyPem": PEM(delegated).decode(),
                "publicKeyPemSha256": H(PEM(delegated)), "publicKeySpkiSha256": H(SPKI(delegated))},
            "trustRoots": {"apiVersion": proof.TRUST_SCHEMA,
                "awsNitroRootCertificatesPem": [certificate.public_bytes(serialization.Encoding.PEM).decode()],
                "awsNitroCrlsDerBase64url": [], "nitroCertificateProfile": {
                    "profileId": "aws-nitro-attestation-pki-native-v1", "allowedLeafExtendedKeyUsageOids": []}}}}
    if purpose == "rotation": payload[currentness.FIELD] = {"schema": currentness.ROTATION_POSTBOOT_SCHEMA}
    descriptor = {"apiVersion": producer.INPUT_SCHEMA, "purpose": purpose,
        "authorityRoot": {"fd": 4, "sha256": H(PEM(root)), "spkiSha256": H(SPKI(root))},
        "authorityConfiguration": {"fd": 5, "sha256": H(b"pending")},
        "controlPlaneConfigurationDigest": H(b"pending"),
        "inheritedDescriptors": {"selector": 80, "authorityRoot": 81, "authorityConfiguration": 82}}
    return dict(purpose=purpose, owner=owner, root=root, root_raw=PEM(root), payload=payload, descriptor=descriptor)


def originals(value):
    signature = value["root"].sign(producer.commitment.framed_digest(
        value["owner"].SIGNED_AUTHORITY_SCHEMA, C(value["payload"])).encode())
    raw = C({"schema": value["owner"].SIGNED_AUTHORITY_SCHEMA, "payload": value["payload"], "signature": B(signature)})
    descriptor = copy.deepcopy(value["descriptor"])
    descriptor["authorityConfiguration"]["sha256"] = H(raw)
    descriptor["controlPlaneConfigurationDigest"] = producer.configuration.full_configuration_digest(value["payload"])
    return descriptor, raw


def prepare(value, descriptor=None, raw=None):
    expected, original = originals(value)
    return producer.prepare(value["purpose"], C(expected if descriptor is None else descriptor),
        value["root_raw"], original if raw is None else raw)


def rejected(call):
    try: call()
    except (ValueError, InvalidSignature): return
    raise AssertionError("changed selector input was accepted")


def public_fd(raw):
    fd = os.memfd_create("synthetic-public-selector", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    os.write(fd, raw); os.fchmod(fd, 0o400)
    fcntl.fcntl(fd, fcntl.F_ADD_SEALS, producer.io.SEALS)
    return fd


def main():
    created, rotated = fixture("creation"), fixture("rotation")
    for value in (created, rotated):
        result = json.loads(prepare(value))
        assert set(result) == value["owner"].CONFIG_FIELDS and result["schema"] == value["owner"].CONFIG_SCHEMA
        assert result["authorityRootFd"] == 81 and result["authorityConfigurationFd"] == 82
    descriptor, raw = originals(rotated)
    changed = copy.deepcopy(descriptor); changed["purpose"] = "creation"
    rejected(lambda: prepare(rotated, changed, raw))
    for target in (31, 80):
        changed = copy.deepcopy(descriptor); changed["inheritedDescriptors"]["authorityRoot"] = target
        rejected(lambda: prepare(rotated, changed, raw))
    changed = copy.deepcopy(descriptor); changed["authorityRoot"]["sha256"] = H(b"wrong")
    rejected(lambda: prepare(rotated, changed, raw))
    changed = copy.deepcopy(descriptor); changed["controlPlaneConfigurationDigest"] = H(b"wrong")
    rejected(lambda: prepare(rotated, changed, raw))
    envelope = json.loads(raw); envelope["signature"] = B(bytes([7]) * 64); bad_raw = C(envelope)
    changed = copy.deepcopy(descriptor); changed["authorityConfiguration"]["sha256"] = H(bad_raw)
    rejected(lambda: prepare(rotated, changed, bad_raw))
    missing = fixture("rotation"); missing["payload"]["roles"]["planner"]["enabledOperations"].remove(producer.currentness.OP_ADMIT)
    rejected(lambda: prepare(missing))
    aliased = fixture("creation")
    aliased["payload"][aliased["owner"].proof.FIELD]["assignmentAuthorizer"] = {
        "publicKeyPem": PEM(aliased["root"]).decode(), "publicKeyPemSha256": H(PEM(aliased["root"])),
        "publicKeySpkiSha256": H(SPKI(aliased["root"]))}
    rejected(lambda: prepare(aliased))
    # One actual -I/-B root invocation with sealed public originals and pipe
    # output. No production keys, future inherited descriptors or owner start.
    root_fd, config_fd = public_fd(rotated["root_raw"]), public_fd(raw)
    try:
        descriptor["authorityRoot"]["fd"], descriptor["authorityConfiguration"]["fd"] = root_fd, config_fd
        original = C(descriptor); input_fd = public_fd(original)
        try:
            result = subprocess.run([sys.executable, "-I", "-B", str(ROOT / "scripts/prepare_static_credential_portal.py"),
                "--purpose", "rotation", "--input-fd", str(input_fd), "--input-sha256", H(original)],
                pass_fds=(root_fd, config_fd, input_fd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False)
            assert result.returncode == 0 and result.stdout == prepare(rotated, descriptor, raw) and result.stderr == b""
        finally: os.close(input_fd)
    finally: os.close(root_fd); os.close(config_fd)
    print("PASS 10 public selector controls + sealed-public-FD/pipe CLI; synthetic signature roots only")


if __name__ == "__main__": main()
