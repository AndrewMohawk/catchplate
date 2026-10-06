#!/usr/bin/env python3
"""Synthetic PKI/signature checks; no NSM, AWS identity or runtime admission.

All certificates, COSE documents and keys below are ephemeral test fixtures.
The actual unmodified cryptographic validators run; no success verdict is mocked.
"""
import base64
import copy
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path
import sys
import time

sys.path[:0] = [str(Path(__file__).resolve().parents[1]), str(Path(__file__).resolve().parent)]
import cbor2
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
from cryptography.x509.oid import NameOID
from serverware import authority_static_credential_assignment_issuer as issuer
from serverware import authority_static_credential_assignment as assignment
from serverware import authority_static_credential_provenance as provenance
from test_static_credential_portal_selector import fixture as selection_fixture, originals

C, H = issuer.canonical, issuer.sha256
B = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def fixture(purpose="creation"):
    selected = selection_fixture(purpose)
    now = time.time_ns() // 1_000_000_000 * 1_000_000_000
    at = datetime.fromtimestamp(now // 1_000_000_000, timezone.utc)
    p384root, p384leaf = ec.generate_private_key(ec.SECP384R1()), ec.generate_private_key(ec.SECP384R1())
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic assignment root")])
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic assignment leaf")])
    def certificate(subject, public, ca, serial):
        return (x509.CertificateBuilder().subject_name(subject).issuer_name(root_name).public_key(public)
            .serial_number(serial).not_valid_before(at-timedelta(hours=1)).not_valid_after(at+timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=ca, crl_sign=ca,
                encipher_only=False, decipher_only=False), critical=True).sign(p384root, hashes.SHA384()))
    cert_root = certificate(root_name, p384root.public_key(), True, 1)
    cert_leaf = certificate(leaf_name, p384leaf.public_key(), False, 2)
    proof = issuer.custody
    policy = selected["payload"][proof.FIELD]
    workload_key = ed25519.Ed25519PrivateKey.from_private_bytes(b"w"*32)
    workload_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic workload CA")])
    workload_ca = (x509.CertificateBuilder().subject_name(workload_name).issuer_name(workload_name)
        .public_key(workload_key.public_key()).serial_number(3).not_valid_before(at-timedelta(hours=1))
        .not_valid_after(at+timedelta(hours=1)).add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
        .sign(workload_key,None))
    ca_raw = workload_ca.public_bytes(serialization.Encoding.DER)
    ca = x509.load_der_x509_certificate(ca_raw)
    policy["trustRoots"]["awsNitroRootCertificatesPem"] = [cert_root.public_bytes(serialization.Encoding.PEM).decode()]
    target = policy["target"]
    if purpose == "rotation":
        current = issuer.current_policy
        ct = {name: target[name] for name in current.ASSIGNMENT_FIELDS - assignment.DYNAMIC_FIELDS}
        ct["targetId"] = "synthetic-native"
        selected["payload"][current.FIELD] = {"schema": current.ROTATION_POSTBOOT_SCHEMA,
            "deploymentId": policy["deploymentId"], "operationMaxSeconds": 30, "maximumHolders": current.profile.MAX_ROWS,
            "trustRoots": {**policy["trustRoots"], "apiVersion": current.TRUST_SCHEMA}, "targets": [ct],
            "assignmentAuthorizer": policy["assignmentAuthorizer"], "staticCreationProvenance": provenance.SCHEMA,
            "staticGenerationProvenance": provenance.ROTATION_SCHEMA}
    _, configuration = originals(selected)
    native_key = ed25519.Ed25519PrivateKey.from_private_bytes(b"p"*32).public_key()
    raw_key = native_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key_id = H(issuer._spki(native_key)); boot = b"b"*32; nonce = b"n"*32
    scope = {"releaseRecordSha256": target["releaseRecordSha256"], "policyHash": target["policyHash"],
        "configurationSha256": H(b"synthetic full N original"), "caCertificateSha256": H(ca_raw),
        "caPublicKeySpkiSha256": H(issuer._spki(ca.public_key()))}
    binding = hashlib.sha256(b"serverware/native-proof-custody-boot/v1\0" + boot
        + bytes.fromhex(key_id[7:]) + bytes.fromhex(target["controlPlaneResponseSigningKeyId"][7:])).digest()
    user_data = b"serverware/enclave-runtime-key-binding/v1\0\x04" + b"".join(
        bytes.fromhex(scope[name][7:]) for name in issuer.SCOPE_FIELDS) + hashlib.sha256(raw_key).digest() + binding
    protected = cbor2.dumps({1: -35}, canonical=True)
    payload = cbor2.dumps({"module_id": "synthetic-module", "timestamp": now//1_000_000, "digest": "SHA384",
        "pcrs": {int(name[3:]): bytes.fromhex(pin[7:]) for name, pin in target["expectedPcrs"].items()},
        "certificate": cert_leaf.public_bytes(serialization.Encoding.DER),
        "cabundle": [cert_root.public_bytes(serialization.Encoding.DER)], "public_key": raw_key,
        "user_data": user_data, "nonce": nonce}, canonical=True)
    signature = p384leaf.sign(cbor2.dumps(["Signature1", protected, b"", payload]), ec.ECDSA(hashes.SHA384()))
    r, s = utils.decode_dss_signature(signature)
    quote = cbor2.dumps([protected, {}, payload, r.to_bytes(48,"big")+s.to_bytes(48,"big")], canonical=True)
    identity = {"apiVersion": issuer.IDENTITY_API, "purpose": "postboot-static-assignment-inputs",
        "evidenceScope": "unverified-startup-role4-public-material", "okForAction": False,
        "bootId": B(boot), "keyId": key_id,
        "publicKeyPem": native_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
        "controlPlaneResponseSigningKeyId": target["controlPlaneResponseSigningKeyId"], "scope": scope,
        "caCertificateDerBase64url": B(ca_raw), "nativeKeyEvidence": {"apiVersion": "serverware.nativeResponseProofKeyEvidence/v1",
            "responseProofPublicKey": B(raw_key), "attestationDocumentB64": B(quote)},
        "quoteNonceBase64url": B(nonce), "quoteUserDataBase64url": B(user_data)}
    launch = {"apiVersion": "serverware.nativeStartupLaunch/v1", "releaseRecordSha256": scope["releaseRecordSha256"],
        "configurationSha256": scope["configurationSha256"], "deadlineBoottimeNs": 1,
        "caNotBeforeUnixSeconds": issuer._epoch_ns(issuer.nitro.certificate_time(ca,"not_valid_before"))//10**9,
        "caNotAfterUnixSeconds": issuer._epoch_ns(issuer.nitro.certificate_time(ca,"not_valid_after"))//10**9,
        "ingressNotBeforeUnixSeconds": now//10**9-1, "ingressNotAfterUnixSeconds": now//10**9+60,
        "ingressNonceBase64url": B(b"i"*32), "proofNonceBase64url": B(nonce)}
    value = {"apiVersion": issuer.API, "configurationOriginal": configuration.decode(),
        "configurationRoot": {"publicKeyPem": selected["root_raw"].decode(), "publicKeyPemSha256": H(selected["root_raw"]),
            "publicKeySpkiSha256": H(issuer._spki(selected["root"].public_key()))},
        "nativeIdentityOriginal": C(identity).decode()+"\n", "nativeLaunchOriginal": C(launch).decode(),
        "expectedModuleId": "synthetic-module", "issuedAtEpochNs": now-10**9, "expiresAtEpochNs": now+60*10**9}
    return value, now, ed25519.Ed25519PrivateKey.from_private_bytes(bytes([2])*32)


def main():
    passed = []
    def reject(name, call):
        try: call()
        except (ValueError, InvalidSignature, issuer.nitro.VerificationError): passed.append(name)
        else: raise AssertionError(name+" accepted")
    for purpose in ("creation", "rotation"):
        value, now, key = fixture(purpose)
        raw = C(value); ready = issuer.prepare_input(raw, now_epoch_ns=now)
        signed = issuer.sign(raw, key, check=lambda: now)
        parsed = assignment.original(signed.decode())["payload"]
        assert set(parsed["assignment"]) == assignment.ASSIGNMENT_FIELDS
        assert parsed["expiresAtEpochNs"] == value["expiresAtEpochNs"] and ready.expires < parsed["expiresAtEpochNs"]
        passed.append(purpose+" actual-PKI/signature")
    value, now, key = fixture()
    def run(changed, at=now): return issuer.prepare_input(C(changed), now_epoch_ns=at)
    for name, field, changed_value in [("module", "expectedModuleId", "different-module"),
            ("expired", "expiresAtEpochNs", now), ("unknown-field", "extra", True)]:
        changed=copy.deepcopy(value); changed[field]=changed_value; reject(name,lambda:run(changed))
    for name, container, field, replacement in [
            ("launch-nonce","nativeLaunchOriginal","proofNonceBase64url",B(b"x"*32)),
            ("launch-N","nativeLaunchOriginal","configurationSha256",H(b"wrong")),
            ("launch-CA-time","nativeLaunchOriginal","caNotAfterUnixSeconds",now//10**9+120),
            ("identity-boot","nativeIdentityOriginal","bootId",B(b"x"*32)),
            ("identity-key","nativeIdentityOriginal","keyId",H(b"wrong")),
            ("identity-role","nativeIdentityOriginal","quoteUserDataBase64url",B(b"wrong"))]:
        changed=copy.deepcopy(value); item=json.loads(changed[container]); item[field]=replacement
        changed[container]=C(item).decode()+("\n" if container=="nativeIdentityOriginal" else "")
        reject(name,lambda:run(changed))
    changed=copy.deepcopy(value); changed["nativeIdentityOriginal"]=changed["nativeIdentityOriginal"].rstrip()
    reject("literal-LF",lambda:run(changed))
    changed=copy.deepcopy(value); envelope=json.loads(changed["configurationOriginal"]); envelope["signature"]=B(bytes(64))
    changed["configurationOriginal"]=C(envelope).decode(); reject("configuration-signature",lambda:run(changed))
    reject("stale-quote",lambda:run(value,now+31*10**9))
    ready=run(value)
    reject("wrong-authority-key",lambda:issuer.sign(C(value),ed25519.Ed25519PrivateKey.generate(),check=lambda:now))
    reject("expires-during-sign",lambda:issuer.sign(C(value),key,check=lambda:ready.expires))
    reject("constructed-preparation",lambda:issuer.sign(ready,key,check=lambda:now))
    duplicate=C(value).replace(b'{',b'{"apiVersion":"duplicate",',1)
    reject("duplicate-input",lambda:issuer.prepare_input(duplicate,now_epoch_ns=now))
    print("PASS",len(passed),"synthetic controls:",", ".join(passed))


if __name__ == "__main__": main()
