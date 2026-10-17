#!/usr/bin/env python3
"""Synthetic public-original controls, not cold admission or native liveness.

Reuse the existing synthetic role-4 PKI fixture and actual assignment validators.
Only in-memory fixture keys sign; no production key, FD installation, CLI,
service, database, NSM or runtime is used.
"""
import base64
import copy
import json
from pathlib import Path
import sys

sys.path[:0] = [str(Path(__file__).resolve().parents[1]), str(Path(__file__).resolve().parent)]
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import prepare_currentness_assignment as producer
from test_static_credential_assignment_issuer import fixture, issuer
from catchplate import authority_credential_currentness_policy as native

C, H = producer.profile.canonical, producer.profile.sha256
B = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def main():
    value, now, key = fixture("rotation")
    # Actual synthetic PKI verification yields these public holder observations.
    # This is fixture construction, not permission to convert static S into S.
    prepared = issuer.prepare_input(C(value), now_epoch_ns=now)
    observed = json.loads(prepared.payload_original)["assignment"]
    authority = value["configurationOriginal"].encode("ascii")
    payload = json.loads(authority)["payload"]
    policy = payload[native.FIELD]
    root = value["configurationRoot"]["publicKeyPem"].encode("ascii")
    selection = {"schema": producer.assignment.SCHEMA,
        "controlPlaneConfigurationDigest": producer.configuration.full_configuration_digest(payload),
        "deploymentId": policy["deploymentId"], "targetId": policy["targets"][0]["targetId"],
        "assignment": {name: observed[name] for name in native.ASSIGNMENT_FIELDS},
        "issuedAtEpochNs": value["issuedAtEpochNs"], "expiresAtEpochNs": value["expiresAtEpochNs"]}

    def signed(item, signing_key=key):
        signature = signing_key.sign(producer.commitment.framed_digest(
            producer.assignment.SIGNED_SCHEMA, C(item)).encode("ascii"))
        return C({"schema": producer.assignment.SIGNED_SCHEMA, "payload": item, "signature": B(signature)})

    assignment = signed(selection)
    assert producer.assignment.verify_original(assignment.decode("ascii"), configuration_payload=payload,
        root_key=prepared.root, now_epoch_ns=now) == selection
    descriptor = {"apiVersion": producer.INPUT_SCHEMA,
        "authorityRoot": {"fd": 4, "sha256": H(root),
            "spkiSha256": value["configurationRoot"]["publicKeySpkiSha256"]},
        "authorityConfiguration": {"fd": 5, "sha256": H(authority)},
        "assignment": {"fd": 6, "sha256": H(assignment)},
        "controlPlaneConfigurationDigest": selection["controlPlaneConfigurationDigest"],
        "inheritedDescriptors": {"selector": 80, "authorityRoot": 81, "authorityConfiguration": 82, "assignment": 83}}
    passed = []

    def run(item=descriptor, root_raw=root, authority_raw=authority, assignment_raw=assignment, at=now):
        return producer.prepare(C(item), root_raw, authority_raw, assignment_raw, now_epoch_ns=at)

    def reject(name, call):
        try:
            call()
        except (ValueError, InvalidSignature):
            passed.append(name)
        else:
            raise AssertionError(name + " accepted")

    output, issued, expires = run()
    decoded = json.loads(output)
    assert C(decoded) == output and not output.endswith(b"\n")
    assert set(decoded) == producer.cold.CONFIG_FIELDS and len(decoded) == 11
    assert decoded["schema"] == producer.cold.CONFIG_SCHEMA
    assert decoded["sourceRevision"] == producer.contract.SOURCE_REVISION
    assert (decoded["authorityRootFd"], decoded["authorityConfigurationFd"], decoded["assignmentFd"]) == (81, 82, 83)
    assert decoded["authorityRootSha256"] == H(root) and decoded["authorityConfigurationSha256"] == H(authority)
    assert decoded["assignmentSha256"] == H(assignment)
    assert decoded["authorityRootSpkiSha256"] == descriptor["authorityRoot"]["spkiSha256"]
    assert decoded["authorityConfigurationDigest"] == decoded["controlPlaneConfigurationDigest"] == selection["controlPlaneConfigurationDigest"]
    assert (issued, expires) == (selection["issuedAtEpochNs"], selection["expiresAtEpochNs"])
    assert len(set(producer.descriptor(C(descriptor))["inheritedDescriptors"].values())) == 4
    passed.append("exact11-field/four-FD selector and unchanged S interval")

    for source in producer.SOURCE_BOUNDS:
        changed = copy.deepcopy(descriptor); changed[source]["sha256"] = H(b"wrong")
        reject(source + " pin", lambda: run(changed))
    changed = copy.deepcopy(descriptor); changed["authorityRoot"]["spkiSha256"] = H(b"wrong")
    reject("root SPKI pin", lambda: run(changed))
    wrong_key = Ed25519PrivateKey.from_private_bytes(b"z" * 32)
    wrong_root = wrong_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    changed = copy.deepcopy(descriptor)
    changed["authorityRoot"].update(sha256=H(wrong_root), spkiSha256=H(wrong_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)))
    reject("repinned wrong root", lambda: run(changed, root_raw=wrong_root))
    changed_envelope = json.loads(authority); changed_envelope["signature"] = B(bytes(64))
    bad_authority = C(changed_envelope); changed = copy.deepcopy(descriptor)
    changed["authorityConfiguration"]["sha256"] = H(bad_authority)
    reject("repinned A signature", lambda: run(changed, authority_raw=bad_authority))
    bad_assignment = signed(selection, wrong_key); changed = copy.deepcopy(descriptor)
    changed["assignment"]["sha256"] = H(bad_assignment)
    reject("repinned S wrong signer", lambda: run(changed, assignment_raw=bad_assignment))
    for field, replacement in (("targetId", "different-target"), ("controlPlaneConfigurationDigest", H(b"wrong"))):
        altered = copy.deepcopy(selection); altered[field] = replacement
        bad_assignment = signed(altered); changed = copy.deepcopy(descriptor)
        changed["assignment"]["sha256"] = H(bad_assignment)
        reject("signed S " + field, lambda: run(changed, assignment_raw=bad_assignment))
    changed = copy.deepcopy(descriptor); changed["controlPlaneConfigurationDigest"] = H(b"wrong")
    reject("full A digest", lambda: run(changed))
    reject("expired S", lambda: run(at=expires))
    reject("not-yet-valid S", lambda: run(at=issued - 1))
    for field, replacement in (("assignment", 80), ("authorityRoot", 31)):
        changed = copy.deepcopy(descriptor); changed["inheritedDescriptors"][field] = replacement
        reject("target FD " + field, lambda: run(changed))
    changed = copy.deepcopy(descriptor); changed["assignment"]["fd"] = 4
    reject("duplicate source FD", lambda: run(changed))
    changed = copy.deepcopy(descriptor); del changed["inheritedDescriptors"]["assignment"]
    reject("missing fourth FD", lambda: run(changed))
    changed = copy.deepcopy(descriptor); changed["extra"] = True
    reject("unknown descriptor field", lambda: run(changed))
    duplicate = C(descriptor).replace(b"{", b'{"apiVersion":"duplicate",', 1)
    reject("duplicate JSON member", lambda: producer.prepare(duplicate, root, authority, assignment, now_epoch_ns=now))
    print("PASS", len(passed), "synthetic public-original controls:", ", ".join(passed))


if __name__ == "__main__":
    main()
