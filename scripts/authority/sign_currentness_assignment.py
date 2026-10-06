#!/usr/bin/env python3
"""Sign one independently approved postboot currentness assignment, offline.

Run python3 -I -B as root with --input-fd, its independently approved complete
--input-sha256, and a distinct preprovisioned sealed 32-byte --authority-key-fd.
Input is canonical serverware.currentnessAssignmentAuthorityInput/v1 containing
payloadOriginal, configurationOriginal (signed v6 authority configuration), and
configurationRoot {publicKeyPem, publicKeyPemSha256, publicKeySpkiSha256}.

Stdout is only the existing canonical signedCredentialCurrentnessAssignment/v1
original, without a newline, on the root supervisor pipe. Require complete
bytes AND exit0; failure or partial output authorizes no retry. No file is
created, replaced or published; no key, target, interval or approval is created.
The input pin/root selection are the independent operator's responsibility.
Python/OpenSSL keys are software custody, not hardware or guaranteed erasure.
An external supervisor must bound filesystem and cryptographic stalls. Native
quote/liveness verification remains mandatory at the actual receiving service.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import native_pilot_authority_io as io
from serverware import authority_contract as contract
from serverware import authority_credential_currentness as p
from serverware import authority_credential_currentness_assignment as assignment
from serverware import authority_credential_currentness_policy as native
from serverware import authority_oauth_setup as codec
from serverware import authority_policy_canary_policy as configuration
from serverware import authority_request_commitment as commitment
from serverware import native_shadow_nitro_originals as originals

API = "serverware.currentnessAssignmentAuthorityInput/v1"
SIGNED_CONFIGURATION = "serverware.signedPolicyAuthorityServiceConfiguration/v6"
MAX_INPUT = 2 * contract.MAX_REQUEST_BYTES + 2 * assignment.MAX_ORIGINAL_BYTES + 16384


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("currentness assignment invocation refused")


def _prepare(raw, now):
    value = codec.document(raw, MAX_INPUT)
    p.require(set(value) == {"apiVersion", "payloadOriginal", "configurationOriginal", "configurationRoot"}
        and value["apiVersion"] == API)
    selected_root = value["configurationRoot"]
    p.require(type(selected_root) is dict and set(selected_root) == assignment.AUTHORIZER_FIELDS
        and type(selected_root["publicKeyPem"]) is str and 0 < len(selected_root["publicKeyPem"]) <= 4096)
    root_raw = selected_root["publicKeyPem"].encode("ascii")
    root = serialization.load_pem_public_key(root_raw)
    p.require(isinstance(root, Ed25519PublicKey)
        and root.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo) == root_raw
        and p.sha256(root_raw) == p.digest(selected_root["publicKeyPemSha256"])
        and p.sha256(root.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
            == p.digest(selected_root["publicKeySpkiSha256"]))
    p.require(type(value["configurationOriginal"]) is str)
    envelope = codec.document(value["configurationOriginal"].encode("utf-8"), contract.MAX_REQUEST_BYTES, exact=False)
    p.require(set(envelope) == {"schema", "payload", "signature"} and envelope["schema"] == SIGNED_CONFIGURATION)
    authority = envelope["payload"]
    p.require(type(authority) is dict and authority.get("schema") == configuration.CONFIGURATION_SCHEMA
        and authority.get("sourceRevision") == contract.SOURCE_REVISION and type(authority.get("roles")) is dict)
    root.verify(p.encoded(envelope["signature"], 64),
        commitment.framed_digest(SIGNED_CONFIGURATION, p.canonical(authority)).encode("ascii"))
    policy = native.validate_policy(authority.get(native.FIELD), payload=authority, root_key=root)
    p.require(policy is not None and policy["schema"] == native.POSTBOOT_SCHEMA)

    original = value["payloadOriginal"]
    p.require(type(original) is str and original.isascii() and 0 < len(original) <= assignment.MAX_ORIGINAL_BYTES)
    payload = codec.document(original.encode("ascii"), assignment.MAX_ORIGINAL_BYTES)
    # The consumer's structural parser needs a fixed-size signature slot. This
    # zero slot is only an unsigned shape/size preflight, never verified as
    # authority, signed, emitted or used as a native-success object.
    preflight = p.canonical({"schema": assignment.SIGNED_SCHEMA, "payload": payload,
        "signature": codec.encoded(bytes(64))}).decode("ascii")
    p.require(assignment.original(preflight)["payload"] == payload)
    p.require(type(now) is int and payload["issuedAtEpochNs"] <= now < payload["expiresAtEpochNs"]
        and payload["controlPlaneConfigurationDigest"] == configuration.full_configuration_digest(authority)
        and payload["deploymentId"] == policy["deploymentId"])
    targets = [item for item in policy["targets"] if item["targetId"] == payload["targetId"]]
    p.require(len(targets) == 1 and p.canonical({"targetId": payload["targetId"], **{
        name: payload["assignment"][name] for name in native.ASSIGNMENT_FIELDS - assignment.DYNAMIC_FIELDS}})
        == p.canonical(targets[0]))
    public = assignment.authorizer(policy["assignmentAuthorizer"], payload=authority,
        root_key=root, targets=policy["targets"])
    p.require(payload["assignment"]["keyId"] not in assignment.excluded_keys(authority, root)
        | {item["controlPlaneResponseSigningKeyId"] for item in policy["targets"]}
        | {policy["assignmentAuthorizer"]["publicKeySpkiSha256"]})
    return payload, authority, root, public


def main():
    try:
        parser = _Parser(description=__doc__, add_help=False, allow_abbrev=False)
        parser.add_argument("--input-fd", type=int, required=True)
        parser.add_argument("--input-sha256", required=True)
        parser.add_argument("--authority-key-fd", type=int, required=True)
        args = parser.parse_args()
        p.require(args.input_fd >= 3 and args.authority_key_fd >= 3 and args.input_fd != args.authority_key_fd)
        pin = p.digest(args.input_sha256)
        input_identity = io._input(args.input_fd, MAX_INPUT)
        key_identity = io._input(args.authority_key_fd, 32, private=True)
        owner = os.getpid(), originals._start(), originals._boot()
        before_boot, before_wall = originals._clock(), time.time_ns()
        raw = io.read_public(args.input_fd, MAX_INPUT)
        p.require(p.sha256(raw) == pin)
        payload, authority, root, public = _prepare(raw, before_wall)
        issued, expires = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
        # Derive once from the initial clock pair; parsing and all key work
        # consume this original interval. No current time becomes new issuance.
        deadline = before_boot + expires - before_wall
        previous = [before_boot, before_wall]
        retained = p.canonical(payload), p.canonical(authority)

        def check():
            p.require(owner == (os.getpid(), originals._start(), originals._boot())
                and io._input(args.input_fd, MAX_INPUT) == input_identity
                and io._input(args.authority_key_fd, 32, private=True) == key_identity
                and io.read_public(args.input_fd, MAX_INPUT) == raw
                and (p.canonical(payload), p.canonical(authority)) == retained)
            now_boot, now_wall = originals._clock(), time.time_ns()
            p.require(previous[0] <= now_boot < deadline and previous[1] <= now_wall
                and issued <= now_wall < expires)
            previous[:] = now_boot, now_wall
            return now_wall

        check()  # All public original, signature and scope checks precede key access.
        key = io.signing_key(args.authority_key_fd)
        check()
        p.require(key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            == public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
        message = commitment.framed_digest(assignment.SIGNED_SCHEMA, retained[0]).encode("ascii")
        check()
        signature = key.sign(message)
        check()
        result = p.canonical({"schema": assignment.SIGNED_SCHEMA, "payload": payload,
            "signature": codec.encoded(signature)})
        p.require(len(result) <= assignment.MAX_ORIGINAL_BYTES)
        verified = assignment.verify_original(result.decode("ascii"), configuration_payload=authority,
            root_key=root, now_epoch_ns=check())
        p.require(p.canonical(verified) == retained[0])
        check()
        io.write_public(result, deadline_boottime_ns=deadline, check=check)
        check()
        return 0
    except BaseException:
        return io.fail()


if __name__ == "__main__":
    raise SystemExit(main())
