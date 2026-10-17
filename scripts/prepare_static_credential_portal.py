#!/usr/bin/env python3
"""Prepare one public cold selector; never start or authorize a portal.

Use python3 -I -B as root with --purpose creation|rotation, --input-fd and its
independently approved --input-sha256. The canonical input has exactly:
apiVersion=catchplate.staticCredentialPortalSelectorInput/v1, purpose,
authorityRoot={fd,sha256,spkiSha256}, authorityConfiguration={fd,sha256},
controlPlaneConfigurationDigest, and
inheritedDescriptors={selector,authorityRoot,authorityConfiguration}.

Source FDs identify existing root:root0400 public originals (or sealed memfds).
The three distinct 32..1023 inherited descriptors are future supervisor choices,
not descriptors this producer opens or admits. Output is only the existing
purpose's exact canonical selector JSON, without framing or newline, to a root
supervisor stdout pipe. Require complete bytes AND exit0. No files, environment
selection, signing keys, assignments, grants, clocks or authority are generated.

The existing cold owner remains authoritative for the actual inherited roster,
custody runtime, full configuration and distinct runtime-root binding. These
public input checks neither replace that admission nor enable a startup mode.
An external supervisor must bound filesystem/crypto stalls; the existing pipe
writer's local I/O ceiling is not an authority lifetime.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

_SCRIPT = Path(__file__).resolve()
_PACKAGED = "/authority/app/scripts/prepare_static_credential_portal.py"
if str(_SCRIPT.parent) == "/authority/app/scripts":
    if not (sys.argv[0] == __file__ == str(_SCRIPT) == _PACKAGED
            and sys.executable == os.path.realpath(sys.executable) == "/runtime/python/bin/python3"
            and sys.prefix == sys.base_prefix == "/runtime/python" and sys.version_info[:2] == (3, 11)
            and sys.flags.isolated == sys.flags.ignore_environment == sys.flags.no_user_site == 1
            and sys.flags.safe_path and sys.flags.dont_write_bytecode == 1):
        raise SystemExit("static portal selector packaged invocation refused")
    sys.path[:0] = ["/authority/app/scripts/authority", "/authority/app", "/vendor", "/app"]
else:
    sys.path[:0] = [str(_SCRIPT.parent / "authority"), str(_SCRIPT.parent.parent)]

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import native_pilot_authority_io as io
from catchplate import authority_contract as contract
from catchplate import authority_request_commitment as commitment
from catchplate import authority_policy_canary_policy as configuration
from catchplate import authority_credential_currentness as currentness
from catchplate import control_plane_static_credential as creation
from catchplate import control_plane_static_credential_rotation as rotation
from catchplate import oauth_application_owner as originals

INPUT_SCHEMA = "catchplate.staticCredentialPortalSelectorInput/v1"
PURPOSES = ("creation", "rotation")
MAX_INPUT = MAX_OUTPUT = 16384
MAX_ROOT = 4096
MAX_CONFIGURATION = contract.MAX_REQUEST_BYTES


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("static portal selector invocation refused")


def descriptor(purpose, raw):
    creation.profile.require(purpose in PURPOSES)
    value = creation._document(raw, MAX_INPUT)
    creation.profile.require(set(value) == {"apiVersion", "purpose", "authorityRoot",
        "authorityConfiguration", "controlPlaneConfigurationDigest", "inheritedDescriptors"}
        and value["apiVersion"] == INPUT_SCHEMA and value["purpose"] == purpose)
    for name, fields in (("authorityRoot", {"fd", "sha256", "spkiSha256"}),
            ("authorityConfiguration", {"fd", "sha256"})):
        source = value[name]
        creation.profile.require(type(source) is dict and set(source) == fields
            and type(source["fd"]) is int and 3 <= source["fd"] < 2**31)
        for field in fields - {"fd"}:
            creation.profile.digest(source[field])
    creation.profile.require(value["authorityRoot"]["fd"] != value["authorityConfiguration"]["fd"])
    creation.profile.digest(value["controlPlaneConfigurationDigest"])
    target = value["inheritedDescriptors"]
    creation.profile.require(type(target) is dict
        and set(target) == {"selector", "authorityRoot", "authorityConfiguration"})
    for fd in target.values():
        originals._fd(fd)
    creation.profile.require(len(set(target.values())) == 3)
    return value


def prepare(purpose, descriptor_raw, root_raw, authority_raw):
    """Validate exact public inputs and return only the existing cold selector."""
    value = descriptor(purpose, descriptor_raw)
    owner = creation if purpose == "creation" else rotation
    profile, proof, approval = owner.profile, owner.proof, owner.approval
    profile.require(type(root_raw) is bytes and 0 < len(root_raw) <= MAX_ROOT
        and type(authority_raw) is bytes and 0 < len(authority_raw) <= MAX_CONFIGURATION
        and profile.sha256(root_raw) == value["authorityRoot"]["sha256"]
        and profile.sha256(authority_raw) == value["authorityConfiguration"]["sha256"])
    root = serialization.load_pem_public_key(root_raw)
    profile.require(isinstance(root, Ed25519PublicKey)
        and root.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo) == root_raw)
    spki = root.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    profile.require(profile.sha256(spki) == value["authorityRoot"]["spkiSha256"])
    envelope = owner._document(authority_raw, MAX_CONFIGURATION, exact=False)
    profile.require(set(envelope) == {"schema", "payload", "signature"}
        and envelope["schema"] == owner.SIGNED_AUTHORITY_SCHEMA)
    payload = envelope["payload"]
    profile.require(type(payload) is dict and payload.get("schema") == owner.AUTHORITY_SCHEMA
        and payload.get("sourceRevision") == contract.SOURCE_REVISION
        and configuration.full_configuration_digest(payload) == value["controlPlaneConfigurationDigest"])
    root.verify(proof.decoded(envelope["signature"], 64, 64),
        commitment.framed_digest(owner.SIGNED_AUTHORITY_SCHEMA, profile.canonical(payload)).encode("ascii"))
    policy = profile.validate_policy(payload.get(profile.FIELD), payload=payload, root_key=root)
    native = proof.validate_policy(payload.get(proof.FIELD), payload=payload, root_key=root)
    profile.require(policy is not None and native is not None)
    required = profile.OPERATIONS | (approval.OPERATIONS if policy["twoPersonRequired"] else set())
    if purpose == "rotation":
        required |= {currentness.OP_QUIESCE, currentness.OP_ADMIT}
    profile.require(required <= set(payload["roles"]["planner"]["enabledOperations"]))
    target = value["inheritedDescriptors"]
    result = {"schema": owner.CONFIG_SCHEMA, "sourceRevision": contract.SOURCE_REVISION,
        "controlPlaneConfigurationDigest": value["controlPlaneConfigurationDigest"],
        "authorityRootFd": target["authorityRoot"], "authorityRootSha256": value["authorityRoot"]["sha256"],
        "authorityRootSpkiSha256": value["authorityRoot"]["spkiSha256"],
        "authorityConfigurationFd": target["authorityConfiguration"],
        "authorityConfigurationSha256": value["authorityConfiguration"]["sha256"],
        "authorityConfigurationDigest": value["controlPlaneConfigurationDigest"]}
    profile.require(set(result) == owner.CONFIG_FIELDS)
    raw = profile.canonical(result)
    profile.require(len(raw) <= MAX_OUTPUT)
    return raw


def main():
    try:
        parser = Parser(description=__doc__, add_help=False, allow_abbrev=False)
        parser.add_argument("--purpose", choices=PURPOSES, required=True)
        parser.add_argument("--input-fd", type=int, required=True)
        parser.add_argument("--input-sha256", required=True)
        args = parser.parse_args()
        io._process()
        creation.profile.digest(args.input_sha256)
        input_identity = io._input(args.input_fd, MAX_INPUT)
        raw = io.read_public(args.input_fd, MAX_INPUT)
        creation.profile.require(creation.profile.sha256(raw) == args.input_sha256)
        value = descriptor(args.purpose, raw)
        sources = (value["authorityRoot"]["fd"], value["authorityConfiguration"]["fd"])
        creation.profile.require(args.input_fd not in sources)
        held = {args.input_fd: (MAX_INPUT, input_identity, raw)}
        for fd, maximum in zip(sources, (MAX_ROOT, MAX_CONFIGURATION)):
            identity = io._input(fd, maximum)
            creation.profile.require(identity[:2] not in {item[1][:2] for item in held.values()})
            held[fd] = (maximum, identity, io.read_public(fd, maximum))
        pid = os.getpid()
        def check():
            creation.profile.require(os.getpid() == pid)
            for fd, (maximum, identity, original) in held.items():
                creation.profile.require(io._input(fd, maximum) == identity
                    and io.read_public(fd, maximum) == original)
        check()
        output = prepare(args.purpose, raw, held[sources[0]][2], held[sources[1]][2])
        check()
        io.write_public(output, check=check)
        check()
        return 0
    except BaseException:
        return io.fail()


if __name__ == "__main__":
    raise SystemExit(main())
