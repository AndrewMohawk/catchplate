#!/usr/bin/env python3
"""Prepare the existing public currentness cold selector, without signing.

Run python3 -I -B as root with --input-fd and its independently approved
--input-sha256. The canonical input contains apiVersion, authorityRoot
{fd,sha256,spkiSha256}, authorityConfiguration {fd,sha256}, assignment
{fd,sha256}, controlPlaneConfigurationDigest and inheritedDescriptors
{selector,authorityRoot,authorityConfiguration,assignment}. All source originals
must already exist in protected public files or fully sealed memfds. The four
distinct inherited numbers, 32..1023, are future supervisor selections only.

The supplied full A and existing currentness assignment S are authenticated;
stdout receives only currentnessAssignmentConfiguration/v1, without a newline.
Require complete output AND exit0. No file, key, signature, assignment, service,
native proof or new validity interval is created. Actual cold startup still
admits its exact independently signed FD roster and runtime binding. A valid S
is not fresh native action authority. An external supervisor bounds stalls.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import time

_SCRIPT = Path(__file__).resolve()
_PACKAGED = "/authority/app/scripts/prepare_currentness_assignment.py"
if str(_SCRIPT.parent) == "/authority/app/scripts":
    if not (sys.argv[0] == __file__ == str(_SCRIPT) == _PACKAGED
            and sys.executable == os.path.realpath(sys.executable) == "/runtime/python/bin/python3"
            and sys.prefix == sys.base_prefix == "/runtime/python" and sys.version_info[:2] == (3, 11)
            and sys.flags.isolated == sys.flags.ignore_environment == sys.flags.no_user_site == 1
            and sys.flags.safe_path and sys.flags.dont_write_bytecode == 1):
        raise SystemExit("currentness selector packaged invocation refused")
    sys.path[:0] = ["/authority/app/scripts/authority", "/authority/app", "/vendor", "/app"]
else:
    sys.path[:0] = [str(_SCRIPT.parent / "authority"), str(_SCRIPT.parent.parent)]

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import native_pilot_authority_io as io
from catchplate import authority_contract as contract
from catchplate import authority_credential_currentness as profile
from catchplate import authority_credential_currentness_assignment as assignment
from catchplate import authority_oauth_setup as codec
from catchplate import authority_policy_canary_policy as configuration
from catchplate import authority_request_commitment as commitment
from catchplate import control_plane_credential_currentness_assignment as cold
from catchplate import native_shadow_nitro_originals as clock
from catchplate import oauth_application_owner as originals

INPUT_SCHEMA = "catchplate.currentnessAssignmentSelectorInput/v1"
MAX_INPUT = MAX_OUTPUT = 16384
SOURCE_BOUNDS = {"authorityRoot": 4096, "authorityConfiguration": contract.MAX_REQUEST_BYTES,
    "assignment": assignment.MAX_ORIGINAL_BYTES}


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("currentness selector invocation refused")


def descriptor(raw):
    value = codec.document(raw, MAX_INPUT)
    profile.require(set(value) == {"apiVersion", *SOURCE_BOUNDS,
        "controlPlaneConfigurationDigest", "inheritedDescriptors"}
        and value["apiVersion"] == INPUT_SCHEMA)
    for name in SOURCE_BOUNDS:
        source = value[name]
        fields = {"fd", "sha256", "spkiSha256"} if name == "authorityRoot" else {"fd", "sha256"}
        profile.require(type(source) is dict and set(source) == fields
            and type(source["fd"]) is int and 3 <= source["fd"] < 2**31)
        for field in fields - {"fd"}:
            profile.digest(source[field])
    profile.require(len({value[name]["fd"] for name in SOURCE_BOUNDS}) == 3)
    profile.digest(value["controlPlaneConfigurationDigest"])
    targets = value["inheritedDescriptors"]
    profile.require(type(targets) is dict and set(targets) == {"selector", *SOURCE_BOUNDS})
    for fd in targets.values():
        originals._fd(fd)
    profile.require(len(set(targets.values())) == 4)
    return value


def prepare(raw, root_raw, configuration_raw, assignment_raw, *, now_epoch_ns):
    """Return selector bytes and the existing S interval, never an admission."""
    profile.require(type(now_epoch_ns) is int)
    value = descriptor(raw)
    for name, original in zip(SOURCE_BOUNDS, (root_raw, configuration_raw, assignment_raw)):
        profile.require(type(original) is bytes and 0 < len(original) <= SOURCE_BOUNDS[name]
            and profile.sha256(original) == value[name]["sha256"])
    root = serialization.load_pem_public_key(root_raw)
    profile.require(isinstance(root, Ed25519PublicKey)
        and root.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo) == root_raw
        and profile.sha256(root.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
            == value["authorityRoot"]["spkiSha256"])
    envelope = codec.document(configuration_raw, contract.MAX_REQUEST_BYTES, exact=False)
    profile.require(set(envelope) == {"schema", "payload", "signature"} and envelope["schema"] == cold.SIGNED)
    payload = envelope["payload"]
    profile.require(type(payload) is dict and payload.get("schema") == configuration.CONFIGURATION_SCHEMA
        and payload.get("sourceRevision") == contract.SOURCE_REVISION
        and configuration.full_configuration_digest(payload) == value["controlPlaneConfigurationDigest"])
    root.verify(profile.encoded(envelope["signature"], 64),
        commitment.framed_digest(cold.SIGNED, profile.canonical(payload)).encode("ascii"))
    selected = assignment.verify_original(assignment_raw.decode("ascii"),
        configuration_payload=payload, root_key=root, now_epoch_ns=now_epoch_ns)
    targets = value["inheritedDescriptors"]
    result = {"schema": cold.CONFIG_SCHEMA, "sourceRevision": contract.SOURCE_REVISION,
        "controlPlaneConfigurationDigest": value["controlPlaneConfigurationDigest"],
        "authorityRootFd": targets["authorityRoot"], "authorityRootSha256": value["authorityRoot"]["sha256"],
        "authorityRootSpkiSha256": value["authorityRoot"]["spkiSha256"],
        "authorityConfigurationFd": targets["authorityConfiguration"],
        "authorityConfigurationSha256": value["authorityConfiguration"]["sha256"],
        "authorityConfigurationDigest": value["controlPlaneConfigurationDigest"],
        "assignmentFd": targets["assignment"], "assignmentSha256": value["assignment"]["sha256"]}
    profile.require(set(result) == cold.CONFIG_FIELDS)
    output = profile.canonical(result)
    profile.require(len(output) <= MAX_OUTPUT)
    return output, selected["issuedAtEpochNs"], selected["expiresAtEpochNs"]


def main():
    try:
        parser = Parser(description=__doc__, add_help=False, allow_abbrev=False)
        parser.add_argument("--input-fd", type=int, required=True)
        parser.add_argument("--input-sha256", required=True)
        args = parser.parse_args()
        io._process()
        profile.require(args.input_fd >= 3)
        profile.digest(args.input_sha256)
        identity = io._input(args.input_fd, MAX_INPUT)
        owner = os.getpid(), clock._start(), clock._boot()
        before_boot, before_wall = clock._clock(), time.time_ns()
        raw = io.read_public(args.input_fd, MAX_INPUT)
        profile.require(profile.sha256(raw) == args.input_sha256)
        value = descriptor(raw)
        profile.require(args.input_fd not in {value[name]["fd"] for name in SOURCE_BOUNDS})
        held = {args.input_fd: (MAX_INPUT, identity, raw)}
        public = []
        for name, maximum in SOURCE_BOUNDS.items():
            fd = value[name]["fd"]
            identity = io._input(fd, maximum)
            profile.require(identity[:2] not in {item[1][:2] for item in held.values()})
            original = io.read_public(fd, maximum)
            held[fd] = (maximum, identity, original)
            public.append(original)
        output, issued, expires = prepare(raw, *public, now_epoch_ns=before_wall)
        deadline = before_boot + expires - before_wall
        previous = [before_boot, before_wall]

        def check():
            profile.require(owner == (os.getpid(), clock._start(), clock._boot()))
            for fd, (maximum, identity, original) in held.items():
                profile.require(io._input(fd, maximum) == identity and io.read_public(fd, maximum) == original)
            now_boot, now_wall = clock._clock(), time.time_ns()
            profile.require(previous[0] <= now_boot < deadline and previous[1] <= now_wall
                and issued <= now_wall < expires)
            previous[:] = now_boot, now_wall

        check()
        io.write_public(output, deadline_boottime_ns=deadline, check=check)
        check()
        return 0
    except BaseException:
        return io.fail()


if __name__ == "__main__":
    raise SystemExit(main())
