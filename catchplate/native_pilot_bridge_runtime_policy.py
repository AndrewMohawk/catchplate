"""Independent, closed bridge expectations, not a prepared runtime template.

Final labels, configuration generations, public credential names and external
endpoint pins require explicit operator approval. Process measurements and
native authority pins are joined separately to actual authenticated originals.
This parser neither provisions those credentials nor proves live endpoints.
"""
from __future__ import annotations

import copy

from catchplate import custody_generation_grants as generation
from catchplate import native_pilot_bridge_preparation as preparation
from catchplate import native_pilot_peer_preparation as peers
from catchplate import native_shadow_driver_outgoing as outgoing

p = generation.p
API = "catchplate.nativePilotSupervisorBridgeRuntimePolicy/v1"
TERMINAL_API = "catchplate.nativePilotSupervisorBridgeRuntimePolicy/v2"
ADOPTED_API = "catchplate.nativePilotSupervisorBridgeRuntimePolicy/v3"
MAX_POLICY = 65536
FIELDS = ("apiVersion", "startupTimeoutMillis", "peerExpectations", "historyCredentials",
    "authorityBindings", "externalSignerEndpoints")
EXPECTATION_FIELDS = ("securityLabelSha256", "configurationGenerationSha256")
AUTHORITY_FIELDS = ("authorityBindingCredential", "authorityKeyId", "authorityKeySpkiSha256")
EXTERNAL_SIGNERS = ("unavailable-ingress", "spool-compaction", "publication-reconciliation",
    "activation-publication")
AUTHORITY_ROLES = tuple(sorted(outgoing._SIGNERS)) + tuple(outgoing._PROOFS)


def _socket(value):
    p.require(type(value) is str and value.isascii() and value.startswith("/")
        and 1 < len(value) < 108 and "\0" not in value
        and all(part not in ("", ".", "..") for part in value.split("/")[1:]))
    return value


def _peer(value):
    """Check exact identity widths/hash without inventing a bridge UID."""
    p.fields(value, outgoing._PEER_FIELDS)
    for field in ("uid", "gid"):
        p.integer(value[field], minimum=1, maximum=2**32 - 2)
    p.integer(value["pid"], minimum=2, maximum=2**31 - 1)
    for field in ("startTimeTicks", "executableDevice", "executableInode", "executableLength",
            "cgroupMountId", "cgroupInode"):
        # Preserve the existing outgoing/runtime JSON reader's i64 ceiling;
        # the native digest uses u64 frames but this policy cannot widen it.
        p.integer(value[field])
    for field in ("processIdentitySha256", "executableSha256", "cgroupPathSha256",
            "securityLabelSha256", "configurationGenerationSha256"):
        p.digest(value[field])
    p.require(value["processIdentitySha256"] == preparation.peer_identity(
        {name: value[name] for name in outgoing._PEER_FIELDS if name != "processIdentitySha256"}))
    return value


def validate_policy(fragment):
    p.fields(fragment, FIELDS)
    p.require(fragment["apiVersion"] in (API, TERMINAL_API, ADOPTED_API) and len(generation.canonical(fragment)) <= MAX_POLICY)
    adopted = fragment["apiVersion"] == ADOPTED_API
    p.integer(fragment["startupTimeoutMillis"], maximum=30000)
    expectations = p.fields(fragment["peerExpectations"], peers.ROLES)
    for kind, roles in peers.ROLES.items():
        if adopted and kind == "native-endpoints":
            roles = peers.ADOPTED_NATIVE_ROLES
        for row in p.fields(expectations[kind], roles).values():
            p.fields(row, EXPECTATION_FIELDS)
            for value in row.values():
                p.digest(value)
    names = set()
    for value in p.fields(fragment["historyCredentials"], generation.ROLES).values():
        name = outgoing._name(value)
        p.require(name not in names)
        names.add(name)
    for row in p.fields(fragment["authorityBindings"], AUTHORITY_ROLES).values():
        p.fields(row, AUTHORITY_FIELDS)
        name = outgoing._name(row["authorityBindingCredential"])
        p.require(name not in names)
        names.add(name)
        p.digest(row["authorityKeyId"])
        p.digest(row["authorityKeySpkiSha256"])
    endpoints = p.fields(fragment["externalSignerEndpoints"],
        tuple(role for role in EXTERNAL_SIGNERS if role != "publication-reconciliation") if adopted else EXTERNAL_SIGNERS)
    paths = set()
    for row in endpoints.values():
        p.fields(row, ("expectedSocketPath", "expectedPeer"))
        path = _socket(row["expectedSocketPath"])
        p.require(path not in paths)
        paths.add(path)
        _peer(row["expectedPeer"])
    return copy.deepcopy(fragment)


def build_peer(observed, ids, expectations):
    """Combine retained public measurements with independently approved fields."""
    p.fields(observed, peers.PEER_FIELDS)
    p.fields(ids, ("uid", "gid"))
    p.fields(expectations, EXPECTATION_FIELDS)
    peers.executable(observed["targetExecutable"])
    peers.cgroup(observed["cgroup"])
    pidfd = p.fields(observed["pidfd"], ("device", "inode"))
    p.integer(pidfd["device"], minimum=0, maximum=peers.U64)
    p.integer(pidfd["inode"], maximum=peers.U64)
    value = dict(ids, pid=observed["processId"], startTimeTicks=observed["startTimeTicks"],
        executableDevice=observed["targetExecutable"]["device"],
        executableInode=observed["targetExecutable"]["inode"],
        executableLength=observed["targetExecutable"]["length"],
        executableSha256=observed["targetExecutable"]["sha256"],
        cgroupPathSha256=observed["cgroup"]["pathSha256"],
        cgroupMountId=observed["cgroup"]["mountId"], cgroupInode=observed["cgroup"]["inode"],
        **expectations)
    value["processIdentitySha256"] = preparation.peer_identity(value)
    _peer(value)
    preparation._peer(value, observed, ids)
    return value
