"""Closed public peer-preparation observations, never final peer admission.

The pure parser creates no process/resource owner. Final UID/GID, socket label
and configuration-generation expectations are deliberately not this wire.
"""
from __future__ import annotations

import copy

from serverware import custody_generation_grants as g

p = g.p
API = "serverware.nativePilotPeerPreparation/v1"
ADOPTED_API = "serverware.nativePilotPeerPreparation/v2"
PROFILE = "retain-observed-cgroup"
MAX_BYTES = 65536
NATIVE_ROLES = ("retrieval", "persistence", "trustedTime", "generationInstall",
    "commitRequest", "ingressAdmission", "terminalAppend", "dispatchBarrier",
    "activeEffectBarrier", "activeEffectCommit")
ROLES = {"ordinary-services": g.ROLES, "native-endpoints": NATIVE_ROLES, "gate": ("gate",)}
ADOPTED_NATIVE_ROLES = NATIVE_ROLES + ("publicationReconciliation",)
FIELDS = ("apiVersion", "profile", "ownerKind", "phase", "configurationSha256",
    "sourceOriginalSha256", "bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode",
    "issuedAtBoottimeNs", "observedAtBoottimeNs", "startupDeadlineBoottimeNs",
    "lifetimeDeadlineBoottimeNs", "invocationId", "peers")
PEER_FIELDS = ("processId", "startTimeTicks", "pidfd", "targetExecutable", "cgroup")
EXECUTABLE_FIELDS = ("device", "inode", "length", "sha256")
CGROUP_FIELDS = ("pathSha256", "mountId", "inode")
U64 = (1 << 64) - 1


def cgroup_path(raw):
    """Same path-only hash input as native common::process_cgroup_identity.

    No filesystem effect. Hybrid/non-v2 lines supply no alternative membership.
    Only one unambiguous absolute v2 path is accepted; no path normalization.
    """
    p.require(type(raw) is bytes and 0 < len(raw) <= 16384)
    # Do not use Python splitlines(), which treats additional Unicode code
    # points as separators unlike Rust str::lines() and Linux proc text.
    lines = [line.removesuffix("\r") for line in raw.decode("utf-8").split("\n")]
    paths = [line[3:] for line in lines if line.startswith("0::")]
    p.require(len(paths) == 1)
    path = paths[0]
    p.require(path.startswith("/") and "\0" not in path and len(path.encode("utf-8")) <= 4096
        and (path == "/" or all(part not in ("", ".", "..") for part in path[1:].split("/"))))
    return path


def executable(value):
    p.fields(value, EXECUTABLE_FIELDS)
    p.integer(value["device"], minimum=0, maximum=U64)
    p.integer(value["inode"], maximum=U64)
    p.integer(value["length"], maximum=256 * 1024 * 1024)
    p.digest(value["sha256"])
    return value


def cgroup(value):
    p.fields(value, CGROUP_FIELDS)
    p.digest(value["pathSha256"])
    for field in ("mountId", "inode"):
        p.integer(value[field], maximum=U64)
    return value


def require_same_cgroup(expected, actual):
    """Pure comparison only: callers must obtain actual from retained FDs."""
    p.require(cgroup(expected) == cgroup(actual))


def shape(raw):
    value = p.fields(g.document(raw, MAX_BYTES), FIELDS)
    kind = value["ownerKind"]
    adopted = value["apiVersion"] == ADOPTED_API
    p.require((adopted and kind == "native-endpoints" or value["apiVersion"] == API) and value["profile"] == PROFILE and kind in ROLES
        and value["phase"] == ("executing-gate" if kind == "gate" else "parked-pre-exec"))
    for field in ("configurationSha256", "sourceOriginalSha256"):
        p.digest(value[field])
    p.decoded(value["bootIdBase64url"], size=16)
    for field in ("timeNamespaceDevice", "timeNamespaceInode"):
        p.integer(value[field], maximum=U64)
    issued, observed, startup, lifetime = (p.ns(value[field]) for field in
        ("issuedAtBoottimeNs", "observedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"))
    p.require(issued <= observed < startup <= lifetime and type(value["invocationId"]) is str
        and 0 < len(value["invocationId"]) <= 128 and value["invocationId"].isascii()
        and "\0" not in value["invocationId"])
    roles = ADOPTED_NATIVE_ROLES if adopted else ROLES[kind]
    peers = p.fields(value["peers"], roles)
    identities, pidfds = set(), set()
    for role in roles:
        item = p.fields(peers[role], PEER_FIELDS)
        pid = p.integer(item["processId"], minimum=2, maximum=(1 << 31) - 1)
        p.integer(item["startTimeTicks"], maximum=U64)
        fd = p.fields(item["pidfd"], ("device", "inode"))
        p.integer(fd["device"], minimum=0, maximum=U64)
        p.integer(fd["inode"], maximum=U64)
        identity = (fd["device"], fd["inode"])
        p.require(pid not in identities and identity not in pidfds)
        identities.add(pid); pidfds.add(identity)
        executable(item["targetExecutable"]); cgroup(item["cgroup"])
    return copy.deepcopy(value)
