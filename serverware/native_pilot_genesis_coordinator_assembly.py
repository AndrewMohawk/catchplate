"""Pure cold Runtime/v2 composition from authenticated retained originals.

These grammars do not reconstruct process ownership. Label/configuration
expectations require an independently pinned approval; measured kernel facts
and literal native/ordinary originals come from the separate retained owner.
"""
from __future__ import annotations

import copy

from serverware import custody_generation_grants as g
from serverware import native_pilot_bridge_preparation as binding
from serverware import native_pilot_genesis_coordinator_runtime as runtime
from serverware import native_pilot_genesis_endpoint_profile as endpoints
from serverware import native_pilot_genesis_ordinary_authority as ordinary
from serverware import native_pilot_peer_preparation as peers

p = g.p
API = "serverware.nativePilotGenesisCoordinatorAssembly/v1"
OBSERVATION = "serverware.nativePilotGenesisCoordinatorAssemblyObservation/v1"
ROLES = (*runtime.ROLES, endpoints.ROLES[1], endpoints.ROLES[0], "resultPeer")
PINS = ("parentConfigurationSha256", "parentPrecreationSha256", "ordinaryConfigurationSha256", "endpointConfigurationSha256")


def approval(raw):
    value = p.fields(g.document(raw, 65536), ("apiVersion", *PINS, "peers"))
    p.require(value["apiVersion"] == API)
    for name in PINS:
        p.digest(value[name])
    for role, row in p.fields(value["peers"], ROLES).items():
        runtime.peer(row, root=role == "resultPeer")
    return copy.deepcopy(value)


def observation(raw):
    value = p.fields(g.document(raw, 65536), ("apiVersion", *PINS, "window", "observedAtBoottimeNs", "peers", "activation"))
    p.require(value["apiVersion"] == OBSERVATION)
    for name in PINS:
        p.digest(value[name])
    window = p.fields(value["window"], endpoints.WINDOW)
    p.decoded(window["bootIdBase64url"], size=16)
    p.integer(window["timeNamespaceDevice"], minimum=0, maximum=p.MAX_U64)
    p.integer(window["timeNamespaceInode"], maximum=p.MAX_U64)
    issued, observed, startup, lifetime = (p.ns(item) for item in (window["issuedAtBoottimeNs"],
        value["observedAtBoottimeNs"], window["startupDeadlineBoottimeNs"], window["lifetimeDeadlineBoottimeNs"]))
    p.require(issued <= observed < startup <= lifetime and startup - issued <= 30_000_000_000)
    endpoints.parent._invocation(window["invocationId"])
    pids, pidfds = set(), set()
    for row in p.fields(value["peers"], ROLES).values():
        p.fields(row, peers.PEER_FIELDS)
        pid = p.integer(row["processId"], minimum=2, maximum=(1 << 31) - 1)
        p.integer(row["startTimeTicks"], maximum=p.MAX_U64)
        fd = p.fields(row["pidfd"], ("device", "inode"))
        p.integer(fd["device"], minimum=0, maximum=p.MAX_U64); p.integer(fd["inode"], maximum=p.MAX_U64)
        identity = fd["device"], fd["inode"]
        p.require(pid not in pids and identity not in pidfds)
        pids.add(pid); pidfds.add(identity)
        peers.executable(row["targetExecutable"]); peers.cgroup(row["cgroup"])
    activation = value["activation"]
    p.require(type(activation) is list and len(activation) == 10)
    identities = set()
    for slot, (row, (name, kind)) in enumerate(zip(activation, runtime.ACTIVATION, strict=True), 6):
        p.fields(row, ("name", "fd", "device", "inode", "mode", "uid", "gid"))
        p.require(type(row["fd"]) is int and row["fd"] == slot and row["name"] == name)
        for field in ("device", "inode", "mode", "uid", "gid"):
            p.integer(row[field], minimum=1 if field == "inode" else 0, maximum=p.MAX_U64)
        p.require(row["mode"] & 0o170000 == kind and row["uid"] == row["gid"] == 0)
        identity = row["device"], row["inode"]
        p.require(identity not in identities); identities.add(identity)
    return copy.deepcopy(value)


def _result_peer(expected, observed):
    """Only this cold native-controller peer is root; hot peers stay closed."""
    runtime.peer(expected, root=True)
    p.require(expected["pid"] == observed["processId"]
        and expected["startTimeTicks"] == observed["startTimeTicks"])
    for name in ("device", "inode", "length", "sha256"):
        p.require(expected["executable" + name[0].upper() + name[1:]] == observed["targetExecutable"][name])
    for target, source in (("cgroupPathSha256", "pathSha256"), ("cgroupMountId", "mountId"), ("cgroupInode", "inode")):
        p.require(expected[target] == observed["cgroup"][source])


def build(*, approval_raw, observation_raw, ordinary_records, native_records, cold, coordinator, boot,
          now_boottime_ns, now_unix_ns):
    approved, observed = approval(approval_raw), observation(observation_raw)
    for name in PINS:
        p.require(approved[name] == observed[name])
    p.require(p.ns(observed["observedAtBoottimeNs"]) <= now_boottime_ns < p.ns(observed["window"]["startupDeadlineBoottimeNs"]))
    p.fields(ordinary_records, runtime.ROLES); p.fields(native_records, endpoints.ROLES)
    histories, grants, sessions = [], [], []
    ids = {}
    for index, role in enumerate(runtime.ROLES):
        row = p.fields(ordinary_records[role], ("runtimeOriginal", "historyOriginal", "grantOriginal", "guest"))
        runtime_raw = ordinary._original(row["runtimeOriginal"], g.MAX_BYTES)
        history_raw = ordinary._original(row["historyOriginal"], g.MAX_BYTES)
        grant_raw = ordinary._original(row["grantOriginal"], ordinary.MAX_GRANT)
        header = runtime.ordinary.validate_runtime(role, runtime_raw)["runtime"]
        history = runtime.initial.runtime_manifest(history_raw, runtime=header, guest=row["guest"])
        ordinary.verify_grant(grant_raw, item={"guest": row["guest"], "runtime_raw": runtime_raw, "history": history})
        payload = g.document(grant_raw, ordinary.MAX_GRANT)["payload"]
        grants.append(payload)
        ids[role] = {name: row["guest"][name] for name in ("uid", "gid")}
        histories.append({"serviceRole": role, "runtimeOriginal": row["runtimeOriginal"], "historyOriginal": row["historyOriginal"],
            "rootKeyId": header["authorityHistoryRootKeyId"], "rootKeySpkiSha256": header["authorityHistoryRootKeySpkiSha256"]})
        sessions.append({"serviceRole": role, "activationFdName": runtime.SESSIONS[index],
            "expectedSocketPath": runtime.ordinary.listener(role), "expectedPeer": approved["peers"][role]})
    scope = grants[0]["scope"]
    native_payloads, epoch_limits, epoch_floors = {}, [], []
    for role in endpoints.ROLES:
        row = p.fields(native_records[role], ("grantOriginal", "guest"))
        raw = ordinary._original(row["grantOriginal"], g.MAX_BYTES)
        signed = p.fields(g.document(raw, g.MAX_BYTES), ("payload", "signature"))
        payload = signed["payload"]
        native_payloads[role] = payload
        # Both independently signed ordinary grants name these exact native
        # originals. Native key/trust possession remains the actual service's
        # admission responsibility, not a fabricated Python capability.
        name = "native" if role == endpoints.ROLES[1] else "retrieval"
        p.require(all(grant[name]["grantSha256"] == p.sha(raw) for grant in grants)
            and g.canonical(payload["scope"]) == g.canonical(scope)
            and g.canonical(payload["authorization"]["guest"]) == g.canonical(row["guest"]))
        ids[role] = {name: row["guest"][name] for name in ("uid", "gid")}
        epoch_limits.append(p.integer(payload["authorization"]["expiresAtUnixNanos"]))
        epoch_floors.append(p.integer(payload["authorization"]["issuedAtUnixNanos"]))
    p.require(native_payloads[endpoints.ROLES[0]]["native"]["grantSha256"] == grants[0]["native"]["grantSha256"])
    for role in ROLES[:-1]:
        binding._peer(approved["peers"][role], observed["peers"][role], ids[role])
    _result_peer(approved["peers"]["resultPeer"], observed["peers"]["resultPeer"])
    value = {"apiVersion": runtime.API, "scope": scope,
        "durableGrantOriginal": ordinary_records[runtime.ROLES[0]]["grantOriginal"],
        "currentGrantOriginal": ordinary_records[runtime.ROLES[1]]["grantOriginal"], "histories": histories,
        "serviceSessions": sessions, "nativeEndpoints": [{"kind": kind, "activationFdName": runtime.NATIVE_SESSIONS[index],
            "expectedPeer": approved["peers"][role], "expectedSocketPath": endpoints.LISTENERS[role]}
            for index, (kind, role) in enumerate(zip(runtime.NATIVE, (endpoints.ROLES[1], endpoints.ROLES[0]), strict=True))],
        "resultPeer": approved["peers"]["resultPeer"]}
    raw = g.canonical(value)
    checked = runtime.validate(raw, window=observed["window"], coordinator=coordinator,
        cold=cold, boot=boot, now_boottime_ns=now_boottime_ns)
    p.require(max(epoch_floors) <= now_unix_ns < min(epoch_limits))
    return {"runtimeOriginal": raw, "deadline": min(checked["deadline"], p.ns(observed["window"]["startupDeadlineBoottimeNs"])),
        "runtimeDeadline": checked["deadline"], "epochFloor": max(epoch_floors), "epochLimit": min(epoch_limits)}
