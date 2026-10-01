"""Public checks for the complete late cold Runtime/v2, never a live owner.

Authenticates the two cold histories and their root-signed grants. Actual
session sockets, result peer, native endpoint grants and image admission remain
the retained native caller's responsibility. No Runtime/v1 fallback exists.
"""
from __future__ import annotations

import stat

from serverware import custody_generation_grants as g
from serverware import native_pilot_genesis_ordinary_authority as grants
from serverware import native_pilot_genesis_ordinary_initial_profile as initial
from serverware import native_pilot_genesis_ordinary_runtime as ordinary
from serverware import native_pilot_publication_cold_binding as binding

p = g.p
API = "serverware.nativePublicationGenesisCoordinatorRuntime/v2"
ROLES = initial.ROLES
NATIVE = ("publication-reconciliation", "retrieval")
SESSIONS = ("publication-genesis-durable-session", "publication-genesis-current-session")
NATIVE_SESSIONS = ("publication-genesis-native-session", "publication-genesis-retrieval-session")
ACTIVATION = ((SESSIONS[0], stat.S_IFSOCK), ("publication-genesis-ordinary-directory-0", stat.S_IFDIR),
    (SESSIONS[1], stat.S_IFSOCK), ("publication-genesis-ordinary-directory-1", stat.S_IFDIR),
    (NATIVE_SESSIONS[0], stat.S_IFSOCK), ("publication-reconciliation-peer-directory", stat.S_IFDIR),
    (NATIVE_SESSIONS[1], stat.S_IFSOCK), ("retrieval-peer-directory", stat.S_IFDIR),
    ("publication-genesis-result", stat.S_IFSOCK), ("publication-genesis-result-parent", stat.S_IFSOCK))
PEER_FIELDS = ("processIdentitySha256", "uid", "gid", "pid", "startTimeTicks", "executableDevice",
    "executableInode", "executableLength", "executableSha256", "cgroupPathSha256", "cgroupMountId",
    "cgroupInode", "securityLabelSha256", "configurationGenerationSha256")


def peer(value, *, root=False):
    p.fields(value, PEER_FIELDS)
    parts = []
    for name, width in (("uid", 4), ("gid", 4), ("pid", 4), ("startTimeTicks", 8),
            ("executableDevice", 8), ("executableInode", 8), ("executableLength", 8)):
        minimum = 0 if name in ("uid", "gid") else 2 if name == "pid" else 1
        maximum = (1 << 31) - 1 if name == "pid" else 256 * 1024 * 1024 if name == "executableLength" else (1 << (width * 8)) - 1
        parts.append(p.integer(value[name], minimum=minimum, maximum=maximum).to_bytes(width, "big"))
    p.require((value["uid"] == value["gid"] == 0) if root else (value["uid"] > 0 and value["gid"] > 0))
    parts.append(bytes.fromhex(p.digest(value["executableSha256"]).removeprefix("sha256:")))
    parts.append(p.digest(value["cgroupPathSha256"]).encode("ascii"))
    for name in ("cgroupMountId", "cgroupInode"):
        parts.append(p.integer(value[name], maximum=p.MAX_U64).to_bytes(8, "big"))
    for name in ("securityLabelSha256", "configurationGenerationSha256"):
        parts.append(p.digest(value[name]).encode("ascii"))
    p.require(value["processIdentitySha256"] == p.framed(b"serverware.policyCustodyPeerProcessIdentity/v4", parts))
    return value


def validate(raw, *, window, coordinator, cold, boot, now_boottime_ns):
    value = p.fields(g.document(raw, g.MAX_BYTES), ("apiVersion", "scope", "durableGrantOriginal",
        "currentGrantOriginal", "histories", "serviceSessions", "nativeEndpoints", "resultPeer"))
    p.require(value["apiVersion"] == API)
    scope = p.fields(value["scope"], binding.GENESIS_FIELDS)
    # verify_grant below authenticates the complete scope and proof-scope joins.
    for name in ("histories", "serviceSessions", "nativeEndpoints"):
        p.require(type(value[name]) is list and len(value[name]) == 2)
    p.require(tuple(row["serviceRole"] for row in value["histories"]) == ROLES
        and tuple(row["serviceRole"] for row in value["serviceSessions"]) == ROLES
        and tuple(row["kind"] for row in value["nativeEndpoints"]) == NATIVE)
    peer(value["resultPeer"], root=True)
    limits, signed, coordinator_peers, roots = [], [], [], []
    uids, gids, pids = {cold["uid"]}, {cold["gid"]}, {coordinator["processId"], value["resultPeer"]["pid"]}
    p.require(len(pids) == 2)
    for index, role in enumerate(ROLES):
        row = p.fields(value["histories"][index], ("serviceRole", "runtimeOriginal", "historyOriginal", "rootKeyId", "rootKeySpkiSha256"))
        runtime_raw = grants._original(row["runtimeOriginal"], g.MAX_BYTES)
        runtime = ordinary.validate_runtime(role, runtime_raw)
        history_raw = grants._original(row["historyOriginal"], initial.MAX_HISTORY)
        header = runtime["runtime"]
        p.require(header["authorityHistoryRootKeyId"] == row["rootKeyId"]
            and header["authorityHistoryRootKeySpkiSha256"] == row["rootKeySpkiSha256"])
        expected = peer(header["expectedPeer"])
        p.require(expected["uid"] == cold["uid"] and expected["gid"] == cold["gid"]
            and expected["pid"] == coordinator["processId"] and expected["startTimeTicks"] == coordinator["startTimeTicks"])
        for name in ("device", "inode", "length", "sha256"):
            p.require(expected["executable" + name[0].upper() + name[1:]] == coordinator["executable"][name])
        coordinator_peers.append(expected)
        grant_raw = grants._original(value[("durableGrantOriginal", "currentGrantOriginal")[index]], grants.MAX_GRANT)
        envelope = p.fields(g.document(grant_raw, grants.MAX_GRANT), ("payload", "signatureBase64url"))
        payload = p.fields(envelope["payload"], grants.GRANT_FIELDS)
        guest = grants._guest(payload["guest"], scope=scope)
        p.require(guest["serviceRole"] == role)
        history = initial.runtime_manifest(history_raw, runtime=header, guest=guest)
        roots.append(grants._raw_key(grants.history_authority._key(history["rootAuthority"])))
        grants.verify_grant(grant_raw, item=dict(guest=guest, runtime_raw=runtime_raw, history=history))
        initial.same(payload["scope"], scope)
        held = initial.require_window(history_raw, role=role,
            root_pin={"keyId": row["rootKeyId"], "keySpkiSha256": row["rootKeySpkiSha256"]},
            boot=boot, now_boottime_ns=now_boottime_ns, issued=scope["issuedAtBoottimeNanos"],
            expires=scope["expiresAtBoottimeNanos"])
        for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode", "invocationId"):
            initial.same(guest[name], window[name])
        limits.append(held["deadline"]); signed.append(payload)
        session = p.fields(value["serviceSessions"][index], ("serviceRole", "activationFdName", "expectedSocketPath", "expectedPeer"))
        endpoint = peer(session["expectedPeer"])
        p.require(session["activationFdName"] == SESSIONS[index] and session["expectedSocketPath"] == ordinary.listener(role)
            and endpoint["uid"] == guest["uid"] and endpoint["gid"] == guest["gid"])
        identity = held["identity"]
        for target, source in (("pid", "endpointPid"), ("startTimeTicks", "endpointStartTimeTicks"),
                ("executableDevice", "executableDevice"), ("executableInode", "executableInode"),
                ("executableLength", "executableLength"), ("executableSha256", "executableSha256")):
            p.require(endpoint[target] == identity[source])
        p.require(endpoint["uid"] not in uids and endpoint["gid"] not in gids and endpoint["pid"] not in pids)
        uids.add(endpoint["uid"]); gids.add(endpoint["gid"]); pids.add(endpoint["pid"])
    initial.same(*coordinator_peers)
    p.require(len(set(roots)) == 2)
    for name in ("native", "retrieval", "durableAuthorityEpoch", "durablePublicKeyBase64url",
            "currentAuthorityEpoch", "currentPublicKeyBase64url"):
        initial.same(signed[0][name], signed[1][name])
    for index, kind in enumerate(NATIVE):
        row = p.fields(value["nativeEndpoints"][index], ("kind", "activationFdName", "expectedPeer", "expectedSocketPath"))
        endpoint = peer(row["expectedPeer"])
        p.require(row["activationFdName"] == NATIVE_SESSIONS[index]
            and row["expectedSocketPath"] == "/run/serverware-shadow-" + kind + "/listener.sock"
            and endpoint["uid"] not in uids and endpoint["gid"] not in gids and endpoint["pid"] not in pids)
        uids.add(endpoint["uid"]); gids.add(endpoint["gid"]); pids.add(endpoint["pid"])
    for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode"):
        initial.same(scope[name], window[name])
    p.require(p.ns(window["issuedAtBoottimeNs"]) <= scope["issuedAtBoottimeNanos"] <= now_boottime_ns
        < scope["expiresAtBoottimeNanos"] <= p.ns(window["lifetimeDeadlineBoottimeNs"]))
    return {"runtime": value, "deadline": min(*limits, scope["expiresAtBoottimeNanos"])}
