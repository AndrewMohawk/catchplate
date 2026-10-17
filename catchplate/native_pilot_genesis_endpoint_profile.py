"""Closed cold-endpoint source grammars, not live ownership or approval."""
from __future__ import annotations

import copy
import os
import stat

from catchplate import custody_generation_grants as g
from catchplate import native_pilot_genesis_parent_authority as parent
from catchplate import native_pilot_peer_preparation as peers

p = g.p
ROLES = ("publicationGenesisRetrieval", "publicationGenesis")
CONFIG_API = "catchplate.nativePublicationGenesisEndpoints/v1"
CONTROL_API = "catchplate.nativePublicationGenesisEndpointControl/v1"
OBSERVATION_API = "catchplate.nativePublicationGenesisEndpointObservation/v1"
PREPARATION_API = "catchplate.nativePilotGenesisEndpointPreparation/v1"
RESOURCES_API = "catchplate.nativePilotGenesisEndpointResources/v1"
STORE_API = "catchplate.nativePilotGenesisRetrievalStoreObservation/v1"
RELEASE_API = "catchplate.nativePublicationGenesisEndpointRelease/v1"
RELEASE_DOMAIN = "catchplate.nativePublicationGenesisEndpointRelease.signature/v1"
MAX_WIRE = 32768
WINDOW = ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode", "issuedAtBoottimeNs",
    "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId")
ACTIVATION = {ROLES[0]: ("retrieval-listener", "retrieval-objects", "ledger-spool-store", "ledger-spool-lock"),
    ROLES[1]: ("publication-reconciliation-listener",)}
DIRECTORIES = {ROLES[0]: ("retrieval-objects", "ledger-spool-store"), ROLES[1]: ()}
LISTENERS = {ROLES[0]: "/run/catchplate-shadow-retrieval/listener.sock",
    ROLES[1]: "/run/catchplate-shadow-publication-reconciliation/listener.sock"}
IDENTITY_FIELDS = ("mountId", "deviceMajor", "deviceMinor", "inode", "uid", "gid", "mode")


def configuration(raw):
    value = p.fields(g.document(raw, MAX_WIRE), ("apiVersion", "parentConfigurationSha256",
        "parentPrecreationSha256", "releaseAuthority", "services"))
    p.require(value["apiVersion"] == CONFIG_API)
    for name in ("parentConfigurationSha256", "parentPrecreationSha256"):
        p.digest(value[name])
    parent._authority(value["releaseAuthority"])
    for role, row in p.fields(value["services"], ROLES).items():
        p.fields(row, ("executableSha256", "deliveryConfiguration", "image"))
        p.require(p.digest(row["executableSha256"]) != p.sha(b""))
        g.c9._pin(row["deliveryConfiguration"])
        g.c9._pin(row["image"])
    return copy.deepcopy(value)


def observation(raw):
    value = p.fields(g.document(raw, MAX_WIRE), ("apiVersion", "configurationSha256", "parentConfigurationSha256",
        "parentPrecreationSha256", "invocationId", "services"))
    p.require(value["apiVersion"] == OBSERVATION_API)
    for name in ("configurationSha256", "parentConfigurationSha256", "parentPrecreationSha256"):
        p.digest(value[name])
    parent._invocation(value["invocationId"])
    pids, pidfds, executables = set(), set(), set()
    for row in p.fields(value["services"], ROLES).values():
        p.fields(row, ("processId", "startTimeTicks", "pidfdDevice", "pidfdInode", "executable"))
        p.integer(row["processId"], minimum=2, maximum=(1 << 31) - 1)
        for name in ("startTimeTicks", "pidfdDevice", "pidfdInode"):
            p.integer(row[name], minimum=0 if name == "pidfdDevice" else 1, maximum=p.MAX_U64)
        peers.executable(row["executable"])
        fd = row["pidfdDevice"], row["pidfdInode"]
        executable = row["executable"]["device"], row["executable"]["inode"]
        p.require(row["processId"] not in pids and fd not in pidfds and executable not in executables)
        pids.add(row["processId"]); pidfds.add(fd); executables.add(executable)
    return copy.deepcopy(value)


def preparation(raw):
    value = p.fields(g.document(raw, 65536), ("apiVersion", "configurationSha256", "parentConfigurationSha256",
        "parentPrecreationSha256", "observationOriginal", *WINDOW, "observedAtBoottimeNs", "services"))
    p.require(value["apiVersion"] == PREPARATION_API and type(value["observationOriginal"]) is str)
    observed = observation(value["observationOriginal"].encode("ascii"))
    for name in ("configurationSha256", "parentConfigurationSha256", "parentPrecreationSha256", "invocationId"):
        p.require(value[name] == observed[name])
    p.require(p.decoded(value["bootIdBase64url"], size=16) != bytes(16))
    for name in ("timeNamespaceDevice", "timeNamespaceInode"):
        p.integer(value[name], minimum=0 if name.endswith("Device") else 1, maximum=p.MAX_U64)
    issued, sampled, startup, lifetime = (p.ns(value[name]) for name in
        ("issuedAtBoottimeNs", "observedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"))
    p.require(issued <= sampled < startup <= lifetime and startup - issued <= 30_000_000_000)
    for role, row in p.fields(value["services"], ROLES).items():
        p.fields(row, peers.PEER_FIELDS)
        actual = observed["services"][role]
        p.require(row["processId"] == actual["processId"] and row["startTimeTicks"] == actual["startTimeTicks"]
            and row["pidfd"] == {"device": actual["pidfdDevice"], "inode": actual["pidfdInode"]}
            and row["targetExecutable"] == actual["executable"])
        peers.cgroup(row["cgroup"])
    return copy.deepcopy(value)


def resources(raw):
    value = p.fields(g.document(raw, 65536), ("apiVersion", "preparationSha256", "issuedAtBoottimeNs", "services"))
    p.require(value["apiVersion"] == RESOURCES_API)
    p.digest(value["preparationSha256"]); p.ns(value["issuedAtBoottimeNs"])
    seen = set()
    for role, row in p.fields(value["services"], ROLES).items():
        p.fields(row, ("activation", "listenerSocketPath", "directories"))
        p.require(row["listenerSocketPath"] == LISTENERS[role]
            and type(row["activation"]) is list and len(row["activation"]) == len(ACTIVATION[role]))
        directories = p.fields(row["directories"], DIRECTORIES[role])
        for slot, (entry, name) in enumerate(zip(row["activation"], ACTIVATION[role], strict=True), 6):
            p.fields(entry, ("name", "fd", "device", "inode", "mode", "uid", "gid"))
            p.require(entry["name"] == name and type(entry["fd"]) is int and entry["fd"] == slot)
            for field in ("device", "inode", "mode", "uid", "gid"):
                p.integer(entry[field], minimum=1 if field == "inode" else 0,
                    maximum=(1 << 32) - 1 if field in ("mode", "uid", "gid") else p.MAX_U64)
            identity = entry["device"], entry["inode"]
            p.require(identity not in seen); seen.add(identity)
            if slot == 6:
                p.require(stat.S_ISSOCK(entry["mode"]))
            elif name == "ledger-spool-lock":
                p.require(entry["mode"] == stat.S_IFREG | 0o600 and entry["uid"] > 0 and entry["gid"] > 0)
            else:
                p.require(entry["mode"] == stat.S_IFDIR | 0o700 and entry["uid"] > 0 and entry["gid"] > 0)
                directory = p.fields(directories[name], ("identity", "entryCount"))
                expected = 1 if name == "ledger-spool-store" else 0
                p.require(type(directory["entryCount"]) is int and directory["entryCount"] == expected)
                actual = p.fields(directory["identity"], IDENTITY_FIELDS)
                for field in IDENTITY_FIELDS:
                    p.integer(actual[field], minimum=1 if field in ("mountId", "inode") else 0,
                        maximum=(1 << 32) - 1 if field in ("uid", "gid", "mode", "deviceMajor", "deviceMinor") else p.MAX_U64)
                p.require([actual[k] for k in IDENTITY_FIELDS[1:]] == [os.major(entry["device"]), os.minor(entry["device"]),
                    entry["inode"], entry["uid"], entry["gid"], entry["mode"]])
    return copy.deepcopy(value)


def context(*, configuration_raw, preparation_raw, resources_raw, parent_configuration_raw,
        parent_delivery_configuration_raw, parent_precreation_raw, parent_observation_raw, boot, now_boottime_ns):
    config, prepared, actual = configuration(configuration_raw), preparation(preparation_raw), resources(resources_raw)
    inherited = parent.validate_precreation(parent_precreation_raw, configuration_raw=parent_configuration_raw,
        delivery_configuration_raw=parent_delivery_configuration_raw, boot=boot, now_boottime_ns=now_boottime_ns)
    coordinator = parent.validate_observation(parent_observation_raw, configuration_raw=parent_configuration_raw,
        precreation_raw=parent_precreation_raw, context=inherited)
    p.require(config["parentConfigurationSha256"] == p.sha(parent_configuration_raw)
        and config["parentPrecreationSha256"] == p.sha(parent_precreation_raw)
        and prepared["configurationSha256"] == p.sha(configuration_raw)
        and actual["preparationSha256"] == p.sha(preparation_raw))
    for name in ("parentConfigurationSha256", "parentPrecreationSha256"):
        p.require(prepared[name] == config[name])
    for name in WINDOW:
        p.require(g.canonical([prepared[name]]) == g.canonical([inherited["window"][name]]))
    p.require(actual["issuedAtBoottimeNs"] == prepared["issuedAtBoottimeNs"]
        and p.ns(prepared["observedAtBoottimeNs"]) <= now_boottime_ns)
    forbidden = {inherited["configuration"][name]["publicKeyBase64url"] for name in ("precreationAuthority", "releaseAuthority")}
    forbidden.add(inherited["cold"]["authority"]["publicKeyBase64url"])
    p.require(config["releaseAuthority"]["publicKeyBase64url"] not in forbidden)
    for role in ROLES:
        row = prepared["services"][role]
        p.require(row["processId"] != coordinator["processId"]
            and row["pidfd"]["inode"] != coordinator["pidfdInode"]
            and row["targetExecutable"]["sha256"] == config["services"][role]["executableSha256"])
    return {"configuration": config, "window": inherited["window"], "preparation": prepared,
        "resources": actual, "deadline": inherited["deadline"]}


def store_observation(raw, *, resources_raw, delivery_raw, proof_scope_raw):
    value = p.fields(g.document(raw, 65536), ("apiVersion", "resourcesSha256", "deliverySha256",
        "proofScopeSha256", "genesisOriginal", "genesisFile", "store"))
    actual = resources(resources_raw)
    envelope = p.fields(g.document(delivery_raw, 65536), ("apiVersion", "payload", "signatureBase64url"))
    payload = p.fields(envelope["payload"], g.c9.FIELDS)
    p.require(value["apiVersion"] == STORE_API and value["resourcesSha256"] == p.sha(resources_raw)
        and value["deliverySha256"] == p.sha(delivery_raw) and value["proofScopeSha256"] == p.sha(proof_scope_raw)
        and payload["activation"] == actual["services"][ROLES[0]]["activation"])
    guest = {name: payload[name] for name in p.GUEST_FIELDS if name not in ("deliverySha256", "runtimeConfigurationSha256")}
    guest.update(deliverySha256=p.sha(delivery_raw), runtimeConfigurationSha256=payload["runtimeConfig"]["sha256"])
    p.require(type(value["genesisOriginal"]) is str)
    original = value["genesisOriginal"].encode("ascii")
    genesis = p.fields(g.document(original, 65536), ("apiVersion", "guest", "proofScopeSha256"))
    p.require(genesis["apiVersion"] == "catchplate.nativeLedgerSpoolStoreGenesis/v1"
        and g.canonical(genesis["guest"]) == g.canonical(guest) and genesis["proofScopeSha256"] == p.sha(proof_scope_raw))
    info = p.fields(value["genesisFile"], ("device", "inode", "mode", "uid", "gid", "length", "sha256"))
    for name in ("device", "inode", "mode", "uid", "gid", "length"):
        p.integer(info[name], minimum=0 if name == "device" else 1, maximum=p.MAX_U64)
    directory = actual["services"][ROLES[0]]["directories"]["ledger-spool-store"]["identity"]
    p.require(info["mode"] == stat.S_IFREG | 0o400 and info["uid"] == guest["uid"] and info["gid"] == guest["gid"]
        and info["length"] == len(original) and info["sha256"] == p.sha(original)
        and (os.major(info["device"]), os.minor(info["device"])) == (directory["deviceMajor"], directory["deviceMinor"]))
    admission = p.fields(value["store"], ("genesisSha256", "sequence", "headSha256"))
    p.require(type(admission["sequence"]) is int and admission["sequence"] == 0
        and admission["genesisSha256"] == admission["headSha256"] == p.sha(original))
    return copy.deepcopy(admission)
