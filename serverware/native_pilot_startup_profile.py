"""Closed public startup joins for the existing three commissioning processes.

These codecs describe observations, never create process/socket ownership or
independent authority. The actual parent owns the protected originals and real
children. Only independently supplied late admission authorizes their fixed
role inputs; no policy mutation, key read, currentness or clock renewal occurs.
"""
from __future__ import annotations

import copy

from serverware import native_pilot_approval_policy as policy
from serverware import native_pilot_current_head_decision_service_profile as decisions

p = policy.p
API = "serverware.nativePilotStartupConfiguration/v1"
PURPOSE = "observed-three-process-commissioning-startup"
OBSERVATION_API = "serverware.nativePilotStartupObservation/v1"
ADMISSION_API = "serverware.nativePilotStartupAdmission/v1"
DIRECTORY = "/etc/serverware/native-pilot-startup"
OBSERVATION_NAME = "observation.json"
ADMISSION_NAME = "admission.json"
ROLES = ("lifecycle", "provider", "decisions")
SOURCE_NAMES = ("listener-configuration", "provider-policy", "recipe", "conductor-inventory",
    "authority-inventory", "decision-configuration")
SOURCE_FILENAMES = {name: name + ".json" for name in SOURCE_NAMES}
SOURCE_LIMITS = {"listener-configuration": policy.lifecycle.rendezvous_profile.MAX_CONFIGURATION,
    "provider-policy": policy.MAX_POLICY, "recipe": policy.lifecycle.measured.MAX_RECIPE,
    "conductor-inventory": policy.lifecycle.artifacts.MAX_MANIFEST_BYTES,
    "authority-inventory": policy.lifecycle.artifacts.MAX_MANIFEST_BYTES,
    "decision-configuration": decisions.MAX_CONFIGURATION}
ROLE_SOURCES = {"lifecycle": ("listener-configuration",),
    "provider": ("provider-policy", "recipe", "conductor-inventory", "authority-inventory"),
    "decisions": ("decision-configuration",)}
ROLE_LISTENERS = {"lifecycle": (), "provider": ("lifecycle",), "decisions": ("heads",)}
ROLE_SOCKETS = {"lifecycle": ("lifecycle",), "provider": ("lifecycle", "heads"), "decisions": ("heads",)}
PEER_ROLES = {"lifecycle": {"lifecycle": "provider"},
    "provider": {"lifecycle": "lifecycle", "heads": "decisions"}, "decisions": {"heads": "provider"}}
KEY_NAMES = tuple((family, name) for family, names in (("cold", policy.cold.jobs.KEY_PURPOSES),
    ("adopted", policy.adopted.profile.KEY_PURPOSES)) for name in names)
MAX_CONFIGURATION = 4096
MAX_MESSAGE = 65536
MAX_OBSERVATION = 65536
MAX_ADMISSION = 4096
BOOT_FIELDS = ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode")
CONFIGURATION_FIELDS = ("apiVersion", "purpose", "supervisorInventorySha256", "invocationId", "directory",
    *BOOT_FIELDS, "issuedAtBoottimeNs", "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos")
PROCESS_FIELDS = ("pid", "uid", "gid", "startTimeTicks", "parentPid")
OBSERVATION_FIELDS = ("apiVersion", "configurationSha256", "supervisorInventorySha256", "invocationId",
    "parentPid", "processes", "hellos", "ready")
ADMISSION_FIELDS = ("apiVersion", "configurationSha256", "observationSha256", "sources",
    "deadlineBoottimeNs", "expiresAtUnixNanos")
MESSAGE_APIS = {kind: "serverware.nativePilotStartup" + title + "/v1" for kind, title in
    (("hello", "Hello"), ("connect", "Connect"), ("ready", "Ready"), ("admit", "Admit"))}
MESSAGE_FIELDS = {"hello": ("process", "control", "listeners"), "connect": ("peers",),
    "ready": ("peersSha256", "sockets"),
    "admit": ("readySha256", "observationSha256", "admissionSha256", "sources", "keys",
        "deadlineBoottimeNs", "expiresAtUnixNanos")}


def _document(raw, maximum, fields):
    p.require(type(raw) is bytes)
    value = p.fields(p.document(raw, maximum), fields)
    p.require(p.canonical(value) == raw)
    return value


def _configuration(raw):
    value = _document(raw, MAX_CONFIGURATION, CONFIGURATION_FIELDS)
    p.require(value["apiVersion"] == API and value["purpose"] == PURPOSE)
    p.digest(value["supervisorInventorySha256"]); p.digest(value["invocationId"])
    p.require(p.decoded(value["bootIdBase64url"], size=16) != bytes(16))
    p.integer(value["timeNamespaceDevice"], minimum=0, maximum=p.MAX_I64)
    p.integer(value["timeNamespaceInode"], maximum=p.MAX_I64)
    socket_identity(value["directory"])
    p.require(p.ns(value["issuedAtBoottimeNs"]) < p.ns(value["deadlineBoottimeNs"]))
    p.require(p.integer(value["issuedAtUnixNanos"], maximum=p.MAX_I64)
        < p.integer(value["expiresAtUnixNanos"], maximum=p.MAX_I64))
    return value


def addresses(value):
    """Only three fixed abstract names; no caller-selected filesystem sockets."""
    p.require(type(value) is dict)
    invocation = p.digest(value["invocationId"])[7:]
    return {name: ("\0serverware.startup." + invocation + "." + name).encode("ascii")
        for name in ("control", "lifecycle", "heads")}


def configuration(raw, *, inventory_sha256, boot, now_boottime_ns, now_unix_ns):
    value = _configuration(raw)
    policy.lifecycle._clocks(boot, now_boottime_ns, now_unix_ns)
    p.require(value["supervisorInventorySha256"] == p.digest(inventory_sha256)
        and tuple(value[name] for name in BOOT_FIELDS) == boot
        and p.ns(value["issuedAtBoottimeNs"]) <= now_boottime_ns < p.ns(value["deadlineBoottimeNs"])
        and value["issuedAtUnixNanos"] <= now_unix_ns < value["expiresAtUnixNanos"])
    return dict(value=copy.deepcopy(value), deadline=p.ns(value["deadlineBoottimeNs"]),
        epochLimit=value["expiresAtUnixNanos"], addresses=addresses(value))


setup = configuration


def process(value):
    p.fields(value, PROCESS_FIELDS)
    p.integer(value["pid"], minimum=2, maximum=(1 << 31) - 1)
    p.integer(value["parentPid"], minimum=1, maximum=(1 << 31) - 1)
    p.integer(value["startTimeTicks"], maximum=p.MAX_I64)
    p.require(value["pid"] != value["parentPid"] and type(value["uid"]) is int
        and type(value["gid"]) is int and value["uid"] == value["gid"] == 0)
    return value


def socket_identity(value):
    p.fields(value, ("device", "inode"))
    p.integer(value["device"], minimum=0, maximum=p.MAX_I64)
    p.integer(value["inode"], maximum=p.MAX_I64)
    return value


def _peers(value):
    p.fields(value, ROLES)
    for row in value.values(): process(row)
    p.require(len({row["pid"] for row in value.values()}) == len(ROLES)
        and len({row["parentPid"] for row in value.values()}) == 1)
    return value


def message(raw, kind, *, role, configuration_sha256):
    p.require(kind in MESSAGE_APIS and role in ROLES)
    value = _document(raw, MAX_MESSAGE, ("apiVersion", "role", "configurationSha256", *MESSAGE_FIELDS[kind]))
    p.require(value["apiVersion"] == MESSAGE_APIS[kind] and value["role"] == role
        and value["configurationSha256"] == p.digest(configuration_sha256))
    if kind == "hello":
        process(value["process"]); socket_identity(value["control"])
        p.fields(value["listeners"], ROLE_LISTENERS[role])
        for row in value["listeners"].values(): socket_identity(row)
    elif kind == "connect":
        _peers(value["peers"])
    elif kind == "ready":
        p.digest(value["peersSha256"])
        p.fields(value["sockets"], ROLE_SOCKETS[role])
        for row in value["sockets"].values():
            p.fields(row, ("socket", "peer")); socket_identity(row["socket"]); process(row["peer"])
    else:
        for name in ("readySha256", "observationSha256", "admissionSha256"): p.digest(value[name])
        p.require(type(value["sources"]) is list and len(value["sources"]) == len(ROLE_SOURCES[role]))
        for name, row in zip(ROLE_SOURCES[role], value["sources"], strict=True):
            p.fields(row, ("purpose", "sha256")); p.require(row["purpose"] == name); p.digest(row["sha256"])
        names = KEY_NAMES if role == "lifecycle" else ()
        p.require(type(value["keys"]) is list and len(value["keys"]) == len(names))
        for offset, ((family, purpose), row) in enumerate(zip(names, value["keys"], strict=True)):
            p.fields(row, ("family", "purpose", "index"))
            p.require(row["family"] == family and row["purpose"] == purpose and type(row["index"]) is int
                and row["index"] == len(ROLE_SOURCES[role]) + offset)
        p.ns(value["deadlineBoottimeNs"]); p.integer(value["expiresAtUnixNanos"], maximum=p.MAX_I64)
    return copy.deepcopy(value)


def encode(kind, role, configuration_sha256, **payload):
    p.require(kind in MESSAGE_APIS)
    raw = p.canonical(dict(apiVersion=MESSAGE_APIS[kind], role=role,
        configurationSha256=configuration_sha256, **payload))
    message(raw, kind, role=role, configuration_sha256=configuration_sha256)
    return raw


def observation(configuration_raw, hello_raws, ready_raws):
    """Join literal actual-owner reports; this pure return is not owner evidence."""
    config = _configuration(configuration_raw)
    p.fields(hello_raws, ROLES); p.fields(ready_raws, ROLES)
    digest = p.sha(configuration_raw)
    hellos = {role: message(hello_raws[role], "hello", role=role, configuration_sha256=digest) for role in ROLES}
    peers = _peers({role: hellos[role]["process"] for role in ROLES})
    ready = {role: message(ready_raws[role], "ready", role=role, configuration_sha256=digest) for role in ROLES}
    identities = []
    for role in ROLES:
        p.require(ready[role]["peersSha256"] == p.sha(p.canonical(peers)))
        identities.append(hellos[role]["control"])
        identities.extend(hellos[role]["listeners"].values())
        for edge, row in ready[role]["sockets"].items():
            p.require(row["peer"] == peers[PEER_ROLES[role][edge]])
            identities.append(row["socket"])
    p.require(len({(row["device"], row["inode"]) for row in identities}) == len(identities))
    raw = p.canonical(dict(apiVersion=OBSERVATION_API, configurationSha256=digest,
        supervisorInventorySha256=config["supervisorInventorySha256"], invocationId=config["invocationId"],
        parentPid=peers["lifecycle"]["parentPid"], processes=peers,
        hellos={role: hello_raws[role].decode("ascii") for role in ROLES},
        ready={role: ready_raws[role].decode("ascii") for role in ROLES}))
    p.require(len(raw) <= MAX_OBSERVATION)
    return raw


def observation_value(raw, *, configuration_raw):
    value = _document(raw, MAX_OBSERVATION, OBSERVATION_FIELDS)
    p.fields(value["hellos"], ROLES); p.fields(value["ready"], ROLES)
    originals = []
    for field in ("hellos", "ready"):
        originals.append({role: policy.lifecycle._original(value[field][role], MAX_MESSAGE) for role in ROLES})
    p.require(observation(configuration_raw, *originals) == raw)
    return copy.deepcopy(value)


def admission(raw, *, configuration_raw, observation_raw, source_originals,
              supervisor_inventory_original, boot, now_boottime_ns, now_unix_ns):
    """Authenticate complete independent late inputs before any role receives keys."""
    config = configuration(configuration_raw, inventory_sha256=p.sha(supervisor_inventory_original),
        boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    observed = observation_value(observation_raw, configuration_raw=configuration_raw)
    value = _document(raw, MAX_ADMISSION, ADMISSION_FIELDS)
    p.require(value["apiVersion"] == ADMISSION_API and value["configurationSha256"] == p.sha(configuration_raw)
        and value["observationSha256"] == p.sha(observation_raw))
    p.fields(source_originals, SOURCE_NAMES); p.fields(value["sources"], SOURCE_NAMES)
    for name in SOURCE_NAMES:
        original = source_originals[name]
        p.require(type(original) is bytes and 0 < len(original) <= SOURCE_LIMITS[name]
            and p.digest(value["sources"][name]) == p.sha(original))
    prepared = policy.prepare(source_originals["provider-policy"], recipe_original=source_originals["recipe"],
        supervisor_inventory_original=supervisor_inventory_original,
        conductor_inventory_original=source_originals["conductor-inventory"],
        authority_inventory_original=source_originals["authority-inventory"],
        boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    peers = observed["processes"]
    peer = lambda role: {name: peers[role][name] for name in policy.PEER_FIELDS}
    p.require(prepared["peer"] == peer("lifecycle") and prepared["currentHeadPeer"] == peer("decisions")
        and prepared["value"]["listenerConfigurationOriginal"].encode("ascii")
            == source_originals["listener-configuration"])
    decision = decisions.configuration(source_originals["decision-configuration"],
        inventory_sha256=config["value"]["supervisorInventorySha256"],
        boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    p.require(decision["value"]["providerPeer"] == peer("provider"))
    listener = policy.lifecycle.rendezvous_profile._configuration(source_originals["listener-configuration"])
    # Resumed existing CLIs enforce their literal source limits, not this
    # startup frame. An approval cannot silently shorten those unseen limits:
    # require containment, never rewrite them or rely on a parent-only min.
    role_deadlines = (p.ns(listener["window"]["lifetimeDeadlineBoottimeNs"]),
        prepared["deadline"], decision["deadline"])
    role_expiries = (listener["expiresAtUnixNanos"], prepared["epochLimit"], decision["epochLimit"])
    accepted_deadline = p.ns(value["deadlineBoottimeNs"])
    accepted_expiry = p.integer(value["expiresAtUnixNanos"], maximum=p.MAX_I64)
    p.require(now_boottime_ns < max(role_deadlines) <= accepted_deadline <= config["deadline"]
        and now_unix_ns < max(role_expiries) <= accepted_expiry <= config["epochLimit"])
    startup = min(accepted_deadline, prepared["startupDeadline"])
    p.require(now_boottime_ns < startup)
    return dict(value=copy.deepcopy(value), deadline=accepted_deadline, epochLimit=accepted_expiry,
        startupDeadline=startup, pins=copy.deepcopy(value["sources"]), peers=copy.deepcopy(peers))


def role_arguments(role, *, supervisor_inventory_fd, supervisor_inventory_sha256,
                   source_fds, source_pins, socket_fds, peers, key_fds=None):
    """Source-fixed existing CLI arguments, not arbitrary commands or FD admission."""
    p.require(role in ROLES); _peers(peers)
    p.fields(source_fds, ROLE_SOURCES[role]); p.fields(source_pins, ROLE_SOURCES[role])
    p.fields(socket_fds, ROLE_SOCKETS[role])
    public = [supervisor_inventory_fd, *source_fds.values(), *socket_fds.values()]
    for fd in public: p.integer(fd, minimum=3, maximum=(1 << 31) - 1)
    p.require(len(public) == len(set(public)))
    p.digest(supervisor_inventory_sha256)
    for pin in source_pins.values(): p.digest(pin)
    def pair(name, fd, pin): return ["--" + name + "-fd", str(fd), "--" + name + "-sha256", pin]
    inventory = pair("supervisor-inventory", supervisor_inventory_fd, supervisor_inventory_sha256)
    if role == "lifecycle":
        p.fields(key_fds, ("cold", "adopted"))
        arguments = ["--run-native-pilot-lifecycle", *inventory,
            *pair("listener-configuration", source_fds["listener-configuration"], source_pins["listener-configuration"]),
            "--approval-fd", str(socket_fds["lifecycle"]), "--approval-peer-pid", str(peers["provider"]["pid"]),
            "--approval-peer-uid", "0", "--approval-peer-gid", "0"]
        for family in ("cold", "adopted"):
            purposes = tuple(name for group, name in KEY_NAMES if group == family)
            p.fields(key_fds[family], purposes)
            for name in purposes:
                fd = p.integer(key_fds[family][name], minimum=3, maximum=(1 << 31) - 1)
                p.require(fd not in public)
                arguments.extend(("--" + family + "-authority-key", name + "=" + str(fd)))
        return arguments
    p.require(key_fds is None or key_fds == {})
    if role == "provider":
        arguments = ["approval-provider", *pair("policy", source_fds["provider-policy"], source_pins["provider-policy"]),
            *inventory]
        for name in ("recipe", "conductor-inventory", "authority-inventory"):
            arguments.extend(pair(name, source_fds[name], source_pins[name]))
        return arguments + ["--approval-socket-fd", str(socket_fds["lifecycle"]),
            "--current-head-socket-fd", str(socket_fds["heads"])]
    return ["current-head-decision-service", *inventory,
        *pair("configuration", source_fds["decision-configuration"], source_pins["decision-configuration"]),
        "--approval-socket-fd", str(socket_fds["heads"])]
