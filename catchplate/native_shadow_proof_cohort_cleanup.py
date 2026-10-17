"""Separate fixed-inventory lifecycle permission and data-only observations.

No key creation, process selection, file mutation or operation-settlement
authority. The actual retained control owner performs contact and waitid.
"""
from __future__ import annotations

import os
import stat

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from catchplate import native_shadow_guest_delivery as delivery

p = delivery.p
DOMAIN = b"catchplate.nativeShadowProofCohortCleanup.signature/v1\0"
SIX_DOMAIN = b"catchplate.nativeShadowProofCohortCleanup.signature/v2\0"
DIRECTORY = "/var/lib/catchplate/native-shadow-proof-cohort-cleanup"
MAX_BYTES = 32768
ROLES = ("retrieval", "persistence", "trustedTime", "generationInstall", "bridge")
FIELDS = ("apiVersion", "purpose", "configurationSha256", "precreationSha256", "observationSha256",
          "releaseSha256", "invocationId", "operationIdSha256", "requestedAtBoottimeNs", "deadlineBoottimeNs", "signingKeyId")
RESULT_FIELDS = ("apiVersion", "authorizationSha256", "intentRecordSha256", "terminalOriginal", "terminalRecordSha256")
TERMINAL_FIELDS = ("apiVersion", "authorizationSha256", "configurationSha256", "precreationSha256", "observationSha256",
                   "releaseSha256", "invocationId", "completedAtBoottimeNs", "children")
CHILD_FIELDS = ("processId", "startTimeTicks", "pidfdDevice", "pidfdInode", "terminalCode", "terminalStatus",
                "observedAtBoottimeNs", "reapedAtBoottimeNs")


def configuration(value):
    p.require(value["apiVersion"] in ("catchplate.nativeShadowProofCohortConfiguration/v2",
        "catchplate.nativeShadowProofCohortConfiguration/v3", "catchplate.nativeShadowProofCohortConfiguration/v4",
        "catchplate.nativeShadowProofCohortConfiguration/v5", "catchplate.nativeShadowProofCohortConfiguration/v6",
        "catchplate.nativeShadowProofCohortConfiguration/v7", "catchplate.nativeShadowProofCohortConfiguration/v8"))
    selected = p.fields(value["cleanup"], ("authority", "scopeId", "journal", "genesisSha256"))
    authority = p.fields(selected["authority"], ("publicKeyBase64url", "keyId"))
    raw = p.decoded(authority["publicKeyBase64url"], size=32)
    p.require(raw != bytes(32) and authority["keyId"] == p.sha(raw)
              and authority["publicKeyBase64url"] != value["authority"]["publicKeyBase64url"])
    p.digest(selected["scopeId"]); p.digest(selected["genesisSha256"])
    identity = p.fields(selected["journal"], ("device", "inode", "mode", "uid", "gid"))
    p.integer(identity["device"], maximum=(1 << 64) - 1)
    p.integer(identity["inode"], maximum=(1 << 64) - 1)
    p.integer(identity["mode"], maximum=(1 << 32) - 1)
    p.integer(identity["uid"], minimum=0, maximum=0); p.integer(identity["gid"], minimum=0, maximum=0)
    p.require(identity["mode"] == (stat.S_IFDIR | 0o700) and identity["uid"] == identity["gid"] == 0)
    return selected


def _six(config):
    configuration(config)
    return config["apiVersion"] == "catchplate.nativeShadowProofCohortConfiguration/v3"


def _api(kind, config):
    configuration(config)
    version = {"catchplate.nativeShadowProofCohortConfiguration/v2": 1,
               "catchplate.nativeShadowProofCohortConfiguration/v3": 2,
               "catchplate.nativeShadowProofCohortConfiguration/v4": 3,
               "catchplate.nativeShadowProofCohortConfiguration/v5": 4,
               "catchplate.nativeShadowProofCohortConfiguration/v6": 5,
               "catchplate.nativeShadowProofCohortConfiguration/v7": 6,
               "catchplate.nativeShadowProofCohortConfiguration/v8": 7}[config["apiVersion"]]
    p.require(kind in ("Cleanup", "CleanupResult", "Terminal"))
    return "catchplate.nativeShadowProofCohort" + kind + "/v" + str(version)


def _domain(config):
    return {"catchplate.nativeShadowProofCohortCleanup/v1": DOMAIN,
            "catchplate.nativeShadowProofCohortCleanup/v2": SIX_DOMAIN,
            "catchplate.nativeShadowProofCohortCleanup/v3": b"catchplate.nativeShadowProofCohortCleanup.signature/v3\0",
            "catchplate.nativeShadowProofCohortCleanup/v4": b"catchplate.nativeShadowProofCohortCleanup.signature/v4\0",
            "catchplate.nativeShadowProofCohortCleanup/v5": b"catchplate.nativeShadowProofCohortCleanup.signature/v5\0",
            "catchplate.nativeShadowProofCohortCleanup/v6": b"catchplate.nativeShadowProofCohortCleanup.signature/v6\0",
            "catchplate.nativeShadowProofCohortCleanup/v7": b"catchplate.nativeShadowProofCohortCleanup.signature/v7\0"}[_api("Cleanup", config)]


def _fields(fields, config):
    return fields + (("externalDriverSha256",) if config is not None
        and config["apiVersion"] in ("catchplate.nativeShadowProofCohortConfiguration/v7", "catchplate.nativeShadowProofCohortConfiguration/v8") else ())


def authorize(*, configuration_raw, precreation_raw, observations_raw, release_raw, payload_raw,
              signing_key, boot, now):
    """Sign a separately approved exact scope with an existing cleanup key.

    Public originals alone are not live ownership. Both actual control owners
    rejoin their retained original process/descriptor state before effects.
    """
    from catchplate import native_shadow_proof_cohort_assignment as profile
    config = profile.configuration(configuration_raw)
    selected = configuration(config)
    payload = p.fields(p.document(payload_raw, MAX_BYTES), _fields(FIELDS, config))
    _scope(payload, configuration_raw, precreation_raw, observations_raw, release_raw, boot, now)
    p.require(isinstance(signing_key, Ed25519PrivateKey))
    public = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p.require(p.encoded(public) == selected["authority"]["publicKeyBase64url"])
    domain = _domain(config)
    result = p.canonical({"payload": payload, "signatureBase64url": p.encoded(signing_key.sign(domain + p.canonical(payload)))})
    authorization(result, configuration_raw, precreation_raw, observations_raw, release_raw, boot, now)
    p.require(len(result) <= MAX_BYTES)
    return result


def authorization(raw, config_raw, precreate_raw, observed_raw, release_raw, boot, now):
    signed = p.fields(p.document(raw, MAX_BYTES), ("payload", "signatureBase64url"))
    from catchplate import native_shadow_proof_cohort_assignment as profile
    value = p.fields(signed["payload"], _fields(FIELDS, profile.configuration(config_raw)))
    selected = _scope(value, config_raw, precreate_raw, observed_raw, release_raw, boot, now)
    domain = _domain(profile.configuration(config_raw))
    Ed25519PublicKey.from_public_bytes(p.decoded(selected["authority"]["publicKeyBase64url"], size=32)).verify(
        p.decoded(signed["signatureBase64url"], size=64), domain + p.canonical(value))
    return value


def _scope(value, config_raw, precreate_raw, observed_raw, release_raw, boot, now):
    from catchplate import native_shadow_proof_cohort_assignment as profile
    config = profile.configuration(config_raw)
    selected = configuration(config)
    p.integer(now, maximum=(1 << 64) - 1)
    launch_key = Ed25519PublicKey.from_public_bytes(p.decoded(config["authority"]["publicKeyBase64url"], size=32))
    signed = p.fields(p.document(precreate_raw, MAX_BYTES), ("apiVersion", "payload", "signatureBase64url"))
    p.require(signed["apiVersion"] == "catchplate.nativeShadowProofCohortPrecreation/v1")
    window = p.fields(signed["payload"], profile.WINDOW_FIELDS)
    launch_key.verify(p.decoded(signed["signatureBase64url"], size=64), profile.PRECREATE_DOMAIN + p.canonical(window))
    p.require(window["configurationSha256"] == p.sha(config_raw) and window["authorityKeyId"] == config["authority"]["keyId"]
              and (window["bootIdBase64url"], window["timeNamespaceDevice"], window["timeNamespaceInode"]) == boot)
    issued, startup, lifetime = (p.ns(window[field]) for field in
        ("issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"))
    p.require(issued < startup <= lifetime and startup - issued <= 30_000_000_000 and issued <= now < lifetime)
    observed = p.fields(p.document(observed_raw, MAX_BYTES), profile.originals_fields(config))
    p.require(observed["apiVersion"] == profile.originals_api(config)
        and observed["configurationSha256"] == p.sha(config_raw) and observed["precreationSha256"] == p.sha(precreate_raw)
        and observed["invocationId"] == window["invocationId"])
    release = p.fields(p.document(release_raw, MAX_BYTES), ("payload", "signatureBase64url"))
    released = p.fields(release["payload"], profile.release_fields(config))
    launch_key.verify(p.decoded(release["signatureBase64url"], size=64), profile.release_domain(config) + p.canonical(released))
    p.require(released["apiVersion"] == profile.release_api(config)
        and released["configurationSha256"] == p.sha(config_raw) and released["precreationSha256"] == p.sha(precreate_raw)
        and released["observationSha256"] == p.sha(observed_raw) and released["invocationId"] == window["invocationId"]
        and released["signingKeyId"] == config["authority"]["keyId"])
    p.require(value["apiVersion"] == _api("Cleanup", config)
        and value["purpose"] == "terminate-owned-proof-cohort" and value["configurationSha256"] == p.sha(config_raw)
        and value["precreationSha256"] == p.sha(precreate_raw) and value["observationSha256"] == p.sha(observed_raw)
        and value["releaseSha256"] == p.sha(release_raw) and value["invocationId"] == window["invocationId"]
        and value["signingKeyId"] == selected["authority"]["keyId"])
    if profile.endpoint_driver_selected(config):
        p.require(value["externalDriverSha256"] == released["externalDriverSha256"]
            == profile.external_driver_sha256(config, observed))
    p.digest(value["operationIdSha256"])
    p.require(issued <= p.ns(value["requestedAtBoottimeNs"]) <= now < p.ns(value["deadlineBoottimeNs"]) <= lifetime - 250_000_000)
    p.require(p.ns(value["deadlineBoottimeNs"]) - p.ns(value["requestedAtBoottimeNs"]) <= 30_000_000_000)
    return selected


def record(sequence, previous, original):
    p.require(type(original) is bytes and original and original.isascii())
    return p.canonical({"apiVersion": "catchplate.nativeShadowProofCohortCleanupRecord/v1", "sequence": sequence,
                        "previousHeadSha256": previous, "original": original.decode("ascii")})


def result(raw, authorization_raw, selected, observed, *, cohort_configuration=None):
    """Data validation only. Caller MUST prove actual retained parent/children."""
    value = p.fields(p.document(raw, MAX_BYTES), _fields(RESULT_FIELDS, cohort_configuration))
    from catchplate import native_shadow_proof_cohort_assignment as profile
    roles = profile.roles(cohort_configuration) if cohort_configuration is not None else ROLES
    api = lambda kind: _api(kind, cohort_configuration) if cohort_configuration is not None else "catchplate.nativeShadowProofCohort" + kind + "/v1"
    p.require(value["apiVersion"] == api("CleanupResult")
              and value["authorizationSha256"] == p.sha(authorization_raw))
    intent = p.sha(record(1, selected["genesisSha256"], authorization_raw))
    p.require(value["intentRecordSha256"] == intent and type(value["terminalOriginal"]) is str
              and value["terminalOriginal"].isascii())
    terminal_raw = value["terminalOriginal"].encode("ascii")
    terminal = p.fields(p.document(terminal_raw, MAX_BYTES), _fields(TERMINAL_FIELDS, cohort_configuration))
    p.require(value["terminalRecordSha256"] == p.sha(record(2, intent, terminal_raw))
              and terminal["apiVersion"] == api("Terminal")
              and terminal["authorizationSha256"] == p.sha(authorization_raw))
    command = p.document(authorization_raw, MAX_BYTES)["payload"]
    p.require(command["apiVersion"] == api("Cleanup"))
    for field in ("configurationSha256", "precreationSha256", "observationSha256", "releaseSha256", "invocationId"):
        p.require(terminal[field] == command[field])
    if cohort_configuration is not None and profile.endpoint_driver_selected(cohort_configuration):
        p.require(value["externalDriverSha256"] == terminal["externalDriverSha256"] == command["externalDriverSha256"]
            == profile.external_driver_sha256(cohort_configuration, observed))
    children = p.fields(terminal["children"], roles)
    completed = p.ns(terminal["completedAtBoottimeNs"])
    p.require(p.ns(command["requestedAtBoottimeNs"]) <= completed < p.ns(command["deadlineBoottimeNs"]))
    for role in roles:
        child = p.fields(children[role], CHILD_FIELDS)
        p.integer(child["processId"], minimum=2, maximum=(1 << 31) - 1)
        p.integer(child["startTimeTicks"], maximum=(1 << 64) - 1)
        p.integer(child["terminalCode"], minimum=1, maximum=3)
        p.require((child["processId"], child["startTimeTicks"]) == (observed[role]["processId"], observed[role]["startTimeTicks"])
                  and child["terminalCode"] in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED))
        p.integer(child["pidfdDevice"], minimum=0, maximum=(1 << 64) - 1); p.integer(child["pidfdInode"], maximum=(1 << 64) - 1)
        p.integer(child["terminalStatus"], minimum=0, maximum=255)
        p.require(p.ns(command["requestedAtBoottimeNs"]) <= p.ns(child["observedAtBoottimeNs"])
                  <= p.ns(child["reapedAtBoottimeNs"]) <= completed)
    return value, terminal


def recover(config, authorization_raw):
    """Read the exact complete two-record journal. No repair, contact or signing."""
    selected = configuration(config)
    read_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    fds, ancestors, held = [], [], []
    structural = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
    original_identity = lambda info: structural(info) + (info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    def names(directory):
        result = set()
        with os.scandir(directory) as entries:
            for item in entries:
                p.require(len(result) < 4 and item.name not in result)
                result.add(item.name)
        p.require(result == {"cleanup.lock", "genesis.json", "intent.json", "terminal.json"})
    try:
        current = os.open("/", read_flags | os.O_DIRECTORY); fds.append(current)
        for name in DIRECTORY.split("/")[1:]:
            info = os.fstat(current)
            p.require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_mode & 0o022 == 0)
            child = os.open(name, read_flags | os.O_DIRECTORY, dir_fd=current); fds.append(child)
            ancestors.append((current, name, child, structural(os.fstat(child))))
            current = child
        info = os.fstat(current)
        p.require(tuple(selected["journal"][field] for field in ("device", "inode", "mode", "uid", "gid"))
                  == (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid))
        names(current)
        lock = os.open("cleanup.lock", read_flags, dir_fd=current); fds.append(lock)
        info = os.fstat(lock)
        p.require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_nlink == 1
                  and info.st_size == 0 and stat.S_IMODE(info.st_mode) == 0o600)
        held.append(("cleanup.lock", lock, original_identity(info), None))
        originals = {}
        for name in ("genesis.json", "intent.json", "terminal.json"):
            fd = os.open(name, read_flags, dir_fd=current); fds.append(fd)
            before = os.fstat(fd)
            p.require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and before.st_nlink == 1
                      and stat.S_IMODE(before.st_mode) == 0o400 and 0 < before.st_size <= 65536)
            raw = os.pread(fd, 65537, 0)
            after = os.fstat(fd)
            p.require(original_identity(before) == original_identity(after) and len(raw) == before.st_size)
            held.append((name, fd, original_identity(before), raw))
            originals[name] = raw
        p.require(p.sha(originals["genesis.json"]) == selected["genesisSha256"]
                  and originals["intent.json"] == record(1, selected["genesisSha256"], authorization_raw))
        terminal = p.fields(p.document(originals["terminal.json"], 65536), ("apiVersion", "sequence", "previousHeadSha256", "original"))
        p.require(type(terminal["original"]) is str and terminal["original"].isascii())
        p.require(originals["terminal.json"] == record(2, p.sha(originals["intent.json"]), terminal["original"].encode("ascii")))
        for parent, name, child, expected in ancestors:
            info = os.fstat(parent)
            p.require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_mode & 0o022 == 0
                      and structural(os.fstat(child)) == expected
                      and structural(os.stat(name, dir_fd=parent, follow_symlinks=False)) == expected)
        for name, fd, expected, raw in held:
            p.require(original_identity(os.fstat(fd)) == expected
                      and original_identity(os.stat(name, dir_fd=current, follow_symlinks=False)) == expected
                      and (raw is None or os.pread(fd, len(raw) + 1, 0) == raw))
        names(current)
        result = {"apiVersion": _api("CleanupResult", config),
            "authorizationSha256": p.sha(authorization_raw), "intentRecordSha256": p.sha(originals["intent.json"]),
            "terminalOriginal": terminal["original"], "terminalRecordSha256": p.sha(originals["terminal.json"])}
        if profile.endpoint_driver_selected(config):
            result["externalDriverSha256"] = p.document(authorization_raw, MAX_BYTES)["payload"]["externalDriverSha256"]
        return p.canonical(result)
    finally:
        for fd in reversed(fds):
            os.close(fd)
