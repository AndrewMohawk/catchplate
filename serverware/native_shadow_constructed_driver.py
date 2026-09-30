"""Purpose-fixed constructed-driver admission from the retained live launcher.

No measurement JSON input, key generation, native signer claim, generation
installation receipt, or reaper-settlement assertion is supported here.
"""
from __future__ import annotations

import fcntl
import os
import socket
import stat
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from serverware import native_shadow_nitro_profile as p

DOMAIN = "serverware.nativeShadowConstructedDriverAdmission.signature/v1"
BOOTSTRAP_DOMAIN = "serverware.nativeShadowBootstrapDriverAdmission.signature/v1"
CENSUS = ("apiVersion", "configurationSha256", "windowSha256", "bootstrapObservationSha256", "scopeSha256",
    "phase", "parent", "parentExecutableSha256", "pidNamespaceSha256", "driver", "descendants", "descriptors",
    "descriptorSetSha256", "observedAtBoottimeNs", "lifetimeDeadlineBoottimeNs")
PUBLIC = ("apiVersion", "bootstrapObservationOriginal", "phaseScopeOriginal", "phaseBundleOriginal", "closureOriginal",
    "assignmentOriginal", "keyConfigurationOriginal", "admissionAuthorizationOriginal", "evidenceOriginal", "combinedResultOriginal")
PROCESS = ("processId", "startTimeTicks", "parentId", "pidfdDevice", "pidfdInode")
DESCRIPTOR = ("fd", "device", "inode", "mode", "uid", "gid", "mountId", "flags")


def authority(value):
    p.fields(value, ("keyId", "keySpkiSha256", "keyMaterialSha256", "publicKeyBase64url"))
    return p.public_key({"role": "custody-supervisor-capability", **value})


def _signing_key(fd, expected):
    from serverware.native_shadow_driver_bootstrap import SEALS
    public = authority(expected)
    p.require(type(fd) is int and fd > 2)
    info = os.fstat(fd)
    p.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 0 and info.st_size == 32
        and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, 0, 0o400)
        and not os.get_inheritable(fd) and fcntl.fcntl(fd, fcntl.F_GET_SEALS) == SEALS)
    private = Ed25519PrivateKey.from_private_bytes(os.pread(fd, 33, 0))
    p.require(private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        == public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    return private, public


def prepare_bootstrap(owner):
    """Return an unsigned payload from this live attempt, never authority.

    The payload issuance time is recorded once while the original launcher
    window is already running. Neither is renewed while an independent signer
    considers these exact bytes. No signing key enters this path.
    """
    from serverware.native_shadow_driver_bootstrap import DriverBootstrap
    p.require(type(owner) is DriverBootstrap)
    owner.check()
    policy = owner._config.get("lifecycle", {})
    p.require(policy.get("apiVersion") == "serverware.nativeShadowDriverLifecyclePolicy/v3"
        and not owner._attempted and not owner._bootstrap_admission_prepare_attempted
        and owner._bootstrap_admission_original is None)
    expected = policy["constructedAdmissionAuthority"]
    authority(expected)
    owner._bootstrap_admission_prepare_attempted = True
    # Same genuine already-running clone parent; no future PID prediction.
    namespace = os.open("/proc/" + str(owner._child_pid) + "/ns/pid", os.O_RDONLY | os.O_CLOEXEC)
    owner._admission_namespace_fd = namespace
    info, pidfd = os.fstat(namespace), os.fstat(owner._pidfd)
    parent = {"processId": owner._child_pid, "startTimeTicks": owner._child_start, "parentId": owner._pid,
        "pidfdDevice": pidfd.st_dev, "pidfdInode": pidfd.st_ino}
    issued = time.time_ns()
    payload = {"apiVersion": "serverware.nativeShadowBootstrapDriverAdmission/v1", "purpose": "native-driver-bootstrap-admission",
        "configurationSha256": owner._config_sha, "windowSha256": owner._window_sha,
        "bootstrapObservationOriginal": owner._observation_raw.decode("ascii"), "parent": parent,
        "parentExecutableSha256": p.sha(os.pread(owner._exec, os.fstat(owner._exec).st_size, 0)),
        "pidNamespaceSha256": p.sha(p.canonical([info.st_dev, info.st_ino])),
        "issuedAtUnixNanos": issued, "expiresAtUnixNanos": issued + 30_000_000_000,
        "startupDeadlineBoottimeNs": owner._window["startupDeadlineBoottimeNs"],
        "lifetimeDeadlineBoottimeNs": owner._window["lifetimeDeadlineBoottimeNs"],
        "signingKeyId": expected["keyId"], "signingKeySpkiSha256": expected["keySpkiSha256"]}
    owner.check()
    raw = p.canonical(payload)
    p.require(len(raw) <= 8192)
    _live_payload(owner, payload)
    owner._bootstrap_admission_payload = raw
    owner.check()
    return bytes(raw)


def _signed_original(raw, maximum, payload_raw, public, domain, extra=None):
    p.require(type(raw) is bytes)
    value = p.fields(p.document(raw, maximum), ("payload", "signature") if extra is None
        else ("bootstrapAdmissionOriginal", "payload", "signature"))
    p.require(p.canonical(value["payload"]) == payload_raw)
    if extra is not None:
        p.require(value["bootstrapAdmissionOriginal"] == extra.decode("ascii"))
    public.verify(p.decoded(value["signature"], size=64), p.preimage(domain, value["payload"]))
    return value["payload"]


def _live_payload(owner, payload):
    from serverware.native_shadow_driver_bootstrap import mechanics
    owner.check()
    p.require(mechanics._clock() < owner._startup)
    p.freshness(payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"], time.time_ns())


def accept_bootstrap(owner, original):
    """Consume one externally signed original against the retained attempt."""
    from serverware.native_shadow_driver_bootstrap import DriverBootstrap
    p.require(type(owner) is DriverBootstrap)
    owner.check()
    p.require(not owner._attempted and owner._bootstrap_admission_payload is not None
        and not owner._bootstrap_admission_accept_attempted and owner._bootstrap_admission_original is None)
    # Malformed/refused originals consume this acceptance, too. The namespace
    # descriptor stays with the actual launcher until definite cleanup.
    owner._bootstrap_admission_accept_attempted = True
    expected = owner._config["lifecycle"]["constructedAdmissionAuthority"]
    payload = _signed_original(original, 8192, owner._bootstrap_admission_payload,
        authority(expected), BOOTSTRAP_DOMAIN)
    _live_payload(owner, payload)
    owner._bootstrap_admission_original = original
    _live_payload(owner, payload)
    return bytes(original)


def admit_bootstrap(owner, *, signing_key_fd):
    """Legacy local signer, sharing the same one-shot preparation/intake."""
    from serverware.native_shadow_driver_bootstrap import DriverBootstrap
    p.require(type(owner) is DriverBootstrap)
    owner.check()
    private, _ = _signing_key(signing_key_fd, owner._config["lifecycle"]["constructedAdmissionAuthority"])
    payload = p.document(prepare_bootstrap(owner), 8192)
    signature = private.sign(p.preimage(BOOTSTRAP_DOMAIN, payload))
    return accept_bootstrap(owner, p.canonical({"payload": payload, "signature": p.encoded(signature)}))


def generation_manifest(owner, *, assignment_original, production):
    """Unsigned deterministic grant recipe; measured fields only from owner.

    The independent generation-grant signer and Rust receiving factory remain
    authoritative. This function does not verify/approve the supplied assignment.
    """
    from serverware.native_shadow_driver_bootstrap import DriverBootstrap
    p.require(type(owner) is DriverBootstrap and owner._bootstrap_admission_original is not None)
    owner.check()
    early = p.document(owner._bootstrap_admission_original, 8192)["payload"]
    assignment = p.document(assignment_original, 4 * 1024 * 1024)["payload"]
    fields = ("signerBackendSha256", "persistenceBackendSha256", "retrievalBackendSha256", "dispatcherProtocolSetSha256",
        "maximumRpcNanos", "cleanupReserveNanos", "maximumInFlightCalls", "maximumAsyncDurabilityNanos", "expectedConfigurationBindingSha256")
    p.fields(production, fields)
    for name in fields[:4] + fields[-1:]:
        p.digest(production[name])
    p.require(250_000_000 <= p.integer(production["maximumRpcNanos"]) <= 1_000_000_000
        and 0 < p.integer(production["cleanupReserveNanos"]) <= 5_000_000_000
        and 0 < p.integer(production["maximumInFlightCalls"]) <= 64
        and 0 < p.integer(production["maximumAsyncDurabilityNanos"]) <= production["maximumRpcNanos"])
    driver = owner._observation["driver"]
    instance = p.sha(owner._window["invocationId"].encode("ascii"))
    boot = p.sha(p.decoded(owner._window["bootIdBase64url"], size=16))
    parent = early["parent"]
    reaper = {"reaperInstanceSha256": p.framed(b"serverware.nativeShadowStableParentInstance/v1", (p.canonical([parent, instance]),)),
        "reaperExecutableSha256": early["parentExecutableSha256"], "supervisorInstanceSha256": instance,
        "supervisorBootIdSha256": boot, "kernelDriverIdentitySha256": driver["identitySha256"],
        "subreaperProcessStartTimeTicks": parent["startTimeTicks"], "pidfdNamespaceSha256": early["pidNamespaceSha256"],
        "retainedDescriptorSetSha256": driver["retainedDescriptorManifestSha256"], "ownershipEpoch": parent["startTimeTicks"],
        "independentRestartForbidden": True}
    reaper["identitySha256"] = p.framed(b"serverware.policyShadowCustodyStableReaper/v1", (p.canonical(list(reaper.values())),))
    operations = ["recover-current-state", "verify-checkpoint-successor", "verify-current-checkpoint-head", "verify-observation-evidence",
        "prepare-generation-publication", "commit-generation-publication", "abort-generation-publication", "begin-ingress",
        "reserve-spool-append", "append-spool-event", "compact-spool", "commit-request", "append-active-effect-barrier",
        "commit-active-effect", "reconcile-active-effect", "append-terminal", "consume-and-publish-activation"]
    coverage = p.framed(b"serverware.policyShadowCustodyOperationCoverage/v1", (p.canonical(operations),))
    bindings = [value for value in assignment["authorityKeyIndependence"]["bindings"]
        if value["role"] == "custody-result-envelope" and value["scopeSha256"] == assignment["assignmentId"]]
    p.require(len(bindings) == 1)
    key = bindings[0]
    manifest = p.framed(b"serverware.policyShadowCustodyDispatchManifest/v1", (p.canonical([
        "serverware.policyShadowCustodyDispatch/v2", coverage, production["dispatcherProtocolSetSha256"], driver["identitySha256"],
        reaper["identitySha256"], driver["driverExecutableSha256"], production["signerBackendSha256"],
        production["persistenceBackendSha256"], production["retrievalBackendSha256"], 8 * 1024 * 1024, 8 * 1024 * 1024,
        production["maximumAsyncDurabilityNanos"], p.digest(key["keyId"]), p.digest(key["keySpkiSha256"])]),))
    owner.check()
    return {"dispatchManifestSha256": manifest, "driverGenerationReceiptSha256": p.sha(owner._bootstrap_admission_original),
        "kernelDriverIdentitySha256": driver["identitySha256"], "retainedDescriptorSetSha256": driver["retainedDescriptorManifestSha256"],
        "operationCoverageRootSha256": coverage, "stableReaperIdentity": reaper}


def _send(owner, operation, original):
    raw = p.canonical({"apiVersion": "serverware.nativeShadowConstructedDriverControl/v1",
        "operation": operation, "original": original})
    p.require(len(raw) <= 65536)
    owner.check()
    p.require(owner._socket.sendmsg([raw], [], socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL) == len(raw))


def _read_public(owner, fd, notice):
    from serverware.native_shadow_driver_bootstrap import SEALS
    info = os.fstat(fd)
    p.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 0 and stat.S_IMODE(info.st_mode) == 0o400
        and (info.st_uid, info.st_gid) == (owner._config["uid"], owner._config["gid"])
        and 0 < info.st_size <= 8 * 1024 * 1024 and info.st_size == notice["length"]
        and not os.get_inheritable(fd) and fcntl.fcntl(fd, fcntl.F_GET_SEALS) == SEALS)
    raw = os.pread(fd, info.st_size + 1, 0)
    p.require(len(raw) == info.st_size and p.sha(raw) == notice["originalSha256"])
    public = p.fields(p.document(raw, 8 * 1024 * 1024), PUBLIC)
    p.require(public["apiVersion"] == "serverware.nativeShadowDriverPublicAdmission/v1"
        and public["bootstrapObservationOriginal"].encode("ascii") == owner._observation_raw
        and public["phaseScopeOriginal"].encode("ascii") == owner._phase_scope_original)
    scope = p.document(owner._phase_scope_original, 32768)["payload"]
    p.require(p.sha(public["phaseBundleOriginal"].encode("ascii")) == scope["publicBundleSha256"])
    return raw, public


def _census(owner, raw):
    from serverware.native_shadow_driver_bootstrap import mechanics
    value = p.fields(p.document(raw, 48 * 1024), CENSUS)
    p.require(value["apiVersion"] == "serverware.nativeShadowDriverLifecycleObservation/v1"
        and value["phase"] == "constructed-driver-subtree"
        and value["configurationSha256"] == owner._config_sha and value["windowSha256"] == owner._window_sha
        and value["bootstrapObservationSha256"] == p.sha(owner._observation_raw)
        and value["scopeSha256"] == p.sha(owner._phase_scope_original)
        and value["parentExecutableSha256"] == p.sha(os.pread(owner._exec, os.fstat(owner._exec).st_size, 0))
        and value["lifetimeDeadlineBoottimeNs"] == owner._window["lifetimeDeadlineBoottimeNs"]
        and p.ns(value["observedAtBoottimeNs"]) <= mechanics._clock() < owner._startup)
    parent, driver = p.fields(value["parent"], PROCESS), p.fields(value["driver"], PROCESS)
    p.require((parent["processId"], parent["startTimeTicks"], parent["parentId"]) == (owner._child_pid, owner._child_start, owner._pid)
        and (driver["processId"], driver["startTimeTicks"], driver["parentId"]) == (owner._driver_pid, owner._driver_start, owner._child_pid))
    for original, fd in ((parent, owner._pidfd), (driver, owner._driver_pidfd)):
        held = os.fstat(fd)
        p.require((original["pidfdDevice"], original["pidfdInode"]) == (held.st_dev, held.st_ino))
    p.require(type(value["descendants"]) is list and 1 <= len(value["descendants"]) <= 16
        and driver in value["descendants"] and type(value["descriptors"]) is list and 1 <= len(value["descriptors"]) <= 256)
    processes, descriptors = [], []
    for item in value["descendants"]:
        p.fields(item, PROCESS)
        p.require(p.integer(item["processId"]) > 1 and p.integer(item["startTimeTicks"]) > 0
            and p.integer(item["pidfdInode"]) > 0)
        processes.append(item["processId"])
    for item in value["descriptors"]:
        p.fields(item, DESCRIPTOR)
        for name in DESCRIPTOR:
            p.integer(item[name], minimum=0, maximum=(1 << 64) - 1)
        descriptors.append(item["fd"])
    p.require(processes == sorted(set(processes)) and descriptors == sorted(set(descriptors))
        and value["descriptorSetSha256"] == p.sha(p.canonical(value["descriptors"])))
    return value


def prepare(owner):
    """Export genuine census/public originals once for independent signing.

    Returned bytes are evidence and an unsigned existing payload, not a
    transferable constructed-driver owner or a successful admission.
    """
    from serverware.native_shadow_driver_bootstrap import DriverBootstrap, mechanics
    p.require(type(owner) is DriverBootstrap)
    owner.check()
    policy = owner._config.get("lifecycle", {})
    p.require(policy.get("apiVersion") == "serverware.nativeShadowDriverLifecyclePolicy/v3"
        and owner._constructed and not owner._constructed_admission_attempted and mechanics._clock() < owner._startup)
    expected = policy["constructedAdmissionAuthority"]
    public_key = authority(expected)
    p.require(owner._bootstrap_admission_original is not None)
    # From this first contact onward, every ambiguous outcome remains consumed.
    owner._constructed_admission_attempted = True
    _send(owner, "export", None)
    reply_raw, rights = owner._receive_rights(65536, 1)
    owner._constructed_public_fd = rights[0]  # retained until definite subtree reap
    reply = p.fields(p.document(reply_raw, 65536), ("apiVersion", "censusOriginal", "publicAdmissionNoticeOriginal"))
    p.require(reply["apiVersion"] == "serverware.nativeShadowConstructedDriverExport/v1")
    census_raw = reply["censusOriginal"].encode("ascii")
    census = _census(owner, census_raw)
    notice = p.fields(p.document(reply["publicAdmissionNoticeOriginal"].encode("ascii"), 4096),
        ("apiVersion", "observationSha256", "scopeSha256", "originalSha256", "length"))
    p.require(notice["apiVersion"] == "serverware.nativeShadowDriverPublicAdmissionNotice/v1"
        and notice["observationSha256"] == p.sha(owner._observation_raw) and notice["scopeSha256"] == p.sha(owner._phase_scope_original))
    public_raw, public = _read_public(owner, owner._constructed_public_fd, notice)
    keys = p.fields(p.document(public["keyConfigurationOriginal"].encode("ascii"), 65536), ("apiVersion", "authorization"))
    p.require(keys["apiVersion"] == "serverware.nativeShadowRoleKeys/v2")
    authorization = p.fields(keys["authorization"], ("payload", "signature"))
    authorized = p.fields(authorization["payload"], p.AUTH_FIELDS)
    p.require(authorized["apiVersion"] == "serverware.nativeShadowRoleKeyAssignment/v2"
        and authorized["purpose"] == "shadow-role-key-possession" and authorized["profile"] == "preassigned-encrypted-local-v1"
        and authorized["signingKeyId"] == expected["keyId"] and authorized["signingKeySpkiSha256"] == expected["keySpkiSha256"])
    public_key.verify(p.decoded(authorization["signature"], size=64), p.preimage("serverware.nativeShadowRoleKeyAssignment.signature/v2", authorized))
    statement = p.document(public["evidenceOriginal"].encode("ascii"), 131072)["statement"]
    issued = time.time_ns()  # issuer observation only; receiver uses its own TrustedTime
    early = p.document(owner._bootstrap_admission_original, 8192)["payload"]
    expires = min(authorized["expiresAtUnixNanos"], early["expiresAtUnixNanos"])
    p.require(early["issuedAtUnixNanos"] <= issued < expires)
    p.freshness(authorized["issuedAtUnixNanos"], authorized["expiresAtUnixNanos"], issued)
    for name in ("assignmentId", "assignmentPayloadSha256", "assignmentRevision"):
        p.require(statement[name] == authorized[name])
    payload = {"apiVersion": "serverware.nativeShadowConstructedDriverAdmission/v1", "purpose": "constructed-native-driver-admission",
        "configurationSha256": owner._config_sha, "windowSha256": owner._window_sha,
        "bootstrapObservationSha256": p.sha(owner._observation_raw), "phaseScopeSha256": p.sha(owner._phase_scope_original),
        "censusSha256": p.sha(census_raw), "publicAdmissionSha256": p.sha(public_raw),
        "bootstrapAdmissionSha256": p.sha(owner._bootstrap_admission_original),
        "kernelDriverIdentitySha256": owner._observation["driver"]["identitySha256"],
        "productionConfigurationBindingSha256": p.digest(statement["productionConfigurationBindingSha256"]),
        **{name: authorized[name] for name in ("assignmentId", "assignmentPayloadSha256", "assignmentRevision",
            "trustCheckpointId", "revocationGeneration", "revocationRootSha256")},
        "issuedAtUnixNanos": issued, "expiresAtUnixNanos": expires,
        "startupDeadlineBoottimeNs": owner._window["startupDeadlineBoottimeNs"],
        "lifetimeDeadlineBoottimeNs": owner._window["lifetimeDeadlineBoottimeNs"],
        "signingKeyId": expected["keyId"], "signingKeySpkiSha256": expected["keySpkiSha256"]}
    payload_raw = p.canonical(payload)
    p.require(len(payload_raw) <= 16384 and mechanics._clock() < owner._startup)
    _read_public(owner, owner._constructed_public_fd, notice)
    _live_payload(owner, payload)
    owner._constructed_admission_request = (payload_raw, census_raw, public_raw, notice)
    return {"payloadOriginal": bytes(payload_raw), "censusOriginal": bytes(census_raw),
        "publicAdmissionOriginal": bytes(public_raw),
        "bootstrapAdmissionOriginal": bytes(owner._bootstrap_admission_original)}


def accept(owner, original):
    """Retain/forward one signed original only for the live exported attempt."""
    from serverware.native_shadow_driver_bootstrap import DriverBootstrap
    p.require(type(owner) is DriverBootstrap)
    owner.check()
    p.require(owner._constructed and owner._constructed_admission_request is not None
        and not owner._constructed_admission_accept_attempted and owner._constructed_admission_original is None)
    owner._constructed_admission_accept_attempted = True
    payload_raw, census_raw, public_raw, notice = owner._constructed_admission_request
    expected = owner._config["lifecycle"]["constructedAdmissionAuthority"]
    payload = _signed_original(original, 16384, payload_raw, authority(expected), DOMAIN,
        owner._bootstrap_admission_original)
    _live_payload(owner, payload)
    _census(owner, census_raw)
    retained_raw, _ = _read_public(owner, owner._constructed_public_fd, notice)
    p.require(retained_raw == public_raw)
    _live_payload(owner, payload)
    owner._constructed_admission_original = original  # retain before contact
    _send(owner, "admit", original.decode("ascii"))
    retained = p.fields(p.document(owner._receive(4096), 4096), ("apiVersion", "admissionSha256", "censusSha256"))
    p.require(retained == {"apiVersion": "serverware.nativeShadowConstructedDriverRetained/v1",
        "admissionSha256": p.sha(original), "censusSha256": p.sha(census_raw)})
    _live_payload(owner, payload)
    return bytes(original)


def admit(owner, *, signing_key_fd):
    """Legacy local signer, sharing the same genuine export/intake owners."""
    from serverware.native_shadow_driver_bootstrap import DriverBootstrap
    p.require(type(owner) is DriverBootstrap)
    owner.check()
    private, _ = _signing_key(signing_key_fd, owner._config["lifecycle"]["constructedAdmissionAuthority"])
    request = prepare(owner)
    payload = p.document(request["payloadOriginal"], 16384)
    signature = private.sign(p.preimage(DOMAIN, payload))
    original = p.canonical({"bootstrapAdmissionOriginal": request["bootstrapAdmissionOriginal"].decode("ascii"),
        "payload": payload, "signature": p.encoded(signature)})
    return accept(owner, original)
