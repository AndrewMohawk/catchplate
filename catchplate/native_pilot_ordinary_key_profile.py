"""Existing ordinary C3 identity/checkpoint bytes and pre-exec preparation joins.

These pure helpers neither observe a process nor approve an authority. A
preparation original describes retained parked children and intended executable
files, not already-executing service identities. Its caller must authenticate
the actual observation channel and the separately approved launch, cold input,
driver window and authority history. Runtime consumers still measure the real
executed process and verify the independently signed current-key checkpoint.
"""
from __future__ import annotations

import copy
import re

from catchplate import custody_generation_grants as g

p = g.p
MAX_PREPARATION = 65536
PREPARATION_API = "catchplate.custodyFiveServicePreparation/v1"
KEY_API = "catchplate.policyCustodyCurrentKeyAuthorization/v3"
PROCESS_DOMAIN = b"catchplate.policyCustodyEndpointProcessIdentity/v3"
PIDFD_DOMAIN = b"catchplate.policyCustodyPidfdStatIdentity/v3"
KEY_DOMAIN = KEY_API.encode("ascii")
ENDPOINT_ROLES = ("signer-hsm", "settlement-store", "fence-authority",
    "cleanup-watchdog", "cgroup-executor", "termination-ledger")
PREPARATION_FIELDS = ("apiVersion", "phase", "configurationSha256", "bootIdBase64url",
    "timeNamespaceDevice", "timeNamespaceInode", "issuedAtBoottimeNs",
    "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId", "services")
SERVICE_FIELDS = ("configurationSha256", "plannedUid", "plannedGid", "processId",
    "startTimeTicks", "pidfdStat", "targetExecutable")
PIDFD_FIELDS = ("device", "inode", "mode", "uid", "gid", "sha256")
EXECUTABLE_FIELDS = ("device", "inode", "length", "sha256", "imaSha256", "fsVeritySha256")
IDENTITY_FIELDS = ("endpointRole", "endpointUid", "endpointGid", "endpointPid",
    "endpointStartTimeTicks", "endpointPidfdInode", "endpointPidfdStatSha256",
    "executableDevice", "executableInode", "executableLength", "executableSha256",
    "executableImaSha256", "executableFsVeritySha256", "identitySha256")
PAYLOAD_FIELDS = ("apiVersion", "endpointRole", "endpointProcessIdentitySha256",
    "exactEndpointGeneration", "authorizedSigningKeyId", "authorizedSigningKeySpkiSha256",
    "checkpointSequence", "predecessorCheckpointSha256", "revocationGenerationHighWater",
    "revocationRootSha256", "revocationStatus", "rollbackFloorCheckpointSequence",
    "rollbackFloorEndpointGeneration", "rollbackFloorConsumerSequence",
    "validFromBoottime", "validUntilBoottime")
CHECKPOINT_FIELDS = ("payload", "authorityKeyId", "authorityKeySpkiSha256",
    "authoritySignatureBase64", "checkpointSha256")
_DOMAIN_FIELDS = ("authorityBootId", "timeNamespaceDevice", "timeNamespaceInode")
_WINDOW_FIELDS = ("configurationSha256", "signingKeyId", "bootIdBase64url",
    "timeNamespaceDevice", "timeNamespaceInode", "issuedAtBoottimeNs",
    "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId")
_LAUNCH_FIELDS = ("apiVersion", "bootIdBase64url", "timeNamespaceDevice",
    "timeNamespaceInode", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs",
    "invocationId", "services")


def _uint(value, bits=64, minimum=1):
    return p.integer(value, minimum=minimum, maximum=(1 << bits) - 1)


def _invocation(value):
    p.require(type(value) is str and re.fullmatch(r"[0-9a-f]{32}", value)
        and value != "0" * 32)


def _boot(value):
    boot = p.decoded(value["bootIdBase64url"], size=16)
    p.require(boot != bytes(16))
    for field in ("timeNamespaceDevice", "timeNamespaceInode"):
        _uint(value[field])
    return {"authorityBootId": list(boot),
        "timeNamespaceDevice": value["timeNamespaceDevice"],
        "timeNamespaceInode": value["timeNamespaceInode"]}


def pidfd_stat_sha256(value: dict) -> str:
    """Rust protocol::pidfd_stat_identity_sha256, over observed fstat values."""
    p.fields(value, PIDFD_FIELDS[:-1])
    parts = []
    for field, bits in zip(PIDFD_FIELDS[:-1], (64, 64, 32, 32, 32)):
        parts.append(_uint(value[field], bits, minimum=0).to_bytes(bits // 8, "big"))
    return p.framed(PIDFD_DOMAIN, parts)


def preparation(raw: bytes) -> dict:
    """Validate a literal observation's grammar/hashes, not its provenance."""
    value = p.fields(g.document(raw, MAX_PREPARATION), PREPARATION_FIELDS)
    p.require(value["apiVersion"] == PREPARATION_API and value["phase"] == "parked-pre-exec")
    p.digest(value["configurationSha256"])
    _boot(value); _invocation(value["invocationId"])
    issued, startup, lifetime = (p.ns(value[field]) for field in
        ("issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"))
    p.require(issued < startup <= lifetime and startup - issued <= 30_000_000_000)
    services = p.fields(value["services"], g.ROLES)
    pids, pidfds, executables, uids, gids = set(), set(), set(), set(), set()
    for role in g.ROLES:
        item = p.fields(services[role], SERVICE_FIELDS)
        p.digest(item["configurationSha256"])
        uid, gid = _uint(item["plannedUid"], 32), _uint(item["plannedGid"], 32)
        pid = p.integer(item["processId"], maximum=(1 << 31) - 1)
        _uint(item["startTimeTicks"])
        stat = p.fields(item["pidfdStat"], PIDFD_FIELDS)
        p.require(stat["sha256"] == pidfd_stat_sha256({name: stat[name] for name in PIDFD_FIELDS[:-1]}))
        _uint(stat["inode"])
        executable = p.fields(item["targetExecutable"], EXECUTABLE_FIELDS)
        for field in ("device", "inode"):
            _uint(executable[field])
        p.integer(executable["length"], maximum=256 * 1024 * 1024)
        for field in ("sha256", "imaSha256", "fsVeritySha256"):
            p.digest(executable[field])
        file_identity = (executable["device"], executable["inode"])
        p.require(pid not in pids and stat["inode"] not in pidfds and file_identity not in executables
            and uid not in uids and gid not in gids)
        pids.add(pid); pidfds.add(stat["inode"]); executables.add(file_identity)
        uids.add(uid); gids.add(gid)
    return value


def validate_identity(value: dict) -> dict:
    """Existing EndpointProcessIdentity shape and semantic hash only."""
    p.fields(value, IDENTITY_FIELDS)
    p.require(value["endpointRole"] in ENDPOINT_ROLES)
    for field in ("endpointUid", "endpointGid"):
        _uint(value[field], 32, minimum=0)
    p.integer(value["endpointPid"], maximum=(1 << 31) - 1)
    for field in ("endpointStartTimeTicks", "endpointPidfdInode", "executableDevice",
                  "executableInode", "executableLength"):
        _uint(value[field])
    for field in ("endpointPidfdStatSha256", "executableSha256", "executableImaSha256",
                  "executableFsVeritySha256", "identitySha256"):
        p.digest(value[field])
    p.require(value["identitySha256"] == p.framed(PROCESS_DOMAIN,
        (g.canonical([value[field] for field in IDENTITY_FIELDS[:-1]]),)))
    return copy.deepcopy(value)


def prepared_identity(observation: dict, *, role: str, endpoint_role: str,
                      launch: dict, configuration: dict, window: dict, now: int, adopted=False) -> dict:
    """Bind approved originals to intended exec; never assert completed exec.

    The caller verifies the signed driver window, independent authority history
    and observation provenance. No arbitrary dictionary becomes a live owner.
    The protocol role is independently selected; only DRS has a fixed role in
    the existing Rust signer constructor.
    """
    observed = preparation(g.canonical(observation))
    p.require(role in g.ROLES and endpoint_role in ENDPOINT_ROLES
        and (role != g.ROLES[0] or endpoint_role == "settlement-store"))
    p.fields(launch, _LAUNCH_FIELDS)
    p.require(type(adopted) is bool and launch["apiVersion"] == "catchplate.custodyFiveServiceLaunch/v" + ("7" if adopted else "6")
        and observed["configurationSha256"] == p.sha(g.canonical(launch)))
    specs = p.fields(launch["services"], g.ROLES)
    for name in g.ROLES:
        spec = p.fields(specs[name], ("executableSha256", "deliveryConfiguration"))
        g.c9._pin(spec["deliveryConfiguration"])
        p.digest(spec["executableSha256"])
        p.require(spec["executableSha256"] == observed["services"][name]["targetExecutable"]["sha256"]
            and spec["deliveryConfiguration"]["sha256"] == observed["services"][name]["configurationSha256"])
    cold = g.configuration(g.canonical(configuration), specs[role]["deliveryConfiguration"]["sha256"], role)
    p.fields(window, _WINDOW_FIELDS)
    for field in ("configurationSha256", "signingKeyId"):
        p.digest(window[field])
    p.require(_boot(window) == _boot(launch) == _boot(observed))
    _invocation(window["invocationId"])
    for field in ("invocationId", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"):
        p.require(observed[field] == launch[field] == window[field])
    issued, startup, lifetime = (p.ns(window[field]) for field in
        ("issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"))
    _uint(now)
    p.require(issued <= p.ns(observed["issuedAtBoottimeNs"]) <= now < startup <= lifetime
        and startup - issued <= 30_000_000_000)
    item = observed["services"][role]
    p.require((item["plannedUid"], item["plannedGid"]) == (cold["uid"], cold["gid"]))
    target, stat = item["targetExecutable"], item["pidfdStat"]
    identity = dict(zip(IDENTITY_FIELDS[:-1], (endpoint_role, cold["uid"], cold["gid"],
        item["processId"], item["startTimeTicks"], stat["inode"], stat["sha256"],
        target["device"], target["inode"], target["length"], target["sha256"],
        target["imaSha256"], target["fsVeritySha256"])))
    identity["identitySha256"] = p.framed(PROCESS_DOMAIN,
        (g.canonical([identity[field] for field in IDENTITY_FIELDS[:-1]]),))
    return validate_identity(identity)


def _deadline(value):
    p.fields(value, ("domain", "absoluteBoottimeNanos"))
    domain = p.fields(value["domain"], _DOMAIN_FIELDS)
    boot = domain["authorityBootId"]
    p.require(type(boot) is list and len(boot) == 16)
    for byte in boot:
        _uint(byte, 8, minimum=0)
    p.require(boot != [0] * 16)
    for field in _DOMAIN_FIELDS[1:]:
        _uint(domain[field])
    _uint(value["absoluteBoottimeNanos"])
    return value


def validate_payload_shape(value: dict) -> dict:
    """Existing Rust payload16 shape; no signature, currentness or approval."""
    p.fields(value, PAYLOAD_FIELDS)
    p.require(value["apiVersion"] == KEY_API and value["endpointRole"] in ENDPOINT_ROLES
        and value["revocationStatus"] == "authorized-and-not-revoked")
    for field in ("endpointProcessIdentitySha256", "authorizedSigningKeyId",
                  "authorizedSigningKeySpkiSha256", "predecessorCheckpointSha256", "revocationRootSha256"):
        p.digest(value[field])
    for field in ("exactEndpointGeneration", "checkpointSequence", "revocationGenerationHighWater",
                  "rollbackFloorCheckpointSequence", "rollbackFloorEndpointGeneration", "rollbackFloorConsumerSequence"):
        _uint(value[field])
    start, end = _deadline(value["validFromBoottime"]), _deadline(value["validUntilBoottime"])
    p.require(value["checkpointSequence"] >= value["rollbackFloorCheckpointSequence"]
        and value["exactEndpointGeneration"] >= value["rollbackFloorEndpointGeneration"]
        and start["domain"] == end["domain"]
        and start["absoluteBoottimeNanos"] < end["absoluteBoottimeNanos"])
    return copy.deepcopy(value)


def validate_payload(value: dict, *, identity: dict, window: dict, now: int) -> dict:
    checked = validate_payload_shape(value)
    intended = validate_identity(identity)
    p.fields(window, _WINDOW_FIELDS)
    domain = _boot(window)
    _invocation(window["invocationId"])
    for field in ("configurationSha256", "signingKeyId"):
        p.digest(window[field])
    issued, startup, lifetime = (p.ns(window[field]) for field in
        ("issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"))
    _uint(now)
    start, end = checked["validFromBoottime"], checked["validUntilBoottime"]
    p.require(checked["endpointRole"] == intended["endpointRole"]
        and checked["endpointProcessIdentitySha256"] == intended["identitySha256"]
        and start["domain"] == domain == end["domain"]
        and issued <= start["absoluteBoottimeNanos"] <= now < end["absoluteBoottimeNanos"] <= lifetime
        and now < startup <= lifetime and startup - issued <= 30_000_000_000)
    return checked


def _signature_payload(payload, authority_key_id, authority_key_spki_sha256):
    return g.canonical([validate_payload_shape(payload), p.digest(authority_key_id),
        p.digest(authority_key_spki_sha256)])


def signature_preimage(payload: dict, authority_key_id: str, authority_key_spki_sha256: str) -> bytes:
    """Rust's C3 framing, deliberately not the native signed-envelope domain."""
    raw = _signature_payload(payload, authority_key_id, authority_key_spki_sha256)
    return (b"catchplate-signature-v1\0" + len(KEY_DOMAIN).to_bytes(8, "big") + KEY_DOMAIN
        + len(raw).to_bytes(8, "big") + raw)


def envelope(payload: dict, authority_key_id: str, authority_key_spki_sha256: str,
             signature_base64: str) -> dict:
    """Encode supplied signature bytes; this is not a signing/verifying API."""
    raw = _signature_payload(payload, authority_key_id, authority_key_spki_sha256)
    p.decoded(signature_base64, size=64)
    value = {"payload": copy.deepcopy(payload), "authorityKeyId": authority_key_id,
        "authorityKeySpkiSha256": authority_key_spki_sha256, "authoritySignatureBase64": signature_base64,
        "checkpointSha256": p.framed(KEY_DOMAIN, (raw, signature_base64.encode("ascii")))}
    return validate_checkpoint(value)


def validate_checkpoint(value: dict) -> dict:
    """Existing signed envelope5 shape/hash; caller verifies the actual key."""
    p.fields(value, CHECKPOINT_FIELDS)
    raw = _signature_payload(value["payload"], value["authorityKeyId"], value["authorityKeySpkiSha256"])
    p.decoded(value["authoritySignatureBase64"], size=64)
    p.require(p.digest(value["checkpointSha256"]) == p.framed(KEY_DOMAIN,
        (raw, value["authoritySignatureBase64"].encode("ascii"))))
    return copy.deepcopy(value)
