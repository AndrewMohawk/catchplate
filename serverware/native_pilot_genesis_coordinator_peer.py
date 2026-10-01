"""Cold coordinator peer data, not process ownership or independent approval.

Only ParkedGenesisController produces this observation from retained kernel
handles. Parsing public bytes cannot establish that provenance. Final UID/GID
come from the approved C9 configuration; labels remain explicit policy inputs.
"""
from __future__ import annotations

import copy

from serverware import custody_generation_grants as codec
from serverware import native_pilot_bridge_preparation as binding
from serverware import native_pilot_genesis_parent_authority as authority
from serverware import native_pilot_peer_preparation as wire

p = codec.p
API = "serverware.nativePilotGenesisCoordinatorPeerPreparation/v1"
ROLE = "publication-genesis-coordinator"
MAX_BYTES = wire.MAX_BYTES


def shape(raw):
    value = p.fields(codec.document(raw, MAX_BYTES), wire.FIELDS)
    p.require(value["apiVersion"] == API and value["ownerKind"] == ROLE
        and value["profile"] == wire.PROFILE and value["phase"] == "parked-pre-exec")
    for field in ("configurationSha256", "sourceOriginalSha256"):
        p.require(p.digest(value[field]) != p.sha(b""))
    p.require(p.decoded(value["bootIdBase64url"], size=16) != bytes(16))
    p.integer(value["timeNamespaceDevice"], minimum=0, maximum=p.MAX_U64)
    p.integer(value["timeNamespaceInode"], maximum=p.MAX_U64)
    issued, observed, startup, lifetime = (p.ns(value[field]) for field in
        ("issuedAtBoottimeNs", "observedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"))
    p.require(issued <= observed < startup <= lifetime and startup - issued <= 30_000_000_000)
    authority._invocation(value["invocationId"])
    row = p.fields(p.fields(value["peers"], (ROLE,))[ROLE], wire.PEER_FIELDS)
    p.integer(row["processId"], minimum=2, maximum=(1 << 31) - 1)
    p.integer(row["startTimeTicks"], maximum=p.MAX_U64)
    fd = p.fields(row["pidfd"], ("device", "inode"))
    p.integer(fd["device"], minimum=0, maximum=p.MAX_U64)
    p.integer(fd["inode"], maximum=p.MAX_U64)
    wire.executable(row["targetExecutable"])
    wire.cgroup(row["cgroup"])
    return copy.deepcopy(value)


def validate(raw, *, observation_raw, configuration_raw, precreation_raw,
             delivery_configuration_raw, boot, now_boottime_ns):
    context = authority.validate_precreation(precreation_raw,
        configuration_raw=configuration_raw, delivery_configuration_raw=delivery_configuration_raw,
        boot=boot, now_boottime_ns=now_boottime_ns)
    observation = authority.validate_observation(observation_raw,
        configuration_raw=configuration_raw, precreation_raw=precreation_raw, context=context)
    value = shape(raw)
    p.require(value["configurationSha256"] == p.sha(configuration_raw)
        and value["sourceOriginalSha256"] == p.sha(observation_raw)
        and p.ns(value["observedAtBoottimeNs"]) <= now_boottime_ns)
    for field in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode",
                  "issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId"):
        p.require(value[field] == context["window"][field])
    row = value["peers"][ROLE]
    p.require(row["processId"] == observation["processId"]
        and row["startTimeTicks"] == observation["startTimeTicks"]
        and row["pidfd"] == {"device": observation["pidfdDevice"], "inode": observation["pidfdInode"]}
        and row["targetExecutable"] == observation["executable"])
    return value


def expected_peer(raw, *, approved, observation_raw, configuration_raw, precreation_raw,
                  delivery_configuration_raw, boot, now_boottime_ns):
    """Check a complete approved peer against the genuine owner's public data.

    Does not generate approval, labels, a new process identity or a new window.
    The independently pinned input must contain both these exact originals and
    the final expected peer; native admission still verifies the live peer.
    """
    value = validate(raw, observation_raw=observation_raw, configuration_raw=configuration_raw,
        precreation_raw=precreation_raw, delivery_configuration_raw=delivery_configuration_raw,
        boot=boot, now_boottime_ns=now_boottime_ns)
    _, cold = authority.validate_configuration(configuration_raw, delivery_configuration_raw)
    binding._peer(approved, value["peers"][ROLE], {name: cold[name] for name in ("uid", "gid")})
    for field in ("processIdentitySha256", "executableSha256", "cgroupPathSha256",
                  "securityLabelSha256", "configurationGenerationSha256"):
        p.require(p.digest(approved[field]) != p.sha(b""))
    return copy.deepcopy(approved)
