from __future__ import annotations

import fcntl
import os
import stat
from copy import deepcopy
from types import MappingProxyType
from typing import Any, Mapping


_active_role: str | None = None
_manifest_digest: str | None = None
_retained_descriptors: frozenset[int] = frozenset()
_bootstrap_control_identity: tuple = ()
_package_versions: Mapping[str, str] = MappingProxyType({})
_generation: Mapping[str, Any] = MappingProxyType({})
_native_stage_zero_handoff: Mapping[str, Any] = MappingProxyType({})
_listener_descriptor: int | None = None
_launch_identity_descriptors: Mapping[str, int] = MappingProxyType({})
_mutable_state_descriptors: Mapping[str, Mapping[str, Any]] = (
    MappingProxyType({})
)
_stage_zero_request: Mapping[str, Any] = MappingProxyType({})
_verified_artifact_package: Any | None = None
_artifact_package: Mapping[str, Any] = MappingProxyType({})
_artifact_trust_state: Mapping[str, Any] = MappingProxyType({})
_launch_assurance: Mapping[str, Any] = MappingProxyType({})


def _require_bootstrap_control_identity(identity: tuple) -> None:
    """Recheck immutable custody of already root-verified original control bytes."""
    if (
        type(identity) is not tuple or len(identity) != 10
        or any(type(value) is not int or value < 0 for value in identity[:9])
        or not 3 <= identity[0] <= 2**31 - 1
        or type(identity[9]) is not str or len(identity[9]) != 71
        or not identity[9].startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in identity[9][7:])
    ):
        raise RuntimeError("authority bootstrap control observation is invalid")
    descriptor = identity[0]
    if (
        os.environ.get("SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD") != str(descriptor)
        or os.environ.get("SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_PATH")
    ):
        raise RuntimeError("authority bootstrap control environment changed")
    try:
        metadata = os.fstat(descriptor)
        seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
    except OSError as exc:
        raise RuntimeError("authority bootstrap control descriptor is unavailable") from exc
    required_seals = 0x0001 | 0x0002 | 0x0004 | 0x0008
    actual = (
        descriptor, metadata.st_dev, metadata.st_ino, metadata.st_mode,
        metadata.st_uid, metadata.st_gid, metadata.st_size,
        metadata.st_mtime_ns, metadata.st_ctime_ns,
    )
    if (
        actual != identity[:9] or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 0 or metadata.st_uid != 0
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or not 2 <= metadata.st_size <= 64 * 1024 * 1024
        or seals & required_seals != required_seals
    ):
        raise RuntimeError("authority bootstrap control custody changed")


def activate(
    *,
    role: str,
    manifest_digest: str,
    retained_descriptors: frozenset[int],
    bootstrap_control_identity: tuple,
    package_versions: Mapping[str, str],
    generation: Mapping[str, Any],
    native_stage_zero_handoff: Mapping[str, Any],
    listener_descriptor: int,
    launch_identity_descriptors: Mapping[str, int],
    mutable_state_descriptors: Mapping[str, Mapping[str, Any]],
    stage_zero_request: Mapping[str, Any],
    verified_artifact_package: Any,
    artifact_package: Mapping[str, Any],
    artifact_trust_state: Mapping[str, Any],
    launch_assurance: Mapping[str, Any],
) -> None:
    global _active_role
    global _manifest_digest
    global _retained_descriptors
    global _bootstrap_control_identity
    global _package_versions
    global _generation
    global _native_stage_zero_handoff
    global _listener_descriptor
    global _launch_identity_descriptors
    global _mutable_state_descriptors
    global _stage_zero_request
    global _verified_artifact_package
    global _artifact_package
    global _artifact_trust_state
    global _launch_assurance
    local_assurance = {
        "schema": "serverware.authorityLaunchAssurance/v1",
        "trustMode": "trusted-host-local",
        "coLocated": True,
        "hardwareBacked": False,
        "nativeStageZero": False,
        "hsmBackedKeys": False,
        "teeVerified": False,
        "externalWitnessVerified": False,
    }
    if (
        _active_role is not None
        or not role
        or not manifest_digest.startswith("sha256:")
        or not retained_descriptors
        or any(descriptor < 3 for descriptor in retained_descriptors)
        or not isinstance(generation, Mapping)
        or not generation
        or not isinstance(native_stage_zero_handoff, Mapping)
        or listener_descriptor < 3
        or listener_descriptor not in retained_descriptors
        or set(launch_identity_descriptors)
        != {"privateKey", "certificate"}
        or any(
            not isinstance(descriptor, int)
            or isinstance(descriptor, bool)
            or descriptor < 3
            or descriptor not in retained_descriptors
            for descriptor in launch_identity_descriptors.values()
        )
        or not isinstance(mutable_state_descriptors, Mapping)
        or any(
            not isinstance(name, str)
            or not name
            or not isinstance(value, Mapping)
            or value.get("fd") not in retained_descriptors
            for name, value in mutable_state_descriptors.items()
        )
        or not isinstance(stage_zero_request, Mapping)
        or not stage_zero_request
        or verified_artifact_package is None
        or not isinstance(artifact_package, Mapping)
        or not artifact_package
        or not isinstance(artifact_trust_state, Mapping)
        or not artifact_trust_state
        or not isinstance(launch_assurance, Mapping)
        or (
            dict(launch_assurance) != local_assurance
            and (
                launch_assurance.get("schema")
                    != "serverware.authorityLaunchAssurance/v1"
                or launch_assurance.get("trustMode")
                    not in {"external-production", "tee-hardware"}
                or launch_assurance.get("nativeStageZero") is not True
            )
        )
        or (
            dict(launch_assurance) == local_assurance
            and native_stage_zero_handoff
        )
        or (
            dict(launch_assurance) != local_assurance
            and not native_stage_zero_handoff
        )
    ):
        raise RuntimeError("authority measured launch activation is invalid")
    _require_bootstrap_control_identity(bootstrap_control_identity)
    control = stage_zero_request.get("bootstrapControl")
    if (
        not isinstance(control, Mapping)
        or set(control) != {"name", "fd", "envelopeSchema", "maximumBytes"}
        or control["name"] != "SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD"
        or type(control["fd"]) is not int
        or control["fd"] != bootstrap_control_identity[0]
        or control["envelopeSchema"] != "serverware.signedPolicyAuthorityLaunchManifest/v5"
        or type(control["maximumBytes"]) is not int
        or control["maximumBytes"] != 64 * 1024 * 1024
        or control["fd"] not in retained_descriptors
    ):
        raise RuntimeError("authority bootstrap control is not the admitted request descriptor")
    other_descriptors = {
        listener_descriptor,
        *launch_identity_descriptors.values(),
        *(value["fd"] for value in mutable_state_descriptors.values()),
        stage_zero_request["stageZero"]["fd"],
        stage_zero_request["process"]["pidfd"]["fd"],
        *(value["fd"] for value in stage_zero_request["retainedFiles"]),
        *(value["fd"] for value in stage_zero_request["retainedDirectories"]),
        *(value["fd"] for value in stage_zero_request["credentials"]),
    }
    if control["fd"] in other_descriptors:
        raise RuntimeError("authority bootstrap control aliases another descriptor")
    # Non-preserved stage-zero declarations still participate in numeric
    # collision rejection, but may already be closed in this process.
    inherited_descriptors = {
        *stage_zero_request["execution"]["preserveFds"],
        listener_descriptor,
        *launch_identity_descriptors.values(),
        *(value["fd"] for value in stage_zero_request["credentials"]),
    }
    inherited_descriptors.discard(control["fd"])
    for descriptor in inherited_descriptors:
        metadata = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) == bootstrap_control_identity[1:3]:
            raise RuntimeError("authority bootstrap control inode aliases another descriptor")
    _active_role = role
    _manifest_digest = manifest_digest
    _retained_descriptors = retained_descriptors
    # The raw SHA is an observation after root verification, not a declaration
    # accepted from the signed request. Seals and the exact stamp protect it.
    _bootstrap_control_identity = bootstrap_control_identity
    _package_versions = MappingProxyType(dict(package_versions))
    _generation = MappingProxyType(deepcopy(dict(generation)))
    _native_stage_zero_handoff = MappingProxyType(
        deepcopy(dict(native_stage_zero_handoff))
    )
    _listener_descriptor = listener_descriptor
    _launch_identity_descriptors = MappingProxyType(
        dict(launch_identity_descriptors)
    )
    _mutable_state_descriptors = MappingProxyType(
        {
            str(name): MappingProxyType(deepcopy(dict(value)))
            for name, value in mutable_state_descriptors.items()
        }
    )
    _stage_zero_request = MappingProxyType(
        deepcopy(dict(stage_zero_request))
    )
    _verified_artifact_package = verified_artifact_package
    _artifact_package = MappingProxyType(
        deepcopy(dict(artifact_package))
    )
    _artifact_trust_state = MappingProxyType(
        deepcopy(dict(artifact_trust_state))
    )
    _launch_assurance = MappingProxyType(
        deepcopy(dict(launch_assurance))
    )


def require_active(role: str) -> str:
    if _active_role != role or _manifest_digest is None:
        raise RuntimeError(
            "authority service was not entered by the measured launcher"
        )
    _require_bootstrap_control_identity(_bootstrap_control_identity)
    return _manifest_digest


def retained_descriptors() -> frozenset[int]:
    if _active_role is None:
        raise RuntimeError("authority measured launch is inactive")
    return _retained_descriptors


def package_versions() -> Mapping[str, str]:
    if _active_role is None:
        raise RuntimeError("authority measured launch is inactive")
    return _package_versions


def generation() -> Mapping[str, Any]:
    if _active_role is None:
        raise RuntimeError("authority measured launch is inactive")
    return MappingProxyType(deepcopy(dict(_generation)))


def native_stage_zero_handoff() -> Mapping[str, Any]:
    if _active_role is None:
        raise RuntimeError("authority measured launch is inactive")
    return MappingProxyType(
        deepcopy(dict(_native_stage_zero_handoff))
    )


def listener_descriptor() -> int:
    if _active_role is None or _listener_descriptor is None:
        raise RuntimeError("authority measured launch is inactive")
    return _listener_descriptor


def launch_identity_descriptors() -> Mapping[str, int]:
    if _active_role is None:
        raise RuntimeError("authority measured launch is inactive")
    return _launch_identity_descriptors


def mutable_state_descriptors() -> Mapping[str, Mapping[str, Any]]:
    if _active_role is None:
        raise RuntimeError("authority measured launch is inactive")
    return MappingProxyType(
        {
            name: MappingProxyType(deepcopy(dict(value)))
            for name, value in _mutable_state_descriptors.items()
        }
    )


def stage_zero_request() -> Mapping[str, Any]:
    if _active_role is None:
        raise RuntimeError("authority measured launch is inactive")
    return MappingProxyType(deepcopy(dict(_stage_zero_request)))


def verified_artifact_package() -> Any:
    if _active_role is None or _verified_artifact_package is None:
        raise RuntimeError("authority measured launch is inactive")
    return _verified_artifact_package


def artifact_package() -> Mapping[str, Any]:
    if _active_role is None:
        raise RuntimeError("authority measured launch is inactive")
    return MappingProxyType(deepcopy(dict(_artifact_package)))


def artifact_trust_state() -> Mapping[str, Any]:
    if _active_role is None:
        raise RuntimeError("authority measured launch is inactive")
    return MappingProxyType(deepcopy(dict(_artifact_trust_state)))


def launch_assurance() -> Mapping[str, Any]:
    if _active_role is None:
        raise RuntimeError("authority measured launch is inactive")
    return MappingProxyType(deepcopy(dict(_launch_assurance)))
