from __future__ import annotations

from copy import deepcopy
from types import MappingProxyType
from typing import Any, Mapping


_active_role: str | None = None
_manifest_digest: str | None = None
_retained_descriptors: frozenset[int] = frozenset()
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


def activate(
    *,
    role: str,
    manifest_digest: str,
    retained_descriptors: frozenset[int],
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
    _active_role = role
    _manifest_digest = manifest_digest
    _retained_descriptors = retained_descriptors
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
