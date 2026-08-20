from __future__ import annotations

import base64
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import select
import socket
import stat
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from serverware import authority_launch_guard


authority_launch_guard.require_active("witness")

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from serverware import authority_contract
from serverware import authority_artifact_spec
from serverware import authority_stage_zero_contract
from serverware import authority_transition_registry


CONFIG_SCHEMA = "serverware.policyAuthorityReplayWitnessConfiguration/v2"
SIGNED_CONFIG_SCHEMA = (
    "serverware.signedPolicyAuthorityReplayWitnessConfiguration/v2"
)
REQUEST_SCHEMA = "serverware.policyAuthorityReplayWitnessRequest/v2"
WITNESS_RECEIPT_SCHEMA = (
    "serverware.policyAuthorityReplayWitnessReceipt/v2"
)
WITNESS_STATE_RECORD_SCHEMA = (
    "serverware.policyAuthorityReplayWitnessStateRecord/v1"
)
GENERATION_CONTEXT_SCHEMA = (
    "serverware.authorityGenerationLaunchContext/v1"
)
LAUNCH_KEY_ID_DOMAIN = (
    "serverware.authorityLaunchPublicKey/v1"
)
TRANSITION_ID_DOMAIN = (
    "serverware.policyAuthorityCredentialReleaseTransition/v1"
)
ENVELOPE_ID_DOMAIN = (
    "serverware.policyAuthorityReplayWitnessEnvelope/v2"
)
MAX_CONFIG_BYTES = authority_contract.MAX_REQUEST_BYTES
MAX_MESSAGE_BYTES = authority_contract.MAX_REQUEST_BYTES
MAX_STATE_BYTES = 1024 * 1024 * 1024
MAX_STATE_RECORD_BYTES = MAX_MESSAGE_BYTES * 4
MAX_STATE_RECORDS = 65536
RENAME_NOREPLACE = 1
STATE_RECORD_PROTOCOL = (
    "append-canonical-record-fdatasync-renameat2-noreplace-fsyncdir-v1"
)
ALLOWED_PHASES = {
    "reserve",
    "commit",
    "abort",
    "reconcile",
    "webauthn-trust-publish",
    "credential-release",
    "credential-release-consume",
}
TERMINAL_PHASES = {
    "commit",
    "abort",
    "reconcile",
    "credential-release-consume",
}
RESERVATION_PHASES = {
    "reserve",
    "webauthn-trust-publish",
    "credential-release",
}


class WitnessError(RuntimeError):
    pass


class WitnessConflict(WitnessError):
    pass


_LIBC = ctypes.CDLL(None, use_errno=True)
_RENAMEAT2 = getattr(_LIBC, "renameat2", None)
if _RENAMEAT2 is not None:
    _RENAMEAT2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    _RENAMEAT2.restype = ctypes.c_int


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _canonical_timestamp_now() -> str:
    return datetime.now(timezone.utc).replace(
        microsecond=0
    ).strftime("%Y-%m-%dT%H:%M:%SZ")


def _rename_noreplace(
    directory_descriptor: int,
    temporary_name: str,
    record_name: str,
) -> None:
    if _RENAMEAT2 is None:
        raise WitnessError("witness requires libc renameat2")
    result = _RENAMEAT2(
        directory_descriptor,
        temporary_name.encode("ascii"),
        directory_descriptor,
        record_name.encode("ascii"),
        RENAME_NOREPLACE,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        if error_number == errno.EEXIST:
            raise WitnessConflict("witness state record already exists")
        raise WitnessError(
            f"witness renameat2 failed with errno {error_number}"
        )


def _state_record_name(sequence: int, canonical_record: bytes) -> str:
    digest = _domain_digest(
        WITNESS_STATE_RECORD_SCHEMA,
        canonical_record,
    )
    return f"record-{sequence:020d}-{digest[7:]}.json"


def _parse_state_record_name(name: str) -> tuple[int, str]:
    if (
        len(name) != 97
        or not name.startswith("record-")
        or not name.endswith(".json")
        or name[27] != "-"
        or not name[7:27].isdigit()
        or any(
            character not in "0123456789abcdef"
            for character in name[28:92]
        )
    ):
        raise WitnessError("witness state directory contains an unknown entry")
    return int(name[7:27], 10), name[28:92]


def _domain_digest(domain: str, *frames: bytes) -> str:
    digest = hashlib.sha256()
    encoded_domain = domain.encode("ascii")
    digest.update(len(encoded_domain).to_bytes(8, "big"))
    digest.update(encoded_domain)
    for frame in frames:
        digest.update(len(frame).to_bytes(8, "big"))
        digest.update(frame)
    return "sha256:" + digest.hexdigest()


def _protocol_digest(domain: str, *frames: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(domain.encode("ascii"))
    digest.update(b"\0")
    for frame in frames:
        digest.update(len(frame).to_bytes(8, "big"))
        digest.update(frame)
    return "sha256:" + digest.hexdigest()


def _is_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and all(
            character in "0123456789abcdef"
            for character in value[7:]
        )
    )


def _request_envelope_id(request: Mapping[str, Any]) -> str:
    material = {
        "phase": request.get("phase"),
        "operation": request.get("operation"),
        "requestDigest": request.get("requestDigest"),
        "capabilityId": request.get("capabilityId"),
        "resultDigest": request.get("resultDigest"),
        "predecessorReceiptDigest":
            request.get("predecessorReceiptDigest"),
        "generationSequence": request.get("generationSequence"),
        "generationDigest": request.get("generationDigest"),
    }
    return _protocol_digest(
        ENVELOPE_ID_DOMAIN,
        _canonical(material),
    )


def _boot_identity_digest() -> str:
    try:
        with open(
            "/proc/sys/kernel/random/boot_id",
            "r",
            encoding="ascii",
        ) as handle:
            boot_id = handle.read(128).strip().lower()
    except OSError as exc:
        raise WitnessError("Linux boot identity is unavailable") from exc
    if (
        len(boot_id) != 36
        or any(
            character not in "0123456789abcdef-"
            for character in boot_id
        )
    ):
        raise WitnessError("Linux boot identity is malformed")
    return _domain_digest(
        "serverware.policyAuthorityBootIdentity/v1",
        boot_id.encode("ascii"),
    )


def _process_identity(pid: int) -> tuple[int, int, str]:
    try:
        with open(
            f"/proc/{pid}/stat",
            "r",
            encoding="ascii",
        ) as handle:
            stat_value = handle.read(16 * 1024)
        closing = stat_value.rfind(")")
        fields = stat_value[closing + 2 :].split()
        start_time_ticks = int(fields[19], 10)
        pid_namespace_inode = os.stat(
            f"/proc/{pid}/ns/pid",
            follow_symlinks=True,
        ).st_ino
    except (OSError, ValueError, IndexError) as exc:
        raise WitnessError(
            "credential-release peer identity is unavailable"
        ) from exc
    if (
        closing < 1
        or start_time_ticks <= 0
        or pid_namespace_inode <= 0
    ):
        raise WitnessError(
            "credential-release peer identity is invalid"
        )
    material = {
        "pid": pid,
        "startTimeTicks": start_time_ticks,
        "pidNamespaceInode": pid_namespace_inode,
    }
    return (
        start_time_ticks,
        pid_namespace_inode,
        _domain_digest(
            "serverware.policyAuthorityProcessIdentity/v1",
            _canonical(material),
        ),
    )


def _b64url_decode(value: object, *, size: int) -> bytes:
    if not isinstance(value, str):
        raise WitnessError("witness base64url value is invalid")
    try:
        decoded = base64.urlsafe_b64decode(
            value + "=" * (-len(value) % 4)
        )
    except (ValueError, TypeError) as exc:
        raise WitnessError("witness base64url value is invalid") from exc
    if (
        len(decoded) != size
        or _b64url_encode(decoded) != value
    ):
        raise WitnessError("witness base64url value has the wrong size")
    return decoded


def _b64url_decode_bounded(
    value: object,
    *,
    maximum: int,
) -> bytes:
    if not isinstance(value, str):
        raise WitnessError("witness base64url value is invalid")
    try:
        decoded = base64.urlsafe_b64decode(
            value + "=" * (-len(value) % 4)
        )
    except (ValueError, TypeError) as exc:
        raise WitnessError("witness base64url value is invalid") from exc
    if (
        len(decoded) > maximum
        or _b64url_encode(decoded) != value
    ):
        raise WitnessError("witness base64url value is oversized")
    return decoded


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _validate_generation_value(
    value: object,
    *,
    require_current_validity: bool,
) -> dict[str, Any]:
    required = {
        "schema",
        "statement",
        "digest",
        "sequence",
        "predecessorDigest",
        "minimumRollbackSequence",
        "validFrom",
        "validUntil",
        "packageDigest",
        "artifactBundleDigest",
        "operationManifestDigest",
        "roleManifestDigests",
        "configurationDigests",
        "trustMode",
        "externalHighWater",
        "launchIdentityIssuer",
        "artifactVerificationReceiptDigest",
        "provisioningReceiptDigest",
        "provisioningPlanDigest",
        "stageZeroRequestDigest",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise WitnessError("witness generation is not closed")
    generation = dict(value)
    statement = generation.get("statement")
    try:
        authority_artifact_spec.validate_generation_statement(statement)
        generation_digest = (
            authority_artifact_spec.generation_statement_digest(
                statement
            )
        )
    except authority_artifact_spec.ArtifactContractError as exc:
        raise WitnessError(
            "witness generation statement is invalid"
        ) from exc
    sequence = generation.get("sequence")
    minimum_rollback = generation.get("minimumRollbackSequence")
    high_water = generation.get("externalHighWater")
    issuer = generation.get("launchIdentityIssuer")
    role_digests = generation.get("roleManifestDigests")
    configuration_digests = generation.get("configurationDigests")
    try:
        valid_from = _parse_canonical_timestamp(
            generation.get("validFrom"),
            name="generation validFrom",
        )
        valid_until = _parse_canonical_timestamp(
            generation.get("validUntil"),
            name="generation validUntil",
        )
    except WitnessError:
        raise
    if (
        generation.get("schema") != GENERATION_CONTEXT_SCHEMA
        or not isinstance(statement, dict)
        or generation.get("digest") != generation_digest
        or not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or sequence < 0
        or valid_until <= valid_from
        or (
            require_current_validity
            and not valid_from
            <= datetime.now(timezone.utc)
            < valid_until
        )
        or not isinstance(minimum_rollback, int)
        or isinstance(minimum_rollback, bool)
        or not 0 <= minimum_rollback <= sequence
        or generation.get("sequence") != statement["sequence"]
        or generation.get("predecessorDigest")
            != statement["predecessorDigest"]
        or generation.get("minimumRollbackSequence")
            != statement["minimumRollbackSequence"]
        or generation.get("validFrom") != statement["validFrom"]
        or generation.get("validUntil") != statement["validUntil"]
        or generation.get("artifactBundleDigest")
            != statement["artifactBundleDigest"]
        or generation.get("operationManifestDigest")
            != statement["operationManifestDigest"]
        or generation.get("configurationDigests")
            != statement["configurationDigests"]
        or generation.get("trustMode")
            != statement["trustMode"]["mode"]
        or not isinstance(role_digests, dict)
        or sorted(role_digests) != list(role_digests)
        or sorted(role_digests.values())
            != statement["roleManifestDigests"]
        or not isinstance(configuration_digests, list)
        or configuration_digests
            != sorted(set(configuration_digests))
        or not isinstance(high_water, dict)
        or set(high_water)
            != {
                "sequence",
                "generationDigest",
                "packageDigest",
                "minimumRollbackSequence",
                "witnessCheckpointDigest",
                "witnessRootDigest",
                "witnessTreeSize",
            }
        or high_water.get("sequence") != sequence
        or high_water.get("generationDigest") != generation_digest
        or high_water.get("packageDigest")
            != generation.get("packageDigest")
        or high_water.get("minimumRollbackSequence")
            != minimum_rollback
        or high_water.get("witnessTreeSize") != sequence + 1
        or not isinstance(issuer, dict)
        or set(issuer)
            != {
                "keyId",
                "publicKeyBase64Url",
                "authorizationDigest",
            }
        or not isinstance(issuer.get("keyId"), str)
        or not issuer["keyId"]
        or any(
            not _is_digest(generation.get(name))
            for name in {
                "digest",
                "packageDigest",
                "artifactBundleDigest",
                "operationManifestDigest",
                "artifactVerificationReceiptDigest",
                "provisioningReceiptDigest",
                "provisioningPlanDigest",
                "stageZeroRequestDigest",
            }
        )
        or any(
            not _is_digest(high_water.get(name))
            for name in {
                "generationDigest",
                "packageDigest",
                "witnessCheckpointDigest",
                "witnessRootDigest",
            }
        )
        or not _is_digest(issuer.get("authorizationDigest"))
    ):
        raise WitnessError("witness generation binding is invalid")
    _b64url_decode(
        issuer.get("publicKeyBase64Url"),
        size=32,
    )
    try:
        checkpoint_digest = (
            authority_artifact_spec.witness_checkpoint_digest(
                statement["witnessCheckpoint"]
            )
        )
    except authority_artifact_spec.ArtifactContractError as exc:
        raise WitnessError(
            "witness generation checkpoint is invalid"
        ) from exc
    if checkpoint_digest != high_water["witnessCheckpointDigest"]:
        raise WitnessError("witness generation high-water changed")
    return generation


def _parse_canonical_timestamp(
    value: object,
    *,
    name: str,
) -> datetime:
    if (
        not isinstance(value, str)
        or len(value) > 64
        or not value.endswith("Z")
    ):
        raise WitnessError(f"{name} is not canonical UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise WitnessError(f"{name} is not RFC3339") from exc
    if (
        parsed.tzinfo != timezone.utc
        or parsed.microsecond != 0
        or value != parsed.strftime("%Y-%m-%dT%H:%M:%SZ")
    ):
        raise WitnessError(f"{name} is not canonical RFC3339")
    return parsed


def _read_descriptor(name: str, maximum: int) -> bytes:
    descriptor_value = os.environ.get(name + "_FD", "")
    if not descriptor_value or os.environ.get(name + "_PATH"):
        raise WitnessError(f"{name} must be descriptor-delivered")
    try:
        descriptor = int(descriptor_value)
    except ValueError as exc:
        raise WitnessError(f"{name}_FD is invalid") from exc
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise WitnessError(f"{name} is mutable")
    value = os.pread(descriptor, maximum + 1, 0)
    metadata_after = os.fstat(descriptor)
    if (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
    ) != (
        metadata_after.st_dev,
        metadata_after.st_ino,
        metadata_after.st_size,
        metadata_after.st_mtime_ns,
    ):
        raise WitnessError(f"{name} changed while read")
    if len(value) > maximum:
        raise WitnessError(f"{name} exceeds its bound")
    return value


def _load_public_key(value: bytes) -> Ed25519PublicKey:
    try:
        if len(value) == 32:
            return Ed25519PublicKey.from_public_bytes(value)
        key = serialization.load_pem_public_key(value)
    except (ValueError, TypeError) as exc:
        raise WitnessError("witness public key is invalid") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise WitnessError("witness public key is not Ed25519")
    return key


def _load_private_key(value: bytes) -> Ed25519PrivateKey:
    try:
        if len(value) == 32:
            return Ed25519PrivateKey.from_private_bytes(value)
        key = serialization.load_pem_private_key(
            value,
            password=None,
        )
    except (ValueError, TypeError) as exc:
        raise WitnessError("witness private key is invalid") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise WitnessError("witness private key is not Ed25519")
    return key


def _public_key_digest(key: Ed25519PublicKey) -> str:
    return "sha256:" + hashlib.sha256(
        key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).hexdigest()


def _load_configuration() -> tuple[dict[str, Any], str]:
    root_key = _load_public_key(
        _read_descriptor(
            "SERVERWARE_POLICY_AUTHORITY_WITNESS_ROOT_PUBLIC_KEY",
            64 * 1024,
        )
    )
    config_value = _read_descriptor(
        "SERVERWARE_POLICY_AUTHORITY_WITNESS_CONFIG",
        MAX_CONFIG_BYTES,
    )
    try:
        envelope = json.loads(config_value)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WitnessError("witness configuration is not JSON") from exc
    if (
        not isinstance(envelope, dict)
        or set(envelope) != {"schema", "payload", "signature"}
        or envelope.get("schema") != SIGNED_CONFIG_SCHEMA
        or not isinstance(envelope.get("payload"), dict)
    ):
        raise WitnessError("witness configuration is not closed")
    payload = dict(envelope["payload"])
    payload_bytes = _canonical(payload)
    try:
        root_key.verify(
            _b64url_decode(envelope["signature"], size=64),
            _domain_digest(
                SIGNED_CONFIG_SCHEMA,
                payload_bytes,
            ).encode("ascii"),
        )
    except InvalidSignature as exc:
        raise WitnessError(
            "witness configuration signature is invalid"
        ) from exc
    required = {
        "schema",
        "sourceRevision",
        "launchManifestDigest",
        "generation",
        "operationManifestDigest",
        "authorityConfigurationDigests",
        "identityDigest",
        "signingSpkiDigest",
        "verifierSigningPublicKeyBase64Url",
        "serviceUid",
        "serviceGid",
        "peerUid",
        "peerGid",
        "socketPath",
        "socketActivationName",
        "listenBacklog",
        "workers",
        "maximumInFlight",
        "requestTimeoutSeconds",
        "maximumRequestAgeNs",
        "releaseConsumerPeers",
        "minimumSequence",
        "minimumReceiptDigest",
    }
    launch_generation = dict(authority_launch_guard.generation())
    payload_generation = _validate_generation_value(
        payload.get("generation"),
        require_current_validity=True,
    )
    payload["generation"] = payload_generation
    digest = _domain_digest(CONFIG_SCHEMA, payload_bytes)
    if (
        set(payload) != required
        or payload.get("schema") != CONFIG_SCHEMA
        or payload.get("sourceRevision")
        != authority_contract.SOURCE_REVISION
        or payload.get("launchManifestDigest")
        != authority_launch_guard.require_active("witness")
        or _canonical(payload["generation"])
            != _canonical(launch_generation)
        or payload["generation"].get("schema")
            != GENERATION_CONTEXT_SCHEMA
        or not _is_digest(
            payload["generation"].get("digest")
        )
        or payload.get("operationManifestDigest")
            != authority_contract.OPERATION_MANIFEST_DIGEST
        or payload.get("operationManifestDigest")
            != payload["generation"].get("operationManifestDigest")
        or not isinstance(
            payload.get("authorityConfigurationDigests"), list
        )
        or payload["authorityConfigurationDigests"]
            != payload["generation"]["configurationDigests"]
        or not Path(str(payload.get("socketPath", ""))).is_absolute()
        or payload.get("socketPath")
            != "/run/serverware/authority-witness/authority.sock"
        or payload.get("socketActivationName")
            != "serverware-authority-witness"
        or os.getuid() != int(payload.get("serviceUid", -1))
        or os.getgid() != int(payload.get("serviceGid", -1))
        or not isinstance(payload.get("minimumSequence"), int)
        or not isinstance(payload.get("releaseConsumerPeers"), dict)
        or set(payload["releaseConsumerPeers"])
            != {
                "verifier",
                "planner",
                "planner-writer",
                "issuer",
                "executor",
            }
        or any(
            not isinstance(identity, dict)
            or set(identity) != {"uid", "gid"}
            or not isinstance(identity.get("uid"), int)
            or not isinstance(identity.get("gid"), int)
            or min(identity["uid"], identity["gid"]) < 0
            for identity in payload["releaseConsumerPeers"].values()
        )
        or isinstance(payload.get("minimumSequence"), bool)
        or int(payload["minimumSequence"]) < 0
        or (
            int(payload["minimumSequence"]) == 0
            and payload.get("minimumReceiptDigest") is not None
        )
        or (
            int(payload["minimumSequence"]) > 0
            and (
                not isinstance(
                    payload.get("minimumReceiptDigest"), str
                )
                or not payload["minimumReceiptDigest"].startswith(
                    "sha256:"
                )
            )
        )
    ):
        raise WitnessError("witness configuration binding changed")
    return payload, digest


def _peer_identity(connection: socket.socket) -> tuple[int, int, int]:
    if not hasattr(socket, "SO_PEERCRED"):
        raise WitnessError("witness requires Linux peer credentials")
    value = connection.getsockopt(
        socket.SOL_SOCKET,
        socket.SO_PEERCRED,
        struct.calcsize("3i"),
    )
    pid, uid, gid = struct.unpack("3i", value)
    if pid <= 0:
        raise WitnessError("witness peer PID is invalid")
    return pid, uid, gid


def _capture_peer_process(pid: int) -> dict[str, int | str]:
    if not hasattr(os, "pidfd_open"):
        raise WitnessError("witness requires Linux pidfd_open")
    try:
        pidfd = os.pidfd_open(pid, 0)
        os.set_inheritable(pidfd, False)
        start_ticks, namespace_inode, identity_digest = (
            _process_identity(pid)
        )
        metadata = os.fstat(pidfd)
        repeated_start, repeated_namespace, repeated_digest = (
            _process_identity(pid)
        )
    except Exception:
        if "pidfd" in locals():
            os.close(pidfd)
        raise
    if (
        start_ticks != repeated_start
        or namespace_inode != repeated_namespace
        or identity_digest != repeated_digest
        or metadata.st_ino <= 0
    ):
        os.close(pidfd)
        raise WitnessConflict("witness peer changed during pidfd capture")
    return {
        "pidfd": pidfd,
        "pid": pid,
        "startTicks": start_ticks,
        "pidNamespaceInode": namespace_inode,
        "processIdentityDigest": identity_digest,
        "pidfdDevice": metadata.st_dev,
        "pidfdInode": metadata.st_ino,
        "bootIdDigest": _boot_identity_digest(),
    }


def _require_live_peer(peer: Mapping[str, int | str]) -> None:
    poller = select.poll()
    poller.register(
        int(peer["pidfd"]),
        select.POLLIN | select.POLLHUP | select.POLLERR,
    )
    if poller.poll(0):
        raise WitnessConflict("credential-release peer process exited")
    start_ticks, namespace_inode, identity_digest = _process_identity(
        int(peer["pid"])
    )
    if (
        start_ticks != peer["startTicks"]
        or namespace_inode != peer["pidNamespaceInode"]
        or identity_digest != peer["processIdentityDigest"]
        or _boot_identity_digest() != peer["bootIdDigest"]
    ):
        raise WitnessConflict("credential-release peer identity changed")


def _recv_exact(connection: socket.socket, length: int) -> bytes:
    value = bytearray()
    while len(value) < length:
        chunk = connection.recv(length - len(value))
        if not chunk:
            raise WitnessError("witness request is incomplete")
        value.extend(chunk)
    return bytes(value)


def _receive(
    connection: socket.socket,
) -> tuple[dict[str, Any], bytes]:
    header = _recv_exact(connection, 8)
    length = int.from_bytes(header, "big")
    if not 2 <= length <= MAX_MESSAGE_BYTES:
        raise WitnessError("witness request size is invalid")
    try:
        canonical_request = _recv_exact(connection, length)
        request = json.loads(canonical_request)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WitnessError("witness request is not JSON") from exc
    if not isinstance(request, dict):
        raise WitnessError("witness request is not an object")
    if canonical_request != _canonical(request):
        raise WitnessError("witness request is not canonical")
    return request, canonical_request


def _send(connection: socket.socket, value: Mapping[str, Any]) -> None:
    payload = _canonical(dict(value))
    _send_canonical(connection, payload)


def _send_canonical(
    connection: socket.socket,
    payload: bytes,
) -> None:
    if len(payload) > MAX_MESSAGE_BYTES:
        raise WitnessError("witness response is oversized")
    connection.sendall(len(payload).to_bytes(8, "big") + payload)


class WitnessStateStore:
    def __init__(
        self,
        *,
        configuration: dict[str, Any],
        configuration_digest: str,
    ) -> None:
        self.configuration = configuration
        self.configuration_digest = configuration_digest
        self.verifier_key = Ed25519PublicKey.from_public_bytes(
            _b64url_decode(
                configuration[
                    "verifierSigningPublicKeyBase64Url"
                ],
                size=32,
            )
        )
        self.signing_key = _load_private_key(
            _read_descriptor(
                "SERVERWARE_POLICY_AUTHORITY_WITNESS_SIGNING_KEY",
                64 * 1024,
            )
        )
        if _public_key_digest(self.signing_key.public_key()) != (
            configuration["signingSpkiDigest"]
        ):
            raise WitnessError(
                "witness signing key does not match its identity"
            )
        state_descriptors = dict(
            authority_launch_guard.mutable_state_descriptors()
        )
        if len(state_descriptors) != 1:
            raise WitnessError(
                "witness requires one signed mutable-state descriptor"
            )
        self.state_binding = dict(next(iter(state_descriptors.values())))
        self.state_directory_descriptor = int(self.state_binding["fd"])
        self._verify_state_directory()
        try:
            fcntl.flock(
                self.state_directory_descriptor,
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
        except OSError as exc:
            raise WitnessError(
                "another witness owns the mutable-state directory"
            ) from exc
        self.lock = threading.Lock()
        self.receipts: dict[str, dict[str, Any]] = {}
        self.terminal_reservations: set[str] = set()
        self.request_phases: set[tuple[str, str]] = set()
        self.request_receipts: dict[tuple[str, str], str] = {}
        self.receipt_record_names: dict[str, str] = {}
        self.transition_records: dict[
            str,
            tuple[str, int, str, str, str, str],
        ] = {}
        self.activation_records: dict[str, str] = {}
        self.state_generation: dict[str, Any] | None = None
        self.state_sequence = 0
        self.state_record_count = 0
        self.state_total_bytes = 0
        self.state_quota_bytes = min(
            int(self.state_binding["quotaBytes"]),
            MAX_STATE_BYTES,
        )
        self.state_record_limit = min(
            MAX_STATE_RECORDS,
            max(1, self.state_quota_bytes // 128),
        )
        self.sequence = 0
        self.fence = 0
        self.head_digest: str | None = None
        self._load_state()
        state_metadata = os.fstat(self.state_directory_descriptor)
        self.state_directory_change = (
            state_metadata.st_mtime_ns,
            state_metadata.st_ctime_ns,
        )
        self._persist_generation_activation()

    def _verify_state_directory(self) -> None:
        metadata = os.fstat(self.state_directory_descriptor)
        if (
            self.state_binding["atomicRecordProtocol"]
                != STATE_RECORD_PROTOCOL
            or self.state_binding["singletonLeaseRequired"] is not True
            or self.state_binding["networkAllowed"] is not False
            or self.state_binding["surviveExec"] is not True
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_dev != self.state_binding["device"]
            or metadata.st_ino != self.state_binding["inode"]
            or metadata.st_uid != self.state_binding["uid"]
            or metadata.st_gid != self.state_binding["gid"]
            or stat.S_IMODE(metadata.st_mode)
                != self.state_binding["mode"]
            or metadata.st_mode & stat.S_IWOTH
        ):
            raise WitnessError(
                "witness mutable-state descriptor binding changed"
            )

    def _verify_receipt_signature(
        self,
        receipt: Mapping[str, Any],
    ) -> None:
        unsigned = dict(receipt)
        signature = unsigned.pop("signature", None)
        schema = receipt.get("schema")
        if schema != WITNESS_RECEIPT_SCHEMA:
            raise WitnessError("stored witness receipt schema is invalid")
        try:
            self.signing_key.public_key().verify(
                _b64url_decode(signature, size=64),
                _protocol_digest(
                    str(schema),
                    _canonical(unsigned),
                ).encode("ascii"),
            )
        except InvalidSignature as exc:
            raise WitnessError(
                "stored witness receipt signature is invalid"
            ) from exc

    def _load_state(self) -> None:
        names = list(os.listdir(self.state_directory_descriptor))
        removed_temporary = False
        record_names: list[tuple[int, str]] = []
        for name in names:
            if name.startswith(".tmp-"):
                descriptor = os.open(
                    name,
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=self.state_directory_descriptor,
                )
                try:
                    metadata = os.fstat(descriptor)
                    if (
                        not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_nlink != 1
                        or metadata.st_uid != self.state_binding["uid"]
                    ):
                        raise WitnessError(
                            "witness temporary state entry is not trusted"
                        )
                finally:
                    os.close(descriptor)
                os.unlink(
                    name,
                    dir_fd=self.state_directory_descriptor,
                )
                removed_temporary = True
                continue
            sequence, _digest_suffix = _parse_state_record_name(name)
            record_names.append((sequence, name))
        if removed_temporary:
            os.fsync(self.state_directory_descriptor)
        directory_identity = os.fstat(self.state_directory_descriptor)
        record_names.sort()
        minimum_receipt_digest = None
        for expected_sequence, (sequence, name) in enumerate(
            record_names,
            start=1,
        ):
            if sequence != expected_sequence:
                raise WitnessError(
                    "witness state record sequence is not contiguous"
                )
            record, canonical_record = self._read_state_record(name)
            if record.get("stateSequence") != sequence:
                raise WitnessError(
                    "witness state filename and record sequence differ"
                )
            receipt_digest = self._accept_stored_state_record(
                record,
                canonical_record,
                record_name=name,
                record_length=len(canonical_record),
            )
            self.state_sequence = sequence
            self.state_record_count += 1
            self.state_total_bytes += len(canonical_record)
            if (
                self.state_record_count > self.state_record_limit
                or self.state_total_bytes > self.state_quota_bytes
            ):
                raise WitnessError("witness state exceeds its signed quota")
            if (
                receipt_digest is not None
                and self.sequence
                    == int(self.configuration["minimumSequence"])
            ):
                minimum_receipt_digest = receipt_digest
        directory_identity_after = os.fstat(
            self.state_directory_descriptor
        )
        if (
            directory_identity.st_mtime_ns,
            directory_identity.st_ctime_ns,
        ) != (
            directory_identity_after.st_mtime_ns,
            directory_identity_after.st_ctime_ns,
        ):
            raise WitnessError(
                "witness state directory changed during startup scan"
            )
        if (
            self.sequence < int(self.configuration["minimumSequence"])
            or minimum_receipt_digest
                != self.configuration["minimumReceiptDigest"]
        ):
            raise WitnessError(
                "witness state is below its externally pinned high-water"
            )
        current_generation = self.configuration["generation"]
        if self.state_generation is not None:
            stored_sequence = self.state_generation["sequence"]
            current_sequence = current_generation["sequence"]
            if (
                current_sequence == stored_sequence
                and current_generation["digest"]
                    != self.state_generation["digest"]
                or current_sequence == stored_sequence + 1
                and current_generation["predecessorDigest"]
                    != self.state_generation["digest"]
                or current_sequence not in {
                    stored_sequence,
                    stored_sequence + 1,
                }
            ):
                raise WitnessError(
                    "configured generation is not the stored successor"
                )

    def _read_state_record(
        self,
        record_name: str,
    ) -> tuple[dict[str, Any], bytes]:
        sequence, _digest_suffix = _parse_state_record_name(record_name)
        descriptor = os.open(
            record_name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=self.state_directory_descriptor,
        )
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != self.state_binding["uid"]
                or metadata.st_gid != self.state_binding["gid"]
                or stat.S_IMODE(metadata.st_mode) != 0o400
                or not 1 <= metadata.st_size <= MAX_STATE_RECORD_BYTES
            ):
                raise WitnessError("witness state record is not immutable")
            canonical_record = os.pread(
                descriptor,
                MAX_STATE_RECORD_BYTES + 1,
                0,
            )
            metadata_after = os.fstat(descriptor)
            if (
                len(canonical_record) != metadata.st_size
                or (
                    metadata.st_dev,
                    metadata.st_ino,
                    metadata.st_size,
                    metadata.st_mtime_ns,
                )
                != (
                    metadata_after.st_dev,
                    metadata_after.st_ino,
                    metadata_after.st_size,
                    metadata_after.st_mtime_ns,
                )
                or _state_record_name(sequence, canonical_record)
                    != record_name
            ):
                raise WitnessError("witness state record identity changed")
        finally:
            os.close(descriptor)
        try:
            record = json.loads(canonical_record)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WitnessError("witness state record is not JSON") from exc
        if (
            not isinstance(record, dict)
            or canonical_record != _canonical(record)
        ):
            raise WitnessError("witness state record is not canonical")
        return record, canonical_record

    def _persist_state_record(
        self,
        record: Mapping[str, Any],
    ) -> tuple[str, bytes]:
        directory_metadata = os.fstat(self.state_directory_descriptor)
        if (
            directory_metadata.st_mtime_ns,
            directory_metadata.st_ctime_ns,
        ) != self.state_directory_change:
            raise WitnessError(
                "witness state directory changed outside its singleton"
            )
        canonical_record = _canonical(dict(record))
        if (
            not 1 <= len(canonical_record) <= MAX_STATE_RECORD_BYTES
            or self.state_record_count + 1 > self.state_record_limit
            or self.state_total_bytes + len(canonical_record)
                > self.state_quota_bytes
        ):
            raise WitnessError("witness state quota is exhausted")
        record_name = _state_record_name(
            int(record["stateSequence"]),
            canonical_record,
        )
        temporary_name = (
            f".tmp-{os.getpid()}-{threading.get_native_id()}-"
            f"{record['stateSequence']:020d}-{record_name[28:92]}"
        )
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | os.O_NOFOLLOW,
            0o600,
            dir_fd=self.state_directory_descriptor,
        )
        published = False
        try:
            offset = 0
            while offset < len(canonical_record):
                written = os.write(descriptor, canonical_record[offset:])
                if written <= 0:
                    raise WitnessError(
                        "witness state record write was incomplete"
                    )
                offset += written
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
            _rename_noreplace(
                self.state_directory_descriptor,
                temporary_name,
                record_name,
            )
            published = True
            os.fsync(self.state_directory_descriptor)
        finally:
            os.close(descriptor)
            if not published:
                try:
                    os.unlink(
                        temporary_name,
                        dir_fd=self.state_directory_descriptor,
                    )
                    os.fsync(self.state_directory_descriptor)
                except FileNotFoundError:
                    pass
        self.state_sequence += 1
        self.state_record_count += 1
        self.state_total_bytes += len(canonical_record)
        directory_metadata = os.fstat(self.state_directory_descriptor)
        self.state_directory_change = (
            directory_metadata.st_mtime_ns,
            directory_metadata.st_ctime_ns,
        )
        return record_name, canonical_record

    def _persist_generation_activation(self) -> None:
        generation = self.configuration["generation"]
        activation_id = _domain_digest(
            "serverware.policyAuthorityWitnessGenerationActivation/v1",
            _canonical(generation),
        )
        existing = self.activation_records.get(generation["digest"])
        if existing is not None:
            record, _canonical_record = self._read_state_record(existing)
            if record.get("transitionId") != activation_id:
                raise WitnessError(
                    "stored generation activation identity changed"
                )
            return
        record = {
            "schema": WITNESS_STATE_RECORD_SCHEMA,
            "kind": "generation-activation",
            "stateSequence": self.state_sequence + 1,
            "generation": generation,
            "transitionId": activation_id,
            "envelopeId": None,
            "parentEnvelopeId": None,
            "consumerLaunchId": None,
            "consumerLaunchKeyId": None,
            "consumerLaunchCertificateDigest": None,
            "canonicalRequestBase64Url": None,
            "canonicalResponseBase64Url": None,
            "canonicalRequestDigest": None,
            "canonicalResponseDigest": None,
        }
        record_name, canonical_record = self._persist_state_record(record)
        self._accept_stored_state_record(
            record,
            canonical_record,
            record_name=record_name,
            record_length=len(canonical_record),
        )

    def _accept_stored_receipt(
        self,
        receipt: Any,
        *,
        response_bytes: bytes,
        record_generation: Mapping[str, Any] | None = None,
    ) -> str:
        if not isinstance(receipt, dict):
            raise WitnessError("witness state receipt is not an object")
        if response_bytes != _canonical(receipt):
            raise WitnessError(
                "witness state response bytes are not canonical"
            )
        if receipt.get("schema") != WITNESS_RECEIPT_SCHEMA:
            raise WitnessError(
                "legacy witness receipts lack exact .19 replay evidence"
            )
        self._verify_receipt_signature(receipt)
        schema = str(receipt.get("schema"))
        receipt_digest = _protocol_digest(
            schema,
            response_bytes,
        )
        phase = receipt.get("phase")
        if schema == WITNESS_RECEIPT_SCHEMA:
            required = {
                "schema",
                "envelopeId",
                "parentEnvelopeId",
                "phase",
                "operation",
                "requestDigest",
                "capabilityId",
                "resultDigest",
                "witnessIdentityDigest",
                "sequence",
                "fence",
                "headDigest",
                "predecessorHeadDigest",
                "predecessorReceiptDigest",
                "logPredecessorHeadDigest",
                "deadlineMonotonicNs",
                "issuedAtEpochNs",
                "generationSequence",
                "generationDigest",
                "canonicalRequestDigest",
                "signature",
            }
            if phase == "credential-release-consume":
                required.update(
                    {
                        "transitionId",
                        "authorizationProjectionDigest",
                        "consumerLaunchId",
                        "consumerLaunchKeyId",
                        "consumerLaunchCertificateDigest",
                    }
                )
            if (
                set(receipt) != required
                or record_generation is None
                or receipt.get("generationSequence")
                    != record_generation["sequence"]
                or receipt.get("generationDigest")
                    != record_generation["digest"]
                or not _is_digest(
                    receipt.get("canonicalRequestDigest")
                )
                or not _is_digest(receipt.get("envelopeId"))
                or receipt.get("parentEnvelopeId")
                    != (
                        receipt.get("predecessorReceiptDigest")
                        if phase in TERMINAL_PHASES
                        else None
                    )
                or (
                    phase == "credential-release-consume"
                    and (
                        not _is_digest(receipt.get("transitionId"))
                        or not _is_digest(
                            receipt.get(
                                "authorizationProjectionDigest"
                            )
                        )
                        or not _is_digest(
                            receipt.get(
                                "consumerLaunchCertificateDigest"
                            )
                        )
                        or not _is_digest(
                            receipt.get("consumerLaunchKeyId")
                        )
                        or not isinstance(
                            receipt.get("consumerLaunchId"), str
                        )
                        or not receipt["consumerLaunchId"]
                    )
                )
            ):
                raise WitnessError(
                    "witness v2 receipt binding is invalid"
                )
        if (
            schema != WITNESS_RECEIPT_SCHEMA
            or receipt.get("witnessIdentityDigest")
            != self.configuration["identityDigest"]
            or receipt.get("sequence") != self.sequence + 1
            or receipt.get("logPredecessorHeadDigest")
            != self.head_digest
        ):
            raise WitnessError("witness state chain changed")
        unsigned = dict(receipt)
        unsigned.pop("signature", None)
        head_material = dict(unsigned)
        head_material["headDigest"] = None
        if receipt.get("headDigest") != _protocol_digest(
            "serverware.policyAuthorityReplayWitnessHead/v2",
            _canonical(head_material),
        ):
            raise WitnessError("witness state head digest changed")
        predecessor_receipt_digest = receipt.get(
            "predecessorReceiptDigest"
        )
        if phase in TERMINAL_PHASES:
            predecessor = self.receipts.get(
                str(predecessor_receipt_digest)
            )
            if (
                predecessor is None
                or predecessor.get("phase")
                    not in RESERVATION_PHASES
                or predecessor_receipt_digest
                    in self.terminal_reservations
                or receipt.get("fence") != predecessor.get("fence")
                or receipt.get("predecessorHeadDigest")
                    != predecessor.get("headDigest")
                or (
                    schema == WITNESS_RECEIPT_SCHEMA
                    and predecessor.get("generationDigest")
                        != receipt.get("generationDigest")
                )
                or (
                    phase == "credential-release-consume"
                    and predecessor.get("phase")
                        != "credential-release"
                )
                or (
                    phase != "credential-release-consume"
                    and predecessor.get("phase")
                        == "credential-release"
                )
            ):
                raise WitnessError(
                    "witness terminal transition is invalid"
                )
            self.terminal_reservations.add(
                predecessor_receipt_digest
            )
        else:
            if (
                predecessor_receipt_digest is not None
                or receipt.get("fence") != self.fence + 1
            ):
                raise WitnessError(
                    "witness reservation transition is invalid"
                )
            self.fence = int(receipt["fence"])
        self.sequence = int(receipt["sequence"])
        self.head_digest = str(receipt["headDigest"])
        self.receipts[receipt_digest] = dict(receipt)
        request_key = (
            str(receipt["phase"]),
            str(receipt["envelopeId"]),
        )
        self.request_phases.add(request_key)
        self.request_receipts[request_key] = receipt_digest
        return receipt_digest

    def _validate_launch_certificate(
        self,
        value: object,
        *,
        role: str,
        request_issued_at_epoch_ns: int,
        generation: Mapping[str, Any],
        launch_request: object,
        artifact_package: object,
        artifact_trust_state: object,
        expected_peer: Mapping[str, int | str] | None,
    ) -> tuple[dict[str, Any], str, Ed25519PublicKey]:
        return self._validate_canonical_launch_certificate(
            value,
            role=role,
            request_issued_at_epoch_ns=request_issued_at_epoch_ns,
            generation=generation,
            launch_request=launch_request,
            artifact_package=artifact_package,
            artifact_trust_state=artifact_trust_state,
            expected_peer=expected_peer,
        )

    def _validate_incompatible_launch_certificate(
        self,
        value: object,
        *,
        role: str,
        request_issued_at_epoch_ns: int,
        generation: Mapping[str, Any],
        expected_peer_pid: int | None,
    ) -> tuple[dict[str, Any], str, Ed25519PublicKey]:
        del (
            value,
            role,
            request_issued_at_epoch_ns,
            generation,
            expected_peer_pid,
        )
        raise WitnessError("legacy launch certificates are forbidden")

    def _validate_canonical_launch_certificate(
        self,
        value: object,
        *,
        role: str,
        request_issued_at_epoch_ns: int,
        generation: Mapping[str, Any],
        launch_request: object,
        artifact_package: object,
        artifact_trust_state: object,
        expected_peer: Mapping[str, int | str] | None,
    ) -> tuple[dict[str, Any], str, Ed25519PublicKey]:
        del request_issued_at_epoch_ns
        if (
            not isinstance(value, dict)
            or not isinstance(launch_request, dict)
            or not isinstance(artifact_package, dict)
            or not isinstance(artifact_trust_state, dict)
        ):
            raise WitnessError(
                "credential-release launch evidence is not an object"
            )
        validation_time = _canonical_timestamp_now()
        try:
            verified_package = (
                authority_artifact_spec.verify_signed_artifact_package(
                    artifact_package,
                    trust_state=artifact_trust_state,
                    validation_time=validation_time,
                )
            )
            if verified_package.disposition != "CurrentExactRetry":
                raise WitnessConflict(
                    "credential-release package is not current high-water"
                )
            process = launch_request["process"]
            pidfd = process["pidfd"]
            expected_pid = int(
                expected_peer["pid"]
                if expected_peer is not None
                else process["processId"]
            )
            expected_start_ticks = int(
                expected_peer["startTicks"]
                if expected_peer is not None
                else process["processStartTicks"]
            )
            if expected_peer is not None:
                _require_live_peer(expected_peer)
                if (
                    pidfd["device"] != expected_peer["pidfdDevice"]
                    or pidfd["inode"] != expected_peer["pidfdInode"]
                ):
                    raise WitnessConflict(
                        "credential-release pidfd identity changed"
                    )
            authority_stage_zero_contract.validate_stage_zero_request(
                launch_request,
                verified_package=verified_package,
                expected_listen_pid=expected_pid,
                expected_peer_pid=expected_pid,
                expected_peer_start_ticks=expected_start_ticks,
                validation_time=validation_time,
            )
            authority_stage_zero_contract.validate_signed_launch_identity(
                value,
                request=launch_request,
                verified_package=verified_package,
                expected_listen_pid=expected_pid,
                expected_peer_pid=expected_pid,
                expected_peer_start_ticks=expected_start_ticks,
                validation_time=validation_time,
            )
        except (
            authority_artifact_spec.ArtifactContractError,
            authority_stage_zero_contract.StageZeroContractError,
            KeyError,
            TypeError,
        ) as exc:
            raise WitnessError(
                "credential-release canonical launch evidence is invalid"
            ) from exc
        canonical_certificate = _canonical(value)
        certificate_digest = _protocol_digest(
            "serverware.authorityLaunchIdentityCertificateDigest/v1",
            canonical_certificate,
        )
        certificate = dict(value["payload"])
        launch_public_key = _b64url_decode(
            certificate["launchPublicKeyBase64Url"],
            size=32,
        )
        launch_key_id = _protocol_digest(
            LAUNCH_KEY_ID_DOMAIN,
            launch_public_key,
        )
        if (
            verified_package.generation_digest != generation["digest"]
            or verified_package.package_digest
                != generation["packageDigest"]
            or verified_package.artifact_bundle_digest
                != generation["artifactBundleDigest"]
            or verified_package.operation_manifest_digest
                != generation["operationManifestDigest"]
            or launch_request["role"]["role"] != role
        ):
            raise WitnessError(
                "credential-release package is outside witness generation"
            )
        if expected_peer is not None:
            _require_live_peer(expected_peer)
        certificate["launchKeyId"] = launch_key_id
        return (
            certificate,
            certificate_digest,
            Ed25519PublicKey.from_public_bytes(launch_public_key),
        )

    def _validate_request(
        self,
        request: Mapping[str, Any],
        canonical_request: bytes,
        *,
        enforce_freshness: bool,
        expected_generation: Mapping[str, Any] | None = None,
        expected_peer: Mapping[str, int | str] | None = None,
        stored_record: bool = False,
    ) -> dict[str, Any]:
        base_required = {
            "schema",
            "envelopeId",
            "parentEnvelopeId",
            "phase",
            "operation",
            "requestDigest",
            "capabilityId",
            "resultDigest",
            "predecessorReceiptDigest",
            "deadlineMonotonicNs",
            "configurationDigest",
            "operationManifestDigest",
            "generationSequence",
            "generationDigest",
            "issuedAtEpochNs",
            "signature",
        }
        phase = request.get("phase")
        required = set(base_required)
        if phase == "credential-release-consume":
            required.update(
                {
                    "transitionId",
                    "authorizationProjectionDigest",
                    "launchIdentityCertificate",
                    "launchIdentityCertificateDigest",
                    "launchStageZeroRequest",
                    "launchArtifactPackage",
                    "launchArtifactTrustState",
                }
            )
        unsigned_request = dict(request)
        signature = unsigned_request.pop("signature", None)
        now_monotonic_ns = time.monotonic_ns()
        now_epoch_ns = time.time_ns()
        generation = (
            dict(expected_generation)
            if expected_generation is not None
            else self.configuration["generation"]
        )
        is_historical_generation = (
            generation["digest"]
            != self.configuration["generation"]["digest"]
        )
        if (
            set(request) != required
            or canonical_request != _canonical(dict(request))
            or request.get("schema") != REQUEST_SCHEMA
            or phase not in ALLOWED_PHASES
            or (
                phase
                    in {
                        "reserve",
                        "commit",
                        "abort",
                        "reconcile",
                        "webauthn-trust-publish",
                    }
                and not is_historical_generation
                and request.get("operation")
                    not in (
                        authority_transition_registry
                        .PLANNABLE_OPERATIONS
                    )
            )
            or request.get("envelopeId")
                != _request_envelope_id(request)
            or request.get("parentEnvelopeId")
                != (
                    request.get("predecessorReceiptDigest")
                    if phase in TERMINAL_PHASES
                    else None
                )
            or (
                not is_historical_generation
                and request.get("configurationDigest")
                    not in self.configuration[
                        "authorityConfigurationDigests"
                    ]
            )
            or (
                is_historical_generation
                and not _is_digest(
                    request.get("configurationDigest")
                )
            )
            or request.get("operationManifestDigest")
                != generation["operationManifestDigest"]
            or request.get("generationSequence")
                != generation["sequence"]
            or request.get("generationDigest")
                != generation["digest"]
            or not _is_digest(request.get("requestDigest"))
            or (
                phase in {
                    "reserve",
                    "abort",
                    "webauthn-trust-publish",
                }
                and request.get("resultDigest") is not None
            )
            or (
                phase not in {
                    "reserve",
                    "abort",
                    "webauthn-trust-publish",
                }
                and not _is_digest(request.get("resultDigest"))
            )
            or not isinstance(request.get("deadlineMonotonicNs"), int)
            or isinstance(request.get("deadlineMonotonicNs"), bool)
            or not isinstance(request.get("issuedAtEpochNs"), int)
            or isinstance(request.get("issuedAtEpochNs"), bool)
            or (
                enforce_freshness
                and phase not in {"abort", "reconcile"}
                and now_monotonic_ns
                    >= request["deadlineMonotonicNs"]
            )
            or (
                enforce_freshness
                and (
                    request["issuedAtEpochNs"] > now_epoch_ns
                    or now_epoch_ns - request["issuedAtEpochNs"]
                        > int(
                            self.configuration["maximumRequestAgeNs"]
                        )
                )
            )
        ):
            raise WitnessError("witness request binding is invalid")
        metadata: dict[str, Any] = {
            "canonicalRequestDigest": _protocol_digest(
                REQUEST_SCHEMA,
                canonical_request,
            ),
            "transitionId": None,
            "consumerLaunchId": None,
            "consumerLaunchKeyId": None,
            "consumerLaunchCertificateDigest": None,
            "authorizationProjectionDigest": None,
        }
        verification_key = self.verifier_key
        if phase == "credential-release-consume":
            if expected_peer is None and not stored_record:
                raise WitnessError(
                    "credential-release requires a live peer identity"
                )
            role = request.get("operation")
            if role not in {
                "verifier",
                "planner",
                "planner-writer",
                "issuer",
                "executor",
            }:
                raise WitnessError(
                    "credential-release consumer role is invalid"
                )
            (
                certificate,
                certificate_digest,
                verification_key,
            ) = self._validate_launch_certificate(
                request.get("launchIdentityCertificate"),
                role=str(role),
                request_issued_at_epoch_ns=request["issuedAtEpochNs"],
                generation=generation,
                launch_request=request.get("launchStageZeroRequest"),
                artifact_package=request.get("launchArtifactPackage"),
                artifact_trust_state=request.get(
                    "launchArtifactTrustState"
                ),
                expected_peer=expected_peer,
            )
            if (
                request.get("launchIdentityCertificateDigest")
                    != certificate_digest
                or not _is_digest(
                    request.get("authorizationProjectionDigest")
                )
            ):
                raise WitnessError(
                    "credential-release launch binding is invalid"
                )
            transition_material = {
                "predecessorReceiptDigest":
                    request.get("predecessorReceiptDigest"),
                "operation": request.get("operation"),
                "requestDigest": request.get("requestDigest"),
                "capabilityId": request.get("capabilityId"),
                "resultDigest": request.get("resultDigest"),
                "authorizationProjectionDigest":
                    request.get("authorizationProjectionDigest"),
                "generationDigest": request.get("generationDigest"),
                "consumerLaunchId": certificate["launchId"],
                "consumerLaunchKeyId": certificate["launchKeyId"],
                "consumerLaunchCertificateDigest": certificate_digest,
            }
            expected_transition_id = _protocol_digest(
                TRANSITION_ID_DOMAIN,
                _canonical(transition_material),
            )
            if request.get("transitionId") != expected_transition_id:
                raise WitnessError(
                    "credential-release transition identity changed"
                )
            metadata.update(
                {
                    "transitionId": expected_transition_id,
                    "consumerLaunchId": certificate["launchId"],
                    "consumerLaunchKeyId": certificate["launchKeyId"],
                    "consumerLaunchCertificateDigest":
                        certificate_digest,
                    "authorizationProjectionDigest":
                        request["authorizationProjectionDigest"],
                }
            )
        if not (
            is_historical_generation
            and phase != "credential-release-consume"
        ):
            try:
                verification_key.verify(
                    _b64url_decode(signature, size=64),
                    _protocol_digest(
                        REQUEST_SCHEMA,
                        _canonical(unsigned_request),
                    ).encode("ascii"),
                )
            except InvalidSignature as exc:
                raise WitnessError(
                    "witness request signature is invalid"
                ) from exc
        if (
            phase == "credential-release-consume"
            and expected_peer is not None
        ):
            _require_live_peer(expected_peer)
        return metadata

    def _accept_stored_state_record(
        self,
        record: Mapping[str, Any],
        canonical_record: bytes,
        *,
        record_name: str,
        record_length: int,
    ) -> str | None:
        required = {
            "schema",
            "kind",
            "stateSequence",
            "generation",
            "transitionId",
            "envelopeId",
            "parentEnvelopeId",
            "consumerLaunchId",
            "consumerLaunchKeyId",
            "consumerLaunchCertificateDigest",
            "canonicalRequestBase64Url",
            "canonicalResponseBase64Url",
            "canonicalRequestDigest",
            "canonicalResponseDigest",
        }
        record_generation = _validate_generation_value(
            record.get("generation"),
            require_current_validity=False,
        )
        configured_generation = self.configuration["generation"]
        state_sequence, _digest_suffix = _parse_state_record_name(
            record_name
        )
        if (
            set(record) != required
            or record.get("schema") != WITNESS_STATE_RECORD_SCHEMA
            or record.get("kind")
                not in {"generation-activation", "transition"}
            or record.get("stateSequence") != state_sequence
            or record_length != len(canonical_record)
            or canonical_record != _canonical(dict(record))
            or _state_record_name(state_sequence, canonical_record)
                != record_name
            or record_generation["sequence"]
                > configured_generation["sequence"]
            or (
                record_generation["sequence"]
                    == configured_generation["sequence"]
                and record_generation["digest"]
                    != configured_generation["digest"]
            )
            or (
                self.state_generation is None
                and record_generation["sequence"]
                    < configured_generation["minimumRollbackSequence"]
            )
        ):
            raise WitnessError("witness state record binding changed")
        if record["kind"] == "generation-activation":
            activation_id = _domain_digest(
                "serverware.policyAuthorityWitnessGenerationActivation/v1",
                _canonical(record_generation),
            )
            if (
                record.get("transitionId") != activation_id
                or any(
                    record.get(name) is not None
                    for name in {
                        "consumerLaunchId",
                        "consumerLaunchKeyId",
                        "consumerLaunchCertificateDigest",
                        "envelopeId",
                        "parentEnvelopeId",
                        "canonicalRequestBase64Url",
                        "canonicalResponseBase64Url",
                        "canonicalRequestDigest",
                        "canonicalResponseDigest",
                    }
                )
                or record_generation["digest"]
                    in self.activation_records
                or (
                    self.state_generation is not None
                    and not (
                        record_generation["sequence"]
                            == self.state_generation["sequence"] + 1
                        and record_generation["predecessorDigest"]
                            == self.state_generation["digest"]
                    )
                )
            ):
                raise WitnessError(
                    "witness generation activation is invalid"
                )
            self.activation_records[
                record_generation["digest"]
            ] = record_name
            self.state_generation = record_generation
            return None
        if (
            self.state_generation is None
            or self.state_generation["digest"]
                != record_generation["digest"]
            or record_generation["digest"] not in self.activation_records
        ):
            raise WitnessError(
                "witness transition precedes generation activation"
            )
        request_bytes = _b64url_decode_bounded(
            record.get("canonicalRequestBase64Url"),
            maximum=MAX_MESSAGE_BYTES,
        )
        response_bytes = _b64url_decode_bounded(
            record.get("canonicalResponseBase64Url"),
            maximum=MAX_MESSAGE_BYTES,
        )
        if (
            record.get("canonicalRequestDigest")
            != _protocol_digest(
                "serverware.policyAuthorityWitnessExactRequest/v1",
                request_bytes,
            )
            or record.get("canonicalResponseDigest")
            != _protocol_digest(
                "serverware.policyAuthorityWitnessExactResponse/v1",
                response_bytes,
            )
        ):
            raise WitnessError("witness exact record digest changed")
        try:
            request = json.loads(request_bytes)
            receipt = json.loads(response_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WitnessError(
                "witness state canonical bytes are invalid"
            ) from exc
        if not isinstance(request, dict) or not isinstance(receipt, dict):
            raise WitnessError(
                "witness state canonical object is invalid"
            )
        metadata = self._validate_request(
            request,
            request_bytes,
            enforce_freshness=False,
            expected_generation=record_generation,
            stored_record=True,
        )
        receipt_digest = self._accept_stored_receipt(
            receipt,
            response_bytes=response_bytes,
            record_generation=record_generation,
        )
        if (
            receipt.get("canonicalRequestDigest")
                != metadata["canonicalRequestDigest"]
            or record.get("envelopeId")
                != request.get("envelopeId")
            or record.get("parentEnvelopeId")
                != request.get("parentEnvelopeId")
            or receipt.get("envelopeId")
                != request.get("envelopeId")
            or receipt.get("parentEnvelopeId")
                != request.get("parentEnvelopeId")
            or receipt.get("phase") != request.get("phase")
            or receipt.get("operation") != request.get("operation")
            or receipt.get("requestDigest")
                != request.get("requestDigest")
            or receipt.get("capabilityId")
                != request.get("capabilityId")
            or receipt.get("resultDigest")
                != request.get("resultDigest")
            or receipt.get("predecessorReceiptDigest")
                != request.get("predecessorReceiptDigest")
            or receipt.get("deadlineMonotonicNs")
                != request.get("deadlineMonotonicNs")
        ):
            raise WitnessError(
                "witness state request and response are not joined"
            )
        transition_id = metadata["transitionId"]
        if transition_id is None:
            if any(
                record.get(name) is not None
                for name in {
                    "transitionId",
                    "consumerLaunchId",
                    "consumerLaunchKeyId",
                    "consumerLaunchCertificateDigest",
                }
            ):
                raise WitnessError(
                    "non-release witness record has launch identity"
                )
        else:
            launch_identity = (
                metadata["consumerLaunchId"],
                metadata["consumerLaunchKeyId"],
                metadata["consumerLaunchCertificateDigest"],
            )
            if (
                record.get("transitionId") != transition_id
                or record.get("consumerLaunchId")
                    != launch_identity[0]
                or record.get("consumerLaunchKeyId")
                    != launch_identity[1]
                or record.get("consumerLaunchCertificateDigest")
                    != launch_identity[2]
                or receipt.get("transitionId") != transition_id
                or receipt.get("consumerLaunchId")
                    != launch_identity[0]
                or receipt.get("consumerLaunchKeyId")
                    != launch_identity[1]
                or receipt.get("consumerLaunchCertificateDigest")
                    != launch_identity[2]
                or transition_id in self.transition_records
            ):
                raise WitnessError(
                    "credential-release transition was reused"
                )
            self.transition_records[transition_id] = (
                record_name,
                record_length,
                launch_identity[0],
                launch_identity[1],
                launch_identity[2],
                record_generation["digest"],
            )
        self.receipt_record_names[receipt_digest] = record_name
        return receipt_digest

    def _read_transition_record(
        self,
        transition_id: str,
    ) -> tuple[bytes, bytes, tuple[str, str, str], str]:
        (
            record_name,
            record_length,
            launch_id,
            launch_key_id,
            certificate_digest,
            generation_digest,
        ) = self.transition_records[transition_id]
        record, canonical_record = self._read_state_record(record_name)
        if len(canonical_record) != record_length:
            raise WitnessError(
                "credential-release replay record is unavailable"
            )
        if (
            record.get("schema") != WITNESS_STATE_RECORD_SCHEMA
            or record.get("kind") != "transition"
            or record.get("transitionId") != transition_id
            or record.get("consumerLaunchId") != launch_id
            or record.get("consumerLaunchKeyId") != launch_key_id
            or record.get("consumerLaunchCertificateDigest")
                != certificate_digest
            or not isinstance(record.get("generation"), dict)
            or record["generation"].get("digest")
                != generation_digest
        ):
            raise WitnessError(
                "credential-release replay index changed"
            )
        request_bytes = _b64url_decode_bounded(
            record.get("canonicalRequestBase64Url"),
            maximum=MAX_MESSAGE_BYTES,
        )
        response_bytes = _b64url_decode_bounded(
            record.get("canonicalResponseBase64Url"),
            maximum=MAX_MESSAGE_BYTES,
        )
        if (
            record.get("canonicalRequestDigest")
            != _protocol_digest(
                "serverware.policyAuthorityWitnessExactRequest/v1",
                request_bytes,
            )
            or record.get("canonicalResponseDigest")
            != _protocol_digest(
                "serverware.policyAuthorityWitnessExactResponse/v1",
                response_bytes,
            )
        ):
            raise WitnessError(
                "credential-release exact replay digest changed"
            )
        return (
            request_bytes,
            response_bytes,
            (launch_id, launch_key_id, certificate_digest),
            generation_digest,
        )

    def _read_receipt_response(self, receipt_digest: str) -> bytes:
        record_name = self.receipt_record_names[receipt_digest]
        record, _canonical_record = self._read_state_record(record_name)
        response_bytes = _b64url_decode_bounded(
            record.get("canonicalResponseBase64Url"),
            maximum=MAX_MESSAGE_BYTES,
        )
        if record.get("canonicalResponseDigest") != _protocol_digest(
            "serverware.policyAuthorityWitnessExactResponse/v1",
            response_bytes,
        ):
            raise WitnessError("indexed witness response digest changed")
        try:
            receipt = json.loads(response_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WitnessError(
                "indexed witness response is invalid"
            ) from exc
        if (
            not isinstance(receipt, dict)
            or response_bytes != _canonical(receipt)
            or _protocol_digest(
                str(receipt.get("schema")),
                response_bytes,
            )
            != receipt_digest
        ):
            raise WitnessError("indexed witness response changed")
        return response_bytes

    def transition(self, request: Mapping[str, Any]) -> dict[str, Any]:
        response = self.transition_bytes(
            request,
            _canonical(dict(request)),
        )
        value = json.loads(response)
        if not isinstance(value, dict):
            raise WitnessError("witness response is not an object")
        return value

    def transition_bytes(
        self,
        request: Mapping[str, Any],
        canonical_request: bytes,
        *,
        peer_process: Mapping[str, int | str] | None = None,
    ) -> bytes:
        if (
            request.get("phase") == "credential-release-consume"
            and peer_process is None
        ):
            raise WitnessError(
                "credential-release requires a live certified peer"
            )
        candidate_transition_id = request.get("transitionId")
        if _is_digest(candidate_transition_id):
            with self.lock:
                if (
                    candidate_transition_id
                        in self.transition_records
                ):
                    existing_request, _response, _launch, generation_digest = (
                        self._read_transition_record(
                            str(candidate_transition_id)
                        )
                    )
                    if (
                        existing_request != canonical_request
                        or request.get("generationDigest")
                            != generation_digest
                    ):
                        raise WitnessConflict(
                            "credential-release transition conflicts"
                        )
        metadata = self._validate_request(
            request,
            canonical_request,
            enforce_freshness=False,
            expected_peer=peer_process,
        )
        phase = str(request["phase"])
        request_digest = str(request["requestDigest"])
        request_key = (phase, str(request["envelopeId"]))
        transition_id = metadata["transitionId"]
        with self.lock:
            if transition_id is not None:
                if transition_id in self.transition_records:
                    (
                        existing_request,
                        existing_response,
                        expected_launch,
                        _existing_generation,
                    ) = self._read_transition_record(transition_id)
                    actual_launch = (
                        metadata["consumerLaunchId"],
                        metadata["consumerLaunchKeyId"],
                        metadata[
                            "consumerLaunchCertificateDigest"
                        ],
                    )
                    if (
                        existing_request != canonical_request
                        or expected_launch != actual_launch
                    ):
                        raise WitnessConflict(
                            "credential-release transition conflicts"
                        )
                    return existing_response
            existing_digest = self.request_receipts.get(request_key)
            if (
                existing_digest is not None
                and transition_id is None
            ):
                existing = self.receipts[existing_digest]
                if (
                    existing.get("canonicalRequestDigest")
                        != metadata["canonicalRequestDigest"]
                    or existing.get("operation")
                        != request.get("operation")
                    or existing.get("capabilityId")
                        != request.get("capabilityId")
                    or existing.get("resultDigest")
                        != request.get("resultDigest")
                    or existing.get("predecessorReceiptDigest")
                        != request.get("predecessorReceiptDigest")
                    or existing.get("deadlineMonotonicNs")
                        != request.get("deadlineMonotonicNs")
                ):
                    raise WitnessConflict(
                        "witness request identity was reused"
                    )
                return self._read_receipt_response(existing_digest)
        metadata = self._validate_request(
            request,
            canonical_request,
            enforce_freshness=True,
            expected_peer=peer_process,
        )
        with self.lock:
            if transition_id is not None:
                if transition_id in self.transition_records:
                    (
                        existing_request,
                        existing_response,
                        _expected_launch,
                        _existing_generation,
                    ) = self._read_transition_record(transition_id)
                    if existing_request != canonical_request:
                        raise WitnessConflict(
                            "credential-release transition conflicts"
                        )
                    return existing_response
            if (
                phase not in {"abort", "reconcile"}
                and time.monotonic_ns()
                    >= request["deadlineMonotonicNs"]
            ):
                raise WitnessError(
                    "witness request expired while awaiting serialization"
                )
            existing_digest = self.request_receipts.get(request_key)
            if existing_digest is not None:
                raise WitnessConflict(
                    "witness request identity was reused"
                )
            predecessor_receipt_digest = request.get(
                "predecessorReceiptDigest"
            )
            predecessor = (
                self.receipts.get(str(predecessor_receipt_digest))
                if predecessor_receipt_digest is not None
                else None
            )
            if phase in TERMINAL_PHASES:
                if (
                    predecessor is None
                    or predecessor.get("phase")
                        not in RESERVATION_PHASES
                    or predecessor_receipt_digest
                        in self.terminal_reservations
                    or predecessor.get("operation")
                        != request.get("operation")
                    or predecessor.get("requestDigest")
                        != request.get("requestDigest")
                    or predecessor.get("generationDigest")
                        != self.configuration["generation"][
                            "digest"
                        ]
                    or (
                        request.get("capabilityId") is None
                        and phase != "abort"
                    )
                    or (
                        phase == "credential-release-consume"
                        and predecessor.get("phase")
                            != "credential-release"
                    )
                    or (
                        phase != "credential-release-consume"
                        and predecessor.get("phase")
                            == "credential-release"
                    )
                ):
                    raise WitnessError(
                        "witness terminal predecessor is invalid"
                    )
                fence = int(predecessor["fence"])
                predecessor_head = predecessor["headDigest"]
            else:
                if (
                    predecessor_receipt_digest is not None
                    or phase == "credential-release"
                    and request.get("capabilityId") is None
                ):
                    raise WitnessError(
                        "witness reservation predecessor is invalid"
                    )
                fence = self.fence + 1
                predecessor_head = None
            unsigned_receipt = {
                "schema": WITNESS_RECEIPT_SCHEMA,
                "envelopeId": request["envelopeId"],
                "parentEnvelopeId": request["parentEnvelopeId"],
                "phase": phase,
                "operation": request["operation"],
                "requestDigest": request_digest,
                "capabilityId": request.get("capabilityId"),
                "resultDigest": request.get("resultDigest"),
                "witnessIdentityDigest":
                    self.configuration["identityDigest"],
                "sequence": self.sequence + 1,
                "fence": fence,
                "headDigest": None,
                "predecessorHeadDigest": predecessor_head,
                "predecessorReceiptDigest":
                    predecessor_receipt_digest,
                "logPredecessorHeadDigest": self.head_digest,
                "deadlineMonotonicNs":
                    request["deadlineMonotonicNs"],
                "issuedAtEpochNs": time.time_ns(),
                "generationSequence":
                    self.configuration["generation"]["sequence"],
                "generationDigest":
                    self.configuration["generation"][
                        "digest"
                    ],
                "canonicalRequestDigest":
                    metadata["canonicalRequestDigest"],
            }
            if transition_id is not None:
                unsigned_receipt.update(
                    {
                        "transitionId": transition_id,
                        "authorizationProjectionDigest":
                            metadata[
                                "authorizationProjectionDigest"
                            ],
                        "consumerLaunchId":
                            metadata["consumerLaunchId"],
                        "consumerLaunchKeyId":
                            metadata["consumerLaunchKeyId"],
                        "consumerLaunchCertificateDigest":
                            metadata[
                                "consumerLaunchCertificateDigest"
                            ],
                    }
                )
            unsigned_receipt["headDigest"] = _protocol_digest(
                "serverware.policyAuthorityReplayWitnessHead/v2",
                _canonical(unsigned_receipt),
            )
            signature_value = self.signing_key.sign(
                _protocol_digest(
                    WITNESS_RECEIPT_SCHEMA,
                    _canonical(unsigned_receipt),
                ).encode("ascii")
            )
            receipt = {
                **unsigned_receipt,
                "signature": _b64url_encode(signature_value),
            }
            response_bytes = _canonical(receipt)
            state_record = {
                "schema": WITNESS_STATE_RECORD_SCHEMA,
                "kind": "transition",
                "stateSequence": self.state_sequence + 1,
                "generation": self.configuration["generation"],
                "transitionId": transition_id,
                "envelopeId": request["envelopeId"],
                "parentEnvelopeId": request["parentEnvelopeId"],
                "consumerLaunchId":
                    metadata["consumerLaunchId"],
                "consumerLaunchKeyId":
                    metadata["consumerLaunchKeyId"],
                "consumerLaunchCertificateDigest":
                    metadata["consumerLaunchCertificateDigest"],
                "canonicalRequestBase64Url":
                    _b64url_encode(canonical_request),
                "canonicalResponseBase64Url":
                    _b64url_encode(response_bytes),
                "canonicalRequestDigest": _protocol_digest(
                    "serverware.policyAuthorityWitnessExactRequest/v1",
                    canonical_request,
                ),
                "canonicalResponseDigest": _protocol_digest(
                    "serverware.policyAuthorityWitnessExactResponse/v1",
                    response_bytes,
                ),
            }
            record_name, canonical_record = self._persist_state_record(
                state_record
            )
            self._accept_stored_state_record(
                state_record,
                canonical_record,
                record_name=record_name,
                record_length=len(canonical_record),
            )
            return response_bytes


class WitnessServer:
    def __init__(
        self,
        *,
        witness: WitnessStateStore,
        configuration: dict[str, Any],
    ) -> None:
        self.witness = witness
        self.configuration = configuration
        self.socket_path = Path(configuration["socketPath"])
        workers = int(configuration["workers"])
        maximum_in_flight = int(
            configuration["maximumInFlight"]
        )
        if (
            not 1 <= workers <= 256
            or not workers <= maximum_in_flight <= 4096
        ):
            raise WitnessError(
                "witness concurrency bounds are invalid"
            )
        self.pool = ThreadPoolExecutor(
            max_workers=workers,
            thread_name_prefix="authority-witness",
        )
        self.in_flight = threading.BoundedSemaphore(
            maximum_in_flight
        )
        listener_descriptor = authority_launch_guard.listener_descriptor()
        if os.environ.get(
            "SERVERWARE_POLICY_AUTHORITY_LISTENER_FD"
        ) != str(listener_descriptor):
            raise WitnessError(
                "witness listener environment binding changed"
            )
        self.socket = socket.fromfd(
            listener_descriptor,
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        )
        self._validate_activated_listener()

    def _validate_activated_listener(self) -> None:
        metadata = os.fstat(self.socket.fileno())
        socket_path = self.socket.getsockname()
        if isinstance(socket_path, bytes):
            socket_path = os.fsdecode(socket_path)
        path_metadata = os.stat(
            self.socket_path,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or self.socket.family != socket.AF_UNIX
            or self.socket.type & socket.SOCK_STREAM
                != socket.SOCK_STREAM
            or self.socket.getsockopt(
                socket.SOL_SOCKET,
                socket.SO_ACCEPTCONN,
            )
            != 1
            or socket_path != str(self.socket_path)
            or not stat.S_ISSOCK(path_metadata.st_mode)
            or path_metadata.st_uid
                != int(self.configuration["serviceUid"])
            or path_metadata.st_gid
                != int(self.configuration["serviceGid"])
            or stat.S_IMODE(path_metadata.st_mode) != 0o660
        ):
            raise WitnessError(
                "witness activated listener binding changed"
            )

    def serve_forever(self) -> None:
        while True:
            connection, _address = self.socket.accept()
            if not self.in_flight.acquire(blocking=False):
                connection.close()
                continue
            future = self.pool.submit(
                self._serve_connection,
                connection,
            )
            future.add_done_callback(
                lambda _future: self.in_flight.release()
            )

    def _serve_connection(self, connection: socket.socket) -> None:
        peer_process: dict[str, int | str] | None = None
        try:
            connection.settimeout(
                float(self.configuration["requestTimeoutSeconds"])
            )
            pid, uid, gid = _peer_identity(connection)
            peer_process = _capture_peer_process(pid)
            request, canonical_request = _receive(connection)
            if request.get("phase") == "credential-release-consume":
                peer = self.configuration[
                    "releaseConsumerPeers"
                ].get(request.get("operation"))
                peer_allowed = (
                    isinstance(peer, dict)
                    and uid == int(peer["uid"])
                    and gid == int(peer["gid"])
                )
            else:
                peer_allowed = (
                    uid == int(self.configuration["peerUid"])
                    and gid == int(self.configuration["peerGid"])
                )
            if not peer_allowed:
                raise WitnessError(
                    "witness peer identity is not allowed"
                )
            response = self.witness.transition_bytes(
                request,
                canonical_request,
                peer_process=peer_process,
            )
            _send_canonical(connection, response)
        except Exception as exc:
            try:
                _send(
                    connection,
                    {
                        "schema":
                            "serverware.policyAuthorityWitnessError/v1",
                        "code": (
                            "witness_conflict"
                            if isinstance(exc, WitnessConflict)
                            else "witness_denied"
                        ),
                        "detailDigest": "sha256:"
                            + hashlib.sha256(
                                str(exc).encode("utf-8")
                            ).hexdigest(),
                    },
                )
            except Exception:
                pass
        finally:
            if peer_process is not None:
                os.close(int(peer_process["pidfd"]))
            connection.close()


def main() -> int:
    if (
        os.environ.get("SERVERWARE_PROCESS_MODE", "").strip()
        != "policy-authority-replay-witness"
        or sys.flags.isolated != 1
        or sys.flags.safe_path is not True
        or sys.flags.no_user_site != 1
        or sys.flags.no_site != 1
        or sys.flags.ignore_environment != 1
    ):
        raise WitnessError(
            "witness process was not isolated by the measured launcher"
        )
    configuration, configuration_digest = _load_configuration()
    witness = WitnessStateStore(
        configuration=configuration,
        configuration_digest=configuration_digest,
    )
    WitnessServer(
        witness=witness,
        configuration=configuration,
    ).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
