#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any


PROVIDER = "aws-nitro-enclaves"
TEE_PLATFORM = "aws-nitro"
USER_DATA_PREFIX = b"catchplate:nitro-production-claims:v2:"
REQUEST_VERSION = "catchplate.nitroAttestationRequest/v2"
CLAIMS_VERSION = "catchplate.productionAttestationClaims/v2"
IDENTITY_VERSION = "catchplate.productionAttestationIdentity/v2"
COMPLETION_IDENTITY_VERSION = "catchplate.finalCompletionIdentity/v3"
COMPLETION_CORE_VERSIONS = {
    "builderA": "catchplate.completionBuilderCore/v1",
    "builderB": "catchplate.completionBuilderCore/v1",
    "custody": "catchplate.completionCustodyCore/v1",
    "eif": "catchplate.completionEifCore/v1",
    "hardware": "catchplate.completionHardwareCore/v1",
    "promotion": "catchplate.completionPromotionCore/v1",
    "release": "catchplate.completionReleaseCore/v1",
    "response": "catchplate.completionResponseCore/v1",
    "runtime": "catchplate.completionRuntimeCore/v1",
    "source": "catchplate.completionSourceCore/v1",
    "trust": "catchplate.completionTrustCore/v1",
    "witness": "catchplate.completionWitnessCore/v1",
}
COMPLETION_CORE_FIELDS = frozenset(
    {*COMPLETION_CORE_VERSIONS, "continuity"}
)
RUNTIME_VERSION = "catchplate.productionAttestationRuntime/v2"
CUSTODY_VERSION = "catchplate.enclaveKeyCustody/v3"
PROMOTED_MANIFEST_VERSION = "catchplate.consolidatedTestArtifacts/v6"
PIPELINE = "manifest-v6-promoted-oci-nitro-eif"
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
SHA384_RE = re.compile(r"sha384:[0-9a-f]{96}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@+-]{0,255}\Z")
MAX_STATE_BYTES = 8 * 1024 * 1024
STATE_PATHS = {
    "productionIdentity": "CATCHPLATE_NITRO_PRODUCTION_IDENTITY_PATH",
    "promotedManifest": "CATCHPLATE_NITRO_PROMOTED_MANIFEST_PATH",
    "runtimeState": "CATCHPLATE_NITRO_RUNTIME_STATE_PATH",
    "keyCustody": "CATCHPLATE_NITRO_KEY_CUSTODY_PATH",
}


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def validate_completion_identity(value: Any) -> dict[str, Any]:
    identity = require_exact(
        value,
        {
            "apiVersion",
            "challengeNonceSha256",
            "coreDigests",
            "pipeline",
            "releaseGeneration",
            "rollbackEpoch",
        },
        "final completion identity",
    )
    core_digests = require_exact(
        identity["coreDigests"],
        COMPLETION_CORE_FIELDS,
        "final completion core digests",
    )
    if (
        identity["apiVersion"] != COMPLETION_IDENTITY_VERSION
        or identity["pipeline"] != PIPELINE
        or type(identity["releaseGeneration"]) is not int
        or identity["releaseGeneration"] < 1
        or type(identity["rollbackEpoch"]) is not int
        or identity["rollbackEpoch"] < 0
    ):
        raise SystemExit("final completion identity is invalid")
    require_digest(
        identity["challengeNonceSha256"],
        "final completion challenge nonce",
    )
    for name, digest in core_digests.items():
        require_digest(digest, f"final completion {name} core")
    return identity


def completion_core(name: str, payload: dict[str, Any]) -> dict[str, Any]:
    if name not in COMPLETION_CORE_VERSIONS:
        raise SystemExit(f"unknown completion core {name}")
    forbidden = {
        "completionIdentity",
        "completionIdentitySha256",
        "completion_identity",
        "completion_identity_sha256",
    }
    stack: list[Any] = [payload]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            if forbidden.intersection(current):
                raise SystemExit(f"{name} completion core contains completion binding")
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)
    return {
        "apiVersion": COMPLETION_CORE_VERSIONS[name],
        "pipeline": PIPELINE,
        "payload": payload,
    }


def claims_user_data(claims: dict[str, Any]) -> bytes:
    digest = hashlib.sha256(canonical_json(claims).encode("utf-8")).hexdigest().encode("ascii")
    return USER_DATA_PREFIX + digest


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def read_stdin() -> dict[str, Any]:
    raw = sys.stdin.buffer.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise SystemExit("stdin exceeds 1 MiB")
    return strict_json(raw or b"{}", "stdin request")


def request_without_digest(payload: dict[str, Any]) -> dict[str, Any]:
    copied = json.loads(json.dumps(payload))
    copied.pop("request_digest", None)
    return copied


def command_mentions(raw: str, *needles: str) -> bool:
    try:
        lowered = " ".join(shlex.split(raw)).lower()
    except ValueError:
        lowered = raw.lower()
    return any(needle.lower() in lowered for needle in needles)


def require_exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise SystemExit(f"{label} fields do not match the closed contract")
    return value


def require_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise SystemExit(f"{label} must be a lowercase SHA-256 digest")
    return value


def require_sha384(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA384_RE.fullmatch(value) is None:
        raise SystemExit(f"{label} must be a lowercase SHA-384 digest")
    return value


def stable_root_owned_read(path: Path, label: str) -> bytes:
    if (
        not path.is_absolute()
        or not path.name
        or ".." in path.parts
        or os.path.normpath(os.fspath(path)) != os.fspath(path)
    ):
        raise SystemExit(f"{label} path must be normalized and absolute")
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory is None:
        raise SystemExit(f"{label} requires no-follow file operations")
    directory_flags = (
        os.O_RDONLY
        | directory
        | no_follow
        | getattr(os, "O_CLOEXEC", 0)
    )
    parent_fd = os.open("/", directory_flags)
    file_fd: int | None = None
    try:
        for component in path.parent.parts[1:]:
            next_fd = os.open(component, directory_flags, dir_fd=parent_fd)
            directory_stat = os.fstat(next_fd)
            if (
                not stat.S_ISDIR(directory_stat.st_mode)
                or directory_stat.st_uid != 0
                or stat.S_IMODE(directory_stat.st_mode) & 0o022
            ):
                os.close(next_fd)
                raise SystemExit(
                    f"{label} path must use root-owned non-writable directories"
                )
            os.close(parent_fd)
            parent_fd = next_fd
        file_fd = os.open(
            path.name,
            os.O_RDONLY
            | no_follow
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=parent_fd,
        )
        before = os.fstat(file_fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != 0
            or stat.S_IMODE(before.st_mode) not in {0o400, 0o440, 0o444}
            or not 1 <= before.st_size <= MAX_STATE_BYTES
        ):
            raise SystemExit(
                f"{label} must be a root-owned read-only single-link regular file"
            )
        result = bytearray()
        while len(result) <= MAX_STATE_BYTES:
            chunk = os.read(file_fd, MAX_STATE_BYTES + 1 - len(result))
            if not chunk:
                break
            result.extend(chunk)
        after = os.fstat(file_fd)
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_nlink,
            item.st_uid,
            item.st_gid,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if (
            identity(before) != identity(after)
            or len(result) != before.st_size
            or len(result) > MAX_STATE_BYTES
        ):
            raise SystemExit(f"{label} changed while being remeasured")
        return bytes(result)
    except OSError as exc:
        raise SystemExit(f"{label} is unavailable through a safe path") from exc
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(parent_fd)


def strict_json(raw: bytes, label: str) -> dict[str, Any]:
    if not raw or raw.startswith(b"\xef\xbb\xbf"):
        raise SystemExit(f"{label} is not canonical JSON")

    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise SystemExit(f"{label} contains duplicate JSON keys")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs,
            parse_float=lambda _: (_ for _ in ()).throw(
                SystemExit(f"{label} contains a floating-point value")
            ),
            parse_constant=lambda _: (_ for _ in ()).throw(
                SystemExit(f"{label} contains a non-finite value")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise SystemExit(f"{label} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{label} must be a JSON object")
    return value


class CborReader:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.offset = 0
        self.items = 0

    def take(self, count: int) -> bytes:
        if count < 0 or self.offset + count > len(self.raw):
            raise SystemExit("Nitro CBOR is truncated")
        value = self.raw[self.offset : self.offset + count]
        self.offset += count
        return value

    def length(self, additional: int) -> int:
        if additional < 24:
            return additional
        widths = {24: 1, 25: 2, 26: 4, 27: 8}
        width = widths.get(additional)
        if width is None:
            raise SystemExit(
                "Nitro CBOR indefinite or reserved lengths are forbidden"
            )
        value = int.from_bytes(self.take(width), "big")
        minimum = {1: 24, 2: 256, 4: 65536, 8: 1 << 32}[width]
        if value < minimum:
            raise SystemExit("Nitro CBOR uses noncanonical integer encoding")
        return value

    def read(self, depth: int = 0) -> Any:
        if depth > 24 or self.items >= 8192:
            raise SystemExit("Nitro CBOR exceeds structural bounds")
        self.items += 1
        initial = self.take(1)[0]
        major = initial >> 5
        additional = initial & 31
        if major in {0, 1}:
            value = self.length(additional)
            return value if major == 0 else -1 - value
        if major in {2, 3}:
            raw = self.take(self.length(additional))
            if len(raw) > 1024 * 1024:
                raise SystemExit("Nitro CBOR string is oversized")
            if major == 2:
                return raw
            try:
                return raw.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise SystemExit("Nitro CBOR text is invalid UTF-8") from exc
        if major == 4:
            length = self.length(additional)
            if length > 4096:
                raise SystemExit("Nitro CBOR array is oversized")
            return [self.read(depth + 1) for _ in range(length)]
        if major == 5:
            length = self.length(additional)
            if length > 4096:
                raise SystemExit("Nitro CBOR map is oversized")
            result: dict[Any, Any] = {}
            for _ in range(length):
                key = self.read(depth + 1)
                if not isinstance(key, (int, str)) or key in result:
                    raise SystemExit(
                        "Nitro CBOR map key is invalid or duplicated"
                    )
                result[key] = self.read(depth + 1)
            return result
        if major == 6:
            return ("tag", self.length(additional), self.read(depth + 1))
        if major == 7 and additional in {20, 21, 22}:
            return {20: False, 21: True, 22: None}[additional]
        raise SystemExit("Nitro CBOR contains an unsupported value")


def parse_nitro_document(raw: bytes) -> dict[str, Any]:
    if not 512 <= len(raw) <= 1024 * 1024:
        raise SystemExit("raw Nitro attestation document is outside its bound")
    reader = CborReader(raw)
    cose = reader.read()
    if reader.offset != len(raw):
        raise SystemExit("raw Nitro COSE has trailing bytes")
    if (
        isinstance(cose, tuple)
        and len(cose) == 3
        and cose[0] == "tag"
        and cose[1] == 18
    ):
        cose = cose[2]
    if (
        not isinstance(cose, list)
        or len(cose) != 4
        or not isinstance(cose[0], bytes)
        or not isinstance(cose[1], dict)
        or not isinstance(cose[2], bytes)
        or not isinstance(cose[3], bytes)
        or len(cose[3]) < 64
    ):
        raise SystemExit("raw Nitro document is not COSE_Sign1")
    payload_reader = CborReader(cose[2])
    payload = payload_reader.read()
    if payload_reader.offset != len(cose[2]) or not isinstance(payload, dict):
        raise SystemExit("raw Nitro COSE payload is invalid")
    if set(payload) != {
        "module_id",
        "digest",
        "timestamp",
        "pcrs",
        "certificate",
        "cabundle",
        "public_key",
        "user_data",
        "nonce",
    }:
        raise SystemExit("raw Nitro payload fields are not the closed schema")
    pcrs = payload.get("pcrs")
    if (
        payload.get("digest") != "SHA384"
        or type(payload.get("timestamp")) is not int
        or payload["timestamp"] < 1
        or not isinstance(payload.get("nonce"), bytes)
        or not isinstance(payload.get("user_data"), bytes)
        or not isinstance(pcrs, dict)
        or set(pcrs) != {0, 1, 2}
        or any(
            not isinstance(pcrs[index], bytes) or len(pcrs[index]) != 48
            for index in (0, 1, 2)
        )
    ):
        raise SystemExit("raw Nitro payload values are invalid")
    parsed_pcrs = {
        f"PCR{index}": "sha384:" + pcrs[index].hex()
        for index in (0, 1, 2)
    }
    return {
        "debug": all(pcrs[index] == b"\x00" * 48 for index in (0, 1, 2)),
        "nonce": payload["nonce"],
        "payloadSha256": sha256_prefixed(cose[2]),
        "pcrs": parsed_pcrs,
        "timestamp": payload["timestamp"],
        "userData": payload["user_data"],
    }


def state_documents() -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    raw: dict[str, bytes] = {}
    for label, environment_name in STATE_PATHS.items():
        configured = os.getenv(environment_name, "")
        if not configured or configured != configured.strip():
            raise SystemExit(f"{environment_name} is required")
        raw[label] = stable_root_owned_read(Path(configured), label)
    documents = {
        label: strict_json(value, label)
        for label, value in raw.items()
    }
    for label, value in raw.items():
        if value != canonical_json(documents[label]).encode("ascii") + b"\n":
            raise SystemExit(
                f"{label} must use canonical versioned JSON encoding"
            )
    digests = {
        label: sha256_prefixed(value)
        for label, value in raw.items()
    }
    return documents, digests


def validate_state(
    documents: dict[str, dict[str, Any]],
    digests: dict[str, str],
    expected: dict[str, Any],
) -> None:
    require_exact(
        expected,
        {
            "keyCustodySha256",
            "productionIdentitySha256",
            "promotedManifestSha256",
            "runtimeStateSha256",
        },
        "expected remeasurements",
    )
    for label, expected_field in (
        ("keyCustody", "keyCustodySha256"),
        ("productionIdentity", "productionIdentitySha256"),
        ("promotedManifest", "promotedManifestSha256"),
        ("runtimeState", "runtimeStateSha256"),
    ):
        require_digest(expected.get(expected_field), expected_field)
        if not hmac.compare_digest(digests[label], str(expected[expected_field])):
            raise SystemExit(f"{label} remeasurement differs from the caller pin")
    identity = require_exact(
        documents["productionIdentity"],
        {
            "apiVersion",
            "builderStatementSha256s",
            "buildWatchdogReceiptSha256",
            "candidateManifestFileSha256",
            "candidateManifestPayloadSha256",
            "completionIdentity",
            "completionIdentitySha256",
            "dependencyClosureSha256",
            "eifImageSha384",
            "importedImageMappingsSha256",
            "monotonicWitnessSha256",
            "pipeline",
            "pcrs",
            "promotedManifestSha256",
            "promotionReceiptSha256",
            "productionContinuitySha256",
            "productionReleaseIdentitySha256",
            "releaseGeneration",
            "sourceClosureSha256",
            "sourceInputApprovalSha256",
            "sourceInputManifestFileSha256",
            "sourceInputManifestPayloadSha256",
        },
        "production identity",
    )
    runtime = require_exact(
        documents["runtimeState"],
        {
            "activeTlsConnection",
            "apiVersion",
            "caSpkiSha256",
            "completionIdentity",
            "completionIdentitySha256",
            "custodyEvidenceSha256",
            "enclaveBootId",
            "enclaveInstanceId",
            "keyGenerations",
            "pipeline",
            "policyHash",
            "policySequence",
            "productionIdentitySha256",
            "promotedManifestSha256",
            "releaseGeneration",
            "rollbackEpoch",
            "tlsScopeSigningKeySpkiSha256",
        },
        "runtime state",
    )
    custody = require_exact(
        documents["keyCustody"],
        {
            "apiVersion",
            "completionIdentity",
            "completionIdentitySha256",
            "eifImageSha384",
            "generationSignerPublicKeySpkiDerBase64url",
            "generationSignerPublicKeySpkiSha256",
            "materials",
            "pcrs",
            "pipeline",
            "policyHash",
            "recipientPublicKeySpkiDerBase64url",
            "recipientPublicKeySpkiSha256",
            "releaseGeneration",
            "rollbackEpoch",
        },
        "key custody",
    )
    manifest = require_exact(
        documents["promotedManifest"],
        {
            "apiVersion",
            "candidate",
            "companions",
            "imageMappings",
            "images",
            "laneOrder",
            "lanes",
            "manifestSha256",
            "platform",
            "promotion",
            "sourceSnapshot",
            "watchdog",
        },
        "promoted Manifest v6",
    )
    if (
        identity.get("apiVersion") != IDENTITY_VERSION
        or runtime.get("apiVersion") != RUNTIME_VERSION
        or custody.get("apiVersion") != CUSTODY_VERSION
        or manifest.get("apiVersion") != PROMOTED_MANIFEST_VERSION
        or manifest.get("platform")
        != {"architecture": "amd64", "os": "linux"}
        or any(
            item.get("pipeline") != PIPELINE
            for item in (identity, runtime, custody)
        )
    ):
        raise SystemExit("remeasured state is not the Manifest v6 Nitro pipeline")
    completion_identity = validate_completion_identity(
        identity["completionIdentity"]
    )
    completion_identity_sha256 = sha256_prefixed(
        canonical_json(completion_identity).encode("ascii")
    )
    if (
        identity["completionIdentitySha256"] != completion_identity_sha256
        or runtime["completionIdentity"] != completion_identity
        or runtime["completionIdentitySha256"] != completion_identity_sha256
        or custody["completionIdentity"] != completion_identity
        or custody["completionIdentitySha256"] != completion_identity_sha256
        or completion_identity["releaseGeneration"]
        != runtime["releaseGeneration"]
        or completion_identity["rollbackEpoch"] != runtime["rollbackEpoch"]
    ):
        raise SystemExit(
            "remeasured state crossed the canonical completion identity"
        )
    manifest_payload = dict(manifest)
    manifest_sha256 = require_digest(
        manifest_payload.pop("manifestSha256", None),
        "promoted Manifest v6 payload",
    )
    if manifest_sha256 != sha256_prefixed(
        canonical_json(manifest_payload).encode("ascii")
    ):
        raise SystemExit("promoted Manifest v6 payload digest is invalid")
    if manifest.get("laneOrder") != [
        "approval-review",
        "browser-python-compatibility",
        "chromium-compatibility",
        "clean-room",
        "credential-constraints",
        "credential-constraints-proxy",
        "host-python-compatibility",
        "internal-service-auth",
        "jit-transaction-sqlite-full",
        "onboarding-evidence",
        "portal-browser-oauth",
        "proxy-python-compatibility",
        "rust-decision-gate-tests",
        "webauthn-attestation",
    ]:
        raise SystemExit("promoted Manifest v6 lane order is invalid")
    for actual, expected_value, label in (
        (
            runtime.get("productionIdentitySha256"),
            digests["productionIdentity"],
            "runtime identity",
        ),
        (
            runtime.get("promotedManifestSha256"),
            digests["promotedManifest"],
            "runtime manifest",
        ),
        (
            runtime.get("custodyEvidenceSha256"),
            digests["keyCustody"],
            "runtime custody",
        ),
        (
            identity.get("promotedManifestSha256"),
            digests["promotedManifest"],
            "identity manifest",
        ),
        (
            runtime.get("releaseGeneration"),
            identity.get("releaseGeneration"),
            "identity generation",
        ),
        (
            runtime.get("releaseGeneration"),
            custody.get("releaseGeneration"),
            "custody generation",
        ),
        (runtime.get("policyHash"), custody.get("policyHash"), "custody policy"),
        (
            runtime.get("rollbackEpoch"),
            custody.get("rollbackEpoch"),
            "custody rollback epoch",
        ),
        (
            identity.get("eifImageSha384"),
            custody.get("eifImageSha384"),
            "custody EIF",
        ),
        (identity.get("pcrs"), custody.get("pcrs"), "custody PCRs"),
    ):
        if actual != expected_value:
            raise SystemExit(f"{label} binding mismatch")
    require_sha384(identity.get("eifImageSha384"), "EIF image")
    pcrs = require_exact(identity.get("pcrs"), {"PCR0", "PCR1", "PCR2"}, "PCRs")
    for name in ("PCR0", "PCR1", "PCR2"):
        require_sha384(pcrs.get(name), name)
    if pcrs["PCR0"] != identity["eifImageSha384"]:
        raise SystemExit("EIF image does not match PCR0")
    if (
        type(identity.get("releaseGeneration")) is not int
        or identity["releaseGeneration"] < 1
        or type(runtime.get("releaseGeneration")) is not int
        or runtime["releaseGeneration"] < 1
        or type(runtime.get("policySequence")) is not int
        or runtime["policySequence"] < 1
        or type(runtime.get("rollbackEpoch")) is not int
        or runtime["rollbackEpoch"] < 0
        or type(custody.get("releaseGeneration")) is not int
        or custody["releaseGeneration"] < 1
        or type(custody.get("rollbackEpoch")) is not int
        or custody["rollbackEpoch"] < 0
    ):
        raise SystemExit(
            "release generation, policy sequence, or rollback epoch is invalid"
        )
    for field in ("enclaveBootId", "enclaveInstanceId"):
        value = runtime.get(field)
        if not isinstance(value, str) or IDENTIFIER_RE.fullmatch(value) is None:
            raise SystemExit(f"runtime {field} is invalid")
    require_digest(
        custody.get("recipientPublicKeySpkiSha256"),
        "custody enclave recipient key",
    )
    require_digest(
        custody.get("generationSignerPublicKeySpkiSha256"),
        "custody generation signer",
    )
    require_digest(
        custody.get("completionIdentitySha256"),
        "custody completion identity",
    )
    require_digest(custody.get("policyHash"), "custody policy")
    builder_statements = identity.get("builderStatementSha256s")
    if (
        not isinstance(builder_statements, list)
        or len(builder_statements) != 2
        or builder_statements != sorted(builder_statements)
        or len(set(builder_statements)) != 2
    ):
        raise SystemExit("production identity must bind exactly two builders")
    for value in builder_statements:
        require_digest(value, "builder statement")
    for field in (
        "buildWatchdogReceiptSha256",
        "candidateManifestFileSha256",
        "candidateManifestPayloadSha256",
        "completionIdentitySha256",
        "dependencyClosureSha256",
        "importedImageMappingsSha256",
        "monotonicWitnessSha256",
        "promotedManifestSha256",
        "promotionReceiptSha256",
        "productionContinuitySha256",
        "productionReleaseIdentitySha256",
        "sourceClosureSha256",
        "sourceInputApprovalSha256",
        "sourceInputManifestFileSha256",
        "sourceInputManifestPayloadSha256",
    ):
        require_digest(identity.get(field), f"identity {field}")
    for field in (
        "caSpkiSha256",
        "custodyEvidenceSha256",
        "policyHash",
        "productionIdentitySha256",
        "promotedManifestSha256",
        "tlsScopeSigningKeySpkiSha256",
    ):
        require_digest(runtime.get(field), f"runtime {field}")
    key_generations = require_exact(
        runtime.get("keyGenerations"),
        {
            "brokerKek",
            "ca",
            "credentialRelease",
            "policy",
            "release",
            "response",
            "tls",
            "tlsScope",
        },
        "key generations",
    )
    if any(type(value) is not int or value < 1 for value in key_generations.values()):
        raise SystemExit("key generations must be positive integers")
    materials = custody.get("materials")
    names = {
        "broker-kek",
        "ca",
        "credentials",
        "release",
        "response",
        "tls",
    }
    if not isinstance(materials, list) or len(materials) != len(names):
        raise SystemExit("key-custody inventory is incomplete")
    observed: set[str] = set()
    material_by_name: dict[str, dict[str, Any]] = {}
    for material_value in materials:
        material = require_exact(
            material_value,
            {
                "generationStatement",
                "identityPublicKeySpkiDerBase64url",
                "identitySpkiSha256",
                "keyGeneration",
                "kmsEncryptionContextSha256",
                "kmsRecipientRelease",
                "name",
                "scopeSigningKey",
            },
            "key-custody material",
        )
        name = material.get("name")
        if name not in names or name in observed:
            raise SystemExit("key-custody inventory is invalid")
        observed.add(str(name))
        material_by_name[str(name)] = material
        require_digest(material.get("identitySpkiSha256"), f"{name} identity")
        require_digest(
            material.get("kmsEncryptionContextSha256"), f"{name} context"
        )
        encoded_identity = material.get("identityPublicKeySpkiDerBase64url")
        if not isinstance(encoded_identity, str):
            raise SystemExit(f"{name} raw identity key is missing")
        try:
            identity_der = b64d(encoded_identity)
        except Exception as exc:
            raise SystemExit(f"{name} raw identity key is invalid") from exc
        if (
            not identity_der
            or b64e(identity_der) != encoded_identity
            or sha256_prefixed(identity_der)
            != material.get("identitySpkiSha256")
        ):
            raise SystemExit(f"{name} raw identity key binding is invalid")
        generation_statement = require_exact(
            material.get("generationStatement"),
            {
                "apiVersion",
                "nitroDocumentBase64url",
                "nitroDocumentSha256",
                "payload",
                "payloadSha256",
                "signature",
                "signingKeyId",
            },
            f"{name} generation statement",
        )
        release = require_exact(
            material.get("kmsRecipientRelease"),
            {
                "conditions",
                "encryptionContext",
                "encryptionContextSha256",
                "generationNitroDocumentSha256",
                "kmsKeyIdSha256",
                "rawResponseBase64url",
                "rawResponseSha256",
            },
            f"{name} KMS recipient release",
        )
        if (
            generation_statement.get("apiVersion")
            != "catchplate.enclaveKeyGeneration/v1"
            or release.get("generationNitroDocumentSha256")
            != generation_statement.get("nitroDocumentSha256")
            or release.get("encryptionContextSha256")
            != material.get("kmsEncryptionContextSha256")
        ):
            raise SystemExit(f"{name} custody raw evidence is not cross-bound")
        for field in (
            "nitroDocumentSha256",
            "payloadSha256",
            "signingKeyId",
        ):
            require_digest(
                generation_statement.get(field),
                f"{name} generation statement {field}",
            )
        for field in (
            "encryptionContextSha256",
            "generationNitroDocumentSha256",
            "kmsKeyIdSha256",
            "rawResponseSha256",
        ):
            require_digest(release.get(field), f"{name} KMS release {field}")
        for field, label in (
            ("nitroDocumentBase64url", "Nitro document"),
            ("rawResponseBase64url", "KMS response"),
        ):
            encoded = (
                generation_statement.get(field)
                if field == "nitroDocumentBase64url"
                else release.get(field)
            )
            if not isinstance(encoded, str):
                raise SystemExit(f"{name} raw {label} is missing")
            try:
                decoded = b64d(encoded)
            except Exception as exc:
                raise SystemExit(f"{name} raw {label} is invalid") from exc
            expected_digest = (
                generation_statement["nitroDocumentSha256"]
                if field == "nitroDocumentBase64url"
                else release["rawResponseSha256"]
            )
            if (
                not decoded
                or b64e(decoded) != encoded
                or sha256_prefixed(decoded) != expected_digest
            ):
                raise SystemExit(f"{name} raw {label} binding is invalid")
        if (
            type(material.get("keyGeneration")) is not int
            or material["keyGeneration"] < 1
        ):
            raise SystemExit(f"{name} key generation is invalid")
    generation_bindings = {
        "broker-kek": "brokerKek",
        "ca": "ca",
        "credentials": "credentialRelease",
        "release": "release",
        "response": "response",
        "tls": "tls",
    }
    for material_name, generation_name in generation_bindings.items():
        if (
            material_by_name[material_name]["keyGeneration"]
            != key_generations[generation_name]
        ):
            raise SystemExit(
                f"{material_name} custody generation does not match runtime state"
            )
    if material_by_name["ca"]["identitySpkiSha256"] != runtime["caSpkiSha256"]:
        raise SystemExit("CA custody identity does not match runtime state")
    tls_scope = require_exact(
        material_by_name["tls"].get("scopeSigningKey"),
        {
            "keyGeneration",
            "publicKeySpkiDerBase64url",
            "publicKeySpkiSha256",
        },
        "TLS scope signing key",
    )
    try:
        tls_scope_der = b64d(str(tls_scope["publicKeySpkiDerBase64url"]))
    except Exception as exc:
        raise SystemExit("TLS scope signing key is invalid") from exc
    if (
        b64e(tls_scope_der) != tls_scope["publicKeySpkiDerBase64url"]
        or sha256_prefixed(tls_scope_der)
        != tls_scope["publicKeySpkiSha256"]
        or tls_scope["publicKeySpkiSha256"]
        != runtime["tlsScopeSigningKeySpkiSha256"]
        or tls_scope["keyGeneration"] != key_generations["tlsScope"]
    ):
        raise SystemExit("TLS scope signing key differs from runtime custody")
    for name in names - {"tls"}:
        if material_by_name[name].get("scopeSigningKey") is not None:
            raise SystemExit(f"{name} has an unauthorized TLS scope key")


def build_claims(
    binding: dict[str, Any],
    documents: dict[str, dict[str, Any]],
    digests: dict[str, str],
) -> tuple[dict[str, Any], bytes]:
    require_exact(
        binding, {"challenge", "requestSha256", "tlsBinding"}, "request binding"
    )
    challenge = require_exact(
        binding.get("challenge"),
        {
            "challengeId",
            "connectionId",
            "expiresAtUnix",
            "issuedAtUnix",
            "peerSpkiSha256",
            "value",
            "valueSha256",
        },
        "challenge",
    )
    value = challenge.get("value")
    if not isinstance(value, str):
        raise SystemExit("challenge value is invalid")
    try:
        nonce = b64d(value)
    except Exception as exc:
        raise SystemExit("challenge value is invalid") from exc
    if (
        len(nonce) != 32
        or b64e(nonce) != value
        or challenge.get("valueSha256") != sha256_prefixed(nonce)
    ):
        raise SystemExit("challenge value binding is invalid")
    try:
        challenge_id = str(uuid.UUID(str(challenge.get("challengeId"))))
    except ValueError as exc:
        raise SystemExit("challenge ID is invalid") from exc
    issued_at = challenge.get("issuedAtUnix")
    expires_at = challenge.get("expiresAtUnix")
    now = int(time.time())
    if (
        challenge_id != challenge.get("challengeId")
        or not isinstance(challenge.get("connectionId"), str)
        or IDENTIFIER_RE.fullmatch(challenge["connectionId"]) is None
        or type(issued_at) is not int
        or type(expires_at) is not int
        or issued_at > now + 5
        or not issued_at <= now < expires_at
        or not 15 <= expires_at - issued_at <= 300
    ):
        raise SystemExit("challenge validity window is invalid")
    require_digest(challenge.get("peerSpkiSha256"), "challenge peer SPKI")
    tls_binding = require_exact(
        binding.get("tlsBinding"),
        {
            "apiVersion",
            "bindingSha256",
            "connectionId",
            "connectionNonceSha256",
            "enclaveBootId",
            "enclaveInstanceId",
            "expiresAtUnix",
            "exporterLabel",
            "exporterSha256",
            "issuedAtUnix",
            "leafCertificateSha256",
            "leafSpkiSha256",
            "peerCertificateSha256",
            "peerIdentity",
            "peerSpkiSha256",
            "provider",
            "tlsKeyGeneration",
            "tlsScopeEnvelopeSha256",
            "tlsScopeKeyGeneration",
            "tlsScopeKeySpkiSha256",
            "tlsStackMeasurementSha256",
        },
        "TLS binding",
    )
    tls_payload = dict(tls_binding)
    tls_digest = tls_payload.pop("bindingSha256", None)
    if tls_digest != sha256_prefixed(canonical_json(tls_payload).encode("ascii")):
        raise SystemExit("TLS binding digest mismatch")
    for field in (
        "connectionNonceSha256",
        "exporterSha256",
        "leafCertificateSha256",
        "leafSpkiSha256",
        "peerCertificateSha256",
        "peerSpkiSha256",
        "tlsScopeEnvelopeSha256",
        "tlsScopeKeySpkiSha256",
        "tlsStackMeasurementSha256",
    ):
        require_digest(tls_binding.get(field), f"TLS {field}")
    if (
        tls_binding.get("apiVersion") != "catchplate.enclaveTlsScope/v2"
        or tls_binding.get("provider") != "enclave-nitro-tls"
        or tls_binding.get("exporterLabel")
        != "EXPORTER-Catchplate-Attestation-v1"
        or not isinstance(tls_binding.get("connectionId"), str)
        or IDENTIFIER_RE.fullmatch(tls_binding["connectionId"]) is None
        or type(tls_binding.get("issuedAtUnix")) is not int
        or type(tls_binding.get("expiresAtUnix")) is not int
        or tls_binding["expiresAtUnix"] <= tls_binding["issuedAtUnix"]
    ):
        raise SystemExit("TLS binding is not enclave-owned")
    request_sha256 = require_digest(
        binding.get("requestSha256"), "attestation request"
    )
    identity = documents["productionIdentity"]
    runtime = documents["runtimeState"]
    custody = documents["keyCustody"]
    materials = {item["name"]: item for item in custody["materials"]}
    active = require_exact(
        runtime.get("activeTlsConnection"),
        {
            "connectionId",
            "connectionNonceSha256",
            "envelopeSha256",
            "expiresAtUnix",
            "exporterSha256",
            "issuedAtUnix",
            "leafCertificateSha256",
            "leafSpkiSha256",
            "peerCertificateSha256",
            "peerIdentity",
            "peerSpkiSha256",
            "tlsStackMeasurementSha256",
        },
        "active TLS connection",
    )
    expected_active = {
        "connectionId": tls_binding.get("connectionId"),
        "connectionNonceSha256": tls_binding.get("connectionNonceSha256"),
        "envelopeSha256": tls_binding.get("tlsScopeEnvelopeSha256"),
        "expiresAtUnix": tls_binding.get("expiresAtUnix"),
        "exporterSha256": tls_binding.get("exporterSha256"),
        "issuedAtUnix": tls_binding.get("issuedAtUnix"),
        "leafCertificateSha256": tls_binding.get("leafCertificateSha256"),
        "leafSpkiSha256": tls_binding.get("leafSpkiSha256"),
        "peerCertificateSha256": tls_binding.get("peerCertificateSha256"),
        "peerIdentity": tls_binding.get("peerIdentity"),
        "peerSpkiSha256": tls_binding.get("peerSpkiSha256"),
        "tlsStackMeasurementSha256": tls_binding.get(
            "tlsStackMeasurementSha256"
        ),
    }
    tls_scope = require_exact(
        materials["tls"].get("scopeSigningKey"),
        {
            "keyGeneration",
            "publicKeySpkiDerBase64url",
            "publicKeySpkiSha256",
        },
        "TLS scope signing key",
    )
    if (
        active != expected_active
        or tls_binding.get("enclaveInstanceId")
        != runtime["enclaveInstanceId"]
        or tls_binding.get("enclaveBootId") != runtime["enclaveBootId"]
        or tls_binding.get("tlsKeyGeneration") != runtime["keyGenerations"]["tls"]
        or tls_binding.get("tlsScopeKeyGeneration")
        != runtime["keyGenerations"]["tlsScope"]
        or tls_binding.get("tlsScopeKeyGeneration")
        != tls_scope["keyGeneration"]
        or tls_binding.get("tlsScopeKeySpkiSha256")
        != runtime["tlsScopeSigningKeySpkiSha256"]
        or tls_binding.get("tlsScopeKeySpkiSha256")
        != tls_scope["publicKeySpkiSha256"]
        or tls_binding.get("leafSpkiSha256")
        != materials["tls"]["identitySpkiSha256"]
        or challenge.get("connectionId") != tls_binding.get("connectionId")
        or challenge.get("peerSpkiSha256") != tls_binding.get("peerSpkiSha256")
    ):
        raise SystemExit("TLS binding does not match remeasured runtime state")
    custody_core_payload = {
        key: value
        for key, value in custody.items()
        if key not in {"completionIdentity", "completionIdentitySha256"}
    }
    custody_core_sha256 = sha256_prefixed(
        canonical_json(
            completion_core("custody", custody_core_payload)
        ).encode("ascii")
    )
    release_core_payload = {
        key: value
        for key, value in identity.items()
        if key
        not in {
            "builderStatementSha256s",
            "completionIdentity",
            "completionIdentitySha256",
            "monotonicWitnessSha256",
            "productionContinuitySha256",
            "productionReleaseIdentitySha256",
        }
    }
    release_core_payload["builderCoreSha256s"] = sorted(
        (
            completion_identity["coreDigests"]["builderA"],
            completion_identity["coreDigests"]["builderB"],
        )
    )
    release_core_payload["eifCoreSha256"] = completion_identity[
        "coreDigests"
    ]["eif"]
    release_core_sha256 = sha256_prefixed(
        canonical_json(
            completion_core("release", release_core_payload)
        ).encode("ascii")
    )
    runtime_core_payload = {
        key: value
        for key, value in runtime.items()
        if key
        not in {
            "completionIdentity",
            "completionIdentitySha256",
            "custodyEvidenceSha256",
            "productionIdentitySha256",
        }
    }
    runtime_core_payload["custodyCoreSha256"] = custody_core_sha256
    runtime_core_payload["releaseCoreSha256"] = release_core_sha256
    runtime_core_sha256 = sha256_prefixed(
        canonical_json(
            completion_core("runtime", runtime_core_payload)
        ).encode("ascii")
    )
    hardware_core_sha256 = sha256_prefixed(
        canonical_json(
            completion_core(
                "hardware",
                {
                    "eifSha384": identity["eifImageSha384"],
                    "moduleId": runtime["enclaveInstanceId"],
                    "pcrs": identity["pcrs"],
                    "recipientPublicKeySha256": custody[
                        "recipientPublicKeySpkiSha256"
                    ],
                },
            )
        ).encode("ascii")
    )
    for name, actual in {
        "custody": custody_core_sha256,
        "hardware": hardware_core_sha256,
        "release": release_core_sha256,
        "runtime": runtime_core_sha256,
    }.items():
        if completion_identity["coreDigests"][name] != actual:
            raise SystemExit(
                f"completion identity {name} core is not reconstructible from remeasured state"
            )
    if completion_identity["challengeNonceSha256"] != challenge["valueSha256"]:
        raise SystemExit(
            "completion identity does not bind the fresh workload challenge"
        )
    claims = {
        "apiVersion": CLAIMS_VERSION,
        "candidate": {
            "builderStatementSha256s": identity["builderStatementSha256s"],
            "buildWatchdogReceiptSha256": identity[
                "buildWatchdogReceiptSha256"
            ],
            "candidateManifestFileSha256": identity[
                "candidateManifestFileSha256"
            ],
            "candidateManifestPayloadSha256": identity[
                "candidateManifestPayloadSha256"
            ],
            "dependencyClosureSha256": identity["dependencyClosureSha256"],
            "importedImageMappingsSha256": identity[
                "importedImageMappingsSha256"
            ],
            "promotionReceiptSha256": identity["promotionReceiptSha256"],
            "sourceClosureSha256": identity["sourceClosureSha256"],
            "sourceInputApprovalSha256": identity[
                "sourceInputApprovalSha256"
            ],
            "sourceInputManifestFileSha256": identity[
                "sourceInputManifestFileSha256"
            ],
            "sourceInputManifestPayloadSha256": identity[
                "sourceInputManifestPayloadSha256"
            ],
        },
        "challenge": challenge,
        "completion": {
            "completionIdentity": completion_identity,
            "completionIdentitySha256": identity["completionIdentitySha256"],
            "keyCustodyEvidenceSha256": digests["keyCustody"],
            "monotonicWitnessSha256": identity["monotonicWitnessSha256"],
            "productionContinuitySha256": identity[
                "productionContinuitySha256"
            ],
            "productionReleaseIdentitySha256": identity[
                "productionReleaseIdentitySha256"
            ],
        },
        "eif": {
            "imageSha384": identity["eifImageSha384"],
            "pcrs": identity["pcrs"],
        },
        "keyCustodySha256": digests["keyCustody"],
        "keyGenerations": runtime["keyGenerations"],
        "pipeline": PIPELINE,
        "policy": {
            "hash": runtime["policyHash"],
            "rollbackEpoch": runtime["rollbackEpoch"],
            "sequence": runtime["policySequence"],
        },
        "productionIdentitySha256": digests["productionIdentity"],
        "promotedManifestSha256": digests["promotedManifest"],
        "release": {
            "caSpkiSha256": runtime["caSpkiSha256"],
            "generation": runtime["releaseGeneration"],
            "responseKeySpkiSha256": materials["response"][
                "identitySpkiSha256"
            ],
            "releaseKeySpkiSha256": materials["release"][
                "identitySpkiSha256"
            ],
        },
        "requestSha256": request_sha256,
        "runtimeStateSha256": digests["runtimeState"],
        "tlsBinding": tls_binding,
    }
    return claims, nonce


def validate_request(payload: dict[str, Any]) -> tuple[bytes, dict[str, Any], bytes]:
    require_exact(
        payload,
        {
            "apiVersion",
            "binding",
            "expectedRemeasurements",
            "kind",
            "provider",
            "request_digest",
            "tee_platform",
        },
        "Nitro attestation request",
    )
    if payload.get("apiVersion") != REQUEST_VERSION:
        raise SystemExit("unexpected apiVersion")
    if payload.get("kind") != "ProductionWorkloadRemeasurement":
        raise SystemExit("unexpected kind")
    if payload.get("provider") != PROVIDER or payload.get("tee_platform") != TEE_PLATFORM:
        raise SystemExit("unexpected Nitro provider metadata")
    expected_request_digest = sha256_prefixed(
        canonical_json(request_without_digest(payload)).encode("ascii")
    )
    if payload.get("request_digest") != expected_request_digest:
        raise SystemExit("request digest mismatch")
    documents, digests = state_documents()
    expected = require_exact(
        payload.get("expectedRemeasurements"),
        {
            "keyCustodySha256",
            "productionIdentitySha256",
            "promotedManifestSha256",
            "runtimeStateSha256",
        },
        "expected remeasurements",
    )
    validate_state(documents, digests, expected)
    binding = require_exact(
        payload.get("binding"),
        {"challenge", "requestSha256", "tlsBinding"},
        "request binding",
    )
    claims, nonce = build_claims(binding, documents, digests)
    return claims_user_data(claims), claims, nonce


def output_document(stdout: bytes, output_path: Path, output_format: str) -> bytes:
    if output_path.exists() and output_path.stat().st_size > 0:
        return output_path.read_bytes()
    if output_format == "raw":
        return stdout
    if output_format == "b64":
        return b64d(stdout.decode("utf-8").strip())
    if output_format == "json":
        parsed = json.loads(stdout.decode("utf-8"))
        if not isinstance(parsed, dict):
            raise SystemExit("NSM helper JSON output must be an object")
        raw_b64 = parsed.get("attestation_document_b64") or parsed.get("raw_attestation_document_b64")
        if not isinstance(raw_b64, str) or not raw_b64:
            raise SystemExit("NSM helper JSON output missing attestation_document_b64")
        return b64d(raw_b64)

    stripped = stdout.strip()
    if not stripped:
        raise SystemExit("NSM helper returned no attestation document")
    try:
        parsed = json.loads(stripped.decode("utf-8"))
        if isinstance(parsed, dict):
            raw_b64 = parsed.get("attestation_document_b64") or parsed.get("raw_attestation_document_b64")
            if isinstance(raw_b64, str) and raw_b64:
                return b64d(raw_b64)
    except Exception:
        pass
    try:
        return b64d(stripped.decode("utf-8"))
    except Exception:
        return bytes(stripped)


def run_nsm_helper(
    *,
    command_template: str,
    user_data: bytes,
    nonce: bytes,
    request_digest: str,
    output_format: str,
    timeout: float,
    max_document_bytes: int,
    allow_fixtures_for_test: bool,
) -> bytes:
    if not 0.1 <= timeout <= 30.0:
        raise SystemExit("Nitro NSM helper timeout is outside the accepted bound")
    if not 1024 <= max_document_bytes <= 1024 * 1024:
        raise SystemExit("Nitro attestation document bound is invalid")
    if not command_template.strip():
        raise SystemExit("--command-template or CATCHPLATE_NITRO_NSM_ATTEST_COMMAND_TEMPLATE is required")
    if "{user_data_path}" not in command_template or "{nonce_path}" not in command_template:
        raise SystemExit(
            "Nitro NSM helper must consume both {user_data_path} and {nonce_path}"
        )
    if allow_fixtures_for_test:
        raise SystemExit(
            "production Nitro attestation v2 never accepts fixture mode"
        )
    if command_mentions(command_template, "fixture", "nitro_attestation_fixture.py"):
        raise SystemExit("Nitro NSM attestation adapter must not use fixture helpers")

    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        user_data_path = tmp / "user-data.bin"
        nonce_path = tmp / "nonce.bin"
        output_path = tmp / "attestation.cbor"
        user_data_path.write_bytes(user_data)
        nonce_path.write_bytes(nonce)
        values = {
            "user_data_path": str(user_data_path),
            "user_data_b64": b64e(user_data),
            "user_data_sha256": sha256_prefixed(user_data),
            "nonce_path": str(nonce_path),
            "nonce_b64": b64e(nonce),
            "nonce_sha256": sha256_prefixed(nonce),
            "request_digest": request_digest,
            "output_path": str(output_path),
        }
        try:
            command = shlex.split(command_template.format(**values))
        except KeyError as exc:
            raise SystemExit(f"unknown command-template placeholder: {exc}") from exc
        except ValueError as exc:
            raise SystemExit(f"invalid command-template: {exc}") from exc
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", errors="replace") or result.stdout.decode("utf-8", errors="replace")
            raise SystemExit(f"Nitro NSM helper failed with exit {result.returncode}: {detail.strip()}")
        raw = output_document(result.stdout, output_path, output_format)
    if not raw:
        raise SystemExit("Nitro NSM helper returned an empty attestation document")
    if len(raw) > max_document_bytes:
        raise SystemExit("Nitro NSM helper returned an oversized attestation document")
    return raw


def attest(args: argparse.Namespace) -> None:
    payload = read_stdin()
    user_data, claims, nonce = validate_request(payload)
    template = args.command_template or os.getenv("CATCHPLATE_NITRO_NSM_ATTEST_COMMAND_TEMPLATE", "")
    raw = run_nsm_helper(
        command_template=template,
        user_data=user_data,
        nonce=nonce,
        request_digest=str(payload["request_digest"]),
        output_format=args.output_format,
        timeout=args.timeout,
        max_document_bytes=args.max_document_bytes,
        allow_fixtures_for_test=args.allow_fixtures_for_test,
    )
    parsed_document = parse_nitro_document(raw)
    expected_pcrs = claims["eif"]["pcrs"]
    if (
        parsed_document["nonce"] != nonce
        or parsed_document["userData"] != user_data
        or parsed_document["pcrs"] != expected_pcrs
        or parsed_document["debug"] is not False
    ):
        raise SystemExit(
            "raw Nitro COSE nonce, user_data, PCRs, or debug state differs from the request"
        )
    document_claims = {
        "debug": parsed_document["debug"],
        "nonceSha256": sha256_prefixed(parsed_document["nonce"]),
        "payloadSha256": parsed_document["payloadSha256"],
        "pcrs": parsed_document["pcrs"],
        "timestamp": parsed_document["timestamp"],
        "userDataSha256": sha256_prefixed(parsed_document["userData"]),
    }
    print(
        canonical_json(
            {
                "version": 2,
                "provider": "aws-nitro-nsm",
                "tee_platform": TEE_PLATFORM,
                "debug": parsed_document["debug"],
                "document_claims": document_claims,
                "request_digest": payload["request_digest"],
                "claims": claims,
                "user_data_sha256": sha256_prefixed(user_data),
                "attestation_document_b64": b64e(raw),
                "attestation_document_sha256": sha256_prefixed(raw),
            }
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize an in-enclave Nitro NSM attestation helper into Catchplate's quote command contract.")
    subparsers = parser.add_subparsers(dest="command")
    attest_parser = subparsers.add_parser("attest")
    attest_parser.add_argument("--command-template", default=None)
    attest_parser.add_argument("--output-format", choices=("auto", "raw", "b64", "json"), default=os.getenv("CATCHPLATE_NITRO_NSM_OUTPUT_FORMAT", "auto"))
    attest_parser.add_argument("--timeout", type=float, default=float(os.getenv("CATCHPLATE_NITRO_NSM_TIMEOUT_SECONDS", "10")))
    attest_parser.add_argument("--max-document-bytes", type=int, default=int(os.getenv("CATCHPLATE_NITRO_NSM_MAX_DOCUMENT_BYTES", str(1024 * 1024))))
    attest_parser.add_argument("--allow-fixtures-for-test", action="store_true")
    args = parser.parse_args()
    if args.command != "attest":
        raise SystemExit("usage: nitro_nsm_attest.py attest --command-template '...'")
    attest(args)


if __name__ == "__main__":
    main()
