#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import secrets
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

import serverware_source_tree
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


ROOT = Path(__file__).resolve().parent.parent
BUILD_API_VERSION = "serverware.productionImagesBuild/v2"
BUILD_KIND = "ProductionImagesBuild"
MANIFEST_API_VERSION = "serverware.reproducibleBuildManifest/v3"
MANIFEST_KIND = "ReproducibleBuildManifest"
VERIFICATION_API_VERSION = "serverware.reproducibleBuildVerification/v3"
VERIFICATION_KIND = "ReproducibleBuildVerification"
BUILD_EXECUTION_API_VERSION = "serverware.buildExecutionStatement/v1"
BUILD_EXECUTION_KIND = "BuildExecutionStatement"
CONTENT_ALGORITHM = "serverware.normalizedRootfs/v1"
RUST_BINARY_PATH = "usr/local/bin/serverware-decision-gate"
LAUNCHER_BINARY_PATH = "usr/local/libexec/serverware-production-launcher"
LAUNCH_AUTHORITY_FIELDS = (
    "launch_authority_key_id",
    "launch_authority_root_sha256",
)
EXPECTED_SERVICES = {
    "serverware-control": "Dockerfile.production",
    "serverware-decision-gate": "data-plane/decision-gate-rs/Dockerfile.production",
}
RUNTIME_EXPORT_EXCLUSIONS = (
    ".dockerenv",
    "etc/hostname",
    "etc/hosts",
    "etc/resolv.conf",
)
PUBLISH_REQUIREMENT = (
    "push these images to a registry and set SERVERWARE_PRODUCTION_IMAGES to immutable "
    "@sha256 digest refs before live readiness"
)
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
RFC3339_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
BUILDER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{2,127}$")
EXECUTION_NONCE_RE = re.compile(r"^[0-9a-f]{64}$")
SIGNATURE_ALGORITHM = "Ed25519"
BUILD_ISOLATION = "builder-attested-isolated-environment/v1"


class VerificationError(ValueError):
    pass


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_json(value).encode("utf-8"))


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            hasher.update(chunk)
    return "sha256:" + hasher.hexdigest()


def validate_builder_id(value: Any, label: str) -> str:
    builder_id = require_string(value, label)
    if not BUILDER_ID_RE.fullmatch(builder_id):
        raise VerificationError(
            f"{label} must be 3-128 ASCII identity characters from [A-Za-z0-9._:/@-]"
        )
    return builder_id


def public_key_id(public_key: Ed25519PublicKey) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256_bytes(der)


def load_private_signing_key(path: Path) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (OSError, TypeError, ValueError) as exc:
        raise VerificationError(f"could not load Ed25519 builder signing key {path}: {exc}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise VerificationError(f"builder signing key {path} is not Ed25519")
    return key


def load_trusted_public_key(path: Path, label: str) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(path.read_bytes())
    except (OSError, TypeError, ValueError) as exc:
        raise VerificationError(f"could not load {label} {path}: {exc}") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise VerificationError(f"{label} {path} is not Ed25519")
    return key


def manifest_body(document: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in document.items()
        if key not in {"attestation", "evidence_sha256"}
    }


def attestation_payload(document: dict[str, Any]) -> bytes:
    unsigned = {key: value for key, value in document.items() if key != "attestation"}
    return canonical_json(unsigned).encode("utf-8")


def sign_manifest(
    document: dict[str, Any], builder_id: str, signing_key: Ed25519PrivateKey
) -> dict[str, Any]:
    builder_id = validate_builder_id(builder_id, "builder identity")
    document.pop("attestation", None)
    document["evidence_sha256"] = sha256_json(manifest_body(document))
    payload = attestation_payload(document)
    public_key = signing_key.public_key()
    document["attestation"] = {
        "builder_id": builder_id,
        "key_id": public_key_id(public_key),
        "algorithm": SIGNATURE_ALGORITHM,
        "payload_sha256": sha256_bytes(payload),
        "signature": base64.b64encode(signing_key.sign(payload)).decode("ascii"),
    }
    return document


def validate_attestation_envelope(document: dict[str, Any]) -> dict[str, str]:
    attestation = require_exact_fields(
        document["attestation"],
        {"builder_id", "key_id", "algorithm", "payload_sha256", "signature"},
        "reproducibility attestation",
    )
    builder_id = validate_builder_id(
        attestation["builder_id"], "reproducibility attestation builder_id"
    )
    key_id = require_sha256(attestation["key_id"], "reproducibility attestation key_id")
    if attestation["algorithm"] != SIGNATURE_ALGORITHM:
        raise VerificationError("reproducibility attestation algorithm must be Ed25519")
    payload = attestation_payload(document)
    payload_digest = require_sha256(
        attestation["payload_sha256"], "reproducibility attestation payload_sha256"
    )
    if payload_digest != sha256_bytes(payload):
        raise VerificationError("reproducibility attestation payload_sha256 does not bind the manifest")
    signature_text = require_string(
        attestation["signature"], "reproducibility attestation signature"
    )
    try:
        signature = base64.b64decode(signature_text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise VerificationError("reproducibility attestation signature is not canonical base64") from exc
    if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != signature_text:
        raise VerificationError(
            "reproducibility attestation signature is not a canonical Ed25519 signature"
        )
    return {
        "builder_id": builder_id,
        "key_id": key_id,
        "payload_sha256": payload_digest,
        "signature": signature_text,
    }


def verify_manifest_attestation(
    document: dict[str, Any], trusted_builders: dict[str, Ed25519PublicKey]
) -> dict[str, Any]:
    envelope = validate_attestation_envelope(document)
    builder_id = envelope["builder_id"]
    public_key = trusted_builders.get(builder_id)
    if public_key is None:
        raise VerificationError(f"builder identity is not operator-trusted: {builder_id}")
    pinned_key_id = public_key_id(public_key)
    if envelope["key_id"] != pinned_key_id:
        raise VerificationError(
            f"builder attestation key ID does not match the operator-pinned key for {builder_id}"
        )
    signature = base64.b64decode(envelope["signature"], validate=True)
    try:
        public_key.verify(signature, attestation_payload(document))
    except InvalidSignature as exc:
        raise VerificationError(f"builder attestation signature is invalid for {builder_id}") from exc
    return {
        "builder_id": builder_id,
        "key_id": pinned_key_id,
        "payload_sha256": envelope["payload_sha256"],
        "signature_verified": True,
        "operator_trusted": True,
    }


def capture_body(document: dict[str, Any]) -> dict[str, Any]:
    return {
        key: document[key]
        for key in ("apiVersion", "kind", "scope", "source", "build_artifact", "images")
    }


def capture_identity(document: dict[str, Any]) -> str:
    return sha256_json(capture_body(document))


def execution_statement_payload(statement: dict[str, Any]) -> bytes:
    return canonical_json(statement).encode("utf-8")


def validate_command_argv(value: Any, label: str) -> list[str]:
    raw = require_list(value, label)
    if not raw or len(raw) > 256:
        raise VerificationError(f"{label} must contain 1-256 arguments")
    command: list[str] = []
    for index, argument in enumerate(raw):
        parsed = require_string(argument, f"{label}[{index}]")
        if len(parsed.encode("utf-8")) > 4096 or "\x00" in parsed:
            raise VerificationError(f"{label}[{index}] is not a supported command argument")
        command.append(parsed)
    return command


def build_recipe_inputs(manifest: dict[str, Any]) -> list[dict[str, str]]:
    inputs: list[dict[str, str]] = []
    for path in sorted({str(image["dockerfile"]) for image in manifest["images"]}):
        recipe_path = ROOT / path
        try:
            digest = sha256_file(recipe_path)
        except OSError as exc:
            raise VerificationError(f"could not hash build recipe input {path}: {exc}") from exc
        inputs.append({"path": path, "sha256": digest})
    return inputs


def sign_build_execution(
    manifest: dict[str, Any],
    *,
    builder_id: str,
    signing_key: Ed25519PrivateKey,
    build_command: list[str],
    build_environment_id: str,
    execution_nonce: str,
    source_clean: bool,
) -> dict[str, Any]:
    builder_id = validate_builder_id(builder_id, "build execution builder identity")
    command = validate_command_argv(build_command, "build execution recipe argv")
    environment_id = require_sha256(
        build_environment_id, "build execution environment identity"
    )
    if source_clean is not True:
        raise VerificationError("build execution source must be a clean checkout")
    if not EXECUTION_NONCE_RE.fullmatch(execution_nonce) or set(execution_nonce) == {"0"}:
        raise VerificationError(
            "build execution nonce must be 64 lowercase hex characters and not all zero"
        )
    public_key = signing_key.public_key()
    statement = {
        "apiVersion": BUILD_EXECUTION_API_VERSION,
        "kind": BUILD_EXECUTION_KIND,
        "builder": {
            "id": builder_id,
            "key_id": public_key_id(public_key),
        },
        "source": {**manifest["source"], "clean": True},
        "recipe": {
            "working_directory": ".",
            "argv": command,
            "argv_sha256": sha256_json(command),
            "inputs": build_recipe_inputs(manifest),
        },
        "environment": {
            "isolation": BUILD_ISOLATION,
            "identity": environment_id,
        },
        "execution_nonce": execution_nonce,
        "result": {
            "build_artifact_sha256": manifest["build_artifact"]["sha256"],
            "capture_sha256": capture_identity(manifest),
        },
    }
    payload = execution_statement_payload(statement)
    manifest["build_execution"] = {
        "statement": statement,
        "attestation": {
            "algorithm": SIGNATURE_ALGORITHM,
            "payload_sha256": sha256_bytes(payload),
            "signature": base64.b64encode(signing_key.sign(payload)).decode("ascii"),
        },
    }
    return manifest


def validate_build_execution(manifest: dict[str, Any]) -> dict[str, str]:
    execution = require_exact_fields(
        manifest["build_execution"],
        {"statement", "attestation"},
        "build execution",
    )
    statement = require_exact_fields(
        execution["statement"],
        {
            "apiVersion",
            "kind",
            "builder",
            "source",
            "recipe",
            "environment",
            "execution_nonce",
            "result",
        },
        "build execution statement",
    )
    if (
        statement["apiVersion"] != BUILD_EXECUTION_API_VERSION
        or statement["kind"] != BUILD_EXECUTION_KIND
    ):
        raise VerificationError("build execution statement type is unsupported")

    builder = require_exact_fields(
        statement["builder"], {"id", "key_id"}, "build execution statement builder"
    )
    builder_id = validate_builder_id(builder["id"], "build execution statement builder id")
    key_id = require_sha256(builder["key_id"], "build execution statement builder key_id")

    source = require_exact_fields(
        statement["source"],
        {*manifest["source"], "clean"},
        "build execution statement source",
    )
    expected_source = {**manifest["source"], "clean": True}
    if source != expected_source:
        raise VerificationError(
            "build execution statement source does not bind the clean captured source identity"
        )

    recipe = require_exact_fields(
        statement["recipe"],
        {"working_directory", "argv", "argv_sha256", "inputs"},
        "build execution statement recipe",
    )
    if recipe["working_directory"] != ".":
        raise VerificationError("build execution statement working_directory must be the source root")
    argv = validate_command_argv(recipe["argv"], "build execution statement recipe argv")
    argv_sha256 = require_sha256(
        recipe["argv_sha256"], "build execution statement recipe argv_sha256"
    )
    if argv_sha256 != sha256_json(argv):
        raise VerificationError("build execution statement argv_sha256 does not bind argv")
    inputs = require_list(recipe["inputs"], "build execution statement recipe inputs")
    normalized_inputs: list[dict[str, str]] = []
    for index, raw_input in enumerate(inputs):
        label = f"build execution statement recipe inputs[{index}]"
        item = require_exact_fields(raw_input, {"path", "sha256"}, label)
        normalized_inputs.append(
            {
                "path": validate_relative_path(item["path"], f"{label}.path"),
                "sha256": require_sha256(item["sha256"], f"{label}.sha256"),
            }
        )
    if normalized_inputs != build_recipe_inputs(manifest):
        raise VerificationError(
            "build execution statement recipe inputs do not bind the captured Dockerfiles"
        )

    environment = require_exact_fields(
        statement["environment"],
        {"isolation", "identity"},
        "build execution statement environment",
    )
    if environment["isolation"] != BUILD_ISOLATION:
        raise VerificationError("build execution statement isolation contract is unsupported")
    environment_id = require_sha256(
        environment["identity"], "build execution statement environment identity"
    )

    execution_nonce = require_string(
        statement["execution_nonce"], "build execution statement execution_nonce"
    )
    if not EXECUTION_NONCE_RE.fullmatch(execution_nonce) or set(execution_nonce) == {"0"}:
        raise VerificationError(
            "build execution statement execution_nonce must be 64 lowercase hex characters and not all zero"
        )

    result = require_exact_fields(
        statement["result"],
        {"build_artifact_sha256", "capture_sha256"},
        "build execution statement result",
    )
    artifact_sha256 = require_sha256(
        result["build_artifact_sha256"],
        "build execution statement result build_artifact_sha256",
    )
    if artifact_sha256 != manifest["build_artifact"]["sha256"]:
        raise VerificationError("build execution statement does not bind the v2 build artifact")
    capture_sha256 = require_sha256(
        result["capture_sha256"], "build execution statement result capture_sha256"
    )
    if capture_sha256 != capture_identity(manifest):
        raise VerificationError("build execution statement does not bind the completed capture")

    attestation = require_exact_fields(
        execution["attestation"],
        {"algorithm", "payload_sha256", "signature"},
        "build execution attestation",
    )
    if attestation["algorithm"] != SIGNATURE_ALGORITHM:
        raise VerificationError("build execution attestation algorithm must be Ed25519")
    payload = execution_statement_payload(statement)
    payload_sha256 = require_sha256(
        attestation["payload_sha256"], "build execution attestation payload_sha256"
    )
    if payload_sha256 != sha256_bytes(payload):
        raise VerificationError("build execution attestation payload_sha256 does not bind the statement")
    signature_text = require_string(
        attestation["signature"], "build execution attestation signature"
    )
    try:
        signature = base64.b64decode(signature_text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise VerificationError("build execution attestation signature is not canonical base64") from exc
    if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != signature_text:
        raise VerificationError(
            "build execution attestation signature is not a canonical Ed25519 signature"
        )
    return {
        "builder_id": builder_id,
        "key_id": key_id,
        "execution_nonce": execution_nonce,
        "environment_id": environment_id,
        "argv_sha256": argv_sha256,
        "build_artifact_sha256": artifact_sha256,
        "capture_sha256": capture_sha256,
        "payload_sha256": payload_sha256,
        "signature": signature_text,
    }


def verify_build_execution(
    manifest: dict[str, Any], trusted_builders: dict[str, Ed25519PublicKey]
) -> dict[str, Any]:
    execution = validate_build_execution(manifest)
    builder_id = execution["builder_id"]
    public_key = trusted_builders.get(builder_id)
    if public_key is None:
        raise VerificationError(f"build execution builder is not operator-trusted: {builder_id}")
    pinned_key_id = public_key_id(public_key)
    if execution["key_id"] != pinned_key_id:
        raise VerificationError(
            f"build execution key ID does not match the operator-pinned key for {builder_id}"
        )
    statement = manifest["build_execution"]["statement"]
    signature = base64.b64decode(execution["signature"], validate=True)
    try:
        public_key.verify(signature, execution_statement_payload(statement))
    except InvalidSignature as exc:
        raise VerificationError(f"build execution signature is invalid for {builder_id}") from exc
    return {
        key: execution[key]
        for key in (
            "builder_id",
            "key_id",
            "execution_nonce",
            "environment_id",
            "argv_sha256",
            "build_artifact_sha256",
            "capture_sha256",
            "payload_sha256",
        )
    } | {"signature_verified": True, "operator_trusted": True, "source_clean": True}


def reject_constant(value: str) -> None:
    raise VerificationError(f"JSON constants are not permitted: {value}")


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def parse_json_bytes(raw: bytes, label: str) -> Any:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VerificationError(f"{label} is not UTF-8 JSON") from exc
    try:
        return json.loads(text, object_pairs_hook=reject_duplicate_keys, parse_constant=reject_constant)
    except VerificationError:
        raise
    except json.JSONDecodeError as exc:
        raise VerificationError(f"{label} is not valid JSON: {exc.msg}") from exc


def load_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise VerificationError(f"could not read {label} {path}: {exc}") from exc
    parsed = parse_json_bytes(raw, label)
    if type(parsed) is not dict:
        raise VerificationError(f"{label} must be a JSON object")
    return parsed, raw


def require_exact_fields(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise VerificationError(f"{label} must be an object")
    actual = set(value)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing or extra:
        details = []
        if missing:
            details.append(f"missing={missing}")
        if extra:
            details.append(f"extra={extra}")
        raise VerificationError(f"{label} fields do not match the contract: {' '.join(details)}")
    return value


def require_string(value: Any, label: str) -> str:
    if type(value) is not str or not value:
        raise VerificationError(f"{label} must be a non-empty string")
    return value


def require_bool(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise VerificationError(f"{label} must be a boolean")
    return value


def require_int(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise VerificationError(f"{label} must be an integer >= {minimum}")
    return value


def require_sha256(value: Any, label: str) -> str:
    if type(value) is not str or not SHA256_RE.fullmatch(value):
        raise VerificationError(f"{label} must be sha256:<64 lowercase hex>")
    return value


def require_list(value: Any, label: str) -> list[Any]:
    if type(value) is not list:
        raise VerificationError(f"{label} must be an array")
    return value


def validate_relative_path(value: Any, label: str) -> str:
    raw = require_string(value, label)
    if "\\" in raw or raw.startswith("/"):
        raise VerificationError(f"{label} must be a normalized relative POSIX path")
    path = PurePosixPath(raw)
    if raw != path.as_posix() or any(part in {"", ".", ".."} for part in path.parts):
        raise VerificationError(f"{label} must be a normalized relative POSIX path")
    return raw


def created_from_epoch(epoch: int, label: str) -> str:
    try:
        return datetime.fromtimestamp(epoch, timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    except (OSError, OverflowError, ValueError) as exc:
        raise VerificationError(f"{label} is outside the supported timestamp range") from exc


def validate_build_artifact(document: dict[str, Any]) -> dict[str, Any]:
    require_exact_fields(
        document,
        {
            "apiVersion",
            "kind",
            "ok",
            "generated_at_unix",
            "metadata",
            "images",
            "no_shell",
            "publish_requirement",
        },
        "production build artifact",
    )
    if document["apiVersion"] != BUILD_API_VERSION or document["kind"] != BUILD_KIND:
        raise VerificationError(f"production build artifact type is not {BUILD_API_VERSION}")
    if document["ok"] is not True:
        raise VerificationError("production build artifact is not ok")
    require_int(document["generated_at_unix"], "production build generated_at_unix")
    if document["publish_requirement"] != PUBLISH_REQUIREMENT:
        raise VerificationError("production build publish_requirement does not match the production contract")

    metadata = require_exact_fields(
        document["metadata"],
        {
            "source",
            "revision",
            "created",
            "source_date_epoch",
            "source_tree_digest",
            *LAUNCH_AUTHORITY_FIELDS,
        },
        "production build metadata",
    )
    repository = require_string(metadata["source"], "production build metadata source")
    revision = require_string(metadata["revision"], "production build metadata revision")
    if not REVISION_RE.fullmatch(revision):
        raise VerificationError("production build metadata revision must be a full lowercase Git object ID")
    created = require_string(metadata["created"], "production build metadata created")
    if not RFC3339_UTC_RE.fullmatch(created):
        raise VerificationError("production build metadata created must be whole-second UTC RFC3339")
    epoch_raw = require_string(metadata["source_date_epoch"], "production build metadata source_date_epoch")
    if not epoch_raw.isascii() or not epoch_raw.isdigit():
        raise VerificationError("production build metadata source_date_epoch must be a non-negative decimal string")
    epoch = int(epoch_raw)
    expected_created = created_from_epoch(epoch, "production build metadata source_date_epoch")
    if created != expected_created:
        raise VerificationError("production build metadata created does not match source_date_epoch")
    source_tree_digest = require_sha256(
        metadata["source_tree_digest"], "production build metadata source_tree_digest"
    )
    launch_authority = {
        field: require_sha256(metadata[field], f"production build metadata {field}")
        for field in LAUNCH_AUTHORITY_FIELDS
    }

    images = require_list(document["images"], "production build images")
    if len(images) != len(EXPECTED_SERVICES):
        raise VerificationError("production build images must contain exactly the control and decision-gate services")
    normalized_images: list[dict[str, Any]] = []
    seen_services: set[str] = set()
    for index, raw_image in enumerate(images):
        label = f"production build images[{index}]"
        if type(raw_image) is not dict:
            raise VerificationError(f"{label} must be an object")
        service_value = raw_image.get("service")
        service = require_string(service_value, f"{label}.service")
        if service not in EXPECTED_SERVICES:
            raise VerificationError(f"{label}.service is not an expected production service: {service}")
        if service in seen_services:
            raise VerificationError(f"production build has duplicate service: {service}")
        seen_services.add(service)
        expected_fields = {"service", "tag", "dockerfile", "image_id"}
        if service == "serverware-decision-gate":
            expected_fields |= {
                "binary_digest",
                "launcher_binary_digest",
                *LAUNCH_AUTHORITY_FIELDS,
            }
        require_exact_fields(raw_image, expected_fields, label)
        dockerfile = validate_relative_path(raw_image["dockerfile"], f"{label}.dockerfile")
        if dockerfile != EXPECTED_SERVICES[service]:
            raise VerificationError(f"{label}.dockerfile does not match the production service contract")
        tag = require_string(raw_image["tag"], f"{label}.tag")
        if any(character.isspace() for character in tag):
            raise VerificationError(f"{label}.tag must not contain whitespace")
        image_id = require_sha256(raw_image["image_id"], f"{label}.image_id")
        normalized = {
            "service": service,
            "dockerfile": dockerfile,
            "image_ref": tag,
            "image_id": image_id,
        }
        if service == "serverware-decision-gate":
            normalized["declared_rust_binary_sha256"] = require_sha256(
                raw_image["binary_digest"], f"{label}.binary_digest"
            )
            normalized["declared_launcher_binary_sha256"] = require_sha256(
                raw_image["launcher_binary_digest"], f"{label}.launcher_binary_digest"
            )
            for field in LAUNCH_AUTHORITY_FIELDS:
                normalized[field] = require_sha256(raw_image[field], f"{label}.{field}")
                if normalized[field] != launch_authority[field]:
                    raise VerificationError(
                        f"{label}.{field} does not match production build metadata"
                    )
        normalized_images.append(normalized)
    if seen_services != set(EXPECTED_SERVICES):
        raise VerificationError("production build service set does not match the production contract")

    no_shell = require_exact_fields(
        document["no_shell"],
        {"ok", "production_images_no_shell", "results", "failures"},
        "production build no_shell",
    )
    if no_shell["ok"] is not True or no_shell["production_images_no_shell"] != "pass":
        raise VerificationError("production build no_shell result is not a pass")
    failures = require_list(no_shell["failures"], "production build no_shell failures")
    if failures:
        raise VerificationError("production build no_shell failures must be empty")
    results = require_list(no_shell["results"], "production build no_shell results")
    if len(results) != len(normalized_images):
        raise VerificationError("production build no_shell results must cover every production image exactly once")
    expected_image_ids = {str(image["image_id"]) for image in normalized_images}
    result_image_ids: set[str] = set()
    for index, result in enumerate(results):
        label = f"production build no_shell results[{index}]"
        require_exact_fields(result, {"image", "ok", "forbidden_shell_paths"}, label)
        image_id = require_sha256(result["image"], f"{label}.image")
        if image_id in result_image_ids:
            raise VerificationError(f"production build no_shell has duplicate image result: {image_id}")
        result_image_ids.add(image_id)
        if result["ok"] is not True:
            raise VerificationError(f"{label}.ok is not true")
        forbidden = require_list(result["forbidden_shell_paths"], f"{label}.forbidden_shell_paths")
        if forbidden:
            raise VerificationError(f"{label}.forbidden_shell_paths must be empty")
    if result_image_ids != expected_image_ids:
        raise VerificationError("production build no_shell image IDs do not match the production build images")

    return {
        "source": {
            "repository": repository,
            "revision": revision,
            "created": created,
            "source_date_epoch": epoch_raw,
            "tree_sha256": source_tree_digest,
            **launch_authority,
        },
        "images": sorted(normalized_images, key=lambda item: str(item["service"])),
    }


def normalize_tar_path(name: str, label: str) -> str | None:
    if not name or "\x00" in name or "\\" in name or name.startswith("/"):
        raise VerificationError(f"{label} contains an unsafe path: {name!r}")
    while name.startswith("./"):
        name = name[2:]
    name = name.rstrip("/")
    if not name or name == ".":
        return None
    path = PurePosixPath(name)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise VerificationError(f"{label} contains an unsafe path: {name!r}")
    normalized = path.as_posix()
    if normalized.startswith("../"):
        raise VerificationError(f"{label} contains an unsafe path: {name!r}")
    return normalized


def normalized_xattrs(member: tarfile.TarInfo, label: str) -> dict[str, str]:
    result: dict[str, str] = {}
    prefixes = ("SCHILY.xattr.", "LIBARCHIVE.xattr.")
    for key, value in member.pax_headers.items():
        matching = next((prefix for prefix in prefixes if key.startswith(prefix)), None)
        if matching is None:
            continue
        name = key[len(matching) :]
        if not name or "\x00" in name:
            raise VerificationError(f"{label} contains an invalid extended-attribute name")
        if name in result and result[name] != value:
            raise VerificationError(f"{label} contains conflicting extended attribute values for {name}")
        result[name] = str(value)
    return dict(sorted(result.items()))


def rootfs_manifest(path: Path) -> dict[str, Any]:
    entries_by_path: dict[str, dict[str, Any]] = {}
    try:
        archive = tarfile.open(path, mode="r:*")
    except (OSError, tarfile.TarError) as exc:
        raise VerificationError(f"could not open rootfs archive {path}: {exc}") from exc
    with archive:
        for member in archive:
            normalized_path = normalize_tar_path(member.name, f"rootfs archive {path}")
            if normalized_path is None or normalized_path in RUNTIME_EXPORT_EXCLUSIONS:
                continue
            if normalized_path in entries_by_path:
                raise VerificationError(f"rootfs archive {path} contains duplicate path: {normalized_path}")
            label = f"rootfs archive {path} path {normalized_path}"
            common: dict[str, Any] = {
                "path": normalized_path,
                "mode": member.mode & 0o7777,
                "uid": require_int(member.uid, f"{label} uid"),
                "gid": require_int(member.gid, f"{label} gid"),
                "xattrs": normalized_xattrs(member, label),
            }
            if member.isfile():
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise VerificationError(f"{label} is not readable as a regular file")
                hasher = hashlib.sha256()
                size = 0
                while chunk := extracted.read(1024 * 1024):
                    size += len(chunk)
                    hasher.update(chunk)
                if size != member.size:
                    raise VerificationError(f"{label} size does not match its tar header")
                entry = {
                    **common,
                    "type": "file",
                    "size": size,
                    "sha256": "sha256:" + hasher.hexdigest(),
                }
            elif member.isdir():
                entry = {**common, "type": "directory"}
            elif member.issym():
                entry = {**common, "type": "symlink", "link_target": member.linkname}
            elif member.islnk():
                target = normalize_tar_path(member.linkname, f"{label} hardlink")
                if target is None:
                    raise VerificationError(f"{label} has an invalid empty hardlink target")
                entry = {**common, "type": "hardlink", "link_target": target}
            elif member.ischr():
                entry = {
                    **common,
                    "type": "character-device",
                    "device_major": require_int(member.devmajor, f"{label} device_major"),
                    "device_minor": require_int(member.devminor, f"{label} device_minor"),
                }
            elif member.isblk():
                entry = {
                    **common,
                    "type": "block-device",
                    "device_major": require_int(member.devmajor, f"{label} device_major"),
                    "device_minor": require_int(member.devminor, f"{label} device_minor"),
                }
            elif member.isfifo():
                entry = {**common, "type": "fifo"}
            else:
                raise VerificationError(f"{label} has unsupported tar entry type {member.type!r}")
            entries_by_path[normalized_path] = entry

    for entry in entries_by_path.values():
        if entry["type"] != "hardlink":
            continue
        target = str(entry["link_target"])
        if target not in entries_by_path:
            raise VerificationError(f"rootfs hardlink target is missing: {entry['path']} -> {target}")
        if entries_by_path[target]["type"] not in {"file", "hardlink"}:
            raise VerificationError(f"rootfs hardlink target is not file-like: {entry['path']} -> {target}")

    entries = [entries_by_path[name] for name in sorted(entries_by_path)]
    return {
        "algorithm": CONTENT_ALGORITHM,
        "excluded_runtime_paths": list(RUNTIME_EXPORT_EXCLUSIONS),
        "entry_count": len(entries),
        "entries_sha256": sha256_json(entries),
        "entries": entries,
    }


def regular_file_from_content(
    content: dict[str, Any], path: str, label: str
) -> dict[str, str]:
    matches = [entry for entry in content["entries"] if entry.get("path") == path]
    if len(matches) != 1 or matches[0].get("type") != "file":
        raise VerificationError(
            f"decision-gate rootfs must contain one regular {label} at /{path}"
        )
    return {
        "path": "/" + path,
        "sha256": require_sha256(matches[0].get("sha256"), f"{label} digest"),
    }


def rust_binary_from_content(content: dict[str, Any]) -> dict[str, str]:
    return regular_file_from_content(content, RUST_BINARY_PATH, "Rust binary")


def launcher_binary_from_content(content: dict[str, Any]) -> dict[str, str]:
    return regular_file_from_content(content, LAUNCHER_BINARY_PATH, "launcher binary")


def build_manifest_from_archives(
    build: dict[str, Any],
    build_raw: bytes,
    archives: dict[str, Path],
    *,
    engine_image_id_verified: bool,
    source_labels_verified: bool,
    builder_id: str,
    signing_key: Ed25519PrivateKey,
    build_command: list[str],
    build_environment_id: str,
    execution_nonce: str,
    source_clean: bool,
) -> dict[str, Any]:
    normalized_build = validate_build_artifact(build)
    if set(archives) != set(EXPECTED_SERVICES):
        raise VerificationError("rootfs archives must cover exactly the control and decision-gate services")
    images: list[dict[str, Any]] = []
    for build_image in normalized_build["images"]:
        service = str(build_image["service"])
        archive_path = archives[service]
        content = rootfs_manifest(archive_path)
        image = {
            **build_image,
            "capture": {
                "method": "docker-export-v1",
                "rootfs_archive_sha256": sha256_file(archive_path),
                "engine_image_id_verified": engine_image_id_verified,
                "source_labels_verified": source_labels_verified,
            },
            "content": content,
        }
        if service == "serverware-decision-gate":
            rust_binary = rust_binary_from_content(content)
            if rust_binary["sha256"] != image["declared_rust_binary_sha256"]:
                raise VerificationError(
                    "extracted decision-gate Rust binary digest does not match the production build artifact"
                )
            image["rust_binary"] = rust_binary
            launcher_binary = launcher_binary_from_content(content)
            if launcher_binary["sha256"] != image["declared_launcher_binary_sha256"]:
                raise VerificationError(
                    "extracted decision-gate launcher binary digest does not match the production build artifact"
                )
            image["launcher_binary_sha256"] = launcher_binary["sha256"]
        images.append(image)
    manifest: dict[str, Any] = {
        "apiVersion": MANIFEST_API_VERSION,
        "kind": MANIFEST_KIND,
        "scope": {
            "artifact_reproducibility_only": True,
            "independent_execution_proven": False,
            "hardware_proof": False,
        },
        "source": normalized_build["source"],
        "build_artifact": {
            "sha256": sha256_bytes(build_raw),
            "apiVersion": BUILD_API_VERSION,
            "kind": BUILD_KIND,
            "no_shell_passed": True,
        },
        "images": images,
    }
    sign_build_execution(
        manifest,
        builder_id=builder_id,
        signing_key=signing_key,
        build_command=build_command,
        build_environment_id=build_environment_id,
        execution_nonce=execution_nonce,
        source_clean=source_clean,
    )
    return sign_manifest(manifest, builder_id, signing_key)


ENTRY_COMMON_FIELDS = {"path", "type", "mode", "uid", "gid", "xattrs"}
ENTRY_TYPE_FIELDS = {
    "file": {"size", "sha256"},
    "directory": set(),
    "symlink": {"link_target"},
    "hardlink": {"link_target"},
    "character-device": {"device_major", "device_minor"},
    "block-device": {"device_major", "device_minor"},
    "fifo": set(),
}


def validate_content(content: Any, label: str) -> dict[str, Any]:
    content = require_exact_fields(
        content,
        {"algorithm", "excluded_runtime_paths", "entry_count", "entries_sha256", "entries"},
        label,
    )
    if content["algorithm"] != CONTENT_ALGORITHM:
        raise VerificationError(f"{label}.algorithm is unsupported")
    if content["excluded_runtime_paths"] != list(RUNTIME_EXPORT_EXCLUSIONS):
        raise VerificationError(f"{label}.excluded_runtime_paths does not match the normalization contract")
    entries = require_list(content["entries"], f"{label}.entries")
    if require_int(content["entry_count"], f"{label}.entry_count") != len(entries):
        raise VerificationError(f"{label}.entry_count does not match entries")
    paths: list[str] = []
    for index, entry_value in enumerate(entries):
        entry_label = f"{label}.entries[{index}]"
        if type(entry_value) is not dict:
            raise VerificationError(f"{entry_label} must be an object")
        entry_type = require_string(entry_value.get("type"), f"{entry_label}.type")
        if entry_type not in ENTRY_TYPE_FIELDS:
            raise VerificationError(f"{entry_label}.type is unsupported: {entry_type}")
        entry = require_exact_fields(entry_value, ENTRY_COMMON_FIELDS | ENTRY_TYPE_FIELDS[entry_type], entry_label)
        path = validate_relative_path(entry["path"], f"{entry_label}.path")
        if path in RUNTIME_EXPORT_EXCLUSIONS:
            raise VerificationError(f"{entry_label}.path is a normalized runtime exclusion")
        paths.append(path)
        mode = require_int(entry["mode"], f"{entry_label}.mode")
        if mode > 0o7777:
            raise VerificationError(f"{entry_label}.mode exceeds supported Unix permission bits")
        require_int(entry["uid"], f"{entry_label}.uid")
        require_int(entry["gid"], f"{entry_label}.gid")
        xattrs = entry["xattrs"]
        if type(xattrs) is not dict:
            raise VerificationError(f"{entry_label}.xattrs must be an object")
        for name, value in xattrs.items():
            require_string(name, f"{entry_label}.xattrs key")
            if type(value) is not str:
                raise VerificationError(f"{entry_label}.xattrs[{name!r}] must be a string")
        if entry_type == "file":
            require_int(entry["size"], f"{entry_label}.size")
            require_sha256(entry["sha256"], f"{entry_label}.sha256")
        elif entry_type in {"symlink", "hardlink"}:
            link_target = require_string(entry["link_target"], f"{entry_label}.link_target")
            if "\x00" in link_target:
                raise VerificationError(f"{entry_label}.link_target must not contain NUL")
            if entry_type == "hardlink":
                validate_relative_path(link_target, f"{entry_label}.link_target")
        elif entry_type in {"character-device", "block-device"}:
            require_int(entry["device_major"], f"{entry_label}.device_major")
            require_int(entry["device_minor"], f"{entry_label}.device_minor")
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise VerificationError(f"{label}.entries must have unique paths in lexical order")
    entries_by_path = {str(entry["path"]): entry for entry in entries}
    for entry in entries:
        if entry["type"] != "hardlink":
            continue
        visited = {str(entry["path"])}
        target = str(entry["link_target"])
        while True:
            target_entry = entries_by_path.get(target)
            if target_entry is None:
                raise VerificationError(f"{label} hardlink target is missing: {entry['path']} -> {target}")
            if target_entry["type"] == "file":
                break
            if target_entry["type"] != "hardlink":
                raise VerificationError(f"{label} hardlink target is not file-like: {entry['path']} -> {target}")
            if target in visited:
                raise VerificationError(f"{label} contains a hardlink cycle involving {target}")
            visited.add(target)
            target = str(target_entry["link_target"])
    expected_digest = sha256_json(entries)
    declared_digest = require_sha256(content["entries_sha256"], f"{label}.entries_sha256")
    if declared_digest != expected_digest:
        raise VerificationError(f"{label}.entries_sha256 does not match the normalized entries")
    return content


def validate_manifest(document: dict[str, Any]) -> dict[str, Any]:
    require_exact_fields(
        document,
        {
            "apiVersion",
            "kind",
            "scope",
            "source",
            "build_artifact",
            "images",
            "build_execution",
            "evidence_sha256",
            "attestation",
        },
        "reproducibility manifest",
    )
    if document["apiVersion"] != MANIFEST_API_VERSION or document["kind"] != MANIFEST_KIND:
        raise VerificationError("reproducibility manifest type is unsupported")
    declared_evidence_digest = require_sha256(document["evidence_sha256"], "reproducibility evidence_sha256")
    if declared_evidence_digest != sha256_json(manifest_body(document)):
        raise VerificationError("reproducibility evidence_sha256 does not bind the complete manifest")
    validate_attestation_envelope(document)
    scope = require_exact_fields(
        document["scope"],
        {"artifact_reproducibility_only", "independent_execution_proven", "hardware_proof"},
        "reproducibility scope",
    )
    if (
        scope["artifact_reproducibility_only"] is not True
        or scope["independent_execution_proven"] is not False
        or scope["hardware_proof"] is not False
    ):
        raise VerificationError("reproducibility scope must not claim independent execution or hardware proof")
    source = require_exact_fields(
        document["source"],
        {
            "repository",
            "revision",
            "created",
            "source_date_epoch",
            "tree_sha256",
            *LAUNCH_AUTHORITY_FIELDS,
        },
        "reproducibility source",
    )
    require_string(source["repository"], "reproducibility source repository")
    revision = require_string(source["revision"], "reproducibility source revision")
    if not REVISION_RE.fullmatch(revision):
        raise VerificationError("reproducibility source revision must be a full lowercase Git object ID")
    created = require_string(source["created"], "reproducibility source created")
    epoch_raw = require_string(source["source_date_epoch"], "reproducibility source source_date_epoch")
    if not RFC3339_UTC_RE.fullmatch(created) or not epoch_raw.isascii() or not epoch_raw.isdigit():
        raise VerificationError("reproducibility source timestamp fields are malformed")
    expected_created = created_from_epoch(int(epoch_raw), "reproducibility source source_date_epoch")
    if created != expected_created:
        raise VerificationError("reproducibility source created does not match source_date_epoch")
    require_sha256(source["tree_sha256"], "reproducibility source tree_sha256")
    source_launch_authority = {
        field: require_sha256(source[field], f"reproducibility source {field}")
        for field in LAUNCH_AUTHORITY_FIELDS
    }
    build_artifact = require_exact_fields(
        document["build_artifact"],
        {"sha256", "apiVersion", "kind", "no_shell_passed"},
        "reproducibility build_artifact",
    )
    require_sha256(build_artifact["sha256"], "reproducibility build_artifact sha256")
    if (
        build_artifact["apiVersion"] != BUILD_API_VERSION
        or build_artifact["kind"] != BUILD_KIND
        or build_artifact["no_shell_passed"] is not True
    ):
        raise VerificationError("reproducibility build_artifact contract is not a passing production build")

    images = require_list(document["images"], "reproducibility images")
    if len(images) != len(EXPECTED_SERVICES):
        raise VerificationError("reproducibility images must contain exactly two production services")
    seen_services: set[str] = set()
    for index, image_value in enumerate(images):
        label = f"reproducibility images[{index}]"
        if type(image_value) is not dict:
            raise VerificationError(f"{label} must be an object")
        service = require_string(image_value.get("service"), f"{label}.service")
        if service not in EXPECTED_SERVICES or service in seen_services:
            raise VerificationError(f"{label}.service is unexpected or duplicated: {service}")
        seen_services.add(service)
        expected_fields = {"service", "dockerfile", "image_ref", "image_id", "capture", "content"}
        if service == "serverware-decision-gate":
            expected_fields |= {
                "declared_rust_binary_sha256",
                "rust_binary",
                "declared_launcher_binary_sha256",
                "launcher_binary_sha256",
                *LAUNCH_AUTHORITY_FIELDS,
            }
        image = require_exact_fields(image_value, expected_fields, label)
        dockerfile = validate_relative_path(image["dockerfile"], f"{label}.dockerfile")
        if dockerfile != EXPECTED_SERVICES[service]:
            raise VerificationError(f"{label}.dockerfile does not match the production contract")
        image_ref = require_string(image["image_ref"], f"{label}.image_ref")
        if any(character.isspace() for character in image_ref):
            raise VerificationError(f"{label}.image_ref must not contain whitespace")
        require_sha256(image["image_id"], f"{label}.image_id")
        capture = require_exact_fields(
            image["capture"],
            {"method", "rootfs_archive_sha256", "engine_image_id_verified", "source_labels_verified"},
            f"{label}.capture",
        )
        if capture["method"] != "docker-export-v1":
            raise VerificationError(f"{label}.capture.method is unsupported")
        require_sha256(capture["rootfs_archive_sha256"], f"{label}.capture.rootfs_archive_sha256")
        if require_bool(capture["engine_image_id_verified"], f"{label}.capture.engine_image_id_verified") is not True:
            raise VerificationError(f"{label}.capture did not verify the image ID through the container engine")
        if require_bool(capture["source_labels_verified"], f"{label}.capture.source_labels_verified") is not True:
            raise VerificationError(f"{label}.capture did not verify source metadata against the image config")
        content = validate_content(image["content"], f"{label}.content")
        if service == "serverware-decision-gate":
            declared = require_sha256(
                image["declared_rust_binary_sha256"], f"{label}.declared_rust_binary_sha256"
            )
            rust = require_exact_fields(image["rust_binary"], {"path", "sha256"}, f"{label}.rust_binary")
            if rust["path"] != "/" + RUST_BINARY_PATH:
                raise VerificationError(f"{label}.rust_binary.path does not match the production executable")
            extracted = require_sha256(rust["sha256"], f"{label}.rust_binary.sha256")
            content_binary = rust_binary_from_content(content)["sha256"]
            if len({declared, extracted, content_binary}) != 1:
                raise VerificationError(f"{label} Rust binary digests do not match")
            declared_launcher = require_sha256(
                image["declared_launcher_binary_sha256"],
                f"{label}.declared_launcher_binary_sha256",
            )
            extracted_launcher = require_sha256(
                image["launcher_binary_sha256"], f"{label}.launcher_binary_sha256"
            )
            content_launcher = launcher_binary_from_content(content)["sha256"]
            if len({declared_launcher, extracted_launcher, content_launcher}) != 1:
                raise VerificationError(f"{label} launcher binary digests do not match")
            for field in LAUNCH_AUTHORITY_FIELDS:
                image_binding = require_sha256(image[field], f"{label}.{field}")
                if image_binding != source_launch_authority[field]:
                    raise VerificationError(
                        f"{label}.{field} does not match reproducibility source metadata"
                    )
    if seen_services != set(EXPECTED_SERVICES):
        raise VerificationError("reproducibility manifest service set does not match the production contract")
    if [image["service"] for image in images] != sorted(EXPECTED_SERVICES):
        raise VerificationError("reproducibility images must be in lexical service order")
    validate_build_execution(document)
    return document


def run_command(command: list[str]) -> bytes:
    result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        if not detail:
            detail = result.stdout.decode("utf-8", errors="replace").strip()
        raise VerificationError(f"{' '.join(command)} failed with exit {result.returncode}: {detail[:4000]}")
    return result.stdout


def inspected_image_id(image: str) -> str:
    raw = run_command(["docker", "image", "inspect", "--format", "{{.Id}}", image])
    value = raw.decode("utf-8", errors="strict").strip()
    return require_sha256(value, f"Docker image ID for {image}")


def inspect_and_verify_source_labels(image: str, source: dict[str, Any]) -> None:
    raw = run_command(["docker", "image", "inspect", "--format", "{{json .Config.Labels}}", image])
    parsed = parse_json_bytes(raw, f"Docker image labels for {image}")
    if type(parsed) is not dict:
        raise VerificationError(f"Docker image labels for {image} must be an object")
    expected = {
        "org.opencontainers.image.source": source["repository"],
        "org.opencontainers.image.revision": source["revision"],
        "org.opencontainers.image.created": source["created"],
        "dev.serverware.source_tree_digest": source["tree_sha256"],
    }
    mismatches = {
        key: {"expected": value, "actual": parsed.get(key)}
        for key, value in expected.items()
        if parsed.get(key) != value
    }
    if mismatches:
        raise VerificationError(
            f"Docker image {image} source labels do not match the production build: {canonical_json(mismatches)}"
        )


def export_docker_image(image: dict[str, Any], source: dict[str, Any], destination: Path) -> None:
    image_id = str(image["image_id"])
    image_ref = str(image["image_ref"])
    if inspected_image_id(image_id) != image_id:
        raise VerificationError(f"Docker image ID did not resolve to itself: {image_id}")
    if inspected_image_id(image_ref) != image_id:
        raise VerificationError(f"Docker image ref {image_ref} does not resolve to declared image ID {image_id}")
    inspect_and_verify_source_labels(image_id, source)
    container_id = run_command(
        ["docker", "create", "--entrypoint", "/__serverware_reproducibility_noop__", image_id]
    ).decode("utf-8", errors="strict").strip()
    if not container_id:
        raise VerificationError(f"docker create returned an empty container ID for {image_id}")
    try:
        run_command(["docker", "export", "--output", str(destination), container_id])
    finally:
        subprocess.run(
            ["docker", "rm", "-f", container_id],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )


def require_clean_source_checkout() -> None:
    status = run_command(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"]
    ).decode("utf-8", errors="replace")
    if status:
        preview = " | ".join(status.splitlines()[:10])
        raise VerificationError(f"build execution requires a clean source checkout: {preview}")


def current_source_revision() -> str:
    revision = run_command(["git", "rev-parse", "--verify", "HEAD"]).decode(
        "ascii", errors="strict"
    ).strip()
    if not REVISION_RE.fullmatch(revision):
        raise VerificationError("current Git revision is not a full lowercase object ID")
    return revision


def remove_preexisting_build_artifact(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    if path.is_symlink() or not path.is_file():
        raise VerificationError(f"pre-existing build artifact path is not a regular file: {path}")
    try:
        path.unlink()
    except OSError as exc:
        raise VerificationError(f"could not remove pre-existing build artifact {path}: {exc}") from exc


def capture_build(
    build_path: Path,
    *,
    builder_id: str,
    signing_key: Ed25519PrivateKey,
    build_command: list[str],
    build_environment_id: str,
    execution_nonce: str | None = None,
) -> dict[str, Any]:
    command = validate_command_argv(build_command, "capture build command")
    environment_id = require_sha256(build_environment_id, "capture build environment identity")
    require_clean_source_checkout()
    source_before = current_source_tree_digest()
    revision_before = current_source_revision()
    remove_preexisting_build_artifact(build_path)
    run_command(command)
    if build_path.is_symlink() or not build_path.is_file():
        raise VerificationError(
            f"fresh production build artifact is not a regular non-symlink file: {build_path}"
        )
    build, build_raw = load_json(build_path, "fresh production build artifact")
    normalized = validate_build_artifact(build)
    require_clean_source_checkout()
    source_after = current_source_tree_digest()
    revision_after = current_source_revision()
    if source_after != source_before or revision_after != revision_before:
        raise VerificationError("build command changed the clean source identity during execution")
    if normalized["source"]["tree_sha256"] != source_after:
        raise VerificationError(
            "fresh production build source tree digest does not match the current checkout: "
            f"build={normalized['source']['tree_sha256']} current={source_after}"
        )
    if normalized["source"]["revision"] != revision_after:
        raise VerificationError(
            "fresh production build revision does not match the clean checkout: "
            f"build={normalized['source']['revision']} current={revision_after}"
        )
    with tempfile.TemporaryDirectory(prefix="serverware-reproducible-build-") as temp_dir:
        temp = Path(temp_dir)
        archives: dict[str, Path] = {}
        for image in normalized["images"]:
            service = str(image["service"])
            archive = temp / f"{service}.rootfs.tar"
            export_docker_image(image, normalized["source"], archive)
            archives[service] = archive
        require_clean_source_checkout()
        if (
            current_source_tree_digest() != source_after
            or current_source_revision() != revision_after
        ):
            raise VerificationError("source identity changed while capturing build outputs")
        return build_manifest_from_archives(
            build,
            build_raw,
            archives,
            engine_image_id_verified=True,
            source_labels_verified=True,
            builder_id=builder_id,
            signing_key=signing_key,
            build_command=command,
            build_environment_id=environment_id,
            execution_nonce=execution_nonce or secrets.token_hex(32),
            source_clean=True,
        )


def current_source_tree_digest() -> str:
    return serverware_source_tree.source_tree_digest(ROOT)


def enforce_current_source(manifest: dict[str, Any]) -> str:
    current = current_source_tree_digest()
    declared = str(manifest["source"]["tree_sha256"])
    if declared != current:
        raise VerificationError(
            "reproducibility source tree digest does not match the current checkout: "
            f"manifest={declared} current={current}"
        )
    return current


def load_evidence(
    path: Path, trusted_builders: dict[str, Ed25519PublicKey]
) -> tuple[dict[str, Any], dict[str, Any]]:
    document, raw = load_json(path, "reproducibility input")
    api_version = document.get("apiVersion")
    kind = document.get("kind")
    if api_version == BUILD_API_VERSION and kind == BUILD_KIND:
        raise VerificationError(
            "verification requires signed capture manifests; run capture with a builder identity and signing key first"
        )
    elif api_version == MANIFEST_API_VERSION and kind == MANIFEST_KIND:
        manifest = validate_manifest(document)
    else:
        raise VerificationError(f"unsupported reproducibility input type: apiVersion={api_version!r} kind={kind!r}")
    enforce_current_source(manifest)
    attestation = verify_manifest_attestation(manifest, trusted_builders)
    build_execution = verify_build_execution(manifest, trusted_builders)
    if (
        attestation["builder_id"] != build_execution["builder_id"]
        or attestation["key_id"] != build_execution["key_id"]
    ):
        raise VerificationError(
            "manifest and build execution attestations must use the same builder identity and key"
        )
    return manifest, {
        "path": str(path),
        "type": "signed-build-execution",
        "document_sha256": sha256_bytes(raw),
        "evidence_sha256": manifest["evidence_sha256"],
        "attestation": attestation,
        "build_execution": build_execution,
    }


def comparison_projection(manifest: dict[str, Any]) -> dict[str, Any]:
    images: list[dict[str, Any]] = []
    for image in manifest["images"]:
        projected = {
            key: value
            for key, value in image.items()
            if key not in {"capture"}
        }
        projected["capture"] = {
            "method": image["capture"]["method"],
            "engine_image_id_verified": image["capture"]["engine_image_id_verified"],
            "source_labels_verified": image["capture"]["source_labels_verified"],
        }
        images.append(projected)
    return {
        "source": manifest["source"],
        "build_contract": {
            "apiVersion": manifest["build_artifact"]["apiVersion"],
            "kind": manifest["build_artifact"]["kind"],
            "no_shell_passed": manifest["build_artifact"]["no_shell_passed"],
        },
        "images": images,
    }


def shortened(value: Any) -> Any:
    if type(value) in {str, int, bool} or value is None:
        return value
    encoded = canonical_json(value)
    if len(encoded) <= 300:
        return value
    return {"sha256": sha256_json(value), "bytes": len(encoded.encode("utf-8"))}


def collect_mismatches(left: Any, right: Any, path: str = "$", *, limit: int = 100) -> list[dict[str, Any]]:
    mismatches: list[dict[str, Any]] = []

    def walk(left_value: Any, right_value: Any, current_path: str) -> None:
        if len(mismatches) >= limit:
            return
        if type(left_value) is not type(right_value):
            mismatches.append(
                {"field": current_path, "left": shortened(left_value), "right": shortened(right_value)}
            )
            return
        if type(left_value) is dict:
            keys = sorted(set(left_value) | set(right_value))
            for key in keys:
                child_path = f"{current_path}.{key}"
                if key not in left_value:
                    mismatches.append({"field": child_path, "left": "<missing>", "right": shortened(right_value[key])})
                elif key not in right_value:
                    mismatches.append({"field": child_path, "left": shortened(left_value[key]), "right": "<missing>"})
                else:
                    walk(left_value[key], right_value[key], child_path)
                if len(mismatches) >= limit:
                    return
            return
        if type(left_value) is list:
            if len(left_value) != len(right_value):
                mismatches.append(
                    {"field": current_path + ".length", "left": len(left_value), "right": len(right_value)}
                )
            for index, (left_item, right_item) in enumerate(zip(left_value, right_value)):
                walk(left_item, right_item, f"{current_path}[{index}]")
                if len(mismatches) >= limit:
                    return
            return
        if left_value != right_value:
            mismatches.append(
                {"field": current_path, "left": shortened(left_value), "right": shortened(right_value)}
            )

    walk(left, right, path)
    return mismatches


def image_bindings(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    bindings: list[dict[str, Any]] = []
    for image in manifest["images"]:
        binding = {
            "service": image["service"],
            "image_ref": image["image_ref"],
            "image_id": image["image_id"],
            "normalized_rootfs_sha256": image["content"]["entries_sha256"],
        }
        if image["service"] == "serverware-decision-gate":
            binding["rust_binary_sha256"] = image["rust_binary"]["sha256"]
            binding["launcher_binary_sha256"] = image["launcher_binary_sha256"]
            for field in LAUNCH_AUTHORITY_FIELDS:
                binding[field] = image[field]
        bindings.append(binding)
    return bindings


def verification_result(
    left: dict[str, Any],
    right: dict[str, Any],
    left_input: dict[str, Any],
    right_input: dict[str, Any],
) -> dict[str, Any]:
    left_attestation = left_input.get("attestation")
    right_attestation = right_input.get("attestation")
    left_execution = left_input.get("build_execution")
    right_execution = right_input.get("build_execution")
    for label, attestation, execution in (
        ("left", left_attestation, left_execution),
        ("right", right_attestation, right_execution),
    ):
        if type(attestation) is not dict:
            raise VerificationError(f"{label} input is missing a verified builder attestation")
        if (
            attestation.get("signature_verified") is not True
            or attestation.get("operator_trusted") is not True
        ):
            raise VerificationError(
                f"{label} input builder attestation is not trusted and signature-verified"
            )
        if type(execution) is not dict:
            raise VerificationError(f"{label} input is missing a verified build execution statement")
        if (
            execution.get("signature_verified") is not True
            or execution.get("operator_trusted") is not True
            or execution.get("source_clean") is not True
        ):
            raise VerificationError(
                f"{label} build execution statement is not clean, trusted, and signature-verified"
            )
        if (
            execution.get("builder_id") != attestation.get("builder_id")
            or execution.get("key_id") != attestation.get("key_id")
        ):
            raise VerificationError(
                f"{label} manifest and build execution attestations use different identities"
            )
    left_builder = require_string(left_execution.get("builder_id"), "left execution builder_id")
    right_builder = require_string(right_execution.get("builder_id"), "right execution builder_id")
    left_key = require_sha256(left_execution.get("key_id"), "left execution key_id")
    right_key = require_sha256(right_execution.get("key_id"), "right execution key_id")
    if left_builder == right_builder:
        raise VerificationError("independent build executions must use distinct builder identities")
    if left_key == right_key:
        raise VerificationError("independent build executions must use distinct operator-pinned keys")
    left_nonce = require_string(
        left_execution.get("execution_nonce"), "left execution execution_nonce"
    )
    right_nonce = require_string(
        right_execution.get("execution_nonce"), "right execution execution_nonce"
    )
    if left_nonce == right_nonce:
        raise VerificationError(
            "independent build executions must use distinct execution nonces; replay rejected"
        )
    left_projection = comparison_projection(left)
    right_projection = comparison_projection(right)
    mismatches = collect_mismatches(left_projection, right_projection)
    reproducible = not mismatches
    return {
        "apiVersion": VERIFICATION_API_VERSION,
        "kind": VERIFICATION_KIND,
        "ok": reproducible,
        "reproducible": reproducible,
        "scope": {
            "artifact_reproducibility_only": True,
            "independent_execution_proven": True,
            "hardware_proof": False,
        },
        "inputs": {"left": left_input, "right": right_input},
        "source_tree_digest": left["source"]["tree_sha256"] if reproducible else None,
        "comparison_sha256": sha256_json(left_projection) if reproducible else None,
        "images": image_bindings(left) if reproducible else [],
        "mismatches": mismatches,
    }


def failure_result(message: str) -> dict[str, Any]:
    return {
        "apiVersion": VERIFICATION_API_VERSION,
        "kind": VERIFICATION_KIND,
        "ok": False,
        "reproducible": False,
        "scope": {
            "artifact_reproducibility_only": True,
            "independent_execution_proven": False,
            "hardware_proof": False,
        },
        "error": {"type": "validation-error", "message": message},
        "mismatches": [],
    }


def emit(document: dict[str, Any], out: str | None) -> None:
    rendered = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if out:
        output_path = Path(out)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
    sys.stdout.write(canonical_json(document) + "\n")


def parse_trusted_builders(specs: list[str]) -> dict[str, Ed25519PublicKey]:
    if len(specs) != 2:
        raise VerificationError(
            "verification requires exactly two --trusted-builder identity=public-key.pem values"
        )
    trusted: dict[str, Ed25519PublicKey] = {}
    seen_key_ids: set[str] = set()
    for index, spec in enumerate(specs):
        if "=" not in spec:
            raise VerificationError(
                f"trusted builder {index + 1} must use identity=public-key.pem syntax"
            )
        builder_raw, path_raw = spec.split("=", 1)
        builder_id = validate_builder_id(builder_raw, f"trusted builder {index + 1} identity")
        if builder_id in trusted:
            raise VerificationError(f"duplicate trusted builder identity: {builder_id}")
        path = Path(require_string(path_raw, f"trusted builder {index + 1} public key path"))
        public_key = load_trusted_public_key(path, f"trusted builder {builder_id} public key")
        key_id = public_key_id(public_key)
        if key_id in seen_key_ids:
            raise VerificationError("trusted builders must use distinct Ed25519 public keys")
        seen_key_ids.add(key_id)
        trusted[builder_id] = public_key
    return trusted


def parse_build_command(value: str) -> list[str]:
    parsed = parse_json_bytes(value.encode("utf-8"), "capture build command")
    return validate_command_argv(parsed, "capture build command")


def default_build_command(build_path: Path) -> list[str]:
    return [sys.executable, "scripts/build_production_images.py", "--out", str(build_path)]


def local_build_environment_id() -> str:
    daemon_id = require_string(
        run_command(["docker", "info", "--format", "{{.ID}}"])
        .decode("utf-8", errors="strict")
        .strip(),
        "Docker build environment daemon ID",
    )
    server = require_string(
        run_command(
            [
                "docker",
                "version",
                "--format",
                "{{.Server.Version}}/{{.Server.Os}}/{{.Server.Arch}}",
            ]
        )
        .decode("utf-8", errors="strict")
        .strip(),
        "Docker build environment server identity",
    )
    return sha256_json(
        {"contract": "serverware.dockerBuildEnvironment/v1", "daemon_id": daemon_id, "server": server}
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run signed build executions and compare two operator-trusted production captures."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    capture = subparsers.add_parser(
        "capture",
        help="Run a fresh build and export its exact local image IDs into a signed manifest.",
    )
    capture.add_argument(
        "--build",
        required=True,
        help=f"Path where the fresh build command must create a {BUILD_API_VERSION} JSON artifact",
    )
    capture.add_argument("--builder-id", required=True, help="Stable identity for this independent builder")
    capture.add_argument("--signing-key", required=True, help="PEM-encoded Ed25519 builder private key")
    capture.add_argument(
        "--build-environment-id",
        help="Optional operator-pinned sha256 identity; defaults to a digest of the Docker daemon/server identity",
    )
    capture.add_argument(
        "--build-command-json",
        help="Optional exact shell-free build argv as JSON; defaults to build_production_images.py --out BUILD",
    )
    capture.add_argument(
        "--out",
        help="Optional pretty-printed manifest output path; canonical JSON is always printed",
    )
    verify = subparsers.add_parser("verify", help="Compare two signed builder capture manifests.")
    verify.add_argument("--left", required=True, help="First signed reproducibility manifest")
    verify.add_argument("--right", required=True, help="Second signed reproducibility manifest")
    verify.add_argument(
        "--trusted-builder",
        action="append",
        required=True,
        metavar="IDENTITY=PUBLIC_KEY_PEM",
        help="Operator-pinned builder identity and Ed25519 public key; provide exactly twice",
    )
    verify.add_argument(
        "--out",
        help="Optional pretty-printed verification output path; canonical JSON is always printed",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "capture":
            signing_key = load_private_signing_key(Path(args.signing_key))
            build_path = Path(args.build)
            manifest = capture_build(
                build_path,
                builder_id=args.builder_id,
                signing_key=signing_key,
                build_command=(
                    parse_build_command(args.build_command_json)
                    if args.build_command_json
                    else default_build_command(build_path)
                ),
                build_environment_id=args.build_environment_id or local_build_environment_id(),
            )
            validate_manifest(manifest)
            enforce_current_source(manifest)
            emit(manifest, args.out)
            return 0
        trusted_builders = parse_trusted_builders(args.trusted_builder)
        left, left_input = load_evidence(Path(args.left), trusted_builders)
        right, right_input = load_evidence(Path(args.right), trusted_builders)
        result = verification_result(left, right, left_input, right_input)
        emit(result, args.out)
        return 0 if result["ok"] else 1
    except Exception as exc:
        emit(failure_result(str(exc)), getattr(args, "out", None))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
