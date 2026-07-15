#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


ROOT = Path(__file__).resolve().parent.parent
MAX_FIXTURE_LOG_LINE_BYTES = 8 * 1024 * 1024
MAX_HTTP_RESPONSE_BYTES = 1024 * 1024
CHECKPOINT_VERSION = "serverware.transparencyCheckpoint/v1"
PUBLICATION_VERSION = "serverware.externalTransparencyCheckpointRequest/v1"
RECEIPT_VERSION = "serverware.externalTransparencyReceipt/v1"


def canonical_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=True)


def encode_fixture_log_line(record: dict[str, Any]) -> bytes:
    encoded = canonical_json(record).encode("utf-8")
    if len(encoded) + 1 > MAX_FIXTURE_LOG_LINE_BYTES:
        raise SystemExit("external transparency fixture log line exceeds 8 MiB")
    return encoded + b"\n"


def sha256_prefixed_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_prefixed_json(value: Any) -> str:
    return sha256_prefixed_bytes(canonical_json(value).encode("utf-8"))


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64d(value: str) -> bytes:
    padded = value + ("=" * ((4 - len(value) % 4) % 4))
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def read_stdin_object() -> dict[str, Any]:
    payload = json.loads(sys.stdin.read() or "{}")
    if not isinstance(payload, dict):
        raise SystemExit("stdin must be a JSON object")
    return payload


def log_path() -> Path:
    return Path(os.getenv("SERVERWARE_EXTERNAL_TRANSPARENCY_LOG_PATH", str(ROOT / ".tmp" / "managed-transparency-log.jsonl")))


def key_path() -> Path:
    return Path(os.getenv("SERVERWARE_EXTERNAL_TRANSPARENCY_LOG_KEY", str(log_path().with_suffix(".ed25519.pem"))))


def load_private_key() -> Ed25519PrivateKey:
    path = key_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise SystemExit(f"{path} is not an Ed25519 private key")
        return key
    key = Ed25519PrivateKey.generate()
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(path, 0o600)
    return key


def public_key_info(public_key: Ed25519PublicKey) -> dict[str, str]:
    pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {"public_key_pem": pem, "log_id": sha256_prefixed_bytes(der)}


def validate_checkpoint(payload: dict[str, Any]) -> None:
    required = {"sequence", "tree_size", "tree_head_hash", "signed_tree_head", "record_digest", "leaf_hash"}
    missing = sorted(required - set(payload))
    if missing:
        raise SystemExit(f"checkpoint payload missing fields: {', '.join(missing)}")
    if payload.get("version") != CHECKPOINT_VERSION:
        raise SystemExit(f"unsupported checkpoint version: {payload.get('version')!r}")
    if not isinstance(payload.get("sequence"), int) or payload["sequence"] < 1:
        raise SystemExit("checkpoint sequence must be a positive integer")
    if not isinstance(payload.get("tree_size"), int) or payload["tree_size"] < 1:
        raise SystemExit("checkpoint tree_size must be a positive integer")
    for field in ("tree_head_hash", "record_digest", "leaf_hash"):
        if not isinstance(payload.get(field), str) or not payload[field].startswith("sha256:"):
            raise SystemExit(f"checkpoint {field} must be a sha256-prefixed digest")
    signed_tree_head = payload.get("signed_tree_head")
    if not isinstance(signed_tree_head, dict):
        raise SystemExit("checkpoint signed_tree_head must be an object")
    if signed_tree_head.get("tree_size") != payload["tree_size"]:
        raise SystemExit("signed tree head tree_size does not match checkpoint payload")
    if signed_tree_head.get("tree_head_hash") != payload["tree_head_hash"]:
        raise SystemExit("signed tree head tree_head_hash does not match checkpoint payload")


def publication_request(payload: dict[str, Any]) -> dict[str, Any]:
    validate_checkpoint(payload)
    body = {
        "apiVersion": PUBLICATION_VERSION,
        "kind": "serverware-signed-tree-head-checkpoint",
        "canonicalization": "serverware.canonical-json.v1",
        "checkpoint_digest": sha256_prefixed_json(payload),
        "checkpoint": payload,
        "receipt_requirements": {
            "must_bind_checkpoint_digest": True,
            "must_bind_request_digest": True,
            "must_bind_tree_head": True,
            "must_include_log_id": True,
            "must_include_verifiable_signature": True,
        },
    }
    body["request_digest"] = sha256_prefixed_json(body)
    return body


def receipt_payload(
    *,
    provider: str,
    log_id: str,
    external_sequence: int | str,
    request_digest: str,
    checkpoint_digest: str,
    checkpoint: dict[str, Any],
) -> dict[str, Any]:
    return {
        "version": RECEIPT_VERSION,
        "provider": provider,
        "log_id": log_id,
        "external_sequence": external_sequence,
        "checkpoint_digest": checkpoint_digest,
        "request_digest": request_digest,
        "source_sequence": checkpoint["sequence"],
        "tree_size": checkpoint["tree_size"],
        "tree_head_hash": checkpoint["tree_head_hash"],
        "record_digest": checkpoint["record_digest"],
        "leaf_hash": checkpoint["leaf_hash"],
    }


def sign_receipt(key: Ed25519PrivateKey, payload: dict[str, Any]) -> str:
    return "ed25519:" + b64e(key.sign(canonical_json(payload).encode("utf-8")))


def verify_ed25519_receipt(receipt: dict[str, Any], expected: dict[str, Any], response_log_id: str) -> bool:
    payload = receipt.get("payload")
    signature = receipt.get("signature")
    public_key_pem = receipt.get("public_key_pem")
    if not isinstance(payload, dict) or not isinstance(signature, str) or not isinstance(public_key_pem, str):
        return False
    if not signature.startswith("ed25519:"):
        raise SystemExit("external checkpoint receipt signature must use ed25519")
    public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    if not isinstance(public_key, Ed25519PublicKey):
        raise SystemExit("external checkpoint receipt public_key_pem is not an Ed25519 key")
    info = public_key_info(public_key)
    if response_log_id != info["log_id"]:
        raise SystemExit("external checkpoint log_id does not match receipt public key")
    for field, expected_value in expected.items():
        if payload.get(field) != expected_value:
            raise SystemExit(f"external checkpoint receipt {field} does not match request")
    try:
        public_key.verify(b64d(signature.removeprefix("ed25519:")), canonical_json(payload).encode("utf-8"))
    except InvalidSignature as exc:
        raise SystemExit("external checkpoint receipt signature did not verify") from exc
    return True


def build_signature_receipt(response: dict[str, Any]) -> dict[str, Any] | None:
    signature = response.get("signature")
    public_key_pem = response.get("public_key_pem")
    payload = response.get("receipt_payload")
    if isinstance(signature, str) and isinstance(public_key_pem, str) and isinstance(payload, dict):
        return {
            "kind": "ed25519-signed-checkpoint",
            "payload": payload,
            "signature": signature,
            "public_key_pem": public_key_pem,
        }
    return None


def normalized_response(
    response: dict[str, Any],
    checkpoint: dict[str, Any],
    request_digest: str,
    *,
    require_verifiable_receipt: bool,
) -> dict[str, Any]:
    if response.get("ok") is not True:
        raise SystemExit(f"external transparency log rejected checkpoint: {response}")
    provider = response.get("provider")
    if not isinstance(provider, str) or not provider:
        raise SystemExit("external checkpoint response missing provider")
    expected_provider = os.getenv("SERVERWARE_TRANSPARENCY_EXPECTED_PROVIDER", "").strip()
    if expected_provider and provider != expected_provider:
        raise SystemExit("external checkpoint provider did not match SERVERWARE_TRANSPARENCY_EXPECTED_PROVIDER")
    mode = response.get("mode") or "external-managed-transparency-log"
    if mode != "external-managed-transparency-log":
        raise SystemExit(f"external checkpoint response used unsupported mode: {mode!r}")
    checkpoint_digest = response.get("checkpoint_digest")
    expected_checkpoint_digest = sha256_prefixed_json(checkpoint)
    if checkpoint_digest != expected_checkpoint_digest:
        raise SystemExit("external checkpoint digest does not match checkpoint payload")
    if response.get("request_digest") != request_digest:
        raise SystemExit("external checkpoint request_digest does not match publication request")
    if response.get("tree_size") != checkpoint["tree_size"]:
        raise SystemExit("external checkpoint tree_size does not match checkpoint payload")
    if response.get("tree_head_hash") != checkpoint["tree_head_hash"]:
        raise SystemExit("external checkpoint tree_head_hash does not match checkpoint payload")
    log_id = response.get("log_id")
    if not isinstance(log_id, str) or not log_id:
        raise SystemExit("external checkpoint response missing log_id")
    expected_log_id = os.getenv("SERVERWARE_TRANSPARENCY_EXPECTED_LOG_ID", "").strip()
    if expected_log_id and log_id != expected_log_id:
        raise SystemExit("external checkpoint log_id did not match SERVERWARE_TRANSPARENCY_EXPECTED_LOG_ID")
    external_sequence = response.get("external_sequence", response.get("checkpoint_id"))
    if external_sequence is None or external_sequence == "":
        raise SystemExit("external checkpoint response missing external_sequence or checkpoint_id")
    receipt = response.get("receipt")
    if not isinstance(receipt, dict):
        receipt = build_signature_receipt(response)
    if not isinstance(receipt, dict) or not receipt.get("kind"):
        raise SystemExit("external checkpoint response missing receipt")
    expected_receipt_fields = {
        "checkpoint_digest": expected_checkpoint_digest,
        "request_digest": request_digest,
        "tree_size": checkpoint["tree_size"],
        "tree_head_hash": checkpoint["tree_head_hash"],
        "record_digest": checkpoint["record_digest"],
        "leaf_hash": checkpoint["leaf_hash"],
    }
    verifiable = verify_ed25519_receipt(receipt, expected_receipt_fields, log_id)
    if require_verifiable_receipt and not verifiable:
        raise SystemExit("external checkpoint receipt is not verifiable by the adapter")
    return {
        "ok": True,
        "provider": provider,
        "mode": "external-managed-transparency-log",
        "external_sequence": external_sequence,
        "checkpoint_digest": expected_checkpoint_digest,
        "request_digest": request_digest,
        "tree_size": checkpoint["tree_size"],
        "tree_head_hash": checkpoint["tree_head_hash"],
        "log_id": log_id,
        "receipt": receipt,
        "signature": receipt.get("signature"),
    }


def checkpoint_fixture(checkpoint: dict[str, Any]) -> dict[str, Any]:
    request = publication_request(checkpoint)
    path = log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        external_sequence = fixture_log_last_sequence_from_handle(handle) + 1
        key = load_private_key()
        info = public_key_info(key.public_key())
        provider = os.getenv("SERVERWARE_EXTERNAL_TRANSPARENCY_PROVIDER", "managed-transparency-log-fixture")
        receipt_body = receipt_payload(
            provider=provider,
            log_id=info["log_id"],
            external_sequence=external_sequence,
            request_digest=request["request_digest"],
            checkpoint_digest=request["checkpoint_digest"],
            checkpoint=checkpoint,
        )
        signature = sign_receipt(key, receipt_body)
        receipt = {
            "kind": "ed25519-signed-checkpoint",
            "payload": receipt_body,
            "signature": signature,
            "public_key_pem": info["public_key_pem"],
        }
        record = {
            "version": RECEIPT_VERSION,
            "provider": provider,
            "mode": "external-managed-transparency-log",
            "external_sequence": external_sequence,
            "received_at": datetime.now(timezone.utc).isoformat(),
            "checkpoint_digest": request["checkpoint_digest"],
            "request_digest": request["request_digest"],
            "tree_size": checkpoint["tree_size"],
            "tree_head_hash": checkpoint["tree_head_hash"],
            "signed_tree_head": checkpoint["signed_tree_head"],
            "record_digest": checkpoint["record_digest"],
            "leaf_hash": checkpoint["leaf_hash"],
            "source_sequence": checkpoint["sequence"],
            "source_mode": checkpoint.get("mode"),
            "log_id": info["log_id"],
            "receipt": receipt,
            "signature": signature,
            "public_key_pem": info["public_key_pem"],
        }
        encoded = encode_fixture_log_line(record)
        handle.seek(0, os.SEEK_END)
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    return normalized_response(record | {"ok": True}, checkpoint, request["request_digest"], require_verifiable_receipt=True)


def fixture_log_last_sequence(path: Path) -> int:
    if not path.exists() or path.stat().st_size == 0:
        return 0
    with path.open("rb") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_SH)
        return fixture_log_last_sequence_from_handle(handle)


def fixture_log_last_sequence_from_handle(handle: Any) -> int:
    handle.seek(0)
    expected_sequence = 1
    line_number = 0
    while True:
        line = handle.readline(MAX_FIXTURE_LOG_LINE_BYTES + 1)
        if not line:
            return expected_sequence - 1
        line_number += 1
        if len(line) > MAX_FIXTURE_LOG_LINE_BYTES:
            raise SystemExit("external transparency fixture log line exceeds 8 MiB")
        if not line.endswith(b"\n"):
            raise SystemExit("external transparency fixture log must end with a newline")
        try:
            record = json.loads(line[:-1].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SystemExit(f"external transparency fixture log record {line_number} is invalid JSON") from exc
        validate_fixture_log_record(record, expected_sequence, line_number)
        expected_sequence += 1


def validate_fixture_log_record(record: Any, expected_sequence: int, line_number: int) -> None:
    if not isinstance(record, dict):
        raise SystemExit(f"external transparency fixture log record {line_number} must be an object")
    required = {
        "version",
        "provider",
        "mode",
        "external_sequence",
        "received_at",
        "checkpoint_digest",
        "request_digest",
        "tree_size",
        "tree_head_hash",
        "signed_tree_head",
        "record_digest",
        "leaf_hash",
        "source_sequence",
        "source_mode",
        "log_id",
        "receipt",
        "signature",
        "public_key_pem",
    }
    missing = sorted(required - set(record))
    if missing:
        raise SystemExit(
            f"external transparency fixture log record {line_number} missing fields: {', '.join(missing)}"
        )
    if record["version"] != RECEIPT_VERSION:
        raise SystemExit(f"external transparency fixture log record {line_number} has an unsupported version")
    if not isinstance(record["provider"], str) or not record["provider"]:
        raise SystemExit(f"external transparency fixture log record {line_number} provider is invalid")
    if record["mode"] != "external-managed-transparency-log":
        raise SystemExit(f"external transparency fixture log record {line_number} mode is invalid")
    sequence = record["external_sequence"]
    if type(sequence) is not int or sequence < 1:
        raise SystemExit(f"external transparency fixture log record {line_number} sequence is invalid")
    if sequence != expected_sequence:
        raise SystemExit("external transparency fixture log sequences must be contiguous and start at 1")
    if not isinstance(record["received_at"], str) or not record["received_at"]:
        raise SystemExit(f"external transparency fixture log record {line_number} received_at is invalid")
    if type(record["tree_size"]) is not int or record["tree_size"] < 1:
        raise SystemExit(f"external transparency fixture log record {line_number} tree_size is invalid")
    if type(record["source_sequence"]) is not int or record["source_sequence"] < 1:
        raise SystemExit(f"external transparency fixture log record {line_number} source_sequence is invalid")
    if record["source_mode"] is not None and not isinstance(record["source_mode"], str):
        raise SystemExit(f"external transparency fixture log record {line_number} source_mode is invalid")
    for field in ("checkpoint_digest", "request_digest", "tree_head_hash", "record_digest", "leaf_hash", "log_id"):
        value = record[field]
        if not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:"):
            raise SystemExit(f"external transparency fixture log record {line_number} {field} is invalid")
        try:
            int(value.removeprefix("sha256:"), 16)
        except ValueError as exc:
            raise SystemExit(f"external transparency fixture log record {line_number} {field} is invalid") from exc
    signed_tree_head = record["signed_tree_head"]
    if not isinstance(signed_tree_head, dict):
        raise SystemExit(f"external transparency fixture log record {line_number} signed_tree_head must be an object")
    if signed_tree_head.get("tree_size") != record["tree_size"]:
        raise SystemExit(f"external transparency fixture log record {line_number} signed tree size does not match")
    if signed_tree_head.get("tree_head_hash") != record["tree_head_hash"]:
        raise SystemExit(f"external transparency fixture log record {line_number} signed tree hash does not match")
    receipt = record["receipt"]
    if not isinstance(receipt, dict) or receipt.get("kind") != "ed25519-signed-checkpoint":
        raise SystemExit(f"external transparency fixture log record {line_number} receipt is invalid")
    if record["signature"] != receipt.get("signature") or record["public_key_pem"] != receipt.get("public_key_pem"):
        raise SystemExit(f"external transparency fixture log record {line_number} receipt metadata does not match")
    expected_receipt_fields = {
        "version": RECEIPT_VERSION,
        "provider": record["provider"],
        "log_id": record["log_id"],
        "external_sequence": sequence,
        "checkpoint_digest": record["checkpoint_digest"],
        "request_digest": record["request_digest"],
        "source_sequence": record["source_sequence"],
        "tree_size": record["tree_size"],
        "tree_head_hash": record["tree_head_hash"],
        "record_digest": record["record_digest"],
        "leaf_hash": record["leaf_hash"],
    }
    try:
        verifiable = verify_ed25519_receipt(receipt, expected_receipt_fields, record["log_id"])
    except SystemExit as exc:
        raise SystemExit(f"external transparency fixture log record {line_number} receipt is invalid: {exc}") from exc
    except Exception as exc:
        raise SystemExit(f"external transparency fixture log record {line_number} receipt is invalid") from exc
    if not verifiable:
        raise SystemExit(f"external transparency fixture log record {line_number} receipt is not verifiable")


def load_extra_headers() -> dict[str, str]:
    headers: dict[str, str] = {}
    raw = os.getenv("SERVERWARE_TRANSPARENCY_LOG_HEADERS", "").strip()
    if raw:
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise SystemExit("SERVERWARE_TRANSPARENCY_LOG_HEADERS must be a JSON object")
        for key, value in parsed.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise SystemExit("SERVERWARE_TRANSPARENCY_LOG_HEADERS entries must be strings")
            lowered = key.lower()
            if lowered in {"authorization", "content-length", "host"}:
                raise SystemExit(f"SERVERWARE_TRANSPARENCY_LOG_HEADERS cannot set {key}")
            headers[key] = value
    token = os.getenv("SERVERWARE_TRANSPARENCY_LOG_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def checkpoint_http(checkpoint: dict[str, Any], url: str) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" and not env_bool("SERVERWARE_TRANSPARENCY_ALLOW_INSECURE_HTTP", False):
        raise SystemExit("SERVERWARE_TRANSPARENCY_LOG_URL must use https unless SERVERWARE_TRANSPARENCY_ALLOW_INSECURE_HTTP=1")
    if parsed.scheme not in {"https", "http"}:
        raise SystemExit("SERVERWARE_TRANSPARENCY_LOG_URL must use http or https")
    request = publication_request(checkpoint)
    body = canonical_json(request).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "serverware-transparency-checkpoint/1",
    }
    headers.update(load_extra_headers())
    http_request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    timeout = float(os.getenv("SERVERWARE_TRANSPARENCY_CHECKPOINT_TIMEOUT_SECONDS", "15"))
    try:
        with urllib.request.urlopen(http_request, timeout=timeout) as handle:
            content_length = handle.headers.get("Content-Length")
            if content_length is not None:
                try:
                    declared_length = int(content_length)
                except ValueError:
                    declared_length = None
                if declared_length is not None and declared_length > MAX_HTTP_RESPONSE_BYTES:
                    raise SystemExit("managed transparency log response exceeds 1 MiB")
            response_body = handle.read(MAX_HTTP_RESPONSE_BYTES + 1)
            if len(response_body) > MAX_HTTP_RESPONSE_BYTES:
                raise SystemExit("managed transparency log response exceeds 1 MiB")
    except urllib.error.HTTPError as exc:
        detail = exc.read(4096).decode("utf-8", errors="replace")
        raise SystemExit(f"managed transparency log returned HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"managed transparency log request failed: {exc.reason}") from exc
    response = json.loads(response_body.decode("utf-8"))
    if not isinstance(response, dict):
        raise SystemExit("managed transparency log returned non-object JSON")
    return normalized_response(
        response,
        checkpoint,
        request["request_digest"],
        require_verifiable_receipt=env_bool("SERVERWARE_TRANSPARENCY_REQUIRE_VERIFIABLE_RECEIPT", True),
    )


def command_checkpoint(args: argparse.Namespace) -> dict[str, Any]:
    checkpoint = read_stdin_object()
    mode = args.mode or os.getenv("SERVERWARE_TRANSPARENCY_CHECKPOINT_MODE", "").strip()
    url = args.url or os.getenv("SERVERWARE_TRANSPARENCY_LOG_URL", "").strip()
    if not mode:
        mode = "http" if url else "fixture"
    if mode == "fixture":
        return checkpoint_fixture(checkpoint)
    if mode == "http":
        if not url:
            raise SystemExit("SERVERWARE_TRANSPARENCY_LOG_URL is required for http checkpoint mode")
        return checkpoint_http(checkpoint, url)
    raise SystemExit(f"unsupported checkpoint mode: {mode}")


def command_verify() -> dict[str, Any]:
    request = read_stdin_object()
    checkpoint = request.get("checkpoint")
    response = request.get("response")
    if not isinstance(checkpoint, dict) or not isinstance(response, dict):
        raise SystemExit("verify input must contain checkpoint and response objects")
    publication = publication_request(checkpoint)
    return normalized_response(
        response,
        checkpoint,
        publication["request_digest"],
        require_verifiable_receipt=env_bool("SERVERWARE_TRANSPARENCY_REQUIRE_VERIFIABLE_RECEIPT", True),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Publish and verify Serverware external transparency checkpoints.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    checkpoint_parser = subparsers.add_parser("checkpoint")
    checkpoint_parser.add_argument("--mode", choices=("fixture", "http"), default=None)
    checkpoint_parser.add_argument("--url", default=None)
    subparsers.add_parser("verify")
    args = parser.parse_args()
    if args.command == "checkpoint":
        result = command_checkpoint(args)
    elif args.command == "verify":
        result = command_verify()
    else:
        raise SystemExit(f"unsupported command: {args.command}")
    print(canonical_json(result))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"transparency checkpoint failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
