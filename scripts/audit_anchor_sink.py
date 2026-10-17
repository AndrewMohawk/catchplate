from __future__ import annotations

import base64
import fcntl
import hashlib
import hmac
import json
import math
import os
import selectors
import shlex
import signal
import subprocess
import threading
import time
import uuid
from collections import deque
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from fastapi import FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

from catchplate.config import AUDIT_ANCHOR_TOKEN as ANCHOR_TOKEN


ANCHOR_PATH = Path(os.getenv("CATCHPLATE_AUDIT_ANCHOR_PATH", "/anchors/transparency-log.jsonl"))
SIGNING_KEY_PATH = Path(os.getenv("CATCHPLATE_TRANSPARENCY_LOG_SIGNING_KEY", "/anchors/transparency-log-ed25519.pem"))
CHECKPOINT_COMMAND = os.getenv("CATCHPLATE_TRANSPARENCY_CHECKPOINT_COMMAND", "").strip()
CHECKPOINT_REQUIRED = os.getenv("CATCHPLATE_TRANSPARENCY_CHECKPOINT_REQUIRED", "0").lower() in {"1", "true", "yes"}
CHECKPOINT_MODE = os.getenv("CATCHPLATE_TRANSPARENCY_CHECKPOINT_MODE", "").strip().lower()
EXPECTED_CHECKPOINT_LOG_ID = os.getenv("CATCHPLATE_TRANSPARENCY_EXPECTED_LOG_ID", "").strip()
EXTERNAL_CHECKPOINT_TRUSTED_PUBLIC_KEY_PATH = os.getenv(
    "CATCHPLATE_EXTERNAL_CHECKPOINT_TRUSTED_PUBLIC_KEY", ""
).strip()
TRUSTED_CHECKPOINT_PUBLIC_KEY_PATH = os.getenv(
    "CATCHPLATE_TRANSPARENCY_TRUSTED_PUBLIC_KEY", ""
).strip()
EXTERNAL_CHECKPOINT_LOG_PATH = os.getenv(
    "CATCHPLATE_EXTERNAL_TRANSPARENCY_LOG_PATH", ""
).strip()
EXTERNAL_CHECKPOINT_KEY_PATH = os.getenv(
    "CATCHPLATE_EXTERNAL_TRANSPARENCY_LOG_KEY", ""
).strip()
TLS_CERT_FILE = os.getenv("CATCHPLATE_AUDIT_ANCHOR_TLS_CERT_FILE", "").strip()
TLS_KEY_FILE = os.getenv("CATCHPLATE_AUDIT_ANCHOR_TLS_KEY_FILE", "").strip()
ANCHOR_LOCK = threading.Lock()
ANCHOR_COUNT_LOCK = threading.Lock()
ANCHOR_COUNT_CACHE: tuple[int, int, int, int, int, int] | None = None
MAX_ANCHOR_LINE_BYTES = 8 * 1024 * 1024
MAX_ANCHOR_PRECHECK_BYTES = 6 * 1024 * 1024
MAX_ANCHOR_REQUEST_BODY_BYTES = 8 * 1024 * 1024
MAX_ANCHOR_BATCH_APPEND_BYTES = 16 * 1024 * 1024
MAX_ANCHOR_TRANSACTION_BYTES = 24 * 1024 * 1024
MAX_EXTERNAL_CHECKPOINT_BYTES = 1024 * 1024
MAX_EXTERNAL_CHECKPOINT_STDERR_BYTES = 256 * 1024
EXTERNAL_CHECKPOINT_TIMEOUT_SECONDS = 15
ANCHOR_TAIL_DIGEST_BYTES = 64 * 1024
ANCHOR_STATE_CACHE: dict[str, Any] | None = None
MAX_JSON_DEPTH = 32
MAX_JSON_KEYS = 10_000
MAX_JSON_KEY_BYTES = 1024
MAX_JSON_STRING_BYTES = 1024 * 1024
MAX_JSON_AGGREGATE_STRING_BYTES = 6 * 1024 * 1024
MAX_JSON_NODES = 50_000


class AnchorBodyLimitMiddleware:
    def __init__(self, app: Any, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def _reject(self, scope: dict[str, Any], receive: Any, send: Any, status: int, detail: str) -> None:
        body = canonical_json({"detail": detail}).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http" or scope.get("method") != "POST" or scope.get("path") != "/anchors":
            await self.app(scope, receive, send)
            return

        content_lengths = [value for name, value in scope.get("headers", []) if name.lower() == b"content-length"]
        if content_lengths:
            try:
                content_length = int(content_lengths[-1])
            except (TypeError, ValueError):
                await self._reject(scope, receive, send, 400, "invalid Content-Length")
                return
            if content_length < 0:
                await self._reject(scope, receive, send, 400, "invalid Content-Length")
                return
            if content_length > self.max_body_bytes:
                await self._reject(scope, receive, send, 413, "anchor request body is too large")
                return

        body = bytearray()
        disconnected = False
        while True:
            message = await receive()
            if message.get("type") == "http.disconnect":
                disconnected = True
                break
            if message.get("type") != "http.request":
                continue
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > self.max_body_bytes:
                await self._reject(scope, receive, send, 413, "anchor request body is too large")
                return
            body.extend(chunk)
            if not message.get("more_body", False):
                break

        replayed = False

        async def replay_receive() -> dict[str, Any]:
            nonlocal replayed
            if disconnected or replayed:
                return {"type": "http.disconnect"}
            replayed = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.app(scope, replay_receive, send)


def validate_anchor_json_limits(value: Any) -> None:
    stack = [(value, 0)]
    key_count = 0
    node_count = 0
    aggregate_string_bytes = 0
    while stack:
        current, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise ValueError(f"anchor JSON exceeds maximum depth {MAX_JSON_DEPTH}")
        node_count += 1
        if node_count > MAX_JSON_NODES:
            raise ValueError(f"anchor JSON exceeds maximum node count {MAX_JSON_NODES}")
        if isinstance(current, dict):
            key_count += len(current)
            if key_count > MAX_JSON_KEYS:
                raise ValueError(f"anchor JSON exceeds maximum key count {MAX_JSON_KEYS}")
            for key, child in current.items():
                if not isinstance(key, str):
                    raise ValueError("anchor JSON object keys must be strings")
                key_bytes = len(key.encode("utf-8", errors="surrogatepass"))
                if key_bytes > MAX_JSON_KEY_BYTES:
                    raise ValueError(f"anchor JSON key exceeds {MAX_JSON_KEY_BYTES} bytes")
                aggregate_string_bytes += key_bytes
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)
        elif isinstance(current, str):
            string_bytes = len(current.encode("utf-8", errors="surrogatepass"))
            if string_bytes > MAX_JSON_STRING_BYTES:
                raise ValueError(f"anchor JSON string exceeds {MAX_JSON_STRING_BYTES} bytes")
            aggregate_string_bytes += string_bytes
        elif current is None or isinstance(current, (bool, int)):
            pass
        elif isinstance(current, float):
            if not math.isfinite(current):
                raise ValueError("anchor JSON numbers must be finite")
        else:
            raise ValueError(f"anchor value has unsupported JSON type {type(current).__name__}")
        if aggregate_string_bytes > MAX_JSON_AGGREGATE_STRING_BYTES:
            raise ValueError(
                f"anchor JSON exceeds aggregate string limit {MAX_JSON_AGGREGATE_STRING_BYTES} bytes"
            )


app = FastAPI(title="Catchplate signed audit transparency log")
app.add_middleware(AnchorBodyLimitMiddleware, max_body_bytes=MAX_ANCHOR_REQUEST_BODY_BYTES)


class AnchorBatch(BaseModel):
    records: list[dict[str, Any]] = Field(default_factory=list, max_length=500)

    @field_validator("records")
    @classmethod
    def enforce_json_limits(cls, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        validate_anchor_json_limits(records)
        return records


def canonical_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=True)


def sha256_bytes(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def sha256_prefixed_bytes(value: bytes) -> str:
    return "sha256:" + sha256_bytes(value).hex()


def sha256_prefixed_json(value: Any) -> str:
    return sha256_prefixed_bytes(canonical_json(value).encode("utf-8"))


def hash_to_bytes(value: str) -> bytes:
    if not value.startswith("sha256:"):
        raise ValueError(f"hash is not sha256-prefixed: {value}")
    return bytes.fromhex(value.split(":", 1)[1])


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64d(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def require_token(candidate: str | None) -> None:
    if not ANCHOR_TOKEN:
        raise HTTPException(status_code=503, detail="audit anchor token is not configured")
    if not candidate or not hmac.compare_digest(candidate, ANCHOR_TOKEN):
        raise HTTPException(status_code=401, detail="audit anchor authentication required")


def anchor_lock_path() -> Path:
    configured = os.getenv("CATCHPLATE_AUDIT_ANCHOR_LOCK_PATH", "").strip()
    return Path(configured) if configured else Path(f"{ANCHOR_PATH}.lock")


def anchor_transaction_path() -> Path:
    configured = os.getenv("CATCHPLATE_AUDIT_ANCHOR_TRANSACTION_PATH", "").strip()
    return Path(configured) if configured else Path(f"{ANCHOR_PATH}.txn")


@contextmanager
def anchor_file_lock(*, exclusive: bool) -> Iterator[None]:
    path = anchor_lock_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def load_signing_key() -> Ed25519PrivateKey:
    SIGNING_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if SIGNING_KEY_PATH.exists():
        key = serialization.load_pem_private_key(SIGNING_KEY_PATH.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("configured transparency log signing key is not Ed25519")
        return key
    key = Ed25519PrivateKey.generate()
    SIGNING_KEY_PATH.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(SIGNING_KEY_PATH, 0o600)
    return key


def public_key_info(key: Ed25519PrivateKey) -> dict[str, str]:
    public_key = key.public_key()
    pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {"pem": pem, "log_id": sha256_prefixed_bytes(der)}


def configured_signing_key_info(key: Ed25519PrivateKey | None = None) -> dict[str, Any]:
    private_key = key or load_signing_key()
    public_key = private_key.public_key()
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return {
        "private_key": private_key,
        "public_key": public_key,
        "der": der,
        "pem": pem,
        "log_id": sha256_prefixed_bytes(der),
    }


def trusted_checkpoint_key_path() -> tuple[Path, bool] | None:
    established = os.getenv(
        "CATCHPLATE_EXTERNAL_CHECKPOINT_TRUSTED_PUBLIC_KEY", ""
    ).strip()
    compatibility_alias = os.getenv(
        "CATCHPLATE_TRANSPARENCY_TRUSTED_PUBLIC_KEY", ""
    ).strip()
    if established and compatibility_alias:
        established_path = Path(established).expanduser().resolve(strict=False)
        alias_path = Path(compatibility_alias).expanduser().resolve(strict=False)
        if established_path != alias_path:
            raise ValueError(
                "CATCHPLATE_EXTERNAL_CHECKPOINT_TRUSTED_PUBLIC_KEY conflicts with "
                "CATCHPLATE_TRANSPARENCY_TRUSTED_PUBLIC_KEY"
            )
    configured_public_key = established or compatibility_alias
    if configured_public_key:
        return Path(configured_public_key), False
    if CHECKPOINT_MODE != "fixture":
        return None
    if EXTERNAL_CHECKPOINT_KEY_PATH:
        return Path(EXTERNAL_CHECKPOINT_KEY_PATH), True
    if EXTERNAL_CHECKPOINT_LOG_PATH:
        return Path(EXTERNAL_CHECKPOINT_LOG_PATH).with_suffix(".ed25519.pem"), True
    default_log = Path(__file__).resolve().parent.parent / ".tmp" / "managed-transparency-log.jsonl"
    return default_log.with_suffix(".ed25519.pem"), True


def configured_checkpoint_key_info(*, required: bool) -> dict[str, Any] | None:
    configured = trusted_checkpoint_key_path()
    if configured is None:
        if required:
            raise ValueError(
                "external checkpoint trusted key is not configured; set "
                "CATCHPLATE_TRANSPARENCY_TRUSTED_PUBLIC_KEY"
            )
        return None
    path, allow_private_fixture_key = configured
    try:
        encoded = path.read_bytes()
    except FileNotFoundError as exc:
        if required:
            raise ValueError(f"external checkpoint trusted key does not exist: {path}") from exc
        return None
    if len(encoded) > 64 * 1024:
        raise ValueError("external checkpoint trusted key exceeds 64 KiB")
    public_key: Ed25519PublicKey | None = None
    try:
        candidate = serialization.load_pem_public_key(encoded)
        if isinstance(candidate, Ed25519PublicKey):
            public_key = candidate
    except Exception:
        candidate = None
    if public_key is None and allow_private_fixture_key:
        try:
            private_candidate = serialization.load_pem_private_key(encoded, password=None)
        except Exception as exc:
            raise ValueError("external checkpoint fixture trust key is invalid") from exc
        if isinstance(private_candidate, Ed25519PrivateKey):
            public_key = private_candidate.public_key()
    if public_key is None:
        raise ValueError("external checkpoint trusted public key is not Ed25519")
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    log_id = sha256_prefixed_bytes(der)
    if EXPECTED_CHECKPOINT_LOG_ID and not hmac.compare_digest(EXPECTED_CHECKPOINT_LOG_ID, log_id):
        raise ValueError(
            "external checkpoint trusted key does not match "
            "CATCHPLATE_TRANSPARENCY_EXPECTED_LOG_ID"
        )
    return {
        "public_key": public_key,
        "der": der,
        "log_id": log_id,
        "path": path,
    }


def sign_tree_head(
    *,
    tree_size: int,
    tree_head_hash: str,
    key: Ed25519PrivateKey | None = None,
) -> dict[str, Any]:
    key = key or load_signing_key()
    key_info = public_key_info(key)
    payload = {
        "version": "catchplate.transparencyLog/v1",
        "tree_size": tree_size,
        "tree_head_hash": tree_head_hash,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "log_id": key_info["log_id"],
    }
    payload["signature"] = "ed25519:" + b64e(key.sign(canonical_json(payload).encode("utf-8")))
    payload["public_key_pem"] = key_info["pem"]
    return payload


def verify_tree_head_signature(sth: dict[str, Any], expected_key_info: dict[str, Any] | None = None) -> None:
    signature = sth.get("signature")
    public_key_pem = sth.get("public_key_pem")
    if not isinstance(signature, str) or not signature.startswith("ed25519:"):
        raise ValueError("signed tree head is missing ed25519 signature")
    if not isinstance(public_key_pem, str):
        raise ValueError("signed tree head is missing public key")
    expected = expected_key_info or configured_signing_key_info()
    try:
        embedded_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    except Exception as exc:
        raise ValueError("signed tree head public key is invalid") from exc
    if not isinstance(embedded_key, Ed25519PublicKey):
        raise ValueError("signed tree head public key is not Ed25519")
    embedded_der = embedded_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    embedded_log_id = sha256_prefixed_bytes(embedded_der)
    claimed_log_id = sth.get("log_id")
    if not isinstance(claimed_log_id, str) or not hmac.compare_digest(claimed_log_id, embedded_log_id):
        raise ValueError("signed tree head log_id does not match its SPKI digest")
    if not hmac.compare_digest(embedded_log_id, expected["log_id"]) or not hmac.compare_digest(
        embedded_der, expected["der"]
    ):
        raise ValueError("signed tree head key does not match the configured signing key")
    payload = dict(sth)
    payload.pop("signature", None)
    payload.pop("public_key_pem", None)
    expected["public_key"].verify(
        b64d(signature.split(":", 1)[1]),
        canonical_json(payload).encode("utf-8"),
    )


def leaf_payload(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "anchor_id": item.get("anchor_id"),
        "sequence": item.get("sequence"),
        "received_at": item.get("received_at"),
        "record": item.get("record"),
        "record_digest": item.get("record_digest"),
    }


def leaf_hash(payload: dict[str, Any]) -> str:
    return sha256_prefixed_bytes(b"\x00" + canonical_json(payload).encode("utf-8"))


def node_hash(left: str, right: str) -> str:
    return sha256_prefixed_bytes(b"\x01" + hash_to_bytes(left) + hash_to_bytes(right))


def split_point(count: int) -> int:
    value = 1
    while value * 2 < count:
        value *= 2
    return value


def merkle_root(leaves: list[str]) -> str | None:
    if not leaves:
        return None
    if len(leaves) == 1:
        return leaves[0]
    split = split_point(len(leaves))
    left = merkle_root(leaves[:split])
    right = merkle_root(leaves[split:])
    if left is None or right is None:
        raise ValueError("invalid empty merkle subtree")
    return node_hash(left, right)


class MerkleAccumulator:
    def __init__(self) -> None:
        self.frontier: list[str | None] = []
        self.size = 0
        self.checkpoint_log_id: str | None = None

    def append(self, leaf: str) -> None:
        carry = leaf
        level = 0
        while level < len(self.frontier) and self.frontier[level] is not None:
            carry = node_hash(self.frontier[level] or "", carry)
            self.frontier[level] = None
            level += 1
        if level == len(self.frontier):
            self.frontier.append(carry)
        else:
            self.frontier[level] = carry
        self.size += 1

    def root(self) -> str | None:
        root: str | None = None
        for subtree in self.frontier:
            if subtree is None:
                continue
            root = subtree if root is None else node_hash(subtree, root)
        return root

    def clone(self) -> MerkleAccumulator:
        cloned = MerkleAccumulator()
        cloned.frontier = list(self.frontier)
        cloned.size = self.size
        cloned.checkpoint_log_id = self.checkpoint_log_id
        return cloned


def inclusion_proof(leaves: list[str], index: int, offset: int = 0) -> list[dict[str, str]]:
    if index < offset or index >= offset + len(leaves):
        raise ValueError("leaf index is outside this subtree")
    if len(leaves) <= 1:
        return []
    split = split_point(len(leaves))
    split_index = offset + split
    if index < split_index:
        sibling = merkle_root(leaves[split:])
        if sibling is None:
            raise ValueError("missing right sibling")
        return inclusion_proof(leaves[:split], index, offset) + [{"side": "right", "hash": sibling}]
    sibling = merkle_root(leaves[:split])
    if sibling is None:
        raise ValueError("missing left sibling")
    return inclusion_proof(leaves[split:], index, split_index) + [{"side": "left", "hash": sibling}]


def verify_inclusion(leaf: str, proof: list[dict[str, str]], root: str) -> bool:
    cursor = leaf
    for step in proof:
        side = step.get("side")
        sibling = step.get("hash")
        if side == "left" and isinstance(sibling, str):
            cursor = node_hash(sibling, cursor)
        elif side == "right" and isinstance(sibling, str):
            cursor = node_hash(cursor, sibling)
        else:
            return False
    return hmac.compare_digest(cursor, root)


def iter_anchors() -> Iterator[dict[str, Any]]:
    if not ANCHOR_PATH.exists():
        return
    with ANCHOR_PATH.open("rb") as handle:
        line_number = 0
        while raw := handle.readline(MAX_ANCHOR_LINE_BYTES + 1):
            line_number += 1
            if len(raw) > MAX_ANCHOR_LINE_BYTES:
                raise ValueError(f"anchor log line {line_number} exceeds 8 MiB")
            line = raw.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except Exception as exc:
                raise ValueError(f"anchor log line {line_number} is not valid JSON") from exc
            if not isinstance(item, dict):
                raise ValueError(f"anchor log line {line_number} must be a JSON object")
            yield item


def anchor_file_stamp() -> tuple[int, int, int, int, int] | None:
    try:
        stat = ANCHOR_PATH.stat()
    except FileNotFoundError:
        return None
    return (
        stat.st_dev,
        stat.st_ino,
        stat.st_mtime_ns,
        stat.st_ctime_ns,
        stat.st_size,
    )


def anchor_tail_digest() -> str | None:
    try:
        handle = ANCHOR_PATH.open("rb")
    except FileNotFoundError:
        return None
    with handle:
        size = handle.seek(0, os.SEEK_END)
        handle.seek(max(0, size - ANCHOR_TAIL_DIGEST_BYTES))
        return hashlib.sha256(handle.read(ANCHOR_TAIL_DIGEST_BYTES)).hexdigest()


def anchor_cache_identity() -> tuple[tuple[int, int, int, int, int] | None, str | None]:
    before = anchor_file_stamp()
    digest = anchor_tail_digest()
    after = anchor_file_stamp()
    if before != after:
        raise HTTPException(status_code=409, detail="anchor log changed while reading cache identity")
    return after, digest


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def reset_anchor_caches() -> None:
    global ANCHOR_COUNT_CACHE, ANCHOR_STATE_CACHE
    ANCHOR_COUNT_CACHE = None
    ANCHOR_STATE_CACHE = None


def write_anchor_transaction_intent(
    encoded_batch: bytes,
    base_identity: tuple[tuple[int, int, int, int, int] | None, str | None],
) -> None:
    if not encoded_batch:
        return
    transaction_path = anchor_transaction_path()
    if transaction_path.exists():
        raise RuntimeError("pending anchor append transaction requires recovery")
    stamp, tail_digest = base_identity
    intent = {
        "version": "catchplate.anchorAppendTransaction/v1",
        "base_exists": stamp is not None,
        "base_device": stamp[0] if stamp else None,
        "base_inode": stamp[1] if stamp else None,
        "base_size": stamp[4] if stamp else 0,
        "base_tail_digest": tail_digest,
        "append_size": len(encoded_batch),
        "append_digest": sha256_prefixed_bytes(encoded_batch),
        "append_base64": b64e(encoded_batch),
    }
    encoded_intent = (canonical_json(intent) + "\n").encode("utf-8")
    if len(encoded_intent) > MAX_ANCHOR_TRANSACTION_BYTES:
        raise HTTPException(status_code=413, detail="anchor append transaction exceeds durable intent limit")
    transaction_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = transaction_path.with_name(
        f".{transaction_path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    )
    try:
        descriptor = os.open(temporary_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            offset = 0
            while offset < len(encoded_intent):
                written = os.write(descriptor, encoded_intent[offset:])
                if written <= 0:
                    raise OSError("anchor transaction intent write made no progress")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary_path, transaction_path)
        fsync_directory(transaction_path.parent)
    finally:
        temporary_path.unlink(missing_ok=True)


def clear_anchor_transaction_intent() -> None:
    transaction_path = anchor_transaction_path()
    transaction_path.unlink()
    fsync_directory(transaction_path.parent)


def recover_anchor_transaction() -> bool:
    transaction_path = anchor_transaction_path()
    try:
        with transaction_path.open("rb") as handle:
            encoded_intent = handle.read(MAX_ANCHOR_TRANSACTION_BYTES + 1)
    except FileNotFoundError:
        return False
    if len(encoded_intent) > MAX_ANCHOR_TRANSACTION_BYTES:
        raise RuntimeError("anchor append transaction intent exceeds size limit")
    try:
        intent = json.loads(encoded_intent)
    except Exception as exc:
        raise RuntimeError("anchor append transaction intent is invalid JSON") from exc
    if not isinstance(intent, dict) or intent.get("version") != "catchplate.anchorAppendTransaction/v1":
        raise RuntimeError("anchor append transaction intent has unsupported format")
    base_exists = intent.get("base_exists")
    base_size = intent.get("base_size")
    append_size = intent.get("append_size")
    append_base64 = intent.get("append_base64")
    if (
        not isinstance(base_exists, bool)
        or not isinstance(base_size, int)
        or base_size < 0
        or not isinstance(append_size, int)
        or append_size <= 0
        or append_size > MAX_ANCHOR_BATCH_APPEND_BYTES
        or not isinstance(append_base64, str)
    ):
        raise RuntimeError("anchor append transaction intent fields are invalid")
    try:
        encoded_batch = b64d(append_base64)
    except Exception as exc:
        raise RuntimeError("anchor append transaction payload is invalid") from exc
    if (
        len(encoded_batch) != append_size
        or b64e(encoded_batch) != append_base64
        or intent.get("append_digest") != sha256_prefixed_bytes(encoded_batch)
    ):
        raise RuntimeError("anchor append transaction payload digest mismatch")

    descriptor: int | None = None
    try:
        descriptor = os.open(ANCHOR_PATH, os.O_RDWR)
    except FileNotFoundError:
        if base_exists or base_size != 0:
            raise RuntimeError("anchor log disappeared during append transaction")
    if descriptor is not None:
        try:
            stat = os.fstat(descriptor)
            if base_exists and (
                stat.st_dev != intent.get("base_device")
                or stat.st_ino != intent.get("base_inode")
            ):
                raise RuntimeError("anchor log identity changed during append transaction")
            if not base_exists and base_size == 0 and stat.st_size > len(encoded_batch):
                raise RuntimeError("new anchor log exceeds pending append transaction")
            if stat.st_size < base_size or stat.st_size > base_size + len(encoded_batch):
                raise RuntimeError("anchor log size diverged from pending append transaction")
            base_tail_start = max(0, base_size - ANCHOR_TAIL_DIGEST_BYTES)
            base_tail = os.pread(descriptor, base_size - base_tail_start, base_tail_start)
            expected_tail_digest = intent.get("base_tail_digest")
            actual_tail_digest = hashlib.sha256(base_tail).hexdigest() if base_exists else None
            if actual_tail_digest != expected_tail_digest:
                raise RuntimeError("anchor log base changed during append transaction")
            appended_size = stat.st_size - base_size
            appended = os.pread(descriptor, appended_size, base_size)
            if appended != encoded_batch[:appended_size]:
                raise RuntimeError("anchor log suffix diverged from pending append transaction")
            os.ftruncate(descriptor, base_size)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    if not base_exists and ANCHOR_PATH.exists():
        ANCHOR_PATH.unlink()
        fsync_directory(ANCHOR_PATH.parent)
    clear_anchor_transaction_intent()
    reset_anchor_caches()
    return True


def encode_anchor_line(item: dict[str, Any]) -> str:
    encoded = canonical_json(item)
    if len(encoded.encode("utf-8")) + 1 > MAX_ANCHOR_LINE_BYTES:
        raise HTTPException(status_code=413, detail="anchor log record exceeds 8 MiB")
    return encoded


def append_anchor_batch_durably(encoded_batch: bytes) -> None:
    if not encoded_batch:
        return
    original_size = ANCHOR_PATH.stat().st_size if ANCHOR_PATH.exists() else 0
    descriptor = os.open(ANCHOR_PATH, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        offset = 0
        while offset < len(encoded_batch):
            written = os.write(descriptor, encoded_batch[offset:])
            if written <= 0:
                raise OSError("anchor batch append made no progress")
            offset += written
        os.fsync(descriptor)
    except BaseException:
        try:
            os.ftruncate(descriptor, original_size)
            os.fsync(descriptor)
        except OSError:
            pass
        raise
    finally:
        os.close(descriptor)


def require_anchor_precheck_size(item: dict[str, Any]) -> None:
    if len(canonical_json(item).encode("utf-8")) > MAX_ANCHOR_PRECHECK_BYTES:
        raise HTTPException(status_code=413, detail="anchor record exceeds the 6 MiB pre-check limit")


def count_anchors() -> int:
    global ANCHOR_COUNT_CACHE
    with ANCHOR_LOCK, anchor_file_lock(exclusive=True):
        recover_anchor_transaction()
        if not ANCHOR_PATH.exists():
            return 0
        with ANCHOR_COUNT_LOCK:
            before = ANCHOR_PATH.stat()
            stamp = (
                before.st_dev,
                before.st_ino,
                before.st_mtime_ns,
                before.st_ctime_ns,
                before.st_size,
            )
            if ANCHOR_COUNT_CACHE and ANCHOR_COUNT_CACHE[:-1] == stamp:
                return ANCHOR_COUNT_CACHE[-1]
            count = sum(1 for _ in iter_anchors())
            after = ANCHOR_PATH.stat()
            after_stamp = (
                after.st_dev,
                after.st_ino,
                after.st_mtime_ns,
                after.st_ctime_ns,
                after.st_size,
            )
            if after_stamp == stamp:
                ANCHOR_COUNT_CACHE = (*stamp, count)
            return count


def cache_anchor_count(count: int) -> None:
    global ANCHOR_COUNT_CACHE
    stat = ANCHOR_PATH.stat()
    with ANCHOR_COUNT_LOCK:
        ANCHOR_COUNT_CACHE = (
            stat.st_dev,
            stat.st_ino,
            stat.st_mtime_ns,
            stat.st_ctime_ns,
            stat.st_size,
            count,
        )


def _verify_items(
    items: Iterable[dict[str, Any]],
    expected_key_info: dict[str, Any] | None = None,
    expected_checkpoint_key_info: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], MerkleAccumulator]:
    accumulator = MerkleAccumulator()
    last_record = None
    last_item = None
    count = 0
    signing_key_info = expected_key_info
    checkpoint_key_info = expected_checkpoint_key_info
    for index, item in enumerate(items):
        expected_sequence = index + 1
        if item.get("sequence") != expected_sequence:
            return {"ok": False, "error": "sequence_mismatch", "index": index}, accumulator
        expected_record_digest = sha256_prefixed_json(item.get("record"))
        if item.get("record_digest") != expected_record_digest:
            return {"ok": False, "error": "record_digest_mismatch", "index": index}, accumulator
        expected_leaf_hash = leaf_hash(leaf_payload(item))
        if item.get("leaf_hash") != expected_leaf_hash:
            return {"ok": False, "error": "leaf_hash_mismatch", "index": index}, accumulator
        accumulator.append(expected_leaf_hash)
        expected_root = accumulator.root()
        if item.get("tree_size") != expected_sequence:
            return {"ok": False, "error": "tree_size_mismatch", "index": index}, accumulator
        if item.get("tree_head_hash") != expected_root:
            return {"ok": False, "error": "tree_head_hash_mismatch", "index": index}, accumulator
        try:
            if signing_key_info is None:
                signing_key_info = configured_signing_key_info()
            verify_tree_head_signature(item.get("signed_tree_head") or {}, signing_key_info)
        except Exception as exc:
            return {
                "ok": False,
                "error": "signed_tree_head_invalid",
                "index": index,
                "detail": str(exc),
            }, accumulator
        sth = item.get("signed_tree_head") or {}
        if sth.get("tree_size") != item.get("tree_size") or sth.get("tree_head_hash") != item.get("tree_head_hash"):
            return {"ok": False, "error": "signed_tree_head_claim_mismatch", "index": index}, accumulator
        external_checkpoint = item.get("external_checkpoint")
        if external_checkpoint is None and CHECKPOINT_REQUIRED:
            return {"ok": False, "error": "external_checkpoint_missing", "index": index}, accumulator
        if external_checkpoint is not None:
            try:
                if checkpoint_key_info is None:
                    checkpoint_key_info = configured_checkpoint_key_info(required=True)
            except Exception as exc:
                return {
                    "ok": False,
                    "error": "external_checkpoint_trusted_key_invalid",
                    "index": index,
                    "detail": str(exc),
                }, accumulator
            error = validate_external_checkpoint_response(
                external_checkpoint,
                checkpoint_payload_for_item(item),
                item,
                checkpoint_key_info,
            )
            if error:
                return {"ok": False, "error": error, "index": index}, accumulator
            accumulator.checkpoint_log_id = checkpoint_key_info["log_id"]
        last_record = item.get("record")
        last_item = item
        count = expected_sequence
    head = accumulator.root()
    return (
        {
            "ok": True,
            "mode": "signed-merkle-transparency-log",
            "count": count,
            "head": head,
            "tree_size": count,
            "signed_tree_head": last_item.get("signed_tree_head") if last_item else None,
            "last_record": last_record,
        },
        accumulator,
    )


def verify_items(items: Iterable[dict[str, Any]]) -> dict[str, Any]:
    return _verify_items(items)[0]


def cache_verified_anchor_state(
    verification: dict[str, Any],
    accumulator: MerkleAccumulator,
    identity: tuple[tuple[int, int, int, int, int] | None, str | None],
    signing_log_id: str,
    checkpoint_log_id: str | None,
) -> None:
    global ANCHOR_STATE_CACHE
    if verification.get("ok") is not True:
        return
    ANCHOR_STATE_CACHE = {
        "identity": identity,
        "verification": dict(verification),
        "frontier": list(accumulator.frontier),
        "size": accumulator.size,
        "signing_log_id": signing_log_id,
        "checkpoint_log_id": checkpoint_log_id,
    }


def verified_anchor_state(
    signing_key_info: dict[str, Any] | None = None,
) -> tuple[
    dict[str, Any],
    MerkleAccumulator,
    tuple[tuple[int, int, int, int, int] | None, str | None],
]:
    cached = ANCHOR_STATE_CACHE
    current_identity = anchor_cache_identity()
    signing_key_info = signing_key_info or configured_signing_key_info()
    cached_checkpoint_log_id = cached.get("checkpoint_log_id") if cached else None
    checkpoint_key_info = None
    if cached_checkpoint_log_id:
        checkpoint_key_info = configured_checkpoint_key_info(required=True)
    if (
        cached
        and cached.get("identity") == current_identity
        and cached.get("signing_log_id") == signing_key_info["log_id"]
        and (
            cached_checkpoint_log_id is None
            or checkpoint_key_info is not None
            and cached_checkpoint_log_id == checkpoint_key_info["log_id"]
        )
    ):
        accumulator = MerkleAccumulator()
        accumulator.frontier = list(cached["frontier"])
        accumulator.size = int(cached["size"])
        accumulator.checkpoint_log_id = cached_checkpoint_log_id
        return dict(cached["verification"]), accumulator, current_identity
    before = current_identity
    verification, accumulator = _verify_items(
        iter_anchors(),
        signing_key_info,
        checkpoint_key_info,
    )
    after = anchor_cache_identity()
    if before != after:
        raise HTTPException(status_code=409, detail="anchor log changed during verification")
    cache_verified_anchor_state(
        verification,
        accumulator,
        after,
        signing_key_info["log_id"],
        accumulator.checkpoint_log_id,
    )
    return verification, accumulator, after


def inclusion_ranges(
    count: int, index: int, offset: int = 0
) -> list[tuple[int, int, str]]:
    if index < offset or index >= offset + count:
        raise ValueError("leaf index is outside this subtree")
    if count <= 1:
        return []
    split = split_point(count)
    split_index = offset + split
    if index < split_index:
        return inclusion_ranges(split, index, offset) + [
            (split_index, offset + count, "right")
        ]
    return inclusion_ranges(count - split, index, split_index) + [
        (offset, split_index, "left")
    ]


def streaming_inclusion_proof(
    items: Iterable[dict[str, Any]], count: int, index: int
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    ranges = inclusion_ranges(count, index)
    states = [
        {"start": start, "end": end, "side": side, "accumulator": MerkleAccumulator()}
        for start, end, side in ranges
    ]
    target = None
    seen = 0
    for seen, item in enumerate(items, start=1):
        item_index = seen - 1
        leaf = item.get("leaf_hash")
        if not isinstance(leaf, str):
            raise ValueError("anchor log item is missing leaf_hash")
        if item_index == index:
            target = item
        for state in states:
            if state["start"] <= item_index < state["end"]:
                state["accumulator"].append(leaf)
                break
    if seen != count or target is None:
        raise ValueError("anchor log changed while building inclusion proof")
    proof = []
    for state in states:
        sibling = state["accumulator"].root()
        if sibling is None:
            raise ValueError("anchor inclusion range is empty")
        proof.append({"side": state["side"], "hash": sibling})
    return proof, target


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    return {
        "ok": True,
        "mode": "signed-merkle-transparency-log",
        "anchors": count_anchors(),
        "external_checkpoint_configured": bool(CHECKPOINT_COMMAND),
        "external_checkpoint_required": CHECKPOINT_REQUIRED,
    }


def checkpoint_payload_for_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "version": "catchplate.transparencyCheckpoint/v1",
        "mode": "signed-merkle-transparency-log",
        "sequence": item["sequence"],
        "record_digest": item["record_digest"],
        "leaf_hash": item["leaf_hash"],
        "tree_size": item["tree_size"],
        "tree_head_hash": item["tree_head_hash"],
        "signed_tree_head": item["signed_tree_head"],
        "record": item["record"],
    }


class SubprocessOutputLimitExceeded(RuntimeError):
    def __init__(self, stream: str, limit: int, stdout: bytes, stderr: bytes) -> None:
        super().__init__(f"subprocess {stream} exceeded {limit} bytes")
        self.stream = stream
        self.limit = limit
        self.stdout = stdout
        self.stderr = stderr


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    process_group = process.pid

    def group_exists() -> bool:
        try:
            os.killpg(process_group, 0)
            return True
        except ProcessLookupError:
            return False

    try:
        os.killpg(process_group, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + 0.5
    while time.monotonic() < deadline:
        process.poll()
        if not group_exists():
            break
        time.sleep(0.02)
    if group_exists():
        try:
            os.killpg(process_group, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def run_bounded_subprocess(
    args: list[str],
    *,
    input_data: bytes,
    timeout: float,
    stdout_limit: int,
    stderr_limit: int,
) -> subprocess.CompletedProcess[bytes]:
    process = subprocess.Popen(
        args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
        start_new_session=True,
    )
    if process.stdin is None or process.stdout is None or process.stderr is None:
        _terminate_process_group(process)
        raise RuntimeError("checkpoint subprocess pipes were not created")

    selector = selectors.DefaultSelector()
    stdout = bytearray()
    stderr = bytearray()
    input_offset = 0
    deadline = time.monotonic() + timeout

    def close_registered(stream: Any) -> None:
        try:
            selector.unregister(stream)
        except Exception:
            pass
        try:
            stream.close()
        except Exception:
            pass

    for stream in (process.stdin, process.stdout, process.stderr):
        os.set_blocking(stream.fileno(), False)
    if input_data:
        selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
    else:
        process.stdin.close()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")

    try:
        while process.poll() is None or any(
            key.data in {"stdout", "stderr"} for key in selector.get_map().values()
        ):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(
                    args,
                    timeout,
                    output=bytes(stdout),
                    stderr=bytes(stderr),
                )
            events = selector.select(min(remaining, 0.1))
            for key, _mask in events:
                stream = key.fileobj
                if key.data == "stdin":
                    try:
                        written = os.write(stream.fileno(), input_data[input_offset : input_offset + 64 * 1024])
                    except BrokenPipeError:
                        close_registered(stream)
                        continue
                    input_offset += written
                    if input_offset >= len(input_data):
                        close_registered(stream)
                    continue

                try:
                    chunk = os.read(stream.fileno(), 64 * 1024)
                except BlockingIOError:
                    continue
                if not chunk:
                    close_registered(stream)
                    continue
                output = stdout if key.data == "stdout" else stderr
                limit = stdout_limit if key.data == "stdout" else stderr_limit
                available = max(0, limit - len(output))
                output.extend(chunk[:available])
                if len(chunk) > available:
                    raise SubprocessOutputLimitExceeded(
                        key.data,
                        limit,
                        bytes(stdout),
                        bytes(stderr),
                    )
        returncode = process.wait()
        _terminate_process_group(process)
        return subprocess.CompletedProcess(args, returncode, bytes(stdout), bytes(stderr))
    except BaseException:
        _terminate_process_group(process)
        raise
    finally:
        for stream in (process.stdin, process.stdout, process.stderr):
            close_registered(stream)
        selector.close()


def verify_external_checkpoint_receipt(
    response: dict[str, Any],
    payload: dict[str, Any],
    item: dict[str, Any],
    trusted_key_info: dict[str, Any],
) -> str | None:
    receipt = response.get("receipt")
    if not isinstance(receipt, dict):
        return "external_checkpoint_receipt_missing"
    if receipt.get("kind") != "ed25519-signed-checkpoint":
        return "external_checkpoint_receipt_kind_unsupported"
    receipt_payload = receipt.get("payload")
    signature = receipt.get("signature")
    public_key_pem = receipt.get("public_key_pem")
    if not isinstance(receipt_payload, dict):
        return "external_checkpoint_receipt_payload_invalid"
    if not isinstance(signature, str) or not signature.startswith("ed25519:"):
        return "external_checkpoint_receipt_signature_invalid"
    if not isinstance(public_key_pem, str):
        return "external_checkpoint_receipt_public_key_invalid"
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    except Exception:
        return "external_checkpoint_receipt_public_key_invalid"
    if not isinstance(public_key, Ed25519PublicKey):
        return "external_checkpoint_receipt_public_key_invalid"
    embedded_key_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    trusted_log_id = trusted_key_info["log_id"]
    if EXPECTED_CHECKPOINT_LOG_ID and not hmac.compare_digest(
        EXPECTED_CHECKPOINT_LOG_ID, trusted_log_id
    ):
        return "external_checkpoint_trusted_log_id_mismatch"
    if not hmac.compare_digest(embedded_key_der, trusted_key_info["der"]):
        return "external_checkpoint_receipt_untrusted_key"
    if response.get("log_id") != trusted_log_id or receipt_payload.get("log_id") != trusted_log_id:
        return "external_checkpoint_receipt_log_id_mismatch"

    external_sequence = response.get("external_sequence", response.get("checkpoint_id"))
    expected_fields = {
        "provider": response.get("provider"),
        "external_sequence": external_sequence,
        "checkpoint_digest": sha256_prefixed_json(payload),
        "request_digest": response.get("request_digest"),
        "source_sequence": item.get("sequence"),
        "tree_size": item.get("tree_size"),
        "tree_head_hash": item.get("tree_head_hash"),
        "record_digest": item.get("record_digest"),
        "leaf_hash": item.get("leaf_hash"),
    }
    for field, expected in expected_fields.items():
        if receipt_payload.get(field) != expected:
            return f"external_checkpoint_receipt_{field}_mismatch"
    try:
        encoded_signature = signature.split(":", 1)[1]
        signature_bytes = b64d(encoded_signature)
        if len(signature_bytes) != 64 or b64e(signature_bytes) != encoded_signature:
            return "external_checkpoint_receipt_signature_invalid"
        trusted_key_info["public_key"].verify(
            signature_bytes,
            canonical_json(receipt_payload).encode("utf-8"),
        )
    except Exception:
        return "external_checkpoint_receipt_signature_mismatch"
    return None


def validate_external_checkpoint_response(
    response: Any,
    payload: dict[str, Any],
    item: dict[str, Any],
    trusted_key_info: dict[str, Any] | None = None,
) -> str | None:
    if not isinstance(response, dict) or response.get("ok") is not True:
        return "external_checkpoint_invalid"
    for field in ("provider", "mode", "checkpoint_digest", "log_id"):
        if not response.get(field):
            return f"external_checkpoint_{field}_missing"
    if response.get("mode") != "external-managed-transparency-log":
        return "external_checkpoint_mode_unsupported"
    if response.get("checkpoint_digest") != sha256_prefixed_json(payload):
        return "external_checkpoint_digest_mismatch"
    if response.get("tree_head_hash") != item["tree_head_hash"]:
        return "external_checkpoint_tree_head_mismatch"
    if response.get("tree_size") != item["tree_size"]:
        return "external_checkpoint_tree_size_mismatch"
    external_sequence = response.get("external_sequence", response.get("checkpoint_id"))
    if external_sequence is None or external_sequence == "":
        return "external_checkpoint_sequence_missing"
    request_digest = response.get("request_digest")
    if not isinstance(request_digest, str) or not request_digest.startswith("sha256:"):
        return "external_checkpoint_request_digest_invalid"
    try:
        trusted = trusted_key_info or configured_checkpoint_key_info(required=True)
    except Exception:
        return "external_checkpoint_trusted_key_invalid"
    if trusted is None:
        return "external_checkpoint_trusted_key_invalid"
    return verify_external_checkpoint_receipt(response, payload, item, trusted)


def publish_external_checkpoint(item: dict[str, Any]) -> dict[str, Any] | None:
    if not CHECKPOINT_COMMAND:
        if CHECKPOINT_REQUIRED:
            raise HTTPException(status_code=503, detail="external transparency checkpoint command is required but not configured")
        return None
    payload = checkpoint_payload_for_item(item)
    try:
        result = run_bounded_subprocess(
            shlex.split(CHECKPOINT_COMMAND),
            input_data=canonical_json(payload).encode("utf-8"),
            stdout_limit=MAX_EXTERNAL_CHECKPOINT_BYTES,
            stderr_limit=MAX_EXTERNAL_CHECKPOINT_STDERR_BYTES,
            timeout=EXTERNAL_CHECKPOINT_TIMEOUT_SECONDS,
        )
    except SubprocessOutputLimitExceeded as exc:
        error = (
            "external_checkpoint_response_too_large"
            if exc.stream == "stdout"
            else "external_checkpoint_error_too_large"
        )
        if CHECKPOINT_REQUIRED:
            raise HTTPException(status_code=502, detail={"error": error}) from exc
        return {"ok": False, "error": error}
    except Exception as exc:
        if CHECKPOINT_REQUIRED:
            raise HTTPException(status_code=502, detail={"error": "external_checkpoint_failed", "detail": str(exc)}) from exc
        return {"ok": False, "error": "external_checkpoint_failed", "detail": str(exc)}
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace") or result.stdout.decode("utf-8", errors="replace")
        if CHECKPOINT_REQUIRED:
            raise HTTPException(
                status_code=502,
                detail={"error": "external_checkpoint_denied", "exit": result.returncode, "detail": detail[-2000:]},
            )
        return {"ok": False, "error": "external_checkpoint_denied", "exit": result.returncode, "detail": detail[-2000:]}
    try:
        response = json.loads(result.stdout.decode("utf-8"))
    except Exception as exc:
        if CHECKPOINT_REQUIRED:
            raise HTTPException(status_code=502, detail={"error": "external_checkpoint_invalid_json"}) from exc
        return {"ok": False, "error": "external_checkpoint_invalid_json"}
    if response.get("ok") is not True:
        if CHECKPOINT_REQUIRED:
            raise HTTPException(status_code=502, detail={"error": "external_checkpoint_rejected", "response": response})
        return response
    validation_error = validate_external_checkpoint_response(response, payload, item)
    if validation_error:
        if CHECKPOINT_REQUIRED:
            raise HTTPException(status_code=502, detail={"error": validation_error, "response": response})
        return {"ok": False, "error": validation_error, "response": response}
    return response


@app.get("/anchors")
def anchors_list(
    limit: int = Query(100, ge=1, le=1000),
    x_catchplate_audit_anchor_token: str | None = Header(default=None, alias="X-Catchplate-Audit-Anchor-Token"),
) -> dict[str, Any]:
    require_token(x_catchplate_audit_anchor_token)
    with ANCHOR_LOCK, anchor_file_lock(exclusive=True):
        recover_anchor_transaction()
        tail: deque[dict[str, Any]] = deque(maxlen=limit)
        signing_key_info = configured_signing_key_info()

        def tracked_items() -> Iterator[dict[str, Any]]:
            for item in iter_anchors():
                tail.append(item)
                yield item

        before = anchor_cache_identity()
        verification, accumulator = _verify_items(tracked_items(), signing_key_info)
        after = anchor_cache_identity()
        if before != after:
            raise HTTPException(status_code=409, detail="anchor log changed during verification")
        if verification.get("ok") is not True:
            raise HTTPException(
                status_code=409,
                detail={"error": "anchor_log_corrupt", "verification": verification},
            )
        cache_verified_anchor_state(
            verification,
            accumulator,
            after,
            signing_key_info["log_id"],
            accumulator.checkpoint_log_id,
        )
    return {
        "ok": True,
        "mode": "signed-merkle-transparency-log",
        "count": verification.get("count", 0),
        "items": list(tail),
        "verification": verification,
    }


@app.get("/anchors/inclusion/{sequence}")
def anchor_inclusion(
    sequence: int,
    x_catchplate_audit_anchor_token: str | None = Header(default=None, alias="X-Catchplate-Audit-Anchor-Token"),
) -> dict[str, Any]:
    require_token(x_catchplate_audit_anchor_token)
    with ANCHOR_LOCK, anchor_file_lock(exclusive=True):
        recover_anchor_transaction()
        signing_key_info = configured_signing_key_info()
        before = anchor_cache_identity()
        verification, accumulator = _verify_items(iter_anchors(), signing_key_info)
        if not verification.get("ok"):
            raise HTTPException(status_code=409, detail={"error": "anchor_log_corrupt", "verification": verification})
        count = int(verification.get("count") or 0)
        if sequence < 1 or sequence > count:
            raise HTTPException(status_code=404, detail="anchor sequence not found")
        verified_identity = anchor_cache_identity()
        if before != verified_identity:
            raise HTTPException(status_code=409, detail="anchor log changed during verification")
        try:
            proof, item = streaming_inclusion_proof(
                iter_anchors(), count, sequence - 1
            )
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        proven_identity = anchor_cache_identity()
        if before != proven_identity:
            raise HTTPException(status_code=409, detail="anchor log changed during inclusion proof")
        cache_verified_anchor_state(
            verification,
            accumulator,
            proven_identity,
            signing_key_info["log_id"],
            accumulator.checkpoint_log_id,
        )
        root = verification.get("head")
        signed_tree_head = verification.get("signed_tree_head")
    verified = isinstance(root, str) and verify_inclusion(item["leaf_hash"], proof, root)
    return {
        "ok": True,
        "mode": "signed-merkle-transparency-log",
        "sequence": sequence,
        "record_digest": item["record_digest"],
        "leaf_hash": item["leaf_hash"],
        "tree_size": count,
        "tree_head_hash": root,
        "signed_tree_head": signed_tree_head,
        "proof": proof,
        "verified": verified,
        "item": item,
    }


@app.post("/anchors")
def anchors(
    batch: AnchorBatch,
    x_catchplate_audit_anchor_token: str | None = Header(default=None, alias="X-Catchplate-Audit-Anchor-Token"),
) -> dict[str, Any]:
    require_token(x_catchplate_audit_anchor_token)
    with ANCHOR_LOCK, anchor_file_lock(exclusive=True):
        recover_anchor_transaction()
        ANCHOR_PATH.parent.mkdir(parents=True, exist_ok=True)
        signing_key_info = configured_signing_key_info()
        verification, accumulator, verified_identity = verified_anchor_state(signing_key_info)
        if not verification.get("ok"):
            raise HTTPException(status_code=409, detail={"error": "anchor_log_corrupt", "verification": verification})
        tree_size = int(verification.get("tree_size") or 0)
        staged_accumulator = accumulator.clone()
        prepared_items: list[dict[str, Any]] = []
        for record in batch.records:
            sequence = tree_size + 1
            item = {
                "anchor_id": str(uuid.uuid4()),
                "sequence": sequence,
                "received_at": datetime.now(timezone.utc).isoformat(),
                "record": record,
                "record_digest": sha256_prefixed_json(record),
            }
            item["leaf_hash"] = leaf_hash(leaf_payload(item))
            staged_accumulator.append(item["leaf_hash"])
            tree_size += 1
            tree_head_hash = staged_accumulator.root()
            if tree_head_hash is None:
                raise HTTPException(status_code=500, detail="empty transparency tree after append")
            item["tree_size"] = tree_size
            item["tree_head_hash"] = tree_head_hash
            item["signed_tree_head"] = sign_tree_head(
                tree_size=tree_size,
                tree_head_hash=tree_head_hash,
                key=signing_key_info["private_key"],
            )
            require_anchor_precheck_size(item)
            encode_anchor_line(item)
            prepared_items.append(item)

        accepted = []
        encoded_lines: list[bytes] = []
        encoded_batch_size = 0
        for item in prepared_items:
            external_checkpoint = publish_external_checkpoint(item)
            if external_checkpoint is not None and external_checkpoint.get("ok") is True:
                item["external_checkpoint"] = external_checkpoint
            if CHECKPOINT_REQUIRED and "external_checkpoint" not in item:
                raise HTTPException(status_code=502, detail="required external checkpoint was not accepted")
            encoded = (encode_anchor_line(item) + "\n").encode("utf-8")
            encoded_batch_size += len(encoded)
            if encoded_batch_size > MAX_ANCHOR_BATCH_APPEND_BYTES:
                raise HTTPException(status_code=413, detail="anchor batch exceeds durable append limit")
            encoded_lines.append(encoded)
            accepted.append(
                {
                    "sequence": item["sequence"],
                    "anchor_hash": item["leaf_hash"],
                    "leaf_hash": item["leaf_hash"],
                    "record_digest": item["record_digest"],
                    "tree_size": item["tree_size"],
                    "tree_head_hash": item["tree_head_hash"],
                    "signed_tree_head": item["signed_tree_head"],
                    "external_checkpoint": item.get("external_checkpoint"),
                }
            )

        if any(item.get("external_checkpoint") is not None for item in prepared_items):
            checkpoint_key_info = configured_checkpoint_key_info(required=True)
            if checkpoint_key_info is None:
                raise HTTPException(status_code=503, detail="external checkpoint trusted key is unavailable")
            staged_accumulator.checkpoint_log_id = checkpoint_key_info["log_id"]

        if anchor_cache_identity() != verified_identity:
            raise HTTPException(status_code=409, detail="anchor log changed before durable append")
        encoded_batch = b"".join(encoded_lines)
        if encoded_batch:
            write_anchor_transaction_intent(encoded_batch, verified_identity)
            try:
                append_anchor_batch_durably(encoded_batch)
            except BaseException:
                recover_anchor_transaction()
                raise
            clear_anchor_transaction_intent()
        accumulator = staged_accumulator
        if ANCHOR_PATH.exists():
            cache_anchor_count(tree_size)
        head = accumulator.root()
        signed_tree_head = (
            accepted[-1]["signed_tree_head"]
            if accepted
            else verification.get("signed_tree_head")
        )
        final_verification = {
            "ok": True,
            "mode": "signed-merkle-transparency-log",
            "count": tree_size,
            "head": head,
            "tree_size": tree_size,
            "signed_tree_head": signed_tree_head,
            "last_record": (
                batch.records[-1] if batch.records else verification.get("last_record")
            ),
        }
        appended_identity = anchor_cache_identity()
        cache_verified_anchor_state(
            final_verification,
            accumulator,
            appended_identity,
            signing_key_info["log_id"],
            accumulator.checkpoint_log_id,
        )
    return {
        "ok": True,
        "mode": "signed-merkle-transparency-log",
        "accepted": len(accepted),
        "anchors": accepted,
        "head": head,
        "tree_head_hash": head,
        "tree_size": tree_size,
        "signed_tree_head": signed_tree_head,
    }


@app.get("/anchors/verify")
def anchors_verify(
    x_catchplate_audit_anchor_token: str | None = Header(default=None, alias="X-Catchplate-Audit-Anchor-Token"),
) -> dict[str, Any]:
    require_token(x_catchplate_audit_anchor_token)
    with ANCHOR_LOCK, anchor_file_lock(exclusive=True):
        recover_anchor_transaction()
        signing_key_info = configured_signing_key_info()
        before = anchor_cache_identity()
        verification, accumulator = _verify_items(iter_anchors(), signing_key_info)
        after = anchor_cache_identity()
        if before != after:
            raise HTTPException(status_code=409, detail="anchor log changed during verification")
        cache_verified_anchor_state(
            verification,
            accumulator,
            after,
            signing_key_info["log_id"],
            accumulator.checkpoint_log_id,
        )
        return verification


def recover_anchor_transaction_on_startup() -> None:
    with ANCHOR_LOCK, anchor_file_lock(exclusive=True):
        recover_anchor_transaction()


app.router.add_event_handler("startup", recover_anchor_transaction_on_startup)


if __name__ == "__main__":
    if bool(TLS_CERT_FILE) != bool(TLS_KEY_FILE):
        raise SystemExit("audit anchor TLS certificate and key must be configured together")
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=9100,
        ssl_certfile=TLS_CERT_FILE or None,
        ssl_keyfile=TLS_KEY_FILE or None,
    )
