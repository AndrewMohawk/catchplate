#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parent.parent


def canonical_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=True)


def sha256_prefixed_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_prefixed_json(value: Any) -> str:
    return sha256_prefixed_bytes(canonical_json(value).encode("utf-8"))


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def log_path() -> Path:
    return Path(os.getenv("CATCHPLATE_EXTERNAL_TRANSPARENCY_LOG_PATH", str(ROOT / ".tmp" / "managed-transparency-log.jsonl")))


def key_path() -> Path:
    return Path(os.getenv("CATCHPLATE_EXTERNAL_TRANSPARENCY_LOG_KEY", str(log_path().with_suffix(".ed25519.pem"))))


def load_key() -> Ed25519PrivateKey:
    path = key_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
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


def key_info(key: Ed25519PrivateKey) -> dict[str, str]:
    public_key = key.public_key()
    pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {"public_key_pem": pem, "log_id": sha256_prefixed_bytes(der)}


def append_checkpoint(payload: dict[str, Any]) -> dict[str, Any]:
    required = {"sequence", "tree_size", "tree_head_hash", "signed_tree_head", "record_digest", "leaf_hash"}
    missing = sorted(required - set(payload))
    if missing:
        raise ValueError(f"checkpoint payload missing fields: {', '.join(missing)}")
    sth = payload.get("signed_tree_head") or {}
    if sth.get("tree_size") != payload.get("tree_size") or sth.get("tree_head_hash") != payload.get("tree_head_hash"):
        raise ValueError("signed tree head claims do not match checkpoint payload")
    path = log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = []
    if path.exists():
        existing = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    external_sequence = len(existing) + 1
    key = load_key()
    info = key_info(key)
    record = {
        "version": "catchplate.externalTransparencyCheckpoint/v1",
        "provider": os.getenv("CATCHPLATE_EXTERNAL_TRANSPARENCY_PROVIDER", "managed-transparency-log-fixture"),
        "external_sequence": external_sequence,
        "received_at": datetime.now(timezone.utc).isoformat(),
        "checkpoint_digest": sha256_prefixed_json(payload),
        "tree_size": payload["tree_size"],
        "tree_head_hash": payload["tree_head_hash"],
        "signed_tree_head": sth,
        "record_digest": payload["record_digest"],
        "leaf_hash": payload["leaf_hash"],
        "source_sequence": payload["sequence"],
        "source_mode": payload.get("mode"),
        "log_id": info["log_id"],
    }
    record["signature"] = "ed25519:" + b64e(key.sign(canonical_json(record).encode("utf-8")))
    record["public_key_pem"] = info["public_key_pem"]
    with path.open("a", encoding="utf-8") as handle:
        handle.write(canonical_json(record) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    return {
        "ok": True,
        "provider": record["provider"],
        "mode": "external-managed-transparency-log",
        "external_sequence": external_sequence,
        "checkpoint_digest": record["checkpoint_digest"],
        "tree_size": payload["tree_size"],
        "tree_head_hash": payload["tree_head_hash"],
        "log_id": info["log_id"],
        "signature": record["signature"],
    }


def main() -> None:
    command = sys.argv[1] if len(sys.argv) > 1 else "checkpoint"
    if command != "checkpoint":
        raise SystemExit(f"unknown command: {command}")
    payload = json.loads(sys.stdin.read() or "{}")
    print(canonical_json(append_checkpoint(payload)))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"external transparency log failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
