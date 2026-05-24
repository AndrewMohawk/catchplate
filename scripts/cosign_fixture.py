#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parent.parent


def canonical_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=True)


def sha256_prefixed_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def key_path() -> Path:
    return Path(os.getenv("SERVERWARE_COSIGN_FIXTURE_KEY", str(ROOT / ".tmp" / "cosign-fixture-ed25519.pem")))


def log_path() -> Path:
    return Path(os.getenv("SERVERWARE_COSIGN_FIXTURE_LOG", str(ROOT / ".tmp" / "cosign-fixture-rekor.jsonl")))


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
    return {"public_key_pem": pem, "key_id": sha256_prefixed_bytes(der)}


def option_value(args: list[str], name: str) -> str | None:
    if name in args:
        index = args.index(name)
        if index + 1 < len(args):
            return args[index + 1]
    prefix = name + "="
    for arg in args:
        if arg.startswith(prefix):
            return arg.split("=", 1)[1]
    return None


def input_path(args: list[str]) -> Path:
    skipped = False
    options_with_values = {
        "--bundle",
        "--output-signature",
        "--signature",
        "--key",
        "--rekor-url",
        "--certificate-identity",
        "--certificate-oidc-issuer",
    }
    candidates: list[str] = []
    for index, arg in enumerate(args):
        if skipped:
            skipped = False
            continue
        if arg in options_with_values:
            skipped = True
            continue
        if arg.startswith("--"):
            continue
        if index == 0:
            continue
        candidates.append(arg)
    if not candidates:
        raise SystemExit("cosign fixture missing input file")
    return Path(candidates[-1])


def append_log(entry: dict[str, Any]) -> dict[str, Any]:
    path = log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = []
    if path.exists():
        existing = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    log_index = len(existing)
    entry = dict(entry)
    entry["log_index"] = log_index
    entry["integrated_time"] = int(time.time())
    entry["entry_uuid"] = str(uuid.uuid5(uuid.NAMESPACE_URL, canonical_json(entry)))
    entry["entry_digest"] = sha256_prefixed_bytes(canonical_json(entry).encode("utf-8"))
    with path.open("a", encoding="utf-8") as handle:
        handle.write(canonical_json(entry) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    return {
        "logId": {"keyId": sha256_prefixed_bytes(str(path).encode("utf-8"))},
        "logIndex": log_index,
        "integratedTime": entry["integrated_time"],
        "entryUUID": entry["entry_uuid"],
        "inclusionProof": {
            "treeSize": log_index + 1,
            "logIndex": log_index,
            "rootHash": entry["entry_digest"],
            "hashes": [],
        },
    }


def sign_blob(args: list[str]) -> None:
    bundle_path = option_value(args, "--bundle")
    signature_path = option_value(args, "--output-signature")
    if not bundle_path or not signature_path:
        raise SystemExit("cosign fixture sign-blob requires --bundle and --output-signature")
    statement_path = input_path(args)
    statement_bytes = statement_path.read_bytes()
    key = load_key()
    info = public_key_info(key)
    signature = "cosign-fixture-ed25519:" + b64e(key.sign(statement_bytes))
    Path(signature_path).write_text(signature + "\n", encoding="utf-8")
    tlog_entries: list[dict[str, Any]] = []
    if not os.getenv("SERVERWARE_COSIGN_FIXTURE_NO_TRANSPARENCY"):
        tlog_entries.append(
            append_log(
                {
                    "kind": "hashedrekord",
                    "statement_sha256": sha256_prefixed_bytes(statement_bytes),
                    "signature": signature,
                    "key_id": info["key_id"],
                }
            )
        )
    bundle = {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "publicKey": info["public_key_pem"],
            "tlogEntries": tlog_entries,
        },
        "messageSignature": {
            "messageDigest": {
                "algorithm": "sha256",
                "digest": hashlib.sha256(statement_bytes).hexdigest(),
            },
            "signature": signature,
        },
    }
    Path(bundle_path).write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def verify_blob(args: list[str]) -> None:
    if os.getenv("SERVERWARE_COSIGN_FIXTURE_VERIFY_FAIL"):
        raise SystemExit("forced cosign fixture verify failure")
    bundle_path = option_value(args, "--bundle")
    signature_path = option_value(args, "--signature")
    if not bundle_path or not signature_path:
        raise SystemExit("cosign fixture verify-blob requires --bundle and --signature")
    statement_path = input_path(args)
    bundle = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
    signature = Path(signature_path).read_text(encoding="utf-8").strip()
    if not signature.startswith("cosign-fixture-ed25519:"):
        raise SystemExit("unsupported fixture signature")
    public_key_pem = ((bundle.get("verificationMaterial") or {}).get("publicKey") or "").encode("ascii")
    public_key = serialization.load_pem_public_key(public_key_pem)
    public_key.verify(b64d(signature.split(":", 1)[1]), statement_path.read_bytes())
    print("Verified OK")


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("usage: cosign_fixture.py sign-blob|verify-blob")
    command = sys.argv[1]
    args = sys.argv[1:]
    if command == "sign-blob":
        sign_blob(args)
    elif command == "verify-blob":
        verify_blob(args)
    else:
        raise SystemExit(f"unsupported cosign fixture command: {command}")


if __name__ == "__main__":
    main()
