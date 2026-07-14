from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import shlex
import subprocess
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field


ANCHOR_PATH = Path(os.getenv("SERVERWARE_AUDIT_ANCHOR_PATH", "/anchors/transparency-log.jsonl"))
ANCHOR_TOKEN = os.getenv("SERVERWARE_AUDIT_ANCHOR_TOKEN", "")
SIGNING_KEY_PATH = Path(os.getenv("SERVERWARE_TRANSPARENCY_LOG_SIGNING_KEY", "/anchors/transparency-log-ed25519.pem"))
CHECKPOINT_COMMAND = os.getenv("SERVERWARE_TRANSPARENCY_CHECKPOINT_COMMAND", "").strip()
CHECKPOINT_REQUIRED = os.getenv("SERVERWARE_TRANSPARENCY_CHECKPOINT_REQUIRED", "0").lower() in {"1", "true", "yes"}
TLS_CERT_FILE = os.getenv("SERVERWARE_AUDIT_ANCHOR_TLS_CERT_FILE", "").strip()
TLS_KEY_FILE = os.getenv("SERVERWARE_AUDIT_ANCHOR_TLS_KEY_FILE", "").strip()
ANCHOR_LOCK = threading.Lock()

app = FastAPI(title="Serverware signed audit transparency log")


class AnchorBatch(BaseModel):
    records: list[dict[str, Any]] = Field(default_factory=list, max_length=500)


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


def load_signing_key() -> Ed25519PrivateKey:
    SIGNING_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if SIGNING_KEY_PATH.exists():
        return serialization.load_pem_private_key(SIGNING_KEY_PATH.read_bytes(), password=None)
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


def sign_tree_head(*, tree_size: int, tree_head_hash: str) -> dict[str, Any]:
    key = load_signing_key()
    key_info = public_key_info(key)
    payload = {
        "version": "serverware.transparencyLog/v1",
        "tree_size": tree_size,
        "tree_head_hash": tree_head_hash,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "log_id": key_info["log_id"],
    }
    payload["signature"] = "ed25519:" + b64e(key.sign(canonical_json(payload).encode("utf-8")))
    payload["public_key_pem"] = key_info["pem"]
    return payload


def verify_tree_head_signature(sth: dict[str, Any]) -> None:
    signature = sth.get("signature")
    public_key_pem = sth.get("public_key_pem")
    if not isinstance(signature, str) or not signature.startswith("ed25519:"):
        raise ValueError("signed tree head is missing ed25519 signature")
    if not isinstance(public_key_pem, str):
        raise ValueError("signed tree head is missing public key")
    payload = dict(sth)
    payload.pop("signature", None)
    payload.pop("public_key_pem", None)
    public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    public_key.verify(b64d(signature.split(":", 1)[1]), canonical_json(payload).encode("utf-8"))


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


def read_anchors() -> list[dict[str, Any]]:
    if not ANCHOR_PATH.exists():
        return []
    items = []
    with ANCHOR_PATH.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                items.append(json.loads(line))
    return items


def verify_items(items: list[dict[str, Any]]) -> dict[str, Any]:
    leaves: list[str] = []
    accumulator = MerkleAccumulator()
    last_record = None
    for index, item in enumerate(items):
        expected_sequence = index + 1
        if item.get("sequence") != expected_sequence:
            return {"ok": False, "error": "sequence_mismatch", "index": index}
        expected_record_digest = sha256_prefixed_json(item.get("record"))
        if item.get("record_digest") != expected_record_digest:
            return {"ok": False, "error": "record_digest_mismatch", "index": index}
        expected_leaf_hash = leaf_hash(leaf_payload(item))
        if item.get("leaf_hash") != expected_leaf_hash:
            return {"ok": False, "error": "leaf_hash_mismatch", "index": index}
        leaves.append(expected_leaf_hash)
        accumulator.append(expected_leaf_hash)
        expected_root = accumulator.root()
        if item.get("tree_size") != expected_sequence:
            return {"ok": False, "error": "tree_size_mismatch", "index": index}
        if item.get("tree_head_hash") != expected_root:
            return {"ok": False, "error": "tree_head_hash_mismatch", "index": index}
        try:
            verify_tree_head_signature(item.get("signed_tree_head") or {})
        except Exception as exc:
            return {"ok": False, "error": "signed_tree_head_invalid", "index": index, "detail": str(exc)}
        sth = item.get("signed_tree_head") or {}
        if sth.get("tree_size") != item.get("tree_size") or sth.get("tree_head_hash") != item.get("tree_head_hash"):
            return {"ok": False, "error": "signed_tree_head_claim_mismatch", "index": index}
        external_checkpoint = item.get("external_checkpoint")
        if external_checkpoint is not None:
            error = validate_external_checkpoint_response(external_checkpoint, checkpoint_payload_for_item(item), item)
            if error:
                return {"ok": False, "error": error, "index": index}
        last_record = item.get("record")
    head = accumulator.root()
    signed_tree_head = (items[-1].get("signed_tree_head") if items else None)
    return {
        "ok": True,
        "mode": "signed-merkle-transparency-log",
        "count": len(items),
        "head": head,
        "tree_size": len(items),
        "signed_tree_head": signed_tree_head,
        "last_record": last_record,
    }


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    return {
        "ok": True,
        "mode": "signed-merkle-transparency-log",
        "anchors": len(read_anchors()),
        "external_checkpoint_configured": bool(CHECKPOINT_COMMAND),
        "external_checkpoint_required": CHECKPOINT_REQUIRED,
    }


def checkpoint_payload_for_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "version": "serverware.transparencyCheckpoint/v1",
        "mode": "signed-merkle-transparency-log",
        "sequence": item["sequence"],
        "record_digest": item["record_digest"],
        "leaf_hash": item["leaf_hash"],
        "tree_size": item["tree_size"],
        "tree_head_hash": item["tree_head_hash"],
        "signed_tree_head": item["signed_tree_head"],
        "record": item["record"],
    }


def response_has_external_receipt(response: dict[str, Any]) -> bool:
    receipt = response.get("receipt")
    if isinstance(receipt, dict) and receipt.get("kind"):
        return any(receipt.get(field) for field in ("signature", "inclusion_proof", "proof", "signed_checkpoint"))
    return isinstance(response.get("signature"), str) and bool(response.get("signature"))


def validate_external_checkpoint_response(response: Any, payload: dict[str, Any], item: dict[str, Any]) -> str | None:
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
    if response.get("request_digest") is not None:
        request_digest = response.get("request_digest")
        if not isinstance(request_digest, str) or not request_digest.startswith("sha256:"):
            return "external_checkpoint_request_digest_invalid"
    if not response_has_external_receipt(response):
        return "external_checkpoint_receipt_missing"
    return None


def publish_external_checkpoint(item: dict[str, Any]) -> dict[str, Any] | None:
    if not CHECKPOINT_COMMAND:
        if CHECKPOINT_REQUIRED:
            raise HTTPException(status_code=503, detail="external transparency checkpoint command is required but not configured")
        return None
    payload = checkpoint_payload_for_item(item)
    try:
        result = subprocess.run(
            shlex.split(CHECKPOINT_COMMAND),
            input=canonical_json(payload).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=15,
        )
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
    x_serverware_audit_anchor_token: str | None = Header(default=None, alias="X-Serverware-Audit-Anchor-Token"),
) -> dict[str, Any]:
    require_token(x_serverware_audit_anchor_token)
    with ANCHOR_LOCK:
        items = read_anchors()
        verification = verify_items(items)
    return {"ok": True, "mode": "signed-merkle-transparency-log", "count": len(items), "items": items[-limit:], "verification": verification}


@app.get("/anchors/inclusion/{sequence}")
def anchor_inclusion(
    sequence: int,
    x_serverware_audit_anchor_token: str | None = Header(default=None, alias="X-Serverware-Audit-Anchor-Token"),
) -> dict[str, Any]:
    require_token(x_serverware_audit_anchor_token)
    with ANCHOR_LOCK:
        items = read_anchors()
        verification = verify_items(items)
        if not verification.get("ok"):
            raise HTTPException(status_code=409, detail={"error": "anchor_log_corrupt", "verification": verification})
        if sequence < 1 or sequence > len(items):
            raise HTTPException(status_code=404, detail="anchor sequence not found")
        leaves = [item["leaf_hash"] for item in items]
        item = items[sequence - 1]
        proof = inclusion_proof(leaves, sequence - 1)
        root = verification.get("head")
        signed_tree_head = verification.get("signed_tree_head")
    if not verification.get("ok"):
        raise HTTPException(status_code=409, detail={"error": "anchor_log_corrupt", "verification": verification})
    if sequence < 1 or sequence > len(items):
        raise HTTPException(status_code=404, detail="anchor sequence not found")
    verified = isinstance(root, str) and verify_inclusion(item["leaf_hash"], proof, root)
    return {
        "ok": True,
        "mode": "signed-merkle-transparency-log",
        "sequence": sequence,
        "record_digest": item["record_digest"],
        "leaf_hash": item["leaf_hash"],
        "tree_size": len(items),
        "tree_head_hash": root,
        "signed_tree_head": signed_tree_head,
        "proof": proof,
        "verified": verified,
        "item": item,
    }


@app.post("/anchors")
def anchors(
    batch: AnchorBatch,
    x_serverware_audit_anchor_token: str | None = Header(default=None, alias="X-Serverware-Audit-Anchor-Token"),
) -> dict[str, Any]:
    require_token(x_serverware_audit_anchor_token)
    with ANCHOR_LOCK:
        ANCHOR_PATH.parent.mkdir(parents=True, exist_ok=True)
        items = read_anchors()
        verification = verify_items(items)
        if not verification.get("ok"):
            raise HTTPException(status_code=409, detail={"error": "anchor_log_corrupt", "verification": verification})
        leaves = [item["leaf_hash"] for item in items]
        accumulator = MerkleAccumulator()
        for leaf in leaves:
            accumulator.append(leaf)
        accepted = []
        with ANCHOR_PATH.open("a", encoding="utf-8") as handle:
            for record in batch.records:
                sequence = len(items) + 1
                item = {
                    "anchor_id": str(uuid.uuid4()),
                    "sequence": sequence,
                    "received_at": datetime.now(timezone.utc).isoformat(),
                    "record": record,
                    "record_digest": sha256_prefixed_json(record),
                }
                item["leaf_hash"] = leaf_hash(leaf_payload(item))
                leaves.append(item["leaf_hash"])
                accumulator.append(item["leaf_hash"])
                tree_head_hash = accumulator.root()
                if tree_head_hash is None:
                    raise HTTPException(status_code=500, detail="empty transparency tree after append")
                item["tree_size"] = len(leaves)
                item["tree_head_hash"] = tree_head_hash
                item["signed_tree_head"] = sign_tree_head(tree_size=len(leaves), tree_head_hash=tree_head_hash)
                external_checkpoint = publish_external_checkpoint(item)
                if external_checkpoint is not None:
                    item["external_checkpoint"] = external_checkpoint
                handle.write(canonical_json(item) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
                items.append(item)
                accepted.append(
                    {
                        "sequence": sequence,
                        "anchor_hash": item["leaf_hash"],
                        "leaf_hash": item["leaf_hash"],
                        "record_digest": item["record_digest"],
                        "tree_size": item["tree_size"],
                        "tree_head_hash": item["tree_head_hash"],
                        "signed_tree_head": item["signed_tree_head"],
                        "external_checkpoint": item.get("external_checkpoint"),
                    }
                )
        head = accumulator.root()
        signed_tree_head = items[-1]["signed_tree_head"] if items else None
    return {
        "ok": True,
        "mode": "signed-merkle-transparency-log",
        "accepted": len(accepted),
        "anchors": accepted,
        "head": head,
        "tree_head_hash": head,
        "tree_size": len(leaves),
        "signed_tree_head": signed_tree_head,
    }


@app.get("/anchors/verify")
def anchors_verify(
    x_serverware_audit_anchor_token: str | None = Header(default=None, alias="X-Serverware-Audit-Anchor-Token"),
) -> dict[str, Any]:
    require_token(x_serverware_audit_anchor_token)
    with ANCHOR_LOCK:
        return verify_items(read_anchors())


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
