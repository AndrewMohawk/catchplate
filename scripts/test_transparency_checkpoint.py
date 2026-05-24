#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parent.parent
HTTP_KEY = Ed25519PrivateKey.generate()


def canonical_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=True)


def sha256_prefixed_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_prefixed_json(value: Any) -> str:
    return sha256_prefixed_bytes(canonical_json(value).encode("utf-8"))


def b64e(value: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def public_key_info() -> dict[str, str]:
    public_key = HTTP_KEY.public_key()
    pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {"public_key_pem": pem, "log_id": sha256_prefixed_bytes(der)}


def checkpoint_payload() -> dict[str, Any]:
    signed_tree_head = {
        "version": "serverware.signedTreeHead/v1",
        "tree_size": 3,
        "tree_head_hash": "sha256:" + "a" * 64,
        "signature": "ed25519:test",
    }
    return {
        "version": "serverware.transparencyCheckpoint/v1",
        "mode": "signed-merkle-transparency-log",
        "sequence": 3,
        "record_digest": "sha256:" + "b" * 64,
        "leaf_hash": "sha256:" + "c" * 64,
        "tree_size": signed_tree_head["tree_size"],
        "tree_head_hash": signed_tree_head["tree_head_hash"],
        "signed_tree_head": signed_tree_head,
        "record": {"kind": "test.record", "value": 1},
    }


def publication_request(payload: dict[str, Any]) -> dict[str, Any]:
    body = {
        "apiVersion": "serverware.externalTransparencyCheckpointRequest/v1",
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


def run_adapter(payload: dict[str, Any], env: dict[str, str], *args: str) -> dict[str, Any]:
    result = subprocess.run(
        [sys.executable, "scripts/transparency_checkpoint.py", "checkpoint", *args],
        cwd=ROOT,
        input=(canonical_json(payload) + "\n").encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"checkpoint failed: {result.stderr.decode('utf-8', errors='replace')}")
    data = json.loads(result.stdout.decode("utf-8"))
    if not isinstance(data, dict):
        raise AssertionError("checkpoint did not return a JSON object")
    return data


def expect_failure(payload: dict[str, Any], env: dict[str, str], expected: str, *args: str) -> None:
    result = subprocess.run(
        [sys.executable, "scripts/transparency_checkpoint.py", "checkpoint", *args],
        cwd=ROOT,
        input=(canonical_json(payload) + "\n").encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        check=False,
    )
    detail = result.stderr.decode("utf-8", errors="replace") + result.stdout.decode("utf-8", errors="replace")
    if result.returncode == 0:
        raise AssertionError(f"checkpoint unexpectedly succeeded: {detail}")
    if expected not in detail:
        raise AssertionError(f"checkpoint failed with wrong error, expected {expected!r}: {detail}")


def sign_receipt(payload: dict[str, Any]) -> str:
    return "ed25519:" + b64e(HTTP_KEY.sign(canonical_json(payload).encode("utf-8")))


class ManagedLogHandler(BaseHTTPRequestHandler):
    server_version = "ServerwareManagedLogFixture/1"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        request = json.loads(body.decode("utf-8"))
        checkpoint = request["checkpoint"]
        info = public_key_info()
        if self.path.endswith("/deny"):
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b'{"ok":false,"error":"denied"}')
            return
        response = {
            "ok": True,
            "provider": "managed-http-fixture",
            "mode": "external-managed-transparency-log",
            "external_sequence": 42,
            "received_at": datetime.now(timezone.utc).isoformat(),
            "checkpoint_digest": request["checkpoint_digest"],
            "request_digest": request["request_digest"],
            "tree_size": checkpoint["tree_size"],
            "tree_head_hash": checkpoint["tree_head_hash"],
            "log_id": info["log_id"],
        }
        receipt_payload = {
            "version": "serverware.externalTransparencyReceipt/v1",
            "provider": response["provider"],
            "log_id": response["log_id"],
            "external_sequence": response["external_sequence"],
            "checkpoint_digest": response["checkpoint_digest"],
            "request_digest": response["request_digest"],
            "source_sequence": checkpoint["sequence"],
            "tree_size": checkpoint["tree_size"],
            "tree_head_hash": checkpoint["tree_head_hash"],
            "record_digest": checkpoint["record_digest"],
            "leaf_hash": checkpoint["leaf_hash"],
        }
        response["receipt"] = {
            "kind": "ed25519-signed-checkpoint",
            "payload": receipt_payload,
            "signature": sign_receipt(receipt_payload),
            "public_key_pem": info["public_key_pem"],
        }
        if self.path.endswith("/mismatch"):
            response["checkpoint_digest"] = "sha256:" + "0" * 64
        if self.path.endswith("/missing-receipt"):
            response.pop("receipt", None)
        encoded = canonical_json(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def start_server() -> tuple[ThreadingHTTPServer, str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), ManagedLogHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    return server, f"http://{host}:{port}"


def main() -> None:
    payload = checkpoint_payload()
    with tempfile.TemporaryDirectory() as tmp:
        fixture_env = os.environ.copy()
        fixture_env.update(
            {
                "SERVERWARE_TRANSPARENCY_CHECKPOINT_MODE": "fixture",
                "SERVERWARE_EXTERNAL_TRANSPARENCY_LOG_PATH": str(Path(tmp) / "managed-log.jsonl"),
                "SERVERWARE_EXTERNAL_TRANSPARENCY_PROVIDER": "managed-fixture-test",
            }
        )
        fixture = run_adapter(payload, fixture_env)
        expected_publication = publication_request(payload)
        if fixture.get("provider") != "managed-fixture-test":
            raise AssertionError(f"fixture provider mismatch: {fixture}")
        if fixture.get("checkpoint_digest") != expected_publication["checkpoint_digest"]:
            raise AssertionError(f"fixture checkpoint digest mismatch: {fixture}")
        if fixture.get("request_digest") != expected_publication["request_digest"]:
            raise AssertionError(f"fixture request digest mismatch: {fixture}")
        receipt = fixture.get("receipt") or {}
        if receipt.get("kind") != "ed25519-signed-checkpoint" or not fixture.get("log_id"):
            raise AssertionError(f"fixture did not return a signed receipt: {fixture}")

    server, base = start_server()
    try:
        http_env = os.environ.copy()
        http_env.update(
            {
                "SERVERWARE_TRANSPARENCY_CHECKPOINT_MODE": "http",
                "SERVERWARE_TRANSPARENCY_LOG_URL": f"{base}/publish",
                "SERVERWARE_TRANSPARENCY_ALLOW_INSECURE_HTTP": "1",
                "SERVERWARE_TRANSPARENCY_EXPECTED_PROVIDER": "managed-http-fixture",
                "SERVERWARE_TRANSPARENCY_EXPECTED_LOG_ID": public_key_info()["log_id"],
            }
        )
        http_response = run_adapter(payload, http_env)
        if http_response.get("external_sequence") != 42:
            raise AssertionError(f"HTTP managed log sequence mismatch: {http_response}")
        verify_input = {"checkpoint": payload, "response": http_response}
        verify_result = subprocess.run(
            [sys.executable, "scripts/transparency_checkpoint.py", "verify"],
            cwd=ROOT,
            input=(canonical_json(verify_input) + "\n").encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=http_env,
            check=False,
        )
        if verify_result.returncode != 0:
            raise AssertionError(f"verify command failed: {verify_result.stderr.decode('utf-8', errors='replace')}")

        tls_env = dict(http_env)
        tls_env.pop("SERVERWARE_TRANSPARENCY_ALLOW_INSECURE_HTTP", None)
        expect_failure(payload, tls_env, "must use https")

        mismatch_env = dict(http_env)
        mismatch_env["SERVERWARE_TRANSPARENCY_LOG_URL"] = f"{base}/mismatch"
        expect_failure(payload, mismatch_env, "digest does not match")

        missing_receipt_env = dict(http_env)
        missing_receipt_env["SERVERWARE_TRANSPARENCY_LOG_URL"] = f"{base}/missing-receipt"
        expect_failure(payload, missing_receipt_env, "missing receipt")

        deny_env = dict(http_env)
        deny_env["SERVERWARE_TRANSPARENCY_LOG_URL"] = f"{base}/deny"
        expect_failure(payload, deny_env, "HTTP 403")
    finally:
        server.shutdown()
        server.server_close()

    print(
        json.dumps(
            {
                "ok": True,
                "transparency_checkpoint": "pass",
                "fixture_provider": fixture.get("provider"),
                "http_provider": "managed-http-fixture",
                "log_id": public_key_info()["log_id"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
