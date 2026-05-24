#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent


def canonical_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=True)


def sha256_prefixed_json(value: Any) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def run_adapter(mode: str, payload: dict[str, Any], env: dict[str, str]) -> dict[str, Any]:
    result = subprocess.run(
        [sys.executable, "scripts/cosign_sigstore.py", mode],
        cwd=ROOT,
        input=(canonical_json(payload) + "\n").encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"{mode} failed: {result.stderr.decode('utf-8', errors='replace')}")
    data = json.loads(result.stdout.decode("utf-8"))
    if not isinstance(data, dict):
        raise AssertionError(f"{mode} did not return a JSON object")
    return data


def expect_failure(mode: str, payload: dict[str, Any], env: dict[str, str], expected: str) -> None:
    result = subprocess.run(
        [sys.executable, "scripts/cosign_sigstore.py", mode],
        cwd=ROOT,
        input=(canonical_json(payload) + "\n").encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        check=False,
    )
    detail = result.stderr.decode("utf-8", errors="replace") + result.stdout.decode("utf-8", errors="replace")
    if result.returncode == 0:
        raise AssertionError(f"{mode} unexpectedly succeeded: {detail}")
    if expected not in detail:
        raise AssertionError(f"{mode} failed with wrong error, expected {expected!r}: {detail}")


def sign_request(statement: dict[str, Any], *, service: str = "serverware") -> dict[str, Any]:
    return {
        "apiVersion": "serverware.sigstoreSignRequest/v1",
        "kind": "oci-image-statement",
        "service": service,
        "image_id": "sha256:" + "1" * 64,
        "statement": statement,
        "statement_digest": sha256_prefixed_json(statement),
    }


def verify_request(sign_payload: dict[str, Any], signature_response: dict[str, Any]) -> dict[str, Any]:
    return {
        "apiVersion": "serverware.sigstoreVerifyRequest/v1",
        "kind": sign_payload["kind"],
        "service": sign_payload["service"],
        "image_id": sign_payload["image_id"],
        "statement": sign_payload["statement"],
        "statement_digest": sign_payload["statement_digest"],
        "signature_response": signature_response,
    }


def main() -> None:
    env = os.environ.copy()
    env.update(
        {
            "SERVERWARE_COSIGN_BINARY": f"{sys.executable} scripts/cosign_fixture.py",
            "SERVERWARE_COSIGN_KEY_ID": "sha256:" + "c" * 64,
            "SERVERWARE_COSIGN_YES": "0",
        }
    )
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "serverware", "digest": {"sha256": "1" * 64}}],
        "predicateType": "https://serverware.local/test/v1",
        "predicate": {"source": "cosign-adapter-test"},
    }
    sign_payload = sign_request(statement)
    signature_response = run_adapter("sign", sign_payload, env)
    if signature_response.get("provider") != "cosign":
        raise AssertionError(f"unexpected provider: {signature_response}")
    if signature_response.get("statement_digest") != sign_payload["statement_digest"]:
        raise AssertionError(f"signature response digest mismatch: {signature_response}")
    if (signature_response.get("key_provider") or {}).get("key_id") != env["SERVERWARE_COSIGN_KEY_ID"]:
        raise AssertionError(f"signature response did not bind configured key ID: {signature_response}")
    transparency = signature_response.get("transparency") or {}
    for field in ("log_id", "entry_uuid", "integrated_time", "inclusion_proof"):
        if field not in transparency:
            raise AssertionError(f"signature response missing transparency {field}: {signature_response}")
    verified = run_adapter("verify", verify_request(sign_payload, signature_response), env)
    if verified.get("ok") is not True or verified.get("verified_transparency") is not True:
        raise AssertionError(f"cosign verification failed: {verified}")

    tampered_payload = verify_request(sign_payload, signature_response)
    tampered_payload["statement"] = dict(tampered_payload["statement"])
    tampered_payload["statement"]["predicate"] = {"source": "tampered"}
    tampered_payload["statement_digest"] = sha256_prefixed_json(tampered_payload["statement"])
    expect_failure("verify", tampered_payload, env, "signature response statement_digest mismatch")

    no_transparency_env = dict(env)
    no_transparency_env["SERVERWARE_COSIGN_FIXTURE_NO_TRANSPARENCY"] = "1"
    expect_failure("sign", sign_payload, no_transparency_env, "missing transparency log entries")

    verify_fail_env = dict(env)
    verify_fail_env["SERVERWARE_COSIGN_FIXTURE_VERIFY_FAIL"] = "1"
    expect_failure("verify", verify_request(sign_payload, signature_response), verify_fail_env, "forced cosign fixture verify failure")

    print(
        json.dumps(
            {
                "ok": True,
                "cosign_sigstore": "pass",
                "provider": signature_response.get("provider"),
                "key_id": (signature_response.get("key_provider") or {}).get("key_id"),
                "transparency_log_id": transparency.get("log_id"),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
