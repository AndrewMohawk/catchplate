#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
PROVIDER = "aws-nitro-enclaves"
TEE_PLATFORM = "aws-nitro"
USER_DATA_PREFIX = b"serverware:nitro-claims:v1:"


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def b64e(value: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def sha256_prefixed(value: bytes) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(value).hexdigest()


def claims_user_data(claims: dict[str, Any]) -> bytes:
    import hashlib

    digest = hashlib.sha256(canonical_json(claims).encode("utf-8")).hexdigest().encode("ascii")
    return USER_DATA_PREFIX + digest


def request_without_digest(payload: dict[str, Any]) -> dict[str, Any]:
    copied = json.loads(json.dumps(payload))
    copied.pop("request_digest", None)
    return copied


def request() -> dict[str, Any]:
    claims = {
        "nonce": "nsm-adapter-test",
        "policy_bundle_digest": "sha256:" + "a" * 64,
        "ca_intermediate_spki_sha256": "sha256:" + "b" * 64,
        "data_plane_binary_digest": "sha256:" + "c" * 64,
        "rollback_epoch": 7,
        "release_channel": "prod",
        "provenance_digest": "sha256:" + "d" * 64,
        "source_tree_digest": "sha256:" + "e" * 64,
        "response_signing_key_id": "sha256:" + "f" * 64,
        "materials": ["broker-kek", "decision-gate-ca"],
        "debug": False,
    }
    user_data = claims_user_data(claims)
    payload = {
        "apiVersion": "serverware.nitroAttestationRequest/v1",
        "kind": "NitroAttestationDocument",
        "provider": PROVIDER,
        "tee_platform": TEE_PLATFORM,
        "claims": claims,
        "user_data_b64": b64e(user_data),
        "user_data_sha256": sha256_prefixed(user_data),
    }
    payload["request_digest"] = sha256_prefixed(canonical_json(payload).encode("utf-8"))
    return payload


def fake_helper(path: Path, *, output_mode: str = "file") -> None:
    if output_mode == "json":
        body = """
import base64
import json
import pathlib
import sys
user_data = pathlib.Path(sys.argv[sys.argv.index("--user-data") + 1]).read_bytes()
if not user_data.startswith(b"serverware:nitro-claims:v1:"):
    raise SystemExit("bad user data")
print(json.dumps({"attestation_document_b64": base64.urlsafe_b64encode(b"raw-json-attestation").decode().rstrip("=")}))
"""
    else:
        body = """
import pathlib
import sys
user_data = pathlib.Path(sys.argv[sys.argv.index("--user-data") + 1]).read_bytes()
out = pathlib.Path(sys.argv[sys.argv.index("--out") + 1])
if not user_data.startswith(b"serverware:nitro-claims:v1:"):
    raise SystemExit("bad user data")
out.write_bytes(b"raw-file-attestation")
"""
    path.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
    path.chmod(0o755)


def run_adapter(payload: dict[str, Any], command_template: str | None = None, *extra: str) -> subprocess.CompletedProcess[bytes]:
    command = [sys.executable, "scripts/nitro_nsm_attest.py", "attest"]
    if command_template is not None:
        command.extend(["--command-template", command_template])
    command.extend(extra)
    return subprocess.run(
        command,
        cwd=ROOT,
        input=(canonical_json(payload) + "\n").encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def detail(result: subprocess.CompletedProcess[bytes]) -> str:
    return result.stderr.decode("utf-8", errors="replace") + result.stdout.decode("utf-8", errors="replace")


def expect_failure(payload: dict[str, Any], expected: str, command_template: str | None = None, *extra: str) -> None:
    result = run_adapter(payload, command_template, *extra)
    if result.returncode == 0:
        raise AssertionError(f"NSM adapter unexpectedly succeeded: {detail(result)}")
    if expected not in detail(result):
        raise AssertionError(f"NSM adapter failed with wrong error, expected {expected!r}: {detail(result)}")


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        helper = tmp / "fake_nsm.py"
        fake_helper(helper)
        template = f"{helper} --user-data {{user_data_path}} --out {{output_path}} --digest {{request_digest}}"
        payload = request()
        result = run_adapter(payload, template)
        if result.returncode != 0:
            raise AssertionError(f"NSM adapter failed: {detail(result)}")
        response = json.loads(result.stdout.decode("utf-8"))
        if response.get("ok") is not True or response.get("request_digest") != payload["request_digest"]:
            raise AssertionError(f"NSM adapter response did not bind request: {response}")
        if not response.get("attestation_document_b64") or not response.get("attestation_document_sha256"):
            raise AssertionError(f"NSM adapter response omitted attestation evidence: {response}")

        json_helper = tmp / "fake_nsm_json.py"
        fake_helper(json_helper, output_mode="json")
        json_template = f"{json_helper} --user-data {{user_data_path}}"
        json_result = run_adapter(payload, json_template, "--output-format", "json")
        if json_result.returncode != 0:
            raise AssertionError(f"NSM adapter did not accept JSON helper output: {detail(json_result)}")

        bad_digest = json.loads(json.dumps(payload))
        bad_digest["request_digest"] = "sha256:" + "0" * 64
        expect_failure(bad_digest, "request digest mismatch", template)
        expect_failure(payload, "command-template", None)
        expect_failure(payload, "fixture helpers", "python scripts/nitro_attestation_fixture.py attest")
        fixture_ok = run_adapter(
            payload,
            f"{helper} --user-data {{user_data_path}} --out {{output_path}}",
            "--allow-fixtures-for-test",
        )
        if fixture_ok.returncode != 0:
            raise AssertionError(f"NSM adapter fixture test opt-in failed: {detail(fixture_ok)}")

    print(canonical_json({"nitro_nsm_attest": "pass", "ok": True}))


if __name__ == "__main__":
    main()
