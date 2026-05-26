#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


PROVIDER = "aws-nitro-enclaves"
TEE_PLATFORM = "aws-nitro"
USER_DATA_PREFIX = b"serverware:nitro-claims:v1:"


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def claims_user_data(claims: dict[str, Any]) -> bytes:
    digest = hashlib.sha256(canonical_json(claims).encode("utf-8")).hexdigest().encode("ascii")
    return USER_DATA_PREFIX + digest


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def read_stdin() -> dict[str, Any]:
    payload = json.loads(sys.stdin.read() or "{}")
    if not isinstance(payload, dict):
        raise SystemExit("stdin must be a JSON object")
    return payload


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


def validate_request(payload: dict[str, Any]) -> bytes:
    if payload.get("apiVersion") != "serverware.nitroAttestationRequest/v1":
        raise SystemExit("unexpected apiVersion")
    if payload.get("kind") != "NitroAttestationDocument":
        raise SystemExit("unexpected kind")
    if payload.get("provider") != PROVIDER or payload.get("tee_platform") != TEE_PLATFORM:
        raise SystemExit("unexpected Nitro provider metadata")
    claims = payload.get("claims")
    if not isinstance(claims, dict):
        raise SystemExit("missing claims")
    expected_user_data = claims_user_data(claims)
    if payload.get("user_data_sha256") != sha256_prefixed(expected_user_data):
        raise SystemExit("user_data_sha256 mismatch")
    expected_request_digest = sha256_prefixed(canonical_json(request_without_digest(payload)).encode("utf-8"))
    if payload.get("request_digest") != expected_request_digest:
        raise SystemExit("request digest mismatch")
    return expected_user_data


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
    request_digest: str,
    output_format: str,
    timeout: float,
    max_document_bytes: int,
    allow_fixtures_for_test: bool,
) -> bytes:
    if not command_template.strip():
        raise SystemExit("--command-template or SERVERWARE_NITRO_NSM_ATTEST_COMMAND_TEMPLATE is required")
    if not allow_fixtures_for_test and command_mentions(command_template, "fixture", "nitro_attestation_fixture.py"):
        raise SystemExit("Nitro NSM attestation adapter must not use fixture helpers")

    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        user_data_path = tmp / "user-data.bin"
        output_path = tmp / "attestation.cbor"
        user_data_path.write_bytes(user_data)
        values = {
            "user_data_path": str(user_data_path),
            "user_data_b64": b64e(user_data),
            "user_data_sha256": sha256_prefixed(user_data),
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
    user_data = validate_request(payload)
    template = args.command_template or os.getenv("SERVERWARE_NITRO_NSM_ATTEST_COMMAND_TEMPLATE", "")
    raw = run_nsm_helper(
        command_template=template,
        user_data=user_data,
        request_digest=str(payload["request_digest"]),
        output_format=args.output_format,
        timeout=args.timeout,
        max_document_bytes=args.max_document_bytes,
        allow_fixtures_for_test=args.allow_fixtures_for_test,
    )
    print(
        canonical_json(
            {
                "ok": True,
                "provider": "aws-nitro-nsm",
                "tee_platform": TEE_PLATFORM,
                "request_digest": payload["request_digest"],
                "attestation_document_b64": b64e(raw),
                "attestation_document_sha256": sha256_prefixed(raw),
            }
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize an in-enclave Nitro NSM attestation helper into Serverware's quote command contract.")
    subparsers = parser.add_subparsers(dest="command")
    attest_parser = subparsers.add_parser("attest")
    attest_parser.add_argument("--command-template", default=None)
    attest_parser.add_argument("--output-format", choices=("auto", "raw", "b64", "json"), default=os.getenv("SERVERWARE_NITRO_NSM_OUTPUT_FORMAT", "auto"))
    attest_parser.add_argument("--timeout", type=float, default=float(os.getenv("SERVERWARE_NITRO_NSM_TIMEOUT_SECONDS", "10")))
    attest_parser.add_argument("--max-document-bytes", type=int, default=int(os.getenv("SERVERWARE_NITRO_NSM_MAX_DOCUMENT_BYTES", str(1024 * 1024))))
    attest_parser.add_argument("--allow-fixtures-for-test", action="store_true")
    args = parser.parse_args()
    if args.command != "attest":
        raise SystemExit("usage: nitro_nsm_attest.py attest --command-template '...'")
    attest(args)


if __name__ == "__main__":
    main()
