#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import os
import shlex
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent


def canonical_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=True)


def sha256_prefixed_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_prefixed_json(value: Any) -> str:
    return sha256_prefixed_bytes(canonical_json(value).encode("utf-8"))


def read_stdin() -> dict[str, Any]:
    payload = json.loads(sys.stdin.read() or "{}")
    if not isinstance(payload, dict):
        raise SystemExit("stdin must be a JSON object")
    return payload


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def command_words(name: str, default: str = "") -> list[str]:
    raw = os.getenv(name, default).strip()
    if not raw:
        return []
    return shlex.split(raw)


def cosign_binary() -> list[str]:
    return command_words("SERVERWARE_COSIGN_BINARY", "cosign")


def run(command: list[str], *, input_bytes: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        command,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=ROOT,
        check=False,
        timeout=float(os.getenv("SERVERWARE_COSIGN_TIMEOUT_SECONDS", "120")),
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace") or result.stdout.decode("utf-8", errors="replace")
        raise SystemExit(f"cosign command failed with exit {result.returncode}: {detail.strip()}")
    return result


def validate_statement_request(request: dict[str, Any]) -> None:
    if request.get("apiVersion") not in {"serverware.sigstoreSignRequest/v1", "serverware.sigstoreVerifyRequest/v1"}:
        raise SystemExit("unsupported request apiVersion")
    statement = request.get("statement")
    if not isinstance(statement, dict):
        raise SystemExit("request missing statement")
    if request.get("statement_digest") != sha256_prefixed_json(statement):
        raise SystemExit("statement_digest does not match statement")


def artifact_paths(base: Path, request: dict[str, Any]) -> dict[str, Path]:
    digest = str(request["statement_digest"]).replace(":", "-")
    kind = str(request.get("kind") or "statement").replace("/", "_")
    service = str(request.get("service") or "unknown").replace("/", "_")
    prefix = base / f"{kind}-{service}-{digest}"
    return {
        "statement": prefix.with_suffix(".json"),
        "signature": prefix.with_suffix(".sig"),
        "bundle": prefix.with_suffix(".bundle.json"),
    }


def write_statement(path: Path, statement: dict[str, Any]) -> None:
    path.write_text(canonical_json(statement) + "\n", encoding="utf-8")


def load_bundle(path: Path) -> dict[str, Any]:
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"cosign bundle is not JSON: {exc}") from exc
    if not isinstance(bundle, dict):
        raise SystemExit("cosign bundle must be a JSON object")
    return bundle


def tlog_entries(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    verification = bundle.get("verificationMaterial") or bundle.get("verification_material") or {}
    candidates = [
        verification.get("tlogEntries"),
        verification.get("transparencyLogEntries"),
        verification.get("transparencyLog"),
        bundle.get("tlogEntries"),
    ]
    for candidate in candidates:
        if isinstance(candidate, list):
            return [item for item in candidate if isinstance(item, dict)]
        if isinstance(candidate, dict):
            return [candidate]
    return []


def transparency_from_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    entries = tlog_entries(bundle)
    if not entries:
        raise SystemExit("cosign bundle is missing transparency log entries")
    entry = entries[0]
    log_id_value = entry.get("log_id") or entry.get("logID") or entry.get("logId")
    if isinstance(log_id_value, dict):
        log_id = log_id_value.get("keyId") or log_id_value.get("key_id")
    else:
        log_id = log_id_value
    if not log_id:
        raise SystemExit("cosign transparency entry is missing log ID")
    integrated_time = entry.get("integrated_time", entry.get("integratedTime"))
    if integrated_time is None:
        raise SystemExit("cosign transparency entry is missing integrated time")
    inclusion_proof = entry.get("inclusion_proof") or entry.get("inclusionProof")
    if not inclusion_proof:
        raise SystemExit("cosign transparency entry is missing inclusion proof")
    log_index = entry.get("log_index", entry.get("logIndex"))
    entry_uuid = entry.get("entry_uuid") or entry.get("entryUUID") or entry.get("uuid")
    if not entry_uuid:
        entry_uuid = str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                canonical_json(
                    {
                        "log_id": log_id,
                        "log_index": log_index,
                        "integrated_time": integrated_time,
                        "entry": entry,
                    }
                ),
            )
        )
    expected_log_id = os.getenv("SERVERWARE_COSIGN_EXPECTED_REKOR_LOG_ID", "").strip()
    if expected_log_id and log_id != expected_log_id:
        raise SystemExit("cosign transparency log ID does not match SERVERWARE_COSIGN_EXPECTED_REKOR_LOG_ID")
    return {
        "log_id": log_id,
        "entry_uuid": entry_uuid,
        "integrated_time": integrated_time,
        "log_index": log_index,
        "inclusion_proof": inclusion_proof,
    }


def key_provider() -> dict[str, Any]:
    key_ref = os.getenv("SERVERWARE_COSIGN_KEY", "").strip()
    cert_identity = os.getenv("SERVERWARE_COSIGN_CERT_IDENTITY", "").strip()
    cert_issuer = os.getenv("SERVERWARE_COSIGN_CERT_OIDC_ISSUER", "").strip()
    explicit_key_id = os.getenv("SERVERWARE_COSIGN_KEY_ID", "").strip()
    if explicit_key_id:
        key_id = explicit_key_id
    elif key_ref:
        key_id = sha256_prefixed_bytes(key_ref.encode("utf-8"))
    elif cert_identity or cert_issuer:
        key_id = sha256_prefixed_bytes(f"{cert_identity}|{cert_issuer}".encode("utf-8"))
    else:
        key_id = sha256_prefixed_bytes(b"sigstore-keyless")
    return {
        "type": "cosign-key" if key_ref else "sigstore-keyless",
        "key_ref": key_ref or "sigstore-keyless",
        "key_id": key_id,
        "workload_identity": cert_identity or os.getenv("SERVERWARE_COSIGN_WORKLOAD_IDENTITY", "sigstore-keyless"),
        "oidc_issuer": cert_issuer or None,
    }


def cosign_common_args() -> list[str]:
    args: list[str] = []
    rekor_url = os.getenv("SERVERWARE_COSIGN_REKOR_URL", "").strip()
    if rekor_url:
        args.extend(["--rekor-url", rekor_url])
    return args


def sign() -> None:
    request = read_stdin()
    validate_statement_request(request)
    tmp_root = ROOT / ".tmp"
    tmp_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="serverware-cosign-", dir=str(tmp_root.resolve())) as tmp:
        paths = artifact_paths(Path(tmp), request)
        write_statement(paths["statement"], request["statement"])
        command = [
            *cosign_binary(),
            "sign-blob",
            "--bundle",
            str(paths["bundle"]),
            "--output-signature",
            str(paths["signature"]),
        ]
        key_ref = os.getenv("SERVERWARE_COSIGN_KEY", "").strip()
        if key_ref:
            command.extend(["--key", key_ref])
        if env_bool("SERVERWARE_COSIGN_YES", True):
            command.append("--yes")
        tlog_upload = os.getenv("SERVERWARE_COSIGN_TLOG_UPLOAD", "").strip()
        if tlog_upload:
            command.append(f"--tlog-upload={tlog_upload}")
        command.extend(cosign_common_args())
        command.extend(command_words("SERVERWARE_COSIGN_SIGN_EXTRA_ARGS"))
        command.append(str(paths["statement"]))
        run(command)
        bundle = load_bundle(paths["bundle"])
        transparency = transparency_from_bundle(bundle)
        signature = paths["signature"].read_text(encoding="utf-8").strip()
        if not signature:
            raise SystemExit("cosign did not write a signature")
        response = {
            "ok": True,
            "provider": "cosign",
            "statement_digest": request["statement_digest"],
            "signature": signature,
            "key_provider": key_provider(),
            "transparency": transparency,
            "bundle": bundle,
        }
        print(canonical_json(response))


def verify() -> None:
    request = read_stdin()
    validate_statement_request(request)
    signature_response = request.get("signature_response")
    if not isinstance(signature_response, dict):
        raise SystemExit("verify request missing signature_response")
    if signature_response.get("statement_digest") != request.get("statement_digest"):
        raise SystemExit("signature response statement_digest mismatch")
    bundle = signature_response.get("bundle")
    if not isinstance(bundle, dict):
        raise SystemExit("signature response missing cosign bundle")
    transparency = transparency_from_bundle(bundle)
    tmp_root = ROOT / ".tmp"
    tmp_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="serverware-cosign-", dir=str(tmp_root.resolve())) as tmp:
        paths = artifact_paths(Path(tmp), request)
        write_statement(paths["statement"], request["statement"])
        paths["signature"].write_text(str(signature_response.get("signature") or "") + "\n", encoding="utf-8")
        paths["bundle"].write_text(json.dumps(bundle, sort_keys=True) + "\n", encoding="utf-8")
        command = [
            *cosign_binary(),
            "verify-blob",
            "--bundle",
            str(paths["bundle"]),
            "--signature",
            str(paths["signature"]),
        ]
        key_ref = os.getenv("SERVERWARE_COSIGN_KEY", "").strip()
        if key_ref:
            command.extend(["--key", key_ref])
        else:
            cert_identity = os.getenv("SERVERWARE_COSIGN_CERT_IDENTITY", "").strip()
            cert_issuer = os.getenv("SERVERWARE_COSIGN_CERT_OIDC_ISSUER", "").strip()
            if cert_identity:
                command.extend(["--certificate-identity", cert_identity])
            if cert_issuer:
                command.extend(["--certificate-oidc-issuer", cert_issuer])
        command.extend(cosign_common_args())
        command.extend(command_words("SERVERWARE_COSIGN_VERIFY_EXTRA_ARGS"))
        command.append(str(paths["statement"]))
        run(command)
    print(
        canonical_json(
            {
                "ok": True,
                "provider": "cosign",
                "statement_digest": request["statement_digest"],
                "verified_transparency": True,
                "transparency": transparency,
                "key_provider": signature_response.get("key_provider"),
            }
        )
    )


def main() -> None:
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command == "sign":
        sign()
    elif command == "verify":
        verify()
    else:
        raise SystemExit("usage: cosign_sigstore.py sign|verify")


if __name__ == "__main__":
    main()
