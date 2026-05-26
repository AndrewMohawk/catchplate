#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


SECRET_FIELD_NAMES = {
    "plaintext",
    "secret",
    "private_key",
    "private_key_pem",
    "raw_material",
    "material_value",
    "unwrapped_key",
    "decrypted_key",
}


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def load_spec(path: Path, *, require_plaintext_files: bool = True) -> dict[str, Any]:
    parsed = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict) or not parsed:
        raise ValueError("AWS KMS materials spec must be a non-empty JSON object")
    for material, config in parsed.items():
        if not isinstance(material, str) or not material or "," in material:
            raise ValueError(f"invalid material name: {material!r}")
        if not isinstance(config, dict):
            raise ValueError(f"material {material} config must be an object")
        key_id = config.get("key_id") or config.get("keyId") or config.get("kms_key_id")
        if not isinstance(key_id, str) or not key_id:
            raise ValueError(f"material {material} missing key_id")
        plaintext_path = config.get("plaintext_path") or config.get("plaintextPath")
        if not isinstance(plaintext_path, str) or not plaintext_path:
            raise ValueError(f"material {material} missing plaintext_path")
        path_obj = Path(plaintext_path)
        if require_plaintext_files and (not path_obj.exists() or not path_obj.is_file()):
            raise ValueError(f"material {material} plaintext_path is not a file: {plaintext_path}")
        context = config.get("encryption_context") or config.get("encryptionContext") or {}
        if not isinstance(context, dict):
            raise ValueError(f"material {material} encryption_context must be an object")
        for key, value in context.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise ValueError(f"material {material} encryption_context entries must be string:string")
    return parsed


def reject_secret_fields(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower() in SECRET_FIELD_NAMES:
                raise ValueError(f"AWS KMS response contained plaintext material field {path}.{key}")
            reject_secret_fields(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_secret_fields(child, f"{path}[{index}]")


def material_config(value: dict[str, Any]) -> tuple[str, Path, dict[str, str]]:
    key_id = str(value.get("key_id") or value.get("keyId") or value.get("kms_key_id"))
    plaintext_path = Path(str(value.get("plaintext_path") or value.get("plaintextPath")))
    context = value.get("encryption_context") or value.get("encryptionContext") or {}
    return key_id, plaintext_path, {str(key): str(child) for key, child in context.items()}


def run_aws_kms_encrypt(
    *,
    aws_binary: str,
    key_id: str,
    plaintext_path: Path,
    encryption_context: dict[str, str],
    region: str | None,
    timeout: float,
) -> dict[str, Any]:
    command = [
        aws_binary,
        "kms",
        "encrypt",
        "--key-id",
        key_id,
        "--plaintext",
        f"fileb://{plaintext_path}",
        "--output",
        "json",
    ]
    if encryption_context:
        command.extend(["--encryption-context", canonical_json(encryption_context)])
    if region:
        command.extend(["--region", region])
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace") or result.stdout.decode("utf-8", errors="replace")
        raise RuntimeError(f"aws kms encrypt failed with exit {result.returncode}: {detail.strip()}")
    response = json.loads(result.stdout.decode("utf-8"))
    if not isinstance(response, dict):
        raise RuntimeError("aws kms encrypt returned non-object JSON")
    reject_secret_fields(response)
    if not response.get("CiphertextBlob"):
        raise RuntimeError("aws kms encrypt response missing CiphertextBlob")
    return response


def prepare_materials(
    spec: dict[str, Any],
    *,
    aws_binary: str,
    region: str | None,
    timeout: float,
) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for material in sorted(spec):
        key_id, plaintext_path, context = material_config(spec[material])
        response = run_aws_kms_encrypt(
            aws_binary=aws_binary,
            key_id=key_id,
            plaintext_path=plaintext_path,
            encryption_context=context,
            region=region,
            timeout=timeout,
        )
        output[material] = {
            "key_id": response.get("KeyId") or key_id,
            "ciphertext_blob_b64": response["CiphertextBlob"],
            "encryption_context": context,
            "source": {
                "plaintext_path_sha256": sha256_prefixed(str(plaintext_path).encode("utf-8")),
                "plaintext_bytes": plaintext_path.stat().st_size,
            },
        }
    return output


def dry_run_plan(spec: dict[str, Any]) -> dict[str, Any]:
    materials = []
    for material in sorted(spec):
        key_id, plaintext_path, context = material_config(spec[material])
        plaintext_path_exists = plaintext_path.exists() and plaintext_path.is_file()
        materials.append(
            {
                "material": material,
                "key_id": key_id,
                "plaintext_path_sha256": sha256_prefixed(str(plaintext_path).encode("utf-8")),
                "plaintext_path_exists": plaintext_path_exists,
                "plaintext_bytes": plaintext_path.stat().st_size if plaintext_path_exists else None,
                "encryption_context_sha256": sha256_prefixed(canonical_json(context).encode("utf-8")),
            }
        )
    return {"ok": True, "materials": materials}


def write_json_private(path: Path, value: dict[str, Any], *, allow_overwrite: bool) -> None:
    if path.exists() and not allow_overwrite:
        raise FileExistsError(f"refusing to overwrite existing output without --allow-overwrite: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare AWS KMS ciphertext material config for Nitro Recipient release.")
    parser.add_argument("--spec", required=True, help="JSON spec mapping material names to key_id, plaintext_path, and optional encryption_context.")
    parser.add_argument("--out", default="/etc/serverware/kms-materials.json")
    parser.add_argument("--aws-binary", default=os.getenv("SERVERWARE_AWS_CLI", "aws"))
    parser.add_argument("--region", default=os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION"))
    parser.add_argument("--timeout", type=float, default=float(os.getenv("SERVERWARE_AWS_KMS_TIMEOUT_SECONDS", "30")))
    parser.add_argument("--allow-overwrite", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    try:
        spec = load_spec(Path(args.spec), require_plaintext_files=not args.dry_run)
        if args.dry_run:
            print(canonical_json(dry_run_plan(spec)))
            return
        materials = prepare_materials(
            spec,
            aws_binary=args.aws_binary,
            region=args.region,
            timeout=args.timeout,
        )
        write_json_private(Path(args.out), materials, allow_overwrite=args.allow_overwrite)
        print(
            canonical_json(
                {
                    "ok": True,
                    "out": args.out,
                    "materials": sorted(materials),
                    "materials_sha256": sha256_prefixed(canonical_json(materials).encode("utf-8")),
                }
            )
        )
    except Exception as exc:
        print(canonical_json({"ok": False, "error": str(exc)}), file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
