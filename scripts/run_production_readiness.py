#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import secrets
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
PLACEHOLDER_RE = re.compile(
    r"(<[^>]+>|\$\{[^}]+\}|CHANGE[_-]?ME|REPLACE[_-]?ME|FILL[_-]?ME|TODO|TBD)",
    re.IGNORECASE,
)
EXAMPLE_DOMAIN_RE = re.compile(r"(^|[/:@,])([A-Za-z0-9-]+\.)*example([/:,]|$)", re.IGNORECASE)
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_prefixed_file(path: Path) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def parse_env_assignment(raw: str, lineno: int) -> tuple[str, str] | None:
    stripped = raw.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if stripped.startswith("export "):
        stripped = stripped[len("export ") :].lstrip()
    lexer = shlex.shlex(stripped, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = "#"
    try:
        tokens = list(lexer)
    except ValueError as exc:
        raise ValueError(f"line {lineno}: invalid shell-style quoting: {exc}") from exc
    if len(tokens) != 1 or "=" not in tokens[0]:
        raise ValueError(f"line {lineno}: expected KEY=value assignment")
    key, value = tokens[0].split("=", 1)
    if not KEY_RE.fullmatch(key):
        raise ValueError(f"line {lineno}: invalid environment key {key!r}")
    if value == "":
        raise ValueError(f"line {lineno}: {key} must not be empty")
    return key, value


def load_env_file(path: Path) -> dict[str, str]:
    loaded: dict[str, str] = {}
    if not path.exists():
        raise FileNotFoundError(f"production readiness env file does not exist: {path}")
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        parsed = parse_env_assignment(raw, lineno)
        if parsed is None:
            continue
        key, value = parsed
        if key in loaded:
            raise ValueError(f"line {lineno}: duplicate environment key {key}")
        if PLACEHOLDER_RE.search(value):
            raise ValueError(f"line {lineno}: {key} still contains a placeholder value")
        if EXAMPLE_DOMAIN_RE.search(value):
            raise ValueError(f"line {lineno}: {key} still contains an example placeholder domain")
        loaded[key] = value
    if not loaded:
        raise ValueError(f"production readiness env file is empty: {path}")
    return loaded


def generated_client_nonce() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")


def collector_command(args: argparse.Namespace) -> dict[str, Any]:
    command = shlex.split(args.proxy_proof_collector_command)
    if not command:
        raise ValueError("proxy proof collector command is empty")
    argv = [
        *command,
        "--proxy",
        args.proxy_address,
        "--url",
        args.proxy_proof_url,
        "--ca",
        args.proxy_proof_ca,
        "--out",
        args.proxy_response_proof,
        "--collector-key",
        args.proxy_collector_key,
        "--verifier-key",
        args.proxy_proof_verifier_public_key,
        "--expected-server-instance-id",
        args.proxy_server_instance_id,
        "--max-age-seconds",
        str(args.proxy_proof_max_age_seconds),
        "--nonce",
        args.proxy_client_nonce,
    ]
    if args.proxy_agent_id:
        agent_header = f"X-Serverware-Agent: {args.proxy_agent_id}"
        argv.extend(["--proxy-header", agent_header, "--header", agent_header])
    return {"label": "collect-production-proxy-response-proof", "argv": argv}


def completion_command(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "label": "verify-release-completion",
        "argv": [
            args.python,
            "scripts/verify_release_completion.py",
            "--production-readiness",
            str(Path(args.readiness_out)),
            "--production-readiness-config",
            str(Path(args.config_out)),
            "--production-readiness-env",
            args.env_file,
            "--compose-file",
            args.compose_file,
            "--production-host-preflight",
            args.production_host_preflight,
            "--nitro-evidence",
            str(Path(args.nitro_evidence_out)),
            "--production-images-build",
            args.production_images_build,
            "--production-images-env",
            args.production_images_env,
            "--production-images-published",
            args.production_images_published,
            "--release-provenance-summary",
            args.release_provenance_summary,
            "--release-provenance",
            args.release_provenance,
            "--image-signatures-summary",
            args.image_signatures_summary,
            "--image-signatures",
            args.image_signatures,
            "--bench",
            args.bench,
            "--kms-materials",
            args.kms_materials,
            "--proxy-response-proof",
            args.proxy_response_proof,
            "--proxy-proof-verifier-public-key",
            args.proxy_proof_verifier_public_key,
            "--proxy-collector-public-key",
            args.proxy_collector_public_key,
            "--proxy-server-instance-id",
            args.proxy_server_instance_id,
            "--proxy-client-nonce",
            args.proxy_client_nonce,
            "--proxy-request-digest",
            args.proxy_request_digest,
            "--proxy-operation-digest",
            args.proxy_operation_digest,
            "--proxy-tls-channel-binding",
            args.proxy_tls_channel_binding,
            "--proxy-proof-max-age-seconds",
            str(args.proxy_proof_max_age_seconds),
            "--out",
            str(Path(args.completion_proof_out)),
        ],
    }


def command_plan(args: argparse.Namespace) -> list[dict[str, Any]]:
    python = args.python
    config_out = str(Path(args.config_out))
    claims_file = str(Path(args.claims_file))
    nitro_evidence_out = str(Path(args.nitro_evidence_out))
    readiness_out = str(Path(args.readiness_out))
    completion_proof_out = str(Path(args.completion_proof_out))

    commands: list[dict[str, Any]] = [
        {
            "label": "verify-production-config",
            "argv": [
                python,
                "scripts/verify_production_readiness.py",
                "--mode",
                "config",
                "--out",
                config_out,
            ],
        }
    ]
    if args.config_only:
        return commands
    if not args.use_existing_claims:
        commands.append(
            {
                "label": "generate-production-readiness-claims",
                "argv": [
                    python,
                    "scripts/generate_production_readiness_claims.py",
                    "--out",
                    claims_file,
                    *args.claims_args,
                ],
            }
        )
    commands.extend(
        [
            {
                "label": "collect-nitro-kms-evidence",
                "argv": [
                    python,
                    "scripts/collect_nitro_kms_evidence.py",
                    "--claims-file",
                    claims_file,
                    "--nitro-evidence-file",
                    nitro_evidence_out,
                    "--out",
                    nitro_evidence_out,
                ],
            },
            {
                "label": "verify-production-readiness",
                "argv": [
                    python,
                    "scripts/verify_production_readiness.py",
                    "--mode",
                    "live",
                    "--claims-file",
                    claims_file,
                    "--out",
                    readiness_out,
                ],
            },
            collector_command(args),
            completion_command(args),
        ]
    )
    return commands


def run_commands(commands: list[dict[str, Any]], env: dict[str, str]) -> None:
    for command in commands:
        label = command["label"]
        argv = command["argv"]
        print(f"==> {label}", file=sys.stderr)
        result = subprocess.run(argv, cwd=ROOT, env=env, check=False)
        if result.returncode != 0:
            raise SystemExit(result.returncode)


def write_private_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    payload = (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        temporary.unlink(missing_ok=True)


def run_collector(command: dict[str, Any], args: argparse.Namespace, env: dict[str, str]) -> dict[str, Any]:
    print(f"==> {command['label']}", file=sys.stderr)
    result = subprocess.run(
        command["argv"],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        print(f"production proxy response proof collection failed: {detail}", file=sys.stderr)
        raise SystemExit(result.returncode)
    try:
        summary = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("production proxy response proof collector returned invalid JSON") from exc
    if not isinstance(summary, dict) or summary.get("ok") is not True:
        raise ValueError("production proxy response proof collector did not return ok=true")
    if summary.get("client_nonce") != args.proxy_client_nonce:
        raise ValueError("production proxy response proof collector did not bind the runner challenge")
    for field in ("request_digest", "operation_digest"):
        value = summary.get(field)
        if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
            raise ValueError(f"production proxy response proof collector returned an invalid {field}")
    tls_binding = summary.get("tls_channel_binding")
    if not isinstance(tls_binding, str) or len(tls_binding) < 43:
        raise ValueError("production proxy response proof collector returned an invalid TLS channel binding")
    if summary.get("server_instance_id") != args.proxy_server_instance_id:
        raise ValueError("production proxy response proof collector reached an unexpected server instance")
    expected_proof_path = str(Path(args.proxy_response_proof))
    if summary.get("proof_path") != expected_proof_path:
        raise ValueError("production proxy response proof collector wrote an unexpected proof path")
    proof_path = Path(args.proxy_response_proof)
    if not proof_path.is_file():
        raise ValueError("production proxy response proof collector did not create the proof artifact")
    proof_digest = sha256_prefixed_file(proof_path)
    if summary.get("proof_sha256") != proof_digest:
        raise ValueError("production proxy response proof collector summary does not bind the proof artifact")
    write_private_json(Path(args.proxy_proof_summary_out), summary)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Serverware's production readiness gates from a strict env file.")
    parser.add_argument("--env-file", default=os.getenv("PRODUCTION_READINESS_ENV", "ops/production-readiness.env"))
    parser.add_argument("--compose-file", default="docker-compose.production.yml")
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--config-out", default=".tmp/production-readiness-config.json")
    parser.add_argument("--claims-file", default=".tmp/production-readiness-claims.json")
    parser.add_argument("--nitro-evidence-out", default=".tmp/nitro-kms-evidence.json")
    parser.add_argument("--readiness-out", default=".tmp/production-readiness.json")
    parser.add_argument("--completion-proof-out", default=".tmp/serverware-completion-proof.json")
    parser.add_argument("--production-host-preflight", default=".tmp/production-host-preflight.json")
    parser.add_argument("--production-images-build", default=".tmp/production-images-build.json")
    parser.add_argument("--production-images-env", default=".tmp/production-images.env")
    parser.add_argument("--production-images-published", default=".tmp/production-images-published.json")
    parser.add_argument("--release-provenance-summary", default=".tmp/release-provenance-summary.json")
    parser.add_argument("--release-provenance", default=".tmp/release-provenance.json")
    parser.add_argument("--image-signatures-summary", default=".tmp/image-signatures-summary.json")
    parser.add_argument("--image-signatures", default=".tmp/image-signatures.json")
    parser.add_argument("--bench", default=".tmp/decision-gate-rs-bench.json")
    parser.add_argument("--kms-materials", default="/etc/serverware/kms-materials.json")
    parser.add_argument("--proxy-response-proof", default=None)
    parser.add_argument("--proxy-proof-summary-out", default=".tmp/proxy-response-proof-summary.json")
    parser.add_argument("--proxy-proof-collector-command", default=None)
    parser.add_argument("--proxy-address", default=None)
    parser.add_argument("--proxy-proof-url", default=None)
    parser.add_argument("--proxy-proof-ca", default=None)
    parser.add_argument("--proxy-collector-key", default=None)
    parser.add_argument("--proxy-collector-public-key", default=None)
    parser.add_argument("--proxy-proof-verifier-public-key", default=None)
    parser.add_argument("--proxy-server-instance-id", default=None)
    parser.add_argument("--proxy-agent-id", default=None)
    parser.add_argument("--proxy-proof-max-age-seconds", type=int, default=None)
    parser.add_argument("--control-plane-base", default=None)
    parser.add_argument("--control-plane-ca-bundle", default=None)
    parser.add_argument("--config-only", action="store_true")
    parser.add_argument("--use-existing-claims", action="store_true")
    parser.add_argument("--dry-run", action="store_true", help="load and validate the env file, then print the command plan")
    parser.add_argument(
        "--claims-arg",
        dest="claims_args",
        action="append",
        default=[],
        help="extra argument to pass through to generate_production_readiness_claims.py; repeat as needed",
    )
    args = parser.parse_args()

    try:
        loaded = load_env_file(Path(args.env_file))
    except Exception as exc:
        print(f"production readiness env error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    env = os.environ.copy()
    env.update(loaded)
    if not args.config_only:
        proof_settings = {
            "proxy_response_proof": "SERVERWARE_PROXY_RESPONSE_PROOF_FILE",
            "proxy_proof_collector_command": "SERVERWARE_PROXY_PROOF_COLLECTOR_COMMAND",
            "proxy_address": "SERVERWARE_PROXY_PROOF_ADDRESS",
            "proxy_proof_url": "SERVERWARE_PROXY_PROOF_URL",
            "proxy_proof_ca": "SERVERWARE_PROXY_PROOF_CA_BUNDLE",
            "proxy_collector_key": "SERVERWARE_PROXY_PROOF_COLLECTOR_PRIVATE_KEY",
            "proxy_collector_public_key": "SERVERWARE_PROXY_PROOF_COLLECTOR_PUBLIC_KEY",
            "proxy_proof_verifier_public_key": "SERVERWARE_PROXY_PROOF_VERIFIER_PUBLIC_KEY",
        }
        missing = []
        for attribute, env_name in proof_settings.items():
            value = getattr(args, attribute) or loaded.get(env_name)
            if not value:
                missing.append(f"--{attribute.replace('_', '-')} or {env_name}")
            else:
                setattr(args, attribute, value)
        args.proxy_server_instance_id = (
            args.proxy_server_instance_id
            or loaded.get("SERVERWARE_PROXY_SERVER_INSTANCE_ID")
            or loaded.get("SERVERWARE_DATA_PLANE_INSTANCE_ID")
        )
        if not args.proxy_server_instance_id:
            missing.append(
                "--proxy-server-instance-id or SERVERWARE_PROXY_SERVER_INSTANCE_ID or "
                "SERVERWARE_DATA_PLANE_INSTANCE_ID"
            )
        args.proxy_agent_id = args.proxy_agent_id or loaded.get("SERVERWARE_PROXY_PROOF_AGENT_ID")
        max_age = args.proxy_proof_max_age_seconds
        if max_age is None:
            raw_max_age = loaded.get("SERVERWARE_PROXY_PROOF_MAX_AGE_SECONDS", "300")
            try:
                max_age = int(raw_max_age)
            except ValueError as exc:
                print(
                    "production readiness env error: SERVERWARE_PROXY_PROOF_MAX_AGE_SECONDS must be an integer",
                    file=sys.stderr,
                )
                raise SystemExit(1) from exc
        if not 1 <= max_age <= 900:
            print(
                "production readiness env error: proxy proof max age must be between 1 and 900 seconds",
                file=sys.stderr,
            )
            raise SystemExit(1)
        args.proxy_proof_max_age_seconds = max_age
        if missing:
            print(
                "production readiness env error: missing production proxy proof settings: "
                + ", ".join(missing),
                file=sys.stderr,
            )
            raise SystemExit(1)
        args.proxy_client_nonce = generated_client_nonce()
        args.proxy_request_digest = "$COLLECTOR_SUMMARY.request_digest"
        args.proxy_operation_digest = "$COLLECTOR_SUMMARY.operation_digest"
        args.proxy_tls_channel_binding = "$COLLECTOR_SUMMARY.tls_channel_binding"
    control_plane_base = (
        args.control_plane_base
        or loaded.get("SERVERWARE_PRODUCTION_CONTROL_PLANE_BASE")
        or loaded.get("SERVERWARE_PUBLIC_URL")
        or "https://localhost:3000"
    )
    control_plane_ca_bundle = (
        args.control_plane_ca_bundle
        or loaded.get("SERVERWARE_PRODUCTION_CONTROL_PLANE_CA_BUNDLE")
        or str(Path(loaded.get("SERVERWARE_CONTROL_PLANE_TLS_DIR", "/etc/serverware/control-plane-tls")) / "ca.pem")
    )
    args.claims_args = [
        "--base",
        control_plane_base,
        "--ca-bundle",
        control_plane_ca_bundle,
        *args.claims_args,
    ]
    env_file = Path(args.env_file)
    images_env = Path(args.production_images_env)
    env["SERVERWARE_PRODUCTION_READINESS_ENV_PATH"] = str(env_file)
    env["SERVERWARE_PRODUCTION_READINESS_ENV_SHA256"] = sha256_prefixed_file(env_file)
    env["SERVERWARE_PRODUCTION_IMAGES_ENV_PATH"] = str(images_env)
    if images_env.exists():
        env["SERVERWARE_PRODUCTION_IMAGES_ENV_SHA256"] = sha256_prefixed_file(images_env)
    commands = command_plan(args)
    if args.dry_run:
        print(
            canonical_json(
                {
                    "ok": True,
                    "env_file": args.env_file,
                    "env_keys": sorted(loaded),
                    "commands": commands,
                }
            )
        )
        return
    if args.config_only:
        run_commands(commands, env)
        return
    run_commands(commands[:-2], env)
    summary = run_collector(commands[-2], args, env)
    args.proxy_request_digest = summary["request_digest"]
    args.proxy_operation_digest = summary["operation_digest"]
    args.proxy_tls_channel_binding = summary["tls_channel_binding"]
    run_commands([completion_command(args)], env)


if __name__ == "__main__":
    main()
