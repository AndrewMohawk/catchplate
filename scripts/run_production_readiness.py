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
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
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


def validate_proxy_proof_policy_consistency(
    policy_bundle_path: Path,
    *,
    agent_id: str,
    principal_id: str,
    proof_url: str,
) -> None:
    from serverware.policy_bundle import compile_policy_bundle, strict_json_loads

    try:
        bundle = strict_json_loads(policy_bundle_path.read_bytes())
        if not isinstance(bundle, dict):
            raise ValueError("policy bundle must be a JSON object")
        policy = compile_policy_bundle(
            bundle,
            validate_schema=False,
            verify_signature=False,
        )
    except Exception as exc:
        raise ValueError(
            f"exact --policy-bundle JSON could not be compiled: {exc}"
        ) from exc

    mapped_principals = []
    for principal in policy.principals.values():
        expected_agent_ids = [
            value
            for name, value in principal.required_headers.items()
            if name.lower() == "x-serverware-agent"
        ]
        if expected_agent_ids and all(value == agent_id for value in expected_agent_ids):
            mapped_principals.append(principal.id)
    if mapped_principals != [principal_id]:
        raise ValueError(
            "SERVERWARE_PROXY_PROOF_AGENT_ID and SERVERWARE_PROXY_PROOF_PRINCIPAL_ID "
            "do not map to the same unique principal in the exact --policy-bundle JSON"
        )

    try:
        parsed_url = urlsplit(proof_url)
        proof_host = parsed_url.hostname
        proof_port = parsed_url.port
    except ValueError as exc:
        raise ValueError("SERVERWARE_PROXY_PROOF_URL is invalid") from exc
    if (
        not parsed_url.scheme
        or not proof_host
        or parsed_url.username is not None
        or parsed_url.password is not None
        or parsed_url.fragment
    ):
        raise ValueError("SERVERWARE_PROXY_PROOF_URL is invalid")
    if proof_port is None:
        proof_port = 443 if parsed_url.scheme.lower() == "https" else 80
    proof_path = parsed_url.path or "/"
    matched = policy.match_route(
        parsed_url.scheme,
        proof_host,
        proof_port,
        "GET",
        proof_path,
        principal_id,
    )
    if matched is None:
        raise ValueError(
            "SERVERWARE_PROXY_PROOF_PRINCIPAL_ID is not authorized for the GET proof URL "
            "scheme, host, port, and path in the exact --policy-bundle JSON"
        )


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
        "--expected-principal-id",
        args.proxy_principal_id,
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
    command = {
        "label": "verify-release-completion",
        "argv": [
            args.python,
            "scripts/verify_release_completion.py",
            "--verification-mode",
            args.verification_mode,
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
            "--release-provenance-trusted-public-key",
            args.release_provenance_trusted_public_key,
            "--image-signatures-summary",
            args.image_signatures_summary,
            "--image-signatures",
            args.image_signatures,
            "--sigstore-trusted-public-key",
            args.sigstore_trusted_public_key,
            "--rekor-trusted-public-key",
            args.rekor_trusted_public_key,
            "--external-checkpoint-provider",
            args.external_checkpoint_provider,
            "--external-checkpoint-trusted-public-key",
            args.external_checkpoint_trusted_public_key,
            "--bench",
            args.bench,
            "--policy-bundle",
            args.policy_bundle,
            "--policy-trusted-public-key",
            args.policy_trusted_public_key,
            "--policy-identity-verification",
            args.policy_identity_verification,
            "--policy-activation-verification",
            args.policy_activation_verification,
            "--policy-activation-signature",
            args.policy_activation_signature,
            "--policy-activation-trusted-public-key",
            args.policy_activation_trusted_public_key,
            "--reproducible-build-verification",
            args.reproducible_build_verification,
            "--reproducible-build-signature",
            args.reproducible_build_signature,
            "--reproducible-build-trusted-public-key",
            args.reproducible_build_trusted_public_key,
            "--kms-materials",
            args.kms_materials,
            "--control-plane-response-signing-public-key",
            args.control_plane_response_signing_public_key,
            "--control-plane-response-signing-public-key-id",
            args.control_plane_response_signing_public_key_id,
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
    if args.verification_mode == "final":
        command["argv"].extend(
            [
                "--hardware-assurance",
                args.hardware_assurance,
                "--hardware-assurance-trusted-public-key",
                args.hardware_assurance_trusted_public_key,
                "--hardware-assurance-trusted-public-key-id",
                args.hardware_assurance_trusted_public_key_id,
                "--final-challenge-receipt",
                args.final_challenge_receipt,
                "--final-challenge-authority-public-key",
                args.final_challenge_authority_public_key,
                "--final-challenge-authority-public-key-id",
                args.final_challenge_authority_public_key_id,
                "--final-challenge-authority-provider",
                args.final_challenge_authority_provider,
            ]
        )
        if args.hardware_assurance_expected_challenge_nonce:
            command["argv"].extend(
                [
                    "--hardware-assurance-expected-challenge-nonce",
                    args.hardware_assurance_expected_challenge_nonce,
                ]
            )
        else:
            command["argv"].extend(
                [
                    "--hardware-assurance-expected-challenge-nonce-sha256",
                    args.hardware_assurance_expected_challenge_nonce_sha256,
                ]
            )
    return command


def command_plan(args: argparse.Namespace) -> list[dict[str, Any]]:
    python = args.python
    config_out = str(Path(args.config_out))
    claims_file = str(Path(args.claims_file))
    nitro_evidence_out = str(Path(args.nitro_evidence_out))
    readiness_out = str(Path(args.readiness_out))

    commands: list[dict[str, Any]] = [
        {
            "label": "verify-production-config",
            "argv": [
                python,
                "scripts/verify_production_readiness.py",
                "--mode",
                "config",
                "--expected-control-plane-uid",
                str(args.expected_control_plane_uid),
                "--expected-control-plane-gid",
                str(args.expected_control_plane_gid),
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
                    "--expected-control-plane-uid",
                    str(args.expected_control_plane_uid),
                    "--expected-control-plane-gid",
                    str(args.expected_control_plane_gid),
                    "--claims-file",
                    claims_file,
                    "--nitro-evidence-file",
                    nitro_evidence_out,
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
    parser.add_argument("--expected-control-plane-uid", type=int, default=65532)
    parser.add_argument("--expected-control-plane-gid", type=int, default=65532)
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
    parser.add_argument("--release-provenance-trusted-public-key", default=None)
    parser.add_argument("--image-signatures-summary", default=".tmp/image-signatures-summary.json")
    parser.add_argument("--image-signatures", default=".tmp/image-signatures.json")
    parser.add_argument("--sigstore-trusted-public-key", default=None)
    parser.add_argument("--rekor-trusted-public-key", default=None)
    parser.add_argument("--external-checkpoint-provider", default=None)
    parser.add_argument("--external-checkpoint-trusted-public-key", default=None)
    parser.add_argument("--verification-mode", choices=("readiness", "final"), default="readiness")
    parser.add_argument("--hardware-assurance", default=None)
    parser.add_argument("--hardware-assurance-trusted-public-key", default=None)
    parser.add_argument("--hardware-assurance-trusted-public-key-id", default=None)
    parser.add_argument("--hardware-assurance-expected-challenge-nonce", default=None)
    parser.add_argument("--hardware-assurance-expected-challenge-nonce-sha256", default=None)
    parser.add_argument("--final-challenge-receipt", default=None)
    parser.add_argument("--final-challenge-authority-public-key", default=None)
    parser.add_argument("--final-challenge-authority-public-key-id", default=None)
    parser.add_argument("--final-challenge-authority-provider", default=None)
    parser.add_argument("--bench", default=".tmp/decision-gate-rs-bench.json")
    parser.add_argument("--policy-bundle", required=True)
    parser.add_argument("--policy-trusted-public-key", required=True)
    parser.add_argument("--policy-identity-verification", required=True)
    parser.add_argument("--policy-activation-verification", required=True)
    parser.add_argument("--policy-activation-signature", required=True)
    parser.add_argument("--policy-activation-trusted-public-key", required=True)
    parser.add_argument("--reproducible-build-verification", required=True)
    parser.add_argument("--reproducible-build-signature", required=True)
    parser.add_argument("--reproducible-build-trusted-public-key", required=True)
    parser.add_argument("--kms-materials", default="/etc/serverware/kms-materials.json")
    parser.add_argument(
        "--control-plane-response-signing-public-key",
        default=None,
    )
    parser.add_argument(
        "--control-plane-response-signing-public-key-id",
        default=None,
    )
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
    parser.add_argument("--proxy-principal-id", default=None)
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

    env_verification_mode = loaded.get("SERVERWARE_COMPLETION_VERIFICATION_MODE")
    if env_verification_mode and env_verification_mode not in {"readiness", "final"}:
        print(
            "production readiness env error: SERVERWARE_COMPLETION_VERIFICATION_MODE must be readiness or final",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if args.verification_mode == "final" and env_verification_mode is None:
        print(
            "production readiness env error: final verification mode must be pinned as "
            "SERVERWARE_COMPLETION_VERIFICATION_MODE=final in the production readiness env file",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if env_verification_mode and env_verification_mode != args.verification_mode:
        print(
            "production readiness env error: --verification-mode must match "
            "SERVERWARE_COMPLETION_VERIFICATION_MODE in the production readiness env file",
            file=sys.stderr,
        )
        raise SystemExit(1)

    env = os.environ.copy()
    env.update(loaded)
    trust_settings = {
        "release_provenance_trusted_public_key": "SERVERWARE_RELEASE_PROVENANCE_TRUSTED_PUBLIC_KEY",
        "sigstore_trusted_public_key": "SERVERWARE_SIGSTORE_TRUSTED_PUBLIC_KEY",
        "rekor_trusted_public_key": "SERVERWARE_REKOR_TRUSTED_PUBLIC_KEY",
        "external_checkpoint_provider": "SERVERWARE_EXTERNAL_CHECKPOINT_PROVIDER",
        "external_checkpoint_trusted_public_key": "SERVERWARE_EXTERNAL_CHECKPOINT_TRUSTED_PUBLIC_KEY",
        "control_plane_response_signing_public_key": (
            "SERVERWARE_CONTROL_PLANE_RESPONSE_SIGNING_PUBLIC_KEY"
        ),
        "control_plane_response_signing_public_key_id": (
            "SERVERWARE_CONTROL_PLANE_RESPONSE_SIGNING_PUBLIC_KEY_ID"
        ),
    }
    missing_trust = []
    for attribute, env_name in trust_settings.items():
        argument_value = getattr(args, attribute)
        env_value = loaded.get(env_name)
        if args.verification_mode == "final":
            if argument_value and env_value and argument_value != env_value:
                print(
                    f"production readiness env error: --{attribute.replace('_', '-')} must match {env_name} "
                    "in final verification mode",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            value = env_value
        else:
            value = argument_value or env_value
        if not value:
            if args.verification_mode == "final":
                missing_trust.append(f"{env_name} (must be pinned in the production readiness env file)")
            else:
                missing_trust.append(f"--{attribute.replace('_', '-')} or {env_name}")
            continue
        if PLACEHOLDER_RE.search(value) or EXAMPLE_DOMAIN_RE.search(value):
            print(f"production readiness env error: {env_name} contains a placeholder value", file=sys.stderr)
            raise SystemExit(1)
        setattr(args, attribute, value)
        env[env_name] = value
    if missing_trust:
        print(
            "production readiness env error: missing release completion trust settings: "
            + ", ".join(missing_trust),
            file=sys.stderr,
        )
        raise SystemExit(1)
    if (
        SHA256_RE.fullmatch(
            args.control_plane_response_signing_public_key_id
        )
        is None
    ):
        print(
            "production readiness env error: control-plane response signing public key ID "
            "must be sha256:<64 lowercase hex>",
            file=sys.stderr,
        )
        raise SystemExit(1)
    final_challenge_settings = {
        "final_challenge_receipt": "SERVERWARE_FINAL_CHALLENGE_RECEIPT",
        "final_challenge_authority_public_key": "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY",
        "final_challenge_authority_public_key_id": "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY_ID",
        "final_challenge_authority_provider": "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PROVIDER",
    }
    hardware_assurance_settings = {
        "hardware_assurance": "SERVERWARE_HARDWARE_ASSURANCE",
        "hardware_assurance_trusted_public_key": "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY",
        "hardware_assurance_trusted_public_key_id": "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY_ID",
        "hardware_assurance_expected_challenge_nonce": "SERVERWARE_HARDWARE_ASSURANCE_EXPECTED_CHALLENGE_NONCE",
        "hardware_assurance_expected_challenge_nonce_sha256": (
            "SERVERWARE_HARDWARE_ASSURANCE_EXPECTED_CHALLENGE_NONCE_SHA256"
        ),
    }
    for env_name in final_challenge_settings.values():
        env.pop(env_name, None)
    for env_name in hardware_assurance_settings.values():
        env.pop(env_name, None)
    resolved_final_challenge = {
        attribute: loaded.get(env_name) for attribute, env_name in final_challenge_settings.items()
    }
    resolved_hardware_assurance = {
        attribute: loaded.get(env_name) for attribute, env_name in hardware_assurance_settings.items()
    }
    supplied_final_challenge = {
        attribute: getattr(args, attribute) for attribute in final_challenge_settings
    }
    supplied_hardware_assurance = {
        attribute: getattr(args, attribute) for attribute in hardware_assurance_settings
    }
    if args.verification_mode == "readiness" and (
        any(resolved_final_challenge.values())
        or any(resolved_hardware_assurance.values())
        or any(supplied_final_challenge.values())
        or any(supplied_hardware_assurance.values())
    ):
        print(
            "production readiness env error: final hardware and challenge-authority inputs are only valid with "
            "--verification-mode final",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if args.verification_mode == "final":
        missing_final_challenge = []
        for attribute, env_name in final_challenge_settings.items():
            value = resolved_final_challenge[attribute]
            argument_value = supplied_final_challenge[attribute]
            if argument_value and value and argument_value != value:
                print(
                    f"production readiness env error: --{attribute.replace('_', '-')} must match {env_name} "
                    "in final verification mode",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            if not value:
                missing_final_challenge.append(
                    f"{env_name} (must be pinned in the production readiness env file)"
                )
                continue
            if PLACEHOLDER_RE.search(value) or EXAMPLE_DOMAIN_RE.search(value):
                print(f"production readiness env error: {env_name} contains a placeholder value", file=sys.stderr)
                raise SystemExit(1)
            setattr(args, attribute, value)
            env[env_name] = value
        if missing_final_challenge:
            print(
                "production readiness env error: final verification mode requires off-host challenge authority "
                "inputs: " + ", ".join(missing_final_challenge),
                file=sys.stderr,
            )
            raise SystemExit(1)
        if len(args.final_challenge_authority_provider) > 256:
            print(
                "production readiness env error: final challenge authority provider must not exceed 256 characters",
                file=sys.stderr,
            )
            raise SystemExit(1)
        missing_hardware_assurance = []
        for attribute, env_name in hardware_assurance_settings.items():
            value = resolved_hardware_assurance[attribute]
            argument_value = supplied_hardware_assurance[attribute]
            if argument_value and value and argument_value != value:
                print(
                    f"production readiness env error: --{attribute.replace('_', '-')} must match {env_name} "
                    "in final verification mode",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            if value:
                if PLACEHOLDER_RE.search(value) or EXAMPLE_DOMAIN_RE.search(value):
                    print(f"production readiness env error: {env_name} contains a placeholder value", file=sys.stderr)
                    raise SystemExit(1)
                setattr(args, attribute, value)
                env[env_name] = value
            elif attribute in {
                "hardware_assurance",
                "hardware_assurance_trusted_public_key",
                "hardware_assurance_trusted_public_key_id",
            }:
                missing_hardware_assurance.append(
                    f"{env_name} (must be pinned in the production readiness env file)"
                )
        if missing_hardware_assurance:
            print(
                "production readiness env error: final verification mode requires hardware assurance inputs: "
                + ", ".join(missing_hardware_assurance),
                file=sys.stderr,
            )
            raise SystemExit(1)
        expected_challenges = sum(
            bool(resolved_hardware_assurance[name])
            for name in (
                "hardware_assurance_expected_challenge_nonce",
                "hardware_assurance_expected_challenge_nonce_sha256",
            )
        )
        if expected_challenges != 1:
            print(
                "production readiness env error: final verification mode requires exactly one hardware assurance "
                "expected challenge nonce or digest",
                file=sys.stderr,
            )
            raise SystemExit(1)
        hardware_key_id = args.hardware_assurance_trusted_public_key_id
        authority_key_id = args.final_challenge_authority_public_key_id
        if SHA256_RE.fullmatch(hardware_key_id) is None:
            print(
                "production readiness env error: hardware assurance trusted public key ID must be "
                "sha256:<64 lowercase hex>",
                file=sys.stderr,
            )
            raise SystemExit(1)
        if SHA256_RE.fullmatch(authority_key_id) is None:
            print(
                "production readiness env error: final challenge authority public key ID must be "
                "sha256:<64 lowercase hex>",
                file=sys.stderr,
            )
            raise SystemExit(1)
        if hardware_key_id == authority_key_id:
            print(
                "production readiness env error: hardware assurance verifier and final challenge authority "
                "must use different public keys",
                file=sys.stderr,
            )
            raise SystemExit(1)
    env["SERVERWARE_COMPLETION_VERIFICATION_MODE"] = args.verification_mode
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
        if not args.proxy_agent_id:
            missing.append("--proxy-agent-id or SERVERWARE_PROXY_PROOF_AGENT_ID")
        args.proxy_principal_id = args.proxy_principal_id or loaded.get(
            "SERVERWARE_PROXY_PROOF_PRINCIPAL_ID"
        )
        if not args.proxy_principal_id:
            missing.append(
                "--proxy-principal-id or SERVERWARE_PROXY_PROOF_PRINCIPAL_ID"
            )
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
        try:
            validate_proxy_proof_policy_consistency(
                Path(args.policy_bundle),
                agent_id=args.proxy_agent_id,
                principal_id=args.proxy_principal_id,
                proof_url=args.proxy_proof_url,
            )
        except Exception as exc:
            print(
                f"production readiness env error: proxy proof policy consistency validation failed: {exc}",
                file=sys.stderr,
            )
            raise SystemExit(1) from exc
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
