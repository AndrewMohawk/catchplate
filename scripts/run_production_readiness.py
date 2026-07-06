#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
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
            {
                "label": "verify-release-completion",
                "argv": [
                    python,
                    "scripts/verify_release_completion.py",
                    "--production-readiness",
                    readiness_out,
                    "--production-readiness-config",
                    config_out,
                    "--production-readiness-env",
                    args.env_file,
                    "--production-host-preflight",
                    args.production_host_preflight,
                    "--nitro-evidence",
                    nitro_evidence_out,
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
                    "--out",
                    completion_proof_out,
                ],
            },
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Serverware's production readiness gates from a strict env file.")
    parser.add_argument("--env-file", default=os.getenv("PRODUCTION_READINESS_ENV", "ops/production-readiness.env"))
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
    run_commands(commands, env)


if __name__ == "__main__":
    main()
