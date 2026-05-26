#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_IMAGES = (
    ("serverware-control", "Dockerfile.production", "serverware/control:production-local"),
    ("serverware-decision-gate", "data-plane/decision-gate-rs/Dockerfile.production", "serverware/decision-gate:production-local"),
)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def run(command: list[str]) -> str:
    result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"{' '.join(command)} failed with exit {result.returncode}: {detail}")
    return result.stdout.strip()


def image_id(tag: str) -> str:
    return run(["docker", "image", "inspect", "--format", "{{.Id}}", tag])


def build_command(dockerfile: str, tag: str, *, platform: str | None) -> list[str]:
    command = ["docker", "build", "-f", dockerfile, "-t", tag]
    if platform:
        command.extend(["--platform", platform])
    command.append(".")
    return command


def verify_no_shell(image_ids: list[str]) -> dict[str, Any]:
    command = [sys.executable, "scripts/verify_production_images_no_shell.py"]
    for image in image_ids:
        command.extend(["--local-image-id", image])
    raw = run(command)
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise RuntimeError("no-shell verifier returned non-object JSON")
    if parsed.get("ok") is not True:
        raise RuntimeError(f"production image no-shell verification failed: {raw}")
    return parsed


def main() -> None:
    parser = argparse.ArgumentParser(description="Build local shell-free Serverware production image candidates.")
    parser.add_argument("--control-tag", default="serverware/control:production-local")
    parser.add_argument("--decision-gate-tag", default="serverware/decision-gate:production-local")
    parser.add_argument("--platform", default=None)
    parser.add_argument("--out", default=".tmp/production-images-build.json")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    image_specs = [
        ("serverware-control", "Dockerfile.production", args.control_tag),
        ("serverware-decision-gate", "data-plane/decision-gate-rs/Dockerfile.production", args.decision_gate_tag),
    ]
    commands = [
        {"service": service, "dockerfile": dockerfile, "tag": tag, "argv": build_command(dockerfile, tag, platform=args.platform)}
        for service, dockerfile, tag in image_specs
    ]
    if args.dry_run:
        print(canonical_json({"ok": True, "commands": commands, "out": args.out}))
        return

    images: list[dict[str, Any]] = []
    for spec in commands:
        print(f"==> building {spec['service']} with {spec['dockerfile']}", file=sys.stderr)
        run(spec["argv"])
        images.append(
            {
                "service": spec["service"],
                "tag": spec["tag"],
                "dockerfile": spec["dockerfile"],
                "image_id": image_id(spec["tag"]),
            }
        )
    no_shell = verify_no_shell([str(item["image_id"]) for item in images])
    result = {
        "apiVersion": "serverware.productionImagesBuild/v1",
        "kind": "ProductionImagesBuild",
        "ok": True,
        "generated_at_unix": int(time.time()),
        "images": images,
        "no_shell": no_shell,
        "publish_requirement": "push these images to a registry and set SERVERWARE_PRODUCTION_IMAGES to immutable @sha256 digest refs before live readiness",
    }
    output_path = Path(args.out)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(canonical_json(result))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(canonical_json({"ok": False, "error": str(exc)}), file=sys.stderr)
        raise SystemExit(1) from exc
