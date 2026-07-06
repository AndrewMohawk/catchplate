#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import aws_kms_recipient_release as recipient  # noqa: E402


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def fake_aws(path: Path) -> None:
    path.write_text(
        """#!/usr/bin/env python3
import base64
import json
import os
import pathlib
import sys

if sys.argv[:3] != [sys.argv[0], "kms", "encrypt"]:
    raise SystemExit("unexpected aws command")
plaintext_arg = sys.argv[sys.argv.index("--plaintext") + 1]
if not plaintext_arg.startswith("fileb://"):
    raise SystemExit("plaintext was not passed as fileb://")
plaintext = pathlib.Path(plaintext_arg.removeprefix("fileb://")).read_bytes()
response = {
    "KeyId": sys.argv[sys.argv.index("--key-id") + 1],
    "CiphertextBlob": base64.b64encode(b"ciphertext:" + plaintext[:8]).decode("ascii"),
}
if os.getenv("SERVERWARE_FAKE_AWS_RETURN_PLAINTEXT"):
    response["Plaintext"] = base64.b64encode(plaintext).decode("ascii")
print(json.dumps(response, sort_keys=True))
""",
        encoding="utf-8",
    )
    path.chmod(0o755)


def run_helper(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
    run_env = None
    if env is not None:
        import os

        run_env = os.environ.copy()
        run_env.update(env)
    return subprocess.run(
        [sys.executable, "scripts/prepare_aws_kms_materials.py", *args],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=run_env,
        check=False,
    )


def detail(result: subprocess.CompletedProcess[bytes]) -> str:
    return result.stdout.decode("utf-8", errors="replace") + result.stderr.decode("utf-8", errors="replace")


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        broker = tmp / "broker-kek.bin"
        ca = tmp / "decision-gate-ca.pem"
        broker.write_bytes(b"broker-kek-plaintext")
        ca.write_bytes(b"decision-gate-ca-private-key")
        spec = tmp / "kms-spec.json"
        spec.write_text(
            canonical_json(
                {
                    "broker-kek": {
                        "key_id": "arn:aws:kms:us-east-1:111122223333:key/broker",
                        "plaintext_path": str(broker),
                        "encryption_context": {"service": "serverware", "material": "broker-kek"},
                    },
                    "decision-gate-ca": {
                        "key_id": "arn:aws:kms:us-east-1:111122223333:key/ca",
                        "plaintext_path": str(ca),
                        "encryption_context": {"service": "serverware", "material": "decision-gate-ca"},
                    },
                }
            ),
            encoding="utf-8",
        )
        aws = tmp / "aws"
        fake_aws(aws)

        dry = run_helper("--spec", str(spec), "--aws-binary", str(aws), "--dry-run")
        if dry.returncode != 0:
            raise AssertionError(f"dry-run failed: {detail(dry)}")
        if "broker-kek-plaintext" in detail(dry):
            raise AssertionError(f"dry-run leaked plaintext: {detail(dry)}")
        dry_plan = json.loads(dry.stdout.decode("utf-8"))
        if not all(item.get("plaintext_path_exists") is True for item in dry_plan.get("materials") or []):
            raise AssertionError(f"dry-run did not report plaintext file state: {dry_plan}")

        missing_spec = tmp / "missing-spec.json"
        missing_spec.write_text(
            canonical_json(
                {
                    "broker-kek": {
                        "key_id": "arn:aws:kms:us-east-1:111122223333:key/broker",
                        "plaintext_path": str(tmp / "missing.bin"),
                    },
                    "decision-gate-ca": {
                        "key_id": "arn:aws:kms:us-east-1:111122223333:key/ca",
                        "plaintext_path": str(ca),
                    }
                }
            ),
            encoding="utf-8",
        )
        missing_dry = run_helper("--spec", str(missing_spec), "--aws-binary", str(aws), "--dry-run")
        if missing_dry.returncode != 0:
            raise AssertionError(f"dry-run should allow missing plaintext files: {detail(missing_dry)}")
        missing_dry_plan = json.loads(missing_dry.stdout.decode("utf-8"))
        missing_materials = missing_dry_plan.get("materials") or []
        missing_entry = next((item for item in missing_materials if item.get("material") == "broker-kek"), None)
        if len(missing_materials) != 2 or not missing_entry or missing_entry.get("plaintext_path_exists") is not False:
            raise AssertionError(f"dry-run did not report missing plaintext file state: {missing_dry_plan}")
        if missing_entry.get("plaintext_bytes") is not None:
            raise AssertionError(f"dry-run reported bytes for missing plaintext: {missing_dry_plan}")
        missing_real = run_helper("--spec", str(missing_spec), "--aws-binary", str(aws), "--out", str(tmp / "missing.json"))
        if missing_real.returncode == 0 or "plaintext_path is not a file" not in detail(missing_real):
            raise AssertionError(f"real run accepted a missing plaintext file: {detail(missing_real)}")

        partial_spec = tmp / "partial-spec.json"
        partial_spec.write_text(
            canonical_json(
                {
                    "broker-kek": {
                        "key_id": "arn:aws:kms:us-east-1:111122223333:key/broker",
                        "plaintext_path": str(broker),
                    }
                }
            ),
            encoding="utf-8",
        )
        partial = run_helper("--spec", str(partial_spec), "--aws-binary", str(aws), "--dry-run")
        if partial.returncode == 0 or "missing required materials" not in detail(partial):
            raise AssertionError(f"materials helper accepted a partial material spec: {detail(partial)}")

        extra_spec = tmp / "extra-spec.json"
        extra_spec.write_text(
            canonical_json(
                {
                    "broker-kek": {
                        "key_id": "arn:aws:kms:us-east-1:111122223333:key/broker",
                        "plaintext_path": str(broker),
                    },
                    "decision-gate-ca": {
                        "key_id": "arn:aws:kms:us-east-1:111122223333:key/ca",
                        "plaintext_path": str(ca),
                    },
                    "debug-material": {
                        "key_id": "arn:aws:kms:us-east-1:111122223333:key/debug",
                        "plaintext_path": str(broker),
                    },
                }
            ),
            encoding="utf-8",
        )
        extra = run_helper("--spec", str(extra_spec), "--aws-binary", str(aws), "--dry-run")
        if extra.returncode == 0 or "unauthorized materials" not in detail(extra):
            raise AssertionError(f"materials helper accepted an unauthorized material spec: {detail(extra)}")

        out = tmp / "kms-materials.json"
        result = run_helper("--spec", str(spec), "--aws-binary", str(aws), "--out", str(out))
        if result.returncode != 0:
            raise AssertionError(f"materials helper failed: {detail(result)}")
        materials = json.loads(out.read_text(encoding="utf-8"))
        if sorted(materials) != ["broker-kek", "decision-gate-ca"]:
            raise AssertionError(f"materials output omitted entries: {materials}")
        if "broker-kek-plaintext" in out.read_text(encoding="utf-8") or "decision-gate-ca-private-key" in out.read_text(encoding="utf-8"):
            raise AssertionError(f"materials output leaked plaintext: {materials}")
        for material in materials:
            recipient.material_config(materials, material)

        rejected = run_helper(
            "--spec",
            str(spec),
            "--aws-binary",
            str(aws),
            "--out",
            str(tmp / "rejected.json"),
            env={"SERVERWARE_FAKE_AWS_RETURN_PLAINTEXT": "1"},
        )
        if rejected.returncode == 0 or "Plaintext" not in detail(rejected):
            raise AssertionError(f"materials helper accepted plaintext AWS response: {detail(rejected)}")

    print(canonical_json({"ok": True, "prepare_aws_kms_materials": "pass"}))


if __name__ == "__main__":
    main()
