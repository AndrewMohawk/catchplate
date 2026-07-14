#!/usr/bin/env python3
from __future__ import annotations

import json
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import test_production_readiness as production_readiness_test  # noqa: E402


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def write_env(path: Path, env: dict[str, str]) -> None:
    lines = []
    for key in sorted(env):
        lines.append(f"{key}={shlex.quote(str(env[key]))}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_runner(*args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "scripts/run_production_readiness.py", *args],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def detail(result: subprocess.CompletedProcess[bytes]) -> str:
    return result.stdout.decode("utf-8", errors="replace") + result.stderr.decode("utf-8", errors="replace")


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        security_args = (
            "--policy-bundle",
            str(tmp / "policy-bundle.json"),
            "--policy-trusted-public-key",
            str(tmp / "policy-signing.pub.pem"),
            "--policy-identity-verification",
            str(tmp / "policy-identity.json"),
            "--policy-activation-verification",
            str(tmp / "policy-activation.json"),
            "--policy-activation-signature",
            str(tmp / "policy-activation.signature.json"),
            "--policy-activation-trusted-public-key",
            str(tmp / "policy-activation.pub.pem"),
            "--reproducible-build-verification",
            str(tmp / "reproducible-build.json"),
            "--reproducible-build-signature",
            str(tmp / "reproducible-build.signature.json"),
            "--reproducible-build-trusted-public-key",
            str(tmp / "reproducible-build.pub.pem"),
        )

        minimal_env = tmp / "minimal.env"
        write_env(
            minimal_env,
            {
                "SERVERWARE_RELEASE_CHANNEL": "prod",
                "SERVERWARE_ADMIN_TOKEN": "prod-admin-token-32-bytes-minimum-value",
                "SERVERWARE_OIDC_JWKS_JSON": canonical_json({"keys": [{"kid": "prod key"}]}),
                "SERVERWARE_PROXY_RESPONSE_PROOF_FILE": str(tmp / "proxy-response-proof.json"),
                "SERVERWARE_PROXY_PROOF_COLLECTOR_COMMAND": "/opt/serverware/bin/serverware-proof-client",
                "SERVERWARE_PROXY_PROOF_ADDRESS": "proxy.prod.internal:9090",
                "SERVERWARE_PROXY_PROOF_URL": "https://proof-target.prod.internal/health",
                "SERVERWARE_PROXY_PROOF_CA_BUNDLE": str(tmp / "proxy-ca.pem"),
                "SERVERWARE_PROXY_PROOF_COLLECTOR_PRIVATE_KEY": str(tmp / "collector-key.pem"),
                "SERVERWARE_PROXY_PROOF_COLLECTOR_PUBLIC_KEY": str(tmp / "collector-key.pub.pem"),
                "SERVERWARE_PROXY_PROOF_VERIFIER_PUBLIC_KEY": str(tmp / "proxy-verifier.pub.pem"),
                "SERVERWARE_DATA_PLANE_INSTANCE_ID": "spiffe://prod.serverware.internal/decision-gate/instance-01",
                "SERVERWARE_PROXY_PROOF_AGENT_ID": "production-proof-agent",
                "SERVERWARE_PROXY_PROOF_MAX_AGE_SECONDS": "240",
            },
        )
        dry_run = run_runner("--env-file", str(minimal_env), "--dry-run", *security_args)
        if dry_run.returncode != 0:
            raise AssertionError(f"runner dry-run failed: {detail(dry_run)}")
        plan = json.loads(dry_run.stdout.decode("utf-8"))
        if plan.get("ok") is not True or len(plan.get("commands") or []) != 6:
            raise AssertionError(f"runner dry-run did not return the full command plan: {plan}")
        labels = [command["label"] for command in plan["commands"]]
        if labels[-3:] != [
            "verify-production-readiness",
            "collect-production-proxy-response-proof",
            "verify-release-completion",
        ]:
            raise AssertionError(f"runner does not collect the response proof after live readiness: {labels}")
        collector_argv = plan["commands"][-2]["argv"]
        completion_argv = plan["commands"][-1]["argv"]
        collector_nonce = collector_argv[collector_argv.index("--nonce") + 1]
        completion_nonce = completion_argv[completion_argv.index("--proxy-client-nonce") + 1]
        if (
            collector_argv[collector_argv.index("--verifier-key") + 1]
            != str(tmp / "proxy-verifier.pub.pem")
            or collector_argv[collector_argv.index("--expected-server-instance-id") + 1]
            != "spiffe://prod.serverware.internal/decision-gate/instance-01"
            or collector_argv[collector_argv.index("--max-age-seconds") + 1] != "240"
            or "--production-readiness-config" not in completion_argv
            or "--production-readiness-env" not in completion_argv
            or "--production-images-env" not in completion_argv
            or "--policy-bundle" not in completion_argv
            or "--policy-identity-verification" not in completion_argv
            or "--policy-activation-verification" not in completion_argv
            or "--policy-activation-signature" not in completion_argv
            or "--reproducible-build-verification" not in completion_argv
            or "--reproducible-build-signature" not in completion_argv
            or "/etc/serverware/kms-materials.json" not in completion_argv
            or "--proxy-response-proof" not in completion_argv
            or "--proxy-proof-verifier-public-key" not in completion_argv
            or "--proxy-collector-public-key" not in completion_argv
            or "--proxy-server-instance-id" not in completion_argv
            or "--proxy-client-nonce" not in completion_argv
            or "--proxy-request-digest" not in completion_argv
            or "--proxy-operation-digest" not in completion_argv
            or "--proxy-tls-channel-binding" not in completion_argv
            or completion_argv[completion_argv.index("--proxy-proof-max-age-seconds") + 1] != "240"
            or collector_nonce != completion_nonce
            or len(collector_nonce) != 43
            or completion_argv[completion_argv.index("--proxy-request-digest") + 1]
            != "$COLLECTOR_SUMMARY.request_digest"
            or completion_argv[completion_argv.index("--proxy-operation-digest") + 1]
            != "$COLLECTOR_SUMMARY.operation_digest"
            or completion_argv[completion_argv.index("--proxy-tls-channel-binding") + 1]
            != "$COLLECTOR_SUMMARY.tls_channel_binding"
        ):
            raise AssertionError(f"runner completion command does not bind current env files: {completion_argv}")
        if "SERVERWARE_PROXY_CLIENT_NONCE" in plan["env_keys"]:
            raise AssertionError(f"runner still accepts a static response-proof nonce: {plan['env_keys']}")
        if "prod-admin-token-32-bytes-minimum-value" in dry_run.stdout.decode("utf-8"):
            raise AssertionError(f"runner dry-run leaked environment values: {plan}")

        missing_proof_env = tmp / "missing-proof.env"
        write_env(missing_proof_env, {"SERVERWARE_RELEASE_CHANNEL": "prod"})
        rejected_missing_proof = run_runner("--env-file", str(missing_proof_env), "--dry-run", *security_args)
        if rejected_missing_proof.returncode == 0 or "missing production proxy proof settings" not in detail(
            rejected_missing_proof
        ):
            raise AssertionError(f"runner accepted missing proxy proof settings: {detail(rejected_missing_proof)}")

        invalid_proof_age_env = tmp / "invalid-proof-age.env"
        invalid_proof_age = {
            key: value
            for key, value in {
                "SERVERWARE_RELEASE_CHANNEL": "prod",
                "SERVERWARE_PROXY_RESPONSE_PROOF_FILE": str(tmp / "proxy-response-proof.json"),
                "SERVERWARE_PROXY_PROOF_COLLECTOR_COMMAND": "/opt/serverware/bin/serverware-proof-client",
                "SERVERWARE_PROXY_PROOF_ADDRESS": "proxy.prod.internal:9090",
                "SERVERWARE_PROXY_PROOF_URL": "https://proof-target.prod.internal/health",
                "SERVERWARE_PROXY_PROOF_CA_BUNDLE": str(tmp / "proxy-ca.pem"),
                "SERVERWARE_PROXY_PROOF_COLLECTOR_PRIVATE_KEY": str(tmp / "collector-key.pem"),
                "SERVERWARE_PROXY_PROOF_COLLECTOR_PUBLIC_KEY": str(tmp / "collector-key.pub.pem"),
                "SERVERWARE_PROXY_PROOF_VERIFIER_PUBLIC_KEY": str(tmp / "proxy-verifier.pub.pem"),
                "SERVERWARE_DATA_PLANE_INSTANCE_ID": "spiffe://prod.serverware.internal/decision-gate/instance-01",
                "SERVERWARE_PROXY_PROOF_MAX_AGE_SECONDS": "901",
            }.items()
        }
        write_env(invalid_proof_age_env, invalid_proof_age)
        rejected_proof_age = run_runner("--env-file", str(invalid_proof_age_env), "--dry-run", *security_args)
        if rejected_proof_age.returncode == 0 or "proxy proof max age" not in detail(rejected_proof_age):
            raise AssertionError(f"runner accepted an invalid proxy proof max age: {detail(rejected_proof_age)}")

        placeholder_env = tmp / "placeholder.env"
        placeholder_env.write_text("SERVERWARE_ADMIN_TOKEN=CHANGE_ME\n", encoding="utf-8")
        rejected = run_runner("--env-file", str(placeholder_env), "--dry-run", *security_args)
        if rejected.returncode == 0 or "placeholder" not in detail(rejected):
            raise AssertionError(f"runner accepted a placeholder env file: {detail(rejected)}")

        example_domain_env = tmp / "example-domain.env"
        example_domain_env.write_text("SERVERWARE_PUBLIC_URL=https://serverware.example\n", encoding="utf-8")
        rejected_example = run_runner("--env-file", str(example_domain_env), "--dry-run", *security_args)
        if rejected_example.returncode == 0 or "example placeholder domain" not in detail(rejected_example):
            raise AssertionError(f"runner accepted an example-domain env file: {detail(rejected_example)}")

        config_env = tmp / "config.env"
        production_env = {
            key: value
            for key, value in production_readiness_test.good_env().items()
            if key.startswith("SERVERWARE_")
        }
        write_env(config_env, production_env)
        config_out = tmp / "production-readiness-config.json"
        config_run = run_runner(
            "--env-file",
            str(config_env),
            "--config-only",
            "--config-out",
            str(config_out),
            *security_args,
        )
        if config_run.returncode != 0:
            raise AssertionError(f"runner config-only path failed: {detail(config_run)}")
        artifact = json.loads(config_out.read_text(encoding="utf-8"))
        if artifact.get("ok") is not True or artifact.get("mode") != "config":
            raise AssertionError(f"runner config artifact was invalid: {artifact}")

    print(canonical_json({"ok": True, "production_readiness_runner": "pass"}))


if __name__ == "__main__":
    main()
