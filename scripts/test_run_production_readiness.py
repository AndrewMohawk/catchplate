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
import test_nitro_kms_evidence as nitro_evidence_test  # noqa: E402


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
        artifact_args = (
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
        trust_paths = {
            "release_provenance_trusted_public_key": tmp / "release-provenance.pub.pem",
            "sigstore_trusted_public_key": tmp / "sigstore.pub.pem",
            "rekor_trusted_public_key": tmp / "rekor.pub.pem",
            "external_checkpoint_trusted_public_key": tmp / "external-checkpoint.pub.pem",
        }
        for path in trust_paths.values():
            path.write_bytes(production_readiness_test.trusted_public_key_file(path.name).read_bytes())
        trust_args = (
            "--release-provenance-trusted-public-key",
            str(trust_paths["release_provenance_trusted_public_key"]),
            "--sigstore-trusted-public-key",
            str(trust_paths["sigstore_trusted_public_key"]),
            "--rekor-trusted-public-key",
            str(trust_paths["rekor_trusted_public_key"]),
            "--external-checkpoint-provider",
            "managed-prod-log",
            "--external-checkpoint-trusted-public-key",
            str(trust_paths["external_checkpoint_trusted_public_key"]),
        )
        security_args = (*artifact_args, *trust_args)
        final_challenge_receipt = tmp / "final-challenge-receipt.json"
        final_challenge_receipt.write_bytes(
            production_readiness_test.final_challenge_receipt_file().read_bytes()
        )
        final_challenge_authority_key = tmp / "final-challenge-authority.pub.pem"
        final_challenge_authority_key.write_bytes(
            production_readiness_test.trusted_public_key_file(final_challenge_authority_key.name).read_bytes()
        )
        final_challenge_args = (
            "--final-challenge-receipt",
            str(final_challenge_receipt),
            "--final-challenge-authority-public-key",
            str(final_challenge_authority_key),
            "--final-challenge-authority-public-key-id",
            production_readiness_test.trusted_public_key_id(
                final_challenge_authority_key.name
            ),
            "--final-challenge-authority-provider",
            "production-final-challenge-authority",
        )
        hardware_assurance = tmp / "hardware-assurance.json"
        hardware_assurance.write_bytes(
            production_readiness_test.hardware_assurance_file().read_bytes()
        )
        hardware_assurance_key = tmp / "hardware-assurance-verifier.pub.pem"
        hardware_assurance_key.write_bytes(
            production_readiness_test.trusted_public_key_file(
                hardware_assurance_key.name
            ).read_bytes()
        )
        expected_hardware_challenge = "a" * 43
        hardware_assurance_args = (
            "--hardware-assurance",
            str(hardware_assurance),
            "--hardware-assurance-trusted-public-key",
            str(hardware_assurance_key),
            "--hardware-assurance-trusted-public-key-id",
            production_readiness_test.trusted_public_key_id(
                hardware_assurance_key.name
            ),
            "--hardware-assurance-expected-challenge-nonce",
            expected_hardware_challenge,
        )

        minimal_env = tmp / "minimal.env"
        minimal_values = {
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
        }
        write_env(minimal_env, minimal_values)
        runner_claims = tmp / "runner-claims.json"
        runner_claims.write_text(
            canonical_json(nitro_evidence_test.claims()) + "\n",
            encoding="utf-8",
        )
        runner_nitro_evidence = tmp / "runner-nitro-evidence.json"
        dry_run = run_runner(
            "--env-file",
            str(minimal_env),
            "--claims-file",
            str(runner_claims),
            "--nitro-evidence-out",
            str(runner_nitro_evidence),
            "--dry-run",
            *security_args,
        )
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
        nitro_collector_argv = plan["commands"][2]["argv"]
        live_readiness_argv = plan["commands"][3]["argv"]
        if "--nitro-evidence-file" in nitro_collector_argv:
            raise AssertionError(f"runner passed a verifier-only option to the Nitro collector: {nitro_collector_argv}")
        if (
            live_readiness_argv[live_readiness_argv.index("--nitro-evidence-file") + 1]
            != str(runner_nitro_evidence)
        ):
            raise AssertionError(f"runner did not reuse pre-collected Nitro evidence: {live_readiness_argv}")
        collector_execution = subprocess.run(
            [*nitro_collector_argv, "--allow-fixtures-for-test"],
            cwd=ROOT,
            env=nitro_evidence_test.fixture_env(tmp),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        collector_detail = detail(collector_execution)
        if (
            collector_execution.returncode == 2
            or "unrecognized arguments" in collector_detail
            or not runner_nitro_evidence.is_file()
        ):
            raise AssertionError(
                "runner's real Nitro collector command failed argument parsing: " + collector_detail
            )
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
            or completion_argv[completion_argv.index("--verification-mode") + 1] != "readiness"
            or "--final-challenge-receipt" in completion_argv
            or "--final-challenge-authority-public-key" in completion_argv
            or "--final-challenge-authority-provider" in completion_argv
            or completion_argv[completion_argv.index("--release-provenance-trusted-public-key") + 1]
            != str(trust_paths["release_provenance_trusted_public_key"])
            or completion_argv[completion_argv.index("--sigstore-trusted-public-key") + 1]
            != str(trust_paths["sigstore_trusted_public_key"])
            or completion_argv[completion_argv.index("--rekor-trusted-public-key") + 1]
            != str(trust_paths["rekor_trusted_public_key"])
            or completion_argv[completion_argv.index("--external-checkpoint-provider") + 1]
            != "managed-prod-log"
            or completion_argv[completion_argv.index("--external-checkpoint-trusted-public-key") + 1]
            != str(trust_paths["external_checkpoint_trusted_public_key"])
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
        key_material = trust_paths["sigstore_trusted_public_key"].read_text(encoding="ascii").strip()
        if key_material in dry_run.stdout.decode("utf-8"):
            raise AssertionError(f"runner dry-run leaked trusted public-key material: {plan}")

        env_trust_file = tmp / "env-trust.env"
        env_trust_values = {
            **minimal_values,
            "SERVERWARE_RELEASE_PROVENANCE_TRUSTED_PUBLIC_KEY": str(
                trust_paths["release_provenance_trusted_public_key"]
            ),
            "SERVERWARE_SIGSTORE_TRUSTED_PUBLIC_KEY": str(trust_paths["sigstore_trusted_public_key"]),
            "SERVERWARE_REKOR_TRUSTED_PUBLIC_KEY": str(trust_paths["rekor_trusted_public_key"]),
            "SERVERWARE_EXTERNAL_CHECKPOINT_PROVIDER": "managed-prod-log",
            "SERVERWARE_EXTERNAL_CHECKPOINT_TRUSTED_PUBLIC_KEY": str(
                trust_paths["external_checkpoint_trusted_public_key"]
            ),
        }
        write_env(env_trust_file, env_trust_values)
        env_trust_run = run_runner("--env-file", str(env_trust_file), "--dry-run", *artifact_args)
        if env_trust_run.returncode != 0:
            raise AssertionError(f"runner rejected env-provided trust settings: {detail(env_trust_run)}")
        env_completion_argv = json.loads(env_trust_run.stdout.decode("utf-8"))["commands"][-1]["argv"]
        if (
            env_completion_argv[env_completion_argv.index("--release-provenance-trusted-public-key") + 1]
            != str(trust_paths["release_provenance_trusted_public_key"])
            or env_completion_argv[env_completion_argv.index("--external-checkpoint-provider") + 1]
            != "managed-prod-log"
        ):
            raise AssertionError(f"runner did not propagate env-provided trust settings: {env_completion_argv}")

        missing_trust = run_runner("--env-file", str(minimal_env), "--dry-run", *artifact_args)
        if missing_trust.returncode == 0 or "missing release completion trust settings" not in detail(missing_trust):
            raise AssertionError(f"runner accepted missing release completion trust settings: {detail(missing_trust)}")

        missing_final_mode = run_runner(
            "--env-file", str(env_trust_file), "--dry-run", "--verification-mode", "final", *security_args
        )
        if missing_final_mode.returncode == 0 or "must be pinned" not in detail(missing_final_mode):
            raise AssertionError(f"runner accepted final mode absent from the hashed env: {detail(missing_final_mode)}")

        final_mode_trust_values = {
            **env_trust_values,
            "SERVERWARE_COMPLETION_VERIFICATION_MODE": "final",
        }
        final_mode_trust_file = tmp / "final-mode-trust.env"
        write_env(final_mode_trust_file, final_mode_trust_values)
        final_without_authority = run_runner(
            "--env-file", str(final_mode_trust_file), "--dry-run", "--verification-mode", "final", *security_args
        )
        if final_without_authority.returncode == 0 or "requires off-host challenge authority inputs" not in detail(
            final_without_authority
        ):
            raise AssertionError(
                f"runner accepted final mode without off-host challenge authority inputs: {detail(final_without_authority)}"
            )

        oversized_provider_env = tmp / "oversized-provider.env"
        write_env(
            oversized_provider_env,
            {
                **final_mode_trust_values,
                "SERVERWARE_FINAL_CHALLENGE_RECEIPT": str(final_challenge_receipt),
                "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY": str(final_challenge_authority_key),
                "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY_ID": (
                    production_readiness_test.trusted_public_key_id(
                        final_challenge_authority_key.name
                    )
                ),
                "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PROVIDER": "x" * 257,
            },
        )
        oversized_provider = run_runner(
            "--env-file",
            str(oversized_provider_env),
            "--dry-run",
            "--verification-mode",
            "final",
            *artifact_args,
        )
        if oversized_provider.returncode == 0 or "must not exceed 256 characters" not in detail(oversized_provider):
            raise AssertionError(f"runner accepted an oversized final authority provider: {detail(oversized_provider)}")

        authority_only_env = tmp / "authority-only.env"
        write_env(
            authority_only_env,
            {
                **final_mode_trust_values,
                "SERVERWARE_FINAL_CHALLENGE_RECEIPT": str(final_challenge_receipt),
                "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY": str(final_challenge_authority_key),
                "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY_ID": (
                    production_readiness_test.trusted_public_key_id(
                        final_challenge_authority_key.name
                    )
                ),
                "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PROVIDER": "production-final-challenge-authority",
            },
        )
        final_without_hardware = run_runner(
            "--env-file",
            str(authority_only_env),
            "--dry-run",
            "--verification-mode",
            "final",
            *security_args,
        )
        if (
            final_without_hardware.returncode == 0
            or "requires hardware assurance inputs" not in detail(final_without_hardware)
        ):
            raise AssertionError(
                f"runner accepted final mode without hardware assurance: {detail(final_without_hardware)}"
            )

        readiness_with_final_input = run_runner(
            "--env-file",
            str(minimal_env),
            "--dry-run",
            "--final-challenge-receipt",
            str(final_challenge_receipt),
            *security_args,
        )
        if readiness_with_final_input.returncode == 0 or "only valid with --verification-mode final" not in detail(
            readiness_with_final_input
        ):
            raise AssertionError(
                f"runner accepted a final challenge authority input in readiness mode: {detail(readiness_with_final_input)}"
            )

        final_env_file = tmp / "final-authority.env"
        final_env_values = {
            **final_mode_trust_values,
            "SERVERWARE_FINAL_CHALLENGE_RECEIPT": str(final_challenge_receipt),
            "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY": str(final_challenge_authority_key),
            "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY_ID": (
                production_readiness_test.trusted_public_key_id(
                    final_challenge_authority_key.name
                )
            ),
            "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PROVIDER": "production-final-challenge-authority",
            "SERVERWARE_HARDWARE_ASSURANCE": str(hardware_assurance),
            "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY": str(
                hardware_assurance_key
            ),
            "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY_ID": (
                production_readiness_test.trusted_public_key_id(
                    hardware_assurance_key.name
                )
            ),
            "SERVERWARE_HARDWARE_ASSURANCE_EXPECTED_CHALLENGE_NONCE": expected_hardware_challenge,
        }
        write_env(final_env_file, final_env_values)
        final_run = run_runner(
            "--env-file",
            str(final_env_file),
            "--dry-run",
            "--verification-mode",
            "final",
            *final_challenge_args,
            *hardware_assurance_args,
            *security_args,
        )
        if final_run.returncode != 0:
            raise AssertionError(f"runner rejected env-pinned final authority inputs: {detail(final_run)}")
        final_argv = json.loads(final_run.stdout.decode("utf-8"))["commands"][-1]["argv"]
        if (
            final_argv[final_argv.index("--verification-mode") + 1] != "final"
            or final_argv[final_argv.index("--final-challenge-receipt") + 1] != str(final_challenge_receipt)
            or final_argv[final_argv.index("--final-challenge-authority-public-key") + 1]
            != str(final_challenge_authority_key)
            or final_argv[final_argv.index("--final-challenge-authority-public-key-id") + 1]
            != production_readiness_test.trusted_public_key_id(
                final_challenge_authority_key.name
            )
            or final_argv[final_argv.index("--final-challenge-authority-provider") + 1]
            != "production-final-challenge-authority"
            or final_argv[final_argv.index("--hardware-assurance") + 1] != str(hardware_assurance)
            or final_argv[final_argv.index("--hardware-assurance-trusted-public-key-id") + 1]
            != production_readiness_test.trusted_public_key_id(
                hardware_assurance_key.name
            )
            or final_argv[final_argv.index("--hardware-assurance-expected-challenge-nonce") + 1]
            != expected_hardware_challenge
        ):
            raise AssertionError(f"runner did not propagate env-pinned final inputs: {final_argv}")

        malformed_hardware_id_env = tmp / "malformed-hardware-id.env"
        write_env(
            malformed_hardware_id_env,
            {
                **final_env_values,
                "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY_ID": "sha256:not-a-key-id",
            },
        )
        malformed_hardware_id = run_runner(
            "--env-file",
            str(malformed_hardware_id_env),
            "--dry-run",
            "--verification-mode",
            "final",
            *security_args,
        )
        if (
            malformed_hardware_id.returncode == 0
            or "hardware assurance trusted public key ID must be sha256" not in detail(
                malformed_hardware_id
            )
        ):
            raise AssertionError(
                f"runner accepted a malformed hardware verifier key ID: {detail(malformed_hardware_id)}"
            )

        same_authority_id_env = tmp / "same-final-authority-id.env"
        write_env(
            same_authority_id_env,
            {
                **final_env_values,
                "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY_ID": (
                    final_env_values[
                        "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY_ID"
                    ]
                ),
            },
        )
        same_authority_id = run_runner(
            "--env-file",
            str(same_authority_id_env),
            "--dry-run",
            "--verification-mode",
            "final",
            *security_args,
        )
        if (
            same_authority_id.returncode == 0
            or "must use different public keys" not in detail(same_authority_id)
        ):
            raise AssertionError(
                f"runner accepted one key ID for both final trust roles: {detail(same_authority_id)}"
            )

        mismatched_mode = run_runner(
            "--env-file",
            str(final_env_file),
            "--dry-run",
            *security_args,
        )
        if mismatched_mode.returncode == 0 or "must match" not in detail(mismatched_mode):
            raise AssertionError(f"runner accepted a command/env verification-mode mismatch: {detail(mismatched_mode)}")

        substituted_authority = run_runner(
            "--env-file",
            str(final_env_file),
            "--dry-run",
            "--verification-mode",
            "final",
            "--final-challenge-authority-provider",
            "caller-selected-authority",
            *security_args,
        )
        if substituted_authority.returncode == 0 or "must match" not in detail(substituted_authority):
            raise AssertionError(
                "runner accepted a caller-selected final authority over the pinned env value: "
                + detail(substituted_authority)
            )

        cli_only_final = run_runner(
            "--env-file",
            str(final_mode_trust_file),
            "--dry-run",
            "--verification-mode",
            "final",
            *final_challenge_args,
            *hardware_assurance_args,
            *security_args,
        )
        if cli_only_final.returncode == 0 or "must be pinned" not in detail(cli_only_final):
            raise AssertionError(f"runner accepted CLI-only final trust inputs: {detail(cli_only_final)}")

        removed_ledger = run_runner(
            "--env-file",
            str(minimal_env),
            "--dry-run",
            "--verification-mode",
            "final",
            "--final-challenge-ledger",
            str(tmp / "ledger.json"),
            *security_args,
        )
        if removed_ledger.returncode == 0 or "unrecognized arguments: --final-challenge-ledger" not in detail(
            removed_ledger
        ):
            raise AssertionError(f"runner still accepts a local final challenge ledger: {detail(removed_ledger)}")

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
