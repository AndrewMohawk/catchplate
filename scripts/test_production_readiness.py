#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import verify_production_readiness as readiness  # noqa: E402


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def run_readiness(env: dict[str, str]) -> dict[str, Any]:
    result = subprocess.run(
        [sys.executable, "scripts/verify_production_readiness.py", "--mode", "config"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        check=False,
    )
    detail = result.stderr.decode("utf-8", errors="replace") + result.stdout.decode("utf-8", errors="replace")
    if result.returncode != 0:
        raise AssertionError(f"production readiness unexpectedly failed: {detail}")
    parsed = json.loads(result.stdout.decode("utf-8"))
    if not isinstance(parsed, dict) or parsed.get("ok") is not True:
        raise AssertionError(f"production readiness returned invalid success: {parsed}")
    return parsed


def run_readiness_output(env: dict[str, str]) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        output_path = Path(tmp) / "production-readiness.json"
        result = subprocess.run(
            [
                sys.executable,
                "scripts/verify_production_readiness.py",
                "--mode",
                "config",
                "--out",
                str(output_path),
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            check=False,
        )
        detail = result.stderr.decode("utf-8", errors="replace") + result.stdout.decode("utf-8", errors="replace")
        if result.returncode != 0:
            raise AssertionError(f"production readiness output run failed: {detail}")
        parsed = json.loads(result.stdout.decode("utf-8"))
        if not output_path.exists() or not parsed.get("result_sha256", "").startswith("sha256:"):
            raise AssertionError(f"production readiness did not write an evidence artifact: {parsed}")
        artifact = json.loads(output_path.read_text(encoding="utf-8"))
        if artifact.get("ok") is not True or artifact.get("mode") != "config":
            raise AssertionError(f"production readiness artifact was invalid: {artifact}")


def run_failure_output(env: dict[str, str], expected: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        output_path = Path(tmp) / "production-readiness-failure.json"
        result = subprocess.run(
            [
                sys.executable,
                "scripts/verify_production_readiness.py",
                "--mode",
                "config",
                "--out",
                str(output_path),
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            check=False,
        )
        detail = result.stderr.decode("utf-8", errors="replace") + result.stdout.decode("utf-8", errors="replace")
        if result.returncode == 0:
            raise AssertionError(f"production readiness failure output run unexpectedly passed: {detail}")
        if expected not in detail:
            raise AssertionError(f"production readiness failure output had wrong error, expected {expected!r}: {detail}")
        parsed = json.loads(result.stdout.decode("utf-8"))
        if not output_path.exists() or not parsed.get("result_sha256", "").startswith("sha256:"):
            raise AssertionError(f"production readiness did not write a failure artifact: {parsed}")
        artifact = json.loads(output_path.read_text(encoding="utf-8"))
        if artifact.get("ok") is not False or artifact.get("production_readiness") != "fail":
            raise AssertionError(f"production readiness failure artifact was invalid: {artifact}")
        if expected not in json.dumps(artifact):
            raise AssertionError(f"production readiness failure artifact omitted the failure reason: {artifact}")


def expect_failure(env: dict[str, str], expected: str) -> None:
    result = subprocess.run(
        [sys.executable, "scripts/verify_production_readiness.py", "--mode", "config"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        check=False,
    )
    detail = result.stderr.decode("utf-8", errors="replace") + result.stdout.decode("utf-8", errors="replace")
    if result.returncode == 0:
        raise AssertionError(f"production readiness unexpectedly succeeded: {detail}")
    if expected not in detail:
        raise AssertionError(f"production readiness failed with wrong error, expected {expected!r}: {detail}")


def expect_failure_without_secret(env: dict[str, str], expected: str, secret: str) -> None:
    result = subprocess.run(
        [sys.executable, "scripts/verify_production_readiness.py", "--mode", "config"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        check=False,
    )
    detail = result.stderr.decode("utf-8", errors="replace") + result.stdout.decode("utf-8", errors="replace")
    if result.returncode == 0 or expected not in detail:
        raise AssertionError(f"production readiness did not reject scoped credentials as expected: {detail}")
    if secret in detail:
        raise AssertionError("production readiness disclosed an internal service credential")


def good_env() -> dict[str, str]:
    env = os.environ.copy()
    env.pop("SERVERWARE_DECISION_GATE_BASE", None)
    env.update(
        {
            "SERVERWARE_RELEASE_CHANNEL": "prod",
            "SERVERWARE_PUBLIC_URL": "https://serverware.prod.acme-corp.net",
            "SERVERWARE_CONTROL_PLANE_TLS_DIR": "/etc/serverware/control-plane-tls",
            "SERVERWARE_AUDIT_ANCHOR_TLS_DIR": "/etc/serverware/audit-anchor-tls",
            "SERVERWARE_PRODUCTION_CONTROL_PLANE_BASE": "https://serverware.prod.acme-corp.net:3000",
            "SERVERWARE_ATTESTATION_HELPER_DIR": "/opt/serverware/attestation-helpers",
            "SERVERWARE_RELEASE_PROVENANCE_FILE": "/opt/serverware/release/release-provenance.json",
            "SERVERWARE_IMAGE_SIGNATURES_FILE": "/opt/serverware/release/image-signatures.json",
            "SERVERWARE_ADMIN_TOKEN": "prod-admin-token-32-bytes-minimum-value",
            "SERVERWARE_AUDIT_ANCHOR_TOKEN": "prod-anchor-token-32-bytes-minimum-value",
            "SERVERWARE_ADMIN_ROLES": "admin,approver,auditor,policy_author,policy_publisher,credential_owner",
            "SERVERWARE_OIDC_ENABLED": "1",
            "SERVERWARE_OIDC_ISSUER": "https://idp.prod.acme-corp.net",
            "SERVERWARE_OIDC_AUDIENCE": "serverware-control-plane",
            "SERVERWARE_OIDC_JWKS_JSON": canonical_json({"keys": [{"kty": "RSA", "kid": "prod-key", "n": "AA", "e": "AQAB"}]}),
            "SERVERWARE_OIDC_ROLE_CLAIM": "serverware_roles",
            "SERVERWARE_WEBAUTHN_ORIGIN": "https://serverware.prod.acme-corp.net",
            "SERVERWARE_CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED": "1",
            "SERVERWARE_DIRECT_CA_DOWNLOAD_ENABLED": "0",
            "SERVERWARE_CA_INSTALL_SESSION_TTL_SECONDS": "300",
            "SERVERWARE_CONTROL_PLANE_TWO_PERSON_REQUIRED": "1",
            "SERVERWARE_CONTROL_PLANE_TWO_PERSON_ACTIONS": "credential.create,credential.update,credential.delete,route.create,route.update,route.delete,policy.publish,webauthn.credential.register,rbac.role.change,rbac.deprovision,control_plane.token.rotate,break_glass.grant",
            "SERVERWARE_WEBAUTHN_BOOTSTRAP_TOKEN": "test-production-bootstrap-token-32-chars-minimum",
            "SERVERWARE_POLICY_PUBLISH_DRY_RUN_REQUIRED": "1",
            "SERVERWARE_POLICY_CANARY_REQUIRED": "1",
            "SERVERWARE_POLICY_CANARY_MIN_OBSERVATION_SECONDS": "60",
            "SERVERWARE_POLICY_CANARY_MIN_AUDIT_EVENTS": "10",
            "SERVERWARE_POLICY_CANARY_MAX_DENIALS": "0",
            "SERVERWARE_TEE_QUOTE_PROVIDER": "aws-nitro-enclaves",
            "SERVERWARE_TEE_PLATFORM": "aws-nitro",
            "SERVERWARE_TEE_QUOTE_COMMAND": "python scripts/aws_nitro_tee_provider.py quote",
            "SERVERWARE_TEE_QUOTE_VERIFY_COMMAND": "python scripts/aws_nitro_tee_provider.py verify",
            "SERVERWARE_KEY_RELEASE_REQUIRED": "1",
            "SERVERWARE_KEY_RELEASE_COMMAND": "python scripts/aws_nitro_tee_provider.py release",
            "SERVERWARE_MASTER_KEY_UNSEAL_COMMAND": "/usr/bin/python3 /app/scripts/aws_nitro_kms_unseal.py unseal",
            "SERVERWARE_NITRO_NSM_UNSEAL_COMMAND_TEMPLATE": "/opt/serverware/bin/nsm-unseal --ciphertext {recipient_ciphertext_path}",
            "SERVERWARE_NITRO_NSM_UNSEAL_OUTPUT_FORMAT": "json",
            "SERVERWARE_KEY_RELEASE_ALLOW_DEBUG": "0",
            "SERVERWARE_KEY_RELEASE_MIN_ROLLBACK_EPOCH": "1",
            "SERVERWARE_KEY_RELEASE_REQUIRE_DATA_PLANE_DIGEST": "1",
            "SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST": "sha256:" + "9" * 64,
            "SERVERWARE_DATA_PLANE_LEASE_RECIPIENT_ATTESTATION_REQUIRED": "1",
            "SERVERWARE_DATA_PLANE_RECIPIENT_ATTESTATION_COMMAND": "/opt/serverware/bin/lease-recipient-attest",
            "SERVERWARE_DATA_PLANE_RESPONSE_PROOF_ATTESTATION_COMMAND": "/opt/serverware/bin/response-proof-attest",
            "SERVERWARE_DATA_PLANE_INSTANCE_ID": "spiffe://prod.serverware.internal/decision-gate/instance-01",
            "SERVERWARE_POLICY_MIN_SEQUENCE": "1",
            "SERVERWARE_POLICY_MIN_ROLLBACK_EPOCH": "1",
            "SERVERWARE_PROXY_RESPONSE_PROOF_FILE": "/opt/serverware/release/proxy-response-proof.json",
            "SERVERWARE_PROXY_PROOF_COLLECTOR_COMMAND": "/opt/serverware/bin/serverware-proof-client",
            "SERVERWARE_PROXY_PROOF_ADDRESS": "proxy.prod.internal:8080",
            "SERVERWARE_PROXY_PROOF_URL": "https://proof-target.prod.internal/health",
            "SERVERWARE_PROXY_PROOF_CA_BUNDLE": "/etc/serverware/proxy-ca.pem",
            "SERVERWARE_PROXY_PROOF_AGENT_ID": "production-proof-agent",
            "SERVERWARE_PROXY_PROOF_COLLECTOR_PRIVATE_KEY": "/etc/serverware/proof-collector.key.pem",
            "SERVERWARE_PROXY_PROOF_COLLECTOR_PUBLIC_KEY": "/etc/serverware/proof-collector.pub.pem",
            "SERVERWARE_PROXY_PROOF_COLLECTOR_KEY_ID": "sha256:" + "a" * 64,
            "SERVERWARE_PROXY_PROOF_VERIFIER_PUBLIC_KEY": "/etc/serverware/proxy-proof-verifier.pub.pem",
            "SERVERWARE_PROXY_PROOF_VERIFIER_KEY_ID": "sha256:" + "b" * 64,
            "SERVERWARE_DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND": "/opt/serverware/bin/lease-recipient-verify",
            "SERVERWARE_CONTROL_PLANE_ATTESTATION_VERIFY_COMMAND": "/opt/serverware/bin/control-plane-attestation-verify",
            "SERVERWARE_NITRO_ATTESTATION_COMMAND": "/opt/serverware/bin/nitro-nsm-attest",
            "SERVERWARE_NITRO_NSM_ATTEST_COMMAND_TEMPLATE": "/opt/serverware/bin/nsm-attest --user-data {user_data_path} --out {output_path}",
            "SERVERWARE_NITRO_ROOT_CERT": "/etc/serverware/nitro-root.pem",
            "SERVERWARE_NITRO_ROOT_CERT_PEM": "-----BEGIN CERTIFICATE-----\\nMIIB\\n-----END CERTIFICATE-----",
            "SERVERWARE_NITRO_EXPECTED_PCRS": canonical_json({"0": "11" * 48, "1": "22" * 48, "2": "33" * 48}),
            "SERVERWARE_NITRO_REQUIRE_KMS_COMMAND": "1",
            "SERVERWARE_NITRO_KMS_RELEASE_COMMAND": "/opt/serverware/bin/kms-unseal --key awskms://arn:aws:kms:us-east-1:111122223333:key/serverware",
            "SERVERWARE_NITRO_KMS_MATERIALS_FILE": "/etc/serverware/kms-materials.json",
            "SERVERWARE_NITRO_ALLOWED_MATERIALS": "broker-kek,decision-gate-ca",
            "SERVERWARE_IMAGE_SIGNATURE_PROVIDER": "sigstore-command",
            "SERVERWARE_IMAGE_SIGN_COMMAND": "python3 scripts/cosign_sigstore.py sign",
            "SERVERWARE_IMAGE_VERIFY_COMMAND": "python3 scripts/cosign_sigstore.py verify",
            "SERVERWARE_COSIGN_BINARY": "cosign",
            "SERVERWARE_COSIGN_KEY": "awskms://arn:aws:kms:us-east-1:111122223333:key/serverware-signing",
            "SERVERWARE_COSIGN_KEY_ID": "sha256:" + "c" * 64,
            "SERVERWARE_COSIGN_EXPECTED_REKOR_LOG_ID": "sha256:" + "5" * 64,
            "SERVERWARE_REQUIRE_SIGSTORE_TRANSPARENCY": "1",
            "SERVERWARE_RELEASE_ANCHOR_BASE": "https://release-anchor.prod.acme-corp.net",
            "SERVERWARE_TRANSPARENCY_CHECKPOINT_REQUIRED": "1",
            "SERVERWARE_TRANSPARENCY_CHECKPOINT_COMMAND": "python3 scripts/transparency_checkpoint.py checkpoint",
            "SERVERWARE_TRANSPARENCY_CHECKPOINT_MODE": "http",
            "SERVERWARE_TRANSPARENCY_LOG_URL": "https://transparency.prod.acme-corp.net/checkpoints",
            "SERVERWARE_TRANSPARENCY_EXPECTED_PROVIDER": "managed-prod-log",
            "SERVERWARE_TRANSPARENCY_EXPECTED_LOG_ID": "sha256:" + "d" * 64,
            "SERVERWARE_APPARMOR_EXPECTED_PROFILE": "serverware-docker",
            "SERVERWARE_METADATA_STORE_BACKEND": "postgres",
            "SERVERWARE_METADATA_STORE_POSTGRES_DSN": "postgresql://serverware:serverware@metadata-store/serverware",
            "SERVERWARE_GRANT_STORE_BACKEND": "postgres",
            "SERVERWARE_GRANT_STORE_POSTGRES_DSN": "postgresql://serverware:serverware@grant-store/serverware",
            "SERVERWARE_AUDIT_STORE_BACKEND": "postgres",
            "SERVERWARE_AUDIT_STORE_POSTGRES_DSN": "postgresql://serverware:serverware@audit-store/serverware",
            "SERVERWARE_CONTROL_PLANE_GRANT_CONSUME_URL": "https://serverware.internal/api/data-plane/grants/consume",
            "SERVERWARE_CONTROL_PLANE_RATE_LIMIT_CONSUME_URL": "https://serverware.internal/api/data-plane/rate-limits/consume",
            "SERVERWARE_DATA_PLANE_CREDENTIAL_LEASE_TOKEN": "credential-lease-scope-0123456789-ABCDEF",
            "SERVERWARE_DATA_PLANE_AUDIT_TOKEN": "audit-ingest-scope-0123456789-GHIJKLMN",
            "SERVERWARE_DATA_PLANE_GRANT_CONSUME_TOKEN": "grant-consume-scope-0123456789-OPQRST",
            "SERVERWARE_DATA_PLANE_RATE_LIMIT_CONSUME_TOKEN": "rate-limit-scope-0123456789-UVWXYZ",
            "SERVERWARE_DATA_PLANE_MANAGEMENT_TOKEN": "rust-management-scope-0123456789-abcdef",
            "SERVERWARE_AGENT_EGRESS_POLICY_REQUIRED": "1",
            "SERVERWARE_AGENT_EGRESS_POLICY_MODE": "kubernetes-network-policy",
            "SERVERWARE_AGENT_EGRESS_PROXY_CIDRS": "10.42.0.10/32,10.42.0.11/32",
            "SERVERWARE_AGENT_EGRESS_PROXY_PORT": "8080",
            "SERVERWARE_AGENT_ENROLLMENT_PACKET_REQUIRED": "1",
            "SERVERWARE_PRODUCTION_IMAGE_NO_SHELL_REQUIRED": "1",
            "SERVERWARE_PRODUCTION_IMAGES": ",".join(
                [
                    "registry.prod.acme-corp.net/serverware/control@sha256:" + "a" * 64,
                    "registry.prod.acme-corp.net/serverware/decision-gate@sha256:" + "b" * 64,
                ]
            ),
            "SERVERWARE_CONTROL_PLANE_IMAGE": "registry.prod.acme-corp.net/serverware/control@sha256:" + "a" * 64,
            "SERVERWARE_DECISION_GATE_IMAGE": "registry.prod.acme-corp.net/serverware/decision-gate@sha256:" + "b" * 64,
        }
    )
    for name in (
        "SERVERWARE_DEV_AUTHENTICATOR",
        "SERVERWARE_NITRO_FIXTURE",
        "SERVERWARE_NITRO_ALLOW_DEBUG",
        "SERVERWARE_NITRO_ALLOW_DEBUG_RELEASE",
        "SERVERWARE_NITRO_ATTESTATION_DOCUMENT",
        "SERVERWARE_NITRO_ATTESTATION_DOCUMENT_B64",
        "SERVERWARE_TRANSPARENCY_ALLOW_INSECURE_HTTP",
    ):
        env.pop(name, None)
    return env


def run_live_probe_helpers() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        env = os.environ.copy()
        env.update(
            {
                "SERVERWARE_RELEASE_CHANNEL": "prod",
                "SERVERWARE_IMAGE_SIGN_COMMAND": f"{sys.executable} scripts/cosign_sigstore.py sign",
                "SERVERWARE_IMAGE_VERIFY_COMMAND": f"{sys.executable} scripts/cosign_sigstore.py verify",
                "SERVERWARE_COSIGN_BINARY": f"{sys.executable} scripts/cosign_fixture.py",
                "SERVERWARE_COSIGN_KEY_ID": "sha256:" + "e" * 64,
                "SERVERWARE_COSIGN_YES": "0",
                "SERVERWARE_COSIGN_FIXTURE_LOG": str(Path(tmp) / "cosign-rekor.jsonl"),
                "SERVERWARE_COSIGN_FIXTURE_KEY": str(Path(tmp) / "cosign-key.pem"),
                "SERVERWARE_REQUIRE_SIGSTORE_TRANSPARENCY": "1",
                "SERVERWARE_TRANSPARENCY_CHECKPOINT_COMMAND": f"{sys.executable} scripts/transparency_checkpoint.py checkpoint",
                "SERVERWARE_TRANSPARENCY_CHECKPOINT_MODE": "fixture",
                "SERVERWARE_EXTERNAL_TRANSPARENCY_LOG_PATH": str(Path(tmp) / "managed-log.jsonl"),
                "SERVERWARE_EXTERNAL_TRANSPARENCY_LOG_KEY": str(Path(tmp) / "managed-log-key.pem"),
                "SERVERWARE_EXTERNAL_TRANSPARENCY_PROVIDER": "managed-production-readiness-test",
            }
        )
        sigstore = readiness.run_sigstore_probe(env)
        if sigstore.get("ok") is not True or not sigstore.get("transparency_log_id"):
            raise AssertionError(f"Sigstore live helper probe did not prove transparency: {sigstore}")
        pinned_rekor_env = dict(env)
        pinned_rekor_env["SERVERWARE_COSIGN_EXPECTED_REKOR_LOG_ID"] = sigstore["transparency_log_id"]
        pinned_sigstore = readiness.run_sigstore_probe(pinned_rekor_env)
        if pinned_sigstore.get("transparency_log_id") != sigstore["transparency_log_id"]:
            raise AssertionError(f"Sigstore probe did not preserve pinned Rekor log ID: {pinned_sigstore}")
        wrong_rekor_env = dict(env)
        wrong_rekor_env["SERVERWARE_COSIGN_EXPECTED_REKOR_LOG_ID"] = "sha256:" + "0" * 64
        try:
            readiness.run_sigstore_probe(wrong_rekor_env)
        except RuntimeError as exc:
            if "SERVERWARE_COSIGN_EXPECTED_REKOR_LOG_ID" not in str(exc):
                raise AssertionError(f"Sigstore probe failed for the wrong reason: {exc}") from exc
        else:
            raise AssertionError("Sigstore probe accepted a mismatched Rekor log ID")
        transparency = readiness.run_transparency_probe(env)
        if transparency.get("ok") is not True or transparency.get("provider") != "managed-production-readiness-test":
            raise AssertionError(f"transparency live helper probe returned invalid result: {transparency}")

        no_transparency_env = dict(env)
        no_transparency_env["SERVERWARE_COSIGN_FIXTURE_NO_TRANSPARENCY"] = "1"
        try:
            readiness.run_sigstore_probe(no_transparency_env)
        except RuntimeError as exc:
            if "transparency" not in str(exc).lower():
                raise AssertionError(f"Sigstore probe failed for the wrong reason: {exc}") from exc
        else:
            raise AssertionError("Sigstore probe accepted a signature without transparency evidence")

        missing_checkpoint_env = dict(env)
        missing_checkpoint_env.pop("SERVERWARE_TRANSPARENCY_CHECKPOINT_COMMAND", None)
        try:
            readiness.run_transparency_probe(missing_checkpoint_env)
        except RuntimeError as exc:
            if "TRANSPARENCY_CHECKPOINT_COMMAND" not in str(exc):
                raise AssertionError(f"transparency probe failed for the wrong reason: {exc}") from exc
        else:
            raise AssertionError("transparency probe accepted a missing checkpoint command")


def run_shared_store_probe_helper() -> None:
    env = good_env()
    calls: list[tuple[str, str, tuple[str, ...]]] = []
    original = readiness.postgres_table_probe

    def fake_postgres_table_probe(label: str, dsn: str, required_tables: tuple[str, ...]) -> dict[str, Any]:
        calls.append((label, dsn, required_tables))
        return {"ok": True, "database": f"{label}_db", "user": "serverware", "tables": list(required_tables)}

    readiness.postgres_table_probe = fake_postgres_table_probe
    try:
        result = readiness.run_shared_store_probe(env)
        missing_dsn_env = good_env()
        missing_dsn_env.pop("SERVERWARE_AUDIT_STORE_POSTGRES_DSN", None)
        try:
            readiness.run_shared_store_probe(missing_dsn_env)
        except RuntimeError as exc:
            if "audit Postgres DSN" not in str(exc):
                raise AssertionError(f"shared-store probe failed for the wrong reason: {exc}") from exc
        else:
            raise AssertionError("shared-store probe accepted a missing audit Postgres DSN")
    finally:
        readiness.postgres_table_probe = original
    if result.get("ok") is not True:
        raise AssertionError(f"shared-store probe returned invalid result: {result}")
    labels = {label for label, _, _ in calls}
    if labels != {"metadata", "grant", "audit"}:
        raise AssertionError(f"shared-store probe did not cover all stores: {calls}")
    required_by_label = {label: set(tables) for label, _, tables in calls}
    if "rate_limit_counters" not in required_by_label.get("metadata", set()):
        raise AssertionError(f"metadata probe did not require shared quota table: {calls}")
    if "policy_high_water" not in required_by_label.get("metadata", set()):
        raise AssertionError(f"metadata probe did not require policy rollback state: {calls}")
    if "control_plane_approvals" not in required_by_label.get("metadata", set()):
        raise AssertionError(f"metadata probe did not require two-person approval table: {calls}")
    if "approval_grant_consumptions" not in required_by_label.get("grant", set()):
        raise AssertionError(f"grant probe did not require consumption outbox table: {calls}")
    if "serverware_audit_events" not in required_by_label.get("audit", set()):
        raise AssertionError(f"audit probe did not require HA audit table: {calls}")


def main() -> None:
    passed = run_readiness(good_env())
    if passed.get("mode") != "config":
        raise AssertionError(f"unexpected readiness mode: {passed}")
    run_readiness_output(good_env())
    run_live_probe_helpers()
    run_shared_store_probe_helper()

    fixture_env = good_env()
    fixture_env["SERVERWARE_NITRO_FIXTURE"] = "1"
    fixture_env["SERVERWARE_NITRO_ATTESTATION_COMMAND"] = "python scripts/nitro_attestation_fixture.py attest"
    fixture_env["SERVERWARE_NITRO_KMS_RELEASE_COMMAND"] = "python scripts/nitro_kms_fixture.py release"
    fixture_env["SERVERWARE_COSIGN_BINARY"] = "python scripts/cosign_fixture.py"
    fixture_env["SERVERWARE_TRANSPARENCY_CHECKPOINT_MODE"] = "fixture"
    expect_failure(fixture_env, "fixture")

    fixture_sign_env = good_env()
    fixture_sign_env["SERVERWARE_IMAGE_SIGN_COMMAND"] = "python scripts/sigstore_fixture.py sign"
    expect_failure(fixture_sign_env, "IMAGE_SIGN_COMMAND")

    missing_rekor_pin_env = good_env()
    missing_rekor_pin_env.pop("SERVERWARE_COSIGN_EXPECTED_REKOR_LOG_ID", None)
    expect_failure(missing_rekor_pin_env, "Rekor log ID")

    fixture_template_env = good_env()
    fixture_template_env["SERVERWARE_NITRO_ATTESTATION_COMMAND"] = "python scripts/nitro_nsm_attest.py attest"
    fixture_template_env["SERVERWARE_NITRO_NSM_ATTEST_COMMAND_TEMPLATE"] = "python scripts/nitro_attestation_fixture.py attest"
    expect_failure(fixture_template_env, "NITRO_NSM_ATTEST_COMMAND_TEMPLATE")

    missing_cosign_env = good_env()
    missing_cosign_env.pop("SERVERWARE_COSIGN_KEY", None)
    missing_cosign_env.pop("SERVERWARE_COSIGN_CERT_IDENTITY", None)
    missing_cosign_env.pop("SERVERWARE_COSIGN_CERT_OIDC_ISSUER", None)
    expect_failure(missing_cosign_env, "KMS/HSM key ref or keyless certificate identity")

    dev_admin_token_env = good_env()
    dev_admin_token_env["SERVERWARE_ADMIN_TOKEN"] = "dev-admin-token"
    expect_failure(dev_admin_token_env, "development/default")

    missing_scope_token_env = good_env()
    missing_scope_token_env.pop("SERVERWARE_DATA_PLANE_GRANT_CONSUME_TOKEN", None)
    expect_failure(missing_scope_token_env, "SERVERWARE_DATA_PLANE_GRANT_CONSUME_TOKEN")

    weak_scope_token_env = good_env()
    weak_scope_token_env["SERVERWARE_DATA_PLANE_RATE_LIMIT_CONSUME_TOKEN"] = "too-short"
    expect_failure(weak_scope_token_env, "SERVERWARE_DATA_PLANE_RATE_LIMIT_CONSUME_TOKEN")

    equal_scope_token_env = good_env()
    duplicate_secret = equal_scope_token_env["SERVERWARE_DATA_PLANE_AUDIT_TOKEN"]
    equal_scope_token_env["SERVERWARE_DATA_PLANE_CREDENTIAL_LEASE_TOKEN"] = duplicate_secret
    expect_failure_without_secret(equal_scope_token_env, "must be distinct", duplicate_secret)

    no_oidc_env = good_env()
    no_oidc_env.pop("SERVERWARE_OIDC_ENABLED", None)
    expect_failure(no_oidc_env, "OIDC authentication")

    localhost_oidc_env = good_env()
    localhost_oidc_env["SERVERWARE_OIDC_ISSUER"] = "http://localhost:8080"
    expect_failure(localhost_oidc_env, "OIDC_ISSUER")

    example_public_url_env = good_env()
    example_public_url_env["SERVERWARE_PUBLIC_URL"] = "https://serverware.example"
    expect_failure(example_public_url_env, "PUBLIC_URL")

    example_oidc_env = good_env()
    example_oidc_env["SERVERWARE_OIDC_ISSUER"] = "https://idp.example"
    expect_failure(example_oidc_env, "OIDC_ISSUER")

    example_transparency_env = good_env()
    example_transparency_env["SERVERWARE_TRANSPARENCY_LOG_URL"] = "https://transparency.example/checkpoints"
    expect_failure(example_transparency_env, "TRANSPARENCY_LOG_URL")

    no_mutation_mfa_env = good_env()
    no_mutation_mfa_env.pop("SERVERWARE_CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED", None)
    expect_failure(no_mutation_mfa_env, "WebAuthn MFA")

    direct_ca_env = good_env()
    direct_ca_env["SERVERWARE_DIRECT_CA_DOWNLOAD_ENABLED"] = "1"
    expect_failure(direct_ca_env, "direct CA download")
    run_failure_output(direct_ca_env, "direct CA download")

    weak_ca_session_env = good_env()
    weak_ca_session_env["SERVERWARE_CA_INSTALL_SESSION_TTL_SECONDS"] = "1200"
    expect_failure(weak_ca_session_env, "CA install session TTL")

    no_two_person_env = good_env()
    no_two_person_env.pop("SERVERWARE_CONTROL_PLANE_TWO_PERSON_REQUIRED", None)
    expect_failure(no_two_person_env, "two-person approval")

    partial_two_person_env = good_env()
    partial_two_person_env["SERVERWARE_CONTROL_PLANE_TWO_PERSON_ACTIONS"] = "credential.update,policy.publish"
    expect_failure(partial_two_person_env, "must cover credential, route, policy publish")

    no_policy_dry_run_env = good_env()
    no_policy_dry_run_env.pop("SERVERWARE_POLICY_PUBLISH_DRY_RUN_REQUIRED", None)
    expect_failure(no_policy_dry_run_env, "dry-run decision tests")

    no_policy_canary_env = good_env()
    no_policy_canary_env.pop("SERVERWARE_POLICY_CANARY_REQUIRED", None)
    expect_failure(no_policy_canary_env, "canary activation")

    weak_policy_canary_env = good_env()
    weak_policy_canary_env["SERVERWARE_POLICY_CANARY_MIN_AUDIT_EVENTS"] = "0"
    expect_failure(weak_policy_canary_env, "audit evidence")

    no_recipient_attestation_env = good_env()
    no_recipient_attestation_env.pop("SERVERWARE_DATA_PLANE_LEASE_RECIPIENT_ATTESTATION_REQUIRED", None)
    expect_failure(no_recipient_attestation_env, "recipient attestation")

    insecure_credential_transport_env = good_env()
    insecure_credential_transport_env["SERVERWARE_ALLOW_INSECURE_DEV_CREDENTIAL_LEASES"] = "1"
    expect_failure(insecure_credential_transport_env, "must be disabled")

    missing_recipient_verifier_env = good_env()
    missing_recipient_verifier_env.pop("SERVERWARE_DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND", None)
    expect_failure(missing_recipient_verifier_env, "RECIPIENT_VERIFY_COMMAND")

    debug_key_release_env = good_env()
    debug_key_release_env["SERVERWARE_KEY_RELEASE_ALLOW_DEBUG"] = "1"
    expect_failure(debug_key_release_env, "reject debug attestation")

    unbound_key_release_env = good_env()
    unbound_key_release_env.pop("SERVERWARE_KEY_RELEASE_REQUIRE_DATA_PLANE_DIGEST", None)
    expect_failure(unbound_key_release_env, "measured data-plane binary digest")

    invalid_binary_digest_env = good_env()
    invalid_binary_digest_env["SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST"] = "sha256:not-a-measurement"
    expect_failure(invalid_binary_digest_env, "64-hex digest")

    fixture_recipient_verifier_env = good_env()
    fixture_recipient_verifier_env["SERVERWARE_DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND"] = "python fixture.py"
    expect_failure(fixture_recipient_verifier_env, "must not use fixture helpers")

    insecure_transparency_env = good_env()
    insecure_transparency_env["SERVERWARE_TRANSPARENCY_LOG_URL"] = "http://transparency.example/checkpoints"
    insecure_transparency_env["SERVERWARE_TRANSPARENCY_ALLOW_INSECURE_HTTP"] = "1"
    expect_failure(insecure_transparency_env, "https URL")

    local_quota_env = good_env()
    local_quota_env.pop("SERVERWARE_CONTROL_PLANE_RATE_LIMIT_CONSUME_URL", None)
    expect_failure(local_quota_env, "shared rate-limit consume URL")

    local_grant_env = good_env()
    local_grant_env.pop("SERVERWARE_CONTROL_PLANE_GRANT_CONSUME_URL", None)
    expect_failure(local_grant_env, "shared JIT grant consume URL")

    mutable_image_env = good_env()
    mutable_image_env["SERVERWARE_PRODUCTION_IMAGES"] = "registry.prod.acme-corp.net/serverware/control:latest"
    expect_failure(mutable_image_env, "pinned by digest")

    example_registry_env = good_env()
    example_registry_env["SERVERWARE_PRODUCTION_IMAGES"] = "registry.example/serverware/control@sha256:" + "a" * 64
    expect_failure(example_registry_env, "placeholder registry")

    extra_nitro_material_env = good_env()
    extra_nitro_material_env["SERVERWARE_NITRO_ALLOWED_MATERIALS"] = "broker-kek,decision-gate-ca,debug-material"
    expect_failure(extra_nitro_material_env, "exactly broker-kek and decision-gate-ca")

    missing_no_shell_env = good_env()
    missing_no_shell_env.pop("SERVERWARE_PRODUCTION_IMAGE_NO_SHELL_REQUIRED", None)
    expect_failure(missing_no_shell_env, "no-shell verification")

    open_egress_env = good_env()
    open_egress_env["SERVERWARE_AGENT_EGRESS_PROXY_CIDRS"] = "0.0.0.0/0"
    expect_failure(open_egress_env, "universal routes")

    missing_enrollment_env = good_env()
    missing_enrollment_env.pop("SERVERWARE_AGENT_ENROLLMENT_PACKET_REQUIRED", None)
    expect_failure(missing_enrollment_env, "agent enrollment packets")

    print(canonical_json({"ok": True, "production_readiness": "pass", "checks": passed.get("checks")}))


if __name__ == "__main__":
    main()
