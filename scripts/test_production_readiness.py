#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import verify_production_readiness as readiness  # noqa: E402


OAUTH_SECRET_TEMP_DIR = tempfile.TemporaryDirectory(prefix="serverware-oauth-readiness-")
EVIDENCE_ISSUED_AT = int(time.time())
TEST_CONTROL_PLANE_UID = (
    readiness.CONTROL_PLANE_RUNTIME_UID if os.geteuid() == 0 else os.getuid()
)
TEST_CONTROL_PLANE_GID = (
    readiness.CONTROL_PLANE_RUNTIME_GID if os.geteuid() == 0 else os.getgid()
)


def clean_subprocess_env() -> dict[str, str]:
    allowed = {
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "PATH",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "TZ",
    }
    return {name: value for name, value in os.environ.items() if name in allowed}


def oauth_secret_file(name: str, value: str, mode: int = 0o600) -> Path:
    path = Path(OAUTH_SECRET_TEMP_DIR.name) / name
    path.write_text(value + "\n", encoding="utf-8")
    path.chmod(mode)
    return path


def trusted_ed25519_private_key(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(
            f"serverware-production-readiness:{name}".encode("utf-8")
        ).digest()
    )


def trusted_public_key_file(name: str) -> Path:
    path = Path(OAUTH_SECRET_TEMP_DIR.name) / name
    if path.exists():
        return path
    if name == "sigstore.pub.pem":
        private_key = generate_private_key(public_exponent=65537, key_size=2048)
    else:
        private_key = trusted_ed25519_private_key(name)
    path.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    path.chmod(0o644)
    return path


def trusted_public_key_id(name: str) -> str:
    public_key = serialization.load_pem_public_key(trusted_public_key_file(name).read_bytes())
    public_key_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "sha256:" + hashlib.sha256(public_key_der).hexdigest()


def trusted_private_key_file(
    filename: str, key_name: str = "response-online-signing.pub.pem"
) -> Path:
    path = Path(OAUTH_SECRET_TEMP_DIR.name) / filename
    path.write_bytes(
        trusted_ed25519_private_key(key_name).private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)
    if os.geteuid() == 0:
        path.chown(TEST_CONTROL_PLANE_UID, TEST_CONTROL_PLANE_GID)
    return path


def digest(character: str) -> str:
    return "sha256:" + character * 64


def sha384_digest(character: str) -> str:
    return "sha384:" + character * 96


def sha256_json(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def ed25519_signature(key_name: str, statement: dict[str, Any]) -> str:
    signature = trusted_ed25519_private_key(key_name).sign(
        canonical_json(statement).encode("utf-8")
    )
    return "ed25519:" + base64url(signature)


def fixture_release_identity() -> dict[str, Any]:
    return {
        "source_tree_digest": digest("1"),
        "provenance_digest": digest("2"),
        "runtime_manifest_digest": digest("3"),
        "data_plane_binary_digest": digest("4"),
        "production_image_digests": [digest("5"), digest("6")],
        "production_image_refs": [
            "registry.prod.acme-corp.net/serverware/control@" + digest("5"),
            "registry.prod.acme-corp.net/serverware/decision-gate@" + digest("6"),
        ],
        "production_images_build_sha256": digest("7"),
        "production_images_published_sha256": digest("8"),
        "image_signature_bundle_digest": digest("9"),
    }


def hardware_assurance_document() -> dict[str, Any]:
    release_identity = fixture_release_identity()
    pcrs = {
        "PCR0": sha384_digest("a"),
        "PCR1": sha384_digest("b"),
        "PCR2": sha384_digest("c"),
    }
    build_manifest = {
        "apiVersion": "serverware.eifBuildManifest/v1",
        "release_identity": release_identity,
        "release_identity_sha256": sha256_json(release_identity),
        "eif_image_sha384": pcrs["PCR0"],
        "pcrs": pcrs,
    }
    host_identity_payload = {
        "scheme": "serverware.currentCompletionHostIdentity/v1",
        "machine_id_sha256": digest("a"),
        "product_uuid_sha256": digest("b"),
        "boot_id_sha256": digest("c"),
    }
    host_identity = {
        **host_identity_payload,
        "identity_sha256": sha256_json(host_identity_payload),
        "observed_at_unix": EVIDENCE_ISSUED_AT,
    }
    host_identity["commitment_sha256"] = sha256_json(host_identity)
    statement = {
        "verifier": {
            "name": "production-independent-verifier",
            "organization": "Acme Assurance Lab",
            "independent": True,
        },
        "issued_at_unix": EVIDENCE_ISSUED_AT,
        "expires_at_unix": EVIDENCE_ISSUED_AT + 300,
        "challenge_nonce": base64url(b"h" * 32),
        "current_host_identity": host_identity,
        "attestation_document_sha256": digest("d"),
        "eif": {
            "image_sha384": pcrs["PCR0"],
            "build_manifest": build_manifest,
            "build_manifest_sha256": sha256_json(build_manifest),
            "signature_verified": True,
            "evidence_sha256": digest("0"),
        },
        "pcrs": pcrs,
        "enclave": {
            "cid": 16,
            "parent_cid": 3,
            "vsock_port": 5000,
            "cid_evidence_sha256": digest("1"),
            "vsock_evidence_sha256": digest("2"),
            "vsock_handshake_verified": True,
        },
        "key_custody": {
            "recipient_key_generated_in_enclave": True,
            "kms_recipient_bound": True,
            "plaintext_key_exported": False,
            "parent_process_key_access": False,
            "kms_recipient_bindings_sha256": digest("e"),
            "evidence_sha256": digest("3"),
        },
        "no_parent_key": {
            "verified": True,
            "parent_key_material_absent": True,
            "evidence_sha256": digest("4"),
        },
        "release_bindings": {
            "policy_digest": digest("f"),
            "policy_sequence": 12,
            "policy_high_water_digest": digest("0"),
            "runtime_manifest_digest": release_identity["runtime_manifest_digest"],
            "data_plane_binary_digest": release_identity["data_plane_binary_digest"],
            "provenance_digest": release_identity["provenance_digest"],
            "source_tree_digest": release_identity["source_tree_digest"],
            "response_signing_key_id": digest("a"),
        },
        "artifact_bindings": {
            "nitro_evidence_sha256": digest("b"),
            "production_host_preflight_sha256": digest("c"),
        },
    }
    key_name = "hardware-assurance-verifier.pub.pem"
    return {
        "apiVersion": "serverware.hardwareAssurance/v1",
        "kind": "ServerwareHardwareAssurance",
        "statement": statement,
        "signing_key_id": trusted_public_key_id(key_name),
        "signature": ed25519_signature(key_name, statement),
    }


def hardware_assurance_file(name: str = "hardware-assurance.json") -> Path:
    path = Path(OAUTH_SECRET_TEMP_DIR.name) / name
    path.write_text(
        canonical_json(hardware_assurance_document()) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)
    return path


def final_challenge_receipt_document() -> dict[str, Any]:
    hardware_document = hardware_assurance_document()
    hardware_statement = hardware_document["statement"]
    statement = {
        "authority_provider": "production-final-challenge-authority",
        "consumption_id": "production-consumption-0001",
        "status": "consumed",
        "issued_at_unix": EVIDENCE_ISSUED_AT,
        "expires_at_unix": EVIDENCE_ISSUED_AT + 300,
        "challenge_nonce_sha256": "sha256:"
        + hashlib.sha256(b"h" * 32).hexdigest(),
        "completion_identity_sha256": digest("d"),
        "release_identity_sha256": hardware_statement["eif"]["build_manifest"][
            "release_identity_sha256"
        ],
        "hardware_verifier_key_id": trusted_public_key_id(
            "hardware-assurance-verifier.pub.pem"
        ),
        "current_host_identity_sha256": hardware_statement[
            "current_host_identity"
        ]["identity_sha256"],
        "proxy_server_statement_sha256": digest("e"),
    }
    key_name = "final-challenge-authority.pub.pem"
    return {
        "apiVersion": "serverware.finalChallengeReceipt/v1",
        "kind": "FinalChallengeConsumption",
        "statement": statement,
        "signing_key_id": trusted_public_key_id(key_name),
        "signature": ed25519_signature(key_name, statement),
    }


def final_challenge_receipt_file(name: str = "final-challenge-receipt.json") -> Path:
    path = Path(OAUTH_SECRET_TEMP_DIR.name) / name
    path.write_text(
        canonical_json(final_challenge_receipt_document()) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)
    return path


def rsa_public_key_file(name: str) -> Path:
    path = Path(OAUTH_SECRET_TEMP_DIR.name) / name
    path.write_bytes(
        generate_private_key(public_exponent=65537, key_size=2048).public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return path


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def readiness_command(*extra: str) -> list[str]:
    return [
        sys.executable,
        "scripts/verify_production_readiness.py",
        "--mode",
        "config",
        "--expected-control-plane-uid",
        str(TEST_CONTROL_PLANE_UID),
        "--expected-control-plane-gid",
        str(TEST_CONTROL_PLANE_GID),
        *extra,
    ]


def run_readiness(env: dict[str, str]) -> dict[str, Any]:
    result = subprocess.run(
        readiness_command(),
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
            readiness_command("--out", str(output_path)),
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
            readiness_command("--out", str(output_path)),
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
        readiness_command(),
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
        readiness_command(),
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
    env = clean_subprocess_env()
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
            "SERVERWARE_RELEASE_PROVENANCE_TRUSTED_PUBLIC_KEY": str(
                trusted_public_key_file("release-provenance.pub.pem")
            ),
            "SERVERWARE_SIGSTORE_TRUSTED_PUBLIC_KEY": str(trusted_public_key_file("sigstore.pub.pem")),
            "SERVERWARE_REKOR_TRUSTED_PUBLIC_KEY": str(trusted_public_key_file("rekor.pub.pem")),
            "SERVERWARE_EXTERNAL_CHECKPOINT_PROVIDER": "managed-prod-log",
            "SERVERWARE_EXTERNAL_CHECKPOINT_TRUSTED_PUBLIC_KEY": str(
                trusted_public_key_file("external-checkpoint.pub.pem")
            ),
            "SERVERWARE_CONTROL_PLANE_RESPONSE_SIGNING_PUBLIC_KEY": str(
                trusted_public_key_file("response-online-signing.pub.pem")
            ),
            "SERVERWARE_CONTROL_PLANE_RESPONSE_SIGNING_PUBLIC_KEY_ID": trusted_public_key_id(
                "response-online-signing.pub.pem"
            ),
            "SERVERWARE_ADMIN_TOKEN": "prod-admin-token-32-bytes-minimum-value",
            "SERVERWARE_AUDIT_ANCHOR_TOKEN": "prod-anchor-token-32-bytes-minimum-value",
            "SERVERWARE_ADMIN_ROLES": "admin,approver,auditor,policy_author,policy_publisher,credential_owner,attestation_operator,attestation_reviewer",
            "SERVERWARE_SETUP_ENROLLMENT_VERIFIER_PUBLIC_KEY": str(
                trusted_public_key_file("setup-enrollment-verifier.pub.pem")
            ),
            "SERVERWARE_SETUP_ENROLLMENT_VERIFIER_KEY_ID": trusted_public_key_id(
                "setup-enrollment-verifier.pub.pem"
            ),
            "SERVERWARE_SETUP_ENROLLMENT_VERIFIER_PROVIDER": "production-enrollment-verifier",
            "SERVERWARE_SETUP_HARDWARE_VERIFIER_PUBLIC_KEY": str(
                trusted_public_key_file("setup-hardware-verifier.pub.pem")
            ),
            "SERVERWARE_SETUP_HARDWARE_VERIFIER_KEY_ID": trusted_public_key_id(
                "setup-hardware-verifier.pub.pem"
            ),
            "SERVERWARE_SETUP_HARDWARE_VERIFIER_PROVIDER": "production-hardware-verifier",
            "SERVERWARE_SETUP_FINAL_AUTHORITY_PUBLIC_KEY": str(
                trusted_public_key_file("setup-final-authority.pub.pem")
            ),
            "SERVERWARE_SETUP_FINAL_AUTHORITY_KEY_ID": trusted_public_key_id(
                "setup-final-authority.pub.pem"
            ),
            "SERVERWARE_SETUP_FINAL_AUTHORITY_PROVIDER": "production-setup-final-authority",
            "SERVERWARE_SETUP_ATTESTATION_CHALLENGE_TTL_SECONDS": "300",
            "SERVERWARE_OAUTH_STATE_TTL_SECONDS": "600",
            "SERVERWARE_OAUTH_PENDING_CREDENTIAL_TTL_SECONDS": "900",
            "SERVERWARE_OAUTH_PENDING_CREDENTIAL_MAX_COUNT": "1000",
            "SERVERWARE_SETUP_SESSION_TTL_SECONDS": "86400",
            "SERVERWARE_SETUP_SESSION_MAX_ACTIVE": "1000",
            "SERVERWARE_SETUP_SESSION_MAX_RETAINED": "10000",
            "SERVERWARE_SETUP_SESSION_RETENTION_SECONDS": "604800",
            "SERVERWARE_SETUP_SESSION_EVIDENCE_MAX_BYTES": "1048576",
            "SERVERWARE_SETUP_SESSION_EVIDENCE_MAX_COUNT": "64",
            "SERVERWARE_SETUP_SESSION_EVENT_MAX_BYTES": "16384",
            "SERVERWARE_SETUP_SESSION_EVENT_MAX_COUNT": "128",
            "SERVERWARE_SETUP_SESSION_AUDIT_OUTBOX_MAX_PENDING": "10000",
            "SERVERWARE_SETUP_SESSION_AUDIT_CLAIM_TTL_SECONDS": "60",
            "SERVERWARE_CREDENTIAL_LEASE_REPLAY_MAX_ENTRIES": "1000000",
            "SERVERWARE_GOOGLE_OAUTH_CLIENT_ID": "test-google-client-id",
            "SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET_FILE": str(
                oauth_secret_file("google-client-secret", "test-google-oauth-secret-0123456789")
            ),
            "SERVERWARE_GOOGLE_OAUTH_REDIRECT_URI": "https://serverware.prod.acme-corp.net/api/oauth/callback/google",
            "SERVERWARE_X_OAUTH_CLIENT_ID": "test-x-client-id",
            "SERVERWARE_X_OAUTH_CLIENT_SECRET_FILE": str(
                oauth_secret_file("x-client-secret", "test-x-oauth-secret-0123456789")
            ),
            "SERVERWARE_X_OAUTH_REDIRECT_URI": "https://serverware.prod.acme-corp.net/api/oauth/callback/x",
            "SERVERWARE_OIDC_ENABLED": "1",
            "SERVERWARE_OIDC_ISSUER": "https://idp.prod.acme-corp.net",
            "SERVERWARE_OIDC_AUDIENCE": "serverware-control-plane",
            "SERVERWARE_OIDC_JWKS_JSON": canonical_json({"keys": [{"kty": "RSA", "kid": "prod-key", "n": "AA", "e": "AQAB"}]}),
            "SERVERWARE_OIDC_ROLE_CLAIM": "serverware_roles",
            "SERVERWARE_OIDC_BROWSER_LOGIN_ENABLED": "1",
            "SERVERWARE_OIDC_AUTHORIZATION_ENDPOINT": "https://idp.prod.acme-corp.net/authorize",
            "SERVERWARE_OIDC_TOKEN_ENDPOINT": "https://idp.prod.acme-corp.net/token",
            "SERVERWARE_OIDC_CLIENT_ID": "serverware-control-plane",
            "SERVERWARE_OIDC_CLIENT_SECRET_FILE": str(
                oauth_secret_file("oidc-client-secret", "test-operator-oidc-secret-0123456789")
            ),
            "SERVERWARE_OIDC_REDIRECT_URI": "https://serverware.prod.acme-corp.net/api/auth/oidc/callback",
            "SERVERWARE_OIDC_BROWSER_SCOPES": "openid,profile,email",
            "SERVERWARE_OIDC_TOKEN_AUTH_METHOD": "client_secret_basic",
            "SERVERWARE_OIDC_LOGIN_STATE_TTL_SECONDS": "300",
            "SERVERWARE_OIDC_SESSION_TTL_SECONDS": "3600",
            "SERVERWARE_OIDC_SESSION_WEBAUTHN_REQUIRED": "1",
            "SERVERWARE_OIDC_SESSION_WEBAUTHN_CHALLENGE_TTL_SECONDS": "120",
            "SERVERWARE_OIDC_SESSION_WEBAUTHN_PENDING_TTL_SECONDS": "300",
            "SERVERWARE_WEBAUTHN_RECOVERY_ENABLED": "1",
            "SERVERWARE_WEBAUTHN_RECOVERY_ROOT_PUBLIC_KEY": str(
                trusted_public_key_file("webauthn-recovery-root.pub.pem")
            ),
            "SERVERWARE_WEBAUTHN_RECOVERY_ROOT_KEY_ID": trusted_public_key_id(
                "webauthn-recovery-root.pub.pem"
            ),
            "SERVERWARE_WEBAUTHN_RECOVERY_ROOT_PROVIDER": "offline-recovery-authority",
            "SERVERWARE_WEBAUTHN_RECOVERY_AUDIENCE": "https://serverware.prod.acme-corp.net",
            "SERVERWARE_WEBAUTHN_RECOVERY_TTL_SECONDS": "180",
            "SERVERWARE_WEBAUTHN_RECOVERY_MAX_LIVE": "100",
            "SERVERWARE_WEBAUTHN_RECOVERY_WITNESS_BACKEND": "postgres",
            "SERVERWARE_WEBAUTHN_RECOVERY_WITNESS_POSTGRES_DSN": "postgresql://serverware:serverware@recovery-witness-store/serverware",
            "SERVERWARE_WEBAUTHN_RECOVERY_WITNESS_FAULT_DOMAIN_ID": "recovery-account:us-east-1b",
            "SERVERWARE_POLICY_SIGNING_PUBLIC_KEY": str(
                trusted_public_key_file("policy-online-signing.pub.pem")
            ),
            "SERVERWARE_RESPONSE_SIGNING_PUBLIC_KEY": str(
                trusted_public_key_file("response-online-signing.pub.pem")
            ),
            "SERVERWARE_RESPONSE_SIGNING_PRIVATE_KEY_FILE": str(
                trusted_private_key_file("response-online-signing.pem")
            ),
            "SERVERWARE_WEBAUTHN_TRUST_SIGNING_PUBLIC_KEY": str(
                trusted_public_key_file("webauthn-trust-online-signing.pub.pem")
            ),
            "SERVERWARE_WEBAUTHN_ORIGIN": "https://serverware.prod.acme-corp.net",
            "SERVERWARE_CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED": "1",
            "SERVERWARE_CONTROL_PLANE_MUTATION_REQUIRE_HARDWARE_ATTESTATION": "1",
            "SERVERWARE_CONTROL_PLANE_MUTATION_ALLOWED_AUTHENTICATOR_CLASSES": "yubikey,hardware",
            "SERVERWARE_DIRECT_CA_DOWNLOAD_ENABLED": "0",
            "SERVERWARE_CA_INSTALL_SESSION_TTL_SECONDS": "300",
            "SERVERWARE_CONTROL_PLANE_TWO_PERSON_REQUIRED": "1",
            "SERVERWARE_CONTROL_PLANE_TWO_PERSON_ACTIONS": "credential.create,credential.oauth.activate,credential.oauth.uncertain.resolve,credential.update,credential.delete,route.create,route.update,route.delete,policy.publish,webauthn.credential.register,webauthn.credential.revoke,webauthn.trust.publish,rbac.role.change,rbac.deprovision,control_plane.token.rotate,break_glass.grant,setup.attestation.finalize",
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
            "SERVERWARE_PROXY_PROOF_PRINCIPAL_ID": "agent:production-proof",
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
            "SERVERWARE_COSIGN_KEY_ID": trusted_public_key_id("sigstore.pub.pem"),
            "SERVERWARE_COSIGN_EXPECTED_REKOR_LOG_ID": trusted_public_key_id("rekor.pub.pem"),
            "SERVERWARE_REQUIRE_SIGSTORE_TRANSPARENCY": "1",
            "SERVERWARE_RELEASE_ANCHOR_BASE": "https://release-anchor.prod.acme-corp.net",
            "SERVERWARE_TRANSPARENCY_CHECKPOINT_REQUIRED": "1",
            "SERVERWARE_TRANSPARENCY_CHECKPOINT_COMMAND": "python3 scripts/transparency_checkpoint.py checkpoint",
            "SERVERWARE_TRANSPARENCY_CHECKPOINT_MODE": "http",
            "SERVERWARE_TRANSPARENCY_LOG_URL": "https://transparency.prod.acme-corp.net/checkpoints",
            "SERVERWARE_TRANSPARENCY_EXPECTED_PROVIDER": "managed-prod-log",
            "SERVERWARE_TRANSPARENCY_EXPECTED_LOG_ID": trusted_public_key_id(
                "external-checkpoint.pub.pem"
            ),
            "SERVERWARE_APPARMOR_EXPECTED_PROFILE": "serverware-docker",
            "SERVERWARE_METADATA_STORE_BACKEND": "postgres",
            "SERVERWARE_METADATA_STORE_POSTGRES_DSN": "postgresql://serverware:serverware@metadata-store/serverware",
            "SERVERWARE_METADATA_STORE_FAULT_DOMAIN_ID": "control-plane-account:us-east-1a",
            "SERVERWARE_GRANT_STORE_BACKEND": "postgres",
            "SERVERWARE_GRANT_STORE_POSTGRES_DSN": "postgresql://serverware:serverware@metadata-store/serverware",
            "SERVERWARE_AUDIT_STORE_BACKEND": "postgres",
            "SERVERWARE_AUDIT_STORE_POSTGRES_DSN": "postgresql://serverware:serverware@audit-store/serverware",
            "SERVERWARE_CONTROL_PLANE_GRANT_CONSUME_URL": "https://serverware.internal/api/data-plane/grants/consume",
            "SERVERWARE_CONTROL_PLANE_RATE_LIMIT_CONSUME_URL": "https://serverware.internal/api/data-plane/rate-limits/consume",
            "SERVERWARE_CONTROL_PLANE_RELEASE_AUTHORIZATION_BASE_URL": "https://serverware.internal/api/data-plane/release-authorizations",
            "SERVERWARE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED": "1",
            "SERVERWARE_RELEASE_AUTHORIZATION_RESERVATION_TTL_SECONDS": "15",
            "SERVERWARE_RELEASE_AUTHORIZATION_DISPATCH_TTL_SECONDS": "30",
            "SERVERWARE_RELEASE_AUTHORIZATION_RECONCILE_LIMIT": "100",
            "SERVERWARE_DATA_PLANE_CREDENTIAL_LEASE_TOKEN": "credential-lease-scope-0123456789-ABCDEF",
            "SERVERWARE_DATA_PLANE_AUDIT_TOKEN": "audit-ingest-scope-0123456789-GHIJKLMN",
            "SERVERWARE_DATA_PLANE_GRANT_CONSUME_TOKEN": "grant-consume-scope-0123456789-OPQRST",
            "SERVERWARE_DATA_PLANE_RATE_LIMIT_CONSUME_TOKEN": "rate-limit-scope-0123456789-UVWXYZ",
            "SERVERWARE_DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN": "release-authorization-scope-0123456789-ZYXWVU",
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
        "SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET",
        "SERVERWARE_X_OAUTH_CLIENT_SECRET",
        "SERVERWARE_TWITTER_OAUTH_CLIENT_ID",
        "SERVERWARE_TWITTER_OAUTH_CLIENT_SECRET",
        "SERVERWARE_TWITTER_OAUTH_REDIRECT_URI",
        "SERVERWARE_COMPLETION_VERIFICATION_MODE",
        "SERVERWARE_FINAL_CHALLENGE_RECEIPT",
        "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY",
        "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY_ID",
        "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PROVIDER",
        "SERVERWARE_HARDWARE_ASSURANCE",
        "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY",
        "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY_ID",
        "SERVERWARE_HARDWARE_ASSURANCE_EXPECTED_CHALLENGE_NONCE",
        "SERVERWARE_HARDWARE_ASSURANCE_EXPECTED_CHALLENGE_NONCE_SHA256",
    ):
        env.pop(name, None)
    return env


def final_challenge_env() -> dict[str, str]:
    env = good_env()
    env.update(
        {
            "SERVERWARE_COMPLETION_VERIFICATION_MODE": "final",
            "SERVERWARE_FINAL_CHALLENGE_RECEIPT": str(final_challenge_receipt_file()),
            "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY": str(
                trusted_public_key_file("final-challenge-authority.pub.pem")
            ),
            "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY_ID": trusted_public_key_id(
                "final-challenge-authority.pub.pem"
            ),
            "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PROVIDER": "production-final-challenge-authority",
            "SERVERWARE_HARDWARE_ASSURANCE": str(hardware_assurance_file()),
            "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY": str(
                trusted_public_key_file("hardware-assurance-verifier.pub.pem")
            ),
            "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY_ID": trusted_public_key_id(
                "hardware-assurance-verifier.pub.pem"
            ),
            "SERVERWARE_HARDWARE_ASSURANCE_EXPECTED_CHALLENGE_NONCE": base64.urlsafe_b64encode(
                b"h" * 32
            )
            .decode("ascii")
            .rstrip("="),
        }
    )
    return env


def run_live_probe_helpers() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cosign_key_path = Path(tmp) / "cosign-key.pem"
        cosign_key = Ed25519PrivateKey.generate()
        cosign_key_path.write_bytes(
            cosign_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        cosign_key_path.chmod(0o600)
        cosign_key_id = "sha256:" + hashlib.sha256(
            cosign_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).hexdigest()
        env = clean_subprocess_env()
        env.update(
            {
                "SERVERWARE_RELEASE_CHANNEL": "prod",
                "SERVERWARE_IMAGE_SIGN_COMMAND": f"{sys.executable} scripts/cosign_sigstore.py sign",
                "SERVERWARE_IMAGE_VERIFY_COMMAND": f"{sys.executable} scripts/cosign_sigstore.py verify",
                "SERVERWARE_COSIGN_BINARY": f"{sys.executable} scripts/cosign_fixture.py",
                "SERVERWARE_COSIGN_KEY_ID": cosign_key_id,
                "SERVERWARE_COSIGN_YES": "0",
                "SERVERWARE_COSIGN_FIXTURE_LOG": str(Path(tmp) / "cosign-rekor.jsonl"),
                "SERVERWARE_COSIGN_FIXTURE_KEY": str(cosign_key_path),
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
        wrong_key_env = dict(env)
        wrong_key_env["SERVERWARE_COSIGN_KEY_ID"] = "sha256:" + "e" * 64
        try:
            readiness.run_sigstore_probe(wrong_key_env)
        except RuntimeError as exc:
            if "does not match the cosign bundle public key" not in str(exc):
                raise AssertionError(f"Sigstore key pin failed for the wrong reason: {exc}") from exc
        else:
            raise AssertionError("Sigstore probe accepted a mismatched signing-key SPKI")
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
        server_address = "witness-db" if label == "recovery_witness" else "metadata-db"
        system_identifier = 222 if label == "recovery_witness" else 111
        return {
            "ok": True,
            "database": f"{label}_db",
            "user": "serverware",
            "server_address": server_address,
            "server_port": 5432,
            "system_identifier": system_identifier,
            "tables": list(required_tables),
        }

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

        def colocated_postgres_table_probe(
            label: str, dsn: str, required_tables: tuple[str, ...]
        ) -> dict[str, Any]:
            return {
                "ok": True,
                "database": f"{label}_db",
                "user": "serverware",
                "server_address": "shared-postgres-host",
                "server_port": 5432,
                "system_identifier": 111,
                "tables": list(required_tables),
            }

        readiness.postgres_table_probe = colocated_postgres_table_probe
        try:
            readiness.run_shared_store_probe(good_env())
        except RuntimeError as exc:
            if "non-colocated Postgres server" not in str(exc):
                raise AssertionError(
                    f"colocated witness probe failed for the wrong reason: {exc}"
                ) from exc
        else:
            raise AssertionError(
                "shared-store probe accepted metadata and witness DSNs on one server"
            )

        def aliased_cluster_probe(
            label: str, dsn: str, required_tables: tuple[str, ...]
        ) -> dict[str, Any]:
            return {
                "ok": True,
                "database": f"{label}_db",
                "user": "serverware",
                "server_address": f"{label}-listener",
                "server_port": 5432,
                "system_identifier": 333,
                "tables": list(required_tables),
            }

        readiness.postgres_table_probe = aliased_cluster_probe
        try:
            readiness.run_shared_store_probe(good_env())
        except RuntimeError as exc:
            if "independent Postgres cluster" not in str(exc):
                raise AssertionError(
                    f"aliased-cluster witness probe failed for the wrong reason: {exc}"
                ) from exc
        else:
            raise AssertionError(
                "shared-store probe accepted metadata and witness listeners on one cluster"
            )
    finally:
        readiness.postgres_table_probe = original
    if result.get("ok") is not True:
        raise AssertionError(f"shared-store probe returned invalid result: {result}")
    labels = {label for label, _, _ in calls}
    if labels != {"metadata", "grant", "audit", "recovery_witness"}:
        raise AssertionError(f"shared-store probe did not cover all stores: {calls}")
    required_by_label = {label: set(tables) for label, _, tables in calls}
    if "rate_limit_counters" not in required_by_label.get("metadata", set()):
        raise AssertionError(f"metadata probe did not require shared quota table: {calls}")
    release_tables = {
        "release_authorization_attempts",
        "release_authorization_quota_reservations",
        "release_authorization_events",
    }
    if not release_tables.issubset(required_by_label.get("metadata", set())):
        raise AssertionError(
            f"metadata probe did not require atomic release tables: {calls}"
        )
    if "policy_high_water" not in required_by_label.get("metadata", set()):
        raise AssertionError(f"metadata probe did not require policy rollback state: {calls}")
    if "control_plane_approvals" not in required_by_label.get("metadata", set()):
        raise AssertionError(f"metadata probe did not require two-person approval table: {calls}")
    if "approval_grant_consumptions" not in required_by_label.get("grant", set()):
        raise AssertionError(f"grant probe did not require consumption outbox table: {calls}")
    if "serverware_audit_events" not in required_by_label.get("audit", set()):
        raise AssertionError(f"audit probe did not require HA audit table: {calls}")
    if "serverware_recovery_authorization_claims" not in required_by_label.get(
        "recovery_witness", set()
    ):
        raise AssertionError(f"witness probe did not require authorization claims: {calls}")


def assert_atomic_release_compose_gate() -> None:
    for compose_name in ("docker-compose.yml", "docker-compose.production.yml"):
        compose_path = ROOT / compose_name
        compose_text = compose_path.read_text(encoding="utf-8")
        compose_env = clean_subprocess_env()
        for name in re.findall(r"\$\{([A-Z0-9_]+):\?[^}]*\}", compose_text):
            compose_env.setdefault(name, "serverware-compose-test-value")
        for name in re.findall(
            r"\$\{([A-Z0-9_]+):\?[^}]*\}:[^\n]+", compose_text
        ):
            compose_env[name] = f"/tmp/{name.lower().replace('_', '-')}"
        result = subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                str(compose_path),
                "config",
                "--format",
                "json",
            ],
            cwd=ROOT,
            env=compose_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            raise AssertionError(
                f"{compose_name} did not parse: "
                f"{result.stderr.decode(errors='replace')}"
            )
        model = json.loads(result.stdout)
        for service_name in ("serverware", "decision-gate-rs"):
            service_env = model["services"][service_name].get("environment") or {}
            if service_env.get("SERVERWARE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED") != "1":
                raise AssertionError(
                    f"{compose_name} {service_name} does not enable atomic release authorization"
                )
        if compose_name == "docker-compose.production.yml":
            serverware = model["services"]["serverware"]
            if (
                (serverware.get("environment") or {}).get(
                    "SERVERWARE_RESPONSE_SIGNING_KEY"
                )
                != "/run/secrets/serverware-response-signing-key"
            ):
                raise AssertionError(
                    "production Compose does not select the mounted response-signing key"
                )
            response_key_mounts = [
                volume
                for volume in serverware.get("volumes") or []
                if volume.get("target")
                == "/run/secrets/serverware-response-signing-key"
            ]
            if len(response_key_mounts) != 1 or response_key_mounts[0].get(
                "read_only"
            ) is not True:
                raise AssertionError(
                    "production Compose must mount one read-only response-signing key"
                )


def verify_response_key_runtime_readability() -> None:
    def file_stat(mode: int, uid: int, gid: int) -> os.stat_result:
        return os.stat_result(
            (stat.S_IFREG | mode, 1, 1, 1, uid, gid, 128, 0, 0, 0)
        )

    root_owned_owner_only = file_stat(0o600, 0, 0)
    if readiness.file_readable_by_identity(
        root_owned_owner_only,
        uid=readiness.CONTROL_PLANE_RUNTIME_UID,
        gid=readiness.CONTROL_PLANE_RUNTIME_GID,
    ):
        raise AssertionError(
            "root-owned mode 0600 response key was readable by the production identity"
        )

    production_owned_owner_only = file_stat(
        0o600,
        readiness.CONTROL_PLANE_RUNTIME_UID,
        readiness.CONTROL_PLANE_RUNTIME_GID,
    )
    if not readiness.file_readable_by_identity(
        production_owned_owner_only,
        uid=readiness.CONTROL_PLANE_RUNTIME_UID,
        gid=readiness.CONTROL_PLANE_RUNTIME_GID,
    ):
        raise AssertionError(
            "production-owned mode 0600 response key was not readable by its owner"
        )

    production_group_readable = file_stat(
        0o640,
        0,
        readiness.CONTROL_PLANE_RUNTIME_GID,
    )
    if not readiness.file_readable_by_identity(
        production_group_readable,
        uid=readiness.CONTROL_PLANE_RUNTIME_UID,
        gid=readiness.CONTROL_PLANE_RUNTIME_GID,
    ):
        raise AssertionError(
            "response key with production group read permission was not readable"
        )

    runtime_key = trusted_private_key_file("runtime-readable-response-key.pem")
    failures: list[str] = []
    payload = readiness.read_bounded_regular_file(
        {"TEST_RESPONSE_KEY": str(runtime_key)},
        "TEST_RESPONSE_KEY",
        failures,
        file_label="response-signing private-key",
        max_bytes=readiness.MAX_TRUSTED_PUBLIC_KEY_FILE_BYTES,
        allowed_modes={0o600},
        required_read_uid=TEST_CONTROL_PLANE_UID,
        required_read_gid=TEST_CONTROL_PLANE_GID,
    )
    if payload is None or failures:
        raise AssertionError(
            f"runtime-readable response key failed descriptor validation: {failures}"
        )

    fifo_path = Path(OAUTH_SECRET_TEMP_DIR.name) / "runtime-response-key.fifo"
    os.mkfifo(fifo_path, 0o600)
    fifo_probe_code = (
        "import os,stat,sys; "
        "from pathlib import Path; "
        "from unittest.mock import patch; "
        "sys.path.insert(0,'scripts'); "
        "import verify_production_readiness as readiness; "
        f"regular=Path({str(runtime_key)!r}); fifo=Path({str(fifo_path)!r}); "
        "failures=[]; "
        "\nwith patch.object(Path,'lstat',return_value=regular.lstat()):\n "
        " payload=readiness.read_bounded_regular_file("
        "{'TEST_RESPONSE_KEY':str(fifo)},'TEST_RESPONSE_KEY',failures,"
        "file_label='response-signing private-key',"
        f"max_bytes={readiness.MAX_TRUSTED_PUBLIC_KEY_FILE_BYTES},"
        "allowed_modes={0o600})"
        "\n(payload is None and failures) or sys.exit('FIFO response key was accepted')"
    )
    try:
        fifo_probe = subprocess.run(
            [sys.executable, "-c", fifo_probe_code],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=3,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise AssertionError("readiness validation blocked on a raced FIFO") from exc
    if fifo_probe.returncode != 0:
        raise AssertionError(
            "readiness FIFO rejection probe failed: "
            + (fifo_probe.stderr or fifo_probe.stdout).strip()
        )

    unreadable_uid = 1 if TEST_CONTROL_PLANE_UID != 1 else 2
    unreadable_gid = 1 if TEST_CONTROL_PLANE_GID != 1 else 2
    failures = []
    payload = readiness.read_bounded_regular_file(
        {"TEST_RESPONSE_KEY": str(runtime_key)},
        "TEST_RESPONSE_KEY",
        failures,
        file_label="response-signing private-key",
        max_bytes=readiness.MAX_TRUSTED_PUBLIC_KEY_FILE_BYTES,
        allowed_modes={0o600},
        required_read_uid=unreadable_uid,
        required_read_gid=unreadable_gid,
    )
    if payload is not None or not any(
        "must be readable by production control-plane" in failure
        for failure in failures
    ):
        raise AssertionError(
            f"runtime-unreadable response key passed descriptor validation: {failures}"
        )


def main() -> None:
    assert_atomic_release_compose_gate()
    verify_response_key_runtime_readability()
    passed = run_readiness(good_env())
    if passed.get("mode") != "config":
        raise AssertionError(f"unexpected readiness mode: {passed}")
    public_key_cosign_env = good_env()
    run_readiness(public_key_cosign_env)

    keyless_only_cosign_env = good_env()
    keyless_only_cosign_env.pop("SERVERWARE_COSIGN_KEY", None)
    keyless_only_cosign_env["SERVERWARE_COSIGN_CERT_IDENTITY"] = (
        "https://github.com/acme/serverware/.github/workflows/release.yml@refs/heads/main"
    )
    keyless_only_cosign_env["SERVERWARE_COSIGN_CERT_OIDC_ISSUER"] = (
        "https://token.actions.githubusercontent.com"
    )
    expect_failure(
        keyless_only_cosign_env,
        "Cosign keyless/Fulcio mode is not supported by release completion",
    )

    mixed_cosign_identity_env = good_env()
    mixed_cosign_identity_env["SERVERWARE_COSIGN_CERT_IDENTITY"] = (
        "https://github.com/acme/serverware/.github/workflows/release.yml@refs/heads/main"
    )
    mixed_cosign_identity_env["SERVERWARE_COSIGN_CERT_OIDC_ISSUER"] = (
        "https://token.actions.githubusercontent.com"
    )
    expect_failure(
        mixed_cosign_identity_env,
        "Cosign keyless/Fulcio mode is not supported by release completion",
    )
    run_readiness_output(good_env())
    run_live_probe_helpers()
    run_shared_store_probe_helper()

    for trust_setting in (
        "SERVERWARE_RELEASE_PROVENANCE_TRUSTED_PUBLIC_KEY",
        "SERVERWARE_SIGSTORE_TRUSTED_PUBLIC_KEY",
        "SERVERWARE_REKOR_TRUSTED_PUBLIC_KEY",
        "SERVERWARE_EXTERNAL_CHECKPOINT_TRUSTED_PUBLIC_KEY",
        "SERVERWARE_EXTERNAL_CHECKPOINT_PROVIDER",
        "SERVERWARE_CONTROL_PLANE_RESPONSE_SIGNING_PUBLIC_KEY",
        "SERVERWARE_CONTROL_PLANE_RESPONSE_SIGNING_PUBLIC_KEY_ID",
    ):
        missing_trust_env = good_env()
        missing_trust_env.pop(trust_setting, None)
        expect_failure(missing_trust_env, trust_setting)

    mismatched_response_key_id_env = good_env()
    mismatched_response_key_id_env[
        "SERVERWARE_CONTROL_PLANE_RESPONSE_SIGNING_PUBLIC_KEY_ID"
    ] = "sha256:" + "0" * 64
    expect_failure(
        mismatched_response_key_id_env,
        "SPKI identity must match",
    )

    substituted_response_key_env = good_env()
    substituted_response_key_env[
        "SERVERWARE_CONTROL_PLANE_RESPONSE_SIGNING_PUBLIC_KEY"
    ] = str(trusted_public_key_file("alternate-control-plane-response.pub.pem"))
    substituted_response_key_env[
        "SERVERWARE_CONTROL_PLANE_RESPONSE_SIGNING_PUBLIC_KEY_ID"
    ] = trusted_public_key_id("alternate-control-plane-response.pub.pem")
    expect_failure(
        substituted_response_key_env,
        "must match the online response-signing public identity",
    )

    missing_response_private_key_env = good_env()
    missing_response_private_key_env.pop(
        "SERVERWARE_RESPONSE_SIGNING_PRIVATE_KEY_FILE", None
    )
    expect_failure(
        missing_response_private_key_env,
        "SERVERWARE_RESPONSE_SIGNING_PRIVATE_KEY_FILE must be configured",
    )

    substituted_response_private_key_env = good_env()
    substituted_response_private_key_env[
        "SERVERWARE_RESPONSE_SIGNING_PRIVATE_KEY_FILE"
    ] = str(
        trusted_private_key_file(
            "alternate-response-signing.pem",
            "alternate-control-plane-response.pub.pem",
        )
    )
    expect_failure(
        substituted_response_private_key_env,
        "provisioned response-signing private key must match",
    )

    permissive_response_private_key_env = good_env()
    permissive_response_private_key_path = Path(
        permissive_response_private_key_env[
            "SERVERWARE_RESPONSE_SIGNING_PRIVATE_KEY_FILE"
        ]
    )
    permissive_response_private_key_path.chmod(0o644)
    expect_failure(
        permissive_response_private_key_env,
        "must use mode 0400 or 0600",
    )

    mismatched_checkpoint_provider_env = good_env()
    mismatched_checkpoint_provider_env["SERVERWARE_EXTERNAL_CHECKPOINT_PROVIDER"] = "different-provider"
    expect_failure(mismatched_checkpoint_provider_env, "must match SERVERWARE_TRANSPARENCY_EXPECTED_PROVIDER")

    symlink_trust_env = good_env()
    symlink_trust_path = Path(OAUTH_SECRET_TEMP_DIR.name) / "release-provenance-link.pub.pem"
    symlink_trust_path.unlink(missing_ok=True)
    symlink_trust_path.symlink_to(trusted_public_key_file("release-provenance-link-target.pub.pem"))
    symlink_trust_env["SERVERWARE_RELEASE_PROVENANCE_TRUSTED_PUBLIC_KEY"] = str(symlink_trust_path)
    expect_failure(symlink_trust_env, "regular, non-symlink public-key file")

    oversized_trust_env = good_env()
    oversized_trust_path = Path(OAUTH_SECRET_TEMP_DIR.name) / "oversized-rekor.pub.pem"
    oversized_trust_path.write_bytes(b"A" * (readiness.MAX_TRUSTED_PUBLIC_KEY_FILE_BYTES + 1))
    oversized_trust_env["SERVERWARE_REKOR_TRUSTED_PUBLIC_KEY"] = str(oversized_trust_path)
    expect_failure(
        oversized_trust_env,
        f"between 1 and {readiness.MAX_TRUSTED_PUBLIC_KEY_FILE_BYTES} bytes",
    )

    invalid_pem_trust_env = good_env()
    invalid_pem_trust_path = Path(OAUTH_SECRET_TEMP_DIR.name) / "invalid-sigstore.pub.pem"
    invalid_pem_trust_path.write_text("not a PEM public key\n", encoding="ascii")
    invalid_pem_trust_env["SERVERWARE_SIGSTORE_TRUSTED_PUBLIC_KEY"] = str(invalid_pem_trust_path)
    expect_failure(invalid_pem_trust_env, "must contain a valid PEM public key")

    mismatched_sigstore_key_id_env = good_env()
    mismatched_sigstore_key_id_env["SERVERWARE_COSIGN_KEY_ID"] = "sha256:" + "0" * 64
    expect_failure(
        mismatched_sigstore_key_id_env,
        "SPKI public-key digest must match SERVERWARE_COSIGN_KEY_ID",
    )

    unsupported_sigstore_key_env = good_env()
    unsupported_sigstore_key_env["SERVERWARE_SIGSTORE_TRUSTED_PUBLIC_KEY"] = str(
        trusted_public_key_file("sigstore-ed25519.pub.pem")
    )
    unsupported_sigstore_key_env["SERVERWARE_COSIGN_KEY_ID"] = trusted_public_key_id(
        "sigstore-ed25519.pub.pem"
    )
    expect_failure(
        unsupported_sigstore_key_env,
        "must contain an ECDSA or RSA public key",
    )

    run_readiness(final_challenge_env())

    missing_hardware_key_pin_env = final_challenge_env()
    missing_hardware_key_pin_env.pop(
        "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY_ID"
    )
    expect_failure(
        missing_hardware_key_pin_env,
        "final verification mode requires SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY_ID",
    )

    missing_final_key_pin_env = final_challenge_env()
    missing_final_key_pin_env.pop(
        "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY_ID"
    )
    expect_failure(
        missing_final_key_pin_env,
        "final verification mode requires SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY_ID",
    )

    mismatched_hardware_key_pin_env = final_challenge_env()
    mismatched_hardware_key_pin_env[
        "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY_ID"
    ] = digest("0")
    expect_failure(
        mismatched_hardware_key_pin_env,
        "SPKI identity must match SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY_ID",
    )

    mismatched_final_key_pin_env = final_challenge_env()
    mismatched_final_key_pin_env[
        "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY_ID"
    ] = digest("0")
    expect_failure(
        mismatched_final_key_pin_env,
        "SPKI identity must match SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY_ID",
    )

    arbitrary_hardware_signature_env = final_challenge_env()
    arbitrary_hardware_document = hardware_assurance_document()
    arbitrary_hardware_document["signature"] = "ed25519:test-signature"
    arbitrary_hardware_path = hardware_assurance_file(
        "arbitrary-signature-hardware-assurance.json"
    )
    arbitrary_hardware_path.write_text(
        canonical_json(arbitrary_hardware_document) + "\n", encoding="utf-8"
    )
    arbitrary_hardware_signature_env["SERVERWARE_HARDWARE_ASSURANCE"] = str(
        arbitrary_hardware_path
    )
    expect_failure(
        arbitrary_hardware_signature_env, "must be canonical unpadded base64url"
    )

    arbitrary_receipt_signature_env = final_challenge_env()
    arbitrary_receipt_document = final_challenge_receipt_document()
    arbitrary_receipt_document["signature"] = "test-signature"
    arbitrary_receipt_path = final_challenge_receipt_file(
        "arbitrary-signature-final-challenge-receipt.json"
    )
    arbitrary_receipt_path.write_text(
        canonical_json(arbitrary_receipt_document) + "\n", encoding="utf-8"
    )
    arbitrary_receipt_signature_env["SERVERWARE_FINAL_CHALLENGE_RECEIPT"] = str(
        arbitrary_receipt_path
    )
    expect_failure(arbitrary_receipt_signature_env, "ed25519 signature scheme")

    forged_receipt_signature_env = final_challenge_env()
    forged_receipt_document = final_challenge_receipt_document()
    forged_receipt_document["signature"] = "ed25519:" + base64url(b"\0" * 64)
    forged_receipt_path = final_challenge_receipt_file(
        "forged-signature-final-challenge-receipt.json"
    )
    forged_receipt_path.write_text(
        canonical_json(forged_receipt_document) + "\n", encoding="utf-8"
    )
    forged_receipt_signature_env["SERVERWARE_FINAL_CHALLENGE_RECEIPT"] = str(
        forged_receipt_path
    )
    expect_failure(forged_receipt_signature_env, "signature verification failed")

    incomplete_receipt_shape_env = final_challenge_env()
    incomplete_receipt_document = final_challenge_receipt_document()
    incomplete_receipt_document["statement"].pop("proxy_server_statement_sha256")
    incomplete_receipt_document["signature"] = ed25519_signature(
        "final-challenge-authority.pub.pem",
        incomplete_receipt_document["statement"],
    )
    incomplete_receipt_path = final_challenge_receipt_file(
        "incomplete-shape-final-challenge-receipt.json"
    )
    incomplete_receipt_path.write_text(
        canonical_json(incomplete_receipt_document) + "\n", encoding="utf-8"
    )
    incomplete_receipt_shape_env["SERVERWARE_FINAL_CHALLENGE_RECEIPT"] = str(
        incomplete_receipt_path
    )
    expect_failure(incomplete_receipt_shape_env, "missing required fields")

    incomplete_hardware_shape_env = final_challenge_env()
    incomplete_hardware_document = hardware_assurance_document()
    incomplete_hardware_document["statement"]["key_custody"].pop(
        "evidence_sha256"
    )
    incomplete_hardware_document["signature"] = ed25519_signature(
        "hardware-assurance-verifier.pub.pem",
        incomplete_hardware_document["statement"],
    )
    incomplete_hardware_path = hardware_assurance_file(
        "incomplete-shape-hardware-assurance.json"
    )
    incomplete_hardware_path.write_text(
        canonical_json(incomplete_hardware_document) + "\n", encoding="utf-8"
    )
    incomplete_hardware_shape_env["SERVERWARE_HARDWARE_ASSURANCE"] = str(
        incomplete_hardware_path
    )
    expect_failure(incomplete_hardware_shape_env, "missing required fields")

    duplicate_receipt_key_env = final_challenge_env()
    duplicate_receipt_path = final_challenge_receipt_file(
        "duplicate-key-final-challenge-receipt.json"
    )
    duplicate_receipt_json = canonical_json(final_challenge_receipt_document())
    duplicate_receipt_path.write_text(
        duplicate_receipt_json.replace(
            '"kind":"FinalChallengeConsumption"',
            '"kind":"FinalChallengeConsumption","kind":"FinalChallengeConsumption"',
            1,
        )
        + "\n",
        encoding="utf-8",
    )
    duplicate_receipt_key_env["SERVERWARE_FINAL_CHALLENGE_RECEIPT"] = str(
        duplicate_receipt_path
    )
    expect_failure(duplicate_receipt_key_env, "duplicate JSON object key: kind")

    floating_point_hardware_env = final_challenge_env()
    floating_point_hardware_document = hardware_assurance_document()
    floating_point_hardware_document["statement"]["issued_at_unix"] = float(
        EVIDENCE_ISSUED_AT
    )
    floating_point_hardware_document["signature"] = ed25519_signature(
        "hardware-assurance-verifier.pub.pem",
        floating_point_hardware_document["statement"],
    )
    floating_point_hardware_path = hardware_assurance_file(
        "floating-point-hardware-assurance.json"
    )
    floating_point_hardware_path.write_text(
        canonical_json(floating_point_hardware_document) + "\n", encoding="utf-8"
    )
    floating_point_hardware_env["SERVERWARE_HARDWARE_ASSURANCE"] = str(
        floating_point_hardware_path
    )
    expect_failure(
        floating_point_hardware_env, "floating-point JSON values are forbidden"
    )

    mismatched_hardware_signing_key_env = final_challenge_env()
    mismatched_hardware_signing_key_document = hardware_assurance_document()
    mismatched_hardware_signing_key_document["signing_key_id"] = digest("0")
    mismatched_hardware_signing_key_path = hardware_assurance_file(
        "mismatched-key-hardware-assurance.json"
    )
    mismatched_hardware_signing_key_path.write_text(
        canonical_json(mismatched_hardware_signing_key_document) + "\n",
        encoding="utf-8",
    )
    mismatched_hardware_signing_key_env["SERVERWARE_HARDWARE_ASSURANCE"] = str(
        mismatched_hardware_signing_key_path
    )
    expect_failure(
        mismatched_hardware_signing_key_env,
        "signer does not match the independently trusted verifier key",
    )

    mismatched_receipt_hardware_key_env = final_challenge_env()
    mismatched_receipt_hardware_key_document = final_challenge_receipt_document()
    mismatched_receipt_hardware_key_document["statement"][
        "hardware_verifier_key_id"
    ] = digest("0")
    mismatched_receipt_hardware_key_document["signature"] = ed25519_signature(
        "final-challenge-authority.pub.pem",
        mismatched_receipt_hardware_key_document["statement"],
    )
    mismatched_receipt_hardware_key_path = final_challenge_receipt_file(
        "mismatched-hardware-key-final-challenge-receipt.json"
    )
    mismatched_receipt_hardware_key_path.write_text(
        canonical_json(mismatched_receipt_hardware_key_document) + "\n",
        encoding="utf-8",
    )
    mismatched_receipt_hardware_key_env[
        "SERVERWARE_FINAL_CHALLENGE_RECEIPT"
    ] = str(mismatched_receipt_hardware_key_path)
    expect_failure(
        mismatched_receipt_hardware_key_env,
        "final challenge receipt hardware_verifier_key_id mismatch",
    )

    setup_key_roles = (
        (
            "SERVERWARE_SETUP_ENROLLMENT_VERIFIER_PUBLIC_KEY",
            "SERVERWARE_SETUP_ENROLLMENT_VERIFIER_KEY_ID",
        ),
        (
            "SERVERWARE_SETUP_HARDWARE_VERIFIER_PUBLIC_KEY",
            "SERVERWARE_SETUP_HARDWARE_VERIFIER_KEY_ID",
        ),
        (
            "SERVERWARE_SETUP_FINAL_AUTHORITY_PUBLIC_KEY",
            "SERVERWARE_SETUP_FINAL_AUTHORITY_KEY_ID",
        ),
    )
    release_key_roles = (
        ("SERVERWARE_RELEASE_PROVENANCE_TRUSTED_PUBLIC_KEY", None),
        ("SERVERWARE_SIGSTORE_TRUSTED_PUBLIC_KEY", "SERVERWARE_COSIGN_KEY_ID"),
        (
            "SERVERWARE_REKOR_TRUSTED_PUBLIC_KEY",
            "SERVERWARE_COSIGN_EXPECTED_REKOR_LOG_ID",
        ),
        (
            "SERVERWARE_EXTERNAL_CHECKPOINT_TRUSTED_PUBLIC_KEY",
            "SERVERWARE_TRANSPARENCY_EXPECTED_LOG_ID",
        ),
        (
            "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY",
            "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY_ID",
        ),
        (
            "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY",
            "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY_ID",
        ),
    )
    for setup_key_setting, setup_key_id_setting in setup_key_roles:
        for release_key_setting, release_key_id_setting in release_key_roles:
            reused_cross_domain_key_env = final_challenge_env()
            reused_cross_domain_key_env[release_key_setting] = (
                reused_cross_domain_key_env[setup_key_setting]
            )
            if release_key_id_setting is not None:
                reused_cross_domain_key_env[release_key_id_setting] = (
                    reused_cross_domain_key_env[setup_key_id_setting]
                )
            expect_failure(
                reused_cross_domain_key_env,
                "cross-domain trust key reuse is forbidden",
            )

    for index, (left_key_setting, _) in enumerate(release_key_roles):
        for right_key_setting, right_key_id_setting in release_key_roles[index + 1 :]:
            reused_production_key_env = final_challenge_env()
            reused_path = Path(reused_production_key_env[left_key_setting])
            reused_production_key_env[right_key_setting] = str(reused_path)
            if right_key_id_setting is not None:
                public_key = serialization.load_pem_public_key(reused_path.read_bytes())
                public_key_der = public_key.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                reused_production_key_env[right_key_id_setting] = (
                    "sha256:" + hashlib.sha256(public_key_der).hexdigest()
                )
            expect_failure(
                reused_production_key_env,
                "production trust key reuse is forbidden",
            )

    readiness_with_final_input_env = good_env()
    readiness_with_final_input_env["SERVERWARE_FINAL_CHALLENGE_RECEIPT"] = str(final_challenge_receipt_file())
    expect_failure(readiness_with_final_input_env, "forbidden in readiness mode")

    incomplete_final_challenge_env = final_challenge_env()
    incomplete_final_challenge_env.pop("SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PROVIDER")
    expect_failure(
        incomplete_final_challenge_env,
        "final verification mode requires SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PROVIDER",
    )

    incomplete_hardware_assurance_env = final_challenge_env()
    incomplete_hardware_assurance_env.pop(
        "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY"
    )
    expect_failure(
        incomplete_hardware_assurance_env,
        "final verification mode requires SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY",
    )

    conflicting_hardware_challenge_env = final_challenge_env()
    conflicting_hardware_challenge_env[
        "SERVERWARE_HARDWARE_ASSURANCE_EXPECTED_CHALLENGE_NONCE_SHA256"
    ] = "sha256:" + "a" * 64
    expect_failure(
        conflicting_hardware_challenge_env,
        "requires exactly one hardware assurance expected challenge nonce or digest",
    )

    mismatched_final_authority_provider_env = final_challenge_env()
    mismatched_final_authority_provider_env["SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PROVIDER"] = "other-authority"
    expect_failure(
        mismatched_final_authority_provider_env,
        "authority provider must match the configured provider",
    )

    oversized_final_authority_provider_env = final_challenge_env()
    oversized_final_authority_provider_env["SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PROVIDER"] = "x" * 257
    expect_failure(
        oversized_final_authority_provider_env,
        "must be a canonical provider identifier",
    )

    malformed_hardware_challenge_env = final_challenge_env()
    malformed_hardware_challenge_env[
        "SERVERWARE_HARDWARE_ASSURANCE_EXPECTED_CHALLENGE_NONCE"
    ] = "!not-base64url"
    expect_failure(
        malformed_hardware_challenge_env,
        "must be unpadded base64url for at least 32 bytes",
    )

    symlink_final_receipt_env = final_challenge_env()
    symlink_final_receipt_path = Path(OAUTH_SECRET_TEMP_DIR.name) / "final-challenge-receipt-link.json"
    symlink_final_receipt_path.unlink(missing_ok=True)
    symlink_final_receipt_path.symlink_to(final_challenge_receipt_file("final-challenge-receipt-target.json"))
    symlink_final_receipt_env["SERVERWARE_FINAL_CHALLENGE_RECEIPT"] = str(symlink_final_receipt_path)
    expect_failure(symlink_final_receipt_env, "regular, non-symlink final challenge receipt file")

    wrong_final_authority_algorithm_env = final_challenge_env()
    wrong_final_authority_algorithm_env["SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY"] = str(
        rsa_public_key_file("final-challenge-authority-rsa.pub.pem")
    )
    expect_failure(wrong_final_authority_algorithm_env, "must contain an Ed25519 public key")

    invalid_final_receipt_env = final_challenge_env()
    invalid_final_receipt_path = final_challenge_receipt_file("invalid-final-challenge-receipt.json")
    invalid_final_receipt_path.write_text(canonical_json({"apiVersion": "wrong/v1"}) + "\n", encoding="utf-8")
    invalid_final_receipt_env["SERVERWARE_FINAL_CHALLENGE_RECEIPT"] = str(invalid_final_receipt_path)
    expect_failure(invalid_final_receipt_env, "missing required fields")

    missing_google_env = good_env()
    for name in (
        "SERVERWARE_GOOGLE_OAUTH_CLIENT_ID",
        "SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET_FILE",
        "SERVERWARE_GOOGLE_OAUTH_REDIRECT_URI",
    ):
        missing_google_env.pop(name, None)
    expect_failure(missing_google_env, "Google OAuth provider configuration")

    incomplete_x_env = good_env()
    incomplete_x_env.pop("SERVERWARE_X_OAUTH_CLIENT_SECRET_FILE", None)
    expect_failure(incomplete_x_env, "X OAuth provider configuration")

    http_callback_env = good_env()
    http_callback_env["SERVERWARE_GOOGLE_OAUTH_REDIRECT_URI"] = (
        "http://serverware.prod.acme-corp.net/api/oauth/callback/google"
    )
    expect_failure(http_callback_env, "exact HTTPS callback")

    wrong_origin_callback_env = good_env()
    wrong_origin_callback_env["SERVERWARE_GOOGLE_OAUTH_REDIRECT_URI"] = (
        "https://accounts.prod.acme-corp.net/api/oauth/callback/google"
    )
    expect_failure(wrong_origin_callback_env, "exact HTTPS callback")

    wrong_path_callback_env = good_env()
    wrong_path_callback_env["SERVERWARE_X_OAUTH_REDIRECT_URI"] = (
        "https://serverware.prod.acme-corp.net/oauth/callback/x"
    )
    expect_failure(wrong_path_callback_env, "exact HTTPS callback")

    unbounded_oauth_state_env = good_env()
    unbounded_oauth_state_env["SERVERWARE_OAUTH_STATE_TTL_SECONDS"] = "901"
    expect_failure(unbounded_oauth_state_env, "between 60 and 900 seconds")

    unbounded_pending_oauth_env = good_env()
    unbounded_pending_oauth_env["SERVERWARE_OAUTH_PENDING_CREDENTIAL_TTL_SECONDS"] = "3601"
    expect_failure(unbounded_pending_oauth_env, "between 60 and 3600 seconds")

    unbounded_pending_oauth_count_env = good_env()
    unbounded_pending_oauth_count_env["SERVERWARE_OAUTH_PENDING_CREDENTIAL_MAX_COUNT"] = "10001"
    expect_failure(unbounded_pending_oauth_count_env, "between 1 and 10000")

    unbounded_setup_session_env = good_env()
    unbounded_setup_session_env["SERVERWARE_SETUP_SESSION_EVENT_MAX_COUNT"] = "4097"
    expect_failure(
        unbounded_setup_session_env,
        "SERVERWARE_SETUP_SESSION_EVENT_MAX_COUNT must be between 4 and 4096",
    )

    inconsistent_setup_capacity_env = good_env()
    inconsistent_setup_capacity_env["SERVERWARE_SETUP_SESSION_MAX_RETAINED"] = "999"
    expect_failure(
        inconsistent_setup_capacity_env,
        "SERVERWARE_SETUP_SESSION_MAX_RETAINED must not be below SERVERWARE_SETUP_SESSION_MAX_ACTIVE",
    )

    undersized_lease_replay_env = good_env()
    undersized_lease_replay_env["SERVERWARE_CREDENTIAL_LEASE_REPLAY_MAX_ENTRIES"] = "9999"
    expect_failure(undersized_lease_replay_env, "between 10000 and 10000000")

    weak_oauth_secret_env = good_env()
    weak_oauth_secret = "weak"
    weak_oauth_secret_env["SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET_FILE"] = str(
        oauth_secret_file("weak-google-client-secret", weak_oauth_secret)
    )
    expect_failure_without_secret(weak_oauth_secret_env, "strong OAuth client secret", weak_oauth_secret)

    unsafe_oauth_secret_mode_env = good_env()
    unsafe_oauth_secret_mode_env["SERVERWARE_X_OAUTH_CLIENT_SECRET_FILE"] = str(
        oauth_secret_file("unsafe-x-client-secret", "test-x-oauth-secret-unsafe-0123456789", 0o644)
    )
    expect_failure(unsafe_oauth_secret_mode_env, "mode 0400 or 0600")

    relative_oauth_secret_path_env = good_env()
    relative_oauth_secret_path_env["SERVERWARE_X_OAUTH_CLIENT_SECRET_FILE"] = "relative/x-client-secret"
    expect_failure(relative_oauth_secret_path_env, "must be an absolute path")

    symlink_oauth_secret_env = good_env()
    symlink_path = Path(OAUTH_SECRET_TEMP_DIR.name) / "google-client-secret-link"
    symlink_path.unlink(missing_ok=True)
    symlink_path.symlink_to(oauth_secret_file("symlink-target", "test-google-oauth-secret-link-0123456789"))
    symlink_oauth_secret_env["SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET_FILE"] = str(symlink_path)
    expect_failure(symlink_oauth_secret_env, "regular, non-symlink file")

    plaintext_oauth_secret_env = good_env()
    plaintext_oauth_secret = "test-plaintext-oauth-secret-0123456789"
    plaintext_oauth_secret_env["SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET"] = plaintext_oauth_secret
    expect_failure_without_secret(
        plaintext_oauth_secret_env,
        "must not be set in production",
        plaintext_oauth_secret,
    )

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
    expect_failure(missing_cosign_env, "SERVERWARE_COSIGN_KEY with a KMS/HSM-backed URI")

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

    no_browser_oidc_env = good_env()
    no_browser_oidc_env["SERVERWARE_OIDC_BROWSER_LOGIN_ENABLED"] = "0"
    expect_failure(no_browser_oidc_env, "browser OIDC login")

    no_oidc_session_webauthn_env = good_env()
    no_oidc_session_webauthn_env.pop(
        "SERVERWARE_OIDC_SESSION_WEBAUTHN_REQUIRED", None
    )
    expect_failure(
        no_oidc_session_webauthn_env, "OIDC browser sessions must require WebAuthn"
    )

    weak_oidc_session_webauthn_ttl_env = good_env()
    weak_oidc_session_webauthn_ttl_env[
        "SERVERWARE_OIDC_SESSION_WEBAUTHN_CHALLENGE_TTL_SECONDS"
    ] = "301"
    expect_failure(
        weak_oidc_session_webauthn_ttl_env,
        "OIDC_SESSION_WEBAUTHN_CHALLENGE_TTL_SECONDS",
    )

    weak_oidc_session_pending_ttl_env = good_env()
    weak_oidc_session_pending_ttl_env[
        "SERVERWARE_OIDC_SESSION_WEBAUTHN_PENDING_TTL_SECONDS"
    ] = "301"
    expect_failure(
        weak_oidc_session_pending_ttl_env,
        "OIDC_SESSION_WEBAUTHN_PENDING_TTL_SECONDS",
    )

    recovery_disabled_env = good_env()
    recovery_disabled_env["SERVERWARE_WEBAUTHN_RECOVERY_ENABLED"] = "0"
    expect_failure(recovery_disabled_env, "offline WebAuthn recovery")

    missing_recovery_root_env = good_env()
    missing_recovery_root_env.pop(
        "SERVERWARE_WEBAUTHN_RECOVERY_ROOT_PUBLIC_KEY", None
    )
    expect_failure(missing_recovery_root_env, "RECOVERY_ROOT_PUBLIC_KEY")

    wrong_recovery_root_id_env = good_env()
    wrong_recovery_root_id_env[
        "SERVERWARE_WEBAUTHN_RECOVERY_ROOT_KEY_ID"
    ] = "sha256:" + "f" * 64
    expect_failure(wrong_recovery_root_id_env, "RECOVERY_ROOT_KEY_ID")

    long_recovery_ttl_env = good_env()
    long_recovery_ttl_env["SERVERWARE_WEBAUTHN_RECOVERY_TTL_SECONDS"] = "301"
    expect_failure(long_recovery_ttl_env, "RECOVERY_TTL_SECONDS")

    placeholder_recovery_audience_env = good_env()
    placeholder_recovery_audience_env[
        "SERVERWARE_WEBAUTHN_RECOVERY_AUDIENCE"
    ] = "https://serverware.example"
    expect_failure(placeholder_recovery_audience_env, "RECOVERY_AUDIENCE")

    reused_recovery_root_env = good_env()
    reused_recovery_root_env[
        "SERVERWARE_WEBAUTHN_RECOVERY_ROOT_PUBLIC_KEY"
    ] = reused_recovery_root_env["SERVERWARE_SETUP_FINAL_AUTHORITY_PUBLIC_KEY"]
    reused_recovery_root_env[
        "SERVERWARE_WEBAUTHN_RECOVERY_ROOT_KEY_ID"
    ] = reused_recovery_root_env["SERVERWARE_SETUP_FINAL_AUTHORITY_KEY_ID"]
    expect_failure(reused_recovery_root_env, "cross-domain trust key reuse")

    cross_origin_oidc_token_env = good_env()
    cross_origin_oidc_token_env["SERVERWARE_OIDC_TOKEN_ENDPOINT"] = "https://tokens.prod.acme-corp.net/token"
    expect_failure(cross_origin_oidc_token_env, "issuer origin")

    wrong_oidc_callback_env = good_env()
    wrong_oidc_callback_env["SERVERWARE_OIDC_REDIRECT_URI"] = "https://serverware.prod.acme-corp.net/oidc/callback"
    expect_failure(wrong_oidc_callback_env, "exact HTTPS callback")

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

    no_hardware_attestation_env = good_env()
    no_hardware_attestation_env.pop(
        "SERVERWARE_CONTROL_PLANE_MUTATION_REQUIRE_HARDWARE_ATTESTATION", None
    )
    expect_failure(no_hardware_attestation_env, "hardware-attested WebAuthn")

    broad_authenticator_classes_env = good_env()
    broad_authenticator_classes_env[
        "SERVERWARE_CONTROL_PLANE_MUTATION_ALLOWED_AUTHENTICATOR_CLASSES"
    ] = "yubikey,hardware,platform"
    expect_failure(
        broad_authenticator_classes_env,
        "must be limited to yubikey and hardware",
    )

    missing_setup_trust_env = good_env()
    missing_setup_trust_env.pop("SERVERWARE_SETUP_ENROLLMENT_VERIFIER_PUBLIC_KEY", None)
    expect_failure(missing_setup_trust_env, "SETUP_ENROLLMENT_VERIFIER_PUBLIC_KEY")

    mismatched_setup_trust_env = good_env()
    mismatched_setup_trust_env["SERVERWARE_SETUP_HARDWARE_VERIFIER_KEY_ID"] = (
        mismatched_setup_trust_env["SERVERWARE_SETUP_ENROLLMENT_VERIFIER_KEY_ID"]
    )
    expect_failure(mismatched_setup_trust_env, "SPKI identity")

    reused_setup_provider_env = good_env()
    reused_setup_provider_env["SERVERWARE_SETUP_FINAL_AUTHORITY_PROVIDER"] = (
        reused_setup_provider_env["SERVERWARE_SETUP_HARDWARE_VERIFIER_PROVIDER"]
    )
    expect_failure(reused_setup_provider_env, "must use distinct providers")

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
    expect_failure(partial_two_person_env, "must cover credential creation, exact-account OAuth activation")

    for required_action in (
        "webauthn.credential.revoke",
        "webauthn.trust.publish",
    ):
        missing_webauthn_action_env = good_env()
        configured_actions = missing_webauthn_action_env[
            "SERVERWARE_CONTROL_PLANE_TWO_PERSON_ACTIONS"
        ].split(",")
        missing_webauthn_action_env[
            "SERVERWARE_CONTROL_PLANE_TWO_PERSON_ACTIONS"
        ] = ",".join(
            action for action in configured_actions if action != required_action
        )
        expect_failure(
            missing_webauthn_action_env,
            "SERVERWARE_CONTROL_PLANE_TWO_PERSON_ACTIONS",
        )

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

    no_atomic_release_url_env = good_env()
    no_atomic_release_url_env.pop(
        "SERVERWARE_CONTROL_PLANE_RELEASE_AUTHORIZATION_BASE_URL", None
    )
    expect_failure(no_atomic_release_url_env, "atomic release authorization base URL")

    wrong_atomic_release_url_env = good_env()
    wrong_atomic_release_url_env[
        "SERVERWARE_CONTROL_PLANE_RELEASE_AUTHORIZATION_BASE_URL"
    ] = "https://serverware.internal/api/data-plane/release-authorizations/reserve?unsafe=1"
    expect_failure(wrong_atomic_release_url_env, "exact API path")

    split_atomic_writer_env = good_env()
    split_atomic_writer_env[
        "SERVERWARE_GRANT_STORE_POSTGRES_DSN"
    ] = "postgresql://serverware:serverware@grant-store/serverware"
    expect_failure(split_atomic_writer_env, "same writer DSN and schema")

    disabled_atomic_release_env = good_env()
    disabled_atomic_release_env["SERVERWARE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED"] = "0"
    expect_failure(disabled_atomic_release_env, "must be enabled")

    unbounded_dispatch_ttl_env = good_env()
    unbounded_dispatch_ttl_env[
        "SERVERWARE_RELEASE_AUTHORIZATION_DISPATCH_TTL_SECONDS"
    ] = "301"
    expect_failure(unbounded_dispatch_ttl_env, "dispatch TTL")

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
