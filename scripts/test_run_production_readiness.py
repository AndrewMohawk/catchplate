#!/usr/bin/env python3
from __future__ import annotations

import json
import fcntl
import hashlib
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import test_production_readiness as production_readiness_test  # noqa: E402
import test_nitro_kms_evidence as nitro_evidence_test  # noqa: E402
import launch_authorization  # noqa: E402
import run_production_readiness  # noqa: E402


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def write_env(path: Path, env: dict[str, str]) -> None:
    lines = []
    for key in sorted(env):
        lines.append(f"{key}={shlex.quote(str(env[key]))}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o600)


def run_runner(*args: str) -> subprocess.CompletedProcess[bytes]:
    argv = list(args)
    if "--verification-mode" in argv and argv[argv.index("--verification-mode") + 1] == "final":
        env_path = Path(argv[argv.index("--env-file") + 1])
        if "--launcher-trusted-production-env-path" not in argv:
            argv.extend(
                [
                    "--launcher-trusted-production-env-path",
                    str(env_path),
                    "--launcher-trusted-production-env-sha256",
                    "sha256:" + hashlib.sha256(env_path.read_bytes()).hexdigest(),
                ]
            )
    return subprocess.run(
        [sys.executable, "scripts/run_production_readiness.py", *argv],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def run_runner_in_environment(
    environment: dict[str, str],
    *args: str,
) -> subprocess.CompletedProcess[bytes]:
    argv = list(args)
    if "--verification-mode" in argv and argv[argv.index("--verification-mode") + 1] == "final":
        env_path = Path(argv[argv.index("--env-file") + 1])
        if "--launcher-trusted-production-env-path" not in argv:
            argv.extend(
                [
                    "--launcher-trusted-production-env-path",
                    str(env_path),
                    "--launcher-trusted-production-env-sha256",
                    "sha256:" + hashlib.sha256(env_path.read_bytes()).hexdigest(),
                ]
            )
    return subprocess.run(
        [sys.executable, "scripts/run_production_readiness.py", *argv],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=environment,
    )


def detail(result: subprocess.CompletedProcess[bytes]) -> str:
    return result.stdout.decode("utf-8", errors="replace") + result.stderr.decode("utf-8", errors="replace")


def verify_launcher_style_helper_import() -> None:
    code = """
import importlib.util
import sys
from pathlib import Path

runner = Path(sys.argv[1]).resolve()
scripts = Path(sys.argv[2]).resolve()
root = scripts.parent
sys.path[:] = [
    entry
    for entry in sys.path
    if Path(entry or '.').resolve() != scripts
]
spec = importlib.util.spec_from_file_location('launcher_style_readiness', runner)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
assert module.launch_authorization.__file__ == str(scripts / 'launch_authorization.py')
assert sys.path[:2] == [str(scripts), str(root)]
"""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            code,
            str(ROOT / "scripts/run_production_readiness.py"),
            str(ROOT / "scripts"),
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            "launcher-style sys.path could not import launch_authorization: "
            + detail(result)
        )


def proof_policy_bundle(
    *,
    agent_id: str = "production-proof-agent",
    principal_id: str = "agent:production-proof",
    scheme: str = "https",
    host: str = "proof-target.prod.internal",
    port: int = 443,
    methods: list[str] | None = None,
    paths: list[str] | None = None,
) -> dict[str, object]:
    return {
        "apiVersion": "serverware.policy/v1",
        "kind": "PolicyBundle",
        "metadata": {
            "id": "production-proof-policy",
            "sequence": 1,
            "rollbackEpoch": 1,
        },
        "defaults": {
            "action": "deny",
            "failMode": "closed",
            "unknownHosts": "block",
            "unknownPaths": "block",
            "validationFailure": "block",
        },
        "principals": [
            {
                "id": principal_id,
                "requiredHeaders": {"X-Serverware-Agent": agent_id},
            }
        ],
        "credentials": [],
        "routes": [
            {
                "id": "production.proof.health",
                "principals": [principal_id],
                "match": {
                    "scheme": scheme,
                    "host": host,
                    "port": port,
                    "methods": methods or ["GET"],
                    "paths": paths or ["/health"],
                },
                "adapter": {
                    "type": "generic.rest",
                    "config": {
                        "request": {
                            "allowedHeaders": ["accept", "user-agent"],
                            "allowedQueryKeys": [],
                            "bodyMode": "none",
                            "maxBodyBytes": 0,
                        },
                        "response": {
                            "mode": "json",
                            "maxBodyBytes": 65536,
                            "allowedFields": ["status"],
                        },
                    },
                },
            }
        ],
    }


def verify_sealed_bootstrap_receipt_contract() -> None:
    def metadata(*, mode: int = 0o100400, link_count: int = 1) -> dict[str, int]:
        return {
            "device": 1,
            "inode": 2,
            "mode": mode,
            "ownerUid": 0,
            "ownerGid": 0,
            "linkCount": link_count,
            "size": 128,
            "modifiedUnixNanos": 1,
            "changedUnixNanos": 1,
        }

    def file_record(path: str, character: str) -> dict[str, object]:
        return {
            "path": path,
            "sha256": "sha256:" + character * 64,
            "metadata": metadata(),
        }

    launcher_digest = "sha256:" + "3" * 64
    release_root = "/opt/serverware/releases/fixture"
    receipt = {
        "apiVersion": run_production_readiness.BOOTSTRAP_RECEIPT_API_VERSION,
        "kind": run_production_readiness.BOOTSTRAP_RECEIPT_KIND,
        "launchId": "1" * 64,
        "bootIdSha256": "sha256:" + "2" * 64,
        "launcher": file_record(
            "/opt/serverware/launchers/sha256-"
            + launcher_digest.removeprefix("sha256:")
            + "/serverware-production-launcher",
            "3",
        ),
        "manifest": file_record("/etc/serverware/production-release-launch.json", "4"),
        "sourceTreeDigest": "sha256:" + "5" * 64,
        "productionEnv": file_record("/etc/serverware/production-readiness.env", "9"),
        "python": {
            **file_record(f"{release_root}/runtime/python/bin/python3", "a"),
            "importRoots": [
                {
                    "path": release_root,
                    "sha256": "sha256:" + "b" * 64,
                    "metadata": metadata(mode=0o40555, link_count=2),
                },
                {
                    "path": f"{release_root}/runtime/python/lib/python3.11",
                    "sha256": "sha256:" + "c" * 64,
                    "metadata": metadata(mode=0o40555, link_count=2),
                },
                {
                    "path": f"{release_root}/runtime/python/lib/python3.11/lib-dynload",
                    "sha256": "sha256:" + "d" * 64,
                    "metadata": metadata(mode=0o40555, link_count=2),
                },
                {
                    "path": f"{release_root}/vendor",
                    "sha256": "sha256:" + "e" * 64,
                    "metadata": metadata(mode=0o40555, link_count=2),
                },
            ],
        },
        "scripts": {
            "preflight": file_record(
                "/opt/serverware/releases/fixture/scripts/production_host_preflight.py", "c"
            ),
            "runner": file_record(
                "/opt/serverware/releases/fixture/scripts/run_production_readiness.py", "d"
            ),
        },
        "composeFile": file_record(
            "/opt/serverware/releases/fixture/docker-compose.production.yml", "e"
        ),
        "inputs": {
            name: file_record(f"/opt/serverware/releases/fixture/evidence/{name}.json", "f")
            for name in sorted(run_production_readiness.BOOTSTRAP_RECEIPT_INPUT_NAMES)
        },
        "argv": {"preflightSha256": "sha256:" + "6" * 64, "readinessSha256": "sha256:" + "7" * 64},
        "environment": {
            "names": run_production_readiness.BOOTSTRAP_RECEIPT_COMMITTED_ENV_NAMES,
            "sha256": "sha256:" + "8" * 64,
        },
    }

    authority_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("11" * 32))

    def authority_spki(key: Ed25519PrivateKey) -> bytes:
        return key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def authorization_for(
        target: dict[str, object],
        *,
        key: Ed25519PrivateKey = authority_key,
        issued_at: int = 100,
        expires_at: int = 120,
        verified_at: int = 101,
    ) -> dict[str, object]:
        inputs = target["inputs"]
        assert isinstance(inputs, dict)
        launcher = target["launcher"]
        manifest = target["manifest"]
        assert isinstance(launcher, dict) and isinstance(manifest, dict)
        request = {
            "apiVersion": launch_authorization.REQUEST_API_VERSION,
            "kind": launch_authorization.REQUEST_KIND,
            "launcherNonce": target["launchId"],
            "bootIdSha256": target["bootIdSha256"],
            "launcherSha256": launcher["sha256"],
            "manifestSha256": manifest["sha256"],
            "releaseProvenanceSha256": inputs["releaseProvenance"]["sha256"],
            "provenanceDigest": "sha256:" + "0" * 64,
            "reproducibleBuildVerificationSha256": inputs[
                "reproducibleBuildVerification"
            ]["sha256"],
            "sourceTreeDigest": target["sourceTreeDigest"],
            "deploymentAudience": "production.us-east-1:primary",
            "deploymentIdentitySha256": "sha256:" + "a" * 64,
            "releaseSequence": 42,
            "rollbackEpoch": 7,
        }
        envelope = launch_authorization.sign_launch_authorization(
            request,
            private_key=key,
            authorization_id="2" * 64,
            issued_at_unix_seconds=issued_at,
            expires_at_unix_seconds=expires_at,
        )
        return {
            "request": request,
            "requestSha256": launch_authorization.launch_authorization_request_sha256(
                request
            ),
            "envelope": envelope,
            "authorizationSha256": "sha256:"
            + hashlib.sha256(
                launch_authorization.canonical_json_bytes(envelope)
            ).hexdigest(),
            "verifiedAtUnixSeconds": verified_at,
        }

    receipt["launchAuthorization"] = authorization_for(receipt)
    authority_public_spki = authority_spki(authority_key)
    authority_public_raw = authority_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    test_authority_identity = {
        "spki": authority_public_spki,
        "keyId": launch_authorization.spki_key_id(authority_public_spki),
        "rootSha256": "sha256:"
        + hashlib.sha256(authority_public_raw.hex().encode("ascii") + b"\n").hexdigest(),
    }
    original_key_loader = run_production_readiness.load_launch_authority_identity
    run_production_readiness.load_launch_authority_identity = (
        lambda: test_authority_identity
    )

    run_production_readiness.validate_bootstrap_receipt_launch_authorization(
        receipt,
        verify_signature=True,
        require_inputs=True,
        authority_identity=test_authority_identity,
    )
    import_paths = [
        str(value["path"]) for value in receipt["python"]["importRoots"]
    ]
    run_production_readiness._validate_receipt_python_layout(
        str(receipt["python"]["path"]), import_paths
    )
    layout_mutations = {
        "missing vendor": import_paths[:-1],
        "reordered stdlib and lib-dynload": [
            import_paths[0],
            import_paths[2],
            import_paths[1],
            import_paths[3],
        ],
        "lib-dynload outside stdlib": [
            import_paths[0],
            import_paths[1],
            f"{release_root}/runtime/python/lib/lib-dynload",
            import_paths[3],
        ],
        "vendor outside release root": [
            import_paths[0],
            import_paths[1],
            import_paths[2],
            f"{release_root}/runtime/vendor",
        ],
        "non-canonical stdlib version": [
            import_paths[0],
            f"{release_root}/runtime/python/lib/python3.011",
            f"{release_root}/runtime/python/lib/python3.011/lib-dynload",
            import_paths[3],
        ],
    }
    for label, paths in layout_mutations.items():
        try:
            run_production_readiness._validate_receipt_python_layout(
                str(receipt["python"]["path"]), paths
            )
        except ValueError:
            pass
        else:
            raise AssertionError(f"bootstrap receipt accepted {label}")
    try:
        run_production_readiness._validate_receipt_python_layout(
            f"{release_root}/bin/python3", import_paths
        )
    except ValueError:
        pass
    else:
        raise AssertionError("bootstrap receipt accepted Python outside the release runtime")
    positive_skew_receipt = json.loads(json.dumps(receipt))
    positive_skew_receipt["launchAuthorization"] = authorization_for(
        positive_skew_receipt,
        issued_at=105,
        expires_at=120,
        verified_at=100,
    )
    run_production_readiness.validate_bootstrap_receipt_launch_authorization(
        positive_skew_receipt,
        verify_signature=True,
        require_inputs=True,
        authority_identity=test_authority_identity,
    )

    authorization_mutations: list[tuple[str, dict[str, object]]] = []

    def mutate(label: str) -> dict[str, object]:
        value = json.loads(json.dumps(receipt))
        authorization_mutations.append((label, value))
        return value

    mutate("request digest mismatch")["launchAuthorization"]["requestSha256"] = (
        "sha256:" + "1" * 64
    )
    mutate("envelope digest mismatch")["launchAuthorization"][
        "authorizationSha256"
    ] = "sha256:" + "1" * 64
    mutate("signature mismatch")["launchAuthorization"]["envelope"]["signature"] = (
        "A" * 86
    )
    wrong_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("22" * 32))
    wrong_key_receipt = mutate("authority key mismatch")
    wrong_key_receipt["launchAuthorization"] = authorization_for(
        wrong_key_receipt,
        key=wrong_key,
    )
    mutate("nonce mismatch")["launchAuthorization"]["request"]["launcherNonce"] = (
        "9" * 64
    )
    mutate("manifest mismatch")["manifest"]["sha256"] = "sha256:" + "1" * 64
    mutate("provenance mismatch")["launchAuthorization"]["request"][
        "provenanceDigest"
    ] = "sha256:" + "1" * 64
    mutate("source mismatch")["sourceTreeDigest"] = "sha256:" + "1" * 64
    mutate("launcher mismatch")["launcher"]["sha256"] = "sha256:" + "1" * 64
    mutate("reproducibility mismatch")["inputs"]["reproducibleBuildVerification"][
        "sha256"
    ] = "sha256:" + "1" * 64
    mutate("sequence mismatch")["launchAuthorization"]["request"][
        "releaseSequence"
    ] = 43
    mutate("rollback mismatch")["launchAuthorization"]["request"][
        "rollbackEpoch"
    ] = 8
    mutate("verification time before issuance")["launchAuthorization"][
        "verifiedAtUnixSeconds"
    ] = 94
    mutate("verification time at expiry")["launchAuthorization"][
        "verifiedAtUnixSeconds"
    ] = 120
    for label, mutated in authorization_mutations:
        try:
            run_production_readiness.validate_bootstrap_receipt_launch_authorization(
                mutated,
                verify_signature=True,
                require_inputs=True,
                authority_identity=test_authority_identity,
            )
        except ValueError:
            pass
        else:
            raise AssertionError(f"bootstrap receipt accepted {label}")

    if not sys.platform.startswith("linux"):
        run_production_readiness.load_launch_authority_identity = original_key_loader
        return

    def open_receipt(data: bytes, *, seal: bool) -> int:
        descriptor = os.memfd_create("serverware-bootstrap-receipt-test", os.MFD_ALLOW_SEALING)
        os.write(descriptor, data)
        if seal:
            fcntl.fcntl(
                descriptor,
                1033,
                run_production_readiness.REQUIRED_BOOTSTRAP_RECEIPT_SEALS,
            )
        return descriptor

    canonical = canonical_json(receipt).encode("ascii")
    descriptor = open_receipt(canonical, seal=True)
    environment = {
        run_production_readiness.BOOTSTRAP_RECEIPT_FD_ENV: str(descriptor),
        run_production_readiness.BOOTSTRAP_RECEIPT_SHA256_ENV: (
            "sha256:" + hashlib.sha256(canonical).hexdigest()
        ),
        run_production_readiness.BOOTSTRAP_RECEIPT_API_VERSION_ENV: (
            run_production_readiness.BOOTSTRAP_RECEIPT_API_VERSION
        ),
    }
    try:
        summary, selected = run_production_readiness.load_sealed_bootstrap_receipt(
            environment,
            required=True,
        )
        if (
            selected != descriptor
            or summary is None
            or summary.get("sealed") is not True
            or summary.get("launchId") != receipt["launchId"]
        ):
            raise AssertionError(f"sealed bootstrap receipt summary is invalid: {summary}")
    finally:
        os.close(descriptor)

    unsealed = open_receipt(canonical, seal=False)
    try:
        try:
            run_production_readiness.load_sealed_bootstrap_receipt(
                {**environment, run_production_readiness.BOOTSTRAP_RECEIPT_FD_ENV: str(unsealed)},
                required=True,
            )
        except ValueError as exc:
            if "immutable seals" not in str(exc):
                raise
        else:
            raise AssertionError("bootstrap receipt validation accepted a writable memfd")
    finally:
        os.close(unsealed)

    mutations = []
    wrong_launcher_path = json.loads(json.dumps(receipt))
    wrong_launcher_path["launcher"]["path"] = "/opt/serverware/launchers/unbound/serverware-production-launcher"
    mutations.append(("non-content-addressed launcher", wrong_launcher_path))
    missing_input = json.loads(json.dumps(receipt))
    missing_input["inputs"].pop("bench")
    mutations.append(("open input set", missing_input))
    open_metadata = json.loads(json.dumps(receipt))
    open_metadata["manifest"]["metadata"]["unexpected"] = 1
    mutations.append(("open nested metadata", open_metadata))
    missing_import_root = json.loads(json.dumps(receipt))
    missing_import_root["python"]["importRoots"].pop()
    mutations.append(("missing Python import root", missing_import_root))
    reordered_import_roots = json.loads(json.dumps(receipt))
    reordered_import_roots["python"]["importRoots"][1:3] = reversed(
        reordered_import_roots["python"]["importRoots"][1:3]
    )
    mutations.append(("reordered Python import roots", reordered_import_roots))
    for label, mutated in mutations:
        mutated_bytes = canonical_json(mutated).encode("ascii")
        mutated_descriptor = open_receipt(mutated_bytes, seal=True)
        try:
            try:
                run_production_readiness.load_sealed_bootstrap_receipt(
                    {
                        **environment,
                        run_production_readiness.BOOTSTRAP_RECEIPT_FD_ENV: str(mutated_descriptor),
                        run_production_readiness.BOOTSTRAP_RECEIPT_SHA256_ENV: (
                            "sha256:" + hashlib.sha256(mutated_bytes).hexdigest()
                        ),
                    },
                    required=True,
                )
            except ValueError:
                pass
            else:
                raise AssertionError(f"bootstrap receipt accepted {label}")
        finally:
            os.close(mutated_descriptor)
    run_production_readiness.load_launch_authority_identity = original_key_loader


def main() -> None:
    verify_launcher_style_helper_import()
    for invalid_path in ("relative/path", "/", "/tmp/../etc/passwd", "/tmp//receipt", "/tmp/receipt/"):
        try:
            run_production_readiness._normalized_absolute_receipt_path(invalid_path, "test")
        except ValueError:
            pass
        else:
            raise AssertionError(f"bootstrap receipt accepted a non-normalized path: {invalid_path}")
    verify_sealed_bootstrap_receipt_contract()
    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw).resolve()
        expected_client_request_digest = "sha256:" + "a" * 64
        expected_request_digest = "sha256:" + "b" * 64
        expected_operation_digest = "sha256:" + "c" * 64
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
        policy_bundle_path = tmp / "policy-bundle.json"
        policy_bundle_path.write_text(
            canonical_json(proof_policy_bundle()) + "\n",
            encoding="utf-8",
        )
        trust_paths = {
            "release_provenance_trusted_public_key": tmp / "release-provenance.pub.pem",
            "sigstore_trusted_public_key": tmp / "sigstore.pub.pem",
            "rekor_trusted_public_key": tmp / "rekor.pub.pem",
            "external_checkpoint_trusted_public_key": tmp / "external-checkpoint.pub.pem",
            "control_plane_response_signing_public_key": (
                tmp / "response-online-signing.pub.pem"
            ),
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
            "--control-plane-response-signing-public-key",
            str(trust_paths["control_plane_response_signing_public_key"]),
            "--control-plane-response-signing-public-key-id",
            production_readiness_test.trusted_public_key_id(
                "response-online-signing.pub.pem"
            ),
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
                "SERVERWARE_PROXY_PROOF_PRINCIPAL_ID": "agent:production-proof",
                "SERVERWARE_PROXY_PROOF_MAX_AGE_SECONDS": "240",
                "SERVERWARE_COMPLETION_P99_LIMIT_MS": "20.0",
                "SERVERWARE_PROXY_EXPECTED_CLIENT_REQUEST_DIGEST": expected_client_request_digest,
                "SERVERWARE_PROXY_EXPECTED_REQUEST_DIGEST": expected_request_digest,
                "SERVERWARE_PROXY_EXPECTED_OPERATION_DIGEST": expected_operation_digest,
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
            or collector_argv[collector_argv.index("--expected-principal-id") + 1]
            != "agent:production-proof"
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
            or completion_argv[
                completion_argv.index("--control-plane-response-signing-public-key")
                + 1
            ]
            != str(trust_paths["control_plane_response_signing_public_key"])
            or completion_argv[
                completion_argv.index("--control-plane-response-signing-public-key-id")
                + 1
            ]
            != production_readiness_test.trusted_public_key_id(
                "response-online-signing.pub.pem"
            )
            or "--proxy-proof-verifier-public-key" not in completion_argv
            or "--proxy-collector-public-key" not in completion_argv
            or "--proxy-server-instance-id" not in completion_argv
            or "--proxy-client-nonce" not in completion_argv
            or "--proxy-client-request-digest" not in completion_argv
            or "--proxy-request-digest" not in completion_argv
            or "--proxy-operation-digest" not in completion_argv
            or "--proxy-tls-channel-binding" not in completion_argv
            or completion_argv[completion_argv.index("--proxy-proof-max-age-seconds") + 1] != "240"
            or collector_nonce != completion_nonce
            or len(collector_nonce) != 43
            or completion_argv[completion_argv.index("--proxy-request-digest") + 1]
            != expected_request_digest
            or completion_argv[
                completion_argv.index("--proxy-client-request-digest") + 1
            ]
            != expected_client_request_digest
            or completion_argv[completion_argv.index("--proxy-operation-digest") + 1]
            != expected_operation_digest
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

        collector_proof = tmp / "collector-proof.json"
        collector_proof.write_bytes(b'{"fixture":"proof"}\n')
        collector_summary_path = tmp / "collector-summary.json"
        collector_summary = {
            "ok": True,
            "client_nonce": "n" * 43,
            "client_request_digest": expected_client_request_digest,
            "request_digest": expected_request_digest,
            "operation_digest": expected_operation_digest,
            "tls_channel_binding": "t" * 43,
            "server_instance_id": "spiffe://prod/instance",
            "proof_path": str(collector_proof),
            "proof_sha256": run_production_readiness.sha256_prefixed_file(collector_proof),
        }
        collector_args = SimpleNamespace(
            proxy_client_nonce="n" * 43,
            proxy_client_request_digest=expected_client_request_digest,
            proxy_request_digest=expected_request_digest,
            proxy_operation_digest=expected_operation_digest,
            proxy_server_instance_id="spiffe://prod/instance",
            proxy_response_proof=str(collector_proof),
            proxy_proof_summary_out=str(collector_summary_path),
        )
        collector_command = {
            "label": "fixture-collector",
            "argv": [
                sys.executable,
                "-c",
                f"import json; print(json.dumps({collector_summary!r}))",
            ],
        }
        accepted_summary = run_production_readiness.run_collector(
            collector_command,
            collector_args,
            os.environ.copy(),
        )
        if accepted_summary != collector_summary or not collector_summary_path.is_file():
            raise AssertionError("runner rejected a collector summary matching every independent digest pin")

        mismatched_collector_summary = {
            **collector_summary,
            "operation_digest": "sha256:" + "d" * 64,
        }
        mismatched_collector_command = {
            "label": "fixture-mismatched-collector",
            "argv": [
                sys.executable,
                "-c",
                f"import json; print(json.dumps({mismatched_collector_summary!r}))",
            ],
        }
        mismatched_summary_path = tmp / "mismatched-collector-summary.json"
        collector_args.proxy_proof_summary_out = str(mismatched_summary_path)
        try:
            run_production_readiness.run_collector(
                mismatched_collector_command,
                collector_args,
                os.environ.copy(),
            )
        except ValueError as exc:
            if "does not match the independent expected pin" not in str(exc):
                raise
        else:
            raise AssertionError("runner accepted a collector-derived operation digest over the independent pin")
        if mismatched_summary_path.exists():
            raise AssertionError("runner persisted a collector summary after an expected digest mismatch")

        collector_derived_pin = run_runner(
            "--env-file",
            str(minimal_env),
            "--dry-run",
            "--proxy-request-digest",
            "$COLLECTOR_SUMMARY.request_digest",
            *security_args,
        )
        if (
            collector_derived_pin.returncode == 0
            or "must be sha256:<64 lowercase hex>" not in detail(collector_derived_pin)
        ):
            raise AssertionError(
                "runner accepted a collector-derived expected request digest: "
                + detail(collector_derived_pin)
            )

        missing_digest_pin_values = dict(minimal_values)
        missing_digest_pin_values.pop("SERVERWARE_PROXY_EXPECTED_OPERATION_DIGEST")
        missing_digest_pin_env = tmp / "missing-digest-pin.env"
        write_env(missing_digest_pin_env, missing_digest_pin_values)
        missing_digest_pin = run_runner(
            "--env-file",
            str(missing_digest_pin_env),
            "--dry-run",
            *security_args,
        )
        if (
            missing_digest_pin.returncode == 0
            or "SERVERWARE_PROXY_EXPECTED_OPERATION_DIGEST" not in detail(missing_digest_pin)
        ):
            raise AssertionError(
                "runner accepted a collection plan without an independent operation digest pin: "
                + detail(missing_digest_pin)
            )

        uppercase_digest_pin_env = tmp / "uppercase-digest-pin.env"
        write_env(
            uppercase_digest_pin_env,
            {
                **minimal_values,
                "SERVERWARE_PROXY_EXPECTED_REQUEST_DIGEST": "sha256:" + "A" * 64,
            },
        )
        uppercase_digest_pin = run_runner(
            "--env-file",
            str(uppercase_digest_pin_env),
            "--dry-run",
            *security_args,
        )
        if (
            uppercase_digest_pin.returncode == 0
            or "must be sha256:<64 lowercase hex>" not in detail(uppercase_digest_pin)
        ):
            raise AssertionError(
                "runner accepted a non-canonical uppercase request digest pin: "
                + detail(uppercase_digest_pin)
            )

        mismatched_identity_env = tmp / "mismatched-proof-identity.env"
        write_env(
            mismatched_identity_env,
            {
                **minimal_values,
                "SERVERWARE_PROXY_PROOF_PRINCIPAL_ID": "agent:different-proof-principal",
            },
        )
        mismatched_identity = run_runner(
            "--env-file",
            str(mismatched_identity_env),
            "--dry-run",
            *security_args,
        )
        if (
            mismatched_identity.returncode == 0
            or "do not map to the same unique principal" not in detail(mismatched_identity)
        ):
            raise AssertionError(
                "runner accepted mismatched proxy proof agent and principal IDs: "
                + detail(mismatched_identity)
            )

        unauthorized_proof_urls = {
            "scheme": "http://proof-target.prod.internal/health",
            "host": "https://different-proof-target.prod.internal/health",
            "port": "https://proof-target.prod.internal:444/health",
            "path": "https://proof-target.prod.internal/status",
        }
        for component, proof_url in unauthorized_proof_urls.items():
            unauthorized_env = tmp / f"unauthorized-proof-{component}.env"
            write_env(
                unauthorized_env,
                {
                    **minimal_values,
                    "SERVERWARE_PROXY_PROOF_URL": proof_url,
                },
            )
            unauthorized = run_runner(
                "--env-file",
                str(unauthorized_env),
                "--dry-run",
                *security_args,
            )
            if (
                unauthorized.returncode == 0
                or "is not authorized for the GET proof URL" not in detail(unauthorized)
            ):
                raise AssertionError(
                    f"runner accepted an unauthorized proof URL {component}: {detail(unauthorized)}"
                )

        post_only_policy_path = tmp / "post-only-proof-policy.json"
        post_only_policy_path.write_text(
            canonical_json(proof_policy_bundle(methods=["POST"])) + "\n",
            encoding="utf-8",
        )
        post_only_security_args = list(security_args)
        post_only_security_args[
            post_only_security_args.index("--policy-bundle") + 1
        ] = str(post_only_policy_path)
        post_only = run_runner(
            "--env-file",
            str(minimal_env),
            "--dry-run",
            *post_only_security_args,
        )
        if (
            post_only.returncode == 0
            or "is not authorized for the GET proof URL" not in detail(post_only)
        ):
            raise AssertionError(
                "runner accepted a proof route that does not authorize GET: "
                + detail(post_only)
            )

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
            "SERVERWARE_CONTROL_PLANE_RESPONSE_SIGNING_PUBLIC_KEY": str(
                trust_paths["control_plane_response_signing_public_key"]
            ),
            "SERVERWARE_CONTROL_PLANE_RESPONSE_SIGNING_PUBLIC_KEY_ID": (
                production_readiness_test.trusted_public_key_id(
                    "response-online-signing.pub.pem"
                )
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

        production_python = str(Path(sys.executable).resolve())
        executable_manifest = {
            setting: "sha256:" + "0" * 64
            for setting in run_production_readiness.PINNED_EXECUTABLE_COMMAND_SETTINGS
        }
        executable_manifest[run_production_readiness.PRODUCTION_PYTHON_EXECUTABLE_ENV] = (
            "sha256:" + hashlib.sha256(Path(production_python).read_bytes()).hexdigest()
        )
        executable_manifest[run_production_readiness.PRODUCTION_DOCKER_EXECUTABLE_ENV] = (
            executable_manifest[run_production_readiness.PRODUCTION_PYTHON_EXECUTABLE_ENV]
        )
        pinned_compose_plugin = tmp / "pinned-compose-plugin"
        pinned_compose_plugin.write_bytes(Path(production_python).read_bytes())
        pinned_compose_plugin.chmod(0o700)
        final_mode_trust_values = {
            **env_trust_values,
            "SERVERWARE_COMPLETION_VERIFICATION_MODE": "final",
            run_production_readiness.FINAL_LAUNCHER_CONTRACT_ENV: (
                run_production_readiness.FINAL_LAUNCHER_CONTRACT
            ),
            run_production_readiness.PRODUCTION_PYTHON_EXECUTABLE_ENV: production_python,
            run_production_readiness.PRODUCTION_DOCKER_EXECUTABLE_ENV: production_python,
            run_production_readiness.EXECUTABLE_DIGEST_MANIFEST_ENV: canonical_json(
                executable_manifest
            ),
            run_production_readiness.DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV: str(pinned_compose_plugin),
            run_production_readiness.DOCKER_COMPOSE_PLUGIN_SHA256_ENV: (
                "sha256:" + hashlib.sha256(pinned_compose_plugin.read_bytes()).hexdigest()
            ),
            run_production_readiness.DOCKER_UNIX_SOCKET_ENV: "/run/docker.sock",
            run_production_readiness.DOCKER_DAEMON_ID_ENV: "fixture-daemon-id",
            run_production_readiness.DOCKER_COMPOSE_PROJECT_NAME_ENV: (
                "serverware-production"
            ),
            run_production_readiness.POLICY_TRUST_ROOT_ENV: str(
                tmp / "policy-signing.pub.pem"
            ),
            run_production_readiness.POLICY_TRUST_ROOT_ID_ENV: (
                production_readiness_test.trusted_public_key_id(
                    "policy-signing.pub.pem"
                )
            ),
            run_production_readiness.POLICY_ACTIVATION_TRUST_ROOT_ENV: str(
                tmp / "policy-activation.pub.pem"
            ),
            run_production_readiness.POLICY_ACTIVATION_TRUST_ROOT_ID_ENV: (
                production_readiness_test.trusted_public_key_id(
                    "policy-activation.pub.pem"
                )
            ),
            run_production_readiness.REPRODUCIBLE_BUILD_TRUST_ROOT_ENV: str(
                tmp / "reproducible-build.pub.pem"
            ),
            run_production_readiness.REPRODUCIBLE_BUILD_TRUST_ROOT_ID_ENV: (
                production_readiness_test.trusted_public_key_id(
                    "reproducible-build.pub.pem"
                )
            ),
            run_production_readiness.PRODUCTION_HOST_PREFLIGHT_SCRIPT_SHA256_ENV: (
                "sha256:"
                + hashlib.sha256(
                    (ROOT / "scripts" / "production_host_preflight.py").read_bytes()
                ).hexdigest()
            ),
            run_production_readiness.VERIFY_PRODUCTION_READINESS_SCRIPT_SHA256_ENV: (
                "sha256:"
                + hashlib.sha256(
                    (ROOT / "scripts" / "verify_production_readiness.py").read_bytes()
                ).hexdigest()
            ),
            run_production_readiness.VERIFY_RELEASE_COMPLETION_SCRIPT_SHA256_ENV: (
                "sha256:"
                + hashlib.sha256(
                    (ROOT / "scripts" / "verify_release_completion.py").read_bytes()
                ).hexdigest()
            ),
            run_production_readiness.PRODUCTION_HOST_PREFLIGHT_SIGNING_PRIVATE_KEY_ENV: str(
                final_challenge_authority_key
            ),
            run_production_readiness.PRODUCTION_HOST_PREFLIGHT_SIGNING_PUBLIC_KEY_ENV: str(
                final_challenge_authority_key
            ),
            run_production_readiness.PRODUCTION_HOST_PREFLIGHT_SIGNING_KEY_ID_ENV: (
                production_readiness_test.trusted_public_key_id(
                    final_challenge_authority_key.name
                )
            ),
            run_production_readiness.PRODUCTION_HOST_PREFLIGHT_MAX_AGE_ENV: "300",
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
        alternate_policy_args = list(security_args)
        alternate_policy_args[
            alternate_policy_args.index("--policy-trusted-public-key") + 1
        ] = str(tmp / "caller-selected-policy.pub.pem")
        rejected_policy_path = run_runner(
            "--env-file",
            str(final_env_file),
            "--dry-run",
            "--verification-mode",
            "final",
            *alternate_policy_args,
        )
        if (
            rejected_policy_path.returncode == 0
            or run_production_readiness.POLICY_TRUST_ROOT_ENV
            not in detail(rejected_policy_path)
        ):
            raise AssertionError(
                "runner accepted a caller-selected final policy trust-root path: "
                + detail(rejected_policy_path)
            )
        rejected_policy_id = run_runner(
            "--env-file",
            str(final_env_file),
            "--dry-run",
            "--verification-mode",
            "final",
            "--policy-trusted-public-key-id",
            "sha256:" + "0" * 64,
            *security_args,
        )
        if (
            rejected_policy_id.returncode == 0
            or run_production_readiness.POLICY_TRUST_ROOT_ID_ENV
            not in detail(rejected_policy_id)
        ):
            raise AssertionError(
                "runner accepted a caller-selected final policy SPKI pin: "
                + detail(rejected_policy_id)
            )
        for injected_name in ("PYTHONPATH", "LD_PRELOAD", "DOCKER_CONTEXT", "COMPOSE_FILE"):
            injected_environment = {**os.environ, injected_name: "/tmp/attacker-selected-runtime"}
            injected = run_runner_in_environment(
                injected_environment,
                "--env-file",
                str(final_env_file),
                "--dry-run",
                "--verification-mode",
                "final",
                *security_args,
            )
            if injected.returncode == 0 or "forbidden runtime/loader injection" not in detail(injected):
                raise AssertionError(
                    f"runner accepted ambient final process injection {injected_name}: {detail(injected)}"
                )
        non_serverware_env = tmp / "non-serverware-final.env"
        write_env(non_serverware_env, {**final_env_values, "PYTHONHOME": "/tmp/attacker-python"})
        rejected_non_serverware = run_runner(
            "--env-file",
            str(non_serverware_env),
            "--dry-run",
            "--verification-mode",
            "final",
            *security_args,
        )
        if rejected_non_serverware.returncode == 0 or "non-SERVERWARE" not in detail(
            rejected_non_serverware
        ):
            raise AssertionError(
                "runner accepted a runtime injection setting from the hashed production env: "
                + detail(rejected_non_serverware)
            )
        missing_launcher_contract_env = tmp / "missing-launcher-contract.env"
        write_env(
            missing_launcher_contract_env,
            {
                key: value
                for key, value in final_env_values.items()
                if key != run_production_readiness.FINAL_LAUNCHER_CONTRACT_ENV
            },
        )
        rejected_missing_launcher_contract = run_runner(
            "--env-file",
            str(missing_launcher_contract_env),
            "--dry-run",
            "--verification-mode",
            "final",
            *security_args,
        )
        if (
            rejected_missing_launcher_contract.returncode == 0
            or run_production_readiness.FINAL_LAUNCHER_CONTRACT_ENV
            not in detail(rejected_missing_launcher_contract)
        ):
            raise AssertionError(
                "runner accepted final mode without the external startup contract declaration: "
                + detail(rejected_missing_launcher_contract)
            )
        wrong_script_env = tmp / "wrong-script-pin.env"
        write_env(
            wrong_script_env,
            {
                **final_env_values,
                run_production_readiness.VERIFY_RELEASE_COMPLETION_SCRIPT_SHA256_ENV: (
                    "sha256:" + "f" * 64
                ),
            },
        )
        rejected_wrong_script = run_runner(
            "--env-file",
            str(wrong_script_env),
            "--dry-run",
            "--verification-mode",
            "final",
            *security_args,
        )
        if rejected_wrong_script.returncode == 0 or "script pin" not in detail(rejected_wrong_script):
            raise AssertionError(
                f"runner accepted replaced verifier script bytes: {detail(rejected_wrong_script)}"
            )
        wrong_preflight_script_env = tmp / "wrong-preflight-script-pin.env"
        write_env(
            wrong_preflight_script_env,
            {
                **final_env_values,
                run_production_readiness.PRODUCTION_HOST_PREFLIGHT_SCRIPT_SHA256_ENV: (
                    "sha256:" + "d" * 64
                ),
            },
        )
        rejected_wrong_preflight_script = run_runner(
            "--env-file",
            str(wrong_preflight_script_env),
            "--dry-run",
            "--verification-mode",
            "final",
            *security_args,
        )
        if (
            rejected_wrong_preflight_script.returncode == 0
            or "script pin" not in detail(rejected_wrong_preflight_script)
        ):
            raise AssertionError(
                "runner accepted replaced production host preflight script bytes: "
                + detail(rejected_wrong_preflight_script)
            )
        wrong_plugin_env = tmp / "wrong-compose-pin.env"
        write_env(
            wrong_plugin_env,
            {
                **final_env_values,
                run_production_readiness.DOCKER_COMPOSE_PLUGIN_SHA256_ENV: (
                    "sha256:" + "e" * 64
                ),
            },
        )
        rejected_wrong_plugin = run_runner(
            "--env-file",
            str(wrong_plugin_env),
            "--dry-run",
            "--verification-mode",
            "final",
            *security_args,
        )
        if rejected_wrong_plugin.returncode == 0 or "executable pin" not in detail(rejected_wrong_plugin):
            raise AssertionError(
                f"runner accepted replaced Compose plugin bytes: {detail(rejected_wrong_plugin)}"
            )
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
            or final_argv[final_argv.index("--policy-trusted-public-key-id") + 1]
            != final_env_values[run_production_readiness.POLICY_TRUST_ROOT_ID_ENV]
            or final_argv[
                final_argv.index("--policy-activation-trusted-public-key-id") + 1
            ]
            != final_env_values[
                run_production_readiness.POLICY_ACTIVATION_TRUST_ROOT_ID_ENV
            ]
            or final_argv[
                final_argv.index("--reproducible-build-trusted-public-key-id") + 1
            ]
            != final_env_values[
                run_production_readiness.REPRODUCIBLE_BUILD_TRUST_ROOT_ID_ENV
            ]
        ):
            raise AssertionError(f"runner did not propagate env-pinned final inputs: {final_argv}")

        alternate_env_file = tmp / "alternate-final-authority.env"
        write_env(alternate_env_file, {**final_env_values, "SERVERWARE_RELEASE_CHANNEL": "alternate-prod"})
        alternate_self_consistent = run_runner(
            "--env-file",
            str(alternate_env_file),
            "--dry-run",
            "--verification-mode",
            "final",
            "--launcher-trusted-production-env-path",
            str(final_env_file),
            "--launcher-trusted-production-env-sha256",
            "sha256:" + hashlib.sha256(final_env_file.read_bytes()).hexdigest(),
            *security_args,
        )
        if (
            alternate_self_consistent.returncode == 0
            or "out-of-band launcher trust path" not in detail(alternate_self_consistent)
        ):
            raise AssertionError(
                "runner accepted an alternate self-consistent final env outside the launcher trust root: "
                + detail(alternate_self_consistent)
            )

        final_proxy_overrides = {
            "--python": str(tmp / "caller-python"),
            "--proxy-response-proof": str(tmp / "caller-proof.json"),
            "--proxy-proof-collector-command": str(tmp / "caller-collector"),
            "--proxy-address": "caller.proxy.internal:9443",
            "--proxy-proof-url": "https://caller-proof.internal/health",
            "--proxy-proof-ca": str(tmp / "caller-ca.pem"),
            "--proxy-collector-key": str(tmp / "caller-collector.key"),
            "--proxy-collector-public-key": str(tmp / "caller-collector.pub"),
            "--proxy-proof-verifier-public-key": str(tmp / "caller-verifier.pub"),
            "--proxy-server-instance-id": "spiffe://caller/instance",
            "--proxy-agent-id": "caller-agent",
            "--proxy-principal-id": "agent:caller",
            "--proxy-client-request-digest": "sha256:" + "d" * 64,
            "--proxy-request-digest": "sha256:" + "e" * 64,
            "--proxy-operation-digest": "sha256:" + "f" * 64,
            "--proxy-proof-max-age-seconds": "239",
            "--p99-limit-ms": "19.0",
            "--docker-executable": str(tmp / "caller-docker"),
            "--docker-compose-plugin-executable": str(tmp / "caller-compose"),
            "--docker-unix-socket": "/run/caller-docker.sock",
            "--docker-daemon-id": "caller-daemon",
        }
        for option, caller_value in final_proxy_overrides.items():
            substituted = run_runner(
                "--env-file",
                str(final_env_file),
                "--dry-run",
                "--verification-mode",
                "final",
                option,
                caller_value,
                *security_args,
            )
            if substituted.returncode == 0 or "must match" not in detail(substituted):
                raise AssertionError(
                    f"runner accepted caller-selected final setting {option}: {detail(substituted)}"
                )

        substituted_digest_pin = run_runner(
            "--env-file",
            str(final_env_file),
            "--dry-run",
            "--verification-mode",
            "final",
            "--proxy-operation-digest",
            "sha256:" + "d" * 64,
            *security_args,
        )
        if substituted_digest_pin.returncode == 0 or "must match SERVERWARE_PROXY_EXPECTED_OPERATION_DIGEST" not in detail(
            substituted_digest_pin
        ):
            raise AssertionError(
                "runner accepted a caller-substituted final operation digest pin: "
                + detail(substituted_digest_pin)
            )

        pinned_executable = tmp / "post-preflight-executable"
        pinned_executable.write_bytes(b"#!/bin/sh\nexit 0\n")
        pinned_executable.chmod(0o755)
        executable_pin = "sha256:" + hashlib.sha256(pinned_executable.read_bytes()).hexdigest()
        pin_map = {
            str(pinned_executable): (
                run_production_readiness.PROOF_COLLECTOR_COMMAND_SETTING,
                executable_pin,
            )
        }
        run_production_readiness.remeasure_command_before_use(
            [str(pinned_executable)],
            pin_map,
        )
        pinned_executable.write_bytes(b"#!/bin/sh\nexit 7\n")
        pinned_executable.chmod(0o755)
        try:
            run_production_readiness.remeasure_command_before_use(
                [str(pinned_executable)],
                pin_map,
            )
        except ValueError as exc:
            if "do not match" not in str(exc):
                raise
        else:
            raise AssertionError("runner accepted executable bytes replaced after preflight")

        measured_race = tmp / "measured-race"
        replacement = tmp / "measured-race-replacement"
        measured_race.write_bytes(b"#!/bin/sh\nprintf 'measured-bytes\\n'\n")
        replacement.write_bytes(b"#!/bin/sh\nprintf 'replacement-bytes\\n'\n")
        measured_race.chmod(0o700)
        replacement.chmod(0o700)
        measured_race_digest = "sha256:" + hashlib.sha256(measured_race.read_bytes()).hexdigest()

        def replace_after_open(_measured: run_production_readiness.MeasuredExecutable) -> None:
            os.replace(replacement, measured_race)

        if sys.platform.startswith("linux"):
            measured_execution = run_production_readiness.run_measured_command(
                [str(measured_race)],
                setting=run_production_readiness.PROOF_COLLECTOR_COMMAND_SETTING,
                expected_digest=measured_race_digest,
                after_open=replace_after_open,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                text=True,
            )
            if measured_execution.returncode != 0 or measured_execution.stdout != "measured-bytes\n":
                raise AssertionError(
                    "descriptor execution reopened replacement bytes after measurement: "
                    f"returncode={measured_execution.returncode} stdout={measured_execution.stdout!r} "
                    f"stderr={measured_execution.stderr!r}"
                )
            measured_script = tmp / "measured-script.py"
            replacement_script = tmp / "replacement-script.py"
            measured_script.write_text("print('measured-script-bytes')\n", encoding="ascii")
            replacement_script.write_text("print('replacement-script-bytes')\n", encoding="ascii")
            measured_script_digest = (
                "sha256:" + hashlib.sha256(measured_script.read_bytes()).hexdigest()
            )

            def replace_script_after_open(
                _measured: run_production_readiness.MeasuredScript,
            ) -> None:
                os.replace(replacement_script, measured_script)

            measured_script_execution = run_production_readiness.run_measured_python_script(
                [str(Path(sys.executable).resolve()), str(measured_script)],
                python_setting=run_production_readiness.PRODUCTION_PYTHON_EXECUTABLE_ENV,
                python_expected_digest=(
                    "sha256:"
                    + hashlib.sha256(Path(sys.executable).resolve().read_bytes()).hexdigest()
                ),
                script_setting=(
                    run_production_readiness.PRODUCTION_HOST_PREFLIGHT_SCRIPT_SHA256_ENV
                ),
                script_expected_digest=measured_script_digest,
                after_script_open=replace_script_after_open,
                cwd=ROOT,
                env=dict(run_production_readiness.FINAL_CHILD_FIXED_ENV),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                text=True,
            )
            if (
                measured_script_execution.returncode != 0
                or measured_script_execution.stdout != "measured-script-bytes\n"
            ):
                raise AssertionError(
                    "isolated Python reopened replacement script bytes after measurement: "
                    f"returncode={measured_script_execution.returncode} "
                    f"stdout={measured_script_execution.stdout!r} "
                    f"stderr={measured_script_execution.stderr!r}"
                )

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
            "--expected-control-plane-uid",
            str(os.getuid()),
            "--expected-control-plane-gid",
            str(os.getgid()),
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
