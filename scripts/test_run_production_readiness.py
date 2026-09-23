#!/usr/bin/env python3
from __future__ import annotations

import json
import base64
import fcntl
import hashlib
import os
import shlex
import subprocess
import sys
import tempfile
import time
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

FINAL_FIXTURE_IDENTITY_API_VERSION = "serverware.finalCompletionIdentity/v3"
FINAL_FIXTURE_PIPELINE = "manifest-v6-promoted-oci-nitro-eif"
FINAL_FIXTURE_BRIDGE_API_VERSION = (
    "serverware.productionReleaseCompletionBridge/v1"
)
FINAL_FIXTURE_ARTIFACT_BINDINGS_API_VERSION = (
    "serverware.manifestV6CompletionArtifactBindings/v1"
)
FINAL_FIXTURE_CANONICAL_PROFILE = (
    "serverware.canonicalJson/integer-string-bool-null-array-object-nfc-v1"
)


def test_temp_root() -> Path:
    root = ROOT / ".tmp"
    root.mkdir(mode=0o700, exist_ok=True)
    return root


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


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def write_env(path: Path, env: dict[str, str]) -> None:
    lines = []
    for key in sorted(env):
        lines.append(f"{key}={shlex.quote(str(env[key]))}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o600)


def run_runner(*args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "scripts/run_production_readiness.py", *args],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=clean_subprocess_env(),
        check=False,
    )


def run_runner_in_environment(
    environment: dict[str, str],
    *args: str,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "scripts/run_production_readiness.py", *args],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=environment,
    )


def detail(result: subprocess.CompletedProcess[bytes]) -> str:
    return result.stdout.decode("utf-8", errors="replace") + result.stderr.decode("utf-8", errors="replace")


def verify_readiness_observation_body_revalidation(
    tmp: Path,
    collector_args: SimpleNamespace,
    observation_body: Path,
) -> None:
    collected_digest = collector_args.collected_proxy_observation_body_sha256
    collected_bytes = collector_args.collected_proxy_observation_body_bytes
    if collected_digest is None or collected_bytes != 4:
        raise AssertionError("observation collector fixture did not retain its body measurement")

    original_bootstrap_validator = (
        run_production_readiness.validate_bootstrap_receipt_summary
    )
    original_bootstrap_identity = (
        run_production_readiness.bootstrap_launch_authorization_identity
    )
    run_production_readiness.validate_bootstrap_receipt_summary = lambda _value: None
    run_production_readiness.bootstrap_launch_authorization_identity = (
        lambda _value: "fixture-launch-authorization"
    )
    try:
        for label, mutated_body, expected_error in (
            (
                "changed",
                b"same",
                "artifact proxy_observation_body digest does not match current bytes",
            ),
            (
                "oversized",
                b"body!",
                "must contain between 0 and 4 bytes",
            ),
        ):
            proof_path = tmp / f"readiness-observation-{label}-completion.json"
            generation = hashlib.sha256(label.encode("ascii")).hexdigest()[:32]
            digest_path = run_production_readiness.completion_proof_digest_path(
                proof_path, generation
            )
            generated_at = int(time.time())
            manual_nonce_assurance = {
                "apiVersion": (
                    run_production_readiness.NONCE_ROLLBACK_ASSURANCE_BINDING_API_VERSION
                ),
                "enforcement": "not-native-launcher-enforced",
                "verified": False,
            }
            proof = {
                "apiVersion": "serverware.completionProof/v6",
                "kind": "ServerwarePreEnclaveReadiness",
                "verificationOk": True,
                "finalCompletionVerified": False,
                "actionAuthorization": None,
                "okForAction": False,
                "verification_passed": True,
                "verification_mode": "readiness",
                "result_scope": "readiness-only",
                "readiness_only": True,
                "readiness_ok": True,
                "completion_status": "pre-enclave-readiness",
                "release_completion": "not-final",
                "hardware_proof": False,
                "assurance_ceiling": {
                    "level": "pre-enclave-readiness",
                    "final_completion": False,
                    "hardware_proof": False,
                    "hardware_evidence_verified": False,
                    "reason": (
                        "trusted-host readiness does not prove final enclave "
                        "execution"
                    ),
                    "required_final_evidence": [
                        "independent Manifest-v6 public Nitro verification"
                    ],
                },
                "generated_at_unix": generated_at,
                "artifacts": {
                    "proxy_observation_body": {
                        "path": str(observation_body),
                        "sha256": collected_digest,
                    }
                },
                "production_readiness": {},
                "production_readiness_config": {},
                "current_completion_host": {},
                "production_env_binding": {},
                "running_production_containers": {},
                "production_host_preflight": {
                    "verification_mode": "readiness",
                    "readiness_only": True,
                    "final_nitro_execution_proven": False,
                    "ok_for_action": False,
                    "authority_boundary": {
                        "apiVersion": (
                            "serverware.productionHostReadinessBoundary/v1"
                        ),
                        "verificationMode": "readiness",
                        "launchManifestApiVersion": (
                            "serverware.productionReadinessLaunch/v3"
                        ),
                        "launchAuthorizationRequestApiVersion": (
                            "serverware.launchAuthorizationRequest/v2"
                        ),
                        "launchAuthorizationApiVersion": (
                            "serverware.launchAuthorization/v2"
                        ),
                        "bootstrapReceiptApiVersion": (
                            "serverware.bootstrapReceipt/v3"
                        ),
                        "authorizationScope": "trusted-host-readiness",
                        "freshnessAuthority": "trusted-host-wall-clock",
                        "launcherEvidenceVerified": False,
                        "currentFreshnessVerifiedUsingTrustedHostWallClock": (
                            False
                        ),
                        "secureTimeProven": False,
                        "finalNitroExecutionProven": False,
                        "actionAuthority": False,
                        "hostBootstrapEvidenceClassification": (
                            "non-authoritative-readiness-context-only"
                        ),
                        "finalAuthority": (
                            "independent-manifest-v6-public-nitro-verifier-and-"
                            "protected-state"
                        ),
                    },
                    "nonce_rollback_assurance": manual_nonce_assurance
                },
                "bootstrap_launcher": {"required": False, "verified": False},
                "nonce_rollback_assurance": {
                    **manual_nonce_assurance,
                    "launchManifest": {
                        "apiVersion": "serverware.productionReadinessLaunch/v3",
                        "purpose": "readiness-only",
                        "verified": False,
                    },
                    "purpose": "readiness-only",
                },
                "nitro_kms_evidence": {},
                "nitro_evidence_binding": {},
                "hardware_assurance_evidence": {},
                "final_challenge_consumption": {
                    "required": False,
                    "consumed": False,
                },
                "production_images_build": {},
                "production_images_published": {},
                "release_provenance": {},
                "image_signatures": {},
                "benchmark": {},
                "release_security_evidence": {},
                "production_proxy_response_proof": {},
                "production_continuity": {
                    "required": False,
                    "verified": False,
                    "pipeline": "readiness-only",
                },
                "proof_core_sha256": "sha256:" + "0" * 64,
                "independently_authenticated": False,
                "aggregate_authentication": {
                    "required": False,
                    "independently_authenticated": False,
                    "scope": "readiness-only",
                },
                "proof_path": str(proof_path),
                "integrity_metadata": {
                    "generation": generation,
                    "detached_sha256_path": str(digest_path),
                    "scope": "checksum-only",
                    "independently_authenticated": False,
                    "authenticity_requires_external_signature_or_checkpoint": True,
                },
            }
            proof["proof_core_sha256"] = _fixture_json_digest(
                run_production_readiness.completion_proof_v6_core(proof)
            )
            run_production_readiness.write_private_json(proof_path, proof)
            digest_path.write_text(
                run_production_readiness.sha256_prefixed_file(proof_path) + "\n",
                encoding="ascii",
            )
            digest_path.chmod(0o600)
            noncanonical_path = (
                tmp / f"readiness-observation-{label}-pretty.json"
            )
            noncanonical_generation = hashlib.sha256(
                f"{label}-pretty".encode("ascii")
            ).hexdigest()[:32]
            noncanonical_digest_path = (
                run_production_readiness.completion_proof_digest_path(
                    noncanonical_path,
                    noncanonical_generation,
                )
            )
            noncanonical_proof = json.loads(json.dumps(proof))
            noncanonical_proof["proof_path"] = str(noncanonical_path)
            noncanonical_proof["integrity_metadata"] = {
                **noncanonical_proof["integrity_metadata"],
                "generation": noncanonical_generation,
                "detached_sha256_path": str(noncanonical_digest_path),
            }
            noncanonical_path.write_bytes(
                (
                    json.dumps(
                        noncanonical_proof,
                        indent=2,
                        sort_keys=True,
                        ensure_ascii=True,
                    )
                    + "\n"
                ).encode("utf-8")
            )
            noncanonical_digest_path.write_text(
                run_production_readiness.sha256_prefixed_file(
                    noncanonical_path
                )
                + "\n",
                encoding="ascii",
            )
            noncanonical_digest_path.chmod(0o600)
            try:
                run_production_readiness.verify_completion_output(
                    noncanonical_path
                )
            except ValueError as exc:
                if "exact canonical JSON bytes plus LF" not in str(exc):
                    raise
            else:
                raise AssertionError(
                    "readiness consumer accepted pretty-printed proof bytes"
                )
            if label == "changed":
                boundary_proof = json.loads(json.dumps(proof))
                boundary_proof_path = (
                    tmp / "readiness-observation-authority-boundary.json"
                )
                boundary_generation = hashlib.sha256(
                    b"authority-boundary"
                ).hexdigest()[:32]
                boundary_digest_path = (
                    run_production_readiness.completion_proof_digest_path(
                        boundary_proof_path, boundary_generation
                    )
                )
                boundary_proof["proof_path"] = str(boundary_proof_path)
                boundary_proof["integrity_metadata"] = {
                    **boundary_proof["integrity_metadata"],
                    "generation": boundary_generation,
                    "detached_sha256_path": str(boundary_digest_path),
                }
                boundary_proof["production_host_preflight"][
                    "authority_boundary"
                ]["actionAuthority"] = True
                boundary_proof["proof_core_sha256"] = _fixture_json_digest(
                    run_production_readiness.completion_proof_v6_core(
                        boundary_proof
                    )
                )
                run_production_readiness.write_private_json(
                    boundary_proof_path, boundary_proof
                )
                boundary_digest_path.write_text(
                    run_production_readiness.sha256_prefixed_file(
                        boundary_proof_path
                    )
                    + "\n",
                    encoding="ascii",
                )
                boundary_digest_path.chmod(0o600)
                collector_args.runner_started_at_unix = generated_at
                collector_args.pre_run_completion_proof_state = {
                    "exists": False
                }
                try:
                    run_production_readiness.verify_completion_output(
                        boundary_proof_path, collector_args
                    )
                except ValueError as exc:
                    if "readiness-only authority boundary" not in str(exc):
                        raise
                else:
                    raise AssertionError(
                        "readiness verification accepted host preflight "
                        "action authority"
                    )
            observation_body.write_bytes(mutated_body)
            collector_args.runner_started_at_unix = generated_at
            collector_args.pre_run_completion_proof_state = {"exists": False}
            try:
                run_production_readiness.verify_completion_output(
                    proof_path, collector_args
                )
            except ValueError as exc:
                if expected_error not in str(exc):
                    raise
            else:
                raise AssertionError(
                    f"readiness verification accepted an observation body {label} after collection"
                )
            if label == "changed" and (
                observation_body.stat().st_size != collected_bytes
                or run_production_readiness.sha256_prefixed_file(observation_body)
                == collected_digest
                or collector_args.collected_proxy_observation_body_sha256
                != collected_digest
            ):
                raise AssertionError(
                    "same-length observation mutation did not exercise fresh digest revalidation"
                )
            if label == "oversized" and (
                observation_body.stat().st_size <= collected_bytes
                or collector_args.proxy_max_observation_body_bytes
                != collected_bytes
                or collector_args.collected_proxy_observation_body_bytes
                != collected_bytes
            ):
                raise AssertionError(
                    "oversized observation mutation did not exercise fresh byte-count revalidation"
                )
    finally:
        run_production_readiness.validate_bootstrap_receipt_summary = (
            original_bootstrap_validator
        )
        run_production_readiness.bootstrap_launch_authorization_identity = (
            original_bootstrap_identity
        )
        observation_body.write_bytes(b"body")


def _fixture_digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def _fixture_sha384(label: str) -> str:
    return "sha384:" + hashlib.sha384(label.encode("utf-8")).hexdigest()


def _fixture_json_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(
        canonical_json(value).encode("utf-8")
    ).hexdigest()


def _fixture_merkle_leaf_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(
        b"\x00" + canonical_json(value).encode("utf-8")
    ).hexdigest()


def _completion_bound_fixture(
    artifact: dict[str, object],
    *,
    identity: dict[str, object],
    identity_sha256: str,
    label: str,
) -> dict[str, object]:
    binding: dict[str, object] = {
        "artifact": artifact,
        "completionIdentity": identity,
        "completionIdentitySha256": identity_sha256,
        "label": label,
    }
    return {**binding, "bindingSha256": _fixture_json_digest(binding)}


def _obsolete_release_completion_result_v1_fixture() -> dict[str, object]:
    raise AssertionError(
        "obsolete final-shaped completionProof/v6 fixture is unreachable"
    )
    core_names = (
        "builderA",
        "builderB",
        "continuity",
        "custody",
        "eif",
        "hardware",
        "promotion",
        "release",
        "response",
        "runtime",
        "source",
        "trust",
        "witness",
    )
    identity: dict[str, object] = {
        "apiVersion": FINAL_FIXTURE_IDENTITY_API_VERSION,
        "challengeNonceSha256": _fixture_digest("challenge"),
        "coreDigests": {
            name: _fixture_digest(f"core-{name}") for name in core_names
        },
        "pipeline": FINAL_FIXTURE_PIPELINE,
        "releaseGeneration": 9,
        "rollbackEpoch": 3,
    }
    identity_sha256 = _fixture_json_digest(identity)
    pcrs = {
        "PCR0": _fixture_sha384("eif"),
        "PCR1": _fixture_sha384("pcr1"),
        "PCR2": _fixture_sha384("pcr2"),
    }
    trust_roles = (
        "sourceGitInventory",
        "sourceUntrackedApproval",
        "buildWatchdog",
        "promotion",
        "builderA",
        "builderB",
        "manifestV6EifBuilder",
        "completion",
        "completionCheckpoint",
        "witness",
        "kmsAudit",
        "clientState",
        "clientStateCheckpoint",
        "stateCommit",
        "currentHeadAuthorization",
        "currentHeadRedemption",
    )
    trust_key_ids = {
        role: _fixture_digest(f"trust-role-{role}") for role in trust_roles
    }
    promotion_canonical_payload = {
        "apiVersion": "serverware.verificationPromotionAcceptance/v2",
        "candidatePromotionContractSha256": _fixture_digest(
            "candidate-promotion-contract"
        ),
    }
    promotion_acceptance_sha256 = _fixture_json_digest(
        promotion_canonical_payload
    )
    builder_artifact = {
        "statementFileSha256": _fixture_digest("builder-statement-file"),
        "statementPayloadSha256": _fixture_digest(
            "builder-statement-payload"
        ),
        "transcriptFileSha256": _fixture_digest("builder-transcript-file"),
        "transcriptPayloadSha256": _fixture_digest(
            "builder-transcript-payload"
        ),
    }
    artifact_bindings_payload: dict[str, object] = {
        "apiVersion": (
            FINAL_FIXTURE_ARTIFACT_BINDINGS_API_VERSION
        ),
        "builders": {
            "left": _completion_bound_fixture(
                dict(builder_artifact),
                identity=identity,
                identity_sha256=identity_sha256,
                label="left-raw-builder-statement-and-transcript",
            ),
            "right": _completion_bound_fixture(
                {
                    key: _fixture_digest(f"right-{key}")
                    for key in builder_artifact
                },
                identity=identity,
                identity_sha256=identity_sha256,
                label="right-raw-builder-statement-and-transcript",
            ),
        },
        "candidateManifestAndSource": _completion_bound_fixture(
            {
                "candidateManifestFileSha256": _fixture_digest(
                    "candidate-file"
                ),
                "candidateManifestPayloadSha256": _fixture_digest(
                    "candidate-payload"
                ),
                "sourceClosureSha256": _fixture_digest("source-closure"),
                "sourceInputManifestFileSha256": _fixture_digest(
                    "source-input-file"
                ),
                "sourceInputManifestPayloadSha256": _fixture_digest(
                    "source-input-payload"
                ),
                "watchdogReceiptFileSha256": _fixture_digest(
                    "watchdog-file"
                ),
                "watchdogReceiptPayloadSha256": _fixture_digest(
                    "watchdog-payload"
                ),
            },
            identity=identity,
            identity_sha256=identity_sha256,
            label="candidate-manifest-source-and-watchdog",
        ),
        "completionIdentity": identity,
        "completionIdentitySha256": identity_sha256,
        "completionProof": _completion_bound_fixture(
            {
                "authenticationPayloadSha256": _fixture_digest(
                    "completion-authentication-payload"
                ),
                "fileSha256": _fixture_digest("completion-proof-file"),
                "proofCoreSha256": _fixture_digest("completion-proof-core"),
                "publicVerifierBridgeSha256": _fixture_digest(
                    "completion-public-bridge"
                ),
            },
            identity=identity,
            identity_sha256=identity_sha256,
            label="completion-proof-v6",
        ),
        "eifMapping": _completion_bound_fixture(
            {
                "candidateToEifBuildStatementFileSha256": _fixture_digest(
                    "candidate-eif-file"
                ),
                "candidateToEifBuildStatementPayloadSha256": _fixture_digest(
                    "candidate-eif-payload"
                ),
                "candidateToEifBuilderKeyId": trust_key_ids[
                    "manifestV6EifBuilder"
                ],
                "eifSha384": pcrs["PCR0"],
                "pcrs": pcrs,
            },
            identity=identity,
            identity_sha256=identity_sha256,
            label="candidate-promotion-to-eif-mapping",
        ),
        "productionIdentity": _completion_bound_fixture(
            {
                "productionIdentityFileSha256": _fixture_digest(
                    "production-identity-file"
                ),
                "productionReleaseIdentitySha256": _fixture_digest(
                    "production-release-identity"
                ),
                "runtimeCustodyFileSha256": _fixture_digest(
                    "runtime-custody-file"
                ),
                "runtimeStateFileSha256": _fixture_digest(
                    "runtime-state-file"
                ),
            },
            identity=identity,
            identity_sha256=identity_sha256,
            label="production-identity-runtime-and-custody",
        ),
        "promotion": _completion_bound_fixture(
            {
                "importedImageMappingsSha256": _fixture_digest(
                    "imported-image-mappings"
                ),
                "promotedManifestFileSha256": _fixture_digest(
                    "promoted-manifest-file"
                ),
                "promotedManifestPayloadSha256": _fixture_digest(
                    "promoted-manifest-payload"
                ),
                "promotionAcceptanceSha256": promotion_acceptance_sha256,
                "promotionReceiptFileSha256": _fixture_digest(
                    "promotion-receipt-file"
                ),
                "promotionReceiptPayloadSha256": _fixture_digest(
                    "promotion-receipt-payload"
                ),
            },
            identity=identity,
            identity_sha256=identity_sha256,
            label="promotion-receipt-and-imported-image-mappings",
        ),
    }
    artifact_bindings: dict[str, object] = {
        **artifact_bindings_payload,
        "artifactBindingsSha256": _fixture_json_digest(
            artifact_bindings_payload
        ),
    }
    challenge_consumption = {
        "challengeNonceSha256": identity["challengeNonceSha256"],
        "consumedAtUnix": 100,
        "consumptionId": "fixture-challenge-consumption",
        "expiresAtUnix": 200,
        "oneUse": True,
        "status": "consumed",
    }
    witness_leaf_sha256 = _fixture_merkle_leaf_digest(
        {
            "releaseGeneration": 9,
            "releaseCoreSha256": identity["coreDigests"]["release"],
            "rollbackEpoch": 3,
        }
    )
    next_state_payload: dict[str, object] = {
        "apiVersion": "serverware.monotonicReleaseWitnessState/v2",
        "challengeConsumptionSha256": _fixture_json_digest(
            challenge_consumption
        ),
        "checkpointSha256": _fixture_digest("witness-checkpoint"),
        "logId": _fixture_digest("witness-log"),
        "provider": "fixture-witness-provider",
        "releaseGeneration": 9,
        "rollbackEpoch": 3,
        "rootHash": witness_leaf_sha256,
        "sequence": 1,
        "treeSize": 1,
        "witnessKeyId": trust_key_ids["witness"],
    }
    next_client_state: dict[str, object] = {
        **next_state_payload,
        "stateSha256": _fixture_json_digest(next_state_payload),
    }
    state_transition_payload = {
        "oldStateSha256": _fixture_digest("prior-state"),
        "newStateSha256": next_client_state["stateSha256"],
    }
    state_transition = {
        **state_transition_payload,
        "transitionSha256": _fixture_json_digest(state_transition_payload),
    }
    state_commit_receipt_identity = {
        "apiVersion": (
            "serverware.publicNitroStateCommitReceiptIdentity/v1"
        ),
        "commitId": "fixture-commit",
        "receiptFileSha256": _fixture_digest("state-commit-file"),
        "receiptPayloadSha256": _fixture_digest("state-commit-payload"),
        "signingKeyId": trust_key_ids["stateCommit"],
        "storeId": "fixture-store",
    }
    pre_authorization_core = {
        "apiVersion": (
            "serverware.publicNitroPreAuthorizationResultCore/v1"
        ),
        "canonicalProfile": (
            FINAL_FIXTURE_CANONICAL_PROFILE
        ),
        "challengeConsumptionSha256": next_client_state[
            "challengeConsumptionSha256"
        ],
        "challengeNonceSha256": identity["challengeNonceSha256"],
        "completionIdentitySha256": identity_sha256,
        "completionProofFileSha256": _fixture_digest(
            "completion-proof-file"
        ),
        "newStateSha256": next_client_state["stateSha256"],
        "oldStateSha256": state_transition["oldStateSha256"],
        "pendingResultSha256": _fixture_digest("pending-result"),
        "pipeline": FINAL_FIXTURE_PIPELINE,
        "requestSha256": _fixture_digest("request"),
        "responseBytesSha256": _fixture_digest("response-bytes"),
        "transitionSha256": state_transition["transitionSha256"],
    }
    current_head = {
        "apiVersion": "serverware.publicNitroStateStoreHead/v2",
        "challengeConsumptionSha256": next_client_state[
            "challengeConsumptionSha256"
        ],
        "commitId": "fixture-commit",
        "generation": 4,
        "redemptionSequence": 1,
        "stateCommitReceiptSha256": state_commit_receipt_identity[
            "receiptFileSha256"
        ],
        "stateSha256": next_client_state["stateSha256"],
        "storeId": "fixture-store",
    }
    current_head_sha256 = _fixture_json_digest(current_head)
    reservation_identity = {
        "apiVersion": (
            "serverware.publicNitroCurrentHeadReservationIdentity/v1"
        ),
        "authorizationId": "fixture-authorization",
        "challengeConsumptionSha256": next_client_state[
            "challengeConsumptionSha256"
        ],
        "completionResultSha256": _fixture_digest(
            "completion-result-before-redemption"
        ),
        "currentRedemptionSequence": 1,
        "expectedFinalGeneration": 5,
        "expectedOneUseSequence": 2,
        "expiresAtUnix": 200,
        "generation": 4,
        "headSha256": current_head_sha256,
        "oneUse": True,
        "receiptIdentitySha256": _fixture_json_digest(
            state_commit_receipt_identity
        ),
        "reservationId": "fixture-reservation",
        "status": "reserved",
        "storeId": "fixture-store",
        "verifierNonceConsumptionSha256": _fixture_digest(
            "authorization-nonce-consumption"
        ),
    }
    reservation_identity_sha256 = _fixture_json_digest(
        reservation_identity
    )
    authorization_identity = {
        "apiVersion": (
            "serverware.publicNitroCurrentHeadAuthorizationIdentity/v1"
        ),
        "authorizationFileSha256": _fixture_digest("authorization-file"),
        "authorizationId": "fixture-authorization",
        "authorizationPayloadSha256": _fixture_digest(
            "authorization-payload"
        ),
        "currentHeadSha256": current_head_sha256,
        "reservationIdentitySha256": reservation_identity_sha256,
        "signingKeyId": trust_key_ids["currentHeadAuthorization"],
        "storeId": "fixture-store",
    }
    current_final_head = {
        "apiVersion": "serverware.publicNitroStateStoreFinalHead/v1",
        "authorizationId": "fixture-authorization",
        "challengeConsumptionSha256": next_client_state[
            "challengeConsumptionSha256"
        ],
        "commitId": "fixture-commit",
        "completionResultSha256": reservation_identity[
            "completionResultSha256"
        ],
        "generation": 5,
        "previousHeadSha256": current_head_sha256,
        "redemptionId": "fixture-redemption",
        "redemptionSequence": 2,
        "redemptionVerifierNonceSha256": _fixture_digest(
            "redemption-verifier-nonce"
        ),
        "reservationId": "fixture-reservation",
        "stateCommitReceiptSha256": state_commit_receipt_identity[
            "receiptFileSha256"
        ],
        "stateSha256": next_client_state["stateSha256"],
        "storeId": "fixture-store",
    }
    current_final_head_sha256 = _fixture_json_digest(current_final_head)
    redemption_identity = {
        "apiVersion": (
            "serverware.publicNitroCurrentHeadRedemptionReceiptIdentity/v1"
        ),
        "oneUseSequence": 2,
        "redemptionFileSha256": _fixture_digest("redemption-file"),
        "redemptionId": "fixture-redemption",
        "redemptionPayloadSha256": _fixture_digest("redemption-payload"),
        "signingKeyId": trust_key_ids["currentHeadRedemption"],
        "storeId": "fixture-store",
    }
    release_identity = {
        "apiVersion": "serverware.releaseIdentity/v1",
        "build": {
            "builderCoreSha256s": sorted(
                [
                    _fixture_digest("builder-a-core"),
                    _fixture_digest("builder-b-core"),
                ]
            ),
            "buildWatchdogReceiptSha256": _fixture_digest(
                "build-watchdog"
            ),
            "candidateManifestFileSha256": _fixture_digest(
                "candidate-file"
            ),
            "candidateManifestPayloadSha256": _fixture_digest(
                "candidate-payload"
            ),
            "dependencyClosureSha256": _fixture_digest(
                "dependency-closure"
            ),
            "eifBuildCoreSha256": _fixture_digest("eif-build-core"),
            "importedImageMappingsSha256": _fixture_digest(
                "imported-image-mappings"
            ),
            "promotedManifestSha256": _fixture_digest(
                "promoted-manifest"
            ),
            "promotionReceiptSha256": _fixture_digest(
                "promotion-receipt"
            ),
            "releaseCoreSha256": identity["coreDigests"]["release"],
        },
        "configuration": {
            "caSpkiSha256": _fixture_digest("ca-spki"),
            "publicAttestation": {
                field: _fixture_digest(field)
                for field in (
                    "nonceStoreIdentitySha256",
                    "nonceStoreKeySpkiSha256",
                    "producerDescriptorSha256",
                    "producerExecutableSha256",
                    "producerRequestSchemaSha256",
                    "sandboxDescriptorSha256",
                    "sandboxLauncherSha256",
                    "witnessStoreIdentitySha256",
                    "witnessStoreKeySpkiSha256",
                )
            },
            "releaseKeySpkiSha256": _fixture_digest("release-key"),
            "responseKeySpkiSha256": _fixture_digest("response-key"),
            "tlsScopeSigningKeySpkiSha256": _fixture_digest(
                "tls-scope-key"
            ),
            "trustRootBundleSha256": _fixture_digest("trust-root-bundle"),
            "witnessKeySpkiSha256": trust_key_ids["witness"],
        },
        "eif": {"imageSha384": pcrs["PCR0"], "pcrs": pcrs},
        "monotonicRelease": {
            "releaseGeneration": 9,
            "rollbackEpoch": 3,
        },
        "pipeline": FINAL_FIXTURE_PIPELINE,
        "policy": {
            "hash": _fixture_digest("policy"),
            "sequence": 7,
        },
        "source": {
            "sourceClosureSha256": _fixture_digest("source-closure"),
            "sourceInputApprovalSha256": _fixture_digest(
                "source-input-approval"
            ),
            "sourceInputManifestFileSha256": _fixture_digest(
                "source-input-file"
            ),
            "sourceInputManifestPayloadSha256": _fixture_digest(
                "source-input-payload"
            ),
        },
    }
    inclusion = {
        "leafIndex": 0,
        "leafSha256": witness_leaf_sha256,
        "proof": [],
        "rootHash": next_client_state["rootHash"],
        "treeSize": next_client_state["treeSize"],
    }
    witness_core_payload = {
        "challengeConsumption": challenge_consumption,
        "consistencyProof": [],
        "expiresAtUnix": 200,
        "inclusion": inclusion,
        "issuedAtUnix": 100,
        "logId": next_client_state["logId"],
        "priorStateSha256": state_transition["oldStateSha256"],
        "provider": next_client_state["provider"],
        "releaseGeneration": 9,
        "releaseCoreSha256": identity["coreDigests"]["release"],
        "revocation": {
            "asOfUnix": 100,
            "completionIdentity": identity,
            "completionIdentitySha256": identity_sha256,
            "releaseCoreSha256": identity["coreDigests"]["release"],
            "revocationListSha256": _fixture_json_digest([]),
            "revokedIdentities": [],
            "status": "active",
        },
        "rollbackEpoch": 3,
        "sequence": next_client_state["sequence"],
        "treeSize": next_client_state["treeSize"],
        "rootHash": next_client_state["rootHash"],
    }
    witness_core = {
        "apiVersion": "serverware.completionWitnessCore/v1",
        "pipeline": FINAL_FIXTURE_PIPELINE,
        "payload": witness_core_payload,
    }
    witness = {
        "checkpointSha256": next_client_state["checkpointSha256"],
        "completionIdentity": identity,
        "completionIdentitySha256": identity_sha256,
        "core": witness_core,
        "coreSha256": _fixture_json_digest(witness_core),
        "productionReleaseIdentitySha256": _fixture_digest(
            "production-release-identity"
        ),
        "releaseGeneration": 9,
        "rollbackEpoch": 3,
        "sequence": next_client_state["sequence"],
        "treeSize": next_client_state["treeSize"],
        "rootHash": next_client_state["rootHash"],
        "leafIndex": inclusion["leafIndex"],
        "consumptionId": challenge_consumption["consumptionId"],
        "challengeConsumptionSha256": next_client_state[
            "challengeConsumptionSha256"
        ],
        "revocationChecked": True,
    }
    kms_audit_proofs = {
        name: _fixture_digest(f"kms-{name}")
        for name in (
            "broker-kek",
            "ca",
            "credentials",
            "release",
            "response",
            "tls",
        )
    }
    final_rollback_boundary = (
        "this is durable historical evidence, never a reusable action "
        "capability; an action gate must atomically re-check this exact "
        "final head as live and consume the redemption receipt identity "
        "once while performing the action"
    )
    public_result = {
        "okForAction": False,
        "status": "redemption-verified-non-actionable",
        "apiVersion": "serverware.publicNitroVerificationResult/v2",
        "pipeline": FINAL_FIXTURE_PIPELINE,
        "productionIdentitySha256": _fixture_digest(
            "production-identity-file"
        ),
        "candidateManifestFileSha256": _fixture_digest("candidate-file"),
        "sourceClosureSha256": _fixture_digest("source-closure"),
        "buildWatchdogReceiptFileSha256": _fixture_digest(
            "watchdog-file"
        ),
        "promotionReceiptFileSha256": _fixture_digest(
            "promotion-receipt-file"
        ),
        "nitroAttestationDocumentSha256": _fixture_digest(
            "nitro-attestation"
        ),
        "eifSha384": pcrs["PCR0"],
        "pcrs": pcrs,
        "tlsExporterSha256": _fixture_digest("tls-exporter"),
        "tlsSpkiSha256": _fixture_digest("tls-spki"),
        "requestSha256": pre_authorization_core["requestSha256"],
        "responseBytesSha256": pre_authorization_core[
            "responseBytesSha256"
        ],
        "completionIdentity": identity,
        "completionIdentitySha256": identity_sha256,
        "completionCoreDigests": identity["coreDigests"],
        "releaseIdentity": release_identity,
        "releaseIdentitySha256": _fixture_json_digest(release_identity),
        "completionProofFileSha256": _fixture_digest(
            "completion-proof-file"
        ),
        "runtimeKeyCustodyFileSha256": _fixture_digest(
            "runtime-custody-file"
        ),
        "candidateToEifBuildStatementFileSha256": _fixture_digest(
            "candidate-eif-file"
        ),
        "kmsAuditProofSha256s": kms_audit_proofs,
        "witness": witness,
        "nextClientState": next_client_state,
        "challengeConsumptionSha256": next_client_state[
            "challengeConsumptionSha256"
        ],
        "stateTransition": state_transition,
        "externalBoundary": (
            "AWS Nitro EIF/KMS, enclave TLS exporter extension, off-host "
            "witness, CAS/current-head reservation and atomic redemption "
            "store, independent builders/promoter, and their trust roots "
            "must be provisioned outside this verifier"
        ),
        "preAuthorizationResultCore": pre_authorization_core,
        "preAuthorizationResultCoreSha256": _fixture_json_digest(
            pre_authorization_core
        ),
        "stateCommitReceiptSha256": state_commit_receipt_identity[
            "receiptFileSha256"
        ],
        "stateCommitReceiptIdentity": state_commit_receipt_identity,
        "stateCommitId": "fixture-commit",
        "stateCommitCommittedAtUnix": 100,
        "stateCommitExpiresAtUnix": 200,
        "stateStoreId": "fixture-store",
        "stateStoreGeneration": 5,
        "stateStoreRedemptionSequence": 2,
        "stateCommitPhase": "committed-awaiting-current-head-authorization",
        "rollbackResistanceBoundary": final_rollback_boundary,
        "currentHeadAuthorizationFileSha256": authorization_identity[
            "authorizationFileSha256"
        ],
        "currentHeadAuthorizationId": "fixture-authorization",
        "currentHeadAuthorizationIdentity": authorization_identity,
        "currentHeadAuthorizationIdentitySha256": _fixture_json_digest(
            authorization_identity
        ),
        "currentHeadAuthorizationIssuedAtUnix": 110,
        "currentHeadAuthorizationExpiresAtUnix": 190,
        "currentHead": current_head,
        "currentHeadSha256": current_head_sha256,
        "currentHeadVerifierNonceSha256": _fixture_digest(
            "authorization-verifier-nonce"
        ),
        "currentHeadReservationId": "fixture-reservation",
        "currentHeadReservationIdentity": reservation_identity,
        "currentHeadReservationIdentitySha256": (
            reservation_identity_sha256
        ),
        "currentHeadExpectedFinalGeneration": 5,
        "currentHeadExpectedOneUseSequence": 2,
        "verificationOk": True,
        "finalCompletionVerified": True,
        "actionAuthorization": None,
        "currentFinalHead": current_final_head,
        "currentFinalHeadSha256": current_final_head_sha256,
        "currentHeadRedemptionReceiptFileSha256": redemption_identity[
            "redemptionFileSha256"
        ],
        "currentHeadRedemptionReceiptIdentity": redemption_identity,
        "currentHeadRedemptionReceiptIdentitySha256": _fixture_json_digest(
            redemption_identity
        ),
        "currentHeadRedemptionId": "fixture-redemption",
        "currentHeadRedemptionVerifierNonceSha256": current_final_head[
            "redemptionVerifierNonceSha256"
        ],
        "currentHeadRedemptionVerified": True,
        "currentHeadOneUseSequence": 2,
    }
    state_commit = {
        "apiVersion": "serverware.publicNitroStateCommit/v1",
        "status": "redemption-verified-non-actionable",
        "actionable": False,
        "redemptionVerified": True,
        "commitId": "fixture-commit",
        "storeId": "fixture-store",
        "signingKeyId": state_commit_receipt_identity["signingKeyId"],
        "receiptFileSha256": state_commit_receipt_identity[
            "receiptFileSha256"
        ],
        "receiptPayloadSha256": state_commit_receipt_identity[
            "receiptPayloadSha256"
        ],
        "priorStateSha256": state_transition["oldStateSha256"],
        "currentStateSha256": next_client_state["stateSha256"],
        "transitionSha256": state_transition["transitionSha256"],
        "challengeConsumptionSha256": next_client_state[
            "challengeConsumptionSha256"
        ],
        "currentHeadAuthorizationId": "fixture-authorization",
        "currentHeadAuthorizationFileSha256": authorization_identity[
            "authorizationFileSha256"
        ],
        "currentHeadSha256": current_head_sha256,
        "currentHeadVerifierNonceSha256": public_result[
            "currentHeadVerifierNonceSha256"
        ],
        "currentHeadReservationId": "fixture-reservation",
        "currentHeadRedemptionId": "fixture-redemption",
        "currentHeadRedemptionReceiptFileSha256": redemption_identity[
            "redemptionFileSha256"
        ],
        "currentHeadRedemptionReceiptIdentitySha256": public_result[
            "currentHeadRedemptionReceiptIdentitySha256"
        ],
        "currentHeadRedemptionVerifierNonceSha256": public_result[
            "currentHeadRedemptionVerifierNonceSha256"
        ],
        "currentFinalHeadSha256": current_final_head_sha256,
        "currentHeadOneUseSequence": 2,
        "rollbackResistanceBoundary": final_rollback_boundary,
    }
    candidate_to_eif = {
        "fileSha256": _fixture_digest("candidate-eif-file"),
        "payloadSha256": _fixture_digest("candidate-eif-payload"),
        "signingKeyId": trust_key_ids["manifestV6EifBuilder"],
        "signingKeyFileSha256": _fixture_digest(
            "candidate-eif-key-file"
        ),
        "builderStatementsSha256": _fixture_digest("builder-statements"),
        "completionIdentity": identity,
        "completionIdentitySha256": identity_sha256,
        "dependencyClosureSha256": _fixture_digest(
            "dependency-closure"
        ),
        "importedImageMappingsSha256": _fixture_digest(
            "imported-image-mappings"
        ),
        "eifSha384": pcrs["PCR0"],
        "pcrs": pcrs,
        "releaseGeneration": 9,
        "rollbackEpoch": 3,
    }
    protected_state_payload = {
        "apiVersion": "serverware.protectedNitroClientStateIdentity/v1",
        "canonicalProfile": (
            FINAL_FIXTURE_CANONICAL_PROFILE
        ),
        "protectedClientStateId": "fixture-protected-state",
        "stateEnvelopeFileSha256": _fixture_digest(
            "protected-state-envelope"
        ),
        "statePayloadSha256": _fixture_digest("protected-state-payload"),
        "clientStateSha256": state_transition["oldStateSha256"],
        "stateSigningKeyId": trust_key_ids["clientState"],
        "stateSigningKeyFileSha256": _fixture_digest("state-key-file"),
        "checkpointFileSha256": _fixture_digest(
            "protected-checkpoint-file"
        ),
        "checkpointPayloadSha256": _fixture_digest(
            "protected-checkpoint-payload"
        ),
        "checkpointKeyId": trust_key_ids["clientStateCheckpoint"],
        "checkpointKeyFileSha256": _fixture_digest(
            "checkpoint-key-file"
        ),
        "checkpointProvider": "fixture-checkpoint-provider",
        "checkpointTreeSize": 8,
        "checkpointRootHashSha256": _fixture_digest(
            "protected-checkpoint-root"
        ),
        "trustRootBundleSha256": _fixture_digest("trust-root-bundle"),
        "trustRootPinId": "fixture-trust-root-pin",
        "provenanceBoundary": (
            "client-or-out-of-band-pinned-protected-state/v1"
        ),
    }
    protected_state = {
        **protected_state_payload,
        "identitySha256": _fixture_json_digest(protected_state_payload),
    }
    host_bootstrap_boundary_payload: dict[str, object] = {
        "apiVersion": "serverware.hostBootstrapBoundary/v1",
        "launchManifestApiVersion": "serverware.productionReadinessLaunch/v3",
        "launchAuthorizationRequestApiVersion": (
            "serverware.launchAuthorizationRequest/v2"
        ),
        "launchAuthorizationApiVersion": "serverware.launchAuthorization/v2",
        "bootstrapReceiptApiVersion": "serverware.bootstrapReceipt/v3",
        "nonceRollbackAssuranceBindingApiVersion": (
            "serverware.productionNonceRollbackAssuranceBinding/v1"
        ),
        "authorizationScope": "trusted-host-readiness",
        "freshnessAuthority": "trusted-host-wall-clock",
        "evidenceProvidedToFinalVerifier": False,
        "authoritativeForFinalCompletion": False,
        "requiredForFinalCompletion": False,
        "relationship": "non-authoritative-readiness-context-only",
        "finalAuthority": (
            "independent-manifest-v6-public-nitro-verifier-and-protected-state"
        ),
        "completionIdentitySha256": identity_sha256,
        "bindingMechanism": (
            "verifier-validated-canonical-binding-to-authenticated-completion-identity"
        ),
    }
    host_bootstrap_boundary = {
        **host_bootstrap_boundary_payload,
        "boundarySha256": _fixture_json_digest(
            host_bootstrap_boundary_payload
        ),
    }
    production_identity_payload: dict[str, object] = {
        "apiVersion": (
            FINAL_FIXTURE_BRIDGE_API_VERSION
        ),
        "canonicalProfile": (
            FINAL_FIXTURE_CANONICAL_PROFILE
        ),
        "pipeline": FINAL_FIXTURE_PIPELINE,
        "legacyDockerNsmAccepted": False,
        "completionIdentity": identity,
        "completionIdentitySha256": identity_sha256,
        "releaseArtifactBindings": artifact_bindings,
        "publicNitroEvidenceBundleFileSha256": _fixture_digest(
            "public-bundle-file"
        ),
        "publicNitroExpectationsFileSha256": _fixture_digest(
            "public-expectations-file"
        ),
        "publicVerifierResultSha256": _fixture_json_digest(public_result),
        "productionIdentitySha256": public_result[
            "productionIdentitySha256"
        ],
        "candidateManifestFileSha256": public_result[
            "candidateManifestFileSha256"
        ],
        "candidateManifestPayloadSha256": _fixture_digest(
            "candidate-payload"
        ),
        "sourceInputManifestFileSha256": _fixture_digest(
            "source-input-file"
        ),
        "sourceClosureSha256": public_result["sourceClosureSha256"],
        "buildWatchdogReceiptFileSha256": public_result[
            "buildWatchdogReceiptFileSha256"
        ],
        "promotionReceiptFileSha256": public_result[
            "promotionReceiptFileSha256"
        ],
        "promotedManifestFileSha256": _fixture_digest(
            "promoted-manifest-file"
        ),
        "promotedManifestPayloadSha256": _fixture_digest(
            "promoted-manifest-payload"
        ),
        "promotedManifestMeasuredFileSha256": _fixture_digest(
            "promoted-manifest-file"
        ),
        "candidateToEif": candidate_to_eif,
        "runtimeStateFileSha256": _fixture_digest("runtime-state-file"),
        "runtimeKeyCustodyFileSha256": public_result[
            "runtimeKeyCustodyFileSha256"
        ],
        "enclaveInstanceId": "fixture-enclave",
        "enclaveBootId": "fixture-enclave-boot",
        "runtimeKeyGenerations": {
            name: index + 1
            for index, name in enumerate(
                (
                    "brokerKek",
                    "ca",
                    "credentialRelease",
                    "policy",
                    "release",
                    "response",
                    "tls",
                    "tlsScope",
                )
            )
        },
        "releaseGeneration": 9,
        "rollbackEpoch": 3,
        "policyHash": _fixture_digest("policy"),
        "policySequence": 7,
        "caSpkiSha256": _fixture_digest("ca-spki"),
        "eifSha384": pcrs["PCR0"],
        "pcrs": pcrs,
        "rawNitroAttestationDocumentSha256": public_result[
            "nitroAttestationDocumentSha256"
        ],
        "tlsExporterSha256": public_result["tlsExporterSha256"],
        "tlsSpkiSha256": public_result["tlsSpkiSha256"],
        "tlsPeerSpkiSha256": _fixture_digest("tls-peer-spki"),
        "tlsStackMeasurementSha256": _fixture_digest(
            "tls-stack-measurement"
        ),
        "attestationRequestSha256": _fixture_digest(
            "attestation-request"
        ),
        "requestSha256": public_result["requestSha256"],
        "responseBytesSha256": public_result["responseBytesSha256"],
        "releaseKeyCustodyEvidenceSha256": public_result[
            "runtimeKeyCustodyFileSha256"
        ],
        "kmsAuditProofSha256s": kms_audit_proofs,
        "completionProofFileSha256": public_result[
            "completionProofFileSha256"
        ],
        "completionAuthenticationKeyId": trust_key_ids["completion"],
        "completionCheckpointKeyId": trust_key_ids[
            "completionCheckpoint"
        ],
        "hostBootstrapBoundarySha256": host_bootstrap_boundary[
            "boundarySha256"
        ],
        "witnessCheckpointSha256": witness["checkpointSha256"],
        "witnessChallengeConsumptionSha256": witness[
            "challengeConsumptionSha256"
        ],
        "witnessLeafIndex": witness["leafIndex"],
        "challengeSha256": identity["challengeNonceSha256"],
        "candidateExecutionContract": {
            field: _fixture_digest(field)
            for field in (
                "commandContractSha256",
                "semanticContractSha256",
                "dependencyManifestFileSha256",
                "dependencyManifestPayloadSha256",
                "planSha256",
                "sourceClosureSha256",
                "sourceFilesSha256",
                "installedSourceFilesSha256",
            )
        },
        "watchdogAndBuilderGrammar": {
            field: _fixture_digest(field)
            for field in (
                "builderEventGrammarSha256",
                "candidateRequestSha256",
                "outputIdentitiesSha256",
                "requestSha256",
                "watchdogEventOrderSha256",
            )
        },
        "promotionAcceptance": {
            "acceptanceSha256": promotion_acceptance_sha256,
            "canonicalPayload": promotion_canonical_payload,
            "canonicalPayloadSha256": promotion_acceptance_sha256,
            "imageMappingsSha256": _fixture_digest(
                "imported-image-mappings"
            ),
            "inspectionInventorySha256": _fixture_digest(
                "promotion-inspection-inventory"
            ),
        },
        "publicHandoff": {
            "httpResponseEnvelopeSha256": _fixture_digest(
                "http-response-envelope"
            ),
            "runtimeCustodyApiVersion": (
                "serverware.enclaveKeyCustody/v3"
            ),
            "tlsScopeApiVersion": "serverware.enclaveTlsScope/v2",
            "responseStatementApiVersion": (
                "serverware.attestationResponse/v2"
            ),
            "protectedPriorClientStateEnvelopeSha256": _fixture_digest(
                "protected-state-envelope"
            ),
            "protectedPriorClientStateCheckpointSha256": _fixture_digest(
                "protected-checkpoint-file"
            ),
            "trustRootBundleSha256": _fixture_digest(
                "trust-root-bundle"
            ),
            "trustRootPinId": "fixture-trust-root-pin",
            "candidateToEifBuildStatementFileSha256": candidate_to_eif[
                "fileSha256"
            ],
        },
        "protectedPriorClientState": protected_state,
        "stateCommit": state_commit,
        "trustRootPin": {
            "bundleFileSha256": _fixture_digest("trust-root-bundle"),
            "expectedBundleFileSha256": _fixture_digest(
                "trust-root-bundle"
            ),
            "pinId": "fixture-trust-root-pin",
            "keyIds": trust_key_ids,
            "provenanceBoundary": (
                "Only a client or out-of-band comparison of the expected "
                "bundle digest and key IDs establishes provenance; these "
                "on-host CLI paths are transport only."
            ),
        },
    }
    production_identity = {
        **production_identity_payload,
        "identitySha256": _fixture_json_digest(production_identity_payload),
    }
    result_payload: dict[str, object] = {
        "apiVersion": (
            run_production_readiness.FINAL_COMPLETION_RESULT_API_VERSION
        ),
        "verificationOk": True,
        "finalCompletionVerified": True,
        "actionAuthorization": None,
        "okForAction": False,
        "verificationMode": "final",
        "redemptionVerified": True,
        "readinessOnly": False,
        "independentlyAuthenticated": True,
        "pipeline": FINAL_FIXTURE_PIPELINE,
        "canonicalProfile": (
            FINAL_FIXTURE_CANONICAL_PROFILE
        ),
        "verifiedAtUnix": 150,
        "productionReleaseIdentity": production_identity,
        "publicVerifierResult": public_result,
        "aggregateAuthentication": {
            "independentlyAuthenticated": True,
            "completionIdentity": identity,
            "completionIdentitySha256": identity_sha256,
            "completionProofFileSha256": public_result[
                "completionProofFileSha256"
            ],
            "completionAuthenticationKeyId": production_identity[
                "completionAuthenticationKeyId"
            ],
            "completionCheckpointKeyId": production_identity[
                "completionCheckpointKeyId"
            ],
            "hostBootstrapBoundarySha256": host_bootstrap_boundary[
                "boundarySha256"
            ],
            "keysAreDistinct": True,
        },
        "completionIdentity": identity,
        "completionIdentitySha256": identity_sha256,
        "releaseArtifactBindings": artifact_bindings,
        "nextClientState": next_client_state,
        "stateCommit": state_commit,
        "hostBootstrapBoundary": host_bootstrap_boundary,
        "externalPinProvenanceBoundary": (
            "The verifier proves equality to supplied pins. It cannot prove "
            "that an on-host argument was independently sourced; the client "
            "or another out-of-band trust channel must pin the bundle digest "
            "and protected-state key IDs."
        ),
        "externalProvisioningBoundary": (
            "Actual AWS Nitro EIF construction and PCR policy, AWS KMS "
            "CiphertextForRecipient releases, enclave-owned TLS exporter "
            "support, independent builders/promoter, off-host monotonic "
            "witness storage, CAS/current-head reservation and atomic "
            "authorization redemption, and a stateful action gate that "
            "re-checks the live final head and consumes the redemption "
            "receipt identity while performing the action must still be "
            "provisioned. This persisted completion is never an action "
            "capability."
        ),
    }
    return {
        **result_payload,
        "resultSha256": _fixture_json_digest(result_payload),
    }


def _fixture_ed25519_material(
    label: str,
) -> tuple[Ed25519PrivateKey, str, str]:
    private_key = Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(f"serverware-fixture:{label}".encode("ascii")).digest()
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_pem, "sha256:" + hashlib.sha256(public_der).hexdigest()


def _fixture_ed25519_signature(
    private_key: Ed25519PrivateKey,
    domain: bytes,
    value: object,
) -> str:
    signature = private_key.sign(
        domain + canonical_json(value).encode("ascii")
    )
    return "ed25519:" + base64.urlsafe_b64encode(signature).decode(
        "ascii"
    ).rstrip("=")


def release_completion_result_v1_fixture() -> dict[str, object]:
    import production_attestation_producer_issuer as producer_issuer
    import verify_release_completion as final_verifier
    import verify_nitro_tee as native_verifier

    public_private, public_pem, public_key_id = _fixture_ed25519_material(
        "public-nitro-result"
    )
    result_private, _, result_key_id = _fixture_ed25519_material(
        "release-completion-result"
    )
    core_names = (
        "builderA",
        "builderB",
        "continuity",
        "custody",
        "eif",
        "hardware",
        "promotion",
        "release",
        "response",
        "runtime",
        "source",
        "trust",
        "witness",
    )
    completion_identity: dict[str, object] = {
        "apiVersion": FINAL_FIXTURE_IDENTITY_API_VERSION,
        "challengeNonceSha256": _fixture_digest("challenge"),
        "coreDigests": {
            name: _fixture_digest(f"completion-core:{name}")
            for name in core_names
        },
        "pipeline": FINAL_FIXTURE_PIPELINE,
        "releaseGeneration": 9,
        "rollbackEpoch": 3,
    }
    completion_identity_sha256 = _fixture_json_digest(
        completion_identity
    )
    public_roles = {
        role: _fixture_digest(f"final-role:{role}")
        for role in (
            "builderA",
            "builderB",
            "buildWatchdog",
            "clientState",
            "clientStateCheckpoint",
            "currentHeadAuthorization",
            "currentHeadRedemption",
            "keyCustody",
            "kmsAudit",
            "manifestV6EifBuilder",
            "nitroAttestationVerifier",
            "promotion",
            "sourceGitInventory",
            "sourceUntrackedApproval",
            "stateCommit",
            "stateStore",
            "storeAssurance",
            "tlsRelease",
            "verifierState",
            "witness",
            "witnessStore",
        )
    }
    public_roles["publicNitroResult"] = public_key_id
    public_roles = {
        role: public_roles[role] for role in sorted(public_roles)
    }
    public_role_registry_sha256 = _fixture_json_digest(
        {
            "apiVersion": "serverware.publicNitroRoleRegistry/v1",
            "roles": public_roles,
        }
    )
    challenge_consumption_sha256 = _fixture_digest(
        "witness-challenge-consumption"
    )
    witness = {
        "checkpointSha256": _fixture_digest("witness-checkpoint"),
        "challengeConsumptionSha256": challenge_consumption_sha256,
        "leafIndex": 4,
        "releaseGeneration": 9,
        "rollbackEpoch": 3,
        "sequence": 11,
        "treeSize": 12,
        "rootHash": _fixture_digest("witness-root"),
        "witnessKeyId": public_roles["witness"],
        "witnessStoreKeyId": public_roles["witnessStore"],
        "witnessStoreIdentitySha256": _fixture_digest(
            "witness-store-identity"
        ),
        "witnessStoreAssuranceSha256": _fixture_digest(
            "witness-store-assurance"
        ),
    }
    next_state_core: dict[str, object] = {
        "apiVersion": "serverware.monotonicReleaseWitnessState/v2",
        "challengeConsumptionSha256": challenge_consumption_sha256,
        "checkpointSha256": witness["checkpointSha256"],
        "logId": _fixture_digest("witness-log"),
        "provider": "fixture-witness-provider",
        "releaseGeneration": 9,
        "rollbackEpoch": 3,
        "rootHash": witness["rootHash"],
        "sequence": witness["sequence"],
        "treeSize": witness["treeSize"],
        "witnessKeyId": public_roles["witness"],
    }
    next_state = {
        **next_state_core,
        "stateSha256": _fixture_json_digest(next_state_core),
    }
    transition_core = {
        "oldStateSha256": _fixture_digest("prior-client-state"),
        "newStateSha256": next_state["stateSha256"],
    }
    state_transition = {
        **transition_core,
        "transitionSha256": _fixture_json_digest(transition_core),
    }
    state_commit = {
        "apiVersion": "serverware.publicNitroStateCommit/v1",
        "status": "redemption-verified-non-actionable",
        "actionable": False,
        "redemptionVerified": True,
        "commitId": "fixture-commit",
        "storeId": "fixture-store",
        "signingKeyId": public_roles["stateCommit"],
        "stateStoreSigningKeyId": public_roles["stateStore"],
        "receiptFileSha256": _fixture_digest("state-commit-receipt"),
        "receiptPayloadSha256": _fixture_digest(
            "state-commit-receipt-payload"
        ),
        "priorStateSha256": state_transition["oldStateSha256"],
        "currentStateSha256": state_transition["newStateSha256"],
        "transitionSha256": state_transition["transitionSha256"],
        "challengeConsumptionSha256": challenge_consumption_sha256,
        "currentHeadAuthorizationId": "fixture-authorization",
        "currentHeadAuthorizationFileSha256": _fixture_digest(
            "current-head-authorization"
        ),
        "currentHeadAuthorizationKeyId": public_roles[
            "currentHeadAuthorization"
        ],
        "currentHeadSha256": _fixture_digest("current-head"),
        "currentHeadVerifierNonceSha256": _fixture_digest(
            "current-head-verifier-nonce"
        ),
        "currentHeadReservationId": "fixture-reservation",
        "currentHeadRedemptionId": "fixture-redemption",
        "currentHeadRedemptionReceiptFileSha256": _fixture_digest(
            "current-head-redemption-receipt"
        ),
        "currentHeadRedemptionReceiptIdentitySha256": _fixture_digest(
            "current-head-redemption-identity"
        ),
        "currentHeadRedemptionVerifierNonceSha256": _fixture_digest(
            "current-head-redemption-verifier-nonce"
        ),
        "currentHeadRedemptionKeyId": public_roles[
            "currentHeadRedemption"
        ],
        "currentFinalHeadSha256": _fixture_digest("current-final-head"),
        "currentHeadOneUseSequence": 12,
        "verifierStateKeyId": public_roles["verifierState"],
        "storeAssuranceKeyId": public_roles["storeAssurance"],
        "tlsReleaseKeyId": public_roles["tlsRelease"],
        "rollbackResistanceBoundary": (
            "historical non-actionable evidence after atomic redemption"
        ),
    }
    pcrs = {
        "PCR0": _fixture_sha384("eif"),
        "PCR1": _fixture_sha384("pcr1"),
        "PCR2": _fixture_sha384("pcr2"),
    }
    public_result: dict[str, object] = {
        "apiVersion": "serverware.publicNitroVerificationResult/v2",
        "verificationOk": True,
        "finalCompletionVerified": True,
        "actionAuthorization": None,
        "okForAction": False,
        "status": "redemption-verified-non-actionable",
        "pipeline": FINAL_FIXTURE_PIPELINE,
        "canonicalProfile": FINAL_FIXTURE_CANONICAL_PROFILE,
        "verifiedAtUnix": 150,
        "evidenceBundleFileSha256": _fixture_digest(
            "public-nitro-evidence-bundle"
        ),
        "expectationsFileSha256": _fixture_digest(
            "public-nitro-expectations"
        ),
        "trustRootBundleFileSha256": _fixture_digest(
            "public-nitro-trust-roots"
        ),
        "completionIdentity": completion_identity,
        "completionIdentitySha256": completion_identity_sha256,
        "completionCoreDigests": completion_identity["coreDigests"],
        "candidateManifestFileSha256": _fixture_digest(
            "candidate-manifest"
        ),
        "candidateManifestPayloadSha256": _fixture_digest(
            "candidate-manifest-payload"
        ),
        "sourceInputManifestFileSha256": _fixture_digest(
            "source-input-manifest"
        ),
        "sourceClosureSha256": _fixture_digest("source-closure"),
        "buildWatchdogReceiptFileSha256": _fixture_digest(
            "build-watchdog-receipt"
        ),
        "promotionReceiptFileSha256": _fixture_digest(
            "promotion-receipt"
        ),
        "promotedManifestFileSha256": _fixture_digest(
            "promoted-manifest"
        ),
        "productionIdentitySha256": _fixture_digest(
            "production-identity"
        ),
        "runtimeStateFileSha256": _fixture_digest("runtime-state"),
        "runtimeKeyCustodyFileSha256": _fixture_digest(
            "runtime-key-custody"
        ),
        "candidateToEifBuildStatementFileSha256": _fixture_digest(
            "candidate-to-eif"
        ),
        "eifSha384": pcrs["PCR0"],
        "pcrs": pcrs,
        "nitroAttestationDocumentSha256": _fixture_digest(
            "nitro-attestation-document"
        ),
        "attestationRequestSha256": _fixture_digest(
            "attestation-request"
        ),
        "requestSha256": _fixture_digest("request"),
        "responseBytesSha256": _fixture_digest("response-bytes"),
        "tlsExporterSha256": _fixture_digest("tls-exporter"),
        "tlsSpkiSha256": _fixture_digest("tls-spki"),
        "tlsPeerSpkiSha256": _fixture_digest("tls-peer-spki"),
        "tlsStackMeasurementSha256": _fixture_digest(
            "tls-stack-measurement"
        ),
        "kmsAuditProofSha256s": {
            name: _fixture_digest(f"kms-audit:{name}")
            for name in (
                "broker-kek",
                "ca",
                "credentials",
                "release",
                "response",
                "tls",
            )
        },
        "witness": witness,
        "nextClientState": next_state,
        "stateTransition": state_transition,
        "stateCommit": state_commit,
        "roleKeyIds": public_roles,
        "roleRegistrySha256": public_role_registry_sha256,
    }
    signer_tls_spki_sha256 = _fixture_digest(
        "public-nitro-signer-server-tls"
    )
    signing_request = (
        native_verifier.build_public_nitro_result_signing_request(
            public_result,
            provider="fixture-public-nitro-verifier",
            signing_key_id=public_key_id,
            signing_key_spki_sha256=public_key_id,
            signer_server_tls_spki_sha256=(
                signer_tls_spki_sha256
            ),
        )
    )

    def invoke_native_signer(request: object) -> bytes:
        if request != signing_request:
            raise AssertionError(
                "production relay changed the native signing request"
            )
        envelope_core = signing_request["envelopeCore"]
        signature = _fixture_ed25519_signature(
            public_private,
            native_verifier.PUBLIC_NITRO_LIVE_RESULT_ENVELOPE_DOMAIN,
            envelope_core,
        )
        response = {
            "apiVersion": (
                native_verifier
                .PUBLIC_NITRO_RESULT_SIGNING_RESPONSE_VERSION
            ),
            "envelope": {
                **envelope_core,
                "signature": signature,
            },
            "operationIdSha256":
            signing_request["operationIdSha256"],
            "recoveryKeySha256":
            signing_request["recoveryKeySha256"],
            "requestSha256": signing_request["requestSha256"],
            "status": "signed",
            "transportPins": signing_request["transportPins"],
        }
        return producer_issuer.canonical_json(response) + b"\n"

    relayed_response = (
        producer_issuer.relay_public_nitro_result_signer_operation(
            signing_request,
            invoke_signer=invoke_native_signer,
            signing_key=public_private.public_key(),
        )
    )
    signing_response = json.loads(relayed_response.decode("utf-8"))
    public_envelope = (
        native_verifier.verify_public_nitro_result_signing_response(
            signing_request,
            signing_response,
            signing_key=public_private.public_key(),
        )
    )
    final_consumed_result = (
        final_verifier.verify_signed_public_nitro_result_envelope(
            public_envelope,
            trusted_public_key_pem=public_pem,
            expected_provider="fixture-public-nitro-verifier",
            expected_key_id=public_key_id,
            expected_spki_sha256=public_key_id,
        )
    )
    if final_consumed_result != public_result:
        raise AssertionError(
            "final-v1 did not consume the native/production signed result"
        )
    public_envelope_file_sha256 = "sha256:" + hashlib.sha256(
        (canonical_json(public_envelope) + "\n").encode("ascii")
    ).hexdigest()
    launch_authority_key_id = _fixture_digest(
        "final-role:launchAuthority"
    )
    host_context = {
        "apiVersion": "serverware.hostReadinessContext/v1",
        "provided": True,
        "completionProofApiVersion": "serverware.completionProof/v6",
        "completionProofFileSha256": _fixture_digest(
            "host-readiness-completion-proof-file"
        ),
        "completionProofCoreSha256": _fixture_digest(
            "host-readiness-completion-proof-core"
        ),
        "generatedAtUnix": 1_700_000_000,
        "launchAuthorityKeyId": launch_authority_key_id,
        "authoritativeForFinalCompletion": False,
    }
    host_boundary_core: dict[str, object] = {
        "apiVersion": "serverware.hostBootstrapBoundary/v1",
        "launchManifestApiVersion": "serverware.productionReadinessLaunch/v3",
        "launchAuthorizationRequestApiVersion": (
            "serverware.launchAuthorizationRequest/v2"
        ),
        "launchAuthorizationApiVersion": "serverware.launchAuthorization/v2",
        "bootstrapReceiptApiVersion": "serverware.bootstrapReceipt/v3",
        "nonceRollbackAssuranceBindingApiVersion": (
            "serverware.productionNonceRollbackAssuranceBinding/v1"
        ),
        "authorizationScope": "trusted-host-readiness",
        "freshnessAuthority": "trusted-host-wall-clock",
        "evidenceProvidedToFinalVerifier": True,
        "hostReadinessContextSha256": _fixture_json_digest(host_context),
        "hostReadinessCompletionProofFileSha256": host_context[
            "completionProofFileSha256"
        ],
        "launchAuthorityKeyId": launch_authority_key_id,
        "authoritativeForFinalCompletion": False,
        "requiredForFinalCompletion": False,
        "relationship": "non-authoritative-readiness-context-only",
        "finalAuthority": (
            "independent-manifest-v6-public-nitro-verifier-and-protected-state"
        ),
        "completionIdentitySha256": completion_identity_sha256,
        "bindingMechanism": (
            "signed-final-result-core-non-authoritative-context-binding"
        ),
    }
    host_boundary = {
        **host_boundary_core,
        "boundarySha256": _fixture_json_digest(host_boundary_core),
    }
    final_roles = {
        **public_roles,
        "launchAuthority": launch_authority_key_id,
        "releaseCompletionResult": result_key_id,
    }
    final_roles = {
        role: final_roles[role] for role in sorted(final_roles)
    }
    global_role_registry_core = {
        "apiVersion": "serverware.finalRoleRegistry/v1",
        "roles": final_roles,
    }
    global_role_registry = {
        **global_role_registry_core,
        "registrySha256": _fixture_json_digest(
            global_role_registry_core
        ),
    }
    final_core = (
        final_verifier.build_release_completion_verification_v1_core(
            public_envelope=public_envelope,
            public_envelope_file_sha256=public_envelope_file_sha256,
            public_result=public_result,
            evidence_bundle_file_sha256=public_result[
                "evidenceBundleFileSha256"
            ],
            expectations_file_sha256=public_result[
                "expectationsFileSha256"
            ],
            trust_root_bundle_file_sha256=public_result[
                "trustRootBundleFileSha256"
            ],
            completion_identity=completion_identity,
            completion_identity_sha256=completion_identity_sha256,
            host_context=host_context,
            host_boundary=host_boundary,
            global_role_registry=global_role_registry,
            result_signer_key_id=result_key_id,
        )
    )
    result_sha256 = _fixture_json_digest(final_core)
    return {
        **final_core,
        "resultSha256": result_sha256,
        "authenticity": {
            "apiVersion": (
                "serverware.releaseCompletionResultSignature/v1"
            ),
            "provider": "fixture-release-completion-signer",
            "signingKeyId": result_key_id,
            "signingKeySpkiSha256": result_key_id,
            "resultSha256": result_sha256,
            "signature": _fixture_ed25519_signature(
                result_private,
                (
                    b"serverware.releaseCompletionResultSignature/v1"
                    b"\x00Ed25519\x00"
                ),
                final_core,
            ),
        },
    }


def release_completion_fixture_validation_kwargs() -> dict[str, str]:
    _, public_pem, public_key_id = _fixture_ed25519_material(
        "public-nitro-result"
    )
    _, result_pem, result_key_id = _fixture_ed25519_material(
        "release-completion-result"
    )
    result = release_completion_result_v1_fixture()
    return {
        "trusted_result_public_key_pem": result_pem,
        "expected_result_provider": "fixture-release-completion-signer",
        "expected_result_key_id": result_key_id,
        "expected_result_spki_sha256": result_key_id,
        "trusted_public_nitro_result_public_key_pem": public_pem,
        "expected_public_nitro_result_provider": (
            "fixture-public-nitro-verifier"
        ),
        "expected_public_nitro_result_key_id": public_key_id,
        "expected_public_nitro_result_spki_sha256": public_key_id,
        "expected_final_role_registry_sha256": result[
            "globalRoleRegistry"
        ]["registrySha256"],
    }


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
                # A header names the agent but is not its trust anchor. This
                # fixture admits only a local proof client; it is not a live
                # deployment identity or evidence that any client connected.
                "sourceCidrs": ["127.0.0.1/32"],
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
                        "credentialMode": "none",
                        "noCredentialProof": {
                            "credentialRefAbsent": True,
                            "secretInjectionDisabled": True,
                            "sensitiveHeadersForwarded": False,
                            "authorizationForwarded": False,
                        },
                        "request": {
                            "allowedHeaders": ["accept", "user-agent"],
                            "allowedQueryKeys": [],
                            "allowedMediaTypes": [],
                            "bodyMode": "none",
                            "maxBodyBytes": 0,
                            "operation": {"name": "production.proof.health"},
                            "valueRules": [],
                        },
                        "response": {
                            "mode": "json",
                            "maxBodyBytes": 65536,
                            "contentTypes": ["application/json"],
                            "allowedFields": ["status"],
                            "allowedHeaders": [],
                            "error": {
                                "mode": "json",
                                "maxBodyBytes": 65536,
                                "allowedFields": ["error", "code", "message"],
                                "allowedHeaders": [],
                                "onInvalid": "block",
                            },
                        },
                    },
                },
                "constraints": [
                    {
                        "id": "production-proof-response-envelope",
                        "type": "responseEnvelope",
                        "phase": "response",
                        "operations": ["production.proof.health"],
                        "statusCodes": [200],
                        "bodyPresence": "required",
                        "contentTypes": ["application/json"],
                        "allowedResponseHeaderNames": [],
                        "responseHeaderRules": [],
                    }
                ],
            }
        ],
    }


def verify_proof_policy_identity_contract() -> None:
    with tempfile.TemporaryDirectory(dir=test_temp_root(), prefix="proof-identity-") as tmp_raw:
        path = Path(tmp_raw) / "policy.json"

        def validate(bundle: dict[str, object]) -> None:
            path.write_text(canonical_json(bundle) + "\n", encoding="utf-8")
            run_production_readiness.validate_proxy_proof_policy_consistency(
                path,
                agent_id="production-proof-agent",
                principal_id="agent:production-proof",
                proof_url="https://proof-target.prod.internal/health",
            )

        validate(proof_policy_bundle())
        for field, value, expected in (
            ("phase", "request", "must use phase response"),
            ("operations", ["unrelated.operation"], "responseEnvelope references unknown operations"),
            ("statusCodes", [True], "must define 1-16 unique statuses"),
            ("contentTypes", [], "invalid body/content-type contract"),
            ("allowedResponseHeaderNames", ["content-type"], "allowedResponseHeaderNames is invalid"),
            ("allowedResponseHeaderNames", ["x-proof"], "exactly one value rule for every allowed response header"),
            (None, None, "must define at least one responseEnvelope"),
        ):
            bundle = proof_policy_bundle()
            if field is None:
                bundle["routes"][0]["constraints"] = []
            else:
                bundle["routes"][0]["constraints"][0][field] = value
            try:
                validate(bundle)
            except ValueError as exc:
                if expected not in str(exc):
                    raise AssertionError(f"response envelope rejected for wrong reason: {exc}") from exc
            else:
                raise AssertionError(f"proof policy accepted invalid responseEnvelope.{field}")
        for selectors, expected in (
            ([], "must define at least one enforceable identity selector"),
            (["0.0.0.0/0"], "requiredHeaders require a non-universal source CIDR"),
        ):
            bundle = proof_policy_bundle()
            bundle["principals"][0]["sourceCidrs"] = selectors
            try:
                validate(bundle)
            except ValueError as exc:
                if expected not in str(exc):
                    raise AssertionError(f"proof identity rejected for wrong reason: {exc}") from exc
            else:
                raise AssertionError("proof policy accepted an unanchored agent header")
        for field in (
            "credentialRefAbsent", "secretInjectionDisabled",
            "sensitiveHeadersForwarded", "authorizationForwarded",
        ):
            bundle = proof_policy_bundle()
            proof = bundle["routes"][0]["adapter"]["config"]["noCredentialProof"]
            proof[field] = not proof[field]
            try:
                validate(bundle)
            except ValueError as exc:
                if "exact non-secret proof" not in str(exc):
                    raise AssertionError(f"credentialless fixture rejected for wrong reason: {exc}") from exc
            else:
                raise AssertionError(f"proof policy accepted invalid noCredentialProof.{field}")


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

    evidence_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("31" * 32))
    verifier_state_key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex("32" * 32)
    )
    verifier_state_store_attestation_key = (
        Ed25519PrivateKey.from_private_bytes(bytes.fromhex("33" * 32))
    )
    evidence_spki = evidence_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    verifier_state_spki = verifier_state_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    verifier_state_store_attestation_spki = (
        verifier_state_store_attestation_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    assurance = {
        "apiVersion": "serverware.nonceAuthorityAssurance/v1",
        "administrativeDomainSha256": "sha256:" + "a" * 64,
        "assuranceEvidenceSha256": "sha256:" + "b" * 64,
        "assuranceEvidenceType": "linearizableCasOperatorAttestation",
        "assuranceLevel": "productionRollbackProtected",
        "authorityEpoch": 1,
        "authorityGeneration": 2,
        "authorityIdentitySha256": "sha256:" + "c" * 64,
        "backendClass": "independentlyAdministeredLinearizableCas",
        "productionEligible": True,
        "rollbackProtection": {
            "administrativeRollbackResistance": True,
            "backendAttestationRequired": True,
            "exactSuccessorRequired": True,
            "freshVerifierChallengeRequired": True,
            "keyProtection": "nonExportableKmsHsm",
            "mechanism": "linearizableCasWithRollbackProtectedStorage",
            "stateCommitment": "hashChainedLinearizableCommitment",
            "verifierStateStoreClass": "independentlyAdministeredLinearizableCas",
        },
    }
    assurance_sha256 = "sha256:" + hashlib.sha256(
        canonical_json(assurance).encode("ascii")
    ).hexdigest()
    pins_contract = {
        "apiVersion": (
            run_production_readiness.NONCE_ROLLBACK_ASSURANCE_PINS_API_VERSION
        ),
        "independentVerifierPins": {
            "expectedNonceAuthorityAssuranceIssuerSpkiSha256": (
                "sha256:" + hashlib.sha256(evidence_spki).hexdigest()
            ),
            "expectedNonceAuthorityAssuranceSha256": assurance_sha256,
        },
        "publicConfigPins": {
            "nonceAuthorityAssurance": assurance,
            "nonceAuthorityAssuranceEvidenceSigningPublicKeySpkiDerBase64url": (
                base64.urlsafe_b64encode(evidence_spki)
                .decode("ascii")
                .rstrip("=")
            ),
            "nonceAuthorityAssuranceSha256": assurance_sha256,
            "nonceAuthorityVerifierStateSigningPublicKeySpkiDerBase64url": (
                base64.urlsafe_b64encode(verifier_state_spki)
                .decode("ascii")
                .rstrip("=")
            ),
            "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256": (
                "sha256:" + "d" * 64
            ),
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256": (
                "sha256:" + "f" * 64
            ),
            "nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url": (
                base64.urlsafe_b64encode(
                    verifier_state_store_attestation_spki
                )
                .decode("ascii")
                .rstrip("=")
            ),
            "nonceAuthorityVerifierStateStoreIdentitySha256": (
                "sha256:" + "e" * 64
            ),
        },
    }
    pins_bytes = canonical_json(pins_contract).encode("ascii") + b"\n"
    pins_file_sha256 = "sha256:" + hashlib.sha256(pins_bytes).hexdigest()
    pins_contract_sha256 = "sha256:" + hashlib.sha256(
        pins_bytes[:-1]
    ).hexdigest()

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
        "nonceRollbackAssurance": {
            "apiVersion": (
                run_production_readiness.NONCE_ROLLBACK_ASSURANCE_BINDING_API_VERSION
            ),
            "contractSha256": pins_contract_sha256,
            "pinsFile": {
                **file_record(
                    "/etc/serverware/nonce-rollback-assurance-pins.json",
                    "0",
                ),
                "sha256": pins_file_sha256,
            },
            "retainedSnapshotFd": 199,
            "retainedSnapshotSha256": pins_file_sha256,
            "verifierStateService": {
                "signingPublicKeySpkiDerBase64url": (
                    pins_contract["publicConfigPins"][
                        "nonceAuthorityVerifierStateSigningPublicKeySpkiDerBase64url"
                    ]
                ),
                "storeAdministrativeDomainSha256": (
                    "sha256:" + "d" * 64
                ),
                "storeAssuranceEvidenceSha256": "sha256:" + "f" * 64,
                "storeAttestationPublicKeySpkiDerBase64url": (
                    pins_contract["publicConfigPins"][
                        "nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url"
                    ]
                ),
                "storeIdentitySha256": "sha256:" + "e" * 64,
            },
        },
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
    witness_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("12" * 32))
    fixture_now = int(time.time())

    def authority_spki(key: Ed25519PrivateKey) -> bytes:
        return key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def authorization_for(
        target: dict[str, object],
        *,
        key: Ed25519PrivateKey = authority_key,
        issued_at: int | None = None,
        expires_at: int | None = None,
        verified_at: int | None = None,
    ) -> dict[str, object]:
        selected_issued_at = fixture_now if issued_at is None else issued_at
        selected_expires_at = (
            selected_issued_at + launch_authorization.MAX_VALIDITY_SECONDS
            if expires_at is None
            else expires_at
        )
        selected_verified_at = (
            selected_issued_at if verified_at is None else verified_at
        )
        inputs = target["inputs"]
        assert isinstance(inputs, dict)
        launcher = target["launcher"]
        manifest = target["manifest"]
        nonce_assurance = target["nonceRollbackAssurance"]
        assert (
            isinstance(launcher, dict)
            and isinstance(manifest, dict)
            and isinstance(nonce_assurance, dict)
        )
        role_values = {
            role: "sha256:" + hashlib.sha256(f"fixture-launch-role:{role}".encode("ascii")).hexdigest()
            for role in launch_authorization.GLOBAL_ROLE_REGISTRY_REQUIRED_ROLES
        }
        role_values.update({
            "launchAuthority": launch_authorization.spki_key_id(authority_spki(key)),
            "launchAuthorityWitness": launch_authorization.spki_key_id(authority_spki(witness_key)),
            "nonceAuthorityAssuranceEvidence": launch_authorization.spki_key_id(evidence_spki),
            "nonceAuthorityVerifierState": launch_authorization.spki_key_id(verifier_state_spki),
            "nonceAuthorityVerifierStateStoreAttestation": launch_authorization.spki_key_id(verifier_state_store_attestation_spki),
        })
        global_role_registry = {
            "apiVersion": launch_authorization.GLOBAL_ROLE_REGISTRY_API_VERSION,
            "claimScope": launch_authorization.GLOBAL_ROLE_REGISTRY_CLAIM_SCOPE,
            "roles": {role: role_values[role] for role in sorted(role_values)},
            "rolesOutsideClaim": list(launch_authorization.GLOBAL_ROLE_REGISTRY_ROLES_OUTSIDE_CLAIM),
        }
        request = {
            "apiVersion": (
                run_production_readiness.LAUNCH_AUTHORIZATION_REQUEST_API_VERSION
            ),
            "kind": launch_authorization.REQUEST_KIND,
            "launcherNonce": target["launchId"],
            "bootIdSha256": target["bootIdSha256"],
            "launcherSha256": launcher["sha256"],
            "manifestSha256": manifest["sha256"],
            "nonceRollbackAssuranceContractSha256": nonce_assurance[
                "contractSha256"
            ],
            "nonceRollbackAssurancePinsSha256": nonce_assurance[
                "retainedSnapshotSha256"
            ],
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
            "authorizationScope": launch_authorization.AUTHORIZATION_SCOPE,
            "freshnessAuthority": launch_authorization.FRESHNESS_AUTHORITY,
            "launchAuthorityWitnessChallenge": "3" * 64,
            "launchAuthorityWitnessKeyId": launch_authorization.spki_key_id(
                authority_spki(witness_key)
            ),
            "launchAuthorityWitnessIdentitySha256": "sha256:" + "4" * 64,
            "launchAuthorityWitnessAdministrativeDomainSha256": (
                "sha256:" + "5" * 64
            ),
            "launchAuthorityWitnessStoreAssuranceSha256": (
                "sha256:" + "6" * 64
            ),
            "globalRoleRegistry": global_role_registry,
            "globalRoleRegistrySha256": launch_authorization.launch_global_role_registry_sha256(global_role_registry),
            "globalRoleRegistryPinsSha256": "sha256:" + hashlib.sha256(b"fixture-global-role-registry-pins").hexdigest(),
            "launchAttemptJournalDomain": launch_authorization.LAUNCH_ATTEMPT_JOURNAL_DOMAIN,
        }
        request["launchAttemptRecoveryIdentitySha256"] = (
            launch_authorization.launch_attempt_recovery_identity_sha256(request)
        )
        request_sha256 = (
            run_production_readiness._v2_launch_authorization_request_sha256(
                request
            )
        )
        key_spki = authority_spki(key)
        authorization_id = "2" * 64
        authority_key_id = launch_authorization.spki_key_id(key_spki)
        witness_statement = {
            "operation": launch_authorization.WITNESS_OPERATION,
            "operationId": request["launcherNonce"],
            "authorizationId": authorization_id,
            "requestSha256": request_sha256,
            "challenge": request["launchAuthorityWitnessChallenge"],
            "issuedAtUnixSeconds": selected_issued_at,
            "expiresAtUnixSeconds": selected_expires_at,
            "authorityKeyId": authority_key_id,
            "witnessKeyId": request["launchAuthorityWitnessKeyId"],
            "witnessIdentitySha256": request[
                "launchAuthorityWitnessIdentitySha256"
            ],
            "witnessAdministrativeDomainSha256": request[
                "launchAuthorityWitnessAdministrativeDomainSha256"
            ],
            "storeAssuranceSha256": request[
                "launchAuthorityWitnessStoreAssuranceSha256"
            ],
            "registryGeneration": 5,
            "registrySha256": "sha256:" + "7" * 64,
            "predecessorStateSha256": "sha256:" + "8" * 64,
            "successorStateSha256": "sha256:" + "9" * 64,
            "deploymentAudience": request["deploymentAudience"],
            "deploymentIdentitySha256": request["deploymentIdentitySha256"],
            "releaseSequence": request["releaseSequence"],
            "rollbackEpoch": request["rollbackEpoch"],
            "authorizationScope": request["authorizationScope"],
            "stateTransitionCommitted": True,
            "checkpointSequence": 11,
        }
        witness = {
            "apiVersion": launch_authorization.WITNESS_API_VERSION,
            "kind": launch_authorization.WITNESS_KIND,
            "statement": witness_statement,
            "signature": launch_authorization.canonical_base64url(
                witness_key.sign(
                    launch_authorization.launch_authority_witness_signing_bytes(
                        witness_statement
                    )
                )
            ),
        }
        envelope = launch_authorization.sign_launch_authorization(
            request,
            private_key=key,
            authorization_id=authorization_id,
            issued_at_unix_seconds=selected_issued_at,
            expires_at_unix_seconds=selected_expires_at,
            monotonic_witness=witness,
        )
        return {
            "request": request,
            "requestSha256": request_sha256,
            "envelope": envelope,
            "authorizationSha256": "sha256:"
            + hashlib.sha256(
                launch_authorization.canonical_json_bytes(envelope)
            ).hexdigest(),
            "witnessPublicKeySpkiDerBase64url": (
                launch_authorization.canonical_base64url(
                    authority_spki(witness_key)
                )
            ),
            "verifiedAtUnixSeconds": selected_verified_at,
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
    run_production_readiness.validate_nonce_rollback_assurance_contract(
        pins_contract
    )
    contract_mutations = []
    unknown_contract = json.loads(json.dumps(pins_contract))
    unknown_contract["unexpected"] = True
    contract_mutations.append(("unknown pins field", unknown_contract))
    missing_store_attestation_key = json.loads(json.dumps(pins_contract))
    missing_store_attestation_key["publicConfigPins"].pop(
        "nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url"
    )
    contract_mutations.append(
        ("missing verifier-state store attestation key", missing_store_attestation_key)
    )
    stale_store_key_alias = json.loads(json.dumps(pins_contract))
    stale_store_key_alias["publicConfigPins"][
        "nonceAuthorityVerifierStateStoreAttestationSigningPublicKeySpkiDerBase64url"
    ] = stale_store_key_alias["publicConfigPins"].pop(
        "nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url"
    )
    contract_mutations.append(
        ("stale verifier-state store attestation key alias", stale_store_key_alias)
    )
    missing_store_assurance_evidence = json.loads(
        json.dumps(pins_contract)
    )
    missing_store_assurance_evidence["publicConfigPins"].pop(
        "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"
    )
    contract_mutations.append(
        (
            "missing verifier-state store assurance evidence",
            missing_store_assurance_evidence,
        )
    )
    stale_store_assurance_alias = json.loads(json.dumps(pins_contract))
    stale_store_assurance_alias["publicConfigPins"][
        "nonceAuthorityVerifierStateStoreAssuranceSha256"
    ] = stale_store_assurance_alias["publicConfigPins"].pop(
        "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"
    )
    contract_mutations.append(
        (
            "stale verifier-state store assurance evidence alias",
            stale_store_assurance_alias,
        )
    )
    wrong_profile = json.loads(json.dumps(pins_contract))
    wrong_profile["publicConfigPins"]["nonceAuthorityAssurance"][
        "backendClass"
    ] = "unapprovedBackend"
    contract_mutations.append(("wrong assurance profile", wrong_profile))
    colliding_roles = json.loads(json.dumps(pins_contract))
    colliding_roles["publicConfigPins"][
        "nonceAuthorityVerifierStateStoreIdentitySha256"
    ] = assurance["authorityIdentitySha256"]
    contract_mutations.append(("authority and store collision", colliding_roles))
    colliding_store_evidence = json.loads(json.dumps(pins_contract))
    colliding_store_evidence["publicConfigPins"][
        "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"
    ] = assurance["assuranceEvidenceSha256"]
    contract_mutations.append(
        ("authority and store assurance evidence collision", colliding_store_evidence)
    )
    unsafe_integer = json.loads(json.dumps(pins_contract))
    unsafe_integer["publicConfigPins"]["nonceAuthorityAssurance"][
        "authorityGeneration"
    ] = (1 << 53)
    contract_mutations.append(("non-interoperable integer", unsafe_integer))
    for label, mutated_contract in contract_mutations:
        try:
            run_production_readiness.validate_nonce_rollback_assurance_contract(
                mutated_contract
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                f"nonce rollback assurance accepted {label}"
            )
    manual_assurance = (
        run_production_readiness.validate_retained_nonce_rollback_assurance(
            retained_path=None,
            expected_pins_sha256=None,
            expected_contract_sha256=None,
            bootstrap_receipt=None,
            required=False,
        )
    )
    if manual_assurance != {
        "apiVersion": (
            run_production_readiness.NONCE_ROLLBACK_ASSURANCE_BINDING_API_VERSION
        ),
        "enforcement": "not-native-launcher-enforced",
        "verified": False,
    }:
        raise AssertionError(
            f"manual nonce rollback assurance classification is invalid: {manual_assurance}"
        )
    try:
        run_production_readiness.validate_retained_nonce_rollback_assurance(
            retained_path="/proc/self/fd/199",
            expected_pins_sha256=pins_file_sha256,
            expected_contract_sha256=pins_contract_sha256,
            bootstrap_receipt=None,
            required=False,
        )
    except ValueError:
        pass
    else:
        raise AssertionError(
            "manual readiness accepted launcher nonce assurance arguments"
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
    expected_authorization_errors = {
        "global role registry digest mismatch": (
            "request global role registry digest binding mismatch"
        ),
        "global role key reuse": (
            "launch global role registry reuses an SPKI across security roles"
        ),
        "launch attempt journal domain mismatch": (
            "request launchAttemptJournalDomain must equal "
            "'serverware.launchAuthorizationAttemptJournal/v1'"
        ),
        "launch attempt recovery identity mismatch": (
            "request launch attempt recovery identity binding mismatch"
        ),
    }

    def mutate(label: str) -> dict[str, object]:
        value = json.loads(json.dumps(receipt))
        authorization_mutations.append((label, value))
        return value

    mutate("request digest mismatch")["launchAuthorization"]["requestSha256"] = (
        "sha256:" + "1" * 64
    )
    for field in (
        "globalRoleRegistry", "globalRoleRegistrySha256", "globalRoleRegistryPinsSha256",
        "launchAttemptJournalDomain", "launchAttemptRecoveryIdentitySha256",
    ):
        label = f"missing {field}"
        mutate(label)["launchAuthorization"]["request"].pop(field)
        expected_authorization_errors[label] = (
            f"launch authorization request is missing required fields: ['{field}']"
        )
    mutate("global role registry digest mismatch")["launchAuthorization"]["request"][
        "globalRoleRegistrySha256"
    ] = "sha256:" + "1" * 64
    collision = mutate("global role key reuse")["launchAuthorization"]["request"]["globalRoleRegistry"]["roles"]
    collision["policyIdentity"] = collision["launchAuthority"]
    mutate("launch attempt journal domain mismatch")["launchAuthorization"]["request"][
        "launchAttemptJournalDomain"
    ] = "serverware.unrelatedJournal/v1"
    mutate("launch attempt recovery identity mismatch")["launchAuthorization"]["request"][
        "launchAttemptRecoveryIdentitySha256"
    ] = "sha256:" + "1" * 64
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
    wrong_witness_key_receipt = mutate("witness key mismatch")
    wrong_witness_key_receipt["launchAuthorization"][
        "witnessPublicKeySpkiDerBase64url"
    ] = launch_authorization.canonical_base64url(
        authority_spki(wrong_key)
    )
    mutate("nonce mismatch")["launchAuthorization"]["request"]["launcherNonce"] = (
        "9" * 64
    )
    mutate("manifest mismatch")["manifest"]["sha256"] = "sha256:" + "1" * 64
    mutate("nonce contract mismatch")["nonceRollbackAssurance"][
        "contractSha256"
    ] = "sha256:" + "1" * 64
    mutate("nonce pins mismatch")["nonceRollbackAssurance"][
        "retainedSnapshotSha256"
    ] = "sha256:" + "1" * 64
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
        except ValueError as exc:
            expected = expected_authorization_errors.get(label)
            if expected is not None and expected not in str(exc):
                raise AssertionError(
                    f"bootstrap receipt rejected {label} at the wrong guard; "
                    f"expected {expected!r}, got {str(exc)!r}"
                ) from exc
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

    def load_from_fixed_receipt_fd(
        descriptor: int,
        environment: dict[str, str],
    ) -> tuple[dict[str, object] | None, int | None]:
        try:
            saved_fixed_descriptor = os.dup(
                run_production_readiness.BOOTSTRAP_RECEIPT_FIXED_FD
            )
        except OSError:
            saved_fixed_descriptor = None
        try:
            os.dup2(
                descriptor,
                run_production_readiness.BOOTSTRAP_RECEIPT_FIXED_FD,
                inheritable=True,
            )
            return run_production_readiness.load_sealed_bootstrap_receipt(
                {
                    **environment,
                    run_production_readiness.BOOTSTRAP_RECEIPT_FD_ENV: str(
                        run_production_readiness.BOOTSTRAP_RECEIPT_FIXED_FD
                    ),
                },
                required=True,
            )
        finally:
            try:
                os.close(run_production_readiness.BOOTSTRAP_RECEIPT_FIXED_FD)
            except OSError:
                pass
            if saved_fixed_descriptor is not None:
                os.dup2(
                    saved_fixed_descriptor,
                    run_production_readiness.BOOTSTRAP_RECEIPT_FIXED_FD,
                    inheritable=True,
                )
                os.close(saved_fixed_descriptor)

    canonical = canonical_json(receipt).encode("ascii")
    descriptor = open_receipt(canonical, seal=True)
    environment = {
        run_production_readiness.BOOTSTRAP_RECEIPT_FD_ENV: str(
            run_production_readiness.BOOTSTRAP_RECEIPT_FIXED_FD
        ),
        run_production_readiness.BOOTSTRAP_RECEIPT_SHA256_ENV: (
            "sha256:" + hashlib.sha256(canonical).hexdigest()
        ),
        run_production_readiness.BOOTSTRAP_RECEIPT_API_VERSION_ENV: (
            run_production_readiness.BOOTSTRAP_RECEIPT_API_VERSION
        ),
    }
    try:
        wrong_descriptor = (
            descriptor
            if descriptor
            != run_production_readiness.BOOTSTRAP_RECEIPT_FIXED_FD
            else descriptor + 1
        )
        try:
            run_production_readiness.load_sealed_bootstrap_receipt(
                {
                    **environment,
                    run_production_readiness.BOOTSTRAP_RECEIPT_FD_ENV: str(
                        wrong_descriptor
                    ),
                },
                required=True,
            )
        except ValueError as exc:
            if "must be exactly 198" not in str(exc):
                raise
        else:
            raise AssertionError(
                "bootstrap receipt loader accepted a descriptor other than FD 198"
            )
        summary, selected = load_from_fixed_receipt_fd(
            descriptor,
            environment,
        )
        if (
            selected != run_production_readiness.BOOTSTRAP_RECEIPT_FIXED_FD
            or summary is None
            or summary.get("sealed") is not True
            or summary.get("launchId") != receipt["launchId"]
        ):
            raise AssertionError(f"sealed bootstrap receipt summary is invalid: {summary}")
        original_time = run_production_readiness.time.time
        run_production_readiness.time.time = lambda: receipt[
            "launchAuthorization"
        ]["envelope"]["statement"]["expiresAtUnixSeconds"]
        try:
            try:
                load_from_fixed_receipt_fd(descriptor, environment)
            except ValueError as exc:
                if "not current at consumption" not in str(exc):
                    raise
            else:
                raise AssertionError(
                    "bootstrap receipt loader accepted an authorization expired at consumption"
                )
        finally:
            run_production_readiness.time.time = original_time
    finally:
        os.close(descriptor)

    pins_descriptor = open_receipt(pins_bytes, seal=True)
    retained_receipt = json.loads(json.dumps(receipt))
    retained_receipt["nonceRollbackAssurance"][
        "retainedSnapshotFd"
    ] = pins_descriptor
    try:
        retained = (
            run_production_readiness.validate_retained_nonce_rollback_assurance(
                retained_path=f"/proc/self/fd/{pins_descriptor}",
                expected_pins_sha256=pins_file_sha256,
                expected_contract_sha256=pins_contract_sha256,
                bootstrap_receipt=retained_receipt,
                required=True,
            )
        )
        if (
            retained.get("verified") is not True
            or retained.get("retainedSnapshotFd") != pins_descriptor
            or retained.get("contractSha256") != pins_contract_sha256
            or retained.get("verifierStateService")
            != retained_receipt["nonceRollbackAssurance"][
                "verifierStateService"
            ]
        ):
            raise AssertionError(
                f"retained nonce rollback assurance summary is invalid: {retained}"
            )
        colliding_receipt = json.loads(json.dumps(retained_receipt))
        colliding_receipt["nonceRollbackAssurance"][
            "retainedSnapshotFd"
        ] = run_production_readiness.BOOTSTRAP_RECEIPT_FIXED_FD
        try:
            run_production_readiness.validate_retained_nonce_rollback_assurance(
                retained_path=(
                    f"/proc/self/fd/"
                    f"{run_production_readiness.BOOTSTRAP_RECEIPT_FIXED_FD}"
                ),
                expected_pins_sha256=pins_file_sha256,
                expected_contract_sha256=pins_contract_sha256,
                bootstrap_receipt=colliding_receipt,
                required=True,
            )
        except ValueError as exc:
            if "collides with the fixed bootstrap receipt descriptor" not in str(
                exc
            ):
                raise
        else:
            raise AssertionError(
                "retained nonce rollback assurance accepted fixed receipt FD "
                "198 as its pins descriptor"
            )
        for label, path, file_digest, contract_digest in (
            (
                "malformed descriptor path",
                f"/dev/fd/{pins_descriptor}",
                pins_file_sha256,
                pins_contract_sha256,
            ),
            (
                "pins digest substitution",
                f"/proc/self/fd/{pins_descriptor}",
                "sha256:" + "1" * 64,
                pins_contract_sha256,
            ),
            (
                "contract digest substitution",
                f"/proc/self/fd/{pins_descriptor}",
                pins_file_sha256,
                "sha256:" + "1" * 64,
            ),
        ):
            try:
                run_production_readiness.validate_retained_nonce_rollback_assurance(
                    retained_path=path,
                    expected_pins_sha256=file_digest,
                    expected_contract_sha256=contract_digest,
                    bootstrap_receipt=retained_receipt,
                    required=True,
                )
            except ValueError:
                pass
            else:
                raise AssertionError(
                    f"retained nonce rollback assurance accepted {label}"
                )
        substituted_service_receipt = json.loads(
            json.dumps(retained_receipt)
        )
        substituted_service_receipt["nonceRollbackAssurance"][
            "verifierStateService"
        ]["storeAssuranceEvidenceSha256"] = "sha256:" + "1" * 64
        try:
            run_production_readiness.validate_retained_nonce_rollback_assurance(
                retained_path=f"/proc/self/fd/{pins_descriptor}",
                expected_pins_sha256=pins_file_sha256,
                expected_contract_sha256=pins_contract_sha256,
                bootstrap_receipt=substituted_service_receipt,
                required=True,
            )
        except ValueError as exc:
            if "verifier-state service configuration" not in str(exc):
                raise
        else:
            raise AssertionError(
                "retained nonce rollback assurance accepted a substituted "
                "verifier-state service configuration"
            )
    finally:
        os.close(pins_descriptor)

    unsealed_pins = open_receipt(pins_bytes, seal=False)
    unsealed_pins_receipt = json.loads(json.dumps(receipt))
    unsealed_pins_receipt["nonceRollbackAssurance"][
        "retainedSnapshotFd"
    ] = unsealed_pins
    try:
        try:
            run_production_readiness.validate_retained_nonce_rollback_assurance(
                retained_path=f"/proc/self/fd/{unsealed_pins}",
                expected_pins_sha256=pins_file_sha256,
                expected_contract_sha256=pins_contract_sha256,
                bootstrap_receipt=unsealed_pins_receipt,
                required=True,
            )
        except ValueError as exc:
            if "immutable seals" not in str(exc):
                raise
        else:
            raise AssertionError(
                "retained nonce rollback assurance accepted an unsealed descriptor"
            )
    finally:
        os.close(unsealed_pins)

    replaced_pins = open_receipt(pins_bytes + b" ", seal=True)
    replaced_pins_receipt = json.loads(json.dumps(receipt))
    replaced_pins_receipt["nonceRollbackAssurance"][
        "retainedSnapshotFd"
    ] = replaced_pins
    try:
        try:
            run_production_readiness.validate_retained_nonce_rollback_assurance(
                retained_path=f"/proc/self/fd/{replaced_pins}",
                expected_pins_sha256=pins_file_sha256,
                expected_contract_sha256=pins_contract_sha256,
                bootstrap_receipt=replaced_pins_receipt,
                required=True,
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                "retained nonce rollback assurance accepted replaced bytes"
            )
    finally:
        os.close(replaced_pins)

    unsealed = open_receipt(canonical, seal=False)
    try:
        try:
            load_from_fixed_receipt_fd(
                unsealed,
                environment,
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
    v2_downgrade = json.loads(json.dumps(receipt))
    v2_downgrade["apiVersion"] = "serverware.bootstrapReceipt/v2"
    mutations.append(("v2 receipt downgrade", v2_downgrade))
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
                load_from_fixed_receipt_fd(
                    mutated_descriptor,
                    {
                        **environment,
                        run_production_readiness.BOOTSTRAP_RECEIPT_SHA256_ENV: (
                            "sha256:" + hashlib.sha256(mutated_bytes).hexdigest()
                        ),
                    },
                )
            except ValueError:
                pass
            else:
                raise AssertionError(f"bootstrap receipt accepted {label}")
        finally:
            os.close(mutated_descriptor)
    run_production_readiness.load_launch_authority_identity = original_key_loader


def verify_proxy_trust_input_path_security() -> None:
    with tempfile.TemporaryDirectory(
        dir=test_temp_root(),
        prefix="readiness-trust-paths-",
    ) as raw_tmp:
        root = Path(raw_tmp)
        output_paths = {"proxy proof output": str(root / "proof.json")}
        inputs = {
            "proxy CA bundle": root / "ca.pem",
            "proxy collector private key": root / "collector-key.pem",
            "proxy collector public key": root / "collector-key.pub.pem",
            "proxy verifier public key": root / "verifier.pub.pem",
        }
        for label, path in inputs.items():
            path.write_bytes(f"{label}\n".encode("ascii"))
            path.chmod(0o600 if label == "proxy collector private key" else 0o644)
        run_production_readiness.validate_proxy_artifact_path_separation(
            output_paths,
            {label: str(path) for label, path in inputs.items()},
        )

        symlinked = root / "ca-link.pem"
        symlinked.symlink_to(inputs["proxy CA bundle"])
        symlink_inputs = {**inputs, "proxy CA bundle": symlinked}
        try:
            run_production_readiness.validate_proxy_artifact_path_separation(
                output_paths,
                {label: str(path) for label, path in symlink_inputs.items()},
            )
        except ValueError as exc:
            if "without following symlinks" not in str(exc):
                raise
        else:
            raise AssertionError("runner accepted a symlinked proxy trust input")

        hardlink = root / "ca-hardlink.pem"
        os.link(inputs["proxy CA bundle"], hardlink)
        try:
            run_production_readiness.validate_proxy_artifact_path_separation(
                output_paths,
                {label: str(path) for label, path in inputs.items()},
            )
        except ValueError as exc:
            if "single-link regular file" not in str(exc):
                raise
        else:
            raise AssertionError("runner accepted a multi-link proxy trust input")
        hardlink.unlink()

        fifo = root / "ca.fifo"
        os.mkfifo(fifo, 0o600)
        fifo_inputs = {**inputs, "proxy CA bundle": fifo}
        try:
            run_production_readiness.validate_proxy_artifact_path_separation(
                output_paths,
                {label: str(path) for label, path in fifo_inputs.items()},
            )
        except ValueError as exc:
            if "single-link regular file" not in str(exc):
                raise
        else:
            raise AssertionError("runner accepted a FIFO proxy trust input")

        unsafe_parent = root / "unsafe"
        unsafe_parent.mkdir(mode=0o770)
        unsafe_parent.chmod(0o770)
        unsafe_ca = unsafe_parent / "ca.pem"
        unsafe_ca.write_bytes(b"unsafe\n")
        unsafe_ca.chmod(0o600)
        unsafe_inputs = {**inputs, "proxy CA bundle": unsafe_ca}
        try:
            run_production_readiness.validate_proxy_artifact_path_separation(
                output_paths,
                {label: str(path) for label, path in unsafe_inputs.items()},
            )
        except ValueError as exc:
            if "must not be writable by group/other" not in str(exc):
                raise
        else:
            raise AssertionError("runner accepted a writable proxy trust ancestor")

        alias_parent = root / "trust-alias"
        alias_parent.symlink_to(root, target_is_directory=True)
        alias_inputs = {
            **inputs,
            "proxy CA bundle": alias_parent / inputs["proxy CA bundle"].name,
        }
        try:
            run_production_readiness.validate_proxy_artifact_path_separation(
                output_paths,
                {label: str(path) for label, path in alias_inputs.items()},
            )
        except ValueError as exc:
            if "without following symlinks" not in str(exc):
                raise
        else:
            raise AssertionError("runner accepted a symlinked proxy trust ancestor")

        normalized_alias = str(root) + "//proof.json"
        try:
            run_production_readiness.validate_proxy_artifact_path_separation(
                {"proxy proof output": normalized_alias},
                {label: str(path) for label, path in inputs.items()},
            )
        except ValueError as exc:
            if "normalized and absolute" not in str(exc):
                raise
        else:
            raise AssertionError("runner accepted a non-normalized proxy output path")

        replaceable = root / "replaceable.pem"
        displaced = root / "opened-replaceable.pem"
        replaceable.write_bytes(b"opened bytes")
        replaceable.chmod(0o600)
        original_read_fd_bytes = run_production_readiness.read_fd_bytes

        def replace_after_open(
            descriptor: int,
            opened: os.stat_result,
            label: str,
            *,
            max_bytes: int,
        ) -> bytes:
            replaceable.rename(displaced)
            replaceable.write_bytes(b"replacement")
            replaceable.chmod(0o600)
            return original_read_fd_bytes(
                descriptor,
                opened,
                label,
                max_bytes=max_bytes,
            )

        run_production_readiness.read_fd_bytes = replace_after_open
        try:
            run_production_readiness.read_regular_file_once(
                replaceable,
                "proxy CA bundle",
                max_bytes=1024,
            )
        except ValueError as exc:
            if "changed while being read" not in str(exc):
                raise
        else:
            raise AssertionError("runner accepted a replaced trust-input pathname")
        finally:
            run_production_readiness.read_fd_bytes = original_read_fd_bytes


def verify_completion_authorization_freshness_boundaries() -> None:
    receipt = {"fixture": "sealed-fd-198-receipt"}
    original_validate = (
        run_production_readiness.validate_bootstrap_receipt_summary
    )
    original_identity = (
        run_production_readiness.bootstrap_launch_authorization_identity
    )
    run_production_readiness.validate_bootstrap_receipt_summary = (
        lambda value: value
    )
    run_production_readiness.bootstrap_launch_authorization_identity = (
        lambda value: {
            "authorization_sha256": _fixture_digest(
                "completion-freshness-authorization"
            ),
            "expires_at_unix_seconds": 120,
        }
    )
    try:
        result = (
            run_production_readiness
            .revalidate_bootstrap_launch_authorization_at_completion(
                expected_receipt=receipt,
                expected_descriptor=198,
                generated_at_unix=119,
                now_unix_seconds=119,
                receipt_loader=lambda *, required: (receipt, 198),
            )
        )
        if result["freshAtCompletion"] is not True:
            raise AssertionError(
                "completion freshness revalidation did not pass before expiry"
            )

        for label, generated_at, published_at in (
            ("generation at expiry", 120, 119),
            ("publication at expiry", 119, 120),
        ):
            try:
                (
                    run_production_readiness
                    .revalidate_bootstrap_launch_authorization_at_completion(
                        expected_receipt=receipt,
                        expected_descriptor=198,
                        generated_at_unix=generated_at,
                        now_unix_seconds=published_at,
                        receipt_loader=lambda *, required: (receipt, 198),
                    )
                )
            except ValueError as exc:
                if "expired before completion" not in str(exc):
                    raise
            else:
                raise AssertionError(
                    f"completion freshness accepted {label}"
                )

        try:
            (
                run_production_readiness
                .revalidate_bootstrap_launch_authorization_at_completion(
                    expected_receipt=receipt,
                    expected_descriptor=197,
                    generated_at_unix=119,
                    now_unix_seconds=119,
                    receipt_loader=lambda *, required: (receipt, 198),
                )
            )
        except ValueError as exc:
            if "exact FD 198" not in str(exc):
                raise
        else:
            raise AssertionError(
                "completion freshness accepted a non-FD-198 authorization"
            )

        try:
            (
                run_production_readiness
                .revalidate_bootstrap_launch_authorization_at_completion(
                    expected_receipt=receipt,
                    expected_descriptor=198,
                    generated_at_unix=119,
                    now_unix_seconds=119,
                    receipt_loader=lambda *, required: (
                        {"fixture": "replacement"},
                        198,
                    ),
                )
            )
        except ValueError as exc:
            if "changed before completion publication" not in str(exc):
                raise
        else:
            raise AssertionError(
                "completion freshness accepted a replaced FD 198 receipt"
            )
    finally:
        run_production_readiness.validate_bootstrap_receipt_summary = (
            original_validate
        )
        run_production_readiness.bootstrap_launch_authorization_identity = (
            original_identity
        )


def main() -> None:
    verify_launcher_style_helper_import()
    verify_proof_policy_identity_contract()
    for invalid_path in ("relative/path", "/", "/tmp/../etc/passwd", "/tmp//receipt", "/tmp/receipt/"):
        try:
            run_production_readiness._normalized_absolute_receipt_path(invalid_path, "test")
        except ValueError:
            pass
        else:
            raise AssertionError(f"bootstrap receipt accepted a non-normalized path: {invalid_path}")
    verify_sealed_bootstrap_receipt_contract()
    verify_proxy_trust_input_path_security()
    verify_completion_authorization_freshness_boundaries()
    with tempfile.TemporaryDirectory(
        dir=test_temp_root(),
        prefix="readiness-runner-",
    ) as tmp_raw:
        tmp = Path(tmp_raw).resolve()
        expected_client_request_digest = "sha256:" + "a" * 64
        expected_request_digest = "sha256:" + "b" * 64
        expected_operation_digest = "sha256:" + "c" * 64
        expected_operation_context_digest = "sha256:" + "d" * 64
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
        minimal_env = tmp / "minimal.env"
        minimal_values = {
                "SERVERWARE_RELEASE_CHANNEL": "prod",
                "SERVERWARE_ADMIN_TOKEN": "prod-admin-token-32-bytes-minimum-value",
                "SERVERWARE_OIDC_JWKS_JSON": canonical_json({"keys": [{"kid": "prod key"}]}),
                "SERVERWARE_PROXY_RESPONSE_PROOF_FILE": str(tmp / "proxy-response-proof.json"),
                "SERVERWARE_PROXY_PROOF_CONTRACT": "buffered-v3",
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
        for setting in (
            "SERVERWARE_PROXY_PROOF_CA_BUNDLE",
            "SERVERWARE_PROXY_PROOF_COLLECTOR_PRIVATE_KEY",
            "SERVERWARE_PROXY_PROOF_COLLECTOR_PUBLIC_KEY",
            "SERVERWARE_PROXY_PROOF_VERIFIER_PUBLIC_KEY",
        ):
            path = Path(minimal_values[setting])
            path.write_bytes(f"{setting}\n".encode("ascii"))
            path.chmod(
                0o600
                if setting == "SERVERWARE_PROXY_PROOF_COLLECTOR_PRIVATE_KEY"
                else 0o644
            )
        write_env(minimal_env, minimal_values)
        missing_readiness_contract_env = tmp / "missing-readiness-proof-contract.env"
        write_env(
            missing_readiness_contract_env,
            {
                key: value
                for key, value in minimal_values.items()
                if key != run_production_readiness.PROXY_PROOF_CONTRACT_ENV
            },
        )
        missing_readiness_contract = run_runner(
            "--env-file",
            str(missing_readiness_contract_env),
            "--dry-run",
            *security_args,
        )
        if (
            missing_readiness_contract.returncode == 0
            or run_production_readiness.PROXY_PROOF_CONTRACT_ENV
            not in detail(missing_readiness_contract)
        ):
            raise AssertionError(
                "runner accepted readiness verification without an env-pinned proof contract: "
                + detail(missing_readiness_contract)
            )
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
            or collector_argv[
                collector_argv.index("--control-plane-response-key") + 1
            ]
            != str(trust_paths["control_plane_response_signing_public_key"])
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
            or completion_argv[completion_argv.index("--proxy-proof-contract") + 1]
            != "buffered-v3"
            or "--stream" in collector_argv
            or "--body-out" in collector_argv
            or "--max-stream-bytes" in collector_argv
            or "--proxy-stream-body" in completion_argv
            or "--proxy-max-stream-bytes" in completion_argv
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

        streaming_body_path = tmp / "proxy-response-body.bin"
        streaming_env = tmp / "streaming.env"
        write_env(
            streaming_env,
            {
                **minimal_values,
                "SERVERWARE_PROXY_PROOF_CONTRACT": "streaming-v1",
                "SERVERWARE_PROXY_STREAM_BODY_FILE": str(streaming_body_path),
                "SERVERWARE_PROXY_PROOF_MAX_STREAM_BYTES": "4096",
                "SERVERWARE_PROXY_EXPECTED_OPERATION_CONTEXT_DIGEST": expected_operation_context_digest,
            },
        )
        streaming_dry_run = run_runner(
            "--env-file",
            str(streaming_env),
            "--dry-run",
            *security_args,
        )
        if streaming_dry_run.returncode != 0:
            raise AssertionError(
                f"runner rejected a complete streaming proof configuration: {detail(streaming_dry_run)}"
            )
        streaming_plan = json.loads(streaming_dry_run.stdout.decode("utf-8"))
        streaming_collector_argv = streaming_plan["commands"][-2]["argv"]
        streaming_completion_argv = streaming_plan["commands"][-1]["argv"]
        if (
            "--stream" not in streaming_collector_argv
            or streaming_collector_argv[
                streaming_collector_argv.index("--body-out") + 1
            ]
            != str(streaming_body_path)
            or streaming_collector_argv[
                streaming_collector_argv.index("--max-stream-bytes") + 1
            ]
            != "4096"
            or streaming_completion_argv[
                streaming_completion_argv.index("--proxy-proof-contract") + 1
            ]
            != "streaming-v1"
            or streaming_completion_argv[
                streaming_completion_argv.index("--proxy-stream-body") + 1
            ]
            != str(streaming_body_path)
            or streaming_completion_argv[
                streaming_completion_argv.index("--proxy-max-stream-bytes") + 1
            ]
            != "4096"
            or streaming_completion_argv[
                streaming_completion_argv.index("--proxy-operation-context-digest")
                + 1
            ]
            != expected_operation_context_digest
        ):
            raise AssertionError(
                "runner did not propagate the independently selected streaming proof contract: "
                f"collector={streaming_collector_argv} completion={streaming_completion_argv}"
            )
        for missing_setting in (
            "SERVERWARE_PROXY_STREAM_BODY_FILE",
            "SERVERWARE_PROXY_PROOF_MAX_STREAM_BYTES",
            "SERVERWARE_PROXY_EXPECTED_OPERATION_CONTEXT_DIGEST",
        ):
            incomplete_streaming_env = tmp / f"missing-{missing_setting.lower()}.env"
            incomplete_values = {
                **minimal_values,
                "SERVERWARE_PROXY_PROOF_CONTRACT": "streaming-v1",
                "SERVERWARE_PROXY_STREAM_BODY_FILE": str(streaming_body_path),
                "SERVERWARE_PROXY_PROOF_MAX_STREAM_BYTES": "4096",
                "SERVERWARE_PROXY_EXPECTED_OPERATION_CONTEXT_DIGEST": expected_operation_context_digest,
            }
            incomplete_values.pop(missing_setting)
            write_env(incomplete_streaming_env, incomplete_values)
            incomplete_streaming = run_runner(
                "--env-file",
                str(incomplete_streaming_env),
                "--dry-run",
                *security_args,
            )
            if (
                incomplete_streaming.returncode == 0
                or missing_setting not in detail(incomplete_streaming)
            ):
                raise AssertionError(
                    f"runner accepted streaming-v1 without {missing_setting}: "
                    + detail(incomplete_streaming)
                )

        for stream_limit, should_succeed in (
            (run_production_readiness.MAX_PROXY_STREAM_BODY_BYTES, True),
            (run_production_readiness.MAX_PROXY_STREAM_BODY_BYTES + 1, False),
        ):
            boundary_env = tmp / f"stream-limit-{stream_limit}.env"
            write_env(
                boundary_env,
                {
                    **minimal_values,
                    "SERVERWARE_PROXY_PROOF_CONTRACT": "streaming-v1",
                    "SERVERWARE_PROXY_STREAM_BODY_FILE": str(streaming_body_path),
                    "SERVERWARE_PROXY_PROOF_MAX_STREAM_BYTES": str(stream_limit),
                    "SERVERWARE_PROXY_EXPECTED_OPERATION_CONTEXT_DIGEST": expected_operation_context_digest,
                },
            )
            boundary_result = run_runner(
                "--env-file", str(boundary_env), "--dry-run", *security_args
            )
            if should_succeed and boundary_result.returncode != 0:
                raise AssertionError(
                    "runner rejected the exact stream body byte ceiling: "
                    + detail(boundary_result)
                )
            if not should_succeed and (
                boundary_result.returncode == 0
                or "proxy proof max stream bytes" not in detail(boundary_result)
            ):
                raise AssertionError(
                    "runner accepted a stream body ceiling above the fixed maximum: "
                    + detail(boundary_result)
                )

        observation_body_path = tmp / "proxy-observation-response-body.bin"
        observation_env = tmp / "observation.env"
        write_env(
            observation_env,
            {
                **minimal_values,
                "SERVERWARE_PROXY_PROOF_CONTRACT": "observation-v1",
                run_production_readiness.PROXY_OBSERVATION_BODY_FILE_ENV: str(
                    observation_body_path
                ),
                run_production_readiness.PROXY_PROOF_MAX_OBSERVATION_BODY_BYTES_ENV: "4096",
            },
        )
        observation_dry_run = run_runner(
            "--env-file",
            str(observation_env),
            "--dry-run",
            *security_args,
        )
        if observation_dry_run.returncode != 0:
            raise AssertionError(
                "runner rejected a complete observation proof configuration: "
                + detail(observation_dry_run)
            )
        mismatched_readiness_contract = run_runner(
            "--env-file",
            str(observation_env),
            "--dry-run",
            "--proxy-proof-contract",
            "buffered-v3",
            *security_args,
        )
        if (
            mismatched_readiness_contract.returncode == 0
            or "--proxy-proof-contract must match"
            not in detail(mismatched_readiness_contract)
        ):
            raise AssertionError(
                "runner accepted a readiness CLI contract downgrade against observation-v1: "
                + detail(mismatched_readiness_contract)
            )
        observation_plan = json.loads(observation_dry_run.stdout.decode("utf-8"))
        observation_collector_argv = observation_plan["commands"][-2]["argv"]
        observation_completion_argv = observation_plan["commands"][-1]["argv"]
        observation_nonce = observation_collector_argv[
            observation_collector_argv.index("--nonce") + 1
        ]
        observation_nonce_bytes = base64.urlsafe_b64decode(
            observation_nonce + "=" * (-len(observation_nonce) % 4)
        )
        observation_nonce_expiry = int.from_bytes(
            observation_nonce_bytes[:4], "big"
        )
        nonce_check_time = int(time.time())
        if (
            "--observation" not in observation_collector_argv
            or observation_collector_argv[
                observation_collector_argv.index("--body-out") + 1
            ]
            != str(observation_body_path)
            or observation_collector_argv[
                observation_collector_argv.index(
                    "--max-observation-body-bytes"
                )
                + 1
            ]
            != "4096"
            or len(observation_nonce_bytes) != 32
            or not any(observation_nonce_bytes[4:])
            or not nonce_check_time < observation_nonce_expiry <= nonce_check_time + 330
            or "--stream" in observation_collector_argv
            or "--max-stream-bytes" in observation_collector_argv
            or observation_completion_argv[
                observation_completion_argv.index("--proxy-proof-contract") + 1
            ]
            != "observation-v1"
            or observation_completion_argv[
                observation_completion_argv.index("--proxy-observation-body") + 1
            ]
            != str(observation_body_path)
            or observation_completion_argv[
                observation_completion_argv.index(
                    "--proxy-max-observation-body-bytes"
                )
                + 1
            ]
            != "4096"
            or "--proxy-stream-body" in observation_completion_argv
            or "--proxy-max-stream-bytes" in observation_completion_argv
            or "--proxy-operation-context-digest" in observation_completion_argv
        ):
            raise AssertionError(
                "runner did not propagate the independently selected observation proof contract: "
                f"collector={observation_collector_argv} completion={observation_completion_argv}"
            )
        for missing_setting in (
            run_production_readiness.PROXY_OBSERVATION_BODY_FILE_ENV,
            run_production_readiness.PROXY_PROOF_MAX_OBSERVATION_BODY_BYTES_ENV,
        ):
            incomplete_observation_env = (
                tmp / f"missing-{missing_setting.lower()}.env"
            )
            incomplete_values = {
                **minimal_values,
                "SERVERWARE_PROXY_PROOF_CONTRACT": "observation-v1",
                run_production_readiness.PROXY_OBSERVATION_BODY_FILE_ENV: str(
                    observation_body_path
                ),
                run_production_readiness.PROXY_PROOF_MAX_OBSERVATION_BODY_BYTES_ENV: "4096",
            }
            incomplete_values.pop(missing_setting)
            write_env(incomplete_observation_env, incomplete_values)
            incomplete_observation = run_runner(
                "--env-file",
                str(incomplete_observation_env),
                "--dry-run",
                *security_args,
            )
            if (
                incomplete_observation.returncode == 0
                or missing_setting not in detail(incomplete_observation)
            ):
                raise AssertionError(
                    f"runner accepted observation-v1 without {missing_setting}: "
                    + detail(incomplete_observation)
                )
        for observation_limit, should_succeed in (
            (0, False),
            (1, True),
            (run_production_readiness.MAX_PROXY_OBSERVATION_BODY_BYTES, True),
            (run_production_readiness.MAX_PROXY_OBSERVATION_BODY_BYTES + 1, False),
        ):
            boundary_env = tmp / f"observation-limit-{observation_limit}.env"
            write_env(
                boundary_env,
                {
                    **minimal_values,
                    "SERVERWARE_PROXY_PROOF_CONTRACT": "observation-v1",
                    run_production_readiness.PROXY_OBSERVATION_BODY_FILE_ENV: str(
                        observation_body_path
                    ),
                    run_production_readiness.PROXY_PROOF_MAX_OBSERVATION_BODY_BYTES_ENV: str(
                        observation_limit
                    ),
                },
            )
            boundary_result = run_runner(
                "--env-file", str(boundary_env), "--dry-run", *security_args
            )
            if should_succeed and boundary_result.returncode != 0:
                raise AssertionError(
                    "runner rejected a valid observation body byte ceiling: "
                    + detail(boundary_result)
                )
            if not should_succeed and (
                boundary_result.returncode == 0
                or "max observation body bytes" not in detail(boundary_result)
            ):
                raise AssertionError(
                    "runner accepted an invalid observation body byte ceiling: "
                    + detail(boundary_result)
                )
        for label, body_path, limit, expected_error in (
            (
                "relative-body",
                "relative-observation-body.bin",
                "4096",
                "must be an absolute path",
            ),
            (
                "colliding-body",
                minimal_values["SERVERWARE_PROXY_RESPONSE_PROOF_FILE"],
                "4096",
                "must use different filesystem locations",
            ),
            (
                "non-integer-limit",
                str(observation_body_path),
                "many",
                "must be an integer",
            ),
        ):
            invalid_observation_env = tmp / f"invalid-observation-{label}.env"
            write_env(
                invalid_observation_env,
                {
                    **minimal_values,
                    "SERVERWARE_PROXY_PROOF_CONTRACT": "observation-v1",
                    run_production_readiness.PROXY_OBSERVATION_BODY_FILE_ENV: body_path,
                    run_production_readiness.PROXY_PROOF_MAX_OBSERVATION_BODY_BYTES_ENV: limit,
                },
            )
            invalid_observation = run_runner(
                "--env-file",
                str(invalid_observation_env),
                "--dry-run",
                *security_args,
            )
            if (
                invalid_observation.returncode == 0
                or expected_error not in detail(invalid_observation)
            ):
                raise AssertionError(
                    f"runner accepted invalid observation setting {label}: "
                    + detail(invalid_observation)
                )
        dotdot_alias_env = tmp / "observation-dotdot-output-alias.env"
        write_env(
            dotdot_alias_env,
            {
                **minimal_values,
                "SERVERWARE_PROXY_PROOF_CONTRACT": "observation-v1",
                run_production_readiness.PROXY_OBSERVATION_BODY_FILE_ENV: str(
                    tmp / "body-alias" / ".." / "proxy-response-proof.json"
                ),
                run_production_readiness.PROXY_PROOF_MAX_OBSERVATION_BODY_BYTES_ENV: "4096",
            },
        )
        rejected_dotdot_alias = run_runner(
            "--env-file",
            str(dotdot_alias_env),
            "--dry-run",
            *security_args,
        )
        if (
            rejected_dotdot_alias.returncode == 0
            or "path must be normalized and absolute"
            not in detail(rejected_dotdot_alias)
        ):
            raise AssertionError(
                "runner accepted proof/body output aliases through a '..' path: "
                + detail(rejected_dotdot_alias)
            )

        alias_parent = tmp / "observation-artifact-parent"
        alias_parent.mkdir()
        alias_parent_link = tmp / "observation-artifact-parent-link"
        alias_parent_link.symlink_to(alias_parent, target_is_directory=True)
        symlink_parent_alias_env = tmp / "observation-symlink-parent-alias.env"
        write_env(
            symlink_parent_alias_env,
            {
                **minimal_values,
                "SERVERWARE_PROXY_RESPONSE_PROOF_FILE": str(
                    alias_parent / "shared-output"
                ),
                "SERVERWARE_PROXY_PROOF_CONTRACT": "observation-v1",
                run_production_readiness.PROXY_OBSERVATION_BODY_FILE_ENV: str(
                    alias_parent_link / "shared-output"
                ),
                run_production_readiness.PROXY_PROOF_MAX_OBSERVATION_BODY_BYTES_ENV: "4096",
            },
        )
        rejected_symlink_parent_alias = run_runner(
            "--env-file",
            str(symlink_parent_alias_env),
            "--dry-run",
            *security_args,
        )
        if (
            rejected_symlink_parent_alias.returncode == 0
            or "ancestor could not be opened without following symlinks"
            not in detail(rejected_symlink_parent_alias)
        ):
            raise AssertionError(
                "runner accepted proof/body output aliases through a symlinked parent: "
                + detail(rejected_symlink_parent_alias)
            )

        hardlink_proof = tmp / "observation-hardlink-proof.json"
        hardlink_body = tmp / "observation-hardlink-body.bin"
        hardlink_proof.write_bytes(b"fixture")
        os.link(hardlink_proof, hardlink_body)
        hardlink_alias_env = tmp / "observation-hardlink-output-alias.env"
        write_env(
            hardlink_alias_env,
            {
                **minimal_values,
                "SERVERWARE_PROXY_RESPONSE_PROOF_FILE": str(hardlink_proof),
                "SERVERWARE_PROXY_PROOF_CONTRACT": "observation-v1",
                run_production_readiness.PROXY_OBSERVATION_BODY_FILE_ENV: str(
                    hardlink_body
                ),
                run_production_readiness.PROXY_PROOF_MAX_OBSERVATION_BODY_BYTES_ENV: "4096",
            },
        )
        rejected_hardlink_alias = run_runner(
            "--env-file",
            str(hardlink_alias_env),
            "--dry-run",
            *security_args,
        )
        if (
            rejected_hardlink_alias.returncode == 0
            or "must be a single-link regular file"
            not in detail(rejected_hardlink_alias)
        ):
            raise AssertionError(
                "runner accepted proof/body outputs sharing an existing inode: "
                + detail(rejected_hardlink_alias)
            )
        observation_with_stream_setting = tmp / "observation-with-stream-setting.env"
        write_env(
            observation_with_stream_setting,
            {
                **minimal_values,
                "SERVERWARE_PROXY_PROOF_CONTRACT": "observation-v1",
                run_production_readiness.PROXY_OBSERVATION_BODY_FILE_ENV: str(
                    observation_body_path
                ),
                run_production_readiness.PROXY_PROOF_MAX_OBSERVATION_BODY_BYTES_ENV: "4096",
                "SERVERWARE_PROXY_EXPECTED_OPERATION_CONTEXT_DIGEST": expected_operation_context_digest,
            },
        )
        rejected_observation_stream_setting = run_runner(
            "--env-file",
            str(observation_with_stream_setting),
            "--dry-run",
            *security_args,
        )
        if (
            rejected_observation_stream_setting.returncode == 0
            or "only valid with proxy proof contract streaming-v1"
            not in detail(rejected_observation_stream_setting)
        ):
            raise AssertionError(
                "runner accepted a streaming-only operation context for observation-v1: "
                + detail(rejected_observation_stream_setting)
            )
        streaming_with_observation_setting = (
            tmp / "streaming-with-observation-setting.env"
        )
        write_env(
            streaming_with_observation_setting,
            {
                **minimal_values,
                "SERVERWARE_PROXY_PROOF_CONTRACT": "streaming-v1",
                "SERVERWARE_PROXY_STREAM_BODY_FILE": str(streaming_body_path),
                "SERVERWARE_PROXY_PROOF_MAX_STREAM_BYTES": "4096",
                "SERVERWARE_PROXY_EXPECTED_OPERATION_CONTEXT_DIGEST": expected_operation_context_digest,
                run_production_readiness.PROXY_OBSERVATION_BODY_FILE_ENV: str(
                    observation_body_path
                ),
            },
        )
        rejected_streaming_observation_setting = run_runner(
            "--env-file",
            str(streaming_with_observation_setting),
            "--dry-run",
            *security_args,
        )
        if (
            rejected_streaming_observation_setting.returncode == 0
            or "only valid with proxy proof contract observation-v1"
            not in detail(rejected_streaming_observation_setting)
        ):
            raise AssertionError(
                "runner accepted an observation-only body path for streaming-v1: "
                + detail(rejected_streaming_observation_setting)
            )

        buffered_with_stream_setting = tmp / "buffered-with-stream-setting.env"
        write_env(
            buffered_with_stream_setting,
            {
                **minimal_values,
                "SERVERWARE_PROXY_EXPECTED_OPERATION_CONTEXT_DIGEST": expected_operation_context_digest,
            },
        )
        rejected_buffered_stream_setting = run_runner(
            "--env-file",
            str(buffered_with_stream_setting),
            "--dry-run",
            *security_args,
        )
        if (
            rejected_buffered_stream_setting.returncode == 0
            or "matching proxy proof contracts"
            not in detail(rejected_buffered_stream_setting)
        ):
            raise AssertionError(
                "runner accepted a streaming-only operation context pin for buffered-v3: "
                + detail(rejected_buffered_stream_setting)
            )
        rejected_buffered_stream_cli = run_runner(
            "--env-file",
            str(minimal_env),
            "--dry-run",
            "--proxy-operation-context-digest",
            expected_operation_context_digest,
            *security_args,
        )
        if (
            rejected_buffered_stream_cli.returncode == 0
            or "matching proxy proof contracts"
            not in detail(rejected_buffered_stream_cli)
        ):
            raise AssertionError(
                "runner accepted a streaming-only CLI pin for buffered-v3: "
                + detail(rejected_buffered_stream_cli)
            )
        buffered_with_observation_setting = (
            tmp / "buffered-with-observation-setting.env"
        )
        write_env(
            buffered_with_observation_setting,
            {
                **minimal_values,
                run_production_readiness.PROXY_OBSERVATION_BODY_FILE_ENV: str(
                    observation_body_path
                ),
            },
        )
        rejected_buffered_observation_setting = run_runner(
            "--env-file",
            str(buffered_with_observation_setting),
            "--dry-run",
            *security_args,
        )
        if (
            rejected_buffered_observation_setting.returncode == 0
            or "matching proxy proof contracts"
            not in detail(rejected_buffered_observation_setting)
        ):
            raise AssertionError(
                "runner accepted an observation-only body path for buffered-v3: "
                + detail(rejected_buffered_observation_setting)
            )

        invalid_contract_env = tmp / "invalid-proof-contract.env"
        write_env(
            invalid_contract_env,
            {**minimal_values, "SERVERWARE_PROXY_PROOF_CONTRACT": "auto"},
        )
        invalid_contract = run_runner(
            "--env-file", str(invalid_contract_env), "--dry-run", *security_args
        )
        if invalid_contract.returncode == 0 or "observation-v1" not in detail(
            invalid_contract
        ):
            raise AssertionError(
                "runner accepted an untrusted or auto-selected proof contract: "
                + detail(invalid_contract)
            )

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
            "proof_contract": "buffered-v3",
        }
        collector_args = SimpleNamespace(
            proxy_client_nonce="n" * 43,
            proxy_client_request_digest=expected_client_request_digest,
            proxy_request_digest=expected_request_digest,
            proxy_operation_digest=expected_operation_digest,
            proxy_server_instance_id="spiffe://prod/instance",
            proxy_response_proof=str(collector_proof),
            proxy_proof_contract="buffered-v3",
            proxy_stream_body=None,
            proxy_max_stream_bytes=None,
            proxy_observation_body=None,
            proxy_max_observation_body_bytes=None,
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
            clean_subprocess_env(),
        )
        if accepted_summary != collector_summary or not collector_summary_path.is_file():
            raise AssertionError("runner rejected a collector summary matching every independent digest pin")

        stream_body = tmp / "collector-stream-body.bin"
        stream_body.write_bytes(b"body")
        stream_body_digest = run_production_readiness.sha256_prefixed_file(stream_body)
        collector_args.proxy_proof_contract = "streaming-v1"
        collector_args.proxy_stream_body = str(stream_body)
        collector_args.proxy_max_stream_bytes = 4
        streaming_collector_summary = {
            **collector_summary,
            "proof_contract": "streaming-v1",
            "stream_verified": True,
            "body_path": str(stream_body),
            "body_sha256": stream_body_digest,
            "body_bytes": 4,
        }

        def streaming_collector_command(summary: dict[str, object]) -> dict[str, object]:
            return {
                "label": "fixture-streaming-collector",
                "argv": [
                    sys.executable,
                    "-c",
                    f"import json; print(json.dumps({summary!r}))",
                ],
            }

        collector_args.proxy_proof_summary_out = str(tmp / "streaming-collector-summary.json")
        accepted_streaming_summary = run_production_readiness.run_collector(
            streaming_collector_command(streaming_collector_summary),
            collector_args,
            clean_subprocess_env(),
        )
        if (
            accepted_streaming_summary != streaming_collector_summary
            or collector_args.collected_proxy_stream_body_sha256 != stream_body_digest
            or collector_args.collected_proxy_stream_body_bytes != 4
            or collector_args.collected_proxy_proof_contract != "streaming-v1"
        ):
            raise AssertionError(
                "runner did not retain the verified streaming body and selected contract"
            )

        stream_summary_mutations = {
            "missing verification": {**streaming_collector_summary, "stream_verified": False},
            "body path swap": {
                **streaming_collector_summary,
                "body_path": str(tmp / "different-body.bin"),
            },
            "body digest swap": {
                **streaming_collector_summary,
                "body_sha256": "sha256:" + "0" * 64,
            },
            "body truncation count": {**streaming_collector_summary, "body_bytes": 3},
            "contract downgrade": {
                **streaming_collector_summary,
                "proof_contract": "buffered-v3",
            },
        }
        for label, mutated_summary in stream_summary_mutations.items():
            rejected_summary_path = tmp / f"rejected-{label.replace(' ', '-')}.json"
            collector_args.proxy_proof_summary_out = str(rejected_summary_path)
            try:
                run_production_readiness.run_collector(
                    streaming_collector_command(mutated_summary),
                    collector_args,
                    clean_subprocess_env(),
                )
            except ValueError:
                pass
            else:
                raise AssertionError(
                    f"runner accepted streaming collector summary mutation: {label}"
                )
            if rejected_summary_path.exists():
                raise AssertionError(
                    f"runner persisted rejected streaming collector summary: {label}"
                )

        collector_args.proxy_max_stream_bytes = 3
        collector_args.proxy_proof_summary_out = str(tmp / "oversized-stream-summary.json")
        try:
            run_production_readiness.run_collector(
                streaming_collector_command(streaming_collector_summary),
                collector_args,
                clean_subprocess_env(),
            )
        except ValueError:
            pass
        else:
            raise AssertionError("runner accepted a stream body above the pinned byte ceiling")
        collector_args.proxy_proof_contract = "buffered-v3"
        collector_args.proxy_stream_body = None
        collector_args.proxy_max_stream_bytes = None

        observation_body = tmp / "collector-observation-body.bin"
        observation_body.write_bytes(b"body")
        observation_body_digest = run_production_readiness.sha256_prefixed_file(
            observation_body
        )
        observation_response = {
            "status": 200,
            "headers_digest": "sha256:" + "4" * 64,
            "header_count": 3,
            "body_digest": observation_body_digest,
            "body_bytes": 4,
            "aggregate_digest": "sha256:" + "5" * 64,
        }
        observation_statement = {
            "issued_at_unix": int(time.time()),
            "client_nonce": "n" * 43,
            "request": {"aggregate_digest": expected_client_request_digest},
            "request_digest": expected_request_digest,
            "operation_digest": expected_operation_digest,
            "emitted_response": observation_response,
            "server_instance": {"id": "spiffe://prod/instance"},
            "tls_channel_binding": {
                "type": "tls-exporter",
                "label": "EXPORTER-Serverware-Response-Observation-v1",
                "value": "t" * 43,
            },
        }
        observation_artifact = {
            "apiVersion": "serverware.responseObservationProof/v1",
            "kind": "ServerwareResponseObservationProof",
            "captured_at_unix": int(time.time()),
            "request": {"aggregate_digest": expected_client_request_digest},
            "response": observation_response,
            "runtime_proof": {"server_statement": observation_statement},
            "collector": {},
        }
        collector_proof.write_text(
            canonical_json(observation_artifact) + "\n", encoding="utf-8"
        )
        observation_collector_summary = {
            "ok": True,
            "observation_verified": True,
            "client_nonce": "n" * 43,
            "request_aggregate_digest": expected_client_request_digest,
            "response_aggregate_digest": observation_response["aggregate_digest"],
            "response_status": 200,
            "server_instance_id": "spiffe://prod/instance",
            "proof_path": str(collector_proof),
            "proof_sha256": run_production_readiness.sha256_prefixed_file(
                collector_proof
            ),
            "proof_contract": "observation-v1",
            "body_path": str(observation_body),
            "body_sha256": observation_body_digest,
            "body_bytes": 4,
        }
        collector_args.proxy_proof_contract = "observation-v1"
        collector_args.proxy_observation_body = str(observation_body)
        collector_args.proxy_max_observation_body_bytes = 4
        collector_args.proxy_proof_summary_out = str(
            tmp / "observation-collector-summary.json"
        )

        def observation_collector_command(
            summary: dict[str, object],
        ) -> dict[str, object]:
            return {
                "label": "fixture-observation-collector",
                "argv": [
                    sys.executable,
                    "-c",
                    f"import json; print(json.dumps({summary!r}))",
                ],
            }

        accepted_observation_summary = run_production_readiness.run_collector(
            observation_collector_command(observation_collector_summary),
            collector_args,
            clean_subprocess_env(),
        )
        if (
            accepted_observation_summary != observation_collector_summary
            or collector_args.collected_proxy_observation_body_sha256
            != observation_body_digest
            or collector_args.collected_proxy_observation_body_bytes != 4
            or collector_args.collected_proxy_tls_channel_binding != "t" * 43
            or collector_args.collected_proxy_proof_contract != "observation-v1"
        ):
            raise AssertionError(
                "runner did not retain the verified observation body, TLS exporter, and selected contract"
            )

        observation_summary_mutations = {
            "missing verification": {
                **observation_collector_summary,
                "observation_verified": False,
            },
            "body path swap": {
                **observation_collector_summary,
                "body_path": str(tmp / "different-observation-body.bin"),
            },
            "body digest swap": {
                **observation_collector_summary,
                "body_sha256": "sha256:" + "0" * 64,
            },
            "body count swap": {
                **observation_collector_summary,
                "body_bytes": 3,
            },
            "response aggregate swap": {
                **observation_collector_summary,
                "response_aggregate_digest": "sha256:" + "0" * 64,
            },
            "contract downgrade": {
                **observation_collector_summary,
                "proof_contract": "buffered-v3",
            },
        }
        for label, mutated_summary in observation_summary_mutations.items():
            rejected_summary_path = (
                tmp / f"rejected-observation-{label.replace(' ', '-')}.json"
            )
            collector_args.proxy_proof_summary_out = str(rejected_summary_path)
            try:
                run_production_readiness.run_collector(
                    observation_collector_command(mutated_summary),
                    collector_args,
                    clean_subprocess_env(),
                )
            except ValueError:
                pass
            else:
                raise AssertionError(
                    f"runner accepted observation collector summary mutation: {label}"
                )
            if rejected_summary_path.exists():
                raise AssertionError(
                    f"runner persisted rejected observation collector summary: {label}"
                )
        malformed_observation_artifact = json.loads(
            json.dumps(observation_artifact)
        )
        malformed_observation_artifact["external_capture"] = {
            "client_nonce": "n" * 43
        }
        collector_proof.write_text(
            canonical_json(malformed_observation_artifact) + "\n",
            encoding="utf-8",
        )
        malformed_artifact_summary = {
            **observation_collector_summary,
            "proof_sha256": run_production_readiness.sha256_prefixed_file(
                collector_proof
            ),
        }
        try:
            run_production_readiness.run_collector(
                observation_collector_command(malformed_artifact_summary),
                collector_args,
                clean_subprocess_env(),
            )
        except ValueError as exc:
            if "top-level shape" not in str(exc):
                raise
        else:
            raise AssertionError(
                "runner accepted an observation proof with buffered/streaming artifact shape"
            )
        collector_proof.write_text(
            canonical_json(observation_artifact) + "\n", encoding="utf-8"
        )
        observation_body.write_bytes(b"same")
        collector_args.proxy_proof_summary_out = str(
            tmp / "mutated-observation-body-summary.json"
        )
        try:
            run_production_readiness.run_collector(
                observation_collector_command(observation_collector_summary),
                collector_args,
                clean_subprocess_env(),
            )
        except ValueError as exc:
            if "body digest" not in str(exc):
                raise
        else:
            raise AssertionError(
                "runner accepted a same-length substituted observation body"
            )
        observation_body.write_bytes(b"body")
        collector_args.proxy_proof_summary_out = str(
            tmp / "readiness-observation-collector-summary.json"
        )
        run_production_readiness.run_collector(
            observation_collector_command(observation_collector_summary),
            collector_args,
            clean_subprocess_env(),
        )
        if collector_args.collector_proof_contract != {
            "proof_contract": "observation-v1",
            "server_statement_sha256": "sha256:"
            + hashlib.sha256(
                canonical_json(observation_statement).encode("utf-8")
            ).hexdigest(),
            "captured_at_unix": observation_artifact["captured_at_unix"],
            "issued_at_unix": observation_statement["issued_at_unix"],
            "client_nonce_sha256": run_production_readiness.sha256_prefixed_base64url(
                "n" * 43, "fixture nonce"
            ),
            "tls_channel_binding_sha256": "sha256:"
            + hashlib.sha256(("t" * 43).encode("utf-8")).hexdigest(),
            "observed_body_artifact_sha256": observation_body_digest,
            "observed_body_artifact_bytes": 4,
            "emitted_body_digest": observation_body_digest,
            "emitted_body_bytes": 4,
        }:
            raise AssertionError(
                "readiness runner did not retain the observation artifact/body contract"
            )
        verify_readiness_observation_body_revalidation(
            tmp,
            collector_args,
            observation_body,
        )
        collector_args.proxy_proof_contract = "buffered-v3"
        collector_args.proxy_observation_body = None
        collector_args.proxy_max_observation_body_bytes = None
        collector_proof.write_bytes(b'{"fixture":"proof"}\n')
        collector_summary["proof_sha256"] = (
            run_production_readiness.sha256_prefixed_file(collector_proof)
        )

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
                clean_subprocess_env(),
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

        rejected_final_mode = run_runner(
            "--env-file",
            str(tmp / "does-not-exist.env"),
            "--dry-run",
            "--verification-mode",
            "final",
            *security_args,
        )
        rejected_final_detail = detail(rejected_final_mode)
        if (
            rejected_final_mode.returncode == 0
            or "this runner is trusted-host readiness only"
            not in rejected_final_detail
            or "scripts/verify_release_completion.py --verification-mode final"
            not in rejected_final_detail
            or "does-not-exist.env" in rejected_final_detail
        ):
            raise AssertionError(
                "readiness runner did not reject final mode before reading inputs: "
                + rejected_final_detail
            )

        rejected_legacy_final_option = run_runner(
            "--env-file",
            str(tmp / "does-not-exist.env"),
            "--final-challenge-receipt",
            str(tmp / "obsolete-final-challenge.json"),
            *security_args,
        )
        if (
            rejected_legacy_final_option.returncode == 0
            or "unrecognized arguments: --final-challenge-receipt"
            not in detail(rejected_legacy_final_option)
        ):
            raise AssertionError(
                "readiness runner accepted an obsolete final integration "
                "option: "
                + detail(rejected_legacy_final_option)
            )

        final_env_selection = tmp / "final-mode.env"
        write_env(
            final_env_selection,
            {
                **env_trust_values,
                "SERVERWARE_COMPLETION_VERIFICATION_MODE": "final",
            },
        )
        rejected_final_env = run_runner(
            "--env-file",
            str(final_env_selection),
            "--dry-run",
            *security_args,
        )
        if (
            rejected_final_env.returncode == 0
            or "must be readiness" not in detail(rejected_final_env)
            or "Manifest-v6 public Nitro verifier"
            not in detail(rejected_final_env)
        ):
            raise AssertionError(
                "readiness runner accepted a legacy env-selected final path: "
                + detail(rejected_final_env)
            )

        missing_proof_env = tmp / "missing-proof.env"
        write_env(missing_proof_env, {"SERVERWARE_RELEASE_CHANNEL": "prod"})
        rejected_missing_proof = run_runner("--env-file", str(missing_proof_env), "--dry-run", *security_args)
        if rejected_missing_proof.returncode == 0 or "SERVERWARE_PROXY_PROOF_CONTRACT must be pinned" not in detail(
            rejected_missing_proof
        ):
            raise AssertionError(f"runner accepted missing proxy proof settings: {detail(rejected_missing_proof)}")

        invalid_proof_age_env = tmp / "invalid-proof-age.env"
        invalid_proof_age = {
            key: value
            for key, value in {
                "SERVERWARE_RELEASE_CHANNEL": "prod",
                "SERVERWARE_PROXY_PROOF_CONTRACT": "buffered-v3",
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
