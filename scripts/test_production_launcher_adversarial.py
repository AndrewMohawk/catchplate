#!/usr/bin/env python3
# Cooperative Coder diagnostics only: this repository-controlled process is
# same-UID code with Docker access, not hostile-source containment, provenance,
# or attestation. It requires a trusted orchestrator and an exclusive disposable
# DinD sidecar whose destruction is the terminal security cleanup boundary.
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import tomllib
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CRATE = ROOT / "data-plane/decision-gate-rs"
SCHEMAS = ROOT / "schemas"
LAUNCHER_SOURCE = (
    CRATE / "src/bin/serverware-production-launcher.rs"
)
PRODUCTION_TRUST = CRATE / "trust/launch-authority-root.ed25519.hex"
GENERATOR = ROOT / "scripts/generate_production_launch_manifest.py"
PLATFORM = "linux/amd64"
CODER_IMAGE_REF = "serverware-production-launcher-adversarial:coder-v3"
IMAGE_REF_ENV = "SERVERWARE_ADVERSARIAL_LAUNCHER_IMAGE"
IMAGE_ID_ENV = "SERVERWARE_ADVERSARIAL_LAUNCHER_IMAGE_ID"
RUST_SLIM_BASE = (
    "rust:1.88-slim-bookworm"
    "@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89"
)
RUST_ALPINE_BASE = (
    "rust:1.88-alpine3.22"
    "@sha256:64eba3726734dcfe89e0a62a0485007a3ab7c7372ce5b38c621d8812f70215f0"
)
PYTHON_SLIM_BASE = (
    "python:3.11-slim-bookworm"
    "@sha256:0030323c9ce4d6dfab5f0812577cb0abd13c806f86b3a1f5b5d8f200ebb1421c"
)
MUSL_APK = ROOT / "production-dependencies/cache/musl-1.2.5-r12.apk"
MUSL_DEV_APK = ROOT / "production-dependencies/cache/musl-dev-1.2.5-r12.apk"
PYTHON_WHEELHOUSE = (
    ROOT
    / "production-dependencies/cache/python-wheelhouse-linux-amd64.tar.gz"
)
REQUIREMENTS_LOCK = ROOT / "requirements.lock"
PYTHON_WHEELHOUSE_SHA256 = (
    "812ea96c673527dd1dca4297af07d25383ecb8630e448648a152055f9fe79836"
)
REQUIREMENTS_LOCK_SHA256 = (
    "d8634b6db76c1c3ee6d22f4b8b2d8cb803ef8dabcf7a43fc084806b5fbadd692"
)
OFFLINE_BUILD_INPUT_SHA256 = {
    MUSL_APK: "4990a5e0ba312e478f94cfe431a70efef1538004eb361c8ae424516848be45bb",
    MUSL_DEV_APK: "1c2068d910cfdbbcb4eb107a5a478f8b48edf3a6311953c8fa5180c5190efab3",
    PYTHON_WHEELHOUSE: PYTHON_WHEELHOUSE_SHA256,
    REQUIREMENTS_LOCK: REQUIREMENTS_LOCK_SHA256,
}
BUILDER_NAME_RE = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
AMBIENT_BUILDER_ENV = "BUILDX_BUILDER"
CONFLICTING_BUILDER_ENV = ("BUILDKIT_HOST", "DOCKER_CONTEXT")

SOURCE_TREE_DIGEST = "sha256:" + "a" * 64
PROVENANCE_DIGEST = "sha256:" + "b" * 64
DEPLOYMENT_IDENTITY_DIGEST = "sha256:" + "c" * 64
DEPLOYMENT_AUDIENCE = "prod.us-east-1.primary"
RELEASE_SEQUENCE = 42
ROLLBACK_EPOCH = 7

ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
ED25519_PKCS8_SEED_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
TEST_AUTHORITY_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)
TEST_AUTHORITY_PUBLIC = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)
WRONG_TEST_AUTHORITY_SEED = bytes.fromhex(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
)
WRONG_TEST_AUTHORITY_PUBLIC = bytes.fromhex(
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
)
TEST_WITNESS_SEED = bytes.fromhex(
    "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
)
TEST_WITNESS_PUBLIC = bytes.fromhex(
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
)
TEST_WITNESS_ASSURANCE_ISSUER_SEED = bytes.fromhex(
    "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5"
)
TEST_WITNESS_ASSURANCE_ISSUER_PUBLIC = bytes.fromhex(
    "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e"
)
CONTEXT_MANIFEST_NAME = "build-input-context-manifest.json"

INPUTS = (
    ("production-images-build", "productionImagesBuild"),
    ("production-images-env", "productionImagesEnv"),
    ("production-images-published", "productionImagesPublished"),
    ("release-provenance-summary", "releaseProvenanceSummary"),
    ("release-provenance", "releaseProvenance"),
    ("image-signatures-summary", "imageSignaturesSummary"),
    ("image-signatures", "imageSignatures"),
    ("bench", "bench"),
    ("kms-materials", "kmsMaterials"),
    ("policy-bundle", "policyBundle"),
    ("policy-trusted-public-key", "policyTrustedPublicKey"),
    ("policy-identity-verification", "policyIdentityVerification"),
    ("policy-activation-verification", "policyActivationVerification"),
    ("policy-activation-signature", "policyActivationSignature"),
    ("policy-activation-trusted-public-key", "policyActivationTrustedPublicKey"),
    ("reproducible-build-verification", "reproducibleBuildVerification"),
    ("reproducible-build-signature", "reproducibleBuildSignature"),
    ("reproducible-build-trusted-public-key", "reproducibleBuildTrustedPublicKey"),
)

OUTPUTS = (
    ("config-out", "config.json"),
    ("claims-file", "claims.json"),
    ("nitro-evidence-out", "nitro.json"),
    ("readiness-out", "readiness.json"),
    ("completion-proof-out", "completion.json"),
    ("proxy-proof-summary-out", "proxy.json"),
    ("production-host-preflight", "host-preflight.json"),
)
INDEPENDENT_ADMINISTRATION_BINDINGS = (
    "launchAuthority.signingKeyId",
    "launchAuthorityWitness.signingKeyId",
    "launchAuthorityWitness.identitySha256",
    "launchAuthorityWitness.administrativeDomainSha256",
    "launchAuthorityWitnessStore.identitySha256",
    "launchAuthorityWitnessStore.administrativeDomainSha256",
    "launchAuthorityWitnessStore.assuranceIssuerKeyId",
)


def validate_launcher_source_contract() -> None:
    source = LAUNCHER_SOURCE.read_text(encoding="utf-8")
    binding_block = source.split(
        "const INDEPENDENT_ADMINISTRATION_BINDING_LABELS: [&str; 7] = [",
        1,
    )[1].split("];", 1)[0]
    native_bindings = tuple(re.findall(r'"([^"]+)"', binding_block))
    if native_bindings != INDEPENDENT_ADMINISTRATION_BINDINGS:
        raise RuntimeError(
            "native independent-administration binding inventory diverges from generator/schema"
        )
    fixture_binding_block = FIXTURE_DRIVER.split(
        "INDEPENDENT_ADMINISTRATION_BINDINGS = (", 1
    )[1].split(")", 1)[0]
    fixture_bindings = tuple(
        re.findall(r'"([^"]+)"', fixture_binding_block)
    )
    if fixture_bindings != INDEPENDENT_ADMINISTRATION_BINDINGS:
        raise RuntimeError(
            "adversarial independent-administration inventory diverges from native enforcement"
        )
    if "independent_administration_collisions == 21" not in FIXTURE_DRIVER:
        raise RuntimeError(
            "adversarial independent-administration matrix is not exhaustive"
        )
    assurance_validation = source.split(
        "fn validate_launch_authority_witness_store_assurance(", 1
    )[1].split(
        "fn require_pairwise_distinct_independent_administration_bindings(",
        1,
    )[0]
    collision_check = (
        "require_pairwise_distinct_independent_administration_bindings(["
    )
    if assurance_validation.count(collision_check) != 1:
        raise RuntimeError(
            "native witness-store validation omits the seven-binding collision check"
        )
    if assurance_validation.index(collision_check) > assurance_validation.index(
        ".verify_strict("
    ):
        raise RuntimeError(
            "native independent-administration collision check runs after assurance verification"
        )
    deadline_conversion = source.split(
        "    fn operation_deadline_from_authorization(", 1
    )[1].split(
        "    fn require_operation_deadline_current(", 1
    )[0]
    if deadline_conversion.count("realtime_timespec()?") != 1:
        raise RuntimeError(
            "operation deadline conversion must use exactly one trusted realtime sample"
        )
    if deadline_conversion.count("boottime_now()?") != 1:
        raise RuntimeError(
            "operation deadline conversion must capture exactly one suspend-aware origin"
        )
    if "Instant::now()" in deadline_conversion:
        raise RuntimeError(
            "operation deadline conversion still uses a suspend-insensitive Instant"
        )
    boottime_contract = source.split(
        "    struct BoottimeInstant {", 1
    )[1].split(
        "    fn build_authorization_request(", 1
    )[0]
    for required in (
        "libc::CLOCK_BOOTTIME",
        "libc::clock_nanosleep",
        "libc::TIMER_ABSTIME",
        "checked_add_timespec_delta",
        ".checked_add(seconds)",
        ".and_then(|value| value.checked_add(carry))",
        "require_authorization_current(statement, now_unix_seconds)?;",
        "deadline.to_timespec()?;",
    ):
        if required not in boottime_contract:
            raise RuntimeError(
                "suspend-aware deadline arithmetic omits " + required
            )
    if "Instant::now()" in boottime_contract:
        raise RuntimeError(
            "authorization-sensitive boottime contract uses Instant"
        )
    run_phase = source.split("    fn run_phase(", 1)[1].split(
        "    pub(super) fn run(", 1
    )[0]
    if "operation_deadline: &BoottimeInstant" not in run_phase:
        raise RuntimeError(
            "production phase supervisor does not accept the captured CLOCK_BOOTTIME deadline"
        )
    if (
        "unix_time_seconds" in run_phase
        or "realtime_timespec" in run_phase
        or "Instant::now()" in run_phase
        or "std::thread::sleep" in run_phase
    ):
        raise RuntimeError(
            "production phase supervisor uses a suspend-insensitive authorization clock"
        )
    if "sleep_until_next_phase_deadline_check(operation_deadline)" not in run_phase:
        raise RuntimeError(
            "production phase supervisor does not sleep against the absolute CLOCK_BOOTTIME deadline"
        )
    barrier_factory = source.split(
        "    fn create_phase_execution_barrier(", 1
    )[1].split(
        "    fn read_phase_barrier_byte(", 1
    )[0]
    if "libc::pipe2" not in barrier_factory or "libc::O_CLOEXEC" not in barrier_factory:
        raise RuntimeError(
            "production phase execution barrier is not a close-on-exec pipe"
        )
    barrier_consumer = source.split(
        "    fn consume_exact_phase_go_token(", 1
    )[1].split(
        "    fn release_phase_go_token(", 1
    )[0]
    for failure in (
        "closed before the go token",
        "wrong go token",
        "extra bytes",
    ):
        if failure not in barrier_consumer:
            raise RuntimeError(
                "production phase execution barrier does not reject " + failure
            )
    child_setup = run_phase.split("        if child == 0 {", 1)[1].split(
        "        drop(barrier_read_end);", 1
    )[0]
    child_order = (
        "libc::PR_SET_PDEATHSIG",
        "libc::setpgid(0, 0)",
        "close_unrelated_descriptors(&keep)",
        "consume_exact_phase_go_token",
        "require_operation_deadline_current(operation_deadline)",
        "libc::SYS_execveat",
    )
    child_positions = [child_setup.index(value) for value in child_order]
    if child_positions != sorted(child_positions):
        raise RuntimeError(
            "child can execute before setup, exact go-token, and boottime approval"
        )
    parent_setup = run_phase.split("        drop(barrier_read_end);", 1)[1].split(
        "        loop {", 1
    )[0]
    parent_order = (
        "establish_phase_process_group_before_exec(child)",
        "require_operation_deadline_current(operation_deadline)",
        "release_phase_go_token(barrier_write_end)",
    )
    parent_positions = [parent_setup.index(value) for value in parent_order]
    if parent_positions != sorted(parent_positions):
        raise RuntimeError(
            "parent releases the child before containment and boottime approval"
        )
    abort_before_exec = source.split(
        "    fn abort_phase_before_exec(", 1
    )[1].split(
        "    fn establish_phase_process_group_before_exec(", 1
    )[0]
    if abort_before_exec.index("drop(write_end)") > abort_before_exec.index(
        "force_kill_and_reap_phase_processes"
    ):
        raise RuntimeError(
            "parent failure does not close the execution barrier before killing the child"
        )
    force_kill = source.split(
        "    fn force_kill_and_reap_phase_processes(", 1
    )[1].split(
        "    fn terminate_phase_process_group(", 1
    )[0]
    if "libc::SIGTERM" in force_kill:
        raise RuntimeError(
            "authorization deadline cleanup still grants a SIGTERM grace interval"
        )
    for required in (
        "signal_phase_processes(process_group, *leader_status, libc::SIGKILL)",
        "signal_adopted_phase_descendants(process_group, libc::SIGKILL)",
        "reap_phase_children_nonblocking(process_group, leader_status)",
        "PHASE_FORCE_REAP_TIMEOUT_MILLIS",
    ):
        if required not in force_kill:
            raise RuntimeError(
                "immediate deadline force-kill omits " + required
            )
    for forbidden in (
        "reap_phase_children_nonblocking(process_group, leader_status)?",
        "phase_process_group_exists(process_group)?",
        "signal_adopted_phase_descendants(process_group, libc::SIGKILL)?",
    ):
        if forbidden in force_kill:
            raise RuntimeError(
                "force-kill cleanup can short-circuit before its bounded deadline: "
                + forbidden
            )
    bounded_reaper = source.split(
        "    fn reap_phase_children_nonblocking(", 1
    )[1].split(
        "    fn phase_process_group_exists(", 1
    )[0]
    if (
        "for _ in 0..PHASE_REAP_BATCH_MAX" not in bounded_reaper
        or "Ok(true)" not in bounded_reaper
    ):
        raise RuntimeError(
            "hostile adopted-child churn can starve CLOCK_BOOTTIME supervision"
        )
    supervisor = run_phase.split("        loop {", 1)[1]
    for forbidden in (
        "reap_phase_children_nonblocking(child, &mut leader_status)?",
        "phase_process_group_exists(child)?",
        "direct_phase_descendants(child)?",
    ):
        if forbidden in supervisor:
            raise RuntimeError(
                "post-go supervision failure can leave the phase running: "
                + forbidden
            )
    nonzero_status = supervisor.index("if status != 0 {")
    zero_deadline_check = supervisor.index(
        "require_operation_deadline_current(operation_deadline)",
        nonzero_status,
    )
    if nonzero_status > zero_deadline_check:
        raise RuntimeError(
            "known nonzero status is not preserved before deadline postchecks"
        )
    status_returns = [
        match.start()
        for match in re.finditer(r"return Ok\(status\);", supervisor)
    ]
    if len(status_returns) < 2 or status_returns[-1] < zero_deadline_check:
        raise RuntimeError(
            "zero phase status is accepted before proving deadline-current completion"
        )
    for fixture in (
        "boottime_deadline_arithmetic_is_checked_and_normalized",
        "wall_expiration_projection_rejects_expiry_and_time_t_overflow",
        "phase_execution_barrier_requires_one_exact_go_token_and_eof",
    ):
        if source.count(f"fn {fixture}()") != 1:
            raise RuntimeError(
                "native adversarial fixture is missing " + fixture
            )
    run_body = source.split("    pub(super) fn run(", 1)[1].split(
        "    #[cfg(test)]", 1
    )[0]
    conversion = (
        "operation_deadline_from_authorization(&authorization_statement)"
    )
    if run_body.count(conversion) != 1:
        raise RuntimeError(
            "launcher must derive exactly one operation deadline from the signed authorization"
        )
    if "unix_time_seconds" in run_body or "realtime_timespec" in run_body:
        raise RuntimeError(
            "launcher re-reads realtime after capturing the operation deadline"
        )
    if run_body.count(
        "require_operation_deadline_current(&operation_deadline)?;"
    ) != 3:
        raise RuntimeError(
            "launcher does not apply the captured deadline at every later phase admission"
        )
    for phase in ("preflight", "readiness"):
        binding = '&operation_deadline,\n            "' + phase + '"'
        if run_body.count(binding) != 1:
            raise RuntimeError(
                "launcher does not pass one captured operation deadline to " + phase
            )
    conversion_index = run_body.index(conversion)
    first_revalidation_index = run_body.index(
        "revalidate_verified_launch(&cli, &verified)?"
    )
    if conversion_index > first_revalidation_index:
        raise RuntimeError(
            "launcher does not capture the operation deadline immediately after authorization verification"
        )
    for phase_status in ("preflight_status", "readiness_status"):
        status_check = f"if {phase_status} != 0 {{"
        status_index = run_body.index(status_check)
        next_revalidation = run_body.find(
            "revalidate_verified_launch(&cli, &verified)?",
            run_body.index(f"let {phase_status} = run_phase("),
        )
        if next_revalidation != -1 and status_index > next_revalidation:
            raise RuntimeError(
                phase_status
                + " is masked by launch/path/deadline postchecks"
            )


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def nonce_rollback_assurance_pins() -> tuple[bytes, str]:
    evidence_spki = ED25519_SPKI_PREFIX + bytes.fromhex("51" * 32)
    verifier_state_spki = ED25519_SPKI_PREFIX + bytes.fromhex("52" * 32)
    verifier_state_store_attestation_spki = (
        ED25519_SPKI_PREFIX + bytes.fromhex("53" * 32)
    )
    assurance = {
        "apiVersion": "serverware.nonceAuthorityAssurance/v1",
        "administrativeDomainSha256": "sha256:" + "1" * 64,
        "assuranceEvidenceSha256": "sha256:" + "2" * 64,
        "assuranceEvidenceType": "linearizableCasOperatorAttestation",
        "assuranceLevel": "productionRollbackProtected",
        "authorityEpoch": 1,
        "authorityGeneration": 2,
        "authorityIdentitySha256": "sha256:" + "3" * 64,
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
    assurance_sha256 = sha256_prefixed(canonical_json_bytes(assurance))
    contract = {
        "apiVersion": "serverware.productionNonceRollbackAssurancePins/v1",
        "independentVerifierPins": {
            "expectedNonceAuthorityAssuranceIssuerSpkiSha256": (
                sha256_prefixed(evidence_spki)
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
                "sha256:" + "4" * 64
            ),
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256": (
                "sha256:" + "6" * 64
            ),
            "nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url": (
                base64.urlsafe_b64encode(
                    verifier_state_store_attestation_spki
                )
                .decode("ascii")
                .rstrip("=")
            ),
            "nonceAuthorityVerifierStateStoreIdentitySha256": (
                "sha256:" + "5" * 64
            ),
        },
    }
    encoded = canonical_json_bytes(contract) + b"\n"
    return encoded, sha256_prefixed(encoded)


CHILD_COMMON = r'''
import base64
import fcntl
import hashlib
import json
import os
import signal
import sys
import time

STATE = "/var/lib/serverware/production-proof"
COMMITTED_NAMES = [
    "LANG",
    "LC_ALL",
    "PATH",
    "SERVERWARE_BOOTSTRAP_RECEIPT_API_VERSION",
    "SERVERWARE_BOOTSTRAP_RECEIPT_FD",
    "SERVERWARE_BOOTSTRAP_RECEIPT_SHA256",
    "SERVERWARE_LAUNCHER_IMPORT_MODE",
    "TZ",
]
REQUEST_DOMAIN = b"serverware.launchAuthorizationRequest/v2\0"
RECOVERY_IDENTITY_DOMAIN = (
    b"serverware.launchAuthorizationAttemptRecoveryIdentity/v1\0"
)
EXPECTED_AUTHORITY_KEY_ID = "__AUTHORITY_KEY_ID__"


def canonical(value):
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def validate_child(phase):
    with open(STATE + "/" + phase + "-python-started", "w", encoding="ascii") as output:
        output.write("started\n")
    assert os.getcwd() == "/opt/serverware/release"
    assert os.environ["LANG"] == "C.UTF-8"
    assert os.environ["LC_ALL"] == "C.UTF-8"
    assert os.environ["PATH"] == "/usr/sbin:/usr/bin:/sbin:/bin"
    assert os.environ["TZ"] == "UTC"
    assert os.environ["SERVERWARE_LAUNCHER_IMPORT_MODE"] == "retained-fd-only"
    assert os.environ["SERVERWARE_BOOTSTRAP_RECEIPT_API_VERSION"] == "serverware.bootstrapReceipt/v3"
    assert sorted(os.environ) == sorted(
        COMMITTED_NAMES + ["SERVERWARE_EXECUTING_SCRIPT_FD"]
    )
    for name in ("LD_PRELOAD", "LD_AUDIT", "PYTHONPATH", "PYTHONHOME"):
        assert name not in os.environ

    if os.path.exists(STATE + "/expect-inherited-fd9-closed"):
        try:
            os.fstat(9)
        except OSError as error:
            assert error.errno == 9
        else:
            raise AssertionError("inherited descriptor 9 reached the Python child")

    receipt_fd = int(os.environ["SERVERWARE_BOOTSTRAP_RECEIPT_FD"])
    assert receipt_fd == 198
    metadata = os.fstat(receipt_fd)
    assert metadata.st_size > 0
    required_seals = (
        fcntl.F_SEAL_WRITE
        | fcntl.F_SEAL_GROW
        | fcntl.F_SEAL_SHRINK
        | fcntl.F_SEAL_SEAL
    )
    assert fcntl.fcntl(receipt_fd, fcntl.F_GET_SEALS) & required_seals == required_seals
    os.lseek(receipt_fd, 0, os.SEEK_SET)
    receipt_bytes = b""
    while len(receipt_bytes) < metadata.st_size:
        receipt_bytes += os.read(receipt_fd, metadata.st_size - len(receipt_bytes))
    assert len(receipt_bytes) == metadata.st_size
    assert digest(receipt_bytes) == os.environ["SERVERWARE_BOOTSTRAP_RECEIPT_SHA256"]

    receipt = json.loads(receipt_bytes.decode("utf-8"))
    assert canonical(receipt) == receipt_bytes
    assert set(receipt) == {
        "apiVersion",
        "kind",
        "launchId",
        "bootIdSha256",
        "launcher",
        "manifest",
        "sourceTreeDigest",
        "launchAuthorization",
        "nonceRollbackAssurance",
        "productionEnv",
        "python",
        "scripts",
        "composeFile",
        "inputs",
        "argv",
        "environment",
    }
    assert receipt["apiVersion"] == "serverware.bootstrapReceipt/v3"
    assert receipt["kind"] == "ProductionBootstrapReceipt"
    assert receipt["sourceTreeDigest"] == "sha256:" + "a" * 64
    assert len(receipt["launchId"]) == 64
    int(receipt["launchId"], 16)
    assert receipt["bootIdSha256"].startswith("sha256:")
    with open("/etc/serverware/production-release-launch.json", "rb") as source:
        manifest_bytes = source.read()
    assert receipt["manifest"]["sha256"] == digest(manifest_bytes)
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    assert [root["path"] for root in receipt["python"]["importRoots"]] == [
        "/opt/serverware/release",
        "/opt/serverware/release/runtime/python/lib/python3.11",
        "/opt/serverware/release/runtime/python/lib/python3.11/lib-dynload",
        "/opt/serverware/release/vendor",
    ]
    for name in ("preflightSha256", "readinessSha256"):
        assert len(receipt["argv"][name]) == 71
        assert receipt["argv"][name].startswith("sha256:")

    authorization = receipt["launchAuthorization"]
    request = authorization["request"]
    envelope = authorization["envelope"]
    statement = envelope["statement"]
    request_sha256 = digest(REQUEST_DOMAIN + canonical(request))
    assert authorization["requestSha256"] == request_sha256
    assert statement["requestSha256"] == request_sha256
    assert authorization["authorizationSha256"] == digest(canonical(envelope))
    assert request == {
        "apiVersion": "serverware.launchAuthorizationRequest/v2",
        "kind": "ProductionLaunchAuthorizationRequest",
        "launcherNonce": receipt["launchId"],
        "bootIdSha256": receipt["bootIdSha256"],
        "launcherSha256": receipt["launcher"]["sha256"],
        "manifestSha256": receipt["manifest"]["sha256"],
        "globalRoleRegistry": manifest["globalRoleRegistry"]["registry"],
        "globalRoleRegistrySha256": manifest["globalRoleRegistry"]["registrySha256"],
        "globalRoleRegistryPinsSha256": manifest["globalRoleRegistry"]["pinsFile"]["sha256"],
        "nonceRollbackAssuranceContractSha256": receipt["nonceRollbackAssurance"]["contractSha256"],
        "nonceRollbackAssurancePinsSha256": receipt["nonceRollbackAssurance"]["retainedSnapshotSha256"],
        "releaseProvenanceSha256": receipt["inputs"]["releaseProvenance"]["sha256"],
        "provenanceDigest": "sha256:" + "b" * 64,
        "reproducibleBuildVerificationSha256": receipt["inputs"]["reproducibleBuildVerification"]["sha256"],
        "sourceTreeDigest": receipt["sourceTreeDigest"],
        "deploymentAudience": "prod.us-east-1.primary",
        "deploymentIdentitySha256": "sha256:" + "c" * 64,
        "releaseSequence": 42,
        "rollbackEpoch": 7,
        "authorizationScope": "trusted-host-readiness",
        "freshnessAuthority": "trusted-host-wall-clock",
        "launchAttemptJournalDomain": manifest["launchAttemptJournal"]["domain"],
        "launchAttemptRecoveryIdentitySha256": request["launchAttemptRecoveryIdentitySha256"],
        "launchAuthorityWitnessChallenge": statement["monotonicWitness"]["statement"]["challenge"],
        "launchAuthorityWitnessKeyId": statement["monotonicWitness"]["statement"]["witnessKeyId"],
        "launchAuthorityWitnessIdentitySha256": statement["monotonicWitness"]["statement"]["witnessIdentitySha256"],
        "launchAuthorityWitnessAdministrativeDomainSha256": statement["monotonicWitness"]["statement"]["witnessAdministrativeDomainSha256"],
        "launchAuthorityWitnessStoreAssuranceSha256": statement["monotonicWitness"]["statement"]["storeAssuranceSha256"],
    }
    recovery_identity = {
        "domain": request["launchAttemptJournalDomain"],
        "launcherNonce": request["launcherNonce"],
        "witnessChallenge": request["launchAuthorityWitnessChallenge"],
        "bootIdSha256": request["bootIdSha256"],
        "manifestSha256": request["manifestSha256"],
        "globalRoleRegistrySha256": request["globalRoleRegistrySha256"],
    }
    assert request["launchAttemptRecoveryIdentitySha256"] == digest(
        RECOVERY_IDENTITY_DOMAIN + canonical(recovery_identity)
    )
    assert set(request["globalRoleRegistry"]["roles"]) == {
        "launchAuthority",
        "launchAuthorityWitness",
        "launchAuthorityWitnessStoreAssurance",
        "launchAuthorityWitnessTls",
        "nonceAuthorityAssuranceEvidence",
        "nonceAuthorityVerifierState",
        "nonceAuthorityVerifierStateStoreAttestation",
        "policyActivation",
        "policyIdentity",
        "reproducibleBuild",
    }
    assert len(set(request["globalRoleRegistry"]["roles"].values())) == 10
    assert request["globalRoleRegistry"]["rolesOutsideClaim"] == [
        "actionGate",
        "publicAttestationNonceStore",
        "publicAttestationProducer",
        "publicAttestationWitnessStore",
        "finalVerifier",
        "nonceAuthorityVerifierStateStoreAssurance",
        "release",
        "response",
        "verifierStateTlsClient",
        "verifierStateTlsServer",
    ]
    assert envelope["apiVersion"] == "serverware.launchAuthorization/v2"
    assert envelope["kind"] == "ProductionLaunchAuthorization"
    assert len(statement["authorizationId"]) == 64
    int(statement["authorizationId"], 16)
    assert statement["authorityKeyId"] == EXPECTED_AUTHORITY_KEY_ID
    assert "useLimit" not in statement
    assert statement["authorizationScope"] == "trusted-host-readiness"
    assert statement["freshnessAuthority"] == "trusted-host-wall-clock"
    assert statement["capabilitySemantics"] == "time-bounded-idempotent-readiness-authorization"
    assert statement["globalRoleRegistrySha256"] == request["globalRoleRegistrySha256"]
    assert statement["expiresAtUnixSeconds"] - statement["issuedAtUnixSeconds"] <= 30
    assert statement["issuedAtUnixSeconds"] <= authorization["verifiedAtUnixSeconds"]
    assert authorization["verifiedAtUnixSeconds"] < statement["expiresAtUnixSeconds"]
    assert "=" not in envelope["signature"]
    signature = base64.urlsafe_b64decode(envelope["signature"] + "==")
    assert len(signature) == 64

    def argument(name):
        assert sys.argv.count(name) == 1
        index = sys.argv.index(name)
        assert index + 1 < len(sys.argv)
        return sys.argv[index + 1]

    pins_path = argument("--launcher-nonce-rollback-assurance-pins")
    pins_sha256 = argument(
        "--launcher-nonce-rollback-assurance-pins-sha256"
    )
    contract_sha256 = argument(
        "--launcher-nonce-rollback-assurance-contract-sha256"
    )
    assert pins_path.startswith("/proc/self/fd/")
    pins_fd = int(pins_path.rsplit("/", 1)[1])
    nonce_binding = receipt["nonceRollbackAssurance"]
    assert nonce_binding["apiVersion"] == "serverware.productionNonceRollbackAssuranceBinding/v1"
    assert pins_fd == nonce_binding["retainedSnapshotFd"]
    assert pins_fd != receipt_fd
    assert pins_sha256 == nonce_binding["retainedSnapshotSha256"]
    assert contract_sha256 == nonce_binding["contractSha256"]
    pins_metadata = os.fstat(pins_fd)
    assert fcntl.fcntl(pins_fd, fcntl.F_GET_SEALS) & required_seals == required_seals
    pins_bytes = os.pread(pins_fd, pins_metadata.st_size, 0)
    assert len(pins_bytes) == pins_metadata.st_size
    assert digest(pins_bytes) == pins_sha256
    assert pins_bytes.endswith(b"\n")
    pins_contract = json.loads(pins_bytes.decode("utf-8"))
    assert canonical(pins_contract) + b"\n" == pins_bytes
    assert digest(canonical(pins_contract)) == contract_sha256
    assert pins_contract["apiVersion"] == "serverware.productionNonceRollbackAssurancePins/v1"
    assert nonce_binding["pinsFile"]["sha256"] == pins_sha256
    public_config = pins_contract["publicConfigPins"]
    assert set(nonce_binding["verifierStateService"]) == {
        "signingPublicKeySpkiDerBase64url",
        "storeAdministrativeDomainSha256",
        "storeAssuranceEvidenceSha256",
        "storeAttestationPublicKeySpkiDerBase64url",
        "storeIdentitySha256",
    }
    assert nonce_binding["verifierStateService"] == {
        "signingPublicKeySpkiDerBase64url": public_config[
            "nonceAuthorityVerifierStateSigningPublicKeySpkiDerBase64url"
        ],
        "storeAdministrativeDomainSha256": public_config[
            "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256"
        ],
        "storeAssuranceEvidenceSha256": public_config[
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"
        ],
        "storeAttestationPublicKeySpkiDerBase64url": public_config[
            "nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url"
        ],
        "storeIdentitySha256": public_config[
            "nonceAuthorityVerifierStateStoreIdentitySha256"
        ],
    }
    try:
        os.write(pins_fd, b"not mutable")
    except OSError as error:
        assert error.errno == 1
    else:
        raise AssertionError("sealed nonce rollback assurance snapshot accepted a write")

    script_fd = int(os.environ["SERVERWARE_EXECUTING_SCRIPT_FD"])
    assert script_fd not in (receipt_fd, pins_fd)
    script_metadata = os.fstat(script_fd)
    assert fcntl.fcntl(script_fd, fcntl.F_GET_SEALS) & required_seals == required_seals
    os.lseek(script_fd, 0, os.SEEK_SET)
    script_bytes = b""
    while len(script_bytes) < script_metadata.st_size:
        script_bytes += os.read(script_fd, script_metadata.st_size - len(script_bytes))
    script_name = "preflight" if phase == "preflight" else "runner"
    script_receipt = receipt["scripts"][script_name]
    assert digest(script_bytes) == script_receipt["sha256"]
    source_metadata = os.stat(script_receipt["path"], follow_symlinks=False)
    assert (script_metadata.st_dev, script_metadata.st_ino) != (
        source_metadata.st_dev,
        source_metadata.st_ino,
    )
    try:
        os.write(script_fd, b"not mutable")
    except OSError as error:
        assert error.errno == 1
    else:
        raise AssertionError("sealed script snapshot accepted a write")

    committed = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "SERVERWARE_BOOTSTRAP_RECEIPT_API_VERSION": "serverware.bootstrapReceipt/v3",
        "SERVERWARE_BOOTSTRAP_RECEIPT_FD": "198",
        "SERVERWARE_BOOTSTRAP_RECEIPT_SHA256": "sha256:<bootstrap-receipt>",
        "SERVERWARE_LAUNCHER_IMPORT_MODE": "retained-fd-only",
        "TZ": "UTC",
    }
    assert receipt["environment"] == {
        "names": COMMITTED_NAMES,
        "sha256": digest(canonical(committed)),
    }
    try:
        os.write(receipt_fd, b"not mutable")
    except OSError as error:
        assert error.errno == 1
    else:
        raise AssertionError("sealed receipt accepted a write")

    assert not os.path.exists(STATE + "/hostile-loader-ran")
    assert not os.path.exists(STATE + "/hostile-site-ran")
    if phase == "preflight":
        with open(STATE + "/launched-request", "w", encoding="ascii") as output:
            output.write(request["launcherNonce"] + "\n")
    with open(STATE + "/" + phase + "-receipt-ok", "w", encoding="ascii") as output:
        output.write(os.environ["SERVERWARE_BOOTSTRAP_RECEIPT_SHA256"] + "\n")
'''

PREFLIGHT = CHILD_COMMON + r'''
validate_child("preflight")
with open(STATE + "/preflight-ran", "w", encoding="ascii") as output:
    output.write("preflight\n")
if os.path.exists(STATE + "/mutate-readiness-source"):
    runner_path = "/opt/serverware/release/scripts/runner.py"
    before = os.stat(runner_path, follow_symlinks=False)
    hostile = (
        b"open('/var/lib/serverware/production-proof/mutated-readiness-ran', 'w').write('bad\\n')\n"
        b"raise SystemExit(91)\n"
    )
    with open(runner_path, "r+b", buffering=0) as target:
        target.write(hostile)
        target.truncate()
    after = os.stat(runner_path, follow_symlinks=False)
    assert (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
    with open(STATE + "/readiness-source-mutated", "w", encoding="ascii") as output:
        output.write("same inode\n")
if os.path.exists(STATE + "/force-preflight-fail"):
    raise SystemExit(23)
if os.path.exists(STATE + "/delay-preflight-until-authorization-expires"):
    time.sleep(3.2)
if os.path.exists(STATE + "/spawn-stubborn-preflight-descendant-until-authorization-expires"):
    descendant = os.fork()
    if descendant == 0:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        with open(
            STATE + "/stubborn-preflight-descendant-pid",
            "w",
            encoding="ascii",
        ) as output:
            output.write(str(os.getpid()) + "\n")
        while True:
            time.sleep(1)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    while True:
        time.sleep(1)
'''

RUNNER = CHILD_COMMON + r'''
validate_child("readiness")
with open(STATE + "/preflight-ran", "r", encoding="ascii") as source:
    assert source.read() == "preflight\n"
with open(STATE + "/readiness-ran", "w", encoding="ascii") as output:
    output.write("readiness\n")
'''

HOSTILE_C = r'''
#include <fcntl.h>
#include <unistd.h>

static void mark_loaded(void) __attribute__((constructor));
static void mark_loaded(void) {
    const char marker[] = "hostile loader executed\n";
    int fd = open(
        "/var/lib/serverware/production-proof/hostile-loader-ran",
        O_WRONLY | O_CREAT | O_APPEND,
        0600
    );
    if (fd >= 0) {
        (void)write(fd, marker, sizeof(marker) - 1);
        (void)close(fd);
    }
}
unsigned int la_version(unsigned int version) { return version; }
'''

AUTHORITY_FIXTURE = r'''
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


SOCKET = Path("/run/serverware/launch-authority.sock")
LAUNCHER = Path("/opt/serverware/bin/serverware-production-launcher-test")
LAUNCHER_BACKUP = LAUNCHER.with_name(LAUNCHER.name + ".authority-original")
MANIFEST = Path("/etc/serverware/production-release-launch.json")
NONCE_PINS = Path("/etc/serverware/nonce-rollback-assurance-pins.json")
NONCE_PINS_BACKUP = NONCE_PINS.with_name(
    NONCE_PINS.name + ".authority-original"
)
PIPELINE_METADATA = Path("/etc/serverware/production-launch-pipeline.json")
STATE = Path("/var/lib/serverware/production-proof")
REPLAY = STATE / "replay-authorization-envelope.json"
PRIVATE_KEY = Path("/etc/serverware/test-launch-authority-private.pem")
WRONG_PRIVATE_KEY = Path("/etc/serverware/test-launch-authority-wrong-private.pem")
WITNESS_PRIVATE_KEY = Path("/etc/serverware/test-launch-witness-private.pem")
WITNESS_ASSURANCE_ISSUER_PRIVATE_KEY = Path(
    "/etc/serverware/test-launch-witness-assurance-issuer-private.pem"
)
WITNESS_STORE_ASSURANCE = Path(
    "/etc/serverware/test-launch-witness-store-assurance.json"
)
GLOBAL_ROLE_REGISTRY = Path(
    "/etc/serverware/production-launch-global-role-registry.json"
)
TRUST_METADATA = Path("/etc/serverware/test-launch-trust-metadata.json")
PUBLIC_KEY_HEX = "__PUBLIC_KEY_HEX__"
WITNESS_PUBLIC_HEX = "__WITNESS_PUBLIC_HEX__"
WITNESS_ASSURANCE_ISSUER_PUBLIC_HEX = (
    "__WITNESS_ASSURANCE_ISSUER_PUBLIC_HEX__"
)
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
REQUEST_DOMAIN = b"serverware.launchAuthorizationRequest/v2\0"
AUTHORIZATION_DOMAIN = b"serverware.launchAuthorization/v2\0"
REQUEST_FIELDS = {
    "apiVersion",
    "kind",
    "launcherNonce",
    "bootIdSha256",
    "launcherSha256",
    "manifestSha256",
    "globalRoleRegistry",
    "globalRoleRegistrySha256",
    "globalRoleRegistryPinsSha256",
    "nonceRollbackAssuranceContractSha256",
    "nonceRollbackAssurancePinsSha256",
    "releaseProvenanceSha256",
    "provenanceDigest",
    "reproducibleBuildVerificationSha256",
    "sourceTreeDigest",
    "deploymentAudience",
    "deploymentIdentitySha256",
    "releaseSequence",
    "rollbackEpoch",
    "authorizationScope",
    "freshnessAuthority",
    "launchAttemptJournalDomain",
    "launchAttemptRecoveryIdentitySha256",
    "launchAuthorityWitnessChallenge",
    "launchAuthorityWitnessKeyId",
    "launchAuthorityWitnessIdentitySha256",
    "launchAuthorityWitnessAdministrativeDomainSha256",
    "launchAuthorityWitnessStoreAssuranceSha256",
}
DIGEST_FIELDS = {
    "bootIdSha256",
    "launcherSha256",
    "manifestSha256",
    "globalRoleRegistrySha256",
    "globalRoleRegistryPinsSha256",
    "nonceRollbackAssuranceContractSha256",
    "nonceRollbackAssurancePinsSha256",
    "releaseProvenanceSha256",
    "provenanceDigest",
    "reproducibleBuildVerificationSha256",
    "sourceTreeDigest",
    "deploymentIdentitySha256",
    "launchAuthorityWitnessKeyId",
    "launchAuthorityWitnessIdentitySha256",
    "launchAuthorityWitnessAdministrativeDomainSha256",
    "launchAuthorityWitnessStoreAssuranceSha256",
    "launchAttemptRecoveryIdentitySha256",
}
GLOBAL_ROLE_NAMES = {
    "launchAuthority",
    "launchAuthorityWitness",
    "launchAuthorityWitnessStoreAssurance",
    "launchAuthorityWitnessTls",
    "nonceAuthorityAssuranceEvidence",
    "nonceAuthorityVerifierState",
    "nonceAuthorityVerifierStateStoreAttestation",
    "policyActivation",
    "policyIdentity",
    "reproducibleBuild",
}
ROLES_OUTSIDE_CLAIM = [
    "actionGate",
    "publicAttestationNonceStore",
    "publicAttestationProducer",
    "publicAttestationWitnessStore",
    "finalVerifier",
    "nonceAuthorityVerifierStateStoreAssurance",
    "release",
    "response",
    "verifierStateTlsClient",
    "verifierStateTlsServer",
]
RECOVERY_IDENTITY_DOMAIN = (
    b"serverware.launchAuthorizationAttemptRecoveryIdentity/v1\0"
)
WITNESS_DOMAIN = b"serverware.launchAuthorityWitnessTransition/v1\0"
BINDING_MUTATIONS = {
    "bind-manifest": "manifestSha256",
    "bind-nonce-contract": "nonceRollbackAssuranceContractSha256",
    "bind-nonce-pins": "nonceRollbackAssurancePinsSha256",
    "bind-release-provenance": "releaseProvenanceSha256",
    "bind-provenance-digest": "provenanceDigest",
    "bind-source-tree": "sourceTreeDigest",
    "bind-launcher": "launcherSha256",
    "bind-reproducible-build": "reproducibleBuildVerificationSha256",
    "bind-release-sequence": "releaseSequence",
    "bind-rollback-epoch": "rollbackEpoch",
}
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)
HEX_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
AUDIENCE_RE = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}\Z", re.ASCII)
MAX_SAFE_INTEGER = (1 << 53) - 1


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def canonical(value):
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")


def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def file_digest(path):
    return digest(path.read_bytes())


def request_digest(request):
    return digest(REQUEST_DOMAIN + canonical(request))


def authority_key_id():
    public = bytes.fromhex(PUBLIC_KEY_HEX)
    require(len(public) == 32, "test authority public key has the wrong length")
    return digest(SPKI_PREFIX + public)


def validate_request(raw):
    require(raw, "launcher sent an empty authorization request")
    require(len(raw) <= 16 * 1024, "launcher sent an oversized authorization request")
    request = json.loads(raw.decode("utf-8"))
    require(type(request) is dict, "authorization request is not an object")
    require(canonical(request) == raw, "authorization request is not canonical JSON")
    require(set(request) == REQUEST_FIELDS, "authorization request fields are not closed")
    require(
        request["apiVersion"] == "serverware.launchAuthorizationRequest/v2",
        "authorization request apiVersion is wrong",
    )
    require(
        request["kind"] == "ProductionLaunchAuthorizationRequest",
        "authorization request kind is wrong",
    )
    require(type(request["launcherNonce"]) is str and HEX_RE.fullmatch(request["launcherNonce"]), "launcher nonce is invalid")
    for field in DIGEST_FIELDS:
        require(type(request[field]) is str and DIGEST_RE.fullmatch(request[field]), field + " is invalid")
    registry = request["globalRoleRegistry"]
    require(
        type(registry) is dict
        and set(registry)
        == {"apiVersion", "claimScope", "roles", "rolesOutsideClaim"},
        "global role registry fields are not closed",
    )
    require(
        registry["apiVersion"]
        == "serverware.productionLaunchGlobalRoleRegistry/v1"
        and registry["claimScope"]
        == "roles-present-in-native-launch-contract"
        and registry["rolesOutsideClaim"] == ROLES_OUTSIDE_CLAIM,
        "global role registry scope is invalid",
    )
    require(
        type(registry["roles"]) is dict
        and set(registry["roles"]) == GLOBAL_ROLE_NAMES
        and len(set(registry["roles"].values())) == len(GLOBAL_ROLE_NAMES)
        and all(
            type(value) is str and DIGEST_RE.fullmatch(value)
            for value in registry["roles"].values()
        ),
        "global role registry is not closed and pairwise distinct",
    )
    require(
        request["globalRoleRegistrySha256"] == digest(canonical(registry)),
        "global role registry digest is invalid",
    )
    require(
        type(request["deploymentAudience"]) is str
        and AUDIENCE_RE.fullmatch(request["deploymentAudience"]),
        "deployment audience is invalid",
    )
    require(
        type(request["releaseSequence"]) is int
        and 1 <= request["releaseSequence"] <= MAX_SAFE_INTEGER,
        "release sequence is invalid",
    )
    require(
        type(request["rollbackEpoch"]) is int
        and 0 <= request["rollbackEpoch"] <= MAX_SAFE_INTEGER,
        "rollback epoch is invalid",
    )
    require(
        request["authorizationScope"] == "trusted-host-readiness"
        and request["freshnessAuthority"] == "trusted-host-wall-clock",
        "authorization scope is invalid",
    )
    require(
        request["launchAttemptJournalDomain"]
        == "serverware.launchAuthorizationAttemptJournal/v1",
        "launch attempt journal domain is invalid",
    )
    require(
        type(request["launchAuthorityWitnessChallenge"]) is str
        and HEX_RE.fullmatch(request["launchAuthorityWitnessChallenge"]),
        "launch authority witness challenge is invalid",
    )
    recovery_identity = {
        "domain": request["launchAttemptJournalDomain"],
        "launcherNonce": request["launcherNonce"],
        "witnessChallenge": request["launchAuthorityWitnessChallenge"],
        "bootIdSha256": request["bootIdSha256"],
        "manifestSha256": request["manifestSha256"],
        "globalRoleRegistrySha256": request["globalRoleRegistrySha256"],
    }
    require(
        request["launchAttemptRecoveryIdentitySha256"]
        == digest(RECOVERY_IDENTITY_DOMAIN + canonical(recovery_identity)),
        "launch attempt recovery identity is invalid",
    )

    manifest_raw = MANIFEST.read_bytes()
    manifest = json.loads(manifest_raw.decode("utf-8"))
    provenance_path = Path(manifest["inputs"]["releaseProvenance"]["path"])
    reproducible_path = Path(manifest["inputs"]["reproducibleBuildVerification"]["path"])
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    expected = {
        "launcherSha256": file_digest(LAUNCHER),
        "manifestSha256": digest(manifest_raw),
        "globalRoleRegistry": manifest["globalRoleRegistry"]["registry"],
        "globalRoleRegistrySha256": manifest["globalRoleRegistry"]["registrySha256"],
        "globalRoleRegistryPinsSha256": manifest["globalRoleRegistry"]["pinsFile"]["sha256"],
        "nonceRollbackAssuranceContractSha256": manifest["nonceRollbackAssurance"]["contractSha256"],
        "nonceRollbackAssurancePinsSha256": manifest["nonceRollbackAssurance"]["pinsFile"]["sha256"],
        "releaseProvenanceSha256": file_digest(provenance_path),
        "provenanceDigest": provenance["provenance_digest"],
        "reproducibleBuildVerificationSha256": file_digest(reproducible_path),
        "sourceTreeDigest": manifest["sourceTreeDigest"],
        "deploymentAudience": manifest["authorization"]["deploymentAudience"],
        "deploymentIdentitySha256": manifest["authorization"]["deploymentIdentitySha256"],
        "releaseSequence": manifest["authorization"]["releaseSequence"],
        "rollbackEpoch": manifest["authorization"]["rollbackEpoch"],
        "authorizationScope": manifest["authorization"]["authorizationScope"],
        "freshnessAuthority": manifest["authorization"]["freshnessAuthority"],
        "launchAttemptJournalDomain": manifest["launchAttemptJournal"]["domain"],
        "launchAuthorityWitnessKeyId": manifest["authorization"]["monotonicWitness"]["signingKeyId"],
        "launchAuthorityWitnessIdentitySha256": manifest["authorization"]["monotonicWitness"]["identitySha256"],
        "launchAuthorityWitnessAdministrativeDomainSha256": manifest["authorization"]["monotonicWitness"]["administrativeDomainSha256"],
        "launchAuthorityWitnessStoreAssuranceSha256": manifest["authorization"]["monotonicWitness"]["storeAssuranceSha256"],
    }
    require(
        provenance["provenance"]["source_tree"]["digest"] == manifest["sourceTreeDigest"],
        "release provenance source tree does not match the manifest",
    )
    for field, value in expected.items():
        require(request[field] == value, field + " is not bound to the measured fixture")
    return request, manifest


def sign(payload, key_path):
    with tempfile.NamedTemporaryFile(dir=SOCKET.parent) as signing_input:
        signing_input.write(payload)
        signing_input.flush()
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(key_path),
                "-in",
                signing_input.name,
            ],
            capture_output=True,
            check=False,
        )
    require(result.returncode == 0, "OpenSSL signing failed: " + result.stderr.decode("utf-8", errors="replace"))
    require(len(result.stdout) == 64, "OpenSSL returned a non-Ed25519 signature")
    return base64.urlsafe_b64encode(result.stdout).rstrip(b"=").decode("ascii")


def read_pem_spki(path):
    lines = [
        line
        for line in path.read_text(encoding="ascii").splitlines()
        if not line.startswith("-----")
    ]
    return base64.b64decode("".join(lines), validate=True)


def decode_unpadded_base64url(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def write_fixture_trust():
    witness_spki = SPKI_PREFIX + bytes.fromhex(WITNESS_PUBLIC_HEX)
    witness_tls_spki = SPKI_PREFIX + bytes([0x71]) * 32
    issuer_spki = (
        SPKI_PREFIX + bytes.fromhex(WITNESS_ASSURANCE_ISSUER_PUBLIC_HEX)
    )
    witness_key_id = digest(witness_spki)
    issuer_key_id = digest(issuer_spki)
    witness_identity = "sha256:" + "d" * 64
    witness_administrative_domain = "sha256:" + "e" * 64
    assurance_statement = {
        "assuranceIssuerKeyId": issuer_key_id,
        "witnessKeyId": witness_key_id,
        "witnessIdentitySha256": witness_identity,
        "witnessAdministrativeDomainSha256": witness_administrative_domain,
        "storeIdentitySha256": "sha256:" + "f" * 64,
        "storeAdministrativeDomainSha256": "sha256:" + "0" * 64,
        "storeClass": "independentlyAdministeredLinearizableCas",
        "rollbackResistance": "externally-witnessed-monotonic",
        "independentAdministration": True,
    }
    assurance_signed = {
        "apiVersion": "serverware.launchAuthorityWitnessStoreAssurance/v1",
        "kind": "LaunchAuthorityWitnessStoreAssurance",
        "statement": assurance_statement,
    }
    assurance = {
        **assurance_signed,
        "signature": sign(
            b"serverware.launchAuthorityWitnessStoreAssurance/v1\0"
            + canonical(assurance_signed),
            WITNESS_ASSURANCE_ISSUER_PRIVATE_KEY,
        ),
    }
    assurance_bytes = canonical(assurance)
    WITNESS_STORE_ASSURANCE.write_bytes(assurance_bytes)

    nonce = json.loads(NONCE_PINS.read_text(encoding="ascii"))
    nonce_public = nonce["publicConfigPins"]
    roles = {
        "launchAuthority": authority_key_id(),
        "launchAuthorityWitness": witness_key_id,
        "launchAuthorityWitnessStoreAssurance": issuer_key_id,
        "launchAuthorityWitnessTls": digest(witness_tls_spki),
        "nonceAuthorityAssuranceEvidence": digest(
            decode_unpadded_base64url(
                nonce_public[
                    "nonceAuthorityAssuranceEvidenceSigningPublicKeySpkiDerBase64url"
                ]
            )
        ),
        "nonceAuthorityVerifierState": digest(
            decode_unpadded_base64url(
                nonce_public[
                    "nonceAuthorityVerifierStateSigningPublicKeySpkiDerBase64url"
                ]
            )
        ),
        "nonceAuthorityVerifierStateStoreAttestation": digest(
            decode_unpadded_base64url(
                nonce_public[
                    "nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url"
                ]
            )
        ),
        "policyActivation": digest(
            read_pem_spki(
                Path(
                    "/opt/serverware/release/evidence/"
                    "policyActivationTrustedPublicKey.json"
                )
            )
        ),
        "policyIdentity": digest(
            read_pem_spki(
                Path(
                    "/opt/serverware/release/evidence/"
                    "policyTrustedPublicKey.json"
                )
            )
        ),
        "reproducibleBuild": digest(
            read_pem_spki(
                Path(
                    "/opt/serverware/release/evidence/"
                    "reproducibleBuildTrustedPublicKey.json"
                )
            )
        ),
    }
    require(
        set(roles) == GLOBAL_ROLE_NAMES
        and len(set(roles.values())) == len(roles),
        "fixture global role registry is not closed and pairwise distinct",
    )
    registry = {
        "apiVersion": "serverware.productionLaunchGlobalRoleRegistry/v1",
        "claimScope": "roles-present-in-native-launch-contract",
        "roles": roles,
        "rolesOutsideClaim": ROLES_OUTSIDE_CLAIM,
    }
    registry_bytes = canonical(registry) + b"\n"
    GLOBAL_ROLE_REGISTRY.write_bytes(registry_bytes)
    metadata = {
        "globalRoleRegistryPinsSha256": digest(registry_bytes),
        "launchAuthorityWitnessAdministrativeDomainSha256": (
            witness_administrative_domain
        ),
        "launchAuthorityWitnessIdentitySha256": witness_identity,
        "launchAuthorityWitnessKeyId": witness_key_id,
        "launchAuthorityWitnessSigningPublicKeySpkiDerBase64url": (
            base64.urlsafe_b64encode(witness_spki)
            .rstrip(b"=")
            .decode("ascii")
        ),
        "launchAuthorityWitnessStoreAssuranceIssuerKeyId": issuer_key_id,
        "launchAuthorityWitnessStoreAssuranceIssuerPublicKeySpkiDerBase64url": (
            base64.urlsafe_b64encode(issuer_spki)
            .rstrip(b"=")
            .decode("ascii")
        ),
        "launchAuthorityWitnessStoreAssuranceSha256": digest(assurance_bytes),
    }
    TRUST_METADATA.write_bytes(canonical(metadata))
    for path in (
        WITNESS_STORE_ASSURANCE,
        GLOBAL_ROLE_REGISTRY,
        TRUST_METADATA,
    ):
        os.chown(path, 0, 0)
        os.chmod(path, 0o400)


def trust_value(name):
    metadata = json.loads(TRUST_METADATA.read_text(encoding="ascii"))
    require(name in metadata, "unknown fixture trust metadata field")
    print(metadata[name])


def build_envelope(request, mode):
    now = int(time.time())
    issued = now - 1
    expires = now + 29
    if mode == "expired":
        issued = now - 21
        expires = now - 1
    elif mode == "future":
        issued = now + 6
        expires = now + 26
    elif mode == "overlong":
        issued = now - 1
        expires = issued + 31
    elif mode == "expires-during-preflight":
        expires = now + 3

    bound_request = request
    if mode in BINDING_MUTATIONS:
        field = BINDING_MUTATIONS[mode]
        bound_request = dict(request)
        if field in ("releaseSequence", "rollbackEpoch"):
            bound_request[field] += 1
        else:
            bound_request[field] = "sha256:" + "f" * 64
    request_sha256 = request_digest(bound_request)
    if mode == "wrong-request-digest":
        request_sha256 = "sha256:" + "0" * 64

    authorization_id = hashlib.sha256(
        canonical(request) + str(time.time_ns()).encode("ascii")
    ).hexdigest()
    authority_id = authority_key_id()
    witness_statement = {
        "operation": "authorize-trusted-host-readiness",
        "operationId": request["launcherNonce"],
        "authorizationId": authorization_id,
        "requestSha256": request_sha256,
        "challenge": request["launchAuthorityWitnessChallenge"],
        "issuedAtUnixSeconds": issued,
        "expiresAtUnixSeconds": expires,
        "authorityKeyId": authority_id,
        "witnessKeyId": request["launchAuthorityWitnessKeyId"],
        "witnessIdentitySha256": request["launchAuthorityWitnessIdentitySha256"],
        "witnessAdministrativeDomainSha256": request[
            "launchAuthorityWitnessAdministrativeDomainSha256"
        ],
        "storeAssuranceSha256": request[
            "launchAuthorityWitnessStoreAssuranceSha256"
        ],
        "registryGeneration": 1,
        "registrySha256": "sha256:" + "6" * 64,
        "predecessorStateSha256": "sha256:" + "7" * 64,
        "successorStateSha256": "sha256:" + "8" * 64,
        "deploymentAudience": request["deploymentAudience"],
        "deploymentIdentitySha256": request["deploymentIdentitySha256"],
        "releaseSequence": request["releaseSequence"],
        "rollbackEpoch": request["rollbackEpoch"],
        "authorizationScope": "trusted-host-readiness",
        "stateTransitionCommitted": True,
        "checkpointSequence": 1,
    }
    witness_signed = {
        "apiVersion": "serverware.launchAuthorityWitnessTransition/v1",
        "kind": "LaunchAuthorityWitnessTransition",
        "statement": witness_statement,
    }
    witness = {
        **witness_signed,
        "signature": sign(
            WITNESS_DOMAIN + canonical(witness_signed),
            WITNESS_PRIVATE_KEY,
        ),
    }
    statement = {
        "authorizationId": authorization_id,
        "authorityKeyId": authority_id,
        "requestSha256": request_sha256,
        "issuedAtUnixSeconds": issued,
        "expiresAtUnixSeconds": expires,
        "authorizationScope": "trusted-host-readiness",
        "freshnessAuthority": "trusted-host-wall-clock",
        "capabilitySemantics": "time-bounded-idempotent-readiness-authorization",
        "globalRoleRegistrySha256": request["globalRoleRegistrySha256"],
        "monotonicWitness": witness,
    }
    if mode == "obsolete-use-limit":
        statement["useLimit"] = 1
    signed = {
        "apiVersion": "serverware.launchAuthorization/v2",
        "kind": "ProductionLaunchAuthorization",
        "statement": statement,
    }
    key_path = WRONG_PRIVATE_KEY if mode == "wrong-signing-key" else PRIVATE_KEY
    return canonical({**signed, "signature": sign(AUTHORIZATION_DOMAIN + canonical(signed), key_path)})


def append_mutation(path):
    with path.open("ab", buffering=0) as target:
        target.write(b" ")
    (STATE / "post-auth-mutation-applied").write_text(str(path) + "\n", encoding="ascii")


def mutate_after_request(mode, manifest):
    if mode == "post-auth-manifest-mutation":
        append_mutation(MANIFEST)
    elif mode == "post-auth-provenance-mutation":
        append_mutation(Path(manifest["inputs"]["releaseProvenance"]["path"]))
    elif mode == "post-auth-repro-mutation":
        append_mutation(Path(manifest["inputs"]["reproducibleBuildVerification"]["path"]))
    elif mode == "post-auth-nonce-pins-mutation":
        append_mutation(NONCE_PINS)
    elif mode == "post-auth-nonce-pins-replacement":
        require(
            not NONCE_PINS_BACKUP.exists(),
            "nonce pin mutation backup already exists",
        )
        NONCE_PINS.rename(NONCE_PINS_BACKUP)
        shutil.copy2(NONCE_PINS_BACKUP, NONCE_PINS)
        os.chown(NONCE_PINS, 0, 0)
        os.chmod(NONCE_PINS, 0o400)
        (STATE / "post-auth-mutation-applied").write_text(
            str(NONCE_PINS) + "\n",
            encoding="ascii",
        )
    elif mode == "post-auth-preflight-mutation":
        append_mutation(Path(manifest["scripts"]["preflight"]["path"]))
    elif mode == "post-auth-launcher-mutation":
        require(not LAUNCHER_BACKUP.exists(), "launcher mutation backup already exists")
        LAUNCHER.rename(LAUNCHER_BACKUP)
        shutil.copy2(LAUNCHER_BACKUP, LAUNCHER)
        os.chown(LAUNCHER, 0, 0)
        os.chmod(LAUNCHER, 0o555)
        (STATE / "post-auth-mutation-applied").write_text(str(LAUNCHER) + "\n", encoding="ascii")


def main():
    mode = sys.argv[1]
    if mode == "generate-fixture-trust":
        write_fixture_trust()
        return
    if mode == "trust-value":
        trust_value(sys.argv[2])
        return
    SOCKET.parent.mkdir(parents=True, exist_ok=True)
    try:
        SOCKET.unlink()
    except FileNotFoundError:
        pass
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
        listener.bind(str(SOCKET))
        os.chown(SOCKET, 0, 0)
        os.chmod(SOCKET, 0o600)
        listener.listen(4)
        attempts = 2 if mode in {
            "timeout",
            "lost-response",
            "drop-all",
            "malformed",
            "noncanonical",
            "oversized",
            "expired",
            "expired-then-valid",
            "old-boot-recovery",
        } else 1
        first_raw = None
        first_request = None
        for attempt in range(attempts):
            with listener.accept()[0] as connection:
                raw = connection.recv(16 * 1024 + 1)
                request, manifest = validate_request(raw)
                if mode in {"lost-response", "drop-all"} and first_raw is not None:
                    require(
                        raw == first_raw,
                        "launcher did not retry the exact canonical request",
                    )
                if mode == "old-boot-recovery":
                    if attempt == 0:
                        require(
                            request["bootIdSha256"] == "sha256:" + "0" * 64,
                            "old-boot recovery did not replay the prior boot request",
                        )
                        (STATE / "old-boot-recovered-request").write_text(
                            request["launcherNonce"] + "\n",
                            encoding="ascii",
                        )
                    else:
                        require(
                            first_request is not None
                            and raw != first_raw
                            and request["bootIdSha256"]
                            != first_request["bootIdSha256"]
                            and request["launcherNonce"]
                            != first_request["launcherNonce"],
                            "old-boot recovery did not create a fresh current-boot request",
                        )
                        (STATE / "fresh-boot-authorized-request").write_text(
                            request["launcherNonce"] + "\n",
                            encoding="ascii",
                        )
                first_raw = raw if first_raw is None else first_raw
                first_request = request if first_request is None else first_request
                (STATE / "authority-request-observed").write_text(
                    request_digest(request) + "\n",
                    encoding="ascii",
                )
                if mode == "timeout":
                    time.sleep(2.1)
                    continue
                if mode == "lost-response" and attempt == 0:
                    continue
                if mode == "drop-all":
                    continue
                response_mode = mode
                if mode in {
                    "lost-response",
                    "expired-then-valid",
                    "old-boot-recovery",
                }:
                    response_mode = (
                        "expired"
                        if mode in {
                            "expired-then-valid",
                            "old-boot-recovery",
                        }
                        and attempt == 0
                        else "valid"
                    )
                if mode == "replay":
                    response = REPLAY.read_bytes()
                elif mode == "malformed":
                    response = b"{"
                elif mode == "oversized":
                    response = b"x" * (16 * 1024 + 1)
                else:
                    response = build_envelope(request, response_mode)
                    if mode == "noncanonical":
                        response += b"\n"
                mutate_after_request(mode, manifest)
                sent = connection.send(response)
                require(
                    sent == len(response),
                    "authorization response was not sent atomically",
                )
                if response_mode == "valid":
                    REPLAY.write_bytes(response)
        time.sleep(0.1)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("test launch authority error: " + str(error), file=sys.stderr)
        sys.exit(1)
'''

FIXTURE_DRIVER = r'''
from __future__ import annotations

import base64
import hashlib
import json
import os
import signal
import stat
import subprocess
import time
from pathlib import Path


LAUNCHER = Path("/opt/serverware/bin/serverware-production-launcher-test")
LAUNCHER_BACKUP = LAUNCHER.with_name(LAUNCHER.name + ".authority-original")
AUTHORITY = "/usr/local/libexec/launch_authority_fixture.py"
AUTHORITY_SOCKET = Path("/run/serverware/launch-authority.sock")
MANIFEST = Path("/etc/serverware/production-release-launch.json")
NONCE_PINS = Path("/etc/serverware/nonce-rollback-assurance-pins.json")
NONCE_PINS_BACKUP = NONCE_PINS.with_name(
    NONCE_PINS.name + ".authority-original"
)
PIPELINE_METADATA = Path("/etc/serverware/production-launch-pipeline.json")
STATE = Path("/var/lib/serverware/production-proof")
ATTEMPT_JOURNAL = STATE / "launch-authorization-attempt.v1.json"
RELEASE_ROOT = Path("/opt/serverware/release")
AUTHORITY_PRIVATE_KEY = Path(
    "/etc/serverware/test-launch-authority-private.pem"
)
REQUEST_DOMAIN = b"serverware.launchAuthorizationRequest/v2\0"
RECOVERY_IDENTITY_DOMAIN = (
    b"serverware.launchAuthorizationAttemptRecoveryIdentity/v1\0"
)
INDEPENDENT_ADMINISTRATION_BINDINGS = (
    "launchAuthority.signingKeyId",
    "launchAuthorityWitness.signingKeyId",
    "launchAuthorityWitness.identitySha256",
    "launchAuthorityWitness.administrativeDomainSha256",
    "launchAuthorityWitnessStore.identitySha256",
    "launchAuthorityWitnessStore.administrativeDomainSha256",
    "launchAuthorityWitnessStore.assuranceIssuerKeyId",
)
MARKERS = (
    "preflight-python-started",
    "readiness-python-started",
    "preflight-ran",
    "readiness-ran",
    "preflight-receipt-ok",
    "readiness-receipt-ok",
    "hostile-loader-ran",
    "hostile-site-ran",
    "readiness-source-mutated",
    "mutated-readiness-ran",
    "authority-request-observed",
    "post-auth-mutation-applied",
    "delay-preflight-until-authorization-expires",
    "spawn-stubborn-preflight-descendant-until-authorization-expires",
    "stubborn-preflight-descendant-pid",
    "old-boot-recovered-request",
    "fresh-boot-authorized-request",
    "launched-request",
)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def canonical(value):
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")


def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def unpadded_base64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def private_key_spki(path):
    result = subprocess.run(
        [
            "/usr/bin/openssl",
            "pkey",
            "-in",
            str(path),
            "-pubout",
            "-outform",
            "DER",
        ],
        check=False,
        capture_output=True,
    )
    require(
        result.returncode == 0,
        "could not derive fixture authority SPKI: "
        + result.stderr.decode("utf-8", errors="replace"),
    )
    return result.stdout


def reset_markers():
    for name in MARKERS:
        try:
            (STATE / name).unlink()
        except FileNotFoundError:
            pass
    ATTEMPT_JOURNAL.unlink(missing_ok=True)


def rewrite_attempt_journal_as_old_boot():
    journal = json.loads(ATTEMPT_JOURNAL.read_text(encoding="ascii"))
    request = journal["request"]
    request["bootIdSha256"] = "sha256:" + "0" * 64
    recovery_identity = {
        "domain": request["launchAttemptJournalDomain"],
        "launcherNonce": request["launcherNonce"],
        "witnessChallenge": request["launchAuthorityWitnessChallenge"],
        "bootIdSha256": request["bootIdSha256"],
        "manifestSha256": request["manifestSha256"],
        "globalRoleRegistrySha256": request["globalRoleRegistrySha256"],
    }
    recovery_sha256 = digest(
        RECOVERY_IDENTITY_DOMAIN + canonical(recovery_identity)
    )
    request["launchAttemptRecoveryIdentitySha256"] = recovery_sha256
    journal["requestSha256"] = digest(REQUEST_DOMAIN + canonical(request))
    journal["recoveryIdentitySha256"] = recovery_sha256
    encoded = canonical(journal) + b"\n"
    with ATTEMPT_JOURNAL.open("r+b", buffering=0) as target:
        target.write(encoded)
        target.truncate()
        os.fsync(target.fileno())
    os.chmod(ATTEMPT_JOURNAL, 0o600)


def wait_for_authority(authority):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if authority.poll() is not None:
            _, stderr = authority.communicate()
            raise AssertionError("launch authority exited before binding: " + stderr)
        try:
            metadata = AUTHORITY_SOCKET.lstat()
        except FileNotFoundError:
            time.sleep(0.01)
            continue
        require(stat.S_ISSOCK(metadata.st_mode), "launch authority fixture is not a socket")
        require((metadata.st_uid, metadata.st_gid) == (0, 0), "launch authority socket is not root-owned")
        require(metadata.st_mode & 0o002 == 0, "launch authority socket is world-writable")
        return
    raise AssertionError("launch authority did not bind its socket")


def launch(
    *extra,
    authority_mode="valid",
    hostile=False,
    fd9=False,
    fd198=False,
    nonroot=False,
    timeout=60,
):
    try:
        AUTHORITY_SOCKET.unlink()
    except FileNotFoundError:
        pass
    authority = None
    if authority_mode is not None:
        authority = subprocess.Popen(
            ["/usr/local/bin/python3", "-I", "-S", AUTHORITY, authority_mode],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        wait_for_authority(authority)

    command = [str(LAUNCHER), "--manifest", str(MANIFEST), *extra]
    environment = os.environ.copy()
    if hostile:
        environment.update(
            {
                "LD_PRELOAD": "/opt/serverware/hostile/hostile.so",
                "LD_AUDIT": "/opt/serverware/hostile/hostile.so",
                "PYTHONPATH": "/opt/serverware/hostile/python",
                "PYTHONHOME": "/opt/serverware/hostile/python-home",
            }
        )

    inherited = []
    if fd9:
        source_fd = os.open("/etc/hostname", os.O_RDONLY)
        os.dup2(source_fd, 9)
        if source_fd != 9:
            os.close(source_fd)
        os.set_inheritable(9, True)
        inherited.append(9)
    if fd198:
        source_fd = os.open("/etc/hostname", os.O_RDONLY)
        os.dup2(source_fd, 198)
        if source_fd != 198:
            os.close(source_fd)
        os.set_inheritable(198, True)
        inherited.append(198)

    def demote():
        os.setgroups([])
        os.setgid(65534)
        os.setuid(65534)

    started = time.monotonic()
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            env=environment,
            pass_fds=tuple(inherited),
            preexec_fn=demote if nonroot else None,
            text=True,
            timeout=timeout,
        )
    finally:
        if fd9:
            os.close(9)
        if fd198:
            os.close(198)
    elapsed = time.monotonic() - started

    if authority is not None:
        try:
            _, authority_stderr = authority.communicate(timeout=0.5)
        except subprocess.TimeoutExpired:
            authority.terminate()
            try:
                _, authority_stderr = authority.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                authority.kill()
                _, authority_stderr = authority.communicate()
        if authority.returncode not in (0, -signal.SIGTERM):
            raise AssertionError(
                "launch authority fixture failed with "
                + str(authority.returncode)
                + ": "
                + authority_stderr
            )
    try:
        AUTHORITY_SOCKET.unlink()
    except FileNotFoundError:
        pass
    return result, elapsed


def assert_no_python(name):
    for marker in (
        "preflight-python-started",
        "readiness-python-started",
        "preflight-ran",
        "readiness-ran",
    ):
        require(not (STATE / marker).exists(), name + " reached Python: " + marker)


def process_is_live(pid):
    try:
        raw = Path("/proc/" + str(pid) + "/stat").read_text(encoding="ascii")
    except FileNotFoundError:
        return False
    _, remainder = raw.rsplit(")", 1)
    return remainder.split()[0] not in {"X", "Z"}


def rejected(name, expected, *extra, authority_mode="valid", nonroot=False, observed=None):
    reset_markers()
    result, elapsed = launch(*extra, authority_mode=authority_mode, nonroot=nonroot)
    require(result.returncode != 0, name + " unexpectedly succeeded")
    require(expected in result.stderr, name + " did not report the expected rejection: " + result.stderr)
    assert_no_python(name)
    if observed is not None:
        require(
            (STATE / "authority-request-observed").exists() == observed,
            name + " had the wrong authority request state",
        )
    return result, elapsed


def restore_bytes(path, original, mode):
    with path.open("r+b", buffering=0) as target:
        target.write(original)
        target.truncate()
    os.chmod(path, mode)


def write_manifest(manifest, mode):
    encoded = json.dumps(
        manifest, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii") + b"\n"
    restore_bytes(MANIFEST, encoded, mode)


def unicode_manifest_path_rejected(name, location, label):
    original = MANIFEST.read_bytes()
    original_mode = stat.S_IMODE(MANIFEST.stat().st_mode)
    manifest = json.loads(original.decode("utf-8"))
    target = manifest
    for component in location[:-1]:
        target = target[component]
    leaf = location[-1]
    target[leaf] = target[leaf] + "-\u00e9"
    try:
        write_manifest(manifest, original_mode)
        rejected(
            name,
            label
            + " must use the safe printable-ASCII production path syntax",
            authority_mode=None,
            observed=False,
        )
    finally:
        restore_bytes(MANIFEST, original, original_mode)


def independent_administration_binding_values(manifest):
    witness = manifest["authorization"]["monotonicWitness"]
    statement = witness["storeAssurance"]["statement"]
    return (
        manifest["globalRoleRegistry"]["registry"]["roles"][
            "launchAuthority"
        ],
        witness["signingKeyId"],
        witness["identitySha256"],
        witness["administrativeDomainSha256"],
        statement["storeIdentitySha256"],
        statement["storeAdministrativeDomainSha256"],
        witness["storeAssuranceIssuerKeyId"],
    )


def set_independent_administration_digest_binding(
    manifest,
    index,
    value,
):
    witness = manifest["authorization"]["monotonicWitness"]
    statement = witness["storeAssurance"]["statement"]
    if index == 2:
        witness["identitySha256"] = value
        statement["witnessIdentitySha256"] = value
    elif index == 3:
        witness["administrativeDomainSha256"] = value
        statement["witnessAdministrativeDomainSha256"] = value
    elif index == 4:
        statement["storeIdentitySha256"] = value
    elif index == 5:
        statement["storeAdministrativeDomainSha256"] = value
    else:
        raise AssertionError("binding is not a mutable digest identity")


def set_witness_signing_spki(manifest, spki):
    witness = manifest["authorization"]["monotonicWitness"]
    key_id = digest(spki)
    witness["signingPublicKeySpkiDerBase64url"] = unpadded_base64url(spki)
    witness["signingKeyId"] = key_id
    witness["storeAssurance"]["statement"]["witnessKeyId"] = key_id


def set_store_assurance_issuer_spki(manifest, spki):
    witness = manifest["authorization"]["monotonicWitness"]
    key_id = digest(spki)
    witness[
        "storeAssuranceIssuerPublicKeySpkiDerBase64url"
    ] = unpadded_base64url(spki)
    witness["storeAssuranceIssuerKeyId"] = key_id
    witness["storeAssurance"]["statement"]["assuranceIssuerKeyId"] = key_id


def rebind_store_assurance_digest(manifest):
    witness = manifest["authorization"]["monotonicWitness"]
    witness["storeAssuranceSha256"] = digest(
        canonical(witness["storeAssurance"])
    )


def independent_administration_collision_rejected(left, right):
    original = MANIFEST.read_bytes()
    original_mode = stat.S_IMODE(MANIFEST.stat().st_mode)
    manifest = json.loads(original.decode("utf-8"))
    values = independent_administration_binding_values(manifest)
    if (left, right) == (0, 1):
        set_witness_signing_spki(
            manifest,
            private_key_spki(AUTHORITY_PRIVATE_KEY),
        )
    elif right == 6:
        if left == 0:
            set_store_assurance_issuer_spki(
                manifest,
                private_key_spki(AUTHORITY_PRIVATE_KEY),
            )
        elif left == 1:
            encoded_witness_spki = manifest["authorization"][
                "monotonicWitness"
            ]["signingPublicKeySpkiDerBase64url"]
            witness_spki = base64.urlsafe_b64decode(
                encoded_witness_spki
                + "=" * (-len(encoded_witness_spki) % 4)
            )
            set_store_assurance_issuer_spki(manifest, witness_spki)
        else:
            set_independent_administration_digest_binding(
                manifest,
                left,
                values[right],
            )
    else:
        set_independent_administration_digest_binding(
            manifest,
            right,
            values[left],
        )
    rebind_store_assurance_digest(manifest)
    left_label = INDEPENDENT_ADMINISTRATION_BINDINGS[left]
    right_label = INDEPENDENT_ADMINISTRATION_BINDINGS[right]
    try:
        write_manifest(manifest, original_mode)
        rejected(
            "independent-administration collision "
            + left_label
            + " / "
            + right_label,
            "independentAdministration requires pairwise-distinct authority, "
            "witness, and witness-store bindings: "
            + left_label
            + " collides with "
            + right_label,
            authority_mode=None,
            observed=False,
        )
    finally:
        restore_bytes(MANIFEST, original, original_mode)


def import_root_contract_rejected(name, mode, expected):
    original = MANIFEST.read_bytes()
    original_mode = stat.S_IMODE(MANIFEST.stat().st_mode)
    manifest = json.loads(original.decode("utf-8"))
    roots = manifest["python"]["importRoots"]
    if mode == "missing-lib-dynload":
        roots.pop(2)
    elif mode == "reordered-lib-dynload":
        roots[2], roots[3] = roots[3], roots[2]
    elif mode == "wrong-lib-dynload":
        roots[2]["path"] = str(RELEASE_ROOT / "runtime/python/lib/lib-dynload")
    elif mode == "wrong-interpreter-version":
        roots[1]["path"] = str(RELEASE_ROOT / "runtime/python/lib/python3.12")
        roots[2]["path"] = str(RELEASE_ROOT / "runtime/python/lib/python3.12/lib-dynload")
    else:
        raise AssertionError("unknown import-root mutation: " + mode)
    try:
        write_manifest(manifest, original_mode)
        rejected(name, expected, observed=False)
    finally:
        restore_bytes(MANIFEST, original, original_mode)


def launcher_locator_contract_rejected(name, mode, expected):
    original = MANIFEST.read_bytes()
    original_mode = stat.S_IMODE(MANIFEST.stat().st_mode)
    manifest = json.loads(original.decode("utf-8"))
    if mode == "moved-state-directory":
        manifest["stateDirectory"] = "/var/lib/serverware/other-production-proof"
    elif mode == "moved-journal":
        manifest["launchAttemptJournal"]["path"] = (
            "/var/lib/serverware/production-proof/other-attempt.json"
        )
    elif mode == "moved-journal-lock":
        manifest["launchAttemptJournal"]["lockPath"] = (
            "/var/lib/serverware/production-proof/other-attempt.lock"
        )
    else:
        raise AssertionError("unknown launcher locator mutation: " + mode)
    try:
        write_manifest(manifest, original_mode)
        rejected(name, expected, observed=False)
    finally:
        restore_bytes(MANIFEST, original, original_mode)


def nonce_manifest_contract_rejected(name, mode, expected):
    original = MANIFEST.read_bytes()
    original_mode = stat.S_IMODE(MANIFEST.stat().st_mode)
    manifest = json.loads(original.decode("utf-8"))
    binding = manifest["nonceRollbackAssurance"]
    assurance = binding["contract"]["publicConfigPins"][
        "nonceAuthorityAssurance"
    ]
    public = binding["contract"]["publicConfigPins"]
    if mode == "v2":
        manifest["apiVersion"] = "serverware.productionReadinessLaunch/v2"
    elif mode == "unknown":
        binding["unexpected"] = True
    elif mode == "wrong-profile":
        assurance["backendClass"] = "unapprovedBackend"
    elif mode == "role-collision":
        public["nonceAuthorityVerifierStateStoreIdentitySha256"] = assurance[
            "authorityIdentitySha256"
        ]
    elif mode == "missing-store-trust":
        public.pop(
            "nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url"
        )
    elif mode == "stale-store-alias":
        public[
            "nonceAuthorityVerifierStateStoreAttestationSigningPublicKeySpkiDerBase64url"
        ] = public.pop(
            "nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url"
        )
    elif mode == "missing-store-evidence":
        public.pop(
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"
        )
    elif mode == "stale-store-evidence-alias":
        public[
            "nonceAuthorityVerifierStateStoreAssuranceSha256"
        ] = public.pop(
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"
        )
    elif mode == "store-key-collision":
        public[
            "nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url"
        ] = public[
            "nonceAuthorityVerifierStateSigningPublicKeySpkiDerBase64url"
        ]
    elif mode == "store-evidence-collision":
        public[
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"
        ] = assurance["assuranceEvidenceSha256"]
    elif mode == "unsafe-integer":
        assurance["authorityGeneration"] = 1 << 53
    elif mode == "contract-substitution":
        public["nonceAuthorityVerifierStateStoreIdentitySha256"] = (
            "sha256:" + "f" * 64
        )
    else:
        raise AssertionError("unknown nonce manifest mutation: " + mode)
    if mode not in {"v2", "unknown"}:
        binding["contractSha256"] = (
            "sha256:"
            + hashlib.sha256(canonical(binding["contract"])).hexdigest()
        )
    try:
        write_manifest(manifest, original_mode)
        rejected(name, expected, observed=False)
    finally:
        restore_bytes(MANIFEST, original, original_mode)


def wrong_libpython_version_rejected():
    python_path = RELEASE_ROOT / "runtime/python/bin/python3"
    original_python = python_path.read_bytes()
    python_mode = stat.S_IMODE(python_path.stat().st_mode)
    original_manifest = MANIFEST.read_bytes()
    manifest_mode = stat.S_IMODE(MANIFEST.stat().st_mode)
    expected = b"libpython3.11.so.1.0"
    replacement = b"libpython3.12.so.1.0"
    require(
        original_python.count(expected) > 0,
        "fixture Python ELF omits its libpython3.11 dependency metadata",
    )
    mutated_python = original_python.replace(expected, replacement)
    manifest = json.loads(original_manifest.decode("utf-8"))
    manifest["python"]["sha256"] = "sha256:" + hashlib.sha256(mutated_python).hexdigest()
    try:
        restore_bytes(python_path, mutated_python, python_mode)
        write_manifest(manifest, manifest_mode)
        rejected(
            "wrong libpython version",
            "python ELF does not depend on a compatible libpython3.11.so",
            observed=False,
        )
    finally:
        restore_bytes(MANIFEST, original_manifest, manifest_mode)
        restore_bytes(python_path, original_python, python_mode)


def post_authorization_file_rejected(name, mode, path, expected):
    original = path.read_bytes()
    original_mode = stat.S_IMODE(path.stat().st_mode)
    try:
        rejected(name, expected, authority_mode=mode, observed=True)
        require((STATE / "post-auth-mutation-applied").is_file(), name + " did not mutate its target")
    finally:
        restore_bytes(path, original, original_mode)


def measured_role_substitution_rejected(
    name,
    target_input,
    replacement_input,
    role,
):
    original_manifest = MANIFEST.read_bytes()
    manifest_mode = stat.S_IMODE(MANIFEST.stat().st_mode)
    manifest = json.loads(original_manifest.decode("utf-8"))
    target = Path(manifest["inputs"][target_input]["path"])
    replacement = Path(manifest["inputs"][replacement_input]["path"])
    original_target = target.read_bytes()
    target_mode = stat.S_IMODE(target.stat().st_mode)
    replacement_bytes = replacement.read_bytes()
    require(
        replacement_bytes != original_target,
        name + " fixture keys unexpectedly have identical bytes",
    )
    manifest["inputs"][target_input]["sha256"] = digest(replacement_bytes)
    try:
        restore_bytes(target, replacement_bytes, target_mode)
        write_manifest(manifest, manifest_mode)
        rejected(
            name,
            "globalRoleRegistry "
            + role
            + " does not match measured "
            + target_input
            + " SPKI",
            observed=False,
        )
    finally:
        restore_bytes(MANIFEST, original_manifest, manifest_mode)
        restore_bytes(target, original_target, target_mode)


def main():
    scenarios = 0
    reset_markers()
    fd9_expectation = STATE / "expect-inherited-fd9-closed"
    fd9_expectation.write_text("1\n", encoding="ascii")
    try:
        valid, _ = launch(hostile=True, fd9=True)
    finally:
        fd9_expectation.unlink()
    require(valid.returncode == 0, "valid launch failed: " + valid.stderr)
    for marker in (
        "preflight-python-started",
        "readiness-python-started",
        "preflight-ran",
        "readiness-ran",
        "preflight-receipt-ok",
        "readiness-receipt-ok",
        "authority-request-observed",
    ):
        require((STATE / marker).is_file(), "valid launch omitted " + marker)
    require(not (STATE / "hostile-loader-ran").exists(), "hostile dynamic-loader environment executed")
    require(not (STATE / "hostile-site-ran").exists(), "hostile sitecustomize executed")
    scenarios += 1

    reset_markers()
    occupied_receipt_fd, _ = launch(fd198=True)
    require(
        occupied_receipt_fd.returncode == 0,
        "launcher did not replace a hostile inherited fixed receipt descriptor: "
        + occupied_receipt_fd.stderr,
    )
    for marker in (
        "preflight-receipt-ok",
        "readiness-receipt-ok",
    ):
        require(
            (STATE / marker).is_file(),
            "fixed receipt descriptor reservation omitted " + marker,
        )
    scenarios += 1

    reset_markers()
    interrupted, _ = launch(authority_mode="drop-all")
    require(
        interrupted.returncode != 0,
        "lost relay responses unexpectedly completed a launch",
    )
    assert_no_python("lost relay responses")
    require(
        ATTEMPT_JOURNAL.is_file(),
        "lost relay responses did not retain the exact prepared operation",
    )
    rewrite_attempt_journal_as_old_boot()
    recovered, _ = launch(authority_mode="old-boot-recovery")
    require(
        recovered.returncode == 0,
        "old-boot recovery did not recover then authorize a fresh request: "
        + recovered.stderr,
    )
    old_nonce = (STATE / "old-boot-recovered-request").read_text(
        encoding="ascii"
    ).strip()
    fresh_nonce = (STATE / "fresh-boot-authorized-request").read_text(
        encoding="ascii"
    ).strip()
    launched_nonce = (STATE / "launched-request").read_text(
        encoding="ascii"
    ).strip()
    require(old_nonce != fresh_nonce, "old and fresh requests reused one nonce")
    require(
        launched_nonce == fresh_nonce and launched_nonce != old_nonce,
        "a recovered prior-boot authorization became launchable",
    )
    require(
        not ATTEMPT_JOURNAL.exists(),
        "terminal old-boot recovery left the attempt journal behind",
    )
    scenarios += 1

    rejected("replayed authorization", "LAUTH_REQUEST_MISMATCH", authority_mode="replay", observed=True)
    scenarios += 1

    preflight_path = RELEASE_ROOT / "scripts/preflight.py"
    post_authorization_file_rejected(
        "post-authorization preflight mutation",
        "post-auth-preflight-mutation",
        preflight_path,
        "python.importRoots[0] post-authorization digest does not match",
    )
    scenarios += 1

    reset_markers()
    readiness_switch = STATE / "mutate-readiness-source"
    readiness_path = RELEASE_ROOT / "scripts/runner.py"
    original_readiness = readiness_path.read_bytes()
    readiness_mode = stat.S_IMODE(readiness_path.stat().st_mode)
    readiness_switch.write_text("1\n", encoding="ascii")
    try:
        mutated_readiness, _ = launch()
    finally:
        readiness_switch.unlink()
        restore_bytes(readiness_path, original_readiness, readiness_mode)
    require(mutated_readiness.returncode != 0, "post-preflight readiness mutation unexpectedly succeeded")
    require(
        "python.importRoots[0] post-authorization digest does not match" in mutated_readiness.stderr,
        "readiness mutation did not trigger post-authorization remeasurement: " + mutated_readiness.stderr,
    )
    require((STATE / "preflight-ran").is_file(), "preflight did not run before readiness mutation rejection")
    require((STATE / "readiness-source-mutated").is_file(), "preflight did not mutate readiness source")
    require(not (STATE / "readiness-ran").exists(), "readiness ran after its source changed")
    require(not (STATE / "mutated-readiness-ran").exists(), "mutated readiness source bytes executed")
    scenarios += 1

    reset_markers()
    expiry_switch = STATE / "delay-preflight-until-authorization-expires"
    expiry_switch.write_text("1\n", encoding="ascii")
    try:
        expired_between_phases, _ = launch(authority_mode="expires-during-preflight")
    finally:
        expiry_switch.unlink(missing_ok=True)
    require(
        expired_between_phases.returncode != 0,
        "authorization that expired during preflight unexpectedly reached the runner",
    )
    require(
        "LAUTH_PHASE_OUTCOME_UNKNOWN" in expired_between_phases.stderr,
        "in-flight preflight expiry was not classified conservatively: "
        + expired_between_phases.stderr,
    )
    require((STATE / "preflight-ran").is_file(), "short-lived authorization did not reach preflight")
    require(not (STATE / "readiness-ran").exists(), "runner used an authorization expired by preflight")
    scenarios += 1

    reset_markers()
    stubborn_switch = (
        STATE
        / "spawn-stubborn-preflight-descendant-until-authorization-expires"
    )
    stubborn_switch.write_text("1\n", encoding="ascii")
    try:
        stubborn_expiry, stubborn_elapsed = launch(
            authority_mode="expires-during-preflight",
            timeout=10,
        )
    finally:
        stubborn_switch.unlink(missing_ok=True)
    require(
        stubborn_expiry.returncode != 0,
        "deadline-resistant preflight process group unexpectedly succeeded",
    )
    require(
        "LAUTH_PHASE_OUTCOME_UNKNOWN" in stubborn_expiry.stderr,
        "deadline-resistant phase was not classified as outcome-unknown: "
        + stubborn_expiry.stderr,
    )
    require(
        "force-killed and reaped" in stubborn_expiry.stderr,
        "deadline-resistant process group was not force-killed and reaped: "
        + stubborn_expiry.stderr,
    )
    require(
        2.0 <= stubborn_elapsed < 6.0,
        "deadline-resistant process group was not bounded: "
        + str(stubborn_elapsed),
    )
    descendant_pid = int(
        (STATE / "stubborn-preflight-descendant-pid")
        .read_text(encoding="ascii")
        .strip()
    )
    survivor_deadline = time.monotonic() + 2
    while process_is_live(descendant_pid) and time.monotonic() < survivor_deadline:
        time.sleep(0.01)
    require(
        not process_is_live(descendant_pid),
        "deadline-resistant phase descendant survived launcher cleanup",
    )
    require(
        not (STATE / "readiness-ran").exists(),
        "readiness ran after deadline-resistant preflight termination",
    )
    scenarios += 1

    pre_authorization_cases = (
        ("non-root invocation", "effective UID 0", (), {"nonroot": True}),
        ("unknown argument", "unknown launcher argument", ("--arbitrary", "value"), {}),
        ("duplicate argument", "duplicate --manifest argument", ("--manifest", str(MANIFEST)), {}),
        (
            "manifest digest override",
            "unknown launcher argument: --manifest-sha256",
            ("--manifest-sha256", "sha256:" + "0" * 64),
            {},
        ),
    )
    for name, expected, extra, options in pre_authorization_cases:
        rejected(name, expected, *extra, observed=False, **options)
        scenarios += 1

    unicode_path_cases = [
        ("release root", ("releaseRoot",), "releaseRoot"),
        ("state directory", ("stateDirectory",), "stateDirectory"),
        (
            "launch attempt journal",
            ("launchAttemptJournal", "path"),
            "launchAttemptJournal.path",
        ),
        (
            "launch attempt journal lock",
            ("launchAttemptJournal", "lockPath"),
            "launchAttemptJournal.lockPath",
        ),
        (
            "global role registry pins",
            ("globalRoleRegistry", "pinsFile", "path"),
            "globalRoleRegistry.pinsFile.path",
        ),
        (
            "nonce rollback assurance pins",
            ("nonceRollbackAssurance", "pinsFile", "path"),
            "nonceRollbackAssurance.pinsFile.path",
        ),
        (
            "production environment",
            ("productionEnv", "path"),
            "productionEnv.path",
        ),
        ("python executable", ("python", "path"), "python.path"),
        (
            "preflight script",
            ("scripts", "preflight", "path"),
            "scripts.preflight.path",
        ),
        (
            "readiness script",
            ("scripts", "runner", "path"),
            "scripts.runner.path",
        ),
        ("compose file", ("composeFile", "path"), "composeFile.path"),
    ]
    for index in range(4):
        unicode_path_cases.append(
            (
                "python import root " + str(index),
                ("python", "importRoots", index, "path"),
                "python.importRoots[" + str(index) + "].path",
            )
        )
    for name in (
        "productionImagesBuild",
        "productionImagesEnv",
        "productionImagesPublished",
        "releaseProvenanceSummary",
        "releaseProvenance",
        "imageSignaturesSummary",
        "imageSignatures",
        "bench",
        "kmsMaterials",
        "policyBundle",
        "policyTrustedPublicKey",
        "policyIdentityVerification",
        "policyActivationVerification",
        "policyActivationSignature",
        "policyActivationTrustedPublicKey",
        "reproducibleBuildVerification",
        "reproducibleBuildSignature",
        "reproducibleBuildTrustedPublicKey",
    ):
        unicode_path_cases.append(
            (
                "input " + name,
                ("inputs", name, "path"),
                "inputs." + name + ".path",
            )
        )
    for name in (
        "configOut",
        "claimsFile",
        "nitroEvidenceOut",
        "readinessOut",
        "completionProofOut",
        "proxyProofSummaryOut",
        "productionHostPreflight",
    ):
        unicode_path_cases.append(
            (
                "output " + name,
                ("outputs", name),
                "outputs." + name,
            )
        )
    require(
        len(unicode_path_cases) == 40,
        "manifest path-field inventory drifted",
    )
    for name, location, label in unicode_path_cases:
        unicode_manifest_path_rejected(
            "non-ASCII " + name,
            location,
            label,
        )
        scenarios += 1

    independent_administration_collisions = 0
    for left in range(len(INDEPENDENT_ADMINISTRATION_BINDINGS)):
        for right in range(
            left + 1,
            len(INDEPENDENT_ADMINISTRATION_BINDINGS),
        ):
            independent_administration_collision_rejected(left, right)
            independent_administration_collisions += 1
            scenarios += 1
    require(
        independent_administration_collisions == 21,
        "independent-administration collision matrix drifted",
    )

    for name, mode, expected in (
        (
            "movable production state directory",
            "moved-state-directory",
            "stateDirectory must be the compiled production state directory",
        ),
        (
            "movable launch attempt journal",
            "moved-journal",
            "launchAttemptJournal path and lockPath must be the fixed v1 children",
        ),
        (
            "movable launch attempt journal lock",
            "moved-journal-lock",
            "launchAttemptJournal path and lockPath must be the fixed v1 children",
        ),
    ):
        launcher_locator_contract_rejected(name, mode, expected)
        scenarios += 1

    os.chmod(MANIFEST, 0o644)
    try:
        rejected("wrong manifest mode", "manifest mode must be exactly 0400 or 0440", observed=False)
    finally:
        os.chmod(MANIFEST, 0o400)
    scenarios += 1

    os.chown(MANIFEST, 65534, 65534)
    try:
        rejected("wrong manifest owner", "manifest must be owned by root:root", observed=False)
    finally:
        os.chown(MANIFEST, 0, 0)
    scenarios += 1

    real_manifest = MANIFEST.with_suffix(".real")
    MANIFEST.rename(real_manifest)
    MANIFEST.symlink_to(real_manifest)
    try:
        rejected("symlink manifest", "could not securely open manifest", observed=False)
    finally:
        MANIFEST.unlink()
        real_manifest.rename(MANIFEST)
    scenarios += 1

    for name, mode, expected in (
        (
            "v2 manifest downgrade",
            "v2",
            "legacy v2 launch manifests are readiness-only",
        ),
        (
            "unknown nonce binding field",
            "unknown",
            "launch manifest is invalid",
        ),
        (
            "wrong nonce assurance profile",
            "wrong-profile",
            "complete production rollback profile",
        ),
        (
            "nonce authority and store role collision",
            "role-collision",
            "pairwise distinct",
        ),
        (
            "missing verifier-state store trust pin",
            "missing-store-trust",
            "launch manifest is invalid",
        ),
        (
            "stale verifier-state store trust alias",
            "stale-store-alias",
            "launch manifest is invalid",
        ),
        (
            "missing verifier-state store assurance evidence pin",
            "missing-store-evidence",
            "launch manifest is invalid",
        ),
        (
            "stale verifier-state store assurance evidence alias",
            "stale-store-evidence-alias",
            "launch manifest is invalid",
        ),
        (
            "verifier-state and store attestation key collision",
            "store-key-collision",
            "signing roles are not independently pinned and separated",
        ),
        (
            "authority and store assurance evidence collision",
            "store-evidence-collision",
            "assurance evidence must be independently pinned",
        ),
        (
            "nonce assurance unsafe integer",
            "unsafe-integer",
            "complete production rollback profile",
        ),
        (
            "nonce contract substitution behind same path",
            "contract-substitution",
            "pin file differs from the manifest-bound canonical contract",
        ),
    ):
        nonce_manifest_contract_rejected(name, mode, expected)
        scenarios += 1

    pins_original = NONCE_PINS.read_bytes()
    pins_mode = stat.S_IMODE(NONCE_PINS.stat().st_mode)
    missing_pins = NONCE_PINS.with_suffix(".missing")
    NONCE_PINS.rename(missing_pins)
    try:
        rejected(
            "missing nonce pin file",
            "could not securely open nonceRollbackAssurance.pinsFile",
            observed=False,
        )
    finally:
        missing_pins.rename(NONCE_PINS)
    scenarios += 1

    try:
        restore_bytes(NONCE_PINS, pins_original + b" ", pins_mode)
        rejected(
            "stale nonce pin file digest",
            "nonceRollbackAssurance.pinsFile digest does not match",
            observed=False,
        )
    finally:
        restore_bytes(NONCE_PINS, pins_original, pins_mode)
    scenarios += 1

    os.chmod(NONCE_PINS, 0o644)
    try:
        rejected(
            "wrong nonce pin file mode",
            "nonceRollbackAssurance.pinsFile mode must be exactly 0400 or 0440",
            observed=False,
        )
    finally:
        os.chmod(NONCE_PINS, pins_mode)
    scenarios += 1

    real_pins = NONCE_PINS.with_suffix(".real")
    NONCE_PINS.rename(real_pins)
    NONCE_PINS.symlink_to(real_pins)
    try:
        rejected(
            "symlink nonce pin file",
            "could not securely open nonceRollbackAssurance.pinsFile",
            observed=False,
        )
    finally:
        NONCE_PINS.unlink()
        real_pins.rename(NONCE_PINS)
    scenarios += 1

    metadata_original = PIPELINE_METADATA.read_bytes()
    metadata_mode = stat.S_IMODE(PIPELINE_METADATA.stat().st_mode)
    restore_bytes(
        PIPELINE_METADATA,
        b'{"crash":"stale projection"}\n',
        metadata_mode,
    )
    try:
        reset_markers()
        metadata_independent, _ = launch()
        require(
            metadata_independent.returncode == 0,
            "mutable metadata projection affected launcher security: "
            + metadata_independent.stderr,
        )
    finally:
        restore_bytes(
            PIPELINE_METADATA,
            metadata_original,
            metadata_mode,
        )
    scenarios += 1

    import_root_contract_rejected(
        "missing lib-dynload import root",
        "missing-lib-dynload",
        "python.importRoots must contain exactly four ordered roots",
    )
    scenarios += 1

    import_root_contract_rejected(
        "reordered lib-dynload import root",
        "reordered-lib-dynload",
        "python.importRoots must be ordered as releaseRoot, stdlib, lib-dynload, vendor",
    )
    scenarios += 1

    import_root_contract_rejected(
        "wrong lib-dynload import root",
        "wrong-lib-dynload",
        "python.importRoots must be ordered as releaseRoot, stdlib, lib-dynload, vendor",
    )
    scenarios += 1

    import_root_contract_rejected(
        "wrong interpreter version",
        "wrong-interpreter-version",
        "python ELF does not depend on a compatible libpython3.12.so",
    )
    scenarios += 1

    wrong_libpython_version_rejected()
    scenarios += 1

    for name, target_input, replacement_input, role in (
        (
            "policy identity SPKI substitution",
            "policyTrustedPublicKey",
            "policyActivationTrustedPublicKey",
            "policyIdentity",
        ),
        (
            "policy activation SPKI substitution",
            "policyActivationTrustedPublicKey",
            "policyTrustedPublicKey",
            "policyActivation",
        ),
        (
            "reproducible-build SPKI substitution",
            "reproducibleBuildTrustedPublicKey",
            "policyTrustedPublicKey",
            "reproducibleBuild",
        ),
    ):
        measured_role_substitution_rejected(
            name,
            target_input,
            replacement_input,
            role,
        )
        scenarios += 1

    mutation = RELEASE_ROOT / "unexpected_mutation.py"
    mutation.write_text("raise RuntimeError('must never import')\n", encoding="ascii")
    os.chmod(mutation, 0o444)
    try:
        rejected("import-root mutation", "python.importRoots[0] digest does not match", observed=False)
    finally:
        mutation.unlink()
    scenarios += 1

    reset_markers()
    failure_switch = STATE / "force-preflight-fail"
    failure_switch.write_text("1\n", encoding="ascii")
    try:
        failed_preflight, _ = launch()
    finally:
        failure_switch.unlink()
    require(
        failed_preflight.returncode == 23,
        "preflight status was not preserved: " + str(failed_preflight.returncode) + " " + failed_preflight.stderr,
    )
    require((STATE / "preflight-ran").is_file(), "failing preflight did not execute")
    require(not (STATE / "readiness-ran").exists(), "readiness ran after preflight rejection")
    scenarios += 1

    reset_markers()
    original_readiness = readiness_path.read_bytes()
    readiness_mode = stat.S_IMODE(readiness_path.stat().st_mode)
    readiness_switch = STATE / "mutate-readiness-source"
    failure_switch = STATE / "force-preflight-fail"
    readiness_switch.write_text("1\n", encoding="ascii")
    failure_switch.write_text("1\n", encoding="ascii")
    try:
        failed_preflight_after_mutation, _ = launch()
    finally:
        readiness_switch.unlink(missing_ok=True)
        failure_switch.unlink(missing_ok=True)
        restore_bytes(readiness_path, original_readiness, readiness_mode)
    require(
        failed_preflight_after_mutation.returncode == 23,
        "known preflight failure was masked by post-phase revalidation: "
        + str(failed_preflight_after_mutation.returncode)
        + " "
        + failed_preflight_after_mutation.stderr,
    )
    require(
        (STATE / "readiness-source-mutated").is_file(),
        "status-preservation fixture did not mutate the later phase source",
    )
    require(
        not (STATE / "readiness-ran").exists(),
        "readiness ran after a known nonzero preflight status",
    )
    scenarios += 1

    rejected(
        "missing launch authority relay",
        "LAUTH_SOCKET_UNAVAILABLE",
        authority_mode=None,
        observed=False,
    )
    scenarios += 1

    _, timeout_elapsed = rejected(
        "launch authority timeout",
        "LAUTH_TIMEOUT",
        authority_mode="timeout",
        observed=True,
    )
    require(1.5 <= timeout_elapsed < 5.0, "launch authority timeout was not bounded: " + str(timeout_elapsed))
    scenarios += 1

    authorization_cases = (
        ("wrong signing key", "LAUTH_SIGNATURE_INVALID", "wrong-signing-key"),
        ("wrong request digest", "LAUTH_REQUEST_MISMATCH", "wrong-request-digest"),
        ("expired authorization", "LAUTH_EXPIRED", "expired"),
        ("future authorization", "LAUTH_FUTURE", "future"),
        ("overlong authorization", "LAUTH_TIME_INVALID", "overlong"),
        (
            "obsolete useLimit authorization",
            "LAUTH_SCHEMA_INVALID",
            "obsolete-use-limit",
        ),
        ("malformed authorization", "LAUTH_SCHEMA_INVALID", "malformed"),
        ("noncanonical authorization", "LAUTH_FRAME_INVALID", "noncanonical"),
        ("oversized authorization", "LAUTH_FRAME_INVALID", "oversized"),
    )
    for name, expected, mode in authorization_cases:
        rejected(name, expected, authority_mode=mode, observed=True)
        scenarios += 1

    binding_cases = (
        ("manifest authorization binding", "bind-manifest"),
        ("nonce contract authorization binding", "bind-nonce-contract"),
        ("nonce pin authorization binding", "bind-nonce-pins"),
        ("release provenance authorization binding", "bind-release-provenance"),
        ("provenance identity authorization binding", "bind-provenance-digest"),
        ("source tree authorization binding", "bind-source-tree"),
        ("launcher authorization binding", "bind-launcher"),
        ("reproducible build authorization binding", "bind-reproducible-build"),
        ("release sequence authorization binding", "bind-release-sequence"),
        ("rollback epoch authorization binding", "bind-rollback-epoch"),
    )
    for name, mode in binding_cases:
        rejected(name, "LAUTH_REQUEST_MISMATCH", authority_mode=mode, observed=True)
        scenarios += 1

    manifest_original = MANIFEST.read_bytes()
    manifest_mode = stat.S_IMODE(MANIFEST.stat().st_mode)
    try:
        post_authorization_file_rejected(
            "post-authorization manifest mutation",
            "post-auth-manifest-mutation",
            MANIFEST,
            "manifest changed after launch authorization",
        )
    finally:
        restore_bytes(MANIFEST, manifest_original, manifest_mode)
    scenarios += 1

    provenance_path = RELEASE_ROOT / "evidence/releaseProvenance.json"
    post_authorization_file_rejected(
        "post-authorization provenance mutation",
        "post-auth-provenance-mutation",
        provenance_path,
        "python.importRoots[0] post-authorization digest does not match",
    )
    scenarios += 1

    reproducible_path = RELEASE_ROOT / "evidence/reproducibleBuildVerification.json"
    post_authorization_file_rejected(
        "post-authorization reproducible build mutation",
        "post-auth-repro-mutation",
        reproducible_path,
        "python.importRoots[0] post-authorization digest does not match",
    )
    scenarios += 1

    post_authorization_file_rejected(
        "post-authorization nonce pin mutation",
        "post-auth-nonce-pins-mutation",
        NONCE_PINS,
        "nonceRollbackAssurance.pinsFile post-authorization digest does not match",
    )
    scenarios += 1

    try:
        post_authorization_file_rejected(
            "post-authorization nonce pin replacement",
            "post-auth-nonce-pins-replacement",
            NONCE_PINS,
            "nonce rollback assurance pins changed after launch authorization",
        )
    finally:
        if NONCE_PINS_BACKUP.exists():
            NONCE_PINS.unlink(missing_ok=True)
            NONCE_PINS_BACKUP.rename(NONCE_PINS)
    scenarios += 1

    try:
        rejected(
            "post-authorization launcher mutation",
            "launcher executable changed after launch authorization",
            authority_mode="post-auth-launcher-mutation",
            observed=True,
        )
        require((STATE / "post-auth-mutation-applied").is_file(), "launcher mutation was not applied")
    finally:
        if LAUNCHER_BACKUP.exists():
            LAUNCHER.unlink(missing_ok=True)
            LAUNCHER_BACKUP.rename(LAUNCHER)
    scenarios += 1

    require(scenarios == 133, "scenario count drifted: " + str(scenarios))
    print("production launcher adversarial fixture: PASS (133 scenarios)")


if __name__ == "__main__":
    main()
'''


def dockerfile() -> str:
    _, nonce_pins_sha256 = nonce_rollback_assurance_pins()
    authority_key_id = sha256_prefixed(
        ED25519_SPKI_PREFIX + TEST_AUTHORITY_PUBLIC
    )
    separator = f" {chr(92)}\n        "
    input_args = separator.join(
        f"--{argument} /opt/serverware/release/evidence/{name}.json"
        for argument, name in INPUTS
    )
    output_args = separator.join(
        f"--{argument} /var/lib/serverware/production-proof/{filename}"
        for argument, filename in OUTPUTS
    )
    names = " ".join(name for _, name in INPUTS)
    provenance = (
        '{"provenance":{"source":"serverware-digest-pinned-production-release","source_tree":{"digest":"'
        + SOURCE_TREE_DIGEST
        + '"},"version":2},"provenance_digest":"'
        + PROVENANCE_DIGEST
        + '"}'
    )
    return textwrap.dedent(
        f"""\
        FROM --platform=linux/amd64 {RUST_SLIM_BASE} AS hostile-build
        COPY hostile.c /src/hostile.c
        RUN cc -shared -fPIC -Wl,-z,relro,-z,now -o /hostile.so /src/hostile.c

        FROM --platform=linux/amd64 {RUST_ALPINE_BASE} AS launcher-build
        ARG SOURCE_DATE_EPOCH="0"
        ENV SOURCE_DATE_EPOCH=${{SOURCE_DATE_EPOCH}} \\
            RUSTFLAGS="-C link-arg=-Wl,--build-id=none"
        WORKDIR /src
        COPY musl-1.2.5-r12.apk musl-dev-1.2.5-r12.apk /dependency-cache/
        RUN apk --no-network --repositories-file /dev/null add \\
                /dependency-cache/musl-1.2.5-r12.apk \\
                /dependency-cache/musl-dev-1.2.5-r12.apk \\
            && command -v cc >/dev/null \\
            && command -v readelf >/dev/null \\
            && test -f /usr/lib/libc.a
        COPY decision-gate-rs/Cargo.toml ./Cargo.toml
        COPY decision-gate-rs/Cargo.lock ./Cargo.lock
        COPY decision-gate-rs/src ./src
        COPY decision-gate-rs/trust ./trust
        COPY schemas /schemas
        RUN cargo build --release --locked --bin serverware-production-launcher \\
            && test "$(readelf -l /src/target/release/serverware-production-launcher | grep -c INTERP)" -eq 0 \\
            && test "$(readelf -d /src/target/release/serverware-production-launcher | grep -c NEEDED)" -eq 0

        FROM --platform=linux/amd64 {PYTHON_SLIM_BASE} AS fixture-python-deps
        ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INDEX=1
        WORKDIR /dependency-cache
        COPY requirements.lock ./requirements.lock
        COPY python-wheelhouse-linux-amd64.tar.gz ./python-wheelhouse-linux-amd64.tar.gz
        RUN --network=none set -eu; \\
            printf '%s  %s\\n' {REQUIREMENTS_LOCK_SHA256} requirements.lock | sha256sum -c -; \\
            printf '%s  %s\\n' {PYTHON_WHEELHOUSE_SHA256} python-wheelhouse-linux-amd64.tar.gz | sha256sum -c -; \\
            tar -xzf python-wheelhouse-linux-amd64.tar.gz; \\
            test -n "$(find wheelhouse -maxdepth 1 -type f -name '*.whl' -print -quit)"; \\
            python3 -m pip install \\
                --no-cache-dir \\
                --no-compile \\
                --no-index \\
                --only-binary=:all: \\
                --find-links=/dependency-cache/wheelhouse \\
                --require-hashes \\
                --target=/deps \\
                -r requirements.lock

        FROM --platform=linux/amd64 {PYTHON_SLIM_BASE}
        COPY --from=launcher-build --chown=0:0 --chmod=0555 /src/target/release/serverware-production-launcher /opt/serverware/bin/serverware-production-launcher-test
        COPY --chown=0:0 --chmod=0555 generate_production_launch_manifest.py /usr/local/libexec/generate_production_launch_manifest.py
        COPY --chown=0:0 --chmod=0500 launch_authority_fixture.py /usr/local/libexec/launch_authority_fixture.py
        COPY --chown=0:0 --chmod=0400 test-launch-authority-private.pem /etc/serverware/test-launch-authority-private.pem
        COPY --chown=0:0 --chmod=0400 test-launch-authority-wrong-private.pem /etc/serverware/test-launch-authority-wrong-private.pem
        COPY --chown=0:0 --chmod=0400 test-launch-witness-private.pem /etc/serverware/test-launch-witness-private.pem
        COPY --chown=0:0 --chmod=0400 test-launch-witness-assurance-issuer-private.pem /etc/serverware/test-launch-witness-assurance-issuer-private.pem
        COPY --chown=0:0 --chmod=0444 policy-identity-public.pem /etc/serverware/test-policy-identity-public.pem
        COPY --chown=0:0 --chmod=0444 policy-activation-public.pem /etc/serverware/test-policy-activation-public.pem
        COPY --chown=0:0 --chmod=0444 reproducible-build-public.pem /etc/serverware/test-reproducible-build-public.pem
        COPY --chown=0:0 --chmod=0400 nonce-rollback-assurance-pins.json /etc/serverware/nonce-rollback-assurance-pins.json
        COPY --chown=0:0 --chmod=0444 {CONTEXT_MANIFEST_NAME} /etc/serverware/build-input-context-manifest.json
        COPY --chown=0:0 --chmod=0400 preflight.py /opt/serverware/release/scripts/preflight.py
        COPY --chown=0:0 --chmod=0400 runner.py /opt/serverware/release/scripts/runner.py
        COPY --chown=0:0 --chmod=0500 fixture_driver.py /usr/local/libexec/fixture_driver.py
        COPY --from=hostile-build --chown=0:0 --chmod=0555 /hostile.so /opt/serverware/hostile/hostile.so
        COPY --from=fixture-python-deps --chown=0:0 /deps/. /opt/serverware/release/vendor/
        RUN set -eu; \\
            openssl version; \\
            mkdir -p /run/serverware \\
                /opt/serverware/release/runtime/python/bin \\
                /opt/serverware/release/runtime/python/lib/python3.11 \\
                /opt/serverware/release/vendor \\
                /opt/serverware/release/evidence \\
                /opt/serverware/hostile/python \\
                /opt/serverware/hostile/python-home \\
                /var/lib/serverware/production-proof; \\
            cp /usr/local/bin/python3.11 /opt/serverware/release/runtime/python/bin/python3; \\
            cp /usr/local/lib/libpython3.11.so.1.0 /opt/serverware/release/runtime/python/lib/libpython3.11.so.1.0; \\
            cp -RL /usr/local/lib/python3.11/. /opt/serverware/release/runtime/python/lib/python3.11/; \\
            rm -rf /opt/serverware/release/runtime/python/lib/python3.11/site-packages \\
                /opt/serverware/release/runtime/python/lib/python3.11/ensurepip \\
                /opt/serverware/release/runtime/python/lib/python3.11/idlelib \\
                /opt/serverware/release/runtime/python/lib/python3.11/tkinter \\
                /opt/serverware/release/runtime/python/lib/python3.11/__pycache__; \\
            find /opt/serverware/release/runtime/python/lib/python3.11 -type d -exec chmod 0755 {{}} +; \\
            find /opt/serverware/release/runtime/python/lib/python3.11 -type f -exec chmod 0444 {{}} +; \\
            test -f /opt/serverware/release/runtime/python/lib/libpython3.11.so.1.0; \\
            test -n "$(find /opt/serverware/release/runtime/python/lib/python3.11/lib-dynload -maxdepth 1 -type f -name '*.so' -print -quit)"; \\
            printf '__all__ = []\\n' > /opt/serverware/release/vendor/serverware_vendor.py; \\
            find /opt/serverware/release/vendor -type d -exec chmod 0755 {{}} +; \\
            find /opt/serverware/release/vendor -type f -exec chmod 0444 {{}} +; \\
            chmod 0444 /opt/serverware/release/vendor/serverware_vendor.py; \\
            chown -R 0:0 /opt/serverware /var/lib/serverware/production-proof /run/serverware; \\
            chmod 0500 /opt/serverware/release/runtime/python/bin/python3; \\
            chmod 0444 /opt/serverware/release/runtime/python/lib/libpython3.11.so.1.0; \\
            chmod 0700 /var/lib/serverware/production-proof; \\
            chmod 0755 /run/serverware; \\
            printf 'services: {{}}\\n' > /opt/serverware/release/docker-compose.production.yml; \\
            chmod 0444 /opt/serverware/release/docker-compose.production.yml; \\
            printf 'SERVERWARE_TEST=1\\n' > /etc/serverware/production-readiness.env; \\
            chmod 0400 /etc/serverware/production-readiness.env; \\
            for name in {names}; do \\
                printf '{{"fixture":true}}\\n' > "/opt/serverware/release/evidence/$name.json"; \\
                chmod 0444 "/opt/serverware/release/evidence/$name.json"; \\
            done; \\
            cp /etc/serverware/test-policy-identity-public.pem /opt/serverware/release/evidence/policyTrustedPublicKey.json; \\
            cp /etc/serverware/test-policy-activation-public.pem /opt/serverware/release/evidence/policyActivationTrustedPublicKey.json; \\
            cp /etc/serverware/test-reproducible-build-public.pem /opt/serverware/release/evidence/reproducibleBuildTrustedPublicKey.json; \\
            printf '%s\\n' '{provenance}' > /opt/serverware/release/evidence/releaseProvenance.json; \\
            printf '%s\\n' 'open("/var/lib/serverware/production-proof/hostile-site-ran", "w").write("hostile site executed\\n")' \\
                > /opt/serverware/hostile/python/sitecustomize.py; \\
            cp /opt/serverware/hostile/python/sitecustomize.py /usr/local/lib/python3.11/sitecustomize.py; \\
            chmod 0444 /opt/serverware/hostile/python/sitecustomize.py /usr/local/lib/python3.11/sitecustomize.py; \\
            python3 -I -S /usr/local/libexec/launch_authority_fixture.py generate-fixture-trust; \\
            PYTHONPATH=/opt/serverware/release/vendor \\
            python3 -S /usr/local/libexec/generate_production_launch_manifest.py \\
                --output /etc/serverware/production-release-launch.json \\
                --release-root /opt/serverware/release \\
                --state-directory /var/lib/serverware/production-proof \\
                --source-tree-digest {SOURCE_TREE_DIGEST} \\
                --deployment-audience {DEPLOYMENT_AUDIENCE} \\
                --deployment-identity-sha256 {DEPLOYMENT_IDENTITY_DIGEST} \\
                --release-sequence {RELEASE_SEQUENCE} \\
                --rollback-epoch {ROLLBACK_EPOCH} \\
                --expected-launch-authority-key-id {authority_key_id} \\
                --global-role-registry /etc/serverware/production-launch-global-role-registry.json \\
                --expected-global-role-registry-pins-sha256 "$(python3 -I -S /usr/local/libexec/launch_authority_fixture.py trust-value globalRoleRegistryPinsSha256)" \\
                --launch-authority-witness-signing-public-key-spki-base64url "$(python3 -I -S /usr/local/libexec/launch_authority_fixture.py trust-value launchAuthorityWitnessSigningPublicKeySpkiDerBase64url)" \\
                --expected-launch-authority-witness-key-id "$(python3 -I -S /usr/local/libexec/launch_authority_fixture.py trust-value launchAuthorityWitnessKeyId)" \\
                --launch-authority-witness-identity-sha256 "$(python3 -I -S /usr/local/libexec/launch_authority_fixture.py trust-value launchAuthorityWitnessIdentitySha256)" \\
                --launch-authority-witness-administrative-domain-sha256 "$(python3 -I -S /usr/local/libexec/launch_authority_fixture.py trust-value launchAuthorityWitnessAdministrativeDomainSha256)" \\
                --launch-authority-witness-store-assurance-sha256 "$(python3 -I -S /usr/local/libexec/launch_authority_fixture.py trust-value launchAuthorityWitnessStoreAssuranceSha256)" \\
                --launch-authority-witness-store-assurance /etc/serverware/test-launch-witness-store-assurance.json \\
                --launch-authority-witness-store-assurance-issuer-public-key-spki-base64url "$(python3 -I -S /usr/local/libexec/launch_authority_fixture.py trust-value launchAuthorityWitnessStoreAssuranceIssuerPublicKeySpkiDerBase64url)" \\
                --expected-launch-authority-witness-store-assurance-issuer-key-id "$(python3 -I -S /usr/local/libexec/launch_authority_fixture.py trust-value launchAuthorityWitnessStoreAssuranceIssuerKeyId)" \\
                --production-env /etc/serverware/production-readiness.env \\
                --nonce-rollback-assurance-pins /etc/serverware/nonce-rollback-assurance-pins.json \\
                --expected-nonce-rollback-assurance-pins-sha256 {nonce_pins_sha256} \\
                --pipeline-metadata-out /etc/serverware/production-launch-pipeline.json \\
                --python /opt/serverware/release/runtime/python/bin/python3 \\
                --python-import-root /opt/serverware/release \\
                --python-import-root /opt/serverware/release/runtime/python/lib/python3.11 \\
                --python-import-root /opt/serverware/release/runtime/python/lib/python3.11/lib-dynload \\
                --python-import-root /opt/serverware/release/vendor \\
                --preflight-script /opt/serverware/release/scripts/preflight.py \\
                --runner-script /opt/serverware/release/scripts/runner.py \\
                --compose-file /opt/serverware/release/docker-compose.production.yml \\
                {input_args} \\
                {output_args}; \\
            test "$(stat -c '%u:%g:%a' /etc/serverware/production-release-launch.json)" = '0:0:400'; \\
            test "$(stat -c '%u:%g:%a' /etc/serverware/nonce-rollback-assurance-pins.json)" = '0:0:400'; \\
            test "$(stat -c '%u:%g:%a' /etc/serverware/build-input-context-manifest.json)" = '0:0:444'; \\
            test "$(stat -c '%u:%g:%a' /etc/serverware/production-launch-pipeline.json)" = '0:0:400'
        ENTRYPOINT ["/usr/local/bin/python3", "/usr/local/libexec/fixture_driver.py"]
        """
    )


def run(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as error:
        raise RuntimeError(f"required command is unavailable: {command[0]}") from error
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"command timed out after {timeout}s: {' '.join(command[:4])}") from error


def require_success(result: subprocess.CompletedProcess[str], label: str) -> None:
    if result.returncode == 0:
        return
    output = (result.stdout + result.stderr).strip()
    if len(output) > 6000:
        output = output[-6000:]
    raise RuntimeError(f"{label} failed with exit {result.returncode}:\n{output}")


def pem_private_key(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise RuntimeError("RFC 8032 test authority seed is not 32 bytes")
    encoded = base64.b64encode(ED25519_PKCS8_SEED_PREFIX + seed).decode("ascii")
    lines = [encoded[index : index + 64] for index in range(0, len(encoded), 64)]
    return (
        "-----BEGIN PRIVATE KEY-----\n"
        + "\n".join(lines)
        + "\n-----END PRIVATE KEY-----\n"
    ).encode("ascii")


def pem_public_key(public_key: bytes) -> bytes:
    if len(public_key) != 32:
        raise RuntimeError("Ed25519 test public key is not 32 bytes")
    encoded = base64.b64encode(
        ED25519_SPKI_PREFIX + public_key
    ).decode("ascii")
    lines = [
        encoded[index : index + 64]
        for index in range(0, len(encoded), 64)
    ]
    return (
        "-----BEGIN PUBLIC KEY-----\n"
        + "\n".join(lines)
        + "\n-----END PUBLIC KEY-----\n"
    ).encode("ascii")


def write_test_authorities(context: Path, production_public: bytes) -> tuple[str, str]:
    production_hex = production_public.decode("ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", production_hex):
        raise RuntimeError("production trust root is not canonical lowercase Ed25519 hex")
    if TEST_AUTHORITY_PUBLIC == WRONG_TEST_AUTHORITY_PUBLIC:
        raise RuntimeError("RFC 8032 test authority public keys are not distinct")
    if production_hex in {
        TEST_AUTHORITY_PUBLIC.hex(),
        WRONG_TEST_AUTHORITY_PUBLIC.hex(),
    }:
        raise RuntimeError("public test authority unexpectedly matches the production trust root")
    private_keys = (
        ("test-launch-authority-private.pem", TEST_AUTHORITY_SEED),
        ("test-launch-authority-wrong-private.pem", WRONG_TEST_AUTHORITY_SEED),
        ("test-launch-witness-private.pem", TEST_WITNESS_SEED),
        (
            "test-launch-witness-assurance-issuer-private.pem",
            TEST_WITNESS_ASSURANCE_ISSUER_SEED,
        ),
    )
    for name, seed in private_keys:
        path = context / name
        path.write_bytes(pem_private_key(seed))
        os.chmod(path, 0o600)
    spki = ED25519_SPKI_PREFIX + TEST_AUTHORITY_PUBLIC
    public_keys = (
        ("policy-identity-public.pem", bytes.fromhex("61" * 32)),
        ("policy-activation-public.pem", bytes.fromhex("62" * 32)),
        ("reproducible-build-public.pem", bytes.fromhex("63" * 32)),
    )
    for name, public_key in public_keys:
        path = context / name
        path.write_bytes(pem_public_key(public_key))
        os.chmod(path, 0o644)
    return TEST_AUTHORITY_PUBLIC.hex(), "sha256:" + hashlib.sha256(spki).hexdigest()


def validate_locked_network_inputs(lock_path: Path) -> None:
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    packages = lock.get("package")
    if not isinstance(packages, list) or not packages:
        raise RuntimeError("Cargo.lock has no package inventory")
    for package in packages:
        if not isinstance(package, dict):
            raise RuntimeError("Cargo.lock package entry is malformed")
        source = package.get("source")
        if source is None:
            continue
        if not isinstance(source, str):
            raise RuntimeError("Cargo.lock package source is malformed")
        checksum = package.get("checksum")
        if source.startswith("registry+"):
            if not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum):
                raise RuntimeError(
                    f"Cargo.lock registry package lacks a canonical checksum: {package.get('name')!r}"
                )
        elif source.startswith("git+"):
            revision = source.rsplit("#", 1)[-1]
            if not re.fullmatch(r"[0-9a-f]{40,64}", revision):
                raise RuntimeError(
                    f"Cargo.lock git package lacks an immutable revision: {package.get('name')!r}"
                )
        else:
            raise RuntimeError(f"Cargo.lock contains unsupported network source: {source!r}")


def context_file_inventory(context: Path) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for path in sorted(context.rglob("*")):
        if path.is_symlink():
            raise RuntimeError(f"build context contains a symlink: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise RuntimeError(f"build context contains an unsupported entry: {path}")
        relative = path.relative_to(context).as_posix()
        if relative == CONTEXT_MANIFEST_NAME:
            continue
        if not relative.isascii() or "\n" in relative or "\t" in relative:
            raise RuntimeError(f"unsafe build-context path: {relative!r}")
        content = path.read_bytes()
        entries.append(
            {
                "mode": path.stat().st_mode & 0o777,
                "path": relative,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
        )
    return entries


def write_context_manifest(
    context: Path,
    public_key_hex: str,
    authority_key_id: str,
) -> bytes:
    for path in sorted(context.rglob("*"), reverse=True):
        if path.is_symlink():
            raise RuntimeError(f"build context contains a symlink: {path}")
        if path.is_dir():
            os.chmod(path, 0o755)
        elif path.is_file():
            mode = 0o600 if path.name in {
                "test-launch-authority-private.pem",
                "test-launch-authority-wrong-private.pem",
                "test-launch-witness-private.pem",
                "test-launch-witness-assurance-issuer-private.pem",
            } else 0o644
            os.chmod(path, mode)
        else:
            raise RuntimeError(f"build context contains an unsupported entry: {path}")
        os.utime(path, (0, 0), follow_symlinks=False)
    entries = context_file_inventory(context)
    manifest = canonical_json_bytes(
        {
            "authority": {
                "key_id": authority_key_id,
                "material_class": "public-deterministic-test-only-never-production",
                "public_key_hex": public_key_hex,
                "test_vector": "RFC8032-Ed25519-test-vector-1",
                "wrong_public_key_hex": WRONG_TEST_AUTHORITY_PUBLIC.hex(),
            },
            "base_images": [RUST_SLIM_BASE, RUST_ALPINE_BASE, PYTHON_SLIM_BASE],
            "files": entries,
            "network_inputs": {
                "cargo_lock_sha256": hashlib.sha256(
                    (context / "decision-gate-rs/Cargo.lock").read_bytes()
                ).hexdigest(),
                "cargo_mode": "--release --locked",
                "python_mode": "--no-index --only-binary=:all: --require-hashes",
                "python_requirements_lock_sha256": REQUIREMENTS_LOCK_SHA256,
                "python_wheelhouse_sha256": PYTHON_WHEELHOUSE_SHA256,
                "registry_payloads": (
                    "Cargo.lock package checksums and requirements.lock hashes"
                ),
            },
            "schema": "serverware.launcher-adversarial-build-inputs.v1",
        }
    )
    manifest_path = context / CONTEXT_MANIFEST_NAME
    manifest_path.write_bytes(manifest)
    os.utime(manifest_path, (0, 0), follow_symlinks=False)
    return manifest


def write_context(context: Path, public_key_hex: str, authority_key_id: str) -> bytes:
    crate = context / "decision-gate-rs"
    (crate / "trust").mkdir(parents=True)
    shutil.copyfile(CRATE / "Cargo.toml", crate / "Cargo.toml")
    shutil.copyfile(CRATE / "Cargo.lock", crate / "Cargo.lock")
    shutil.copytree(CRATE / "src", crate / "src")
    shutil.copytree(SCHEMAS, context / "schemas")
    (crate / "trust/launch-authority-root.ed25519.hex").write_text(
        public_key_hex + "\n", encoding="ascii"
    )
    shutil.copyfile(GENERATOR, context / "generate_production_launch_manifest.py")
    shutil.copyfile(MUSL_APK, context / MUSL_APK.name)
    shutil.copyfile(MUSL_DEV_APK, context / MUSL_DEV_APK.name)
    shutil.copyfile(PYTHON_WHEELHOUSE, context / PYTHON_WHEELHOUSE.name)
    shutil.copyfile(REQUIREMENTS_LOCK, context / REQUIREMENTS_LOCK.name)
    files = {
        "Dockerfile": dockerfile(),
        "hostile.c": HOSTILE_C,
        "preflight.py": PREFLIGHT.replace("__AUTHORITY_KEY_ID__", authority_key_id),
        "runner.py": RUNNER.replace("__AUTHORITY_KEY_ID__", authority_key_id),
        "launch_authority_fixture.py": (
            AUTHORITY_FIXTURE
            .replace("__PUBLIC_KEY_HEX__", public_key_hex)
            .replace("__WITNESS_PUBLIC_HEX__", TEST_WITNESS_PUBLIC.hex())
            .replace(
                "__WITNESS_ASSURANCE_ISSUER_PUBLIC_HEX__",
                TEST_WITNESS_ASSURANCE_ISSUER_PUBLIC.hex(),
            )
        ),
        "fixture_driver.py": FIXTURE_DRIVER,
    }
    for name, content in files.items():
        (context / name).write_text(content, encoding="ascii")
    pins, _ = nonce_rollback_assurance_pins()
    (context / "nonce-rollback-assurance-pins.json").write_bytes(pins)
    validate_locked_network_inputs(crate / "Cargo.lock")
    return write_context_manifest(context, public_key_hex, authority_key_id)


def inspect_image(image_ref: str, expected_image_id: str | None = None) -> str:
    inspection = run(
        [
            "docker",
            "image",
            "inspect",
            "--format",
            "{{.Id}}\t{{.Os}}\t{{.Architecture}}",
            image_ref,
        ],
        30,
    )
    require_success(inspection, "fixture image inspection")
    fields = inspection.stdout.strip().split("\t")
    if len(fields) != 3:
        raise RuntimeError("Docker returned malformed fixture image identity")
    image_id, operating_system, architecture = fields
    if (operating_system, architecture) != ("linux", "amd64"):
        raise RuntimeError(
            "fixture image platform is not linux/amd64: "
            f"{operating_system}/{architecture}"
        )
    if not image_id.startswith("sha256:") or len(image_id) != 71:
        raise RuntimeError(f"Docker returned malformed fixture image ID: {image_id!r}")
    try:
        int(image_id[7:], 16)
    except ValueError as error:
        raise RuntimeError(f"Docker returned malformed fixture image ID: {image_id!r}") from error
    if expected_image_id is not None and image_id != expected_image_id:
        raise RuntimeError(
            "prebuilt fixture image ID mismatch: "
            f"expected {expected_image_id!r}, observed {image_id!r}"
        )
    return image_id


def write_image_id(path: Path, image_id: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(image_id + "\n", encoding="ascii")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def read_buildx_iid(path: Path) -> str:
    try:
        raw = path.read_bytes()
    except FileNotFoundError as error:
        raise RuntimeError("Buildx did not emit the required IID file") from error
    if not re.fullmatch(rb"sha256:[0-9a-f]{64}\n?", raw):
        raise RuntimeError(f"Buildx emitted a malformed IID file: {raw!r}")
    return raw.decode("ascii").strip()


def validate_builder_name(builder_name: str) -> str:
    if not BUILDER_NAME_RE.fullmatch(builder_name):
        raise RuntimeError(
            "builder name must match the closed grammar "
            "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
        )
    return builder_name


def validate_ambient_builder_selection(
    builder_name: str, environment: dict[str, str]
) -> None:
    ambient_builder = environment.get(AMBIENT_BUILDER_ENV)
    if ambient_builder not in (None, "", builder_name):
        raise RuntimeError(f"{AMBIENT_BUILDER_ENV} conflicts with --builder")
    for variable in CONFLICTING_BUILDER_ENV:
        if environment.get(variable):
            raise RuntimeError(
                f"{variable} is prohibited when an explicit builder is required"
            )


def validate_build_mode(
    *,
    prepare_image: bool,
    test_prebuilt_image: bool,
    builder: str | None,
    expected_image_id: str | None,
    image_id_out: str | None,
    environment: dict[str, str],
) -> str | None:
    if prepare_image:
        if builder is None:
            raise RuntimeError("--prepare-image requires --builder")
        validated_builder = validate_builder_name(builder)
        validate_ambient_builder_selection(validated_builder, environment)
        if expected_image_id is not None:
            raise RuntimeError(
                "--prepare-image does not accept --expected-image-id"
            )
        if image_id_out is None:
            raise RuntimeError("--prepare-image requires --image-id-out")
        return validated_builder

    if test_prebuilt_image:
        if builder is not None:
            raise RuntimeError(
                "--test-prebuilt-image does not accept --builder"
            )
        if expected_image_id is None:
            raise RuntimeError(
                "--test-prebuilt-image requires --expected-image-id"
            )
        if image_id_out is not None:
            raise RuntimeError(
                "--test-prebuilt-image does not accept --image-id-out"
            )
        # Prebuilt mode intentionally does not read build-related environment.
        return None

    if builder is None:
        raise RuntimeError(
            "standalone build mode requires an explicit --builder"
        )
    validated_builder = validate_builder_name(builder)
    validate_ambient_builder_selection(validated_builder, environment)
    if expected_image_id is not None or image_id_out is not None:
        raise RuntimeError(
            "standalone mode does not accept strict two-phase image arguments"
        )
    return validated_builder


def validate_build_mode_hostile_fixtures() -> None:
    common = {
        "expected_image_id": None,
        "image_id_out": "/tmp/launcher-adversarial.iid",
    }
    hostile_prepare_cases = (
        {"builder": None, "environment": {}},
        {"builder": "UPPERCASE", "environment": {}},
        {"builder": "../builder", "environment": {}},
        {"builder": "builder-", "environment": {}},
        {
            "builder": "recorded-builder",
            "environment": {AMBIENT_BUILDER_ENV: "other-builder"},
        },
        {
            "builder": "recorded-builder",
            "environment": {"BUILDKIT_HOST": "tcp://other-builder.invalid:1234"},
        },
        {
            "builder": "recorded-builder",
            "environment": {"DOCKER_CONTEXT": "other-context"},
        },
    )
    for fixture in hostile_prepare_cases:
        try:
            validate_build_mode(
                prepare_image=True,
                test_prebuilt_image=False,
                **common,
                **fixture,
            )
        except RuntimeError:
            continue
        raise RuntimeError(
            f"hostile prepare builder fixture unexpectedly accepted: {fixture!r}"
        )

    try:
        validate_build_mode(
            prepare_image=True,
            test_prebuilt_image=False,
            builder="recorded-builder",
            expected_image_id=None,
            image_id_out=None,
            environment={},
        )
    except RuntimeError:
        pass
    else:
        raise RuntimeError("prepare mode unexpectedly accepted a missing IID output")

    validate_build_mode(
        prepare_image=False,
        test_prebuilt_image=True,
        builder=None,
        expected_image_id="sha256:" + ("0" * 64),
        image_id_out=None,
        environment={
            AMBIENT_BUILDER_ENV: "../ignored-in-prebuilt-mode",
            "BUILDKIT_HOST": "tcp://ignored.invalid:1234",
            "DOCKER_BUILDKIT": "0",
        },
    )
    try:
        validate_build_mode(
            prepare_image=False,
            test_prebuilt_image=True,
            builder="recorded-builder",
            expected_image_id="sha256:" + ("0" * 64),
            image_id_out=None,
            environment={},
        )
    except RuntimeError:
        pass
    else:
        raise RuntimeError(
            "prebuilt mode unexpectedly accepted a builder selection"
        )


def build_fixture_image(
    image_ref: str,
    builder_name: str,
    image_id_out: Path | None = None,
    context_manifest_out: Path | None = None,
) -> str:
    if not PRODUCTION_TRUST.is_file():
        raise RuntimeError(f"production launch authority trust root is missing: {PRODUCTION_TRUST}")
    if not GENERATOR.is_file():
        raise RuntimeError(f"manifest generator is missing: {GENERATOR}")
    for dependency, expected_sha256 in OFFLINE_BUILD_INPUT_SHA256.items():
        if not dependency.is_file():
            raise RuntimeError(
                f"offline launcher build dependency is missing: {dependency}"
            )
        observed_sha256 = hashlib.sha256(dependency.read_bytes()).hexdigest()
        if observed_sha256 != expected_sha256:
            raise RuntimeError(
                "offline launcher build dependency digest mismatch: "
                f"{dependency}"
            )
    production_trust_before = PRODUCTION_TRUST.read_bytes()
    require_success(
        run(["docker", "version", "--format", "{{.Server.Os}}/{{.Server.Arch}}"], 30),
        "Docker availability check",
    )

    with tempfile.TemporaryDirectory(prefix="serverware-launcher-adversarial-") as temporary:
        context = Path(temporary)
        public_key_hex, authority_key_id = write_test_authorities(
            context, production_trust_before
        )
        context_manifest = write_context(context, public_key_hex, authority_key_id)
        if context_manifest_out is not None:
            context_manifest_out.parent.mkdir(parents=True, exist_ok=True)
            temporary_manifest = context_manifest_out.with_name(
                f".{context_manifest_out.name}.{uuid.uuid4().hex}.tmp"
            )
            try:
                temporary_manifest.write_bytes(context_manifest)
                os.chmod(temporary_manifest, 0o600)
                os.replace(temporary_manifest, context_manifest_out)
            finally:
                temporary_manifest.unlink(missing_ok=True)
        iid_parent = image_id_out.parent if image_id_out is not None else context
        iid_parent.mkdir(parents=True, exist_ok=True)
        iid_file = iid_parent / f".launcher-buildx-iid.{uuid.uuid4().hex}.tmp"
        build_result: subprocess.CompletedProcess[str] | None = None
        build_error: RuntimeError | None = None
        try:
            build_result = run(
                [
                    "docker",
                    "buildx",
                    "build",
                    "--builder",
                    builder_name,
                    "--platform",
                    PLATFORM,
                    "--load",
                    "--progress",
                    "plain",
                    "--iidfile",
                    str(iid_file),
                    "--tag",
                    image_ref,
                    str(context),
                ],
                900,
            )
        except RuntimeError as error:
            build_error = error
        try:
            image_id = read_buildx_iid(iid_file) if iid_file.exists() else None
            if image_id is not None and image_id_out is not None:
                write_image_id(image_id_out, image_id)
            if build_error is not None:
                raise build_error
            if build_result is None:
                raise RuntimeError("Buildx returned neither a result nor an error")
            require_success(build_result, "adversarial fixture image build")
            if image_id is None:
                raise RuntimeError("successful Buildx build did not emit an IID")
        finally:
            iid_file.unlink(missing_ok=True)
        if (context / CONTEXT_MANIFEST_NAME).read_bytes() != context_manifest:
            raise RuntimeError("fixture build-input context manifest changed during Buildx execution")
        if (
            context_manifest_out is not None
            and context_manifest_out.read_bytes() != context_manifest
        ):
            raise RuntimeError("published fixture build-input manifest changed during Buildx execution")
        expected_inventory = json.loads(context_manifest.decode("ascii"))["files"]
        if context_file_inventory(context) != expected_inventory:
            raise RuntimeError("fixture build-input context changed during Buildx execution")

    if PRODUCTION_TRUST.read_bytes() != production_trust_before:
        raise RuntimeError("production launch authority trust root changed during test build")
    inspect_image(image_ref, image_id)
    return image_id


def run_fixture_image(image_ref: str, expected_image_id: str) -> None:
    inspect_image(image_ref, expected_image_id)
    fixture = run(
        [
            "docker",
            "run",
            "--rm",
            "--pull=never",
            "--platform",
            PLATFORM,
            expected_image_id,
        ],
        600,
    )
    require_success(fixture, "adversarial fixture scenarios")
    print(fixture.stdout.strip())


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build or run the production launcher adversarial image."
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--prepare-image",
        action="store_true",
        help="build and retain the exact adversarial image for a later no-build run",
    )
    mode.add_argument(
        "--test-prebuilt-image",
        action="store_true",
        help="inspect and run an exact prebuilt image without building, pulling, or removing it",
    )
    parser.add_argument(
        "--image-ref",
        default=os.environ.get(IMAGE_REF_ENV, CODER_IMAGE_REF),
        help=f"image reference (default: ${IMAGE_REF_ENV} or {CODER_IMAGE_REF})",
    )
    parser.add_argument(
        "--builder",
        default=None,
        help=(
            "explicit buildx builder for prepare or standalone mode; "
            "never inferred from ambient Docker state"
        ),
    )
    parser.add_argument(
        "--expected-image-id",
        default=os.environ.get(IMAGE_ID_ENV),
        help=f"exact sha256 image ID required by no-build mode (or ${IMAGE_ID_ENV})",
    )
    parser.add_argument(
        "--image-id-out",
        type=Path,
        help="atomically publish the exact Buildx-emitted IID to this file",
    )
    parser.add_argument(
        "--context-manifest-out",
        type=Path,
        help="atomically write the canonical fixture build-input manifest",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    validate_launcher_source_contract()
    validate_build_mode_hostile_fixtures()
    builder_name = validate_build_mode(
        prepare_image=args.prepare_image,
        test_prebuilt_image=args.test_prebuilt_image,
        builder=args.builder,
        expected_image_id=args.expected_image_id,
        image_id_out=None if args.image_id_out is None else str(args.image_id_out),
        environment=dict(os.environ),
    )
    if args.prepare_image:
        if builder_name is None:
            raise RuntimeError("validated prepare mode lost its builder binding")
        if args.image_id_out is None:
            raise RuntimeError("--prepare-image requires --image-id-out")
        if args.context_manifest_out is None:
            raise RuntimeError("--prepare-image requires --context-manifest-out")
        image_id = build_fixture_image(
            args.image_ref,
            builder_name,
            args.image_id_out,
            args.context_manifest_out,
        )
        print(image_id)
        return 0

    if args.test_prebuilt_image:
        if args.expected_image_id is None:
            raise RuntimeError("validated prebuilt mode lost its image ID")
        if args.context_manifest_out is not None:
            raise RuntimeError("--test-prebuilt-image does not accept --context-manifest-out")
        run_fixture_image(args.image_ref, args.expected_image_id)
        return 0

    if builder_name is None:
        raise RuntimeError("validated standalone mode lost its builder binding")
    if args.context_manifest_out is not None:
        raise RuntimeError("standalone mode does not accept --context-manifest-out")
    image = "serverware-production-launcher-adversarial:" + uuid.uuid4().hex[:20]
    image_id: str | None = None
    try:
        image_id = build_fixture_image(image, builder_name)
        run_fixture_image(image, image_id)
        return 0
    finally:
        if image_id is not None:
            current = run(
                ["docker", "image", "inspect", "--format", "{{.Id}}", image],
                30,
            )
            if current.returncode == 0 and current.stdout.strip() == image_id:
                run(["docker", "image", "rm", image], 60)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError) as error:
        print(f"production launcher adversarial test error: {error}", file=sys.stderr)
        sys.exit(1)
