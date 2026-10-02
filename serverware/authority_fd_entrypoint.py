from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import socket
import stat
import sys


MAX_SOURCE_BYTES = 64 * 1024 * 1024
CONTROL_PLANE_CUSTODY_CONFIG_NAME = "SERVERWARE_CONTROL_PLANE_CUSTODY_CONFIG_FD"
CONTROL_PLANE_CUSTODY_CONFIG_SCHEMA = "serverware.controlPlaneCustodyStartup/v1"
CONTROL_PLANE_CUSTODY_CONFIG_MAX_BYTES = 16384
CONTROL_PLANE_CUSTODY_DIRECTORY = "/var/lib/serverware/control-plane-custody"
CONTROL_PLANE_CUSTODY_FD_MIN = 32
CONTROL_PLANE_CUSTODY_FD_MAX = 1023
OAUTH_APPLICATION_CONFIG_NAME = "SERVERWARE_OAUTH_APPLICATION_CONFIG_FD"
OAUTH_APPLICATION_CONFIG_MAX_BYTES = 64 * 1024
OAUTH_REVOCATION_CONFIG_NAME = "SERVERWARE_OAUTH_REVOCATION_CONFIG_FD"
OAUTH_REVOCATION_CONFIG_MAX_BYTES = 2 * 1024 * 1024
MEASURED_AUDIT_CONFIG_NAME = "SERVERWARE_MEASURED_AUDIT_CONFIG_FD"
MEASURED_AUDIT_CONFIG_MAX_BYTES = 3 * 1024 * 1024
POLICY_CANARY_CONFIG_NAME = "SERVERWARE_POLICY_CANARY_INTAKE_CONFIG_FD"
SETUP_NATIVE_CONFIG_NAME = "SERVERWARE_SETUP_NATIVE_OBSERVATION_CONFIG_FD"
OAUTH_REFRESH_CLEANUP_CONFIG_NAME = "SERVERWARE_OAUTH_REFRESH_CLEANUP_CONFIG_FD"
OAUTH_REFRESH_CLEANUP_CONFIG_MAX_BYTES = 2 * 1024 * 1024
RBAC_WITNESS_CONFIG_NAME = "SERVERWARE_RBAC_WITNESS_CONFIG_FD"
RBAC_WITNESS_CONFIG_MAX_BYTES = 96 * 1024
CONTROL_PLANE_ENROLLMENT_BOOTSTRAP_NAME = "SERVERWARE_CONTROL_PLANE_ENROLLMENT_BOOTSTRAP_FD"
CONTROL_PLANE_ENROLLMENT_BOOTSTRAP_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v2"
CONTROL_PLANE_ENROLLMENT_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v2"
CONTROL_PLANE_ENROLLMENT_V3_BOOTSTRAP_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v3"
CONTROL_PLANE_ENROLLMENT_V3_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v3"
CONTROL_PLANE_ENROLLMENT_V4_BOOTSTRAP_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v4"
CONTROL_PLANE_ENROLLMENT_V4_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v4"
CONTROL_PLANE_ENROLLMENT_V5_BOOTSTRAP_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v5"
CONTROL_PLANE_ENROLLMENT_V5_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v5"
CONTROL_PLANE_ENROLLMENT_V6_BOOTSTRAP_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v6"
CONTROL_PLANE_ENROLLMENT_V6_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v6"
CONTROL_PLANE_ENROLLMENT_V7_BOOTSTRAP_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v7"
CONTROL_PLANE_ENROLLMENT_V7_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v7"
CONTROL_PLANE_ENROLLMENT_V8_BOOTSTRAP_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v8"
CONTROL_PLANE_ENROLLMENT_V8_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v8"
CONTROL_PLANE_ENROLLMENT_V9_BOOTSTRAP_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v9"
CONTROL_PLANE_ENROLLMENT_V9_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v9"
CONTROL_PLANE_ENROLLMENT_V10_BOOTSTRAP_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v10"
CONTROL_PLANE_ENROLLMENT_V10_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v10"
CONTROL_PLANE_ENROLLMENT_V11_BOOTSTRAP_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v11"
CONTROL_PLANE_ENROLLMENT_V11_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v11"
CONTROL_PLANE_ENROLLMENT_V12_BOOTSTRAP_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v12"
CONTROL_PLANE_ENROLLMENT_V12_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v12"
CONTROL_PLANE_ENROLLMENT_V13_BOOTSTRAP_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v13"
CONTROL_PLANE_ENROLLMENT_V13_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v13"
CONTROL_PLANE_ENROLLMENT_V14_BOOTSTRAP_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v14"
CONTROL_PLANE_ENROLLMENT_V14_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v14"
CONTROL_PLANE_ENROLLMENT_V15_BOOTSTRAP_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v15"
CONTROL_PLANE_ENROLLMENT_V15_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v15"
CONTROL_PLANE_ENROLLMENT_V16_BOOTSTRAP_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v16"
CONTROL_PLANE_ENROLLMENT_V16_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v16"
CONTROL_PLANE_ENROLLMENT_V17_BOOTSTRAP_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v17"
CONTROL_PLANE_ENROLLMENT_V17_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v17"
CONTROL_PLANE_ENROLLMENT_V18_BOOTSTRAP_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v18"
CONTROL_PLANE_ENROLLMENT_V18_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v18"
CONTROL_PLANE_ENROLLMENT_V19_BOOTSTRAP_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v19"
CONTROL_PLANE_ENROLLMENT_V19_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v19"
CONTROL_PLANE_ENROLLMENT_V20_BOOTSTRAP_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v20"
CONTROL_PLANE_ENROLLMENT_V20_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v20"
CONTROL_PLANE_ENROLLMENT_V21_BOOTSTRAP_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v21"
CONTROL_PLANE_ENROLLMENT_V21_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v21"
CONTROL_PLANE_ENROLLMENT_V22_BOOTSTRAP_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v22"
CONTROL_PLANE_ENROLLMENT_V22_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v22"
CONTROL_PLANE_ENROLLMENT_V23_BOOTSTRAP_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v23"
CONTROL_PLANE_ENROLLMENT_V23_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v23"
CONTROL_PLANE_REVOCATION_KEY_FD = 208
CONTROL_PLANE_REVOCATION_KEY_NAME = "serverware-public-webauthn-revocation-caller-key"
CONTROL_PLANE_COMPLETION_RECOVERY_SCHEMA = "serverware.controlPlaneOidcSessionActivationCompletionRecovery/v1"
CONTROL_PLANE_ACTIVATION_COMPLETION_RECOVERY_SCHEMA = "serverware.controlPlaneOidcSessionActivationCompletionRecoveryScope/v1"
CONTROL_PLANE_CONSUME_COMPLETION_RECOVERY_SCHEMA = "serverware.controlPlaneOidcSessionActivationConsumeCompletionRecoveryScope/v1"
CONTROL_PLANE_RECOVERY_GRANT_ACQUISITION_SCHEMA = "serverware.controlPlaneOidcSessionActivationReleaseRecoveryGrantAcquisition/v1"
CONTROL_PLANE_RECOVERY_GRANT_ACQUISITION_SOCKET = "/run/serverware/oidc-session-activation-token-release/recovery-grants.sock"
CONTROL_PLANE_PROOF_ACQUISITION_SCHEMA = "serverware.controlPlaneOidcSessionActivationReleaseProofAcquisition/v1"
CONTROL_PLANE_PROOF_ACQUISITION_SOCKET = "/run/serverware/oidc-session-activation-release-proof-inputs/grants.sock"
CONTROL_PLANE_CONSUME_INPUT_ACQUISITION_SCHEMA = "serverware.controlPlaneOidcSessionActivationConsumeInputAcquisition/v1"
CONTROL_PLANE_CONSUME_INPUT_ACQUISITION_V2_SCHEMA = "serverware.controlPlaneOidcSessionActivationConsumeInputAcquisition/v2"
CONTROL_PLANE_CONSUME_INPUT_ACQUISITION_SOCKET = "/run/serverware/oidc-session-activation-consume-inputs/grants.sock"
CONTROL_PLANE_GRANT_ACQUISITION_SCHEMA = "serverware.controlPlaneOidcSessionActivationReleaseGrantAcquisition/v1"
CONTROL_PLANE_GRANT_ACQUISITION_SOCKET = "/run/serverware/oidc-session-activation-token-release/grants.sock"
CONTROL_PLANE_HANDOFF_SCHEMA = "serverware.controlPlaneOidcSessionActivationReleaseHandoff/v1"
CONTROL_PLANE_HANDOFF_SOCKET = "/run/serverware/oidc-session-activation-token-release/release.sock"
CONTROL_PLANE_PROOF_SCHEMA = "serverware.controlPlaneOidcSessionActivationReleaseProof/v1"
CONTROL_PLANE_PROOF_SOCKET = "/run/serverware/oidc-session-activation-token-release/proof.sock"
CONTROL_PLANE_INTENT_SCHEMA = "serverware.controlPlaneOidcSessionActivationReleaseIntent/v1"
CONTROL_PLANE_INTENT_KEY_FD = 207
CONTROL_PLANE_INTENT_KEY_NAME = "serverware-oidc-session-activation-release-intent-key"
CONTROL_PLANE_CONSUME_SCHEMA = "serverware.controlPlaneOidcSessionActivationConsumeExecution/v1"
CONTROL_PLANE_CONSUME_V2_SCHEMA = "serverware.controlPlaneOidcSessionActivationConsumeExecution/v2"
CONTROL_PLANE_CONSUME_V3_SCHEMA = "serverware.controlPlaneOidcSessionActivationConsumeExecution/v3"
CONTROL_PLANE_CONSUME_V4_SCHEMA = "serverware.controlPlaneOidcSessionActivationConsumeExecution/v4"
CONTROL_PLANE_CONSUME_KEY_FD = 206
CONTROL_PLANE_CONSUME_KEY_NAME = "serverware-oidc-session-activation-consume-caller-key"
CONTROL_PLANE_CONSUME_SOCKET = "/run/serverware/oidc-session-activation-delivery-execution/authorizer.sock"
CONTROL_PLANE_CONSUME_RESERVATION_SOCKET = "/run/serverware/oidc-session-activation-delivery-execution/reserver.sock"
CONTROL_PLANE_CONSUME_SQL_SOCKET = "/run/serverware/oidc-session-activation-delivery-execution/sql.sock"
CONTROL_PLANE_CONSUME_COMPLETION_SOCKET = "/run/serverware/oidc-session-activation-delivery-execution/completion.sock"
CONTROL_PLANE_ACTIVATION_PLANNING_SCHEMA = "serverware.controlPlaneOidcSessionActivationPlanning/v1"
CONTROL_PLANE_ACTIVATION_PLANNER_SOCKET = "/run/serverware/oidc-session-activation/planner.sock"
CONTROL_PLANE_ACTIVATION_SCHEMA = "serverware.controlPlaneOidcSessionActivationExecution/v1"
CONTROL_PLANE_ACTIVATION_V2_SCHEMA = "serverware.controlPlaneOidcSessionActivationExecution/v2"
CONTROL_PLANE_ACTIVATION_V3_SCHEMA = "serverware.controlPlaneOidcSessionActivationExecution/v3"
CONTROL_PLANE_ACTIVATION_V4_SCHEMA = "serverware.controlPlaneOidcSessionActivationExecution/v4"
CONTROL_PLANE_ACTIVATION_KEY_FD = 205
CONTROL_PLANE_ACTIVATION_KEY_NAME = "serverware-oidc-session-activation-execution-caller-key"
CONTROL_PLANE_ACTIVATION_SOCKET = "/run/serverware/oidc-session-activation-execution/authorizer.sock"
CONTROL_PLANE_ACTIVATION_RESERVER_SOCKET = "/run/serverware/oidc-session-activation-execution/reserver.sock"
CONTROL_PLANE_ACTIVATION_SQL_SOCKET = "/run/serverware/oidc-session-activation-execution/sql.sock"
CONTROL_PLANE_ACTIVATION_COMPLETION_SOCKET = "/run/serverware/oidc-session-activation/completion.sock"
CONTROL_PLANE_ACTIVATION_CONSUME_PLANNER_SOCKET = "/run/serverware/oidc-session-activation/delivery-planner.sock"
CONTROL_PLANE_RELEASE_SCHEMA = "serverware.controlPlaneOidcSessionActivationRelease/v1"
CONTROL_PLANE_RELEASE_SOCKET = "/run/serverware/oidc-session-activation-token-release/release.sock"
CONTROL_PLANE_ENROLLMENT_BOOTSTRAP_MAX_BYTES = 4 * 1024 * 1024
CONTROL_PLANE_ENROLLMENT_KEY_MAX_BYTES = 4096
CONTROL_PLANE_ENROLLMENT_KEY_NAME = "serverware-control-plane-enrollment-signing-key"
CONTROL_PLANE_EXECUTION_SCHEMA = "serverware.controlPlaneRegistrationExecution/v1"
CONTROL_PLANE_EXECUTION_V2_SCHEMA = "serverware.controlPlaneRegistrationExecution/v2"
CONTROL_PLANE_EXECUTION_V3_SCHEMA = "serverware.controlPlaneRegistrationExecution/v3"
CONTROL_PLANE_EXECUTION_KEY_NAME = "serverware-registration-execution-caller-key"
CONTROL_PLANE_EXECUTION_KEY_FD = 203
CONTROL_PLANE_EXECUTION_SOCKET = "/run/serverware/registration-execution/authorizer.sock"
CONTROL_PLANE_RESERVATION_SOCKET = "/run/serverware/registration-execution/reserver.sock"
CONTROL_PLANE_SQL_SOCKET = "/run/serverware/registration-execution/sql.sock"
CONTROL_PLANE_COMPLETION_SOCKET = "/run/serverware/registration-execution/completion.sock"
CONTROL_PLANE_FINALIZATION_SCHEMA = "serverware.controlPlaneRegistrationFinalization/v1"
CONTROL_PLANE_FINALIZATION_V2_SCHEMA = "serverware.controlPlaneRegistrationFinalization/v2"
CONTROL_PLANE_FINALIZATION_V3_SCHEMA = "serverware.controlPlaneRegistrationFinalization/v3"
CONTROL_PLANE_FINALIZATION_V4_SCHEMA = "serverware.controlPlaneRegistrationFinalization/v4"
CONTROL_PLANE_FINALIZATION_KEY_NAME = "serverware-registration-finalization-caller-key"
CONTROL_PLANE_FINALIZATION_KEY_FD = 204
CONTROL_PLANE_FINALIZATION_SOCKET = "/run/serverware/registration-finalization-authorizer.sock"
CONTROL_PLANE_FINALIZATION_RESERVATION_SOCKET = "/run/serverware/registration-finalization/reserver.sock"
CONTROL_PLANE_FINALIZATION_SQL_SOCKET = "/run/serverware/registration-finalization/sql.sock"
CONTROL_PLANE_FINALIZATION_COMPLETION_SOCKET = "/run/serverware/registration-finalization/completion.sock"
TRUSTED_HOST_LOCAL_WITNESS_STATE_PATH = (
    "/var/lib/serverware/authority-witness"
)
TRUSTED_HOST_LOCAL_WITNESS_STATE_FD_MIN = 32
TRUSTED_HOST_LOCAL_WITNESS_STATE_FD_MAX = 1023
BOOTSTRAP_LAUNCHER_PATH = (
    "/runtime/authority-bootstrap/authority_launcher.py"
)
LOCAL_ADMISSION_SCHEMA = "serverware.authorityTrustedHostLocalAdmission/v1"
LOCAL_ADMISSION_MAX_BYTES = 1024 * 1024
# Local retained resources match the existing signed stage-zero roster bounds.
# Only their actual parent-assigned descriptors may use the high namespace;
# control, late credentials and mutable witness slots keep their old limits.
LOCAL_RETAINED_FILES_MAX = 32768
LOCAL_RETAINED_DIRECTORIES_MAX = 64
LOCAL_RETAINED_FD_MAX = 2**31 - 1
LOCAL_LATE_DESCRIPTORS = {
    "SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD": 256,
    "SERVERWARE_POLICY_AUTHORITY_ATTESTATION_FD": 258,
}
# Kept equal to the stage-zero interface without importing application code
# before the isolated launcher admits its measured import closure.
LOCAL_EXEC_ENVIRONMENT = frozenset({
    "LANG", "LC_ALL", "PATH", "PYTHONDONTWRITEBYTECODE", "PYTHONHASHSEED",
    "SERVERWARE_ARTIFACT_BUNDLE_DIGEST", "SERVERWARE_AUTHORITY_GENERATION_DIGEST",
    "SERVERWARE_AUTHORITY_LAUNCH_CERTIFICATE_FD",
    "SERVERWARE_AUTHORITY_LAUNCH_PRIVATE_KEY_FD", "SERVERWARE_AUTHORITY_ROLE",
    "SERVERWARE_OPERATION_MANIFEST_DIGEST", *LOCAL_LATE_DESCRIPTORS, "TZ",
})
ROLE_IDENTITIES = {
    "control-plane": (65532, 65532),
    "runtime": (65524, 65524),
    "verifier": (65520, 65520),
    "planner": (65518, 65518),
    "planner-writer": (65519, 65519),
    "issuer": (65521, 65521),
    "executor": (65522, 65522),
    "witness": (65523, 65523),
}
ROLE_SUPPLEMENTARY_GIDS = {
    "control-plane": (65530, 65524),
    "runtime": (65520,),
    "verifier": (65518, 65521, 65522, 65523),
    "planner": (65519,),
    "planner-writer": (),
    "issuer": (65523,),
    "executor": (65523,),
    "witness": (),
}
ROLE_SOCKET_PATHS = {
    "runtime": "/run/serverware/authority-runtime/authority.sock",
    "verifier": "/run/serverware/authority-verifier/authority.sock",
    "planner": "/run/serverware/authority-planner/authority.sock",
    "planner-writer":
        "/run/serverware/authority-planner-writer/authority.sock",
    "issuer": "/run/serverware/authority-issuer/authority.sock",
    "executor": "/run/serverware/authority-executor/authority.sock",
    "witness": "/run/serverware/authority-witness/authority.sock",
}
ROLE_LISTENER_NAMES = {
    role: f"serverware-authority-{role}"
    for role in ROLE_SOCKET_PATHS
}
STAGE_ZERO_HANDOFF_DESCRIPTOR_NAME = (
    "SERVERWARE_AUTHORITY_NATIVE_STAGE_ZERO_HANDOFF_FD"
)
OBSOLETE_STATIC_RELEASE_CONSUMER_NAMES = (
    "SERVERWARE_POLICY_AUTHORITY_RELEASE_CONSUMER_SIGNING_KEY_FD",
    "SERVERWARE_POLICY_AUTHORITY_RELEASE_CONSUMER_SIGNING_KEY_PATH",
)

# Delivery inventory, not the stage-zero ordinary credential inventory. The
# launch manifest is delivered here as a separately root-verified bootstrap
# control document; its bytes must never be hashed into their own payload.
# Attestation is separately retained runtime evidence, not an ordinary
# credential. Delivery preserves its original bytes; receipt admission remains
# in the service and is not granted by opening the systemd credential.
ROLE_SOURCES = {
    "control-plane": (
        (
            "SERVERWARE_POLICY_AUTHORITY_RUNTIME_ROOT_PUBLIC_KEY_FD",
            "/run/serverware/authority-trust/runtime-root-public-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_RUNTIME_TRUST_FD",
            "/run/serverware/authority-trust/runtime-trust.json",
        ),
        (
            CONTROL_PLANE_CUSTODY_CONFIG_NAME,
            "/run/serverware/authority-trust/control-plane-custody.json",
        ),
        (
            CONTROL_PLANE_ENROLLMENT_BOOTSTRAP_NAME,
            "/run/serverware/authority-trust/control-plane-enrollment.json",
        ),
        (
            OAUTH_APPLICATION_CONFIG_NAME,
            "/run/serverware/authority-trust/oauth-applications.json",
        ),
        (
            OAUTH_REVOCATION_CONFIG_NAME,
            "/run/serverware/authority-trust/oauth-revocations.json",
        ),
        (OAUTH_REFRESH_CLEANUP_CONFIG_NAME, "/run/serverware/authority-trust/oauth-refresh-cleanups.json"),
        (RBAC_WITNESS_CONFIG_NAME, "/run/serverware/authority-trust/rbac-witness.json"),
        (MEASURED_AUDIT_CONFIG_NAME, "/run/serverware/authority-trust/measured-audit.json"),
    ),
    "runtime": (
        (
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_ROOT_PUBLIC_KEY_FD",
            "/run/secrets/serverware-authority-launch-root-public-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD",
            "/run/secrets/serverware-authority-runtime-launch-manifest",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_RUNTIME_ROOT_PUBLIC_KEY_FD",
            "/run/secrets/serverware-authority-runtime-root-public-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_RUNTIME_TRUST_FD",
            "/run/secrets/serverware-authority-runtime-trust",
        ),
    ),
    "verifier": (
        (
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_ROOT_PUBLIC_KEY_FD",
            "/run/secrets/serverware-authority-launch-root-public-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD",
            "/run/secrets/serverware-authority-verifier-launch-manifest",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_ROOT_PUBLIC_KEY_FD",
            "/run/secrets/serverware-authority-root-public-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_CONFIG_FD",
            "/run/secrets/serverware-authority-verifier-config",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_ATTESTATION_FD",
            "/run/secrets/serverware-authority-verifier-attestation",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_VERIFIER_SIGNING_KEY_FD",
            "/run/secrets/serverware-authority-verifier-signing-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_VERIFIER_READ_POSTGRES_DSN_FD",
            "/run/secrets/serverware-authority-verifier-read-dsn",
        ),
    ),
    "planner": (
        (
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_ROOT_PUBLIC_KEY_FD",
            "/run/secrets/serverware-authority-launch-root-public-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD",
            "/run/secrets/serverware-authority-planner-launch-manifest",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_ROOT_PUBLIC_KEY_FD",
            "/run/secrets/serverware-authority-root-public-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_CONFIG_FD",
            "/run/secrets/serverware-authority-planner-config",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_ATTESTATION_FD",
            "/run/secrets/serverware-authority-planner-attestation",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_PLANNER_SIGNING_KEY_FD",
            "/run/secrets/serverware-authority-planner-signing-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_PLANNER_READ_POSTGRES_DSN_FD",
            "/run/secrets/serverware-authority-planner-read-dsn",
        ),
    ),
    "planner-writer": (
        (
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_ROOT_PUBLIC_KEY_FD",
            "/run/secrets/serverware-authority-launch-root-public-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD",
            "/run/secrets/serverware-authority-planner-writer-launch-manifest",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_ROOT_PUBLIC_KEY_FD",
            "/run/secrets/serverware-authority-root-public-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_CONFIG_FD",
            "/run/secrets/serverware-authority-planner-writer-config",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_ATTESTATION_FD",
            "/run/secrets/serverware-authority-planner-writer-attestation",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_SIGNING_KEY_FD",
            "/run/secrets/serverware-authority-planner-writer-signing-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_POSTGRES_DSN_FD",
            "/run/secrets/serverware-authority-planner-writer-dsn",
        ),
    ),
    "issuer": (
        (
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_ROOT_PUBLIC_KEY_FD",
            "/run/secrets/serverware-authority-launch-root-public-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD",
            "/run/secrets/serverware-authority-issuer-launch-manifest",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_ROOT_PUBLIC_KEY_FD",
            "/run/secrets/serverware-authority-root-public-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_CONFIG_FD",
            "/run/secrets/serverware-authority-issuer-config",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_ATTESTATION_FD",
            "/run/secrets/serverware-authority-issuer-attestation",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_CAPABILITY_ISSUER_POSTGRES_DSN_FD",
            "/run/secrets/serverware-authority-issuer-dsn",
        ),
    ),
    "executor": (
        (
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_ROOT_PUBLIC_KEY_FD",
            "/run/secrets/serverware-authority-launch-root-public-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD",
            "/run/secrets/serverware-authority-executor-launch-manifest",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_ROOT_PUBLIC_KEY_FD",
            "/run/secrets/serverware-authority-root-public-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_CONFIG_FD",
            "/run/secrets/serverware-authority-executor-config",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_ATTESTATION_FD",
            "/run/secrets/serverware-authority-executor-attestation",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_EXECUTOR_POSTGRES_DSN_FD",
            "/run/secrets/serverware-authority-executor-dsn",
        ),
    ),
    "witness": (
        (
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_ROOT_PUBLIC_KEY_FD",
            "/run/secrets/serverware-authority-launch-root-public-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD",
            "/run/secrets/serverware-authority-witness-launch-manifest",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_WITNESS_ROOT_PUBLIC_KEY_FD",
            "/run/secrets/serverware-authority-witness-root-public-key",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_WITNESS_CONFIG_FD",
            "/run/secrets/serverware-authority-witness-config",
        ),
        (
            "SERVERWARE_POLICY_AUTHORITY_WITNESS_SIGNING_KEY_FD",
            "/run/secrets/serverware-authority-witness-signing-key",
        ),
    ),
}

for _rbac_role in ("verifier", "planner", "executor"):
    ROLE_SOURCES[_rbac_role] += (
        (RBAC_WITNESS_CONFIG_NAME, "/run/secrets/serverware-rbac-witness-" + _rbac_role + "-config"),
        ("SERVERWARE_RBAC_WITNESS_ROOT_FD", "/run/secrets/serverware-rbac-witness-root-public-key"),
        ("SERVERWARE_RBAC_WITNESS_TLS_ROOT_FD", "/run/secrets/serverware-rbac-witness-tls-root"),
        ("SERVERWARE_RBAC_WITNESS_CLIENT_CERTIFICATE_FD", "/run/secrets/serverware-rbac-witness-" + _rbac_role + "-certificate"),
        ("SERVERWARE_RBAC_WITNESS_CLIENT_KEY_FD", "/run/secrets/serverware-rbac-witness-" + _rbac_role + "-key"),
    )

PROCESS_MODES = {
    "control-plane": "serverware-control-plane",
    "runtime": "policy-authority-runtime",
    "verifier": "policy-authority-verifier",
    "planner": "policy-authority-planner",
    "planner-writer": "policy-authority-planner-writer",
    "issuer": "policy-authority-issuer",
    "executor": "policy-authority-executor",
    "witness": "policy-authority-replay-witness",
}
CONTROL_PLANE_HEALTH_CODE = (
    "import json,ssl,sys,urllib.request; "
    "from pathlib import Path; "
    "from serverware.response_identity import "
    "validate_response_signing_key_custody; "
    "validate_response_signing_key_custody("
    "Path('/run/secrets/serverware-response-signing-key'),"
    "Path('/run/serverware/custody-trust/"
    "control-plane-response-signing.pub.pem'),"
    "Path('/run/serverware/custody-trust/"
    "control-plane-response-signing.key-id')); "
    "context=ssl.create_default_context("
    "cafile='/run/serverware/tls/ca.pem'); "
    "response=urllib.request.urlopen("
    "'https://serverware:3000/healthz',"
    "context=context,timeout=2); "
    "response.status == 200 or sys.exit(1); "
    "json.load(response).get('ok') is True or sys.exit(1)"
)


def _read_exact_source(descriptor: int, size: int) -> bytes:
    if not 0 <= size <= MAX_SOURCE_BYTES:
        raise RuntimeError("authority descriptor source exceeds 64 MiB")
    value = bytearray()
    offset = 0
    while len(value) < size:
        chunk = os.pread(
            descriptor,
            min(1024 * 1024, size - len(value)),
            offset,
        )
        if not chunk:
            raise RuntimeError("authority descriptor source was truncated")
        value.extend(chunk)
        offset += len(chunk)
    if os.pread(descriptor, 1, size):
        raise RuntimeError("authority descriptor source grew while read")
    return bytes(value)


def _seal_bytes(
    descriptor_number: int,
    *,
    name: str,
    value: bytes,
    mode: int,
) -> int:
    if not hasattr(os, "memfd_create"):
        raise RuntimeError("authority bootstrap requires sealed memfd support")
    sealed = os.memfd_create(
        name,
        flags=os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
    )
    try:
        offset = 0
        while offset < len(value):
            written = os.write(sealed, value[offset:])
            if written <= 0:
                raise RuntimeError(
                    "authority bootstrap memfd write was incomplete"
                )
            offset += written
        os.fchmod(sealed, mode)
        fcntl.fcntl(
            sealed,
            fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_SEAL
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_WRITE,
        )
        os.dup2(sealed, descriptor_number, inheritable=True)
    finally:
        os.close(sealed)
    return descriptor_number


def _open_oauth_application_material(config_fd, *, occupied_descriptors):
    """Fixed root delivery only; signed purpose admission occurs in cold owner."""
    raw = os.pread(config_fd, OAUTH_APPLICATION_CONFIG_MAX_BYTES + 1, 0)
    if not 2 <= len(raw) <= OAUTH_APPLICATION_CONFIG_MAX_BYTES:
        raise RuntimeError("OAuth application startup exceeds its fixed bound")
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise RuntimeError("OAuth startup has duplicate fields")
            result[key] = value
        return result
    config = json.loads(raw.decode("ascii"), object_pairs_hook=pairs)
    if (type(config) is not dict or set(config) != ({"schema", "sourceRevision", "configurationDigest",
            "authorityRootFd", "authorityRootSha256", "applications"} | ({"reconnect"} if config.get("schema") == "serverware.oauthApplicationStartup/v4" else
                {"retiredScopeSuccession"} if config.get("schema") == "serverware.oauthApplicationStartup/v5" else set()))
            or config["schema"] not in {"serverware.oauthApplicationStartup/v1", "serverware.oauthApplicationStartup/v2", "serverware.oauthApplicationStartup/v3", "serverware.oauthApplicationStartup/v4", "serverware.oauthApplicationStartup/v5"}
            or json.dumps(config, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii") != raw
            or type(config["applications"]) is not list or len(config["applications"]) > 2):
        raise RuntimeError("OAuth application startup shape is not exact")
    if not config["applications"]:
        if config["authorityRootFd"] is not None or config["authorityRootSha256"] is not None or config["schema"] in {"serverware.oauthApplicationStartup/v4", "serverware.oauthApplicationStartup/v5"}:
            raise RuntimeError("disabled OAuth startup has an authority root")
        return ()
    selected = [(config["authorityRootFd"], "/run/serverware/authority-trust/oauth-application-root-public-key", 4096, False)]
    if config["schema"] == "serverware.oauthApplicationStartup/v4":
        item = config["reconnect"]
        if type(item) is not dict or set(item) != {"rootFd", "rootSha256", "grantsFd", "grantsSha256"}:
            raise RuntimeError("reconnect cold inventory shape differs")
        selected.extend(((item["rootFd"], "/run/serverware/authority-trust/oauth-reconnect-root-public-key", 4096, False),
            (item["grantsFd"], "/run/serverware/authority-trust/oauth-reconnect-authorizations.json", 1024 * 1024, False)))
    if config["schema"] == "serverware.oauthApplicationStartup/v5":
        item = config["retiredScopeSuccession"]
        if type(item) is not dict or set(item) != {"rootFd", "rootSha256", "grantsFd", "grantsSha256"}:
            raise RuntimeError("retired-scope succession cold inventory shape differs")
        selected.extend(((item["rootFd"], "/run/serverware/authority-trust/oauth-retired-scope-succession-root-public-key", 4096, False),
            (item["grantsFd"], "/run/serverware/authority-trust/oauth-retired-scope-succession-authorizations.json", 2 * 1024 * 1024 + 8192, False)))
    providers = set()
    for entry in config["applications"]:
        if type(entry) is not dict or set(entry) != {"enrollment", "clientMaterialFd"}:
            raise RuntimeError("OAuth application entry is not exact")
        envelope = entry["enrollment"]
        if (type(envelope) is not dict or set(envelope) != {"schema", "payload", "signatureBase64Url"}
                or envelope["schema"] != "serverware.signedOAuthApplicationEnrollment/v1"
                or type(envelope["payload"]) is not dict):
            raise RuntimeError("OAuth enrollment delivery shape is not exact")
        provider = envelope["payload"].get("providerId")
        if provider not in {"google", "x"} or provider in providers:
            raise RuntimeError("OAuth provider delivery is not unique")
        providers.add(provider)
        measured = config["schema"] in {"serverware.oauthApplicationStartup/v2", "serverware.oauthApplicationStartup/v3", "serverware.oauthApplicationStartup/v4"}
        selected.append((entry["clientMaterialFd"], "/run/secrets/serverware-oauth-" + provider
            + ("-client-ciphertext" if measured else "-client"), (64 if measured else 32) * 1024, True))
    targets = [item[0] for item in selected]
    if (any(type(target) is not int or not 32 <= target <= 1023 for target in targets)
            or len(set(targets)) != len(targets) or set(targets) & set(occupied_descriptors)):
        raise RuntimeError("OAuth inherited descriptor slots overlap")
    for target in targets:
        try:
            os.fstat(target)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
        else:
            raise RuntimeError("OAuth inherited descriptor slot is already occupied")
    opened = []
    try:
        for target, path, maximum, private in selected:
            descriptor = _open_source(path, expected_owner_uid=0, maximum_bytes=maximum,
                required_mode=0o400 if private else None)
            try:
                os.dup2(descriptor, target, inheritable=True)
                opened.append(target)
            finally:
                if descriptor != target:
                    os.close(descriptor)
        return tuple(opened)
    except BaseException:
        for descriptor in opened:
            os.close(descriptor)
        raise


def _open_measured_audit_material(config_fd, *, occupied_descriptors):
    from serverware import data_plane_audit_authority as profile
    value = profile.document(os.pread(config_fd, MEASURED_AUDIT_CONFIG_MAX_BYTES + 1, 0), MEASURED_AUDIT_CONFIG_MAX_BYTES)
    profile.require(set(value) == {"schema", "sourceRevision", "configurationDigest", "authorityRootFd", "authorityRootSha256", "authorization"}
        and value["schema"] == profile.STARTUP_SCHEMA)
    target = value["authorityRootFd"]
    profile.require(type(target) is int and 32 <= target <= 1023 and target not in occupied_descriptors)
    try:
        os.fstat(target)
    except OSError as exc:
        if exc.errno != errno.EBADF: raise
    else: raise RuntimeError("measured audit root descriptor is occupied")
    descriptor = _open_source("/run/serverware/authority-trust/measured-audit-root-public-key", expected_owner_uid=0, maximum_bytes=4096)
    try:
        os.dup2(descriptor, target, inheritable=True)
    finally:
        if descriptor != target: os.close(descriptor)
    return (target,)


def _open_setup_native_material(config_fd, *, occupied_descriptors):
    """Read-only native identity originals at two fixed administrator paths."""
    from serverware import control_plane_native_loaded_trust as cold
    value = cold.configuration(cold.codec.document(os.pread(config_fd, 16385, 0), 16384))
    selections = ((value["authorityRootFd"], "/run/serverware/authority-trust/setup-native-observation-root-public-key", 4096),
        (value["authorityConfigurationFd"], "/run/serverware/authority-trust/setup-native-observation-authority-configuration.json", cold.contract.MAX_REQUEST_BYTES))
    opened = []
    try:
        for target, path, maximum in selections:
            if type(target) is not int or not 32 <= target <= 1023 or target in occupied_descriptors or target in opened:
                raise RuntimeError("native observation public-original descriptor overlaps")
            try:
                os.fstat(target)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise
            else:
                raise RuntimeError("native observation public-original descriptor is occupied")
            descriptor = _open_source(path, expected_owner_uid=0, maximum_bytes=maximum)
            try:
                if descriptor != target:
                    os.dup2(descriptor, target, inheritable=True)
                else:
                    os.set_inheritable(target, True)
                opened.append(target)
            finally:
                if descriptor != target:
                    os.close(descriptor)
        return tuple(opened)
    except BaseException:
        for descriptor in opened:
            os.close(descriptor)
        raise


def _open_policy_canary_material(config_fd, *, occupied_descriptors):
    """Closed public configuration delivery; never caller-selected key paths."""
    from serverware import control_plane_policy_canary_startup as cold
    from serverware import authority_policy_canary as profile
    value = cold.configuration(profile.document(os.pread(config_fd, cold.CONFIG_MAX + 1, 0), cold.CONFIG_MAX, exact=False))
    selections = ((value["authorityRootFd"], "/run/serverware/authority-trust/policy-canary-root-public-key", 4096),
        (value["authorityConfigurationFd"], "/run/serverware/authority-trust/policy-canary-authority-configuration.json", cold.AUTHORITY_MAX))
    opened = []
    try:
        for target, path, maximum in selections:
            profile.require(type(target) is int and 32 <= target <= 1023
                and target not in occupied_descriptors and target not in opened)
            try:
                os.fstat(target)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise
            else:
                raise RuntimeError("canary public-policy descriptor is occupied")
            descriptor = _open_source(path, expected_owner_uid=0, maximum_bytes=maximum)
            try:
                if descriptor != target:
                    os.dup2(descriptor, target, inheritable=True)
                else:
                    os.set_inheritable(target, True)
                opened.append(target)
            finally:
                if descriptor != target:
                    os.close(descriptor)
        return tuple(opened)
    except BaseException:
        for descriptor in opened:
            os.close(descriptor)
        raise


def _open_oauth_revocation_material(config_fd, *, occupied_descriptors):
    """Deliver fixed cleanup originals; no arbitrary pathname or signing key."""
    from serverware import authority_oauth_revocation as profile
    raw = os.pread(config_fd, OAUTH_REVOCATION_CONFIG_MAX_BYTES + 1, 0)
    config = profile.document(raw, OAUTH_REVOCATION_CONFIG_MAX_BYTES)
    profile.require(set(config) == {"schema", "sourceRevision", "configurationDigest", "authorityRootFd", "authorityRootSha256", "authorizations"}
        and config["schema"] == "serverware.oauthRevocationStartup/v1"
        and type(config["authorizations"]) is list and len(config["authorizations"]) <= 16)
    if not config["authorizations"]:
        profile.require(config["authorityRootFd"] is None and config["authorityRootSha256"] is None)
        return ()
    selected = [(config["authorityRootFd"], "/run/serverware/authority-trust/oauth-revocation-root-public-key", 4096, False)]
    work_ids = set()
    for entry in config["authorizations"]:
        profile.require(type(entry) is dict and set(entry) == {"authorization", "clientMaterialFd", "historicalEnrollmentRootFd"})
        grant = profile.grant_document(profile.canonical(entry["authorization"]))["payload"]
        profile.require(grant["exchangeId"] not in work_ids)
        work_ids.add(grant["exchangeId"])
        selected.extend(((entry["clientMaterialFd"],
            "/run/secrets/serverware-oauth-revocation-" + grant["authorizationId"] + "-client", 32 * 1024, True),
            (entry["historicalEnrollmentRootFd"], "/run/serverware/authority-trust/oauth-enrollment-history/"
                + grant["historicalEnrollmentRootSpkiSha256"][7:] + "-public-key", 4096, False)))
    targets = [item[0] for item in selected]
    profile.require(all(type(target) is int and 32 <= target <= 1023 for target in targets)
        and len(set(targets)) == len(targets) and not set(targets) & set(occupied_descriptors))
    for target in targets:
        try:
            os.fstat(target)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
        else:
            raise RuntimeError("OAuth cleanup inherited descriptor slot is occupied")
    opened = []
    try:
        for target, path, maximum, private in selected:
            descriptor = _open_source(path, expected_owner_uid=0, maximum_bytes=maximum,
                required_mode=0o400 if private else None)
            try:
                os.dup2(descriptor, target, inheritable=True)
                opened.append(target)
            finally:
                if descriptor != target:
                    os.close(descriptor)
        return tuple(opened)
    except BaseException:
        for descriptor in opened:
            os.close(descriptor)
        raise


def _open_oauth_refresh_cleanup_material(config_fd, *, occupied_descriptors):
    """Deliver fixed cleanup originals; no arbitrary pathname or signing key."""
    from serverware import authority_oauth_refresh_cleanup as profile
    raw = os.pread(config_fd, OAUTH_REFRESH_CLEANUP_CONFIG_MAX_BYTES + 1, 0)
    config = profile.document(raw, OAUTH_REFRESH_CLEANUP_CONFIG_MAX_BYTES)
    profile.require(set(config) == {"schema", "sourceRevision", "configurationDigest", "authorityRootFd", "authorityRootSha256", "authorizations"}
        and config["schema"] == "serverware.oauthRefreshCleanupStartup/v1"
        and type(config["authorizations"]) is list and len(config["authorizations"]) <= 16)
    if not config["authorizations"]:
        profile.require(config["authorityRootFd"] is None and config["authorityRootSha256"] is None)
        return ()
    selected = [(config["authorityRootFd"], "/run/serverware/authority-trust/oauth-refresh-cleanup-root-public-key", 4096, False)]
    work_ids = set()
    for entry in config["authorizations"]:
        profile.require(type(entry) is dict and set(entry) == {"authorization", "clientMaterialFd", "historicalEnrollmentRootFd"})
        grant = profile.grant_document(profile.canonical(entry["authorization"]))["payload"]
        profile.require(grant["workId"] not in work_ids)
        work_ids.add(grant["workId"])
        selected.extend(((entry["clientMaterialFd"],
            "/run/secrets/serverware-oauth-refresh-cleanup-" + grant["authorizationId"] + "-client", 32 * 1024, True),
            (entry["historicalEnrollmentRootFd"], "/run/serverware/authority-trust/oauth-enrollment-history/"
                + grant["historicalEnrollmentRootSpkiSha256"][7:] + "-public-key", 4096, False)))
    targets = [item[0] for item in selected]
    profile.require(all(type(target) is int and 32 <= target <= 1023 for target in targets)
        and len(set(targets)) == len(targets) and not set(targets) & set(occupied_descriptors))
    for target in targets:
        try:
            os.fstat(target)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
        else:
            raise RuntimeError("OAuth cleanup inherited descriptor slot is occupied")
    opened = []
    try:
        for target, path, maximum, private in selected:
            descriptor = _open_source(path, expected_owner_uid=0, maximum_bytes=maximum,
                required_mode=0o400 if private else None)
            try:
                os.dup2(descriptor, target, inheritable=True)
                opened.append(target)
            finally:
                if descriptor != target:
                    os.close(descriptor)
        return tuple(opened)
    except BaseException:
        for descriptor in opened:
            os.close(descriptor)
        raise


def _open_rbac_witness_material(config_fd, *, occupied_descriptors):
    """CP delivery only; authority roles use their signed descriptor inventory."""
    from serverware import authority_rbac_currentness as profile
    config = profile.document(os.pread(config_fd, RBAC_WITNESS_CONFIG_MAX_BYTES + 1, 0), RBAC_WITNESS_CONFIG_MAX_BYTES)
    profile.require(type(config) is dict and config.get("schema") in {
        profile.STARTUP_SCHEMA, profile.STARTUP_V2_SCHEMA, profile.LOCAL_STARTUP_SCHEMA})
    second = config["schema"] == profile.STARTUP_V2_SCHEMA
    profile.require(set(config) == {"schema", "sourceRevision", "configurationDigest",
        "root", "enrollment", "tlsRoot", "clientCertificate", "clientKey"} | ({"recoveryAuthorization"} if second else set())
        and (not second or config["recoveryAuthorization"] is None), "HTTP runtime cannot acquire recovery-only permission")
    selected = (("root", "/run/serverware/authority-trust/rbac-witness-root-public-key", 4096, False),
        ("tlsRoot", "/run/serverware/authority-trust/rbac-witness-tls-root", 65536, False),
        ("clientCertificate", "/run/serverware/authority-trust/rbac-witness-reader-certificate", 65536, False),
        ("clientKey", "/run/secrets/serverware-rbac-witness-reader-key", 16384, True))
    targets = []
    for name, _, _, _ in selected:
        item = config[name]
        profile.require(type(item) is dict and set(item) == {"fd", "sha256"}
            and type(item["fd"]) is int and 32 <= item["fd"] <= 1023)
        profile.digest(item["sha256"]); targets.append(item["fd"])
    profile.require(len(set(targets)) == 4 and not set(targets) & set(occupied_descriptors))
    for target in targets:
        try: os.fstat(target)
        except OSError as exc:
            if exc.errno != errno.EBADF: raise
        else: raise RuntimeError("RBAC original descriptor slot is occupied")
    opened = []
    try:
        for (name, path, maximum, private), target in zip(selected, targets):
            descriptor = _open_source(path, expected_owner_uid=0, maximum_bytes=maximum, required_mode=0o400 if private else None)
            try:
                profile.require(profile.sha256(os.pread(descriptor, maximum + 1, 0)) == config[name]["sha256"])
                os.dup2(descriptor, target, inheritable=True); opened.append(target)
            finally:
                if descriptor != target: os.close(descriptor)
        return tuple(opened)
    except BaseException:
        for descriptor in opened: os.close(descriptor)
        raise


def _open_source(
    path: str,
    *,
    expected_owner_uid: int,
    maximum_bytes: int = MAX_SOURCE_BYTES,
    required_mode: int | None = None,
    directory_fd: int | None = None,
) -> int:
    if type(maximum_bytes) is not int or not 1 <= maximum_bytes <= MAX_SOURCE_BYTES:
        raise RuntimeError("authority descriptor source bound is invalid")
    if required_mode is not None and (type(required_mode) is not int or required_mode != 0o400):
        raise RuntimeError("authority private source mode is not exact")
    if directory_fd is not None and (type(directory_fd) is not int or directory_fd < 0):
        raise RuntimeError("authority source parent descriptor is invalid")
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        | (os.O_NONBLOCK if required_mode is not None else 0),
        dir_fd=directory_fd,
    )
    try:
        metadata_before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata_before.st_mode)
            or metadata_before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or metadata_before.st_uid != expected_owner_uid
            or metadata_before.st_nlink != 1
            or not 0 <= metadata_before.st_size <= maximum_bytes
            or required_mode is not None and (
                stat.S_IMODE(metadata_before.st_mode) != required_mode
                or metadata_before.st_size < 1)
        ):
            raise RuntimeError("authority descriptor source is not trusted")
        value = _read_exact_source(descriptor, metadata_before.st_size)
        metadata_after = os.fstat(descriptor)
        if (
            metadata_before.st_dev,
            metadata_before.st_ino,
            metadata_before.st_size,
            metadata_before.st_mtime_ns,
        ) != (
            metadata_after.st_dev,
            metadata_after.st_ino,
            metadata_after.st_size,
            metadata_after.st_mtime_ns,
        ):
            raise RuntimeError(
                "authority descriptor source changed while sealing"
            )
        if required_mode is not None and _material_identity(metadata_before) != _material_identity(metadata_after):
            raise RuntimeError("authority private source identity changed while sealing")
        return _seal_bytes(
            descriptor,
            name="serverware-authority-material",
            value=value,
            mode=stat.S_IMODE(metadata_before.st_mode),
        )
    except BaseException:
        os.close(descriptor)
        raise


def _material_identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid,
        metadata.st_gid, metadata.st_nlink, metadata.st_size,
        metadata.st_mtime_ns, metadata.st_ctime_ns)


def _control_plane_execution_key_slot(value, *, issuer_descriptor, bootstrap_descriptor):
    """Closed v3 delivery projection, not signature or purpose admission."""
    if value is None:
        return None
    if type(value) is not dict:
        raise RuntimeError("registration execution caller key delivery scope is invalid")
    version = value.get("schema")
    if type(version) is not str or version not in (
            CONTROL_PLANE_EXECUTION_SCHEMA, CONTROL_PLANE_EXECUTION_V2_SCHEMA,
            CONTROL_PLANE_EXECUTION_V3_SCHEMA):
        raise RuntimeError("registration execution caller delivery profile is unsupported")
    fields = {"schema", "executionCallerPrivateKeyFd", "currentRootEnrollment",
        "grantEnrollment", "authorizationEnrollment", "authorizerEndpoint"}
    if version in (CONTROL_PLANE_EXECUTION_V2_SCHEMA, CONTROL_PLANE_EXECUTION_V3_SCHEMA):
        fields.update(("reserverEndpoint", "statePredecessor"))
    if version == CONTROL_PLANE_EXECUTION_V3_SCHEMA:
        fields.update(("sqlEndpoint", "completionEndpoint", "currentPending", "completionPacketDigest"))
    if (set(value) != fields or type(value["executionCallerPrivateKeyFd"]) is not int
            or value["executionCallerPrivateKeyFd"] != CONTROL_PLANE_EXECUTION_KEY_FD
            or issuer_descriptor is None
            or CONTROL_PLANE_EXECUTION_KEY_FD in (issuer_descriptor, bootstrap_descriptor)):
        raise RuntimeError("registration execution caller key delivery scope is invalid")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    for name, maximum in (("currentRootEnrollment", 128 * 1024),
            ("grantEnrollment", 16 * 1024), ("authorizationEnrollment", 16 * 1024)):
        original = value[name]
        if type(original) is not dict or set(original) != {"base64Url", "byteCount"}:
            raise RuntimeError("registration execution enrollment record is not closed")
        encoded, size = original["base64Url"], original["byteCount"]
        if (type(size) is not int or not 2 <= size <= maximum or type(encoded) is not str
                or len(encoded) != (4 * size + 2) // 3
                or any(character not in alphabet for character in encoded)):
            raise RuntimeError("registration execution enrollment original exceeds its delivery bound")
    endpoints = (("authorizerEndpoint", CONTROL_PLANE_EXECUTION_SOCKET),)
    if version in (CONTROL_PLANE_EXECUTION_V2_SCHEMA, CONTROL_PLANE_EXECUTION_V3_SCHEMA):
        endpoints += (("reserverEndpoint", CONTROL_PLANE_RESERVATION_SOCKET),)
    if version == CONTROL_PLANE_EXECUTION_V3_SCHEMA:
        endpoints += (("sqlEndpoint", CONTROL_PLANE_SQL_SOCKET),
            ("completionEndpoint", CONTROL_PLANE_COMPLETION_SOCKET))
    for name, path in endpoints:
        endpoint = value[name]
        if (type(endpoint) is not dict or set(endpoint) != {"socketPath", "requestTimeoutSeconds",
                "listenerUid", "listenerGid"}
                or type(endpoint["socketPath"]) is not str or endpoint["socketPath"] != path
                or type(endpoint["requestTimeoutSeconds"]) is not int
                or not 1 <= endpoint["requestTimeoutSeconds"] <= 30
                or any(type(endpoint[field]) is not int or endpoint[field] != 0
                    for field in ("listenerUid", "listenerGid"))):
            raise RuntimeError("registration execution endpoint differs from its fixed delivery contract")
    if version in (CONTROL_PLANE_EXECUTION_V2_SCHEMA, CONTROL_PLANE_EXECUTION_V3_SCHEMA):
        predecessor = value["statePredecessor"]
        if type(predecessor) is not dict or set(predecessor) != {"sequence", "headDigest", "nextFence"}:
            raise RuntimeError("registration reserve predecessor delivery scope is not closed")
        sequence, head, fence = predecessor["sequence"], predecessor["headDigest"], predecessor["nextFence"]
        # Match the source shape only: current-root MAX_RECORDS is 1024 and
        # its fence is positive I63. Enrolled capacity and the actual genesis
        # enrollment digest remain the child's cryptographic admission gates.
        if (type(sequence) is not int or not 0 <= sequence <= 1024
                or type(head) is not str or len(head) != 71 or not head.startswith("sha256:")
                or any(character not in "0123456789abcdef" for character in head[7:])
                or type(fence) is not int or not 1 <= fence <= 2**63 - 1
                or sequence == 0 and fence != 1):
            raise RuntimeError("registration reserve predecessor exceeds its fixed delivery shape")
    if version == CONTROL_PLANE_EXECUTION_V3_SCHEMA:
        pending = value["currentPending"]
        if type(pending) is not dict or set(pending) != {"sequence", "headDigest", "fence"}:
            raise RuntimeError("registration execution pending delivery scope is not closed")
        pending_sequence, pending_fence = pending["sequence"], pending["fence"]
        if (type(pending_sequence) is not int or not 1 <= pending_sequence <= 1024
                or type(pending_fence) is not int or not 1 <= pending_fence <= 2**63 - 1
                or pending_sequence != sequence + 1 or pending_fence != fence):
            raise RuntimeError("registration execution pending scope differs from its cold predecessor")
        for digest in (pending["headDigest"], value["completionPacketDigest"]):
            if (type(digest) is not str or len(digest) != 71 or not digest.startswith("sha256:")
                    or any(character not in "0123456789abcdef" for character in digest[7:])):
                raise RuntimeError("registration execution handoff pin is not canonical SHA-256")
        # Actual enrollment capacity, signatures and original generation/key
        # joins still belong to the child. No extra key or FD is delivered.
    return CONTROL_PLANE_EXECUTION_KEY_FD


def _control_plane_finalization_key_slot(value, *, issuer_descriptor, bootstrap_descriptor):
    """Fixed v4 delivery shape only; no root or finalization-purpose admission."""
    if issuer_descriptor == CONTROL_PLANE_FINALIZATION_KEY_FD:
        raise RuntimeError("v4 reserves the finalization key slot independently of enablement")
    if value is None:
        return None
    fields = {"schema", "finalizationCallerPrivateKeyFd", "currentRootEnrollment",
        "grantEnrollment", "authorizationEnrollment", "authorizerEndpoint"}
    version = value.get("schema") if type(value) is dict else None
    if type(version) is not str or version not in (CONTROL_PLANE_FINALIZATION_SCHEMA,
            CONTROL_PLANE_FINALIZATION_V2_SCHEMA, CONTROL_PLANE_FINALIZATION_V3_SCHEMA,
            CONTROL_PLANE_FINALIZATION_V4_SCHEMA):
        raise RuntimeError("finalization caller delivery version is unsupported")
    if version in (CONTROL_PLANE_FINALIZATION_V2_SCHEMA, CONTROL_PLANE_FINALIZATION_V3_SCHEMA,
            CONTROL_PLANE_FINALIZATION_V4_SCHEMA):
        fields |= {"reserverEndpoint", "statePredecessor"}
    if version in (CONTROL_PLANE_FINALIZATION_V3_SCHEMA, CONTROL_PLANE_FINALIZATION_V4_SCHEMA):
        fields |= {"sqlEndpoint", "currentPending"}
    if version == CONTROL_PLANE_FINALIZATION_V4_SCHEMA:
        fields |= {"completionEndpoint", "completionPacketDigest", "completionAuthorizationDigest"}
    if (type(value) is not dict or set(value) != fields
            or type(value["finalizationCallerPrivateKeyFd"]) is not int
            or value["finalizationCallerPrivateKeyFd"] != CONTROL_PLANE_FINALIZATION_KEY_FD
            or issuer_descriptor is None
            or CONTROL_PLANE_FINALIZATION_KEY_FD == bootstrap_descriptor):
        raise RuntimeError("finalization caller key delivery scope is invalid")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    for name, maximum in (("currentRootEnrollment", 128 * 1024),
            ("grantEnrollment", 16 * 1024), ("authorizationEnrollment", 16 * 1024)):
        original = value[name]
        if type(original) is not dict or set(original) != {"base64Url", "byteCount"}:
            raise RuntimeError("finalization enrollment record is not closed")
        encoded, size = original["base64Url"], original["byteCount"]
        if (type(size) is not int or not 2 <= size <= maximum or type(encoded) is not str
                or len(encoded) != (4 * size + 2) // 3
                or any(character not in alphabet for character in encoded)):
            raise RuntimeError("finalization enrollment original exceeds its delivery bound")
    endpoints = (("authorizerEndpoint", CONTROL_PLANE_FINALIZATION_SOCKET),)
    if version in (CONTROL_PLANE_FINALIZATION_V2_SCHEMA, CONTROL_PLANE_FINALIZATION_V3_SCHEMA,
            CONTROL_PLANE_FINALIZATION_V4_SCHEMA):
        endpoints += (("reserverEndpoint", CONTROL_PLANE_FINALIZATION_RESERVATION_SOCKET),)
    if version in (CONTROL_PLANE_FINALIZATION_V3_SCHEMA, CONTROL_PLANE_FINALIZATION_V4_SCHEMA):
        endpoints += (("sqlEndpoint", CONTROL_PLANE_FINALIZATION_SQL_SOCKET),)
    if version == CONTROL_PLANE_FINALIZATION_V4_SCHEMA:
        endpoints += (("completionEndpoint", CONTROL_PLANE_FINALIZATION_COMPLETION_SOCKET),)
    for name, path in endpoints:
        endpoint = value[name]
        if (type(endpoint) is not dict or set(endpoint) != {"socketPath", "requestTimeoutSeconds",
                "listenerUid", "listenerGid"}
                or type(endpoint["socketPath"]) is not str or endpoint["socketPath"] != path
                or type(endpoint["requestTimeoutSeconds"]) is not int
                or not 1 <= endpoint["requestTimeoutSeconds"] <= 30
                or any(type(endpoint[field]) is not int or endpoint[field] != 0
                    for field in ("listenerUid", "listenerGid"))):
            raise RuntimeError("finalization endpoint differs from its fixed delivery contract")
    if version in (CONTROL_PLANE_FINALIZATION_V2_SCHEMA, CONTROL_PLANE_FINALIZATION_V3_SCHEMA,
            CONTROL_PLANE_FINALIZATION_V4_SCHEMA):
        predecessor = value["statePredecessor"]
        if type(predecessor) is not dict or set(predecessor) != {"sequence", "headDigest", "nextFence"}:
            raise RuntimeError("finalization predecessor delivery scope is not closed")
        sequence, head, fence = predecessor["sequence"], predecessor["headDigest"], predecessor["nextFence"]
        if (type(sequence) is not int or not 0 <= sequence <= 1024
                or type(head) is not str or len(head) != 71 or not head.startswith("sha256:")
                or any(character not in "0123456789abcdef" for character in head[7:])
                or type(fence) is not int or not 1 <= fence <= 2**63 - 1
                or sequence == 0 and fence != 1):
            raise RuntimeError("finalization predecessor exceeds its delivery shape")
    if version in (CONTROL_PLANE_FINALIZATION_V3_SCHEMA, CONTROL_PLANE_FINALIZATION_V4_SCHEMA):
        pending = value["currentPending"]
        if type(pending) is not dict or set(pending) != {"sequence", "headDigest", "fence"}:
            raise RuntimeError("finalization pending delivery scope is not closed")
        pending_sequence, pending_head, pending_fence = pending["sequence"], pending["headDigest"], pending["fence"]
        if (type(pending_sequence) is not int or not 1 <= pending_sequence <= 1024
                or type(pending_fence) is not int or not 1 <= pending_fence <= 2**63 - 1
                or pending_sequence != sequence + 1 or pending_fence != fence
                or type(pending_head) is not str or len(pending_head) != 71
                or not pending_head.startswith("sha256:")
                or any(character not in "0123456789abcdef" for character in pending_head[7:])):
            raise RuntimeError("finalization pending scope differs from its cold predecessor")
    if version == CONTROL_PLANE_FINALIZATION_V4_SCHEMA:
        for name in ("completionPacketDigest", "completionAuthorizationDigest"):
            digest = value[name]
            if (type(digest) is not str or len(digest) != 71 or not digest.startswith("sha256:")
                    or any(character not in "0123456789abcdef" for character in digest[7:])):
                raise RuntimeError("finalization completion identity is not a canonical delivery pin")
    # This stdlib-only projection does not authenticate any original or enroll
    # a current head. The child still verifies root signatures, operation/key/
    # generation scope, actual enrollment capacity and independent pending pins.
    # Nested v4 completion pins neither add an FD nor prove a returned packet.
    return CONTROL_PLANE_FINALIZATION_KEY_FD


def _control_plane_release_public_shape(value):
    """Closed public-data projection only: no release key, FD, crypto or clock."""
    if value is None:
        return
    if (type(value) is not dict
            or set(value) != {"schema", "clientAuthorization", "serverBootstrap", "expectedScope"}
            or value["schema"] != CONTROL_PLANE_RELEASE_SCHEMA):
        raise RuntimeError("control-plane release public configuration is not closed")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    total = 0
    for name, maximum in (("clientAuthorization", 16 * 1024), ("serverBootstrap", 16 * 1024 * 1024)):
        original = value[name]
        if type(original) is not dict or set(original) != {"base64Url", "byteCount"}:
            raise RuntimeError("control-plane release public original is not closed")
        encoded, size = original["base64Url"], original["byteCount"]
        if (type(size) is not int or not 2 <= size <= maximum or type(encoded) is not str
                or len(encoded) != (4 * size + 2) // 3
                or any(character not in alphabet for character in encoded)):
            raise RuntimeError("control-plane release public original exceeds its delivery bound")
        unused = 4 if size % 3 == 1 else 2 if size % 3 == 2 else 0
        if unused and alphabet.index(encoded[-1]) & ((1 << unused) - 1):
            raise RuntimeError("control-plane release public original encoding is not canonical")
        total += size
    if total > CONTROL_PLANE_ENROLLMENT_BOOTSTRAP_MAX_BYTES:
        raise RuntimeError("control-plane release public originals exceed the parent bound")

    def digest(value):
        if (type(value) is not str or len(value) != 71 or not value.startswith("sha256:")
                or any(character not in "0123456789abcdef" for character in value[7:])):
            raise RuntimeError("control-plane release identity is not canonical SHA-256")

    scope = value["expectedScope"]
    if (type(scope) is not dict or set(scope) != {"serverBootstrapDigest", "profile", "requestIdentity",
            "configurationDigest", "databaseId", "generationDigest", "runtimeClosureDigest",
            "clientId", "clientIdentity", "callerId", "receiverIdentity", "producerId",
            "producerIdentity", "stateReceiptDigest", "expectedRelease", "expectedOutcomeDigest", "endpoint"}
            or type(scope["profile"]) is not str or scope["profile"] not in ("live-release", "recovery")):
        raise RuntimeError("control-plane release independent scope is not closed")
    for name in ("serverBootstrapDigest", "requestIdentity", "configurationDigest", "generationDigest",
            "runtimeClosureDigest", "stateReceiptDigest", "expectedOutcomeDigest"):
        digest(scope[name])
    token_start = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    for name in ("databaseId", "clientId", "callerId", "producerId"):
        token = scope[name]
        if (type(token) is not str or not 1 <= len(token) <= 128 or token[0] not in token_start
                or any(character not in token_start + "._:-" for character in token)):
            raise RuntimeError("control-plane release identifier is not a bounded ASCII token")
    for name in ("clientIdentity", "receiverIdentity", "producerIdentity"):
        identity = scope[name]
        if type(identity) is not dict or set(identity) != {
                "sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest"}:
            raise RuntimeError("control-plane release identity scope is not closed")
        for item in identity.values():
            digest(item)
    release = scope["expectedRelease"]
    if type(release) is not dict or set(release) != {"activationRequestDigest", "activationOperationId",
            "consumeRequestDigest", "deliveryEnvelopeDigest", "deliveryScope", "consumeBinding"}:
        raise RuntimeError("control-plane release target is not closed")
    for name in ("activationRequestDigest", "activationOperationId", "consumeRequestDigest", "deliveryEnvelopeDigest"):
        digest(release[name])
    binding = release["consumeBinding"]
    if type(binding) is not dict or set(binding) != {"packetDigest", "pendingDecisionDigest",
            "completionRequestDigest", "effectsDigest", "afterVectorDigest"}:
        raise RuntimeError("control-plane release consume binding is not closed")
    for item in binding.values():
        digest(item)
    delivery = release["deliveryScope"]
    limits = {"deliveryId": 128, "userId": 4096, "sessionId": 128, "credentialId": 1366,
        "credentialRecordId": 4096, "challengeId": 4096, "assertionDigest": 71,
        "oldTokenDigest": 71, "newTokenDigest": 71, "createdAt": 64, "expiresAt": 64}
    if type(delivery) is not dict or set(delivery) != set(limits):
        raise RuntimeError("control-plane release delivery scope is not closed")
    for name, maximum in limits.items():
        item = delivery[name]
        if type(item) is not str or not 1 <= len(item) <= maximum or "\x00" in item:
            raise RuntimeError("control-plane release delivery field exceeds its shape bound")
    for name in ("assertionDigest", "oldTokenDigest", "newTokenDigest"):
        digest(delivery[name])
    endpoint = scope["endpoint"]
    if (type(endpoint) is not dict or set(endpoint) != {"path", "timeoutSeconds", "peerUid", "peerGid"}
            or endpoint["path"] != CONTROL_PLANE_RELEASE_SOCKET
            or type(endpoint["timeoutSeconds"]) is not int or not 1 <= endpoint["timeoutSeconds"] <= 30
            or any(type(endpoint[name]) is not int or endpoint[name] != 0 for name in ("peerUid", "peerGid"))):
        raise RuntimeError("control-plane release endpoint differs from its fixed public contract")
    # All signature, source-cohort, canonical timestamp, target and freshness
    # checks remain in actual child admission. This adds no delivered slot.


def _control_plane_activation_key_slot(value, *, issuer_descriptor, bootstrap_descriptor):
    """V6 metadata only; actual caller/root/key admission belongs to startup."""
    if issuer_descriptor == CONTROL_PLANE_ACTIVATION_KEY_FD:
        raise RuntimeError("v6 reserves the activation key slot independently of enablement")
    if value is None:
        return None
    if (type(value) is not dict or type(value.get("schema")) is not str
            or value["schema"] not in (CONTROL_PLANE_ACTIVATION_SCHEMA,
                CONTROL_PLANE_ACTIVATION_V2_SCHEMA, CONTROL_PLANE_ACTIVATION_V3_SCHEMA,
                CONTROL_PLANE_ACTIVATION_V4_SCHEMA)):
        raise RuntimeError("activation caller delivery schema differs")
    fields = {"schema", "activationCallerPrivateKeyFd", "plannerKey", "currentRootEnrollment",
        "grantEnrollment", "authorizationEnrollment", "authorizerEndpoint"}
    if value["schema"] in (CONTROL_PLANE_ACTIVATION_V2_SCHEMA, CONTROL_PLANE_ACTIVATION_V3_SCHEMA,
            CONTROL_PLANE_ACTIVATION_V4_SCHEMA):
        fields |= {"reserverEndpoint", "sqlEndpoint", "statePredecessor"}
    if value["schema"] in (CONTROL_PLANE_ACTIVATION_V3_SCHEMA, CONTROL_PLANE_ACTIVATION_V4_SCHEMA):
        fields.add("completionEndpoint")
    if value["schema"] == CONTROL_PLANE_ACTIVATION_V4_SCHEMA:
        fields |= {"consumePlannerEndpoint", "consumePlannerKey"}
    if (set(value) != fields or type(value["activationCallerPrivateKeyFd"]) is not int
            or value["activationCallerPrivateKeyFd"] != CONTROL_PLANE_ACTIVATION_KEY_FD
            or bootstrap_descriptor == CONTROL_PLANE_ACTIVATION_KEY_FD):
        raise RuntimeError("activation caller key delivery scope is invalid")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    planner = value["plannerKey"]
    if type(planner) is not dict or set(planner) != {"publicKeyBase64Url", "spkiDigest"}:
        raise RuntimeError("activation planner key delivery shape is not closed")
    encoded, pin = planner["publicKeyBase64Url"], planner["spkiDigest"]
    if (type(encoded) is not str or len(encoded) != 43
            or any(character not in alphabet for character in encoded)
            or alphabet.index(encoded[-1]) & 3
            or type(pin) is not str or len(pin) != 71 or not pin.startswith("sha256:")
            or any(character not in "0123456789abcdef" for character in pin[7:])):
        raise RuntimeError("activation planner public key encoding is not bounded canonical data")
    if value["schema"] == CONTROL_PLANE_ACTIVATION_V4_SCHEMA:
        consume = value["consumePlannerKey"]
        if type(consume) is not dict or set(consume) != {"publicKeyBase64Url", "spkiDigest", "measurementDigest"}:
            raise RuntimeError("consume planner public key delivery shape is not closed")
        encoded = consume["publicKeyBase64Url"]
        if (type(encoded) is not str or len(encoded) != 43
                or any(character not in alphabet for character in encoded)
                or alphabet.index(encoded[-1]) & 3):
            raise RuntimeError("consume planner public key encoding is not canonical")
        for name in ("spkiDigest", "measurementDigest"):
            pin = consume[name]
            if (type(pin) is not str or len(pin) != 71 or not pin.startswith("sha256:")
                    or any(character not in "0123456789abcdef" for character in pin[7:])):
                raise RuntimeError("consume planner public identity is not canonical SHA256")
    for name, maximum in (("currentRootEnrollment", 128 * 1024),
            ("grantEnrollment", 16 * 1024), ("authorizationEnrollment", 16 * 1024)):
        original = value[name]
        if type(original) is not dict or set(original) != {"base64Url", "byteCount"}:
            raise RuntimeError("activation caller enrollment delivery shape is not closed")
        encoded, size = original["base64Url"], original["byteCount"]
        if (type(size) is not int or not 2 <= size <= maximum or type(encoded) is not str
                or len(encoded) != (4 * size + 2) // 3
                or any(character not in alphabet for character in encoded)):
            raise RuntimeError("activation caller enrollment original exceeds its delivery bound")
        unused = 4 if size % 3 == 1 else 2 if size % 3 == 2 else 0
        if unused and alphabet.index(encoded[-1]) & ((1 << unused) - 1):
            raise RuntimeError("activation caller enrollment encoding is not canonical")
    endpoints = (("authorizerEndpoint", CONTROL_PLANE_ACTIVATION_SOCKET),)
    if value["schema"] in (CONTROL_PLANE_ACTIVATION_V2_SCHEMA, CONTROL_PLANE_ACTIVATION_V3_SCHEMA,
            CONTROL_PLANE_ACTIVATION_V4_SCHEMA):
        endpoints += (("reserverEndpoint", CONTROL_PLANE_ACTIVATION_RESERVER_SOCKET),
            ("sqlEndpoint", CONTROL_PLANE_ACTIVATION_SQL_SOCKET))
        predecessor = value["statePredecessor"]
        if (type(predecessor) is not dict or set(predecessor) != {"sequence", "headDigest", "nextFence"}
                or type(predecessor["sequence"]) is not int or not 0 <= predecessor["sequence"] <= 1024
                or type(predecessor["nextFence"]) is not int or not 1 <= predecessor["nextFence"] <= 2**63 - 1
                or predecessor["sequence"] == 0 and predecessor["nextFence"] != 1):
            raise RuntimeError("activation independent predecessor delivery shape differs")
        pin = predecessor["headDigest"]
        if (type(pin) is not str or len(pin) != 71 or not pin.startswith("sha256:")
                or any(character not in "0123456789abcdef" for character in pin[7:])):
            raise RuntimeError("activation predecessor head is not canonical SHA256")
    if value["schema"] in (CONTROL_PLANE_ACTIVATION_V3_SCHEMA, CONTROL_PLANE_ACTIVATION_V4_SCHEMA):
        endpoints += (("completionEndpoint", CONTROL_PLANE_ACTIVATION_COMPLETION_SOCKET),)
    if value["schema"] == CONTROL_PLANE_ACTIVATION_V4_SCHEMA:
        endpoints += (("consumePlannerEndpoint", CONTROL_PLANE_ACTIVATION_CONSUME_PLANNER_SOCKET),)
    for field, path in endpoints:
        endpoint = value[field]
        if (type(endpoint) is not dict
                or set(endpoint) != {"socketPath", "requestTimeoutSeconds", "listenerUid", "listenerGid"}
                or endpoint["socketPath"] != path
                or type(endpoint["requestTimeoutSeconds"]) is not int
                or not 1 <= endpoint["requestTimeoutSeconds"] <= 30
                or any(type(endpoint[name]) is not int or endpoint[name] != 0
                    for name in ("listenerUid", "listenerGid"))):
            raise RuntimeError("activation endpoint differs from its fixed delivery contract")
    return CONTROL_PLANE_ACTIVATION_KEY_FD


def _control_plane_activation_planning_shape(value, *, activation_target):
    """V7 public data only; root signatures and freshness belong to admission."""
    if value is None:
        return
    if (activation_target != CONTROL_PLANE_ACTIVATION_KEY_FD or type(value) is not dict
            or set(value) != {"schema", "plannerBootstrap", "plannerEndpoint"}
            or value["schema"] != CONTROL_PLANE_ACTIVATION_PLANNING_SCHEMA):
        raise RuntimeError("activation planning requires its explicit dedicated caller lane")
    record = value["plannerBootstrap"]
    if type(record) is not dict or set(record) != {"base64Url", "byteCount"}:
        raise RuntimeError("activation planning bootstrap original shape differs")
    encoded, size = record["base64Url"], record["byteCount"]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    if (type(size) is not int or not 2 <= size <= CONTROL_PLANE_ENROLLMENT_BOOTSTRAP_MAX_BYTES
            or type(encoded) is not str or len(encoded) != (4 * size + 2) // 3
            or any(character not in alphabet for character in encoded)):
        raise RuntimeError("activation planning bootstrap encoding exceeds its original bound")
    unused = 4 if size % 3 == 1 else 2 if size % 3 == 2 else 0
    if unused and alphabet.index(encoded[-1]) & ((1 << unused) - 1):
        raise RuntimeError("activation planning bootstrap encoding is not canonical")
    endpoint = value["plannerEndpoint"]
    if (type(endpoint) is not dict
            or set(endpoint) != {"socketPath", "requestTimeoutSeconds", "listenerUid", "listenerGid"}
            or endpoint["socketPath"] != CONTROL_PLANE_ACTIVATION_PLANNER_SOCKET
            or type(endpoint["requestTimeoutSeconds"]) is not int
            or not 1 <= endpoint["requestTimeoutSeconds"] <= 30
            or any(type(endpoint[name]) is not int or endpoint[name] != 0
                for name in ("listenerUid", "listenerGid"))):
        raise RuntimeError("activation planning endpoint differs from its fixed contract")


def _control_plane_consume_key_slot(value, *, issuer_descriptor, bootstrap_descriptor,
        activation_value, planning_value):
    """V8 metadata only; no repository imports or enrollment authority."""
    if issuer_descriptor == CONTROL_PLANE_CONSUME_KEY_FD or bootstrap_descriptor == CONTROL_PLANE_CONSUME_KEY_FD:
        raise RuntimeError("v8 reserves the consume key slot independently of enablement")
    if value is None:
        return None
    if (type(value) is not dict or type(value.get("schema")) is not str
            or value["schema"] not in (CONTROL_PLANE_CONSUME_SCHEMA, CONTROL_PLANE_CONSUME_V2_SCHEMA,
                CONTROL_PLANE_CONSUME_V3_SCHEMA, CONTROL_PLANE_CONSUME_V4_SCHEMA)):
        raise RuntimeError("consume caller delivery schema differs")
    fields = {"schema", "callerPrivateKeyFd", "grantEnrollment", "authorizationEnrollment", "authorizerEndpoint"}
    if value["schema"] in (CONTROL_PLANE_CONSUME_V2_SCHEMA, CONTROL_PLANE_CONSUME_V3_SCHEMA, CONTROL_PLANE_CONSUME_V4_SCHEMA):
        fields |= {"reservationEndpoint", "reservationPredecessor", "sqlEndpoint"}
    if value["schema"] in (CONTROL_PLANE_CONSUME_V3_SCHEMA, CONTROL_PLANE_CONSUME_V4_SCHEMA):
        fields.add("completionEndpoint")
    if (set(value) != fields or type(value["callerPrivateKeyFd"]) is not int
            or value["callerPrivateKeyFd"] != CONTROL_PLANE_CONSUME_KEY_FD
            or type(activation_value) is not dict
            or activation_value.get("schema") != CONTROL_PLANE_ACTIVATION_V4_SCHEMA
            or planning_value is None):
        raise RuntimeError("consume caller requires its fixed slot and actual activation v4/planning configuration")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    for name in ("grantEnrollment", "authorizationEnrollment"):
        original = value[name]
        if type(original) is not dict or set(original) != {"base64Url", "byteCount"}:
            raise RuntimeError("consume caller enrollment delivery shape is not closed")
        encoded, size = original["base64Url"], original["byteCount"]
        if (type(size) is not int or not 2 <= size <= 16 * 1024 or type(encoded) is not str
                or len(encoded) != (4 * size + 2) // 3
                or any(character not in alphabet for character in encoded)):
            raise RuntimeError("consume caller enrollment original exceeds its delivery bound")
        unused = 4 if size % 3 == 1 else 2 if size % 3 == 2 else 0
        if unused and alphabet.index(encoded[-1]) & ((1 << unused) - 1):
            raise RuntimeError("consume caller enrollment encoding is not canonical")
    endpoints = (("authorizerEndpoint", CONTROL_PLANE_CONSUME_SOCKET),)
    if value["schema"] in (CONTROL_PLANE_CONSUME_V2_SCHEMA, CONTROL_PLANE_CONSUME_V3_SCHEMA, CONTROL_PLANE_CONSUME_V4_SCHEMA):
        endpoints += (("reservationEndpoint", CONTROL_PLANE_CONSUME_RESERVATION_SOCKET),
            ("sqlEndpoint", CONTROL_PLANE_CONSUME_SQL_SOCKET))
        predecessor = value["reservationPredecessor"]
        if (type(predecessor) is not dict or set(predecessor) != {"sequence", "headDigest", "nextFence"}
                or type(predecessor["sequence"]) is not int or not 0 <= predecessor["sequence"] <= 1022
                or type(predecessor["nextFence"]) is not int or not 1 <= predecessor["nextFence"] <= 2**63 - 1
                or predecessor["sequence"] == 0 and predecessor["nextFence"] != 1):
            raise RuntimeError("consume independent predecessor delivery shape differs")
        head = predecessor["headDigest"]
        if (type(head) is not str or len(head) != 71 or not head.startswith("sha256:")
                or any(character not in "0123456789abcdef" for character in head[7:])):
            raise RuntimeError("consume predecessor head is not canonical SHA256")
    if value["schema"] in (CONTROL_PLANE_CONSUME_V3_SCHEMA, CONTROL_PLANE_CONSUME_V4_SCHEMA):
        endpoints += (("completionEndpoint", CONTROL_PLANE_CONSUME_COMPLETION_SOCKET),)
    for name, path in endpoints:
        endpoint = value[name]
        if (type(endpoint) is not dict
                or set(endpoint) != {"socketPath", "requestTimeoutSeconds", "listenerUid", "listenerGid"}
                or endpoint["socketPath"] != path
                or type(endpoint["requestTimeoutSeconds"]) is not int
                or not 1 <= endpoint["requestTimeoutSeconds"] <= 30
                or any(type(endpoint[field]) is not int or endpoint[field] != 0
                    for field in ("listenerUid", "listenerGid"))):
            raise RuntimeError("consume endpoint differs from its fixed delivery contract")
    return CONTROL_PLANE_CONSUME_KEY_FD


def _control_plane_intent_key_slot(value, *, issuer_descriptor, bootstrap_descriptor, consume_value):
    """Closed v9 data only; genuine enrollment and key admission belong to startup."""
    if issuer_descriptor == CONTROL_PLANE_INTENT_KEY_FD or bootstrap_descriptor == CONTROL_PLANE_INTENT_KEY_FD:
        raise RuntimeError("v9 reserves intent FD207 even when disabled")
    if value is None:
        return None
    if (type(value) is not dict or set(value) != {"schema", "callerPrivateKeyFd", "intentEnrollment", "expectedScope"}
            or value["schema"] != CONTROL_PLANE_INTENT_SCHEMA
            or type(value["callerPrivateKeyFd"]) is not int or value["callerPrivateKeyFd"] != CONTROL_PLANE_INTENT_KEY_FD
            or type(consume_value) is not dict or consume_value.get("schema") != CONTROL_PLANE_CONSUME_V4_SCHEMA):
        raise RuntimeError("release intent requires its closed configuration, dedicated FD and consume v4")
    original = value["intentEnrollment"]
    if type(original) is not dict or set(original) != {"base64Url", "byteCount"}:
        raise RuntimeError("intent enrollment original is not closed")
    encoded, size = original["base64Url"], original["byteCount"]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    if (type(size) is not int or not 2 <= size <= 16 * 1024 or type(encoded) is not str
            or len(encoded) != (4 * size + 2) // 3 or any(character not in alphabet for character in encoded)):
        raise RuntimeError("intent enrollment exceeds its original bound")
    unused = 4 if size % 3 == 1 else 2 if size % 3 == 2 else 0
    if unused and alphabet.index(encoded[-1]) & ((1 << unused) - 1):
        raise RuntimeError("intent enrollment encoding is not canonical")
    scope = value["expectedScope"]
    if type(scope) is not dict or set(scope) != {"configurationDigest", "databaseId", "generationDigest",
            "runtimeClosureDigest", "callerId", "receiverIdentity"}:
        raise RuntimeError("intent independent scope is not closed")
    identity = scope["receiverIdentity"]
    if type(identity) is not dict or set(identity) != {
            "sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest"}:
        raise RuntimeError("intent receiver identity is not closed")
    for digest in (*(scope[name] for name in ("configurationDigest", "generationDigest", "runtimeClosureDigest")),
            *identity.values()):
        if (type(digest) is not str or len(digest) != 71 or not digest.startswith("sha256:")
                or any(character not in "0123456789abcdef" for character in digest[7:])):
            raise RuntimeError("intent scope digest is not canonical")
    start = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    for name in ("databaseId", "callerId"):
        token = scope[name]
        if (type(token) is not str or not 1 <= len(token) <= 128 or token[0] not in start
                or any(character not in start + "._:-" for character in token)):
            raise RuntimeError("intent scope token is not canonical")
    return CONTROL_PLANE_INTENT_KEY_FD


def _control_plane_proof_public_shape(value, *, intent_value):
    """Closed v10 public data only; no new key slot or admission shortcut."""
    if value is None:
        return
    if (type(value) is not dict or set(value) != {"schema", "proofEnrollment", "expectedScope", "endpoint"}
            or value["schema"] != CONTROL_PLANE_PROOF_SCHEMA or type(intent_value) is not dict):
        raise RuntimeError("release proof requires its closed public configuration and enabled intent")
    original = value["proofEnrollment"]
    if type(original) is not dict or set(original) != {"base64Url", "byteCount"}:
        raise RuntimeError("proof enrollment original is not closed")
    encoded, size = original["base64Url"], original["byteCount"]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    if (type(size) is not int or not 2 <= size <= 16 * 1024 or type(encoded) is not str
            or len(encoded) != (4 * size + 2) // 3 or any(character not in alphabet for character in encoded)):
        raise RuntimeError("proof enrollment exceeds its original bound")
    unused = 4 if size % 3 == 1 else 2 if size % 3 == 2 else 0
    if unused and alphabet.index(encoded[-1]) & ((1 << unused) - 1):
        raise RuntimeError("proof enrollment encoding is not canonical")
    scope = value["expectedScope"]
    if type(scope) is not dict or set(scope) != {"configurationDigest", "databaseId", "generationDigest",
            "runtimeClosureDigest", "producerId", "producerIdentity", "receiverIdentity"}:
        raise RuntimeError("proof independent scope is not closed")
    for name in ("producerIdentity", "receiverIdentity"):
        identity = scope[name]
        if type(identity) is not dict or set(identity) != {
                "sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest"}:
            raise RuntimeError("proof identity is not closed")
        for digest in identity.values():
            if (type(digest) is not str or len(digest) != 71 or not digest.startswith("sha256:")
                    or any(character not in "0123456789abcdef" for character in digest[7:])):
                raise RuntimeError("proof identity digest is not canonical")
    for name in ("configurationDigest", "generationDigest", "runtimeClosureDigest"):
        digest = scope[name]
        if (type(digest) is not str or len(digest) != 71 or not digest.startswith("sha256:")
                or any(character not in "0123456789abcdef" for character in digest[7:])):
            raise RuntimeError("proof scope digest is not canonical")
    start = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    for name in ("databaseId", "producerId"):
        token = scope[name]
        if (type(token) is not str or not 1 <= len(token) <= 128 or token[0] not in start
                or any(character not in start + "._:-" for character in token)):
            raise RuntimeError("proof scope token is not canonical")
    for name in ("configurationDigest", "databaseId", "generationDigest", "runtimeClosureDigest", "receiverIdentity"):
        if scope[name] != intent_value["expectedScope"][name]:
            raise RuntimeError("proof scope differs from the shared intent configuration")
    endpoint = value["endpoint"]
    if (type(endpoint) is not dict
            or set(endpoint) != {"socketPath", "requestTimeoutSeconds", "listenerUid", "listenerGid"}
            or endpoint["socketPath"] != CONTROL_PLANE_PROOF_SOCKET
            or type(endpoint["requestTimeoutSeconds"]) is not int
            or not 1 <= endpoint["requestTimeoutSeconds"] <= 30
            or any(type(endpoint[name]) is not int or endpoint[name] != 0
                for name in ("listenerUid", "listenerGid"))):
        raise RuntimeError("proof endpoint differs from its fixed delivery contract")


def _control_plane_handoff_public_shape(value, *, intent_value, proof_value):
    """Closed v11 static public pins only; no new FD or crypto admission."""
    if value is None:
        return
    if (type(value) is not dict or set(value) != {"schema", "clientId", "clientIdentity", "endpoint"}
            or value["schema"] != CONTROL_PLANE_HANDOFF_SCHEMA
            or type(intent_value) is not dict or type(proof_value) is not dict):
        raise RuntimeError("release handoff requires closed pins and enabled intent/proof")
    token = value["clientId"]
    start = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    if (type(token) is not str or not 1 <= len(token) <= 128 or token[0] not in start
            or any(character not in start + "._:-" for character in token)):
        raise RuntimeError("release handoff client ID is not canonical")
    identity = value["clientIdentity"]
    if type(identity) is not dict or set(identity) != {
            "sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest"}:
        raise RuntimeError("release handoff identity is not closed")
    for digest in identity.values():
        if (type(digest) is not str or len(digest) != 71 or not digest.startswith("sha256:")
                or any(character not in "0123456789abcdef" for character in digest[7:])):
            raise RuntimeError("release handoff identity digest is not canonical")
    endpoint = value["endpoint"]
    if (type(endpoint) is not dict or set(endpoint) != {"path", "timeoutSeconds", "peerUid", "peerGid"}
            or endpoint["path"] != CONTROL_PLANE_HANDOFF_SOCKET
            or type(endpoint["timeoutSeconds"]) is not int or not 1 <= endpoint["timeoutSeconds"] <= 30
            or any(type(endpoint[name]) is not int or endpoint[name] != 0 for name in ("peerUid", "peerGid"))):
        raise RuntimeError("release handoff endpoint differs from the fixed live worker")


def _control_plane_grant_acquisition_public_shape(value, *, handoff_value):
    """Closed v12 public endpoint only; no additional purpose-key slot."""
    if value is None:
        return
    if (type(value) is not dict or set(value) != {"schema", "endpoint"}
            or value["schema"] != CONTROL_PLANE_GRANT_ACQUISITION_SCHEMA
            or type(handoff_value) is not dict):
        raise RuntimeError("release grant acquisition requires closed endpoint and enabled handoff")
    endpoint = value["endpoint"]
    if (type(endpoint) is not dict or set(endpoint) != {"path", "timeoutSeconds", "peerUid", "peerGid"}
            or type(endpoint["path"]) is not str or endpoint["path"] != CONTROL_PLANE_GRANT_ACQUISITION_SOCKET
            or type(endpoint["timeoutSeconds"]) is not int or not 1 <= endpoint["timeoutSeconds"] <= 30
            or any(type(endpoint[name]) is not int or endpoint[name] != 0 for name in ("peerUid", "peerGid"))):
        raise RuntimeError("release grant acquisition endpoint differs from the fixed issuer")


def _control_plane_consume_input_acquisition_public_shape(value, *, planning_value, activation_value,
        allow_history=False):
    """Closed v13 public policy/endpoint data; no new FD or crypto authority."""
    if value is None:
        return
    if (type(value) is not dict or set(value) != {"schema", "endpoint", "issuerPolicy"}
            or value["schema"] not in ((CONTROL_PLANE_CONSUME_INPUT_ACQUISITION_SCHEMA,
                CONTROL_PLANE_CONSUME_INPUT_ACQUISITION_V2_SCHEMA) if allow_history else
                (CONTROL_PLANE_CONSUME_INPUT_ACQUISITION_SCHEMA,))
            or type(planning_value) is not dict or type(activation_value) is not dict
            or activation_value.get("schema") != CONTROL_PLANE_ACTIVATION_V4_SCHEMA):
        raise RuntimeError("consume input acquisition requires closed policy and enabled planning/execution")
    endpoint = value["endpoint"]
    if (type(endpoint) is not dict or set(endpoint) != {"path", "timeoutSeconds", "peerUid", "peerGid"}
            or type(endpoint["path"]) is not str or endpoint["path"] != CONTROL_PLANE_CONSUME_INPUT_ACQUISITION_SOCKET
            or type(endpoint["timeoutSeconds"]) is not int or not 1 <= endpoint["timeoutSeconds"] <= 30
            or any(type(endpoint[name]) is not int or endpoint[name] != 0 for name in ("peerUid", "peerGid"))):
        raise RuntimeError("consume input acquisition endpoint differs from the fixed issuer")
    original = value["issuerPolicy"]
    if type(original) is not dict or set(original) != {"base64Url", "byteCount"}:
        raise RuntimeError("consume input issuer policy original is not closed")
    encoded, size = original["base64Url"], original["byteCount"]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    maximum = (6 * 1024 * 1024 if value["schema"] == CONTROL_PLANE_CONSUME_INPUT_ACQUISITION_V2_SCHEMA
        else 64 * 1024)
    if (type(size) is not int or not 2 <= size <= maximum or type(encoded) is not str
            or len(encoded) != (4 * size + 2) // 3 or any(character not in alphabet for character in encoded)):
        raise RuntimeError("consume input issuer policy exceeds its original bound")
    unused = 4 if size % 3 == 1 else 2 if size % 3 == 2 else 0
    if unused and alphabet.index(encoded[-1]) & ((1 << unused) - 1):
        raise RuntimeError("consume input issuer policy encoding is not canonical")


def _control_plane_proof_acquisition_public_shape(value, *, intent_value, proof_value):
    """Closed v14 public policy/endpoint; no packet or additional key slot."""
    if value is None:
        return
    if (type(value) is not dict or set(value) != {"schema", "endpoint", "issuerPolicy"}
            or value["schema"] != CONTROL_PLANE_PROOF_ACQUISITION_SCHEMA
            or type(intent_value) is not dict or type(proof_value) is not dict):
        raise RuntimeError("proof acquisition requires closed policy and enabled intent/proof")
    endpoint = value["endpoint"]
    if (type(endpoint) is not dict or set(endpoint) != {"path", "timeoutSeconds", "peerUid", "peerGid"}
            or type(endpoint["path"]) is not str or endpoint["path"] != CONTROL_PLANE_PROOF_ACQUISITION_SOCKET
            or type(endpoint["timeoutSeconds"]) is not int or not 1 <= endpoint["timeoutSeconds"] <= 30
            or any(type(endpoint[name]) is not int or endpoint[name] != 0 for name in ("peerUid", "peerGid"))):
        raise RuntimeError("proof acquisition endpoint differs from the fixed issuer")
    original = value["issuerPolicy"]
    if type(original) is not dict or set(original) != {"base64Url", "byteCount"}:
        raise RuntimeError("proof issuer policy original is not closed")
    encoded, size = original["base64Url"], original["byteCount"]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    if (type(size) is not int or not 2 <= size <= 64 * 1024 or type(encoded) is not str
            or len(encoded) != (4 * size + 2) // 3 or any(character not in alphabet for character in encoded)):
        raise RuntimeError("proof issuer policy exceeds its original bound")
    unused = 4 if size % 3 == 1 else 2 if size % 3 == 2 else 0
    if unused and alphabet.index(encoded[-1]) & ((1 << unused) - 1):
        raise RuntimeError("proof issuer policy encoding is not canonical")


def _control_plane_recovery_grant_acquisition_public_shape(value, *, intent_value, proof_value):
    """Closed v15 original wrappers only; no key slot or recovery authority."""
    if value is None:
        return
    fields = {"schema", "endpoint", "issuerPolicy", "releaseCustody", "proofEnrollment", "intentEnrollment"}
    if (type(value) is not dict or set(value) != fields
            or value["schema"] != CONTROL_PLANE_RECOVERY_GRANT_ACQUISITION_SCHEMA
            or type(intent_value) is not dict or type(proof_value) is not dict):
        raise RuntimeError("recovery acquisition requires closed originals and enabled intent/proof")
    endpoint = value["endpoint"]
    if (type(endpoint) is not dict or set(endpoint) != {"path", "timeoutSeconds", "peerUid", "peerGid"}
            or type(endpoint["path"]) is not str or endpoint["path"] != CONTROL_PLANE_RECOVERY_GRANT_ACQUISITION_SOCKET
            or type(endpoint["timeoutSeconds"]) is not int or not 1 <= endpoint["timeoutSeconds"] <= 30
            or any(type(endpoint[name]) is not int or endpoint[name] != 0 for name in ("peerUid", "peerGid"))):
        raise RuntimeError("recovery acquisition endpoint differs from its fixed issuer")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    for name, maximum in (("issuerPolicy", 64 * 1024), ("releaseCustody", 8 * 1024 * 1024),
            ("proofEnrollment", 16 * 1024), ("intentEnrollment", 16 * 1024)):
        original = value[name]
        if type(original) is not dict or set(original) != {"base64Url", "byteCount"}:
            raise RuntimeError("recovery acquisition original wrapper is not closed")
        encoded, size = original["base64Url"], original["byteCount"]
        if (type(size) is not int or not 2 <= size <= maximum or type(encoded) is not str
                or len(encoded) != (4 * size + 2) // 3 or any(character not in alphabet for character in encoded)):
            raise RuntimeError("recovery acquisition original exceeds its fixed bound")
        unused = 4 if size % 3 == 1 else 2 if size % 3 == 2 else 0
        if unused and alphabet.index(encoded[-1]) & ((1 << unused) - 1):
            raise RuntimeError("recovery acquisition original encoding is not canonical")


def _control_plane_completion_recovery_public_shape(value, *, activation_value, consume_value):
    """Closed v16 public pins only; no new key slot or completion permission."""
    if value is None:
        return
    if (type(value) is not dict or set(value) != {"schema", "activation", "consume"}
            or value["schema"] != CONTROL_PLANE_COMPLETION_RECOVERY_SCHEMA
            or value["activation"] is None and value["consume"] is None):
        raise RuntimeError("completion recovery requires explicit closed role configuration")
    for name, schema, path, configured, versions, predecessor_name in (
            ("activation", CONTROL_PLANE_ACTIVATION_COMPLETION_RECOVERY_SCHEMA,
                CONTROL_PLANE_ACTIVATION_COMPLETION_SOCKET, activation_value,
                (CONTROL_PLANE_ACTIVATION_V3_SCHEMA, CONTROL_PLANE_ACTIVATION_V4_SCHEMA), "statePredecessor"),
            ("consume", CONTROL_PLANE_CONSUME_COMPLETION_RECOVERY_SCHEMA,
                CONTROL_PLANE_CONSUME_COMPLETION_SOCKET, consume_value,
                (CONTROL_PLANE_CONSUME_V4_SCHEMA,), "reservationPredecessor")):
        lane = value[name]
        if lane is None:
            continue
        if (type(lane) is not dict
                or set(lane) != {"schema", "endpoint", "packetDigest", "authorizationDigest", "currentPending"}
                or lane["schema"] != schema or type(configured) is not dict
                or configured.get("schema") not in versions):
            raise RuntimeError("completion recovery role lacks its explicit execution profile")
        endpoint = lane["endpoint"]
        if (type(endpoint) is not dict
                or set(endpoint) != {"socketPath", "requestTimeoutSeconds", "listenerUid", "listenerGid"}
                or type(endpoint["socketPath"]) is not str or endpoint["socketPath"] != path
                or type(endpoint["requestTimeoutSeconds"]) is not int
                or not 1 <= endpoint["requestTimeoutSeconds"] <= 30
                or any(type(endpoint[key]) is not int or endpoint[key] != 0
                    for key in ("listenerUid", "listenerGid"))
                or endpoint != configured["completionEndpoint"]):
            raise RuntimeError("completion recovery endpoint differs from its actual parent")
        pending, predecessor = lane["currentPending"], configured[predecessor_name]
        if (type(pending) is not dict or set(pending) != {"sequence", "headDigest", "fence"}
                or type(pending["sequence"]) is not int or not 1 <= pending["sequence"] <= 1024
                or type(pending["fence"]) is not int or not 1 <= pending["fence"] <= 2**63 - 1
                or pending["sequence"] != predecessor["sequence"] + 1
                or pending["fence"] != predecessor["nextFence"]):
            raise RuntimeError("completion recovery pending scope differs from its independent predecessor")
        for pin in (lane["packetDigest"], lane["authorizationDigest"], pending["headDigest"]):
            if (type(pin) is not str or len(pin) != 71 or not pin.startswith("sha256:")
                    or any(character not in "0123456789abcdef" for character in pin[7:])):
                raise RuntimeError("completion recovery original pin is not canonical SHA256")


def _control_plane_history_public_shape(payload, *, registration, finalization, activation, v20, v22=False):
    """Data-only history fields never contribute a key or purpose descriptor.

    The bounded sealed parent reaches genuine child signature/archive admission
    unchanged. This projection checks only the outer data namespaces; it must
    not interpret historical key-slot numbers as live startup capabilities.
    """
    inventories = (
        (registration, "registrationHistory", ("serverware.controlPlaneRegistrationHistory/v1",),
            {"schema", "currentEntry", "archive", "registrations"}),
        (finalization, "finalizationHistory", ("serverware.controlPlaneRegistrationFinalizationHistory/v1",),
            {"schema", "finalizations"}),
        (activation, "activationHistory", (("serverware.controlPlaneOidcSessionActivationHistory/v1",
            "serverware.controlPlaneOidcSessionActivationHistory/v2",
            "serverware.controlPlaneOidcSessionActivationHistory/v3") if v22 else
            ("serverware.controlPlaneOidcSessionActivationHistory/v1",
            "serverware.controlPlaneOidcSessionActivationHistory/v2") if v20 else
            ("serverware.controlPlaneOidcSessionActivationHistory/v1",)), {"schema", "activations"}))
    for enabled, name, schemas, fields in inventories:
        if not enabled:
            continue
        value = payload[name]
        if value is not None and (type(value) is not dict or set(value) != fields
                or type(value["schema"]) is not str or value["schema"] not in schemas):
            raise RuntimeError("control-plane historical data namespace is not closed")
    if finalization and payload["finalizationHistory"] is not None and payload["registrationHistory"] is None:
        raise RuntimeError("finalization history requires the shared registration archive")
    if activation and payload["activationHistory"] is not None and (
            payload["registrationHistory"] is None or payload["finalizationHistory"] is None):
        raise RuntimeError("activation history requires both shared historical inventories")


def _control_plane_public_revocation_key_slot(value, *, issuer_descriptor, bootstrap_descriptor):
    """Bound delivery shape only; actual signed admission stays in the child."""
    if CONTROL_PLANE_REVOCATION_KEY_FD in (issuer_descriptor, bootstrap_descriptor):
        raise RuntimeError("v23 reserves public revocation FD208 even when disabled")
    if value is None:
        return None
    if (type(value) is not dict or set(value) != {"schema", "callerPrivateKeyFd",
            "currentRootEnrollment", "grantEnrollment", "authorizationEnrollment", "stateEndpoint",
            "mutationPolicy"}
            or value["schema"] != "serverware.controlPlanePublicWebAuthnRevocation/v1"
            or type(value["callerPrivateKeyFd"]) is not int or value["callerPrivateKeyFd"] != 208):
        raise RuntimeError("public revocation delivery scope is not closed")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    for name, maximum in (("currentRootEnrollment", 128 * 1024),
            ("grantEnrollment", 16 * 1024), ("authorizationEnrollment", 16 * 1024)):
        raw = value[name]
        if type(raw) is not dict or set(raw) != {"base64Url", "byteCount"}:
            raise RuntimeError("public revocation enrollment original is not closed")
        encoded, size = raw["base64Url"], raw["byteCount"]
        if (type(size) is not int or not 2 <= size <= maximum or type(encoded) is not str
                or len(encoded) != (4 * size + 2) // 3 or any(c not in alphabet for c in encoded)):
            raise RuntimeError("public revocation enrollment exceeds its fixed bound")
        unused = 4 if size % 3 == 1 else 2 if size % 3 == 2 else 0
        if unused and alphabet.index(encoded[-1]) & ((1 << unused) - 1):
            raise RuntimeError("public revocation enrollment encoding is not canonical")
    endpoint = value["stateEndpoint"]
    if (type(endpoint) is not dict or set(endpoint) != {"socketPath", "requestTimeoutSeconds",
            "serviceUid", "serviceGid", "listenerUid", "listenerGid"}
            or endpoint["socketPath"] != "/run/serverware/current-root/state.sock"
            or type(endpoint["requestTimeoutSeconds"]) is not int
            or not 1 <= endpoint["requestTimeoutSeconds"] <= 30
            or any(type(endpoint[name]) is not int or endpoint[name] != expected
                for name, expected in (("serviceUid", 65516), ("serviceGid", 65516),
                    ("listenerUid", 0), ("listenerGid", 0)))):
        raise RuntimeError("public revocation state endpoint is not fixed")
    policy = value["mutationPolicy"]
    if (type(policy) is not dict or set(policy) != {"mfaRequired", "twoPersonRequired", "credentialPolicy"}
            or any(type(policy[name]) is not bool for name in ("mfaRequired", "twoPersonRequired"))):
        raise RuntimeError("public revocation mutation policy is not closed")
    credential = policy["credentialPolicy"]
    if (type(credential) is not dict or credential.get("userVerification") != "required"
            or not set(credential) <= {"userVerification", "allowedAuthenticatorClasses", "requireHardwareAttestation"}
            or "requireHardwareAttestation" in credential and type(credential["requireHardwareAttestation"]) is not bool):
        raise RuntimeError("public revocation credential policy differs")
    if "allowedAuthenticatorClasses" in credential:
        classes = credential["allowedAuthenticatorClasses"]
        if (type(classes) is not list or not 1 <= len(classes) <= 32
                or any(type(item) is not str or not 1 <= len(item) <= 128 for item in classes)
                or len(set(classes)) != len(classes)):
            raise RuntimeError("public revocation authenticator classes are invalid")
    return CONTROL_PLANE_REVOCATION_KEY_FD


def _control_plane_enrollment_slot_projection(descriptor: int) -> tuple:
    """Project closed v2-v23 slots; child admission alone supplies authority."""
    if type(descriptor) is not int or not 3 <= descriptor <= 1023:
        raise RuntimeError("control-plane enrollment bootstrap descriptor is outside its range")
    metadata = os.fstat(descriptor)
    seals = (fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK
        | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_nlink != 0
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not 2 <= metadata.st_size <= CONTROL_PLANE_ENROLLMENT_BOOTSTRAP_MAX_BYTES
            or fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & seals != seals):
        raise RuntimeError("control-plane enrollment bootstrap is not bounded root-owned sealed material")
    original = _read_exact_source(descriptor, metadata.st_size)
    if _material_identity(os.fstat(descriptor)) != _material_identity(metadata):
        raise RuntimeError("control-plane enrollment bootstrap changed while reading")
    try:
        value = json.loads(original)
        if (type(value) is not dict or set(value) != {"schema", "payload", "signatureBase64Url"}
                or value["schema"] not in (CONTROL_PLANE_ENROLLMENT_BOOTSTRAP_SCHEMA,
                    CONTROL_PLANE_ENROLLMENT_V3_BOOTSTRAP_SCHEMA,
                    CONTROL_PLANE_ENROLLMENT_V4_BOOTSTRAP_SCHEMA,
                    CONTROL_PLANE_ENROLLMENT_V5_BOOTSTRAP_SCHEMA,
                    CONTROL_PLANE_ENROLLMENT_V6_BOOTSTRAP_SCHEMA,
                    CONTROL_PLANE_ENROLLMENT_V7_BOOTSTRAP_SCHEMA,
                    CONTROL_PLANE_ENROLLMENT_V8_BOOTSTRAP_SCHEMA,
                    CONTROL_PLANE_ENROLLMENT_V9_BOOTSTRAP_SCHEMA,
                    CONTROL_PLANE_ENROLLMENT_V10_BOOTSTRAP_SCHEMA,
                    CONTROL_PLANE_ENROLLMENT_V11_BOOTSTRAP_SCHEMA,
                    CONTROL_PLANE_ENROLLMENT_V12_BOOTSTRAP_SCHEMA,
                    CONTROL_PLANE_ENROLLMENT_V13_BOOTSTRAP_SCHEMA,
                    CONTROL_PLANE_ENROLLMENT_V14_BOOTSTRAP_SCHEMA,
                    CONTROL_PLANE_ENROLLMENT_V15_BOOTSTRAP_SCHEMA,
                    CONTROL_PLANE_ENROLLMENT_V16_BOOTSTRAP_SCHEMA,
                    CONTROL_PLANE_ENROLLMENT_V17_BOOTSTRAP_SCHEMA,
                    CONTROL_PLANE_ENROLLMENT_V18_BOOTSTRAP_SCHEMA,
                    CONTROL_PLANE_ENROLLMENT_V19_BOOTSTRAP_SCHEMA,
                    CONTROL_PLANE_ENROLLMENT_V20_BOOTSTRAP_SCHEMA,
                    CONTROL_PLANE_ENROLLMENT_V21_BOOTSTRAP_SCHEMA,
                    CONTROL_PLANE_ENROLLMENT_V22_BOOTSTRAP_SCHEMA,
                    CONTROL_PLANE_ENROLLMENT_V23_BOOTSTRAP_SCHEMA)):
            raise RuntimeError("control-plane enrollment bootstrap envelope is not closed")
        is_v3 = value["schema"] == CONTROL_PLANE_ENROLLMENT_V3_BOOTSTRAP_SCHEMA
        is_v4 = value["schema"] == CONTROL_PLANE_ENROLLMENT_V4_BOOTSTRAP_SCHEMA
        is_v5 = value["schema"] == CONTROL_PLANE_ENROLLMENT_V5_BOOTSTRAP_SCHEMA
        is_v6 = value["schema"] == CONTROL_PLANE_ENROLLMENT_V6_BOOTSTRAP_SCHEMA
        is_v7 = value["schema"] == CONTROL_PLANE_ENROLLMENT_V7_BOOTSTRAP_SCHEMA
        is_v8 = value["schema"] == CONTROL_PLANE_ENROLLMENT_V8_BOOTSTRAP_SCHEMA
        is_v9 = value["schema"] == CONTROL_PLANE_ENROLLMENT_V9_BOOTSTRAP_SCHEMA
        is_v10 = value["schema"] == CONTROL_PLANE_ENROLLMENT_V10_BOOTSTRAP_SCHEMA
        is_v11 = value["schema"] == CONTROL_PLANE_ENROLLMENT_V11_BOOTSTRAP_SCHEMA
        is_v12 = value["schema"] == CONTROL_PLANE_ENROLLMENT_V12_BOOTSTRAP_SCHEMA
        is_v23 = value["schema"] == CONTROL_PLANE_ENROLLMENT_V23_BOOTSTRAP_SCHEMA
        is_v22 = value["schema"] == CONTROL_PLANE_ENROLLMENT_V22_BOOTSTRAP_SCHEMA or is_v23
        is_v21 = value["schema"] == CONTROL_PLANE_ENROLLMENT_V21_BOOTSTRAP_SCHEMA or is_v22
        is_v20 = value["schema"] == CONTROL_PLANE_ENROLLMENT_V20_BOOTSTRAP_SCHEMA or is_v21
        is_v19 = value["schema"] == CONTROL_PLANE_ENROLLMENT_V19_BOOTSTRAP_SCHEMA or is_v20
        is_v18 = value["schema"] == CONTROL_PLANE_ENROLLMENT_V18_BOOTSTRAP_SCHEMA or is_v19
        is_v17 = value["schema"] == CONTROL_PLANE_ENROLLMENT_V17_BOOTSTRAP_SCHEMA or is_v18
        is_v16 = value["schema"] == CONTROL_PLANE_ENROLLMENT_V16_BOOTSTRAP_SCHEMA or is_v17
        is_v15 = value["schema"] == CONTROL_PLANE_ENROLLMENT_V15_BOOTSTRAP_SCHEMA or is_v16
        is_v14 = value["schema"] == CONTROL_PLANE_ENROLLMENT_V14_BOOTSTRAP_SCHEMA or is_v15
        # v14-v22 preserve the exact v13 prefix and all ten purpose slots.
        # v17-v22 historical inventories and bridge policies add no FDs.
        is_v13 = value["schema"] == CONTROL_PLANE_ENROLLMENT_V13_BOOTSTRAP_SCHEMA or is_v14
        payload_fields = {"schema", "sourceRevision", "configurationDigest", "configurationPayload",
            "generation", "runtimeRoleIdentities", "issuerPrivateKeyFd", "signerEndpoint"}
        if is_v3 or is_v4 or is_v5 or is_v6 or is_v7 or is_v8 or is_v9 or is_v10 or is_v11 or is_v12 or is_v13:
            payload_fields.add("registrationExecution")
        if is_v4 or is_v5 or is_v6 or is_v7 or is_v8 or is_v9 or is_v10 or is_v11 or is_v12 or is_v13:
            payload_fields.add("registrationFinalization")
        if is_v5 or is_v6 or is_v7 or is_v8 or is_v9 or is_v10 or is_v11 or is_v12 or is_v13:
            payload_fields.add("oidcSessionActivationRelease")
        if is_v6 or is_v7 or is_v8 or is_v9 or is_v10 or is_v11 or is_v12 or is_v13:
            payload_fields.add("oidcSessionActivationExecution")
        if is_v7 or is_v8 or is_v9 or is_v10 or is_v11 or is_v12 or is_v13:
            payload_fields.add("oidcSessionActivationPlanning")
        if is_v8 or is_v9 or is_v10 or is_v11 or is_v12 or is_v13:
            payload_fields.add("oidcSessionActivationConsumeExecution")
        if is_v9 or is_v10 or is_v11 or is_v12 or is_v13:
            payload_fields.add("oidcSessionActivationReleaseIntent")
        if is_v10 or is_v11 or is_v12 or is_v13:
            payload_fields.add("oidcSessionActivationReleaseProof")
        if is_v11 or is_v12 or is_v13:
            payload_fields.add("oidcSessionActivationReleaseHandoff")
        if is_v12 or is_v13:
            payload_fields.add("oidcSessionActivationReleaseGrantAcquisition")
        if is_v13:
            payload_fields.add("oidcSessionActivationConsumeInputAcquisition")
        if is_v14:
            payload_fields.add("oidcSessionActivationReleaseProofAcquisition")
        if is_v15:
            payload_fields.add("oidcSessionActivationReleaseRecoveryGrantAcquisition")
        if is_v16:
            payload_fields.add("oidcSessionActivationCompletionRecovery")
        if is_v17:
            payload_fields.add("registrationHistory")
        if is_v18:
            payload_fields.add("finalizationHistory")
        if is_v19:
            payload_fields.add("activationHistory")
        if is_v21:
            payload_fields.add("historicalConsumeInputAcquisition")
        if is_v23:
            payload_fields.add("publicWebAuthnRevocation")
        payload = value["payload"]
        if (type(payload) is not dict or set(payload) != payload_fields
                or payload["schema"] != (CONTROL_PLANE_ENROLLMENT_V23_PAYLOAD_SCHEMA if is_v23
                    else CONTROL_PLANE_ENROLLMENT_V22_PAYLOAD_SCHEMA if is_v22
                    else CONTROL_PLANE_ENROLLMENT_V21_PAYLOAD_SCHEMA if is_v21
                    else CONTROL_PLANE_ENROLLMENT_V20_PAYLOAD_SCHEMA if is_v20
                    else CONTROL_PLANE_ENROLLMENT_V19_PAYLOAD_SCHEMA if is_v19
                    else CONTROL_PLANE_ENROLLMENT_V18_PAYLOAD_SCHEMA if is_v18
                    else CONTROL_PLANE_ENROLLMENT_V17_PAYLOAD_SCHEMA if is_v17
                    else CONTROL_PLANE_ENROLLMENT_V16_PAYLOAD_SCHEMA if is_v16
                    else CONTROL_PLANE_ENROLLMENT_V15_PAYLOAD_SCHEMA if is_v15
                    else CONTROL_PLANE_ENROLLMENT_V14_PAYLOAD_SCHEMA if is_v14
                    else CONTROL_PLANE_ENROLLMENT_V13_PAYLOAD_SCHEMA if is_v13
                    else CONTROL_PLANE_ENROLLMENT_V12_PAYLOAD_SCHEMA if is_v12
                    else CONTROL_PLANE_ENROLLMENT_V11_PAYLOAD_SCHEMA if is_v11
                    else CONTROL_PLANE_ENROLLMENT_V10_PAYLOAD_SCHEMA if is_v10
                    else CONTROL_PLANE_ENROLLMENT_V9_PAYLOAD_SCHEMA if is_v9
                    else CONTROL_PLANE_ENROLLMENT_V8_PAYLOAD_SCHEMA if is_v8
                    else CONTROL_PLANE_ENROLLMENT_V7_PAYLOAD_SCHEMA if is_v7
                    else CONTROL_PLANE_ENROLLMENT_V6_PAYLOAD_SCHEMA if is_v6
                    else CONTROL_PLANE_ENROLLMENT_V5_PAYLOAD_SCHEMA if is_v5
                    else CONTROL_PLANE_ENROLLMENT_V4_PAYLOAD_SCHEMA if is_v4
                    else CONTROL_PLANE_ENROLLMENT_V3_PAYLOAD_SCHEMA if is_v3
                    else CONTROL_PLANE_ENROLLMENT_PAYLOAD_SCHEMA)):
            raise RuntimeError("control-plane enrollment bootstrap payload is not closed")
        signature = value["signatureBase64Url"]
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        if (type(signature) is not str or len(signature) != 86
                or any(character not in alphabet for character in signature)):
            raise RuntimeError("control-plane enrollment bootstrap signature encoding is invalid")
        revision = payload["sourceRevision"]
        allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._/-"
        if (type(revision) is not str or not 1 <= len(revision) <= 256
                or not revision[0].isascii() or not revision[0].isalnum()
                or any(character not in allowed for character in revision)):
            raise RuntimeError("control-plane enrollment source revision is not a bounded ASCII token")
        digest = payload["configurationDigest"]
        if (type(digest) is not str or len(digest) != 71 or not digest.startswith("sha256:")
                or any(character not in "0123456789abcdef" for character in digest[7:])):
            raise RuntimeError("control-plane enrollment configuration identity is not canonical")
        if any(type(payload[name]) is not dict
                for name in ("configurationPayload", "generation", "runtimeRoleIdentities")):
            raise RuntimeError("control-plane enrollment bootstrap graphs are not objects")
        target = payload["issuerPrivateKeyFd"]
        if target is not None and (type(target) is not int or not 32 <= target <= 1023):
            raise RuntimeError("control-plane enrollment key descriptor is outside its exact range")
        execution_target = (_control_plane_execution_key_slot(payload["registrationExecution"],
            issuer_descriptor=target, bootstrap_descriptor=descriptor) if is_v3 or is_v4 or is_v5 or is_v6 or is_v7 or is_v8 or is_v9 or is_v10 or is_v11 or is_v12 or is_v13 else None)
        finalization_target = (_control_plane_finalization_key_slot(payload["registrationFinalization"],
            issuer_descriptor=target, bootstrap_descriptor=descriptor) if is_v4 or is_v5 or is_v6 or is_v7 or is_v8 or is_v9 or is_v10 or is_v11 or is_v12 or is_v13 else None)
        if is_v5 or is_v6 or is_v7 or is_v8 or is_v9 or is_v10 or is_v11 or is_v12 or is_v13:
            _control_plane_release_public_shape(payload["oidcSessionActivationRelease"])
        activation_target = (_control_plane_activation_key_slot(payload["oidcSessionActivationExecution"],
            issuer_descriptor=target, bootstrap_descriptor=descriptor) if is_v6 or is_v7 or is_v8 or is_v9 or is_v10 or is_v11 or is_v12 or is_v13 else None)
        if is_v7 or is_v8 or is_v9 or is_v10 or is_v11 or is_v12 or is_v13:
            _control_plane_activation_planning_shape(payload["oidcSessionActivationPlanning"],
                activation_target=activation_target)
        consume_target = (_control_plane_consume_key_slot(payload["oidcSessionActivationConsumeExecution"],
            issuer_descriptor=target, bootstrap_descriptor=descriptor,
            activation_value=payload["oidcSessionActivationExecution"],
            planning_value=payload["oidcSessionActivationPlanning"]) if is_v8 or is_v9 or is_v10 or is_v11 or is_v12 or is_v13 else None)
        intent_target = (_control_plane_intent_key_slot(payload["oidcSessionActivationReleaseIntent"],
            issuer_descriptor=target, bootstrap_descriptor=descriptor,
            consume_value=payload["oidcSessionActivationConsumeExecution"]) if is_v9 or is_v10 or is_v11 or is_v12 or is_v13 else None)
        if is_v10 or is_v11 or is_v12 or is_v13:
            _control_plane_proof_public_shape(payload["oidcSessionActivationReleaseProof"],
                intent_value=payload["oidcSessionActivationReleaseIntent"])
        if is_v11 or is_v12 or is_v13:
            _control_plane_handoff_public_shape(payload["oidcSessionActivationReleaseHandoff"],
                intent_value=payload["oidcSessionActivationReleaseIntent"],
                proof_value=payload["oidcSessionActivationReleaseProof"])
        if is_v12 or is_v13:
            _control_plane_grant_acquisition_public_shape(payload["oidcSessionActivationReleaseGrantAcquisition"],
                handoff_value=payload["oidcSessionActivationReleaseHandoff"])
        if is_v13:
            _control_plane_consume_input_acquisition_public_shape(payload["oidcSessionActivationConsumeInputAcquisition"],
                planning_value=payload["oidcSessionActivationPlanning"],
                activation_value=payload["oidcSessionActivationExecution"])
        if is_v21:
            historical_consume = payload["historicalConsumeInputAcquisition"]
            if historical_consume is not None and (
                    type(historical_consume) is not dict
                    or historical_consume.get("schema") != CONTROL_PLANE_CONSUME_INPUT_ACQUISITION_V2_SCHEMA
                    or payload["activationHistory"] is None
                    or payload["oidcSessionActivationConsumeExecution"] is None):
                raise RuntimeError("historical consume acquisition requires its archive and current consume lane")
            _control_plane_consume_input_acquisition_public_shape(historical_consume,
                planning_value=payload["oidcSessionActivationPlanning"],
                activation_value=payload["oidcSessionActivationExecution"], allow_history=True)
        if is_v14:
            _control_plane_proof_acquisition_public_shape(payload["oidcSessionActivationReleaseProofAcquisition"],
                intent_value=payload["oidcSessionActivationReleaseIntent"],
                proof_value=payload["oidcSessionActivationReleaseProof"])
        if is_v15:
            _control_plane_recovery_grant_acquisition_public_shape(payload["oidcSessionActivationReleaseRecoveryGrantAcquisition"],
                intent_value=payload["oidcSessionActivationReleaseIntent"],
                proof_value=payload["oidcSessionActivationReleaseProof"])
        if is_v16:
            if (payload["oidcSessionActivationCompletionRecovery"] is not None
                    and payload["oidcSessionActivationPlanning"] is None):
                raise RuntimeError("completion recovery requires configured activation planning")
            _control_plane_completion_recovery_public_shape(payload["oidcSessionActivationCompletionRecovery"],
                activation_value=payload["oidcSessionActivationExecution"],
                consume_value=payload["oidcSessionActivationConsumeExecution"])
        _control_plane_history_public_shape(payload, registration=is_v17,
            finalization=is_v18, activation=is_v19, v20=is_v20, v22=is_v22)
        revocation_target = (_control_plane_public_revocation_key_slot(payload["publicWebAuthnRevocation"],
            issuer_descriptor=target, bootstrap_descriptor=descriptor) if is_v23 else None)
        canonical = json.dumps(value, ensure_ascii=True, allow_nan=False,
            separators=(",", ":"), sort_keys=True).encode("ascii")
        if canonical != original:
            raise RuntimeError("control-plane enrollment bootstrap is not original canonical JSON")
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError) as exc:
        raise RuntimeError("control-plane enrollment bootstrap is invalid") from exc
    return (target, execution_target, finalization_target, is_v4 or is_v5 or is_v6 or is_v7 or is_v8 or is_v9 or is_v10 or is_v11 or is_v12 or is_v13,
        activation_target, is_v6 or is_v7 or is_v8 or is_v9 or is_v10 or is_v11 or is_v12 or is_v13, consume_target, is_v8 or is_v9 or is_v10 or is_v11 or is_v12 or is_v13,
        intent_target, is_v9 or is_v10 or is_v11 or is_v12 or is_v13, revocation_target, is_v23)


def _control_plane_enrollment_purpose_slots(descriptor: int) -> tuple:
    """Preserve the existing exact four-field projection for prior consumers."""
    return _control_plane_enrollment_slot_projection(descriptor)[:4]


def _control_plane_enrollment_key_slots(descriptor: int) -> tuple[int | None, int | None]:
    """Preserve the existing two-slot projection API and old profile behavior."""
    slots = _control_plane_enrollment_purpose_slots(descriptor)
    return slots[0], slots[1]


def _control_plane_enrollment_key_slot(descriptor: int) -> int | None:
    """Retain the existing evidence-issuer slot projection API."""
    return _control_plane_enrollment_key_slots(descriptor)[0]


def _open_control_plane_enrollment_key(bootstrap_descriptor: int, *,
        occupied_descriptors: set[int]) -> int | None:
    """Deliver original key bytes at one declared free slot, never authorize it.

    The full original signed runtime inventory must already include bootstrap
    and key. Root signature, policy/null correspondence and actual key admission
    belong to the child; no inventory or key environment is synthesized here.
    """
    target = _control_plane_enrollment_key_slot(bootstrap_descriptor)
    return _open_control_plane_purpose_key(bootstrap_descriptor, target=target,
        source_name=CONTROL_PLANE_ENROLLMENT_KEY_NAME, occupied_descriptors=occupied_descriptors)


def _open_control_plane_registration_execution_key(bootstrap_descriptor: int, *,
        occupied_descriptors: set[int]) -> int | None:
    """Deliver only the opt-in dedicated caller key; never infer its inventory."""
    target = _control_plane_enrollment_key_slots(bootstrap_descriptor)[1]
    return _open_control_plane_purpose_key(bootstrap_descriptor, target=target,
        source_name=CONTROL_PLANE_EXECUTION_KEY_NAME, occupied_descriptors=occupied_descriptors)


def _open_control_plane_registration_finalization_key(bootstrap_descriptor: int, *,
        occupied_descriptors: set[int]) -> int | None:
    """Deliver v4/v5's independent key; disabled finalization leaves FD204 absent."""
    slots = _control_plane_enrollment_purpose_slots(bootstrap_descriptor)
    target, reserved = slots[2], slots[3]
    if reserved and target is None:
        if CONTROL_PLANE_FINALIZATION_KEY_FD in occupied_descriptors:
            raise RuntimeError("disabled v4 finalization has an occupied reserved key slot")
        try:
            fcntl.fcntl(CONTROL_PLANE_FINALIZATION_KEY_FD, fcntl.F_GETFD)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
        else:
            raise RuntimeError("disabled v4 finalization has an undeclared open key slot")
    return _open_control_plane_purpose_key(bootstrap_descriptor, target=target,
        source_name=CONTROL_PLANE_FINALIZATION_KEY_NAME, occupied_descriptors=occupied_descriptors)


def _open_control_plane_purpose_key(bootstrap_descriptor: int, *, target,
        source_name: str, occupied_descriptors: set[int]) -> int | None:
    if source_name not in (CONTROL_PLANE_ENROLLMENT_KEY_NAME, CONTROL_PLANE_EXECUTION_KEY_NAME,
            CONTROL_PLANE_FINALIZATION_KEY_NAME, CONTROL_PLANE_ACTIVATION_KEY_NAME,
            CONTROL_PLANE_CONSUME_KEY_NAME, CONTROL_PLANE_INTENT_KEY_NAME, CONTROL_PLANE_REVOCATION_KEY_NAME):
        raise RuntimeError("control-plane private-key source is not a fixed purpose")
    if target is None:
        return None
    if (type(target) is not int or not 32 <= target <= 1023 or target == bootstrap_descriptor
            or source_name == CONTROL_PLANE_EXECUTION_KEY_NAME and target != CONTROL_PLANE_EXECUTION_KEY_FD
            or source_name == CONTROL_PLANE_FINALIZATION_KEY_NAME and target != CONTROL_PLANE_FINALIZATION_KEY_FD
            or source_name == CONTROL_PLANE_ACTIVATION_KEY_NAME and target != CONTROL_PLANE_ACTIVATION_KEY_FD
            or source_name == CONTROL_PLANE_CONSUME_KEY_NAME and target != CONTROL_PLANE_CONSUME_KEY_FD
            or source_name == CONTROL_PLANE_INTENT_KEY_NAME and target != CONTROL_PLANE_INTENT_KEY_FD
            or source_name == CONTROL_PLANE_REVOCATION_KEY_NAME and target != CONTROL_PLANE_REVOCATION_KEY_FD):
        raise RuntimeError("control-plane private-key target differs from its fixed purpose")
    if target in occupied_descriptors:
        raise RuntimeError("control-plane enrollment key descriptor is already assigned")
    owned: list[int] = []
    try:
        # This non-overwriting reservation also detects undeclared open FDs.
        reserved = fcntl.fcntl(bootstrap_descriptor, fcntl.F_DUPFD_CLOEXEC, target)
        owned.append(reserved)
        if reserved != target:
            raise RuntimeError("control-plane enrollment key descriptor is occupied")
        reservation_identity = _material_identity(os.fstat(reserved))
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        parent = os.open("/", flags)
        owned.append(parent)
        for component in (None, "run", "secrets"):
            if component is not None:
                parent = os.open(component, flags, dir_fd=parent)
                owned.append(parent)
            metadata = os.fstat(parent)
            if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0
                    or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
                raise RuntimeError("control-plane enrollment key ancestor is not root-owned nonwritable material")
        key = _open_source(source_name, expected_owner_uid=0,
            maximum_bytes=CONTROL_PLANE_ENROLLMENT_KEY_MAX_BYTES,
            required_mode=0o400, directory_fd=parent)
        owned.append(key)
        if _material_identity(os.fstat(reserved)) != reservation_identity:
            # Do not close a slot which no longer belongs to our reservation.
            owned.remove(reserved)
            raise RuntimeError("control-plane enrollment key reservation changed")
        owned.remove(reserved)
        os.close(reserved)
        retained = fcntl.fcntl(key, fcntl.F_DUPFD_CLOEXEC, target)
        owned.append(retained)
        if retained != target:
            raise RuntimeError("control-plane enrollment reserved key slot changed")
        os.set_inheritable(retained, True)
        for descriptor in tuple(reversed(owned)):
            if descriptor != retained:
                owned.remove(descriptor)
                os.close(descriptor)
        owned.clear()
        return retained
    except BaseException:
        for descriptor in reversed(owned):
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _open_control_plane_oidc_session_activation_key(bootstrap_descriptor: int, *,
        occupied_descriptors: set[int]) -> int | None:
    """Deliver the fixed activation key only; null v6 forbids any FD205."""
    slots = _control_plane_enrollment_slot_projection(bootstrap_descriptor)
    target, reserved = slots[4], slots[5]
    if reserved and target is None:
        if CONTROL_PLANE_ACTIVATION_KEY_FD in occupied_descriptors:
            raise RuntimeError("disabled v6 activation has an occupied reserved key slot")
        try:
            fcntl.fcntl(CONTROL_PLANE_ACTIVATION_KEY_FD, fcntl.F_GETFD)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
        else:
            raise RuntimeError("disabled v6 activation has an undeclared open key slot")
    return _open_control_plane_purpose_key(bootstrap_descriptor, target=target,
        source_name=CONTROL_PLANE_ACTIVATION_KEY_NAME, occupied_descriptors=occupied_descriptors)


def _open_control_plane_oidc_session_activation_consume_key(bootstrap_descriptor: int, *,
        occupied_descriptors: set[int]) -> int | None:
    """Deliver only fixed consume FD206; a null v8 lane forbids that slot."""
    slots = _control_plane_enrollment_slot_projection(bootstrap_descriptor)
    target, reserved = slots[6], slots[7]
    if reserved and target is None:
        if CONTROL_PLANE_CONSUME_KEY_FD in occupied_descriptors:
            raise RuntimeError("disabled v8 consume caller has an occupied reserved key slot")
        try:
            fcntl.fcntl(CONTROL_PLANE_CONSUME_KEY_FD, fcntl.F_GETFD)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
        else:
            raise RuntimeError("disabled v8 consume caller has an undeclared open key slot")
    return _open_control_plane_purpose_key(bootstrap_descriptor, target=target,
        source_name=CONTROL_PLANE_CONSUME_KEY_NAME, occupied_descriptors=occupied_descriptors)


def _open_control_plane_oidc_session_activation_release_intent_key(bootstrap_descriptor: int, *,
        occupied_descriptors: set[int]) -> int | None:
    """Deliver only sealed intent FD207; a null v9 lane forbids that slot."""
    slots = _control_plane_enrollment_slot_projection(bootstrap_descriptor)
    target, reserved = slots[8], slots[9]
    if reserved and target is None:
        if CONTROL_PLANE_INTENT_KEY_FD in occupied_descriptors:
            raise RuntimeError("disabled v9 intent has an occupied reserved key slot")
        try:
            fcntl.fcntl(CONTROL_PLANE_INTENT_KEY_FD, fcntl.F_GETFD)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
        else:
            raise RuntimeError("disabled v9 intent has an undeclared open key slot")
    return _open_control_plane_purpose_key(bootstrap_descriptor, target=target,
        source_name=CONTROL_PLANE_INTENT_KEY_NAME, occupied_descriptors=occupied_descriptors)


def _open_control_plane_public_revocation_key(bootstrap_descriptor: int, *,
        occupied_descriptors: set[int]) -> int | None:
    slots = _control_plane_enrollment_slot_projection(bootstrap_descriptor)
    target, reserved = slots[10:12]
    if reserved and target is None:
        if CONTROL_PLANE_REVOCATION_KEY_FD in occupied_descriptors:
            raise RuntimeError("disabled public revocation has an occupied reserved key slot")
        try:
            fcntl.fcntl(CONTROL_PLANE_REVOCATION_KEY_FD, fcntl.F_GETFD)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
        else:
            raise RuntimeError("disabled public revocation has an undeclared key slot")
    return _open_control_plane_purpose_key(bootstrap_descriptor, target=target,
        source_name=CONTROL_PLANE_REVOCATION_KEY_NAME, occupied_descriptors=occupied_descriptors)


def _control_plane_custody_configuration(descriptor: int) -> dict:
    """Read only the closed root-delivered startup document, without app imports."""
    metadata = os.fstat(descriptor)
    seals = (fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK
        | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not 2 <= metadata.st_size <= CONTROL_PLANE_CUSTODY_CONFIG_MAX_BYTES
            or fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & seals != seals):
        raise RuntimeError("control-plane custody startup configuration is not root-owned sealed material")
    original = _read_exact_source(descriptor, metadata.st_size)
    try:
        value = json.loads(original)
        fields = {"schema", "sourceRevision", "configurationDigest", "directoryFd",
            "device", "inode", "uid", "gid", "quotaBytes", "maximumRecords"}
        broker = type(value) is dict and value.get("schema") == "serverware.controlPlaneCustodyStartup/v2"
        genesis = type(value) is dict and value.get("schema") == "serverware.controlPlaneCustodyStartup/v3"
        if broker:
            fields |= {"credentialBrokerProfile", "signature"}
        if genesis:
            fields |= {"policyFileGenesisMaintenance", "signature"}
        if type(value) is not dict or set(value) != fields:
            raise RuntimeError("control-plane custody startup configuration is not closed")
        if not broker and not genesis and value["schema"] != CONTROL_PLANE_CUSTODY_CONFIG_SCHEMA:
            raise RuntimeError("control-plane custody startup schema is not supported")
        if broker and (value["credentialBrokerProfile"] != "enclave-ciphertext-rows-v1"
                or type(value["signature"]) is not str or len(value["signature"]) != 94
                or not value["signature"].startswith("ed25519:")
                or any(char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for char in value["signature"][8:])):
            raise RuntimeError("control-plane broker startup authorization is not exact")
        if genesis:
            from serverware import control_plane_policy_genesis_bootstrap as genesis_profile
            genesis_profile._unsigned(value)
            if (type(value["signature"]) is not str or len(value["signature"]) != 94
                    or not value["signature"].startswith("ed25519:")
                    or any(char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for char in value["signature"][8:])):
                raise RuntimeError("genesis maintenance cold signature is not exact")
        # The genuine cold runtime owner verifies this purpose-specific signature
        # against its actually admitted root after permanent privilege drop.
        revision = value["sourceRevision"]
        allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._/-"
        if (type(revision) is not str or not 1 <= len(revision) <= 256
                or not revision[0].isascii() or not revision[0].isalnum()
                or any(character not in allowed for character in revision)):
            raise RuntimeError("control-plane custody source revision is not a bounded ASCII token")
        digest = value["configurationDigest"]
        if (type(digest) is not str or len(digest) != 71 or not digest.startswith("sha256:")
                or any(character not in "0123456789abcdef" for character in digest[7:])):
            raise RuntimeError("control-plane custody configuration identity is not canonical")
        uid, gid = ROLE_IDENTITIES["control-plane"]
        for name, minimum, maximum in (
            ("directoryFd", CONTROL_PLANE_CUSTODY_FD_MIN, CONTROL_PLANE_CUSTODY_FD_MAX),
            ("device", 0, 2**64 - 1), ("inode", 1, 2**64 - 1),
            ("uid", uid, uid), ("gid", gid, gid),
            ("quotaBytes", 1, 8 * 1024**3), ("maximumRecords", 1, 4096),
        ):
            if type(value[name]) is not int or not minimum <= value[name] <= maximum:
                raise RuntimeError("control-plane custody " + name + " is not an exact bounded scalar")
        canonical = json.dumps(value, ensure_ascii=True, allow_nan=False,
            separators=(",", ":"), sort_keys=True).encode("ascii")
        if canonical != original:
            raise RuntimeError("control-plane custody startup configuration is not original canonical JSON")
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError) as exc:
        raise RuntimeError("control-plane custody startup configuration is invalid") from exc
    return value


def _open_control_plane_custody(
    configuration_descriptor: int,
    *,
    occupied_descriptors: set[int],
) -> tuple[int, int]:
    """Retain the exact preprovisioned directory and sealed startup config.

    This is descriptor delivery only. The cold caller still admits the full
    runtime-root-signed inherited inventory, current configuration identity
    and original source before acquiring the journal's real owner/lease.
    """
    configuration = _control_plane_custody_configuration(configuration_descriptor)
    target = configuration["directoryFd"]
    if target in occupied_descriptors:
        raise RuntimeError("control-plane custody directory descriptor is already assigned")
    owned: list[int] = []
    try:
        # F_DUPFD_CLOEXEC never overwrites an existing slot. A result above the
        # requested number proves collision, even with an undeclared open FD.
        reserved = fcntl.fcntl(configuration_descriptor, fcntl.F_DUPFD_CLOEXEC, target)
        owned.append(reserved)
        if reserved != target:
            raise RuntimeError("control-plane custody directory descriptor is occupied")
        retained_configuration = fcntl.fcntl(configuration_descriptor,
            fcntl.F_DUPFD_CLOEXEC, CONTROL_PLANE_CUSTODY_FD_MIN)
        owned.append(retained_configuration)
        if retained_configuration > CONTROL_PLANE_CUSTODY_FD_MAX:
            raise RuntimeError("control-plane custody configuration descriptor exceeds its range")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        parent = os.open("/", flags)
        owned.append(parent)
        # Each component is opened relative to its already checked parent.
        # No symlink traversal or caller-selected path is allowed.
        for component in (None, "var", "lib", "serverware"):
            if component is not None:
                parent = os.open(component, flags, dir_fd=parent)
                owned.append(parent)
            metadata = os.fstat(parent)
            if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0
                    or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
                raise RuntimeError("control-plane custody directory ancestor is not root-owned nonwritable material")
        directory = os.open(os.path.basename(CONTROL_PLANE_CUSTODY_DIRECTORY),
            flags, dir_fd=parent)
        owned.append(directory)
        metadata = os.fstat(directory)
        if (not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700
                or (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid)
                != (configuration["device"], configuration["inode"],
                    configuration["uid"], configuration["gid"])):
            raise RuntimeError("control-plane custody directory differs from its provisioned identity")
        # Release only our reservation, then duplicate without overwriting.
        # If another descriptor appeared in that slot, fail and close only
        # the new duplicate; never clobber the conflicting descriptor.
        owned.remove(reserved)
        os.close(reserved)
        retained_directory = fcntl.fcntl(directory, fcntl.F_DUPFD_CLOEXEC, target)
        owned.append(retained_directory)
        if retained_directory != target:
            raise RuntimeError("control-plane custody reserved directory slot changed")
        os.set_inheritable(retained_configuration, True)
        os.set_inheritable(retained_directory, True)
        result = retained_configuration, retained_directory
        for descriptor in tuple(reversed(owned)):
            if descriptor not in result:
                owned.remove(descriptor)
                os.close(descriptor)
        owned.clear()
        return result
    except BaseException:
        for descriptor in reversed(owned):
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _open_systemd_credential(name: str) -> int:
    directory_path = os.environ.get("CREDENTIALS_DIRECTORY", "")
    if (
        not directory_path
        or not os.path.isabs(directory_path)
        or not name
        or name != os.path.basename(name)
        or "/" in name
    ):
        raise RuntimeError(
            "trusted-host-local requires an exact systemd credential key"
        )
    directory = os.open(
        directory_path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    descriptor = -1
    try:
        directory_metadata = os.fstat(directory)
        if (
            not stat.S_ISDIR(directory_metadata.st_mode)
            or directory_metadata.st_uid != 0
            or directory_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise RuntimeError(
                "systemd credential directory is not trusted"
            )
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory,
        )
        metadata_before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata_before.st_mode)
            or metadata_before.st_uid != 0
            or metadata_before.st_nlink != 1
            or metadata_before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise RuntimeError(
                "systemd credential source is not an exact root-owned file"
            )
        value = _read_exact_source(
            descriptor,
            metadata_before.st_size,
        )
        metadata_after = os.fstat(descriptor)
        if (
            metadata_before.st_dev,
            metadata_before.st_ino,
            metadata_before.st_size,
            metadata_before.st_mtime_ns,
        ) != (
            metadata_after.st_dev,
            metadata_after.st_ino,
            metadata_after.st_size,
            metadata_after.st_mtime_ns,
        ):
            raise RuntimeError(
                "systemd credential changed while it was sealed"
            )
        sealed_descriptor = _seal_bytes(
            descriptor,
            name=f"serverware-{name}",
            value=value,
            mode=stat.S_IMODE(metadata_before.st_mode),
        )
        descriptor = -1
        return sealed_descriptor
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory)


def _open_trusted_host_local_witness_state(
    launch_manifest_descriptor: int,
    *,
    occupied_descriptors: set[int],
) -> int:
    metadata = os.fstat(launch_manifest_descriptor)
    try:
        manifest_value = _read_exact_source(
            launch_manifest_descriptor,
            metadata.st_size,
        )
        manifest = json.loads(manifest_value)
        canonical_manifest = json.dumps(
            manifest,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (UnicodeDecodeError, ValueError, TypeError) as exc:
        raise RuntimeError(
            "witness launch manifest is not readable canonical JSON"
        ) from exc
    payload = manifest.get("payload") if isinstance(manifest, dict) else None
    request = (
        payload.get("stageZeroRequest")
        if isinstance(payload, dict)
        else None
    )
    mutable_state = (
        request.get("mutableStateDescriptors")
        if isinstance(request, dict)
        else None
    )
    state = (
        mutable_state[0]
        if isinstance(mutable_state, list) and len(mutable_state) == 1
        else None
    )
    target_descriptor = (
        state.get("fd") if isinstance(state, dict) else None
    )
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"schema", "payload", "signature"}
        or canonical_manifest != manifest_value
        or manifest.get("schema")
            != "serverware.signedPolicyAuthorityLaunchManifest/v7"
        or not isinstance(payload, dict)
        or payload.get("role") != "witness"
        or payload.get("processMode") != "policy-authority-replay-witness"
        or not isinstance(request, dict)
        or request.get("trustMode") != "trusted-host-local"
        or not isinstance(state, dict)
        or set(state)
            != {
                "name",
                "ownerRole",
                "fd",
                "runtimePath",
                "device",
                "inode",
                "generation",
                "mountId",
                "uid",
                "gid",
                "mode",
                "singletonLeaseRequired",
                "leaseIdentityDigest",
                "leaseHeld",
                "atomicRecordProtocol",
                "quotaBytes",
                "networkAllowed",
                "surviveExec",
            }
        or state.get("name") != "witness"
        or state.get("ownerRole") != "witness"
        or state.get("runtimePath")
            != TRUSTED_HOST_LOCAL_WITNESS_STATE_PATH
        or state.get("singletonLeaseRequired") is not True
        or state.get("leaseHeld") is not True
        or state.get("networkAllowed") is not False
        or state.get("surviveExec") is not True
        or not isinstance(target_descriptor, int)
        or isinstance(target_descriptor, bool)
        or not (
            TRUSTED_HOST_LOCAL_WITNESS_STATE_FD_MIN
            <= target_descriptor
            <= TRUSTED_HOST_LOCAL_WITNESS_STATE_FD_MAX
        )
        or target_descriptor in occupied_descriptors
    ):
        raise RuntimeError(
            "trusted-host-local witness state descriptor is not exact"
        )
    try:
        os.fstat(target_descriptor)
    except OSError as exc:
        if exc.errno != errno.EBADF:
            raise RuntimeError(
                "trusted-host-local witness target descriptor is invalid"
            ) from exc
    else:
        raise RuntimeError(
            "trusted-host-local witness target descriptor is occupied"
        )
    os.dup2(
        launch_manifest_descriptor,
        target_descriptor,
        inheritable=False,
    )
    target_reserved = True
    parent = -1
    descriptor = -1
    try:
        parent = os.open(
            "/var/lib/serverware",
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        parent_metadata = os.fstat(parent)
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or parent_metadata.st_uid != 0
            or parent_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise RuntimeError(
                "trusted-host-local witness state parent is not trusted"
            )
        descriptor = os.open(
            "authority-witness",
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent,
        )
        state_metadata = os.fstat(descriptor)
        mount_id: int | None = None
        with open(
            f"/proc/self/fdinfo/{descriptor}",
            "r",
            encoding="ascii",
        ) as handle:
            for line in handle:
                name, separator, value = line.partition(":")
                if separator and name == "mnt_id":
                    try:
                        mount_id = int(value.strip(), 10)
                    except ValueError as exc:
                        raise RuntimeError(
                            "trusted-host-local witness mount ID is invalid"
                        ) from exc
        witness_uid, witness_gid = ROLE_IDENTITIES["witness"]
        if (
            not stat.S_ISDIR(state_metadata.st_mode)
            or state_metadata.st_uid != witness_uid
            or state_metadata.st_gid != witness_gid
            or stat.S_IMODE(state_metadata.st_mode) != 0o700
            or state_metadata.st_dev != state.get("device")
            or state_metadata.st_ino != state.get("inode")
            or state_metadata.st_uid != state.get("uid")
            or state_metadata.st_gid != state.get("gid")
            or stat.S_IMODE(state_metadata.st_mode) != state.get("mode")
            or mount_id != state.get("mountId")
        ):
            raise RuntimeError(
                "trusted-host-local witness state identity changed"
            )
        try:
            fcntl.flock(
                descriptor,
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
        except OSError as exc:
            raise RuntimeError(
                "trusted-host-local witness state lease is unavailable"
            ) from exc
        if descriptor == target_descriptor:
            raise RuntimeError(
                "trusted-host-local witness state descriptor overlaps"
            )
        os.dup2(descriptor, target_descriptor, inheritable=True)
        source_descriptor = descriptor
        descriptor = -1
        os.close(source_descriptor)
        descriptor = target_descriptor
        parent_descriptor = parent
        parent = -1
        os.close(parent_descriptor)
        target_reserved = False
        return descriptor
    except Exception:
        if descriptor >= 0 and descriptor != target_descriptor:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if target_reserved:
            try:
                os.close(target_descriptor)
            except OSError:
                pass
        raise
    finally:
        if parent >= 0:
            try:
                os.close(parent)
            except OSError:
                pass


def _drop_identity(role: str) -> None:
    uid, gid = ROLE_IDENTITIES[role]
    if os.geteuid() != 0 or os.getegid() != 0:
        raise RuntimeError("authority bootstrap must begin as root")
    os.setgroups(list(ROLE_SUPPLEMENTARY_GIDS[role]))
    os.setgid(gid)
    os.setuid(uid)
    if (
        os.geteuid() != uid
        or os.getegid() != gid
        or tuple(sorted(os.getgroups()))
        != tuple(sorted(ROLE_SUPPLEMENTARY_GIDS[role]))
    ):
        raise RuntimeError("authority bootstrap identity drop was not exact")
    _require_unprivileged_process()


def _require_unprivileged_process() -> None:
    values: dict[str, str] = {}
    with open("/proc/self/status", "r", encoding="ascii") as handle:
        for line in handle:
            name, separator, value = line.partition(":")
            if separator and name in {
                "CapEff",
                "CapInh",
                "CapPrm",
                "CapAmb",
                "NoNewPrivs",
            }:
                values[name] = value.strip()
    if (
        set(values)
        != {"CapEff", "CapInh", "CapPrm", "CapAmb", "NoNewPrivs"}
        or any(
            int(values[name], 16) != 0
            for name in {"CapEff", "CapInh", "CapPrm", "CapAmb"}
        )
        or values["NoNewPrivs"] != "1"
    ):
        raise RuntimeError(
            "authority runtime retained privilege after identity drop"
        )


def _socket_directory_descriptor(role: str) -> tuple[int, str]:
    path = ROLE_SOCKET_PATHS[role]
    parent, name = os.path.split(path)
    descriptor = os.open(
        parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    metadata = os.fstat(descriptor)
    uid, gid = ROLE_IDENTITIES[role]
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != uid
        or metadata.st_gid != gid
        or metadata.st_mode & stat.S_IWOTH
    ):
        os.close(descriptor)
        raise RuntimeError("authority socket directory is not trusted")
    return descriptor, name


def _consume_socket_activation(role: str) -> int:
    if (
        os.environ.get("LISTEN_PID") != str(os.getpid())
        or os.environ.get("LISTEN_FDS") != "1"
        or os.environ.get("LISTEN_FDNAMES")
        != ROLE_LISTENER_NAMES[role]
    ):
        raise RuntimeError(
            "authority requires exactly one named service-manager listener"
        )
    descriptor = 3
    metadata = os.fstat(descriptor)
    activated = socket.fromfd(
        descriptor,
        socket.AF_UNIX,
        socket.SOCK_STREAM,
    )
    try:
        socket_path = activated.getsockname()
        if isinstance(socket_path, bytes):
            socket_path = os.fsdecode(socket_path)
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or activated.family != socket.AF_UNIX
            or activated.type & socket.SOCK_STREAM != socket.SOCK_STREAM
            or activated.getsockopt(
                socket.SOL_SOCKET,
                socket.SO_ACCEPTCONN,
            )
            != 1
            or socket_path != ROLE_SOCKET_PATHS[role]
        ):
            raise RuntimeError(
                "authority service-manager listener binding changed"
            )
    finally:
        activated.close()
    path_metadata = os.stat(
        ROLE_SOCKET_PATHS[role],
        follow_symlinks=False,
    )
    uid, gid = ROLE_IDENTITIES[role]
    if (
        not stat.S_ISSOCK(path_metadata.st_mode)
        or path_metadata.st_uid != uid
        or path_metadata.st_gid != gid
        or stat.S_IMODE(path_metadata.st_mode) != 0o660
    ):
        raise RuntimeError(
            "authority service-manager socket path is not exact"
        )
    os.set_inheritable(descriptor, True)
    return descriptor


def _socket_health(role: str) -> int:
    directory, name = _socket_directory_descriptor(role)
    try:
        metadata = os.stat(
            name,
            dir_fd=directory,
            follow_symlinks=False,
        )
        uid, gid = ROLE_IDENTITIES[role]
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or metadata.st_uid != uid
            or metadata.st_gid != gid
        ):
            raise RuntimeError("authority health socket identity changed")
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        probe.settimeout(0.5)
        try:
            probe.connect(f"/proc/self/fd/{directory}/{name}")
        finally:
            probe.close()
    finally:
        os.close(directory)
    return 0


def _control_plane_health() -> int:
    _drop_identity("control-plane")
    os.execve(
        "/usr/bin/python3",
        [
            "/usr/bin/python3",
            "-P",
            "-s",
            "-c",
            CONTROL_PLANE_HEALTH_CODE,
        ],
        dict(os.environ),
    )
    return 1


def _local_admission_sources(role: str, selection: tuple[int, str, int]) -> tuple[int, ...]:
    """Preserve a parent's explicit empty slots, not provisional authority.

    The final same-PID launcher independently admits the full setup, producer,
    original clocks and signed late documents. This check only makes descriptor
    delivery safe before static credentials are opened; it issues no trust.
    """
    setup_fd, expected_digest, channel_fd = selection
    if (role == "control-plane" or role not in ROLE_SOURCES
            or any(type(fd) is not int or not 4 <= fd <= 1023 for fd in (setup_fd, channel_fd))
            or setup_fd == channel_fd or type(expected_digest) is not str
            or len(expected_digest) != 71 or not expected_digest.startswith("sha256:")
            or any(c not in "0123456789abcdef" for c in expected_digest[7:])):
        raise RuntimeError("local admission selection is not exact")
    seals = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
    metadata = os.fstat(setup_fd)
    if (not stat.S_ISREG(metadata.st_mode) or (metadata.st_uid, metadata.st_gid) != (0, 0)
            or stat.S_IMODE(metadata.st_mode) != 0o400
            or not 1 <= metadata.st_size <= LOCAL_ADMISSION_MAX_BYTES
            or fcntl.fcntl(setup_fd, fcntl.F_GET_SEALS) & seals != seals):
        raise RuntimeError("local admission setup is not protected")
    raw = _read_exact_source(setup_fd, metadata.st_size)
    if "sha256:" + hashlib.sha256(raw).hexdigest() != expected_digest:
        raise RuntimeError("local admission setup digest differs")
    setup = json.loads(raw)
    if (type(setup) is not dict or setup.get("schema") != LOCAL_ADMISSION_SCHEMA
            or setup.get("role") != role
            or json.dumps(setup, ensure_ascii=True, allow_nan=False,
                          separators=(",", ":"), sort_keys=True).encode("ascii") != raw):
        raise RuntimeError("local admission setup selection differs")
    expected_slots = {"manifest": 256, "certificate": 257}
    if role not in {"runtime", "witness"}:
        expected_slots["evidence"] = 258
    reservations = setup.get("reservations")
    if type(reservations) is not dict or set(reservations) != set(expected_slots):
        raise RuntimeError("local admission late slots differ")
    inherited = [setup_fd, channel_fd]
    for purpose, target in expected_slots.items():
        item = reservations[purpose]
        if (type(item) is not dict or set(item) != {"fd", "device", "inode"}
                or type(item["fd"]) is not int or item["fd"] != target
                or type(item["device"]) is not int or item["device"] < 0
                or type(item["inode"]) is not int or item["inode"] < 1):
            raise RuntimeError("local admission reservation differs")
        observed = os.fstat(target)
        if (not stat.S_ISREG(observed.st_mode) or observed.st_size != 0
                or (observed.st_uid, observed.st_gid) != (0, 0)
                or stat.S_IMODE(observed.st_mode) != 0o400
                or (observed.st_dev, observed.st_ino) != (item["device"], item["inode"])
                or fcntl.fcntl(target, fcntl.F_GET_SEALS) & seals != seals):
            raise RuntimeError("local admission reservation is not the original empty slot")
        inherited.append(target)
    for name, regular, maximum in (("retainedFiles", True, LOCAL_RETAINED_FILES_MAX),
            ("retainedDirectories", False, LOCAL_RETAINED_DIRECTORIES_MAX)):
        entries = setup.get(name)
        if (type(entries) is not list or not 1 <= len(entries) <= maximum
                or any(type(fd) is not int or not 4 <= fd <= LOCAL_RETAINED_FD_MAX for fd in entries)
                or entries != sorted(set(entries))):
            raise RuntimeError("local admission retained inventory differs")
        for descriptor in entries:
            observed = os.fstat(descriptor)
            if not (stat.S_ISREG(observed.st_mode) if regular else stat.S_ISDIR(observed.st_mode)):
                raise RuntimeError("local admission retained resource type differs")
            inherited.append(descriptor)
    states = setup.get("mutableStateDescriptors")
    if type(states) is not list or len(states) != (1 if role == "witness" else 0):
        raise RuntimeError("local admission mutable inventory differs")
    for state in states:
        descriptor = state.get("fd") if type(state) is dict else None
        if type(descriptor) is not int or not 32 <= descriptor <= 1023:
            raise RuntimeError("local admission witness descriptor differs")
        observed = os.fstat(descriptor)
        if (not stat.S_ISDIR(observed.st_mode) or stat.S_IMODE(observed.st_mode) != 0o700
                or (observed.st_uid, observed.st_gid) != ROLE_IDENTITIES["witness"]
                or (observed.st_dev, observed.st_ino) != (state.get("device"), state.get("inode"))):
            raise RuntimeError("local admission witness directory differs")
        inherited.append(descriptor)
    if len(inherited) != len(set(inherited)) or 3 in inherited:
        raise RuntimeError("local admission inherited descriptors overlap")
    channel = socket.fromfd(channel_fd, socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        if (channel.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) != socket.AF_UNIX
                or channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET):
            raise RuntimeError("local admission channel type differs")
        channel.getpeername()
    finally:
        channel.close()
    for descriptor in inherited:
        os.set_inheritable(descriptor, True)
    return tuple(inherited)


def _normal_main(role: str, *, public_revocation: bool = False, genesis_maintenance: bool = False, policy_canary_intake: bool = False,
        setup_native_observation: bool = False, local_admission: tuple[int, str, int] | None = None) -> int:
    if type(public_revocation) is not bool or public_revocation and role not in {"verifier", "issuer", "executor"}:
        raise RuntimeError("public revocation cold selection requires its fixed measured roles")
    if type(genesis_maintenance) is not bool or genesis_maintenance and (role != "control-plane" or public_revocation):
        raise RuntimeError("genesis maintenance cold selection requires the fixed control-plane role")
    if type(policy_canary_intake) is not bool or policy_canary_intake and (role != "control-plane" or genesis_maintenance or public_revocation):
        raise RuntimeError("canary intake cold selection requires the fixed normal control-plane role")
    if type(setup_native_observation) is not bool or setup_native_observation and (role != "control-plane" or genesis_maintenance or public_revocation):
        raise RuntimeError("native observation requires the fixed normal control-plane role")
    trusted_host_local = (
        os.environ.get("SERVERWARE_AUTHORITY_TRUST_MODE")
        == "trusted-host-local"
    )
    if local_admission is not None and (not trusted_host_local or role == "control-plane"
            or public_revocation or genesis_maintenance or policy_canary_intake or setup_native_observation):
        raise RuntimeError("late local admission requires its fixed authority selection")
    if role != "control-plane" and not trusted_host_local:
        raise RuntimeError(
            "native-stage-zero-required: authority roles must be entered "
            "by the unavailable native stage-zero entrypoint, or explicitly "
            "use trusted-host-local with systemd credential keys"
        )
    if os.geteuid() != 0 or os.getegid() != 0:
        raise RuntimeError("authority descriptor bootstrap must start as root")
    environment = (dict(os.environ) if local_admission is None else
                   {name: value for name, value in os.environ.items() if name in LOCAL_EXEC_ENVIRONMENT})
    if local_admission is not None:
        environment["SERVERWARE_AUTHORITY_ROLE"] = role
    environment.pop("SERVERWARE_PUBLIC_WEBAUTHN_REVOCATION_BOOTSTRAP_FD", None)
    environment.pop("SERVERWARE_PUBLIC_WEBAUTHN_REVOCATION_BOOTSTRAP_PATH", None)
    if any(
        environment.get(name)
        for name in OBSOLETE_STATIC_RELEASE_CONSUMER_NAMES
    ):
        raise RuntimeError(
            "static release-consumer credentials are forbidden in .19"
        )
    inherited_descriptors: list[int] = ([] if local_admission is None else
                                       list(_local_admission_sources(role, local_admission)))
    if role != "control-plane":
        listener_descriptor = _consume_socket_activation(role)
        inherited_descriptors.append(listener_descriptor)
        launch_private_descriptor = _open_systemd_credential(
            "serverware-authority-launch-private-key"
        )
        launch_certificate_descriptor = (257 if local_admission is not None else
            _open_systemd_credential("serverware-authority-launch-certificate"))
        inherited_descriptors.extend(
            (launch_private_descriptor,) if local_admission is not None else
            (launch_private_descriptor, launch_certificate_descriptor)
        )
        environment[
            "SERVERWARE_AUTHORITY_LAUNCH_PRIVATE_KEY_FD"
        ] = str(launch_private_descriptor)
        environment[
            "SERVERWARE_AUTHORITY_LAUNCH_CERTIFICATE_FD"
        ] = str(launch_certificate_descriptor)
        if len(set(inherited_descriptors)) != len(inherited_descriptors):
            raise RuntimeError(
                "authority inherited descriptor identities overlap"
            )
        environment.pop(STAGE_ZERO_HANDOFF_DESCRIPTOR_NAME, None)
        environment.pop(
            STAGE_ZERO_HANDOFF_DESCRIPTOR_NAME.removesuffix("_FD")
            + "_PATH",
            None,
        )
        environment.pop(
            "SERVERWARE_POLICY_AUTHORITY_LISTENER_FD",
            None,
        )
    for role_sources in ROLE_SOURCES.values():
        for descriptor_name, _path in role_sources:
            environment.pop(descriptor_name, None)
            environment.pop(
                descriptor_name.removesuffix("_FD") + "_PATH",
                None,
            )
    for name in tuple(environment):
        if name.startswith(("SERVERWARE_CONTROL_PLANE_CUSTODY_",
                "SERVERWARE_CONTROL_PLANE_ENROLLMENT_", "SERVERWARE_OAUTH_APPLICATION_", "SERVERWARE_OAUTH_REVOCATION_", "SERVERWARE_OAUTH_REFRESH_CLEANUP_", "SERVERWARE_MEASURED_AUDIT_", "SERVERWARE_RBAC_WITNESS_", "SERVERWARE_POLICY_CANARY_INTAKE_", "SERVERWARE_SETUP_NATIVE_OBSERVATION_")):
            environment.pop(name, None)
    environment.pop("SERVERWARE_AUTHORITY_BOOTSTRAP_FD", None)
    environment.pop("SERVERWARE_PROCESS_MODE", None)
    environment.pop("LISTEN_PID", None)
    environment.pop("LISTEN_FDS", None)
    environment.pop("LISTEN_FDNAMES", None)
    environment.pop("CREDENTIALS_DIRECTORY", None)
    environment.pop("SERVERWARE_AUTHORITY_TRUST_MODE", None)
    descriptors: list[int] = list(inherited_descriptors)
    descriptor_assignments: list[tuple[str, int]] = []
    launch_manifest_descriptor: int | None = None
    custody_configuration_descriptor: int | None = None
    enrollment_bootstrap_descriptor: int | None = None
    oauth_application_descriptor: int | None = None
    oauth_revocation_descriptor: int | None = None
    oauth_refresh_cleanup_descriptor: int | None = None
    rbac_witness_descriptor: int | None = None
    measured_audit_descriptor: int | None = None
    control_plane_source_limits = {
        CONTROL_PLANE_CUSTODY_CONFIG_NAME: CONTROL_PLANE_CUSTODY_CONFIG_MAX_BYTES,
        CONTROL_PLANE_ENROLLMENT_BOOTSTRAP_NAME: CONTROL_PLANE_ENROLLMENT_BOOTSTRAP_MAX_BYTES,
        OAUTH_APPLICATION_CONFIG_NAME: OAUTH_APPLICATION_CONFIG_MAX_BYTES,
        OAUTH_REVOCATION_CONFIG_NAME: OAUTH_REVOCATION_CONFIG_MAX_BYTES,
        OAUTH_REFRESH_CLEANUP_CONFIG_NAME: OAUTH_REFRESH_CLEANUP_CONFIG_MAX_BYTES,
        RBAC_WITNESS_CONFIG_NAME: RBAC_WITNESS_CONFIG_MAX_BYTES,
        MEASURED_AUDIT_CONFIG_NAME: MEASURED_AUDIT_CONFIG_MAX_BYTES,
    }
    try:
        for environment_name, path in ROLE_SOURCES[role]:
            if local_admission is not None and environment_name in LOCAL_LATE_DESCRIPTORS:
                descriptor_assignments.append((environment_name, LOCAL_LATE_DESCRIPTORS[environment_name]))
                continue
            descriptor = (
                _open_source(path, expected_owner_uid=0,
                    maximum_bytes=control_plane_source_limits.get(environment_name, MAX_SOURCE_BYTES))
                if role == "control-plane"
                else _open_systemd_credential(
                    os.path.basename(path)
                )
            )
            descriptors.append(descriptor)
            if role == "control-plane":
                environment[environment_name] = str(descriptor)
                if environment_name == CONTROL_PLANE_CUSTODY_CONFIG_NAME:
                    custody_configuration_descriptor = descriptor
                elif environment_name == CONTROL_PLANE_ENROLLMENT_BOOTSTRAP_NAME:
                    enrollment_bootstrap_descriptor = descriptor
                elif environment_name == OAUTH_APPLICATION_CONFIG_NAME:
                    oauth_application_descriptor = descriptor
                elif environment_name == OAUTH_REVOCATION_CONFIG_NAME:
                    oauth_revocation_descriptor = descriptor
                elif environment_name == OAUTH_REFRESH_CLEANUP_CONFIG_NAME:
                    oauth_refresh_cleanup_descriptor = descriptor
                elif environment_name == RBAC_WITNESS_CONFIG_NAME:
                    rbac_witness_descriptor = descriptor
                elif environment_name == MEASURED_AUDIT_CONFIG_NAME:
                    measured_audit_descriptor = descriptor
            else:
                descriptor_assignments.append(
                    (environment_name, descriptor)
                )
                if environment_name == (
                    "SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD"
                ):
                    launch_manifest_descriptor = descriptor
        if public_revocation:
            target = 212
            if target in descriptors:
                raise RuntimeError("public revocation terminal descriptor overlaps another original")
            try:
                os.fstat(target)
            except OSError as exc:
                if exc.errno != 9:
                    raise
            else:
                raise RuntimeError("public revocation terminal descriptor is already occupied")
            original = _open_systemd_credential("serverware-authority-" + role + "-public-revocation")
            if original != target:
                try:
                    os.dup2(original, target, inheritable=True)
                finally:
                    os.close(original)
            else:
                os.set_inheritable(target, True)
            descriptors.append(target)
            descriptor_assignments.append(("SERVERWARE_PUBLIC_WEBAUTHN_REVOCATION_BOOTSTRAP_FD", target))
        if role == "witness" and local_admission is None:
            if launch_manifest_descriptor is None:
                raise RuntimeError(
                    "trusted-host-local witness launch manifest is unavailable"
                )
            descriptors.append(
                _open_trusted_host_local_witness_state(
                    launch_manifest_descriptor,
                    occupied_descriptors=set(descriptors),
                )
            )
        if role == "control-plane":
            if setup_native_observation:
                native_descriptor = _open_source("/run/serverware/authority-trust/setup-native-observation.json",
                    expected_owner_uid=0, maximum_bytes=16384)
                descriptors.append(native_descriptor)
                environment[SETUP_NATIVE_CONFIG_NAME] = str(native_descriptor)
                descriptors.extend(_open_setup_native_material(native_descriptor, occupied_descriptors=set(descriptors)))
            if policy_canary_intake:
                from serverware import control_plane_policy_canary_startup as canary_cold
                canary_descriptor = _open_source("/run/serverware/authority-trust/policy-canary-intake.json",
                    expected_owner_uid=0, maximum_bytes=canary_cold.CONFIG_MAX)
                descriptors.append(canary_descriptor)
                environment[POLICY_CANARY_CONFIG_NAME] = str(canary_descriptor)
                descriptors.extend(_open_policy_canary_material(canary_descriptor, occupied_descriptors=set(descriptors)))
            if rbac_witness_descriptor is None:
                raise RuntimeError("RBAC witness cold configuration is unavailable")
            descriptors.extend(_open_rbac_witness_material(rbac_witness_descriptor, occupied_descriptors=set(descriptors)))
            if oauth_application_descriptor is None:
                raise RuntimeError("OAuth cold startup configuration is unavailable")
            descriptors.extend(_open_oauth_application_material(
                oauth_application_descriptor, occupied_descriptors=set(descriptors)))
            if oauth_revocation_descriptor is None:
                raise RuntimeError("OAuth cleanup cold configuration is unavailable")
            descriptors.extend(_open_oauth_revocation_material(
                oauth_revocation_descriptor, occupied_descriptors=set(descriptors)))
            if oauth_refresh_cleanup_descriptor is None:
                raise RuntimeError("OAuth family retirement cold configuration is unavailable")
            descriptors.extend(_open_oauth_refresh_cleanup_material(
                oauth_refresh_cleanup_descriptor, occupied_descriptors=set(descriptors)))
            if measured_audit_descriptor is None:
                raise RuntimeError("measured audit cold configuration is unavailable")
            descriptors.extend(_open_measured_audit_material(measured_audit_descriptor, occupied_descriptors=set(descriptors)))
            if custody_configuration_descriptor is None:
                raise RuntimeError("control-plane custody startup configuration is unavailable")
            custody_shape = _control_plane_custody_configuration(custody_configuration_descriptor)
            if (custody_shape["schema"] == "serverware.controlPlaneCustodyStartup/v3") != genesis_maintenance:
                raise RuntimeError("maintenance command and original custody profile must be explicitly paired")
            custody_configuration, custody_directory = _open_control_plane_custody(
                custody_configuration_descriptor, occupied_descriptors=set(descriptors))
            descriptors.extend((custody_configuration, custody_directory))
            environment[CONTROL_PLANE_CUSTODY_CONFIG_NAME] = str(custody_configuration)
            descriptors.remove(custody_configuration_descriptor)
            os.close(custody_configuration_descriptor)
            if enrollment_bootstrap_descriptor is None:
                raise RuntimeError("control-plane enrollment bootstrap is unavailable")
            enrollment_key = _open_control_plane_enrollment_key(
                enrollment_bootstrap_descriptor, occupied_descriptors=set(descriptors))
            if enrollment_key is not None:
                descriptors.append(enrollment_key)
            execution_key = _open_control_plane_registration_execution_key(
                enrollment_bootstrap_descriptor, occupied_descriptors=set(descriptors))
            if execution_key is not None:
                descriptors.append(execution_key)
            finalization_key = _open_control_plane_registration_finalization_key(
                enrollment_bootstrap_descriptor, occupied_descriptors=set(descriptors))
            if finalization_key is not None:
                descriptors.append(finalization_key)
            activation_key = _open_control_plane_oidc_session_activation_key(
                enrollment_bootstrap_descriptor, occupied_descriptors=set(descriptors))
            if activation_key is not None:
                descriptors.append(activation_key)
            consume_key = _open_control_plane_oidc_session_activation_consume_key(
                enrollment_bootstrap_descriptor, occupied_descriptors=set(descriptors))
            if consume_key is not None:
                descriptors.append(consume_key)
            intent_key = _open_control_plane_oidc_session_activation_release_intent_key(
                enrollment_bootstrap_descriptor, occupied_descriptors=set(descriptors))
            if intent_key is not None:
                descriptors.append(intent_key)
            revocation_key = _open_control_plane_public_revocation_key(
                enrollment_bootstrap_descriptor, occupied_descriptors=set(descriptors))
            if revocation_key is not None:
                descriptors.append(revocation_key)
            environment["SERVERWARE_PROCESS_MODE"] = PROCESS_MODES[role]
            _drop_identity(role)
            os.execve(
                "/runtime/python/bin/python3",
                [
                    "/runtime/python/bin/python3",
                    "-P",
                    "-s",
                    "-m",
                    "serverware.control_plane_policy_genesis_runner" if genesis_maintenance else "serverware.control_plane_runner",
                ],
                environment,
            )
        launcher_descriptor = _open_source(
            BOOTSTRAP_LAUNCHER_PATH,
            expected_owner_uid=0,
        )
        descriptors.append(launcher_descriptor)
        launcher_arguments = [
            "/runtime/python/bin/python3",
            "-I",
            "-P",
            "-s",
            "-S",
            "-E",
            f"/proc/self/fd/{launcher_descriptor}",
            "--bootstrap-fd",
            str(launcher_descriptor),
            "--trusted-host-local",
        ]
        if local_admission is not None:
            setup_fd, setup_digest, channel_fd = local_admission
            launcher_arguments.extend(["--local-admission-fd", str(setup_fd),
                "--local-admission-sha256", setup_digest,
                "--local-admission-channel-fd", str(channel_fd)])
        for environment_name, descriptor in descriptor_assignments:
            launcher_arguments.extend(
                [
                    "--descriptor",
                    f"{environment_name}={descriptor}",
                ]
            )
        if public_revocation:
            launcher_arguments.append("--public-webauthn-revocation")
        launcher_arguments.append(role)
        os.execve(
            "/runtime/python/bin/python3",
            launcher_arguments,
            environment,
        )
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
    return 1


def main() -> int:
    if (len(sys.argv) == 8 and sys.argv[1] in ROLE_SOURCES
            and sys.argv[2::2] == ["--local-admission-fd", "--local-admission-sha256", "--local-admission-channel-fd"]):
        try:
            setup_fd, channel_fd = int(sys.argv[3]), int(sys.argv[7])
        except ValueError as exc:
            raise RuntimeError("local admission descriptor is invalid") from exc
        if str(setup_fd) != sys.argv[3] or str(channel_fd) != sys.argv[7]:
            raise RuntimeError("local admission descriptor is not canonical")
        return _normal_main(sys.argv[1], local_admission=(setup_fd, sys.argv[5], channel_fd))
    if sys.argv[1:] in (["control-plane", "--setup-native-observation"],
            ["control-plane", "--policy-canary-intake", "--setup-native-observation"]):
        return _normal_main("control-plane", setup_native_observation=True, policy_canary_intake=len(sys.argv) == 4)
    if len(sys.argv) == 3 and sys.argv[1:] == ["control-plane", "--policy-canary-intake"]:
        return _normal_main("control-plane", policy_canary_intake=True)
    if len(sys.argv) == 3 and sys.argv[1:] == ["control-plane", "--policy-file-genesis-maintenance"]:
        return _normal_main("control-plane", genesis_maintenance=True)
    if (len(sys.argv) == 3 and sys.argv[2] == "--public-webauthn-revocation"
            and sys.argv[1] in {"verifier", "issuer", "executor"}):
        return _normal_main(sys.argv[1], public_revocation=True)
    if len(sys.argv) == 2 and sys.argv[1] == "witness-init":
        raise RuntimeError(
            "legacy witness ledger initialization is forbidden; "
            "native stage zero must retain the signed mutable-state directory"
        )
    if len(sys.argv) == 2 and sys.argv[1] == "control-plane-health":
        return _control_plane_health()
    if (
        len(sys.argv) >= 3
        and sys.argv[1] == "socket-health"
        and all(role in ROLE_SOCKET_PATHS for role in sys.argv[2:])
    ):
        if os.geteuid() == 0:
            _drop_identity(sys.argv[2])
        for role in sys.argv[2:]:
            _socket_health(role)
        return 0
    if len(sys.argv) != 2 or sys.argv[1] not in ROLE_SOURCES:
        raise RuntimeError("authority descriptor role is invalid")
    return _normal_main(sys.argv[1])


if __name__ == "__main__":
    raise SystemExit(main())
