from __future__ import annotations

import os

from serverware import db
from serverware.attestation import quote_public_key_info
from serverware.ca_material import ensure_mitm_ca_material
from serverware.config import (
    ATOMIC_RELEASE_AUTHORIZATION_ENABLED,
    CONTROL_PLANE_MUTATION_ALLOWED_AUTHENTICATOR_CLASSES,
    CONTROL_PLANE_MUTATION_REQUIRE_HARDWARE_ATTESTATION,
    CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED,
    CONTROL_PLANE_TWO_PERSON_ACTIONS,
    CONTROL_PLANE_TWO_PERSON_REQUIRED,
    DEV_AUTHENTICATOR_ENABLED,
    DIRECT_CA_DOWNLOAD_ENABLED,
    MASTER_KEY_UNSEAL_COMMAND,
    NITRO_NSM_UNSEAL_COMMAND_TEMPLATE,
    OIDC_SESSION_WEBAUTHN_REQUIRED,
    POLICY_CANARY_MAX_DENIALS,
    POLICY_CANARY_MIN_AUDIT_EVENTS,
    POLICY_CANARY_MIN_OBSERVATION_SECONDS,
    POLICY_CANARY_REQUIRED,
    POLICY_PUBLISH_DRY_RUN_REQUIRED,
    PRODUCTION_IMAGE,
    RELEASE_CHANNEL,
    RELEASE_AUTHORIZATION_RECONCILE_LIMIT,
    WEBAUTHN_BOOTSTRAP_TOKEN,
    WEBAUTHN_RECOVERY_ENABLED,
    WEB_TLS_CERT_FILE,
    WEB_TLS_KEY_FILE,
    ensure_data_dirs,
    validate_internal_service_auth,
)
from serverware.policy_bundle import (
    enforce_policy_high_water,
    get_policy_snapshot,
    policy_uses_atomic_release_authorization,
    policy_public_key_hash,
)
from serverware.response_identity import response_public_key_info
from serverware.setup_receipt_service import (
    SetupReceiptTrustConfigurationError,
    setup_receipt_trust_profile,
)
from serverware.webauthn import (
    WebAuthnError,
    validate_webauthn_recovery_configuration,
)
from serverware.webauthn_trust import reconcile_trust_publications
from serverware.webauthn_trust import trust_public_key_hash


_DEVELOPMENT_RELEASE_CHANNELS = {"dev", "development", "local", "test"}
_STARTUP_VALIDATED_PID_ENV = "SERVERWARE_CONTROL_PLANE_STARTUP_VALIDATED_PID"
_PRODUCTION_TWO_PERSON_ACTIONS = {
    "credential.create",
    "credential.oauth.activate",
    "credential.oauth.uncertain.resolve",
    "credential.update",
    "credential.delete",
    "route.create",
    "route.update",
    "route.delete",
    "policy.publish",
    "webauthn.credential.register",
    "webauthn.credential.revoke",
    "webauthn.trust.publish",
    "rbac.role.change",
    "rbac.deprovision",
    "control_plane.token.rotate",
    "break_glass.grant",
    "setup.attestation.finalize",
}


def control_plane_startup_required() -> bool:
    return os.getenv(_STARTUP_VALIDATED_PID_ENV) != str(os.getpid())


def production_release() -> bool:
    return RELEASE_CHANNEL.strip().lower() not in _DEVELOPMENT_RELEASE_CHANNELS


def validate_control_plane_configuration() -> None:
    """Validate launch-invariant configuration before starting any workers."""
    from serverware import control_plane_custody_startup
    from serverware import control_plane_enrollment_startup

    # Production and explicitly configured development must have completed
    # cold admission in the runner, never lazily after imports or DB startup.
    control_plane_custody_startup.require_started()
    enrollment_owner = control_plane_enrollment_startup.require_started()
    production = production_release()
    if PRODUCTION_IMAGE and not production:
        raise RuntimeError(
            "the production control-plane image requires a non-development release channel"
        )
    if bool(WEB_TLS_CERT_FILE) != bool(WEB_TLS_KEY_FILE):
        raise RuntimeError(
            "SERVERWARE_WEB_TLS_CERT_FILE and SERVERWARE_WEB_TLS_KEY_FILE must be set together"
        )
    if production and not WEB_TLS_CERT_FILE:
        raise RuntimeError("production control plane requires configured TLS certificate and key")

    validate_internal_service_auth()
    try:
        online_key_ids = (
            {
                "response signing key": response_public_key_info()["spki_sha256"],
                "policy signing key": policy_public_key_hash(),
                "development quote signing key": quote_public_key_info()[
                    "spki_sha256"
                ],
                "WebAuthn trust signing key": trust_public_key_hash(),
            }
            if WEBAUTHN_RECOVERY_ENABLED
            else {}
        )
        validate_webauthn_recovery_configuration(
            production=production,
            additional_online_key_ids=online_key_ids,
        )
        if WEBAUTHN_RECOVERY_ENABLED:
            db.require_independent_recovery_witness(production=production)
    except (WebAuthnError, db.RecoveryWitnessError) as exc:
        raise RuntimeError(
            "WebAuthn recovery is not securely configured"
        ) from exc
    if not production:
        return

    if len(WEBAUTHN_BOOTSTRAP_TOKEN) < 32:
        raise RuntimeError(
            "production requires SERVERWARE_WEBAUTHN_BOOTSTRAP_TOKEN with at least 32 characters"
        )
    if not CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED:
        raise RuntimeError("production requires control-plane WebAuthn mutation authorization")
    if not OIDC_SESSION_WEBAUTHN_REQUIRED:
        raise RuntimeError("production requires WebAuthn-bound OIDC browser sessions")
    if not CONTROL_PLANE_MUTATION_REQUIRE_HARDWARE_ATTESTATION:
        raise RuntimeError(
            "production requires hardware-attested control-plane WebAuthn authorization"
        )
    allowed_authenticator_classes = set(
        CONTROL_PLANE_MUTATION_ALLOWED_AUTHENTICATOR_CLASSES
    )
    if not allowed_authenticator_classes or not allowed_authenticator_classes.issubset(
        {"yubikey", "hardware"}
    ):
        raise RuntimeError(
            "production control-plane WebAuthn authenticator classes must be limited "
            "to yubikey and hardware"
        )
    if not CONTROL_PLANE_TWO_PERSON_REQUIRED:
        raise RuntimeError("production requires two-person control-plane authorization")
    configured_actions = set(CONTROL_PLANE_TWO_PERSON_ACTIONS)
    required_actions = set(_PRODUCTION_TWO_PERSON_ACTIONS)
    # Only the actual root-admitted cold owner enables this distinct purpose;
    # evidence-only v2 and an explicitly disabled owner keep the old action set.
    if enrollment_owner is not None and enrollment_owner.execution_enabled:
        required_actions.add("webauthn.registration.execution.prepare")
    if "*" not in configured_actions and not required_actions.issubset(
        configured_actions
    ):
        missing = sorted(required_actions - configured_actions)
        raise RuntimeError(
            "production two-person control is missing mandatory actions: "
            + ", ".join(missing)
        )
    if DEV_AUTHENTICATOR_ENABLED:
        raise RuntimeError("production forbids the development authenticator and demo seed")
    if DIRECT_CA_DOWNLOAD_ENABLED:
        raise RuntimeError(
            "production forbids direct CA download; use verifier-mediated install sessions"
        )
    if not POLICY_PUBLISH_DRY_RUN_REQUIRED:
        raise RuntimeError("production policy publishing requires dry-run decision tests")
    if not POLICY_CANARY_REQUIRED:
        raise RuntimeError("production policy publishing requires canary activation")
    if POLICY_CANARY_MIN_OBSERVATION_SECONDS <= 0:
        raise RuntimeError("production policy canaries require a positive observation window")
    if POLICY_CANARY_MIN_AUDIT_EVENTS <= 0:
        raise RuntimeError("production policy canaries require audit evidence")
    if POLICY_CANARY_MAX_DENIALS != 0:
        raise RuntimeError("production policy canaries must fail on every denial")
    if not MASTER_KEY_UNSEAL_COMMAND:
        raise RuntimeError("production requires SERVERWARE_MASTER_KEY_UNSEAL_COMMAND")
    if not NITRO_NSM_UNSEAL_COMMAND_TEMPLATE:
        raise RuntimeError("production requires SERVERWARE_NITRO_NSM_UNSEAL_COMMAND_TEMPLATE")
    try:
        setup_receipt_trust_profile()
    except SetupReceiptTrustConfigurationError as exc:
        raise RuntimeError(
            "production setup receipt trust roots are not securely configured"
        ) from exc


def validate_control_plane_startup() -> None:
    """Apply the common configuration and persistent-state startup gate."""
    validate_control_plane_configuration()
    ensure_data_dirs()
    db.init_db()
    if OIDC_SESSION_WEBAUTHN_REQUIRED:
        db.revoke_unbound_oidc_browser_sessions(
            actor_id="system:startup",
            reason="WebAuthn-bound OIDC browser sessions are required",
        )
    try:
        reconcile_trust_publications()
    except Exception as exc:
        raise RuntimeError(
            "control plane could not reconcile WebAuthn trust publication"
        ) from exc
    metadata_audit_delivery = db.drain_metadata_audit_outbox_fully(
        limit=500, max_batches=200 if production_release() else 1
    )
    if production_release():
        if (
            metadata_audit_delivery["failed"] > 0
            or metadata_audit_delivery["pending"] > 0
        ):
            raise RuntimeError(
                "production control plane requires complete metadata audit outbox delivery"
            )
    if production_release():
        audit_verification = db.verify_audit_chain()
        if (
            audit_verification.get("ok") is not True
            or audit_verification.get("complete") is not True
        ):
            raise RuntimeError(
                "production control plane requires a complete verified audit chain"
            )
    snapshot = get_policy_snapshot()
    if snapshot is None and production_release():
        raise RuntimeError("production control plane requires an active signed policy bundle")
    if snapshot is not None:
        enforce_policy_high_water(snapshot)
        if production_release() and policy_uses_atomic_release_authorization(snapshot):
            try:
                db.require_atomic_release_writer()
            except db.ReleaseAuthorizationError as exc:
                raise RuntimeError(
                    "production atomic release authorization requires metadata and "
                    "grant stores on the same writer DSN and schema"
                ) from exc
    if ATOMIC_RELEASE_AUTHORIZATION_ENABLED:
        db.require_atomic_release_writer()
        db.reconcile_release_authorizations(
            limit=RELEASE_AUTHORIZATION_RECONCILE_LIMIT
        )
        db.drain_release_authorization_audit_outbox(
            RELEASE_AUTHORIZATION_RECONCILE_LIMIT
        )
    ensure_mitm_ca_material()
    os.environ[_STARTUP_VALIDATED_PID_ENV] = str(os.getpid())
