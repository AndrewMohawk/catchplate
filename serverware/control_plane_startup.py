from __future__ import annotations

from serverware import db
from serverware.ca_material import ensure_mitm_ca_material
from serverware.config import (
    ATOMIC_RELEASE_AUTHORIZATION_ENABLED,
    CONTROL_PLANE_MUTATION_ALLOWED_AUTHENTICATOR_CLASSES,
    CONTROL_PLANE_MUTATION_REQUIRE_HARDWARE_ATTESTATION,
    CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED,
    CONTROL_PLANE_TWO_PERSON_REQUIRED,
    MASTER_KEY_UNSEAL_COMMAND,
    NITRO_NSM_UNSEAL_COMMAND_TEMPLATE,
    RELEASE_CHANNEL,
    RELEASE_AUTHORIZATION_RECONCILE_LIMIT,
    WEBAUTHN_BOOTSTRAP_TOKEN,
    WEB_TLS_CERT_FILE,
    WEB_TLS_KEY_FILE,
    ensure_data_dirs,
    validate_internal_service_auth,
)
from serverware.policy_bundle import (
    enforce_policy_high_water,
    get_policy_snapshot,
    policy_uses_atomic_release_authorization,
)
from serverware.setup_receipt_service import (
    SetupReceiptTrustConfigurationError,
    setup_receipt_trust_profile,
)


_DEVELOPMENT_RELEASE_CHANNELS = {"dev", "development", "local", "test"}


def production_release() -> bool:
    return RELEASE_CHANNEL.strip().lower() not in _DEVELOPMENT_RELEASE_CHANNELS


def validate_control_plane_configuration() -> None:
    """Validate launch-invariant configuration before starting any workers."""
    production = production_release()
    if bool(WEB_TLS_CERT_FILE) != bool(WEB_TLS_KEY_FILE):
        raise RuntimeError(
            "SERVERWARE_WEB_TLS_CERT_FILE and SERVERWARE_WEB_TLS_KEY_FILE must be set together"
        )
    if production and not WEB_TLS_CERT_FILE:
        raise RuntimeError("production control plane requires configured TLS certificate and key")

    validate_internal_service_auth()
    if not production:
        return

    if len(WEBAUTHN_BOOTSTRAP_TOKEN) < 32:
        raise RuntimeError(
            "production requires SERVERWARE_WEBAUTHN_BOOTSTRAP_TOKEN with at least 32 characters"
        )
    if not CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED:
        raise RuntimeError("production requires control-plane WebAuthn mutation authorization")
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
