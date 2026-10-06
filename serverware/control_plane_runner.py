from __future__ import annotations


def main() -> None:
    # Admit the exact inherited descriptor inventory before importing the
    # application, database configuration or HTTP runtime. Those imports and
    # startup may legitimately open descriptors which are not inherited trust.
    from serverware import control_plane_custody_startup as custody_startup
    enrollment_startup = None
    workload_identity_startup = None
    oauth_application_startup = None
    oauth_revocation_startup = None
    oauth_refresh_cleanup_startup = None
    measured_audit_startup = None
    policy_canary_startup = None
    rbac_currentness_startup = None
    static_credential_startup = None

    try:
        custody_startup.initialize_from_environment()
        if custody_startup.genesis_maintenance_configuration() is not None:
            raise RuntimeError("genesis maintenance requires its distinct cold runner; normal startup is forbidden")
        # Reuse that admitted root and original FD inventory; the custody
        # journal has now opened a private handle, so never repeat admission.
        from serverware import control_plane_enrollment_startup as enrollment_startup
        enrollment_startup.initialize_from_environment()
        from serverware import control_plane_workload_identity_startup as workload_identity_startup
        workload_identity_startup.initialize_from_environment()
        from serverware import oauth_application_owner as oauth_application_startup
        oauth_application_startup.initialize_from_environment()
        from serverware import control_plane_oauth_revocation as oauth_revocation_startup
        oauth_revocation_startup.initialize_from_environment()
        from serverware import control_plane_oauth_refresh_cleanup as oauth_refresh_cleanup_startup
        oauth_refresh_cleanup_startup.initialize_from_environment()
        from serverware import control_plane_data_plane_audit as measured_audit_startup
        measured_audit_startup.initialize_from_environment()
        from serverware import control_plane_policy_canary_startup as policy_canary_startup
        policy_canary_startup.initialize_from_environment()
        from serverware import control_plane_rbac_currentness as rbac_currentness_startup
        rbac_currentness_startup.initialize_from_environment()
        from serverware import control_plane_static_credential as static_credential_startup
        static_credential_startup.initialize_from_environment()

        import uvicorn
        from serverware.config import WEB_HOST, WEB_PORT, WEB_TLS_CERT_FILE, WEB_TLS_KEY_FILE
        from serverware.control_plane_startup import validate_control_plane_startup
        from serverware.signed_http import SignedOnlyHttpToolsProtocol, validate_signed_http_protocol

        validate_control_plane_startup()
        validate_signed_http_protocol()
        configuration = uvicorn.Config(
            "serverware.app:app",
            host=WEB_HOST,
            port=WEB_PORT,
            log_level="info",
            http=SignedOnlyHttpToolsProtocol,
            ws="none",
            server_header=False,
            date_header=False,
            ssl_certfile=WEB_TLS_CERT_FILE or None,
            ssl_keyfile=WEB_TLS_KEY_FILE or None,
        )
        configuration.load()
        measured_audit_startup.configure_tls(configuration.ssl)
        policy_canary_startup.configure_tls(configuration.ssl)
        uvicorn.Server(configuration).run()
    except BaseException:
        # Preserve the original launch/runtime error if cleanup also fails.
        for owner in (static_credential_startup, rbac_currentness_startup, policy_canary_startup, measured_audit_startup, oauth_refresh_cleanup_startup, oauth_revocation_startup, oauth_application_startup, workload_identity_startup, enrollment_startup, custody_startup):
            try:
                if owner is not None:
                    owner.close()
            except BaseException:
                pass
        raise
    else:
        _close_remaining(static_credential_startup, rbac_currentness_startup, policy_canary_startup, measured_audit_startup,
            oauth_refresh_cleanup_startup, oauth_revocation_startup, oauth_application_startup,
            workload_identity_startup, enrollment_startup, custody_startup)


def _close_remaining(*owners):
    first_error = None
    for owner in owners:
        try:
            owner.close()
        except BaseException as exc:
            if first_error is None:
                first_error = exc
    if first_error is not None:
        raise first_error


if __name__ == "__main__":
    main()
