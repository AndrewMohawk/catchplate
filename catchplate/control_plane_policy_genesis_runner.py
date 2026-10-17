"""Explicit production maintenance entrypoint; no fallback policy or workers."""
from __future__ import annotations


def main():
    owners = []
    failed = False
    try:
        # The exact inherited inventory must be admitted before any other IO.
        from catchplate import control_plane_custody_startup as custody
        owners.append(custody)
        custody.initialize_from_environment()
        if custody.genesis_maintenance_configuration() is None:
            raise RuntimeError("maintenance requires the original root-signed v3 cold profile")
        from catchplate import control_plane_enrollment_startup as enrollment
        owners.append(enrollment)
        enrollment.initialize_from_environment()
        from catchplate import control_plane_workload_identity_startup as workload
        owners.append(workload)
        workload.initialize_from_environment()
        from catchplate import control_plane_rbac_currentness as rbac
        owners.append(rbac)
        rbac.initialize_from_environment()
        from catchplate import control_plane_startup as startup, db
        if not startup.production_release():
            raise RuntimeError("genesis maintenance never substitutes development identities")
        startup.validate_control_plane_configuration()
        # Validate the existing protected store, not its policy-file loader or
        # broad reconciliation/worker/CA startup. No genesis is created here.
        db.init_db()
        from catchplate import control_plane_policy_genesis_maintenance as maintenance
        owners.append(maintenance)
        owner = maintenance.initialize_from_started()
        application = maintenance.MaintenanceApplication(owner)
        import uvicorn
        from catchplate.config import WEB_HOST, WEB_PORT, WEB_TLS_CERT_FILE, WEB_TLS_KEY_FILE
        from catchplate.signed_http import SignedOnlyHttpToolsProtocol, validate_signed_http_protocol
        validate_signed_http_protocol()
        configuration = uvicorn.Config(application, host=WEB_HOST, port=WEB_PORT, log_level="info",
            http=SignedOnlyHttpToolsProtocol, ws="none", server_header=False, date_header=False,
            ssl_certfile=WEB_TLS_CERT_FILE, ssl_keyfile=WEB_TLS_KEY_FILE, lifespan="on")
        configuration.load()
        owner.check()
        uvicorn.Server(configuration).run()
    except BaseException:
        failed = True
        raise
    finally:
        first = None
        for module in reversed(owners):
            try:
                module.close()
            except BaseException as exc:
                if first is None:
                    first = exc
        if first is not None and not failed:
            raise first


if __name__ == "__main__":
    main()
