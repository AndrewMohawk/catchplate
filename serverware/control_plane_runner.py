from __future__ import annotations


def main() -> None:
    # Admit the exact inherited descriptor inventory before importing the
    # application, database configuration or HTTP runtime. Those imports and
    # startup may legitimately open descriptors which are not inherited trust.
    from serverware import control_plane_custody_startup as custody_startup
    enrollment_startup = None

    try:
        custody_startup.initialize_from_environment()
        # Reuse that admitted root and original FD inventory; the custody
        # journal has now opened a private handle, so never repeat admission.
        from serverware import control_plane_enrollment_startup as enrollment_startup
        enrollment_startup.initialize_from_environment()

        import uvicorn
        from serverware.config import WEB_HOST, WEB_PORT, WEB_TLS_CERT_FILE, WEB_TLS_KEY_FILE
        from serverware.control_plane_startup import validate_control_plane_startup
        from serverware.signed_http import SignedOnlyHttpToolsProtocol, validate_signed_http_protocol

        validate_control_plane_startup()
        validate_signed_http_protocol()
        uvicorn.run(
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
    except BaseException:
        # Preserve the original launch/runtime error if cleanup also fails.
        try:
            if enrollment_startup is not None:
                enrollment_startup.close()
        except BaseException:
            pass
        try:
            custody_startup.close()
        except BaseException:
            pass
        raise
    else:
        try:
            enrollment_startup.close()
        finally:
            custody_startup.close()


if __name__ == "__main__":
    main()
