from __future__ import annotations

import uvicorn

from serverware.config import (
    WEB_HOST,
    WEB_PORT,
    WEB_TLS_CERT_FILE,
    WEB_TLS_KEY_FILE,
)
from serverware.control_plane_startup import validate_control_plane_startup
from serverware.signed_http import (
    SignedOnlyHttpToolsProtocol,
    validate_signed_http_protocol,
)


def main() -> None:
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


if __name__ == "__main__":
    main()
