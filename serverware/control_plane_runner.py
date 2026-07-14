from __future__ import annotations

import uvicorn

from serverware.ca_material import ensure_mitm_ca_material
from serverware.config import (
    CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED,
    CONTROL_PLANE_TWO_PERSON_REQUIRED,
    MASTER_KEY_UNSEAL_COMMAND,
    NITRO_NSM_UNSEAL_COMMAND_TEMPLATE,
    RELEASE_CHANNEL,
    WEBAUTHN_BOOTSTRAP_TOKEN,
    WEB_HOST,
    WEB_PORT,
    WEB_TLS_CERT_FILE,
    WEB_TLS_KEY_FILE,
    ensure_data_dirs,
)
from serverware.db import init_db
from serverware.policy_bundle import enforce_policy_high_water, get_policy_snapshot


def main() -> None:
    ensure_data_dirs()
    init_db()
    snapshot = get_policy_snapshot()
    production = RELEASE_CHANNEL.strip().lower() not in {"dev", "development", "local", "test"}
    if snapshot is None and production:
        raise RuntimeError("production control plane requires an active signed policy bundle")
    if snapshot is not None:
        enforce_policy_high_water(snapshot)
    ensure_mitm_ca_material()
    if bool(WEB_TLS_CERT_FILE) != bool(WEB_TLS_KEY_FILE):
        raise RuntimeError("SERVERWARE_WEB_TLS_CERT_FILE and SERVERWARE_WEB_TLS_KEY_FILE must be set together")
    if RELEASE_CHANNEL.strip().lower() not in {"dev", "development"} and not WEB_TLS_CERT_FILE:
        raise RuntimeError("production control plane requires configured TLS certificate and key")
    if production:
        if len(WEBAUTHN_BOOTSTRAP_TOKEN) < 32:
            raise RuntimeError("production requires SERVERWARE_WEBAUTHN_BOOTSTRAP_TOKEN with at least 32 characters")
        if not CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED:
            raise RuntimeError("production requires control-plane WebAuthn mutation authorization")
        if not CONTROL_PLANE_TWO_PERSON_REQUIRED:
            raise RuntimeError("production requires two-person control-plane authorization")
        if not MASTER_KEY_UNSEAL_COMMAND:
            raise RuntimeError("production requires SERVERWARE_MASTER_KEY_UNSEAL_COMMAND")
        if not NITRO_NSM_UNSEAL_COMMAND_TEMPLATE:
            raise RuntimeError("production requires SERVERWARE_NITRO_NSM_UNSEAL_COMMAND_TEMPLATE")
    uvicorn.run(
        "serverware.app:app",
        host=WEB_HOST,
        port=WEB_PORT,
        log_level="info",
        ssl_certfile=WEB_TLS_CERT_FILE or None,
        ssl_keyfile=WEB_TLS_KEY_FILE or None,
    )


if __name__ == "__main__":
    main()
