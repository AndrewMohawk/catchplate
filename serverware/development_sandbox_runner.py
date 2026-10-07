"""Dedicated opt-in entrypoint; never used by the normal or production image."""
from __future__ import annotations
import os


def main() -> None:
    os.umask(0o077)
    if os.getenv("SERVERWARE_DEVELOPMENT_SANDBOX") != "1":
        raise RuntimeError("explicit SERVERWARE_DEVELOPMENT_SANDBOX=1 is required")
    defaults = {
        "SERVERWARE_RELEASE_CHANNEL": "dev",
        "SERVERWARE_PROCESS_MODE": "serverware-control-plane",
        "SERVERWARE_METADATA_STORE_BACKEND": "sqlite",
        "SERVERWARE_AUDIT_STORE_BACKEND": "sqlite",
        "SERVERWARE_GRANT_STORE_BACKEND": "sqlite",
        "SERVERWARE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED": "0",
        "SERVERWARE_KEY_RELEASE_REQUIRED": "0",
        "SERVERWARE_DEV_AUTHENTICATOR": "1",
        "SERVERWARE_DEV_DEMO_SEED": "1",
    }
    for name, value in defaults.items():
        os.environ.setdefault(name, value)
    from serverware import development_sandbox
    development_sandbox.activate()
    from serverware.control_plane_runner import main as run_control_plane
    run_control_plane()


if __name__ == "__main__":
    main()
