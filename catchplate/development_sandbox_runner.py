"""Dedicated opt-in entrypoint; never used by the normal or production image."""
from __future__ import annotations
import os
from pathlib import Path


def require_complete_migration() -> None:
    marker = Path(os.environ.get("CATCHPLATE_DATA_DIR", "/data")) / "rebrand-incomplete.json"
    try:
        marker.lstat()
    except FileNotFoundError:
        return
    raise RuntimeError("incomplete Catchplate sandbox migration; preserve the staged store and do not start it")


def main() -> None:
    os.umask(0o077)
    require_complete_migration()
    if os.getenv("CATCHPLATE_DEVELOPMENT_SANDBOX") != "1":
        raise RuntimeError("explicit CATCHPLATE_DEVELOPMENT_SANDBOX=1 is required")
    defaults = {
        "CATCHPLATE_RELEASE_CHANNEL": "dev",
        "CATCHPLATE_PROCESS_MODE": "catchplate-control-plane",
        "CATCHPLATE_METADATA_STORE_BACKEND": "sqlite",
        "CATCHPLATE_AUDIT_STORE_BACKEND": "sqlite",
        "CATCHPLATE_GRANT_STORE_BACKEND": "sqlite",
        "CATCHPLATE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED": "0",
        "CATCHPLATE_KEY_RELEASE_REQUIRED": "0",
        "CATCHPLATE_DEV_AUTHENTICATOR": "1",
        "CATCHPLATE_DEV_DEMO_SEED": "1",
    }
    for name, value in defaults.items():
        os.environ.setdefault(name, value)
    from catchplate import development_sandbox
    development_sandbox.activate()
    from catchplate.control_plane_runner import main as run_control_plane
    run_control_plane()


if __name__ == "__main__":
    main()
