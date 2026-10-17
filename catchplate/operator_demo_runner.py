"""Deliberate non-production operator-demo entrypoint, separate from the synthetic fixture."""
import os
from pathlib import Path


def require_complete_migration() -> None:
    """Never admit a partially imported store, including a dangling marker."""
    marker = Path(os.environ.get("CATCHPLATE_DATA_DIR", "/data")) / "rebrand-incomplete.json"
    try:
        marker.lstat()
    except FileNotFoundError:
        return
    raise RuntimeError("incomplete Catchplate migration; preserve the staged store and do not start it")


def main() -> None:
    os.umask(0o077)
    require_complete_migration()
    if os.getenv("CATCHPLATE_OPERATOR_DEMO") != "1":
        raise RuntimeError("explicit CATCHPLATE_OPERATOR_DEMO=1 is required")
    managed = os.getenv("CATCHPLATE_OPERATOR_MANAGED_GOOGLE_ENABLED", "0")
    if managed not in {"0", "1"}:
        raise RuntimeError("operator Google profile refused")
    defaults = {
        "CATCHPLATE_RELEASE_CHANNEL": "dev", "CATCHPLATE_PROCESS_MODE": "catchplate-control-plane",
        "CATCHPLATE_METADATA_STORE_BACKEND": "sqlite", "CATCHPLATE_AUDIT_STORE_BACKEND": "sqlite",
        "CATCHPLATE_GRANT_STORE_BACKEND": "sqlite", "CATCHPLATE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED": "0",
        "CATCHPLATE_KEY_RELEASE_REQUIRED": "0", "CATCHPLATE_DEV_AUTHENTICATOR": "0",
        "CATCHPLATE_DEV_DEMO_SEED": "0",
    }
    if managed == "1":
        # Managed admission observes the actual deployment configuration. It
        # must not manufacture missing ownership flags or legacy Google env.
        from catchplate import operator_google_managed_config
        operator_google_managed_config.bootstrap()
    else:
        for name, value in defaults.items():
            os.environ.setdefault(name, value)
    from catchplate import operator_demo
    operator_demo.activate()
    from catchplate.control_plane_runner import main as run
    run()


if __name__ == "__main__":
    main()
