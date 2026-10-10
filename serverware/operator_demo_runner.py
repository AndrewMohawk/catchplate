"""Deliberate non-production operator-demo entrypoint, separate from the synthetic fixture."""
import os


def main() -> None:
    os.umask(0o077)
    if os.getenv("SERVERWARE_OPERATOR_DEMO") != "1":
        raise RuntimeError("explicit SERVERWARE_OPERATOR_DEMO=1 is required")
    managed = os.getenv("SERVERWARE_OPERATOR_MANAGED_GOOGLE_ENABLED", "0")
    if managed not in {"0", "1"}:
        raise RuntimeError("operator Google profile refused")
    defaults = {
        "SERVERWARE_RELEASE_CHANNEL": "dev", "SERVERWARE_PROCESS_MODE": "serverware-control-plane",
        "SERVERWARE_METADATA_STORE_BACKEND": "sqlite", "SERVERWARE_AUDIT_STORE_BACKEND": "sqlite",
        "SERVERWARE_GRANT_STORE_BACKEND": "sqlite", "SERVERWARE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED": "0",
        "SERVERWARE_KEY_RELEASE_REQUIRED": "0", "SERVERWARE_DEV_AUTHENTICATOR": "0",
        "SERVERWARE_DEV_DEMO_SEED": "0",
    }
    if managed == "1":
        # Managed admission observes the actual deployment configuration. It
        # must not manufacture missing ownership flags or legacy Google env.
        from serverware import operator_google_managed_config
        operator_google_managed_config.bootstrap()
    else:
        for name, value in defaults.items():
            os.environ.setdefault(name, value)
    from serverware import operator_demo
    operator_demo.activate()
    from serverware.control_plane_runner import main as run
    run()


if __name__ == "__main__":
    main()
