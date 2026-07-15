from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import uvicorn
from serverware.ca_material import ensure_mitm_ca_material
from serverware.config import (
    DATA_PLANE_GID,
    DATA_PLANE_UID,
    DECISION_GATE_CA_CERT_PATH,
    DECISION_GATE_CA_KEY_PATH,
    MITMPROXY_CONF_DIR,
    PROXY_HOST,
    PROXY_PORT,
    RELEASE_CHANNEL,
    WEB_HOST,
    WEB_PORT,
    ensure_data_dirs,
)
from serverware.db import init_db


_DEVELOPMENT_RELEASE_CHANNELS = {"dev", "development", "local", "test"}


def _require_development_release_channel() -> None:
    if RELEASE_CHANNEL.strip().lower() not in _DEVELOPMENT_RELEASE_CHANNELS:
        raise RuntimeError(
            "legacy Python mitmproxy transport is development-only; "
            "use the Rust decision gate for non-development release channels"
        )


_require_development_release_channel()


def _mitmdump_command() -> list[str]:
    addon_path = Path(__file__).with_name("mitm_addon.py")
    return [
        "mitmdump",
        "--listen-host",
        PROXY_HOST,
        "--listen-port",
        str(PROXY_PORT),
        "--set",
        f"confdir={MITMPROXY_CONF_DIR}",
        "--set",
        "rawtcp=false",
        "--set",
        "connection_strategy=lazy",
        "--set",
        "ssl_insecure=false",
        "--set",
        "block_global=false",
        "-s",
        str(addon_path),
    ]


def start_mitmdump() -> subprocess.Popen:
    _require_development_release_channel()
    env = os.environ.copy()
    env["PYTHONPATH"] = f"/app:{env.get('PYTHONPATH', '')}"
    return subprocess.Popen(_mitmdump_command(), env=env)


def _write_owned(path: Path, data: bytes, *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_bytes(data)
    try:
        os.chown(tmp, DATA_PLANE_UID, DATA_PLANE_GID)
    except (AttributeError, PermissionError, OSError):
        pass
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def publish_decision_gate_ca_cert() -> None:
    ca_key_path = MITMPROXY_CONF_DIR / "mitmproxy-ca.pem"
    ca_cert_path = MITMPROXY_CONF_DIR / "mitmproxy-ca-cert.pem"
    try:
        DECISION_GATE_CA_KEY_PATH.unlink()
    except FileNotFoundError:
        pass
    for _ in range(50):
        if ca_key_path.exists() and ca_cert_path.exists():
            _write_owned(DECISION_GATE_CA_CERT_PATH, ca_cert_path.read_bytes(), mode=0o444)
            return
        time.sleep(0.1)
    raise SystemExit("mitmproxy CA was not generated in time for decision-gate CA handoff")


def main() -> None:
    _require_development_release_channel()
    ensure_data_dirs()
    ensure_mitm_ca_material()
    init_db()
    mitm = start_mitmdump()
    time.sleep(1)
    if mitm.poll() is not None:
        raise SystemExit(f"mitmdump exited early with {mitm.returncode}")
    publish_decision_gate_ca_cert()

    def stop(signum, frame):
        mitm.terminate()
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    try:
        uvicorn.run("serverware.app:app", host=WEB_HOST, port=WEB_PORT, log_level="info")
    finally:
        mitm.terminate()
        try:
            mitm.wait(timeout=5)
        except subprocess.TimeoutExpired:
            mitm.kill()


if __name__ == "__main__":
    main()
