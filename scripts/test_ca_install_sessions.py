#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def expect_http_error(label: str, func: Any, expected_status: int, expected_detail: str) -> None:
    from fastapi import HTTPException

    try:
        func()
    except HTTPException as exc:
        detail = json.dumps(exc.detail, sort_keys=True) if isinstance(exc.detail, dict) else str(exc.detail)
        if exc.status_code != expected_status or expected_detail not in detail:
            raise AssertionError(f"{label} failed with wrong error: {exc.status_code} {detail}") from exc
        return
    raise AssertionError(f"{label} unexpectedly succeeded")


def write_test_ca(ca_path: Path) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Serverware Test CA")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    ca_path.parent.mkdir(parents=True, exist_ok=True)
    ca_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["SERVERWARE_DATA_DIR"] = tmp
        os.environ["SERVERWARE_DIRECT_CA_DOWNLOAD_ENABLED"] = "0"

        from serverware import app as app_module
        from serverware import db
        from serverware.auth import AdminIdentity

        db.init_db()
        identity = AdminIdentity("user:admin", frozenset({"admin", "auditor"}), "admin-token-header")
        write_test_ca(app_module.MITMPROXY_CONF_DIR / "mitmproxy-ca-cert.pem")

        expect_http_error(
            "direct CA download disabled",
            lambda: app_module.ca_pem(identity=identity),
            403,
            "direct CA download is disabled",
        )

        created = app_module.ca_install_session_create(identity=identity)
        session = created["session"]
        if session.get("installMethod") != "verifier-mediated-attestation" or not session.get("nonce"):
            raise AssertionError(f"CA install session is missing verifier binding fields: {created}")
        serialized_session = json.dumps(created, sort_keys=True)
        if session["token"] not in serialized_session:
            raise AssertionError("session response did not return the install token to the caller")

        expect_http_error(
            "CA install session bad token",
            lambda: app_module.ca_install_session_download(
                session["id"],
                x_serverware_ca_install_token="wrong-token",
                identity=identity,
            ),
            403,
            "token mismatch",
        )
        response = app_module.ca_install_session_download(
            session["id"],
            x_serverware_ca_install_token=session["token"],
            identity=identity,
        )
        if Path(response.path).name != "mitmproxy-ca-cert.pem":
            raise AssertionError(f"verified CA install session did not return the CA file: {response.path}")
        expect_http_error(
            "CA install session one-use",
            lambda: app_module.ca_install_session_download(
                session["id"],
                x_serverware_ca_install_token=session["token"],
                identity=identity,
            ),
            409,
            "consumed",
        )

        audits = db.list_audit_events(limit=20)
        event_types = [item["event_type"] for item in audits]
        for expected in ("ca.install_session.created", "ca.install_session.consumed"):
            if expected not in event_types:
                raise AssertionError(f"missing {expected} audit event: {event_types}")
        serialized_audits = json.dumps(audits, sort_keys=True)
        if session["token"] in serialized_audits:
            raise AssertionError("CA install token leaked into audit events")

    print(json.dumps({"ca_install_sessions": "pass", "ok": True}, sort_keys=True))


if __name__ == "__main__":
    main()
