#!/usr/bin/env python3
from __future__ import annotations

import importlib
import json
import os
import sys
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["SERVERWARE_DATA_DIR"] = tmp
        import serverware.config as config
        import serverware.ca_material as ca_material

        importlib.reload(config)
        importlib.reload(ca_material)

        key_path, cert_path = ca_material.ensure_mitm_ca_material()
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        if not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise AssertionError("generated decision-gate CA is not a CA certificate")
        if key.public_key().public_numbers() != cert.public_key().public_numbers():
            raise AssertionError("generated CA key does not match certificate public key")
        if key_path.stat().st_mode & 0o077:
            raise AssertionError("generated CA key is readable by group/other")
        print(json.dumps({"ok": True, "ca_material": "pass"}, sort_keys=True))


if __name__ == "__main__":
    main()
