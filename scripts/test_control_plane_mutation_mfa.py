#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_prefixed_json(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["SERVERWARE_DATA_DIR"] = tmp
        os.environ["SERVERWARE_DEV_AUTHENTICATOR"] = "1"
        os.environ["SERVERWARE_CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED"] = "1"
        os.environ["SERVERWARE_PUBLIC_URL"] = "http://localhost:3000"
        os.environ["SERVERWARE_WEBAUTHN_ORIGIN"] = "http://localhost:3000"

        from fastapi import HTTPException

        from serverware import app as app_module
        from serverware import db, webauthn
        from serverware.auth import AdminIdentity

        db.init_db()
        user_id = "user:demo"
        webauthn.create_dev_credential(user_id)

        mutation_payload = {
            "credential_id": "cred-demo-bearer",
            "changes": {"secret": "new-production-token", "metadata": {"scope": "gmail.readonly"}},
        }
        payload_digest = sha256_prefixed_json(mutation_payload)
        options = webauthn.control_plane_mutation_options(
            user_id=user_id,
            action="credential.update",
            resource_id="cred-demo-bearer",
            payload_digest=payload_digest,
            authn_policy={"userVerification": "required"},
        )
        serialized_options = canonical_json(options)
        if "new-production-token" in serialized_options:
            raise AssertionError("control-plane mutation challenge leaked plaintext credential material")
        if payload_digest not in serialized_options:
            raise AssertionError("control-plane mutation challenge did not bind the payload digest")

        assertion = webauthn.dev_assertion(options["publicKey"]["challenge"])
        verified = webauthn.verify_control_plane_mutation_assertion(
            user_id=user_id,
            action="credential.update",
            resource_id="cred-demo-bearer",
            payload_digest=payload_digest,
            authn_policy={"userVerification": "required"},
            assertion=assertion,
        )
        if verified.get("method") != "webauthn" or verified.get("payload_digest") != payload_digest:
            raise AssertionError(f"mutation MFA verification returned unexpected result: {verified}")
        if verified.get("user_verified") is not True:
            raise AssertionError(f"mutation MFA did not require user verification: {verified}")

        try:
            webauthn.verify_control_plane_mutation_assertion(
                user_id=user_id,
                action="credential.update",
                resource_id="cred-demo-bearer",
                payload_digest=payload_digest,
                authn_policy={"userVerification": "required"},
                assertion=assertion,
            )
        except webauthn.WebAuthnError:
            pass
        else:
            raise AssertionError("control-plane mutation MFA assertion replay unexpectedly succeeded")

        mismatch_options = webauthn.control_plane_mutation_options(
            user_id=user_id,
            action="credential.update",
            resource_id="cred-demo-bearer",
            payload_digest=payload_digest,
            authn_policy={"userVerification": "required"},
        )
        mismatch_assertion = webauthn.dev_assertion(mismatch_options["publicKey"]["challenge"])
        try:
            webauthn.verify_control_plane_mutation_assertion(
                user_id=user_id,
                action="credential.update",
                resource_id="cred-demo-bearer",
                payload_digest=sha256_prefixed_json({"credential_id": "cred-demo-bearer", "changes": {"secret": "tampered"}}),
                authn_policy={"userVerification": "required"},
                assertion=mismatch_assertion,
            )
        except webauthn.WebAuthnError as exc:
            if "payload_digest mismatch" not in str(exc):
                raise AssertionError(f"mutation MFA failed for the wrong reason: {exc}") from exc
        else:
            raise AssertionError("control-plane mutation MFA accepted a mismatched payload digest")

        identity = AdminIdentity(user_id, frozenset({"admin", "policy_author"}), "admin-token-header")
        app_digest = sha256_prefixed_json({"credential_id": "cred-demo-bearer", "changes": {"metadata": {"scope": "gmail.readonly"}}})
        try:
            app_module._require_control_plane_mutation_mfa(
                action="credential.update",
                resource_id="cred-demo-bearer",
                payload_digest=app_digest,
                mfa=None,
                identity=identity,
            )
        except HTTPException as exc:
            if exc.status_code != 412:
                raise AssertionError(f"mutation MFA helper failed with wrong status: {exc.status_code} {exc.detail}") from exc
        else:
            raise AssertionError("mutation MFA helper accepted a missing assertion while enforcement is enabled")

        app_options = webauthn.control_plane_mutation_options(
            user_id=user_id,
            action="credential.update",
            resource_id="cred-demo-bearer",
            payload_digest=app_digest,
            authn_policy={"userVerification": "required"},
        )
        app_assertion = webauthn.dev_assertion(app_options["publicKey"]["challenge"])
        app_verified = app_module._require_control_plane_mutation_mfa(
            action="credential.update",
            resource_id="cred-demo-bearer",
            payload_digest=app_digest,
            mfa={"assertion": app_assertion},
            identity=identity,
        )
        if not app_verified or app_verified.get("method") != "webauthn":
            raise AssertionError(f"mutation MFA helper did not verify assertion: {app_verified}")

    print(json.dumps({"control_plane_mutation_mfa": "pass", "ok": True}, sort_keys=True))


if __name__ == "__main__":
    main()
