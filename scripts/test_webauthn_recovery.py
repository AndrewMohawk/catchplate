#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID, ObjectIdentifier


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
YUBIKEY_AAGUID = uuid.UUID("2fc0579f-8113-47ea-b116-bb5a8db9202a").bytes
FIDO_AAGUID_EXTENSION = ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4")


def b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def cert_name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def make_ca(
    common_name: str,
    issuer_cert: x509.Certificate | None = None,
    issuer_key: ec.EllipticCurvePrivateKey | None = None,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = cert_name(common_name)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject if issuer_cert else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(issuer_key or key, hashes.SHA256())
    )
    return key, cert


def make_leaf(
    issuer_cert: x509.Certificate,
    issuer_key: ec.EllipticCurvePrivateKey,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(cert_name("recovery yubikey attestation"))
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.UnrecognizedExtension(FIDO_AAGUID_EXTENSION, YUBIKEY_AAGUID),
            critical=False,
        )
        .sign(issuer_key, hashes.SHA256())
    )
    return key, cert


def cose_public_key(public_key: ec.EllipticCurvePublicKey) -> bytes:
    numbers = public_key.public_numbers()
    return cbor2.dumps(
        {
            1: 2,
            3: -7,
            -1: 1,
            -2: numbers.x.to_bytes(32, "big"),
            -3: numbers.y.to_bytes(32, "big"),
        }
    )


def registration_response(
    webauthn,
    challenge: str,
    *,
    leaf_key: ec.EllipticCurvePrivateKey,
    leaf_cert: x509.Certificate,
    intermediate_cert: x509.Certificate,
) -> tuple[dict[str, object], ec.EllipticCurvePrivateKey]:
    credential_key = ec.generate_private_key(ec.SECP256R1())
    credential_id = os.urandom(32)
    public_key_cose = cose_public_key(credential_key.public_key())
    auth_data = (
        webauthn._rp_hash()
        + bytes([webauthn.UP_FLAG | webauthn.UV_FLAG | webauthn.AT_FLAG])
        + (1).to_bytes(4, "big")
        + YUBIKEY_AAGUID
        + len(credential_id).to_bytes(2, "big")
        + credential_id
        + public_key_cose
    )
    client_data_raw = json.dumps(
        {
            "type": "webauthn.create",
            "challenge": challenge,
            "origin": webauthn.WEBAUTHN_ORIGIN,
            "crossOrigin": False,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    signature = leaf_key.sign(
        auth_data + hashlib.sha256(client_data_raw).digest(),
        ec.ECDSA(hashes.SHA256()),
    )
    attestation = cbor2.dumps(
        {
            "fmt": "packed",
            "authData": auth_data,
            "attStmt": {
                "alg": -7,
                "sig": signature,
                "x5c": [
                    leaf_cert.public_bytes(serialization.Encoding.DER),
                    intermediate_cert.public_bytes(serialization.Encoding.DER),
                ],
            },
        }
    )
    encoded_id = b64u(credential_id)
    return (
        {
            "id": encoded_id,
            "rawId": encoded_id,
            "type": "public-key",
            "transports": ["usb"],
            "response": {
                "clientDataJSON": b64u(client_data_raw),
                "attestationObject": b64u(attestation),
            },
        },
        credential_key,
    )


def assertion_response(
    webauthn,
    *,
    credential_id: str,
    private_key: ec.EllipticCurvePrivateKey,
    challenge: str,
    sign_count: int,
) -> dict[str, object]:
    auth_data = (
        webauthn._rp_hash()
        + bytes([webauthn.UP_FLAG | webauthn.UV_FLAG])
        + sign_count.to_bytes(4, "big")
    )
    client_data_raw = json.dumps(
        {
            "type": "webauthn.get",
            "challenge": challenge,
            "origin": webauthn.WEBAUTHN_ORIGIN,
            "crossOrigin": False,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    signature = private_key.sign(
        auth_data + hashlib.sha256(client_data_raw).digest(),
        ec.ECDSA(hashes.SHA256()),
    )
    return {
        "id": credential_id,
        "rawId": credential_id,
        "type": "public-key",
        "response": {
            "clientDataJSON": b64u(client_data_raw),
            "authenticatorData": b64u(auth_data),
            "signature": b64u(signature),
        },
    }


def expect_recovery_error(callback, marker: str) -> None:
    from catchplate.webauthn import WebAuthnError

    try:
        callback()
    except WebAuthnError as exc:
        if marker.lower() not in str(exc).lower():
            raise AssertionError(f"expected {marker!r}, got {exc!r}") from exc
    else:
        raise AssertionError(f"expected WebAuthn recovery failure containing {marker!r}")


def main() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        data = root / "data"
        recovery_private_key = Ed25519PrivateKey.generate()
        recovery_public_path = root / "offline-recovery.pub.pem"
        recovery_public_path.write_bytes(
            recovery_private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        recovery_public_path.chmod(0o444)
        recovery_key_id = sha256(
            recovery_private_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        os.environ.update(
            {
                "CATCHPLATE_DATA_DIR": str(data),
                "CATCHPLATE_METADATA_STORE_BACKEND": "sqlite",
                "CATCHPLATE_AUDIT_STORE_BACKEND": "sqlite",
                "CATCHPLATE_GRANT_STORE_BACKEND": "sqlite",
                "CATCHPLATE_KEY_RELEASE_REQUIRED": "0",
                "CATCHPLATE_RELEASE_CHANNEL": "test",
                "CATCHPLATE_PUBLIC_URL": "http://localhost:3000",
                "CATCHPLATE_WEBAUTHN_ORIGIN": "http://localhost:3000",
                "CATCHPLATE_WEBAUTHN_TRUST_BUNDLE": str(
                    data / "webauthn-trust-bundle.json"
                ),
                "CATCHPLATE_WEBAUTHN_TRUST_BUNDLE_STATE": str(
                    data / "webauthn-trust-bundle-state.json"
                ),
                "CATCHPLATE_WEBAUTHN_TRUST_SIGNING_KEY": str(
                    data / "webauthn-trust-signing.pem"
                ),
                "CATCHPLATE_WEBAUTHN_TRUST_SIGNING_PUBLIC_KEY": str(
                    data / "webauthn-trust-signing.pub.pem"
                ),
                "CATCHPLATE_WEBAUTHN_RECOVERY_ENABLED": "1",
                "CATCHPLATE_WEBAUTHN_RECOVERY_ROOT_PUBLIC_KEY": str(
                    recovery_public_path
                ),
                "CATCHPLATE_WEBAUTHN_RECOVERY_ROOT_KEY_ID": recovery_key_id,
                "CATCHPLATE_WEBAUTHN_RECOVERY_ROOT_PROVIDER": "offline-test-root",
                "CATCHPLATE_WEBAUTHN_RECOVERY_AUDIENCE": "urn:catchplate:test",
                "CATCHPLATE_WEBAUTHN_RECOVERY_TTL_SECONDS": "180",
                "CATCHPLATE_WEBAUTHN_RECOVERY_MAX_LIVE": "100",
                "CATCHPLATE_OIDC_SESSION_WEBAUTHN_PENDING_TTL_SECONDS": "300",
                "CATCHPLATE_CONTROL_PLANE_MUTATION_ALLOWED_AUTHENTICATOR_CLASSES": "yubikey,hardware",
            }
        )

        from catchplate import auth, crypto, db, webauthn, webauthn_trust

        db.init_db()
        ca_key, ca_cert = make_ca("recovery root CA")
        intermediate_key, intermediate_cert = make_ca(
            "recovery intermediate CA", ca_cert, ca_key
        )
        leaf_key, leaf_cert = make_leaf(intermediate_cert, intermediate_key)
        raw_bundle = {
            "apiVersion": "catchplate.webauthnTrust/v1",
            "kind": "WebAuthnTrustBundle",
            "metadata": {
                "id": "recovery-test-roots",
                "sequence": 1,
                "rollbackEpoch": 1,
                "validFrom": (
                    datetime.now(timezone.utc) - timedelta(minutes=5)
                ).isoformat(),
            },
            "roots": [
                {
                    "id": "recovery-yubikey-root",
                    "authenticatorClass": "yubikey",
                    "aaguids": [str(uuid.UUID(bytes=YUBIKEY_AAGUID))],
                    "certificatePem": ca_cert.public_bytes(
                        serialization.Encoding.PEM
                    ).decode("ascii"),
                    "certificateSha256": webauthn_trust.cert_digest(ca_cert),
                }
            ],
        }
        signed_bundle = webauthn_trust.sign_trust_bundle(raw_bundle)
        webauthn_trust.write_trust_bundle(signed_bundle)
        policy = {
            "userVerification": "required",
            "requireHardwareAttestation": True,
            "allowedAuthenticatorClasses": ["yubikey", "hardware"],
        }
        policy_digest = sha256(
            webauthn.canonical_json(policy).encode("utf-8")
        )

        counter = 0
        counter_lock = threading.Lock()

        def create_session(user_id: str) -> tuple[str, dict[str, object]]:
            nonlocal counter
            with counter_lock:
                counter += 1
                suffix = counter
            token = f"pending-session-{user_id}-{suffix}-{os.urandom(12).hex()}"
            session = db.create_oidc_browser_session(
                token_digest=auth.oidc_session_token_digest(token),
                oidc_token_digest=sha256(f"oidc-token-{user_id}-{suffix}".encode()),
                user_id=user_id,
                roles=["admin", "approver"],
                ttl_seconds=600,
                provider_expires_at_epoch=int(time.time()) + 600,
                require_webauthn=True,
                pending_ttl_seconds=300,
            )
            return token, session

        def create_history(user_id: str, *, revoke: bool) -> dict[str, object]:
            key = ec.generate_private_key(ec.SECP256R1())
            credential = db.create_webauthn_credential(
                credential_id=b64u(os.urandom(32)),
                user_id=user_id,
                label="old key",
                public_key_cose=b64u(cose_public_key(key.public_key())),
                sign_count=1,
                aaguid=str(uuid.UUID(bytes=YUBIKEY_AAGUID)),
                authenticator_class="yubikey",
                attestation_fmt="packed",
                attestation_trusted=True,
                attestation_trust_path=[webauthn_trust.cert_digest(ca_cert)],
                attestation_root_sha256=webauthn_trust.cert_digest(ca_cert),
                attestation_trust_bundle_digest=webauthn_trust.trust_bundle_digest(
                    signed_bundle
                ),
                attestation_trust_bundle_sequence=1,
                attestation_verified_at=db.iso_now(),
                transports=["usb"],
            )
            if revoke:
                return db.revoke_webauthn_credential(
                    str(credential["id"]),
                    actor_id="test:offline-recovery",
                    reason="last key revoked",
                )
            return credential

        def options_for(
            token: str, session: dict[str, object], *, label: str = "replacement"
        ) -> dict[str, object]:
            return webauthn.recovery_registration_options(
                pending_token_digest=auth.oidc_session_token_digest(token),
                oidc_session_id=str(session["id"]),
                user_id=str(session["user_id"]),
                label=label,
                reason="last key revoked",
                auth_policy_digest=policy_digest,
            )

        zero_token, zero_session = create_session("oidc:zero-history")
        expect_recovery_error(
            lambda: options_for(zero_token, zero_session), "history is empty"
        )

        active_user = "oidc:active-key"
        active_token, active_session = create_session(active_user)
        active_credential = create_history(active_user, revoke=False)
        expect_recovery_error(
            lambda: options_for(active_token, active_session), "active WebAuthn"
        )
        revocation = webauthn.prepare_lost_active_key_revocation(
            pending_token_digest=auth.oidc_session_token_digest(active_token),
            oidc_session_id=str(active_session["id"]),
            user_id=active_user,
            reason="explicitly decommission lost active key",
            auth_policy_digest=policy_digest,
        )
        wrong_revocation_authorization = {
            "statement": revocation["statement"],
            "signature": "ed25519:"
            + b64u(
                Ed25519PrivateKey.generate().sign(
                    str(revocation["canonicalStatement"]).encode("ascii")
                )
            ),
        }
        expect_recovery_error(
            lambda: webauthn.verify_lost_active_key_revocation(
                revocation_id=str(revocation["revocationId"]),
                pending_token_digest=auth.oidc_session_token_digest(active_token),
                user_id=active_user,
                authorization=wrong_revocation_authorization,
                auth_policy_digest=policy_digest,
            ),
            "signature verification",
        )
        revocation_signature = recovery_private_key.sign(
            str(revocation["canonicalStatement"]).encode("ascii")
        )
        revocation_authorization = {
            "statement": revocation["statement"],
            "signature": "ed25519:" + b64u(revocation_signature),
        }
        with patch.object(
            db,
            "append_audit_event",
            side_effect=lambda *args, **kwargs: (
                (_ for _ in ()).throw(RuntimeError("injected revocation audit failure"))
                if kwargs.get("event_type")
                == "webauthn.recovery_revocation.consumed"
                else None
            ),
        ):
            try:
                webauthn.verify_lost_active_key_revocation(
                    revocation_id=str(revocation["revocationId"]),
                    pending_token_digest=auth.oidc_session_token_digest(
                        active_token
                    ),
                    user_id=active_user,
                    authorization=revocation_authorization,
                    auth_policy_digest=policy_digest,
                )
            except RuntimeError as exc:
                if "injected revocation audit failure" not in str(exc):
                    raise
            else:
                raise AssertionError(
                    "injected audit failure did not roll back lost-key decommission"
                )
        rolled_back_active = db.get_webauthn_credential_by_record_id(
            str(active_credential["id"]), include_revoked=True
        )
        if rolled_back_active is None or rolled_back_active["revoked_at"] is not None:
            raise AssertionError(
                f"lost key remained revoked after transaction rollback: {rolled_back_active}"
            )
        rolled_back_revocation = db.get_webauthn_recovery_revocation(
            str(revocation["revocationId"])
        )
        if (
            rolled_back_revocation is None
            or rolled_back_revocation["status"] != "expired"
            or rolled_back_revocation["authorization"] != revocation_authorization
        ):
            raise AssertionError(
                "witnessed lost-key authorization was not retained as burned evidence"
            )
        expect_recovery_error(
            lambda: webauthn.verify_lost_active_key_revocation(
                revocation_id=str(revocation["revocationId"]),
                pending_token_digest=auth.oidc_session_token_digest(active_token),
                user_id=active_user,
                authorization=revocation_authorization,
                auth_policy_digest=policy_digest,
            ),
            "not live",
        )
        revocation = webauthn.prepare_lost_active_key_revocation(
            pending_token_digest=auth.oidc_session_token_digest(active_token),
            oidc_session_id=str(active_session["id"]),
            user_id=active_user,
            reason="lost active key retry after burned authorization",
            auth_policy_digest=policy_digest,
        )
        revocation_signature = recovery_private_key.sign(
            str(revocation["canonicalStatement"]).encode("ascii")
        )
        revocation_authorization = {
            "statement": revocation["statement"],
            "signature": "ed25519:" + b64u(revocation_signature),
        }
        revoked = webauthn.verify_lost_active_key_revocation(
            revocation_id=str(revocation["revocationId"]),
            pending_token_digest=auth.oidc_session_token_digest(active_token),
            user_id=active_user,
            authorization=revocation_authorization,
            auth_policy_digest=policy_digest,
        )
        if not revoked["recoveryRequired"] or revoked["rootSequence"] != 2:
            raise AssertionError(f"lost-key decommission result is invalid: {revoked}")
        consumed_revocation = db.get_webauthn_recovery_revocation(
            str(revocation["revocationId"])
        )
        if (
            consumed_revocation is None
            or consumed_revocation["status"] != "consumed"
            or consumed_revocation["authorization"] != revocation_authorization
        ):
            raise AssertionError(
                "lost-key decommission did not retain exact replay evidence"
            )
        with db.connect() as conn:
            root_state = conn.execute(
                "SELECT last_consumed_sequence FROM webauthn_recovery_root_state "
                "WHERE signing_key_id = ? AND user_id = ?",
                (recovery_key_id, active_user),
            ).fetchone()
        if root_state is None or int(root_state["last_consumed_sequence"]) != 2:
            raise AssertionError(
                f"lost-key decommission did not advance root high-water: {root_state}"
            )
        pending_after_revocation = db.get_oidc_browser_session(
            auth.oidc_session_token_digest(active_token)
        )
        if (
            pending_after_revocation is None
            or pending_after_revocation["status"] != "pending_webauthn"
        ):
            raise AssertionError(
                "lost-key decommission did not preserve the pending OIDC session"
            )
        expect_recovery_error(
            lambda: webauthn.verify_lost_active_key_revocation(
                revocation_id=str(revocation["revocationId"]),
                pending_token_digest=auth.oidc_session_token_digest(active_token),
                user_id=active_user,
                authorization=revocation_authorization,
                auth_policy_digest=policy_digest,
            ),
            "not live",
        )

        user_id = active_user
        token, session = active_token, active_session
        options = options_for(token, session)
        response, replacement_private_key = registration_response(
            webauthn,
            str(options["publicKey"]["challenge"]),
            leaf_key=leaf_key,
            leaf_cert=leaf_cert,
            intermediate_cert=intermediate_cert,
        )
        prepared = webauthn.prepare_recovery_registration(
            recovery_id=str(options["recoveryId"]),
            pending_token_digest=auth.oidc_session_token_digest(token),
            user_id=user_id,
            response=response,
            allowed_authenticator_classes=("yubikey", "hardware"),
        )
        if int(prepared["root"]["sequence"]) != 3:
            raise AssertionError(
                f"replacement did not follow revocation root sequence: {prepared}"
            )
        substituted_response, _ = registration_response(
            webauthn,
            str(options["publicKey"]["challenge"]),
            leaf_key=leaf_key,
            leaf_cert=leaf_cert,
            intermediate_cert=intermediate_cert,
        )
        signature = recovery_private_key.sign(
            str(prepared["canonicalStatement"]).encode("ascii")
        )
        authorization = {
            "statement": prepared["statement"],
            "signature": "ed25519:" + b64u(signature),
        }
        wrong_signature = dict(authorization)
        wrong_signature["signature"] = "ed25519:" + b64u(
            Ed25519PrivateKey.generate().sign(
                str(prepared["canonicalStatement"]).encode("ascii")
            )
        )
        expect_recovery_error(
            lambda: webauthn.verify_recovery_registration(
                recovery_id=str(options["recoveryId"]),
                pending_token_digest=auth.oidc_session_token_digest(token),
                user_id=user_id,
                response=response,
                authorization=wrong_signature,
                auth_policy_digest=policy_digest,
                allowed_authenticator_classes=("yubikey", "hardware"),
            ),
            "signature verification",
        )
        wrong_audience = json.loads(json.dumps(authorization))
        wrong_audience["statement"]["audience"] = "urn:wrong-deployment"
        expect_recovery_error(
            lambda: webauthn.verify_recovery_registration(
                recovery_id=str(options["recoveryId"]),
                pending_token_digest=auth.oidc_session_token_digest(token),
                user_id=user_id,
                response=response,
                authorization=wrong_audience,
                auth_policy_digest=policy_digest,
                allowed_authenticator_classes=("yubikey", "hardware"),
            ),
            "statement mismatch",
        )
        other_token, _ = create_session("oidc:other-session")
        expect_recovery_error(
            lambda: webauthn.verify_recovery_registration(
                recovery_id=str(options["recoveryId"]),
                pending_token_digest=auth.oidc_session_token_digest(other_token),
                user_id=user_id,
                response=response,
                authorization=authorization,
                auth_policy_digest=policy_digest,
                allowed_authenticator_classes=("yubikey", "hardware"),
            ),
            "pending_token_digest binding changed",
        )
        expect_recovery_error(
            lambda: webauthn.verify_recovery_registration(
                recovery_id=str(options["recoveryId"]),
                pending_token_digest=auth.oidc_session_token_digest(token),
                user_id=user_id,
                response=substituted_response,
                authorization=authorization,
                auth_policy_digest=policy_digest,
                allowed_authenticator_classes=("yubikey", "hardware"),
            ),
            "candidate",
        )
        substituted = db.get_webauthn_recovery_ceremony(str(options["recoveryId"]))
        if substituted is None or substituted["status"] != "prepared":
            raise AssertionError("candidate substitution changed recovery state")

        with patch.object(
            db,
            "append_audit_event",
            side_effect=lambda *args, **kwargs: (
                (_ for _ in ()).throw(RuntimeError("injected audit failure"))
                if kwargs.get("event_type") == "webauthn.recovery.consumed"
                else None
            ),
        ):
            try:
                webauthn.verify_recovery_registration(
                    recovery_id=str(options["recoveryId"]),
                    pending_token_digest=auth.oidc_session_token_digest(token),
                    user_id=user_id,
                    response=response,
                    authorization=authorization,
                    auth_policy_digest=policy_digest,
                    allowed_authenticator_classes=("yubikey", "hardware"),
                )
            except RuntimeError as exc:
                if "injected audit failure" not in str(exc):
                    raise
            else:
                raise AssertionError("injected audit failure did not roll back recovery")
        rolled_back = db.get_webauthn_recovery_ceremony(str(options["recoveryId"]))
        if rolled_back is None or rolled_back["status"] != "invalidated":
            raise AssertionError(
                f"witnessed recovery authorization was not burned: {rolled_back}"
            )
        if db.get_webauthn_credential(str(response["id"]), include_revoked=True):
            raise AssertionError("replacement credential survived transaction rollback")
        expect_recovery_error(
            lambda: webauthn.verify_recovery_registration(
                recovery_id=str(options["recoveryId"]),
                pending_token_digest=auth.oidc_session_token_digest(token),
                user_id=user_id,
                response=response,
                authorization=authorization,
                auth_policy_digest=policy_digest,
                allowed_authenticator_classes=("yubikey", "hardware"),
            ),
            "not prepared",
        )
        options = options_for(token, session)
        response, replacement_private_key = registration_response(
            webauthn,
            str(options["publicKey"]["challenge"]),
            leaf_key=leaf_key,
            leaf_cert=leaf_cert,
            intermediate_cert=intermediate_cert,
        )
        prepared = webauthn.prepare_recovery_registration(
            recovery_id=str(options["recoveryId"]),
            pending_token_digest=auth.oidc_session_token_digest(token),
            user_id=user_id,
            response=response,
            allowed_authenticator_classes=("yubikey", "hardware"),
        )
        if int(prepared["root"]["sequence"]) != 4:
            raise AssertionError(
                f"fresh recovery did not advance beyond burned witness claim: {prepared}"
            )
        signature = recovery_private_key.sign(
            str(prepared["canonicalStatement"]).encode("ascii")
        )
        authorization = {
            "statement": prepared["statement"],
            "signature": "ed25519:" + b64u(signature),
        }
        result = webauthn.verify_recovery_registration(
            recovery_id=str(options["recoveryId"]),
            pending_token_digest=auth.oidc_session_token_digest(token),
            user_id=user_id,
            response=response,
            authorization=authorization,
            auth_policy_digest=policy_digest,
            allowed_authenticator_classes=("yubikey", "hardware"),
        )
        if not result["ordinaryAssertionRequired"]:
            raise AssertionError(f"recovery activated the session directly: {result}")
        pending = db.get_oidc_browser_session(auth.oidc_session_token_digest(token))
        if pending is None or pending["status"] != "pending_webauthn":
            raise AssertionError(f"recovery did not leave session pending: {pending}")
        expect_recovery_error(
            lambda: webauthn.verify_recovery_registration(
                recovery_id=str(options["recoveryId"]),
                pending_token_digest=auth.oidc_session_token_digest(token),
                user_id=user_id,
                response=response,
                authorization=authorization,
                auth_policy_digest=policy_digest,
                allowed_authenticator_classes=("yubikey", "hardware"),
            ),
            "not prepared",
        )

        binding = webauthn.oidc_session_binding_options(
            session_id=str(pending["id"]),
            user_id=user_id,
            session_expires_at=str(pending["expires_at"]),
            pending_expires_at=str(pending["pending_expires_at"]),
            authn_policy=policy,
            ttl_seconds=120,
        )
        assertion = assertion_response(
            webauthn,
            credential_id=str(response["id"]),
            private_key=replacement_private_key,
            challenge=str(binding["publicKey"]["challenge"]),
            sign_count=2,
        )
        active_token = b64u(os.urandom(48))
        activated = webauthn.verify_oidc_session_binding_assertion(
            old_token_digest=auth.oidc_session_token_digest(token),
            new_token_digest=auth.oidc_session_token_digest(active_token),
            session_id=str(pending["id"]),
            user_id=user_id,
            session_expires_at=str(pending["expires_at"]),
            pending_expires_at=str(pending["pending_expires_at"]),
            authn_policy=policy,
            assertion=assertion,
            encrypted_active_token=crypto.encrypt_secret(active_token),
        )
        if activated["session"]["status"] != "active":
            raise AssertionError(f"ordinary possession proof did not activate: {activated}")
        if db.get_oidc_browser_session(auth.oidc_session_token_digest(token)) is not None:
            raise AssertionError("pending session token remained valid after rotation")

        parallel_user = "oidc:parallel-recovery"
        parallel_token, parallel_session = create_session(parallel_user)
        create_history(parallel_user, revoke=True)
        parallel_options = options_for(parallel_token, parallel_session)
        parallel_response, _ = registration_response(
            webauthn,
            str(parallel_options["publicKey"]["challenge"]),
            leaf_key=leaf_key,
            leaf_cert=leaf_cert,
            intermediate_cert=intermediate_cert,
        )
        parallel_prepared = webauthn.prepare_recovery_registration(
            recovery_id=str(parallel_options["recoveryId"]),
            pending_token_digest=auth.oidc_session_token_digest(parallel_token),
            user_id=parallel_user,
            response=parallel_response,
            allowed_authenticator_classes=("yubikey", "hardware"),
        )
        parallel_signature = recovery_private_key.sign(
            str(parallel_prepared["canonicalStatement"]).encode("ascii")
        )
        parallel_authorization = {
            "statement": parallel_prepared["statement"],
            "signature": "ed25519:" + b64u(parallel_signature),
        }

        def parallel_finalize() -> str:
            try:
                webauthn.verify_recovery_registration(
                    recovery_id=str(parallel_options["recoveryId"]),
                    pending_token_digest=auth.oidc_session_token_digest(
                        parallel_token
                    ),
                    user_id=parallel_user,
                    response=parallel_response,
                    authorization=parallel_authorization,
                    auth_policy_digest=policy_digest,
                    allowed_authenticator_classes=("yubikey", "hardware"),
                )
                return "won"
            except webauthn.WebAuthnError:
                return "lost"

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(lambda _: parallel_finalize(), range(2)))
        if sorted(outcomes) != ["lost", "won"]:
            raise AssertionError(f"parallel recovery did not have one winner: {outcomes}")

        rollback_user = "oidc:metadata-snapshot-rollback"
        rollback_token, rollback_session = create_session(rollback_user)
        create_history(rollback_user, revoke=True)
        rollback_options = options_for(rollback_token, rollback_session)
        rollback_response, _ = registration_response(
            webauthn,
            str(rollback_options["publicKey"]["challenge"]),
            leaf_key=leaf_key,
            leaf_cert=leaf_cert,
            intermediate_cert=intermediate_cert,
        )
        rollback_prepared = webauthn.prepare_recovery_registration(
            recovery_id=str(rollback_options["recoveryId"]),
            pending_token_digest=auth.oidc_session_token_digest(rollback_token),
            user_id=rollback_user,
            response=rollback_response,
            allowed_authenticator_classes=("yubikey", "hardware"),
        )
        rollback_authorization = {
            "statement": rollback_prepared["statement"],
            "signature": "ed25519:"
            + b64u(
                recovery_private_key.sign(
                    str(rollback_prepared["canonicalStatement"]).encode("ascii")
                )
            ),
        }
        metadata_snapshot = root / "metadata-before-witnessed-finalize.sqlite3"
        with db.connect() as source, sqlite3.connect(metadata_snapshot) as target:
            source.backup(target)
        webauthn.verify_recovery_registration(
            recovery_id=str(rollback_options["recoveryId"]),
            pending_token_digest=auth.oidc_session_token_digest(rollback_token),
            user_id=rollback_user,
            response=rollback_response,
            authorization=rollback_authorization,
            auth_policy_digest=policy_digest,
            allowed_authenticator_classes=("yubikey", "hardware"),
        )
        with sqlite3.connect(metadata_snapshot) as source, sqlite3.connect(
            db.DB_PATH
        ) as target:
            source.backup(target)
        expect_recovery_error(
            lambda: webauthn.verify_recovery_registration(
                recovery_id=str(rollback_options["recoveryId"]),
                pending_token_digest=auth.oidc_session_token_digest(
                    rollback_token
                ),
                user_id=rollback_user,
                response=rollback_response,
                authorization=rollback_authorization,
                auth_policy_digest=policy_digest,
                allowed_authenticator_classes=("yubikey", "hardware"),
            ),
            "witness",
        )
        rollback_ceremony = db.get_webauthn_recovery_ceremony(
            str(rollback_options["recoveryId"])
        )
        if rollback_ceremony is None or rollback_ceremony["status"] != "invalidated":
            raise AssertionError(
                "metadata snapshot rollback replay was not terminalized"
            )
        if db.get_webauthn_credential(
            str(rollback_response["id"]), include_revoked=True
        ) is not None:
            raise AssertionError(
                "metadata snapshot restore unexpectedly retained replacement credential"
            )

        with db.connect() as conn:
            schema_rows = conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' "
                "AND name IN ('webauthn_recovery_ceremonies', "
                "'webauthn_recovery_revocations', "
                "'webauthn_recovery_root_state') ORDER BY name"
            ).fetchall()
        if [row["name"] for row in schema_rows] != [
            "webauthn_recovery_ceremonies",
            "webauthn_recovery_revocations",
            "webauthn_recovery_root_state",
        ]:
            raise AssertionError("SQLite recovery schema is incomplete")

        print(
            "WebAuthn recovery tests passed: signed lost-active-key decommission, "
            "gates, trusted candidate binding, separate offline signatures, "
            "rollback, replay, ordinary possession proof, token rotation, and "
            "parallel one-winner finalization"
        )


if __name__ == "__main__":
    main()
