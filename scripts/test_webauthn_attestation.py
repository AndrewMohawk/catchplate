#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier


YUBIKEY_AAGUID = uuid.UUID("2fc0579f-8113-47ea-b116-bb5a8db9202a").bytes
OTHER_AAGUID = uuid.UUID("00000000-0000-0000-0000-000000000001").bytes
FIDO_AAGUID_EXTENSION = ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def cert_name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def make_ca(common_name: str, issuer_cert: x509.Certificate | None = None, issuer_key=None):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = cert_name(common_name)
    issuer = issuer_cert.subject if issuer_cert else subject
    signer = issuer_key or key
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(signer, hashes.SHA256())
    )
    return key, cert


def make_leaf(common_name: str, issuer_cert: x509.Certificate, issuer_key, aaguid: bytes = YUBIKEY_AAGUID):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(cert_name(common_name))
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.UnrecognizedExtension(FIDO_AAGUID_EXTENSION, aaguid), critical=False)
        .sign(issuer_key, hashes.SHA256())
    )
    return key, cert


def b64u(value: bytes) -> str:
    return __import__("base64").urlsafe_b64encode(value).decode("ascii").rstrip("=")


def cose_from_public_key(public_key: ec.EllipticCurvePublicKey) -> bytes:
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


def registration_response(webauthn, challenge: str, *, leaf_key=None, leaf_cert=None, intermediate_cert=None, aaguid: bytes = YUBIKEY_AAGUID, fmt: str = "packed") -> dict:
    credential_key = ec.generate_private_key(ec.SECP256R1())
    credential_id = os.urandom(32)
    public_key_cose = cose_from_public_key(credential_key.public_key())
    auth_data = (
        webauthn._rp_hash()
        + bytes([webauthn.UP_FLAG | webauthn.UV_FLAG | webauthn.AT_FLAG])
        + (1).to_bytes(4, "big")
        + aaguid
        + len(credential_id).to_bytes(2, "big")
        + credential_id
        + public_key_cose
    )
    client_data = {
        "type": "webauthn.create",
        "challenge": challenge,
        "origin": "http://localhost:3000",
        "crossOrigin": False,
    }
    client_data_raw = json.dumps(client_data, separators=(",", ":"), sort_keys=True).encode("utf-8")
    att_stmt = {}
    if fmt == "packed":
        signed = auth_data + __import__("hashlib").sha256(client_data_raw).digest()
        att_stmt = {
            "alg": -7,
            "sig": leaf_key.sign(signed, ec.ECDSA(hashes.SHA256())),
            "x5c": [
                leaf_cert.public_bytes(serialization.Encoding.DER),
                intermediate_cert.public_bytes(serialization.Encoding.DER),
            ],
        }
    attestation_object = cbor2.dumps({"fmt": fmt, "authData": auth_data, "attStmt": att_stmt})
    encoded_id = b64u(credential_id)
    return {
        "id": encoded_id,
        "rawId": encoded_id,
        "type": "public-key",
        "transports": ["usb"],
        "response": {
            "clientDataJSON": b64u(client_data_raw),
            "attestationObject": b64u(attestation_object),
        },
    }


def register(webauthn, user_id: str, label: str, response: dict) -> dict:
    return webauthn.verify_registration(user_id, label, response)


def publish_bundle(webauthn_trust, *, sequence: int, rollback_epoch: int, root_cert: x509.Certificate, root_id: str) -> dict:
    raw = {
        "apiVersion": "serverware.webauthnTrust/v1",
        "kind": "WebAuthnTrustBundle",
        "metadata": {
            "id": "test-fido-roots",
            "sequence": sequence,
            "rollbackEpoch": rollback_epoch,
            "validFrom": (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(),
        },
        "roots": [
            {
                "id": root_id,
                "authenticatorClass": "yubikey",
                "aaguids": [str(uuid.UUID(bytes=YUBIKEY_AAGUID))],
                "certificatePem": root_cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
                "certificateSha256": webauthn_trust.cert_digest(root_cert),
            }
        ],
    }
    signed = webauthn_trust.sign_trust_bundle(raw)
    return {"bundle": signed, "result": webauthn_trust.write_trust_bundle(signed)}


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        os.environ["SERVERWARE_DATA_DIR"] = str(tmp_path / "data")
        os.environ["SERVERWARE_WEBAUTHN_TRUST_BUNDLE"] = str(tmp_path / "data" / "webauthn-trust-bundle.json")
        os.environ["SERVERWARE_WEBAUTHN_TRUST_BUNDLE_STATE"] = str(tmp_path / "data" / "webauthn-trust-bundle-state.json")
        os.environ["SERVERWARE_WEBAUTHN_TRUST_SIGNING_KEY"] = str(tmp_path / "data" / "webauthn-trust-signing-ed25519.pem")
        os.environ["SERVERWARE_WEBAUTHN_TRUST_SIGNING_PUBLIC_KEY"] = str(tmp_path / "data" / "webauthn-trust-signing-ed25519.pub.pem")
        os.environ["SERVERWARE_PUBLIC_URL"] = "http://localhost:3000"
        os.environ["SERVERWARE_WEBAUTHN_ORIGIN"] = "http://localhost:3000"

        from serverware import db, webauthn, webauthn_trust

        db.init_db()
        trusted_root_key, trusted_root_cert = make_ca("trusted fido root")
        trusted_intermediate_key, trusted_intermediate_cert = make_ca(
            "trusted fido intermediate", trusted_root_cert, trusted_root_key
        )
        trusted_leaf_key, trusted_leaf_cert = make_leaf(
            "trusted yubikey attestation", trusted_intermediate_cert, trusted_intermediate_key
        )
        first_bundle = publish_bundle(
            webauthn_trust,
            sequence=1,
            rollback_epoch=1,
            root_cert=trusted_root_cert,
            root_id="trusted-root-v1",
        )

        unauthorized_options = webauthn.registration_options("user:unauthorized", "stolen-session key")
        unauthorized_response = registration_response(
            webauthn,
            unauthorized_options["publicKey"]["challenge"],
            leaf_key=trusted_leaf_key,
            leaf_cert=trusted_leaf_cert,
            intermediate_cert=trusted_intermediate_cert,
        )
        try:
            webauthn.verify_registration(
                "user:unauthorized",
                "stolen-session key",
                unauthorized_response,
                require_authorization=True,
            )
        except webauthn.WebAuthnError as exc:
            if "lacks enrollment authorization" not in str(exc):
                raise
        else:
            raise SystemExit("registration challenge without bootstrap or existing-key authorization was accepted")

        authorized_options = webauthn.registration_options(
            "user:authorized",
            "bootstrap key",
            authorization={
                "mode": "bootstrap-token",
                "payload_digest": "sha256:" + "1" * 64,
                "existing_credential_count": 0,
            },
        )
        authorized_response = registration_response(
            webauthn,
            authorized_options["publicKey"]["challenge"],
            leaf_key=trusted_leaf_key,
            leaf_cert=trusted_leaf_cert,
            intermediate_cert=trusted_intermediate_cert,
        )
        authorized = webauthn.verify_registration(
            "user:authorized",
            "bootstrap key",
            authorized_response,
            require_authorization=True,
        )
        if (authorized.get("_registration_authorization") or {}).get("mode") != "bootstrap-token":
            raise SystemExit(f"authorized registration did not retain enrollment evidence: {authorized}")

        opts = webauthn.registration_options("user:test", "trusted yubikey")
        trusted_response = registration_response(
            webauthn,
            opts["publicKey"]["challenge"],
            leaf_key=trusted_leaf_key,
            leaf_cert=trusted_leaf_cert,
            intermediate_cert=trusted_intermediate_cert,
        )
        trusted = register(webauthn, "user:test", "trusted yubikey", trusted_response)
        if trusted["authenticator_class"] != "yubikey" or not trusted["attestation_trusted"]:
            raise SystemExit(f"trusted YubiKey registration was not classified as trusted: {trusted}")
        if trusted["attestation_trust_bundle_digest"] != first_bundle["result"]["digest"]:
            raise SystemExit(f"trusted credential did not record trust bundle digest: {trusted}")
        webauthn._allowed_authenticator(
            trusted,
            {"allowedAuthenticatorClasses": ["yubikey"], "requireHardwareAttestation": True},
        )
        webauthn._allowed_authenticator(
            trusted,
            {"allowedAuthenticatorClasses": ["hardware"], "requireHardwareAttestation": True},
        )

        untrusted_root_key, untrusted_root_cert = make_ca("untrusted fido root")
        untrusted_intermediate_key, untrusted_intermediate_cert = make_ca(
            "untrusted fido intermediate", untrusted_root_cert, untrusted_root_key
        )
        untrusted_leaf_key, untrusted_leaf_cert = make_leaf(
            "untrusted yubikey attestation", untrusted_intermediate_cert, untrusted_intermediate_key
        )
        opts = webauthn.registration_options("user:test", "untrusted yubikey")
        untrusted_response = registration_response(
            webauthn,
            opts["publicKey"]["challenge"],
            leaf_key=untrusted_leaf_key,
            leaf_cert=untrusted_leaf_cert,
            intermediate_cert=untrusted_intermediate_cert,
        )
        untrusted = register(webauthn, "user:test", "untrusted yubikey", untrusted_response)
        if untrusted["authenticator_class"] != "unknown" or untrusted["attestation_trusted"]:
            raise SystemExit(f"untrusted AAGUID should not classify as YubiKey: {untrusted}")
        try:
            webauthn._allowed_authenticator(
                untrusted,
                {"allowedAuthenticatorClasses": ["unknown"], "requireHardwareAttestation": True},
            )
        except webauthn.WebAuthnError as exc:
            if "trusted hardware attestation required" not in str(exc):
                raise
        else:
            raise SystemExit("requireHardwareAttestation accepted an untrusted credential")

        rotated_root_key, rotated_root_cert = make_ca("rotated fido root")
        rotated_intermediate_key, rotated_intermediate_cert = make_ca(
            "rotated fido intermediate", rotated_root_cert, rotated_root_key
        )
        rotated_leaf_key, rotated_leaf_cert = make_leaf(
            "rotated yubikey attestation", rotated_intermediate_cert, rotated_intermediate_key
        )
        rotated_bundle = publish_bundle(
            webauthn_trust,
            sequence=2,
            rollback_epoch=1,
            root_cert=rotated_root_cert,
            root_id="trusted-root-v2",
        )
        opts = webauthn.registration_options("user:test", "rotated yubikey")
        rotated_response = registration_response(
            webauthn,
            opts["publicKey"]["challenge"],
            leaf_key=rotated_leaf_key,
            leaf_cert=rotated_leaf_cert,
            intermediate_cert=rotated_intermediate_cert,
        )
        rotated = register(webauthn, "user:test", "rotated yubikey", rotated_response)
        if rotated["authenticator_class"] != "yubikey" or rotated["attestation_trust_bundle_sequence"] != 2:
            raise SystemExit(f"rotated trust bundle was not used: {rotated}")
        try:
            webauthn_trust.write_trust_bundle(first_bundle["bundle"])
        except webauthn_trust.WebAuthnTrustError as exc:
            if "sequence is stale" not in str(exc):
                raise
        else:
            raise SystemExit("stale WebAuthn trust bundle sequence was accepted")

        opts = webauthn.registration_options("user:test", "old root after rotation")
        old_after_rotation_response = registration_response(
            webauthn,
            opts["publicKey"]["challenge"],
            leaf_key=trusted_leaf_key,
            leaf_cert=trusted_leaf_cert,
            intermediate_cert=trusted_intermediate_cert,
        )
        old_after_rotation = register(webauthn, "user:test", "old root after rotation", old_after_rotation_response)
        if old_after_rotation["authenticator_class"] != "unknown" or old_after_rotation["attestation_trusted"]:
            raise SystemExit(f"old root should not remain trusted after rotation: {old_after_rotation}")

        opts = webauthn.registration_options("user:test", "spoofed aaguid")
        spoofed_response = registration_response(webauthn, opts["publicKey"]["challenge"], fmt="none")
        spoofed = register(webauthn, "user:test", "spoofed aaguid", spoofed_response)
        if spoofed["authenticator_class"] != "unknown" or spoofed["attestation_trusted"]:
            raise SystemExit(f"AAGUID-only registration should remain unknown: {spoofed}")

        wrong_leaf_key, wrong_leaf_cert = make_leaf(
            "wrong aaguid attestation", rotated_intermediate_cert, rotated_intermediate_key, OTHER_AAGUID
        )
        opts = webauthn.registration_options("user:test", "wrong aaguid")
        wrong_response = registration_response(
            webauthn,
            opts["publicKey"]["challenge"],
            leaf_key=wrong_leaf_key,
            leaf_cert=wrong_leaf_cert,
            intermediate_cert=rotated_intermediate_cert,
        )
        try:
            register(webauthn, "user:test", "wrong aaguid", wrong_response)
        except webauthn.WebAuthnError as exc:
            if "AAGUID mismatch" not in str(exc):
                raise
        else:
            raise SystemExit("registration accepted a mismatched attestation certificate AAGUID")

        print(
            json.dumps(
                {
                    "ok": True,
                    "webauthn_attestation": "pass",
                    "trusted_class": trusted["authenticator_class"],
                    "trusted_root": trusted["attestation_root_sha256"],
                    "trust_bundle_digest": rotated_bundle["result"]["digest"],
                    "trust_bundle_sequence": rotated["attestation_trust_bundle_sequence"],
                    "untrusted_class": untrusted["authenticator_class"],
                    "spoofed_class": spoofed["authenticator_class"],
                },
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()
