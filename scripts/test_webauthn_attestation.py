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


def publish_bundle(
    webauthn_trust,
    *,
    sequence: int,
    rollback_epoch: int,
    root_cert: x509.Certificate | None,
    root_id: str | None = None,
    write: bool = True,
) -> dict:
    roots = []
    if root_cert is not None:
        if not root_id:
            raise ValueError("root_id is required when root_cert is provided")
        roots.append(
            {
                "id": root_id,
                "authenticatorClass": "yubikey",
                "aaguids": [str(uuid.UUID(bytes=YUBIKEY_AAGUID))],
                "certificatePem": root_cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
                "certificateSha256": webauthn_trust.cert_digest(root_cert),
            }
        )
    raw = {
        "apiVersion": "serverware.webauthnTrust/v1",
        "kind": "WebAuthnTrustBundle",
        "metadata": {
            "id": "test-fido-roots",
            "sequence": sequence,
            "rollbackEpoch": rollback_epoch,
            "validFrom": (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(),
        },
        "roots": roots,
    }
    signed = webauthn_trust.sign_trust_bundle(raw)
    return {
        "bundle": signed,
        "result": webauthn_trust.write_trust_bundle(signed) if write else None,
    }


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

        from serverware import app as app_module
        from serverware import db, webauthn, webauthn_trust
        from serverware.auth import AdminIdentity

        db.init_db()
        with db.connect() as conn:
            latest_publication = conn.execute(
                "SELECT MAX(rollback_epoch) AS rollback_epoch FROM webauthn_trust_publications"
            ).fetchone()
        test_rollback_epoch = int(latest_publication["rollback_epoch"] or 0) + 1
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
            rollback_epoch=test_rollback_epoch,
            root_cert=trusted_root_cert,
            root_id="trusted-root-v1",
        )
        try:
            publish_bundle(
                webauthn_trust,
                sequence=1,
                rollback_epoch=test_rollback_epoch,
                root_cert=trusted_root_cert,
                root_id="conflicting-root-v1",
            )
        except webauthn_trust.WebAuthnTrustError as exc:
            if "content changed without advancing sequence" not in str(exc):
                raise
        else:
            raise SystemExit("signed WebAuthn trust bundle content changed without advancing sequence")

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

        scoped_options = webauthn.registration_options(
            "user:challenge-owner", "challenge-scoped key"
        )
        scoped_response = registration_response(
            webauthn,
            scoped_options["publicKey"]["challenge"],
            leaf_key=trusted_leaf_key,
            leaf_cert=trusted_leaf_cert,
            intermediate_cert=trusted_intermediate_cert,
        )
        try:
            register(
                webauthn,
                "user:wrong-challenge-owner",
                "challenge-scoped key",
                scoped_response,
            )
        except webauthn.WebAuthnError as exc:
            if "challenge not found or expired" not in str(exc):
                raise
        else:
            raise SystemExit("registration challenge was accepted for the wrong user")
        scoped_credential = register(
            webauthn,
            "user:challenge-owner",
            "challenge-scoped key",
            scoped_response,
        )

        pending_options = webauthn.registration_options(
            "user:pending-registration", "must be invalidated"
        )
        pending_response = registration_response(
            webauthn,
            pending_options["publicKey"]["challenge"],
            leaf_key=trusted_leaf_key,
            leaf_cert=trusted_leaf_cert,
            intermediate_cert=trusted_intermediate_cert,
        )
        scoped_record = db.get_webauthn_credential(scoped_credential["credential_id"])
        if scoped_record is None:
            raise SystemExit("challenge-scoped credential disappeared before revocation")
        revoked = db.revoke_webauthn_credential(
            scoped_record["id"],
            actor_id="user:challenge-owner",
            reason="registration challenge invalidation regression test",
            source="explicit",
        )
        if not revoked.get("ok") or revoked.get(
            "invalidated_registration_challenge_count", 0
        ) < 1:
            raise SystemExit(
                "explicit credential revocation did not invalidate live registration "
                f"challenges: {revoked}"
            )
        try:
            register(
                webauthn,
                "user:pending-registration",
                "must be invalidated",
                pending_response,
            )
        except webauthn.WebAuthnError as exc:
            if "challenge not found or expired" not in str(exc):
                raise
        else:
            raise SystemExit("registration succeeded with a pre-revocation challenge")
        if db.get_webauthn_credential(pending_response["id"]) is not None:
            raise SystemExit("invalidated registration challenge inserted a credential")

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
        publish_bundle(
            webauthn_trust,
            sequence=2,
            rollback_epoch=test_rollback_epoch,
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
            webauthn._allowed_authenticator(
                trusted,
                {"allowedAuthenticatorClasses": ["hardware"], "requireHardwareAttestation": True},
            )
        except webauthn.WebAuthnError as exc:
            if "attestation trust root was withdrawn" not in str(exc):
                raise
        else:
            raise SystemExit("credential trusted at enrollment remained usable after its trust root was withdrawn")
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

        rotated_record = db.get_webauthn_credential(rotated["credential_id"])
        if rotated_record is None:
            raise SystemExit("rotated credential disappeared before trust withdrawal")
        withdrawal_resource = (
            f"credential:trust-withdrawal-test:{test_rollback_epoch}"
        )
        withdrawal_approval = db.ensure_control_plane_approval(
            action="credential.update",
            resource_id=withdrawal_resource,
            payload_digest="sha256:" + "7" * 64,
            requester_id="user:withdrawal-requester",
            request={"credential_id": withdrawal_resource},
            ttl_seconds=300,
        )
        withdrawal_approval = db.approve_control_plane_approval(
            withdrawal_approval["id"],
            actor_id="user:test",
            authn={
                "method": "webauthn",
                "user_id": "user:test",
                "credential_record_id": rotated_record["id"],
                "control_plane_action": "credential.update",
                "resource_id": withdrawal_resource,
                "payload_digest": "sha256:" + "7" * 64,
                "control_plane_approval_id": withdrawal_approval["id"],
                "approval_requester_id": withdrawal_approval["requester_id"],
                "approval_expires_at": withdrawal_approval["expires_at"],
                "decision": "approve",
            },
        )
        if not withdrawal_approval or withdrawal_approval["status"] != "approved":
            raise SystemExit(
                f"trust-withdrawal approval fixture was not approved: {withdrawal_approval}"
            )

        emergency_bundle = publish_bundle(
            webauthn_trust,
            sequence=3,
            rollback_epoch=test_rollback_epoch,
            root_cert=None,
            write=False,
        )
        pre_publication_digest = (
            webauthn_trust.status().get("state") or {}
        ).get("bundle_digest")
        pending_trust_options = webauthn.registration_options(
            "user:pending-trust-registration", "trust transition invalidates this"
        )
        original_reconcile = app_module.reconcile_trust_publications
        reconcile_calls = 0

        def interrupt_after_metadata_commit(**_: object) -> dict[str, object]:
            nonlocal reconcile_calls
            reconcile_calls += 1
            if reconcile_calls == 1:
                return original_reconcile()
            raise webauthn_trust.WebAuthnTrustError("simulated post-commit interruption")

        app_module.reconcile_trust_publications = interrupt_after_metadata_commit
        try:
            app_module.webauthn_trust_publish(
                app_module.WebAuthnTrustPublish(
                    bundle=emergency_bundle["bundle"],
                    reason="emergency withdrawal regression test",
                ),
                identity=AdminIdentity(
                    "user:security-admin",
                    frozenset({"admin"}),
                    "test",
                ),
            )
        except app_module.HTTPException as exc:
            if exc.status_code != 503:
                raise
        else:
            raise SystemExit("interrupted trust publication unexpectedly succeeded")
        finally:
            app_module.reconcile_trust_publications = original_reconcile
        pending_publication = db.get_pending_webauthn_trust_publication()
        if pending_publication is None:
            raise SystemExit("interrupted trust publication did not retain its journal")
        if (
            (webauthn_trust.status().get("state") or {}).get("bundle_digest")
            != pre_publication_digest
        ):
            raise SystemExit("trust files changed before the journaled projection ran")
        if db.get_unused_webauthn_challenge(
            pending_trust_options["publicKey"]["challenge"],
            challenge_type="registration",
            user_id="user:pending-trust-registration",
        ) is not None:
            raise SystemExit("trust transition left a pre-transition registration challenge live")
        emergency_result = webauthn_trust.reconcile_trust_publications(
            expected_publication_id=pending_publication["id"]
        )
        if db.get_pending_webauthn_trust_publication() is not None:
            raise SystemExit("trust publication reconciliation left pending journal state")
        emergency_bundle["result"] = emergency_result
        if emergency_result.get("root_count") != 0:
            raise SystemExit(f"empty-root emergency bundle reported roots: {emergency_bundle}")
        if emergency_result.get("root_certificate_sha256") != []:
            raise SystemExit(f"empty-root emergency bundle reported root digests: {emergency_bundle}")
        if webauthn_trust.load_trust_roots() != []:
            raise SystemExit("empty-root emergency bundle did not withdraw every trust root")
        invalidated_withdrawal_approval = db.get_control_plane_approval(
            withdrawal_approval["id"]
        )
        if (
            invalidated_withdrawal_approval is None
            or invalidated_withdrawal_approval["status"] != "invalidated"
        ):
            raise SystemExit(
                "trust-root withdrawal left passkey-derived control-plane authority usable: "
                f"{invalidated_withdrawal_approval}"
            )
        for credential in (trusted, rotated):
            if db.get_webauthn_credential(credential["credential_id"]) is not None:
                raise SystemExit("trust-root withdrawal left an affected credential active")
            retained = db.get_webauthn_credential(
                credential["credential_id"], include_revoked=True
            )
            if retained is None or retained.get("revocation_source") != "trust-root-withdrawal":
                raise SystemExit(
                    f"trust-root withdrawal did not retain revocation provenance: {retained}"
                )
        try:
            webauthn._allowed_authenticator(
                rotated,
                {"allowedAuthenticatorClasses": ["hardware"], "requireHardwareAttestation": True},
            )
        except webauthn.WebAuthnError as exc:
            if "attestation trust root was withdrawn" not in str(exc):
                raise
        else:
            raise SystemExit("empty-root emergency bundle left a previously trusted credential usable")

        restored_bundle = publish_bundle(
            webauthn_trust,
            sequence=4,
            rollback_epoch=test_rollback_epoch,
            root_cert=rotated_root_cert,
            root_id="trusted-root-v2-restored",
            write=False,
        )
        app_module.webauthn_trust_publish(
            app_module.WebAuthnTrustPublish(
                bundle=restored_bundle["bundle"],
                reason="root restoration regression test",
            ),
            identity=AdminIdentity(
                "user:security-admin",
                frozenset({"admin"}),
                "test",
            ),
        )
        if db.get_webauthn_credential(rotated["credential_id"]) is not None:
            raise SystemExit("re-adding a withdrawn root silently reactivated a credential")

        print(
            json.dumps(
                {
                    "ok": True,
                    "webauthn_attestation": "pass",
                    "trusted_class": trusted["authenticator_class"],
                    "trusted_root": trusted["attestation_root_sha256"],
                    "trust_bundle_digest": emergency_bundle["result"]["digest"],
                    "trust_bundle_sequence": emergency_bundle["result"]["sequence"],
                    "untrusted_class": untrusted["authenticator_class"],
                    "spoofed_class": spoofed["authenticator_class"],
                },
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()
