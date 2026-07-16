#!/usr/bin/env python3
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
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
        os.environ["SERVERWARE_KEY_RELEASE_REQUIRED"] = "0"
        os.environ["SERVERWARE_METADATA_STORE_BACKEND"] = "sqlite"
        os.environ["SERVERWARE_AUDIT_STORE_BACKEND"] = "sqlite"
        os.environ["SERVERWARE_GRANT_STORE_BACKEND"] = "sqlite"
        os.environ.pop("SERVERWARE_METADATA_STORE_POSTGRES_DSN", None)
        os.environ.pop("SERVERWARE_AUDIT_STORE_POSTGRES_DSN", None)
        os.environ.pop("SERVERWARE_GRANT_STORE_POSTGRES_DSN", None)

        from serverware import app as app_module
        from serverware import db
        from serverware.auth import AdminIdentity
        from verify_attestation import (
            canonical_json,
            enrollment_install_session,
            load_enrollment_packet,
            verify_enrollment_measurements,
        )

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
        if (
            session.get("installMethod") != "verifier-mediated-attestation"
            or not session.get("nonce")
            or not session.get("policyUrl")
        ):
            raise AssertionError(f"CA install session is missing verifier binding fields: {created}")
        serialized_session = json.dumps(created, sort_keys=True)
        if session["token"] not in serialized_session:
            raise AssertionError("session response did not return the install token to the caller")

        state = app_module._read_ca_install_sessions()
        stored_session = state["sessions"][session["id"]]
        expected_policy_hash = stored_session.get("policy_hash") or "sha256:" + "a" * 64
        stored_session["policy_hash"] = expected_policy_hash
        app_module._write_ca_install_sessions(state)
        original_policy_status_document = app_module._policy_status_document
        app_module._policy_status_document = lambda: {
            "policy_hash": expected_policy_hash,
            "bundle": {"metadata": {"signature": "ed25519:test"}},
            "high_water": {},
        }
        try:
            expect_http_error(
                "CA install session policy bad token",
                lambda: app_module.ca_install_session_policy(
                    session["id"],
                    x_serverware_ca_install_token="wrong-token",
                ),
                403,
                "token mismatch",
            )
            policy_status = app_module.ca_install_session_policy(
                session["id"],
                x_serverware_ca_install_token=session["token"],
            )
            if policy_status.get("policy_hash") != expected_policy_hash:
                raise AssertionError(f"scoped policy endpoint returned the wrong policy: {policy_status}")

            app_module._policy_status_document = lambda: {
                "policy_hash": "sha256:" + "b" * 64,
                "bundle": {},
                "high_water": {},
            }
            expect_http_error(
                "CA install session policy hash mismatch",
                lambda: app_module.ca_install_session_policy(
                    session["id"],
                    x_serverware_ca_install_token=session["token"],
                ),
                409,
                "policy changed",
            )
        finally:
            app_module._policy_status_document = original_policy_status_document

        expect_http_error(
            "CA install session bad token",
            lambda: app_module.ca_install_session_download(
                session["id"],
                x_serverware_ca_install_token="wrong-token",
            ),
            403,
            "token mismatch",
        )
        response = app_module.ca_install_session_download(
            session["id"],
            x_serverware_ca_install_token=session["token"],
        )
        if Path(response.path).name != "mitmproxy-ca-cert.pem":
            raise AssertionError(f"verified CA install session did not return the CA file: {response.path}")
        expect_http_error(
            "CA install session one-use",
            lambda: app_module.ca_install_session_download(
                session["id"],
                x_serverware_ca_install_token=session["token"],
            ),
            409,
            "consumed",
        )

        concurrent_created = app_module.ca_install_session_create(identity=identity)["session"]
        barrier = threading.Barrier(8)

        def consume_concurrently(_: int) -> int:
            barrier.wait(timeout=5)
            try:
                app_module.ca_install_session_download(
                    concurrent_created["id"],
                    x_serverware_ca_install_token=concurrent_created["token"],
                )
                return 200
            except app_module.HTTPException as exc:
                return exc.status_code

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            statuses = list(executor.map(consume_concurrently, range(8)))
        if statuses.count(200) != 1 or statuses.count(409) != 7:
            raise AssertionError(f"CA install capability was not consumed atomically: {statuses}")

        retry_created = app_module.ca_install_session_create(identity=identity)["session"]
        original_record_audit_event = db.record_audit_event
        failed_consumption_audit = False

        def fail_first_consumption_audit(event_type: str, event: dict[str, Any], **kwargs: Any) -> Any:
            nonlocal failed_consumption_audit
            if event_type == "ca.install_session.consumed" and not failed_consumption_audit:
                failed_consumption_audit = True
                raise RuntimeError("simulated audit outage")
            return original_record_audit_event(event_type, event, **kwargs)

        db.record_audit_event = fail_first_consumption_audit
        try:
            try:
                app_module.ca_install_session_download(
                    retry_created["id"],
                    x_serverware_ca_install_token=retry_created["token"],
                )
            except RuntimeError as exc:
                if "simulated audit outage" not in str(exc):
                    raise
            else:
                raise AssertionError("audit failure unexpectedly returned the CA file")
            retry_state = app_module._read_ca_install_sessions()["sessions"][retry_created["id"]]
            retry_outbox = retry_state.get("consume_audit_outbox")
            if (
                retry_state.get("status") != "consumed"
                or not isinstance(retry_outbox, dict)
                or retry_outbox.get("status") != "pending"
                or retry_state.get("consumed_by") != f"capability:ca-install-session:{retry_created['id']}"
            ):
                raise AssertionError(f"audit failure was not durably queued for retry: {retry_state}")
        finally:
            db.record_audit_event = original_record_audit_event
        retry_response = app_module.ca_install_session_download(
            retry_created["id"],
            x_serverware_ca_install_token=retry_created["token"],
        )
        if Path(retry_response.path).name != "mitmproxy-ca-cert.pem":
            raise AssertionError("retry after an audit outage did not return the CA file")

        finalize_retry_created = app_module.ca_install_session_create(identity=identity)["session"]
        original_finish_audit_delivery = app_module._finish_ca_install_session_audit_delivery
        failed_finish = False

        def fail_first_audit_delivery_finish(*args: Any, **kwargs: Any) -> None:
            nonlocal failed_finish
            if not failed_finish:
                failed_finish = True
                raise OSError("simulated outbox state write failure")
            original_finish_audit_delivery(*args, **kwargs)

        app_module._finish_ca_install_session_audit_delivery = fail_first_audit_delivery_finish
        try:
            try:
                app_module.ca_install_session_download(
                    finalize_retry_created["id"],
                    x_serverware_ca_install_token=finalize_retry_created["token"],
                )
            except OSError as exc:
                if "simulated outbox state write failure" not in str(exc):
                    raise
            else:
                raise AssertionError("outbox state write failure unexpectedly returned the CA file")
        finally:
            app_module._finish_ca_install_session_audit_delivery = original_finish_audit_delivery
        finalize_state = app_module._read_ca_install_sessions()["sessions"][finalize_retry_created["id"]]
        finalize_outbox = finalize_state.get("consume_audit_outbox")
        if (
            finalize_state.get("status") != "consumed"
            or not isinstance(finalize_outbox, dict)
            or finalize_outbox.get("status") != "pending"
        ):
            raise AssertionError(f"failed outbox finalization lost durable consumption state: {finalize_state}")
        outbox_id = finalize_outbox["id"]
        before_retry_audits = db.search_audit_events(
            event_type="ca.install_session.consumed",
            actor_type="capability",
            q=outbox_id,
            limit=10,
            scan_limit=500,
        )
        if len(before_retry_audits.get("items", [])) != 1:
            raise AssertionError(f"consumption audit was not committed exactly once before retry: {before_retry_audits}")
        finalize_retry_response = app_module.ca_install_session_download(
            finalize_retry_created["id"],
            x_serverware_ca_install_token=finalize_retry_created["token"],
        )
        if Path(finalize_retry_response.path).name != "mitmproxy-ca-cert.pem":
            raise AssertionError("retry after outbox finalization failure did not return the CA file")
        after_retry_audits = db.search_audit_events(
            event_type="ca.install_session.consumed",
            actor_type="capability",
            q=outbox_id,
            limit=10,
            scan_limit=500,
        )
        if len(after_retry_audits.get("items", [])) != 1:
            raise AssertionError(f"outbox retry duplicated the consumption audit: {after_retry_audits}")

        idempotency_key = "ca-consume:test-concurrent-idempotency"
        idempotent_event = {
            "session_id": "test-concurrent-idempotency",
            "consume_outbox_id": idempotency_key,
        }

        def append_idempotently(_: int) -> str:
            result = db.record_audit_event(
                "ca.install_session.consumed",
                idempotent_event,
                actor_type="capability",
                actor_id="ca-install-session:test-concurrent-idempotency",
                idempotency_key=idempotency_key,
            )
            return str(result["event_hash"])

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            idempotent_hashes = list(executor.map(append_idempotently, range(8)))
        if len(set(idempotent_hashes)) != 1:
            raise AssertionError(f"audit idempotency returned multiple event hashes: {idempotent_hashes}")
        idempotent_audits = db.search_audit_events(
            event_type="ca.install_session.consumed",
            actor_type="capability",
            q=idempotency_key,
            limit=10,
            scan_limit=500,
        )
        if len(idempotent_audits.get("items", [])) != 1:
            raise AssertionError(f"audit idempotency inserted duplicate events: {idempotent_audits}")

        abandoned_created = app_module.ca_install_session_create(identity=identity)["session"]

        def fail_abandoned_consumption_audit(event_type: str, event: dict[str, Any], **kwargs: Any) -> Any:
            if (
                event_type == "ca.install_session.consumed"
                and event.get("session_id") == abandoned_created["id"]
            ):
                raise RuntimeError("simulated abandoned audit outage")
            return original_record_audit_event(event_type, event, **kwargs)

        db.record_audit_event = fail_abandoned_consumption_audit
        try:
            try:
                app_module.ca_install_session_download(
                    abandoned_created["id"],
                    x_serverware_ca_install_token=abandoned_created["token"],
                )
            except RuntimeError as exc:
                if "simulated abandoned audit outage" not in str(exc):
                    raise
            else:
                raise AssertionError("abandoned audit outage unexpectedly returned the CA file")
        finally:
            db.record_audit_event = original_record_audit_event
        abandoned_state = app_module._read_ca_install_sessions()["sessions"][abandoned_created["id"]]
        if abandoned_state.get("consume_audit_outbox", {}).get("status") != "pending":
            raise AssertionError(f"abandoned consumption was not retained in the outbox: {abandoned_state}")
        app_module._create_ca_install_session(created_by="user:outbox-drain-test")
        drained_state = app_module._read_ca_install_sessions()["sessions"][abandoned_created["id"]]
        if drained_state.get("consume_audit_outbox", {}).get("status") != "delivered":
            raise AssertionError(f"session creation did not drain the recovered audit outbox: {drained_state}")

        old_retention = app_module.CA_INSTALL_SESSION_RETENTION_SECONDS
        old_capacity = app_module.CA_INSTALL_SESSION_MAX_ENTRIES
        try:
            app_module.CA_INSTALL_SESSION_RETENTION_SECONDS = 60
            retention_state = app_module._read_ca_install_sessions()
            retention_state["sessions"]["old-terminal-session"] = {
                "id": "old-terminal-session",
                "status": "consumed",
                "created_at": (datetime.now(timezone.utc) - timedelta(days=2)).isoformat(),
                "expires_at": (datetime.now(timezone.utc) - timedelta(days=2)).isoformat(),
                "consumed_at": (datetime.now(timezone.utc) - timedelta(days=2)).isoformat(),
            }
            retention_state["sessions"]["old-active-session"] = {
                "id": "old-active-session",
                "status": "active",
                "created_at": (datetime.now(timezone.utc) - timedelta(days=3)).isoformat(),
                "expires_at": (datetime.now(timezone.utc) - timedelta(days=2)).isoformat(),
            }
            app_module._write_ca_install_sessions(retention_state)
            app_module._create_ca_install_session(created_by="user:retention-test")
            retained_sessions = app_module._read_ca_install_sessions()["sessions"]
            if "old-terminal-session" in retained_sessions or "old-active-session" in retained_sessions:
                raise AssertionError("expired CA install sessions exceeded retention")

            current_count = len(app_module._read_ca_install_sessions()["sessions"])
            app_module.CA_INSTALL_SESSION_MAX_ENTRIES = current_count
            expect_http_error(
                "CA install session capacity",
                lambda: app_module._create_ca_install_session(created_by="user:capacity-test"),
                429,
                "capacity reached",
            )
        finally:
            app_module.CA_INSTALL_SESSION_RETENTION_SECONDS = old_retention
            app_module.CA_INSTALL_SESSION_MAX_ENTRIES = old_capacity

        audits = db.list_audit_events(limit=20)
        event_types = [item["event_type"] for item in audits]
        for expected in ("ca.install_session.created", "ca.install_session.consumed"):
            if expected not in event_types:
                raise AssertionError(f"missing {expected} audit event: {event_types}")
        serialized_audits = json.dumps(audits, sort_keys=True)
        if session["token"] in serialized_audits:
            raise AssertionError("CA install token leaked into audit events")

        unsigned_packet = {
            "apiVersion": "serverware.agentEnrollment/v1",
            "kind": "AgentEnrollment",
            "nonce": session["nonce"],
            "serverware": {"controlPlaneUrl": "https://serverware.example"},
            "ca": {
                "installSession": {
                    "id": "A" * 32,
                    "nonce": session["nonce"],
                    "token": session["token"],
                    "tokenHeader": session["tokenHeader"],
                    "policyUrl": "/api/ca/install-sessions/" + "A" * 32 + "/policy",
                    "downloadUrl": "/api/ca/install-sessions/" + "A" * 32 + "/ca.pem",
                    "expiresAt": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
                }
            },
        }
        packet_digest = "sha256:" + hashlib.sha256(canonical_json(unsigned_packet).encode("utf-8")).hexdigest()
        statement = {"packetSha256": packet_digest}
        statement_digest = "sha256:" + hashlib.sha256(canonical_json(statement).encode("utf-8")).hexdigest()
        verified_packet = {
            **unsigned_packet,
            "authenticity": {
                "statement": statement,
                "statementSha256": statement_digest,
                "signature": "ed25519:test",
            },
            "verificationReceipt": {
                "apiVersion": "serverware.agentEnrollmentVerification/v1",
                "kind": "AgentEnrollmentVerification",
                "nonce": session["nonce"],
                "packetSha256": packet_digest,
                "statementSha256": statement_digest,
            },
        }
        packet_path = Path(tmp) / "verified-enrollment.json"
        packet_path.write_text(json.dumps(verified_packet))
        loaded_packet = load_enrollment_packet(packet_path)
        scoped_base, loaded_session = enrollment_install_session(
            loaded_packet,
            base="https://serverware.example/",
        )
        if scoped_base != "https://serverware.example" or loaded_session["token"] != session["token"]:
            raise AssertionError("verified enrollment packet did not yield its scoped verifier capability")

        mismatched_receipt = json.loads(json.dumps(verified_packet))
        mismatched_receipt["verificationReceipt"]["packetSha256"] = "sha256:" + "0" * 64
        try:
            enrollment_install_session(mismatched_receipt, base="https://serverware.example")
        except ValueError as exc:
            if "does not bind" not in str(exc):
                raise AssertionError(f"receipt digest mismatch failed with the wrong error: {exc}") from exc
        else:
            raise AssertionError("receipt digest mismatch unexpectedly succeeded")

        measurement_now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        measurement_packet = {
            "principalId": "agent:demo",
            "nonce": session["nonce"],
            "issuedAtEpochMs": measurement_now_ms - 1_000,
            "expiresAtEpochMs": measurement_now_ms + 60_000,
            "pinning": {
                "policyHash": "sha256:" + "1" * 64,
                "policySigningKeyId": "sha256:" + "2" * 64,
                "policySequence": 7,
                "policyHighWaterDigest": "sha256:" + "3" * 64,
                "caIntermediateSpkiSha256": "sha256:" + "4" * 64,
                "dataPlaneBinaryDigest": "sha256:" + "5" * 64,
                "runtimeManifestDigest": "sha256:" + "6" * 64,
                "responseSigningKeyId": "sha256:" + "7" * 64,
                "provenanceDigest": "sha256:" + "8" * 64,
                "imageSignaturesDigest": "sha256:" + "9" * 64,
                "sourceTreeDigest": "sha256:" + "a" * 64,
                "rollbackEpoch": 4,
                "releaseChannel": "stable",
            },
            "authenticity": {
                "statement": {
                    "principalId": "agent:demo",
                    "nonce": session["nonce"],
                    "issuedAtEpochMs": measurement_now_ms - 1_000,
                    "expiresAtEpochMs": measurement_now_ms + 60_000,
                    "policyHash": "sha256:" + "1" * 64,
                    "runtimeManifestDigest": "sha256:" + "6" * 64,
                    "responseSigningKeyId": "sha256:" + "7" * 64,
                }
            },
            "verificationReceipt": {
                "verifiedAtEpochMs": measurement_now_ms,
                "policyHash": "sha256:" + "1" * 64,
                "runtimeManifestDigest": "sha256:" + "6" * 64,
                "responseSigningKeyId": "sha256:" + "7" * 64,
                # This is intentionally not the digest of the fresh quote below.
                "attestationQuoteSha256": "sha256:" + "b" * 64,
                "downloadedPacketSha256": "sha256:" + "c" * 64,
                "expectedPrincipalId": "agent:demo",
                "checks": [
                    "attestation-nonce",
                    "attestation-quote",
                    "runtime-manifest",
                    "measurement-pins",
                    "packet-expiry",
                    "packet-signature",
                    "downloaded-file-digest",
                    "expected-principal",
                    "expected-nonce",
                ],
            },
        }
        fresh_attestation = {
            "policy_bundle_digest": "sha256:" + "1" * 64,
            "policy_signing_key_id": "sha256:" + "2" * 64,
            "policy_sequence": 7,
            "policy_high_water_digest": "sha256:" + "3" * 64,
            "ca_intermediate_spki_sha256": "sha256:" + "4" * 64,
            "data_plane_binary_digest": "sha256:" + "5" * 64,
            "runtime_manifest_digest": "sha256:" + "6" * 64,
            "response_signing_key_id": "sha256:" + "7" * 64,
            "provenance_digest": "sha256:" + "8" * 64,
            "image_signatures_digest": "sha256:" + "9" * 64,
            "source_tree_digest": "sha256:" + "a" * 64,
            "rollback_epoch": 4,
            "release_channel": "stable",
            "quote": {"fresh": True},
        }
        verify_enrollment_measurements(
            measurement_packet,
            attestation=fresh_attestation,
            response_key_id="sha256:" + "7" * 64,
        )
        malformed_quote_receipt = json.loads(json.dumps(measurement_packet))
        malformed_quote_receipt["verificationReceipt"]["attestationQuoteSha256"] = "not-a-digest"
        try:
            verify_enrollment_measurements(
                malformed_quote_receipt,
                attestation=fresh_attestation,
                response_key_id="sha256:" + "7" * 64,
            )
        except ValueError as exc:
            if "attestationQuoteSha256 is invalid" not in str(exc):
                raise AssertionError(f"malformed receipt quote digest failed incorrectly: {exc}") from exc
        else:
            raise AssertionError("malformed receipt quote digest unexpectedly succeeded")

        try:
            enrollment_install_session(loaded_packet, base="https://attacker.example")
        except ValueError as exc:
            if "origin does not match" not in str(exc):
                raise AssertionError(f"control-plane origin mismatch failed with the wrong error: {exc}") from exc
        else:
            raise AssertionError("control-plane origin mismatch unexpectedly succeeded")

        duplicate_packet_path = Path(tmp) / "duplicate-enrollment.json"
        duplicate_packet_path.write_text('{"apiVersion":"serverware.agentEnrollment/v1","apiVersion":"duplicate"}')
        try:
            load_enrollment_packet(duplicate_packet_path)
        except ValueError as exc:
            if "duplicate key" not in str(exc):
                raise AssertionError(f"duplicate enrollment JSON failed with the wrong error: {exc}") from exc
        else:
            raise AssertionError("duplicate enrollment JSON unexpectedly succeeded")

        forbidden_admin = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "verify_attestation.py"),
                "--enrollment-packet",
                str(packet_path),
                "--admin-token",
                "must-not-be-used",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=False,
        )
        if forbidden_admin.returncode == 0 or "forbids --admin-token" not in forbidden_admin.stderr:
            raise AssertionError(
                f"enrollment verifier did not reject admin authentication: {forbidden_admin.stderr}"
            )

    print(json.dumps({"ca_install_sessions": "pass", "ok": True}, sort_keys=True))


if __name__ == "__main__":
    main()
