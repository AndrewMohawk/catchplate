#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import argparse
import base64
import copy
import fcntl
import hashlib
import importlib.util
import inspect
import json
import os
import socket
import tempfile
import threading
import time
import unittest
from contextlib import ExitStack
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from fastapi import HTTPException, Request, Response
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID, ObjectIdentifier

from serverware import attestation
from serverware import app as serverware_app
from serverware import setup_receipts
from scripts import attestation_nonce_service
from scripts import attestation_verifier_state_service
from scripts import attestation_witness_service
from scripts import production_attestation_producer_issuer
from scripts import public_attestation_production_sandbox_launcher
from scripts import verify_nitro_tee
from serverware.setup_receipts import (
    Ed25519TrustRoot,
    FixedClock,
    HardwareVerificationExpected,
    ReceiptContractError,
    ReceiptVerificationError,
    SetupAssignment,
    canonical_base64url,
    canonical_json_bytes,
    sha256_digest,
    verify_setup_hardware_verification,
)


def digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("ascii")).hexdigest()


def completion_identity() -> dict[str, object]:
    return {
        "apiVersion": attestation.FINAL_COMPLETION_IDENTITY_VERSION,
        "challengeNonceSha256": digest("challenge"),
        "coreDigests": {
            name: digest(name)
            for name in attestation.FINAL_COMPLETION_CORE_FIELDS
        },
        "pipeline": attestation.PRODUCTION_PIPELINE,
        "releaseGeneration": 7,
        "rollbackEpoch": 3,
    }


def sha384_bytes(value: bytes) -> str:
    return "sha384:" + value.hex()


def stable_release_identity(
    *,
    attestation_component_pins: dict[str, str] | None = None,
    policy_sequence: int = 5,
    release_generation: int = 7,
    release_key_id: str | None = None,
    response_key_id: str | None = None,
    rollback_epoch: int = 3,
    tls_scope_key_id: str | None = None,
    trust_roots_sha256: str | None = None,
    witness_key_id: str | None = None,
    witness_store_key_id: str | None = None,
) -> dict[str, object]:
    image_sha384 = sha384_bytes(b"\x11" * 48)
    public_attestation = (
        {
            "nonceStoreIdentitySha256":
            digest("nonce-store-identity"),
            "producerExecutableSha256":
            digest("producer-executable"),
            "producerRequestSchemaSha256":
            digest("producer-request-schema"),
            "sandboxLauncherSha256":
            digest("sandbox-launcher"),
            "witnessStoreIdentitySha256":
            digest("witness-store-identity"),
            "witnessStoreKeySpkiSha256": (
                digest("witness-store-key")
                if witness_store_key_id is None
                else witness_store_key_id
            ),
        }
        if attestation_component_pins is None
        else dict(attestation_component_pins)
    )
    return {
        "apiVersion": attestation.RELEASE_IDENTITY_VERSION,
        "build": {
            "builderCoreSha256s":
            sorted([digest("builderA"), digest("builderB")]),
            "buildWatchdogReceiptSha256": digest("watchdog"),
            "candidateManifestFileSha256": digest("candidate-file"),
            "candidateManifestPayloadSha256":
            digest("candidate-payload"),
            "dependencyClosureSha256": digest("dependency-closure"),
            "eifBuildCoreSha256": digest("eif-build-core"),
            "importedImageMappingsSha256": digest("image-mappings"),
            "promotedManifestSha256": digest("promoted-manifest"),
            "promotionReceiptSha256": digest("promotion-receipt"),
            "releaseCoreSha256": digest("release-core"),
        },
        "configuration": {
            "caSpkiSha256": digest("ca"),
            "publicAttestation": public_attestation,
            "releaseKeySpkiSha256": (
                digest("release-key")
                if release_key_id is None else release_key_id
            ),
            "responseKeySpkiSha256": (
                digest("response-key")
                if response_key_id is None else response_key_id
            ),
            "tlsScopeSigningKeySpkiSha256": (
                digest("tls-scope-key")
                if tls_scope_key_id is None else tls_scope_key_id
            ),
            "trustRootBundleSha256": (
                digest("trust-roots")
                if trust_roots_sha256 is None else trust_roots_sha256
            ),
            "witnessKeySpkiSha256": (
                digest("witness-key")
                if witness_key_id is None else witness_key_id
            ),
        },
        "eif": {
            "imageSha384": image_sha384,
            "pcrs": {
                "PCR0": image_sha384,
                "PCR1": sha384_bytes(b"\x12" * 48),
                "PCR2": sha384_bytes(b"\x13" * 48),
            },
        },
        "monotonicRelease": {
            "releaseGeneration": release_generation,
            "rollbackEpoch": rollback_epoch,
        },
        "pipeline": attestation.PRODUCTION_PIPELINE,
        "policy": {
            "hash": digest(
                "policy"
                if policy_sequence == 5
                else f"policy-{policy_sequence}"
            ),
            "sequence": policy_sequence,
        },
        "source": {
            "sourceClosureSha256": digest("source-closure"),
            "sourceInputApprovalSha256": digest("source-approval"),
            "sourceInputManifestFileSha256":
            digest("source-manifest-file"),
            "sourceInputManifestPayloadSha256":
            digest("source-manifest-payload"),
        },
    }


def key_material() -> tuple[Ed25519PrivateKey, Ed25519TrustRoot, str]:
    private_key = Ed25519PrivateKey.generate()
    der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    trust = Ed25519TrustRoot(
        provider="independent-" + hashlib.sha256(der).hexdigest()[:16],
        public_key_spki_der=der,
    )
    return private_key, trust, canonical_base64url(der)


def signed_verifier_envelope(
    private_key: Ed25519PrivateKey,
    *,
    api_version: str,
    domain: bytes,
    payload: dict[str, object],
) -> dict[str, object]:
    der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    payload_sha256 = verify_nitro_tee.sha256_json(payload)
    signed = domain + verify_nitro_tee.canonical_json_bytes(
        {"payload": payload, "payloadSha256": payload_sha256}
    )
    return {
        "apiVersion": api_version,
        "payload": payload,
        "payloadSha256": payload_sha256,
        "signature": attestation.b64e(private_key.sign(signed)),
        "signingKeyId": verify_nitro_tee.sha256(der),
    }


def signed_service_envelope(
    private_key: Ed25519PrivateKey,
    *,
    api_version: str,
    domain: bytes,
    payload: dict[str, object],
) -> dict[str, object]:
    der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_id = verify_nitro_tee.sha256(der)
    payload_sha256 = verify_nitro_tee.sha256_json(payload)
    signed = domain + verify_nitro_tee.canonical_json_bytes(
        {"payload": payload, "payloadSha256": payload_sha256}
    )
    return {
        "apiVersion": api_version,
        "payload": payload,
        "payloadSha256": payload_sha256,
        "signatureAlgorithm": "Ed25519",
        "signatureBase64url": attestation.b64e(
            private_key.sign(signed)
        ),
        "signingKeyId": key_id,
        "signingKeySpkiSha256": key_id,
    }


def cbor(value: object) -> bytes:
    def length(major: int, size: int) -> bytes:
        if size < 24:
            return bytes([(major << 5) | size])
        if size < 256:
            return bytes([(major << 5) | 24, size])
        if size < 65536:
            return bytes([(major << 5) | 25]) + size.to_bytes(2, "big")
        return bytes([(major << 5) | 26]) + size.to_bytes(4, "big")

    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        return length(0, value) if value >= 0 else length(1, -1 - value)
    if isinstance(value, bytes):
        return length(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return length(3, len(encoded)) + encoded
    if isinstance(value, list):
        return length(4, len(value)) + b"".join(cbor(item) for item in value)
    if isinstance(value, dict):
        entries = [(cbor(key), cbor(item)) for key, item in value.items()]
        entries.sort(key=lambda item: (len(item[0]), item[0]))
        return length(5, len(entries)) + b"".join(
            key + item for key, item in entries
        )
    raise TypeError(value)


def nitro_document(
    *,
    nonce: bytes,
    user_data: bytes,
    pcr_byte: int = 1,
    debug: bool = False,
) -> tuple[bytes, dict[str, str]]:
    pcrs = (
        {0: b"\x00" * 48, 1: b"\x00" * 48, 2: b"\x00" * 48}
        if debug
        else {
            0: bytes([pcr_byte]) * 48,
            1: bytes([pcr_byte + 1]) * 48,
            2: bytes([pcr_byte + 2]) * 48,
        }
    )
    payload = {
        "module_id": "i-00000000000000000-enc0000000000000000",
        "digest": "SHA384",
        "timestamp": 1_000_000,
        "pcrs": pcrs,
        "certificate": b"c" * 256,
        "cabundle": [b"a" * 256],
        "public_key": b"k" * 44,
        "user_data": user_data,
        "nonce": nonce,
    }
    raw = cbor([b"\xa1\x01\x38\x22", {}, cbor(payload), b"s" * 96])
    return raw, {
        "PCR0": sha384_bytes(pcrs[0]),
        "PCR1": sha384_bytes(pcrs[1]),
        "PCR2": sha384_bytes(pcrs[2]),
    }


def strict_nitro_document(
    *,
    nonce: bytes,
    user_data: bytes,
    now_unix: int = 1_010,
    revoke_leaf: bool = False,
    stale_crl: bool = False,
    tamper_signature: bool = False,
    debug: bool = False,
) -> tuple[
    bytes,
    dict[str, str],
    attestation.NitroVerificationTrust,
    str,
]:
    root_key = ec.generate_private_key(ec.SECP384R1())
    leaf_key = ec.generate_private_key(ec.SECP384R1())
    recipient_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    root_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Nitro fixture root")]
    )
    leaf_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Nitro fixture leaf")]
    )
    valid_from = datetime.fromtimestamp(now_unix - 110, tz=timezone.utc)
    valid_until = datetime.fromtimestamp(now_unix + 990, tz=timezone.utc)
    root = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(1)
        .not_valid_before(valid_from)
        .not_valid_after(valid_until)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .sign(root_key, hashes.SHA384())
    )
    eku_oid = ObjectIdentifier("1.3.6.1.4.1.49653.1.1")
    leaf = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(root_name)
        .public_key(leaf_key.public_key())
        .serial_number(2)
        .not_valid_before(valid_from)
        .not_valid_after(valid_until)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([eku_oid]), critical=False
        )
        .sign(root_key, hashes.SHA384())
    )
    crl_builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(root_name)
        .last_update(
            datetime.fromtimestamp(now_unix - 110, tz=timezone.utc)
        )
        .next_update(
            datetime.fromtimestamp(
                now_unix - 1 if stale_crl else now_unix + 190,
                tz=timezone.utc,
            )
        )
    )
    if revoke_leaf:
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(leaf.serial_number)
            .revocation_date(
                datetime.fromtimestamp(now_unix - 60, tz=timezone.utc)
            )
            .build()
        )
        crl_builder = crl_builder.add_revoked_certificate(revoked)
    crl = crl_builder.sign(root_key, hashes.SHA384())
    module_id = "i-00000000000000000-enc0000000000000000"
    pcr_bytes = (
        {0: b"\x00" * 48, 1: b"\x00" * 48, 2: b"\x00" * 48}
        if debug
        else {
            0: b"\x11" * 48,
            1: b"\x22" * 48,
            2: b"\x33" * 48,
        }
    )
    payload = {
        "module_id": module_id,
        "digest": "SHA384",
        "timestamp": (now_unix - 10) * 1_000,
        "pcrs": pcr_bytes,
        "certificate": leaf.public_bytes(serialization.Encoding.DER),
        "cabundle": [root.public_bytes(serialization.Encoding.DER)],
        "public_key": recipient_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
        "user_data": user_data,
        "nonce": nonce,
    }
    protected = cbor({1: -35})
    payload_raw = cbor(payload)
    signed = cbor(["Signature1", protected, b"", payload_raw])
    der_signature = leaf_key.sign(signed, ec.ECDSA(hashes.SHA384()))
    r, s = decode_dss_signature(der_signature)
    signature = r.to_bytes(48, "big") + s.to_bytes(48, "big")
    if tamper_signature:
        signature = signature[:-1] + bytes([signature[-1] ^ 1])
    raw = b"\xd2" + cbor([protected, {}, payload_raw, signature])
    trust = attestation.NitroVerificationTrust(
        bundle_sha256=digest("setup-nitro-trust"),
        roots=(root,),
        crls=(crl,),
        allowed_leaf_extended_key_usage_oids=(eku_oid.dotted_string,),
        expected_module_id=module_id,
        expected_eif_sha384=sha384_bytes(pcr_bytes[0]),
        expected_pcrs=(
            sha384_bytes(pcr_bytes[0]),
            sha384_bytes(pcr_bytes[1]),
            sha384_bytes(pcr_bytes[2]),
        ),
        max_attestation_age_seconds=60,
        max_future_skew_seconds=5,
    )
    return (
        raw,
        {
            "PCR0": sha384_bytes(pcr_bytes[0]),
            "PCR1": sha384_bytes(pcr_bytes[1]),
            "PCR2": sha384_bytes(pcr_bytes[2]),
        },
        trust,
        module_id,
    )


def trusted_scope(
    *,
    exporter: bytes = b"x" * 32,
    envelope_sha256: str = digest("tls-envelope"),
) -> attestation.TrustedTlsScope:
    return attestation.TrustedTlsScope(
        api_version=attestation.TRUSTED_TLS_SCOPE_VERSION,
        provider="enclave-nitro-tls",
        exporter=exporter,
        exporter_label="EXPORTER-Serverware-Attestation-v1",
        connection_id="connection-0001",
        connection_nonce=b"n" * 32,
        issued_at_unix=1_000,
        expires_at_unix=1_060,
        leaf_certificate_sha256=digest("leaf-certificate"),
        leaf_spki_sha256=digest("tls-leaf"),
        peer_certificate_sha256=digest("peer-certificate"),
        peer_spki_sha256=digest("peer-spki"),
        peer_identity="peer-0001",
        tls_stack_measurement_sha256=digest("tls-stack"),
        enclave_instance_id="enclave-instance-0001",
        enclave_boot_id="enclave-boot-0001",
        tls_key_generation=7,
        tls_scope_key_generation=8,
        tls_scope_key_spki_sha256=digest("tls-scope-key"),
        envelope_sha256=envelope_sha256,
    )


def challenge(scope: attestation.TrustedTlsScope) -> attestation.AttestationChallenge:
    value = attestation.b64e(b"q" * 32)
    return attestation.AttestationChallenge(
        challenge_id="00000000-0000-0000-0000-000000000001",
        value=value,
        value_sha256=attestation.sha256_prefixed(b"q" * 32),
        tls_binding_sha256=scope.binding_document()["bindingSha256"],
        connection_id=scope.connection_id,
        peer_spki_sha256=scope.peer_spki_sha256,
        issued_at_unix=1_000,
        expires_at_unix=1_060,
    )


class ChallengeTests(unittest.TestCase):
    def store(self, now: list[int]) -> attestation.ProductionAttestationChallengeStore:
        return attestation.ProductionAttestationChallengeStore(
            capacity=16,
            ttl_seconds=30,
            reservation_ttl_seconds=20,
            per_peer_capacity=2,
            clock=lambda: now[0],
        )

    def issue(self, store: attestation.ProductionAttestationChallengeStore):
        return store.issue(
            tls_binding_sha256=digest("tls-binding"),
            connection_id="connection-0001",
            peer_spki_sha256=digest("peer"),
            bound_expires_at_unix=1_060,
        )

    def test_reserve_blocks_replay_and_exact_release_reopens(self) -> None:
        now = [1_000]
        store = self.store(now)
        issued = self.issue(store)
        reserved = store.reserve(
            issued.challenge_id,
            issued.value,
            issued.tls_binding_sha256,
            issued.connection_id,
            issued.peer_spki_sha256,
        )
        with self.assertRaises(attestation.AttestationContractError):
            store.reserve(
                issued.challenge_id,
                issued.value,
                issued.tls_binding_sha256,
                issued.connection_id,
                issued.peer_spki_sha256,
            )
        store.release(reserved)
        retried = store.reserve(
            issued.challenge_id,
            issued.value,
            issued.tls_binding_sha256,
            issued.connection_id,
            issued.peer_spki_sha256,
        )
        store.finalize(retried)
        with self.assertRaises(attestation.AttestationContractError):
            store.reserve(
                issued.challenge_id,
                issued.value,
                issued.tls_binding_sha256,
                issued.connection_id,
                issued.peer_spki_sha256,
            )

    def test_post_reserve_failure_can_release_only_its_token(self) -> None:
        now = [1_000]
        store = self.store(now)
        issued = self.issue(store)
        reserved = store.reserve(
            issued.challenge_id,
            issued.value,
            issued.tls_binding_sha256,
            issued.connection_id,
            issued.peer_spki_sha256,
        )
        forged = attestation.AttestationChallengeReservation(
            reservation_id="00000000-0000-0000-0000-000000000099",
            challenge=reserved.challenge,
        )
        with self.assertRaises(attestation.AttestationContractError):
            store.release(forged)
        store.release(reserved)

    def test_multi_worker_or_missing_same_connection_mode_fails_closed(self) -> None:
        with (
            mock.patch.object(attestation, "RELEASE_CHANNEL", "production"),
            mock.patch.dict(
                os.environ,
                {
                    "SERVERWARE_ATTESTATION_CHALLENGE_MODE": "single-worker",
                    "SERVERWARE_ATTESTATION_SAME_CONNECTION_ROUTING": "required",
                    "SERVERWARE_ATTESTATION_WORKER_COUNT": "2",
                },
                clear=False,
            ),
        ):
            with self.assertRaises(attestation.AttestationContractError):
                attestation._require_single_worker_challenge_deployment()

    def test_stale_and_invalid_challenges_fail_closed(self) -> None:
        now = [1_000]
        store = self.store(now)
        issued = self.issue(store)
        now[0] = issued.expires_at_unix
        with self.assertRaises(attestation.AttestationContractError):
            store.reserve(
                issued.challenge_id,
                issued.value,
                issued.tls_binding_sha256,
                issued.connection_id,
                issued.peer_spki_sha256,
            )
        with self.assertRaises(attestation.AttestationContractError):
            store.reserve(
                "00000000-0000-0000-0000-000000000099",
                issued.value,
                issued.tls_binding_sha256,
                issued.connection_id,
                issued.peer_spki_sha256,
            )


class SignedTlsScopeTests(unittest.TestCase):
    def signed_envelope(self) -> tuple[bytes, dict[str, object]]:
        private_key, trust, key_b64 = key_material()
        payload = {
            "apiVersion": attestation.TRUSTED_TLS_SCOPE_VERSION,
            "connectionId": "connection-0001",
            "connectionNonce": attestation.b64e(b"n" * 32),
            "enclaveBootId": "enclave-boot-0001",
            "enclaveInstanceId": "enclave-instance-0001",
            "expiresAtUnix": 1_060,
            "exporter": attestation.b64e(b"x" * 32),
            "exporterLabel": "EXPORTER-Serverware-Attestation-v1",
            "issuedAtUnix": 1_000,
            "leafCertificateSha256": digest("leaf-certificate"),
            "leafSpkiSha256": digest("tls-leaf"),
            "peerCertificateSha256": digest("peer-certificate"),
            "peerIdentity": "peer-0001",
            "peerSpkiSha256": digest("peer-spki"),
            "provider": "enclave-nitro-tls",
            "tlsKeyGeneration": 7,
            "tlsScopeKeyGeneration": 8,
            "tlsStackMeasurementSha256": digest("tls-stack"),
        }
        payload_sha256 = attestation.sha256_prefixed(
            attestation.canonical_json(payload).encode("ascii")
        )
        signature = private_key.sign(
            attestation.TLS_SCOPE_SIGNATURE_DOMAIN
            + attestation.canonical_json(
                {"payload": payload, "payloadSha256": payload_sha256}
            ).encode("ascii")
        )
        envelope = {
            "apiVersion": attestation.TRUSTED_TLS_SCOPE_ENVELOPE_VERSION,
            "payload": payload,
            "payloadSha256": payload_sha256,
            "signature": "ed25519:" + attestation.b64e(signature),
            "signingKeyId": trust.key_id,
        }
        raw = attestation.canonical_json(envelope).encode("ascii")
        state = {
            "custody": {
                "materials": [
                    {
                        "identitySpkiSha256": digest("tls-leaf"),
                        "keyGeneration": 7,
                        "name": "tls",
                        "scopeSigningKey": {
                            "keyGeneration": 8,
                            "publicKeySpkiDerBase64url": key_b64,
                            "publicKeySpkiSha256": trust.key_id,
                        },
                    }
                ]
            },
            "runtime": {
                "activeTlsConnection": {
                    "connectionId": payload["connectionId"],
                    "connectionNonceSha256": digest_bytes(b"n" * 32),
                    "envelopeSha256": digest_bytes(raw),
                    "expiresAtUnix": 1_060,
                    "exporterSha256": digest_bytes(b"x" * 32),
                    "issuedAtUnix": 1_000,
                    "leafCertificateSha256": digest("leaf-certificate"),
                    "leafSpkiSha256": digest("tls-leaf"),
                    "peerCertificateSha256": digest("peer-certificate"),
                    "peerIdentity": "peer-0001",
                    "peerSpkiSha256": digest("peer-spki"),
                    "tlsStackMeasurementSha256": digest("tls-stack"),
                },
                "enclaveBootId": "enclave-boot-0001",
                "enclaveInstanceId": "enclave-instance-0001",
                "keyGenerations": {"tls": 7, "tlsScope": 8},
                "tlsScopeSigningKeySpkiSha256": trust.key_id,
            },
        }
        return raw, state

    def test_typed_scope_forgery_and_signature_tampering_fail(self) -> None:
        raw, state = self.signed_envelope()
        with self.assertRaises(attestation.AttestationContractError):
            attestation.trusted_tls_scope_from_asgi(
                {
                    "extensions": {
                        attestation.TRUSTED_TLS_SCOPE_EXTENSION: trusted_scope()
                    }
                },
                production_state=state,
            )
        tampered = json.loads(raw)
        tampered["signature"] = "ed25519:" + attestation.b64e(b"z" * 64)
        with (
            mock.patch.object(attestation.time, "time", return_value=1_010),
            self.assertRaises(attestation.AttestationContractError),
        ):
            attestation.trusted_tls_scope_from_asgi(
                {
                    "extensions": {
                        attestation.TRUSTED_TLS_SCOPE_EXTENSION:
                        attestation.canonical_json(tampered).encode("ascii")
                    }
                },
                production_state=state,
            )

    def test_unavailable_extension_and_relayed_exporter_or_spki_fail(self) -> None:
        raw, state = self.signed_envelope()
        with self.assertRaises(attestation.AttestationContractError):
            attestation.trusted_tls_scope_from_asgi(
                {"extensions": {}},
                production_state=state,
            )
        with self.assertRaises(attestation.AttestationContractError):
            attestation.trusted_tls_scope_from_asgi(
                {
                    "extensions": {},
                    "headers": [
                        (b"x-serverware-enclave-tls-scope", raw)
                    ],
                },
                production_state=state,
            )
        for field, wrong in (
            ("exporterSha256", digest("wrong-exporter")),
            ("leafSpkiSha256", digest("wrong-leaf-spki")),
            ("peerSpkiSha256", digest("wrong-peer-spki")),
        ):
            relayed_state = json.loads(json.dumps(state))
            relayed_state["runtime"]["activeTlsConnection"][field] = wrong
            with (
                self.subTest(field=field),
                mock.patch.object(attestation.time, "time", return_value=1_010),
                self.assertRaises(attestation.AttestationContractError),
            ):
                attestation.trusted_tls_scope_from_asgi(
                    {
                        "extensions": {
                            attestation.TRUSTED_TLS_SCOPE_EXTENSION: raw
                        }
                    },
                    production_state=relayed_state,
                )

    def test_public_scope_uses_release_config_key_and_not_headers(
        self,
    ) -> None:
        raw, state = self.signed_envelope()
        scope_key = state["custody"]["materials"][0]["scopeSigningKey"]
        release_identity = stable_release_identity(
            tls_scope_key_id=scope_key["publicKeySpkiSha256"],
        )
        descriptor = public_evidence_descriptor(
            release_identity=release_identity,
            tls_scope_public_key_spki_der_base64url=(
                scope_key["publicKeySpkiDerBase64url"]
            ),
        )
        with mock.patch.object(attestation.time, "time", return_value=1_010):
            verified = attestation.trusted_public_tls_scope_from_asgi(
                {
                    "extensions": {
                        attestation.TRUSTED_TLS_SCOPE_EXTENSION: raw
                    },
                    "headers": [
                        (b"x-serverware-enclave-tls-scope", b"forged")
                    ],
                },
                descriptor=descriptor,
            )
        self.assertEqual(
            verified.tls_scope_key_spki_sha256,
            release_identity["configuration"][
                "tlsScopeSigningKeySpkiSha256"
            ],
        )
        wrong_descriptor = public_evidence_descriptor()
        with (
            mock.patch.object(attestation.time, "time", return_value=1_010),
            self.assertRaises(attestation.AttestationContractError),
        ):
            attestation.trusted_public_tls_scope_from_asgi(
                {
                    "extensions": {
                        attestation.TRUSTED_TLS_SCOPE_EXTENSION: raw
                    }
                },
                descriptor=wrong_descriptor,
            )


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def canonical_line(value: object) -> bytes:
    return attestation.canonical_json(value).encode("ascii") + b"\n"


def sealed_read_only_memfd(raw: bytes, label: str) -> int:
    """Fixture FD matching the producer's immutable retained-FD contract."""
    descriptor = os.memfd_create(
        "serverware-fixture-" + label,
        os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
    )
    try:
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        fcntl.fcntl(
            descriptor,
            fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_SEAL
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_WRITE,
        )
        read_only = os.open(
            f"/proc/self/fd/{descriptor}",
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
        )
    finally:
        os.close(descriptor)
    return read_only


class FixtureNonceSignerBoundary:
    """Explicitly non-production key-custody boundary for SQLite fixtures."""

    is_non_production_fixture = True

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        *,
        non_production: bool,
    ) -> None:
        if non_production is not True:
            raise ValueError(
                "fixture nonce signer requires non-production acknowledgement"
            )
        self._private_key = private_key
        self._public_key = private_key.public_key()
        self._spki = self._public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self._key_id = digest_bytes(self._spki)
        self._channel_binding_sha256 = digest(
            "fixture-nonce-signer-channel"
        )

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def spki_sha256(self) -> str:
        return self._key_id

    @property
    def channel_binding_sha256(self) -> str:
        return self._channel_binding_sha256

    def sign(self, *, domain: bytes, message: bytes) -> bytes:
        return self._private_key.sign(domain + message)

    def verify(
        self,
        *,
        signature: bytes,
        domain: bytes,
        message: bytes,
    ) -> None:
        self._public_key.verify(signature, domain + message)


def fixture_nonce_authority_assurance(
    *,
    authority_identity_sha256: str,
    administrative_domain_label: str,
) -> dict[str, object]:
    """Closed SQLite assurance profile; never production eligible."""
    return {
        "apiVersion":
        attestation_nonce_service.NONCE_AUTHORITY_ASSURANCE_VERSION,
        "administrativeDomainSha256": digest(
            administrative_domain_label
        ),
        "assuranceEvidenceSha256": None,
        "assuranceEvidenceType": "none",
        "assuranceLevel": "nonProductionFixture",
        "authorityEpoch": 1,
        "authorityGeneration": 1,
        "authorityIdentitySha256": authority_identity_sha256,
        "backendClass": "nonProductionSqlite",
        "productionEligible": False,
        "rollbackProtection": {
            "administrativeRollbackResistance": False,
            "backendAttestationRequired": False,
            "exactSuccessorRequired": True,
            "freshVerifierChallengeRequired": True,
            "keyProtection": "retainedFdReference",
            "mechanism": "none",
            "stateCommitment": "localHashChain",
            "verifierStateStoreClass": "nonProductionCallerFile",
        },
    }


class FixtureNonceVerifierStateBoundary:
    """Process-local current-head model without external CAS guarantees."""

    is_non_production_fixture = True
    provides_external_cas = False
    restart_rollback_resistant = False

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        *,
        assurance: dict[str, object],
        assurance_evidence: dict[str, object],
        assurance_evidence_sha256: str,
        assurance_sha256: str,
        nonce_receipt_signing_key_id: str,
        service_binding: dict[str, object],
        store_attestation_private_key: Ed25519PrivateKey,
        store_assurance_evidence: dict[str, object],
        store_assurance_evidence_sha256: str,
        role_separation_evidence: dict[str, object],
        role_separation_evidence_sha256: str,
        state_store_administrative_domain_sha256: str,
        state_store_configuration_sha256: str,
        state_store_identity_sha256: str,
        state_store_minimum_commit_index: int,
        state_store_minimum_generation: int,
        production_eligible: bool,
        now: int,
        non_production: bool,
    ) -> None:
        if (
            non_production is not True
            or assurance["productionEligible"] is not production_eligible
            or type(production_eligible) is not bool
        ):
            raise ValueError(
                "fixture verifier-state boundary eligibility is inconsistent"
            )
        self._private_key = private_key
        spki = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self._key_id = digest_bytes(spki)
        self._assurance = json.loads(json.dumps(assurance))
        self._assurance_evidence = json.loads(
            json.dumps(assurance_evidence)
        )
        self._assurance_evidence_sha256 = assurance_evidence_sha256
        self._assurance_sha256 = assurance_sha256
        self._nonce_receipt_signing_key_id = (
            nonce_receipt_signing_key_id
        )
        self._service_binding = json.loads(json.dumps(service_binding))
        self._store_attestation_private_key = (
            store_attestation_private_key
        )
        self._store_attestation_key_id = digest_bytes(
            store_attestation_private_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        self._store_assurance_evidence = json.loads(
            json.dumps(store_assurance_evidence)
        )
        self._store_assurance_evidence_sha256 = (
            store_assurance_evidence_sha256
        )
        self._role_separation_evidence = json.loads(
            json.dumps(role_separation_evidence)
        )
        self._role_separation_evidence_sha256 = (
            role_separation_evidence_sha256
        )
        self._state_store_administrative_domain_sha256 = (
            state_store_administrative_domain_sha256
        )
        self._state_store_configuration_sha256 = (
            state_store_configuration_sha256
        )
        self._state_store_identity_sha256 = (
            state_store_identity_sha256
        )
        self._state_store_minimum_commit_index = (
            state_store_minimum_commit_index
        )
        self._state_store_minimum_generation = (
            state_store_minimum_generation
        )
        self._production_eligible = production_eligible
        self._consumed_authorizations: set[str] = set()
        self._committed_receipts: set[str] = set()
        self._pending_authorization: dict[str, object] | None = None
        self._prepared_operation: dict[str, object] | None = None
        self._prior_read: dict[str, object] | None = None
        self._transition: dict[str, object] | None = None
        genesis_payload = {
            "apiVersion":
            verify_nitro_tee.NONCE_AUTHORITY_VERIFIER_STATE_VERSION,
            "assuranceSha256": assurance_sha256,
            "authorityEpoch": assurance["authorityEpoch"],
            "authorityGeneration":
            assurance["authorityGeneration"],
            "commitOperationIdBase64url": None,
            "committedAtUnix": now - 1,
            "highWaterCommitmentSha256": (
                attestation_nonce_service
                .nonce_authority_genesis_commitment(
                    assurance_sha256
                )
            ),
            "highWaterReceiptSha256": None,
            "highWaterSequence": 0,
            "priorVerifierStateSha256": None,
            "stateStoreGeneration": 1,
            "stateStoreHeadSha256": (
                verify_nitro_tee.sha256_json(
                    {
                        "apiVersion":
                        "serverware.fixtureNonceVerifierStateGenesis/v1",
                        "assuranceSha256": assurance_sha256,
                        "stateStoreIdentitySha256":
                        state_store_identity_sha256,
                    }
                )
            ),
            "stateStoreIdentitySha256":
            state_store_identity_sha256,
        }
        self._current_state = self._signed_envelope(
            api_version=(
                verify_nitro_tee
                .SIGNED_NONCE_AUTHORITY_VERIFIER_STATE_VERSION
            ),
            domain=(
                verify_nitro_tee
                .NONCE_AUTHORITY_VERIFIER_STATE_DOMAIN
            ),
            payload=genesis_payload,
        )

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def current_state(self) -> dict[str, object]:
        return json.loads(json.dumps(self._current_state))

    @property
    def pending_authorization(self) -> dict[str, object]:
        if self._pending_authorization is None:
            raise AssertionError(
                "fixture current-head authorization was not issued"
            )
        return json.loads(json.dumps(self._pending_authorization))

    @property
    def pending_authorization_sha256(self) -> str:
        return verify_nitro_tee.sha256_json(
            self.pending_authorization
        )

    @property
    def transition(self) -> dict[str, object]:
        if self._transition is None:
            raise AssertionError(
                "fixture verifier-state transition was not committed"
            )
        return json.loads(json.dumps(self._transition))

    def _signed_envelope(
        self,
        *,
        api_version: str,
        domain: bytes,
        payload: dict[str, object],
        private_key: Ed25519PrivateKey | None = None,
        key_id: str | None = None,
    ) -> dict[str, object]:
        signing_key = (
            self._private_key
            if private_key is None
            else private_key
        )
        signing_key_id = self._key_id if key_id is None else key_id
        payload_sha256 = verify_nitro_tee.sha256_json(payload)
        message = verify_nitro_tee.canonical_json_bytes(
            {
                "payload": payload,
                "payloadSha256": payload_sha256,
            }
        )
        return {
            "apiVersion": api_version,
            "payload": json.loads(json.dumps(payload)),
            "payloadSha256": payload_sha256,
            "signatureAlgorithm": "Ed25519",
            "signatureBase64url": attestation.b64e(
                signing_key.sign(domain + message)
            ),
            "signingKeyId": signing_key_id,
            "signingKeySpkiSha256": signing_key_id,
        }

    def prepare_current_head(
        self,
        *,
        operation_id: bytes,
        producer_invocation: dict[str, object],
        recovery_identity: dict[str, object],
        verifier_challenge: bytes,
        now: int,
    ) -> dict[str, object]:
        if self._pending_authorization is not None:
            raise AssertionError(
                "fixture current-head authorization is already pending"
            )
        prior_payload = self._current_state["payload"]
        self._prior_read = {
            "apiVersion":
            "serverware.nonceAuthorityVerifierStateReadResponse/v2",
            "challengeBase64url": attestation.b64e(verifier_challenge),
            "challengeExpiresAtUnix": now + 30,
            "challengeIssuedAtUnix": now,
            "challengeSha256": digest_bytes(verifier_challenge),
            "expectedVerifierStateSha256":
            verify_nitro_tee.sha256_json(self._current_state),
            "nonActionable": True,
            "state": self.current_state,
            "stateSha256":
            verify_nitro_tee.sha256_json(self._current_state),
        }
        if len(operation_id) != 32 or operation_id == verifier_challenge:
            raise AssertionError(
                "fixture operation ID is not an independent 32-byte value"
            )
        operation_id_base64url = attestation.b64e(operation_id)
        recovery_identity_sha256 = verify_nitro_tee.sha256_json(
            recovery_identity
        )
        recovery_key_sha256 = verify_nitro_tee.sha256(
            verify_nitro_tee
            .NONCE_AUTHORITY_VERIFIER_STATE_RECOVERY_KEY_DOMAIN
            + verify_nitro_tee.canonical_json_bytes(
                recovery_identity
            )
        )
        producer_invocation_sha256 = verify_nitro_tee.sha256_json(
            producer_invocation
        )
        request_binding = {
            "apiVersion":
            verify_nitro_tee.VERIFIER_STATE_REQUEST_BINDING_VERSION,
            "expiresAtUnix": producer_invocation["expiresAtUnix"],
            "nonceSha256": recovery_identity["callerNonceSha256"],
            "producerChannelChallengeBase64url":
            producer_invocation[
                "producerChannelChallengeBase64url"
            ],
            "producerEphemeralKeySha256":
            producer_invocation[
                "producerEphemeralKeySpkiSha256"
            ],
            "producerInvocationSha256":
            producer_invocation_sha256,
            "requestBodySha256":
            recovery_identity["requestBodySha256"],
            "tlsBindingSha256":
            producer_invocation["tlsBindingSha256"],
            "transactionIdBase64url": operation_id_base64url,
        }
        request_binding_sha256 = verify_nitro_tee.sha256(
            verify_nitro_tee
            .NONCE_AUTHORITY_VERIFIER_STATE_REQUEST_BINDING_DOMAIN
            + verify_nitro_tee.canonical_json_bytes(request_binding)
        )
        prepare_request = {
            "apiVersion":
            verify_nitro_tee.VERIFIER_STATE_PREPARE_REQUEST_VERSION,
            "assuranceSha256": self._assurance_sha256,
            "expectedVerifierStateSha256":
            verify_nitro_tee.sha256_json(self._current_state),
            "operationIdBase64url": operation_id_base64url,
            "priorStateRead": self._prior_read,
            "priorStateReadSha256":
            verify_nitro_tee.sha256_json(self._prior_read),
            "producerInvocation": producer_invocation,
            "producerInvocationSha256":
            producer_invocation_sha256,
            "recoveryIdentity": recovery_identity,
            "recoveryIdentitySha256": recovery_identity_sha256,
            "recoveryKeySha256": recovery_key_sha256,
            "requestBinding": request_binding,
            "requestBindingSha256": request_binding_sha256,
            "verifierChallengeBase64url":
            attestation.b64e(verifier_challenge),
        }
        prepare_request_sha256 = verify_nitro_tee.sha256_json(
            prepare_request
        )
        payload = {
            "apiVersion": (
                verify_nitro_tee
                .NONCE_AUTHORITY_VERIFIER_STATE_AUTHORIZATION_VERSION
            ),
            "assuranceSha256": self._assurance_sha256,
            "authorityEpoch": self._assurance["authorityEpoch"],
            "authorityGeneration":
            self._assurance["authorityGeneration"],
            "expiresAtUnix": now + 15,
            "highWaterCommitmentSha256":
            prior_payload["highWaterCommitmentSha256"],
            "highWaterReceiptSha256":
            prior_payload["highWaterReceiptSha256"],
            "highWaterSequence":
            prior_payload["highWaterSequence"],
            "issuedAtUnix": now,
            "nonceReceiptSigningKeySpkiSha256":
            self._nonce_receipt_signing_key_id,
            "nonceTransactionIdBase64url":
            operation_id_base64url,
            "oneUse": True,
            "operationIdBase64url": operation_id_base64url,
            "prepareRequestSha256": prepare_request_sha256,
            "priorVerifierStateSha256":
            verify_nitro_tee.sha256_json(self._current_state),
            "priorCommittedAtUnix":
            prior_payload["committedAtUnix"],
            "recoveryIdentitySha256": recovery_identity_sha256,
            "recoveryKeySha256": recovery_key_sha256,
            "requestBindingSha256": request_binding_sha256,
            "stateStoreAssuranceEvidenceSha256":
            self._store_assurance_evidence_sha256,
            "stateStoreAttestationKeySpkiSha256":
            self._store_attestation_key_id,
            "stateStoreConfigurationSha256":
            self._state_store_configuration_sha256,
            "stateStoreGeneration":
            prior_payload["stateStoreGeneration"],
            "stateStoreHeadSha256":
            prior_payload["stateStoreHeadSha256"],
            "stateStoreIdentitySha256":
            self._state_store_identity_sha256,
            "verifierChallengeSha256":
            digest_bytes(verifier_challenge),
        }
        self._pending_authorization = self._signed_envelope(
            api_version=(
                verify_nitro_tee
                .NONCE_AUTHORITY_VERIFIER_STATE_AUTHORIZATION_VERSION
            ),
            domain=(
                verify_nitro_tee
                .NONCE_AUTHORITY_VERIFIER_STATE_AUTHORIZATION_DOMAIN
            ),
            payload=payload,
        )
        authorization_sha256 = verify_nitro_tee.sha256_json(
            self._pending_authorization
        )
        nonce_consume_request = {
            "apiVersion":
            verify_nitro_tee
            .PUBLIC_ATTESTATION_NONCE_CONSUME_ONCE_REQUEST_VERSION,
            "expiresAtUnix": request_binding["expiresAtUnix"],
            "nonceAuthorityVerifierStateAuthorizationSha256":
            authorization_sha256,
            "nonceSha256": request_binding["nonceSha256"],
            "producerChannelChallengeBase64url":
            request_binding[
                "producerChannelChallengeBase64url"
            ],
            "producerEphemeralKeySha256":
            request_binding["producerEphemeralKeySha256"],
            "producerInvocationSha256":
            request_binding["producerInvocationSha256"],
            "requestBodySha256":
            request_binding["requestBodySha256"],
            "tlsBindingSha256":
            request_binding["tlsBindingSha256"],
            "transactionIdBase64url": operation_id_base64url,
        }
        nonce_consume_request_sha256 = verify_nitro_tee.sha256(
            verify_nitro_tee
            .PUBLIC_ATTESTATION_NONCE_CONSUME_REQUEST_DIGEST_DOMAIN
            + verify_nitro_tee.canonical_json_bytes(
                nonce_consume_request
            )
        )
        recovery_binding = {
            "apiVersion":
            verify_nitro_tee.VERIFIER_STATE_RECOVERY_BINDING_VERSION,
            "assuranceSha256": self._assurance_sha256,
            "expectedVerifierStateSha256":
            verify_nitro_tee.sha256_json(self._current_state),
            "operationIdBase64url": operation_id_base64url,
            "requestBindingSha256": request_binding_sha256,
            "verifierChallengeSha256":
            digest_bytes(verifier_challenge),
        }
        successor_intent = {
            "apiVersion":
            verify_nitro_tee.VERIFIER_STATE_SUCCESSOR_INTENT_VERSION,
            "authorizationSha256": authorization_sha256,
            "expectedHighWaterSequence":
            prior_payload["highWaterSequence"] + 1,
            "expectedStateStoreGeneration":
            prior_payload["stateStoreGeneration"] + 1,
            "expectedVerifierStateSha256":
            verify_nitro_tee.sha256_json(self._current_state),
            "nonceConsumeRequestSha256":
            nonce_consume_request_sha256,
            "operationIdBase64url": operation_id_base64url,
            "previousStateStoreHeadSha256":
            prior_payload["stateStoreHeadSha256"],
            "requestBindingSha256": request_binding_sha256,
            "transactionIdBase64url": operation_id_base64url,
            "verifierChallengeSha256":
            digest_bytes(verifier_challenge),
        }
        self._prepared_operation = {
            "apiVersion":
            verify_nitro_tee.VERIFIER_STATE_PREPARED_OPERATION_VERSION,
            "authorization": self._pending_authorization,
            "authorizationSha256": authorization_sha256,
            "nonceConsumeRequest": nonce_consume_request,
            "nonceConsumeRequestSha256":
            nonce_consume_request_sha256,
            "prepareRequest": prepare_request,
            "prepareRequestSha256": prepare_request_sha256,
            "recoveryBinding": recovery_binding,
            "recoveryIdentity": recovery_identity,
            "recoveryIdentitySha256": recovery_identity_sha256,
            "recoveryKeySha256": recovery_key_sha256,
            "requestBinding": request_binding,
            "requestBindingSha256": request_binding_sha256,
            "successorIntent": successor_intent,
            "successorIntentSha256":
            verify_nitro_tee.sha256_json(successor_intent),
        }
        return self.pending_authorization

    def commit_successor(
        self,
        receipt: dict[str, object],
        *,
        verifier_challenge: bytes,
        committed_at_unix: int,
    ) -> dict[str, object]:
        receipt_sha256 = verify_nitro_tee.sha256_json(receipt)
        if receipt_sha256 in self._committed_receipts:
            raise AssertionError("fixture nonce receipt was replayed")
        if self._pending_authorization is None:
            raise AssertionError(
                "fixture receipt has no current-head authorization"
            )
        if self._prepared_operation is None:
            raise AssertionError(
                "fixture receipt has no durable prepared operation"
            )
        authorization = self._pending_authorization
        prepared_operation = self._prepared_operation
        prepared_operation_sha256 = (
            verify_nitro_tee.sha256_json(prepared_operation)
        )
        authorization_sha256 = verify_nitro_tee.sha256_json(
            authorization
        )
        if authorization_sha256 in self._consumed_authorizations:
            raise AssertionError(
                "fixture current-head authorization was replayed"
            )
        receipt_payload = receipt["payload"]
        if (
            receipt_payload[
                "nonceAuthorityVerifierStateAuthorizationSha256"
            ]
            != authorization_sha256
            or receipt_payload["nonceAuthorityAssuranceSha256"]
            != self._assurance_sha256
            or receipt_payload["nonceAuthorityStateSha256"]
            != verify_nitro_tee.sha256_json(
                receipt_payload["nonceAuthorityState"]
            )
            or authorization["payload"]["verifierChallengeSha256"]
            != digest_bytes(verifier_challenge)
            or not (
                authorization["payload"]["issuedAtUnix"]
                <= receipt_payload["consumedAtUnix"]
                < authorization["payload"]["expiresAtUnix"]
                and receipt_payload["consumedAtUnix"]
                <= committed_at_unix
            )
        ):
            raise AssertionError(
                "fixture nonce receipt crossed its authorization or assurance"
            )
        prior_verified = {
            "document": self._current_state,
            "envelopeSha256":
            verify_nitro_tee.sha256_json(self._current_state),
            "payload": self._current_state["payload"],
        }
        authority_state = (
            verify_nitro_tee
            .validate_nonce_authority_state_transition(
                receipt_payload["nonceAuthorityState"],
                assurance=self._assurance,
                assurance_sha256=self._assurance_sha256,
                nonce_consumption_sha256=receipt_payload[
                    "nonceConsumptionSha256"
                ],
                nonce_verifier_state_authorization_sha256=(
                    authorization_sha256
                ),
                previous_receipt_sha256=receipt_payload[
                    "previousReceiptSha256"
                ],
                sequence=receipt_payload["sequence"],
                transaction_id_base64url=receipt_payload[
                    "transactionIdBase64url"
                ],
                prior_verifier_state=prior_verified,
            )
        )
        prior_payload = self._current_state["payload"]
        next_generation = prior_payload["stateStoreGeneration"] + 1
        operation_id = authorization["payload"][
            "operationIdBase64url"
        ]
        authority_state_sha256 = verify_nitro_tee.sha256_json(
            authority_state
        )
        commit_request = {
            "apiVersion":
            "serverware.attestationVerifierStateCommitRequest/v3",
            "authorization": authorization,
            "nonceConsumptionReceipt": receipt,
            "preparedOperationSha256":
            prepared_operation_sha256,
            "recoveryKeySha256":
            prepared_operation["recoveryKeySha256"],
            "requestBindingSha256":
            prepared_operation["requestBindingSha256"],
            "verifierChallengeBase64url":
            attestation.b64e(verifier_challenge),
        }
        commit_request_sha256 = verify_nitro_tee.sha256_json(
            commit_request
        )
        next_state_head_sha256 = verify_nitro_tee.sha256(
            verify_nitro_tee.NONCE_AUTHORITY_VERIFIER_STATE_HEAD_DOMAIN
            + verify_nitro_tee.canonical_json_bytes(
                {
                    "assuranceSha256": self._assurance_sha256,
                    "authorizationSha256": authorization_sha256,
                    "commitOperationIdBase64url": operation_id,
                    "nonceAuthorityStateSha256":
                    authority_state_sha256,
                    "nonceConsumptionReceiptSha256":
                    receipt_sha256,
                    "previousStateStoreHeadSha256":
                    prior_payload["stateStoreHeadSha256"],
                    "stateStoreGeneration": next_generation,
                }
            )
        )
        committed_state = {
            "apiVersion":
            verify_nitro_tee.NONCE_AUTHORITY_VERIFIER_STATE_VERSION,
            "assuranceSha256": self._assurance_sha256,
            "authorityEpoch": self._assurance["authorityEpoch"],
            "authorityGeneration":
            self._assurance["authorityGeneration"],
            "commitOperationIdBase64url": operation_id,
            "committedAtUnix": committed_at_unix,
            "highWaterCommitmentSha256":
            authority_state["highWaterCommitmentSha256"],
            "highWaterReceiptSha256": receipt_sha256,
            "highWaterSequence":
            authority_state["highWaterSequence"],
            "priorVerifierStateSha256":
            verify_nitro_tee.sha256_json(self._current_state),
            "stateStoreGeneration": next_generation,
            "stateStoreHeadSha256": next_state_head_sha256,
            "stateStoreIdentitySha256":
            self._state_store_identity_sha256,
        }
        commit_candidate = {
            "apiVersion":
            "serverware.verifierStateStoreCommitCandidate/v2",
            "assuranceSha256": self._assurance_sha256,
            "authorizationSha256": authorization_sha256,
            "commitRequestSha256": commit_request_sha256,
            "expectedVerifierStateSha256":
            verify_nitro_tee.sha256_json(self._current_state),
            "nonceAuthorityStateSha256": authority_state_sha256,
            "nonceConsumptionReceiptSha256": receipt_sha256,
            "nonceConsumptionSha256":
            receipt_payload["nonceConsumptionSha256"],
            "operationIdBase64url": operation_id,
            "previousCommittedAtUnix":
            prior_payload["committedAtUnix"],
            "previousStateStoreGeneration":
            prior_payload["stateStoreGeneration"],
            "previousStateStoreHeadSha256":
            prior_payload["stateStoreHeadSha256"],
            "proposedStateStoreGeneration": next_generation,
            "proposedStateStoreHeadSha256": next_state_head_sha256,
            "verifierChallengeSha256":
            digest_bytes(verifier_challenge),
        }
        signed_store_commit_proof = self._signed_envelope(
            api_version=(
                "serverware.signedVerifierStateStoreCommitProof/v3"
            ),
            domain=(
                b"serverware.verifierStateStoreCommitProof/v3"
                b"\x00Ed25519\x00"
            ),
            payload={
                "apiVersion":
                "serverware.verifierStateStoreCommitProof/v3",
                "authorizationSha256": authorization_sha256,
                "casCommitted": True,
                "commitCandidateSha256":
                verify_nitro_tee.sha256_json(commit_candidate),
                "commitClockMonotonic": True,
                "commitRequestSha256": commit_request_sha256,
                "committedAtUnix": committed_at_unix,
                "operationIdBase64url": operation_id,
                "previousCommittedAtUnix":
                prior_payload["committedAtUnix"],
                "previousVerifierStateSha256":
                verify_nitro_tee.sha256_json(self._current_state),
                "productionEligible": self._production_eligible,
                "stateStoreAdministrativeDomainSha256":
                self._state_store_administrative_domain_sha256,
                "stateStoreAssuranceEvidenceSha256":
                self._store_assurance_evidence_sha256,
                "stateStoreAttestationKeySpkiSha256":
                self._store_attestation_key_id,
                "stateStoreCommitIndex": next_generation,
                "stateStoreConfigurationSha256":
                self._state_store_configuration_sha256,
                "stateStoreGeneration": next_generation,
                "stateStoreIdentitySha256":
                self._state_store_identity_sha256,
            },
            private_key=self._store_attestation_private_key,
            key_id=self._store_attestation_key_id,
        )
        signed_store_commit_proof_sha256 = (
            verify_nitro_tee.sha256_json(
                signed_store_commit_proof
            )
        )
        commit_payload = {
            "apiVersion": (
                verify_nitro_tee
                .NONCE_AUTHORITY_VERIFIER_STATE_COMMIT_RECEIPT_VERSION
            ),
            "assuranceSha256": self._assurance_sha256,
            "authorizationSha256": authorization_sha256,
            "casCommitted": True,
            "commitOperationIdBase64url": operation_id,
            "commitRequestSha256": commit_request_sha256,
            "committedAtUnix": committed_at_unix,
            "committedVerifierState": committed_state,
            "committedVerifierStateSha256":
            verify_nitro_tee.sha256_json(committed_state),
            "nonceAuthorityStateSha256":
            authority_state_sha256,
            "nonceConsumptionReceiptSha256": receipt_sha256,
            "nonceConsumptionSha256":
            receipt_payload["nonceConsumptionSha256"],
            "nonceReceiptSigningKeySpkiSha256":
            self._nonce_receipt_signing_key_id,
            "oneUseAuthorizationConsumed": True,
            "preparedOperationSha256":
            prepared_operation_sha256,
            "previousStateStoreGeneration":
            prior_payload["stateStoreGeneration"],
            "previousStateStoreHeadSha256":
            prior_payload["stateStoreHeadSha256"],
            "priorVerifierStateSha256":
            verify_nitro_tee.sha256_json(self._current_state),
            "recoveryIdentitySha256":
            prepared_operation["recoveryIdentitySha256"],
            "recoveryKeySha256":
            prepared_operation["recoveryKeySha256"],
            "requestBindingSha256":
            prepared_operation["requestBindingSha256"],
            "signedStoreCommitProof": signed_store_commit_proof,
            "signedStoreCommitProofSha256":
            signed_store_commit_proof_sha256,
            "stateStoreAdministrativeDomainSha256":
            self._state_store_administrative_domain_sha256,
            "stateStoreAssuranceEvidenceSha256":
            self._store_assurance_evidence_sha256,
            "stateStoreAttestationKeySpkiSha256":
            self._store_attestation_key_id,
            "stateStoreCommitIndex": next_generation,
            "stateStoreConfigurationSha256":
            self._state_store_configuration_sha256,
            "stateStoreGeneration": next_generation,
            "stateStoreIdentitySha256":
            self._state_store_identity_sha256,
            "verifierChallengeSha256":
            digest_bytes(verifier_challenge),
        }
        commit_receipt = self._signed_envelope(
            api_version=(
                verify_nitro_tee
                .NONCE_AUTHORITY_VERIFIER_STATE_COMMIT_RECEIPT_VERSION
            ),
            domain=(
                verify_nitro_tee
                .NONCE_AUTHORITY_VERIFIER_STATE_COMMIT_RECEIPT_DOMAIN
            ),
            payload=commit_payload,
        )
        self._consumed_authorizations.add(authorization_sha256)
        self._committed_receipts.add(receipt_sha256)
        self._current_state = self._signed_envelope(
            api_version=(
                verify_nitro_tee
                .SIGNED_NONCE_AUTHORITY_VERIFIER_STATE_VERSION
            ),
            domain=(
                verify_nitro_tee
                .NONCE_AUTHORITY_VERIFIER_STATE_DOMAIN
            ),
            payload=committed_state,
        )
        final_challenge = hashlib.sha256(
            verifier_challenge + b":fixture-final-read"
        ).digest()
        if final_challenge == verifier_challenge:
            raise AssertionError(
                "fixture final verifier challenge was not independent"
            )
        final_read = {
            "apiVersion":
            "serverware.nonceAuthorityVerifierStateReadResponse/v2",
            "challengeBase64url": attestation.b64e(final_challenge),
            "challengeExpiresAtUnix": committed_at_unix + 30,
            "challengeIssuedAtUnix": committed_at_unix,
            "challengeSha256": digest_bytes(final_challenge),
            "expectedVerifierStateSha256":
            verify_nitro_tee.sha256_json(self._current_state),
            "nonActionable": True,
            "state": self.current_state,
            "stateSha256":
            verify_nitro_tee.sha256_json(self._current_state),
        }
        if self._prior_read is None:
            raise AssertionError(
                "fixture transition has no service-issued prior read"
            )
        self._transition = {
            "apiVersion":
            "serverware.nonceAuthorityVerifierStateTransition/v3",
            "assurance": self._assurance,
            "assuranceEvidence": self._assurance_evidence,
            "assuranceEvidenceSha256":
            self._assurance_evidence_sha256,
            "assuranceSha256": self._assurance_sha256,
            "authorization": authorization,
            "authorizationSha256": authorization_sha256,
            "commitRequest": commit_request,
            "commitRequestSha256": commit_request_sha256,
            "commitReceipt": commit_receipt,
            "commitReceiptSha256":
            verify_nitro_tee.sha256_json(commit_receipt),
            "committedState": self.current_state,
            "committedStateRead": final_read,
            "committedStateReadSha256":
            verify_nitro_tee.sha256_json(final_read),
            "committedStateSha256":
            verify_nitro_tee.sha256_json(self._current_state),
            "nonActionable": True,
            "nonceAuthorityState": authority_state,
            "nonceAuthorityStateSha256": authority_state_sha256,
            "nonceConsumptionReceipt": receipt,
            "nonceConsumptionReceiptSha256": receipt_sha256,
            "nonceConsumptionSha256":
            receipt_payload["nonceConsumptionSha256"],
            "operationIdBase64url": operation_id,
            "preparedOperation": prepared_operation,
            "preparedOperationSha256":
            prepared_operation_sha256,
            "priorState": self._prior_read["state"],
            "priorStateRead": self._prior_read,
            "priorStateReadSha256":
            verify_nitro_tee.sha256_json(self._prior_read),
            "priorStateSha256":
            self._prior_read["stateSha256"],
            "recoveryIdentity":
            prepared_operation["recoveryIdentity"],
            "recoveryIdentitySha256":
            prepared_operation["recoveryIdentitySha256"],
            "recoveryKeySha256":
            prepared_operation["recoveryKeySha256"],
            "requestBindingSha256":
            prepared_operation["requestBindingSha256"],
            "roleSeparationEvidence": self._role_separation_evidence,
            "roleSeparationEvidenceSha256":
            self._role_separation_evidence_sha256,
            "serviceBinding": self._service_binding,
            "signedStoreCommitProof": signed_store_commit_proof,
            "signedStoreCommitProofSha256":
            signed_store_commit_proof_sha256,
            "storeAssuranceEvidence": self._store_assurance_evidence,
            "storeAssuranceEvidenceSha256":
            self._store_assurance_evidence_sha256,
            "transactionIdBase64url":
            receipt_payload["transactionIdBase64url"],
            "verifierChallengeBase64url":
            attestation.b64e(verifier_challenge),
            "verifierChallengeSha256":
            digest_bytes(verifier_challenge),
        }
        self._pending_authorization = None
        self._prepared_operation = None
        return commit_receipt


def fixture_sandbox_descriptor(
    *,
    producer_executable_sha256: str,
    producer_request_schema_sha256: str,
    sandbox_launcher_sha256: str,
    trust_roots_sha256: str,
    nonce_service_executable_sha256: str,
    witness_service_executable_sha256: str,
) -> dict[str, object]:
    challenge = {
        "apiVersion":
        "serverware.publicAttestationServiceChannelChallenge/v1",
        "challengeBytes": 32,
        "required": True,
    }

    def service_fd(
        *,
        direction: str,
        executable_sha256: str,
        protocol: str,
        role: str,
        socket_type: str,
        target_fd: int,
    ) -> dict[str, object]:
        return {
            "access": "read-write",
            "direction": direction,
            "kind": "connected-unix-service",
            "peerCgroupPath": "/serverware-attestation-services",
            "peerExecutableSha256": executable_sha256,
            "peerGid": 0,
            "peerUid": 0,
            "protocol": protocol,
            "protocolChallenge": challenge,
            "role": role,
            "socketType": socket_type,
            "targetFd": target_fd,
        }

    named_fds = [
        service_fd(
            direction="producer-to-service",
            executable_sha256=nonce_service_executable_sha256,
            protocol="serverware.attestationNonceService/v2",
            role="nonceRequest",
            socket_type="SOCK_STREAM",
            target_fd=4,
        ),
        service_fd(
            direction="service-to-producer",
            executable_sha256=nonce_service_executable_sha256,
            protocol="serverware.attestationNonceService/v2",
            role="nonceResponse",
            socket_type="SOCK_STREAM",
            target_fd=5,
        ),
        {
            "access": "read-only",
            "kind": "sealed-release-bound-file",
            "maxBytes": 64 * 1024,
            "requireSealed": True,
            "role": "producerDescriptor",
            "targetFd": 6,
        },
        {
            "access": "read-only",
            "exactBytes": 32,
            "kind": "sealed-ephemeral-secret",
            "requireSealed": True,
            "role": "producerEphemeralSeed",
            "targetFd": 7,
        },
        {
            "access": "read-only",
            "kind": "sealed-measurement-copy",
            "maxBytes": 256 * 1024 * 1024,
            "measurementOf": "producerExecutable",
            "requireSealed": True,
            "role": "producerExecutableMeasurement",
            "targetFd": 8,
        },
        {
            "access": "read-only",
            "expectedSha256": producer_request_schema_sha256,
            "kind": "sealed-regular-file",
            "maxBytes": 4 * 1024 * 1024,
            "requireSealed": True,
            "role": "producerRequestSchema",
            "targetFd": 9,
        },
        {
            "access": "read-only",
            "kind": "sealed-measurement-copy",
            "maxBytes": 64 * 1024,
            "measurementOf": "sandboxDescriptor",
            "requireSealed": True,
            "role": "sandboxDescriptorMeasurement",
            "targetFd": 10,
        },
        {
            "access": "read-only",
            "expectedSha256": sandbox_launcher_sha256,
            "kind": "sealed-regular-file",
            "maxBytes": 256 * 1024 * 1024,
            "requireSealed": True,
            "role": "sandboxLauncher",
            "targetFd": 11,
        },
        {
            "access": "read-only",
            "kind": "sealed-release-bound-file",
            "maxBytes": 2 * 1024 * 1024,
            "requireSealed": True,
            "role": "stableReleaseStatement",
            "targetFd": 12,
        },
        {
            "access": "read-only",
            "expectedSha256": trust_roots_sha256,
            "kind": "sealed-regular-file",
            "maxBytes": 4 * 1024 * 1024,
            "requireSealed": True,
            "role": "trustRoots",
            "targetFd": 13,
        },
        service_fd(
            direction="producer-to-service",
            executable_sha256=witness_service_executable_sha256,
            protocol="serverware.attestationWitnessService/v2",
            role="witnessRequest",
            socket_type="SOCK_SEQPACKET",
            target_fd=14,
        ),
        service_fd(
            direction="service-to-producer",
            executable_sha256=witness_service_executable_sha256,
            protocol="serverware.attestationWitnessService/v2",
            role="witnessResponse",
            socket_type="SOCK_SEQPACKET",
            target_fd=15,
        ),
    ]
    return {
        "apiVersion":
        "serverware.publicAttestationExecutionSandbox/v2",
        "capabilities": {
            "ambient": [],
            "bounding": [],
            "effective": [],
            "inheritable": [],
            "permitted": [],
        },
        "cgroup": {
            "disposable": True,
            "fdRole": "cgroup",
            "identity": {
                "device": 1,
                "filesystemMagic": 0x63677270,
                "gid": 0,
                "inode": 2,
                "mode": 0o555,
                "mountId": 1,
                "uid": 0,
            },
            "killMode": "pid-namespace-init-plus-cgroup.kill",
            "limits": {
                "cgroupMaxDepth": 0,
                "cgroupMaxDescendants": 0,
                "cpuMaxPeriodMicros": 100_000,
                "cpuMaxQuotaMicros": 50_000,
                "cpuWeight": 100,
                "ioMax": [
                    {
                        "major": 8,
                        "minor": 0,
                        "rbps": 16 * 1024 * 1024,
                        "riops": 1024,
                        "wbps": 16 * 1024 * 1024,
                        "wiops": 1024,
                    }
                ],
                "memoryHighBytes": 64 * 1024 * 1024,
                "memoryMaxBytes": 128 * 1024 * 1024,
                "memoryOomGroup": True,
                "memorySwapMaxBytes": 0,
                "pidsMax": 16,
            },
            "membershipPath": "/serverware-public-attestation",
            "path": "/sys/fs/cgroup/serverware-public-attestation",
            "requireEmptyBeforeLaunch": True,
            "requireEmptyOnExit": True,
            "requiredControllers": ["cpu", "io", "memory", "pids"],
        },
        "executionMode": "fixture-non-production",
        "executable": {
            "architecture": "x86_64",
            "command": {
                "apiVersion":
                "serverware.publicAttestationProducerCommand/v1",
                "expectedTrustRootsSha256": trust_roots_sha256,
                "fdRoles": {
                    role: role
                    for role in (
                        "nonceRequest",
                        "nonceResponse",
                        "producerDescriptor",
                        "producerEphemeralSeed",
                        "producerExecutableMeasurement",
                        "producerRequestSchema",
                        "sandboxDescriptorMeasurement",
                        "sandboxLauncher",
                        "stableReleaseStatement",
                        "trustRoots",
                        "witnessRequest",
                        "witnessResponse",
                    )
                },
                "ioTimeoutMilliseconds": 1_000,
                "operation": "produce-bundle",
            },
            "executionSource": "sealed-memfd",
            "executableSha256": producer_executable_sha256,
            "format": "elf",
            "requireSealed": True,
            "sourceFdRole": "producerExecutable",
            "static": True,
        },
        "fdPolicy": {
            "closeAllOthers": True,
            "immutableConfig": {
                "access": "read-only",
                "binding": {
                    "configApiVersion":
                    "serverware.publicAttestationConfig/v2",
                    "releaseIdentityConfigurationField":
                    "configuration",
                    "releaseIdentityField": "releaseIdentity",
                    "releaseIdentityPublicAttestationField":
                    "publicAttestation",
                    "releaseIdentitySandboxDescriptorSha256Field":
                    "sandboxDescriptorSha256",
                    "sandboxDescriptorSha256Field":
                    "sandboxDescriptorSha256",
                },
                "maxBytes": 1024 * 1024,
                "requireSealed": True,
                "sourceFdRole": "immutableConfig",
                "targetFd": 3,
            },
            "namedProducerFds": named_fds,
            "stderr": "closed",
            "stdin": {
                "access": "read-only",
                "maxBytes": 256 * 1024,
                "requireSealed": True,
                "source": "launcher-stdin",
                "targetFd": 0,
            },
            "stdout": {
                "access": "write-only",
                "source": "launcher-stdout",
                "targetFd": 1,
            },
        },
        "identity": {
            "gid": 65534,
            "supplementaryGroups": [],
            "uid": 65534,
        },
        "monitoring": {
            "killAndReapTimeoutMilliseconds": 1_000,
            "limitMutationWatch":
            "inotify-fail-on-write-attrib-delete-move",
            "membershipPollMilliseconds": 10,
            "startupTimeoutMilliseconds": 1_000,
        },
        "namespaces": {
            "required": ["cgroup", "ipc", "mount", "network", "pid", "uts"],
            "userNamespace": False,
        },
        "network": {
            "allowedAddressFamilies": ["AF_UNIX"],
            "denyNewNetworkSockets": True,
            "loopback": "down",
            "mode": "none",
        },
        "noNewPrivileges": True,
        "process": {
            "launcherIsSessionLeader": True,
            "namespaceInitIsProducer": True,
            "parentDeathSignal": "SIGKILL",
            "producerIsProcessGroupLeader": True,
            "producerStartsNewSession": True,
            "reapEntireTreeBeforeExit": True,
        },
        "productionClaim": False,
        "rootFilesystem": {
            "bindMounts": [],
            "emptyTmpfs": True,
            "maxBytes": 16 * 1024 * 1024,
            "nodev": True,
            "noexec": True,
            "nosuid": True,
            "path": "/run/serverware/public-attestation-root",
            "readOnlyAfterSetup": True,
            "rootDirectoryFdRole": "sandboxRoot",
            "rootDirectoryIdentity": {
                "device": 1,
                "gid": 0,
                "inode": 1,
                "mode": 0o555,
                "uid": 0,
            },
        },
        "seccomp": {
            "architecture": "x86_64",
            "blocksNamespaceCreation": True,
            "blocksProcessGroupEscape": True,
            "blocksSocketCreation": True,
            "defaultAction": "kill-process",
            "format": "linux-cbpf-sock-filter-le-v1",
            "instructionCount": 1,
            "profileFdRole": "seccompProfile",
            "profileSha256": digest("fixture-seccomp-profile"),
        },
    }


def producer_trust_key_record(
    private_key: Ed25519PrivateKey,
) -> dict[str, str]:
    public_key = private_key.public_key()
    key_file = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    spki = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    raw = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return {
        "fileBase64url": attestation.b64e(key_file),
        "keyFileSha256": digest_bytes(key_file),
        "keyId": digest_bytes(spki),
        "rawKeySha256": digest_bytes(raw),
    }


def fixture_public_trust_roots(
    *,
    now: int,
) -> tuple[
    bytes,
    dict[str, Ed25519PrivateKey],
    dict[str, object],
]:
    _, _, nitro_trust, _ = strict_nitro_document(
        nonce=b"t" * 32,
        user_data=b"r" * 64,
        now_unix=now,
    )
    private_keys = {
        role: Ed25519PrivateKey.generate()
        for role in production_attestation_producer_issuer.TRUST_KEY_ROLES
    }
    document = {
        "apiVersion":
        production_attestation_producer_issuer.TRUST_ROOTS_VERSION,
        "awsNitroCrlsDerBase64url": [
            attestation.b64e(
                item.public_bytes(serialization.Encoding.DER)
            )
            for item in nitro_trust.crls
        ],
        "awsNitroRootCertificatesPem": [
            item.public_bytes(
                serialization.Encoding.PEM
            ).decode("ascii")
            for item in nitro_trust.roots
        ],
        "keys": {
            role: producer_trust_key_record(private_keys[role])
            for role in production_attestation_producer_issuer.TRUST_KEY_ROLES
        },
        "nitroCertificateProfile": {
            "allowedLeafExtendedKeyUsageOids": sorted(
                nitro_trust.allowed_leaf_extended_key_usage_oids
            ),
            "profileId": "aws-nitro-attestation-pki-offline-v1",
        },
    }
    raw = canonical_line(document)
    trust = production_attestation_producer_issuer.load_trust_roots(
        raw,
        independently_expected_sha256=digest_bytes(raw),
    )
    return raw, private_keys, trust


class FixtureStableReleaseSignerBoundary:
    """Process-local signer fixture; never evidence of restart safety.

    The lock makes authorization consumption and high-water updates atomic only
    within this process. Production requires an external rollback-resistant
    signer-owned authorization, consumption, and high-water backend.
    """

    is_non_production_fixture = True

    _REQUEST_FIELDS = {
        "algorithm",
        "apiVersion",
        "authorizationNonceBase64url",
        "keyId",
        "preauthorization",
        "preauthorizationSha256",
        "purpose",
        "statementPayload",
        "statementPayloadSha256",
    }
    _PREAUTHORIZATION_FIELDS = {
        "approvedIssuerRequestSha256",
        "authorizationExpiresAtUnix",
        "authorizationIdBase64url",
        "authorizationIssuedAtUnix",
        "authorizationNonceSha256",
        "authorizationSequence",
        "minimumPolicySequence",
        "minimumReleaseGeneration",
        "minimumRollbackEpoch",
        "releaseIdentitySha256",
        "statementPayloadSha256",
        "useLimit",
    }
    _STATEMENT_PAYLOAD_FIELDS = {
        "attestationPins",
        "releaseIdentity",
        "releaseIdentitySha256",
        "trustRootBundleSha256",
    }
    _STATEMENT_PIN_FIELDS = {
        "descriptorSha256",
        "executableSha256",
        "immutableConfigSha256",
        "nonceStoreIdentitySha256",
        "nonceStoreKeySpkiSha256",
        "producerRequestSchemaSha256",
        "sandboxDescriptorSha256",
        "sandboxLauncherSha256",
        "trustRootsSha256",
        "witnessStoreIdentitySha256",
        "witnessStoreKeySpkiSha256",
    }

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        *,
        now_unix: int | None = None,
        non_production: bool,
        provisioning_capability: object,
    ) -> None:
        if non_production is not True:
            raise ValueError(
                "fixture release signer requires non-production acknowledgement"
            )
        self._private_key = private_key
        public_key = private_key.public_key()
        spki = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self._key_id = digest_bytes(spki)
        self._now_unix = now_unix
        self._lock = threading.Lock()
        self._preauthorizations: dict[
            tuple[str, str], dict[str, object]
        ] = {}
        self._consumed: set[tuple[str, str]] = set()
        self._authorization_sequence_high_water: dict[str, int] = {}
        self._release_high_water: dict[
            str, tuple[int, int, int]
        ] = {}
        self.__provisioning_capability = provisioning_capability

    @property
    def key_id(self) -> str:
        return self._key_id

    @staticmethod
    def _clone(value: object) -> object:
        return json.loads(json.dumps(value))

    @staticmethod
    def _require_exact(
        value: object,
        fields: set[str],
        label: str,
    ) -> dict[str, object]:
        if not isinstance(value, dict) or set(value) != fields:
            raise AssertionError(f"{label} is not an exact object")
        return value

    @staticmethod
    def _require_sha256(value: object, label: str) -> str:
        if (
            not isinstance(value, str)
            or len(value) != 71
            or not value.startswith("sha256:")
            or any(
                character not in "0123456789abcdef"
                for character in value[7:]
            )
        ):
            raise AssertionError(f"{label} is not a SHA-256 digest")
        return value

    def _install_preauthorization(
        self,
        *,
        capability: object,
        key_id: str,
        preauthorization: dict[str, object],
    ) -> None:
        if capability is not self.__provisioning_capability:
            raise AssertionError(
                "fixture signer provisioning capability is invalid"
            )
        document = self._require_exact(
            self._clone(preauthorization),
            self._PREAUTHORIZATION_FIELDS,
            "fixture signer preauthorization",
        )
        authorization_id = document["authorizationIdBase64url"]
        if not isinstance(authorization_id, str):
            raise AssertionError("fixture signer authorization id is invalid")
        if key_id != self._key_id:
            raise AssertionError("fixture signer key id is invalid")
        key = (key_id, authorization_id)
        with self._lock:
            if key in self._preauthorizations:
                raise AssertionError(
                    "fixture signer authorization was provisioned twice"
                )
            self._preauthorizations[key] = document

    def sign_request(
        self,
        request_value: object,
    ) -> dict[str, object]:
        request = self._require_exact(
            self._clone(request_value),
            self._REQUEST_FIELDS,
            "fixture release signer request",
        )
        if (
            request["apiVersion"]
            != production_attestation_producer_issuer.SIGN_REQUEST_VERSION
            or request["algorithm"] != "Ed25519"
            or request["purpose"] != "stable-release-statement"
            or request["keyId"] != self._key_id
        ):
            raise AssertionError(
                "fixture release signer request crossed its command"
            )
        preauthorization = self._require_exact(
            request["preauthorization"],
            self._PREAUTHORIZATION_FIELDS,
            "fixture release signer preauthorization",
        )
        statement_payload = self._require_exact(
            request["statementPayload"],
            self._STATEMENT_PAYLOAD_FIELDS,
            "fixture stable statement payload",
        )
        authorization_nonce_base64url = request[
            "authorizationNonceBase64url"
        ]
        if not isinstance(authorization_nonce_base64url, str):
            raise AssertionError(
                "fixture release signer authorization nonce is invalid"
            )
        # Python's decoder first creates immutable bytes. Convert immediately,
        # drop that reference, and wipe the mutable copy on every path. This
        # fixture does not claim complete heap or serialized-buffer zeroization.
        immutable_nonce = attestation.b64d(
            authorization_nonce_base64url
        )
        authorization_nonce = bytearray(immutable_nonce)
        del immutable_nonce
        try:
            if (
                len(authorization_nonce) != 32
                or attestation.b64e(authorization_nonce)
                != authorization_nonce_base64url
            ):
                raise AssertionError(
                    "fixture release signer authorization nonce is invalid"
                )
            return self._sign_request_with_nonce(
                request=request,
                preauthorization=preauthorization,
                statement_payload=statement_payload,
                authorization_nonce=authorization_nonce,
            )
        finally:
            production_attestation_producer_issuer.zeroize(
                authorization_nonce
            )

    def _sign_request_with_nonce(
        self,
        *,
        request: dict[str, object],
        preauthorization: dict[str, object],
        statement_payload: dict[str, object],
        authorization_nonce: bytearray,
    ) -> dict[str, object]:
        statement_payload_sha256 = (
            production_attestation_producer_issuer.sha256_json(
                statement_payload
            )
        )
        preauthorization_sha256 = (
            production_attestation_producer_issuer.sha256_json(
                preauthorization
            )
        )
        if (
            request["statementPayloadSha256"]
            != statement_payload_sha256
            or request["preauthorizationSha256"]
            != preauthorization_sha256
            or preauthorization["statementPayloadSha256"]
            != statement_payload_sha256
            or preauthorization["authorizationNonceSha256"]
            != production_attestation_producer_issuer.sha256_bytes(
                authorization_nonce
            )
        ):
            raise AssertionError(
                "fixture release signer request digest is invalid"
            )
        try:
            pins = (
                production_attestation_producer_issuer.statement_pins(
                    statement_payload["attestationPins"],
                    "fixture stable statement pins",
                )
            )
            release_identity = (
                production_attestation_producer_issuer
                .validate_release_identity(
                    statement_payload["releaseIdentity"],
                    label="fixture stable release identity",
                )
            )
        except production_attestation_producer_issuer.ContractError as exc:
            raise AssertionError(
                "fixture stable statement contract is invalid"
            ) from exc
        release_identity_sha256 = (
            production_attestation_producer_issuer.sha256_json(
                release_identity
            )
        )
        if (
            statement_payload["releaseIdentitySha256"]
            != release_identity_sha256
            or preauthorization["releaseIdentitySha256"]
            != release_identity_sha256
            or statement_payload["trustRootBundleSha256"]
            != pins["trustRootsSha256"]
            or release_identity["configuration"][
                "releaseKeySpkiSha256"
            ] != self._key_id
            or release_identity["configuration"][
                "trustRootBundleSha256"
            ] != pins["trustRootsSha256"]
            or release_identity["configuration"]["publicAttestation"]
            != production_attestation_producer_issuer
            .component_pins_from_statement(pins)
        ):
            raise AssertionError(
                "fixture release signer stable target is invalid"
            )
        authorization_id = preauthorization[
            "authorizationIdBase64url"
        ]
        if not isinstance(authorization_id, str):
            raise AssertionError(
                "fixture release signer authorization id is invalid"
            )
        authorization_id_raw = attestation.b64d(authorization_id)
        if (
            len(authorization_id_raw) != 32
            or attestation.b64e(authorization_id_raw) != authorization_id
        ):
            raise AssertionError(
                "fixture release signer authorization id is invalid"
            )
        self._require_sha256(
            preauthorization["approvedIssuerRequestSha256"],
            "fixture approved issuer request",
        )
        key = (self._key_id, authorization_id)
        now = (
            int(
                production_attestation_producer_issuer.time.time()
            )
            if self._now_unix is None
            else self._now_unix
        )
        issued_at = preauthorization["authorizationIssuedAtUnix"]
        expires_at = preauthorization["authorizationExpiresAtUnix"]
        sequence = preauthorization["authorizationSequence"]
        counters = {
            "authorizationExpiresAtUnix": expires_at,
            "authorizationIssuedAtUnix": issued_at,
            "authorizationSequence": sequence,
            "minimumPolicySequence":
            preauthorization["minimumPolicySequence"],
            "minimumReleaseGeneration":
            preauthorization["minimumReleaseGeneration"],
            "minimumRollbackEpoch":
            preauthorization["minimumRollbackEpoch"],
            "useLimit": preauthorization["useLimit"],
        }
        for field, value in counters.items():
            minimum = (
                0 if field == "minimumRollbackEpoch" else 1
            )
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < minimum
                or value > 18_446_744_073_709_551_615
            ):
                raise AssertionError(
                    "fixture release signer authorization "
                    f"{field} is invalid"
                )
        policy = release_identity["policy"]
        monotonic = release_identity["monotonicRelease"]
        policy_sequence = policy["sequence"]
        release_generation = monotonic["releaseGeneration"]
        rollback_epoch = monotonic["rollbackEpoch"]
        with self._lock:
            stored = self._preauthorizations.get(key)
            if stored != preauthorization:
                raise AssertionError(
                    "fixture release signer authorization was not approved"
                )
            if (
                key in self._consumed
                or sequence
                <= self._authorization_sequence_high_water.get(
                    self._key_id, 0
                )
            ):
                raise AssertionError(
                    "fixture release signer authorization was already consumed"
                )
            if (
                preauthorization["useLimit"] != 1
                or not issued_at <= now < expires_at
                or expires_at - issued_at
                > production_attestation_producer_issuer
                .MAX_RELEASE_SIGN_AUTHORIZATION_SECONDS
            ):
                raise AssertionError(
                    "fixture release signer authorization is not active"
                )
            if (
                policy_sequence
                < preauthorization["minimumPolicySequence"]
                or release_generation
                < preauthorization["minimumReleaseGeneration"]
                or rollback_epoch
                < preauthorization["minimumRollbackEpoch"]
            ):
                raise AssertionError(
                    "fixture release signer monotonic floor was violated"
                )
            previous_release = self._release_high_water.get(
                self._key_id
            )
            if previous_release is not None:
                (
                    previous_rollback_epoch,
                    previous_release_generation,
                    previous_policy_sequence,
                ) = previous_release
                if (
                    rollback_epoch < previous_rollback_epoch
                    or policy_sequence < previous_policy_sequence
                    or (
                        rollback_epoch == previous_rollback_epoch
                        and release_generation
                        < previous_release_generation
                    )
                ):
                    raise AssertionError(
                        "fixture release signer release high-water "
                        "state regressed"
                    )
                if (
                    rollback_epoch > previous_rollback_epoch
                    and preauthorization["minimumRollbackEpoch"]
                    != rollback_epoch
                ):
                    raise AssertionError(
                        "fixture release signer rollback-epoch transition "
                        "was not explicitly authorized"
                    )
            self._consumed.add(key)
            self._authorization_sequence_high_water[
                self._key_id
            ] = sequence
            # Within an epoch, generation and policy cannot regress. Advancing
            # the rollback epoch may reset generation only when that exact new
            # epoch is the signer-owned authorization floor; policy never
            # regresses. This state is process-local fixture coverage only.
            self._release_high_water[self._key_id] = (
                rollback_epoch,
                release_generation,
                policy_sequence,
            )
            signing_core = {
                "payload": statement_payload,
                "payloadSha256": statement_payload_sha256,
            }
            message = (
                production_attestation_producer_issuer
                .STABLE_STATEMENT_DOMAIN
                + production_attestation_producer_issuer.canonical_json(
                    signing_core
                )
            )
            signature = self._private_key.sign(message)
        return {
            "algorithm": "Ed25519",
            "apiVersion":
            production_attestation_producer_issuer.SIGN_RESPONSE_VERSION,
            "approvedIssuerRequestSha256":
            preauthorization["approvedIssuerRequestSha256"],
            "authorizationIdBase64url": authorization_id,
            "authorizationSequence": sequence,
            "keyId": self._key_id,
            "messageSha256": digest_bytes(message),
            "preauthorizationSha256": preauthorization_sha256,
            "releaseIdentitySha256": release_identity_sha256,
            "signatureBase64url": attestation.b64e(signature),
            "statementPayloadSha256": statement_payload_sha256,
        }

    def serve_once(
        self,
        *,
        request_fd: int,
        response_fd: int,
        discard_response: bool = False,
    ) -> None:
        production_attestation_producer_issuer.validate_retained_pipe_fd(
            request_fd,
            label="fixture release signer request",
            writable=False,
        )
        production_attestation_producer_issuer.validate_retained_pipe_fd(
            response_fd,
            label="fixture release signer response",
            writable=True,
        )
        request_raw = bytearray()
        request_value: object | None = None
        try:
            while not request_raw.endswith(b"\n"):
                chunk = os.read(request_fd, 4096)
                if not chunk:
                    raise AssertionError(
                        "fixture release signer request closed"
                    )
                request_raw.extend(chunk)
                if len(request_raw) > 2 * 1024 * 1024:
                    raise AssertionError(
                        "fixture release signer request is oversized"
                    )
            # Decoding and JSON parsing necessarily create immutable Python
            # objects. The transport buffer is still wiped on every path.
            request_value = json.loads(request_raw.decode("ascii"))
            response = self.sign_request(request_value)
        finally:
            request_value = None
            production_attestation_producer_issuer.zeroize(request_raw)
        if discard_response:
            return
        response_raw = canonical_line(response)
        offset = 0
        while offset < len(response_raw):
            offset += os.write(response_fd, response_raw[offset:])


class FixtureStableReleaseSignerProvisioningBoundary:
    """Separate fixture-only provisioning API, not an authenticated service."""

    is_non_production_fixture = True

    def __init__(
        self,
        *,
        signer: FixtureStableReleaseSignerBoundary,
        capability: object,
        non_production: bool,
    ) -> None:
        if non_production is not True:
            raise ValueError(
                "fixture signer provisioning requires non-production "
                "acknowledgement"
            )
        self._signer = signer
        self.__capability = capability

    def provision_approved_authorization(
        self,
        *,
        key_id: str,
        preauthorization: dict[str, object],
    ) -> None:
        self._signer._install_preauthorization(
            capability=self.__capability,
            key_id=key_id,
            preauthorization=preauthorization,
        )


def fixture_stable_release_signer_boundaries(
    private_key: Ed25519PrivateKey,
    *,
    now_unix: int | None = None,
) -> tuple[
    FixtureStableReleaseSignerBoundary,
    FixtureStableReleaseSignerProvisioningBoundary,
]:
    """Create separate signing and provisioning APIs for this fixture only."""
    capability = object()
    signer = FixtureStableReleaseSignerBoundary(
        private_key,
        now_unix=now_unix,
        non_production=True,
        provisioning_capability=capability,
    )
    provisioner = FixtureStableReleaseSignerProvisioningBoundary(
        signer=signer,
        capability=capability,
        non_production=True,
    )
    return signer, provisioner


def fixture_stable_signer_request(
    *,
    private_key: Ed25519PrivateKey,
    now: int,
    authorization_label: str,
    authorization_sequence: int,
    boundary: FixtureStableReleaseSignerBoundary | None = None,
    provisioning_boundary: (
        FixtureStableReleaseSignerProvisioningBoundary | None
    ) = None,
    authorization_issued_at_unix: int | None = None,
    authorization_expires_at_unix: int | None = None,
    minimum_policy_sequence: int = 5,
    minimum_release_generation: int = 7,
    minimum_rollback_epoch: int = 3,
    policy_sequence: int = 5,
    release_generation: int = 7,
    rollback_epoch: int = 3,
    use_limit: int = 1,
) -> tuple[
    FixtureStableReleaseSignerBoundary,
    FixtureStableReleaseSignerProvisioningBoundary,
    dict[str, object],
    bytes,
]:
    if boundary is None:
        signer, provisioner = fixture_stable_release_signer_boundaries(
            private_key,
            now_unix=now,
        )
    else:
        signer = boundary
        if provisioning_boundary is None:
            raise AssertionError(
                "existing fixture signer requires its separate "
                "provisioning boundary"
            )
        provisioner = provisioning_boundary
    authorization_nonce = hashlib.sha256(
        ("nonce-" + authorization_label).encode("ascii")
    ).digest()
    authorization_id = hashlib.sha256(
        ("authorization-" + authorization_label).encode("ascii")
    ).digest()
    pins = {
        field: digest(
            "stable-signer-" + authorization_label + "-" + field
        )
        for field in sorted(
            FixtureStableReleaseSignerBoundary
            ._STATEMENT_PIN_FIELDS
        )
    }
    component_pins = (
        production_attestation_producer_issuer
        .component_pins_from_statement(pins)
    )
    release_identity = stable_release_identity(
        attestation_component_pins=component_pins,
        policy_sequence=policy_sequence,
        release_generation=release_generation,
        release_key_id=signer.key_id,
        rollback_epoch=rollback_epoch,
        trust_roots_sha256=pins["trustRootsSha256"],
    )
    release_identity_sha256 = (
        production_attestation_producer_issuer.sha256_json(
            release_identity
        )
    )
    statement_payload = {
        "attestationPins": pins,
        "releaseIdentity": release_identity,
        "releaseIdentitySha256": release_identity_sha256,
        "trustRootBundleSha256": pins["trustRootsSha256"],
    }
    statement_payload_sha256 = (
        production_attestation_producer_issuer.sha256_json(
            statement_payload
        )
    )
    preauthorization = {
        "approvedIssuerRequestSha256":
        digest("issuer-request-" + authorization_label),
        "authorizationExpiresAtUnix": (
            now + 60
            if authorization_expires_at_unix is None
            else authorization_expires_at_unix
        ),
        "authorizationIdBase64url": attestation.b64e(
            authorization_id
        ),
        "authorizationIssuedAtUnix": (
            now - 1
            if authorization_issued_at_unix is None
            else authorization_issued_at_unix
        ),
        "authorizationNonceSha256":
        digest_bytes(authorization_nonce),
        "authorizationSequence": authorization_sequence,
        "minimumPolicySequence": minimum_policy_sequence,
        "minimumReleaseGeneration": minimum_release_generation,
        "minimumRollbackEpoch": minimum_rollback_epoch,
        "releaseIdentitySha256": release_identity_sha256,
        "statementPayloadSha256": statement_payload_sha256,
        "useLimit": use_limit,
    }
    request = {
        "algorithm": "Ed25519",
        "apiVersion":
        production_attestation_producer_issuer.SIGN_REQUEST_VERSION,
        "authorizationNonceBase64url":
        attestation.b64e(authorization_nonce),
        "keyId": signer.key_id,
        "preauthorization": preauthorization,
        "preauthorizationSha256":
        production_attestation_producer_issuer.sha256_json(
            preauthorization
        ),
        "purpose": "stable-release-statement",
        "statementPayload": statement_payload,
        "statementPayloadSha256": statement_payload_sha256,
    }
    provisioner.provision_approved_authorization(
        key_id=signer.key_id,
        preauthorization=preauthorization,
    )
    return signer, provisioner, request, authorization_nonce


def issue_stable_statement_via_real_issuer(
    *,
    artifacts: dict[str, bytes],
    authorization_nonce: bytes,
    issuer_request: dict[str, object],
    release_private_key: Ed25519PrivateKey,
    trust_roots_sha256: str,
) -> bytes:
    signer_request_read, signer_request_write = os.pipe()
    signer_response_read, signer_response_write = os.pipe()
    issuer_request = json.loads(json.dumps(issuer_request))
    issuer_request["signerBoundary"]["requestFd"] = (
        signer_request_write
    )
    issuer_request["signerBoundary"]["responseFd"] = (
        signer_response_read
    )
    issuer_request_raw = canonical_line(issuer_request)
    signer, provisioner = fixture_stable_release_signer_boundaries(
        release_private_key,
    )
    signer_preauthorization = {
        "approvedIssuerRequestSha256":
        digest_bytes(issuer_request_raw),
        **issuer_request["signerBoundary"]["preauthorization"],
    }
    provisioner.provision_approved_authorization(
        key_id=issuer_request["signerBoundary"]["keyId"],
        preauthorization=signer_preauthorization,
    )
    issuer_request_fd = sealed_read_only_memfd(
        issuer_request_raw,
        "stable-issuer-request",
    )
    authorization_nonce_fd = sealed_read_only_memfd(
        authorization_nonce,
        "stable-release-signing-authorization-nonce",
    )
    response = tempfile.TemporaryFile()
    static_fds = {
        name: sealed_read_only_memfd(raw, name)
        for name, raw in artifacts.items()
    }
    signer_errors: list[BaseException] = []

    def retained_fd_signer() -> None:
        try:
            signer.serve_once(
                request_fd=signer_request_read,
                response_fd=signer_response_write,
            )
        except BaseException as exc:
            signer_errors.append(exc)
        finally:
            os.close(signer_request_read)
            os.close(signer_response_write)

    signer_thread = threading.Thread(
        target=retained_fd_signer,
        name="fixture-release-retained-fd-signer",
    )
    signer_thread.start()
    try:
        args = argparse.Namespace(
            expected_issuer_request_sha256=
            digest_bytes(issuer_request_raw),
            expected_trust_roots_sha256=trust_roots_sha256,
            fixture_non_production=True,
            immutable_config_fd=static_fds["immutableConfigSha256"],
            io_timeout_ms=1_000,
            producer_descriptor_fd=static_fds["descriptorSha256"],
            producer_executable_fd=static_fds["executableSha256"],
            producer_request_schema_fd=static_fds[
                "producerRequestSchemaSha256"
            ],
            request_fd=issuer_request_fd,
            response_fd=response.fileno(),
            sandbox_descriptor_fd=static_fds[
                "sandboxDescriptorSha256"
            ],
            sandbox_launcher_fd=static_fds[
                "sandboxLauncherSha256"
            ],
            signer_authorization_nonce_fd=authorization_nonce_fd,
            signer_request_fd=signer_request_write,
            signer_response_fd=signer_response_read,
            trust_roots_fd=static_fds["trustRootsSha256"],
        )
        # Namespace ownership is transferred into issue_stable_release. The
        # reader closes it, so this local must never retain the stale integer.
        authorization_nonce_fd = -1
        production_attestation_producer_issuer.issue_stable_release(
            args
        )
        response.seek(0)
        statement_raw = response.read()
    finally:
        if authorization_nonce_fd >= 0:
            os.close(authorization_nonce_fd)
        os.close(issuer_request_fd)
        os.close(signer_request_write)
        os.close(signer_response_read)
        for descriptor in static_fds.values():
            os.close(descriptor)
        response.close()
        signer_thread.join(timeout=2)
    if signer_thread.is_alive():
        raise AssertionError("fixture release signer did not stop")
    if signer_errors:
        raise signer_errors[0]
    return statement_raw


class StableReleaseSignerBoundaryTests(unittest.TestCase):
    @staticmethod
    def _clone(value: object) -> object:
        return json.loads(json.dumps(value))

    @staticmethod
    def _refresh_request_digests(
        request: dict[str, object],
    ) -> None:
        statement_payload_sha256 = (
            production_attestation_producer_issuer.sha256_json(
                request["statementPayload"]
            )
        )
        request["statementPayloadSha256"] = statement_payload_sha256
        request["preauthorization"][
            "statementPayloadSha256"
        ] = statement_payload_sha256
        request["preauthorizationSha256"] = (
            production_attestation_producer_issuer.sha256_json(
                request["preauthorization"]
            )
        )

    def test_retained_fd_roles_reject_type_and_direction_substitution(
        self,
    ) -> None:
        request_read, request_write = os.pipe()
        response_read, response_write = os.pipe()
        try:
            production_attestation_producer_issuer.validate_retained_pipe_fd(
                request_write,
                label="fixture request",
                writable=True,
            )
            production_attestation_producer_issuer.validate_retained_pipe_fd(
                response_read,
                label="fixture response",
                writable=False,
            )
            with self.assertRaises(
                production_attestation_producer_issuer.ContractError
            ):
                production_attestation_producer_issuer.validate_retained_pipe_fd(
                    request_read,
                    label="substituted request",
                    writable=True,
                )
            substituted_response_fd = os.open(
                "/dev/null",
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                with self.assertRaises(
                    production_attestation_producer_issuer.ContractError
                ):
                    production_attestation_producer_issuer.validate_retained_pipe_fd(
                        substituted_response_fd,
                        label="substituted response",
                        writable=False,
                    )
            finally:
                os.close(substituted_response_fd)
            with tempfile.TemporaryFile() as regular_file:
                regular_file.write(b"x" * 32)
                regular_file.flush()
                substituted_nonce_fd = os.dup(regular_file.fileno())
                with self.assertRaises(
                    production_attestation_producer_issuer.ContractError
                ):
                    production_attestation_producer_issuer.read_exact_sealed_secret_fd(
                        substituted_nonce_fd,
                        label="substituted authorization nonce",
                    )
        finally:
            for descriptor in (
                request_read,
                request_write,
                response_read,
                response_write,
            ):
                os.close(descriptor)

    def test_signer_reconstructs_only_exact_preauthorized_statement(
        self,
    ) -> None:
        now = 1_800_000_000
        private_key = Ed25519PrivateKey.generate()
        mutations = (
            (
                "arbitrary-message",
                lambda request: request.update(
                    {
                        "messageBase64url":
                        attestation.b64e(b"arbitrary"),
                        "messageSha256": digest("arbitrary-message"),
                    }
                ),
            ),
            (
                "issuer-request",
                lambda request: request["preauthorization"].update(
                    {
                        "approvedIssuerRequestSha256":
                        digest("crossed-issuer-request")
                    }
                ),
            ),
            (
                "authorization-id",
                lambda request: request["preauthorization"].update(
                    {
                        "authorizationIdBase64url":
                        attestation.b64e(b"x" * 32)
                    }
                ),
            ),
            (
                "nonce",
                lambda request: request.update(
                    {
                        "authorizationNonceBase64url":
                        attestation.b64e(b"x" * 32)
                    }
                ),
            ),
            (
                "payload",
                lambda request: request["statementPayload"][
                    "attestationPins"
                ].update(
                    {"trustRootsSha256": digest("crossed-trust-root")}
                ),
            ),
        )
        for index, (label, mutate) in enumerate(mutations, start=1):
            signer, _, request_value, _ = fixture_stable_signer_request(
                private_key=private_key,
                now=now,
                authorization_label=f"{label}-{index}",
                authorization_sequence=index,
            )
            request = self._clone(request_value)
            mutate(request)
            if label in {
                "issuer-request",
                "authorization-id",
            }:
                request["preauthorizationSha256"] = (
                    production_attestation_producer_issuer.sha256_json(
                        request["preauthorization"]
                    )
                )
            if label == "payload":
                self._refresh_request_digests(request)
            with self.subTest(label=label), self.assertRaises(
                AssertionError
            ):
                signer.sign_request(request)

        signer, _, request_value, _ = fixture_stable_signer_request(
            private_key=private_key,
            now=now,
            authorization_label="release-identity",
            authorization_sequence=20,
        )
        crossed_identity_request = self._clone(request_value)
        crossed_identity = crossed_identity_request[
            "statementPayload"
        ]["releaseIdentity"]
        crossed_identity["policy"]["hash"] = digest(
            "crossed-release-policy"
        )
        crossed_identity_sha256 = (
            production_attestation_producer_issuer.sha256_json(
                crossed_identity
            )
        )
        crossed_identity_request["statementPayload"][
            "releaseIdentitySha256"
        ] = crossed_identity_sha256
        crossed_identity_request["preauthorization"][
            "releaseIdentitySha256"
        ] = crossed_identity_sha256
        self._refresh_request_digests(crossed_identity_request)
        with self.assertRaises(AssertionError):
            signer.sign_request(crossed_identity_request)

        signer, _, request_value, _ = fixture_stable_signer_request(
            private_key=private_key,
            now=now,
            authorization_label="release-identity-schema",
            authorization_sequence=21,
        )
        schema_invalid_request = self._clone(request_value)
        schema_invalid_request["statementPayload"]["releaseIdentity"][
            "unapprovedDynamicField"
        ] = "forbidden"
        schema_invalid_identity_sha256 = (
            production_attestation_producer_issuer.sha256_json(
                schema_invalid_request["statementPayload"][
                    "releaseIdentity"
                ]
            )
        )
        schema_invalid_request["statementPayload"][
            "releaseIdentitySha256"
        ] = schema_invalid_identity_sha256
        schema_invalid_request["preauthorization"][
            "releaseIdentitySha256"
        ] = schema_invalid_identity_sha256
        self._refresh_request_digests(schema_invalid_request)
        with self.assertRaises(AssertionError):
            signer.sign_request(schema_invalid_request)

    def test_signing_request_cannot_mutate_signer_owned_authorization(
        self,
    ) -> None:
        now = 1_800_000_000
        private_key = Ed25519PrivateKey.generate()
        signer, _, approved_request, _ = (
            fixture_stable_signer_request(
                private_key=private_key,
                now=now,
                authorization_label="provisioning-separation",
                authorization_sequence=1,
            )
        )
        self.assertFalse(hasattr(signer, "provision"))
        self.assertFalse(
            hasattr(signer, "provision_approved_authorization")
        )
        untrusted_request = self._clone(approved_request)
        untrusted_request["preauthorization"][
            "minimumReleaseGeneration"
        ] = 1
        untrusted_request["preauthorizationSha256"] = (
            production_attestation_producer_issuer.sha256_json(
                untrusted_request["preauthorization"]
            )
        )
        with self.assertRaises(AssertionError):
            signer.sign_request(untrusted_request)
        signer.sign_request(approved_request)

    def test_signer_rejects_expiry_floor_and_non_one_use_records(
        self,
    ) -> None:
        now = 1_800_000_000
        private_key = Ed25519PrivateKey.generate()
        invalid_authorizations = (
            {
                "authorization_expires_at_unix": now,
                "authorization_label": "expired",
            },
            {
                "authorization_expires_at_unix": now + 61,
                "authorization_issued_at_unix": now + 1,
                "authorization_label": "not-yet-valid",
            },
            {
                "authorization_label": "policy-floor",
                "minimum_policy_sequence": 6,
            },
            {
                "authorization_label": "release-floor",
                "minimum_release_generation": 8,
            },
            {
                "authorization_label": "rollback-floor",
                "minimum_rollback_epoch": 4,
            },
            {
                "authorization_label": "not-one-use",
                "use_limit": 2,
            },
        )
        for index, options in enumerate(
            invalid_authorizations,
            start=1,
        ):
            signer, _, request, _ = fixture_stable_signer_request(
                private_key=private_key,
                now=now,
                authorization_sequence=index,
                **options,
            )
            with self.subTest(
                label=options["authorization_label"]
            ), self.assertRaises(AssertionError):
                signer.sign_request(request)

    def test_signer_enforces_release_tuple_high_water_transitions(
        self,
    ) -> None:
        now = 1_800_000_000
        private_key = Ed25519PrivateKey.generate()
        (
            signer,
            provisioner,
            initial_request,
            _,
        ) = fixture_stable_signer_request(
            private_key=private_key,
            now=now,
            authorization_label="release-high-water-initial",
            authorization_sequence=10,
        )
        signer.sign_request(initial_request)

        regressions = (
            {
                "authorization_label": "regressed-policy",
                "authorization_sequence": 11,
                "minimum_policy_sequence": 4,
                "policy_sequence": 4,
            },
            {
                "authorization_label": "regressed-generation",
                "authorization_sequence": 12,
                "minimum_release_generation": 6,
                "release_generation": 6,
            },
            {
                "authorization_label": "regressed-rollback-epoch",
                "authorization_sequence": 13,
                "minimum_rollback_epoch": 2,
                "rollback_epoch": 2,
            },
        )
        for options in regressions:
            _, _, regressed_request, _ = (
                fixture_stable_signer_request(
                    private_key=private_key,
                    now=now,
                    boundary=signer,
                    provisioning_boundary=provisioner,
                    **options,
                )
            )
            with self.subTest(
                label=options["authorization_label"]
            ), self.assertRaises(AssertionError):
                signer.sign_request(regressed_request)

        _, _, forward_request, _ = fixture_stable_signer_request(
            private_key=private_key,
            now=now,
            authorization_label="forward-release",
            authorization_sequence=14,
            boundary=signer,
            minimum_policy_sequence=6,
            minimum_release_generation=8,
            policy_sequence=6,
            provisioning_boundary=provisioner,
            release_generation=8,
        )
        signer.sign_request(forward_request)

        _, _, implicit_epoch_request, _ = (
            fixture_stable_signer_request(
                private_key=private_key,
                now=now,
                authorization_label="implicit-epoch-advance",
                authorization_sequence=15,
                boundary=signer,
                minimum_policy_sequence=6,
                minimum_release_generation=1,
                policy_sequence=6,
                provisioning_boundary=provisioner,
                release_generation=1,
                rollback_epoch=4,
            )
        )
        with self.assertRaises(AssertionError):
            signer.sign_request(implicit_epoch_request)

        _, _, explicit_epoch_request, _ = (
            fixture_stable_signer_request(
                private_key=private_key,
                now=now,
                authorization_label="explicit-epoch-advance",
                authorization_sequence=16,
                boundary=signer,
                minimum_policy_sequence=6,
                minimum_release_generation=1,
                minimum_rollback_epoch=4,
                policy_sequence=6,
                provisioning_boundary=provisioner,
                release_generation=1,
                rollback_epoch=4,
            )
        )
        signer.sign_request(explicit_epoch_request)

    def test_signer_rejects_stale_sequence_replay_and_double_use(
        self,
    ) -> None:
        now = 1_800_000_000
        private_key = Ed25519PrivateKey.generate()
        (
            signer,
            provisioner,
            first_request,
            _,
        ) = fixture_stable_signer_request(
            private_key=private_key,
            now=now,
            authorization_label="first",
            authorization_sequence=10,
        )
        signer.sign_request(first_request)
        with self.assertRaises(AssertionError):
            signer.sign_request(first_request)

        _, _, stale_request, _ = fixture_stable_signer_request(
            private_key=private_key,
            now=now,
            authorization_label="stale",
            authorization_sequence=10,
            boundary=signer,
            provisioning_boundary=provisioner,
        )
        with self.assertRaises(AssertionError):
            signer.sign_request(stale_request)

        (
            concurrent_signer,
            concurrent_provisioner,
            concurrent_request_a,
            _,
        ) = (
            fixture_stable_signer_request(
                private_key=private_key,
                now=now,
                authorization_label="concurrent-a",
                authorization_sequence=30,
            )
        )
        _, _, concurrent_request_b, _ = (
            fixture_stable_signer_request(
                private_key=private_key,
                now=now,
                authorization_label="concurrent-b",
                authorization_sequence=30,
                boundary=concurrent_signer,
                provisioning_boundary=concurrent_provisioner,
            )
        )
        successes: list[dict[str, object]] = []
        failures: list[BaseException] = []

        def sign_concurrently(request: dict[str, object]) -> None:
            try:
                successes.append(
                    concurrent_signer.sign_request(
                        request
                    )
                )
            except BaseException as exc:
                failures.append(exc)

        threads = [
            threading.Thread(
                target=sign_concurrently,
                args=(request,),
            )
            for request in (
                concurrent_request_a,
                concurrent_request_b,
            )
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=2)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], AssertionError)

    def test_lost_response_leaves_authorization_consumed(
        self,
    ) -> None:
        now = 1_800_000_000
        private_key = Ed25519PrivateKey.generate()
        signer, _, request, _ = fixture_stable_signer_request(
            private_key=private_key,
            now=now,
            authorization_label="lost-response",
            authorization_sequence=1,
        )
        request_read, request_write = os.pipe()
        response_read, response_write = os.pipe()
        try:
            request_raw = canonical_line(request)
            offset = 0
            while offset < len(request_raw):
                offset += os.write(
                    request_write,
                    request_raw[offset:],
                )
            os.close(request_write)
            request_write = -1
            signer.serve_once(
                request_fd=request_read,
                response_fd=response_write,
                discard_response=True,
            )
            os.close(response_write)
            response_write = -1
            self.assertEqual(os.read(response_read, 1), b"")
            with self.assertRaises(AssertionError):
                signer.sign_request(request)
        finally:
            for descriptor in (
                request_read,
                request_write,
                response_read,
                response_write,
            ):
                if descriptor >= 0:
                    os.close(descriptor)


class FixtureExternalWitnessFdBoundary:
    """Non-production retained-FD harness for the external CAS interface."""

    def __init__(
        self,
        *,
        release_identity_sha256: str,
        store_identity: dict[str, object],
        store_private_key: Ed25519PrivateKey,
        witness_private_key: Ed25519PrivateKey,
        now: int,
        non_production: bool,
    ) -> None:
        if non_production is not True:
            raise ValueError(
                "fixture witness boundary requires non-production acknowledgement"
            )
        self.release_identity_sha256 = release_identity_sha256
        self.store_identity = store_identity
        self.store_identity_sha256 = (
            attestation_witness_service.sha256_json(store_identity)
        )
        self.store_signer = (
            attestation_witness_service.FixtureEd25519Signer(
                store_private_key,
                non_production=True,
            )
        )
        self.witness_signer = (
            attestation_witness_service.FixtureEd25519Signer(
                witness_private_key,
                non_production=True,
            )
        )
        self.now = now
        prior = self._checkpoint(
            sequence=1,
            tree_size=1,
            previous=None,
        )
        self.minimum_rollback_continuity_commitment_sha256 = (
            production_attestation_producer_issuer
            .live_witness_continuity_sha256(
                current=prior,
                previous_commitment_sha256=None,
                witness_store_identity_sha256=(
                    self.store_identity_sha256
                ),
                witness_store_key_spki_sha256=(
                    self.store_signer.key_id
                ),
            )
        )
        self.prior_protected_state: dict[str, object] | None = None
        self.last_response: dict[str, object] | None = None

    def _checkpoint(
        self,
        *,
        sequence: int,
        tree_size: int,
        previous: dict[str, object] | None,
    ) -> dict[str, object]:
        current = {
            "checkpointSha256": digest(
                f"fixture-witness-checkpoint-{sequence}"
            ),
            "generation": 7,
            "headSha256": digest("placeholder"),
            "releaseIdentitySha256": self.release_identity_sha256,
            "rollbackEpoch": 3,
            "sequence": sequence,
            "treeSize": tree_size,
        }
        current["headSha256"] = (
            production_attestation_producer_issuer
            .live_witness_head_chain_sha256(current, previous)
        )
        return current

    @staticmethod
    def _invocation_binding(
        request: dict[str, object],
    ) -> dict[str, object]:
        return {
            "apiVersion":
            attestation_witness_service.INVOCATION_BINDING_VERSION,
            "currentRequestSha256":
            attestation_witness_service.sha256_json(request),
            "producerEphemeralKeySpkiSha256":
            request["producerEphemeralKeySpkiSha256"],
            "producerInvocationSha256":
            request["producerInvocationSha256"],
            "producerRequestSha256":
            request["producerRequestSha256"],
            "tlsBindingSha256": request["tlsBindingSha256"],
            "verifierChallengeBase64url":
            request["verifierChallengeBase64url"],
        }

    def _signed_state(
        self,
        *,
        current: dict[str, object],
        previous: dict[str, object] | None,
        previous_commitment: str | None,
        invocation: dict[str, object],
        issued_at: int,
    ) -> tuple[
        dict[str, object],
        dict[str, object],
        dict[str, object],
        str,
    ]:
        live_payload = {
            "expiresAtUnix": issued_at + 30,
            "generation": current["generation"],
            "headSha256": current["headSha256"],
            "invocationBinding": invocation,
            "issuedAtUnix": issued_at,
            "releaseIdentitySha256": self.release_identity_sha256,
            "rollbackEpoch": current["rollbackEpoch"],
            "sequence": current["sequence"],
            "treeSize": current["treeSize"],
        }
        live_head = attestation_witness_service.signed_envelope(
            api_version=
            attestation_witness_service.LIVE_WITNESS_HEAD_VERSION,
            domain=attestation_witness_service.LIVE_WITNESS_DOMAIN,
            payload=live_payload,
            signer=self.witness_signer,
        )
        current_with_payload = {
            **current,
            "liveWitnessHeadPayloadSha256":
            live_head["payloadSha256"],
        }
        continuity = (
            production_attestation_producer_issuer
            .live_witness_continuity_sha256(
                current=current_with_payload,
                previous_commitment_sha256=previous_commitment,
                witness_store_identity_sha256=(
                    self.store_identity_sha256
                ),
                witness_store_key_spki_sha256=(
                    self.store_signer.key_id
                ),
            )
        )
        receipt = {
            "apiVersion":
            attestation_witness_service.CAS_RECEIPT_VERSION,
            "checkpointSha256": current["checkpointSha256"],
            "committedAtUnix": issued_at,
            "committedRollbackContinuityCommitmentSha256":
            continuity,
            "generation": current["generation"],
            "previousRollbackContinuityCommitmentSha256":
            previous_commitment,
            "releaseIdentitySha256": self.release_identity_sha256,
            "sequence": current["sequence"],
            "transactionIdBase64url": attestation.b64e(
                bytes([int(current["sequence"])]) * 32
            ),
            "witnessStoreIdentitySha256":
            self.store_identity_sha256,
        }
        protected_payload = {
            "checkpointCasReceipt": receipt,
            "current": current_with_payload,
            "expiresAtUnix": issued_at + 30,
            "invocationBinding": invocation,
            "issuedAtUnix": issued_at,
            "previous": previous,
            "releaseIdentitySha256": self.release_identity_sha256,
            "rollbackContinuityCommitmentSha256": continuity,
            "storeAssurance":
            "externallyWitnessedRollbackProtected",
            "witnessSigningKeyId": self.witness_signer.key_id,
            "witnessStoreIdentity": self.store_identity,
            "witnessStoreIdentitySha256":
            self.store_identity_sha256,
            "witnessStoreKeySpkiSha256":
            self.store_signer.key_id,
        }
        protected = attestation_witness_service.signed_envelope(
            api_version=
            attestation_witness_service.PROTECTED_STATE_VERSION,
            domain=attestation_witness_service.PROTECTED_STATE_DOMAIN,
            payload=protected_payload,
            signer=self.store_signer,
        )
        return live_head, protected, receipt, continuity

    def response_for(
        self,
        request: dict[str, object],
    ) -> dict[str, object]:
        if (
            request["minimumReleaseIdentitySha256"]
            != self.release_identity_sha256
            or request[
                "minimumRollbackContinuityCommitmentSha256"
            ]
            != self.minimum_rollback_continuity_commitment_sha256
        ):
            raise AssertionError(
                "fixture witness request crossed its retained continuity floor"
            )
        current_invocation = self._invocation_binding(request)
        prior_request = {
            **request,
            "producerInvocationSha256":
            digest("fixture-prior-producer-invocation"),
            "producerRequestSha256":
            digest("fixture-prior-producer-request"),
            "verifierChallengeBase64url":
            attestation.b64e(b"p" * 32),
        }
        prior_invocation = self._invocation_binding(prior_request)
        prior = self._checkpoint(
            sequence=1,
            tree_size=1,
            previous=None,
        )
        _, prior_protected, _, prior_continuity = self._signed_state(
            current=prior,
            previous=None,
            previous_commitment=None,
            invocation=prior_invocation,
            issued_at=self.now - 1,
        )
        if (
            prior_continuity
            != self.minimum_rollback_continuity_commitment_sha256
        ):
            raise AssertionError(
                "fixture witness prior continuity changed"
            )
        current = self._checkpoint(
            sequence=2,
            tree_size=2,
            previous=prior,
        )
        live_head, protected, receipt, continuity = self._signed_state(
            current=current,
            previous=prior,
            previous_commitment=prior_continuity,
            invocation=current_invocation,
            issued_at=self.now,
        )
        response = {
            "apiVersion":
            attestation_witness_service.CURRENT_RESPONSE_VERSION,
            "checkpointCasReceipt": receipt,
            "currentRequestSha256":
            attestation_witness_service.sha256_json(request),
            "invocationBinding": current_invocation,
            "liveWitnessHead": live_head,
            "protectedLiveWitnessState": protected,
            "rollbackContinuityCommitmentSha256": continuity,
            "witnessStoreIdentitySha256":
            self.store_identity_sha256,
            "witnessStoreKeySpkiSha256":
            self.store_signer.key_id,
        }
        self.prior_protected_state = prior_protected
        self.last_response = response
        return response


def produce_bundle_via_real_producer(
    *,
    artifacts: dict[str, bytes],
    producer_request_raw: bytes,
    producer_ephemeral_seed: bytes,
    stable_statement_raw: bytes,
    trust_roots_sha256: str,
    witness_boundary: FixtureExternalWitnessFdBoundary,
) -> bytes:
    request_fd = sealed_read_only_memfd(
        producer_request_raw,
        "producer-request",
    )
    seed_fd = sealed_read_only_memfd(
        producer_ephemeral_seed,
        "producer-ephemeral-seed",
    )
    statement_fd = sealed_read_only_memfd(
        stable_statement_raw,
        "stable-statement",
    )
    static_fds = {
        name: sealed_read_only_memfd(raw, name)
        for name, raw in artifacts.items()
    }
    nonce_request_read, nonce_request_write = os.pipe()
    nonce_response_read, nonce_response_write = os.pipe()
    witness_request_read, witness_request_write = os.pipe()
    witness_response_read, witness_response_write = os.pipe()
    response = tempfile.TemporaryFile()
    witness_errors: list[BaseException] = []

    def retained_fd_witness_service() -> None:
        try:
            request_raw = b""
            while not request_raw.endswith(b"\n"):
                chunk = os.read(witness_request_read, 4096)
                if not chunk:
                    raise AssertionError(
                        "fixture witness request channel closed"
                    )
                request_raw += chunk
            request = json.loads(request_raw.decode("ascii"))
            response_raw = canonical_line(
                witness_boundary.response_for(request)
            )
            offset = 0
            while offset < len(response_raw):
                offset += os.write(
                    witness_response_write,
                    response_raw[offset:],
                )
        except BaseException as exc:
            witness_errors.append(exc)
        finally:
            os.close(witness_request_read)
            os.close(witness_response_write)

    witness_thread = threading.Thread(
        target=retained_fd_witness_service,
        name="fixture-witness-retained-fd-service",
    )
    witness_thread.start()
    try:
        args = argparse.Namespace(
            expected_stable_statement_sha256=
            digest_bytes(stable_statement_raw),
            expected_trust_roots_sha256=trust_roots_sha256,
            immutable_config_fd=static_fds["immutableConfigSha256"],
            io_timeout_ms=1_000,
            nonce_request_fd=nonce_request_write,
            nonce_response_fd=nonce_response_read,
            producer_descriptor_fd=static_fds["descriptorSha256"],
            producer_ephemeral_seed_fd=seed_fd,
            producer_executable_fd=static_fds["executableSha256"],
            producer_request_schema_fd=static_fds[
                "producerRequestSchemaSha256"
            ],
            request_fd=request_fd,
            response_fd=response.fileno(),
            sandbox_descriptor_fd=static_fds[
                "sandboxDescriptorSha256"
            ],
            sandbox_launcher_fd=static_fds[
                "sandboxLauncherSha256"
            ],
            stable_statement_fd=statement_fd,
            trust_roots_fd=static_fds["trustRootsSha256"],
            witness_request_fd=witness_request_write,
            witness_response_fd=witness_response_read,
        )
        production_attestation_producer_issuer.produce_public_bundle(
            args
        )
        response.seek(0)
        raw = response.read()
    finally:
        os.close(request_fd)
        os.close(seed_fd)
        os.close(statement_fd)
        for descriptor in (
            nonce_request_read,
            nonce_request_write,
            nonce_response_read,
            nonce_response_write,
        ):
            try:
                os.close(descriptor)
            except OSError:
                pass
        os.close(witness_request_write)
        os.close(witness_response_read)
        for descriptor in static_fds.values():
            os.close(descriptor)
        response.close()
        witness_thread.join(timeout=2)
    if witness_thread.is_alive():
        raise AssertionError("fixture witness service did not stop")
    if witness_errors:
        raise witness_errors[0]
    return raw


def public_evidence_descriptor(
    *,
    release_identity: dict[str, object] | None = None,
    trust_roots_sha256: str | None = None,
    tls_scope_private_key: Ed25519PrivateKey | None = None,
    tls_scope_public_key_spki_der_base64url: str | None = None,
    nonce_store_private_key: Ed25519PrivateKey | None = None,
    witness_store_private_key: Ed25519PrivateKey | None = None,
) -> attestation.PublicEvidenceProducerDescriptor:
    if tls_scope_public_key_spki_der_base64url is None:
        tls_scope_private_key = (
            Ed25519PrivateKey.generate()
            if tls_scope_private_key is None
            else tls_scope_private_key
        )
        tls_scope_der = tls_scope_private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    else:
        if tls_scope_private_key is not None:
            raise ValueError("fixture TLS scope key inputs are mutually exclusive")
        tls_scope_der = attestation.b64d(
            tls_scope_public_key_spki_der_base64url
        )
    selected_trust_roots = (
        digest("trust-roots")
        if trust_roots_sha256 is None else trust_roots_sha256
    )
    witness_store_private_key = (
        Ed25519PrivateKey.generate()
        if witness_store_private_key is None
        else witness_store_private_key
    )
    nonce_store_private_key = (
        Ed25519PrivateKey.generate()
        if nonce_store_private_key is None
        else nonce_store_private_key
    )
    nonce_authority_assurance_evidence_private_key = (
        Ed25519PrivateKey.generate()
    )
    nonce_authority_verifier_state_private_key = (
        Ed25519PrivateKey.generate()
    )
    nonce_store_der = (
        nonce_store_private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    witness_store_der = (
        witness_store_private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    selected_release_identity = (
        stable_release_identity(
            tls_scope_key_id=digest_bytes(tls_scope_der),
            trust_roots_sha256=selected_trust_roots,
            witness_store_key_id=digest_bytes(witness_store_der),
        )
        if release_identity is None
        else json.loads(json.dumps(release_identity))
    )
    nonce_authority_assurance = fixture_nonce_authority_assurance(
        authority_identity_sha256=selected_release_identity[
            "configuration"
        ]["publicAttestation"]["nonceStoreIdentitySha256"],
        administrative_domain_label=(
            "descriptor-fixture-nonce-authority-admin-domain"
        ),
    )
    nonce_authority_assurance_sha256 = (
        verify_nitro_tee.sha256_json(nonce_authority_assurance)
    )
    immutable_config = (
        attestation.canonical_json(
            {
                "apiVersion": attestation.PUBLIC_EVIDENCE_CONFIG_VERSION,
                "minimumRollbackContinuityCommitmentSha256":
                digest("minimum-rollback-continuity"),
                "nonceAuthorityAssurance":
                nonce_authority_assurance,
                "nonceAuthorityAssuranceEvidenceSigningPublicKeySpkiDerBase64url":
                attestation.b64e(
                    nonce_authority_assurance_evidence_private_key
                    .public_key()
                    .public_bytes(
                        serialization.Encoding.DER,
                        serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                ),
                "nonceAuthorityAssuranceSha256":
                nonce_authority_assurance_sha256,
                "nonceAuthorityVerifierStateSigningPublicKeySpkiDerBase64url":
                attestation.b64e(
                    nonce_authority_verifier_state_private_key
                    .public_key()
                    .public_bytes(
                        serialization.Encoding.DER,
                        serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                ),
                "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256":
                digest(
                    "descriptor-fixture-verifier-state-admin-domain"
                ),
                "nonceAuthorityVerifierStateStoreIdentitySha256":
                digest("descriptor-fixture-verifier-state-store"),
                "nonceStoreSigningPublicKeySpkiDerBase64url":
                attestation.b64e(nonce_store_der),
                "producerPolicy": selected_release_identity[
                    "configuration"
                ]["publicAttestation"],
                "releaseIdentity": selected_release_identity,
                "releaseIdentitySha256":
                verify_nitro_tee.sha256_json(selected_release_identity),
                "sandboxDescriptorSha256":
                selected_release_identity["configuration"][
                    "publicAttestation"
                ]["sandboxDescriptorSha256"],
                "tlsScopeSigningPublicKeySpkiDerBase64url":
                attestation.b64e(tls_scope_der),
                "witnessStoreSigningPublicKeySpkiDerBase64url":
                attestation.b64e(witness_store_der),
            }
        ).encode("ascii")
        + b"\n"
    )
    sandbox_document = fixture_sandbox_descriptor(
        producer_executable_sha256=digest("producer-executable"),
        producer_request_schema_sha256=
        digest("producer-request-schema"),
        sandbox_launcher_sha256=digest("sandbox-launcher"),
        trust_roots_sha256=selected_trust_roots,
        nonce_service_executable_sha256=
        digest("nonce-service-executable"),
        witness_service_executable_sha256=
        digest("witness-service-executable"),
    )
    sandbox_descriptor = canonical_line(sandbox_document)
    return attestation.PublicEvidenceProducerDescriptor(
        descriptor_sha256=digest("producer-descriptor"),
        executable_path=Path(
            "/run/serverware/public-evidence-producer"
        ),
        executable_sha256=digest("producer-executable"),
        immutable_config_bytes=immutable_config,
        immutable_config_sha256=digest_bytes(immutable_config),
        minimum_rollback_continuity_commitment_sha256=(
            digest("minimum-rollback-continuity")
        ),
        release_identity=selected_release_identity,
        release_identity_sha256=verify_nitro_tee.sha256_json(
            selected_release_identity
        ),
        tls_scope_signing_public_key_spki_der_base64url=(
            attestation.b64e(tls_scope_der)
        ),
        sandbox_launcher_path=Path(
            "/run/serverware/public-evidence-sandbox"
        ),
        sandbox_launcher_sha256=digest("sandbox-launcher"),
        sandbox_descriptor_bytes=sandbox_descriptor,
        sandbox_descriptor_sha256=digest_bytes(sandbox_descriptor),
        stable_statement_sha256=digest("stable-statement"),
        sandbox_cgroup_path=Path(
            "/sys/fs/cgroup/serverware-public-attestation"
        ),
        sandbox_root_path=Path(
            "/run/serverware/public-attestation-root"
        ),
        sandbox_seccomp_profile_path=Path(
            "/run/serverware/public-attestation.seccomp"
        ),
        sandbox_seccomp_profile_sha256=
        digest("fixture-seccomp-profile"),
        sandbox_mount_sources=(),
        sandbox_sealed_files=(),
        sandbox_measurement_copies=(
            ("producerExecutableMeasurement", "producerExecutable"),
            ("sandboxDescriptorMeasurement", "sandboxDescriptor"),
        ),
        sandbox_producer_streams=(),
        sandbox_fixture_mode=True,
        nonce_store_identity_sha256=
        digest("nonce-store-identity"),
        nonce_store_key_spki_sha256=digest_bytes(nonce_store_der),
        nonce_store_signing_public_key_spki_der_base64url=(
            attestation.b64e(nonce_store_der)
        ),
        nonce_service_request_fd=100,
        nonce_service_response_fd=101,
        nonce_service_expected_peer_uid=0,
        nonce_service_expected_peer_gid=0,
        nonce_service_expected_peer_executable_sha256=(
            digest("nonce-service-executable")
        ),
        nonce_service_expected_peer_cgroup_path=(
            "/serverware-attestation-services"
        ),
        nonce_service_max_response_bytes=1024 * 1024,
        nonce_service_timeout_milliseconds=1_000,
        producer_request_schema_sha256=
        digest("producer-request-schema"),
        witness_store_identity_sha256=
        digest("witness-store-identity"),
        witness_store_key_spki_sha256=
        digest_bytes(witness_store_der),
        witness_store_signing_public_key_spki_der_base64url=(
            attestation.b64e(witness_store_der)
        ),
        trust_roots_sha256=(
            selected_trust_roots
        ),
        max_input_bytes=64 * 1024,
        max_output_bytes=4 * 1024 * 1024,
        timeout_milliseconds=1_000,
        concurrency_limit=1,
    )


class NitroHelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        script = Path(__file__).with_name("nitro_nsm_attest.py")
        spec = importlib.util.spec_from_file_location("nitro_nsm_attest", script)
        if spec is None or spec.loader is None:
            raise AssertionError("Nitro adapter could not be loaded")
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_raw_nsm_nonce_user_data_pcr_and_debug_mismatch_fail(self) -> None:
        expected_nonce = b"n" * 32
        expected_user_data = b"u" * 64
        good_raw, expected_pcrs = nitro_document(
            nonce=expected_nonce, user_data=expected_user_data
        )
        claims = {"eif": {"pcrs": expected_pcrs}}
        args = SimpleNamespace(
            command_template="unused",
            output_format="raw",
            timeout=1.0,
            max_document_bytes=128 * 1024,
            allow_fixtures_for_test=False,
        )
        cases = [
            nitro_document(nonce=b"r" * 32, user_data=expected_user_data)[0],
            nitro_document(nonce=expected_nonce, user_data=b"v" * 64)[0],
            nitro_document(
                nonce=expected_nonce, user_data=expected_user_data, pcr_byte=9
            )[0],
            nitro_document(
                nonce=expected_nonce,
                user_data=expected_user_data,
                debug=True,
            )[0],
        ]
        for raw in cases:
            with (
                self.subTest(raw=digest_bytes(raw)),
                mock.patch.object(
                    self.module,
                    "validate_request",
                    return_value=(expected_user_data, claims, expected_nonce),
                ),
                mock.patch.object(
                    self.module, "run_nsm_helper", return_value=raw
                ),
                self.assertRaises(SystemExit),
            ):
                self.module.attest(args)
        parsed = self.module.parse_nitro_document(good_raw)
        self.assertFalse(parsed["debug"])

    def test_arbitrary_user_data_request_shape_is_rejected(self) -> None:
        with self.assertRaises(SystemExit):
            self.module.validate_request(
                {
                    "apiVersion": self.module.REQUEST_VERSION,
                    "claims": {"attacker": "chosen"},
                    "user_data": "attacker-chosen",
                }
            )


class ExactResponseTests(unittest.TestCase):
    def test_exact_http_envelope_and_statement_signature(self) -> None:
        scope = trusted_scope()
        item = challenge(scope)
        response_private, response_trust, _ = key_material()
        claims = {
            "keyGenerations": {"response": 1},
            "policy": {
                "hash": digest("policy"),
                "rollbackEpoch": 1,
                "sequence": 1,
            },
            "release": {
                "caSpkiSha256": digest("ca"),
                "generation": 1,
                "releaseKeySpkiSha256": digest("release"),
                "responseKeySpkiSha256": response_trust.key_id,
            },
        }
        with (
            mock.patch.object(attestation, "RELEASE_CHANNEL", "production"),
            mock.patch.object(
                attestation, "TEE_QUOTE_PROVIDER", "aws-nitro-nsm"
            ),
            mock.patch.object(
                attestation,
                "response_public_key_info",
                return_value={
                    "pem": "public",
                    "spki_sha256": response_trust.key_id,
                },
            ),
            mock.patch.object(
                attestation, "_production_claims", return_value=claims
            ),
            mock.patch.object(
                attestation,
                "sign_quote",
                return_value={"provider": "aws-nitro-nsm", "debug": False},
            ),
            mock.patch.object(
                attestation,
                "sign_response_statement",
                side_effect=lambda statement: "ed25519:"
                + attestation.b64e(
                    response_private.sign(
                        attestation.canonical_json(statement).encode("ascii")
                    )
                ),
            ),
            mock.patch.object(attestation.time, "time", return_value=1_010),
        ):
            result = attestation.production_attestation_response(
                challenge=item,
                tls_scope=scope,
                method="GET",
                path="/attestation",
                raw_query="challengeId=x&challenge=y",
                production_state={},
            )
        headers = dict(result.raw_headers)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(headers[b"content-type"], b"application/json")
        self.assertEqual(
            headers[b"content-length"], str(len(result.body)).encode("ascii")
        )
        self.assertEqual(
            result.statement["httpResponse"]["coreHeaders"],
            [
                {
                    "name": name.decode("ascii"),
                    "value": value.decode("ascii"),
                }
                for name, value in result.raw_headers[:9]
            ],
        )
        self.assertEqual(
            result.statement["httpResponse"]["detachedProofHeaders"],
            {
                "statement": (
                    "x-serverware-attestation-statement-b64:"
                    "base64url(canonical-statement)"
                ),
                "statementSha256": (
                    "x-serverware-attestation-statement-sha256:"
                    "sha256(canonical-statement)"
                ),
                "signature": (
                    "x-serverware-attestation-signature:"
                    "ed25519(canonical-statement)"
                ),
            },
        )
        response_private.public_key().verify(
            attestation.b64d(result.signature.split(":", 1)[1]),
            attestation.canonical_json(result.statement).encode("ascii"),
        )


class PublicEvidenceRouteTests(unittest.IsolatedAsyncioTestCase):
    def request(
        self,
        body: bytes,
        *,
        extensions: dict | None = None,
        headers: list[tuple[bytes, bytes]] | None = None,
        query_string: bytes = b"",
        receive: object | None = None,
    ) -> Request:
        delivered = False

        async def default_receive() -> dict[str, object]:
            nonlocal delivered
            if delivered:
                return {
                    "type": "http.request",
                    "body": b"",
                    "more_body": False,
                }
            delivered = True
            return {
                "type": "http.request",
                "body": body,
                "more_body": False,
            }

        return Request(
            {
                "type": "http",
                "asgi": {"spec_version": "2.3", "version": "3.0"},
                "http_version": "1.1",
                "method": "POST",
                "scheme": "https",
                "path": "/attestation/public-evidence",
                "raw_path": b"/attestation/public-evidence",
                "query_string": query_string,
                "headers": (
                    [(b"content-type", b"application/json")]
                    if headers is None
                    else headers
                ),
                "client": ("192.0.2.1", 443),
                "server": ("attested.example", 443),
                "extensions": {} if extensions is None else extensions,
            },
            default_receive if receive is None else receive,
        )

    async def test_missing_enclave_tls_extension_returns_503(self) -> None:
        receive = mock.AsyncMock(
            return_value={
                "type": "http.request",
                "body": b"untrusted-body",
                "more_body": False,
            }
        )
        request = self.request(
            b'{"apiVersion":"serverware.publicAttestationRequest/v1",'
            b'"callerNonceBase64url":"'
            + attestation.b64e(b"u" * 32).encode("ascii")
            + b'"}',
            headers=[
                (b"content-type", b"application/json"),
                (b"content-length", b"122"),
            ],
            receive=receive,
        )
        with (
            mock.patch.object(
                serverware_app,
                "_load_public_evidence_producer_descriptor",
            ) as descriptor_loader,
            self.assertRaises(HTTPException) as captured,
        ):
            await serverware_app.attestation_public_evidence(request)
        self.assertEqual(captured.exception.status_code, 503)
        receive.assert_not_awaited()
        descriptor_loader.assert_not_called()

    async def test_query_and_oversized_length_reject_before_body_read(
        self,
    ) -> None:
        cases = (
            {
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", b"2"),
                ],
                "query_string": b"nonce=forbidden",
                "status": 400,
            },
            {
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", b"4097"),
                ],
                "query_string": b"",
                "status": 413,
            },
        )
        for case in cases:
            receive = mock.AsyncMock(
                return_value={
                    "type": "http.request",
                    "body": b"{}",
                    "more_body": False,
                }
            )
            request = self.request(
                b"{}",
                extensions={
                    attestation.TRUSTED_TLS_SCOPE_EXTENSION: b"scope"
                },
                headers=case["headers"],
                query_string=case["query_string"],
                receive=receive,
            )
            with (
                self.subTest(case=case),
                mock.patch.object(
                    serverware_app,
                    "_load_public_evidence_producer_descriptor",
                ) as descriptor_loader,
                mock.patch.object(
                    serverware_app,
                    "trusted_public_tls_scope_from_asgi",
                ) as tls_from_scope,
                mock.patch.object(
                    serverware_app,
                    "production_public_evidence_response",
                ) as producer,
                self.assertRaises(HTTPException) as captured,
            ):
                await serverware_app.attestation_public_evidence(request)
            self.assertEqual(captured.exception.status_code, case["status"])
            receive.assert_not_awaited()
            descriptor_loader.assert_not_called()
            tls_from_scope.assert_not_called()
            producer.assert_not_called()

    async def test_public_middleware_preflights_without_global_body_read(
        self,
    ) -> None:
        receive = mock.AsyncMock()
        accepted = self.request(
            b"{}",
            extensions={
                attestation.TRUSTED_TLS_SCOPE_EXTENSION: b"scope"
            },
            headers=[
                (b"content-type", b"application/json"),
                (b"content-length", b"2"),
            ],
            receive=receive,
        )
        expected_response = Response(status_code=204)
        call_next = mock.AsyncMock(return_value=expected_response)
        response = (
            await serverware_app.bounded_control_plane_request_middleware(
                accepted,
                call_next,
            )
        )
        self.assertIs(response, expected_response)
        receive.assert_not_awaited()
        call_next.assert_awaited_once_with(accepted)

        oversized = self.request(
            b"",
            extensions={
                attestation.TRUSTED_TLS_SCOPE_EXTENSION: b"scope"
            },
            headers=[
                (b"content-type", b"application/json"),
                (b"content-length", b"4097"),
            ],
            receive=receive,
        )
        call_next.reset_mock()
        response = (
            await serverware_app.bounded_control_plane_request_middleware(
                oversized,
                call_next,
            )
        )
        self.assertEqual(response.status_code, 413)
        receive.assert_not_awaited()
        call_next.assert_not_awaited()

    async def test_chunked_body_stops_at_4097_without_global_read(
        self,
    ) -> None:
        chunks = iter(
            (
                {
                    "type": "http.request",
                    "body": b"a" * 4096,
                    "more_body": True,
                },
                {
                    "type": "http.request",
                    "body": b"b",
                    "more_body": True,
                },
            )
        )
        receive_calls = 0

        async def receive() -> dict[str, object]:
            nonlocal receive_calls
            receive_calls += 1
            if receive_calls > 2:
                self.fail(
                    "route consumed another chunk after crossing 4 KiB"
                )
            return next(chunks)

        request = self.request(
            b"",
            extensions={
                attestation.TRUSTED_TLS_SCOPE_EXTENSION: b"scope"
            },
            headers=[(b"content-type", b"application/json")],
            receive=receive,
        )
        with (
            mock.patch.object(
                serverware_app,
                "_load_public_evidence_producer_descriptor",
            ) as descriptor_loader,
            mock.patch.object(
                serverware_app,
                "trusted_public_tls_scope_from_asgi",
            ) as tls_from_scope,
            mock.patch.object(
                serverware_app.asyncio,
                "to_thread",
                new=mock.AsyncMock(),
            ) as to_thread,
            self.assertRaises(HTTPException) as captured,
        ):
            await serverware_app.attestation_public_evidence(request)
        self.assertEqual(captured.exception.status_code, 413)
        self.assertEqual(receive_calls, 2)
        descriptor_loader.assert_not_called()
        tls_from_scope.assert_not_called()
        to_thread.assert_not_awaited()

    async def test_route_capacity_denies_before_thread_dispatch(
        self,
    ) -> None:
        receive = mock.AsyncMock(
            return_value={
                "type": "http.request",
                "body": b"{}",
                "more_body": False,
            }
        )
        request = self.request(
            b"{}",
            extensions={
                attestation.TRUSTED_TLS_SCOPE_EXTENSION: b"scope"
            },
            headers=[
                (b"content-type", b"application/json"),
                (b"content-length", b"2"),
            ],
            receive=receive,
        )
        route_slots = SimpleNamespace(
            acquire=mock.AsyncMock(side_effect=TimeoutError),
            release=mock.Mock(),
        )
        with (
            mock.patch.object(
                serverware_app,
                "_load_public_evidence_producer_descriptor",
                return_value=mock.sentinel.descriptor,
            ),
            mock.patch.object(
                serverware_app,
                "trusted_public_tls_scope_from_asgi",
                return_value=trusted_scope(),
            ),
            mock.patch.object(
                serverware_app,
                "_PUBLIC_EVIDENCE_ROUTE_SLOTS",
                route_slots,
            ),
            mock.patch.object(
                serverware_app.asyncio,
                "to_thread",
                new=mock.AsyncMock(),
            ) as to_thread,
            self.assertRaises(HTTPException) as captured,
        ):
            await serverware_app.attestation_public_evidence(request)
        self.assertEqual(captured.exception.status_code, 503)
        receive.assert_awaited()
        route_slots.acquire.assert_awaited_once()
        route_slots.release.assert_not_called()
        to_thread.assert_not_awaited()

    async def test_route_serves_validated_bytes_without_reserialization(
        self,
    ) -> None:
        body = b'{"apiVersion":"serverware.publicAttestationBundle/v3"}\n'
        response_result = attestation.PublicEvidenceHttpResponse(
            body=body,
            status_code=200,
            raw_headers=(
                (b"content-type", b"application/json"),
                (b"cache-control", b"no-store"),
            ),
            body_sha256=digest_bytes(body),
        )
        receive = mock.AsyncMock(
            return_value={
                "type": "http.request",
                "body": b"{}",
                "more_body": False,
            }
        )
        request = self.request(
            b"{}",
            extensions={
                attestation.TRUSTED_TLS_SCOPE_EXTENSION: b"scope"
            },
            headers=[
                (b"content-type", b"application/json"),
                (b"content-length", b"2"),
            ],
            receive=receive,
        )
        with (
            mock.patch.object(
                serverware_app,
                "_load_public_evidence_producer_descriptor",
                return_value=mock.sentinel.descriptor,
            ),
            mock.patch.object(
                serverware_app,
                "trusted_public_tls_scope_from_asgi",
                return_value=trusted_scope(),
            ) as tls_from_scope,
            mock.patch.object(
                serverware_app,
                "production_public_evidence_response",
            ) as producer,
            mock.patch.object(
                serverware_app.asyncio,
                "to_thread",
                new=mock.AsyncMock(
                    side_effect=lambda function, **kwargs: function(
                        **kwargs
                    )
                ),
            ) as to_thread,
        ):
            response = (
                await serverware_app.attestation_public_evidence(request)
            )
        receive.assert_awaited()
        tls_from_scope.assert_called_once_with(
            request.scope, descriptor=mock.sentinel.descriptor
        )
        producer.assert_called_once_with(
            raw_request_body=b"{}",
            tls_scope=mock.ANY,
            descriptor=mock.sentinel.descriptor,
        )
        to_thread.assert_awaited_once_with(
            serverware_app._produce_public_evidence_from_scope,
            raw_request_body=b"{}",
            scope=request.scope,
        )
        self.assertEqual(response.body, body)
        self.assertEqual(response.raw_headers, list(response_result.raw_headers))

    async def test_route_cancellation_holds_capacity_until_worker_exits(
        self,
    ) -> None:
        response_result = attestation.PublicEvidenceHttpResponse(
            body=b"{}\n",
            status_code=200,
            raw_headers=((b"content-type", b"application/json"),),
            body_sha256=digest_bytes(b"{}\n"),
        )
        request = self.request(
            b"{}",
            extensions={
                attestation.TRUSTED_TLS_SCOPE_EXTENSION: b"scope"
            },
            headers=[
                (b"content-type", b"application/json"),
                (b"content-length", b"2"),
            ],
        )
        slot_released = asyncio.Event()
        route_slots = SimpleNamespace(
            acquire=mock.AsyncMock(return_value=True),
            release=mock.Mock(side_effect=slot_released.set),
        )
        worker_started = asyncio.Event()
        release_worker = asyncio.Event()

        async def delayed_thread(
            _function: object, **_kwargs: object
        ) -> attestation.PublicEvidenceHttpResponse:
            worker_started.set()
            await release_worker.wait()
            return response_result

        with (
            mock.patch.object(
                serverware_app,
                "_PUBLIC_EVIDENCE_ROUTE_SLOTS",
                route_slots,
            ),
            mock.patch.object(
                serverware_app.asyncio,
                "to_thread",
                new=mock.AsyncMock(side_effect=delayed_thread),
            ),
        ):
            request_task = asyncio.create_task(
                serverware_app.attestation_public_evidence(request)
            )
            await worker_started.wait()
            request_task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await request_task
            route_slots.release.assert_not_called()
            release_worker.set()
            await asyncio.wait_for(slot_released.wait(), timeout=1.0)
            route_slots.release.assert_called_once_with()


class PublicEvidenceProducerIsolationTests(unittest.TestCase):
    def test_descriptor_retains_measured_bytes_not_config_path(self) -> None:
        descriptor = public_evidence_descriptor()
        self.assertIsInstance(descriptor.immutable_config_bytes, bytes)
        self.assertIsInstance(descriptor.sandbox_descriptor_bytes, bytes)
        self.assertEqual(
            digest_bytes(descriptor.immutable_config_bytes),
            descriptor.immutable_config_sha256,
        )
        self.assertEqual(
            digest_bytes(descriptor.sandbox_descriptor_bytes),
            descriptor.sandbox_descriptor_sha256,
        )
        self.assertFalse(hasattr(descriptor, "immutable_config_path"))
        self.assertFalse(hasattr(descriptor, "sandbox_descriptor_path"))

    def test_legacy_descriptor_without_sandbox_fails_closed(self) -> None:
        legacy = {
            "apiVersion":
            attestation.PUBLIC_EVIDENCE_PRODUCER_DESCRIPTOR_VERSION,
            "concurrencyLimit": 1,
            "executablePath":
            "/run/serverware/public-evidence-producer",
            "executableSha256": digest("producer-executable"),
            "immutableConfigPath":
            "/run/serverware/public-evidence.json",
            "immutableConfigSha256": digest("producer-config"),
            "maxInputBytes": 64 * 1024,
            "maxOutputBytes": 4 * 1024 * 1024,
            "timeoutMilliseconds": 1_000,
            "trustRootsSha256": digest("trust-roots"),
        }
        raw = attestation.canonical_json(legacy).encode("ascii") + b"\n"
        with (
            mock.patch.object(
                attestation,
                "_configured_production_path",
                return_value=Path("/run/serverware/descriptor.json"),
            ),
            mock.patch.object(
                attestation,
                "_read_stable_root_owned_file",
                return_value=raw,
            ),
            mock.patch.object(
                attestation,
                "_required_public_pin",
                return_value=digest_bytes(raw),
            ),
            self.assertRaises(attestation.AttestationContractError),
        ):
            attestation._load_public_evidence_producer_descriptor()

    def test_missing_disposable_cgroup_fails_before_launch(self) -> None:
        with (
            mock.patch.object(
                attestation.os,
                "open",
                side_effect=FileNotFoundError,
            ),
            self.assertRaises(attestation.AttestationContractError),
        ):
            attestation._open_public_evidence_cgroup(
                public_evidence_descriptor()
            )

    def test_tree_is_accepted_only_after_group_and_cgroup_are_dead(
        self,
    ) -> None:
        process = mock.Mock(pid=4242)
        process.poll.return_value = 0
        with (
            mock.patch.object(attestation.os, "killpg") as kill_group,
            mock.patch.object(
                attestation, "_kill_public_evidence_cgroup"
            ) as kill_cgroup,
            mock.patch.object(
                attestation,
                "_public_evidence_process_group_dead",
                return_value=True,
            ),
            mock.patch.object(
                attestation,
                "_public_evidence_cgroup_populated",
                return_value=False,
            ),
            mock.patch.object(
                attestation.time, "monotonic", return_value=0.0
            ),
        ):
            attestation._terminate_public_evidence_tree(
                process, 9, deadline=1.0
            )
        kill_group.assert_called_once_with(4242, attestation.signal.SIGKILL)
        kill_cgroup.assert_called_once_with(9)

        with (
            mock.patch.object(attestation.os, "killpg"),
            mock.patch.object(
                attestation, "_kill_public_evidence_cgroup"
            ),
            mock.patch.object(
                attestation,
                "_public_evidence_process_group_dead",
                return_value=False,
            ),
            mock.patch.object(
                attestation,
                "_public_evidence_cgroup_populated",
                return_value=True,
            ),
            mock.patch.object(
                attestation.time,
                "monotonic",
                side_effect=(0.0, 2.0),
            ),
            mock.patch.object(attestation.time, "sleep"),
            self.assertRaises(attestation.AttestationContractError),
        ):
            attestation._terminate_public_evidence_tree(
                process, 9, deadline=1.0
            )

    def test_quarantine_retains_full_tree_until_reaper_proves_death(
        self,
    ) -> None:
        process = mock.Mock(pid=4242)
        semaphore = mock.Mock()
        tree = attestation._QuarantinedPublicEvidenceTree(
            process=process,
            process_group=4242,
            cgroup_descriptor=9,
            semaphore=semaphore,
        )
        quarantined = [tree]
        with (
            mock.patch.object(
                attestation,
                "_PUBLIC_EVIDENCE_QUARANTINED_TREES",
                quarantined,
            ),
            mock.patch.object(
                attestation, "_terminate_public_evidence_tree"
            ) as terminate,
            mock.patch.object(attestation.os, "close") as close,
        ):
            attestation._reap_quarantined_public_evidence_trees()
        terminate.assert_called_once_with(
            process,
            9,
            process_group=4242,
            deadline=mock.ANY,
        )
        close.assert_called_once_with(9)
        semaphore.release.assert_called_once_with()
        self.assertEqual(quarantined, [])

        quarantined = [tree]
        semaphore.reset_mock()
        with (
            mock.patch.object(
                attestation,
                "_PUBLIC_EVIDENCE_QUARANTINED_TREES",
                quarantined,
            ),
            mock.patch.object(
                attestation,
                "_terminate_public_evidence_tree",
                side_effect=attestation.AttestationContractError(
                    "tree still live"
                ),
            ),
            mock.patch.object(attestation.os, "close") as close,
        ):
            attestation._reap_quarantined_public_evidence_trees()
        close.assert_not_called()
        semaphore.release.assert_not_called()
        self.assertEqual(quarantined, [tree])


class PublicEvidenceTests(unittest.TestCase):
    def test_missing_journal_recovers_off_host_before_new_material(
        self,
    ) -> None:
        scope = trusted_scope()
        request_body = attestation.canonical_json(
            {
                "apiVersion":
                attestation.PUBLIC_EVIDENCE_REQUEST_VERSION,
                "callerNonceBase64url":
                attestation.b64e(b"r" * 32),
            }
        ).encode("ascii")
        descriptor = SimpleNamespace(
            descriptor_sha256=digest("descriptor"),
            executable_sha256=digest("executable"),
            immutable_config_sha256=digest("immutable-config"),
            nonce_authority_assurance_sha256=digest(
                "nonce-assurance"
            ),
            nonce_service_timeout_milliseconds=1_000,
            nonce_store_identity_sha256=digest(
                "nonce-store-identity"
            ),
            nonce_store_key_spki_sha256=digest("nonce-store-key"),
            producer_request_schema_sha256=digest(
                "producer-request-schema"
            ),
            release_identity_sha256=digest("release-identity"),
            sandbox_descriptor_sha256=digest(
                "sandbox-descriptor"
            ),
            sandbox_launcher_sha256=digest("sandbox-launcher"),
            trust_roots_sha256=digest("trust-roots"),
            verifier_state_service_timeout_milliseconds=1_000,
            witness_store_identity_sha256=digest(
                "witness-store-identity"
            ),
            witness_store_key_spki_sha256=digest(
                "witness-store-key"
            ),
        )
        journal_modes: list[bool] = []

        def absent_journal(**values: object) -> None:
            journal_modes.append(
                bool(values["create_if_missing"])
            )
            return None

        with mock.patch.object(
            attestation,
            "_public_evidence_recovery_journal_material",
            side_effect=absent_journal,
        ), mock.patch.object(
            attestation,
            "_public_evidence_begin_verifier_state_transition",
            return_value={"recoveredStatus": "consumptionPending"},
        ) as recovery:
            with self.assertRaisesRegex(
                attestation.AttestationContractError,
                "authoritative prepared operation exists",
            ):
                attestation._public_evidence_request_context(
                    raw_request_body=request_body,
                    tls_scope=scope,
                    descriptor=descriptor,
                    now=1_010,
                )
        self.assertEqual(journal_modes, [False])
        self.assertIsNone(
            recovery.call_args.kwargs["producer_invocation_base"]
        )
        self.assertIsNone(
            recovery.call_args.kwargs["expires_at_unix"]
        )
        self.assertIs(
            recovery.call_args.kwargs["recover_only"],
            True,
        )

    def test_completion_identity_is_closed_and_canonically_bound(self) -> None:
        identity = completion_identity()
        identity_sha256 = digest_bytes(
            attestation.canonical_json(identity).encode("ascii")
        )
        self.assertEqual(
            attestation._validate_completion_identity_binding(
                identity,
                identity_sha256,
                label="fixture",
            ),
            identity,
        )
        crossed = dict(identity)
        crossed["coreDigests"] = dict(identity["coreDigests"])
        crossed["coreDigests"]["response"] = digest("other-response")
        with self.assertRaises(attestation.AttestationContractError):
            attestation._validate_completion_identity_binding(
                crossed,
                identity_sha256,
                label="fixture",
            )
        extended = dict(identity)
        extended["unbound"] = digest("unbound")
        with self.assertRaises(attestation.AttestationContractError):
            attestation._validate_completion_identity_binding(
                extended,
                digest_bytes(
                    attestation.canonical_json(extended).encode("ascii")
                ),
                label="fixture",
            )

    def test_public_v3_release_graph_rejects_crossed_stable_roots(
        self,
    ) -> None:
        release_identity = stable_release_identity()
        release_identity_sha256 = verify_nitro_tee.sha256_json(
            release_identity
        )
        verified_release = {
            "releaseIdentity": release_identity,
            "releaseIdentitySha256": release_identity_sha256,
        }
        statement_sha256 = digest("stable-release-statement")
        release_config_sha256 = digest("release-config")
        trust_roots_sha256 = digest("trust-roots")
        graph = {
            "apiVersion": attestation.PUBLIC_RELEASE_GRAPH_VERSION,
            "releaseIdentity": release_identity,
            "releaseIdentitySha256": release_identity_sha256,
            "releaseConfigSha256": release_config_sha256,
            "stableReleaseStatementSha256": statement_sha256,
            "trustRootBundleSha256": trust_roots_sha256,
        }
        attestation._validate_public_release_graph(
            graph,
            verified_release=verified_release,
            release_config_sha256=release_config_sha256,
            stable_statement_sha256=statement_sha256,
            trust_root_bundle_sha256=trust_roots_sha256,
            public_verifier=verify_nitro_tee,
        )
        for field in (
            "releaseIdentitySha256",
            "releaseConfigSha256",
            "stableReleaseStatementSha256",
            "trustRootBundleSha256",
        ):
            crossed = json.loads(json.dumps(graph))
            crossed[field] = digest("crossed-" + field)
            with self.subTest(field=field), self.assertRaises(
                attestation.AttestationContractError
            ):
                attestation._validate_public_release_graph(
                    crossed,
                    verified_release=verified_release,
                    release_config_sha256=release_config_sha256,
                    stable_statement_sha256=statement_sha256,
                    trust_root_bundle_sha256=trust_roots_sha256,
                    public_verifier=verify_nitro_tee,
                )
        extended = json.loads(json.dumps(graph))
        extended["completionIdentity"] = completion_identity()
        with self.assertRaises(attestation.AttestationContractError):
            attestation._validate_public_release_graph(
                extended,
                verified_release=verified_release,
                release_config_sha256=release_config_sha256,
                stable_statement_sha256=statement_sha256,
                trust_root_bundle_sha256=trust_roots_sha256,
                public_verifier=verify_nitro_tee,
            )

    def public_v3_fixture(
        self,
        *,
        scope: attestation.TrustedTlsScope | None = None,
    ) -> SimpleNamespace:
        now = int(attestation.time.time())
        scope = (
            trusted_scope(
                envelope_sha256=digest("exact-fixture-tls-envelope")
            )
            if scope is None
            else scope
        )
        scope = replace(
            scope,
            issued_at_unix=now - 10,
            expires_at_unix=now + 40,
        )
        raw_request = attestation.canonical_json(
            {
                "apiVersion": attestation.PUBLIC_EVIDENCE_REQUEST_VERSION,
                "callerNonceBase64url": attestation.b64e(b"u" * 32),
            }
        ).encode("ascii")
        caller_nonce = b"u" * 32
        caller_nonce_sha256 = digest_bytes(caller_nonce)
        request_body_sha256 = digest_bytes(raw_request)
        tls_binding = scope.binding_document()
        tls_binding_sha256 = tls_binding["bindingSha256"]

        trust_roots_raw, trust_private_keys, trust = (
            fixture_public_trust_roots(now=now)
        )
        release_private_key = trust_private_keys["completion"]
        witness_private_key = trust_private_keys["witness"]
        nonce_store_private_key = Ed25519PrivateKey.generate()
        nonce_authority_assurance_evidence_private_key = (
            Ed25519PrivateKey.generate()
        )
        nonce_authority_verifier_state_private_key = (
            Ed25519PrivateKey.generate()
        )
        verifier_state_store_attestation_private_key = (
            Ed25519PrivateKey.generate()
        )
        verifier_state_store_assurance_private_key = (
            Ed25519PrivateKey.generate()
        )
        verifier_state_role_evidence_private_key = (
            Ed25519PrivateKey.generate()
        )
        public_client_tls_private_key = Ed25519PrivateKey.generate()
        verifier_listener_tls_private_key = Ed25519PrivateKey.generate()
        verifier_signer_client_tls_private_key = (
            Ed25519PrivateKey.generate()
        )
        verifier_signer_server_tls_private_key = (
            Ed25519PrivateKey.generate()
        )
        verifier_store_client_tls_private_key = (
            Ed25519PrivateKey.generate()
        )
        verifier_store_server_tls_private_key = (
            Ed25519PrivateKey.generate()
        )
        witness_store_private_key = Ed25519PrivateKey.generate()
        tls_scope_private_key = Ed25519PrivateKey.generate()
        response_private_key = Ed25519PrivateKey.generate()

        def spki(private_key: Ed25519PrivateKey) -> bytes:
            return private_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )

        producer_executable_raw = Path(
            production_attestation_producer_issuer.__file__
        ).read_bytes()
        producer_request_schema_raw = (
            Path(__file__).parents[1]
            / "schemas"
            / "public-attestation-producer-request.v2.schema.json"
        ).read_bytes()
        sandbox_launcher_raw = Path(
            public_attestation_production_sandbox_launcher.__file__
        ).read_bytes()
        nonce_service_raw = Path(
            attestation_nonce_service.__file__
        ).read_bytes()
        witness_service_raw = Path(
            attestation_witness_service.__file__
        ).read_bytes()

        nonce_store_identity_sha256 = digest(
            "fixture-production-nonce-authority"
        )
        nonce_authority_administrative_domain_sha256 = digest(
            "fixture-production-nonce-administrator"
        )
        nonce_authority_verifier_state_store_identity_sha256 = (
            digest("fixture-nonce-verifier-state-store")
        )
        nonce_authority_verifier_state_admin_domain_sha256 = (
            digest("fixture-nonce-verifier-state-admin-domain")
        )
        verifier_state_store_credential_identity_sha256 = digest(
            "fixture-verifier-state-store-credential"
        )
        verifier_state_store_configuration_sha256 = digest(
            "fixture-verifier-state-store-configuration"
        )
        verifier_state_store_minimum_generation = 1
        verifier_state_store_minimum_commit_index = 1
        verifier_state_store_rollback_mechanism = (
            "linearizableCasWithRollbackProtectedStorage"
        )
        store_assurance_issuer_administrative_domain_sha256 = digest(
            "fixture-store-assurance-issuer-admin"
        )
        store_assurance_issuer_credential_identity_sha256 = digest(
            "fixture-store-assurance-issuer-credential"
        )
        store_assurance_issuer_identity_sha256 = digest(
            "fixture-store-assurance-issuer-identity"
        )
        nonce_assurance_payload = {
            "administrativeDomainSha256":
            nonce_authority_administrative_domain_sha256,
            "apiVersion":
            production_attestation_producer_issuer
            .NONCE_AUTHORITY_ASSURANCE_EVIDENCE_VERSION,
            "assuranceEvidenceType":
            "linearizableCasOperatorAttestation",
            "authorityEpoch": 1,
            "authorityGeneration": 1,
            "authorityIdentitySha256": nonce_store_identity_sha256,
            "backendClass":
            "independentlyAdministeredLinearizableCas",
            "expiresAtUnix": now + 600,
            "issuedAtUnix": now - 1,
            "nonceAuthorityStateSigningKeySpkiSha256":
            digest_bytes(spki(nonce_store_private_key)),
            "rollbackMechanism":
            "linearizableCasWithRollbackProtectedStorage",
            "stateCommitment": "hashChainedLinearizableCommitment",
            "verifierStateStoreAdministrativeDomainSha256":
            nonce_authority_verifier_state_admin_domain_sha256,
            "verifierStateStoreClass":
            "independentlyAdministeredLinearizableCas",
            "verifierStateStoreIdentitySha256":
            nonce_authority_verifier_state_store_identity_sha256,
            "verifierStateStoreSigningKeySpkiSha256":
            digest_bytes(
                spki(nonce_authority_verifier_state_private_key)
            ),
        }
        nonce_authority_assurance_evidence = signed_service_envelope(
            nonce_authority_assurance_evidence_private_key,
            api_version=(
                production_attestation_producer_issuer
                .SIGNED_NONCE_AUTHORITY_ASSURANCE_EVIDENCE_VERSION
            ),
            domain=(
                production_attestation_producer_issuer
                .NONCE_AUTHORITY_ASSURANCE_EVIDENCE_DOMAIN
            ),
            payload=nonce_assurance_payload,
        )
        nonce_authority_assurance = {
            "apiVersion":
            production_attestation_producer_issuer
            .NONCE_AUTHORITY_ASSURANCE_VERSION,
            "administrativeDomainSha256":
            nonce_authority_administrative_domain_sha256,
            "assuranceEvidenceSha256":
            verify_nitro_tee.sha256_json(
                nonce_authority_assurance_evidence
            ),
            "assuranceEvidenceType":
            "linearizableCasOperatorAttestation",
            "assuranceLevel": "productionRollbackProtected",
            "authorityEpoch": 1,
            "authorityGeneration": 1,
            "authorityIdentitySha256": nonce_store_identity_sha256,
            "backendClass":
            "independentlyAdministeredLinearizableCas",
            "productionEligible": True,
            "rollbackProtection": {
                "administrativeRollbackResistance": True,
                "backendAttestationRequired": True,
                "exactSuccessorRequired": True,
                "freshVerifierChallengeRequired": True,
                "keyProtection": "nonExportableKmsHsm",
                "mechanism":
                "linearizableCasWithRollbackProtectedStorage",
                "stateCommitment":
                "hashChainedLinearizableCommitment",
                "verifierStateStoreClass":
                "independentlyAdministeredLinearizableCas",
            },
        }
        nonce_authority_assurance_sha256 = (
            verify_nitro_tee.sha256_json(
                nonce_authority_assurance
            )
        )
        store_assurance_payload = {
            "apiVersion":
            production_attestation_producer_issuer
            .VERIFIER_STATE_STORE_ASSURANCE_EVIDENCE_VERSION,
            "commitIndexSemantics":
            "equalToVerifierStateGeneration",
            "evidenceExpiresAtUnix": now + 600,
            "evidenceIssuedAtUnix": now - 1,
            "generationSemantics": "strictlyMonotonicU64",
            "issuerAdministrativeDomainSha256":
            store_assurance_issuer_administrative_domain_sha256,
            "issuerCredentialIdentitySha256":
            store_assurance_issuer_credential_identity_sha256,
            "issuerIdentitySha256":
            store_assurance_issuer_identity_sha256,
            "minimumStoreCommitIndex":
            verifier_state_store_minimum_commit_index,
            "minimumStoreGeneration":
            verifier_state_store_minimum_generation,
            "productionEligible": True,
            "rollbackMechanism":
            verifier_state_store_rollback_mechanism,
            "storeAdministrativeDomainSha256":
            nonce_authority_verifier_state_admin_domain_sha256,
            "storeAttestationKeySpkiSha256":
            digest_bytes(
                spki(verifier_state_store_attestation_private_key)
            ),
            "storeConfigurationSha256":
            verifier_state_store_configuration_sha256,
            "storeCredentialIdentitySha256":
            verifier_state_store_credential_identity_sha256,
            "storeIdentitySha256":
            nonce_authority_verifier_state_store_identity_sha256,
        }
        store_assurance_evidence = signed_service_envelope(
            verifier_state_store_assurance_private_key,
            api_version=(
                production_attestation_producer_issuer
                .SIGNED_VERIFIER_STATE_STORE_ASSURANCE_EVIDENCE_VERSION
            ),
            domain=(
                production_attestation_producer_issuer
                .VERIFIER_STATE_STORE_ASSURANCE_EVIDENCE_DOMAIN
            ),
            payload=store_assurance_payload,
        )
        store_assurance_evidence_sha256 = (
            verify_nitro_tee.sha256_json(store_assurance_evidence)
        )
        verifier_state_service = {
            "apiVersion":
            "serverware.attestationVerifierStateClient/v2",
            "abortPath": "/v1/state/abort",
            "attachNonceStatusPath":
            "/v1/state/attach-nonce-status",
            "clientCertificateSpkiSha256":
            digest_bytes(spki(public_client_tls_private_key)),
            "commitPath": "/v1/state/commit",
            "concurrencyLimit": 1,
            "endpoint": "https://192.0.2.1:9443",
            "issueChallengePath": "/v1/state/issue-challenge",
            "markConsumptionPath": "/v1/state/mark-consumption",
            "maxResponseBytes": 256 * 1024,
            "preparePath": "/v1/state/prepare",
            "readPath": "/v1/state/read",
            "recoverPath": "/v1/state/recover",
            "recoverChallengePath":
            "/v1/state/recover-challenge",
            "recoveryLookupPath": "/v1/state/recovery-lookup",
            "serverLeafSpkiSha256":
            digest_bytes(spki(verifier_listener_tls_private_key)),
            "serviceConfigurationSha256":
            digest("fixture-verifier-state-service-configuration"),
            "timeoutMilliseconds": 1_000,
        }

        def role(
            name: str,
            *,
            key_spki_sha256: str,
            assurance_evidence_sha256: str | None = None,
            administrative_domain_sha256: str | None = None,
            credential_identity_sha256: str | None = None,
            role_identity_sha256: str | None = None,
        ) -> dict[str, str]:
            return {
                "administrativeDomainSha256": (
                    digest(f"{name}-admin")
                    if administrative_domain_sha256 is None
                    else administrative_domain_sha256
                ),
                "assuranceEvidenceSha256": (
                    digest(f"{name}-assurance")
                    if assurance_evidence_sha256 is None
                    else assurance_evidence_sha256
                ),
                "credentialIdentitySha256": (
                    digest(f"{name}-credential")
                    if credential_identity_sha256 is None
                    else credential_identity_sha256
                ),
                "endpointIdentitySha256":
                digest(f"{name}-endpoint"),
                "keySpkiSha256": key_spki_sha256,
                "roleIdentitySha256": (
                    digest(f"{name}-identity")
                    if role_identity_sha256 is None
                    else role_identity_sha256
                ),
            }

        role_separation_evidence_issuer = role(
            "fixture-role-evidence-issuer",
            key_spki_sha256=digest_bytes(
                spki(verifier_state_role_evidence_private_key)
            ),
        )
        role_separation_payload = {
            "apiVersion":
            production_attestation_producer_issuer
            .VERIFIER_STATE_ROLE_SEPARATION_EVIDENCE_VERSION,
            "assuranceSha256": nonce_authority_assurance_sha256,
            "evidenceExpiresAtUnix": now + 600,
            "evidenceIssuedAtUnix": now - 1,
            "nonceAuthority": role(
                "fixture-nonce-authority",
                key_spki_sha256=digest_bytes(
                    spki(nonce_store_private_key)
                ),
                assurance_evidence_sha256=(
                    nonce_authority_assurance[
                        "assuranceEvidenceSha256"
                    ]
                ),
                administrative_domain_sha256=(
                    nonce_authority_administrative_domain_sha256
                ),
                role_identity_sha256=nonce_store_identity_sha256,
            ),
            "nonceAuthorityAssuranceEvidenceIssuer": role(
                "fixture-nonce-assurance-issuer",
                key_spki_sha256=digest_bytes(
                    spki(
                        nonce_authority_assurance_evidence_private_key
                    )
                ),
            ),
            "productionEligible": True,
            "publicAttestationClientTls": role(
                "fixture-public-client-tls",
                key_spki_sha256=digest_bytes(
                    spki(public_client_tls_private_key)
                ),
            ),
            "roleSeparationEvidenceIssuer":
            role_separation_evidence_issuer,
            "storeAssuranceEvidenceIssuer": role(
                "fixture-store-assurance-issuer",
                key_spki_sha256=digest_bytes(
                    spki(verifier_state_store_assurance_private_key)
                ),
                administrative_domain_sha256=(
                    store_assurance_issuer_administrative_domain_sha256
                ),
                credential_identity_sha256=(
                    store_assurance_issuer_credential_identity_sha256
                ),
                role_identity_sha256=(
                    store_assurance_issuer_identity_sha256
                ),
            ),
            "verifierStateServiceListenerTls": role(
                "fixture-verifier-listener-tls",
                key_spki_sha256=digest_bytes(
                    spki(verifier_listener_tls_private_key)
                ),
            ),
            "verifierStateSigner": role(
                "fixture-verifier-state-signer",
                key_spki_sha256=digest_bytes(
                    spki(
                        nonce_authority_verifier_state_private_key
                    )
                ),
            ),
            "verifierStateSignerClientTls": role(
                "fixture-verifier-signer-client-tls",
                key_spki_sha256=digest_bytes(
                    spki(verifier_signer_client_tls_private_key)
                ),
            ),
            "verifierStateSignerServerTls": role(
                "fixture-verifier-signer-server-tls",
                key_spki_sha256=digest_bytes(
                    spki(verifier_signer_server_tls_private_key)
                ),
            ),
            "verifierStateStore": role(
                "fixture-verifier-state-store",
                key_spki_sha256=digest_bytes(
                    spki(
                        verifier_state_store_attestation_private_key
                    )
                ),
                assurance_evidence_sha256=(
                    store_assurance_evidence_sha256
                ),
                administrative_domain_sha256=(
                    nonce_authority_verifier_state_admin_domain_sha256
                ),
                credential_identity_sha256=(
                    verifier_state_store_credential_identity_sha256
                ),
                role_identity_sha256=(
                    nonce_authority_verifier_state_store_identity_sha256
                ),
            ),
            "verifierStateStoreClientTls": role(
                "fixture-verifier-store-client-tls",
                key_spki_sha256=digest_bytes(
                    spki(verifier_store_client_tls_private_key)
                ),
            ),
            "verifierStateStoreServerTls": role(
                "fixture-verifier-store-server-tls",
                key_spki_sha256=digest_bytes(
                    spki(verifier_store_server_tls_private_key)
                ),
            ),
        }
        role_separation_evidence = signed_service_envelope(
            verifier_state_role_evidence_private_key,
            api_version=(
                production_attestation_producer_issuer
                .SIGNED_VERIFIER_STATE_ROLE_SEPARATION_EVIDENCE_VERSION
            ),
            domain=(
                production_attestation_producer_issuer
                .VERIFIER_STATE_ROLE_SEPARATION_EVIDENCE_DOMAIN
            ),
            payload=role_separation_payload,
        )
        role_separation_evidence_sha256 = (
            verify_nitro_tee.sha256_json(role_separation_evidence)
        )
        verifier_state_service_binding = {
            "apiVersion": verifier_state_service["apiVersion"],
            "clientCertificateSpkiSha256":
            verifier_state_service["clientCertificateSpkiSha256"],
            "endpoint": verifier_state_service["endpoint"],
            "serverLeafSpkiSha256":
            verifier_state_service["serverLeafSpkiSha256"],
            "serviceConfigurationSha256":
            verifier_state_service["serviceConfigurationSha256"],
            "signingKeySpkiSha256":
            digest_bytes(
                spki(nonce_authority_verifier_state_private_key)
            ),
            "roleSeparationEvidenceSha256":
            role_separation_evidence_sha256,
            "stateStoreAdministrativeDomainSha256":
            nonce_authority_verifier_state_admin_domain_sha256,
            "stateStoreAssuranceEvidenceSha256":
            store_assurance_evidence_sha256,
            "stateStoreAttestationKeySpkiSha256":
            digest_bytes(
                spki(verifier_state_store_attestation_private_key)
            ),
            "stateStoreConfigurationSha256":
            verifier_state_store_configuration_sha256,
            "stateStoreIdentitySha256":
            nonce_authority_verifier_state_store_identity_sha256,
            "stateStoreMinimumCommitIndex":
            verifier_state_store_minimum_commit_index,
            "stateStoreMinimumGeneration":
            verifier_state_store_minimum_generation,
        }
        witness_store_identity = {
            "apiVersion":
            attestation_witness_service.STORE_IDENTITY_VERSION,
            "assurance": "externallyWitnessedRollbackProtected",
            "deploymentId": "fixture-external-cas-boundary",
            "serviceId": "fixture-witness-store",
            "storageBackend": "external-linearizable-cas",
        }
        witness_store_identity_sha256 = (
            attestation_witness_service.sha256_json(
                witness_store_identity
            )
        )
        sandbox_document = fixture_sandbox_descriptor(
            producer_executable_sha256=
            digest_bytes(producer_executable_raw),
            producer_request_schema_sha256=
            digest_bytes(producer_request_schema_raw),
            sandbox_launcher_sha256=
            digest_bytes(sandbox_launcher_raw),
            trust_roots_sha256=digest_bytes(trust_roots_raw),
            nonce_service_executable_sha256=
            digest_bytes(nonce_service_raw),
            witness_service_executable_sha256=
            digest_bytes(witness_service_raw),
        )
        public_attestation_production_sandbox_launcher._validate_descriptor(
            sandbox_document,
            fixture_mode=True,
        )
        sandbox_descriptor_raw = canonical_line(sandbox_document)
        descriptor_document = {
            "apiVersion":
            attestation.PUBLIC_EVIDENCE_PRODUCER_DESCRIPTOR_VERSION,
            "concurrencyLimit": 1,
            "executablePath":
            "/run/serverware/public-attestation-producer",
            "executableSha256":
            digest_bytes(producer_executable_raw),
            "immutableConfigPath":
            "/run/serverware/public-attestation-config.json",
            "maxInputBytes": 256 * 1024,
            "maxOutputBytes": 4 * 1024 * 1024,
            "nonceService": {
                "apiVersion":
                attestation_nonce_service.CONSUME_ONCE_REQUEST_VERSION,
                "expectedPeerCgroupPath":
                "/serverware-attestation-services",
                "expectedPeerExecutableSha256":
                digest_bytes(nonce_service_raw),
                "expectedPeerGid": 10001,
                "expectedPeerUid": 10001,
                "maxResponseBytes": 1024 * 1024,
                "requestRole": "nonceRequest",
                "responseRole": "nonceResponse",
                "socketType": "AF_UNIX/SOCK_SEQPACKET",
                "timeoutMilliseconds": 1_000,
            },
            "nonceStoreIdentitySha256":
            nonce_store_identity_sha256,
            "nonceStoreKeySpkiSha256":
            digest_bytes(spki(nonce_store_private_key)),
            "producerRequestSchemaSha256":
            digest_bytes(producer_request_schema_raw),
            "sandboxDescriptorPath":
            "/run/serverware/public-attestation-sandbox.json",
            "sandboxDescriptorSha256":
            digest_bytes(sandbox_descriptor_raw),
            "sandboxLauncherPath":
            "/run/serverware/public-attestation-sandbox-launcher",
            "sandboxLauncherSha256":
            digest_bytes(sandbox_launcher_raw),
            "sandboxResources": {
                "measurementCopies": [
                    {
                        "measurementOf": "producerExecutable",
                        "role": "producerExecutableMeasurement",
                    },
                    {
                        "measurementOf": "sandboxDescriptor",
                        "role": "sandboxDescriptorMeasurement",
                    },
                ],
                "mountSources": [],
                "producerStreams": [
                    {"role": "nonceRequest"},
                    {"role": "nonceResponse"},
                    {"role": "witnessRequest"},
                    {"role": "witnessResponse"},
                ],
                "rootPath":
                "/run/serverware/public-attestation-root",
                "sealedFiles": [
                    {
                        "path":
                        "/run/serverware/public-attestation-producer-descriptor.json",
                        "role": "producerDescriptor",
                    },
                    {
                        "path":
                        "/run/serverware/public-attestation-producer-request.schema.json",
                        "role": "producerRequestSchema",
                    },
                    {
                        "path":
                        "/run/serverware/public-attestation-sandbox-launcher",
                        "role": "sandboxLauncher",
                    },
                    {
                        "path":
                        "/run/serverware/stable-release-statement.json",
                        "role": "stableReleaseStatement",
                    },
                    {
                        "path":
                        "/run/serverware/public-nitro-trust-roots.json",
                        "role": "trustRoots",
                    },
                ],
                "seccompProfilePath":
                "/run/serverware/public-attestation.seccomp",
            },
            "timeoutMilliseconds": 1_000,
            "trustRootsSha256": digest_bytes(trust_roots_raw),
            "verifierStateService": {
                **verifier_state_service,
                "caFdRole": "verifierStateCa",
                "clientCertificateFdRole":
                "verifierStateClientCertificate",
                "clientKeyFdRole": "verifierStateClientKey",
            },
            "witnessStoreIdentitySha256":
            witness_store_identity_sha256,
            "witnessStoreKeySpkiSha256":
            digest_bytes(spki(witness_store_private_key)),
        }
        producer_descriptor_raw = canonical_line(
            descriptor_document
        )
        component_pins = {
            "nonceStoreIdentitySha256":
            nonce_store_identity_sha256,
            "nonceStoreKeySpkiSha256":
            digest_bytes(spki(nonce_store_private_key)),
            "producerDescriptorSha256":
            digest_bytes(producer_descriptor_raw),
            "producerExecutableSha256":
            digest_bytes(producer_executable_raw),
            "producerRequestSchemaSha256":
            digest_bytes(producer_request_schema_raw),
            "sandboxDescriptorSha256":
            digest_bytes(sandbox_descriptor_raw),
            "sandboxLauncherSha256":
            digest_bytes(sandbox_launcher_raw),
            "witnessStoreIdentitySha256":
            witness_store_identity_sha256,
            "witnessStoreKeySpkiSha256":
            digest_bytes(spki(witness_store_private_key)),
        }
        release_identity = stable_release_identity(
            attestation_component_pins=component_pins,
            release_key_id=digest_bytes(spki(release_private_key)),
            response_key_id=digest_bytes(spki(response_private_key)),
            tls_scope_key_id=digest_bytes(spki(tls_scope_private_key)),
            trust_roots_sha256=digest_bytes(trust_roots_raw),
            witness_key_id=digest_bytes(spki(witness_private_key)),
            witness_store_key_id=(
                digest_bytes(spki(witness_store_private_key))
            ),
        )
        release_identity_sha256 = (
            production_attestation_producer_issuer.sha256_json(
                release_identity
            )
        )
        witness_boundary = FixtureExternalWitnessFdBoundary(
            release_identity_sha256=release_identity_sha256,
            store_identity=witness_store_identity,
            store_private_key=witness_store_private_key,
            witness_private_key=witness_private_key,
            now=now,
            non_production=True,
        )
        immutable_config = {
            "apiVersion":
            production_attestation_producer_issuer.RELEASE_CONFIG_VERSION,
            "minimumRollbackContinuityCommitmentSha256": (
                witness_boundary
                .minimum_rollback_continuity_commitment_sha256
            ),
            "nonceAuthorityAssurance":
            nonce_authority_assurance,
            "nonceAuthorityAssuranceEvidence":
            nonce_authority_assurance_evidence,
            "nonceAuthorityAssuranceEvidenceSigningPublicKeySpkiDerBase64url":
            attestation.b64e(
                spki(
                    nonce_authority_assurance_evidence_private_key
                )
            ),
            "nonceAuthorityAssuranceSha256":
            nonce_authority_assurance_sha256,
            "nonceAuthorityVerifierStateService":
            verifier_state_service,
            "nonceAuthorityVerifierStateRoleSeparationEvidence":
            role_separation_evidence,
            "nonceAuthorityVerifierStateRoleSeparationEvidenceIssuer":
            role_separation_evidence_issuer,
            "nonceAuthorityVerifierStateRoleSeparationEvidenceSigningPublicKeySpkiDerBase64url":
            attestation.b64e(
                spki(verifier_state_role_evidence_private_key)
            ),
            "nonceAuthorityVerifierStateSigningPublicKeySpkiDerBase64url":
            attestation.b64e(
                spki(
                    nonce_authority_verifier_state_private_key
                )
            ),
            "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256":
            nonce_authority_verifier_state_admin_domain_sha256,
            "nonceAuthorityVerifierStateStoreAssuranceEvidence":
            store_assurance_evidence,
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256":
            store_assurance_evidence_sha256,
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSigningPublicKeySpkiDerBase64url":
            attestation.b64e(
                spki(verifier_state_store_assurance_private_key)
            ),
            "nonceAuthorityVerifierStateStoreAssuranceIssuerAdministrativeDomainSha256":
            store_assurance_issuer_administrative_domain_sha256,
            "nonceAuthorityVerifierStateStoreAssuranceIssuerCredentialIdentitySha256":
            store_assurance_issuer_credential_identity_sha256,
            "nonceAuthorityVerifierStateStoreAssuranceIssuerIdentitySha256":
            store_assurance_issuer_identity_sha256,
            "nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url":
            attestation.b64e(
                spki(verifier_state_store_attestation_private_key)
            ),
            "nonceAuthorityVerifierStateStoreConfigurationSha256":
            verifier_state_store_configuration_sha256,
            "nonceAuthorityVerifierStateStoreCredentialIdentitySha256":
            verifier_state_store_credential_identity_sha256,
            "nonceAuthorityVerifierStateStoreIdentitySha256":
            nonce_authority_verifier_state_store_identity_sha256,
            "nonceAuthorityVerifierStateStoreMinimumCommitIndex":
            verifier_state_store_minimum_commit_index,
            "nonceAuthorityVerifierStateStoreMinimumGeneration":
            verifier_state_store_minimum_generation,
            "nonceAuthorityVerifierStateStoreRollbackMechanism":
            verifier_state_store_rollback_mechanism,
            "nonceStoreSigningPublicKeySpkiDerBase64url":
            attestation.b64e(spki(nonce_store_private_key)),
            "producerPolicy": component_pins,
            "releaseIdentity": release_identity,
            "releaseIdentitySha256": release_identity_sha256,
            "sandboxDescriptorSha256":
            digest_bytes(sandbox_descriptor_raw),
            "tlsScopeSigningPublicKeySpkiDerBase64url":
            attestation.b64e(spki(tls_scope_private_key)),
            "witnessStoreSigningPublicKeySpkiDerBase64url":
            attestation.b64e(spki(witness_store_private_key)),
        }
        immutable_config_raw = canonical_line(immutable_config)
        statement_pins = {
            "descriptorSha256":
            digest_bytes(producer_descriptor_raw),
            "executableSha256":
            digest_bytes(producer_executable_raw),
            "immutableConfigSha256":
            digest_bytes(immutable_config_raw),
            "nonceStoreIdentitySha256":
            nonce_store_identity_sha256,
            "nonceStoreKeySpkiSha256":
            digest_bytes(spki(nonce_store_private_key)),
            "producerRequestSchemaSha256":
            digest_bytes(producer_request_schema_raw),
            "sandboxDescriptorSha256":
            digest_bytes(sandbox_descriptor_raw),
            "sandboxLauncherSha256":
            digest_bytes(sandbox_launcher_raw),
            "trustRootsSha256": digest_bytes(trust_roots_raw),
            "witnessStoreIdentitySha256":
            witness_store_identity_sha256,
            "witnessStoreKeySpkiSha256":
            digest_bytes(spki(witness_store_private_key)),
        }
        artifacts = {
            "descriptorSha256": producer_descriptor_raw,
            "executableSha256": producer_executable_raw,
            "immutableConfigSha256": immutable_config_raw,
            "producerRequestSchemaSha256":
            producer_request_schema_raw,
            "sandboxDescriptorSha256": sandbox_descriptor_raw,
            "sandboxLauncherSha256": sandbox_launcher_raw,
            "trustRootsSha256": trust_roots_raw,
        }
        authorization_nonce = b"a" * 32
        statement_payload = {
            "attestationPins": statement_pins,
            "releaseIdentity": release_identity,
            "releaseIdentitySha256": release_identity_sha256,
            "trustRootBundleSha256":
            statement_pins["trustRootsSha256"],
        }
        signing_preauthorization = {
            "authorizationExpiresAtUnix": now + 120,
            "authorizationIdBase64url": attestation.b64e(b"i" * 32),
            "authorizationIssuedAtUnix": now - 1,
            "authorizationNonceSha256":
            digest_bytes(authorization_nonce),
            "authorizationSequence": 1,
            "minimumPolicySequence":
            release_identity["policy"]["sequence"],
            "minimumReleaseGeneration":
            release_identity["monotonicRelease"][
                "releaseGeneration"
            ],
            "minimumRollbackEpoch":
            release_identity["monotonicRelease"]["rollbackEpoch"],
            "releaseIdentitySha256": release_identity_sha256,
            "statementPayloadSha256":
            production_attestation_producer_issuer.sha256_json(
                statement_payload
            ),
            "useLimit": 1,
        }
        issuer_request = {
            "apiVersion":
            production_attestation_producer_issuer.ISSUER_REQUEST_VERSION,
            "attestationPins": statement_pins,
            "containmentBoundary": {
                "producerMakesContainmentClaim": False,
                "requiredLauncherContract":
                "serverware.publicAttestationExecutionSandbox/v2",
            },
            "deploymentMode": "fixture-non-production-retained-fd",
            "fixtureMode": True,
            "limits": {
                "maxSignerRequestBytes": 2 * 1024 * 1024,
                "maxSignerResponseBytes": 4 * 1024,
                "signerTimeoutMilliseconds": 1_000,
            },
            "releaseIdentity": release_identity,
            "releaseIdentitySha256": release_identity_sha256,
            "signerBoundary": {
                "algorithm": "Ed25519",
                "keyId": digest_bytes(spki(release_private_key)),
                "preauthorization": signing_preauthorization,
                "requestFd": 3,
                "responseFd": 4,
                "signatureDomain":
                production_attestation_producer_issuer
                .STABLE_STATEMENT_VERSION,
                "transport":
                "canonical-json-lines-over-retained-fd/v1",
            },
        }
        stable_statement_raw = issue_stable_statement_via_real_issuer(
            artifacts=artifacts,
            authorization_nonce=authorization_nonce,
            issuer_request=issuer_request,
            release_private_key=release_private_key,
            trust_roots_sha256=digest_bytes(trust_roots_raw),
        )
        stable_statement = json.loads(
            stable_statement_raw.decode("ascii")
        )

        producer_ephemeral_seed = b"e" * 32
        ephemeral_seed_copy = bytearray(producer_ephemeral_seed)
        (
            producer_ephemeral_spki,
            producer_ephemeral_key_id,
        ) = production_attestation_producer_issuer.ephemeral_public_key(
            ephemeral_seed_copy
        )
        production_attestation_producer_issuer.zeroize(
            ephemeral_seed_copy
        )
        producer_channel_challenge = attestation.b64e(b"c" * 32)
        nonce_authority_verifier_challenge = b"n" * 32
        recovery_identity = {
            "apiVersion":
            production_attestation_producer_issuer
            .VERIFIER_STATE_RECOVERY_IDENTITY_VERSION,
            "assuranceSha256":
            nonce_authority_assurance_sha256,
            "callerNonceSha256": caller_nonce_sha256,
            "immutableConfigSha256":
            digest_bytes(immutable_config_raw),
            "releaseIdentitySha256": release_identity_sha256,
            "requestBodySha256": request_body_sha256,
        }
        nonce_authority_verifier_state_operation_id = (
            hashlib.sha256(
                attestation
                .NONCE_AUTHORITY_VERIFIER_STATE_OPERATION_ID_DOMAIN
                + verify_nitro_tee.canonical_json_bytes(
                    recovery_identity
                )
            ).digest()
        )
        witness_verifier_challenge = attestation.b64e(b"v" * 32)
        invocation = (
            production_attestation_producer_issuer
            .producer_invocation_preimage(
                caller_nonce_sha256=caller_nonce_sha256,
                expires_at_unix=now + 20,
                issued_at_unix=now,
                minimum_release_identity_sha256=
                release_identity_sha256,
                minimum_rollback_continuity_commitment_sha256=(
                    witness_boundary
                    .minimum_rollback_continuity_commitment_sha256
                ),
                nonce_authority_verifier_challenge_base64url=(
                    attestation.b64e(
                        nonce_authority_verifier_challenge
                    )
                ),
                nonce_authority_verifier_state_operation_id_base64url=(
                    attestation.b64e(
                        nonce_authority_verifier_state_operation_id
                    )
                ),
                producer_channel_challenge_base64url=
                producer_channel_challenge,
                producer_ephemeral_public_key_spki_der_base64url=(
                    attestation.b64e(producer_ephemeral_spki)
                ),
                producer_ephemeral_key_spki_sha256=
                producer_ephemeral_key_id,
                release_identity_sha256=release_identity_sha256,
                request_body_sha256=request_body_sha256,
                static_pins=statement_pins,
                tls_binding_sha256=tls_binding_sha256,
                witness_verifier_challenge_base64url=(
                    witness_verifier_challenge
                ),
            )
        )
        producer_invocation_sha256 = (
            production_attestation_producer_issuer.sha256_json(
                invocation
            )
        )
        nonce_signer = FixtureNonceSignerBoundary(
            nonce_store_private_key,
            non_production=True,
        )
        nonce_verifier_state_boundary = (
            FixtureNonceVerifierStateBoundary(
                nonce_authority_verifier_state_private_key,
                assurance=nonce_authority_assurance,
                assurance_evidence=(
                    nonce_authority_assurance_evidence
                ),
                assurance_evidence_sha256=(
                    nonce_authority_assurance[
                        "assuranceEvidenceSha256"
                    ]
                ),
                assurance_sha256=
                nonce_authority_assurance_sha256,
                nonce_receipt_signing_key_id=digest_bytes(
                    spki(nonce_store_private_key)
                ),
                service_binding=verifier_state_service_binding,
                store_attestation_private_key=(
                    verifier_state_store_attestation_private_key
                ),
                store_assurance_evidence=store_assurance_evidence,
                store_assurance_evidence_sha256=(
                    store_assurance_evidence_sha256
                ),
                role_separation_evidence=role_separation_evidence,
                role_separation_evidence_sha256=(
                    role_separation_evidence_sha256
                ),
                state_store_administrative_domain_sha256=(
                    nonce_authority_verifier_state_admin_domain_sha256
                ),
                state_store_configuration_sha256=(
                    verifier_state_store_configuration_sha256
                ),
                state_store_identity_sha256=(
                    nonce_authority_verifier_state_store_identity_sha256
                ),
                state_store_minimum_commit_index=(
                    verifier_state_store_minimum_commit_index
                ),
                state_store_minimum_generation=(
                    verifier_state_store_minimum_generation
                ),
                production_eligible=True,
                now=now - 1,
                non_production=True,
            )
        )
        prior_nonce_authority_verifier_state = (
            nonce_verifier_state_boundary.current_state
        )
        nonce_authority_state_authorization = (
            nonce_verifier_state_boundary.prepare_current_head(
                operation_id=(
                    nonce_authority_verifier_state_operation_id
                ),
                producer_invocation=invocation,
                recovery_identity=recovery_identity,
                verifier_challenge=
                nonce_authority_verifier_challenge,
                now=now - 1,
            )
        )
        nonce_authority_state_authorization_sha256 = (
            verify_nitro_tee.sha256_json(
                nonce_authority_state_authorization
            )
        )
        transaction_id_base64url = attestation.b64e(
            nonce_authority_verifier_state_operation_id
        )
        consumed_at = now - 1
        nonce_consumption = {
            "apiVersion":
            attestation_nonce_service.NONCE_CONSUMPTION_VERSION,
            "consumedAtUnix": consumed_at,
            "nonceSha256": caller_nonce_sha256,
            "oneUse": True,
            "requestBodySha256": request_body_sha256,
            "sequence": 1,
            "storeIdentitySha256": nonce_store_identity_sha256,
            "tlsBindingSha256": tls_binding_sha256,
        }
        nonce_consumption_sha256 = verify_nitro_tee.sha256_json(
            nonce_consumption
        )
        nonce_authority_state = {
            "apiVersion":
            attestation_nonce_service.NONCE_AUTHORITY_STATE_VERSION,
            "assuranceSha256": nonce_authority_assurance_sha256,
            "authorityEpoch":
            nonce_authority_assurance["authorityEpoch"],
            "authorityGeneration":
            nonce_authority_assurance["authorityGeneration"],
            "highWaterCommitmentSha256": (
                attestation_nonce_service
                .nonce_authority_high_water_commitment(
                    assurance_sha256=(
                        nonce_authority_assurance_sha256
                    ),
                    authority_epoch=(
                        nonce_authority_assurance["authorityEpoch"]
                    ),
                    authority_generation=(
                        nonce_authority_assurance[
                            "authorityGeneration"
                        ]
                    ),
                    nonce_consumption_sha256=(
                        nonce_consumption_sha256
                    ),
                    nonce_verifier_state_authorization_sha256=(
                        nonce_authority_state_authorization_sha256
                    ),
                    previous_high_water_commitment_sha256=(
                        nonce_verifier_state_boundary.current_state[
                            "payload"
                        ]["highWaterCommitmentSha256"]
                    ),
                    previous_receipt_sha256=None,
                    sequence=1,
                    transaction_id_base64url=(
                        transaction_id_base64url
                    ),
                )
            ),
            "highWaterSequence": 1,
            "previousHighWaterCommitmentSha256": (
                nonce_verifier_state_boundary.current_state[
                    "payload"
                ]["highWaterCommitmentSha256"]
            ),
        }
        nonce_consume_request = {
            "apiVersion":
            attestation_nonce_service.CONSUME_ONCE_REQUEST_VERSION,
            "expiresAtUnix": now + 20,
            "nonceAuthorityVerifierStateAuthorizationSha256":
            nonce_authority_state_authorization_sha256,
            "nonceSha256": caller_nonce_sha256,
            "producerChannelChallengeBase64url":
            producer_channel_challenge,
            "producerEphemeralKeySha256":
            producer_ephemeral_key_id,
            "producerInvocationSha256":
            producer_invocation_sha256,
            "requestBodySha256": request_body_sha256,
            "tlsBindingSha256": tls_binding_sha256,
            "transactionIdBase64url": transaction_id_base64url,
        }
        nonce_receipt_payload = {
            "apiVersion":
            attestation_nonce_service.NONCE_RECEIPT_PAYLOAD_VERSION,
            "consumeRequestSha256": verify_nitro_tee.sha256(
                attestation_nonce_service
                .NONCE_CONSUME_REQUEST_DIGEST_DOMAIN
                + verify_nitro_tee.canonical_json_bytes(
                    nonce_consume_request
                )
            ),
            "consumedAtUnix": consumed_at,
            "expiresAtUnix": now + 20,
            "finalExternalVerifierChallengeConsumed": False,
            "finalExternalVerifierChallengeConsumptionRequired": True,
            "nonceAuthorityAssuranceSha256":
            nonce_authority_assurance_sha256,
            "nonceAuthorityState": nonce_authority_state,
            "nonceAuthorityStateSha256":
            verify_nitro_tee.sha256_json(nonce_authority_state),
            "nonceAuthorityVerifierStateAuthorizationSha256":
            nonce_authority_state_authorization_sha256,
            "nonceConsumption": nonce_consumption,
            "nonceConsumptionSha256": nonce_consumption_sha256,
            "nonceSha256": caller_nonce_sha256,
            "previousReceiptSha256": None,
            "producerChannelChallengeBase64url":
            producer_channel_challenge,
            "producerEphemeralKeySha256":
            producer_ephemeral_key_id,
            "producerInvocationSha256":
            producer_invocation_sha256,
            "receiptIssuedAtUnix": consumed_at,
            "requestBodySha256": request_body_sha256,
            "sequence": 1,
            "signerChannelBindingSha256":
            digest("fixture-nonce-signer-channel"),
            "storeIdentitySha256": nonce_store_identity_sha256,
            "tlsBindingSha256": tls_binding_sha256,
            "transactionIdBase64url": transaction_id_base64url,
        }
        nonce_consumption_receipt = (
            attestation_nonce_service.signed_receipt_envelope(
                payload=nonce_receipt_payload,
                signer=nonce_signer,
            )
        )
        nonce_response = {
            "nonceAuthorityAssurance":
            nonce_authority_assurance,
            "nonceAuthorityAssuranceSha256":
            nonce_authority_assurance_sha256,
            "nonceConsumption": nonce_consumption,
            "nonceConsumptionReceipt": nonce_consumption_receipt,
            "nonceConsumptionReceiptSha256":
            verify_nitro_tee.sha256_json(nonce_consumption_receipt),
        }
        self.assertEqual(
            nonce_response["nonceAuthorityAssurance"],
            nonce_authority_assurance,
        )
        self.assertEqual(
            nonce_response["nonceAuthorityAssuranceSha256"],
            nonce_authority_assurance_sha256,
        )
        nonce_authority_state_commit_receipt = (
            nonce_verifier_state_boundary.commit_successor(
                nonce_response["nonceConsumptionReceipt"],
                verifier_challenge=
                nonce_authority_verifier_challenge,
                committed_at_unix=now,
            )
        )
        producer_request = {
            "apiVersion":
            production_attestation_producer_issuer
            .PRODUCER_REQUEST_VERSION,
            "liveSessionRequest": {
                "apiVersion":
                production_attestation_producer_issuer
                .LIVE_REQUEST_VERSION,
                "callerNonceBase64url": attestation.b64e(caller_nonce),
                "callerNonceSha256": caller_nonce_sha256,
                "expiresAtUnix": now + 20,
                "httpRequest": {
                    "bodySha256": request_body_sha256,
                    "method": "POST",
                    "path": "/attestation/public-evidence",
                },
                "issuedAtUnix": now,
                "nonceConsumption":
                nonce_response["nonceConsumption"],
                "nonceConsumptionReceipt":
                nonce_response["nonceConsumptionReceipt"],
                "nonceConsumptionReceiptSha256":
                nonce_response["nonceConsumptionReceiptSha256"],
                "nonceAuthorityVerifierStateTransition":
                nonce_verifier_state_boundary.transition,
                "oneUse": True,
                "producerInvocation": invocation,
                "producerInvocationSha256":
                producer_invocation_sha256,
                "tlsBinding": tls_binding,
                "tlsBindingSha256": tls_binding_sha256,
            },
            "releaseIdentitySha256": release_identity_sha256,
            "staticPins": statement_pins,
        }
        producer_request_raw = canonical_line(producer_request)
        body = produce_bundle_via_real_producer(
            artifacts=artifacts,
            producer_request_raw=producer_request_raw,
            producer_ephemeral_seed=producer_ephemeral_seed,
            stable_statement_raw=stable_statement_raw,
            trust_roots_sha256=digest_bytes(trust_roots_raw),
            witness_boundary=witness_boundary,
        )
        document = json.loads(body.decode("ascii"))
        witness_response = witness_boundary.last_response
        if witness_response is None:
            raise AssertionError("fixture witness was not queried")
        protected_state = witness_response[
            "protectedLiveWitnessState"
        ]
        current = protected_state["payload"]["current"]
        witness_coordinates = {
            "generation": current["generation"],
            "headSha256": current["headSha256"],
            "rollbackEpoch": current["rollbackEpoch"],
            "sequence": current["sequence"],
            "treeSize": current["treeSize"],
        }
        live_session_proof = {
            "apiVersion": attestation.LIVE_SESSION_PROOF_VERSION,
            "callerNonceSha256": caller_nonce_sha256,
            "evidenceBodySha256": digest_bytes(body),
            "expiresAtUnix": now + 20,
            "producedAtUnix": now,
            "releaseIdentity": release_identity,
            "releaseIdentitySha256": release_identity_sha256,
            "request": {
                "bodySha256": request_body_sha256,
                "method": "POST",
                "path": "/attestation/public-evidence",
            },
            "responseSigningKeyId":
            digest_bytes(spki(response_private_key)),
            "tlsBinding": tls_binding,
            "tlsBindingSha256": tls_binding_sha256,
            "witness": witness_coordinates,
        }
        live_session_signature = (
            "ed25519:"
            + attestation.b64e(
                response_private_key.sign(
                    verify_nitro_tee.canonical_json_bytes(
                        live_session_proof
                    )
                )
            )
        )
        historical_result = {
            "evidenceBodySha256": digest_bytes(body),
            "liveSessionProofSha256":
            verify_nitro_tee.sha256_json(live_session_proof),
            "liveSessionSignatureSha256": digest_bytes(
                live_session_signature.encode("ascii")
            ),
        }
        delivery_rebind_payload = {
            "apiVersion":
            verify_nitro_tee.PUBLIC_ATTESTATION_DELIVERY_REBIND_VERSION,
            "currentTlsBinding": tls_binding,
            "currentTlsBindingSha256": tls_binding_sha256,
            "rebindIssuedAtUnix": now,
            "expiresAtUnix": now + 20,
            "historicalResult": historical_result,
            "historicalResultSha256":
            verify_nitro_tee.sha256_json(historical_result),
            "historicalTlsBindingSha256": tls_binding_sha256,
            "recoveryIdentity": recovery_identity,
            "recoveryIdentitySha256":
            verify_nitro_tee.sha256_json(recovery_identity),
            "responseSigningKeyId":
            digest_bytes(spki(response_private_key)),
        }
        delivery_rebind_core = {
            "apiVersion":
            verify_nitro_tee
            .SIGNED_PUBLIC_ATTESTATION_DELIVERY_REBIND_VERSION,
            "payload": delivery_rebind_payload,
            "payloadSha256":
            verify_nitro_tee.sha256_json(delivery_rebind_payload),
            "responseSigningKeyId":
            digest_bytes(spki(response_private_key)),
            "signatureAlgorithm": "Ed25519",
        }
        delivery_rebind = {
            **delivery_rebind_core,
            "signature": (
                "ed25519:"
                + attestation.b64e(
                    response_private_key.sign(
                        verify_nitro_tee.canonical_json_bytes(
                            delivery_rebind_core
                        )
                    )
                )
            ),
        }
        response_public_key_pem = (
            response_private_key.public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("ascii")
        )
        return SimpleNamespace(
            artifacts=artifacts,
            body=body,
            caller_nonce=caller_nonce,
            current_witness=witness_coordinates,
            document=document,
            delivery_rebind=delivery_rebind,
            expected_attestation_pins=statement_pins,
            immutable_config=immutable_config,
            immutable_config_raw=immutable_config_raw,
            invocation=invocation,
            key_role_spki_der={
                "assuranceEvidence":
                spki(nonce_authority_assurance_evidence_private_key),
                "publicClientTls":
                spki(public_client_tls_private_key),
                "roleSeparationEvidence":
                spki(verifier_state_role_evidence_private_key),
                "nonceReceipt": spki(nonce_store_private_key),
                "release": spki(release_private_key),
                "storeAttestation":
                spki(verifier_state_store_attestation_private_key),
                "storeAssuranceEvidence":
                spki(verifier_state_store_assurance_private_key),
                "tlsScope": spki(tls_scope_private_key),
                "verifierState":
                spki(nonce_authority_verifier_state_private_key),
                "witness": spki(witness_private_key),
                "witnessStore": spki(witness_store_private_key),
            },
            live_session_proof=live_session_proof,
            live_session_signature=live_session_signature,
            nonce_consumption=nonce_response["nonceConsumption"],
            nonce_consumption_receipt=
            nonce_response["nonceConsumptionReceipt"],
            nonce_authority_assurance=
            nonce_authority_assurance,
            nonce_authority_assurance_evidence=(
                nonce_authority_assurance_evidence
            ),
            nonce_authority_assurance_evidence_key_id=(
                digest_bytes(
                    spki(
                        nonce_authority_assurance_evidence_private_key
                    )
                )
            ),
            nonce_authority_assurance_evidence_public_key=(
                nonce_authority_assurance_evidence_private_key.public_key()
            ),
            nonce_authority_assurance_evidence_private_key=(
                nonce_authority_assurance_evidence_private_key
            ),
            nonce_authority_assurance_sha256=
            nonce_authority_assurance_sha256,
            nonce_authority_state_authorization=
            nonce_authority_state_authorization,
            nonce_authority_state_commit_receipt=
            nonce_authority_state_commit_receipt,
            nonce_authority_verifier_challenge=
            nonce_authority_verifier_challenge,
            nonce_authority_verifier_state_operation_id=(
                nonce_authority_verifier_state_operation_id
            ),
            nonce_authority_verifier_state_boundary=(
                nonce_verifier_state_boundary
            ),
            nonce_authority_verifier_state_key_id=(
                nonce_verifier_state_boundary.key_id
            ),
            nonce_authority_verifier_state_public_key=(
                nonce_authority_verifier_state_private_key.public_key()
            ),
            verifier_state_role_evidence_private_key=(
                verifier_state_role_evidence_private_key
            ),
            verifier_state_store_assurance_private_key=(
                verifier_state_store_assurance_private_key
            ),
            nonce_store_public_key=
            nonce_store_private_key.public_key(),
            nonce_store_key_id=
            digest_bytes(spki(nonce_store_private_key)),
            nonce_store_signer=nonce_signer,
            prior_protected_witness_state=(
                witness_boundary.prior_protected_state
            ),
            prior_nonce_authority_verifier_state=(
                prior_nonce_authority_verifier_state
            ),
            recovery_identity=recovery_identity,
            response_private_key=response_private_key,
            producer_request=producer_request_raw,
            protected_witness_state=protected_state,
            raw_request=raw_request,
            release_identity=release_identity,
            response_public_key_pem=response_public_key_pem,
            scope=scope,
            stable_statement=stable_statement,
            stable_statement_raw=stable_statement_raw,
            trust=trust,
            trust_roots_raw=trust_roots_raw,
            verifier_state_store_attestation_public_key=(
                verifier_state_store_attestation_private_key.public_key()
            ),
            verifier_state_store_attestation_private_key=(
                verifier_state_store_attestation_private_key
            ),
            witness_verifier_challenge=b"v" * 32,
        )

    def test_production_verifier_state_ingress_rejects_signed_assurance_matrix(
        self,
    ) -> None:
        fixture = self.public_v3_fixture()
        config = fixture.immutable_config
        role_evidence = config[
            "nonceAuthorityVerifierStateRoleSeparationEvidence"
        ]
        role_payload = role_evidence["payload"]
        now = fixture.live_session_proof["producedAtUnix"]

        class UnexpectedExternalCall:
            def post(self, *_args: object, **_kwargs: object) -> object:
                raise AssertionError(
                    "hostile evidence reached the external state service"
                )

        def service() -> (
            attestation_verifier_state_service.VerifierStateService
        ):
            client = UnexpectedExternalCall()
            signer_role = role_payload["verifierStateSigner"]
            store_role = role_payload["verifierStateStore"]
            nonce_role = role_payload["nonceAuthority"]
            signer = (
                attestation_verifier_state_service
                .ExternalEd25519Signer(
                    client=client,
                    public_key_spki_der_base64url=config[
                        "nonceAuthorityVerifierStateSigningPublicKeySpkiDerBase64url"
                    ],
                    administrative_domain_sha256=signer_role[
                        "administrativeDomainSha256"
                    ],
                    endpoint_identity_sha256=signer_role[
                        "endpointIdentitySha256"
                    ],
                    credential_identity_sha256=signer_role[
                        "credentialIdentitySha256"
                    ],
                    assurance_evidence_sha256=signer_role[
                        "assuranceEvidenceSha256"
                    ],
                )
            )
            store = (
                attestation_verifier_state_service
                .ExternalLinearizableStateStore(
                    client=client,
                    store_class=fixture.nonce_authority_assurance[
                        "rollbackProtection"
                    ]["verifierStateStoreClass"],
                    rollback_mechanism=config[
                        "nonceAuthorityVerifierStateStoreRollbackMechanism"
                    ],
                    store_identity_sha256=config[
                        "nonceAuthorityVerifierStateStoreIdentitySha256"
                    ],
                    administrative_domain_sha256=store_role[
                        "administrativeDomainSha256"
                    ],
                    endpoint_identity_sha256=store_role[
                        "endpointIdentitySha256"
                    ],
                    credential_identity_sha256=store_role[
                        "credentialIdentitySha256"
                    ],
                    assurance_evidence_sha256=config[
                        "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"
                    ],
                    configuration_sha256=config[
                        "nonceAuthorityVerifierStateStoreConfigurationSha256"
                    ],
                    minimum_generation=config[
                        "nonceAuthorityVerifierStateStoreMinimumGeneration"
                    ],
                    minimum_commit_index=config[
                        "nonceAuthorityVerifierStateStoreMinimumCommitIndex"
                    ],
                    attestation_public_key_spki_der_base64url=config[
                        "nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url"
                    ],
                )
            )
            nonce_authority = (
                attestation_verifier_state_service
                .NonceAuthorityReceiptVerifier(
                    signing_public_key_spki_der_base64url=config[
                        "nonceStoreSigningPublicKeySpkiDerBase64url"
                    ],
                    store_identity_sha256=config[
                        "nonceStoreIdentitySha256"
                    ],
                    administrative_domain_sha256=nonce_role[
                        "administrativeDomainSha256"
                    ],
                    endpoint_identity_sha256=nonce_role[
                        "endpointIdentitySha256"
                    ],
                    credential_identity_sha256=nonce_role[
                        "credentialIdentitySha256"
                    ],
                    assurance_evidence_sha256=(
                        fixture.nonce_authority_assurance[
                            "assuranceEvidenceSha256"
                        ]
                    ),
                )
            )
            additional_role_names = {
                "nonceAuthorityAssuranceEvidenceIssuer",
                "publicAttestationClientTls",
                "roleSeparationEvidenceIssuer",
                "storeAssuranceEvidenceIssuer",
                "verifierStateServiceListenerTls",
                "verifierStateSignerClientTls",
                "verifierStateSignerServerTls",
                "verifierStateStoreClientTls",
                "verifierStateStoreServerTls",
            }
            return (
                attestation_verifier_state_service
                .VerifierStateService(
                    mode="production",
                    assurance=copy.deepcopy(
                        fixture.nonce_authority_assurance
                    ),
                    assurance_sha256=(
                        fixture.nonce_authority_assurance_sha256
                    ),
                    store=store,
                    signer=signer,
                    nonce_authority=nonce_authority,
                    nonce_authority_assurance_evidence=copy.deepcopy(
                        fixture.nonce_authority_assurance_evidence
                    ),
                    nonce_authority_assurance_evidence_public_key=(
                        fixture
                        .nonce_authority_assurance_evidence_public_key
                    ),
                    nonce_authority_assurance_evidence_key_id=(
                        fixture
                        .nonce_authority_assurance_evidence_key_id
                    ),
                    role_separation_evidence=copy.deepcopy(
                        role_evidence
                    ),
                    role_separation_evidence_public_key=(
                        fixture
                        .verifier_state_role_evidence_private_key
                        .public_key()
                    ),
                    role_separation_evidence_key_id=(
                        role_evidence["signingKeyId"]
                    ),
                    role_separation_additional_roles={
                        name: copy.deepcopy(role_payload[name])
                        for name in additional_role_names
                    },
                    store_assurance_evidence=copy.deepcopy(
                        config[
                            "nonceAuthorityVerifierStateStoreAssuranceEvidence"
                        ]
                    ),
                    store_assurance_evidence_public_key=(
                        fixture
                        .verifier_state_store_assurance_private_key
                        .public_key()
                    ),
                    store_assurance_evidence_key_id=config[
                        "nonceAuthorityVerifierStateStoreAssuranceEvidence"
                    ]["signingKeyId"],
                    store_assurance_issuer_administrative_domain_sha256=config[
                        "nonceAuthorityVerifierStateStoreAssuranceIssuerAdministrativeDomainSha256"
                    ],
                    store_assurance_issuer_credential_identity_sha256=config[
                        "nonceAuthorityVerifierStateStoreAssuranceIssuerCredentialIdentitySha256"
                    ],
                    store_assurance_issuer_identity_sha256=config[
                        "nonceAuthorityVerifierStateStoreAssuranceIssuerIdentitySha256"
                    ],
                    initialize_reference_genesis=False,
                )
            )

        def resign_nonce(
            instance: (
                attestation_verifier_state_service
                .VerifierStateService
            ),
            **changes: object,
        ) -> None:
            payload = copy.deepcopy(
                fixture.nonce_authority_assurance_evidence["payload"]
            )
            payload.update(changes)
            instance._nonce_authority_assurance_evidence_document = (
                signed_service_envelope(
                    fixture
                    .nonce_authority_assurance_evidence_private_key,
                    api_version=(
                        production_attestation_producer_issuer
                        .SIGNED_NONCE_AUTHORITY_ASSURANCE_EVIDENCE_VERSION
                    ),
                    domain=(
                        production_attestation_producer_issuer
                        .NONCE_AUTHORITY_ASSURANCE_EVIDENCE_DOMAIN
                    ),
                    payload=payload,
                )
            )

        def resign_store(
            instance: (
                attestation_verifier_state_service
                .VerifierStateService
            ),
        ) -> None:
            payload = copy.deepcopy(
                config[
                    "nonceAuthorityVerifierStateStoreAssuranceEvidence"
                ]["payload"]
            )
            payload["storeIdentitySha256"] = digest(
                "hostile-store-substitution"
            )
            instance._store_assurance_evidence_document = (
                signed_service_envelope(
                    fixture.verifier_state_store_assurance_private_key,
                    api_version=(
                        production_attestation_producer_issuer
                        .SIGNED_VERIFIER_STATE_STORE_ASSURANCE_EVIDENCE_VERSION
                    ),
                    domain=(
                        production_attestation_producer_issuer
                        .VERIFIER_STATE_STORE_ASSURANCE_EVIDENCE_DOMAIN
                    ),
                    payload=payload,
                )
            )

        def resign_tls(
            instance: (
                attestation_verifier_state_service
                .VerifierStateService
            ),
        ) -> None:
            payload = copy.deepcopy(role_payload)
            payload["publicAttestationClientTls"][
                "keySpkiSha256"
            ] = digest("hostile-public-client-tls")
            instance._role_separation_evidence_document = (
                signed_service_envelope(
                    fixture.verifier_state_role_evidence_private_key,
                    api_version=(
                        production_attestation_producer_issuer
                        .SIGNED_VERIFIER_STATE_ROLE_SEPARATION_EVIDENCE_VERSION
                    ),
                    domain=(
                        production_attestation_producer_issuer
                        .VERIFIER_STATE_ROLE_SEPARATION_EVIDENCE_DOMAIN
                    ),
                    payload=payload,
                )
            )

        hostile_mutations = {
            "digest": lambda instance: (
                instance
                ._nonce_authority_assurance_evidence_document
                .__setitem__(
                    "payloadSha256",
                    digest("hostile-evidence-digest"),
                )
            ),
            "signature": lambda instance: (
                instance
                ._nonce_authority_assurance_evidence_document
                .__setitem__(
                    "signatureBase64url",
                    attestation.b64e(b"\x00" * 64),
                )
            ),
            "issuer": lambda instance: setattr(
                instance,
                "_nonce_authority_assurance_evidence_key_id",
                digest("hostile-evidence-issuer"),
            ),
            "freshness": lambda instance: resign_nonce(
                instance,
                issuedAtUnix=now - 20,
                expiresAtUnix=now,
            ),
            "authority": lambda instance: resign_nonce(
                instance,
                authorityIdentitySha256=digest(
                    "hostile-nonce-authority"
                ),
            ),
            "store": resign_store,
            "tls": resign_tls,
        }
        recovery_request = {
            "apiVersion":
            attestation_verifier_state_service.RECOVERY_REQUEST_VERSION,
            "recoveryIdentity": fixture.recovery_identity,
            "recoveryIdentitySha256": verify_nitro_tee.sha256_json(
                fixture.recovery_identity
            ),
            "recoveryKeySha256": json.loads(
                fixture.producer_request.decode("ascii")
            )["liveSessionRequest"][
                "nonceAuthorityVerifierStateTransition"
            ]["recoveryKeySha256"],
        }
        for name, mutate in hostile_mutations.items():
            instance = service()
            mutate(instance)
            with self.subTest(substitution=name), self.assertRaises(
                attestation_verifier_state_service.ContractError
            ):
                instance.recover(
                    copy.deepcopy(recovery_request),
                    now=now,
                )

    def validate_fixture_producer_request(
        self,
        fixture: SimpleNamespace,
        producer_request: dict[str, object],
    ) -> dict[str, object]:
        raw = canonical_line(producer_request)
        invocation = producer_request["liveSessionRequest"][
            "producerInvocation"
        ]
        return (
            production_attestation_producer_issuer
            .validate_producer_request(
                producer_request,
                raw=raw,
                stable_pins=fixture.expected_attestation_pins,
                release_identity_sha256=(
                    production_attestation_producer_issuer
                    .sha256_json(fixture.release_identity)
                ),
                producer_ephemeral_public_key_spki_der=(
                    attestation.b64d(
                        invocation[
                            "producerEphemeralKeySpkiDerBase64url"
                        ]
                    )
                ),
                producer_ephemeral_key_spki_sha256=invocation[
                    "producerEphemeralKeySpkiSha256"
                ],
                nonce_store_key=fixture.nonce_store_public_key,
                nonce_authority_assurance=(
                    fixture.nonce_authority_assurance
                ),
                nonce_authority_assurance_sha256=(
                    fixture.nonce_authority_assurance_sha256
                ),
                minimum_rollback_continuity_commitment_sha256=(
                    invocation[
                        "minimumRollbackContinuityCommitmentSha256"
                    ]
                ),
                release_config=fixture.immutable_config,
                trust_key_ids=fixture.trust["keyIds"],
                verifier_state_key=(
                    fixture.nonce_authority_verifier_state_public_key
                ),
                assurance_evidence_key=(
                    fixture.nonce_authority_assurance_evidence_public_key
                ),
                store_attestation_key=(
                    fixture.verifier_state_store_attestation_public_key
                ),
            )
        )

    @staticmethod
    def producer_request_with_receipt(
        fixture: SimpleNamespace,
        receipt: dict[str, object],
    ) -> dict[str, object]:
        request = json.loads(fixture.producer_request.decode("ascii"))
        live = request["liveSessionRequest"]
        live["nonceConsumption"] = receipt["payload"][
            "nonceConsumption"
        ]
        live["nonceConsumptionReceipt"] = receipt
        live["nonceConsumptionReceiptSha256"] = (
            verify_nitro_tee.sha256_json(receipt)
        )
        return request

    @staticmethod
    def resign_fixture_nonce_receipt(
        fixture: SimpleNamespace,
        payload: dict[str, object],
    ) -> dict[str, object]:
        return attestation_nonce_service.signed_receipt_envelope(
            payload=payload,
            signer=fixture.nonce_store_signer,
        )

    def test_producer_request_uses_measured_material_not_paths(
        self,
    ) -> None:
        fixture = self.public_v3_fixture()
        producer_request = json.loads(
            fixture.producer_request.decode("ascii")
        )
        self.validate_fixture_producer_request(
            fixture,
            producer_request,
        )
        self.assertEqual(
            producer_request["apiVersion"],
            attestation.PUBLIC_EVIDENCE_PRODUCER_REQUEST_VERSION,
        )
        live_request = producer_request["liveSessionRequest"]
        self.assertIs(live_request["oneUse"], True)
        self.assertEqual(
            live_request["nonceConsumptionReceiptSha256"],
            verify_nitro_tee.sha256_json(
                live_request["nonceConsumptionReceipt"]
            ),
        )
        self.assertEqual(
            live_request["producerInvocation"],
            fixture.invocation,
        )
        self.assertNotIn(
            "completionIdentity", fixture.producer_request.decode("ascii")
        )
        self.assertEqual(
            producer_request["staticPins"]["immutableConfigSha256"],
            digest_bytes(fixture.immutable_config_raw),
        )
        self.assertNotIn(
            "immutableConfigPath", fixture.producer_request.decode("ascii")
        )
        self.assertNotIn(
            "sandboxDescriptorPath", fixture.producer_request.decode("ascii")
        )

    def test_public_v3_carries_signed_durable_nonce_v2_receipt(
        self,
    ) -> None:
        fixture = self.public_v3_fixture()
        verified = (
            verify_nitro_tee
            .verify_public_attestation_nonce_receipt_envelope(
                fixture.nonce_consumption_receipt,
                key=fixture.nonce_store_public_key,
                key_id=fixture.nonce_store_key_id,
            )
        )
        self.assertIs(
            verified["payload"][
                "finalExternalVerifierChallengeConsumptionRequired"
            ],
            True,
        )
        self.assertIs(
            verified["payload"][
                "finalExternalVerifierChallengeConsumed"
            ],
            False,
        )
        self.assertEqual(
            verified["payload"]["producerInvocationSha256"],
            verify_nitro_tee.sha256_json(fixture.invocation),
        )
        payload = verified["payload"]
        self.assertEqual(
            payload["nonceAuthorityAssuranceSha256"],
            fixture.nonce_authority_assurance_sha256,
        )
        self.assertEqual(
            payload[
                "nonceAuthorityVerifierStateAuthorizationSha256"
            ],
            verify_nitro_tee.sha256_json(
                fixture.nonce_authority_state_authorization
            ),
        )
        self.assertEqual(
            payload["nonceAuthorityStateSha256"],
            verify_nitro_tee.sha256_json(
                payload["nonceAuthorityState"]
            ),
        )
        context = self.validate_fixture_producer_request(
            fixture,
            json.loads(fixture.producer_request.decode("ascii")),
        )
        self.assertEqual(
            context["nonceAuthorityStateSha256"],
            payload["nonceAuthorityStateSha256"],
        )

    def test_producer_rejects_omitted_or_wrong_nonce_authority_digests(
        self,
    ) -> None:
        fixture = self.public_v3_fixture()
        original_payload = fixture.nonce_consumption_receipt[
            "payload"
        ]
        omitted = json.loads(json.dumps(original_payload))
        omitted.pop(
            "nonceAuthorityVerifierStateAuthorizationSha256"
        )
        omitted_receipt = self.resign_fixture_nonce_receipt(
            fixture,
            omitted,
        )
        with self.assertRaises(
            production_attestation_producer_issuer.ContractError
        ):
            self.validate_fixture_producer_request(
                fixture,
                self.producer_request_with_receipt(
                    fixture,
                    omitted_receipt,
                ),
            )

        wrong_assurance = json.loads(json.dumps(original_payload))
        wrong_assurance["nonceAuthorityAssuranceSha256"] = digest(
            "substituted-nonce-authority-assurance"
        )
        wrong_assurance_receipt = (
            self.resign_fixture_nonce_receipt(
                fixture,
                wrong_assurance,
            )
        )
        with self.assertRaises(
            production_attestation_producer_issuer.ContractError
        ):
            self.validate_fixture_producer_request(
                fixture,
                self.producer_request_with_receipt(
                    fixture,
                    wrong_assurance_receipt,
                ),
            )

    def test_producer_request_cannot_self_assert_production_assurance(
        self,
    ) -> None:
        fixture = self.public_v3_fixture()
        request = json.loads(fixture.producer_request.decode("ascii"))
        asserted = json.loads(
            json.dumps(fixture.nonce_authority_assurance)
        )
        asserted["productionEligible"] = True
        asserted["assuranceLevel"] = "productionRollbackProtected"
        request["liveSessionRequest"][
            "nonceAuthorityAssurance"
        ] = asserted
        request["liveSessionRequest"][
            "nonceAuthorityAssuranceSha256"
        ] = verify_nitro_tee.sha256_json(asserted)
        with self.assertRaises(
            production_attestation_producer_issuer.ContractError
        ):
            self.validate_fixture_producer_request(
                fixture,
                request,
            )

    def test_producer_and_fixture_reject_wrong_or_stale_authority_head(
        self,
    ) -> None:
        fixture = self.public_v3_fixture()
        payload = json.loads(
            json.dumps(
                fixture.nonce_consumption_receipt["payload"]
            )
        )
        payload["nonceAuthorityState"][
            "previousHighWaterCommitmentSha256"
        ] = digest("wrong-previous-nonce-authority-head")
        payload["nonceAuthorityStateSha256"] = (
            verify_nitro_tee.sha256_json(
                payload["nonceAuthorityState"]
            )
        )
        wrong_head_receipt = self.resign_fixture_nonce_receipt(
            fixture,
            payload,
        )
        with self.assertRaises(
            production_attestation_producer_issuer.ContractError
        ):
            self.validate_fixture_producer_request(
                fixture,
                self.producer_request_with_receipt(
                    fixture,
                    wrong_head_receipt,
                ),
            )

        with self.assertRaisesRegex(
            AssertionError,
            "replayed",
        ):
            fixture.nonce_authority_verifier_state_boundary.commit_successor(
                fixture.nonce_consumption_receipt,
                verifier_challenge=(
                    fixture.nonce_authority_verifier_challenge
                ),
                committed_at_unix=(
                    fixture.live_session_proof["producedAtUnix"]
                ),
            )

        boundary = fixture.nonce_authority_verifier_state_boundary
        next_recovery_identity = json.loads(
            json.dumps(fixture.recovery_identity)
        )
        next_recovery_identity["requestBodySha256"] = digest(
            "next-request-body"
        )
        next_operation_id = hashlib.sha256(
            attestation
            .NONCE_AUTHORITY_VERIFIER_STATE_OPERATION_ID_DOMAIN
            + verify_nitro_tee.canonical_json_bytes(
                next_recovery_identity
            )
        ).digest()
        next_invocation = json.loads(
            json.dumps(fixture.invocation)
        )
        next_invocation["requestBodySha256"] = (
            next_recovery_identity["requestBodySha256"]
        )
        next_invocation[
            "nonceAuthorityVerifierStateOperationIdBase64url"
        ] = attestation.b64e(next_operation_id)
        next_verifier_challenge = b"q" * 32
        next_authorization = boundary.prepare_current_head(
            operation_id=next_operation_id,
            producer_invocation=next_invocation,
            recovery_identity=next_recovery_identity,
            verifier_challenge=next_verifier_challenge,
            now=fixture.live_session_proof["producedAtUnix"],
        )
        stale_payload = json.loads(
            json.dumps(
                fixture.nonce_consumption_receipt["payload"]
            )
        )
        stale_payload[
            "nonceAuthorityVerifierStateAuthorizationSha256"
        ] = verify_nitro_tee.sha256_json(next_authorization)
        stale_receipt = self.resign_fixture_nonce_receipt(
            fixture,
            stale_payload,
        )
        with self.assertRaises(verify_nitro_tee.VerificationError):
            boundary.commit_successor(
                stale_receipt,
                verifier_challenge=next_verifier_challenge,
                committed_at_unix=(
                    fixture.live_session_proof["producedAtUnix"] + 1
                ),
            )

    def verify_public_fixture(
        self,
        fixture: SimpleNamespace,
        *,
        evidence_body: bytes | None = None,
        expected_tls_binding: dict[str, object] | None = None,
        delivery_rebind: dict[str, object] | None = None,
        now: int | None = None,
    ) -> dict[str, object]:
        if fixture.prior_protected_witness_state is None:
            raise AssertionError("fixture prior witness state is missing")
        return verify_nitro_tee.verify_public_v3_response(
            evidence_body=(
                fixture.body
                if evidence_body is None
                else evidence_body
            ),
            live_session_proof=fixture.live_session_proof,
            live_session_signature=fixture.live_session_signature,
            response_signing_public_key_pem=(
                fixture.response_public_key_pem
            ),
            caller_nonce=fixture.caller_nonce,
            request_body=fixture.raw_request,
            expected_tls_binding=(
                fixture.scope.binding_document()
                if expected_tls_binding is None
                else expected_tls_binding
            ),
            delivery_rebind=(
                fixture.delivery_rebind
                if delivery_rebind is None
                else delivery_rebind
            ),
            trust=fixture.trust,
            expected_release_config_sha256=digest_bytes(
                fixture.immutable_config_raw
            ),
            expected_nonce_authority_assurance_sha256=(
                fixture.nonce_authority_assurance_sha256
            ),
            expected_nonce_authority_assurance_issuer_spki_sha256=(
                fixture
                .nonce_authority_assurance_evidence_key_id
            ),
            expected_attestation_pins=
            fixture.expected_attestation_pins,
            protected_witness_state=
            fixture.protected_witness_state,
            protected_witness_state_raw=canonical_line(
                fixture.protected_witness_state
            ),
            prior_protected_witness_state=(
                fixture.prior_protected_witness_state
            ),
            nonce_consumption_receipt=
            fixture.nonce_consumption_receipt,
            nonce_authority_assurance_evidence=(
                fixture.nonce_authority_assurance_evidence
            ),
            prior_nonce_authority_verifier_state=(
                fixture.prior_nonce_authority_verifier_state
            ),
            nonce_authority_state_authorization=(
                fixture.nonce_authority_state_authorization
            ),
            nonce_authority_state_commit_receipt=(
                fixture.nonce_authority_state_commit_receipt
            ),
            nonce_authority_verifier_challenge=(
                fixture.nonce_authority_verifier_challenge
            ),
            witness_verifier_challenge=
            fixture.witness_verifier_challenge,
            now=(
                fixture.live_session_proof["producedAtUnix"]
                if now is None
                else now
            ),
        )

    def test_public_v3_accepts_signed_production_assurance(
        self,
    ) -> None:
        fixture = self.public_v3_fixture()
        self.assertIs(
            fixture.nonce_authority_assurance[
                "productionEligible"
            ],
            True,
        )
        result = self.verify_public_fixture(fixture)
        self.assertIs(result["verificationOk"], True)
        self.assertIs(result["finalCompletionVerified"], True)
        self.assertTrue(fixture.body.endswith(b"\n"))
        self.assertFalse(fixture.body.endswith(b"\n\n"))
        self.assertEqual(
            fixture.body,
            verify_nitro_tee.canonical_json_bytes(
                fixture.document
            )
            + b"\n",
        )

    def test_producer_rejects_changed_tls_and_stale_request(
        self,
    ) -> None:
        fixture = self.public_v3_fixture()
        request = json.loads(fixture.producer_request.decode("ascii"))
        changed_tls = dict(
            request["liveSessionRequest"]["tlsBinding"]
        )
        changed_tls["exporterSha256"] = digest("changed-exporter")
        changed_tls["bindingSha256"] = verify_nitro_tee.sha256_json(
            {
                key: value
                for key, value in changed_tls.items()
                if key != "bindingSha256"
            }
        )
        changed_request = json.loads(json.dumps(request))
        changed_request["liveSessionRequest"]["tlsBinding"] = (
            changed_tls
        )
        changed_request["liveSessionRequest"]["tlsBindingSha256"] = (
            changed_tls["bindingSha256"]
        )
        with self.assertRaises(
            production_attestation_producer_issuer.ContractError
        ):
            self.validate_fixture_producer_request(
                fixture,
                changed_request,
            )

        stale_request = json.loads(json.dumps(request))
        stale_request["liveSessionRequest"]["issuedAtUnix"] = (
            stale_request["liveSessionRequest"]["expiresAtUnix"]
        )
        with self.assertRaises(
            production_attestation_producer_issuer.ContractError
        ):
            self.validate_fixture_producer_request(
                fixture,
                stale_request,
            )

    def test_delivery_rebind_is_signed_and_exactly_cross_bound(
        self,
    ) -> None:
        fixture = self.public_v3_fixture()
        self.assertIs(
            self.verify_public_fixture(fixture)["verificationOk"],
            True,
        )
        for label, path, replacement in (
            (
                "historical body",
                ("payload", "historicalResult", "evidenceBodySha256"),
                digest("crossed-historical-body"),
            ),
            (
                "recovery identity",
                ("payload", "recoveryIdentity", "requestBodySha256"),
                digest("crossed-recovery-request"),
            ),
            (
                "current exporter",
                ("payload", "currentTlsBinding", "exporterSha256"),
                digest("crossed-current-exporter"),
            ),
        ):
            crossed = copy.deepcopy(fixture.delivery_rebind)
            target = crossed
            for field in path[:-1]:
                target = target[field]
            target[path[-1]] = replacement
            payload = crossed["payload"]
            payload["historicalResultSha256"] = (
                verify_nitro_tee.sha256_json(
                    payload["historicalResult"]
                )
            )
            payload["recoveryIdentitySha256"] = (
                verify_nitro_tee.sha256_json(
                    payload["recoveryIdentity"]
                )
            )
            current_tls = payload["currentTlsBinding"]
            current_tls["bindingSha256"] = (
                verify_nitro_tee.sha256_json(
                    {
                        key: value
                        for key, value in current_tls.items()
                        if key != "bindingSha256"
                    }
                )
            )
            payload["currentTlsBindingSha256"] = current_tls[
                "bindingSha256"
            ]
            crossed["payloadSha256"] = (
                verify_nitro_tee.sha256_json(payload)
            )
            crossed_core = {
                key: value
                for key, value in crossed.items()
                if key != "signature"
            }
            crossed["signature"] = (
                "ed25519:"
                + attestation.b64e(
                    fixture.response_private_key.sign(
                        verify_nitro_tee.canonical_json_bytes(
                            crossed_core
                        )
                    )
                )
            )
            with self.subTest(label=label), self.assertRaises(
                verify_nitro_tee.VerificationError
            ):
                self.verify_public_fixture(
                    fixture,
                    delivery_rebind=crossed,
                )

    def test_verifier_state_v3_rejects_crossed_live_chain_fields(
        self,
    ) -> None:
        fixture = self.public_v3_fixture()
        request = json.loads(fixture.producer_request.decode("ascii"))
        cases = {
            "predecessor": (
                ("priorStateSha256",),
                digest("substituted-prior-state"),
            ),
            "successor": (
                ("committedStateSha256",),
                digest("substituted-committed-state"),
            ),
            "challenge": (
                ("verifierChallengeBase64url",),
                attestation.b64e(b"x" * 32),
            ),
            "operation": (
                ("operationIdBase64url",),
                attestation.b64e(b"y" * 32),
            ),
            "transaction": (
                ("transactionIdBase64url",),
                attestation.b64e(b"z" * 32),
            ),
            "consumption": (
                ("nonceConsumptionSha256",),
                digest("substituted-consumption"),
            ),
            "receipt": (
                ("nonceConsumptionReceiptSha256",),
                digest("substituted-receipt"),
            ),
            "assurance": (
                ("assuranceSha256",),
                digest("substituted-assurance"),
            ),
            "state signing key": (
                ("serviceBinding", "signingKeySpkiSha256"),
                digest("substituted-verifier-state-key"),
            ),
            "store identity": (
                ("serviceBinding", "stateStoreIdentitySha256"),
                digest("substituted-state-store"),
            ),
            "store administrative domain": (
                (
                    "serviceBinding",
                    "stateStoreAdministrativeDomainSha256",
                ),
                digest("substituted-state-store-admin"),
            ),
            "store assurance": (
                (
                    "serviceBinding",
                    "stateStoreAssuranceEvidenceSha256",
                ),
                digest("substituted-state-store-assurance"),
            ),
            "store attestation key": (
                (
                    "serviceBinding",
                    "stateStoreAttestationKeySpkiSha256",
                ),
                digest("substituted-state-store-key"),
            ),
            "store proof": (
                ("signedStoreCommitProofSha256",),
                digest("substituted-state-store-proof"),
            ),
            "commit request": (
                ("commitRequestSha256",),
                digest("substituted-commit-request"),
            ),
            "commit receipt": (
                ("commitReceiptSha256",),
                digest("substituted-commit-receipt"),
            ),
        }
        for label, (path, replacement) in cases.items():
            with self.subTest(label=label):
                changed = json.loads(json.dumps(request))
                target = changed["liveSessionRequest"][
                    "nonceAuthorityVerifierStateTransition"
                ]
                for field in path[:-1]:
                    target = target[field]
                target[path[-1]] = replacement
                with self.assertRaises(
                    production_attestation_producer_issuer.ContractError
                ):
                    self.validate_fixture_producer_request(
                        fixture,
                        changed,
                    )

        malformed = json.loads(json.dumps(request))
        malformed["liveSessionRequest"][
            "nonceAuthorityVerifierStateTransition"
        ]["commitReceipt"]["signatureBase64url"] = "AA"
        with self.assertRaises(
            production_attestation_producer_issuer.ContractError
        ):
            self.validate_fixture_producer_request(fixture, malformed)

        obsolete_projection = json.loads(json.dumps(request))
        obsolete_projection["liveSessionRequest"][
            "nonceAuthorityVerifierStateTransition"
        ]["commitRequest"]["nonceConsumptionSha256"] = digest(
            "obsolete-caller-projection"
        )
        with self.assertRaises(
            production_attestation_producer_issuer.ContractError
        ):
            self.validate_fixture_producer_request(
                fixture,
                obsolete_projection,
            )

        missing_complete_receipt = json.loads(json.dumps(request))
        del missing_complete_receipt["liveSessionRequest"][
            "nonceAuthorityVerifierStateTransition"
        ]["commitRequest"]["nonceConsumptionReceipt"]
        with self.assertRaises(
            production_attestation_producer_issuer.ContractError
        ):
            self.validate_fixture_producer_request(
                fixture,
                missing_complete_receipt,
            )

    def test_verifier_state_v3_rejects_stale_signed_authorization(
        self,
    ) -> None:
        fixture = self.public_v3_fixture()
        request = json.loads(fixture.producer_request.decode("ascii"))
        transition = request["liveSessionRequest"][
            "nonceAuthorityVerifierStateTransition"
        ]
        stale_payload = json.loads(
            json.dumps(transition["authorization"]["payload"])
        )
        stale_payload["issuedAtUnix"] = (
            transition["priorStateRead"]["challengeIssuedAtUnix"] - 1
        )
        stale_payload["expiresAtUnix"] = (
            transition["priorStateRead"]["challengeIssuedAtUnix"]
        )
        stale_authorization = (
            fixture.nonce_authority_verifier_state_boundary
            ._signed_envelope(
                api_version=(
                    production_attestation_producer_issuer
                    .NONCE_AUTHORITY_VERIFIER_STATE_AUTHORIZATION_VERSION
                ),
                domain=(
                    production_attestation_producer_issuer
                    .NONCE_AUTHORITY_VERIFIER_STATE_AUTHORIZATION_DOMAIN
                ),
                payload=stale_payload,
            )
        )
        transition["authorization"] = stale_authorization
        transition["authorizationSha256"] = (
            verify_nitro_tee.sha256_json(stale_authorization)
        )
        transition["commitRequest"]["authorization"] = stale_authorization
        transition["commitRequestSha256"] = verify_nitro_tee.sha256_json(
            transition["commitRequest"]
        )
        with self.assertRaises(
            production_attestation_producer_issuer.ContractError
        ):
            self.validate_fixture_producer_request(fixture, request)

    def test_verifier_state_v3_rejects_reads_before_signed_state(
        self,
    ) -> None:
        fixture = self.public_v3_fixture()
        for read_field, state_field, digest_field in (
            (
                "priorStateRead",
                "priorState",
                "priorStateReadSha256",
            ),
            (
                "committedStateRead",
                "committedState",
                "committedStateReadSha256",
            ),
        ):
            with self.subTest(read_field=read_field):
                request = json.loads(
                    fixture.producer_request.decode("ascii")
                )
                transition = request["liveSessionRequest"][
                    "nonceAuthorityVerifierStateTransition"
                ]
                signed_state = transition[state_field]
                read = transition[read_field]
                issued = signed_state["payload"]["committedAtUnix"] - 1
                read["challengeIssuedAtUnix"] = issued
                read["challengeExpiresAtUnix"] = issued + 30
                transition[digest_field] = (
                    verify_nitro_tee.sha256_json(read)
                )
                with self.assertRaises(
                    production_attestation_producer_issuer.ContractError
                ):
                    self.validate_fixture_producer_request(
                        fixture,
                        request,
                    )

    def test_verifier_state_v3_sends_exact_lookup_read_and_prepare(
        self,
    ) -> None:
        fixture = self.public_v3_fixture()
        document = json.loads(fixture.producer_request.decode("ascii"))[
            "liveSessionRequest"
        ]["nonceAuthorityVerifierStateTransition"]
        config = fixture.immutable_config
        service = config["nonceAuthorityVerifierStateService"]
        descriptor = SimpleNamespace(
            nonce_authority_assurance=config[
                "nonceAuthorityAssurance"
            ],
            nonce_authority_assurance_evidence=config[
                "nonceAuthorityAssuranceEvidence"
            ],
            nonce_authority_assurance_evidence_key_spki_sha256=(
                fixture.nonce_authority_assurance_evidence_key_id
            ),
            nonce_authority_assurance_evidence_signing_public_key_spki_der_base64url=(
                config[
                    "nonceAuthorityAssuranceEvidenceSigningPublicKeySpkiDerBase64url"
                ]
            ),
            nonce_authority_assurance_sha256=config[
                "nonceAuthorityAssuranceSha256"
            ],
            nonce_authority_verifier_state_key_spki_sha256=(
                fixture.nonce_authority_verifier_state_key_id
            ),
            nonce_authority_verifier_state_signing_public_key_spki_der_base64url=(
                config[
                    "nonceAuthorityVerifierStateSigningPublicKeySpkiDerBase64url"
                ]
            ),
            nonce_authority_verifier_state_store_administrative_domain_sha256=(
                config[
                    "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256"
                ]
            ),
            nonce_authority_verifier_state_store_assurance_evidence_sha256=(
                config[
                    "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"
                ]
            ),
            nonce_authority_verifier_state_store_attestation_key_spki_sha256=(
                document["serviceBinding"][
                    "stateStoreAttestationKeySpkiSha256"
                ]
            ),
            nonce_authority_verifier_state_store_configuration_sha256=(
                config[
                    "nonceAuthorityVerifierStateStoreConfigurationSha256"
                ]
            ),
            nonce_authority_verifier_state_store_identity_sha256=config[
                "nonceAuthorityVerifierStateStoreIdentitySha256"
            ],
            nonce_authority_verifier_state_store_minimum_commit_index=(
                config[
                    "nonceAuthorityVerifierStateStoreMinimumCommitIndex"
                ]
            ),
            nonce_authority_verifier_state_store_minimum_generation=(
                config[
                    "nonceAuthorityVerifierStateStoreMinimumGeneration"
                ]
            ),
            nonce_store_key_spki_sha256=fixture.nonce_store_key_id,
            immutable_config_sha256=(
                fixture.recovery_identity[
                    "immutableConfigSha256"
                ]
            ),
            release_identity_sha256=(
                fixture.recovery_identity[
                    "releaseIdentitySha256"
                ]
            ),
            verifier_state_service_prepare_path=service[
                "preparePath"
            ],
            verifier_state_service_read_path=service["readPath"],
            verifier_state_service_recovery_lookup_path=service[
                "recoveryLookupPath"
            ],
        )
        observed_requests: list[tuple[str, dict[str, object]]] = []
        recovery_identity = document["recoveryIdentity"]
        prepared_operation = document["preparedOperation"]
        prepare_request = prepared_operation["prepareRequest"]
        producer_invocation = json.loads(
            json.dumps(prepare_request["producerInvocation"])
        )
        producer_invocation_base = json.loads(
            json.dumps(producer_invocation)
        )
        producer_invocation_base.pop(
            "nonceAuthorityVerifierChallengeBase64url"
        )
        producer_invocation_base.pop(
            "nonceAuthorityVerifierStateOperationIdBase64url"
        )

        def verifier_state_post(
            **kwargs: object,
        ) -> dict[str, object]:
            path = str(kwargs["path"])
            request = json.loads(json.dumps(kwargs["request"]))
            observed_requests.append((path, request))
            if path == service["recoveryLookupPath"]:
                self.assertEqual(
                    request,
                    {
                        "apiVersion":
                        "serverware.attestationVerifierStateRecoveryLookupRequest/v1",
                        "recoveryIdentity": recovery_identity,
                        "recoveryIdentitySha256":
                        document["recoveryIdentitySha256"],
                        "recoveryKeySha256":
                        document["recoveryKeySha256"],
                    },
                )
                return {
                    "apiVersion":
                    "serverware.attestationVerifierStateRecoveryLookupResponse/v1",
                    "commitReceipt": None,
                    "nonActionable": True,
                    "nonceConsumptionReceipt": None,
                    "nonceRecoveryRequired": False,
                    "nonceStatusEvidence": None,
                    "preparedOperation": None,
                    "preparedOperationSha256": None,
                    "recoveryIdentity": recovery_identity,
                    "recoveryIdentitySha256":
                    document["recoveryIdentitySha256"],
                    "recoveryKeySha256":
                    document["recoveryKeySha256"],
                    "replacementForbidden": False,
                    "requestBindingSha256": None,
                    "status": "notFound",
                }
            if path == service["readPath"]:
                self.assertEqual(
                    request,
                    {
                        "apiVersion":
                        "serverware.nonceAuthorityVerifierStateReadRequest/v2",
                        "assuranceSha256":
                        config["nonceAuthorityAssuranceSha256"],
                    },
                )
                return document["priorStateRead"]
            if path == service["preparePath"]:
                self.assertEqual(request, prepare_request)
                return {
                    "apiVersion":
                    "serverware.attestationVerifierStatePrepareResponse/v3",
                    "nonActionable": True,
                    "preparedOperation": prepared_operation,
                    "preparedOperationSha256":
                    document["preparedOperationSha256"],
                    "recoveryKeySha256":
                    document["recoveryKeySha256"],
                    "replacementForbidden": True,
                    "status": "prepared",
                }
            raise AssertionError("unexpected verifier-state fixture path")

        with mock.patch.object(
            attestation,
            "_public_evidence_verifier_state_post",
            side_effect=verifier_state_post,
        ):
            transition = (
                attestation
                ._public_evidence_begin_verifier_state_transition(
                    descriptor=descriptor,
                    operation_id=attestation.b64d(
                        document["operationIdBase64url"]
                    ),
                    recovery_identity=recovery_identity,
                    caller_nonce_sha256=(
                        producer_invocation["callerNonceSha256"]
                    ),
                    request_body_sha256=(
                        producer_invocation["requestBodySha256"]
                    ),
                    tls_binding_sha256=(
                        producer_invocation["tlsBindingSha256"]
                    ),
                    producer_invocation_base=(
                        producer_invocation_base
                    ),
                    expires_at_unix=(
                        producer_invocation["expiresAtUnix"]
                    ),
                    deadline=attestation.time.monotonic() + 1.0,
                )
            )
        self.assertEqual(
            [path for path, _ in observed_requests],
            [
                service["recoveryLookupPath"],
                service["readPath"],
                service["preparePath"],
            ],
        )
        self.assertEqual(
            transition["authorization"]["document"],
            document["authorization"],
        )
        self.assertEqual(
            transition["preparedOperation"],
            prepared_operation,
        )

    def test_verifier_state_v3_recovers_exact_unknown_commit(
        self,
    ) -> None:
        fixture = self.public_v3_fixture()
        document = json.loads(fixture.producer_request.decode("ascii"))[
            "liveSessionRequest"
        ]["nonceAuthorityVerifierStateTransition"]
        authorization_document = document["authorization"]
        prior_state_document = document["priorState"]
        receipt_document = document["nonceConsumptionReceipt"]
        receipt_payload = receipt_document["payload"]
        config = fixture.immutable_config
        service = config["nonceAuthorityVerifierStateService"]
        transition = {
            "assuranceEvidence": document["assuranceEvidence"],
            "authorization": {
                "document": authorization_document,
                "envelopeSha256": document["authorizationSha256"],
                "payload": authorization_document["payload"],
            },
            "operationIdBase64url": document["operationIdBase64url"],
            "preparedOperation": document["preparedOperation"],
            "preparedOperationSha256":
            document["preparedOperationSha256"],
            "priorRead": document["priorStateRead"],
            "priorReadSha256": document["priorStateReadSha256"],
            "priorState": {
                "document": prior_state_document,
                "envelopeSha256": document["priorStateSha256"],
                "payload": prior_state_document["payload"],
            },
            "recoveryIdentity": document["recoveryIdentity"],
            "recoveryIdentitySha256":
            document["recoveryIdentitySha256"],
            "recoveryKeySha256": document["recoveryKeySha256"],
            "requestBindingSha256":
            document["requestBindingSha256"],
            "verifierChallengeBase64url":
            document["verifierChallengeBase64url"],
            "verifierChallengeSha256":
            document["verifierChallengeSha256"],
            "verifierStateKey":
            fixture.nonce_authority_verifier_state_public_key,
        }
        nonce_receipt = {
            "authorityState": receipt_payload["nonceAuthorityState"],
            "authorityStateSha256":
            receipt_payload["nonceAuthorityStateSha256"],
            "consumption": receipt_payload["nonceConsumption"],
            "consumptionSha256":
            receipt_payload["nonceConsumptionSha256"],
            "document": receipt_document,
            "payload": receipt_payload,
            "receiptSha256": document[
                "nonceConsumptionReceiptSha256"
            ],
        }
        prepared_operation = document["preparedOperation"]
        recovered_nonce_status = (
            attestation_nonce_service.signed_status_evidence_envelope(
                payload={
                    "apiVersion":
                    attestation_nonce_service.STATUS_EVIDENCE_VERSION,
                    "consumeRequestSha256":
                    prepared_operation[
                        "nonceConsumeRequestSha256"
                    ],
                    "evidenceIssuedAtUnix":
                    receipt_payload["consumedAtUnix"],
                    "neverConsumable": False,
                    "nonceAuthorityVerifierStateAuthorizationSha256":
                    prepared_operation["authorizationSha256"],
                    "nonceConsumptionReceiptSha256":
                    document["nonceConsumptionReceiptSha256"],
                    "nonceSha256":
                    prepared_operation["nonceConsumeRequest"][
                        "nonceSha256"
                    ],
                    "preparedOperationSha256":
                    document["preparedOperationSha256"],
                    "recoveryKeySha256":
                    document["recoveryKeySha256"],
                    "requestBindingSha256":
                    document["requestBindingSha256"],
                    "requestOperation": "recoverExact",
                    "status": "consumed",
                    "transactionIdBase64url":
                    document["operationIdBase64url"],
                },
                signer=fixture.nonce_store_signer,
            )
        )
        descriptor = SimpleNamespace(
            nonce_authority_assurance=config[
                "nonceAuthorityAssurance"
            ],
            nonce_authority_assurance_sha256=config[
                "nonceAuthorityAssuranceSha256"
            ],
            nonce_authority_verifier_state_key_spki_sha256=(
                fixture.nonce_authority_verifier_state_key_id
            ),
            nonce_authority_verifier_state_store_administrative_domain_sha256=(
                config[
                    "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256"
                ]
            ),
            nonce_authority_verifier_state_store_assurance_evidence_sha256=(
                config[
                    "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"
                ]
            ),
            nonce_authority_verifier_state_store_assurance_evidence=(
                config[
                    "nonceAuthorityVerifierStateStoreAssuranceEvidence"
                ]
            ),
            nonce_authority_verifier_state_store_attestation_key_spki_sha256=(
                document["serviceBinding"][
                    "stateStoreAttestationKeySpkiSha256"
                ]
            ),
            nonce_authority_verifier_state_store_attestation_public_key_spki_der_base64url=(
                config[
                    "nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url"
                ]
            ),
            nonce_authority_verifier_state_store_configuration_sha256=(
                config[
                    "nonceAuthorityVerifierStateStoreConfigurationSha256"
                ]
            ),
            nonce_authority_verifier_state_store_identity_sha256=config[
                "nonceAuthorityVerifierStateStoreIdentitySha256"
            ],
            nonce_authority_verifier_state_store_minimum_commit_index=(
                config[
                    "nonceAuthorityVerifierStateStoreMinimumCommitIndex"
                ]
            ),
            nonce_authority_verifier_state_store_minimum_generation=(
                config[
                    "nonceAuthorityVerifierStateStoreMinimumGeneration"
                ]
            ),
            nonce_authority_verifier_state_role_separation_evidence=(
                config[
                    "nonceAuthorityVerifierStateRoleSeparationEvidence"
                ]
            ),
            nonce_authority_verifier_state_role_separation_evidence_sha256=(
                verify_nitro_tee.sha256_json(
                    config[
                        "nonceAuthorityVerifierStateRoleSeparationEvidence"
                    ]
                )
            ),
            nonce_store_key_spki_sha256=fixture.nonce_store_key_id,
            nonce_store_signing_public_key_spki_der_base64url=config[
                "nonceStoreSigningPublicKeySpkiDerBase64url"
            ],
            verifier_state_service_authority=service[
                "endpoint"
            ].removeprefix("https://"),
            verifier_state_service_client_certificate_spki_sha256=service[
                "clientCertificateSpkiSha256"
            ],
            verifier_state_service_commit_path=service["commitPath"],
            verifier_state_service_configuration_sha256=service[
                "serviceConfigurationSha256"
            ],
            verifier_state_service_read_path=service["readPath"],
            verifier_state_service_recover_path=service["recoverPath"],
            verifier_state_service_server_leaf_spki_sha256=service[
                "serverLeafSpkiSha256"
            ],
        )
        observed_requests: list[tuple[str, dict[str, object]]] = []
        recovery_response_version = (
            "serverware.attestationVerifierStateRecoveryResponse/v3"
        )

        def verifier_state_post(
            **kwargs: object,
        ) -> dict[str, object]:
            path = str(kwargs["path"])
            request = json.loads(json.dumps(kwargs["request"]))
            observed_requests.append((path, request))
            if path == service["commitPath"]:
                self.assertEqual(request, document["commitRequest"])
                raise (
                    attestation
                    ._PublicEvidenceUnknownVerifierStateOutcome(
                        "fixture commit response was lost"
                    )
                )
            if path == service["recoverPath"]:
                self.assertEqual(
                    request,
                    {
                        "apiVersion":
                        "serverware.attestationVerifierStateRecoveryRequest/v3",
                        "recoveryIdentity":
                        document["recoveryIdentity"],
                        "recoveryIdentitySha256":
                        document["recoveryIdentitySha256"],
                        "recoveryKeySha256":
                        document["recoveryKeySha256"],
                    },
                )
                return {
                    "apiVersion": recovery_response_version,
                    "commitReceipt": document["commitReceipt"],
                    "commitRequestSha256":
                    document["commitRequestSha256"],
                    "nonActionable": True,
                    "nonceConsumptionReceipt":
                    document["nonceConsumptionReceipt"],
                    "nonceRecoveryRequired": False,
                    "nonceStatusEvidence": recovered_nonce_status,
                    "operationIdBase64url":
                    document["operationIdBase64url"],
                    "preparedOperation":
                    document["preparedOperation"],
                    "preparedOperationSha256":
                    document["preparedOperationSha256"],
                    "recoveryIdentity":
                    document["recoveryIdentity"],
                    "recoveryIdentitySha256":
                    document["recoveryIdentitySha256"],
                    "recoveryKeySha256":
                    document["recoveryKeySha256"],
                    "replacementForbidden": True,
                    "requestBindingSha256":
                    document["requestBindingSha256"],
                    "sameOperationOnly": True,
                    "status": "committed",
                }
            if path == service["readPath"]:
                return document["committedStateRead"]
            raise AssertionError("unexpected verifier-state fixture path")

        with mock.patch.object(
            attestation,
            "_public_evidence_verifier_state_post",
            side_effect=verifier_state_post,
        ):
            completed = (
                attestation
                ._public_evidence_commit_verifier_state_transition(
                    descriptor=descriptor,
                    transition=transition,
                    nonce_receipt=nonce_receipt,
                    deadline=attestation.time.monotonic() + 1.0,
                )
            )
        self.assertEqual(completed, document)
        self.assertEqual(
            [path for path, _ in observed_requests],
            [
                service["commitPath"],
                service["recoverPath"],
                service["readPath"],
            ],
        )
        self.assertEqual(
            observed_requests[1][1],
            {
                "apiVersion":
                "serverware.attestationVerifierStateRecoveryRequest/v3",
                "recoveryIdentity": document["recoveryIdentity"],
                "recoveryIdentitySha256":
                document["recoveryIdentitySha256"],
                "recoveryKeySha256":
                document["recoveryKeySha256"],
            },
        )
        for obsolete_response_version in (
            "serverware.attestationVerifierStateRecoveryResponse/v1",
            "serverware.attestationVerifierStateRecoveryResponse/v2",
            "serverware.nonceAuthorityVerifierStateRecoveryResponse/v1",
            "serverware.nonceAuthorityVerifierStateRecoveryResponse/v2",
        ):
            recovery_response_version = obsolete_response_version
            observed_requests.clear()
            with self.subTest(
                api_version=obsolete_response_version
            ), mock.patch.object(
                attestation,
                "_public_evidence_verifier_state_post",
                side_effect=verifier_state_post,
            ), self.assertRaises(attestation.AttestationContractError):
                (
                    attestation
                    ._public_evidence_commit_verifier_state_transition(
                        descriptor=descriptor,
                        transition=transition,
                        nonce_receipt=nonce_receipt,
                        deadline=attestation.time.monotonic() + 1.0,
                    )
                )

    def test_attestation_key_roles_are_pairwise_collision_cases(
        self,
    ) -> None:
        fixture = self.public_v3_fixture()
        roles = (
            "assuranceEvidence",
            "nonceReceipt",
            "release",
            "storeAttestation",
            "tlsScope",
            "verifierState",
            "witness",
            "witnessStore",
        )
        collisions = {
            (left, right)
            for index, left in enumerate(roles)
            for right in roles[index + 1:]
        }
        embedded_fields = {
            "assuranceEvidence":
            "nonceAuthorityAssuranceEvidenceSigningPublicKeySpkiDerBase64url",
            "nonceReceipt":
            "nonceStoreSigningPublicKeySpkiDerBase64url",
            "storeAttestation":
            "nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url",
            "tlsScope":
            "tlsScopeSigningPublicKeySpkiDerBase64url",
            "verifierState":
            "nonceAuthorityVerifierStateSigningPublicKeySpkiDerBase64url",
            "witnessStore":
            "witnessStoreSigningPublicKeySpkiDerBase64url",
        }
        release_identity_fields = {
            "release": "releaseKeySpkiSha256",
            "tlsScope": "tlsScopeSigningKeySpkiSha256",
            "witness": "witnessKeySpkiSha256",
        }
        pin_fields = {
            "nonceReceipt": "nonceStoreKeySpkiSha256",
            "witnessStore": "witnessStoreKeySpkiSha256",
        }
        for source_role, target_role in sorted(collisions):
            with self.subTest(
                source_role=source_role,
                target_role=target_role,
            ):
                config = json.loads(
                    json.dumps(fixture.immutable_config)
                )
                pins = dict(fixture.expected_attestation_pins)
                release_identity = json.loads(
                    json.dumps(fixture.release_identity)
                )
                source_der = fixture.key_role_spki_der[source_role]
                source_der_base64url = attestation.b64e(source_der)
                source_spki_sha256 = digest_bytes(source_der)
                embedded_field = embedded_fields.get(target_role)
                if embedded_field is not None:
                    config[embedded_field] = source_der_base64url
                release_identity_field = release_identity_fields.get(
                    target_role
                )
                if release_identity_field is not None:
                    release_identity["configuration"][
                        release_identity_field
                    ] = source_spki_sha256
                pin_field = pin_fields.get(target_role)
                if pin_field is not None:
                    pins[pin_field] = source_spki_sha256
                component_pins = (
                    production_attestation_producer_issuer
                    .component_pins_from_statement(pins)
                )
                release_identity["configuration"][
                    "publicAttestation"
                ] = component_pins
                config["producerPolicy"] = component_pins
                config["releaseIdentity"] = release_identity
                config["releaseIdentitySha256"] = (
                    production_attestation_producer_issuer.sha256_json(
                        release_identity
                    )
                )
                raw = canonical_line(config)
                pins["immutableConfigSha256"] = digest_bytes(raw)
                with self.assertRaises(
                    production_attestation_producer_issuer.ContractError
                ):
                    production_attestation_producer_issuer.validate_release_config(
                        raw,
                        pins=pins,
                        release_identity=release_identity,
                    )

    def test_signed_role_evidence_rejects_every_pairwise_collision(
        self,
    ) -> None:
        fixture = self.public_v3_fixture()
        config = fixture.immutable_config
        transition = json.loads(
            fixture.producer_request.decode("ascii")
        )["liveSessionRequest"][
            "nonceAuthorityVerifierStateTransition"
        ]
        now = fixture.live_session_proof["producedAtUnix"]
        store_attestation_key_id = transition["serviceBinding"][
            "stateStoreAttestationKeySpkiSha256"
        ]
        store_assurance = (
            production_attestation_producer_issuer
            .validate_verifier_state_store_assurance(
                config,
                store_attestation_key_id=store_attestation_key_id,
                now=now,
            )
        )
        role_names = (
            "nonceAuthority",
            "nonceAuthorityAssuranceEvidenceIssuer",
            "publicAttestationClientTls",
            "roleSeparationEvidenceIssuer",
            "storeAssuranceEvidenceIssuer",
            "verifierStateServiceListenerTls",
            "verifierStateSigner",
            "verifierStateSignerClientTls",
            "verifierStateStore",
            "verifierStateStoreClientTls",
        )
        collision_fields = (
            "administrativeDomainSha256",
            "credentialIdentitySha256",
            "endpointIdentitySha256",
            "keySpkiSha256",
            "roleIdentitySha256",
        )
        for index, left in enumerate(role_names):
            for right in role_names[index + 1:]:
                for field in collision_fields:
                    hostile_config = copy.deepcopy(config)
                    payload = copy.deepcopy(
                        hostile_config[
                            "nonceAuthorityVerifierStateRoleSeparationEvidence"
                        ]["payload"]
                    )
                    payload[right][field] = payload[left][field]
                    hostile_config[
                        "nonceAuthorityVerifierStateRoleSeparationEvidence"
                    ] = signed_service_envelope(
                        fixture.verifier_state_role_evidence_private_key,
                        api_version=(
                            production_attestation_producer_issuer
                            .SIGNED_VERIFIER_STATE_ROLE_SEPARATION_EVIDENCE_VERSION
                        ),
                        domain=(
                            production_attestation_producer_issuer
                            .VERIFIER_STATE_ROLE_SEPARATION_EVIDENCE_DOMAIN
                        ),
                        payload=payload,
                    )
                    with self.subTest(
                        left=left,
                        right=right,
                        field=field,
                    ), self.assertRaises(
                        production_attestation_producer_issuer.ContractError
                    ):
                        (
                            production_attestation_producer_issuer
                            .validate_verifier_state_role_separation(
                                hostile_config,
                                nonce_authority_assurance=(
                                    fixture
                                    .nonce_authority_assurance
                                ),
                                nonce_store_key_id=(
                                    fixture.nonce_store_key_id
                                ),
                                verifier_state_key_id=(
                                    fixture
                                    .nonce_authority_verifier_state_key_id
                                ),
                                store_attestation_key_id=(
                                    store_attestation_key_id
                                ),
                                store_assurance=store_assurance,
                                service=config[
                                    "nonceAuthorityVerifierStateService"
                                ],
                                now=now,
                            )
                        )
                    with self.subTest(
                        left=left,
                        right=right,
                        field=field,
                        validator="offline",
                    ), self.assertRaises(
                        verify_nitro_tee.VerificationError
                    ):
                        (
                            verify_nitro_tee
                            .verify_verifier_state_store_and_role_assurance(
                                hostile_config,
                                assurance=(
                                    fixture.nonce_authority_assurance
                                ),
                                nonce_store_key_id=(
                                    fixture.nonce_store_key_id
                                ),
                                verifier_state_key_id=(
                                    fixture
                                    .nonce_authority_verifier_state_key_id
                                ),
                                store_attestation_key_id=(
                                    store_attestation_key_id
                                ),
                                service=config[
                                    "nonceAuthorityVerifierStateService"
                                ],
                                now=now,
                            )
                        )

    def test_signed_assurance_freshness_has_exact_time_boundaries(
        self,
    ) -> None:
        fixture = self.public_v3_fixture()
        config = fixture.immutable_config
        transition = json.loads(
            fixture.producer_request.decode("ascii")
        )["liveSessionRequest"][
            "nonceAuthorityVerifierStateTransition"
        ]
        now = fixture.live_session_proof["producedAtUnix"]
        store_attestation_key_id = transition["serviceBinding"][
            "stateStoreAttestationKeySpkiSha256"
        ]
        valid_store_assurance = (
            production_attestation_producer_issuer
            .validate_verifier_state_store_assurance(
                config,
                store_attestation_key_id=store_attestation_key_id,
                now=now,
            )
        )
        freshness_windows = {
            "expired": (now - 10, now),
            "future": (now + 1, now + 10),
        }
        for name, (issued, expires) in freshness_windows.items():
            hostile_store_config = copy.deepcopy(config)
            store_payload = copy.deepcopy(
                hostile_store_config[
                    "nonceAuthorityVerifierStateStoreAssuranceEvidence"
                ]["payload"]
            )
            store_payload["evidenceIssuedAtUnix"] = issued
            store_payload["evidenceExpiresAtUnix"] = expires
            store_evidence = signed_service_envelope(
                fixture.verifier_state_store_assurance_private_key,
                api_version=(
                    production_attestation_producer_issuer
                    .SIGNED_VERIFIER_STATE_STORE_ASSURANCE_EVIDENCE_VERSION
                ),
                domain=(
                    production_attestation_producer_issuer
                    .VERIFIER_STATE_STORE_ASSURANCE_EVIDENCE_DOMAIN
                ),
                payload=store_payload,
            )
            hostile_store_config[
                "nonceAuthorityVerifierStateStoreAssuranceEvidence"
            ] = store_evidence
            hostile_store_config[
                "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"
            ] = verify_nitro_tee.sha256_json(store_evidence)
            with self.subTest(
                evidence="store",
                freshness=name,
            ), self.assertRaises(
                production_attestation_producer_issuer.ContractError
            ):
                (
                    production_attestation_producer_issuer
                    .validate_verifier_state_store_assurance(
                        hostile_store_config,
                        store_attestation_key_id=store_attestation_key_id,
                        now=now,
                    )
                )
            with self.subTest(
                evidence="store",
                freshness=name,
                validator="offline",
            ), self.assertRaises(verify_nitro_tee.VerificationError):
                (
                    verify_nitro_tee
                    .verify_verifier_state_store_and_role_assurance(
                        hostile_store_config,
                        assurance=fixture.nonce_authority_assurance,
                        nonce_store_key_id=fixture.nonce_store_key_id,
                        verifier_state_key_id=(
                            fixture
                            .nonce_authority_verifier_state_key_id
                        ),
                        store_attestation_key_id=(
                            store_attestation_key_id
                        ),
                        service=config[
                            "nonceAuthorityVerifierStateService"
                        ],
                        now=now,
                    )
                )

    def test_store_assurance_rejects_every_self_attested_dimension(
        self,
    ) -> None:
        fixture = self.public_v3_fixture()
        config = fixture.immutable_config
        transition = json.loads(
            fixture.producer_request.decode("ascii")
        )["liveSessionRequest"][
            "nonceAuthorityVerifierStateTransition"
        ]
        now = fixture.live_session_proof["producedAtUnix"]
        store_attestation_key_id = transition["serviceBinding"][
            "stateStoreAttestationKeySpkiSha256"
        ]
        dimensions = (
            (
                "administrative-domain",
                "issuerAdministrativeDomainSha256",
                "storeAdministrativeDomainSha256",
                "nonceAuthorityVerifierStateStoreAssuranceIssuerAdministrativeDomainSha256",
            ),
            (
                "credential-identity",
                "issuerCredentialIdentitySha256",
                "storeCredentialIdentitySha256",
                "nonceAuthorityVerifierStateStoreAssuranceIssuerCredentialIdentitySha256",
            ),
            (
                "role-identity",
                "issuerIdentitySha256",
                "storeIdentitySha256",
                "nonceAuthorityVerifierStateStoreAssuranceIssuerIdentitySha256",
            ),
        )
        for name, issuer_field, store_field, config_field in dimensions:
            hostile_config = copy.deepcopy(config)
            payload = copy.deepcopy(
                hostile_config[
                    "nonceAuthorityVerifierStateStoreAssuranceEvidence"
                ]["payload"]
            )
            payload[issuer_field] = payload[store_field]
            hostile_config[config_field] = payload[store_field]
            evidence = signed_service_envelope(
                fixture.verifier_state_store_assurance_private_key,
                api_version=(
                    production_attestation_producer_issuer
                    .SIGNED_VERIFIER_STATE_STORE_ASSURANCE_EVIDENCE_VERSION
                ),
                domain=(
                    production_attestation_producer_issuer
                    .VERIFIER_STATE_STORE_ASSURANCE_EVIDENCE_DOMAIN
                ),
                payload=payload,
            )
            hostile_config[
                "nonceAuthorityVerifierStateStoreAssuranceEvidence"
            ] = evidence
            hostile_config[
                "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"
            ] = verify_nitro_tee.sha256_json(evidence)
            with self.subTest(
                dimension=name,
                validator="producer",
            ), self.assertRaises(
                production_attestation_producer_issuer.ContractError
            ):
                (
                    production_attestation_producer_issuer
                    .validate_verifier_state_store_assurance(
                        hostile_config,
                        store_attestation_key_id=(
                            store_attestation_key_id
                        ),
                        now=now,
                    )
                )
            with self.subTest(
                dimension=name,
                validator="offline",
            ), self.assertRaises(verify_nitro_tee.VerificationError):
                (
                    verify_nitro_tee
                    .verify_verifier_state_store_and_role_assurance(
                        hostile_config,
                        assurance=fixture.nonce_authority_assurance,
                        nonce_store_key_id=fixture.nonce_store_key_id,
                        verifier_state_key_id=(
                            fixture
                            .nonce_authority_verifier_state_key_id
                        ),
                        store_attestation_key_id=(
                            store_attestation_key_id
                        ),
                        service=config[
                            "nonceAuthorityVerifierStateService"
                        ],
                        now=now,
                    )
                )

        hostile_key_config = copy.deepcopy(config)
        key_collision_evidence = signed_service_envelope(
            fixture.verifier_state_store_attestation_private_key,
            api_version=(
                production_attestation_producer_issuer
                .SIGNED_VERIFIER_STATE_STORE_ASSURANCE_EVIDENCE_VERSION
            ),
            domain=(
                production_attestation_producer_issuer
                .VERIFIER_STATE_STORE_ASSURANCE_EVIDENCE_DOMAIN
            ),
            payload=copy.deepcopy(
                hostile_key_config[
                    "nonceAuthorityVerifierStateStoreAssuranceEvidence"
                ]["payload"]
            ),
        )
        hostile_key_config[
            "nonceAuthorityVerifierStateStoreAssuranceEvidence"
        ] = key_collision_evidence
        hostile_key_config[
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"
        ] = verify_nitro_tee.sha256_json(key_collision_evidence)
        hostile_key_config[
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSigningPublicKeySpkiDerBase64url"
        ] = attestation.b64e(
            spki(fixture.verifier_state_store_attestation_private_key)
        )
        with self.subTest(
            dimension="signing-key",
            validator="producer",
        ), self.assertRaises(
            production_attestation_producer_issuer.ContractError
        ):
            (
                production_attestation_producer_issuer
                .validate_verifier_state_store_assurance(
                    hostile_key_config,
                    store_attestation_key_id=store_attestation_key_id,
                    now=now,
                )
            )
        with self.subTest(
            dimension="signing-key",
            validator="offline",
        ), self.assertRaises(verify_nitro_tee.VerificationError):
            (
                verify_nitro_tee
                .verify_verifier_state_store_and_role_assurance(
                    hostile_key_config,
                    assurance=fixture.nonce_authority_assurance,
                    nonce_store_key_id=fixture.nonce_store_key_id,
                    verifier_state_key_id=(
                        fixture.nonce_authority_verifier_state_key_id
                    ),
                    store_attestation_key_id=store_attestation_key_id,
                    service=config[
                        "nonceAuthorityVerifierStateService"
                    ],
                    now=now,
                )
            )

        valid_store_assurance = (
            production_attestation_producer_issuer
            .validate_verifier_state_store_assurance(
                config,
                store_attestation_key_id=store_attestation_key_id,
                now=now,
            )
        )
        for name, (issued, expires) in {
            "expired": (now - 10, now),
            "future": (now + 1, now + 10),
        }.items():
            hostile_role_config = copy.deepcopy(config)
            role_payload = copy.deepcopy(
                hostile_role_config[
                    "nonceAuthorityVerifierStateRoleSeparationEvidence"
                ]["payload"]
            )
            role_payload["evidenceIssuedAtUnix"] = issued
            role_payload["evidenceExpiresAtUnix"] = expires
            hostile_role_config[
                "nonceAuthorityVerifierStateRoleSeparationEvidence"
            ] = signed_service_envelope(
                fixture.verifier_state_role_evidence_private_key,
                api_version=(
                    production_attestation_producer_issuer
                    .SIGNED_VERIFIER_STATE_ROLE_SEPARATION_EVIDENCE_VERSION
                ),
                domain=(
                    production_attestation_producer_issuer
                    .VERIFIER_STATE_ROLE_SEPARATION_EVIDENCE_DOMAIN
                ),
                payload=role_payload,
            )
            with self.subTest(
                evidence="role",
                freshness=name,
            ), self.assertRaises(
                production_attestation_producer_issuer.ContractError
            ):
                (
                    production_attestation_producer_issuer
                    .validate_verifier_state_role_separation(
                        hostile_role_config,
                        nonce_authority_assurance=(
                            fixture.nonce_authority_assurance
                        ),
                        nonce_store_key_id=fixture.nonce_store_key_id,
                        verifier_state_key_id=(
                            fixture
                            .nonce_authority_verifier_state_key_id
                        ),
                        store_attestation_key_id=(
                            store_attestation_key_id
                        ),
                        store_assurance=valid_store_assurance,
                        service=config[
                            "nonceAuthorityVerifierStateService"
                        ],
                        now=now,
                    )
                )
            with self.subTest(
                evidence="role",
                freshness=name,
                validator="offline",
            ), self.assertRaises(verify_nitro_tee.VerificationError):
                (
                    verify_nitro_tee
                    .verify_verifier_state_store_and_role_assurance(
                        hostile_role_config,
                        assurance=fixture.nonce_authority_assurance,
                        nonce_store_key_id=fixture.nonce_store_key_id,
                        verifier_state_key_id=(
                            fixture
                            .nonce_authority_verifier_state_key_id
                        ),
                        store_attestation_key_id=(
                            store_attestation_key_id
                        ),
                        service=config[
                            "nonceAuthorityVerifierStateService"
                        ],
                        now=now,
                    )
                )

            nonce_payload = copy.deepcopy(
                fixture.nonce_authority_assurance_evidence["payload"]
            )
            nonce_payload["issuedAtUnix"] = issued
            nonce_payload["expiresAtUnix"] = expires
            nonce_evidence = signed_service_envelope(
                fixture.nonce_authority_assurance_evidence_private_key,
                api_version=(
                    production_attestation_producer_issuer
                    .SIGNED_NONCE_AUTHORITY_ASSURANCE_EVIDENCE_VERSION
                ),
                domain=(
                    production_attestation_producer_issuer
                    .NONCE_AUTHORITY_ASSURANCE_EVIDENCE_DOMAIN
                ),
                payload=nonce_payload,
            )
            nonce_assurance = copy.deepcopy(
                fixture.nonce_authority_assurance
            )
            nonce_assurance["assuranceEvidenceSha256"] = (
                verify_nitro_tee.sha256_json(nonce_evidence)
            )
            with self.subTest(
                evidence="nonce-authority",
                freshness=name,
            ), self.assertRaises(
                production_attestation_producer_issuer.ContractError
            ):
                (
                    production_attestation_producer_issuer
                    .validate_nonce_authority_assurance_evidence(
                        nonce_evidence,
                        key=(
                            fixture
                            .nonce_authority_assurance_evidence_public_key
                        ),
                        key_id=(
                            fixture
                            .nonce_authority_assurance_evidence_key_id
                        ),
                        assurance=nonce_assurance,
                        nonce_store_key_id=fixture.nonce_store_key_id,
                        verifier_state_key_id=(
                            fixture
                            .nonce_authority_verifier_state_key_id
                        ),
                        verifier_state_store_identity_sha256=config[
                            "nonceAuthorityVerifierStateStoreIdentitySha256"
                        ],
                        verifier_state_store_administrative_domain_sha256=config[
                            "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256"
                        ],
                        now=now,
                    )
                )
            with self.subTest(
                evidence="nonce-authority",
                freshness=name,
                validator="offline",
            ), self.assertRaises(verify_nitro_tee.VerificationError):
                (
                    verify_nitro_tee
                    .verify_nonce_authority_assurance_evidence(
                        nonce_evidence,
                        signing_key=(
                            fixture
                            .nonce_authority_assurance_evidence_public_key
                        ),
                        signing_key_id=(
                            fixture
                            .nonce_authority_assurance_evidence_key_id
                        ),
                        assurance=nonce_assurance,
                        nonce_authority_state_signing_key_id=(
                            fixture.nonce_store_key_id
                        ),
                        verifier_state_store_administrative_domain_sha256=config[
                            "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256"
                        ],
                        verifier_state_store_identity_sha256=config[
                            "nonceAuthorityVerifierStateStoreIdentitySha256"
                        ],
                        verifier_state_store_signing_key_id=(
                            fixture
                            .nonce_authority_verifier_state_key_id
                        ),
                        now=now,
                    )
                )


class DurableWitnessNonceServiceFixtures(unittest.TestCase):
    @staticmethod
    def witness_store_identity() -> dict[str, object]:
        return {
            "apiVersion":
            attestation_witness_service.STORE_IDENTITY_VERSION,
            "assurance": "nonProductionFixture",
            "deploymentId": "fixture-attestation-witness",
            "serviceId": "fixture-witness-store",
            "storageBackend": "fixture-sqlite",
        }

    @staticmethod
    def nonce_store_identity() -> dict[str, object]:
        return {
            "apiVersion":
            attestation_nonce_service.STORE_IDENTITY_VERSION,
            "assurance": "nonProductionFixture",
            "deploymentId": "fixture-attestation-nonce",
            "productionEligible": False,
            "referenceOnly": True,
            "serviceId": "fixture-nonce-store",
            "storageBackend": "fixture-sqlite",
        }

    @staticmethod
    def verify_fixture_envelope(
        envelope: dict[str, object],
        *,
        domain: bytes,
        public_key: object,
    ) -> None:
        payload = envelope["payload"]
        payload_sha256 = attestation_witness_service.sha256_json(
            payload
        )
        if envelope["payloadSha256"] != payload_sha256:
            raise AssertionError("fixture payload digest changed")
        message = attestation_witness_service.canonical_json_bytes(
            {
                "payload": payload,
                "payloadSha256": payload_sha256,
            }
        )
        signature = (
            attestation_witness_service.decode_base64url(
                envelope["signature"],
                expected_bytes=64,
                label="fixture envelope signature",
            )
        )
        public_key.verify(signature, domain + message)

    def test_signed_witness_state_survives_restart_and_advances_cas(
        self,
    ) -> None:
        witness_private_key = Ed25519PrivateKey.generate()
        store_private_key = Ed25519PrivateKey.generate()
        witness_signer = (
            attestation_witness_service.FixtureEd25519Signer(
                witness_private_key,
                non_production=True,
            )
        )
        store_signer = (
            attestation_witness_service.FixtureEd25519Signer(
                store_private_key,
                non_production=True,
            )
        )
        store_public_key_spki = attestation.b64e(
            store_private_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        identity = self.witness_store_identity()
        identity_sha256 = (
            attestation_witness_service.sha256_json(identity)
        )
        with tempfile.TemporaryDirectory() as directory:
            database_path = str(Path(directory) / "witness.sqlite3")
            store = attestation_witness_service.DurableWitnessStore(
                database_path=database_path,
                store_identity=identity,
                expected_store_identity_sha256=identity_sha256,
                expected_store_key_spki_sha256=store_signer.key_id,
                expected_store_signing_public_key_spki_der_base64url=(
                    store_public_key_spki
                ),
                witness_signer=witness_signer,
                store_signer=store_signer,
                allow_create=True,
                clock=lambda: 1_010,
            )
            first = store.advance(
                {
                    "apiVersion":
                    attestation_witness_service.ADVANCE_REQUEST_VERSION,
                    "eventSha256": digest("witness-event-1"),
                    "expectedPreviousRollbackContinuityCommitmentSha256":
                    None,
                    "generation": 7,
                    "idempotencyKeyBase64url":
                    attestation.b64e(b"i" * 32),
                    "releaseIdentitySha256": digest(
                        "fixture-release-identity"
                    ),
                    "rollbackEpoch": 3,
                    "treeSize": 1,
                }
            )
            store.close()

            protected = first["protectedLiveWitnessState"]
            self.assertEqual(
                protected["apiVersion"],
                "serverware.protectedLiveWitnessState/v2",
            )
            self.assertEqual(
                protected["payload"]["witnessStoreIdentitySha256"],
                identity_sha256,
            )
            self.assertEqual(
                protected["payload"]["witnessStoreKeySpkiSha256"],
                store_signer.key_id,
            )
            self.assertEqual(
                protected["signingKeyId"], store_signer.key_id
            )
            self.assertEqual(
                protected["payload"]["current"][
                    "liveWitnessHeadPayloadSha256"
                ],
                first["liveWitnessHead"]["payloadSha256"],
            )
            self.verify_fixture_envelope(
                protected,
                domain=(
                    attestation_witness_service.PROTECTED_STATE_DOMAIN
                ),
                public_key=store_private_key.public_key(),
            )
            self.verify_fixture_envelope(
                first["liveWitnessHead"],
                domain=attestation_witness_service.LIVE_WITNESS_DOMAIN,
                public_key=witness_private_key.public_key(),
            )

            restarted = (
                attestation_witness_service.DurableWitnessStore(
                    database_path=database_path,
                    store_identity=identity,
                    expected_store_identity_sha256=identity_sha256,
                    expected_store_key_spki_sha256=store_signer.key_id,
                    expected_store_signing_public_key_spki_der_base64url=(
                        store_public_key_spki
                    ),
                    witness_signer=witness_signer,
                    store_signer=store_signer,
                    allow_create=True,
                    clock=lambda: 1_011,
                )
            )
            first_continuity = first[
                "rollbackContinuityCommitmentSha256"
            ]
            current = restarted.current(
                {
                    "apiVersion":
                    attestation_witness_service.CURRENT_REQUEST_VERSION,
                    "expectedReleaseIdentitySha256": digest(
                        "fixture-release-identity"
                    ),
                    "expectedRollbackContinuityCommitmentSha256":
                    first_continuity,
                }
            )
            self.assertEqual(
                current["protectedLiveWitnessState"]["payload"][
                    "checkpointCasReceipt"
                ]["committedRollbackContinuityCommitmentSha256"],
                first_continuity,
            )
            second = restarted.advance(
                {
                    "apiVersion":
                    attestation_witness_service.ADVANCE_REQUEST_VERSION,
                    "eventSha256": digest("witness-event-2"),
                    "expectedPreviousRollbackContinuityCommitmentSha256":
                    first_continuity,
                    "generation": 7,
                    "idempotencyKeyBase64url":
                    attestation.b64e(b"j" * 32),
                    "releaseIdentitySha256": digest(
                        "fixture-release-identity"
                    ),
                    "rollbackEpoch": 3,
                    "treeSize": 2,
                }
            )
            restarted.close()
        second_payload = second["protectedLiveWitnessState"]["payload"]
        self.assertEqual(second_payload["current"]["sequence"], 2)
        self.assertEqual(second_payload["previous"]["sequence"], 1)
        self.assertEqual(
            second_payload["checkpointCasReceipt"][
                "previousRollbackContinuityCommitmentSha256"
            ],
            first_continuity,
        )
        self.assertNotEqual(
            second["rollbackContinuityCommitmentSha256"],
            first_continuity,
        )

    def test_nonce_one_use_is_emitted_only_after_durable_consumption(
        self,
    ) -> None:
        identity = self.nonce_store_identity()
        identity_sha256 = (
            attestation_nonce_service.sha256_json(identity)
        )
        nonce_private_key = Ed25519PrivateKey.generate()
        nonce_signer = FixtureNonceSignerBoundary(
            nonce_private_key,
            non_production=True,
        )
        nonce_sha256 = digest("fixture-caller-nonce")
        request_sha256 = digest("fixture-request-body")
        tls_sha256 = digest("fixture-tls-binding")
        authorization_sha256 = digest(
            "fixture-verifier-state-authorization"
        )
        bindings = {
            "nonceAuthorityVerifierStateAuthorizationSha256":
            authorization_sha256,
            "nonceSha256": nonce_sha256,
            "producerChannelChallengeBase64url":
            attestation.b64e(b"c" * 32),
            "producerEphemeralKeySha256":
            digest("fixture-producer-ephemeral-key"),
            "producerInvocationSha256":
            digest("fixture-producer-invocation"),
            "requestBodySha256": request_sha256,
            "tlsBindingSha256": tls_sha256,
        }
        with tempfile.TemporaryDirectory() as directory:
            database_path = str(Path(directory) / "nonce.sqlite3")
            store = attestation_nonce_service.DurableNonceStore(
                database_path=database_path,
                store_identity=identity,
                expected_store_identity_sha256=identity_sha256,
                allow_create=True,
                signer=nonce_signer,
                release_identity_sha256=
                digest("fixture-release-identity"),
                clock=lambda: 1_010,
            )
            reservation = store.reserve(
                {
                    "apiVersion":
                    attestation_nonce_service.RESERVE_REQUEST_VERSION,
                    "expiresAtUnix": 1_030,
                    **bindings,
                }
            )
            self.assertNotIn("oneUse", reservation)
            self.assertEqual(
                set(reservation),
                {
                    "apiVersion",
                    "expiresAtUnix",
                    "nonceAuthorityAssurance",
                    "nonceAuthorityAssuranceSha256",
                    "nonceSha256",
                    "producerChannelChallengeBase64url",
                    "producerInvocationSha256",
                    "reservationIdBase64url",
                    "reservedAtUnix",
                    "storeIdentitySha256",
                },
            )
            self.assertIs(
                reservation["nonceAuthorityAssurance"][
                    "productionEligible"
                ],
                False,
            )
            self.assertEqual(
                reservation["nonceAuthorityAssuranceSha256"],
                attestation_nonce_service.sha256_json(
                    reservation["nonceAuthorityAssurance"]
                ),
            )
            store.close()

            restarted = attestation_nonce_service.DurableNonceStore(
                database_path=database_path,
                store_identity=identity,
                expected_store_identity_sha256=identity_sha256,
                allow_create=True,
                signer=nonce_signer,
                release_identity_sha256=
                digest("fixture-release-identity"),
                clock=lambda: 1_011,
            )
            consumed = restarted.consume(
                {
                    "apiVersion":
                    attestation_nonce_service.CONSUME_REQUEST_VERSION,
                    "reservationIdBase64url":
                    reservation["reservationIdBase64url"],
                    **bindings,
                }
            )
            restarted.close()
            self.assertEqual(
                set(consumed),
                {
                    "apiVersion",
                    "nonceAuthorityAssurance",
                    "nonceAuthorityAssuranceSha256",
                    "nonceConsumption",
                    "nonceConsumptionReceipt",
                    "nonceConsumptionReceiptSha256",
                    "nonceConsumptionSha256",
                    "nonceStoreIdentitySha256",
                },
            )
            consumption = consumed["nonceConsumption"]
            self.assertEqual(
                set(consumption),
                {
                    "apiVersion",
                    "consumedAtUnix",
                    "nonceSha256",
                    "oneUse",
                    "requestBodySha256",
                    "sequence",
                    "storeIdentitySha256",
                    "tlsBindingSha256",
                },
            )
            self.assertIs(consumption["oneUse"], True)
            self.assertEqual(
                consumption["apiVersion"],
                "serverware.publicAttestationNonceConsumption/v1",
            )
            self.assertEqual(
                consumption["storeIdentitySha256"], identity_sha256
            )
            self.assertEqual(
                consumed["nonceConsumptionSha256"],
                attestation_nonce_service.sha256_json(consumption),
            )
            self.assertEqual(
                consumed["nonceAuthorityAssurance"],
                reservation["nonceAuthorityAssurance"],
            )
            receipt_payload = consumed[
                "nonceConsumptionReceipt"
            ]["payload"]
            authority_state = receipt_payload["nonceAuthorityState"]
            self.assertEqual(
                receipt_payload[
                    "nonceAuthorityVerifierStateAuthorizationSha256"
                ],
                authorization_sha256,
            )
            self.assertEqual(
                receipt_payload["nonceAuthorityAssuranceSha256"],
                reservation["nonceAuthorityAssuranceSha256"],
            )
            self.assertEqual(
                receipt_payload["nonceAuthorityStateSha256"],
                attestation_nonce_service.sha256_json(
                    authority_state
                ),
            )
            self.assertEqual(
                authority_state[
                    "previousHighWaterCommitmentSha256"
                ],
                attestation_nonce_service
                .nonce_authority_genesis_commitment(
                    reservation["nonceAuthorityAssuranceSha256"]
                ),
            )

            replay_store = attestation_nonce_service.DurableNonceStore(
                database_path=database_path,
                store_identity=identity,
                expected_store_identity_sha256=identity_sha256,
                allow_create=True,
                signer=nonce_signer,
                release_identity_sha256=
                digest("fixture-release-identity"),
                clock=lambda: 1_012,
            )
            with self.assertRaises(
                attestation_nonce_service.NonceServiceError
            ):
                replay_store.consume(
                    {
                        "apiVersion":
                        attestation_nonce_service.CONSUME_REQUEST_VERSION,
                        "reservationIdBase64url":
                        reservation["reservationIdBase64url"],
                        **bindings,
                    }
                )
            with self.assertRaises(
                attestation_nonce_service.NonceServiceError
            ):
                replay_store.consume_once(
                    {
                        "apiVersion": (
                            attestation_nonce_service.CONSUME_ONCE_REQUEST_VERSION
                        ),
                        "expiresAtUnix": 1_030,
                        "transactionIdBase64url":
                        attestation.b64e(b"t" * 32),
                        **bindings,
                    }
                )
            replay_store.close()

    def test_reference_nonce_lost_response_recovers_exact_receipt(
        self,
    ) -> None:
        identity = self.nonce_store_identity()
        identity_sha256 = attestation_nonce_service.sha256_json(identity)
        signer = FixtureNonceSignerBoundary(
            Ed25519PrivateKey.generate(),
            non_production=True,
        )
        request = {
            "apiVersion":
            attestation_nonce_service.CONSUME_ONCE_REQUEST_VERSION,
            "expiresAtUnix": 3_030,
            "nonceAuthorityVerifierStateAuthorizationSha256":
            digest("fixture-lost-response-authorization"),
            "nonceSha256": digest("fixture-lost-response-nonce"),
            "producerChannelChallengeBase64url":
            attestation.b64e(b"c" * 32),
            "producerEphemeralKeySha256":
            digest("fixture-lost-response-producer-key"),
            "producerInvocationSha256":
            digest("fixture-lost-response-invocation"),
            "requestBodySha256":
            digest("fixture-lost-response-request"),
            "tlsBindingSha256":
            digest("fixture-lost-response-tls"),
            "transactionIdBase64url": attestation.b64e(b"t" * 32),
        }
        with tempfile.TemporaryDirectory() as directory:
            database_path = str(Path(directory) / "nonce.sqlite3")
            store = attestation_nonce_service.DurableNonceStore(
                database_path=database_path,
                store_identity=identity,
                expected_store_identity_sha256=identity_sha256,
                allow_create=True,
                signer=signer,
                release_identity_sha256=
                digest("fixture-release-identity"),
                clock=lambda: 3_000,
            )
            first = store.consume_once(request)
            store.close()
            recovered_store = attestation_nonce_service.DurableNonceStore(
                database_path=database_path,
                store_identity=identity,
                expected_store_identity_sha256=identity_sha256,
                allow_create=True,
                signer=signer,
                release_identity_sha256=
                digest("fixture-release-identity"),
                clock=lambda: 3_001,
            )
            recovered = recovered_store.consume_once(
                copy.deepcopy(request)
            )
            self.assertEqual(recovered, first)
            with (
                mock.patch.object(
                    recovered_store,
                    "_validate_database",
                    return_value=None,
                ),
                mock.patch.object(
                    recovered_store,
                    "_read_metadata",
                    return_value={"sequenceExhausted": "true"},
                ),
            ):
                self.assertEqual(
                    recovered_store.consume_once(
                        copy.deepcopy(request)
                    ),
                    first,
                )
            self.assertEqual(
                recovered["nonceConsumptionReceipt"],
                first["nonceConsumptionReceipt"],
            )
            self.assertEqual(
                recovered["nonceConsumption"]["sequence"],
                1,
            )
            substitutions = {
                "same-transaction-different-request":
                {
                    **copy.deepcopy(request),
                    "requestBodySha256":
                    digest("substituted-lost-response-request"),
                },
                "same-request-different-transaction":
                {
                    **copy.deepcopy(request),
                    "transactionIdBase64url":
                    attestation.b64e(b"u" * 32),
                },
                "same-transaction-different-nonce":
                {
                    **copy.deepcopy(request),
                    "nonceSha256":
                    digest("substituted-lost-response-nonce"),
                },
            }
            for name, substituted in substitutions.items():
                with self.subTest(name=name), self.assertRaises(
                    attestation_nonce_service.NonceRequestError
                ):
                    recovered_store.consume_once(substituted)
            self.assertEqual(
                recovered_store.consume_once(copy.deepcopy(request)),
                first,
            )
            descriptor = SimpleNamespace(
                nonce_authority_assurance=first[
                    "nonceAuthorityAssurance"
                ],
                nonce_authority_assurance_sha256=first[
                    "nonceAuthorityAssuranceSha256"
                ],
                nonce_service_max_response_bytes=256 * 1024,
                nonce_service_request_fd=101,
                nonce_service_response_fd=102,
                nonce_store_identity_sha256=identity_sha256,
                nonce_store_key_spki_sha256=signer.key_id,
                nonce_store_signing_public_key_spki_der_base64url=(
                    attestation.b64e(signer._spki)
                ),
            )
            response_bytes = (
                attestation.canonical_json(first).encode("ascii")
                + b"\n"
            )
            channel_lock = mock.MagicMock()
            channel_lock.__enter__.return_value = None
            writes: list[bytes] = []

            def retain_exact_write(
                _fd: int,
                raw: bytes,
                **_values: object,
            ) -> None:
                writes.append(raw)

            with (
                mock.patch.object(
                    attestation,
                    "_public_evidence_nonce_channel_lock",
                    return_value=channel_lock,
                ),
                mock.patch.object(
                    attestation,
                    "_public_evidence_service_peer_pid",
                    return_value=((2001, 2002, 2003), 901),
                ),
                mock.patch.object(
                    attestation,
                    "_public_evidence_pidfd_exited",
                    return_value=False,
                ),
                mock.patch.object(
                    attestation,
                    "_challenge_public_evidence_service_channel",
                ) as challenge_channel,
                mock.patch.object(
                    attestation,
                    "_public_evidence_fd_write_line",
                    side_effect=retain_exact_write,
                ),
                mock.patch.object(
                    attestation,
                    "_public_evidence_fd_read_line",
                    side_effect=[
                        attestation
                        ._PublicEvidenceNonceChannelTransportError(
                            "fixture lost response"
                        ),
                        response_bytes,
                        response_bytes,
                    ],
                ),
                mock.patch.object(attestation.os, "close"),
            ):
                recovered_over_channel = (
                    attestation
                    ._public_evidence_nonce_consumption_response(
                        descriptor=descriptor,
                        consume_request=request,
                        deadline=attestation.time.monotonic() + 1.0,
                    )
                )
            self.assertEqual(recovered_over_channel, first)
            self.assertEqual(
                writes,
                [
                    attestation.canonical_json(request).encode("ascii")
                    + b"\n",
                    attestation.canonical_json(request).encode("ascii")
                    + b"\n",
                ],
            )
            self.assertEqual(challenge_channel.call_count, 3)
            self.assertEqual(
                challenge_channel.call_args.kwargs["role"],
                "nonceRequest",
            )
            recovered_store.close()

    def test_never_consumed_tombstone_survives_restart_and_rejects_consume(
        self,
    ) -> None:
        identity = self.nonce_store_identity()
        identity_sha256 = (
            attestation_nonce_service.sha256_json(identity)
        )
        private_key = Ed25519PrivateKey.generate()
        signer = FixtureNonceSignerBoundary(
            private_key,
            non_production=True,
        )
        consume_request = {
            "apiVersion":
            attestation_nonce_service.CONSUME_ONCE_REQUEST_VERSION,
            "expiresAtUnix": 4_030,
            "nonceAuthorityVerifierStateAuthorizationSha256":
            digest("tombstone-verifier-state-authorization"),
            "nonceSha256": digest("tombstone-nonce"),
            "producerChannelChallengeBase64url":
            attestation.b64e(b"c" * 32),
            "producerEphemeralKeySha256":
            digest("tombstone-producer-key"),
            "producerInvocationSha256":
            digest("tombstone-producer-invocation"),
            "requestBodySha256": digest("tombstone-request"),
            "tlsBindingSha256": digest("tombstone-tls"),
            "transactionIdBase64url": attestation.b64e(b"t" * 32),
        }
        status_request = {
            "apiVersion":
            attestation_nonce_service.STATUS_REQUEST_VERSION,
            "consumeRequest": consume_request,
            "preparedOperationSha256":
            digest("tombstone-prepared-operation"),
            "recoveryKeySha256": digest("tombstone-recovery-key"),
            "requestBindingSha256":
            digest("tombstone-request-binding"),
            "requestOperation": "proveNeverConsumedAndBlock",
        }
        with tempfile.TemporaryDirectory() as directory:
            database_path = str(Path(directory) / "nonce.sqlite3")
            store = attestation_nonce_service.DurableNonceStore(
                database_path=database_path,
                store_identity=identity,
                expected_store_identity_sha256=identity_sha256,
                allow_create=True,
                signer=signer,
                release_identity_sha256=
                digest("fixture-release-identity"),
                clock=lambda: 4_000,
            )
            blocked = store.transaction_status(status_request)
            self.assertEqual(blocked["status"], "neverConsumed")
            self.assertIs(
                blocked["nonceStatusEvidence"]["payload"][
                    "neverConsumable"
                ],
                True,
            )
            self.assertIsNone(blocked["nonceConsumptionReceipt"])
            status_envelope = blocked["nonceStatusEvidence"]
            status_payload_sha256 = (
                attestation_nonce_service.sha256_json(
                    status_envelope["payload"]
                )
            )
            self.assertEqual(
                status_envelope["payloadSha256"],
                status_payload_sha256,
            )
            private_key.public_key().verify(
                attestation.b64d(
                    status_envelope["signatureBase64url"]
                ),
                (
                    attestation_nonce_service
                    .NONCE_STATUS_EVIDENCE_DOMAIN
                    + attestation_nonce_service.canonical_json_bytes(
                        {
                            "payload": status_envelope["payload"],
                            "payloadSha256": status_payload_sha256,
                        }
                    )
                ),
            )
            store.close()

            restarted = attestation_nonce_service.DurableNonceStore(
                database_path=database_path,
                store_identity=identity,
                expected_store_identity_sha256=identity_sha256,
                allow_create=True,
                signer=signer,
                release_identity_sha256=
                digest("fixture-release-identity"),
                clock=lambda: 4_001,
            )
            recovered = restarted.transaction_status(status_request)
            self.assertEqual(recovered["status"], "neverConsumed")
            self.assertIs(
                recovered["nonceStatusEvidence"]["payload"][
                    "neverConsumable"
                ],
                True,
            )
            with self.assertRaises(
                attestation_nonce_service.NonceRequestError
            ) as rejected:
                restarted.consume_once(
                    copy.deepcopy(consume_request)
                )
            self.assertEqual(
                rejected.exception.error_code,
                "replayRejected",
            )
            restarted.close()

    def test_nonce_service_rejects_omitted_or_substituted_authorization(
        self,
    ) -> None:
        identity = self.nonce_store_identity()
        identity_sha256 = attestation_nonce_service.sha256_json(
            identity
        )
        signer = FixtureNonceSignerBoundary(
            Ed25519PrivateKey.generate(),
            non_production=True,
        )
        bindings = {
            "nonceAuthorityVerifierStateAuthorizationSha256":
            digest("fixture-current-head-authorization"),
            "nonceSha256": digest("fixture-authorized-nonce"),
            "producerChannelChallengeBase64url":
            attestation.b64e(b"h" * 32),
            "producerEphemeralKeySha256":
            digest("fixture-authorized-ephemeral-key"),
            "producerInvocationSha256":
            digest("fixture-authorized-invocation"),
            "requestBodySha256":
            digest("fixture-authorized-request"),
            "tlsBindingSha256": digest("fixture-authorized-tls"),
        }
        with tempfile.TemporaryDirectory() as directory:
            store = attestation_nonce_service.DurableNonceStore(
                database_path=str(
                    Path(directory) / "nonce.sqlite3"
                ),
                store_identity=identity,
                expected_store_identity_sha256=identity_sha256,
                allow_create=True,
                signer=signer,
                release_identity_sha256=
                digest("fixture-release-identity"),
                clock=lambda: 2_000,
            )
            omitted = {
                "apiVersion":
                attestation_nonce_service.RESERVE_REQUEST_VERSION,
                "expiresAtUnix": 2_020,
                **bindings,
            }
            omitted.pop(
                "nonceAuthorityVerifierStateAuthorizationSha256"
            )
            with self.assertRaises(
                attestation_nonce_service.NonceServiceError
            ):
                store.reserve(omitted)
            reservation = store.reserve(
                {
                    "apiVersion":
                    attestation_nonce_service.RESERVE_REQUEST_VERSION,
                    "expiresAtUnix": 2_020,
                    **bindings,
                }
            )
            substituted = {
                "apiVersion":
                attestation_nonce_service.CONSUME_REQUEST_VERSION,
                "reservationIdBase64url":
                reservation["reservationIdBase64url"],
                **bindings,
            }
            substituted[
                "nonceAuthorityVerifierStateAuthorizationSha256"
            ] = digest("substituted-current-head-authorization")
            with self.assertRaises(
                attestation_nonce_service.NonceServiceError
            ):
                store.consume(substituted)
            store.close()

    def test_service_contracts_reject_boolean_counters(self) -> None:
        with self.assertRaises(
            attestation_witness_service.WitnessServiceError
        ):
            attestation_witness_service.require_u64(
                True, "fixture counter"
            )


class ManifestSeparationTests(unittest.TestCase):
    def test_runtime_manifest_advertises_decision_bound_lease_contract(
        self,
    ) -> None:
        capability = attestation.runtime_manifest()[
            "credential_lease_capability"
        ]
        self.assertEqual(
            capability,
            {
                "apiVersion":
                "serverware.credentialLeaseCapability/v1",
                "controlledDispatch": {
                    "request":
                    "serverware.credentialLeaseRequest/v4",
                    "requestAuthority":
                    "serverware.credentialLeaseRequestAuthority/v1",
                    "envelope":
                    "serverware.credentialLeaseEnvelope/v3",
                    "set": "serverware.credentialLeaseSet/v4",
                    "releaseKinds": [
                        "atomicReservation",
                        "decisionBound",
                        "jitGrant",
                    ],
                    "decisionBound": True,
                },
                "uncontrolledDispatchCompatibility": {
                    "request":
                    "serverware.credentialLeaseRequest/v3",
                    "requestAuthority": None,
                    "envelope":
                    "serverware.credentialLeaseEnvelope/v2",
                    "set": "serverware.credentialLeaseSet/v3",
                    "releaseKinds": [],
                    "decisionBound": False,
                },
                "legacyCompatibilityScope":
                "uncontrolledDispatchOnly",
            },
        )

    def test_legacy_manifest_with_current_top_level_shape_is_rejected(self) -> None:
        manifest = {
            "apiVersion": "serverware.consolidatedTestArtifacts/v5",
            "candidate": {},
            "companions": {},
            "imageMappings": {},
            "images": {},
            "laneOrder": [],
            "lanes": {},
            "platform": {"architecture": "amd64", "os": "linux"},
            "promotion": {},
            "sourceSnapshot": {},
            "watchdog": {},
        }
        manifest["manifestSha256"] = digest_bytes(
            attestation.canonical_json(manifest).encode("ascii")
        )
        with self.assertRaises(attestation.AttestationContractError):
            attestation._validate_promoted_manifest(manifest)


def setup_expected(proxy_raw: bytes) -> HardwareVerificationExpected:
    return HardwareVerificationExpected(
        receipt_id="00000000-0000-0000-0000-000000000001",
        setup_session_id="00000000-0000-0000-0000-000000000002",
        assignment=SetupAssignment(
            principal_id="principal",
            route_id="route",
            credential_id="credential",
            credential_version=1,
            policy_hash=digest("policy"),
            route_policy_digest=digest("route-policy"),
        ),
        runtime_evidence_sha256=digest("runtime"),
        challenge=b"h" * 32,
        hardware_assurance_sha256=digest("hardware-assurance"),
        hardware_statement_sha256=digest("hardware-statement"),
        release_identity_sha256=digest("release-identity"),
        current_host_identity_sha256=digest("host-identity"),
        proxy_server_statement_sha256=sha256_digest(proxy_raw),
        trust_profile_sha256=digest("trust-profile"),
    )


def subproof_envelope(
    private_key: Ed25519PrivateKey,
    trust: Ed25519TrustRoot,
    domain: bytes,
    payload: dict[str, object],
) -> dict[str, object]:
    payload_sha256 = sha256_digest(canonical_json_bytes(payload))
    signed = domain + canonical_json_bytes(
        {"payload": payload, "payloadSha256": payload_sha256}
    )
    return {
        "apiVersion": setup_receipts.SETUP_SUBPROOF_ENVELOPE_API_VERSION,
        "payload": payload,
        "payloadSha256": payload_sha256,
        "signature": "ed25519:"
        + canonical_base64url(private_key.sign(signed)),
        "signingKeyId": trust.key_id,
    }


def setup_receipt_fixture(
    *,
    tamper_proxy_signature: bool = False,
    tamper_nitro_signature: bool = False,
    revoke_nitro_leaf: bool = False,
    stale_nitro_crl: bool = False,
):
    outer_private, outer_trust, _ = key_material()
    proxy_private, proxy_trust, proxy_spki = key_material()
    proxy_claims = {
        "leafSpkiSha256": digest("leaf"),
        "peerSpkiSha256": digest("peer"),
        "pipeline": attestation.PRODUCTION_PIPELINE,
        "releaseIdentitySha256": digest("release-identity"),
        "requestSha256": digest("request"),
        "responseSha256": digest("response"),
        "tlsExporterSha256": digest("exporter"),
    }
    proxy_raw = canonical_json_bytes(proxy_claims)
    expected = setup_expected(proxy_raw)
    user_data = canonical_json_bytes(
        {
            "apiVersion": "serverware.setupNitroUserData/v1",
            "currentHostIdentitySha256":
            expected.current_host_identity_sha256,
            "hardwareAssuranceSha256":
            expected.hardware_assurance_sha256,
            "hardwareStatementSha256":
            expected.hardware_statement_sha256,
            "pipeline": attestation.PRODUCTION_PIPELINE,
            "releaseIdentitySha256": expected.release_identity_sha256,
            "runtimeEvidenceSha256": expected.runtime_evidence_sha256,
            "setupSessionId": expected.setup_session_id,
        }
    )
    nitro_raw, pcrs, nitro_trust, module_id = strict_nitro_document(
        nonce=expected.challenge,
        user_data=user_data,
        tamper_signature=tamper_nitro_signature,
        revoke_leaf=revoke_nitro_leaf,
        stale_crl=stale_nitro_crl,
    )
    outer_trust = Ed25519TrustRoot(
        provider=outer_trust.provider,
        public_key_spki_der=outer_trust.public_key_spki_der,
        nitro_verification_trust=nitro_trust,
    )
    proxy_payload = {
        "apiVersion": setup_receipts.VERIFIED_PROXY_SUBPROOF_API_VERSION,
        "claims": proxy_claims,
        "rawEvidenceSha256": sha256_digest(proxy_raw),
    }
    proxy_envelope = subproof_envelope(
        proxy_private,
        proxy_trust,
        setup_receipts.PROXY_SUBPROOF_SIGNATURE_DOMAIN,
        proxy_payload,
    )
    if tamper_proxy_signature:
        proxy_envelope["signature"] = "ed25519:" + canonical_base64url(b"z" * 64)
    subproofs = {
        "hardware": {
            "apiVersion":
            setup_receipts.VERIFIED_HARDWARE_SUBPROOF_API_VERSION,
            "eifImageSha384": pcrs["PCR0"],
            "expectedModuleId": module_id,
            "nitroTrustBundleSha256": nitro_trust.bundle_sha256,
            "pcrs": pcrs,
            "rawEvidenceBase64url": canonical_base64url(nitro_raw),
            "rawEvidenceSha256": sha256_digest(nitro_raw),
            "userDataSha256": sha256_digest(user_data),
        },
        "proxy": {
            "apiVersion": setup_receipts.VERIFIED_PROXY_SUBPROOF_API_VERSION,
            "rawEvidenceBase64url": canonical_base64url(proxy_raw),
            "rawEvidenceSha256": sha256_digest(proxy_raw),
            "signedEnvelope": proxy_envelope,
            "trustRoot": {
                "keyId": proxy_trust.key_id,
                "provider": proxy_trust.provider,
                "publicKeySpkiDerBase64url": proxy_spki,
            },
        },
    }
    statement = {
        "assignment": expected.assignment.as_document(),
        "assignment_digest": expected.assignment.digest,
        "challenge": expected.challenge_base64url,
        "challenge_sha256": expected.challenge_sha256,
        "current_host_identity_sha256":
        expected.current_host_identity_sha256,
        "expires_at_unix": 1_100,
        "hardware_verifier_key_id": outer_trust.key_id,
        "hardware_verifier_provider": outer_trust.provider,
        "issued_at_unix": 1_000,
        "receipt_id": expected.receipt_id,
        "release_identity_sha256": expected.release_identity_sha256,
        "runtime_evidence_sha256": expected.runtime_evidence_sha256,
        "setup_session_id": expected.setup_session_id,
        "trust_profile_sha256": expected.trust_profile_sha256,
        "verified_subproofs": subproofs,
    }
    document = {
        "apiVersion":
        setup_receipts.HARDWARE_VERIFICATION_CLOSED_API_VERSION,
        "kind": "SetupHardwareVerification",
        "statement": statement,
        "signing_key_id": outer_trust.key_id,
        "signature": "ed25519:"
        + canonical_base64url(
            outer_private.sign(canonical_json_bytes(statement))
        ),
    }
    return (
        canonical_json_bytes(document),
        outer_trust,
        nitro_trust,
        proxy_trust,
        expected,
    )


class SetupReceiptTests(unittest.TestCase):
    def test_valid_v2_and_tampered_v2(self) -> None:
        raw, outer, _, proxy, expected = setup_receipt_fixture()
        with mock.patch.object(
            setup_receipts,
            "_configured_subproof_trust_root",
            return_value=proxy,
        ):
            verified = verify_setup_hardware_verification(
                raw,
                trust=outer,
                expected=expected,
                clock=FixedClock(1_010),
            )
        self.assertEqual(
            verified.decision,
            "verified-hardware-identity-no-custody-claim",
        )
        tampered, outer, _, proxy, expected = setup_receipt_fixture(
            tamper_proxy_signature=True
        )
        with (
            mock.patch.object(
                setup_receipts,
                "_configured_subproof_trust_root",
                return_value=proxy,
            ),
            self.assertRaises(ReceiptVerificationError),
        ):
            verify_setup_hardware_verification(
                tampered,
                trust=outer,
                expected=expected,
                clock=FixedClock(1_010),
            )

    def test_raw_nitro_signature_revocation_and_crl_are_authoritative(
        self,
    ) -> None:
        hostile_cases = (
            {"tamper_nitro_signature": True},
            {"revoke_nitro_leaf": True},
            {"stale_nitro_crl": True},
        )
        for case in hostile_cases:
            with self.subTest(case=case):
                raw, outer, _, proxy, expected = setup_receipt_fixture(
                    **case
                )
                with (
                    mock.patch.object(
                        setup_receipts,
                        "_configured_subproof_trust_root",
                        return_value=proxy,
                    ),
                    self.assertRaises(ReceiptVerificationError),
                ):
                    verify_setup_hardware_verification(
                        raw,
                        trust=outer,
                        expected=expected,
                        clock=FixedClock(1_010),
                    )

    def test_raw_nitro_exact_identity_and_freshness_bindings(self) -> None:
        nonce = b"n" * 32
        user_data = b"closed-setup-user-data"
        raw, pcrs, trust, module_id = strict_nitro_document(
            nonce=nonce, user_data=user_data
        )
        verified = attestation.verify_nitro_attestation_document(
            raw,
            trust=trust,
            expected_module_id=module_id,
            expected_nonce=nonce,
            expected_user_data=user_data,
            expected_pcrs=pcrs,
            expected_eif_sha384=pcrs["PCR0"],
            now_unix=1_010,
        )
        self.assertTrue(verified["hardwareIdentityVerified"])
        self.assertFalse(verified["keyCustodyVerified"])
        wrong_pcrs = dict(pcrs)
        wrong_pcrs["PCR1"] = sha384_bytes(b"\x44" * 48)
        hostile_inputs = (
            {"expected_module_id": "other-enclave"},
            {"expected_nonce": b"x" * 32},
            {"expected_user_data": b"other-user-data"},
            {"expected_pcrs": wrong_pcrs},
            {
                "expected_eif_sha384":
                sha384_bytes(b"\x55" * 48)
            },
            {"now_unix": 1_100},
        )
        baseline = {
            "trust": trust,
            "expected_module_id": module_id,
            "expected_nonce": nonce,
            "expected_user_data": user_data,
            "expected_pcrs": pcrs,
            "expected_eif_sha384": pcrs["PCR0"],
            "now_unix": 1_010,
        }
        for override in hostile_inputs:
            with (
                self.subTest(override=override),
                self.assertRaises(attestation.AttestationContractError),
            ):
                attestation.verify_nitro_attestation_document(
                    raw, **(baseline | override)
                )
        debug_raw, debug_pcrs, debug_trust, debug_module = (
            strict_nitro_document(
                nonce=nonce, user_data=user_data, debug=True
            )
        )
        with self.assertRaises(attestation.AttestationContractError):
            attestation.verify_nitro_attestation_document(
                debug_raw,
                trust=debug_trust,
                expected_module_id=debug_module,
                expected_nonce=nonce,
                expected_user_data=user_data,
                expected_pcrs=debug_pcrs,
                expected_eif_sha384=debug_pcrs["PCR0"],
                now_unix=1_010,
            )

    def test_signed_hardware_verdict_without_nitro_trust_fails_closed(
        self,
    ) -> None:
        raw, outer, _, proxy, expected = setup_receipt_fixture()
        unbound_outer = Ed25519TrustRoot(
            provider=outer.provider,
            public_key_spki_der=outer.public_key_spki_der,
        )
        with (
            mock.patch.object(
                setup_receipts,
                "_configured_subproof_trust_root",
                return_value=proxy,
            ),
            self.assertRaises(ReceiptVerificationError),
        ):
            verify_setup_hardware_verification(
                raw,
                trust=unbound_outer,
                expected=expected,
                clock=FixedClock(1_010),
            )

    def test_nitro_trust_bundle_requires_roots_and_crls(self) -> None:
        document = {
            "apiVersion": "serverware.setupNitroTrustBundle/v1",
            "awsNitroCrlsDerBase64url": [],
            "awsNitroRootCertificatesPem": [],
            "nitroCertificateProfile": {
                "allowedLeafExtendedKeyUsageOids": [],
                "expectedEifSha384": sha384_bytes(b"\x11" * 48),
                "expectedModuleId": "expected-enclave",
                "expectedPcrs": {
                    "PCR0": sha384_bytes(b"\x11" * 48),
                    "PCR1": sha384_bytes(b"\x22" * 48),
                    "PCR2": sha384_bytes(b"\x33" * 48),
                },
                "maxAttestationAgeSeconds": 60,
                "maxFutureSkewSeconds": 5,
            },
        }
        raw = (
            attestation.canonical_json(document).encode("ascii") + b"\n"
        )
        with self.assertRaises(attestation.AttestationContractError):
            attestation.load_nitro_verification_trust(
                raw, expected_sha256=sha256_digest(raw)
            )

    def test_legacy_correct_top_level_shape_is_rejected(self) -> None:
        private_key, trust, _ = key_material()
        proxy_raw = canonical_json_bytes(
            {
                "leafSpkiSha256": digest("leaf"),
                "peerSpkiSha256": digest("peer"),
                "pipeline": attestation.PRODUCTION_PIPELINE,
                "releaseIdentitySha256": digest("release-identity"),
                "requestSha256": digest("request"),
                "responseSha256": digest("response"),
                "tlsExporterSha256": digest("exporter"),
            }
        )
        expected = setup_expected(proxy_raw)
        statement = {"decision": "verified"}
        document = {
            "apiVersion": setup_receipts.HARDWARE_VERIFICATION_API_VERSION,
            "kind": "SetupHardwareVerification",
            "statement": statement,
            "signing_key_id": trust.key_id,
            "signature": "ed25519:"
            + canonical_base64url(
                private_key.sign(canonical_json_bytes(statement))
            ),
        }
        with self.assertRaises(ReceiptContractError):
            verify_setup_hardware_verification(
                canonical_json_bytes(document),
                trust=trust,
                expected=expected,
                clock=FixedClock(1_010),
            )

    def test_subproof_root_path_and_size_bounds(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "SERVERWARE_SETUP_HARDWARE_SUBPROOF_PROVIDER": "hardware",
                "SERVERWARE_SETUP_HARDWARE_SUBPROOF_KEY_ID": digest("key"),
                "SERVERWARE_SETUP_HARDWARE_SUBPROOF_PUBLIC_KEY_PATH":
                "../key.pem",
            },
            clear=False,
        ):
            with self.assertRaises(ReceiptVerificationError):
                setup_receipts._configured_subproof_trust_root("hardware")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "key.pem"
            path.write_bytes(b"x" * (16 * 1024 + 1))
            with mock.patch.dict(
                os.environ,
                {
                    "SERVERWARE_SETUP_PROXY_SUBPROOF_PROVIDER": "proxy",
                    "SERVERWARE_SETUP_PROXY_SUBPROOF_KEY_ID": digest("key"),
                    "SERVERWARE_SETUP_PROXY_SUBPROOF_PUBLIC_KEY_PATH":
                    str(path),
                },
                clear=False,
            ):
                with self.assertRaises(ReceiptVerificationError):
                    setup_receipts._configured_subproof_trust_root("proxy")


class SharedMonotonicFdDeadlineFixtures(unittest.TestCase):
    @staticmethod
    def _load_script(filename: str, module_name: str) -> Any:
        import importlib.util
        from pathlib import Path

        path = Path(__file__).resolve().with_name(filename)
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            raise AssertionError(f"cannot load {filename}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def _assert_nonce_read_deadlines(self, module: Any) -> None:
        import os
        import time

        for partial in (b"", b'{"apiVersion":'):
            read_fd, write_fd = os.pipe()
            try:
                if partial:
                    os.write(write_fd, partial)
                channel = module.BoundedCanonicalJsonLineFd(
                    read_fd,
                    max_bytes=module.MAX_FRAME_BYTES,
                )
                started = time.monotonic()
                deadline = started + 0.05
                with self.assertRaises(Exception):
                    channel.read(
                        label="fixture nonce partial read",
                        deadline=deadline,
                    )
                self.assertLess(time.monotonic() - started, 0.5)
            finally:
                os.close(read_fd)
                os.close(write_fd)

        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, b'{"ok":true}\n')
            deadline = time.monotonic() + 0.5
            result = module.BoundedCanonicalJsonLineFd(
                read_fd,
                max_bytes=module.MAX_FRAME_BYTES,
            ).read(
                label="fixture nonce complete read",
                deadline=deadline,
            )
            self.assertEqual(result, {"ok": True})
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def _assert_producer_read_deadlines(self, module: Any) -> None:
        import os
        import time

        for partial in (b"", b'{"apiVersion":'):
            read_fd, write_fd = os.pipe()
            try:
                if partial:
                    os.write(write_fd, partial)
                started = time.monotonic()
                deadline = started + 0.05
                with self.assertRaises(Exception):
                    module.read_json_line_fd(
                        read_fd,
                        maximum=module.MAX_PUBLIC_NITRO_SIGNING_BYTES,
                        timeout_ms=500,
                        label="fixture producer partial read",
                        deadline=deadline,
                    )
                self.assertLess(time.monotonic() - started, 0.5)
            finally:
                os.close(read_fd)
                os.close(write_fd)

        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, b'{"ok":true}\n')
            deadline = time.monotonic() + 0.5
            value, raw = module.read_json_line_fd(
                read_fd,
                maximum=module.MAX_PUBLIC_NITRO_SIGNING_BYTES,
                timeout_ms=500,
                label="fixture producer complete read",
                deadline=deadline,
            )
            self.assertEqual(value, {"ok": True})
            self.assertEqual(raw, b'{"ok":true}\n')
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def _assert_nonce_write_deadline(self, module: Any) -> None:
        import os
        import time

        read_fd, write_fd = os.pipe()
        try:
            started = time.monotonic()
            deadline = started + 0.05
            channel = module.BoundedCanonicalJsonLineFd(
                write_fd,
                max_bytes=module.MAX_FRAME_BYTES,
            )
            with self.assertRaises(Exception):
                channel.write(
                    {"body": "x" * (512 * 1024)},
                    label="fixture nonce nonreading peer",
                    deadline=deadline,
                )
            self.assertLess(time.monotonic() - started, 0.5)
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def _assert_producer_write_deadline(self, module: Any) -> None:
        import os
        import time

        read_fd, write_fd = os.pipe()
        try:
            started = time.monotonic()
            deadline = started + 0.05
            with self.assertRaises(Exception):
                module.write_json_line_fd(
                    write_fd,
                    {"body": "x" * (512 * 1024)},
                    maximum=module.MAX_PUBLIC_NITRO_SIGNING_BYTES,
                    timeout_ms=500,
                    label="fixture producer nonreading peer",
                    deadline=deadline,
                )
            self.assertLess(time.monotonic() - started, 0.5)
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_nonce_and_signer_channels_share_absolute_deadlines(self) -> None:
        nonce_module = self._load_script(
            "attestation_nonce_service.py",
            "deadline_fixture_nonce_service",
        )
        producer_module = self._load_script(
            "production_attestation_producer_issuer.py",
            "deadline_fixture_producer_issuer",
        )
        self._assert_nonce_read_deadlines(nonce_module)
        self._assert_nonce_write_deadline(nonce_module)
        self._assert_producer_read_deadlines(producer_module)
        self._assert_producer_write_deadline(producer_module)


class VerifierStateIngressDeadlineFixtures(unittest.TestCase):
    def test_one_absolute_deadline_reaches_store_and_signer(self) -> None:
        service = object.__new__(
            attestation_verifier_state_service.VerifierStateService
        )
        service._ingress_deadline = threading.local()
        deadline = time.monotonic() + 1.0
        service.bind_ingress_deadline(deadline)
        external_store = object.__new__(
            attestation_verifier_state_service
            .ExternalLinearizableStateStore
        )
        service.store = external_store
        with mock.patch.object(
            attestation_verifier_state_service
            .ExternalLinearizableStateStore,
            "read",
            autospec=True,
            return_value={"fixture": True},
        ) as read:
            self.assertEqual(
                service._store_call("read"),
                {"fixture": True},
            )
            self.assertEqual(
                read.call_args.kwargs["deadline"],
                deadline,
            )
        external_signer = object.__new__(
            attestation_verifier_state_service.ExternalEd25519Signer
        )
        service.signer = external_signer
        with mock.patch.object(
            attestation_verifier_state_service,
            "sign_envelope",
            return_value={"fixture": True},
        ) as sign:
            self.assertEqual(
                service._sign_envelope(
                    api_version="fixture/v1",
                    domain=b"fixture\x00",
                    payload={"value": True},
                ),
                {"fixture": True},
            )
            self.assertEqual(
                sign.call_args.kwargs["deadline"],
                deadline,
            )
        service.clear_ingress_deadline()

    def test_expired_deadline_starts_no_hop_and_preserves_ambiguity(
        self,
    ) -> None:
        service = object.__new__(
            attestation_verifier_state_service.VerifierStateService
        )
        service._ingress_deadline = threading.local()
        service._ingress_deadline.value = time.monotonic() - 1.0
        external_store = object.__new__(
            attestation_verifier_state_service
            .ExternalLinearizableStateStore
        )
        service.store = external_store
        with mock.patch.object(
            attestation_verifier_state_service
            .ExternalLinearizableStateStore,
            "prepare",
            autospec=True,
        ) as prepare:
            with self.assertRaises(
                attestation_verifier_state_service.ContractError
            ):
                service._store_call("prepare")
            prepare.assert_not_called()
            with self.assertRaises(
                attestation_verifier_state_service.UnknownOutcomeError
            ):
                service._store_call(
                    "prepare",
                    ambiguous_mutation=True,
                )
            prepare.assert_not_called()

    def test_outbound_slot_is_released_when_deadline_expires_after_admission(
        self,
    ) -> None:
        client = object.__new__(
            attestation_verifier_state_service.CanonicalHttpsClient
        )
        client._timeout = 10.0
        client._request_slots = threading.BoundedSemaphore(1)
        client._numeric_address = "127.0.0.1"
        client._port = 443
        client._context = mock.Mock()
        client._authority = "fixture.invalid"
        client._expected_server_certificate_spki_sha256 = digest(
            "fixture-server"
        )
        client._expected_server_spiffe_uri = None
        with mock.patch.object(
            attestation_verifier_state_service.time,
            "monotonic",
            side_effect=(0.0, 0.0, 2.0),
        ):
            with self.assertRaises(
                attestation_verifier_state_service.UnknownOutcomeError
            ):
                client.post(
                    "/v1/state",
                    {"fixture": True},
                    outcome_may_be_unknown=True,
                    deadline=1.0,
                )
        self.assertTrue(
            client._request_slots.acquire(blocking=False)
        )
        client._request_slots.release()

    def test_numeric_https_connection_never_calls_a_resolver(
        self,
    ) -> None:
        outbound_source = inspect.getsource(
            attestation_verifier_state_service
            .CanonicalHttpsClient.post
        )
        self.assertIn(
            "NumericAddressHttpsConnection(",
            outbound_source,
        )
        self.assertNotIn(
            "http.client.HTTPSConnection(",
            outbound_source,
        )
        events: list[tuple[str, object]] = []

        class FakeRawSocket:
            def fileno(self) -> int:
                return 101

            def settimeout(self, value: float) -> None:
                events.append(("raw-timeout", value))

            def connect(self, endpoint: tuple[str, int]) -> None:
                events.append(("connect", endpoint))

            def close(self) -> None:
                events.append(("raw-close", None))

        class FakeTlsSocket:
            def settimeout(self, value: float) -> None:
                events.append(("tls-timeout", value))

            def do_handshake(self) -> None:
                events.append(("handshake", None))

            def close(self) -> None:
                events.append(("tls-close", None))

        raw_socket = FakeRawSocket()
        tls_socket = FakeTlsSocket()
        context = mock.Mock()
        context.wrap_socket.return_value = tls_socket
        resolver_error = AssertionError(
            "numeric outbound path called a resolver"
        )
        with (
            mock.patch.object(
                attestation_verifier_state_service.socket,
                "socket",
                return_value=raw_socket,
            ),
            mock.patch.object(
                attestation_verifier_state_service.os,
                "set_inheritable",
            ),
            mock.patch.object(
                socket,
                "getaddrinfo",
                side_effect=resolver_error,
            ) as getaddrinfo,
            mock.patch.object(
                socket,
                "gethostbyname",
                side_effect=resolver_error,
            ) as gethostbyname,
            mock.patch.object(
                socket,
                "gethostbyname_ex",
                side_effect=resolver_error,
            ) as gethostbyname_ex,
            mock.patch.object(
                socket,
                "create_connection",
                side_effect=resolver_error,
            ) as create_connection,
        ):
            connection = (
                attestation_verifier_state_service
                .NumericAddressHttpsConnection(
                    numeric_address="127.0.0.1",
                    port=8443,
                    context=context,
                    remaining=lambda _phase: 1.0,
                )
            )
            connection.connect()
            connection.close()
        self.assertIn(("connect", ("127.0.0.1", 8443)), events)
        self.assertIn(("handshake", None), events)
        getaddrinfo.assert_not_called()
        gethostbyname.assert_not_called()
        gethostbyname_ex.assert_not_called()
        create_connection.assert_not_called()

    def test_outbound_adapter_rejects_non_numeric_authority(
        self,
    ) -> None:
        with self.assertRaises(
            attestation_verifier_state_service.ContractError
        ):
            attestation_verifier_state_service.CanonicalHttpsClient(
                endpoint="https://verifier-state.invalid:8443",
                ca_file="/fixture/ca.pem",
                client_certificate_file="/fixture/client.pem",
                client_key_file="/fixture/client.key",
                expected_server_certificate_spki_sha256=digest(
                    "fixture-server"
                ),
                expected_server_spiffe_uri=None,
                timeout_seconds=1.0,
            )


class PublicNitroRelayFdValidationFixtures(unittest.TestCase):
    @staticmethod
    def _args(
        *,
        request_fd: int,
        response_fd: int,
        signer_request_fd: int,
        signer_response_fd: int,
        signing_public_key_fd: int,
    ) -> argparse.Namespace:
        return argparse.Namespace(
            expected_signer_provider="fixture",
            expected_signer_server_tls_spki_sha256=digest(
                "fixture-signer-tls"
            ),
            expected_signing_key_id=digest("fixture-signing-key"),
            expected_signing_key_spki_sha256=digest(
                "fixture-signing-key"
            ),
            io_timeout_ms=50,
            request_fd=request_fd,
            response_fd=response_fd,
            signer_request_fd=signer_request_fd,
            signer_response_fd=signer_response_fd,
            signing_public_key_fd=signing_public_key_fd,
        )

    def test_active_relay_rejects_aliased_underlying_pipe(self) -> None:
        request_read, response_write = os.pipe()
        signer_request_read, signer_request_write = os.pipe()
        signer_response_read, signer_response_write = os.pipe()
        signing_key = tempfile.TemporaryFile()
        try:
            args = self._args(
                request_fd=request_read,
                response_fd=response_write,
                signer_request_fd=signer_request_write,
                signer_response_fd=signer_response_read,
                signing_public_key_fd=signing_key.fileno(),
            )
            with self.assertRaises(
                production_attestation_producer_issuer.ContractError
            ):
                production_attestation_producer_issuer.relay_public_nitro_result_signing(
                    args
                )
        finally:
            signing_key.close()
            for descriptor in (
                request_read,
                response_write,
                signer_request_read,
                signer_request_write,
                signer_response_read,
                signer_response_write,
            ):
                os.close(descriptor)

    def test_active_relay_rejects_type_direction_and_cloexec(self) -> None:
        pipe_pairs = [os.pipe() for _ in range(4)]
        descriptors = [
            descriptor
            for pair in pipe_pairs
            for descriptor in pair
        ]
        signing_key = tempfile.TemporaryFile()
        regular_read_fd = os.open(
            "/dev/null",
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            base = self._args(
                request_fd=pipe_pairs[0][0],
                response_fd=pipe_pairs[1][1],
                signer_request_fd=pipe_pairs[2][1],
                signer_response_fd=pipe_pairs[3][0],
                signing_public_key_fd=signing_key.fileno(),
            )
            hostile = [
                argparse.Namespace(
                    **{
                        **vars(base),
                        "request_fd": regular_read_fd,
                    }
                ),
                argparse.Namespace(
                    **{
                        **vars(base),
                        "request_fd": pipe_pairs[0][1],
                    }
                ),
            ]
            original_flags = fcntl.fcntl(
                pipe_pairs[0][0],
                fcntl.F_GETFD,
            )
            fcntl.fcntl(
                pipe_pairs[0][0],
                fcntl.F_SETFD,
                original_flags & ~fcntl.FD_CLOEXEC,
            )
            hostile.append(base)
            for args in hostile:
                with self.subTest(request_fd=args.request_fd):
                    with self.assertRaises(
                        production_attestation_producer_issuer
                        .ContractError
                    ):
                        production_attestation_producer_issuer.relay_public_nitro_result_signing(
                            args
                        )
        finally:
            os.close(regular_read_fd)
            signing_key.close()
            for descriptor in descriptors:
                os.close(descriptor)


if __name__ == "__main__":
    unittest.main()
