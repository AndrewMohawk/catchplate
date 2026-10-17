#!/usr/bin/env python3
from __future__ import annotations

import concurrent.futures
import datetime as dt
import hashlib
import http.client
import ipaddress
import json
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import launch_authority_relay as relay
import launch_authority_service as service
import launch_authorization as protocol


ROOT = Path(__file__).resolve().parents[1]
NOW = 1_800_000_000


def digest(character: str) -> str:
    return "sha256:" + character * 64


DEFAULT_RELAY_CERTIFICATE_SHA256 = digest("c")
WITNESS_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes([0x66]) * 32)
AUTHORITY_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes([0x67]) * 32)


def public_spki(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


WITNESS_KEY_ID = protocol.spki_key_id(public_spki(WITNESS_PRIVATE_KEY))
WITNESS_IDENTITY_SHA256 = digest("4")
WITNESS_ADMINISTRATIVE_DOMAIN_SHA256 = digest("5")
WITNESS_STORE_ASSURANCE_SHA256 = digest("8")
WITNESS_STORE_ASSURANCE_KEY_ID = digest("a")
WITNESS_TLS_SPKI_SHA256 = digest("b")


def named_digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("ascii")).hexdigest()


def global_role_registry() -> dict[str, Any]:
    return protocol.build_launch_global_role_registry(
        {
            "launchAuthority": protocol.spki_key_id(
                public_spki(AUTHORITY_PRIVATE_KEY)
            ),
            "launchAuthorityWitness": WITNESS_KEY_ID,
            "launchAuthorityWitnessStoreAssurance": (
                WITNESS_STORE_ASSURANCE_KEY_ID
            ),
            "launchAuthorityWitnessTls": WITNESS_TLS_SPKI_SHA256,
            "nonceAuthorityAssuranceEvidence": named_digest(
                "nonce-authority-assurance-evidence"
            ),
            "nonceAuthorityVerifierState": named_digest(
                "nonce-authority-verifier-state"
            ),
            "nonceAuthorityVerifierStateStoreAttestation": named_digest(
                "nonce-authority-verifier-state-store-attestation"
            ),
            "policyActivation": named_digest("policy-activation"),
            "policyIdentity": named_digest("policy-identity"),
            "reproducibleBuild": named_digest("reproducible-build"),
        }
    )


def binding(
    token: str,
    *,
    sequence: int,
    epoch: int,
    audience: str = "prod.us-east-1.primary",
    identity: str = digest("9"),
) -> dict[str, Any]:
    return {
        "deploymentAudience": audience,
        "deploymentIdentitySha256": identity,
        "releaseSequence": sequence,
        "rollbackEpoch": epoch,
        "manifestSha256": digest(token),
        "nonceRollbackAssuranceContractSha256": digest("6"),
        "nonceRollbackAssurancePinsSha256": digest("7"),
        "releaseProvenanceSha256": digest(token),
        "provenanceDigest": digest(token),
        "sourceTreeDigest": digest(token),
        "launcherSha256": digest(token),
        "reproducibleBuildVerificationSha256": digest(token),
        "authorizationScope": protocol.AUTHORIZATION_SCOPE,
        "freshnessAuthority": protocol.FRESHNESS_AUTHORITY,
        "launchAuthorityWitnessKeyId": WITNESS_KEY_ID,
        "launchAuthorityWitnessIdentitySha256": WITNESS_IDENTITY_SHA256,
        "launchAuthorityWitnessAdministrativeDomainSha256": (
            WITNESS_ADMINISTRATIVE_DOMAIN_SHA256
        ),
        "launchAuthorityWitnessStoreAssuranceSha256": (
            WITNESS_STORE_ASSURANCE_SHA256
        ),
    }


def registry_entry(
    token: str,
    *,
    sequence: int,
    epoch: int,
    enabled: bool = True,
    revoked: bool = False,
    relay_certificate_sha256: str = DEFAULT_RELAY_CERTIFICATE_SHA256,
) -> dict[str, Any]:
    return {
        **binding(token, sequence=sequence, epoch=epoch),
        "relayClientCertificateSha256": relay_certificate_sha256,
        "enabled": enabled,
        "revoked": revoked,
    }


def request_for(
    entry: dict[str, Any],
    *,
    nonce: str,
    boot: str = "8",
) -> dict[str, Any]:
    role_registry = global_role_registry()
    role_registry_sha256 = protocol.launch_global_role_registry_sha256(
        role_registry
    )
    recovery_binding = {
        "launcherNonce": nonce * 64,
        "bootIdSha256": digest(boot),
        "manifestSha256": entry["manifestSha256"],
        "globalRoleRegistrySha256": role_registry_sha256,
        "launchAuthorityWitnessChallenge": nonce * 64,
    }
    return {
        "apiVersion": protocol.REQUEST_API_VERSION,
        "kind": protocol.REQUEST_KIND,
        **recovery_binding,
        "globalRoleRegistry": role_registry,
        "globalRoleRegistryPinsSha256": named_digest(
            "global-role-registry-pins"
        ),
        "launchAttemptJournalDomain": protocol.LAUNCH_ATTEMPT_JOURNAL_DOMAIN,
        "launchAttemptRecoveryIdentitySha256": (
            protocol.launch_attempt_recovery_identity_sha256(recovery_binding)
        ),
        **{field: entry[field] for field in service._ENTRY_BINDING_FIELDS},
    }


def canonical_request(entry: dict[str, Any], *, nonce: str, boot: str = "8") -> bytes:
    return protocol.canonical_json_bytes(request_for(entry, nonce=nonce, boot=boot))


def write_bytes(path: Path, value: bytes, mode: int) -> Path:
    path.write_bytes(value)
    path.chmod(mode)
    return path


def issue_authorization(
    engine: service.LaunchAuthority,
    raw: bytes,
    *,
    now: int = NOW,
    peer_certificate_sha256: str = DEFAULT_RELAY_CERTIFICATE_SHA256,
    operation_context: service.AuthorityOperationContext | None = None,
) -> bytes:
    return engine.issue(
        raw,
        peer_certificate_sha256=peer_certificate_sha256,
        now_unix_seconds=now,
        operation_context=operation_context,
    )


class MonotonicWitnessFixture:
    def __init__(self) -> None:
        self.signing_public_key_spki_der = public_spki(WITNESS_PRIVATE_KEY)
        self.signing_key_id = WITNESS_KEY_ID
        self.witness_identity_sha256 = WITNESS_IDENTITY_SHA256
        self.administrative_domain_sha256 = (
            WITNESS_ADMINISTRATIVE_DOMAIN_SHA256
        )
        self.store_assurance_sha256 = WITNESS_STORE_ASSURANCE_SHA256
        self.store_assurance_key_id = WITNESS_STORE_ASSURANCE_KEY_ID
        self.expected_tls_spki_sha256 = WITNESS_TLS_SPKI_SHA256
        self.head: str | None = None
        self.checkpoint_sequence = 0
        self.operations: dict[str, tuple[bytes, dict[str, Any]]] = {}
        self.registry_generation: int | None = None
        self.registry_sha256: str | None = None
        self.registry_observations: dict[
            str, tuple[bytes, dict[str, Any]]
        ] = {}
        self.fail_after_commit_once = False
        self.fail_recovery = False

    def observe_registry_head(
        self,
        request: dict[str, Any],
        *,
        operation_context: service.AuthorityOperationContext,
    ) -> dict[str, Any]:
        operation_context.checkpoint("fixture registry observation")
        validated = protocol.validate_registry_observation_request(request)
        operation_id = (
            f"{validated['operationId']}:{validated['registryGeneration']}:"
            f"{validated['registrySha256']}"
        )
        request_bytes = protocol.canonical_json_bytes(validated)
        cached = self.registry_observations.get(operation_id)
        if cached is not None:
            if cached[0] != request_bytes:
                raise service.AuthorityConfigurationError(
                    "registry observation replay changed its exact request"
                )
            return deepcopy(cached[1])
        generation = validated["registryGeneration"]
        registry_sha256 = validated["registrySha256"]
        if (
            self.registry_generation is not None
            and generation < self.registry_generation
        ):
            raise service.AuthorityConfigurationError(
                "registry observation is below the external generation head"
            )
        if (
            self.registry_generation == generation
            and self.registry_sha256 != registry_sha256
        ):
            raise service.AuthorityConfigurationError(
                "registry observation conflicts at the external generation head"
            )
        operation_context.checkpoint("fixture registry observation mutation")
        self.checkpoint_sequence += 1
        statement = {
            field: validated[field]
            for field in validated
            if field not in {"apiVersion", "kind"}
        }
        statement.update(
            {
                "registryHeadObserved": True,
                "checkpointSequence": self.checkpoint_sequence,
            }
        )
        observation = {
            "apiVersion": protocol.REGISTRY_OBSERVATION_API_VERSION,
            "kind": protocol.REGISTRY_OBSERVATION_KIND,
            "statement": statement,
            "signature": protocol.canonical_base64url(
                WITNESS_PRIVATE_KEY.sign(
                    protocol.registry_observation_signing_bytes(statement)
                )
            ),
        }
        self.registry_generation = generation
        self.registry_sha256 = registry_sha256
        self.registry_observations[operation_id] = (
            request_bytes,
            deepcopy(observation),
        )
        return observation

    def authorize_transition(
        self,
        request: dict[str, Any],
        *,
        operation_context: service.AuthorityOperationContext,
    ) -> dict[str, Any]:
        operation_context.checkpoint("fixture witness transition")
        operation_id = request["operationId"]
        canonical_request_bytes = protocol.canonical_json_bytes(request)
        cached = self.operations.get(operation_id)
        if cached is not None:
            if cached[0] != canonical_request_bytes:
                raise service.AuthorityConfigurationError(
                    "witness operation replay changed its exact transition"
                )
            if cached[1]["statement"]["successorStateSha256"] != self.head:
                raise service.AuthorityConfigurationError(
                    "witness operation is no longer the external monotonic head"
                )
            return deepcopy(cached[1])
        if (
            self.head is not None
            and request["predecessorStateSha256"] != self.head
        ):
            raise service.AuthorityConfigurationError(
                "witness predecessor is not the external monotonic head"
            )
        operation_context.checkpoint("fixture witness transition mutation")
        self.checkpoint_sequence += 1
        statement = {
            field: request[field]
            for field in (
                "operation",
                "operationId",
                "authorizationId",
                "requestSha256",
                "challenge",
                "issuedAtUnixSeconds",
                "expiresAtUnixSeconds",
                "authorityKeyId",
                "witnessKeyId",
                "witnessIdentitySha256",
                "witnessAdministrativeDomainSha256",
                "storeAssuranceSha256",
                "registryGeneration",
                "registrySha256",
                "predecessorStateSha256",
                "successorStateSha256",
                "deploymentAudience",
                "deploymentIdentitySha256",
                "releaseSequence",
                "rollbackEpoch",
                "authorizationScope",
            )
        }
        statement.update(
            {
                "stateTransitionCommitted": True,
                "checkpointSequence": self.checkpoint_sequence,
            }
        )
        witness = {
            "apiVersion": protocol.WITNESS_API_VERSION,
            "kind": protocol.WITNESS_KIND,
            "statement": statement,
            "signature": protocol.canonical_base64url(
                WITNESS_PRIVATE_KEY.sign(
                    protocol.launch_authority_witness_signing_bytes(statement)
                )
            ),
        }
        self.operations[operation_id] = (
            canonical_request_bytes,
            deepcopy(witness),
        )
        self.head = request["successorStateSha256"]
        if self.fail_after_commit_once:
            self.fail_after_commit_once = False
            raise service.AuthorityConfigurationError(
                "injected lost witness response after durable commit"
            )
        return witness

    def recover_transition(
        self,
        request: dict[str, Any],
        *,
        operation_context: service.AuthorityOperationContext,
    ) -> dict[str, Any]:
        operation_context.checkpoint("fixture witness recovery")
        if self.fail_recovery:
            raise service.AuthorityConfigurationError(
                "injected witness recovery outage"
            )
        return self.authorize_transition(
            request,
            operation_context=operation_context,
        )


class TestPKI:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        self.ca_certificate = self._ca_certificate(self.ca_key, "Catchplate Test CA")
        self.server_key = ec.generate_private_key(ec.SECP256R1())
        self.server_certificate = self._leaf_certificate(
            self.server_key,
            common_name="localhost",
            extended_usage=ExtendedKeyUsageOID.SERVER_AUTH,
            san=x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]
            ),
        )
        self.client_key = ec.generate_private_key(ec.SECP256R1())
        self.client_certificate = self._leaf_certificate(
            self.client_key,
            common_name="catchplate-launch-relay",
            extended_usage=ExtendedKeyUsageOID.CLIENT_AUTH,
            san=None,
        )
        self.alternate_client_key = ec.generate_private_key(ec.SECP256R1())
        self.alternate_client_certificate = self._leaf_certificate(
            self.alternate_client_key,
            common_name="catchplate-other-launch-relay",
            extended_usage=ExtendedKeyUsageOID.CLIENT_AUTH,
            san=None,
        )
        self.other_ca_key = ec.generate_private_key(ec.SECP256R1())
        self.other_ca_certificate = self._ca_certificate(
            self.other_ca_key, "Untrusted Test CA"
        )

        self.ca_path = self._write_certificate("ca.pem", self.ca_certificate)
        self.server_certificate_path = self._write_certificate(
            "server.pem", self.server_certificate
        )
        self.server_key_path = self._write_key("server-key.pem", self.server_key)
        self.client_certificate_path = self._write_certificate(
            "client.pem", self.client_certificate
        )
        self.client_key_path = self._write_key("client-key.pem", self.client_key)
        self.alternate_client_certificate_path = self._write_certificate(
            "alternate-client.pem", self.alternate_client_certificate
        )
        self.alternate_client_key_path = self._write_key(
            "alternate-client-key.pem", self.alternate_client_key
        )
        self.other_ca_path = self._write_certificate(
            "other-ca.pem", self.other_ca_certificate
        )

    @staticmethod
    def _ca_certificate(
        key: ec.EllipticCurvePrivateKey, common_name: str
    ) -> x509.Certificate:
        now = dt.datetime.now(dt.timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        return (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + dt.timedelta(days=2))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
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
            .sign(key, hashes.SHA256())
        )

    def _leaf_certificate(
        self,
        key: ec.EllipticCurvePrivateKey,
        *,
        common_name: str,
        extended_usage: x509.ObjectIdentifier,
        san: x509.SubjectAlternativeName | None,
    ) -> x509.Certificate:
        now = dt.datetime.now(dt.timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
            )
            .issuer_name(self.ca_certificate.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(x509.ExtendedKeyUsage([extended_usage]), critical=False)
        )
        if san is not None:
            builder = builder.add_extension(san, critical=False)
        return builder.sign(self.ca_key, hashes.SHA256())

    def _write_certificate(self, name: str, certificate: x509.Certificate) -> Path:
        return write_bytes(
            self.root / name,
            certificate.public_bytes(serialization.Encoding.PEM),
            0o644,
        )

    def _write_key(self, name: str, key: ec.EllipticCurvePrivateKey) -> Path:
        return write_bytes(
            self.root / name,
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
            0o600,
        )

    @staticmethod
    def certificate_sha256(certificate: x509.Certificate) -> str:
        return service.der_certificate_sha256(
            certificate.public_bytes(serialization.Encoding.DER)
        )

    def client_context(
        self,
        *,
        include_certificate: bool = True,
        alternate_certificate: bool = False,
        ca_path: Path | None = None,
    ) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=str(ca_path or self.ca_path))
        if include_certificate:
            certificate_path = (
                self.alternate_client_certificate_path
                if alternate_certificate
                else self.client_certificate_path
            )
            key_path = (
                self.alternate_client_key_path
                if alternate_certificate
                else self.client_key_path
            )
            context.load_cert_chain(str(certificate_path), str(key_path))
        return context


class AuthorityFixture:
    def __init__(
        self,
        root: Path,
        *,
        relay_certificate_sha256: str = DEFAULT_RELAY_CERTIFICATE_SHA256,
    ) -> None:
        self.root = root
        self.monotonic_witness = MonotonicWitnessFixture()
        self.entries = [
            registry_entry(
                token,
                sequence=sequence,
                epoch=epoch,
                enabled=enabled,
                revoked=revoked,
                relay_certificate_sha256=relay_certificate_sha256,
            )
            for token, sequence, epoch, enabled, revoked in (
                ("a", 1, 0, True, False),
                ("b", 1, 0, True, False),
                ("b", 2, 0, True, False),
                ("a", 3, 0, True, False),
                ("a", 3, 1, True, False),
                ("c", 4, 0, True, False),
                ("c", 4, 1, True, False),
                ("c", 4, 2, True, False),
                ("d", 5, 1, True, False),
                ("b", 2, 2, True, False),
                ("e", 10, 1, False, False),
                ("f", 11, 1, True, True),
            )
        ]
        self.registry_document = {
            "apiVersion": service.REGISTRY_API_VERSION,
            "generation": 1,
            "kind": service.REGISTRY_KIND,
            "releases": self.entries,
        }
        self.registry_path = write_bytes(
            root / "release-registry.json",
            protocol.canonical_json_bytes(self.registry_document),
            0o600,
        )
        self.authority_private_key = AUTHORITY_PRIVATE_KEY
        self.authority_key_path = write_bytes(
            root / "launch-authority-key.pem",
            self.authority_private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
            0o600,
        )
        self.authority_spki = self.authority_private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.authority_key_id = protocol.spki_key_id(self.authority_spki)
        self.ledger_path = root / "launch-authority.sqlite3"
        service.LaunchAuthorityLedger(self.ledger_path, initialize=True)

    def engine(
        self,
        *,
        signing_key: service.AuthoritySigningKey | None = None,
        expected_global_role_registry_sha256: str | None = None,
        expected_global_role_registry_pins_sha256: str | None = None,
    ) -> service.LaunchAuthority:
        return service.LaunchAuthority(
            registry_path=self.registry_path,
            ledger=service.LaunchAuthorityLedger(self.ledger_path),
            signing_key=(
                signing_key
                or service.load_authority_signing_key(
                    self.authority_key_path,
                    expected_key_id=self.authority_key_id,
                )
            ),
            monotonic_witness=self.monotonic_witness,
            expected_global_role_registry_sha256=(
                expected_global_role_registry_sha256
                or protocol.launch_global_role_registry_sha256(
                    global_role_registry()
                )
            ),
            expected_global_role_registry_pins_sha256=(
                expected_global_role_registry_pins_sha256
                or named_digest("global-role-registry-pins")
            ),
        )

    def entry(
        self,
        token: str,
        *,
        sequence: int,
        epoch: int,
        enabled: bool | None = None,
        revoked: bool | None = None,
    ) -> dict[str, Any]:
        matches = [
            item
            for item in self.entries
            if item["manifestSha256"] == digest(token)
            and item["releaseSequence"] == sequence
            and item["rollbackEpoch"] == epoch
            and (enabled is None or item["enabled"] is enabled)
            and (revoked is None or item["revoked"] is revoked)
        ]
        if len(matches) != 1:
            raise AssertionError(
                f"entry lookup was ambiguous: {token} {sequence} {epoch}"
            )
        return matches[0]


class PhaseCancellingOperationContext(service.AuthorityOperationContext):
    def __init__(self, phase: str) -> None:
        super().__init__(time.monotonic() + 30.0)
        self.phase = phase
        self.triggered = False

    def checkpoint(self, phase: str) -> None:
        if phase == self.phase and not self.triggered:
            self.triggered = True
            self.cancel("deadline_expired")
        super().checkpoint(phase)


class RunningServer:
    def __init__(self, server: ThreadingHTTPServer) -> None:
        self.server = server
        self.thread = threading.Thread(
            target=server.serve_forever,
            name="launch-authority-test-server",
            daemon=True,
        )

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    def __enter__(self) -> RunningServer:
        self.thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise AssertionError("test HTTPS server did not stop")


def authority_server(
    engine: service.LaunchAuthority,
    pki: TestPKI,
    *,
    allowed_source_cidrs: tuple[str, ...] = ("127.0.0.1/32", "::1/128"),
    max_handshakes: int = service.DEFAULT_MAX_HANDSHAKES,
    max_handshakes_per_ip: int = service.DEFAULT_MAX_HANDSHAKES_PER_IP,
    max_issuance_workers: int = service.DEFAULT_MAX_ISSUANCE_WORKERS,
    max_issuance_workers_per_ip: int = (service.DEFAULT_MAX_ISSUANCE_WORKERS_PER_IP),
    handshake_deadline_seconds: float = service.DEFAULT_HANDSHAKE_DEADLINE_SECONDS,
    connection_deadline_seconds: float = service.DEFAULT_CONNECTION_DEADLINE_SECONDS,
) -> service.LaunchAuthorityHTTPServer:
    return service.create_https_server(
        ("127.0.0.1", 0),
        authority=engine,
        server_certificate=pki.server_certificate_path,
        server_private_key=pki.server_key_path,
        client_ca_certificate=pki.ca_path,
        allowed_source_cidrs=allowed_source_cidrs,
        max_handshakes=max_handshakes,
        max_handshakes_per_ip=max_handshakes_per_ip,
        max_issuance_workers=max_issuance_workers,
        max_issuance_workers_per_ip=max_issuance_workers_per_ip,
        handshake_deadline_seconds=handshake_deadline_seconds,
        connection_deadline_seconds=connection_deadline_seconds,
    )


def https_request(
    port: int,
    context: ssl.SSLContext,
    *,
    body: bytes,
    method: str = "POST",
    path: str = service.AUTHORIZATION_PATH,
    content_type: str = service.REQUEST_CONTENT_TYPE,
    timeout: float = 2.0,
) -> tuple[int, list[tuple[str, str]], bytes]:
    connection = http.client.HTTPSConnection(
        "localhost", port, context=context, timeout=timeout
    )
    try:
        connection.request(
            method,
            path,
            body=body,
            headers={"Content-Type": content_type, "Content-Length": str(len(body))},
        )
        response = connection.getresponse()
        response_body = response.read()
        return response.status, response.getheaders(), response_body
    finally:
        connection.close()


class ScriptedAuthorityServer:
    def __init__(
        self,
        pki: TestPKI,
        *,
        status: int = 200,
        content_type: str = relay.RESPONSE_CONTENT_TYPE,
        body: bytes,
        delay_seconds: float = 0.0,
        body_chunk_delay_seconds: float = 0.0,
        body_chunk_size: int = 16,
        include_length: bool = True,
    ) -> None:
        self.received: list[bytes] = []
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                fixture.received.append(self.rfile.read(length))
                if delay_seconds:
                    time.sleep(delay_seconds)
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                if include_length:
                    self.send_header("Content-Length", str(len(body)))
                if 300 <= status < 400:
                    self.send_header("Location", "https://elsewhere.invalid/")
                self.send_header("Connection", "close")
                self.end_headers()
                try:
                    if body_chunk_delay_seconds:
                        for offset in range(0, len(body), body_chunk_size):
                            self.wfile.write(body[offset : offset + body_chunk_size])
                            self.wfile.flush()
                            time.sleep(body_chunk_delay_seconds)
                    else:
                        self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, _format: str, *args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(
            str(pki.server_certificate_path), str(pki.server_key_path)
        )
        context.load_verify_locations(cafile=str(pki.ca_path))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        self.running = RunningServer(server)

    @property
    def port(self) -> int:
        return self.running.port

    def __enter__(self) -> ScriptedAuthorityServer:
        self.running.__enter__()
        return self

    def __exit__(self, *args: object) -> None:
        self.running.__exit__(*args)


def witness_http_response(
    body: bytes,
    *,
    content_type: str = "application/test-witness-response+json",
) -> bytes:
    return (
        b"HTTP/1.1 200 OK\r\n"
        + f"Content-Type: {content_type}\r\n".encode("ascii")
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"Connection: close\r\n"
        + b"\r\n"
        + body
    )


class ScriptedWitnessTlsPeer:
    def __init__(
        self,
        pki: TestPKI,
        *,
        response_chunks: tuple[bytes, ...],
        chunk_delay_seconds: float = 0.0,
        withhold_tls_close: bool = False,
        abrupt_tcp_close: bool = False,
    ) -> None:
        self.response_chunks = response_chunks
        self.chunk_delay_seconds = chunk_delay_seconds
        self.withhold_tls_close = withhold_tls_close
        self.abrupt_tcp_close = abrupt_tcp_close
        self.received_request = b""
        self.release = threading.Event()
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(2.0)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.context.maximum_version = ssl.TLSVersion.TLSv1_3
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.context.load_cert_chain(
            str(pki.server_certificate_path),
            str(pki.server_key_path),
        )
        self.context.load_verify_locations(cafile=str(pki.ca_path))
        self.thread = threading.Thread(
            target=self._serve,
            name="scripted-witness-tls-peer",
            daemon=True,
        )

    @property
    def port(self) -> int:
        return int(self.listener.getsockname()[1])

    @staticmethod
    def _receive_request(stream: ssl.SSLSocket) -> bytes:
        received = bytearray()
        header_end = -1
        while header_end < 0:
            chunk = stream.recv(4096)
            if not chunk:
                raise AssertionError("witness fixture received a truncated request")
            received.extend(chunk)
            if len(received) > 32 * 1024:
                raise AssertionError("witness fixture request headers are oversized")
            marker = received.find(b"\r\n\r\n")
            if marker >= 0:
                header_end = marker + 4
        raw_headers = bytes(received[:header_end])
        content_lengths = [
            line.split(b":", 1)[1].strip()
            for line in raw_headers[:-4].split(b"\r\n")[1:]
            if line.lower().startswith(b"content-length:")
        ]
        if len(content_lengths) != 1 or not content_lengths[0].isdigit():
            raise AssertionError(
                "witness fixture request has invalid Content-Length"
            )
        content_length = int(content_lengths[0])
        while len(received) - header_end < content_length:
            chunk = stream.recv(content_length - (len(received) - header_end))
            if not chunk:
                raise AssertionError("witness fixture request body is truncated")
            received.extend(chunk)
        if len(received) - header_end != content_length:
            raise AssertionError("witness fixture request has appended bytes")
        return bytes(received)

    def _serve(self) -> None:
        accepted: socket.socket | None = None
        stream: ssl.SSLSocket | None = None
        unwrapped: socket.socket | None = None
        try:
            accepted, _peer = self.listener.accept()
            accepted.settimeout(2.0)
            stream = self.context.wrap_socket(
                accepted,
                server_side=True,
            )
            accepted = None
            stream.settimeout(2.0)
            self.received_request = self._receive_request(stream)
            for chunk in self.response_chunks:
                stream.sendall(chunk)
                if self.chunk_delay_seconds:
                    if self.release.wait(self.chunk_delay_seconds):
                        return
            if self.abrupt_tcp_close:
                descriptor = stream.detach()
                stream = None
                socket.close(descriptor)
                return
            if self.withhold_tls_close:
                self.release.wait(2.0)
            stream.settimeout(0.5)
            try:
                unwrapped = stream.unwrap()
                stream = None
            except (OSError, ssl.SSLError):
                pass
        except (OSError, ssl.SSLError, AssertionError):
            pass
        finally:
            if stream is not None:
                stream.close()
            if unwrapped is not None:
                unwrapped.close()
            if accepted is not None:
                accepted.close()

    def __enter__(self) -> ScriptedWitnessTlsPeer:
        self.thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self.release.set()
        self.listener.close()
        self.thread.join(timeout=3)
        if self.thread.is_alive():
            raise AssertionError("scripted witness TLS peer did not stop")


class LaunchAuthorityEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.fixture = AuthorityFixture(self.root)
        self.engine = self.fixture.engine()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def assert_authority_error(self, code: str, raw: bytes) -> service.AuthorityError:
        with self.assertRaises(service.AuthorityError) as caught:
            issue_authorization(self.engine, raw)
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def test_registry_observation_preserves_dispatch_classification(self) -> None:
        entry = self.fixture.entry("a", sequence=1, epoch=0)
        for nonce, outcome_unknown, expected_code in (
            ("1", False, "REGISTRY_WITNESS_UNAVAILABLE"),
            ("2", True, "AUTHORITY_OPERATION_RECOVERY_PENDING"),
        ):
            with self.subTest(outcome_unknown=outcome_unknown):
                failure = service.AuthorityWitnessExchangeError(
                    "injected registry observation exchange failure",
                    phase="registry witness fixture",
                    outcome_unknown=outcome_unknown,
                )
                with (
                    mock.patch.object(
                        self.fixture.monotonic_witness,
                        "observe_registry_head",
                        side_effect=failure,
                    ),
                    self.assertRaises(service.AuthorityError) as caught,
                ):
                    issue_authorization(
                        self.engine,
                        canonical_request(entry, nonce=nonce),
                    )
                self.assertEqual(caught.exception.code, expected_code)

    def test_valid_issuance_is_signed_registry_bound_and_persisted(self) -> None:
        entry = self.fixture.entry("a", sequence=1, epoch=0)
        raw = canonical_request(entry, nonce="1")
        response = issue_authorization(self.engine, raw)
        request = protocol.require_canonical_json_bytes(raw)
        verified = protocol.verify_launch_authorization(
            response,
            authority_public_key_spki_der=self.fixture.authority_spki,
            expected_request_sha256=protocol.launch_authorization_request_sha256(
                request
            ),
            expected_authority_key_id=self.fixture.authority_key_id,
            now_unix_seconds=NOW + 1,
        )
        self.assertEqual(verified.issued_at_unix_seconds, NOW)
        self.assertEqual(verified.expires_at_unix_seconds, NOW + 30)
        verified_witness = protocol.verify_launch_authority_witness(
            verified.monotonic_witness,
            witness_public_key_spki_der=(
                self.fixture.monotonic_witness.signing_public_key_spki_der
            ),
            expected_witness_key_id=WITNESS_KEY_ID,
            expected_request=request,
            expected_authorization_id=verified.authorization_id,
            expected_authority_key_id=self.fixture.authority_key_id,
            expected_registry_generation=1,
        )
        self.assertGreaterEqual(
            verified_witness["statement"]["checkpointSequence"],
            2,
        )
        connection = self.engine.ledger.connect()
        try:
            durable = connection.execute(
                """
                SELECT nonce_rollback_assurance_contract_sha256,
                       nonce_rollback_assurance_pins_sha256
                FROM authorizations WHERE launcher_nonce = ?
                """,
                (request["launcherNonce"],),
            ).fetchone()
            high_water = connection.execute(
                """
                SELECT nonce_rollback_assurance_contract_sha256,
                       nonce_rollback_assurance_pins_sha256
                FROM deployment_high_water
                WHERE deployment_audience = ?
                  AND deployment_identity_sha256 = ?
                """,
                (
                    request["deploymentAudience"],
                    request["deploymentIdentitySha256"],
                ),
            ).fetchone()
            self.assertEqual(
                tuple(durable),
                (
                    request["nonceRollbackAssuranceContractSha256"],
                    request["nonceRollbackAssurancePinsSha256"],
                ),
            )
            self.assertEqual(tuple(high_water), tuple(durable))
        finally:
            connection.close()
        self.assertEqual(
            self.engine.ledger.counts(),
            {
                "authorizations": 1,
                "deployment_high_water": 1,
                "seen_release_tuples": 1,
                "registry_state": 1,
                "revoked_release_bindings": 1,
                "issuance_operations": 1,
            },
        )

    def test_identical_retry_is_byte_identical_and_nonce_collision_fails(self) -> None:
        entry = self.fixture.entry("a", sequence=1, epoch=0)
        raw = canonical_request(entry, nonce="2")
        first = issue_authorization(self.engine, raw)
        retry = issue_authorization(self.engine, raw, now=NOW + 1)
        self.assertEqual(first, retry)
        collision = canonical_request(entry, nonce="2", boot="7")
        self.assert_authority_error("NONCE_COLLISION", collision)
        self.assertEqual(self.engine.ledger.counts()["authorizations"], 1)

    def test_release_and_retry_are_bound_to_exact_relay_certificate(self) -> None:
        entry = self.fixture.entry("a", sequence=1, epoch=0)
        raw = canonical_request(entry, nonce="2")
        wrong_certificate = digest("d")
        with self.assertRaises(service.AuthorityError) as caught:
            issue_authorization(
                self.engine,
                raw,
                peer_certificate_sha256=wrong_certificate,
            )
        self.assertEqual(caught.exception.code, "RELAY_CLIENT_CERTIFICATE_MISMATCH")
        issued = issue_authorization(self.engine, raw)
        with self.assertRaises(service.AuthorityError) as caught:
            issue_authorization(
                self.engine,
                raw,
                now=NOW + 1,
                peer_certificate_sha256=wrong_certificate,
            )
        self.assertEqual(caught.exception.code, "RELAY_CLIENT_CERTIFICATE_MISMATCH")
        self.assertEqual(issue_authorization(self.engine, raw, now=NOW + 1), issued)

    def test_registry_generation_revocation_and_corruption_block_retry(self) -> None:
        entry = self.fixture.entry("a", sequence=1, epoch=0)
        first_raw = canonical_request(entry, nonce="3")
        issue_authorization(self.engine, first_raw)

        reused_generation = deepcopy(self.fixture.registry_document)
        reused_generation["releases"][0]["enabled"] = False
        write_bytes(
            self.fixture.registry_path,
            protocol.canonical_json_bytes(reused_generation),
            0o600,
        )
        with self.assertRaises(service.AuthorityError) as caught:
            issue_authorization(self.engine, first_raw)
        self.assertEqual(
            caught.exception.code, "TERMINAL_REGISTRY_WITNESS_UNAVAILABLE"
        )

        disabled = deepcopy(self.fixture.registry_document)
        disabled["generation"] = 2
        disabled["releases"][0]["enabled"] = False
        write_bytes(
            self.fixture.registry_path,
            protocol.canonical_json_bytes(disabled),
            0o600,
        )
        with self.assertRaises(service.AuthorityError) as caught:
            issue_authorization(self.engine, first_raw)
        self.assertEqual(caught.exception.code, "REGISTRY_CHANGED_DURING_ISSUANCE")
        self.assertEqual(self.engine.ledger.registry_generation(), 1)
        with self.assertRaises(service.AuthorityError) as disabled_new:
            issue_authorization(
                self.engine,
                canonical_request(disabled["releases"][0], nonce="4"),
            )
        self.assertEqual(disabled_new.exception.code, "RELEASE_DISABLED")

        write_bytes(
            self.fixture.registry_path,
            protocol.canonical_json_bytes(self.fixture.registry_document),
            0o600,
        )
        with self.assertRaises(service.AuthorityError) as caught:
            issue_authorization(self.engine, first_raw)
        self.assertEqual(
            caught.exception.code, "TERMINAL_REGISTRY_WITNESS_UNAVAILABLE"
        )

        revoked = deepcopy(self.fixture.registry_document)
        revoked["generation"] = 3
        revoked["releases"][0]["revoked"] = True
        write_bytes(
            self.fixture.registry_path,
            protocol.canonical_json_bytes(revoked),
            0o600,
        )
        with self.assertRaises(service.AuthorityError) as caught:
            issue_authorization(self.engine, first_raw)
        self.assertEqual(caught.exception.code, "REGISTRY_CHANGED_DURING_ISSUANCE")
        with self.assertRaises(service.AuthorityError) as revoked_new:
            issue_authorization(
                self.engine,
                canonical_request(revoked["releases"][0], nonce="5"),
            )
        self.assertEqual(revoked_new.exception.code, "RELEASE_REVOKED")
        self.assertEqual(self.engine.ledger.registry_generation(), 1)

        resurrected = deepcopy(self.fixture.registry_document)
        resurrected["generation"] = 4
        write_bytes(
            self.fixture.registry_path,
            protocol.canonical_json_bytes(resurrected),
            0o600,
        )
        with self.assertRaises(service.AuthorityError) as caught:
            issue_authorization(self.engine, first_raw)
        self.assertEqual(caught.exception.code, "REGISTRY_CHANGED_DURING_ISSUANCE")
        with self.assertRaises(service.AuthorityError) as resurrected_new:
            issue_authorization(
                self.engine,
                canonical_request(resurrected["releases"][0], nonce="6"),
            )
        self.assertEqual(
            resurrected_new.exception.code,
            "REGISTRY_REVOKED_BINDING_RESURRECTION",
        )
        self.assertEqual(self.engine.ledger.registry_generation(), 1)

        write_bytes(self.fixture.registry_path, b"{}", 0o600)
        with self.assertRaises(service.AuthorityError) as caught:
            issue_authorization(self.engine, first_raw)
        self.assertEqual(
            caught.exception.code, "TERMINAL_REGISTRY_WITNESS_UNAVAILABLE"
        )

    def test_cached_retry_fails_after_registry_nonce_assurance_change(self) -> None:
        entry = self.fixture.entry("a", sequence=1, epoch=0)
        raw = canonical_request(entry, nonce="9")
        issue_authorization(self.engine, raw)

        for generation, field, replacement in (
            (2, "nonceRollbackAssuranceContractSha256", digest("8")),
            (3, "nonceRollbackAssurancePinsSha256", digest("9")),
        ):
            changed = deepcopy(self.fixture.registry_document)
            changed["generation"] = generation
            changed["releases"][0][field] = replacement
            write_bytes(
                self.fixture.registry_path,
                protocol.canonical_json_bytes(changed),
                0o600,
            )
            with self.subTest(field=field), self.assertRaises(
                service.AuthorityError
            ) as caught:
                issue_authorization(self.engine, raw)
            self.assertEqual(caught.exception.code, "UNKNOWN_RELEASE")

    def test_disabled_binding_may_be_reenabled_by_higher_generation(self) -> None:
        entry = self.fixture.entry("a", sequence=1, epoch=0)
        raw = canonical_request(entry, nonce="4")
        original = issue_authorization(self.engine, raw)

        disabled = deepcopy(self.fixture.registry_document)
        disabled["generation"] = 2
        disabled["releases"][0]["enabled"] = False
        write_bytes(
            self.fixture.registry_path,
            protocol.canonical_json_bytes(disabled),
            0o600,
        )
        with self.assertRaises(service.AuthorityError) as caught:
            issue_authorization(self.engine, raw)
        self.assertEqual(caught.exception.code, "RELEASE_DISABLED")

        reenabled = deepcopy(self.fixture.registry_document)
        reenabled["generation"] = 3
        write_bytes(
            self.fixture.registry_path,
            protocol.canonical_json_bytes(reenabled),
            0o600,
        )
        with self.assertRaises(service.AuthorityError) as caught:
            issue_authorization(self.engine, raw)
        self.assertEqual(caught.exception.code, "REGISTRY_CHANGED_DURING_ISSUANCE")
        issue_authorization(
            self.engine,
            canonical_request(reenabled["releases"][0], nonce="5"),
        )

    def test_registry_reload_fails_closed_on_unstable_path(self) -> None:
        enrolled = self.fixture.entry("a", sequence=1, epoch=0)
        replacement = write_bytes(
            self.root / "replacement-registry.json",
            self.fixture.registry_path.read_bytes(),
            0o600,
        )
        self.fixture.registry_path.unlink()
        self.fixture.registry_path.symlink_to(replacement)
        with self.assertRaises(service.AuthorityError) as caught:
            issue_authorization(self.engine, canonical_request(enrolled, nonce="6"))
        self.assertEqual(caught.exception.code, "REGISTRY_UNAVAILABLE")

    def test_ledger_requires_one_time_initialization_and_missing_restart_fails(
        self,
    ) -> None:
        one_time_path = self.root / "one-time.sqlite3"
        with self.assertRaisesRegex(
            service.AuthorityConfigurationError, "initialize it explicitly"
        ):
            service.LaunchAuthorityLedger(one_time_path)
        self.assertEqual(service.main(["--initialize-ledger", str(one_time_path)]), 0)
        service.LaunchAuthorityLedger(one_time_path)
        self.assertEqual(service.main(["--initialize-ledger", str(one_time_path)]), 2)

        self.fixture.ledger_path.unlink()
        with self.assertRaisesRegex(
            service.AuthorityConfigurationError, "initialize it explicitly"
        ):
            self.fixture.engine()

    def test_ledger_initialization_failure_is_atomic_and_normalized(self) -> None:
        failed_path = self.root / "failed-initialization.sqlite3"
        with (
            mock.patch.object(
                service.LaunchAuthorityLedger,
                "_create_schema",
                side_effect=sqlite3.OperationalError("injected schema failure"),
            ),
            self.assertRaisesRegex(
                service.AuthorityConfigurationError, "setup failed closed"
            ),
        ):
            service.LaunchAuthorityLedger(failed_path, initialize=True)
        self.assertFalse(failed_path.exists())
        self.assertFalse(Path(str(failed_path) + "-wal").exists())
        self.assertFalse(Path(str(failed_path) + "-shm").exists())

        initialized_path = self.root / "atomic-initialization.sqlite3"
        ledger = service.LaunchAuthorityLedger(initialized_path, initialize=True)
        self.assertEqual(ledger.counts()["registry_state"], 0)
        connection = ledger.connect()
        try:
            self.assertEqual(
                connection.execute("PRAGMA user_version").fetchone()[0],
                service.LEDGER_SCHEMA_VERSION,
            )
            self.assertFalse(connection.in_transaction)
        finally:
            connection.close()

    def test_cancellation_before_preparation_commit_leaves_no_local_mutation(
        self,
    ) -> None:
        raw = canonical_request(
            self.fixture.entry("a", sequence=1, epoch=0),
            nonce="2",
        )
        operation_context = PhaseCancellingOperationContext(
            "durable issuance operation insert"
        )
        with self.assertRaises(service.AuthorityError) as caught:
            issue_authorization(
                self.engine,
                raw,
                operation_context=operation_context,
            )
        self.assertEqual(
            caught.exception.code,
            "AUTHORITY_OPERATION_DEADLINE_EXPIRED",
        )
        self.assertTrue(operation_context.triggered)
        self.assertEqual(self.engine.ledger.counts()["issuance_operations"], 0)
        self.assertEqual(self.engine.ledger.counts()["authorizations"], 0)

    def test_cancellation_before_signing_preserves_prepared_exact_recovery(
        self,
    ) -> None:
        raw = canonical_request(
            self.fixture.entry("a", sequence=1, epoch=0),
            nonce="3",
        )
        operation_context = PhaseCancellingOperationContext(
            "authority signature generation"
        )
        with self.assertRaises(service.AuthorityError) as caught:
            issue_authorization(
                self.engine,
                raw,
                operation_context=operation_context,
            )
        self.assertEqual(
            caught.exception.code,
            "AUTHORITY_OPERATION_DEADLINE_EXPIRED",
        )
        connection = self.engine.ledger.connect()
        try:
            state = connection.execute(
                "SELECT state FROM issuance_operations"
            ).fetchone()["state"]
            self.assertEqual(state, "prepared")
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM authorizations"
                ).fetchone()[0],
                0,
            )
        finally:
            connection.close()

        recovered = issue_authorization(self.engine, raw, now=NOW + 1)
        protocol.validate_launch_authorization(
            protocol.require_canonical_json_bytes(recovered)
        )

    def test_cancellation_before_terminalization_recovers_finalized_operation(
        self,
    ) -> None:
        raw = canonical_request(
            self.fixture.entry("a", sequence=1, epoch=0),
            nonce="4",
        )
        operation_context = PhaseCancellingOperationContext(
            "authority terminalization"
        )
        with self.assertRaises(service.AuthorityError) as caught:
            issue_authorization(
                self.engine,
                raw,
                operation_context=operation_context,
            )
        self.assertEqual(
            caught.exception.code,
            "AUTHORITY_OPERATION_DEADLINE_EXPIRED",
        )
        connection = self.engine.ledger.connect()
        try:
            state = connection.execute(
                "SELECT state FROM issuance_operations"
            ).fetchone()["state"]
            self.assertEqual(state, "finalized")
        finally:
            connection.close()

        recovered = issue_authorization(self.engine, raw, now=NOW + 1)
        connection = self.engine.ledger.connect()
        try:
            state = connection.execute(
                "SELECT state FROM issuance_operations"
            ).fetchone()["state"]
            self.assertEqual(state, "terminal")
        finally:
            connection.close()
        protocol.validate_launch_authorization(
            protocol.require_canonical_json_bytes(recovered)
        )

    def test_cancellation_racing_final_commit_is_recovery_pending(
        self,
    ) -> None:
        raw = canonical_request(
            self.fixture.entry("a", sequence=1, epoch=0),
            nonce="5",
        )
        operation_context = PhaseCancellingOperationContext(
            "authority finalization post-commit"
        )
        with self.assertRaises(service.AuthorityError) as caught:
            issue_authorization(
                self.engine,
                raw,
                operation_context=operation_context,
            )
        self.assertEqual(
            caught.exception.code,
            "AUTHORITY_COMMIT_OUTCOME_UNKNOWN",
        )
        connection = self.engine.ledger.connect()
        try:
            state = connection.execute(
                "SELECT state FROM issuance_operations"
            ).fetchone()["state"]
            self.assertEqual(state, "finalized")
        finally:
            connection.close()

        recovered = issue_authorization(self.engine, raw, now=NOW + 1)
        protocol.validate_launch_authorization(
            protocol.require_canonical_json_bytes(recovered)
        )

    def test_blocked_witness_stops_at_deadline_without_in_worker_recovery(
        self,
    ) -> None:
        raw = canonical_request(
            self.fixture.entry("a", sequence=1, epoch=0),
            nonce="6",
        )
        operation_context = service.AuthorityOperationContext(
            time.monotonic() + 30.0
        )
        entered = threading.Event()

        def blocked_witness(
            _request: dict[str, Any],
            *,
            operation_context: service.AuthorityOperationContext,
        ) -> dict[str, Any]:
            entered.set()
            while not operation_context.cancelled:
                time.sleep(0.001)
            operation_context.assert_active(
                "blocked witness",
                outcome_unknown=True,
            )
            raise AssertionError("cancelled witness call returned")

        cancel = threading.Timer(
            0.02,
            lambda: operation_context.cancel("deadline_expired"),
        )
        cancel.start()
        try:
            with (
                mock.patch.object(
                    self.fixture.monotonic_witness,
                    "authorize_transition",
                    side_effect=blocked_witness,
                ),
                self.assertRaises(service.AuthorityError) as caught,
            ):
                issue_authorization(
                    self.engine,
                    raw,
                    operation_context=operation_context,
                )
        finally:
            cancel.cancel()
            cancel.join()
        self.assertTrue(entered.is_set())
        self.assertEqual(
            caught.exception.code,
            "MONOTONIC_WITNESS_RECOVERY_PENDING",
        )
        connection = self.engine.ledger.connect()
        try:
            state = connection.execute(
                "SELECT state FROM issuance_operations"
            ).fetchone()["state"]
            self.assertEqual(state, "prepared")
        finally:
            connection.close()

        recovered = issue_authorization(self.engine, raw, now=NOW + 1)
        protocol.validate_launch_authorization(
            protocol.require_canonical_json_bytes(recovered)
        )

    def test_later_freshness_decisions_resample_wall_time(self) -> None:
        raw = canonical_request(
            self.fixture.entry("a", sequence=1, epoch=0),
            nonce="7",
        )
        original_authorize = self.fixture.monotonic_witness.authorize_transition

        def advance_registry_after_witness(
            request: dict[str, Any],
            *,
            operation_context: service.AuthorityOperationContext,
        ) -> dict[str, Any]:
            witnessed = original_authorize(
                request,
                operation_context=operation_context,
            )
            advanced = deepcopy(self.fixture.registry_document)
            advanced["generation"] = 2
            write_bytes(
                self.fixture.registry_path,
                protocol.canonical_json_bytes(advanced),
                0o600,
            )
            return witnessed

        with (
            mock.patch.object(
                self.fixture.monotonic_witness,
                "authorize_transition",
                side_effect=advance_registry_after_witness,
            ),
            mock.patch.object(
                service.time,
                "time",
                side_effect=(NOW, NOW + 30, NOW + 30, NOW + 30),
            ),
        ):
            recovered_expired = self.engine.issue(
                raw,
                peer_certificate_sha256=DEFAULT_RELAY_CERTIFICATE_SHA256,
            )

        verified = protocol.verify_launch_authorization_for_recovery(
            recovered_expired,
            authority_public_key_spki_der=self.fixture.authority_spki,
            expected_request_sha256=(
                protocol.launch_authorization_request_sha256(
                    protocol.require_canonical_json_bytes(raw)
                )
            ),
            expected_authority_key_id=self.fixture.authority_key_id,
            expected_global_role_registry_sha256=(
                protocol.launch_global_role_registry_sha256(
                    global_role_registry()
                )
            ),
        )
        self.assertEqual(verified.issued_at_unix_seconds, NOW)
        self.assertEqual(verified.expires_at_unix_seconds, NOW + 30)
        connection = self.engine.ledger.connect()
        try:
            operation = connection.execute(
                """
                SELECT state, terminal_observed_at_unix_seconds
                FROM issuance_operations
                """
            ).fetchone()
            self.assertEqual(operation["state"], "terminal")
            self.assertEqual(
                operation["terminal_observed_at_unix_seconds"],
                NOW + 30,
            )
        finally:
            connection.close()

    def test_v6_ledger_is_not_reinterpreted_as_v7(self) -> None:
        connection = self.engine.ledger.connect()
        try:
            connection.execute("PRAGMA user_version=6")
        finally:
            connection.close()
        with self.assertRaisesRegex(
            service.AuthorityConfigurationError,
            "required schema version 7",
        ):
            service.LaunchAuthorityLedger(self.fixture.ledger_path)

    def test_ledger_unlink_during_issuance_fails_before_envelope_release(self) -> None:
        raw = canonical_request(self.fixture.entry("a", sequence=1, epoch=0), nonce="a")
        original_sign = protocol.sign_launch_authorization

        def unlink_after_sign(*args: Any, **kwargs: Any) -> dict[str, Any]:
            envelope = original_sign(*args, **kwargs)
            self.fixture.ledger_path.unlink()
            return envelope

        with (
            mock.patch.object(
                protocol,
                "sign_launch_authorization",
                side_effect=unlink_after_sign,
            ),
            self.assertRaises(service.AuthorityError) as caught,
        ):
            issue_authorization(self.engine, raw)
        self.assertEqual(caught.exception.code, "LEDGER_UNAVAILABLE")

    def test_ledger_session_detects_pathname_inode_replacement(self) -> None:
        replacement = self.root / "replacement-ledger.sqlite3"
        shutil.copy2(self.fixture.ledger_path, replacement)
        replacement.chmod(0o600)
        session = self.engine.ledger.open_session()
        try:
            replacement.replace(self.fixture.ledger_path)
            with self.assertRaisesRegex(
                service.AuthorityConfigurationError, "pathname was replaced"
            ):
                session.assert_path_identity()
        finally:
            session.connection.close()

    def test_external_witness_rejects_joint_registry_and_ledger_rollback(
        self,
    ) -> None:
        first = self.fixture.entry("a", sequence=1, epoch=0)
        raw = canonical_request(first, nonce="7")
        issue_authorization(self.engine, raw)
        snapshot = self.root / "old-ledger-snapshot.sqlite3"
        shutil.copy2(self.fixture.ledger_path, snapshot)
        snapshot.chmod(0o600)
        old_registry = self.fixture.registry_path.read_bytes()

        advanced = self.fixture.entry("b", sequence=2, epoch=0)
        issue_authorization(
            self.engine,
            canonical_request(advanced, nonce="8"),
        )

        for suffix in ("-wal", "-shm"):
            Path(str(self.fixture.ledger_path) + suffix).unlink(missing_ok=True)
        snapshot.replace(self.fixture.ledger_path)
        write_bytes(self.fixture.registry_path, old_registry, 0o600)
        restored = self.fixture.engine()
        rollback_request = canonical_request(advanced, nonce="9")
        with self.assertRaises(service.AuthorityError) as caught:
            issue_authorization(restored, rollback_request)
        self.assertEqual(
            caught.exception.code, "MONOTONIC_WITNESS_RECOVERY_PENDING"
        )
        self.assertIn(
            "online external monotonic witness",
            service.EXTERNAL_ANTI_ROLLBACK_REQUIREMENT,
        )

    def test_unknown_disabled_and_revoked_releases_fail_closed(self) -> None:
        disabled = self.fixture.entry("e", sequence=10, epoch=1, enabled=False)
        revoked = self.fixture.entry("f", sequence=11, epoch=1, revoked=True)
        self.assert_authority_error(
            "RELEASE_DISABLED", canonical_request(disabled, nonce="3")
        )
        self.assert_authority_error(
            "RELEASE_REVOKED", canonical_request(revoked, nonce="4")
        )
        unknown = registry_entry("0", sequence=99, epoch=9)
        self.assert_authority_error(
            "UNKNOWN_RELEASE", canonical_request(unknown, nonce="5")
        )
        self.assertEqual(self.engine.ledger.counts()["authorizations"], 0)

    def test_service_rejects_v1_omitted_and_extra_request_contracts(self) -> None:
        enrolled = self.fixture.entry("a", sequence=1, epoch=0)
        valid = request_for(enrolled, nonce="0")

        v1 = deepcopy(valid)
        v1["apiVersion"] = "catchplate.launchAuthorizationRequest/v1"
        self.assert_authority_error(
            "INVALID_REQUEST",
            protocol.canonical_json_bytes(v1),
        )

        omitted = deepcopy(valid)
        omitted.pop("nonceRollbackAssurancePinsSha256")
        self.assert_authority_error(
            "INVALID_REQUEST",
            protocol.canonical_json_bytes(omitted),
        )

        extra = deepcopy(valid)
        extra["nonceRollbackAssurance"] = {}
        self.assert_authority_error(
            "INVALID_REQUEST",
            protocol.canonical_json_bytes(extra),
        )

    def test_service_pins_global_roles_and_rejects_collisions_and_substitution(
        self,
    ) -> None:
        enrolled = self.fixture.entry("a", sequence=1, epoch=0)
        valid = request_for(enrolled, nonce="0")

        omitted = deepcopy(valid)
        omitted["globalRoleRegistry"]["roles"].pop("reproducibleBuild")
        self.assert_authority_error(
            "INVALID_REQUEST", protocol.canonical_json_bytes(omitted)
        )

        unsupported_claim = deepcopy(valid)
        unsupported_claim["globalRoleRegistry"]["roles"][
            "finalVerifier"
        ] = named_digest("unsupported-final-verifier")
        self.assert_authority_error(
            "INVALID_REQUEST",
            protocol.canonical_json_bytes(unsupported_claim),
        )

        collision = deepcopy(valid)
        collision["globalRoleRegistry"]["roles"]["reproducibleBuild"] = collision[
            "globalRoleRegistry"
        ]["roles"]["policyIdentity"]
        self.assert_authority_error(
            "INVALID_REQUEST", protocol.canonical_json_bytes(collision)
        )

        substituted = deepcopy(valid)
        substituted_registry = deepcopy(substituted["globalRoleRegistry"])
        substituted_registry["roles"]["reproducibleBuild"] = named_digest(
            "substituted-reproducible-build"
        )
        substituted_registry = protocol.build_launch_global_role_registry(
            substituted_registry["roles"]
        )
        substituted["globalRoleRegistry"] = substituted_registry
        substituted["globalRoleRegistrySha256"] = (
            protocol.launch_global_role_registry_sha256(
                substituted_registry
            )
        )
        substituted["launchAttemptRecoveryIdentitySha256"] = (
            protocol.launch_attempt_recovery_identity_sha256(substituted)
        )
        with self.assertRaises(service.AuthorityError) as caught:
            issue_authorization(
                self.engine, protocol.canonical_json_bytes(substituted)
            )
        self.assertEqual(caught.exception.code, "GLOBAL_ROLE_REGISTRY_MISMATCH")

        wrong_authority = deepcopy(valid)
        wrong_authority_registry = deepcopy(wrong_authority["globalRoleRegistry"])
        wrong_authority_registry["roles"]["launchAuthority"] = named_digest(
            "wrong-launch-authority"
        )
        wrong_authority_registry = protocol.build_launch_global_role_registry(
            wrong_authority_registry["roles"]
        )
        wrong_authority["globalRoleRegistry"] = wrong_authority_registry
        wrong_authority["globalRoleRegistrySha256"] = (
            protocol.launch_global_role_registry_sha256(
                wrong_authority_registry
            )
        )
        wrong_authority["launchAttemptRecoveryIdentitySha256"] = (
            protocol.launch_attempt_recovery_identity_sha256(wrong_authority)
        )
        wrong_pin_engine = service.LaunchAuthority(
            registry_path=self.fixture.registry_path,
            ledger=service.LaunchAuthorityLedger(self.fixture.ledger_path),
            signing_key=service.load_authority_signing_key(
                self.fixture.authority_key_path,
                expected_key_id=self.fixture.authority_key_id,
            ),
            monotonic_witness=self.fixture.monotonic_witness,
            expected_global_role_registry_sha256=(
                protocol.launch_global_role_registry_sha256(
                    wrong_authority_registry
                )
            ),
            expected_global_role_registry_pins_sha256=named_digest(
                "global-role-registry-pins"
            ),
        )
        with self.assertRaises(service.AuthorityError) as crossed:
            issue_authorization(
                wrong_pin_engine,
                protocol.canonical_json_bytes(wrong_authority),
            )
        self.assertEqual(crossed.exception.code, "GLOBAL_ROLE_BINDING_MISMATCH")

        wrong_tls = deepcopy(valid)
        wrong_tls_registry = deepcopy(wrong_tls["globalRoleRegistry"])
        wrong_tls_registry["roles"]["launchAuthorityWitnessTls"] = (
            named_digest("wrong-witness-tls")
        )
        wrong_tls_registry = protocol.build_launch_global_role_registry(
            wrong_tls_registry["roles"]
        )
        wrong_tls["globalRoleRegistry"] = wrong_tls_registry
        wrong_tls["globalRoleRegistrySha256"] = (
            protocol.launch_global_role_registry_sha256(
                wrong_tls_registry
            )
        )
        wrong_tls["launchAttemptRecoveryIdentitySha256"] = (
            protocol.launch_attempt_recovery_identity_sha256(wrong_tls)
        )
        wrong_tls_pin_engine = service.LaunchAuthority(
            registry_path=self.fixture.registry_path,
            ledger=service.LaunchAuthorityLedger(self.fixture.ledger_path),
            signing_key=service.load_authority_signing_key(
                self.fixture.authority_key_path,
                expected_key_id=self.fixture.authority_key_id,
            ),
            monotonic_witness=self.fixture.monotonic_witness,
            expected_global_role_registry_sha256=(
                protocol.launch_global_role_registry_sha256(
                    wrong_tls_registry
                )
            ),
            expected_global_role_registry_pins_sha256=named_digest(
                "global-role-registry-pins"
            ),
        )
        with self.assertRaises(service.AuthorityError) as wrong_tls_binding:
            issue_authorization(
                wrong_tls_pin_engine,
                protocol.canonical_json_bytes(wrong_tls),
            )
        self.assertEqual(
            wrong_tls_binding.exception.code,
            "GLOBAL_ROLE_BINDING_MISMATCH",
        )

    def test_registry_match_binds_every_release_field(self) -> None:
        enrolled = self.fixture.entry("a", sequence=1, epoch=0)
        mutations: dict[str, Any] = {
            "deploymentAudience": "prod.us-west-2.secondary",
            "deploymentIdentitySha256": digest("0"),
            "releaseSequence": 99,
            "rollbackEpoch": 9,
            "manifestSha256": digest("0"),
            "nonceRollbackAssuranceContractSha256": digest("8"),
            "nonceRollbackAssurancePinsSha256": digest("9"),
            "releaseProvenanceSha256": digest("0"),
            "provenanceDigest": digest("0"),
            "sourceTreeDigest": digest("0"),
            "launcherSha256": digest("0"),
            "reproducibleBuildVerificationSha256": digest("0"),
        }
        for index, (field, value) in enumerate(mutations.items()):
            request = request_for(enrolled, nonce=f"{index:x}")
            request[field] = value
            with (
                self.subTest(field=field),
                self.assertRaises(service.AuthorityError) as caught,
            ):
                issue_authorization(self.engine, protocol.canonical_json_bytes(request))
            self.assertEqual(caught.exception.code, "UNKNOWN_RELEASE")

        swapped = request_for(enrolled, nonce="f")
        swapped["nonceRollbackAssuranceContractSha256"], swapped[
            "nonceRollbackAssurancePinsSha256"
        ] = (
            swapped["nonceRollbackAssurancePinsSha256"],
            swapped["nonceRollbackAssuranceContractSha256"],
        )
        with self.assertRaises(service.AuthorityError) as caught:
            issue_authorization(
                self.engine,
                protocol.canonical_json_bytes(swapped),
            )
        self.assertEqual(caught.exception.code, "UNKNOWN_RELEASE")

    def test_sequence_tuple_and_rollback_high_water_state_machine(self) -> None:
        def issue(token: str, sequence: int, epoch: int, nonce: str) -> bytes:
            return issue_authorization(
                self.engine,
                canonical_request(
                    self.fixture.entry(token, sequence=sequence, epoch=epoch),
                    nonce=nonce,
                ),
            )

        issue("a", 1, 0, "1")
        with self.assertRaisesRegex(
            service.AuthorityError, "equal release sequence"
        ) as caught:
            issue("b", 1, 0, "2")
        self.assertEqual(caught.exception.code, "SEQUENCE_TUPLE_MISMATCH")
        issue("b", 2, 0, "3")
        with self.assertRaises(service.AuthorityError) as caught:
            issue("a", 1, 0, "1")
        self.assertEqual(caught.exception.code, "SEQUENCE_ROLLBACK")
        with self.assertRaises(service.AuthorityError) as caught:
            issue("a", 3, 0, "4")
        self.assertEqual(caught.exception.code, "ROLLBACK_EPOCH_REQUIRED")
        issue("a", 3, 1, "5")
        with self.assertRaises(service.AuthorityError) as caught:
            issue("c", 4, 0, "6")
        self.assertEqual(caught.exception.code, "ROLLBACK_EPOCH_ROLLBACK")
        issue("c", 4, 1, "7")
        with self.assertRaises(service.AuthorityError) as caught:
            issue("c", 4, 2, "8")
        self.assertEqual(caught.exception.code, "SEQUENCE_TUPLE_MISMATCH")
        with self.assertRaises(service.AuthorityError) as caught:
            issue("b", 2, 2, "9")
        self.assertEqual(caught.exception.code, "SEQUENCE_ROLLBACK")
        issue("d", 5, 1, "a")
        issue("d", 5, 1, "b")
        self.assertEqual(
            self.engine.ledger.counts(),
            {
                "authorizations": 6,
                "deployment_high_water": 1,
                "seen_release_tuples": 4,
                "registry_state": 1,
                "revoked_release_bindings": 1,
                "issuance_operations": 6,
            },
        )

    def test_restart_preserves_retry_bytes_and_high_water(self) -> None:
        current = self.fixture.entry("c", sequence=4, epoch=1)
        raw = canonical_request(current, nonce="c")
        first = issue_authorization(self.engine, raw)
        restarted = self.fixture.engine()
        self.assertEqual(issue_authorization(restarted, raw, now=NOW + 1), first)
        old = canonical_request(self.fixture.entry("b", sequence=2, epoch=2), nonce="d")
        with self.assertRaises(service.AuthorityError) as caught:
            issue_authorization(restarted, old, now=NOW + 1)
        self.assertEqual(caught.exception.code, "SEQUENCE_ROLLBACK")

    def test_lost_witness_response_is_durably_recovered_after_restart(self) -> None:
        entry = self.fixture.entry("a", sequence=1, epoch=0)
        raw = canonical_request(entry, nonce="d")
        self.fixture.monotonic_witness.fail_after_commit_once = True
        self.fixture.monotonic_witness.fail_recovery = True
        with self.assertRaises(service.AuthorityError) as caught:
            issue_authorization(self.engine, raw)
        self.assertEqual(
            caught.exception.code, "MONOTONIC_WITNESS_RECOVERY_PENDING"
        )

        connection = self.engine.ledger.connect()
        try:
            prepared = connection.execute(
                """
                SELECT state, request_bytes, witness_request_bytes,
                       witness_transition_bytes, envelope_bytes
                FROM issuance_operations WHERE operation_id = ?
                """,
                ("d" * 64,),
            ).fetchone()
            self.assertEqual(prepared["state"], "prepared")
            self.assertEqual(bytes(prepared["request_bytes"]), raw)
            self.assertIsNotNone(prepared["witness_request_bytes"])
            self.assertIsNone(prepared["witness_transition_bytes"])
            self.assertIsNone(prepared["envelope_bytes"])
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM authorizations"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM deployment_high_water"
                ).fetchone()[0],
                0,
            )
        finally:
            connection.close()

        different = canonical_request(entry, nonce="e")
        with self.assertRaises(service.AuthorityError) as blocked:
            issue_authorization(self.engine, different, now=NOW + 1)
        self.assertEqual(blocked.exception.code, "ISSUANCE_IN_PROGRESS")

        self.fixture.monotonic_witness.fail_recovery = False
        restarted = self.fixture.engine()
        recovered = issue_authorization(restarted, raw, now=NOW + 1)
        retry = issue_authorization(restarted, raw, now=NOW + 2)
        self.assertEqual(recovered, retry)
        connection = restarted.ledger.connect()
        try:
            finalized = connection.execute(
                """
                SELECT state, witness_transition_bytes, envelope_bytes
                FROM issuance_operations WHERE operation_id = ?
                """,
                ("d" * 64,),
            ).fetchone()
            self.assertEqual(finalized["state"], "terminal")
            self.assertIsNotNone(finalized["witness_transition_bytes"])
            self.assertEqual(bytes(finalized["envelope_bytes"]), recovered)
        finally:
            connection.close()

    def test_startup_rejects_every_nonterminal_non_key_trust_rotation(
        self,
    ) -> None:
        changed_pins = (
            (
                "witness identity",
                "witness",
                "witness_identity_sha256",
            ),
            (
                "witness administrative domain",
                "witness",
                "administrative_domain_sha256",
            ),
            (
                "witness store assurance",
                "witness",
                "store_assurance_sha256",
            ),
            (
                "witness store-assurance issuer",
                "witness",
                "store_assurance_key_id",
            ),
            (
                "witness TLS SPKI",
                "witness",
                "expected_tls_spki_sha256",
            ),
            (
                "global role registry",
                "authority",
                "expected_global_role_registry_sha256",
            ),
            (
                "global role registry pins file",
                "authority",
                "expected_global_role_registry_pins_sha256",
            ),
        )
        for index, (label, owner, attribute) in enumerate(changed_pins):
            with self.subTest(pin=label), tempfile.TemporaryDirectory() as temporary:
                fixture = AuthorityFixture(Path(temporary).resolve())
                engine = fixture.engine()
                entry = fixture.entry("a", sequence=1, epoch=0)
                raw = canonical_request(entry, nonce=f"{index:x}")
                fixture.monotonic_witness.fail_after_commit_once = True
                fixture.monotonic_witness.fail_recovery = True
                with self.assertRaises(service.AuthorityError):
                    issue_authorization(engine, raw, now=NOW)

                fixture.monotonic_witness.fail_recovery = False
                changed = named_digest(f"changed-{label}")
                original: str | None = None
                arguments: dict[str, str] = {}
                if owner == "witness":
                    original = getattr(fixture.monotonic_witness, attribute)
                    setattr(fixture.monotonic_witness, attribute, changed)
                else:
                    arguments[attribute] = changed
                with self.assertRaisesRegex(
                    service.AuthorityConfigurationError,
                    "startup trust rotation.*original retained.*terminalize",
                ):
                    fixture.engine(**arguments)
                if original is not None:
                    setattr(fixture.monotonic_witness, attribute, original)

                retained = fixture.engine()
                recovered = issue_authorization(retained, raw, now=NOW + 1)
                request = protocol.require_canonical_json_bytes(raw)
                protocol.verify_launch_authorization(
                    recovered,
                    authority_public_key_spki_der=fixture.authority_spki,
                    expected_request_sha256=(
                        protocol.launch_authorization_request_sha256(request)
                    ),
                    expected_authority_key_id=fixture.authority_key_id,
                    now_unix_seconds=NOW + 1,
                )
                connection = retained.ledger.connect()
                try:
                    operation = connection.execute(
                        """
                        SELECT state FROM issuance_operations
                        WHERE operation_id = ?
                        """,
                        (f"{index:x}" * 64,),
                    ).fetchone()
                    self.assertEqual(operation["state"], "terminal")
                finally:
                    connection.close()

    def test_startup_rejects_nonterminal_authority_and_witness_key_rotation(
        self,
    ) -> None:
        rotations = ("authority", "witness")
        for index, rotation in enumerate(rotations, start=7):
            with self.subTest(rotation=rotation), tempfile.TemporaryDirectory() as temporary:
                fixture = AuthorityFixture(Path(temporary).resolve())
                raw = canonical_request(
                    fixture.entry("a", sequence=1, epoch=0),
                    nonce=f"{index:x}",
                )
                fixture.monotonic_witness.fail_after_commit_once = True
                fixture.monotonic_witness.fail_recovery = True
                with self.assertRaises(service.AuthorityError):
                    issue_authorization(fixture.engine(), raw, now=NOW)
                fixture.monotonic_witness.fail_recovery = False

                replacement = Ed25519PrivateKey.from_private_bytes(
                    bytes([0x68 + index]) * 32
                )
                replacement_spki = public_spki(replacement)
                if rotation == "authority":
                    arguments = {
                        "signing_key": service.AuthoritySigningKey(
                            private_key=replacement,
                            key_id=protocol.spki_key_id(replacement_spki),
                        )
                    }
                    original_witness_spki = None
                    original_witness_key_id = None
                else:
                    arguments = {}
                    original_witness_spki = (
                        fixture.monotonic_witness.signing_public_key_spki_der
                    )
                    original_witness_key_id = (
                        fixture.monotonic_witness.signing_key_id
                    )
                    fixture.monotonic_witness.signing_public_key_spki_der = (
                        replacement_spki
                    )
                    fixture.monotonic_witness.signing_key_id = (
                        protocol.spki_key_id(replacement_spki)
                    )
                with self.assertRaisesRegex(
                    service.AuthorityConfigurationError,
                    "startup trust rotation.*original retained.*terminalize",
                ):
                    fixture.engine(**arguments)
                if original_witness_spki is not None:
                    fixture.monotonic_witness.signing_public_key_spki_der = (
                        original_witness_spki
                    )
                    fixture.monotonic_witness.signing_key_id = (
                        original_witness_key_id
                    )

                retained = fixture.engine()
                issue_authorization(retained, raw, now=NOW + 1)
                connection = retained.ledger.connect()
                try:
                    state = connection.execute(
                        """
                        SELECT state FROM issuance_operations
                        WHERE operation_id = ?
                        """,
                        (f"{index:x}" * 64,),
                    ).fetchone()["state"]
                    self.assertEqual(state, "terminal")
                finally:
                    connection.close()

    def test_process_trust_snapshot_is_rechecked_before_return(self) -> None:
        entry = self.fixture.entry("a", sequence=1, epoch=0)
        raw = canonical_request(entry, nonce="5")
        original_identity = (
            self.fixture.monotonic_witness.witness_identity_sha256
        )
        original_observe = (
            self.fixture.monotonic_witness.observe_registry_head
        )
        observation_calls = 0

        def rotate_after_terminal_observation(
            request: dict[str, Any],
        ) -> dict[str, Any]:
            nonlocal observation_calls
            observation_calls += 1
            response = original_observe(request)
            if observation_calls == 2:
                self.fixture.monotonic_witness.witness_identity_sha256 = (
                    named_digest("runtime-rotated-witness-identity")
                )
            return response

        with (
            mock.patch.object(
                self.fixture.monotonic_witness,
                "observe_registry_head",
                side_effect=rotate_after_terminal_observation,
            ),
            self.assertRaises(service.AuthorityError) as blocked,
        ):
            issue_authorization(self.engine, raw, now=NOW)
        self.assertEqual(blocked.exception.code, "TRUST_SNAPSHOT_CHANGED")
        connection = self.engine.ledger.connect()
        try:
            state = connection.execute(
                """
                SELECT state FROM issuance_operations WHERE operation_id = ?
                """,
                ("5" * 64,),
            ).fetchone()["state"]
            self.assertEqual(state, "terminal")
        finally:
            connection.close()
        self.fixture.monotonic_witness.witness_identity_sha256 = original_identity
        issue_authorization(self.engine, raw, now=NOW + 1)

    def test_trust_lifecycle_contract_requires_external_stop_drain_restart(
        self,
    ) -> None:
        contract = service.TRUST_CONFIGURATION_LIFECYCLE
        ordered_steps = (
            "stop accepting traffic",
            "drain active requests",
            "original retained authority and witness trust",
            "terminalize every nonterminal issuance",
            "stop that process",
            "one replacement listener",
        )
        positions = [contract.index(step) for step in ordered_steps]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("in-memory startup snapshot", contract)
        self.assertIn("on-disk changes are not dynamically observed", contract)
        self.assertIn("overlapping listeners", contract)
        self.assertIn("in-process reload", contract)

    def test_finalized_operation_blocks_new_attempt_until_terminal_head(
        self,
    ) -> None:
        entry = self.fixture.entry("a", sequence=1, epoch=0)
        raw = canonical_request(entry, nonce="6")
        original_observe = (
            self.fixture.monotonic_witness.observe_registry_head
        )
        observation_calls = 0

        def fail_terminal_observation(
            request: dict[str, Any],
            *,
            operation_context: service.AuthorityOperationContext,
        ) -> dict[str, Any]:
            nonlocal observation_calls
            observation_calls += 1
            if observation_calls == 2:
                raise service.AuthorityWitnessExchangeError(
                    "injected terminal registry observation response loss",
                    phase="terminal registry witness fixture",
                    outcome_unknown=True,
                )
            return original_observe(
                request,
                operation_context=operation_context,
            )

        with (
            mock.patch.object(
                self.fixture.monotonic_witness,
                "observe_registry_head",
                side_effect=fail_terminal_observation,
            ),
            self.assertRaises(service.AuthorityError) as interrupted,
        ):
            issue_authorization(self.engine, raw)
        self.assertEqual(
            interrupted.exception.code,
            "AUTHORITY_TERMINAL_RECOVERY_PENDING",
        )
        original_identity = (
            self.fixture.monotonic_witness.witness_identity_sha256
        )
        self.fixture.monotonic_witness.witness_identity_sha256 = named_digest(
            "rotated-during-finalized-recovery"
        )
        with self.assertRaisesRegex(
            service.AuthorityConfigurationError,
            "startup trust rotation.*original retained.*terminalize",
        ):
            self.fixture.engine()
        self.fixture.monotonic_witness.witness_identity_sha256 = original_identity
        retained_restart = self.fixture.engine()

        different = canonical_request(entry, nonce="7")
        with self.assertRaises(service.AuthorityError) as blocked:
            issue_authorization(retained_restart, different, now=NOW + 1)
        self.assertEqual(blocked.exception.code, "ISSUANCE_IN_PROGRESS")

        recovered = issue_authorization(retained_restart, raw, now=NOW + 1)
        self.assertTrue(recovered)
        self.assertTrue(
            issue_authorization(retained_restart, different, now=NOW + 2)
        )

    def test_lost_response_recovers_prepared_policy_before_current_registry(
        self,
    ) -> None:
        entry = self.fixture.entry("a", sequence=1, epoch=0)
        raw = canonical_request(entry, nonce="9")
        self.fixture.monotonic_witness.fail_after_commit_once = True
        self.fixture.monotonic_witness.fail_recovery = True
        with self.assertRaises(service.AuthorityError) as lost:
            issue_authorization(self.engine, raw, now=NOW)
        self.assertEqual(
            lost.exception.code, "MONOTONIC_WITNESS_RECOVERY_PENDING"
        )

        changed = deepcopy(self.fixture.registry_document)
        changed["generation"] = 2
        changed["releases"][0]["enabled"] = False
        write_bytes(
            self.fixture.registry_path,
            protocol.canonical_json_bytes(changed),
            0o600,
        )
        self.fixture.monotonic_witness.fail_recovery = False
        restarted = self.fixture.engine()
        with self.assertRaises(service.AuthorityError) as fresh:
            issue_authorization(restarted, raw, now=NOW + 1)
        self.assertEqual(
            fresh.exception.code, "REGISTRY_CHANGED_DURING_ISSUANCE"
        )

        connection = restarted.ledger.connect()
        try:
            operation = connection.execute(
                """
                SELECT state, registry_generation, envelope_bytes
                FROM issuance_operations WHERE operation_id = ?
                """,
                ("9" * 64,),
            ).fetchone()
            self.assertEqual(operation["state"], "finalized")
            self.assertEqual(operation["registry_generation"], 1)
            self.assertIsNotNone(operation["envelope_bytes"])
        finally:
            connection.close()

        different = canonical_request(changed["releases"][3], nonce="a")
        with self.assertRaises(service.AuthorityError) as blocked:
            issue_authorization(restarted, different, now=NOW + 2)
        self.assertEqual(blocked.exception.code, "ISSUANCE_IN_PROGRESS")

        terminal = issue_authorization(restarted, raw, now=NOW + 30)
        protocol.verify_launch_authorization_with_witness_for_recovery(
            terminal,
            authority_public_key_spki_der=self.fixture.authority_spki,
            expected_request=protocol.require_canonical_json_bytes(raw),
            expected_authority_key_id=self.fixture.authority_key_id,
            witness_public_key_spki_der=(
                self.fixture.monotonic_witness.signing_public_key_spki_der
            ),
            expected_witness_key_id=WITNESS_KEY_ID,
            expected_registry_generation=1,
        )

    def test_expired_recovery_returns_only_an_authentic_terminal_envelope(
        self,
    ) -> None:
        entry = self.fixture.entry("a", sequence=1, epoch=0)
        raw = canonical_request(entry, nonce="b")
        self.fixture.monotonic_witness.fail_after_commit_once = True
        self.fixture.monotonic_witness.fail_recovery = True
        with self.assertRaises(service.AuthorityError):
            issue_authorization(self.engine, raw, now=NOW)

        self.fixture.monotonic_witness.fail_recovery = False
        restarted = self.fixture.engine()
        recovered_terminal = issue_authorization(
            restarted, raw, now=NOW + 30
        )
        with self.assertRaisesRegex(
            protocol.LaunchAuthorizationError, "expired"
        ):
            protocol.verify_launch_authorization(
                recovered_terminal,
                authority_public_key_spki_der=self.fixture.authority_spki,
                expected_request_sha256=(
                    protocol.launch_authorization_request_sha256(
                        protocol.require_canonical_json_bytes(raw)
                    )
                ),
                expected_authority_key_id=self.fixture.authority_key_id,
                now_unix_seconds=NOW + 30,
                expected_global_role_registry_sha256=(
                    protocol.launch_global_role_registry_sha256(
                        global_role_registry()
                    )
                ),
            )
        connection = restarted.ledger.connect()
        try:
            row = connection.execute(
                """
                SELECT state, envelope_bytes FROM issuance_operations
                WHERE operation_id = ?
                """,
                ("b" * 64,),
            ).fetchone()
            self.assertEqual(row["state"], "terminal")
            recovered = bytes(row["envelope_bytes"])
            self.assertEqual(recovered, recovered_terminal)
            protocol.verify_launch_authorization_with_witness_for_recovery(
                recovered,
                authority_public_key_spki_der=self.fixture.authority_spki,
                expected_request=protocol.require_canonical_json_bytes(raw),
                expected_authority_key_id=self.fixture.authority_key_id,
                witness_public_key_spki_der=(
                    self.fixture.monotonic_witness.signing_public_key_spki_der
                ),
                expected_witness_key_id=WITNESS_KEY_ID,
                expected_registry_generation=1,
            )
        finally:
            connection.close()

        next_raw = canonical_request(entry, nonce="c")
        self.assertTrue(
            issue_authorization(restarted, next_raw, now=NOW + 31)
        )

    def test_policy_change_withholds_fresh_recovery_until_expiry(self) -> None:
        entry = self.fixture.entry("a", sequence=1, epoch=0)
        raw = canonical_request(entry, nonce="7")
        issued = issue_authorization(self.engine, raw, now=NOW)

        changed = deepcopy(self.fixture.registry_document)
        changed["generation"] = 2
        changed["releases"][0]["enabled"] = False
        write_bytes(
            self.fixture.registry_path,
            protocol.canonical_json_bytes(changed),
            0o600,
        )
        with self.assertRaises(service.AuthorityError) as fresh:
            issue_authorization(self.engine, raw, now=NOW + 1)
        self.assertEqual(
            fresh.exception.code, "REGISTRY_CHANGED_DURING_ISSUANCE"
        )

        terminal = issue_authorization(self.engine, raw, now=NOW + 30)
        self.assertEqual(terminal, issued)
        with self.assertRaisesRegex(
            protocol.LaunchAuthorizationError, "expired"
        ):
            protocol.verify_launch_authorization(
                terminal,
                authority_public_key_spki_der=self.fixture.authority_spki,
                expected_request_sha256=(
                    protocol.launch_authorization_request_sha256(
                        protocol.require_canonical_json_bytes(raw)
                    )
                ),
                expected_authority_key_id=self.fixture.authority_key_id,
                now_unix_seconds=NOW + 30,
                expected_global_role_registry_sha256=(
                    request_for(entry, nonce="7")[
                        "globalRoleRegistrySha256"
                    ]
                ),
            )
        protocol.verify_launch_authorization_with_witness_for_recovery(
            terminal,
            authority_public_key_spki_der=self.fixture.authority_spki,
            expected_request=protocol.require_canonical_json_bytes(raw),
            expected_authority_key_id=self.fixture.authority_key_id,
            witness_public_key_spki_der=(
                self.fixture.monotonic_witness.signing_public_key_spki_der
            ),
            expected_witness_key_id=WITNESS_KEY_ID,
            expected_registry_generation=1,
        )

        later = canonical_request(changed["releases"][3], nonce="8")
        self.assertTrue(
            issue_authorization(self.engine, later, now=NOW + 31)
        )

    def test_prepared_operation_tamper_fails_before_witness_recovery(self) -> None:
        entry = self.fixture.entry("a", sequence=1, epoch=0)
        raw = canonical_request(entry, nonce="f")
        self.fixture.monotonic_witness.fail_after_commit_once = True
        self.fixture.monotonic_witness.fail_recovery = True
        with self.assertRaises(service.AuthorityError):
            issue_authorization(self.engine, raw)
        connection = self.engine.ledger.connect()
        try:
            witness_request = protocol.require_canonical_json_bytes(
                bytes(
                    connection.execute(
                        """
                        SELECT witness_request_bytes FROM issuance_operations
                        WHERE operation_id = ?
                        """,
                        ("f" * 64,),
                    ).fetchone()[0]
                )
            )
            witness_request["challenge"] = "0" * 64
            connection.execute(
                """
                UPDATE issuance_operations SET witness_request_bytes = ?
                WHERE operation_id = ?
                """,
                (
                    protocol.canonical_json_bytes(witness_request),
                    "f" * 64,
                ),
            )
        finally:
            connection.close()
        self.fixture.monotonic_witness.fail_recovery = False
        with self.assertRaises(service.AuthorityError) as caught:
            issue_authorization(self.fixture.engine(), raw, now=NOW + 1)
        self.assertEqual(caught.exception.code, "PREPARED_OPERATION_TAMPERED")

    def test_concurrent_identical_issuance_commits_once(self) -> None:
        entry = self.fixture.entry("a", sequence=1, epoch=0)
        raw = canonical_request(entry, nonce="e")
        barrier = threading.Barrier(12)

        def issue_once() -> bytes:
            barrier.wait(timeout=5)
            return issue_authorization(self.engine, raw)

        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
            results = list(executor.map(lambda _index: issue_once(), range(12)))
        self.assertTrue(all(value == results[0] for value in results))
        self.assertEqual(self.engine.ledger.counts()["authorizations"], 1)

    def test_registry_is_closed_strict_and_cannot_enroll_caller_urls(self) -> None:
        duplicate_key = (
            b'{"apiVersion":"'
            + service.REGISTRY_API_VERSION.encode("ascii")
            + b'","apiVersion":"x","kind":"'
            + service.REGISTRY_KIND.encode("ascii")
            + b'","releases":[]}'
        )
        with self.assertRaises(service.AuthorityConfigurationError):
            service.ReleaseRegistry.from_bytes(duplicate_key)

        v1_registry = deepcopy(self.fixture.registry_document)
        v1_registry["apiVersion"] = "catchplate.launchAuthorityReleaseRegistry/v1"
        with self.assertRaisesRegex(
            service.AuthorityConfigurationError, "apiVersion"
        ):
            service.ReleaseRegistry.from_bytes(
                protocol.canonical_json_bytes(v1_registry)
            )

        with self.assertRaisesRegex(
            service.AuthorityConfigurationError, "canonical compact"
        ):
            service.ReleaseRegistry.from_bytes(
                json.dumps(self.fixture.registry_document, indent=2).encode("ascii")
            )

        invalid_generation = deepcopy(self.fixture.registry_document)
        invalid_generation["generation"] = 0
        with self.assertRaisesRegex(
            service.AuthorityConfigurationError, "positive safe integer"
        ):
            service.ReleaseRegistry.from_bytes(
                protocol.canonical_json_bytes(invalid_generation)
            )

        open_registry = deepcopy(self.fixture.registry_document)
        open_registry["releaseRegistryUrl"] = "https://caller.invalid/releases"
        with self.assertRaises(service.AuthorityConfigurationError):
            service.ReleaseRegistry.from_bytes(
                protocol.canonical_json_bytes(open_registry)
            )

        open_entry = deepcopy(self.fixture.registry_document)
        open_entry["releases"][0]["provenanceUrl"] = "https://caller.invalid/provenance"
        with self.assertRaises(service.AuthorityConfigurationError):
            service.ReleaseRegistry.from_bytes(
                protocol.canonical_json_bytes(open_entry)
            )

        duplicate_entry = deepcopy(self.fixture.registry_document)
        duplicate_entry["releases"].append(deepcopy(duplicate_entry["releases"][0]))
        with self.assertRaises(service.AuthorityConfigurationError):
            service.ReleaseRegistry.from_bytes(
                protocol.canonical_json_bytes(duplicate_entry)
            )

        missing_certificate_binding = deepcopy(self.fixture.registry_document)
        del missing_certificate_binding["releases"][0]["relayClientCertificateSha256"]
        with self.assertRaises(service.AuthorityConfigurationError):
            service.ReleaseRegistry.from_bytes(
                protocol.canonical_json_bytes(missing_certificate_binding)
            )

        for field in (
            "nonceRollbackAssuranceContractSha256",
            "nonceRollbackAssurancePinsSha256",
        ):
            missing_assurance_binding = deepcopy(self.fixture.registry_document)
            del missing_assurance_binding["releases"][0][field]
            with self.subTest(field=field), self.assertRaises(
                service.AuthorityConfigurationError
            ):
                service.ReleaseRegistry.from_bytes(
                    protocol.canonical_json_bytes(missing_assurance_binding)
                )

        invalid_certificate_binding = deepcopy(self.fixture.registry_document)
        invalid_certificate_binding["releases"][0]["relayClientCertificateSha256"] = (
            "SHA256:invalid"
        )
        with self.assertRaisesRegex(
            service.AuthorityConfigurationError, "relay client certificate digest"
        ):
            service.ReleaseRegistry.from_bytes(
                protocol.canonical_json_bytes(invalid_certificate_binding)
            )

    def test_private_key_requires_matching_owner_only_regular_pkcs8(self) -> None:
        valid = service.load_authority_signing_key(
            self.fixture.authority_key_path,
            expected_key_id=self.fixture.authority_key_id,
        )
        self.assertEqual(valid.key_id, self.fixture.authority_key_id)
        with self.assertRaisesRegex(
            service.AuthorityConfigurationError, "configured key ID"
        ):
            service.load_authority_signing_key(
                self.fixture.authority_key_path, expected_key_id=digest("0")
            )
        with self.assertRaisesRegex(
            service.AuthorityConfigurationError, "lowercase hex"
        ):
            service.load_authority_signing_key(
                self.fixture.authority_key_path, expected_key_id="not-a-key-id"
            )

        self.fixture.authority_key_path.chmod(0o644)
        with self.assertRaisesRegex(
            service.AuthorityConfigurationError, "0400 or 0600"
        ):
            service.load_authority_signing_key(
                self.fixture.authority_key_path,
                expected_key_id=self.fixture.authority_key_id,
            )
        self.fixture.authority_key_path.chmod(0o600)

        symlink = self.root / "authority-key-link.pem"
        symlink.symlink_to(self.fixture.authority_key_path)
        with self.assertRaisesRegex(service.AuthorityConfigurationError, "non-symlink"):
            service.load_authority_signing_key(
                symlink, expected_key_id=self.fixture.authority_key_id
            )

        ec_key = ec.generate_private_key(ec.SECP256R1())
        wrong_algorithm = write_bytes(
            self.root / "ec-key.pem",
            ec_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
            0o600,
        )
        with self.assertRaisesRegex(service.AuthorityConfigurationError, "Ed25519"):
            service.load_authority_signing_key(
                wrong_algorithm, expected_key_id=self.fixture.authority_key_id
            )

        noncanonical = write_bytes(
            self.root / "noncanonical-key.pem",
            self.fixture.authority_key_path.read_bytes() + b"\n",
            0o600,
        )
        with self.assertRaisesRegex(service.AuthorityConfigurationError, "canonical"):
            service.load_authority_signing_key(
                noncanonical, expected_key_id=self.fixture.authority_key_id
            )


class HTTPSAndRelayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.pki = TestPKI(self.root)
        self.client_certificate_sha256 = self.pki.certificate_sha256(
            self.pki.client_certificate
        )
        self.fixture = AuthorityFixture(
            self.root,
            relay_certificate_sha256=self.client_certificate_sha256,
        )
        self.engine = self.fixture.engine()
        self.entry = self.fixture.entry("a", sequence=1, epoch=0)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def relay_configuration(
        self, port: int, *, timeout: float = 2.0
    ) -> relay.RelayConfiguration:
        return relay.RelayConfiguration(
            authority_url=f"https://localhost:{port}{relay.AUTHORIZATION_PATH}",
            server_name="localhost",
            ca_certificate=self.pki.ca_path,
            client_certificate=self.pki.client_certificate_path,
            client_private_key=self.pki.client_key_path,
            timeout_seconds=timeout,
        )

    def witness_client(
        self,
        url: str,
        *,
        timeout_seconds: float = 1.0,
    ) -> service.LaunchAuthorityMonotonicWitnessClient:
        signing_public_key = write_bytes(
            self.root / "witness-signing-public-key.pem",
            WITNESS_PRIVATE_KEY.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
            0o644,
        )
        tls_spki = self.pki.server_certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return service.LaunchAuthorityMonotonicWitnessClient(
            url=url,
            ca_certificate=self.pki.ca_path,
            client_certificate=self.pki.client_certificate_path,
            client_private_key=self.pki.client_key_path,
            expected_tls_spki_sha256=(
                "sha256:" + hashlib.sha256(tls_spki).hexdigest()
            ),
            signing_public_key=signing_public_key,
            expected_signing_key_id=WITNESS_KEY_ID,
            witness_identity_sha256=WITNESS_IDENTITY_SHA256,
            administrative_domain_sha256=WITNESS_ADMINISTRATIVE_DOMAIN_SHA256,
            store_assurance_sha256=WITNESS_STORE_ASSURANCE_SHA256,
            store_assurance_key_id=WITNESS_STORE_ASSURANCE_KEY_ID,
            timeout_seconds=timeout_seconds,
        )

    def test_witness_transport_requires_canonical_literal_ipv4_and_no_resolver(
        self,
    ) -> None:
        client = self.witness_client(
            "https://127.0.0.1/v1/launch-authority-transitions"
        )
        self.assertEqual(client.host, "127.0.0.1")
        self.assertEqual(client.port, 443)
        for invalid_url in (
            "https://localhost/v1/launch-authority-transitions",
            "https://127.000.000.001/v1/launch-authority-transitions",
            "https://127.0.0.1:443/v1/launch-authority-transitions",
            "https://127.0.0.1:0/v1/launch-authority-transitions",
            "https://127.0.0.1/v1/launch-authority-transitions?",
            "https://[::1]/v1/launch-authority-transitions",
        ):
            with self.subTest(url=invalid_url), self.assertRaisesRegex(
                service.AuthorityConfigurationError,
                "canonical|literal|port",
            ):
                self.witness_client(invalid_url)

        source = (ROOT / "scripts/launch_authority_service.py").read_text(
            encoding="utf-8"
        )
        response_parser_source = source.split(
            "def _parse_witness_http_response_head", 1
        )[1].split("class LiteralIpv4TlsTransport", 1)[0]
        literal_transport_source = source.split(
            "class LiteralIpv4TlsTransport", 1
        )[1].split("class LaunchAuthorityMonotonicWitnessClient", 1)[0]
        witness_client_source = source.split(
            "class LaunchAuthorityMonotonicWitnessClient", 1
        )[1].split("class LaunchAuthorityLedger", 1)[0]
        self.assertIn("socket.socket(socket.AF_INET, socket.SOCK_STREAM)", literal_transport_source)
        self.assertIn(
            "raw_socket.connect_ex(",
            literal_transport_source,
        )
        self.assertNotIn("getaddrinfo", literal_transport_source)
        self.assertNotIn("socket.create_connection", literal_transport_source)
        self.assertNotIn("settimeout", literal_transport_source)
        self.assertIn("select.select(", literal_transport_source)
        self.assertIn("suppress_ragged_eofs=False", literal_transport_source)
        self.assertIn("current.shutdown(socket.SHUT_RDWR)", literal_transport_source)
        self.assertIn("receive_http_response", literal_transport_source)
        self.assertIn("response TLS close", literal_transport_source)
        self.assertIn("transfer-encoding", response_parser_source)
        self.assertIn("content-encoding", response_parser_source)
        self.assertLess(
            literal_transport_source.index(
                "current.shutdown(socket.SHUT_RDWR)"
            ),
            literal_transport_source.index("current.close()"),
        )
        self.assertIn("_remaining_deadline_seconds(local_deadline)", witness_client_source)
        self.assertIn("operation_context.remaining_seconds", witness_client_source)
        self.assertIn(
            "server_hostname=self._literal_address",
            literal_transport_source,
        )
        self.assertIn("LiteralIpv4TlsTransport(", witness_client_source)
        self.assertIn("self.context.check_hostname = True", witness_client_source)
        self.assertIn(
            "peer_spki_sha256, self.expected_tls_spki_sha256",
            witness_client_source,
        )
        server_sans = self.pki.server_certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        self.assertIn(
            ipaddress.IPv4Address("127.0.0.1"),
            server_sans.get_values_for_type(x509.IPAddress),
        )
        self.assertNotIn(
            "http.client.HTTPSConnection(",
            witness_client_source,
        )
        self.assertNotIn("getresponse(", witness_client_source)
        self.assertNotIn(".read(", witness_client_source)

        transport = service.LiteralIpv4TlsTransport(
            "127.0.0.1",
            443,
            context=ssl.create_default_context(),
            remaining_seconds=lambda _phase: 1.0,
        )
        fake_socket = mock.Mock()
        transport._install_socket(fake_socket)
        transport.abort()
        self.assertEqual(
            fake_socket.method_calls,
            [
                mock.call.shutdown(socket.SHUT_RDWR),
                mock.call.close(),
            ],
        )

    def _post_to_scripted_witness(
        self,
        peer: ScriptedWitnessTlsPeer,
        *,
        timeout_seconds: float,
    ) -> bytes:
        client = self.witness_client(
            (
                f"https://127.0.0.1:{peer.port}"
                "/v1/launch-authority-transitions"
            ),
            timeout_seconds=timeout_seconds,
        )
        operation_context = service.AuthorityOperationContext(
            time.monotonic() + timeout_seconds
        )
        return client._post_json(
            {"fixture": "request"},
            path="/v1/launch-authority-transitions",
            request_content_type="application/test-witness-request+json",
            response_content_type="application/test-witness-response+json",
            operation_context=operation_context,
        )

    def _assert_post_dispatch_outcome_unknown(
        self,
        peer: ScriptedWitnessTlsPeer,
        *,
        timeout_seconds: float,
    ) -> None:
        with self.assertRaises(
            service.AuthorityWitnessExchangeError
        ) as captured:
            self._post_to_scripted_witness(
                peer,
                timeout_seconds=timeout_seconds,
            )
        self.assertTrue(captured.exception.outcome_unknown)
        self.assertTrue(peer.received_request)

    def test_witness_exchange_classifies_pre_dispatch_failure(self) -> None:
        client = self.witness_client(
            "https://127.0.0.1/v1/launch-authority-transitions"
        )
        operation_context = service.AuthorityOperationContext(
            time.monotonic() + 1.0
        )
        with mock.patch.object(
            service.LiteralIpv4TlsTransport,
            "connect",
            side_effect=OSError("injected pre-dispatch connection failure"),
        ):
            with self.assertRaises(
                service.AuthorityWitnessExchangeError
            ) as captured:
                client._post_json(
                    {"fixture": "request"},
                    path="/v1/launch-authority-transitions",
                    request_content_type="application/test-witness-request+json",
                    response_content_type=(
                        "application/test-witness-response+json"
                    ),
                    operation_context=operation_context,
                )
        self.assertFalse(captured.exception.outcome_unknown)

    def test_transition_verification_cancellation_preserves_unknown_outcome(
        self,
    ) -> None:
        client = self.witness_client(
            "https://127.0.0.1/v1/launch-authority-transitions"
        )
        for method_name in ("authorize_transition", "recover_transition"):
            with self.subTest(method=method_name):
                operation_context = service.AuthorityOperationContext(
                    time.monotonic() + 1.0
                )

                def cancel_during_verification(
                    _payload: dict[str, Any],
                ) -> dict[str, Any]:
                    operation_context.cancel("deadline_expired")
                    return {"fixture": "verified"}

                with (
                    mock.patch.object(
                        protocol,
                        "validate_launch_authority_witness_request",
                        return_value={"fixture": "request"},
                    ),
                    mock.patch.object(
                        client,
                        "_post_json",
                        return_value=b"{}",
                    ),
                    mock.patch.object(
                        protocol,
                        "require_canonical_json_bytes",
                        return_value={"fixture": "canonical"},
                    ),
                    mock.patch.object(
                        protocol,
                        "validate_launch_authority_witness",
                        side_effect=cancel_during_verification,
                    ),
                ):
                    with self.assertRaises(
                        service.AuthorityOperationAborted
                    ) as captured:
                        getattr(client, method_name)(
                            {"fixture": "input"},
                            operation_context=operation_context,
                        )
                self.assertTrue(captured.exception.outcome_unknown)
                self.assertEqual(
                    captured.exception.phase,
                    "witness transition response verification completion",
                )

    def test_witness_response_requires_absolute_deadline_exact_body_and_tls_close(
        self,
    ) -> None:
        exact_body = b"{}"
        for forbidden_header in (
            b"Transfer-Encoding: chunked\r\n",
            b"Content-Encoding: gzip\r\n",
        ):
            with self.subTest(header=forbidden_header), self.assertRaises(
                service.AuthorityConfigurationError
            ):
                service._parse_witness_http_response_head(
                    b"HTTP/1.1 200 OK\r\n"
                    + b"Content-Type: application/test-witness-response+json\r\n"
                    + b"Content-Length: 2\r\n"
                    + b"Connection: close\r\n"
                    + forbidden_header
                    + b"\r\n",
                    expected_content_type=(
                        "application/test-witness-response+json"
                    ),
                )

        with ScriptedWitnessTlsPeer(
            self.pki,
            response_chunks=(witness_http_response(exact_body),),
        ) as peer:
            self.assertEqual(
                self._post_to_scripted_witness(
                    peer,
                    timeout_seconds=0.5,
                ),
                exact_body,
            )
            self.assertTrue(peer.received_request)

        full_response = witness_http_response(exact_body)
        with ScriptedWitnessTlsPeer(
            self.pki,
            response_chunks=tuple(bytes((byte,)) for byte in full_response),
            chunk_delay_seconds=0.01,
        ) as peer:
            self._assert_post_dispatch_outcome_unknown(
                peer,
                timeout_seconds=0.2,
            )

        trickled_body = b"x" * 32
        response_head, _separator, _body = witness_http_response(
            trickled_body
        ).partition(b"\r\n\r\n")
        with ScriptedWitnessTlsPeer(
            self.pki,
            response_chunks=(
                response_head + b"\r\n\r\n",
                *(bytes((byte,)) for byte in trickled_body),
            ),
            chunk_delay_seconds=0.01,
        ) as peer:
            self._assert_post_dispatch_outcome_unknown(
                peer,
                timeout_seconds=0.2,
            )

        with ScriptedWitnessTlsPeer(
            self.pki,
            response_chunks=(witness_http_response(exact_body),),
            withhold_tls_close=True,
        ) as peer:
            self._assert_post_dispatch_outcome_unknown(
                peer,
                timeout_seconds=0.2,
            )

        with ScriptedWitnessTlsPeer(
            self.pki,
            response_chunks=(
                witness_http_response(exact_body),
                b"x",
            ),
            chunk_delay_seconds=0.01,
        ) as peer:
            self._assert_post_dispatch_outcome_unknown(
                peer,
                timeout_seconds=0.5,
            )

        malformed_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/test-witness-response+json\r\n"
            b"Content-Length: 2\r\n"
            b"Connection: close\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            + exact_body
        )
        with ScriptedWitnessTlsPeer(
            self.pki,
            response_chunks=(malformed_response,),
        ) as peer:
            self._assert_post_dispatch_outcome_unknown(
                peer,
                timeout_seconds=0.5,
            )

        with ScriptedWitnessTlsPeer(
            self.pki,
            response_chunks=(witness_http_response(exact_body),),
            abrupt_tcp_close=True,
        ) as peer:
            self._assert_post_dispatch_outcome_unknown(
                peer,
                timeout_seconds=0.5,
            )

    def test_listener_lease_forbids_overlap_and_allows_ordered_restart(
        self,
    ) -> None:
        first = authority_server(self.engine, self.pki)
        try:
            with self.assertRaisesRegex(
                service.AuthorityConfigurationError,
                "another launch-authority listener.*overlapping listeners",
            ):
                authority_server(self.fixture.engine(), self.pki)
        finally:
            first.server_close()

        replacement = authority_server(self.fixture.engine(), self.pki)
        replacement.server_close()

    def test_https_endpoint_requires_mtls_and_exact_canonical_post(self) -> None:
        raw = canonical_request(self.entry, nonce="1")
        with RunningServer(authority_server(self.engine, self.pki)) as running:
            status, headers, body = https_request(
                running.port, self.pki.client_context(), body=raw
            )
            self.assertEqual(status, 200)
            self.assertEqual(
                [value for name, value in headers if name.lower() == "content-type"],
                [service.RESPONSE_CONTENT_TYPE],
            )
            self.assertEqual(protocol.canonical_json_bytes(json.loads(body)), body)

            status, _headers, error = https_request(
                running.port,
                self.pki.client_context(alternate_certificate=True),
                body=canonical_request(self.entry, nonce="9"),
            )
            self.assertEqual(status, 403)
            self.assertEqual(
                json.loads(error)["code"],
                "RELAY_CLIENT_CERTIFICATE_MISMATCH",
            )

            status, _headers, error = https_request(
                running.port,
                self.pki.client_context(),
                body=json.dumps(json.loads(raw), indent=2).encode("ascii"),
            )
            self.assertEqual(status, 400)
            self.assertEqual(json.loads(error)["code"], "INVALID_REQUEST")

            status, _headers, error = https_request(
                running.port,
                self.pki.client_context(),
                body=canonical_request(self.entry, nonce="2"),
                content_type="application/json",
            )
            self.assertEqual(status, 415)
            self.assertEqual(json.loads(error)["code"], "CONTENT_TYPE_INVALID")

            status, headers, _error = https_request(
                running.port,
                self.pki.client_context(),
                body=b"",
                method="GET",
            )
            self.assertEqual(status, 405)
            self.assertFalse(any(name.lower() == "location" for name, _ in headers))

            with self.assertRaises((ssl.SSLError, OSError, http.client.HTTPException)):
                https_request(
                    running.port,
                    self.pki.client_context(include_certificate=False),
                    body=canonical_request(self.entry, nonce="3"),
                )
            with self.assertRaises((ssl.SSLError, OSError, http.client.HTTPException)):
                https_request(
                    running.port,
                    self.pki.client_context(ca_path=self.pki.other_ca_path),
                    body=canonical_request(self.entry, nonce="4"),
                )

    def test_partial_tls_uses_handshake_capacity_not_issuance_capacity(self) -> None:
        server = authority_server(
            self.engine,
            self.pki,
            max_handshakes=2,
            max_handshakes_per_ip=2,
            max_issuance_workers=1,
            max_issuance_workers_per_ip=1,
            handshake_deadline_seconds=0.2,
            connection_deadline_seconds=0.5,
        )
        with RunningServer(server) as running:
            partial_tls = socket.create_connection(("127.0.0.1", running.port))
            partial_tls.sendall(b"\x16\x03")
            worker_deadline = time.monotonic() + 1
            while server.active_handshakes != 1:
                self.assertLess(time.monotonic(), worker_deadline)
                time.sleep(0.005)
            self.assertEqual(server.active_issuance_workers, 0)

            status, _headers, _body = https_request(
                running.port,
                self.pki.client_context(),
                body=canonical_request(self.entry, nonce="a"),
                timeout=0.5,
            )
            self.assertEqual(status, 200)
            self.assertEqual(server.peak_issuance_workers, 1)
            self.assertGreaterEqual(server.peak_handshakes, 1)
            time.sleep(0.25)
            partial_tls.close()
            self.assertEqual(server.active_handshakes, 0)
            self.assertEqual(server.active_issuance_workers, 0)

    def test_source_allowlist_precedes_slots_and_is_required_at_startup(self) -> None:
        for invalid in (
            (),
            ("127.0.0.1/24",),
            ("127.0.0.1/32", "127.0.0.1/32"),
            ("127.0.0.1",),
        ):
            with (
                self.subTest(cidrs=invalid),
                self.assertRaises(service.AuthorityConfigurationError),
            ):
                authority_server(
                    self.engine,
                    self.pki,
                    allowed_source_cidrs=invalid,
                )

        server = authority_server(
            self.engine,
            self.pki,
            allowed_source_cidrs=("127.0.0.1/32", "::1/128"),
            max_handshakes=1,
            max_handshakes_per_ip=1,
            max_issuance_workers=1,
            max_issuance_workers_per_ip=1,
        )
        client, rejected = socket.socketpair()
        try:
            server.process_request(rejected, ("192.0.2.1", 12345))
            self.assertEqual(server.rejected_source_count, 1)
            self.assertEqual(server.active_handshakes, 0)
            self.assertEqual(server.active_issuance_workers, 0)
        finally:
            client.close()
            rejected.close()
            server.server_close()
        self.assertIn(
            "upstream firewall/routing policy", service.NETWORK_ADMISSION_BOUNDARY
        )

    def test_per_ip_handshake_limit_rejects_excess_partial_tls(self) -> None:
        server = authority_server(
            self.engine,
            self.pki,
            max_handshakes=2,
            max_handshakes_per_ip=1,
            max_issuance_workers=1,
            max_issuance_workers_per_ip=1,
            handshake_deadline_seconds=0.2,
            connection_deadline_seconds=0.5,
        )
        with RunningServer(server) as running:
            first = socket.create_connection(("127.0.0.1", running.port))
            first.sendall(b"\x16\x03")
            worker_deadline = time.monotonic() + 1
            while server.active_handshakes != 1:
                self.assertLess(time.monotonic(), worker_deadline)
                time.sleep(0.005)
            second = socket.create_connection(("127.0.0.1", running.port))
            second.sendall(b"\x16\x03")
            second.settimeout(0.5)
            with self.assertRaises(OSError):
                if second.recv(1) == b"":
                    raise OSError("excess per-IP handshake was closed")
            self.assertEqual(server.active_handshakes, 1)
            self.assertEqual(server.active_issuance_workers, 0)
            first.close()
            second.close()
            time.sleep(0.25)
            self.assertEqual(server.active_handshakes, 0)

    def test_authority_absolute_deadline_covers_headers_body_and_response(
        self,
    ) -> None:
        server = authority_server(
            self.engine,
            self.pki,
            max_issuance_workers=1,
            max_issuance_workers_per_ip=1,
            handshake_deadline_seconds=0.2,
            connection_deadline_seconds=0.25,
        )
        with RunningServer(server) as running:
            tls_socket = self.pki.client_context().wrap_socket(
                socket.create_connection(("127.0.0.1", running.port)),
                server_hostname="localhost",
            )
            partial_body = canonical_request(self.entry, nonce="c")
            headers = (
                f"POST {service.AUTHORIZATION_PATH} HTTP/1.1\r\n"
                f"Host: localhost\r\n"
                f"Content-Type: {service.REQUEST_CONTENT_TYPE}\r\n"
                f"Content-Length: {len(partial_body)}\r\n\r\n"
            ).encode("ascii")
            tls_socket.sendall(headers + partial_body[:1])
            with self.assertRaises((ssl.SSLError, OSError, http.client.HTTPException)):
                https_request(
                    running.port,
                    self.pki.client_context(),
                    body=canonical_request(self.entry, nonce="f"),
                    timeout=0.5,
                )
            time.sleep(0.3)
            tls_socket.settimeout(0.2)
            with self.assertRaises((OSError, ssl.SSLError)):
                if tls_socket.recv(1) == b"":
                    raise OSError("authority closed the expired connection")
            tls_socket.close()

            original_issue = self.engine.issue

            def slow_issue(*args: Any, **kwargs: Any) -> bytes:
                time.sleep(0.3)
                return original_issue(*args, **kwargs)

            with mock.patch.object(self.engine, "issue", side_effect=slow_issue):
                with self.assertRaises(
                    (ssl.SSLError, OSError, http.client.HTTPException)
                ):
                    https_request(
                        running.port,
                        self.pki.client_context(),
                        body=canonical_request(self.entry, nonce="d"),
                        timeout=1,
                    )
            worker_deadline = time.monotonic() + 1
            while server.active_issuance_workers:
                self.assertLess(time.monotonic(), worker_deadline)
                time.sleep(0.01)
            self.assertEqual(server.peak_issuance_workers, 1)

    def test_disconnect_and_pipelined_extra_data_cancel_blocked_issuance(
        self,
    ) -> None:
        cases = (
            (
                "disconnect",
                self.fixture.entry("a", sequence=1, epoch=0),
                "7",
                None,
                "client_disconnected",
            ),
            (
                "pipelined-extra-data",
                self.fixture.entry("b", sequence=2, epoch=0),
                "8",
                b"GET /forbidden HTTP/1.1\r\nHost: localhost\r\n\r\n",
                "unexpected_client_data",
            ),
        )
        for label, entry, nonce, extra, expected_reason in cases:
            with self.subTest(label=label):
                raw = canonical_request(entry, nonce=nonce)
                entered = threading.Event()
                contexts: list[service.AuthorityOperationContext] = []

                def blocked_witness(
                    _request: dict[str, Any],
                    *,
                    operation_context: service.AuthorityOperationContext,
                ) -> dict[str, Any]:
                    contexts.append(operation_context)
                    entered.set()
                    while not operation_context.cancelled:
                        time.sleep(0.001)
                    operation_context.assert_active(
                        "blocked HTTPS witness",
                        outcome_unknown=True,
                    )
                    raise AssertionError("cancelled HTTPS witness returned")

                server = authority_server(
                    self.engine,
                    self.pki,
                    connection_deadline_seconds=1.0,
                )
                with (
                    mock.patch.object(
                        self.fixture.monotonic_witness,
                        "authorize_transition",
                        side_effect=blocked_witness,
                    ),
                    RunningServer(server) as running,
                ):
                    tls_socket = self.pki.client_context().wrap_socket(
                        socket.create_connection(("127.0.0.1", running.port)),
                        server_hostname="localhost",
                    )
                    headers = (
                        f"POST {service.AUTHORIZATION_PATH} HTTP/1.1\r\n"
                        "Host: localhost\r\n"
                        f"Content-Type: {service.REQUEST_CONTENT_TYPE}\r\n"
                        f"Content-Length: {len(raw)}\r\n\r\n"
                    ).encode("ascii")
                    tls_socket.sendall(headers + raw)
                    self.assertTrue(entered.wait(timeout=1.0))
                    if extra is None:
                        tls_socket.close()
                    else:
                        tls_socket.sendall(extra)
                        tls_socket.settimeout(1.0)
                        try:
                            tls_socket.recv(1)
                        except (OSError, ssl.SSLError):
                            pass
                        finally:
                            tls_socket.close()

                    worker_deadline = time.monotonic() + 1.0
                    while server.active_issuance_workers:
                        self.assertLess(time.monotonic(), worker_deadline)
                        time.sleep(0.005)
                    self.assertEqual(server.active_issuance_workers, 0)
                    self.assertEqual(len(contexts), 1)
                    self.assertEqual(contexts[0].reason, expected_reason)

                self.assertFalse(
                    any(
                        thread.name
                        == "launch-authority-disconnect-monitor"
                        and thread.is_alive()
                        for thread in threading.enumerate()
                    )
                )
                request = protocol.require_canonical_json_bytes(raw)
                connection = self.engine.ledger.connect()
                try:
                    operation = connection.execute(
                        """
                        SELECT state FROM issuance_operations
                        WHERE operation_id = ?
                        """,
                        (request["launcherNonce"],),
                    ).fetchone()
                    self.assertEqual(operation["state"], "prepared")
                finally:
                    connection.close()

                recovered = issue_authorization(
                    self.engine,
                    raw,
                    now=NOW + 1,
                    peer_certificate_sha256=self.client_certificate_sha256,
                )
                protocol.validate_launch_authorization(
                    protocol.require_canonical_json_bytes(recovered)
                )

    def test_relay_forwards_exact_bytes_over_tls13_mtls(self) -> None:
        raw = canonical_request(self.entry, nonce="5")
        with RunningServer(authority_server(self.engine, self.pki)) as running:
            configuration = self.relay_configuration(running.port)
            with mock.patch.object(
                relay.socket,
                "getaddrinfo",
                side_effect=AssertionError("per-launch DNS resolution is forbidden"),
            ):
                response = relay.forward_authorization_request(raw, configuration)
        self.assertEqual(
            response,
            issue_authorization(
                self.engine,
                raw,
                peer_certificate_sha256=self.pki.certificate_sha256(
                    self.pki.client_certificate
                ),
            ),
        )
        protocol.validate_launch_authorization(
            protocol.require_canonical_json_bytes(response)
        )

    def test_relay_rejects_redirect_status_content_type_and_noncanonical_response(
        self,
    ) -> None:
        raw = canonical_request(self.entry, nonce="6")
        valid_response = issue_authorization(
            self.engine,
            raw,
            peer_certificate_sha256=self.pki.certificate_sha256(
                self.pki.client_certificate
            ),
        )
        cases = (
            (302, relay.RESPONSE_CONTENT_TYPE, valid_response, "REMOTE_STATUS_INVALID"),
            (503, relay.RESPONSE_CONTENT_TYPE, valid_response, "REMOTE_STATUS_INVALID"),
            (
                200,
                "application/octet-stream",
                valid_response,
                "REMOTE_CONTENT_TYPE_INVALID",
            ),
            (
                200,
                relay.RESPONSE_CONTENT_TYPE,
                json.dumps(json.loads(valid_response), indent=2).encode("ascii"),
                "REMOTE_RESPONSE_INVALID",
            ),
        )
        for status, content_type, body, code in cases:
            with (
                self.subTest(status=status, content_type=content_type),
                ScriptedAuthorityServer(
                    self.pki, status=status, content_type=content_type, body=body
                ) as scripted,
            ):
                with self.assertRaises(relay.RelayError) as caught:
                    relay.forward_authorization_request(
                        raw, self.relay_configuration(scripted.port)
                    )
                self.assertEqual(caught.exception.code, code)

    def test_relay_preserves_request_and_response_bytes_and_enforces_timeout(
        self,
    ) -> None:
        raw = canonical_request(self.entry, nonce="7")
        response = issue_authorization(
            self.engine,
            raw,
            peer_certificate_sha256=self.pki.certificate_sha256(
                self.pki.client_certificate
            ),
        )
        with ScriptedAuthorityServer(self.pki, body=response) as scripted:
            returned = relay.forward_authorization_request(
                raw, self.relay_configuration(scripted.port)
            )
            self.assertEqual(scripted.received, [raw])
            self.assertEqual(returned, response)

        with ScriptedAuthorityServer(
            self.pki, body=response, delay_seconds=0.25
        ) as scripted:
            with self.assertRaises(relay.RelayError) as caught:
                relay.forward_authorization_request(
                    raw, self.relay_configuration(scripted.port, timeout=0.05)
                )
            self.assertEqual(caught.exception.code, "REMOTE_DEADLINE_EXCEEDED")

        with ScriptedAuthorityServer(
            self.pki,
            body=response,
            body_chunk_delay_seconds=0.02,
            body_chunk_size=32,
        ) as scripted:
            started = time.monotonic()
            with self.assertRaises(relay.RelayError) as caught:
                relay.forward_authorization_request(
                    raw, self.relay_configuration(scripted.port, timeout=0.1)
                )
            self.assertEqual(caught.exception.code, "REMOTE_DEADLINE_EXCEEDED")
            self.assertLess(time.monotonic() - started, 0.3)

    def test_relay_configuration_has_pinned_https_identity_and_secure_client_key(
        self,
    ) -> None:
        with self.assertRaises(relay.RelayConfigurationError):
            relay.RelayConfiguration(
                authority_url=f"http://localhost:443{relay.AUTHORIZATION_PATH}",
                server_name="localhost",
                ca_certificate=self.pki.ca_path,
                client_certificate=self.pki.client_certificate_path,
                client_private_key=self.pki.client_key_path,
            )
        with self.assertRaisesRegex(relay.RelayConfigurationError, "exactly match"):
            relay.RelayConfiguration(
                authority_url=f"https://localhost:443{relay.AUTHORIZATION_PATH}",
                server_name="authority.example",
                ca_certificate=self.pki.ca_path,
                client_certificate=self.pki.client_certificate_path,
                client_private_key=self.pki.client_key_path,
            )
        self.pki.client_key_path.chmod(0o644)
        with self.assertRaisesRegex(relay.RelayConfigurationError, "0400 or 0600"):
            self.relay_configuration(443)

    def test_tls_material_rejects_untrusted_or_symlinked_ancestors(self) -> None:
        real_directory = self.root / "real-tls"
        real_directory.mkdir(mode=0o700)
        copied_ca = real_directory / "ca.pem"
        copied_server_certificate = real_directory / "server.pem"
        shutil.copy2(self.pki.ca_path, copied_ca)
        shutil.copy2(self.pki.server_certificate_path, copied_server_certificate)
        alias = self.root / "tls-alias"
        alias.symlink_to(real_directory, target_is_directory=True)

        with self.assertRaisesRegex(
            relay.RelayConfigurationError, "ancestor must be a real directory"
        ):
            relay.RelayConfiguration(
                authority_url=(f"https://localhost:443{relay.AUTHORIZATION_PATH}"),
                server_name="localhost",
                ca_certificate=alias / "ca.pem",
                client_certificate=self.pki.client_certificate_path,
                client_private_key=self.pki.client_key_path,
            )
        with self.assertRaisesRegex(
            service.AuthorityConfigurationError,
            "ancestor must be a real directory",
        ):
            service.create_https_server(
                ("127.0.0.1", 0),
                authority=self.engine,
                server_certificate=alias / "server.pem",
                server_private_key=self.pki.server_key_path,
                client_ca_certificate=self.pki.ca_path,
                allowed_source_cidrs=("127.0.0.1/32",),
            )

        writable_directory = self.root / "writable-tls"
        writable_directory.mkdir(mode=0o700)
        writable_directory.chmod(0o777)
        writable_ca = writable_directory / "ca.pem"
        shutil.copy2(self.pki.ca_path, writable_ca)
        with self.assertRaisesRegex(
            relay.RelayConfigurationError, "ancestor is not trusted"
        ):
            relay.RelayConfiguration(
                authority_url=(f"https://localhost:443{relay.AUTHORIZATION_PATH}"),
                server_name="localhost",
                ca_certificate=writable_ca,
                client_certificate=self.pki.client_certificate_path,
                client_private_key=self.pki.client_key_path,
            )

    def test_tls_material_is_stable_across_python_ssl_path_loads(self) -> None:
        service_reader = service._read_stable_regular_file
        service_certificate_reads = 0

        def unstable_service_reader(*args: Any, **kwargs: Any) -> bytes:
            nonlocal service_certificate_reads
            value = service_reader(*args, **kwargs)
            if kwargs["label"] == "authority TLS server certificate":
                service_certificate_reads += 1
                if service_certificate_reads == 2:
                    return value + b"\n"
            return value

        with (
            mock.patch.object(
                service,
                "_read_stable_regular_file",
                side_effect=unstable_service_reader,
            ),
            self.assertRaisesRegex(
                service.AuthorityConfigurationError,
                "changed while the TLS context was created",
            ),
        ):
            service.create_https_server(
                ("127.0.0.1", 0),
                authority=self.engine,
                server_certificate=self.pki.server_certificate_path,
                server_private_key=self.pki.server_key_path,
                client_ca_certificate=self.pki.ca_path,
                allowed_source_cidrs=("127.0.0.1/32",),
            )

        configuration = self.relay_configuration(443)
        relay_reader = relay._read_stable_regular_file
        relay_ca_reads = 0

        def unstable_relay_reader(*args: Any, **kwargs: Any) -> bytes:
            nonlocal relay_ca_reads
            value = relay_reader(*args, **kwargs)
            if kwargs["label"] == "authority CA certificate":
                relay_ca_reads += 1
                if relay_ca_reads == 2:
                    return value + b"\n"
            return value

        with (
            mock.patch.object(
                relay,
                "_read_stable_regular_file",
                side_effect=unstable_relay_reader,
            ),
            self.assertRaisesRegex(
                relay.RelayConfigurationError,
                "changed while the TLS context was created",
            ),
        ):
            configuration.tls_context()

    def test_seqpacket_framing_size_and_single_packet_byte_preservation(self) -> None:
        packet_type = getattr(socket, "SOCK_SEQPACKET", socket.SOCK_DGRAM)
        try:
            probe = socket.socketpair(socket.AF_UNIX, packet_type)
        except OSError:
            packet_type = socket.SOCK_DGRAM
            probe = socket.socketpair(socket.AF_UNIX, packet_type)
        probe[0].close()
        probe[1].close()
        configuration = self.relay_configuration(443)
        raw = canonical_request(self.entry, nonce="8")
        response = issue_authorization(
            self.engine,
            raw,
            peer_certificate_sha256=self.pki.certificate_sha256(
                self.pki.client_certificate
            ),
        )
        client, server = socket.socketpair(socket.AF_UNIX, packet_type)
        try:
            worker_error: list[BaseException] = []

            def worker() -> None:
                try:
                    relay.serve_connection(
                        server,
                        configuration,
                        forwarder=lambda value, _configuration: (
                            response if value == raw else b""
                        ),
                        enforce_root_peer=False,
                    )
                except BaseException as exc:
                    worker_error.append(exc)

            thread = threading.Thread(target=worker, daemon=True)
            thread.start()
            self.assertEqual(client.send(raw), len(raw))
            self.assertEqual(client.recv(relay.MAX_PACKET_BYTES), response)
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(worker_error, [])
        finally:
            client.close()
            server.close()

    def test_relay_worker_pool_is_concurrent_and_strictly_bounded(self) -> None:
        packet_type = getattr(socket, "SOCK_SEQPACKET", socket.SOCK_DGRAM)
        try:
            probe = socket.socketpair(socket.AF_UNIX, packet_type)
        except OSError:
            packet_type = socket.SOCK_DGRAM
            probe = socket.socketpair(socket.AF_UNIX, packet_type)
        probe[0].close()
        probe[1].close()

        raw = canonical_request(self.entry, nonce="e")
        response = issue_authorization(
            self.engine,
            raw,
            peer_certificate_sha256=self.client_certificate_sha256,
        )
        pool = relay.BoundedRelayWorkerPool(max_workers=2)
        entered = threading.Barrier(3)
        release = threading.Event()

        def blocking_forwarder(
            value: bytes, _configuration: relay.RelayConfiguration
        ) -> bytes:
            self.assertEqual(value, raw)
            entered.wait(timeout=2)
            self.assertTrue(release.wait(timeout=2))
            return response

        pairs = [socket.socketpair(socket.AF_UNIX, packet_type) for _index in range(3)]
        try:
            configuration = self.relay_configuration(443)
            for client, server_socket in pairs[:2]:
                self.assertTrue(
                    pool.submit(
                        server_socket,
                        configuration,
                        forwarder=blocking_forwarder,
                        enforce_root_peer=False,
                    )
                )
                self.assertEqual(client.send(raw), len(raw))
            entered.wait(timeout=2)
            self.assertEqual(pool.active_workers, 2)
            self.assertEqual(pool.peak_workers, 2)
            self.assertFalse(
                pool.submit(
                    pairs[2][1],
                    configuration,
                    forwarder=blocking_forwarder,
                    enforce_root_peer=False,
                )
            )
            release.set()
            for client, _server_socket in pairs[:2]:
                self.assertEqual(client.recv(relay.MAX_PACKET_BYTES), response)
            self.assertTrue(pool.wait_for_idle(2))
            self.assertEqual(pool.peak_workers, 2)
        finally:
            release.set()
            for client, server_socket in pairs:
                client.close()
                server_socket.close()

        class OversizedPacket:
            def recvmsg(self, _size: int) -> tuple[bytes, list[Any], int, None]:
                return b"x" * (relay.MAX_PACKET_BYTES + 1), [], 0, None

        with self.assertRaises(relay.RelayError) as caught:
            relay.receive_packet(OversizedPacket())  # type: ignore[arg-type]
        self.assertEqual(caught.exception.code, "FRAME_INVALID")

        client, server = socket.socketpair(socket.AF_UNIX, packet_type)
        try:
            server.settimeout(0.03)
            with self.assertRaises(relay.RelayError) as caught:
                relay.receive_packet(server)
            self.assertEqual(caught.exception.code, "LOCAL_RECEIVE_FAILED")
        finally:
            client.close()
            server.close()

    def test_systemd_units_pin_root_seqpacket_and_harden_relay(self) -> None:
        socket_unit = (
            ROOT / "ops/systemd/catchplate-launch-authority-relay.socket"
        ).read_text(encoding="utf-8")
        service_unit = (
            ROOT / "ops/systemd/catchplate-launch-authority-relay.service"
        ).read_text(encoding="utf-8")
        for expected in (
            "ListenSequentialPacket=/run/catchplate/launch-authority.sock",
            "SocketMode=0600",
            "SocketUser=root",
            "SocketGroup=root",
            "DirectoryMode=0711",
        ):
            self.assertIn(expected, socket_unit)
        for expected in (
            "User=catchplate-launch-authority-relay",
            "Group=catchplate-launch-authority-relay",
            "UMask=0077",
            "EnvironmentFile=/etc/catchplate/launch-authority-relay.env",
            "NoNewPrivileges=yes",
            "CapabilityBoundingSet=",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "PrivateDevices=yes",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
            "MemoryDenyWriteExecute=yes",
            "/usr/bin/python3 -I ",
            "client private key must be owned by this account with mode 0400 or 0600",
            "SO_PEERCRED",
            "TimeoutStartSec=10s",
        ):
            self.assertIn(expected, service_unit)
        self.assertNotIn("User=root", service_unit)
        self.assertNotIn("Group=root", service_unit)
        self.assertNotIn("/bin/sh", service_unit)
        self.assertNotIn("authority-public-key", service_unit)
        self.assertNotIn("authority-signing-key", service_unit)
        self.assertNotIn("SSL_CERT_FILE=", service_unit)

    def test_entry_points_resolve_protocol_sibling_under_isolated_python(self) -> None:
        for relative_path in (
            "scripts/launch_authority_service.py",
            "scripts/launch_authority_relay.py",
        ):
            result = subprocess.run(
                [sys.executable, "-I", str(ROOT / relative_path), "--help"],
                cwd=self.root,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
                check=False,
            )
            with self.subTest(path=relative_path):
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("usage:", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
