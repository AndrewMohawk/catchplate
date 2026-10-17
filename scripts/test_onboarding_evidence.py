#!/usr/bin/env python3
from __future__ import annotations

import base64
import contextlib
import copy
import errno
import hashlib
import hmac
import importlib.util
import io
import json
import os
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
import zlib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock
from urllib.parse import quote

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

SCRIPT = Path(__file__).with_name("verify_onboarding_evidence.py")
SPEC = importlib.util.spec_from_file_location("verify_onboarding_evidence", SCRIPT)
assert SPEC and SPEC.loader
evidence = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = evidence
SPEC.loader.exec_module(evidence)

REQUESTER = "operator:requester"
REVIEWER = "operator:reviewer"
GMAIL_CREDENTIAL = "credential:gmail"
X_CREDENTIAL = "credential:x"
NPM_CREDENTIAL = "credential:npm"
CAPTURE_START = int(
    datetime(2026, 7, 27, 11, 59, tzinfo=timezone.utc).timestamp()
)
CAPTURE_END = int(
    datetime(2026, 7, 27, 12, 5, tzinfo=timezone.utc).timestamp()
)
GMAIL_CAPTURE = int(
    datetime(2026, 7, 27, 12, 0, tzinfo=timezone.utc).timestamp()
)
X_CAPTURE = int(
    datetime(2026, 7, 27, 12, 3, tzinfo=timezone.utc).timestamp()
)
JIT_CHALLENGE = int(
    datetime(2026, 7, 27, 12, 3, 10, tzinfo=timezone.utc).timestamp()
)
AUTH_VALID_FROM = int(
    datetime(2026, 7, 27, 13, 0, tzinfo=timezone.utc).timestamp()
)
AUTH_VALID_UNTIL = AUTH_VALID_FROM + 300
AUTH_VERIFY_TIME = AUTH_VALID_FROM + 30
AUTH_SIGNER = "signer:onboarding-production-1"
AUTH_VERIFIER = "verifier:independent-auditor-1"
AUTH_CHALLENGE = bytes(range(32))
TEST_AUTHENTICATED_SIGNATURE_DOMAIN = (
    b"catchplate.onboardingEvidenceVerifierEnvelope/v1\x00"
)
TEST_P256_ORDER = (
    0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
)
TEST_P256_FIELD = (
    0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
)
TEST_P256_A = TEST_P256_FIELD - 3
TEST_P256_GENERATOR = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)
RFC6979_P256_PRIVATE_SCALAR = int(
    "C9AFA9D845BA75166B5C215767B1D6934"
    "E50C3DB36E89B127B8A622B120F6721",
    16,
)

REFERENCE_PATHS = [
    "source/enrollment.packet",
    "source/gmail-request.http",
    "source/gmail-response.http",
    "source/npm-challenge.request",
    "source/npm-challenge.response",
    "source/npm-retry.request",
    "source/npm-retry.response",
    "source/policy.json",
    "source/webauthn-authenticator-data.bin",
    "source/webauthn-client-data.json",
    "source/webauthn-public-key.pem",
    "source/webauthn-signature.der",
    "source/x-post-1-request.http",
    "source/x-post-1-response.http",
    "source/x-post-2-request.http",
    "source/x-post-2-response.http",
    "source/x-post-counter.json",
    "source/x-search-request.http",
    "source/x-search-response.http",
]
SOURCE_PATHS = sorted([*REFERENCE_PATHS, "source/journey.py"])


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def public_key_sha256(
    public_key: ec.EllipticCurvePublicKey,
) -> str:
    encoded = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256(encoded)


def low_s_signature(
    private_key: ec.EllipticCurvePrivateKey,
    message: bytes,
) -> bytes:
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    r_value, s_value = decode_dss_signature(signature)
    if s_value > TEST_P256_ORDER // 2:
        s_value = TEST_P256_ORDER - s_value
    return encode_dss_signature(r_value, s_value)


def test_authenticated_signature_payload(
    statement: dict[str, object],
) -> bytes:
    return TEST_AUTHENTICATED_SIGNATURE_DOMAIN + canonical_json(
        {
            "apiVersion": (
                "catchplate.onboardingEvidenceVerifierEnvelope/v1"
            ),
            "signedStatement": statement,
        }
    )


def base64url_without_padding(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def independent_p256_add(
    left: tuple[int, int] | None,
    right: tuple[int, int] | None,
) -> tuple[int, int] | None:
    if left is None:
        return right
    if right is None:
        return left
    left_x, left_y = left
    right_x, right_y = right
    if left_x == right_x and (left_y + right_y) % TEST_P256_FIELD == 0:
        return None
    if left == right:
        slope = (
            (3 * left_x * left_x + TEST_P256_A)
            * pow(2 * left_y, -1, TEST_P256_FIELD)
        ) % TEST_P256_FIELD
    else:
        slope = (
            (right_y - left_y)
            * pow(right_x - left_x, -1, TEST_P256_FIELD)
        ) % TEST_P256_FIELD
    result_x = (slope * slope - left_x - right_x) % TEST_P256_FIELD
    result_y = (slope * (left_x - result_x) - left_y) % TEST_P256_FIELD
    return result_x, result_y


def independent_p256_multiply(
    scalar: int,
    point: tuple[int, int],
) -> tuple[int, int]:
    result: tuple[int, int] | None = None
    addend: tuple[int, int] | None = point
    while scalar:
        if scalar & 1:
            result = independent_p256_add(result, addend)
        addend = independent_p256_add(addend, addend)
        scalar >>= 1
    if result is None:
        raise AssertionError("P-256 scalar multiplication produced infinity")
    return result


def independent_rfc6979_nonce(
    private_scalar: int,
    digest: bytes,
) -> int:
    private_octets = private_scalar.to_bytes(32, "big")
    digest_integer = int.from_bytes(digest, "big")
    digest_octets = (digest_integer % TEST_P256_ORDER).to_bytes(32, "big")
    value = b"\x01" * 32
    key = b"\x00" * 32
    key = hmac.new(
        key,
        value + b"\x00" + private_octets + digest_octets,
        hashlib.sha256,
    ).digest()
    value = hmac.new(key, value, hashlib.sha256).digest()
    key = hmac.new(
        key,
        value + b"\x01" + private_octets + digest_octets,
        hashlib.sha256,
    ).digest()
    value = hmac.new(key, value, hashlib.sha256).digest()
    while True:
        value = hmac.new(key, value, hashlib.sha256).digest()
        candidate = int.from_bytes(value, "big")
        if 1 <= candidate < TEST_P256_ORDER:
            return candidate
        key = hmac.new(key, value + b"\x00", hashlib.sha256).digest()
        value = hmac.new(key, value, hashlib.sha256).digest()


def independent_der_integer(value: int) -> bytes:
    encoded = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return b"\x02" + bytes([len(encoded)]) + encoded


def independent_rfc6979_es256_signature(
    private_scalar: int,
    message: bytes,
) -> bytes:
    digest = hashlib.sha256(message).digest()
    nonce = independent_rfc6979_nonce(private_scalar, digest)
    nonce_point = independent_p256_multiply(nonce, TEST_P256_GENERATOR)
    r_value = nonce_point[0] % TEST_P256_ORDER
    s_value = (
        pow(nonce, -1, TEST_P256_ORDER)
        * (int.from_bytes(digest, "big") + r_value * private_scalar)
    ) % TEST_P256_ORDER
    if s_value > TEST_P256_ORDER // 2:
        s_value = TEST_P256_ORDER - s_value
    encoded = independent_der_integer(r_value) + independent_der_integer(s_value)
    return b"\x30" + bytes([len(encoded)]) + encoded


def independent_public_key_pem(spki_der: bytes) -> bytes:
    encoded = base64.b64encode(spki_der)
    lines = [encoded[index : index + 64] for index in range(0, len(encoded), 64)]
    return (
        b"-----BEGIN PUBLIC KEY-----\n"
        + b"\n".join(lines)
        + b"\n-----END PUBLIC KEY-----\n"
    )


def png_chunk(kind: bytes, data: bytes) -> bytes:
    checksum = zlib.crc32(kind)
    checksum = zlib.crc32(data, checksum) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", checksum)


def png_bytes(
    width: int,
    height: int,
    *,
    color_type: int = 6,
    interlace: int = 0,
    filter_byte: int = 0,
    before_idat: tuple[tuple[bytes, bytes], ...] = (),
    split_idat: bool = False,
    row_override: bytes | None = None,
) -> bytes:
    ihdr = struct.pack(">IIBBBBB", width, height, 8, color_type, 0, 0, interlace)
    pixel = b"\x12\x34\x56" if color_type == 2 else b"\x12\x34\x56\xff"
    rows = (
        row_override
        if row_override is not None
        else b"".join(
            bytes([filter_byte]) + pixel * width for _ in range(height)
        )
    )
    compressed = zlib.compress(rows)
    chunks = [png_chunk(b"IHDR", ihdr)]
    chunks.extend(png_chunk(kind, data) for kind, data in before_idat)
    if split_idat:
        middle = max(1, len(compressed) // 2)
        chunks.extend(
            [
                png_chunk(b"IDAT", compressed[:middle]),
                png_chunk(b"IDAT", compressed[middle:]),
            ]
        )
    else:
        chunks.append(png_chunk(b"IDAT", compressed))
    chunks.append(png_chunk(b"IEND", b""))
    return evidence.PNG_SIGNATURE + b"".join(chunks)


def independent_png_weighted_work(data: bytes) -> int:
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise AssertionError("test PNG is missing its literal signature")
    offset = 8
    chunk_count = 0
    compressed_bytes = 0
    decoded_bytes: int | None = None
    while offset < len(data):
        if offset + 12 > len(data):
            raise AssertionError("test PNG is truncated")
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        chunk_type = data[offset + 4 : offset + 8]
        chunk_data = data[offset + 8 : offset + 8 + length]
        offset += 12 + length
        chunk_count += 1
        if chunk_type == b"IHDR":
            width, height, bit_depth, color_type, _, _, interlace = struct.unpack(
                ">IIBBBBB",
                chunk_data,
            )
            if bit_depth != 8 or color_type not in {2, 6} or interlace != 0:
                raise AssertionError("test PNG is outside the expected static subset")
            channels = 3 if color_type == 2 else 4
            decoded_bytes = height * (width * channels + 1)
        elif chunk_type == b"IDAT":
            compressed_bytes += length
        elif chunk_type == b"IEND":
            break
    if offset != len(data) or decoded_bytes is None:
        raise AssertionError("test PNG layout is incomplete")
    return (
        len(data) * 3
        + compressed_bytes
        + decoded_bytes * 2
        + 1
        + chunk_count * 256
    )


def http_request(
    method: str,
    target: str,
    host: str,
    *,
    body: bytes = b"",
    principal: str | None = None,
    credential: str | None = None,
    extra_headers: dict[str, str] | None = None,
) -> bytes:
    headers = {"host": host}
    if principal is not None:
        headers["x-catchplate-principal"] = principal
    if credential is not None:
        headers["x-catchplate-credential-id"] = credential
    if body:
        headers["content-type"] = "application/json"
        headers["content-length"] = str(len(body))
    headers.update(extra_headers or {})
    lines = [f"{method} {target} HTTP/1.1"]
    lines.extend(f"{key}:{value}" for key, value in headers.items())
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body


def http_response(
    status: int,
    reason: str,
    body_value: object,
    *,
    content_type: str = "application/json",
) -> bytes:
    body = canonical_json(body_value)
    return (
        f"HTTP/1.1 {status} {reason}\r\n"
        f"content-type:{content_type}\r\n"
        f"content-length:{len(body)}\r\n\r\n"
    ).encode("ascii") + body


def valid_policy() -> dict[str, object]:
    return {
        "gmail": {"maximumAgeDays": 30},
        "x": {
            "maximumSearchLookbackDays": 7,
            "maximumPostsPerUtcDay": 1,
        },
    }


def valid_journey() -> dict[str, object]:
    return {
        "ok": True,
        "captureInterval": {
            "startedAtEpochSeconds": CAPTURE_START,
            "endedAtEpochSeconds": CAPTURE_END,
            "timestampsAuthenticated": False,
        },
        "operators": {
            "requesterId": REQUESTER,
            "reviewerId": REVIEWER,
        },
        "oauthApprovals": {
            "google": {
                "approvalId": "approval:google",
                "expectedAccountId": "user@example.com",
                "observedAccountId": "user@example.com",
                "exactAccount": True,
                "requestedBy": REQUESTER,
                "approvedBy": REVIEWER,
                "activatedBy": REQUESTER,
                "credentialId": GMAIL_CREDENTIAL,
            },
            "x": {
                "approvalId": "approval:x",
                "expectedAccountId": "x-user-123",
                "observedAccountId": "x-user-123",
                "exactAccount": True,
                "requestedBy": REQUESTER,
                "approvedBy": REVIEWER,
                "activatedBy": REQUESTER,
                "credentialId": X_CREDENTIAL,
            },
        },
        "oauthActivationChallenges": {
            "google": {
                "status": 428,
                "approvalId": "approval:google",
                "actorId": REQUESTER,
            },
            "x": {
                "status": 428,
                "approvalId": "approval:x",
                "actorId": REQUESTER,
            },
        },
        "policy": {"artifactPath": "source/policy.json"},
        "packet": {"artifactPath": "source/enrollment.packet"},
        "gmail": {
            "requestArtifactPath": "source/gmail-request.http",
            "responseArtifactPath": "source/gmail-response.http",
        },
        "x": {
            "searchRequestArtifactPath": "source/x-search-request.http",
            "searchResponseArtifactPath": "source/x-search-response.http",
            "firstPostRequestArtifactPath": "source/x-post-1-request.http",
            "firstPostResponseArtifactPath": "source/x-post-1-response.http",
            "secondPostRequestArtifactPath": "source/x-post-2-request.http",
            "secondPostResponseArtifactPath": "source/x-post-2-response.http",
            "postCounterArtifactPath": "source/x-post-counter.json",
            "capturedAtEpochSeconds": X_CAPTURE,
            "captureTimeAuthenticated": False,
        },
        "jitApproval": {
            "approvedBy": REVIEWER,
            "approvalRequestId": "approval:npm-write",
            "challengeRequestArtifactPath": "source/npm-challenge.request",
            "retryRequestArtifactPath": "source/npm-retry.request",
            "challengeResponseArtifactPath": "source/npm-challenge.response",
            "retryResponseArtifactPath": "source/npm-retry.response",
            "challengeIssuedAtEpochSeconds": JIT_CHALLENGE,
            "approvedAtEpochSeconds": JIT_CHALLENGE + 5,
            "expiresAtEpochSeconds": JIT_CHALLENGE + 35,
            "retryAtEpochSeconds": JIT_CHALLENGE + 6,
            "webauthn": {
                "credentialId": "webauthn:reviewer:yubikey",
                "clientDataJSONArtifactPath": "source/webauthn-client-data.json",
                "authenticatorDataArtifactPath": (
                    "source/webauthn-authenticator-data.bin"
                ),
                "signatureArtifactPath": "source/webauthn-signature.der",
                "publicKeyArtifactPath": "source/webauthn-public-key.pem",
                "expectedOrigin": "https://catchplate.example",
                "expectedRpId": "catchplate.example",
                "expectedSignatureCounter": 7,
            },
        },
        "unknownRoute": {
            "status": 403,
            "error": "unknown_route_denied",
            "upstreamCalls": 0,
            "credentialLeaseIssued": False,
        },
    }


def approval_challenge(journey: dict[str, object], npm_request: bytes) -> bytes:
    binding = {
        "approvalRequestId": journey["jitApproval"]["approvalRequestId"],
        "approvedBy": journey["jitApproval"]["approvedBy"],
        "principalId": REQUESTER,
        "credentialId": NPM_CREDENTIAL,
        "routeId": "npm.publish",
        "operation": "npm.publish example-package@1.0.0",
        "requestSha256": sha256(npm_request),
        "expiresAtEpochSeconds": journey["jitApproval"]["expiresAtEpochSeconds"],
        "webauthnCredentialId": journey["jitApproval"]["webauthn"]["credentialId"],
    }
    return hashlib.sha256(canonical_json(binding)).digest()


def build_artifacts(
    journey: dict[str, object],
    private_key: ec.EllipticCurvePrivateKey,
) -> dict[str, bytes]:
    gmail_request = http_request(
        "GET",
        "/gmail/v1/users/me/messages?q=newer_than%3A30d&maxResults=100",
        "gmail.googleapis.com",
        principal=REQUESTER,
        credential=GMAIL_CREDENTIAL,
    )
    gmail_response = http_response(
        200,
        "OK",
        {
            "schema": "catchplate.gatewayNormalizedGmailMessages/v1",
            "captureTimeAuthenticated": False,
            "capturedAtEpochSeconds": GMAIL_CAPTURE,
            "messages": [
                {
                    "id": "m1",
                    "internalDateEpochMillis": str(
                        (GMAIL_CAPTURE - 3_600) * 1_000
                    ),
                },
                {
                    "id": "m2",
                    "internalDateEpochMillis": str(
                        (GMAIL_CAPTURE - 29 * 86_400) * 1_000
                    ),
                },
            ],
        },
    )
    x_search_request = http_request(
        "GET",
        (
            "/2/tweets/search/recent?query=catchplate"
            f"&start_time={quote('2026-07-20T12:00:00Z')}"
            f"&end_time={quote('2026-07-27T12:00:00Z')}"
            "&tweet.fields=created_at"
        ),
        "api.x.com",
        principal=REQUESTER,
        credential=X_CREDENTIAL,
    )
    x_search_response = http_response(
        200,
        "OK",
        {
            "data": [
                {"id": "tweet-search-1", "created_at": "2026-07-26T10:00:00Z"}
            ],
            "meta": {"result_count": 1},
        },
    )
    x_post_1_request = http_request(
        "POST",
        "/2/tweets",
        "api.x.com",
        body=canonical_json({"text": "first post"}),
        principal=REQUESTER,
        credential=X_CREDENTIAL,
    )
    x_post_1_response = http_response(
        201,
        "Created",
        {"data": {"id": "tweet-created-1"}},
    )
    x_post_2_request = http_request(
        "POST",
        "/2/tweets",
        "api.x.com",
        body=canonical_json({"text": "second post"}),
        principal=REQUESTER,
        credential=X_CREDENTIAL,
    )
    x_post_2_response = http_response(
        429,
        "Too Many Requests",
        {
            "error": "daily_post_limit",
            "limit": 1,
            "used": 1,
            "utcDay": "2026-07-27",
        },
    )
    x_counter = canonical_json(
        {
            "utcDay": "2026-07-27",
            "limit": 1,
            "events": [
                {
                    "at": "2026-07-27T12:01:00Z",
                    "decision": "accepted",
                    "requestSha256": sha256(x_post_1_request),
                    "responseSha256": sha256(x_post_1_response),
                },
                {
                    "at": "2026-07-27T12:02:00Z",
                    "decision": "denied",
                    "requestSha256": sha256(x_post_2_request),
                    "responseSha256": sha256(x_post_2_response),
                },
            ],
        }
    )
    npm_request = http_request(
        "PUT",
        "/example-package",
        "registry.npmjs.org",
        body=canonical_json({"name": "example-package", "version": "1.0.0"}),
        principal=REQUESTER,
        credential=NPM_CREDENTIAL,
    )
    npm_challenge_response = http_response(
        428,
        "Precondition Required",
        {
            "error": "approval_required",
            "approvalRequestId": "approval:npm-write",
            "upstreamCalls": 0,
        },
    )
    npm_retry_response = http_response(
        201,
        "Created",
        {
            "ok": True,
            "approvalRequestId": "approval:npm-write",
            "upstreamCalls": 1,
        },
    )

    challenge = approval_challenge(journey, npm_request)
    webauthn = journey["jitApproval"]["webauthn"]
    client_data = canonical_json(
        {
            "type": "webauthn.get",
            "challenge": base64.urlsafe_b64encode(challenge)
            .rstrip(b"=")
            .decode("ascii"),
            "origin": webauthn["expectedOrigin"],
            "crossOrigin": False,
        }
    )
    authenticator_data = (
        hashlib.sha256(webauthn["expectedRpId"].encode("utf-8")).digest()
        + b"\x05"
        + struct.pack(">I", webauthn["expectedSignatureCounter"])
    )
    signature = private_key.sign(
        authenticator_data + hashlib.sha256(client_data).digest(),
        ec.ECDSA(hashes.SHA256()),
    )
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "source/policy.json": canonical_json(valid_policy()),
        "source/enrollment.packet": b"signed-enrollment-packet-v1",
        "source/gmail-request.http": gmail_request,
        "source/gmail-response.http": gmail_response,
        "source/x-search-request.http": x_search_request,
        "source/x-search-response.http": x_search_response,
        "source/x-post-1-request.http": x_post_1_request,
        "source/x-post-1-response.http": x_post_1_response,
        "source/x-post-2-request.http": x_post_2_request,
        "source/x-post-2-response.http": x_post_2_response,
        "source/x-post-counter.json": x_counter,
        "source/npm-challenge.request": npm_request,
        "source/npm-retry.request": npm_request,
        "source/npm-challenge.response": npm_challenge_response,
        "source/npm-retry.response": npm_retry_response,
        "source/webauthn-client-data.json": client_data,
        "source/webauthn-authenticator-data.bin": authenticator_data,
        "source/webauthn-signature.der": signature,
        "source/webauthn-public-key.pem": public_key,
    }


class OnboardingEvidenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="catchplate-onboarding-evidence-"
        )
        self.root = Path(self.temporary.name).resolve()
        self.replay_temporary = tempfile.TemporaryDirectory(
            prefix="catchplate-onboarding-replay-"
        )
        self.replay_root = Path(self.replay_temporary.name).resolve()
        self.replay_root.chmod(0o700)
        (self.root / "source").mkdir()
        (self.root / "screens").mkdir()
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.envelope_private_key = ec.generate_private_key(ec.SECP256R1())
        self.write_fixture()

    def tearDown(self) -> None:
        self.replay_temporary.cleanup()
        self.temporary.cleanup()

    def write_fixture(
        self,
        *,
        journey: dict[str, object] | None = None,
        overrides: dict[str, bytes] | None = None,
        private_key: ec.EllipticCurvePrivateKey | None = None,
    ) -> tuple[dict[str, object], dict[str, bytes]]:
        journey = copy.deepcopy(journey or valid_journey())
        artifacts = build_artifacts(journey, private_key or self.private_key)
        artifacts.update(overrides or {})
        (self.root / "source" / "journey.py").write_text(
            "print('journey')\n",
            encoding="utf-8",
        )
        for relative, data in artifacts.items():
            (self.root / relative).write_bytes(data)
        (self.root / "journey.json").write_bytes(canonical_json(journey))
        (self.root / "screens" / "portal.png").write_bytes(png_bytes(3, 2))
        return journey, artifacts

    def create(
        self,
        *,
        output_path: str = "evidence.json",
        source_paths: list[str] | None = None,
        screenshot_paths: list[str] | None = None,
        root: Path | None = None,
    ) -> dict[str, object]:
        return evidence.create_manifest(
            root=root or self.root,
            output_path=output_path,
            journey_path="journey.json",
            source_paths=list(source_paths or SOURCE_PATHS),
            screenshot_paths=list(screenshot_paths or ["screens/portal.png"]),
            playwright_version="1.55.0",
            chromium_version="139.0.7258.5",
        )

    def load_manifest(self) -> dict[str, object]:
        return json.loads((self.root / "evidence.json").read_text(encoding="utf-8"))

    def write_manifest(self, manifest: dict[str, object]) -> None:
        (self.root / "evidence.json").write_text(
            json.dumps(manifest, sort_keys=True),
            encoding="utf-8",
        )

    def write_authenticated_envelope(
        self,
        *,
        statement_overrides: dict[str, object] | None = None,
        envelope_overrides: dict[str, object] | None = None,
        signing_key: ec.EllipticCurvePrivateKey | None = None,
        challenge: bytes = AUTH_CHALLENGE,
        signature_payload_prefix: bytes = b"",
    ) -> dict[str, object]:
        if not (self.root / "evidence.json").exists():
            self.create()
        signing_key = signing_key or self.envelope_private_key
        public_key = signing_key.public_key()
        public_pem = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        (self.root / "trusted-envelope-key.pem").write_bytes(public_pem)
        (self.root / "verifier-challenge.bin").write_bytes(challenge)
        replay = self.replay_root / "ledger"
        replay.mkdir(mode=0o700, exist_ok=True)
        replay.chmod(0o700)
        manifest_sha256 = sha256((self.root / "evidence.json").read_bytes())
        key_sha256 = public_key_sha256(public_key)
        statement: dict[str, object] = {
            "statementType": evidence.AUTHENTICATED_STATEMENT_TYPE,
            "manifestApiVersion": evidence.API_VERSION,
            "assuranceProfile": evidence.AUTHENTICATED_ASSURANCE_PROFILE,
            "challengeScope": evidence.AUTHENTICATED_CHALLENGE_SCOPE,
            "verifierChallengeSha256": sha256(challenge),
            "manifestSha256": manifest_sha256,
            "signingKeySha256": key_sha256,
            "verifierId": AUTH_VERIFIER,
            "signerId": AUTH_SIGNER,
            "validFromEpochSeconds": AUTH_VALID_FROM,
            "validUntilEpochSeconds": AUTH_VALID_UNTIL,
            "validityWindowScope": evidence.AUTHENTICATED_VALIDITY_SCOPE,
            "underlyingV3TimestampsAuthenticated": False,
            "underlyingJourneyActionsChallengeBound": False,
            "signatureAlgorithm": evidence.AUTHENTICATED_SIGNATURE_ALGORITHM,
            "signatureEncoding": evidence.AUTHENTICATED_SIGNATURE_ENCODING,
        }
        statement.update(statement_overrides or {})
        signed_payload = (
            signature_payload_prefix
            + test_authenticated_signature_payload(statement)
        )
        envelope: dict[str, object] = {
            "apiVersion": evidence.AUTHENTICATED_ENVELOPE_VERSION,
            "signedStatement": statement,
            "signature": {
                "value": base64url_without_padding(
                    low_s_signature(signing_key, signed_payload)
                ),
            },
        }
        envelope.update(envelope_overrides or {})
        (self.root / "authenticated-envelope.json").write_bytes(
            canonical_json(envelope)
        )
        return {
            "root": self.root,
            "manifest_path": "evidence.json",
            "envelope_path": "authenticated-envelope.json",
            "verifier_challenge_path": "verifier-challenge.bin",
            "expected_manifest_sha256": manifest_sha256,
            "trusted_public_key_path": "trusted-envelope-key.pem",
            "trusted_public_key_sha256": key_sha256,
            "expected_verifier_id": AUTH_VERIFIER,
            "expected_signer_id": AUTH_SIGNER,
            "expected_valid_from_epoch_seconds": AUTH_VALID_FROM,
            "expected_valid_until_epoch_seconds": AUTH_VALID_UNTIL,
            "verification_time_epoch_seconds": AUTH_VERIFY_TIME,
            "replay_root": self.replay_root,
            "replay_directory": "ledger",
        }

    def verify_authenticated(
        self,
        context: dict[str, object],
        **overrides: object,
    ) -> dict[str, object]:
        arguments = dict(context)
        arguments.update(overrides)
        return evidence.verify_authenticated_envelope(**arguments)

    def authenticated_cli_command(
        self,
        context: dict[str, object],
    ) -> list[str]:
        return [
            sys.executable,
            str(SCRIPT),
            "--root",
            str(self.root),
            "verify-authenticated",
            "--manifest",
            str(context["manifest_path"]),
            "--envelope",
            str(context["envelope_path"]),
            "--verifier-challenge",
            str(context["verifier_challenge_path"]),
            "--expected-manifest-sha256",
            str(context["expected_manifest_sha256"]),
            "--trusted-public-key",
            str(context["trusted_public_key_path"]),
            "--trusted-public-key-sha256",
            str(context["trusted_public_key_sha256"]),
            "--expected-verifier-id",
            str(context["expected_verifier_id"]),
            "--expected-signer-id",
            str(context["expected_signer_id"]),
            "--expected-valid-from-epoch-seconds",
            str(context["expected_valid_from_epoch_seconds"]),
            "--expected-valid-until-epoch-seconds",
            str(context["expected_valid_until_epoch_seconds"]),
            "--verifier-time-epoch-seconds",
            str(context["verification_time_epoch_seconds"]),
            "--replay-root",
            os.fspath(context["replay_root"]),
            "--replay-directory",
            str(context["replay_directory"]),
        ]

    def assert_rejected(self, expected: str) -> None:
        with self.assertRaisesRegex(evidence.EvidenceError, expected):
            evidence.verify_manifest(self.root, "evidence.json")

    def descriptor_is_open(self, descriptor: int) -> bool:
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
            return False
        return True

    def assert_tracked_descriptor_cleanup(
        self,
        descriptors: set[int],
        *,
        intentionally_open: set[int] | None = None,
    ) -> None:
        expected_open = set(intentionally_open or ())
        open_before_cleanup = {
            descriptor
            for descriptor in descriptors
            if self.descriptor_is_open(descriptor)
        }
        unexpected_open = open_before_cleanup - expected_open
        unexpectedly_closed = expected_open - open_before_cleanup
        cleanup_errors: list[str] = []
        for descriptor in sorted(open_before_cleanup):
            try:
                os.close(descriptor)
            except OSError as exc:
                cleanup_errors.append(f"fd {descriptor}: {exc}")
        open_after_cleanup = {
            descriptor
            for descriptor in descriptors
            if self.descriptor_is_open(descriptor)
        }
        self.assertEqual(unexpected_open, set())
        self.assertEqual(unexpectedly_closed, set())
        self.assertEqual(cleanup_errors, [])
        self.assertEqual(open_after_cleanup, set())

    def test_create_verify_cli_and_local_only_assurance(self) -> None:
        command = [
            sys.executable,
            str(SCRIPT),
            "--root",
            str(self.root),
            "create",
            "--journey",
            "journey.json",
        ]
        for source in SOURCE_PATHS:
            command.extend(["--source", source])
        command.extend(
            [
                "--screenshot",
                "screens/portal.png",
                "--playwright-version",
                "1.55.0",
                "--chromium-version",
                "139.0.7258.5",
                "--output",
                "evidence.json",
            ]
        )
        created = subprocess.run(command, check=False, capture_output=True, text=True)
        self.assertEqual(created.returncode, 0, created.stderr)
        self.assertIn("local-integrity-only, unsigned", created.stdout)
        verified = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--root",
                str(self.root),
                "verify",
                "--manifest",
                "evidence.json",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(verified.returncode, 0, verified.stderr)
        manifest = self.load_manifest()
        self.assertEqual(manifest["apiVersion"], evidence.API_VERSION)
        self.assertEqual(manifest["assurance"], evidence.ASSURANCE)
        self.assertFalse(manifest["assurance"]["provenanceAttestation"])
        self.assertEqual(
            stat.S_IMODE((self.root / "evidence.json").stat().st_mode),
            0o600,
        )

    def test_authenticated_envelope_is_pinned_and_challenge_is_one_use(self) -> None:
        context = self.write_authenticated_envelope()
        result = self.verify_authenticated(context)
        self.assertEqual(
            result["apiVersion"],
            evidence.AUTHENTICATED_RESULT_VERSION,
        )
        self.assertTrue(result["signatureVerified"])
        self.assertEqual(
            result["manifestSha256"],
            context["expected_manifest_sha256"],
        )
        self.assertEqual(
            result["replayProtectionScope"],
            "caller-provided-private-root-local-ledger-only",
        )
        self.assertFalse(result["pinProvenanceEstablishedByThisTool"])
        self.assertFalse(
            result["assurance"]["pinProvenanceEstablishedByThisTool"]
        )
        self.assertFalse(result["underlyingV3TimestampsAuthenticated"])
        self.assertFalse(result["underlyingJourneyActionsChallengeBound"])
        self.assertFalse(result["staleTranscriptReenvelopingPrevented"])
        self.assertFalse(
            result["verifierChallengeFreshnessEstablishedByThisTool"]
        )
        self.assertEqual(result["verificationTimeSource"], "caller-supplied")
        self.assertFalse(result["trustworthyTimeEstablishedByThisTool"])
        self.assertFalse(
            result["portableFilesystemAclPrivacyEstablishedByThisTool"]
        )
        self.assertFalse(
            result["assurance"][
                "portableFilesystemAclPrivacyEstablishedByThisTool"
            ]
        )
        self.assertIn(
            "stale transcript can be re-enveloped",
            result["assurance"]["statement"],
        )
        self.assertIn("platform ACLs", result["assurance"]["statement"])
        self.assertIn(
            "weighted application byte operations",
            result["authenticatedWorkBudget"]["scope"],
        )
        marker = self.replay_root / result["challengeConsumptionMarker"]
        self.assertTrue(marker.is_file())
        self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o600)
        with self.assertRaisesRegex(
            evidence.EvidenceError,
            "replay or caller-ledger conflict rejected",
        ):
            self.verify_authenticated(context)

    def test_production_envelope_known_answer_vector_is_independent(self) -> None:
        literal_order = int(
            "FFFFFFFF00000000FFFFFFFFFFFFFFFF"
            "BCE6FAADA7179E84F3B9CAC2FC632551",
            16,
        )
        literal_signature_domain = (
            b"catchplate.onboardingEvidenceVerifierEnvelope/v1\x00"
        )
        literal_statement_type = (
            "catchplate.onboardingEvidenceManifestDigest/v1"
        )
        literal_spki_der = bytes.fromhex(
            "3059301306072a8648ce3d020106082a8648ce3d030107"
            "03420004"
            "60fed4ba255a9d31c961eb74c6356d68"
            "c049b8923e3b61fa6ce669622e60f29fb"
            "7903fe1008b8bc99a41ae9e95628bc64"
            "f2f1b20c2d7e9f5177a3c294d4462299"
        )
        literal_low_s_sample_signature = bytes.fromhex(
            "3045022100"
            "efd48b2aacb6a8fd1140dd9cd45e81d6"
            "9d2c877b56aaf991c34d0ea84eaf3716"
            "0220"
            "0834e36ad29a83bf2bc9385e491d6099"
            "c8fdf9d1ed67aa7ea5f51f93782857a9"
        )
        self.assertEqual(literal_order, TEST_P256_ORDER)
        self.assertEqual(literal_order, evidence.P256_ORDER)
        self.assertEqual(
            literal_signature_domain,
            evidence.AUTHENTICATED_SIGNATURE_DOMAIN,
        )
        self.assertEqual(
            literal_statement_type,
            evidence.AUTHENTICATED_STATEMENT_TYPE,
        )
        expected_x, expected_y = independent_p256_multiply(
            RFC6979_P256_PRIVATE_SCALAR,
            TEST_P256_GENERATOR,
        )
        self.assertTrue(
            literal_spki_der.endswith(
                b"\x04"
                + expected_x.to_bytes(32, "big")
                + expected_y.to_bytes(32, "big")
            )
        )
        self.assertEqual(
            independent_rfc6979_es256_signature(
                RFC6979_P256_PRIVATE_SCALAR,
                b"sample",
            ),
            literal_low_s_sample_signature,
        )
        literal_public_key_pem = independent_public_key_pem(literal_spki_der)
        independent_spki_hasher = hashes.Hash(hashes.SHA256())
        independent_spki_hasher.update(literal_spki_der)
        literal_spki_sha256 = (
            "sha256:" + independent_spki_hasher.finalize().hex()
        )
        statement: dict[str, object] = {
            "statementType": literal_statement_type,
            "manifestApiVersion": "catchplate.onboardingEvidence/v3",
            "assuranceProfile": "manifest-authentication-only-v1",
            "challengeScope": "envelope-response-only",
            "verifierChallengeSha256": "sha256:" + "00" * 32,
            "manifestSha256": "sha256:" + "11" * 32,
            "signingKeySha256": literal_spki_sha256,
            "verifierId": "verifier:known-answer",
            "signerId": "signer:known-answer",
            "validFromEpochSeconds": 100,
            "validUntilEpochSeconds": 200,
            "validityWindowScope": "envelope-signature-only",
            "underlyingV3TimestampsAuthenticated": False,
            "underlyingJourneyActionsChallengeBound": False,
            "signatureAlgorithm": "ES256-SHA256",
            "signatureEncoding": "asn1-der-low-s",
        }
        literal_payload = b"".join(
            (
                literal_signature_domain,
                b'{"apiVersion":'
                b'"catchplate.onboardingEvidenceVerifierEnvelope/v1",',
                b'"signedStatement":{"assuranceProfile":'
                b'"manifest-authentication-only-v1","challengeScope":'
                b'"envelope-response-only","manifestApiVersion":'
                b'"catchplate.onboardingEvidence/v3","manifestSha256":"sha256:',
                b"11" * 32,
                b'","signatureAlgorithm":"ES256-SHA256",'
                b'"signatureEncoding":"asn1-der-low-s",'
                b'"signerId":"signer:known-answer",'
                b'"signingKeySha256":"',
                literal_spki_sha256.encode("ascii"),
                b'","statementType":'
                b'"catchplate.onboardingEvidenceManifestDigest/v1",'
                b'"underlyingJourneyActionsChallengeBound":false,'
                b'"underlyingV3TimestampsAuthenticated":false,'
                b'"validFromEpochSeconds":100,'
                b'"validUntilEpochSeconds":200,'
                b'"validityWindowScope":"envelope-signature-only",'
                b'"verifierChallengeSha256":"sha256:',
                b"00" * 32,
                b'","verifierId":"verifier:known-answer"}}',
            )
        )
        self.assertEqual(
            evidence._authenticated_signature_payload(statement),
            literal_payload,
        )
        signature = independent_rfc6979_es256_signature(
            RFC6979_P256_PRIVATE_SCALAR,
            literal_payload,
        )
        envelope = {
            "apiVersion": (
                "catchplate.onboardingEvidenceVerifierEnvelope/v1"
            ),
            "signedStatement": statement,
            "signature": {"value": base64url_without_padding(signature)},
        }
        decoded = evidence._decode_json(
            canonical_json(envelope),
            name="literal production envelope KAT",
        )
        _, parsed_statement, parsed_signature = (
            evidence._validate_authenticated_envelope(decoded)
        )
        self.assertEqual(parsed_statement, statement)
        self.assertEqual(parsed_signature, signature)
        public_key, loaded_digest = evidence._load_pinned_envelope_public_key(
            literal_public_key_pem,
            expected_sha256=literal_spki_sha256,
        )
        self.assertEqual(loaded_digest, literal_spki_sha256)
        evidence._verify_authenticated_signature(
            public_key,
            parsed_signature,
            evidence._authenticated_signature_payload(parsed_statement),
        )
        for field, original in statement.items():
            with self.subTest(field=field):
                mutated = dict(statement)
                if isinstance(original, bool):
                    mutated[field] = not original
                elif isinstance(original, int):
                    mutated[field] = original + 1
                else:
                    mutated[field] = f"{original}-mutated"
                with self.assertRaisesRegex(
                    evidence.EvidenceError,
                    "signature verification failed",
                ):
                    evidence._verify_authenticated_signature(
                        public_key,
                        signature,
                        evidence._authenticated_signature_payload(mutated),
                    )
        mutated_outer = TEST_AUTHENTICATED_SIGNATURE_DOMAIN + canonical_json(
            {
                "apiVersion": (
                    "catchplate.onboardingEvidenceVerifierEnvelope/v2"
                ),
                "signedStatement": statement,
            }
        )
        with self.assertRaisesRegex(
            evidence.EvidenceError,
            "signature verification failed",
        ):
            evidence._verify_authenticated_signature(
                public_key,
                signature,
                mutated_outer,
            )

    def test_concurrent_challenge_consumption_allows_at_most_one_success(
        self,
    ) -> None:
        context = self.write_authenticated_envelope()
        state_check_barrier = threading.Barrier(2)
        link_barrier = threading.Barrier(2)
        real_assert_new_output_state = evidence._assert_new_output_state
        real_link = evidence.os.link
        state_check_arrivals: list[str] = []
        link_arrivals: list[tuple[object, object]] = []
        arrival_lock = threading.Lock()

        def collide_after_initial_state_check(
            publication: evidence._OutputPublication,
        ) -> None:
            real_assert_new_output_state(publication)
            with arrival_lock:
                state_check_arrivals.append(publication.relative)
            state_check_barrier.wait(timeout=5)

        def collide_at_final_link(
            source: object,
            destination: object,
            *,
            src_dir_fd: int | None = None,
            dst_dir_fd: int | None = None,
            follow_symlinks: bool = True,
        ) -> None:
            with arrival_lock:
                link_arrivals.append((source, destination))
            link_barrier.wait(timeout=5)
            real_link(
                source,
                destination,
                src_dir_fd=src_dir_fd,
                dst_dir_fd=dst_dir_fd,
                follow_symlinks=follow_symlinks,
            )

        def verify_once() -> tuple[str, str]:
            try:
                result = self.verify_authenticated(context)
                return ("verified", str(result["challengeConsumptionMarker"]))
            except evidence.EvidenceError as exc:
                message = str(exc)
                if "replay or caller-ledger conflict rejected" in message:
                    return ("replay-conflict", message)
                return ("unexpected-error", message)

        with (
            mock.patch.object(
                evidence,
                "_assert_new_output_state",
                side_effect=collide_after_initial_state_check,
            ),
            mock.patch.object(
                evidence.os,
                "link",
                side_effect=collide_at_final_link,
            ),
            ThreadPoolExecutor(max_workers=2) as executor,
        ):
            outcomes = list(executor.map(lambda _: verify_once(), range(2)))
        self.assertEqual(
            [status for status, _ in outcomes].count("verified"),
            1,
        )
        self.assertEqual(
            [status for status, _ in outcomes].count("replay-conflict"),
            1,
        )
        self.assertEqual(len(state_check_arrivals), 2)
        self.assertEqual(len(set(state_check_arrivals)), 1)
        self.assertEqual(len(link_arrivals), 2)
        self.assertEqual(
            {os.fspath(destination) for _, destination in link_arrivals},
            {
                "challenge-v1-"
                f"{sha256(AUTH_CHALLENGE)[7:]}.used"
            },
        )
        replay_entries = list((self.replay_root / "ledger").iterdir())
        self.assertEqual(
            len([entry for entry in replay_entries if entry.name.endswith(".used")]),
            1,
        )
        self.assertEqual(
            [entry for entry in replay_entries if entry.name.endswith(".pending")],
            [],
        )
        marker = next(entry for entry in replay_entries if entry.name.endswith(".used"))
        marker_stat = marker.stat()
        self.assertEqual(stat.S_IMODE(marker_stat.st_mode), 0o600)
        self.assertEqual(marker_stat.st_uid, os.geteuid())
        self.assertEqual(marker_stat.st_nlink, 1)
        envelope = json.loads(
            (self.root / "authenticated-envelope.json").read_text(
                encoding="utf-8"
            )
        )
        expected_marker = {
            "apiVersion": (
                "catchplate.onboardingEvidenceChallengeConsumption/v1"
            ),
            "verifierChallengeSha256": sha256(AUTH_CHALLENGE),
            "statementSha256": sha256(
                test_authenticated_signature_payload(
                    envelope["signedStatement"]
                )
            ),
            "manifestSha256": context["expected_manifest_sha256"],
            "trustedPublicKeySha256": context["trusted_public_key_sha256"],
            "verifierId": AUTH_VERIFIER,
            "signerId": AUTH_SIGNER,
            "verificationTimeEpochSeconds": AUTH_VERIFY_TIME,
            "verificationTimeSource": "caller-supplied",
            "trustworthyTimeEstablishedByThisTool": False,
            "replayProtectionScope": (
                "caller-provided-private-root-local-ledger-only"
            ),
        }
        self.assertEqual(marker.read_bytes(), canonical_json(expected_marker) + b"\n")

    def test_authenticated_cli_reports_scoped_not_journey_fresh_assurance(
        self,
    ) -> None:
        context = self.write_authenticated_envelope()
        verified = subprocess.run(
            self.authenticated_cli_command(context),
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertIn("caller-provided private local ledger", verified.stdout)
        self.assertIn("pin provenance was not established", verified.stdout)
        self.assertIn("checked against caller-supplied time", verified.stdout)
        self.assertIn("platform ACL access", verified.stdout)
        self.assertIn(
            "underlying v3 timestamps and actions remain unauthenticated",
            verified.stdout,
        )
        self.assertIn("can be stale/re-enveloped", verified.stdout)
        self.assertIn(
            "not server/source/execution/provenance/TEE attestation",
            verified.stdout,
        )

    def test_authenticated_envelope_rejects_duplicate_and_unknown_fields(
        self,
    ) -> None:
        context = self.write_authenticated_envelope()
        envelope_path = self.root / "authenticated-envelope.json"
        original = envelope_path.read_bytes()
        duplicate = (
            b'{"apiVersion":"'
            + evidence.AUTHENTICATED_ENVELOPE_VERSION.encode("ascii")
            + b'",'
            + original[1:]
        )
        envelope_path.write_bytes(duplicate)
        with self.assertRaisesRegex(evidence.EvidenceError, "duplicate object key"):
            self.verify_authenticated(context)

        self.write_authenticated_envelope(envelope_overrides={"publicKey": "self"})
        with self.assertRaisesRegex(evidence.EvidenceError, "unknown fields"):
            self.verify_authenticated(context)

        context = self.write_authenticated_envelope()
        envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
        del envelope["signedStatement"]["signerId"]
        envelope_path.write_bytes(canonical_json(envelope))
        with self.assertRaisesRegex(evidence.EvidenceError, "missing fields"):
            self.verify_authenticated(context)

    def test_authenticated_envelope_rejects_unpinned_or_self_described_key(
        self,
    ) -> None:
        context = self.write_authenticated_envelope()
        with self.assertRaisesRegex(
            evidence.EvidenceError,
            "caller-supplied expected canonical DER",
        ):
            self.verify_authenticated(
                context,
                trusted_public_key_sha256=sha256(b"not-the-key"),
            )

        other_key = ec.generate_private_key(ec.SECP256R1())
        other_public = other_key.public_key()
        (self.root / "trusted-envelope-key.pem").write_bytes(
            other_public.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        envelope_path = self.root / "authenticated-envelope.json"
        envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
        replacement_digest = public_key_sha256(other_public)
        envelope["signedStatement"]["signingKeySha256"] = replacement_digest
        envelope_path.write_bytes(canonical_json(envelope))
        with self.assertRaisesRegex(
            evidence.EvidenceError,
            "signature verification failed",
        ):
            self.verify_authenticated(
                context,
                trusted_public_key_sha256=replacement_digest,
            )

        context = self.write_authenticated_envelope(signing_key=self.private_key)
        with self.assertRaisesRegex(
            evidence.EvidenceError,
            "must be independent of the manifest",
        ):
            self.verify_authenticated(
                context,
                trusted_public_key_path="source/webauthn-public-key.pem",
            )

    def test_authenticated_crypto_backend_errors_are_evidence_errors(self) -> None:
        context = self.write_authenticated_envelope()
        with (
            mock.patch.object(
                evidence.serialization,
                "load_pem_public_key",
                side_effect=UnsupportedAlgorithm("injected key algorithm"),
            ),
            self.assertRaisesRegex(
                evidence.EvidenceError,
                "trusted public key is not valid PEM",
            ),
        ):
            self.verify_authenticated(context)

        unsupported_key = mock.Mock()
        unsupported_key.verify.side_effect = UnsupportedAlgorithm(
            "injected signature algorithm"
        )
        with self.assertRaisesRegex(
            evidence.EvidenceError,
            "signature algorithm is unsupported",
        ):
            evidence._verify_authenticated_signature(
                unsupported_key,
                b"signature",
                b"payload",
            )

    def test_authenticated_envelope_rejects_identity_and_challenge_substitution(
        self,
    ) -> None:
        context = self.write_authenticated_envelope()
        with self.assertRaisesRegex(evidence.EvidenceError, "expected signer"):
            self.verify_authenticated(
                context,
                expected_signer_id="signer:other",
            )
        with self.assertRaisesRegex(evidence.EvidenceError, "expected verifier"):
            self.verify_authenticated(
                context,
                expected_verifier_id="verifier:other",
            )
        (self.root / "verifier-challenge.bin").write_bytes(b"x" * 32)
        with self.assertRaisesRegex(
            evidence.EvidenceError,
            "caller-supplied verifier challenge",
        ):
            self.verify_authenticated(context)

    def test_authenticated_envelope_rejects_cross_manifest_substitution(
        self,
    ) -> None:
        context = self.write_authenticated_envelope()
        substituted = (
            (self.root / "evidence.json").read_bytes().rstrip() + b"\n\n"
        )
        (self.root / "evidence-substituted.json").write_bytes(substituted)
        (self.root / "evidence-substituted.json").chmod(0o600)
        with self.assertRaisesRegex(
            evidence.EvidenceError,
            "exact manifest bytes do not match",
        ):
            self.verify_authenticated(
                context,
                manifest_path="evidence-substituted.json",
            )
        with self.assertRaisesRegex(
            evidence.EvidenceError,
            "caller-supplied expected digest",
        ):
            self.verify_authenticated(
                context,
                manifest_path="evidence-substituted.json",
                expected_manifest_sha256=sha256(substituted),
            )

    def test_authenticated_envelope_rejects_stale_future_and_window_drift(
        self,
    ) -> None:
        at_start = self.write_authenticated_envelope(
            challenge=b"validity-start-boundary"
        )
        self.assertTrue(
            self.verify_authenticated(
                at_start,
                verification_time_epoch_seconds=AUTH_VALID_FROM,
            )["signatureVerified"]
        )
        before_end = self.write_authenticated_envelope(
            challenge=b"validity-end-boundary"
        )
        self.assertTrue(
            self.verify_authenticated(
                before_end,
                verification_time_epoch_seconds=AUTH_VALID_UNTIL - 1,
            )["signatureVerified"]
        )
        context = self.write_authenticated_envelope()
        with self.assertRaisesRegex(evidence.EvidenceError, "not yet valid"):
            self.verify_authenticated(
                context,
                verification_time_epoch_seconds=AUTH_VALID_FROM - 1,
            )
        with self.assertRaisesRegex(evidence.EvidenceError, "is stale"):
            self.verify_authenticated(
                context,
                verification_time_epoch_seconds=AUTH_VALID_UNTIL,
            )
        with self.assertRaisesRegex(
            evidence.EvidenceError,
            "caller-supplied expected window",
        ):
            self.verify_authenticated(
                context,
                expected_valid_until_epoch_seconds=AUTH_VALID_UNTIL - 1,
            )

        context = self.write_authenticated_envelope(
            statement_overrides={
                "validUntilEpochSeconds": (
                    AUTH_VALID_FROM
                    + evidence.MAX_AUTHENTICATED_VALIDITY_SECONDS
                    + 1
                )
            }
        )
        with self.assertRaisesRegex(evidence.EvidenceError, "window exceeds"):
            self.verify_authenticated(context)
        for valid_from, valid_until in ((100, 100), (101, 100)):
            with self.subTest(
                valid_from=valid_from,
                valid_until=valid_until,
            ):
                context = self.write_authenticated_envelope(
                    statement_overrides={
                        "validFromEpochSeconds": valid_from,
                        "validUntilEpochSeconds": valid_until,
                    }
                )
                with self.assertRaisesRegex(
                    evidence.EvidenceError,
                    "validity window must be non-empty",
                ):
                    self.verify_authenticated(context)

    def test_authenticated_envelope_rejects_assurance_escalation(self) -> None:
        for field in (
            "underlyingV3TimestampsAuthenticated",
            "underlyingJourneyActionsChallengeBound",
        ):
            with self.subTest(field=field):
                context = self.write_authenticated_envelope(
                    statement_overrides={field: True}
                )
                with self.assertRaisesRegex(evidence.EvidenceError, "must be false"):
                    self.verify_authenticated(context)

    def test_authenticated_envelope_rejects_signature_and_domain_substitution(
        self,
    ) -> None:
        context = self.write_authenticated_envelope(
            signature_payload_prefix=b"other-protocol\x00"
        )
        with self.assertRaisesRegex(
            evidence.EvidenceError,
            "signature verification failed",
        ):
            self.verify_authenticated(context)
        self.assertEqual(list((self.replay_root / "ledger").iterdir()), [])

        context = self.write_authenticated_envelope()
        envelope_path = self.root / "authenticated-envelope.json"
        envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
        raw_signature = base64.urlsafe_b64decode(
            envelope["signature"]["value"]
            + "=" * (-len(envelope["signature"]["value"]) % 4)
        )
        r_value, s_value = decode_dss_signature(raw_signature)
        high_s = TEST_P256_ORDER - s_value
        envelope["signature"]["value"] = base64url_without_padding(
            encode_dss_signature(r_value, high_s)
        )
        envelope_path.write_bytes(canonical_json(envelope))
        with self.assertRaisesRegex(evidence.EvidenceError, "canonical low-S DER"):
            self.verify_authenticated(context)

        context = self.write_authenticated_envelope(
            statement_overrides={"signatureAlgorithm": "Ed25519"}
        )
        with self.assertRaisesRegex(
            evidence.EvidenceError,
            "signatureAlgorithm must be",
        ):
            self.verify_authenticated(context)

    def test_authenticated_envelope_rejects_noncanonical_signature_encoding(
        self,
    ) -> None:
        context = self.write_authenticated_envelope()
        envelope_path = self.root / "authenticated-envelope.json"
        envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
        envelope["signature"]["value"] += "="
        envelope_path.write_bytes(canonical_json(envelope))
        with self.assertRaisesRegex(
            evidence.EvidenceError,
            "canonical unpadded base64url",
        ):
            self.verify_authenticated(context)

    def test_failed_authentication_does_not_consume_challenge(self) -> None:
        context = self.write_authenticated_envelope(
            signature_payload_prefix=b"wrong-domain\x00"
        )
        with self.assertRaisesRegex(
            evidence.EvidenceError,
            "signature verification failed",
        ):
            self.verify_authenticated(context)
        self.assertEqual(list((self.replay_root / "ledger").iterdir()), [])

        context = self.write_authenticated_envelope()
        result = self.verify_authenticated(context)
        self.assertTrue(
            (
                self.replay_root / result["challengeConsumptionMarker"]
            ).is_file()
        )

    def test_authenticated_inputs_reject_symlinks_hardlinks_and_fifo(self) -> None:
        for relative in (
            "authenticated-envelope.json",
            "verifier-challenge.bin",
            "trusted-envelope-key.pem",
        ):
            with self.subTest(relative=relative):
                context = self.write_authenticated_envelope()
                target = self.root / relative
                replacement = self.root / f"{relative}.replacement"
                replacement.write_bytes(target.read_bytes())
                target.unlink()
                target.symlink_to(replacement.name)
                with self.assertRaisesRegex(evidence.EvidenceError, "symlinks"):
                    self.verify_authenticated(context)
                target.unlink()
                replacement.replace(target)

        context = self.write_authenticated_envelope()
        os.link(
            self.root / "trusted-envelope-key.pem",
            self.root / "trusted-envelope-key-alias.pem",
        )
        with self.assertRaisesRegex(
            evidence.EvidenceError,
            "exactly one hard link",
        ):
            self.verify_authenticated(context)

        if hasattr(os, "mkfifo"):
            (self.root / "trusted-envelope-key-alias.pem").unlink()
            context = self.write_authenticated_envelope()
            challenge = self.root / "verifier-challenge.bin"
            challenge.unlink()
            os.mkfifo(challenge, mode=0o600)
            process = subprocess.Popen(
                self.authenticated_cli_command(context),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            stderr = ""
            timed_out = False
            communication_error: Exception | None = None
            cleanup_errors: list[str] = []
            try:
                _, stderr = process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                timed_out = True
            except Exception as exc:
                communication_error = exc
            finally:
                if process.poll() is None:
                    try:
                        process.terminate()
                    except ProcessLookupError:
                        pass
                    except Exception as exc:
                        cleanup_errors.append(f"terminate failed: {exc}")
                if process.poll() is None:
                    try:
                        _, final_stderr = process.communicate(timeout=0.5)
                        if final_stderr:
                            stderr += final_stderr
                    except subprocess.TimeoutExpired as exc:
                        cleanup_errors.append(
                            f"post-terminate communicate timed out: {exc}"
                        )
                    except Exception as exc:
                        cleanup_errors.append(
                            f"post-terminate communicate failed: {exc}"
                        )
                if process.poll() is None:
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                    except Exception as exc:
                        cleanup_errors.append(f"kill failed: {exc}")
                if process.poll() is None:
                    try:
                        process.wait(timeout=1)
                    except subprocess.TimeoutExpired as exc:
                        cleanup_errors.append(
                            f"bounded post-kill wait timed out: {exc}"
                        )
                    except Exception as exc:
                        cleanup_errors.append(f"bounded post-kill wait failed: {exc}")
                if process.poll() is None:
                    try:
                        os.kill(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    except Exception as exc:
                        cleanup_errors.append(f"direct SIGKILL fallback failed: {exc}")
                try:
                    process.wait()
                except ChildProcessError:
                    process.poll()
                except Exception as exc:
                    cleanup_errors.append(f"final Popen wait failed: {exc}")
                    try:
                        waited_pid, status = os.waitpid(process.pid, 0)
                    except ChildProcessError:
                        process.poll()
                    except Exception as wait_exc:
                        cleanup_errors.append(
                            f"final direct waitpid failed: {wait_exc}"
                        )
                    else:
                        if waited_pid != process.pid:
                            cleanup_errors.append(
                                "final direct waitpid reaped an unexpected child"
                            )
                        process.returncode = os.waitstatus_to_exitcode(status)
                if process.poll() is None:
                    cleanup_errors.append(
                        "FIFO verification child was not reaped after final waitpid"
                    )
                for label, stream in (
                    ("stdout", process.stdout),
                    ("stderr", process.stderr),
                ):
                    if stream is not None:
                        try:
                            stream.close()
                        except Exception as exc:
                            cleanup_errors.append(
                                f"{label} pipe close failed: {exc}"
                            )
            if cleanup_errors:
                if communication_error is not None:
                    cleanup_errors.insert(
                        0,
                        f"initial communicate failed: {communication_error}",
                    )
                self.fail("; ".join(cleanup_errors))
            if communication_error is not None:
                raise AssertionError(
                    f"FIFO verification communicate failed: {communication_error}"
                ) from communication_error
            if timed_out:
                self.fail("FIFO verification child failed to terminate")
            self.assertEqual(process.returncode, 2, stderr)
            self.assertIn("must be a regular file", stderr)

    def test_authenticated_replay_root_is_separate_private_and_no_follow(
        self,
    ) -> None:
        context = self.write_authenticated_envelope()
        with self.assertRaisesRegex(
            evidence.EvidenceError,
            "separately pinned directory",
        ):
            self.verify_authenticated(context, replay_root=self.root)

        self.replay_root.chmod(0o755)
        with self.assertRaisesRegex(evidence.EvidenceError, "mode 0700"):
            self.verify_authenticated(context)
        self.replay_root.chmod(0o700)

        self.replay_root.chmod(0o1700)
        with self.assertRaisesRegex(evidence.EvidenceError, "no special bits"):
            self.verify_authenticated(context)
        self.replay_root.chmod(0o700)

        ledger = self.replay_root / "ledger"
        alternate = self.replay_root / "alternate"
        alternate.mkdir(mode=0o700)
        ledger.rmdir()
        ledger.symlink_to(alternate.name)
        with self.assertRaisesRegex(
            evidence.EvidenceError,
            "without following links",
        ):
            self.verify_authenticated(context)

    def test_output_stat_errors_are_normalized_to_evidence_errors(self) -> None:
        root_pin = evidence._open_root_fd(self.replay_root)
        publication = evidence._pin_output_publication(
            root_pin.fd,
            "ledger/output-stat-error.used",
        )
        try:
            with (
                mock.patch.object(
                    evidence.os,
                    "fstat",
                    side_effect=OSError("injected output stat failure"),
                ),
                self.assertRaisesRegex(
                    evidence.EvidenceError,
                    "cannot revalidate pinned output directory chain",
                ),
            ):
                evidence._revalidate_output_chain(publication)
        finally:
            self.assertEqual(
                evidence._close_output_publication(publication),
                [],
            )
            self.assertEqual(root_pin.close(), [])

    def test_input_and_root_stat_errors_are_normalized_to_evidence_errors(
        self,
    ) -> None:
        root_pin = evidence._open_root_fd(self.root)
        real_input_open = evidence.os.open
        real_input_dup = evidence.os.dup
        opened_input_descriptors: set[int] = set()

        def track_input_open(
            path: object,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            if dir_fd is None:
                descriptor = real_input_open(path, flags, mode)
            else:
                descriptor = real_input_open(path, flags, mode, dir_fd=dir_fd)
            opened_input_descriptors.add(descriptor)
            return descriptor

        def track_input_dup(descriptor: int) -> int:
            duplicate = real_input_dup(descriptor)
            opened_input_descriptors.add(duplicate)
            return duplicate

        try:
            with (
                mock.patch.object(
                    evidence.os,
                    "open",
                    side_effect=track_input_open,
                ),
                mock.patch.object(
                    evidence.os,
                    "dup",
                    side_effect=track_input_dup,
                ),
                mock.patch.object(
                    evidence.os,
                    "fstat",
                    side_effect=OSError("injected input stat failure"),
                ),
                self.assertRaisesRegex(
                    evidence.EvidenceError,
                    "cannot inspect safely opened input.*injected input stat failure",
                ) as raised,
            ):
                evidence._open_regular_fd(
                    root_pin.fd,
                    "verifier-challenge.bin",
                )
            self.assertIsInstance(raised.exception.__cause__, OSError)
        finally:
            self.assertEqual(root_pin.close(), [])
        self.assert_tracked_descriptor_cleanup(opened_input_descriptors)

        real_open = evidence.os.open
        real_close = evidence.os.close
        real_root_fstat = evidence.os.fstat
        opened_root_descriptors: set[int] = set()
        intentionally_open_root_descriptors: set[int] = set()
        root_fstat_calls = 0

        def track_root_open(
            path: object,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            if dir_fd is None:
                descriptor = real_open(path, flags, mode)
            else:
                descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
            opened_root_descriptors.add(descriptor)
            return descriptor

        def fail_during_partial_root_construction(
            descriptor: int,
        ) -> os.stat_result:
            nonlocal root_fstat_calls
            root_fstat_calls += 1
            if root_fstat_calls == 3:
                raise OSError("injected root construction stat failure")
            return real_root_fstat(descriptor)

        def fail_one_root_close_without_closing(descriptor: int) -> None:
            if (
                descriptor in opened_root_descriptors
                and not intentionally_open_root_descriptors
            ):
                intentionally_open_root_descriptors.add(descriptor)
                raise OSError("injected root cleanup close failure")
            real_close(descriptor)

        with (
            mock.patch.object(
                evidence.os,
                "open",
                side_effect=track_root_open,
            ),
            mock.patch.object(
                evidence.os,
                "fstat",
                side_effect=fail_during_partial_root_construction,
            ),
            mock.patch.object(
                evidence.os,
                "close",
                side_effect=fail_one_root_close_without_closing,
            ),
            self.assertRaises(evidence.EvidenceError) as raised,
        ):
            evidence._open_root_fd(self.root)
        self.assert_tracked_descriptor_cleanup(
            opened_root_descriptors,
            intentionally_open=intentionally_open_root_descriptors,
        )
        self.assertGreaterEqual(len(opened_root_descriptors), 3)
        self.assertIn(
            "injected root construction stat failure",
            str(raised.exception),
        )
        self.assertIn(
            "injected root cleanup close failure",
            str(raised.exception),
        )
        self.assertIsInstance(raised.exception.__cause__, OSError)

        context = self.write_authenticated_envelope(
            challenge=b"normalized-root-stat-failure"
        )
        real_open_root = evidence._open_root_fd
        real_fstat = evidence.os.fstat
        pinned_root_terminal_descriptors: set[int] = set()
        all_pinned_root_descriptors: set[int] = set()

        def track_open_root(root: Path) -> evidence._PinnedRoot:
            pin = real_open_root(root)
            pinned_root_terminal_descriptors.add(pin.fd)
            all_pinned_root_descriptors.update(pin.descriptors)
            return pin

        def fail_pinned_root_stat(descriptor: int) -> os.stat_result:
            if descriptor in pinned_root_terminal_descriptors:
                raise OSError("injected pinned root stat failure")
            return real_fstat(descriptor)

        with (
            mock.patch.object(
                evidence,
                "_open_root_fd",
                side_effect=track_open_root,
            ),
            mock.patch.object(
                evidence.os,
                "fstat",
                side_effect=fail_pinned_root_stat,
            ),
            self.assertRaisesRegex(
                evidence.EvidenceError,
                "cannot inspect pinned evidence and replay root identities.*"
                "injected pinned root stat failure",
            ) as raised,
        ):
            self.verify_authenticated(context)
        self.assert_tracked_descriptor_cleanup(all_pinned_root_descriptors)
        self.assertIsInstance(raised.exception.__cause__, OSError)

    def test_publication_close_failures_are_observable_and_chained(self) -> None:
        def close_failure_hooks(
            message: str,
        ) -> tuple[object, object, object, object, dict[str, object]]:
            real_stage = evidence._stage_output_file
            real_close = evidence.os.close
            real_open = evidence.os.open
            real_dup = evidence.os.dup
            state: dict[str, object] = {
                "target": None,
                "failed": False,
                "tracked": set(),
                "intentionally_open": set(),
            }

            def stage_and_capture(
                publication: evidence._OutputPublication,
                data: bytes,
            ) -> None:
                real_stage(publication, data)
                state["target"] = publication.pending_fd

            def track_open(
                path: object,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                if dir_fd is None:
                    descriptor = real_open(path, flags, mode)
                else:
                    descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
                tracked = state["tracked"]
                assert isinstance(tracked, set)
                tracked.add(descriptor)
                return descriptor

            def track_dup(descriptor: int) -> int:
                duplicate = real_dup(descriptor)
                tracked = state["tracked"]
                assert isinstance(tracked, set)
                tracked.add(duplicate)
                return duplicate

            def close_without_closing_then_report(descriptor: int) -> None:
                if descriptor == state["target"] and not state["failed"]:
                    state["failed"] = True
                    intentionally_open = state["intentionally_open"]
                    assert isinstance(intentionally_open, set)
                    intentionally_open.add(descriptor)
                    raise OSError(message)
                real_close(descriptor)

            return (
                stage_and_capture,
                close_without_closing_then_report,
                track_open,
                track_dup,
                state,
            )

        def assert_close_failure_cleanup(state: dict[str, object]) -> None:
            tracked = state["tracked"]
            intentionally_open = state["intentionally_open"]
            assert isinstance(tracked, set)
            assert isinstance(intentionally_open, set)
            self.assert_tracked_descriptor_cleanup(
                tracked,
                intentionally_open=intentionally_open,
            )
            self.assertTrue(state["failed"])

        stage, close, track_open, track_dup, state = close_failure_hooks(
            "injected successful manifest close failure"
        )
        with (
            mock.patch.object(
                evidence,
                "_stage_output_file",
                side_effect=stage,
            ),
            mock.patch.object(evidence.os, "open", side_effect=track_open),
            mock.patch.object(evidence.os, "dup", side_effect=track_dup),
            mock.patch.object(evidence.os, "close", side_effect=close),
            self.assertRaises(evidence.EvidenceError) as raised,
        ):
            self.create(output_path="close-success.json")
        assert_close_failure_cleanup(state)
        self.assertIn(
            "manifest publication descriptor cleanup",
            str(raised.exception),
        )
        self.assertIn(
            "injected successful manifest close failure",
            str(raised.exception),
        )
        self.assertTrue((self.root / "close-success.json").is_file())

        stage, close, track_open, track_dup, state = close_failure_hooks(
            "injected exceptional manifest close failure"
        )
        with (
            mock.patch.object(
                evidence,
                "_stage_output_file",
                side_effect=stage,
            ),
            mock.patch.object(
                evidence,
                "_publish_output_file",
                side_effect=OSError("injected primary manifest publication failure"),
            ),
            mock.patch.object(evidence.os, "open", side_effect=track_open),
            mock.patch.object(evidence.os, "dup", side_effect=track_dup),
            mock.patch.object(evidence.os, "close", side_effect=close),
            self.assertRaises(evidence.EvidenceError) as raised,
        ):
            self.create(output_path="close-failure.json")
        assert_close_failure_cleanup(state)
        self.assertIn(
            "injected primary manifest publication failure",
            str(raised.exception),
        )
        self.assertIn(
            "injected exceptional manifest close failure",
            str(raised.exception),
        )
        self.assertIsInstance(raised.exception.__cause__, evidence.EvidenceError)
        self.assertIsInstance(raised.exception.__cause__.__cause__, OSError)
        self.assertFalse((self.root / "close-failure.json").exists())

        context = self.write_authenticated_envelope(
            challenge=b"successful-challenge-close-failure"
        )
        stage, close, track_open, track_dup, state = close_failure_hooks(
            "injected successful challenge close failure"
        )
        with (
            mock.patch.object(
                evidence,
                "_stage_output_file",
                side_effect=stage,
            ),
            mock.patch.object(evidence.os, "open", side_effect=track_open),
            mock.patch.object(evidence.os, "dup", side_effect=track_dup),
            mock.patch.object(evidence.os, "close", side_effect=close),
            self.assertRaises(evidence.EvidenceError) as raised,
        ):
            self.verify_authenticated(context)
        assert_close_failure_cleanup(state)
        self.assertIn(
            "challenge publication descriptor cleanup",
            str(raised.exception),
        )
        self.assertIn(
            "injected successful challenge close failure",
            str(raised.exception),
        )
        self.assertEqual(
            len(list((self.replay_root / "ledger").glob("*.used"))),
            1,
        )

        context = self.write_authenticated_envelope(
            challenge=b"exceptional-challenge-close-failure"
        )
        stage, close, track_open, track_dup, state = close_failure_hooks(
            "injected exceptional challenge close failure"
        )
        with (
            mock.patch.object(
                evidence,
                "_stage_output_file",
                side_effect=stage,
            ),
            mock.patch.object(
                evidence,
                "_publish_output_file",
                side_effect=OSError("injected primary challenge publication failure"),
            ),
            mock.patch.object(evidence.os, "open", side_effect=track_open),
            mock.patch.object(evidence.os, "dup", side_effect=track_dup),
            mock.patch.object(evidence.os, "close", side_effect=close),
            self.assertRaises(evidence.EvidenceError) as raised,
        ):
            self.verify_authenticated(context)
        assert_close_failure_cleanup(state)
        self.assertIn(
            "injected primary challenge publication failure",
            str(raised.exception),
        )
        self.assertIn(
            "injected exceptional challenge close failure",
            str(raised.exception),
        )
        self.assertIsInstance(raised.exception.__cause__, evidence.EvidenceError)
        self.assertIsInstance(raised.exception.__cause__.__cause__, OSError)
        self.assertEqual(
            list((self.replay_root / "ledger").glob("*.pending")),
            [],
        )

    def test_every_publication_descriptor_close_failure_is_tracked(self) -> None:
        for index, role in enumerate(
            (
                "pending",
                "root-directory",
                "ancestor-directory",
                "parent-directory",
            )
        ):
            with self.subTest(role=role):
                output_directory = self.root / f"publication-close-{index}"
                output_directory.mkdir(mode=0o700)
                private_parent = output_directory / "private"
                private_parent.mkdir(mode=0o700)
                output_path = (
                    f"{output_directory.name}/{private_parent.name}/evidence.json"
                )
                real_stage = evidence._stage_output_file
                real_open = evidence.os.open
                real_dup = evidence.os.dup
                real_close = evidence.os.close
                tracked_descriptors: set[int] = set()
                publication_descriptors: set[int] = set()
                intentionally_open: set[int] = set()
                target_descriptor: int | None = None

                def track_open(
                    path: object,
                    flags: int,
                    mode: int = 0o777,
                    *,
                    dir_fd: int | None = None,
                ) -> int:
                    if dir_fd is None:
                        descriptor = real_open(path, flags, mode)
                    else:
                        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
                    tracked_descriptors.add(descriptor)
                    return descriptor

                def track_dup(descriptor: int) -> int:
                    duplicate = real_dup(descriptor)
                    tracked_descriptors.add(duplicate)
                    return duplicate

                def stage_and_select_target(
                    publication: evidence._OutputPublication,
                    data: bytes,
                ) -> None:
                    nonlocal target_descriptor
                    real_stage(publication, data)
                    assert publication.pending_fd is not None
                    self.assertEqual(len(publication.directory_fds), 3)
                    publication_descriptors.update(publication.directory_fds)
                    publication_descriptors.add(publication.pending_fd)
                    if role == "pending":
                        target_descriptor = publication.pending_fd
                    elif role == "root-directory":
                        target_descriptor = publication.directory_fds[0]
                    elif role == "ancestor-directory":
                        target_descriptor = publication.directory_fds[1]
                    else:
                        target_descriptor = publication.directory_fds[2]

                def fail_target_close_without_closing(descriptor: int) -> None:
                    if (
                        descriptor == target_descriptor
                        and not intentionally_open
                    ):
                        intentionally_open.add(descriptor)
                        raise OSError(
                            f"injected {role} publication descriptor close failure"
                        )
                    real_close(descriptor)

                with (
                    mock.patch.object(
                        evidence,
                        "_stage_output_file",
                        side_effect=stage_and_select_target,
                    ),
                    mock.patch.object(
                        evidence.os,
                        "open",
                        side_effect=track_open,
                    ),
                    mock.patch.object(
                        evidence.os,
                        "dup",
                        side_effect=track_dup,
                    ),
                    mock.patch.object(
                        evidence.os,
                        "close",
                        side_effect=fail_target_close_without_closing,
                    ),
                    self.assertRaisesRegex(
                        evidence.EvidenceError,
                        f"injected {role} publication descriptor close failure",
                    ),
                ):
                    self.create(output_path=output_path)

                self.assert_tracked_descriptor_cleanup(
                    tracked_descriptors,
                    intentionally_open=intentionally_open,
                )
                self.assertEqual(len(publication_descriptors), 4)
                self.assertTrue(
                    publication_descriptors <= tracked_descriptors
                )
                self.assertEqual(intentionally_open, {target_descriptor})
                self.assertTrue((self.root / output_path).is_file())

    def test_authenticated_replay_residue_is_fail_closed(self) -> None:
        context = self.write_authenticated_envelope()
        marker_leaf = (
            "challenge-v1-"
            f"{sha256(AUTH_CHALLENGE)[7:]}.used"
        )
        prefix = (
            ".catchplate-onboarding-"
            + hashlib.sha256(marker_leaf.encode("utf-8")).hexdigest()[:20]
            + "-"
        )
        residue = self.replay_root / "ledger" / f"{prefix}residue.pending"
        residue.write_bytes(b"untrusted residue")
        residue.chmod(0o600)
        with self.assertRaisesRegex(
            evidence.EvidenceError,
            "incomplete fail-closed publication state",
        ):
            self.verify_authenticated(context)

        residue.unlink()
        with (
            mock.patch.object(
                evidence,
                "_publish_output_file",
                side_effect=OSError("injected pre-publication failure"),
            ),
            self.assertRaisesRegex(
                evidence.EvidenceError,
                "injected pre-publication failure",
            ),
        ):
            self.verify_authenticated(context)
        self.assertEqual(list((self.replay_root / "ledger").iterdir()), [])

        context = self.write_authenticated_envelope(
            challenge=b"post-link-residue"
        )
        real_unlink = evidence.os.unlink

        def fail_pending_unlink(
            path: object,
            *,
            dir_fd: int | None = None,
        ) -> None:
            if os.fspath(path).endswith(".pending"):
                raise OSError("injected post-link unlink failure")
            real_unlink(path, dir_fd=dir_fd)

        with (
            mock.patch.object(
                evidence.os,
                "unlink",
                side_effect=fail_pending_unlink,
            ),
            self.assertRaisesRegex(
                evidence.EvidenceError,
                "fail-closed challenge marker remains present",
            ),
        ):
            self.verify_authenticated(context)
        entries = list((self.replay_root / "ledger").iterdir())
        self.assertEqual(len(entries), 2)
        self.assertEqual(
            {entry.stat().st_ino for entry in entries},
            {entries[0].stat().st_ino},
        )
        self.assertEqual(entries[0].stat().st_nlink, 2)

    def test_authenticated_replay_enumeration_is_streaming_and_bounded(
        self,
    ) -> None:
        self.write_authenticated_envelope()
        ledger = self.replay_root / "ledger"
        for index in range(3):
            (ledger / f"unrelated-{index}.used").write_bytes(b"bounded")
        root_pin = evidence._open_root_fd(self.replay_root)
        publication = evidence._pin_output_publication(
            root_pin.fd,
            "ledger/bounded-enumeration.used",
        )
        try:
            with (
                mock.patch.object(
                    evidence,
                    "MAX_REPLAY_DIRECTORY_ENTRIES",
                    2,
                ),
                self.assertRaisesRegex(
                    evidence.EvidenceError,
                    "2-entry bounded enumeration limit",
                ),
            ):
                evidence._pending_entries(publication)
        finally:
            self.assertEqual(
                evidence._close_output_publication(publication),
                [],
            )
            self.assertEqual(root_pin.close(), [])

    def test_authenticated_work_budget_counts_each_png_parse_once(self) -> None:
        context = self.write_authenticated_envelope(
            challenge=b"aggregate-work-budget"
        )
        root_pin = evidence._open_root_fd(self.root)
        isolated_budget = evidence._WorkBudget(4_096)
        real_read = evidence.os.read

        def partial_read(descriptor: int, requested: int) -> bytes:
            return real_read(descriptor, max(1, requested // 2))

        try:
            with mock.patch.object(
                evidence.os,
                "read",
                side_effect=partial_read,
            ):
                capture, raw = evidence._capture_regular(
                    root_pin.fd,
                    "verifier-challenge.bin",
                    limit=evidence.MAX_VERIFIER_CHALLENGE_BYTES,
                    collect=True,
                    work_budget=isolated_budget,
                )
            self.assertEqual(raw, b"aggregate-work-budget")
            self.assertEqual(
                isolated_budget.consumed,
                len(raw) * evidence.FILE_READ_HASH_WORK_PER_BYTE,
            )
            os.fstat(int(capture.descriptor))
        finally:
            self.assertEqual(
                isolated_budget.close_retained_descriptors(),
                [],
            )
            self.assertEqual(root_pin.close(), [])

        real_parse_png = evidence._parse_png
        parse_calls: list[str] = []

        def track_parse(
            data: bytes,
            *,
            relative: str,
            work_budget: evidence._WorkBudget | None = None,
        ) -> dict[str, int]:
            parse_calls.append(relative)
            return real_parse_png(
                data,
                relative=relative,
                work_budget=work_budget,
            )

        with mock.patch.object(
            evidence,
            "_parse_png",
            side_effect=track_parse,
        ):
            self.verify_authenticated(context)
        self.assertEqual(parse_calls, ["screens/portal.png"])

        context = self.write_authenticated_envelope(
            challenge=b"aggregate-work-reject"
        )
        with (
            mock.patch.object(evidence, "MAX_AUTHENTICATED_WORK_UNITS", 1),
            self.assertRaisesRegex(
                evidence.EvidenceError,
                "aggregate work budget",
            ),
        ):
            self.verify_authenticated(context)

        context = self.write_authenticated_envelope(
            challenge=b"retained-capture-count-limit"
        )
        with (
            mock.patch.object(evidence, "MAX_AUTHENTICATED_CAPTURE_FILES", 2),
            self.assertRaisesRegex(
                evidence.EvidenceError,
                "2-file retained capture limit",
            ),
        ):
            self.verify_authenticated(context)

    def test_authenticated_work_budget_covers_every_artifact_class_exactly(
        self,
    ) -> None:
        context = self.write_authenticated_envelope(
            challenge=b"exact-aggregate-work-accounting"
        )
        manifest = self.load_manifest()
        artifact_groups = {
            "authority": [
                str(context["envelope_path"]),
                str(context["verifier_challenge_path"]),
                str(context["trusted_public_key_path"]),
            ],
            "manifest": [str(context["manifest_path"])],
            "journey": [str(manifest["journeyArtifact"]["path"])],
            "source": [
                str(entry["path"]) for entry in manifest["sourceInputs"]
            ],
            "screenshot": [
                str(entry["path"]) for entry in manifest["screenshots"]
            ],
        }
        captured_paths = [
            path for paths in artifact_groups.values() for path in paths
        ]
        self.assertEqual(len(captured_paths), len(set(captured_paths)))
        for group, paths in artifact_groups.items():
            with self.subTest(group=group):
                self.assertTrue(paths)

        self.assertEqual(evidence.FILE_READ_HASH_WORK_PER_BYTE, 2)
        self.assertEqual(evidence.PNG_ENCODED_WORK_PER_BYTE, 3)
        self.assertEqual(evidence.PNG_DECODED_WORK_PER_BYTE, 2)
        self.assertEqual(
            evidence.PNG_DECOMPRESSION_OVERFLOW_SENTINEL_WORK_UNITS,
            1,
        )
        self.assertEqual(evidence.PNG_CHUNK_WORK_UNITS, 256)
        exact_file_bytes = {
            path: (self.root / path).read_bytes() for path in captured_paths
        }
        expected_work = sum(
            len(data) * 2 for data in exact_file_bytes.values()
        )
        expected_work += sum(
            independent_png_weighted_work(exact_file_bytes[path])
            for path in artifact_groups["screenshot"]
        )

        real_capture_regular = evidence._capture_regular
        observed_budgets: dict[str, evidence._WorkBudget | None] = {}

        def record_capture_budget(
            root_fd: int,
            relative: str,
            *,
            limit: int,
            collect: bool = False,
            work_budget: evidence._WorkBudget | None = None,
        ) -> tuple[evidence._Capture, bytes | None]:
            if relative in observed_budgets:
                raise AssertionError(f"duplicate capture for {relative}")
            observed_budgets[relative] = work_budget
            return real_capture_regular(
                root_fd,
                relative,
                limit=limit,
                collect=collect,
                work_budget=work_budget,
            )

        with mock.patch.object(
            evidence,
            "_capture_regular",
            side_effect=record_capture_budget,
        ):
            result = self.verify_authenticated(context)

        self.assertEqual(set(observed_budgets), set(captured_paths))
        self.assertNotIn(None, observed_budgets.values())
        self.assertEqual(
            len({id(budget) for budget in observed_budgets.values()}),
            1,
        )
        self.assertEqual(
            result["authenticatedWorkBudget"][
                "consumedWeightedApplicationByteWorkUnits"
            ],
            expected_work,
        )

    def test_png_work_is_precharged_before_crc_and_decompression(self) -> None:
        payload = png_bytes(1, 1)
        with (
            mock.patch.object(evidence.zlib, "crc32") as crc32,
            self.assertRaisesRegex(
                evidence.EvidenceError,
                "aggregate work budget",
            ),
        ):
            evidence._parse_png(
                payload,
                relative="precharge-crc.png",
                work_budget=evidence._WorkBudget(1),
            )
        crc32.assert_not_called()

        encoded_only_limit = (
            len(payload) * evidence.PNG_ENCODED_WORK_PER_BYTE
            + 3 * evidence.PNG_CHUNK_WORK_UNITS
        )
        with (
            mock.patch.object(evidence, "MAX_PNG_CHUNKS", 3),
            mock.patch.object(evidence.zlib, "decompressobj") as decompressobj,
            self.assertRaisesRegex(
                evidence.EvidenceError,
                "aggregate work budget",
            ),
        ):
            evidence._parse_png(
                payload,
                relative="precharge-decompression.png",
                work_budget=evidence._WorkBudget(encoded_only_limit),
            )
        decompressobj.assert_not_called()

        without_overflow_sentinel = (
            encoded_only_limit
            + len(zlib.compress(b"\x00\x12\x34\x56\xff"))
            + 5 * evidence.PNG_DECODED_WORK_PER_BYTE
        )
        with (
            mock.patch.object(evidence, "MAX_PNG_CHUNKS", 3),
            mock.patch.object(evidence.zlib, "decompressobj") as decompressobj,
            self.assertRaisesRegex(
                evidence.EvidenceError,
                "aggregate work budget",
            ),
        ):
            evidence._parse_png(
                payload,
                relative="precharge-overflow-sentinel.png",
                work_budget=evidence._WorkBudget(without_overflow_sentinel),
            )
        decompressobj.assert_not_called()

    def test_authenticated_inputs_remain_descriptor_pinned_until_consumption(
        self,
    ) -> None:
        context = self.write_authenticated_envelope(
            challenge=b"retained-descriptor-lifetime"
        )
        real_consume = evidence._consume_verifier_challenge
        observed_descriptors: list[int] = []

        def observe_retained_descriptors(
            *args: object,
            **kwargs: object,
        ) -> str:
            captures = kwargs["captures"]
            self.assertLessEqual(
                len(captures),
                evidence.MAX_AUTHENTICATED_CAPTURE_FILES,
            )
            for capture in captures:
                self.assertIsNotNone(capture.descriptor)
                descriptor = int(capture.descriptor)
                os.fstat(descriptor)
                observed_descriptors.append(descriptor)
            return real_consume(*args, **kwargs)

        with mock.patch.object(
            evidence,
            "_consume_verifier_challenge",
            side_effect=observe_retained_descriptors,
        ):
            self.verify_authenticated(context)
        self.assertTrue(observed_descriptors)
        self.assertEqual(
            len(observed_descriptors),
            len(set(observed_descriptors)),
        )
        for descriptor in observed_descriptors:
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_authenticated_cli_rejects_abbreviations_and_duplicate_authority(
        self,
    ) -> None:
        def assert_duplicate_rejected(
            arguments: list[str],
            option: str,
        ) -> None:
            stderr = io.StringIO()
            with (
                contextlib.redirect_stderr(stderr),
                self.assertRaises(SystemExit) as raised,
            ):
                evidence._parser().parse_args(arguments)
            self.assertEqual(raised.exception.code, 2)
            self.assertIn(
                f"{option} may be supplied only once",
                stderr.getvalue(),
            )

        assert_duplicate_rejected(
            [
                "--root",
                os.fspath(self.root),
                "--root",
                os.fspath(self.root),
                "verify",
                "--manifest",
                "evidence.json",
            ],
            "--root",
        )
        assert_duplicate_rejected(
            [
                "verify",
                "--manifest",
                "evidence.json",
                "--manifest",
                "other.json",
            ],
            "--manifest",
        )
        context = self.write_authenticated_envelope()
        authenticated_arguments = self.authenticated_cli_command(context)[2:]
        assert_duplicate_rejected(
            [*authenticated_arguments, "--manifest", "other.json"],
            "--manifest",
        )
        create_arguments = [
            "create",
            "--journey",
            "journey.json",
            "--source",
            SOURCE_PATHS[0],
            "--screenshot",
            "screens/portal.png",
            "--playwright-version",
            "1.55.0",
            "--chromium-version",
            "139.0.0.0",
            "--output",
            "evidence.json",
        ]
        for option, second in (
            ("--journey", "other.json"),
            ("--playwright-version", "1.56.0"),
            ("--chromium-version", "140.0.0.0"),
            ("--output", "other.json"),
        ):
            with self.subTest(option=option):
                assert_duplicate_rejected(
                    [*create_arguments, option, second],
                    option,
                )

        with self.assertRaises(SystemExit):
            evidence._parser().parse_args(
                [
                    "--ro",
                    os.fspath(self.root),
                    "verify",
                    "--manifest",
                    "evidence.json",
                ]
            )

    def test_workflow_is_derived_from_all_exact_artifact_bytes(self) -> None:
        manifest = self.create()
        gmail = manifest["workflow"]["gmail"]
        self.assertEqual(gmail["query"], "newer_than:30d")
        self.assertEqual(gmail["messageCount"], 2)
        self.assertEqual(
            gmail["responseFormat"],
            "catchplate.gatewayNormalizedGmailMessages/v1",
        )
        self.assertFalse(gmail["captureTimeAuthenticated"])
        self.assertEqual(
            gmail["oldestInternalDateEpochMillis"],
            str((GMAIL_CAPTURE - 29 * 86_400) * 1_000),
        )
        self.assertEqual(
            gmail["requestArtifact"]["sha256"],
            sha256((self.root / "source/gmail-request.http").read_bytes()),
        )
        x_workflow = manifest["workflow"]["x"]
        self.assertEqual(x_workflow["search"]["lookbackSeconds"], 7 * 86_400)
        self.assertEqual(x_workflow["search"]["tweetFields"], "created_at")
        self.assertFalse(x_workflow["search"]["captureTimeAuthenticated"])
        self.assertEqual(x_workflow["posting"]["acceptedCount"], 1)
        self.assertEqual(x_workflow["posting"]["deniedCount"], 1)
        jit = manifest["workflow"]["jitApproval"]
        self.assertEqual(jit["method"], "PUT")
        self.assertEqual(jit["authority"], "registry.npmjs.org")
        self.assertEqual(jit["path"], "/example-package")
        self.assertEqual(jit["route"], "npm.publish")
        self.assertEqual(jit["operation"], "npm.publish example-package@1.0.0")
        self.assertTrue(jit["webauthn"]["signatureVerified"])
        self.assertEqual(jit["webauthn"]["signatureAlgorithm"], "ES256")
        self.assertEqual(jit["webauthn"]["signatureCounter"], 7)

    def test_capture_interval_is_bounded_and_contains_gmail_x_and_jit(self) -> None:
        manifest = self.create()
        self.assertEqual(
            manifest["workflow"]["captureInterval"],
            valid_journey()["captureInterval"],
        )

        too_long = valid_journey()
        too_long["captureInterval"]["endedAtEpochSeconds"] = (
            CAPTURE_START + evidence.MAX_CAPTURE_INTERVAL_SECONDS + 1
        )
        self.write_fixture(journey=too_long)
        with self.assertRaisesRegex(evidence.EvidenceError, "captureInterval exceeds"):
            self.create()

        gmail_outside = valid_journey()
        gmail_outside["captureInterval"]["startedAtEpochSeconds"] = GMAIL_CAPTURE + 1
        self.write_fixture(journey=gmail_outside)
        with self.assertRaisesRegex(
            evidence.EvidenceError,
            "Gmail response capturedAtEpochSeconds.*captureInterval",
        ):
            self.create()

        x_outside = valid_journey()
        x_outside["x"]["capturedAtEpochSeconds"] = CAPTURE_END + 1
        self.write_fixture(journey=x_outside)
        with self.assertRaisesRegex(
            evidence.EvidenceError,
            "journey.x.capturedAtEpochSeconds.*captureInterval",
        ):
            self.create()

        jit_outside = valid_journey()
        jit_outside["jitApproval"]["retryAtEpochSeconds"] = CAPTURE_END + 1
        jit_outside["jitApproval"]["expiresAtEpochSeconds"] = CAPTURE_END + 2
        self.write_fixture(journey=jit_outside)
        with self.assertRaisesRegex(
            evidence.EvidenceError,
            "jitApproval.retryAtEpochSeconds.*captureInterval",
        ):
            self.create()

    def test_webauthn_result_is_explicitly_self_anchored(self) -> None:
        webauthn = self.create()["workflow"]["jitApproval"]["webauthn"]
        self.assertEqual(webauthn["trustAnchor"], "evidence-supplied-public-key")
        self.assertTrue(webauthn["selfAnchored"])
        self.assertFalse(webauthn["registeredAuthenticatorOwnershipEstablished"])

    def test_webauthn_crypto_backend_errors_are_evidence_errors(self) -> None:
        self.write_fixture()
        with (
            mock.patch.object(
                evidence.serialization,
                "load_pem_public_key",
                side_effect=UnsupportedAlgorithm("injected WebAuthn key algorithm"),
            ),
            self.assertRaisesRegex(
                evidence.EvidenceError,
                "WebAuthn public key artifact is not valid PEM",
            ),
        ):
            self.create()

        _, artifacts = self.write_fixture()
        public_key_bytes = artifacts["source/webauthn-public-key.pem"]

        class UnsupportedWebAuthnPublicKey:
            curve = ec.SECP256R1()

            def public_bytes(
                self,
                encoding: serialization.Encoding,
                format: serialization.PublicFormat,
            ) -> bytes:
                del encoding, format
                return public_key_bytes

            def verify(
                self,
                signature: bytes,
                data: bytes,
                signature_algorithm: ec.ECDSA,
            ) -> None:
                del signature, data, signature_algorithm
                raise UnsupportedAlgorithm(
                    "injected WebAuthn signature algorithm"
                )

        unsupported_key = UnsupportedWebAuthnPublicKey()
        with (
            mock.patch.object(
                evidence.serialization,
                "load_pem_public_key",
                return_value=unsupported_key,
            ),
            mock.patch.object(
                evidence.ec,
                "EllipticCurvePublicKey",
                UnsupportedWebAuthnPublicKey,
            ),
            self.assertRaisesRegex(
                evidence.EvidenceError,
                "WebAuthn signature algorithm is unsupported",
            ),
        ):
            self.create()

    def test_webauthn_rejects_forged_signature(self) -> None:
        _, artifacts = self.write_fixture()
        forged = bytearray(artifacts["source/webauthn-signature.der"])
        forged[-1] ^= 1
        self.write_fixture(
            overrides={"source/webauthn-signature.der": bytes(forged)}
        )
        with self.assertRaisesRegex(evidence.EvidenceError, "signature verification failed"):
            self.create()

    def test_webauthn_rejects_origin_and_challenge_mismatch(self) -> None:
        journey, artifacts = self.write_fixture()
        client = json.loads(artifacts["source/webauthn-client-data.json"])
        client["type"] = "webauthn.create"
        self.write_fixture(
            journey=journey,
            overrides={"source/webauthn-client-data.json": canonical_json(client)},
        )
        with self.assertRaisesRegex(evidence.EvidenceError, "clientDataJSON.type"):
            self.create()

        client["type"] = "webauthn.get"
        client["origin"] = "https://attacker.example"
        self.write_fixture(
            journey=journey,
            overrides={"source/webauthn-client-data.json": canonical_json(client)},
        )
        with self.assertRaisesRegex(evidence.EvidenceError, "clientDataJSON.origin"):
            self.create()

        client["origin"] = "https://catchplate.example"
        client["challenge"] = base64.urlsafe_b64encode(b"wrong").rstrip(b"=").decode()
        self.write_fixture(
            journey=journey,
            overrides={"source/webauthn-client-data.json": canonical_json(client)},
        )
        with self.assertRaisesRegex(evidence.EvidenceError, "challenge does not match"):
            self.create()

        base_journey = valid_journey()
        _, base_artifacts = self.write_fixture(journey=base_journey)
        changed_expiry = valid_journey()
        changed_expiry["jitApproval"]["expiresAtEpochSeconds"] += 1
        self.write_fixture(
            journey=changed_expiry,
            overrides={
                path: base_artifacts[path]
                for path in (
                    "source/webauthn-client-data.json",
                    "source/webauthn-authenticator-data.bin",
                    "source/webauthn-signature.der",
                    "source/webauthn-public-key.pem",
                )
            },
        )
        with self.assertRaisesRegex(evidence.EvidenceError, "challenge does not match"):
            self.create()

    def test_webauthn_rejects_rpid_up_uv_and_counter_mismatch(self) -> None:
        journey, artifacts = self.write_fixture()
        auth = artifacts["source/webauthn-authenticator-data.bin"]
        cases = [
            ("rp", b"\x00" * 32 + auth[32:], "RP ID hash mismatch"),
            ("up", auth[:32] + b"\x04" + auth[33:], "exactly UP and UV"),
            ("uv", auth[:32] + b"\x01" + auth[33:], "exactly UP and UV"),
            (
                "counter",
                auth[:33] + struct.pack(">I", 8),
                "signature counter",
            ),
        ]
        for label, mutated, expected in cases:
            with self.subTest(label=label):
                self.write_fixture(
                    journey=journey,
                    overrides={
                        "source/webauthn-authenticator-data.bin": mutated,
                    },
                )
                with self.assertRaisesRegex(evidence.EvidenceError, expected):
                    self.create()

    def test_webauthn_rejects_malformed_or_wrong_curve_public_key(self) -> None:
        self.write_fixture(
            overrides={"source/webauthn-public-key.pem": b"not a key\n"}
        )
        with self.assertRaisesRegex(evidence.EvidenceError, "not valid PEM"):
            self.create()

        wrong_key = ec.generate_private_key(ec.SECP384R1()).public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.write_fixture(
            overrides={"source/webauthn-public-key.pem": wrong_key}
        )
        with self.assertRaisesRegex(evidence.EvidenceError, "ES256 P-256"):
            self.create()

    def test_gmail_request_is_parsed_for_exact_30_day_constraint(self) -> None:
        bad = http_request(
            "GET",
            "/gmail/v1/users/me/messages?q=newer_than%3A31d&maxResults=100",
            "gmail.googleapis.com",
            principal=REQUESTER,
            credential=GMAIL_CREDENTIAL,
        )
        self.write_fixture(overrides={"source/gmail-request.http": bad})
        with self.assertRaisesRegex(evidence.EvidenceError, "maximum age"):
            self.create()

        malformed = http_request(
            "GET",
            "/gmail/v1/users/me/messages?q=newer_than%zz30d&maxResults=100",
            "gmail.googleapis.com",
            principal=REQUESTER,
            credential=GMAIL_CREDENTIAL,
        )
        self.write_fixture(overrides={"source/gmail-request.http": malformed})
        with self.assertRaisesRegex(evidence.EvidenceError, "percent encoding"):
            self.create()

    def test_gmail_requires_named_normalized_untrusted_epoch_millis_envelope(
        self,
    ) -> None:
        base = {
            "schema": "catchplate.gatewayNormalizedGmailMessages/v1",
            "captureTimeAuthenticated": False,
            "capturedAtEpochSeconds": GMAIL_CAPTURE,
            "messages": [
                {
                    "id": "m1",
                    "internalDateEpochMillis": str(
                        (GMAIL_CAPTURE - 3_600) * 1_000
                    ),
                }
            ],
        }
        cases = []
        wrong_schema = copy.deepcopy(base)
        wrong_schema["schema"] = "gmail.messages.list"
        cases.append(("schema", wrong_schema, "Gmail response schema"))
        trusted_capture = copy.deepcopy(base)
        trusted_capture["captureTimeAuthenticated"] = True
        cases.append(
            (
                "capture-authentication",
                trusted_capture,
                "captureTimeAuthenticated",
            )
        )
        provider_shaped = copy.deepcopy(base)
        provider_shaped["messages"][0] = {
            "id": "m1",
            "internalDate": str((GMAIL_CAPTURE - 3_600) * 1_000),
        }
        cases.append(
            ("provider-shape", provider_shaped, "missing fields: internalDateEpochMillis")
        )
        for label, body, expected in cases:
            with self.subTest(label=label):
                self.write_fixture(
                    overrides={
                        "source/gmail-response.http": http_response(
                            200,
                            "OK",
                            body,
                        )
                    }
                )
                with self.assertRaisesRegex(evidence.EvidenceError, expected):
                    self.create()

    def test_gmail_response_rejects_missing_old_future_and_unparseable_timestamps(self) -> None:
        cases = [
            (
                "missing",
                {
                    "schema": "catchplate.gatewayNormalizedGmailMessages/v1",
                    "captureTimeAuthenticated": False,
                    "capturedAtEpochSeconds": GMAIL_CAPTURE,
                    "messages": [{"id": "m1"}],
                },
                "missing fields",
            ),
            (
                "older",
                {
                    "schema": "catchplate.gatewayNormalizedGmailMessages/v1",
                    "captureTimeAuthenticated": False,
                    "capturedAtEpochSeconds": GMAIL_CAPTURE,
                    "messages": [
                        {
                            "id": "m1",
                            "internalDateEpochMillis": str(
                                (GMAIL_CAPTURE - 31 * 86_400) * 1_000
                            ),
                        }
                    ],
                },
                "older than",
            ),
            (
                "future",
                {
                    "schema": "catchplate.gatewayNormalizedGmailMessages/v1",
                    "captureTimeAuthenticated": False,
                    "capturedAtEpochSeconds": GMAIL_CAPTURE,
                    "messages": [
                        {
                            "id": "m1",
                            "internalDateEpochMillis": str(
                                (GMAIL_CAPTURE + 1) * 1_000
                            ),
                        }
                    ],
                },
                "future message",
            ),
            (
                "unparseable",
                {
                    "schema": "catchplate.gatewayNormalizedGmailMessages/v1",
                    "captureTimeAuthenticated": False,
                    "capturedAtEpochSeconds": GMAIL_CAPTURE,
                    "messages": [
                        {"id": "m1", "internalDateEpochMillis": "01774779840000"}
                    ],
                },
                "canonical decimal epoch milliseconds",
            ),
        ]
        for label, body, expected in cases:
            with self.subTest(label=label):
                response = http_response(200, "OK", body)
                self.write_fixture(
                    overrides={"source/gmail-response.http": response}
                )
                with self.assertRaisesRegex(evidence.EvidenceError, expected):
                    self.create()

    def test_x_search_requires_get_read_only_and_policy_lookback(self) -> None:
        bad_method = http_request(
            "POST",
            (
                "/2/tweets/search/recent?query=catchplate"
                f"&start_time={quote('2026-07-20T12:00:00Z')}"
                f"&end_time={quote('2026-07-27T12:00:00Z')}"
                "&tweet.fields=created_at"
            ),
            "api.x.com",
            principal=REQUESTER,
            credential=X_CREDENTIAL,
        )
        self.write_fixture(overrides={"source/x-search-request.http": bad_method})
        with self.assertRaisesRegex(evidence.EvidenceError, "X search method"):
            self.create()

        excessive = http_request(
            "GET",
            (
                "/2/tweets/search/recent?query=catchplate"
                f"&start_time={quote('2026-07-19T12:00:00Z')}"
                f"&end_time={quote('2026-07-27T12:00:00Z')}"
                "&tweet.fields=created_at"
            ),
            "api.x.com",
            principal=REQUESTER,
            credential=X_CREDENTIAL,
        )
        self.write_fixture(overrides={"source/x-search-request.http": excessive})
        with self.assertRaisesRegex(evidence.EvidenceError, "lookback exceeds"):
            self.create()

    def test_x_search_requires_created_at_field_selection(self) -> None:
        _, artifacts = self.write_fixture()
        request = artifacts["source/x-search-request.http"]
        cases = [
            (
                "missing",
                request.replace(b"&tweet.fields=created_at", b""),
                "must contain exactly",
            ),
            (
                "wrong",
                request.replace(b"tweet.fields=created_at", b"tweet.fields=id"),
                "X search tweet.fields",
            ),
        ]
        for label, candidate, expected in cases:
            with self.subTest(label=label):
                self.write_fixture(
                    overrides={"source/x-search-request.http": candidate}
                )
                with self.assertRaisesRegex(evidence.EvidenceError, expected):
                    self.create()

    def test_x_search_response_timestamps_are_derived_and_bounded(self) -> None:
        outside = http_response(
            200,
            "OK",
            {
                "data": [
                    {"id": "old", "created_at": "2026-07-19T12:00:00Z"}
                ],
                "meta": {"result_count": 1},
            },
        )
        self.write_fixture(overrides={"source/x-search-response.http": outside})
        with self.assertRaisesRegex(evidence.EvidenceError, "outside the requested"):
            self.create()

        malformed = http_response(
            200,
            "OK",
            {
                "data": [{"id": "bad", "created_at": "not-a-time"}],
                "meta": {"result_count": 1},
            },
        )
        self.write_fixture(overrides={"source/x-search-response.http": malformed})
        with self.assertRaisesRegex(evidence.EvidenceError, "canonical second-resolution"):
            self.create()

    def test_x_post_requires_first_acceptance_and_second_denial(self) -> None:
        wrong_first = http_response(
            200,
            "OK",
            {"data": {"id": "tweet-created-1"}},
        )
        self.write_fixture(
            overrides={"source/x-post-1-response.http": wrong_first}
        )
        with self.assertRaisesRegex(evidence.EvidenceError, "first X post response status"):
            self.create()

        wrong_second = http_response(
            201,
            "Created",
            {"data": {"id": "tweet-created-2"}},
        )
        self.write_fixture(
            overrides={"source/x-post-2-response.http": wrong_second}
        )
        with self.assertRaisesRegex(evidence.EvidenceError, "second X post response status"):
            self.create()

        _, artifacts = self.write_fixture()
        self.write_fixture(
            overrides={
                "source/x-post-2-request.http": artifacts[
                    "source/x-post-1-request.http"
                ]
            }
        )
        with self.assertRaisesRegex(evidence.EvidenceError, "must be distinct"):
            self.create()

    def test_x_counter_binds_hashes_limit_order_and_same_utc_day(self) -> None:
        _, artifacts = self.write_fixture()
        counter = json.loads(artifacts["source/x-post-counter.json"])
        cases: list[tuple[str, dict[str, object], str]] = []
        bad_hash = copy.deepcopy(counter)
        bad_hash["events"][0]["requestSha256"] = "sha256:" + "0" * 64
        cases.append(("hash", bad_hash, "requestSha256"))
        bad_limit = copy.deepcopy(counter)
        bad_limit["limit"] = 2
        cases.append(("limit", bad_limit, "counter limit"))
        bad_day = copy.deepcopy(counter)
        bad_day["events"][1]["at"] = "2026-07-28T00:00:00Z"
        cases.append(("day", bad_day, "declared UTC day"))
        bad_order = copy.deepcopy(counter)
        bad_order["events"][1]["at"] = "2026-07-27T12:00:00Z"
        cases.append(("order", bad_order, "strictly chronological"))
        for label, candidate, expected in cases:
            with self.subTest(label=label):
                self.write_fixture(
                    overrides={
                        "source/x-post-counter.json": canonical_json(candidate)
                    }
                )
                with self.assertRaisesRegex(evidence.EvidenceError, expected):
                    self.create()

    def test_jit_request_derives_principal_credential_route_and_operation(self) -> None:
        _, artifacts = self.write_fixture()
        request = artifacts["source/npm-challenge.request"]
        cases = [
            (
                "principal",
                request.replace(REQUESTER.encode(), b"operator:other"),
                "x-catchplate-principal",
            ),
            (
                "credential",
                request.replace(NPM_CREDENTIAL.encode(), b"credential:other"),
                "x-catchplate-credential-id",
            ),
            (
                "method",
                request.replace(b"PUT ", b"POST ", 1),
                "challenged npm request method",
            ),
            (
                "path",
                request.replace(b"/example-package ", b"/other-package ", 1),
                "path must exactly",
            ),
            (
                "operation",
                request.replace(b'"version":"1.0.0"', b'"version":"1.0.1"'),
                "retry raw HTTP request bytes",
            ),
        ]
        for label, candidate, expected in cases:
            with self.subTest(label=label):
                self.write_fixture(
                    overrides={"source/npm-challenge.request": candidate}
                )
                with self.assertRaisesRegex(evidence.EvidenceError, expected):
                    self.create()

    def test_jit_request_parser_rejects_duplicate_headers_and_bad_lengths(self) -> None:
        _, artifacts = self.write_fixture()
        request = artifacts["source/npm-challenge.request"]
        duplicate = request.replace(
            b"host:registry.npmjs.org\r\n",
            b"host:registry.npmjs.org\r\nhost:registry.npmjs.org\r\n",
        )
        self.write_fixture(
            overrides={
                "source/npm-challenge.request": duplicate,
                "source/npm-retry.request": duplicate,
            }
        )
        with self.assertRaisesRegex(evidence.EvidenceError, "duplicate HTTP header"):
            self.create()

        extra = request.replace(
            b"host:registry.npmjs.org\r\n",
            b"host:registry.npmjs.org\r\nx-extra:forbidden\r\n",
        )
        self.write_fixture(
            overrides={
                "source/npm-challenge.request": extra,
                "source/npm-retry.request": extra,
            }
        )
        with self.assertRaisesRegex(evidence.EvidenceError, "headers must be exactly"):
            self.create()

        wrong_length = request.replace(
            b"content-length:",
            b"content-length:999\r\nx-ignored:",
        )
        self.write_fixture(
            overrides={
                "source/npm-challenge.request": wrong_length,
                "source/npm-retry.request": wrong_length,
            }
        )
        with self.assertRaises(evidence.EvidenceError):
            self.create()

        huge_length = request.replace(
            b"content-length:",
            b"content-length:" + b"9" * 5_000 + b"\r\nx-ignored:",
        )
        self.write_fixture(
            overrides={
                "source/npm-challenge.request": huge_length,
                "source/npm-retry.request": huge_length,
            }
        )
        with self.assertRaisesRegex(evidence.EvidenceError, "content-length"):
            self.create()

    def test_specialized_artifact_limits_apply_during_capture(self) -> None:
        with (
            mock.patch.object(evidence, "MAX_HTTP_BYTES", 32),
            self.assertRaisesRegex(evidence.EvidenceError, "exceeds the 32-byte limit"),
        ):
            self.create()
        with (
            mock.patch.object(evidence, "MAX_WEBAUTHN_COMPONENT_BYTES", 16),
            self.assertRaisesRegex(evidence.EvidenceError, "exceeds the 16-byte limit"),
        ):
            self.create()

    def test_jit_challenge_and_retry_responses_are_byte_derived(self) -> None:
        bad_challenge = http_response(
            200,
            "OK",
            {
                "error": "approval_required",
                "approvalRequestId": "approval:npm-write",
                "upstreamCalls": 0,
            },
        )
        self.write_fixture(
            overrides={"source/npm-challenge.response": bad_challenge}
        )
        with self.assertRaisesRegex(evidence.EvidenceError, "challenge response status"):
            self.create()

        bad_retry = http_response(
            500,
            "Error",
            {
                "ok": True,
                "approvalRequestId": "approval:npm-write",
                "upstreamCalls": 1,
            },
        )
        self.write_fixture(overrides={"source/npm-retry.response": bad_retry})
        with self.assertRaisesRegex(evidence.EvidenceError, "must be successful"):
            self.create()

    def test_post_publication_revalidation_removes_output_on_drift(self) -> None:
        original_publish = evidence._publish_output_file

        def publish_then_mutate(
            publication: evidence._OutputPublication,
            data_size: int,
        ) -> None:
            original_publish(publication, data_size)
            (self.root / "source/journey.py").write_text(
                "print('post-publication mutation')\n",
                encoding="utf-8",
            )

        with (
            mock.patch.object(
                evidence,
                "_publish_output_file",
                side_effect=publish_then_mutate,
            ),
            self.assertRaisesRegex(evidence.EvidenceError, "before finalization"),
        ):
            self.create()
        self.assertFalse((self.root / "evidence.json").exists())
        self.assertEqual(
            list(self.root.glob(".catchplate-onboarding-*.pending")),
            [],
        )

    def test_partial_write_crash_leaves_only_fail_closed_pending_state(self) -> None:
        class SimulatedCrash(BaseException):
            pass

        real_write = evidence.os.write
        writes = 0

        def partial_then_crash(descriptor: int, data: object) -> int:
            nonlocal writes
            if writes:
                raise SimulatedCrash("injected partial-write crash")
            writes += 1
            return real_write(descriptor, bytes(data)[:32])

        with (
            mock.patch.object(evidence.os, "write", side_effect=partial_then_crash),
            self.assertRaises(SimulatedCrash),
        ):
            self.create()
        self.assertFalse((self.root / "evidence.json").exists())
        pending = list(self.root.glob(".catchplate-onboarding-*.pending"))
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0].stat().st_size, 32)
        with self.assertRaisesRegex(
            evidence.EvidenceError,
            "incomplete fail-closed publication state",
        ):
            self.create()

    def test_crash_between_publish_steps_leaves_explicit_alias_state(self) -> None:
        class SimulatedCrash(BaseException):
            pass

        real_unlink = evidence.os.unlink

        def crash_before_pending_unlink(
            path: object,
            *,
            dir_fd: int | None = None,
        ) -> None:
            if os.fspath(path).endswith(".pending"):
                raise SimulatedCrash("injected crash after final link")
            real_unlink(path, dir_fd=dir_fd)

        with (
            mock.patch.object(
                evidence.os,
                "unlink",
                side_effect=crash_before_pending_unlink,
            ),
            self.assertRaises(SimulatedCrash),
        ):
            self.create()
        final = self.root / "evidence.json"
        pending = list(self.root.glob(".catchplate-onboarding-*.pending"))
        self.assertTrue(final.exists())
        self.assertEqual(len(pending), 1)
        self.assertEqual(final.stat().st_ino, pending[0].stat().st_ino)
        self.assertEqual(final.stat().st_nlink, 2)
        with self.assertRaisesRegex(evidence.EvidenceError, "exactly one hard link"):
            evidence.verify_manifest(self.root, "evidence.json")
        with self.assertRaisesRegex(
            evidence.EvidenceError,
            "incomplete fail-closed publication state",
        ):
            self.create()

    def test_final_name_collision_is_atomic_and_preserves_collision(self) -> None:
        real_link = evidence.os.link

        def collide_then_link(
            source: object,
            destination: object,
            *,
            src_dir_fd: int | None = None,
            dst_dir_fd: int | None = None,
            follow_symlinks: bool = True,
        ) -> None:
            assert dst_dir_fd is not None
            collision = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=dst_dir_fd,
            )
            try:
                os.write(collision, b"collision")
                os.fsync(collision)
            finally:
                os.close(collision)
            real_link(
                source,
                destination,
                src_dir_fd=src_dir_fd,
                dst_dir_fd=dst_dir_fd,
                follow_symlinks=follow_symlinks,
            )

        with (
            mock.patch.object(evidence.os, "link", side_effect=collide_then_link),
            self.assertRaisesRegex(evidence.EvidenceError, "already exists"),
        ):
            self.create()
        self.assertEqual((self.root / "evidence.json").read_bytes(), b"collision")
        self.assertEqual(
            list(self.root.glob(".catchplate-onboarding-*.pending")),
            [],
        )

    def test_publish_failure_cleans_final_and_pending_from_pinned_parent(
        self,
    ) -> None:
        real_unlink = evidence.os.unlink
        failed = False

        def fail_first_unlink(
            path: object,
            *,
            dir_fd: int | None = None,
        ) -> None:
            nonlocal failed
            if not failed and os.fspath(path).endswith(".pending"):
                failed = True
                raise OSError("injected publish unlink failure")
            real_unlink(path, dir_fd=dir_fd)

        with (
            mock.patch.object(
                evidence.os,
                "unlink",
                side_effect=fail_first_unlink,
            ),
            self.assertRaisesRegex(
                evidence.EvidenceError,
                "output publication failed.*injected publish unlink failure",
            ),
        ):
            self.create()
        self.assertFalse((self.root / "evidence.json").exists())
        self.assertEqual(
            list(self.root.glob(".catchplate-onboarding-*.pending")),
            [],
        )

    def test_publish_cleanup_failure_is_explicit_and_fail_closed(self) -> None:
        with (
            mock.patch.object(
                evidence.os,
                "unlink",
                side_effect=OSError("injected unlink failure"),
            ),
            self.assertRaisesRegex(
                evidence.EvidenceError,
                "cleanup failed.*injected unlink failure.*"
                "fail-closed publication residue may remain",
            ),
        ):
            self.create()
        final = self.root / "evidence.json"
        pending = list(self.root.glob(".catchplate-onboarding-*.pending"))
        self.assertTrue(final.exists())
        self.assertEqual(len(pending), 1)
        self.assertEqual(final.stat().st_ino, pending[0].stat().st_ino)
        self.assertEqual(final.stat().st_nlink, 2)

    def test_root_is_component_traversed_from_one_pinned_anchor(self) -> None:
        real_open = evidence.os.open
        root_opens: list[object] = []

        def tracking_open(
            path: object,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            if dir_fd is None:
                root_opens.append(path)
                return real_open(path, flags, mode)
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch.object(evidence.os, "open", side_effect=tracking_open):
            self.create()
        self.assertEqual(root_opens, [self.root.anchor])
        root_opens.clear()
        with mock.patch.object(evidence.os, "open", side_effect=tracking_open):
            evidence.verify_manifest(self.root, "evidence.json")
        self.assertEqual(root_opens, [self.root.anchor])

    def test_root_component_traversal_rejects_intermediate_symlink_and_parent(
        self,
    ) -> None:
        real_parent = self.root / "real-parent"
        real_parent.mkdir()
        (real_parent / "child").mkdir()
        alias = self.root / "alias-parent"
        alias.symlink_to(real_parent.name)
        with self.assertRaisesRegex(
            evidence.EvidenceError,
            "cannot pin root directory safely",
        ):
            evidence._open_root_fd(alias / "child")
        with self.assertRaisesRegex(
            evidence.EvidenceError,
            "parent traversal",
        ):
            evidence._open_root_fd(self.root / ".." / self.root.name)
        with self.assertRaisesRegex(
            evidence.EvidenceError,
            "64-component limit",
        ):
            evidence._root_path_components(
                Path("/") / Path(*(["component"] * 65))
            )
        with self.assertRaisesRegex(
            evidence.EvidenceError,
            "32-component relative path limit",
        ):
            evidence._canonical_relative_path(
                "/".join(["component"] * 33),
                name="deep path",
            )

    def test_rejects_symlink_and_any_hard_link(self) -> None:
        (self.root / "source-link").symlink_to(
            self.root / "source" / "journey.py"
        )
        sources = [
            path for path in SOURCE_PATHS if path != "source/journey.py"
        ] + ["source-link"]
        with self.assertRaisesRegex(evidence.EvidenceError, "symlinks"):
            self.create(source_paths=sources)

        os.link(
            self.root / "source" / "journey.py",
            self.root / "undeclared-hardlink",
        )
        with self.assertRaisesRegex(evidence.EvidenceError, "exactly one hard link"):
            self.create()

    def test_private_output_refuses_existing_and_shared_parent(self) -> None:
        self.create()
        with self.assertRaisesRegex(evidence.EvidenceError, "already exists"):
            self.create()
        os.chmod(self.root / "evidence.json", 0o644)
        self.assert_rejected("must remain owner-owned mode 0600")

        shared = self.root / "shared"
        shared.mkdir(mode=0o755)
        with self.assertRaisesRegex(evidence.EvidenceError, "private"):
            self.create(output_path="shared/evidence.json")

    def test_writable_output_ancestor_is_rejected(self) -> None:
        writable = self.root / "writable"
        writable.mkdir(mode=0o700)
        os.chmod(writable, 0o777)
        private = writable / "private"
        private.mkdir(mode=0o700)
        with self.assertRaisesRegex(
            evidence.EvidenceError,
            "writable/private/evidence.json.*must not be writable by group or world",
        ):
            self.create(output_path="writable/private/evidence.json")

    def test_json_duplicate_depth_node_string_and_container_limits(self) -> None:
        with self.assertRaisesRegex(evidence.EvidenceError, "duplicate object key"):
            evidence._decode_json(b'{"x":1,"x":2}', name="duplicate.json")
        with self.assertRaisesRegex(evidence.EvidenceError, "depth limit"):
            evidence._decode_json(
                (
                    "[" * (evidence.MAX_JSON_DEPTH + 1)
                    + "0"
                    + "]" * (evidence.MAX_JSON_DEPTH + 1)
                ).encode(),
                name="deep.json",
            )
        with (
            mock.patch.object(evidence, "MAX_JSON_NODES", 3),
            self.assertRaisesRegex(evidence.EvidenceError, "node JSON limit"),
        ):
            evidence._decode_json(b"[1,2,3]", name="nodes.json")
        with (
            mock.patch.object(evidence, "MAX_JSON_STRING_LENGTH", 3),
            self.assertRaisesRegex(evidence.EvidenceError, "string longer"),
        ):
            evidence._decode_json(b'{"x":"abcd"}', name="string.json")
        with (
            mock.patch.object(evidence, "MAX_JSON_CONTAINER_ITEMS", 2),
            self.assertRaisesRegex(evidence.EvidenceError, "array with more"),
        ):
            evidence._decode_json(b"[1,2,3]", name="container.json")

    def test_png_rejects_apng_compressed_ancillary_and_unknown_chunks(self) -> None:
        cases = [
            (
                png_bytes(1, 1, before_idat=((b"acTL", struct.pack(">II", 1, 0)),)),
                "APNG animation",
            ),
            (
                png_bytes(1, 1, before_idat=((b"iCCP", b"profile\x00\x00x"),)),
                "compressed ancillary",
            ),
            (
                png_bytes(1, 1, before_idat=((b"tEXt", b"key\x00value"),)),
                "unsupported PNG chunk",
            ),
        ]
        for payload, expected in cases:
            with self.subTest(expected=expected):
                (self.root / "screens/portal.png").write_bytes(payload)
                with self.assertRaisesRegex(evidence.EvidenceError, expected):
                    self.create()

    def test_png_accepts_strict_rgb_and_rgba_with_exact_row_sizes(self) -> None:
        rgb = evidence._parse_png(
            png_bytes(3, 2, color_type=2),
            relative="rgb.png",
        )
        rgba = evidence._parse_png(
            png_bytes(3, 2, color_type=6),
            relative="rgba.png",
        )
        self.assertEqual(rgb["decodedByteSize"], 2 * (1 + 3 * 3))
        self.assertEqual(rgba["decodedByteSize"], 2 * (1 + 3 * 4))
        self.assertEqual(rgb["width"], rgba["width"])
        self.assertEqual(rgb["height"], rgba["height"])

    def test_png_rejects_unsupported_color_and_rgb_rgba_row_mismatch(self) -> None:
        with self.assertRaisesRegex(
            evidence.EvidenceError,
            "8-bit RGB or RGBA",
        ):
            evidence._parse_png(
                png_bytes(1, 1, color_type=0),
                relative="grayscale.png",
            )
        with self.assertRaisesRegex(
            evidence.EvidenceError,
            "decodes beyond its declared dimensions",
        ):
            evidence._parse_png(
                png_bytes(
                    2,
                    1,
                    color_type=2,
                    row_override=b"\x00" + b"\x12\x34\x56\xff" * 2,
                ),
                relative="rgb-with-rgba-row.png",
            )
        with self.assertRaisesRegex(
            evidence.EvidenceError,
            "does not match declared dimensions",
        ):
            evidence._parse_png(
                png_bytes(
                    2,
                    1,
                    color_type=6,
                    row_override=b"\x00" + b"\x12\x34\x56" * 2,
                ),
                relative="rgba-with-rgb-row.png",
            )

    def test_png_rejects_decoder_variants_and_resource_exhaustion(self) -> None:
        cases = [
            ("MAX_PNG_CHUNKS", 2, png_bytes(3, 2), "chunk limit"),
            ("MAX_PNG_WIDTH", 2, png_bytes(3, 2), "width exceeds"),
            ("MAX_PNG_ROWS", 1, png_bytes(3, 2), "rows exceed"),
            (
                "MAX_DECODED_PNG_BYTES",
                8,
                png_bytes(3, 2),
                "decoded PNG exceeds",
            ),
            (
                "MAX_PNG_IDAT_CHUNKS",
                1,
                png_bytes(3, 2, split_idat=True),
                "IDAT-chunk limit",
            ),
        ]
        for constant, limit, payload, expected in cases:
            with self.subTest(constant=constant):
                (self.root / "screens/portal.png").write_bytes(payload)
                with (
                    mock.patch.object(evidence, constant, limit),
                    self.assertRaisesRegex(evidence.EvidenceError, expected),
                ):
                    self.create()
        (self.root / "screens/portal.png").write_bytes(
            png_bytes(1, 1, interlace=1)
        )
        with self.assertRaisesRegex(evidence.EvidenceError, "non-interlaced"):
            self.create()

    def test_manifest_schema_and_workflow_are_closed(self) -> None:
        self.create()
        original = self.load_manifest()
        unknown = copy.deepcopy(original)
        unknown["unknown"] = True
        self.write_manifest(unknown)
        self.assert_rejected("unknown fields")

        workflow = copy.deepcopy(original)
        workflow["workflow"]["gmail"]["proof"] = True
        self.write_manifest(workflow)
        self.assert_rejected("workflow does not match")

    def test_source_journey_and_packet_drift_are_detected(self) -> None:
        self.create()
        (self.root / "journey.json").write_bytes(b"{}")
        self.assert_rejected("journey artifact drift")

        (self.root / "evidence.json").unlink()
        self.write_fixture()
        self.create()
        (self.root / "source/enrollment.packet").write_bytes(b"replacement")
        self.assert_rejected("source input drift")

    def test_references_must_all_be_distinct_and_declared(self) -> None:
        sources = [
            path for path in SOURCE_PATHS if path != "source/gmail-request.http"
        ]
        with self.assertRaisesRegex(evidence.EvidenceError, "declared --source"):
            self.create(source_paths=sources)

        journey = valid_journey()
        journey["gmail"]["requestArtifactPath"] = (
            journey["gmail"]["responseArtifactPath"]
        )
        self.write_fixture(journey=journey)
        with self.assertRaisesRegex(evidence.EvidenceError, "must be distinct"):
            self.create()


if __name__ == "__main__":
    unittest.main()
