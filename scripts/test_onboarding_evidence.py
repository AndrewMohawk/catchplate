#!/usr/bin/env python3
from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import os
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock
from urllib.parse import quote

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

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


def png_chunk(kind: bytes, data: bytes) -> bytes:
    checksum = zlib.crc32(kind)
    checksum = zlib.crc32(data, checksum) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", checksum)


def png_bytes(
    width: int,
    height: int,
    *,
    interlace: int = 0,
    filter_byte: int = 0,
    before_idat: tuple[tuple[bytes, bytes], ...] = (),
    split_idat: bool = False,
) -> bytes:
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, interlace)
    pixel = b"\x12\x34\x56\xff"
    rows = b"".join(bytes([filter_byte]) + pixel * width for _ in range(height))
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
        headers["x-serverware-principal"] = principal
    if credential is not None:
        headers["x-serverware-credential-id"] = credential
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
                "expectedOrigin": "https://serverware.example",
                "expectedRpId": "serverware.example",
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
            "schema": "serverware.gatewayNormalizedGmailMessages/v1",
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
            "/2/tweets/search/recent?query=serverware"
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
            prefix="serverware-onboarding-evidence-"
        )
        self.root = Path(self.temporary.name)
        (self.root / "source").mkdir()
        (self.root / "screens").mkdir()
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.write_fixture()

    def tearDown(self) -> None:
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

    def assert_rejected(self, expected: str) -> None:
        with self.assertRaisesRegex(evidence.EvidenceError, expected):
            evidence.verify_manifest(self.root, "evidence.json")

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

    def test_workflow_is_derived_from_all_exact_artifact_bytes(self) -> None:
        manifest = self.create()
        gmail = manifest["workflow"]["gmail"]
        self.assertEqual(gmail["query"], "newer_than:30d")
        self.assertEqual(gmail["messageCount"], 2)
        self.assertEqual(
            gmail["responseFormat"],
            "serverware.gatewayNormalizedGmailMessages/v1",
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

        client["origin"] = "https://serverware.example"
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
            "schema": "serverware.gatewayNormalizedGmailMessages/v1",
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
                    "schema": "serverware.gatewayNormalizedGmailMessages/v1",
                    "captureTimeAuthenticated": False,
                    "capturedAtEpochSeconds": GMAIL_CAPTURE,
                    "messages": [{"id": "m1"}],
                },
                "missing fields",
            ),
            (
                "older",
                {
                    "schema": "serverware.gatewayNormalizedGmailMessages/v1",
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
                    "schema": "serverware.gatewayNormalizedGmailMessages/v1",
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
                    "schema": "serverware.gatewayNormalizedGmailMessages/v1",
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
                "/2/tweets/search/recent?query=serverware"
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
                "/2/tweets/search/recent?query=serverware"
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
                "x-serverware-principal",
            ),
            (
                "credential",
                request.replace(NPM_CREDENTIAL.encode(), b"credential:other"),
                "x-serverware-credential-id",
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
            list(self.root.glob(".serverware-onboarding-*.pending")),
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
        pending = list(self.root.glob(".serverware-onboarding-*.pending"))
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
        pending = list(self.root.glob(".serverware-onboarding-*.pending"))
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
            list(self.root.glob(".serverware-onboarding-*.pending")),
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
            list(self.root.glob(".serverware-onboarding-*.pending")),
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
        pending = list(self.root.glob(".serverware-onboarding-*.pending"))
        self.assertTrue(final.exists())
        self.assertEqual(len(pending), 1)
        self.assertEqual(final.stat().st_ino, pending[0].stat().st_ino)
        self.assertEqual(final.stat().st_nlink, 2)

    def test_root_is_pinned_once_for_create_and_verify(self) -> None:
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
        self.assertEqual(root_opens, [os.fspath(self.root)])
        root_opens.clear()
        with mock.patch.object(evidence.os, "open", side_effect=tracking_open):
            evidence.verify_manifest(self.root, "evidence.json")
        self.assertEqual(root_opens, [os.fspath(self.root)])

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
