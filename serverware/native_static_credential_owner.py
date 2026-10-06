"""Private static intake retained by the actual native broker child.

Only the same native TLS owner may reach this purpose through the inherited
private channel. Configuration is that parent's admitted cold projection, not
HTTP input. This module neither verifies a supplied TLS verdict nor accepts
existing ciphertext. It does not load a key, sign proof, insert a credential,
or claim approval or commit. The parent must independently bind its actual
TLS/runtime identity when signing the returned fresh preparation.

Candidates live only in this broker process. There is no reconstruction,
expiry renewal, repeat preparation, or recovery of an uncertain dispatch.
Python allocations do not provide a complete plaintext-erasure guarantee.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hmac
import json
import os
import time
from urllib.parse import urlsplit

from serverware import authority_static_credential_create as profile
from serverware import native_oauth_refresh as codec
from serverware import native_static_credential as material
from serverware.native_oauth_refresh_owner import IDENTITY_FIELDS

CHANNEL = "serverware.nativeStaticCredentialChannel/v1"
CONFIG = "serverware.nativeStaticCredentialConfiguration/v1"
MAX_CANDIDATES = 16
_CONFIG_FIELDS = frozenset({"apiVersion", "controlPlaneConfigurationDigest",
    "staticCredentialCreationPolicy", "candidateCapacity", "deploymentId", "instanceId",
    "identity", "intakeOrigin", "portalOrigin", "ingressLeafCertificateSha256",
    "ingressLeafSpkiSha256"})
_INTENT_FIELDS = frozenset({"apiVersion", "operation", "actorId",
    "controlPlaneConfigurationDigest", "credentialPolicy", "request"})


def _require(value):
    if not value:
        raise ValueError("native static credential owner unavailable")


def _original(value, maximum):
    _require(type(value) is str and 0 < len(value) <= maximum)
    raw = value.encode("ascii")

    def pairs(items):
        result = {}
        for key, child in items:
            _require(key not in result)
            result[key] = child
        return result

    parsed = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: _require(False))
    _require(type(parsed) is dict and profile.canonical(parsed) == raw)
    # Full 16 KiB metadata can exceed OAuth's 8192-node envelope once
    # surrounded by these originals. Preserve this family's existing domain;
    # its exact profile still separately checks metadata size, keys and depth.
    pending, count = [(parsed, 0)], 0
    while pending:
        child, depth = pending.pop()
        count += 1
        _require(depth <= 32 and count <= 32768)
        if type(child) is dict:
            pending.extend((item, depth + 1) for item in child.values())
        elif type(child) is list:
            pending.extend((item, depth + 1) for item in child)
    return parsed


def _origin(value):
    codec.text(value, 2048)
    parsed = urlsplit(value)
    _require(value == value.strip() and not any(ord(char) < 33 or ord(char) == 127 for char in value)
        and parsed.scheme == "https" and parsed.hostname and parsed.username is None
        and parsed.password is None and not parsed.path and not parsed.query and not parsed.fragment
        and parsed.netloc == parsed.netloc.lower() and parsed.port is None)


def _timestamp(value):
    stamp = datetime.fromisoformat(value)
    delta = stamp - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000


@dataclass(frozen=True, slots=True)
class _Candidate:
    intent_original: str
    generation_original: str
    browser_nonce: bytes
    sealed_at: int
    started: int
    expires: int
    retention_deadline: int


class Owner:
    def __init__(self, broker, value):
        broker.require_owner_configuration()
        _require(type(value) is dict and set(value) == {"apiVersion", "phase", "configuration"}
            and value["apiVersion"] == CHANNEL and value["phase"] == "configure"
            and broker.kek is not None and broker.rsa is None and broker.service_tokens_opened)
        broker.channel.check()
        # Copy the closed public projection; retain the actual provisioned key
        # object and private channel rather than any supplied key or verdict.
        config = codec.document(profile.canonical(value["configuration"]), 32768)
        _require(set(config) == _CONFIG_FIELDS and config["apiVersion"] == CONFIG)
        selected = profile.validate_policy(config["staticCredentialCreationPolicy"])
        _require(config["controlPlaneConfigurationDigest"] == selected["controlPlaneConfigurationDigest"]
            and selected["nativeSecretKekId"] == broker.key_id)
        codec.integer(config["candidateCapacity"], maximum=MAX_CANDIDATES)
        for name in ("deploymentId", "instanceId"):
            codec.text(config[name], 512)
        _origin(config["intakeOrigin"])
        _origin(config["portalOrigin"])
        _require(config["intakeOrigin"] != config["portalOrigin"])
        for name in ("ingressLeafCertificateSha256", "ingressLeafSpkiSha256"):
            profile.digest(config[name])
        identity = config["identity"]
        _require(type(identity) is dict and set(identity) == IDENTITY_FIELDS)
        for name in ("holderId", "bootId", "keyId", "controlPlaneResponseSigningKeyId"):
            codec.text(identity[name], 512)
        for name in IDENTITY_FIELDS - {"holderId", "bootId", "keyId", "controlPlaneResponseSigningKeyId"}:
            profile.digest(identity[name])
        self.broker, self.config = broker, config
        self._channel, self._kek, self._key_id = broker.channel, broker.kek, broker.key_id
        self._channel_deadline = broker.channel.deadline
        self._config_original = profile.canonical(config)
        self._candidates, self._spent = {}, set()
        self.operation = None
        self._poisoned = False
        self._last_wall, self._last_boot = time.time_ns(), time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        self.check()
        self._channel.send({"apiVersion": CHANNEL, "phase": "configured"})
        self.check()

    def check(self, deadline=None):
        _require(not self._poisoned and self.broker.channel is self._channel
            and self.broker.kek is self._kek and self.broker.key_id == self._key_id
            and self.broker.rsa is None and self.broker.service_tokens_opened
            and self._channel.deadline == self._channel_deadline
            and profile.canonical(self.config) == self._config_original)
        self._channel.check(deadline)
        wall, boot = time.time_ns(), time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        _require(self._last_wall <= wall and self._last_boot <= boot)
        self._last_wall, self._last_boot = wall, boot
        return wall, boot

    def _window(self, deadline, issued, expires, *, retention_deadline=None):
        codec.integer(deadline, maximum=2**64 - 1)
        wall, boot = self.check()
        _require(issued <= wall < expires)
        limit = min(deadline, self._channel_deadline, boot + 30_000_000_000,
            boot + expires - wall)
        if retention_deadline is not None:
            limit = min(limit, retention_deadline)
        _require(boot < limit)
        return _Window(self, wall, min(expires, wall + limit - boot), limit)

    def handle(self, value):
        try:
            self.check()
            _require(type(value) is dict and value.get("apiVersion") == CHANNEL and self.operation is None)
            if value.get("phase") == "intake":
                self._intake(value)
            else:
                _require(value.get("phase") == "prepare-execution")
                self._prepare(value)
        except BaseException:
            # The parent's existing helper lifecycle must terminate on error.
            # Even if a caller catches it, this owner cannot resume custody.
            self._poisoned = True
            raise

    def _intake(self, value):
        _require(set(value) == {"apiVersion", "phase", "intentOriginal", "secretBase64url", "deadlineBoottimeNs"}
            and len(self._candidates) < self.config["candidateCapacity"])
        intent = _original(value["intentOriginal"], profile.MAX_ARGUMENT_BYTES)
        _require(set(intent) == _INTENT_FIELDS and intent["apiVersion"] == profile.INTENT_SCHEMA
            and intent["operation"] == profile.OPERATION)
        original = profile.intent_original(actor_id=intent["actorId"],
            configuration_digest=intent["controlPlaneConfigurationDigest"],
            credential_policy=intent["credentialPolicy"], request=intent["request"])
        _require(original == value["intentOriginal"].encode("ascii"))
        request = intent["request"]
        selected = self.config["staticCredentialCreationPolicy"]
        _require(intent["controlPlaneConfigurationDigest"] == self.config["controlPlaneConfigurationDigest"]
            and intent["credentialPolicy"] == selected["credentialPolicy"]
            and request["expiresAtEpochNs"] - request["issuedAtEpochNs"] <= selected["intentMaxSeconds"] * 1_000_000_000
            and request["credentialId"] not in self._candidates)
        window = self._window(value["deadlineBoottimeNs"], request["issuedAtEpochNs"], request["expiresAtEpochNs"])
        self.operation = window
        # BOOTTIME retention is frozen at intake, not recomputed after approval.
        wall, boot = self.check(window.deadline)
        retention_deadline = min(self._channel_deadline, boot + request["expiresAtEpochNs"] - wall)
        raw = codec.decoded(value["secretBase64url"], material.MAX_SECRET_BYTES)
        window.check()
        # ISO database timestamps have microsecond resolution. Choose an exact
        # representable instant still inside the retained intent, never round
        # it backwards across its original issuance boundary.
        sealed_at = time.time_ns() // 1000 * 1000
        _require(request["issuedAtEpochNs"] <= sealed_at < window.expires)
        try:
            generation = material.seal_generation_original(actor_id=intent["actorId"],
                configuration_digest=intent["controlPlaneConfigurationDigest"],
                credential_policy=intent["credentialPolicy"], intent=request, raw=raw,
                secret_kek_id=self._key_id, kek=self._kek, epoch_ns=sealed_at)
        finally:
            del raw
        window.check()
        _require(_timestamp(profile.generation(generation)["envelope"]["secret_updated_at"]) == sealed_at)
        nonce = os.urandom(32)
        candidate = _Candidate(value["intentOriginal"], generation, nonce, sealed_at,
            request["issuedAtEpochNs"], request["expiresAtEpochNs"], retention_deadline)
        self._candidates[request["credentialId"]] = candidate
        # This whole reply is private IPC. Only candidate may be published;
        # browserNonce goes solely to the actual TLS owner's __Host cookie.
        self._channel.send({"apiVersion": CHANNEL, "phase": "retained", "candidate": {
            "credentialId": request["credentialId"], "intentOriginal": candidate.intent_original,
            "nativeGenerationOriginal": candidate.generation_original,
            "intentSha256": profile.sha256(original),
            "generationSha256": profile.sha256(generation.encode("ascii")),
            "expiresAtEpochNs": candidate.expires}, "browserNonce": codec.encoded(nonce)}, window.deadline)
        window.check()
        self.operation = None

    def _prepare(self, value):
        _require(set(value) == {"apiVersion", "phase", "credentialId", "browserNonce", "argumentsOriginal",
            "challenge", "deadlineBoottimeNs"})
        identifier = profile.identifier(value["credentialId"])
        candidate = self._candidates.get(identifier)
        _require(type(candidate) is _Candidate and identifier not in self._spent
            and hmac.compare_digest(codec.decoded(value["browserNonce"], 32, 32), candidate.browser_nonce))
        codec.decoded(value["challenge"], 32, 32)
        values = _original(value["argumentsOriginal"], profile.MAX_ARGUMENT_BYTES)
        values = profile.arguments(profile.OPERATION, values)
        _require(profile.canonical(values).decode("ascii") == value["argumentsOriginal"])
        intent = _original(candidate.intent_original, profile.MAX_ARGUMENT_BYTES)
        request = values["request"]
        _require(request["credentialId"] == identifier
            and request["nativeGenerationOriginal"] == candidate.generation_original
            and profile.intent_original(actor_id=values["actor_id"],
                configuration_digest=values["control_plane_configuration_digest"],
                credential_policy=values["credential_policy"],
                request={name: request[name] for name in profile.INTENT_FIELDS}) == candidate.intent_original.encode("ascii"))
        window = self._window(value["deadlineBoottimeNs"], request["executionIssuedAtEpochNs"],
            request["executionExpiresAtEpochNs"], retention_deadline=candidate.retention_deadline)
        self.operation = window
        now, _ = self.check(window.deadline)
        profile.verify_request_context(profile.OPERATION, values,
            selected_policy=self.config["staticCredentialCreationPolicy"], now_epoch_ns=now)
        window.check()
        bindings = {"controlPlaneConfigurationDigest": intent["controlPlaneConfigurationDigest"],
            "deploymentId": self.config["deploymentId"], "instanceId": self.config["instanceId"],
            "actorId": intent["actorId"], "credentialId": identifier, "credentialVersion": 1,
            "intentSha256": profile.sha256(candidate.intent_original.encode("ascii")),
            "generationSha256": profile.sha256(candidate.generation_original.encode("ascii")),
            "inputSha256": profile.sha256(value["argumentsOriginal"].encode("ascii")),
            "secretKekId": self._key_id, "generationCreatedAtEpochNs": candidate.sealed_at,
            "challenge": value["challenge"], "issuedAtEpochNs": window.started,
            "expiresAtEpochNs": window.expires,
            **{name: self.config[name] for name in ("intakeOrigin", "portalOrigin",
                "ingressLeafCertificateSha256", "ingressLeafSpkiSha256")}}
        # A returned preparation may already be signed/dispatched. Fence before
        # the first byte of output; no later expiry or missing reply permits a
        # new attempt. Approval and current state remain the kernel's checks.
        self._spent.add(identifier)
        self._channel.send({"apiVersion": CHANNEL, "phase": "prepared", "operation": profile.OPERATION,
            "argumentsOriginal": value["argumentsOriginal"], "statementBindings": bindings}, window.deadline)
        window.check()
        self.operation = None


class _Window:
    def __init__(self, owner, started, expires, deadline):
        self.owner, self.started, self.expires, self.deadline = owner, started, expires, deadline

    def check(self):
        wall, _ = self.owner.check(self.deadline)
        _require(self.owner.operation is self and self.started <= wall < self.expires)
