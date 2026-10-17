"""Separate, purpose-authorized retained-pair opening on the broker's FD3.

The real native parent independently admits cold policy and owns the browser
TLS stream, challenge cookie and recipient private key. This child verifies
the distinct signed opening assignment, native challenge and current-read
authorization before using its existing provisioned KEK. Only recipient-
encrypted redacted JSON leaves this process. It grants preparation, not display:
the native owner must withhold its immutable view until the exact commit ACK.

Any refused/uncertain attempt poisons the owner. It neither reads historical
keys nor acquires permission from the sealing owner. Python allocations do not
provide a complete plaintext-erasure guarantee.
"""
from __future__ import annotations

import os
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from catchplate import authority_native_jit_review_assignment as grammar
from catchplate import authority_native_jit_review_open_contract as wire
from catchplate import authority_native_jit_review_open_custody as custody
from catchplate import authority_native_jit_retained_history as history
from catchplate import authority_transition_core as core
from catchplate import native_jit_review_material as material
from catchplate import native_jit_review_owner as sealing
from catchplate import native_oauth_refresh as codec

CHANNEL = "catchplate.nativeJitReviewOpenChannel/v1"
CONFIG = custody.CONFIG
OUTPUT = "catchplate.nativeJitReviewOpenCiphertext/v1"
DOMAIN = b"catchplate/native-jit-review-open-ciphertext/v1\0"
MAX_COMMAND_BYTES = 5 * 1024 * 1024
PREPARE_FIELDS = frozenset({"apiVersion", "phase", "challengeOriginal", "authorizationOriginal",
    "parentOriginal", "childOriginal", "pairOriginal", "evidenceOriginal", "deadlineBoottimeNs"})
_LITERAL_HASHES = {"parentOriginal": "parentOriginalSha256", "childOriginal": "childOriginalSha256",
    "pairOriginal": "pairSha256", "evidenceOriginal": "sealProofSha256"}
_CHALLENGE_JOINS = frozenset({"reviewId", "approvalRequestId", "sourceContractDigest",
    "controlPlaneConfigurationDigest", "openingAssignmentSha256", "ownerScopeDigest",
    "browserNonceCommitment", "recipientPublicKey"})
_OTHER_OWNERS = ("refresh_owner", "cleanup_owner", "pending_retirement_owner", "capture_retirement_owner",
    "exchange_owner", "setup_owner", "reconnect_owner", "succession_owner", "historical_keys",
    "static_credential_owner", "static_credential_rotation_owner")


class OwnerError(ValueError):
    def __init__(self):
        super().__init__("native JIT review opening is unavailable")


def _require(value):
    if not value:
        raise OwnerError()


def _encrypt(value, challenge, raw):
    """New purpose/domain; the signed native challenge alone selects recipient."""
    recipient = x25519.X25519PublicKey.from_public_bytes(
        grammar.decoded(challenge["recipientPublicKey"], 32, 32))
    ephemeral = x25519.X25519PrivateKey.generate()
    digest = grammar.sha256(grammar.canonical(value))
    aad = DOMAIN + bytes.fromhex(digest[7:])
    key = HKDF(algorithm=hashes.SHA256(), length=32,
        salt=grammar.decoded(challenge["challenge"], 32, 32), info=aad).derive(ephemeral.exchange(recipient))
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, raw, aad)
    return {"apiVersion": OUTPUT, "requestSha256": digest,
        "recipientPublicKey": challenge["recipientPublicKey"],
        "serverEphemeralPublicKey": codec.encoded(ephemeral.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
        "aeadNonce": codec.encoded(nonce), "ciphertext": codec.encoded(ciphertext)}


class Owner:
    def __init__(self, broker, value):
        self._poisoned = True
        try:
            broker.require_owner_configuration()
            _require(type(value) is dict and set(value) == {"apiVersion", "phase", "configuration"}
                and value["apiVersion"] == CHANNEL and value["phase"] == "configure"
                and type(broker.kek) is AESGCM and broker.rsa is None
                and broker.service_tokens_opened is True and broker.completed_service_operation_id is not None
                and broker.jit_configuration_closed is False
                and all(getattr(broker, name) is None for name in _OTHER_OWNERS)
                and type(broker.jit_review_owner) is sealing.Owner)
            self._wall_clock, self._boot_clock = time.time_ns, time.clock_gettime_ns
            # Sample BOOTTIME first: clipping an absolute wall expiry cannot
            # add verification time back onto the original monotonic bound.
            boot, wall = self._boot_clock(time.CLOCK_BOOTTIME), self._wall_clock()
            config, selected = custody.validate_broker_configuration(value["configuration"], now_epoch_ns=wall)
            seal = broker.jit_review_owner
            seal.check()
            _require(seal.broker is broker and seal.operation is None and not seal._spent
                and seal.config["identity"] == {name: selected["assignment"][name] for name in custody.IDENTITY_FIELDS}
                and seal.config["sourceContractDigest"] == config["sourceContractDigest"]
                and seal.config["controlPlaneConfigurationDigest"] == config["controlPlaneConfigurationDigest"]
                and seal.config["instanceId"] == selected["assignment"]["instanceId"]
                and seal.config["secretKekId"] == selected["assignment"]["secretKekId"])
            _require(selected["assignment"]["secretKekId"] == broker.key_id
                == "attested-memory-kek:" + grammar.digest(broker.commitment)[7:31])
            self.broker, self.config, self.assignment = broker, config, selected
            self._seal_owner = seal
            self._channel, self._kek, self._key_id = broker.channel, broker.kek, broker.key_id
            self._commitment = broker.commitment
            self._service_operation = broker.completed_service_operation_id
            self._channel_deadline = grammar.integer(broker.channel.deadline, maximum=2**64 - 1)
            self._deadline = min(self._channel_deadline, boot + selected["expiresAtEpochNs"] - wall)
            self._config_original = grammar.canonical(config)
            self._assignment_original = grammar.canonical(selected)
            self.owner_scope_digest = grammar.sha256(self._config_original)
            self._pid, self._last_wall, self._last_boot = os.getpid(), wall, boot
            self._spent_reviews, self._spent_challenges, self._spent_recipients = set(), set(), set()
            self.operation = None
            self._poisoned = False
            self.check()
            self._channel.send({"apiVersion": CHANNEL, "phase": "configured"}, self._deadline)
            self.check()
        except BaseException as error:
            self._poisoned = True
            if isinstance(error, Exception):
                raise OwnerError() from None
            raise

    def check(self, deadline=None):
        try:
            _require(not self._poisoned and os.getpid() == self._pid
                and self.broker.channel is self._channel and self.broker.kek is self._kek
                and self.broker.key_id == self._key_id and self.broker.commitment == self._commitment
                and self.broker.rsa is None and self.broker.service_tokens_opened is True
                and self.broker.completed_service_operation_id == self._service_operation
                and self.broker.jit_review_owner is self._seal_owner
                and all(getattr(self.broker, name) is None for name in _OTHER_OWNERS)
                and self._channel.deadline == self._channel_deadline
                and grammar.canonical(self.config) == self._config_original
                and grammar.canonical(self.assignment) == self._assignment_original
                and self.owner_scope_digest == grammar.sha256(self._config_original))
            selected = min(self._deadline, self._deadline if deadline is None
                else grammar.integer(deadline, maximum=2**64 - 1))
            self._channel.check(selected)
            self._seal_owner.check(selected)
            boot, wall = self._boot_clock(time.CLOCK_BOOTTIME), self._wall_clock()
            _require(type(wall) is int and type(boot) is int and 0 < self._last_wall <= wall
                and 0 < self._last_boot <= boot < selected
                and self.assignment["issuedAtEpochNs"] <= wall < self.assignment["expiresAtEpochNs"])
            if self.operation is not None:
                _require(boot < self.operation.deadline and wall < self.operation.expires)
            self._last_wall, self._last_boot = wall, boot
            return wall, boot
        except BaseException as error:
            self._poisoned = True
            if isinstance(error, Exception):
                raise OwnerError() from None
            raise

    def handle(self, value):
        try:
            wall, boot = self.check()
            _require(self.operation is None)
            value = grammar.document(grammar.canonical(value).decode("ascii"), MAX_COMMAND_BYTES)
            _require(set(value) == PREPARE_FIELDS and value["apiVersion"] == CHANNEL and value["phase"] == "prepare")
            self.broker.jit_configuration_closed = True
            deadline = min(self._deadline, grammar.integer(value["deadlineBoottimeNs"], maximum=2**64 - 1),
                boot + self.config["policy"]["operationMaxSeconds"] * 1_000_000_000)
            _require(boot < deadline)
            self.operation = _Window(deadline, wall + deadline - boot)
            self._prepare(value, wall, boot)
        except BaseException as error:
            # The reply may have escaped, even when send/check raised. No
            # current or later request may rearm this poisoned owner.
            self._poisoned = True
            if isinstance(error, Exception):
                raise OwnerError() from None
            raise

    def _prepare(self, value, wall, boot):
        policy = self.config["policy"]
        grant = wire.verify_authorization_original(value["authorizationOriginal"],
            public_key=custody.purpose_key(policy["authorizerKey"]), now_epoch_ns=wall)["payload"]
        scope = grant["scope"]
        proof = custody._native_proof(value["challengeOriginal"], purpose="challenge", policy=policy,
            configuration_digest=self.config["controlPlaneConfigurationDigest"], now_epoch_ns=wall)
        challenge = proof["statement"]
        _require(proof["assignmentOriginal"] == self.config["assignmentOriginal"]
            and scope["challengeSha256"] == grammar.sha256(value["challengeOriginal"].encode("ascii"))
            and scope["ownerScopeDigest"] == self.owner_scope_digest
            and scope["assignmentExpiresAtEpochNs"] == self.assignment["expiresAtEpochNs"]
            and all(scope[name] == challenge[name] for name in _CHALLENGE_JOINS)
            and challenge["issuedAtEpochNs"] <= grant["issuedAtEpochNs"]
            and grant["expiresAtEpochNs"] <= challenge["expiresAtEpochNs"])
        for literal, digest in _LITERAL_HASHES.items():
            _require(type(value[literal]) is str and value[literal].isascii()
                and scope[digest] == grammar.sha256(value[literal].encode("ascii")))
        parent, child, pair, _seal = history.retained_original_documents(
            parent_original=value["parentOriginal"], child_original=value["childOriginal"],
            pair_original=value["pairOriginal"], evidence_original=value["evidenceOriginal"])
        _require(scope["sealedSourceContractDigest"] == parent["operationManifestDigest"]
            == child["operationManifestDigest"] == pair["scope"]["sourceContractDigest"]
            and scope["approvalRequestId"] == core.deterministic_uuid(operation="jit.request",
                request_digest=child["requestDigest"], purpose="jit-approval-request")
            and pair["keyId"] == self._key_id
            and scope["documentExpiresAtEpochNs"] == pair["scope"]["documentExpiresAtEpochNs"])
        expires = min(grant["expiresAtEpochNs"], challenge["expiresAtEpochNs"], wire.scope_expiry(scope),
            self.operation.expires)
        self.operation.expires = expires
        self.operation.deadline = min(self.operation.deadline, boot + expires - wall)
        now, _ = self.check(self.operation.deadline)
        _require(len(self._spent_reviews) < policy["attemptCapacity"]
            and scope["reviewId"] not in self._spent_reviews
            and scope["challengeSha256"] not in self._spent_challenges
            and scope["recipientPublicKey"] not in self._spent_recipients)
        # Fence before either plaintext exists or any ciphertext reply escapes.
        self._spent_reviews.add(scope["reviewId"])
        self._spent_challenges.add(scope["challengeSha256"])
        self._spent_recipients.add(scope["recipientPublicKey"])
        private = material.open_release_pair(pair, expected_scope=pair["scope"],
            key_id=self._key_id, kek=self._kek, now_epoch_ns=now)
        # open_release_pair decrypts and checks BOTH documents and commitments.
        # The canonical request and URL never enter the response plaintext.
        raw = material.canonical(private["redacted_display"])
        _require(grammar.sha256(raw) == child["arguments"]["redacted_display_digest"]
            and len(raw) <= material.MAX_PRIVATE_BYTES)
        self.check(self.operation.deadline)
        result = _encrypt(value, challenge, raw)
        del private, raw
        self.check(self.operation.deadline)
        self._channel.send(result, self.operation.deadline)
        self.check(self.operation.deadline)
        self.operation = None


class _Window:
    def __init__(self, deadline, expires):
        self.deadline, self.expires = deadline, expires
